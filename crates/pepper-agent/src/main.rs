// SPDX-License-Identifier: Apache-2.0

mod api_error;
mod bucket_api;
mod compute;
mod diagnostics;
mod ec_planner;
mod fast_path;
mod filesystem_api;
mod http;
mod metrics;
mod namespace_api;
mod network_services;
mod objects;
mod pins;
mod placement;
mod publication;
mod reconstructed_cache;
mod repair;
mod s3_api;
mod small_object_pack;

use api_error::ApiError;
use bucket_api::*;
use compute::*;
use ec_planner::{EcPlanDecision, EcPlannerInputs, EcTransferPlan, ErasurePlanner};
use fast_path::FastPathRuntime;
use filesystem_api::*;
use metrics::*;
use namespace_api::*;
use network_services::*;
use objects::*;
use pins::*;
use placement::{PlacementRuntime, placement_map_from_candidates};
use publication::*;
use reconstructed_cache::ReconstructedStripeCache;
use repair::*;
use s3_api::*;
use small_object_pack::*;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// Bind jemalloc arenas to the CPU executing each per-core owner. This keeps
// allocations and frees local without requiring a process-wide allocator lock.
#[cfg(all(not(target_env = "msvc"), target_os = "linux"))]
#[unsafe(export_name = "malloc_conf")]
pub static MALLOC_CONF: &[u8] = b"percpu_arena:percpu,background_thread:true\0";

use ::time::OffsetDateTime;
use anyhow::{Context, Result};
use async_trait::async_trait;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use clap::{Parser, Subcommand};
use fs2::FileExt;
use futures_util::{StreamExt, TryStreamExt, stream};
use pepper_bucket::{
    BucketObjectCodecHandler, BucketPartition, BucketPartitionMap, BucketPartitionMapState,
    DEFAULT_BUCKET_PARTITIONS, MAX_BUCKET_PARTITIONS,
};
use pepper_compute::validate_job_spec;
use pepper_config::{LoadedConfig, SmallObjectPackConfig, default_config_path, load_from_path};
use pepper_consensus::{ConsensusConfig, ConsensusDataStore, NamespaceGroupManager};
use pepper_crypto::{NodeIdentity, verify_signature};
use pepper_dag::{
    BlockResolver as DagBlockResolver, DagCodecHandler, DagCodecRegistry, DagError, TraversalLimits,
};
use pepper_filesystem::{FilesystemInodeCodecHandler, FilesystemRootCodecHandler};
use pepper_merkle::MerkleNodeCodecHandler;
use pepper_metadata::MetadataStore;
use pepper_namespace::{
    NamespaceCheckpointCodecHandler, NamespaceCommitCodecHandler, NamespaceDescriptorCodecHandler,
    NamespaceId, NamespaceState, PinAction,
};
use pepper_network::{
    ErasureChunkReceiver, NetworkBlockService, NetworkComputeService, NetworkConfig,
    NetworkErasureService, NetworkError, NetworkHandle, NetworkNamespaceAliasService,
    NetworkPinService, PeerStatus, proto,
};
use pepper_placement::{
    AuthoritativePlacementError, PlacementException, PlacementMap, PlacementMapNodeState,
    PlacementNode, select_replicas,
};
use pepper_publication::{PublicationLimits, PublicationRepository};
use pepper_storage::{BlockStore, StorageError};
use pepper_types::{
    CODEC_BUCKET_PARTITION_BARRIER, CODEC_DIR_MANIFEST, CODEC_ERASURE_MANIFEST,
    CODEC_OBJECT_MANIFEST, CODEC_RAW, CODEC_SMALL_OBJECT, CODEC_SMALL_OBJECT_EXTENT_INDEX, Cid,
    Codec, ComputeAttempt, ComputeJobSpec, ComputeJobStatus, ComputeLogsResponse, ComputeOffer,
    ComputeReceipt, DirEntry, DirManifest, DurabilityReceipt, ErasureManifest, ErasureShard,
    ErasureStripe, ErasureStripeEncoding, ErrorCode, GcReport, InitStatus, NodeStatus, ObjectChunk,
    ObjectManifest, PinCreateRequest, PinRecord, PinStatusResponse, PlacedCid, PlacementReference,
    PlacementRole, ProviderRecord, PutBlockResponse, SubmitComputeResponse,
};
use redb::{ReadableTable, TableDefinition};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    io::{Read, Write},
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    process::Command as TokioCommand,
    sync::{OnceCell, RwLock, Semaphore, oneshot},
    task::AbortHandle,
    time::{self, Duration},
};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, prelude::*};

const JOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("jobs");
static JOB_COUNTER: AtomicU64 = AtomicU64::new(1);
static PIN_COUNTER: AtomicU64 = AtomicU64::new(1);
static READ_DIAGNOSTIC_COUNTER: AtomicU64 = AtomicU64::new(1);
const STORAGE_SOFT_PRESSURE_PERCENT: u64 = 85;
const STORAGE_HARD_PRESSURE_PERCENT: u64 = 95;
const DEFAULT_MAX_BLOCK_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;
const OBJECT_CHUNK_SIZE: usize = 4 * 1024 * 1024;
const OBJECT_CHUNK_PIPELINE_DEPTH: usize = 4;
const REPLICATED_BLOCK_CONCURRENCY: usize = 8;
const S3_HTTP_CONCURRENCY: usize = 128;
const S3_WRITE_CONCURRENCY: usize = 16;
const S3_WRITE_QUEUE_DEPTH: usize = 48;
const S3_WRITE_QUEUE_TIMEOUT_MS: u64 = 5_000;
const S3_WRITE_INITIAL_SERVICE_MICROS: u64 = 5_000_000;
const S3_INTERNAL_KEY_PREFIX: &[u8] = b"\xffs3/";
const ERASURE_COMPRESSION_LEVEL: i32 = 1;
const ERASURE_COMPRESSION_MIN_SAVINGS_PERCENT: usize = 10;
const ERASURE_COMPRESSION_PROBE_REGION_BYTES: usize = 16 * 1024;
const ERASURE_HEDGE_MAX_ACTIVE_STRIPE_READS: u64 = 1;
const ERASURE_STRIPE_READ_CONCURRENCY: usize = 32;
const ERASURE_REPAIR_BYTES_PER_SECOND: u64 = 32 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "pepper-agent", about = "Pepper node agent")]
struct Args {
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize local node directories, identity, metadata, and storage locations.
    Init,
    /// Copy quiesced metadata and a signed-identity backup manifest.
    Backup {
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Restore quiesced metadata after verifying its manifest and node identity.
    Restore {
        #[arg(long, value_name = "PATH")]
        input: PathBuf,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Clone)]
struct AppState {
    status: Arc<NodeStatus>,
    metadata: Arc<MetadataStore>,
    block_store: Arc<BlockStore>,
    dag_registry: Arc<DagCodecRegistry>,
    network: NetworkHandle,
    namespace_groups: Option<Arc<NamespaceGroupManager>>,
    namespace_data_store: ConsensusDataStore,
    publication_repository: PublicationRepository,
    _publication_limits: PublicationLimits,
    namespace_log_bytes: u64,
    replication_factor: usize,
    placement: Arc<PlacementRuntime>,
    fast_path: Option<Arc<FastPathRuntime>>,
    local_block_writer: BlockBatchWriter,
    repair_block_writer: BlockBatchWriter,
    replicated_block_slots: Arc<Semaphore>,
    s3_write_slots: Arc<Semaphore>,
    s3_write_capacity: usize,
    s3_write_queue_slots: Arc<Semaphore>,
    s3_write_queue_timeout: Duration,
    s3_write_service_micros: Arc<AtomicU64>,
    s3_list_cache: Arc<S3ListCache>,
    repair_interval: Duration,
    repair_semaphore: Arc<Semaphore>,
    repair_diagnostics: Arc<Mutex<VecDeque<RepairDiagnosticRecord>>>,
    read_diagnostics: Arc<Mutex<VecDeque<ReadDiagnosticRecord>>>,
    operation_lock: Arc<RwLock<()>>,
    compute_enabled: bool,
    compute_runtime: String,
    compute_work_dir: PathBuf,
    compute_semaphore: Arc<Semaphore>,
    compute_tasks: Arc<Mutex<HashMap<String, AbortHandle>>>,
    compute_state_lock: Arc<tokio::sync::Mutex<()>>,
    compute_queue_limit: usize,
    compute_queue_slots: Arc<Semaphore>,
    active_guest_cids: Arc<Mutex<HashMap<u32, String>>>,
    firecracker_binary: PathBuf,
    firecracker_jailer_binary: PathBuf,
    firecracker_enable_jailer: bool,
    firecracker_jailer_uid: u32,
    firecracker_jailer_gid: u32,
    firecracker_jailer_chroot_base: PathBuf,
    firecracker_strict_sandbox: bool,
    firecracker_allow_untrusted_rootfs: bool,
    firecracker_allowed_rootfs_cids: Arc<HashSet<Cid>>,
    firecracker_kernel_image: Option<PathBuf>,
    firecracker_memory_mib: u32,
    firecracker_vcpu_count: u8,
    firecracker_max_input_bytes: u64,
    firecracker_max_output_bytes: u64,
    firecracker_cgroup_enabled: bool,
    firecracker_cgroup_base: PathBuf,
    identity: NodeIdentity,
    api_bearer_token: Option<String>,
    s3: Option<Arc<S3RuntimeConfig>>,
    max_block_bytes: Option<u64>,
    max_object_bytes: Option<u64>,
    small_object_max_bytes: Option<u64>,
    small_object_pack: Option<SmallObjectPackConfig>,
    max_compute_timeout_seconds: Option<u64>,
    erasure_enabled: bool,
    erasure_min_size_bytes: u64,
    erasure_data_shards: u16,
    erasure_parity_shards: u16,
    erasure_planner: Arc<ErasurePlanner>,
    reconstructed_stripe_cache: Option<Arc<ReconstructedStripeCache>>,
    erasure_stripe_read_slots: Arc<Semaphore>,
    http_requests_per_minute: Option<u64>,
    http_concurrency: Arc<Semaphore>,
    http_rate_limits: Arc<Mutex<HashMap<String, RateLimitBucket>>>,
    erasure_repair_semaphore: Arc<Semaphore>,
    erasure_repair_bytes_per_second: u64,
    _identity_lock: Arc<std::fs::File>,
}

fn refresh_fast_path_placement(state: &AppState) {
    if let Some(runtime) = &state.fast_path {
        runtime.refresh_placement(state.placement.snapshot());
    }
}

fn cache_fast_path_bucket(state: &AppState, bucket: &str, namespace_id: &NamespaceId) {
    if let Some(runtime) = &state.fast_path {
        runtime.cache_bucket_namespace(bucket, namespace_id.clone());
    }
}

fn invalidate_fast_path_bucket(state: &AppState, bucket: &str) {
    if let Some(runtime) = &state.fast_path {
        runtime.invalidate_bucket_namespace(bucket);
    }
}

fn record_read_diagnostic(
    state: &AppState,
    mut record: ReadDiagnosticRecord,
) -> Result<(), ApiError> {
    record.sequence = READ_DIAGNOSTIC_COUNTER.fetch_add(1, Ordering::Relaxed);
    let record = match fast_path::record_read_diagnostic(record) {
        Ok(()) => return Ok(()),
        Err(record) => record,
    };
    let mut records = state
        .read_diagnostics
        .lock()
        .map_err(|_| ApiError::internal("read diagnostic lock poisoned"))?;
    if records.len() == 512 {
        records.pop_front();
    }
    records.push_back(record);
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct ReadDiagnosticRecord {
    sequence: u64,
    cid: Cid,
    source_node: String,
    route: String,
    verified_bytes: u64,
    timestamp_unix_seconds: i64,
}

#[derive(Debug, Clone, Serialize)]
struct RepairDiagnosticRecord {
    sequence: u64,
    cid: Cid,
    repair_kind: String,
    reason: String,
    source_node: Option<String>,
    destination_node: Option<String>,
    result: String,
    verified_bytes: u64,
    timestamp_unix_seconds: i64,
}

#[derive(Debug, Clone)]
struct RateLimitBucket {
    window_start_unix_seconds: i64,
    count: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct BlockPutQuery {
    replication_factor: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ObjectPutQuery {
    erasure_data_shards: Option<u16>,
    erasure_parity_shards: Option<u16>,
    pin: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct GcQuery {
    #[serde(default)]
    dry_run: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let config_path = args.config.unwrap_or_else(default_config_path);
    let loaded = load_from_path(&config_path).with_context(|| {
        format!(
            "failed to load configuration from {}",
            config_path.display()
        )
    })?;

    init_tracing(&loaded.config.logging.format);

    match args.command {
        Some(Command::Init) => init_node(loaded),
        Some(Command::Backup { output }) => backup_metadata(loaded, output),
        Some(Command::Restore { input, force }) => restore_metadata(loaded, input, force),
        None => {
            let runtime = control_runtime(&loaded.config.fast_path)?;
            runtime.block_on(run_agent(loaded))
        }
    }
}

fn control_runtime(config: &pepper_config::FastPathConfig) -> Result<tokio::runtime::Runtime> {
    let cpu_ids = fast_path::available_cpu_ids();
    let control_threads = if config.enabled {
        config.control_cores.min(cpu_ids.len()).max(1)
    } else {
        cpu_ids.len().max(1)
    };
    let control_cpus = Arc::new(
        cpu_ids
            .into_iter()
            .take(control_threads)
            .collect::<Vec<_>>(),
    );
    let next_cpu = Arc::new(AtomicU64::new(0));
    let pin_cpus = config.pin_cpus;
    let thread_cpus = control_cpus.clone();
    let thread_index = next_cpu.clone();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(control_threads)
        .thread_name("pepper-control")
        .on_thread_start(move || {
            if pin_cpus && !thread_cpus.is_empty() {
                let index = thread_index.fetch_add(1, Ordering::Relaxed) as usize;
                fast_path::pin_current_thread(thread_cpus[index % thread_cpus.len()]);
            }
        })
        .enable_all()
        .build()
        .context("failed to construct reserved Pepper control runtime")
}

fn load_cluster_secret(path: Option<&PathBuf>) -> Result<Option<Vec<u8>>> {
    match path {
        Some(path) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(path)
                    .with_context(|| {
                        format!("failed to stat cluster secret at {}", path.display())
                    })?
                    .permissions()
                    .mode()
                    & 0o777;
                anyhow::ensure!(
                    mode & 0o077 == 0,
                    "cluster secret permissions must be 0600 or stricter"
                );
            }
            let secret = std::fs::read(path)
                .with_context(|| format!("failed to read cluster secret at {}", path.display()))?;
            anyhow::ensure!(
                secret.len() >= 32,
                "cluster secret must contain at least 32 bytes"
            );
            Ok(Some(secret))
        }
        None => Ok(None),
    }
}

fn load_s3_secret(path: &PathBuf) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("failed to stat S3 secret at {}", path.display()))?
            .permissions()
            .mode()
            & 0o777;
        anyhow::ensure!(
            mode & 0o077 == 0,
            "S3 secret permissions must be 0600 or stricter"
        );
    }
    let mut secret = std::fs::read(path)
        .with_context(|| format!("failed to read S3 secret at {}", path.display()))?;
    while secret
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        secret.pop();
    }
    anyhow::ensure!(
        secret.len() >= 16,
        "S3 secret must contain at least 16 bytes"
    );
    Ok(secret)
}

fn init_tracing(format: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let registry = tracing_subscriber::registry().with(filter);
    if format == "json" {
        registry
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        registry.with(tracing_subscriber::fmt::layer()).init();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupManifestPayload {
    format_version: u32,
    node_id: String,
    public_key_hex: String,
    metadata_blake3: String,
    metadata_bytes: u64,
    schema_version: u32,
    created_at_unix_seconds: i64,
    requires_consensus_catch_up: bool,
    namespaces: Vec<pepper_consensus::NamespaceBackupRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupManifest {
    payload: BackupManifestPayload,
    signature_hex: String,
}

fn backup_manifest_path(path: &FsPath) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".manifest.json");
    PathBuf::from(value)
}

fn hash_file(path: &FsPath) -> Result<(String, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes.saturating_add(read as u64);
        hasher.update(&buffer[..read]);
    }
    Ok((hasher.finalize().to_hex().to_string(), bytes))
}

fn acquire_identity_lock(loaded: &LoadedConfig) -> Result<Arc<std::fs::File>> {
    let key_path = loaded.config.identity_key_path();
    let mut lock_path = key_path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock_path = PathBuf::from(lock_path);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    file.try_lock_exclusive().with_context(|| {
        format!(
            "node identity is already active; refusing a second process for {}",
            key_path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(Arc::new(file))
}

fn backup_metadata(loaded: LoadedConfig, output: PathBuf) -> Result<()> {
    let _identity_lock = acquire_identity_lock(&loaded)?;
    let metadata_path = loaded.config.metadata_path();
    anyhow::ensure!(
        metadata_path.is_file(),
        "metadata database does not exist at {}",
        metadata_path.display()
    );
    let metadata_check = Arc::new(MetadataStore::open_or_create(&metadata_path).with_context(
        || {
            format!(
                "metadata database {} must be available exclusively; stop the agent before backup",
                metadata_path.display()
            )
        },
    )?);
    let backup_info = metadata_check
        .backup_info()
        .context("failed to verify metadata before backup")?;
    let namespaces = pepper_consensus::inspect_namespace_backup_records(&metadata_check)?;
    drop(metadata_check);
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = std::fs::copy(&metadata_path, &output)?;
    let (metadata_blake3, metadata_bytes) = hash_file(&output)?;
    let identity = NodeIdentity::load_or_generate(loaded.config.identity_key_path(), false)?;
    let payload = BackupManifestPayload {
        format_version: 1,
        node_id: identity.node_id().to_string(),
        public_key_hex: hex::encode(identity.public_key_bytes()),
        metadata_blake3,
        metadata_bytes,
        schema_version: backup_info.schema_version,
        created_at_unix_seconds: unix_seconds(),
        requires_consensus_catch_up: !namespaces.is_empty(),
        namespaces,
    };
    let signature_hex = hex::encode(identity.sign(&serde_json::to_vec(&payload)?));
    let manifest = BackupManifest {
        payload,
        signature_hex,
    };
    let manifest_path = backup_manifest_path(&output);
    let mut manifest_file = std::fs::File::create(&manifest_path)?;
    manifest_file.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
    manifest_file.sync_all()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status":"ok", "source":metadata_path, "output":output, "manifest":manifest_path,
            "bytes":bytes, "source_bytes":backup_info.file_bytes, "schema_version":backup_info.schema_version,
            "namespace_count":manifest.payload.namespaces.len()
        }))?
    );
    Ok(())
}

fn restore_metadata(loaded: LoadedConfig, input: PathBuf, force: bool) -> Result<()> {
    anyhow::ensure!(
        force,
        "restore replaces local consensus metadata; pass --force after stopping the node"
    );
    let _identity_lock = acquire_identity_lock(&loaded)?;
    let identity = NodeIdentity::load_or_generate(loaded.config.identity_key_path(), false)
        .context("restore requires an initialized local node identity")?;
    let manifest_path = backup_manifest_path(&input);
    let manifest: BackupManifest = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    anyhow::ensure!(
        manifest.payload.format_version == 1,
        "unsupported backup manifest version"
    );
    anyhow::ensure!(
        manifest.payload.node_id == identity.node_id(),
        "backup belongs to a different node identity"
    );
    anyhow::ensure!(
        manifest.payload.public_key_hex == hex::encode(identity.public_key_bytes()),
        "backup public key does not match local identity"
    );
    let signature: [u8; 64] = hex::decode(&manifest.signature_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid backup signature length"))?;
    anyhow::ensure!(
        verify_signature(
            &identity.public_key_bytes(),
            &serde_json::to_vec(&manifest.payload)?,
            &signature
        ),
        "backup manifest signature is invalid"
    );
    let (digest, bytes) = hash_file(&input)?;
    anyhow::ensure!(
        digest == manifest.payload.metadata_blake3 && bytes == manifest.payload.metadata_bytes,
        "backup metadata hash or size does not match manifest"
    );
    let backup_store =
        MetadataStore::open_or_create(&input).context("backup metadata verification failed")?;
    anyhow::ensure!(
        backup_store.schema_version() == manifest.payload.schema_version,
        "backup schema does not match manifest"
    );
    backup_store.backup_info()?;
    drop(backup_store);
    loaded.config.ensure_directories()?;
    let target = loaded.config.metadata_path();
    if target.exists() {
        let current = MetadataStore::open_or_create(&target)
            .context("local metadata is in use; stop the node before restore")?;
        drop(current);
    }
    let temporary = target.with_extension("redb.restore.tmp");
    std::fs::copy(&input, &temporary)?;
    std::fs::File::open(&temporary)?.sync_all()?;
    std::fs::rename(&temporary, &target)?;
    if let Some(parent) = target.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status":"ok", "input":input, "target":target, "node_id":identity.node_id(),
            "namespace_count":manifest.payload.namespaces.len(), "requires_consensus_catch_up":manifest.payload.requires_consensus_catch_up
        }))?
    );
    Ok(())
}

fn init_node(loaded: LoadedConfig) -> Result<()> {
    loaded
        .config
        .ensure_directories()
        .context("failed to create node directories")?;
    let key_path = loaded.config.identity_key_path();
    let identity =
        NodeIdentity::load_or_generate(&key_path, loaded.config.identity.generate_if_missing)
            .with_context(|| format!("failed to initialize identity at {}", key_path.display()))?;
    let metadata_path = loaded.config.metadata_path();
    let metadata = Arc::new(
        MetadataStore::open_or_create(&metadata_path).with_context(|| {
            format!(
                "failed to initialize metadata store at {}",
                metadata_path.display()
            )
        })?,
    );
    let _block_store = BlockStore::open_with_config(
        metadata.clone(),
        &loaded.config.storage,
        loaded
            .config
            .limits
            .max_block_bytes
            .unwrap_or(DEFAULT_MAX_BLOCK_BYTES),
    )
    .context("failed to initialize local block store")?;
    let status = InitStatus {
        name: loaded.config.node.name.clone(),
        node_id: identity.node_id().to_string(),
        data_path: loaded.config.data.path.display().to_string(),
        identity_key_path: key_path.display().to_string(),
        metadata_path: metadata.path().display().to_string(),
        schema_version: metadata.schema_version(),
    };
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

async fn run_agent(loaded: LoadedConfig) -> Result<()> {
    let identity_lock = acquire_identity_lock(&loaded)?;
    loaded
        .config
        .ensure_directories()
        .context("failed to create node directories")?;
    let key_path = loaded.config.identity_key_path();
    let identity =
        NodeIdentity::load_or_generate(&key_path, loaded.config.identity.generate_if_missing)
            .with_context(|| format!("failed to load identity at {}", key_path.display()))?;
    let metadata_path = loaded.config.metadata_path();
    let metadata = Arc::new(
        MetadataStore::open_or_create(&metadata_path).with_context(|| {
            format!(
                "failed to open metadata store at {}",
                metadata_path.display()
            )
        })?,
    );
    let block_store = Arc::new(
        BlockStore::open_with_config(
            metadata.clone(),
            &loaded.config.storage,
            loaded
                .config
                .limits
                .max_block_bytes
                .unwrap_or(DEFAULT_MAX_BLOCK_BYTES),
        )
        .context("failed to open local block store")?,
    );
    let operation_lock = Arc::new(RwLock::new(()));
    let local_block_writer = BlockBatchWriter::normal(block_store.clone());
    let placement = Arc::new(PlacementRuntime::default());
    let replica_block_writer = BlockBatchWriter::replica(block_store.clone());
    let network_block_service = Arc::new(AgentBlockService {
        block_store: block_store.clone(),
        replica_writer: replica_block_writer.clone(),
        operation_lock: operation_lock.clone(),
    });
    let cluster_secret = load_cluster_secret(loaded.config.auth.cluster_secret_path.as_ref())?;
    let s3 = if loaded.config.s3.enabled {
        let path = loaded
            .config
            .s3
            .secret_access_key_path
            .as_ref()
            .context("s3.secret_access_key_path is required when S3 is enabled")?;
        Some(Arc::new(S3RuntimeConfig {
            region: loaded.config.s3.region.clone(),
            access_key_id: loaded
                .config
                .s3
                .access_key_id
                .clone()
                .context("s3.access_key_id is required when S3 is enabled")?,
            secret_access_key: load_s3_secret(path)?,
            max_clock_skew_seconds: loaded.config.s3.max_clock_skew_seconds,
            bucket_partitions: usize::from(loaded.config.s3.bucket_partitions),
            bucket_create_lock: Arc::new(tokio::sync::Mutex::new(())),
            bucket_catalog_lock: Arc::new(tokio::sync::Mutex::new(())),
            placement_map_lock: Arc::new(tokio::sync::Mutex::new(())),
            multipart_lock: Arc::new(tokio::sync::Mutex::new(())),
        }))
    } else {
        None
    };
    let p2p_addr: SocketAddr = loaded
        .config
        .node
        .listen_addr
        .parse()
        .context("node.listen_addr should have been validated as a socket address")?;
    anyhow::ensure!(
        p2p_addr.ip().is_loopback() || cluster_secret.is_some(),
        "auth.cluster_secret_path is required when the P2P listener is not loopback"
    );
    let advertise_addr: SocketAddr = loaded
        .config
        .node
        .advertise_addr
        .as_deref()
        .unwrap_or(&loaded.config.node.listen_addr)
        .parse()
        .context("node advertise address should have been validated")?;
    let bulk_p2p_addr: SocketAddr = loaded
        .config
        .node
        .bulk_listen_addr
        .as_deref()
        .map(str::parse)
        .transpose()
        .context("node.bulk_listen_addr should have been validated")?
        .unwrap_or_else(|| {
            SocketAddr::new(
                p2p_addr.ip(),
                p2p_addr
                    .port()
                    .checked_add(1)
                    .expect("bulk listener derivation was validated"),
            )
        });
    let bulk_advertise_addr: SocketAddr = loaded
        .config
        .node
        .bulk_advertise_addr
        .as_deref()
        .map(str::parse)
        .transpose()
        .context("node.bulk_advertise_addr should have been validated")?
        .unwrap_or_else(|| {
            SocketAddr::new(
                advertise_addr.ip(),
                advertise_addr
                    .port()
                    .checked_add(1)
                    .expect("bulk advertise derivation was validated"),
            )
        });
    let storage_summary = block_store
        .storage_summary()
        .context("failed to summarize local storage")?;
    let network = NetworkHandle::start(
        NetworkConfig {
            node_name: loaded.config.node.name.clone(),
            listen_addr: p2p_addr,
            advertise_addr,
            bulk_listen_addr: bulk_p2p_addr,
            bulk_advertise_addr,
            bulk_worker_threads: loaded.config.network.bulk.worker_threads,
            bulk_inbound_connections: loaded.config.network.bulk.inbound_connections,
            bulk_streams_per_connection: loaded.config.network.bulk.streams_per_connection,
            bulk_send_window_bytes: loaded.config.network.bulk.send_window_bytes,
            bulk_connection_receive_window_bytes: loaded
                .config
                .network
                .bulk
                .connection_receive_window_bytes,
            bulk_stream_receive_window_bytes: loaded
                .config
                .network
                .bulk
                .stream_receive_window_bytes,
            bulk_request_timeout_seconds: loaded.config.network.bulk.request_timeout_seconds,
            bulk_max_bytes_per_second: loaded.config.network.bulk.max_bytes_per_second,
            bulk_bandwidth_burst_bytes: loaded.config.network.bulk.bandwidth_burst_bytes,
            bootstrap_peers: loaded.config.network.bootstrap_peers.clone(),
            cluster_secret,
            requests_per_minute: loaded.config.limits.rpc_requests_per_minute,
            failure_domain: loaded.config.node.failure_domain.clone(),
            placement_labels: loaded
                .config
                .node
                .placement_labels
                .clone()
                .into_iter()
                .collect(),
            storage_capacity_bytes: storage_summary.capacity_bytes,
            storage_available_bytes: storage_summary.available_bytes,
            namespace_consensus_enabled: loaded.config.namespace.consensus_enabled,
            namespace_group_capacity: loaded.config.namespace.max_namespace_groups as u64,
            namespace_group_count: 0,
            max_consensus_log_bytes: loaded.config.namespace.max_consensus_log_bytes,
            max_namespace_write_rate: loaded.config.namespace.max_namespace_write_rate,
        },
        identity.clone(),
        metadata.clone(),
        network_block_service,
    )
    .await
    .context("failed to start P2P network")?;
    let fast_path = if loaded.config.fast_path.enabled && loaded.config.s3.enabled {
        Some(FastPathRuntime::start(
            &loaded.config.fast_path,
            block_store.clone(),
            placement.snapshot(),
            Some(&network),
        )?)
    } else {
        None
    };

    let started_at = OffsetDateTime::now_utc();
    let status = NodeStatus {
        name: loaded.config.node.name.clone(),
        node_id: identity.node_id().to_string(),
        started_at,
        uptime_seconds: 0,
        schema_version: metadata.schema_version(),
        config: loaded.config.summary(&loaded.path),
    };
    let mut dag_registry = pepper_dag::builtin_registry();
    dag_registry
        .register(FilesystemRootCodecHandler)
        .expect("filesystem root codec must be registered exactly once");
    dag_registry
        .register(FilesystemInodeCodecHandler)
        .expect("filesystem inode codec must be registered exactly once");
    dag_registry
        .register(BucketObjectCodecHandler)
        .expect("bucket object codec must be registered exactly once");
    dag_registry
        .register(S3ListBarrierCodecHandler)
        .expect("bucket partition barrier codec must be registered exactly once");
    dag_registry
        .register(SmallObjectExtentIndexCodecHandler)
        .expect("small-object extent index codec must be registered exactly once");
    dag_registry
        .register(MerkleNodeCodecHandler)
        .expect("Merkle node codec must be registered exactly once");
    dag_registry
        .register(NamespaceDescriptorCodecHandler)
        .expect("namespace descriptor codec must be registered exactly once");
    dag_registry
        .register(NamespaceCheckpointCodecHandler)
        .expect("namespace checkpoint codec must be registered exactly once");
    dag_registry
        .register(NamespaceCommitCodecHandler)
        .expect("namespace commit codec must be registered exactly once");
    let namespace_data_store =
        ConsensusDataStore::from_networked_block_store(block_store.clone(), network.clone());
    let namespace_groups =
        if loaded.config.namespace.enabled && loaded.config.namespace.consensus_enabled {
            Some(Arc::new(
                NamespaceGroupManager::new_networked_with_data_store(
                    identity.node_id().to_string(),
                    metadata.clone(),
                    network.clone(),
                    namespace_data_store.clone(),
                    ConsensusConfig {
                        heartbeat_interval_ms: loaded.config.namespace.heartbeat_interval_ms,
                        election_timeout_min_ms: loaded.config.namespace.election_timeout_min_ms,
                        election_timeout_max_ms: loaded.config.namespace.election_timeout_max_ms,
                        snapshot_after_logs: loaded.config.namespace.snapshot_after_logs,
                        max_logs_after_snapshot: loaded.config.namespace.max_logs_after_snapshot,
                        checkpoint_log_bytes: loaded.config.namespace.checkpoint_log_bytes,
                        checkpoint_restore_target_ms: loaded
                            .config
                            .namespace
                            .checkpoint_restore_target_ms,
                        max_namespace_groups: loaded.config.namespace.max_namespace_groups,
                        max_consensus_log_bytes: loaded.config.namespace.max_consensus_log_bytes,
                        max_namespace_write_rate: loaded.config.namespace.max_namespace_write_rate,
                        max_command_bytes: loaded.config.namespace.max_consensus_command_bytes,
                    },
                )?,
            ))
        } else {
            None
        };
    if let Some(groups) = &namespace_groups {
        groups
            .recover_assigned_groups()
            .await
            .context("failed to recover assigned namespace groups before serving")?;
        network.set_namespace_service(groups.clone()).await;
    }
    let publication_limits = PublicationLimits {
        max_staging_leases: loaded.config.namespace.max_staging_leases,
        max_staging_bytes: loaded.config.namespace.max_staging_bytes,
        max_staging_ttl_seconds: loaded.config.namespace.staging_ttl_seconds as i64,
        max_read_ttl_seconds: loaded.config.namespace.read_lease_ttl_seconds as i64,
        ..PublicationLimits::default()
    };
    let publication_repository = PublicationRepository::new(metadata.clone(), publication_limits)?;
    let reconstructed_stripe_cache =
        ReconstructedStripeCache::open(&loaded.config.erasure.reconstructed_cache)
            .map_err(anyhow::Error::msg)?
            .map(Arc::new);
    let state = AppState {
        status: Arc::new(status),
        metadata: metadata.clone(),
        block_store,
        dag_registry: Arc::new(dag_registry),
        network,
        namespace_groups,
        namespace_data_store,
        publication_repository,
        _publication_limits: publication_limits,
        namespace_log_bytes: loaded.config.namespace.max_consensus_log_bytes,
        replication_factor: loaded.config.replication.default_factor as usize,
        placement,
        fast_path,
        local_block_writer,
        repair_block_writer: replica_block_writer,
        replicated_block_slots: Arc::new(Semaphore::new(REPLICATED_BLOCK_CONCURRENCY)),
        s3_write_slots: Arc::new(Semaphore::new(
            loaded
                .config
                .limits
                .s3_write_concurrency
                .unwrap_or(S3_WRITE_CONCURRENCY),
        )),
        s3_write_capacity: loaded
            .config
            .limits
            .s3_write_concurrency
            .unwrap_or(S3_WRITE_CONCURRENCY),
        s3_write_queue_slots: Arc::new(Semaphore::new(
            loaded
                .config
                .limits
                .s3_write_queue_depth
                .unwrap_or(S3_WRITE_QUEUE_DEPTH),
        )),
        s3_write_queue_timeout: Duration::from_millis(
            loaded
                .config
                .limits
                .s3_write_queue_timeout_ms
                .unwrap_or(S3_WRITE_QUEUE_TIMEOUT_MS),
        ),
        s3_write_service_micros: Arc::new(AtomicU64::new(S3_WRITE_INITIAL_SERVICE_MICROS)),
        s3_list_cache: Arc::new(S3ListCache::default()),
        repair_interval: Duration::from_secs(loaded.config.replication.repair_interval_seconds),
        repair_semaphore: Arc::new(Semaphore::new(1)),
        repair_diagnostics: Arc::new(Mutex::new(VecDeque::with_capacity(512))),
        read_diagnostics: Arc::new(Mutex::new(VecDeque::with_capacity(512))),
        operation_lock,
        compute_enabled: loaded.config.compute.enabled,
        compute_runtime: loaded.config.compute.runtime.clone(),
        compute_work_dir: loaded.config.compute.work_dir.clone(),
        compute_semaphore: Arc::new(Semaphore::new(loaded.config.compute.max_concurrent_jobs)),
        compute_tasks: Arc::new(Mutex::new(HashMap::new())),
        compute_state_lock: Arc::new(tokio::sync::Mutex::new(())),
        compute_queue_limit: loaded
            .config
            .compute
            .max_concurrent_jobs
            .saturating_mul(16)
            .max(16),
        compute_queue_slots: Arc::new(Semaphore::new(
            loaded
                .config
                .compute
                .max_concurrent_jobs
                .saturating_mul(16)
                .max(16),
        )),
        active_guest_cids: Arc::new(Mutex::new(HashMap::new())),
        firecracker_binary: loaded.config.compute.firecracker_binary.clone(),
        firecracker_jailer_binary: loaded.config.compute.firecracker_jailer_binary.clone(),
        firecracker_enable_jailer: loaded.config.compute.firecracker_enable_jailer,
        firecracker_jailer_uid: loaded.config.compute.firecracker_jailer_uid,
        firecracker_jailer_gid: loaded.config.compute.firecracker_jailer_gid,
        firecracker_jailer_chroot_base: loaded
            .config
            .compute
            .firecracker_jailer_chroot_base
            .clone(),
        firecracker_strict_sandbox: loaded.config.compute.firecracker_strict_sandbox,
        firecracker_allow_untrusted_rootfs: loaded
            .config
            .compute
            .firecracker_allow_untrusted_rootfs,
        firecracker_allowed_rootfs_cids: Arc::new(
            loaded
                .config
                .compute
                .firecracker_allowed_rootfs_cids
                .iter()
                .cloned()
                .collect(),
        ),
        firecracker_kernel_image: loaded.config.compute.firecracker_kernel_image.clone(),
        firecracker_memory_mib: loaded.config.compute.firecracker_memory_mib,
        firecracker_vcpu_count: loaded.config.compute.firecracker_vcpu_count,
        firecracker_max_input_bytes: loaded.config.compute.firecracker_max_input_bytes,
        firecracker_max_output_bytes: loaded.config.compute.firecracker_max_output_bytes,
        firecracker_cgroup_enabled: loaded.config.compute.firecracker_cgroup_enabled,
        firecracker_cgroup_base: loaded.config.compute.firecracker_cgroup_base.clone(),
        identity: identity.clone(),
        api_bearer_token: loaded.config.auth.api_bearer_token.clone(),
        s3,
        max_block_bytes: Some(
            loaded
                .config
                .limits
                .max_block_bytes
                .unwrap_or(DEFAULT_MAX_BLOCK_BYTES),
        ),
        max_object_bytes: Some(
            loaded
                .config
                .limits
                .max_object_bytes
                .unwrap_or(DEFAULT_MAX_OBJECT_BYTES),
        ),
        small_object_max_bytes: loaded
            .config
            .storage
            .small_object_pack
            .enabled
            .then_some(loaded.config.storage.small_object_pack.max_object_bytes),
        small_object_pack: loaded
            .config
            .storage
            .small_object_pack
            .enabled
            .then(|| loaded.config.storage.small_object_pack.clone()),
        max_compute_timeout_seconds: loaded.config.limits.max_compute_timeout_seconds,
        erasure_enabled: loaded.config.erasure.enabled,
        erasure_min_size_bytes: loaded.config.erasure.min_size_bytes,
        erasure_data_shards: loaded.config.erasure.data_shards,
        erasure_parity_shards: loaded.config.erasure.parity_shards,
        erasure_planner: Arc::new(ErasurePlanner::new(loaded.config.erasure.transfer.clone())),
        reconstructed_stripe_cache,
        erasure_stripe_read_slots: Arc::new(Semaphore::new(
            loaded
                .config
                .limits
                .erasure_read_max_concurrent_stripes
                .unwrap_or(ERASURE_STRIPE_READ_CONCURRENCY),
        )),
        http_requests_per_minute: loaded.config.limits.http_requests_per_minute,
        http_concurrency: Arc::new(Semaphore::new(
            loaded
                .config
                .limits
                .s3_http_concurrency
                .unwrap_or(S3_HTTP_CONCURRENCY),
        )),
        http_rate_limits: Arc::new(Mutex::new(HashMap::new())),
        erasure_repair_semaphore: Arc::new(Semaphore::new(
            loaded
                .config
                .limits
                .erasure_repair_max_concurrent_shards
                .unwrap_or(2),
        )),
        erasure_repair_bytes_per_second: loaded
            .config
            .limits
            .erasure_repair_bytes_per_second
            .unwrap_or(ERASURE_REPAIR_BYTES_PER_SECOND),
        _identity_lock: identity_lock,
    };

    state
        .network
        .set_erasure_service(Arc::new(AgentErasureService {
            state: state.clone(),
        }))
        .await;
    state
        .network
        .set_compute_service(Arc::new(AgentComputeService {
            state: state.clone(),
        }))
        .await;
    state
        .network
        .set_pin_service(Arc::new(AgentPinService {
            state: state.clone(),
        }))
        .await;
    state
        .network
        .set_namespace_alias_service(Arc::new(AgentNamespaceAliasService {
            state: state.clone(),
        }))
        .await;

    recover_compute_jobs(&state).map_err(|error| anyhow::anyhow!(error.message))?;
    initialize_repair_inventory_tables(&state).map_err(|error| anyhow::anyhow!(error.message))?;
    spawn_repair_loop(state.clone());
    spawn_publication_reconciler(state.clone());
    spawn_s3_lifecycle_reconciler(state.clone());
    spawn_s3_placement_refresh_loop(state.clone());
    spawn_small_object_pack_loop(state.clone());

    let shutdown_state = state.clone();
    let app = http::router(state);

    let addr: SocketAddr = loaded
        .config
        .api
        .bind_addr
        .parse()
        .context("api.bind_addr should have been validated as a socket address")?;
    anyhow::ensure!(
        addr.ip().is_loopback() || loaded.config.api.allow_insecure_remote,
        "the built-in HTTP API must bind to loopback unless api.allow_insecure_remote is explicitly enabled"
    );
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind local HTTP API at {addr}"))?;
    let actual_addr = listener.local_addr()?;

    info!(
        node_id = identity.node_id(),
        node_name = loaded.config.node.name,
        api_addr = %actual_addr,
        metadata_path = %metadata.path().display(),
        "pepper agent started"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server failed")?;

    shutdown_state.network.shutdown();
    if let Ok(mut tasks) = shutdown_state.compute_tasks.lock() {
        for (_, handle) in tasks.drain() {
            handle.abort();
        }
    }
    info!("pepper agent stopped");
    Ok(())
}

async fn node_status(State(state): State<AppState>) -> Json<NodeStatus> {
    let mut status = (*state.status).clone();
    status.uptime_seconds = (OffsetDateTime::now_utc() - status.started_at)
        .whole_seconds()
        .max(0) as u64;
    Json(status)
}

async fn node_peers(State(state): State<AppState>) -> Json<Vec<PeerStatus>> {
    Json(state.network.peers().await)
}

async fn put_block(
    State(state): State<AppState>,
    Query(query): Query<BlockPutQuery>,
    body: Body,
) -> Result<Json<DurabilityReceipt>, ApiError> {
    let _guard = state.operation_lock.read().await;
    let replication_factor = query.replication_factor.unwrap_or(state.replication_factor);
    if !(1..=32).contains(&replication_factor) {
        return Err(ApiError::bad_request(
            "block replication_factor must be between 1 and 32",
        ));
    }
    let body = read_body_limited(body, state.max_block_bytes, "block").await?;
    let receipt =
        put_replicated_block_with_factor(&state, CODEC_RAW, body, replication_factor).await?;
    ensure_implicit_pin_with_factor(&state, &receipt.cid, replication_factor).await?;
    Ok(Json(receipt))
}

async fn get_block(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> Result<Response, ApiError> {
    let _guard = state.operation_lock.read().await;
    let cid = BlockStore::parse_cid(&cid)?;
    let block = get_block_resolved(&state, &cid).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        "x-pepper-cid",
        HeaderValue::from_str(&block.cid.to_string()).map_err(ApiError::header)?,
    );
    headers.insert(
        "x-pepper-codec",
        HeaderValue::from_str(&block.codec.canonical_display()).map_err(ApiError::header)?,
    );
    Ok((headers, block.payload).into_response())
}

async fn get_block_resolved(state: &AppState, cid: &Cid) -> Result<pepper_types::Block, ApiError> {
    get_block_resolved_with_policy(state, cid, true).await
}

async fn get_block_resolved_transient(
    state: &AppState,
    cid: &Cid,
) -> Result<pepper_types::Block, ApiError> {
    get_block_resolved_with_policy(state, cid, false).await
}

async fn get_block_at_placement(
    state: &AppState,
    cid: &Cid,
    reference: &PlacementReference,
) -> Result<pepper_types::Block, ApiError> {
    if state.s3.is_none() && state.placement.map(reference.epoch).is_none() {
        return get_block_resolved_transient(state, cid).await;
    }
    let node_ids = placement_target_node_ids(state, cid, reference).await?;
    get_block_with_placement_fallback(state, cid, reference, node_ids).await
}

async fn placement_target_node_ids(
    state: &AppState,
    cid: &Cid,
    reference: &PlacementReference,
) -> Result<Vec<String>, ApiError> {
    if reference.seed != *cid && reference.role == PlacementRole::Replicated {
        return Err(ApiError::bad_request(
            "replicated placement reference does not match block CID",
        ));
    }
    if state.placement.map(reference.epoch).is_none() && state.s3.is_some() {
        s3_api::ensure_s3_placement_epoch_loaded(state, reference.epoch).await?;
    }
    metrics::PLACEMENT_CALCULATIONS.fetch_add(1, Ordering::Relaxed);
    let decision = state
        .placement
        .decide(reference)
        .map_err(authoritative_placement_error)?;
    Ok(decision.node_ids)
}

async fn get_block_with_placement_fallback(
    state: &AppState,
    cid: &Cid,
    reference: &PlacementReference,
    canonical_node_ids: Vec<String>,
) -> Result<pepper_types::Block, ApiError> {
    let canonical_error =
        match get_block_from_placement_targets(state, cid, canonical_node_ids.clone()).await {
            Ok(block) => return Ok(block),
            Err(error) => error,
        };
    if let Some(exception) = state
        .placement
        .exception(reference, unix_seconds())
        .filter(|exception| exception.block_cid == *cid)
    {
        let exception_nodes = exception
            .node_ids
            .into_iter()
            .filter(|node_id| !canonical_node_ids.contains(node_id))
            .collect::<Vec<_>>();
        if !exception_nodes.is_empty() {
            metrics::PLACEMENT_EXCEPTION_HITS.fetch_add(1, Ordering::Relaxed);
            return get_block_from_placement_targets(state, cid, exception_nodes).await;
        }
    }
    Err(canonical_error)
}

async fn get_block_from_placement_targets(
    state: &AppState,
    cid: &Cid,
    node_ids: Vec<String>,
) -> Result<pepper_types::Block, ApiError> {
    let local_node_id = state.network.local_descriptor().node_id;
    let local_error = if node_ids.contains(&local_node_id) {
        match tokio::task::block_in_place(|| state.block_store.get(cid)) {
            Ok(block) => return Ok(block),
            Err(StorageError::NotFound(_)) | Err(StorageError::HashMismatch(_)) => Some(format!(
                "authoritative placement node {local_node_id} does not hold {cid}"
            )),
            Err(error) => return Err(ApiError::from(error)),
        }
    } else {
        None
    };
    let remote_node_ids = node_ids
        .into_iter()
        .filter(|node_id| node_id != &local_node_id)
        .collect::<Vec<_>>();
    if !remote_node_ids.is_empty() {
        metrics::PLACEMENT_DIRECT_TARGET_ATTEMPTS
            .fetch_add(remote_node_ids.len() as u64, Ordering::Relaxed);
    }
    let remote_result = if remote_node_ids.is_empty() {
        Err(local_error.unwrap_or_else(|| format!("no authoritative placement holds {cid}")))
    } else {
        fetch_block_from_replica_targets(state, cid, remote_node_ids, Duration::from_secs(5)).await
    };
    match remote_result {
        Ok((node_id, payload)) => {
            metrics::PLACEMENT_DIRECT_TARGET_BYTES
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
            record_read_diagnostic(
                state,
                ReadDiagnosticRecord {
                    sequence: 0,
                    cid: cid.clone(),
                    source_node: node_id,
                    route: "direct_placement".to_string(),
                    verified_bytes: payload.len() as u64,
                    timestamp_unix_seconds: unix_seconds(),
                },
            )?;
            Ok(pepper_types::Block {
                cid: cid.clone(),
                codec: cid.codec,
                size: payload.len() as u64,
                payload,
            })
        }
        Err(error) => {
            metrics::PLACEMENT_DIRECT_TARGET_ERRORS.fetch_add(1, Ordering::Relaxed);
            Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Unavailable,
                error,
            ))
        }
    }
}

/// Fetch a block from the first healthy authoritative replica within one
/// request-wide deadline. Starting all replica reads together prevents a dead
/// target from charging its timeout once for every node in a Merkle traversal.
async fn fetch_block_from_replica_targets(
    state: &AppState,
    cid: &Cid,
    node_ids: Vec<String>,
    deadline: Duration,
) -> Result<(String, Vec<u8>), String> {
    let mut fetches = stream::FuturesUnordered::new();
    let mut unique = HashSet::new();
    for node_id in node_ids {
        if !unique.insert(node_id.clone()) {
            continue;
        }
        let network = fast_path::io_network(&state.network);
        let cid = cid.clone();
        fetches.push(async move {
            let Some(address) = fast_path::peer_address(&network, &node_id).await else {
                return (
                    node_id.clone(),
                    Err(format!("replica {node_id} has no routable bulk address")),
                );
            };
            let result = network
                .block_get(address, &cid)
                .await
                .map_err(|error| error.to_string());
            (node_id, result)
        });
    }
    if fetches.is_empty() {
        return Err(format!("no remote authoritative replica holds {cid}"));
    }

    match time::timeout(deadline, async {
        let mut last_error = None;
        while let Some((node_id, result)) = fetches.next().await {
            match result {
                Ok(payload) => return Ok((node_id, payload)),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| format!("no authoritative replica holds {cid}")))
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(format!(
            "authoritative replicas did not return {cid} within {}ms",
            deadline.as_millis()
        )),
    }
}

/// Fetch namespace state-machine data from the leader first, hedging to the
/// remaining voters after a short delay or an immediate failure. A newly
/// committed Merkle node is present on the leader before a routed head can
/// expose it, but an unreachable former leader must not consume the complete
/// request deadline and prevent a healthy voter from serving the block.
async fn fetch_block_from_ordered_replica_targets(
    state: &AppState,
    namespace_id: &str,
    cid: &Cid,
    node_ids: Vec<String>,
    deadline: Duration,
) -> Result<(String, Vec<u8>), String> {
    let mut unique = HashSet::new();
    let network = fast_path::io_network(&state.network);
    let candidates = node_ids
        .into_iter()
        .filter(|node_id| unique.insert(node_id.clone()))
        .collect::<Vec<_>>();
    let Some((first, remaining)) = candidates.split_first() else {
        return Err(format!("no authoritative replica holds {cid}"));
    };
    let fetch = |node_id: String| {
        let network = network.clone();
        let cid = cid.clone();
        async move {
            let Some(address) = fast_path::peer_address(&network, &node_id).await else {
                return (
                    node_id.clone(),
                    Err(format!("replica {node_id} has no routable bulk address")),
                );
            };
            let result = network
                .block_get(address, &cid)
                .await
                .map_err(|error| error.to_string());
            (node_id, result)
        }
    };
    let mut fetches = stream::FuturesUnordered::new();
    fetches.push(fetch(first.clone()));
    let mut remaining = Some(remaining.to_vec());
    match time::timeout(deadline, async {
        let mut last_error = None;
        let hedge = time::sleep(Duration::from_millis(100));
        tokio::pin!(hedge);
        loop {
            tokio::select! {
                result = fetches.next() => {
                    let Some((node_id, result)) = result else {
                        return Err(last_error.unwrap_or_else(|| {
                            format!("no authoritative replica holds {cid}")
                        }));
                    };
                    match result {
                        Ok(payload) => return Ok((node_id, payload)),
                        Err(error) => {
                            warn!(
                                namespace_id,
                                cid = %cid,
                                target_node_id = %node_id,
                                error = %error,
                                "namespace Merkle read target missed"
                            );
                            last_error = Some(error);
                            if let Some(remaining) = remaining.take() {
                                for node_id in remaining {
                                    fetches.push(fetch(node_id));
                                }
                            }
                        }
                    }
                }
                _ = &mut hedge, if remaining.is_some() => {
                    for node_id in remaining.take().expect("hedge candidates exist") {
                        fetches.push(fetch(node_id));
                    }
                }
            }
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(format!(
            "authoritative replicas did not return {cid} within {}ms",
            deadline.as_millis()
        )),
    }
}

async fn get_block_resolved_with_policy(
    state: &AppState,
    cid: &Cid,
    persist_remote: bool,
) -> Result<pepper_types::Block, ApiError> {
    match tokio::task::block_in_place(|| state.block_store.get(cid)) {
        Ok(block) => Ok(block),
        Err(StorageError::NotFound(_)) | Err(StorageError::HashMismatch(_)) => {
            let Some(resolution) = fast_path::io_network(&state.network)
                .get_block_from_any_peer_with_source(cid)
                .await?
            else {
                return Err(ApiError::from(StorageError::NotFound(cid.clone())));
            };
            let payload = resolution.payload;
            if !cid.verify(&payload) {
                return Err(ApiError::network(NetworkError::BlockService(
                    "remote block hash mismatch".to_string(),
                )));
            }
            if persist_remote {
                let repaired = state.block_store.put_replica(cid.codec, &payload)?;
                if repaired.cid != *cid {
                    return Err(ApiError::internal("recovered block CID mismatch"));
                }
            }
            record_read_diagnostic(
                state,
                ReadDiagnosticRecord {
                    sequence: 0,
                    cid: cid.clone(),
                    source_node: resolution.source_node_id,
                    route: resolution.route,
                    verified_bytes: payload.len() as u64,
                    timestamp_unix_seconds: unix_seconds(),
                },
            )?;
            Ok(pepper_types::Block {
                cid: cid.clone(),
                codec: cid.codec,
                size: payload.len() as u64,
                payload,
            })
        }
        Err(error) => Err(ApiError::from(error)),
    }
}

async fn get_block_range_at_placement(
    state: &AppState,
    cid: &Cid,
    placement: &PlacementReference,
    start: u64,
    end: u64,
) -> Result<Vec<u8>, ApiError> {
    if state.s3.is_none() && state.placement.map(placement.epoch).is_none() {
        let block = get_block_resolved_transient(state, cid).await?;
        let start = usize::try_from(start)
            .map_err(|_| ApiError::bad_request("block range start is too large"))?;
        let end = usize::try_from(end)
            .map_err(|_| ApiError::bad_request("block range end is too large"))?;
        return block
            .payload
            .get(start..end)
            .map(ToOwned::to_owned)
            .ok_or_else(|| ApiError::bad_request("block range exceeds recovered payload"));
    }
    let node_ids = placement_target_node_ids(state, cid, placement).await?;
    get_block_range_with_placement_fallback(state, cid, placement, node_ids, start, end).await
}

async fn get_block_range_with_placement_fallback(
    state: &AppState,
    cid: &Cid,
    reference: &PlacementReference,
    canonical_node_ids: Vec<String>,
    start: u64,
    end: u64,
) -> Result<Vec<u8>, ApiError> {
    let canonical_error = match get_block_range_from_placement_targets(
        state,
        cid,
        canonical_node_ids.clone(),
        start,
        end,
    )
    .await
    {
        Ok(payload) => return Ok(payload),
        Err(error) => error,
    };
    if let Some(exception) = state
        .placement
        .exception(reference, unix_seconds())
        .filter(|exception| exception.block_cid == *cid)
    {
        let exception_nodes = exception
            .node_ids
            .into_iter()
            .filter(|node_id| !canonical_node_ids.contains(node_id))
            .collect::<Vec<_>>();
        if !exception_nodes.is_empty() {
            metrics::PLACEMENT_EXCEPTION_HITS.fetch_add(1, Ordering::Relaxed);
            return get_block_range_from_placement_targets(state, cid, exception_nodes, start, end)
                .await
                .map_err(|error| {
                    ApiError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        ErrorCode::Unavailable,
                        error,
                    )
                });
        }
    }
    Err(ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::Unavailable,
        canonical_error,
    ))
}

async fn get_block_range_from_placement_targets(
    state: &AppState,
    cid: &Cid,
    node_ids: Vec<String>,
    start: u64,
    end: u64,
) -> Result<Vec<u8>, String> {
    let local_node_id = state.network.local_descriptor().node_id;
    let local_error = if node_ids.contains(&local_node_id) {
        match tokio::task::block_in_place(|| state.block_store.get_range(cid, start, end)) {
            Ok(payload) => return Ok(payload),
            Err(StorageError::NotFound(_)) | Err(StorageError::HashMismatch(_)) => Some(format!(
                "authoritative placement node {local_node_id} does not hold {cid}"
            )),
            Err(error) => return Err(error.to_string()),
        }
    } else {
        None
    };
    let remote_node_ids = node_ids
        .into_iter()
        .filter(|node_id| node_id != &local_node_id)
        .collect::<Vec<_>>();
    if !remote_node_ids.is_empty() {
        metrics::PLACEMENT_DIRECT_TARGET_ATTEMPTS
            .fetch_add(remote_node_ids.len() as u64, Ordering::Relaxed);
    }
    let mut fetches = stream::FuturesUnordered::new();
    let mut unique = HashSet::new();
    for node_id in remote_node_ids {
        if !unique.insert(node_id.clone()) {
            continue;
        }
        let network = fast_path::io_network(&state.network);
        let cid = cid.clone();
        fetches.push(async move {
            let Some(address) = fast_path::peer_address(&network, &node_id).await else {
                return (
                    node_id.clone(),
                    Err(format!("replica {node_id} has no routable bulk address")),
                );
            };
            let result = network
                .block_get_range(address, &cid, start, end)
                .await
                .map_err(|error| error.to_string());
            (node_id, result)
        });
    }
    if fetches.is_empty() {
        return Err(
            local_error.unwrap_or_else(|| format!("no authoritative placement holds {cid}"))
        );
    }
    match time::timeout(Duration::from_secs(5), async {
        let mut last_error = local_error;
        while let Some((_node_id, result)) = fetches.next().await {
            match result {
                Ok(payload) => return Ok(payload),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| format!("no authoritative placement holds {cid}")))
    })
    .await
    {
        Ok(Ok(payload)) => {
            metrics::PLACEMENT_DIRECT_TARGET_BYTES
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
            Ok(payload)
        }
        Ok(Err(error)) => {
            metrics::PLACEMENT_DIRECT_TARGET_ERRORS.fetch_add(1, Ordering::Relaxed);
            Err(error)
        }
        Err(_) => {
            metrics::PLACEMENT_DIRECT_TARGET_ERRORS.fetch_add(1, Ordering::Relaxed);
            Err(format!(
                "authoritative replicas did not return range for {cid} within 5000ms"
            ))
        }
    }
}

async fn has_block(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> Result<StatusCode, ApiError> {
    let cid = BlockStore::parse_cid(&cid)?;
    if state.block_store.has(&cid)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

fn placement_candidates(state: &AppState, peers: Vec<PeerStatus>) -> Vec<PlacementNode> {
    let local_storage = state.block_store.storage_summary().ok();
    if let Some(summary) = local_storage {
        state
            .network
            .update_storage_advertisement(summary.capacity_bytes, summary.available_bytes);
    }
    let local_descriptor = state.network.local_descriptor();
    let mut candidates = vec![PlacementNode {
        node_id: local_descriptor.node_id,
        addresses: local_descriptor.addresses,
        is_local: true,
        failure_domain: if local_descriptor.failure_domain.is_empty() {
            None
        } else {
            Some(local_descriptor.failure_domain)
        },
        placement_labels: local_descriptor.placement_labels.into_iter().collect(),
        storage_capacity_bytes: local_storage.map(|summary| summary.capacity_bytes),
        storage_available_bytes: local_storage.map(|summary| summary.available_bytes),
    }];
    candidates.extend(peers.into_iter().map(|peer| PlacementNode {
        node_id: peer.node_id,
        addresses: peer.addresses,
        is_local: false,
        failure_domain: peer.failure_domain,
        placement_labels: peer.placement_labels.into_iter().collect(),
        storage_capacity_bytes: Some(peer.storage_capacity_bytes),
        storage_available_bytes: Some(peer.storage_available_bytes),
    }));
    let mut seen_node_ids = HashSet::new();
    candidates.retain(|candidate| seen_node_ids.insert(candidate.node_id.clone()));
    candidates
}

fn authoritative_placement_error(error: AuthoritativePlacementError) -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::Unavailable,
        format!("authoritative placement failed: {error}"),
    )
}

fn validate_replica_ack(
    state: &AppState,
    expected_node_id: &str,
    expected_cid: &Cid,
    expected_codec: Codec,
    expected_size: u64,
    ack: &proto::BlockPutReplicaResponse,
) -> Result<ProviderRecord, ApiError> {
    let record = parse_replica_ack(
        expected_node_id,
        expected_cid,
        expected_codec,
        expected_size,
        ack,
    )?;
    state.network.persist_provider_record(&record)?;
    Ok(record)
}

fn parse_replica_ack(
    expected_node_id: &str,
    expected_cid: &Cid,
    expected_codec: Codec,
    expected_size: u64,
    ack: &proto::BlockPutReplicaResponse,
) -> Result<ProviderRecord, ApiError> {
    if ack.cid != expected_cid.to_string()
        || ack.codec != expected_codec.canonical_display()
        || ack.size != expected_size
        || ack.provider_record_json.is_empty()
    {
        return Err(ApiError::internal(
            "replica acknowledgement does not match request",
        ));
    }
    let record: ProviderRecord =
        serde_json::from_str(&ack.provider_record_json).map_err(ApiError::serde)?;
    if record.cid != *expected_cid || record.node_id != expected_node_id {
        return Err(ApiError::internal(
            "replica provider record does not match target node or CID",
        ));
    }
    Ok(record)
}

async fn put_replicated_block(
    state: &AppState,
    codec: Codec,
    payload: Vec<u8>,
) -> Result<DurabilityReceipt, ApiError> {
    put_replicated_block_with_factor(state, codec, payload, state.replication_factor).await
}

async fn put_replicated_block_with_factor(
    state: &AppState,
    codec: Codec,
    payload: Vec<u8>,
    replication_factor: usize,
) -> Result<DurabilityReceipt, ApiError> {
    put_replicated_block_with_placement_map(
        state,
        codec,
        payload,
        replication_factor,
        state.placement.current_map(),
    )
    .await
}

async fn put_replicated_block_with_placement_map(
    state: &AppState,
    codec: Codec,
    payload: Vec<u8>,
    replication_factor: usize,
    placement_map: Option<Arc<PlacementMap>>,
) -> Result<DurabilityReceipt, ApiError> {
    if replication_factor == 0 {
        return Err(ApiError::bad_request(
            "replication factor must be greater than zero",
        ));
    }
    let _publication_slot = if replication_factor > 1 {
        let slots =
            fast_path::replication_slots().unwrap_or_else(|| state.replicated_block_slots.clone());
        Some(
            slots
                .acquire_owned()
                .await
                .map_err(|_| ApiError::internal("replicated block scheduler is unavailable"))?,
        )
    } else {
        None
    };
    let local_put_started = time::Instant::now();
    let local_put = if placement_map.is_some() {
        let encoded = tokio::task::block_in_place(|| state.block_store.encode(codec, &payload))?;
        let put = PutBlockResponse {
            cid: encoded.cid().clone(),
            codec,
            size: encoded.logical_size_bytes(),
            already_existed: false,
            storage_location: "authoritative-placement-pending".to_string(),
        };
        let wire = encoded.bytes().to_vec();
        Ok((put, wire, Some(encoded)))
    } else if replication_factor > 1 {
        fast_path::local_block_writer()
            .unwrap_or_else(|| state.local_block_writer.clone())
            .put_with_payload(codec, payload)
            .await
            .map(|(put, wire)| (put, wire, None))
            .map_err(ApiError::internal)
    } else {
        tokio::task::block_in_place(|| state.block_store.put(codec, &payload))
            .map(|put| (put, payload, None))
            .map_err(ApiError::from)
    };
    metrics::observe_phase(
        &metrics::S3_BLOCK_HASH_STORAGE_PHASES,
        &metrics::S3_BLOCK_HASH_STORAGE_MICROS,
        local_put_started.elapsed(),
    );
    let (local_put, payload, pending_local_encoded) = local_put?;
    let local_descriptor = state.network.local_descriptor();

    let (placement, selected) = if let Some(map) = placement_map {
        let replicas = u16::try_from(replication_factor)
            .map_err(|_| ApiError::bad_request("replication factor exceeds placement bounds"))?;
        let reference = PlacementReference::replicated(map.epoch, local_put.cid.clone(), replicas);
        metrics::PLACEMENT_CALCULATIONS.fetch_add(1, Ordering::Relaxed);
        let decision = pepper_placement::select_authoritative(&map, &reference)
            .map_err(authoritative_placement_error)?;
        let selected = decision
            .node_ids
            .into_iter()
            .map(|node_id| {
                let is_local = node_id == local_descriptor.node_id;
                (node_id, is_local, None)
            })
            .collect::<Vec<_>>();
        (Some(reference), selected)
    } else {
        let candidates = placement_candidates(state, state.network.peers().await);
        let selected = select_replicas(&local_put.cid, &candidates, replication_factor)
            .into_iter()
            .map(|node| {
                let address = node.addresses.iter().find_map(|address| {
                    address.parse::<SocketAddr>().ok().filter(|address| {
                        !address.ip().is_unspecified() && !address.ip().is_multicast()
                    })
                });
                (node.node_id, node.is_local, address)
            })
            .collect();
        (None, selected)
    };
    // The ingress persists the encoded block only when it is an authoritative
    // owner. A non-owner gateway forwards the bytes without leaving an
    // untracked durable copy behind.
    let local_selected = selected.iter().any(|(_, is_local, _)| *is_local);
    if local_selected && let Some(encoded) = pending_local_encoded.as_ref() {
        tokio::task::block_in_place(|| state.block_store.put_encoded(encoded))?;
    }
    let mut replica_nodes = local_selected
        .then(|| local_descriptor.node_id.clone())
        .into_iter()
        .collect::<Vec<_>>();

    let payload: Arc<[u8]> = Arc::from(payload);
    let writes = selected
        .into_iter()
        .filter(|(_, is_local, _)| !*is_local)
        .map(|(node_id, _, address)| {
            let network = fast_path::io_network(&state.network);
            let payload = payload.clone();
            let cid = local_put.cid.clone();
            async move {
                metrics::PLACEMENT_DIRECT_TARGET_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
                let result = async {
                    let address = match address {
                        Some(address) => address,
                        None => fast_path::peer_address(&network, &node_id)
                            .await
                            .ok_or_else(|| {
                                format!("placement node {node_id} has no routable address")
                            })?,
                    };
                    network
                        .block_put_replica_stream(address, codec, &cid, local_put.size, payload)
                        .await
                        .map_err(|error| error.to_string())
                }
                .await;
                (node_id, result)
            }
        });
    let mut replica_writes = stream::iter(writes).buffered(8);
    let replica_transfer_started = time::Instant::now();

    while let Some((node_id, result)) = replica_writes.next().await {
        match result {
            Ok(ack) => {
                match parse_replica_ack(&node_id, &local_put.cid, codec, local_put.size, &ack) {
                    Ok(record) => {
                        metrics::PLACEMENT_DIRECT_TARGET_BYTES
                            .fetch_add(local_put.size, Ordering::Relaxed);
                        replica_nodes.push(node_id.clone());
                        let _ = record;
                    }
                    Err(error) => warn!(
                        node_id = %node_id,
                        %error.message,
                        "replica acknowledgement validation failed"
                    ),
                }
            }
            Err(error) => {
                metrics::PLACEMENT_DIRECT_TARGET_ERRORS.fetch_add(1, Ordering::Relaxed);
                warn!(%error, node_id = %node_id, "replica write failed");
            }
        }
    }

    metrics::observe_phase(
        &metrics::S3_REPLICA_TRANSFER_PHASES,
        &metrics::S3_REPLICA_TRANSFER_MICROS,
        replica_transfer_started.elapsed(),
    );

    replica_nodes.sort();
    replica_nodes.dedup();
    let replicas_accepted = replica_nodes.len();
    if replicas_accepted < replication_factor {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            format!(
                "authoritative placement durability was not met for {}: accepted {replicas_accepted} of {replication_factor}",
                local_put.cid
            ),
        ));
    }
    let status = "durable".to_string();
    let placement = match placement {
        Some(placement) => Some(placement),
        None if state.s3.is_none() => Some(PlacementReference::replicated(
            1,
            local_put.cid.clone(),
            u16::try_from(replication_factor).map_err(|_| {
                ApiError::bad_request("replication factor exceeds placement bounds")
            })?,
        )),
        None => None,
    };

    Ok(DurabilityReceipt {
        cid: local_put.cid.clone(),
        placement,
        codec: local_put.codec,
        size: local_put.size,
        replicas_accepted,
        replica_nodes,
        status,
    })
}

struct StoredErasureStripe {
    stripe: ErasureStripe,
    receipts: Vec<DurabilityReceipt>,
    distinct_nodes: usize,
}

struct ErasureStripeStoreContext {
    data_shards: u16,
    parity_shards: u16,
    candidates: Vec<PlacementNode>,
    request_plan: Arc<OnceCell<EcPlanDecision>>,
    allow_compression: bool,
}

fn semaphore_pressure_milli(semaphore: &Semaphore, capacity: usize) -> u16 {
    let active = capacity.saturating_sub(semaphore.available_permits());
    active
        .saturating_mul(1_000)
        .checked_div(capacity.max(1))
        .unwrap_or(1_000)
        .min(1_000) as u16
}

async fn encode_and_store_erasure_stripe(
    state: &AppState,
    bytes: Vec<u8>,
    offset: u64,
    context: Arc<ErasureStripeStoreContext>,
) -> Result<StoredErasureStripe, ApiError> {
    let data_shards = context.data_shards;
    let parity_shards = context.parity_shards;
    let candidates = context.candidates.clone();
    let request_plan = context.request_plan.clone();
    let allow_compression = context.allow_compression;
    validate_erasure_policy(data_shards, parity_shards)?;
    let data_shards_usize = data_shards as usize;
    let parity_shards_usize = parity_shards as usize;
    let total_shards = data_shards_usize + parity_shards_usize;
    let logical_size = bytes.len() as u64;
    let logical_cid = Cid::new(CODEC_RAW, &bytes);
    let max_block_bytes = state.max_block_bytes.unwrap_or(DEFAULT_MAX_BLOCK_BYTES);
    let compression_started = std::time::Instant::now();
    let compression_scratch =
        fast_path::take_buffer(ERASURE_COMPRESSION_PROBE_REGION_BYTES.saturating_mul(3));
    let encoding_guard = state.erasure_planner.encoding_guard();
    let (encoding, encoded_size, shard_size, encoded, systematic_shards, compression_scratch) =
        tokio::task::spawn_blocking(move || {
        let (encoding, encoded, compression_scratch) = if allow_compression {
            encode_erasure_stripe_payload(bytes, compression_scratch)?
        } else {
            (ErasureStripeEncoding::Raw, bytes, compression_scratch)
        };
        let encoded_size = encoded.len();
        let shard_size = std::cmp::max(1, encoded_size.div_ceil(data_shards_usize));
        if shard_size as u64 > max_block_bytes {
            return Err(ApiError::bad_request(format!(
                "erasure shard size {shard_size} exceeds block limit {max_block_bytes}; increase data_shards"
            )));
        }
        let allocation_bytes = shard_size
            .checked_mul(total_shards)
            .ok_or_else(|| ApiError::bad_request("erasure allocation size overflow"))?;
        if allocation_bytes > 512 * 1024 * 1024 {
            return Err(ApiError::bad_request(
                "erasure encoding would exceed the 512 MiB memory safety limit",
            ));
        }
        // Split the systematic data before selecting a transfer plan, but do
        // not calculate parity here. Distributed and hierarchical plans must
        // actually move that CPU work off the gateway rather than recomputing
        // parity after the gateway has already done it once.
        let systematic_shards =
            adaptive_systematic_shards(&encoded, data_shards_usize, shard_size);
        Ok::<_, ApiError>((
            encoding,
            encoded_size,
            shard_size,
            encoded,
            systematic_shards,
            compression_scratch,
        ))
    })
    .await
    .map_err(|error| ApiError::internal(format!("erasure encoder task failed: {error}")))??;
    fast_path::recycle_buffer(compression_scratch);
    metrics::record_erasure_stripe_encoding(
        logical_size,
        encoded_size as u64,
        encoding,
        compression_started.elapsed(),
    );
    drop(encoding_guard);
    let encoded: Arc<[u8]> = encoded.into();

    let transport = fast_path::io_network(&state.network).transport_metrics();
    let failure_domains = candidates
        .iter()
        .map(primary_failure_domain_key)
        .collect::<HashSet<_>>()
        .len();
    let decision = request_plan
        .get_or_init(|| async {
            state.erasure_planner.select(EcPlannerInputs {
                logical_bytes: logical_size,
                encoded_bytes: encoded_size as u64,
                failure_domains,
                active_bulk_streams: transport.bulk_streams_active,
                bulk_stream_capacity: transport.bulk_stream_capacity,
                bulk_stream_queue_micros: transport.bulk_stream_queue_ewma_microseconds,
                write_queue_pressure_milli: fast_path::write_pressure_milli().unwrap_or_else(
                    || semaphore_pressure_milli(&state.s3_write_slots, state.s3_write_capacity),
                ),
                target_queue_pressure_milli: state.erasure_planner.target_pressure_milli(
                    candidates.iter().map(|node| node.node_id.as_str()),
                    transport.bulk_stream_capacity,
                ),
                active_encoders: 0,
                encoder_capacity: std::thread::available_parallelism().map_or(1, usize::from),
            })
        })
        .await
        .clone();
    info!(
        plan = %decision.plan,
        candidate = %decision.candidate,
        reasons = %decision.reasons,
        gateway_pressure_milli = decision.estimated_gateway_pressure_milli,
        encoded_ratio_milli = decision.encoded_ratio_milli,
        logical_bytes = logical_size,
        encoded_bytes = encoded_size,
        "selected erasure transfer plan"
    );
    let (receipts, used_nodes) = if let Some(map) = state.placement.current_map() {
        let mut plan_guard = state.erasure_planner.begin(decision.plan, logical_size);
        let transfer_context = ErasureTransferContext {
            candidates: &candidates,
            logical_cid: &logical_cid,
            epoch: map.epoch,
            data_shards: data_shards_usize,
            parity_shards: parity_shards_usize,
            shard_size,
            logical_size,
            encoding,
            encoded: &encoded,
            systematic_shards: &systematic_shards,
        };
        match execute_erasure_transfer_plan(state, &transfer_context, decision.plan).await {
            Ok(transfer) => {
                plan_guard.add_gateway_bytes(transfer.gateway_bytes);
                plan_guard.add_internal_bytes(transfer.internal_bytes);
                plan_guard.add_cross_domain_bytes(transfer.cross_domain_bytes);
                plan_guard.complete();
                let nodes = receipt_nodes(&transfer.receipts);
                (transfer.receipts, nodes)
            }
            Err(error) if decision.plan != EcTransferPlan::GatewayFanout => {
                drop(plan_guard);
                state.erasure_planner.record_fallback(decision.plan);
                warn!(
                    plan = %decision.plan,
                    error = ?error,
                    "adaptive erasure plan failed; retrying the identical placement with gateway fanout"
                );
                let mut fallback = state
                    .erasure_planner
                    .begin(EcTransferPlan::GatewayFanout, logical_size);
                let shards = adaptive_encode_parity(
                    systematic_shards.clone(),
                    data_shards_usize,
                    parity_shards_usize,
                )
                .await?;
                let transfer =
                    gateway_fanout_shards(state, &candidates, &logical_cid, map.epoch, shards)
                        .await?;
                fallback.add_gateway_bytes(transfer.gateway_bytes);
                fallback.add_internal_bytes(transfer.internal_bytes);
                fallback.add_cross_domain_bytes(transfer.cross_domain_bytes);
                fallback.complete();
                let nodes = receipt_nodes(&transfer.receipts);
                (transfer.receipts, nodes)
            }
            Err(error) => return Err(error),
        }
    } else if state.s3.is_none() {
        let shards =
            adaptive_encode_parity(systematic_shards, data_shards_usize, parity_shards_usize)
                .await?;
        let mut receipts = Vec::with_capacity(total_shards);
        let mut used_nodes = HashSet::new();
        let mut used_constraint_values = HashSet::new();
        for (index, shard) in shards.into_iter().enumerate() {
            let cid = Cid::new(CODEC_RAW, &shard);
            let placement = PlacementReference::erasure_shard(1, logical_cid.clone(), index as u16);
            let (node_id, constraints, receipt) = store_erasure_shard_legacy(
                state,
                &candidates,
                cid,
                shard,
                &used_nodes,
                &used_constraint_values,
                placement,
            )
            .await?;
            used_nodes.insert(node_id);
            used_constraint_values.extend(constraints);
            receipts.push(receipt);
        }
        (receipts, used_nodes)
    } else {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "authoritative placement map is not loaded",
        ));
    };
    let placement_epoch = receipts
        .first()
        .and_then(|receipt| receipt.placement.as_ref())
        .map_or(1, |placement| placement.epoch);
    let manifest_shards =
        shards_for_manifest(&logical_cid, placement_epoch, shard_size, &receipts)?;
    Ok(StoredErasureStripe {
        stripe: ErasureStripe {
            offset,
            size: logical_size,
            logical_cid,
            encoding,
            encoded_size: encoded_size as u64,
            shard_size: shard_size as u64,
            shards: manifest_shards,
        },
        receipts,
        distinct_nodes: used_nodes.len(),
    })
}

fn receipt_nodes(receipts: &[DurabilityReceipt]) -> HashSet<String> {
    receipts
        .iter()
        .flat_map(|receipt| receipt.replica_nodes.iter().cloned())
        .collect()
}

fn shards_for_manifest(
    logical_cid: &Cid,
    epoch: u64,
    shard_size: usize,
    receipts: &[DurabilityReceipt],
) -> Result<Vec<ErasureShard>, ApiError> {
    let mut shards = receipts
        .iter()
        .map(|receipt| {
            let placement = receipt
                .placement
                .clone()
                .ok_or_else(|| ApiError::internal("erasure receipt is missing placement"))?;
            if placement.epoch != epoch
                || placement.seed != *logical_cid
                || placement.role != PlacementRole::ErasureShard
            {
                return Err(ApiError::internal(
                    "erasure receipt placement does not match stripe",
                ));
            }
            Ok(ErasureShard {
                index: placement.index,
                cid: receipt.cid.clone(),
                size: shard_size as u64,
                placement,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    shards.sort_by_key(|shard| shard.index);
    if shards
        .iter()
        .enumerate()
        .any(|(index, shard)| usize::from(shard.index) != index)
    {
        return Err(ApiError::internal(
            "adaptive erasure transfer returned incomplete shard indices",
        ));
    }
    Ok(shards)
}

struct ErasureTransferContext<'a> {
    candidates: &'a [PlacementNode],
    logical_cid: &'a Cid,
    epoch: u64,
    data_shards: usize,
    parity_shards: usize,
    shard_size: usize,
    logical_size: u64,
    encoding: ErasureStripeEncoding,
    encoded: &'a Arc<[u8]>,
    systematic_shards: &'a [Vec<u8>],
}

impl ErasureTransferContext<'_> {
    fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    fn request(
        &self,
        plan: EcTransferPlan,
        pipeline: Vec<proto::ErasurePipelineHop>,
    ) -> proto::ErasureTransferRequest {
        proto::ErasureTransferRequest {
            logical_cid: self.logical_cid.to_string(),
            placement_epoch: self.epoch,
            data_shards: self.data_shards as u32,
            parity_shards: self.parity_shards as u32,
            encoded_size: self.encoded.len() as u64,
            shard_size: self.shard_size as u64,
            data_cids: self.systematic_shards[..self.data_shards]
                .iter()
                .map(|shard| Cid::new(CODEC_RAW, shard).to_string())
                .collect(),
            pipeline,
            plan: plan.as_str().to_string(),
            logical_size: self.logical_size,
            encoding: match self.encoding {
                ErasureStripeEncoding::Raw => "raw",
                ErasureStripeEncoding::Zstd => "zstd",
            }
            .to_string(),
            completed_indices: Vec::new(),
            encoded_cid: Cid::new(CODEC_RAW, self.encoded.as_ref()).to_string(),
        }
    }
}

async fn execute_erasure_transfer_plan(
    state: &AppState,
    transfer: &ErasureTransferContext<'_>,
    plan: EcTransferPlan,
) -> Result<ErasurePlanTransfer, ApiError> {
    match plan {
        EcTransferPlan::GatewayFanout => {
            let shards = adaptive_encode_parity(
                transfer.systematic_shards.to_vec(),
                transfer.data_shards,
                transfer.parity_shards,
            )
            .await?;
            gateway_fanout_shards(
                state,
                transfer.candidates,
                transfer.logical_cid,
                transfer.epoch,
                shards,
            )
            .await
        }
        EcTransferPlan::DistributedParity => distributed_parity_shards(state, transfer).await,
        EcTransferPlan::Hierarchical | EcTransferPlan::Pipelined => {
            remote_transfer_shards(state, transfer, plan).await
        }
    }
}

async fn gateway_fanout_shards(
    state: &AppState,
    candidates: &[PlacementNode],
    logical_cid: &Cid,
    epoch: u64,
    shards: Vec<Vec<u8>>,
) -> Result<ErasurePlanTransfer, ApiError> {
    let transfers = stream::iter(shards.into_iter().enumerate().map(|(index, shard)| {
        let candidates = candidates.to_vec();
        let logical_cid = logical_cid.clone();
        async move {
            let cid = Cid::new(CODEC_RAW, &shard);
            let placement = PlacementReference::erasure_shard(epoch, logical_cid, index as u16);
            let (_, receipt) =
                store_erasure_shard(state, &candidates, cid, shard, placement).await?;
            Ok::<_, ApiError>(receipt)
        }
    }))
    .buffer_unordered(32)
    .try_collect::<Vec<_>>()
    .await?;
    let (internal_bytes, cross_domain_bytes) =
        receipt_transfer_bytes(state, candidates, &transfers);
    Ok(ErasurePlanTransfer {
        receipts: transfers,
        gateway_bytes: internal_bytes,
        internal_bytes,
        cross_domain_bytes,
    })
}

struct ErasurePlanTransfer {
    receipts: Vec<DurabilityReceipt>,
    gateway_bytes: u64,
    internal_bytes: u64,
    cross_domain_bytes: u64,
}

fn receipt_transfer_bytes(
    state: &AppState,
    candidates: &[PlacementNode],
    receipts: &[DurabilityReceipt],
) -> (u64, u64) {
    let local_domain = candidates
        .iter()
        .find(|node| node.node_id == state.status.node_id)
        .map(primary_failure_domain_key);
    receipts.iter().fold((0u64, 0u64), |mut totals, receipt| {
        let Some(target) = receipt.replica_nodes.first() else {
            return totals;
        };
        if target == &state.status.node_id {
            return totals;
        }
        totals.0 = totals.0.saturating_add(receipt.size);
        let target_domain = candidates
            .iter()
            .find(|node| &node.node_id == target)
            .map(primary_failure_domain_key);
        if target_domain != local_domain {
            totals.1 = totals.1.saturating_add(receipt.size);
        }
        totals
    })
}

fn placement_node_for_shard<'a>(
    state: &AppState,
    candidates: &'a [PlacementNode],
    logical_cid: &Cid,
    epoch: u64,
    index: usize,
) -> Result<&'a PlacementNode, ApiError> {
    let reference = PlacementReference::erasure_shard(epoch, logical_cid.clone(), index as u16);
    metrics::PLACEMENT_CALCULATIONS.fetch_add(1, Ordering::Relaxed);
    let node_id = state
        .placement
        .decide(&reference)
        .map_err(authoritative_placement_error)?
        .node_ids
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::internal("erasure shard has no placement owner"))?;
    candidates
        .iter()
        .find(|candidate| candidate.node_id == node_id)
        .ok_or_else(|| ApiError::internal("erasure shard owner has no signed descriptor"))
}

fn coordinator_address(node: &PlacementNode) -> Result<SocketAddr, ApiError> {
    node.addresses
        .iter()
        .find_map(|address| address.parse().ok())
        .ok_or_else(|| ApiError::internal("erasure coordinator has no routable control address"))
}

fn choose_erasure_coordinator<'a>(
    state: &AppState,
    candidates: &'a [PlacementNode],
    logical_cid: &Cid,
    epoch: u64,
    data_shards: usize,
) -> Result<&'a PlacementNode, ApiError> {
    let mut nodes = (0..data_shards)
        .map(|index| placement_node_for_shard(state, candidates, logical_cid, epoch, index))
        .collect::<Result<Vec<_>, _>>()?;
    nodes.sort_by(|left, right| {
        left.is_local
            .cmp(&right.is_local)
            .then_with(|| {
                right
                    .storage_available_bytes
                    .unwrap_or(0)
                    .cmp(&left.storage_available_bytes.unwrap_or(0))
            })
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    nodes
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::internal("erasure transfer has no data coordinator"))
}

fn choose_hierarchical_coordinator<'a>(
    state: &AppState,
    transfer: &'a ErasureTransferContext<'a>,
) -> Result<&'a PlacementNode, ApiError> {
    let owners = (0..transfer.total_shards())
        .map(|index| {
            placement_node_for_shard(
                state,
                transfer.candidates,
                transfer.logical_cid,
                transfer.epoch,
                index,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let gateway_domain = transfer
        .candidates
        .iter()
        .find(|node| node.node_id == state.status.node_id)
        .map(primary_failure_domain_key)
        .unwrap_or_else(|| format!("node:{}", state.status.node_id));
    let owner_domains = owners
        .iter()
        .map(|owner| primary_failure_domain_key(owner))
        .collect::<Vec<_>>();
    let stream_capacity = state
        .network
        .transport_metrics()
        .bulk_stream_capacity
        .max(1);
    let mut coordinators = owners[..transfer.data_shards]
        .iter()
        .copied()
        .filter(|node| !node.is_local)
        .collect::<Vec<_>>();
    coordinators.sort_by(|left, right| {
        let score = |coordinator: &PlacementNode| {
            let domain = primary_failure_domain_key(coordinator);
            hierarchical_cross_domain_bytes(
                &gateway_domain,
                &domain,
                &owner_domains,
                transfer.encoded.len() as u64,
                transfer.shard_size as u64,
            )
        };
        score(left)
            .cmp(&score(right))
            .then_with(|| {
                state
                    .erasure_planner
                    .target_pressure_milli([left.node_id.as_str()], stream_capacity)
                    .cmp(
                        &state
                            .erasure_planner
                            .target_pressure_milli([right.node_id.as_str()], stream_capacity),
                    )
            })
            .then_with(|| {
                right
                    .storage_available_bytes
                    .unwrap_or(0)
                    .cmp(&left.storage_available_bytes.unwrap_or(0))
            })
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    coordinators
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::internal("hierarchical transfer has no remote data coordinator"))
}

fn hierarchical_cross_domain_bytes(
    gateway_domain: &str,
    coordinator_domain: &str,
    owner_domains: &[String],
    encoded_size: u64,
    shard_size: u64,
) -> u64 {
    let ingress = u64::from(coordinator_domain != gateway_domain).saturating_mul(encoded_size);
    owner_domains.iter().fold(ingress, |bytes, owner_domain| {
        bytes.saturating_add(
            u64::from(owner_domain != coordinator_domain).saturating_mul(shard_size),
        )
    })
}

fn validate_adaptive_response(
    state: &AppState,
    transfer: &ErasureTransferContext<'_>,
    response: proto::ErasureTransferResponse,
    expected_indices: std::ops::Range<usize>,
) -> Result<Vec<DurabilityReceipt>, ApiError> {
    let expected = expected_indices.collect::<HashSet<_>>();
    if response.shards.len() != expected.len() {
        return Err(ApiError::internal(
            "adaptive erasure executor returned the wrong shard count",
        ));
    }
    let mut seen = HashSet::new();
    let mut receipts = Vec::with_capacity(response.shards.len());
    for shard in response.shards {
        let index = shard.index as usize;
        if !expected.contains(&index) || !seen.insert(index) {
            return Err(ApiError::internal(
                "adaptive erasure executor returned an unexpected shard index",
            ));
        }
        let cid = shard
            .cid
            .parse::<Cid>()
            .map_err(|error| ApiError::internal(error.to_string()))?;
        if index >= transfer.total_shards() {
            return Err(ApiError::internal(
                "adaptive erasure executor returned an out-of-range shard",
            ));
        }
        let expected_size = transfer
            .systematic_shards
            .first()
            .map_or(0, |shard| shard.len() as u64);
        let owner = placement_node_for_shard(
            state,
            transfer.candidates,
            transfer.logical_cid,
            transfer.epoch,
            index,
        )?;
        let systematic_matches = index >= transfer.systematic_shards.len()
            || cid == Cid::new(CODEC_RAW, &transfer.systematic_shards[index]);
        if cid.codec != CODEC_RAW
            || !systematic_matches
            || shard.node_id != owner.node_id
            || shard.size != expected_size
        {
            return Err(ApiError::internal(
                "adaptive erasure executor changed the canonical layout",
            ));
        }
        receipts.push(DurabilityReceipt {
            cid,
            placement: Some(PlacementReference::erasure_shard(
                transfer.epoch,
                transfer.logical_cid.clone(),
                index as u16,
            )),
            codec: CODEC_RAW,
            size: shard.size,
            replicas_accepted: 1,
            replica_nodes: vec![shard.node_id],
            status: "durable".to_string(),
        });
    }
    Ok(receipts)
}

async fn distributed_parity_shards(
    state: &AppState,
    transfer_context: &ErasureTransferContext<'_>,
) -> Result<ErasurePlanTransfer, ApiError> {
    let mut transfer = gateway_fanout_shards(
        state,
        transfer_context.candidates,
        transfer_context.logical_cid,
        transfer_context.epoch,
        transfer_context.systematic_shards.to_vec(),
    )
    .await?;
    let coordinator = choose_erasure_coordinator(
        state,
        transfer_context.candidates,
        transfer_context.logical_cid,
        transfer_context.epoch,
        transfer_context.data_shards,
    );
    let coordinator = coordinator?;
    let request = transfer_context.request(EcTransferPlan::DistributedParity, Vec::new());
    let mut target_guard = state.erasure_planner.target_guard(&coordinator.node_id);
    let response = state
        .network
        .erasure_encode_parity(coordinator_address(coordinator)?, request)
        .await
        .map_err(ApiError::network)?;
    target_guard.complete();
    let response_internal_bytes = response.internal_bytes;
    let response_cross_domain_bytes = response.cross_domain_bytes;
    transfer.receipts.extend(validate_adaptive_response(
        state,
        transfer_context,
        response,
        transfer_context.data_shards..transfer_context.total_shards(),
    )?);
    transfer.internal_bytes = transfer
        .internal_bytes
        .saturating_add(response_internal_bytes);
    transfer.cross_domain_bytes = transfer
        .cross_domain_bytes
        .saturating_add(response_cross_domain_bytes);
    Ok(transfer)
}

async fn remote_transfer_shards(
    state: &AppState,
    transfer: &ErasureTransferContext<'_>,
    plan: EcTransferPlan,
) -> Result<ErasurePlanTransfer, ApiError> {
    let pipeline = if plan == EcTransferPlan::Pipelined {
        let mut hops = (0..transfer.data_shards)
            .map(|index| {
                placement_node_for_shard(
                    state,
                    transfer.candidates,
                    transfer.logical_cid,
                    transfer.epoch,
                    index,
                )
                .map(|node| proto::ErasurePipelineHop {
                    index: index as u32,
                    node_id: node.node_id.clone(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        hops.sort_by(|left, right| {
            let left_local = left.node_id == state.status.node_id;
            let right_local = right.node_id == state.status.node_id;
            left_local
                .cmp(&right_local)
                .then_with(|| left.index.cmp(&right.index))
        });
        hops.truncate(state.erasure_planner.pipeline_max_hops());
        hops
    } else {
        Vec::new()
    };
    let ingress = if let Some(first) = pipeline.first() {
        transfer
            .candidates
            .iter()
            .find(|node| node.node_id == first.node_id)
            .ok_or_else(|| ApiError::internal("pipeline ingress is unknown"))?
    } else if plan == EcTransferPlan::Hierarchical {
        choose_hierarchical_coordinator(state, transfer)?
    } else {
        choose_erasure_coordinator(
            state,
            transfer.candidates,
            transfer.logical_cid,
            transfer.epoch,
            transfer.data_shards,
        )?
    };
    if ingress.is_local {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "adaptive remote transfer selected the local gateway",
        ));
    }
    let request = transfer.request(plan, pipeline);
    let mut target_guard = state.erasure_planner.target_guard(&ingress.node_id);
    let response = fast_path::io_network(&state.network)
        .erasure_store_stripe_stream(
            coordinator_address(ingress)?,
            request,
            Arc::clone(transfer.encoded),
        )
        .await
        .map_err(ApiError::network)?;
    target_guard.complete();
    let executor_internal_bytes = response.internal_bytes;
    let executor_cross_domain_bytes = response.cross_domain_bytes;
    let receipts =
        validate_adaptive_response(state, transfer, response, 0..transfer.total_shards())?;
    let ingress_cross_domain = transfer
        .candidates
        .iter()
        .find(|node| node.node_id == state.status.node_id)
        .map(primary_failure_domain_key)
        != Some(primary_failure_domain_key(ingress));
    Ok(ErasurePlanTransfer {
        receipts,
        gateway_bytes: transfer.encoded.len() as u64,
        internal_bytes: (transfer.encoded.len() as u64).saturating_add(executor_internal_bytes),
        cross_domain_bytes: executor_cross_domain_bytes.saturating_add(if ingress_cross_domain {
            transfer.encoded.len() as u64
        } else {
            0
        }),
    })
}

fn encode_erasure_stripe_payload(
    logical: Vec<u8>,
    mut sample: Vec<u8>,
) -> Result<(ErasureStripeEncoding, Vec<u8>, Vec<u8>), ApiError> {
    let region = ERASURE_COMPRESSION_PROBE_REGION_BYTES.min(logical.len() / 3);
    if region == 0 {
        return Ok((ErasureStripeEncoding::Raw, logical, sample));
    }
    let middle = logical.len() / 2 - region / 2;
    let end = logical.len() - region;
    sample.clear();
    sample.reserve(region.saturating_mul(3).saturating_sub(sample.capacity()));
    sample.extend_from_slice(&logical[..region]);
    sample.extend_from_slice(&logical[middle..middle + region]);
    sample.extend_from_slice(&logical[end..]);
    let compressed_sample =
        zstd::bulk::compress(&sample, ERASURE_COMPRESSION_LEVEL).map_err(|error| {
            ApiError::internal(format!("erasure compression probe failed: {error}"))
        })?;
    let required_sample_savings = sample
        .len()
        .saturating_mul(ERASURE_COMPRESSION_MIN_SAVINGS_PERCENT)
        / 100;
    if compressed_sample.len() > sample.len().saturating_sub(required_sample_savings) {
        return Ok((ErasureStripeEncoding::Raw, logical, sample));
    }
    let compressed = zstd::bulk::compress(&logical, ERASURE_COMPRESSION_LEVEL)
        .map_err(|error| ApiError::internal(format!("erasure compression failed: {error}")))?;
    let required_savings = logical
        .len()
        .saturating_mul(ERASURE_COMPRESSION_MIN_SAVINGS_PERCENT)
        / 100;
    if compressed.len() <= logical.len().saturating_sub(required_savings) {
        Ok((ErasureStripeEncoding::Zstd, compressed, sample))
    } else {
        Ok((ErasureStripeEncoding::Raw, logical, sample))
    }
}

fn primary_failure_domain_key(node: &PlacementNode) -> String {
    node.failure_domain
        .clone()
        .filter(|domain| !domain.is_empty())
        .or_else(|| node.placement_labels.get("failure_domain").cloned())
        .or_else(|| node.placement_labels.get("zone").cloned())
        .or_else(|| node.placement_labels.get("rack").cloned())
        .unwrap_or_else(|| format!("node:{}", node.node_id))
}

fn placement_constraint_values(node: &PlacementNode) -> HashSet<String> {
    let mut values = HashSet::new();
    values.insert(format!("node:{}", node.node_id));
    if let Some(domain) = node
        .failure_domain
        .as_ref()
        .filter(|domain| !domain.is_empty())
    {
        values.insert(format!("failure_domain:{domain}"));
    }
    for (key, value) in &node.placement_labels {
        if !key.is_empty() && !value.is_empty() {
            values.insert(format!("label:{key}={value}"));
        }
    }
    values
}

fn has_advertised_capacity(node: &PlacementNode, min_available_bytes: u64) -> bool {
    node.storage_available_bytes
        .is_none_or(|available| available >= min_available_bytes)
}

fn choose_capacity_aware_target(
    selected: &[PlacementNode],
    predicate: impl Fn(&PlacementNode) -> bool,
) -> Option<PlacementNode> {
    selected
        .iter()
        .filter(|node| predicate(node))
        .max_by(|left, right| {
            left.storage_available_bytes
                .unwrap_or(u64::MAX / 2)
                .cmp(&right.storage_available_bytes.unwrap_or(u64::MAX / 2))
                .then_with(|| right.node_id.cmp(&left.node_id))
        })
        .cloned()
}

fn select_erasure_target_legacy(
    cid: &Cid,
    candidates: &[PlacementNode],
    excluded_node_ids: &HashSet<String>,
    used_constraint_values: &HashSet<String>,
    min_available_bytes: u64,
) -> Option<PlacementNode> {
    let selected = select_replicas(cid, candidates, candidates.len());
    choose_capacity_aware_target(&selected, |node| {
        !excluded_node_ids.contains(&node.node_id)
            && has_advertised_capacity(node, min_available_bytes)
            && placement_constraint_values(node).is_disjoint(used_constraint_values)
    })
    .or_else(|| {
        choose_capacity_aware_target(&selected, |node| {
            !excluded_node_ids.contains(&node.node_id)
                && has_advertised_capacity(node, min_available_bytes)
        })
    })
    .or_else(|| {
        choose_capacity_aware_target(&selected, |node| {
            has_advertised_capacity(node, min_available_bytes)
        })
    })
    .or_else(|| selected.into_iter().next())
}

async fn store_erasure_shard_legacy(
    state: &AppState,
    candidates: &[PlacementNode],
    cid: Cid,
    payload: Vec<u8>,
    excluded_node_ids: &HashSet<String>,
    used_constraint_values: &HashSet<String>,
    placement: PlacementReference,
) -> Result<(String, HashSet<String>, DurabilityReceipt), ApiError> {
    let payload_size = payload.len() as u64;
    let encoded = state
        .block_store
        .encode_preverified_raw(cid.clone(), &payload)?;
    drop(payload);
    let logical_size = encoded.logical_size_bytes();
    let selected = select_erasure_target_legacy(
        &cid,
        candidates,
        excluded_node_ids,
        used_constraint_values,
        payload_size,
    );
    if let Some(node) = selected
        && !node.is_local
        && let Some(address) = node
            .addresses
            .iter()
            .find_map(|address| address.parse().ok())
    {
        let encoded_payload: Arc<[u8]> = Arc::from(encoded.into_bytes());
        if let Ok(ack) = state
            .network
            .block_put_replica_stream(
                address,
                CODEC_RAW,
                &cid,
                logical_size,
                encoded_payload.clone(),
            )
            .await
            && let Ok(record) =
                validate_replica_ack(state, &node.node_id, &cid, CODEC_RAW, logical_size, &ack)
        {
            state.network.announce_provider_to_peers(&record).await;
            return Ok((
                node.node_id.clone(),
                placement_constraint_values(&node),
                DurabilityReceipt {
                    cid,
                    placement: Some(placement),
                    codec: CODEC_RAW,
                    size: logical_size,
                    replicas_accepted: 1,
                    replica_nodes: vec![node.node_id],
                    status: "durable".to_string(),
                },
            ));
        }
        let encoded = state.block_store.validate_encoded_replica(
            cid.clone(),
            logical_size,
            encoded_payload.as_ref().to_vec(),
        )?;
        state.block_store.put_encoded(&encoded)?;
    } else {
        state.block_store.put_encoded(&encoded)?;
    }
    let provider = state.network.local_provider_record(&cid);
    state.network.persist_provider_record(&provider)?;
    state.network.announce_provider_to_peers(&provider).await;
    let local = candidates
        .iter()
        .find(|node| node.is_local)
        .cloned()
        .unwrap_or_else(|| PlacementNode {
            node_id: state.status.node_id.clone(),
            addresses: Vec::new(),
            is_local: true,
            failure_domain: None,
            placement_labels: BTreeMap::new(),
            storage_capacity_bytes: None,
            storage_available_bytes: None,
        });
    Ok((
        state.status.node_id.clone(),
        placement_constraint_values(&local),
        DurabilityReceipt {
            cid,
            placement: Some(placement),
            codec: CODEC_RAW,
            size: logical_size,
            replicas_accepted: 1,
            replica_nodes: vec![state.status.node_id.clone()],
            status: "durable".to_string(),
        },
    ))
}

async fn copy_erasure_shard_to_node(
    state: &AppState,
    node: &PlacementNode,
    cid: &Cid,
    payload: Vec<u8>,
) -> Result<(), ApiError> {
    let encoded = state
        .block_store
        .encode_preverified_raw(cid.clone(), &payload)?;
    drop(payload);
    if node.is_local {
        state.block_store.put_encoded(&encoded)?;
        return Ok(());
    }
    let address = node
        .addresses
        .iter()
        .find_map(|address| address.parse().ok())
        .ok_or_else(|| ApiError::internal("erasure target has no routable address"))?;
    let size = encoded.logical_size_bytes();
    let ack = state
        .network
        .block_put_replica_stream(
            address,
            CODEC_RAW,
            cid,
            size,
            Arc::from(encoded.into_bytes()),
        )
        .await?;
    let record = validate_replica_ack(state, &node.node_id, cid, CODEC_RAW, size, &ack)?;
    state.network.announce_provider_to_peers(&record).await;
    Ok(())
}

fn validate_erasure_policy(data_shards: u16, parity_shards: u16) -> Result<(), ApiError> {
    if data_shards == 0 || parity_shards == 0 {
        return Err(ApiError::bad_request(
            "erasure data and parity shard counts must be greater than zero",
        ));
    }
    if parity_shards > data_shards {
        return Err(ApiError::bad_request(
            "erasure parity shard count must not exceed data shard count",
        ));
    }
    if data_shards.saturating_add(parity_shards) > 32 {
        return Err(ApiError::bad_request(
            "erasure data+parity shard count must be <= 32",
        ));
    }
    Ok(())
}

async fn store_erasure_shard(
    state: &AppState,
    candidates: &[PlacementNode],
    cid: Cid,
    payload: Vec<u8>,
    placement: PlacementReference,
) -> Result<(String, DurabilityReceipt), ApiError> {
    let encoded = state
        .block_store
        .encode_preverified_raw(cid.clone(), &payload)?;
    drop(payload);
    let logical_size = encoded.logical_size_bytes();
    metrics::PLACEMENT_CALCULATIONS.fetch_add(1, Ordering::Relaxed);
    let target_id = state
        .placement
        .decide(&placement)
        .map_err(authoritative_placement_error)?
        .node_ids
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::internal("erasure placement returned no owner"))?;
    let node = candidates
        .iter()
        .find(|node| node.node_id == target_id)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Unavailable,
                format!("erasure placement node {target_id} has no signed address descriptor"),
            )
        })?;
    let mut target_guard = state.erasure_planner.target_guard(&target_id);
    if !node.is_local {
        let address = node
            .addresses
            .iter()
            .find_map(|address| address.parse().ok())
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::Unavailable,
                    format!("erasure placement node {target_id} has no routable address"),
                )
            })?;
        let encoded_payload: Arc<[u8]> = Arc::from(encoded.into_bytes());
        metrics::PLACEMENT_DIRECT_TARGET_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        let ack = fast_path::io_network(&state.network)
            .block_put_replica_stream(
                address,
                CODEC_RAW,
                &cid,
                logical_size,
                encoded_payload.clone(),
            )
            .await
            .map_err(|error| {
                metrics::PLACEMENT_DIRECT_TARGET_ERRORS.fetch_add(1, Ordering::Relaxed);
                ApiError::network(error)
            })?;
        parse_replica_ack(&node.node_id, &cid, CODEC_RAW, logical_size, &ack)?;
        metrics::PLACEMENT_DIRECT_TARGET_BYTES.fetch_add(logical_size, Ordering::Relaxed);
        target_guard.complete();
        return Ok((
            node.node_id.clone(),
            DurabilityReceipt {
                cid,
                placement: Some(placement),
                codec: CODEC_RAW,
                size: logical_size,
                replicas_accepted: 1,
                replica_nodes: vec![node.node_id.clone()],
                status: "durable".to_string(),
            },
        ));
    }
    state.block_store.put_encoded(&encoded)?;
    target_guard.complete();
    Ok((
        state.status.node_id.clone(),
        DurabilityReceipt {
            cid,
            placement: Some(placement),
            codec: CODEC_RAW,
            size: logical_size,
            replicas_accepted: 1,
            replica_nodes: vec![state.status.node_id.clone()],
            status: "durable".to_string(),
        },
    ))
}

fn parse_adaptive_erasure_request(
    request: &proto::ErasureTransferRequest,
) -> Result<(Cid, usize, usize, usize), ApiError> {
    let logical_cid = request
        .logical_cid
        .parse::<Cid>()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let data_shards = request.data_shards as usize;
    let parity_shards = request.parity_shards as usize;
    validate_erasure_policy(request.data_shards as u16, request.parity_shards as u16)?;
    let shard_size = usize::try_from(request.shard_size)
        .map_err(|_| ApiError::bad_request("adaptive erasure shard size does not fit usize"))?;
    if logical_cid.codec != CODEC_RAW
        || request.placement_epoch == 0
        || request.encoded_size == 0
        || request.logical_size == 0
        || request.data_cids.len() != data_shards
        || request.shard_size
            != request
                .encoded_size
                .div_ceil(u64::from(request.data_shards))
        || !matches!(request.encoding.as_str(), "raw" | "zstd")
    {
        return Err(ApiError::bad_request(
            "invalid adaptive erasure transfer request",
        ));
    }
    Ok((logical_cid, data_shards, parity_shards, shard_size))
}

fn validate_adaptive_encoded_payload(
    request: &proto::ErasureTransferRequest,
    logical_cid: &Cid,
    encoded: &[u8],
) -> Result<(), ApiError> {
    if encoded.len() as u64 != request.encoded_size {
        return Err(ApiError::bad_request(
            "adaptive erasure encoded payload size mismatch",
        ));
    }
    let encoded_cid = request
        .encoded_cid
        .parse::<Cid>()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    if encoded_cid.codec != CODEC_RAW || !encoded_cid.verify(encoded) {
        return Err(ApiError::bad_request(
            "adaptive erasure encoded CID verification failed",
        ));
    }
    if request.encoding == "raw"
        && (request.logical_size != request.encoded_size || encoded_cid != *logical_cid)
    {
        return Err(ApiError::bad_request("raw adaptive erasure CID mismatch"));
    }
    Ok(())
}

fn adaptive_systematic_shards(
    encoded: &[u8],
    data_shards: usize,
    shard_size: usize,
) -> Vec<Vec<u8>> {
    let mut shards = vec![vec![0u8; shard_size]; data_shards];
    for (index, chunk) in encoded.chunks(shard_size).enumerate() {
        shards[index][..chunk.len()].copy_from_slice(chunk);
    }
    shards
}

async fn adaptive_all_shards(
    encoded: Vec<u8>,
    data_shards: usize,
    parity_shards: usize,
    shard_size: usize,
) -> Result<Vec<Vec<u8>>, ApiError> {
    let systematic = adaptive_systematic_shards(&encoded, data_shards, shard_size);
    adaptive_encode_parity(systematic, data_shards, parity_shards).await
}

async fn adaptive_encode_parity(
    mut systematic: Vec<Vec<u8>>,
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<Vec<u8>>, ApiError> {
    tokio::task::spawn_blocking(move || {
        if systematic.len() != data_shards
            || systematic.is_empty()
            || systematic
                .iter()
                .any(|shard| shard.len() != systematic[0].len())
        {
            return Err(ApiError::bad_request(
                "adaptive erasure systematic geometry is invalid",
            ));
        }
        let shard_size = systematic[0].len();
        systematic.extend((0..parity_shards).map(|_| vec![0u8; shard_size]));
        ReedSolomon::new(data_shards, parity_shards)
            .map_err(|error| ApiError::bad_request(error.to_string()))?
            .encode(&mut systematic)
            .map_err(|error| ApiError::internal(error.to_string()))?;
        Ok(systematic)
    })
    .await
    .map_err(|error| ApiError::internal(format!("adaptive erasure task failed: {error}")))?
}

async fn adaptive_store_shard(
    state: &AppState,
    candidates: &[PlacementNode],
    logical_cid: &Cid,
    epoch: u64,
    index: usize,
    payload: Vec<u8>,
) -> Result<proto::ErasureTransferShard, ApiError> {
    let cid = Cid::new(CODEC_RAW, &payload);
    let placement = PlacementReference::erasure_shard(epoch, logical_cid.clone(), index as u16);
    let (node_id, receipt) =
        store_erasure_shard(state, candidates, cid.clone(), payload, placement).await?;
    Ok(proto::ErasureTransferShard {
        index: index as u32,
        cid: cid.to_string(),
        node_id,
        size: receipt.size,
    })
}

async fn execute_distributed_parity(
    state: &AppState,
    request: proto::ErasureTransferRequest,
) -> Result<proto::ErasureTransferResponse, ApiError> {
    let (logical_cid, data_shards, parity_shards, shard_size) =
        parse_adaptive_erasure_request(&request)?;
    if request.plan != EcTransferPlan::DistributedParity.as_str() || !request.pipeline.is_empty() {
        return Err(ApiError::bad_request(
            "distributed parity request contains an invalid plan",
        ));
    }
    let candidates = placement_candidates(state, state.network.peers().await);
    let sources = request
        .data_cids
        .iter()
        .enumerate()
        .map(|(index, cid)| {
            let owner = placement_node_for_shard(
                state,
                &candidates,
                &logical_cid,
                request.placement_epoch,
                index,
            )?
            .node_id
            .clone();
            Ok::<_, ApiError>((
                cid.parse::<Cid>()
                    .map_err(|error| ApiError::bad_request(error.to_string()))?,
                PlacementReference::erasure_shard(
                    request.placement_epoch,
                    logical_cid.clone(),
                    index as u16,
                ),
                owner,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fetched = stream::iter(
        sources
            .into_iter()
            .map(|(cid, placement, owner)| async move {
                let payload = get_block_at_placement(state, &cid, &placement)
                    .await?
                    .payload;
                if payload.len() != shard_size || !cid.verify(&payload) {
                    return Err(ApiError::bad_request(
                        "distributed parity source shard failed verification",
                    ));
                }
                Ok::<_, ApiError>((payload, owner))
            }),
    )
    .buffered(data_shards.min(16))
    .try_collect::<Vec<_>>()
    .await?;
    let local_domain = candidates
        .iter()
        .find(|node| node.node_id == state.status.node_id)
        .map(primary_failure_domain_key);
    let (fetch_internal_bytes, fetch_cross_domain_bytes) =
        fetched
            .iter()
            .fold((0u64, 0u64), |mut totals, (payload, owner)| {
                if owner != &state.status.node_id {
                    totals.0 = totals.0.saturating_add(payload.len() as u64);
                    let owner_domain = candidates
                        .iter()
                        .find(|node| &node.node_id == owner)
                        .map(primary_failure_domain_key);
                    if owner_domain != local_domain {
                        totals.1 = totals.1.saturating_add(payload.len() as u64);
                    }
                }
                totals
            });
    let data = fetched
        .into_iter()
        .map(|(payload, _)| payload)
        .collect::<Vec<_>>();
    let mut shards = data;
    shards.extend((0..parity_shards).map(|_| vec![0u8; shard_size]));
    let encoding_guard = state.erasure_planner.encoding_guard();
    let shards = tokio::task::spawn_blocking(move || {
        ReedSolomon::new(data_shards, parity_shards)
            .map_err(|error| ApiError::bad_request(error.to_string()))?
            .encode(&mut shards)
            .map_err(|error| ApiError::internal(error.to_string()))?;
        Ok::<_, ApiError>(shards)
    })
    .await
    .map_err(|error| ApiError::internal(format!("distributed parity task failed: {error}")))??;
    drop(encoding_guard);
    let candidates_ref = &candidates;
    let logical_cid_ref = &logical_cid;
    let placement_epoch = request.placement_epoch;
    let stored = stream::iter(shards.into_iter().enumerate().skip(data_shards).map(
        move |(index, shard)| async move {
            adaptive_store_shard(
                state,
                candidates_ref,
                logical_cid_ref,
                placement_epoch,
                index,
                shard,
            )
            .await
        },
    ))
    .buffer_unordered(parity_shards.min(16))
    .try_collect::<Vec<_>>()
    .await?;
    let (store_internal_bytes, store_cross_domain_bytes) =
        proto_transfer_bytes(state, &candidates, &stored);
    Ok(proto::ErasureTransferResponse {
        shards: stored,
        executor_node_id: state.status.node_id.clone(),
        internal_bytes: fetch_internal_bytes.saturating_add(store_internal_bytes),
        cross_domain_bytes: fetch_cross_domain_bytes.saturating_add(store_cross_domain_bytes),
    })
}

async fn execute_remote_erasure_transfer(
    state: &AppState,
    request: proto::ErasureTransferRequest,
    encoded: Vec<u8>,
) -> Result<proto::ErasureTransferResponse, ApiError> {
    let (logical_cid, data_shards, parity_shards, shard_size) =
        parse_adaptive_erasure_request(&request)?;
    validate_adaptive_encoded_payload(&request, &logical_cid, &encoded)?;
    let candidates = placement_candidates(state, state.network.peers().await);
    if request.plan != EcTransferPlan::Hierarchical.as_str()
        || !request.pipeline.is_empty()
        || !request.completed_indices.is_empty()
    {
        return Err(ApiError::bad_request(
            "hierarchical erasure transfer has invalid routing state",
        ));
    }
    let encoding_guard = state.erasure_planner.encoding_guard();
    let shards = adaptive_all_shards(encoded, data_shards, parity_shards, shard_size).await?;
    drop(encoding_guard);
    let candidates_ref = &candidates;
    let logical_cid_ref = &logical_cid;
    let placement_epoch = request.placement_epoch;
    let stored = stream::iter(shards.into_iter().enumerate().map(
        move |(index, shard)| async move {
            adaptive_store_shard(
                state,
                candidates_ref,
                logical_cid_ref,
                placement_epoch,
                index,
                shard,
            )
            .await
        },
    ))
    .buffer_unordered((data_shards + parity_shards).min(32))
    .try_collect::<Vec<_>>()
    .await?;
    let (internal_bytes, cross_domain_bytes) = proto_transfer_bytes(state, &candidates, &stored);
    Ok(proto::ErasureTransferResponse {
        shards: stored,
        executor_node_id: state.status.node_id.clone(),
        internal_bytes,
        cross_domain_bytes,
    })
}

async fn execute_pipelined_erasure_transfer(
    state: &AppState,
    mut request: proto::ErasureTransferRequest,
    mut chunks: ErasureChunkReceiver,
) -> Result<proto::ErasureTransferResponse, ApiError> {
    let (logical_cid, data_shards, parity_shards, shard_size) =
        parse_adaptive_erasure_request(&request)?;
    if request.plan != EcTransferPlan::Pipelined.as_str() {
        return Err(ApiError::bad_request(
            "streaming pipeline received an invalid plan",
        ));
    }
    let candidates = placement_candidates(state, state.network.peers().await);
    let hop = request
        .pipeline
        .first()
        .cloned()
        .ok_or_else(|| ApiError::bad_request("pipelined transfer has no next hop"))?;
    if hop.node_id != state.status.node_id {
        return Err(ApiError::bad_request(
            "pipelined transfer reached the wrong owner",
        ));
    }
    let index = hop.index as usize;
    let expected_systematic = request.data_cids[index]
        .parse::<Cid>()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let encoded_cid = request
        .encoded_cid
        .parse::<Cid>()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let mut verifier = encoded_cid
        .stream_verifier(request.encoded_size)
        .ok_or_else(|| ApiError::bad_request("invalid pipelined encoded CID"))?;
    let encoded_size = usize::try_from(request.encoded_size)
        .map_err(|_| ApiError::bad_request("pipelined encoded size does not fit usize"))?;
    let systematic_start = index
        .checked_mul(shard_size)
        .ok_or_else(|| ApiError::bad_request("pipelined systematic offset overflow"))?;
    let systematic_end = systematic_start.saturating_add(shard_size);
    let mut systematic = vec![0u8; shard_size];

    request.pipeline.remove(0);
    request.completed_indices.push(index as u32);
    let next = request.pipeline.first().cloned();
    let mut forwarded_cross_domain = false;
    let (forward_sender, forward_task) = if let Some(next) = next {
        let next_node = candidates
            .iter()
            .find(|node| node.node_id == next.node_id)
            .ok_or_else(|| ApiError::internal("pipeline target is unknown"))?;
        let target = coordinator_address(next_node)?;
        forwarded_cross_domain = primary_failure_domain_key(next_node)
            != candidates
                .iter()
                .find(|node| node.node_id == state.status.node_id)
                .map(primary_failure_domain_key)
                .unwrap_or_else(|| format!("node:{}", state.status.node_id));
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        let network = state.network.clone();
        let forwarded_request = request.clone();
        let task = tokio::spawn(async move {
            network
                .erasure_relay_stripe_stream(target, forwarded_request, receiver)
                .await
        });
        (Some(sender), Some(PipelineRelayTask::new(task)))
    } else {
        (None, None)
    };
    let mut terminal_encoded = forward_task
        .is_none()
        .then(|| Vec::with_capacity(encoded_size));
    let mut received = 0usize;
    while let Some(chunk) = chunks.recv().await {
        let chunk_start = received;
        received = received
            .checked_add(chunk.len())
            .ok_or_else(|| ApiError::bad_request("pipelined stream size overflow"))?;
        if received > encoded_size {
            return Err(ApiError::bad_request(
                "pipelined stream exceeded declared size",
            ));
        }
        verifier.update(&chunk);
        let overlap_start = chunk_start.max(systematic_start);
        let overlap_end = received.min(systematic_end).min(encoded_size);
        if overlap_start < overlap_end {
            let source_start = overlap_start - chunk_start;
            let target_start = overlap_start - systematic_start;
            let length = overlap_end - overlap_start;
            systematic[target_start..target_start + length]
                .copy_from_slice(&chunk[source_start..source_start + length]);
        }
        if let Some(sender) = &forward_sender {
            sender.send(chunk).await.map_err(|_| {
                ApiError::network(NetworkError::TransportTask(
                    "erasure pipeline relay closed".to_string(),
                ))
            })?;
        } else if let Some(encoded) = &mut terminal_encoded {
            encoded.extend_from_slice(&chunk);
        }
    }
    drop(forward_sender);
    if received != encoded_size || !verifier.finish() {
        return Err(ApiError::bad_request(
            "pipelined encoded CID verification failed",
        ));
    }
    if Cid::new(CODEC_RAW, &systematic) != expected_systematic {
        return Err(ApiError::bad_request(
            "pipelined systematic shard CID mismatch",
        ));
    }

    let local_store = adaptive_store_shard(
        state,
        &candidates,
        &logical_cid,
        request.placement_epoch,
        index,
        systematic,
    );
    if let Some(mut forward_task) = forward_task {
        let forward_task = forward_task.take();
        let forward = async {
            forward_task
                .await
                .map_err(|error| {
                    ApiError::internal(format!("pipeline relay task failed: {error}"))
                })?
                .map_err(ApiError::network)
        };
        let (local, mut response) = tokio::try_join!(local_store, forward)?;
        response.internal_bytes = response.internal_bytes.saturating_add(request.encoded_size);
        if forwarded_cross_domain {
            response.cross_domain_bytes = response
                .cross_domain_bytes
                .saturating_add(request.encoded_size);
        }
        response.shards.push(local);
        return Ok(response);
    }

    let encoded = terminal_encoded.expect("terminal pipeline retains encoded bytes");
    let completed = request
        .completed_indices
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let placement_epoch = request.placement_epoch;
    let tail = async {
        let encoding_guard = state.erasure_planner.encoding_guard();
        let shards = adaptive_all_shards(encoded, data_shards, parity_shards, shard_size).await?;
        drop(encoding_guard);
        let candidates_ref = &candidates;
        let logical_cid_ref = &logical_cid;
        stream::iter(
            shards
                .into_iter()
                .enumerate()
                .filter_map(|(shard_index, shard)| {
                    (!completed.contains(&(shard_index as u32))).then_some((shard_index, shard))
                })
                .map(move |(shard_index, shard)| async move {
                    adaptive_store_shard(
                        state,
                        candidates_ref,
                        logical_cid_ref,
                        placement_epoch,
                        shard_index,
                        shard,
                    )
                    .await
                }),
        )
        .buffer_unordered((data_shards + parity_shards).min(32))
        .try_collect::<Vec<_>>()
        .await
    };
    let (local, mut stored) = tokio::try_join!(local_store, tail)?;
    stored.push(local);
    let (internal_bytes, cross_domain_bytes) = proto_transfer_bytes(state, &candidates, &stored);
    Ok(proto::ErasureTransferResponse {
        shards: stored,
        executor_node_id: state.status.node_id.clone(),
        internal_bytes,
        cross_domain_bytes,
    })
}

struct PipelineRelayTask {
    task: Option<tokio::task::JoinHandle<Result<proto::ErasureTransferResponse, NetworkError>>>,
}

impl PipelineRelayTask {
    fn new(
        task: tokio::task::JoinHandle<Result<proto::ErasureTransferResponse, NetworkError>>,
    ) -> Self {
        Self { task: Some(task) }
    }

    fn take(
        &mut self,
    ) -> tokio::task::JoinHandle<Result<proto::ErasureTransferResponse, NetworkError>> {
        self.task.take().expect("pipeline relay task exists")
    }
}

impl Drop for PipelineRelayTask {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn proto_transfer_bytes(
    state: &AppState,
    candidates: &[PlacementNode],
    shards: &[proto::ErasureTransferShard],
) -> (u64, u64) {
    let local_domain = candidates
        .iter()
        .find(|node| node.node_id == state.status.node_id)
        .map(primary_failure_domain_key);
    shards.iter().fold((0u64, 0u64), |mut totals, shard| {
        if shard.node_id == state.status.node_id {
            return totals;
        }
        totals.0 = totals.0.saturating_add(shard.size);
        let target_domain = candidates
            .iter()
            .find(|node| node.node_id == shard.node_id)
            .map(primary_failure_domain_key);
        if target_domain != local_domain {
            totals.1 = totals.1.saturating_add(shard.size);
        }
        totals
    })
}

async fn run_gc(
    State(state): State<AppState>,
    Query(query): Query<GcQuery>,
) -> Result<Json<GcReport>, ApiError> {
    let _guard = state.operation_lock.write().await;
    let mut protected = HashSet::new();
    for pin in active_pins(&state)? {
        protected.extend(traverse_reachable(&state, pin.root_cid).await?);
    }
    for root in state
        .publication_repository
        .protected_roots(unix_seconds())
        .map_err(|error| ApiError::internal(error.to_string()))?
    {
        protected.extend(traverse_reachable(&state, root).await?);
    }
    let report = if query.dry_run {
        state.block_store.garbage_collect_dry_run(&protected)?
    } else {
        state.block_store.garbage_collect(&protected)?
    };
    Ok(Json(report))
}

async fn admin_status(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let block_count = state.block_store.list_blocks()?.len();
    let peers = state.network.peers().await.len();
    let queue_depth = compute_queue_depth(&state)?;
    let namespace_groups = if let Some(manager) = &state.namespace_groups {
        manager.operational_statuses().await
    } else {
        Vec::new()
    };
    let publication = state
        .publication_repository
        .operational_stats(unix_seconds())
        .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok(Json(serde_json::json!({
        "node_id": state.status.node_id,
        "name": state.status.name,
        "schema_version": state.status.schema_version,
        "uptime_seconds": (OffsetDateTime::now_utc() - state.status.started_at).whole_seconds().max(0),
        "subsystems": {
            "metadata": {"status": "ok"},
            "storage": {"status": "ok", "blocks": block_count},
            "network": {"status": "ok", "peers": peers},
            "compute": {"status": if state.compute_enabled { "enabled" } else { "disabled" }, "queue_depth": queue_depth},
            "namespace": {
                "status": if state.namespace_groups.is_some() { "enabled" } else { "disabled" },
                "groups_hosted": namespace_groups.len(),
                "groups": namespace_groups,
                "publication": publication
            }
        },
        "auth": {
            "api_bearer_token_configured": state.api_bearer_token.is_some()
        },
        "limits": {
            "max_block_bytes": state.max_block_bytes,
            "max_object_bytes": state.max_object_bytes,
            "max_compute_timeout_seconds": state.max_compute_timeout_seconds,
            "http_requests_per_minute": state.http_requests_per_minute
        }
    })))
}

async fn admin_storage(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let blocks = state.block_store.list_blocks()?;
    let storage = state.block_store.storage_summary()?;
    let locations = state
        .block_store
        .storage_location_summaries()?
        .into_iter()
        .map(|location| {
            let used_bytes = location.used_bytes.saturating_add(location.reserved_bytes);
            let pressure_percent = used_bytes
                .saturating_mul(100)
                .checked_div(location.max_capacity_bytes)
                .unwrap_or(100);
            let pressure_state = if pressure_percent >= STORAGE_HARD_PRESSURE_PERCENT {
                "hard"
            } else if pressure_percent >= STORAGE_SOFT_PRESSURE_PERCENT {
                "soft"
            } else {
                "normal"
            };
            serde_json::json!({
                "path": location.path,
                "max_capacity_bytes": location.max_capacity_bytes,
                "used_bytes": used_bytes,
                "available_bytes": location.max_capacity_bytes.saturating_sub(used_bytes),
                "pressure_percent": pressure_percent,
                "pressure_state": pressure_state,
                "healthy": location.healthy,
                "reserved_bytes": location.reserved_bytes,
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({
        "blocks": blocks.len(),
        "bytes": storage.used_bytes,
        "locations": locations,
        "pressure_thresholds": {
            "soft_percent": STORAGE_SOFT_PRESSURE_PERCENT,
            "hard_percent": STORAGE_HARD_PRESSURE_PERCENT,
        },
    })))
}

async fn admin_erasure(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let blocks = state.block_store.list_blocks()?;
    let mut manifests = 0usize;
    let mut logical_bytes = 0u64;
    let mut encoded_bytes = 0u64;
    let mut shard_bytes = 0u64;
    let mut total_shards = 0usize;
    let mut healthy_shards = 0usize;
    let mut repairable_manifests = 0usize;
    let mut unrecoverable_manifests = 0usize;
    for stat in blocks
        .into_iter()
        .filter(|stat| stat.codec == CODEC_ERASURE_MANIFEST)
    {
        let block = state.block_store.get(&stat.cid)?;
        let manifest: ErasureManifest =
            serde_json::from_slice(&block.payload).map_err(ApiError::serde)?;
        manifest.validate().map_err(ApiError::manifest)?;
        manifests += 1;
        logical_bytes = logical_bytes.saturating_add(manifest.size);
        let mut manifest_unrecoverable = false;
        let mut manifest_repairable = false;
        for stripe in &manifest.stripes {
            encoded_bytes = encoded_bytes.saturating_add(stripe.encoded_size);
            shard_bytes = shard_bytes
                .saturating_add(stripe.shards.iter().map(|shard| shard.size).sum::<u64>());
            total_shards += stripe.shards.len();
            let mut healthy = 0usize;
            for shard in &stripe.shards {
                if placed_block_is_healthy(&state, &shard.cid, &shard.placement).await? {
                    healthy += 1;
                }
            }
            healthy_shards += healthy;
            if healthy < manifest.data_shards as usize {
                manifest_unrecoverable = true;
            } else if healthy < stripe.shards.len() {
                manifest_repairable = true;
            }
        }
        if manifest_unrecoverable {
            unrecoverable_manifests += 1;
        } else if manifest_repairable {
            repairable_manifests += 1;
        }
    }
    Ok(Json(serde_json::json!({
        "manifests": manifests,
        "logical_bytes": logical_bytes,
        "encoded_bytes": encoded_bytes,
        "shard_bytes": shard_bytes,
        "encoded_ratio": if logical_bytes > 0 { Some(encoded_bytes as f64 / logical_bytes as f64) } else { None },
        "shard_amplification": if logical_bytes > 0 { Some(shard_bytes as f64 / logical_bytes as f64) } else { None },
        "total_shards": total_shards,
        "healthy_shards": healthy_shards,
        "missing_shards": total_shards.saturating_sub(healthy_shards),
        "repairable_manifests": repairable_manifests,
        "unrecoverable_manifests": unrecoverable_manifests,
        "policy": {
            "auto_enabled": state.erasure_enabled,
            "auto_min_size_bytes": state.erasure_min_size_bytes,
            "data_shards": state.erasure_data_shards,
            "parity_shards": state.erasure_parity_shards,
            "repair_bytes_per_second": state.erasure_repair_bytes_per_second,
            "repair_available_permits": state.erasure_repair_semaphore.available_permits(),
        },
        "metrics": {
            "object_writes_total": ERASURE_OBJECT_WRITES.load(Ordering::Relaxed),
            "object_reads_total": ERASURE_OBJECT_READS.load(Ordering::Relaxed),
            "shard_repairs_total": ERASURE_SHARD_REPAIRS.load(Ordering::Relaxed),
            "shard_rebalances_total": ERASURE_SHARD_REBALANCES.load(Ordering::Relaxed),
            "reconstruction_failures_total": ERASURE_RECONSTRUCTION_FAILURES.load(Ordering::Relaxed),
            "stripes_encoded_total": metrics::ERASURE_STRIPES_ENCODED.load(Ordering::Relaxed),
            "stripes_compressed_total": metrics::ERASURE_STRIPES_COMPRESSED.load(Ordering::Relaxed),
            "stripe_logical_bytes_total": metrics::ERASURE_STRIPE_LOGICAL_BYTES.load(Ordering::Relaxed),
            "stripe_encoded_bytes_total": metrics::ERASURE_STRIPE_ENCODED_BYTES.load(Ordering::Relaxed),
            "stripe_encoding_microseconds_total": metrics::ERASURE_STRIPE_ENCODING_MICROS.load(Ordering::Relaxed),
        }
    })))
}

async fn admin_dag_inspect(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let root = BlockStore::parse_cid(&cid)?;
    let traversal = pepper_dag::traverse(
        &state.dag_registry,
        &AgentDagResolver { state: &state },
        root.clone(),
        TraversalLimits::default(),
    )
    .await
    .map_err(ApiError::dag)?;
    let mut codecs = BTreeMap::<String, usize>::new();
    for cid in &traversal.cids {
        *codecs.entry(cid.codec.canonical_display()).or_default() += 1;
    }
    const MAX_DIAGNOSTIC_CIDS: usize = 256;
    let truncated = traversal.cids.len() > MAX_DIAGNOSTIC_CIDS;
    let cids = traversal
        .cids
        .iter()
        .take(MAX_DIAGNOSTIC_CIDS)
        .cloned()
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({
        "root_cid": root,
        "reachable_count": traversal.cids.len(),
        "decoded_payload_bytes": traversal.decoded_payload_bytes,
        "links_examined": traversal.links_examined,
        "codecs": codecs,
        "cids": cids,
        "truncated": truncated,
    })))
}

async fn admin_quarantine_purge(State(state): State<AppState>) -> Result<Json<GcReport>, ApiError> {
    let _guard = state.operation_lock.write().await;
    Ok(Json(state.block_store.purge_quarantine()?))
}

async fn admin_corruption_scan(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _guard = state.operation_lock.read().await;
    let (scanned, corrupt_cids) = state.block_store.corruption_scan()?;
    let mut recovered = Vec::new();
    let mut unrecovered = Vec::new();
    for cid in corrupt_cids {
        match get_block_resolved(&state, &cid).await {
            Ok(block) => {
                record_repair(
                    &state,
                    RepairDiagnosticRecord {
                        sequence: 0,
                        cid: cid.clone(),
                        repair_kind: "corruption_recovery".to_string(),
                        reason: "hash_mismatch".to_string(),
                        source_node: None,
                        destination_node: Some(state.status.node_id.clone()),
                        result: "verified".to_string(),
                        verified_bytes: block.size,
                        timestamp_unix_seconds: 0,
                    },
                );
                recovered.push(cid.to_string());
            }
            Err(_) => {
                state.block_store.quarantine_block(&cid)?;
                unrecovered.push(cid.to_string());
            }
        }
    }
    Ok(Json(serde_json::json!({
        "scanned": scanned,
        "corrupt": recovered.len() + unrecovered.len(),
        "recovered": recovered.len(),
        "recovered_cids": recovered,
        "unrecovered_cids": unrecovered,
    })))
}

struct AgentDagResolver<'a> {
    state: &'a AppState,
}

#[async_trait]
impl DagBlockResolver for AgentDagResolver<'_> {
    async fn resolve(&self, cid: &Cid) -> Result<Vec<u8>, String> {
        get_dag_block_from_authoritative_placement(self.state, cid)
            .await
            .map(|block| block.payload)
            .map_err(|error| error.message)
    }
}

async fn get_dag_block_from_authoritative_placement(
    state: &AppState,
    cid: &Cid,
) -> Result<pepper_types::Block, ApiError> {
    match tokio::task::block_in_place(|| state.block_store.get(cid)) {
        Ok(block) => return Ok(block),
        Err(StorageError::NotFound(_)) | Err(StorageError::HashMismatch(_)) => {}
        Err(error) => return Err(ApiError::from(error)),
    }

    let mut epochs = state.placement.epochs_descending();
    if epochs.is_empty() && state.s3.is_some() {
        s3_api::ensure_s3_current_placement_loaded(state).await?;
        epochs = state.placement.epochs_descending();
    }
    if epochs.is_empty() {
        return get_block_resolved_transient(state, cid).await;
    }

    let replication_factor = u16::try_from(state.replication_factor)
        .map_err(|_| ApiError::internal("replication factor exceeds placement limits"))?;
    let mut last_error = None;
    for epoch in epochs {
        let reference = PlacementReference::replicated(epoch, cid.clone(), replication_factor);
        match get_block_at_placement(state, cid, &reference).await {
            Ok(block) => return Ok(block),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            format!("no retained authoritative placement holds DAG block {cid}"),
        )
    }))
}

async fn traverse_reachable(state: &AppState, root: Cid) -> Result<HashSet<Cid>, ApiError> {
    pepper_dag::traverse(
        &state.dag_registry,
        &AgentDagResolver { state },
        root,
        TraversalLimits::default(),
    )
    .await
    .map(pepper_dag::Traversal::into_set)
    .map_err(ApiError::dag)
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

async fn object_bytes(state: &AppState, cid: &Cid) -> Result<Vec<u8>, ApiError> {
    match cid.codec {
        CODEC_SMALL_OBJECT => Ok(get_block_resolved(state, cid).await?.payload),
        CODEC_OBJECT_MANIFEST => {
            let manifest_block = get_block_resolved(state, cid).await?;
            let manifest: ObjectManifest =
                serde_json::from_slice(&manifest_block.payload).map_err(ApiError::serde)?;
            validate_object_resource_limits(state, &manifest)?;
            let chunks = fetch_object_chunks_parallel(state.clone(), manifest.chunks).await?;
            Ok(chunks.into_iter().flatten().collect())
        }
        CODEC_ERASURE_MANIFEST => erasure_object_bytes(state, cid).await,
        _ => Err(ApiError::bad_request("CID is not an object manifest")),
    }
}

async fn erasure_object_bytes(state: &AppState, cid: &Cid) -> Result<Vec<u8>, ApiError> {
    let manifest_block = get_block_resolved(state, cid).await?;
    let manifest: ErasureManifest =
        serde_json::from_slice(&manifest_block.payload).map_err(ApiError::serde)?;
    validate_erasure_resource_limits(state, &manifest)?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(manifest.size)
            .map_err(|_| ApiError::bad_request("erasure object is too large for this node"))?,
    );
    for stripe in &manifest.stripes {
        bytes.extend_from_slice(
            &erasure_stripe_bytes(state, manifest.data_shards, manifest.parity_shards, stripe)
                .await?,
        );
    }
    bytes.truncate(manifest.size as usize);
    ERASURE_OBJECT_READS.fetch_add(1, Ordering::Relaxed);
    Ok(bytes)
}

async fn erasure_stripe_bytes(
    state: &AppState,
    data_shards: u16,
    parity_shards: u16,
    stripe: &ErasureStripe,
) -> Result<Bytes, ApiError> {
    let logical_size = usize::try_from(stripe.size)
        .map_err(|_| ApiError::bad_request("erasure logical stripe is too large"))?;
    if let Some(bytes) = cached_erasure_stripe(state, &stripe.logical_cid, logical_size).await? {
        return Ok(bytes);
    }
    let bytes = reconstruct_erasure_stripe_bytes(state, data_shards, parity_shards, stripe).await?;
    admit_reconstructed_stripe(
        state,
        stripe.logical_cid.clone(),
        bytes.clone(),
        0..logical_size,
    );
    Ok(bytes)
}

async fn erasure_stripe_range_bytes(
    state: &AppState,
    data_shards: u16,
    parity_shards: u16,
    stripe: &ErasureStripe,
    range: std::ops::Range<usize>,
) -> Result<Bytes, ApiError> {
    let logical_size = usize::try_from(stripe.size)
        .map_err(|_| ApiError::bad_request("erasure logical stripe is too large"))?;
    if range.start >= range.end || range.end > logical_size {
        return Err(ApiError::bad_request(
            "erasure range exceeds its logical stripe",
        ));
    }
    if let Some(bytes) = cached_erasure_stripe(state, &stripe.logical_cid, logical_size).await? {
        return Ok(bytes.slice(range));
    }
    if let Some(bytes) =
        read_raw_systematic_erasure_range(state, data_shards, stripe, range.clone()).await?
    {
        return Ok(bytes);
    }
    let bytes = reconstruct_erasure_stripe_bytes(state, data_shards, parity_shards, stripe).await?;
    admit_reconstructed_stripe(
        state,
        stripe.logical_cid.clone(),
        bytes.clone(),
        range.clone(),
    );
    Ok(bytes.slice(range))
}

async fn read_raw_systematic_erasure_range(
    state: &AppState,
    data_shards: u16,
    stripe: &ErasureStripe,
    range: std::ops::Range<usize>,
) -> Result<Option<Bytes>, ApiError> {
    if stripe.encoding != ErasureStripeEncoding::Raw {
        return Ok(None);
    }
    let _read_slot = acquire_erasure_stripe_read_slot(state).await?;
    let shard_size = usize::try_from(stripe.shard_size)
        .map_err(|_| ApiError::bad_request("erasure shard is too large"))?;
    if shard_size == 0 {
        return Err(ApiError::bad_request("erasure shard size must be non-zero"));
    }
    let first = range.start / shard_size;
    let last = (range.end - 1) / shard_size;
    if last >= usize::from(data_shards) {
        return Err(ApiError::bad_request(
            "erasure range references a parity shard",
        ));
    }
    let selected = (first..=last)
        .map(|index| {
            let shard = stripe
                .shards
                .iter()
                .find(|shard| usize::from(shard.index) == index)
                .cloned()
                .ok_or_else(|| ApiError::bad_request("erasure manifest is missing a data shard"))?;
            let shard_start = index * shard_size;
            let overlap_start = range.start.max(shard_start) - shard_start;
            let overlap_end = range.end.min(shard_start + shard_size) - shard_start;
            Ok::<_, ApiError>((shard, overlap_start as u64, overlap_end as u64))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut fetches = stream::FuturesUnordered::new();
    for (shard, start, end) in selected {
        let state = state.clone();
        fetches.push(async move {
            let started = std::time::Instant::now();
            let result =
                get_block_range_at_placement(&state, &shard.cid, &shard.placement, start, end)
                    .await;
            let sample = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
            let _ = metrics::ERASURE_SHARD_FETCH_EWMA_MICROS.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| Some(current.saturating_mul(7).saturating_add(sample) / 8),
            );
            (shard, result)
        });
    }
    let mut blocks = vec![None::<Vec<u8>>; last - first + 1];
    while let Some((shard, result)) = fetches.next().await {
        let Ok(payload) = result else {
            return Ok(None);
        };
        blocks[usize::from(shard.index) - first] = Some(payload);
    }
    let mut output = Vec::with_capacity(range.end - range.start);
    for block in blocks {
        let Some(block) = block else {
            return Ok(None);
        };
        output.extend_from_slice(&block);
    }
    if output.len() != range.end - range.start {
        return Err(ApiError::internal(
            "systematic erasure range produced an unexpected length",
        ));
    }
    metrics::ERASURE_SYSTEMATIC_RANGE_BYTES.fetch_add(output.len() as u64, Ordering::Relaxed);
    Ok(Some(Bytes::from(output)))
}

async fn erasure_stripe_frames(
    state: &AppState,
    data_shards: u16,
    parity_shards: u16,
    stripe: &ErasureStripe,
) -> Result<Vec<Bytes>, ApiError> {
    let logical_size = usize::try_from(stripe.size)
        .map_err(|_| ApiError::bad_request("erasure logical stripe is too large"))?;
    if let Some(bytes) = cached_erasure_stripe(state, &stripe.logical_cid, logical_size).await? {
        return Ok(vec![bytes]);
    }
    if stripe.encoding == ErasureStripeEncoding::Zstd {
        let shards = read_erasure_data_shards(state, data_shards, parity_shards, stripe).await?;
        let encoded_size = usize::try_from(stripe.encoded_size)
            .map_err(|_| ApiError::bad_request("erasure encoded stripe is too large"))?;
        let logical_cid = stripe.logical_cid.clone();
        let frames = tokio::task::spawn_blocking(move || {
            decode_zstd_erasure_stripe_frames(shards, encoded_size, logical_size, &logical_cid)
        })
        .await
        .map_err(|error| {
            ApiError::internal(format!("erasure decompressor task failed: {error}"))
        })??;
        metrics::ERASURE_STREAMED_DECOMPRESSION_BYTES.fetch_add(stripe.size, Ordering::Relaxed);
        admit_reconstructed_stripe_frames(
            state,
            stripe.logical_cid.clone(),
            frames.clone(),
            logical_size,
        );
        return Ok(frames);
    }

    let shards = read_erasure_data_shards(state, data_shards, parity_shards, stripe).await?;
    let mut remaining = logical_size;
    let mut frames = Vec::with_capacity(shards.len());
    for shard in shards {
        if remaining == 0 {
            break;
        }
        let take = remaining.min(shard.len());
        let mut frame = Bytes::from(shard);
        frame.truncate(take);
        frames.push(frame);
        remaining -= take;
    }
    if remaining != 0 {
        return Err(ApiError::internal(
            "erasure systematic shards are shorter than the logical stripe",
        ));
    }
    let segments = frames.iter().map(Bytes::as_ref).collect::<Vec<_>>();
    if !stripe.logical_cid.verify_segments(&segments) {
        return Err(ApiError::internal(
            "erasure stripe logical checksum mismatch",
        ));
    }
    metrics::ERASURE_ZERO_COPY_STREAMED_BYTES.fetch_add(stripe.size, Ordering::Relaxed);
    admit_reconstructed_stripe_frames(
        state,
        stripe.logical_cid.clone(),
        frames.clone(),
        logical_size,
    );
    Ok(frames)
}

fn decode_zstd_erasure_stripe_frames(
    shards: Vec<Vec<u8>>,
    encoded_size: usize,
    logical_size: usize,
    logical_cid: &Cid,
) -> Result<Vec<Bytes>, ApiError> {
    const RESPONSE_FRAME_BYTES: usize = 4 * 1024 * 1024;
    let mut decoder = zstd_safe::DCtx::try_create()
        .ok_or_else(|| ApiError::internal("could not allocate erasure decompressor"))?;
    let mut encoded_remaining = encoded_size;
    let mut logical_produced = 0usize;
    let mut frame_finished = false;
    let mut frames = Vec::with_capacity(logical_size.div_ceil(RESPONSE_FRAME_BYTES));
    for shard in shards {
        if encoded_remaining == 0 {
            break;
        }
        let input_size = shard.len().min(encoded_remaining);
        encoded_remaining -= input_size;
        let mut input = zstd_safe::InBuffer {
            src: &shard[..input_size],
            pos: 0,
        };
        while input.pos < input.src.len() {
            let remaining_bound = logical_size.saturating_sub(logical_produced);
            let mut frame = Vec::with_capacity(RESPONSE_FRAME_BYTES.min(remaining_bound + 1));
            let input_before = input.pos;
            let (hint, output_size) = {
                let mut output = zstd_safe::OutBuffer::around(&mut frame);
                let hint = decoder
                    .decompress_stream(&mut output, &mut input)
                    .map_err(|code| {
                        ApiError::internal(format!(
                            "erasure decompression failed: {}",
                            zstd_safe::get_error_name(code)
                        ))
                    })?;
                (hint, output.pos())
            };
            if logical_produced.saturating_add(output_size) > logical_size {
                return Err(ApiError::internal(
                    "erasure stripe decompressed beyond its logical size",
                ));
            }
            logical_produced += output_size;
            if !frame.is_empty() {
                frames.push(Bytes::from(frame));
            }
            if hint == 0 {
                frame_finished = true;
                if input.pos != input.src.len() || encoded_remaining != 0 {
                    return Err(ApiError::internal(
                        "erasure stripe contains trailing compressed bytes",
                    ));
                }
                break;
            }
            if input.pos == input_before && output_size == 0 {
                return Err(ApiError::internal(
                    "erasure decompressor made no forward progress",
                ));
            }
        }
    }
    if !frame_finished {
        return Err(ApiError::internal(
            "erasure stripe contains a truncated compressed frame",
        ));
    }
    if logical_produced != logical_size {
        return Err(ApiError::internal(
            "erasure stripe decoded to an unexpected logical size",
        ));
    }
    let segments = frames.iter().map(Bytes::as_ref).collect::<Vec<_>>();
    if !logical_cid.verify_segments(&segments) {
        return Err(ApiError::internal(
            "erasure stripe logical checksum mismatch",
        ));
    }
    Ok(frames)
}

async fn cached_erasure_stripe(
    state: &AppState,
    cid: &Cid,
    logical_size: usize,
) -> Result<Option<Bytes>, ApiError> {
    if let Some(cache) = &state.reconstructed_stripe_cache {
        let cache = cache.clone();
        let cid = cid.clone();
        return tokio::task::spawn_blocking(move || cache.get(&cid, logical_size))
            .await
            .map_err(|error| ApiError::internal(format!("cache reader task failed: {error}")));
    }
    Ok(None)
}

fn admit_reconstructed_stripe(
    state: &AppState,
    cid: Cid,
    bytes: Bytes,
    observation: std::ops::Range<usize>,
) {
    let Some(cache) = &state.reconstructed_stripe_cache else {
        return;
    };
    let cache = cache.clone();
    // This cache is disposable and never receives durability credit. Do not
    // hold the response behind a large cache-file write; the verified
    // reconstructed bytes can be returned while admission completes on the
    // blocking pool.
    if let Some(write_slot) = cache.try_write_slot() {
        let _admission = tokio::task::spawn_blocking(move || {
            cache.observe_range_and_maybe_put(&cid, &bytes, observation);
            drop(write_slot);
        });
    } else {
        cache.record_write_saturation_bypass();
    }
}

fn admit_reconstructed_stripe_frames(
    state: &AppState,
    cid: Cid,
    frames: Vec<Bytes>,
    logical_size: usize,
) {
    let Some(cache) = &state.reconstructed_stripe_cache else {
        return;
    };
    let cache = cache.clone();
    if let Some(write_slot) = cache.try_write_slot() {
        let _admission = tokio::task::spawn_blocking(move || {
            cache.observe_and_maybe_put_frames(&cid, &frames, logical_size);
            drop(write_slot);
        });
    } else {
        cache.record_write_saturation_bypass();
    }
}

async fn reconstruct_erasure_stripe_bytes(
    state: &AppState,
    data_shards: u16,
    parity_shards: u16,
    stripe: &ErasureStripe,
) -> Result<Bytes, ApiError> {
    let logical_size = usize::try_from(stripe.size)
        .map_err(|_| ApiError::bad_request("erasure logical stripe is too large"))?;
    let data_shards = read_erasure_data_shards(state, data_shards, parity_shards, stripe).await?;
    let encoded_size = usize::try_from(stripe.encoded_size)
        .map_err(|_| ApiError::bad_request("erasure encoded stripe is too large"))?;
    let mut encoded = Vec::with_capacity(encoded_size);
    for shard in data_shards {
        encoded.extend_from_slice(&shard);
    }
    encoded.truncate(encoded_size);
    let encoding = stripe.encoding;
    let logical_cid = stripe.logical_cid.clone();
    let logical = tokio::task::spawn_blocking(move || {
        decode_erasure_stripe_payload(encoding, encoded, logical_size, &logical_cid)
    })
    .await
    .map_err(|error| ApiError::internal(format!("erasure decompressor task failed: {error}")))??;
    Ok(Bytes::from(logical))
}

async fn read_erasure_data_shards(
    state: &AppState,
    data_shards: u16,
    parity_shards: u16,
    stripe: &ErasureStripe,
) -> Result<Vec<Vec<u8>>, ApiError> {
    let _read_slot = acquire_erasure_stripe_read_slot(state).await?;
    let active_stripe_reads = metrics::ERASURE_ACTIVE_STRIPE_READS
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    let _active_guard = ErasureActiveStripeReadGuard;
    let allow_one_hedge = active_stripe_reads <= ERASURE_HEDGE_MAX_ACTIVE_STRIPE_READS;
    let mut hedge_issued = false;
    let data_shards = data_shards as usize;
    let parity_shards = parity_shards as usize;
    let total_shards = data_shards + parity_shards;
    let shard_size = stripe.shard_size as usize;
    let mut shards = vec![None::<Vec<u8>>; total_shards];
    let mut fetches = stream::FuturesUnordered::new();
    for shard in stripe.shards.iter().take(data_shards).cloned() {
        fetches.push(fetch_erasure_shard(state.clone(), shard));
    }
    let mut parity = stripe.shards.iter().skip(data_shards).cloned();
    let mut available = 0usize;
    while available < data_shards {
        if fetches.is_empty() {
            let Some(shard) = parity.next() else { break };
            fetches.push(fetch_erasure_shard(state.clone(), shard));
        }
        let next = if allow_one_hedge && !hedge_issued {
            let hedge_delay = erasure_shard_hedge_delay();
            match time::timeout(hedge_delay, fetches.next()).await {
                Ok(next) => next,
                Err(_) => {
                    if let Some(shard) = parity.next() {
                        hedge_issued = true;
                        metrics::ERASURE_SHARD_READ_HEDGES.fetch_add(1, Ordering::Relaxed);
                        fetches.push(fetch_erasure_shard(state.clone(), shard));
                        continue;
                    } else {
                        fetches.next().await
                    }
                }
            }
        } else {
            fetches.next().await
        };
        let Some((shard, result)) = next else {
            continue;
        };
        match result {
            Ok(block) if block.payload.len() == shard_size => {
                let slot = &mut shards[shard.index as usize];
                if slot.is_none() {
                    *slot = Some(block.payload);
                    available += 1;
                }
            }
            Ok(_) => warn!(cid = %shard.cid, "erasure shard size mismatch"),
            Err(error) => warn!(?error, cid = %shard.cid, "erasure shard unavailable"),
        }
    }
    if available < data_shards {
        ERASURE_RECONSTRUCTION_FAILURES.fetch_add(1, Ordering::Relaxed);
        return Err(ApiError::internal(
            "not enough erasure shards to reconstruct object",
        ));
    }
    if shards.iter().take(data_shards).any(Option::is_none) {
        shards = tokio::task::spawn_blocking(move || {
            let reed_solomon = ReedSolomon::new(data_shards, parity_shards)
                .map_err(|error| ApiError::internal(error.to_string()))?;
            reed_solomon
                .reconstruct(&mut shards)
                .map_err(|error| ApiError::internal(error.to_string()))?;
            Ok::<_, ApiError>(shards)
        })
        .await
        .map_err(|error| ApiError::internal(format!("erasure decoder task failed: {error}")))??;
    }
    let mut data = Vec::with_capacity(data_shards);
    for shard in shards.iter_mut().take(data_shards) {
        let shard = shard
            .take()
            .ok_or_else(|| ApiError::internal("erasure reconstruction left data shard missing"))?;
        data.push(shard);
    }
    Ok(data)
}

async fn acquire_erasure_stripe_read_slot(
    state: &AppState,
) -> Result<tokio::sync::OwnedSemaphorePermit, ApiError> {
    let started = time::Instant::now();
    let permit = fast_path::stripe_read_slots()
        .unwrap_or_else(|| state.erasure_stripe_read_slots.clone())
        .acquire_owned()
        .await
        .map_err(|_| ApiError::internal("erasure read scheduler is unavailable"))?;
    metrics::ERASURE_READ_ADMISSION_QUEUE_MICROS.fetch_add(
        started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
    metrics::ERASURE_READ_ADMISSION_OBSERVATIONS.fetch_add(1, Ordering::Relaxed);
    Ok(permit)
}

struct ErasureActiveStripeReadGuard;

impl Drop for ErasureActiveStripeReadGuard {
    fn drop(&mut self) {
        metrics::ERASURE_ACTIVE_STRIPE_READS.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn fetch_erasure_shard(
    state: AppState,
    shard: ErasureShard,
) -> (ErasureShard, Result<pepper_types::Block, ApiError>) {
    let started = std::time::Instant::now();
    let result = get_block_at_placement(&state, &shard.cid, &shard.placement).await;
    let sample = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    let _ = metrics::ERASURE_SHARD_FETCH_EWMA_MICROS.fetch_update(
        Ordering::Relaxed,
        Ordering::Relaxed,
        |current| Some(current.saturating_mul(7).saturating_add(sample) / 8),
    );
    (shard, result)
}

fn erasure_shard_hedge_delay() -> Duration {
    Duration::from_micros(
        metrics::ERASURE_SHARD_FETCH_EWMA_MICROS
            .load(Ordering::Relaxed)
            .saturating_mul(4)
            .clamp(10_000, 100_000),
    )
}

fn decode_erasure_stripe_payload(
    encoding: ErasureStripeEncoding,
    encoded: Vec<u8>,
    logical_size: usize,
    logical_cid: &Cid,
) -> Result<Vec<u8>, ApiError> {
    let logical = match encoding {
        ErasureStripeEncoding::Raw => encoded,
        ErasureStripeEncoding::Zstd => {
            zstd::bulk::decompress(&encoded, logical_size).map_err(|error| {
                ApiError::internal(format!("erasure decompression failed: {error}"))
            })?
        }
    };
    if logical.len() != logical_size {
        return Err(ApiError::internal(format!(
            "erasure stripe decoded to {} bytes; expected {logical_size}",
            logical.len()
        )));
    }
    if !logical_cid.verify(&logical) {
        return Err(ApiError::internal(
            "erasure stripe logical checksum mismatch",
        ));
    }
    Ok(logical)
}

async fn restore_dir_manifest(state: &AppState, cid: &Cid, path: &FsPath) -> Result<(), ApiError> {
    std::fs::create_dir_all(path).map_err(|error| ApiError::internal(error.to_string()))?;
    let block = get_block_resolved(state, cid).await?;
    let manifest: DirManifest = serde_json::from_slice(&block.payload).map_err(ApiError::serde)?;
    manifest.validate().map_err(ApiError::manifest)?;
    for entry in manifest.entries {
        let target = path.join(&entry.path);
        if entry.kind == "directory" {
            std::fs::create_dir_all(&target)
                .map_err(|error| ApiError::internal(error.to_string()))?;
        } else if let Some(cid) = entry.cid {
            let bytes = match cid.codec {
                CODEC_RAW => get_block_resolved(state, &cid).await?.payload,
                CODEC_SMALL_OBJECT | CODEC_OBJECT_MANIFEST | CODEC_ERASURE_MANIFEST => {
                    object_bytes(state, &cid).await?
                }
                _ => return Err(ApiError::bad_request("unsupported directory file codec")),
            };
            write_bytes(&target, &bytes)?;
        }
    }
    Ok(())
}

async fn collect_compute_output(
    state: &AppState,
    work_dir: &FsPath,
    outputs: &[pepper_types::ComputeOutput],
) -> Result<Option<Cid>, ApiError> {
    let output_path = if outputs.is_empty() {
        work_dir.join("output")
    } else {
        let collection = work_dir.join(".pepper-collected");
        if collection.exists() {
            std::fs::remove_dir_all(&collection)
                .map_err(|error| ApiError::internal(error.to_string()))?;
        }
        std::fs::create_dir_all(&collection)
            .map_err(|error| ApiError::internal(error.to_string()))?;
        for output in outputs {
            let source = safe_join(work_dir, &output.path)?;
            if !source.exists() {
                continue;
            }
            let target = safe_join(&collection, &output.name)?;
            copy_output_path(&source, &target)?;
        }
        collection
    };
    let root_cid = if output_path.is_dir() {
        let manifest = build_dir_manifest_from_path(state, &output_path).await?;
        let bytes = serde_json::to_vec(&manifest).map_err(ApiError::serde)?;
        Some(
            put_replicated_block(state, CODEC_DIR_MANIFEST, bytes)
                .await?
                .cid,
        )
    } else if output_path.is_file() {
        let bytes =
            std::fs::read(&output_path).map_err(|error| ApiError::internal(error.to_string()))?;
        Some(put_object_bytes_internal(state, bytes).await?)
    } else {
        None
    };
    if let Some(cid) = &root_cid {
        ensure_implicit_pin(state, cid).await?;
    }
    Ok(root_cid)
}

fn copy_output_path(source: &FsPath, target: &FsPath) -> Result<(), ApiError> {
    let metadata =
        std::fs::symlink_metadata(source).map_err(|error| ApiError::internal(error.to_string()))?;
    if metadata.file_type().is_symlink() {
        return Err(ApiError::bad_request(
            "compute outputs must not contain symlinks",
        ));
    }
    if metadata.is_file() {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| ApiError::internal(error.to_string()))?;
        }
        std::fs::copy(source, target).map_err(|error| ApiError::internal(error.to_string()))?;
        return Ok(());
    }
    if metadata.is_dir() {
        std::fs::create_dir_all(target).map_err(|error| ApiError::internal(error.to_string()))?;
        for entry in
            std::fs::read_dir(source).map_err(|error| ApiError::internal(error.to_string()))?
        {
            let entry = entry.map_err(|error| ApiError::internal(error.to_string()))?;
            copy_output_path(&entry.path(), &target.join(entry.file_name()))?;
        }
        return Ok(());
    }
    Err(ApiError::bad_request("unsupported compute output type"))
}

async fn build_dir_manifest_from_path(
    state: &AppState,
    root: &FsPath,
) -> Result<DirManifest, ApiError> {
    let mut entries = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in
            std::fs::read_dir(&path).map_err(|error| ApiError::internal(error.to_string()))?
        {
            let path = entry
                .map_err(|error| ApiError::internal(error.to_string()))?
                .path();
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| ApiError::internal(error.to_string()))?;
            if metadata.file_type().is_symlink() {
                return Err(ApiError::bad_request(
                    "compute outputs must not contain symlinks",
                ));
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|error| ApiError::internal(error.to_string()))?
                .to_string_lossy()
                .replace('\\', "/");
            if metadata.is_dir() {
                entries.push(DirEntry {
                    path: relative,
                    kind: "directory".to_string(),
                    mode: 0o755,
                    size: None,
                    cid: None,
                });
                stack.push(path);
            } else if metadata.is_file() {
                let bytes =
                    std::fs::read(&path).map_err(|error| ApiError::internal(error.to_string()))?;
                let cid = put_object_bytes_internal(state, bytes).await?;
                entries.push(DirEntry {
                    path: relative,
                    kind: "file".to_string(),
                    mode: 0o644,
                    size: Some(metadata.len()),
                    cid: Some(cid),
                });
            } else {
                return Err(ApiError::bad_request(
                    "compute outputs must contain only regular files and directories",
                ));
            }
        }
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = DirManifest::new(entries);
    manifest.validate().map_err(ApiError::manifest)?;
    Ok(manifest)
}

async fn read_body_limited(
    body: Body,
    limit: Option<u64>,
    name: &str,
) -> Result<Vec<u8>, ApiError> {
    let mut stream = body.into_data_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| ApiError::bad_request(error.to_string()))?;
        let new_len = (bytes.len() as u64).saturating_add(chunk.len() as u64);
        enforce_size_limit(limit, new_len, name)?;
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

struct ObjectWriteReceipts {
    receipt: DurabilityReceipt,
    blocks: Vec<DurabilityReceipt>,
}

async fn put_policy_object_stream_receipts(
    state: &AppState,
    body: Body,
    content_length: Option<u64>,
    force_erasure: bool,
) -> Result<ObjectWriteReceipts, ApiError> {
    if !force_erasure
        && content_length.is_some_and(|length| {
            state
                .small_object_max_bytes
                .is_some_and(|maximum| length <= maximum)
        })
    {
        return put_small_object_stream_receipts(state, body).await;
    }
    if content_length.is_none()
        && !force_erasure
        && let Some(maximum) = state.small_object_max_bytes
    {
        let mut source = body.into_data_stream();
        let mut prefix = Vec::<Bytes>::new();
        let mut prefix_bytes = 0u64;
        loop {
            let Some(chunk) = source.next().await else {
                let body = Body::from_stream(stream::iter(
                    prefix
                        .into_iter()
                        .map(Ok::<Bytes, std::convert::Infallible>),
                ));
                return put_small_object_stream_receipts(state, body).await;
            };
            let chunk = chunk.map_err(|error| ApiError::bad_request(error.to_string()))?;
            prefix_bytes = prefix_bytes.saturating_add(chunk.len() as u64);
            prefix.push(chunk);
            if prefix_bytes > maximum {
                let body = Body::from_stream(
                    stream::iter(prefix.into_iter().map(Ok::<Bytes, axum::Error>)).chain(source),
                );
                return put_non_small_policy_stream_receipts(state, body, None, false).await;
            }
        }
    }
    put_non_small_policy_stream_receipts(state, body, content_length, force_erasure).await
}

async fn put_non_small_policy_stream_receipts(
    state: &AppState,
    body: Body,
    content_length: Option<u64>,
    force_erasure: bool,
) -> Result<ObjectWriteReceipts, ApiError> {
    if !state.erasure_enabled {
        return put_object_stream_receipts(state, body).await;
    }
    if force_erasure || content_length.is_some_and(|length| length >= state.erasure_min_size_bytes)
    {
        return put_erasure_object_stream_receipts(
            state,
            body,
            state.erasure_data_shards,
            state.erasure_parity_shards,
        )
        .await;
    }
    if content_length.is_some() {
        return put_object_stream_receipts(state, body).await;
    }

    let mut source = body.into_data_stream();
    let mut prefix = Vec::<Bytes>::new();
    let mut prefix_bytes = 0u64;
    while prefix_bytes < state.erasure_min_size_bytes {
        let Some(chunk) = source.next().await else {
            let body = Body::from_stream(stream::iter(
                prefix
                    .into_iter()
                    .map(Ok::<Bytes, std::convert::Infallible>),
            ));
            return put_object_stream_receipts(state, body).await;
        };
        let chunk = chunk.map_err(|error| ApiError::bad_request(error.to_string()))?;
        prefix_bytes = prefix_bytes.saturating_add(chunk.len() as u64);
        prefix.push(chunk);
    }
    let body = Body::from_stream(
        stream::iter(prefix.into_iter().map(Ok::<Bytes, axum::Error>)).chain(source),
    );
    put_erasure_object_stream_receipts(
        state,
        body,
        state.erasure_data_shards,
        state.erasure_parity_shards,
    )
    .await
}

async fn put_small_object_stream_receipts(
    state: &AppState,
    body: Body,
) -> Result<ObjectWriteReceipts, ApiError> {
    let maximum = state
        .small_object_max_bytes
        .ok_or_else(|| ApiError::internal("small-object packing is disabled"))?;
    let payload = read_body_limited(body, Some(maximum), "small object").await?;
    let receipt = put_replicated_block(state, CODEC_SMALL_OBJECT, payload).await?;
    Ok(ObjectWriteReceipts {
        receipt: receipt.clone(),
        blocks: vec![receipt],
    })
}

async fn put_erasure_object_stream_receipts(
    state: &AppState,
    body: Body,
    data_shards: u16,
    parity_shards: u16,
) -> Result<ObjectWriteReceipts, ApiError> {
    put_erasure_object_stream_receipts_with_compression(
        state,
        body,
        data_shards,
        parity_shards,
        true,
    )
    .await
}

async fn put_erasure_object_stream_receipts_with_compression(
    state: &AppState,
    body: Body,
    data_shards: u16,
    parity_shards: u16,
    allow_compression: bool,
) -> Result<ObjectWriteReceipts, ApiError> {
    validate_erasure_policy(data_shards, parity_shards)?;
    let max_block_bytes = state.max_block_bytes.unwrap_or(DEFAULT_MAX_BLOCK_BYTES);
    let shard_size = max_block_bytes.min(OBJECT_CHUNK_SIZE as u64) as usize;
    if shard_size == 0 {
        return Err(ApiError::internal(
            "erasure stripe shard size must be greater than zero",
        ));
    }
    let stripe_size = shard_size
        .checked_mul(data_shards as usize)
        .ok_or_else(|| ApiError::bad_request("erasure stripe size overflow"))?;
    let candidates = placement_candidates(state, state.network.peers().await);
    let pipeline_depth = object_chunk_pipeline_depth(1).clamp(1, 4);
    let mut body_stream = body.into_data_stream();
    let mut pending = Vec::with_capacity(stripe_size);
    let mut transfers = stream::FuturesOrdered::new();
    let mut stripes = Vec::new();
    let mut block_receipts = Vec::new();
    let mut total = 0u64;
    let mut next_offset = 0u64;
    let mut all_stripes_durable = true;
    let request_plan = Arc::new(OnceCell::new());
    let stripe_context = Arc::new(ErasureStripeStoreContext {
        data_shards,
        parity_shards,
        candidates,
        request_plan,
        allow_compression,
    });

    loop {
        let streaming_started = time::Instant::now();
        let next = body_stream.next().await;
        metrics::observe_phase(
            &metrics::S3_REQUEST_STREAMING_PHASES,
            &metrics::S3_REQUEST_STREAMING_MICROS,
            streaming_started.elapsed(),
        );
        let Some(data) = next else {
            break;
        };
        let data = data.map_err(|error| ApiError::bad_request(error.to_string()))?;
        let projected = total.saturating_add(data.len() as u64);
        enforce_size_limit(state.max_object_bytes, projected, "erasure object")?;
        total = projected;
        let mut remaining = data.as_ref();
        while !remaining.is_empty() {
            let take = (stripe_size - pending.len()).min(remaining.len());
            pending.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            if pending.len() == stripe_size {
                let payload = std::mem::replace(&mut pending, Vec::with_capacity(stripe_size));
                transfers.push_back(encode_and_store_erasure_stripe(
                    state,
                    payload,
                    next_offset,
                    stripe_context.clone(),
                ));
                next_offset = next_offset.saturating_add(stripe_size as u64);
                if transfers.len() >= pipeline_depth {
                    let stored = transfers
                        .next()
                        .await
                        .expect("a full erasure stripe pipeline has a result")?;
                    all_stripes_durable &=
                        stored.distinct_nodes >= data_shards.saturating_add(parity_shards) as usize;
                    stripes.push(stored.stripe);
                    block_receipts.extend(stored.receipts);
                }
            }
        }
    }
    if !pending.is_empty() {
        transfers.push_back(encode_and_store_erasure_stripe(
            state,
            pending,
            next_offset,
            stripe_context,
        ));
    }
    while let Some(stored) = transfers.next().await {
        let stored = stored?;
        all_stripes_durable &=
            stored.distinct_nodes >= data_shards.saturating_add(parity_shards) as usize;
        stripes.push(stored.stripe);
        block_receipts.extend(stored.receipts);
    }

    let manifest = ErasureManifest::new(
        total,
        data_shards,
        parity_shards,
        stripe_size as u64,
        stripes,
    );
    manifest.validate().map_err(ApiError::manifest)?;
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(ApiError::serde)?;
    let mut receipt = put_replicated_block(state, CODEC_ERASURE_MANIFEST, manifest_bytes).await?;
    if !all_stripes_durable {
        receipt.status = "degraded".to_string();
    }
    ERASURE_OBJECT_WRITES.fetch_add(1, Ordering::Relaxed);
    block_receipts.push(receipt.clone());
    Ok(ObjectWriteReceipts {
        receipt,
        blocks: block_receipts,
    })
}

async fn put_object_stream_receipts(
    state: &AppState,
    body: Body,
) -> Result<ObjectWriteReceipts, ApiError> {
    let mut body_stream = body.into_data_stream();
    let mut pending = Vec::with_capacity(OBJECT_CHUNK_SIZE);
    let mut transfers = stream::FuturesOrdered::new();
    let mut chunks = Vec::new();
    let mut block_receipts = Vec::new();
    let mut total = 0u64;
    let mut next_chunk_offset = 0u64;
    let mut all_chunks_durable = true;
    let pipeline_depth = object_chunk_pipeline_depth(state.replication_factor);
    loop {
        let streaming_started = time::Instant::now();
        let next = body_stream.next().await;
        metrics::observe_phase(
            &metrics::S3_REQUEST_STREAMING_PHASES,
            &metrics::S3_REQUEST_STREAMING_MICROS,
            streaming_started.elapsed(),
        );
        let Some(data) = next else {
            break;
        };
        let data = data.map_err(|error| ApiError::bad_request(error.to_string()))?;
        let projected = total.saturating_add(data.len() as u64);
        enforce_size_limit(state.max_object_bytes, projected, "object")?;
        total = projected;
        let mut remaining = data.as_ref();
        while !remaining.is_empty() {
            let take = (OBJECT_CHUNK_SIZE - pending.len()).min(remaining.len());
            pending.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            if pending.len() == OBJECT_CHUNK_SIZE {
                let payload =
                    std::mem::replace(&mut pending, Vec::with_capacity(OBJECT_CHUNK_SIZE));
                transfers.push_back(put_object_chunk(state, payload, next_chunk_offset));
                next_chunk_offset += OBJECT_CHUNK_SIZE as u64;
                if transfers.len() >= pipeline_depth {
                    let (chunk, receipt) = transfers
                        .next()
                        .await
                        .expect("a full object chunk pipeline has a result")?;
                    all_chunks_durable &= receipt.status == "durable";
                    chunks.push(chunk);
                    block_receipts.push(receipt);
                }
            }
        }
    }
    if !pending.is_empty() {
        transfers.push_back(put_object_chunk(state, pending, next_chunk_offset));
    }
    while let Some(result) = transfers.next().await {
        let (chunk, receipt) = result?;
        all_chunks_durable &= receipt.status == "durable";
        chunks.push(chunk);
        block_receipts.push(receipt);
    }
    let manifest = ObjectManifest::new(total, OBJECT_CHUNK_SIZE as u64, chunks);
    manifest.validate().map_err(ApiError::manifest)?;
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(ApiError::serde)?;
    let mut receipt = put_replicated_block(state, CODEC_OBJECT_MANIFEST, manifest_bytes).await?;
    if !all_chunks_durable {
        receipt.status = "degraded".to_string();
    }
    block_receipts.push(receipt.clone());
    Ok(ObjectWriteReceipts {
        receipt,
        blocks: block_receipts,
    })
}

async fn put_object_bytes_internal(state: &AppState, bytes: Vec<u8>) -> Result<Cid, ApiError> {
    Ok(put_object_bytes_receipt(state, bytes).await?.cid)
}

async fn put_object_bytes_receipt(
    state: &AppState,
    bytes: Vec<u8>,
) -> Result<DurabilityReceipt, ApiError> {
    enforce_size_limit(state.max_object_bytes, bytes.len() as u64, "object")?;
    let mut transfers = stream::FuturesOrdered::new();
    let mut chunks = Vec::new();
    let mut all_chunks_durable = true;
    let pipeline_depth = object_chunk_pipeline_depth(state.replication_factor);
    for (index, chunk) in bytes.chunks(OBJECT_CHUNK_SIZE).enumerate() {
        transfers.push_back(put_object_chunk(
            state,
            chunk.to_vec(),
            (index * OBJECT_CHUNK_SIZE) as u64,
        ));
        if transfers.len() >= pipeline_depth {
            let (chunk, receipt) = transfers
                .next()
                .await
                .expect("a full object chunk pipeline has a result")?;
            all_chunks_durable &= receipt.status == "durable";
            chunks.push(chunk);
        }
    }
    while let Some(result) = transfers.next().await {
        let (chunk, receipt) = result?;
        all_chunks_durable &= receipt.status == "durable";
        chunks.push(chunk);
    }
    let manifest = ObjectManifest::new(bytes.len() as u64, OBJECT_CHUNK_SIZE as u64, chunks);
    manifest.validate().map_err(ApiError::manifest)?;
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(ApiError::serde)?;
    let mut receipt = put_replicated_block(state, CODEC_OBJECT_MANIFEST, manifest_bytes).await?;
    if !all_chunks_durable {
        receipt.status = "degraded".to_string();
    }
    Ok(receipt)
}

async fn put_object_chunk(
    state: &AppState,
    payload: Vec<u8>,
    offset: u64,
) -> Result<(ObjectChunk, DurabilityReceipt), ApiError> {
    let size = payload.len() as u64;
    let receipt = put_replicated_block(state, CODEC_RAW, payload).await?;
    let placement = receipt.placement.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "object chunk was stored without authoritative placement",
        )
    })?;
    Ok((
        ObjectChunk {
            offset,
            size,
            cid: receipt.cid.clone(),
            placement,
        },
        receipt,
    ))
}

fn object_chunk_pipeline_depth(replication_factor: usize) -> usize {
    if replication_factor > 1 {
        OBJECT_CHUNK_PIPELINE_DEPTH
    } else {
        1
    }
}

fn safe_join(root: &FsPath, requested: &str) -> Result<PathBuf, ApiError> {
    let relative = requested.strip_prefix('/').unwrap_or(requested);
    if relative.is_empty()
        || relative.starts_with('/')
        || relative.contains('\\')
        || relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ApiError::bad_request(
            "path must be a safe non-empty relative path",
        ));
    }
    Ok(root.join(relative))
}

fn write_bytes(path: &FsPath, bytes: &[u8]) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| ApiError::internal(error.to_string()))?;
    }
    std::fs::write(path, bytes).map_err(|error| ApiError::internal(error.to_string()))
}

fn persist_job(state: &AppState, job: &ComputeJobStatus) -> Result<(), ApiError> {
    let write_txn = state
        .metadata
        .database()
        .begin_write()
        .map_err(ApiError::redb_transaction)?;
    {
        let mut table = write_txn.open_table(JOBS).map_err(ApiError::redb_table)?;
        let existing = table
            .get(job.job_id.as_str())
            .map_err(ApiError::redb_storage)?
            .map(|value| serde_json::from_slice::<ComputeJobStatus>(value.value()))
            .transpose()
            .map_err(ApiError::serde)?;
        if let Some(existing) = existing
            && is_terminal_job_status(&existing.status)
            && existing.status != job.status
        {
            return Ok(());
        }
        let bytes = serde_json::to_vec(job).map_err(ApiError::serde)?;
        table
            .insert(job.job_id.as_str(), bytes.as_slice())
            .map_err(ApiError::redb_storage)?;
    }
    write_txn.commit().map_err(ApiError::redb_commit)?;
    Ok(())
}

fn is_terminal_job_status(status: &str) -> bool {
    matches!(status, "succeeded" | "failed" | "timed_out" | "canceled")
}

fn load_job(state: &AppState, job_id: &str) -> Result<Option<ComputeJobStatus>, ApiError> {
    let read_txn = state
        .metadata
        .database()
        .begin_read()
        .map_err(ApiError::redb_transaction)?;
    let table = match read_txn.open_table(JOBS) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(error) => return Err(ApiError::redb_table(error)),
    };
    table
        .get(job_id)
        .map_err(ApiError::redb_storage)?
        .map(|value| serde_json::from_slice(value.value()).map_err(ApiError::serde))
        .transpose()
}

fn next_pin_id() -> String {
    let mut nonce = [0u8; 16];
    if getrandom::fill(&mut nonce).is_ok() {
        format!("pin-{}", hex::encode(nonce))
    } else {
        format!(
            "pin-{}-{}-{}",
            unix_seconds(),
            std::process::id(),
            PIN_COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }
}

fn next_job_id() -> String {
    let mut nonce = [0u8; 16];
    if getrandom::fill(&mut nonce).is_ok() {
        format!("job-{}", hex::encode(nonce))
    } else {
        format!(
            "job-{}-{}-{}",
            unix_seconds(),
            std::process::id(),
            JOB_COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }
}

fn validate_job_id(job_id: &str) -> Result<(), ApiError> {
    if job_id.is_empty()
        || job_id.len() > 96
        || !job_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(ApiError::bad_request("invalid compute job ID"));
    }
    Ok(())
}

async fn healthz() -> &'static str {
    "ok\n"
}

async fn readyz(State(state): State<AppState>) -> Response {
    let statuses = if let Some(manager) = &state.namespace_groups {
        manager.operational_statuses().await
    } else {
        Vec::new()
    };
    // A healthy follower commonly trails the last appended entry while a
    // write is in flight. Requiring exact zero lag made readiness oscillate on
    // every busy namespace even though the gateway could route linearizable
    // I/O to the known leader. Readiness describes whether the group can
    // serve/reroute requests; exact apply lag remains an admin metric and a
    // benchmark health assertion.
    let ready = statuses.iter().all(|status| {
        status.running
            && status.leader_raft_id.is_some()
            && status.voter_count == 3
            && !status.membership_joint
            && (status.role != "leader" || status.quorum_recently_acknowledged)
    });
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(serde_json::json!({
            "ready": ready,
            "node_id": state.status.node_id,
            "namespace_groups": statuses
        })),
    )
        .into_response()
}

async fn require_http_auth_and_rate_limit(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let s3_request = state.s3.is_some()
        && !request.uri().path().starts_with("/v1/")
        && !matches!(request.uri().path(), "/healthz" | "/readyz" | "/metrics");
    let permit = if s3_request && state.fast_path.is_some() {
        None
    } else {
        Some(match state.http_concurrency.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) if s3_request => {
                metrics::S3_HTTP_ADMISSION_REJECTIONS.fetch_add(1, Ordering::Relaxed);
                return Ok(S3Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "SlowDown",
                    "the bounded S3 request queue is full",
                    request.uri().path(),
                )
                .into_response());
            }
            Err(_) => {
                return Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::Unavailable,
                    "HTTP concurrency limit exceeded",
                ));
            }
        })
    };
    if let Some(token) = &state.api_bearer_token
        && !s3_request
    {
        let expected = format!("Bearer {token}");
        let authorized = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(|value| constant_time_eq(value.as_bytes(), expected.as_bytes()))
            .unwrap_or(false);
        if !authorized {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                ErrorCode::Unauthorized,
                "missing or invalid bearer token",
            ));
        }
    }
    if let Some(limit) = state.http_requests_per_minute {
        // The API is local/private by design. Do not trust caller-controlled forwarding headers.
        check_http_rate_limit(&state, "api", limit)?;
    }
    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    let stream = body.into_data_stream().map(move |result| {
        let _permit = &permit;
        result
    });
    Ok(Response::from_parts(parts, Body::from_stream(stream)))
}

fn check_http_rate_limit(state: &AppState, key: &str, limit: u64) -> Result<(), ApiError> {
    let now = unix_seconds();
    let window_start = now - now.rem_euclid(60);
    let mut limits = state
        .http_rate_limits
        .lock()
        .map_err(|_| ApiError::internal("rate limiter lock poisoned"))?;
    limits.retain(|_, bucket| bucket.window_start_unix_seconds >= window_start - 60);
    let bucket = limits.entry(key.to_string()).or_insert(RateLimitBucket {
        window_start_unix_seconds: window_start,
        count: 0,
    });
    if bucket.window_start_unix_seconds != window_start {
        bucket.window_start_unix_seconds = window_start;
        bucket.count = 0;
    }
    bucket.count = bucket.count.saturating_add(1);
    if bucket.count > limit {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::RateLimited,
            "HTTP request rate limit exceeded",
        ));
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

fn compute_queue_depth(state: &AppState) -> Result<u64, ApiError> {
    let read_txn = state
        .metadata
        .database()
        .begin_read()
        .map_err(ApiError::redb_transaction)?;
    let table = match read_txn.open_table(JOBS) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
        Err(error) => return Err(ApiError::redb_table(error)),
    };
    let mut count = 0u64;
    for row in table.iter().map_err(ApiError::redb_storage)? {
        let (_, value) = row.map_err(ApiError::redb_storage)?;
        let job: ComputeJobStatus =
            serde_json::from_slice(value.value()).map_err(ApiError::serde)?;
        if matches!(job.status.as_str(), "queued" | "delegated") {
            count += 1;
        }
    }
    Ok(count)
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        warn!(%error, "failed to install Ctrl-C shutdown handler");
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn hierarchical_coordinator_minimizes_cross_domain_bytes() {
        let owners = [
            "rack-a", "rack-a", "rack-b", "rack-b", "rack-b", "rack-b", "rack-c",
        ]
        .map(str::to_string);
        let local_rack = hierarchical_cross_domain_bytes("rack-a", "rack-a", &owners, 60, 10);
        let remote_dense_rack =
            hierarchical_cross_domain_bytes("rack-a", "rack-b", &owners, 60, 10);
        assert_eq!(local_rack, 50);
        assert_eq!(remote_dense_rack, 90);

        let from_other_gateway =
            hierarchical_cross_domain_bytes("rack-d", "rack-b", &owners, 60, 10);
        let sparse_rack = hierarchical_cross_domain_bytes("rack-d", "rack-a", &owners, 60, 10);
        assert_eq!(from_other_gateway, 90);
        assert_eq!(sparse_rack, 110);
    }

    #[test]
    fn erasure_stripe_compression_is_canonical_and_checksum_bound() {
        let compressible = vec![b'a'; 1024 * 1024];
        let logical_cid = Cid::new(CODEC_RAW, &compressible);
        let (encoding, encoded, _) =
            encode_erasure_stripe_payload(compressible.clone(), Vec::new()).unwrap();
        assert_eq!(encoding, ErasureStripeEncoding::Zstd);
        assert!(encoded.len() < compressible.len() / 10);
        assert_eq!(
            decode_erasure_stripe_payload(encoding, encoded, compressible.len(), &logical_cid)
                .unwrap(),
            compressible
        );

        let mut value = 0x6a09e667f3bcc909u64;
        let mut incompressible = vec![0u8; 1024 * 1024];
        for byte in &mut incompressible {
            value ^= value << 13;
            value ^= value >> 7;
            value ^= value << 17;
            *byte = value as u8;
        }
        let (encoding, encoded, _) =
            encode_erasure_stripe_payload(incompressible.clone(), Vec::new()).unwrap();
        assert_eq!(encoding, ErasureStripeEncoding::Raw);
        assert_eq!(encoded, incompressible);
    }

    #[test]
    fn compressed_erasure_shards_decode_into_verified_frames() {
        let logical = (0..3 * 1024 * 1024 + 17)
            .map(|index| ((index / 97) % 251) as u8)
            .collect::<Vec<_>>();
        let cid = Cid::new(CODEC_RAW, &logical);
        let encoded = zstd::bulk::compress(&logical, ERASURE_COMPRESSION_LEVEL).unwrap();
        let shard_size = encoded.len().div_ceil(6);
        let mut shards = encoded
            .chunks(shard_size)
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        while shards.len() < 6 {
            shards.push(Vec::new());
        }
        for shard in &mut shards {
            shard.resize(shard_size, 0);
        }
        let frames =
            decode_zstd_erasure_stripe_frames(shards, encoded.len(), logical.len(), &cid).unwrap();
        assert!(frames.len() > 1);
        assert_eq!(frames.concat(), logical);
    }

    #[test]
    fn rejects_unsafe_job_ids_and_paths() {
        assert!(validate_job_id("job-123_ok").is_ok());
        for invalid in ["", "../job", "/tmp/job", "job/name", "job name"] {
            assert!(validate_job_id(invalid).is_err(), "accepted {invalid:?}");
        }
        let root = FsPath::new("/tmp/root");
        assert_eq!(
            safe_join(root, "/input/data").unwrap(),
            root.join("input/data")
        );
        for invalid in ["", "/", "../data", "a/../b", "a\\b", "a//b"] {
            assert!(safe_join(root, invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_in_extracted_compute_output() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        symlink("/etc/passwd", directory.path().join("leak")).unwrap();
        assert!(directory_size_bytes(directory.path()).is_err());
    }
}
