// SPDX-License-Identifier: Apache-2.0

mod api_error;
mod bucket_api;
mod compute;
mod diagnostics;
mod filesystem_api;
mod http;
mod metrics;
mod namespace_api;
mod network_services;
mod objects;
mod pins;
mod publication;
mod repair;
mod s3_api;

use api_error::ApiError;
use bucket_api::*;
use compute::*;
use filesystem_api::*;
use metrics::*;
use namespace_api::*;
use network_services::*;
use objects::*;
use pins::*;
use publication::*;
use repair::*;
use s3_api::*;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

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
use futures_util::{StreamExt, stream};
use pepper_bucket::BucketObjectCodecHandler;
use pepper_compute::validate_job_spec;
use pepper_config::{LoadedConfig, default_config_path, load_from_path};
use pepper_consensus::{ConsensusConfig, ConsensusDataStore, NamespaceGroupManager};
use pepper_crypto::{NodeIdentity, verify_signature};
use pepper_dag::{BlockResolver as DagBlockResolver, DagCodecRegistry, TraversalLimits};
use pepper_filesystem::{FilesystemInodeCodecHandler, FilesystemRootCodecHandler};
use pepper_merkle::MerkleNodeCodecHandler;
use pepper_metadata::MetadataStore;
use pepper_namespace::{
    NamespaceCheckpointCodecHandler, NamespaceCommitCodecHandler, NamespaceDescriptorCodecHandler,
    NamespaceId, PinAction,
};
use pepper_network::{
    NetworkBlockService, NetworkComputeService, NetworkConfig, NetworkError, NetworkHandle,
    NetworkNamespaceAliasService, NetworkPinService, PeerStatus, proto,
};
use pepper_placement::{PlacementNode, select_replicas};
use pepper_publication::{PublicationLimits, PublicationRepository};
use pepper_storage::{BlockStore, StorageError};
use pepper_types::{
    CODEC_DIR_MANIFEST, CODEC_ERASURE_MANIFEST, CODEC_OBJECT_MANIFEST, CODEC_RAW, Cid, Codec,
    ComputeAttempt, ComputeJobSpec, ComputeJobStatus, ComputeLogsResponse, ComputeOffer,
    ComputeReceipt, DirEntry, DirManifest, DurabilityReceipt, ErasureManifest, ErasureShard,
    ErrorCode, GcReport, InitStatus, NodeStatus, ObjectChunk, ObjectManifest, PinCreateRequest,
    PinRecord, PinStatusResponse, ProviderRecord, PutBlockResponse, SubmitComputeResponse,
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
    sync::{RwLock, Semaphore, oneshot},
    task::AbortHandle,
    time::{self, Duration},
};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, prelude::*};

const JOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("jobs");
static JOB_COUNTER: AtomicU64 = AtomicU64::new(1);
static PIN_COUNTER: AtomicU64 = AtomicU64::new(1);
const STORAGE_SOFT_PRESSURE_PERCENT: u64 = 85;
const STORAGE_HARD_PRESSURE_PERCENT: u64 = 95;
const DEFAULT_MAX_BLOCK_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ERASURE_OBJECT_BYTES: u64 = 256 * 1024 * 1024;
const S3_INTERNAL_KEY_PREFIX: &[u8] = b"\xffs3/";

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
    max_compute_timeout_seconds: Option<u64>,
    erasure_enabled: bool,
    erasure_min_size_bytes: u64,
    erasure_data_shards: u16,
    erasure_parity_shards: u16,
    http_requests_per_minute: Option<u64>,
    http_concurrency: Arc<Semaphore>,
    http_rate_limits: Arc<Mutex<HashMap<String, RateLimitBucket>>>,
    erasure_repair_semaphore: Arc<Semaphore>,
    erasure_repair_bytes_per_second: Option<u64>,
    _identity_lock: Arc<std::fs::File>,
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

#[tokio::main]
async fn main() -> Result<()> {
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
        None => run_agent(loaded).await,
    }
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
    let _block_store = BlockStore::open_with_limit(
        metadata.clone(),
        &loaded.config.storage.locations,
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
        BlockStore::open_with_limit(
            metadata.clone(),
            &loaded.config.storage.locations,
            loaded
                .config
                .limits
                .max_block_bytes
                .unwrap_or(DEFAULT_MAX_BLOCK_BYTES),
        )
        .context("failed to open local block store")?,
    );
    let operation_lock = Arc::new(RwLock::new(()));
    let network_block_service = Arc::new(AgentBlockService {
        block_store: block_store.clone(),
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
            bucket_create_lock: Arc::new(tokio::sync::Mutex::new(())),
            bucket_catalog_lock: Arc::new(tokio::sync::Mutex::new(())),
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
    let storage_summary = block_store
        .storage_summary()
        .context("failed to summarize local storage")?;
    let network = NetworkHandle::start(
        NetworkConfig {
            node_name: loaded.config.node.name.clone(),
            listen_addr: p2p_addr,
            advertise_addr,
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
        max_compute_timeout_seconds: loaded.config.limits.max_compute_timeout_seconds,
        erasure_enabled: loaded.config.erasure.enabled,
        erasure_min_size_bytes: loaded.config.erasure.min_size_bytes,
        erasure_data_shards: loaded.config.erasure.data_shards,
        erasure_parity_shards: loaded.config.erasure.parity_shards,
        http_requests_per_minute: loaded.config.limits.http_requests_per_minute,
        http_concurrency: Arc::new(Semaphore::new(128)),
        http_rate_limits: Arc::new(Mutex::new(HashMap::new())),
        erasure_repair_semaphore: Arc::new(Semaphore::new(
            loaded
                .config
                .limits
                .erasure_repair_max_concurrent_shards
                .unwrap_or(2),
        )),
        erasure_repair_bytes_per_second: loaded.config.limits.erasure_repair_bytes_per_second,
        _identity_lock: identity_lock,
    };

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
    spawn_repair_loop(state.clone());
    spawn_publication_reconciler(state.clone());
    spawn_s3_lifecycle_reconciler(state.clone());

    let shutdown_state = state.clone();
    let app = http::router(state);

    let addr: SocketAddr = loaded
        .config
        .api
        .bind_addr
        .parse()
        .context("api.bind_addr should have been validated as a socket address")?;
    anyhow::ensure!(
        addr.ip().is_loopback(),
        "the built-in HTTP API must bind to loopback; use a TLS-authenticated reverse proxy for remote access"
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
    match tokio::task::block_in_place(|| state.block_store.get(cid)) {
        Ok(block) => Ok(block),
        Err(StorageError::NotFound(_)) | Err(StorageError::HashMismatch(_)) => {
            let Some(resolution) = state
                .network
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
            let repaired = state.block_store.put_replica(cid.codec, &payload)?;
            if repaired.cid != *cid {
                return Err(ApiError::internal("recovered block CID mismatch"));
            }
            let mut records = state
                .read_diagnostics
                .lock()
                .map_err(|_| ApiError::internal("read diagnostic lock poisoned"))?;
            let sequence = records
                .back()
                .map_or(1, |record| record.sequence.saturating_add(1));
            if records.len() == 512 {
                records.pop_front();
            }
            records.push_back(ReadDiagnosticRecord {
                sequence,
                cid: cid.clone(),
                source_node: resolution.source_node_id,
                route: resolution.route,
                verified_bytes: payload.len() as u64,
                timestamp_unix_seconds: unix_seconds(),
            });
            drop(records);
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
    candidates
}

fn validate_replica_ack(
    state: &AppState,
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
    state.network.persist_provider_record(&record)?;
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
    if replication_factor == 0 {
        return Err(ApiError::bad_request(
            "replication factor must be greater than zero",
        ));
    }
    let local_put_started = time::Instant::now();
    let local_put = tokio::task::block_in_place(|| state.block_store.put(codec, &payload));
    metrics::observe_phase(
        &metrics::S3_BLOCK_HASH_STORAGE_PHASES,
        &metrics::S3_BLOCK_HASH_STORAGE_MICROS,
        local_put_started.elapsed(),
    );
    let local_put = local_put?;
    let local_provider = state.network.local_provider_record(&local_put.cid);
    state.network.persist_provider_record(&local_provider)?;
    state
        .network
        .announce_provider_to_peers(&local_provider)
        .await;

    let local_descriptor = state.network.local_descriptor();
    let candidates = placement_candidates(state, state.network.peers().await);

    let selected = select_replicas(&local_put.cid, &candidates, replication_factor);
    // The ingress keeps a verified cache copy, but durability credit follows
    // deterministic placement. Do not over-credit the local cache when the
    // ingress is not one of the selected replicas.
    let local_selected = selected.iter().any(|node| node.is_local);
    let mut replica_nodes = local_selected
        .then(|| local_descriptor.node_id.clone())
        .into_iter()
        .collect::<Vec<_>>();
    let mut providers = local_selected
        .then_some(local_provider)
        .into_iter()
        .collect::<Vec<_>>();

    let payload = Arc::new(payload);
    let writes = selected
        .into_iter()
        .filter(|node| !node.is_local)
        .filter_map(|node| {
            let address = node.addresses.iter().find_map(|address| {
                address.parse::<SocketAddr>().ok().filter(|address| {
                    !address.ip().is_unspecified() && !address.ip().is_multicast()
                })
            })?;
            Some((node, address))
        })
        .map(|(node, address)| {
            let network = state.network.clone();
            let payload = payload.clone();
            async move {
                let result = network
                    .block_put_replica(address, codec, payload.as_ref().clone())
                    .await;
                (node, result)
            }
        });
    let mut replica_writes = stream::iter(writes).buffered(8);
    let replica_transfer_started = time::Instant::now();

    while let Some((node, result)) = replica_writes.next().await {
        match result {
            Ok(ack) => match validate_replica_ack(
                state,
                &node.node_id,
                &local_put.cid,
                codec,
                local_put.size,
                &ack,
            ) {
                Ok(record) => {
                    state.network.announce_provider_to_peers(&record).await;
                    replica_nodes.push(node.node_id.clone());
                    providers.push(record);
                }
                Err(error) => warn!(
                    node_id = %node.node_id,
                    %error.message,
                    "replica acknowledgement validation failed"
                ),
            },
            Err(error) => warn!(%error, node_id = %node.node_id, "replica write failed"),
        }
    }
    metrics::observe_phase(
        &metrics::S3_REPLICA_TRANSFER_PHASES,
        &metrics::S3_REPLICA_TRANSFER_MICROS,
        replica_transfer_started.elapsed(),
    );

    replica_nodes.sort();
    replica_nodes.dedup();
    providers.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    providers.dedup_by(|left, right| left.node_id == right.node_id && left.cid == right.cid);
    let replicas_accepted = replica_nodes.len();
    let status = if replicas_accepted >= replication_factor {
        "durable"
    } else {
        "degraded"
    }
    .to_string();

    Ok(DurabilityReceipt {
        cid: local_put.cid,
        codec: local_put.codec,
        size: local_put.size,
        replicas_accepted,
        replica_nodes,
        status,
        providers,
    })
}

async fn put_erasure_object_bytes(
    state: &AppState,
    bytes: Vec<u8>,
    data_shards: u16,
    parity_shards: u16,
) -> Result<DurabilityReceipt, ApiError> {
    validate_erasure_policy(data_shards, parity_shards)?;
    let data_shards_usize = data_shards as usize;
    let parity_shards_usize = parity_shards as usize;
    let total_shards = data_shards_usize + parity_shards_usize;
    let shard_size = std::cmp::max(1, bytes.len().div_ceil(data_shards_usize));
    let max_block_bytes = state.max_block_bytes.unwrap_or(DEFAULT_MAX_BLOCK_BYTES);
    if shard_size as u64 > max_block_bytes {
        return Err(ApiError::bad_request(format!(
            "erasure shard size {shard_size} exceeds block limit {max_block_bytes}; increase data_shards"
        )));
    }
    let encoded_bytes = shard_size
        .checked_mul(total_shards)
        .ok_or_else(|| ApiError::bad_request("erasure allocation size overflow"))?;
    if encoded_bytes > 512 * 1024 * 1024 {
        return Err(ApiError::bad_request(
            "erasure encoding would exceed the 512 MiB memory safety limit",
        ));
    }
    let mut shards = vec![vec![0u8; shard_size]; total_shards];
    for (index, chunk) in bytes.chunks(shard_size).enumerate() {
        shards[index][..chunk.len()].copy_from_slice(chunk);
    }
    let reed_solomon = ReedSolomon::new(data_shards_usize, parity_shards_usize)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    reed_solomon
        .encode(&mut shards)
        .map_err(|error| ApiError::internal(error.to_string()))?;

    let candidates = placement_candidates(state, state.network.peers().await);
    let mut manifest_shards = Vec::with_capacity(total_shards);
    let mut used_nodes = HashSet::new();
    let mut used_constraint_values = HashSet::new();
    for (index, shard) in shards.into_iter().enumerate() {
        let cid = Cid::new(CODEC_RAW, &shard);
        let (node_id, constraints) = store_erasure_shard(
            state,
            &candidates,
            cid.clone(),
            shard,
            &used_nodes,
            &used_constraint_values,
        )
        .await?;
        used_nodes.insert(node_id);
        used_constraint_values.extend(constraints);
        manifest_shards.push(ErasureShard {
            index: index as u16,
            cid,
            size: shard_size as u64,
        });
    }
    ERASURE_OBJECT_WRITES.fetch_add(1, Ordering::Relaxed);

    let manifest = ErasureManifest::new(
        bytes.len() as u64,
        data_shards,
        parity_shards,
        shard_size as u64,
        manifest_shards,
    );
    manifest.validate().map_err(ApiError::manifest)?;
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(ApiError::serde)?;
    let mut receipt = put_replicated_block(state, CODEC_ERASURE_MANIFEST, manifest_bytes).await?;
    if used_nodes.len() < data_shards as usize {
        receipt.status = "degraded".to_string();
    }
    Ok(receipt)
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

fn capacity_score(node: &PlacementNode) -> u64 {
    node.storage_available_bytes.unwrap_or(u64::MAX / 2)
}

fn choose_capacity_aware_target(
    selected: &[PlacementNode],
    predicate: impl Fn(&PlacementNode) -> bool,
) -> Option<PlacementNode> {
    selected
        .iter()
        .filter(|node| predicate(node))
        .max_by(|left, right| {
            capacity_score(left)
                .cmp(&capacity_score(right))
                .then_with(|| right.node_id.cmp(&left.node_id))
        })
        .cloned()
}

fn select_erasure_target(
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

fn candidate_failure_domain(node_id: &str, candidates: &[PlacementNode]) -> String {
    candidates
        .iter()
        .find(|node| node.node_id == node_id)
        .map(primary_failure_domain_key)
        .unwrap_or_else(|| format!("node:{node_id}"))
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
    excluded_node_ids: &HashSet<String>,
    used_constraint_values: &HashSet<String>,
) -> Result<(String, HashSet<String>), ApiError> {
    let selected = select_erasure_target(
        &cid,
        candidates,
        excluded_node_ids,
        used_constraint_values,
        payload.len() as u64,
    );
    if let Some(node) = selected
        && !node.is_local
        && let Some(address) = node
            .addresses
            .iter()
            .find_map(|address| address.parse().ok())
    {
        match state
            .network
            .block_put_replica(address, CODEC_RAW, payload.clone())
            .await
        {
            Ok(ack) => match validate_replica_ack(
                state,
                &node.node_id,
                &cid,
                CODEC_RAW,
                payload.len() as u64,
                &ack,
            ) {
                Ok(record) => {
                    state.network.announce_provider_to_peers(&record).await;
                    return Ok((node.node_id.clone(), placement_constraint_values(&node)));
                }
                Err(error) => {
                    warn!(%error.message, expected = %cid, "remote erasure shard acknowledgement failed validation; storing locally")
                }
            },
            Err(error) => warn!(%error, "remote erasure shard write failed; storing locally"),
        }
    }

    state.block_store.put(CODEC_RAW, &payload)?;
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
    ))
}

async fn copy_erasure_shard_to_node(
    state: &AppState,
    node: &PlacementNode,
    cid: &Cid,
    payload: Vec<u8>,
) -> Result<(), ApiError> {
    if node.is_local {
        let ack = state.block_store.put_replica(CODEC_RAW, &payload)?;
        if ack.cid != *cid {
            return Err(ApiError::internal(format!(
                "local erasure shard CID mismatch: expected {cid}, got {}",
                ack.cid
            )));
        }
        let provider = state.network.local_provider_record(cid);
        state.network.persist_provider_record(&provider)?;
        state.network.announce_provider_to_peers(&provider).await;
        return Ok(());
    }

    let address = node
        .addresses
        .iter()
        .find_map(|address| address.parse().ok())
        .ok_or_else(|| {
            ApiError::internal(format!("node {} has no routable address", node.node_id))
        })?;
    let payload_len = payload.len() as u64;
    let ack = time::timeout(
        Duration::from_secs(2),
        state.network.block_put_replica(address, CODEC_RAW, payload),
    )
    .await
    .map_err(|_| {
        ApiError::internal(format!("erasure shard copy to {} timed out", node.node_id))
    })??;
    let record = validate_replica_ack(state, &node.node_id, cid, CODEC_RAW, payload_len, &ack)?;
    state.network.announce_provider_to_peers(&record).await;
    Ok(())
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
        total_shards += manifest.shards.len();
        let mut healthy = 0usize;
        for shard in &manifest.shards {
            if has_healthy_provider(&state, &shard.cid).await {
                healthy += 1;
            }
        }
        healthy_shards += healthy;
        if healthy < manifest.data_shards as usize {
            unrecoverable_manifests += 1;
        } else if healthy < manifest.shards.len() {
            repairable_manifests += 1;
        }
    }
    Ok(Json(serde_json::json!({
        "manifests": manifests,
        "logical_bytes": logical_bytes,
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
        get_block_resolved(self.state, cid)
            .await
            .map(|block| block.payload)
            .map_err(|error| error.message)
    }
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
    let data_shards = manifest.data_shards as usize;
    let parity_shards = manifest.parity_shards as usize;
    let total_shards = data_shards + parity_shards;
    let shard_size = manifest.shard_size as usize;
    let mut shards = vec![None::<Vec<u8>>; total_shards];
    let mut available = 0usize;
    for shard in &manifest.shards {
        if available >= data_shards {
            break;
        }
        match get_block_resolved(state, &shard.cid).await {
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
    let reed_solomon = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    reed_solomon
        .reconstruct(&mut shards)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let mut bytes = Vec::with_capacity(manifest.size as usize);
    for shard in shards.iter_mut().take(data_shards) {
        let shard = shard
            .take()
            .ok_or_else(|| ApiError::internal("erasure reconstruction left data shard missing"))?;
        bytes.extend_from_slice(&shard);
    }
    bytes.truncate(manifest.size as usize);
    ERASURE_OBJECT_READS.fetch_add(1, Ordering::Relaxed);
    Ok(bytes)
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
                CODEC_OBJECT_MANIFEST | CODEC_ERASURE_MANIFEST => object_bytes(state, &cid).await?,
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

async fn put_object_stream_receipt(
    state: &AppState,
    body: Body,
) -> Result<DurabilityReceipt, ApiError> {
    const CHUNK_SIZE: usize = 4 * 1024 * 1024;
    let mut body_stream = body.into_data_stream();
    let mut pending = Vec::with_capacity(CHUNK_SIZE);
    let mut chunks = Vec::new();
    let mut total = 0u64;
    let mut all_chunks_durable = true;
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
            let take = (CHUNK_SIZE - pending.len()).min(remaining.len());
            pending.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            if pending.len() == CHUNK_SIZE {
                let payload = std::mem::replace(&mut pending, Vec::with_capacity(CHUNK_SIZE));
                let receipt = put_replicated_block(state, CODEC_RAW, payload).await?;
                all_chunks_durable &= receipt.status == "durable";
                chunks.push(ObjectChunk {
                    offset: chunks.len() as u64 * CHUNK_SIZE as u64,
                    size: CHUNK_SIZE as u64,
                    cid: receipt.cid,
                });
            }
        }
    }
    if !pending.is_empty() {
        let size = pending.len() as u64;
        let receipt = put_replicated_block(state, CODEC_RAW, pending).await?;
        all_chunks_durable &= receipt.status == "durable";
        chunks.push(ObjectChunk {
            offset: total - size,
            size,
            cid: receipt.cid,
        });
    }
    let manifest = ObjectManifest::new(total, CHUNK_SIZE as u64, chunks);
    manifest.validate().map_err(ApiError::manifest)?;
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(ApiError::serde)?;
    let mut receipt = put_replicated_block(state, CODEC_OBJECT_MANIFEST, manifest_bytes).await?;
    if !all_chunks_durable {
        receipt.status = "degraded".to_string();
    }
    Ok(receipt)
}

async fn put_object_bytes_internal(state: &AppState, bytes: Vec<u8>) -> Result<Cid, ApiError> {
    Ok(put_object_bytes_receipt(state, bytes).await?.cid)
}

async fn put_object_bytes_receipt(
    state: &AppState,
    bytes: Vec<u8>,
) -> Result<DurabilityReceipt, ApiError> {
    enforce_size_limit(state.max_object_bytes, bytes.len() as u64, "object")?;
    let chunk_size = 4 * 1024 * 1024usize;
    let mut chunks = Vec::new();
    let mut all_chunks_durable = true;
    for (index, chunk) in bytes.chunks(chunk_size).enumerate() {
        let receipt = put_replicated_block(state, CODEC_RAW, chunk.to_vec()).await?;
        all_chunks_durable &= receipt.status == "durable";
        chunks.push(ObjectChunk {
            offset: (index * chunk_size) as u64,
            size: chunk.len() as u64,
            cid: receipt.cid,
        });
    }
    let manifest = ObjectManifest::new(bytes.len() as u64, chunk_size as u64, chunks);
    manifest.validate().map_err(ApiError::manifest)?;
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(ApiError::serde)?;
    let mut receipt = put_replicated_block(state, CODEC_OBJECT_MANIFEST, manifest_bytes).await?;
    if !all_chunks_durable {
        receipt.status = "degraded".to_string();
    }
    Ok(receipt)
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
    let ready = statuses
        .iter()
        .all(|status| status.running && status.log_lag == 0 && status.leader_raft_id.is_some());
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
    let _permit = state
        .http_concurrency
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Unavailable,
                "HTTP concurrency limit exceeded",
            )
        })?;
    let s3_request = state.s3.is_some()
        && !request.uri().path().starts_with("/v1/")
        && !matches!(request.uri().path(), "/healthz" | "/readyz" | "/metrics");
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
    Ok(next.run(request).await)
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
