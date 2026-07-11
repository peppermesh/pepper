// SPDX-License-Identifier: Apache-2.0

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
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use futures_util::{StreamExt, stream};
use pepper_compute::validate_job_spec;
use pepper_config::{LoadedConfig, default_config_path, load_from_path};
use pepper_crypto::{NodeIdentity, verify_signature};
use pepper_metadata::MetadataStore;
use pepper_network::{
    NetworkBlockService, NetworkComputeService, NetworkConfig, NetworkError, NetworkHandle,
    PeerStatus, proto,
};
use pepper_placement::{PlacementNode, select_replicas};
use pepper_storage::{BlockStore, StorageError};
use pepper_types::{
    CODEC_DIR_MANIFEST, CODEC_ERASURE_MANIFEST, CODEC_OBJECT_MANIFEST, CODEC_RAW, Cid, Codec,
    ComputeAttempt, ComputeJobSpec, ComputeJobStatus, ComputeLogsResponse, ComputeOffer,
    ComputeReceipt, DirEntry, DirManifest, DurabilityReceipt, ErasureManifest, ErasureShard,
    GcReport, InitStatus, NodeStatus, ObjectChunk, ObjectManifest, PinCreateRequest, PinRecord,
    PinStatusResponse, ProviderRecord, PutBlockResponse, SubmitComputeResponse,
};
use redb::{ReadableTable, TableDefinition};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
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

const PINS: TableDefinition<&str, &[u8]> = TableDefinition::new("pins");
const PINS_BY_ROOT: TableDefinition<&str, &str> = TableDefinition::new("pins_by_root");
const JOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("jobs");
static JOB_COUNTER: AtomicU64 = AtomicU64::new(1);
static PIN_COUNTER: AtomicU64 = AtomicU64::new(1);
static COMPUTE_SCHEDULED_LOCAL: AtomicU64 = AtomicU64::new(0);
static COMPUTE_SCHEDULED_REMOTE: AtomicU64 = AtomicU64::new(0);
static COMPUTE_SCHEDULE_RETRIES: AtomicU64 = AtomicU64::new(0);
static FIRECRACKER_VM_STARTS: AtomicU64 = AtomicU64::new(0);
static FIRECRACKER_VM_SUCCESSES: AtomicU64 = AtomicU64::new(0);
static FIRECRACKER_VM_FAILURES: AtomicU64 = AtomicU64::new(0);
static FIRECRACKER_ROOTFS_VALIDATION_FAILURES: AtomicU64 = AtomicU64::new(0);
static FIRECRACKER_VSOCK_CANCEL_DELIVERED: AtomicU64 = AtomicU64::new(0);
static FIRECRACKER_VSOCK_CANCEL_ACKS: AtomicU64 = AtomicU64::new(0);
static FIRECRACKER_VSOCK_CANCEL_FALLBACKS: AtomicU64 = AtomicU64::new(0);
static FIRECRACKER_JAILER_SETUP_FAILURES: AtomicU64 = AtomicU64::new(0);
static FIRECRACKER_OUTPUT_EXTRACTION_FAILURES: AtomicU64 = AtomicU64::new(0);
static FIRECRACKER_HEARTBEATS: AtomicU64 = AtomicU64::new(0);
static FIRECRACKER_HEARTBEAT_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static ERASURE_OBJECT_WRITES: AtomicU64 = AtomicU64::new(0);
static ERASURE_OBJECT_READS: AtomicU64 = AtomicU64::new(0);
static ERASURE_SHARD_REPAIRS: AtomicU64 = AtomicU64::new(0);
static ERASURE_SHARD_REBALANCES: AtomicU64 = AtomicU64::new(0);
static ERASURE_RECONSTRUCTION_FAILURES: AtomicU64 = AtomicU64::new(0);
const STORAGE_SOFT_PRESSURE_PERCENT: u64 = 85;
const STORAGE_HARD_PRESSURE_PERCENT: u64 = 95;
const DEFAULT_MAX_BLOCK_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ERASURE_OBJECT_BYTES: u64 = 256 * 1024 * 1024;

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
    /// Copy the local redb metadata database to a backup file.
    Backup {
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
}

#[derive(Clone)]
struct AppState {
    status: Arc<NodeStatus>,
    metadata: Arc<MetadataStore>,
    block_store: Arc<BlockStore>,
    network: NetworkHandle,
    replication_factor: usize,
    repair_interval: Duration,
    repair_semaphore: Arc<Semaphore>,
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
}

#[derive(Debug, Clone)]
struct RateLimitBucket {
    window_start_unix_seconds: i64,
    count: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ObjectPutQuery {
    erasure_data_shards: Option<u16>,
    erasure_parity_shards: Option<u16>,
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

fn backup_metadata(loaded: LoadedConfig, output: PathBuf) -> Result<()> {
    let metadata_path = loaded.config.metadata_path();
    anyhow::ensure!(
        metadata_path.is_file(),
        "metadata database does not exist at {}",
        metadata_path.display()
    );
    let metadata_check = MetadataStore::open_or_create(&metadata_path).with_context(|| {
        format!(
            "metadata database {} must be available exclusively; stop the agent before backup",
            metadata_path.display()
        )
    })?;
    drop(metadata_check);
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create backup directory {}", parent.display()))?;
    }
    let bytes = std::fs::copy(&metadata_path, &output).with_context(|| {
        format!(
            "failed to copy metadata database from {} to {}",
            metadata_path.display(),
            output.display()
        )
    })?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "source": metadata_path,
            "output": output,
            "bytes": bytes,
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
    let state = AppState {
        status: Arc::new(status),
        metadata: metadata.clone(),
        block_store,
        network,
        replication_factor: loaded.config.replication.default_factor as usize,
        repair_interval: Duration::from_secs(loaded.config.replication.repair_interval_seconds),
        repair_semaphore: Arc::new(Semaphore::new(1)),
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
    };

    state
        .network
        .set_compute_service(Arc::new(AgentComputeService {
            state: state.clone(),
        }))
        .await;

    recover_compute_jobs(&state).map_err(|error| anyhow::anyhow!(error.message))?;
    spawn_repair_loop(state.clone());

    let shutdown_state = state.clone();
    let app = Router::new()
        .route("/v1/node/status", get(node_status))
        .route("/v1/node/peers", get(node_peers))
        .route("/v1/blocks", post(put_block))
        .route("/v1/blocks/{cid}", get(get_block).head(has_block))
        .route("/v1/objects", post(put_object))
        .route("/v1/objects/{cid}", get(get_object))
        .route("/v1/dirs", post(put_dir))
        .route("/v1/dirs/{cid}", get(get_dir))
        .route("/v1/pins", post(create_pin))
        .route("/v1/pins/{cid}", get(pin_status).delete(delete_pin))
        .route("/v1/admin/gc", post(run_gc))
        .route("/v1/admin/repair", post(run_repair))
        .route("/v1/admin/status", get(admin_status))
        .route("/v1/admin/storage", get(admin_storage))
        .route("/v1/admin/erasure", get(admin_erasure))
        .route("/v1/admin/corruption-scan", post(admin_corruption_scan))
        .route("/v1/admin/quarantine/purge", post(admin_quarantine_purge))
        .route("/v1/compute/jobs", post(submit_compute_job))
        .route("/v1/compute/jobs/{job_id}", get(compute_job_status))
        .route("/v1/compute/jobs/{job_id}/logs", get(compute_job_logs))
        .route("/v1/compute/jobs/{job_id}/cancel", post(cancel_compute_job))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_http_auth_and_rate_limit,
        ))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

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
    body: Body,
) -> Result<Json<DurabilityReceipt>, ApiError> {
    let _guard = state.operation_lock.read().await;
    let body = read_body_limited(body, state.max_block_bytes, "block").await?;
    let receipt = put_replicated_block(&state, CODEC_RAW, body).await?;
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

async fn put_object(
    State(state): State<AppState>,
    Query(query): Query<ObjectPutQuery>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<DurabilityReceipt>, ApiError> {
    let _guard = state.operation_lock.read().await;
    let content_length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if let Some(length) = content_length {
        enforce_size_limit(state.max_object_bytes, length, "object")?;
    }
    let use_erasure = query.erasure_data_shards.is_some()
        || query.erasure_parity_shards.is_some()
        || (state.erasure_enabled
            && content_length.is_some_and(|length| length >= state.erasure_min_size_bytes));
    let receipt = if use_erasure {
        let erasure_limit = state
            .max_object_bytes
            .unwrap_or(DEFAULT_MAX_OBJECT_BYTES)
            .min(MAX_ERASURE_OBJECT_BYTES);
        if let Some(length) = content_length {
            enforce_size_limit(Some(erasure_limit), length, "erasure object")?;
        }
        let bytes = read_body_limited(body, Some(erasure_limit), "erasure object").await?;
        put_erasure_object_bytes(
            &state,
            bytes,
            query
                .erasure_data_shards
                .unwrap_or(state.erasure_data_shards),
            query
                .erasure_parity_shards
                .unwrap_or(state.erasure_parity_shards),
        )
        .await?
    } else {
        put_object_stream_receipt(&state, body).await?
    };
    Ok(Json(receipt))
}

async fn get_object(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> Result<Response, ApiError> {
    let guard = Arc::new(state.operation_lock.clone().read_owned().await);
    let cid = BlockStore::parse_cid(&cid)?;
    if cid.codec != CODEC_OBJECT_MANIFEST && cid.codec != CODEC_ERASURE_MANIFEST {
        return Err(ApiError::bad_request("CID is not an object manifest"));
    }
    let body = if cid.codec == CODEC_ERASURE_MANIFEST {
        let bytes = object_bytes(&state, &cid).await?;
        Body::from(bytes)
    } else {
        let manifest_block = get_block_resolved(&state, &cid).await?;
        let manifest: ObjectManifest =
            serde_json::from_slice(&manifest_block.payload).map_err(ApiError::serde)?;
        validate_object_resource_limits(&state, &manifest)?;
        if manifest.chunks.len() > 1_000_000 {
            return Err(ApiError::bad_request(
                "object manifest contains too many chunks",
            ));
        }
        let chunks = manifest.chunks;
        let body_stream = stream::iter(chunks.into_iter().map(move |chunk| {
            let state = state.clone();
            let guard = guard.clone();
            async move {
                let _guard = guard;
                let block = get_block_resolved(&state, &chunk.cid)
                    .await
                    .map_err(|error| std::io::Error::other(error.message))?;
                if block.payload.len() as u64 != chunk.size {
                    return Err(std::io::Error::other("object chunk size mismatch"));
                }
                Ok::<Bytes, std::io::Error>(Bytes::from(block.payload))
            }
        }))
        .buffered(16);
        Body::from_stream(body_stream)
    };
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response())
}

async fn put_dir(
    State(state): State<AppState>,
    body: Body,
) -> Result<Json<DurabilityReceipt>, ApiError> {
    let _guard = state.operation_lock.read().await;
    let body = read_body_limited(body, state.max_block_bytes, "directory manifest").await?;
    let manifest: DirManifest = serde_json::from_slice(&body).map_err(ApiError::serde)?;
    manifest.validate().map_err(ApiError::manifest)?;
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(ApiError::serde)?;
    let mut receipt = put_replicated_block(&state, CODEC_DIR_MANIFEST, manifest_bytes).await?;
    let mut children_durable = true;
    for root in manifest
        .entries
        .iter()
        .filter_map(|entry| entry.cid.clone())
    {
        for cid in traverse_reachable(&state, root).await? {
            let providers = state.network.find_providers(&cid).await?;
            if healthy_provider_node_ids(&state, &cid, providers)
                .await
                .len()
                < state.replication_factor
            {
                children_durable = false;
                break;
            }
        }
        if !children_durable {
            break;
        }
    }
    if !children_durable {
        receipt.status = "degraded".to_string();
    }
    Ok(Json(receipt))
}

async fn get_dir(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> Result<Json<DirManifest>, ApiError> {
    let _guard = state.operation_lock.read().await;
    let cid = BlockStore::parse_cid(&cid)?;
    if cid.codec != CODEC_DIR_MANIFEST {
        return Err(ApiError::bad_request("CID is not a directory manifest"));
    }
    let manifest_block = get_block_resolved(&state, &cid).await?;
    let manifest: DirManifest =
        serde_json::from_slice(&manifest_block.payload).map_err(ApiError::serde)?;
    manifest.validate().map_err(ApiError::manifest)?;
    Ok(Json(manifest))
}

fn validate_object_resource_limits(
    state: &AppState,
    manifest: &ObjectManifest,
) -> Result<(), ApiError> {
    manifest.validate().map_err(ApiError::manifest)?;
    enforce_size_limit(state.max_object_bytes, manifest.size, "object manifest")?;
    let max_block = state.max_block_bytes.unwrap_or(DEFAULT_MAX_BLOCK_BYTES);
    if manifest.chunk_size > max_block || manifest.chunks.iter().any(|chunk| chunk.size > max_block)
    {
        return Err(ApiError::bad_request(
            "object manifest chunk size exceeds the local block limit",
        ));
    }
    if manifest.chunks.len() > 1_000_000 {
        return Err(ApiError::bad_request(
            "object manifest contains too many chunks",
        ));
    }
    Ok(())
}

fn validate_erasure_resource_limits(
    state: &AppState,
    manifest: &ErasureManifest,
) -> Result<(), ApiError> {
    manifest.validate().map_err(ApiError::manifest)?;
    let object_limit = state
        .max_object_bytes
        .unwrap_or(DEFAULT_MAX_OBJECT_BYTES)
        .min(MAX_ERASURE_OBJECT_BYTES);
    enforce_size_limit(Some(object_limit), manifest.size, "erasure object manifest")?;
    let max_block = state.max_block_bytes.unwrap_or(DEFAULT_MAX_BLOCK_BYTES);
    if manifest.shard_size > max_block {
        return Err(ApiError::bad_request(
            "erasure manifest shard size exceeds the local block limit",
        ));
    }
    let total = u64::from(manifest.data_shards) + u64::from(manifest.parity_shards);
    let encoded = manifest
        .shard_size
        .checked_mul(total)
        .ok_or_else(|| ApiError::bad_request("erasure working-set size overflow"))?;
    if encoded > 512 * 1024 * 1024 {
        return Err(ApiError::bad_request(
            "erasure reconstruction exceeds the 512 MiB working-set limit",
        ));
    }
    Ok(())
}

async fn fetch_object_chunks_parallel(
    state: AppState,
    chunks: Vec<ObjectChunk>,
) -> Result<Vec<Vec<u8>>, ApiError> {
    if chunks.len() > 1_000_000 {
        return Err(ApiError::bad_request(
            "object manifest contains too many chunks",
        ));
    }
    let mut fetches = stream::iter(chunks.into_iter().map(|chunk| {
        let state = state.clone();
        async move {
            let block = get_block_resolved(&state, &chunk.cid).await?;
            if block.payload.len() as u64 != chunk.size {
                return Err(ApiError::bad_request("object chunk size mismatch"));
            }
            Ok::<_, ApiError>(block.payload)
        }
    }))
    .buffered(16);
    let mut results = Vec::new();
    while let Some(result) = fetches.next().await {
        results.push(result?);
    }
    Ok(results)
}

async fn get_block_resolved(state: &AppState, cid: &Cid) -> Result<pepper_types::Block, ApiError> {
    match tokio::task::block_in_place(|| state.block_store.get(cid)) {
        Ok(block) => Ok(block),
        Err(StorageError::NotFound(_)) | Err(StorageError::HashMismatch(_)) => {
            let Some(payload) = state.network.get_block_from_any_peer(cid).await? else {
                return Err(ApiError::from(StorageError::NotFound(cid.clone())));
            };
            if !cid.verify(&payload) {
                return Err(ApiError::network(NetworkError::BlockService(
                    "remote block hash mismatch".to_string(),
                )));
            }
            let repaired = state.block_store.put_replica(cid.codec, &payload)?;
            if repaired.cid != *cid {
                return Err(ApiError::internal("recovered block CID mismatch"));
            }
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
    let local_put = tokio::task::block_in_place(|| state.block_store.put(codec, &payload))?;
    let local_provider = state.network.local_provider_record(&local_put.cid);
    state.network.persist_provider_record(&local_provider)?;
    state
        .network
        .announce_provider_to_peers(&local_provider)
        .await;

    let local_descriptor = state.network.local_descriptor();
    let candidates = placement_candidates(state, state.network.peers().await);

    let selected = select_replicas(&local_put.cid, &candidates, replication_factor);
    let mut replica_nodes = vec![local_descriptor.node_id.clone()];
    let mut providers = vec![local_provider];

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

fn spawn_repair_loop(state: AppState) {
    tokio::spawn(async move {
        let mut interval = time::interval(state.repair_interval);
        loop {
            interval.tick().await;
            if let Err(error) = run_repair_once(&state).await {
                warn!(?error, "repair loop iteration failed");
            }
        }
    });
}

async fn healthy_provider_node_ids(
    state: &AppState,
    cid: &Cid,
    providers: Vec<ProviderRecord>,
) -> Vec<String> {
    let local_node_id = &state.status.node_id;
    let mut healthy = Vec::new();
    for provider in providers {
        if &provider.node_id == local_node_id {
            if state.block_store.has(cid).unwrap_or(false) {
                healthy.push(provider.node_id);
            }
            continue;
        }
        let mut provider_healthy = false;
        for address in provider.addresses {
            let Ok(peer) = address.parse::<SocketAddr>() else {
                continue;
            };
            if matches!(
                time::timeout(
                    Duration::from_millis(500),
                    state.network.block_has(peer, cid)
                )
                .await,
                Ok(Ok(true))
            ) {
                provider_healthy = true;
                break;
            }
        }
        if provider_healthy {
            healthy.push(provider.node_id);
        }
    }
    healthy.sort();
    healthy.dedup();
    healthy
}

async fn run_repair_once(state: &AppState) -> Result<(), ApiError> {
    let _repair_permit = state
        .repair_semaphore
        .acquire()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let _ = state.network.cleanup_expired_provider_records()?;

    for peer in state.network.peers().await {
        let mut healthy = false;
        for address in peer.addresses {
            let Ok(address) = address.parse() else {
                continue;
            };
            match time::timeout(Duration::from_millis(500), state.network.node_info(address)).await
            {
                Ok(Ok(_)) => {
                    healthy = true;
                    break;
                }
                Ok(Err(error)) => {
                    warn!(%error, node_id = %peer.node_id, %address, "peer liveness probe failed");
                }
                Err(_) => {
                    warn!(node_id = %peer.node_id, %address, "peer liveness probe timed out");
                }
            }
        }
        if !healthy {
            state.network.remove_peer(&peer.node_id).await;
        }
    }

    let candidates = placement_candidates(state, state.network.peers().await);
    let mut pinned_replication = HashMap::<Cid, usize>::new();
    for pin in active_pins(state)? {
        for cid in traverse_reachable(state, pin.root_cid).await? {
            pinned_replication
                .entry(cid)
                .and_modify(|factor| *factor = (*factor).max(pin.replication_factor as usize))
                .or_insert(pin.replication_factor as usize);
        }
    }

    for stat in state.block_store.list_blocks()? {
        let locally_responsible = select_replicas(&stat.cid, &candidates, state.replication_factor)
            .iter()
            .any(|node| node.is_local);
        let desired_replication =
            pinned_replication
                .get(&stat.cid)
                .copied()
                .unwrap_or(if locally_responsible {
                    state.replication_factor
                } else if stat.codec == CODEC_ERASURE_MANIFEST {
                    // A retained EC control manifest coordinates shard repair and rebalance.
                    1
                } else {
                    0
                });
        if desired_replication == 0 {
            continue;
        }
        let local_record_fresh = state
            .network
            .local_provider_records(&stat.cid)?
            .into_iter()
            .any(|record| {
                record.node_id == state.status.node_id
                    && record.expires_at_unix_seconds > unix_seconds() + 12 * 60 * 60
            });
        if !local_record_fresh {
            let local_provider = state.network.local_provider_record(&stat.cid);
            state.network.persist_provider_record(&local_provider)?;
            state
                .network
                .announce_provider_to_peers(&local_provider)
                .await;
        }

        if stat.codec == CODEC_ERASURE_MANIFEST {
            match state.block_store.get(&stat.cid) {
                Ok(block) => match serde_json::from_slice::<ErasureManifest>(&block.payload) {
                    Ok(manifest) => {
                        if let Err(error) =
                            repair_erasure_manifest(state, &candidates, &manifest).await
                        {
                            warn!(?error, cid = %stat.cid, "erasure repair failed");
                        }
                    }
                    Err(error) => {
                        warn!(%error, cid = %stat.cid, "invalid erasure manifest during repair")
                    }
                },
                Err(error) => {
                    warn!(%error, cid = %stat.cid, "could not read erasure manifest during repair")
                }
            }
        }

        let providers = match time::timeout(
            Duration::from_secs(1),
            state.network.find_providers(&stat.cid),
        )
        .await
        {
            Ok(Ok(providers)) => providers,
            Ok(Err(error)) => {
                warn!(%error, cid = %stat.cid, "provider lookup failed during repair");
                state.network.local_provider_records(&stat.cid)?
            }
            Err(_) => {
                warn!(cid = %stat.cid, "provider lookup timed out during repair");
                state.network.local_provider_records(&stat.cid)?
            }
        };
        let mut healthy_provider_node_ids =
            healthy_provider_node_ids(state, &stat.cid, providers).await;
        if healthy_provider_node_ids.len() >= desired_replication {
            continue;
        }

        let block = state.block_store.get(&stat.cid)?;
        let selected = select_replicas(&stat.cid, &candidates, candidates.len());
        for node in selected {
            if node.is_local || healthy_provider_node_ids.contains(&node.node_id) {
                continue;
            }
            let Some(address) = node
                .addresses
                .iter()
                .find_map(|address| address.parse().ok())
            else {
                continue;
            };
            match time::timeout(
                Duration::from_secs(1),
                state
                    .network
                    .block_put_replica(address, stat.codec, block.payload.clone()),
            )
            .await
            {
                Ok(Ok(ack)) => match validate_replica_ack(
                    state,
                    &node.node_id,
                    &stat.cid,
                    stat.codec,
                    block.size,
                    &ack,
                ) {
                    Ok(record) => {
                        healthy_provider_node_ids.push(node.node_id.clone());
                        state.network.announce_provider_to_peers(&record).await;
                    }
                    Err(error) => {
                        warn!(%error.message, node_id = %node.node_id, "repair acknowledgement validation failed")
                    }
                },
                Ok(Err(error)) => {
                    warn!(%error, node_id = %node.node_id, "repair replica write failed")
                }
                Err(_) => warn!(node_id = %node.node_id, "repair replica write timed out"),
            }
            healthy_provider_node_ids.sort();
            healthy_provider_node_ids.dedup();
            if healthy_provider_node_ids.len() >= desired_replication {
                break;
            }
        }
    }
    Ok(())
}

async fn repair_erasure_manifest(
    state: &AppState,
    candidates: &[PlacementNode],
    manifest: &ErasureManifest,
) -> Result<(), ApiError> {
    validate_erasure_resource_limits(state, manifest)?;
    let mut missing = Vec::new();
    let mut healthy_by_index = HashMap::new();
    for shard in &manifest.shards {
        let healthy = healthy_providers_for_cid(state, &shard.cid).await;
        if healthy.is_empty() {
            missing.push(shard.index);
        }
        healthy_by_index.insert(shard.index, healthy);
    }

    if !missing.is_empty() {
        let mut reconstructed = reconstruct_erasure_shards(state, manifest).await?;
        for index in missing {
            let shard_payload = reconstructed
                .get_mut(index as usize)
                .and_then(Option::take)
                .ok_or_else(|| ApiError::internal("erasure repair missing reconstructed shard"))?;
            let shard_cid = manifest
                .shards
                .iter()
                .find(|shard| shard.index == index)
                .map(|shard| shard.cid.clone())
                .ok_or_else(|| ApiError::internal("erasure repair missing shard metadata"))?;
            let _permit = state
                .erasure_repair_semaphore
                .acquire()
                .await
                .map_err(|error| ApiError::internal(error.to_string()))?;
            throttle_erasure_repair(state, shard_payload.len()).await;
            store_erasure_shard(
                state,
                candidates,
                shard_cid,
                shard_payload,
                &HashSet::new(),
                &HashSet::new(),
            )
            .await?;
            ERASURE_SHARD_REPAIRS.fetch_add(1, Ordering::Relaxed);
        }
        healthy_by_index.clear();
        for shard in &manifest.shards {
            healthy_by_index.insert(
                shard.index,
                healthy_providers_for_cid(state, &shard.cid).await,
            );
        }
    }

    rebalance_erasure_manifest(state, candidates, manifest, &healthy_by_index).await
}

async fn rebalance_erasure_manifest(
    state: &AppState,
    candidates: &[PlacementNode],
    manifest: &ErasureManifest,
    healthy_by_index: &HashMap<u16, Vec<ProviderRecord>>,
) -> Result<(), ApiError> {
    let mut used_nodes = HashSet::new();
    let mut used_constraint_values = HashSet::new();
    let mut shards = manifest.shards.clone();
    shards.sort_by_key(|shard| shard.index);

    for shard in shards {
        let Some(target) = select_erasure_target(
            &shard.cid,
            candidates,
            &used_nodes,
            &used_constraint_values,
            shard.size,
        ) else {
            continue;
        };
        used_nodes.insert(target.node_id.clone());
        used_constraint_values.extend(placement_constraint_values(&target));

        let healthy = healthy_by_index
            .get(&shard.index)
            .cloned()
            .unwrap_or_default();
        if healthy
            .iter()
            .any(|provider| provider.node_id == target.node_id)
        {
            continue;
        }
        if healthy.is_empty() {
            continue;
        }

        let payload = match get_block_resolved(state, &shard.cid).await {
            Ok(block) if block.payload.len() == shard.size as usize => block.payload,
            Ok(block) => {
                warn!(
                    cid = %shard.cid,
                    actual = block.payload.len(),
                    expected = shard.size,
                    "skipping erasure shard rebalance with unexpected shard size"
                );
                continue;
            }
            Err(error) => {
                warn!(?error, cid = %shard.cid, "skipping erasure shard rebalance; shard unavailable");
                continue;
            }
        };
        let _permit = state
            .erasure_repair_semaphore
            .acquire()
            .await
            .map_err(|error| ApiError::internal(error.to_string()))?;
        throttle_erasure_repair(state, payload.len()).await;
        match copy_erasure_shard_to_node(state, &target, &shard.cid, payload).await {
            Ok(()) => {
                ERASURE_SHARD_REBALANCES.fetch_add(1, Ordering::Relaxed);
                info!(
                    cid = %shard.cid,
                    shard_index = shard.index,
                    target_node = %target.node_id,
                    target_failure_domain = %candidate_failure_domain(&target.node_id, candidates),
                    "rebalanced erasure shard to preferred placement target"
                );
            }
            Err(error) => warn!(
                ?error,
                cid = %shard.cid,
                shard_index = shard.index,
                target_node = %target.node_id,
                "erasure shard rebalance copy failed"
            ),
        }
    }
    Ok(())
}

async fn throttle_erasure_repair(state: &AppState, bytes: usize) {
    if let Some(bytes_per_second) = state.erasure_repair_bytes_per_second {
        let millis = ((bytes as u128) * 1000).div_ceil(bytes_per_second as u128) as u64;
        if millis > 0 {
            time::sleep(Duration::from_millis(millis)).await;
        }
    }
}

async fn healthy_providers_for_cid(state: &AppState, cid: &Cid) -> Vec<ProviderRecord> {
    let providers =
        match time::timeout(Duration::from_secs(1), state.network.find_providers(cid)).await {
            Ok(Ok(providers)) => providers,
            Ok(Err(error)) => {
                warn!(%error, %cid, "erasure shard provider lookup failed");
                state
                    .network
                    .local_provider_records(cid)
                    .unwrap_or_default()
            }
            Err(_) => {
                warn!(%cid, "erasure shard provider lookup timed out");
                state
                    .network
                    .local_provider_records(cid)
                    .unwrap_or_default()
            }
        };
    let mut healthy = Vec::new();
    let mut seen = HashSet::new();
    if state.block_store.get(cid).is_ok() {
        let local = state.network.local_provider_record(cid);
        seen.insert(local.node_id.clone());
        healthy.push(local);
    }
    for provider in providers {
        if !seen.insert(provider.node_id.clone()) {
            continue;
        }
        if provider.node_id == state.status.node_id {
            if state.block_store.get(cid).is_ok() {
                healthy.push(provider);
            }
            continue;
        }
        let mut provider_healthy = false;
        for address in provider
            .addresses
            .iter()
            .filter_map(|address| address.parse().ok())
        {
            if matches!(
                time::timeout(
                    Duration::from_millis(500),
                    state.network.block_has(address, cid)
                )
                .await,
                Ok(Ok(true))
            ) {
                provider_healthy = true;
                break;
            }
        }
        if provider_healthy {
            healthy.push(provider);
        }
    }
    healthy
}

async fn has_healthy_provider(state: &AppState, cid: &Cid) -> bool {
    !healthy_providers_for_cid(state, cid).await.is_empty()
}

async fn reconstruct_erasure_shards(
    state: &AppState,
    manifest: &ErasureManifest,
) -> Result<Vec<Option<Vec<u8>>>, ApiError> {
    let data_shards = manifest.data_shards as usize;
    let parity_shards = manifest.parity_shards as usize;
    let total_shards = data_shards + parity_shards;
    let shard_size = manifest.shard_size as usize;
    let mut shards = vec![None::<Vec<u8>>; total_shards];
    let mut available = 0usize;
    for shard in &manifest.shards {
        match get_block_resolved(state, &shard.cid).await {
            Ok(block) if block.payload.len() == shard_size => {
                let slot = &mut shards[shard.index as usize];
                if slot.is_none() {
                    *slot = Some(block.payload);
                    available += 1;
                }
            }
            Ok(_) => warn!(cid = %shard.cid, "erasure repair shard size mismatch"),
            Err(error) => warn!(?error, cid = %shard.cid, "erasure repair shard unavailable"),
        }
    }
    if available < data_shards {
        ERASURE_RECONSTRUCTION_FAILURES.fetch_add(1, Ordering::Relaxed);
        return Err(ApiError::internal(
            "not enough erasure shards to repair object",
        ));
    }
    ReedSolomon::new(data_shards, parity_shards)
        .map_err(|error| ApiError::internal(error.to_string()))?
        .reconstruct(&mut shards)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok(shards)
}

async fn create_pin(
    State(state): State<AppState>,
    Json(request): Json<PinCreateRequest>,
) -> Result<Json<PinStatusResponse>, ApiError> {
    let _guard = state.operation_lock.read().await;
    if request.ttl_seconds.is_some_and(|ttl| ttl <= 0) {
        return Err(ApiError::bad_request(
            "pin ttl_seconds must be greater than zero",
        ));
    }
    let replication_factor = request
        .replication_factor
        .unwrap_or(state.replication_factor as u16);
    if replication_factor == 0 {
        return Err(ApiError::bad_request(
            "pin replication factor must be greater than zero",
        ));
    }
    let reachable = traverse_reachable(&state, request.root_cid.clone()).await?;
    for cid in &reachable {
        let block = get_block_resolved(&state, cid).await?;
        let receipt = put_replicated_block_with_factor(
            &state,
            cid.codec,
            block.payload,
            replication_factor as usize,
        )
        .await?;
        if receipt.replicas_accepted < replication_factor as usize {
            return Err(ApiError::internal(format!(
                "pin durability not met for {cid}: accepted {}, requested {replication_factor}",
                receipt.replicas_accepted
            )));
        }
    }
    let now = unix_seconds();
    let mut pin = PinRecord {
        pin_id: format!(
            "pin-{now}-{}-{}",
            std::process::id(),
            PIN_COUNTER.fetch_add(1, Ordering::Relaxed)
        ),
        root_cid: request.root_cid.clone(),
        owner: "local".to_string(),
        replication_factor,
        created_at_unix_seconds: now,
        expires_at_unix_seconds: request.ttl_seconds.map(|ttl| now.saturating_add(ttl)),
        status: "active".to_string(),
        signature_hex: String::new(),
    };
    sign_pin(&state, &mut pin)?;
    persist_pin(&state, &pin)?;
    Ok(Json(PinStatusResponse {
        root_cid: request.root_cid,
        pins: active_pins_for_root(&state, &pin.root_cid)?,
        reachable_count: reachable.len(),
    }))
}

async fn pin_status(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> Result<Json<PinStatusResponse>, ApiError> {
    let root_cid = BlockStore::parse_cid(&cid)?;
    let pins = active_pins_for_root(&state, &root_cid)?;
    let reachable_count = if pins.is_empty() {
        0
    } else {
        traverse_reachable(&state, root_cid.clone()).await?.len()
    };
    Ok(Json(PinStatusResponse {
        root_cid,
        pins,
        reachable_count,
    }))
}

async fn delete_pin(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> Result<Json<PinStatusResponse>, ApiError> {
    let root_cid = BlockStore::parse_cid(&cid)?;
    deactivate_pins_for_root(&state, &root_cid)?;
    Ok(Json(PinStatusResponse {
        root_cid,
        pins: Vec::new(),
        reachable_count: 0,
    }))
}

async fn run_repair(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    run_repair_once(&state).await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
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
    protect_local_replica_responsibility(&state, &mut protected).await?;
    let report = if query.dry_run {
        state.block_store.garbage_collect_dry_run(&protected)?
    } else {
        state.block_store.garbage_collect(&protected)?
    };
    Ok(Json(report))
}

async fn protect_local_replica_responsibility(
    state: &AppState,
    protected: &mut HashSet<Cid>,
) -> Result<(), ApiError> {
    let candidates = placement_candidates(state, state.network.peers().await);
    for stat in state.block_store.list_blocks()? {
        if select_replicas(&stat.cid, &candidates, state.replication_factor)
            .iter()
            .any(|node| node.is_local)
        {
            protected.insert(stat.cid);
        }
    }
    Ok(())
}

async fn admin_status(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let block_count = state.block_store.list_blocks()?.len();
    let peers = state.network.peers().await.len();
    let queue_depth = compute_queue_depth(&state)?;
    Ok(Json(serde_json::json!({
        "node_id": state.status.node_id,
        "name": state.status.name,
        "schema_version": state.status.schema_version,
        "uptime_seconds": (OffsetDateTime::now_utc() - state.status.started_at).whole_seconds().max(0),
        "subsystems": {
            "metadata": {"status": "ok"},
            "storage": {"status": "ok", "blocks": block_count},
            "network": {"status": "ok", "peers": peers},
            "compute": {"status": if state.compute_enabled { "enabled" } else { "disabled" }, "queue_depth": queue_depth}
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
            Ok(_) => recovered.push(cid.to_string()),
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

async fn traverse_reachable(state: &AppState, root: Cid) -> Result<HashSet<Cid>, ApiError> {
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([root]);
    while let Some(cid) = queue.pop_front() {
        if !seen.insert(cid.clone()) {
            continue;
        }
        if seen.len() > 100_000 {
            return Err(ApiError::bad_request(
                "DAG traversal exceeds the 100000-block safety limit",
            ));
        }
        match cid.codec {
            CODEC_RAW => {}
            CODEC_OBJECT_MANIFEST => {
                let block = get_block_resolved(state, &cid).await?;
                let manifest: ObjectManifest =
                    serde_json::from_slice(&block.payload).map_err(ApiError::serde)?;
                manifest.validate().map_err(ApiError::manifest)?;
                for chunk in manifest.chunks {
                    queue.push_back(chunk.cid);
                }
            }
            CODEC_ERASURE_MANIFEST => {
                let block = get_block_resolved(state, &cid).await?;
                let manifest: ErasureManifest =
                    serde_json::from_slice(&block.payload).map_err(ApiError::serde)?;
                manifest.validate().map_err(ApiError::manifest)?;
                for shard in manifest.shards {
                    queue.push_back(shard.cid);
                }
            }
            CODEC_DIR_MANIFEST => {
                let block = get_block_resolved(state, &cid).await?;
                let manifest: DirManifest =
                    serde_json::from_slice(&block.payload).map_err(ApiError::serde)?;
                manifest.validate().map_err(ApiError::manifest)?;
                for entry in manifest.entries {
                    if let Some(cid) = entry.cid {
                        queue.push_back(cid);
                    }
                }
            }
            _ => {
                return Err(ApiError::bad_request(format!(
                    "unsupported codec {} during DAG traversal",
                    cid.codec.canonical_display()
                )));
            }
        }
    }
    Ok(seen)
}

fn pin_signature_payload(pin: &PinRecord) -> Result<Vec<u8>, ApiError> {
    let mut unsigned = pin.clone();
    unsigned.signature_hex.clear();
    serde_json::to_vec(&unsigned).map_err(ApiError::serde)
}

fn sign_pin(state: &AppState, pin: &mut PinRecord) -> Result<(), ApiError> {
    pin.signature_hex = hex::encode(state.identity.sign(&pin_signature_payload(pin)?));
    Ok(())
}

fn verify_pin(state: &AppState, pin: &PinRecord) -> Result<(), ApiError> {
    let signature: [u8; 64] = hex::decode(&pin.signature_hex)
        .map_err(|_| ApiError::bad_request("pin signature is invalid"))?
        .try_into()
        .map_err(|_| ApiError::bad_request("pin signature must be 64 bytes"))?;
    if !verify_signature(
        &state.identity.public_key_bytes(),
        &pin_signature_payload(pin)?,
        &signature,
    ) {
        return Err(ApiError::bad_request("pin signature verification failed"));
    }
    Ok(())
}

fn persist_pin(state: &AppState, pin: &PinRecord) -> Result<(), ApiError> {
    verify_pin(state, pin)?;
    let write_txn = state
        .metadata
        .database()
        .begin_write()
        .map_err(ApiError::redb_transaction)?;
    {
        let mut pins = write_txn.open_table(PINS).map_err(ApiError::redb_table)?;
        let bytes = serde_json::to_vec(pin).map_err(ApiError::serde)?;
        pins.insert(pin.pin_id.as_str(), bytes.as_slice())
            .map_err(ApiError::redb_storage)?;
    }
    {
        let mut by_root = write_txn
            .open_table(PINS_BY_ROOT)
            .map_err(ApiError::redb_table)?;
        by_root
            .insert(
                format!("{}:{}", pin.root_cid, pin.pin_id).as_str(),
                pin.pin_id.as_str(),
            )
            .map_err(ApiError::redb_storage)?;
    }
    write_txn.commit().map_err(ApiError::redb_commit)?;
    Ok(())
}

fn active_pins_for_root(state: &AppState, root: &Cid) -> Result<Vec<PinRecord>, ApiError> {
    Ok(active_pins(state)?
        .into_iter()
        .filter(|pin| &pin.root_cid == root)
        .collect())
}

fn active_pins(state: &AppState) -> Result<Vec<PinRecord>, ApiError> {
    let read_txn = state
        .metadata
        .database()
        .begin_read()
        .map_err(ApiError::redb_transaction)?;
    let table = match read_txn.open_table(PINS) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(error) => return Err(ApiError::redb_table(error)),
    };
    let now = unix_seconds();
    let mut pins = Vec::new();
    for item in table.iter().map_err(ApiError::redb_storage)? {
        let (_, value) = item.map_err(ApiError::redb_storage)?;
        let pin: PinRecord = serde_json::from_slice(value.value()).map_err(ApiError::serde)?;
        verify_pin(state, &pin)?;
        if pin.status == "active"
            && pin
                .expires_at_unix_seconds
                .is_none_or(|expiry| expiry > now)
        {
            pins.push(pin);
        }
    }
    Ok(pins)
}

fn deactivate_pins_for_root(state: &AppState, root: &Cid) -> Result<(), ApiError> {
    let mut pins = active_pins_for_root(state, root)?;
    let write_txn = state
        .metadata
        .database()
        .begin_write()
        .map_err(ApiError::redb_transaction)?;
    {
        let mut table = write_txn.open_table(PINS).map_err(ApiError::redb_table)?;
        for pin in &mut pins {
            pin.status = "deleted".to_string();
            sign_pin(state, pin)?;
            let bytes = serde_json::to_vec(pin).map_err(ApiError::serde)?;
            table
                .insert(pin.pin_id.as_str(), bytes.as_slice())
                .map_err(ApiError::redb_storage)?;
        }
    }
    write_txn.commit().map_err(ApiError::redb_commit)?;
    Ok(())
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

async fn submit_compute_job(
    State(state): State<AppState>,
    Json(spec): Json<ComputeJobSpec>,
) -> Result<Json<SubmitComputeResponse>, ApiError> {
    let response = schedule_compute_job(state, next_job_id(), spec).await?;
    Ok(Json(response))
}

async fn compute_job_status(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<ComputeJobStatus>, ApiError> {
    let job = load_job(&state, &job_id)?.ok_or_else(|| ApiError::not_found("job not found"))?;
    if job.status == "delegated"
        && let Some(address) = &job.assigned_address
        && let Ok(peer) = address.parse::<SocketAddr>()
    {
        let response = state
            .network
            .compute_status(peer, job_id.clone())
            .await
            .map_err(ApiError::network)?;
        let remote: ComputeJobStatus =
            serde_json::from_str(&response.job_status_json).map_err(ApiError::serde)?;
        if remote.receipt.is_some() {
            verify_compute_receipt(&state, &remote)?;
        }
        if matches!(
            remote.status.as_str(),
            "succeeded" | "failed" | "timed_out" | "canceled"
        ) {
            let mut updated = remote.clone();
            updated.assigned_address = job.assigned_address.clone();
            updated.attempts = job.attempts.clone();
            persist_job(&state, &updated)?;
        }
        return Ok(Json(remote));
    }
    Ok(Json(job))
}

async fn compute_job_logs(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<ComputeLogsResponse>, ApiError> {
    let logs = compute_logs_for_job(&state, &job_id).await?;
    Ok(Json(logs))
}

async fn cancel_compute_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<ComputeJobStatus>, ApiError> {
    let job = cancel_compute_job_by_id(&state, &job_id).await?;
    Ok(Json(job))
}

async fn schedule_compute_job(
    state: AppState,
    job_id: String,
    spec: ComputeJobSpec,
) -> Result<SubmitComputeResponse, ApiError> {
    if !state.compute_enabled {
        return Err(ApiError::bad_request("compute is disabled"));
    }
    validate_job_spec(&spec).map_err(|error| ApiError::bad_request(error.to_string()))?;
    enforce_compute_limits(&state, &spec)?;
    let mut offers = collect_compute_offers(&state, &spec).await?;
    let rejection_reasons = offers
        .iter()
        .filter(|offer| !offer.accepted)
        .filter_map(|offer| {
            offer
                .rejection_reason
                .as_ref()
                .map(|reason| format!("{}:{reason}", offer.node_id))
        })
        .collect::<Vec<_>>();
    offers.retain(|offer| offer.accepted);
    offers.sort_by(|left, right| {
        right
            .local_input_bytes
            .cmp(&left.local_input_bytes)
            .then_with(|| {
                left.estimated_queue_delay_seconds
                    .cmp(&right.estimated_queue_delay_seconds)
            })
            .then_with(|| right.available_parallelism.cmp(&left.available_parallelism))
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    if offers.is_empty() {
        let detail = if rejection_reasons.is_empty() {
            "no compute node accepted the job".to_string()
        } else {
            format!(
                "no compute node accepted the job: {}",
                rejection_reasons.join(", ")
            )
        };
        return Err(ApiError::bad_request(detail));
    }

    let mut attempts = Vec::new();
    for offer in offers {
        let started = unix_seconds();
        if offer.node_id == state.status.node_id {
            let mut job = new_compute_job(
                job_id.clone(),
                spec.clone(),
                "queued",
                Some(offer.node_id.clone()),
                None,
            );
            job.attempts = attempts;
            job.attempts.push(ComputeAttempt {
                node_id: offer.node_id.clone(),
                address: None,
                status: "accepted".to_string(),
                error: None,
                started_at_unix_seconds: started,
                finished_at_unix_seconds: None,
                events: Vec::new(),
            });
            persist_job(&state, &job)?;
            if let Err(error) = spawn_compute_job(state.clone(), job_id.clone()) {
                job.status = "failed".to_string();
                job.finished_at_unix_seconds = Some(unix_seconds());
                job.error = Some(error.message.clone());
                persist_job(&state, &job)?;
                return Err(error);
            }
            COMPUTE_SCHEDULED_LOCAL.fetch_add(1, Ordering::Relaxed);
            return Ok(SubmitComputeResponse {
                job_id,
                status: "queued".to_string(),
                assigned_node_id: Some(offer.node_id),
            });
        }

        let Some(address) = offer.address.clone() else {
            continue;
        };
        let peer = match address.parse::<SocketAddr>() {
            Ok(peer) => peer,
            Err(error) => {
                attempts.push(ComputeAttempt {
                    node_id: offer.node_id,
                    address: Some(address),
                    status: "failed".to_string(),
                    error: Some(error.to_string()),
                    started_at_unix_seconds: started,
                    finished_at_unix_seconds: Some(unix_seconds()),
                    events: Vec::new(),
                });
                continue;
            }
        };
        let spec_json = serde_json::to_string(&spec).map_err(ApiError::serde)?;
        match state
            .network
            .compute_submit(peer, job_id.clone(), spec_json)
            .await
        {
            Ok(response) => {
                let remote: ComputeJobStatus =
                    serde_json::from_str(&response.job_status_json).map_err(ApiError::serde)?;
                let mut proxy = new_compute_job(
                    job_id.clone(),
                    spec.clone(),
                    "delegated",
                    Some(
                        remote
                            .assigned_node_id
                            .clone()
                            .unwrap_or(offer.node_id.clone()),
                    ),
                    Some(address.clone()),
                );
                proxy.attempts = attempts;
                proxy.attempts.push(ComputeAttempt {
                    node_id: offer.node_id.clone(),
                    address: Some(address),
                    status: "accepted".to_string(),
                    error: None,
                    started_at_unix_seconds: started,
                    finished_at_unix_seconds: None,
                    events: Vec::new(),
                });
                persist_job(&state, &proxy)?;
                COMPUTE_SCHEDULED_REMOTE.fetch_add(1, Ordering::Relaxed);
                return Ok(SubmitComputeResponse {
                    job_id,
                    status: remote.status,
                    assigned_node_id: Some(offer.node_id),
                });
            }
            Err(error) => {
                COMPUTE_SCHEDULE_RETRIES.fetch_add(1, Ordering::Relaxed);
                attempts.push(ComputeAttempt {
                    node_id: offer.node_id,
                    address: Some(address),
                    status: "failed".to_string(),
                    error: Some(error.to_string()),
                    started_at_unix_seconds: started,
                    finished_at_unix_seconds: Some(unix_seconds()),
                    events: Vec::new(),
                })
            }
        }
    }

    Err(ApiError::bad_request("all compute submit attempts failed"))
}

fn verify_compute_receipt(state: &AppState, job: &ComputeJobStatus) -> Result<(), ApiError> {
    let receipt = job
        .receipt
        .as_ref()
        .ok_or_else(|| ApiError::bad_request("compute receipt is missing"))?;
    if receipt.job_id != job.job_id
        || receipt.status != job.status
        || receipt.node_id
            != job
                .assigned_node_id
                .clone()
                .unwrap_or_else(|| receipt.node_id.clone())
    {
        return Err(ApiError::bad_request(
            "compute receipt does not match job status",
        ));
    }
    let mut unsigned = receipt.clone();
    let signature = std::mem::take(&mut unsigned.signature_hex);
    let payload = serde_json::to_vec(&unsigned).map_err(ApiError::serde)?;
    state
        .network
        .verify_node_signature(&receipt.node_id, &payload, &signature)
        .map_err(ApiError::network)
}

fn enforce_size_limit(limit: Option<u64>, actual: u64, name: &str) -> Result<(), ApiError> {
    if let Some(limit) = limit
        && actual > limit
    {
        return Err(ApiError {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            message: format!("{name} size {actual} exceeds configured limit {limit}"),
        });
    }
    Ok(())
}

fn enforce_compute_limits(state: &AppState, spec: &ComputeJobSpec) -> Result<(), ApiError> {
    if let Some(rootfs_cid) = &spec.rootfs_cid
        && !state.firecracker_allow_untrusted_rootfs
        && !state.firecracker_allowed_rootfs_cids.contains(rootfs_cid)
    {
        return Err(ApiError::bad_request(
            "rootfs_cid is not in compute.firecracker_allowed_rootfs_cids",
        ));
    }
    if let Some(resources) = &spec.resources {
        if resources
            .memory_mib
            .is_some_and(|value| value > state.firecracker_memory_mib as u64)
        {
            return Err(ApiError::bad_request(format!(
                "compute memory exceeds node limit of {} MiB",
                state.firecracker_memory_mib
            )));
        }
        let cpu_limit = state.firecracker_vcpu_count as u64 * 1000;
        if resources.cpu_millis.is_some_and(|value| value > cpu_limit) {
            return Err(ApiError::bad_request(format!(
                "compute CPU exceeds node limit of {cpu_limit} millicores"
            )));
        }
        if resources
            .max_input_bytes
            .is_some_and(|value| value > state.firecracker_max_input_bytes)
        {
            return Err(ApiError::bad_request(
                "compute input limit exceeds node policy",
            ));
        }
        if resources
            .max_output_bytes
            .is_some_and(|value| value > state.firecracker_max_output_bytes)
        {
            return Err(ApiError::bad_request(
                "compute output limit exceeds node policy",
            ));
        }
    }
    if let Some(limit) = state.max_compute_timeout_seconds {
        let requested = spec
            .resources
            .as_ref()
            .and_then(|resources| resources.timeout_seconds)
            .unwrap_or(600);
        if requested > limit {
            return Err(ApiError::bad_request(format!(
                "compute timeout {requested}s exceeds configured limit {limit}s"
            )));
        }
    }
    Ok(())
}

fn new_compute_job(
    job_id: String,
    spec: ComputeJobSpec,
    status: &str,
    assigned_node_id: Option<String>,
    assigned_address: Option<String>,
) -> ComputeJobStatus {
    ComputeJobStatus {
        job_id,
        status: status.to_string(),
        spec,
        created_at_unix_seconds: unix_seconds(),
        started_at_unix_seconds: None,
        finished_at_unix_seconds: None,
        exit_code: None,
        stdout_cid: None,
        stderr_cid: None,
        output_root_cid: None,
        error: None,
        receipt: None,
        firecracker_error_class: None,
        cancel_requested_at_unix_seconds: None,
        cancel_delivered_at_unix_seconds: None,
        cancel_acknowledged_at_unix_seconds: None,
        guest_exited_after_cancel: false,
        vm_killed_after_cancel: false,
        assigned_node_id,
        assigned_address,
        attempts: Vec::new(),
    }
}

fn recover_compute_jobs(state: &AppState) -> Result<(), ApiError> {
    let read_txn = state
        .metadata
        .database()
        .begin_read()
        .map_err(ApiError::redb_transaction)?;
    let table = match read_txn.open_table(JOBS) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
        Err(error) => return Err(ApiError::redb_table(error)),
    };
    let mut queued = Vec::new();
    let mut interrupted = Vec::new();
    for row in table.iter().map_err(ApiError::redb_storage)? {
        let (_, value) = row.map_err(ApiError::redb_storage)?;
        let job: ComputeJobStatus =
            serde_json::from_slice(value.value()).map_err(ApiError::serde)?;
        match job.status.as_str() {
            "queued" => queued.push(job.job_id),
            "running" => interrupted.push(job),
            _ => {}
        }
    }
    drop(table);
    drop(read_txn);
    for mut job in interrupted {
        if validate_job_id(&job.job_id).is_ok() {
            let _ = std::fs::remove_dir_all(state.compute_work_dir.join(&job.job_id));
        }
        job.status = "failed".to_string();
        job.finished_at_unix_seconds = Some(unix_seconds());
        job.error = Some("agent restarted while job was running".to_string());
        persist_job(state, &job)?;
    }
    for job_id in queued {
        if let Err(error) = spawn_compute_job(state.clone(), job_id.clone())
            && let Some(mut job) = load_job(state, &job_id)?
        {
            job.status = "failed".to_string();
            job.finished_at_unix_seconds = Some(unix_seconds());
            job.error = Some(error.message);
            persist_job(state, &job)?;
        }
    }
    Ok(())
}

fn spawn_compute_job(state: AppState, job_id: String) -> Result<(), ApiError> {
    let queue_permit = state
        .compute_queue_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::bad_request("compute queue is full"))?;
    let (start_tx, start_rx) = oneshot::channel();
    let task_state = state.clone();
    let task_job_id = job_id.clone();
    let handle = tokio::spawn(async move {
        let _queue_permit = queue_permit;
        if start_rx.await.is_err() {
            return;
        }
        if let Err(error) = execute_compute_job(task_state.clone(), task_job_id.clone()).await
            && let Ok(Some(mut failed)) = load_job(&task_state, &task_job_id)
            && failed.status != "canceled"
        {
            failed.status = "failed".to_string();
            failed.finished_at_unix_seconds = Some(unix_seconds());
            failed.error = Some(error.message);
            let _ = persist_job(&task_state, &failed);
        }
        if let Ok(mut tasks) = task_state.compute_tasks.lock() {
            tasks.remove(&task_job_id);
        }
    });
    let abort_handle = handle.abort_handle();
    {
        let mut tasks = state
            .compute_tasks
            .lock()
            .map_err(|_| ApiError::internal("compute task map lock poisoned"))?;
        if tasks.insert(job_id, abort_handle).is_some() {
            handle.abort();
            return Err(ApiError::bad_request("compute job is already running"));
        }
    }
    let _ = start_tx.send(());
    Ok(())
}

async fn collect_compute_offers(
    state: &AppState,
    spec: &ComputeJobSpec,
) -> Result<Vec<ComputeOffer>, ApiError> {
    let mut offers = Vec::new();
    offers.push(local_compute_offer(state, spec, None)?);

    let mut candidates = Vec::new();
    for input in &spec.inputs {
        if let Ok(providers) = state.network.find_providers(&input.cid).await {
            for provider in providers {
                if provider.node_id == state.status.node_id {
                    continue;
                }
                for address in provider.addresses {
                    candidates.push((provider.node_id.clone(), address));
                }
            }
        }
    }
    for peer in state.network.peers().await {
        for address in peer.addresses {
            candidates.push((peer.node_id.clone(), address));
        }
    }
    candidates.sort();
    candidates.dedup();

    let spec_json = serde_json::to_string(spec).map_err(ApiError::serde)?;
    for (node_id, address) in candidates {
        let Ok(peer) = address.parse::<SocketAddr>() else {
            continue;
        };
        match state.network.compute_offer(peer, spec_json.clone()).await {
            Ok(response) => offers.push(ComputeOffer {
                accepted: response.accepted,
                node_id: if response.node_id.is_empty() {
                    node_id
                } else {
                    response.node_id
                },
                address: Some(address),
                estimated_queue_delay_seconds: response.estimated_queue_delay_seconds,
                local_input_bytes: response.local_input_bytes,
                total_input_bytes: response.total_input_bytes,
                available_parallelism: response.available_parallelism,
                rejection_reason: if response.rejection_reason.is_empty() {
                    None
                } else {
                    Some(response.rejection_reason)
                },
            }),
            Err(error) => warn!(%peer, %error, "compute offer request failed"),
        }
    }
    Ok(offers)
}

fn local_compute_offer(
    state: &AppState,
    spec: &ComputeJobSpec,
    address: Option<String>,
) -> Result<ComputeOffer, ApiError> {
    let queue_available = state.compute_queue_slots.available_permits();
    let rejection_reason = if !state.compute_enabled {
        Some("compute is disabled".to_string())
    } else if queue_available == 0 {
        Some("compute queue is full".to_string())
    } else if let Err(error) = validate_job_spec(spec) {
        Some(error.to_string())
    } else if let Err(error) = enforce_compute_limits(state, spec) {
        Some(error.message)
    } else if spec.runtime.as_deref().unwrap_or(&state.compute_runtime) == "firecracker"
        && spec.rootfs_cid.is_none()
    {
        Some("firecracker compute jobs must set rootfs_cid".to_string())
    } else if spec.runtime.as_deref().unwrap_or(&state.compute_runtime) == "firecracker"
        && let Err(error) = ensure_firecracker_available(state)
    {
        Some(error.message)
    } else {
        None
    };
    let (local_input_bytes, total_input_bytes) = estimate_job_input_locality(state, spec);
    let available = state.compute_semaphore.available_permits() as u32;
    Ok(ComputeOffer {
        accepted: rejection_reason.is_none(),
        node_id: state.status.node_id.clone(),
        address,
        estimated_queue_delay_seconds: if available > 0 { 0 } else { 1 },
        local_input_bytes,
        total_input_bytes,
        available_parallelism: available,
        rejection_reason,
    })
}

fn estimate_job_input_locality(state: &AppState, spec: &ComputeJobSpec) -> (u64, u64) {
    let mut local = 0u64;
    let mut total = 0u64;
    let mut visited = HashSet::new();
    if let Some(rootfs_cid) = &spec.rootfs_cid {
        let (rootfs_local, rootfs_total) =
            estimate_cid_locality(state, rootfs_cid, &mut visited, 128);
        local = local.saturating_add(rootfs_local);
        total = total.saturating_add(rootfs_total);
    }
    for input in &spec.inputs {
        let (input_local, input_total) =
            estimate_cid_locality(state, &input.cid, &mut visited, 128);
        local = local.saturating_add(input_local);
        total = total.saturating_add(input_total);
    }
    (local, total)
}

fn estimate_cid_locality(
    state: &AppState,
    cid: &Cid,
    visited: &mut HashSet<Cid>,
    remaining: usize,
) -> (u64, u64) {
    if remaining == 0 || visited.len() >= 4096 || !visited.insert(cid.clone()) {
        return (0, 0);
    }
    let has_local = state.block_store.has(cid).unwrap_or(false);
    match cid.codec {
        CODEC_RAW => {
            let size = state
                .block_store
                .stat(cid)
                .map(|stat| stat.size)
                .unwrap_or(0);
            (if has_local { size } else { 0 }, size)
        }
        CODEC_OBJECT_MANIFEST if has_local => {
            let Ok(block) = state.block_store.get(cid) else {
                return (0, 0);
            };
            let Ok(manifest) = serde_json::from_slice::<ObjectManifest>(&block.payload) else {
                return (0, 0);
            };
            let mut local = 0u64;
            let mut total = manifest.size;
            for chunk in manifest.chunks {
                if state.block_store.has(&chunk.cid).unwrap_or(false) {
                    local = local.saturating_add(chunk.size);
                }
            }
            if total == 0 {
                total = local;
            }
            (local, total)
        }
        CODEC_ERASURE_MANIFEST if has_local => {
            let Ok(block) = state.block_store.get(cid) else {
                return (0, 0);
            };
            let Ok(manifest) = serde_json::from_slice::<ErasureManifest>(&block.payload) else {
                return (0, 0);
            };
            if manifest.validate().is_err() {
                return (0, 0);
            }
            let local_shards = manifest
                .shards
                .iter()
                .filter(|shard| state.block_store.has(&shard.cid).unwrap_or(false))
                .count();
            let local = if local_shards >= manifest.data_shards as usize {
                manifest.size
            } else {
                (local_shards as u64)
                    .saturating_mul(manifest.shard_size)
                    .min(manifest.size)
            };
            (local, manifest.size)
        }
        CODEC_DIR_MANIFEST if has_local => {
            let Ok(block) = state.block_store.get(cid) else {
                return (0, 0);
            };
            let Ok(manifest) = serde_json::from_slice::<DirManifest>(&block.payload) else {
                return (0, 0);
            };
            let mut local = 0u64;
            let mut total = 0u64;
            for entry in manifest.entries {
                if let Some(child) = entry.cid {
                    let (child_local, child_total) =
                        estimate_cid_locality(state, &child, visited, remaining.saturating_sub(1));
                    local = local.saturating_add(child_local);
                    total = total.saturating_add(child_total.max(entry.size.unwrap_or(0)));
                }
            }
            (local, total)
        }
        _ => (0, 0),
    }
}

fn record_attempt_event(job: &mut ComputeJobStatus, event: impl Into<String>) {
    const MAX_EVENTS: usize = 256;
    const MAX_EVENT_BYTES: usize = 1024;
    if let Some(attempt) = job.attempts.last_mut() {
        if attempt.events.len() >= MAX_EVENTS {
            return;
        }
        let mut event = event.into();
        event.truncate(
            event
                .char_indices()
                .take_while(|(index, _)| *index < MAX_EVENT_BYTES)
                .last()
                .map(|(index, ch)| index + ch.len_utf8())
                .unwrap_or(0),
        );
        attempt.events.push(format!("{}:{event}", unix_seconds()));
    }
}

async fn cancel_compute_job_by_id(
    state: &AppState,
    job_id: &str,
) -> Result<ComputeJobStatus, ApiError> {
    let mut job = load_job(state, job_id)?.ok_or_else(|| ApiError::not_found("job not found"))?;
    if job.status == "delegated"
        && let Some(address) = &job.assigned_address
        && let Ok(peer) = address.parse::<SocketAddr>()
    {
        let response = state
            .network
            .compute_cancel(peer, job_id.to_string())
            .await
            .map_err(ApiError::network)?;
        let remote: ComputeJobStatus =
            serde_json::from_str(&response.job_status_json).map_err(ApiError::serde)?;
        job.status = remote.status.clone();
        job.finished_at_unix_seconds = remote.finished_at_unix_seconds;
        job.error = remote.error.clone();
        persist_job(state, &job)?;
        return Ok(remote);
    }

    let _state_guard = state.compute_state_lock.lock().await;
    job = load_job(state, job_id)?.ok_or_else(|| ApiError::not_found("job not found"))?;
    match job.status.as_str() {
        "queued" => {
            job.status = "canceled".to_string();
            job.finished_at_unix_seconds = Some(unix_seconds());
            job.error = Some("job canceled before execution".to_string());
            if let Some(attempt) = job.attempts.last_mut()
                && attempt.finished_at_unix_seconds.is_none()
            {
                attempt.status = "canceled".to_string();
                attempt.finished_at_unix_seconds = Some(unix_seconds());
            }
            persist_job(state, &job)?;
            if let Ok(mut tasks) = state.compute_tasks.lock()
                && let Some(handle) = tasks.remove(job_id)
            {
                handle.abort();
            }
            Ok(job)
        }
        "running" => {
            let mut cancel_detail = "running job canceled".to_string();
            if job
                .spec
                .runtime
                .as_deref()
                .unwrap_or(&state.compute_runtime)
                == "firecracker"
            {
                let requested_at = unix_seconds();
                job.cancel_requested_at_unix_seconds = Some(requested_at);
                record_attempt_event(&mut job, "cancel_requested");
                match send_firecracker_cancel(state, &job).await {
                    Ok(outcome) => {
                        if outcome.delivered {
                            job.cancel_delivered_at_unix_seconds = Some(unix_seconds());
                        }
                        if outcome.acknowledged {
                            job.cancel_acknowledged_at_unix_seconds = Some(unix_seconds());
                        }
                        for event in outcome.events() {
                            record_attempt_event(&mut job, event);
                        }
                        cancel_detail = outcome.description();
                    }
                    Err(error) => {
                        record_attempt_event(
                            &mut job,
                            format!("cancel_vsock_failed:{}", error.message),
                        );
                        warn!(?error, job_id = %job.job_id, "firecracker vsock cancel request failed; falling back to VM process-group termination");
                        cancel_detail = format!(
                            "firecracker cancel fell back to VM termination after vsock error: {}",
                            error.message
                        );
                    }
                }
                time::sleep(Duration::from_secs(2)).await;
                let current = load_job(state, job_id)?;
                if let Some(current) = current
                    && matches!(
                        current.status.as_str(),
                        "succeeded" | "failed" | "timed_out" | "canceled"
                    )
                {
                    return Ok(current);
                }
                let guest_finished = false;
                job.guest_exited_after_cancel = guest_finished;
                job.vm_killed_after_cancel = !guest_finished;
                record_attempt_event(
                    &mut job,
                    if guest_finished {
                        "guest_exited_after_cancel"
                    } else {
                        "vm_killed_after_cancel"
                    },
                );
            }
            if let Ok(mut tasks) = state.compute_tasks.lock()
                && let Some(handle) = tasks.remove(job_id)
            {
                handle.abort();
            }
            job.status = "canceled".to_string();
            job.finished_at_unix_seconds = Some(unix_seconds());
            job.error = Some(cancel_detail);
            if let Some(attempt) = job.attempts.last_mut()
                && attempt.finished_at_unix_seconds.is_none()
            {
                attempt.status = "canceled".to_string();
                attempt.finished_at_unix_seconds = Some(unix_seconds());
            }
            persist_job(state, &job)?;
            Ok(job)
        }
        "canceled" | "succeeded" | "failed" | "timed_out" => Ok(job),
        _ => Err(ApiError::bad_request(
            "job cannot be canceled in current state",
        )),
    }
}

async fn compute_logs_for_job(
    state: &AppState,
    job_id: &str,
) -> Result<ComputeLogsResponse, ApiError> {
    let job = load_job(state, job_id)?.ok_or_else(|| ApiError::not_found("job not found"))?;
    if job.status == "delegated"
        && let Some(address) = &job.assigned_address
        && let Ok(peer) = address.parse::<SocketAddr>()
    {
        let response = state
            .network
            .compute_logs(peer, job_id.to_string())
            .await
            .map_err(ApiError::network)?;
        return serde_json::from_str(&response.logs_json).map_err(ApiError::serde);
    }
    let stdout = if let Some(cid) = &job.stdout_cid {
        String::from_utf8_lossy(&get_block_resolved(state, cid).await?.payload).to_string()
    } else {
        String::new()
    };
    let stderr = if let Some(cid) = &job.stderr_cid {
        String::from_utf8_lossy(&get_block_resolved(state, cid).await?.payload).to_string()
    } else {
        String::new()
    };
    Ok(ComputeLogsResponse {
        job_id: job_id.to_string(),
        stdout,
        stderr,
    })
}

async fn execute_compute_job(state: AppState, job_id: String) -> Result<(), ApiError> {
    let _permit = state
        .compute_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let _guard = state.operation_lock.read().await;
    let job = {
        let _state_guard = state.compute_state_lock.lock().await;
        let mut job =
            load_job(&state, &job_id)?.ok_or_else(|| ApiError::not_found("job not found"))?;
        if job.status == "canceled" {
            return Ok(());
        }
        job.status = "running".to_string();
        job.started_at_unix_seconds = Some(unix_seconds());
        persist_job(&state, &job)?;
        job
    };

    let runtime = job
        .spec
        .runtime
        .clone()
        .unwrap_or_else(|| state.compute_runtime.clone());
    if runtime != "firecracker" {
        return Err(ApiError::bad_request(format!(
            "unsupported compute runtime {runtime}; only firecracker is supported"
        )));
    }
    execute_firecracker_job(state.clone(), job).await
}

async fn execute_firecracker_job(
    state: AppState,
    mut job: ComputeJobStatus,
) -> Result<(), ApiError> {
    ensure_firecracker_available(&state)?;
    let rootfs_cid = job
        .spec
        .rootfs_cid
        .clone()
        .ok_or_else(|| ApiError::bad_request("firecracker compute jobs must set rootfs_cid"))?;
    let job_id = job.job_id.clone();
    validate_job_id(&job_id)?;
    let work_dir = state.compute_work_dir.join(&job_id);
    let root_dir = work_dir.join("firecracker-root");
    let input_dir = work_dir.join("firecracker-input");
    let extract_dir = work_dir.join("firecracker-extract");
    let rootfs = work_dir.join("rootfs.ext4");
    let inputfs = work_dir.join("inputs.ext4");
    let outputfs = work_dir.join("outputs.ext4");
    let vsock_path = work_dir.join("vsock.sock");
    let guest_cid_guard = allocate_firecracker_guest_cid(&state, &job_id)?;
    let guest_cid = guest_cid_guard.cid;
    let config_path = work_dir.join("firecracker.json");
    std::fs::create_dir(&work_dir).map_err(|error| {
        ApiError::internal(format!(
            "failed to create fresh compute work directory {}: {error}",
            work_dir.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&work_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| ApiError::internal(error.to_string()))?;
    }
    let _cleanup_guard = FirecrackerCleanupGuard {
        work_dir: work_dir.clone(),
        root_dir: root_dir.clone(),
        input_dir: input_dir.clone(),
        rootfs: rootfs.clone(),
        inputfs: Some(inputfs.clone()),
        outputfs: Some(outputfs.clone()),
        vsock_path: Some(vsock_path.clone()),
        config_path: config_path.clone(),
        jail_dir: state.firecracker_enable_jailer.then(|| {
            state
                .firecracker_jailer_chroot_base
                .join("firecracker")
                .join(safe_jailer_id(&job_id))
        }),
    };
    std::fs::create_dir_all(&root_dir).map_err(|error| ApiError::internal(error.to_string()))?;
    std::fs::create_dir_all(&input_dir).map_err(|error| ApiError::internal(error.to_string()))?;
    std::fs::create_dir_all(root_dir.join("pepper_runtime"))
        .map_err(|error| ApiError::internal(error.to_string()))?;

    let input_limit = job
        .spec
        .resources
        .as_ref()
        .and_then(|resources| resources.max_input_bytes)
        .unwrap_or(state.firecracker_max_input_bytes);
    let mut declared_input_bytes = 0u64;
    for input in &job.spec.inputs {
        declared_input_bytes = declared_input_bytes
            .checked_add(logical_cid_size(&state, &input.cid).await?)
            .ok_or_else(|| ApiError::bad_request("compute input size overflow"))?;
        enforce_size_limit(Some(input_limit), declared_input_bytes, "compute inputs")?;
    }
    let declared_rootfs_bytes = logical_cid_size(&state, &rootfs_cid).await?;
    enforce_size_limit(
        Some(input_limit),
        declared_rootfs_bytes,
        "firecracker rootfs",
    )?;

    for input in &job.spec.inputs {
        let target = safe_join(&input_dir, &input.mount)?;
        materialize_cid_to_path(&state, &input.cid, &target).await?;
    }
    tokio::task::block_in_place(|| {
        enforce_firecracker_input_limit(&state, &job, &input_dir)?;
        create_ext4_rootfs(&input_dir, &inputfs)
    })?;
    let output_limit = firecracker_output_limit(&state, &job);
    tokio::task::block_in_place(|| create_empty_ext4_image(&outputfs, output_limit))?;
    write_firecracker_mount_script(&root_dir, &job.spec.inputs)?;

    let command_line = job
        .spec
        .command
        .iter()
        .map(|part| shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ");
    write_executable(
        &root_dir.join("job.sh"),
        format!("#!/bin/sh\nexport PATH=/bin:/sbin:/usr/bin:/usr/sbin\ncd /\n{command_line}\n")
            .as_bytes(),
    )?;
    write_executable(&root_dir.join("init"), firecracker_guest_init_script())?;
    write_bytes(&root_dir.join("pepper_job_id"), job_id.as_bytes())?;

    let rootfs_bytes = rootfs_image_bytes(&state, &rootfs_cid).await?;
    let rootfs_limit = job
        .spec
        .resources
        .as_ref()
        .and_then(|resources| resources.max_input_bytes)
        .unwrap_or(state.firecracker_max_input_bytes);
    enforce_size_limit(
        Some(rootfs_limit),
        rootfs_bytes.len() as u64,
        "firecracker rootfs",
    )?;
    std::fs::write(&rootfs, rootfs_bytes).map_err(|error| ApiError::internal(error.to_string()))?;
    if let Err(error) = tokio::task::block_in_place(|| validate_firecracker_rootfs_image(&rootfs)) {
        FIRECRACKER_ROOTFS_VALIDATION_FAILURES.fetch_add(1, Ordering::Relaxed);
        job.firecracker_error_class = Some("rootfs_validation".to_string());
        job.status = "failed".to_string();
        job.finished_at_unix_seconds = Some(unix_seconds());
        job.error = Some(error.message.clone());
        persist_job(&state, &job)?;
        return Err(error);
    }
    tokio::task::block_in_place(|| {
        debugfs_write_tree(&rootfs, &root_dir)?;
        debugfs_runtime_symlinks(&rootfs)
    })?;
    let kernel = state
        .firecracker_kernel_image
        .clone()
        .unwrap_or_else(default_firecracker_kernel_image);
    let config_kernel_path = if state.firecracker_enable_jailer {
        PathBuf::from("/vmlinux")
    } else {
        kernel.clone()
    };
    let config_rootfs_path = if state.firecracker_enable_jailer {
        PathBuf::from("/rootfs.ext4")
    } else {
        rootfs.clone()
    };
    let config_inputfs_path = if state.firecracker_enable_jailer {
        PathBuf::from("/inputs.ext4")
    } else {
        inputfs.clone()
    };
    let config_outputfs_path = if state.firecracker_enable_jailer {
        PathBuf::from("/outputs.ext4")
    } else {
        outputfs.clone()
    };
    let config_vsock_path = if state.firecracker_enable_jailer {
        PathBuf::from("/vsock.sock")
    } else {
        vsock_path.clone()
    };
    let vm_memory_mib = job
        .spec
        .resources
        .as_ref()
        .and_then(|resources| resources.memory_mib)
        .unwrap_or(state.firecracker_memory_mib as u64)
        .min(u32::MAX as u64) as u32;
    let firecracker_config = serde_json::json!({
        "boot-source": {
            "kernel_image_path": config_kernel_path,
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off nomodules random.trust_cpu=on root=/dev/vda ro init=/init"
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": config_rootfs_path,
                "is_root_device": true,
                "is_read_only": true
            },
            {
                "drive_id": "inputs",
                "path_on_host": config_inputfs_path,
                "is_root_device": false,
                "is_read_only": true
            },
            {
                "drive_id": "outputs",
                "path_on_host": config_outputfs_path,
                "is_root_device": false,
                "is_read_only": false
            }
        ],
        "machine-config": {
            "vcpu_count": state.firecracker_vcpu_count,
            "mem_size_mib": vm_memory_mib,
            "smt": false,
            "track_dirty_pages": false
        },
        "vsock": {
            "guest_cid": guest_cid,
            "uds_path": config_vsock_path
        }
    });
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&firecracker_config).map_err(ApiError::serde)?,
    )
    .map_err(|error| ApiError::internal(error.to_string()))?;

    let timeout = Duration::from_secs(
        job.spec
            .resources
            .as_ref()
            .and_then(|resources| resources.timeout_seconds)
            .unwrap_or(600),
    );
    let firecracker_paths = FirecrackerRuntimePaths {
        rootfs: &rootfs,
        inputfs: &inputfs,
        outputfs: &outputfs,
        vsock_path: &vsock_path,
        kernel: &kernel,
        config_path: &config_path,
    };
    let firecracker_command = prepare_firecracker_command(&state, &job_id, &firecracker_paths)?;
    let mut firecracker = firecracker_command;
    FIRECRACKER_VM_STARTS.fetch_add(1, Ordering::Relaxed);
    let child = firecracker.spawn().map_err(|error| {
        FIRECRACKER_VM_FAILURES.fetch_add(1, Ordering::Relaxed);
        job.firecracker_error_class = Some("vm_start".to_string());
        job.status = "failed".to_string();
        job.finished_at_unix_seconds = Some(unix_seconds());
        job.error = Some(error.to_string());
        let _ = persist_job(&state, &job);
        ApiError::internal(error.to_string())
    })?;
    let mut process_guard = ProcessGroupGuard::new(child.id());
    let _cgroup_guard = apply_firecracker_cgroup(&state, &job, child.id())?;
    let host_vsock_path = firecracker_host_vsock_path(&state, &job_id, &vsock_path);
    let poll_handle = spawn_firecracker_control_stream(
        state.clone(),
        job_id.clone(),
        host_vsock_path,
        work_dir.clone(),
        timeout,
    );
    let output = match time::timeout(timeout, child.wait_with_output()).await {
        Ok(result) => result.map_err(|error| ApiError::internal(error.to_string()))?,
        Err(_) => {
            job.status = "timed_out".to_string();
            job.firecracker_error_class = Some("timeout".to_string());
            job.finished_at_unix_seconds = Some(unix_seconds());
            job.error = Some("firecracker job timed out".to_string());
            merge_current_attempt_events(&state, &mut job)?;
            persist_job(&state, &job)?;
            FIRECRACKER_VM_FAILURES.fetch_add(1, Ordering::Relaxed);
            FIRECRACKER_HEARTBEAT_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            poll_handle.abort();
            process_guard.terminate();
            cleanup_firecracker_temp(
                &root_dir,
                &input_dir,
                &rootfs,
                Some(&inputfs),
                Some(&outputfs),
                Some(&vsock_path),
                &config_path,
            );
            return Ok(());
        }
    };
    poll_handle.abort();
    process_guard.disarm();

    let runtime_outputfs = firecracker_runtime_outputfs(&state, &job_id, &outputfs);
    std::fs::create_dir_all(&extract_dir).map_err(|error| ApiError::internal(error.to_string()))?;
    let stdout_bytes = tokio::task::block_in_place(|| {
        debugfs_dump(&runtime_outputfs, "/fc_stdout", 16 * 1024 * 1024).unwrap_or_else(|_| {
            std::fs::read(work_dir.join("vsock_stdout.log"))
                .unwrap_or_else(|_| output.stdout.clone())
        })
    });
    let stderr_bytes = tokio::task::block_in_place(|| {
        debugfs_dump(&runtime_outputfs, "/fc_stderr", 16 * 1024 * 1024).unwrap_or_else(|_| {
            std::fs::read(work_dir.join("vsock_stderr.log"))
                .unwrap_or_else(|_| output.stderr.clone())
        })
    });
    let exit_code =
        tokio::task::block_in_place(|| debugfs_dump(&runtime_outputfs, "/exit_code", 64))
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|text| text.trim().parse::<i32>().ok())
            .unwrap_or_else(|| output.status.code().unwrap_or(1));
    if let Err(error) =
        tokio::task::block_in_place(|| debugfs_rdump(&runtime_outputfs, "/output", &extract_dir))
    {
        FIRECRACKER_OUTPUT_EXTRACTION_FAILURES.fetch_add(1, Ordering::Relaxed);
        job.firecracker_error_class = Some("output_extraction".to_string());
        job.status = "failed".to_string();
        job.finished_at_unix_seconds = Some(unix_seconds());
        job.error = Some(error.message.clone());
        persist_job(&state, &job)?;
        return Err(error);
    }
    tokio::task::block_in_place(|| enforce_firecracker_output_limit(&state, &job, &extract_dir))?;

    let stdout_receipt = put_replicated_block(&state, CODEC_RAW, stdout_bytes).await?;
    let stderr_receipt = put_replicated_block(&state, CODEC_RAW, stderr_bytes).await?;
    let output_root_cid = collect_compute_output(&state, &extract_dir, &job.spec.outputs).await?;
    let finished_at = unix_seconds();
    let status = if exit_code == 0 {
        FIRECRACKER_VM_SUCCESSES.fetch_add(1, Ordering::Relaxed);
        "succeeded"
    } else {
        FIRECRACKER_VM_FAILURES.fetch_add(1, Ordering::Relaxed);
        "failed"
    }
    .to_string();
    let _state_guard = state.compute_state_lock.lock().await;
    let current_status = load_job(&state, &job_id)?.map(|current| current.status);
    let final_status = if current_status.as_deref() == Some("canceled") {
        "canceled".to_string()
    } else {
        status
    };
    let mut receipt = ComputeReceipt {
        job_id: job_id.clone(),
        status: final_status.clone(),
        node_id: state.status.node_id.clone(),
        exit_code: Some(exit_code),
        stdout_cid: Some(stdout_receipt.cid),
        stderr_cid: Some(stderr_receipt.cid),
        output_root_cid: output_root_cid.clone(),
        started_at_unix_seconds: job.started_at_unix_seconds.unwrap_or(finished_at),
        finished_at_unix_seconds: finished_at,
        signature_hex: String::new(),
    };
    let receipt_payload = serde_json::to_vec(&receipt).map_err(ApiError::serde)?;
    receipt.signature_hex = hex::encode(state.identity.sign(&receipt_payload));

    job.status = final_status;
    if job.status == "canceled" {
        job.guest_exited_after_cancel = true;
    }
    job.finished_at_unix_seconds = Some(finished_at);
    job.exit_code = Some(exit_code);
    job.stdout_cid = receipt.stdout_cid.clone();
    job.stderr_cid = receipt.stderr_cid.clone();
    job.output_root_cid = output_root_cid;
    job.receipt = Some(receipt);
    merge_current_attempt_events(&state, &mut job)?;
    if exit_code != 0 && job.status != "canceled" {
        job.firecracker_error_class = Some("job_failure".to_string());
        job.error = Some(format!("firecracker process exited with {exit_code}"));
    }
    persist_job(&state, &job)?;
    cleanup_firecracker_temp(
        &root_dir,
        &input_dir,
        &rootfs,
        Some(&inputfs),
        Some(&outputfs),
        Some(&vsock_path),
        &config_path,
    );
    Ok(())
}

const FIRECRACKER_CONTROL_PORT: u32 = 1024;
const FIRECRACKER_CONTROL_PROTOCOL_VERSION: u32 = 1;

fn firecracker_guest_init_script() -> &'static [u8] {
    br#"#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /pepper_inputs /pepper_runtime
if ! mount -o ro /dev/vdb /pepper_inputs 2>/dev/null; then
  echo "failed to mount input disk" >&2
  poweroff -f
fi
if ! mount /dev/vdc /pepper_runtime 2>/dev/null; then
  echo "failed to mount runtime output disk" >&2
  poweroff -f
fi
mkdir -p /pepper_runtime/output
[ -f /pepper_mounts.sh ] && /bin/sh /pepper_mounts.sh || true
export PEPPER_INPUT=/pepper_inputs
export PEPPER_OUTPUT=/pepper_runtime/output
export PEPPER_VSOCK_PORT=1024
job_id_arg=
if [ -f /pepper_job_id ]; then
  job_id_arg="--job-id $(cat /pepper_job_id)"
fi
/pepper-guest-agent --port 1024 --cancel-file /pepper_runtime/pepper_cancel --status-file /pepper_runtime/pepper_status --progress-file /pepper_runtime/pepper_progress --stdout-file /pepper_runtime/fc_stdout --stderr-file /pepper_runtime/fc_stderr $job_id_arg >/pepper_runtime/pepper_agent_stdout 2>/pepper_runtime/pepper_agent_stderr &
guest_agent_pid=$!
echo job_started > /pepper_runtime/pepper_status
( /bin/sh /job.sh > /pepper_runtime/fc_stdout 2> /pepper_runtime/fc_stderr ) &
job_pid=$!
trap 'kill -TERM $job_pid 2>/dev/null || true; kill -TERM $guest_agent_pid 2>/dev/null || true; echo 130 > /pepper_runtime/exit_code; echo cancel_completed > /pepper_runtime/pepper_status; sync; poweroff -f' INT TERM
while kill -0 $job_pid 2>/dev/null; do
  if [ -f /pepper_runtime/pepper_cancel ]; then
    kill -TERM $job_pid 2>/dev/null || true
    sleep 1
    kill -KILL $job_pid 2>/dev/null || true
    wait $job_pid 2>/dev/null || true
    kill -TERM $guest_agent_pid 2>/dev/null || true
    echo 130 > /pepper_runtime/exit_code
    echo cancel_completed > /pepper_runtime/pepper_status
    sync
    poweroff -f
  fi
  sleep 1
done
wait $job_pid
code=$?
echo $code > /pepper_runtime/exit_code
if [ "$code" = "0" ]; then echo job_exited:succeeded > /pepper_runtime/pepper_status; else echo job_exited:failed > /pepper_runtime/pepper_status; fi
kill -TERM $guest_agent_pid 2>/dev/null || true
sync
poweroff -f
reboot -f
"#
}

fn write_firecracker_mount_script(
    root_dir: &FsPath,
    inputs: &[pepper_types::ComputeInput],
) -> Result<(), ApiError> {
    let mut script = String::from("#!/bin/sh\nmkdir -p /pepper_inputs /output\n");
    for input in inputs {
        let guest_mount = guest_safe_path(&input.mount)?;
        let input_path = guest_safe_path(&format!(
            "pepper_inputs/{}",
            input.mount.trim_start_matches('/')
        ))?;
        if let Some(parent) = FsPath::new(&guest_mount).parent()
            && parent != FsPath::new("")
        {
            script.push_str(&format!(
                "mkdir -p {}\n",
                shell_quote(&parent.display().to_string())
            ));
        }
        script.push_str(&format!(
            "rm -rf {} 2>/dev/null || true\nln -s {} {} 2>/dev/null || true\n",
            shell_quote(&guest_mount),
            shell_quote(&input_path),
            shell_quote(&guest_mount)
        ));
    }
    write_executable(&root_dir.join("pepper_mounts.sh"), script.as_bytes())
}

fn guest_safe_path(path: &str) -> Result<String, ApiError> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty()
        || trimmed
            .split('/')
            .any(|part| part.is_empty() || part == "..")
    {
        return Err(ApiError::bad_request(
            "guest path must be relative and must not contain ..",
        ));
    }
    Ok(format!("/{trimmed}"))
}

#[derive(Debug, Clone)]
struct FirecrackerCancelOutcome {
    delivered: bool,
    acknowledged: bool,
    response: Option<String>,
}

impl FirecrackerCancelOutcome {
    fn description(&self) -> String {
        match (self.delivered, self.acknowledged, self.response.as_deref()) {
            (true, true, Some(response)) => {
                format!("firecracker cancel delivered and acknowledged over vsock: {response}; VM termination fallback scheduled if still running")
            }
            (true, true, None) => "firecracker cancel delivered and acknowledged over vsock; VM termination fallback scheduled if still running".to_string(),
            (true, false, _) => "firecracker cancel delivered over vsock without acknowledgement; VM termination fallback scheduled if still running".to_string(),
            _ => "firecracker cancel requested; VM termination fallback scheduled".to_string(),
        }
    }

    fn events(&self) -> Vec<String> {
        let mut events = Vec::new();
        if self.delivered {
            events.push("cancel_delivered".to_string());
        }
        if self.acknowledged {
            events.push("cancel_acknowledged".to_string());
        }
        if let Some(response) = &self.response {
            events.push(format!("cancel_response:{response}"));
        }
        events
    }
}

fn spawn_firecracker_control_stream(
    state: AppState,
    job_id: String,
    vsock_path: PathBuf,
    work_dir: PathBuf,
    timeout: Duration,
) -> AbortHandle {
    tokio::spawn(async move {
        let deadline = time::Instant::now() + timeout;
        let mut stdout_offset = 0usize;
        let mut stderr_offset = 0usize;
        while time::Instant::now() < deadline {
            let should_continue = load_job(&state, &job_id)
                .ok()
                .flatten()
                .is_some_and(|job| job.status == "running");
            if !should_continue {
                break;
            }
            let stream_state = state.clone();
            let stream_job_id = job_id.clone();
            let stream_work_dir = work_dir.clone();
            let stream_vsock_path = vsock_path.clone();
            let stream_result = tokio::task::spawn_blocking(move || {
                firecracker_stream_session(
                    &stream_state,
                    &stream_job_id,
                    &stream_vsock_path,
                    &stream_work_dir,
                )
            })
            .await;
            match stream_result {
                Ok(Ok(())) => break,
                Ok(Err(error)) => {
                    warn!(?error, job_id = %job_id, "firecracker long-lived vsock stream failed; falling back to one-shot polling");
                }
                Err(error) => warn!(?error, job_id = %job_id, "firecracker stream task failed"),
            }
            time::sleep(Duration::from_secs(1)).await;
            if let Ok(Some(status)) = firecracker_status_request(&job_id, &vsock_path).await {
                FIRECRACKER_HEARTBEATS.fetch_add(1, Ordering::Relaxed);
                let _ = append_attempt_event_by_job_id(
                    &state,
                    &job_id,
                    format!("guest_status:{status}"),
                );
            }
            match firecracker_logs_request(
                &job_id,
                &vsock_path,
                stdout_offset,
                stderr_offset,
            )
            .await
            {
                Ok(Some(logs)) => {
                    stdout_offset = logs.stdout_offset;
                    stderr_offset = logs.stderr_offset;
                    if !logs.stdout.is_empty() {
                        let _ = append_file(&work_dir.join("vsock_stdout.log"), logs.stdout.as_bytes());
                    }
                    if !logs.stderr.is_empty() {
                        let _ = append_file(&work_dir.join("vsock_stderr.log"), logs.stderr.as_bytes());
                    }
                }
                Ok(None) => {}
                Err(error) => warn!(?error, job_id = %job_id, "firecracker vsock log poll failed"),
            }
        }
    })
    .abort_handle()
}

fn append_file(path: &FsPath, bytes: &[u8]) -> Result<(), ApiError> {
    use std::io::Write;
    const MAX_STREAMED_LOG_BYTES: u64 = 16 * 1024 * 1024;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| ApiError::internal(error.to_string()))?;
    }
    let existing = std::fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    if existing.saturating_add(bytes.len() as u64) > MAX_STREAMED_LOG_BYTES {
        return Err(ApiError::bad_request(
            "streamed guest logs exceed the 16 MiB host limit",
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    file.write_all(bytes)
        .map_err(|error| ApiError::internal(error.to_string()))
}

fn append_attempt_event_by_job_id(
    state: &AppState,
    job_id: &str,
    event: impl Into<String>,
) -> Result<(), ApiError> {
    let mut job = load_job(state, job_id)?.ok_or_else(|| ApiError::not_found("job not found"))?;
    record_attempt_event(&mut job, event);
    persist_job(state, &job)
}

fn merge_current_attempt_events(
    state: &AppState,
    job: &mut ComputeJobStatus,
) -> Result<(), ApiError> {
    let Some(current) = load_job(state, &job.job_id)? else {
        return Ok(());
    };
    let Some(current_attempt) = current.attempts.last() else {
        return Ok(());
    };
    let Some(job_attempt) = job.attempts.last_mut() else {
        return Ok(());
    };
    for event in &current_attempt.events {
        if !job_attempt.events.contains(event) {
            job_attempt.events.push(event.clone());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn firecracker_stream_session(
    state: &AppState,
    job_id: &str,
    vsock_path: &FsPath,
    work_dir: &FsPath,
) -> Result<(), ApiError> {
    use std::io::{BufRead, BufReader, Read, Write};
    let mut socket = firecracker_vsock_connect(vsock_path, FIRECRACKER_CONTROL_PORT)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let payload = serde_json::json!({
        "protocol_version": FIRECRACKER_CONTROL_PROTOCOL_VERSION,
        "type": "stream",
        "job_id": job_id,
    })
    .to_string()
        + "\n";
    socket
        .write_all(payload.as_bytes())
        .map_err(|error| ApiError::internal(error.to_string()))?;
    socket
        .flush()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    const MAX_CONTROL_LINE_BYTES: u64 = 64 * 1024;
    let mut reader = BufReader::new(socket);
    loop {
        let mut line = String::new();
        let read = reader
            .by_ref()
            .take(MAX_CONTROL_LINE_BYTES + 1)
            .read_line(&mut line)
            .map_err(|error| ApiError::internal(error.to_string()))?;
        if line.len() as u64 > MAX_CONTROL_LINE_BYTES || (read > 0 && !line.ends_with('\n')) {
            return Err(ApiError::bad_request(
                "guest control message exceeds the 64 KiB limit",
            ));
        }
        if read == 0 {
            break;
        }
        handle_firecracker_stream_line(state, job_id, work_dir, line.trim())?;
        let running = load_job(state, job_id)
            .ok()
            .flatten()
            .is_some_and(|job| job.status == "running");
        if !running {
            break;
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn firecracker_stream_session(
    _state: &AppState,
    _job_id: &str,
    _vsock_path: &FsPath,
    _work_dir: &FsPath,
) -> Result<(), ApiError> {
    Err(ApiError::internal(
        "Firecracker vsock control is only supported on Linux",
    ))
}

fn handle_firecracker_stream_line(
    state: &AppState,
    job_id: &str,
    work_dir: &FsPath,
    line: &str,
) -> Result<(), ApiError> {
    if line.is_empty() {
        return Ok(());
    }
    let value: serde_json::Value = serde_json::from_str(line).map_err(ApiError::serde)?;
    match value.get("type").and_then(|value| value.as_str()) {
        Some("status") => {
            FIRECRACKER_HEARTBEATS.fetch_add(1, Ordering::Relaxed);
            let status = value
                .get("status")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            append_attempt_event_by_job_id(state, job_id, format!("guest_status:{status}"))?;
            if let Some(progress) = value.get("progress").and_then(|value| value.as_str())
                && !progress.is_empty()
            {
                append_attempt_event_by_job_id(
                    state,
                    job_id,
                    format!("guest_progress:{progress}"),
                )?;
            }
        }
        Some("log_chunk") => {
            if let Some(stdout) = value.get("stdout").and_then(|value| value.as_str())
                && !stdout.is_empty()
            {
                append_file(&work_dir.join("vsock_stdout.log"), stdout.as_bytes())?;
            }
            if let Some(stderr) = value.get("stderr").and_then(|value| value.as_str())
                && !stderr.is_empty()
            {
                append_file(&work_dir.join("vsock_stderr.log"), stderr.as_bytes())?;
            }
        }
        Some("lifecycle") => {
            if let Some(event) = value.get("event").and_then(|value| value.as_str()) {
                append_attempt_event_by_job_id(state, job_id, format!("guest_lifecycle:{event}"))?;
            }
        }
        Some("error") => {
            if let Some(error) = value.get("error").and_then(|value| value.as_str()) {
                append_attempt_event_by_job_id(state, job_id, format!("guest_error:{error}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct FirecrackerLogPoll {
    stdout: String,
    stderr: String,
    stdout_offset: usize,
    stderr_offset: usize,
}

async fn firecracker_status_request(
    job_id: &str,
    vsock_path: &FsPath,
) -> Result<Option<String>, ApiError> {
    let payload = serde_json::json!({
        "protocol_version": FIRECRACKER_CONTROL_PROTOCOL_VERSION,
        "type": "status",
        "job_id": job_id,
    })
    .to_string()
        + "\n";
    let vsock_path = vsock_path.to_path_buf();
    let task = tokio::task::spawn_blocking(move || {
        firecracker_vsock_request(&vsock_path, FIRECRACKER_CONTROL_PORT, payload.as_bytes())
    });
    match time::timeout(Duration::from_millis(500), task).await {
        Ok(Ok(Ok(response))) => Ok(response),
        Ok(Ok(Err(error))) => Err(ApiError::internal(error.to_string())),
        Ok(Err(error)) => Err(ApiError::internal(error.to_string())),
        Err(_) => Err(ApiError::internal("firecracker vsock status timed out")),
    }
}

async fn firecracker_logs_request(
    job_id: &str,
    vsock_path: &FsPath,
    stdout_offset: usize,
    stderr_offset: usize,
) -> Result<Option<FirecrackerLogPoll>, ApiError> {
    let payload = serde_json::json!({
        "protocol_version": FIRECRACKER_CONTROL_PROTOCOL_VERSION,
        "type": "logs",
        "job_id": job_id,
        "stdout_offset": stdout_offset,
        "stderr_offset": stderr_offset,
    })
    .to_string()
        + "\n";
    let vsock_path = vsock_path.to_path_buf();
    let task = tokio::task::spawn_blocking(move || {
        firecracker_vsock_request(&vsock_path, FIRECRACKER_CONTROL_PORT, payload.as_bytes())
    });
    let response = match time::timeout(Duration::from_millis(500), task).await {
        Ok(Ok(Ok(response))) => response,
        Ok(Ok(Err(error))) => return Err(ApiError::internal(error.to_string())),
        Ok(Err(error)) => return Err(ApiError::internal(error.to_string())),
        Err(_) => return Err(ApiError::internal("firecracker vsock logs timed out")),
    };
    let Some(response) = response else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_str(&response).map_err(ApiError::serde)?;
    Ok(Some(FirecrackerLogPoll {
        stdout: value
            .get("stdout")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        stderr: value
            .get("stderr")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        stdout_offset: value
            .get("stdout_offset")
            .and_then(|value| value.as_u64())
            .unwrap_or(stdout_offset as u64) as usize,
        stderr_offset: value
            .get("stderr_offset")
            .and_then(|value| value.as_u64())
            .unwrap_or(stderr_offset as u64) as usize,
    }))
}

async fn send_firecracker_cancel(
    state: &AppState,
    job: &ComputeJobStatus,
) -> Result<FirecrackerCancelOutcome, ApiError> {
    let configured_vsock_path = state.compute_work_dir.join(&job.job_id).join("vsock.sock");
    let vsock_path = firecracker_host_vsock_path(state, &job.job_id, &configured_vsock_path);
    let payload = serde_json::json!({
        "protocol_version": FIRECRACKER_CONTROL_PROTOCOL_VERSION,
        "type": "cancel",
        "job_id": job.job_id,
    })
    .to_string()
        + "\n";
    let task = tokio::task::spawn_blocking(move || {
        firecracker_vsock_request(&vsock_path, FIRECRACKER_CONTROL_PORT, payload.as_bytes())
    });
    match time::timeout(Duration::from_millis(750), task).await {
        Ok(Ok(Ok(response))) => {
            FIRECRACKER_VSOCK_CANCEL_DELIVERED.fetch_add(1, Ordering::Relaxed);
            let acknowledged = response
                .as_deref()
                .is_some_and(|response| response.contains("cancel_ack"));
            if acknowledged {
                FIRECRACKER_VSOCK_CANCEL_ACKS.fetch_add(1, Ordering::Relaxed);
            }
            Ok(FirecrackerCancelOutcome {
                delivered: true,
                acknowledged,
                response,
            })
        }
        Ok(Ok(Err(error))) => {
            FIRECRACKER_VSOCK_CANCEL_FALLBACKS.fetch_add(1, Ordering::Relaxed);
            Err(ApiError::internal(error.to_string()))
        }
        Ok(Err(error)) => {
            FIRECRACKER_VSOCK_CANCEL_FALLBACKS.fetch_add(1, Ordering::Relaxed);
            Err(ApiError::internal(error.to_string()))
        }
        Err(_) => {
            FIRECRACKER_VSOCK_CANCEL_FALLBACKS.fetch_add(1, Ordering::Relaxed);
            Err(ApiError::internal("firecracker vsock cancel timed out"))
        }
    }
}

struct FirecrackerGuestCidGuard {
    cid: u32,
    active: Arc<Mutex<HashMap<u32, String>>>,
}

impl Drop for FirecrackerGuestCidGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock()
            && active.get(&self.cid).is_some()
        {
            active.remove(&self.cid);
        }
    }
}

fn allocate_firecracker_guest_cid(
    state: &AppState,
    job_id: &str,
) -> Result<FirecrackerGuestCidGuard, ApiError> {
    const CID_RANGE: u32 = 2_000_000_000;
    let digest = blake3::hash(job_id.as_bytes());
    let mut prefix = [0u8; 4];
    prefix.copy_from_slice(&digest.as_bytes()[0..4]);
    let mut candidate = 3 + (u32::from_le_bytes(prefix) % CID_RANGE);
    let mut active = state
        .active_guest_cids
        .lock()
        .map_err(|_| ApiError::internal("guest CID allocator lock poisoned"))?;
    for _ in 0..=state.compute_queue_limit {
        if let std::collections::hash_map::Entry::Vacant(entry) = active.entry(candidate) {
            entry.insert(job_id.to_string());
            return Ok(FirecrackerGuestCidGuard {
                cid: candidate,
                active: state.active_guest_cids.clone(),
            });
        }
        candidate = 3 + ((candidate - 2) % CID_RANGE);
    }
    Err(ApiError::internal(
        "could not allocate a unique Firecracker guest CID",
    ))
}

trait FirecrackerControlStream: std::io::Read + std::io::Write + Send {}
impl<T: std::io::Read + std::io::Write + Send> FirecrackerControlStream for T {}

#[cfg(target_os = "linux")]
fn firecracker_vsock_connect(
    path: &FsPath,
    port: u32,
) -> std::io::Result<Box<dyn FirecrackerControlStream>> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    stream.write_all(format!("CONNECT {port}\n").as_bytes())?;
    stream.flush()?;
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while response.len() <= 64 {
        let read = stream.read(&mut byte)?;
        if read == 0 {
            break;
        }
        response.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    let response = String::from_utf8_lossy(&response);
    if !response.starts_with("OK ") {
        return Err(std::io::Error::other(format!(
            "Firecracker vsock CONNECT failed: {}",
            response.trim()
        )));
    }
    Ok(Box::new(stream))
}

#[cfg(not(target_os = "linux"))]
fn firecracker_vsock_connect(
    _path: &FsPath,
    _port: u32,
) -> std::io::Result<Box<dyn FirecrackerControlStream>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Firecracker vsock control requires Linux",
    ))
}

fn firecracker_vsock_request(
    path: &FsPath,
    port: u32,
    payload: &[u8],
) -> std::io::Result<Option<String>> {
    use std::io::{Read, Write};
    const MAX_RESPONSE_BYTES: usize = 64 * 1024;
    let mut stream = firecracker_vsock_connect(path, port)?;
    stream.write_all(payload)?;
    stream.flush()?;
    let mut response = Vec::new();
    let mut buffer = [0u8; 1024];
    while response.len() <= MAX_RESPONSE_BYTES {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                response.extend_from_slice(&buffer[..read]);
                if response.contains(&b'\n') {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => return Err(error),
        }
    }
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(std::io::Error::other(
            "Firecracker guest response exceeds 64 KiB",
        ));
    }
    if response.is_empty() {
        Ok(None)
    } else {
        Ok(Some(String::from_utf8_lossy(&response).trim().to_string()))
    }
}

async fn rootfs_image_bytes(state: &AppState, cid: &Cid) -> Result<Vec<u8>, ApiError> {
    match cid.codec {
        CODEC_RAW => Ok(get_block_resolved(state, cid).await?.payload),
        CODEC_OBJECT_MANIFEST | CODEC_ERASURE_MANIFEST => object_bytes(state, cid).await,
        _ => Err(ApiError::bad_request(
            "firecracker rootfs_cid must be raw, object, or erasure object data",
        )),
    }
}

struct FirecrackerRuntimePaths<'a> {
    rootfs: &'a FsPath,
    inputfs: &'a FsPath,
    outputfs: &'a FsPath,
    vsock_path: &'a FsPath,
    kernel: &'a FsPath,
    config_path: &'a FsPath,
}

fn prepare_firecracker_command(
    state: &AppState,
    job_id: &str,
    paths: &FirecrackerRuntimePaths<'_>,
) -> Result<TokioCommand, ApiError> {
    if state.firecracker_enable_jailer {
        if let Err(error) = prepare_firecracker_jail(state, job_id, paths) {
            FIRECRACKER_JAILER_SETUP_FAILURES.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
        let mut command = TokioCommand::new(&state.firecracker_jailer_binary);
        command
            .kill_on_drop(true)
            .arg("--id")
            .arg(safe_jailer_id(job_id))
            .arg("--exec-file")
            .arg(&state.firecracker_binary)
            .arg("--uid")
            .arg(state.firecracker_jailer_uid.to_string())
            .arg("--gid")
            .arg(state.firecracker_jailer_gid.to_string())
            .arg("--chroot-base-dir")
            .arg(&state.firecracker_jailer_chroot_base)
            .arg("--")
            .arg("--no-api")
            .arg("--config-file")
            .arg("/firecracker.json");
        if state.firecracker_strict_sandbox {
            command.arg("--seccomp-level").arg("2");
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        configure_sandbox_process(&mut command);
        return Ok(command);
    }

    let mut command = TokioCommand::new(&state.firecracker_binary);
    command
        .kill_on_drop(true)
        .arg("--no-api")
        .arg("--config-file")
        .arg(paths.config_path);
    if state.firecracker_strict_sandbox {
        command.arg("--seccomp-level").arg("2");
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    configure_sandbox_process(&mut command);
    Ok(command)
}

fn prepare_firecracker_jail(
    state: &AppState,
    job_id: &str,
    paths: &FirecrackerRuntimePaths<'_>,
) -> Result<(), ApiError> {
    let jail_instance = firecracker_jail_instance_root(state, job_id);
    let jail_root = firecracker_jail_root(state, job_id);
    validate_or_create_jailer_base(state)?;
    if jail_instance.exists() {
        return Err(ApiError::internal(format!(
            "firecracker jail directory already exists: {}",
            jail_instance.display()
        )));
    }
    std::fs::create_dir(&jail_instance).map_err(|error| ApiError::internal(error.to_string()))?;
    std::fs::create_dir(&jail_root).map_err(|error| ApiError::internal(error.to_string()))?;
    std::fs::copy(paths.rootfs, jail_root.join("rootfs.ext4"))
        .map_err(|error| ApiError::internal(error.to_string()))?;
    std::fs::copy(paths.inputfs, jail_root.join("inputs.ext4"))
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let jailed_output = jail_root.join("outputs.ext4");
    std::fs::copy(paths.outputfs, &jailed_output)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    set_path_owner(
        &jail_root,
        state.firecracker_jailer_uid,
        state.firecracker_jailer_gid,
    )?;
    set_path_owner(
        &jailed_output,
        state.firecracker_jailer_uid,
        state.firecracker_jailer_gid,
    )?;
    let _ = std::fs::remove_file(jail_root.join("vsock.sock"));
    if let Some(parent) = paths.vsock_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| ApiError::internal(error.to_string()))?;
    }
    std::fs::copy(paths.kernel, jail_root.join("vmlinux"))
        .map_err(|error| ApiError::internal(error.to_string()))?;
    std::fs::copy(paths.config_path, jail_root.join("firecracker.json"))
        .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok(())
}

#[cfg(unix)]
fn set_path_owner(path: &FsPath, uid: u32, gid: u32) -> Result<(), ApiError> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| ApiError::internal("path contains a NUL byte"))?;
    if unsafe { chown(path.as_ptr(), uid, gid) } != 0 {
        return Err(ApiError::internal(format!(
            "failed to set jail ownership: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_path_owner(_path: &FsPath, _uid: u32, _gid: u32) -> Result<(), ApiError> {
    Err(ApiError::internal("Firecracker jailer requires Unix"))
}

fn validate_or_create_jailer_base(state: &AppState) -> Result<(), ApiError> {
    let base = state.firecracker_jailer_chroot_base.join("firecracker");
    std::fs::create_dir_all(&base).map_err(|error| ApiError::internal(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata =
            std::fs::metadata(&base).map_err(|error| ApiError::internal(error.to_string()))?;
        if metadata.mode() & 0o002 != 0 {
            return Err(ApiError::internal(format!(
                "firecracker jailer base {} must not be world-writable",
                base.display()
            )));
        }
    }
    Ok(())
}

fn firecracker_jail_instance_root(state: &AppState, job_id: &str) -> PathBuf {
    state
        .firecracker_jailer_chroot_base
        .join("firecracker")
        .join(safe_jailer_id(job_id))
}

fn firecracker_jail_root(state: &AppState, job_id: &str) -> PathBuf {
    firecracker_jail_instance_root(state, job_id).join("root")
}

fn firecracker_runtime_outputfs(state: &AppState, job_id: &str, outputfs: &FsPath) -> PathBuf {
    if state.firecracker_enable_jailer {
        firecracker_jail_root(state, job_id).join("outputs.ext4")
    } else {
        outputfs.to_path_buf()
    }
}

fn firecracker_host_vsock_path(
    state: &AppState,
    job_id: &str,
    configured_path: &FsPath,
) -> PathBuf {
    if state.firecracker_enable_jailer {
        firecracker_jail_root(state, job_id).join("vsock.sock")
    } else {
        configured_path.to_path_buf()
    }
}

fn safe_jailer_id(job_id: &str) -> String {
    job_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .take(64)
        .collect::<String>()
}

struct FirecrackerCgroupGuard {
    path: Option<PathBuf>,
}

impl Drop for FirecrackerCgroupGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = std::fs::remove_dir(path);
        }
    }
}

fn apply_firecracker_cgroup(
    state: &AppState,
    job: &ComputeJobStatus,
    pid: Option<u32>,
) -> Result<FirecrackerCgroupGuard, ApiError> {
    let Some(pid) = pid else {
        return Ok(FirecrackerCgroupGuard { path: None });
    };
    if !state.firecracker_cgroup_enabled {
        return Ok(FirecrackerCgroupGuard { path: None });
    }
    let base = &state.firecracker_cgroup_base;
    if let Some(parent) = base.parent()
        && !parent.exists()
    {
        return Err(ApiError::internal(format!(
            "cgroup enforcement is enabled but parent {} is unavailable",
            parent.display()
        )));
    }
    std::fs::create_dir_all(base).map_err(|error| ApiError::internal(error.to_string()))?;
    let cgroup_path = base.join(safe_jailer_id(&job.job_id));
    if cgroup_path.exists() {
        let _ = std::fs::remove_dir(&cgroup_path);
    }
    std::fs::create_dir(&cgroup_path).map_err(|error| ApiError::internal(error.to_string()))?;
    let memory_mib = job
        .spec
        .resources
        .as_ref()
        .and_then(|resources| resources.memory_mib)
        .unwrap_or(state.firecracker_memory_mib as u64)
        .saturating_add(128);
    let memory_bytes = memory_mib.saturating_mul(1024 * 1024);
    std::fs::write(cgroup_path.join("memory.max"), memory_bytes.to_string()).map_err(|error| {
        ApiError::internal(format!("failed to enforce cgroup memory.max: {error}"))
    })?;
    if let Some(cpu_millis) = job
        .spec
        .resources
        .as_ref()
        .and_then(|resources| resources.cpu_millis)
    {
        let quota = cpu_millis.max(1).saturating_mul(100);
        std::fs::write(cgroup_path.join("cpu.max"), format!("{quota} 100000")).map_err(
            |error| ApiError::internal(format!("failed to enforce cgroup cpu.max: {error}")),
        )?;
    }
    std::fs::write(cgroup_path.join("cgroup.procs"), pid.to_string())
        .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok(FirecrackerCgroupGuard {
        path: Some(cgroup_path),
    })
}

struct ProcessGroupGuard {
    pid: Option<u32>,
    active: bool,
}

impl ProcessGroupGuard {
    fn new(pid: Option<u32>) -> Self {
        Self { pid, active: true }
    }

    fn disarm(&mut self) {
        self.active = false;
    }

    fn terminate(&mut self) {
        #[cfg(unix)]
        if self.active
            && let Some(pid) = self.pid
        {
            kill_process_group(pid);
        }
        self.active = false;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.active
            && let Some(pid) = self.pid
        {
            kill_process_group(pid);
        }
    }
}

#[cfg(unix)]
fn configure_sandbox_process(command: &mut TokioCommand) {
    unsafe {
        command.pre_exec(|| {
            if set_process_group() != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if set_no_new_privs() != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_sandbox_process(_command: &mut TokioCommand) {}

#[cfg(unix)]
fn set_process_group() -> i32 {
    unsafe { setpgid(0, 0) }
}

#[cfg(unix)]
fn set_no_new_privs() -> i32 {
    unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }
}

#[cfg(unix)]
fn kill_process_group(pid: u32) {
    unsafe {
        let _ = kill(-(pid as i32), SIGKILL);
    }
}

#[cfg(unix)]
const SIGKILL: i32 = 9;

#[cfg(unix)]
const PR_SET_NO_NEW_PRIVS: i32 = 38;

#[cfg(unix)]
unsafe extern "C" {
    fn setpgid(pid: i32, pgid: i32) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> i32;
    fn chown(path: *const std::ffi::c_char, owner: u32, group: u32) -> i32;
}

struct FirecrackerCleanupGuard {
    work_dir: PathBuf,
    root_dir: PathBuf,
    input_dir: PathBuf,
    rootfs: PathBuf,
    inputfs: Option<PathBuf>,
    outputfs: Option<PathBuf>,
    vsock_path: Option<PathBuf>,
    config_path: PathBuf,
    jail_dir: Option<PathBuf>,
}

impl Drop for FirecrackerCleanupGuard {
    fn drop(&mut self) {
        cleanup_firecracker_temp(
            &self.root_dir,
            &self.input_dir,
            &self.rootfs,
            self.inputfs.as_deref(),
            self.outputfs.as_deref(),
            self.vsock_path.as_deref(),
            &self.config_path,
        );
        if let Some(jail_dir) = &self.jail_dir {
            let _ = std::fs::remove_dir_all(jail_dir);
        }
        let _ = std::fs::remove_dir_all(&self.work_dir);
    }
}

fn cleanup_firecracker_temp(
    root_dir: &FsPath,
    input_dir: &FsPath,
    rootfs: &FsPath,
    inputfs: Option<&FsPath>,
    outputfs: Option<&FsPath>,
    vsock_path: Option<&FsPath>,
    config_path: &FsPath,
) {
    let _ = std::fs::remove_dir_all(root_dir);
    let _ = std::fs::remove_dir_all(input_dir);
    let _ = std::fs::remove_file(rootfs);
    if let Some(inputfs) = inputfs {
        let _ = std::fs::remove_file(inputfs);
    }
    if let Some(outputfs) = outputfs {
        let _ = std::fs::remove_file(outputfs);
    }
    if let Some(vsock_path) = vsock_path {
        let _ = std::fs::remove_file(vsock_path);
    }
    for suffix in ["fc_stdout", "fc_stderr", "exit_code"] {
        let _ = std::fs::remove_file(rootfs.with_extension(format!("dump-{suffix}")));
        if let Some(outputfs) = outputfs {
            let _ = std::fs::remove_file(outputfs.with_extension(format!("dump-{suffix}")));
        }
    }
    let _ = std::fs::remove_file(config_path);
}

fn ensure_firecracker_available(state: &AppState) -> Result<(), ApiError> {
    if !state.firecracker_binary.exists() {
        return Err(ApiError::bad_request(format!(
            "firecracker binary not found at {}",
            state.firecracker_binary.display()
        )));
    }
    if state.firecracker_enable_jailer && !state.firecracker_jailer_binary.exists() {
        return Err(ApiError::bad_request(format!(
            "firecracker jailer binary not found at {}",
            state.firecracker_jailer_binary.display()
        )));
    }
    if std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_err()
    {
        return Err(ApiError::bad_request(
            "/dev/kvm is not available or not accessible",
        ));
    }
    let kernel = state
        .firecracker_kernel_image
        .clone()
        .unwrap_or_else(default_firecracker_kernel_image);
    if std::fs::File::open(&kernel).is_err() {
        return Err(ApiError::bad_request(format!(
            "firecracker kernel image is not readable at {}",
            kernel.display()
        )));
    }
    if state.firecracker_strict_sandbox && !state.firecracker_enable_jailer {
        warn!(
            "Firecracker strict sandbox requested without jailer; enforcing no network, no API, process-group cleanup, and seccomp level 2 only"
        );
    }
    Ok(())
}

fn default_firecracker_kernel_image() -> PathBuf {
    std::env::var_os("PEPPER_FIRECRACKER_KERNEL_IMAGE")
        .map(PathBuf::from)
        .or_else(|| {
            [
                "/boot/vmlinux",
                "/boot/vmlinuz",
                "/usr/share/firecracker/vmlinux",
            ]
            .iter()
            .map(PathBuf::from)
            .find(|path| std::fs::File::open(path).is_ok())
        })
        .unwrap_or_else(|| PathBuf::from("/boot/vmlinux"))
}

fn write_executable(path: &FsPath, bytes: &[u8]) -> Result<(), ApiError> {
    write_bytes(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(path)
            .map_err(|error| ApiError::internal(error.to_string()))?
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions)
            .map_err(|error| ApiError::internal(error.to_string()))?;
    }
    Ok(())
}

fn enforce_firecracker_input_limit(
    state: &AppState,
    job: &ComputeJobStatus,
    input_dir: &FsPath,
) -> Result<(), ApiError> {
    let limit = job
        .spec
        .resources
        .as_ref()
        .and_then(|resources| resources.max_input_bytes)
        .unwrap_or(state.firecracker_max_input_bytes);
    let size = directory_size_bytes(input_dir)?;
    if size > limit {
        return Err(ApiError::bad_request(format!(
            "firecracker input size {size} exceeds limit {limit}"
        )));
    }
    Ok(())
}

fn firecracker_output_limit(state: &AppState, job: &ComputeJobStatus) -> u64 {
    job.spec
        .resources
        .as_ref()
        .and_then(|resources| resources.max_output_bytes)
        .unwrap_or(state.firecracker_max_output_bytes)
}

fn enforce_firecracker_output_limit(
    state: &AppState,
    job: &ComputeJobStatus,
    output_dir: &FsPath,
) -> Result<(), ApiError> {
    let limit = firecracker_output_limit(state, job);
    let size = directory_size_bytes(output_dir)?;
    if size > limit {
        return Err(ApiError::bad_request(format!(
            "firecracker output size {size} exceeds limit {limit}"
        )));
    }
    Ok(())
}

fn create_ext4_rootfs(root: &FsPath, image: &FsPath) -> Result<(), ApiError> {
    let content_bytes = directory_size_bytes(root)?;
    let image_mib = std::cmp::max(
        128,
        content_bytes
            .div_ceil(1024 * 1024)
            .saturating_mul(2)
            .saturating_add(64),
    );
    let status = std::process::Command::new("mkfs.ext4")
        .arg("-q")
        .arg("-d")
        .arg(root)
        .arg(image)
        .arg(format!("{image_mib}M"))
        .status()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    if !status.success() {
        return Err(ApiError::internal("mkfs.ext4 failed"));
    }
    Ok(())
}

fn create_empty_ext4_image(image: &FsPath, requested_bytes: u64) -> Result<(), ApiError> {
    let image_mib = std::cmp::max(64, requested_bytes.div_ceil(1024 * 1024).saturating_add(16));
    let file =
        std::fs::File::create(image).map_err(|error| ApiError::internal(error.to_string()))?;
    file.set_len(image_mib.saturating_mul(1024 * 1024))
        .map_err(|error| ApiError::internal(error.to_string()))?;
    drop(file);
    let status = std::process::Command::new("mkfs.ext4")
        .arg("-q")
        .arg("-F")
        .arg(image)
        .status()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    if !status.success() {
        return Err(ApiError::internal("mkfs.ext4 failed"));
    }
    Ok(())
}

fn directory_size_bytes(root: &FsPath) -> Result<u64, ApiError> {
    let mut total = 0u64;
    let mut stack = VecDeque::from([root.to_path_buf()]);
    while let Some(path) = stack.pop_front() {
        for entry in
            std::fs::read_dir(&path).map_err(|error| ApiError::internal(error.to_string()))?
        {
            let entry = entry.map_err(|error| ApiError::internal(error.to_string()))?;
            let metadata = entry
                .path()
                .symlink_metadata()
                .map_err(|error| ApiError::internal(error.to_string()))?;
            if metadata.file_type().is_symlink() {
                return Err(ApiError::bad_request(
                    "filesystem trees must not contain symlinks",
                ));
            }
            if metadata.is_dir() {
                stack.push_back(entry.path());
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            } else {
                return Err(ApiError::bad_request(
                    "filesystem trees must contain only regular files and directories",
                ));
            }
        }
    }
    Ok(total)
}

fn validate_firecracker_rootfs_image(image: &FsPath) -> Result<(), ApiError> {
    let required_commands = [
        "sh", "mount", "mkdir", "ln", "rm", "kill", "sleep", "sync", "poweroff",
    ];
    for command in required_commands {
        if !debugfs_command_exists(image, command) {
            return Err(ApiError::bad_request(format!(
                "firecracker rootfs image is missing required guest command '{command}' in /bin, /sbin, /usr/bin, or /usr/sbin"
            )));
        }
    }
    if !debugfs_path_exists(image, "/pepper-guest-agent") {
        return Err(ApiError::bad_request(
            "firecracker rootfs image must contain /pepper-guest-agent for the vsock control plane",
        ));
    }
    if !debugfs_path_is_executable(image, "/pepper-guest-agent") {
        return Err(ApiError::bad_request(
            "firecracker rootfs /pepper-guest-agent must be executable",
        ));
    }
    Ok(())
}

fn debugfs_command_exists(image: &FsPath, command: &str) -> bool {
    ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
        .iter()
        .any(|dir| debugfs_path_is_executable(image, &format!("{dir}/{command}")))
}

fn debugfs_path_exists(image: &FsPath, path: &str) -> bool {
    debugfs_stat(image, path).is_some()
}

fn debugfs_path_is_executable(image: &FsPath, path: &str) -> bool {
    let Some(stat) = debugfs_stat(image, path) else {
        return false;
    };
    [
        "0755", "0775", "0777", "0555", "0700", "0711", "0750", "0511",
    ]
    .iter()
    .any(|mode| stat.contains(mode))
}

fn debugfs_stat(image: &FsPath, path: &str) -> Option<String> {
    let output = std::process::Command::new("debugfs")
        .arg("-R")
        .arg(format!("stat {path}"))
        .arg(image)
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}

fn debugfs_dump(image: &FsPath, source: &str, max_bytes: u64) -> Result<Vec<u8>, ApiError> {
    let temp = image.with_extension(format!("dump-{}", source.trim_start_matches('/')));
    let status = std::process::Command::new("debugfs")
        .arg("-R")
        .arg(format!(
            "dump {source} {}",
            debugfs_quote(&temp.display().to_string())
        ))
        .arg(image)
        .status()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    if !status.success() {
        return Err(ApiError::internal("debugfs dump failed"));
    }
    let metadata =
        std::fs::metadata(&temp).map_err(|error| ApiError::internal(error.to_string()))?;
    if metadata.len() > max_bytes {
        let _ = std::fs::remove_file(&temp);
        return Err(ApiError::bad_request(format!(
            "debugfs output {source} exceeds limit {max_bytes}"
        )));
    }
    let bytes = std::fs::read(&temp).map_err(|error| ApiError::internal(error.to_string()))?;
    let _ = std::fs::remove_file(&temp);
    Ok(bytes)
}

fn debugfs_rdump(image: &FsPath, source: &str, target: &FsPath) -> Result<(), ApiError> {
    let status = std::process::Command::new("debugfs")
        .arg("-R")
        .arg(format!(
            "rdump {source} {}",
            debugfs_quote(&target.display().to_string())
        ))
        .arg(image)
        .status()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    if !status.success() {
        return Err(ApiError::internal("debugfs rdump failed"));
    }
    Ok(())
}

fn debugfs_runtime_symlinks(image: &FsPath) -> Result<(), ApiError> {
    for (link, target) in [
        ("/output", "/pepper_runtime/output"),
        ("/pepper_progress", "/pepper_runtime/pepper_progress"),
        ("/pepper_status", "/pepper_runtime/pepper_status"),
        ("/pepper_cancel", "/pepper_runtime/pepper_cancel"),
    ] {
        if !debugfs_path_exists(image, link) {
            debugfs_command(image, &format!("symlink {link} {target}"))?;
        }
    }
    Ok(())
}

fn debugfs_write_tree(image: &FsPath, source_root: &FsPath) -> Result<(), ApiError> {
    let mut stack = VecDeque::from([source_root.to_path_buf()]);
    while let Some(path) = stack.pop_front() {
        for entry in
            std::fs::read_dir(&path).map_err(|error| ApiError::internal(error.to_string()))?
        {
            let entry = entry.map_err(|error| ApiError::internal(error.to_string()))?;
            let path = entry.path();
            let relative = path
                .strip_prefix(source_root)
                .map_err(|error| ApiError::internal(error.to_string()))?;
            let guest_path = format!("/{}", relative.display());
            if path.is_dir() {
                let _ = debugfs_command(image, &format!("mkdir {guest_path}"));
                stack.push_back(path);
            } else if path.is_file() {
                if debugfs_path_exists(image, &guest_path) {
                    debugfs_command(image, &format!("rm {guest_path}"))?;
                }
                debugfs_command(
                    image,
                    &format!(
                        "write {} {guest_path}",
                        debugfs_quote(&path.display().to_string())
                    ),
                )?;
                if guest_path == "/init" || guest_path == "/job.sh" {
                    debugfs_command(image, &format!("sif {guest_path} mode 0100755"))?;
                }
            }
        }
    }
    Ok(())
}

fn debugfs_command(image: &FsPath, command: &str) -> Result<(), ApiError> {
    let status = std::process::Command::new("debugfs")
        .arg("-w")
        .arg("-R")
        .arg(command)
        .arg(image)
        .status()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    if !status.success() {
        return Err(ApiError::internal(format!(
            "debugfs command failed: {command}"
        )));
    }
    Ok(())
}

fn debugfs_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('\"', "\\\""))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
async fn logical_cid_size(state: &AppState, root: &Cid) -> Result<u64, ApiError> {
    let mut total = 0u64;
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([root.clone()]);
    while let Some(cid) = queue.pop_front() {
        if !seen.insert(cid.clone()) {
            continue;
        }
        if seen.len() > 100_000 {
            return Err(ApiError::bad_request(
                "compute input DAG exceeds the 100000-block safety limit",
            ));
        }
        match cid.codec {
            CODEC_RAW => {
                let block = get_block_resolved(state, &cid).await?;
                total = total
                    .checked_add(block.size)
                    .ok_or_else(|| ApiError::bad_request("compute input size overflow"))?;
            }
            CODEC_OBJECT_MANIFEST => {
                let block = get_block_resolved(state, &cid).await?;
                let manifest: ObjectManifest =
                    serde_json::from_slice(&block.payload).map_err(ApiError::serde)?;
                validate_object_resource_limits(state, &manifest)?;
                total = total
                    .checked_add(manifest.size)
                    .ok_or_else(|| ApiError::bad_request("compute input size overflow"))?;
            }
            CODEC_ERASURE_MANIFEST => {
                let block = get_block_resolved(state, &cid).await?;
                let manifest: ErasureManifest =
                    serde_json::from_slice(&block.payload).map_err(ApiError::serde)?;
                validate_erasure_resource_limits(state, &manifest)?;
                total = total
                    .checked_add(manifest.size)
                    .ok_or_else(|| ApiError::bad_request("compute input size overflow"))?;
            }
            CODEC_DIR_MANIFEST => {
                let block = get_block_resolved(state, &cid).await?;
                let manifest: DirManifest =
                    serde_json::from_slice(&block.payload).map_err(ApiError::serde)?;
                manifest.validate().map_err(ApiError::manifest)?;
                queue.extend(manifest.entries.into_iter().filter_map(|entry| entry.cid));
            }
            _ => return Err(ApiError::bad_request("unsupported compute input codec")),
        }
    }
    Ok(total)
}

async fn materialize_cid_to_path(
    state: &AppState,
    cid: &Cid,
    path: &FsPath,
) -> Result<(), ApiError> {
    match cid.codec {
        CODEC_DIR_MANIFEST => restore_dir_manifest(state, cid, path).await,
        CODEC_OBJECT_MANIFEST | CODEC_ERASURE_MANIFEST => {
            let bytes = object_bytes(state, cid).await?;
            write_bytes(path, &bytes)
        }
        CODEC_RAW => {
            let block = get_block_resolved(state, cid).await?;
            write_bytes(path, &block.payload)
        }
        _ => Err(ApiError::bad_request("unsupported compute input codec")),
    }
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
    if output_path.is_dir() {
        let manifest = build_dir_manifest_from_path(state, &output_path).await?;
        let bytes = serde_json::to_vec(&manifest).map_err(ApiError::serde)?;
        Ok(Some(
            put_replicated_block(state, CODEC_DIR_MANIFEST, bytes)
                .await?
                .cid,
        ))
    } else if output_path.is_file() {
        let bytes =
            std::fs::read(&output_path).map_err(|error| ApiError::internal(error.to_string()))?;
        Ok(Some(put_object_bytes_internal(state, bytes).await?))
    } else {
        Ok(None)
    }
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
    while let Some(data) = body_stream.next().await {
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

async fn require_http_auth_and_rate_limit(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let _permit = state
        .http_concurrency
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "HTTP concurrency limit exceeded".to_string(),
        })?;
    if let Some(token) = &state.api_bearer_token {
        let expected = format!("Bearer {token}");
        let authorized = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(|value| constant_time_eq(value.as_bytes(), expected.as_bytes()))
            .unwrap_or(false);
        if !authorized {
            return Err(ApiError {
                status: StatusCode::UNAUTHORIZED,
                message: "missing or invalid bearer token".to_string(),
            });
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
        return Err(ApiError {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "HTTP request rate limit exceeded".to_string(),
        });
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

async fn metrics(State(state): State<AppState>) -> Response {
    let uptime_seconds = (OffsetDateTime::now_utc() - state.status.started_at)
        .whole_seconds()
        .max(0);
    let queue_depth = compute_queue_depth(&state).unwrap_or(0);
    let body = format!(
        "# HELP pepper_agent_uptime_seconds Agent uptime in seconds.\n\
         # TYPE pepper_agent_uptime_seconds gauge\n\
         pepper_agent_uptime_seconds {uptime_seconds}\n\
         # HELP pepper_metadata_schema_version Local metadata schema version.\n\
         # TYPE pepper_metadata_schema_version gauge\n\
         pepper_metadata_schema_version {}\n\
         # HELP pepper_compute_queue_depth Queued or delegated compute jobs.\n\
         # TYPE pepper_compute_queue_depth gauge\n\
         pepper_compute_queue_depth {queue_depth}\n\
         # HELP pepper_compute_scheduled_local_total Compute jobs scheduled on this node.\n\
         # TYPE pepper_compute_scheduled_local_total counter\n\
         pepper_compute_scheduled_local_total {}\n\
         # HELP pepper_compute_scheduled_remote_total Compute jobs scheduled on a peer.\n\
         # TYPE pepper_compute_scheduled_remote_total counter\n\
         pepper_compute_scheduled_remote_total {}\n\
         # HELP pepper_compute_schedule_retries_total Failed remote scheduling attempts.\n\
         # TYPE pepper_compute_schedule_retries_total counter\n\
         pepper_compute_schedule_retries_total {}\n\
         # HELP pepper_firecracker_vm_starts_total Firecracker VM starts attempted.\n\
         # TYPE pepper_firecracker_vm_starts_total counter\n\
         pepper_firecracker_vm_starts_total {}\n\
         # HELP pepper_firecracker_vm_successes_total Firecracker VMs that completed successfully.\n\
         # TYPE pepper_firecracker_vm_successes_total counter\n\
         pepper_firecracker_vm_successes_total {}\n\
         # HELP pepper_firecracker_vm_failures_total Firecracker VM failures.\n\
         # TYPE pepper_firecracker_vm_failures_total counter\n\
         pepper_firecracker_vm_failures_total {}\n\
         # HELP pepper_firecracker_rootfs_validation_failures_total Firecracker rootfs validation failures.\n\
         # TYPE pepper_firecracker_rootfs_validation_failures_total counter\n\
         pepper_firecracker_rootfs_validation_failures_total {}\n\
         # HELP pepper_firecracker_vsock_cancel_delivered_total Firecracker cancel requests delivered over vsock.\n\
         # TYPE pepper_firecracker_vsock_cancel_delivered_total counter\n\
         pepper_firecracker_vsock_cancel_delivered_total {}\n\
         # HELP pepper_firecracker_vsock_cancel_acks_total Firecracker cancel acknowledgements received over vsock.\n\
         # TYPE pepper_firecracker_vsock_cancel_acks_total counter\n\
         pepper_firecracker_vsock_cancel_acks_total {}\n\
         # HELP pepper_firecracker_vsock_cancel_fallbacks_total Firecracker cancels that fell back after vsock failure.\n\
         # TYPE pepper_firecracker_vsock_cancel_fallbacks_total counter\n\
         pepper_firecracker_vsock_cancel_fallbacks_total {}\n\
         # HELP pepper_firecracker_jailer_setup_failures_total Firecracker jailer setup failures.\n\
         # TYPE pepper_firecracker_jailer_setup_failures_total counter\n\
         pepper_firecracker_jailer_setup_failures_total {}\n\
         # HELP pepper_firecracker_output_extraction_failures_total Firecracker output extraction failures.\n\
         # TYPE pepper_firecracker_output_extraction_failures_total counter\n\
         pepper_firecracker_output_extraction_failures_total {}\n\
         # HELP pepper_firecracker_heartbeats_total Firecracker guest heartbeat/status responses received.\n\
         # TYPE pepper_firecracker_heartbeats_total counter\n\
         pepper_firecracker_heartbeats_total {}\n\
         # HELP pepper_firecracker_heartbeat_timeouts_total Firecracker heartbeat/job timeout failures.\n\
         # TYPE pepper_firecracker_heartbeat_timeouts_total counter\n\
         pepper_firecracker_heartbeat_timeouts_total {}\n\
         # HELP pepper_erasure_object_writes_total Erasure-coded objects written.\n\
         # TYPE pepper_erasure_object_writes_total counter\n\
         pepper_erasure_object_writes_total {}\n\
         # HELP pepper_erasure_object_reads_total Erasure-coded objects reconstructed for reads.\n\
         # TYPE pepper_erasure_object_reads_total counter\n\
         pepper_erasure_object_reads_total {}\n\
         # HELP pepper_erasure_shard_repairs_total Erasure shards repaired.\n\
         # TYPE pepper_erasure_shard_repairs_total counter\n\
         pepper_erasure_shard_repairs_total {}\n\
         # HELP pepper_erasure_shard_rebalances_total Erasure shards proactively copied to preferred placement targets.\n\
         # TYPE pepper_erasure_shard_rebalances_total counter\n\
         pepper_erasure_shard_rebalances_total {}\n\
         # HELP pepper_erasure_reconstruction_failures_total Erasure reconstruction failures.\n\
         # TYPE pepper_erasure_reconstruction_failures_total counter\n\
         pepper_erasure_reconstruction_failures_total {}\n",
        state.status.schema_version,
        COMPUTE_SCHEDULED_LOCAL.load(Ordering::Relaxed),
        COMPUTE_SCHEDULED_REMOTE.load(Ordering::Relaxed),
        COMPUTE_SCHEDULE_RETRIES.load(Ordering::Relaxed),
        FIRECRACKER_VM_STARTS.load(Ordering::Relaxed),
        FIRECRACKER_VM_SUCCESSES.load(Ordering::Relaxed),
        FIRECRACKER_VM_FAILURES.load(Ordering::Relaxed),
        FIRECRACKER_ROOTFS_VALIDATION_FAILURES.load(Ordering::Relaxed),
        FIRECRACKER_VSOCK_CANCEL_DELIVERED.load(Ordering::Relaxed),
        FIRECRACKER_VSOCK_CANCEL_ACKS.load(Ordering::Relaxed),
        FIRECRACKER_VSOCK_CANCEL_FALLBACKS.load(Ordering::Relaxed),
        FIRECRACKER_JAILER_SETUP_FAILURES.load(Ordering::Relaxed),
        FIRECRACKER_OUTPUT_EXTRACTION_FAILURES.load(Ordering::Relaxed),
        FIRECRACKER_HEARTBEATS.load(Ordering::Relaxed),
        FIRECRACKER_HEARTBEAT_TIMEOUTS.load(Ordering::Relaxed),
        ERASURE_OBJECT_WRITES.load(Ordering::Relaxed),
        ERASURE_OBJECT_READS.load(Ordering::Relaxed),
        ERASURE_SHARD_REPAIRS.load(Ordering::Relaxed),
        ERASURE_SHARD_REBALANCES.load(Ordering::Relaxed),
        ERASURE_RECONSTRUCTION_FAILURES.load(Ordering::Relaxed)
    );
    body.into_response()
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        warn!(%error, "failed to install Ctrl-C shutdown handler");
    }
}

struct AgentBlockService {
    block_store: Arc<BlockStore>,
    operation_lock: Arc<RwLock<()>>,
}

#[async_trait]
impl NetworkBlockService for AgentBlockService {
    async fn has_block(&self, cid: &Cid) -> Result<bool, NetworkError> {
        let _guard = self.operation_lock.read().await;
        tokio::task::block_in_place(|| self.block_store.has(cid))
            .map_err(|error| NetworkError::BlockService(error.to_string()))
    }

    async fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, NetworkError> {
        let _guard = self.operation_lock.read().await;
        tokio::task::block_in_place(|| self.block_store.get(cid))
            .map(|block| block.payload)
            .map_err(|error| NetworkError::BlockService(error.to_string()))
    }

    async fn put_replica(
        &self,
        codec: Codec,
        payload: Vec<u8>,
    ) -> Result<PutBlockResponse, NetworkError> {
        let _guard = self.operation_lock.read().await;
        tokio::task::block_in_place(|| self.block_store.put_replica(codec, &payload))
            .map_err(|error| NetworkError::BlockService(error.to_string()))
    }
}

struct AgentComputeService {
    state: AppState,
}

#[async_trait]
impl NetworkComputeService for AgentComputeService {
    async fn offer(&self, spec_json: String) -> Result<proto::ComputeOfferResponse, NetworkError> {
        let spec: ComputeJobSpec = serde_json::from_str(&spec_json)?;
        let offer = local_compute_offer(&self.state, &spec, None)
            .map_err(|error| NetworkError::BlockService(error.message))?;
        Ok(proto::ComputeOfferResponse {
            accepted: offer.accepted,
            node_id: offer.node_id,
            estimated_queue_delay_seconds: offer.estimated_queue_delay_seconds,
            local_input_bytes: offer.local_input_bytes,
            total_input_bytes: offer.total_input_bytes,
            available_parallelism: offer.available_parallelism,
            rejection_reason: offer.rejection_reason.unwrap_or_default(),
        })
    }

    async fn submit(
        &self,
        job_id: String,
        spec_json: String,
    ) -> Result<proto::ComputeSubmitResponse, NetworkError> {
        validate_job_id(&job_id).map_err(|error| NetworkError::BlockService(error.message))?;
        let spec: ComputeJobSpec = serde_json::from_str(&spec_json)?;
        if let Some(existing) = load_job(&self.state, &job_id)
            .map_err(|error| NetworkError::BlockService(error.message))?
        {
            if existing.spec != spec {
                return Err(NetworkError::Rpc {
                    code: "idempotency_conflict".to_string(),
                    message: "job ID already exists with a different specification".to_string(),
                });
            }
            return Ok(proto::ComputeSubmitResponse {
                job_status_json: serde_json::to_string(&existing)?,
            });
        }
        let offer = local_compute_offer(&self.state, &spec, None)
            .map_err(|error| NetworkError::BlockService(error.message))?;
        if !offer.accepted {
            return Err(NetworkError::Rpc {
                code: "compute_rejected".to_string(),
                message: offer
                    .rejection_reason
                    .unwrap_or_else(|| "compute offer rejected".to_string()),
            });
        }
        let mut job = new_compute_job(
            job_id.clone(),
            spec,
            "queued",
            Some(self.state.status.node_id.clone()),
            None,
        );
        job.attempts.push(ComputeAttempt {
            node_id: self.state.status.node_id.clone(),
            address: None,
            status: "accepted".to_string(),
            error: None,
            started_at_unix_seconds: unix_seconds(),
            finished_at_unix_seconds: None,
            events: Vec::new(),
        });
        persist_job(&self.state, &job)
            .map_err(|error| NetworkError::BlockService(error.message))?;
        if let Err(error) = spawn_compute_job(self.state.clone(), job_id) {
            job.status = "failed".to_string();
            job.finished_at_unix_seconds = Some(unix_seconds());
            job.error = Some(error.message.clone());
            let _ = persist_job(&self.state, &job);
            return Err(NetworkError::BlockService(error.message));
        }
        Ok(proto::ComputeSubmitResponse {
            job_status_json: serde_json::to_string(&job)?,
        })
    }

    async fn status(&self, job_id: String) -> Result<proto::ComputeStatusResponse, NetworkError> {
        let job = load_job(&self.state, &job_id)
            .map_err(|error| NetworkError::BlockService(error.message))?
            .ok_or_else(|| NetworkError::BlockService("job not found".to_string()))?;
        Ok(proto::ComputeStatusResponse {
            job_status_json: serde_json::to_string(&job)?,
        })
    }

    async fn logs(&self, job_id: String) -> Result<proto::ComputeLogsResponse, NetworkError> {
        let logs = compute_logs_for_job(&self.state, &job_id)
            .await
            .map_err(|error| NetworkError::BlockService(error.message))?;
        Ok(proto::ComputeLogsResponse {
            logs_json: serde_json::to_string(&logs)?,
        })
    }

    async fn cancel(&self, job_id: String) -> Result<proto::ComputeCancelResponse, NetworkError> {
        let job = cancel_compute_job_by_id(&self.state, &job_id)
            .await
            .map_err(|error| NetworkError::BlockService(error.message))?;
        Ok(proto::ComputeCancelResponse {
            job_status_json: serde_json::to_string(&job)?,
        })
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn header(error: axum::http::header::InvalidHeaderValue) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }

    fn network(error: NetworkError) -> Self {
        Self::from(error)
    }

    fn serde(error: serde_json::Error) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: error.to_string(),
        }
    }

    fn manifest(error: pepper_types::ManifestError) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: error.to_string(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    fn redb_transaction(error: redb::TransactionError) -> Self {
        Self::internal(error.to_string())
    }

    fn redb_table(error: redb::TableError) -> Self {
        Self::internal(error.to_string())
    }

    fn redb_storage(error: redb::StorageError) -> Self {
        Self::internal(error.to_string())
    }

    fn redb_commit(error: redb::CommitError) -> Self {
        Self::internal(error.to_string())
    }
}

impl From<StorageError> for ApiError {
    fn from(error: StorageError) -> Self {
        let status = match error {
            StorageError::InvalidCid(_) => StatusCode::BAD_REQUEST,
            StorageError::NotFound(_) => StatusCode::NOT_FOUND,
            StorageError::HashMismatch(_) => StatusCode::UNPROCESSABLE_ENTITY,
            StorageError::CapacityExceeded { .. } => StatusCode::INSUFFICIENT_STORAGE,
            StorageError::NoStorageLocations => StatusCode::INSUFFICIENT_STORAGE,
            StorageError::BlockTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            StorageError::LocationLocked(_) | StorageError::LockPoisoned => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            StorageError::Io { .. }
            | StorageError::Transaction(_)
            | StorageError::Table(_)
            | StorageError::RedbStorage(_)
            | StorageError::Commit(_)
            | StorageError::Serde(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self {
            status,
            message: error.to_string(),
        }
    }
}

impl From<NetworkError> for ApiError {
    fn from(error: NetworkError) -> Self {
        let status = match error {
            NetworkError::Rpc { .. } => StatusCode::BAD_GATEWAY,
            NetworkError::BlockService(_) => StatusCode::BAD_GATEWAY,
            NetworkError::InvalidPeerAddress { .. } | NetworkError::InvalidDescriptor(_) => {
                StatusCode::BAD_REQUEST
            }
            NetworkError::UnsupportedMethod(_) => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self {
            status,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.message });
        (self.status, Json(body)).into_response()
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
