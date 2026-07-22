// SPDX-License-Identifier: Apache-2.0

use pepper_types::{Cid, ConfigSummary, StorageLocationStatus};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub path: PathBuf,
    pub config: PepperConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PepperConfig {
    #[serde(default)]
    pub node: NodeConfig,
    #[serde(default)]
    pub data: DataConfig,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub namespace: NamespaceConfig,
    #[serde(default)]
    pub replication: ReplicationConfig,
    #[serde(default)]
    pub erasure: ErasureConfig,
    #[serde(default)]
    pub compute: ComputeConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub s3: S3Config,
    #[serde(default)]
    pub fast_path: FastPathConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    #[serde(default = "default_node_name")]
    pub name: String,
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    pub advertise_addr: Option<String>,
    /// Dedicated QUIC bulk-data listener. When omitted, Pepper uses the
    /// control listener port plus one on the same address.
    pub bulk_listen_addr: Option<String>,
    /// Routable address advertised for the dedicated bulk-data listener.
    /// When omitted, Pepper uses the control advertise port plus one.
    pub bulk_advertise_addr: Option<String>,
    pub failure_domain: Option<String>,
    #[serde(default)]
    pub placement_labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataConfig {
    #[serde(default = "default_data_path")]
    pub path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    pub key_path: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub generate_if_missing: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    #[serde(default = "default_api_bind_addr")]
    pub bind_addr: String,
    /// Explicitly permits the built-in plaintext HTTP server to listen beyond
    /// loopback. This is intended for isolated test networks; production
    /// deployments should terminate TLS and authentication at a proxy.
    #[serde(default)]
    pub allow_insecure_remote: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    #[serde(default)]
    pub engine: StorageEngine,
    #[serde(default)]
    pub native: NativeStorageConfig,
    #[serde(default)]
    pub small_object_pack: SmallObjectPackConfig,
    #[serde(default)]
    pub locations: Vec<StorageLocationConfig>,
}

/// Durable append-log storage for small content blocks on the files backend.
/// Sealed local segments are the replicated-record stage consumed by the
/// object-level EC packer; the native backend already provides this physical
/// representation for every block.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmallObjectPackConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_small_object_pack_max_bytes")]
    pub max_object_bytes: u64,
    #[serde(default = "default_small_object_pack_segment_bytes")]
    pub segment_bytes: u64,
    #[serde(default = "default_small_object_pack_owners")]
    pub owners: usize,
    #[serde(default = "default_native_io_uring_entries")]
    pub io_uring_entries: u32,
    #[serde(default)]
    pub require_io_uring: bool,
    #[serde(default = "default_small_object_pack_group_commit_delay_microseconds")]
    pub group_commit_delay_microseconds: u64,
    #[serde(default = "default_small_object_pack_group_commit_max_requests")]
    pub group_commit_max_requests: usize,
    #[serde(default = "default_native_compaction_percent")]
    pub compaction_dead_percent: u8,
}

impl Default for SmallObjectPackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_object_bytes: default_small_object_pack_max_bytes(),
            segment_bytes: default_small_object_pack_segment_bytes(),
            owners: default_small_object_pack_owners(),
            io_uring_entries: default_native_io_uring_entries(),
            require_io_uring: false,
            group_commit_delay_microseconds:
                default_small_object_pack_group_commit_delay_microseconds(),
            group_commit_max_requests: default_small_object_pack_group_commit_max_requests(),
            compaction_dead_percent: default_native_compaction_percent(),
        }
    }
}

impl SmallObjectPackConfig {
    pub fn native_config(&self) -> NativeStorageConfig {
        NativeStorageConfig {
            segment_bytes: self.segment_bytes,
            owners: self.owners,
            io_uring_entries: self.io_uring_entries,
            // Buffered append logs avoid direct-I/O padding overhead for 4 KiB
            // records while retaining the same grouped durability protocol.
            direct_io: false,
            require_io_uring: self.require_io_uring,
            group_commit_delay_microseconds: self.group_commit_delay_microseconds,
            group_commit_max_requests: self.group_commit_max_requests,
            compaction_dead_percent: self.compaction_dead_percent,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StorageEngine {
    #[default]
    Files,
    NativeNvme,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeStorageConfig {
    #[serde(default = "default_native_segment_bytes")]
    pub segment_bytes: u64,
    /// Zero selects a bounded number of online CPUs.
    #[serde(default)]
    pub owners: usize,
    #[serde(default = "default_native_io_uring_entries")]
    pub io_uring_entries: u32,
    #[serde(default = "default_true")]
    pub direct_io: bool,
    #[serde(default)]
    pub require_io_uring: bool,
    /// Maximum time the native engine waits to combine independent object
    /// commits into one device durability barrier.
    #[serde(default = "default_native_group_commit_delay_microseconds")]
    pub group_commit_delay_microseconds: u64,
    #[serde(default = "default_native_group_commit_max_requests")]
    pub group_commit_max_requests: usize,
    #[serde(default = "default_native_compaction_percent")]
    pub compaction_dead_percent: u8,
}

impl Default for NativeStorageConfig {
    fn default() -> Self {
        Self {
            segment_bytes: default_native_segment_bytes(),
            owners: 0,
            io_uring_entries: default_native_io_uring_entries(),
            direct_io: true,
            require_io_uring: false,
            group_commit_delay_microseconds: default_native_group_commit_delay_microseconds(),
            group_commit_max_requests: default_native_group_commit_max_requests(),
            compaction_dead_percent: default_native_compaction_percent(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageLocationConfig {
    pub path: PathBuf,
    pub max_capacity_bytes: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
    #[serde(default)]
    pub bulk: BulkTransportConfig,
}

/// Physical bulk-data plane limits. Control and Raft traffic never consumes
/// these workers, connection slots, stream slots, or flow-control windows.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkTransportConfig {
    #[serde(default = "default_bulk_worker_threads")]
    pub worker_threads: usize,
    #[serde(default = "default_bulk_inbound_connections")]
    pub inbound_connections: usize,
    #[serde(default = "default_bulk_streams_per_connection")]
    pub streams_per_connection: usize,
    #[serde(default = "default_bulk_send_window_bytes")]
    pub send_window_bytes: u64,
    #[serde(default = "default_bulk_connection_receive_window_bytes")]
    pub connection_receive_window_bytes: u64,
    #[serde(default = "default_bulk_stream_receive_window_bytes")]
    pub stream_receive_window_bytes: u64,
    #[serde(default = "default_bulk_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
    /// Aggregate raw bulk payload budget. Zero disables shaping. Set this
    /// below measured link capacity to reserve bandwidth for control traffic.
    #[serde(default)]
    pub max_bytes_per_second: u64,
    #[serde(default = "default_bulk_bandwidth_burst_bytes")]
    pub bandwidth_burst_bytes: u64,
}

impl Default for BulkTransportConfig {
    fn default() -> Self {
        Self {
            worker_threads: default_bulk_worker_threads(),
            inbound_connections: default_bulk_inbound_connections(),
            streams_per_connection: default_bulk_streams_per_connection(),
            send_window_bytes: default_bulk_send_window_bytes(),
            connection_receive_window_bytes: default_bulk_connection_receive_window_bytes(),
            stream_receive_window_bytes: default_bulk_stream_receive_window_bytes(),
            request_timeout_seconds: default_bulk_request_timeout_seconds(),
            max_bytes_per_second: 0,
            bandwidth_burst_bytes: default_bulk_bandwidth_burst_bytes(),
        }
    }
}

/// Transactional namespace and per-node consensus resource configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub consensus_enabled: bool,
    #[serde(default = "default_max_namespace_groups")]
    pub max_namespace_groups: usize,
    #[serde(default = "default_max_consensus_log_bytes")]
    pub max_consensus_log_bytes: u64,
    #[serde(default = "default_max_namespace_write_rate")]
    pub max_namespace_write_rate: u64,
    #[serde(default = "default_max_consensus_command_bytes")]
    pub max_consensus_command_bytes: u64,
    #[serde(default = "default_consensus_heartbeat_ms")]
    pub heartbeat_interval_ms: u64,
    #[serde(default = "default_consensus_election_min_ms")]
    pub election_timeout_min_ms: u64,
    #[serde(default = "default_consensus_election_max_ms")]
    pub election_timeout_max_ms: u64,
    #[serde(default = "default_consensus_snapshot_after_logs")]
    pub snapshot_after_logs: u64,
    #[serde(default = "default_consensus_logs_after_snapshot")]
    pub max_logs_after_snapshot: u64,
    #[serde(default = "default_consensus_checkpoint_log_bytes")]
    pub checkpoint_log_bytes: u64,
    #[serde(default = "default_consensus_restore_target_ms")]
    pub checkpoint_restore_target_ms: u64,
    #[serde(default = "default_namespace_max_staging_leases")]
    pub max_staging_leases: usize,
    #[serde(default = "default_namespace_max_staging_bytes")]
    pub max_staging_bytes: u64,
    #[serde(default = "default_namespace_staging_ttl_seconds")]
    pub staging_ttl_seconds: u64,
    #[serde(default = "default_namespace_read_lease_ttl_seconds")]
    pub read_lease_ttl_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicationConfig {
    #[serde(default = "default_replication_factor")]
    pub default_factor: u16,
    #[serde(default = "default_repair_interval_seconds")]
    pub repair_interval_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_erasure_min_size_bytes")]
    pub min_size_bytes: u64,
    #[serde(default = "default_erasure_data_shards")]
    pub data_shards: u16,
    #[serde(default = "default_erasure_parity_shards")]
    pub parity_shards: u16,
    #[serde(default)]
    pub transfer: ErasureTransferConfig,
    #[serde(default)]
    pub reconstructed_cache: ReconstructedCacheConfig,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ErasureTransferStrategy {
    #[default]
    Adaptive,
    GatewayFanout,
    DistributedParity,
    Hierarchical,
    Pipelined,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureTransferConfig {
    #[serde(default)]
    pub strategy: ErasureTransferStrategy,
    /// Gateway link shape used with live queue/completion telemetry. Zero lets
    /// the selector infer pressure only from bounded stream occupancy.
    #[serde(default)]
    pub gateway_capacity_mbps: u64,
    #[serde(default = "default_erasure_transfer_switch_samples")]
    pub switch_after_samples: u16,
    #[serde(default = "default_erasure_transfer_min_dwell_ms")]
    pub minimum_dwell_ms: u64,
    #[serde(default = "default_erasure_transfer_min_stripe_bytes")]
    pub minimum_adaptive_stripe_bytes: u64,
    #[serde(default = "default_erasure_pipeline_max_hops")]
    pub pipeline_max_hops: u8,
}

impl Default for ErasureTransferConfig {
    fn default() -> Self {
        Self {
            strategy: ErasureTransferStrategy::Adaptive,
            gateway_capacity_mbps: 0,
            switch_after_samples: default_erasure_transfer_switch_samples(),
            minimum_dwell_ms: default_erasure_transfer_min_dwell_ms(),
            minimum_adaptive_stripe_bytes: default_erasure_transfer_min_stripe_bytes(),
            pipeline_max_hops: default_erasure_pipeline_max_hops(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ReconstructedCacheConfig {
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub max_capacity_bytes: u64,
    #[serde(default = "default_reconstructed_cache_admission_hits")]
    pub admission_hits: u8,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_compute_runtime")]
    pub runtime: String,
    #[serde(default = "default_max_concurrent_jobs")]
    pub max_concurrent_jobs: usize,
    #[serde(default = "default_compute_work_dir")]
    pub work_dir: PathBuf,
    #[serde(default = "default_firecracker_binary")]
    pub firecracker_binary: PathBuf,
    #[serde(default = "default_firecracker_jailer_binary")]
    pub firecracker_jailer_binary: PathBuf,
    #[serde(default)]
    pub firecracker_enable_jailer: bool,
    #[serde(default = "default_firecracker_jailer_uid")]
    pub firecracker_jailer_uid: u32,
    #[serde(default = "default_firecracker_jailer_gid")]
    pub firecracker_jailer_gid: u32,
    #[serde(default = "default_firecracker_jailer_chroot_base")]
    pub firecracker_jailer_chroot_base: PathBuf,
    #[serde(default = "default_true")]
    pub firecracker_strict_sandbox: bool,
    #[serde(default)]
    pub firecracker_allow_untrusted_rootfs: bool,
    #[serde(default)]
    pub firecracker_allowed_rootfs_cids: Vec<Cid>,
    pub firecracker_kernel_image: Option<PathBuf>,
    #[serde(default = "default_firecracker_memory_mib")]
    pub firecracker_memory_mib: u32,
    #[serde(default = "default_firecracker_vcpu_count")]
    pub firecracker_vcpu_count: u8,
    #[serde(default = "default_firecracker_max_input_bytes")]
    pub firecracker_max_input_bytes: u64,
    #[serde(default = "default_firecracker_max_output_bytes")]
    pub firecracker_max_output_bytes: u64,
    #[serde(default = "default_true")]
    pub firecracker_cgroup_enabled: bool,
    #[serde(default = "default_firecracker_cgroup_base")]
    pub firecracker_cgroup_base: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub cluster_secret_path: Option<PathBuf>,
    pub api_bearer_token: Option<String>,
}

/// Opt-in S3-compatible gateway configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Config {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_s3_region")]
    pub region: String,
    pub access_key_id: Option<String>,
    pub secret_access_key_path: Option<PathBuf>,
    #[serde(default = "default_s3_clock_skew_seconds")]
    pub max_clock_skew_seconds: u64,
    #[serde(default = "default_s3_bucket_partitions")]
    pub bucket_partitions: u16,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            enabled: false,
            region: default_s3_region(),
            access_key_id: None,
            secret_access_key_path: None,
            max_clock_skew_seconds: default_s3_clock_skew_seconds(),
            bucket_partitions: default_s3_bucket_partitions(),
        }
    }
}

/// Per-core S3 execution ownership and admission configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FastPathConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Zero selects one owner for every online CPU not reserved for control.
    #[serde(default)]
    pub workers: usize,
    #[serde(default = "default_fast_path_control_cores")]
    pub control_cores: usize,
    #[serde(default = "default_fast_path_queue_depth")]
    pub queue_depth: usize,
    #[serde(default = "default_fast_path_requests_per_worker")]
    pub requests_per_worker: usize,
    #[serde(default = "default_fast_path_writes_per_worker")]
    pub writes_per_worker: usize,
    #[serde(default = "default_fast_path_replications_per_worker")]
    pub replications_per_worker: usize,
    #[serde(default = "default_fast_path_stripe_reads_per_worker")]
    pub stripe_reads_per_worker: usize,
    #[serde(default = "default_fast_path_response_frames")]
    pub response_frames: usize,
    #[serde(default = "default_true")]
    pub pin_cpus: bool,
}

impl Default for FastPathConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            workers: 0,
            control_cores: default_fast_path_control_cores(),
            queue_depth: default_fast_path_queue_depth(),
            requests_per_worker: default_fast_path_requests_per_worker(),
            writes_per_worker: default_fast_path_writes_per_worker(),
            replications_per_worker: default_fast_path_replications_per_worker(),
            stripe_reads_per_worker: default_fast_path_stripe_reads_per_worker(),
            response_frames: default_fast_path_response_frames(),
            pin_cpus: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    pub max_block_bytes: Option<u64>,
    pub max_object_bytes: Option<u64>,
    pub max_compute_timeout_seconds: Option<u64>,
    pub http_requests_per_minute: Option<u64>,
    pub rpc_requests_per_minute: Option<u64>,
    pub erasure_repair_max_concurrent_shards: Option<usize>,
    pub erasure_repair_bytes_per_second: Option<u64>,
    pub erasure_read_max_concurrent_stripes: Option<usize>,
    pub s3_http_concurrency: Option<usize>,
    pub s3_write_concurrency: Option<usize>,
    pub s3_write_queue_depth: Option<usize>,
    pub s3_write_queue_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            name: default_node_name(),
            listen_addr: default_listen_addr(),
            advertise_addr: None,
            bulk_listen_addr: None,
            bulk_advertise_addr: None,
            failure_domain: None,
            placement_labels: BTreeMap::new(),
        }
    }
}

impl Default for DataConfig {
    fn default() -> Self {
        Self {
            path: default_data_path(),
        }
    }
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            key_path: None,
            generate_if_missing: true,
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_api_bind_addr(),
            allow_insecure_remote: false,
        }
    }
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            consensus_enabled: false,
            max_namespace_groups: default_max_namespace_groups(),
            max_consensus_log_bytes: default_max_consensus_log_bytes(),
            max_namespace_write_rate: default_max_namespace_write_rate(),
            max_consensus_command_bytes: default_max_consensus_command_bytes(),
            heartbeat_interval_ms: default_consensus_heartbeat_ms(),
            election_timeout_min_ms: default_consensus_election_min_ms(),
            election_timeout_max_ms: default_consensus_election_max_ms(),
            snapshot_after_logs: default_consensus_snapshot_after_logs(),
            max_logs_after_snapshot: default_consensus_logs_after_snapshot(),
            checkpoint_log_bytes: default_consensus_checkpoint_log_bytes(),
            checkpoint_restore_target_ms: default_consensus_restore_target_ms(),
            max_staging_leases: default_namespace_max_staging_leases(),
            max_staging_bytes: default_namespace_max_staging_bytes(),
            staging_ttl_seconds: default_namespace_staging_ttl_seconds(),
            read_lease_ttl_seconds: default_namespace_read_lease_ttl_seconds(),
        }
    }
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            default_factor: default_replication_factor(),
            repair_interval_seconds: default_repair_interval_seconds(),
        }
    }
}

impl Default for ErasureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_size_bytes: default_erasure_min_size_bytes(),
            data_shards: default_erasure_data_shards(),
            parity_shards: default_erasure_parity_shards(),
            transfer: ErasureTransferConfig::default(),
            reconstructed_cache: ReconstructedCacheConfig::default(),
        }
    }
}

impl Default for ComputeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            runtime: default_compute_runtime(),
            max_concurrent_jobs: default_max_concurrent_jobs(),
            work_dir: default_compute_work_dir(),
            firecracker_binary: default_firecracker_binary(),
            firecracker_jailer_binary: default_firecracker_jailer_binary(),
            firecracker_enable_jailer: false,
            firecracker_jailer_uid: default_firecracker_jailer_uid(),
            firecracker_jailer_gid: default_firecracker_jailer_gid(),
            firecracker_jailer_chroot_base: default_firecracker_jailer_chroot_base(),
            firecracker_strict_sandbox: true,
            firecracker_allow_untrusted_rootfs: false,
            firecracker_allowed_rootfs_cids: Vec::new(),
            firecracker_kernel_image: None,
            firecracker_memory_mib: default_firecracker_memory_mib(),
            firecracker_vcpu_count: default_firecracker_vcpu_count(),
            firecracker_max_input_bytes: default_firecracker_max_input_bytes(),
            firecracker_max_output_bytes: default_firecracker_max_output_bytes(),
            firecracker_cgroup_enabled: true,
            firecracker_cgroup_base: default_firecracker_cgroup_base(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: default_log_format(),
        }
    }
}

fn default_node_name() -> String {
    "pepper-node".to_string()
}

fn default_listen_addr() -> String {
    "127.0.0.1:9000".to_string()
}

fn default_bulk_worker_threads() -> usize {
    2
}

fn default_bulk_inbound_connections() -> usize {
    512
}

fn default_bulk_streams_per_connection() -> usize {
    256
}

fn default_bulk_send_window_bytes() -> u64 {
    512 * 1024 * 1024
}

fn default_bulk_connection_receive_window_bytes() -> u64 {
    512 * 1024 * 1024
}

fn default_bulk_stream_receive_window_bytes() -> u64 {
    68 * 1024 * 1024
}

fn default_bulk_request_timeout_seconds() -> u64 {
    10
}

fn default_bulk_bandwidth_burst_bytes() -> u64 {
    128 * 1024 * 1024
}

fn default_api_bind_addr() -> String {
    "127.0.0.1:9080".to_string()
}

fn default_s3_region() -> String {
    "us-east-1".to_string()
}

fn default_s3_clock_skew_seconds() -> u64 {
    900
}

fn default_s3_bucket_partitions() -> u16 {
    16
}

fn default_native_segment_bytes() -> u64 {
    256 * 1024 * 1024
}

fn default_small_object_pack_max_bytes() -> u64 {
    4 * 1024
}

fn default_small_object_pack_segment_bytes() -> u64 {
    64 * 1024 * 1024
}

fn default_small_object_pack_owners() -> usize {
    8
}

fn default_small_object_pack_group_commit_delay_microseconds() -> u64 {
    200
}

fn default_small_object_pack_group_commit_max_requests() -> usize {
    256
}

fn default_native_io_uring_entries() -> u32 {
    256
}

fn default_native_group_commit_delay_microseconds() -> u64 {
    0
}

fn default_native_group_commit_max_requests() -> usize {
    64
}

fn default_native_compaction_percent() -> u8 {
    50
}

fn default_fast_path_control_cores() -> usize {
    2
}

fn default_fast_path_queue_depth() -> usize {
    256
}

fn default_fast_path_requests_per_worker() -> usize {
    128
}

fn default_fast_path_writes_per_worker() -> usize {
    4
}

fn default_fast_path_replications_per_worker() -> usize {
    8
}

fn default_fast_path_stripe_reads_per_worker() -> usize {
    32
}

fn default_fast_path_response_frames() -> usize {
    8
}

fn default_data_path() -> PathBuf {
    PathBuf::from("./.pepper")
}

fn default_true() -> bool {
    true
}

fn default_replication_factor() -> u16 {
    3
}

fn default_max_namespace_groups() -> usize {
    128
}

fn default_max_consensus_log_bytes() -> u64 {
    256 * 1024 * 1024
}

fn default_max_namespace_write_rate() -> u64 {
    1_000
}

fn default_max_consensus_command_bytes() -> u64 {
    1024 * 1024
}

fn default_consensus_heartbeat_ms() -> u64 {
    100
}

fn default_consensus_election_min_ms() -> u64 {
    300
}

fn default_consensus_election_max_ms() -> u64 {
    600
}

fn default_consensus_snapshot_after_logs() -> u64 {
    1_000
}

fn default_consensus_logs_after_snapshot() -> u64 {
    128
}

fn default_consensus_checkpoint_log_bytes() -> u64 {
    64 * 1024 * 1024
}

fn default_consensus_restore_target_ms() -> u64 {
    2_000
}

fn default_namespace_max_staging_leases() -> usize {
    10_000
}

fn default_namespace_max_staging_bytes() -> u64 {
    16 * 1024 * 1024 * 1024
}

fn default_namespace_staging_ttl_seconds() -> u64 {
    15 * 60
}

fn default_namespace_read_lease_ttl_seconds() -> u64 {
    60 * 60
}

fn default_repair_interval_seconds() -> u64 {
    30
}

fn default_erasure_min_size_bytes() -> u64 {
    64 * 1024 * 1024
}

fn default_erasure_data_shards() -> u16 {
    6
}

fn default_erasure_parity_shards() -> u16 {
    3
}

fn default_erasure_transfer_switch_samples() -> u16 {
    3
}

fn default_erasure_transfer_min_dwell_ms() -> u64 {
    5_000
}

fn default_erasure_transfer_min_stripe_bytes() -> u64 {
    8 * 1024 * 1024
}

fn default_erasure_pipeline_max_hops() -> u8 {
    6
}

fn default_reconstructed_cache_admission_hits() -> u8 {
    2
}

fn default_compute_runtime() -> String {
    "firecracker".to_string()
}

fn default_max_concurrent_jobs() -> usize {
    1
}

fn default_compute_work_dir() -> PathBuf {
    PathBuf::from("./.pepper/compute")
}

fn default_firecracker_binary() -> PathBuf {
    PathBuf::from("/usr/local/bin/firecracker")
}

fn default_firecracker_jailer_binary() -> PathBuf {
    PathBuf::from("/usr/local/bin/jailer")
}

fn default_firecracker_jailer_uid() -> u32 {
    65534
}

fn default_firecracker_jailer_gid() -> u32 {
    65534
}

fn default_firecracker_jailer_chroot_base() -> PathBuf {
    PathBuf::from("/srv/jailer")
}

fn default_firecracker_memory_mib() -> u32 {
    128
}

fn default_firecracker_vcpu_count() -> u8 {
    1
}

fn default_firecracker_max_input_bytes() -> u64 {
    1024 * 1024 * 1024
}

fn default_firecracker_max_output_bytes() -> u64 {
    1024 * 1024 * 1024
}

fn default_firecracker_cgroup_base() -> PathBuf {
    PathBuf::from("/sys/fs/cgroup/pepper")
}

fn default_log_format() -> String {
    "pretty".to_string()
}

pub fn default_config_path() -> PathBuf {
    let local = PathBuf::from("./pepper.toml");
    if local.exists() {
        local
    } else {
        PathBuf::from("/etc/pepper/pepper.toml")
    }
}

pub fn load_from_path(path: impl AsRef<Path>) -> Result<LoadedConfig, ConfigError> {
    let path = path.as_ref().to_path_buf();
    let contents = fs::read_to_string(&path).map_err(|source| ConfigError::Read {
        path: path.clone(),
        source,
    })?;
    let config: PepperConfig = toml::from_str(&contents).map_err(|source| ConfigError::Parse {
        path: path.clone(),
        source,
    })?;
    validate(&config)?;
    Ok(LoadedConfig { path, config })
}

pub fn validate(config: &PepperConfig) -> Result<(), ConfigError> {
    let listen_addr = config.node.listen_addr.parse::<SocketAddr>().map_err(|e| {
        ConfigError::Invalid(format!("node.listen_addr is not a socket address: {e}"))
    })?;
    if let Some(advertise_addr) = &config.node.advertise_addr {
        let advertise_addr = advertise_addr.parse::<SocketAddr>().map_err(|e| {
            ConfigError::Invalid(format!("node.advertise_addr is not a socket address: {e}"))
        })?;
        if advertise_addr.ip().is_unspecified() || advertise_addr.ip().is_multicast() {
            return Err(ConfigError::Invalid(
                "node.advertise_addr must be a routable unicast address".to_string(),
            ));
        }
    } else if listen_addr.ip().is_unspecified() {
        return Err(ConfigError::Invalid(
            "node.advertise_addr is required when node.listen_addr uses an unspecified IP"
                .to_string(),
        ));
    }
    let derived_bulk_listen = SocketAddr::new(
        listen_addr.ip(),
        listen_addr.port().checked_add(1).ok_or_else(|| {
            ConfigError::Invalid(
                "node.bulk_listen_addr is required when node.listen_addr uses port 65535"
                    .to_string(),
            )
        })?,
    );
    let bulk_listen_addr = config
        .node
        .bulk_listen_addr
        .as_deref()
        .map(str::parse::<SocketAddr>)
        .transpose()
        .map_err(|e| {
            ConfigError::Invalid(format!(
                "node.bulk_listen_addr is not a socket address: {e}"
            ))
        })?
        .unwrap_or(derived_bulk_listen);
    if bulk_listen_addr == listen_addr {
        return Err(ConfigError::Invalid(
            "node.bulk_listen_addr must differ from node.listen_addr".to_string(),
        ));
    }
    let advertise_addr = config
        .node
        .advertise_addr
        .as_deref()
        .unwrap_or(&config.node.listen_addr)
        .parse::<SocketAddr>()
        .expect("control advertise address was validated above");
    let derived_bulk_advertise = SocketAddr::new(
        advertise_addr.ip(),
        advertise_addr.port().checked_add(1).ok_or_else(|| {
            ConfigError::Invalid(
                "node.bulk_advertise_addr is required when node.advertise_addr uses port 65535"
                    .to_string(),
            )
        })?,
    );
    let bulk_advertise_addr = config
        .node
        .bulk_advertise_addr
        .as_deref()
        .map(str::parse::<SocketAddr>)
        .transpose()
        .map_err(|e| {
            ConfigError::Invalid(format!(
                "node.bulk_advertise_addr is not a socket address: {e}"
            ))
        })?
        .unwrap_or(derived_bulk_advertise);
    if bulk_advertise_addr.ip().is_unspecified() || bulk_advertise_addr.ip().is_multicast() {
        return Err(ConfigError::Invalid(
            "node.bulk_advertise_addr must be a routable unicast address".to_string(),
        ));
    }
    let bulk = &config.network.bulk;
    if bulk.worker_threads == 0
        || bulk.worker_threads > 128
        || bulk.inbound_connections == 0
        || bulk.inbound_connections > 65_535
        || bulk.streams_per_connection == 0
        || bulk.streams_per_connection > 65_535
        || bulk.send_window_bytes < 4 * 1024 * 1024
        || bulk.send_window_bytes > u64::from(u32::MAX)
        || bulk.connection_receive_window_bytes < 4 * 1024 * 1024
        || bulk.connection_receive_window_bytes > u64::from(u32::MAX)
        || bulk.stream_receive_window_bytes < 1024 * 1024
        || bulk.stream_receive_window_bytes > bulk.connection_receive_window_bytes
        || bulk.request_timeout_seconds == 0
        || bulk.request_timeout_seconds > 3600
        || (bulk.max_bytes_per_second > 0
            && (bulk.max_bytes_per_second < 1024 * 1024
                || bulk.bandwidth_burst_bytes < 68 * 1024 * 1024))
        || bulk.bandwidth_burst_bytes > u64::from(u32::MAX)
    {
        return Err(ConfigError::Invalid(
            "network.bulk limits are outside their supported ranges".to_string(),
        ));
    }

    let api_addr =
        config.api.bind_addr.parse::<SocketAddr>().map_err(|e| {
            ConfigError::Invalid(format!("api.bind_addr is not a socket address: {e}"))
        })?;
    if !api_addr.ip().is_loopback() && !config.api.allow_insecure_remote {
        return Err(ConfigError::Invalid(
            "api.bind_addr must use a loopback address unless api.allow_insecure_remote is explicitly enabled; use a TLS reverse proxy for production remote access".to_string(),
        ));
    }

    if config.node.name.trim().is_empty() {
        return Err(ConfigError::Invalid(
            "node.name must not be empty".to_string(),
        ));
    }

    if config.namespace.consensus_enabled && !config.namespace.enabled {
        return Err(ConfigError::Invalid(
            "namespace.consensus_enabled requires namespace.enabled".to_string(),
        ));
    }
    if config.namespace.max_namespace_groups == 0
        || config.namespace.max_consensus_log_bytes == 0
        || config.namespace.max_namespace_write_rate == 0
        || config.namespace.max_consensus_command_bytes == 0
        || config.namespace.snapshot_after_logs == 0
        || config.namespace.max_logs_after_snapshot == 0
        || config.namespace.checkpoint_log_bytes == 0
        || config.namespace.checkpoint_restore_target_ms == 0
        || config.namespace.max_staging_leases == 0
        || config.namespace.max_staging_bytes == 0
        || config.namespace.staging_ttl_seconds == 0
        || config.namespace.read_lease_ttl_seconds == 0
    {
        return Err(ConfigError::Invalid(
            "namespace consensus limits must be greater than zero".to_string(),
        ));
    }
    if config.namespace.staging_ttl_seconds > i64::MAX as u64
        || config.namespace.read_lease_ttl_seconds > i64::MAX as u64
    {
        return Err(ConfigError::Invalid(
            "namespace lease TTL values exceed the supported range".to_string(),
        ));
    }
    if config.namespace.max_logs_after_snapshot >= config.namespace.snapshot_after_logs {
        return Err(ConfigError::Invalid(
            "namespace.max_logs_after_snapshot must be below snapshot_after_logs".to_string(),
        ));
    }
    if config.namespace.max_consensus_command_bytes >= config.namespace.max_consensus_log_bytes {
        return Err(ConfigError::Invalid(
            "namespace.max_consensus_command_bytes must be below max_consensus_log_bytes"
                .to_string(),
        ));
    }
    if config.namespace.checkpoint_log_bytes >= config.namespace.max_consensus_log_bytes {
        return Err(ConfigError::Invalid(
            "namespace.checkpoint_log_bytes must be below max_consensus_log_bytes".to_string(),
        ));
    }
    if config.namespace.heartbeat_interval_ms == 0
        || config.namespace.election_timeout_min_ms <= config.namespace.heartbeat_interval_ms
        || config.namespace.election_timeout_max_ms <= config.namespace.election_timeout_min_ms
    {
        return Err(ConfigError::Invalid(
            "namespace election timeouts must satisfy 0 < heartbeat < election_min < election_max"
                .to_string(),
        ));
    }

    if config.compute.enabled && config.compute.max_concurrent_jobs == 0 {
        return Err(ConfigError::Invalid(
            "compute.max_concurrent_jobs must be greater than zero when compute is enabled"
                .to_string(),
        ));
    }
    if config.compute.runtime != "firecracker" {
        return Err(ConfigError::Invalid(
            "compute.runtime must be 'firecracker'".to_string(),
        ));
    }
    if config.compute.firecracker_vcpu_count == 0 {
        return Err(ConfigError::Invalid(
            "compute.firecracker_vcpu_count must be greater than zero".to_string(),
        ));
    }
    if config.compute.firecracker_memory_mib == 0 {
        return Err(ConfigError::Invalid(
            "compute.firecracker_memory_mib must be greater than zero".to_string(),
        ));
    }
    if config.compute.firecracker_max_input_bytes == 0
        || config.compute.firecracker_max_input_bytes > 16 * 1024 * 1024 * 1024
    {
        return Err(ConfigError::Invalid(
            "compute.firecracker_max_input_bytes must be between 1 and 16 GiB".to_string(),
        ));
    }
    if config
        .compute
        .firecracker_allowed_rootfs_cids
        .iter()
        .any(|cid| {
            !matches!(
                cid.codec,
                pepper_types::CODEC_RAW
                    | pepper_types::CODEC_OBJECT_MANIFEST
                    | pepper_types::CODEC_ERASURE_MANIFEST
            )
        })
    {
        return Err(ConfigError::Invalid(
            "compute.firecracker_allowed_rootfs_cids entries must be raw, object, or erasure CIDs"
                .to_string(),
        ));
    }
    if config.compute.firecracker_max_output_bytes == 0
        || config.compute.firecracker_max_output_bytes > 16 * 1024 * 1024 * 1024
    {
        return Err(ConfigError::Invalid(
            "compute.firecracker_max_output_bytes must be between 1 and 16 GiB".to_string(),
        ));
    }
    if config.compute.firecracker_enable_jailer
        && (config.compute.firecracker_jailer_uid == 0
            || config.compute.firecracker_jailer_gid == 0)
    {
        return Err(ConfigError::Invalid(
            "compute.firecracker_jailer_uid and compute.firecracker_jailer_gid must be non-zero when jailer is enabled".to_string(),
        ));
    }

    if let Some(token) = &config.auth.api_bearer_token
        && token.is_empty()
    {
        return Err(ConfigError::Invalid(
            "auth.api_bearer_token must not be empty when configured".to_string(),
        ));
    }
    if config.s3.enabled {
        if !config.namespace.enabled || !config.namespace.consensus_enabled {
            return Err(ConfigError::Invalid(
                "s3.enabled requires namespace.enabled and namespace.consensus_enabled".to_string(),
            ));
        }
        let access_key = config.s3.access_key_id.as_deref().unwrap_or_default();
        if access_key.is_empty()
            || access_key.len() > 128
            || !access_key.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(ConfigError::Invalid(
                "s3.access_key_id must contain 1 to 128 visible ASCII bytes when S3 is enabled"
                    .to_string(),
            ));
        }
        if config.s3.secret_access_key_path.is_none() {
            return Err(ConfigError::Invalid(
                "s3.secret_access_key_path is required when S3 is enabled".to_string(),
            ));
        }
        if config.s3.region.is_empty()
            || config.s3.region.len() > 64
            || !config
                .s3
                .region
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ConfigError::Invalid(
                "s3.region must contain 1 to 64 ASCII letters, digits, or hyphens".to_string(),
            ));
        }
        if config.s3.max_clock_skew_seconds == 0 || config.s3.max_clock_skew_seconds > 3600 {
            return Err(ConfigError::Invalid(
                "s3.max_clock_skew_seconds must be between 1 and 3600".to_string(),
            ));
        }
        if config.s3.bucket_partitions == 0
            || config.s3.bucket_partitions > 256
            || !config.s3.bucket_partitions.is_power_of_two()
        {
            return Err(ConfigError::Invalid(
                "s3.bucket_partitions must be a power of two between 1 and 256".to_string(),
            ));
        }
    }
    if config.fast_path.enabled {
        if config.fast_path.control_cores == 0 {
            return Err(ConfigError::Invalid(
                "fast_path.control_cores must be greater than zero".to_string(),
            ));
        }
        for (name, value) in [
            ("queue_depth", config.fast_path.queue_depth),
            ("requests_per_worker", config.fast_path.requests_per_worker),
            ("writes_per_worker", config.fast_path.writes_per_worker),
            (
                "replications_per_worker",
                config.fast_path.replications_per_worker,
            ),
            (
                "stripe_reads_per_worker",
                config.fast_path.stripe_reads_per_worker,
            ),
            ("response_frames", config.fast_path.response_frames),
        ] {
            if value == 0 {
                return Err(ConfigError::Invalid(format!(
                    "fast_path.{name} must be greater than zero"
                )));
            }
        }
    }
    if config
        .limits
        .max_block_bytes
        .is_some_and(|value| value == 0 || value > 64 * 1024 * 1024)
    {
        return Err(ConfigError::Invalid(
            "limits.max_block_bytes must be between 1 and 67108864".to_string(),
        ));
    }
    if config
        .limits
        .max_object_bytes
        .is_some_and(|value| value == 0 || value > 1024 * 1024 * 1024 * 1024)
    {
        return Err(ConfigError::Invalid(
            "limits.max_object_bytes must be between 1 and 1 TiB".to_string(),
        ));
    }
    if matches!(config.limits.max_compute_timeout_seconds, Some(0)) {
        return Err(ConfigError::Invalid(
            "limits.max_compute_timeout_seconds must be greater than zero".to_string(),
        ));
    }
    if matches!(config.limits.http_requests_per_minute, Some(0)) {
        return Err(ConfigError::Invalid(
            "limits.http_requests_per_minute must be greater than zero".to_string(),
        ));
    }
    if matches!(config.limits.rpc_requests_per_minute, Some(0)) {
        return Err(ConfigError::Invalid(
            "limits.rpc_requests_per_minute must be greater than zero".to_string(),
        ));
    }
    if matches!(config.limits.erasure_repair_max_concurrent_shards, Some(0)) {
        return Err(ConfigError::Invalid(
            "limits.erasure_repair_max_concurrent_shards must be greater than zero".to_string(),
        ));
    }
    if matches!(config.limits.erasure_repair_bytes_per_second, Some(0)) {
        return Err(ConfigError::Invalid(
            "limits.erasure_repair_bytes_per_second must be greater than zero".to_string(),
        ));
    }

    for (key, value) in &config.node.placement_labels {
        if key.trim().is_empty() || value.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "node.placement_labels keys and values must be non-empty".to_string(),
            ));
        }
    }

    if config.replication.default_factor == 0 || config.replication.default_factor > 64 {
        return Err(ConfigError::Invalid(
            "replication.default_factor must be between 1 and 64".to_string(),
        ));
    }
    if !(5..=24 * 60 * 60).contains(&config.replication.repair_interval_seconds) {
        return Err(ConfigError::Invalid(
            "replication.repair_interval_seconds must be between 5 and 86400".to_string(),
        ));
    }
    if config.erasure.enabled && config.erasure.min_size_bytes == 0 {
        return Err(ConfigError::Invalid(
            "erasure.min_size_bytes must be greater than zero when erasure is enabled".to_string(),
        ));
    }
    if config.erasure.data_shards == 0 || config.erasure.parity_shards == 0 {
        return Err(ConfigError::Invalid(
            "erasure data_shards and parity_shards must be greater than zero".to_string(),
        ));
    }
    if config.erasure.parity_shards > config.erasure.data_shards {
        return Err(ConfigError::Invalid(
            "erasure parity_shards must not exceed data_shards".to_string(),
        ));
    }
    if config
        .erasure
        .data_shards
        .saturating_add(config.erasure.parity_shards)
        > 32
    {
        return Err(ConfigError::Invalid(
            "erasure data_shards + parity_shards must be <= 32".to_string(),
        ));
    }
    let transfer = &config.erasure.transfer;
    if !(1..=100).contains(&transfer.switch_after_samples) {
        return Err(ConfigError::Invalid(
            "erasure.transfer.switch_after_samples must be between 1 and 100".to_string(),
        ));
    }
    if transfer.minimum_dwell_ms > 60_000 {
        return Err(ConfigError::Invalid(
            "erasure.transfer.minimum_dwell_ms must not exceed 60000".to_string(),
        ));
    }
    if transfer.minimum_adaptive_stripe_bytes == 0 {
        return Err(ConfigError::Invalid(
            "erasure.transfer.minimum_adaptive_stripe_bytes must be greater than zero".to_string(),
        ));
    }
    if !(1..=config.erasure.data_shards.min(32) as u8).contains(&transfer.pipeline_max_hops) {
        return Err(ConfigError::Invalid(format!(
            "erasure.transfer.pipeline_max_hops must be between 1 and erasure.data_shards ({})",
            config.erasure.data_shards
        )));
    }
    let cache = &config.erasure.reconstructed_cache;
    if cache.path.is_some() != (cache.max_capacity_bytes > 0) {
        return Err(ConfigError::Invalid(
            "erasure.reconstructed_cache path and max_capacity_bytes must be configured together"
                .to_string(),
        ));
    }
    if cache.path.is_some() && cache.admission_hits == 0 {
        return Err(ConfigError::Invalid(
            "erasure.reconstructed_cache.admission_hits must be greater than zero".to_string(),
        ));
    }

    if config.storage.locations.is_empty() {
        return Err(ConfigError::Invalid(
            "at least one storage location must be configured".to_string(),
        ));
    }
    let mut seen = HashSet::new();
    for location in &config.storage.locations {
        if location.max_capacity_bytes == 0 {
            return Err(ConfigError::Invalid(format!(
                "storage location {} must have max_capacity_bytes > 0",
                location.path.display()
            )));
        }
        if !seen.insert(location.path.clone()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate storage location path {}",
                location.path.display()
            )));
        }
    }
    if config.storage.engine == StorageEngine::NativeNvme {
        let native = &config.storage.native;
        if native.segment_bytes < 4 * 1024 * 1024
            || native.segment_bytes > u64::from(u32::MAX)
            || native.segment_bytes % 4096 != 0
        {
            return Err(ConfigError::Invalid(
                "storage.native.segment_bytes must be between 4 MiB and 4 GiB and 4096-byte aligned"
                    .to_string(),
            ));
        }
        let maximum_block = config.limits.max_block_bytes.unwrap_or(64 * 1024 * 1024);
        if native.segment_bytes < maximum_block.saturating_add(1024 * 1024) {
            return Err(ConfigError::Invalid(
                "storage.native.segment_bytes must exceed limits.max_block_bytes by at least 1 MiB"
                    .to_string(),
            ));
        }
        if config
            .storage
            .locations
            .iter()
            .any(|location| location.max_capacity_bytes < native.segment_bytes)
        {
            return Err(ConfigError::Invalid(
                "each native storage location must have capacity for at least one segment"
                    .to_string(),
            ));
        }
        if !(8..=32_768).contains(&native.io_uring_entries) {
            return Err(ConfigError::Invalid(
                "storage.native.io_uring_entries must be between 8 and 32768".to_string(),
            ));
        }
        if native.owners > 4096 {
            return Err(ConfigError::Invalid(
                "storage.native.owners must be zero or at most 4096".to_string(),
            ));
        }
        if native.group_commit_delay_microseconds > 10_000 {
            return Err(ConfigError::Invalid(
                "storage.native.group_commit_delay_microseconds must be at most 10000".to_string(),
            ));
        }
        if !(1..=4096).contains(&native.group_commit_max_requests) {
            return Err(ConfigError::Invalid(
                "storage.native.group_commit_max_requests must be between 1 and 4096".to_string(),
            ));
        }
        if !(10..=90).contains(&native.compaction_dead_percent) {
            return Err(ConfigError::Invalid(
                "storage.native.compaction_dead_percent must be between 10 and 90".to_string(),
            ));
        }
    }
    let pack = &config.storage.small_object_pack;
    if pack.enabled && config.storage.engine == StorageEngine::Files {
        if !(4 * 1024..=1024 * 1024).contains(&pack.max_object_bytes) {
            return Err(ConfigError::Invalid(
                "storage.small_object_pack.max_object_bytes must be between 4 KiB and 1 MiB"
                    .to_string(),
            ));
        }
        if pack.segment_bytes < 4 * 1024 * 1024
            || pack.segment_bytes > u64::from(u32::MAX)
            || pack.segment_bytes % 4096 != 0
            || pack.segment_bytes < pack.max_object_bytes.saturating_add(1024 * 1024)
        {
            return Err(ConfigError::Invalid(
                "storage.small_object_pack.segment_bytes must be 4 MiB to 4 GiB, 4096-byte aligned, and exceed max_object_bytes by at least 1 MiB"
                    .to_string(),
            ));
        }
        if pack.owners == 0 || pack.owners > 4096 {
            return Err(ConfigError::Invalid(
                "storage.small_object_pack.owners must be between 1 and 4096".to_string(),
            ));
        }
        if !(8..=32_768).contains(&pack.io_uring_entries) {
            return Err(ConfigError::Invalid(
                "storage.small_object_pack.io_uring_entries must be between 8 and 32768"
                    .to_string(),
            ));
        }
        if pack.group_commit_delay_microseconds > 10_000
            || !(1..=4096).contains(&pack.group_commit_max_requests)
            || !(10..=90).contains(&pack.compaction_dead_percent)
        {
            return Err(ConfigError::Invalid(
                "storage.small_object_pack group commit or compaction settings are out of range"
                    .to_string(),
            ));
        }
        if config
            .storage
            .locations
            .iter()
            .any(|location| location.max_capacity_bytes < pack.segment_bytes)
        {
            return Err(ConfigError::Invalid(
                "each storage location must have capacity for one small-object pack segment"
                    .to_string(),
            ));
        }
    }
    for (name, value) in [
        (
            "limits.erasure_read_max_concurrent_stripes",
            config.limits.erasure_read_max_concurrent_stripes,
        ),
        (
            "limits.s3_http_concurrency",
            config.limits.s3_http_concurrency,
        ),
        (
            "limits.s3_write_concurrency",
            config.limits.s3_write_concurrency,
        ),
        (
            "limits.s3_write_queue_depth",
            config.limits.s3_write_queue_depth,
        ),
    ] {
        if value == Some(0) {
            return Err(ConfigError::Invalid(format!(
                "{name} must be greater than zero"
            )));
        }
    }
    if config.limits.s3_write_queue_timeout_ms == Some(0) {
        return Err(ConfigError::Invalid(
            "limits.s3_write_queue_timeout_ms must be greater than zero".to_string(),
        ));
    }

    let log_format = config.logging.format.as_str();
    if log_format != "pretty" && log_format != "json" {
        return Err(ConfigError::Invalid(
            "logging.format must be either 'pretty' or 'json'".to_string(),
        ));
    }

    Ok(())
}

impl PepperConfig {
    pub fn identity_key_path(&self) -> PathBuf {
        self.identity
            .key_path
            .clone()
            .unwrap_or_else(|| self.data.path.join("node.key"))
    }

    pub fn metadata_path(&self) -> PathBuf {
        self.data.path.join("metadata.redb")
    }

    pub fn ensure_directories(&self) -> Result<(), std::io::Error> {
        fs::create_dir_all(&self.data.path)?;
        for location in &self.storage.locations {
            fs::create_dir_all(location.path.join("blocks"))?;
            fs::create_dir_all(location.path.join("tmp"))?;
            fs::create_dir_all(location.path.join("gc"))?;
            fs::create_dir_all(location.path.join("meta"))?;
            if self.storage.engine == StorageEngine::NativeNvme {
                fs::create_dir_all(location.path.join("segments"))?;
            }
        }
        if let Some(path) = &self.erasure.reconstructed_cache.path {
            fs::create_dir_all(path)?;
        }
        if let Some(parent) = self.identity_key_path().parent() {
            fs::create_dir_all(parent)?;
        }
        if self.compute.enabled {
            fs::create_dir_all(&self.compute.work_dir)?;
        }
        Ok(())
    }

    pub fn summary(&self, config_path: &Path) -> ConfigSummary {
        ConfigSummary {
            config_path: config_path.display().to_string(),
            data_path: self.data.path.display().to_string(),
            listen_addr: self.node.listen_addr.clone(),
            api_bind_addr: self.api.bind_addr.clone(),
            storage_locations: self
                .storage
                .locations
                .iter()
                .map(|location| StorageLocationStatus {
                    path: location.path.display().to_string(),
                    max_capacity_bytes: location.max_capacity_bytes,
                })
                .collect(),
            bootstrap_peers: self.network.bootstrap_peers.clone(),
            namespace_enabled: self.namespace.enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config_with_defaults() {
        let cfg: PepperConfig = toml::from_str(
            r#"
            [node]
            name = "node-a"
            [[storage.locations]]
            path = "/tmp/pepper-config-test"
            max_capacity_bytes = 1024
            "#,
        )
        .unwrap();
        validate(&cfg).unwrap();
        assert_eq!(cfg.node.name, "node-a");
        assert_eq!(cfg.api.bind_addr, "127.0.0.1:9080");
        assert!(!cfg.api.allow_insecure_remote);
        assert_eq!(cfg.replication.default_factor, 3);
        assert!(!cfg.namespace.enabled);
        assert!(!cfg.s3.enabled);
        assert_eq!(cfg.s3.region, "us-east-1");
        assert!(cfg.fast_path.enabled);
        assert_eq!(cfg.fast_path.control_cores, 2);
        assert_eq!(cfg.network.bulk.worker_threads, 2);
        assert_eq!(cfg.network.bulk.max_bytes_per_second, 0);
        assert_eq!(cfg.storage.small_object_pack.max_object_bytes, 4 * 1024);
        assert!(!cfg.erasure.enabled);
        assert_eq!(cfg.erasure.data_shards, 6);
        assert_eq!(cfg.erasure.parity_shards, 3);
    }

    #[test]
    fn remote_plaintext_api_binding_requires_explicit_opt_in() {
        let rejected: PepperConfig = toml::from_str(
            r#"
            [node]
            name = "node-a"
            [api]
            bind_addr = "0.0.0.0:9080"
            [[storage.locations]]
            path = "/tmp/pepper-config-remote-rejected"
            max_capacity_bytes = 1024
            "#,
        )
        .unwrap();
        assert!(validate(&rejected).is_err());

        let allowed: PepperConfig = toml::from_str(
            r#"
            [node]
            name = "node-a"
            [api]
            bind_addr = "0.0.0.0:9080"
            allow_insecure_remote = true
            [[storage.locations]]
            path = "/tmp/pepper-config-remote-allowed"
            max_capacity_bytes = 1024
            "#,
        )
        .unwrap();
        validate(&allowed).unwrap();
    }

    #[test]
    fn validates_per_core_fast_path() {
        let cfg: PepperConfig = toml::from_str(
            r#"
            [fast_path]
            workers = 4
            control_cores = 2
            queue_depth = 64
            requests_per_worker = 32
            writes_per_worker = 2
            replications_per_worker = 4
            stripe_reads_per_worker = 8
            response_frames = 4
            pin_cpus = false
            [[storage.locations]]
            path = "/tmp/pepper-config-fast-path-test"
            max_capacity_bytes = 1024
            "#,
        )
        .unwrap();
        validate(&cfg).unwrap();
        assert_eq!(cfg.fast_path.workers, 4);

        let mut invalid = cfg;
        invalid.fast_path.queue_depth = 0;
        assert!(validate(&invalid).is_err());
    }

    #[test]
    fn validates_isolated_bulk_transport() {
        let cfg: PepperConfig = toml::from_str(
            r#"
            [node]
            listen_addr = "127.0.0.1:9000"
            bulk_listen_addr = "127.0.0.1:9100"
            bulk_advertise_addr = "127.0.0.1:9100"
            [network.bulk]
            worker_threads = 3
            inbound_connections = 128
            streams_per_connection = 64
            send_window_bytes = 268435456
            connection_receive_window_bytes = 268435456
            stream_receive_window_bytes = 71303168
            request_timeout_seconds = 90
            max_bytes_per_second = 125000000
            bandwidth_burst_bytes = 134217728
            [[storage.locations]]
            path = "/tmp/pepper-config-bulk-transport-test"
            max_capacity_bytes = 1024
            "#,
        )
        .unwrap();
        validate(&cfg).unwrap();
        assert_eq!(cfg.network.bulk.worker_threads, 3);
        assert_eq!(cfg.network.bulk.max_bytes_per_second, 125_000_000);

        let mut invalid = cfg.clone();
        invalid.node.bulk_listen_addr = Some(invalid.node.listen_addr.clone());
        assert!(validate(&invalid).is_err());
        invalid.node.bulk_listen_addr = Some("127.0.0.1:9100".to_string());
        invalid.network.bulk.stream_receive_window_bytes =
            invalid.network.bulk.connection_receive_window_bytes + 1;
        assert!(validate(&invalid).is_err());
    }

    #[test]
    fn validates_s3_gateway_configuration() {
        let cfg: PepperConfig = toml::from_str(
            r#"
            [namespace]
            enabled = true
            consensus_enabled = true
            [s3]
            enabled = true
            region = "us-west-2"
            access_key_id = "pepper-test"
            secret_access_key_path = "/tmp/pepper-s3.secret"
            max_clock_skew_seconds = 300
            [[storage.locations]]
            path = "/tmp/pepper-config-s3-test"
            max_capacity_bytes = 1024
            "#,
        )
        .unwrap();
        validate(&cfg).unwrap();
        assert_eq!(cfg.s3.bucket_partitions, 16);
        let mut invalid_partitions = cfg.clone();
        invalid_partitions.s3.bucket_partitions = 3;
        assert!(validate(&invalid_partitions).is_err());

        let invalid: PepperConfig = toml::from_str(
            r#"
            [s3]
            enabled = true
            access_key_id = "pepper-test"
            secret_access_key_path = "/tmp/pepper-s3.secret"
            [[storage.locations]]
            path = "/tmp/pepper-config-invalid-s3-test"
            max_capacity_bytes = 1024
            "#,
        )
        .unwrap();
        assert!(validate(&invalid).is_err());
    }

    #[test]
    fn namespace_feature_gate_is_explicitly_configurable() {
        let cfg: PepperConfig = toml::from_str(
            r#"
            [namespace]
            enabled = true
            consensus_enabled = true
            [[storage.locations]]
            path = "/tmp/pepper-config-namespace-test"
            max_capacity_bytes = 1024
            "#,
        )
        .unwrap();
        validate(&cfg).unwrap();
        assert!(cfg.namespace.enabled);
        assert!(cfg.namespace.consensus_enabled);
        assert_eq!(cfg.namespace.max_namespace_groups, 128);
        assert!(cfg.summary(Path::new("pepper.toml")).namespace_enabled);
    }

    #[test]
    fn validates_erasure_policy() {
        let cfg: PepperConfig = toml::from_str(
            r#"
            [[storage.locations]]
            path = "/tmp/pepper-config-erasure-test"
            max_capacity_bytes = 1024
            [erasure]
            enabled = true
            min_size_bytes = 1024
            data_shards = 4
            parity_shards = 2
            [erasure.transfer]
            strategy = "distributed-parity"
            gateway_capacity_mbps = 10000
            switch_after_samples = 4
            minimum_dwell_ms = 2000
            minimum_adaptive_stripe_bytes = 8388608
            pipeline_max_hops = 4
            [erasure.reconstructed_cache]
            path = "/tmp/pepper-config-erasure-cache"
            max_capacity_bytes = 4096
            admission_hits = 2
            "#,
        )
        .unwrap();
        validate(&cfg).unwrap();
        assert_eq!(
            cfg.erasure.reconstructed_cache.path.as_deref(),
            Some(Path::new("/tmp/pepper-config-erasure-cache"))
        );
        assert_eq!(
            cfg.erasure.transfer.strategy,
            ErasureTransferStrategy::DistributedParity
        );
        assert_eq!(cfg.erasure.transfer.gateway_capacity_mbps, 10_000);

        let invalid: PepperConfig = toml::from_str(
            r#"
            [[storage.locations]]
            path = "/tmp/pepper-config-invalid-erasure-test"
            max_capacity_bytes = 1024
            [erasure]
            data_shards = 32
            parity_shards = 1
            "#,
        )
        .unwrap();
        assert!(validate(&invalid).is_err());

        let invalid_cache: PepperConfig = toml::from_str(
            r#"
            [[storage.locations]]
            path = "/tmp/pepper-config-invalid-cache-test"
            max_capacity_bytes = 1024
            [erasure.reconstructed_cache]
            path = "/tmp/pepper-config-invalid-cache"
            admission_hits = 2
            "#,
        )
        .unwrap();
        assert!(validate(&invalid_cache).is_err());
    }

    #[test]
    fn rejects_duplicate_storage_locations() {
        let cfg: PepperConfig = toml::from_str(
            r#"
            [[storage.locations]]
            path = "/tmp/pepper-a"
            max_capacity_bytes = 1
            [[storage.locations]]
            path = "/tmp/pepper-a"
            max_capacity_bytes = 2
            "#,
        )
        .unwrap();
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn validates_native_nvme_storage_configuration() {
        let cfg: PepperConfig = toml::from_str(
            r#"
            [storage]
            engine = "native-nvme"
            [storage.native]
            segment_bytes = 268435456
            owners = 8
            io_uring_entries = 256
            direct_io = true
            require_io_uring = false
            group_commit_delay_microseconds = 0
            group_commit_max_requests = 64
            compaction_dead_percent = 50
            [[storage.locations]]
            path = "/tmp/pepper-config-native-test"
            max_capacity_bytes = 1073741824
            [limits]
            max_block_bytes = 67108864
            "#,
        )
        .unwrap();
        validate(&cfg).unwrap();
        assert_eq!(cfg.storage.engine, StorageEngine::NativeNvme);
        assert_eq!(cfg.storage.native.owners, 8);
        assert_eq!(cfg.storage.native.group_commit_max_requests, 64);

        let mut undersized = cfg.clone();
        undersized.storage.native.segment_bytes = 64 * 1024 * 1024;
        assert!(validate(&undersized).is_err());

        let mut unaligned = cfg;
        unaligned.storage.native.segment_bytes += 1;
        assert!(validate(&unaligned).is_err());
    }

    #[test]
    fn validates_small_object_pack_configuration() {
        let cfg: PepperConfig = toml::from_str(
            r#"
            [storage.small_object_pack]
            enabled = true
            max_object_bytes = 1048576
            segment_bytes = 67108864
            owners = 8
            io_uring_entries = 256
            group_commit_delay_microseconds = 200
            group_commit_max_requests = 256
            compaction_dead_percent = 50
            [[storage.locations]]
            path = "/tmp/pepper-config-pack-test"
            max_capacity_bytes = 1073741824
            "#,
        )
        .unwrap();
        validate(&cfg).unwrap();
        assert!(cfg.storage.small_object_pack.enabled);
        assert_eq!(cfg.storage.small_object_pack.max_object_bytes, 1024 * 1024);

        let mut invalid = cfg;
        invalid.storage.small_object_pack.segment_bytes = 1024 * 1024;
        assert!(validate(&invalid).is_err());
    }
}
