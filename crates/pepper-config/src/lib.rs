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
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    #[serde(default)]
    pub locations: Vec<StorageLocationConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageLocationConfig {
    pub path: PathBuf,
    pub max_capacity_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
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
    pub reconstructed_cache: ReconstructedCacheConfig,
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
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            enabled: false,
            region: default_s3_region(),
            access_key_id: None,
            secret_access_key_path: None,
            max_clock_skew_seconds: default_s3_clock_skew_seconds(),
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

fn default_api_bind_addr() -> String {
    "127.0.0.1:9080".to_string()
}

fn default_s3_region() -> String {
    "us-east-1".to_string()
}

fn default_s3_clock_skew_seconds() -> u64 {
    900
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

    let api_addr =
        config.api.bind_addr.parse::<SocketAddr>().map_err(|e| {
            ConfigError::Invalid(format!("api.bind_addr is not a socket address: {e}"))
        })?;
    if !api_addr.ip().is_loopback() {
        return Err(ConfigError::Invalid(
            "api.bind_addr must use a loopback address; use a TLS reverse proxy for remote access"
                .to_string(),
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
        assert_eq!(cfg.replication.default_factor, 3);
        assert!(!cfg.namespace.enabled);
        assert!(!cfg.s3.enabled);
        assert_eq!(cfg.s3.region, "us-east-1");
        assert!(!cfg.erasure.enabled);
        assert_eq!(cfg.erasure.data_shards, 6);
        assert_eq!(cfg.erasure.parity_shards, 3);
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
}
