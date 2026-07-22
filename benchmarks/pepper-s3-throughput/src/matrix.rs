// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    env, fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const METRIC_FAMILIES: &[&str] = &[
    "pepper_namespace_commits_total",
    "pepper_namespace_commit_latency_microseconds_total",
    "pepper_namespace_reads_total",
    "pepper_namespace_read_latency_microseconds_total",
    "pepper_namespace_linearizable_reads_total",
    "pepper_rpc_request_bytes_total",
    "pepper_rpc_response_bytes_total",
    "pepper_rpc_requests_total",
    "pepper_rpc_errors_total",
    "pepper_placement_calculations_total",
    "pepper_placement_direct_target_attempts_total",
    "pepper_placement_direct_target_errors_total",
    "pepper_placement_direct_target_bytes_total",
    "pepper_placement_exception_hits_total",
    "pepper_placement_map_refreshes_total",
    "pepper_placement_map_refresh_failures_total",
    "pepper_placement_repair_inventory_events_total",
    "pepper_placement_repair_inventory_push_errors_total",
    "pepper_placement_repair_health_batches_total",
    "pepper_placement_repair_health_blocks_total",
    "pepper_placement_repair_health_batch_errors_total",
    "pepper_placement_repair_owner_runs_total",
    "pepper_placement_repair_standby_deferrals_total",
    "pepper_placement_repair_leases_acquired_total",
    "pepper_placement_repair_lease_renewals_total",
    "pepper_placement_repair_lease_conflicts_total",
    "pepper_placement_repair_fence_rejections_total",
    "pepper_placement_repair_tasks_started_total",
    "pepper_placement_repair_tasks_completed_total",
    "pepper_placement_repair_tasks_already_healthy_total",
    "pepper_placement_repair_task_errors_total",
    "pepper_placement_repair_destination_reconstructions_total",
    "pepper_placement_repair_temporary_exceptions_total",
    "pepper_placement_repair_stale_extras_collected_total",
    "pepper_merkle_nodes_written_total",
    "pepper_merkle_mutations_total",
    "pepper_block_write_batch_requests_total",
    "pepper_block_write_batches_total",
    "pepper_block_write_coalesced_batches_total",
    "pepper_block_write_batch_size_max",
    "pepper_block_write_queue_microseconds_total",
    "pepper_block_write_execution_microseconds_total",
    "pepper_raft_storage_operations_total",
    "pepper_raft_storage_entries_total",
    "pepper_raft_storage_queue_microseconds_total",
    "pepper_raft_storage_execution_microseconds_total",
    "pepper_raft_proposal_requests_total",
    "pepper_raft_proposal_batches_total",
    "pepper_raft_proposal_batch_size_max",
    "pepper_raft_proposal_queue_microseconds_total",
    "pepper_raft_proposal_execution_microseconds_total",
    "pepper_s3_put_phase_duration_microseconds_total",
    "pepper_s3_put_phase_observations_total",
    "pepper_namespace_durability_receipt_sources_total",
    "pepper_namespace_durability_preverified_rejections_total",
    "pepper_storage_block_encoding_attempts_total",
    "pepper_storage_block_encoding_blocks_total",
    "pepper_storage_block_encoding_bytes_total",
    "pepper_storage_block_encoding_microseconds_total",
    "pepper_storage_block_reads_total",
    "pepper_storage_block_read_bytes_total",
    "pepper_storage_inline_block_writes_total",
    "pepper_storage_inline_block_write_bytes_total",
    "pepper_storage_packed_block_writes_total",
    "pepper_storage_packed_block_write_bytes_total",
    "pepper_storage_packed_block_reads_total",
    "pepper_storage_packed_block_read_bytes_total",
    "pepper_small_object_pack_extents_written_total",
    "pepper_small_object_pack_extent_bytes_total",
    "pepper_small_object_pack_records_transitioned_total",
    "pepper_small_object_pack_logical_bytes_transitioned_total",
    "pepper_small_object_pack_extents_compacted_total",
    "pepper_small_object_pack_records_compacted_total",
    "pepper_small_object_pack_bytes_reclaimed_total",
    "pepper_small_object_pack_index_hits_total",
    "pepper_small_object_pack_index_misses_total",
    "pepper_small_object_pack_failures_total",
    "pepper_storage_data_durability_barriers_total",
    "pepper_storage_data_files_durable_total",
    "pepper_storage_directory_durability_barriers_total",
    "pepper_storage_native_writes_total",
    "pepper_storage_native_write_bytes_total",
    "pepper_storage_native_reads_total",
    "pepper_storage_native_read_bytes_total",
    "pepper_storage_native_durability_barriers_total",
    "pepper_storage_native_durability_groups_total",
    "pepper_storage_native_durability_group_requests_total",
    "pepper_storage_native_io_uring_submissions_total",
    "pepper_storage_native_sync_fallbacks_total",
    "pepper_storage_native_recovered_records_total",
    "pepper_storage_native_torn_tails_total",
    "pepper_storage_native_compactions_total",
    "pepper_storage_native_compacted_bytes_total",
    "pepper_erasure_stripes_encoded_total",
    "pepper_erasure_stripes_compressed_total",
    "pepper_erasure_stripe_logical_bytes_total",
    "pepper_erasure_stripe_encoded_bytes_total",
    "pepper_erasure_stripe_encoding_microseconds_total",
    "pepper_erasure_shard_read_hedges_total",
    "pepper_erasure_shard_fetch_ewma_microseconds",
    "pepper_erasure_read_admission_queue_microseconds_total",
    "pepper_erasure_read_admission_observations_total",
    "pepper_erasure_repair_throttle_microseconds_total",
    "pepper_erasure_zero_copy_streamed_bytes_total",
    "pepper_erasure_streamed_decompression_bytes_total",
    "pepper_erasure_systematic_range_bytes_total",
    "pepper_reconstructed_cache_requests_total",
    "pepper_reconstructed_cache_admissions_total",
    "pepper_reconstructed_cache_evictions_total",
    "pepper_reconstructed_cache_bypasses_total",
    "pepper_reconstructed_cache_integrity_failures_total",
    "pepper_reconstructed_cache_bytes_total",
    "pepper_s3_write_admission_rejections_total",
    "pepper_s3_write_admission_queue_microseconds_total",
    "pepper_s3_http_admission_rejections_total",
    "pepper_s3_list_cache_hits_total",
    "pepper_s3_list_cache_misses_total",
    "pepper_s3_list_cache_coalesced_total",
    "pepper_s3_partition_routes_total",
    "pepper_s3_list_barriers_total",
    "pepper_s3_list_partitions_scanned_total",
    "pepper_s3_partition_reconfigurations_total",
    "pepper_fast_path_dispatches_total",
    "pepper_fast_path_rejections_total",
    "pepper_fast_path_owner_failovers_total",
    "pepper_fast_path_cross_core_hops_total",
    "pepper_fast_path_owner_requests_total",
    "pepper_fast_path_owner_queue_microseconds_total",
    "pepper_fast_path_owner_execution_microseconds_total",
    "pepper_fast_path_owner_response_bytes_total",
    "pepper_fast_path_owner_buffer_hits_total",
    "pepper_fast_path_owner_buffer_misses_total",
    "pepper_transport_connections_active",
    "pepper_transport_connections_total",
    "pepper_transport_streams_active",
    "pepper_transport_streams_total",
    "pepper_transport_errors_total",
    "pepper_transport_control_cancellations_total",
    "pepper_transport_bulk_cancellations_total",
    "pepper_transport_bulk_bytes_total",
    "pepper_transport_bulk_throttle_microseconds_total",
    "pepper_transport_bulk_stream_capacity",
    "pepper_transport_bulk_stream_queue_ewma_microseconds",
    "pepper_erasure_transfer_plan_selected_total",
    "pepper_erasure_transfer_plan_completed_total",
    "pepper_erasure_transfer_plan_failures_total",
    "pepper_erasure_transfer_plan_fallback_total",
    "pepper_erasure_transfer_plan_completion_microseconds_total",
    "pepper_erasure_transfer_plan_logical_bytes_total",
    "pepper_erasure_transfer_plan_gateway_bytes_total",
    "pepper_erasure_transfer_plan_internal_bytes_total",
    "pepper_erasure_transfer_plan_cross_domain_bytes_total",
];
const PHASES: &[&str] = &[
    "request_streaming",
    "block_hash_storage",
    "replica_transfer",
    "durability_fsync_barrier",
    "merkle_update",
    "raft_namespace_publication",
];
const BENCHMARK_BUCKET: &str = "pepper-s3-throughput";
const BENCHMARK_SMALL_OBJECT_MAX_BYTES: u64 = 4 * 1024;

#[derive(Debug, Args)]
pub struct MatrixArgs {
    #[arg(long)]
    matrix: Option<PathBuf>,
    /// Bulk-data root on a dedicated XFS filesystem (never the OS root filesystem).
    #[arg(long)]
    root: Option<PathBuf>,
    #[arg(long)]
    artifacts: Option<PathBuf>,
    #[arg(long, default_value_t = 60)]
    duration: u64,
    /// Maximum transient S3 retries per logical benchmark operation.
    #[arg(long, default_value_t = 8)]
    s3_retries: u32,
    #[arg(long, default_value_t = 0)]
    cold_bytes: u64,
    #[arg(long)]
    sizes: Option<String>,
    #[arg(long)]
    concurrency: Option<String>,
    #[arg(long)]
    routing: Option<String>,
    #[arg(long)]
    topologies: Option<String>,
    /// Comma-separated Pepper storage engines: files,files-direct,native-nvme.
    #[arg(long)]
    storage_engines: Option<String>,
    #[arg(long)]
    operations: Option<String>,
    #[arg(long)]
    payload_profiles: Option<String>,
    /// Comma-separated nine-node EC transfer plans.
    #[arg(long)]
    erasure_transfer_plans: Option<String>,
    /// Comma-separated nine-node gateway link shapes in megabits per second.
    #[arg(long)]
    gateway_capacities_mbps: Option<String>,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    allow_short: bool,
    #[arg(long)]
    skip_fio: bool,
    /// Reuse the existing Docker image for iterative benchmark-only changes.
    #[arg(long)]
    no_build: bool,
    #[arg(long, default_value_t = 60)]
    fio_runtime: u64,
    #[arg(long, default_value = "16g")]
    fio_size: String,
    #[arg(long)]
    fresh: bool,
    /// Keep topology data and preload markers for an exact follow-up run.
    #[arg(long)]
    retain_data: bool,
    /// Drop only Pepper's disposable reconstructed-stripe cache before startup.
    #[arg(long)]
    clear_reconstructed_cache: bool,
    /// Restart the current namespace leader this many seconds into every non-raw cell.
    #[arg(long)]
    restart_leader_at_seconds: Option<u64>,
    /// How long the selected leader remains stopped so followers must elect a replacement.
    #[arg(long, default_value_t = 10)]
    leader_outage_seconds: u64,
}

#[derive(Debug, Deserialize)]
struct Matrix {
    object_sizes: Vec<u64>,
    concurrency: Vec<usize>,
    routing: Vec<String>,
    topologies: Vec<String>,
    #[serde(default = "default_storage_engines")]
    storage_engines: Vec<String>,
    operations: Vec<String>,
    #[serde(default = "default_payload_profiles")]
    payload_profiles: Vec<String>,
    #[serde(default = "default_erasure_transfer_plans")]
    erasure_transfer_plans: Vec<String>,
    #[serde(default = "default_gateway_capacities_mbps")]
    gateway_capacities_mbps: Vec<u64>,
    range_bytes: u64,
    minimum_duration_seconds: u64,
    cold_dataset_memory_ratio: f64,
}

#[derive(Debug, Clone)]
struct Cell {
    topology: String,
    storage_engine: String,
    size: u64,
    concurrency: usize,
    routing: String,
    operation: String,
    payload_profile: String,
    erasure_transfer_plan: String,
    gateway_capacity_mbps: u64,
}

fn default_payload_profiles() -> Vec<String> {
    vec!["incompressible".to_string()]
}

fn default_storage_engines() -> Vec<String> {
    vec!["files".to_string()]
}

fn default_erasure_transfer_plans() -> Vec<String> {
    vec!["adaptive".to_string()]
}

fn default_gateway_capacities_mbps() -> Vec<u64> {
    vec![0]
}

#[derive(Debug, Clone, Default, Serialize)]
struct Sample {
    time: f64,
    process_ticks: u64,
    disk: BTreeMap<String, Vec<u64>>,
    term_changes: u64,
    max_log_lag: f64,
    quorum_unhealthy: usize,
}

pub(crate) type Metrics = BTreeMap<String, f64>;
pub(crate) type Scrape = BTreeMap<String, Metrics>;

fn here() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn compose() -> PathBuf {
    here().join("compose.yaml")
}

pub(crate) fn run_command(command: &mut Command) -> Result<Output> {
    let display = format!("{command:?}");
    let output = command
        .output()
        .with_context(|| format!("failed to run {display}"))?;
    if !output.status.success() {
        bail!(
            "command failed: {display}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output)
}

pub(crate) fn prepare_benchmark_root(root: &Path) -> Result<PathBuf> {
    fs::create_dir_all(root)
        .with_context(|| format!("failed to create benchmark root {}", root.display()))?;
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to resolve benchmark root {}", root.display()))?;
    ensure!(root.is_dir(), "benchmark root is not a directory");
    ensure!(
        fs::metadata(&root)?.dev() != fs::metadata("/")?.dev(),
        "benchmark root {} is on the OS root filesystem; select a dedicated data mount",
        root.display()
    );
    prepare_runtime_configs(&root, "files", "adaptive", 0)?;
    Ok(root)
}

fn prepare_runtime_configs(
    root: &Path,
    engine: &str,
    erasure_transfer_plan: &str,
    gateway_capacity_mbps: u64,
) -> Result<()> {
    ensure!(
        matches!(engine, "files" | "files-direct" | "native-nvme"),
        "unsupported storage engine {engine}"
    );
    let source = here().join("config");
    let target = root.join(".runtime-config");
    fs::create_dir_all(&target)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
    for entry in fs::read_dir(&source)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "toml") {
            continue;
        }
        let mut config = toml::from_str::<toml::Value>(&fs::read_to_string(&path)?)?;
        let storage = config
            .as_table_mut()
            .context("benchmark node config is not a TOML table")?
            .entry("storage")
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
            .as_table_mut()
            .context("benchmark storage config is not a TOML table")?;
        storage.insert(
            "engine".to_string(),
            toml::Value::String(if engine == "files-direct" {
                "files".to_string()
            } else {
                engine.to_string()
            }),
        );
        storage.insert(
            "small_object_pack".to_string(),
            toml::Value::Table(toml::map::Map::from_iter([
                (
                    "enabled".to_string(),
                    toml::Value::Boolean(engine != "files-direct"),
                ),
                (
                    "max_object_bytes".to_string(),
                    // The OPT-14 crossover matrix found packed reads ahead at
                    // 4 KiB but 25-53% behind direct placement from 16-256
                    // KiB. Keep the benchmark on the measured production
                    // threshold instead of silently packing every 1 MiB cell.
                    toml::Value::Integer(BENCHMARK_SMALL_OBJECT_MAX_BYTES as i64),
                ),
                (
                    "segment_bytes".to_string(),
                    toml::Value::Integer(67_108_864),
                ),
                ("owners".to_string(), toml::Value::Integer(8)),
                ("io_uring_entries".to_string(), toml::Value::Integer(256)),
                ("require_io_uring".to_string(), toml::Value::Boolean(false)),
                (
                    "group_commit_delay_microseconds".to_string(),
                    toml::Value::Integer(200),
                ),
                (
                    "group_commit_max_requests".to_string(),
                    toml::Value::Integer(256),
                ),
                (
                    "compaction_dead_percent".to_string(),
                    toml::Value::Integer(50),
                ),
            ])),
        );
        storage.insert(
            "native".to_string(),
            toml::Value::Table(toml::map::Map::from_iter([
                (
                    "segment_bytes".to_string(),
                    toml::Value::Integer(268_435_456),
                ),
                ("owners".to_string(), toml::Value::Integer(8)),
                ("io_uring_entries".to_string(), toml::Value::Integer(256)),
                ("direct_io".to_string(), toml::Value::Boolean(true)),
                (
                    "require_io_uring".to_string(),
                    toml::Value::Boolean(engine == "native-nvme"),
                ),
                (
                    "group_commit_delay_microseconds".to_string(),
                    toml::Value::Integer(0),
                ),
                (
                    "group_commit_max_requests".to_string(),
                    toml::Value::Integer(64),
                ),
                (
                    "compaction_dead_percent".to_string(),
                    toml::Value::Integer(50),
                ),
            ])),
        );
        if erasure_transfer_plan != "not-applicable" {
            let root_table = config
                .as_table_mut()
                .context("benchmark node config is not a TOML table")?;
            if let Some(erasure) = root_table
                .get_mut("erasure")
                .and_then(toml::Value::as_table_mut)
                .filter(|erasure| {
                    erasure
                        .get("enabled")
                        .and_then(toml::Value::as_bool)
                        .unwrap_or(false)
                })
            {
                let transfer = erasure
                    .entry("transfer")
                    .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                    .as_table_mut()
                    .context("benchmark erasure transfer config is not a TOML table")?;
                transfer.insert(
                    "strategy".to_string(),
                    toml::Value::String(erasure_transfer_plan.to_string()),
                );
                transfer.insert(
                    "gateway_capacity_mbps".to_string(),
                    toml::Value::Integer(i64::try_from(gateway_capacity_mbps)?),
                );
            }
        }
        if gateway_capacity_mbps > 0 {
            let network = config
                .as_table_mut()
                .context("benchmark node config is not a TOML table")?
                .entry("network")
                .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                .as_table_mut()
                .context("benchmark network config is not a TOML table")?;
            let bulk = network
                .entry("bulk")
                .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                .as_table_mut()
                .context("benchmark bulk network config is not a TOML table")?;
            let bytes_per_second = gateway_capacity_mbps
                .checked_mul(1_000_000)
                .context("gateway capacity overflow")?
                / 8;
            bulk.insert(
                "max_bytes_per_second".to_string(),
                toml::Value::Integer(i64::try_from(bytes_per_second)?),
            );
        }
        let generated = target.join(entry.file_name());
        fs::write(&generated, toml::to_string_pretty(&config)?)?;
        fs::set_permissions(generated, fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

pub(crate) fn docker(root: &Path) -> Command {
    let mut command = Command::new("docker");
    command
        .env("PEPPER_BENCH_ROOT", root)
        .env("PEPPER_BENCH_CONFIG_DIR", root.join(".runtime-config"))
        .args(["compose", "-f"])
        .arg(compose());
    command
}

fn filter_strings(selected: &Option<String>, all: &[String]) -> Result<Vec<String>> {
    let Some(selected) = selected else {
        return Ok(all.to_vec());
    };
    let wanted = selected
        .split(',')
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    for value in &wanted {
        ensure!(all.contains(value), "unknown filter value: {value}");
    }
    Ok(all
        .iter()
        .filter(|value| wanted.contains(*value))
        .cloned()
        .collect())
}

fn payload_profiles(selected: &Option<String>, defaults: &[String]) -> Result<Vec<String>> {
    let profiles = selected.as_ref().map_or_else(
        || defaults.to_vec(),
        |selected| selected.split(',').map(str::to_string).collect(),
    );
    for profile in &profiles {
        ensure!(
            matches!(
                profile.as_str(),
                "incompressible"
                    | "compressible-2x"
                    | "compressible-4x"
                    | "compressible-10x"
                    | "compressible-20x"
            ),
            "unknown payload profile: {profile}"
        );
    }
    Ok(profiles)
}

fn erasure_transfer_plans(selected: &Option<String>, defaults: &[String]) -> Result<Vec<String>> {
    let plans = selected.as_ref().map_or_else(
        || defaults.to_vec(),
        |selected| selected.split(',').map(str::to_string).collect(),
    );
    ensure!(
        !plans.is_empty(),
        "at least one erasure transfer plan is required"
    );
    for plan in &plans {
        ensure!(
            matches!(
                plan.as_str(),
                "adaptive" | "gateway-fanout" | "distributed-parity" | "hierarchical" | "pipelined"
            ),
            "unknown erasure transfer plan: {plan}"
        );
    }
    Ok(plans)
}

fn filter_numbers<T>(selected: &Option<String>, all: &[T]) -> Result<Vec<T>>
where
    T: Copy + Ord + std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let Some(selected) = selected else {
        return Ok(all.to_vec());
    };
    let wanted = selected
        .split(',')
        .map(str::parse)
        .collect::<std::result::Result<BTreeSet<T>, _>>()?;
    for value in &wanted {
        ensure!(all.contains(value), "unknown numeric filter value");
    }
    Ok(all
        .iter()
        .filter(|value| wanted.contains(*value))
        .copied()
        .collect())
}

fn mem_total() -> Result<u64> {
    fs::read_to_string("/proc/meminfo")?
        .lines()
        .find(|line| line.starts_with("MemTotal:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .context("MemTotal is unavailable")?
        .parse::<u64>()
        .map(|kib| kib * 1024)
        .context("invalid MemTotal")
}

fn cpu_model() -> String {
    fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|contents| {
            contents
                .lines()
                .find_map(|line| line.strip_prefix("model name\t:").map(str::trim))
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn sha256_tree(root: &Path) -> Result<String> {
    fn visit(root: &Path, current: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(current)? {
            let path = entry?.path();
            if path.is_dir() {
                visit(root, &path, files)?;
            } else if path.is_file() {
                files.push(path.strip_prefix(root)?.to_path_buf());
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    visit(root, root, &mut files)?;
    files.sort();
    let mut digest = Sha256::new();
    for relative in files {
        digest.update(relative.to_string_lossy().as_bytes());
        digest.update([0]);
        digest.update(fs::read(root.join(relative))?);
    }
    Ok(hex::encode(digest.finalize()))
}

fn git_output(args: &[&str]) -> String {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_default()
}

fn program_output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_default()
}

pub(crate) fn topology_endpoints(topology: &str) -> Vec<String> {
    let ports: &[u16] = match topology {
        "single" => &[29080, 29081, 29082],
        "three" => &[29180, 29181, 29182],
        "nine-ec" => &[
            29280, 29281, 29282, 29283, 29284, 29285, 29286, 29287, 29288,
        ],
        _ => &[],
    };
    ports
        .iter()
        .map(|port| format!("http://127.0.0.1:{port}"))
        .collect()
}

pub(crate) fn topology_services(topology: &str) -> Vec<&'static str> {
    match topology {
        "single" => vec!["single", "single2", "single3"],
        "three" => vec!["node1", "node2", "node3"],
        "nine-ec" => vec![
            "ec1", "ec2", "ec3", "ec4", "ec5", "ec6", "ec7", "ec8", "ec9",
        ],
        _ => Vec::new(),
    }
}

fn regular_file_count(path: &Path) -> Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let mut pending = vec![path.to_path_buf()];
    let mut count = 0u64;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                count = count.saturating_add(1);
            }
        }
    }
    Ok(count)
}

fn storage_file_count(root: &Path, topology: &str) -> Result<u64> {
    if topology == "raw" {
        return regular_file_count(&root.join("raw"));
    }
    topology_services(topology)
        .into_iter()
        .try_fold(0u64, |total, service| {
            let output = run_command(docker(root).args([
                "exec",
                "-T",
                "--user",
                "0",
                service,
                "sh",
                "-c",
                "find /var/lib/pepper -type f -print | wc -l",
            ]))?;
            let count = String::from_utf8(output.stdout)?.trim().parse::<u64>()?;
            Ok(total.saturating_add(count))
        })
}

async fn get_text(client: &reqwest::Client, url: String) -> Result<String> {
    Ok(client
        .get(url)
        .timeout(Duration::from_secs(5))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?)
}

fn parse_metrics(text: &str) -> Metrics {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let (key, value) = line.rsplit_once(char::is_whitespace)?;
            value
                .trim()
                .parse::<f64>()
                .ok()
                .map(|value| (key.trim().to_string(), value))
        })
        .collect()
}

pub(crate) async fn scrape(
    client: &reqwest::Client,
    endpoints: &[String],
) -> (Scrape, BTreeMap<String, String>) {
    let mut parsed = Scrape::new();
    let mut raw = BTreeMap::new();
    for endpoint in endpoints {
        let text = get_text(client, format!("{endpoint}/metrics"))
            .await
            .unwrap_or_default();
        parsed.insert(endpoint.clone(), parse_metrics(&text));
        raw.insert(endpoint.clone(), text);
    }
    (parsed, raw)
}

pub(crate) fn family<'a>(
    metrics: &'a Metrics,
    name: &'a str,
) -> impl Iterator<Item = (&'a String, &'a f64)> {
    metrics
        .iter()
        .filter(move |(key, _)| key.as_str() == name || key.starts_with(&format!("{name}{{")))
}

pub(crate) fn metric_sum(metrics: &Metrics, name: &str) -> f64 {
    family(metrics, name).map(|(_, value)| value).sum()
}

pub(crate) fn unhealthy_quorum_count(scrape: &Scrape) -> usize {
    let mut namespaces = BTreeMap::<String, f64>::new();
    for metrics in scrape.values() {
        for (key, value) in family(metrics, "pepper_namespace_quorum_healthy") {
            namespaces
                .entry(key.clone())
                .and_modify(|old| *old = old.max(*value))
                .or_insert(*value);
        }
    }
    namespaces.values().filter(|value| **value == 0.0).count()
}

async fn wait_ready(client: &reqwest::Client, endpoints: &[String]) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(180);
    while Instant::now() < deadline {
        let mut ready = true;
        for endpoint in endpoints {
            ready &= client
                .get(format!("{endpoint}/readyz"))
                .timeout(Duration::from_secs(2))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success());
        }
        if ready {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("nodes did not become ready: {endpoints:?}")
}

pub(crate) async fn wait_quorum(client: &reqwest::Client, endpoints: &[String]) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut stable = 0;
    while Instant::now() < deadline {
        let (metrics, _) = scrape(client, endpoints).await;
        let hosted = metrics
            .values()
            .map(|values| metric_sum(values, "pepper_namespace_groups_hosted"))
            .collect::<Vec<_>>();
        let required_hosts = endpoints.len().min(3);
        let hosted_quorum = hosted.iter().filter(|value| **value > 0.0).count() >= required_hosts;
        if hosted_quorum && unhealthy_quorum_count(&metrics) == 0 {
            stable += 1;
        } else {
            stable = 0;
        }
        if stable >= 3 {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("namespace quorum did not remain stable for three samples")
}

async fn settle_small_object_pack(client: &reqwest::Client, endpoints: &[String]) -> Result<()> {
    ensure!(
        !endpoints.is_empty(),
        "small-object pack requires an endpoint"
    );
    let mut last_error = String::new();
    for attempt in 0..128usize {
        let endpoint = &endpoints[attempt % endpoints.len()];
        match client
            .post(format!(
                "{endpoint}/v1/admin/s3/buckets/{BENCHMARK_BUCKET}/pack"
            ))
            .timeout(Duration::from_secs(120))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                let report = response.json::<Value>().await?;
                let transitioned = report["records_transitioned"].as_u64().unwrap_or(0);
                if transitioned == 0 {
                    return Ok(());
                }
            }
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                last_error = format!("{status}: {body}");
            }
            Err(error) => last_error = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!("small-object packing did not settle: {last_error}")
}

pub(crate) fn stop_topology(root: &Path) {
    let _ = docker(root)
        .args([
            "--profile",
            "single",
            "--profile",
            "three",
            "--profile",
            "nine-ec",
            "down",
            "--remove-orphans",
        ])
        .status();
}

pub(crate) async fn start_topology(
    client: &reqwest::Client,
    topology: &str,
    root: &Path,
) -> Result<()> {
    if topology == "raw" {
        return Ok(());
    }
    let services = topology_services(topology);
    run_command(
        docker(root)
            .args(["--profile", topology, "up", "-d"])
            .args(&services),
    )?;
    wait_ready(client, &topology_endpoints(topology)).await
}

pub(crate) fn build_topology(topology: &str, root: &Path) -> Result<()> {
    if topology == "raw" {
        return Ok(());
    }
    let services = topology_services(topology);
    run_command(docker(root).args(["--profile", topology, "build", services[0]]))?;
    Ok(())
}

pub(crate) fn reset_data(topology: &str, root: &Path) -> Result<()> {
    if topology == "raw" {
        let path = root.join("raw");
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir(&path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o777))?;
        return Ok(());
    }
    reclaim_data(topology, root)
}

pub(crate) fn reclaim_data(topology: &str, root: &Path) -> Result<()> {
    if topology == "raw" {
        let path = root.join("raw");
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        return Ok(());
    }
    let services = topology_services(topology);
    for service in services {
        run_command(docker(root).args([
            "--profile",
            topology,
            "run",
            "--rm",
            "--no-deps",
            "--user",
            "0",
            "--entrypoint",
            "/bin/sh",
            service,
            "-c",
            "find /var/lib/pepper -mindepth 1 -delete",
        ]))?;
    }
    Ok(())
}

fn clear_reconstructed_cache(topology: &str, root: &Path) -> Result<()> {
    if topology == "raw" {
        return Ok(());
    }
    for service in topology_services(topology) {
        run_command(docker(root).args([
            "--profile",
            topology,
            "run",
            "--rm",
            "--no-deps",
            "--user",
            "0",
            "--entrypoint",
            "/bin/sh",
            service,
            "-c",
            "if [ -d /var/lib/pepper/reconstructed-cache ]; then find /var/lib/pepper/reconstructed-cache -mindepth 1 -delete; fi",
        ]))?;
    }
    Ok(())
}

fn loadgen_command() -> Result<Command> {
    let mut command = Command::new(env::current_exe()?);
    command.arg("loadgen");
    Ok(command)
}

pub(crate) fn ensure_bucket(endpoints: &[String]) -> Result<()> {
    run_command(loadgen_command()?.args([
        "--backend",
        "s3",
        "--operation",
        "head",
        "--size",
        "1",
        "--concurrency",
        "1",
        "--duration",
        "1",
        "--allow-short",
        "--object-count",
        "1",
        "--prepare-only",
        "--endpoints",
        &endpoints[0],
        "--quiet",
    ]))?;
    Ok(())
}

pub(crate) async fn routed_endpoints(
    client: &reqwest::Client,
    topology: &str,
    routing: &str,
    endpoints: &[String],
) -> Vec<String> {
    if topology == "raw" {
        return Vec::new();
    }
    let (metrics, _) = scrape(client, endpoints).await;
    let leader = bucket_leader_index(client, endpoints)
        .await
        .unwrap_or_else(|| namespace_leader_index(&metrics));
    match routing {
        "leader" => vec![endpoints[leader].clone()],
        "follower" => endpoints
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != leader)
            .map(|(_, value)| value.clone())
            .collect(),
        _ => endpoints.to_vec(),
    }
}

async fn bucket_leader_index(client: &reqwest::Client, endpoints: &[String]) -> Option<usize> {
    for (index, endpoint) in endpoints.iter().enumerate() {
        let Ok(response) = client
            .get(format!(
                "{endpoint}/v1/namespaces/{BENCHMARK_BUCKET}/status"
            ))
            .timeout(Duration::from_secs(2))
            .send()
            .await
        else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        let Ok(status) = response.json::<Value>().await else {
            continue;
        };
        if status["state"].as_str() == Some("Leader") {
            return Some(index);
        }
    }
    None
}

fn namespace_leader_index(metrics: &Scrape) -> usize {
    metrics
        .values()
        .enumerate()
        .max_by_key(|(_, values)| {
            values
                .keys()
                .filter(|key| {
                    key.starts_with("pepper_namespace_role{") && key.contains("role=\"leader\"")
                })
                .count()
        })
        .map_or(0, |(index, _)| index)
}

pub(crate) fn container_pids(topology: &str, root: &Path) -> Result<Vec<u32>> {
    let mut pids = Vec::new();
    for service in topology_services(topology) {
        let container =
            String::from_utf8(run_command(docker(root).args(["ps", "-q", service]))?.stdout)?
                .trim()
                .to_string();
        if !container.is_empty() {
            let output = run_command(Command::new("docker").args([
                "inspect",
                "-f",
                "{{.State.Pid}}",
                &container,
            ]))?;
            pids.push(String::from_utf8(output.stdout)?.trim().parse()?);
        }
    }
    Ok(pids)
}

fn process_tree(roots: &[u32]) -> BTreeSet<u32> {
    let mut found = roots.iter().copied().collect::<BTreeSet<_>>();
    let mut pending = VecDeque::from(roots.to_vec());
    while let Some(pid) = pending.pop_front() {
        if let Ok(children) = fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")) {
            for child in children
                .split_whitespace()
                .filter_map(|value| value.parse().ok())
            {
                if found.insert(child) {
                    pending.push_back(child);
                }
            }
        }
    }
    found
}

pub(crate) fn proc_ticks(pids: &[u32]) -> u64 {
    process_tree(pids)
        .iter()
        .filter_map(|pid| fs::read_to_string(format!("/proc/{pid}/stat")).ok())
        .filter_map(|stat| {
            let close = stat.rfind(')')?;
            let fields = stat[close + 2..].split_whitespace().collect::<Vec<_>>();
            Some(fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?)
        })
        .sum()
}

pub(crate) fn host_cpu() -> Result<Vec<u64>> {
    Ok(fs::read_to_string("/proc/stat")?
        .lines()
        .next()
        .context("missing aggregate CPU stats")?
        .split_whitespace()
        .skip(1)
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?)
}

fn leaf_devices(path: &Path) -> Result<Vec<PathBuf>> {
    let resolved = path.canonicalize()?;
    let slaves = resolved.join("slaves");
    let children = fs::read_dir(&slaves)
        .map(|items| {
            items
                .filter_map(|item| item.ok().map(|item| item.path()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if children.is_empty() {
        Ok(vec![resolved])
    } else {
        children
            .into_iter()
            .map(|child| leaf_devices(&child))
            .collect::<Result<Vec<_>>>()
            .map(|nested| nested.into_iter().flatten().collect())
    }
}

pub(crate) fn block_stats(root: &Path) -> Result<BTreeMap<String, Vec<u64>>> {
    let device = fs::metadata(root)?.dev();
    // Linux's gnu_dev_major/gnu_dev_minor encoding for dev_t.
    let major = ((device >> 8) & 0xfff) | ((device >> 32) & 0xffff_f000);
    let minor = (device & 0xff) | ((device >> 12) & 0xffff_ff00);
    let sysfs = PathBuf::from(format!("/sys/dev/block/{major}:{minor}"));
    leaf_devices(&sysfs)?
        .into_iter()
        .map(|device| {
            let name = device
                .file_name()
                .context("block device has no name")?
                .to_string_lossy()
                .to_string();
            let stats = fs::read_to_string(device.join("stat"))?
                .split_whitespace()
                .map(str::parse)
                .collect::<std::result::Result<Vec<u64>, _>>()?;
            Ok((name, stats))
        })
        .collect()
}

pub(crate) fn disk_delta(
    before: &BTreeMap<String, Vec<u64>>,
    after: &BTreeMap<String, Vec<u64>>,
    elapsed: f64,
) -> Value {
    let mut devices = serde_json::Map::new();
    let mut reads = 0u64;
    let mut writes = 0u64;
    let mut busy: f64 = 0.0;
    for (name, start) in before {
        let Some(end) = after.get(name) else { continue };
        let read = end[2].saturating_sub(start[2]) * 512;
        let write = end[6].saturating_sub(start[6]) * 512;
        let percent = (end[9].saturating_sub(start[9]) as f64 / (elapsed * 10.0)).min(100.0);
        reads += read;
        writes += write;
        busy = busy.max(percent);
        devices.insert(
            name.clone(),
            json!({"read_bytes": read, "write_bytes": write,
            "read_mb_per_second": read as f64 / 1e6 / elapsed,
            "write_mb_per_second": write as f64 / 1e6 / elapsed, "busy_percent": percent}),
        );
    }
    json!({"read_bytes": reads, "write_bytes": writes,
        "read_mb_per_second": reads as f64 / 1e6 / elapsed,
        "write_mb_per_second": writes as f64 / 1e6 / elapsed,
        "busy_percent": busy, "per_device": devices})
}

fn aggregate_metrics(before: &Scrape, after: &Scrape) -> BTreeMap<String, f64> {
    let mut result = BTreeMap::new();
    for name in METRIC_FAMILIES {
        if matches!(
            *name,
            "pepper_block_write_batch_size_max" | "pepper_raft_proposal_batch_size_max"
        ) {
            let value = after
                .values()
                .map(|values| {
                    family(values, name)
                        .map(|(_, value)| *value)
                        .fold(0.0, f64::max)
                })
                .fold(0.0, f64::max);
            result.insert((*name).to_string(), value);
            continue;
        }
        let start: f64 = before.values().map(|values| metric_sum(values, name)).sum();
        let end: f64 = after.values().map(|values| metric_sum(values, name)).sum();
        result.insert((*name).to_string(), (end - start).max(0.0));
    }
    // Retain labelled deltas for every family. In particular, an aggregate RPC
    // error count without method and direction hides whether the data path,
    // linearizable-read proof, or discovery fallback is churning.
    for name in METRIC_FAMILIES {
        let keys = after
            .values()
            .flat_map(|values| family(values, name).map(|(key, _)| key.clone()))
            .collect::<BTreeSet<_>>();
        for key in keys {
            if matches!(
                *name,
                "pepper_block_write_batch_size_max" | "pepper_raft_proposal_batch_size_max"
            ) {
                let value = after
                    .values()
                    .filter_map(|values| values.get(&key).copied())
                    .fold(0.0, f64::max);
                result.insert(key, value);
                continue;
            }
            let start: f64 = before
                .values()
                .map(|values| values.get(&key).copied().unwrap_or(0.0))
                .sum();
            let end: f64 = after
                .values()
                .map(|values| values.get(&key).copied().unwrap_or(0.0))
                .sum();
            result.insert(key, (end - start).max(0.0));
        }
    }
    result
}

fn raft_term_increments(before: &Scrape, after: &Scrape) -> u64 {
    fn terms(values: &Scrape) -> BTreeMap<String, f64> {
        let mut result = BTreeMap::new();
        for metrics in values.values() {
            for (key, value) in family(metrics, "pepper_namespace_term") {
                result
                    .entry(key.clone())
                    .and_modify(|old: &mut f64| *old = old.max(*value))
                    .or_insert(*value);
            }
        }
        result
    }
    let start = terms(before);
    terms(after)
        .iter()
        .map(|(key, value)| (value - start.get(key).unwrap_or(value)).max(0.0) as u64)
        .sum()
}

fn fio_baselines(
    root: &Path,
    artifacts: &Path,
    runtime: u64,
    size: &str,
) -> Result<BTreeMap<String, f64>> {
    let mut summary = BTreeMap::new();
    fs::create_dir_all(root.join("fio"))?;
    for mode in ["buffered", "durable"] {
        for depth in [1, 8, 32] {
            let path = artifacts.join(format!("fio-{mode}-qd{depth}.json"));
            if !path.exists() {
                let mut command = docker(root);
                command
                    .args(["--profile", "fio", "run", "--rm", "fio"])
                    .arg(format!("--name={mode}-qd{depth}"))
                    .arg(format!("--filename=/bench/fio/{mode}-qd{depth}.dat"))
                    .args(["--rw=write", "--bs=4m"])
                    .arg(format!("--iodepth={depth}"))
                    .args(["--ioengine=libaio"])
                    .arg(format!("--size={size}"))
                    .arg(format!("--runtime={runtime}"))
                    .args([
                        "--time_based=1",
                        "--group_reporting=1",
                        "--output-format=json",
                    ])
                    .arg(if mode == "buffered" {
                        "--direct=0"
                    } else {
                        "--direct=1"
                    });
                if mode == "durable" {
                    command.arg("--fdatasync=1");
                }
                fs::write(&path, run_command(&mut command)?.stdout)?;
                let _ = fs::remove_file(root.join("fio").join(format!("{mode}-qd{depth}.dat")));
            }
            let report: Value = serde_json::from_slice(&fs::read(path)?)?;
            summary.insert(
                format!("{mode}_qd{depth}"),
                report["jobs"][0]["write"]["bw_bytes"]
                    .as_f64()
                    .unwrap_or(0.0),
            );
        }
    }
    Ok(summary)
}

fn nearest_qd(concurrency: usize) -> usize {
    [1usize, 8, 32]
        .into_iter()
        .min_by_key(|depth| depth.abs_diff(concurrency))
        .unwrap_or(1)
}

fn unix_time() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub async fn run(args: MatrixArgs) -> Result<()> {
    let matrix_path = args
        .matrix
        .clone()
        .unwrap_or_else(|| here().join("matrix.toml"));
    let matrix: Matrix = toml::from_str(&fs::read_to_string(matrix_path)?)?;
    ensure!(
        args.duration >= matrix.minimum_duration_seconds || args.allow_short,
        "duration must be at least {} seconds",
        matrix.minimum_duration_seconds
    );
    if let Some(at) = args.restart_leader_at_seconds {
        ensure!(
            at > 0 && at < args.duration,
            "leader restart must occur within the cell duration"
        );
        ensure!(
            args.leader_outage_seconds > 0,
            "leader outage must be greater than zero"
        );
    }
    let sizes = filter_numbers(&args.sizes, &matrix.object_sizes)?;
    let concurrencies = filter_numbers(&args.concurrency, &matrix.concurrency)?;
    let routings = filter_strings(&args.routing, &matrix.routing)?;
    let topologies = filter_strings(&args.topologies, &matrix.topologies)?;
    let mut storage_engine_choices = matrix.storage_engines.clone();
    if args
        .storage_engines
        .as_deref()
        .is_some_and(|selected| selected.split(',').any(|engine| engine == "files-direct"))
    {
        storage_engine_choices.push("files-direct".to_string());
    }
    let storage_engines = filter_strings(&args.storage_engines, &storage_engine_choices)?;
    let operations = filter_strings(&args.operations, &matrix.operations)?;
    let payload_profiles = payload_profiles(&args.payload_profiles, &matrix.payload_profiles)?;
    let erasure_transfer_plans =
        erasure_transfer_plans(&args.erasure_transfer_plans, &matrix.erasure_transfer_plans)?;
    let gateway_capacities_mbps = filter_numbers(
        &args.gateway_capacities_mbps,
        &matrix.gateway_capacities_mbps,
    )?;
    let cold_bytes = if args.cold_bytes == 0 {
        (mem_total()? as f64 * matrix.cold_dataset_memory_ratio) as u64
    } else {
        args.cold_bytes
    };
    let mut cells = Vec::new();
    for storage_engine in &storage_engines {
        for topology in &topologies {
            // The raw topology is a direct local-filesystem ceiling and has
            // no Pepper engine. Include it once even when comparing engines.
            if topology == "raw" && storage_engine != &storage_engines[0] {
                continue;
            }
            let topology_plans = if topology == "nine-ec" {
                erasure_transfer_plans.clone()
            } else {
                vec!["not-applicable".to_string()]
            };
            for erasure_transfer_plan in &topology_plans {
                // Apply the same physical link shape to both adaptive and
                // forced plans. Otherwise a forced-plan comparison silently
                // removes the bottleneck that the adaptive selector is meant
                // to respond to and cannot establish whether its choice was
                // actually better.
                let plan_capacities = if topology == "nine-ec" {
                    gateway_capacities_mbps.clone()
                } else {
                    vec![0]
                };
                for gateway_capacity_mbps in &plan_capacities {
                    for size in &sizes {
                        for concurrency in &concurrencies {
                            for routing in &routings {
                                for operation in &operations {
                                    for payload_profile in &payload_profiles {
                                        if topology != "raw" || routing == "leader" {
                                            cells.push(Cell {
                                                topology: topology.clone(),
                                                storage_engine: if topology == "raw" {
                                                    "raw-local".to_string()
                                                } else {
                                                    storage_engine.clone()
                                                },
                                                size: *size,
                                                concurrency: *concurrency,
                                                routing: routing.clone(),
                                                operation: operation.clone(),
                                                payload_profile: payload_profile.clone(),
                                                erasure_transfer_plan: erasure_transfer_plan
                                                    .clone(),
                                                gateway_capacity_mbps: *gateway_capacity_mbps,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if args.dry_run {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"cells": cells.len(),
            "minimum_runtime_seconds": cells.len() as u64 * args.duration, "cold_bytes": cold_bytes}))?
        );
        return Ok(());
    }
    let requested_root = args
        .root
        .as_deref()
        .context("--root is required for a benchmark run; select a dedicated XFS data mount")?;
    let root = prepare_benchmark_root(requested_root)?;
    for name in [
        "single", "single2", "single3", "node1", "node2", "node3", "ec1", "ec2", "ec3", "ec4",
        "ec5", "ec6", "ec7", "ec8", "ec9", "control", "raw", "fio",
    ] {
        let path = root.join(name);
        fs::create_dir_all(&path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o777))?;
    }
    let fs_type = String::from_utf8(
        run_command(
            Command::new("findmnt")
                .args(["-n", "-o", "FSTYPE", "-T"])
                .arg(&root),
        )?
        .stdout,
    )?
    .trim()
    .to_string();
    ensure!(
        fs_type.eq_ignore_ascii_case("xfs"),
        "benchmark root must be on XFS, found {fs_type:?}"
    );
    let stamp = time::OffsetDateTime::now_utc().format(time::macros::format_description!(
        "[year][month][day]T[hour][minute][second]Z"
    ))?;
    let artifacts = args
        .artifacts
        .clone()
        .unwrap_or_else(|| root.join("artifacts").join(stamp));
    fs::create_dir_all(artifacts.join("cells"))?;
    let prepared_root = root.join(".prepared");
    fs::create_dir_all(&prepared_root)?;
    let diff = Command::new("git")
        .args(["diff", "--binary"])
        .output()?
        .stdout;
    let docker_version = String::from_utf8(
        run_command(Command::new("docker").args(["version", "--format", "{{.Server.Version}}"]))?
            .stdout,
    )?
    .trim()
    .to_string();
    let manifest = json!({"schema_version": 1, "started_at": time::OffsetDateTime::now_utc().to_string(),
        "root": root, "filesystem": fs_type, "cold_bytes": cold_bytes,
        "duration_seconds": args.duration, "cell_count": cells.len(), "git_commit": git_output(&["rev-parse", "HEAD"]),
        "s3_retries": args.s3_retries,
        "git_diff_sha256": hex::encode(Sha256::digest(diff)), "benchmark_source_sha256": sha256_tree(&here())?,
        "host": {"kernel": program_output("uname", &["-r"]), "cpu_model": cpu_model(),
            "logical_cpus": std::thread::available_parallelism().map(usize::from).unwrap_or(1), "memory_bytes": mem_total()?,
            "rust": program_output("rustc", &["--version"]), "docker": docker_version},
        "restart_leader_at_seconds": args.restart_leader_at_seconds,
        "leader_outage_seconds": args.leader_outage_seconds,
        "matrix": {"object_sizes": sizes, "concurrency": concurrencies, "routing": routings,
            "topologies": topologies, "storage_engines": storage_engines,
            "operations": operations, "payload_profiles": payload_profiles,
            "erasure_transfer_plans": erasure_transfer_plans,
            "gateway_capacities_mbps": gateway_capacities_mbps}});
    fs::write(
        artifacts.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)? + "\n",
    )?;
    let fio = if args.skip_fio {
        BTreeMap::new()
    } else {
        fio_baselines(&root, &artifacts, args.fio_runtime, &args.fio_size)?
    };
    fs::write(
        artifacts.join("fio-summary.json"),
        serde_json::to_string_pretty(&fio)? + "\n",
    )?;
    let client = reqwest::Client::new();
    let max_concurrency = concurrencies.iter().copied().max().unwrap_or(1) as u64;
    let mut current = String::new();
    let mut prepared = BTreeSet::new();
    let mut built = BTreeSet::new();
    let result = async {
        for (cell_index, cell) in cells.iter().enumerate() {
            let target = format!(
                "{}:{}:{}:{}",
                cell.storage_engine,
                cell.topology,
                cell.erasure_transfer_plan,
                cell.gateway_capacity_mbps
            );
            if target != current {
                stop_topology(&root);
                if cell.topology != "raw" {
                    prepare_runtime_configs(
                        &root,
                        &cell.storage_engine,
                        &cell.erasure_transfer_plan,
                        cell.gateway_capacity_mbps,
                    )?;
                }
                if !args.no_build && built.insert(cell.topology.clone()) {
                    build_topology(&cell.topology, &root)?;
                }
                let engine_marker = root.join(format!(".storage-engine-{}", cell.topology));
                let engine_changed = cell.topology != "raw"
                    && fs::read_to_string(&engine_marker)
                        .map(|value| {
                            value.trim()
                                != format!(
                                    "{}:{}:{}",
                                    cell.storage_engine,
                                    cell.erasure_transfer_plan,
                                    cell.gateway_capacity_mbps
                                )
                        })
                        .unwrap_or(true);
                if args.fresh || engine_changed {
                    reset_data(&cell.topology, &root)?;
                    for entry in fs::read_dir(&prepared_root)? {
                        let path = entry?.path();
                        if path.file_name().is_some_and(|name| name.to_string_lossy().starts_with(&format!("{}-{}-", cell.storage_engine, cell.topology))) { fs::remove_file(path)?; }
                    }
                } else if args.clear_reconstructed_cache {
                    clear_reconstructed_cache(&cell.topology, &root)?;
                }
                if cell.topology != "raw" {
                    fs::write(
                        &engine_marker,
                        format!(
                            "{}:{}:{}\n",
                            cell.storage_engine,
                            cell.erasure_transfer_plan,
                            cell.gateway_capacity_mbps
                        ),
                    )?;
                }
                start_topology(&client, &cell.topology, &root).await?;
                current = target;
                if cell.topology != "raw" {
                    let endpoints = topology_endpoints(&cell.topology); ensure_bucket(&endpoints)?; wait_quorum(&client, &endpoints).await?;
                }
            }
            let cell_id = format!("{}-{}-{}-gw{}-s{}-c{}-{}-{}-{}", cell.storage_engine, cell.topology, cell.erasure_transfer_plan, cell.gateway_capacity_mbps, cell.size, cell.concurrency, cell.routing, cell.operation, cell.payload_profile);
            let output = artifacts.join("cells").join(format!("{cell_id}.json"));
            if output.exists() { println!("[{}/{}] resume: {cell_id}", cell_index + 1, cells.len()); continue; }
            let object_count = max_concurrency.max(cold_bytes.div_ceil(cell.size));
            let needs_data = matches!(cell.operation.as_str(), "get" | "range-get" | "head" | "list" | "mixed");
            let marker = prepared_root.join(format!("{}-{}-{}-{}-{}-{}-{object_count}", cell.storage_engine, cell.topology, cell.erasure_transfer_plan, cell.gateway_capacity_mbps, cell.size, cell.payload_profile));
            if marker.exists() { prepared.insert((cell.storage_engine.clone(), cell.topology.clone(), cell.erasure_transfer_plan.clone(), cell.gateway_capacity_mbps, cell.size, cell.payload_profile.clone())); }
            if needs_data && !prepared.contains(&(cell.storage_engine.clone(), cell.topology.clone(), cell.erasure_transfer_plan.clone(), cell.gateway_capacity_mbps, cell.size, cell.payload_profile.clone())) {
                println!("[{}/{}] preload {} size={} objects={object_count}", cell_index + 1, cells.len(), cell.topology, cell.size);
                let mut command = loadgen_command()?;
                command.args(["--backend", if cell.topology == "raw" { "raw" } else { "s3" }, "--operation", "put",
                    "--size", &cell.size.to_string(), "--concurrency", &cell.concurrency.min(32).to_string(), "--duration", "1",
                    "--allow-short", "--object-count", &object_count.to_string(), "--prepare", "--prepare-only", "--quiet"]);
                command.args(["--payload-profile", &cell.payload_profile]);
                if cell.topology == "raw" { command.args(["--raw-root"]).arg(root.join("raw")); }
                else { command.args(["--endpoints", &topology_endpoints(&cell.topology).join(",")]); }
                run_command(&mut command)?;
                prepared.insert((cell.storage_engine.clone(), cell.topology.clone(), cell.erasure_transfer_plan.clone(), cell.gateway_capacity_mbps, cell.size, cell.payload_profile.clone()));
                fs::write(marker, serde_json::to_vec(&json!({"storage_engine": cell.storage_engine, "topology": cell.topology, "erasure_transfer_plan": cell.erasure_transfer_plan, "gateway_capacity_mbps": cell.gateway_capacity_mbps, "size": cell.size, "objects": object_count}))?)?;
            }
            if needs_data
                && cell.topology != "raw"
                && cell.storage_engine != "files-direct"
                && cell.size <= BENCHMARK_SMALL_OBJECT_MAX_BYTES
            {
                settle_small_object_pack(&client, &topology_endpoints(&cell.topology)).await?;
            }
            let endpoints = routed_endpoints(&client, &cell.topology, &cell.routing, &topology_endpoints(&cell.topology)).await;
            let loadgen_output = output.with_extension("loadgen.json");
            let log = fs::File::create(output.with_extension("log"))?;
            let mut command = loadgen_command()?;
            command.args(["--backend", if cell.topology == "raw" { "raw" } else { "s3" }, "--operation", &cell.operation,
                "--size", &cell.size.to_string(), "--concurrency", &cell.concurrency.to_string(), "--duration", &args.duration.to_string(),
                "--object-count", &object_count.to_string(), "--range-bytes", &matrix.range_bytes.to_string(), "--retries", &args.s3_retries.to_string(), "--output"])
                .arg(&loadgen_output).arg("--quiet");
            command.args(["--payload-profile", &cell.payload_profile]);
            if args.allow_short { command.arg("--allow-short"); }
            if cell.topology == "raw" { command.arg("--raw-root").arg(root.join("raw")); }
            else { command.args(["--endpoints", &endpoints.join(",")]); }
            command.stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log));
            let pids = container_pids(&cell.topology, &root)?;
            let metrics_endpoints = topology_endpoints(&cell.topology);
            let (metrics_before, raw_before) = scrape(&client, &metrics_endpoints).await;
            let disk_before = block_stats(&root)?;
            let storage_files_before = storage_file_count(&root, &cell.topology)?;
            let cpu_before = host_cpu()?; let ticks_before = proc_ticks(&pids);
            println!("[{}/{}] run {cell_id}", cell_index + 1, cells.len());
            let started = Instant::now();
            let mut child = command.spawn()?;
            let mut samples = Vec::new();
            let mut previous_terms = BTreeMap::new();
            let mut term_changes = 0;
            let mut fault_event = None;
            loop {
                if let Some(status) = child.try_wait()? {
                    ensure!(status.success(), "load generator failed for {cell_id}; see {}", output.with_extension("log").display());
                    break;
                }
                let (metrics, _) = scrape(&client, &metrics_endpoints).await;
                if fault_event.is_none()
                    && args.restart_leader_at_seconds.is_some_and(|at| {
                        started.elapsed() >= Duration::from_secs(at)
                    })
                    && cell.topology != "raw"
                {
                    let leader = bucket_leader_index(&client, &metrics_endpoints)
                        .await
                        .unwrap_or_else(|| namespace_leader_index(&metrics));
                    let services = topology_services(&cell.topology);
                    let service = services.get(leader).context("leader service is missing")?;
                    let stopped_at = started.elapsed().as_secs_f64();
                    run_command(docker(&root).args(["stop", "-t", "1", service]))?;
                    tokio::time::sleep(Duration::from_secs(args.leader_outage_seconds)).await;
                    run_command(docker(&root).args(["start", service]))?;
                    fault_event = Some(json!({
                        "kind": "leader_failover",
                        "service": service,
                        "stopped_at_seconds": stopped_at,
                        "restarted_at_seconds": started.elapsed().as_secs_f64(),
                        "outage_seconds": args.leader_outage_seconds,
                    }));
                }
                let terms = metrics.iter().flat_map(|(endpoint, values)| family(values, "pepper_namespace_term").map(move |(key, value)| (format!("{endpoint}{key}"), *value))).collect::<BTreeMap<_, _>>();
                term_changes += terms.iter().filter(|(key, value)| previous_terms.get(*key).is_some_and(|old| old != *value)).count() as u64;
                previous_terms = terms;
                let max_log_lag = metrics.values().flat_map(|values| family(values, "pepper_namespace_log_lag").map(|(_, value)| *value)).fold(0.0, f64::max);
                samples.push(Sample { time: unix_time(), process_ticks: proc_ticks(&pids), disk: block_stats(&root).unwrap_or_default(),
                    term_changes, max_log_lag, quorum_unhealthy: unhealthy_quorum_count(&metrics) });
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            let elapsed = started.elapsed().as_secs_f64();
            let cpu_after = host_cpu()?; let ticks_after = proc_ticks(&pids); let disk_after = block_stats(&root)?;
            let storage_files_after = storage_file_count(&root, &cell.topology)?;
            let (metrics_after, raw_after) = scrape(&client, &metrics_endpoints).await;
            let mut report: Value = serde_json::from_slice(&fs::read(&loadgen_output)?)?;
            let logical = report["results"]["logical_bytes"].as_u64().unwrap_or(0);
            let disk = disk_delta(&disk_before, &disk_after, elapsed);
            let physical_write_bytes = disk["write_bytes"].as_u64().unwrap_or(0);
            let total = cpu_after.iter().sum::<u64>().saturating_sub(cpu_before.iter().sum());
            let idle = cpu_after.get(3..5).unwrap_or(&[]).iter().sum::<u64>().saturating_sub(cpu_before.get(3..5).unwrap_or(&[]).iter().sum());
            let tick_rate = String::from_utf8(run_command(Command::new("getconf").arg("CLK_TCK"))?.stdout)?.trim().parse::<f64>()?;
            let metrics_delta = aggregate_metrics(&metrics_before, &metrics_after);
            let mut phase_averages = serde_json::Map::new();
            for phase in PHASES {
                let duration = metrics_delta.get(&format!("pepper_s3_put_phase_duration_microseconds_total{{phase=\"{phase}\"}}")).copied().unwrap_or(0.0);
                let count = metrics_delta.get(&format!("pepper_s3_put_phase_observations_total{{phase=\"{phase}\"}}")).copied().unwrap_or(0.0);
                phase_averages.insert((*phase).to_string(), if count > 0.0 { json!(duration / count) } else { Value::Null });
            }
            let qd = nearest_qd(cell.concurrency); let fio_rate = fio.get(&format!("durable_qd{qd}")).copied().unwrap_or(0.0);
            report["matrix"] = json!({"topology": cell.topology, "storage_engine": cell.storage_engine, "erasure_transfer_plan": cell.erasure_transfer_plan, "gateway_capacity_mbps": cell.gateway_capacity_mbps, "routing": cell.routing, "cell_id": cell_id});
            report["telemetry"] = json!({"block_devices": disk_before.keys().collect::<Vec<_>>(),
                "host_cpu_percent": if total > 0 { 100.0 * (total - idle) as f64 / total as f64 } else { 0.0 },
                "pepper_cpu_cores": ticks_after.saturating_sub(ticks_before) as f64 / tick_rate / elapsed,
                "storage_files_before": storage_files_before,
                "storage_files_after": storage_files_after,
                "storage_files_delta": i128::from(storage_files_after) - i128::from(storage_files_before),
                "disk": disk, "write_amplification": if logical > 0 { Some(physical_write_bytes as f64 / logical as f64) } else { None },
                "raft_term_changes": samples.last().map_or(0, |sample| sample.term_changes),
                "raft_term_increments": raft_term_increments(&metrics_before, &metrics_after),
                "max_log_lag": samples.iter().map(|sample| sample.max_log_lag).fold(0.0, f64::max),
                "quorum_unhealthy_samples": samples.iter().map(|sample| sample.quorum_unhealthy).sum::<usize>(),
                "fault_event": fault_event,
                "metrics_delta": metrics_delta, "put_phase_average_microseconds": phase_averages,
                "raft_commit_latency_microseconds_avg": phase_averages.get("raft_namespace_publication")});
            report["efficiency"] = json!({"fio_queue_depth": qd, "durability_fio_bytes_per_second": fio_rate,
                "pepper_over_fio": if fio_rate > 0.0 { report["results"]["logical_mb_per_second"].as_f64().map(|rate| rate * 1e6 / fio_rate) } else { None }});
            fs::write(&output, serde_json::to_string_pretty(&report)? + "\n")?;
            fs::write(output.with_extension("metrics-before.prom"), raw_before.values().cloned().collect::<Vec<_>>().join("\n"))?;
            fs::write(output.with_extension("metrics-after.prom"), raw_after.values().cloned().collect::<Vec<_>>().join("\n"))?;
            fs::write(output.with_extension("samples.json"), serde_json::to_string_pretty(&samples)? + "\n")?;
            if cell.topology != "raw" {
                let mut logs = docker(&root);
                logs.args(["logs", "--no-color"]);
                for service in topology_services(&cell.topology) {
                    logs.arg(service);
                }
                let logs = run_command(&mut logs)?;
                let mut combined = logs.stdout;
                combined.extend_from_slice(&logs.stderr);
                fs::write(output.with_extension("cluster.log"), combined)?;
            }
            fs::remove_file(loadgen_output)?;
        }
        Ok(())
    }.await;
    stop_topology(&root);
    if result.is_ok() && !args.retain_data {
        for topology in &topologies {
            reclaim_data(topology, &root).with_context(|| {
                format!("failed to reclaim {topology} benchmark data after a successful run")
            })?;
        }
        if prepared_root.exists() {
            fs::remove_dir_all(&prepared_root)?;
        }
    }
    result
}
