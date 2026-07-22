// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use clap::Args;
use serde_json::Value;
use std::{fs, path::PathBuf};

const FIELDS: &[&str] = &[
    "cell_id",
    "topology",
    "storage_engine",
    "erasure_transfer_plan",
    "gateway_capacity_mbps",
    "erasure_selected_plan_counts",
    "routing",
    "operation",
    "object_size_bytes",
    "concurrency",
    "logical_mb_per_second",
    "operations_per_second",
    "latency_p50_ms",
    "latency_p95_ms",
    "latency_p99_ms",
    "failure_rate",
    "retries",
    "pepper_cpu_cores",
    "host_cpu_percent",
    "disk_read_mb_per_second",
    "disk_write_mb_per_second",
    "disk_busy_percent",
    "write_amplification",
    "storage_files_before",
    "storage_files_after",
    "storage_files_delta",
    "data_durability_barriers",
    "directory_durability_barriers",
    "durability_barriers_per_success",
    "raft_commit_latency_microseconds_avg",
    "namespace_read_latency_microseconds_avg",
    "raft_term_changes",
    "raft_term_increments",
    "max_log_lag",
    "quorum_unhealthy_samples",
    "provider_discovery_requests",
    "placement_calculations",
    "placement_direct_target_attempts",
    "placement_direct_target_errors",
    "placement_direct_target_bytes",
    "placement_exception_hits",
    "placement_map_refreshes",
    "placement_map_refresh_failures",
    "repair_inventory_events",
    "repair_inventory_push_errors",
    "repair_health_batches",
    "repair_health_blocks",
    "repair_health_batch_errors",
    "repair_owner_runs",
    "repair_standby_deferrals",
    "repair_leases_acquired",
    "repair_lease_renewals",
    "repair_lease_conflicts",
    "repair_fence_rejections",
    "repair_tasks_started",
    "repair_tasks_completed",
    "repair_tasks_already_healthy",
    "repair_task_errors",
    "repair_destination_reconstructions",
    "repair_temporary_exceptions",
    "repair_stale_extras_collected",
    "partition_routes",
    "list_barriers",
    "list_partitions_scanned",
    "partition_reconfigurations",
    "fast_path_dispatches",
    "fast_path_rejections",
    "fast_path_owner_failovers",
    "fast_path_cross_core_hops",
    "fast_path_queue_microseconds",
    "fast_path_execution_microseconds",
    "fast_path_buffer_hit_rate",
    "control_connections",
    "bulk_connections",
    "control_streams",
    "bulk_streams",
    "control_transport_errors",
    "bulk_transport_errors",
    "control_cancellations",
    "bulk_cancellations",
    "bulk_bytes_sent",
    "bulk_bytes_received",
    "bulk_throttle_microseconds",
    "rpc_bytes",
    "storage_read_bytes",
    "storage_read_amplification",
    "packed_block_writes",
    "packed_block_write_bytes",
    "packed_block_reads",
    "packed_block_read_bytes",
    "small_pack_extents",
    "small_pack_extent_bytes",
    "small_pack_records",
    "small_pack_logical_bytes",
    "small_pack_extents_compacted",
    "small_pack_records_compacted",
    "small_pack_bytes_reclaimed",
    "small_pack_index_hits",
    "small_pack_index_misses",
    "small_pack_failures",
    "native_writes",
    "native_write_bytes",
    "native_reads",
    "native_read_bytes",
    "native_durability_barriers",
    "native_durability_groups",
    "native_durability_group_requests",
    "native_durability_group_average",
    "native_io_uring_submissions",
    "native_sync_fallbacks",
    "native_torn_tails",
    "native_compactions",
    "native_compacted_bytes",
    "native_internal_write_amplification",
    "logical_to_internal_byte_amplification",
    "rpc_errors",
    "merkle_nodes_written",
    "erasure_stripes_compressed",
    "erasure_encoded_ratio",
    "erasure_encoding_microseconds_avg",
    "erasure_shard_read_hedges",
    "erasure_plan_selected",
    "erasure_plan_completed",
    "erasure_plan_failures",
    "erasure_plan_fallbacks",
    "erasure_plan_completion_microseconds_avg",
    "erasure_plan_logical_bytes",
    "erasure_plan_gateway_bytes",
    "erasure_plan_internal_bytes",
    "erasure_plan_cross_domain_bytes",
    "erasure_plan_gateway_byte_amplification",
    "erasure_plan_internal_byte_amplification",
    "erasure_plan_cross_domain_byte_amplification",
    "reconstructed_cache_hits",
    "reconstructed_cache_misses",
    "reconstructed_cache_hit_rate",
    "s3_write_admission_rejections",
    "s3_write_admission_queue_microseconds",
    "s3_http_admission_rejections",
    "efficiency",
];

#[derive(Debug, Args)]
pub struct SummarizeArgs {
    pub artifacts: PathBuf,
    #[arg(long)]
    pub output: Option<PathBuf>,
}

fn at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(value, |current, key| current.get(key))
}

fn field(value: &Value, path: &[&str]) -> String {
    match at(value, path) {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    }
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn raw_metric_sum(path: &std::path::Path, name: &str, labels: &[&str]) -> f64 {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.rsplit_once(char::is_whitespace))
        .filter(|(key, _)| {
            (*key == name || key.starts_with(&format!("{name}{{")))
                && labels.iter().all(|label| key.contains(label))
        })
        .filter_map(|(_, value)| value.trim().parse::<f64>().ok())
        .sum()
}

pub fn run(args: SummarizeArgs) -> Result<()> {
    let cells = args.artifacts.join("cells");
    let output = args
        .output
        .unwrap_or_else(|| args.artifacts.join("summary.csv"));
    let mut paths = fs::read_dir(&cells)
        .with_context(|| format!("failed to read {}", cells.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
                && !path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().ends_with(".samples.json"))
        })
        .collect::<Vec<_>>();
    paths.sort();
    let mut rows = Vec::with_capacity(paths.len() + 1);
    rows.push(FIELDS.join(","));
    for path in paths {
        let report: Value = serde_json::from_slice(&fs::read(&path)?)?;
        let metrics = at(&report, &["telemetry", "metrics_delta"]);
        let metric = |name: &str| {
            metrics
                .and_then(|value| value.get(name))
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
        };
        let raw_delta = |name: &str, labels: &[&str]| {
            let before = raw_metric_sum(&path.with_extension("metrics-before.prom"), name, labels);
            let after = raw_metric_sum(&path.with_extension("metrics-after.prom"), name, labels);
            (after - before).max(0.0)
        };
        let erasure_logical = metric("pepper_erasure_stripe_logical_bytes_total");
        let erasure_encoded = metric("pepper_erasure_stripe_encoded_bytes_total");
        let erasure_stripes = metric("pepper_erasure_stripes_encoded_total");
        let erasure_encoding_micros = metric("pepper_erasure_stripe_encoding_microseconds_total");
        let cache_hits = metric("pepper_reconstructed_cache_requests_total{result=\"hit\"}");
        let cache_misses = metric("pepper_reconstructed_cache_requests_total{result=\"miss\"}");
        let logical_bytes = at(&report, &["results", "logical_bytes"])
            .and_then(Value::as_u64)
            .unwrap_or(0) as f64;
        let successes = at(&report, &["results", "successes"])
            .and_then(Value::as_u64)
            .unwrap_or(0) as f64;
        let data_durability_barriers = metric("pepper_storage_data_durability_barriers_total");
        let directory_durability_barriers =
            metric("pepper_storage_directory_durability_barriers_total");
        let rpc_bytes =
            metric("pepper_rpc_request_bytes_total") + metric("pepper_rpc_response_bytes_total");
        let storage_read_bytes = metric("pepper_storage_block_read_bytes_total");
        let namespace_reads = metric("pepper_namespace_reads_total");
        let namespace_read_micros = metric("pepper_namespace_read_latency_microseconds_total");
        let transfer_plan = field(&report, &["matrix", "erasure_transfer_plan"]);
        let transfer_plan_label = format!("plan=\"{transfer_plan}\"");
        let plan_delta = |name: &str| {
            if transfer_plan == "adaptive" {
                raw_delta(name, &[])
            } else {
                raw_delta(name, &[transfer_plan_label.as_str()])
            }
        };
        let selected_plan_counts = [
            "gateway-fanout",
            "distributed-parity",
            "hierarchical",
            "pipelined",
        ]
        .into_iter()
        .filter_map(|plan| {
            let label = format!("plan=\"{plan}\"");
            let count = raw_delta(
                "pepper_erasure_transfer_plan_selected_total",
                &[label.as_str()],
            );
            (count > 0.0).then(|| format!("{plan}:{count}"))
        })
        .collect::<Vec<_>>()
        .join(";");
        let plan_selected = plan_delta("pepper_erasure_transfer_plan_selected_total");
        let plan_completed = plan_delta("pepper_erasure_transfer_plan_completed_total");
        let plan_failures = plan_delta("pepper_erasure_transfer_plan_failures_total");
        let plan_fallbacks = plan_delta("pepper_erasure_transfer_plan_fallback_total");
        let plan_completion =
            plan_delta("pepper_erasure_transfer_plan_completion_microseconds_total");
        let plan_logical = plan_delta("pepper_erasure_transfer_plan_logical_bytes_total");
        let plan_gateway = plan_delta("pepper_erasure_transfer_plan_gateway_bytes_total");
        let plan_internal = plan_delta("pepper_erasure_transfer_plan_internal_bytes_total");
        let plan_cross = plan_delta("pepper_erasure_transfer_plan_cross_domain_bytes_total");
        let values = [
            field(&report, &["matrix", "cell_id"]),
            field(&report, &["matrix", "topology"]),
            field(&report, &["matrix", "storage_engine"]),
            transfer_plan,
            field(&report, &["matrix", "gateway_capacity_mbps"]),
            selected_plan_counts,
            field(&report, &["matrix", "routing"]),
            field(&report, &["config", "operation"]),
            field(&report, &["config", "object_size_bytes"]),
            field(&report, &["config", "concurrency"]),
            field(&report, &["results", "logical_mb_per_second"]),
            field(&report, &["results", "operations_per_second"]),
            field(&report, &["results", "latency_ms", "p50"]),
            field(&report, &["results", "latency_ms", "p95"]),
            field(&report, &["results", "latency_ms", "p99"]),
            field(&report, &["results", "failure_rate"]),
            field(&report, &["results", "retries"]),
            field(&report, &["telemetry", "pepper_cpu_cores"]),
            field(&report, &["telemetry", "host_cpu_percent"]),
            field(&report, &["telemetry", "disk", "read_mb_per_second"]),
            field(&report, &["telemetry", "disk", "write_mb_per_second"]),
            field(&report, &["telemetry", "disk", "busy_percent"]),
            field(&report, &["telemetry", "write_amplification"]),
            field(&report, &["telemetry", "storage_files_before"]),
            field(&report, &["telemetry", "storage_files_after"]),
            field(&report, &["telemetry", "storage_files_delta"]),
            data_durability_barriers.to_string(),
            directory_durability_barriers.to_string(),
            if successes > 0.0 {
                ((data_durability_barriers + directory_durability_barriers) / successes).to_string()
            } else {
                String::new()
            },
            field(
                &report,
                &["telemetry", "raft_commit_latency_microseconds_avg"],
            ),
            if namespace_reads > 0.0 {
                (namespace_read_micros / namespace_reads).to_string()
            } else {
                String::new()
            },
            field(&report, &["telemetry", "raft_term_changes"]),
            field(&report, &["telemetry", "raft_term_increments"]),
            field(&report, &["telemetry", "max_log_lag"]),
            field(&report, &["telemetry", "quorum_unhealthy_samples"]),
            raw_delta(
                "pepper_rpc_requests_total",
                &["method=\"/block/providers\"", "direction=\"outbound\""],
            )
            .to_string(),
            raw_delta("pepper_placement_calculations_total", &[]).to_string(),
            raw_delta("pepper_placement_direct_target_attempts_total", &[]).to_string(),
            raw_delta("pepper_placement_direct_target_errors_total", &[]).to_string(),
            raw_delta("pepper_placement_direct_target_bytes_total", &[]).to_string(),
            raw_delta("pepper_placement_exception_hits_total", &[]).to_string(),
            raw_delta("pepper_placement_map_refreshes_total", &[]).to_string(),
            raw_delta("pepper_placement_map_refresh_failures_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_inventory_events_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_inventory_push_errors_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_health_batches_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_health_blocks_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_health_batch_errors_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_owner_runs_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_standby_deferrals_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_leases_acquired_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_lease_renewals_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_lease_conflicts_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_fence_rejections_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_tasks_started_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_tasks_completed_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_tasks_already_healthy_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_task_errors_total", &[]).to_string(),
            raw_delta(
                "pepper_placement_repair_destination_reconstructions_total",
                &[],
            )
            .to_string(),
            raw_delta("pepper_placement_repair_temporary_exceptions_total", &[]).to_string(),
            raw_delta("pepper_placement_repair_stale_extras_collected_total", &[]).to_string(),
            metric("pepper_s3_partition_routes_total").to_string(),
            metric("pepper_s3_list_barriers_total").to_string(),
            metric("pepper_s3_list_partitions_scanned_total").to_string(),
            metric("pepper_s3_partition_reconfigurations_total").to_string(),
            metric("pepper_fast_path_dispatches_total").to_string(),
            metric("pepper_fast_path_rejections_total").to_string(),
            metric("pepper_fast_path_owner_failovers_total").to_string(),
            metric("pepper_fast_path_cross_core_hops_total").to_string(),
            metric("pepper_fast_path_owner_queue_microseconds_total").to_string(),
            metric("pepper_fast_path_owner_execution_microseconds_total").to_string(),
            {
                let hits = metric("pepper_fast_path_owner_buffer_hits_total");
                let misses = metric("pepper_fast_path_owner_buffer_misses_total");
                if hits + misses > 0.0 {
                    (hits / (hits + misses)).to_string()
                } else {
                    String::new()
                }
            },
            metric("pepper_transport_connections_total{lane=\"control\"}").to_string(),
            metric("pepper_transport_connections_total{lane=\"bulk\"}").to_string(),
            metric("pepper_transport_streams_total{lane=\"control\"}").to_string(),
            metric("pepper_transport_streams_total{lane=\"bulk\"}").to_string(),
            metric("pepper_transport_errors_total{lane=\"control\"}").to_string(),
            metric("pepper_transport_errors_total{lane=\"bulk\"}").to_string(),
            metric("pepper_transport_control_cancellations_total").to_string(),
            metric("pepper_transport_bulk_cancellations_total").to_string(),
            metric("pepper_transport_bulk_bytes_total{direction=\"sent\"}").to_string(),
            metric("pepper_transport_bulk_bytes_total{direction=\"received\"}").to_string(),
            metric("pepper_transport_bulk_throttle_microseconds_total").to_string(),
            rpc_bytes.to_string(),
            storage_read_bytes.to_string(),
            if logical_bytes > 0.0 {
                (storage_read_bytes / logical_bytes).to_string()
            } else {
                String::new()
            },
            metric("pepper_storage_packed_block_writes_total").to_string(),
            metric("pepper_storage_packed_block_write_bytes_total").to_string(),
            metric("pepper_storage_packed_block_reads_total").to_string(),
            metric("pepper_storage_packed_block_read_bytes_total").to_string(),
            metric("pepper_small_object_pack_extents_written_total").to_string(),
            metric("pepper_small_object_pack_extent_bytes_total").to_string(),
            metric("pepper_small_object_pack_records_transitioned_total").to_string(),
            metric("pepper_small_object_pack_logical_bytes_transitioned_total").to_string(),
            metric("pepper_small_object_pack_extents_compacted_total").to_string(),
            metric("pepper_small_object_pack_records_compacted_total").to_string(),
            metric("pepper_small_object_pack_bytes_reclaimed_total").to_string(),
            metric("pepper_small_object_pack_index_hits_total").to_string(),
            metric("pepper_small_object_pack_index_misses_total").to_string(),
            metric("pepper_small_object_pack_failures_total").to_string(),
            metric("pepper_storage_native_writes_total").to_string(),
            metric("pepper_storage_native_write_bytes_total").to_string(),
            metric("pepper_storage_native_reads_total").to_string(),
            metric("pepper_storage_native_read_bytes_total").to_string(),
            metric("pepper_storage_native_durability_barriers_total").to_string(),
            metric("pepper_storage_native_durability_groups_total").to_string(),
            metric("pepper_storage_native_durability_group_requests_total").to_string(),
            {
                let groups = metric("pepper_storage_native_durability_groups_total");
                if groups > 0.0 {
                    (metric("pepper_storage_native_durability_group_requests_total") / groups)
                        .to_string()
                } else {
                    String::new()
                }
            },
            metric("pepper_storage_native_io_uring_submissions_total").to_string(),
            metric("pepper_storage_native_sync_fallbacks_total").to_string(),
            metric("pepper_storage_native_torn_tails_total").to_string(),
            metric("pepper_storage_native_compactions_total").to_string(),
            metric("pepper_storage_native_compacted_bytes_total").to_string(),
            if logical_bytes > 0.0 {
                (metric("pepper_storage_native_write_bytes_total") / logical_bytes).to_string()
            } else {
                String::new()
            },
            if logical_bytes > 0.0 {
                ((storage_read_bytes + rpc_bytes) / logical_bytes).to_string()
            } else {
                String::new()
            },
            metric("pepper_rpc_errors_total").to_string(),
            metric("pepper_merkle_nodes_written_total").to_string(),
            metric("pepper_erasure_stripes_compressed_total").to_string(),
            if erasure_logical > 0.0 {
                (erasure_encoded / erasure_logical).to_string()
            } else {
                String::new()
            },
            if erasure_stripes > 0.0 {
                (erasure_encoding_micros / erasure_stripes).to_string()
            } else {
                String::new()
            },
            metric("pepper_erasure_shard_read_hedges_total").to_string(),
            plan_selected.to_string(),
            plan_completed.to_string(),
            plan_failures.to_string(),
            plan_fallbacks.to_string(),
            if plan_completed > 0.0 {
                (plan_completion / plan_completed).to_string()
            } else {
                String::new()
            },
            plan_logical.to_string(),
            plan_gateway.to_string(),
            plan_internal.to_string(),
            plan_cross.to_string(),
            if plan_logical > 0.0 {
                (plan_gateway / plan_logical).to_string()
            } else {
                String::new()
            },
            if plan_logical > 0.0 {
                (plan_internal / plan_logical).to_string()
            } else {
                String::new()
            },
            if plan_logical > 0.0 {
                (plan_cross / plan_logical).to_string()
            } else {
                String::new()
            },
            cache_hits.to_string(),
            cache_misses.to_string(),
            if cache_hits + cache_misses > 0.0 {
                (cache_hits / (cache_hits + cache_misses)).to_string()
            } else {
                String::new()
            },
            metric("pepper_s3_write_admission_rejections_total").to_string(),
            metric("pepper_s3_write_admission_queue_microseconds_total").to_string(),
            metric("pepper_s3_http_admission_rejections_total").to_string(),
            field(&report, &["efficiency", "pepper_over_fio"]),
        ];
        debug_assert_eq!(values.len(), FIELDS.len());
        rows.push(
            values
                .iter()
                .map(|value| csv_escape(value))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, rows.join("\n") + "\n")?;
    println!("wrote {} rows to {}", rows.len() - 1, output.display());
    Ok(())
}
