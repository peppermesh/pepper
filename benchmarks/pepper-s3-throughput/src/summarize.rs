// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use clap::Args;
use serde_json::Value;
use std::{fs, path::PathBuf};

const FIELDS: &[&str] = &[
    "cell_id",
    "topology",
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
    "raft_commit_latency_microseconds_avg",
    "namespace_read_latency_microseconds_avg",
    "raft_term_changes",
    "raft_term_increments",
    "max_log_lag",
    "quorum_unhealthy_samples",
    "rpc_bytes",
    "storage_read_bytes",
    "storage_read_amplification",
    "logical_to_internal_byte_amplification",
    "rpc_errors",
    "merkle_nodes_written",
    "erasure_stripes_compressed",
    "erasure_encoded_ratio",
    "erasure_encoding_microseconds_avg",
    "erasure_shard_read_hedges",
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
        let erasure_logical = metric("pepper_erasure_stripe_logical_bytes_total");
        let erasure_encoded = metric("pepper_erasure_stripe_encoded_bytes_total");
        let erasure_stripes = metric("pepper_erasure_stripes_encoded_total");
        let erasure_encoding_micros = metric("pepper_erasure_stripe_encoding_microseconds_total");
        let cache_hits = metric("pepper_reconstructed_cache_requests_total{result=\"hit\"}");
        let cache_misses = metric("pepper_reconstructed_cache_requests_total{result=\"miss\"}");
        let logical_bytes = at(&report, &["results", "logical_bytes"])
            .and_then(Value::as_u64)
            .unwrap_or(0) as f64;
        let rpc_bytes =
            metric("pepper_rpc_request_bytes_total") + metric("pepper_rpc_response_bytes_total");
        let storage_read_bytes = metric("pepper_storage_block_read_bytes_total");
        let namespace_reads = metric("pepper_namespace_reads_total");
        let namespace_read_micros = metric("pepper_namespace_read_latency_microseconds_total");
        let values = [
            field(&report, &["matrix", "cell_id"]),
            field(&report, &["matrix", "topology"]),
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
            rpc_bytes.to_string(),
            storage_read_bytes.to_string(),
            if logical_bytes > 0.0 {
                (storage_read_bytes / logical_bytes).to_string()
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
