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
    "pepper_cpu_cores",
    "host_cpu_percent",
    "disk_read_mb_per_second",
    "disk_write_mb_per_second",
    "disk_busy_percent",
    "write_amplification",
    "raft_commit_latency_microseconds_avg",
    "raft_term_changes",
    "raft_term_increments",
    "max_log_lag",
    "quorum_unhealthy_samples",
    "rpc_bytes",
    "rpc_errors",
    "merkle_nodes_written",
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
            field(&report, &["telemetry", "raft_term_changes"]),
            field(&report, &["telemetry", "raft_term_increments"]),
            field(&report, &["telemetry", "max_log_lag"]),
            field(&report, &["telemetry", "quorum_unhealthy_samples"]),
            (metric("pepper_rpc_request_bytes_total") + metric("pepper_rpc_response_bytes_total"))
                .to_string(),
            metric("pepper_rpc_errors_total").to_string(),
            metric("pepper_merkle_nodes_written_total").to_string(),
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
