// SPDX-License-Identifier: Apache-2.0

//! Normalizers reducing per-driver measurement output to one cell result.
//!
//! Every driver output — the S3 loadgen report, the Kafka perf-tool summary
//! line, or the SQLite benchmark report — reduces to [`Measurement`], the
//! only shape the ratio and gate computation understands.

use crate::schema::ResultParser;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct LatencyMs {
    pub mean: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub max: f64,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Measurement {
    pub elapsed_seconds: f64,
    pub operations_per_second: f64,
    /// Logical payload throughput; zero when a driver does not report it.
    pub logical_mb_per_second: f64,
    pub latency_ms: LatencyMs,
    pub failure_rate: f64,
}

pub fn parse_measurement(parser: ResultParser, raw: &str) -> Result<Measurement> {
    match parser {
        ResultParser::S3LoadgenJson => parse_s3_loadgen(raw),
        ResultParser::KafkaPerfStdout => parse_kafka_producer_perf(raw),
        ResultParser::KafkaConsumerPerfStdout => parse_kafka_consumer_perf(raw),
        ResultParser::SqliteBenchmarkJson => parse_sqlite_benchmark(raw),
        ResultParser::ParityJson => {
            serde_json::from_str(raw).context("failed to parse normalized parity JSON")
        }
    }
}

#[derive(Debug, Deserialize)]
struct S3LoadgenReport {
    schema_version: u32,
    results: S3LoadgenResults,
}

#[derive(Debug, Deserialize)]
struct S3LoadgenResults {
    elapsed_seconds: f64,
    failure_rate: f64,
    logical_mb_per_second: f64,
    operations_per_second: f64,
    latency_ms: S3LoadgenLatency,
}

#[derive(Debug, Deserialize)]
struct S3LoadgenLatency {
    mean: f64,
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
}

/// Loadgen report schema versions whose result fields this parser reads.
/// Version 6 is current; older retained reports back to version 1 share the
/// same `results` shape.
const S3_LOADGEN_SCHEMA_VERSIONS: std::ops::RangeInclusive<u32> = 1..=6;

fn parse_s3_loadgen(raw: &str) -> Result<Measurement> {
    let report: S3LoadgenReport =
        serde_json::from_str(raw).context("failed to parse s3 loadgen report JSON")?;
    if !S3_LOADGEN_SCHEMA_VERSIONS.contains(&report.schema_version) {
        bail!(
            "unsupported s3 loadgen report schema version {}",
            report.schema_version
        );
    }
    Ok(Measurement {
        elapsed_seconds: report.results.elapsed_seconds,
        operations_per_second: report.results.operations_per_second,
        logical_mb_per_second: report.results.logical_mb_per_second,
        latency_ms: LatencyMs {
            mean: report.results.latency_ms.mean,
            p50: report.results.latency_ms.p50,
            p95: report.results.latency_ms.p95,
            p99: report.results.latency_ms.p99,
            max: report.results.latency_ms.max,
        },
        failure_rate: report.results.failure_rate,
    })
}

/// Parse the final summary line of `kafka-producer-perf-test`:
///
/// ```text
/// 1000000 records sent, 249938.0 records/sec (238.36 MB/sec), 2.50 ms avg
/// latency, 150.00 ms max latency, 2 ms 50th, 3 ms 95th, 4 ms 99th, 10 ms 99.9th.
/// ```
fn parse_kafka_producer_perf(raw: &str) -> Result<Measurement> {
    let line = raw
        .lines()
        .rev()
        .find(|line| line.contains("records sent") && line.contains("records/sec"))
        .ok_or_else(|| anyhow!("no kafka producer perf summary line found"))?;
    let records: u64 = leading_number(line)?.0 as u64;
    let records_per_second = number_before(line, " records/sec")?;
    let mb_per_second = number_before(line, " MB/sec")?;
    let mean = number_before(line, " ms avg latency")?;
    let max = number_before(line, " ms max latency")?;
    let p50 = number_before(line, " ms 50th")?;
    let p95 = number_before(line, " ms 95th")?;
    let p99 = number_before(line, " ms 99th")?;
    if records_per_second <= 0.0 {
        bail!("kafka producer perf reported non-positive throughput");
    }
    Ok(Measurement {
        elapsed_seconds: records as f64 / records_per_second,
        operations_per_second: records_per_second,
        logical_mb_per_second: mb_per_second,
        latency_ms: LatencyMs {
            mean,
            p50,
            p95,
            p99,
            max,
        },
        failure_rate: 0.0,
    })
}

/// Parse `kafka-consumer-perf-test` CSV output:
///
/// ```text
/// start.time, end.time, data.consumed.in.MB, MB.sec, data.consumed.in.nMsg, nMsg.sec, ...
/// 2026-08-08 12:00:00:000, 2026-08-08 12:01:00:100, 1024.0000, 17.0667, 1048576, 17476.2667, ...
/// ```
///
/// The tool reports no latency percentiles; latency fields are zero and the
/// report gates consume cells on throughput only.
fn parse_kafka_consumer_perf(raw: &str) -> Result<Measurement> {
    let mut lines = raw.lines();
    let header = lines
        .by_ref()
        .find(|line| line.contains("start.time") && line.contains("nMsg.sec"))
        .ok_or_else(|| anyhow!("no kafka consumer perf header found"))?;
    let columns: Vec<&str> = header.split(',').map(str::trim).collect();
    let mb_sec_index = columns
        .iter()
        .position(|column| *column == "MB.sec")
        .ok_or_else(|| anyhow!("MB.sec column missing from consumer perf header"))?;
    let msg_count_index = columns
        .iter()
        .position(|column| *column == "data.consumed.in.nMsg")
        .ok_or_else(|| anyhow!("data.consumed.in.nMsg column missing"))?;
    let msg_sec_index = columns
        .iter()
        .position(|column| *column == "nMsg.sec")
        .ok_or_else(|| anyhow!("nMsg.sec column missing from consumer perf header"))?;
    let data = lines
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| anyhow!("no kafka consumer perf data row found"))?;
    let fields: Vec<&str> = data.split(',').map(str::trim).collect();
    if fields.len() != columns.len() {
        bail!(
            "consumer perf data row has {} fields, header has {}",
            fields.len(),
            columns.len()
        );
    }
    let mb_per_second: f64 = fields[mb_sec_index]
        .parse()
        .context("invalid MB.sec value")?;
    let messages: f64 = fields[msg_count_index]
        .parse()
        .context("invalid data.consumed.in.nMsg value")?;
    let messages_per_second: f64 = fields[msg_sec_index]
        .parse()
        .context("invalid nMsg.sec value")?;
    if messages_per_second <= 0.0 {
        bail!("kafka consumer perf reported non-positive throughput");
    }
    Ok(Measurement {
        elapsed_seconds: messages / messages_per_second,
        operations_per_second: messages_per_second,
        logical_mb_per_second: mb_per_second,
        latency_ms: LatencyMs {
            mean: 0.0,
            p50: 0.0,
            p95: 0.0,
            p99: 0.0,
            max: 0.0,
        },
        failure_rate: 0.0,
    })
}

fn leading_number(line: &str) -> Result<(f64, usize)> {
    let end = line
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(line.len());
    let value = line[..end]
        .parse::<f64>()
        .with_context(|| format!("no leading number in {line:?}"))?;
    Ok((value, end))
}

fn number_before(line: &str, marker: &str) -> Result<f64> {
    let position = line
        .find(marker)
        .ok_or_else(|| anyhow!("marker {marker:?} not found in kafka perf output"))?;
    let prefix = &line[..position];
    let start = prefix
        .rfind(|character: char| !character.is_ascii_digit() && character != '.')
        .map(|index| index + 1)
        .unwrap_or(0);
    prefix[start..]
        .parse::<f64>()
        .with_context(|| format!("no number before {marker:?}"))
}

#[derive(Debug, Deserialize)]
struct SqliteBenchmarkReport {
    schema_version: u32,
    backends: Vec<SqliteBackendReport>,
}

#[derive(Debug, Deserialize)]
struct SqliteBackendReport {
    backend: String,
    workloads: Vec<SqliteWorkloadReport>,
}

#[derive(Debug, Deserialize)]
struct SqliteWorkloadReport {
    name: String,
    elapsed_seconds: f64,
    throughput_operations_per_second: f64,
    latency_microseconds: SqliteLatency,
}

#[derive(Debug, Deserialize)]
struct SqliteLatency {
    p50: f64,
    p95: f64,
    p99: f64,
    maximum: f64,
    mean: f64,
}

/// The SQLite benchmark reports several named workloads per backend. The
/// harness maps a cell operation to a workload name and the target name to a
/// backend, so the raw input here is pre-filtered by the runner into
/// `{"backend": ..., "workload": ..., "report": <full JSON>}`.
#[derive(Debug, Deserialize)]
struct SqliteSelection {
    backend: String,
    workload: String,
    report: serde_json::Value,
}

fn parse_sqlite_benchmark(raw: &str) -> Result<Measurement> {
    let selection: SqliteSelection =
        serde_json::from_str(raw).context("failed to parse sqlite benchmark selection")?;
    let report: SqliteBenchmarkReport = serde_json::from_value(selection.report)
        .context("failed to parse sqlite benchmark report JSON")?;
    if report.schema_version != 1 {
        bail!(
            "unsupported sqlite benchmark schema version {}",
            report.schema_version
        );
    }
    let backend = report
        .backends
        .iter()
        .find(|backend| backend.backend == selection.backend)
        .ok_or_else(|| anyhow!("backend {} not present in report", selection.backend))?;
    let workload = backend
        .workloads
        .iter()
        .find(|workload| workload.name == selection.workload)
        .ok_or_else(|| {
            anyhow!(
                "workload {} not present for backend {}",
                selection.workload,
                selection.backend
            )
        })?;
    Ok(Measurement {
        elapsed_seconds: workload.elapsed_seconds,
        operations_per_second: workload.throughput_operations_per_second,
        logical_mb_per_second: 0.0,
        latency_ms: LatencyMs {
            mean: workload.latency_microseconds.mean / 1000.0,
            p50: workload.latency_microseconds.p50 / 1000.0,
            p95: workload.latency_microseconds.p95 / 1000.0,
            p99: workload.latency_microseconds.p99 / 1000.0,
            max: workload.latency_microseconds.maximum / 1000.0,
        },
        failure_rate: 0.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_loadgen_report_normalizes() {
        let raw = r#"{
            "schema_version": 6,
            "started_at": "2026-08-08T00:00:00Z",
            "config": {},
            "results": {
                "elapsed_seconds": 60.2,
                "attempts": 1000,
                "successes": 1000,
                "failures": 0,
                "retries": 2,
                "failure_rate": 0.0,
                "logical_bytes": 1048576000,
                "logical_mb_per_second": 412.5,
                "operations_per_second": 412.5,
                "latency_ms": {"mean": 19.2, "p50": 17.8, "p95": 30.1, "p99": 44.0, "max": 91.5, "total": 12000.0},
                "http_status_counts": {},
                "error_counts": {},
                "final_error_counts": {}
            }
        }"#;
        let measurement =
            parse_measurement(ResultParser::S3LoadgenJson, raw).expect("report parses");
        assert_eq!(measurement.operations_per_second, 412.5);
        assert_eq!(measurement.latency_ms.p99, 44.0);
    }

    #[test]
    fn kafka_producer_perf_summary_normalizes() {
        let raw = "warmup noise\n\
            250000 records sent, 49876.2 records/sec (47.56 MB/sec), 2.50 ms avg latency, 150.00 ms max latency, 2 ms 50th, 3 ms 95th, 4 ms 99th, 10 ms 99.9th.\n";
        let measurement =
            parse_measurement(ResultParser::KafkaPerfStdout, raw).expect("summary parses");
        assert_eq!(measurement.operations_per_second, 49876.2);
        assert_eq!(measurement.logical_mb_per_second, 47.56);
        assert_eq!(measurement.latency_ms.p50, 2.0);
        assert_eq!(measurement.latency_ms.p99, 4.0);
        assert_eq!(measurement.latency_ms.max, 150.0);
    }

    #[test]
    fn kafka_perf_without_summary_is_rejected() {
        assert!(parse_measurement(ResultParser::KafkaPerfStdout, "no summary here").is_err());
    }

    #[test]
    fn kafka_consumer_perf_csv_normalizes_without_latency() {
        let raw = "start.time, end.time, data.consumed.in.MB, MB.sec, data.consumed.in.nMsg, nMsg.sec, rebalance.time.ms, fetch.time.ms, fetch.MB.sec, fetch.nMsg.sec\n\
            2026-08-08 12:00:00:000, 2026-08-08 12:01:00:100, 1024.0000, 17.0667, 1048576, 17476.2667, 500, 59500, 17.2101, 17623.1234\n";
        let measurement =
            parse_measurement(ResultParser::KafkaConsumerPerfStdout, raw).expect("csv parses");
        assert_eq!(measurement.operations_per_second, 17476.2667);
        assert_eq!(measurement.logical_mb_per_second, 17.0667);
        assert_eq!(measurement.latency_ms.p99, 0.0);
        assert!((measurement.elapsed_seconds - 60.0).abs() < 0.1);
    }

    #[test]
    fn kafka_consumer_perf_field_mismatch_is_rejected() {
        let raw = "start.time, end.time, data.consumed.in.MB, MB.sec, data.consumed.in.nMsg, nMsg.sec\n\
            2026-08-08 12:00:00:000, 1024.0000, 17.0667\n";
        assert!(parse_measurement(ResultParser::KafkaConsumerPerfStdout, raw).is_err());
    }

    #[test]
    fn sqlite_selection_normalizes_microseconds_to_milliseconds() {
        let raw = r#"{
            "backend": "pepper",
            "workload": "point_reads",
            "report": {
                "schema_version": 1,
                "backends": [{
                    "backend": "pepper",
                    "workloads": [{
                        "name": "point_reads",
                        "elapsed_seconds": 12.5,
                        "throughput_operations_per_second": 8000.0,
                        "latency_microseconds": {"minimum": 50.0, "p50": 110.0, "p95": 240.0, "p99": 400.0, "maximum": 1200.0, "mean": 130.0}
                    }]
                }]
            }
        }"#;
        let measurement =
            parse_measurement(ResultParser::SqliteBenchmarkJson, raw).expect("selection parses");
        assert_eq!(measurement.operations_per_second, 8000.0);
        assert_eq!(measurement.latency_ms.p99, 0.4);
    }

    #[test]
    fn parity_json_round_trips() {
        let measurement = Measurement {
            elapsed_seconds: 60.0,
            operations_per_second: 100.0,
            logical_mb_per_second: 100.0,
            latency_ms: LatencyMs {
                mean: 1.0,
                p50: 1.0,
                p95: 2.0,
                p99: 3.0,
                max: 9.0,
            },
            failure_rate: 0.0,
        };
        let encoded = serde_json::to_string(&measurement).expect("encode");
        let decoded = parse_measurement(ResultParser::ParityJson, &encoded).expect("decode");
        assert_eq!(decoded, measurement);
    }
}
