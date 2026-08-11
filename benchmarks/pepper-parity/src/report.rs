// SPDX-License-Identifier: Apache-2.0

//! Parity computation and rendering.
//!
//! Ratios always compare the subject (Pepper) against one competitor at the
//! same cell using the median across repetitions. Ceiling targets are
//! rendered but never gated. Cells with excessive failures on either side
//! are invalid rather than pass/fail, so a broken run cannot pass a gate.

use crate::parse::Measurement;
use crate::schema::{Cell, Suite, TargetRole};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CellRecord {
    pub target: String,
    pub cell: Cell,
    pub repetition: u32,
    pub measurement: Measurement,
    /// `passed`, `failed`, or `skipped` when no audit is configured.
    #[serde(default = "default_guarantee_audit")]
    pub guarantee_audit: String,
}

fn default_guarantee_audit() -> String {
    "skipped".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Pass,
    Fail,
    Invalid,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Pass => "pass",
            Self::Fail => "FAIL",
            Self::Invalid => "invalid",
        };
        formatter.write_str(text)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CellComparison {
    pub cell: Cell,
    pub competitor: String,
    pub subject_operations_per_second: f64,
    pub competitor_operations_per_second: f64,
    pub subject_p99_ms: f64,
    pub competitor_p99_ms: f64,
    pub throughput_ratio: f64,
    pub p99_ratio: f64,
    pub verdict: Verdict,
    pub detail: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ParityReport {
    pub schema_version: u32,
    pub suite_title: String,
    pub api: String,
    pub generated_at: String,
    pub comparisons: Vec<CellComparison>,
    pub ceilings: Vec<CellRecord>,
    pub worst_throughput_ratio: Option<f64>,
    pub worst_p99_ratio: Option<f64>,
    pub passed: bool,
    pub summary: String,
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|left, right| left.partial_cmp(right).expect("finite measurements"));
    let count = values.len();
    if count == 0 {
        return f64::NAN;
    }
    if count % 2 == 1 {
        values[count / 2]
    } else {
        (values[count / 2 - 1] + values[count / 2]) / 2.0
    }
}

/// Median operations/second, median p99, worst failure rate, and audit
/// outcome for one (target, cell) across repetitions.
#[derive(Debug)]
struct Aggregate {
    operations_per_second: f64,
    p99_ms: f64,
    failure_rate: f64,
    guarantee_audit: String,
}

#[derive(Debug, Default)]
struct AggregateSamples {
    operations_per_second: Vec<f64>,
    p99_ms: Vec<f64>,
    failure_rates: Vec<f64>,
    guarantee_audit: String,
}

fn aggregate(records: &[CellRecord]) -> BTreeMap<(String, String), Aggregate> {
    let mut grouped: BTreeMap<(String, String), AggregateSamples> = BTreeMap::new();
    for record in records {
        let key = (record.target.clone(), record.cell.slug());
        let entry = grouped.entry(key).or_default();
        if entry.guarantee_audit.is_empty() {
            entry.guarantee_audit = record.guarantee_audit.clone();
        }
        entry
            .operations_per_second
            .push(record.measurement.operations_per_second);
        entry.p99_ms.push(record.measurement.latency_ms.p99);
        entry.failure_rates.push(record.measurement.failure_rate);
        if record.guarantee_audit == "failed" {
            entry.guarantee_audit = "failed".to_string();
        }
    }
    grouped
        .into_iter()
        .map(|(key, mut samples)| {
            let aggregate = Aggregate {
                operations_per_second: median(&mut samples.operations_per_second),
                p99_ms: median(&mut samples.p99_ms),
                failure_rate: samples.failure_rates.iter().copied().fold(0.0f64, f64::max),
                guarantee_audit: samples.guarantee_audit,
            };
            (key, aggregate)
        })
        .collect()
}

pub fn compute(suite: &Suite, records: &[CellRecord]) -> Result<ParityReport> {
    let subject_name = suite.subject().name.clone();
    let aggregated = aggregate(records);
    let gates = &suite.gates;
    let tolerance = gates.tolerance_percent / 100.0;
    let throughput_floor = gates.throughput_ratio_minimum * (1.0 - tolerance);
    let p99_ceiling = gates.p99_ratio_maximum * (1.0 + tolerance);

    let mut comparisons = Vec::new();
    let mut ceilings = Vec::new();
    for record in records {
        let target_role = suite
            .targets
            .iter()
            .find(|target| target.name == record.target)
            .map(|target| target.role);
        if target_role == Some(TargetRole::Ceiling) {
            ceilings.push(record.clone());
        }
    }

    for competitor in suite
        .targets
        .iter()
        .filter(|target| target.role == TargetRole::Competitor)
    {
        for cell in suite.cells() {
            let subject = aggregated.get(&(subject_name.clone(), cell.slug()));
            let peer = aggregated.get(&(competitor.name.clone(), cell.slug()));
            let (Some(subject), Some(peer)) = (subject, peer) else {
                comparisons.push(CellComparison {
                    cell: cell.clone(),
                    competitor: competitor.name.clone(),
                    subject_operations_per_second: subject
                        .map_or(0.0, |value| value.operations_per_second),
                    competitor_operations_per_second: peer
                        .map_or(0.0, |value| value.operations_per_second),
                    subject_p99_ms: subject.map_or(0.0, |value| value.p99_ms),
                    competitor_p99_ms: peer.map_or(0.0, |value| value.p99_ms),
                    throughput_ratio: 0.0,
                    p99_ratio: 0.0,
                    verdict: Verdict::Invalid,
                    detail: "missing measurement".to_string(),
                });
                continue;
            };
            let mut detail = String::new();
            let mut verdict = None;
            if subject.guarantee_audit == "failed" || peer.guarantee_audit == "failed" {
                verdict = Some(Verdict::Invalid);
                detail = "guarantee audit failed".to_string();
            } else if subject.failure_rate > gates.maximum_failure_rate
                || peer.failure_rate > gates.maximum_failure_rate
            {
                verdict = Some(Verdict::Invalid);
                detail = format!(
                    "failure rate above {:.3}% (subject {:.3}%, competitor {:.3}%)",
                    gates.maximum_failure_rate * 100.0,
                    subject.failure_rate * 100.0,
                    peer.failure_rate * 100.0
                );
            } else if peer.operations_per_second <= 0.0 || subject.operations_per_second <= 0.0 {
                verdict = Some(Verdict::Invalid);
                detail = "non-positive throughput measurement".to_string();
            } else if (peer.p99_ms <= 0.0) != (subject.p99_ms <= 0.0) {
                // One driver reported latency and the other did not; the
                // latency gate cannot be compared honestly.
                verdict = Some(Verdict::Invalid);
                detail = "one-sided latency measurement".to_string();
            }
            let throughput_ratio = if peer.operations_per_second > 0.0 {
                subject.operations_per_second / peer.operations_per_second
            } else {
                0.0
            };
            // Drivers without latency percentiles (consumer perf) report
            // zero on both sides; the cell then gates on throughput alone
            // with a neutral latency ratio.
            let p99_ratio = if peer.p99_ms > 0.0 && subject.p99_ms > 0.0 {
                subject.p99_ms / peer.p99_ms
            } else {
                1.0
            };
            let verdict = verdict.unwrap_or_else(|| {
                let throughput_ok = throughput_ratio >= throughput_floor;
                let latency_ok = p99_ratio <= p99_ceiling;
                if throughput_ok && latency_ok {
                    Verdict::Pass
                } else {
                    if !throughput_ok {
                        detail = format!(
                            "throughput ratio {throughput_ratio:.2} below floor {throughput_floor:.2}"
                        );
                    }
                    if !latency_ok {
                        if !detail.is_empty() {
                            detail.push_str("; ");
                        }
                        detail.push_str(&format!(
                            "p99 ratio {p99_ratio:.2} above ceiling {p99_ceiling:.2}"
                        ));
                    }
                    Verdict::Fail
                }
            });
            comparisons.push(CellComparison {
                cell,
                competitor: competitor.name.clone(),
                subject_operations_per_second: subject.operations_per_second,
                competitor_operations_per_second: peer.operations_per_second,
                subject_p99_ms: subject.p99_ms,
                competitor_p99_ms: peer.p99_ms,
                throughput_ratio,
                p99_ratio,
                verdict,
                detail,
            });
        }
    }

    if comparisons.is_empty() {
        bail!("no competitor comparisons could be computed");
    }

    let valid = comparisons
        .iter()
        .filter(|comparison| comparison.verdict != Verdict::Invalid)
        .collect::<Vec<_>>();
    let worst_throughput_ratio = valid
        .iter()
        .map(|comparison| comparison.throughput_ratio)
        .fold(None, |worst: Option<f64>, ratio| {
            Some(worst.map_or(ratio, |value| value.min(ratio)))
        });
    let worst_p99_ratio = valid
        .iter()
        .map(|comparison| comparison.p99_ratio)
        .fold(None, |worst: Option<f64>, ratio| {
            Some(worst.map_or(ratio, |value| value.max(ratio)))
        });
    let failed = comparisons
        .iter()
        .filter(|comparison| comparison.verdict == Verdict::Fail)
        .count();
    let invalid = comparisons
        .iter()
        .filter(|comparison| comparison.verdict == Verdict::Invalid)
        .count();
    let passed = if gates.required {
        failed == 0 && invalid == 0
    } else {
        true
    };
    let summary = format!(
        "{} of {} cells passed, {} failed, {} invalid{}",
        comparisons.len() - failed - invalid,
        comparisons.len(),
        failed,
        invalid,
        if gates.required {
            ""
        } else {
            " (gates informational)"
        }
    );

    Ok(ParityReport {
        schema_version: 1,
        suite_title: suite.title.clone(),
        api: suite.api.to_string(),
        generated_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        comparisons,
        ceilings,
        worst_throughput_ratio,
        worst_p99_ratio,
        passed,
        summary,
    })
}

pub fn render_markdown(report: &ParityReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# {} — {}\n\ngenerated {}\n\n",
        report.suite_title, report.api, report.generated_at
    ));
    out.push_str(
        "| cell | competitor | pepper op/s | competitor op/s | ratio | pepper p99 ms | competitor p99 ms | p99 ratio | verdict | detail |\n",
    );
    out.push_str("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |\n");
    for comparison in &report.comparisons {
        out.push_str(&format!(
            "| {} | {} | {:.1} | {:.1} | {:.2}x | {:.2} | {:.2} | {:.2}x | {} | {} |\n",
            comparison.cell.label(),
            comparison.competitor,
            comparison.subject_operations_per_second,
            comparison.competitor_operations_per_second,
            comparison.throughput_ratio,
            comparison.subject_p99_ms,
            comparison.competitor_p99_ms,
            comparison.p99_ratio,
            comparison.verdict,
            comparison.detail,
        ));
    }
    out.push('\n');
    if let Some(worst) = report.worst_throughput_ratio {
        out.push_str(&format!("worst throughput ratio: {worst:.2}x\n\n"));
    }
    if let Some(worst) = report.worst_p99_ratio {
        out.push_str(&format!("worst p99 ratio: {worst:.2}x\n\n"));
    }
    out.push_str(&format!(
        "suite verdict: {} ({})\n",
        if report.passed { "PASS" } else { "FAIL" },
        report.summary
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{LatencyMs, Measurement};

    fn suite() -> Suite {
        toml::from_str(
            r#"
            version = 1
            api = "s3"
            title = "test parity"

            [[profiles]]
            name = "p"
            fault_tolerance = "single node"

            [[targets]]
            name = "pepper"
            role = "subject"
            profile = "p"
            parser = "parity-json"
            [targets.measure]
            command = ["true"]

            [[targets]]
            name = "minio"
            role = "competitor"
            profile = "p"
            parser = "parity-json"
            [targets.measure]
            command = ["true"]

            [workload]
            operations = ["put"]
            payload_sizes_bytes = [4096]
            concurrency = [8]
            duration_seconds = 60
            repetitions = 3

            [gates]
            throughput_ratio_minimum = 1.0
            p99_ratio_maximum = 1.0
            tolerance_percent = 5.0
            "#,
        )
        .expect("suite parses")
    }

    fn record(target: &str, repetition: u32, ops: f64, p99: f64, failure: f64) -> CellRecord {
        CellRecord {
            target: target.to_string(),
            cell: Cell {
                operation: "put".to_string(),
                payload_size_bytes: 4096,
                concurrency: 8,
            },
            repetition,
            measurement: Measurement {
                elapsed_seconds: 60.0,
                operations_per_second: ops,
                logical_mb_per_second: 0.0,
                latency_ms: LatencyMs {
                    mean: p99 / 2.0,
                    p50: p99 / 2.0,
                    p95: p99 * 0.9,
                    p99,
                    max: p99 * 2.0,
                },
                failure_rate: failure,
            },
            guarantee_audit: "skipped".to_string(),
        }
    }

    #[test]
    fn median_of_repetitions_gates_pass_within_tolerance() {
        let suite = suite();
        // Subject medians: ops 990 (below 1000 but within 5% tolerance),
        // p99 10.4 (above 10 but within tolerance).
        let records = vec![
            record("pepper", 1, 980.0, 10.5, 0.0),
            record("pepper", 2, 990.0, 10.4, 0.0),
            record("pepper", 3, 1000.0, 10.3, 0.0),
            record("minio", 1, 1000.0, 10.0, 0.0),
            record("minio", 2, 1000.0, 10.0, 0.0),
            record("minio", 3, 1000.0, 10.0, 0.0),
        ];
        let report = compute(&suite, &records).expect("report computes");
        assert_eq!(report.comparisons.len(), 1);
        assert_eq!(report.comparisons[0].verdict, Verdict::Pass);
        assert!(report.passed);
        assert!((report.comparisons[0].throughput_ratio - 0.99).abs() < 1e-9);
    }

    #[test]
    fn losing_cell_fails_the_suite_and_is_reported() {
        let suite = suite();
        let records = vec![
            record("pepper", 1, 700.0, 25.0, 0.0),
            record("minio", 1, 1000.0, 10.0, 0.0),
        ];
        let report = compute(&suite, &records).expect("report computes");
        assert_eq!(report.comparisons[0].verdict, Verdict::Fail);
        assert!(!report.passed);
        assert!(report.comparisons[0].detail.contains("throughput ratio"));
        assert!(report.comparisons[0].detail.contains("p99 ratio"));
        let markdown = render_markdown(&report);
        assert!(markdown.contains("suite verdict: FAIL"));
        assert!(markdown.contains("0.70x"));
    }

    #[test]
    fn excessive_failures_invalidate_instead_of_gating() {
        let suite = suite();
        let records = vec![
            record("pepper", 1, 5000.0, 1.0, 0.05),
            record("minio", 1, 1000.0, 10.0, 0.0),
        ];
        let report = compute(&suite, &records).expect("report computes");
        assert_eq!(report.comparisons[0].verdict, Verdict::Invalid);
        assert!(
            !report.passed,
            "invalid cells must not pass a required gate"
        );
    }

    #[test]
    fn missing_competitor_measurement_is_invalid() {
        let suite = suite();
        let records = vec![record("pepper", 1, 1000.0, 10.0, 0.0)];
        let report = compute(&suite, &records).expect("report computes");
        assert_eq!(report.comparisons[0].verdict, Verdict::Invalid);
        assert_eq!(report.comparisons[0].detail, "missing measurement");
    }

    #[test]
    fn latency_free_drivers_gate_on_throughput_alone() {
        let suite = suite();
        let records = vec![
            record("pepper", 1, 1200.0, 0.0, 0.0),
            record("minio", 1, 1000.0, 0.0, 0.0),
        ];
        let report = compute(&suite, &records).expect("report computes");
        assert_eq!(report.comparisons[0].verdict, Verdict::Pass);
        assert_eq!(report.comparisons[0].p99_ratio, 1.0);
    }

    #[test]
    fn one_sided_latency_is_invalid() {
        let suite = suite();
        let records = vec![
            record("pepper", 1, 1200.0, 5.0, 0.0),
            record("minio", 1, 1000.0, 0.0, 0.0),
        ];
        let report = compute(&suite, &records).expect("report computes");
        assert_eq!(report.comparisons[0].verdict, Verdict::Invalid);
        assert_eq!(
            report.comparisons[0].detail,
            "one-sided latency measurement"
        );
    }

    #[test]
    fn failed_guarantee_audit_invalidates_cells() {
        let suite = suite();
        let mut audited = record("minio", 1, 1000.0, 10.0, 0.0);
        audited.guarantee_audit = "failed".to_string();
        let records = vec![record("pepper", 1, 1000.0, 10.0, 0.0), audited];
        let report = compute(&suite, &records).expect("report computes");
        assert_eq!(report.comparisons[0].verdict, Verdict::Invalid);
        assert_eq!(report.comparisons[0].detail, "guarantee audit failed");
    }
}
