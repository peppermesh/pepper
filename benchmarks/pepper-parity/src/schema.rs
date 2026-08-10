// SPDX-License-Identifier: Apache-2.0

//! Versioned parity-suite schema.
//!
//! A suite binds one API to a set of targets, one guarantee profile per
//! target, a workload cell matrix, and parity gates. Unknown fields are
//! rejected so a typo cannot silently weaken a qualification run.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const SUITE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Suite {
    pub version: u32,
    pub api: Api,
    pub title: String,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    pub targets: Vec<Target>,
    pub workload: Workload,
    pub gates: Gates,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Api {
    S3,
    Kafka,
    Sqlite,
    Kv,
    Object,
}

impl std::fmt::Display for Api {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::S3 => "s3",
            Self::Kafka => "kafka",
            Self::Sqlite => "sqlite",
            Self::Kv => "kv",
            Self::Object => "object",
        };
        formatter.write_str(name)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub fault_tolerance: String,
    #[serde(default)]
    pub claims: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetRole {
    /// Pepper itself. Exactly one target per suite.
    Subject,
    /// A same-guarantee peer; parity gates apply.
    Competitor,
    /// An informational ceiling (raw device, local library); never gated.
    Ceiling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResultParser {
    /// `pepper-s3-throughput loadgen --output` report JSON.
    S3LoadgenJson,
    /// `kafka-producer-perf-test` stdout (throughput and latency percentiles).
    KafkaPerfStdout,
    /// `kafka-consumer-perf-test` stdout (throughput only; the tool reports
    /// no latency percentiles, so consume cells gate on throughput alone).
    KafkaConsumerPerfStdout,
    /// `pepper-sqlite-benchmark --output` report JSON.
    SqliteBenchmarkJson,
    /// Already-normalized parity cell-result JSON.
    ParityJson,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub name: String,
    pub role: TargetRole,
    pub profile: String,
    #[serde(default)]
    pub endpoint: String,
    pub parser: ResultParser,
    /// Per-operation parser overrides (e.g. consume cells parsed with the
    /// consumer perf parser while produce cells use the producer parser).
    #[serde(default)]
    pub parser_overrides: BTreeMap<String, ResultParser>,
    #[serde(default)]
    pub lifecycle: Option<Lifecycle>,
    pub measure: Measure,
    /// Optional dedicated warmup command; the measure command with the
    /// warmup duration substituted is used when absent.
    #[serde(default)]
    pub warmup: Option<Measure>,
    /// Optional guarantee audit run once per target after readiness. A
    /// failing audit invalidates every cell of the target in the report.
    #[serde(default)]
    pub audit: Option<Audit>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Audit {
    /// Ordered command steps; the first non-zero exit fails the audit.
    pub steps: Vec<Vec<String>>,
    #[serde(default = "default_audit_timeout_seconds")]
    pub timeout_seconds: u64,
}

fn default_audit_timeout_seconds() -> u64 {
    600
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lifecycle {
    /// Optional bootstrap commands run in order before `up` (e.g. topology
    /// config generation). Commands run without a shell; use `bash -c` for
    /// environment expansion.
    #[serde(default)]
    pub prepare: Vec<Vec<String>>,
    pub up: Vec<String>,
    pub down: Vec<String>,
    #[serde(default)]
    pub ready_url: Option<String>,
    #[serde(default = "default_ready_timeout_seconds")]
    pub ready_timeout_seconds: u64,
}

fn default_ready_timeout_seconds() -> u64 {
    120
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Measure {
    /// Command template. `{operation}`, `{payload_size_bytes}`,
    /// `{concurrency}`, `{duration_seconds}`, `{warmup_seconds}`,
    /// `{endpoint}`, `{output}`, and `{repetition}` are expanded per cell.
    pub command: Vec<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

fn default_timeout_seconds() -> u64 {
    1800
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    pub operations: Vec<String>,
    pub payload_sizes_bytes: Vec<u64>,
    pub concurrency: Vec<usize>,
    pub duration_seconds: u64,
    #[serde(default)]
    pub warmup_seconds: u64,
    #[serde(default = "default_repetitions")]
    pub repetitions: u32,
}

fn default_repetitions() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Gates {
    /// Minimum subject/competitor operations-per-second ratio.
    pub throughput_ratio_minimum: f64,
    /// Maximum subject/competitor p99 latency ratio.
    pub p99_ratio_maximum: f64,
    /// Symmetric tolerance applied to both gates, in percent.
    #[serde(default)]
    pub tolerance_percent: f64,
    /// Maximum failure rate before a cell is invalid instead of gated.
    #[serde(default = "default_maximum_failure_rate")]
    pub maximum_failure_rate: f64,
    #[serde(default = "default_required")]
    pub required: bool,
}

fn default_maximum_failure_rate() -> f64 {
    0.001
}

fn default_required() -> bool {
    true
}

/// One expanded workload cell.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Cell {
    pub operation: String,
    pub payload_size_bytes: u64,
    pub concurrency: usize,
}

impl Cell {
    pub fn label(&self) -> String {
        format!(
            "{} {} c{}",
            self.operation,
            format_bytes(self.payload_size_bytes),
            self.concurrency
        )
    }

    pub fn slug(&self) -> String {
        format!(
            "{}-{}-c{}",
            self.operation, self.payload_size_bytes, self.concurrency
        )
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [(u64, &str); 4] = [
        (1 << 30, "GiB"),
        (1 << 20, "MiB"),
        (1 << 10, "KiB"),
        (1, "B"),
    ];
    for (scale, unit) in UNITS {
        if bytes >= scale && bytes % scale == 0 {
            return format!("{}{unit}", bytes / scale);
        }
    }
    format!("{bytes}B")
}

impl Suite {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read suite {}", path.display()))?;
        let suite: Suite = toml::from_str(&text)
            .with_context(|| format!("failed to parse suite {}", path.display()))?;
        suite
            .validate()
            .with_context(|| format!("invalid suite {}", path.display()))?;
        Ok(suite)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != SUITE_SCHEMA_VERSION {
            bail!(
                "unsupported suite schema version {} (expected {SUITE_SCHEMA_VERSION})",
                self.version
            );
        }
        if self.title.trim().is_empty() {
            bail!("suite title must not be empty");
        }
        let profile_names: BTreeSet<&str> = self
            .profiles
            .iter()
            .map(|profile| profile.name.as_str())
            .collect();
        if profile_names.len() != self.profiles.len() {
            bail!("profile names must be unique");
        }
        let mut target_names = BTreeSet::new();
        let mut subjects = 0usize;
        let mut competitors = 0usize;
        for target in &self.targets {
            if !target_names.insert(target.name.as_str()) {
                bail!("duplicate target name {}", target.name);
            }
            if !profile_names.contains(target.profile.as_str()) {
                bail!(
                    "target {} references unknown profile {}",
                    target.name,
                    target.profile
                );
            }
            if target.measure.command.is_empty() {
                bail!("target {} has an empty measure command", target.name);
            }
            if let Some(warmup) = &target.warmup
                && warmup.command.is_empty()
            {
                bail!("target {} has an empty warmup command", target.name);
            }
            if let Some(audit) = &target.audit
                && (audit.steps.is_empty() || audit.steps.iter().any(Vec::is_empty))
            {
                bail!("target {} has empty guarantee audit steps", target.name);
            }
            match target.role {
                TargetRole::Subject => subjects += 1,
                TargetRole::Competitor => competitors += 1,
                TargetRole::Ceiling => {}
            }
        }
        if subjects != 1 {
            bail!("a suite must define exactly one subject target, found {subjects}");
        }
        if competitors == 0 && self.gates.required {
            bail!("a suite with required gates must define at least one competitor target");
        }
        if self.workload.operations.is_empty()
            || self.workload.payload_sizes_bytes.is_empty()
            || self.workload.concurrency.is_empty()
        {
            bail!("workload operations, payload sizes, and concurrency must be non-empty");
        }
        if self.workload.duration_seconds == 0 {
            bail!("workload duration must be non-zero");
        }
        if self.workload.repetitions == 0 {
            bail!("workload repetitions must be non-zero");
        }
        if self.gates.throughput_ratio_minimum <= 0.0 || self.gates.p99_ratio_maximum <= 0.0 {
            bail!("gate ratios must be positive");
        }
        if !(0.0..=50.0).contains(&self.gates.tolerance_percent) {
            bail!("gate tolerance must be between 0 and 50 percent");
        }
        Ok(())
    }

    pub fn cells(&self) -> Vec<Cell> {
        let mut cells = Vec::new();
        for operation in &self.workload.operations {
            for &payload_size_bytes in &self.workload.payload_sizes_bytes {
                for &concurrency in &self.workload.concurrency {
                    cells.push(Cell {
                        operation: operation.clone(),
                        payload_size_bytes,
                        concurrency,
                    });
                }
            }
        }
        cells
    }

    pub fn parser_for(target: &Target, operation: &str) -> ResultParser {
        target
            .parser_overrides
            .get(operation)
            .copied()
            .unwrap_or(target.parser)
    }

    pub fn subject(&self) -> &Target {
        self.targets
            .iter()
            .find(|target| target.role == TargetRole::Subject)
            .expect("validated suite has exactly one subject")
    }
}

/// Expand `{placeholder}` template fields in a measure command.
pub fn expand_template(
    template: &[String],
    substitutions: &BTreeMap<&str, String>,
) -> Result<Vec<String>> {
    template
        .iter()
        .map(|part| {
            let mut expanded = part.clone();
            for (key, value) in substitutions {
                expanded = expanded.replace(&format!("{{{key}}}"), value);
            }
            if let (Some(start), Some(_)) = (expanded.find('{'), expanded.find('}')) {
                let unresolved: String = expanded[start..].chars().take(32).collect();
                bail!("unresolved template placeholder near {unresolved:?}");
            }
            Ok(expanded)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_suite() -> Suite {
        toml::from_str(
            r#"
            version = 1
            api = "s3"
            title = "test"

            [[profiles]]
            name = "p"
            fault_tolerance = "single node"

            [[targets]]
            name = "pepper"
            role = "subject"
            profile = "p"
            endpoint = "http://127.0.0.1:29080"
            parser = "s3-loadgen-json"
            [targets.measure]
            command = ["true", "{operation}", "{endpoint}", "{output}"]

            [[targets]]
            name = "minio"
            role = "competitor"
            profile = "p"
            endpoint = "http://127.0.0.1:29081"
            parser = "s3-loadgen-json"
            [targets.measure]
            command = ["true", "{operation}", "{endpoint}", "{output}"]

            [workload]
            operations = ["put", "get"]
            payload_sizes_bytes = [4096, 1048576]
            concurrency = [1, 8]
            duration_seconds = 60

            [gates]
            throughput_ratio_minimum = 1.0
            p99_ratio_maximum = 1.0
            tolerance_percent = 5.0
            "#,
        )
        .expect("suite parses")
    }

    #[test]
    fn minimal_suite_validates_and_expands_cells() {
        let suite = minimal_suite();
        suite.validate().expect("suite validates");
        let cells = suite.cells();
        assert_eq!(cells.len(), 8);
        assert_eq!(cells[0].label(), "put 4KiB c1");
        assert_eq!(suite.subject().name, "pepper");
    }

    #[test]
    fn unknown_fields_and_bad_shapes_are_rejected() {
        let mut text = toml::to_string(&minimal_suite()).expect("serialize");
        text.push_str("\nunknown_field = 1\n");
        assert!(toml::from_str::<Suite>(&text).is_err());

        let mut no_subject = minimal_suite();
        no_subject.targets[0].role = TargetRole::Ceiling;
        assert!(no_subject.validate().is_err());

        let mut duplicate = minimal_suite();
        duplicate.targets[1].name = "pepper".to_string();
        assert!(duplicate.validate().is_err());

        let mut bad_profile = minimal_suite();
        bad_profile.targets[1].profile = "missing".to_string();
        assert!(bad_profile.validate().is_err());

        let mut zero_duration = minimal_suite();
        zero_duration.workload.duration_seconds = 0;
        assert!(zero_duration.validate().is_err());
    }

    #[test]
    fn template_expansion_resolves_all_placeholders_or_fails() {
        let substitutions = BTreeMap::from([
            ("operation", "put".to_string()),
            ("endpoint", "http://127.0.0.1:1".to_string()),
            ("output", "/tmp/out.json".to_string()),
        ]);
        let expanded = expand_template(
            &[
                "run".to_string(),
                "--operation".to_string(),
                "{operation}".to_string(),
                "{endpoint}".to_string(),
                "{output}".to_string(),
            ],
            &substitutions,
        )
        .expect("expansion succeeds");
        assert_eq!(expanded[2], "put");

        let error = expand_template(&["{missing}".to_string()], &substitutions);
        assert!(error.is_err());
    }

    #[test]
    fn byte_formatting_uses_exact_units() {
        assert_eq!(format_bytes(4096), "4KiB");
        assert_eq!(format_bytes(1048576), "1MiB");
        assert_eq!(format_bytes(5000), "5000B");
        assert_eq!(format_bytes(1 << 30), "1GiB");
    }
}
