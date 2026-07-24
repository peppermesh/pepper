// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{process::Command, time::timeout};

#[derive(Debug, Parser)]
#[command(name = "pepper-phase0")]
#[command(about = "Capture reproducible Pepper/Kafka architecture baseline artifacts")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Validate a suite without executing its cases.
    Validate {
        #[arg(long)]
        suite: PathBuf,
    },
    /// Execute a suite and write a self-checking artifact directory.
    Run {
        #[arg(long)]
        suite: PathBuf,
        #[arg(long)]
        output_directory: PathBuf,
        #[arg(long)]
        allow_dirty: bool,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Suite {
    schema_version: u32,
    name: String,
    environment_label: String,
    #[serde(default)]
    required_environment: Vec<String>,
    #[serde(default)]
    metrics: Vec<MetricSource>,
    cases: Vec<Case>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MetricSource {
    name: String,
    url: String,
    #[serde(default = "default_true")]
    required: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    product: Product,
    command: Vec<String>,
    #[serde(default = "default_one")]
    repetitions: u32,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    #[serde(default)]
    environment: BTreeMap<String, String>,
    /// Every string must occur in stdout for a repetition to pass.
    #[serde(default)]
    required_stdout: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Product {
    Storage,
    Network,
    Consensus,
    S3,
    Filesystem,
    Sqlite,
    KafkaComparator,
    Model,
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    suite: Suite,
    started_at_unix_millis: u128,
    finished_at_unix_millis: u128,
    source: SourceState,
    host: HostSnapshot,
    before_metrics: Vec<MetricCapture>,
    after_metrics: Vec<MetricCapture>,
    cases: Vec<CaseReport>,
    success: bool,
}

#[derive(Debug, Serialize)]
struct SourceState {
    revision: String,
    branch: String,
    dirty: bool,
    cargo_lock_sha256: String,
}

#[derive(Debug, Serialize)]
struct HostSnapshot {
    operating_system: String,
    architecture: String,
    logical_cpus: usize,
    rustc: CommandCapture,
    uname: CommandCapture,
    lscpu: CommandCapture,
    lsblk: CommandCapture,
    findmnt: CommandCapture,
    proc_meminfo: String,
    proc_cpuinfo: String,
    proc_diskstats: String,
    proc_net_dev: String,
}

#[derive(Debug, Serialize)]
struct CommandCapture {
    available: bool,
    success: bool,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Serialize)]
struct MetricCapture {
    name: String,
    url: String,
    required: bool,
    success: bool,
    status: Option<u16>,
    body: String,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct CaseReport {
    name: String,
    product: Product,
    repetitions: Vec<RepetitionReport>,
    success: bool,
}

#[derive(Debug, Serialize)]
struct RepetitionReport {
    repetition: u32,
    command: Vec<String>,
    started_at_unix_millis: u128,
    duration_millis: u128,
    exit_code: Option<i32>,
    timed_out: bool,
    stdout_file: String,
    stderr_file: String,
    stdout_sha256: String,
    stderr_sha256: String,
    required_stdout_matches: bool,
    before_system: SystemCounters,
    after_system: SystemCounters,
}

#[derive(Debug, Serialize)]
struct SystemCounters {
    proc_stat: String,
    proc_meminfo: String,
    proc_diskstats: String,
    proc_net_dev: String,
}

#[derive(Debug, Serialize)]
struct ArtifactHash {
    path: String,
    sha256: String,
    bytes: u64,
}

fn default_true() -> bool {
    true
}

fn default_one() -> u32 {
    1
}

fn default_timeout() -> u64 {
    900
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Validate { suite } => {
            let suite = load_suite(&suite)?;
            validate_suite(&suite)?;
            println!(
                "suite '{}' is valid with {} cases",
                suite.name,
                suite.cases.len()
            );
            Ok(())
        }
        Commands::Run {
            suite,
            output_directory,
            allow_dirty,
        } => run(&suite, &output_directory, allow_dirty).await,
    }
}

async fn run(suite_path: &Path, output_directory: &Path, allow_dirty: bool) -> Result<()> {
    ensure!(
        !output_directory.exists(),
        "output directory already exists: {}",
        output_directory.display()
    );
    let suite = load_suite(suite_path)?;
    validate_suite(&suite)?;
    validate_environment(&suite.required_environment)?;

    let source = source_state().await?;
    ensure!(
        allow_dirty || !source.dirty,
        "worktree is dirty; commit/stash changes or pass --allow-dirty for exploratory evidence"
    );

    fs::create_dir_all(output_directory)
        .with_context(|| format!("create {}", output_directory.display()))?;
    let started_at_unix_millis = unix_millis()?;
    let host = host_snapshot().await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("build metrics client")?;
    let before_metrics = capture_metrics(&client, &suite.metrics).await;

    let mut cases = Vec::with_capacity(suite.cases.len());
    for (case_index, case) in suite.cases.iter().enumerate() {
        cases.push(run_case(case_index, case, output_directory).await?);
    }

    let after_metrics = capture_metrics(&client, &suite.metrics).await;
    let required_metrics_ok = before_metrics
        .iter()
        .chain(&after_metrics)
        .all(|metric| !metric.required || metric.success);
    let success = required_metrics_ok && cases.iter().all(|case| case.success);
    let report = Report {
        schema_version: 1,
        suite,
        started_at_unix_millis,
        finished_at_unix_millis: unix_millis()?,
        source,
        host,
        before_metrics,
        after_metrics,
        cases,
        success,
    };
    write_json(&output_directory.join("run.json"), &report)?;
    write_artifact_manifest(output_directory)?;
    ensure!(
        success,
        "one or more required metrics or workload cases failed"
    );
    Ok(())
}

fn load_suite(path: &Path) -> Result<Suite> {
    let bytes = fs::read(path).with_context(|| format!("read suite {}", path.display()))?;
    let text = std::str::from_utf8(&bytes).context("suite must be UTF-8")?;
    toml::from_str(text).with_context(|| format!("parse suite {}", path.display()))
}

fn validate_suite(suite: &Suite) -> Result<()> {
    ensure!(suite.schema_version == 1, "unsupported suite schema");
    ensure!(!suite.name.trim().is_empty(), "suite name is empty");
    ensure!(
        !suite.environment_label.trim().is_empty(),
        "environment label is empty"
    );
    ensure!(!suite.cases.is_empty(), "suite has no cases");
    let mut case_names = std::collections::BTreeSet::new();
    for case in &suite.cases {
        ensure!(
            is_safe_name(&case.name),
            "case name '{}' must contain only ASCII alphanumeric, '-', or '_'",
            case.name
        );
        ensure!(
            case_names.insert(case.name.as_str()),
            "duplicate case name '{}'",
            case.name
        );
        ensure!(
            !case.command.is_empty(),
            "case '{}' has no command",
            case.name
        );
        ensure!(
            case.repetitions > 0,
            "case '{}' has zero repetitions",
            case.name
        );
        ensure!(
            case.timeout_seconds > 0,
            "case '{}' has zero timeout",
            case.name
        );
    }
    let mut metric_names = std::collections::BTreeSet::new();
    for metric in &suite.metrics {
        ensure!(
            is_safe_name(&metric.name),
            "metric name '{}' is unsafe",
            metric.name
        );
        ensure!(
            metric_names.insert(metric.name.as_str()),
            "duplicate metric source '{}'",
            metric.name
        );
        ensure!(
            metric.url.starts_with("http://")
                || metric.url.starts_with("https://")
                || metric.url.starts_with("${"),
            "metric source '{}' must use HTTP(S) after environment expansion",
            metric.name
        );
    }
    Ok(())
}

fn validate_environment(required: &[String]) -> Result<()> {
    for name in required {
        ensure!(
            is_environment_name(name),
            "invalid required environment variable name '{name}'"
        );
        ensure!(
            env::var_os(name).is_some(),
            "required environment variable '{name}' is not set"
        );
    }
    Ok(())
}

async fn source_state() -> Result<SourceState> {
    let revision = required_command_output("git", &["rev-parse", "HEAD"]).await?;
    let branch = required_command_output("git", &["branch", "--show-current"]).await?;
    let status = required_command_output("git", &["status", "--porcelain=v1"]).await?;
    Ok(SourceState {
        revision: revision.trim().to_string(),
        branch: branch.trim().to_string(),
        dirty: !status.trim().is_empty(),
        cargo_lock_sha256: sha256_file(Path::new("Cargo.lock"))?,
    })
}

async fn host_snapshot() -> HostSnapshot {
    HostSnapshot {
        operating_system: env::consts::OS.to_string(),
        architecture: env::consts::ARCH.to_string(),
        logical_cpus: std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(0),
        rustc: capture_command("rustc", &["--version", "--verbose"]).await,
        uname: capture_command("uname", &["-a"]).await,
        lscpu: capture_command("lscpu", &["--json"]).await,
        lsblk: capture_command(
            "lsblk",
            &[
                "--json",
                "--output",
                "NAME,TYPE,SIZE,ROTA,PHY-SEC,LOG-SEC,FSTYPE,MOUNTPOINTS,MODEL",
            ],
        )
        .await,
        findmnt: capture_command("findmnt", &["--json"]).await,
        proc_meminfo: read_optional("/proc/meminfo"),
        proc_cpuinfo: read_optional("/proc/cpuinfo"),
        proc_diskstats: read_optional("/proc/diskstats"),
        proc_net_dev: read_optional("/proc/net/dev"),
    }
}

async fn run_case(index: usize, case: &Case, output_directory: &Path) -> Result<CaseReport> {
    let mut repetitions = Vec::with_capacity(case.repetitions as usize);
    for repetition in 1..=case.repetitions {
        let expansion_variables = BTreeMap::from([
            (
                "PEPPER_PHASE0_REPETITION".to_string(),
                repetition.to_string(),
            ),
            ("PEPPER_PHASE0_CASE".to_string(), case.name.clone()),
        ]);
        let command = case
            .command
            .iter()
            .map(|value| expand_environment_with(value, &expansion_variables))
            .collect::<Result<Vec<_>>>()?;
        let mut environment = case
            .environment
            .iter()
            .map(|(name, value)| {
                ensure!(
                    is_environment_name(name),
                    "case '{}' has invalid environment key '{name}'",
                    case.name
                );
                Ok((
                    name.clone(),
                    expand_environment_with(value, &expansion_variables)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        environment.extend(expansion_variables);
        repetitions.push(
            run_repetition(
                index,
                case,
                repetition,
                &command,
                &environment,
                output_directory,
            )
            .await?,
        );
    }
    let success = repetitions
        .iter()
        .all(|run| !run.timed_out && run.exit_code == Some(0) && run.required_stdout_matches);
    Ok(CaseReport {
        name: case.name.clone(),
        product: case.product,
        repetitions,
        success,
    })
}

async fn run_repetition(
    index: usize,
    case: &Case,
    repetition: u32,
    command: &[String],
    environment: &BTreeMap<String, String>,
    output_directory: &Path,
) -> Result<RepetitionReport> {
    let prefix = format!("{index:03}-{}-{repetition:03}", case.name);
    let stdout_name = format!("{prefix}.stdout");
    let stderr_name = format!("{prefix}.stderr");
    let stdout_path = output_directory.join(&stdout_name);
    let stderr_path = output_directory.join(&stderr_name);
    let started_at_unix_millis = unix_millis()?;
    let started = Instant::now();
    let before_system = system_counters();

    let mut process = Command::new(&command[0]);
    process
        .args(&command[1..])
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = timeout(Duration::from_secs(case.timeout_seconds), process.output()).await;

    let duration_millis = started.elapsed().as_millis();
    let after_system = system_counters();
    let (exit_code, timed_out, stdout, stderr) = match output {
        Ok(result) => {
            let result = result.with_context(|| {
                format!("execute case '{}' command '{}'", case.name, command[0])
            })?;
            (result.status.code(), false, result.stdout, result.stderr)
        }
        Err(_) => (
            None,
            true,
            Vec::new(),
            format!("timed out after {} seconds\n", case.timeout_seconds).into_bytes(),
        ),
    };
    fs::write(&stdout_path, &stdout).with_context(|| format!("write {}", stdout_path.display()))?;
    fs::write(&stderr_path, &stderr).with_context(|| format!("write {}", stderr_path.display()))?;
    let stdout_text = String::from_utf8_lossy(&stdout);
    let required_stdout_matches = case
        .required_stdout
        .iter()
        .all(|required| stdout_text.contains(required));
    Ok(RepetitionReport {
        repetition,
        command: command.to_vec(),
        started_at_unix_millis,
        duration_millis,
        exit_code,
        timed_out,
        stdout_file: stdout_name,
        stderr_file: stderr_name,
        stdout_sha256: sha256_bytes(&stdout),
        stderr_sha256: sha256_bytes(&stderr),
        required_stdout_matches,
        before_system,
        after_system,
    })
}

async fn capture_metrics(client: &reqwest::Client, sources: &[MetricSource]) -> Vec<MetricCapture> {
    let mut captures = Vec::with_capacity(sources.len());
    for source in sources {
        let url = match expand_environment(&source.url) {
            Ok(url) => url,
            Err(error) => {
                captures.push(MetricCapture {
                    name: source.name.clone(),
                    url: source.url.clone(),
                    required: source.required,
                    success: false,
                    status: None,
                    body: String::new(),
                    error: Some(error.to_string()),
                });
                continue;
            }
        };
        match client.get(&url).send().await {
            Ok(response) => {
                let status = response.status();
                match response.text().await {
                    Ok(body) => captures.push(MetricCapture {
                        name: source.name.clone(),
                        url,
                        required: source.required,
                        success: status.is_success(),
                        status: Some(status.as_u16()),
                        body,
                        error: None,
                    }),
                    Err(error) => captures.push(MetricCapture {
                        name: source.name.clone(),
                        url,
                        required: source.required,
                        success: false,
                        status: Some(status.as_u16()),
                        body: String::new(),
                        error: Some(error.to_string()),
                    }),
                }
            }
            Err(error) => captures.push(MetricCapture {
                name: source.name.clone(),
                url,
                required: source.required,
                success: false,
                status: None,
                body: String::new(),
                error: Some(error.to_string()),
            }),
        }
    }
    captures
}

fn expand_environment(value: &str) -> Result<String> {
    expand_environment_with(value, &BTreeMap::new())
}

fn expand_environment_with(value: &str, overrides: &BTreeMap<String, String>) -> Result<String> {
    let mut expanded = String::with_capacity(value.len());
    let mut remaining = value;
    while let Some(start) = remaining.find("${") {
        expanded.push_str(&remaining[..start]);
        let variable = &remaining[start + 2..];
        let end = variable
            .find('}')
            .ok_or_else(|| anyhow::anyhow!("unterminated environment expansion in '{value}'"))?;
        let name = &variable[..end];
        ensure!(
            is_environment_name(name),
            "invalid environment variable '{name}'"
        );
        let replacement = match overrides.get(name) {
            Some(value) => value.clone(),
            None => env::var(name)
                .with_context(|| format!("environment variable '{name}' is not set"))?,
        };
        expanded.push_str(&replacement);
        remaining = &variable[end + 1..];
    }
    expanded.push_str(remaining);
    Ok(expanded)
}

fn is_safe_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn is_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn system_counters() -> SystemCounters {
    SystemCounters {
        proc_stat: read_optional("/proc/stat"),
        proc_meminfo: read_optional("/proc/meminfo"),
        proc_diskstats: read_optional("/proc/diskstats"),
        proc_net_dev: read_optional("/proc/net/dev"),
    }
}

fn read_optional(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

async fn required_command_output(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .with_context(|| format!("run {program}"))?;
    ensure!(
        output.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

async fn capture_command(program: &str, args: &[&str]) -> CommandCapture {
    match Command::new(program).args(args).output().await {
        Ok(output) => CommandCapture {
            available: true,
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => CommandCapture {
            available: false,
            success: false,
            stdout: String::new(),
            stderr: error.to_string(),
        },
        Err(error) => CommandCapture {
            available: true,
            success: false,
            stdout: String::new(),
            stderr: error.to_string(),
        },
    }
}

fn unix_millis() -> Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time precedes Unix epoch")?
        .as_millis())
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

fn write_artifact_manifest(output_directory: &Path) -> Result<()> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(output_directory)
        .with_context(|| format!("read {}", output_directory.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || path.file_name().is_some_and(|name| name == "manifest.json") {
            continue;
        }
        let relative = path
            .strip_prefix(output_directory)
            .context("artifact escaped output directory")?
            .to_string_lossy()
            .into_owned();
        entries.push(ArtifactHash {
            path: relative,
            sha256: sha256_file(&path)?,
            bytes: fs::metadata(&path)?.len(),
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    write_json(&output_directory.join("manifest.json"), &entries)
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(sha256_bytes(&bytes))
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn expansion_variables_override_process_environment() {
        let overrides = BTreeMap::from([
            ("PEPPER_PHASE0_REPETITION".to_string(), "7".to_string()),
            ("PEPPER_PHASE0_CASE".to_string(), "filesystem".to_string()),
        ]);

        assert_eq!(
            expand_environment_with(
                "results/${PEPPER_PHASE0_CASE}-${PEPPER_PHASE0_REPETITION}.json",
                &overrides,
            )
            .unwrap(),
            "results/filesystem-7.json"
        );
    }

    #[test]
    fn expansion_rejects_invalid_and_unterminated_names() {
        assert!(expand_environment("${NOT-A-NAME}").is_err());
        assert!(expand_environment("${UNTERMINATED").is_err());
    }

    #[test]
    fn validation_rejects_duplicate_case_names() {
        let case = Case {
            name: "duplicate".to_string(),
            product: Product::Storage,
            command: vec!["true".to_string()],
            repetitions: 1,
            timeout_seconds: 1,
            environment: BTreeMap::new(),
            required_stdout: Vec::new(),
        };
        let suite = Suite {
            schema_version: 1,
            name: "test".to_string(),
            environment_label: "test".to_string(),
            required_environment: Vec::new(),
            metrics: Vec::new(),
            cases: vec![case.clone(), case],
        };

        assert!(validate_suite(&suite).is_err());
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
