// SPDX-License-Identifier: Apache-2.0

//! Suite execution: target lifecycle, per-cell measurement, artifact layout.
//!
//! Targets run strictly sequentially — never concurrently — so competitor
//! and subject measurements see the same quiet host. Every expanded command
//! and its complete output are retained under the artifact directory.

use crate::parse::parse_measurement;
use crate::report::CellRecord;
use crate::schema::{Cell, ResultParser, Suite, Target, expand_template};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

pub struct RunOptions {
    pub suite_path: PathBuf,
    pub output_directory: PathBuf,
    pub targets: Option<Vec<String>>,
    pub keep_targets_up: bool,
}

#[derive(Debug, Serialize)]
struct RunProvenance {
    schema_version: u32,
    started_at: String,
    suite_path: String,
    suite_sha256: String,
    git_revision: Option<String>,
    git_branch: Option<String>,
    git_dirty: Option<bool>,
    hostname: Option<String>,
    kernel: Option<String>,
}

async fn command_stdout(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .await
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn capture_provenance(suite_path: &Path) -> Result<RunProvenance> {
    let suite_bytes = std::fs::read(suite_path)
        .with_context(|| format!("failed to read suite {}", suite_path.display()))?;
    Ok(RunProvenance {
        schema_version: 1,
        started_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        suite_path: suite_path.display().to_string(),
        suite_sha256: hex::encode(Sha256::digest(&suite_bytes)),
        git_revision: command_stdout("git", &["rev-parse", "HEAD"]).await,
        git_branch: command_stdout("git", &["rev-parse", "--abbrev-ref", "HEAD"]).await,
        git_dirty: command_stdout("git", &["status", "--porcelain"])
            .await
            .map(|status| !status.is_empty()),
        hostname: command_stdout("hostname", &[]).await,
        kernel: command_stdout("uname", &["-sr"]).await,
    })
}

async fn run_lifecycle_command(command: &[String], label: &str) -> Result<()> {
    let (program, arguments) = command
        .split_first()
        .with_context(|| format!("{label} command is empty"))?;
    let status = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .status()
        .await
        .with_context(|| format!("failed to spawn {label} command {program}"))?;
    if !status.success() {
        bail!("{label} command exited with {status}");
    }
    Ok(())
}

async fn wait_ready(url: &str, timeout_seconds: u64) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("failed to build readiness client")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_seconds);
    loop {
        match client.get(url).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            _ if tokio::time::Instant::now() >= deadline => {
                bail!("target readiness probe {url} did not succeed within {timeout_seconds}s");
            }
            _ => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    }
}

fn cell_substitutions<'a>(
    duration_seconds: u64,
    suite: &Suite,
    target: &Target,
    cell: &Cell,
    repetition: u32,
    output: &Path,
) -> BTreeMap<&'a str, String> {
    BTreeMap::from([
        ("operation", cell.operation.clone()),
        ("payload_size_bytes", cell.payload_size_bytes.to_string()),
        ("object_size_bytes", cell.payload_size_bytes.to_string()),
        ("concurrency", cell.concurrency.to_string()),
        ("duration_seconds", duration_seconds.to_string()),
        ("warmup_seconds", suite.workload.warmup_seconds.to_string()),
        ("endpoint", target.endpoint.clone()),
        ("repetition", repetition.to_string()),
        ("output", output.display().to_string()),
    ])
}

/// Expand and execute one driver command, retaining command/stdout/stderr
/// artifacts, and fail on non-zero exit or timeout.
async fn execute_driver(
    measure: &crate::schema::Measure,
    substitutions: &BTreeMap<&str, String>,
    directory: &Path,
    label: &str,
) -> Result<std::process::Output> {
    std::fs::create_dir_all(directory)
        .with_context(|| format!("failed to create directory {}", directory.display()))?;
    let command = expand_template(&measure.command, substitutions)
        .with_context(|| format!("{label} command"))?;
    std::fs::write(
        directory.join("command.json"),
        serde_json::to_string_pretty(&command)? + "\n",
    )?;
    let (program, arguments) = command
        .split_first()
        .with_context(|| format!("expanded {label} command is empty"))?;
    let mut child = Command::new(program);
    child
        .args(arguments)
        .envs(&measure.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = tokio::time::Instant::now();
    let output = tokio::time::timeout(Duration::from_secs(measure.timeout_seconds), child.output())
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "{label} command timed out after {}s",
                measure.timeout_seconds
            )
        })?
        .with_context(|| format!("failed to run {label} command"))?;
    let elapsed = started.elapsed();
    std::fs::write(directory.join("stdout.txt"), &output.stdout)?;
    std::fs::write(directory.join("stderr.txt"), &output.stderr)?;
    if !output.status.success() {
        bail!(
            "{label} command exited with {} after {:.1}s (artifacts in {})",
            output.status,
            elapsed.as_secs_f64(),
            directory.display()
        );
    }
    Ok(output)
}

/// Run a target's guarantee audit and return `skipped`, `passed`, or
/// `failed`. Audit steps run in order; the first failing step marks the
/// audit failed but does not abort the run — the report invalidates every
/// cell of a target whose audit failed, which is the honest outcome: numbers
/// without the promised guarantee are not comparable.
async fn run_guarantee_audit(target: &Target, audit_directory: &Path) -> Result<String> {
    let Some(audit) = &target.audit else {
        return Ok("skipped".to_string());
    };
    println!("  running guarantee audit ({} steps)", audit.steps.len());
    std::fs::create_dir_all(audit_directory)
        .with_context(|| format!("failed to create {}", audit_directory.display()))?;
    for (index, step) in audit.steps.iter().enumerate() {
        let step_directory = audit_directory.join(format!("step{index}"));
        std::fs::create_dir_all(&step_directory)
            .with_context(|| format!("failed to create {}", step_directory.display()))?;
        std::fs::write(
            step_directory.join("command.json"),
            serde_json::to_string_pretty(step)? + "\n",
        )?;
        let (program, arguments) = step
            .split_first()
            .with_context(|| format!("audit step {index} is empty"))?;
        let mut child = Command::new(program);
        child
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let outcome =
            tokio::time::timeout(Duration::from_secs(audit.timeout_seconds), child.output()).await;
        let failed = match outcome {
            Err(_) => {
                std::fs::write(step_directory.join("stderr.txt"), b"audit step timed out")?;
                true
            }
            Ok(Err(error)) => {
                std::fs::write(step_directory.join("stderr.txt"), error.to_string())?;
                true
            }
            Ok(Ok(output)) => {
                std::fs::write(step_directory.join("stdout.txt"), &output.stdout)?;
                std::fs::write(step_directory.join("stderr.txt"), &output.stderr)?;
                !output.status.success()
            }
        };
        if failed {
            println!("  guarantee audit step {index} failed");
            return Ok("failed".to_string());
        }
    }
    Ok("passed".to_string())
}

/// Run the discarded warmup pass for one cell. The warmup reuses the measure
/// command with the warmup duration substituted unless the target declares a
/// dedicated warmup command.
async fn warmup_cell(
    suite: &Suite,
    target: &Target,
    cell: &Cell,
    cell_directory: &Path,
) -> Result<()> {
    let warmup_directory = cell_directory.join("warmup");
    let output_path = warmup_directory.join("driver-output.json");
    let substitutions = cell_substitutions(
        suite.workload.warmup_seconds,
        suite,
        target,
        cell,
        0,
        &output_path,
    );
    let measure = target.warmup.as_ref().unwrap_or(&target.measure);
    execute_driver(
        measure,
        &substitutions,
        &warmup_directory,
        &format!("warmup for {} {}", target.name, cell.label()),
    )
    .await?;
    Ok(())
}

async fn measure_cell(
    suite: &Suite,
    target: &Target,
    cell: &Cell,
    repetition: u32,
    cell_directory: &Path,
    guarantee_audit: &str,
) -> Result<CellRecord> {
    let output_path = cell_directory.join("driver-output.json");
    let substitutions = cell_substitutions(
        suite.workload.duration_seconds,
        suite,
        target,
        cell,
        repetition,
        &output_path,
    );
    let output = execute_driver(
        &target.measure,
        &substitutions,
        cell_directory,
        &format!("measure for {} {}", target.name, cell.label()),
    )
    .await?;
    let parser = Suite::parser_for(target, &cell.operation);
    let raw = match parser {
        // File-emitting drivers write their report to {output}; stream
        // parsers read stdout.
        ResultParser::S3LoadgenJson
        | ResultParser::SqliteBenchmarkJson
        | ResultParser::ParityJson
            if output_path.exists() =>
        {
            std::fs::read_to_string(&output_path)?
        }
        _ => String::from_utf8_lossy(&output.stdout).to_string(),
    };
    let measurement = parse_measurement(parser, &raw).with_context(|| {
        format!(
            "failed to normalize driver output for {} {} (artifacts in {})",
            target.name,
            cell.label(),
            cell_directory.display()
        )
    })?;
    let record = CellRecord {
        target: target.name.clone(),
        cell: cell.clone(),
        repetition,
        measurement,
        guarantee_audit: guarantee_audit.to_string(),
    };
    std::fs::write(
        cell_directory.join("cell-record.json"),
        serde_json::to_string_pretty(&record)? + "\n",
    )?;
    Ok(record)
}

pub async fn run(options: RunOptions) -> Result<()> {
    let suite = Suite::load(&options.suite_path)?;
    std::fs::create_dir_all(&options.output_directory).with_context(|| {
        format!(
            "failed to create output directory {}",
            options.output_directory.display()
        )
    })?;
    let provenance = capture_provenance(&options.suite_path).await?;
    std::fs::write(
        options.output_directory.join("run.json"),
        serde_json::to_string_pretty(&provenance)? + "\n",
    )?;

    let selected: Vec<&Target> = suite
        .targets
        .iter()
        .filter(|target| {
            options
                .targets
                .as_ref()
                .is_none_or(|names| names.iter().any(|name| name == &target.name))
        })
        .collect();
    if selected.is_empty() {
        bail!("no targets selected");
    }

    let mut records = Vec::new();
    for target in selected {
        println!("=== target {} ({:?}) ===", target.name, target.role);
        if let Some(lifecycle) = &target.lifecycle {
            for (index, prepare) in lifecycle.prepare.iter().enumerate() {
                run_lifecycle_command(prepare, &format!("lifecycle prepare step {index}")).await?;
            }
            run_lifecycle_command(&lifecycle.up, "lifecycle up").await?;
            if let Some(url) = &lifecycle.ready_url {
                wait_ready(url, lifecycle.ready_timeout_seconds).await?;
            }
        }
        let target_result: Result<()> = async {
            let guarantee_audit = run_guarantee_audit(
                target,
                &options.output_directory.join(&target.name).join("audit"),
            )
            .await?;
            if guarantee_audit == "failed" {
                println!(
                    "  guarantee audit FAILED; measuring anyway, cells will be invalid in the report"
                );
            }
            for repetition in 1..=suite.workload.repetitions {
                for cell in suite.cells() {
                    let cell_directory = options
                        .output_directory
                        .join(&target.name)
                        .join(format!("rep{repetition}"))
                        .join(cell.slug());
                    if repetition == 1 && suite.workload.warmup_seconds > 0 {
                        println!("  {} warmup {}s", cell.label(), suite.workload.warmup_seconds);
                        warmup_cell(&suite, target, &cell, &cell_directory).await?;
                    }
                    println!(
                        "  {} rep {repetition}/{}",
                        cell.label(),
                        suite.workload.repetitions
                    );
                    let record = measure_cell(
                        &suite,
                        target,
                        &cell,
                        repetition,
                        &cell_directory,
                        &guarantee_audit,
                    )
                    .await?;
                    records.push(record);
                }
            }
            Ok(())
        }
        .await;
        if let Some(lifecycle) = &target.lifecycle
            && !options.keep_targets_up
        {
            // Teardown runs even when measurement failed, then the original
            // error is surfaced.
            let teardown = run_lifecycle_command(&lifecycle.down, "lifecycle down").await;
            target_result?;
            teardown?;
        } else {
            target_result?;
        }
    }

    let records_path = options.output_directory.join("cell-records.json");
    std::fs::write(
        &records_path,
        serde_json::to_string_pretty(&records)? + "\n",
    )?;
    let report = crate::report::compute(&suite, &records)?;
    std::fs::write(
        options.output_directory.join("parity-report.json"),
        serde_json::to_string_pretty(&report)? + "\n",
    )?;
    let markdown = crate::report::render_markdown(&report);
    std::fs::write(options.output_directory.join("parity-report.md"), &markdown)?;
    println!("\n{markdown}");
    // A target-filtered run (e.g. a subject-only baseline) cannot produce
    // complete comparisons; its records are the deliverable and gates are
    // informational.
    if options.targets.is_some() {
        println!(
            "target filter active: gates are informational; records in {}",
            records_path.display()
        );
        return Ok(());
    }
    if !report.passed && suite.gates.required {
        bail!("parity gate failed: {}", report.summary);
    }
    Ok(())
}
