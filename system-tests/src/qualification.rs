// SPDX-License-Identifier: Apache-2.0

//! Deterministic release-qualification report generation over archived run artifacts.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema_version: u8,
    release: String,
    tiers: Vec<TierPolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TierPolicy {
    name: String,
    requirements: Vec<Requirement>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Requirement {
    scenario: String,
    backend: String,
    #[serde(default = "one")]
    minimum_passes: usize,
    #[serde(default)]
    required_files: Vec<String>,
    #[serde(default)]
    required_capability: Option<String>,
    #[serde(default)]
    require_image_digest: bool,
}

fn one() -> usize {
    1
}

#[derive(Debug, Serialize)]
pub struct QualificationReport {
    schema_version: u8,
    release: String,
    release_commit: String,
    generated_at: String,
    result: &'static str,
    artifact_root: String,
    passed_runs: usize,
    rejected_runs: usize,
    tiers: Vec<TierReport>,
    archive_manifests: Vec<ArchiveManifest>,
}

#[derive(Debug, Serialize)]
struct TierReport {
    name: String,
    result: &'static str,
    requirements: Vec<RequirementReport>,
}

#[derive(Debug, Serialize)]
struct RequirementReport {
    scenario: String,
    backend: String,
    required_capability: Option<String>,
    minimum_passes: usize,
    matching_runs: Vec<String>,
    result: &'static str,
}

#[derive(Debug, Serialize)]
struct ArchiveManifest {
    run_id: String,
    manifest_sha256: String,
}

struct RunRecord {
    directory: PathBuf,
    run_id: String,
    scenario: String,
    backend: String,
    commit: String,
    passed: bool,
    image_digest: Option<String>,
    capabilities: BTreeSet<String>,
}

pub fn generate(
    policy_path: &Path,
    artifact_root: &Path,
    output: &Path,
    release_commit: &str,
) -> Result<bool> {
    ensure!(
        !release_commit.is_empty() && release_commit.len() <= 128,
        "release commit is invalid"
    );
    let policy: Policy = serde_json::from_slice(
        &fs::read(policy_path)
            .with_context(|| format!("failed to read {}", policy_path.display()))?,
    )?;
    ensure!(
        policy.schema_version == 1,
        "unsupported qualification policy schema"
    );
    ensure!(
        !policy.tiers.is_empty(),
        "qualification policy has no tiers"
    );
    ensure!(
        policy.release == env!("CARGO_PKG_VERSION"),
        "qualification policy release does not match the runner version"
    );
    let mut tier_names = BTreeSet::new();
    for tier in &policy.tiers {
        ensure!(
            !tier.name.is_empty() && tier_names.insert(&tier.name),
            "qualification policy has an empty or duplicate tier"
        );
        ensure!(
            !tier.requirements.is_empty(),
            "qualification tier {} has no requirements",
            tier.name
        );
        let mut keys = BTreeSet::new();
        for requirement in &tier.requirements {
            ensure!(
                (1..=100).contains(&requirement.minimum_passes),
                "qualification pass count must be 1 to 100"
            );
            ensure!(
                keys.insert((
                    &requirement.scenario,
                    &requirement.backend,
                    &requirement.required_capability,
                )),
                "duplicate qualification requirement in tier {}",
                tier.name
            );
            for relative in &requirement.required_files {
                safe_relative(relative)?;
            }
        }
    }
    let mut run_files = Vec::new();
    collect_run_files(artifact_root, artifact_root, &mut run_files)?;
    ensure!(
        run_files.len() <= 100_000,
        "qualification input exceeds 100,000 runs"
    );
    let mut runs = Vec::new();
    let mut accepted_ids = BTreeSet::new();
    let mut rejected = 0usize;
    for path in run_files {
        match load_run(&path) {
            Ok(run)
                if run.passed
                    && run.commit == release_commit
                    && accepted_ids.insert(run.run_id.clone()) =>
            {
                runs.push(run);
            }
            Ok(_) | Err(_) => rejected += 1,
        }
    }
    let mut tier_reports = Vec::new();
    let mut complete = true;
    let mut selected = BTreeSet::new();
    for tier in policy.tiers {
        let mut requirement_reports = Vec::new();
        let mut tier_complete = true;
        for requirement in tier.requirements {
            let matching = runs
                .iter()
                .filter(|run| {
                    run.scenario == requirement.scenario
                        && run.backend == requirement.backend
                        && requirement
                            .required_capability
                            .as_ref()
                            .is_none_or(|capability| run.capabilities.contains(capability))
                        && (!requirement.require_image_digest
                            || run
                                .image_digest
                                .as_deref()
                                .is_some_and(|v| v.starts_with("sha256:")))
                        && requirement
                            .required_files
                            .iter()
                            .all(|relative| run.directory.join(relative).is_file())
                })
                .map(|run| run.run_id.clone())
                .collect::<Vec<_>>();
            let passed = matching.len() >= requirement.minimum_passes;
            tier_complete &= passed;
            selected.extend(matching.iter().cloned());
            requirement_reports.push(RequirementReport {
                scenario: requirement.scenario,
                backend: requirement.backend,
                required_capability: requirement.required_capability,
                minimum_passes: requirement.minimum_passes,
                matching_runs: matching,
                result: if passed { "passed" } else { "incomplete" },
            });
        }
        complete &= tier_complete;
        tier_reports.push(TierReport {
            name: tier.name,
            result: if tier_complete {
                "passed"
            } else {
                "incomplete"
            },
            requirements: requirement_reports,
        });
    }
    let mut manifests = Vec::new();
    for run in runs.iter().filter(|run| selected.contains(&run.run_id)) {
        let bytes = fs::read(run.directory.join("artifact-manifest.json"))?;
        manifests.push(ArchiveManifest {
            run_id: run.run_id.clone(),
            manifest_sha256: hex::encode(Sha256::digest(bytes)),
        });
    }
    manifests.sort_by(|a, b| a.run_id.cmp(&b.run_id));
    let report = QualificationReport {
        schema_version: 1,
        release: policy.release,
        release_commit: release_commit.to_string(),
        generated_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
        result: if complete { "passed" } else { "incomplete" },
        artifact_root: artifact_root.display().to_string(),
        passed_runs: runs.len(),
        rejected_runs: rejected,
        tiers: tier_reports,
        archive_manifests: manifests,
    };
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, serde_json::to_vec_pretty(&report)?)?;
    fs::write(output.with_extension("md"), markdown(&report))?;
    Ok(complete)
}

fn load_run(path: &Path) -> Result<RunRecord> {
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(value["schema_version"] == 1, "unsupported run schema");
    let directory = path
        .parent()
        .context("run file has no parent")?
        .to_path_buf();
    ensure!(
        directory.join("artifact-manifest.json").is_file(),
        "run has no finalized manifest"
    );
    validate_manifest(&directory)?;
    Ok(RunRecord {
        directory,
        run_id: value["run_id"]
            .as_str()
            .context("run_id missing")?
            .to_string(),
        scenario: value["scenario"]
            .as_str()
            .context("scenario missing")?
            .to_string(),
        backend: value["backend"]
            .as_str()
            .context("backend missing")?
            .to_string(),
        commit: value["pepper_git_commit"]
            .as_str()
            .context("commit missing")?
            .to_string(),
        passed: value["result"].as_str() == Some("passed"),
        image_digest: value["image_digest"].as_str().map(str::to_string),
        capabilities: value["capabilities"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string)
            .collect(),
    })
}

fn validate_manifest(directory: &Path) -> Result<()> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("artifact-manifest.json"))?)?;
    ensure!(
        manifest["schema_version"] == 1,
        "unsupported artifact manifest schema"
    );
    let files = manifest["files"]
        .as_array()
        .context("artifact manifest files missing")?;
    ensure!(
        files.len() <= 10_000,
        "artifact manifest exceeds 10,000 files"
    );
    let mut seen = BTreeSet::new();
    for file in files {
        let relative = file["path"]
            .as_str()
            .context("manifest file path missing")?;
        safe_relative(relative)?;
        ensure!(seen.insert(relative), "duplicate file in artifact manifest");
        let path = directory.join(relative);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.file_type().is_file(),
            "manifest entry is not a regular file: {relative}"
        );
        ensure!(
            metadata.len()
                == file["bytes"]
                    .as_u64()
                    .context("manifest byte count missing")?,
            "artifact byte count mismatch: {relative}"
        );
        let mut input = fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        ensure!(
            hex::encode(hasher.finalize())
                == file["sha256"]
                    .as_str()
                    .context("manifest SHA-256 missing")?,
            "artifact digest mismatch: {relative}"
        );
    }
    Ok(())
}

fn collect_run_files(root: &Path, directory: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    ensure!(
        directory.starts_with(root),
        "artifact traversal escaped root"
    );
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to read {}", directory.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            bail!(
                "symlinks are prohibited in qualification input: {}",
                entry.path().display()
            );
        }
        if file_type.is_dir() {
            collect_run_files(root, &entry.path(), output)?;
        } else if entry.file_name() == "run.json" {
            output.push(entry.path());
        }
    }
    Ok(())
}

fn safe_relative(value: &str) -> Result<()> {
    let path = Path::new(value);
    ensure!(
        !path.as_os_str().is_empty()
            && !path.is_absolute()
            && !path.components().any(|part| matches!(
                part,
                std::path::Component::ParentDir
                    | std::path::Component::CurDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )),
        "unsafe required artifact path"
    );
    Ok(())
}

fn markdown(report: &QualificationReport) -> String {
    let mut text = format!(
        "# Pepper {} release qualification\n\n- Result: **{}**\n- Commit: `{}`\n- Generated: {}\n- Accepted runs: {}\n- Rejected runs: {}\n\n",
        report.release,
        report.result,
        report.release_commit,
        report.generated_at,
        report.passed_runs,
        report.rejected_runs
    );
    for tier in &report.tiers {
        text.push_str(&format!("## {} — {}\n\n| Scenario | Backend | Required | Found | Result |\n|---|---|---:|---:|---|\n", tier.name, tier.result));
        for requirement in &tier.requirements {
            text.push_str(&format!(
                "| {} | {}{} | {} | {} | {} |\n",
                requirement.scenario,
                requirement.backend,
                requirement
                    .required_capability
                    .as_ref()
                    .map_or_else(String::new, |capability| format!(" ({capability})")),
                requirement.minimum_passes,
                requirement.matching_runs.len(),
                requirement.result
            ));
        }
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(root: &Path, scenario: &str, backend: &str, commit: &str) {
        let directory = root.join(format!("{scenario}-{backend}"));
        fs::create_dir_all(directory.join("observations")).unwrap();
        fs::write(directory.join("observations/proof.json"), b"{}\n").unwrap();
        fs::write(directory.join("run.json"), serde_json::to_vec(&serde_json::json!({
            "schema_version":1,"run_id":format!("{scenario}-{backend}"),"scenario":scenario,
            "backend":backend,"pepper_git_commit":commit,"result":"passed","image_digest":"sha256:abc"
        })).unwrap()).unwrap();
        let files = ["observations/proof.json", "run.json"].into_iter().map(|relative| {
            let bytes = fs::read(directory.join(relative)).unwrap();
            serde_json::json!({"path":relative,"bytes":bytes.len(),"sha256":hex::encode(Sha256::digest(bytes))})
        }).collect::<Vec<_>>();
        fs::write(
            directory.join("artifact-manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version":1,"files":files
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn report_is_complete_only_with_matching_finalized_archives() {
        let temp = tempfile::tempdir().unwrap();
        let artifacts = temp.path().join("artifacts");
        fs::create_dir_all(&artifacts).unwrap();
        fixture(&artifacts, "SOAK-001", "docker", "abc");
        let policy = temp.path().join("policy.json");
        fs::write(
            &policy,
            serde_json::to_vec(&serde_json::json!({
                "schema_version":1,"release":"0.2.0","tiers":[{"name":"soak","requirements":[{
                    "scenario":"SOAK-001","backend":"docker","minimum_passes":1,
                    "required_files":["observations/proof.json"],"require_image_digest":true
                }]}]
            }))
            .unwrap(),
        )
        .unwrap();
        let report = temp.path().join("report.json");
        assert!(generate(&policy, &artifacts, &report, "abc").unwrap());
        assert!(report.is_file() && report.with_extension("md").is_file());
        assert!(!generate(&policy, &artifacts, &report, "different").unwrap());
    }

    #[test]
    fn policy_paths_cannot_escape_run_archive() {
        assert!(safe_relative("observations/report.json").is_ok());
        assert!(safe_relative("../secret").is_err());
        assert!(safe_relative("/etc/passwd").is_err());
    }
}
