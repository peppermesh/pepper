// SPDX-License-Identifier: Apache-2.0

use crate::harness::{
    artifacts::RunArtifacts,
    backend::{BackendMetadata, ClusterBackend},
    cluster::Cluster,
    events::EventRecorder,
};
use anyhow::Result;
use serde::Serialize;
use std::{path::Path, sync::Arc};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Serialize)]
struct RunMetadata<'a> {
    schema_version: u8,
    run_id: &'a str,
    scenario: &'a str,
    scenario_version: u8,
    seed: u64,
    backend: &'a str,
    started_at: String,
    completed_at: Option<String>,
    result: &'a str,
    pepper_git_commit: &'a str,
    framework_git_commit: Option<&'a str>,
    image_reference: Option<&'a str>,
    image_digest: Option<&'a str>,
    host: HostMetadata,
    deadline_profile: String,
    capabilities: Vec<String>,
    topology_file: &'a str,
    event_file: &'a str,
    artifact_manifest_file: &'a str,
    failure_file: Option<&'a str>,
    reproduce_file: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct HostMetadata {
    os: String,
    arch: String,
    kernel: String,
    logical_cpus: usize,
    memory_bytes: Option<u64>,
    docker_version: Option<String>,
}

pub struct RunContextOptions<'a> {
    pub scenario: &'a str,
    pub seed: u64,
    pub duration_seconds: Option<u64>,
    pub expected_kernel: Option<&'a str>,
    pub repository_root: &'a Path,
    pub agent_binary: Option<&'a Path>,
    pub backend: BackendMetadata,
    pub reproduction_arguments: Vec<String>,
    pub artifact_base: &'a Path,
    pub pepper_git_commit: String,
}

pub struct RunContext {
    pub run_id: String,
    pub scenario: String,
    pub seed: u64,
    pub duration_seconds: Option<u64>,
    pub expected_kernel: Option<String>,
    pub started_at: String,
    pub repository_root: std::path::PathBuf,
    pub agent_binary: Option<std::path::PathBuf>,
    pub backend: BackendMetadata,
    pub reproduction_arguments: Vec<String>,
    pub artifacts: Arc<RunArtifacts>,
    pub events: Arc<EventRecorder>,
    pub pepper_git_commit: String,
}

impl RunContext {
    pub fn create(options: RunContextOptions<'_>) -> Result<Self> {
        let timestamp = OffsetDateTime::now_utc().unix_timestamp_nanos();
        let run_id = format!(
            "{}-{:016x}-{timestamp}",
            sanitize(options.scenario),
            options.seed
        );
        let artifacts = Arc::new(RunArtifacts::create(options.artifact_base, &run_id)?);
        let events = Arc::new(EventRecorder::create(
            &run_id,
            &artifacts.root.join("events.jsonl"),
        )?);
        let context = Self {
            run_id,
            scenario: options.scenario.to_string(),
            seed: options.seed,
            duration_seconds: options.duration_seconds,
            expected_kernel: options.expected_kernel.map(str::to_owned),
            started_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
            repository_root: options.repository_root.to_path_buf(),
            agent_binary: options.agent_binary.map(Path::to_path_buf),
            backend: options.backend,
            reproduction_arguments: options.reproduction_arguments,
            artifacts,
            events,
            pepper_git_commit: options.pepper_git_commit,
        };
        context.write_run("running", None)?;
        context.write_reproduction()?;
        Ok(context)
    }

    pub fn write_run(&self, result: &str, failure: Option<&str>) -> Result<()> {
        self.artifacts.write_json(
            "run.json",
            &RunMetadata {
                schema_version: 1,
                run_id: &self.run_id,
                scenario: &self.scenario,
                scenario_version: 1,
                seed: self.seed,
                backend: &self.backend.name,
                started_at: self.started_at.clone(),
                completed_at: (result != "running")
                    .then(|| OffsetDateTime::now_utc().format(&Rfc3339))
                    .transpose()?,
                result,
                pepper_git_commit: &self.pepper_git_commit,
                framework_git_commit: None,
                image_reference: self.backend.image_reference.as_deref(),
                image_digest: self.backend.image_digest.as_deref(),
                host: HostMetadata {
                    os: std::env::consts::OS.to_string(),
                    arch: std::env::consts::ARCH.to_string(),
                    kernel: kernel_version(),
                    logical_cpus: std::thread::available_parallelism()
                        .map_or(1, std::num::NonZero::get),
                    memory_bytes: None,
                    docker_version: self.backend.docker_version.clone(),
                },
                deadline_profile: format!("{}-smoke", self.backend.name),
                capabilities: backend_capabilities(&self.backend),
                topology_file: "topology.json",
                event_file: "events.jsonl",
                artifact_manifest_file: "artifact-manifest.json",
                failure_file: failure.map(|_| "failure.txt"),
                reproduce_file: Some("reproduce.sh"),
            },
        )
    }

    fn write_reproduction(&self) -> Result<()> {
        let mut arguments = self.reproduction_arguments.clone();
        if let Some(duration) = self.duration_seconds {
            arguments.push("--duration-seconds".to_string());
            arguments.push(duration.to_string());
        }
        if let Some(kernel) = &self.expected_kernel {
            arguments.push("--expected-kernel".to_string());
            arguments.push(kernel.clone());
        }
        if let Some(agent_binary) = &self.agent_binary {
            arguments.push("--agent-bin".to_string());
            arguments.push(agent_binary.display().to_string());
        }
        let arguments = arguments
            .iter()
            .map(|argument| shell_quote(argument))
            .collect::<Vec<_>>()
            .join(" ");
        let command = format!(
            "#!/usr/bin/env bash\nset -euo pipefail\nARTIFACT_DIR=\"$(cd \"$(dirname \"${{BASH_SOURCE[0]}}\")\" && pwd)\"\ncargo run --manifest-path system-tests/Cargo.toml --locked -- run --scenario '{}' --seed {} {} --topology \"${{ARTIFACT_DIR}}/topology.json\"\n",
            self.scenario, self.seed, arguments
        );
        self.artifacts.write_text("reproduce.sh", &command)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                self.artifacts.root.join("reproduce.sh"),
                std::fs::Permissions::from_mode(0o755),
            )?;
        }
        Ok(())
    }
}

pub struct ScenarioContext {
    pub run: Arc<RunContext>,
    pub backend: Arc<dyn ClusterBackend>,
    pub cluster: Option<Cluster>,
}

impl ScenarioContext {
    pub fn new(run: Arc<RunContext>, backend: Arc<dyn ClusterBackend>) -> Self {
        Self {
            run,
            backend,
            cluster: None,
        }
    }
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn backend_capabilities(backend: &BackendMetadata) -> Vec<String> {
    let mut capabilities = match backend.name.as_str() {
        "docker" => vec![
            "docker".to_string(),
            "isolated-network".to_string(),
            "named-volumes".to_string(),
            "multi-agent".to_string(),
        ],
        "kvm" => vec![
            "process".to_string(),
            "kvm".to_string(),
            "firecracker".to_string(),
            "host-gated".to_string(),
        ],
        "wan" => vec![
            "remote".to_string(),
            "wan".to_string(),
            "non-owning".to_string(),
            "multi-agent".to_string(),
        ],
        _ => vec![
            "process".to_string(),
            "loopback".to_string(),
            "multi-agent".to_string(),
        ],
    };
    capabilities.extend(backend.capabilities.iter().cloned());
    capabilities.sort();
    capabilities.dedup();
    capabilities
}

fn kernel_version() -> String {
    std::process::Command::new("uname")
        .arg("-sr")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
