// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use futures_util::FutureExt;
use pepper_system_tests::{
    DockerBackend, ProcessBackend, RemoteBackend, ScenarioContext, WanMode,
    harness::context::{RunContext, RunContextOptions},
    scenario_by_name, scenario_names,
};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::Instant,
};

#[derive(Parser)]
#[command(
    name = "pepper-system-test",
    version,
    about = "Reproducible Pepper system test runner"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BackendKind {
    Process,
    Docker,
    Remote,
    Kvm,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum WanModeArg {
    Tailscale,
    Direct,
}

#[derive(Subcommand)]
enum Commands {
    /// List stable scenario identifiers.
    List,
    /// Generate and enforce a release qualification report from archived runs.
    Qualify {
        #[arg(long, default_value = "system-tests/ci/qualification-policy.json")]
        policy: PathBuf,
        #[arg(long)]
        artifacts: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        release_commit: String,
    },
    /// Run one scenario with the selected backend.
    Run {
        #[arg(long)]
        scenario: String,
        #[arg(long)]
        seed: Option<u64>,
        #[arg(long, value_enum, default_value = "docker")]
        backend: BackendKind,
        #[arg(long, env = "PEPPER_SYSTEM_AGENT_BIN")]
        agent_bin: Option<PathBuf>,
        #[arg(long, default_value = "system-tests/artifacts")]
        artifacts: PathBuf,
        /// Reuse node names and ports from a previous topology artifact.
        #[arg(long)]
        topology: Option<PathBuf>,
        /// Do not automatically build pepper-agent when the binary is absent.
        #[arg(long)]
        no_build: bool,
        /// Required wall-clock duration for bounded soak scenarios.
        #[arg(long)]
        duration_seconds: Option<u64>,
        /// Exact `uname -r` value required by fixed-kernel scenarios.
        #[arg(long)]
        expected_kernel: Option<String>,
        /// Address class required when using the non-owning remote backend.
        #[arg(long, value_enum)]
        wan_mode: Option<WanModeArg>,
        /// Docker image reference used by the Docker backend.
        #[arg(
            long,
            default_value = "pepper-system-test:local",
            env = "PEPPER_SYSTEM_IMAGE"
        )]
        image: String,
        /// Require the Docker image to exist instead of building it with Bollard.
        #[arg(long)]
        no_image_build: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::List => {
            for (id, name) in scenario_names() {
                println!("{id}\t{name}");
            }
            Ok(())
        }
        Commands::Qualify {
            policy,
            artifacts,
            output,
            release_commit,
        } => {
            let complete = pepper_system_tests::qualification::generate(
                &policy,
                &artifacts,
                &output,
                &release_commit,
            )?;
            if !complete {
                bail!(
                    "release qualification is incomplete; report: {}",
                    output.display()
                );
            }
            println!("PASS release qualification {}", output.display());
            Ok(())
        }
        Commands::Run {
            scenario,
            seed,
            backend,
            agent_bin,
            artifacts,
            topology,
            no_build,
            duration_seconds,
            expected_kernel,
            wan_mode,
            image,
            no_image_build,
        } => {
            run(RunOptions {
                scenario,
                seed: seed.unwrap_or_else(random_seed),
                backend,
                agent_bin,
                artifacts,
                topology,
                no_build,
                duration_seconds,
                expected_kernel,
                wan_mode,
                image,
                no_image_build,
            })
            .await
        }
    }
}

struct RunOptions {
    scenario: String,
    seed: u64,
    backend: BackendKind,
    agent_bin: Option<PathBuf>,
    artifacts: PathBuf,
    topology: Option<PathBuf>,
    no_build: bool,
    duration_seconds: Option<u64>,
    expected_kernel: Option<String>,
    wan_mode: Option<WanModeArg>,
    image: String,
    no_image_build: bool,
}

async fn run(options: RunOptions) -> Result<()> {
    let RunOptions {
        scenario: scenario_name,
        seed,
        backend: backend_kind,
        agent_bin,
        artifacts: artifact_base,
        topology,
        no_build,
        duration_seconds,
        expected_kernel,
        wan_mode,
        image,
        no_image_build,
    } = options;
    let scenario = scenario_by_name(&scenario_name)?;
    let requirements = scenario.requirements();
    if requirements.requires_docker && !matches!(backend_kind, BackendKind::Docker) {
        bail!("scenario {} requires the Docker backend", scenario.id());
    }
    if requirements.requires_net_admin && !matches!(backend_kind, BackendKind::Docker) {
        bail!(
            "scenario {} requires Docker NET_ADMIN support",
            scenario.id()
        );
    }
    if requirements.requires_kvm && !matches!(backend_kind, BackendKind::Kvm) {
        bail!("scenario {} requires the KVM backend", scenario.id());
    }
    if requirements.requires_wan && !matches!(backend_kind, BackendKind::Remote) {
        bail!("scenario {} requires the remote WAN backend", scenario.id());
    }
    if requirements.requires_fixed_kernel && expected_kernel.is_none() {
        bail!("scenario {} requires --expected-kernel", scenario.id());
    }
    if expected_kernel
        .as_deref()
        .is_some_and(|expected| host_kernel() != expected)
    {
        bail!(
            "host kernel drift: expected {}, observed {}",
            expected_kernel.as_deref().unwrap_or_default(),
            host_kernel()
        );
    }
    let scenario_id = scenario.id();
    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("system-tests has no repository parent")?
        .to_path_buf();
    let (backend, agent_binary): (
        Arc<dyn pepper_system_tests::ClusterBackend>,
        Option<PathBuf>,
    ) = match backend_kind {
        BackendKind::Process | BackendKind::Kvm => {
            let agent_binary = agent_bin.unwrap_or_else(|| {
                repository_root
                    .join("target")
                    .join("debug")
                    .join(if cfg!(windows) {
                        "pepper-agent.exe"
                    } else {
                        "pepper-agent"
                    })
            });
            if !agent_binary.is_file() {
                if no_build {
                    bail!(
                        "pepper-agent binary does not exist at {}",
                        agent_binary.display()
                    );
                }
                build_agent(&repository_root)?;
            }
            if matches!(backend_kind, BackendKind::Kvm) {
                validate_kvm_host()?;
            }
            let backend: Arc<dyn pepper_system_tests::ClusterBackend> =
                Arc::new(if matches!(backend_kind, BackendKind::Kvm) {
                    match topology.as_deref() {
                        Some(path) => {
                            ProcessBackend::kvm_from_topology(agent_binary.clone(), seed, path)?
                        }
                        None => ProcessBackend::kvm(agent_binary.clone(), seed),
                    }
                } else {
                    match topology.as_deref() {
                        Some(path) => {
                            ProcessBackend::from_topology(agent_binary.clone(), seed, path)?
                        }
                        None => ProcessBackend::new(agent_binary.clone(), seed),
                    }
                });
            (backend, Some(agent_binary))
        }
        BackendKind::Docker => {
            if agent_bin.is_some() {
                bail!("--agent-bin is valid only with --backend process");
            }
            let backend: Arc<dyn pepper_system_tests::ClusterBackend> = Arc::new(
                DockerBackend::connect(
                    repository_root.clone(),
                    image,
                    !no_image_build,
                    seed,
                    topology.as_deref(),
                )
                .await?,
            );
            (backend, None)
        }
        BackendKind::Remote => {
            if agent_bin.is_some() {
                bail!("--agent-bin is not valid with --backend remote");
            }
            let path = topology
                .as_deref()
                .context("--backend remote requires --topology")?;
            let mode = match wan_mode.context("--backend remote requires --wan-mode")? {
                WanModeArg::Tailscale => WanMode::Tailscale,
                WanModeArg::Direct => WanMode::Direct,
            };
            (Arc::new(RemoteBackend::from_topology(path, mode)?), None)
        }
    };
    let artifact_base = if artifact_base.is_absolute() {
        artifact_base
    } else {
        repository_root.join(artifact_base)
    };
    let commit = git_commit(&repository_root);
    let metadata = backend.metadata();
    let run = Arc::new(RunContext::create(RunContextOptions {
        scenario: scenario_id,
        seed,
        duration_seconds,
        expected_kernel: expected_kernel.as_deref(),
        repository_root: &repository_root,
        agent_binary: agent_binary.as_deref(),
        backend: metadata.clone(),
        reproduction_arguments: backend.reproduction_arguments(),
        artifact_base: &artifact_base,
        pepper_git_commit: commit,
    })?);
    println!(
        "run_id={} seed={} artifacts={}",
        run.run_id,
        seed,
        run.artifacts.root.display()
    );
    run.events.record("run", json!({
        "operation":"start","result":"ok","details":{"scenario_id":scenario_id,"scenario_name":scenario.name(),"seed":seed,"backend":metadata.name,"image_digest":metadata.image_digest}
    }))?;

    let mut context = ScenarioContext::new(run.clone(), backend.clone());
    let started = Instant::now();
    let (result, cancelled) = {
        let scenario_future =
            std::panic::AssertUnwindSafe(scenario.run(&mut context)).catch_unwind();
        tokio::pin!(scenario_future);
        tokio::select! {
            outcome = &mut scenario_future => {
                let result = match outcome {
                    Ok(result) => result,
                    Err(payload) => Err(anyhow::anyhow!("scenario panicked: {}", panic_message(payload))),
                };
                (result, false)
            }
            signal = tokio::signal::ctrl_c() => {
                signal?;
                (Err(anyhow::anyhow!("scenario cancelled by interrupt")), true)
            }
        }
    };

    let collection_result = backend
        .collect_artifacts(&run.artifacts.root.join("backend"))
        .await;
    let cleanup_result = if let Some(cluster) = context.cluster.as_ref() {
        cluster.destroy().await
    } else {
        backend.destroy().await
    };
    let result = match result {
        Ok(()) => collection_result.and(cleanup_result),
        Err(primary) => {
            let secondary = [collection_result.err(), cleanup_result.err()]
                .into_iter()
                .flatten()
                .map(|error| format!("{error:#}"))
                .collect::<Vec<_>>();
            if !secondary.is_empty() {
                run.artifacts
                    .write_text("cleanup-errors.txt", &format!("{}\n", secondary.join("\n")))?;
            }
            Err(primary)
        }
    };
    let elapsed = started.elapsed();
    let result_name = if result.is_ok() {
        "passed"
    } else if cancelled {
        "cancelled"
    } else {
        "failed"
    };
    if let Err(error) = &result {
        run.artifacts
            .write_text("failure.txt", &format!("{error:#}\n"))?;
    }
    write_junit(
        &run.artifacts.root.join("junit.xml"),
        scenario_id,
        elapsed.as_secs_f64(),
        result.as_ref().err(),
    )?;
    run.events.record("run", json!({
        "operation":"complete","result":if result.is_ok(){"ok"}else if cancelled{"cancelled"}else{"error"},
        "details":{"scenario_id":scenario_id,"scenario_name":scenario.name(),"elapsed_seconds":elapsed.as_secs_f64()}
    }))?;
    run.write_run(
        result_name,
        result.as_ref().err().map(ToString::to_string).as_deref(),
    )?;
    run.events.sync()?;
    run.artifacts.finalize()?;

    match result {
        Ok(()) => {
            println!(
                "PASS {scenario_id} {} ({:.3}s)",
                scenario.name(),
                elapsed.as_secs_f64()
            );
            Ok(())
        }
        Err(error) => Err(error).context(format!(
            "FAIL {scenario_id} {}; reproduce with seed {seed}; artifacts: {}",
            scenario.name(),
            run.artifacts.root.display()
        )),
    }
}

fn build_agent(repository_root: &Path) -> Result<()> {
    eprintln!("pepper-agent not found; building it first");
    let status = Command::new("cargo")
        .current_dir(repository_root)
        .args([
            "build",
            "--locked",
            "-p",
            "pepper-agent",
            "-p",
            "pepper-cli",
        ])
        .status()
        .context("failed to invoke cargo build")?;
    if !status.success() {
        bail!("cargo build for pepper-agent and pepper CLI failed with {status}");
    }
    Ok(())
}

fn git_commit(repository_root: &Path) -> String {
    Command::new("git")
        .current_dir(repository_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn host_kernel() -> String {
    Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn validate_kvm_host() -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("the KVM backend requires Linux");
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .context("/dev/kvm is unavailable or not writable")?;
    for variable in [
        "PEPPER_FIRECRACKER_ROOTFS_IMAGE",
        "PEPPER_FIRECRACKER_KERNEL_IMAGE",
    ] {
        let path = std::env::var_os(variable)
            .map(PathBuf::from)
            .with_context(|| format!("{variable} is required by the KVM backend"))?;
        let metadata = std::fs::metadata(&path)
            .with_context(|| format!("{variable}={} is unreadable", path.display()))?;
        if !metadata.is_file() || metadata.len() == 0 {
            bail!(
                "{variable}={} must be a non-empty regular file",
                path.display()
            );
        }
    }
    let status = Command::new("firecracker")
        .arg("--version")
        .status()
        .context("firecracker is not installed")?;
    if !status.success() {
        bail!("firecracker --version failed with {status}");
    }
    Ok(())
}

fn random_seed() -> u64 {
    let now = time::OffsetDateTime::now_utc()
        .unix_timestamp_nanos()
        .to_be_bytes();
    let digest = blake3::hash(&now);
    u64::from_be_bytes(digest.as_bytes()[..8].try_into().expect("8 bytes"))
}

fn write_junit(
    path: &Path,
    scenario: &str,
    seconds: f64,
    error: Option<&anyhow::Error>,
) -> Result<()> {
    let failure = error.map_or_else(String::new, |error| {
        format!(
            "<failure message=\"{}\">{}</failure>",
            xml_escape(&error.to_string()),
            xml_escape(&format!("{error:#}"))
        )
    });
    let failed = usize::from(error.is_some());
    std::fs::write(
        path,
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"pepper-system-tests\" tests=\"1\" failures=\"{failed}\" time=\"{seconds:.6}\"><testcase name=\"{}\" classname=\"system\" time=\"{seconds:.6}\">{failure}</testcase></testsuite>\n",
            xml_escape(scenario)
        ),
    )?;
    Ok(())
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|value| (*value).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_string())
}
