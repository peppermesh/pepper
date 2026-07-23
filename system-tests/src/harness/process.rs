// SPDX-License-Identifier: Apache-2.0

use crate::harness::{
    backend::{
        BackendMetadata, ClusterBackend, ExecRequest, ExecResult, Fault, FaultGuard, HttpRequest,
        HttpResponse, NodeObservation, RestartPolicy,
    },
    cluster::{Cluster, ClusterSpec, NodeId, NodeRuntime},
    config::{render_agent_config, write_deterministic_identity},
    context::RunContext,
};
use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Write as _,
    net::{TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

struct ManagedChild {
    child: Child,
    process_group: bool,
}

impl ManagedChild {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn terminate(&mut self, grace: Duration) {
        if self.child.try_wait().ok().flatten().is_some() {
            self.kill_remaining_group();
            return;
        }
        #[cfg(unix)]
        unsafe {
            let pid = self.child.id() as i32;
            libc::kill(if self.process_group { -pid } else { pid }, libc::SIGTERM);
        }
        let started = Instant::now();
        while started.elapsed() < grace {
            if self.child.try_wait().ok().flatten().is_some() {
                self.kill_remaining_group();
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        self.kill_remaining_group();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn kill_remaining_group(&self) {
        #[cfg(unix)]
        if self.process_group {
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
        }
    }

    fn kill(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            self.kill_remaining_group();
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        self.terminate(Duration::from_secs(1));
    }
}

enum ProcessRestoration {
    File { path: PathBuf, bytes: Vec<u8> },
    Pressure { path: PathBuf },
    ReadOnly { path: PathBuf },
}

pub struct ProcessBackend {
    agent_binary: PathBuf,
    seed: u64,
    backend_name: &'static str,
    runtimes: Mutex<BTreeMap<NodeId, NodeRuntime>>,
    children: Mutex<BTreeMap<NodeId, ManagedChild>>,
    work_directory: Mutex<Option<tempfile::TempDir>>,
    events: Mutex<Option<Arc<crate::harness::events::EventRecorder>>>,
    port_overrides: Option<BTreeMap<NodeId, (u16, u16)>>,
    restorations: Mutex<BTreeMap<String, ProcessRestoration>>,
    artifact_root: Mutex<Option<PathBuf>>,
}

impl ProcessBackend {
    pub fn new(agent_binary: PathBuf, seed: u64) -> Self {
        Self {
            agent_binary,
            seed,
            backend_name: "process",
            runtimes: Mutex::new(BTreeMap::new()),
            children: Mutex::new(BTreeMap::new()),
            work_directory: Mutex::new(None),
            events: Mutex::new(None),
            port_overrides: None,
            restorations: Mutex::new(BTreeMap::new()),
            artifact_root: Mutex::new(None),
        }
    }

    pub fn kvm(agent_binary: PathBuf, seed: u64) -> Self {
        let mut backend = Self::new(agent_binary, seed);
        backend.backend_name = "kvm";
        backend
    }

    pub fn kvm_from_topology(agent_binary: PathBuf, seed: u64, path: &Path) -> Result<Self> {
        let mut backend = Self::from_topology(agent_binary, seed, path)?;
        backend.backend_name = "kvm";
        Ok(backend)
    }

    pub fn from_topology(agent_binary: PathBuf, seed: u64, path: &Path) -> Result<Self> {
        let document: serde_json::Value = serde_json::from_slice(
            &std::fs::read(path)
                .with_context(|| format!("failed to read topology {}", path.display()))?,
        )?;
        if document["schema_version"] != 1 {
            bail!("topology {} is not schema version 1", path.display());
        }
        let nodes = document["nodes"]
            .as_array()
            .context("topology nodes must be an array")?;
        let mut port_overrides = BTreeMap::new();
        for node in nodes {
            let id = NodeId::new(
                node["name"]
                    .as_str()
                    .context("topology node name missing")?,
            )?;
            let p2p = u16::try_from(
                node["p2p_port"]
                    .as_u64()
                    .context("topology P2P port missing")?,
            )?;
            let api = u16::try_from(
                node["api_port"]
                    .as_u64()
                    .context("topology API port missing")?,
            )?;
            if port_overrides.insert(id.clone(), (p2p, api)).is_some() {
                bail!("duplicate topology node {id}");
            }
        }
        Ok(Self {
            agent_binary,
            seed,
            backend_name: "process",
            runtimes: Mutex::new(BTreeMap::new()),
            children: Mutex::new(BTreeMap::new()),
            work_directory: Mutex::new(None),
            events: Mutex::new(None),
            port_overrides: Some(port_overrides),
            restorations: Mutex::new(BTreeMap::new()),
            artifact_root: Mutex::new(None),
        })
    }

    fn runtime(&self, node: &NodeId) -> Result<NodeRuntime> {
        self.runtimes
            .lock()
            .map_err(|_| anyhow::anyhow!("runtime mutex poisoned"))?
            .get(node)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown process node {node}"))
    }

    fn record(&self, event_type: &str, details: serde_json::Value) {
        if let Ok(events) = self.events.lock()
            && let Some(events) = events.as_ref()
        {
            let _ = events.record(event_type, details);
        }
    }

    fn destroy_sync(&self) {
        if let Ok(mut children) = self.children.lock() {
            for child in children.values_mut() {
                child.terminate(Duration::from_secs(2));
            }
            children.clear();
        }
        if let Ok(mut restorations) = self.restorations.lock() {
            let pending = std::mem::take(&mut *restorations)
                .into_values()
                .collect::<Vec<_>>();
            for restoration in &pending {
                if let ProcessRestoration::ReadOnly { path } = restoration {
                    let _ = Command::new("chmod")
                        .args(["-R", "u+rwX"])
                        .arg(path)
                        .status();
                }
            }
            for restoration in pending {
                match restoration {
                    ProcessRestoration::File { path, bytes } => {
                        let _ = std::fs::write(path, bytes);
                    }
                    ProcessRestoration::Pressure { path } => {
                        let _ = std::fs::remove_file(path);
                    }
                    ProcessRestoration::ReadOnly { .. } => {}
                }
            }
        }
    }
}

impl Drop for ProcessBackend {
    fn drop(&mut self) {
        self.destroy_sync();
    }
}

#[async_trait]
impl ClusterBackend for ProcessBackend {
    async fn provision(self: Arc<Self>, spec: ClusterSpec, run: &RunContext) -> Result<Cluster> {
        spec.validate()?;
        *self
            .artifact_root
            .lock()
            .map_err(|_| anyhow::anyhow!("artifact mutex poisoned"))? =
            Some(run.artifacts.root.clone());
        if !self.agent_binary.is_file() {
            bail!(
                "pepper-agent binary not found at {}",
                self.agent_binary.display()
            );
        }
        let work = tempfile::Builder::new()
            .prefix(&format!("pepper-system-{}-", run.run_id))
            .tempdir()?;
        let work_root = work.path().to_path_buf();
        if let Some(overrides) = &self.port_overrides
            && overrides.len() != spec.nodes.len()
        {
            bail!(
                "reproduction topology has {} nodes but scenario requires {}",
                overrides.len(),
                spec.nodes.len()
            );
        }
        let mut runtimes = BTreeMap::new();
        for (index, node) in spec.nodes.iter().enumerate() {
            let data_path = work_root.join(&node.id.0);
            let config_path = run
                .artifacts
                .root
                .join("configs")
                .join(format!("{}.toml", node.id));
            let log_path = run
                .artifacts
                .root
                .join("logs")
                .join(format!("{}.log", node.id));
            std::fs::create_dir_all(&data_path)?;
            let node_identity = write_deterministic_identity(
                self.seed,
                &node.id,
                &data_path.join("identity.ed25519"),
            )?;
            let (p2p_port, api_port) = match &self.port_overrides {
                Some(overrides) => *overrides
                    .get(&node.id)
                    .with_context(|| format!("reproduction topology is missing {}", node.id))?,
                None => deterministic_ports(self.seed, index)?,
            };
            ensure_ports_available(p2p_port, api_port)?;
            runtimes.insert(
                node.id.clone(),
                NodeRuntime {
                    id: node.id.clone(),
                    node_identity,
                    address: "127.0.0.1".to_string(),
                    p2p_port,
                    api_port,
                    config_path,
                    data_path,
                    log_path,
                },
            );
        }
        for node in &spec.nodes {
            let runtime = runtimes.get(&node.id).expect("runtime created");
            let mut config = render_agent_config(node, runtime, &runtimes, &spec)?;
            if self.backend_name == "kvm" {
                config =
                    config.replace("max_object_bytes = 6291456", "max_object_bytes = 536870912");
            }
            std::fs::write(&runtime.config_path, config)?;
            let output = Command::new(&self.agent_binary)
                .arg("--config")
                .arg(&runtime.config_path)
                .arg("init")
                .env(
                    "TOKIO_WORKER_THREADS",
                    node.resources.tokio_workers.to_string(),
                )
                .output()
                .with_context(|| format!("failed to initialize {}", node.id))?;
            if !output.status.success() {
                bail!(
                    "agent init failed for {}: stdout={} stderr={}",
                    node.id,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        run.artifacts
            .write_json("topology.json", &topology_json(run, &spec, &runtimes))?;
        *self
            .runtimes
            .lock()
            .map_err(|_| anyhow::anyhow!("runtime mutex poisoned"))? = runtimes.clone();
        *self
            .work_directory
            .lock()
            .map_err(|_| anyhow::anyhow!("work-directory mutex poisoned"))? = Some(work);
        *self
            .events
            .lock()
            .map_err(|_| anyhow::anyhow!("event mutex poisoned"))? = Some(run.events.clone());
        self.record(
            "lifecycle",
            json!({"operation":"provision", "result":"ok", "details":{"nodes":spec.nodes.len()}}),
        );
        Ok(Cluster {
            spec,
            root: work_root,
            nodes: runtimes,
            backend: self,
        })
    }

    async fn start(&self, node: &NodeId) -> Result<()> {
        let runtime = self.runtime(node)?;
        let mut children = self
            .children
            .lock()
            .map_err(|_| anyhow::anyhow!("child mutex poisoned"))?;
        if let Some(child) = children.get_mut(node) {
            if child.child.try_wait()?.is_none() {
                return Ok(());
            }
            children.remove(node);
        }
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&runtime.log_path)?;
        let error_log = log.try_clone()?;
        let mut command = Command::new(&self.agent_binary);
        command
            .arg("--config")
            .arg(&runtime.config_path)
            .env("TOKIO_WORKER_THREADS", "2")
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(error_log));
        let process_group = configure_process_group(&mut command);
        let child = command
            .spawn()
            .with_context(|| format!("failed to start {node}"))?;
        let pid = child.id();
        children.insert(
            node.clone(),
            ManagedChild {
                child,
                process_group,
            },
        );
        drop(children);
        self.record(
            "lifecycle",
            json!({"node_id":node,"operation":"start","result":"ok","details":{"pid":pid}}),
        );
        Ok(())
    }

    async fn stop(&self, node: &NodeId) -> Result<()> {
        if let Some(mut child) = self
            .children
            .lock()
            .map_err(|_| anyhow::anyhow!("child mutex poisoned"))?
            .remove(node)
        {
            child.terminate(Duration::from_secs(5));
        }
        self.record(
            "lifecycle",
            json!({"node_id":node,"operation":"stop","result":"ok"}),
        );
        Ok(())
    }

    async fn kill(&self, node: &NodeId) -> Result<()> {
        if let Some(mut child) = self
            .children
            .lock()
            .map_err(|_| anyhow::anyhow!("child mutex poisoned"))?
            .remove(node)
        {
            child.kill();
        }
        self.record(
            "lifecycle",
            json!({"node_id":node,"operation":"kill","result":"ok"}),
        );
        Ok(())
    }

    async fn pause(&self, node: &NodeId) -> Result<()> {
        let mut children = self
            .children
            .lock()
            .map_err(|_| anyhow::anyhow!("child mutex poisoned"))?;
        let child = children
            .get_mut(node)
            .ok_or_else(|| anyhow::anyhow!("node {node} is not running"))?;
        #[cfg(unix)]
        if unsafe { libc::kill(child.pid() as i32, libc::SIGSTOP) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        self.record(
            "fault",
            json!({"node_id":node,"fault_id":format!("pause-{node}"),"fault_action":"apply"}),
        );
        Ok(())
    }

    async fn resume(&self, node: &NodeId) -> Result<()> {
        let mut children = self
            .children
            .lock()
            .map_err(|_| anyhow::anyhow!("child mutex poisoned"))?;
        let child = children
            .get_mut(node)
            .ok_or_else(|| anyhow::anyhow!("node {node} is not running"))?;
        #[cfg(unix)]
        if unsafe { libc::kill(child.pid() as i32, libc::SIGCONT) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        self.record(
            "fault",
            json!({"node_id":node,"fault_id":format!("pause-{node}"),"fault_action":"heal"}),
        );
        Ok(())
    }

    async fn restart(&self, node: &NodeId, policy: RestartPolicy) -> Result<()> {
        match policy {
            RestartPolicy::PreserveAll | RestartPolicy::ProcessOnly => self.stop(node).await?,
            RestartPolicy::PreserveIdentityDropMetadata
            | RestartPolicy::PreserveMetadataDropBlocks
            | RestartPolicy::FreshNode => {
                bail!("FreshNode restart is reserved for the Docker/backend fault phase")
            }
        }
        self.start(node).await
    }

    async fn exec(&self, _node: &NodeId, request: ExecRequest) -> Result<ExecResult> {
        let (program, arguments) = request
            .command
            .split_first()
            .context("exec command must not be empty")?;
        let resolved_program = if program == "pepper" {
            self.agent_binary.with_file_name(if cfg!(windows) {
                "pepper.exe"
            } else {
                "pepper"
            })
        } else if program == "pepper-agent" {
            self.agent_binary.clone()
        } else if program == "pepper-sqlite" {
            self.agent_binary.with_file_name(if cfg!(windows) {
                "pepper-sqlite.exe"
            } else {
                "pepper-sqlite"
            })
        } else {
            PathBuf::from(program)
        };
        let mut command = tokio::process::Command::new(resolved_program);
        command.args(arguments);
        if !request.stdin.is_empty() {
            command.stdin(Stdio::piped());
        }
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if !request.stdin.is_empty() {
            use tokio::io::AsyncWriteExt;
            let mut stdin = child
                .stdin
                .take()
                .context("process exec stdin unavailable")?;
            stdin.write_all(&request.stdin).await?;
            stdin.shutdown().await?;
        }
        let output = tokio::time::timeout(
            Duration::from_secs(request.timeout_seconds.max(1)),
            child.wait_with_output(),
        )
        .await
        .context("process exec timed out")??;
        if output.stdout.len().saturating_add(output.stderr.len()) > request.max_output_bytes {
            bail!(
                "process exec output exceeded {} bytes",
                request.max_output_bytes
            );
        }
        Ok(ExecResult {
            exit_code: output.status.code().map_or(-1, i64::from),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    async fn offline_exec(&self, node: &NodeId, request: ExecRequest) -> Result<ExecResult> {
        self.exec(node, request).await
    }

    async fn network_exec(&self, _node: &NodeId, _request: ExecRequest) -> Result<ExecResult> {
        bail!("network namespace execution requires the Docker backend")
    }

    async fn http(&self, node: &NodeId, request: HttpRequest) -> Result<HttpResponse> {
        let runtime = self.runtime(node)?;
        let method = reqwest::Method::from_bytes(request.method.as_bytes())?;
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(request.timeout_seconds.max(1)))
            .build()?
            .request(
                method,
                format!("http://127.0.0.1:{}{}", runtime.api_port, request.path),
            )
            .body(request.body);
        if let Some(content_type) = request.content_type {
            builder = builder.header(reqwest::header::CONTENT_TYPE, content_type);
        }
        let response = builder.send().await?;
        Ok(HttpResponse {
            status: response.status().as_u16(),
            body: response.bytes().await?.to_vec(),
        })
    }

    async fn read_storage_file(
        &self,
        node: &NodeId,
        relative_path: &Path,
        max_bytes: usize,
    ) -> Result<Vec<u8>> {
        if relative_path.is_absolute()
            || relative_path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            bail!("unsafe storage-relative path {}", relative_path.display());
        }
        let bytes = std::fs::read(
            self.runtime(node)?
                .data_path
                .join("storage")
                .join(relative_path),
        )?;
        if bytes.len() > max_bytes {
            bail!("storage file exceeded {max_bytes} bytes");
        }
        Ok(bytes)
    }

    async fn overwrite_storage_file(
        &self,
        node: &NodeId,
        relative_path: &Path,
        bytes: &[u8],
    ) -> Result<()> {
        validate_storage_relative_path(relative_path)?;
        let path = self
            .runtime(node)?
            .data_path
            .join("storage")
            .join(relative_path);
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() {
            bail!(
                "storage fault target is not a regular file: {}",
                path.display()
            );
        }
        std::fs::write(&path, bytes)?;
        self.record(
            "fault",
            json!({"node_id":node,"fault_id":format!("storage-corrupt-{node}"),"fault_action":"apply","details":{"relative_path":relative_path,"bytes":bytes.len()}}),
        );
        Ok(())
    }

    async fn remove_storage_file(&self, node: &NodeId, relative_path: &Path) -> Result<()> {
        validate_storage_relative_path(relative_path)?;
        let path = self
            .runtime(node)?
            .data_path
            .join("storage")
            .join(relative_path);
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() {
            bail!(
                "storage fault target is not a regular file: {}",
                path.display()
            );
        }
        std::fs::remove_file(&path)?;
        self.record(
            "fault",
            json!({"node_id":node,"fault_id":format!("storage-delete-{node}"),"fault_action":"apply","details":{"relative_path":relative_path}}),
        );
        Ok(())
    }

    async fn apply_fault(self: Arc<Self>, fault: Fault) -> Result<FaultGuard> {
        let fault_id = fault.stable_id();
        match &fault {
            Fault::Stop { node } => self.stop(node).await?,
            Fault::Kill { node } => self.kill(node).await?,
            Fault::Pause { node } => self.pause(node).await?,
            Fault::NetworkPartition { .. } | Fault::NetworkNetem { .. } => {
                bail!("network namespace faults require the Docker backend")
            }
            Fault::StorageDelete {
                node,
                relative_path,
            }
            | Fault::StorageCorrupt {
                node,
                relative_path,
            } => {
                let relative = Path::new(relative_path);
                validate_storage_relative_path(relative)?;
                let path = self.runtime(node)?.data_path.join("storage").join(relative);
                let bytes = std::fs::read(&path)?;
                if let Some(root) = self
                    .artifact_root
                    .lock()
                    .map_err(|_| anyhow::anyhow!("artifact mutex poisoned"))?
                    .as_ref()
                {
                    let directory = root.join("fault-originals");
                    std::fs::create_dir_all(&directory)?;
                    let artifact = directory.join(format!("{fault_id}.bin"));
                    if !artifact.exists() {
                        std::fs::write(artifact, &bytes)?;
                    }
                }
                let replacement = matches!(&fault, Fault::StorageCorrupt { .. })
                    .then(|| vec![0xa5; bytes.len().max(1)]);
                self.stop(node).await?;
                self.restorations
                    .lock()
                    .map_err(|_| anyhow::anyhow!("restoration mutex poisoned"))?
                    .insert(
                        fault_id.clone(),
                        ProcessRestoration::File {
                            path: path.clone(),
                            bytes,
                        },
                    );
                if let Some(replacement) = replacement {
                    std::fs::write(path, replacement)?;
                } else {
                    std::fs::remove_file(path)?;
                }
                self.start(node).await?;
            }
            Fault::StoragePressure { node, bytes } => {
                if *bytes == 0 || *bytes > 1024 * 1024 * 1024 {
                    bail!("storage pressure bytes must be 1 to 1 GiB");
                }
                self.stop(node).await?;
                let path = self
                    .runtime(node)?
                    .data_path
                    .join("storage/pressure/fill.bin");
                std::fs::create_dir_all(path.parent().expect("pressure path has parent"))?;
                let mut file = std::fs::File::create(&path)?;
                let chunk = vec![0u8; 1024 * 1024];
                let mut remaining = *bytes;
                while remaining > 0 {
                    let length = usize::try_from(remaining.min(chunk.len() as u64))?;
                    file.write_all(&chunk[..length])?;
                    remaining -= length as u64;
                }
                file.sync_data()?;
                self.restorations
                    .lock()
                    .map_err(|_| anyhow::anyhow!("restoration mutex poisoned"))?
                    .insert(fault_id.clone(), ProcessRestoration::Pressure { path });
                self.start(node).await?;
            }
            Fault::StorageReadOnly { node } => {
                self.stop(node).await?;
                let path = self.runtime(node)?.data_path.join("storage");
                let status = Command::new("chmod")
                    .args(["-R", "a-w"])
                    .arg(&path)
                    .status()?;
                ensure!(status.success(), "failed to make storage read-only");
                self.restorations
                    .lock()
                    .map_err(|_| anyhow::anyhow!("restoration mutex poisoned"))?
                    .insert(fault_id.clone(), ProcessRestoration::ReadOnly { path });
                self.start(node).await?;
            }
        }
        self.record(
            "fault",
            json!({"fault_id":fault_id,"fault_action":"apply","details":{"fault":fault}}),
        );
        Ok(FaultGuard::new(self, fault))
    }

    async fn heal_fault(&self, fault: &Fault) -> Result<()> {
        let fault_id = fault.stable_id();
        match fault {
            Fault::Stop { node } | Fault::Kill { node } => self.start(node).await?,
            Fault::Pause { node } => self.resume(node).await?,
            Fault::NetworkPartition { .. } | Fault::NetworkNetem { .. } => {
                bail!("network namespace faults require the Docker backend")
            }
            Fault::StorageDelete { node, .. }
            | Fault::StorageCorrupt { node, .. }
            | Fault::StoragePressure { node, .. }
            | Fault::StorageReadOnly { node } => {
                self.stop(node).await?;
                let restoration = self
                    .restorations
                    .lock()
                    .map_err(|_| anyhow::anyhow!("restoration mutex poisoned"))?
                    .remove(&fault_id)
                    .ok_or_else(|| anyhow::anyhow!("fault {fault_id} has no restoration state"))?;
                match restoration {
                    ProcessRestoration::File { path, bytes } => {
                        if let Some(parent) = path.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        std::fs::write(path, bytes)?;
                    }
                    ProcessRestoration::Pressure { path } => {
                        if path.exists() {
                            std::fs::remove_file(path)?;
                        }
                    }
                    ProcessRestoration::ReadOnly { path } => {
                        let status = Command::new("chmod")
                            .args(["-R", "u+rwX"])
                            .arg(path)
                            .status()?;
                        ensure!(status.success(), "failed to restore storage permissions");
                    }
                }
                self.start(node).await?;
            }
        }
        self.record("fault", json!({"fault_id":fault_id,"fault_action":"heal"}));
        Ok(())
    }

    async fn observe(&self, node: &NodeId) -> Result<NodeObservation> {
        let runtime = self.runtime(node)?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()?;
        let base = format!("http://127.0.0.1:{}", runtime.api_port);
        let health = client.get(format!("{base}/healthz")).send().await;
        let readiness = client.get(format!("{base}/readyz")).send().await;
        let status = client.get(format!("{base}/v1/admin/status")).send().await;
        let live = health
            .as_ref()
            .is_ok_and(|response| response.status().is_success());
        let ready = readiness
            .as_ref()
            .is_ok_and(|response| response.status().is_success());
        let (status, status_error) = match status {
            Ok(response) if response.status().is_success() => (Some(response.json().await?), None),
            Ok(response) => (None, Some(format!("status HTTP {}", response.status()))),
            Err(error) => (None, Some(format!("status: {error}"))),
        };
        let mut errors = Vec::new();
        match &health {
            Ok(response) if !response.status().is_success() => {
                errors.push(format!("health HTTP {}", response.status()));
            }
            Err(error) => errors.push(format!("health: {error}")),
            _ => {}
        }
        match &readiness {
            Ok(response) if !response.status().is_success() => {
                errors.push(format!("readiness HTTP {}", response.status()));
            }
            Err(error) => errors.push(format!("readiness: {error}")),
            _ => {}
        }
        if let Some(error) = status_error {
            errors.push(error);
        }
        Ok(NodeObservation {
            node: node.clone(),
            live,
            ready,
            status,
            error: (!errors.is_empty()).then(|| errors.join("; ")),
        })
    }

    async fn collect_artifacts(&self, destination: &Path) -> Result<()> {
        std::fs::create_dir_all(destination)?;
        for runtime in self
            .runtimes
            .lock()
            .map_err(|_| anyhow::anyhow!("runtime mutex poisoned"))?
            .values()
        {
            if runtime.log_path.exists() {
                std::fs::copy(
                    &runtime.log_path,
                    destination.join(format!("{}.log", runtime.id)),
                )?;
            }
        }
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        self.destroy_sync();
        self.record("lifecycle", json!({"operation":"destroy","result":"ok"}));
        Ok(())
    }

    fn metadata(&self) -> BackendMetadata {
        BackendMetadata {
            name: self.backend_name.to_string(),
            capabilities: Vec::new(),
            image_reference: None,
            image_digest: None,
            docker_version: None,
        }
    }

    fn reproduction_arguments(&self) -> Vec<String> {
        vec!["--backend".to_string(), self.backend_name.to_string()]
    }

    fn artifact_root_hint(&self) -> Option<PathBuf> {
        self.artifact_root.lock().ok()?.clone()
    }
}

fn validate_storage_relative_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir
                    | std::path::Component::CurDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        bail!("unsafe storage-relative path {}", path.display());
    }
    Ok(())
}

fn configure_process_group(command: &mut Command) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        true
    }
    #[cfg(not(unix))]
    {
        let _ = command;
        false
    }
}

fn deterministic_ports(seed: u64, index: usize) -> Result<(u16, u16)> {
    let base = 20_000 + ((seed % 6_000) as u16 * 6);
    let offset = u16::try_from(index)?
        .checked_mul(2)
        .context("node port offset overflow")?;
    let p2p_port = base.checked_add(offset).context("P2P port overflow")?;
    let api_port = p2p_port.checked_add(1).context("API port overflow")?;
    Ok((p2p_port, api_port))
}

fn ensure_ports_available(p2p_port: u16, api_port: u16) -> Result<()> {
    UdpSocket::bind(("127.0.0.1", p2p_port)).with_context(|| {
        format!("deterministic P2P port {p2p_port} is occupied; choose another seed")
    })?;
    TcpListener::bind(("127.0.0.1", api_port)).with_context(|| {
        format!("deterministic API port {api_port} is occupied; choose another seed")
    })?;
    Ok(())
}

fn topology_json(
    run: &RunContext,
    spec: &ClusterSpec,
    runtimes: &BTreeMap<NodeId, NodeRuntime>,
) -> serde_json::Value {
    let nodes = spec.nodes.iter().map(|node| {
        let runtime = &runtimes[&node.id];
        json!({
            "name":node.id,
            "node_id":runtime.node_identity,
            "address":runtime.address,
            "p2p_port":runtime.p2p_port,
            "api_port":runtime.api_port,
            "failure_domain":node.failure_domain,
            "placement_labels":{},
            "bootstrap_nodes":node.bootstrap_nodes,
            "storage":[{"volume":runtime.data_path.join("storage"),"capacity_bytes":node.storage.capacity_bytes}],
            "resources":{"cpu_limit":node.resources.cpu_limit,"memory_bytes":node.resources.memory_bytes,"tokio_workers":node.resources.tokio_workers},
            "identity_fixture":runtime.data_path.join("identity.ed25519"),
            "consensus_enabled":node.consensus_enabled,
            "compute_enabled":node.compute_enabled
        })
    }).collect::<Vec<_>>();
    json!({
        "schema_version":1,
        "run_id":run.run_id,
        "profile":spec.profile,
        "network":{"name":format!("process-{}",run.run_id),"subnet":"127.0.0.0/8","mtu":null,"internal":true},
        "nodes":nodes,
        "policies":{"replication_factor":spec.replication_factor,"erasure_data_shards":null,"erasure_parity_shards":null,"namespace_voter_count":spec.namespace_voter_count}
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_plan_is_seeded_and_stable() {
        let first = deterministic_ports(4_242, 0).unwrap();
        let second = deterministic_ports(4_242, 1).unwrap();
        assert_eq!(first.1, first.0 + 1);
        assert_eq!(second.0, first.0 + 2);
        assert_eq!(first, deterministic_ports(4_242, 0).unwrap());
    }

    #[test]
    fn storage_fault_paths_cannot_escape_node_storage() {
        assert!(validate_storage_relative_path(Path::new("blocks/b3/aa/bb/file.blk")).is_ok());
        assert!(validate_storage_relative_path(Path::new("../metadata.redb")).is_err());
        assert!(validate_storage_relative_path(Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn managed_child_is_terminated_on_drop() {
        #[cfg(unix)]
        {
            let mut command = Command::new("sh");
            command.args(["-c", "sleep 60 & wait"]);
            let process_group = configure_process_group(&mut command);
            let child = command.spawn().unwrap();
            let pid = child.id();
            drop(ManagedChild {
                child,
                process_group,
            });
            let result = unsafe { libc::kill(pid as i32, 0) };
            assert_ne!(result, 0, "child {pid} survived guard drop");
        }
    }
}
