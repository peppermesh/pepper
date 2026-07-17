// SPDX-License-Identifier: Apache-2.0

use crate::harness::{
    backend::{
        BackendMetadata, ClusterBackend, ExecRequest, ExecResult, Fault, FaultGuard, HttpRequest,
        HttpResponse, NodeObservation, RestartPolicy,
    },
    cluster::{Cluster, ClusterSpec, NodeId, NodeRuntime},
    config::{render_docker_agent_config, write_deterministic_identity},
    context::RunContext,
};
use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use bollard::{
    Docker,
    container::LogOutput,
    models::{
        ContainerCreateBody, EndpointIpamConfig, EndpointSettings, HostConfig, Ipam, IpamConfig,
        Mount, MountTypeEnum, NetworkCreateRequest, NetworkingConfig, VolumeCreateOptions,
    },
    query_parameters::{
        BuildImageOptionsBuilder, CreateContainerOptionsBuilder, InspectContainerOptions,
        InspectNetworkOptions, KillContainerOptionsBuilder, LogsOptionsBuilder,
        RemoveContainerOptionsBuilder, RemoveVolumeOptionsBuilder, StartContainerOptions,
        StopContainerOptionsBuilder, WaitContainerOptionsBuilder,
    },
};
use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt};
use serde_json::json;
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

const CONTAINER_P2P_PORT: u16 = 7000;
const CONTAINER_API_PORT: u16 = 8080;
const TEST_UID: u64 = 65_532;
const TEST_GID: u64 = 65_532;
const MAX_EXEC_OUTPUT: usize = 64 * 1024 * 1024;
const CONTAINER_CONFIG_PATH: &str = "/var/lib/pepper/identity/config.toml";

#[derive(Debug, Clone)]
struct DockerNode {
    runtime: NodeRuntime,
    container_id: String,
    volumes: BTreeMap<String, String>,
}

#[derive(Debug)]
enum DockerRestoration {
    File {
        node: NodeId,
        path: String,
        backup: String,
    },
    Pressure {
        node: NodeId,
        path: String,
    },
    ReadOnly {
        node: NodeId,
        path: String,
    },
    Network {
        node: NodeId,
        command: Vec<String>,
    },
}

#[derive(Debug, Default)]
struct DockerState {
    run_id: Option<String>,
    artifact_root: Option<PathBuf>,
    network_name: Option<String>,
    subnet: Option<String>,
    nodes: BTreeMap<NodeId, DockerNode>,
    volumes: Vec<String>,
    helper_containers: Vec<String>,
    restorations: BTreeMap<String, DockerRestoration>,
}

#[derive(Debug, Clone)]
struct TopologyOverride {
    subnet: String,
    addresses: BTreeMap<NodeId, String>,
    identity_seed: u64,
}

pub struct DockerBackend {
    docker: Docker,
    image_reference: String,
    image_digest: String,
    docker_version: String,
    seed: u64,
    topology_override: Option<TopologyOverride>,
    state: Mutex<DockerState>,
}

impl DockerBackend {
    pub async fn connect(
        repository_root: PathBuf,
        image_reference: String,
        build_if_missing: bool,
        seed: u64,
        topology: Option<&Path>,
    ) -> Result<Self> {
        let docker = Docker::connect_with_local_defaults()
            .context("failed to connect to the local Docker Engine")?;
        docker.ping().await.context("Docker Engine ping failed")?;
        let docker_version = docker
            .version()
            .await?
            .version
            .unwrap_or_else(|| "unknown".to_string());
        if docker.inspect_image(&image_reference).await.is_err() {
            if !build_if_missing {
                bail!("Docker image {image_reference} is absent and image building is disabled");
            }
            build_image(&docker, &repository_root, &image_reference).await?;
        }
        let image = docker.inspect_image(&image_reference).await?;
        let image_digest = image.id.context("Docker image has no content ID")?;
        if !image_digest.starts_with("sha256:") {
            bail!("Docker image content ID is not a sha256 digest");
        }
        let topology_override = topology.map(load_topology_override).transpose()?;
        Ok(Self {
            docker,
            image_reference,
            image_digest,
            docker_version,
            seed,
            topology_override,
            state: Mutex::new(DockerState::default()),
        })
    }

    fn node(&self, node: &NodeId) -> Result<DockerNode> {
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?
            .nodes
            .get(node)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown Docker node {node}"))
    }

    async fn create_volume(
        &self,
        name: &str,
        run_id: &str,
        node: &NodeId,
        kind: &str,
    ) -> Result<()> {
        let mut labels = HashMap::new();
        labels.insert("pepper.system-test.run".to_string(), run_id.to_string());
        labels.insert("pepper.system-test.node".to_string(), node.to_string());
        labels.insert("pepper.system-test.kind".to_string(), kind.to_string());
        self.docker
            .create_volume(VolumeCreateOptions {
                name: Some(name.to_string()),
                labels: Some(labels),
                ..Default::default()
            })
            .await?;
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?
            .volumes
            .push(name.to_string());
        Ok(())
    }

    async fn prepare_node_volumes(
        &self,
        run_id: &str,
        node: &NodeId,
        volumes: &BTreeMap<String, String>,
        identity_path: &Path,
        config_path: &Path,
        identity_seed: u64,
    ) -> Result<()> {
        let helper_name = format!("{}-volume-init", docker_name(run_id, node));
        let mounts = volume_mounts(volumes);
        let helper = self
            .docker
            .create_container(
                Some(
                    CreateContainerOptionsBuilder::default()
                        .name(&helper_name)
                        .build(),
                ),
                ContainerCreateBody {
                    image: Some(self.image_digest.clone()),
                    user: Some("0:0".to_string()),
                    entrypoint: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
                    cmd: Some(vec![
                        "chown -R 65532:65532 /var/lib/pepper/identity /var/lib/pepper/metadata /var/lib/pepper/storage /var/lib/pepper/compute"
                            .to_string(),
                    ]),
                    host_config: Some(HostConfig {
                        mounts: Some(mounts),
                        ..Default::default()
                    }),
                    labels: Some(resource_labels(run_id, node)),
                    ..Default::default()
                },
            )
            .await?;
        self.docker
            .start_container(&helper.id, None::<StartContainerOptions>)
            .await?;
        wait_success(&self.docker, &helper.id).await?;
        self.docker
            .remove_container(
                &helper.id,
                Some(RemoveContainerOptionsBuilder::default().force(true).build()),
            )
            .await?;

        let upload_name = format!("{}-identity-init", docker_name(run_id, node));
        let identity_volume = volumes.get("identity").context("identity volume missing")?;
        let upload = self
            .docker
            .create_container(
                Some(
                    CreateContainerOptionsBuilder::default()
                        .name(&upload_name)
                        .build(),
                ),
                ContainerCreateBody {
                    image: Some(self.image_digest.clone()),
                    user: Some("0:0".to_string()),
                    entrypoint: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
                    cmd: Some(vec!["true".to_string()]),
                    host_config: Some(HostConfig {
                        mounts: Some(vec![volume_mount(
                            identity_volume,
                            "/var/lib/pepper/identity",
                        )]),
                        ..Default::default()
                    }),
                    labels: Some(resource_labels(run_id, node)),
                    ..Default::default()
                },
            )
            .await?;
        let archive = identity_archive(identity_path, config_path, identity_seed)?;
        self.docker
            .upload_to_container(
                &upload.id,
                Some(
                    bollard::query_parameters::UploadToContainerOptionsBuilder::default()
                        .path("/var/lib/pepper/identity")
                        .build(),
                ),
                bollard::body_full(Bytes::from(archive)),
            )
            .await?;
        self.docker
            .remove_container(
                &upload.id,
                Some(RemoveContainerOptionsBuilder::default().force(true).build()),
            )
            .await?;
        Ok(())
    }

    async fn initialize_node(
        &self,
        run_id: &str,
        node: &NodeId,
        volumes: &BTreeMap<String, String>,
    ) -> Result<()> {
        let name = format!("{}-agent-init", docker_name(run_id, node));
        let mounts = volume_mounts(volumes);
        let container = self
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::default().name(&name).build()),
                ContainerCreateBody {
                    image: Some(self.image_digest.clone()),
                    cmd: Some(vec![
                        "pepper-agent".to_string(),
                        "--config".to_string(),
                        CONTAINER_CONFIG_PATH.to_string(),
                        "init".to_string(),
                    ]),
                    host_config: Some(HostConfig {
                        mounts: Some(mounts),
                        ..Default::default()
                    }),
                    labels: Some(resource_labels(run_id, node)),
                    ..Default::default()
                },
            )
            .await?;
        self.docker
            .start_container(&container.id, None::<StartContainerOptions>)
            .await?;
        if let Err(error) = wait_success(&self.docker, &container.id).await {
            let logs = container_logs(&self.docker, &container.id)
                .await
                .unwrap_or_default();
            let _ = self
                .docker
                .remove_container(
                    &container.id,
                    Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                )
                .await;
            bail!("Docker agent init failed for {node}: {error}; {logs}");
        }
        self.docker
            .remove_container(
                &container.id,
                Some(RemoveContainerOptionsBuilder::default().force(true).build()),
            )
            .await?;
        Ok(())
    }

    async fn create_agent_container(
        &self,
        run_id: &str,
        node_spec: &crate::harness::cluster::NodeSpec,
        runtime: &NodeRuntime,
        volumes: &BTreeMap<String, String>,
        network_name: &str,
        net_admin: bool,
    ) -> Result<(String, String)> {
        let name = docker_name(run_id, &node_spec.id);
        let mounts = volume_mounts(volumes);
        let mut endpoints = HashMap::new();
        endpoints.insert(
            network_name.to_string(),
            EndpointSettings {
                ipam_config: Some(EndpointIpamConfig {
                    ipv4_address: Some(runtime.address.clone()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let container = self
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::default().name(&name).build()),
                ContainerCreateBody {
                    image: Some(self.image_digest.clone()),
                    hostname: Some(node_spec.id.to_string()),
                    cmd: Some(vec![
                        "pepper-agent".to_string(),
                        "--config".to_string(),
                        CONTAINER_CONFIG_PATH.to_string(),
                    ]),
                    env: Some(vec![format!(
                        "TOKIO_WORKER_THREADS={}",
                        node_spec.resources.tokio_workers
                    )]),
                    labels: Some(resource_labels(run_id, &node_spec.id)),
                    host_config: Some(HostConfig {
                        mounts: Some(mounts),
                        memory: Some(node_spec.resources.memory_bytes as i64),
                        nano_cpus: Some((node_spec.resources.cpu_limit * 1_000_000_000.0) as i64),
                        cap_drop: Some(vec!["ALL".to_string()]),
                        cap_add: net_admin.then(|| vec!["NET_ADMIN".to_string()]),
                        security_opt: Some(vec!["no-new-privileges:true".to_string()]),
                        readonly_rootfs: Some(true),
                        tmpfs: Some(HashMap::from([(
                            "/tmp".to_string(),
                            "rw,noexec,nosuid,size=16m,uid=65532,gid=65532".to_string(),
                        )])),
                        ..Default::default()
                    }),
                    networking_config: Some(NetworkingConfig {
                        endpoints_config: Some(endpoints),
                    }),
                    ..Default::default()
                },
            )
            .await?;
        Ok((container.id, name))
    }

    async fn exec_internal(&self, node: &DockerNode, request: ExecRequest) -> Result<ExecResult> {
        if request.command.is_empty() {
            bail!("exec command must not be empty");
        }
        let exec = self
            .docker
            .create_exec(
                &node.container_id,
                bollard::models::ExecConfig {
                    attach_stdin: Some(!request.stdin.is_empty()),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(request.command),
                    ..Default::default()
                },
            )
            .await?;
        let started = self.docker.start_exec(&exec.id, None).await?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        if let bollard::exec::StartExecResults::Attached {
            mut output,
            mut input,
        } = started
        {
            if !request.stdin.is_empty() {
                use tokio::io::AsyncWriteExt;
                input.write_all(&request.stdin).await?;
                input.shutdown().await?;
            }
            tokio::time::timeout(Duration::from_secs(request.timeout_seconds.max(1)), async {
                while let Some(message) = output.next().await {
                    match message? {
                        LogOutput::StdOut { message } | LogOutput::Console { message } => {
                            stdout.extend_from_slice(&message)
                        }
                        LogOutput::StdErr { message } => stderr.extend_from_slice(&message),
                        LogOutput::StdIn { .. } => {}
                    }
                    if stdout.len().saturating_add(stderr.len()) > request.max_output_bytes {
                        bail!(
                            "Docker exec output exceeded {} bytes",
                            request.max_output_bytes
                        );
                    }
                }
                Result::<()>::Ok(())
            })
            .await
            .context("Docker exec timed out")??;
        } else {
            bail!("Docker exec unexpectedly detached");
        }
        let inspected = self.docker.inspect_exec(&exec.id).await?;
        Ok(ExecResult {
            exit_code: inspected.exit_code.unwrap_or(-1),
            stdout,
            stderr,
        })
    }

    async fn network_exec_internal(
        &self,
        node: &DockerNode,
        request: ExecRequest,
    ) -> Result<ExecResult> {
        ensure!(
            request.stdin.is_empty(),
            "network helper does not accept stdin"
        );
        ensure!(
            !request.command.is_empty(),
            "network helper command is empty"
        );
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let name = format!(
            "pepper-netfault-{}-{nonce:x}",
            short_node_slug(&node.runtime.id)
        );
        let body = ContainerCreateBody {
            image: Some(self.image_digest.clone()),
            cmd: Some(request.command),
            user: Some("0:0".to_string()),
            host_config: Some(HostConfig {
                network_mode: Some(format!("container:{}", node.container_id)),
                readonly_rootfs: Some(true),
                cap_drop: Some(vec!["ALL".to_string()]),
                cap_add: Some(vec!["NET_ADMIN".to_string()]),
                security_opt: Some(vec!["no-new-privileges:true".to_string()]),
                ..Default::default()
            }),
            labels: Some(HashMap::from([
                (
                    "pepper.system-test.run".to_string(),
                    self.state
                        .lock()
                        .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?
                        .run_id
                        .clone()
                        .unwrap_or_default(),
                ),
                (
                    "pepper.system-test.helper".to_string(),
                    "network-fault".to_string(),
                ),
            ])),
            ..Default::default()
        };
        let created = self
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::default().name(&name).build()),
                body,
            )
            .await?;
        let id = created.id;
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?
            .helper_containers
            .push(id.clone());
        self.docker
            .start_container(&id, None::<StartContainerOptions>)
            .await?;
        let mut wait = self.docker.wait_container(
            &id,
            Some(
                WaitContainerOptionsBuilder::default()
                    .condition("not-running")
                    .build(),
            ),
        );
        let result = tokio::time::timeout(
            Duration::from_secs(request.timeout_seconds.max(1)),
            wait.next(),
        )
        .await;
        let exit_code = match result {
            Ok(Some(Ok(result))) => result.status_code,
            Ok(Some(Err(error))) => return Err(error.into()),
            Ok(None) => -1,
            Err(_) => {
                let _ = self
                    .docker
                    .kill_container(
                        &id,
                        Some(
                            KillContainerOptionsBuilder::default()
                                .signal("SIGKILL")
                                .build(),
                        ),
                    )
                    .await;
                -1
            }
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut logs = self.docker.logs(
            &id,
            Some(
                LogsOptionsBuilder::default()
                    .stdout(true)
                    .stderr(true)
                    .build(),
            ),
        );
        while let Some(log) = logs.next().await {
            match log? {
                LogOutput::StdOut { message } | LogOutput::Console { message } => {
                    stdout.extend_from_slice(&message)
                }
                LogOutput::StdErr { message } => stderr.extend_from_slice(&message),
                _ => {}
            }
            ensure!(
                stdout.len().saturating_add(stderr.len()) <= request.max_output_bytes,
                "network helper output exceeded bound"
            );
        }
        self.docker
            .remove_container(
                &id,
                Some(RemoveContainerOptionsBuilder::default().force(true).build()),
            )
            .await?;
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?
            .helper_containers
            .retain(|container| container != &id);
        Ok(ExecResult {
            exit_code,
            stdout,
            stderr,
        })
    }

    async fn cleanup_resources(&self) -> Result<()> {
        let (containers, volumes, network) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?;
            let mut containers = state
                .nodes
                .values()
                .map(|node| node.container_id.clone())
                .collect::<Vec<_>>();
            containers.append(&mut state.helper_containers);
            let volumes = std::mem::take(&mut state.volumes);
            let network = state.network_name.take();
            state.nodes.clear();
            (containers, volumes, network)
        };
        let mut errors = Vec::new();
        for container in containers {
            if let Err(error) = self
                .docker
                .remove_container(
                    &container,
                    Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                )
                .await
                && !is_not_found(&error)
            {
                errors.push(error.to_string());
            }
        }
        for volume in volumes {
            if let Err(error) = self
                .docker
                .remove_volume(
                    &volume,
                    Some(RemoveVolumeOptionsBuilder::default().force(true).build()),
                )
                .await
                && !is_not_found(&error)
            {
                errors.push(error.to_string());
            }
        }
        if let Some(network) = network
            && let Err(error) = self.docker.remove_network(&network).await
            && !is_not_found(&error)
        {
            errors.push(error.to_string());
        }
        if !errors.is_empty() {
            bail!("Docker cleanup errors: {}", errors.join("; "));
        }
        Ok(())
    }
}

impl Drop for DockerBackend {
    fn drop(&mut self) {
        let docker = self.docker.clone();
        let resources = self.state.lock().ok().map(|state| {
            (
                state
                    .nodes
                    .values()
                    .map(|node| node.container_id.clone())
                    .collect::<Vec<_>>(),
                state.volumes.clone(),
                state.network_name.clone(),
            )
        });
        if let (Some((containers, volumes, network)), Ok(runtime)) =
            (resources, tokio::runtime::Handle::try_current())
        {
            runtime.spawn(async move {
                for container in containers {
                    let _ = docker
                        .remove_container(
                            &container,
                            Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                        )
                        .await;
                }
                for volume in volumes {
                    let _ = docker
                        .remove_volume(
                            &volume,
                            Some(RemoveVolumeOptionsBuilder::default().force(true).build()),
                        )
                        .await;
                }
                if let Some(network) = network {
                    let _ = docker.remove_network(&network).await;
                }
            });
        }
    }
}

#[async_trait]
impl ClusterBackend for DockerBackend {
    async fn provision(self: Arc<Self>, spec: ClusterSpec, run: &RunContext) -> Result<Cluster> {
        spec.validate()?;
        let run_slug = short_run_slug(&run.run_id);
        let (subnet, addresses, identity_seed) = match &self.topology_override {
            Some(topology) => (
                topology.subnet.clone(),
                topology.addresses.clone(),
                topology.identity_seed,
            ),
            None => {
                let (subnet, addresses) = docker_topology(&run.run_id, &spec);
                (
                    subnet,
                    addresses,
                    docker_identity_seed(&run.run_id, self.seed),
                )
            }
        };
        if addresses.len() != spec.nodes.len() {
            bail!("Docker topology node count does not match scenario");
        }
        let network_name = format!("pepper-st-{run_slug}");
        let mut labels = HashMap::new();
        labels.insert("pepper.system-test.run".to_string(), run.run_id.clone());
        self.docker
            .create_network(NetworkCreateRequest {
                name: network_name.clone(),
                driver: Some("bridge".to_string()),
                internal: Some(true),
                labels: Some(labels),
                ipam: Some(Ipam {
                    config: Some(vec![IpamConfig {
                        subnet: Some(subnet.clone()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .with_context(|| format!("failed to create isolated Docker network {network_name}"))?;
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?;
            state.run_id = Some(run.run_id.clone());
            state.artifact_root = Some(run.artifacts.root.clone());
            state.network_name = Some(network_name.clone());
            state.subnet = Some(subnet.clone());
        }

        let identity_temp = tempfile::tempdir()?;
        let mut runtimes = BTreeMap::new();
        for node in &spec.nodes {
            let identity_path = identity_temp.path().join(format!("{}.key", node.id));
            let node_identity =
                write_deterministic_identity(identity_seed, &node.id, &identity_path)?;
            let address = addresses
                .get(&node.id)
                .with_context(|| format!("Docker topology missing {}", node.id))?
                .clone();
            runtimes.insert(
                node.id.clone(),
                NodeRuntime {
                    id: node.id.clone(),
                    node_identity,
                    address,
                    p2p_port: CONTAINER_P2P_PORT,
                    api_port: CONTAINER_API_PORT,
                    config_path: run
                        .artifacts
                        .root
                        .join("configs")
                        .join(format!("{}.toml", node.id)),
                    data_path: PathBuf::from(format!("docker-volume://{run_slug}/{}", node.id)),
                    log_path: run
                        .artifacts
                        .root
                        .join("logs")
                        .join(format!("{}.log", node.id)),
                },
            );
        }

        for node_spec in &spec.nodes {
            let runtime = &runtimes[&node_spec.id];
            fs::write(
                &runtime.config_path,
                render_docker_agent_config(node_spec, runtime, &runtimes, &spec)?,
            )?;
            let mut volumes = BTreeMap::new();
            for kind in ["identity", "metadata", "storage", "compute"] {
                let name = format!(
                    "pepper-st-{}-{}-{kind}",
                    run_slug,
                    short_node_slug(&node_spec.id)
                );
                self.create_volume(&name, &run.run_id, &node_spec.id, kind)
                    .await?;
                volumes.insert(kind.to_string(), name);
            }
            let identity_path = identity_temp.path().join(format!("{}.key", node_spec.id));
            self.prepare_node_volumes(
                &run.run_id,
                &node_spec.id,
                &volumes,
                &identity_path,
                &runtime.config_path,
                identity_seed,
            )
            .await?;
            self.initialize_node(&run.run_id, &node_spec.id, &volumes)
                .await?;
            let (container_id, _container_name) = self
                .create_agent_container(
                    &run.run_id,
                    node_spec,
                    runtime,
                    &volumes,
                    &network_name,
                    spec.net_admin,
                )
                .await?;
            self.state
                .lock()
                .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?
                .nodes
                .insert(
                    node_spec.id.clone(),
                    DockerNode {
                        runtime: runtime.clone(),
                        container_id,
                        volumes,
                    },
                );
        }
        run.artifacts.write_json(
            "topology.json",
            &docker_topology_json(run, &spec, &runtimes, &subnet, identity_seed),
        )?;
        run.artifacts.write_text(
            "compose.yaml",
            &compose_yaml(&self.image_digest, &network_name, &subnet, &spec, &runtimes),
        )?;
        Ok(Cluster {
            spec,
            root: PathBuf::from(format!("docker://{network_name}")),
            nodes: runtimes,
            backend: self,
        })
    }

    async fn start(&self, node: &NodeId) -> Result<()> {
        let node = self.node(node)?;
        self.docker
            .start_container(&node.container_id, None::<StartContainerOptions>)
            .await?;
        Ok(())
    }

    async fn stop(&self, node: &NodeId) -> Result<()> {
        let node = self.node(node)?;
        self.docker
            .stop_container(
                &node.container_id,
                Some(StopContainerOptionsBuilder::default().t(10).build()),
            )
            .await?;
        Ok(())
    }

    async fn kill(&self, node: &NodeId) -> Result<()> {
        let node = self.node(node)?;
        self.docker
            .kill_container(
                &node.container_id,
                Some(
                    KillContainerOptionsBuilder::default()
                        .signal("SIGKILL")
                        .build(),
                ),
            )
            .await?;
        Ok(())
    }

    async fn pause(&self, node: &NodeId) -> Result<()> {
        let node = self.node(node)?;
        self.docker.pause_container(&node.container_id).await?;
        Ok(())
    }

    async fn resume(&self, node: &NodeId) -> Result<()> {
        let node = self.node(node)?;
        self.docker.unpause_container(&node.container_id).await?;
        Ok(())
    }

    async fn restart(&self, node: &NodeId, policy: RestartPolicy) -> Result<()> {
        match policy {
            RestartPolicy::PreserveAll | RestartPolicy::ProcessOnly => {
                self.stop(node).await?;
                self.start(node).await
            }
            RestartPolicy::PreserveIdentityDropMetadata
            | RestartPolicy::PreserveMetadataDropBlocks
            | RestartPolicy::FreshNode => bail!(
                "destructive Docker restart policy {policy:?} requires the Phase 7 storage-fault declaration API"
            ),
        }
    }

    async fn exec(&self, node: &NodeId, request: ExecRequest) -> Result<ExecResult> {
        self.exec_internal(&self.node(node)?, request).await
    }

    async fn offline_exec(&self, node: &NodeId, request: ExecRequest) -> Result<ExecResult> {
        ensure!(
            request.stdin.is_empty(),
            "offline Docker exec does not accept stdin"
        );
        let node_state = self.node(node)?;
        let mounts = volume_mounts(&node_state.volumes);
        let run_id = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?
            .run_id
            .clone()
            .context("Docker run is not provisioned")?;
        let name = format!(
            "{}-maintenance-{}",
            docker_name(&run_id, node),
            std::process::id()
        );
        let body = ContainerCreateBody {
            image: Some(self.image_digest.clone()),
            cmd: Some(request.command),
            user: Some(format!("{TEST_UID}:{TEST_UID}")),
            host_config: Some(HostConfig {
                mounts: Some(mounts),
                readonly_rootfs: Some(true),
                cap_drop: Some(vec!["ALL".to_string()]),
                security_opt: Some(vec!["no-new-privileges:true".to_string()]),
                ..Default::default()
            }),
            labels: Some(resource_labels(&run_id, node)),
            ..Default::default()
        };
        let created = self
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::default().name(&name).build()),
                body,
            )
            .await?;
        let id = created.id;
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?
            .helper_containers
            .push(id.clone());
        self.docker
            .start_container(&id, None::<StartContainerOptions>)
            .await?;
        let wait = tokio::time::timeout(
            Duration::from_secs(request.timeout_seconds.max(1)),
            self.docker
                .wait_container(
                    &id,
                    Some(
                        WaitContainerOptionsBuilder::default()
                            .condition("not-running")
                            .build(),
                    ),
                )
                .next(),
        )
        .await;
        let status = match wait {
            Ok(Some(Ok(result))) => result.status_code,
            Ok(Some(Err(error))) => return Err(error.into()),
            Ok(None) => -1,
            Err(_) => {
                let _ = self
                    .docker
                    .kill_container(
                        &id,
                        Some(
                            KillContainerOptionsBuilder::default()
                                .signal("SIGKILL")
                                .build(),
                        ),
                    )
                    .await;
                -1
            }
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut logs = self.docker.logs(
            &id,
            Some(
                LogsOptionsBuilder::default()
                    .stdout(true)
                    .stderr(true)
                    .build(),
            ),
        );
        while let Some(log) = logs.next().await {
            match log? {
                LogOutput::StdOut { message } | LogOutput::Console { message } => {
                    stdout.extend_from_slice(&message)
                }
                LogOutput::StdErr { message } => stderr.extend_from_slice(&message),
                _ => {}
            }
            ensure!(
                stdout.len().saturating_add(stderr.len()) <= request.max_output_bytes,
                "offline exec output exceeded bound"
            );
        }
        self.docker
            .remove_container(
                &id,
                Some(RemoveContainerOptionsBuilder::default().force(true).build()),
            )
            .await?;
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?
            .helper_containers
            .retain(|container| container != &id);
        Ok(ExecResult {
            exit_code: status,
            stdout,
            stderr,
        })
    }

    async fn network_exec(&self, node: &NodeId, request: ExecRequest) -> Result<ExecResult> {
        self.network_exec_internal(&self.node(node)?, request).await
    }

    async fn http(&self, node: &NodeId, request: HttpRequest) -> Result<HttpResponse> {
        if !request.path.starts_with('/') || request.path.contains("..") {
            bail!("unsafe HTTP path {}", request.path);
        }
        let node_state = self.node(node)?;
        let mut command = vec![
            "curl".to_string(),
            "--silent".to_string(),
            "--show-error".to_string(),
            "--request".to_string(),
            request.method,
            "--max-time".to_string(),
            request.timeout_seconds.max(1).to_string(),
        ];
        if let Some(content_type) = request.content_type {
            command.extend([
                "--header".to_string(),
                format!("Content-Type: {content_type}"),
            ]);
        }
        if !request.body.is_empty() {
            command.extend(["--data-binary".to_string(), "@-".to_string()]);
        }
        command.extend([
            "--write-out".to_string(),
            "%{http_code}".to_string(),
            format!(
                "http://127.0.0.1:{}{}",
                node_state.runtime.api_port, request.path
            ),
        ]);
        let result = self
            .exec_internal(
                &node_state,
                ExecRequest {
                    command,
                    stdin: request.body,
                    timeout_seconds: request.timeout_seconds.saturating_add(2),
                    max_output_bytes: MAX_EXEC_OUTPUT,
                },
            )
            .await?;
        if result.exit_code != 0 {
            bail!(
                "in-container HTTP request failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        if result.stdout.len() < 3 {
            bail!("curl response omitted HTTP status");
        }
        let split = result.stdout.len() - 3;
        let status = std::str::from_utf8(&result.stdout[split..])?.parse::<u16>()?;
        Ok(HttpResponse {
            status,
            body: result.stdout[..split].to_vec(),
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
        let node_state = self.node(node)?;
        let path = format!("/var/lib/pepper/storage/{}", relative_path.display());
        let result = self
            .exec_internal(
                &node_state,
                ExecRequest {
                    command: vec!["cat".to_string(), path],
                    stdin: Vec::new(),
                    timeout_seconds: 10,
                    max_output_bytes: max_bytes,
                },
            )
            .await?;
        if result.exit_code != 0 {
            bail!(
                "storage read failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        Ok(result.stdout)
    }

    async fn overwrite_storage_file(
        &self,
        node: &NodeId,
        relative_path: &Path,
        bytes: &[u8],
    ) -> Result<()> {
        validate_storage_relative_path(relative_path)?;
        let node_state = self.node(node)?;
        let path = format!("/var/lib/pepper/storage/{}", relative_path.display());
        let result = self
            .exec_internal(
                &node_state,
                ExecRequest {
                    command: vec!["tee".to_string(), path],
                    stdin: bytes.to_vec(),
                    timeout_seconds: 10,
                    max_output_bytes: bytes.len().saturating_add(1024),
                },
            )
            .await?;
        ensure!(
            result.exit_code == 0,
            "storage overwrite failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        Ok(())
    }

    async fn remove_storage_file(&self, node: &NodeId, relative_path: &Path) -> Result<()> {
        validate_storage_relative_path(relative_path)?;
        let node_state = self.node(node)?;
        let path = format!("/var/lib/pepper/storage/{}", relative_path.display());
        let result = self
            .exec_internal(
                &node_state,
                ExecRequest {
                    command: vec!["rm".to_string(), "--".to_string(), path],
                    stdin: Vec::new(),
                    timeout_seconds: 10,
                    max_output_bytes: 4096,
                },
            )
            .await?;
        ensure!(
            result.exit_code == 0,
            "storage removal failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        Ok(())
    }

    async fn apply_fault(self: Arc<Self>, fault: Fault) -> Result<FaultGuard> {
        let fault_id = fault.stable_id();
        let restoration = match &fault {
            Fault::Stop { node } => {
                self.stop(node).await?;
                None
            }
            Fault::Kill { node } => {
                self.kill(node).await?;
                None
            }
            Fault::Pause { node } => {
                self.pause(node).await?;
                None
            }
            Fault::NetworkPartition { source, target } => {
                let source_state = self.node(source)?;
                let target_state = self.node(target)?;
                let table = format!("pepper_{}", short_fault_hash(&fault_id));
                let script = format!(
                    "nft add table inet {table} && nft 'add chain inet {table} output {{ type filter hook output priority 0; policy accept; }}' && nft add rule inet {table} output ip daddr {} udp dport {} drop",
                    target_state.runtime.address, target_state.runtime.p2p_port
                );
                let result = self
                    .network_exec_internal(
                        &source_state,
                        ExecRequest {
                            command: vec!["sh".into(), "-c".into(), script],
                            stdin: Vec::new(),
                            timeout_seconds: 10,
                            max_output_bytes: 4096,
                        },
                    )
                    .await?;
                ensure!(
                    result.exit_code == 0,
                    "partition activation failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                Some(DockerRestoration::Network {
                    node: source.clone(),
                    command: vec![
                        "nft".into(),
                        "delete".into(),
                        "table".into(),
                        "inet".into(),
                        table,
                    ],
                })
            }
            Fault::NetworkNetem {
                node,
                latency_ms,
                jitter_ms,
                loss_percent,
                duplicate_percent,
                reorder_percent,
                rate_kbit,
            } => {
                ensure!(
                    *latency_ms <= 60_000 && *jitter_ms <= 60_000,
                    "netem delay exceeds 60 seconds"
                );
                ensure!(
                    *loss_percent <= 100 && *duplicate_percent <= 100 && *reorder_percent <= 100,
                    "netem percentage exceeds 100"
                );
                let node_state = self.node(node)?;
                let mut command = vec![
                    "tc".into(),
                    "qdisc".into(),
                    "add".into(),
                    "dev".into(),
                    "eth0".into(),
                    "root".into(),
                    "netem".into(),
                    "delay".into(),
                    format!("{latency_ms}ms"),
                    format!("{jitter_ms}ms"),
                    "loss".into(),
                    format!("{loss_percent}%"),
                    "duplicate".into(),
                    format!("{duplicate_percent}%"),
                    "reorder".into(),
                    format!("{reorder_percent}%"),
                ];
                if let Some(rate) = rate_kbit {
                    ensure!(*rate > 0, "netem rate must be positive");
                    command.extend(["rate".into(), format!("{rate}kbit")]);
                }
                let result = self
                    .network_exec_internal(
                        &node_state,
                        ExecRequest {
                            command,
                            stdin: Vec::new(),
                            timeout_seconds: 10,
                            max_output_bytes: 4096,
                        },
                    )
                    .await?;
                ensure!(
                    result.exit_code == 0,
                    "netem activation failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                Some(DockerRestoration::Network {
                    node: node.clone(),
                    command: vec![
                        "tc".into(),
                        "qdisc".into(),
                        "del".into(),
                        "dev".into(),
                        "eth0".into(),
                        "root".into(),
                    ],
                })
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
                let bytes = self
                    .read_storage_file(node, relative, 64 * 1024 * 1024)
                    .await?;
                if let Some(root) = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?
                    .artifact_root
                    .as_ref()
                {
                    let directory = root.join("fault-originals");
                    std::fs::create_dir_all(&directory)?;
                    let artifact = directory.join(format!("{fault_id}.bin"));
                    if !artifact.exists() {
                        std::fs::write(artifact, &bytes)?;
                    }
                }
                let path = format!("/var/lib/pepper/storage/{relative_path}");
                let backup = format!("/var/lib/pepper/storage/fault-backups/{fault_id}.bin");
                self.stop(node).await?;
                let operation = if matches!(&fault, Fault::StorageCorrupt { .. }) {
                    "mkdir -p \"$1\" && cp -- \"$2\" \"$3\" && printf '\\245' > \"$2\""
                } else {
                    "mkdir -p \"$1\" && cp -- \"$2\" \"$3\" && rm -- \"$2\""
                };
                let result = self
                    .offline_exec(
                        node,
                        ExecRequest {
                            command: vec![
                                "sh".into(),
                                "-c".into(),
                                operation.into(),
                                "sh".into(),
                                "/var/lib/pepper/storage/fault-backups".into(),
                                path.clone(),
                                backup.clone(),
                            ],
                            stdin: Vec::new(),
                            timeout_seconds: 10,
                            max_output_bytes: 4096,
                        },
                    )
                    .await?;
                ensure!(
                    result.exit_code == 0,
                    "offline storage mutation failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                self.start(node).await?;
                Some(DockerRestoration::File {
                    node: node.clone(),
                    path,
                    backup,
                })
            }
            Fault::StoragePressure { node, bytes } => {
                ensure!(
                    *bytes > 0 && *bytes <= 1024 * 1024 * 1024,
                    "storage pressure bytes must be 1 to 1 GiB"
                );
                let path = "/var/lib/pepper/storage/pressure/fill.bin".to_string();
                self.stop(node).await?;
                let result = self.offline_exec(node, ExecRequest {
                    command: vec!["sh".into(), "-c".into(), "mkdir -p /var/lib/pepper/storage/pressure && fallocate -l \"$1\" \"$2\"".into(), "sh".into(), bytes.to_string(), path.clone()],
                    stdin: Vec::new(), timeout_seconds: 10, max_output_bytes: 4096,
                }).await?;
                ensure!(result.exit_code == 0, "storage pressure activation failed");
                self.start(node).await?;
                Some(DockerRestoration::Pressure {
                    node: node.clone(),
                    path,
                })
            }
            Fault::StorageReadOnly { node } => {
                let path = "/var/lib/pepper/storage".to_string();
                self.stop(node).await?;
                let result = self
                    .offline_exec(
                        node,
                        ExecRequest {
                            command: vec!["chmod".into(), "-R".into(), "a-w".into(), path.clone()],
                            stdin: Vec::new(),
                            timeout_seconds: 10,
                            max_output_bytes: 4096,
                        },
                    )
                    .await?;
                ensure!(result.exit_code == 0, "read-only storage activation failed");
                self.start(node).await?;
                Some(DockerRestoration::ReadOnly {
                    node: node.clone(),
                    path,
                })
            }
        };
        if let Some(restoration) = restoration {
            self.state
                .lock()
                .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?
                .restorations
                .insert(fault_id, restoration);
        }
        Ok(FaultGuard::new(self, fault))
    }

    async fn heal_fault(&self, fault: &Fault) -> Result<()> {
        let fault_id = fault.stable_id();
        match fault {
            Fault::Stop { node } | Fault::Kill { node } => self.start(node).await,
            Fault::Pause { node } => self.resume(node).await,
            _ => {
                let restoration = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?
                    .restorations
                    .remove(&fault_id)
                    .ok_or_else(|| anyhow::anyhow!("fault {fault_id} has no restoration state"))?;
                match restoration {
                    DockerRestoration::File { node, path, backup } => {
                        self.stop(&node).await?;
                        let result = self
                            .offline_exec(
                                &node,
                                ExecRequest {
                                    command: vec!["mv".into(), "--".into(), backup, path],
                                    stdin: Vec::new(),
                                    timeout_seconds: 10,
                                    max_output_bytes: 4096,
                                },
                            )
                            .await?;
                        ensure!(
                            result.exit_code == 0,
                            "storage restoration failed: {}",
                            String::from_utf8_lossy(&result.stderr)
                        );
                        self.start(&node).await
                    }
                    DockerRestoration::Pressure { node, path } => {
                        self.stop(&node).await?;
                        let result = self
                            .offline_exec(
                                &node,
                                ExecRequest {
                                    command: vec!["rm".into(), "-f".into(), "--".into(), path],
                                    stdin: Vec::new(),
                                    timeout_seconds: 10,
                                    max_output_bytes: 4096,
                                },
                            )
                            .await?;
                        ensure!(result.exit_code == 0, "pressure cleanup failed");
                        self.start(&node).await
                    }
                    DockerRestoration::ReadOnly { node, path } => {
                        self.stop(&node).await?;
                        let result = self
                            .offline_exec(
                                &node,
                                ExecRequest {
                                    command: vec![
                                        "chmod".into(),
                                        "-R".into(),
                                        "u+rwX".into(),
                                        path,
                                    ],
                                    stdin: Vec::new(),
                                    timeout_seconds: 10,
                                    max_output_bytes: 4096,
                                },
                            )
                            .await?;
                        ensure!(result.exit_code == 0, "storage permission cleanup failed");
                        self.start(&node).await
                    }
                    DockerRestoration::Network { node, command } => {
                        let result = self
                            .network_exec_internal(
                                &self.node(&node)?,
                                ExecRequest {
                                    command,
                                    stdin: Vec::new(),
                                    timeout_seconds: 10,
                                    max_output_bytes: 4096,
                                },
                            )
                            .await?;
                        ensure!(
                            result.exit_code == 0,
                            "network fault cleanup failed: {}",
                            String::from_utf8_lossy(&result.stderr)
                        );
                        Ok(())
                    }
                }
            }
        }
    }

    async fn observe(&self, node: &NodeId) -> Result<NodeObservation> {
        let live = self
            .http(
                node,
                HttpRequest {
                    method: "GET".to_string(),
                    path: "/healthz".to_string(),
                    content_type: None,
                    body: Vec::new(),
                    timeout_seconds: 2,
                },
            )
            .await;
        let ready = self
            .http(
                node,
                HttpRequest {
                    method: "GET".to_string(),
                    path: "/readyz".to_string(),
                    content_type: None,
                    body: Vec::new(),
                    timeout_seconds: 2,
                },
            )
            .await;
        let status = self
            .http(
                node,
                HttpRequest {
                    method: "GET".to_string(),
                    path: "/v1/admin/status".to_string(),
                    content_type: None,
                    body: Vec::new(),
                    timeout_seconds: 2,
                },
            )
            .await;
        let live_ok = live.as_ref().is_ok_and(|response| response.status == 200);
        let ready_ok = ready.as_ref().is_ok_and(|response| response.status == 200);
        let status_value = status
            .as_ref()
            .ok()
            .filter(|response| response.status == 200)
            .and_then(|response| serde_json::from_slice(&response.body).ok());
        let errors = [live.err(), ready.err(), status.err()]
            .into_iter()
            .flatten()
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        Ok(NodeObservation {
            node: node.clone(),
            live: live_ok,
            ready: ready_ok,
            status: status_value,
            error: (!errors.is_empty()).then(|| errors.join("; ")),
        })
    }

    async fn collect_artifacts(&self, destination: &Path) -> Result<()> {
        fs::create_dir_all(destination)?;
        let nodes = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?
            .nodes
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut volume_manifest = Vec::new();
        for node in nodes {
            fs::write(
                destination.join(format!("{}.log", node.runtime.id)),
                container_logs(&self.docker, &node.container_id).await?,
            )?;
            if let Ok(metrics) = self
                .http(
                    &node.runtime.id,
                    HttpRequest {
                        method: "GET".to_string(),
                        path: "/metrics".to_string(),
                        content_type: None,
                        body: Vec::new(),
                        timeout_seconds: 3,
                    },
                )
                .await
                && metrics.status == 200
            {
                fs::write(
                    destination.join(format!("{}.metrics.prom", node.runtime.id)),
                    metrics.body,
                )?;
            }
            let inspect = self
                .docker
                .inspect_container(&node.container_id, None::<InspectContainerOptions>)
                .await?;
            fs::write(
                destination.join(format!("{}.container.json", node.runtime.id)),
                serde_json::to_vec_pretty(&inspect)?,
            )?;
            for (kind, volume) in &node.volumes {
                let inspect = self.docker.inspect_volume(volume).await?;
                volume_manifest.push(json!({
                    "node_id":node.runtime.id,"kind":kind,"name":volume,
                    "driver":inspect.driver,"mountpoint":inspect.mountpoint,
                    "labels":inspect.labels
                }));
            }
        }
        fs::write(
            destination.join("volume-manifest.json"),
            serde_json::to_vec_pretty(&volume_manifest)?,
        )?;
        let network = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Docker state mutex poisoned"))?
            .network_name
            .clone();
        if let Some(network) = network {
            let inspect = self
                .docker
                .inspect_network(&network, None::<InspectNetworkOptions>)
                .await?;
            fs::write(
                destination.join("network.json"),
                serde_json::to_vec_pretty(&inspect)?,
            )?;
        }
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        self.cleanup_resources().await
    }

    fn metadata(&self) -> BackendMetadata {
        BackendMetadata {
            name: "docker".to_string(),
            capabilities: Vec::new(),
            image_reference: Some(self.image_reference.clone()),
            image_digest: Some(self.image_digest.clone()),
            docker_version: Some(self.docker_version.clone()),
        }
    }

    fn reproduction_arguments(&self) -> Vec<String> {
        vec![
            "--backend".to_string(),
            "docker".to_string(),
            "--image".to_string(),
            self.image_digest.clone(),
            "--no-image-build".to_string(),
        ]
    }

    fn artifact_root_hint(&self) -> Option<PathBuf> {
        self.state.lock().ok()?.artifact_root.clone()
    }
}

async fn build_image(docker: &Docker, repository_root: &Path, image: &str) -> Result<()> {
    let context = build_context(repository_root)?;
    let source_commit = std::process::Command::new("git")
        .current_dir(repository_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let build_arguments = HashMap::from([("SOURCE_COMMIT", source_commit.as_str())]);
    let mut stream = docker.build_image(
        BuildImageOptionsBuilder::default()
            .dockerfile("system-tests/docker/Dockerfile")
            .t(image)
            .buildargs(&build_arguments)
            .pull("true")
            .rm(true)
            .forcerm(true)
            .build(),
        None,
        Some(bollard::body_full(Bytes::from(context))),
    );
    while let Some(message) = stream.next().await {
        let message = message?;
        if let Some(error) = message.error {
            bail!("Docker image build failed: {error}");
        }
        if let Some(stream) = message.stream {
            eprint!("{stream}");
        }
    }
    Ok(())
}

fn short_fault_hash(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex()[..12].to_string()
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

fn build_context(repository_root: &Path) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    {
        let mut archive = tar::Builder::new(&mut output);
        append_context(&mut archive, repository_root, repository_root)?;
        archive.finish()?;
    }
    Ok(output)
}

fn append_context<W: std::io::Write>(
    archive: &mut tar::Builder<W>,
    root: &Path,
    current: &Path,
) -> Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path.strip_prefix(root)?;
        if ignored_context_path(relative) {
            continue;
        }
        if entry.file_type()?.is_dir() {
            archive.append_dir(relative, &path)?;
            append_context(archive, root, &path)?;
        } else if entry.file_type()?.is_file() {
            archive.append_path_with_name(&path, relative)?;
        }
    }
    Ok(())
}

fn ignored_context_path(path: &Path) -> bool {
    let value = path.to_string_lossy().replace('\\', "/");
    value == ".git"
        || value == "target"
        || value == "docs"
        || value == "system-tests/target"
        || value == "system-tests/artifacts"
        || value.contains("/fuzz/target")
        || value.contains("/fuzz/artifacts")
        || (value.starts_with("dev/") && (value.ends_with("-data") || value.ends_with("-storage")))
}

fn load_topology_override(path: &Path) -> Result<TopologyOverride> {
    let document: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    if document["schema_version"] != 1 {
        bail!("topology is not schema version 1");
    }
    let subnet = document["network"]["subnet"]
        .as_str()
        .context("topology network subnet missing")?
        .to_string();
    let mut addresses = BTreeMap::new();
    let mut identity_seed = None;
    for node in document["nodes"]
        .as_array()
        .context("topology nodes missing")?
    {
        addresses.insert(
            NodeId::new(node["name"].as_str().context("node name missing")?)?,
            node["address"]
                .as_str()
                .context("node address missing")?
                .to_string(),
        );
        let fixture = node["identity_fixture"]
            .as_str()
            .context("Docker identity fixture descriptor missing")?;
        let seed = fixture
            .strip_prefix("docker-seed-v1:")
            .and_then(|value| value.split(':').next())
            .context("unsupported Docker identity fixture descriptor")?
            .parse::<u64>()?;
        if identity_seed
            .replace(seed)
            .is_some_and(|existing| existing != seed)
        {
            bail!("Docker topology contains inconsistent identity seeds");
        }
    }
    Ok(TopologyOverride {
        subnet,
        addresses,
        identity_seed: identity_seed.context("Docker topology contains no nodes")?,
    })
}

fn docker_identity_seed(run_id: &str, scenario_seed: u64) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pepper-docker-run-identity-v1");
    hasher.update(&scenario_seed.to_be_bytes());
    hasher.update(run_id.as_bytes());
    u64::from_be_bytes(
        hasher.finalize().as_bytes()[..8]
            .try_into()
            .expect("8 bytes"),
    )
}

fn docker_topology(run_id: &str, spec: &ClusterSpec) -> (String, BTreeMap<NodeId, String>) {
    let digest = blake3::hash(run_id.as_bytes());
    let second = 64 + (digest.as_bytes()[0] % 64);
    let third = digest.as_bytes()[1];
    let subnet = format!("10.{second}.{third}.0/24");
    let addresses = spec
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            (
                node.id.clone(),
                format!("10.{second}.{third}.{}", index + 10),
            )
        })
        .collect();
    (subnet, addresses)
}

fn docker_topology_json(
    run: &RunContext,
    spec: &ClusterSpec,
    runtimes: &BTreeMap<NodeId, NodeRuntime>,
    subnet: &str,
    identity_seed: u64,
) -> serde_json::Value {
    let nodes = spec
        .nodes
        .iter()
        .map(|node| {
            let runtime = &runtimes[&node.id];
            json!({
                "name":node.id,"node_id":runtime.node_identity,"address":runtime.address,
                "p2p_port":runtime.p2p_port,"api_port":runtime.api_port,
                "failure_domain":node.failure_domain,"placement_labels":{},
                "bootstrap_nodes":node.bootstrap_nodes,
                "storage":[{"volume":format!("pepper-st-{}-{}-storage",short_run_slug(&run.run_id),short_node_slug(&node.id)),"capacity_bytes":node.storage.capacity_bytes}],
                "resources":{"cpu_limit":node.resources.cpu_limit,"memory_bytes":node.resources.memory_bytes,"tokio_workers":node.resources.tokio_workers},
                "identity_fixture":format!("docker-seed-v1:{identity_seed}:{}",node.id),
                "consensus_enabled":node.consensus_enabled,"compute_enabled":node.compute_enabled
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema_version":1,"run_id":run.run_id,"profile":spec.profile,
        "network":{"name":format!("pepper-st-{}",short_run_slug(&run.run_id)),"subnet":subnet,"mtu":1500,"internal":true},
        "nodes":nodes,
        "policies":{"replication_factor":spec.replication_factor,"erasure_data_shards":null,"erasure_parity_shards":null,"namespace_voter_count":spec.namespace_voter_count}
    })
}

fn compose_yaml(
    image: &str,
    network: &str,
    subnet: &str,
    spec: &ClusterSpec,
    runtimes: &BTreeMap<NodeId, NodeRuntime>,
) -> String {
    let mut output = "# Generated reproduction aid; use reproduce.sh for deterministic identity initialization.\nservices:\n".to_string();
    for node in &spec.nodes {
        let runtime = &runtimes[&node.id];
        output.push_str(&format!(
            "  {}:\n    image: {}\n    command: [pepper-agent, --config, /var/lib/pepper/identity/config.toml]\n    user: \"65532:65532\"\n    read_only: true\n    networks:\n      pepper:\n        ipv4_address: {}\n    volumes:\n      - {}-identity:/var/lib/pepper/identity\n      - {}-metadata:/var/lib/pepper/metadata\n      - {}-storage:/var/lib/pepper/storage\n      - {}-compute:/var/lib/pepper/compute\n",
            short_node_slug(&node.id), image, runtime.address,
            short_node_slug(&node.id), short_node_slug(&node.id), short_node_slug(&node.id), short_node_slug(&node.id)
        ));
    }
    output.push_str("networks:\n  pepper:\n    internal: true\n    ipam:\n      config:\n");
    output.push_str(&format!("        - subnet: {subnet}\n"));
    output.push_str("volumes:\n");
    for node in &spec.nodes {
        for kind in ["identity", "metadata", "storage", "compute"] {
            output.push_str(&format!("  {}-{kind}: {{}}\n", short_node_slug(&node.id)));
        }
    }
    output.push_str(&format!("# Engine network name: {network}\n"));
    output
}

fn volume_mounts(volumes: &BTreeMap<String, String>) -> Vec<Mount> {
    volumes
        .iter()
        .map(|(kind, volume)| volume_mount(volume, &format!("/var/lib/pepper/{kind}")))
        .collect()
}

fn volume_mount(volume: &str, target: &str) -> Mount {
    Mount {
        target: Some(target.to_string()),
        source: Some(volume.to_string()),
        typ: Some(MountTypeEnum::VOLUME),
        read_only: Some(false),
        ..Default::default()
    }
}

fn resource_labels(run_id: &str, node: &NodeId) -> HashMap<String, String> {
    HashMap::from([
        ("pepper.system-test.run".to_string(), run_id.to_string()),
        ("pepper.system-test.node".to_string(), node.to_string()),
    ])
}

async fn wait_success(docker: &Docker, container: &str) -> Result<()> {
    let mut stream = docker.wait_container(
        container,
        Some(
            WaitContainerOptionsBuilder::default()
                .condition("not-running")
                .build(),
        ),
    );
    let result = stream
        .next()
        .await
        .context("container wait ended early")??;
    if result.status_code != 0 {
        bail!("container exited with status {}", result.status_code);
    }
    Ok(())
}

async fn container_logs(docker: &Docker, container: &str) -> Result<String> {
    let logs = docker
        .logs(
            container,
            Some(
                LogsOptionsBuilder::default()
                    .stdout(true)
                    .stderr(true)
                    .timestamps(true)
                    .build(),
            ),
        )
        .try_collect::<Vec<_>>()
        .await?;
    Ok(logs.into_iter().map(|line| line.to_string()).collect())
}

fn identity_archive(identity_path: &Path, config_path: &Path, seed: u64) -> Result<Vec<u8>> {
    let identity = fs::read(identity_path)?;
    let config = fs::read(config_path)?;
    let mut secret_hasher = blake3::Hasher::new();
    secret_hasher.update(b"pepper-system-test-cluster-secret-v1");
    secret_hasher.update(&seed.to_be_bytes());
    let secret = secret_hasher.finalize();
    let mut output = Vec::new();
    {
        let mut archive = tar::Builder::new(&mut output);
        append_bytes(&mut archive, &identity, "identity.ed25519", 0o600)?;
        append_bytes(&mut archive, secret.as_bytes(), "cluster.secret", 0o600)?;
        append_bytes(&mut archive, &config, "config.toml", 0o600)?;
        archive.finish()?;
    }
    Ok(output)
}

fn append_bytes<W: std::io::Write>(
    archive: &mut tar::Builder<W>,
    bytes: &[u8],
    name: &str,
    mode: u32,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_uid(TEST_UID);
    header.set_gid(TEST_GID);
    header.set_cksum();
    archive.append_data(&mut header, name, Cursor::new(bytes))?;
    Ok(())
}

fn docker_name(run_id: &str, node: &NodeId) -> String {
    format!(
        "pepper-st-{}-{}",
        short_run_slug(run_id),
        short_node_slug(node)
    )
}

fn short_run_slug(run_id: &str) -> String {
    let digest = hex::encode(&blake3::hash(run_id.as_bytes()).as_bytes()[..6]);
    format!(
        "{}-{digest}",
        run_id
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(18)
            .collect::<String>()
            .to_ascii_lowercase()
    )
}

fn short_node_slug(node: &NodeId) -> String {
    node.0
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(24)
        .collect::<String>()
        .to_ascii_lowercase()
}

fn is_not_found(error: &bollard::errors::Error) -> bool {
    matches!(
        error,
        bollard::errors::Error::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_topologies_are_run_isolated() {
        let spec = ClusterSpec::three_node(42);
        let (first_subnet, first) = docker_topology("run-a", &spec);
        let (second_subnet, second) = docker_topology("run-b", &spec);
        assert_ne!(first_subnet, second_subnet);
        assert_ne!(first, second);
        assert_eq!(first.len(), 3);
    }

    #[test]
    fn identity_scope_is_stable_per_run_and_isolates_parallel_runs() {
        assert_eq!(
            docker_identity_seed("run-a", 42),
            docker_identity_seed("run-a", 42)
        );
        assert_ne!(
            docker_identity_seed("run-a", 42),
            docker_identity_seed("run-b", 42)
        );
    }

    #[test]
    fn build_context_keeps_product_storage_crate() {
        assert!(!ignored_context_path(Path::new("crates/pepper-storage")));
        assert!(ignored_context_path(Path::new("dev/node1-storage")));
        assert!(ignored_context_path(Path::new("system-tests/target")));
    }

    #[test]
    fn storage_fault_paths_cannot_escape_named_volume() {
        assert!(validate_storage_relative_path(Path::new("blocks/b3/aa/bb/file.blk")).is_ok());
        assert!(validate_storage_relative_path(Path::new("../metadata.redb")).is_err());
        assert!(validate_storage_relative_path(Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn identity_archive_contains_private_bootstrap_files() {
        let fixture = tempfile::tempdir().unwrap();
        let identity = fixture.path().join("identity.ed25519");
        let config = fixture.path().join("config.toml");
        fs::write(&identity, b"identity fixture").unwrap();
        fs::write(&config, b"config fixture").unwrap();
        let bytes = identity_archive(&identity, &config, 42).unwrap();
        let mut archive = tar::Archive::new(bytes.as_slice());
        let mut names = Vec::new();
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            names.push(entry.path().unwrap().into_owned());
            assert_eq!(entry.header().mode().unwrap(), 0o600);
            assert_eq!(entry.header().uid().unwrap(), TEST_UID);
            assert_eq!(entry.header().gid().unwrap(), TEST_GID);
        }
        assert_eq!(
            names,
            ["identity.ed25519", "cluster.secret", "config.toml"]
                .map(PathBuf::from)
                .to_vec()
        );
    }
}
