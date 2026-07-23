// SPDX-License-Identifier: Apache-2.0

//! Non-owning backend for pre-provisioned WAN and Tailscale qualification clusters.
//! It never starts, stops, mutates, or logs into remote hosts.

use crate::harness::{
    backend::{
        BackendMetadata, ClusterBackend, ExecRequest, ExecResult, Fault, FaultGuard, HttpRequest,
        HttpResponse, NodeObservation, RestartPolicy,
    },
    cluster::{Cluster, ClusterSpec, NodeId, NodeRuntime, NodeSpec, ResourceSpec, StorageSpec},
    context::RunContext,
};
use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WanMode {
    Tailscale,
    Direct,
}

impl WanMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tailscale => "tailscale",
            Self::Direct => "direct",
        }
    }
}

pub struct RemoteBackend {
    mode: WanMode,
    source: PathBuf,
    topology: serde_json::Value,
    runtimes: BTreeMap<NodeId, NodeRuntime>,
    spec: ClusterSpec,
    client: reqwest::Client,
}

impl RemoteBackend {
    pub fn from_topology(path: &Path, mode: WanMode) -> Result<Self> {
        let mut topology: serde_json::Value = serde_json::from_slice(
            &std::fs::read(path)
                .with_context(|| format!("failed to read WAN topology {}", path.display()))?,
        )?;
        ensure!(
            topology["schema_version"] == 1,
            "WAN topology must use schema version 1"
        );
        let nodes = topology["nodes"]
            .as_array()
            .context("WAN topology nodes missing")?;
        ensure!(
            nodes.len() >= 3,
            "WAN qualification requires at least three nodes"
        );
        let mut runtimes = BTreeMap::new();
        let mut specs = Vec::new();
        for node in nodes {
            let id = NodeId::new(node["name"].as_str().context("WAN node name missing")?)?;
            let public_id = node["node_id"].as_str().context("WAN node ID missing")?;
            ensure!(
                public_id.len() == 64 && public_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "WAN node {id} has an invalid public node ID"
            );
            let fixture = node["identity_fixture"]
                .as_str()
                .context("WAN identity descriptor missing")?;
            ensure!(
                fixture == format!("remote-public-v1:{public_id}"),
                "WAN node {id} identity fixture must contain only its public identity descriptor"
            );
            let address = node["address"]
                .as_str()
                .context("WAN node address missing")?
                .to_string();
            validate_address(&address, mode)?;
            let p2p_port =
                u16::try_from(node["p2p_port"].as_u64().context("WAN P2P port missing")?)?;
            let api_port =
                u16::try_from(node["api_port"].as_u64().context("WAN API port missing")?)?;
            let runtime = NodeRuntime {
                id: id.clone(),
                node_identity: public_id.to_string(),
                address,
                p2p_port,
                api_port,
                config_path: PathBuf::new(),
                data_path: PathBuf::new(),
                log_path: PathBuf::new(),
            };
            ensure!(
                runtimes.insert(id.clone(), runtime).is_none(),
                "duplicate WAN node {id}"
            );
            let bootstrap_nodes = node["bootstrap_nodes"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .map(|name| NodeId::new(name.to_string()))
                .collect::<Result<Vec<_>>>()?;
            specs.push(NodeSpec {
                id,
                failure_domain: node["failure_domain"]
                    .as_str()
                    .unwrap_or("remote")
                    .to_string(),
                bootstrap_nodes,
                storage: StorageSpec {
                    capacity_bytes: node["storage"][0]["capacity_bytes"].as_u64().unwrap_or(1),
                    repair_interval_seconds: 300,
                },
                resources: ResourceSpec {
                    cpu_limit: node["resources"]["cpu_limit"].as_f64().unwrap_or(1.0),
                    memory_bytes: node["resources"]["memory_bytes"]
                        .as_u64()
                        .unwrap_or(512 * 1024 * 1024),
                    tokio_workers: node["resources"]["tokio_workers"].as_u64().unwrap_or(2)
                        as usize,
                },
                consensus_enabled: node["consensus_enabled"].as_bool().unwrap_or(true),
                compute_enabled: node["compute_enabled"].as_bool().unwrap_or(false),
            });
        }
        let replication_factor = topology["policies"]["replication_factor"]
            .as_u64()
            .unwrap_or(3) as usize;
        let spec = ClusterSpec {
            profile: format!("wan-{}", mode.as_str()),
            nodes: specs,
            replication_factor,
            namespace_voter_count: topology["policies"]["namespace_voter_count"]
                .as_u64()
                .map(|v| v as usize)
                .or(Some(3)),
            net_admin: false,
            sqlite_enabled: topology["policies"]["sqlite_enabled"]
                .as_bool()
                .unwrap_or(false),
        };
        spec.validate()?;
        topology["profile"] = format!("wan-{}", mode.as_str()).into();
        Ok(Self {
            mode,
            source: path.to_path_buf(),
            topology,
            runtimes,
            spec,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(90))
                .build()?,
        })
    }

    fn runtime(&self, node: &NodeId) -> Result<&NodeRuntime> {
        self.runtimes
            .get(node)
            .with_context(|| format!("unknown WAN node {node}"))
    }
}

fn validate_address(value: &str, mode: WanMode) -> Result<()> {
    let address: IpAddr = value.parse().with_context(|| {
        format!("WAN node address {value:?} must be a stable literal IP address")
    })?;
    ensure!(
        !address.is_loopback() && !address.is_unspecified() && !address.is_multicast(),
        "WAN address {value} is not routable"
    );
    let tailscale = match address {
        IpAddr::V4(ip) => (u32::from(ip) & 0xffc0_0000) == 0x6440_0000,
        IpAddr::V6(ip) => ip.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    };
    match mode {
        WanMode::Tailscale => ensure!(
            tailscale,
            "Tailscale mode requires a 100.64.0.0/10 or fd7a:115c:a1e0::/48 address, got {value}"
        ),
        WanMode::Direct => ensure!(
            !tailscale && !is_private(address),
            "direct-WAN mode requires a public non-Tailscale address, got {value}"
        ),
    }
    Ok(())
}

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local() || ip.is_documentation(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

#[async_trait]
impl ClusterBackend for RemoteBackend {
    async fn provision(
        self: Arc<Self>,
        requested: ClusterSpec,
        run: &RunContext,
    ) -> Result<Cluster> {
        ensure!(
            requested.nodes.len() <= self.spec.nodes.len(),
            "remote topology has fewer nodes than scenario requires"
        );
        let mut topology = self.topology.clone();
        topology["run_id"] = run.run_id.clone().into();
        run.artifacts.write_json("topology.json", &topology)?;
        run.artifacts.write_json("observations/wan-environment.json", &serde_json::json!({
            "schema_version": 1, "mode": self.mode.as_str(), "source_topology": self.source.file_name().and_then(|v| v.to_str()),
            "node_count": self.runtimes.len(), "lifecycle_owned": false
        }))?;
        Ok(Cluster {
            spec: self.spec.clone(),
            root: PathBuf::new(),
            nodes: self.runtimes.clone(),
            backend: self,
        })
    }
    async fn start(&self, _: &NodeId) -> Result<()> {
        Ok(())
    }
    async fn stop(&self, _: &NodeId) -> Result<()> {
        bail!("remote backend never stops operator-owned nodes")
    }
    async fn kill(&self, _: &NodeId) -> Result<()> {
        bail!("remote backend never kills operator-owned nodes")
    }
    async fn pause(&self, _: &NodeId) -> Result<()> {
        bail!("remote backend never pauses operator-owned nodes")
    }
    async fn resume(&self, _: &NodeId) -> Result<()> {
        bail!("remote backend never resumes operator-owned nodes")
    }
    async fn restart(&self, _: &NodeId, _: RestartPolicy) -> Result<()> {
        bail!("remote backend never restarts operator-owned nodes")
    }
    async fn exec(&self, _: &NodeId, _: ExecRequest) -> Result<ExecResult> {
        bail!("remote command execution is prohibited")
    }
    async fn offline_exec(&self, _: &NodeId, _: ExecRequest) -> Result<ExecResult> {
        bail!("remote offline execution is prohibited")
    }
    async fn network_exec(&self, _: &NodeId, _: ExecRequest) -> Result<ExecResult> {
        bail!("remote network mutation is prohibited")
    }
    async fn http(&self, node: &NodeId, request: HttpRequest) -> Result<HttpResponse> {
        let runtime = self.runtime(node)?;
        let method = reqwest::Method::from_bytes(request.method.as_bytes())?;
        let mut builder = self
            .client
            .request(
                method,
                format!(
                    "http://{}:{}{}",
                    runtime.address, runtime.api_port, request.path
                ),
            )
            .timeout(Duration::from_secs(request.timeout_seconds.max(1)));
        if let Some(content_type) = request.content_type {
            builder = builder.header(reqwest::header::CONTENT_TYPE, content_type);
        }
        let response = builder.body(request.body).send().await?;
        let status = response.status().as_u16();
        let body = response.bytes().await?;
        ensure!(
            body.len() <= 64 * 1024 * 1024,
            "remote HTTP response exceeded 64 MiB"
        );
        Ok(HttpResponse {
            status,
            body: body.to_vec(),
        })
    }
    async fn read_storage_file(&self, _: &NodeId, _: &Path, _: usize) -> Result<Vec<u8>> {
        bail!("remote storage access is prohibited")
    }
    async fn overwrite_storage_file(&self, _: &NodeId, _: &Path, _: &[u8]) -> Result<()> {
        bail!("remote storage mutation is prohibited")
    }
    async fn remove_storage_file(&self, _: &NodeId, _: &Path) -> Result<()> {
        bail!("remote storage mutation is prohibited")
    }
    async fn apply_fault(self: Arc<Self>, _: Fault) -> Result<FaultGuard> {
        bail!("remote fault injection is prohibited")
    }
    async fn heal_fault(&self, _: &Fault) -> Result<()> {
        bail!("remote fault injection is prohibited")
    }
    async fn observe(&self, node: &NodeId) -> Result<NodeObservation> {
        let response = self
            .http(
                node,
                HttpRequest {
                    method: "GET".into(),
                    path: "/readyz".into(),
                    content_type: None,
                    body: Vec::new(),
                    timeout_seconds: 10,
                },
            )
            .await;
        Ok(NodeObservation {
            node: node.clone(),
            live: response.is_ok(),
            ready: response.is_ok_and(|r| (200..300).contains(&r.status)),
            status: None,
            error: None,
        })
    }
    async fn collect_artifacts(&self, destination: &Path) -> Result<()> {
        std::fs::create_dir_all(destination)?;
        for node in self.runtimes.keys() {
            for (name, path) in [("health", "/healthz"), ("metrics", "/metrics")] {
                if let Ok(response) = self
                    .http(
                        node,
                        HttpRequest {
                            method: "GET".into(),
                            path: path.into(),
                            content_type: None,
                            body: Vec::new(),
                            timeout_seconds: 10,
                        },
                    )
                    .await
                {
                    let body = &response.body[..response.body.len().min(2 * 1024 * 1024)];
                    std::fs::write(destination.join(format!("{node}.{name}")), body)?;
                }
            }
        }
        Ok(())
    }
    async fn destroy(&self) -> Result<()> {
        Ok(())
    }
    fn metadata(&self) -> BackendMetadata {
        BackendMetadata {
            name: "wan".to_string(),
            capabilities: vec![self.mode.as_str().to_string()],
            image_reference: None,
            image_digest: None,
            docker_version: None,
        }
    }
    fn reproduction_arguments(&self) -> Vec<String> {
        vec![
            "--backend".into(),
            "remote".into(),
            "--wan-mode".into(),
            self.mode.as_str().into(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wan_address_modes_are_strict_and_disjoint() {
        assert!(validate_address("100.64.1.2", WanMode::Tailscale).is_ok());
        assert!(validate_address("fd7a:115c:a1e0::1", WanMode::Tailscale).is_ok());
        assert!(validate_address("8.8.8.8", WanMode::Direct).is_ok());
        assert!(validate_address("100.64.1.2", WanMode::Direct).is_err());
        assert!(validate_address("10.0.0.1", WanMode::Direct).is_err());
        assert!(validate_address("192.0.2.1", WanMode::Direct).is_err());
        assert!(validate_address("127.0.0.1", WanMode::Tailscale).is_err());
        assert!(validate_address("node.example", WanMode::Direct).is_err());
    }

    #[test]
    fn packaged_wan_templates_pass_after_direct_placeholders_are_replaced() {
        let temp = tempfile::tempdir().unwrap();
        for (name, mode, contents) in [
            (
                "tailscale.json",
                WanMode::Tailscale,
                include_str!("../../topologies/wan-tailscale.example.json"),
            ),
            (
                "direct.json",
                WanMode::Direct,
                include_str!("../../topologies/wan-direct.example.json"),
            ),
        ] {
            let path = temp.path().join(name);
            let mut topology: serde_json::Value = serde_json::from_str(contents).unwrap();
            if mode == WanMode::Direct {
                for (node, address) in topology["nodes"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .zip(["8.8.8.8", "1.1.1.1", "9.9.9.9"])
                {
                    node["address"] = address.into();
                }
            }
            std::fs::write(&path, serde_json::to_vec(&topology).unwrap()).unwrap();
            let backend = RemoteBackend::from_topology(&path, mode).unwrap();
            assert_eq!(backend.runtimes.len(), 3);
        }
    }
}
