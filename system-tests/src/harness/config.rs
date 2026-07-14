// SPDX-License-Identifier: Apache-2.0

use crate::harness::cluster::{ClusterSpec, NodeId, NodeRuntime, NodeSpec};
use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Serialize)]
struct IdentityFile {
    version: u8,
    algorithm: &'static str,
    private_key_hex: String,
    public_key_hex: String,
}

pub fn write_deterministic_identity(seed: u64, node: &NodeId, path: &Path) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pepper-system-test-identity-v1");
    hasher.update(&seed.to_be_bytes());
    hasher.update(node.0.as_bytes());
    let secret = *hasher.finalize().as_bytes();
    let signing = SigningKey::from_bytes(&secret);
    let public = signing.verifying_key().to_bytes();
    let identity = IdentityFile {
        version: 1,
        algorithm: "ed25519",
        private_key_hex: hex::encode(secret),
        public_key_hex: hex::encode(public),
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(&identity)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(hex::encode(blake3::hash(&public).as_bytes()))
}

pub fn render_agent_config(
    node: &NodeSpec,
    runtime: &NodeRuntime,
    runtimes: &BTreeMap<NodeId, NodeRuntime>,
    cluster: &ClusterSpec,
) -> Result<String> {
    let bootstrap = node
        .bootstrap_nodes
        .iter()
        .map(|id| {
            let runtime = runtimes
                .get(id)
                .with_context(|| format!("bootstrap runtime {id} missing"))?;
            Ok(format!("\"127.0.0.1:{}\"", runtime.p2p_port))
        })
        .collect::<Result<Vec<_>>>()?
        .join(", ");
    Ok(format!(
        r#"[node]
name = "{name}"
listen_addr = "127.0.0.1:{p2p_port}"
advertise_addr = "127.0.0.1:{p2p_port}"
failure_domain = "{failure_domain}"

[data]
path = "{data_path}"

[identity]
key_path = "{identity_path}"
generate_if_missing = false

[api]
bind_addr = "127.0.0.1:{api_port}"

[[storage.locations]]
path = "{storage_path}"
max_capacity_bytes = {capacity}

[network]
bootstrap_peers = [{bootstrap}]

[namespace]
enabled = {consensus}
consensus_enabled = {consensus}
heartbeat_interval_ms = 250
election_timeout_min_ms = 1500
election_timeout_max_ms = 3000

[replication]
default_factor = {replication}
repair_interval_seconds = {repair_interval}

[compute]
enabled = {compute}
runtime = "firecracker"
max_concurrent_jobs = 1
work_dir = "{compute_path}"
firecracker_allow_untrusted_rootfs = false

[limits]
max_block_bytes = 5242880
max_object_bytes = 6291456
http_requests_per_minute = 12000
rpc_requests_per_minute = 12000

[logging]
format = "json"
"#,
        name = node.id,
        p2p_port = runtime.p2p_port,
        failure_domain = node.failure_domain,
        data_path = runtime.data_path.display(),
        identity_path = runtime.data_path.join("identity.ed25519").display(),
        api_port = runtime.api_port,
        storage_path = runtime.data_path.join("storage").display(),
        capacity = node.storage.capacity_bytes,
        consensus = node.consensus_enabled,
        replication = cluster.replication_factor,
        repair_interval = node.storage.repair_interval_seconds,
        compute = node.compute_enabled,
        compute_path = runtime.data_path.join("compute").display(),
    ))
}

pub fn render_docker_agent_config(
    node: &NodeSpec,
    runtime: &NodeRuntime,
    runtimes: &BTreeMap<NodeId, NodeRuntime>,
    cluster: &ClusterSpec,
) -> Result<String> {
    let bootstrap = node
        .bootstrap_nodes
        .iter()
        .map(|id| {
            let peer = runtimes
                .get(id)
                .with_context(|| format!("bootstrap runtime {id} missing"))?;
            Ok(format!("\"{}:{}\"", peer.address, peer.p2p_port))
        })
        .collect::<Result<Vec<_>>>()?
        .join(", ");
    Ok(format!(
        r#"[node]
name = "{name}"
listen_addr = "0.0.0.0:{p2p_port}"
advertise_addr = "{address}:{p2p_port}"
failure_domain = "{failure_domain}"

[data]
path = "/var/lib/pepper/metadata"

[identity]
key_path = "/var/lib/pepper/identity/identity.ed25519"
generate_if_missing = false

[api]
bind_addr = "127.0.0.1:{api_port}"

[auth]
cluster_secret_path = "/var/lib/pepper/identity/cluster.secret"

[[storage.locations]]
path = "/var/lib/pepper/storage"
max_capacity_bytes = {capacity}

[network]
bootstrap_peers = [{bootstrap}]

[namespace]
enabled = {consensus}
consensus_enabled = {consensus}
heartbeat_interval_ms = 250
election_timeout_min_ms = 1500
election_timeout_max_ms = 3000

[replication]
default_factor = {replication}
repair_interval_seconds = {repair_interval}

[compute]
enabled = {compute}
runtime = "firecracker"
max_concurrent_jobs = 1
work_dir = "/var/lib/pepper/compute"
firecracker_allow_untrusted_rootfs = false

[limits]
max_block_bytes = 5242880
max_object_bytes = 6291456
http_requests_per_minute = 12000
rpc_requests_per_minute = 12000

[logging]
format = "json"
"#,
        name = node.id,
        p2p_port = runtime.p2p_port,
        address = runtime.address,
        failure_domain = node.failure_domain,
        api_port = runtime.api_port,
        capacity = node.storage.capacity_bytes,
        consensus = node.consensus_enabled,
        replication = cluster.replication_factor,
        repair_interval = node.storage.repair_interval_seconds,
        compute = node.compute_enabled,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn identity_generation_is_seeded_and_stable() {
        let directory = tempdir().unwrap();
        let node = NodeId::new("node-a").unwrap();
        let first = directory.path().join("first.key");
        let second = directory.path().join("second.key");
        let first_id = write_deterministic_identity(42, &node, &first).unwrap();
        let second_id = write_deterministic_identity(42, &node, &second).unwrap();
        assert_eq!(first_id, second_id);
        assert_eq!(fs::read(first).unwrap(), fs::read(second).unwrap());
    }
}
