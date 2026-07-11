// SPDX-License-Identifier: Apache-2.0

use pepper_types::{
    Cid, ComputeJobStatus, DurabilityReceipt, ErasureManifest, GcReport, NodeStatus,
    PinStatusResponse,
};
use reqwest::StatusCode;
use std::{
    collections::HashSet,
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
    time::Duration,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct ChildGuard(Child);

impl ChildGuard {
    fn kill_and_wait(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn metadata_backup_command_copies_redb() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let config = write_config(temp.path(), "backup-node", free_port()?, free_port()?, &[])?;
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    run_init(agent, &config)?;
    let backup = temp.path().join("backup.redb");
    run_backup(agent, &config, &backup)?;
    assert!(backup.exists());
    assert!(fs::metadata(backup)?.len() > 0);
    Ok(())
}

#[tokio::test]
async fn http_auth_and_limits_are_enforced() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p = free_port()?;
    let api = free_port()?;
    let config = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "auth-node",
        p2p_port: p2p,
        api_port: api,
        bootstrap: &[],
        api_token: Some("dev-token"),
        max_block_bytes: Some(4),
        replication_factor: 1,
    })?;
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    run_init(agent, &config)?;
    let _node = spawn_agent(agent, &config)?;
    let client = reqwest::Client::new();
    wait_health_with_token(api, Some("dev-token")).await?;

    let unauthorized = client
        .get(format!("http://127.0.0.1:{api}/v1/admin/status"))
        .send()
        .await?;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let status = client
        .get(format!("http://127.0.0.1:{api}/v1/admin/status"))
        .bearer_auth("dev-token")
        .send()
        .await?;
    assert_eq!(status.status(), StatusCode::OK);

    let too_large = client
        .post(format!("http://127.0.0.1:{api}/v1/blocks"))
        .bearer_auth("dev-token")
        .body("12345")
        .send()
        .await?;
    assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let accepted: DurabilityReceipt = client
        .post(format!("http://127.0.0.1:{api}/v1/blocks"))
        .bearer_auth("dev-token")
        .body("1234")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let invalid_pin = client
        .post(format!("http://127.0.0.1:{api}/v1/pins"))
        .bearer_auth("dev-token")
        .json(&serde_json::json!({
            "root_cid": accepted.cid,
            "ttl_seconds": 0,
        }))
        .send()
        .await?;
    assert_eq!(invalid_pin.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn erasure_coded_object_roundtrips() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p = free_port()?;
    let api = free_port()?;
    let config = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "ec-node",
        p2p_port: p2p,
        api_port: api,
        bootstrap: &[],
        api_token: None,
        max_block_bytes: None,
        replication_factor: 1,
    })?;
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    run_init(agent, &config)?;
    let _node = spawn_agent(agent, &config)?;
    wait_health(api).await?;

    let client = reqwest::Client::new();
    let payload = b"erasure-coded object payload".repeat(1024);
    let put: DurabilityReceipt = client
        .post(format!(
            "http://127.0.0.1:{api}/v1/objects?erasure_data_shards=3&erasure_parity_shards=2"
        ))
        .body(payload.clone())
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(put.codec.canonical_display(), "0x6");
    let manifest: ErasureManifest = client
        .get(format!(
            "http://127.0.0.1:{api}/v1/blocks/{}",
            encode_path_segment(&put.cid.to_string())
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let missing_shard = manifest.shards[0].cid.clone();
    let missing_shard_path = block_file_path(temp.path(), "ec-node", &missing_shard);
    fs::remove_file(&missing_shard_path)?;

    let restored = client
        .get(format!(
            "http://127.0.0.1:{api}/v1/objects/{}",
            encode_path_segment(&put.cid.to_string())
        ))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    assert_eq!(&restored[..], &payload[..]);

    client
        .post(format!("http://127.0.0.1:{api}/v1/admin/repair"))
        .send()
        .await?
        .error_for_status()?;
    assert!(missing_shard_path.exists());

    let erasure: serde_json::Value = client
        .get(format!("http://127.0.0.1:{api}/v1/admin/erasure"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(erasure["manifests"], 1);
    assert_eq!(erasure["missing_shards"], 0);
    assert_eq!(erasure["unrecoverable_manifests"], 0);
    Ok(())
}

#[tokio::test]
async fn erasure_repair_proactively_rebalances_after_nodes_join() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p1 = free_port()?;
    let p2p2 = free_port()?;
    let p2p3 = free_port()?;
    let api1 = free_port()?;
    let api2 = free_port()?;
    let api3 = free_port()?;
    let config1 = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "node1",
        p2p_port: p2p1,
        api_port: api1,
        bootstrap: &[],
        api_token: None,
        max_block_bytes: None,
        replication_factor: 1,
    })?;
    let config2 = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "node2",
        p2p_port: p2p2,
        api_port: api2,
        bootstrap: &[format!("127.0.0.1:{p2p1}")],
        api_token: None,
        max_block_bytes: None,
        replication_factor: 1,
    })?;
    let config3 = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "node3",
        p2p_port: p2p3,
        api_port: api3,
        bootstrap: &[format!("127.0.0.1:{p2p1}")],
        api_token: None,
        max_block_bytes: None,
        replication_factor: 1,
    })?;
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    run_init(agent, &config1)?;
    run_init(agent, &config2)?;
    run_init(agent, &config3)?;

    let _node1 = spawn_agent(agent, &config1)?;
    wait_health(api1).await?;
    let client = reqwest::Client::new();
    let put: DurabilityReceipt = client
        .post(format!(
            "http://127.0.0.1:{api1}/v1/objects?erasure_data_shards=4&erasure_parity_shards=2"
        ))
        .body(b"rebalance-me".repeat(4096))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let manifest: ErasureManifest = client
        .get(format!(
            "http://127.0.0.1:{api1}/v1/blocks/{}",
            encode_path_segment(&put.cid.to_string())
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let _node2 = spawn_agent(agent, &config2)?;
    let _node3 = spawn_agent(agent, &config3)?;
    wait_health(api2).await?;
    wait_health(api3).await?;
    wait_for_peer_count(api1, 2).await?;

    for _ in 0..80 {
        let _ = client
            .post(format!("http://127.0.0.1:{api1}/v1/admin/repair"))
            .send()
            .await?;
        let erasure: serde_json::Value = client
            .get(format!("http://127.0.0.1:{api1}/v1/admin/erasure"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let copied_to_new_node = manifest.shards.iter().any(|shard| {
            block_file_path(temp.path(), "node2", &shard.cid).exists()
                || block_file_path(temp.path(), "node3", &shard.cid).exists()
        });
        if erasure["metrics"]["shard_rebalances_total"]
            .as_u64()
            .unwrap_or(0)
            > 0
            && copied_to_new_node
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err("EC rebalance did not copy any shard to a newly joined node".into())
}

#[tokio::test]
async fn churn_partition_soak_harness() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p1 = free_port()?;
    let p2p2 = free_port()?;
    let p2p3 = free_port()?;
    let api1 = free_port()?;
    let api2 = free_port()?;
    let api3 = free_port()?;
    let config1 = write_config(temp.path(), "node1", p2p1, api1, &[])?;
    let config2 = write_config(
        temp.path(),
        "node2",
        p2p2,
        api2,
        &[format!("127.0.0.1:{p2p1}")],
    )?;
    let config3 = write_config(
        temp.path(),
        "node3",
        p2p3,
        api3,
        &[format!("127.0.0.1:{p2p1}")],
    )?;
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    run_init(agent, &config1)?;
    run_init(agent, &config2)?;
    run_init(agent, &config3)?;

    let _node1 = spawn_agent(agent, &config1)?;
    let mut node2 = spawn_agent(agent, &config2)?;
    let _node3 = spawn_agent(agent, &config3)?;
    wait_health(api1).await?;
    wait_health(api2).await?;
    wait_health(api3).await?;
    wait_for_peer_count(api1, 2).await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?;

    for iteration in 0..6 {
        let put: DurabilityReceipt = client
            .post(format!(
                "http://127.0.0.1:{api1}/v1/objects?erasure_data_shards=2&erasure_parity_shards=1"
            ))
            .body(format!("soak-payload-{iteration}").repeat(1024))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let restored = client
            .get(format!(
                "http://127.0.0.1:{api3}/v1/objects/{}",
                encode_path_segment(&put.cid.to_string())
            ))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        assert!(restored.starts_with(format!("soak-payload-{iteration}").as_bytes()));
        if iteration % 3 == 1 {
            node2.kill_and_wait();
            node2 = spawn_agent(agent, &config2)?;
            wait_health(api2).await?;
            wait_for_peer_count(api1, 2).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn dht_provider_lookup_finds_block_through_indirect_peer() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p1 = free_port()?;
    let p2p2 = free_port()?;
    let p2p3 = free_port()?;
    let api1 = free_port()?;
    let api2 = free_port()?;
    let api3 = free_port()?;
    let node2_addr = format!("127.0.0.1:{p2p2}");
    let node3_addr = format!("127.0.0.1:{p2p3}");
    let config1 = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "node1",
        p2p_port: p2p1,
        api_port: api1,
        bootstrap: std::slice::from_ref(&node2_addr),
        api_token: None,
        max_block_bytes: None,
        replication_factor: 1,
    })?;
    let config2 = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "node2",
        p2p_port: p2p2,
        api_port: api2,
        bootstrap: std::slice::from_ref(&node3_addr),
        api_token: None,
        max_block_bytes: None,
        replication_factor: 1,
    })?;
    let config3 = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "node3",
        p2p_port: p2p3,
        api_port: api3,
        bootstrap: &[],
        api_token: None,
        max_block_bytes: None,
        replication_factor: 1,
    })?;
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    run_init(agent, &config1)?;
    run_init(agent, &config2)?;
    run_init(agent, &config3)?;

    let _node3 = spawn_agent(agent, &config3)?;
    wait_health(api3).await?;
    let client = reqwest::Client::new();
    let put: DurabilityReceipt = client
        .post(format!("http://127.0.0.1:{api3}/v1/blocks"))
        .body("indirect-dht")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let _node2 = spawn_agent(agent, &config2)?;
    wait_health(api2).await?;
    wait_for_peer(api2).await?;
    let _node1 = spawn_agent(agent, &config1)?;
    wait_health(api1).await?;
    wait_for_peer(api1).await?;

    let bytes = client
        .get(format!(
            "http://127.0.0.1:{api1}/v1/blocks/{}",
            encode_path_segment(&put.cid.to_string())
        ))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    assert_eq!(&bytes[..], b"indirect-dht");
    Ok(())
}

#[tokio::test]
async fn provider_fallback_reads_from_peer_without_local_replica() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p1 = free_port()?;
    let p2p2 = free_port()?;
    let api1 = free_port()?;
    let api2 = free_port()?;
    let node2_addr = format!("127.0.0.1:{p2p2}");
    let config1 = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "node1",
        p2p_port: p2p1,
        api_port: api1,
        bootstrap: std::slice::from_ref(&node2_addr),
        api_token: None,
        max_block_bytes: None,
        replication_factor: 1,
    })?;
    let config2 = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "node2",
        p2p_port: p2p2,
        api_port: api2,
        bootstrap: &[],
        api_token: None,
        max_block_bytes: None,
        replication_factor: 1,
    })?;
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    run_init(agent, &config1)?;
    run_init(agent, &config2)?;
    let _node2 = spawn_agent(agent, &config2)?;
    wait_health(api2).await?;

    let client = reqwest::Client::new();
    let put: DurabilityReceipt = client
        .post(format!("http://127.0.0.1:{api2}/v1/blocks"))
        .body("provider-only")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let _node1 = spawn_agent(agent, &config1)?;
    wait_health(api1).await?;
    wait_for_peer(api1).await?;
    let encoded = encode_path_segment(&put.cid.to_string());
    assert_eq!(
        client
            .head(format!("http://127.0.0.1:{api1}/v1/blocks/{encoded}"))
            .send()
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    let bytes = client
        .get(format!("http://127.0.0.1:{api1}/v1/blocks/{encoded}"))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    assert_eq!(&bytes[..], b"provider-only");
    Ok(())
}

#[tokio::test]
async fn compute_requires_firecracker_rootfs() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p = free_port()?;
    let api = free_port()?;
    let config = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "compute-node",
        p2p_port: p2p,
        api_port: api,
        bootstrap: &[],
        api_token: None,
        max_block_bytes: None,
        replication_factor: 1,
    })?;
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    run_init(agent, &config)?;
    let _node = spawn_agent(agent, &config)?;
    wait_health(api).await?;

    let client = reqwest::Client::new();
    let job = serde_json::json!({
        "type": "pepper.compute_job",
        "version": 1,
        "command": ["sh", "-c", "echo should-not-run"],
        "resources": {"timeout_seconds": 20}
    });
    let response = client
        .post(format!("http://127.0.0.1:{api}/v1/compute/jobs"))
        .json(&job)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.text().await?;
    assert!(body.contains("firecracker compute jobs must set rootfs_cid"));
    Ok(())
}

#[tokio::test]
#[ignore = "requires a Linux/KVM Firecracker host and PEPPER_FIRECRACKER_ROOTFS_IMAGE"]
async fn firecracker_rootfs_cid_and_cancel_host_gated() -> TestResult<()> {
    let Some(rootfs_image) = std::env::var_os("PEPPER_FIRECRACKER_ROOTFS_IMAGE").map(PathBuf::from)
    else {
        eprintln!(
            "skipping host-gated Firecracker test: PEPPER_FIRECRACKER_ROOTFS_IMAGE is not set"
        );
        return Ok(());
    };
    let Some(kernel_image) = readable_firecracker_kernel_image() else {
        eprintln!(
            "skipping host-gated Firecracker test: no readable Firecracker kernel image found; set PEPPER_FIRECRACKER_KERNEL_IMAGE"
        );
        return Ok(());
    };
    let temp = tempfile::tempdir()?;
    let p2p = free_port()?;
    let api = free_port()?;
    let config = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "fc-node",
        p2p_port: p2p,
        api_port: api,
        bootstrap: &[],
        api_token: None,
        max_block_bytes: None,
        replication_factor: 1,
    })?;
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    run_init(agent, &config)?;
    let _node = spawn_agent_with_env(
        agent,
        &config,
        &[("PEPPER_FIRECRACKER_KERNEL_IMAGE", &kernel_image)],
    )?;
    wait_health(api).await?;

    let client = reqwest::Client::new();
    let rootfs_bytes = fs::read(rootfs_image)?;
    let rootfs: DurabilityReceipt = client
        .post(format!("http://127.0.0.1:{api}/v1/objects"))
        .body(rootfs_bytes)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let job = serde_json::json!({
        "type": "pepper.compute_job",
        "version": 1,
        "runtime": "firecracker",
        "rootfs_cid": rootfs.cid,
        "command": ["sh", "-c", "mkdir -p /output && echo firecracker-ok > /output/result.txt"],
        "outputs": [{"path": "output", "name": "result"}],
        "resources": {"timeout_seconds": 60}
    });
    let submit_response = client
        .post(format!("http://127.0.0.1:{api}/v1/compute/jobs"))
        .json(&job)
        .send()
        .await?;
    if !submit_response.status().is_success() {
        return Err(format!(
            "firecracker submit failed: {} {}",
            submit_response.status(),
            submit_response.text().await.unwrap_or_default()
        )
        .into());
    }
    let submit: serde_json::Value = submit_response.json().await?;
    let job_id = submit["job_id"].as_str().expect("job id");
    let status = wait_compute_finished(api, job_id).await?;
    assert_eq!(status.status, "succeeded", "status: {status:?}");

    let cancel_job = serde_json::json!({
        "type": "pepper.compute_job",
        "version": 1,
        "runtime": "firecracker",
        "rootfs_cid": rootfs.cid,
        "command": ["sh", "-c", "sleep 60"],
        "resources": {"timeout_seconds": 120}
    });
    let submit_cancel_response = client
        .post(format!("http://127.0.0.1:{api}/v1/compute/jobs"))
        .json(&cancel_job)
        .send()
        .await?;
    if !submit_cancel_response.status().is_success() {
        return Err(format!(
            "firecracker cancel-job submit failed: {} {}",
            submit_cancel_response.status(),
            submit_cancel_response.text().await.unwrap_or_default()
        )
        .into());
    }
    let submit_cancel: serde_json::Value = submit_cancel_response.json().await?;
    let cancel_job_id = submit_cancel["job_id"].as_str().expect("job id");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let canceled: ComputeJobStatus = client
        .post(format!(
            "http://127.0.0.1:{api}/v1/compute/jobs/{cancel_job_id}/cancel"
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(canceled.status, "canceled");
    assert!(
        canceled
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("firecracker cancel")
    );
    Ok(())
}

#[tokio::test]
async fn repair_replicates_to_new_node_after_replica_loss() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p1 = free_port()?;
    let p2p2 = free_port()?;
    let p2p3 = free_port()?;
    let api1 = free_port()?;
    let api2 = free_port()?;
    let api3 = free_port()?;
    let config1 = write_config(temp.path(), "node1", p2p1, api1, &[])?;
    let config2 = write_config(
        temp.path(),
        "node2",
        p2p2,
        api2,
        &[format!("127.0.0.1:{p2p1}")],
    )?;
    let config3 = write_config(
        temp.path(),
        "node3",
        p2p3,
        api3,
        &[format!("127.0.0.1:{p2p1}")],
    )?;
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    run_init(agent, &config1)?;
    run_init(agent, &config2)?;
    run_init(agent, &config3)?;

    let _node1 = spawn_agent(agent, &config1)?;
    let mut node2 = spawn_agent(agent, &config2)?;
    wait_health(api1).await?;
    wait_health(api2).await?;
    wait_for_peer(api2).await?;

    let client = reqwest::Client::new();
    let put: DurabilityReceipt = client
        .post(format!("http://127.0.0.1:{api1}/v1/blocks"))
        .body("repair-me")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(put.replicas_accepted >= 2, "receipt: {put:?}");
    node2.kill_and_wait();

    let _node3 = spawn_agent(agent, &config3)?;
    wait_health(api3).await?;
    wait_for_peer(api3).await?;
    wait_for_peer_count(api1, 2).await?;
    let encoded = encode_path_segment(&put.cid.to_string());
    for _ in 0..80 {
        let _ = client
            .post(format!("http://127.0.0.1:{api1}/v1/admin/repair"))
            .send()
            .await?;
        if client
            .head(format!("http://127.0.0.1:{api3}/v1/blocks/{encoded}"))
            .send()
            .await?
            .status()
            == StatusCode::NO_CONTENT
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err("repair did not copy block to replacement node".into())
}

#[tokio::test]
async fn implicit_object_root_pin_protects_chunks_until_unpinned() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p = free_port()?;
    let api = free_port()?;
    let config = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "object-pin-node",
        p2p_port: p2p,
        api_port: api,
        bootstrap: &[],
        api_token: None,
        max_block_bytes: None,
        replication_factor: 1,
    })?;
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    run_init(agent, &config)?;
    let _node = spawn_agent(agent, &config)?;
    wait_health(api).await?;

    let client = reqwest::Client::new();
    let payload = vec![42u8; 4 * 1024 * 1024 + 1];
    let put: DurabilityReceipt = client
        .post(format!("http://127.0.0.1:{api}/v1/objects"))
        .body(payload)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let encoded = encode_path_segment(&put.cid.to_string());
    let status: PinStatusResponse = client
        .get(format!("http://127.0.0.1:{api}/v1/pins/{encoded}"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(status.pins.len(), 1);
    assert_eq!(status.reachable_count, 3);

    let protected: GcReport = client
        .post(format!("http://127.0.0.1:{api}/v1/admin/gc"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(protected.deleted_blocks, 0);
    client
        .delete(format!("http://127.0.0.1:{api}/v1/pins/{encoded}"))
        .send()
        .await?
        .error_for_status()?;
    let collected: GcReport = client
        .post(format!("http://127.0.0.1:{api}/v1/admin/gc"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(collected.deleted_blocks, 3);
    Ok(())
}

#[tokio::test]
async fn implicit_pins_protect_and_unpin_collects_three_node_replicas() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p1 = free_port()?;
    let p2p2 = free_port()?;
    let p2p3 = free_port()?;
    let api1 = free_port()?;
    let api2 = free_port()?;
    let api3 = free_port()?;
    let config1 = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "pin-node1",
        p2p_port: p2p1,
        api_port: api1,
        bootstrap: &[],
        api_token: None,
        max_block_bytes: None,
        replication_factor: 3,
    })?;
    let bootstrap = [format!("127.0.0.1:{p2p1}")];
    let config2 = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "pin-node2",
        p2p_port: p2p2,
        api_port: api2,
        bootstrap: &bootstrap,
        api_token: None,
        max_block_bytes: None,
        replication_factor: 3,
    })?;
    let config3 = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "pin-node3",
        p2p_port: p2p3,
        api_port: api3,
        bootstrap: &bootstrap,
        api_token: None,
        max_block_bytes: None,
        replication_factor: 3,
    })?;
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    for config in [&config1, &config2, &config3] {
        run_init(agent, config)?;
    }
    let _node1 = spawn_agent(agent, &config1)?;
    let _node2 = spawn_agent(agent, &config2)?;
    let _node3 = spawn_agent(agent, &config3)?;
    for api in [api1, api2, api3] {
        wait_health(api).await?;
    }
    wait_for_peer_count(api1, 2).await?;

    let client = reqwest::Client::new();
    let put: DurabilityReceipt = client
        .post(format!("http://127.0.0.1:{api1}/v1/blocks"))
        .body("implicitly pinned")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(put.replicas_accepted, 3, "receipt: {put:?}");
    let encoded = encode_path_segment(&put.cid.to_string());

    for api in [api1, api2, api3] {
        let status: PinStatusResponse = client
            .get(format!("http://127.0.0.1:{api}/v1/pins/{encoded}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(status.pins.len(), 1);
        let gc: GcReport = client
            .post(format!("http://127.0.0.1:{api}/v1/admin/gc"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(gc.deleted_blocks, 0);
    }

    client
        .delete(format!("http://127.0.0.1:{api1}/v1/pins/{encoded}"))
        .send()
        .await?
        .error_for_status()?;
    let mut deleted = 0usize;
    for api in [api1, api2, api3] {
        let gc: GcReport = client
            .post(format!("http://127.0.0.1:{api}/v1/admin/gc"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        deleted += gc.deleted_blocks;
    }
    assert_eq!(deleted, 3);
    Ok(())
}

#[tokio::test]
async fn two_node_replicated_write_and_remote_read() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p1 = free_port()?;
    let p2p2 = free_port()?;
    let api1 = free_port()?;
    let api2 = free_port()?;
    let config1 = write_config(temp.path(), "node1", p2p1, api1, &[])?;
    let config2 = write_config(
        temp.path(),
        "node2",
        p2p2,
        api2,
        &[format!("127.0.0.1:{p2p1}")],
    )?;

    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    run_init(agent, &config1)?;
    run_init(agent, &config2)?;

    let _node1 = spawn_agent(agent, &config1)?;
    let _node2 = spawn_agent(agent, &config2)?;
    wait_health(api1).await?;
    wait_health(api2).await?;
    wait_for_peer(api2).await?;

    let client = reqwest::Client::new();
    let put: DurabilityReceipt = client
        .post(format!("http://127.0.0.1:{api2}/v1/blocks"))
        .body("hello from node2")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    assert_eq!(put.status, "durable");
    assert!(put.replicas_accepted >= 2, "receipt: {put:?}");

    let bytes = client
        .get(format!(
            "http://127.0.0.1:{api1}/v1/blocks/{}",
            encode_path_segment(&put.cid.to_string())
        ))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    assert_eq!(&bytes[..], b"hello from node2");

    let status: NodeStatus = client
        .get(format!("http://127.0.0.1:{api1}/v1/node/status"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(status.name, "node1");
    Ok(())
}

fn free_port() -> TestResult<u16> {
    static ALLOCATED_PORTS: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let allocated = ALLOCATED_PORTS.get_or_init(|| Mutex::new(HashSet::new()));
    loop {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let mut allocated = allocated
            .lock()
            .map_err(|_| "test port allocator lock poisoned")?;
        if allocated.insert(port) {
            return Ok(port);
        }
    }
}

fn write_config(
    root: &Path,
    name: &str,
    p2p_port: u16,
    api_port: u16,
    bootstrap: &[String],
) -> TestResult<PathBuf> {
    write_config_with_options(TestConfigOptions {
        root,
        name,
        p2p_port,
        api_port,
        bootstrap,
        api_token: None,
        max_block_bytes: None,
        replication_factor: 2,
    })
}

struct TestConfigOptions<'a> {
    root: &'a Path,
    name: &'a str,
    p2p_port: u16,
    api_port: u16,
    bootstrap: &'a [String],
    api_token: Option<&'a str>,
    max_block_bytes: Option<u64>,
    replication_factor: u16,
}

fn write_config_with_options(options: TestConfigOptions<'_>) -> TestResult<PathBuf> {
    let TestConfigOptions {
        root,
        name,
        p2p_port,
        api_port,
        bootstrap,
        api_token,
        max_block_bytes,
        replication_factor,
    } = options;
    let dir = root.join(name);
    fs::create_dir_all(&dir)?;
    let bootstrap = bootstrap
        .iter()
        .map(|peer| format!("\"{peer}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config = format!(
        r#"
[node]
name = "{name}"
listen_addr = "127.0.0.1:{p2p_port}"

[data]
path = "{dir}/data"

[identity]
key_path = "{dir}/identity.ed25519"
generate_if_missing = true

[api]
bind_addr = "127.0.0.1:{api_port}"

[[storage.locations]]
path = "{dir}/storage"
max_capacity_bytes = 104857600

[network]
bootstrap_peers = [{bootstrap}]

[replication]
default_factor = {replication_factor}
repair_interval_seconds = 5

[compute]
enabled = true
runtime = "firecracker"
max_concurrent_jobs = 1
work_dir = "{dir}/compute"
firecracker_allow_untrusted_rootfs = true

{auth_section}{limits_section}
[logging]
format = "pretty"
"#,
        dir = dir.display(),
        auth_section = api_token
            .map(|token| format!("\n[auth]\napi_bearer_token = \"{token}\"\n"))
            .unwrap_or_default(),
        limits_section = max_block_bytes
            .map(|limit| format!("\n[limits]\nmax_block_bytes = {limit}\n"))
            .unwrap_or_default(),
    );
    let path = dir.join("pepper.toml");
    fs::write(&path, config)?;
    Ok(path)
}

fn run_init(agent: &str, config: &Path) -> TestResult<()> {
    let status = Command::new(agent)
        .arg("--config")
        .arg(config)
        .arg("init")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(format!("pepper-agent init failed for {}", config.display()).into());
    }
    Ok(())
}

fn run_backup(agent: &str, config: &Path, output: &Path) -> TestResult<()> {
    let status = Command::new(agent)
        .arg("--config")
        .arg(config)
        .arg("backup")
        .arg("--output")
        .arg(output)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(format!("pepper-agent backup failed for {}", config.display()).into());
    }
    Ok(())
}

fn spawn_agent(agent: &str, config: &Path) -> TestResult<ChildGuard> {
    spawn_agent_with_env(agent, config, &[])
}

fn spawn_agent_with_env(
    agent: &str,
    config: &Path,
    envs: &[(&str, &Path)],
) -> TestResult<ChildGuard> {
    let mut command = Command::new(agent);
    command
        .arg("--config")
        .arg(config)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in envs {
        command.env(key, value);
    }
    Ok(ChildGuard(command.spawn()?))
}

fn readable_firecracker_kernel_image() -> Option<PathBuf> {
    std::env::var_os("PEPPER_FIRECRACKER_KERNEL_IMAGE")
        .map(PathBuf::from)
        .into_iter()
        .chain([
            PathBuf::from("/boot/vmlinux"),
            PathBuf::from("/boot/vmlinuz"),
            PathBuf::from("/usr/share/firecracker/vmlinux"),
        ])
        .find(|path| std::fs::File::open(path).is_ok())
}

fn block_file_path(root: &Path, name: &str, cid: &Cid) -> PathBuf {
    let digest = hex::encode(cid.digest);
    root.join(name)
        .join("storage")
        .join("blocks")
        .join(cid.hash_alg.code())
        .join(&digest[0..2])
        .join(&digest[2..4])
        .join(
            format!(
                "pepper-v{}_{}_{}_{}.blk",
                cid.version,
                cid.codec.canonical_display(),
                cid.hash_alg.code(),
                digest
            )
            .replace(':', "_"),
        )
}

fn encode_path_segment(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
}

async fn wait_health(api_port: u16) -> TestResult<()> {
    wait_health_with_token(api_port, None).await
}

async fn wait_health_with_token(api_port: u16, token: Option<&str>) -> TestResult<()> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{api_port}/healthz");
    for _ in 0..200 {
        let mut request = client.get(&url);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Ok(response) = request.send().await
            && response.status().is_success()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("agent on port {api_port} did not become healthy after 20 seconds").into())
}

async fn wait_for_peer(api_port: u16) -> TestResult<()> {
    wait_for_peer_count(api_port, 1).await
}

async fn wait_for_peer_count(api_port: u16, count: usize) -> TestResult<()> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{api_port}/v1/node/peers");
    for _ in 0..100 {
        let response = client.get(&url).send().await?;
        if response.status() == StatusCode::OK {
            let peers = response.json::<Vec<serde_json::Value>>().await?;
            if peers.len() >= count {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("agent on port {api_port} did not discover {count} peer(s)").into())
}

async fn wait_compute_finished(api_port: u16, job_id: &str) -> TestResult<ComputeJobStatus> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{api_port}/v1/compute/jobs/{job_id}");
    for _ in 0..100 {
        let status: ComputeJobStatus = client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if matches!(
            status.status.as_str(),
            "succeeded" | "failed" | "timed_out" | "canceled"
        ) {
            return Ok(status);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("compute job {job_id} did not finish").into())
}
