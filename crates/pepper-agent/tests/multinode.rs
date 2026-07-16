// SPDX-License-Identifier: Apache-2.0

use hmac::{Hmac, Mac};
use pepper_types::{
    Cid, ComputeJobStatus, DurabilityReceipt, ErasureManifest, GcReport, NodeStatus,
    PinStatusResponse,
};
use reqwest::{Method, StatusCode};
use sha2::{Digest, Sha256};
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
    assert!(fs::metadata(&backup)?.len() > 0);
    assert!(temp.path().join("backup.redb.manifest.json").exists());
    let restored = Command::new(agent)
        .arg("--config")
        .arg(&config)
        .arg("restore")
        .arg("--input")
        .arg(&backup)
        .arg("--force")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert!(restored.success());
    let mut damaged = fs::read(&backup)?;
    damaged[0] ^= 1;
    fs::write(&backup, damaged)?;
    let rejected = Command::new(agent)
        .arg("--config")
        .arg(&config)
        .arg("restore")
        .arg("--input")
        .arg(&backup)
        .arg("--force")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert!(!rejected.success());
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
    let duplicate = Command::new(agent)
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert!(
        !duplicate.success(),
        "duplicate live identity must be rejected"
    );

    let unauthorized = client
        .get(format!("http://127.0.0.1:{api}/v1/admin/status"))
        .send()
        .await?;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    let unauthorized_diagnostics = client
        .get(format!(
            "http://127.0.0.1:{api}/v1/admin/diagnostics/blocks"
        ))
        .send()
        .await?;
    assert_eq!(
        unauthorized_diagnostics.status(),
        StatusCode::UNAUTHORIZED,
        "diagnostics must use the same authorization boundary as admin APIs"
    );

    let status = client
        .get(format!("http://127.0.0.1:{api}/v1/admin/status"))
        .bearer_auth("dev-token")
        .send()
        .await?;
    assert_eq!(status.status(), StatusCode::OK);
    let metrics = client
        .get(format!("http://127.0.0.1:{api}/metrics"))
        .bearer_auth("dev-token")
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    assert!(metrics.contains("pepper_namespace_commits_total"));
    assert!(metrics.contains("pepper_merkle_nodes_written_total"));
    assert!(metrics.contains("pepper_rpc_request_bytes_total"));
    assert!(metrics.contains("pepper_raft_command_encoded_bytes_total"));
    let ready = client
        .get(format!("http://127.0.0.1:{api}/readyz"))
        .bearer_auth("dev-token")
        .send()
        .await?;
    assert_eq!(ready.status(), StatusCode::OK);

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

    let inventory: serde_json::Value = client
        .get(format!(
            "http://127.0.0.1:{api}/v1/admin/diagnostics/blocks?limit=1"
        ))
        .bearer_auth("dev-token")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(inventory["diagnostic_version"], 1);
    assert_eq!(inventory["consistency"], "local");
    assert_eq!(inventory["data"]["entries"].as_array().unwrap().len(), 1);
    let serialized_inventory = serde_json::to_string(&inventory)?;
    assert!(!serialized_inventory.contains("payload"));
    assert!(!serialized_inventory.contains("private_key"));
    assert!(!serialized_inventory.contains("signature_hex"));
    let encoded_cid = encode_path_segment(&accepted.cid.to_string());
    for path in [
        format!("/v1/admin/diagnostics/providers/{encoded_cid}"),
        format!("/v1/admin/diagnostics/reads/{encoded_cid}"),
        format!("/v1/admin/diagnostics/gc/{encoded_cid}"),
        "/v1/admin/diagnostics/publication-intents?limit=1".to_string(),
        "/v1/admin/diagnostics/network-rpc".to_string(),
        "/v1/admin/diagnostics/repairs".to_string(),
        "/v1/admin/diagnostics/namespaces".to_string(),
    ] {
        let diagnostic: serde_json::Value = client
            .get(format!("http://127.0.0.1:{api}{path}"))
            .bearer_auth("dev-token")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(diagnostic["diagnostic_version"], 1, "path {path}");
        assert_eq!(diagnostic["consistency"], "local", "path {path}");
        let serialized = serde_json::to_string(&diagnostic)?;
        assert!(!serialized.contains("private_key"), "path {path}");
        assert!(!serialized.contains("signature_hex"), "path {path}");
        assert!(!serialized.contains("dev-token"), "path {path}");
    }
    let wrong_erasure_codec = client
        .get(format!(
            "http://127.0.0.1:{api}/v1/admin/diagnostics/erasure/{encoded_cid}"
        ))
        .bearer_auth("dev-token")
        .send()
        .await?;
    assert_eq!(wrong_erasure_codec.status(), StatusCode::BAD_REQUEST);
    let oversized_page = client
        .get(format!(
            "http://127.0.0.1:{api}/v1/admin/diagnostics/blocks?limit=257"
        ))
        .bearer_auth("dev-token")
        .send()
        .await?;
    assert_eq!(oversized_page.status(), StatusCode::BAD_REQUEST);
    let oversized_namespace_page = client
        .get(format!(
            "http://127.0.0.1:{api}/v1/admin/diagnostics/namespaces?limit=257"
        ))
        .bearer_auth("dev-token")
        .send()
        .await?;
    assert_eq!(oversized_namespace_page.status(), StatusCode::BAD_REQUEST);
    let oversized_repair_page = client
        .get(format!(
            "http://127.0.0.1:{api}/v1/admin/diagnostics/repairs?limit=257"
        ))
        .bearer_auth("dev-token")
        .send()
        .await?;
    assert_eq!(oversized_repair_page.status(), StatusCode::BAD_REQUEST);

    let invalid_replication = client
        .post(format!(
            "http://127.0.0.1:{api}/v1/blocks?replication_factor=33"
        ))
        .bearer_auth("dev-token")
        .body("bounded")
        .send()
        .await?;
    assert_eq!(invalid_replication.status(), StatusCode::BAD_REQUEST);

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
async fn s3_multipart_upload_http_contract() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p1 = free_port()?;
    let p2p2 = free_port()?;
    let p2p3 = free_port()?;
    let api = free_port()?;
    let api2 = free_port()?;
    let api3 = free_port()?;
    let config1 = write_s3_config(temp.path(), "s3-multipart-1", p2p1, api, &[])?;
    let config2 = write_s3_config(
        temp.path(),
        "s3-multipart-2",
        p2p2,
        api2,
        &[format!("127.0.0.1:{p2p1}")],
    )?;
    let config3 = write_s3_config(
        temp.path(),
        "s3-multipart-3",
        p2p3,
        api3,
        &[format!("127.0.0.1:{p2p1}"), format!("127.0.0.1:{p2p2}")],
    )?;
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    for config in [&config1, &config2, &config3] {
        run_init(agent, config)?;
    }
    let _node1 = spawn_agent(agent, &config1)?;
    let _node2 = spawn_agent(agent, &config2)?;
    let _node3 = spawn_agent(agent, &config3)?;
    for port in [api, api2, api3] {
        wait_health(port).await?;
    }
    for port in [api, api2, api3] {
        wait_for_peer_count(port, 2).await?;
    }
    let client = reqwest::Client::builder()
        // Completion verifies the composed object's full DAG and may cross several
        // Raft groups. GitHub's two-core runner can take more than 60 seconds while
        // the three child agents are concurrently replicating and applying state.
        .timeout(Duration::from_secs(180))
        .build()?;

    signed_s3_success_with_retry(&client, api, Method::PUT, "/multipart-test", Vec::new()).await?;
    assert!(
        signed_s3_success_with_retry(&client, api2, Method::HEAD, "/multipart-test", Vec::new(),)
            .await?
            .status()
            .is_success()
    );
    let buckets = signed_s3_success_with_retry(&client, api3, Method::GET, "/", Vec::new())
        .await?
        .text()
        .await?;
    assert!(buckets.contains("<Name>multipart-test</Name>"));
    let initiated = signed_s3_success_with_retry(
        &client,
        api2,
        Method::POST,
        "/multipart-test/large.bin?uploads=",
        Vec::new(),
    )
    .await?
    .text()
    .await?;
    let upload_id = xml_value(&initiated, "UploadId")?;
    let empty_objects = signed_s3_success_with_retry(
        &client,
        api,
        Method::GET,
        "/multipart-test?list-type=2",
        Vec::new(),
    )
    .await?
    .text()
    .await?;
    assert!(!empty_objects.contains("<Contents>"));

    let first = vec![b'a'; 5 * 1024 * 1024];
    let first_response = signed_s3_success_with_retry(
        &client,
        api2,
        Method::PUT,
        &format!("/multipart-test/large.bin?partNumber=1&uploadId={upload_id}"),
        first.clone(),
    )
    .await?;
    let first_etag = first_response
        .headers()
        .get("etag")
        .ok_or("UploadPart response omitted ETag")?
        .to_str()?
        .to_string();

    let second = b"pepper multipart tail".to_vec();
    let second_response = signed_s3_success_with_retry(
        &client,
        api3,
        Method::PUT,
        &format!("/multipart-test/large.bin?partNumber=2&uploadId={upload_id}"),
        second.clone(),
    )
    .await?;
    let second_etag = second_response
        .headers()
        .get("etag")
        .ok_or("UploadPart response omitted ETag")?
        .to_str()?
        .to_string();

    let listed = signed_s3_success_with_retry(
        &client,
        api2,
        Method::GET,
        &format!("/multipart-test/large.bin?uploadId={upload_id}"),
        Vec::new(),
    )
    .await?
    .text()
    .await?;
    assert!(listed.contains("<PartNumber>1</PartNumber>"));
    assert!(listed.contains("<PartNumber>2</PartNumber>"));

    let complete = format!(
        "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Part><PartNumber>1</PartNumber><ETag>{first_etag}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{second_etag}</ETag></Part></CompleteMultipartUpload>"
    );
    signed_s3_success_with_retry(
        &client,
        api3,
        Method::POST,
        &format!("/multipart-test/large.bin?uploadId={upload_id}"),
        complete.into_bytes(),
    )
    .await?;

    let downloaded = signed_s3_success_with_retry(
        &client,
        api2,
        Method::GET,
        "/multipart-test/large.bin",
        Vec::new(),
    )
    .await?
    .bytes()
    .await?;
    let mut expected = first;
    expected.extend_from_slice(&second);
    assert_eq!(downloaded.as_ref(), expected.as_slice());

    let abandoned = signed_s3_success_with_retry(
        &client,
        api3,
        Method::POST,
        "/multipart-test/aborted.bin?uploads=",
        Vec::new(),
    )
    .await?
    .text()
    .await?;
    let abandoned_id = xml_value(&abandoned, "UploadId")?;
    assert_eq!(
        signed_s3_success_with_retry(
            &client,
            api2,
            Method::DELETE,
            &format!("/multipart-test/aborted.bin?uploadId={abandoned_id}"),
            Vec::new(),
        )
        .await?
        .status(),
        StatusCode::NO_CONTENT
    );
    let uploads = signed_s3_success_with_retry(
        &client,
        api3,
        Method::GET,
        "/multipart-test?uploads=",
        Vec::new(),
    )
    .await?
    .text()
    .await?;
    assert!(!uploads.contains("<Upload>"));
    Ok(())
}

#[tokio::test]
async fn dag_inspection_uses_shared_traversal() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p = free_port()?;
    let api = free_port()?;
    let config = write_config_with_options(TestConfigOptions {
        root: temp.path(),
        name: "dag-node",
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
    let put: DurabilityReceipt = client
        .post(format!("http://127.0.0.1:{api}/v1/objects"))
        .body("dag inspection payload")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let inspection: serde_json::Value = client
        .get(format!(
            "http://127.0.0.1:{api}/v1/admin/dag/{}",
            encode_path_segment(&put.cid.to_string())
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(inspection["root_cid"], put.cid.to_string());
    assert_eq!(inspection["reachable_count"], 2);
    assert_eq!(inspection["links_examined"], 1);
    assert_eq!(inspection["codecs"]["0x1"], 1);
    assert_eq!(inspection["codecs"]["0x2"], 1);
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
#[ignore = "manual legacy removal gate; replaced by NS-001..004, BUCKET-001..003, and FS-001..003"]
async fn transactional_namespace_http_contract() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p1 = free_port()?;
    let p2p2 = free_port()?;
    let p2p3 = free_port()?;
    let api1 = free_port()?;
    let api2 = free_port()?;
    let api3 = free_port()?;
    let config1 = write_config(temp.path(), "namespace1", p2p1, api1, &[])?;
    let config2 = write_config(
        temp.path(),
        "namespace2",
        p2p2,
        api2,
        &[format!("127.0.0.1:{p2p1}")],
    )?;
    let config3 = write_config(
        temp.path(),
        "namespace3",
        p2p3,
        api3,
        &[format!("127.0.0.1:{p2p1}"), format!("127.0.0.1:{p2p2}")],
    )?;
    for config in [&config1, &config2, &config3] {
        let contents = fs::read_to_string(config)?;
        fs::write(
            config,
            contents
                .replace("default_factor = 2", "default_factor = 3")
                .replace(
                    "consensus_enabled = true",
                    "consensus_enabled = true\nheartbeat_interval_ms = 500\nelection_timeout_min_ms = 3000\nelection_timeout_max_ms = 6000",
                ),
        )?;
    }
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    for config in [&config1, &config2, &config3] {
        run_init(agent, config)?;
    }
    let _one = spawn_agent(agent, &config1)?;
    let _two = spawn_agent(agent, &config2)?;
    let _three = spawn_agent(agent, &config3)?;
    for port in [api1, api2, api3] {
        wait_health(port).await?;
    }
    wait_for_peer_count(api1, 2).await?;
    wait_for_peer_count(api2, 2).await?;
    wait_for_peer_count(api3, 2).await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let create_response = client
        .post(format!("http://127.0.0.1:{api1}/v1/namespaces"))
        .json(&serde_json::json!({"kind":"kv", "alias":"contract"}))
        .send()
        .await?;
    if !create_response.status().is_success() {
        return Err(format!(
            "namespace create failed: {} {}",
            create_response.status(),
            create_response.text().await?
        )
        .into());
    }
    let created: serde_json::Value = create_response.json().await?;
    let namespace = created["namespace_id"]
        .as_str()
        .ok_or("missing namespace_id")?;
    assert_eq!(namespace, created["descriptor_cid"].as_str().unwrap());
    wait_for_namespace_quorum(&[api1, api2, api3], namespace).await?;

    let block: DurabilityReceipt = client
        .post(format!("http://127.0.0.1:{api1}/v1/blocks"))
        .body("namespace-value")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let leader_api = api1;
    let committed = post_json_success_with_retry(
        client.clone(),
        format!("http://127.0.0.1:{leader_api}/v1/kv/put"),
        serde_json::json!({
            "namespace": namespace,
            "key_hex": hex::encode("key"),
            "value_cid": block.cid,
            "request_id": "contract-put"
        }),
    )
    .await?;
    assert_eq!(committed["namespace_revision"], 1);
    let got: serde_json::Value = client.post(format!("http://127.0.0.1:{leader_api}/v1/kv/get"))
        .json(&serde_json::json!({"namespace":namespace, "key_hex":hex::encode("key"), "consistency":"linearizable"}))
        .send().await?.error_for_status()?.json().await?;
    assert_eq!(got["value"]["cid"], block.cid.to_string());
    let replay = post_json_success_with_retry(
        client.clone(),
        format!("http://127.0.0.1:{leader_api}/v1/kv/put"),
        serde_json::json!({"namespace":namespace, "key_hex":hex::encode("key"), "value_cid":block.cid, "request_id":"contract-put"}),
    )
    .await?;
    assert_eq!(replay["replayed"], true);
    let conflict = post_json_until_terminal(
        client.clone(),
        format!("http://127.0.0.1:{leader_api}/v1/kv/put"),
        serde_json::json!({"namespace":namespace, "key_hex":hex::encode("key"), "value_cid":block.cid, "if_generation":0, "request_id":"contract-conflict"}),
    )
    .await?;
    assert_eq!(conflict, reqwest::StatusCode::CONFLICT);
    let historical: serde_json::Value = client
        .post(format!("http://127.0.0.1:{leader_api}/v1/kv/get"))
        .json(
            &serde_json::json!({"namespace":namespace, "key_hex":hex::encode("key"), "revision":0}),
        )
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(historical["stale"], true);
    assert!(historical["value"].is_null());
    let scan: serde_json::Value = client.post(format!("http://127.0.0.1:{leader_api}/v1/kv/scan"))
        .json(&serde_json::json!({"namespace":namespace, "prefix_hex":hex::encode("k"), "limit":10, "consistency":"linearizable"}))
        .send().await?.error_for_status()?.json().await?;
    assert_eq!(scan["entries"].as_array().unwrap().len(), 1);
    let history: serde_json::Value = client
        .get(format!(
            "http://127.0.0.1:{leader_api}/v1/namespaces/{}/history",
            encode_path_segment(namespace)
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(history["history"].get("1").is_some());

    let bucket_created: serde_json::Value = client
        .post(format!("http://127.0.0.1:{api1}/v1/buckets"))
        .json(&serde_json::json!({"alias":"objects"}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let bucket = bucket_created["namespace_id"].as_str().unwrap();
    wait_for_namespace_quorum(&[api1, api2, api3], bucket).await?;
    let bucket_leader = api1;
    let bucket_commit = post_json_success_with_retry(
        client.clone(),
        format!("http://127.0.0.1:{bucket_leader}/v1/bucket/put"),
        serde_json::json!({
            "bucket":bucket,
            "key_hex":hex::encode("object"),
            "content_cid":block.cid,
            "logical_size":15,
            "content_type":"text/plain",
            "request_id":"bucket-put-1"
        }),
    )
    .await?;
    assert_eq!(bucket_commit["namespace_revision"], 1);
    let object: serde_json::Value = client
        .post(format!("http://127.0.0.1:{bucket_leader}/v1/bucket/get"))
        .json(&serde_json::json!({"bucket":bucket, "key_hex":hex::encode("object")}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(object["object"]["content_cid"], block.cid.to_string());
    let object_generation = object["key_generation"]
        .as_u64()
        .ok_or("bucket response is missing key generation")?;
    let race_url = format!("http://127.0.0.1:{bucket_leader}/v1/bucket/put");
    let race_a = post_json_until_terminal(
        client.clone(),
        race_url.clone(),
        serde_json::json!({"bucket":bucket, "key_hex":hex::encode("object"), "content_cid":block.cid, "logical_size":15, "if_generation":object_generation, "request_id":"bucket-race-a"}),
    )
    .await?;
    assert!(race_a.is_success());
    let race_b = post_json_until_terminal(
        client.clone(),
        race_url,
        serde_json::json!({"bucket":bucket, "key_hex":hex::encode("object"), "content_cid":block.cid, "logical_size":15, "if_generation":object_generation, "request_id":"bucket-race-b"}),
    )
    .await?;
    assert_eq!(race_b, reqwest::StatusCode::CONFLICT);
    post_json_success_with_retry(
        client.clone(),
        format!("http://127.0.0.1:{bucket_leader}/v1/bucket/put"),
        serde_json::json!({"bucket":bucket, "key_hex":hex::encode("other"), "content_cid":block.cid, "logical_size":15, "request_id":"bucket-other"}),
    )
    .await?;
    let first_page: serde_json::Value = client
        .post(format!("http://127.0.0.1:{bucket_leader}/v1/bucket/list"))
        .json(&serde_json::json!({"bucket":bucket, "limit":1}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let cursor = first_page["next_cursor"]
        .as_str()
        .ok_or("missing bucket cursor")?;
    post_json_success_with_retry(
        client.clone(),
        format!("http://127.0.0.1:{bucket_leader}/v1/bucket/put"),
        serde_json::json!({"bucket":bucket, "key_hex":hex::encode("third"), "content_cid":block.cid, "logical_size":15, "request_id":"bucket-third"}),
    )
    .await?;
    let mixed_page = client
        .post(format!("http://127.0.0.1:{bucket_leader}/v1/bucket/list"))
        .json(&serde_json::json!({"bucket":bucket, "limit":1, "cursor":cursor}))
        .send()
        .await?;
    assert_eq!(mixed_page.status(), reqwest::StatusCode::BAD_REQUEST);
    let mixed_error: serde_json::Value = mixed_page.json().await?;
    assert_eq!(mixed_error["code"], "invalid_cursor");
    let deleted = post_json_success_with_retry(
        client.clone(),
        format!("http://127.0.0.1:{bucket_leader}/v1/bucket/delete"),
        serde_json::json!({"bucket":bucket, "key_hex":hex::encode("object"), "request_id":"bucket-delete"}),
    )
    .await?;
    assert_eq!(deleted["tombstone"], true);
    let versions: serde_json::Value = client
        .post(format!(
            "http://127.0.0.1:{bucket_leader}/v1/bucket/versions"
        ))
        .json(&serde_json::json!({"bucket":bucket, "key_hex":hex::encode("object")}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(versions["versions"].as_array().unwrap().len() >= 3);
    let historical: serde_json::Value = client
        .post(format!("http://127.0.0.1:{bucket_leader}/v1/bucket/get"))
        .json(&serde_json::json!({"bucket":bucket, "key_hex":hex::encode("object"), "revision":1}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(historical["stale"], true);

    let filesystem_created: serde_json::Value = client
        .post(format!("http://127.0.0.1:{api1}/v1/filesystems"))
        .json(&serde_json::json!({"alias":"tree"}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let filesystem = filesystem_created["namespace_id"].as_str().unwrap();
    wait_for_namespace_quorum(&[api1, api2, api3], filesystem).await?;
    let first_tree = serde_json::json!([
        {"path":"bin","kind":"directory","mode":493,"logical_size":0,"content_cid":null},
        {"path":"bin/hello","kind":"regular_file","mode":493,"logical_size":15,"content_cid":block.cid}
    ]);
    let filesystem_leader = api1;
    let first_commit = post_json_success_with_retry(
        client.clone(),
        format!("http://127.0.0.1:{filesystem_leader}/v1/fs/commit"),
        serde_json::json!({"filesystem":filesystem,"base_revision":0,"entries":first_tree,"message":"initial tree","request_id":"fs-commit-1"}),
    )
    .await?;
    assert_eq!(first_commit["namespace_revision"], 1);
    let checkout: serde_json::Value = client
        .post(format!(
            "http://127.0.0.1:{filesystem_leader}/v1/fs/checkout"
        ))
        .json(&serde_json::json!({"filesystem":filesystem}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(checkout["entries"].as_array().unwrap().len(), 2);
    let second_tree = serde_json::json!([
        {"path":"README","kind":"regular_file","mode":420,"logical_size":15,"content_cid":block.cid},
        {"path":"bin","kind":"directory","mode":493,"logical_size":0,"content_cid":null},
        {"path":"bin/hello","kind":"regular_file","mode":493,"logical_size":15,"content_cid":block.cid}
    ]);
    post_json_success_with_retry(
        client.clone(),
        format!("http://127.0.0.1:{filesystem_leader}/v1/fs/commit"),
        serde_json::json!({"filesystem":filesystem,"base_revision":1,"entries":second_tree,"request_id":"fs-commit-2"}),
    )
    .await?;
    let tree_diff: serde_json::Value = client
        .post(format!("http://127.0.0.1:{filesystem_leader}/v1/fs/diff"))
        .json(&serde_json::json!({"filesystem":filesystem,"revision_a":1,"revision_b":2}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(tree_diff["changes"][0]["path"], "README");
    Ok(())
}

#[tokio::test]
#[ignore = "manual legacy removal gate; replacements include RAFT-002, NEMESIS-001, and SOAK-001; publication-fault and historical gates remain"]
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

async fn signed_s3_request(
    client: &reqwest::Client,
    api_port: u16,
    method: Method,
    path_and_query: &str,
    body: Vec<u8>,
) -> TestResult<reqwest::Response> {
    let (path, query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, ""), |(path, query)| (path, query));
    let host = format!("127.0.0.1:{api_port}");
    let now = time::OffsetDateTime::now_utc();
    let amz_date = now.format(time::macros::format_description!(
        "[year][month][day]T[hour][minute][second]Z"
    ))?;
    let date = &amz_date[..8];
    let payload_hash = hex::encode(Sha256::digest(&body));
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let canonical_request = format!(
        "{}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        method.as_str()
    );
    let scope = format!("{date}/us-east-1/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let mut root_key = b"AWS4".to_vec();
    root_key.extend_from_slice(b"pepper-test-s3-secret-key-1234");
    let date_key = test_hmac(&root_key, date.as_bytes());
    let region_key = test_hmac(&date_key, b"us-east-1");
    let service_key = test_hmac(&region_key, b"s3");
    let signing_key = test_hmac(&service_key, b"aws4_request");
    let signature = hex::encode(test_hmac(&signing_key, string_to_sign.as_bytes()));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential=pepper-test/{scope},SignedHeaders={signed_headers},Signature={signature}"
    );
    Ok(client
        .request(method, format!("http://{host}{path_and_query}"))
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("authorization", authorization)
        .body(body)
        .send()
        .await?)
}

fn test_hmac(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(value);
    mac.finalize().into_bytes().to_vec()
}

async fn s3_success(response: reqwest::Response) -> TestResult<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response.text().await?;
    Err(format!("S3 request failed: {status} {body}").into())
}

async fn signed_s3_success_with_retry(
    client: &reqwest::Client,
    api_port: u16,
    method: Method,
    path_and_query: &str,
    body: Vec<u8>,
) -> TestResult<reqwest::Response> {
    s3_success(signed_s3_response_with_retry(client, api_port, method, path_and_query, body).await?)
        .await
}

async fn signed_s3_response_with_retry(
    client: &reqwest::Client,
    api_port: u16,
    method: Method,
    path_and_query: &str,
    body: Vec<u8>,
) -> TestResult<reqwest::Response> {
    let mut last_error = String::new();
    for _ in 0..40 {
        let response = signed_s3_request(
            client,
            api_port,
            method.clone(),
            path_and_query,
            body.clone(),
        )
        .await?;
        if response.status() != StatusCode::SERVICE_UNAVAILABLE
            && response.status() != StatusCode::CONFLICT
        {
            return Ok(response);
        }
        let status = response.status();
        last_error = format!("{status}: {}", response.text().await?);
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(format!(
        "S3 request {method} {path_and_query} did not succeed before the retry deadline: {last_error}"
    )
    .into())
}

fn xml_value(xml: &str, element: &str) -> TestResult<String> {
    let start_tag = format!("<{element}>");
    let end_tag = format!("</{element}>");
    let start = xml.find(&start_tag).ok_or("missing XML start tag")? + start_tag.len();
    let end = xml[start..]
        .find(&end_tag)
        .map(|offset| start + offset)
        .ok_or("missing XML end tag")?;
    Ok(xml[start..end].to_string())
}

fn write_s3_config(
    root: &Path,
    name: &str,
    p2p_port: u16,
    api_port: u16,
    bootstrap: &[String],
) -> TestResult<PathBuf> {
    let config = write_config_with_options(TestConfigOptions {
        root,
        name,
        p2p_port,
        api_port,
        bootstrap,
        api_token: None,
        max_block_bytes: None,
        replication_factor: 3,
    })?;
    let secret_path = root.join(name).join("s3.secret");
    fs::write(&secret_path, b"pepper-test-s3-secret-key-1234")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))?;
    }
    let mut contents = fs::read_to_string(&config)?;
    contents = contents.replace(
        "consensus_enabled = true",
        "consensus_enabled = true\nheartbeat_interval_ms = 500\nelection_timeout_min_ms = 3000\nelection_timeout_max_ms = 6000",
    );
    contents.push_str(&format!(
        "\n[s3]\nenabled = true\nregion = \"us-east-1\"\naccess_key_id = \"pepper-test\"\nsecret_access_key_path = \"{}\"\n",
        secret_path.display()
    ));
    fs::write(&config, contents)?;
    Ok(config)
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

[namespace]
enabled = true
consensus_enabled = true

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
        // Keep process-level tests from creating one Tokio worker per visible
        // host CPU for every spawned agent. CI executes several agents and
        // consensus runtimes concurrently; two workers are sufficient for the
        // loopback transport while avoiding scheduler starvation.
        .env("TOKIO_WORKER_THREADS", "2")
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
    const ATTEMPTS: usize = 600;
    const INTERVAL: Duration = Duration::from_millis(100);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let url = format!("http://127.0.0.1:{api_port}/v1/node/peers");
    let mut observed = 0usize;
    let mut last_error = None;
    for _ in 0..ATTEMPTS {
        match client.get(&url).send().await {
            Ok(response) if response.status() == StatusCode::OK => {
                match response.json::<Vec<serde_json::Value>>().await {
                    Ok(peers) => {
                        observed = observed.max(peers.len());
                        if peers.len() >= count {
                            return Ok(());
                        }
                    }
                    Err(error) => last_error = Some(error.to_string()),
                }
            }
            Ok(response) => last_error = Some(format!("HTTP {}", response.status())),
            Err(error) => last_error = Some(error.to_string()),
        }
        tokio::time::sleep(INTERVAL).await;
    }
    Err(format!(
        "agent on port {api_port} discovered at most {observed}/{count} peer(s) after {} seconds{}",
        ATTEMPTS as u64 * INTERVAL.as_millis() as u64 / 1_000,
        last_error.map_or_else(String::new, |error| format!("; last error: {error}"))
    )
    .into())
}

async fn post_json_success_with_retry(
    client: reqwest::Client,
    url: String,
    body: serde_json::Value,
) -> TestResult<serde_json::Value> {
    let mut last = None;
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(180) {
        match client
            .post(&url)
            .timeout(Duration::from_secs(120))
            .json(&body)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                return Ok(response.json().await?);
            }
            Ok(response)
                if response.status() == StatusCode::SERVICE_UNAVAILABLE
                    || response.status() == StatusCode::TOO_MANY_REQUESTS =>
            {
                last = Some(format!(
                    "HTTP {}: {}",
                    response.status(),
                    response.text().await?
                ));
            }
            Ok(response) => {
                return Err(format!(
                    "non-retryable response from {url}: HTTP {}: {}",
                    response.status(),
                    response.text().await?
                )
                .into());
            }
            Err(error) => last = Some(error.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "request to {url} did not succeed after 180 seconds: {}",
        last.unwrap_or_else(|| "no response".to_string())
    )
    .into())
}

async fn post_json_until_terminal(
    client: reqwest::Client,
    url: String,
    body: serde_json::Value,
) -> TestResult<StatusCode> {
    let mut last = None;
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(180) {
        match client
            .post(&url)
            .timeout(Duration::from_secs(120))
            .json(&body)
            .send()
            .await
        {
            Ok(response)
                if response.status().is_success() || response.status() == StatusCode::CONFLICT =>
            {
                return Ok(response.status());
            }
            Ok(response)
                if response.status() == StatusCode::SERVICE_UNAVAILABLE
                    || response.status() == StatusCode::TOO_MANY_REQUESTS =>
            {
                last = Some(format!(
                    "HTTP {}: {}",
                    response.status(),
                    response.text().await?
                ));
            }
            Ok(response) => {
                return Err(format!(
                    "non-retryable response from {url}: HTTP {}: {}",
                    response.status(),
                    response.text().await?
                )
                .into());
            }
            Err(error) => last = Some(error.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "request to {url} did not reach a terminal result: {}",
        last.unwrap_or_else(|| "no response".to_string())
    )
    .into())
}

async fn wait_for_namespace_quorum(api_ports: &[u16], namespace: &str) -> TestResult<()> {
    const ATTEMPTS: usize = 600;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let mut errors = Vec::new();
    for _ in 0..ATTEMPTS {
        errors.clear();
        for api_port in api_ports {
            let response = client
                .post(format!("http://127.0.0.1:{api_port}/v1/kv/get"))
                .json(&serde_json::json!({
                    "namespace": namespace,
                    "key_hex": hex::encode("quorum-probe"),
                    "consistency": "linearizable"
                }))
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response) => errors.push(format!("{api_port}: HTTP {}", response.status())),
                Err(error) => errors.push(format!("{api_port}: {error}")),
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "namespace {namespace} did not establish a linearizable quorum after 60 seconds; {}",
        errors.join("; ")
    )
    .into())
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
