// SPDX-License-Identifier: Apache-2.0

use futures_util::future::join_all;
use hmac::{Hmac, Mac};
use pepper_placement::{
    DEFAULT_REPAIR_OWNER_COUNT, PlacementException, PlacementMap, select_authoritative,
    select_repair_owners,
};
use pepper_types::{
    CODEC_SMALL_OBJECT, Cid, ComputeJobStatus, DurabilityReceipt, ErasureManifest,
    ErasureStripeEncoding, GcReport, NodeStatus, PinStatusResponse, PlacementReference,
};
use reqwest::{Method, StatusCode};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Default)]
struct RepairWave {
    successes: usize,
    last_retryable_error: Option<String>,
}

async fn concurrent_repair_wave(
    client: &reqwest::Client,
    api_ports: &[u16],
    requests_per_node: usize,
) -> TestResult<RepairWave> {
    let responses = join_all(
        api_ports
            .iter()
            .cycle()
            .take(api_ports.len().saturating_mul(requests_per_node))
            .map(|api| {
                client
                    .post(format!("http://127.0.0.1:{api}/v1/admin/repair"))
                    .send()
            }),
    )
    .await;
    let mut wave = RepairWave::default();
    for response in responses {
        match response {
            Ok(response) if response.status().is_success() => wave.successes += 1,
            Ok(response)
                if matches!(
                    response.status(),
                    StatusCode::CONFLICT
                        | StatusCode::TOO_MANY_REQUESTS
                        | StatusCode::SERVICE_UNAVAILABLE
                ) =>
            {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                wave.last_retryable_error = Some(format!("{status}: {body}"));
            }
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(format!("non-retryable repair response {status}: {body}").into());
            }
            Err(error) => wave.last_retryable_error = Some(error.to_string()),
        }
    }
    Ok(wave)
}

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
async fn single_node_demo_serves_s3_without_replication() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p = free_port()?;
    let api = free_port()?;
    let config = write_single_node_s3_config(temp.path(), "s3-single-demo", p2p, api)?;
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    run_init(agent, &config)?;
    let mut node = spawn_agent(agent, &config)?;
    wait_health(api).await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;

    signed_s3_success_with_retry(&client, api, Method::PUT, "/demo-bucket", Vec::new()).await?;
    signed_s3_success_with_retry(
        &client,
        api,
        Method::PUT,
        "/demo-bucket/hello.txt",
        b"hello from one node".to_vec(),
    )
    .await?;
    let downloaded = signed_s3_success_with_retry(
        &client,
        api,
        Method::GET,
        "/demo-bucket/hello.txt",
        Vec::new(),
    )
    .await?
    .bytes()
    .await?;
    assert_eq!(downloaded.as_ref(), b"hello from one node");

    let ready: serde_json::Value = client
        .get(format!("http://127.0.0.1:{api}/readyz"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(ready["ready"], true);
    assert!(ready["namespace_groups"].as_array().is_some_and(
        |groups| !groups.is_empty() && groups.iter().all(|group| group["voter_count"] == 1)
    ));

    node.kill_and_wait();
    node = spawn_agent(agent, &config)?;
    wait_health(api).await?;
    let after_restart = signed_s3_success_with_retry(
        &client,
        api,
        Method::GET,
        "/demo-bucket/hello.txt",
        Vec::new(),
    )
    .await?
    .bytes()
    .await?;
    assert_eq!(after_restart.as_ref(), b"hello from one node");
    drop(node);
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
        wait_for_connected_peer_count(port, 2).await?;
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
    let range_start = 3 * 1024 * 1024 + 512 * 1024;
    let range_end = range_start + 1024 * 1024 - 1;
    let range_header = format!("bytes={range_start}-{range_end}");
    let ranged = signed_s3_request_with_headers(
        &client,
        api3,
        Method::GET,
        "/multipart-test/large.bin",
        Vec::new(),
        &[("range", &range_header)],
    )
    .await?;
    assert_eq!(ranged.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        ranged.bytes().await?.as_ref(),
        &expected[range_start..=range_end]
    );

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
async fn s3_catalog_survives_gateway_loss_and_concurrent_load() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p1 = free_port()?;
    let p2p2 = free_port()?;
    let p2p3 = free_port()?;
    let api1 = free_port()?;
    let api2 = free_port()?;
    let api3 = free_port()?;
    let config1 = write_s3_config(temp.path(), "s3-load-1", p2p1, api1, &[])?;
    let config2 = write_s3_config(
        temp.path(),
        "s3-load-2",
        p2p2,
        api2,
        &[format!("127.0.0.1:{p2p1}")],
    )?;
    let config3 = write_s3_config(
        temp.path(),
        "s3-load-3",
        p2p3,
        api3,
        &[format!("127.0.0.1:{p2p1}"), format!("127.0.0.1:{p2p2}")],
    )?;
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    for config in [&config1, &config2, &config3] {
        run_init(agent, config)?;
    }
    let mut node1 = spawn_agent(agent, &config1)?;
    let mut node2 = spawn_agent(agent, &config2)?;
    let _node3 = spawn_agent(agent, &config3)?;
    for api in [api1, api2, api3] {
        wait_health(api).await?;
        wait_for_connected_peer_count(api, 2).await?;
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;
    let provider_discovery_before =
        prometheus_rpc_requests(&client, &[api1, api2, api3], "/block/providers").await?;

    signed_s3_success_with_retry(&client, api1, Method::PUT, "/catalog-warmup", Vec::new()).await?;
    let (left, right) = tokio::join!(
        signed_s3_request(&client, api1, Method::PUT, "/catalog-race", Vec::new()),
        signed_s3_request(&client, api2, Method::PUT, "/catalog-race", Vec::new())
    );
    let statuses = [left?.status(), right?.status()];
    assert_eq!(
        statuses.iter().filter(|status| status.is_success()).count(),
        1,
        "exactly one concurrent CreateBucket must win: {statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CONFLICT)
            .count(),
        1,
        "the losing CreateBucket must receive a stable conflict: {statuses:?}"
    );

    signed_s3_success_with_retry(&client, api1, Method::PUT, "/load-test", Vec::new()).await?;
    let packed_put = signed_s3_success_with_retry(
        &client,
        api1,
        Method::PUT,
        "/load-test/read-target",
        b"stable concurrent read target".to_vec(),
    )
    .await?;
    let packed_cid = packed_put
        .headers()
        .get(reqwest::header::ETAG)
        .ok_or("small-object PUT omitted ETag")?
        .to_str()?
        .trim_matches('"')
        .parse::<Cid>()?;
    assert_eq!(
        packed_cid.codec, CODEC_SMALL_OBJECT,
        "small S3 objects must use the direct segment-record representation"
    );
    let placement_status: serde_json::Value = client
        .get(format!("http://127.0.0.1:{api1}/v1/admin/placement"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let mut next_map = placement_status["current_map"].clone();
    let old_epoch = next_map["epoch"]
        .as_u64()
        .ok_or("placement status omitted the current epoch")?;
    next_map["epoch"] = serde_json::json!(old_epoch + 1);
    let updated: serde_json::Value = client
        .post(format!("http://127.0.0.1:{api1}/v1/admin/placement/maps"))
        .json(&next_map)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(updated["map"]["epoch"].as_u64(), Some(old_epoch + 1));
    let conflicting_epoch = client
        .post(format!("http://127.0.0.1:{api1}/v1/admin/placement/maps"))
        .json(&next_map)
        .send()
        .await?;
    assert_eq!(
        conflicting_epoch.status(),
        StatusCode::BAD_REQUEST,
        "a committed placement epoch cannot be overwritten"
    );
    let old_epoch_bytes = signed_s3_success_with_retry(
        &client,
        api2,
        Method::GET,
        "/load-test/read-target",
        Vec::new(),
    )
    .await?
    .bytes()
    .await?;
    assert_eq!(old_epoch_bytes.as_ref(), b"stable concurrent read target");
    signed_s3_success_with_retry(
        &client,
        api1,
        Method::PUT,
        "/load-test/read-after-write",
        b"generation one".to_vec(),
    )
    .await?;
    let generation_one = signed_s3_success_with_retry(
        &client,
        api2,
        Method::GET,
        "/load-test/read-after-write",
        Vec::new(),
    )
    .await?
    .bytes()
    .await?;
    assert_eq!(generation_one.as_ref(), b"generation one");
    signed_s3_success_with_retry(
        &client,
        api3,
        Method::PUT,
        "/load-test/read-after-write",
        b"generation two".to_vec(),
    )
    .await?;
    let generation_two = signed_s3_success_with_retry(
        &client,
        api2,
        Method::GET,
        "/load-test/read-after-write",
        Vec::new(),
    )
    .await?
    .bytes()
    .await?;
    assert_eq!(generation_two.as_ref(), b"generation two");
    signed_s3_success_with_retry(
        &client,
        api2,
        Method::DELETE,
        "/load-test/read-after-write",
        Vec::new(),
    )
    .await?;
    for method in [Method::GET, Method::HEAD] {
        let deleted = signed_s3_response_with_retry(
            &client,
            api3,
            method,
            "/load-test/read-after-write",
            Vec::new(),
        )
        .await?;
        assert_eq!(deleted.status(), StatusCode::NOT_FOUND);
    }
    let initial_term = stable_namespace_term(&client, api1, "load-test").await?;
    let ports = [api1, api2, api3];
    // Preserve the full load while avoiding a 96-request thundering herd that
    // can starve three agents' Raft runtimes on two-core CI workers.
    let request_slots = Arc::new(Semaphore::new(8));
    let mut writes = tokio::task::JoinSet::new();
    for index in 0..32usize {
        let client = client.clone();
        let api = ports[index % ports.len()];
        let body = vec![index as u8; 4 * 1024];
        let request_slots = Arc::clone(&request_slots);
        writes.spawn(async move {
            let _permit = request_slots.acquire_owned().await?;
            signed_s3_success_with_retry(
                &client,
                api,
                Method::PUT,
                &format!("/load-test/object-{index:02}"),
                body,
            )
            .await
            .map(|response| response.status())
        });
    }
    let mut reads = tokio::task::JoinSet::new();
    for request in 0..64usize {
        let client = client.clone();
        let api = ports[request % ports.len()];
        let request_slots = Arc::clone(&request_slots);
        reads.spawn(async move {
            let _permit = request_slots.acquire_owned().await?;
            let response = signed_s3_success_with_retry(
                &client,
                api,
                if request % 2 == 0 {
                    Method::GET
                } else {
                    Method::HEAD
                },
                "/load-test/read-target",
                Vec::new(),
            )
            .await?;
            if request % 2 == 0 {
                let bytes = response.bytes().await?;
                if bytes.as_ref() != b"stable concurrent read target" {
                    return Err("concurrent S3 GET returned incorrect bytes".into());
                }
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
    }
    while let Some(result) = writes.join_next().await {
        assert!(result??.is_success());
    }
    while let Some(result) = reads.join_next().await {
        result??;
    }
    let final_term = stable_namespace_term(&client, api2, "load-test").await?;
    assert_eq!(
        final_term, initial_term,
        "healthy concurrent S3 traffic must not churn the bucket Raft term"
    );
    let provider_discovery_after =
        prometheus_rpc_requests(&client, &[api1, api2, api3], "/block/providers").await?;
    assert_eq!(
        provider_discovery_after, provider_discovery_before,
        "normal S3 PUT/GET/HEAD/LIST must not issue provider-discovery RPCs"
    );
    let placement_calculations = prometheus_metric_sum(
        &client,
        &[api1, api2, api3],
        "pepper_placement_calculations_total",
    )
    .await?;
    assert!(
        placement_calculations > 0,
        "S3 traffic must exercise authoritative computed placement"
    );
    assert!(
        prometheus_metric_sum(
            &client,
            &[api1, api2, api3],
            "pepper_storage_packed_block_writes_total",
        )
        .await?
            > 0,
        "small-object S3 traffic must append records to the packed segment log"
    );
    let fast_path_dispatches = prometheus_metric_sum(
        &client,
        &[api1, api2, api3],
        "pepper_fast_path_dispatches_total",
    )
    .await?;
    assert!(
        fast_path_dispatches >= 96,
        "ordinary object traffic must execute on stable per-core owners"
    );
    assert_eq!(
        prometheus_metric_sum(
            &client,
            &[api1, api2, api3],
            "pepper_fast_path_rejections_total",
        )
        .await?,
        0,
        "healthy bounded load must not exhaust an owner queue"
    );
    assert_eq!(
        prometheus_metric_sum(
            &client,
            &[api1, api2, api3],
            "pepper_fast_path_owner_failovers_total",
        )
        .await?,
        0,
        "healthy owners must retain stable request affinity"
    );
    assert!(
        prometheus_metric_sum(
            &client,
            &[api1, api2, api3],
            "pepper_fast_path_cross_core_hops_total",
        )
        .await?
            >= fast_path_dispatches.saturating_mul(2),
        "every completed owner request must expose request and response ownership transfers"
    );

    let partition_status: serde_json::Value = client
        .get(format!(
            "http://127.0.0.1:{api2}/v1/admin/s3/buckets/load-test/partitions"
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(partition_status["epoch"].as_u64(), Some(1));
    assert_eq!(
        partition_status["partitions"].as_array().map(Vec::len),
        Some(16)
    );
    let partition_leaders = partition_status["partitions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|partition| partition["leader_id"].as_u64())
        .collect::<HashSet<_>>();
    assert!(
        partition_leaders.len() >= 2,
        "bucket partitions should distribute independent Raft leaders"
    );
    let first_page = signed_s3_success_with_retry(
        &client,
        api1,
        Method::GET,
        "/load-test?list-type=2&max-keys=5",
        Vec::new(),
    )
    .await?
    .text()
    .await?;
    assert!(first_page.contains("<IsTruncated>true</IsTruncated>"));
    let continuation = xml_value(&first_page, "NextContinuationToken")?;
    let first_keys = xml_values(&first_page, "Key");
    assert_eq!(first_keys.len(), 5);
    assert!(first_keys.windows(2).all(|keys| keys[0] < keys[1]));
    let split_partition = partition_status["partitions"][0]["partition"]["partition_id"]
        .as_u64()
        .ok_or("partition status omitted partition_id")?;
    let mut reconfiguration_writes = tokio::task::JoinSet::new();
    for index in 0..16usize {
        let client = client.clone();
        let api = ports[index % ports.len()];
        let request_slots = Arc::clone(&request_slots);
        reconfiguration_writes.spawn(async move {
            let _permit = request_slots.acquire_owned().await?;
            signed_s3_success_with_retry(
                &client,
                api,
                Method::PUT,
                &format!("/load-test/reconfiguration-{index:02}"),
                vec![index as u8; 1024],
            )
            .await
            .map(|response| response.status())
        });
    }
    let split: serde_json::Value = client
        .post(format!(
            "http://127.0.0.1:{api3}/v1/admin/s3/buckets/load-test/partitions"
        ))
        .json(&serde_json::json!({
            "operation": "split",
            "partition_id": split_partition,
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(split["epoch"].as_u64(), Some(2));
    assert_eq!(split["partition_count"].as_u64(), Some(17));
    while let Some(result) = reconfiguration_writes.join_next().await {
        assert!(result??.is_success());
    }
    let stable_second_page = signed_s3_success_with_retry(
        &client,
        api2,
        Method::GET,
        &format!("/load-test?continuation-token={continuation}&list-type=2&max-keys=5"),
        Vec::new(),
    )
    .await?
    .text()
    .await?;
    assert!(stable_second_page.contains("<ListBucketResult"));
    let second_keys = xml_values(&stable_second_page, "Key");
    assert_eq!(second_keys.len(), 5);
    assert!(second_keys.windows(2).all(|keys| keys[0] < keys[1]));
    assert!(first_keys.last() < second_keys.first());
    for key in ["read-target", "object-00", "object-31"] {
        let bytes = signed_s3_success_with_retry(
            &client,
            api3,
            Method::GET,
            &format!("/load-test/{key}"),
            Vec::new(),
        )
        .await?
        .bytes()
        .await?;
        assert!(!bytes.is_empty(), "{key} must remain readable after split");
    }
    let after_split: serde_json::Value = client
        .get(format!(
            "http://127.0.0.1:{api1}/v1/admin/s3/buckets/load-test/partitions"
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let moved_id = after_split["partitions"][0]["partition"]["partition_id"]
        .as_u64()
        .ok_or("split status omitted partition_id")?;
    let moved: serde_json::Value = client
        .post(format!(
            "http://127.0.0.1:{api2}/v1/admin/s3/buckets/load-test/partitions"
        ))
        .json(&serde_json::json!({"operation": "move", "partition_id": moved_id}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(moved["epoch"].as_u64(), Some(3));
    assert_eq!(moved["partition_count"].as_u64(), Some(17));
    let after_move: serde_json::Value = client
        .get(format!(
            "http://127.0.0.1:{api3}/v1/admin/s3/buckets/load-test/partitions"
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let merge_id = after_move["partitions"][0]["partition"]["partition_id"]
        .as_u64()
        .ok_or("move status omitted partition_id")?;
    let merged: serde_json::Value = client
        .post(format!(
            "http://127.0.0.1:{api1}/v1/admin/s3/buckets/load-test/partitions"
        ))
        .json(&serde_json::json!({"operation": "merge", "partition_id": merge_id}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(merged["epoch"].as_u64(), Some(4));
    assert_eq!(merged["partition_count"].as_u64(), Some(16));
    let partition_routes = prometheus_metric_sum(
        &client,
        &[api1, api2, api3],
        "pepper_s3_partition_routes_total",
    )
    .await?;
    let list_barriers = prometheus_metric_sum(
        &client,
        &[api1, api2, api3],
        "pepper_s3_list_barriers_total",
    )
    .await?;
    assert!(partition_routes > 0 && list_barriers > 0);

    node2.kill_and_wait();
    let _restarted_node2 = spawn_agent(agent, &config2)?;
    wait_health(api2).await?;
    wait_for_connected_peer_count(api2, 2).await?;
    let after_restart = signed_s3_success_with_retry(
        &client,
        api2,
        Method::GET,
        "/load-test/read-target",
        Vec::new(),
    )
    .await?
    .bytes()
    .await?;
    assert_eq!(after_restart.as_ref(), b"stable concurrent read target");

    signed_s3_success_with_retry(
        &client,
        api1,
        Method::PUT,
        "/load-test/gateway-loss",
        b"catalog remains quorum-readable".to_vec(),
    )
    .await?;
    node1.kill_and_wait();
    for api in [api2, api3] {
        let buckets = signed_s3_success_with_retry(&client, api, Method::GET, "/", Vec::new())
            .await?
            .text()
            .await?;
        assert!(buckets.contains("<Name>load-test</Name>"));
        assert!(
            signed_s3_success_with_retry(&client, api, Method::HEAD, "/load-test", Vec::new())
                .await?
                .status()
                .is_success()
        );
        let bytes = signed_s3_success_with_retry(
            &client,
            api,
            Method::GET,
            "/load-test/gateway-loss",
            Vec::new(),
        )
        .await?
        .bytes()
        .await?;
        assert_eq!(bytes.as_ref(), b"catalog remains quorum-readable");
    }
    Ok(())
}

async fn prometheus_rpc_requests(
    client: &reqwest::Client,
    api_ports: &[u16],
    method: &str,
) -> TestResult<u64> {
    let mut total = 0u64;
    for api in api_ports {
        let body = client
            .get(format!("http://127.0.0.1:{api}/metrics"))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        total = total.saturating_add(
            body.lines()
                .filter(|line| {
                    line.starts_with("pepper_rpc_requests_total{")
                        && line.contains(&format!("method=\"{method}\""))
                        && line.contains("direction=\"outbound\"")
                })
                .filter_map(|line| line.rsplit_once(' '))
                .filter_map(|(_, value)| value.parse::<u64>().ok())
                .sum::<u64>(),
        );
    }
    Ok(total)
}

async fn prometheus_metric_sum(
    client: &reqwest::Client,
    api_ports: &[u16],
    metric: &str,
) -> TestResult<u64> {
    let mut total = 0u64;
    for api in api_ports {
        let body = client
            .get(format!("http://127.0.0.1:{api}/metrics"))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        total = total.saturating_add(
            body.lines()
                .find_map(|line| {
                    line.strip_prefix(metric)
                        .and_then(|value| value.strip_prefix(' '))
                        .and_then(|value| value.parse::<u64>().ok())
                })
                .unwrap_or(0),
        );
    }
    Ok(total)
}

async fn prometheus_labelled_metric(
    client: &reqwest::Client,
    api: u16,
    metric: &str,
    label: &str,
) -> TestResult<u64> {
    let body = client
        .get(format!("http://127.0.0.1:{api}/metrics"))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    Ok(body
        .lines()
        .find_map(|line| {
            line.strip_prefix(&format!("{metric}{{plan=\"{label}\"}} "))
                .and_then(|value| value.parse::<u64>().ok())
        })
        .unwrap_or(0))
}

fn deterministic_incompressible(size: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut payload = vec![0u8; size];
    for output in payload.chunks_mut(std::mem::size_of::<u64>()) {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^= value >> 31;
        output.copy_from_slice(&value.to_le_bytes()[..output.len()]);
    }
    payload
}

fn deterministic_compressible(size: usize, seed: u64, ratio: usize) -> Vec<u8> {
    let base = deterministic_incompressible(size.div_ceil(ratio).max(1), seed);
    base.iter().copied().cycle().take(size).collect()
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
    let payload = (0..25 * 1024 * 1024)
        .map(|index| ((index * 31 + index / 4093) & 0xff) as u8)
        .collect::<Vec<_>>();
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
    assert_eq!(manifest.stripes.len(), 3);
    assert_eq!(manifest.stripes[0].offset, 0);
    assert_eq!(manifest.stripes[1].offset, 12 * 1024 * 1024);
    assert_eq!(manifest.stripes[2].offset, 24 * 1024 * 1024);
    let missing_shard = manifest.stripes[0].shards[0].cid.clone();
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

    for shard in manifest.stripes[0].shards.iter().take(3) {
        fs::remove_file(block_file_path(temp.path(), "ec-node", &shard.cid))?;
    }
    let unavailable = client
        .get(format!(
            "http://127.0.0.1:{api}/v1/objects/{}",
            encode_path_segment(&put.cid.to_string())
        ))
        .send()
        .await?;
    assert_eq!(unavailable.status().as_u16(), 500);
    let error: serde_json::Value = unavailable.json().await?;
    assert_eq!(error["code"], "internal");
    Ok(())
}

#[tokio::test]
async fn s3_adaptive_erasure_transfer_plans_preserve_canonical_layout() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p_ports = (0..9)
        .map(|_| free_port())
        .collect::<TestResult<Vec<_>>>()?;
    let api_ports = (0..9)
        .map(|_| free_port())
        .collect::<TestResult<Vec<_>>>()?;
    let peer_addresses = p2p_ports
        .iter()
        .map(|port| format!("127.0.0.1:{port}"))
        .collect::<Vec<_>>();
    let plans = [
        "gateway-fanout",
        "distributed-parity",
        "hierarchical",
        "pipelined",
    ];
    let mut configs = Vec::new();
    let mut node_names = Vec::new();
    for index in 0..9 {
        let node_name = format!("adaptive-ec-node-{}", index + 1);
        let bootstrap = peer_addresses
            .iter()
            .enumerate()
            .filter(|(peer_index, _)| *peer_index != index)
            .map(|(_, address)| address.clone())
            .collect::<Vec<_>>();
        configs.push(write_s3_erasure_config_with_options(
            temp.path(),
            &node_name,
            &format!("rack-{}", index + 1),
            p2p_ports[index],
            api_ports[index],
            &bootstrap,
            plans
                .get(index)
                .copied()
                .or((index == 4).then_some("distributed-parity")),
            1,
        )?);
        node_names.push(node_name);
    }
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    for config in &configs {
        run_init(agent, config)?;
    }
    let mut nodes = Vec::new();
    let mut logs = Vec::new();
    for (index, config) in configs.iter().enumerate() {
        let log = temp
            .path()
            .join(format!("adaptive-ec-node-{}.log", index + 1));
        nodes.push(spawn_agent_with_log(agent, config, &log)?);
        logs.push(log);
    }
    for api in &api_ports {
        wait_health(*api).await?;
    }
    for api in &api_ports[..4] {
        wait_for_connected_peer_count(*api, 8).await?;
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()?;
    signed_s3_success_with_retry(
        &client,
        api_ports[0],
        Method::PUT,
        "/adaptive-transfer",
        Vec::new(),
    )
    .await?;
    for api in &api_ports {
        signed_s3_success_with_retry(
            &client,
            *api,
            Method::HEAD,
            "/adaptive-transfer",
            Vec::new(),
        )
        .await?;
    }
    let placement_status: serde_json::Value = client
        .get(format!(
            "http://127.0.0.1:{}/v1/admin/placement",
            api_ports[0]
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let placement_map: PlacementMap =
        serde_json::from_value(placement_status["current_map"].clone())?;
    let mut node_index_by_id = std::collections::HashMap::new();
    for (index, api) in api_ports.iter().enumerate() {
        let status: NodeStatus = client
            .get(format!("http://127.0.0.1:{api}/v1/node/status"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        node_index_by_id.insert(status.node_id, index);
    }

    for (index, plan) in plans.iter().enumerate() {
        let payload = deterministic_incompressible(8 * 1024 * 1024, index as u64 + 1);
        let path = format!("/adaptive-transfer/{plan}.bin");
        let put = signed_s3_success_with_retry(
            &client,
            api_ports[index],
            Method::PUT,
            &path,
            payload.clone(),
        )
        .await?;
        let manifest_cid = put
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim_matches('"').parse::<Cid>())
            .transpose()?
            .ok_or("adaptive EC PUT omitted manifest ETag")?;
        let manifest_placement =
            PlacementReference::replicated(placement_map.epoch, manifest_cid.clone(), 3);
        let manifest_owner = select_authoritative(&placement_map, &manifest_placement)?
            .node_ids
            .into_iter()
            .next()
            .ok_or("adaptive manifest has no owner")?;
        let manifest_owner_index = *node_index_by_id
            .get(&manifest_owner)
            .ok_or("adaptive manifest owner is unknown")?;
        let manifest: ErasureManifest = client
            .get(format!(
                "http://127.0.0.1:{}/v1/blocks/{}",
                api_ports[manifest_owner_index],
                encode_path_segment(&manifest_cid.to_string())
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!((manifest.data_shards, manifest.parity_shards), (6, 3));
        assert_eq!(manifest.stripes.len(), 1);
        assert_eq!(manifest.stripes[0].shards.len(), 9);
        assert_eq!(manifest.stripes[0].encoding, ErasureStripeEncoding::Raw);
        let mut shard_owners = HashSet::new();
        for shard in &manifest.stripes[0].shards {
            let owner = select_authoritative(&placement_map, &shard.placement)?
                .node_ids
                .into_iter()
                .next()
                .ok_or("adaptive shard has no owner")?;
            assert!(shard_owners.insert(owner.clone()));
            let owner_index = *node_index_by_id
                .get(&owner)
                .ok_or("adaptive shard owner is unknown")?;
            for (node_index, node_name) in node_names.iter().enumerate() {
                assert_eq!(
                    block_file_path(temp.path(), node_name, &shard.cid).exists(),
                    node_index == owner_index,
                    "plan {plan} changed canonical owner for shard {}",
                    shard.index
                );
            }
        }
        let reader = api_ports[(index + 4) % api_ports.len()];
        let downloaded =
            signed_s3_bytes_with_retry(&client, reader, Method::GET, &path, Vec::new()).await?;
        assert_eq!(downloaded.as_slice(), payload.as_slice(), "plan {plan}");
        let plan_completed = prometheus_labelled_metric(
            &client,
            api_ports[index],
            "pepper_erasure_transfer_plan_completed_total",
            plan,
        )
        .await?;
        let plan_failures = prometheus_labelled_metric(
            &client,
            api_ports[index],
            "pepper_erasure_transfer_plan_failures_total",
            plan,
        )
        .await?;
        if plan_completed != 1 || plan_failures != 0 {
            for log in &logs {
                eprintln!("===== {} =====", log.display());
                for line in fs::read_to_string(log).unwrap_or_default().lines() {
                    if line.contains("erasure")
                        || line.contains("deadline")
                        || line.contains("Deadline")
                        || line.contains("stream")
                    {
                        eprintln!("{line}");
                    }
                }
            }
        }
        assert_eq!(
            plan_completed, 1,
            "forced plan {plan} did not complete exactly one stripe"
        );
        assert_eq!(plan_failures, 0, "forced plan {plan} required fallback");
        let internal_bytes = prometheus_labelled_metric(
            &client,
            api_ports[index],
            "pepper_erasure_transfer_plan_internal_bytes_total",
            plan,
        )
        .await?;
        let gateway_bytes = prometheus_labelled_metric(
            &client,
            api_ports[index],
            "pepper_erasure_transfer_plan_gateway_bytes_total",
            plan,
        )
        .await?;
        let cross_domain_bytes = prometheus_labelled_metric(
            &client,
            api_ports[index],
            "pepper_erasure_transfer_plan_cross_domain_bytes_total",
            plan,
        )
        .await?;
        assert!(internal_bytes >= gateway_bytes && gateway_bytes > 0);
        assert!(cross_domain_bytes > 0 && cross_domain_bytes <= internal_bytes);
    }

    // Fail a parity-only canonical target after all six systematic owners are
    // known. The distributed executor and direct fallback must both retain the
    // same OPT-8 destination, so this request fails rather than silently
    // weakening or changing the 6+3 layout. Once that exact node returns, an
    // identical request is idempotently safe and succeeds.
    let failure_gateway_index = 4usize;
    let (failure_payload, failed_target_index) = (100u64..)
        .find_map(|seed| {
            let payload = deterministic_incompressible(8 * 1024 * 1024, seed);
            let logical_cid = Cid::new(pepper_types::CODEC_RAW, &payload);
            let parity = PlacementReference::erasure_shard(placement_map.epoch, logical_cid, 6);
            let owner = select_authoritative(&placement_map, &parity)
                .ok()?
                .node_ids
                .into_iter()
                .next()?;
            let target = *node_index_by_id.get(&owner)?;
            (target != failure_gateway_index).then_some((payload, target))
        })
        .ok_or("could not choose a remote parity target")?;
    nodes[failed_target_index].kill_and_wait();
    let failure_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(45))
        .build()?;
    let failed = signed_s3_request(
        &failure_client,
        api_ports[failure_gateway_index],
        Method::PUT,
        "/adaptive-transfer/parity-target-retry.bin",
        failure_payload.clone(),
    )
    .await?;
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    let absent = signed_s3_request(
        &client,
        api_ports[failure_gateway_index],
        Method::HEAD,
        "/adaptive-transfer/parity-target-retry.bin",
        Vec::new(),
    )
    .await?;
    assert_eq!(absent.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        prometheus_labelled_metric(
            &client,
            api_ports[failure_gateway_index],
            "pepper_erasure_transfer_plan_failures_total",
            "distributed-parity",
        )
        .await?,
        1
    );
    assert_eq!(
        prometheus_labelled_metric(
            &client,
            api_ports[failure_gateway_index],
            "pepper_erasure_transfer_plan_fallback_total",
            "distributed-parity",
        )
        .await?,
        1
    );

    nodes[failed_target_index] = spawn_agent_with_log(
        agent,
        &configs[failed_target_index],
        &logs[failed_target_index],
    )?;
    wait_health(api_ports[failed_target_index]).await?;
    wait_for_connected_peer_count(api_ports[failure_gateway_index], 8).await?;
    signed_s3_success_with_retry(
        &client,
        api_ports[failure_gateway_index],
        Method::PUT,
        "/adaptive-transfer/parity-target-retry.bin",
        failure_payload.clone(),
    )
    .await?;
    let restored = signed_s3_bytes_with_retry(
        &client,
        api_ports[7],
        Method::GET,
        "/adaptive-transfer/parity-target-retry.bin",
        Vec::new(),
    )
    .await?;
    assert_eq!(restored.as_slice(), failure_payload.as_slice());
    let completed = prometheus_labelled_metric(
        &client,
        api_ports[failure_gateway_index],
        "pepper_erasure_transfer_plan_completed_total",
        "distributed-parity",
    )
    .await?;
    if completed == 0 {
        for log in &logs {
            eprintln!("===== {} =====", log.display());
            eprintln!("{}", fs::read_to_string(log).unwrap_or_default());
        }
    }
    // A transport or publication retry may repeat an already-idempotent data
    // transfer before the S3 operation becomes visible. Require proof that
    // the distributed plan recovered, without treating a safe repeated
    // transfer as a correctness failure.
    assert!(completed >= 1);
    drop(nodes);
    Ok(())
}

#[tokio::test]
async fn s3_streaming_six_plus_three_survives_three_missing_shards() -> TestResult<()> {
    s3_nine_node_streaming_contract(false).await
}

#[tokio::test]
async fn s3_small_objects_pack_into_partitioned_ec_extents() -> TestResult<()> {
    s3_nine_node_streaming_contract(true).await
}

#[tokio::test]
async fn s3_placement_owned_repair_fails_over_migrates_and_collects_extras() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p_ports = (0..4)
        .map(|_| free_port())
        .collect::<TestResult<Vec<_>>>()?;
    let api_ports = (0..4)
        .map(|_| free_port())
        .collect::<TestResult<Vec<_>>>()?;
    let peer_addresses = p2p_ports
        .iter()
        .map(|port| format!("127.0.0.1:{port}"))
        .collect::<Vec<_>>();
    let mut configs = Vec::new();
    let mut node_names = Vec::new();
    for index in 0..4 {
        let name = format!("owned-repair-node-{}", index + 1);
        let bootstrap = peer_addresses
            .iter()
            .enumerate()
            .filter(|(peer_index, _)| *peer_index != index)
            .map(|(_, address)| address.clone())
            .collect::<Vec<_>>();
        configs.push(write_s3_config(
            temp.path(),
            &name,
            p2p_ports[index],
            api_ports[index],
            &bootstrap,
        )?);
        node_names.push(name);
    }
    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    for config in &configs {
        run_init(agent, config)?;
    }
    let mut nodes = Vec::new();
    let mut logs = Vec::new();
    for (index, config) in configs.iter().enumerate() {
        let log = temp
            .path()
            .join(format!("owned-repair-node-{}.log", index + 1));
        nodes.push(spawn_agent_with_log(agent, config, &log)?);
        logs.push(log);
    }
    for api in &api_ports {
        wait_health(*api).await?;
    }
    wait_for_connected_peer_count(api_ports[0], 3).await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()?;
    let provider_before = prometheus_rpc_requests(&client, &api_ports, "/block/providers").await?;
    signed_s3_success_with_retry(
        &client,
        api_ports[0],
        Method::PUT,
        "/owned-repair",
        Vec::new(),
    )
    .await?;
    let payload = deterministic_incompressible(2 * 1024 * 1024, 0x51a7);
    let put = signed_s3_success_with_retry(
        &client,
        api_ports[0],
        Method::PUT,
        "/owned-repair/object.bin",
        payload.clone(),
    )
    .await?;
    let content_cid = put
        .headers()
        .get(reqwest::header::ETAG)
        .ok_or("owned-repair PUT omitted ETag")?
        .to_str()?
        .trim_matches('"')
        .parse::<Cid>()?;
    let placement_status: serde_json::Value = client
        .get(format!(
            "http://127.0.0.1:{}/v1/admin/placement",
            api_ports[0]
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let mut next_map_json = placement_status["current_map"].clone();
    let initial_map: PlacementMap = serde_json::from_value(next_map_json.clone())?;
    let content_placement =
        PlacementReference::replicated(initial_map.epoch, content_cid.clone(), 3);
    let mut node_index_by_id = std::collections::HashMap::new();
    for (index, api) in api_ports.iter().enumerate() {
        let status: NodeStatus = client
            .get(format!("http://127.0.0.1:{api}/v1/node/status"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        node_index_by_id.insert(status.node_id, index);
    }
    let canonical = select_authoritative(&initial_map, &content_placement)?.node_ids;
    assert_eq!(canonical.len(), 3);

    // Commit a new map epoch before repair. Inventory replay must move to the
    // new deterministic owner set while the immutable object remains bound to
    // its original placement epoch.
    next_map_json["epoch"] = serde_json::json!(initial_map.epoch + 1);
    let updated: serde_json::Value = client
        .post(format!(
            "http://127.0.0.1:{}/v1/admin/placement/maps",
            api_ports[0]
        ))
        .json(&next_map_json)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let next_map: PlacementMap = serde_json::from_value(updated["map"].clone())?;
    for api in &api_ports {
        let observed: serde_json::Value = client
            .get(format!("http://127.0.0.1:{api}/v1/admin/placement"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(
            observed["current_map"]["epoch"].as_u64(),
            Some(next_map.epoch)
        );
    }
    let repair_owners =
        select_repair_owners(&next_map, &content_placement, DEFAULT_REPAIR_OWNER_COUNT)?;
    let primary_index = *node_index_by_id
        .get(&repair_owners[0])
        .ok_or("primary repair owner is unknown")?;
    let standby_index = *node_index_by_id
        .get(&repair_owners[1])
        .ok_or("first standby repair owner is unknown")?;
    let responses = join_all(api_ports.iter().map(|api| {
        client
            .post(format!("http://127.0.0.1:{api}/v1/admin/repair"))
            .send()
    }))
    .await;
    for response in responses {
        response?.error_for_status()?;
    }
    for owner in &repair_owners {
        let owner_index = *node_index_by_id
            .get(owner)
            .ok_or("repair inventory owner is unknown")?;
        assert!(
            prometheus_metric_sum(
                &client,
                &[api_ports[owner_index]],
                "pepper_placement_repair_inventory_events_total",
            )
            .await?
                >= 1,
            "placement epoch handoff did not install inventory on owner {owner}"
        );
    }
    let missing_owner = canonical
        .iter()
        .find(|node_id| *node_id != &repair_owners[0])
        .ok_or("no canonical target distinct from the primary repair owner")?;
    let missing_index = *node_index_by_id
        .get(missing_owner)
        .ok_or("missing canonical target is unknown")?;
    let missing_path = block_file_path(temp.path(), &node_names[missing_index], &content_cid);
    assert!(missing_path.exists());
    fs::remove_file(&missing_path)?;
    let missing_head = client
        .head(format!(
            "http://127.0.0.1:{}/v1/blocks/{}",
            api_ports[missing_index],
            encode_path_segment(&content_cid.to_string())
        ))
        .send()
        .await?;
    assert_eq!(
        missing_head.status(),
        StatusCode::NOT_FOUND,
        "test setup did not remove the selected canonical replica"
    );
    let completed_before = prometheus_metric_sum(
        &client,
        &api_ports,
        "pepper_placement_repair_tasks_completed_total",
    )
    .await?;
    nodes[primary_index].kill_and_wait();
    let active_apis = api_ports
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != primary_index)
        .map(|(_, api)| *api)
        .collect::<Vec<_>>();
    for _ in 0..1 {
        let response = client
            .post(format!(
                "http://127.0.0.1:{}/v1/admin/repair",
                api_ports[standby_index]
            ))
            .send()
            .await;
        if let Ok(response) = response
            && !response.status().is_success()
        {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            eprintln!("standby repair returned {status}: {body}");
        }
        if missing_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    if !missing_path.exists() {
        for log in &logs {
            eprintln!("===== {} =====", log.display());
            for line in fs::read_to_string(log).unwrap_or_default().lines() {
                if line.contains("authoritative repair owner")
                    || line.contains("repair inventory")
                    || line.contains("placement-owned")
                {
                    eprintln!("{line}");
                }
            }
        }
    }
    assert!(
        missing_path.exists(),
        "standby did not repair after primary-owner loss"
    );
    assert!(
        prometheus_metric_sum(
            &client,
            &active_apis,
            "pepper_placement_repair_tasks_completed_total",
        )
        .await?
        .saturating_sub(completed_before)
            >= 1,
        "owner failover must complete at least the deliberately removed replica; data placements on the stopped owner are repaired too"
    );

    nodes[primary_index] =
        spawn_agent_with_log(agent, &configs[primary_index], &logs[primary_index])?;
    wait_health(api_ports[primary_index]).await?;
    for api in &api_ports {
        wait_for_connected_peer_count(*api, 3).await?;
    }

    // Take one canonical data owner down. Repair must choose the one spare
    // node, reconstruct there, and commit that temporary location before it
    // becomes an authoritative read source.
    let lost_index = *node_index_by_id
        .get(&canonical[0])
        .ok_or("temporary-repair canonical owner is unknown")?;
    let lost_path = block_file_path(temp.path(), &node_names[lost_index], &content_cid);
    assert!(lost_path.exists());
    fs::remove_file(&lost_path)?;
    nodes[lost_index].kill_and_wait();
    let survivor_apis = api_ports
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != lost_index)
        .map(|(_, api)| *api)
        .collect::<Vec<_>>();
    let mut temporary = None::<PlacementException>;
    for _ in 0..16 {
        let _ = join_all(survivor_apis.iter().map(|api| {
            client
                .post(format!("http://127.0.0.1:{api}/v1/admin/repair"))
                .send()
        }))
        .await;
        for api in &survivor_apis {
            let status = client
                .get(format!("http://127.0.0.1:{api}/v1/admin/placement"))
                .send()
                .await?;
            if !status.status().is_success() {
                continue;
            }
            let status: serde_json::Value = status.json().await?;
            temporary = status["exceptions"].as_array().and_then(|exceptions| {
                exceptions.iter().find_map(|value| {
                    serde_json::from_value::<PlacementException>(value.clone())
                        .ok()
                        .filter(|exception| exception.reference == content_placement)
                })
            });
            if temporary.is_some() {
                break;
            }
        }
        if temporary.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let temporary = temporary.ok_or("owner loss did not commit a temporary placement exception")?;
    assert_eq!(temporary.reason, "repair_temporary_owner_loss");
    assert_eq!(temporary.node_ids.len(), 1);
    let replacement_index = *node_index_by_id
        .get(&temporary.node_ids[0])
        .ok_or("temporary repair destination is unknown")?;
    assert!(!canonical.contains(&temporary.node_ids[0]));
    let replacement_path =
        block_file_path(temp.path(), &node_names[replacement_index], &content_cid);
    assert!(replacement_path.exists());
    let read = signed_s3_success_with_retry(
        &client,
        survivor_apis[0],
        Method::GET,
        "/owned-repair/object.bin",
        Vec::new(),
    )
    .await?
    .bytes()
    .await?;
    assert_eq!(read.as_ref(), payload.as_slice());

    nodes[lost_index] = spawn_agent_with_log(agent, &configs[lost_index], &logs[lost_index])?;
    wait_health(api_ports[lost_index]).await?;
    for api in &api_ports {
        wait_for_connected_peer_count(*api, 3).await?;
    }
    for _ in 0..60 {
        let response = client
            .post(format!(
                "http://127.0.0.1:{}/v1/admin/repair",
                api_ports[primary_index]
            ))
            .send()
            .await;
        if let Ok(response) = response
            && !response.status().is_success()
        {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            eprintln!("canonical migration repair returned {status}: {body}");
        }
        if lost_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if !lost_path.exists() {
        for log in &logs {
            eprintln!("===== {} =====", log.display());
            for line in fs::read_to_string(log).unwrap_or_default().lines() {
                let lowercase = line.to_ascii_lowercase();
                if lowercase.contains("repair") || lowercase.contains("error") {
                    eprintln!("{line}");
                }
            }
        }
    }
    assert!(
        lost_path.exists(),
        "canonical owner was not restored from its exception"
    );

    // Shorten the committed exception through the generation-CAS admin path.
    // Once it expires, every canonical owner is probed before the extra copy
    // is deleted and only then is the catalog record removed.
    let stale_before = prometheus_metric_sum(
        &client,
        &api_ports,
        "pepper_placement_repair_stale_extras_collected_total",
    )
    .await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let expiring = PlacementException {
        generation: temporary.generation.saturating_add(1),
        created_at_unix_seconds: now,
        expires_at_unix_seconds: now + 2,
        ..temporary
    };
    client
        .post(format!(
            "http://127.0.0.1:{}/v1/admin/placement/exceptions",
            api_ports[0]
        ))
        .json(&expiring)
        .send()
        .await?
        .error_for_status()?;
    let mut collected = false;
    for _ in 0..30 {
        let status: serde_json::Value = client
            .get(format!(
                "http://127.0.0.1:{}/v1/admin/placement",
                api_ports[0]
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let absent = status["exceptions"].as_array().is_some_and(|exceptions| {
            !exceptions.iter().any(|value| {
                serde_json::from_value::<PlacementException>(value.clone())
                    .is_ok_and(|exception| exception.reference == content_placement)
            })
        });
        if absent && !replacement_path.exists() {
            collected = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if !collected {
        for log in &logs {
            eprintln!("===== {} =====", log.display());
            eprintln!("{}", fs::read_to_string(log).unwrap_or_default());
        }
    }
    assert!(
        collected,
        "expired temporary placement was not safely collected"
    );
    assert!(
        prometheus_metric_sum(
            &client,
            &api_ports,
            "pepper_placement_repair_stale_extras_collected_total",
        )
        .await?
            > stale_before
    );
    assert_eq!(
        prometheus_rpc_requests(&client, &api_ports, "/block/providers").await?,
        provider_before,
        "owner failover, epoch handoff, migration, and cleanup must not discover providers"
    );
    drop(nodes);
    Ok(())
}

async fn s3_nine_node_streaming_contract(exercise_small_object_pack: bool) -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    // The streaming contract exercises 6+3 data placement and reconstruction,
    // not metadata partition scaling. The packing contract needs multiple
    // partitions to exercise split-local repacking, while the catalog contract
    // owns the heavier 16-partition scaling coverage.
    let bucket_partitions = if exercise_small_object_pack { 4 } else { 1 };
    let packed_partition_hash_end = 65_536 / u64::from(bucket_partitions);
    let p2p_ports = (0..9)
        .map(|_| free_port())
        .collect::<TestResult<Vec<_>>>()?;
    let api_ports = (0..9)
        .map(|_| free_port())
        .collect::<TestResult<Vec<_>>>()?;
    let peer_addresses = p2p_ports
        .iter()
        .map(|port| format!("127.0.0.1:{port}"))
        .collect::<Vec<_>>();
    let mut configs = Vec::new();
    let mut node_names = Vec::new();
    for index in 0..9 {
        let name = format!("ec-s3-node-{}", index + 1);
        let bootstrap = peer_addresses
            .iter()
            .enumerate()
            .filter(|(peer_index, _)| *peer_index != index)
            .map(|(_, address)| address.clone())
            .collect::<Vec<_>>();
        configs.push(write_s3_erasure_config_with_partitions(
            temp.path(),
            &name,
            &format!("rack-{}", index + 1),
            p2p_ports[index],
            api_ports[index],
            &bootstrap,
            bucket_partitions,
        )?);
        node_names.push(name);
    }

    let agent = env!("CARGO_BIN_EXE_pepper-agent");
    for config in &configs {
        run_init(agent, config)?;
    }
    let mut nodes = Vec::new();
    let mut logs = Vec::new();
    for (index, config) in configs.iter().enumerate() {
        let log = temp.path().join(format!("ec-node-{}.log", index + 1));
        nodes.push(if exercise_small_object_pack {
            let mut environment = vec![("PEPPER_TEST_DISABLE_SMALL_PACK_BACKGROUND", "1")];
            if index == 0 {
                environment.push(("PEPPER_TEST_SMALL_PACK_TRANSITION_DELAY_MS", "30000"));
            }
            spawn_agent_with_log_and_env(agent, config, &log, &environment)?
        } else {
            spawn_agent_with_log(agent, config, &log)?
        });
        logs.push(log);
    }
    for api in &api_ports {
        wait_health(*api).await?;
    }
    for api in &api_ports {
        wait_for_connected_peer_count(*api, 8).await?;
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()?;
    let provider_discovery_before =
        prometheus_rpc_requests(&client, &api_ports, "/block/providers").await?;
    if let Err(error) = signed_s3_success_with_retry(
        &client,
        api_ports[0],
        Method::PUT,
        "/ec-streaming",
        Vec::new(),
    )
    .await
    {
        dump_s3_cluster_diagnostics(&client, &api_ports, &logs).await;
        return Err(error);
    }
    if exercise_small_object_pack {
        let small_sizes = [
            4 * 1024,
            8 * 1024,
            32 * 1024,
            64 * 1024,
            128 * 1024,
            256 * 1024,
            512 * 1024,
            1024 * 1024,
        ];
        let mut small_objects = Vec::new();
        let mut candidate = 0u64;
        while small_objects.len() < small_sizes.len() {
            let key = format!("packed-{candidate:08}.bin");
            let digest = Cid::new(pepper_types::CODEC_RAW, key.as_bytes()).digest;
            if u64::from(u16::from_be_bytes([digest[0], digest[1]])) < packed_partition_hash_end {
                let size = small_sizes[small_objects.len()];
                let payload = match small_objects.len() {
                    6 => deterministic_compressible(size, candidate + 11, 10),
                    7 => deterministic_compressible(size, candidate + 11, 20),
                    _ => deterministic_incompressible(size, candidate + 11),
                };
                let response = signed_s3_success_with_retry(
                    &client,
                    api_ports[small_objects.len() % api_ports.len()],
                    Method::PUT,
                    &format!("/ec-streaming/{key}"),
                    payload.clone(),
                )
                .await?;
                let cid = response
                    .headers()
                    .get(reqwest::header::ETAG)
                    .ok_or("small-object PUT omitted ETag")?
                    .to_str()?
                    .trim_matches('"')
                    .parse::<Cid>()?;
                assert_eq!(cid.codec, CODEC_SMALL_OBJECT);
                small_objects.push((key, payload));
            }
            candidate += 1;
        }
        let pack_client = client.clone();
        let pack_url = format!(
            "http://127.0.0.1:{}/v1/admin/s3/buckets/ec-streaming/pack",
            api_ports[0]
        );
        let interrupted_pack = tokio::spawn(async move { pack_client.post(pack_url).send().await });
        let mut extent_started = false;
        for _ in 0..240 {
            if prometheus_metric_sum(
                &client,
                &[api_ports[0]],
                "pepper_small_object_pack_extents_written_total",
            )
            .await?
                > 0
            {
                extent_started = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert!(
            extent_started,
            "pack failpoint did not reach the extent stage"
        );
        nodes[0].kill_and_wait();
        let interrupted = interrupted_pack.await?;
        assert!(
            interrupted.is_err()
                || interrupted
                    .as_ref()
                    .is_ok_and(|response| !response.status().is_success()),
            "a gateway crash before the index transition must not report success"
        );
        nodes[0] = spawn_agent_with_log_and_env(
            agent,
            &configs[0],
            &logs[0],
            &[("PEPPER_TEST_DISABLE_SMALL_PACK_BACKGROUND", "1")],
        )?;
        wait_health(api_ports[0]).await?;
        wait_for_connected_peer_count(api_ports[1], 8).await?;
        let packed_response = client
            .post(format!(
                "http://127.0.0.1:{}/v1/admin/s3/buckets/ec-streaming/pack",
                api_ports[1]
            ))
            .send()
            .await?;
        if !packed_response.status().is_success() {
            let status = packed_response.status();
            let body = packed_response.text().await?;
            for log in &logs {
                eprintln!("===== {} =====", log.display());
                for line in fs::read_to_string(log).unwrap_or_default().lines() {
                    let lowercase = line.to_ascii_lowercase();
                    if lowercase.contains("small-object")
                        || lowercase.contains("invalid namespace")
                        || lowercase.contains("error")
                    {
                        eprintln!("{line}");
                    }
                }
            }
            return Err(format!("small-object pack failed: {status} {body}").into());
        }
        let packed: serde_json::Value = packed_response.json().await?;
        assert_eq!(
            packed["records_transitioned"].as_u64(),
            Some(small_objects.len() as u64)
        );
        assert_eq!(packed["extent_cids"].as_array().map(Vec::len), Some(1));
        assert!(
            packed["encoded_bytes_written"].as_u64().unwrap_or(u64::MAX)
                < packed["logical_bytes_transitioned"].as_u64().unwrap_or(0),
            "per-record compression must reduce a mixed 10x/20x extent"
        );
        let extent_cid = packed["extent_cids"][0]
            .as_str()
            .ok_or("pack report omitted extent CID")?
            .parse::<Cid>()?;
        let placement_status: serde_json::Value = client
            .get(format!(
                "http://127.0.0.1:{}/v1/admin/placement",
                api_ports[1]
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let placement_map: PlacementMap =
            serde_json::from_value(placement_status["current_map"].clone())?;
        let extent_placement =
            PlacementReference::replicated(placement_map.epoch, extent_cid.clone(), 3);
        let extent_owner = select_authoritative(&placement_map, &extent_placement)?
            .node_ids
            .into_iter()
            .next()
            .ok_or("packed extent manifest has no owner")?;
        let mut node_index_by_id = std::collections::HashMap::new();
        for (index, api) in api_ports.iter().enumerate() {
            let status: NodeStatus = client
                .get(format!("http://127.0.0.1:{api}/v1/node/status"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            node_index_by_id.insert(status.node_id, index);
        }
        let extent_owner_index = *node_index_by_id
            .get(&extent_owner)
            .ok_or("packed extent owner is unknown")?;
        let extent_manifest: ErasureManifest = client
            .get(format!(
                "http://127.0.0.1:{}/v1/blocks/{}",
                api_ports[extent_owner_index],
                encode_path_segment(&extent_cid.to_string())
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(
            extent_manifest.size,
            packed["encoded_bytes_written"].as_u64().unwrap()
        );
        assert!(
            extent_manifest
                .stripes
                .iter()
                .all(|stripe| stripe.encoding == ErasureStripeEncoding::Raw),
            "individually compressed records must be placed in a range-addressable raw EC extent"
        );
        let mut packed_partition = None;
        let mut split_api = None;
        for api in &api_ports {
            let partitions_response = client
                .get(format!(
                    "http://127.0.0.1:{api}/v1/admin/s3/buckets/ec-streaming/partitions"
                ))
                .send()
                .await?;
            if !partitions_response.status().is_success() {
                continue;
            }
            let partitions: serde_json::Value = partitions_response.json().await?;
            if let Some(partition) = partitions["partitions"].as_array().and_then(|partitions| {
                partitions.iter().find(|partition| {
                    partition["partition"]["hash_start"].as_u64() == Some(0)
                        && partition["partition"]["hash_end"].as_u64()
                            == Some(packed_partition_hash_end)
                        && partition["locally_hosted"].as_bool() == Some(true)
                })
            }) {
                packed_partition = partition["partition"]["partition_id"].as_u64();
                split_api = Some(*api);
                break;
            }
        }
        let packed_partition =
            packed_partition.ok_or("could not locate a voter for the packed partition")?;
        let split_api = split_api.expect("packed partition voter has an API endpoint");
        let split_response = client
            .post(format!(
                "http://127.0.0.1:{split_api}/v1/admin/s3/buckets/ec-streaming/partitions"
            ))
            .json(&serde_json::json!({
                "operation": "split",
                "partition_id": packed_partition,
            }))
            .send()
            .await?;
        if !split_response.status().is_success() {
            let status = split_response.status();
            let body = split_response.text().await?;
            for log in &logs {
                eprintln!("===== {} =====", log.display());
                let contents = fs::read_to_string(log).unwrap_or_default();
                for line in contents
                    .lines()
                    .rev()
                    .take(80)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                {
                    eprintln!("{line}");
                }
            }
            return Err(format!("partition split failed: {status} {body}").into());
        }
        let split: serde_json::Value = split_response.json().await?;
        assert_eq!(split["epoch"].as_u64(), Some(2));
        assert!(
            split["small_object_repack"]["extents_compacted"]
                .as_u64()
                .unwrap_or(0)
                >= 1,
            "a split must localize cross-partition packed extents"
        );
        let recovery_extent_cid = split["small_object_repack"]["extent_cids"][0]
            .as_str()
            .ok_or("split omitted its partition-local replacement extent")?
            .parse::<Cid>()?;
        let recovery_placement =
            PlacementReference::replicated(placement_map.epoch, recovery_extent_cid.clone(), 3);
        let recovery_owner = select_authoritative(&placement_map, &recovery_placement)?
            .node_ids
            .into_iter()
            .next()
            .ok_or("replacement extent manifest has no owner")?;
        let recovery_owner_index = *node_index_by_id
            .get(&recovery_owner)
            .ok_or("replacement extent owner is unknown")?;
        let recovery_manifest: ErasureManifest = client
            .get(format!(
                "http://127.0.0.1:{}/v1/blocks/{}",
                api_ports[recovery_owner_index],
                encode_path_segment(&recovery_extent_cid.to_string())
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let mut packed_removed_shards = Vec::new();
        for shard in recovery_manifest.stripes[0].shards.iter().take(3) {
            let path = node_names
                .iter()
                .map(|name| block_file_path(temp.path(), name, &shard.cid))
                .find(|path| path.exists())
                .ok_or("could not locate packed extent shard")?;
            fs::remove_file(path)?;
            packed_removed_shards.push(shard.cid.clone());
        }
        for (index, (key, expected)) in small_objects.iter().enumerate() {
            let path = format!("/ec-streaming/{key}");
            let head = signed_s3_success_with_retry(
                &client,
                api_ports[(index + 1) % api_ports.len()],
                Method::HEAD,
                &path,
                Vec::new(),
            )
            .await?;
            assert_eq!(
                head.headers()
                    .get(reqwest::header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<usize>().ok()),
                Some(expected.len())
            );
            let full = signed_s3_success_with_retry(
                &client,
                api_ports[(index + 2) % api_ports.len()],
                Method::GET,
                &path,
                Vec::new(),
            )
            .await?
            .bytes()
            .await?;
            assert_eq!(full.as_ref(), expected.as_slice());
            let range_end = expected.len().min(4096) - 1;
            let range = format!("bytes=0-{range_end}");
            let ranged = signed_s3_request_with_headers(
                &client,
                api_ports[(index + 3) % api_ports.len()],
                Method::GET,
                &path,
                Vec::new(),
                &[("range", &range)],
            )
            .await?;
            assert_eq!(ranged.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(ranged.bytes().await?.as_ref(), &expected[..=range_end]);
        }
        let listing = signed_s3_success_with_retry(
            &client,
            api_ports[3],
            Method::GET,
            "/ec-streaming?list-type=2",
            Vec::new(),
        )
        .await?
        .text()
        .await?;
        for (key, _) in &small_objects {
            assert!(listing.contains(&format!("<Key>{key}</Key>")));
        }
        let replacement = deterministic_compressible(small_objects[0].1.len(), 91, 20);
        signed_s3_success_with_retry(
            &client,
            api_ports[4],
            Method::PUT,
            &format!("/ec-streaming/{}", small_objects[0].0),
            replacement.clone(),
        )
        .await?;
        let repacked: serde_json::Value = client
            .post(format!(
                "http://127.0.0.1:{}/v1/admin/s3/buckets/ec-streaming/pack",
                api_ports[4]
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(repacked["records_transitioned"].as_u64(), Some(1));
        let replaced = signed_s3_success_with_retry(
            &client,
            api_ports[5],
            Method::GET,
            &format!("/ec-streaming/{}", small_objects[0].0),
            Vec::new(),
        )
        .await?
        .bytes()
        .await?;
        assert_eq!(replaced.as_ref(), replacement.as_slice());
        signed_s3_success_with_retry(
            &client,
            api_ports[6],
            Method::DELETE,
            &format!("/ec-streaming/{}", small_objects[1].0),
            Vec::new(),
        )
        .await?;
        assert_eq!(
            signed_s3_response_with_retry(
                &client,
                api_ports[7],
                Method::HEAD,
                &format!("/ec-streaming/{}", small_objects[1].0),
                Vec::new(),
            )
            .await?
            .status(),
            StatusCode::NOT_FOUND
        );
        // Remove enough encoded payload from the original mixed-size extent
        // to cross its 50% dead-byte threshold. Compaction must range-read and
        // verify only the surviving records, write a new EC extent, and swap
        // every live index atomically.
        let compactions_before = prometheus_metric_sum(
            &client,
            &api_ports,
            "pepper_small_object_pack_extents_compacted_total",
        )
        .await?;
        let compacted_records_before = prometheus_metric_sum(
            &client,
            &api_ports,
            "pepper_small_object_pack_records_compacted_total",
        )
        .await?;
        let reclaimed_before = prometheus_metric_sum(
            &client,
            &api_ports,
            "pepper_small_object_pack_bytes_reclaimed_total",
        )
        .await?;
        for (offset, (key, _)) in small_objects.iter().enumerate().skip(3).take(3) {
            signed_s3_success_with_retry(
                &client,
                api_ports[(offset + 6) % api_ports.len()],
                Method::DELETE,
                &format!("/ec-streaming/{key}"),
                Vec::new(),
            )
            .await?;
        }
        let compacted: serde_json::Value = client
            .post(format!(
                "http://127.0.0.1:{}/v1/admin/s3/buckets/ec-streaming/pack",
                api_ports[8]
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let compactions_after = prometheus_metric_sum(
            &client,
            &api_ports,
            "pepper_small_object_pack_extents_compacted_total",
        )
        .await?;
        let compacted_records_after = prometheus_metric_sum(
            &client,
            &api_ports,
            "pepper_small_object_pack_records_compacted_total",
        )
        .await?;
        let reclaimed_after = prometheus_metric_sum(
            &client,
            &api_ports,
            "pepper_small_object_pack_bytes_reclaimed_total",
        )
        .await?;
        assert!(
            compacted["extents_compacted"].as_u64().unwrap_or(0) >= 1
                || compactions_after > compactions_before,
            "neither the background worker nor explicit request compacted the dirty extent"
        );
        assert!(
            compacted["records_compacted"].as_u64().unwrap_or(0) >= 1
                || compacted_records_after > compacted_records_before
        );
        assert!(
            compacted["bytes_reclaimed"].as_u64().unwrap_or(0) > 0
                || reclaimed_after > reclaimed_before
        );
        if let Some(compacted_extent_cid) = compacted["extent_cids"]
            .as_array()
            .and_then(|cids| cids.first())
            .and_then(|cid| cid.as_str())
        {
            assert_ne!(
                compacted_extent_cid,
                extent_cid.to_string(),
                "compaction must replace the partially dead extent"
            );
        }
        for index in [2usize, 6, 7] {
            let bytes = signed_s3_success_with_retry(
                &client,
                api_ports[index],
                Method::GET,
                &format!("/ec-streaming/{}", small_objects[index].0),
                Vec::new(),
            )
            .await?
            .bytes()
            .await?;
            assert_eq!(bytes.as_ref(), small_objects[index].1.as_slice());
        }
        assert!(
            prometheus_metric_sum(
                &client,
                &api_ports,
                "pepper_small_object_pack_records_transitioned_total",
            )
            .await?
                >= small_objects.len() as u64
        );
        assert!(
            prometheus_metric_sum(
                &client,
                &api_ports,
                "pepper_small_object_pack_extents_compacted_total",
            )
            .await?
                >= 2
        );
        let inventory_before = prometheus_metric_sum(
            &client,
            &api_ports,
            "pepper_placement_repair_inventory_events_total",
        )
        .await?;
        let mut last_repair_error = None;
        for _ in 0..16 {
            let responses = join_all(api_ports.iter().map(|api| {
                client
                    .post(format!("http://127.0.0.1:{api}/v1/admin/repair"))
                    .send()
            }))
            .await;
            for response in responses {
                match response {
                    Ok(response) if response.status().is_success() => {}
                    Ok(response)
                        if matches!(
                            response.status(),
                            StatusCode::CONFLICT
                                | StatusCode::TOO_MANY_REQUESTS
                                | StatusCode::SERVICE_UNAVAILABLE
                        ) =>
                    {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        last_repair_error = Some(format!("{status}: {body}"));
                    }
                    Ok(response) => {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        return Err(
                            format!("non-retryable repair response {status}: {body}").into()
                        );
                    }
                    Err(error) => last_repair_error = Some(error.to_string()),
                }
            }
            if packed_removed_shards.iter().all(|cid| {
                node_names
                    .iter()
                    .map(|name| block_file_path(temp.path(), name, cid))
                    .any(|path| path.exists())
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        if packed_removed_shards.iter().any(|cid| {
            !node_names
                .iter()
                .map(|name| block_file_path(temp.path(), name, cid))
                .any(|path| path.exists())
        }) && let Some(error) = last_repair_error
        {
            eprintln!("last retryable packed-extent repair error: {error}");
        }
        for cid in &packed_removed_shards {
            assert!(
                node_names
                    .iter()
                    .map(|name| block_file_path(temp.path(), name, cid))
                    .any(|path| path.exists()),
                "placement-owned inventory did not restore packed extent shard {cid}"
            );
        }
        assert!(
            prometheus_metric_sum(
                &client,
                &api_ports,
                "pepper_placement_repair_inventory_events_total",
            )
            .await?
                > inventory_before,
            "packed extent transition must enter the authoritative repair inventory"
        );
        assert_eq!(
            prometheus_rpc_requests(&client, &api_ports, "/block/providers").await?,
            provider_discovery_before,
            "packed-object write, reconstruction, range read, and repartition must not discover providers"
        );
        return Ok(());
    }
    let payload = (0..25 * 1024 * 1024)
        .map(|index| ((index * 17 + index / 8191) & 0xff) as u8)
        .collect::<Vec<_>>();
    let put = signed_s3_success_with_retry(
        &client,
        api_ports[0],
        Method::PUT,
        "/ec-streaming/large.bin",
        payload.clone(),
    )
    .await;
    let put = match put {
        Ok(response) => response,
        Err(error) => {
            dump_s3_cluster_diagnostics(&client, &api_ports, &logs).await;
            return Err(error);
        }
    };
    let manifest_cid = put
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim_matches('"').to_string())
        .ok_or("S3 erasure PUT omitted ETag")?;
    let manifest_cid = manifest_cid.parse::<Cid>()?;
    let placement_status: serde_json::Value = client
        .get(format!(
            "http://127.0.0.1:{}/v1/admin/placement",
            api_ports[0]
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let placement_map: PlacementMap =
        serde_json::from_value(placement_status["current_map"].clone())?;
    let manifest_placement =
        PlacementReference::replicated(placement_map.epoch, manifest_cid.clone(), 3);
    let manifest_decision = select_authoritative(&placement_map, &manifest_placement)?;
    let manifest_owner = manifest_decision
        .node_ids
        .first()
        .cloned()
        .ok_or("manifest placement returned no owner")?;
    let mut manifest_owner_api = None;
    let mut node_index_by_id = std::collections::HashMap::new();
    for (index, api) in api_ports.iter().enumerate() {
        let status: NodeStatus = client
            .get(format!("http://127.0.0.1:{api}/v1/node/status"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        node_index_by_id.insert(status.node_id.clone(), index);
        if status.node_id == manifest_owner {
            manifest_owner_api = Some(*api);
        }
    }
    let manifest_owner_api = manifest_owner_api.ok_or("manifest owner has no API endpoint")?;
    let manifest: ErasureManifest = client
        .get(format!(
            "http://127.0.0.1:{}/v1/blocks/{}",
            manifest_owner_api,
            encode_path_segment(&manifest_cid.to_string())
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(manifest.data_shards, 6);
    assert_eq!(manifest.parity_shards, 3);
    assert_eq!(manifest.stripes.len(), 2);
    assert!(
        manifest
            .stripes
            .iter()
            .all(|stripe| stripe.encoding == ErasureStripeEncoding::Zstd)
    );

    let exception_target = placement_map
        .nodes
        .iter()
        .find(|node| !manifest_decision.node_ids.contains(&node.node_id))
        .map(|node| node.node_id.clone())
        .ok_or("manifest placement has no noncanonical exception target")?;
    let exception_target_index = *node_index_by_id
        .get(&exception_target)
        .ok_or("exception target has no test node")?;
    let exception_target_path = block_file_path(
        temp.path(),
        &node_names[exception_target_index],
        &manifest_cid,
    );
    assert!(!exception_target_path.exists());
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    client
        .post(format!(
            "http://127.0.0.1:{}/v1/admin/placement/exceptions",
            api_ports[0]
        ))
        .json(&serde_json::json!({
            "reference": manifest_placement,
            "block_cid": manifest_cid,
            "source_epoch": placement_map.epoch,
            "target_epoch": placement_map.epoch,
            "generation": 1,
            "node_ids": [exception_target],
            "reason": "multinode migration contract",
            "created_at_unix_seconds": now,
            "expires_at_unix_seconds": now + 600
        }))
        .send()
        .await?
        .error_for_status()?;
    assert!(exception_target_path.exists());
    let placement_status: serde_json::Value = client
        .get(format!(
            "http://127.0.0.1:{}/v1/admin/placement",
            api_ports[0]
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(
        placement_status["exceptions"].as_array().map(Vec::len),
        Some(1)
    );
    client
        .post(format!(
            "http://127.0.0.1:{}/v1/admin/placement/exceptions/delete",
            api_ports[0]
        ))
        .json(&serde_json::json!({
            "reference": manifest_placement,
            "generation": 1
        }))
        .send()
        .await?
        .error_for_status()?;
    fs::remove_file(exception_target_path)?;

    let mut removed_shards = Vec::new();
    for shard in manifest.stripes[0].shards.iter().take(3) {
        let path = node_names
            .iter()
            .map(|name| block_file_path(temp.path(), name, &shard.cid))
            .find(|path| path.exists())
            .ok_or("could not locate placed erasure shard")?;
        fs::remove_file(path)?;
        removed_shards.push(shard.cid.clone());
    }

    let full_response = signed_s3_success_with_retry(
        &client,
        api_ports[1],
        Method::GET,
        "/ec-streaming/large.bin",
        Vec::new(),
    )
    .await;
    let full_response = match full_response {
        Ok(response) => response,
        Err(error) => {
            dump_s3_cluster_diagnostics(&client, &api_ports, &logs).await;
            return Err(error);
        }
    };
    let full = match full_response.bytes().await {
        Ok(bytes) => bytes,
        Err(error) => {
            dump_s3_cluster_diagnostics(&client, &api_ports, &logs).await;
            return Err(error.into());
        }
    };
    assert_eq!(&full[..], &payload[..]);

    let range_start = 8 * 1024 * 1024usize;
    let range_end = 16 * 1024 * 1024usize - 1;
    let range_header = format!("bytes={range_start}-{range_end}");
    let range_response = signed_s3_success_with_headers_and_retry(
        &client,
        api_ports[2],
        Method::GET,
        "/ec-streaming/large.bin",
        Vec::new(),
        &[("range", &range_header)],
    )
    .await;
    let range_response = match range_response {
        Ok(response) => response,
        Err(error) => {
            dump_s3_cluster_diagnostics(&client, &api_ports, &logs).await;
            return Err(error);
        }
    };
    let range = range_response.bytes().await?;
    assert_eq!(&range[..], &payload[range_start..=range_end]);

    let provider_discovery_after =
        prometheus_rpc_requests(&client, &api_ports, "/block/providers").await?;
    assert_eq!(
        provider_discovery_after, provider_discovery_before,
        "normal erasure-coded S3 PUT/GET/range GET must not issue provider-discovery RPCs"
    );

    for shard in manifest.stripes.iter().flat_map(|stripe| &stripe.shards) {
        let copies = node_names
            .iter()
            .map(|name| block_file_path(temp.path(), name, &shard.cid))
            .filter(|path| path.exists())
            .count();
        let expected = usize::from(!removed_shards.contains(&shard.cid));
        assert_eq!(
            copies, expected,
            "ordinary reads changed durable placement for shard {}",
            shard.cid
        );
    }

    let reconstructions_before = prometheus_metric_sum(
        &client,
        &api_ports,
        "pepper_placement_repair_destination_reconstructions_total",
    )
    .await?;
    let tasks_before = prometheus_metric_sum(
        &client,
        &api_ports,
        "pepper_placement_repair_tasks_completed_total",
    )
    .await?;
    let mut erasure = None;
    let mut last_repair_error = None;
    for attempt in 0..8 {
        let repair_wave = concurrent_repair_wave(&client, &api_ports, 2).await?;
        if repair_wave.last_retryable_error.is_some() {
            last_repair_error = repair_wave.last_retryable_error;
        }
        let status: serde_json::Value = client
            .get(format!(
                "http://127.0.0.1:{}/v1/admin/erasure",
                api_ports[0]
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let canonical_files_restored = removed_shards.iter().all(|cid| {
            node_names
                .iter()
                .map(|name| block_file_path(temp.path(), name, cid))
                .any(|path| path.exists())
        });
        let complete = status["missing_shards"].as_u64() == Some(0)
            && status["unrecoverable_manifests"].as_u64() == Some(0)
            && canonical_files_restored;
        erasure = Some(status);
        if complete {
            break;
        }
        eprintln!("erasure repair pass {} incomplete; retrying", attempt + 1);
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    if erasure.as_ref().is_none_or(|status| {
        status["missing_shards"].as_u64() != Some(0)
            || status["unrecoverable_manifests"].as_u64() != Some(0)
    }) && let Some(error) = last_repair_error
    {
        eprintln!("last retryable erasure repair error: {error}");
    }
    let erasure = erasure.ok_or("erasure repair did not run")?;
    assert_eq!(erasure["missing_shards"], 0);
    assert_eq!(erasure["unrecoverable_manifests"], 0);
    for cid in &removed_shards {
        assert!(
            node_names
                .iter()
                .map(|name| block_file_path(temp.path(), name, cid))
                .any(|path| path.exists()),
            "repair did not restore shard {cid}"
        );
    }
    let reconstructions_after = prometheus_metric_sum(
        &client,
        &api_ports,
        "pepper_placement_repair_destination_reconstructions_total",
    )
    .await?;
    let tasks_after = prometheus_metric_sum(
        &client,
        &api_ports,
        "pepper_placement_repair_tasks_completed_total",
    )
    .await?;
    assert_eq!(
        reconstructions_after.saturating_sub(reconstructions_before),
        removed_shards.len() as u64,
        "concurrent repair passes must reconstruct each missing shard exactly once"
    );
    assert_eq!(
        tasks_after.saturating_sub(tasks_before),
        removed_shards.len() as u64,
        "each missing shard must produce exactly one completed fenced task"
    );
    let healthy_lease_before = prometheus_metric_sum(
        &client,
        &api_ports,
        "pepper_placement_repair_leases_acquired_total",
    )
    .await?;
    let mut healthy_pass_completed = false;
    let mut last_healthy_error = None;
    for _ in 0..8 {
        let repair_wave = concurrent_repair_wave(&client, &api_ports, 2).await?;
        if repair_wave.last_retryable_error.is_some() {
            last_healthy_error = repair_wave.last_retryable_error;
        }
        if repair_wave.successes > 0 {
            healthy_pass_completed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    if !healthy_pass_completed {
        return Err(format!(
            "healthy repair pass did not complete: {}",
            last_healthy_error.unwrap_or_else(|| "no successful response".to_string())
        )
        .into());
    }
    assert_eq!(
        prometheus_metric_sum(
            &client,
            &api_ports,
            "pepper_placement_repair_leases_acquired_total",
        )
        .await?,
        healthy_lease_before,
        "a healthy inventory must not acquire a repair lease"
    );
    assert_eq!(
        prometheus_rpc_requests(&client, &api_ports, "/block/providers").await?,
        provider_discovery_before,
        "placement-owned repair must not issue provider-discovery RPCs"
    );

    drop(nodes);
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
        let copied_to_new_node = manifest
            .stripes
            .iter()
            .flat_map(|stripe| &stripe.shards)
            .any(|shard| {
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
async fn sqlite_whole_file_multi_ingress_exactly_one_writer_commits() -> TestResult<()> {
    let temp = tempfile::tempdir()?;
    let p2p1 = free_port()?;
    let p2p2 = free_port()?;
    let p2p3 = free_port()?;
    let api1 = free_port()?;
    let api2 = free_port()?;
    let api3 = free_port()?;
    let config1 = write_config(temp.path(), "sqlite1", p2p1, api1, &[])?;
    let config2 = write_config(
        temp.path(),
        "sqlite2",
        p2p2,
        api2,
        &[format!("127.0.0.1:{p2p1}")],
    )?;
    let config3 = write_config(
        temp.path(),
        "sqlite3",
        p2p3,
        api3,
        &[format!("127.0.0.1:{p2p1}"), format!("127.0.0.1:{p2p2}")],
    )?;
    for config in [&config1, &config2, &config3] {
        let contents = fs::read_to_string(config)?;
        fs::write(
            config,
            format!(
                "{}\n[sqlite]\nenabled = true\n",
                contents
                    .replace("default_factor = 2", "default_factor = 3")
                    .replace(
                        "consensus_enabled = true",
                        "consensus_enabled = true\nheartbeat_interval_ms = 250\nelection_timeout_min_ms = 1500\nelection_timeout_max_ms = 3000",
                    )
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
        .timeout(Duration::from_secs(60))
        .build()?;
    let create = client
        .post(format!(
            "http://127.0.0.1:{api1}/v1/sqlite/experimental/databases"
        ))
        .json(&serde_json::json!({
            "database":"shared-db",
            "request_id":"sqlite-create",
            "page_size":4096
        }))
        .send()
        .await?;
    if !create.status().is_success() {
        return Err(format!(
            "SQLite create failed: {} {}",
            create.status(),
            create.text().await?
        )
        .into());
    }
    assert_eq!(
        create
            .headers()
            .get("x-pepper-experimental")
            .and_then(|value| value.to_str().ok()),
        Some("whole-file-v1")
    );
    let created: serde_json::Value = create.json().await?;
    let namespace = created["namespace_id"]
        .as_str()
        .ok_or("missing SQLite namespace ID")?
        .to_string();
    let initial_head = created["head_cid"]
        .as_str()
        .ok_or("missing SQLite initial head")?
        .to_string();
    wait_for_namespace_quorum(&[api1, api2, api3], &namespace).await?;
    let encoded_namespace = encode_path_segment(&namespace);

    let initial_file = client
        .get(format!(
            "http://127.0.0.1:{api2}/v1/sqlite/experimental/databases/{encoded_namespace}/file"
        ))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    assert!(initial_file.is_empty());
    let candidate_a = sqlite_candidate(temp.path(), "candidate-a.db", &initial_file, "writer-a")?;
    let candidate_b = sqlite_candidate(temp.path(), "candidate-b.db", &initial_file, "writer-b")?;
    let commit_url_a = format!(
        "http://127.0.0.1:{api2}/v1/sqlite/experimental/databases/{encoded_namespace}/file"
    );
    let commit_url_b = format!(
        "http://127.0.0.1:{api3}/v1/sqlite/experimental/databases/{encoded_namespace}/file"
    );
    let request_a = client
        .put(commit_url_a)
        .query(&[
            ("request_id", "sqlite-writer-a"),
            ("base_revision", "1"),
            ("base_generation", "1"),
            ("base_cid", initial_head.as_str()),
        ])
        .body(candidate_a.clone())
        .send();
    let request_b = client
        .put(commit_url_b)
        .query(&[
            ("request_id", "sqlite-writer-b"),
            ("base_revision", "1"),
            ("base_generation", "1"),
            ("base_cid", initial_head.as_str()),
        ])
        .body(candidate_b.clone())
        .send();
    let (response_a, response_b) = tokio::join!(request_a, request_b);
    let response_a = response_a?;
    let response_b = response_b?;
    let a_won = response_a.status().is_success();
    let b_won = response_b.status().is_success();
    assert_ne!(a_won, b_won, "exactly one stale-base candidate must commit");
    let loser = if a_won { &response_b } else { &response_a };
    assert_eq!(loser.status(), StatusCode::CONFLICT);
    let (winner_id, winner_bytes) = if a_won {
        ("sqlite-writer-a", candidate_a)
    } else {
        ("sqlite-writer-b", candidate_b)
    };

    let status: serde_json::Value = client
        .get(format!(
            "http://127.0.0.1:{api1}/v1/sqlite/experimental/databases/{encoded_namespace}/commits/{winner_id}"
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(status["request_id"], winner_id);

    let exported = client
        .get(format!(
            "http://127.0.0.1:{api3}/v1/sqlite/experimental/databases/{encoded_namespace}/file"
        ))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    assert_eq!(exported.as_ref(), winner_bytes.as_slice());
    let exported_path = temp.path().join("exported.db");
    fs::write(&exported_path, &exported)?;
    let connection = rusqlite::Connection::open_with_flags(
        exported_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    assert_eq!(integrity, "ok");
    let value: String = connection.query_row("SELECT value FROM records", [], |row| row.get(0))?;
    assert_eq!(value, if a_won { "writer-a" } else { "writer-b" });

    // Exercise the production page-DAG path through three distinct ingress
    // peers. The imported ordinary file must export byte-identically and each
    // peer's immutable read session must return the same verified page.
    let create = client
        .post(format!("http://127.0.0.1:{api1}/v1/sqlite/databases"))
        .json(&serde_json::json!({
            "database":"paged-db",
            "request_id":"paged-create",
            "page_size":4096
        }))
        .send()
        .await?
        .error_for_status()?;
    let paged: serde_json::Value = create.json().await?;
    let paged_namespace = paged["namespace_id"].as_str().unwrap();
    let initial_snapshot = paged["snapshot_cid"].as_str().unwrap();
    wait_for_namespace_quorum(&[api1, api2, api3], paged_namespace).await?;
    let encoded_paged = encode_path_segment(paged_namespace);
    let imported: serde_json::Value = client
        .post(format!(
            "http://127.0.0.1:{api2}/v1/sqlite/databases/{encoded_paged}/import"
        ))
        .query(&[
            ("request_id", "paged-import"),
            ("base_revision", "1"),
            ("base_generation", "1"),
            ("base_snapshot", initial_snapshot),
        ])
        .body(winner_bytes.clone())
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let imported_snapshot = imported["snapshot_cid"].as_str().unwrap();
    let exported = client
        .get(format!(
            "http://127.0.0.1:{api3}/v1/sqlite/databases/{encoded_paged}/export"
        ))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    assert_eq!(exported.as_ref(), winner_bytes.as_slice());

    let mut first_pages: Option<Vec<u8>> = None;
    for port in [api2, api3] {
        let session: serde_json::Value = client
            .post(format!(
                "http://127.0.0.1:{port}/v1/sqlite/databases/{encoded_paged}/sessions"
            ))
            .json(&serde_json::json!({"snapshot": imported_snapshot}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let session_id = session["session_id"].as_str().unwrap();
        let page = client
            .get(format!(
                "http://127.0.0.1:{port}/v1/sqlite/sessions/{session_id}/pages"
            ))
            .query(&[("pages", "1")])
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        assert_eq!(page.len(), 4096);
        if let Some(first) = &first_pages {
            assert_eq!(page.as_ref(), first.as_slice());
        } else {
            first_pages = Some(page.to_vec());
        }
        client
            .delete(format!(
                "http://127.0.0.1:{port}/v1/sqlite/sessions/{session_id}"
            ))
            .send()
            .await?
            .error_for_status()?;
    }

    let historical: serde_json::Value = client
        .post(format!(
            "http://127.0.0.1:{api2}/v1/sqlite/databases/{encoded_paged}/sessions"
        ))
        .json(&serde_json::json!({"snapshot": imported_snapshot}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let historical_id = historical["session_id"].as_str().unwrap();
    let historical_page = client
        .get(format!(
            "http://127.0.0.1:{api2}/v1/sqlite/sessions/{historical_id}/pages"
        ))
        .query(&[("pages", "1")])
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let incremental_bytes =
        sqlite_update_candidate(temp.path(), "incremental.db", &winner_bytes, "incremental")?;
    let dirty = incremental_bytes
        .chunks_exact(4096)
        .zip(winner_bytes.chunks_exact(4096))
        .enumerate()
        .filter(|(_, (next, base))| next != base)
        .map(|(index, (next, _))| (index as u32 + 1, next))
        .collect::<Vec<_>>();
    assert!(!dirty.is_empty());

    // Writer ownership is leader-scoped, not ingress-local: acquisitions sent
    // through two different peers contend for the same ticket.
    let probe_a: serde_json::Value = client
        .post(format!(
            "http://127.0.0.1:{api2}/v1/sqlite/databases/{encoded_paged}/writer/acquire"
        ))
        .json(&serde_json::json!({
            "session_id":"probe-a",
            "acquisition_id":"probe-a",
            "base_snapshot":imported_snapshot,
            "base_generation":2,
            "wait_timeout_millis":0
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(probe_a["status"], "granted");
    let probe_b: serde_json::Value = client
        .post(format!(
            "http://127.0.0.1:{api3}/v1/sqlite/databases/{encoded_paged}/writer/acquire"
        ))
        .json(&serde_json::json!({
            "session_id":"probe-b",
            "acquisition_id":"probe-b",
            "base_snapshot":imported_snapshot,
            "base_generation":2,
            "wait_timeout_millis":0
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(probe_b["status"], "busy");
    client
        .post(format!(
            "http://127.0.0.1:{api2}/v1/sqlite/databases/{encoded_paged}/writer/release"
        ))
        .json(&serde_json::json!({"ticket": probe_a["ticket"].clone()}))
        .send()
        .await?
        .error_for_status()?;

    let acquired: serde_json::Value = client
        .post(format!(
            "http://127.0.0.1:{api2}/v1/sqlite/databases/{encoded_paged}/writer/acquire"
        ))
        .json(&serde_json::json!({
            "session_id":"incremental-client",
            "acquisition_id":"incremental-acquire",
            "base_snapshot":imported_snapshot,
            "base_generation":2,
            "wait_timeout_millis":0
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(acquired["status"], "granted");
    let ticket = &acquired["ticket"];
    let pages = dirty
        .iter()
        .map(|(number, _)| number.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let payload = dirty
        .iter()
        .flat_map(|(_, bytes)| bytes.iter().copied())
        .collect::<Vec<_>>();
    let commit = client
        .post(format!(
            "http://127.0.0.1:{api2}/v1/sqlite/databases/{encoded_paged}/transactions"
        ))
        .query(&[
            ("request_id", "incremental-commit".to_string()),
            ("base_revision", "2".to_string()),
            ("base_generation", "2".to_string()),
            ("base_snapshot", imported_snapshot.to_string()),
            ("new_logical_size", incremental_bytes.len().to_string()),
            ("pages", pages),
            (
                "ticket_id",
                ticket["ticket_id"].as_str().unwrap().to_string(),
            ),
            (
                "acquisition_id",
                ticket["acquisition_id"].as_str().unwrap().to_string(),
            ),
            ("holder", ticket["holder"].as_str().unwrap().to_string()),
            ("leader_term", ticket["leader_term"].to_string()),
            ("lease_epoch", ticket["lease_epoch"].to_string()),
            ("expires_at_millis", ticket["expires_at_millis"].to_string()),
        ])
        .body(payload)
        .send()
        .await?;
    if !commit.status().is_success() {
        return Err(format!(
            "incremental commit failed: {} {}",
            commit.status(),
            commit.text().await?
        )
        .into());
    }
    let committed: serde_json::Value = commit.json().await?;
    assert_eq!(committed["commit"]["generation"], 3);
    let recovered: serde_json::Value = client
        .get(format!(
            "http://127.0.0.1:{api3}/v1/sqlite/databases/{encoded_paged}/commits/incremental-commit"
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(
        recovered["snapshot_cid"],
        committed["commit"]["snapshot_cid"]
    );
    assert_eq!(recovered["generation"], 3);
    let latest = client
        .get(format!(
            "http://127.0.0.1:{api3}/v1/sqlite/databases/{encoded_paged}/export"
        ))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    assert_eq!(latest.as_ref(), incremental_bytes.as_slice());
    let stable_historical_page = client
        .get(format!(
            "http://127.0.0.1:{api2}/v1/sqlite/sessions/{historical_id}/pages"
        ))
        .query(&[("pages", "1")])
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    assert_eq!(stable_historical_page, historical_page);
    client
        .delete(format!(
            "http://127.0.0.1:{api2}/v1/sqlite/sessions/{historical_id}"
        ))
        .send()
        .await?
        .error_for_status()?;

    let socket = temp.path().join("sqlite1/data/sqlite.sock");
    let backend = std::sync::Arc::new(pepper_sqlite_vfs::UnixSocketBackend::new(
        socket,
        Duration::from_secs(30),
    ));
    pepper_sqlite_vfs::register_pepper_vfs(backend)?;
    {
        let connection = rusqlite::Connection::open_with_flags(
            "file:pepper%3Apaged-db?mode=rw&vfs=pepper&busy_timeout_ms=10000",
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|error| {
            format!(
                "VFS open failed: {error}; {}",
                pepper_sqlite_vfs::last_pepper_vfs_error()
            )
        })?;
        let value: String = connection
            .query_row("SELECT value FROM records", [], |row| row.get(0))
            .map_err(|error| {
                format!(
                    "VFS read failed: {error}; {}",
                    pepper_sqlite_vfs::last_pepper_vfs_error()
                )
            })?;
        assert_eq!(value, "incremental");
        connection
            .execute("UPDATE records SET value='vfs'", [])
            .map_err(|error| {
                format!(
                    "VFS write failed: {error}; {}",
                    pepper_sqlite_vfs::last_pepper_vfs_error()
                )
            })?;
        let value: String = connection
            .query_row("SELECT value FROM records", [], |row| row.get(0))
            .map_err(|error| {
                format!(
                    "VFS reread failed: {error}; {}",
                    pepper_sqlite_vfs::last_pepper_vfs_error()
                )
            })?;
        assert_eq!(value, "vfs");
    }
    pepper_sqlite_vfs::unregister_pepper_vfs()?;
    let vfs_export = client
        .get(format!(
            "http://127.0.0.1:{api1}/v1/sqlite/databases/{encoded_paged}/export"
        ))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let vfs_path = temp.path().join("vfs-export.db");
    fs::write(&vfs_path, &vfs_export)?;
    let connection = rusqlite::Connection::open_with_flags(
        &vfs_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    assert_eq!(integrity, "ok");
    let value: String = connection.query_row("SELECT value FROM records", [], |row| row.get(0))?;
    assert_eq!(value, "vfs");

    // Explicit EC page packs use the ordinary manifest/shard data plane while
    // SQLite control blocks and the namespace head remain replicated.
    let ec_created: serde_json::Value = client
        .post(format!("http://127.0.0.1:{api2}/v1/sqlite/databases"))
        .json(&serde_json::json!({
            "database":"ec-db",
            "request_id":"ec-create",
            "page_size":4096,
            "storage_policy":{
                "kind":"erasure",
                "data_shards":2,
                "parity_shards":1,
                "shard_copies":1
            }
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let ec_namespace = ec_created["namespace_id"].as_str().unwrap();
    let ec_base = ec_created["snapshot_cid"].as_str().unwrap();
    wait_for_namespace_quorum(&[api1, api2, api3], ec_namespace).await?;
    let ec_encoded = encode_path_segment(ec_namespace);
    let ec_import = client
        .post(format!(
            "http://127.0.0.1:{api3}/v1/sqlite/databases/{ec_encoded}/import"
        ))
        .query(&[
            ("request_id", "ec-import"),
            ("base_revision", "1"),
            ("base_generation", "1"),
            ("base_snapshot", ec_base),
        ])
        .body(vfs_export.clone())
        .send()
        .await?;
    if !ec_import.status().is_success() {
        return Err(format!(
            "EC SQLite import failed: {} {}",
            ec_import.status(),
            ec_import.text().await?
        )
        .into());
    }
    let ec_export = client
        .get(format!(
            "http://127.0.0.1:{api1}/v1/sqlite/databases/{ec_encoded}/export"
        ))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    assert_eq!(ec_export, vfs_export);
    Ok(())
}

fn sqlite_candidate(root: &Path, name: &str, base: &[u8], value: &str) -> TestResult<Vec<u8>> {
    let path = root.join(name);
    fs::write(&path, base)?;
    {
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(
            "PRAGMA page_size=4096; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;\
             CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT NOT NULL);",
        )?;
        connection.execute("INSERT INTO records(value) VALUES (?1)", [value])?;
    }
    Ok(fs::read(path)?)
}

fn sqlite_update_candidate(
    root: &Path,
    name: &str,
    base: &[u8],
    value: &str,
) -> TestResult<Vec<u8>> {
    let path = root.join(name);
    fs::write(&path, base)?;
    {
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute("UPDATE records SET value=?1", [value])?;
    }
    Ok(fs::read(path)?)
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
    let payload = vec![b'a'; 1024 * 1024];
    let put: DurabilityReceipt = client
        .post(format!("http://127.0.0.1:{api2}/v1/blocks"))
        .body(payload.clone())
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
    assert_eq!(&bytes[..], payload);

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
    signed_s3_request_with_headers(client, api_port, method, path_and_query, body, &[]).await
}

async fn signed_s3_request_with_headers(
    client: &reqwest::Client,
    api_port: u16,
    method: Method,
    path_and_query: &str,
    body: Vec<u8>,
    extra_headers: &[(&str, &str)],
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
    let mut request = client
        .request(method, format!("http://{host}{path_and_query}"))
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("authorization", authorization);
    for (name, value) in extra_headers {
        request = request.header(*name, *value);
    }
    Ok(request.body(body).send().await?)
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

async fn signed_s3_success_with_headers_and_retry(
    client: &reqwest::Client,
    api_port: u16,
    method: Method,
    path_and_query: &str,
    body: Vec<u8>,
    extra_headers: &[(&str, &str)],
) -> TestResult<reqwest::Response> {
    s3_success(
        signed_s3_response_with_headers_and_retry(
            client,
            api_port,
            method,
            path_and_query,
            body,
            extra_headers,
        )
        .await?,
    )
    .await
}

async fn signed_s3_bytes_with_retry(
    client: &reqwest::Client,
    api_port: u16,
    method: Method,
    path_and_query: &str,
    body: Vec<u8>,
) -> TestResult<Vec<u8>> {
    let mut last_error = String::new();
    for _ in 0..4 {
        match signed_s3_success_with_retry(
            client,
            api_port,
            method.clone(),
            path_and_query,
            body.clone(),
        )
        .await
        {
            Ok(response) => match response.bytes().await {
                Ok(bytes) => return Ok(bytes.to_vec()),
                Err(error) => last_error = format!("response body failed: {error}"),
            },
            Err(error) => last_error = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(format!(
        "S3 request {method} {path_and_query} did not return a complete body: {last_error}"
    )
    .into())
}

async fn signed_s3_response_with_retry(
    client: &reqwest::Client,
    api_port: u16,
    method: Method,
    path_and_query: &str,
    body: Vec<u8>,
) -> TestResult<reqwest::Response> {
    signed_s3_response_with_headers_and_retry(client, api_port, method, path_and_query, body, &[])
        .await
}

async fn signed_s3_response_with_headers_and_retry(
    client: &reqwest::Client,
    api_port: u16,
    method: Method,
    path_and_query: &str,
    body: Vec<u8>,
    extra_headers: &[(&str, &str)],
) -> TestResult<reqwest::Response> {
    const RETRY_DEADLINE: Duration = Duration::from_secs(180);
    let mut last_error = String::new();
    let started = std::time::Instant::now();
    while started.elapsed() < RETRY_DEADLINE {
        let response = match signed_s3_request_with_headers(
            client,
            api_port,
            method.clone(),
            path_and_query,
            body.clone(),
            extra_headers,
        )
        .await
        {
            Ok(response) => Some(response),
            Err(error) => {
                last_error = format!("transport error: {error}");
                None
            }
        };
        if let Some(response) = response {
            if !matches!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE
                    | StatusCode::CONFLICT
                    | StatusCode::TOO_MANY_REQUESTS
            ) {
                return Ok(response);
            }
            let status = response.status();
            last_error = format!("{status}: {}", response.text().await?);
        }
        let remaining = RETRY_DEADLINE.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250).min(remaining)).await;
    }
    Err(format!(
        "S3 request {method} {path_and_query} did not succeed before the retry deadline: {last_error}"
    )
    .into())
}

async fn dump_s3_cluster_diagnostics(
    client: &reqwest::Client,
    api_ports: &[u16],
    logs: &[PathBuf],
) {
    let readiness = join_all(api_ports.iter().map(|api| {
        client
            .get(format!("http://127.0.0.1:{api}/readyz"))
            .timeout(Duration::from_secs(2))
            .send()
    }))
    .await;
    for (api, response) in api_ports.iter().zip(readiness) {
        match response {
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                eprintln!("===== readyz {api}: {status} =====\n{body}");
            }
            Err(error) => eprintln!("===== readyz {api} failed =====\n{error}"),
        }
    }
    for log in logs {
        let contents = fs::read_to_string(log).unwrap_or_default();
        let tail = contents
            .lines()
            .rev()
            .take(250)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        eprintln!("===== {} (last 250 lines) =====\n{tail}", log.display());
    }
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

fn xml_values(xml: &str, element: &str) -> Vec<String> {
    let start_tag = format!("<{element}>");
    let end_tag = format!("</{element}>");
    let mut values = Vec::new();
    let mut remaining = xml;
    while let Some(start) = remaining.find(&start_tag) {
        let value_start = start + start_tag.len();
        let Some(end) = remaining[value_start..].find(&end_tag) else {
            break;
        };
        values.push(remaining[value_start..value_start + end].to_string());
        remaining = &remaining[value_start + end + end_tag.len()..];
    }
    values
}

fn write_s3_config(
    root: &Path,
    name: &str,
    p2p_port: u16,
    api_port: u16,
    bootstrap: &[String],
) -> TestResult<PathBuf> {
    write_s3_config_with_partitions(root, name, p2p_port, api_port, bootstrap, 16)
}

fn write_single_node_s3_config(
    root: &Path,
    name: &str,
    p2p_port: u16,
    api_port: u16,
) -> TestResult<PathBuf> {
    let config = write_s3_config_with_partitions(root, name, p2p_port, api_port, &[], 1)?;
    let contents = fs::read_to_string(&config)?
        .replacen("\n[node]", "\n[demo]\nsingle_node = true\n\n[node]", 1)
        .replace("default_factor = 3", "default_factor = 1");
    fs::write(&config, contents)?;
    Ok(config)
}

fn write_s3_config_with_partitions(
    root: &Path,
    name: &str,
    p2p_port: u16,
    api_port: u16,
    bootstrap: &[String],
    bucket_partitions: u16,
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
    // Provider-directory repair is intentionally outside the normal S3 I/O
    // assertion. Explicit repair tests invoke the admin repair endpoint.
    contents = contents.replace(
        "repair_interval_seconds = 5",
        "repair_interval_seconds = 3600",
    );
    contents.push_str(&format!(
        "\n[storage.small_object_pack]\nenabled = true\nmax_object_bytes = 1048576\nsegment_bytes = 4194304\nowners = 1\nio_uring_entries = 32\nrequire_io_uring = false\ngroup_commit_delay_microseconds = 200\ngroup_commit_max_requests = 64\ncompaction_dead_percent = 50\n\n[s3]\nenabled = true\nregion = \"us-east-1\"\naccess_key_id = \"pepper-test\"\nsecret_access_key_path = \"{}\"\nbucket_partitions = {bucket_partitions}\n\n[fast_path]\nworkers = 2\ncontrol_cores = 2\npin_cpus = false\n",
        secret_path.display()
    ));
    fs::write(&config, contents)?;
    Ok(config)
}

fn write_s3_erasure_config_with_partitions(
    root: &Path,
    name: &str,
    failure_domain: &str,
    p2p_port: u16,
    api_port: u16,
    bootstrap: &[String],
    bucket_partitions: u16,
) -> TestResult<PathBuf> {
    write_s3_erasure_config_with_options(
        root,
        name,
        failure_domain,
        p2p_port,
        api_port,
        bootstrap,
        None,
        bucket_partitions,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_s3_erasure_config_with_options(
    root: &Path,
    name: &str,
    failure_domain: &str,
    p2p_port: u16,
    api_port: u16,
    bootstrap: &[String],
    strategy: Option<&str>,
    bucket_partitions: u16,
) -> TestResult<PathBuf> {
    let config = write_s3_config_with_partitions(
        root,
        name,
        p2p_port,
        api_port,
        bootstrap,
        bucket_partitions,
    )?;
    let mut contents = fs::read_to_string(&config)?;
    contents = contents.replace(
        &format!("listen_addr = \"127.0.0.1:{p2p_port}\""),
        &format!("listen_addr = \"127.0.0.1:{p2p_port}\"\nfailure_domain = \"{failure_domain}\""),
    );
    contents.push_str(
        "\n[erasure]\nenabled = true\nmin_size_bytes = 1\ndata_shards = 6\nparity_shards = 3\n",
    );
    if let Some(strategy) = strategy {
        contents.push_str(&format!(
            "\n[erasure.transfer]\nstrategy = \"{strategy}\"\npipeline_max_hops = 4\n"
        ));
    }
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

fn spawn_agent_with_log(agent: &str, config: &Path, log: &Path) -> TestResult<ChildGuard> {
    spawn_agent_with_log_and_env(agent, config, log, &[])
}

fn spawn_agent_with_log_and_env(
    agent: &str,
    config: &Path,
    log: &Path,
    envs: &[(&str, &str)],
) -> TestResult<ChildGuard> {
    let output = fs::File::create(log)?;
    let mut command = Command::new(agent);
    command
        .arg("--config")
        .arg(config)
        .env("TOKIO_WORKER_THREADS", "2")
        .stdout(Stdio::from(output.try_clone()?))
        .stderr(Stdio::from(output));
    for (key, value) in envs {
        command.env(key, value);
    }
    Ok(ChildGuard(command.spawn()?))
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
        .env("TOKIO_WORKER_THREADS", "2");
    command.stdout(Stdio::null()).stderr(Stdio::null());
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
    const ATTEMPTS: usize = 600;
    const INTERVAL: Duration = Duration::from_millis(100);
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{api_port}/healthz");
    for _ in 0..ATTEMPTS {
        let mut request = client.get(&url);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Ok(response) = request.send().await
            && response.status().is_success()
        {
            return Ok(());
        }
        tokio::time::sleep(INTERVAL).await;
    }
    Err(format!(
        "agent on port {api_port} did not become healthy after {} seconds",
        ATTEMPTS as u128 * INTERVAL.as_millis() / 1_000
    )
    .into())
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

async fn wait_for_connected_peer_count(api_port: u16, count: usize) -> TestResult<()> {
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
                        let connected = peers
                            .iter()
                            .filter(|peer| peer["connected"].as_bool() == Some(true))
                            .count();
                        observed = observed.max(connected);
                        if connected >= count {
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
        "agent on port {api_port} connected to at most {observed}/{count} peer(s) after {} seconds{}",
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

async fn stable_namespace_term(
    client: &reqwest::Client,
    api_port: u16,
    namespace: &str,
) -> TestResult<u64> {
    let url = format!("http://127.0.0.1:{api_port}/v1/namespaces/{namespace}/status");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let mut previous = None;
    let mut stable = 0usize;
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        match client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                let status: serde_json::Value = response.json().await?;
                let term = status["term"]
                    .as_u64()
                    .ok_or("namespace status has no term")?;
                if !status["quorum_available"].as_bool().unwrap_or(false) {
                    stable = 0;
                } else if previous == Some(term) {
                    stable += 1;
                    if stable >= 3 {
                        return Ok(term);
                    }
                } else {
                    previous = Some(term);
                    stable = 1;
                }
            }
            Ok(response) => {
                last = format!("HTTP {}: {}", response.status(), response.text().await?);
                stable = 0;
            }
            Err(error) => {
                last = error.to_string();
                stable = 0;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("namespace {namespace} did not reach a stable term: {last}").into())
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
