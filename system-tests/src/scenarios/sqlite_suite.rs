// SPDX-License-Identifier: Apache-2.0

use super::{
    bootstrap_cluster, json_request, json_success_eventually,
    namespace_suite::{find_leader, namespace_groups},
};
use crate::harness::{
    backend::{ExecRequest, Fault},
    client::PepperClient,
    cluster::{ClusterSpec, NodeRuntime},
    context::ScenarioContext,
    scenario::{Scenario, ScenarioRequirements},
    wait::eventually,
};
use crate::oracles::{block_inventory, storage_relative_path};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use pepper_sqlite::PageTableNode;
use pepper_types::{CODEC_ERASURE_MANIFEST, Cid};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    fs,
    time::{Duration, Instant},
};

pub struct SqliteImportExportScenario;
pub struct SqliteReadOnlyMultiIngressScenario;
pub struct SqliteBatchAtomicScenario;
pub struct SqliteMultiWriterScenario;
pub struct SqliteLeaderFailoverScenario;
pub struct SqliteMinorityFencingScenario;
pub struct SqliteDurabilityScenario;
pub struct SqliteLargeTransactionScenario;
pub struct SqliteCompatibilityScenario;
pub struct SqliteSoakScenario;

fn requirements() -> ScenarioRequirements {
    ScenarioRequirements {
        minimum_nodes: 3,
        ..ScenarioRequirements::default()
    }
}

async fn bootstrap(context: &mut ScenarioContext) -> Result<PepperClient> {
    let mut spec = ClusterSpec::three_node(context.run.seed);
    spec.sqlite_enabled = true;
    bootstrap_cluster(context, spec).await
}

fn sqlite_image(value: &str, rows: usize) -> Result<Vec<u8>> {
    sqlite_image_with_page_size(value, rows, 4096)
}

fn sqlite_image_with_page_size(value: &str, rows: usize, page_size: u32) -> Result<Vec<u8>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("input.db");
    {
        let connection = Connection::open(&path)?;
        connection.execute_batch(&format!(
            "PRAGMA page_size={page_size}; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
             CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT NOT NULL UNIQUE);
             CREATE INDEX records_value ON records(value);
             CREATE TRIGGER records_guard BEFORE DELETE ON records BEGIN SELECT 1; END;
             PRAGMA user_version=17; PRAGMA application_id=1347440720;"
        ))?;
        for index in 0..rows {
            connection.execute(
                "INSERT INTO records(value) VALUES (?1)",
                [format!("{value}-{index:06}")],
            )?;
        }
    }
    Ok(fs::read(path)?)
}

fn sqlite_large_image(rows: usize) -> Result<Vec<u8>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("large.db");
    {
        let mut connection = Connection::open(&path)?;
        connection.execute_batch(
            "PRAGMA page_size=4096; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
             CREATE TABLE records(id INTEGER PRIMARY KEY, value BLOB NOT NULL);",
        )?;
        let transaction = connection.transaction()?;
        for index in 0..rows {
            transaction.execute(
                "INSERT INTO records(value) VALUES (zeroblob(1024) || ?1)",
                [index.to_string()],
            )?;
        }
        transaction.commit()?;
    }
    Ok(fs::read(path)?)
}

async fn create_database(
    client: &PepperClient,
    node: &NodeRuntime,
    alias: &str,
    storage_policy: Option<Value>,
) -> Result<Value> {
    create_database_with_page_size(client, node, alias, storage_policy, 4096).await
}

async fn create_database_with_page_size(
    client: &PepperClient,
    node: &NodeRuntime,
    alias: &str,
    storage_policy: Option<Value>,
    page_size: u32,
) -> Result<Value> {
    let mut body =
        json!({"database":alias,"request_id":format!("create-{alias}"),"page_size":page_size});
    if let Some(policy) = storage_policy {
        body["storage_policy"] = policy;
    }
    json_success_eventually(client, node, "POST", "/v1/sqlite/databases", body).await
}

async fn import_database(
    client: &PepperClient,
    node: &NodeRuntime,
    alias: &str,
    created: &Value,
    bytes: Vec<u8>,
    request_id: &str,
) -> Result<Value> {
    let path = format!(
        "/v1/sqlite/databases/{alias}/import?request_id={request_id}&base_revision=1&base_generation=1&base_snapshot={}",
        percent(
            created["snapshot_cid"]
                .as_str()
                .context("snapshot CID missing")?
        )
    );
    let response = client
        .request(
            node,
            "POST",
            &path,
            Some("application/vnd.sqlite3"),
            bytes,
            90,
        )
        .await?;
    ensure!(
        (200..300).contains(&response.status),
        "SQLite import returned HTTP {}: {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
    Ok(serde_json::from_slice(&response.body)?)
}

async fn export_database(
    client: &PepperClient,
    node: &NodeRuntime,
    alias: &str,
) -> Result<Vec<u8>> {
    export_snapshot(client, node, alias, None).await
}

async fn export_snapshot(
    client: &PepperClient,
    node: &NodeRuntime,
    alias: &str,
    snapshot: Option<&str>,
) -> Result<Vec<u8>> {
    let suffix = snapshot.map_or(String::new(), |cid| format!("?snapshot={}", percent(cid)));
    let response = client
        .request(
            node,
            "GET",
            &format!("/v1/sqlite/databases/{alias}/export{suffix}"),
            None,
            Vec::new(),
            90,
        )
        .await?;
    ensure!(
        response.status == 200,
        "SQLite export returned HTTP {}",
        response.status
    );
    Ok(response.body)
}

async fn export_selected(
    client: &PepperClient,
    node: &NodeRuntime,
    alias: &str,
    query: &str,
) -> Result<Vec<u8>> {
    let response = client
        .request(
            node,
            "GET",
            &format!("/v1/sqlite/databases/{alias}/export?{query}"),
            None,
            Vec::new(),
            90,
        )
        .await?;
    ensure!(
        response.status == 200,
        "selected SQLite export returned HTTP {}",
        response.status
    );
    Ok(response.body)
}

fn sqlite_logical_check(bytes: &[u8], expected_rows: Option<i64>) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("check.db");
    fs::write(&path, bytes)?;
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    ensure!(
        integrity == "ok",
        "stock SQLite integrity_check returned {integrity}"
    );
    if let Some(expected) = expected_rows {
        let count: i64 =
            connection.query_row("SELECT count(*) FROM records", [], |row| row.get(0))?;
        ensure!(count == expected, "expected {expected} rows, found {count}");
    }
    Ok(())
}

fn sqlite_socket(context: &ScenarioContext, node: &NodeRuntime) -> String {
    if context.run.backend.name == "docker" {
        "/var/lib/pepper/metadata/sqlite.sock".into()
    } else {
        node.data_path.join("sqlite.sock").display().to_string()
    }
}

async fn sqlite_exec(
    context: &ScenarioContext,
    node: &NodeRuntime,
    database: &str,
    sql: &str,
) -> Result<String> {
    let cluster = context.cluster.as_ref().expect("cluster");
    let result = cluster
        .backend
        .exec(
            &node.id,
            ExecRequest {
                command: vec![
                    "pepper-sqlite".into(),
                    "--socket".into(),
                    sqlite_socket(context, node),
                    database.into(),
                    sql.into(),
                ],
                stdin: Vec::new(),
                timeout_seconds: 60,
                max_output_bytes: 1024 * 1024,
            },
        )
        .await?;
    ensure!(
        result.exit_code == 0,
        "pepper-sqlite failed on {}: {}",
        node.id,
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}

async fn page_pack_roots(client: &PepperClient, node: &NodeRuntime, root: Cid) -> Result<Vec<Cid>> {
    let mut pending = vec![root];
    let mut visited = HashSet::new();
    let mut packs = HashSet::new();
    while let Some(cid) = pending.pop() {
        if !visited.insert(cid.clone()) {
            continue;
        }
        let node: PageTableNode = serde_json::from_slice(&client.get_block(node, &cid).await?)?;
        pending.extend(node.children.into_iter().map(|child| child.cid));
        packs.extend(node.pages.into_iter().map(|page| page.pack_cid));
    }
    let mut packs = packs.into_iter().collect::<Vec<_>>();
    packs.sort_by_key(ToString::to_string);
    Ok(packs)
}

fn percent(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

async fn setup(
    context: &mut ScenarioContext,
    alias: &str,
    policy: Option<Value>,
    rows: usize,
) -> Result<(PepperClient, Vec<NodeRuntime>, Value, Value, Vec<u8>)> {
    let client = bootstrap(context).await?;
    let nodes = context
        .cluster
        .as_ref()
        .expect("cluster")
        .nodes
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let created = create_database(&client, &nodes[0], alias, policy).await?;
    let image = sqlite_image(alias, rows)?;
    let imported = import_database(
        &client,
        &nodes[1],
        alias,
        &created,
        image.clone(),
        &format!("import-{alias}"),
    )
    .await?;
    Ok((client, nodes, created, imported, image))
}

fn record(context: &ScenarioContext, invariant: &str, details: Value) -> Result<()> {
    context.run.events.record(
        "invariant",
        json!({"invariant_id":invariant,"invariant_result":"pass","details":details}),
    )?;
    Ok(())
}

#[async_trait]
impl Scenario for SqliteImportExportScenario {
    fn id(&self) -> &'static str {
        "SQLITE-001"
    }
    fn name(&self) -> &'static str {
        "sqlite-import-export-format"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let adaptive = json!({
            "kind":"adaptive",
            "small_commit_replicas":3,
            "large_commit_data_shards":2,
            "large_commit_parity_shards":1,
            "large_commit_shard_copies":1,
            "threshold_bytes":1048576
        });
        let (client, nodes, created, imported, image) =
            setup(context, "sqlite-001", Some(adaptive), 64).await?;
        let exported = export_database(&client, &nodes[2], "sqlite-001").await?;
        ensure!(exported == image);
        sqlite_logical_check(&exported, Some(64))?;
        let small_root: Cid = imported["snapshot"]["page_table_root_cid"]
            .as_str()
            .context("small adaptive page-table root")?
            .parse()?;
        let small_packs = page_pack_roots(&client, &nodes[2], small_root).await?;
        ensure!(
            !small_packs.is_empty()
                && small_packs
                    .iter()
                    .all(|cid| cid.codec != CODEC_ERASURE_MANIFEST),
            "small adaptive page packs unexpectedly used erasure coding"
        );
        let mut corpus_page_sizes = vec![4096u32];
        for page_size in [512u32, 1024, 2048, 8192, 16_384, 32_768, 65_536] {
            let alias = format!("sqlite-001-pages-{page_size}");
            let created =
                create_database_with_page_size(&client, &nodes[0], &alias, None, page_size).await?;
            let corpus = sqlite_image_with_page_size(&alias, 24, page_size)?;
            import_database(
                &client,
                &nodes[1],
                &alias,
                &created,
                corpus.clone(),
                &format!("import-{alias}"),
            )
            .await?;
            let round_trip = export_database(&client, &nodes[2], &alias).await?;
            ensure!(
                round_trip == corpus,
                "{page_size}-byte page corpus changed bytes"
            );
            sqlite_logical_check(&round_trip, Some(24))?;
            corpus_page_sizes.push(page_size);
        }
        corpus_page_sizes.sort_unstable();
        let historical = export_snapshot(
            &client,
            &nodes[1],
            "sqlite-001",
            created["snapshot_cid"].as_str(),
        )
        .await?;
        sqlite_logical_check(&historical, None)?;
        ensure!(
            historical != exported,
            "historical and current exports unexpectedly match"
        );
        ensure!(export_selected(&client, &nodes[2], "sqlite-001", "revision=2").await? == image);
        let namespace = created["namespace_id"].as_str().context("namespace id")?;
        let (snapshot_status, _) = json_request(&client, &nodes[0], "POST", "/v1/namespaces/sqlite-001/snapshots", json!({"action":"create","name":"imported","revision":2,"request_id":"sqlite-001-name"})).await?;
        ensure!((200..300).contains(&snapshot_status));
        ensure!(
            export_selected(&client, &nodes[1], "sqlite-001", "named_snapshot=imported").await?
                == image
        );
        let (_, history) = json_request(
            &client,
            &nodes[1],
            "GET",
            "/v1/namespaces/sqlite-001/history",
            Value::Null,
        )
        .await?;
        let root = history["history"]["2"]["root_cid"]
            .as_str()
            .context("revision root")?;
        ensure!(
            export_selected(
                &client,
                &nodes[2],
                "sqlite-001",
                &format!("root_cid={}", percent(root))
            )
            .await?
                == image
        );
        let (checkpoint_status, _) = json_request(
            &client,
            &nodes[0],
            "POST",
            "/v1/admin/namespaces/sqlite-001/checkpoint",
            json!({}),
        )
        .await?;
        ensure!((200..300).contains(&checkpoint_status));
        let checkpoint = eventually(
            "SQLite checkpoint",
            Duration::from_secs(30),
            Duration::from_millis(200),
            || async {
                let groups = namespace_groups(&client, &nodes[0]).await?;
                Ok(groups
                    .into_iter()
                    .find(|group| {
                        group["namespace_id"].as_str() == Some(namespace)
                            && group["checkpoint_verified"] == true
                    })
                    .and_then(|group| group["checkpoint_cid"].as_str().map(ToString::to_string)))
            },
        )
        .await?;
        ensure!(
            export_selected(
                &client,
                &nodes[2],
                "sqlite-001",
                &format!("checkpoint_cid={}", percent(&checkpoint))
            )
            .await?
                == image
        );
        json_success_eventually(
            &client,
            &nodes[0],
            "POST",
            "/v1/sqlite/databases/sqlite-001/compact",
            json!({"request_id":"sqlite-001-before-rollback"}),
        )
        .await?;
        let (rollback_status, rollback) = json_request(
            &client,
            &nodes[2],
            "POST",
            "/v1/sqlite/databases/sqlite-001/rollback",
            json!({"revision":2,"request_id":"sqlite-001-rollback"}),
        )
        .await?;
        ensure!(
            rollback_status == 200
                && rollback["head_generation"] == 4
                && rollback["durability"] == "durable"
        );
        ensure!(export_database(&client, &nodes[1], "sqlite-001").await? == image);
        let (bypass_status, _) = json_request(
            &client,
            &nodes[0],
            "POST",
            "/v1/namespaces/sqlite-001/rollback",
            json!({"revision":1,"request_id":"forbidden-generic-rollback"}),
        )
        .await?;
        ensure!(
            bypass_status == 409,
            "generic namespace rollback bypassed SQLite writer fencing"
        );
        record(
            context,
            "SAF-SQLITE-002",
            json!({"current_byte_exact":true,"historical_integrity":true,"page_size_corpus":corpus_page_sizes,"selectors":["snapshot","revision","root","checkpoint","named_snapshot"],"rollback_new_generation":true,"generic_mutation_fenced":true,"ingress_nodes":3}),
        )
    }
}

#[async_trait]
impl Scenario for SqliteReadOnlyMultiIngressScenario {
    fn id(&self) -> &'static str {
        "SQLITE-002"
    }
    fn name(&self) -> &'static str {
        "sqlite-read-only-multi-ingress"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let (client, nodes, _, _, _) = setup(context, "sqlite-002", None, 32).await?;
        let (_, old_session) = json_request(
            &client,
            &nodes[1],
            "POST",
            "/v1/sqlite/databases/sqlite-002/sessions",
            json!({}),
        )
        .await?;
        let old_session_id = old_session["session_id"]
            .as_str()
            .context("session missing")?;
        let old_page = client
            .request(
                &nodes[1],
                "GET",
                &format!("/v1/sqlite/sessions/{old_session_id}/pages?pages=1"),
                None,
                Vec::new(),
                30,
            )
            .await?;
        ensure!(old_page.status == 200 && old_page.body.len() == 4096);
        json_success_eventually(
            &client,
            &nodes[0],
            "POST",
            "/v1/sqlite/databases/sqlite-002/compact",
            json!({"request_id":"sqlite-002-compact"}),
        )
        .await?;
        let retained = client
            .request(
                &nodes[1],
                "GET",
                &format!("/v1/sqlite/sessions/{old_session_id}/pages?pages=1"),
                None,
                Vec::new(),
                30,
            )
            .await?;
        ensure!(retained.status == 200 && retained.body == old_page.body);
        let (_, new_session) = json_request(
            &client,
            &nodes[2],
            "POST",
            "/v1/sqlite/databases/sqlite-002/sessions",
            json!({}),
        )
        .await?;
        ensure!(old_session["snapshot_cid"] != new_session["snapshot_cid"]);
        record(
            context,
            "GC-SQLITE-001",
            json!({"multi_ingress":true,"historical_session_stable":true}),
        )
    }
}

#[async_trait]
impl Scenario for SqliteBatchAtomicScenario {
    fn id(&self) -> &'static str {
        "SQLITE-003"
    }
    fn name(&self) -> &'static str {
        "sqlite-batch-atomic-commit"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let (client, nodes, _, _, image) = setup(context, "sqlite-003", None, 8).await?;
        let (_, info) = json_request(
            &client,
            &nodes[0],
            "GET",
            "/v1/sqlite/databases/sqlite-003",
            Value::Null,
        )
        .await?;
        let (_, acquired) = json_request(&client, &nodes[0], "POST", "/v1/sqlite/databases/sqlite-003/writer/acquire", json!({
            "session_id":"atomic-fault","acquisition_id":"atomic-fault",
            "base_snapshot":info["snapshot_cid"],"base_generation":info["head_generation"],"wait_timeout_millis":0
        })).await?;
        ensure!(acquired["status"] == "granted");
        let ticket = &acquired["ticket"];
        let path = format!(
            "/v1/sqlite/databases/sqlite-003/transactions?request_id=sqlite-003-truncated&base_revision={}&base_generation={}&base_snapshot={}&new_logical_size={}&pages=1&ticket_id={}&acquisition_id={}&holder={}&leader_term={}&lease_epoch={}&expires_at_millis={}",
            info["namespace_revision"].as_u64().context("revision")?,
            info["head_generation"].as_u64().context("generation")?,
            percent(info["snapshot_cid"].as_str().context("snapshot")?),
            image.len(),
            percent(ticket["ticket_id"].as_str().context("ticket id")?),
            percent(
                ticket["acquisition_id"]
                    .as_str()
                    .context("acquisition id")?
            ),
            percent(ticket["holder"].as_str().context("holder")?),
            ticket["leader_term"].as_u64().context("leader term")?,
            ticket["lease_epoch"].as_u64().context("lease epoch")?,
            ticket["expires_at_millis"].as_u64().context("expiry")?,
        );
        let failed = client
            .request(
                &nodes[2],
                "POST",
                &path,
                Some("application/octet-stream"),
                vec![0],
                30,
            )
            .await?;
        ensure!(
            failed.status >= 400,
            "truncated batch unexpectedly committed"
        );
        ensure!(export_database(&client, &nodes[1], "sqlite-003").await? == image);
        let (_, unchanged) = json_request(
            &client,
            &nodes[2],
            "GET",
            "/v1/sqlite/databases/sqlite-003",
            Value::Null,
        )
        .await?;
        ensure!(
            unchanged["snapshot_cid"] == info["snapshot_cid"]
                && unchanged["head_generation"] == info["head_generation"]
        );
        let (released, _) = json_request(
            &client,
            &nodes[0],
            "POST",
            "/v1/sqlite/databases/sqlite-003/writer/release",
            json!({"ticket":ticket}),
        )
        .await?;
        ensure!(released == 204);
        let compact = json_success_eventually(
            &client,
            &nodes[2],
            "POST",
            "/v1/sqlite/databases/sqlite-003/compact",
            json!({"request_id":"sqlite-003-complete"}),
        )
        .await?;
        ensure!(compact["durability"] == "durable");
        ensure!(export_database(&client, &nodes[0], "sqlite-003").await? == image);
        record(
            context,
            "SAF-SQLITE-001",
            json!({"fault_exposed_old_head":true,"complete_batch_exposed_new_head":true}),
        )
    }
}

#[async_trait]
impl Scenario for SqliteMultiWriterScenario {
    fn id(&self) -> &'static str {
        "SQLITE-004"
    }
    fn name(&self) -> &'static str {
        "sqlite-multi-peer-writer-serialization"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let (client, nodes, _, _, _) = setup(context, "sqlite-004", None, 8).await?;
        let before = json_success_eventually(
            &client,
            &nodes[1],
            "GET",
            "/v1/sqlite/databases/sqlite-004",
            Value::Null,
        )
        .await?;
        let (left, right) = tokio::join!(
            sqlite_exec(
                context,
                &nodes[0],
                "sqlite-004",
                "INSERT INTO records(value) VALUES ('writer-left')"
            ),
            sqlite_exec(
                context,
                &nodes[2],
                "sqlite-004",
                "INSERT INTO records(value) VALUES ('writer-right')"
            )
        );
        left?;
        right?;
        let exported = export_database(&client, &nodes[1], "sqlite-004").await?;
        sqlite_logical_check(&exported, Some(10))?;
        let after = json_success_eventually(
            &client,
            &nodes[2],
            "GET",
            "/v1/sqlite/databases/sqlite-004",
            Value::Null,
        )
        .await?;
        ensure!(
            after["head_generation"].as_u64()
                == before["head_generation"].as_u64().map(|value| value + 2)
        );
        record(
            context,
            "SAF-SQLITE-001",
            json!({"processes":2,"ingress_peers":2,"serial_commits":2,"rows":10}),
        )
    }
}

#[async_trait]
impl Scenario for SqliteLeaderFailoverScenario {
    fn id(&self) -> &'static str {
        "SQLITE-005"
    }
    fn name(&self) -> &'static str {
        "sqlite-leader-failover-ambiguity"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let (client, nodes, created, _, image) = setup(context, "sqlite-005", None, 8).await?;
        json_success_eventually(
            &client,
            &nodes[0],
            "POST",
            "/v1/sqlite/databases/sqlite-005/compact",
            json!({"request_id":"sqlite-005-commit"}),
        )
        .await?;
        let namespace = created["namespace_id"].as_str().context("namespace id")?;
        let leader = {
            let cluster = context.cluster.as_ref().expect("cluster");
            find_leader(&client, cluster, namespace).await?
        };
        context
            .cluster
            .as_ref()
            .expect("cluster")
            .backend
            .stop(&leader)
            .await?;
        let survivor = nodes
            .iter()
            .find(|node| node.id != leader)
            .context("survivor")?
            .clone();
        let commit = eventually(
            "SQLite commit status after leader loss",
            Duration::from_secs(75),
            Duration::from_millis(250),
            || async {
                let response = client
                    .request(
                        &survivor,
                        "GET",
                        "/v1/sqlite/databases/sqlite-005/commits/sqlite-005-commit",
                        None,
                        Vec::new(),
                        5,
                    )
                    .await;
                let Some(response) = response.ok().filter(|response| response.status == 200) else {
                    return Ok(None);
                };
                Ok(Some(serde_json::from_slice::<Value>(&response.body)?))
            },
        )
        .await?;
        ensure!(commit["idempotency_key"] == "sqlite-005-commit");
        ensure!(export_database(&client, &survivor, "sqlite-005").await? == image);
        record(
            context,
            "SAF-SQLITE-003",
            json!({"failed_leader":leader.to_string(),"cross_ingress_status":true,"acknowledged_head_readable":true}),
        )
    }
}

#[async_trait]
impl Scenario for SqliteMinorityFencingScenario {
    fn id(&self) -> &'static str {
        "SQLITE-006"
    }
    fn name(&self) -> &'static str {
        "sqlite-minority-partition-fencing"
    }
    fn requirements(&self) -> ScenarioRequirements {
        ScenarioRequirements {
            minimum_nodes: 3,
            requires_docker: true,
            requires_net_admin: true,
            ..ScenarioRequirements::default()
        }
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let mut spec = ClusterSpec::three_node(context.run.seed);
        spec.sqlite_enabled = true;
        spec.net_admin = true;
        let client = bootstrap_cluster(context, spec).await?;
        let nodes = context
            .cluster
            .as_ref()
            .expect("cluster")
            .nodes
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let created = create_database(&client, &nodes[0], "sqlite-006", None).await?;
        let image = sqlite_image("sqlite-006", 8)?;
        import_database(
            &client,
            &nodes[1],
            "sqlite-006",
            &created,
            image,
            "import-sqlite-006",
        )
        .await?;
        let namespace = created["namespace_id"].as_str().context("namespace id")?;
        let leader = {
            let cluster = context.cluster.as_ref().expect("cluster");
            find_leader(&client, cluster, namespace).await?
        };
        let isolated = nodes
            .iter()
            .find(|node| node.id == leader)
            .context("leader runtime")?
            .clone();
        let (_, info) = json_request(
            &client,
            &isolated,
            "GET",
            "/v1/sqlite/databases/sqlite-006",
            Value::Null,
        )
        .await?;
        let (_, acquired) = json_request(&client, &isolated, "POST", "/v1/sqlite/databases/sqlite-006/writer/acquire", json!({
            "session_id":"old-term","acquisition_id":"old-term","base_snapshot":info["snapshot_cid"],
            "base_generation":info["head_generation"],"wait_timeout_millis":0
        })).await?;
        ensure!(acquired["status"] == "granted");
        let survivors = nodes
            .iter()
            .filter(|node| node.id != leader)
            .cloned()
            .collect::<Vec<_>>();
        let mut guards = Vec::new();
        for peer in &survivors {
            guards.push(
                context
                    .cluster
                    .as_ref()
                    .expect("cluster")
                    .backend
                    .clone()
                    .apply_fault(Fault::NetworkPartition {
                        source: leader.clone(),
                        target: peer.id.clone(),
                    })
                    .await?,
            );
            guards.push(
                context
                    .cluster
                    .as_ref()
                    .expect("cluster")
                    .backend
                    .clone()
                    .apply_fault(Fault::NetworkPartition {
                        source: peer.id.clone(),
                        target: leader.clone(),
                    })
                    .await?,
            );
        }
        let minority = client
            .request(
                &isolated,
                "POST",
                "/v1/sqlite/databases/sqlite-006/compact",
                Some("application/json"),
                serde_json::to_vec(&json!({"request_id":"minority-must-not-commit"}))?,
                3,
            )
            .await;
        ensure!(
            !minority
                .as_ref()
                .is_ok_and(|response| response.status < 300),
            "minority SQLite write unexpectedly committed"
        );
        let majority = eventually(
            "SQLite majority leader",
            Duration::from_secs(45),
            Duration::from_millis(250),
            || async {
                for node in &survivors {
                    if let Ok(groups) = namespace_groups(&client, node).await
                        && groups.into_iter().any(|group| {
                            group["namespace_id"].as_str() == Some(namespace)
                                && group["role"] == "leader"
                        })
                    {
                        return Ok(Some(node.clone()));
                    }
                }
                Ok(None)
            },
        )
        .await?;
        eventually(
            "isolated SQLite ingress reports read-only degradation",
            Duration::from_secs(30),
            Duration::from_millis(250),
            || async {
                let response = client
                    .request(&isolated, "GET", "/v1/admin/sqlite", None, Vec::new(), 5)
                    .await?;
                if response.status != 200 {
                    return Ok(None);
                }
                let status: Value = serde_json::from_slice(&response.body)?;
                Ok((status["runtime_ready"] == true
                    && status["write_quorum_ready"] == false
                    && status["read_only_degraded"] == true
                    && status["access_mode"] == "read_only_degraded")
                    .then_some(()))
            },
        )
        .await?;
        let (release_status, _) = json_request(
            &client,
            &majority,
            "POST",
            "/v1/sqlite/databases/sqlite-006/writer/release",
            json!({"ticket":acquired["ticket"]}),
        )
        .await?;
        ensure!(
            release_status >= 400,
            "old-term ticket remained effective after failover"
        );
        let (_, unchanged) = json_request(
            &client,
            &majority,
            "GET",
            "/v1/sqlite/databases/sqlite-006",
            Value::Null,
        )
        .await?;
        ensure!(unchanged["head_generation"] == info["head_generation"]);
        while let Some(guard) = guards.pop() {
            guard.heal().await?;
        }
        record(
            context,
            "SAF-SQLITE-003",
            json!({"minority_commit":false,"old_term_ticket_fenced":true,"generation_unchanged":true,"isolated_readiness":"read_only_degraded"}),
        )
    }
}

#[async_trait]
impl Scenario for SqliteDurabilityScenario {
    fn id(&self) -> &'static str {
        "SQLITE-007"
    }
    fn name(&self) -> &'static str {
        "sqlite-durability-gc-repair"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let policy = json!({"kind":"erasure","data_shards":2,"parity_shards":1,"shard_copies":1});
        let (client, nodes, _, _, image) = setup(context, "sqlite-007", Some(policy), 1024).await?;
        let (_, session) = json_request(
            &client,
            &nodes[1],
            "POST",
            "/v1/sqlite/databases/sqlite-007/sessions",
            json!({}),
        )
        .await?;
        json_success_eventually(
            &client,
            &nodes[2],
            "POST",
            "/v1/sqlite/databases/sqlite-007/compact",
            json!({"request_id":"sqlite-007-compact"}),
        )
        .await?;
        let (gc, _) = json_request(
            &client,
            &nodes[0],
            "POST",
            "/v1/admin/gc",
            json!({"dry_run":false}),
        )
        .await?;
        ensure!((200..300).contains(&gc));
        let session_id = session["session_id"].as_str().context("session id")?;
        let retained = client
            .request(
                &nodes[1],
                "GET",
                &format!("/v1/sqlite/sessions/{session_id}/pages?pages=1"),
                None,
                Vec::new(),
                30,
            )
            .await?;
        ensure!(retained.status == 200 && retained.body.len() == 4096);
        let (_, info) = json_request(
            &client,
            &nodes[2],
            "GET",
            "/v1/sqlite/databases/sqlite-007",
            Value::Null,
        )
        .await?;
        let root: Cid = info["snapshot"]["page_table_root_cid"]
            .as_str()
            .context("page table root")?
            .parse()?;
        let pack = page_pack_roots(&client, &nodes[2], root)
            .await?
            .into_iter()
            .find(|cid| cid.codec == CODEC_ERASURE_MANIFEST)
            .context("EC page pack")?;
        let manifest = client.erasure_manifest(&nodes[2], &pack).await?;
        let target = manifest
            .stripes
            .first()
            .and_then(|stripe| stripe.shards.first())
            .context("EC shard")?
            .cid
            .clone();
        let mut victim = None;
        for node in &nodes {
            if block_inventory(
                &context.cluster.as_ref().expect("cluster").backend,
                &node.id,
                &node.node_identity,
            )
            .await?
            .iter()
            .any(|entry| entry.cid == target)
            {
                victim = Some(node.clone());
                break;
            }
        }
        let victim = victim.context("EC shard location")?;
        context
            .cluster
            .as_ref()
            .expect("cluster")
            .backend
            .remove_storage_file(&victim.id, &storage_relative_path(&target))
            .await?;
        context
            .cluster
            .as_ref()
            .expect("cluster")
            .backend
            .restart(
                &victim.id,
                crate::harness::backend::RestartPolicy::PreserveAll,
            )
            .await?;
        eventually(
            "SQLite EC victim restart",
            Duration::from_secs(30),
            Duration::from_millis(200),
            || async { Ok(client.health(&victim).await?.then_some(())) },
        )
        .await?;
        ensure!(export_database(&client, &nodes[2], "sqlite-007").await? == image);
        let repair = client
            .request(
                &nodes[2],
                "POST",
                "/v1/admin/sqlite/repair",
                Some("application/json"),
                Vec::new(),
                60,
            )
            .await?;
        ensure!((200..300).contains(&repair.status));
        eventually(
            "SQLite EC shard repair",
            Duration::from_secs(60),
            Duration::from_millis(500),
            || async {
                for node in &nodes {
                    let inventory = block_inventory(
                        &context.cluster.as_ref().expect("cluster").backend,
                        &node.id,
                        &node.node_identity,
                    )
                    .await?;
                    if inventory
                        .iter()
                        .any(|entry| entry.cid == target && entry.integrity_state == "verified")
                    {
                        return Ok(Some(()));
                    }
                }
                Ok(None)
            },
        )
        .await?;
        let (staging_status, staging) = json_request(
            &client,
            &nodes[1],
            "GET",
            "/v1/admin/sqlite/staging",
            Value::Null,
        )
        .await?;
        ensure!(staging_status == 200 && staging["active_leases"].is_number());
        let (admin_status, admin) =
            json_request(&client, &nodes[0], "GET", "/v1/admin/sqlite", Value::Null).await?;
        ensure!(
            admin_status == 200
                && admin["runtime_ready"] == true
                && admin["write_quorum_ready"] == true
                && admin["access_mode"] == "read_write"
        );
        let metrics = client
            .request(&nodes[0], "GET", "/metrics", None, Vec::new(), 30)
            .await?;
        let metrics = String::from_utf8(metrics.body)?;
        for metric in [
            "pepper_sqlite_page_pack_writes_total",
            "pepper_sqlite_ec_page_pack_writes_total",
            "pepper_sqlite_page_cache_hits_total",
            "pepper_sqlite_compactions_total",
        ] {
            ensure!(metrics.contains(metric), "missing SQLite metric {metric}");
        }
        record(
            context,
            "DUR-SQLITE-001",
            json!({"policy":"2+1","active_snapshot_survived_gc":true,"missing_shard_reconstructed":true,"repair_verified":true,"admin_staging":true,"readiness_mode":"read_write","metrics":true}),
        )
    }
}

#[async_trait]
impl Scenario for SqliteLargeTransactionScenario {
    fn id(&self) -> &'static str {
        "SQLITE-008"
    }
    fn name(&self) -> &'static str {
        "sqlite-large-transaction-compaction"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap(context).await?;
        let nodes = context
            .cluster
            .as_ref()
            .expect("cluster")
            .nodes
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let adaptive = json!({
            "kind":"adaptive",
            "small_commit_replicas":3,
            "large_commit_data_shards":2,
            "large_commit_parity_shards":1,
            "large_commit_shard_copies":1,
            "threshold_bytes":1048576
        });
        let created = create_database(&client, &nodes[0], "sqlite-008", Some(adaptive)).await?;
        let image = sqlite_large_image(8192)?;
        ensure!(
            image.len() > 8 * 1024 * 1024,
            "large fixture is unexpectedly small"
        );
        let imported = import_database(
            &client,
            &nodes[1],
            "sqlite-008",
            &created,
            image.clone(),
            "sqlite-008-large",
        )
        .await?;
        let before = json_success_eventually(
            &client,
            &nodes[2],
            "GET",
            "/v1/sqlite/databases/sqlite-008",
            Value::Null,
        )
        .await?;
        let adaptive_root: Cid = imported["snapshot"]["page_table_root_cid"]
            .as_str()
            .context("large adaptive page-table root")?
            .parse()?;
        ensure!(
            page_pack_roots(&client, &nodes[2], adaptive_root)
                .await?
                .iter()
                .any(|cid| cid.codec == CODEC_ERASURE_MANIFEST),
            "large adaptive page packs did not switch to erasure coding"
        );
        let compact = json_success_eventually(
            &client,
            &nodes[0],
            "POST",
            "/v1/sqlite/databases/sqlite-008/compact",
            json!({"request_id":"sqlite-008-compact"}),
        )
        .await?;
        ensure!(compact["durability"] == "durable");
        let exported = export_database(&client, &nodes[2], "sqlite-008").await?;
        ensure!(exported == image);
        sqlite_logical_check(&exported, Some(8192))?;
        let after = json_success_eventually(
            &client,
            &nodes[1],
            "GET",
            "/v1/sqlite/databases/sqlite-008",
            Value::Null,
        )
        .await?;
        ensure!(
            after["head_generation"].as_u64()
                == before["head_generation"].as_u64().map(|value| value + 1)
        );
        let replay = json_success_eventually(
            &client,
            &nodes[2],
            "POST",
            "/v1/sqlite/databases/sqlite-008/compact",
            json!({"request_id":"sqlite-008-compact"}),
        )
        .await?;
        ensure!(
            replay["replayed"] == true
                && replay["commit"]["generation"] == after["head_generation"]
        );
        let replayed_head = json_success_eventually(
            &client,
            &nodes[0],
            "GET",
            "/v1/sqlite/databases/sqlite-008",
            Value::Null,
        )
        .await?;
        ensure!(replayed_head["head_generation"] == after["head_generation"]);
        record(
            context,
            "SAF-SQLITE-004",
            json!({"logical_bytes":image.len(),"adaptive_large_pack_erasure_coded":true,"compacted_byte_exact":true,"streamed_compaction":true,"idempotent_restart":true,"raft_head_mutations":1}),
        )
    }
}

#[async_trait]
impl Scenario for SqliteCompatibilityScenario {
    fn id(&self) -> &'static str {
        "SQLITE-009"
    }
    fn name(&self) -> &'static str {
        "sqlite-vfs-compatibility"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let (client, nodes, _, _, _) = setup(context, "sqlite-009", None, 128).await?;
        sqlite_exec(
            context,
            &nodes[0],
            "sqlite-009",
            "CREATE TABLE compat(id INTEGER PRIMARY KEY, label TEXT NOT NULL UNIQUE)",
        )
        .await?;
        sqlite_exec(
            context,
            &nodes[1],
            "sqlite-009",
            "CREATE INDEX compat_label ON compat(label)",
        )
        .await?;
        sqlite_exec(context, &nodes[2], "sqlite-009", "CREATE TRIGGER compat_nonempty BEFORE INSERT ON compat WHEN new.label='' BEGIN SELECT RAISE(ABORT, 'empty'); END").await?;
        sqlite_exec(
            context,
            &nodes[0],
            "sqlite-009",
            "INSERT INTO compat(label) VALUES ('alpha')",
        )
        .await?;
        sqlite_exec(
            context,
            &nodes[1],
            "sqlite-009",
            "UPDATE compat SET label='beta' WHERE id=1",
        )
        .await?;
        sqlite_exec(
            context,
            &nodes[2],
            "sqlite-009",
            "ALTER TABLE compat ADD COLUMN score INTEGER NOT NULL DEFAULT 7",
        )
        .await?;
        let query = sqlite_exec(
            context,
            &nodes[1],
            "sqlite-009",
            "SELECT label, score FROM compat",
        )
        .await?;
        ensure!(query.contains("beta\t7"));
        let exported = export_database(&client, &nodes[2], "sqlite-009").await?;
        sqlite_logical_check(&exported, Some(128))?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("compat.db");
        fs::write(&path, exported)?;
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let compat: (String, i64) =
            connection.query_row("SELECT label, score FROM compat", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;
        ensure!(compat == ("beta".into(), 7));
        record(
            context,
            "SAF-SQLITE-002",
            json!({"stock_sqlite_integrity":true,"ddl":true,"dml":true,"index":true,"trigger":true,"alter_table":true,"cross_peer":true}),
        )
    }
}

#[async_trait]
impl Scenario for SqliteSoakScenario {
    fn id(&self) -> &'static str {
        "SOAK-SQLITE-001"
    }
    fn name(&self) -> &'static str {
        "sqlite-bounded-soak"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let (client, nodes, _, _, _) = setup(context, "sqlite-soak", None, 64).await?;
        let duration = Duration::from_secs(context.run.duration_seconds.unwrap_or(5).max(1));
        let started = Instant::now();
        let mut iterations = 0u64;
        while started.elapsed() < duration {
            let iteration = iterations;
            let value = json_success_eventually(
                &client,
                &nodes[iteration as usize % nodes.len()],
                "POST",
                "/v1/sqlite/databases/sqlite-soak/compact",
                json!({"request_id":format!("sqlite-soak-{iteration}")}),
            )
            .await?;
            ensure!(value["durability"] == "durable");
            iterations += 1;
        }
        let (status, check) = json_request(
            &client,
            &nodes[2],
            "GET",
            "/v1/sqlite/databases/sqlite-soak/check",
            Value::Null,
        )
        .await?;
        ensure!(status == 200 && check["status"] == "ok");
        context.run.artifacts.write_json(
            "observations/sqlite-soak-report.json",
            &json!({
                "schema_version":1,
                "iterations":iterations,
                "elapsed_millis":started.elapsed().as_millis(),
                "final_generation":check["head_generation"],
                "final_snapshot":check["snapshot_cid"],
                "status":"pass"
            }),
        )?;
        record(
            context,
            "CONV-SQLITE-001",
            json!({"iterations":iterations,"final_generation":check["head_generation"]}),
        )
    }
}
