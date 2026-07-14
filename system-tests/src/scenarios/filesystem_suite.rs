// SPDX-License-Identifier: Apache-2.0

use super::{
    bootstrap_three_nodes, json_request, json_success_eventually,
    namespace_suite::wait_namespace_converged,
};
use crate::{
    harness::{
        backend::Fault,
        context::ScenarioContext,
        scenario::{Scenario, ScenarioRequirements},
    },
    oracles::deterministic_bytes,
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub struct FilesystemTreeScenario;
pub struct FilesystemSharingScenario;
pub struct FilesystemHistoryScenario;

fn requirements() -> ScenarioRequirements {
    ScenarioRequirements {
        minimum_nodes: 3,
        ..ScenarioRequirements::default()
    }
}

async fn create_fs(
    client: &crate::harness::client::PepperClient,
    node: &crate::harness::cluster::NodeRuntime,
    alias: &str,
) -> Result<Value> {
    json_success_eventually(
        client,
        node,
        "POST",
        "/v1/filesystems",
        json!({"alias":alias}),
    )
    .await
}

async fn commit(
    client: &crate::harness::client::PepperClient,
    node: &crate::harness::cluster::NodeRuntime,
    filesystem: &str,
    base: u64,
    entries: Value,
    request: &str,
) -> Result<Value> {
    json_success_eventually(client, node, "POST", "/v1/fs/commit", json!({"filesystem":filesystem,"base_revision":base,"entries":entries,"request_id":request})).await
}

fn entry(path: &str, kind: &str, mode: u32, size: usize, cid: Option<String>) -> Value {
    json!({"path":path,"kind":kind,"mode":mode,"logical_size":size,"content_cid":cid})
}

#[async_trait]
impl Scenario for FilesystemTreeScenario {
    fn id(&self) -> &'static str {
        "FS-001"
    }
    fn name(&self) -> &'static str {
        "filesystem-generated-tree"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().unwrap();
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = create_fs(&client, &nodes[0], "fs-001").await?;
        let filesystem = created["namespace_id"].as_str().unwrap().to_string();
        wait_namespace_converged(
            &client,
            cluster,
            &filesystem,
            0,
            created["root_cid"].as_str(),
        )
        .await?;
        let mut entries = vec![
            entry("bin", "directory", 0o755, 0, None),
            entry("data", "directory", 0o750, 0, None),
        ];
        let mut expected = BTreeMap::new();
        for index in 0..6usize {
            let bytes =
                deterministic_bytes(b"fs-001", context.run.seed ^ index as u64, 500 + index * 17);
            let content = client.put_block(&nodes[index % 3], &bytes).await?;
            let path = if index % 2 == 0 {
                format!("bin/file-{index}")
            } else {
                format!("data/file-{index}")
            };
            let mode = if index % 2 == 0 { 0o755 } else { 0o640 };
            entries.push(entry(
                &path,
                "regular_file",
                mode,
                bytes.len(),
                Some(content.cid.to_string()),
            ));
            expected.insert(path, (mode, content.cid.to_string(), bytes));
        }
        entries.sort_by_key(|value| value["path"].as_str().unwrap().to_string());
        let committed = commit(
            &client,
            &nodes[1],
            &filesystem,
            0,
            Value::Array(entries),
            "fs001-commit",
        )
        .await?;
        wait_namespace_converged(
            &client,
            cluster,
            &filesystem,
            1,
            committed["root_cid"].as_str(),
        )
        .await?;
        for node in &nodes {
            let (status, checkout) = json_request(
                &client,
                node,
                "POST",
                "/v1/fs/checkout",
                json!({"filesystem":filesystem}),
            )
            .await?;
            ensure!(status == 200);
            let actual = checkout["entries"]
                .as_array()
                .context("filesystem entries missing")?;
            for (path, (mode, cid, bytes)) in &expected {
                let found = actual
                    .iter()
                    .find(|item| item["path"].as_str() == Some(path))
                    .context("generated path missing")?;
                ensure!(found["inode"]["mode"].as_u64() == Some(*mode as u64));
                ensure!(found["inode"]["content_cid"].as_str() == Some(cid.as_str()));
                ensure!(client.get_block(node, &cid.parse()?).await? == *bytes);
            }
        }
        let fault = cluster
            .backend
            .clone()
            .apply_fault(Fault::Kill {
                node: nodes[0].id.clone(),
            })
            .await?;
        let (status, checkout) = json_request(
            &client,
            &nodes[1],
            "POST",
            "/v1/fs/checkout",
            json!({"filesystem":filesystem}),
        )
        .await?;
        ensure!(
            status == 200
                && checkout["entries"]
                    .as_array()
                    .is_some_and(|items| items.len() == 8)
        );
        fault.heal().await?;
        context.run.events.record("invariant", json!({"invariant_id":"SAF-FS-001","invariant_result":"pass","details":{"filesystem":filesystem,"files":expected.len(),"directories":2,"exact_modes":true,"node_loss":true}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for FilesystemSharingScenario {
    fn id(&self) -> &'static str {
        "FS-002"
    }
    fn name(&self) -> &'static str {
        "filesystem-structural-sharing"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().unwrap();
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = create_fs(&client, &nodes[0], "fs-002").await?;
        let filesystem = created["namespace_id"].as_str().unwrap();
        wait_namespace_converged(
            &client,
            cluster,
            filesystem,
            0,
            created["root_cid"].as_str(),
        )
        .await?;
        let stable = client.put_block(&nodes[0], b"stable").await?;
        let changing = client.put_block(&nodes[0], b"version-one").await?;
        let first_entries = json!([
            entry("dir", "directory", 0o755, 0, None),
            entry(
                "dir/stable",
                "regular_file",
                0o644,
                6,
                Some(stable.cid.to_string())
            ),
            entry(
                "dir/changing",
                "regular_file",
                0o644,
                11,
                Some(changing.cid.to_string())
            )
        ]);
        commit(
            &client,
            &nodes[0],
            filesystem,
            0,
            first_entries,
            "fs002-first",
        )
        .await?;
        let (_, first) = json_request(
            &client,
            &nodes[1],
            "POST",
            "/v1/fs/checkout",
            json!({"filesystem":filesystem}),
        )
        .await?;
        let first_map = inode_map(&first)?;
        let changed = client.put_block(&nodes[2], b"version-two").await?;
        let second_entries = json!([
            entry("dir", "directory", 0o755, 0, None),
            entry(
                "dir/stable",
                "regular_file",
                0o644,
                6,
                Some(stable.cid.to_string())
            ),
            entry(
                "dir/changing",
                "regular_file",
                0o644,
                11,
                Some(changed.cid.to_string())
            ),
            entry(
                "new",
                "regular_file",
                0o600,
                6,
                Some(stable.cid.to_string())
            )
        ]);
        let second_commit = commit(
            &client,
            &nodes[2],
            filesystem,
            1,
            second_entries,
            "fs002-second",
        )
        .await?;
        let (_, second) = json_request(
            &client,
            &nodes[0],
            "POST",
            "/v1/fs/checkout",
            json!({"filesystem":filesystem}),
        )
        .await?;
        let second_map = inode_map(&second)?;
        ensure!(
            first_map["dir/stable"] == second_map["dir/stable"],
            "unchanged file inode CID changed"
        );
        ensure!(
            first_map["dir/changing"] != second_map["dir/changing"],
            "modified file inode CID was reused"
        );
        ensure!(first["filesystem_root_cid"] != second["filesystem_root_cid"]);
        wait_namespace_converged(
            &client,
            cluster,
            filesystem,
            2,
            second_commit["root_cid"].as_str(),
        )
        .await?;
        context.run.events.record("invariant", json!({"invariant_id":"SAF-FS-004","invariant_result":"pass","details":{"filesystem":filesystem,"unchanged_inode":first_map["dir/stable"],"old_root":first["filesystem_root_cid"],"new_root":second["filesystem_root_cid"]}}))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for FilesystemHistoryScenario {
    fn id(&self) -> &'static str {
        "FS-003"
    }
    fn name(&self) -> &'static str {
        "filesystem-history-rollback-clone"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }
    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().unwrap();
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();
        let created = create_fs(&client, &nodes[0], "fs-003").await?;
        let filesystem = created["namespace_id"].as_str().unwrap();
        wait_namespace_converged(
            &client,
            cluster,
            filesystem,
            0,
            created["root_cid"].as_str(),
        )
        .await?;
        let content = client.put_block(&nodes[0], b"history").await?;
        let first = commit(
            &client,
            &nodes[0],
            filesystem,
            0,
            json!([entry(
                "one",
                "regular_file",
                0o644,
                7,
                Some(content.cid.to_string())
            )]),
            "fs003-one",
        )
        .await?;
        let (_, checkout_one) = json_request(
            &client,
            &nodes[0],
            "POST",
            "/v1/fs/checkout",
            json!({"filesystem":filesystem}),
        )
        .await?;
        commit(
            &client,
            &nodes[1],
            filesystem,
            1,
            json!([
                entry(
                    "one",
                    "regular_file",
                    0o644,
                    7,
                    Some(content.cid.to_string())
                ),
                entry(
                    "two",
                    "regular_file",
                    0o600,
                    7,
                    Some(content.cid.to_string())
                )
            ]),
            "fs003-two",
        )
        .await?;
        let (status, diff) = json_request(
            &client,
            &nodes[2],
            "POST",
            "/v1/fs/diff",
            json!({"filesystem":filesystem,"revision_a":1,"revision_b":2}),
        )
        .await?;
        ensure!(
            status == 200
                && diff["changes"]
                    .as_array()
                    .is_some_and(|changes| changes.len() == 1 && changes[0]["path"] == "two")
        );
        let (rollback_status, rollback) = json_request(
            &client,
            &nodes[0],
            "POST",
            "/v1/fs/rollback",
            json!({"filesystem":filesystem,"revision":1,"request_id":"fs003-rollback"}),
        )
        .await?;
        ensure!(
            (200..300).contains(&rollback_status),
            "filesystem rollback failed with HTTP {rollback_status}: {rollback}"
        );
        ensure!(rollback["namespace_revision"].as_u64() == Some(3));
        let (_, after) = json_request(
            &client,
            &nodes[1],
            "POST",
            "/v1/fs/checkout",
            json!({"filesystem":filesystem}),
        )
        .await?;
        ensure!(
            after["entries"]
                .as_array()
                .is_some_and(|entries| entries.len() == 1)
        );
        let clone_created = create_fs(&client, &nodes[2], "fs-003-clone").await?;
        let clone = clone_created["namespace_id"].as_str().unwrap();
        wait_namespace_converged(
            &client,
            cluster,
            clone,
            0,
            clone_created["root_cid"].as_str(),
        )
        .await?;
        json_success_eventually(&client, &nodes[2], "POST", "/v1/fs/clone", json!({"filesystem":clone,"root_cid":checkout_one["filesystem_root_cid"],"request_id":"fs003-clone"})).await?;
        let (_, cloned) = json_request(
            &client,
            &nodes[0],
            "POST",
            "/v1/fs/checkout",
            json!({"filesystem":clone}),
        )
        .await?;
        ensure!(inode_map(&checkout_one)? == inode_map(&cloned)?);
        let (status, history) = json_request(
            &client,
            &nodes[2],
            "GET",
            &format!("/v1/fs/history/{}", encode_segment(filesystem)),
            Value::Null,
        )
        .await?;
        ensure!(
            status == 200
                && history["history"]
                    .as_object()
                    .is_some_and(|items| items.len() == 4)
        );
        context.run.events.record("invariant", json!({"invariant_id":"SAF-FS-001","invariant_result":"pass","details":{"filesystem":filesystem,"first_root":first["filesystem_root_cid"],"diff":1,"rollback_revision":3,"clone":clone}}))?;
        Ok(())
    }
}

fn inode_map(checkout: &Value) -> Result<BTreeMap<String, String>> {
    Ok(checkout["entries"]
        .as_array()
        .context("entries missing")?
        .iter()
        .map(|entry| {
            (
                entry["path"].as_str().unwrap().to_string(),
                entry["inode_cid"].as_str().unwrap().to_string(),
            )
        })
        .collect())
}

fn encode_segment(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
}
