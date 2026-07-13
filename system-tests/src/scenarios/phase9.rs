// SPDX-License-Identifier: Apache-2.0

use super::{
    bootstrap_three_nodes, json_request, json_success_eventually,
    namespace_suite::{create_namespace, put_value},
};
use crate::harness::{
    backend::ExecRequest,
    client::PepperClient,
    cluster::ClusterSpec,
    context::ScenarioContext,
    scenario::{Scenario, ScenarioRequirements},
    wait::eventually,
};
use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use pepper_types::DurabilityReceipt;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

pub struct SoakQualificationScenario;
pub struct WanQualificationScenario;
pub struct KvmFirecrackerScenario;

#[derive(Debug, Serialize)]
struct ResourceSample {
    elapsed_seconds: u64,
    node: String,
    rss_bytes: u64,
    open_fds: u64,
    storage_bytes: u64,
}

#[derive(Debug, Serialize)]
struct GrowthAnalysis {
    node: String,
    elapsed_seconds: u64,
    rss_growth_bytes: i128,
    fd_growth: i128,
    storage_growth_bytes: i128,
    rss_slope_bytes_per_minute: f64,
    fd_slope_per_minute: f64,
    storage_slope_bytes_per_minute: f64,
}

#[async_trait]
impl Scenario for SoakQualificationScenario {
    fn id(&self) -> &'static str {
        "SOAK-001"
    }
    fn name(&self) -> &'static str {
        "fixed-kernel-growth-soak"
    }
    fn requirements(&self) -> ScenarioRequirements {
        ScenarioRequirements {
            minimum_nodes: 3,
            requires_docker: true,
            requires_fixed_kernel: true,
            ..Default::default()
        }
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let duration = context
            .run
            .duration_seconds
            .context("SOAK-001 requires --duration-seconds")?;
        ensure!(duration >= 10, "soak duration must be at least 10 seconds");
        let expected_kernel = context
            .run
            .expected_kernel
            .clone()
            .context("SOAK-001 requires --expected-kernel")?;
        let client = bootstrap_three_nodes(context).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let first = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let kernel = exec_text(context, &first.id, vec!["uname", "-r"]).await?;
        ensure!(
            kernel.trim() == expected_kernel,
            "kernel drift: expected {expected_kernel}, observed {}",
            kernel.trim()
        );
        context.run.artifacts.write_json(
            "observations/kernel-lock.json",
            &json!({
                "schema_version":1,"expected":expected_kernel,"observed":kernel.trim(),
                "image_digest":context.run.backend.image_digest
            }),
        )?;

        let created = create_namespace(&client, &first, "soak-001").await?;
        let namespace = created["namespace_id"]
            .as_str()
            .context("namespace ID missing")?
            .to_string();
        let started = Instant::now();
        let interval = Duration::from_secs((duration / 120).clamp(1, 30));
        let mut samples = Vec::new();
        let mut iteration = 0_u64;
        while started.elapsed() < Duration::from_secs(duration) {
            let payload = format!("pepper-soak-payload-{:02}", iteration % 32)
                .repeat(1024)
                .into_bytes();
            let receipt = client.put_block(&first, &payload).await?;
            let ingress = cluster
                .node(&cluster.spec.nodes[(iteration as usize) % cluster.spec.nodes.len()].id)?
                .clone();
            put_value(
                &client,
                &ingress,
                &namespace,
                "active",
                &receipt.cid.to_string(),
                &format!("soak-{iteration}"),
            )
            .await?;
            let fetched = client.get_block(&ingress, &receipt.cid).await?;
            ensure!(fetched == payload, "soak block read differed from write");
            if iteration > 0 && iteration.is_multiple_of(20) {
                let restart = &cluster.spec.nodes[1 + (iteration as usize / 20) % 2].id;
                cluster
                    .backend
                    .restart(restart, crate::RestartPolicy::PreserveAll)
                    .await?;
                let runtime = cluster.node(restart)?.clone();
                eventually(
                    "restarted soak node ready",
                    Duration::from_secs(30),
                    Duration::from_millis(250),
                    || async { Ok(client.ready(&runtime).await?.then_some(())) },
                )
                .await?;
            }
            for node in &cluster.spec.nodes {
                samples
                    .push(sample_resources(context, &node.id, started.elapsed().as_secs()).await?);
            }
            iteration += 1;
            tokio::time::sleep(
                interval.min(Duration::from_secs(duration).saturating_sub(started.elapsed())),
            )
            .await;
        }
        ensure!(iteration >= 3, "soak collected too few operation cycles");
        let growth = analyze_growth(&samples)?;
        context
            .run
            .artifacts
            .write_json("observations/resource-samples.json", &samples)?;
        context
            .run
            .artifacts
            .write_json("observations/growth-analysis.json", &growth)?;
        context.run.artifacts.write_json("observations/soak-report.json", &json!({
            "schema_version":1,"duration_seconds":started.elapsed().as_secs(),"iterations":iteration,
            "samples":samples.len(),"result":"passed","limits":{"rss_growth_bytes":134217728_u64,"fd_growth":64_u64,"storage_growth_bytes":536870912_u64}
        }))?;
        Ok(())
    }
}

async fn sample_resources(
    context: &ScenarioContext,
    node: &crate::NodeId,
    elapsed: u64,
) -> Result<ResourceSample> {
    let output = exec_text(context, node, vec![
        "sh", "-c", "awk '/VmRSS:/{print $2*1024}' /proc/1/status; find /proc/1/fd -mindepth 1 -maxdepth 1 2>/dev/null | wc -l; du -sb /var/lib/pepper/storage 2>/dev/null | awk '{print $1}'"
    ]).await?;
    let values = output
        .lines()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        values.len() == 3,
        "resource probe returned malformed output: {output:?}"
    );
    Ok(ResourceSample {
        elapsed_seconds: elapsed,
        node: node.to_string(),
        rss_bytes: values[0],
        open_fds: values[1],
        storage_bytes: values[2],
    })
}

fn analyze_growth(samples: &[ResourceSample]) -> Result<Vec<GrowthAnalysis>> {
    let mut nodes = std::collections::BTreeMap::<&str, Vec<&ResourceSample>>::new();
    for sample in samples {
        nodes.entry(&sample.node).or_default().push(sample);
    }
    let mut analysis = Vec::new();
    for (node, values) in nodes {
        ensure!(
            values.len() >= 3,
            "node {node} has fewer than three resource samples"
        );
        let baseline = values[values.len().min(3) - 1];
        let final_sample = values.last().expect("nonempty");
        ensure!(
            final_sample.rss_bytes <= baseline.rss_bytes.saturating_add(128 * 1024 * 1024),
            "node {node} RSS grew beyond 128 MiB: {} -> {}",
            baseline.rss_bytes,
            final_sample.rss_bytes
        );
        ensure!(
            final_sample.open_fds <= baseline.open_fds.saturating_add(64),
            "node {node} open descriptors grew beyond 64: {} -> {}",
            baseline.open_fds,
            final_sample.open_fds
        );
        ensure!(
            final_sample.storage_bytes <= baseline.storage_bytes.saturating_add(512 * 1024 * 1024),
            "node {node} storage grew beyond the 512 MiB soak budget"
        );
        let elapsed = final_sample
            .elapsed_seconds
            .saturating_sub(values.first().expect("nonempty").elapsed_seconds);
        let rss_slope = regression_slope(&values, |sample| sample.rss_bytes);
        let fd_slope = regression_slope(&values, |sample| sample.open_fds);
        let storage_slope = regression_slope(&values, |sample| sample.storage_bytes);
        if elapsed >= 300 {
            ensure!(
                rss_slope <= 2.0 * 1024.0 * 1024.0,
                "node {node} sustained RSS slope exceeds 2 MiB/min: {rss_slope:.1}"
            );
            ensure!(
                fd_slope <= 1.0,
                "node {node} sustained descriptor slope exceeds 1/min: {fd_slope:.3}"
            );
            ensure!(
                storage_slope <= 8.0 * 1024.0 * 1024.0,
                "node {node} sustained storage slope exceeds 8 MiB/min: {storage_slope:.1}"
            );
        }
        analysis.push(GrowthAnalysis {
            node: node.to_string(),
            elapsed_seconds: elapsed,
            rss_growth_bytes: i128::from(final_sample.rss_bytes) - i128::from(baseline.rss_bytes),
            fd_growth: i128::from(final_sample.open_fds) - i128::from(baseline.open_fds),
            storage_growth_bytes: i128::from(final_sample.storage_bytes)
                - i128::from(baseline.storage_bytes),
            rss_slope_bytes_per_minute: rss_slope,
            fd_slope_per_minute: fd_slope,
            storage_slope_bytes_per_minute: storage_slope,
        });
    }
    Ok(analysis)
}

fn regression_slope<F>(values: &[&ResourceSample], field: F) -> f64
where
    F: Fn(&ResourceSample) -> u64,
{
    let count = values.len() as f64;
    let mean_x = values
        .iter()
        .map(|sample| sample.elapsed_seconds as f64 / 60.0)
        .sum::<f64>()
        / count;
    let mean_y = values
        .iter()
        .map(|sample| field(sample) as f64)
        .sum::<f64>()
        / count;
    let numerator = values
        .iter()
        .map(|sample| {
            let x = sample.elapsed_seconds as f64 / 60.0;
            (x - mean_x) * (field(sample) as f64 - mean_y)
        })
        .sum::<f64>();
    let denominator = values
        .iter()
        .map(|sample| {
            let x = sample.elapsed_seconds as f64 / 60.0;
            (x - mean_x).powi(2)
        })
        .sum::<f64>();
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

async fn exec_text(
    context: &ScenarioContext,
    node: &crate::NodeId,
    command: Vec<&str>,
) -> Result<String> {
    let result = context
        .backend
        .exec(
            node,
            ExecRequest {
                command: command.into_iter().map(str::to_string).collect(),
                stdin: Vec::new(),
                timeout_seconds: 15,
                max_output_bytes: 64 * 1024,
            },
        )
        .await?;
    ensure!(
        result.exit_code == 0,
        "probe command failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}

#[async_trait]
impl Scenario for WanQualificationScenario {
    fn id(&self) -> &'static str {
        "WAN-001"
    }
    fn name(&self) -> &'static str {
        "tailscale-direct-wan"
    }
    fn requirements(&self) -> ScenarioRequirements {
        ScenarioRequirements {
            minimum_nodes: 3,
            requires_wan: true,
            ..Default::default()
        }
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let requested = ClusterSpec::three_node(context.run.seed);
        let cluster = context
            .backend
            .clone()
            .provision(requested, &context.run)
            .await?;
        context.cluster = Some(cluster);
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let client = PepperClient::new(context.run.events.clone(), context.backend.clone());
        let failure_domains = cluster
            .spec
            .nodes
            .iter()
            .map(|node| &node.failure_domain)
            .collect::<std::collections::BTreeSet<_>>();
        ensure!(
            failure_domains.len() >= 3,
            "WAN qualification requires three distinct failure domains"
        );
        for node in cluster.nodes.values() {
            eventually(
                &format!("WAN node {} ready", node.id),
                Duration::from_secs(60),
                Duration::from_secs(1),
                || async {
                    Ok((client.health(node).await? && client.ready(node).await?).then_some(()))
                },
            )
            .await?;
            eventually(
                &format!("WAN node {} peer convergence", node.id),
                Duration::from_secs(60),
                Duration::from_secs(1),
                || async { Ok((client.peer_count(node).await? >= 2).then_some(())) },
            )
            .await?;
        }
        let first = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        let second = cluster.node(&cluster.spec.nodes[1].id)?.clone();
        let mut latencies = Vec::new();
        for iteration in 0..8_u64 {
            let payload = format!("pepper-wan-qualification-{iteration}")
                .repeat(4096)
                .into_bytes();
            let began = Instant::now();
            let receipt = client.put_block(&first, &payload).await?;
            let fetched = client.get_block(&second, &receipt.cid).await?;
            ensure!(
                fetched == payload,
                "WAN cross-node read differed from write"
            );
            latencies.push(began.elapsed().as_millis() as u64);
        }
        let created = create_namespace(&client, &first, "wan-001").await?;
        let namespace = created["namespace_id"]
            .as_str()
            .context("namespace ID missing")?;
        let receipt = client.put_block(&second, b"wan-namespace-value").await?;
        put_value(
            &client,
            &second,
            namespace,
            "wan-key",
            &receipt.cid.to_string(),
            "wan-put-1",
        )
        .await?;
        let value = json_success_eventually(
            &client,
            &first,
            "GET",
            &format!(
                "/v1/kv/get?namespace={namespace}&key_hex={}",
                hex::encode("wan-key")
            ),
            Value::Null,
        )
        .await?;
        ensure!(
            value["value_cid"].as_str() == Some(receipt.cid.to_string().as_str()),
            "WAN linearizable namespace read returned the wrong value"
        );
        latencies.sort_unstable();
        context.run.artifacts.write_json("observations/wan-report.json", &json!({
            "schema_version":1,"backend":context.run.backend.name,"operations":latencies.len(),
            "latency_ms":{"p50":latencies[latencies.len()/2],"p95":latencies[(latencies.len()*95/100).min(latencies.len()-1)],"max":latencies.last()},
            "namespace_linearizable":true,"cross_node_content":true
        }))?;
        Ok(())
    }
}

#[async_trait]
impl Scenario for KvmFirecrackerScenario {
    fn id(&self) -> &'static str {
        "KVM-001"
    }
    fn name(&self) -> &'static str {
        "firecracker-rootfs-cancel"
    }
    fn requirements(&self) -> ScenarioRequirements {
        ScenarioRequirements {
            minimum_nodes: 1,
            requires_kvm: true,
            ..Default::default()
        }
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let rootfs = PathBuf::from(
            std::env::var_os("PEPPER_FIRECRACKER_ROOTFS_IMAGE")
                .context("PEPPER_FIRECRACKER_ROOTFS_IMAGE is required")?,
        );
        let metadata = std::fs::metadata(&rootfs)
            .with_context(|| format!("rootfs {} is unreadable", rootfs.display()))?;
        ensure!(
            metadata.len() > 0 && metadata.len() <= 512 * 1024 * 1024,
            "rootfs must be 1 byte to 512 MiB"
        );
        let mut spec = ClusterSpec::storage_cluster(context.run.seed, 1, 1, 4 * 1024 * 1024 * 1024);
        spec.nodes[0].compute_enabled = true;
        spec.nodes[0].consensus_enabled = false;
        spec.namespace_voter_count = None;
        let cluster = context
            .backend
            .clone()
            .provision(spec, &context.run)
            .await?;
        context.cluster = Some(cluster);
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let node = cluster.node(&cluster.spec.nodes[0].id)?.clone();
        cluster.backend.start(&node.id).await?;
        let client = PepperClient::new(context.run.events.clone(), context.backend.clone());
        eventually(
            "KVM agent ready",
            Duration::from_secs(30),
            Duration::from_millis(250),
            || async { Ok(client.ready(&node).await?.then_some(())) },
        )
        .await?;
        let rootfs_bytes = std::fs::read(&rootfs)?;
        let response = client
            .request(
                &node,
                "POST",
                "/v1/objects",
                Some("application/octet-stream"),
                rootfs_bytes,
                180,
            )
            .await?;
        ensure!(
            (200..300).contains(&response.status),
            "rootfs upload failed with HTTP {}",
            response.status
        );
        let receipt: DurabilityReceipt = serde_json::from_slice(&response.body)?;
        let completed = submit_compute(&client, &node, json!({
            "type":"pepper.compute_job","version":1,"runtime":"firecracker","rootfs_cid":receipt.cid,
            "command":["sh","-c","mkdir -p /output && echo firecracker-ok > /output/result.txt"],
            "outputs":[{"path":"output","name":"result"}],"resources":{"timeout_seconds":60}
        })).await?;
        let status = wait_compute(&client, &node, &completed).await?;
        ensure!(
            status["status"] == "succeeded",
            "Firecracker job failed: {status}"
        );
        ensure!(
            status["output_root_cid"].as_str().is_some(),
            "Firecracker job succeeded without a captured output root: {status}"
        );
        let cancel_id = submit_compute(&client, &node, json!({
            "type":"pepper.compute_job","version":1,"runtime":"firecracker","rootfs_cid":receipt.cid,
            "command":["sh","-c","sleep 60"],"resources":{"timeout_seconds":120}
        })).await?;
        tokio::time::sleep(Duration::from_secs(3)).await;
        let (cancel_status, canceled) = json_request(
            &client,
            &node,
            "POST",
            &format!("/v1/compute/jobs/{cancel_id}/cancel"),
            Value::Null,
        )
        .await?;
        ensure!(
            (200..300).contains(&cancel_status) && canceled["status"] == "canceled",
            "Firecracker cancellation failed: HTTP {cancel_status} {canceled}"
        );
        context.run.artifacts.write_json("observations/kvm-report.json", &json!({
            "schema_version":1,"rootfs_bytes":metadata.len(),"completed_job":completed,"canceled_job":cancel_id,"result":"passed"
        }))?;
        Ok(())
    }
}

async fn submit_compute(
    client: &PepperClient,
    node: &crate::harness::cluster::NodeRuntime,
    job: Value,
) -> Result<String> {
    let (status, response) = json_request(client, node, "POST", "/v1/compute/jobs", job).await?;
    ensure!(
        (200..300).contains(&status),
        "compute submit failed: HTTP {status} {response}"
    );
    Ok(response["job_id"]
        .as_str()
        .context("compute response omitted job_id")?
        .to_string())
}

async fn wait_compute(
    client: &PepperClient,
    node: &crate::harness::cluster::NodeRuntime,
    job: &str,
) -> Result<Value> {
    eventually(
        "Firecracker job completion",
        Duration::from_secs(90),
        Duration::from_millis(500),
        || async {
            let (status, response) = json_request(
                client,
                node,
                "GET",
                &format!("/v1/compute/jobs/{job}"),
                Value::Null,
            )
            .await?;
            if status != 200 {
                bail!("compute status returned HTTP {status}: {response}");
            }
            Ok(matches!(
                response["status"].as_str(),
                Some("succeeded" | "failed" | "canceled")
            )
            .then_some(response))
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(elapsed: u64, rss: u64, fds: u64, storage: u64) -> ResourceSample {
        ResourceSample {
            elapsed_seconds: elapsed,
            node: "node-1".into(),
            rss_bytes: rss,
            open_fds: fds,
            storage_bytes: storage,
        }
    }

    #[test]
    fn growth_analysis_accepts_bounded_plateau_and_rejects_leaks() {
        let bounded = vec![
            sample(0, 100, 10, 100),
            sample(300, 110, 11, 110),
            sample(600, 115, 11, 120),
        ];
        let report = analyze_growth(&bounded).unwrap();
        assert_eq!(report.len(), 1);
        let leaked = vec![
            sample(0, 100, 10, 100),
            sample(300, 200, 11, 110),
            sample(600, 200 * 1024 * 1024, 11, 120),
        ];
        assert!(analyze_growth(&leaked).is_err());
        let descriptors = vec![
            sample(0, 100, 10, 100),
            sample(300, 100, 20, 110),
            sample(600, 100, 100, 120),
        ];
        assert!(analyze_growth(&descriptors).is_err());
    }
}
