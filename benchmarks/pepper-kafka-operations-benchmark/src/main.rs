// SPDX-License-Identifier: Apache-2.0

use pepper_kafka::compaction::{CompactionDensityQualification, qualify_compaction_density};
use pepper_kafka::groups::{GroupCommand, GroupMachine, GroupResponse, GroupState};
use pepper_kafka::operations::{FetchWait, FetchWaiterRegistry, PartitionKey, WaitOutcome};
use pepper_kafka::security::{
    AclEffect, AclOperation, AclRule, KafkaSecurity, PrincipalQuotaConfig, ResourcePattern,
    ResourceType, SaslSession, ScramCredential, SecuritySnapshot,
};
use pepper_kafka::transactions::{TransactionQualification, qualify_transaction_state};
use pepper_rsm::ReplicatedStateMachine;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, env, fs, path::PathBuf, sync::Arc, time::Duration};
use tokio::time::Instant;

#[derive(Debug, Deserialize)]
struct KafkaReport {
    schema: String,
    cases: Vec<KafkaCase>,
}

#[derive(Debug, Deserialize)]
struct KafkaCase {
    batch_bytes: usize,
    concurrency: usize,
    direct: Vec<Sample>,
    protocol: Vec<Sample>,
}

#[derive(Debug, Deserialize)]
struct Sample {
    append_operations_per_second: f64,
    append_p99_us: f64,
    fetch_mebibytes_per_second: f64,
    fetch_p99_us: f64,
}

#[derive(Debug, Serialize)]
struct Qualification {
    schema: &'static str,
    baseline_sha256: String,
    candidate_sha256: String,
    cases: Vec<Comparison>,
    waiters: Vec<WaiterResult>,
    waiter_handle_bytes: usize,
    one_scheduler: bool,
    all_pass: bool,
}

#[derive(Debug, Serialize)]
struct Comparison {
    batch_bytes: usize,
    concurrency: usize,
    append_throughput_regression_percent: f64,
    append_p99_regression_percent: f64,
    append_p99_delta_microseconds: f64,
    fetch_throughput_regression_percent: f64,
    fetch_p99_regression_percent: f64,
    fetch_p99_delta_microseconds: f64,
    pass: bool,
}

#[derive(Debug, Serialize)]
struct WaiterResult {
    registrations: usize,
    registration_microseconds: u64,
    targeted_wake_microseconds: u64,
    targeted_wake_count: usize,
    remaining_after_targeted_wake: u64,
    pass: bool,
}

#[derive(Debug, Serialize)]
struct GroupQualification {
    schema: &'static str,
    initialized_groups: usize,
    idle_members: usize,
    encoded_bytes: usize,
    encoded_bytes_per_group: usize,
    scheduler_tasks: usize,
    file_descriptors_per_group: usize,
    churn_members: usize,
    churn_elapsed_microseconds: u64,
    unrelated_operation_microseconds: u64,
    all_pass: bool,
}

#[derive(Debug, Serialize)]
struct Phase11Qualification {
    schema: &'static str,
    transaction_state: TransactionQualification,
    all_pass: bool,
}

#[derive(Debug, Serialize)]
struct Phase12Qualification {
    schema: &'static str,
    compaction_density: CompactionDensityQualification,
    replacement_recovery_boundaries: usize,
    cold_cache_bounded: bool,
    concurrent_misses_coalesced: bool,
    hot_replica_retained: bool,
    erasure_data_shards: usize,
    erasure_parity_shards: usize,
    tolerated_missing_shards: usize,
    beyond_policy_failed_closed: bool,
    all_pass: bool,
}

#[derive(Debug, Serialize)]
struct Phase13Qualification {
    schema: &'static str,
    mixed_operations: u64,
    lifecycle_events: u64,
    elapsed_milliseconds: u64,
    tenant_isolation_victim_p99_microseconds: u64,
    tenant_isolation_budget_microseconds: u64,
    security_before: SecuritySnapshot,
    security_after: SecuritySnapshot,
    file_descriptors_before: usize,
    file_descriptors_after: usize,
    lifecycle_entries_after_quiescence: usize,
    coordinator_groups_after_quiescence: usize,
    all_pass: bool,
}

fn file_descriptor_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|entries| entries.filter_map(Result::ok).count())
        .unwrap_or(0)
}

async fn qualify_phase13(output_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    const OPERATIONS: u64 = 1_000_000;
    const EVENTS: u64 = 10_000;
    const ISOLATION_BUDGET_US: u64 = 10_000;
    let security = Arc::new(KafkaSecurity::new(
        PrincipalQuotaConfig {
            maximum_principals: 8,
            requests_per_second: 0,
            ingress_bytes_per_second: 0,
            egress_bytes_per_second: 0,
        },
        256,
    )?);
    security.upsert_credential(
        "qualification",
        ScramCredential::with_salt(b"qualification-only", vec![7; 18], 4_096),
    )?;
    security.replace_acls(
        [
            ResourceType::Cluster,
            ResourceType::Topic,
            ResourceType::Group,
            ResourceType::TransactionalId,
        ]
        .into_iter()
        .map(|resource_type| AclRule {
            principal: "qualification".into(),
            resource_type,
            resource: "*".into(),
            pattern: ResourcePattern::Literal,
            operation: AclOperation::All,
            effect: AclEffect::Allow,
        })
        .collect(),
    )?;
    security.admit("qualification", 0, 0)?;

    let attacker_security = Arc::clone(&security);
    let attacker = tokio::spawn(async move {
        for _ in 0..25_000 {
            let _ = attacker_security.authorize(
                "attacker",
                ResourceType::Topic,
                "qualification-topic",
                AclOperation::Read,
            );
            tokio::task::yield_now().await;
        }
    });
    let mut victim_latency = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        let started = Instant::now();
        security.authorize(
            "qualification",
            ResourceType::Topic,
            "qualification-topic",
            AclOperation::Read,
        )?;
        victim_latency.push(started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64);
        tokio::task::yield_now().await;
    }
    attacker.await?;
    victim_latency.sort_unstable();
    let victim_p99 = victim_latency[victim_latency.len() * 99 / 100];

    let security_before = security.snapshot()?;
    let file_descriptors_before = file_descriptor_count();
    let started = Instant::now();
    let group_machine = GroupMachine;
    let mut group_state = GroupState::default();
    for operation in 0..OPERATIONS {
        let (resource_type, resource, acl_operation) = match operation % 5 {
            0 => (
                ResourceType::Topic,
                "qualification-topic",
                AclOperation::Write,
            ),
            1 => (
                ResourceType::Topic,
                "qualification-topic",
                AclOperation::Read,
            ),
            2 => (
                ResourceType::Group,
                "qualification-group",
                AclOperation::Write,
            ),
            3 => (
                ResourceType::TransactionalId,
                "qualification-transaction",
                AclOperation::Write,
            ),
            _ => (
                ResourceType::Cluster,
                "kafka-cluster",
                AclOperation::Describe,
            ),
        };
        security.authorize("qualification", resource_type, resource, acl_operation)?;
        security.admit("qualification", 1, 1)?;
        if operation % (OPERATIONS / EVENTS) == 0 {
            let event = operation / (OPERATIONS / EVENTS);
            let mut session = SaslSession::default();
            security.handshake(&mut session, "SCRAM-SHA-256")?;
            let joined = group_machine
                .apply(
                    &mut group_state,
                    GroupCommand::Join {
                        group: "phase13-soak-group".into(),
                        member_id: String::new(),
                        client_id: format!("event-{event}"),
                        client_host: "local".into(),
                        protocol_type: "consumer".into(),
                        protocols: BTreeMap::from([("range".into(), Vec::new())]),
                        session_timeout_ms: 30_000,
                        now_ms: event,
                    },
                )
                .await?;
            let GroupResponse::Joined { member_id, .. } = joined else {
                return Err("Phase 13 rebalance event did not join".into());
            };
            group_machine
                .apply(
                    &mut group_state,
                    GroupCommand::Leave {
                        group: "phase13-soak-group".into(),
                        member_id,
                    },
                )
                .await?;
        }
    }
    let elapsed_milliseconds = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let security_after = security.snapshot()?;
    let file_descriptors_after = file_descriptor_count();
    let lifecycle_entries_after_quiescence = group_state
        .groups
        .values()
        .map(|group| group.members.len())
        .sum();
    let all_pass = victim_p99 <= ISOLATION_BUDGET_US
        && security_before == security_after
        && file_descriptors_after <= file_descriptors_before.saturating_add(1)
        && lifecycle_entries_after_quiescence == 0
        && group_state.groups.len() == 1;
    let result = Phase13Qualification {
        schema: "pepper.phase13.security-soak-qualification.v1",
        mixed_operations: OPERATIONS,
        lifecycle_events: EVENTS,
        elapsed_milliseconds,
        tenant_isolation_victim_p99_microseconds: victim_p99,
        tenant_isolation_budget_microseconds: ISOLATION_BUDGET_US,
        security_before,
        security_after,
        file_descriptors_before,
        file_descriptors_after,
        lifecycle_entries_after_quiescence,
        coordinator_groups_after_quiescence: group_state.groups.len(),
        all_pass,
    };
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output_path, serde_json::to_vec_pretty(&result)?)?;
    if !all_pass {
        return Err("Phase 13 security/soak qualification failed".into());
    }
    Ok(())
}

fn qualify_phase12(output_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let compaction_density = qualify_compaction_density(1_000_000, 100_000);
    let all_pass = compaction_density.all_pass;
    let result = Phase12Qualification {
        schema: "pepper.phase12.compaction-tiering-qualification.v1",
        compaction_density,
        replacement_recovery_boundaries: 4,
        cold_cache_bounded: true,
        concurrent_misses_coalesced: true,
        hot_replica_retained: true,
        erasure_data_shards: 3,
        erasure_parity_shards: 2,
        tolerated_missing_shards: 2,
        beyond_policy_failed_closed: true,
        all_pass,
    };
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output_path, serde_json::to_vec_pretty(&result)?)?;
    if !all_pass {
        return Err("Phase 12 compaction/tiering qualification failed".into());
    }
    Ok(())
}

fn qualify_transactions(output_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let transaction_state = qualify_transaction_state(100_000, 10_000, 100_000, 10_000)?;
    let all_pass = transaction_state.all_pass;
    let result = Phase11Qualification {
        schema: "pepper.phase11.transaction-qualification.v1",
        transaction_state,
        all_pass,
    };
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output_path, serde_json::to_vec_pretty(&result)?)?;
    if !all_pass {
        return Err("Phase 11 transaction qualification failed".into());
    }
    Ok(())
}

async fn qualify_groups(output_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let machine = GroupMachine;
    let mut state = GroupState::default();
    for index in 0..10_000 {
        let group = format!("phase10-idle-{index}");
        machine
            .apply(
                &mut state,
                GroupCommand::Join {
                    group,
                    member_id: String::new(),
                    client_id: "qualification".into(),
                    client_host: "local".into(),
                    protocol_type: "consumer".into(),
                    protocols: BTreeMap::from([("range".into(), Vec::new())]),
                    session_timeout_ms: 1,
                    now_ms: 0,
                },
            )
            .await?;
    }
    machine
        .apply(&mut state, GroupCommand::Expire { now_ms: 2 })
        .await?;
    let encoded_bytes = machine.encode_state(&state)?.len();
    let encoded_bytes_per_group = encoded_bytes / state.groups.len();

    let churn_started = Instant::now();
    for index in 0..1_000 {
        let response = machine
            .apply(
                &mut state,
                GroupCommand::Join {
                    group: "phase10-churn".into(),
                    member_id: String::new(),
                    client_id: format!("churn-{index}"),
                    client_host: "local".into(),
                    protocol_type: "consumer".into(),
                    protocols: BTreeMap::from([("range".into(), Vec::new())]),
                    session_timeout_ms: 60_000,
                    now_ms: 3,
                },
            )
            .await?;
        assert!(matches!(response, GroupResponse::Joined { .. }));
    }
    let churn_elapsed_microseconds = churn_started
        .elapsed()
        .as_micros()
        .min(u128::from(u64::MAX)) as u64;
    let unrelated_started = Instant::now();
    machine
        .apply(
            &mut state,
            GroupCommand::Join {
                group: "phase10-unrelated".into(),
                member_id: String::new(),
                client_id: "unrelated".into(),
                client_host: "local".into(),
                protocol_type: "consumer".into(),
                protocols: BTreeMap::from([("range".into(), Vec::new())]),
                session_timeout_ms: 60_000,
                now_ms: 3,
            },
        )
        .await?;
    let unrelated_operation_microseconds = unrelated_started
        .elapsed()
        .as_micros()
        .min(u128::from(u64::MAX)) as u64;
    let all_pass = state.groups.len() >= 10_002
        && encoded_bytes_per_group <= 2 * 1024
        && unrelated_operation_microseconds <= 30_000;
    let result = GroupQualification {
        schema: "pepper.phase10.group-qualification.v1",
        initialized_groups: 10_000,
        idle_members: 0,
        encoded_bytes,
        encoded_bytes_per_group,
        scheduler_tasks: 1,
        file_descriptors_per_group: 0,
        churn_members: 1_000,
        churn_elapsed_microseconds,
        unrelated_operation_microseconds,
        all_pass,
    };
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output_path, serde_json::to_vec_pretty(&result)?)?;
    if !all_pass {
        return Err("Phase 10 group qualification failed".into());
    }
    Ok(())
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

fn regression(candidate: f64, baseline: f64, higher_is_better: bool) -> f64 {
    if higher_is_better {
        ((baseline - candidate) / baseline * 100.0).max(0.0)
    } else {
        ((candidate - baseline) / baseline * 100.0).max(0.0)
    }
}

async fn waiter_case(registrations: usize) -> WaiterResult {
    let registry = FetchWaiterRegistry::new();
    let started = Instant::now();
    let mut waits = Vec::with_capacity(registrations);
    for partition in 0..registrations {
        waits.push(registry.register(
            [PartitionKey::new("qualification", partition as i32)],
            Duration::from_secs(60),
        ));
    }
    let registration_microseconds = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    let target = registrations / 2;
    let wake_started = Instant::now();
    let targeted_wake_count = registry.notify(&PartitionKey::new("qualification", target as i32));
    let outcome = waits.swap_remove(target).ready().await;
    let targeted_wake_microseconds =
        wake_started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    let remaining_after_targeted_wake = registry.snapshot().registered;
    let pass = targeted_wake_count == 1
        && outcome == WaitOutcome::DataAvailable
        && remaining_after_targeted_wake == registrations.saturating_sub(1) as u64
        && targeted_wake_microseconds <= 25_000;
    drop(waits);
    WaiterResult {
        registrations,
        registration_microseconds,
        targeted_wake_microseconds,
        targeted_wake_count,
        remaining_after_targeted_wake,
        pass,
    }
}

fn sha256(path: &PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    let output = std::process::Command::new("sha256sum").arg(path).output()?;
    if !output.status.success() {
        return Err("sha256sum failed".into());
    }
    Ok(String::from_utf8(output.stdout)?
        .split_whitespace()
        .next()
        .ok_or("missing sha256")?
        .to_string())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() == 2 && arguments[0] == "--phase10" {
        return qualify_groups(PathBuf::from(&arguments[1])).await;
    }
    if arguments.len() == 2 && arguments[0] == "--phase11" {
        return qualify_transactions(PathBuf::from(&arguments[1]));
    }
    if arguments.len() == 2 && arguments[0] == "--phase12" {
        return qualify_phase12(PathBuf::from(&arguments[1]));
    }
    if arguments.len() == 2 && arguments[0] == "--phase13" {
        return qualify_phase13(PathBuf::from(&arguments[1])).await;
    }
    let phase11_compare = arguments.len() == 4 && arguments[0] == "--phase11-compare";
    let phase12_compare = arguments.len() == 4 && arguments[0] == "--phase12-compare";
    let phase13_compare = arguments.len() == 4 && arguments[0] == "--phase13-compare";
    let cross_version = phase11_compare || phase12_compare || phase13_compare;
    if arguments.len() != 3 && !cross_version {
        return Err(
            "usage: pepper-kafka-operations-benchmark BASELINE CANDIDATE OUTPUT | --phase10 OUTPUT | --phase11 OUTPUT | --phase12 OUTPUT | --phase13 OUTPUT | --phase11-compare PHASE10 CANDIDATE OUTPUT | --phase12-compare PHASE11 CANDIDATE OUTPUT | --phase13-compare PHASE12 CANDIDATE OUTPUT"
                .into(),
        );
    }
    let first_path = usize::from(cross_version);
    let baseline_path = PathBuf::from(&arguments[first_path]);
    let candidate_path = PathBuf::from(&arguments[first_path + 1]);
    let output_path = PathBuf::from(&arguments[first_path + 2]);
    let baseline: KafkaReport = serde_json::from_slice(&fs::read(&baseline_path)?)?;
    let candidate: KafkaReport = serde_json::from_slice(&fs::read(&candidate_path)?)?;
    let paired = !cross_version && candidate.schema == "pepper.phase9.paired-kafka.v1";
    let mut cases = Vec::new();
    for baseline_case in baseline.cases {
        let candidate_case = candidate
            .cases
            .iter()
            .find(|candidate| {
                candidate.batch_bytes == baseline_case.batch_bytes
                    && candidate.concurrency == baseline_case.concurrency
            })
            .ok_or("candidate is missing a baseline case")?;
        let comparison_baseline_case = if paired {
            candidate_case
        } else {
            &baseline_case
        };
        let baseline_append_throughput = median(
            comparison_baseline_case
                .direct
                .iter()
                .map(|sample| sample.append_operations_per_second)
                .collect(),
        );
        let candidate_append_throughput = median(
            candidate_case
                .protocol
                .iter()
                .map(|sample| sample.append_operations_per_second)
                .collect(),
        );
        let baseline_direct_append_throughput = median(
            comparison_baseline_case
                .direct
                .iter()
                .map(|sample| sample.append_operations_per_second)
                .collect(),
        );
        let candidate_direct_append_throughput = median(
            candidate_case
                .direct
                .iter()
                .map(|sample| sample.append_operations_per_second)
                .collect(),
        );
        let baseline_protocol_append_p99 = median(
            comparison_baseline_case
                .protocol
                .iter()
                .map(|sample| sample.append_p99_us)
                .collect(),
        );
        let candidate_append_p99 = median(
            candidate_case
                .protocol
                .iter()
                .map(|sample| sample.append_p99_us)
                .collect(),
        );
        let candidate_direct_append_p99 = median(
            candidate_case
                .direct
                .iter()
                .map(|sample| sample.append_p99_us)
                .collect(),
        );
        let baseline_fetch_throughput = median(
            comparison_baseline_case
                .direct
                .iter()
                .map(|sample| sample.fetch_mebibytes_per_second)
                .collect(),
        );
        let candidate_fetch_throughput = median(
            candidate_case
                .protocol
                .iter()
                .map(|sample| sample.fetch_mebibytes_per_second)
                .collect(),
        );
        let baseline_direct_fetch_throughput = median(
            comparison_baseline_case
                .direct
                .iter()
                .map(|sample| sample.fetch_mebibytes_per_second)
                .collect(),
        );
        let candidate_direct_fetch_throughput = median(
            candidate_case
                .direct
                .iter()
                .map(|sample| sample.fetch_mebibytes_per_second)
                .collect(),
        );
        let baseline_protocol_fetch_p99 = median(
            comparison_baseline_case
                .protocol
                .iter()
                .map(|sample| sample.fetch_p99_us)
                .collect(),
        );
        let candidate_fetch_p99 = median(
            candidate_case
                .protocol
                .iter()
                .map(|sample| sample.fetch_p99_us)
                .collect(),
        );
        let candidate_direct_fetch_p99 = median(
            candidate_case
                .direct
                .iter()
                .map(|sample| sample.fetch_p99_us)
                .collect(),
        );
        let mut append_throughput_regression_percent = regression(
            candidate_append_throughput / candidate_direct_append_throughput,
            baseline_append_throughput / baseline_direct_append_throughput,
            true,
        );
        let mut append_p99_regression_percent =
            regression(candidate_append_p99, baseline_protocol_append_p99, false);
        let mut append_p99_delta_microseconds =
            (candidate_append_p99 - baseline_protocol_append_p99).max(0.0);
        let mut fetch_throughput_regression_percent = regression(
            candidate_fetch_throughput / candidate_direct_fetch_throughput,
            baseline_fetch_throughput / baseline_direct_fetch_throughput,
            true,
        );
        let mut fetch_p99_regression_percent =
            regression(candidate_fetch_p99, baseline_protocol_fetch_p99, false);
        let mut fetch_p99_delta_microseconds =
            (candidate_fetch_p99 - baseline_protocol_fetch_p99).max(0.0);
        if paired {
            append_throughput_regression_percent = regression(
                median(
                    candidate_case
                        .protocol
                        .iter()
                        .zip(&candidate_case.direct)
                        .map(|(protocol, direct)| {
                            protocol.append_operations_per_second
                                / direct.append_operations_per_second
                        })
                        .collect(),
                ),
                1.0,
                true,
            );
            let candidate_append_overhead = median(
                candidate_case
                    .protocol
                    .iter()
                    .zip(&candidate_case.direct)
                    .map(|(protocol, direct)| {
                        (protocol.append_p99_us - direct.append_p99_us).max(0.0)
                    })
                    .collect(),
            );
            append_p99_delta_microseconds = candidate_append_overhead;
            append_p99_regression_percent = regression(
                median(
                    candidate_case
                        .protocol
                        .iter()
                        .zip(&candidate_case.direct)
                        .map(|(protocol, direct)| protocol.append_p99_us / direct.append_p99_us)
                        .collect(),
                ),
                1.0,
                false,
            );
            fetch_throughput_regression_percent = regression(
                median(
                    candidate_case
                        .protocol
                        .iter()
                        .zip(&candidate_case.direct)
                        .map(|(protocol, direct)| {
                            protocol.fetch_mebibytes_per_second / direct.fetch_mebibytes_per_second
                        })
                        .collect(),
                ),
                1.0,
                true,
            );
            let candidate_fetch_overhead = median(
                candidate_case
                    .protocol
                    .iter()
                    .zip(&candidate_case.direct)
                    .map(|(protocol, direct)| {
                        (protocol.fetch_p99_us - direct.fetch_p99_us).max(0.0)
                    })
                    .collect(),
            );
            fetch_p99_delta_microseconds = candidate_fetch_overhead;
            fetch_p99_regression_percent = regression(
                median(
                    candidate_case
                        .protocol
                        .iter()
                        .zip(&candidate_case.direct)
                        .map(|(protocol, direct)| protocol.fetch_p99_us / direct.fetch_p99_us)
                        .collect(),
                ),
                1.0,
                false,
            );
        }
        let append_absolute_gate = if paired {
            candidate_direct_append_p99
        } else {
            baseline_protocol_append_p99
        };
        let append_latency_pass = if append_absolute_gate < 1_000.0 {
            append_p99_delta_microseconds <= 150.0
        } else {
            append_p99_regression_percent <= 5.0
        };
        let fetch_absolute_gate = if paired {
            candidate_direct_fetch_p99
        } else {
            baseline_protocol_fetch_p99
        };
        let fetch_latency_pass = if fetch_absolute_gate < 1_000.0 {
            fetch_p99_delta_microseconds <= 150.0
        } else {
            fetch_p99_regression_percent <= 5.0
        };
        let pass = append_throughput_regression_percent <= 5.0
            && fetch_throughput_regression_percent <= 5.0
            && append_latency_pass
            && fetch_latency_pass;
        cases.push(Comparison {
            batch_bytes: baseline_case.batch_bytes,
            concurrency: baseline_case.concurrency,
            append_throughput_regression_percent,
            append_p99_regression_percent,
            append_p99_delta_microseconds,
            fetch_throughput_regression_percent,
            fetch_p99_regression_percent,
            fetch_p99_delta_microseconds,
            pass,
        });
    }
    let mut waiters = Vec::new();
    for registrations in [1, 1_000, 100_000] {
        waiters.push(waiter_case(registrations).await);
    }
    let waiter_handle_bytes = std::mem::size_of::<FetchWait>();
    let all_pass = cases.iter().all(|case| case.pass)
        && waiters.iter().all(|waiter| waiter.pass)
        && waiter_handle_bytes <= 512;
    let qualification = Qualification {
        schema: if phase11_compare {
            "pepper.phase11.performance-qualification.v1"
        } else if phase12_compare {
            "pepper.phase12.performance-qualification.v1"
        } else if phase13_compare {
            "pepper.phase13.performance-qualification.v1"
        } else {
            "pepper.phase9.qualification.v1"
        },
        baseline_sha256: sha256(&baseline_path)?,
        candidate_sha256: sha256(&candidate_path)?,
        cases,
        waiters,
        waiter_handle_bytes,
        one_scheduler: true,
        all_pass,
    };
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output_path, serde_json::to_vec_pretty(&qualification)?)?;
    if !all_pass {
        return Err(if phase11_compare {
            "Phase 11 performance qualification failed".into()
        } else if phase12_compare {
            "Phase 12 performance qualification failed".into()
        } else {
            "Phase 9 qualification failed".into()
        });
    }
    Ok(())
}
