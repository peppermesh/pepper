// SPDX-License-Identifier: Apache-2.0

use crate::harness::{artifacts::RunArtifacts, events::EventRecorder};
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

pub const MAX_CONTINUOUS_SAMPLES: usize = 10_000;
pub const RETAINED_CONTINUOUS_SAMPLES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaObservation {
    pub node: String,
    pub namespace: String,
    pub epoch: u64,
    pub revision: u64,
    pub root: String,
    pub last_log_index: Option<u64>,
    pub commit_index: Option<u64>,
    pub applied_index: Option<u64>,
    pub local_raft_id: u64,
    pub local_voting: bool,
    pub voter_ids: BTreeSet<u64>,
    pub learner_ids: BTreeSet<u64>,
    pub replication_match: BTreeMap<u64, Option<u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurabilityObservation {
    pub cid: String,
    pub required: usize,
    pub verified_replicas: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcProtectionObservation {
    pub node: String,
    pub root: String,
    pub protected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentObservation {
    pub intent_id: String,
    pub status: String,
    pub age_seconds: u64,
    pub actionable: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContinuousSnapshot {
    pub sequence: u64,
    pub replicas: Vec<ReplicaObservation>,
    pub durability: Vec<DurabilityObservation>,
    pub gc_protection: Vec<GcProtectionObservation>,
    pub intents: Vec<IntentObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantViolation {
    pub invariant_id: String,
    pub message: String,
    pub snapshot_sequence: u64,
}

#[derive(Default)]
struct TemporalState {
    initial_voters: BTreeMap<(String, u64), BTreeSet<u64>>,
    caught_up_learners: BTreeSet<(String, u64, u64)>,
}

pub struct ContinuousChecker {
    events: Arc<EventRecorder>,
    max_pending_intent_age_seconds: u64,
    temporal: Mutex<TemporalState>,
    samples: Mutex<Vec<ContinuousSnapshot>>,
    total_samples: Mutex<usize>,
}

impl ContinuousChecker {
    pub fn new(events: Arc<EventRecorder>, max_pending_intent_age_seconds: u64) -> Self {
        Self {
            events,
            max_pending_intent_age_seconds,
            temporal: Mutex::new(TemporalState::default()),
            samples: Mutex::new(Vec::new()),
            total_samples: Mutex::new(0),
        }
    }

    pub fn observe(&self, snapshot: ContinuousSnapshot) -> Result<()> {
        let mut total = self
            .total_samples
            .lock()
            .map_err(|_| anyhow!("continuous sample counter poisoned"))?;
        if *total >= MAX_CONTINUOUS_SAMPLES {
            bail!("continuous checker exceeded {MAX_CONTINUOUS_SAMPLES} samples");
        }
        *total += 1;
        let violations = self.check(&snapshot)?;
        {
            let mut samples = self
                .samples
                .lock()
                .map_err(|_| anyhow!("continuous sample mutex poisoned"))?;
            samples.push(snapshot.clone());
            if samples.len() > RETAINED_CONTINUOUS_SAMPLES {
                samples.remove(0);
            }
        }
        if let Some(violation) = violations.first() {
            self.events.record("invariant", serde_json::json!({"invariant_id":violation.invariant_id,"invariant_result":"fail","details":violation}))?;
            bail!(
                "{}: {} at continuous sample {}",
                violation.invariant_id,
                violation.message,
                violation.snapshot_sequence
            );
        }
        self.events.record("observation", serde_json::json!({"observation_type":"continuous_invariants","details":{"sequence":snapshot.sequence,"replicas":snapshot.replicas.len(),"durability":snapshot.durability.len(),"gc":snapshot.gc_protection.len(),"intents":snapshot.intents.len()}}))?;
        Ok(())
    }

    pub fn write_artifact(&self, artifacts: &RunArtifacts) -> Result<()> {
        let samples = self
            .samples
            .lock()
            .map_err(|_| anyhow!("continuous sample mutex poisoned"))?;
        let total = *self
            .total_samples
            .lock()
            .map_err(|_| anyhow!("continuous sample counter poisoned"))?;
        artifacts.write_json("observations/continuous-checks.json", &serde_json::json!({"checker_version":1,"total_samples":total,"retained_samples":samples.len(),"samples":&*samples}))
    }

    fn check(&self, snapshot: &ContinuousSnapshot) -> Result<Vec<InvariantViolation>> {
        let mut violations = Vec::new();
        let mut roots = BTreeMap::<(String, u64, u64), String>::new();
        let mut temporal = self
            .temporal
            .lock()
            .map_err(|_| anyhow!("continuous temporal state poisoned"))?;
        for replica in &snapshot.replicas {
            if let (Some(commit), Some(applied)) = (replica.commit_index, replica.applied_index)
                && commit < applied
            {
                violation(
                    &mut violations,
                    "SAF-RAFT-001",
                    snapshot.sequence,
                    format!(
                        "{} commit index {commit} is below applied index {applied}",
                        replica.node
                    ),
                );
            }
            if let (Some(last), Some(commit)) = (replica.last_log_index, replica.commit_index)
                && last < commit
            {
                violation(
                    &mut violations,
                    "SAF-RAFT-001",
                    snapshot.sequence,
                    format!(
                        "{} last log index {last} is below commit index {commit}",
                        replica.node
                    ),
                );
            }
            let root_key = (replica.namespace.clone(), replica.epoch, replica.revision);
            if let Some(previous) = roots.insert(root_key, replica.root.clone())
                && previous != replica.root
            {
                violation(
                    &mut violations,
                    "SAF-RAFT-001",
                    snapshot.sequence,
                    format!(
                        "namespace {} epoch {} revision {} has roots {previous} and {}",
                        replica.namespace, replica.epoch, replica.revision, replica.root
                    ),
                );
            }
            if replica.local_voting != replica.voter_ids.contains(&replica.local_raft_id) {
                violation(
                    &mut violations,
                    "SAF-RAFT-004",
                    snapshot.sequence,
                    format!(
                        "{} local voting flag disagrees with membership",
                        replica.node
                    ),
                );
            }
            if !replica.voter_ids.is_disjoint(&replica.learner_ids) {
                violation(
                    &mut violations,
                    "SAF-RAFT-004",
                    snapshot.sequence,
                    format!("{} membership contains a voting learner", replica.node),
                );
            }
            let membership_key = (replica.namespace.clone(), replica.epoch);
            let initial = temporal
                .initial_voters
                .entry(membership_key)
                .or_insert_with(|| replica.voter_ids.clone())
                .clone();
            if let Some(commit) = replica.commit_index {
                for learner in &replica.learner_ids {
                    if replica
                        .replication_match
                        .get(learner)
                        .and_then(|index| *index)
                        .is_some_and(|index| index >= commit)
                    {
                        temporal.caught_up_learners.insert((
                            replica.namespace.clone(),
                            replica.epoch,
                            *learner,
                        ));
                    }
                }
            }
            for voter in replica.voter_ids.difference(&initial) {
                if !temporal.caught_up_learners.contains(&(
                    replica.namespace.clone(),
                    replica.epoch,
                    *voter,
                )) {
                    violation(
                        &mut violations,
                        "SAF-RAFT-004",
                        snapshot.sequence,
                        format!("learner {voter} became a voter before observed catch-up"),
                    );
                }
            }
        }
        for durability in &snapshot.durability {
            if durability.verified_replicas < durability.required {
                violation(
                    &mut violations,
                    "SAF-RECEIPT-001",
                    snapshot.sequence,
                    format!(
                        "{} has {} verified replicas but requires {}",
                        durability.cid, durability.verified_replicas, durability.required
                    ),
                );
            }
        }
        for protection in &snapshot.gc_protection {
            if !protection.protected {
                violation(
                    &mut violations,
                    "SAF-GC-001",
                    snapshot.sequence,
                    format!(
                        "{} does not protect current root {}",
                        protection.node, protection.root
                    ),
                );
            }
        }
        for intent in &snapshot.intents {
            if matches!(intent.status.as_str(), "applied" | "resolved") && intent.actionable {
                violation(
                    &mut violations,
                    "SAF-OBS-001",
                    snapshot.sequence,
                    format!("terminal intent {} remains actionable", intent.intent_id),
                );
            }
            if intent.status == "pending"
                && intent.age_seconds > self.max_pending_intent_age_seconds
            {
                violation(
                    &mut violations,
                    "LIV-GC-001",
                    snapshot.sequence,
                    format!(
                        "pending intent {} is {} seconds old",
                        intent.intent_id, intent.age_seconds
                    ),
                );
            }
        }
        Ok(violations)
    }
}

fn violation(
    violations: &mut Vec<InvariantViolation>,
    invariant_id: &str,
    sequence: u64,
    message: String,
) {
    violations.push(InvariantViolation {
        invariant_id: invariant_id.into(),
        message,
        snapshot_sequence: sequence,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn checker() -> (ContinuousChecker, tempfile::TempDir) {
        let directory = tempdir().unwrap();
        let events = Arc::new(
            EventRecorder::create("test", &directory.path().join("events.jsonl")).unwrap(),
        );
        (ContinuousChecker::new(events, 30), directory)
    }

    fn replica() -> ReplicaObservation {
        ReplicaObservation {
            node: "n1".into(),
            namespace: "ns".into(),
            epoch: 1,
            revision: 1,
            root: "root".into(),
            last_log_index: Some(4),
            commit_index: Some(4),
            applied_index: Some(4),
            local_raft_id: 1,
            local_voting: true,
            voter_ids: BTreeSet::from([1, 2, 3]),
            learner_ids: BTreeSet::new(),
            replication_match: BTreeMap::new(),
        }
    }

    #[test]
    fn accepts_consistent_snapshot() {
        let (checker, _directory) = checker();
        checker
            .observe(ContinuousSnapshot {
                sequence: 1,
                replicas: vec![replica()],
                durability: vec![DurabilityObservation {
                    cid: "cid".into(),
                    required: 2,
                    verified_replicas: 2,
                }],
                gc_protection: vec![GcProtectionObservation {
                    node: "n1".into(),
                    root: "root".into(),
                    protected: true,
                }],
                intents: vec![],
            })
            .unwrap();
    }

    #[test]
    fn detects_injected_consensus_durability_gc_and_learner_violations() {
        let cases = [
            {
                let mut value = replica();
                value.commit_index = Some(2);
                value.applied_index = Some(3);
                ContinuousSnapshot {
                    sequence: 1,
                    replicas: vec![value],
                    ..Default::default()
                }
            },
            ContinuousSnapshot {
                sequence: 2,
                durability: vec![DurabilityObservation {
                    cid: "cid".into(),
                    required: 3,
                    verified_replicas: 2,
                }],
                ..Default::default()
            },
            ContinuousSnapshot {
                sequence: 3,
                gc_protection: vec![GcProtectionObservation {
                    node: "n1".into(),
                    root: "root".into(),
                    protected: false,
                }],
                ..Default::default()
            },
            {
                let mut value = replica();
                value.learner_ids.insert(1);
                ContinuousSnapshot {
                    sequence: 4,
                    replicas: vec![value],
                    ..Default::default()
                }
            },
        ];
        for snapshot in cases {
            let (checker, _directory) = checker();
            assert!(checker.observe(snapshot).is_err());
        }
    }

    #[test]
    fn detects_split_root_and_terminal_actionable_intent() {
        let (checker, _directory) = checker();
        let mut other = replica();
        other.node = "n2".into();
        other.root = "other".into();
        let snapshot = ContinuousSnapshot {
            sequence: 1,
            replicas: vec![replica(), other],
            intents: vec![IntentObservation {
                intent_id: "i".into(),
                status: "resolved".into(),
                age_seconds: 0,
                actionable: true,
            }],
            ..Default::default()
        };
        assert!(checker.observe(snapshot).is_err());
    }
}
