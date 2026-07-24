// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use pepper_rsm::ReplicatedStateMachine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerRegistration {
    pub broker_id: i32,
    pub host: String,
    pub port: u16,
    pub rack: Option<String>,
    pub broker_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionRecord {
    pub partition_id: i32,
    pub assignment_epoch: u64,
    pub leader_id: i32,
    pub leader_epoch: u64,
    pub replicas: Vec<i32>,
    pub minimum_in_sync_replicas: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicRecord {
    pub topic_id: [u8; 16],
    pub name: String,
    pub epoch: u64,
    pub partitions: Vec<PartitionRecord>,
    pub configs: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerState {
    pub cluster_id: String,
    pub revision: u64,
    pub controller_id: i32,
    pub brokers: BTreeMap<i32, BrokerRegistration>,
    pub topics: BTreeMap<String, TopicRecord>,
}

impl ControllerState {
    pub fn new(cluster_id: impl Into<String>, controller_id: i32) -> Self {
        Self {
            cluster_id: cluster_id.into(),
            revision: 0,
            controller_id,
            brokers: BTreeMap::new(),
            topics: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControllerCommand {
    RegisterBroker {
        broker_id: i32,
        host: String,
        port: u16,
        rack: Option<String>,
        expected_epoch: Option<u64>,
    },
    CreateTopic {
        name: String,
        partitions: u32,
        replication_factor: u16,
        minimum_in_sync_replicas: u16,
        configs: BTreeMap<String, String>,
    },
    DeleteTopic {
        name: String,
        expected_epoch: Option<u64>,
    },
    AlterTopicConfigs {
        name: String,
        configs: BTreeMap<String, String>,
        validate_only: bool,
    },
    ElectLeader {
        topic: String,
        partition: i32,
        leader_id: i32,
        expected_assignment_epoch: u64,
    },
    ReassignPartition {
        topic: String,
        partition: i32,
        replicas: Vec<i32>,
        expected_assignment_epoch: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControllerResponse {
    Broker(BrokerRegistration),
    Topic(TopicRecord),
    Deleted { topic_id: [u8; 16], revision: u64 },
}

pub struct ControllerMachine;

#[async_trait]
impl ReplicatedStateMachine for ControllerMachine {
    type State = ControllerState;
    type Command = ControllerCommand;
    type Response = ControllerResponse;
    type Error = ControllerError;

    async fn apply(
        &self,
        state: &mut Self::State,
        command: Self::Command,
    ) -> Result<Self::Response, Self::Error> {
        match command {
            ControllerCommand::RegisterBroker {
                broker_id,
                host,
                port,
                rack,
                expected_epoch,
            } => {
                if broker_id < 0 || host.is_empty() || port == 0 {
                    return Err(ControllerError::Invalid);
                }
                if let Some(expected) = expected_epoch
                    && state
                        .brokers
                        .get(&broker_id)
                        .map(|broker| broker.broker_epoch)
                        != Some(expected)
                {
                    return Err(ControllerError::Fenced);
                }
                state.revision = state.revision.saturating_add(1);
                let broker = BrokerRegistration {
                    broker_id,
                    host,
                    port,
                    rack,
                    broker_epoch: state.revision,
                };
                state.brokers.insert(broker_id, broker.clone());
                Ok(ControllerResponse::Broker(broker))
            }
            ControllerCommand::CreateTopic {
                name,
                partitions,
                replication_factor,
                minimum_in_sync_replicas,
                configs,
            } => {
                validate_topic_name(&name)?;
                if state.topics.contains_key(&name) {
                    return Err(ControllerError::TopicExists);
                }
                if partitions == 0
                    || replication_factor == 0
                    || usize::from(replication_factor) > state.brokers.len()
                    || minimum_in_sync_replicas == 0
                    || minimum_in_sync_replicas > replication_factor
                {
                    return Err(ControllerError::InvalidReplication);
                }
                state.revision = state.revision.saturating_add(1);
                let broker_ids = state.brokers.keys().copied().collect::<Vec<_>>();
                let mut descriptors = Vec::with_capacity(partitions as usize);
                for partition_id in 0..partitions {
                    let replicas = (0..usize::from(replication_factor))
                        .map(|position| {
                            broker_ids[(partition_id as usize + position) % broker_ids.len()]
                        })
                        .collect::<Vec<_>>();
                    descriptors.push(PartitionRecord {
                        partition_id: partition_id as i32,
                        assignment_epoch: state.revision,
                        leader_id: replicas[0],
                        leader_epoch: 1,
                        replicas,
                        minimum_in_sync_replicas,
                    });
                }
                let mut material = Vec::new();
                material.extend_from_slice(state.cluster_id.as_bytes());
                material.extend_from_slice(name.as_bytes());
                material.extend_from_slice(&state.revision.to_le_bytes());
                let digest = blake3::hash(&material);
                let topic = TopicRecord {
                    topic_id: digest.as_bytes()[..16].try_into().expect("fixed"),
                    name: name.clone(),
                    epoch: state.revision,
                    partitions: descriptors,
                    configs,
                };
                state.topics.insert(name, topic.clone());
                Ok(ControllerResponse::Topic(topic))
            }
            ControllerCommand::DeleteTopic {
                name,
                expected_epoch,
            } => {
                let topic = state
                    .topics
                    .get(&name)
                    .ok_or(ControllerError::UnknownTopic)?;
                if expected_epoch.is_some_and(|expected| expected != topic.epoch) {
                    return Err(ControllerError::Fenced);
                }
                let topic_id = topic.topic_id;
                state.topics.remove(&name);
                state.revision = state.revision.saturating_add(1);
                Ok(ControllerResponse::Deleted {
                    topic_id,
                    revision: state.revision,
                })
            }
            ControllerCommand::AlterTopicConfigs {
                name,
                configs,
                validate_only,
            } => {
                let record = state
                    .topics
                    .get_mut(&name)
                    .ok_or(ControllerError::UnknownTopic)?;
                for key in configs.keys() {
                    if !matches!(
                        key.as_str(),
                        "cleanup.policy"
                            | "retention.bytes"
                            | "retention.ms"
                            | "segment.bytes"
                            | "min.insync.replicas"
                    ) {
                        return Err(ControllerError::Invalid);
                    }
                }
                if !validate_only {
                    state.revision = state.revision.saturating_add(1);
                    record.configs.extend(configs);
                    record.epoch = state.revision;
                }
                Ok(ControllerResponse::Topic(record.clone()))
            }
            ControllerCommand::ElectLeader {
                topic,
                partition,
                leader_id,
                expected_assignment_epoch,
            } => {
                let record = state
                    .topics
                    .get_mut(&topic)
                    .ok_or(ControllerError::UnknownTopic)?;
                let descriptor = record
                    .partitions
                    .get_mut(partition as usize)
                    .ok_or(ControllerError::UnknownPartition)?;
                if descriptor.assignment_epoch != expected_assignment_epoch
                    || !descriptor.replicas.contains(&leader_id)
                {
                    return Err(ControllerError::Fenced);
                }
                state.revision = state.revision.saturating_add(1);
                descriptor.leader_id = leader_id;
                descriptor.leader_epoch = descriptor.leader_epoch.saturating_add(1);
                descriptor.assignment_epoch = state.revision;
                record.epoch = state.revision;
                Ok(ControllerResponse::Topic(record.clone()))
            }
            ControllerCommand::ReassignPartition {
                topic,
                partition,
                replicas,
                expected_assignment_epoch,
            } => {
                let record = state
                    .topics
                    .get_mut(&topic)
                    .ok_or(ControllerError::UnknownTopic)?;
                let descriptor = record
                    .partitions
                    .get_mut(partition as usize)
                    .ok_or(ControllerError::UnknownPartition)?;
                let unique = replicas
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>();
                if descriptor.assignment_epoch != expected_assignment_epoch
                    || unique.len() != replicas.len()
                    || unique.len() < usize::from(descriptor.minimum_in_sync_replicas)
                    || !unique.contains(&descriptor.leader_id)
                    || !unique
                        .iter()
                        .all(|broker| state.brokers.contains_key(broker))
                {
                    return Err(ControllerError::Fenced);
                }
                state.revision = state.revision.saturating_add(1);
                descriptor.replicas = replicas;
                descriptor.leader_epoch = descriptor.leader_epoch.saturating_add(1);
                descriptor.assignment_epoch = state.revision;
                record.epoch = state.revision;
                Ok(ControllerResponse::Topic(record.clone()))
            }
        }
    }

    fn encode_state(&self, state: &Self::State) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(state).map_err(|error| ControllerError::Codec(error.to_string()))
    }

    fn decode_state(&self, encoded: &[u8]) -> Result<Self::State, Self::Error> {
        serde_json::from_slice(encoded).map_err(|error| ControllerError::Codec(error.to_string()))
    }

    fn command_class(&self, command: &Self::Command) -> &'static str {
        match command {
            ControllerCommand::RegisterBroker { .. } => "register_broker",
            ControllerCommand::CreateTopic { .. } => "create_topic",
            ControllerCommand::DeleteTopic { .. } => "delete_topic",
            ControllerCommand::AlterTopicConfigs { .. } => "alter_topic_configs",
            ControllerCommand::ElectLeader { .. } => "elect_leader",
            ControllerCommand::ReassignPartition { .. } => "reassign_partition",
        }
    }
}

fn validate_topic_name(name: &str) -> Result<(), ControllerError> {
    if name.is_empty()
        || name.len() > 249
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ControllerError::Invalid);
    }
    Ok(())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ControllerError {
    #[error("invalid controller command")]
    Invalid,
    #[error("invalid replication policy")]
    InvalidReplication,
    #[error("topic already exists")]
    TopicExists,
    #[error("unknown topic")]
    UnknownTopic,
    #[error("unknown partition")]
    UnknownPartition,
    #[error("controller command was fenced")]
    Fenced,
    #[error("controller codec failed: {0}")]
    Codec(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_rsm::{DeterministicHost, ReplicatedStateMachine};
    use std::sync::Arc;

    async fn populated_host() -> DeterministicHost<ControllerMachine> {
        let host = DeterministicHost::new(
            Arc::new(ControllerMachine),
            ControllerState::new("deterministic", 0),
        );
        for broker_id in 0..3 {
            host.apply_batch([ControllerCommand::RegisterBroker {
                broker_id,
                host: "127.0.0.1".into(),
                port: 19092 + broker_id as u16,
                rack: None,
                expected_epoch: None,
            }])
            .await
            .unwrap();
        }
        host.apply_batch([ControllerCommand::CreateTopic {
            name: "events".into(),
            partitions: 3,
            replication_factor: 3,
            minimum_in_sync_replicas: 2,
            configs: BTreeMap::new(),
        }])
        .await
        .unwrap();
        host
    }

    #[tokio::test]
    async fn replay_and_snapshot_bytes_are_deterministic() {
        let left = populated_host().await;
        let right = populated_host().await;
        assert_eq!(
            left.snapshot().await.unwrap(),
            right.snapshot().await.unwrap()
        );

        let snapshot = left.snapshot().await.unwrap();
        let restored = DeterministicHost::new(
            Arc::new(ControllerMachine),
            ControllerState::new("empty", 0),
        );
        restored.restore(snapshot.clone()).await.unwrap();
        assert_eq!(restored.snapshot().await.unwrap(), snapshot);
    }

    #[tokio::test]
    async fn duplicate_and_stale_administration_is_fenced_without_state_change() {
        let host = populated_host().await;
        let before = host.snapshot().await.unwrap();
        assert_eq!(
            host.apply_batch([ControllerCommand::CreateTopic {
                name: "events".into(),
                partitions: 1,
                replication_factor: 1,
                minimum_in_sync_replicas: 1,
                configs: BTreeMap::new(),
            }])
            .await,
            Err(ControllerError::TopicExists)
        );
        assert_eq!(host.snapshot().await.unwrap(), before);

        let state = host.state().await;
        let assignment_epoch = state.topics["events"].partitions[0].assignment_epoch;
        let broker_epoch = state.brokers[&0].broker_epoch;
        assert_eq!(
            host.apply_batch([ControllerCommand::RegisterBroker {
                broker_id: 0,
                host: "127.0.0.1".into(),
                port: 19092,
                rack: None,
                expected_epoch: Some(broker_epoch.saturating_sub(1)),
            }])
            .await,
            Err(ControllerError::Fenced)
        );
        host.apply_batch([ControllerCommand::ElectLeader {
            topic: "events".into(),
            partition: 0,
            leader_id: 1,
            expected_assignment_epoch: assignment_epoch,
        }])
        .await
        .unwrap();
        assert_eq!(
            host.apply_batch([ControllerCommand::ElectLeader {
                topic: "events".into(),
                partition: 0,
                leader_id: 2,
                expected_assignment_epoch: assignment_epoch,
            }])
            .await,
            Err(ControllerError::Fenced)
        );
    }

    #[test]
    fn state_codec_round_trips_byte_exactly() {
        let state = ControllerState::new("codec", 3);
        let encoded = ControllerMachine.encode_state(&state).unwrap();
        let decoded = ControllerMachine.decode_state(&encoded).unwrap();
        assert_eq!(decoded, state);
        assert_eq!(ControllerMachine.encode_state(&decoded).unwrap(), encoded);
    }
}
