// SPDX-License-Identifier: Apache-2.0

//! Small deterministic metadata and coordinator machines used to qualify the
//! generic RSM host before Kafka protocol and storage code depends on it.

use async_trait::async_trait;
use pepper_rsm::ReplicatedStateMachine;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub fn metadata_shard(topic: &str, shards: u16) -> Result<u16, TestRsmError> {
    shard(topic, shards)
}

pub fn coordinator_shard(group: &str, shards: u16) -> Result<u16, TestRsmError> {
    shard(group, shards)
}

fn shard(key: &str, shards: u16) -> Result<u16, TestRsmError> {
    if key.is_empty() || shards == 0 {
        return Err(TestRsmError::Invalid);
    }
    let digest = blake3::hash(key.as_bytes());
    let value = u64::from_be_bytes(
        digest.as_bytes()[..8]
            .try_into()
            .expect("fixed digest prefix"),
    );
    Ok((value % u64::from(shards)) as u16)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataState {
    pub revision: u64,
    pub topics: BTreeMap<String, TopicRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopicRecord {
    pub partitions: u32,
    pub replication_factor: u16,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum MetadataCommand {
    CreateTopic {
        name: String,
        partitions: u32,
        replication_factor: u16,
    },
    DeleteTopic {
        name: String,
        expected_epoch: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataResponse {
    pub revision: u64,
    pub topic: Option<TopicRecord>,
}

pub struct TestMetadataMachine;

#[async_trait]
impl ReplicatedStateMachine for TestMetadataMachine {
    type State = MetadataState;
    type Command = MetadataCommand;
    type Response = MetadataResponse;
    type Error = TestRsmError;

    async fn apply(
        &self,
        state: &mut Self::State,
        command: Self::Command,
    ) -> Result<Self::Response, Self::Error> {
        match command {
            MetadataCommand::CreateTopic {
                name,
                partitions,
                replication_factor,
            } => {
                if name.is_empty() || partitions == 0 || replication_factor == 0 {
                    return Err(TestRsmError::Invalid);
                }
                if state.topics.contains_key(&name) {
                    return Err(TestRsmError::Conflict);
                }
                state.revision = state.revision.saturating_add(1);
                let record = TopicRecord {
                    partitions,
                    replication_factor,
                    epoch: state.revision,
                };
                state.topics.insert(name, record.clone());
                Ok(MetadataResponse {
                    revision: state.revision,
                    topic: Some(record),
                })
            }
            MetadataCommand::DeleteTopic {
                name,
                expected_epoch,
            } => {
                if state.topics.get(&name).map(|topic| topic.epoch) != Some(expected_epoch) {
                    return Err(TestRsmError::Fenced);
                }
                state.topics.remove(&name);
                state.revision = state.revision.saturating_add(1);
                Ok(MetadataResponse {
                    revision: state.revision,
                    topic: None,
                })
            }
        }
    }

    fn encode_state(&self, state: &Self::State) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(state).map_err(|error| TestRsmError::Codec(error.to_string()))
    }

    fn decode_state(&self, encoded: &[u8]) -> Result<Self::State, Self::Error> {
        serde_json::from_slice(encoded).map_err(|error| TestRsmError::Codec(error.to_string()))
    }

    fn command_class(&self, command: &Self::Command) -> &'static str {
        match command {
            MetadataCommand::CreateTopic { .. } => "create_topic",
            MetadataCommand::DeleteTopic { .. } => "delete_topic",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorState {
    pub groups: BTreeMap<String, GroupRecord>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRecord {
    pub generation: u32,
    pub members: BTreeSet<String>,
    pub offsets: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoordinatorCommand {
    Join {
        group: String,
        member: String,
    },
    Leave {
        group: String,
        member: String,
        generation: u32,
    },
    CommitOffset {
        group: String,
        member: String,
        generation: u32,
        topic: String,
        partition: u32,
        offset: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorResponse {
    pub generation: u32,
    pub member_count: usize,
}

pub struct TestCoordinatorMachine;

#[async_trait]
impl ReplicatedStateMachine for TestCoordinatorMachine {
    type State = CoordinatorState;
    type Command = CoordinatorCommand;
    type Response = CoordinatorResponse;
    type Error = TestRsmError;

    async fn apply(
        &self,
        state: &mut Self::State,
        command: Self::Command,
    ) -> Result<Self::Response, Self::Error> {
        let (group_name, member) = match &command {
            CoordinatorCommand::Join { group, member }
            | CoordinatorCommand::Leave { group, member, .. }
            | CoordinatorCommand::CommitOffset { group, member, .. } => (group, member),
        };
        if group_name.is_empty() || member.is_empty() {
            return Err(TestRsmError::Invalid);
        }
        let group = state.groups.entry(group_name.clone()).or_default();
        match command {
            CoordinatorCommand::Join { member, .. } => {
                if group.members.insert(member) {
                    group.generation = group.generation.saturating_add(1);
                }
            }
            CoordinatorCommand::Leave {
                member, generation, ..
            } => {
                validate_member(group, &member, generation)?;
                group.members.remove(&member);
                group.generation = group.generation.saturating_add(1);
            }
            CoordinatorCommand::CommitOffset {
                member,
                generation,
                topic,
                partition,
                offset,
                ..
            } => {
                validate_member(group, &member, generation)?;
                if topic.is_empty() {
                    return Err(TestRsmError::Invalid);
                }
                group
                    .offsets
                    .insert(format!("{topic}:{partition:010}"), offset);
            }
        }
        Ok(CoordinatorResponse {
            generation: group.generation,
            member_count: group.members.len(),
        })
    }

    fn encode_state(&self, state: &Self::State) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(state).map_err(|error| TestRsmError::Codec(error.to_string()))
    }

    fn decode_state(&self, encoded: &[u8]) -> Result<Self::State, Self::Error> {
        serde_json::from_slice(encoded).map_err(|error| TestRsmError::Codec(error.to_string()))
    }

    fn command_class(&self, command: &Self::Command) -> &'static str {
        match command {
            CoordinatorCommand::Join { .. } => "join",
            CoordinatorCommand::Leave { .. } => "leave",
            CoordinatorCommand::CommitOffset { .. } => "commit_offset",
        }
    }
}

fn validate_member(group: &GroupRecord, member: &str, generation: u32) -> Result<(), TestRsmError> {
    if group.generation != generation || !group.members.contains(member) {
        return Err(TestRsmError::Fenced);
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TestRsmError {
    #[error("invalid test RSM command")]
    Invalid,
    #[error("test RSM entity already exists")]
    Conflict,
    #[error("test RSM command is fenced")]
    Fenced,
    #[error("test RSM codec failed: {0}")]
    Codec(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_rsm::DeterministicHost;
    use std::sync::Arc;

    #[tokio::test]
    async fn metadata_and_coordinator_replay_identically_across_shards() {
        let metadata =
            DeterministicHost::new(Arc::new(TestMetadataMachine), MetadataState::default());
        metadata
            .apply_batch([
                MetadataCommand::CreateTopic {
                    name: "orders".into(),
                    partitions: 12,
                    replication_factor: 3,
                },
                MetadataCommand::CreateTopic {
                    name: "payments".into(),
                    partitions: 6,
                    replication_factor: 3,
                },
            ])
            .await
            .unwrap();
        let snapshot = metadata.snapshot().await.unwrap();
        let replay =
            DeterministicHost::new(Arc::new(TestMetadataMachine), MetadataState::default());
        replay.restore(snapshot.clone()).await.unwrap();
        assert_eq!(replay.snapshot().await.unwrap(), snapshot);

        let coordinator = DeterministicHost::new(
            Arc::new(TestCoordinatorMachine),
            CoordinatorState::default(),
        );
        let joined = coordinator
            .apply_batch([CoordinatorCommand::Join {
                group: "billing".into(),
                member: "consumer-1".into(),
            }])
            .await
            .unwrap()
            .remove(0);
        coordinator
            .apply_batch([CoordinatorCommand::CommitOffset {
                group: "billing".into(),
                member: "consumer-1".into(),
                generation: joined.generation,
                topic: "orders".into(),
                partition: 2,
                offset: 41,
            }])
            .await
            .unwrap();
        assert_eq!(
            coordinator
                .state()
                .await
                .groups
                .get("billing")
                .unwrap()
                .offsets
                .get("orders:0000000002"),
            Some(&41)
        );
        assert_eq!(metadata_shard("orders", 32), metadata_shard("orders", 32));
        assert_eq!(
            coordinator_shard("billing", 32),
            coordinator_shard("billing", 32)
        );
    }
}
