// SPDX-License-Identifier: Apache-2.0

//! Sharded deterministic classic consumer-group coordinator.

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use kafka_protocol::{messages::ConsumerProtocolAssignment, protocol::Decodable};
use pepper_rsm::{DeterministicHost, ReplicatedStateMachine};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupPhase {
    Empty,
    PreparingRebalance,
    Stable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    pub member_id: String,
    pub client_id: String,
    pub client_host: String,
    pub session_timeout_ms: u64,
    pub last_heartbeat_ms: u64,
    pub protocols: BTreeMap<String, Vec<u8>>,
    pub assignment: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OffsetKey {
    pub group: String,
    pub topic: String,
    pub partition: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffsetRecord {
    pub offset: i64,
    pub metadata: String,
    pub commit_timestamp_ms: u64,
    pub expire_timestamp_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRecord {
    pub generation: i32,
    pub leader: String,
    pub protocol_type: String,
    pub protocol_name: String,
    pub phase: GroupPhase,
    pub members: BTreeMap<String, GroupMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupState {
    pub revision: u64,
    pub coordinator_epoch: u64,
    pub next_member: u64,
    pub groups: BTreeMap<String, GroupRecord>,
    pub offsets: BTreeMap<OffsetKey, OffsetRecord>,
}

impl Default for GroupState {
    fn default() -> Self {
        Self {
            revision: 0,
            coordinator_epoch: 1,
            next_member: 0,
            groups: BTreeMap::new(),
            offsets: BTreeMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedGroupState {
    revision: u64,
    coordinator_epoch: u64,
    next_member: u64,
    groups: BTreeMap<String, GroupRecord>,
    offsets: Vec<(OffsetKey, OffsetRecord)>,
}

impl From<GroupState> for PersistedGroupState {
    fn from(state: GroupState) -> Self {
        Self {
            revision: state.revision,
            coordinator_epoch: state.coordinator_epoch,
            next_member: state.next_member,
            groups: state.groups,
            offsets: state.offsets.into_iter().collect(),
        }
    }
}

impl From<PersistedGroupState> for GroupState {
    fn from(state: PersistedGroupState) -> Self {
        Self {
            revision: state.revision,
            coordinator_epoch: state.coordinator_epoch,
            next_member: state.next_member,
            groups: state.groups,
            offsets: state.offsets.into_iter().collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupCommand {
    Join {
        group: String,
        member_id: String,
        client_id: String,
        client_host: String,
        protocol_type: String,
        protocols: BTreeMap<String, Vec<u8>>,
        session_timeout_ms: u64,
        now_ms: u64,
    },
    Sync {
        group: String,
        generation: i32,
        member_id: String,
        assignments: BTreeMap<String, Vec<u8>>,
    },
    Heartbeat {
        group: String,
        generation: i32,
        member_id: String,
        now_ms: u64,
    },
    Leave {
        group: String,
        member_id: String,
    },
    CommitOffsets {
        group: String,
        generation: i32,
        member_id: String,
        offsets: Vec<(String, i32, i64, String)>,
        retention_ms: Option<u64>,
        now_ms: u64,
    },
    CommitTransactionalOffsets {
        group: String,
        offsets: Vec<(String, i32, i64, String)>,
        now_ms: u64,
    },
    Expire {
        now_ms: u64,
    },
    Migrate {
        expected_epoch: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupResponse {
    Joined {
        generation: i32,
        protocol_name: String,
        leader: String,
        member_id: String,
        members: Vec<(String, Vec<u8>)>,
    },
    Assignment(Vec<u8>),
    Empty,
    Expired {
        members: u64,
        offsets: u64,
    },
    Migrated(u64),
}

pub struct GroupMachine;

#[async_trait]
impl ReplicatedStateMachine for GroupMachine {
    type State = GroupState;
    type Command = GroupCommand;
    type Response = GroupResponse;
    type Error = GroupError;

    async fn apply(
        &self,
        state: &mut Self::State,
        command: Self::Command,
    ) -> Result<Self::Response, Self::Error> {
        match command {
            GroupCommand::Join {
                group,
                mut member_id,
                client_id,
                client_host,
                protocol_type,
                protocols,
                session_timeout_ms,
                now_ms,
            } => {
                if group.is_empty()
                    || protocol_type.is_empty()
                    || protocols.is_empty()
                    || session_timeout_ms == 0
                {
                    return Err(GroupError::Invalid);
                }
                if member_id.is_empty() {
                    state.next_member = state.next_member.saturating_add(1);
                    member_id = format!("pepper-member-{}", state.next_member);
                }
                let record = state.groups.entry(group).or_insert_with(|| GroupRecord {
                    generation: 0,
                    leader: member_id.clone(),
                    protocol_type: protocol_type.clone(),
                    protocol_name: protocols.keys().next().cloned().unwrap_or_default(),
                    phase: GroupPhase::Empty,
                    members: BTreeMap::new(),
                });
                if record.protocol_type != protocol_type {
                    return Err(GroupError::InconsistentProtocol);
                }
                let selected = record
                    .protocol_name
                    .clone()
                    .or_else_nonempty(protocols.keys().next().cloned())
                    .ok_or(GroupError::InconsistentProtocol)?;
                if !protocols.contains_key(&selected)
                    || record
                        .members
                        .values()
                        .any(|member| !member.protocols.contains_key(&selected))
                {
                    return Err(GroupError::InconsistentProtocol);
                }
                record.protocol_name = selected;
                let member_is_new = !record.members.contains_key(&member_id);
                let begins_rebalance =
                    member_is_new || record.phase != GroupPhase::PreparingRebalance;
                record.members.insert(
                    member_id.clone(),
                    GroupMember {
                        member_id: member_id.clone(),
                        client_id,
                        client_host,
                        session_timeout_ms,
                        last_heartbeat_ms: now_ms,
                        protocols,
                        assignment: Vec::new(),
                    },
                );
                if begins_rebalance {
                    record.generation = record.generation.saturating_add(1);
                }
                record.leader = record
                    .members
                    .keys()
                    .next()
                    .cloned()
                    .ok_or(GroupError::UnknownMember)?;
                record.phase = GroupPhase::PreparingRebalance;
                state.revision = state.revision.saturating_add(1);
                let members = record
                    .members
                    .values()
                    .map(|member| {
                        (
                            member.member_id.clone(),
                            member.protocols[&record.protocol_name].clone(),
                        )
                    })
                    .collect();
                Ok(GroupResponse::Joined {
                    generation: record.generation,
                    protocol_name: record.protocol_name.clone(),
                    leader: record.leader.clone(),
                    member_id,
                    members,
                })
            }
            GroupCommand::Sync {
                group,
                generation,
                member_id,
                assignments,
            } => {
                let record = validate_member_mut(state, &group, generation, &member_id)?;
                if !assignments.is_empty() {
                    if record.leader != member_id
                        || assignments
                            .keys()
                            .any(|member| !record.members.contains_key(member))
                    {
                        return Err(GroupError::UnknownMember);
                    }
                    validate_unique_assignments(&assignments)?;
                    for member in record.members.values_mut() {
                        member.assignment = assignments
                            .get(&member.member_id)
                            .cloned()
                            .unwrap_or_default();
                    }
                    record.phase = GroupPhase::Stable;
                }
                if record.phase != GroupPhase::Stable {
                    return Err(GroupError::RebalanceInProgress);
                }
                let assignment = record.members[&member_id].assignment.clone();
                state.revision = state.revision.saturating_add(1);
                Ok(GroupResponse::Assignment(assignment))
            }
            GroupCommand::Heartbeat {
                group,
                generation,
                member_id,
                now_ms,
            } => {
                let record = validate_member_mut(state, &group, generation, &member_id)?;
                if record.phase != GroupPhase::Stable {
                    return Err(GroupError::RebalanceInProgress);
                }
                record
                    .members
                    .get_mut(&member_id)
                    .ok_or(GroupError::UnknownMember)?
                    .last_heartbeat_ms = now_ms;
                state.revision = state.revision.saturating_add(1);
                Ok(GroupResponse::Empty)
            }
            GroupCommand::Leave { group, member_id } => {
                let record = state
                    .groups
                    .get_mut(&group)
                    .ok_or(GroupError::UnknownGroup)?;
                if record.members.remove(&member_id).is_none() {
                    return Err(GroupError::UnknownMember);
                }
                record.generation = record.generation.saturating_add(1);
                record.leader = record.members.keys().next().cloned().unwrap_or_default();
                record.phase = if record.members.is_empty() {
                    GroupPhase::Empty
                } else {
                    GroupPhase::PreparingRebalance
                };
                state.revision = state.revision.saturating_add(1);
                Ok(GroupResponse::Empty)
            }
            GroupCommand::CommitOffsets {
                group,
                generation,
                member_id,
                offsets,
                retention_ms,
                now_ms,
            } => {
                validate_member(state, &group, generation, &member_id)?;
                for (topic, partition, offset, metadata) in offsets {
                    state.offsets.insert(
                        OffsetKey {
                            group: group.clone(),
                            topic,
                            partition,
                        },
                        OffsetRecord {
                            offset,
                            metadata,
                            commit_timestamp_ms: now_ms,
                            expire_timestamp_ms: retention_ms
                                .map(|retention| now_ms.saturating_add(retention)),
                        },
                    );
                }
                state.revision = state.revision.saturating_add(1);
                Ok(GroupResponse::Empty)
            }
            GroupCommand::CommitTransactionalOffsets {
                group,
                offsets,
                now_ms,
            } => {
                for (topic, partition, offset, metadata) in offsets {
                    state.offsets.insert(
                        OffsetKey {
                            group: group.clone(),
                            topic,
                            partition,
                        },
                        OffsetRecord {
                            offset,
                            metadata,
                            commit_timestamp_ms: now_ms,
                            expire_timestamp_ms: None,
                        },
                    );
                }
                state.revision = state.revision.saturating_add(1);
                Ok(GroupResponse::Empty)
            }
            GroupCommand::Expire { now_ms } => {
                let mut expired_members = 0u64;
                for record in state.groups.values_mut() {
                    let before = record.members.len();
                    record.members.retain(|_, member| {
                        now_ms.saturating_sub(member.last_heartbeat_ms) <= member.session_timeout_ms
                    });
                    expired_members += before.saturating_sub(record.members.len()) as u64;
                    if before != record.members.len() {
                        record.generation = record.generation.saturating_add(1);
                        record.leader = record.members.keys().next().cloned().unwrap_or_default();
                        record.phase = if record.members.is_empty() {
                            GroupPhase::Empty
                        } else {
                            GroupPhase::PreparingRebalance
                        };
                    }
                }
                let active = state
                    .groups
                    .iter()
                    .filter(|(_, group)| !group.members.is_empty())
                    .map(|(name, _)| name.clone())
                    .collect::<BTreeSet<_>>();
                let before = state.offsets.len();
                state.offsets.retain(|key, offset| {
                    active.contains(&key.group)
                        || offset
                            .expire_timestamp_ms
                            .is_none_or(|deadline| deadline > now_ms)
                });
                let expired_offsets = before.saturating_sub(state.offsets.len()) as u64;
                if expired_members > 0 || expired_offsets > 0 {
                    state.revision = state.revision.saturating_add(1);
                }
                Ok(GroupResponse::Expired {
                    members: expired_members,
                    offsets: expired_offsets,
                })
            }
            GroupCommand::Migrate { expected_epoch } => {
                if state.coordinator_epoch != expected_epoch {
                    return Err(GroupError::FencedCoordinator);
                }
                state.coordinator_epoch = state.coordinator_epoch.saturating_add(1);
                state.revision = state.revision.saturating_add(1);
                Ok(GroupResponse::Migrated(state.coordinator_epoch))
            }
        }
    }

    fn encode_state(&self, state: &Self::State) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(&PersistedGroupState::from(state.clone()))
            .map_err(|error| GroupError::Codec(error.to_string()))
    }

    fn decode_state(&self, encoded: &[u8]) -> Result<Self::State, Self::Error> {
        serde_json::from_slice::<PersistedGroupState>(encoded)
            .map(Into::into)
            .map_err(|error| GroupError::Codec(error.to_string()))
    }

    fn command_class(&self, command: &Self::Command) -> &'static str {
        match command {
            GroupCommand::Join { .. } => "join",
            GroupCommand::Sync { .. } => "sync",
            GroupCommand::Heartbeat { .. } => "heartbeat",
            GroupCommand::Leave { .. } => "leave",
            GroupCommand::CommitOffsets { .. } => "commit_offsets",
            GroupCommand::CommitTransactionalOffsets { .. } => "transactional_offsets",
            GroupCommand::Expire { .. } => "expire",
            GroupCommand::Migrate { .. } => "migrate",
        }
    }
}

trait NonEmptyString {
    fn or_else_nonempty(self, fallback: Option<String>) -> Option<String>;
}

impl NonEmptyString for String {
    fn or_else_nonempty(self, fallback: Option<String>) -> Option<String> {
        if self.is_empty() {
            fallback
        } else {
            Some(self)
        }
    }
}

fn validate_member(
    state: &GroupState,
    group: &str,
    generation: i32,
    member: &str,
) -> Result<(), GroupError> {
    let record = state.groups.get(group).ok_or(GroupError::UnknownGroup)?;
    if record.generation != generation {
        return Err(GroupError::IllegalGeneration);
    }
    if !record.members.contains_key(member) {
        return Err(GroupError::UnknownMember);
    }
    Ok(())
}

fn validate_unique_assignments(assignments: &BTreeMap<String, Vec<u8>>) -> Result<(), GroupError> {
    let mut owners = BTreeSet::new();
    for assignment in assignments.values() {
        if assignment.is_empty() {
            continue;
        }
        let mut bytes = Bytes::copy_from_slice(assignment);
        if bytes.remaining() < 2 {
            return Err(GroupError::InvalidAssignment);
        }
        let version = bytes.get_i16();
        let decoded = ConsumerProtocolAssignment::decode(&mut bytes, version)
            .map_err(|_| GroupError::InvalidAssignment)?;
        if bytes.has_remaining() {
            return Err(GroupError::InvalidAssignment);
        }
        for topic in decoded.assigned_partitions {
            for partition in topic.partitions {
                if !owners.insert((topic.topic.0.to_string(), partition)) {
                    return Err(GroupError::DuplicateAssignment);
                }
            }
        }
    }
    Ok(())
}

fn validate_member_mut<'a>(
    state: &'a mut GroupState,
    group: &str,
    generation: i32,
    member: &str,
) -> Result<&'a mut GroupRecord, GroupError> {
    validate_member(state, group, generation, member)?;
    state.groups.get_mut(group).ok_or(GroupError::UnknownGroup)
}

pub struct GroupCoordinator {
    root: PathBuf,
    shards: Vec<Arc<DeterministicHost<GroupMachine>>>,
    persist_locks: Vec<tokio::sync::Mutex<()>>,
}

impl GroupCoordinator {
    pub async fn open(root: impl AsRef<Path>, shard_count: u16) -> Result<Arc<Self>, GroupError> {
        if shard_count == 0 {
            return Err(GroupError::Invalid);
        }
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        let mut shards = Vec::with_capacity(shard_count as usize);
        let mut persist_locks = Vec::with_capacity(shard_count as usize);
        for shard in 0..shard_count {
            let path = root.join(format!("shard-{shard}.json"));
            let state = if path.exists() {
                serde_json::from_slice::<PersistedGroupState>(&std::fs::read(path)?)
                    .map_err(|error| GroupError::Codec(error.to_string()))?
                    .into()
            } else {
                GroupState::default()
            };
            shards.push(Arc::new(DeterministicHost::new(
                Arc::new(GroupMachine),
                state,
            )));
            persist_locks.push(tokio::sync::Mutex::new(()));
        }
        let coordinator = Arc::new(Self {
            root,
            shards,
            persist_locks,
        });
        let weak = Arc::downgrade(&coordinator);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let Some(coordinator) = weak.upgrade() else {
                    return;
                };
                let _ = coordinator.expire(now_millis()).await;
            }
        });
        Ok(coordinator)
    }

    pub fn shard_for(&self, group: &str) -> Result<usize, GroupError> {
        if group.is_empty() {
            return Err(GroupError::Invalid);
        }
        let digest = blake3::hash(group.as_bytes());
        let value = u64::from_be_bytes(digest.as_bytes()[..8].try_into().expect("fixed"));
        Ok(value as usize % self.shards.len())
    }

    pub async fn apply(
        &self,
        group: &str,
        command: GroupCommand,
    ) -> Result<GroupResponse, GroupError> {
        let shard = self.shard_for(group)?;
        let response = self.shards[shard]
            .apply_batch([command])
            .await?
            .pop()
            .ok_or(GroupError::Invalid)?;
        self.persist(shard).await?;
        Ok(response)
    }

    pub async fn group(&self, group: &str) -> Result<Option<GroupRecord>, GroupError> {
        let shard = self.shard_for(group)?;
        Ok(self.shards[shard].state().await.groups.get(group).cloned())
    }

    pub async fn offsets(
        &self,
        group: &str,
    ) -> Result<BTreeMap<OffsetKey, OffsetRecord>, GroupError> {
        let shard = self.shard_for(group)?;
        Ok(self.shards[shard]
            .state()
            .await
            .offsets
            .into_iter()
            .filter(|(key, _)| key.group == group)
            .collect())
    }

    pub async fn groups(&self) -> Vec<(String, GroupRecord)> {
        let mut groups = Vec::new();
        for shard in &self.shards {
            groups.extend(shard.state().await.groups);
        }
        groups.sort_by(|left, right| left.0.cmp(&right.0));
        groups
    }

    pub async fn expire(&self, now_ms: u64) -> Result<(u64, u64), GroupError> {
        let mut members = 0;
        let mut offsets = 0;
        for shard in 0..self.shards.len() {
            let response = self.shards[shard]
                .apply_batch([GroupCommand::Expire { now_ms }])
                .await?
                .pop()
                .ok_or(GroupError::Invalid)?;
            if let GroupResponse::Expired {
                members: expired_members,
                offsets: expired_offsets,
            } = response
            {
                members += expired_members;
                offsets += expired_offsets;
                if expired_members > 0 || expired_offsets > 0 {
                    self.persist(shard).await?;
                }
            }
        }
        Ok((members, offsets))
    }

    async fn persist(&self, shard: usize) -> Result<(), GroupError> {
        let _guard = self.persist_locks[shard].lock().await;
        let bytes =
            serde_json::to_vec(&PersistedGroupState::from(self.shards[shard].state().await))
                .map_err(|error| GroupError::Codec(error.to_string()))?;
        let path = self.root.join(format!("shard-{shard}.json"));
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, bytes)?;
        std::fs::File::open(&temporary)?.sync_all()?;
        std::fs::rename(temporary, path)?;
        std::fs::File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[derive(Debug, Error)]
pub enum GroupError {
    #[error("invalid group request")]
    Invalid,
    #[error("unknown group")]
    UnknownGroup,
    #[error("unknown member")]
    UnknownMember,
    #[error("illegal generation")]
    IllegalGeneration,
    #[error("inconsistent group protocol")]
    InconsistentProtocol,
    #[error("rebalance in progress")]
    RebalanceInProgress,
    #[error("consumer assignment is malformed")]
    InvalidAssignment,
    #[error("a partition is assigned to more than one member")]
    DuplicateAssignment,
    #[error("coordinator epoch is fenced")]
    FencedCoordinator,
    #[error("group codec failed: {0}")]
    Codec(String),
    #[error("group I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};
    use kafka_protocol::protocol::Encodable;

    #[tokio::test]
    async fn replay_fencing_expiration_and_offset_reopen_are_deterministic() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = GroupCoordinator::open(root.path(), 8).await.unwrap();
        let joined = coordinator
            .apply(
                "billing",
                GroupCommand::Join {
                    group: "billing".into(),
                    member_id: String::new(),
                    client_id: "test".into(),
                    client_host: "127.0.0.1".into(),
                    protocol_type: "consumer".into(),
                    protocols: BTreeMap::from([("range".into(), vec![1])]),
                    session_timeout_ms: 10,
                    now_ms: 1,
                },
            )
            .await
            .unwrap();
        let GroupResponse::Joined {
            generation,
            member_id,
            ..
        } = joined
        else {
            panic!("join response");
        };
        coordinator
            .apply(
                "billing",
                GroupCommand::CommitOffsets {
                    group: "billing".into(),
                    generation,
                    member_id: member_id.clone(),
                    offsets: vec![("events".into(), 0, 9, String::new())],
                    retention_ms: Some(10),
                    now_ms: 2,
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            coordinator
                .apply(
                    "billing",
                    GroupCommand::Heartbeat {
                        group: "billing".into(),
                        generation: generation - 1,
                        member_id,
                        now_ms: 3,
                    },
                )
                .await,
            Err(GroupError::IllegalGeneration)
        ));
        coordinator.expire(20).await.unwrap();
        assert!(coordinator.offsets("billing").await.unwrap().is_empty());
        drop(coordinator);
        let reopened = GroupCoordinator::open(root.path(), 8).await.unwrap();
        assert!(reopened.offsets("billing").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn ten_thousand_idle_groups_share_one_machine_and_stay_dense() {
        let machine = GroupMachine;
        let mut state = GroupState::default();
        for index in 0..10_000 {
            let group = format!("idle-{index}");
            let response = machine
                .apply(
                    &mut state,
                    GroupCommand::Join {
                        group,
                        member_id: String::new(),
                        client_id: "density".into(),
                        client_host: "local".into(),
                        protocol_type: "consumer".into(),
                        protocols: BTreeMap::from([("range".into(), Vec::new())]),
                        session_timeout_ms: 1,
                        now_ms: 0,
                    },
                )
                .await
                .unwrap();
            assert!(matches!(response, GroupResponse::Joined { .. }));
        }
        machine
            .apply(&mut state, GroupCommand::Expire { now_ms: 2 })
            .await
            .unwrap();
        assert_eq!(state.groups.len(), 10_000);
        assert!(state.groups.values().all(|group| group.members.is_empty()));
        let encoded = machine.encode_state(&state).unwrap();
        assert!(
            encoded.len() / state.groups.len() <= 2 * 1024,
            "{} serialized bytes per idle group",
            encoded.len() / state.groups.len()
        );
    }

    #[tokio::test]
    async fn coordinator_epoch_migration_is_fenced_and_snapshot_stable() {
        let host = DeterministicHost::new(Arc::new(GroupMachine), GroupState::default());
        assert_eq!(
            host.apply_batch([GroupCommand::Migrate { expected_epoch: 1 }])
                .await
                .unwrap(),
            vec![GroupResponse::Migrated(2)]
        );
        assert!(matches!(
            host.apply_batch([GroupCommand::Migrate { expected_epoch: 1 }])
                .await,
            Err(GroupError::FencedCoordinator)
        ));
        let first = host.snapshot().await.unwrap();
        let second = host.snapshot().await.unwrap();
        assert_eq!(first.state_bytes, second.state_bytes);
        assert_eq!(first.digest, second.digest);
    }

    #[tokio::test]
    async fn completed_generation_rejects_duplicate_partition_ownership() {
        let machine = GroupMachine;
        let mut state = GroupState::default();
        let mut members = Vec::new();
        for client in ["first", "second"] {
            let joined = machine
                .apply(
                    &mut state,
                    GroupCommand::Join {
                        group: "assignment".into(),
                        member_id: String::new(),
                        client_id: client.into(),
                        client_host: "local".into(),
                        protocol_type: "consumer".into(),
                        protocols: BTreeMap::from([
                            ("range".into(), Vec::new()),
                            ("roundrobin".into(), Vec::new()),
                        ]),
                        session_timeout_ms: 10_000,
                        now_ms: 1,
                    },
                )
                .await
                .unwrap();
            let GroupResponse::Joined {
                generation,
                member_id,
                leader,
                ..
            } = joined
            else {
                panic!("join response");
            };
            members.push((generation, member_id, leader));
        }
        let generation = members[1].0;
        let leader = members[1].2.clone();
        let mut assignment = BytesMut::new();
        assignment.put_i16(0);
        ConsumerProtocolAssignment::default()
            .with_assigned_partitions(vec![
                kafka_protocol::messages::consumer_protocol_assignment::TopicPartition::default()
                    .with_topic(
                        kafka_protocol::protocol::StrBytes::from_static_str("events").into(),
                    )
                    .with_partitions(vec![0]),
            ])
            .encode(&mut assignment, 0)
            .unwrap();
        let duplicate = BTreeMap::from([
            (members[0].1.clone(), assignment.to_vec()),
            (members[1].1.clone(), assignment.to_vec()),
        ]);
        assert!(matches!(
            machine
                .apply(
                    &mut state,
                    GroupCommand::Sync {
                        group: "assignment".into(),
                        generation,
                        member_id: leader.clone(),
                        assignments: duplicate,
                    },
                )
                .await,
            Err(GroupError::DuplicateAssignment)
        ));
        let distinct = BTreeMap::from([
            (members[0].1.clone(), assignment.to_vec()),
            (members[1].1.clone(), Vec::new()),
        ]);
        machine
            .apply(
                &mut state,
                GroupCommand::Sync {
                    group: "assignment".into(),
                    generation,
                    member_id: leader,
                    assignments: distinct,
                },
            )
            .await
            .unwrap();
        assert_eq!(state.groups["assignment"].phase, GroupPhase::Stable);
    }
}
