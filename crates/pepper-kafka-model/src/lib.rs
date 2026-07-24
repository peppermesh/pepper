// SPDX-License-Identifier: Apache-2.0

//! Executable state-transition models for Pepper's Kafka design.
//!
//! These models deliberately contain no storage, networking, async runtime, or
//! Kafka wire-protocol code. They lock the safety rules that production
//! implementations must refine without weakening.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub mod rsm;

pub type NodeId = u8;
pub type Offset = u64;
pub type ProducerId = u64;
pub type Sequence = u32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub offset: Offset,
    pub epoch: u64,
    pub digest: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Replica {
    pub promised_epoch: u64,
    pub log: Vec<LogEntry>,
    pub committed: Option<Offset>,
}

impl Replica {
    fn entry(&self, offset: Offset) -> Option<&LogEntry> {
        self.log.get(usize::try_from(offset).ok()?)
    }

    fn last_offset(&self) -> Option<Offset> {
        self.log.last().map(|entry| entry.offset)
    }

    fn truncate_uncommitted(&mut self, offset: Offset) -> Result<(), ModelError> {
        if self.committed.is_some_and(|committed| offset <= committed) {
            return Err(ModelError::CommittedTruncation);
        }
        self.log
            .truncate(usize::try_from(offset).map_err(|_| ModelError::OffsetOverflow)?);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leader {
    pub node: NodeId,
    pub epoch: u64,
}

/// A bounded model of one majority-replicated partition.
///
/// Election is intentionally modeled as a quorum promise plus log repair. The
/// candidate must contain the complete committed prefix observed by the quorum
/// before leadership becomes active. An append is committed only after the
/// exact `(offset, epoch, digest)` exists on a majority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionModel {
    pub replicas: BTreeMap<NodeId, Replica>,
    pub leader: Option<Leader>,
    pub committed_values: BTreeMap<Offset, u64>,
}

impl PartitionModel {
    pub fn new(nodes: impl IntoIterator<Item = NodeId>) -> Result<Self, ModelError> {
        let replicas = nodes
            .into_iter()
            .map(|node| {
                (
                    node,
                    Replica {
                        promised_epoch: 0,
                        log: Vec::new(),
                        committed: None,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        if replicas.len() < 3 || replicas.len() % 2 == 0 {
            return Err(ModelError::InvalidReplicaSet);
        }
        Ok(Self {
            replicas,
            leader: None,
            committed_values: BTreeMap::new(),
        })
    }

    pub fn quorum(&self) -> usize {
        self.replicas.len() / 2 + 1
    }

    pub fn elect(
        &mut self,
        candidate: NodeId,
        epoch: u64,
        voters: &BTreeSet<NodeId>,
    ) -> Result<(), ModelError> {
        if voters.len() < self.quorum() || !voters.contains(&candidate) {
            return Err(ModelError::NoQuorum);
        }
        if voters.iter().any(|node| !self.replicas.contains_key(node)) {
            return Err(ModelError::UnknownReplica);
        }
        if voters.iter().any(|node| {
            self.replicas
                .get(node)
                .is_some_and(|replica| replica.promised_epoch >= epoch)
        }) {
            return Err(ModelError::StaleEpoch);
        }

        let safe_committed = voters
            .iter()
            .filter_map(|node| self.replicas.get(node)?.committed)
            .max();
        let source = voters
            .iter()
            .filter_map(|node| self.replicas.get(node).map(|replica| (*node, replica)))
            .filter(|(_, replica)| {
                safe_committed.is_none_or(|offset| replica.last_offset() >= Some(offset))
            })
            .max_by_key(|(node, replica)| {
                (
                    replica
                        .log
                        .last()
                        .map(|entry| (entry.epoch, entry.offset))
                        .unwrap_or((0, 0)),
                    *node,
                )
            })
            .map(|(_, replica)| replica.log.clone())
            .ok_or(ModelError::NoSafeElectionSource)?;

        if let Some(committed) = safe_committed {
            for offset in 0..=committed {
                let expected = self
                    .committed_values
                    .get(&offset)
                    .ok_or(ModelError::MissingCommittedValue)?;
                if source
                    .get(usize::try_from(offset).map_err(|_| ModelError::OffsetOverflow)?)
                    .map(|entry| entry.digest)
                    != Some(*expected)
                {
                    return Err(ModelError::UnsafeElection);
                }
            }
        }

        for node in voters {
            self.replicas
                .get_mut(node)
                .ok_or(ModelError::UnknownReplica)?
                .promised_epoch = epoch;
        }

        let candidate_replica = self
            .replicas
            .get_mut(&candidate)
            .ok_or(ModelError::UnknownReplica)?;
        candidate_replica.log = source;
        candidate_replica.committed = safe_committed;
        self.leader = Some(Leader {
            node: candidate,
            epoch,
        });
        self.check_invariants()
    }

    pub fn append(&mut self, digest: u64) -> Result<LogEntry, ModelError> {
        let leader = self.leader.clone().ok_or(ModelError::NoLeader)?;
        let replica = self
            .replicas
            .get_mut(&leader.node)
            .ok_or(ModelError::UnknownReplica)?;
        if replica.promised_epoch != leader.epoch {
            return Err(ModelError::StaleEpoch);
        }
        let entry = LogEntry {
            offset: u64::try_from(replica.log.len()).map_err(|_| ModelError::OffsetOverflow)?,
            epoch: leader.epoch,
            digest,
        };
        replica.log.push(entry.clone());
        self.check_invariants()?;
        Ok(entry)
    }

    pub fn replicate(&mut self, follower: NodeId, entry: &LogEntry) -> Result<(), ModelError> {
        let leader = self.leader.as_ref().ok_or(ModelError::NoLeader)?;
        if entry.epoch != leader.epoch || follower == leader.node {
            return Err(ModelError::StaleEpoch);
        }
        let index = usize::try_from(entry.offset).map_err(|_| ModelError::OffsetOverflow)?;
        let leader_replica = self
            .replicas
            .get(&leader.node)
            .ok_or(ModelError::UnknownReplica)?;
        if leader_replica.entry(entry.offset) != Some(entry) {
            return Err(ModelError::LeaderEntryMismatch);
        }
        let leader_prefix = leader_replica
            .log
            .get(..index)
            .ok_or(ModelError::LogGap)?
            .to_vec();
        let replica = self
            .replicas
            .get_mut(&follower)
            .ok_or(ModelError::UnknownReplica)?;
        if replica.promised_epoch > entry.epoch {
            return Err(ModelError::StaleEpoch);
        }
        if replica.promised_epoch < entry.epoch {
            replica.promised_epoch = entry.epoch;
        }

        let shared = replica.log.len().min(leader_prefix.len());
        if let Some(mismatch) =
            (0..shared).find(|position| replica.log[*position] != leader_prefix[*position])
        {
            replica.truncate_uncommitted(
                u64::try_from(mismatch).map_err(|_| ModelError::OffsetOverflow)?,
            )?;
        }
        if replica.log.len() < leader_prefix.len() {
            replica
                .log
                .extend_from_slice(&leader_prefix[replica.log.len()..]);
        }
        if index < replica.log.len() {
            let existing = &replica.log[index];
            if existing == entry {
                return Ok(());
            }
            replica.truncate_uncommitted(entry.offset)?;
        }
        if index != replica.log.len() {
            return Err(ModelError::LogGap);
        }
        if replica.log[..index] != leader_prefix {
            return Err(ModelError::PrefixMismatch);
        }
        replica.log.push(entry.clone());
        self.check_invariants()
    }

    pub fn commit(&mut self, offset: Offset) -> Result<(), ModelError> {
        let leader = self.leader.as_ref().ok_or(ModelError::NoLeader)?;
        let leader_entry = self
            .replicas
            .get(&leader.node)
            .and_then(|replica| replica.entry(offset))
            .cloned()
            .ok_or(ModelError::UnknownOffset)?;
        if leader_entry.epoch != leader.epoch {
            return Err(ModelError::OldEpochCommit);
        }
        let matching = self
            .replicas
            .values()
            .filter(|replica| replica.entry(offset) == Some(&leader_entry))
            .count();
        if matching < self.quorum() {
            return Err(ModelError::NoQuorum);
        }
        if offset > 0 && !self.committed_values.contains_key(&(offset - 1)) {
            return Err(ModelError::CommitGap);
        }
        if let Some(existing) = self.committed_values.insert(offset, leader_entry.digest)
            && existing != leader_entry.digest
        {
            return Err(ModelError::CommittedValueChanged);
        }
        self.replicas
            .get_mut(&leader.node)
            .ok_or(ModelError::UnknownReplica)?
            .committed = Some(offset);
        self.check_invariants()
    }

    pub fn propagate_commit(&mut self, node: NodeId, offset: Offset) -> Result<(), ModelError> {
        let expected = self
            .committed_values
            .get(&offset)
            .ok_or(ModelError::UnknownOffset)?;
        let replica = self
            .replicas
            .get_mut(&node)
            .ok_or(ModelError::UnknownReplica)?;
        if replica.entry(offset).map(|entry| entry.digest) != Some(*expected) {
            return Err(ModelError::MissingCommittedValue);
        }
        replica.committed = Some(offset);
        self.check_invariants()
    }

    pub fn check_invariants(&self) -> Result<(), ModelError> {
        for (expected_offset, (offset, _)) in self.committed_values.iter().enumerate() {
            if usize::try_from(*offset).map_err(|_| ModelError::OffsetOverflow)? != expected_offset
            {
                return Err(ModelError::CommitGap);
            }
        }
        for replica in self.replicas.values() {
            for (index, entry) in replica.log.iter().enumerate() {
                if usize::try_from(entry.offset).map_err(|_| ModelError::OffsetOverflow)? != index {
                    return Err(ModelError::LogGap);
                }
            }
            if let Some(committed) = replica.committed {
                for offset in 0..=committed {
                    let expected = self
                        .committed_values
                        .get(&offset)
                        .ok_or(ModelError::MissingCommittedValue)?;
                    if replica.entry(offset).map(|entry| entry.digest) != Some(*expected) {
                        return Err(ModelError::CommittedValueChanged);
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducerState {
    pub epoch: u16,
    pub next_sequence: Sequence,
    pub accepted: BTreeMap<Sequence, AcceptedBatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedBatch {
    pub last_sequence: Sequence,
    pub base_offset: Offset,
    pub last_offset: Offset,
    pub digest: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProduceOutcome {
    Appended(AcceptedBatch),
    Duplicate(AcceptedBatch),
}

impl ProducerState {
    pub fn new(epoch: u16) -> Self {
        Self {
            epoch,
            next_sequence: 0,
            accepted: BTreeMap::new(),
        }
    }

    pub fn bump_epoch(&mut self, epoch: u16) -> Result<(), ModelError> {
        if epoch <= self.epoch {
            return Err(ModelError::ProducerFenced);
        }
        self.epoch = epoch;
        self.next_sequence = 0;
        self.accepted.clear();
        Ok(())
    }

    pub fn produce(
        &mut self,
        epoch: u16,
        first_sequence: Sequence,
        count: u32,
        digest: u64,
        next_offset: Offset,
    ) -> Result<ProduceOutcome, ModelError> {
        if epoch != self.epoch {
            return Err(ModelError::ProducerFenced);
        }
        if count == 0 {
            return Err(ModelError::EmptyBatch);
        }
        if let Some(accepted) = self.accepted.get(&first_sequence) {
            if accepted.digest == digest
                && accepted.last_sequence
                    == first_sequence
                        .checked_add(count - 1)
                        .ok_or(ModelError::SequenceOverflow)?
            {
                return Ok(ProduceOutcome::Duplicate(accepted.clone()));
            }
            return Err(ModelError::DuplicateSequenceConflict);
        }
        if first_sequence != self.next_sequence {
            return Err(ModelError::OutOfOrderSequence);
        }

        let last_sequence = first_sequence
            .checked_add(count - 1)
            .ok_or(ModelError::SequenceOverflow)?;
        let last_offset = next_offset
            .checked_add(u64::from(count - 1))
            .ok_or(ModelError::OffsetOverflow)?;
        let accepted = AcceptedBatch {
            last_sequence,
            base_offset: next_offset,
            last_offset,
            digest,
        };
        self.accepted.insert(first_sequence, accepted.clone());
        self.next_sequence = last_sequence
            .checked_add(1)
            .ok_or(ModelError::SequenceOverflow)?;
        Ok(ProduceOutcome::Appended(accepted))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupModel {
    pub generation: u32,
    pub leader: Option<String>,
    pub members: BTreeSet<String>,
    pub assignments: BTreeMap<u32, String>,
    pub synchronized: bool,
}

impl GroupModel {
    pub fn new() -> Self {
        Self {
            generation: 0,
            leader: None,
            members: BTreeSet::new(),
            assignments: BTreeMap::new(),
            synchronized: false,
        }
    }

    pub fn join(&mut self, member: String) -> Result<u32, ModelError> {
        if member.is_empty() {
            return Err(ModelError::InvalidMember);
        }
        self.members.insert(member);
        self.rebalance()
    }

    pub fn leave(&mut self, member: &str) -> Result<u32, ModelError> {
        if !self.members.remove(member) {
            return Err(ModelError::UnknownMember);
        }
        self.rebalance()
    }

    fn rebalance(&mut self) -> Result<u32, ModelError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(ModelError::GenerationOverflow)?;
        self.leader = self.members.first().cloned();
        self.assignments.clear();
        self.synchronized = false;
        Ok(self.generation)
    }

    pub fn sync(
        &mut self,
        leader: &str,
        generation: u32,
        assignments: BTreeMap<u32, String>,
    ) -> Result<(), ModelError> {
        if generation != self.generation {
            return Err(ModelError::IllegalGeneration);
        }
        if self.leader.as_deref() != Some(leader) {
            return Err(ModelError::NotGroupLeader);
        }
        if assignments
            .values()
            .any(|member| !self.members.contains(member))
        {
            return Err(ModelError::UnknownMember);
        }
        self.assignments = assignments;
        self.synchronized = true;
        self.check_invariants()
    }

    pub fn check_invariants(&self) -> Result<(), ModelError> {
        if self.synchronized && self.leader.is_none() {
            return Err(ModelError::MissingGroupLeader);
        }
        if self
            .assignments
            .values()
            .any(|member| !self.members.contains(member))
        {
            return Err(ModelError::UnknownMember);
        }
        Ok(())
    }
}

impl Default for GroupModel {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionPhase {
    Empty,
    Ongoing,
    PrepareCommit,
    PrepareAbort,
    CompleteCommit,
    CompleteAbort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionModel {
    pub producer_id: ProducerId,
    pub producer_epoch: u16,
    pub phase: TransactionPhase,
    pub first_offset: Option<Offset>,
    pub last_offset: Option<Offset>,
    pub partitions: BTreeSet<u32>,
    pub markers: BTreeMap<u32, bool>,
}

impl TransactionModel {
    pub fn new(producer_id: ProducerId, producer_epoch: u16) -> Self {
        Self {
            producer_id,
            producer_epoch,
            phase: TransactionPhase::Empty,
            first_offset: None,
            last_offset: None,
            partitions: BTreeSet::new(),
            markers: BTreeMap::new(),
        }
    }

    pub fn begin(&mut self, producer_epoch: u16) -> Result<(), ModelError> {
        self.require_epoch(producer_epoch)?;
        if !matches!(
            self.phase,
            TransactionPhase::Empty
                | TransactionPhase::CompleteCommit
                | TransactionPhase::CompleteAbort
        ) {
            return Err(ModelError::InvalidTransactionTransition);
        }
        self.phase = TransactionPhase::Ongoing;
        self.first_offset = None;
        self.last_offset = None;
        self.partitions.clear();
        self.markers.clear();
        Ok(())
    }

    pub fn append(
        &mut self,
        producer_epoch: u16,
        partition: u32,
        first_offset: Offset,
        last_offset: Offset,
    ) -> Result<(), ModelError> {
        self.require_epoch(producer_epoch)?;
        if self.phase != TransactionPhase::Ongoing || first_offset > last_offset {
            return Err(ModelError::InvalidTransactionTransition);
        }
        self.partitions.insert(partition);
        self.first_offset = Some(
            self.first_offset
                .map_or(first_offset, |current| current.min(first_offset)),
        );
        self.last_offset = Some(
            self.last_offset
                .map_or(last_offset, |current| current.max(last_offset)),
        );
        Ok(())
    }

    pub fn prepare(&mut self, producer_epoch: u16, commit: bool) -> Result<(), ModelError> {
        self.require_epoch(producer_epoch)?;
        if self.phase != TransactionPhase::Ongoing {
            return Err(ModelError::InvalidTransactionTransition);
        }
        self.phase = if commit {
            TransactionPhase::PrepareCommit
        } else {
            TransactionPhase::PrepareAbort
        };
        Ok(())
    }

    pub fn record_marker(
        &mut self,
        producer_epoch: u16,
        partition: u32,
        commit: bool,
    ) -> Result<(), ModelError> {
        self.require_epoch(producer_epoch)?;
        let expected = match self.phase {
            TransactionPhase::PrepareCommit => true,
            TransactionPhase::PrepareAbort => false,
            _ => return Err(ModelError::InvalidTransactionTransition),
        };
        if commit != expected || !self.partitions.contains(&partition) {
            return Err(ModelError::InvalidTransactionMarker);
        }
        if self.markers.insert(partition, commit).is_some() {
            return Err(ModelError::DuplicateTransactionMarker);
        }
        Ok(())
    }

    pub fn complete(&mut self, producer_epoch: u16) -> Result<(), ModelError> {
        self.require_epoch(producer_epoch)?;
        if self.markers.len() != self.partitions.len() {
            return Err(ModelError::MissingTransactionMarker);
        }
        self.phase = match self.phase {
            TransactionPhase::PrepareCommit => TransactionPhase::CompleteCommit,
            TransactionPhase::PrepareAbort => TransactionPhase::CompleteAbort,
            _ => return Err(ModelError::InvalidTransactionTransition),
        };
        Ok(())
    }

    pub fn read_committed_visible(&self) -> bool {
        self.phase == TransactionPhase::CompleteCommit
    }

    pub fn constrains_last_stable_offset(&self) -> Option<Offset> {
        matches!(
            self.phase,
            TransactionPhase::Ongoing
                | TransactionPhase::PrepareCommit
                | TransactionPhase::PrepareAbort
        )
        .then_some(self.first_offset)
        .flatten()
    }

    fn require_epoch(&self, producer_epoch: u16) -> Result<(), ModelError> {
        if producer_epoch == self.producer_epoch {
            Ok(())
        } else {
            Err(ModelError::ProducerFenced)
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelError {
    #[error("replica set must contain an odd number of at least three nodes")]
    InvalidReplicaSet,
    #[error("operation does not have a quorum")]
    NoQuorum,
    #[error("replica is unknown")]
    UnknownReplica,
    #[error("epoch is stale")]
    StaleEpoch,
    #[error("no safe election source contains the committed prefix")]
    NoSafeElectionSource,
    #[error("election source conflicts with the committed prefix")]
    UnsafeElection,
    #[error("partition has no leader")]
    NoLeader,
    #[error("offset cannot be represented")]
    OffsetOverflow,
    #[error("sequence cannot be represented")]
    SequenceOverflow,
    #[error("replica log contains a gap")]
    LogGap,
    #[error("replica log prefix differs from the leader")]
    PrefixMismatch,
    #[error("replicated entry differs from the leader entry")]
    LeaderEntryMismatch,
    #[error("committed data cannot be truncated")]
    CommittedTruncation,
    #[error("offset is unknown")]
    UnknownOffset,
    #[error("old-epoch entry cannot be newly committed")]
    OldEpochCommit,
    #[error("committed offsets must form a prefix")]
    CommitGap,
    #[error("committed value is missing")]
    MissingCommittedValue,
    #[error("committed value changed")]
    CommittedValueChanged,
    #[error("producer epoch is fenced")]
    ProducerFenced,
    #[error("record batch is empty")]
    EmptyBatch,
    #[error("duplicate sequence identifies different bytes")]
    DuplicateSequenceConflict,
    #[error("producer sequence is out of order")]
    OutOfOrderSequence,
    #[error("group member is invalid")]
    InvalidMember,
    #[error("group member is unknown")]
    UnknownMember,
    #[error("group generation overflowed")]
    GenerationOverflow,
    #[error("group generation is stale")]
    IllegalGeneration,
    #[error("requester is not the group leader")]
    NotGroupLeader,
    #[error("synchronized group has no leader")]
    MissingGroupLeader,
    #[error("transaction transition is invalid")]
    InvalidTransactionTransition,
    #[error("transaction marker is invalid")]
    InvalidTransactionMarker,
    #[error("transaction marker was written twice")]
    DuplicateTransactionMarker,
    #[error("transaction marker is missing")]
    MissingTransactionMarker,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn nodes(values: &[NodeId]) -> BTreeSet<NodeId> {
        values.iter().copied().collect()
    }

    #[test]
    fn partition_failover_retains_the_committed_prefix() {
        let mut model = PartitionModel::new([1, 2, 3]).unwrap();
        model.elect(1, 1, &nodes(&[1, 2])).unwrap();
        let first = model.append(11).unwrap();
        model.replicate(2, &first).unwrap();
        model.commit(0).unwrap();
        model.propagate_commit(2, 0).unwrap();

        model.leader = None;
        model.elect(2, 2, &nodes(&[2, 3])).unwrap();
        let second = model.append(22).unwrap();
        model.replicate(3, &second).unwrap();
        model.commit(1).unwrap();

        assert_eq!(model.committed_values, BTreeMap::from([(0, 11), (1, 22)]));
        model.check_invariants().unwrap();
    }

    #[test]
    fn partition_rejects_stale_leader_and_non_quorum_commit() {
        let mut model = PartitionModel::new([1, 2, 3]).unwrap();
        model.elect(1, 1, &nodes(&[1, 2])).unwrap();
        let entry = model.append(11).unwrap();
        assert_eq!(model.commit(0), Err(ModelError::NoQuorum));
        model.replicas.get_mut(&2).unwrap().promised_epoch = 2;
        assert_eq!(model.replicate(2, &entry), Err(ModelError::StaleEpoch));
    }

    #[test]
    fn producer_retry_reconstructs_the_original_result() {
        let mut producer = ProducerState::new(7);
        let appended = producer.produce(7, 0, 3, 99, 41).unwrap();
        let duplicate = producer.produce(7, 0, 3, 99, 80).unwrap();
        let ProduceOutcome::Appended(expected) = appended else {
            panic!("first request must append");
        };
        assert_eq!(duplicate, ProduceOutcome::Duplicate(expected));
        assert_eq!(
            producer.produce(7, 0, 3, 100, 80),
            Err(ModelError::DuplicateSequenceConflict)
        );
        assert_eq!(
            producer.produce(6, 3, 1, 101, 80),
            Err(ModelError::ProducerFenced)
        );
    }

    #[test]
    fn group_rebalance_fences_the_old_generation() {
        let mut group = GroupModel::new();
        let first_generation = group.join("a".to_string()).unwrap();
        group
            .sync(
                "a",
                first_generation,
                BTreeMap::from([(0, "a".to_string())]),
            )
            .unwrap();
        let second_generation = group.join("b".to_string()).unwrap();
        assert_eq!(
            group.sync("a", first_generation, BTreeMap::new()),
            Err(ModelError::IllegalGeneration)
        );
        group
            .sync(
                "a",
                second_generation,
                BTreeMap::from([(0, "a".to_string()), (1, "b".to_string())]),
            )
            .unwrap();
        group.check_invariants().unwrap();
    }

    #[test]
    fn transaction_visibility_requires_all_commit_markers() {
        let mut transaction = TransactionModel::new(1, 2);
        transaction.begin(2).unwrap();
        transaction.append(2, 0, 10, 12).unwrap();
        transaction.append(2, 1, 20, 22).unwrap();
        transaction.prepare(2, true).unwrap();
        transaction.record_marker(2, 0, true).unwrap();
        assert_eq!(
            transaction.complete(2),
            Err(ModelError::MissingTransactionMarker)
        );
        assert!(!transaction.read_committed_visible());
        transaction.record_marker(2, 1, true).unwrap();
        transaction.complete(2).unwrap();
        assert!(transaction.read_committed_visible());
        assert_eq!(transaction.constrains_last_stable_offset(), None);
    }

    proptest! {
        #[test]
        fn producer_never_accepts_a_gap(
            epoch in any::<u16>(),
            accepted_count in 1u32..100,
            gap in 1u32..100,
        ) {
            let mut producer = ProducerState::new(epoch);
            producer.produce(epoch, 0, accepted_count, 1, 0).unwrap();
            let first_sequence = accepted_count.checked_add(gap).unwrap();
            prop_assert_eq!(
                producer.produce(epoch, first_sequence, 1, 2, u64::from(accepted_count)),
                Err(ModelError::OutOfOrderSequence)
            );
        }

        #[test]
        fn committed_partition_digest_is_immutable(
            first_digest in any::<u64>(),
            second_digest in any::<u64>(),
        ) {
            let mut model = PartitionModel::new([1, 2, 3]).unwrap();
            model.elect(1, 1, &nodes(&[1, 2])).unwrap();
            let entry = model.append(first_digest).unwrap();
            model.replicate(2, &entry).unwrap();
            model.commit(0).unwrap();
            model.propagate_commit(2, 0).unwrap();
            model.leader = None;
            model.elect(2, 2, &nodes(&[2, 3])).unwrap();

            prop_assert_eq!(model.committed_values.get(&0), Some(&first_digest));
            if first_digest != second_digest {
                let conflicting = LogEntry { offset: 0, epoch: 2, digest: second_digest };
                prop_assert!(model.replicate(3, &conflicting).is_err());
            }
            model.check_invariants().unwrap();
        }
    }
}
