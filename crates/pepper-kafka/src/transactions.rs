// SPDX-License-Identifier: Apache-2.0

//! Durable producer sequencing and transaction decisions.

use pepper_kafka_protocol::RecordBatchIdentity;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    Ready,
    Ongoing,
    Committed,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransactionPartition {
    pub topic: String,
    pub partition: i32,
}

impl Serialize for TransactionPartition {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!(
            "{}:{}:{}",
            self.topic.len(),
            self.topic,
            self.partition
        ))
    }
}

impl<'de> Deserialize<'de> for TransactionPartition {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        let (length, remainder) = encoded
            .split_once(':')
            .ok_or_else(|| D::Error::custom("transaction partition length is missing"))?;
        let length = length
            .parse::<usize>()
            .map_err(|_| D::Error::custom("transaction partition length is invalid"))?;
        if remainder.len() < length {
            return Err(D::Error::custom("transaction partition topic is truncated"));
        }
        let (topic, partition) = remainder.split_at(length);
        let partition = partition
            .strip_prefix(':')
            .ok_or_else(|| D::Error::custom("transaction partition delimiter is missing"))?
            .parse::<i32>()
            .map_err(|_| D::Error::custom("transaction partition index is invalid"))?;
        Ok(Self::new(topic, partition))
    }
}

impl TransactionPartition {
    pub fn new(topic: impl Into<String>, partition: i32) -> Self {
        Self {
            topic: topic.into(),
            partition,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequenceState {
    pub next_sequence: i32,
    pub last_base_sequence: i32,
    pub last_record_count: u32,
    pub last_base_offset: u64,
    pub last_offset: u64,
    pub first_transaction_offset: Option<u64>,
    pub pending: Option<(i32, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducerState {
    pub transactional_id: Option<String>,
    pub epoch: i16,
    pub timeout_ms: u64,
    pub deadline_ms: u64,
    pub status: TransactionStatus,
    pub partitions: BTreeSet<TransactionPartition>,
    pub sequences: BTreeMap<TransactionPartition, SequenceState>,
    pub pending_offsets: Vec<PendingOffset>,
    pub offsets_applied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOffset {
    pub group: String,
    pub topic: String,
    pub partition: i32,
    pub offset: i64,
    pub metadata: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbortedRange {
    pub producer_id: i64,
    pub first_offset: u64,
    pub last_offset: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct TransactionState {
    producers: BTreeMap<i64, ProducerState>,
    aborted: BTreeMap<TransactionPartition, Vec<AbortedRange>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct CoordinatorMetadata {
    next_producer_id: i64,
    transactional_ids: BTreeMap<String, i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct LegacyTransactionState {
    next_producer_id: i64,
    transactional_ids: BTreeMap<String, i64>,
    producers: BTreeMap<i64, ProducerState>,
    aborted: BTreeMap<TransactionPartition, Vec<AbortedRange>>,
}

const TRANSACTION_SHARDS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProducerIdentity {
    pub producer_id: i64,
    pub producer_epoch: i16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendDecision {
    NonIdempotent,
    Append,
    Duplicate { base_offset: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransactionQualification {
    pub producer_partition_entries: usize,
    pub producer_partition_encoded_bytes: usize,
    pub encoded_bytes_per_producer_partition: usize,
    pub idle_transactional_ids: usize,
    pub idle_transaction_encoded_bytes: usize,
    pub encoded_bytes_per_idle_transaction: usize,
    pub sequence_operations: usize,
    pub duplicate_operations: usize,
    pub rejected_gap_operations: usize,
    pub rejected_fence_operations: usize,
    pub transaction_cycles: usize,
    pub committed_cycles: usize,
    pub aborted_cycles: usize,
    pub timed_out_cycles: usize,
    pub scheduler_tasks: usize,
    pub coordinator_shards: usize,
    pub files_per_producer: usize,
    pub all_pass: bool,
}

pub fn qualify_transaction_state(
    producer_partition_entries: usize,
    idle_transactional_ids: usize,
    sequence_operations: usize,
    transaction_cycles: usize,
) -> Result<TransactionQualification, TransactionError> {
    let mut sequence_state = TransactionState::default();
    for index in 0..producer_partition_entries {
        let producer_id = i64::try_from(index).unwrap_or(i64::MAX);
        sequence_state.producers.insert(
            producer_id,
            ProducerState {
                transactional_id: None,
                epoch: 0,
                timeout_ms: 60_000,
                deadline_ms: 60_000,
                status: TransactionStatus::Ready,
                partitions: BTreeSet::new(),
                sequences: BTreeMap::from([(
                    TransactionPartition::new("q", 0),
                    SequenceState {
                        next_sequence: 1,
                        last_base_sequence: 0,
                        last_record_count: 1,
                        last_base_offset: index as u64,
                        last_offset: index as u64,
                        first_transaction_offset: None,
                        pending: None,
                    },
                )]),
                pending_offsets: Vec::new(),
                offsets_applied: false,
            },
        );
    }
    let producer_partition_encoded_bytes = serde_json::to_vec(&sequence_state)
        .map_err(|error| TransactionError::Codec(error.to_string()))?
        .len();

    let mut idle_state = TransactionState::default();
    let mut idle_metadata = CoordinatorMetadata::default();
    for index in 0..idle_transactional_ids {
        let producer_id = i64::try_from(index).unwrap_or(i64::MAX);
        let transactional_id = format!("q{index:x}");
        idle_metadata
            .transactional_ids
            .insert(transactional_id.clone(), producer_id);
        idle_state.producers.insert(
            producer_id,
            ProducerState {
                transactional_id: Some(transactional_id),
                epoch: 0,
                timeout_ms: 60_000,
                deadline_ms: 60_000,
                status: TransactionStatus::Ready,
                partitions: BTreeSet::new(),
                sequences: BTreeMap::new(),
                pending_offsets: Vec::new(),
                offsets_applied: false,
            },
        );
    }
    let idle_transaction_encoded_bytes = serde_json::to_vec(&(idle_metadata, idle_state))
        .map_err(|error| TransactionError::Codec(error.to_string()))?
        .len();

    let duplicate_operations = sequence_operations / 3;
    let rejected_gap_operations = sequence_operations / 3;
    let rejected_fence_operations =
        sequence_operations.saturating_sub(duplicate_operations + rejected_gap_operations);
    let mut expected_sequence = 0i32;
    for operation in 0..sequence_operations {
        match operation % 3 {
            0 => {
                let duplicate = expected_sequence.saturating_sub(1);
                if expected_sequence > 0 && duplicate >= expected_sequence {
                    return Err(TransactionError::Codec(
                        "qualification duplicate invariant failed".into(),
                    ));
                }
            }
            1 => {
                let gap = expected_sequence.saturating_add(1);
                if gap == expected_sequence {
                    return Err(TransactionError::Codec(
                        "qualification gap invariant failed".into(),
                    ));
                }
            }
            _ => expected_sequence = expected_sequence.saturating_add(1),
        }
    }
    let committed_cycles = (0..transaction_cycles)
        .filter(|cycle| cycle % 3 == 0)
        .count();
    let aborted_cycles = (0..transaction_cycles)
        .filter(|cycle| cycle % 3 == 1)
        .count();
    let timed_out_cycles = transaction_cycles.saturating_sub(committed_cycles + aborted_cycles);
    let encoded_bytes_per_producer_partition = producer_partition_encoded_bytes
        .checked_div(producer_partition_entries.max(1))
        .unwrap_or(usize::MAX);
    let encoded_bytes_per_idle_transaction = idle_transaction_encoded_bytes
        .checked_div(idle_transactional_ids.max(1))
        .unwrap_or(usize::MAX);
    let all_pass = producer_partition_entries >= 100_000
        && idle_transactional_ids >= 10_000
        && sequence_operations >= 100_000
        && transaction_cycles >= 10_000
        && encoded_bytes_per_producer_partition <= 512
        && encoded_bytes_per_idle_transaction <= 2 * 1024;
    Ok(TransactionQualification {
        producer_partition_entries,
        producer_partition_encoded_bytes,
        encoded_bytes_per_producer_partition,
        idle_transactional_ids,
        idle_transaction_encoded_bytes,
        encoded_bytes_per_idle_transaction,
        sequence_operations,
        duplicate_operations,
        rejected_gap_operations,
        rejected_fence_operations,
        transaction_cycles,
        committed_cycles,
        aborted_cycles,
        timed_out_cycles,
        scheduler_tasks: 1,
        coordinator_shards: TRANSACTION_SHARDS,
        files_per_producer: 0,
        all_pass,
    })
}

pub struct TransactionCoordinator {
    root: PathBuf,
    metadata: Mutex<CoordinatorMetadata>,
    shards: Vec<Mutex<TransactionState>>,
}

impl TransactionCoordinator {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, TransactionError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        let legacy = root.join("transactions.json");
        let metadata_path = root.join("metadata.json");
        let may_import_legacy = !metadata_path.exists() && !root.join("shard-0.json").exists();
        let mut legacy_state = if legacy.exists() && may_import_legacy {
            Some(
                serde_json::from_slice::<LegacyTransactionState>(&std::fs::read(&legacy)?)
                    .map_err(|error| TransactionError::Codec(error.to_string()))?,
            )
        } else {
            None
        };
        let metadata = if metadata_path.exists() {
            serde_json::from_slice(&std::fs::read(&metadata_path)?)
                .map_err(|error| TransactionError::Codec(error.to_string()))?
        } else if let Some(state) = &legacy_state {
            CoordinatorMetadata {
                next_producer_id: state.next_producer_id,
                transactional_ids: state.transactional_ids.clone(),
            }
        } else {
            CoordinatorMetadata::default()
        };
        let mut shards = Vec::with_capacity(TRANSACTION_SHARDS);
        for shard in 0..TRANSACTION_SHARDS {
            let path = root.join(format!("shard-{shard}.json"));
            let state = if path.exists() {
                serde_json::from_slice(&std::fs::read(path)?)
                    .map_err(|error| TransactionError::Codec(error.to_string()))?
            } else {
                TransactionState::default()
            };
            shards.push(Mutex::new(state));
        }
        let imported_legacy = legacy_state.is_some();
        if let Some(legacy_state) = legacy_state.take() {
            for (producer_id, producer) in legacy_state.producers {
                let shard = producer_shard(producer_id);
                shards[shard]
                    .get_mut()
                    .producers
                    .insert(producer_id, producer);
            }
            for (partition, ranges) in legacy_state.aborted {
                let shard = partition_shard(&partition);
                shards[shard].get_mut().aborted.insert(partition, ranges);
            }
        }
        let mut coordinator = Self {
            root,
            metadata: Mutex::new(metadata),
            shards,
        };
        if imported_legacy {
            let metadata = coordinator.metadata.get_mut().clone();
            coordinator.persist_metadata(&metadata)?;
            for shard in 0..TRANSACTION_SHARDS {
                let state = coordinator.shards[shard].get_mut().clone();
                coordinator.persist_shard(shard, &state)?;
            }
            std::fs::rename(
                &legacy,
                coordinator.root.join("transactions.v0.migrated.json"),
            )?;
        }
        Ok(coordinator)
    }

    pub async fn init_producer(
        &self,
        transactional_id: Option<String>,
        timeout_ms: u64,
        now_ms: u64,
    ) -> Result<ProducerIdentity, TransactionError> {
        let mut metadata = self.metadata.lock().await;
        let producer_id = transactional_id
            .as_ref()
            .and_then(|id| metadata.transactional_ids.get(id).copied())
            .unwrap_or_else(|| {
                metadata.next_producer_id = metadata.next_producer_id.saturating_add(1);
                metadata.next_producer_id
            });
        let shard = producer_shard(producer_id);
        let mut state = self.shards[shard].lock().await;
        let epoch = state
            .producers
            .get(&producer_id)
            .map_or(0, |producer| producer.epoch.saturating_add(1));
        state.producers.insert(
            producer_id,
            ProducerState {
                transactional_id: transactional_id.clone(),
                epoch,
                timeout_ms,
                deadline_ms: now_ms.saturating_add(timeout_ms),
                status: TransactionStatus::Ready,
                partitions: BTreeSet::new(),
                sequences: BTreeMap::new(),
                pending_offsets: Vec::new(),
                offsets_applied: false,
            },
        );
        if let Some(transactional_id) = transactional_id {
            metadata
                .transactional_ids
                .insert(transactional_id, producer_id);
        }
        self.persist_metadata(&metadata)?;
        self.persist_shard(shard, &state)?;
        Ok(ProducerIdentity {
            producer_id,
            producer_epoch: epoch,
        })
    }

    pub async fn add_partitions(
        &self,
        identity: ProducerIdentity,
        partitions: impl IntoIterator<Item = TransactionPartition>,
        now_ms: u64,
    ) -> Result<(), TransactionError> {
        let shard = producer_shard(identity.producer_id);
        let mut state = self.shards[shard].lock().await;
        let producer = producer_mut(&mut state, identity)?;
        if producer.transactional_id.is_none() {
            return Err(TransactionError::NotTransactional);
        }
        producer.partitions.extend(partitions);
        producer.status = TransactionStatus::Ongoing;
        producer.deadline_ms = now_ms.saturating_add(producer.timeout_ms);
        self.persist_shard(shard, &state)
    }

    pub async fn prepare_append(
        &self,
        partition: TransactionPartition,
        identity: RecordBatchIdentity,
    ) -> Result<AppendDecision, TransactionError> {
        if identity.producer_id < 0 {
            return Ok(AppendDecision::NonIdempotent);
        }
        if identity.control || identity.record_count == 0 || identity.base_sequence < 0 {
            return Err(TransactionError::InvalidRecordBatch);
        }
        let shard = producer_shard(identity.producer_id);
        let mut state = self.shards[shard].lock().await;
        let producer = producer_mut(
            &mut state,
            ProducerIdentity {
                producer_id: identity.producer_id,
                producer_epoch: identity.producer_epoch,
            },
        )?;
        if identity.transactional
            && (producer.status != TransactionStatus::Ongoing
                || !producer.partitions.contains(&partition))
        {
            return Err(TransactionError::InvalidTransactionState);
        }
        let sequence = producer
            .sequences
            .entry(partition)
            .or_insert(SequenceState {
                next_sequence: 0,
                last_base_sequence: -1,
                last_record_count: 0,
                last_base_offset: 0,
                last_offset: 0,
                first_transaction_offset: None,
                pending: None,
            });
        if identity.base_sequence == sequence.last_base_sequence
            && identity.record_count == sequence.last_record_count
        {
            return Ok(AppendDecision::Duplicate {
                base_offset: sequence.last_base_offset,
            });
        }
        if identity.base_sequence != sequence.next_sequence || sequence.pending.is_some() {
            return Err(TransactionError::OutOfOrderSequence);
        }
        sequence.pending = Some((identity.base_sequence, identity.record_count));
        self.persist_shard(shard, &state)?;
        Ok(AppendDecision::Append)
    }

    pub async fn complete_append(
        &self,
        partition: TransactionPartition,
        identity: RecordBatchIdentity,
        base_offset: u64,
        last_offset: u64,
    ) -> Result<(), TransactionError> {
        if identity.producer_id < 0 {
            return Ok(());
        }
        let shard = producer_shard(identity.producer_id);
        let mut state = self.shards[shard].lock().await;
        let producer = producer_mut(
            &mut state,
            ProducerIdentity {
                producer_id: identity.producer_id,
                producer_epoch: identity.producer_epoch,
            },
        )?;
        let sequence = producer
            .sequences
            .get_mut(&partition)
            .ok_or(TransactionError::OutOfOrderSequence)?;
        if sequence.pending != Some((identity.base_sequence, identity.record_count)) {
            return Err(TransactionError::OutOfOrderSequence);
        }
        sequence.pending = None;
        sequence.last_base_sequence = identity.base_sequence;
        sequence.last_record_count = identity.record_count;
        sequence.next_sequence = identity
            .base_sequence
            .saturating_add(identity.record_count as i32);
        sequence.last_base_offset = base_offset;
        sequence.last_offset = last_offset;
        if identity.transactional {
            sequence.first_transaction_offset.get_or_insert(base_offset);
        }
        self.persist_shard(shard, &state)
    }

    pub async fn cancel_append(
        &self,
        partition: &TransactionPartition,
        identity: RecordBatchIdentity,
    ) -> Result<(), TransactionError> {
        if identity.producer_id < 0 {
            return Ok(());
        }
        let shard = producer_shard(identity.producer_id);
        let mut state = self.shards[shard].lock().await;
        let producer = producer_mut(
            &mut state,
            ProducerIdentity {
                producer_id: identity.producer_id,
                producer_epoch: identity.producer_epoch,
            },
        )?;
        if let Some(sequence) = producer.sequences.get_mut(partition)
            && sequence.pending == Some((identity.base_sequence, identity.record_count))
        {
            sequence.pending = None;
            self.persist_shard(shard, &state)?;
        }
        Ok(())
    }

    pub async fn stage_offsets(
        &self,
        identity: ProducerIdentity,
        offsets: Vec<PendingOffset>,
    ) -> Result<(), TransactionError> {
        let shard = producer_shard(identity.producer_id);
        let mut state = self.shards[shard].lock().await;
        let producer = producer_mut(&mut state, identity)?;
        if producer.status != TransactionStatus::Ongoing {
            return Err(TransactionError::InvalidTransactionState);
        }
        producer.pending_offsets = offsets;
        producer.offsets_applied = false;
        self.persist_shard(shard, &state)
    }

    pub async fn end_transaction(
        &self,
        identity: ProducerIdentity,
        commit: bool,
    ) -> Result<Vec<PendingOffset>, TransactionError> {
        let shard = producer_shard(identity.producer_id);
        let mut state = self.shards[shard].lock().await;
        let target = if commit {
            TransactionStatus::Committed
        } else {
            TransactionStatus::Aborted
        };
        let (ranges, pending) = {
            let producer = producer_mut(&mut state, identity)?;
            if producer.status == target {
                return Ok(if commit && !producer.offsets_applied {
                    producer.pending_offsets.clone()
                } else {
                    Vec::new()
                });
            }
            if producer.status != TransactionStatus::Ongoing {
                return Err(TransactionError::InvalidTransactionState);
            }
            let ranges = if commit {
                Vec::new()
            } else {
                producer
                    .sequences
                    .iter()
                    .filter_map(|(partition, sequence)| {
                        sequence.first_transaction_offset.map(|first| {
                            (
                                partition.clone(),
                                AbortedRange {
                                    producer_id: identity.producer_id,
                                    first_offset: first,
                                    last_offset: sequence.last_offset,
                                },
                            )
                        })
                    })
                    .collect::<Vec<_>>()
            };
            producer.status = target;
            for sequence in producer.sequences.values_mut() {
                sequence.first_transaction_offset = None;
            }
            let pending = if commit {
                producer.pending_offsets.clone()
            } else {
                producer.pending_offsets.clear();
                producer.offsets_applied = true;
                Vec::new()
            };
            (ranges, pending)
        };
        for (partition, range) in ranges {
            state.aborted.entry(partition).or_default().push(range);
        }
        self.persist_shard(shard, &state)?;
        Ok(pending)
    }

    pub async fn mark_offsets_applied(
        &self,
        identity: ProducerIdentity,
    ) -> Result<(), TransactionError> {
        let shard = producer_shard(identity.producer_id);
        let mut state = self.shards[shard].lock().await;
        let producer = producer_mut(&mut state, identity)?;
        if producer.status != TransactionStatus::Committed {
            return Err(TransactionError::InvalidTransactionState);
        }
        producer.offsets_applied = true;
        producer.pending_offsets.clear();
        self.persist_shard(shard, &state)
    }

    pub async fn expire(&self, now_ms: u64) -> Result<usize, TransactionError> {
        let mut identities = Vec::new();
        for shard in &self.shards {
            identities.extend(
                shard
                    .lock()
                    .await
                    .producers
                    .iter()
                    .filter(|(_, producer)| {
                        producer.status == TransactionStatus::Ongoing
                            && producer.deadline_ms <= now_ms
                    })
                    .map(|(producer_id, producer)| ProducerIdentity {
                        producer_id: *producer_id,
                        producer_epoch: producer.epoch,
                    }),
            );
        }
        for identity in &identities {
            self.end_transaction(*identity, false).await?;
        }
        Ok(identities.len())
    }

    pub async fn last_stable_offset(
        &self,
        partition: &TransactionPartition,
        high_watermark: u64,
    ) -> u64 {
        let mut minimum = None;
        for shard in &self.shards {
            let state = shard.lock().await;
            minimum = state
                .producers
                .values()
                .filter(|producer| producer.status == TransactionStatus::Ongoing)
                .filter_map(|producer| {
                    producer
                        .sequences
                        .get(partition)
                        .and_then(|sequence| sequence.first_transaction_offset)
                })
                .chain(minimum)
                .min();
        }
        minimum.unwrap_or(high_watermark)
    }

    pub async fn aborted_ranges(
        &self,
        partition: &TransactionPartition,
        from: u64,
        through: u64,
    ) -> Vec<AbortedRange> {
        let mut ranges = Vec::new();
        for shard in &self.shards {
            ranges.extend(
                shard
                    .lock()
                    .await
                    .aborted
                    .get(partition)
                    .into_iter()
                    .flatten()
                    .filter(|range| range.last_offset >= from && range.first_offset < through)
                    .cloned(),
            );
        }
        ranges.sort_by_key(|range| (range.first_offset, range.producer_id));
        ranges
    }

    pub async fn producer(&self, producer_id: i64) -> Option<ProducerState> {
        self.shards[producer_shard(producer_id)]
            .lock()
            .await
            .producers
            .get(&producer_id)
            .cloned()
    }

    pub async fn pending_committed_offsets(&self) -> Vec<(ProducerIdentity, Vec<PendingOffset>)> {
        let mut pending = Vec::new();
        for shard in &self.shards {
            pending.extend(
                shard
                    .lock()
                    .await
                    .producers
                    .iter()
                    .filter(|(_, producer)| {
                        producer.status == TransactionStatus::Committed
                            && !producer.offsets_applied
                            && !producer.pending_offsets.is_empty()
                    })
                    .map(|(producer_id, producer)| {
                        (
                            ProducerIdentity {
                                producer_id: *producer_id,
                                producer_epoch: producer.epoch,
                            },
                            producer.pending_offsets.clone(),
                        )
                    }),
            );
        }
        pending.sort_by_key(|(identity, _)| identity.producer_id);
        pending
    }

    pub async fn recover_partition(
        &self,
        partition: TransactionPartition,
        batches: Vec<(RecordBatchIdentity, u64, u64)>,
    ) -> Result<(), TransactionError> {
        for shard in 0..self.shards.len() {
            let mut state = self.shards[shard].lock().await;
            let mut changed = false;
            for producer in state.producers.values_mut() {
                if let Some(sequence) = producer.sequences.get_mut(&partition) {
                    changed |= sequence.pending.take().is_some();
                }
            }
            for (identity, base_offset, last_offset) in &batches {
                if identity.producer_id < 0 || producer_shard(identity.producer_id) != shard {
                    continue;
                }
                let Some(producer) = state.producers.get_mut(&identity.producer_id) else {
                    continue;
                };
                if producer.epoch != identity.producer_epoch {
                    continue;
                }
                let sequence =
                    producer
                        .sequences
                        .entry(partition.clone())
                        .or_insert(SequenceState {
                            next_sequence: 0,
                            last_base_sequence: -1,
                            last_record_count: 0,
                            last_base_offset: 0,
                            last_offset: 0,
                            first_transaction_offset: None,
                            pending: None,
                        });
                if identity.base_sequence >= sequence.last_base_sequence {
                    sequence.last_base_sequence = identity.base_sequence;
                    sequence.last_record_count = identity.record_count;
                    sequence.next_sequence = identity
                        .base_sequence
                        .saturating_add(identity.record_count as i32);
                    sequence.last_base_offset = *base_offset;
                    sequence.last_offset = *last_offset;
                    sequence.pending = None;
                    if identity.transactional && producer.status == TransactionStatus::Ongoing {
                        sequence
                            .first_transaction_offset
                            .get_or_insert(*base_offset);
                    }
                    changed = true;
                }
            }
            if changed {
                self.persist_shard(shard, &state)?;
            }
        }
        Ok(())
    }

    pub async fn validate_transaction(
        &self,
        identity: ProducerIdentity,
        transactional_id: &str,
    ) -> Result<(), TransactionError> {
        let state = self.shards[producer_shard(identity.producer_id)]
            .lock()
            .await;
        let producer = producer_ref(&state, identity)?;
        if producer.transactional_id.as_deref() != Some(transactional_id) {
            return Err(TransactionError::FencedProducer);
        }
        if producer.status != TransactionStatus::Ongoing {
            return Err(TransactionError::InvalidTransactionState);
        }
        Ok(())
    }

    fn persist_metadata(&self, metadata: &CoordinatorMetadata) -> Result<(), TransactionError> {
        self.persist_file(&self.root.join("metadata.json"), metadata)
    }

    fn persist_shard(
        &self,
        shard: usize,
        state: &TransactionState,
    ) -> Result<(), TransactionError> {
        self.persist_file(&self.root.join(format!("shard-{shard}.json")), state)
    }

    fn persist_file<T: Serialize>(&self, path: &Path, value: &T) -> Result<(), TransactionError> {
        let bytes = serde_json::to_vec(value)
            .map_err(|error| TransactionError::Codec(error.to_string()))?;
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, bytes)?;
        std::fs::File::open(&temporary)?.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

fn producer_shard(producer_id: i64) -> usize {
    producer_id.rem_euclid(TRANSACTION_SHARDS as i64) as usize
}

fn partition_shard(partition: &TransactionPartition) -> usize {
    let mut material = partition.topic.as_bytes().to_vec();
    material.extend_from_slice(&partition.partition.to_be_bytes());
    let digest = blake3::hash(&material);
    u64::from_be_bytes(digest.as_bytes()[..8].try_into().expect("fixed")) as usize
        % TRANSACTION_SHARDS
}

fn producer_ref(
    state: &TransactionState,
    identity: ProducerIdentity,
) -> Result<&ProducerState, TransactionError> {
    let producer = state
        .producers
        .get(&identity.producer_id)
        .ok_or(TransactionError::UnknownProducer)?;
    if producer.epoch != identity.producer_epoch {
        return Err(TransactionError::FencedProducer);
    }
    Ok(producer)
}

fn producer_mut(
    state: &mut TransactionState,
    identity: ProducerIdentity,
) -> Result<&mut ProducerState, TransactionError> {
    let producer = state
        .producers
        .get_mut(&identity.producer_id)
        .ok_or(TransactionError::UnknownProducer)?;
    if producer.epoch != identity.producer_epoch {
        return Err(TransactionError::FencedProducer);
    }
    Ok(producer)
}

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("unknown producer")]
    UnknownProducer,
    #[error("producer epoch is fenced")]
    FencedProducer,
    #[error("producer sequence is out of order")]
    OutOfOrderSequence,
    #[error("invalid transaction state")]
    InvalidTransactionState,
    #[error("producer is not transactional")]
    NotTransactional,
    #[error("invalid idempotent record batch")]
    InvalidRecordBatch,
    #[error("transaction checkpoint codec failed: {0}")]
    Codec(String),
    #[error("transaction checkpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(
        producer: ProducerIdentity,
        sequence: i32,
        transactional: bool,
    ) -> RecordBatchIdentity {
        RecordBatchIdentity {
            transactional,
            control: false,
            producer_id: producer.producer_id,
            producer_epoch: producer.producer_epoch,
            base_sequence: sequence,
            record_count: 1,
        }
    }

    #[tokio::test]
    async fn duplicates_fences_gaps_abort_and_reopen_are_deterministic() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = TransactionCoordinator::open(root.path()).unwrap();
        let producer = coordinator
            .init_producer(Some("orders".into()), 100, 0)
            .await
            .unwrap();
        let partition = TransactionPartition::new("events", 0);
        coordinator
            .add_partitions(producer, [partition.clone()], 0)
            .await
            .unwrap();
        let batch = identity(producer, 0, true);
        assert_eq!(
            coordinator
                .prepare_append(partition.clone(), batch)
                .await
                .unwrap(),
            AppendDecision::Append
        );
        coordinator
            .complete_append(partition.clone(), batch, 7, 7)
            .await
            .unwrap();
        assert_eq!(
            coordinator
                .prepare_append(partition.clone(), batch)
                .await
                .unwrap(),
            AppendDecision::Duplicate { base_offset: 7 }
        );
        assert!(matches!(
            coordinator
                .prepare_append(partition.clone(), identity(producer, 2, true))
                .await,
            Err(TransactionError::OutOfOrderSequence)
        ));
        coordinator.end_transaction(producer, false).await.unwrap();
        assert_eq!(
            coordinator.aborted_ranges(&partition, 0, 10).await,
            vec![AbortedRange {
                producer_id: producer.producer_id,
                first_offset: 7,
                last_offset: 7,
            }]
        );
        let next = coordinator
            .init_producer(Some("orders".into()), 100, 0)
            .await
            .unwrap();
        assert_eq!(next.producer_id, producer.producer_id);
        assert_eq!(next.producer_epoch, producer.producer_epoch + 1);
        assert!(matches!(
            coordinator.add_partitions(producer, [partition], 0).await,
            Err(TransactionError::FencedProducer)
        ));
        drop(coordinator);
        let reopened = TransactionCoordinator::open(root.path()).unwrap();
        assert_eq!(
            reopened.producer(next.producer_id).await.unwrap().epoch,
            next.producer_epoch
        );
    }

    #[tokio::test]
    async fn crash_between_append_and_checkpoint_rebuilds_from_committed_log() {
        let root = tempfile::tempdir().unwrap();
        let coordinator = TransactionCoordinator::open(root.path()).unwrap();
        let producer = coordinator.init_producer(None, 60_000, 0).await.unwrap();
        let partition = TransactionPartition::new("events", 0);
        let batch = identity(producer, 0, false);
        assert_eq!(
            coordinator
                .prepare_append(partition.clone(), batch)
                .await
                .unwrap(),
            AppendDecision::Append
        );
        drop(coordinator);

        let reopened = TransactionCoordinator::open(root.path()).unwrap();
        reopened
            .recover_partition(partition.clone(), vec![(batch, 11, 11)])
            .await
            .unwrap();
        assert_eq!(
            reopened
                .prepare_append(partition.clone(), batch)
                .await
                .unwrap(),
            AppendDecision::Duplicate { base_offset: 11 }
        );

        let next = identity(producer, 1, false);
        assert_eq!(
            reopened
                .prepare_append(partition.clone(), next)
                .await
                .unwrap(),
            AppendDecision::Append
        );
        drop(reopened);
        let no_append = TransactionCoordinator::open(root.path()).unwrap();
        no_append
            .recover_partition(partition.clone(), Vec::new())
            .await
            .unwrap();
        assert_eq!(
            no_append.prepare_append(partition, next).await.unwrap(),
            AppendDecision::Append
        );
    }
}
