// SPDX-License-Identifier: Apache-2.0

//! Product-neutral ordered logs over Pepper extents.
//!
//! The control plane owns assignments, epochs, and the committed prefix. This
//! crate owns original record bytes, logical offsets, sparse indexes, segment
//! lifecycle, and replica recovery. Record bytes are appended exactly once to
//! each replica's retained extent; they are never copied into a second
//! consensus log.

use pepper_buffer::{BufferChain, OwnedBuffer};
use pepper_extent::{
    AppendPlan, ExtentError, ExtentId, ExtentStore, RangeRead, RecordId, ReplacementRecord,
    SealedExtent,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use thiserror::Error;

const RECORD_ID_MAGIC: &[u8; 8] = b"PEPLOG01";
const RECORD_ID_BYTES: usize = 64;
pub type Offset = u64;
pub type Epoch = u64;
pub type NodeId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderedLogConfig {
    pub partition_key: [u8; 16],
    pub sparse_index_stride: u32,
    pub maximum_segment_bytes: u64,
    pub maximum_segment_batches: u64,
}

impl Default for OrderedLogConfig {
    fn default() -> Self {
        Self {
            partition_key: [0; 16],
            sparse_index_stride: 256,
            maximum_segment_bytes: 1024 * 1024 * 1024,
            maximum_segment_batches: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecoveryState {
    pub promised_epoch: Epoch,
    /// Exclusive committed offset supplied by the authoritative control RSM.
    pub high_watermark: Offset,
    pub log_start_offset: Offset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseIndexEntry {
    pub base_offset: Offset,
    pub extent_id: ExtentId,
    pub record_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSegmentManifest {
    pub extent_id: ExtentId,
    pub base_offset: Offset,
    pub end_offset: Offset,
    pub batch_count: u64,
    pub payload_bytes: u64,
    pub minimum_timestamp_ms: u64,
    pub maximum_timestamp_ms: u64,
    pub maximum_epoch: Epoch,
    pub extent_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendResult {
    pub base_offset: Offset,
    pub last_offset: Offset,
    pub leader_epoch: Epoch,
    pub high_watermark: Offset,
    pub durable_media_appends: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedBatch {
    pub base_offset: Offset,
    pub last_offset: Offset,
    pub leader_epoch: Epoch,
    pub timestamp_ms: u64,
    pub bytes: OwnedBuffer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResult {
    pub batches: Vec<FetchedBatch>,
    pub high_watermark: Offset,
    pub log_start_offset: Offset,
    pub log_end_offset: Offset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionResult {
    pub replaced: SealedSegmentManifest,
    pub replacement: SealedSegmentManifest,
    pub input_batches: u64,
    pub retained_batches: u64,
    pub reclaimed_payload_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicaProgress {
    pub promised_epoch: Epoch,
    pub leader_epoch: Option<Epoch>,
    pub log_start_offset: Offset,
    pub high_watermark: Offset,
    pub log_end_offset: Offset,
    pub lag: Offset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub retain_after_timestamp_ms: Option<u64>,
    pub maximum_sealed_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCommand {
    pub partition_key: [u8; 16],
    pub controller_epoch: Epoch,
    pub leader_epoch: Epoch,
    pub truncate_to: Offset,
    pub authenticator: [u8; 32],
}

#[derive(Clone)]
pub struct RecoveryAuthority {
    key: [u8; 32],
}

impl RecoveryAuthority {
    pub const fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn issue(
        &self,
        partition_key: [u8; 16],
        controller_epoch: Epoch,
        leader_epoch: Epoch,
        truncate_to: Offset,
    ) -> RecoveryCommand {
        RecoveryCommand {
            partition_key,
            controller_epoch,
            leader_epoch,
            truncate_to,
            authenticator: recovery_authenticator(
                &self.key,
                partition_key,
                controller_epoch,
                leader_epoch,
                truncate_to,
            ),
        }
    }
}

#[derive(Debug, Clone)]
struct BatchLocation {
    base_offset: Offset,
    last_offset: Offset,
    epoch: Epoch,
    timestamp_ms: u64,
    extent_id: ExtentId,
    record_index: u64,
    encoded_len: u64,
}

#[derive(Debug, Clone)]
struct SegmentState {
    extent_id: ExtentId,
    base_offset: Offset,
    payload_bytes: u64,
    batches: Vec<BatchLocation>,
    sealed: Option<SealedSegmentManifest>,
}

impl SegmentState {
    fn end_offset(&self) -> Offset {
        self.batches.last().map_or(self.base_offset, |batch| {
            batch.last_offset.saturating_add(1)
        })
    }
}

#[derive(Debug)]
struct LogState {
    segments: Vec<SegmentState>,
    sparse_index: Vec<SparseIndexEntry>,
    promised_epoch: Epoch,
    leader_epoch: Option<Epoch>,
    controller_epoch: Epoch,
    high_watermark: Offset,
    log_start_offset: Offset,
    next_offset: Offset,
    total_batches: u64,
}

/// One partition replica. A replica directory should contain extents for only
/// one partition key; this keeps extent ownership and recovery unambiguous.
pub struct OrderedLog {
    store: Arc<dyn ExtentStore>,
    config: OrderedLogConfig,
    state: Mutex<LogState>,
}

impl OrderedLog {
    pub fn open(
        store: Arc<dyn ExtentStore>,
        config: OrderedLogConfig,
        recovery: RecoveryState,
    ) -> Result<Self, OrderedLogError> {
        validate_config(config)?;
        let mut segments = Vec::new();
        for extent_id in store.extent_ids()? {
            let inspection = store.recover(extent_id)?;
            let sealed_digest = inspection.digest;
            let mut batches = Vec::with_capacity(inspection.records.len());
            for record in inspection.records {
                let identity = decode_record_id(record.record_id.as_bytes())?;
                if identity.partition_key != config.partition_key {
                    return Err(OrderedLogError::ForeignPartition(extent_id));
                }
                batches.push(BatchLocation {
                    base_offset: identity.base_offset,
                    last_offset: identity.last_offset,
                    epoch: identity.epoch,
                    timestamp_ms: identity.timestamp_ms,
                    extent_id,
                    record_index: record.record_index,
                    encoded_len: record.encoded_len,
                });
            }
            validate_contiguous_batches(&batches)?;
            let base_offset = batches.first().map_or(0, |batch| batch.base_offset);
            let payload_bytes = batches.iter().map(|batch| batch.encoded_len).sum();
            let sealed = inspection.sealed.then(|| {
                manifest_from_inspection(
                    extent_id,
                    base_offset,
                    &batches,
                    payload_bytes,
                    sealed_digest.expect("sealed inspection carries a digest"),
                )
            });
            segments.push(SegmentState {
                extent_id,
                base_offset,
                payload_bytes,
                batches,
                sealed,
            });
        }
        segments.sort_by_key(|segment| {
            (
                segment.batches.is_empty(),
                segment.base_offset,
                segment.extent_id,
            )
        });
        validate_segments(&segments)?;
        if segments.is_empty() {
            segments.push(SegmentState {
                extent_id: store.create()?,
                base_offset: recovery.high_watermark,
                payload_bytes: 0,
                batches: Vec::new(),
                sealed: None,
            });
        }
        let unsealed = segments
            .iter()
            .enumerate()
            .filter(|(_, segment)| segment.sealed.is_none())
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if unsealed.len() != 1 {
            return Err(OrderedLogError::ActiveExtentCount(unsealed.len()));
        }
        if unsealed[0] + 1 != segments.len() {
            let active = segments.remove(unsealed[0]);
            segments.push(active);
        }
        if segments
            .last()
            .is_some_and(|active| active.batches.is_empty())
        {
            let inferred_base = segments
                .iter()
                .rev()
                .skip(1)
                .find(|segment| !segment.batches.is_empty())
                .map_or(recovery.high_watermark, SegmentState::end_offset);
            if let Some(active) = segments.last_mut() {
                active.base_offset = inferred_base;
            }
        }

        let next_offset = segments
            .iter()
            .flat_map(|segment| segment.batches.iter())
            .last()
            .map_or(recovery.high_watermark, |batch| batch.last_offset + 1);
        if recovery.high_watermark > next_offset
            || recovery.log_start_offset > recovery.high_watermark
        {
            return Err(OrderedLogError::InvalidRecoveryPoint {
                log_start: recovery.log_start_offset,
                high_watermark: recovery.high_watermark,
                log_end: next_offset,
            });
        }
        if segments
            .iter()
            .filter(|segment| segment.sealed.is_some())
            .any(|segment| segment.end_offset() > recovery.high_watermark)
        {
            return Err(OrderedLogError::UncommittedSealedSegment);
        }
        let mut state = LogState {
            segments,
            sparse_index: Vec::new(),
            promised_epoch: recovery.promised_epoch,
            leader_epoch: None,
            controller_epoch: recovery.promised_epoch,
            high_watermark: recovery.high_watermark,
            log_start_offset: recovery.log_start_offset,
            next_offset,
            total_batches: 0,
        };
        truncate_active_to(&*store, &mut state, recovery.high_watermark)?;
        rebuild_sparse_index(&mut state, config.sparse_index_stride);
        Ok(Self {
            store,
            config,
            state: Mutex::new(state),
        })
    }

    pub fn promise_epoch(
        &self,
        controller_epoch: Epoch,
        epoch: Epoch,
    ) -> Result<(), OrderedLogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OrderedLogError::LockPoisoned)?;
        if controller_epoch < state.controller_epoch || epoch <= state.promised_epoch {
            return Err(OrderedLogError::StaleEpoch {
                promised: state.promised_epoch,
                supplied: epoch,
            });
        }
        state.controller_epoch = controller_epoch;
        state.promised_epoch = epoch;
        state.leader_epoch = None;
        Ok(())
    }

    pub fn activate_leader(
        &self,
        controller_epoch: Epoch,
        epoch: Epoch,
    ) -> Result<(), OrderedLogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OrderedLogError::LockPoisoned)?;
        if controller_epoch != state.controller_epoch || epoch != state.promised_epoch {
            return Err(OrderedLogError::StaleEpoch {
                promised: state.promised_epoch,
                supplied: epoch,
            });
        }
        state.leader_epoch = Some(epoch);
        Ok(())
    }

    pub fn append(
        &self,
        epoch: Epoch,
        timestamp_ms: u64,
        record_count: u32,
        payload: BufferChain,
    ) -> Result<AppendResult, OrderedLogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OrderedLogError::LockPoisoned)?;
        if state.leader_epoch != Some(epoch) || state.promised_epoch != epoch {
            return Err(OrderedLogError::StaleEpoch {
                promised: state.promised_epoch,
                supplied: epoch,
            });
        }
        let base_offset = state.next_offset;
        append_assigned(
            &*self.store,
            self.config,
            &mut state,
            epoch,
            base_offset,
            timestamp_ms,
            record_count,
            payload,
        )
    }

    pub fn replicate(
        &self,
        epoch: Epoch,
        base_offset: Offset,
        timestamp_ms: u64,
        record_count: u32,
        payload: BufferChain,
    ) -> Result<AppendResult, OrderedLogError> {
        self.replicate_with_identity(
            epoch,
            epoch,
            base_offset,
            timestamp_ms,
            record_count,
            payload,
        )
    }

    fn replicate_with_identity(
        &self,
        command_epoch: Epoch,
        record_epoch: Epoch,
        base_offset: Offset,
        timestamp_ms: u64,
        record_count: u32,
        payload: BufferChain,
    ) -> Result<AppendResult, OrderedLogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OrderedLogError::LockPoisoned)?;
        if state.promised_epoch != command_epoch {
            return Err(OrderedLogError::StaleEpoch {
                promised: state.promised_epoch,
                supplied: command_epoch,
            });
        }
        append_assigned(
            &*self.store,
            self.config,
            &mut state,
            record_epoch,
            base_offset,
            timestamp_ms,
            record_count,
            payload,
        )
    }

    pub fn commit(&self, epoch: Epoch, high_watermark: Offset) -> Result<(), OrderedLogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OrderedLogError::LockPoisoned)?;
        if state.promised_epoch != epoch {
            return Err(OrderedLogError::StaleEpoch {
                promised: state.promised_epoch,
                supplied: epoch,
            });
        }
        if high_watermark < state.high_watermark
            || high_watermark > state.next_offset
            || !is_batch_boundary(&state, high_watermark)
        {
            return Err(OrderedLogError::InvalidCommit(high_watermark));
        }
        state.high_watermark = high_watermark;
        Ok(())
    }

    pub fn fetch(
        &self,
        offset: Offset,
        maximum_bytes: u64,
        committed_only: bool,
    ) -> Result<FetchResult, OrderedLogError> {
        let state = self
            .state
            .lock()
            .map_err(|_| OrderedLogError::LockPoisoned)?;
        if offset < state.log_start_offset {
            return Err(OrderedLogError::OffsetBeforeLogStart {
                offset,
                log_start: state.log_start_offset,
            });
        }
        let visible_end = if committed_only {
            state.high_watermark
        } else {
            state.next_offset
        };
        let mut locations = Vec::new();
        let mut bytes = 0u64;
        let first_segment = state
            .segments
            .partition_point(|segment| segment.end_offset() <= offset);
        'segments: for (segment_index, segment) in
            state.segments.iter().enumerate().skip(first_segment)
        {
            let first_batch = if segment_index == first_segment {
                segment
                    .batches
                    .partition_point(|batch| batch.last_offset < offset)
            } else {
                0
            };
            for batch in segment.batches.iter().skip(first_batch) {
                if batch.last_offset >= visible_end {
                    break 'segments;
                }
                if !locations.is_empty() && bytes.saturating_add(batch.encoded_len) > maximum_bytes
                {
                    break 'segments;
                }
                bytes = bytes.saturating_add(batch.encoded_len);
                locations.push(batch.clone());
            }
        }
        let requests = locations
            .iter()
            .map(|batch| RangeRead {
                extent_id: batch.extent_id,
                record_index: batch.record_index,
                offset: 0,
                length: batch.encoded_len,
            })
            .collect::<Vec<_>>();
        let buffers = self.store.read_vectored(&requests)?;
        let batches = locations
            .into_iter()
            .zip(buffers)
            .map(|(location, bytes)| FetchedBatch {
                base_offset: location.base_offset,
                last_offset: location.last_offset,
                leader_epoch: location.epoch,
                timestamp_ms: location.timestamp_ms,
                bytes,
            })
            .collect();
        Ok(FetchResult {
            batches,
            high_watermark: state.high_watermark,
            log_start_offset: state.log_start_offset,
            log_end_offset: state.next_offset,
        })
    }

    pub fn seal_and_rotate(&self, epoch: Epoch) -> Result<SealedSegmentManifest, OrderedLogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OrderedLogError::LockPoisoned)?;
        if state.promised_epoch != epoch || state.leader_epoch != Some(epoch) {
            return Err(OrderedLogError::StaleEpoch {
                promised: state.promised_epoch,
                supplied: epoch,
            });
        }
        rotate_active(&*self.store, &mut state)
    }

    pub fn truncate(
        &self,
        authority: &RecoveryAuthority,
        command: &RecoveryCommand,
    ) -> Result<(), OrderedLogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OrderedLogError::LockPoisoned)?;
        if command.partition_key != self.config.partition_key
            || command.controller_epoch != state.controller_epoch
            || command.leader_epoch != state.promised_epoch
            || command.authenticator
                != recovery_authenticator(
                    &authority.key,
                    command.partition_key,
                    command.controller_epoch,
                    command.leader_epoch,
                    command.truncate_to,
                )
        {
            return Err(OrderedLogError::UnauthenticatedRecovery);
        }
        if command.truncate_to < state.high_watermark {
            return Err(OrderedLogError::CommittedTruncation {
                requested: command.truncate_to,
                high_watermark: state.high_watermark,
            });
        }
        truncate_active_to(&*self.store, &mut state, command.truncate_to)?;
        rebuild_sparse_index(&mut state, self.config.sparse_index_stride);
        Ok(())
    }

    pub fn sealed_manifests(&self) -> Result<Vec<SealedSegmentManifest>, OrderedLogError> {
        let state = self
            .state
            .lock()
            .map_err(|_| OrderedLogError::LockPoisoned)?;
        Ok(state
            .segments
            .iter()
            .filter_map(|segment| segment.sealed.clone())
            .collect())
    }

    /// Produce a stable logical image for immutable cold placement. Extent
    /// headers and alignment padding are excluded; original record bytes and
    /// Kafka offsets are retained.
    pub fn sealed_segment_image(&self, extent_id: ExtentId) -> Result<Vec<u8>, OrderedLogError> {
        let state = self
            .state
            .lock()
            .map_err(|_| OrderedLogError::LockPoisoned)?;
        let segment = state
            .segments
            .iter()
            .find(|segment| segment.extent_id == extent_id)
            .ok_or(OrderedLogError::UnknownExtent(extent_id))?;
        if segment.sealed.is_none() {
            return Err(OrderedLogError::ActiveCompaction);
        }
        let requests = segment
            .batches
            .iter()
            .map(|batch| RangeRead {
                extent_id,
                record_index: batch.record_index,
                offset: 0,
                length: batch.encoded_len,
            })
            .collect::<Vec<_>>();
        let buffers = self.store.read_vectored(&requests)?;
        let capacity = segment
            .payload_bytes
            .checked_add(16)
            .and_then(|bytes| bytes.checked_add((segment.batches.len() as u64).saturating_mul(44)))
            .and_then(|bytes| usize::try_from(bytes).ok())
            .ok_or(OrderedLogError::ImageTooLarge)?;
        let mut image = Vec::with_capacity(capacity);
        image.extend_from_slice(b"PEPKCOLD");
        image.extend_from_slice(&(segment.batches.len() as u64).to_le_bytes());
        for (batch, buffer) in segment.batches.iter().zip(buffers) {
            image.extend_from_slice(&batch.base_offset.to_le_bytes());
            image.extend_from_slice(&batch.last_offset.to_le_bytes());
            image.extend_from_slice(&batch.epoch.to_le_bytes());
            image.extend_from_slice(&batch.timestamp_ms.to_le_bytes());
            image.extend_from_slice(&batch.encoded_len.to_le_bytes());
            image.extend_from_slice(buffer.bytes());
        }
        Ok(image)
    }

    /// Rewrite one committed sealed segment while preserving surviving logical
    /// offsets. The first and last batches are retained as offset-span anchors,
    /// even when the product cleaner does not select them.
    pub fn compact_sealed(
        &self,
        extent_id: ExtentId,
        retained_base_offsets: &BTreeSet<Offset>,
    ) -> Result<CompactionResult, OrderedLogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OrderedLogError::LockPoisoned)?;
        let segment_index = state
            .segments
            .iter()
            .position(|segment| segment.extent_id == extent_id)
            .ok_or(OrderedLogError::UnknownExtent(extent_id))?;
        let segment = state.segments[segment_index].clone();
        let replaced = segment
            .sealed
            .clone()
            .ok_or(OrderedLogError::ActiveCompaction)?;
        if segment.end_offset() > state.high_watermark {
            return Err(OrderedLogError::UncommittedSealedSegment);
        }
        let first = segment.batches.first().map(|batch| batch.base_offset);
        let last = segment.batches.last().map(|batch| batch.base_offset);
        let retained = segment
            .batches
            .iter()
            .filter(|batch| {
                retained_base_offsets.contains(&batch.base_offset)
                    || Some(batch.base_offset) == first
                    || Some(batch.base_offset) == last
            })
            .cloned()
            .collect::<Vec<_>>();
        if retained.len() == segment.batches.len() {
            return Ok(CompactionResult {
                replaced: replaced.clone(),
                replacement: replaced,
                input_batches: segment.batches.len() as u64,
                retained_batches: retained.len() as u64,
                reclaimed_payload_bytes: 0,
            });
        }
        let reads = retained
            .iter()
            .map(|batch| RangeRead {
                extent_id: batch.extent_id,
                record_index: batch.record_index,
                offset: 0,
                length: batch.encoded_len,
            })
            .collect::<Vec<_>>();
        let buffers = self.store.read_vectored(&reads)?;
        let records = retained
            .iter()
            .zip(buffers)
            .map(|(batch, buffer)| {
                Ok(ReplacementRecord {
                    record_id: encode_record_id(RecordIdentity {
                        partition_key: self.config.partition_key,
                        epoch: batch.epoch,
                        base_offset: batch.base_offset,
                        last_offset: batch.last_offset,
                        timestamp_ms: batch.timestamp_ms,
                    })?,
                    logical_len: buffer.logical_len(),
                    checksum: buffer.checksum(),
                    payload: buffer.into(),
                    metadata: Default::default(),
                })
            })
            .collect::<Result<Vec<_>, OrderedLogError>>()?;
        let sealed = self.store.replace_sealed(extent_id, records)?;
        let replacement_batches = retained
            .into_iter()
            .enumerate()
            .map(|(record_index, mut batch)| {
                batch.extent_id = sealed.extent_id;
                batch.record_index = record_index as u64;
                batch
            })
            .collect::<Vec<_>>();
        let replacement_bytes = replacement_batches
            .iter()
            .map(|batch| batch.encoded_len)
            .sum();
        let replacement = manifest_from_inspection(
            sealed.extent_id,
            segment.base_offset,
            &replacement_batches,
            replacement_bytes,
            sealed.digest,
        );
        state.total_batches = state
            .total_batches
            .saturating_sub(segment.batches.len() as u64)
            .saturating_add(replacement_batches.len() as u64);
        state.segments[segment_index] = SegmentState {
            extent_id: sealed.extent_id,
            base_offset: segment.base_offset,
            payload_bytes: replacement_bytes,
            batches: replacement_batches,
            sealed: Some(replacement.clone()),
        };
        rebuild_sparse_index(&mut state, self.config.sparse_index_stride);
        Ok(CompactionResult {
            replaced,
            replacement,
            input_batches: segment.batches.len() as u64,
            retained_batches: state.segments[segment_index].batches.len() as u64,
            reclaimed_payload_bytes: segment.payload_bytes.saturating_sub(replacement_bytes),
        })
    }

    /// Returns candidates for a later epoch-fenced catalog transition. It
    /// never reclaims physical bytes itself.
    pub fn retention_candidates(
        &self,
        policy: RetentionPolicy,
    ) -> Result<Vec<SealedSegmentManifest>, OrderedLogError> {
        let manifests = self.sealed_manifests()?;
        let mut retained = manifests
            .iter()
            .map(|manifest| manifest.payload_bytes)
            .sum::<u64>();
        let mut candidates = Vec::new();
        for manifest in manifests {
            let expired = policy
                .retain_after_timestamp_ms
                .is_some_and(|cutoff| manifest.maximum_timestamp_ms < cutoff);
            let oversized = policy
                .maximum_sealed_bytes
                .is_some_and(|maximum| retained > maximum);
            if expired || oversized {
                retained = retained.saturating_sub(manifest.payload_bytes);
                candidates.push(manifest);
            }
        }
        Ok(candidates)
    }

    pub fn advance_log_start(
        &self,
        controller_epoch: Epoch,
        offset: Offset,
    ) -> Result<(), OrderedLogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OrderedLogError::LockPoisoned)?;
        if controller_epoch != state.controller_epoch
            || offset < state.log_start_offset
            || offset > state.high_watermark
            || !state
                .segments
                .iter()
                .any(|segment| segment.sealed.is_some() && segment.end_offset() == offset)
        {
            return Err(OrderedLogError::InvalidLogStart(offset));
        }
        state.log_start_offset = offset;
        Ok(())
    }

    /// Reclaim whole sealed extents made unreachable by a previously durable
    /// log-start transition. The active extent and every visible offset are
    /// retained. A leased extent returns an error and is retried later.
    pub fn reclaim_below_log_start(&self) -> Result<Vec<SealedSegmentManifest>, OrderedLogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OrderedLogError::LockPoisoned)?;
        let mut reclaimed = Vec::new();
        loop {
            let candidate = state.segments.first().and_then(|segment| {
                segment.sealed.as_ref().filter(|manifest| {
                    manifest.end_offset <= state.log_start_offset
                        && manifest.end_offset <= state.high_watermark
                })
            });
            let Some(manifest) = candidate.cloned() else {
                break;
            };
            self.store.reclaim(manifest.extent_id)?;
            state.segments.remove(0);
            state.total_batches = state.total_batches.saturating_sub(manifest.batch_count);
            reclaimed.push(manifest);
        }
        if !reclaimed.is_empty() {
            rebuild_sparse_index(&mut state, self.config.sparse_index_stride);
        }
        Ok(reclaimed)
    }

    pub fn progress(&self, leader_end: Offset) -> Result<ReplicaProgress, OrderedLogError> {
        let state = self
            .state
            .lock()
            .map_err(|_| OrderedLogError::LockPoisoned)?;
        Ok(ReplicaProgress {
            promised_epoch: state.promised_epoch,
            leader_epoch: state.leader_epoch,
            log_start_offset: state.log_start_offset,
            high_watermark: state.high_watermark,
            log_end_offset: state.next_offset,
            lag: leader_end.saturating_sub(state.next_offset),
        })
    }

    pub fn sparse_index(&self) -> Result<Vec<SparseIndexEntry>, OrderedLogError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| OrderedLogError::LockPoisoned)?
            .sparse_index
            .clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acknowledgments {
    None,
    Leader,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicatedAppend {
    pub result: AppendResult,
    pub durable_replicas: BTreeSet<NodeId>,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicationStatus {
    pub assignment: BTreeSet<NodeId>,
    pub in_sync_replicas: BTreeSet<NodeId>,
    pub online_replicas: BTreeSet<NodeId>,
    pub leader: NodeId,
    pub leader_epoch: Epoch,
    pub controller_epoch: Epoch,
    pub high_watermark: Offset,
    pub minimum_isr: usize,
}

/// The selected production replication shape: a small epoch/assignment
/// control state fences direct leader-to-follower appends. The retained extent
/// is the only durable record-byte log on each replica.
pub struct ReplicatedPartition {
    replicas: BTreeMap<NodeId, Arc<OrderedLog>>,
    assignment: BTreeSet<NodeId>,
    isr: BTreeSet<NodeId>,
    online: BTreeSet<NodeId>,
    leader: NodeId,
    epoch: Epoch,
    controller_epoch: Epoch,
    minimum_isr: usize,
    high_watermark: Offset,
}

impl ReplicatedPartition {
    pub fn new(
        replicas: BTreeMap<NodeId, Arc<OrderedLog>>,
        leader: NodeId,
        epoch: Epoch,
        controller_epoch: Epoch,
        minimum_isr: usize,
    ) -> Result<Self, OrderedLogError> {
        if replicas.is_empty()
            || !replicas.contains_key(&leader)
            || minimum_isr == 0
            || minimum_isr > replicas.len()
        {
            return Err(OrderedLogError::InvalidReplicaSet);
        }
        let assignment = replicas.keys().copied().collect::<BTreeSet<_>>();
        for replica in replicas.values() {
            replica.promise_epoch(controller_epoch, epoch)?;
        }
        replicas
            .get(&leader)
            .ok_or(OrderedLogError::UnknownReplica(leader))?
            .activate_leader(controller_epoch, epoch)?;
        let high_watermark = replicas
            .get(&leader)
            .ok_or(OrderedLogError::UnknownReplica(leader))?
            .progress(0)?
            .high_watermark;
        Ok(Self {
            replicas,
            assignment: assignment.clone(),
            isr: assignment.clone(),
            online: assignment,
            leader,
            epoch,
            controller_epoch,
            minimum_isr,
            high_watermark,
        })
    }

    pub fn append(
        &mut self,
        claimed_leader: NodeId,
        claimed_epoch: Epoch,
        timestamp_ms: u64,
        record_count: u32,
        payload: BufferChain,
        acknowledgments: Acknowledgments,
    ) -> Result<ReplicatedAppend, OrderedLogError> {
        if claimed_leader != self.leader || claimed_epoch != self.epoch {
            return Err(OrderedLogError::StaleLeader);
        }
        if !self.online.contains(&self.leader) {
            return Err(OrderedLogError::ReplicaOffline(self.leader));
        }
        let result = self
            .replicas
            .get(&self.leader)
            .ok_or(OrderedLogError::UnknownReplica(self.leader))?
            .append(self.epoch, timestamp_ms, record_count, payload.clone())?;
        let mut durable = BTreeSet::from([self.leader]);
        for follower in self
            .isr
            .iter()
            .copied()
            .filter(|node| *node != self.leader && self.online.contains(node))
        {
            if self
                .replicas
                .get(&follower)
                .ok_or(OrderedLogError::UnknownReplica(follower))?
                .replicate(
                    self.epoch,
                    result.base_offset,
                    timestamp_ms,
                    record_count,
                    payload.clone(),
                )
                .is_ok()
            {
                durable.insert(follower);
            }
        }
        let commit_eligible = durable.len() >= self.minimum_isr;
        if commit_eligible {
            let high_watermark = result.last_offset + 1;
            for node in &durable {
                self.replicas
                    .get(node)
                    .ok_or(OrderedLogError::UnknownReplica(*node))?
                    .commit(self.epoch, high_watermark)?;
            }
            self.high_watermark = high_watermark;
        }
        let acknowledged = match acknowledgments {
            Acknowledgments::None | Acknowledgments::Leader => true,
            Acknowledgments::All => {
                commit_eligible && self.isr.iter().all(|node| durable.contains(node))
            }
        };
        Ok(ReplicatedAppend {
            result: AppendResult {
                high_watermark: if commit_eligible {
                    result.last_offset + 1
                } else {
                    result.high_watermark
                },
                durable_media_appends: durable.len() as u64,
                ..result
            },
            durable_replicas: durable,
            acknowledged,
        })
    }

    pub fn elect(
        &mut self,
        candidate: NodeId,
        new_epoch: Epoch,
        new_controller_epoch: Epoch,
        voters: &BTreeSet<NodeId>,
    ) -> Result<(), OrderedLogError> {
        let quorum = self.assignment.len() / 2 + 1;
        if new_epoch <= self.epoch
            || new_controller_epoch < self.controller_epoch
            || voters.len() < quorum
            || !voters.contains(&candidate)
            || !voters
                .iter()
                .all(|node| self.assignment.contains(node) && self.online.contains(node))
        {
            return Err(OrderedLogError::NoQuorum);
        }
        let committed = self.high_watermark;
        for node in voters {
            self.replicas
                .get(node)
                .ok_or(OrderedLogError::UnknownReplica(*node))?
                .promise_epoch(new_controller_epoch, new_epoch)?;
        }
        let source = voters
            .iter()
            .copied()
            .max_by_key(|node| {
                self.replicas
                    .get(node)
                    .and_then(|replica| replica.progress(0).ok())
                    .map_or(0, |progress| progress.log_end_offset)
            })
            .ok_or(OrderedLogError::NoQuorum)?;
        self.catch_up(source, candidate, committed, new_epoch)?;
        self.replicas
            .get(&candidate)
            .ok_or(OrderedLogError::UnknownReplica(candidate))?
            .activate_leader(new_controller_epoch, new_epoch)?;
        self.leader = candidate;
        self.epoch = new_epoch;
        self.controller_epoch = new_controller_epoch;
        self.isr = voters.clone();
        Ok(())
    }

    fn catch_up(
        &self,
        source: NodeId,
        target: NodeId,
        through: Offset,
        epoch: Epoch,
    ) -> Result<(), OrderedLogError> {
        if source == target {
            if self
                .replicas
                .get(&target)
                .ok_or(OrderedLogError::UnknownReplica(target))?
                .progress(through)?
                .log_end_offset
                < through
            {
                return Err(OrderedLogError::MissingCommittedPrefix);
            }
            return Ok(());
        }
        let target_log = self
            .replicas
            .get(&target)
            .ok_or(OrderedLogError::UnknownReplica(target))?;
        let target_end = target_log.progress(through)?.log_end_offset;
        if target_end > through {
            return Err(OrderedLogError::DivergentReplica);
        }
        let fetched = self
            .replicas
            .get(&source)
            .ok_or(OrderedLogError::UnknownReplica(source))?
            .fetch(target_end, u64::MAX, false)?;
        for batch in fetched
            .batches
            .into_iter()
            .filter(|batch| batch.last_offset < through)
        {
            let count = u32::try_from(batch.last_offset - batch.base_offset + 1)
                .map_err(|_| OrderedLogError::OffsetOverflow)?;
            target_log.replicate_with_identity(
                epoch,
                batch.leader_epoch,
                batch.base_offset,
                batch.timestamp_ms,
                count,
                BufferChain::from(batch.bytes),
            )?;
        }
        target_log.commit(epoch, through)?;
        Ok(())
    }

    pub fn set_online(&mut self, node: NodeId, online: bool) -> Result<(), OrderedLogError> {
        if !self.assignment.contains(&node) {
            return Err(OrderedLogError::UnknownReplica(node));
        }
        if online {
            self.online.insert(node);
        } else {
            self.online.remove(&node);
        }
        Ok(())
    }

    pub fn add_replica(
        &mut self,
        node: NodeId,
        replica: Arc<OrderedLog>,
    ) -> Result<(), OrderedLogError> {
        if self.replicas.contains_key(&node) {
            return Err(OrderedLogError::ReplicaAlreadyExists(node));
        }
        // A new empty replica may already carry the current promise from its
        // recovery state, so advance only when necessary.
        let progress = replica.progress(0)?;
        if progress.promised_epoch < self.epoch {
            replica.promise_epoch(self.controller_epoch, self.epoch)?;
        } else if progress.promised_epoch > self.epoch {
            return Err(OrderedLogError::StaleLeader);
        }
        self.replicas.insert(node, replica);
        self.assignment.insert(node);
        self.online.insert(node);
        let committed = self.high_watermark;
        self.catch_up(self.leader, node, committed, self.epoch)?;
        self.isr.insert(node);
        Ok(())
    }

    pub fn remove_replica(&mut self, node: NodeId) -> Result<(), OrderedLogError> {
        if node == self.leader
            || !self.assignment.contains(&node)
            || self
                .isr
                .len()
                .saturating_sub(usize::from(self.isr.contains(&node)))
                < self.minimum_isr
        {
            return Err(OrderedLogError::UnsafeAssignmentChange(node));
        }
        self.isr.remove(&node);
        self.assignment.remove(&node);
        self.online.remove(&node);
        Ok(())
    }

    pub fn recover_replica(&mut self, node: NodeId) -> Result<(), OrderedLogError> {
        if !self.assignment.contains(&node) {
            return Err(OrderedLogError::UnknownReplica(node));
        }
        self.online.insert(node);
        self.catch_up(self.leader, node, self.high_watermark, self.epoch)?;
        self.isr.insert(node);
        Ok(())
    }

    pub fn reconfigure(
        &mut self,
        assignment: BTreeSet<NodeId>,
        new_epoch: Epoch,
        new_controller_epoch: Epoch,
    ) -> Result<(), OrderedLogError> {
        if assignment.len() < self.minimum_isr
            || !assignment.contains(&self.leader)
            || !assignment
                .iter()
                .all(|node| self.replicas.contains_key(node))
            || new_epoch <= self.epoch
            || new_controller_epoch <= self.controller_epoch
        {
            return Err(OrderedLogError::UnsafeAssignment);
        }
        let committed = self.high_watermark;
        for node in assignment.difference(&self.assignment).copied() {
            self.online.insert(node);
            self.catch_up(self.leader, node, committed, self.epoch)?;
        }
        for node in &assignment {
            self.replicas
                .get(node)
                .ok_or(OrderedLogError::UnknownReplica(*node))?
                .promise_epoch(new_controller_epoch, new_epoch)?;
        }
        self.replicas
            .get(&self.leader)
            .ok_or(OrderedLogError::UnknownReplica(self.leader))?
            .activate_leader(new_controller_epoch, new_epoch)?;
        self.assignment = assignment.clone();
        self.online.retain(|node| assignment.contains(node));
        self.isr = assignment
            .iter()
            .copied()
            .filter(|node| self.online.contains(node))
            .collect();
        self.epoch = new_epoch;
        self.controller_epoch = new_controller_epoch;
        Ok(())
    }

    pub fn status(&self) -> ReplicationStatus {
        ReplicationStatus {
            assignment: self.assignment.clone(),
            in_sync_replicas: self.isr.clone(),
            online_replicas: self.online.clone(),
            leader: self.leader,
            leader_epoch: self.epoch,
            controller_epoch: self.controller_epoch,
            high_watermark: self.high_watermark,
            minimum_isr: self.minimum_isr,
        }
    }

    pub const fn leader(&self) -> (NodeId, Epoch) {
        (self.leader, self.epoch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicationSpike {
    DirectLeaderFollower,
    DataBearingConsensus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpikeReport {
    pub candidate: ReplicationSpike,
    pub batches: u64,
    pub replicas: u64,
    pub durable_record_appends: u64,
    pub durable_record_bytes: u64,
    pub control_bytes: u64,
    pub durable_barriers: u64,
    pub record_copies_per_replica: u64,
}

/// Deterministic write-amplification accounting for both section 6.5 spikes.
/// The data-bearing candidate is valid only when its stable consensus log is
/// the retained extent, represented here by `single_write=true`.
pub fn replication_spike(
    candidate: ReplicationSpike,
    batches: u64,
    replicas: u64,
    bytes_per_batch: u64,
    single_write: bool,
) -> SpikeReport {
    let copies = if single_write { 1 } else { 2 };
    let durable_record_appends = batches.saturating_mul(replicas).saturating_mul(copies);
    let control_per_batch = match candidate {
        ReplicationSpike::DirectLeaderFollower => 40,
        ReplicationSpike::DataBearingConsensus => 96,
    };
    SpikeReport {
        candidate,
        batches,
        replicas,
        durable_record_appends,
        durable_record_bytes: durable_record_appends.saturating_mul(bytes_per_batch),
        control_bytes: batches.saturating_mul(control_per_batch),
        durable_barriers: durable_record_appends,
        record_copies_per_replica: copies,
    }
}

#[derive(Debug, Error)]
pub enum OrderedLogError {
    #[error("invalid ordered-log configuration: {0}")]
    InvalidConfiguration(String),
    #[error("extent operation failed: {0}")]
    Extent(#[from] ExtentError),
    #[error("ordered-log lock is poisoned")]
    LockPoisoned,
    #[error("extent {0} belongs to another partition")]
    ForeignPartition(ExtentId),
    #[error("record identity is malformed")]
    MalformedRecordIdentity,
    #[error("logical offsets are not contiguous")]
    OffsetGap,
    #[error("offset arithmetic overflow")]
    OffsetOverflow,
    #[error("expected exactly one active extent, found {0}")]
    ActiveExtentCount(usize),
    #[error(
        "invalid recovery point start={log_start}, high-watermark={high_watermark}, end={log_end}"
    )]
    InvalidRecoveryPoint {
        log_start: Offset,
        high_watermark: Offset,
        log_end: Offset,
    },
    #[error("a sealed segment contains uncommitted offsets")]
    UncommittedSealedSegment,
    #[error("stale epoch {supplied}; replica promised {promised}")]
    StaleEpoch { promised: Epoch, supplied: Epoch },
    #[error("record count must be nonzero")]
    EmptyRecordBatch,
    #[error("assigned base offset {supplied} does not match log end {expected}")]
    AssignedOffsetMismatch { expected: Offset, supplied: Offset },
    #[error("invalid committed offset {0}")]
    InvalidCommit(Offset),
    #[error("offset {offset} is before log start {log_start}")]
    OffsetBeforeLogStart { offset: Offset, log_start: Offset },
    #[error("only a fully committed active segment may be sealed")]
    UncommittedRotation,
    #[error("extent {0} is not part of this ordered log")]
    UnknownExtent(ExtentId),
    #[error("only a sealed segment may be compacted")]
    ActiveCompaction,
    #[error("sealed segment image is too large")]
    ImageTooLarge,
    #[error("recovery command authentication or epoch check failed")]
    UnauthenticatedRecovery,
    #[error("cannot truncate committed prefix to {requested}; high watermark is {high_watermark}")]
    CommittedTruncation {
        requested: Offset,
        high_watermark: Offset,
    },
    #[error("truncate offset {0} is not an active-segment batch boundary")]
    InvalidTruncateOffset(Offset),
    #[error("invalid log-start offset {0}")]
    InvalidLogStart(Offset),
    #[error("invalid replica set")]
    InvalidReplicaSet,
    #[error("unknown replica {0}")]
    UnknownReplica(NodeId),
    #[error("replica {0} is offline")]
    ReplicaOffline(NodeId),
    #[error("stale leader")]
    StaleLeader,
    #[error("no election quorum")]
    NoQuorum,
    #[error("candidate is missing the committed prefix")]
    MissingCommittedPrefix,
    #[error("replica has a divergent suffix and requires authenticated truncation")]
    DivergentReplica,
    #[error("replica {0} already exists")]
    ReplicaAlreadyExists(NodeId),
    #[error("removing replica {0} would violate the durability policy")]
    UnsafeAssignmentChange(NodeId),
    #[error("replica assignment change is unsafe or stale")]
    UnsafeAssignment,
}

#[derive(Debug, Clone, Copy)]
struct RecordIdentity {
    partition_key: [u8; 16],
    epoch: Epoch,
    base_offset: Offset,
    last_offset: Offset,
    timestamp_ms: u64,
}

fn validate_config(config: OrderedLogConfig) -> Result<(), OrderedLogError> {
    if config.sparse_index_stride == 0
        || config.maximum_segment_bytes == 0
        || config.maximum_segment_batches == 0
    {
        return Err(OrderedLogError::InvalidConfiguration(
            "index stride and segment limits must be nonzero".to_string(),
        ));
    }
    Ok(())
}

fn encode_record_id(identity: RecordIdentity) -> Result<RecordId, OrderedLogError> {
    let mut bytes = vec![0u8; RECORD_ID_BYTES];
    bytes[..8].copy_from_slice(RECORD_ID_MAGIC);
    bytes[8..24].copy_from_slice(&identity.partition_key);
    bytes[24..32].copy_from_slice(&identity.epoch.to_le_bytes());
    bytes[32..40].copy_from_slice(&identity.base_offset.to_le_bytes());
    bytes[40..48].copy_from_slice(&identity.last_offset.to_le_bytes());
    bytes[48..56].copy_from_slice(&identity.timestamp_ms.to_le_bytes());
    let checksum = crc32c::crc32c(&bytes[..56]);
    bytes[56..60].copy_from_slice(&checksum.to_le_bytes());
    RecordId::new(bytes).map_err(OrderedLogError::from)
}

fn decode_record_id(bytes: &[u8]) -> Result<RecordIdentity, OrderedLogError> {
    if bytes.len() != RECORD_ID_BYTES || &bytes[..8] != RECORD_ID_MAGIC {
        return Err(OrderedLogError::MalformedRecordIdentity);
    }
    let checksum = u32::from_le_bytes(
        bytes[56..60]
            .try_into()
            .map_err(|_| OrderedLogError::MalformedRecordIdentity)?,
    );
    if crc32c::crc32c(&bytes[..56]) != checksum {
        return Err(OrderedLogError::MalformedRecordIdentity);
    }
    Ok(RecordIdentity {
        partition_key: bytes[8..24]
            .try_into()
            .map_err(|_| OrderedLogError::MalformedRecordIdentity)?,
        epoch: u64::from_le_bytes(
            bytes[24..32]
                .try_into()
                .map_err(|_| OrderedLogError::MalformedRecordIdentity)?,
        ),
        base_offset: u64::from_le_bytes(
            bytes[32..40]
                .try_into()
                .map_err(|_| OrderedLogError::MalformedRecordIdentity)?,
        ),
        last_offset: u64::from_le_bytes(
            bytes[40..48]
                .try_into()
                .map_err(|_| OrderedLogError::MalformedRecordIdentity)?,
        ),
        timestamp_ms: u64::from_le_bytes(
            bytes[48..56]
                .try_into()
                .map_err(|_| OrderedLogError::MalformedRecordIdentity)?,
        ),
    })
}

#[allow(clippy::too_many_arguments)]
fn append_assigned(
    store: &dyn ExtentStore,
    config: OrderedLogConfig,
    state: &mut LogState,
    epoch: Epoch,
    base_offset: Offset,
    timestamp_ms: u64,
    record_count: u32,
    payload: BufferChain,
) -> Result<AppendResult, OrderedLogError> {
    if record_count == 0 {
        return Err(OrderedLogError::EmptyRecordBatch);
    }
    if base_offset != state.next_offset {
        return Err(OrderedLogError::AssignedOffsetMismatch {
            expected: state.next_offset,
            supplied: base_offset,
        });
    }
    let last_offset = base_offset
        .checked_add(u64::from(record_count) - 1)
        .ok_or(OrderedLogError::OffsetOverflow)?;
    let should_rotate = state.segments.last().is_some_and(|active| {
        !active.batches.is_empty()
            && (active
                .payload_bytes
                .saturating_add(payload.encoded_len() as u64)
                > config.maximum_segment_bytes
                || active.batches.len() as u64 >= config.maximum_segment_batches)
    });
    if should_rotate {
        rotate_active(store, state)?;
    }
    let extent_id = state
        .segments
        .last()
        .ok_or(OrderedLogError::ActiveExtentCount(0))?
        .extent_id;
    let receipt = store.append(AppendPlan::new(
        extent_id,
        encode_record_id(RecordIdentity {
            partition_key: config.partition_key,
            epoch,
            base_offset,
            last_offset,
            timestamp_ms,
        })?,
        payload,
    ))?;
    let location = BatchLocation {
        base_offset,
        last_offset,
        epoch,
        timestamp_ms,
        extent_id: receipt.extent_id,
        record_index: receipt.record_index,
        encoded_len: receipt.encoded_len,
    };
    let batch_ordinal = state.total_batches;
    let active = state
        .segments
        .last_mut()
        .ok_or(OrderedLogError::ActiveExtentCount(0))?;
    if active.batches.is_empty() {
        active.base_offset = base_offset;
    }
    active.payload_bytes = active.payload_bytes.saturating_add(receipt.encoded_len);
    active.batches.push(location);
    if batch_ordinal % u64::from(config.sparse_index_stride) == 0 {
        state.sparse_index.push(SparseIndexEntry {
            base_offset,
            extent_id: receipt.extent_id,
            record_index: receipt.record_index,
        });
    }
    state.total_batches = state.total_batches.saturating_add(1);
    state.next_offset = last_offset + 1;
    Ok(AppendResult {
        base_offset,
        last_offset,
        leader_epoch: epoch,
        high_watermark: state.high_watermark,
        durable_media_appends: 1,
    })
}

fn rotate_active(
    store: &dyn ExtentStore,
    state: &mut LogState,
) -> Result<SealedSegmentManifest, OrderedLogError> {
    let active = state
        .segments
        .last()
        .ok_or(OrderedLogError::ActiveExtentCount(0))?;
    if active.batches.is_empty() {
        return Err(OrderedLogError::InvalidConfiguration(
            "empty active extent cannot be rotated".to_string(),
        ));
    }
    if active.end_offset() > state.high_watermark {
        return Err(OrderedLogError::UncommittedRotation);
    }
    let sealed = store.seal(active.extent_id)?;
    let manifest = manifest_from_sealed(active, &sealed);
    state
        .segments
        .last_mut()
        .ok_or(OrderedLogError::ActiveExtentCount(0))?
        .sealed = Some(manifest.clone());
    state.segments.push(SegmentState {
        extent_id: store.create()?,
        base_offset: state.next_offset,
        payload_bytes: 0,
        batches: Vec::new(),
        sealed: None,
    });
    Ok(manifest)
}

fn manifest_from_sealed(active: &SegmentState, sealed: &SealedExtent) -> SealedSegmentManifest {
    manifest_from_inspection(
        active.extent_id,
        active.base_offset,
        &active.batches,
        active.payload_bytes,
        sealed.digest,
    )
}

fn manifest_from_inspection(
    extent_id: ExtentId,
    base_offset: Offset,
    batches: &[BatchLocation],
    payload_bytes: u64,
    extent_digest: [u8; 32],
) -> SealedSegmentManifest {
    SealedSegmentManifest {
        extent_id,
        base_offset,
        end_offset: batches
            .last()
            .map_or(base_offset, |batch| batch.last_offset + 1),
        batch_count: batches.len() as u64,
        payload_bytes,
        minimum_timestamp_ms: batches
            .iter()
            .map(|batch| batch.timestamp_ms)
            .min()
            .unwrap_or(0),
        maximum_timestamp_ms: batches
            .iter()
            .map(|batch| batch.timestamp_ms)
            .max()
            .unwrap_or(0),
        maximum_epoch: batches.iter().map(|batch| batch.epoch).max().unwrap_or(0),
        extent_digest,
    }
}

fn truncate_active_to(
    store: &dyn ExtentStore,
    state: &mut LogState,
    truncate_to: Offset,
) -> Result<(), OrderedLogError> {
    if truncate_to < state.high_watermark || truncate_to > state.next_offset {
        return Err(OrderedLogError::InvalidTruncateOffset(truncate_to));
    }
    let active = state
        .segments
        .last_mut()
        .ok_or(OrderedLogError::ActiveExtentCount(0))?;
    if active.sealed.is_some() || truncate_to < active.base_offset {
        return Err(OrderedLogError::InvalidTruncateOffset(truncate_to));
    }
    let keep = active
        .batches
        .iter()
        .take_while(|batch| batch.last_offset < truncate_to)
        .count();
    let boundary = if keep == active.batches.len() {
        active.end_offset()
    } else {
        active.batches[keep].base_offset
    };
    if boundary != truncate_to {
        return Err(OrderedLogError::InvalidTruncateOffset(truncate_to));
    }
    if keep != active.batches.len() {
        store.truncate(active.extent_id, keep as u64)?;
        active.batches.truncate(keep);
        active.payload_bytes = active.batches.iter().map(|batch| batch.encoded_len).sum();
    }
    state.next_offset = truncate_to;
    Ok(())
}

fn rebuild_sparse_index(state: &mut LogState, stride: u32) {
    state.sparse_index.clear();
    state.total_batches = 0;
    for batch in state
        .segments
        .iter()
        .flat_map(|segment| segment.batches.iter())
    {
        if state.total_batches % u64::from(stride) == 0 {
            state.sparse_index.push(SparseIndexEntry {
                base_offset: batch.base_offset,
                extent_id: batch.extent_id,
                record_index: batch.record_index,
            });
        }
        state.total_batches += 1;
    }
}

fn validate_contiguous_batches(batches: &[BatchLocation]) -> Result<(), OrderedLogError> {
    for pair in batches.windows(2) {
        if pair[0].last_offset >= pair[1].base_offset {
            return Err(OrderedLogError::OffsetGap);
        }
    }
    Ok(())
}

fn validate_segments(segments: &[SegmentState]) -> Result<(), OrderedLogError> {
    let batches = segments
        .iter()
        .flat_map(|segment| segment.batches.iter())
        .collect::<Vec<_>>();
    for pair in batches.windows(2) {
        if pair[0].last_offset >= pair[1].base_offset {
            return Err(OrderedLogError::OffsetGap);
        }
    }
    Ok(())
}

fn is_batch_boundary(state: &LogState, offset: Offset) -> bool {
    offset == state.log_start_offset
        || offset == state.next_offset
        || state
            .segments
            .iter()
            .flat_map(|segment| segment.batches.iter())
            .any(|batch| batch.base_offset == offset || batch.last_offset + 1 == offset)
}

fn recovery_authenticator(
    key: &[u8; 32],
    partition_key: [u8; 16],
    controller_epoch: Epoch,
    leader_epoch: Epoch,
    truncate_to: Offset,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(&partition_key);
    hasher.update(&controller_epoch.to_le_bytes());
    hasher.update(&leader_epoch.to_le_bytes());
    hasher.update(&truncate_to.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use pepper_extent::{FileExtentConfig, FileExtentStore};
    use tempfile::TempDir;

    fn payload(value: &[u8]) -> BufferChain {
        BufferChain::from(OwnedBuffer::new(Bytes::copy_from_slice(value)))
    }

    fn log_at(
        directory: &TempDir,
        recovery: RecoveryState,
        maximum_batches: u64,
    ) -> Arc<OrderedLog> {
        let store =
            Arc::new(FileExtentStore::open(directory.path(), FileExtentConfig::default()).unwrap());
        Arc::new(
            OrderedLog::open(
                store,
                OrderedLogConfig {
                    partition_key: [7; 16],
                    sparse_index_stride: 16,
                    maximum_segment_batches: maximum_batches,
                    ..OrderedLogConfig::default()
                },
                recovery,
            )
            .unwrap(),
        )
    }

    #[test]
    fn append_fetch_seal_and_recover_original_bytes() {
        let directory = TempDir::new().unwrap();
        let expected_manifest;
        {
            let log = log_at(&directory, RecoveryState::default(), 2);
            log.promise_epoch(1, 1).unwrap();
            log.activate_leader(1, 1).unwrap();
            let first = log.append(1, 10, 2, payload(b"first")).unwrap();
            assert_eq!((first.base_offset, first.last_offset), (0, 1));
            log.commit(1, 2).unwrap();
            log.append(1, 11, 1, payload(b"second")).unwrap();
            log.commit(1, 3).unwrap();
            expected_manifest = log.seal_and_rotate(1).unwrap();
            assert_eq!(
                (expected_manifest.base_offset, expected_manifest.end_offset),
                (0, 3)
            );
            log.append(1, 12, 1, payload(b"uncommitted")).unwrap();
        }
        let recovered = log_at(
            &directory,
            RecoveryState {
                promised_epoch: 2,
                high_watermark: 3,
                log_start_offset: 0,
            },
            2,
        );
        let fetched = recovered.fetch(0, u64::MAX, true).unwrap();
        assert_eq!(fetched.batches.len(), 2);
        assert_eq!(fetched.batches[0].bytes.bytes(), b"first".as_slice());
        assert_eq!(fetched.batches[1].bytes.bytes(), b"second".as_slice());
        assert_eq!(fetched.log_end_offset, 3);
        assert_eq!(
            recovered.sealed_manifests().unwrap(),
            vec![expected_manifest]
        );
        drop(recovered);
        let clean_reopen = log_at(
            &directory,
            RecoveryState {
                promised_epoch: 3,
                high_watermark: 3,
                log_start_offset: 0,
            },
            2,
        );
        assert_eq!(clean_reopen.progress(0).unwrap().log_end_offset, 3);
    }

    #[test]
    fn authenticated_truncation_preserves_committed_prefix() {
        let directory = TempDir::new().unwrap();
        let log = log_at(&directory, RecoveryState::default(), 100);
        log.promise_epoch(9, 4).unwrap();
        log.activate_leader(9, 4).unwrap();
        log.append(4, 0, 1, payload(b"a")).unwrap();
        log.commit(4, 1).unwrap();
        log.append(4, 0, 1, payload(b"b")).unwrap();
        let authority = RecoveryAuthority::new([3; 32]);
        let bad = RecoveryAuthority::new([4; 32]).issue([7; 16], 9, 4, 1);
        assert!(matches!(
            log.truncate(&authority, &bad),
            Err(OrderedLogError::UnauthenticatedRecovery)
        ));
        let committed = authority.issue([7; 16], 9, 4, 0);
        assert!(matches!(
            log.truncate(&authority, &committed),
            Err(OrderedLogError::CommittedTruncation { .. })
        ));
        let valid = authority.issue([7; 16], 9, 4, 1);
        log.truncate(&authority, &valid).unwrap();
        assert_eq!(log.progress(0).unwrap().log_end_offset, 1);
    }

    #[test]
    fn replicated_failover_fences_stale_leader_and_keeps_prefix() {
        let directories = [
            TempDir::new().unwrap(),
            TempDir::new().unwrap(),
            TempDir::new().unwrap(),
        ];
        let replicas = directories
            .iter()
            .enumerate()
            .map(|(index, directory)| {
                (
                    index as NodeId,
                    log_at(directory, RecoveryState::default(), 100),
                )
            })
            .collect();
        let mut partition = ReplicatedPartition::new(replicas, 0, 1, 1, 2).unwrap();
        let appended = partition
            .append(0, 1, 0, 1, payload(b"safe"), Acknowledgments::All)
            .unwrap();
        assert!(appended.acknowledged);
        assert_eq!(appended.result.durable_media_appends, 3);
        partition.set_online(0, false).unwrap();
        partition.elect(1, 2, 2, &BTreeSet::from([1, 2])).unwrap();
        assert!(matches!(
            partition.append(0, 1, 0, 1, payload(b"stale"), Acknowledgments::All),
            Err(OrderedLogError::StaleLeader)
        ));
        let next = partition
            .append(1, 2, 0, 1, payload(b"next"), Acknowledgments::All)
            .unwrap();
        assert!(next.acknowledged);
        assert_eq!(next.result.base_offset, 1);
    }

    #[test]
    fn sparse_index_and_spike_accounting_are_bounded() {
        let directory = TempDir::new().unwrap();
        let log = log_at(&directory, RecoveryState::default(), 100_000);
        log.promise_epoch(1, 1).unwrap();
        log.activate_leader(1, 1).unwrap();
        for offset in 0u64..1024 {
            log.append(1, offset, 1, payload(&offset.to_le_bytes()))
                .unwrap();
            log.commit(1, offset + 1).unwrap();
        }
        assert_eq!(log.sparse_index().unwrap().len(), 64);
        let direct = replication_spike(
            ReplicationSpike::DirectLeaderFollower,
            10_000,
            3,
            16 * 1024,
            true,
        );
        let duplicate = replication_spike(
            ReplicationSpike::DataBearingConsensus,
            10_000,
            3,
            16 * 1024,
            false,
        );
        assert_eq!(direct.record_copies_per_replica, 1);
        assert_eq!(duplicate.record_copies_per_replica, 2);
        assert!(direct.control_bytes < duplicate.control_bytes);
    }

    #[test]
    fn sparse_index_scales_with_stride_for_65536_batch_fixture() {
        let extent_id = ExtentId::from_bytes([9; 16]);
        for stride in [1, 16, 256, 4096] {
            let batches = (0..65_536)
                .map(|offset| BatchLocation {
                    base_offset: offset,
                    last_offset: offset,
                    epoch: 1,
                    timestamp_ms: offset,
                    extent_id,
                    record_index: offset,
                    encoded_len: 1024,
                })
                .collect::<Vec<_>>();
            let mut state = LogState {
                segments: vec![SegmentState {
                    extent_id,
                    base_offset: 0,
                    payload_bytes: 65_536 * 1024,
                    batches,
                    sealed: None,
                }],
                sparse_index: Vec::new(),
                promised_epoch: 1,
                leader_epoch: Some(1),
                controller_epoch: 1,
                high_watermark: 65_536,
                log_start_offset: 0,
                next_offset: 65_536,
                total_batches: 0,
            };
            rebuild_sparse_index(&mut state, stride);
            assert_eq!(
                state.sparse_index.len() as u64,
                65_536u64.div_ceil(u64::from(stride))
            );
            assert_eq!(state.sparse_index.first().unwrap().base_offset, 0);
        }
    }

    #[test]
    fn deterministic_multinode_fault_harness_preserves_acknowledged_prefix() {
        for seed in 0u64..16 {
            let directories = [
                TempDir::new().unwrap(),
                TempDir::new().unwrap(),
                TempDir::new().unwrap(),
            ];
            let logs = directories
                .iter()
                .enumerate()
                .map(|(index, directory)| {
                    (
                        index as NodeId,
                        log_at(directory, RecoveryState::default(), 100),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let mut partition = ReplicatedPartition::new(logs.clone(), 0, 1, 1, 2).unwrap();
            let first = partition
                .append(
                    0,
                    1,
                    seed,
                    1,
                    payload(&seed.to_le_bytes()),
                    Acknowledgments::All,
                )
                .unwrap();
            assert!(first.acknowledged);

            let failed_follower = 1 + (seed as NodeId % 2);
            partition.set_online(failed_follower, false).unwrap();
            let uncertain = partition
                .append(
                    0,
                    1,
                    seed + 1,
                    1,
                    payload(b"quorum-only"),
                    Acknowledgments::All,
                )
                .unwrap();
            assert!(!uncertain.acknowledged);
            partition.set_online(failed_follower, true).unwrap();

            let candidate = failed_follower;
            let other = if candidate == 1 { 2 } else { 1 };
            partition
                .elect(candidate, 2, 2, &BTreeSet::from([candidate, other]))
                .unwrap();
            let committed = partition
                .append(
                    candidate,
                    2,
                    seed + 2,
                    1,
                    payload(b"after-failover"),
                    Acknowledgments::All,
                )
                .unwrap();
            assert!(committed.acknowledged);
            for node in [candidate, other] {
                let fetched = logs[&node].fetch(0, u64::MAX, true).unwrap();
                assert_eq!(fetched.high_watermark, 3);
                assert_eq!(fetched.batches.len(), 3);
                assert_eq!(
                    fetched.batches[0].bytes.bytes(),
                    seed.to_le_bytes().as_slice()
                );
                assert_eq!(
                    fetched.batches[2].bytes.bytes(),
                    b"after-failover".as_slice()
                );
            }
        }
    }

    #[test]
    fn catch_up_and_assignment_change_make_new_replica_ack_eligible() {
        let directories = [
            TempDir::new().unwrap(),
            TempDir::new().unwrap(),
            TempDir::new().unwrap(),
            TempDir::new().unwrap(),
        ];
        let logs = directories[..3]
            .iter()
            .enumerate()
            .map(|(node, directory)| {
                (
                    node as NodeId,
                    log_at(directory, RecoveryState::default(), 100),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut partition = ReplicatedPartition::new(logs, 0, 1, 1, 2).unwrap();
        partition
            .append(0, 1, 0, 1, payload(b"first"), Acknowledgments::All)
            .unwrap();
        let joining = log_at(&directories[3], RecoveryState::default(), 100);
        partition.add_replica(3, Arc::clone(&joining)).unwrap();
        assert_eq!(joining.progress(1).unwrap().lag, 0);
        assert_eq!(
            joining.fetch(0, u64::MAX, true).unwrap().batches[0]
                .bytes
                .bytes(),
            b"first".as_slice()
        );
        partition.remove_replica(2).unwrap();
        let result = partition
            .append(0, 1, 1, 1, payload(b"second"), Acknowledgments::All)
            .unwrap();
        assert!(result.acknowledged);
        assert_eq!(result.durable_replicas, BTreeSet::from([0, 1, 3]));
    }

    #[test]
    fn retention_candidates_require_an_epoch_fenced_log_start_transition() {
        let directory = TempDir::new().unwrap();
        let log = log_at(&directory, RecoveryState::default(), 2);
        log.promise_epoch(5, 1).unwrap();
        log.activate_leader(5, 1).unwrap();
        for offset in 0..2 {
            log.append(1, 10 + offset, 1, payload(b"old")).unwrap();
            log.commit(1, offset + 1).unwrap();
        }
        let manifest = log.seal_and_rotate(1).unwrap();
        let candidates = log
            .retention_candidates(RetentionPolicy {
                retain_after_timestamp_ms: Some(20),
                maximum_sealed_bytes: None,
            })
            .unwrap();
        assert_eq!(candidates, vec![manifest.clone()]);
        assert!(matches!(
            log.advance_log_start(4, manifest.end_offset),
            Err(OrderedLogError::InvalidLogStart(_))
        ));
        log.advance_log_start(5, manifest.end_offset).unwrap();
        assert!(matches!(
            log.fetch(0, 1, true),
            Err(OrderedLogError::OffsetBeforeLogStart {
                offset: 0,
                log_start: 2
            })
        ));
    }

    #[test]
    fn sealed_compaction_is_atomic_preserves_offsets_and_reopens() {
        let directory = TempDir::new().unwrap();
        {
            let log = log_at(&directory, RecoveryState::default(), 100);
            log.promise_epoch(1, 1).unwrap();
            log.activate_leader(1, 1).unwrap();
            for offset in 0..5 {
                log.append(1, 10 + offset, 1, payload(&[offset as u8]))
                    .unwrap();
                log.commit(1, offset + 1).unwrap();
            }
            let sealed = log.seal_and_rotate(1).unwrap();
            let compacted = log
                .compact_sealed(sealed.extent_id, &BTreeSet::from([2]))
                .unwrap();
            assert_eq!(
                (
                    compacted.input_batches,
                    compacted.retained_batches,
                    compacted.replacement.base_offset,
                    compacted.replacement.end_offset,
                ),
                (5, 3, 0, 5)
            );
            let fetched = log.fetch(1, u64::MAX, true).unwrap();
            assert_eq!(
                fetched
                    .batches
                    .iter()
                    .map(|batch| batch.base_offset)
                    .collect::<Vec<_>>(),
                vec![2, 4]
            );
            assert_eq!((fetched.high_watermark, fetched.log_end_offset), (5, 5));
        }
        let reopened = log_at(
            &directory,
            RecoveryState {
                promised_epoch: 2,
                high_watermark: 5,
                log_start_offset: 0,
            },
            100,
        );
        let fetched = reopened.fetch(0, u64::MAX, true).unwrap();
        assert_eq!(
            fetched
                .batches
                .iter()
                .map(|batch| batch.base_offset)
                .collect::<Vec<_>>(),
            vec![0, 2, 4]
        );
        assert_eq!((fetched.high_watermark, fetched.log_end_offset), (5, 5));
        assert_eq!(reopened.sealed_manifests().unwrap().len(), 1);
    }
}
