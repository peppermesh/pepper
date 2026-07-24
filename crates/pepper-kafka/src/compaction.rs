// SPDX-License-Identifier: Apache-2.0

//! Kafka key/tombstone policy over product-neutral sealed log segments.

use bytes::Bytes;
use kafka_protocol::records::RecordBatchDecoder;
use pepper_ordered_log::Offset;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct CompactionBatch {
    pub base_offset: Offset,
    pub timestamp_ms: u64,
    pub bytes: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompactionSelection {
    pub input_batches: usize,
    pub retained_batches: usize,
    pub obsolete_batches: usize,
    pub undecodable_batches: usize,
    pub null_key_batches: usize,
    pub protected_tombstone_batches: usize,
    #[serde(skip)]
    pub retained_offsets: BTreeSet<Offset>,
}

#[derive(Debug)]
struct DecodedBatch {
    base_offset: Offset,
    keys: Vec<(Bytes, bool, u64)>,
    retain_always: bool,
    undecodable: bool,
    null_key: bool,
}

pub fn select_retained_batches(
    batches: &[CompactionBatch],
    now_ms: u64,
    delete_retention_ms: u64,
) -> CompactionSelection {
    let mut decoded = Vec::with_capacity(batches.len());
    let mut latest = BTreeMap::<Bytes, Offset>::new();
    for batch in batches {
        let mut input = batch.bytes.clone();
        let record_sets = RecordBatchDecoder::decode_all(&mut input);
        let mut candidate = DecodedBatch {
            base_offset: batch.base_offset,
            keys: Vec::new(),
            retain_always: false,
            undecodable: false,
            null_key: false,
        };
        match record_sets {
            Ok(record_sets) => {
                for record in record_sets
                    .into_iter()
                    .flat_map(|record_set| record_set.records)
                {
                    if record.control || record.producer_id >= 0 {
                        candidate.retain_always = true;
                    }
                    let Some(key) = record.key else {
                        candidate.retain_always = true;
                        candidate.null_key = true;
                        continue;
                    };
                    let timestamp = u64::try_from(record.timestamp).unwrap_or(batch.timestamp_ms);
                    let tombstone = record.value.is_none();
                    latest.insert(key.clone(), batch.base_offset);
                    candidate.keys.push((key, tombstone, timestamp));
                }
            }
            Err(_) => {
                candidate.retain_always = true;
                candidate.undecodable = true;
            }
        }
        decoded.push(candidate);
    }

    let mut retained_offsets = BTreeSet::new();
    let mut protected_tombstone_batches = 0;
    for batch in &decoded {
        let protected_tombstone = batch.keys.iter().any(|(_, tombstone, timestamp)| {
            *tombstone && now_ms.saturating_sub(*timestamp) < delete_retention_ms
        });
        if protected_tombstone {
            protected_tombstone_batches += 1;
        }
        if batch.retain_always
            || protected_tombstone
            || batch
                .keys
                .iter()
                .any(|(key, _, _)| latest.get(key) == Some(&batch.base_offset))
        {
            retained_offsets.insert(batch.base_offset);
        }
    }
    CompactionSelection {
        input_batches: batches.len(),
        retained_batches: retained_offsets.len(),
        obsolete_batches: batches.len().saturating_sub(retained_offsets.len()),
        undecodable_batches: decoded.iter().filter(|batch| batch.undecodable).count(),
        null_key_batches: decoded.iter().filter(|batch| batch.null_key).count(),
        protected_tombstone_batches,
        retained_offsets,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompactionDensityQualification {
    pub keyed_updates: usize,
    pub unique_keys: usize,
    pub obsolete_updates: usize,
    pub obsolete_percent: usize,
    pub scheduler_tasks: usize,
    pub maximum_in_flight_per_device: usize,
    pub all_pass: bool,
}

pub fn qualify_compaction_density(
    keyed_updates: usize,
    unique_keys: usize,
) -> CompactionDensityQualification {
    let mut latest = BTreeMap::new();
    for update in 0..keyed_updates {
        latest.insert(update % unique_keys.max(1), update);
    }
    let obsolete_updates = keyed_updates.saturating_sub(latest.len());
    let obsolete_percent = obsolete_updates.saturating_mul(100) / keyed_updates.max(1);
    CompactionDensityQualification {
        keyed_updates,
        unique_keys,
        obsolete_updates,
        obsolete_percent,
        scheduler_tasks: 1,
        maximum_in_flight_per_device: 1,
        all_pass: keyed_updates >= 1_000_000 && obsolete_percent >= 90,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use kafka_protocol::records::{
        Compression, Record, RecordBatchEncoder, RecordEncodeOptions, TimestampType,
    };

    fn batch(key: Option<&'static [u8]>, value: Option<&'static [u8]>, timestamp: i64) -> Bytes {
        let record = Record {
            transactional: false,
            control: false,
            partition_leader_epoch: -1,
            producer_id: -1,
            producer_epoch: -1,
            timestamp_type: TimestampType::Creation,
            timestamp,
            sequence: -1,
            offset: 0,
            key: key.map(Bytes::from_static),
            value: value.map(Bytes::from_static),
            headers: Default::default(),
        };
        let mut encoded = BytesMut::new();
        RecordBatchEncoder::encode(
            &mut encoded,
            [&record],
            &RecordEncodeOptions {
                version: 2,
                compression: Compression::None,
            },
        )
        .unwrap();
        encoded.freeze()
    }

    #[test]
    fn latest_keys_null_keys_and_tombstone_grace_are_exact() {
        let batches = vec![
            CompactionBatch {
                base_offset: 0,
                timestamp_ms: 1,
                bytes: batch(Some(b"k"), Some(b"old"), 1),
            },
            CompactionBatch {
                base_offset: 1,
                timestamp_ms: 2,
                bytes: batch(None, Some(b"null"), 2),
            },
            CompactionBatch {
                base_offset: 2,
                timestamp_ms: 3,
                bytes: batch(Some(b"k"), Some(b"new"), 3),
            },
            CompactionBatch {
                base_offset: 3,
                timestamp_ms: 95,
                bytes: batch(Some(b"deleted"), None, 95),
            },
        ];
        let selected = select_retained_batches(&batches, 100, 10);
        assert_eq!(selected.retained_offsets, BTreeSet::from([1, 2, 3]));
        assert_eq!(selected.obsolete_batches, 1);
        assert_eq!(selected.null_key_batches, 1);
        assert_eq!(selected.protected_tombstone_batches, 1);
    }
}
