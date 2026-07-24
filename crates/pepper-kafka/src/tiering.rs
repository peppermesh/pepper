// SPDX-License-Identifier: Apache-2.0

//! Optional immutable Kafka sealed-segment placement in Pepper block storage.

use pepper_storage::{BlockStore, StorageError};
use pepper_types::{CODEC_RAW, Cid};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ColdSegmentKey {
    pub topic: String,
    pub partition: i32,
    pub base_offset: u64,
    pub end_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColdPlacement {
    Replicated {
        cid: Cid,
    },
    Erasure {
        data_shards: usize,
        parity_shards: usize,
        shard_bytes: usize,
        logical_bytes: usize,
        shard_cids: Vec<Cid>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdSegmentRecord {
    pub key: ColdSegmentKey,
    pub image_digest: [u8; 32],
    pub image_bytes: u64,
    pub placement: ColdPlacement,
    /// Phase 12 never makes normal fetch depend on cold recall.
    pub hot_replica_retained: bool,
}

#[derive(Debug, Clone, Default)]
struct ColdCatalog {
    segments: BTreeMap<ColdSegmentKey, ColdSegmentRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedColdCatalog {
    segments: Vec<ColdSegmentRecord>,
}

impl From<PersistedColdCatalog> for ColdCatalog {
    fn from(catalog: PersistedColdCatalog) -> Self {
        Self {
            segments: catalog
                .segments
                .into_iter()
                .map(|record| (record.key.clone(), record))
                .collect(),
        }
    }
}

impl From<&ColdCatalog> for PersistedColdCatalog {
    fn from(catalog: &ColdCatalog) -> Self {
        Self {
            segments: catalog.segments.values().cloned().collect(),
        }
    }
}

#[derive(Default)]
struct RecallCache {
    entries: BTreeMap<ColdSegmentKey, Arc<Vec<u8>>>,
    order: VecDeque<ColdSegmentKey>,
    bytes: usize,
}

struct ColdState {
    catalog: ColdCatalog,
    cache: RecallCache,
}

pub struct ColdTier {
    catalog_path: PathBuf,
    store: Arc<BlockStore>,
    maximum_cache_bytes: usize,
    state: Mutex<ColdState>,
}

impl ColdTier {
    pub fn open(
        root: impl AsRef<Path>,
        store: Arc<BlockStore>,
        maximum_cache_bytes: usize,
    ) -> Result<Self, ColdTierError> {
        let root = root.as_ref();
        std::fs::create_dir_all(root)?;
        let catalog_path = root.join("kafka-cold-catalog.json");
        let catalog = if catalog_path.exists() {
            serde_json::from_slice::<PersistedColdCatalog>(&std::fs::read(&catalog_path)?)
                .map_err(|error| ColdTierError::Codec(error.to_string()))?
                .into()
        } else {
            ColdCatalog::default()
        };
        Ok(Self {
            catalog_path,
            store,
            maximum_cache_bytes,
            state: Mutex::new(ColdState {
                catalog,
                cache: RecallCache::default(),
            }),
        })
    }

    pub fn archive_replicated(
        &self,
        key: ColdSegmentKey,
        image: &[u8],
    ) -> Result<ColdSegmentRecord, ColdTierError> {
        let put = self.store.put_raw(image)?;
        let verified = self.store.get(&put.cid)?;
        if verified.payload != image {
            return Err(ColdTierError::Verification);
        }
        self.publish(key, image, ColdPlacement::Replicated { cid: put.cid })
    }

    pub fn archive_erasure(
        &self,
        key: ColdSegmentKey,
        image: &[u8],
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<ColdSegmentRecord, ColdTierError> {
        if data_shards == 0 || parity_shards == 0 || data_shards + parity_shards > 32 {
            return Err(ColdTierError::InvalidErasure);
        }
        let shard_bytes = image.len().div_ceil(data_shards).max(1);
        let mut shards = vec![vec![0u8; shard_bytes]; data_shards + parity_shards];
        for (index, byte) in image.iter().enumerate() {
            shards[index / shard_bytes][index % shard_bytes] = *byte;
        }
        ReedSolomon::new(data_shards, parity_shards)
            .map_err(|error| ColdTierError::Erasure(error.to_string()))?
            .encode(&mut shards)
            .map_err(|error| ColdTierError::Erasure(error.to_string()))?;
        let shard_cids = shards
            .iter()
            .map(|shard| self.store.put_raw(shard).map(|put| put.cid))
            .collect::<Result<Vec<_>, _>>()?;
        self.publish(
            key,
            image,
            ColdPlacement::Erasure {
                data_shards,
                parity_shards,
                shard_bytes,
                logical_bytes: image.len(),
                shard_cids,
            },
        )
    }

    fn publish(
        &self,
        key: ColdSegmentKey,
        image: &[u8],
        placement: ColdPlacement,
    ) -> Result<ColdSegmentRecord, ColdTierError> {
        let record = ColdSegmentRecord {
            key: key.clone(),
            image_digest: *blake3::hash(image).as_bytes(),
            image_bytes: image.len() as u64,
            placement,
            hot_replica_retained: true,
        };
        let mut state = self.state.lock().map_err(|_| ColdTierError::Lock)?;
        state.catalog.segments.insert(key, record.clone());
        self.persist(&state.catalog)?;
        Ok(record)
    }

    pub fn recall_range(
        &self,
        key: &ColdSegmentKey,
        start: usize,
        end: usize,
    ) -> Result<Vec<u8>, ColdTierError> {
        let image = self.recall(key)?;
        if start > end || end > image.len() {
            return Err(ColdTierError::InvalidRange);
        }
        Ok(image[start..end].to_vec())
    }

    pub fn recall(&self, key: &ColdSegmentKey) -> Result<Arc<Vec<u8>>, ColdTierError> {
        // The lock deliberately spans a miss: concurrent recalls coalesce into
        // one verified block read/reconstruction.
        let mut state = self.state.lock().map_err(|_| ColdTierError::Lock)?;
        if let Some(image) = state.cache.entries.get(key).cloned() {
            touch(&mut state.cache.order, key);
            return Ok(image);
        }
        let record = state
            .catalog
            .segments
            .get(key)
            .cloned()
            .ok_or(ColdTierError::UnknownSegment)?;
        let image = match &record.placement {
            ColdPlacement::Replicated { cid } => self.store.get(cid)?.payload,
            ColdPlacement::Erasure {
                data_shards,
                parity_shards,
                logical_bytes,
                shard_cids,
                ..
            } => {
                let mut shards = shard_cids
                    .iter()
                    .map(|cid| self.store.get(cid).ok().map(|block| block.payload))
                    .collect::<Vec<_>>();
                ReedSolomon::new(*data_shards, *parity_shards)
                    .map_err(|error| ColdTierError::Erasure(error.to_string()))?
                    .reconstruct(&mut shards)
                    .map_err(|error| ColdTierError::Erasure(error.to_string()))?;
                let mut image = shards
                    .into_iter()
                    .take(*data_shards)
                    .flatten()
                    .flatten()
                    .collect::<Vec<_>>();
                image.truncate(*logical_bytes);
                image
            }
        };
        if image.len() as u64 != record.image_bytes
            || blake3::hash(&image).as_bytes() != &record.image_digest
        {
            return Err(ColdTierError::Verification);
        }
        let image = Arc::new(image);
        self.insert_cache(&mut state.cache, key.clone(), Arc::clone(&image));
        Ok(image)
    }

    pub fn repair_from_hot(
        &self,
        key: &ColdSegmentKey,
        image: &[u8],
    ) -> Result<usize, ColdTierError> {
        let state = self.state.lock().map_err(|_| ColdTierError::Lock)?;
        let record = state
            .catalog
            .segments
            .get(key)
            .ok_or(ColdTierError::UnknownSegment)?;
        if blake3::hash(image).as_bytes() != &record.image_digest {
            return Err(ColdTierError::Verification);
        }
        let repaired = match &record.placement {
            ColdPlacement::Replicated { cid } => usize::from(
                !self.store.has(cid)?
                    && !self
                        .store
                        .put_replica_verified(CODEC_RAW, image, cid)?
                        .already_existed,
            ),
            ColdPlacement::Erasure {
                data_shards,
                parity_shards,
                shard_bytes,
                shard_cids,
                ..
            } => {
                let mut shards = vec![vec![0u8; *shard_bytes]; data_shards + parity_shards];
                for (index, byte) in image.iter().enumerate() {
                    shards[index / shard_bytes][index % shard_bytes] = *byte;
                }
                ReedSolomon::new(*data_shards, *parity_shards)
                    .map_err(|error| ColdTierError::Erasure(error.to_string()))?
                    .encode(&mut shards)
                    .map_err(|error| ColdTierError::Erasure(error.to_string()))?;
                let mut repaired = 0;
                for (shard, cid) in shards.iter().zip(shard_cids) {
                    if !self.store.has(cid)? {
                        self.store.put_replica_verified(CODEC_RAW, shard, cid)?;
                        repaired += 1;
                    }
                }
                repaired
            }
        };
        Ok(repaired)
    }

    pub fn record(&self, key: &ColdSegmentKey) -> Option<ColdSegmentRecord> {
        self.state.lock().ok()?.catalog.segments.get(key).cloned()
    }

    pub fn cache_bytes(&self) -> usize {
        self.state.lock().map_or(0, |state| state.cache.bytes)
    }

    fn insert_cache(&self, cache: &mut RecallCache, key: ColdSegmentKey, image: Arc<Vec<u8>>) {
        if image.len() > self.maximum_cache_bytes {
            return;
        }
        while cache.bytes.saturating_add(image.len()) > self.maximum_cache_bytes {
            let Some(evicted) = cache.order.pop_front() else {
                break;
            };
            if let Some(bytes) = cache.entries.remove(&evicted) {
                cache.bytes = cache.bytes.saturating_sub(bytes.len());
            }
        }
        touch(&mut cache.order, &key);
        cache.bytes = cache.bytes.saturating_add(image.len());
        cache.entries.insert(key, image);
    }

    fn persist(&self, catalog: &ColdCatalog) -> Result<(), ColdTierError> {
        let bytes = serde_json::to_vec(&PersistedColdCatalog::from(catalog))
            .map_err(|error| ColdTierError::Codec(error.to_string()))?;
        let temporary = self.catalog_path.with_extension("tmp");
        std::fs::write(&temporary, bytes)?;
        std::fs::File::open(&temporary)?.sync_all()?;
        std::fs::rename(&temporary, &self.catalog_path)?;
        if let Some(parent) = self.catalog_path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
}

fn touch(order: &mut VecDeque<ColdSegmentKey>, key: &ColdSegmentKey) {
    if let Some(index) = order.iter().position(|candidate| candidate == key) {
        order.remove(index);
    }
    order.push_back(key.clone());
}

#[derive(Debug, Error)]
pub enum ColdTierError {
    #[error("cold-tier storage failed: {0}")]
    Storage(#[from] StorageError),
    #[error("cold-tier checkpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("cold-tier checkpoint codec failed: {0}")]
    Codec(String),
    #[error("unknown cold segment")]
    UnknownSegment,
    #[error("cold segment verification failed")]
    Verification,
    #[error("invalid cold recall range")]
    InvalidRange,
    #[error("invalid erasure geometry")]
    InvalidErasure,
    #[error("erasure coding failed: {0}")]
    Erasure(String),
    #[error("cold-tier state lock poisoned")]
    Lock,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_config::StorageLocationConfig;
    use pepper_metadata::MetadataStore;

    fn tier(root: &Path, maximum_cache_bytes: usize) -> (Arc<BlockStore>, ColdTier) {
        let metadata = Arc::new(MetadataStore::open_or_create(root.join("metadata.redb")).unwrap());
        let store = Arc::new(
            BlockStore::open(
                metadata,
                &[StorageLocationConfig {
                    path: root.join("blocks"),
                    max_capacity_bytes: 64 * 1024 * 1024,
                }],
            )
            .unwrap(),
        );
        let tier = ColdTier::open(
            root.join("catalog"),
            Arc::clone(&store),
            maximum_cache_bytes,
        )
        .unwrap();
        (store, tier)
    }

    fn key(marker: u64) -> ColdSegmentKey {
        ColdSegmentKey {
            topic: "cold".into(),
            partition: 0,
            base_offset: marker,
            end_offset: marker + 10,
        }
    }

    #[test]
    fn replicated_recall_cache_repair_and_erasure_loss_are_bounded() {
        let root = tempfile::tempdir().unwrap();
        let (store, tier) = tier(root.path(), 64);
        let image = (0..128u8).collect::<Vec<_>>();
        let replicated = tier.archive_replicated(key(0), &image).unwrap();
        assert!(replicated.hot_replica_retained);
        assert_eq!(tier.recall_range(&key(0), 10, 20).unwrap(), image[10..20]);
        assert_eq!(tier.cache_bytes(), 0);
        let ColdPlacement::Replicated { cid } = replicated.placement else {
            panic!("replicated placement")
        };
        store.delete_repair_extra(&cid).unwrap();
        let cold = ColdTier::open(root.path().join("catalog"), Arc::clone(&store), 1024).unwrap();
        assert!(cold.recall(&key(0)).is_err());
        assert_eq!(cold.repair_from_hot(&key(0), &image).unwrap(), 1);
        assert_eq!(&**cold.recall(&key(0)).unwrap(), &image);

        let erasure = cold.archive_erasure(key(10), &image, 3, 2).unwrap();
        let ColdPlacement::Erasure { shard_cids, .. } = erasure.placement else {
            panic!("erasure placement")
        };
        for cid in shard_cids.iter().take(2) {
            store.delete_repair_extra(cid).unwrap();
        }
        let recalled =
            ColdTier::open(root.path().join("catalog"), Arc::clone(&store), 1024).unwrap();
        assert_eq!(&**recalled.recall(&key(10)).unwrap(), &image);
        assert_eq!(recalled.repair_from_hot(&key(10), &image).unwrap(), 2);
        for cid in shard_cids.iter().take(3) {
            store.delete_repair_extra(cid).unwrap();
        }
        let beyond = ColdTier::open(root.path().join("catalog"), Arc::clone(&store), 1024).unwrap();
        assert!(beyond.recall(&key(10)).is_err());
    }
}
