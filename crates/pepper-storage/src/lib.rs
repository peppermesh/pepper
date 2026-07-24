// SPDX-License-Identifier: Apache-2.0

mod native;

use fs2::FileExt;
use pepper_config::{SmallObjectPackConfig, StorageConfig, StorageEngine, StorageLocationConfig};
use pepper_metadata::MetadataStore;
use pepper_observability::{
    CostMetric as OperationCostMetric, OperationStage, add_current_cost, observe_current_stage,
};
use pepper_types::{
    Block, BlockStatResponse, CODEC_BUCKET_OBJECT, CODEC_MERKLE_NODE, CODEC_NAMESPACE_CHECKPOINT,
    CODEC_NAMESPACE_COMMIT, CODEC_NAMESPACE_DESCRIPTOR, CODEC_RAW, CODEC_SMALL_OBJECT, Cid, Codec,
    GcReport, HashAlg, PutBlockResponse,
};
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::fs::MetadataExt;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use thiserror::Error;

const BLOCKS: TableDefinition<&str, &[u8]> = TableDefinition::new("blocks");
const INLINE_BLOCKS: TableDefinition<&str, &[u8]> = TableDefinition::new("inline_blocks");
const BLOCKS_BY_RETENTION: TableDefinition<&str, &str> =
    TableDefinition::new("blocks_by_retention");
const STORAGE_LOCATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("storage_locations");
const STORAGE_LOCATIONS_BY_PATH: TableDefinition<&str, &str> =
    TableDefinition::new("storage_locations_by_path");
const SOFT_PRESSURE_PERCENT: u64 = 85;
const HARD_PRESSURE_PERCENT: u64 = 95;
const BLOCK_ENVELOPE_MAGIC: &[u8; 8] = b"PEPBLK01";
const BLOCK_ENVELOPE_VERSION: u8 = 2;
const BLOCK_ENCODING_RAW: u8 = 0;
const BLOCK_ENCODING_ZSTD: u8 = 1;
const BLOCK_ENVELOPE_FIXED_BYTES: usize = 36;
const BLOCK_ENVELOPE_MAX_BYTES: u64 = 1024;
const BLOCK_CHECKSUM_CHUNK_BYTES: usize = 1024 * 1024;
const COMPRESSION_MIN_BYTES: usize = 1024;
const COMPRESSION_SAVINGS_PERCENT: usize = 10;
const COMPRESSION_PROBE_THRESHOLD_BYTES: usize = 256 * 1024;
const COMPRESSION_PROBE_REGION_BYTES: usize = 16 * 1024;
const INLINE_INTERNAL_BLOCK_MAX_BYTES: u64 = 64 * 1024;
const ZSTD_LEVEL: i32 = 1;
static PROCESS_BLOCK_READS: AtomicU64 = AtomicU64::new(0);
static PROCESS_BLOCK_READ_BYTES: AtomicU64 = AtomicU64::new(0);
static PROCESS_BLOCK_ENCODING_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static PROCESS_BLOCK_ENCODING_RAW: AtomicU64 = AtomicU64::new(0);
static PROCESS_BLOCK_ENCODING_ZSTD: AtomicU64 = AtomicU64::new(0);
static PROCESS_BLOCK_ENCODING_LOGICAL_BYTES: AtomicU64 = AtomicU64::new(0);
static PROCESS_BLOCK_ENCODING_STORED_BYTES: AtomicU64 = AtomicU64::new(0);
static PROCESS_BLOCK_ENCODING_MICROS: AtomicU64 = AtomicU64::new(0);
static PROCESS_INLINE_BLOCK_WRITES: AtomicU64 = AtomicU64::new(0);
static PROCESS_INLINE_BLOCK_WRITE_BYTES: AtomicU64 = AtomicU64::new(0);
static PROCESS_PACKED_BLOCK_WRITES: AtomicU64 = AtomicU64::new(0);
static PROCESS_PACKED_BLOCK_WRITE_BYTES: AtomicU64 = AtomicU64::new(0);
static PROCESS_PACKED_BLOCK_READS: AtomicU64 = AtomicU64::new(0);
static PROCESS_PACKED_BLOCK_READ_BYTES: AtomicU64 = AtomicU64::new(0);
static PROCESS_DATA_DURABILITY_BARRIERS: AtomicU64 = AtomicU64::new(0);
static PROCESS_DATA_FILES_DURABLE: AtomicU64 = AtomicU64::new(0);
static PROCESS_DIRECTORY_DURABILITY_BARRIERS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StorageIoStats {
    pub block_reads: u64,
    pub block_read_bytes: u64,
    pub inline_block_writes: u64,
    pub inline_block_write_bytes: u64,
    pub packed_block_writes: u64,
    pub packed_block_write_bytes: u64,
    pub packed_block_reads: u64,
    pub packed_block_read_bytes: u64,
    pub data_durability_barriers: u64,
    pub data_files_durable: u64,
    pub directory_durability_barriers: u64,
}

pub fn process_io_stats() -> StorageIoStats {
    StorageIoStats {
        block_reads: PROCESS_BLOCK_READS.load(Ordering::Relaxed),
        block_read_bytes: PROCESS_BLOCK_READ_BYTES.load(Ordering::Relaxed),
        inline_block_writes: PROCESS_INLINE_BLOCK_WRITES.load(Ordering::Relaxed),
        inline_block_write_bytes: PROCESS_INLINE_BLOCK_WRITE_BYTES.load(Ordering::Relaxed),
        packed_block_writes: PROCESS_PACKED_BLOCK_WRITES.load(Ordering::Relaxed),
        packed_block_write_bytes: PROCESS_PACKED_BLOCK_WRITE_BYTES.load(Ordering::Relaxed),
        packed_block_reads: PROCESS_PACKED_BLOCK_READS.load(Ordering::Relaxed),
        packed_block_read_bytes: PROCESS_PACKED_BLOCK_READ_BYTES.load(Ordering::Relaxed),
        data_durability_barriers: PROCESS_DATA_DURABILITY_BARRIERS.load(Ordering::Relaxed),
        data_files_durable: PROCESS_DATA_FILES_DURABLE.load(Ordering::Relaxed),
        directory_durability_barriers: PROCESS_DIRECTORY_DURABILITY_BARRIERS
            .load(Ordering::Relaxed),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StorageEncodingStats {
    pub attempts: u64,
    pub raw_blocks: u64,
    pub zstd_blocks: u64,
    pub logical_bytes: u64,
    pub stored_bytes: u64,
    pub encoding_micros: u64,
}

pub fn process_encoding_stats() -> StorageEncodingStats {
    StorageEncodingStats {
        attempts: PROCESS_BLOCK_ENCODING_ATTEMPTS.load(Ordering::Relaxed),
        raw_blocks: PROCESS_BLOCK_ENCODING_RAW.load(Ordering::Relaxed),
        zstd_blocks: PROCESS_BLOCK_ENCODING_ZSTD.load(Ordering::Relaxed),
        logical_bytes: PROCESS_BLOCK_ENCODING_LOGICAL_BYTES.load(Ordering::Relaxed),
        stored_bytes: PROCESS_BLOCK_ENCODING_STORED_BYTES.load(Ordering::Relaxed),
        encoding_micros: PROCESS_BLOCK_ENCODING_MICROS.load(Ordering::Relaxed),
    }
}

pub use native::NativeStats as NativeStorageStats;

pub fn process_native_stats() -> NativeStorageStats {
    native::stats()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteIntent {
    Normal,
    Repair,
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("invalid CID: {0}")]
    InvalidCid(#[from] pepper_types::CidParseError),
    #[error("block not found: {0}")]
    NotFound(Cid),
    #[error("block failed hash verification: {0}")]
    HashMismatch(Cid),
    #[error("invalid block range {start}..{end} for logical size {size}")]
    InvalidRange { start: u64, end: u64, size: u64 },
    #[error("storage capacity exceeded for block size {size_bytes} bytes")]
    CapacityExceeded { size_bytes: u64 },
    #[error("I/O error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("metadata transaction failed: {0}")]
    Transaction(#[from] Box<redb::TransactionError>),
    #[error("metadata table operation failed: {0}")]
    Table(#[from] Box<redb::TableError>),
    #[error("metadata storage operation failed: {0}")]
    RedbStorage(#[from] Box<redb::StorageError>),
    #[error("metadata commit failed: {0}")]
    Commit(#[from] Box<redb::CommitError>),
    #[error("metadata serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("no storage locations are configured")]
    NoStorageLocations,
    #[error("block size {size_bytes} exceeds maximum {max_bytes}")]
    BlockTooLarge { size_bytes: u64, max_bytes: u64 },
    #[error("storage location is already in use: {0}")]
    LocationLocked(String),
    #[error("storage write lock is poisoned")]
    LockPoisoned,
    #[error("batch block write did not produce a result")]
    BatchResultMissing,
    #[error("preverified CID does not match block codec: {0}")]
    PreverifiedCidMismatch(Cid),
    #[error("invalid encoded block: {0}")]
    InvalidEncodedBlock(String),
    #[error("block compression failed: {0}")]
    Compression(String),
    #[error("native storage engine failed: {0}")]
    Native(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockMeta {
    cid: Cid,
    codec: Codec,
    hash_alg: HashAlg,
    size_bytes: u64,
    stored_size_bytes: u64,
    storage_location_id: String,
    storage_location_path: String,
    relative_path: String,
    created_at_unix_seconds: u64,
    pin_state: String,
    replica_state: String,
    retention_class: String,
    verified_at_unix_seconds: Option<u64>,
    corrupt: bool,
    inline: bool,
}

/// Versioned physical representation of a logical content-addressed block.
/// The CID always identifies the decoded bytes, independent of this encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedBlock {
    cid: Cid,
    logical_size_bytes: u64,
    bytes: Vec<u8>,
}

impl EncodedBlock {
    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    pub fn logical_size_bytes(&self) -> u64 {
        self.logical_size_bytes
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StorageLocationMeta {
    id: String,
    path: String,
    max_capacity_bytes: u64,
    used_bytes: u64,
    reserved_bytes: u64,
    healthy: bool,
    last_checked_at_unix_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
struct StorageLocationRuntime {
    id: String,
    path: PathBuf,
    max_capacity_bytes: u64,
    _lock_file: Arc<File>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageSummary {
    pub capacity_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageLocationSummary {
    pub path: String,
    pub max_capacity_bytes: u64,
    pub used_bytes: u64,
    pub reserved_bytes: u64,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockInventoryEntry {
    pub cid: Cid,
    pub codec: Codec,
    pub logical_size_bytes: u64,
    pub stored_size_bytes: Option<u64>,
    pub storage_location_id: String,
    pub integrity_state: String,
    pub retention_class: String,
    pub pin_state: String,
    pub replica_state: String,
    pub verified_at_unix_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockInventoryPage {
    pub entries: Vec<BlockInventoryEntry>,
    pub next_cursor: Option<String>,
}

#[derive(Clone)]
enum PhysicalBackend {
    Files { packed: Option<PackedBackend> },
    Native(native::NativeEngine),
}

#[derive(Clone)]
struct PackedBackend {
    engine: native::NativeEngine,
    max_object_bytes: u64,
}

impl PhysicalBackend {
    fn native(&self) -> Option<&native::NativeEngine> {
        match self {
            Self::Files { packed } => packed.as_ref().map(|packed| &packed.engine),
            Self::Native(engine) => Some(engine),
        }
    }

    fn is_native(&self) -> bool {
        matches!(self, Self::Native(_))
    }

    fn packs(&self, block: &EncodedBlock) -> bool {
        match self {
            Self::Files {
                packed: Some(packed),
            } => {
                matches!(block.cid.codec, CODEC_SMALL_OBJECT | CODEC_BUCKET_OBJECT)
                    && !inline_internal_block(block)
                    && block.logical_size_bytes <= packed.max_object_bytes
            }
            Self::Files { packed: None } | Self::Native(_) => false,
        }
    }
}

#[derive(Clone)]
pub struct BlockStore {
    metadata: Arc<MetadataStore>,
    locations: Arc<Vec<StorageLocationRuntime>>,
    max_block_bytes: u64,
    write_lock: Arc<Mutex<()>>,
    backend: PhysicalBackend,
}

impl BlockStore {
    pub fn open(
        metadata: Arc<MetadataStore>,
        locations: &[StorageLocationConfig],
    ) -> Result<Self, StorageError> {
        Self::open_with_limit(metadata, locations, 64 * 1024 * 1024)
    }

    pub fn open_with_limit(
        metadata: Arc<MetadataStore>,
        locations: &[StorageLocationConfig],
        max_block_bytes: u64,
    ) -> Result<Self, StorageError> {
        Self::open_inner(metadata, locations, max_block_bytes, None, None)
    }

    pub fn open_with_config(
        metadata: Arc<MetadataStore>,
        storage: &StorageConfig,
        max_block_bytes: u64,
    ) -> Result<Self, StorageError> {
        let native = (storage.engine == StorageEngine::NativeNvme).then(|| storage.native.clone());
        let packed = (storage.engine == StorageEngine::Files && storage.small_object_pack.enabled)
            .then(|| storage.small_object_pack.clone());
        Self::open_inner(
            metadata,
            &storage.locations,
            max_block_bytes,
            native,
            packed,
        )
    }

    fn open_inner(
        metadata: Arc<MetadataStore>,
        locations: &[StorageLocationConfig],
        max_block_bytes: u64,
        native_config: Option<pepper_config::NativeStorageConfig>,
        packed_config: Option<SmallObjectPackConfig>,
    ) -> Result<Self, StorageError> {
        if locations.is_empty() {
            return Err(StorageError::NoStorageLocations);
        }
        let runtimes = locations
            .iter()
            .map(|location| initialize_location(&metadata, location))
            .collect::<Result<Vec<_>, _>>()?;
        let mut unique_paths = HashSet::new();
        if runtimes
            .iter()
            .any(|runtime| !unique_paths.insert(runtime.path.clone()))
        {
            return Err(StorageError::LocationLocked(
                "duplicate canonical storage location".to_string(),
            ));
        }
        let locations = Arc::new(runtimes);
        let backend = match native_config {
            Some(config) => PhysicalBackend::Native(native::NativeEngine::open(
                locations.clone(),
                config,
                "segments",
                "nvme",
            )?),
            None => {
                let packed = match packed_config {
                    Some(config) => Some(PackedBackend {
                        engine: native::NativeEngine::open(
                            locations.clone(),
                            config.native_config(),
                            "small-object-segments",
                            "small-pack",
                        )?,
                        max_object_bytes: config.max_object_bytes,
                    }),
                    None => None,
                };
                PhysicalBackend::Files { packed }
            }
        };
        let store = Self {
            metadata,
            locations,
            max_block_bytes,
            write_lock: Arc::new(Mutex::new(())),
            backend,
        };
        if store.backend.is_native() {
            store.reconcile_metadata_with_native()?;
        } else {
            store.reconcile_metadata_with_files()?;
            if store.backend.native().is_some() {
                store.reconcile_missing_native_metadata()?;
            }
        }
        Ok(store)
    }

    pub fn put_raw(&self, payload: &[u8]) -> Result<PutBlockResponse, StorageError> {
        self.put(CODEC_RAW, payload)
    }

    pub fn encode(&self, codec: Codec, payload: &[u8]) -> Result<EncodedBlock, StorageError> {
        if payload.len() as u64 > self.max_block_bytes {
            return Err(StorageError::BlockTooLarge {
                size_bytes: payload.len() as u64,
                max_bytes: self.max_block_bytes,
            });
        }
        encode_block(Cid::new(codec, payload), payload)
    }

    /// Frame a block whose CID was computed from these bytes by the caller.
    /// Erasure shards are already statistically whitened, so this canonical
    /// path skips a duplicate hash and a compression probe that cannot help.
    pub fn encode_preverified_raw(
        &self,
        cid: Cid,
        payload: &[u8],
    ) -> Result<EncodedBlock, StorageError> {
        if cid.codec != CODEC_RAW {
            return Err(StorageError::PreverifiedCidMismatch(cid));
        }
        if payload.len() as u64 > self.max_block_bytes {
            return Err(StorageError::BlockTooLarge {
                size_bytes: payload.len() as u64,
                max_bytes: self.max_block_bytes,
            });
        }
        let started = std::time::Instant::now();
        encode_block_payload(cid, payload, BLOCK_ENCODING_RAW, payload, started)
    }

    pub fn get_encoded(&self, cid: &Cid) -> Result<EncodedBlock, StorageError> {
        let meta = self
            .get_meta(cid)?
            .ok_or_else(|| StorageError::NotFound(cid.clone()))?;
        let stored = if is_native_meta(&meta) {
            self.backend
                .native()
                .ok_or_else(|| StorageError::NotFound(cid.clone()))?
                .read(cid)?
        } else if meta.inline {
            self.get_inline_block(cid)?
                .ok_or_else(|| StorageError::NotFound(cid.clone()))?
        } else {
            read_regular_file_bounded(
                &self.block_path(&meta),
                self.max_block_bytes
                    .saturating_add(BLOCK_ENVELOPE_MAX_BYTES),
            )?
        };
        self.record_packed_read(&meta, stored.len() as u64);
        decode_block_bytes(&stored, cid, self.max_block_bytes, Some(meta.size_bytes))?;
        Ok(EncodedBlock {
            cid: cid.clone(),
            logical_size_bytes: meta.size_bytes,
            bytes: stored,
        })
    }

    pub fn put_encoded(&self, block: &EncodedBlock) -> Result<PutBlockResponse, StorageError> {
        decode_block_bytes(
            &block.bytes,
            &block.cid,
            self.max_block_bytes,
            Some(block.logical_size_bytes),
        )?;
        self.put_encoded_batch_with_intent(std::slice::from_ref(block), WriteIntent::Normal)?
            .into_iter()
            .next()
            .ok_or(StorageError::BatchResultMissing)
    }

    pub fn put(&self, codec: Codec, payload: &[u8]) -> Result<PutBlockResponse, StorageError> {
        self.put_with_intent(codec, payload, WriteIntent::Normal)
    }

    pub fn put_replica(
        &self,
        codec: Codec,
        payload: &[u8],
    ) -> Result<PutBlockResponse, StorageError> {
        self.put_with_intent(codec, payload, WriteIntent::Repair)
    }

    /// Store bytes whose CID was already verified by the authenticated
    /// transport. This avoids hashing a replica a second time in storage.
    pub fn put_replica_verified(
        &self,
        codec: Codec,
        payload: &[u8],
        cid: &Cid,
    ) -> Result<PutBlockResponse, StorageError> {
        self.put_with_intent_and_cid(codec, payload, WriteIntent::Repair, Some(cid))
    }

    pub fn put_batch(
        &self,
        blocks: &[(Codec, Vec<u8>)],
    ) -> Result<Vec<PutBlockResponse>, StorageError> {
        self.put_batch_with_intent(blocks, WriteIntent::Normal)
    }

    pub fn put_replica_batch(
        &self,
        blocks: &[(Codec, Vec<u8>)],
    ) -> Result<Vec<PutBlockResponse>, StorageError> {
        self.put_batch_with_intent(blocks, WriteIntent::Repair)
    }

    pub fn put_replica_batch_verified(
        &self,
        blocks: &[(Codec, Vec<u8>)],
        cids: &[Cid],
    ) -> Result<Vec<PutBlockResponse>, StorageError> {
        if blocks.len() != cids.len() {
            return Err(StorageError::BatchResultMissing);
        }
        self.put_batch_with_intent_and_cids(blocks, WriteIntent::Repair, Some(cids))
    }

    fn put_batch_with_intent(
        &self,
        blocks: &[(Codec, Vec<u8>)],
        intent: WriteIntent,
    ) -> Result<Vec<PutBlockResponse>, StorageError> {
        self.put_batch_with_intent_and_cids(blocks, intent, None)
    }

    fn put_batch_with_intent_and_cids(
        &self,
        blocks: &[(Codec, Vec<u8>)],
        intent: WriteIntent,
        preverified_cids: Option<&[Cid]>,
    ) -> Result<Vec<PutBlockResponse>, StorageError> {
        let mut encoded = Vec::with_capacity(blocks.len());
        for (input_index, (codec, payload)) in blocks.iter().enumerate() {
            if payload.len() as u64 > self.max_block_bytes {
                return Err(StorageError::BlockTooLarge {
                    size_bytes: payload.len() as u64,
                    max_bytes: self.max_block_bytes,
                });
            }
            let cid = if let Some(cids) = preverified_cids {
                let cid = cids
                    .get(input_index)
                    .ok_or(StorageError::BatchResultMissing)?
                    .clone();
                if cid.codec != *codec {
                    return Err(StorageError::PreverifiedCidMismatch(cid));
                }
                cid
            } else {
                Cid::new(*codec, payload)
            };
            encoded.push(encode_block(cid, payload)?);
        }
        self.put_encoded_batch_with_intent(&encoded, intent)
    }

    /// Encode logical blocks once and persist exactly those bytes. The returned
    /// representation is suitable for replica transfer and later repair.
    pub fn put_batch_with_encoded(
        &self,
        blocks: &[(Codec, Vec<u8>)],
    ) -> Result<(Vec<PutBlockResponse>, Vec<EncodedBlock>), StorageError> {
        let mut encoded = Vec::with_capacity(blocks.len());
        for (codec, payload) in blocks {
            if payload.len() as u64 > self.max_block_bytes {
                return Err(StorageError::BlockTooLarge {
                    size_bytes: payload.len() as u64,
                    max_bytes: self.max_block_bytes,
                });
            }
            encoded.push(encode_block(Cid::new(*codec, payload), payload)?);
        }
        let puts = self.put_encoded_batch_with_intent(&encoded, WriteIntent::Normal)?;
        for (put, block) in puts.iter().zip(&mut encoded) {
            if put.already_existed {
                *block = self.get_encoded(&put.cid)?;
            }
        }
        Ok((puts, encoded))
    }

    /// Validate a replica's encoded representation against its logical CID and
    /// store it without recompressing it.
    pub fn put_replica_encoded_batch(
        &self,
        encoded_blocks: &[EncodedBlock],
    ) -> Result<Vec<PutBlockResponse>, StorageError> {
        for block in encoded_blocks {
            decode_block_bytes(
                &block.bytes,
                &block.cid,
                self.max_block_bytes,
                Some(block.logical_size_bytes),
            )?;
        }
        self.put_encoded_batch_with_intent(encoded_blocks, WriteIntent::Repair)
    }

    pub fn validate_encoded_replica(
        &self,
        cid: Cid,
        logical_size_bytes: u64,
        bytes: Vec<u8>,
    ) -> Result<EncodedBlock, StorageError> {
        decode_block_bytes(&bytes, &cid, self.max_block_bytes, Some(logical_size_bytes))?;
        Ok(EncodedBlock {
            cid,
            logical_size_bytes,
            bytes,
        })
    }

    pub fn put_replica_encoded_wire_batch(
        &self,
        blocks: Vec<(Cid, u64, Vec<u8>)>,
    ) -> Result<Vec<PutBlockResponse>, StorageError> {
        let encoded = blocks
            .into_iter()
            .map(|(cid, logical_size_bytes, bytes)| {
                self.validate_encoded_replica(cid, logical_size_bytes, bytes)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.put_encoded_batch_with_intent(&encoded, WriteIntent::Repair)
    }

    fn put_encoded_batch_with_intent(
        &self,
        blocks: &[EncodedBlock],
        intent: WriteIntent,
    ) -> Result<Vec<PutBlockResponse>, StorageError> {
        if self.backend.is_native() {
            return self.put_native_encoded_batch(blocks, intent);
        }
        let packed_indices = blocks
            .iter()
            .enumerate()
            .filter_map(|(index, block)| self.backend.packs(block).then_some(index))
            .collect::<Vec<_>>();
        if packed_indices.is_empty() {
            return self.put_files_encoded_batch_with_intent(blocks, intent);
        }
        if packed_indices.len() == blocks.len() {
            let results = self.put_native_encoded_batch(blocks, intent)?;
            record_packed_writes(blocks, &results);
            return Ok(results);
        }

        let packed = packed_indices
            .iter()
            .map(|index| blocks[*index].clone())
            .collect::<Vec<_>>();
        let packed_set = packed_indices.iter().copied().collect::<HashSet<_>>();
        let file_indices = (0..blocks.len())
            .filter(|index| !packed_set.contains(index))
            .collect::<Vec<_>>();
        let files = file_indices
            .iter()
            .map(|index| blocks[*index].clone())
            .collect::<Vec<_>>();
        let packed_results = self.put_native_encoded_batch(&packed, intent)?;
        record_packed_writes(&packed, &packed_results);
        let file_results = self.put_files_encoded_batch_with_intent(&files, intent)?;
        let mut results = vec![None; blocks.len()];
        for (index, result) in packed_indices.into_iter().zip(packed_results) {
            results[index] = Some(result);
        }
        for (index, result) in file_indices.into_iter().zip(file_results) {
            results[index] = Some(result);
        }
        results
            .into_iter()
            .map(|result| result.ok_or(StorageError::BatchResultMissing))
            .collect()
    }

    fn put_files_encoded_batch_with_intent(
        &self,
        blocks: &[EncodedBlock],
        intent: WriteIntent,
    ) -> Result<Vec<PutBlockResponse>, StorageError> {
        struct PreparedBlock {
            input_index: usize,
            meta: BlockMeta,
            temp_path: Option<PathBuf>,
            final_path: Option<PathBuf>,
            temp_file: Option<File>,
            inline_bytes: Option<Vec<u8>>,
            durability_required: bool,
        }

        for block in blocks {
            if block.logical_size_bytes > self.max_block_bytes {
                return Err(StorageError::BlockTooLarge {
                    size_bytes: block.logical_size_bytes,
                    max_bytes: self.max_block_bytes,
                });
            }
        }
        let _write_guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let mut results = vec![None; blocks.len()];
        let mut known = HashMap::<Cid, PutBlockResponse>::new();
        let mut pending_by_location = HashMap::<String, u64>::new();
        let mut prepared = Vec::<PreparedBlock>::new();

        for (input_index, block) in blocks.iter().enumerate() {
            let cid = block.cid.clone();
            if let Some(existing) = known.get(&cid) {
                let mut duplicate = existing.clone();
                duplicate.already_existed = true;
                results[input_index] = Some(duplicate);
                continue;
            }
            if let Some(meta) = self.get_meta(&cid)? {
                let existing_valid = !meta.corrupt
                    && if meta.inline {
                        self.inline_block_is_valid(&meta)?
                    } else if is_native_meta(&meta) {
                        self.backend
                            .native()
                            .is_some_and(|native| native.contains(&cid).unwrap_or(false))
                    } else {
                        let path = self.block_path(&meta);
                        match verify_file(&path, &cid, self.max_block_bytes) {
                            Ok(valid) => valid,
                            Err(StorageError::BlockTooLarge { .. }) => false,
                            Err(error) => return Err(error),
                        }
                    };
                if existing_valid {
                    let response = meta.to_put_response(true);
                    known.insert(cid, response.clone());
                    results[input_index] = Some(response);
                    continue;
                }
                if is_native_meta(&meta) {
                    if let Some(native) = self.backend.native() {
                        native.delete(&meta.cid)?;
                    }
                } else if !meta.inline {
                    let path = self.block_path(&meta);
                    if path.exists() {
                        fs::remove_file(&path).map_err(|source| StorageError::Io {
                            path: path.display().to_string(),
                            source,
                        })?;
                    }
                }
                self.remove_block_meta(&meta)?;
            }

            let size = block.logical_size_bytes;
            let stored_size = block.bytes.len() as u64;
            let location =
                self.select_location_with_pending(stored_size, intent, &pending_by_location)?;
            *pending_by_location.entry(location.id.clone()).or_default() += stored_size;
            let inline = inline_internal_block(block);
            let (relative_path, final_path, temp_path, temp_file, inline_bytes) = if inline {
                (String::new(), None, None, None, Some(block.bytes.clone()))
            } else {
                let relative_path = relative_block_path(&cid);
                let final_path = location.path.join(&relative_path);
                let temp_path = location.path.join("tmp").join(format!(
                    "batch-{}-{}-{input_index}.tmp",
                    unix_nanos(),
                    std::process::id()
                ));
                let temp_file = write_temp_file_unflushed(&temp_path, &block.bytes)?;
                (
                    relative_path.to_string_lossy().to_string(),
                    Some(final_path),
                    Some(temp_path),
                    Some(temp_file),
                    None,
                )
            };
            let now = unix_seconds();
            let meta = BlockMeta {
                cid: cid.clone(),
                codec: cid.codec,
                hash_alg: cid.hash_alg,
                size_bytes: size,
                stored_size_bytes: stored_size,
                storage_location_id: location.id.clone(),
                storage_location_path: location.path.display().to_string(),
                relative_path,
                created_at_unix_seconds: now,
                pin_state: "none".to_string(),
                replica_state: "none".to_string(),
                retention_class: "cache".to_string(),
                verified_at_unix_seconds: Some(now),
                corrupt: false,
                inline,
            };
            let response = meta.to_put_response(false);
            known.insert(cid, response);
            prepared.push(PreparedBlock {
                input_index,
                meta,
                temp_path,
                final_path,
                temp_file,
                inline_bytes,
                durability_required: false,
            });
        }

        // Portable targets must make each temp file durable before rename.
        // Linux uses one filesystem-wide barrier after every rename below, so
        // both file data and directory metadata share the same group commit.
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let mut data_files = 0u64;
            for block in &prepared {
                if let (Some(file), Some(path)) = (&block.temp_file, &block.temp_path) {
                    file.sync_data().map_err(|source| StorageError::Io {
                        path: path.display().to_string(),
                        source,
                    })?;
                    data_files += 1;
                }
            }
            PROCESS_DATA_DURABILITY_BARRIERS.fetch_add(data_files, Ordering::Relaxed);
            PROCESS_DATA_FILES_DURABLE.fetch_add(data_files, Ordering::Relaxed);
            if data_files > 0 {
                observe_current_stage(OperationStage::Durability);
                add_current_cost(OperationCostMetric::DurabilityBarriers, data_files);
            }
        }
        for block in &mut prepared {
            drop(block.temp_file.take());
        }

        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let mut changed_parents = HashSet::<PathBuf>::new();
        for block in &mut prepared {
            if block.meta.inline {
                results[block.input_index] = Some(block.meta.to_put_response(false));
                continue;
            }
            let final_path = block
                .final_path
                .as_ref()
                .expect("file-backed block has a final path");
            let temp_path = block
                .temp_path
                .as_ref()
                .expect("file-backed block has a temporary path");
            if let Some(parent) = final_path.parent() {
                fs::create_dir_all(parent).map_err(|source| StorageError::Io {
                    path: parent.display().to_string(),
                    source,
                })?;
            }
            let final_valid = final_path.exists()
                && match verify_file(final_path, &block.meta.cid, self.max_block_bytes) {
                    Ok(valid) => valid,
                    Err(StorageError::BlockTooLarge { .. }) => false,
                    Err(error) => return Err(error),
                };
            if final_valid {
                fs::remove_file(temp_path).map_err(|source| StorageError::Io {
                    path: temp_path.display().to_string(),
                    source,
                })?;
                results[block.input_index] = Some(block.meta.to_put_response(true));
            } else {
                if final_path.exists() {
                    fs::remove_file(final_path).map_err(|source| StorageError::Io {
                        path: final_path.display().to_string(),
                        source,
                    })?;
                }
                fs::rename(temp_path, final_path).map_err(|source| StorageError::Io {
                    path: final_path.display().to_string(),
                    source,
                })?;
                block.durability_required = true;
                #[cfg(not(any(target_os = "linux", target_os = "android")))]
                if let Some(parent) = final_path.parent() {
                    changed_parents.insert(parent.to_path_buf());
                }
                results[block.input_index] = Some(block.meta.to_put_response(false));
            }
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let mut filesystems = HashMap::<u64, (File, PathBuf)>::new();
            let mut data_files = 0u64;
            for block in prepared.iter().filter(|block| block.durability_required) {
                let path = block
                    .final_path
                    .as_ref()
                    .expect("durable file-backed block has a final path");
                let file = File::open(path).map_err(|source| StorageError::Io {
                    path: path.display().to_string(),
                    source,
                })?;
                let device = file
                    .metadata()
                    .map_err(|source| StorageError::Io {
                        path: path.display().to_string(),
                        source,
                    })?
                    .dev();
                filesystems
                    .entry(device)
                    .or_insert_with(|| (file, path.clone()));
                data_files += 1;
            }
            for (file, path) in filesystems.values() {
                rustix::fs::syncfs(file).map_err(|source| StorageError::Io {
                    path: path.display().to_string(),
                    source: source.into(),
                })?;
            }
            PROCESS_DATA_DURABILITY_BARRIERS.fetch_add(filesystems.len() as u64, Ordering::Relaxed);
            PROCESS_DATA_FILES_DURABLE.fetch_add(data_files, Ordering::Relaxed);
            if !filesystems.is_empty() {
                observe_current_stage(OperationStage::Durability);
                add_current_cost(
                    OperationCostMetric::DurabilityBarriers,
                    filesystems.len() as u64,
                );
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        for parent in changed_parents {
            File::open(&parent)
                .and_then(|file| file.sync_all())
                .map_err(|source| StorageError::Io {
                    path: parent.display().to_string(),
                    source,
                })?;
            PROCESS_DIRECTORY_DURABILITY_BARRIERS.fetch_add(1, Ordering::Relaxed);
            observe_current_stage(OperationStage::Durability);
            add_current_cost(OperationCostMetric::DurabilityBarriers, 1);
        }
        let metas = prepared
            .iter()
            .map(|block| block.meta.clone())
            .collect::<Vec<_>>();
        let inline_blocks = prepared
            .iter()
            .filter_map(|block| {
                block
                    .inline_bytes
                    .as_ref()
                    .map(|bytes| (block.meta.cid.clone(), bytes.clone()))
            })
            .collect::<Vec<_>>();
        self.insert_block_metas_and_inline(&metas, &inline_blocks)?;
        PROCESS_INLINE_BLOCK_WRITES.fetch_add(inline_blocks.len() as u64, Ordering::Relaxed);
        PROCESS_INLINE_BLOCK_WRITE_BYTES.fetch_add(
            inline_blocks
                .iter()
                .map(|(_, bytes)| bytes.len() as u64)
                .sum(),
            Ordering::Relaxed,
        );

        results
            .into_iter()
            .map(|result| result.ok_or(StorageError::BatchResultMissing))
            .collect()
    }

    fn put_native_encoded_batch(
        &self,
        blocks: &[EncodedBlock],
        _intent: WriteIntent,
    ) -> Result<Vec<PutBlockResponse>, StorageError> {
        let engine = self
            .backend
            .native()
            .ok_or_else(|| StorageError::Native("native engine is not open".to_string()))?;
        let mut metadata_missing = Vec::with_capacity(blocks.len());
        for block in blocks {
            if block.logical_size_bytes > self.max_block_bytes {
                return Err(StorageError::BlockTooLarge {
                    size_bytes: block.logical_size_bytes,
                    max_bytes: self.max_block_bytes,
                });
            }
            // EncodedBlock has no public unchecked constructor. Local paths
            // create it from logical bytes, while public and wire replica
            // paths verify it before entering this trusted internal method.
            // Re-decoding here would hash every large block twice and made the
            // native backend substantially slower than the files backend.
            let present = engine.contains(block.cid())?;
            let metadata = self.get_meta(block.cid())?;
            if !present && let Some(stale) = metadata.as_ref() {
                self.remove_block_meta(stale)?;
            }
            metadata_missing.push(metadata.is_none());
        }
        let records = engine.put_batch(blocks)?;
        let now = unix_seconds();
        let metas = records
            .iter()
            .map(|record| {
                let location = self.locations.get(record.location_index).ok_or_else(|| {
                    StorageError::Native("native record location is invalid".to_string())
                })?;
                Ok(BlockMeta {
                    cid: record.cid.clone(),
                    codec: record.cid.codec,
                    hash_alg: record.cid.hash_alg,
                    size_bytes: record.logical_size,
                    stored_size_bytes: record.stored_size,
                    storage_location_id: location.id.clone(),
                    storage_location_path: location.path.display().to_string(),
                    relative_path: native_relative_path(record),
                    created_at_unix_seconds: now,
                    pin_state: "none".to_string(),
                    replica_state: "none".to_string(),
                    retention_class: "cache".to_string(),
                    verified_at_unix_seconds: Some(now),
                    corrupt: false,
                    inline: false,
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        let new_metas = metas
            .iter()
            .zip(&records)
            .zip(&metadata_missing)
            .filter_map(|((meta, record), metadata_missing)| {
                (!record.already_existed || *metadata_missing).then_some(meta.clone())
            })
            .collect::<Vec<_>>();
        self.insert_block_metas(&new_metas)?;
        Ok(metas
            .into_iter()
            .zip(records)
            .map(|(meta, record)| meta.to_put_response(record.already_existed))
            .collect())
    }

    fn put_with_intent(
        &self,
        codec: Codec,
        payload: &[u8],
        intent: WriteIntent,
    ) -> Result<PutBlockResponse, StorageError> {
        self.put_with_intent_and_cid(codec, payload, intent, None)
    }

    fn put_with_intent_and_cid(
        &self,
        codec: Codec,
        payload: &[u8],
        intent: WriteIntent,
        preverified_cid: Option<&Cid>,
    ) -> Result<PutBlockResponse, StorageError> {
        let cid = if let Some(cid) = preverified_cid {
            if cid.codec != codec {
                return Err(StorageError::PreverifiedCidMismatch(cid.clone()));
            }
            cid.clone()
        } else {
            Cid::new(codec, payload)
        };
        let encoded = encode_block(cid, payload)?;
        self.put_encoded_batch_with_intent(std::slice::from_ref(&encoded), intent)?
            .into_iter()
            .next()
            .ok_or(StorageError::BatchResultMissing)
    }

    pub fn get(&self, cid: &Cid) -> Result<Block, StorageError> {
        let meta = self
            .get_meta(cid)?
            .ok_or_else(|| StorageError::NotFound(cid.clone()))?;
        if meta.size_bytes > self.max_block_bytes {
            return Err(StorageError::BlockTooLarge {
                size_bytes: meta.size_bytes,
                max_bytes: self.max_block_bytes,
            });
        }
        let stored = if is_native_meta(&meta) {
            self.backend
                .native()
                .ok_or_else(|| StorageError::NotFound(cid.clone()))?
                .read(cid)?
        } else if meta.inline {
            self.get_inline_block(cid)?
                .ok_or_else(|| StorageError::NotFound(cid.clone()))?
        } else {
            let path = self.block_path(&meta);
            read_regular_file_bounded(
                &path,
                self.max_block_bytes
                    .saturating_add(BLOCK_ENVELOPE_MAX_BYTES),
            )?
        };
        let payload =
            match decode_block_bytes(&stored, cid, self.max_block_bytes, Some(meta.size_bytes)) {
                Ok(payload) => payload,
                Err(StorageError::HashMismatch(_)) | Err(StorageError::InvalidEncodedBlock(_)) => {
                    self.mark_corrupt(cid)?;
                    return Err(StorageError::HashMismatch(cid.clone()));
                }
                Err(error) => return Err(error),
            };
        PROCESS_BLOCK_READS.fetch_add(1, Ordering::Relaxed);
        PROCESS_BLOCK_READ_BYTES.fetch_add(payload.len() as u64, Ordering::Relaxed);
        self.record_packed_read(&meta, payload.len() as u64);
        Ok(Block {
            cid: cid.clone(),
            codec: meta.codec,
            size: payload.len() as u64,
            payload,
        })
    }

    /// Read an exclusive logical byte range. Canonical raw envelopes verify
    /// only the independently checksummed 1 MiB regions covering the request;
    /// compressed and inline blocks fall back to full verified decode.
    pub fn get_range(&self, cid: &Cid, start: u64, end: u64) -> Result<Vec<u8>, StorageError> {
        let meta = self
            .get_meta(cid)?
            .ok_or_else(|| StorageError::NotFound(cid.clone()))?;
        if start > end || end > meta.size_bytes {
            return Err(StorageError::InvalidRange {
                start,
                end,
                size: meta.size_bytes,
            });
        }
        if start == end {
            return Ok(Vec::new());
        }
        if meta.inline || (start == 0 && end == meta.size_bytes) {
            let payload = self.get(cid)?.payload;
            if start == 0 && end == meta.size_bytes {
                return Ok(payload);
            }
            return Ok(payload[start as usize..end as usize].to_vec());
        }
        if is_native_meta(&meta) {
            let native = self
                .backend
                .native()
                .ok_or_else(|| StorageError::NotFound(cid.clone()))?;
            match read_native_raw_block_range(
                native,
                cid,
                self.max_block_bytes,
                meta.size_bytes,
                start,
                end,
                meta.stored_size_bytes,
            ) {
                Ok(Some((payload, bytes_read))) => {
                    PROCESS_BLOCK_READS.fetch_add(1, Ordering::Relaxed);
                    PROCESS_BLOCK_READ_BYTES.fetch_add(bytes_read, Ordering::Relaxed);
                    self.record_packed_read(&meta, bytes_read);
                    return Ok(payload);
                }
                Ok(None) => {
                    let payload = self.get(cid)?.payload;
                    return Ok(payload[start as usize..end as usize].to_vec());
                }
                Err(StorageError::HashMismatch(_)) | Err(StorageError::InvalidEncodedBlock(_)) => {
                    self.mark_corrupt(cid)?;
                    return Err(StorageError::HashMismatch(cid.clone()));
                }
                Err(error) => return Err(error),
            }
        }
        let path = self.block_path(&meta);
        match read_raw_block_range(
            &path,
            cid,
            self.max_block_bytes,
            meta.size_bytes,
            start,
            end,
        ) {
            Ok(Some((payload, bytes_read))) => {
                PROCESS_BLOCK_READS.fetch_add(1, Ordering::Relaxed);
                PROCESS_BLOCK_READ_BYTES.fetch_add(bytes_read, Ordering::Relaxed);
                Ok(payload)
            }
            Ok(None) => {
                let payload = self.get(cid)?.payload;
                Ok(payload[start as usize..end as usize].to_vec())
            }
            Err(StorageError::HashMismatch(_)) | Err(StorageError::InvalidEncodedBlock(_)) => {
                self.mark_corrupt(cid)?;
                Err(StorageError::HashMismatch(cid.clone()))
            }
            Err(error) => Err(error),
        }
    }

    pub fn has(&self, cid: &Cid) -> Result<bool, StorageError> {
        let Some(meta) = self.get_meta(cid)? else {
            return Ok(false);
        };
        if meta.corrupt || meta.size_bytes > self.max_block_bytes {
            return Ok(false);
        }
        if meta.inline {
            return self.inline_block_is_valid(&meta);
        }
        if is_native_meta(&meta) {
            return self
                .backend
                .native()
                .map_or(Ok(false), |engine| engine.contains(cid));
        }
        let path = self.block_path(&meta);
        let Ok(file_meta) = path.symlink_metadata() else {
            return Ok(false);
        };
        Ok(file_meta.is_file() && file_meta.len() == meta.stored_size_bytes)
    }

    pub fn stat(&self, cid: &Cid) -> Result<BlockStatResponse, StorageError> {
        let meta = self
            .get_meta(cid)?
            .ok_or_else(|| StorageError::NotFound(cid.clone()))?;
        Ok(meta.to_stat_response())
    }

    pub fn quarantine_block(&self, cid: &Cid) -> Result<(), StorageError> {
        let _write_guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let Some(meta) = self.get_meta(cid)? else {
            return Ok(());
        };
        let path = self.block_path(&meta);
        if is_native_meta(&meta) {
            if let Some(native) = self.backend.native() {
                native.delete(cid)?;
            }
        } else if !meta.inline
            && path.exists()
            && let Some(location) = self
                .locations
                .iter()
                .find(|location| location.id == meta.storage_location_id)
        {
            quarantine_file(location, &path)?;
        }
        self.remove_block_meta(&meta)?;
        self.rebuild_storage_location_usage()
    }

    /// Remove a verified stale repair/migration copy. Callers must first prove
    /// that this node is neither a canonical owner nor an active exception
    /// target and that the canonical placement is healthy.
    pub fn delete_repair_extra(&self, cid: &Cid) -> Result<bool, StorageError> {
        let _write_guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let Some(meta) = self.get_meta(cid)? else {
            return Ok(false);
        };
        if is_native_meta(&meta) {
            if let Some(native) = self.backend.native() {
                native.delete(cid)?;
            }
        } else if !meta.inline {
            let path = self.block_path(&meta);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(StorageError::Io {
                        path: path.display().to_string(),
                        source,
                    });
                }
            }
        }
        self.remove_block_meta(&meta)?;
        self.rebuild_storage_location_usage()?;
        Ok(true)
    }

    pub fn corruption_scan(&self) -> Result<(usize, Vec<Cid>), StorageError> {
        let metas = self.list_block_metas()?;
        let scanned = metas.len();
        let mut corrupt = Vec::new();
        for meta in metas {
            if meta.corrupt || self.get(&meta.cid).is_err() {
                corrupt.push(meta.cid);
            }
        }
        Ok((scanned, corrupt))
    }

    pub fn list_blocks(&self) -> Result<Vec<BlockStatResponse>, StorageError> {
        Ok(self
            .list_block_metas()?
            .into_iter()
            .filter(|meta| {
                !meta.corrupt
                    && if meta.inline {
                        self.get_inline_block(&meta.cid)
                            .is_ok_and(|value| value.is_some())
                    } else if is_native_meta(meta) {
                        self.backend
                            .native()
                            .is_some_and(|native| native.contains(&meta.cid).unwrap_or(false))
                    } else {
                        self.block_path(meta).exists()
                    }
            })
            .map(|meta| meta.to_stat_response())
            .collect())
    }

    pub fn inventory_page(
        &self,
        after: Option<&Cid>,
        limit: usize,
    ) -> Result<BlockInventoryPage, StorageError> {
        let mut metas = self.list_block_metas()?;
        metas.sort_by_key(|meta| meta.cid.to_string());
        let after = after.map(ToString::to_string);
        let mut matching = metas
            .into_iter()
            .filter(|meta| {
                after
                    .as_ref()
                    .is_none_or(|cursor| meta.cid.to_string() > *cursor)
            })
            .take(limit.saturating_add(1))
            .collect::<Vec<_>>();
        let has_more = matching.len() > limit;
        matching.truncate(limit);
        let entries = matching
            .iter()
            .map(|meta| {
                let stored_size_bytes = if is_native_meta(meta) {
                    self.backend
                        .native()
                        .and_then(|native| native.contains(&meta.cid).ok())
                        .filter(|present| *present)
                        .map(|_| meta.stored_size_bytes)
                } else if meta.inline {
                    self.get_inline_block(&meta.cid)
                        .ok()
                        .flatten()
                        .map(|bytes| bytes.len() as u64)
                } else {
                    let path = self.block_path(meta);
                    path.symlink_metadata()
                        .ok()
                        .filter(|file| file.is_file())
                        .map(|file| file.len())
                };
                let integrity_state = if meta.corrupt {
                    "corrupt"
                } else if stored_size_bytes.is_none() {
                    "missing"
                } else if stored_size_bytes != Some(meta.stored_size_bytes) {
                    "size_mismatch"
                } else if meta.verified_at_unix_seconds.is_some() {
                    "verified"
                } else {
                    "unverified"
                };
                BlockInventoryEntry {
                    cid: meta.cid.clone(),
                    codec: meta.codec,
                    logical_size_bytes: meta.size_bytes,
                    stored_size_bytes,
                    storage_location_id: meta.storage_location_id.clone(),
                    integrity_state: integrity_state.to_string(),
                    retention_class: meta.retention_class.clone(),
                    pin_state: meta.pin_state.clone(),
                    replica_state: meta.replica_state.clone(),
                    verified_at_unix_seconds: meta.verified_at_unix_seconds,
                }
            })
            .collect::<Vec<_>>();
        let next_cursor = has_more
            .then(|| entries.last().map(|entry| entry.cid.to_string()))
            .flatten();
        Ok(BlockInventoryPage {
            entries,
            next_cursor,
        })
    }

    pub fn storage_location_summaries(&self) -> Result<Vec<StorageLocationSummary>, StorageError> {
        let mut summaries = Vec::new();
        for location in self.locations.iter() {
            if let Some(meta) = self.get_location_meta(&location.id)? {
                summaries.push(StorageLocationSummary {
                    path: meta.path,
                    max_capacity_bytes: meta.max_capacity_bytes,
                    used_bytes: meta.used_bytes,
                    reserved_bytes: meta.reserved_bytes,
                    healthy: meta.healthy,
                });
            }
        }
        summaries.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(summaries)
    }

    pub fn storage_summary(&self) -> Result<StorageSummary, StorageError> {
        let mut capacity_bytes = 0u64;
        let mut used_bytes = 0u64;
        for location in self.locations.iter() {
            let Some(meta) = self.get_location_meta(&location.id)? else {
                continue;
            };
            if !meta.healthy {
                continue;
            }
            capacity_bytes = capacity_bytes.saturating_add(meta.max_capacity_bytes);
            used_bytes =
                used_bytes.saturating_add(meta.used_bytes.saturating_add(meta.reserved_bytes));
        }
        Ok(StorageSummary {
            capacity_bytes,
            used_bytes,
            available_bytes: capacity_bytes.saturating_sub(used_bytes),
        })
    }

    fn list_block_metas(&self) -> Result<Vec<BlockMeta>, StorageError> {
        let read_txn = self
            .metadata
            .database()
            .begin_read()
            .map_err(|source| StorageError::Transaction(Box::new(source)))?;
        let table = match read_txn.open_table(BLOCKS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(source) => return Err(StorageError::Table(Box::new(source))),
        };
        let mut blocks = Vec::new();
        for item in table
            .iter()
            .map_err(|source| StorageError::RedbStorage(Box::new(source)))?
        {
            let (_, value) = item.map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
            blocks.push(serde_json::from_slice(value.value())?);
        }
        Ok(blocks)
    }

    pub fn purge_quarantine(&self) -> Result<GcReport, StorageError> {
        let _write_guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let mut deleted_blocks = 0usize;
        let mut reclaimed_bytes = 0u64;
        for location in self.locations.iter() {
            let root = location.path.join("gc");
            if !root.exists() {
                continue;
            }
            for entry in fs::read_dir(&root).map_err(|source| StorageError::Io {
                path: root.display().to_string(),
                source,
            })? {
                let path = entry
                    .map_err(|source| StorageError::Io {
                        path: root.display().to_string(),
                        source,
                    })?
                    .path();
                let metadata = path.symlink_metadata().map_err(|source| StorageError::Io {
                    path: path.display().to_string(),
                    source,
                })?;
                if metadata.is_file() {
                    fs::remove_file(&path).map_err(|source| StorageError::Io {
                        path: path.display().to_string(),
                        source,
                    })?;
                    deleted_blocks += 1;
                    reclaimed_bytes = reclaimed_bytes.saturating_add(metadata.len());
                }
            }
        }
        self.rebuild_storage_location_usage()?;
        Ok(GcReport {
            protected_blocks: 0,
            deleted_blocks,
            reclaimed_bytes,
        })
    }

    pub fn garbage_collect(&self, protected: &HashSet<Cid>) -> Result<GcReport, StorageError> {
        self.garbage_collect_inner(protected, false)
    }

    pub fn garbage_collect_dry_run(
        &self,
        protected: &HashSet<Cid>,
    ) -> Result<GcReport, StorageError> {
        self.garbage_collect_inner(protected, true)
    }

    fn garbage_collect_inner(
        &self,
        protected: &HashSet<Cid>,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        let _write_guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let blocks = self
            .list_block_metas()?
            .into_iter()
            .filter(|meta| !meta.corrupt && !protected.contains(&meta.cid))
            .collect::<Vec<_>>();
        let mut deleted_blocks = 0usize;
        let mut reclaimed_bytes = 0u64;
        for meta in blocks {
            if !dry_run {
                if is_native_meta(&meta) {
                    if let Some(native) = self.backend.native() {
                        native.delete(&meta.cid)?;
                    }
                } else if !meta.inline {
                    let path = self.block_path(&meta);
                    if path.exists() {
                        fs::remove_file(&path).map_err(|source| StorageError::Io {
                            path: path.display().to_string(),
                            source,
                        })?;
                    }
                }
                self.remove_block_meta(&meta)?;
            }
            deleted_blocks += 1;
            reclaimed_bytes = reclaimed_bytes.saturating_add(meta.stored_size_bytes);
        }
        Ok(GcReport {
            protected_blocks: protected.len(),
            deleted_blocks,
            reclaimed_bytes,
        })
    }

    pub fn parse_cid(value: &str) -> Result<Cid, StorageError> {
        Cid::from_str(value).map_err(StorageError::from)
    }

    fn reconcile_metadata_with_native(&self) -> Result<(), StorageError> {
        let records = self.validated_native_records()?;
        for meta in self.list_block_metas()? {
            let present = if meta.inline {
                self.inline_block_is_valid(&meta)?
            } else {
                is_native_meta(&meta) && records.contains_key(&meta.cid)
            };
            if !present {
                self.remove_block_meta(&meta)?;
            }
        }
        self.insert_missing_native_metadata(&records)?;
        self.rebuild_storage_location_usage()
    }

    fn reconcile_missing_native_metadata(&self) -> Result<(), StorageError> {
        let records = self.validated_native_records()?;
        self.insert_missing_native_metadata(&records)?;
        self.rebuild_storage_location_usage()
    }

    fn validated_native_records(&self) -> Result<HashMap<Cid, native::NativeRecord>, StorageError> {
        let native = self
            .backend
            .native()
            .ok_or_else(|| StorageError::Native("native engine is not open".to_string()))?;
        let mut records = HashMap::<Cid, native::NativeRecord>::new();
        for record in native.records()? {
            let encoded = native.read(&record.cid)?;
            if decode_block_bytes(
                &encoded,
                &record.cid,
                self.max_block_bytes,
                Some(record.logical_size),
            )
            .is_err()
            {
                native.delete(&record.cid)?;
                continue;
            }
            records.insert(record.cid.clone(), record);
        }
        Ok(records)
    }

    fn insert_missing_native_metadata(
        &self,
        records: &HashMap<Cid, native::NativeRecord>,
    ) -> Result<(), StorageError> {
        let known = self
            .list_block_metas()?
            .into_iter()
            .map(|meta| meta.cid)
            .collect::<HashSet<_>>();
        let now = unix_seconds();
        let metas = records
            .values()
            .filter(|record| !known.contains(&record.cid))
            .map(|record| {
                let location = self.locations.get(record.location_index).ok_or_else(|| {
                    StorageError::Native("native record location is invalid".to_string())
                })?;
                Ok(BlockMeta {
                    cid: record.cid.clone(),
                    codec: record.cid.codec,
                    hash_alg: record.cid.hash_alg,
                    size_bytes: record.logical_size,
                    stored_size_bytes: record.stored_size,
                    storage_location_id: location.id.clone(),
                    storage_location_path: location.path.display().to_string(),
                    relative_path: native_relative_path(record),
                    created_at_unix_seconds: now,
                    pin_state: "none".to_string(),
                    replica_state: "none".to_string(),
                    retention_class: "cache".to_string(),
                    verified_at_unix_seconds: Some(now),
                    corrupt: false,
                    inline: false,
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        self.insert_block_metas(&metas)?;
        Ok(())
    }

    fn reconcile_metadata_with_files(&self) -> Result<(), StorageError> {
        for location in self.locations.iter() {
            let tmp_dir = location.path.join("tmp");
            if tmp_dir.exists() {
                for entry in fs::read_dir(&tmp_dir).map_err(|source| StorageError::Io {
                    path: tmp_dir.display().to_string(),
                    source,
                })? {
                    let path = entry
                        .map_err(|source| StorageError::Io {
                            path: tmp_dir.display().to_string(),
                            source,
                        })?
                        .path();
                    if path.is_file() {
                        let _ = fs::remove_file(&path);
                    }
                }
            }
        }

        for meta in self.list_block_metas()? {
            let present = if meta.inline {
                self.inline_block_is_valid(&meta)?
            } else if is_native_meta(&meta) {
                self.backend
                    .native()
                    .is_some_and(|native| native.contains(&meta.cid).unwrap_or(false))
            } else {
                self.block_path(&meta).exists()
            };
            if !present {
                self.remove_block_meta(&meta)?;
            }
        }

        for location in self.locations.iter() {
            self.reconstruct_missing_metadata_for_location(location)?;
        }
        self.rebuild_storage_location_usage()?;
        Ok(())
    }

    fn reconstruct_missing_metadata_for_location(
        &self,
        location: &StorageLocationRuntime,
    ) -> Result<(), StorageError> {
        let root = location.path.join("blocks");
        if !root.exists() {
            return Ok(());
        }
        let mut stack = VecDeque::from([root]);
        while let Some(dir) = stack.pop_front() {
            for entry in fs::read_dir(&dir).map_err(|source| StorageError::Io {
                path: dir.display().to_string(),
                source,
            })? {
                let path = entry
                    .map_err(|source| StorageError::Io {
                        path: dir.display().to_string(),
                        source,
                    })?
                    .path();
                let file_meta = path.symlink_metadata().map_err(|source| StorageError::Io {
                    path: path.display().to_string(),
                    source,
                })?;
                if file_meta.file_type().is_symlink() {
                    quarantine_file(location, &path)?;
                    continue;
                }
                if file_meta.is_dir() {
                    stack.push_back(path);
                    continue;
                }
                if !file_meta.is_file() {
                    continue;
                }
                let Some(cid) = cid_from_block_filename(&path) else {
                    quarantine_file(location, &path)?;
                    continue;
                };
                if self.get_meta(&cid)?.is_some() {
                    continue;
                }
                if file_meta.len()
                    > self
                        .max_block_bytes
                        .saturating_add(BLOCK_ENVELOPE_MAX_BYTES)
                {
                    quarantine_file(location, &path)?;
                    continue;
                }
                let stored = read_regular_file_bounded(
                    &path,
                    self.max_block_bytes
                        .saturating_add(BLOCK_ENVELOPE_MAX_BYTES),
                )?;
                let payload = match decode_block_bytes(&stored, &cid, self.max_block_bytes, None) {
                    Ok(payload) => payload,
                    Err(_) => {
                        quarantine_file(location, &path)?;
                        continue;
                    }
                };
                let relative_path = path
                    .strip_prefix(&location.path)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                let meta = BlockMeta {
                    cid: cid.clone(),
                    codec: cid.codec,
                    hash_alg: cid.hash_alg,
                    size_bytes: payload.len() as u64,
                    stored_size_bytes: file_meta.len(),
                    storage_location_id: location.id.clone(),
                    storage_location_path: location.path.display().to_string(),
                    relative_path,
                    created_at_unix_seconds: unix_seconds(),
                    pin_state: "none".to_string(),
                    replica_state: "none".to_string(),
                    retention_class: "cache".to_string(),
                    verified_at_unix_seconds: Some(unix_seconds()),
                    corrupt: false,
                    inline: false,
                };
                self.insert_block_meta(&meta)?;
            }
        }
        Ok(())
    }

    fn rebuild_storage_location_usage(&self) -> Result<(), StorageError> {
        let mut used_by_location = HashMap::<String, u64>::new();
        if let Some(native) = self.backend.native() {
            for (index, location) in self.locations.iter().enumerate() {
                used_by_location.insert(location.id.clone(), native.allocated_bytes(index));
            }
        }
        for meta in self.list_block_metas()? {
            if is_native_meta(&meta) {
                continue;
            }
            let present = if meta.inline {
                self.get_inline_block(&meta.cid)?.is_some()
            } else if is_native_meta(&meta) {
                self.backend
                    .native()
                    .is_some_and(|native| native.contains(&meta.cid).unwrap_or(false))
            } else {
                self.block_path(&meta).exists()
            };
            if present && !meta.corrupt {
                let stored_size = if meta.inline || is_native_meta(&meta) {
                    meta.stored_size_bytes
                } else {
                    self.block_path(&meta)
                        .symlink_metadata()
                        .ok()
                        .filter(|file| file.is_file())
                        .map(|file| file.len())
                        .unwrap_or(meta.stored_size_bytes)
                };
                *used_by_location
                    .entry(meta.storage_location_id.clone())
                    .or_default() += stored_size;
            }
        }
        let write_txn = self
            .metadata
            .database()
            .begin_write()
            .map_err(|source| StorageError::Transaction(Box::new(source)))?;
        {
            let mut locations = write_txn
                .open_table(STORAGE_LOCATIONS)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            for location in self.locations.iter() {
                let Some(mut meta) = ({
                    let value = locations
                        .get(location.id.as_str())
                        .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
                    value
                        .map(|value| serde_json::from_slice::<StorageLocationMeta>(value.value()))
                        .transpose()?
                }) else {
                    continue;
                };
                meta.used_bytes = used_by_location.get(&meta.id).copied().unwrap_or(0);
                meta.reserved_bytes = directory_regular_file_bytes(&location.path.join("gc"))?;
                let bytes = serde_json::to_vec(&meta)?;
                locations
                    .insert(meta.id.as_str(), bytes.as_slice())
                    .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
            }
        }
        write_txn
            .commit()
            .map_err(|source| StorageError::Commit(Box::new(source)))?;
        Ok(())
    }

    fn select_location_with_pending(
        &self,
        size_bytes: u64,
        intent: WriteIntent,
        pending_by_location: &HashMap<String, u64>,
    ) -> Result<StorageLocationRuntime, StorageError> {
        let mut best_below_soft: Option<(StorageLocationRuntime, u64)> = None;
        let mut best_allowed: Option<(StorageLocationRuntime, u64)> = None;
        for location in self.locations.iter() {
            let Some(meta) = self.get_location_meta(&location.id)? else {
                continue;
            };
            if !meta.healthy {
                continue;
            }
            let used = meta
                .used_bytes
                .saturating_add(meta.reserved_bytes)
                .saturating_add(
                    pending_by_location
                        .get(&location.id)
                        .copied()
                        .unwrap_or_default(),
                );
            let projected = used.saturating_add(size_bytes);
            if projected > meta.max_capacity_bytes {
                continue;
            }
            if intent == WriteIntent::Normal
                && projected > pressure_bytes(meta.max_capacity_bytes, HARD_PRESSURE_PERCENT)
            {
                continue;
            }
            let available = meta.max_capacity_bytes.saturating_sub(used);
            if projected <= pressure_bytes(meta.max_capacity_bytes, SOFT_PRESSURE_PERCENT)
                && best_below_soft
                    .as_ref()
                    .is_none_or(|(_, best_available)| available > *best_available)
            {
                best_below_soft = Some((location.clone(), available));
            }
            if best_allowed
                .as_ref()
                .is_none_or(|(_, best_available)| available > *best_available)
            {
                best_allowed = Some((location.clone(), available));
            }
        }
        best_below_soft
            .or(best_allowed)
            .map(|(location, _)| location)
            .ok_or(StorageError::CapacityExceeded { size_bytes })
    }

    fn block_path(&self, meta: &BlockMeta) -> PathBuf {
        PathBuf::from(&meta.storage_location_path).join(&meta.relative_path)
    }

    fn record_packed_read(&self, meta: &BlockMeta, bytes: u64) {
        if !self.backend.is_native() && is_native_meta(meta) {
            PROCESS_PACKED_BLOCK_READS.fetch_add(1, Ordering::Relaxed);
            PROCESS_PACKED_BLOCK_READ_BYTES.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    fn get_inline_block(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StorageError> {
        let read_txn = self
            .metadata
            .database()
            .begin_read()
            .map_err(|source| StorageError::Transaction(Box::new(source)))?;
        let table = match read_txn.open_table(INLINE_BLOCKS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(source) => return Err(StorageError::Table(Box::new(source))),
        };
        table
            .get(cid.to_string().as_str())
            .map_err(|source| StorageError::RedbStorage(Box::new(source)))
            .map(|value| value.map(|value| value.value().to_vec()))
    }

    fn inline_block_is_valid(&self, meta: &BlockMeta) -> Result<bool, StorageError> {
        let Some(stored) = self.get_inline_block(&meta.cid)? else {
            return Ok(false);
        };
        if stored.len() as u64 != meta.stored_size_bytes {
            return Ok(false);
        }
        match decode_block_bytes(
            &stored,
            &meta.cid,
            self.max_block_bytes,
            Some(meta.size_bytes),
        ) {
            Ok(payload) => Ok(meta.cid.verify(&payload)),
            Err(StorageError::BlockTooLarge { .. })
            | Err(StorageError::HashMismatch(_))
            | Err(StorageError::InvalidEncodedBlock(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn get_meta(&self, cid: &Cid) -> Result<Option<BlockMeta>, StorageError> {
        let read_txn = self
            .metadata
            .database()
            .begin_read()
            .map_err(|source| StorageError::Transaction(Box::new(source)))?;
        let table = read_txn
            .open_table(BLOCKS)
            .map_err(|source| StorageError::Table(Box::new(source)))?;
        let value = table
            .get(cid.to_string().as_str())
            .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
        value
            .map(|value| serde_json::from_slice(value.value()).map_err(StorageError::from))
            .transpose()
    }

    fn get_location_meta(
        &self,
        location_id: &str,
    ) -> Result<Option<StorageLocationMeta>, StorageError> {
        let read_txn = self
            .metadata
            .database()
            .begin_read()
            .map_err(|source| StorageError::Transaction(Box::new(source)))?;
        let table = read_txn
            .open_table(STORAGE_LOCATIONS)
            .map_err(|source| StorageError::Table(Box::new(source)))?;
        let value = table
            .get(location_id)
            .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
        value
            .map(|value| serde_json::from_slice(value.value()).map_err(StorageError::from))
            .transpose()
    }

    fn insert_block_meta(&self, meta: &BlockMeta) -> Result<(), StorageError> {
        self.insert_block_metas(std::slice::from_ref(meta))
    }

    fn insert_block_metas(&self, metas: &[BlockMeta]) -> Result<(), StorageError> {
        self.insert_block_metas_and_inline(metas, &[])
    }

    fn insert_block_metas_and_inline(
        &self,
        metas: &[BlockMeta],
        inline_blocks: &[(Cid, Vec<u8>)],
    ) -> Result<(), StorageError> {
        let write_txn = self
            .metadata
            .database()
            .begin_write()
            .map_err(|source| StorageError::Transaction(Box::new(source)))?;
        {
            let mut blocks = write_txn
                .open_table(BLOCKS)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            for meta in metas {
                if blocks
                    .get(meta.cid.to_string().as_str())
                    .map_err(|source| StorageError::RedbStorage(Box::new(source)))?
                    .is_some()
                {
                    continue;
                }
                let meta_bytes = serde_json::to_vec(meta)?;
                blocks
                    .insert(meta.cid.to_string().as_str(), meta_bytes.as_slice())
                    .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
            }
        }
        if !inline_blocks.is_empty() {
            let mut table = write_txn
                .open_table(INLINE_BLOCKS)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            for (cid, bytes) in inline_blocks {
                table
                    .insert(cid.to_string().as_str(), bytes.as_slice())
                    .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
            }
        }
        {
            let mut retention = write_txn
                .open_table(BLOCKS_BY_RETENTION)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            for meta in metas {
                retention
                    .insert(
                        format!("{}:{}", meta.retention_class, meta.cid).as_str(),
                        "",
                    )
                    .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
            }
        }
        {
            let mut locations = write_txn
                .open_table(STORAGE_LOCATIONS)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            let mut updates = HashMap::<String, (u64, Option<u64>)>::new();
            for meta in metas {
                updates
                    .entry(meta.storage_location_id.clone())
                    .or_default()
                    .0 += meta.stored_size_bytes;
            }
            if let Some(native) = self.backend.native() {
                for (index, location) in self.locations.iter().enumerate() {
                    updates.entry(location.id.clone()).or_default().1 =
                        Some(native.allocated_bytes(index));
                }
            }
            for (location_id, (added_bytes, physical_bytes)) in updates {
                let mut location: StorageLocationMeta = {
                    let Some(location_value) = locations
                        .get(location_id.as_str())
                        .map_err(|source| StorageError::RedbStorage(Box::new(source)))?
                    else {
                        return Err(StorageError::NoStorageLocations);
                    };
                    serde_json::from_slice(location_value.value())?
                };
                location.used_bytes = physical_bytes
                    .unwrap_or_else(|| location.used_bytes.saturating_add(added_bytes));
                let location_bytes = serde_json::to_vec(&location)?;
                locations
                    .insert(location_id.as_str(), location_bytes.as_slice())
                    .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
            }
        }
        write_txn
            .commit()
            .map_err(|source| StorageError::Commit(Box::new(source)))?;
        Ok(())
    }

    fn remove_block_meta(&self, meta: &BlockMeta) -> Result<(), StorageError> {
        let write_txn = self
            .metadata
            .database()
            .begin_write()
            .map_err(|source| StorageError::Transaction(Box::new(source)))?;
        {
            let mut blocks = write_txn
                .open_table(BLOCKS)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            blocks
                .remove(meta.cid.to_string().as_str())
                .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
        }
        if meta.inline {
            let mut inline = write_txn
                .open_table(INLINE_BLOCKS)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            inline
                .remove(meta.cid.to_string().as_str())
                .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
        }
        {
            let mut retention = write_txn
                .open_table(BLOCKS_BY_RETENTION)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            retention
                .remove(format!("{}:{}", meta.retention_class, meta.cid).as_str())
                .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
        }
        {
            let mut locations = write_txn
                .open_table(STORAGE_LOCATIONS)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            let location = {
                let value = locations
                    .get(meta.storage_location_id.as_str())
                    .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
                value
                    .map(|value| serde_json::from_slice::<StorageLocationMeta>(value.value()))
                    .transpose()?
            };
            if let Some(mut location) = location {
                location.used_bytes = if let Some(native) = self.backend.native()
                    && is_native_meta(meta)
                {
                    self.locations
                        .iter()
                        .position(|candidate| candidate.id == meta.storage_location_id)
                        .map_or(location.used_bytes, |index| native.allocated_bytes(index))
                } else {
                    location.used_bytes.saturating_sub(meta.stored_size_bytes)
                };
                let bytes = serde_json::to_vec(&location)?;
                locations
                    .insert(meta.storage_location_id.as_str(), bytes.as_slice())
                    .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
            }
        }
        write_txn
            .commit()
            .map_err(|source| StorageError::Commit(Box::new(source)))?;
        Ok(())
    }

    fn mark_corrupt(&self, cid: &Cid) -> Result<(), StorageError> {
        let Some(mut meta) = self.get_meta(cid)? else {
            return Ok(());
        };
        meta.corrupt = true;
        let write_txn = self
            .metadata
            .database()
            .begin_write()
            .map_err(|source| StorageError::Transaction(Box::new(source)))?;
        {
            let mut blocks = write_txn
                .open_table(BLOCKS)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            let meta_bytes = serde_json::to_vec(&meta)?;
            blocks
                .insert(cid.to_string().as_str(), meta_bytes.as_slice())
                .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
        }
        write_txn
            .commit()
            .map_err(|source| StorageError::Commit(Box::new(source)))?;
        Ok(())
    }
}

impl BlockMeta {
    fn to_put_response(&self, already_existed: bool) -> PutBlockResponse {
        PutBlockResponse {
            cid: self.cid.clone(),
            codec: self.codec,
            size: self.size_bytes,
            already_existed,
            storage_location: self.storage_location_path.clone(),
        }
    }

    fn to_stat_response(&self) -> BlockStatResponse {
        BlockStatResponse {
            cid: self.cid.clone(),
            codec: self.codec,
            size: self.size_bytes,
            storage_location: self.storage_location_path.clone(),
            created_at_unix_seconds: self.created_at_unix_seconds,
        }
    }
}

fn initialize_location(
    metadata: &MetadataStore,
    location: &StorageLocationConfig,
) -> Result<StorageLocationRuntime, StorageError> {
    fs::create_dir_all(location.path.join("blocks")).map_err(|source| StorageError::Io {
        path: location.path.join("blocks").display().to_string(),
        source,
    })?;
    fs::create_dir_all(location.path.join("tmp")).map_err(|source| StorageError::Io {
        path: location.path.join("tmp").display().to_string(),
        source,
    })?;
    fs::create_dir_all(location.path.join("gc")).map_err(|source| StorageError::Io {
        path: location.path.join("gc").display().to_string(),
        source,
    })?;
    fs::create_dir_all(location.path.join("meta")).map_err(|source| StorageError::Io {
        path: location.path.join("meta").display().to_string(),
        source,
    })?;

    let canonical = fs::canonicalize(&location.path).map_err(|source| StorageError::Io {
        path: location.path.display().to_string(),
        source,
    })?;
    let lock_path = canonical.join("meta/location.lock");
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|source| StorageError::Io {
            path: lock_path.display().to_string(),
            source,
        })?;
    lock_file
        .try_lock_exclusive()
        .map_err(|_| StorageError::LocationLocked(canonical.display().to_string()))?;
    let canonical_path = canonical.display().to_string();
    let id = hex_id(&canonical_path);
    let write_txn = metadata
        .database()
        .begin_write()
        .map_err(|source| StorageError::Transaction(Box::new(source)))?;
    {
        let mut locations = write_txn
            .open_table(STORAGE_LOCATIONS)
            .map_err(|source| StorageError::Table(Box::new(source)))?;
        let existing_meta = {
            let existing = locations
                .get(id.as_str())
                .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
            existing
                .map(|value| serde_json::from_slice::<StorageLocationMeta>(value.value()))
                .transpose()?
        };
        let mut meta = if let Some(value) = existing_meta {
            value
        } else {
            StorageLocationMeta {
                id: id.clone(),
                path: canonical_path.clone(),
                max_capacity_bytes: location.max_capacity_bytes,
                used_bytes: 0,
                reserved_bytes: 0,
                healthy: true,
                last_checked_at_unix_seconds: None,
            }
        };
        meta.path = canonical_path.clone();
        meta.max_capacity_bytes = location.max_capacity_bytes;
        meta.healthy = true;
        meta.last_checked_at_unix_seconds = Some(unix_seconds());
        let meta_bytes = serde_json::to_vec(&meta)?;
        locations
            .insert(id.as_str(), meta_bytes.as_slice())
            .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
    }
    {
        let mut by_path = write_txn
            .open_table(STORAGE_LOCATIONS_BY_PATH)
            .map_err(|source| StorageError::Table(Box::new(source)))?;
        by_path
            .insert(canonical_path.as_str(), id.as_str())
            .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
    }
    // Create index tables during Phase 1 initialization so the redb schema exists now.
    {
        write_txn
            .open_table(BLOCKS)
            .map_err(|source| StorageError::Table(Box::new(source)))?;
        write_txn
            .open_table(BLOCKS_BY_RETENTION)
            .map_err(|source| StorageError::Table(Box::new(source)))?;
    }
    write_txn
        .commit()
        .map_err(|source| StorageError::Commit(Box::new(source)))?;

    Ok(StorageLocationRuntime {
        id,
        path: canonical,
        max_capacity_bytes: location.max_capacity_bytes,
        _lock_file: Arc::new(lock_file),
    })
}

fn quarantine_file(location: &StorageLocationRuntime, path: &Path) -> Result<(), StorageError> {
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("invalid-block");
    let target = location
        .path
        .join("gc")
        .join(format!("quarantine-{}-{filename}", unix_nanos()));
    fs::rename(path, &target).map_err(|source| StorageError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn directory_regular_file_bytes(root: &Path) -> Result<u64, StorageError> {
    if !root.exists() {
        return Ok(0);
    }
    let mut total = 0u64;
    let mut stack = VecDeque::from([root.to_path_buf()]);
    while let Some(directory) = stack.pop_front() {
        for entry in fs::read_dir(&directory).map_err(|source| StorageError::Io {
            path: directory.display().to_string(),
            source,
        })? {
            let entry = entry.map_err(|source| StorageError::Io {
                path: directory.display().to_string(),
                source,
            })?;
            let metadata = entry
                .path()
                .symlink_metadata()
                .map_err(|source| StorageError::Io {
                    path: entry.path().display().to_string(),
                    source,
                })?;
            if metadata.is_dir() {
                stack.push_back(entry.path());
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    Ok(total)
}

fn read_regular_file_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, StorageError> {
    let metadata = path.symlink_metadata().map_err(|source| StorageError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(StorageError::Io {
            path: path.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "block path is not a regular file",
            ),
        });
    }
    if metadata.len() > max_bytes {
        return Err(StorageError::BlockTooLarge {
            size_bytes: metadata.len(),
            max_bytes,
        });
    }
    let mut payload = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|source| StorageError::Io {
            path: path.display().to_string(),
            source,
        })?
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut payload)
        .map_err(|source| StorageError::Io {
            path: path.display().to_string(),
            source,
        })?;
    if payload.len() as u64 > max_bytes {
        return Err(StorageError::BlockTooLarge {
            size_bytes: payload.len() as u64,
            max_bytes,
        });
    }
    Ok(payload)
}

fn encode_block(cid: Cid, logical: &[u8]) -> Result<EncodedBlock, StorageError> {
    let started = std::time::Instant::now();
    if logical.len() >= COMPRESSION_MIN_BYTES && compression_probe_accepts(logical)? {
        let compressed = zstd::bulk::compress(logical, ZSTD_LEVEL)
            .map_err(|error| StorageError::Compression(error.to_string()))?;
        let required_savings = logical.len().saturating_mul(COMPRESSION_SAVINGS_PERCENT) / 100;
        if compressed.len() <= logical.len().saturating_sub(required_savings) {
            return encode_block_payload(cid, logical, BLOCK_ENCODING_ZSTD, &compressed, started);
        }
    }
    encode_block_payload(cid, logical, BLOCK_ENCODING_RAW, logical, started)
}

fn encode_block_payload(
    cid: Cid,
    logical: &[u8],
    encoding: u8,
    encoded_payload: &[u8],
    started: std::time::Instant,
) -> Result<EncodedBlock, StorageError> {
    let cid_text = cid.to_string();
    let cid_bytes = cid_text.as_bytes();
    let cid_len = u16::try_from(cid_bytes.len()).map_err(|_| {
        StorageError::InvalidEncodedBlock("CID is too long for block envelope".to_string())
    })?;
    let checksums = encoded_payload
        .chunks(BLOCK_CHECKSUM_CHUNK_BYTES)
        .map(crc32c::crc32c)
        .collect::<Vec<_>>();
    let checksum_count = u32::try_from(checksums.len())
        .map_err(|_| StorageError::InvalidEncodedBlock("too many checksum chunks".to_string()))?;
    let mut bytes = Vec::with_capacity(
        BLOCK_ENVELOPE_FIXED_BYTES
            + cid_bytes.len()
            + checksums.len() * std::mem::size_of::<u32>()
            + encoded_payload.len(),
    );
    bytes.extend_from_slice(BLOCK_ENVELOPE_MAGIC);
    bytes.push(BLOCK_ENVELOPE_VERSION);
    bytes.push(encoding);
    bytes.extend_from_slice(&cid_len.to_be_bytes());
    bytes.extend_from_slice(&(logical.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&(encoded_payload.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&(BLOCK_CHECKSUM_CHUNK_BYTES as u32).to_be_bytes());
    bytes.extend_from_slice(&checksum_count.to_be_bytes());
    bytes.extend_from_slice(cid_bytes);
    for checksum in checksums {
        bytes.extend_from_slice(&checksum.to_be_bytes());
    }
    bytes.extend_from_slice(encoded_payload);
    PROCESS_BLOCK_ENCODING_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    if encoding == BLOCK_ENCODING_ZSTD {
        PROCESS_BLOCK_ENCODING_ZSTD.fetch_add(1, Ordering::Relaxed);
    } else {
        PROCESS_BLOCK_ENCODING_RAW.fetch_add(1, Ordering::Relaxed);
    }
    PROCESS_BLOCK_ENCODING_LOGICAL_BYTES.fetch_add(logical.len() as u64, Ordering::Relaxed);
    PROCESS_BLOCK_ENCODING_STORED_BYTES.fetch_add(bytes.len() as u64, Ordering::Relaxed);
    PROCESS_BLOCK_ENCODING_MICROS.fetch_add(
        started.elapsed().as_micros().min(u64::MAX as u128) as u64,
        Ordering::Relaxed,
    );
    Ok(EncodedBlock {
        cid,
        logical_size_bytes: logical.len() as u64,
        bytes,
    })
}

fn compression_probe_accepts(logical: &[u8]) -> Result<bool, StorageError> {
    if logical.len() < COMPRESSION_PROBE_THRESHOLD_BYTES {
        return Ok(true);
    }
    let region = COMPRESSION_PROBE_REGION_BYTES.min(logical.len() / 3);
    let middle = logical.len() / 2 - region / 2;
    let end = logical.len() - region;
    let mut sample = Vec::with_capacity(region * 3);
    sample.extend_from_slice(&logical[..region]);
    sample.extend_from_slice(&logical[middle..middle + region]);
    sample.extend_from_slice(&logical[end..]);
    let compressed = zstd::bulk::compress(&sample, ZSTD_LEVEL)
        .map_err(|error| StorageError::Compression(error.to_string()))?;
    let required_savings = sample.len().saturating_mul(COMPRESSION_SAVINGS_PERCENT) / 100;
    Ok(compressed.len() <= sample.len().saturating_sub(required_savings))
}

fn inline_internal_block(block: &EncodedBlock) -> bool {
    block.logical_size_bytes <= INLINE_INTERNAL_BLOCK_MAX_BYTES
        && block.bytes.len() as u64 <= INLINE_INTERNAL_BLOCK_MAX_BYTES
        && matches!(
            block.cid.codec,
            CODEC_MERKLE_NODE
                | CODEC_NAMESPACE_DESCRIPTOR
                | CODEC_NAMESPACE_CHECKPOINT
                | CODEC_NAMESPACE_COMMIT
        )
}

#[derive(Debug, Clone, Copy)]
struct BlockEnvelopeLayout {
    encoding: u8,
    logical_size: usize,
    encoded_size: usize,
    cid_end: usize,
    payload_offset: usize,
}

fn parse_block_envelope(
    header: &[u8],
    stored_size: usize,
    expected_cid: &Cid,
    max_logical_bytes: u64,
    expected_logical_size: Option<u64>,
) -> Result<BlockEnvelopeLayout, StorageError> {
    if header.len() < BLOCK_ENVELOPE_FIXED_BYTES {
        return Err(StorageError::InvalidEncodedBlock(
            "truncated block envelope".to_string(),
        ));
    }
    if !header.starts_with(BLOCK_ENVELOPE_MAGIC) {
        return Err(StorageError::InvalidEncodedBlock(
            "block envelope magic is missing".to_string(),
        ));
    }
    if header[8] != BLOCK_ENVELOPE_VERSION {
        return Err(StorageError::InvalidEncodedBlock(format!(
            "unsupported block envelope version {}",
            header[8]
        )));
    }
    let encoding = header[9];
    let cid_len = u16::from_be_bytes([header[10], header[11]]) as usize;
    let logical_size = u64::from_be_bytes(
        header[12..20]
            .try_into()
            .expect("fixed block envelope logical size slice"),
    );
    let encoded_size = u64::from_be_bytes(
        header[20..28]
            .try_into()
            .expect("fixed block envelope encoded size slice"),
    );
    let checksum_chunk_bytes = u32::from_be_bytes(
        header[28..32]
            .try_into()
            .expect("fixed block envelope checksum chunk-size slice"),
    ) as usize;
    let checksum_count = u32::from_be_bytes(
        header[32..36]
            .try_into()
            .expect("fixed block envelope checksum count slice"),
    ) as usize;
    if logical_size > max_logical_bytes {
        return Err(StorageError::BlockTooLarge {
            size_bytes: logical_size,
            max_bytes: max_logical_bytes,
        });
    }
    if expected_logical_size.is_some_and(|size| size != logical_size) {
        return Err(StorageError::InvalidEncodedBlock(
            "logical size does not match transfer metadata".to_string(),
        ));
    }
    let logical_size = usize::try_from(logical_size).map_err(|_| {
        StorageError::InvalidEncodedBlock("logical size does not fit usize".to_string())
    })?;
    let encoded_size = usize::try_from(encoded_size).map_err(|_| {
        StorageError::InvalidEncodedBlock("encoded size does not fit usize".to_string())
    })?;
    if checksum_chunk_bytes != BLOCK_CHECKSUM_CHUNK_BYTES
        || checksum_count != encoded_size.div_ceil(BLOCK_CHECKSUM_CHUNK_BYTES)
    {
        return Err(StorageError::InvalidEncodedBlock(
            "invalid checksum chunk layout".to_string(),
        ));
    }
    let cid_end = BLOCK_ENVELOPE_FIXED_BYTES
        .checked_add(cid_len)
        .ok_or_else(|| StorageError::InvalidEncodedBlock("CID length overflow".to_string()))?;
    let checksum_bytes = checksum_count
        .checked_mul(std::mem::size_of::<u32>())
        .ok_or_else(|| {
            StorageError::InvalidEncodedBlock("checksum table length overflow".to_string())
        })?;
    let payload_offset = cid_end.checked_add(checksum_bytes).ok_or_else(|| {
        StorageError::InvalidEncodedBlock("checksum table length overflow".to_string())
    })?;
    let expected_total = payload_offset.checked_add(encoded_size).ok_or_else(|| {
        StorageError::InvalidEncodedBlock("encoded payload length overflow".to_string())
    })?;
    if stored_size != expected_total {
        return Err(StorageError::InvalidEncodedBlock(
            "encoded payload length does not match envelope".to_string(),
        ));
    }
    if header.len() < payload_offset {
        return Err(StorageError::InvalidEncodedBlock(
            "truncated block envelope header".to_string(),
        ));
    }
    let envelope_cid = std::str::from_utf8(&header[BLOCK_ENVELOPE_FIXED_BYTES..cid_end])
        .map_err(|_| StorageError::InvalidEncodedBlock("CID is not UTF-8".to_string()))?;
    if envelope_cid != expected_cid.to_string() {
        return Err(StorageError::InvalidEncodedBlock(
            "envelope CID does not match expected CID".to_string(),
        ));
    }
    Ok(BlockEnvelopeLayout {
        encoding,
        logical_size,
        encoded_size,
        cid_end,
        payload_offset,
    })
}

fn decode_block_bytes(
    stored: &[u8],
    expected_cid: &Cid,
    max_logical_bytes: u64,
    expected_logical_size: Option<u64>,
) -> Result<Vec<u8>, StorageError> {
    let layout = parse_block_envelope(
        stored,
        stored.len(),
        expected_cid,
        max_logical_bytes,
        expected_logical_size,
    )?;
    let encoded = &stored[layout.payload_offset..];
    for (index, chunk) in encoded.chunks(BLOCK_CHECKSUM_CHUNK_BYTES).enumerate() {
        let checksum_offset = layout.cid_end + index * std::mem::size_of::<u32>();
        let expected_checksum = u32::from_be_bytes(
            stored[checksum_offset..checksum_offset + std::mem::size_of::<u32>()]
                .try_into()
                .expect("validated checksum-table slice"),
        );
        if crc32c::crc32c(chunk) != expected_checksum {
            return Err(StorageError::InvalidEncodedBlock(format!(
                "encoded payload checksum chunk {index} mismatch"
            )));
        }
    }
    let logical = match layout.encoding {
        BLOCK_ENCODING_RAW => {
            if encoded.len() != layout.logical_size {
                return Err(StorageError::InvalidEncodedBlock(
                    "raw encoded payload length does not match logical length".to_string(),
                ));
            }
            encoded.to_vec()
        }
        BLOCK_ENCODING_ZSTD => {
            zstd::bulk::decompress(encoded, layout.logical_size).map_err(|error| {
                StorageError::InvalidEncodedBlock(format!("zstd decode failed: {error}"))
            })?
        }
        value => {
            return Err(StorageError::InvalidEncodedBlock(format!(
                "unsupported block encoding {value}"
            )));
        }
    };
    if logical.len() != layout.logical_size {
        return Err(StorageError::InvalidEncodedBlock(
            "decoded payload length does not match logical length".to_string(),
        ));
    }
    if !expected_cid.verify(&logical) {
        return Err(StorageError::HashMismatch(expected_cid.clone()));
    }
    Ok(logical)
}

fn read_raw_block_range(
    path: &Path,
    expected_cid: &Cid,
    max_logical_bytes: u64,
    expected_logical_size: u64,
    start: u64,
    end: u64,
) -> Result<Option<(Vec<u8>, u64)>, StorageError> {
    let metadata = path.symlink_metadata().map_err(|source| StorageError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(StorageError::Io {
            path: path.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "block path is not a regular file",
            ),
        });
    }
    let stored_size = usize::try_from(metadata.len()).map_err(|_| {
        StorageError::InvalidEncodedBlock("stored block size does not fit usize".to_string())
    })?;
    if metadata.len() > max_logical_bytes.saturating_add(BLOCK_ENVELOPE_MAX_BYTES) {
        return Err(StorageError::BlockTooLarge {
            size_bytes: metadata.len(),
            max_bytes: max_logical_bytes.saturating_add(BLOCK_ENVELOPE_MAX_BYTES),
        });
    }
    let mut file = File::open(path).map_err(|source| StorageError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let header_bytes = stored_size.min(BLOCK_ENVELOPE_MAX_BYTES as usize);
    let mut header = vec![0u8; header_bytes];
    file.read_exact(&mut header)
        .map_err(|source| StorageError::Io {
            path: path.display().to_string(),
            source,
        })?;
    let layout = parse_block_envelope(
        &header,
        stored_size,
        expected_cid,
        max_logical_bytes,
        Some(expected_logical_size),
    )?;
    if layout.encoding == BLOCK_ENCODING_ZSTD {
        return Ok(None);
    }
    if layout.encoding != BLOCK_ENCODING_RAW || layout.logical_size != layout.encoded_size {
        return Err(StorageError::InvalidEncodedBlock(
            "raw range envelope has incompatible lengths or encoding".to_string(),
        ));
    }
    let start = usize::try_from(start)
        .map_err(|_| StorageError::InvalidEncodedBlock("range start overflow".to_string()))?;
    let end = usize::try_from(end)
        .map_err(|_| StorageError::InvalidEncodedBlock("range end overflow".to_string()))?;
    let first_chunk = start / BLOCK_CHECKSUM_CHUNK_BYTES;
    let last_chunk = end.div_ceil(BLOCK_CHECKSUM_CHUNK_BYTES);
    let covered_start = first_chunk * BLOCK_CHECKSUM_CHUNK_BYTES;
    let covered_end = last_chunk
        .saturating_mul(BLOCK_CHECKSUM_CHUNK_BYTES)
        .min(layout.logical_size);
    let mut covered = vec![0u8; covered_end - covered_start];
    file.seek(SeekFrom::Start(
        (layout.payload_offset + covered_start) as u64,
    ))
    .and_then(|_| file.read_exact(&mut covered))
    .map_err(|source| StorageError::Io {
        path: path.display().to_string(),
        source,
    })?;
    for (relative_index, chunk) in covered.chunks(BLOCK_CHECKSUM_CHUNK_BYTES).enumerate() {
        let checksum_index = first_chunk + relative_index;
        let checksum_offset = layout.cid_end + checksum_index * std::mem::size_of::<u32>();
        let expected_checksum = u32::from_be_bytes(
            header[checksum_offset..checksum_offset + std::mem::size_of::<u32>()]
                .try_into()
                .expect("validated range checksum-table slice"),
        );
        if crc32c::crc32c(chunk) != expected_checksum {
            return Err(StorageError::InvalidEncodedBlock(format!(
                "encoded payload checksum chunk {checksum_index} mismatch"
            )));
        }
    }
    let result = covered[start - covered_start..end - covered_start].to_vec();
    Ok(Some((result, (header_bytes + covered.len()) as u64)))
}

fn read_native_raw_block_range(
    native: &native::NativeEngine,
    expected_cid: &Cid,
    max_logical_bytes: u64,
    expected_logical_size: u64,
    start: u64,
    end: u64,
    stored_size: u64,
) -> Result<Option<(Vec<u8>, u64)>, StorageError> {
    let stored_size = usize::try_from(stored_size).map_err(|_| {
        StorageError::InvalidEncodedBlock("stored block size does not fit usize".to_string())
    })?;
    if stored_size as u64 > max_logical_bytes.saturating_add(BLOCK_ENVELOPE_MAX_BYTES) {
        return Err(StorageError::BlockTooLarge {
            size_bytes: stored_size as u64,
            max_bytes: max_logical_bytes.saturating_add(BLOCK_ENVELOPE_MAX_BYTES),
        });
    }
    let header_bytes = stored_size.min(BLOCK_ENVELOPE_MAX_BYTES as usize);
    let (header, header_physical) = native.read_slice(expected_cid, 0, header_bytes)?;
    let layout = parse_block_envelope(
        &header,
        stored_size,
        expected_cid,
        max_logical_bytes,
        Some(expected_logical_size),
    )?;
    if layout.encoding == BLOCK_ENCODING_ZSTD {
        return Ok(None);
    }
    if layout.encoding != BLOCK_ENCODING_RAW || layout.logical_size != layout.encoded_size {
        return Err(StorageError::InvalidEncodedBlock(
            "raw range envelope has incompatible lengths or encoding".to_string(),
        ));
    }
    let start = usize::try_from(start)
        .map_err(|_| StorageError::InvalidEncodedBlock("range start overflow".to_string()))?;
    let end = usize::try_from(end)
        .map_err(|_| StorageError::InvalidEncodedBlock("range end overflow".to_string()))?;
    let first_chunk = start / BLOCK_CHECKSUM_CHUNK_BYTES;
    let last_chunk = end.div_ceil(BLOCK_CHECKSUM_CHUNK_BYTES);
    let covered_start = first_chunk * BLOCK_CHECKSUM_CHUNK_BYTES;
    let covered_end = last_chunk
        .saturating_mul(BLOCK_CHECKSUM_CHUNK_BYTES)
        .min(layout.logical_size);
    let (covered, payload_physical) = native.read_slice(
        expected_cid,
        layout.payload_offset + covered_start,
        layout.payload_offset + covered_end,
    )?;
    for chunk_index in first_chunk..last_chunk {
        let relative = (chunk_index - first_chunk) * BLOCK_CHECKSUM_CHUNK_BYTES;
        let chunk_end = (relative + BLOCK_CHECKSUM_CHUNK_BYTES).min(covered.len());
        let checksum_offset = layout.cid_end + chunk_index * std::mem::size_of::<u32>();
        let expected = u32::from_be_bytes(
            header[checksum_offset..checksum_offset + 4]
                .try_into()
                .expect("validated checksum table contains complete entries"),
        );
        if crc32c::crc32c(&covered[relative..chunk_end]) != expected {
            return Err(StorageError::HashMismatch(expected_cid.clone()));
        }
    }
    let requested_start = start - covered_start;
    let requested_end = requested_start + (end - start);
    Ok(Some((
        covered[requested_start..requested_end].to_vec(),
        header_physical.saturating_add(payload_physical),
    )))
}

fn verify_file(path: &Path, cid: &Cid, max_bytes: u64) -> Result<bool, StorageError> {
    if !path.exists() {
        return Ok(false);
    }
    let stored =
        read_regular_file_bounded(path, max_bytes.saturating_add(BLOCK_ENVELOPE_MAX_BYTES))?;
    Ok(decode_block_bytes(&stored, cid, max_bytes, None).is_ok())
}

fn relative_block_path(cid: &Cid) -> PathBuf {
    let digest = hex::encode(cid.digest);
    let shard_a = &digest[0..2];
    let shard_b = &digest[2..4];
    PathBuf::from("blocks")
        .join(cid.hash_alg.code())
        .join(shard_a)
        .join(shard_b)
        .join(cid_filename(cid))
}

fn native_relative_path(record: &native::NativeRecord) -> String {
    format!(
        "@native/{}/{}/{}/{}",
        record.owner, record.generation, record.segment_id, record.payload_offset
    )
}

fn record_packed_writes(blocks: &[EncodedBlock], results: &[PutBlockResponse]) {
    let mut writes = 0u64;
    let mut bytes = 0u64;
    for (block, result) in blocks.iter().zip(results) {
        if !result.already_existed {
            writes += 1;
            bytes = bytes.saturating_add(block.bytes.len() as u64);
        }
    }
    PROCESS_PACKED_BLOCK_WRITES.fetch_add(writes, Ordering::Relaxed);
    PROCESS_PACKED_BLOCK_WRITE_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

fn is_native_meta(meta: &BlockMeta) -> bool {
    meta.relative_path.starts_with("@native/")
}

fn cid_filename(cid: &Cid) -> String {
    format!(
        "pepper-v{}_{}_{}_{}.blk",
        cid.version,
        cid.codec.canonical_display(),
        cid.hash_alg.code(),
        hex::encode(cid.digest)
    )
}

fn cid_from_block_filename(path: &Path) -> Option<Cid> {
    let filename = path.file_name()?.to_str()?;
    let filename = filename.strip_suffix(".blk")?;
    let mut parts = filename.splitn(4, '_');
    let version = parts.next()?.strip_prefix("pepper-v")?;
    let codec = parts.next()?;
    let hash_alg = parts.next()?;
    let digest = parts.next()?;
    Cid::from_str(&format!(
        "cid://pepper-v{version}:{codec}:{hash_alg}:{digest}"
    ))
    .ok()
}

fn write_temp_file_unflushed(path: &Path, payload: &[u8]) -> Result<File, StorageError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|source| StorageError::Io {
        path: path.display().to_string(),
        source,
    })?;
    file.write_all(payload).map_err(|source| StorageError::Io {
        path: path.display().to_string(),
        source,
    })?;
    Ok(file)
}

fn hex_id(value: &str) -> String {
    hex::encode(blake3::hash(value.as_bytes()).as_bytes())
}

fn pressure_bytes(capacity: u64, percent: u64) -> u64 {
    capacity.saturating_mul(percent) / 100
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_metadata::MetadataStore;
    use std::os::unix::fs::FileExt as _;

    fn incompressible_bytes(size: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut logical = vec![0u8; size];
        for chunk in logical.chunks_mut(8) {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value = state;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            let bytes = (value ^ (value >> 31)).to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        logical
    }

    fn native_config(root: &Path) -> StorageConfig {
        StorageConfig {
            engine: StorageEngine::NativeNvme,
            native: pepper_config::NativeStorageConfig {
                segment_bytes: 4 * 1024 * 1024,
                owners: 2,
                io_uring_entries: 32,
                direct_io: false,
                require_io_uring: false,
                group_commit_delay_microseconds: 0,
                group_commit_max_requests: 64,
                compaction_dead_percent: 10,
            },
            small_object_pack: SmallObjectPackConfig::default(),
            locations: vec![StorageLocationConfig {
                path: root.join("native-store"),
                max_capacity_bytes: 64 * 1024 * 1024,
            }],
        }
    }

    fn packed_files_config(root: &Path) -> StorageConfig {
        StorageConfig {
            engine: StorageEngine::Files,
            native: pepper_config::NativeStorageConfig::default(),
            small_object_pack: SmallObjectPackConfig {
                enabled: true,
                max_object_bytes: 1024 * 1024,
                segment_bytes: 4 * 1024 * 1024,
                owners: 2,
                io_uring_entries: 32,
                require_io_uring: false,
                group_commit_delay_microseconds: 0,
                group_commit_max_requests: 64,
                compaction_dead_percent: 10,
            },
            locations: vec![StorageLocationConfig {
                path: root.join("packed-files-store"),
                max_capacity_bytes: 64 * 1024 * 1024,
            }],
        }
    }

    #[test]
    fn verified_repair_extra_deletion_is_idempotent_for_files_inline_and_native() {
        let files_dir = tempfile::tempdir().unwrap();
        let files_metadata =
            Arc::new(MetadataStore::open_or_create(files_dir.path().join("files.redb")).unwrap());
        let files = BlockStore::open(
            files_metadata,
            &[StorageLocationConfig {
                path: files_dir.path().join("files"),
                max_capacity_bytes: 16 * 1024 * 1024,
            }],
        )
        .unwrap();
        let file = files.put_raw(&incompressible_bytes(128 * 1024)).unwrap();
        let inline = files.put(CODEC_MERKLE_NODE, b"inline-extra").unwrap();
        for cid in [&file.cid, &inline.cid] {
            assert!(files.has(cid).unwrap());
            assert!(files.delete_repair_extra(cid).unwrap());
            assert!(!files.has(cid).unwrap());
            assert!(!files.delete_repair_extra(cid).unwrap());
        }

        let native_dir = tempfile::tempdir().unwrap();
        let native_metadata =
            Arc::new(MetadataStore::open_or_create(native_dir.path().join("native.redb")).unwrap());
        let native_config = native_config(native_dir.path());
        let native =
            BlockStore::open_with_config(native_metadata, &native_config, 4 * 1024 * 1024).unwrap();
        let block = native.put_raw(&incompressible_bytes(128 * 1024)).unwrap();
        assert!(native.delete_repair_extra(&block.cid).unwrap());
        assert!(!native.has(&block.cid).unwrap());
        drop(native);

        let native_metadata =
            Arc::new(MetadataStore::open_or_create(native_dir.path().join("native.redb")).unwrap());
        let reopened =
            BlockStore::open_with_config(native_metadata, &native_config, 4 * 1024 * 1024).unwrap();
        assert!(!reopened.has(&block.cid).unwrap());
    }

    #[test]
    fn files_backend_packs_small_object_records_and_recovers_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let metadata_path = dir.path().join("metadata.redb");
        let config = packed_files_config(dir.path());
        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let store = BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();
        let small = incompressible_bytes(4096);
        let boundary = incompressible_bytes(1024 * 1024);
        let large = incompressible_bytes(1024 * 1024 + 1);
        let small_put = store.put(CODEC_SMALL_OBJECT, &small).unwrap();
        let boundary_put = store.put(CODEC_SMALL_OBJECT, &boundary).unwrap();
        let large_put = store.put(CODEC_SMALL_OBJECT, &large).unwrap();
        assert_eq!(store.get(&small_put.cid).unwrap().payload, small);
        assert_eq!(
            store.get_range(&boundary_put.cid, 4096, 8192).unwrap(),
            boundary[4096..8192]
        );
        assert!(
            config.locations[0]
                .path
                .join("small-object-segments")
                .exists()
        );
        assert_eq!(store.backend.native().unwrap().records().unwrap().len(), 2);
        assert!(
            store
                .block_path(&store.get_meta(&large_put.cid).unwrap().unwrap())
                .exists()
        );
        drop(store);

        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let reopened = BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();
        assert_eq!(reopened.get(&small_put.cid).unwrap().payload, small);
        assert_eq!(reopened.get(&boundary_put.cid).unwrap().payload, boundary);
        assert_eq!(reopened.get(&large_put.cid).unwrap().payload, large);
    }

    #[test]
    fn native_segments_roundtrip_deduplicate_and_recover_index() {
        let dir = tempfile::tempdir().unwrap();
        let metadata_path = dir.path().join("metadata.redb");
        let config = native_config(dir.path());
        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let store = BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();
        let payload = incompressible_bytes(512 * 1024);
        let first = store.put_raw(&payload).unwrap();
        let second = store.put_raw(&payload).unwrap();
        assert!(second.already_existed);
        assert_eq!(store.get(&first.cid).unwrap().payload, payload);
        assert!(config.locations[0].path.join("segments").exists());
        assert_eq!(
            directory_regular_file_bytes(&config.locations[0].path.join("blocks")).unwrap(),
            0
        );
        drop(store);

        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let reopened = BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();
        assert_eq!(reopened.get(&first.cid).unwrap().payload, payload);
        assert_eq!(reopened.list_blocks().unwrap().len(), 1);
    }

    #[test]
    fn native_recovery_ignores_torn_tail_and_rejects_corrupt_payload() {
        let dir = tempfile::tempdir().unwrap();
        let metadata_path = dir.path().join("metadata.redb");
        let config = native_config(dir.path());
        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let store = BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();
        let put = store.put_raw(&incompressible_bytes(256 * 1024)).unwrap();
        let record = store
            .backend
            .native()
            .unwrap()
            .records()
            .unwrap()
            .into_iter()
            .find(|record| record.cid == put.cid)
            .unwrap();
        drop(store);
        let segment = config.locations[0]
            .path
            .join("segments")
            .join(format!("owner-{}", record.owner))
            .join(format!(
                "segment-{:020}-{:020}.pepper",
                record.generation, record.segment_id
            ));
        let file = OpenOptions::new().write(true).open(&segment).unwrap();
        file.write_all_at(&vec![0xa5; 4096], record.payload_offset)
            .unwrap();
        file.sync_data().unwrap();

        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let reopened = BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();
        assert!(!reopened.has(&put.cid).unwrap());
        assert!(matches!(
            reopened.get(&put.cid),
            Err(StorageError::NotFound(_))
        ));
        assert!(process_native_stats().torn_tails > 0);
    }

    #[test]
    fn native_recovery_rewinds_to_the_last_committed_batch() {
        let dir = tempfile::tempdir().unwrap();
        let metadata_path = dir.path().join("metadata.redb");
        let mut config = native_config(dir.path());
        config.native.owners = 1;
        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let store = BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();
        let committed = store.put_raw(&incompressible_bytes(128 * 1024)).unwrap();
        let abandoned_payload = incompressible_bytes(128 * 1024 + 1);
        let abandoned = store.encode(CODEC_RAW, &abandoned_payload).unwrap();
        store
            .backend
            .native()
            .unwrap()
            .append_uncommitted_for_test(&abandoned)
            .unwrap();
        drop(store);

        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let reopened = BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();
        assert!(reopened.has(&committed.cid).unwrap());
        assert!(!reopened.has(abandoned.cid()).unwrap());
        let after_recovery = reopened
            .put_raw(&incompressible_bytes(128 * 1024 + 2))
            .unwrap();
        drop(reopened);

        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let recovered_again =
            BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();
        assert!(recovered_again.has(&committed.cid).unwrap());
        assert!(recovered_again.has(&after_recovery.cid).unwrap());
        assert!(!recovered_again.has(abandoned.cid()).unwrap());
    }

    #[test]
    fn native_large_group_commit_splits_at_segment_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = native_config(dir.path());
        config.native.owners = 1;
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let store = BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();
        let blocks = (0..3)
            .map(|extra| (CODEC_RAW, incompressible_bytes(1536 * 1024 + extra)))
            .collect::<Vec<_>>();
        let before = process_native_stats();
        let puts = store.put_batch(&blocks).unwrap();
        let after = process_native_stats();
        assert_eq!(puts.len(), blocks.len());
        assert!(after.durability_barriers - before.durability_barriers >= 2);
        for (put, (_, payload)) in puts.iter().zip(&blocks) {
            assert_eq!(store.get(&put.cid).unwrap().payload, *payload);
        }
    }

    #[test]
    fn native_group_commit_uses_one_barrier_per_device() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = native_config(dir.path());
        config.native.owners = 1;
        config.native.segment_bytes = 8 * 1024 * 1024;
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let store = BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();

        // Create and durably initialize the active segment before measuring.
        store.put_raw(&incompressible_bytes(64 * 1024)).unwrap();
        let engine = store.backend.native().unwrap();
        let before = engine.device_barriers();
        let blocks = (0..8)
            .map(|extra| (CODEC_RAW, incompressible_bytes(128 * 1024 + extra)))
            .collect::<Vec<_>>();
        let puts = store.put_batch(&blocks).unwrap();

        assert_eq!(puts.len(), blocks.len());
        assert_eq!(engine.device_barriers() - before, 1);
    }

    #[test]
    fn block_encoding_round_trips_through_product_neutral_extent_adapter() {
        use pepper_buffer::{BufferChain, OwnedBuffer};
        use pepper_extent::{
            AppendPlan, ExtentStore, FileExtentConfig, FileExtentStore, RangeRead, RecordId,
        };

        let directory = tempfile::tempdir().unwrap();
        let metadata = Arc::new(
            MetadataStore::open_or_create(directory.path().join("metadata.redb")).unwrap(),
        );
        let block_root = directory.path().join("blocks");
        fs::create_dir_all(&block_root).unwrap();
        let store = BlockStore::open(
            metadata,
            &[StorageLocationConfig {
                path: block_root,
                max_capacity_bytes: 64 * 1024 * 1024,
            }],
        )
        .unwrap();
        let extent_store = FileExtentStore::open(
            directory.path().join("extents"),
            FileExtentConfig::default(),
        )
        .unwrap();
        let extent_id = extent_store.create().unwrap();
        let logical = incompressible_bytes(128 * 1024);
        let encoded = store.encode(CODEC_RAW, &logical).unwrap();
        let cid = encoded.cid().clone();
        let logical_size = encoded.logical_size_bytes();
        let encoded_bytes = encoded.into_bytes();
        let encoded_len = encoded_bytes.len() as u64;
        let plan = AppendPlan::new(
            extent_id,
            RecordId::new(cid.to_string().into_bytes()).unwrap(),
            BufferChain::from_buffer(OwnedBuffer::from_vec(encoded_bytes)),
        );
        let receipt = extent_store.append(plan).unwrap();
        let recovered = extent_store
            .read_range(RangeRead {
                extent_id,
                record_index: receipt.record_index,
                offset: 0,
                length: encoded_len,
            })
            .unwrap();
        let verified = store
            .validate_encoded_replica(cid.clone(), logical_size, recovered.bytes().to_vec())
            .unwrap();
        store.put_encoded(&verified).unwrap();
        assert_eq!(store.get(&cid).unwrap().payload, logical);

        let mut corrupt = recovered.bytes().to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(matches!(
            store.validate_encoded_replica(cid, logical_size, corrupt),
            Err(StorageError::HashMismatch(_) | StorageError::InvalidEncodedBlock(_))
        ));
    }

    #[test]
    fn native_concurrent_duplicate_put_has_one_creator() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = native_config(dir.path());
        config.native.owners = 1;
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let store =
            Arc::new(BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap());
        let payload = Arc::new(incompressible_bytes(512 * 1024));
        let start = Arc::new(std::sync::Barrier::new(16));
        let threads = (0..16)
            .map(|_| {
                let store = Arc::clone(&store);
                let payload = Arc::clone(&payload);
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    store.put_raw(payload.as_slice()).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let puts = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(puts.iter().filter(|put| !put.already_existed).count(), 1);
        assert!(puts.iter().all(|put| put.cid == puts[0].cid));
        assert_eq!(store.get(&puts[0].cid).unwrap().payload, *payload);
        assert_eq!(store.backend.native().unwrap().records().unwrap().len(), 1);
    }

    #[test]
    fn native_public_and_wire_ingress_reject_unverified_encoded_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let config = native_config(dir.path());
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let store = BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();
        let invalid = store
            .encode_preverified_raw(Cid::new(CODEC_RAW, b"different"), b"payload")
            .unwrap();

        assert!(matches!(
            store.put_encoded(&invalid),
            Err(StorageError::HashMismatch(_))
        ));
        assert!(
            store
                .put_replica_encoded_wire_batch(vec![(
                    invalid.cid().clone(),
                    invalid.logical_size_bytes(),
                    invalid.bytes().to_vec(),
                )])
                .is_err()
        );
        assert!(
            store
                .backend
                .native()
                .unwrap()
                .records()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn native_independent_puts_share_a_cross_request_barrier() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = native_config(dir.path());
        config.native.owners = 8;
        // The deliberately wide test window makes the batching assertion
        // deterministic even on a heavily loaded CI runner.
        config.native.group_commit_delay_microseconds = 100_000;
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let store =
            Arc::new(BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap());
        let engine = store.backend.native().unwrap();
        let mut by_owner = HashMap::new();
        for extra in 0..512 {
            let payload = incompressible_bytes(128 * 1024 + extra);
            let encoded = store.encode(CODEC_RAW, &payload).unwrap();
            by_owner
                .entry(engine.owner_for_test(encoded.cid()))
                .or_insert(encoded);
            if by_owner.len() == 8 {
                break;
            }
        }
        assert_eq!(by_owner.len(), 8);
        let blocks = by_owner.into_values().collect::<Vec<_>>();
        let start = Arc::new(std::sync::Barrier::new(blocks.len()));
        let before = engine.device_barriers();
        let threads = blocks
            .into_iter()
            .map(|block| {
                let store = Arc::clone(&store);
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    store.put_encoded(&block).unwrap()
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            assert!(!thread.join().unwrap().already_existed);
        }

        assert_eq!(engine.device_barriers() - before, 1);
    }

    #[test]
    fn native_tombstones_survive_compaction_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let metadata_path = dir.path().join("metadata.redb");
        let config = native_config(dir.path());
        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let store = BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();
        let keep = store.put_raw(&incompressible_bytes(128 * 1024)).unwrap();
        let remove_a = store
            .put_raw(&incompressible_bytes(128 * 1024 + 1))
            .unwrap();
        let remove_b = store
            .put_raw(&incompressible_bytes(128 * 1024 + 2))
            .unwrap();
        store
            .garbage_collect(&HashSet::from([keep.cid.clone()]))
            .unwrap();
        store.backend.native().unwrap().compact_now().unwrap();
        assert_eq!(store.get(&keep.cid).unwrap().size, 128 * 1024);
        assert!(!store.has(&remove_a.cid).unwrap());
        assert!(!store.has(&remove_b.cid).unwrap());
        drop(store);

        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let reopened = BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();
        assert!(reopened.has(&keep.cid).unwrap());
        assert!(!reopened.has(&remove_a.cid).unwrap());
        assert!(!reopened.has(&remove_b.cid).unwrap());
        assert!(process_native_stats().compactions > 0);
    }

    #[test]
    fn native_compaction_reclaims_fully_dead_segments() {
        let dir = tempfile::tempdir().unwrap();
        let metadata_path = dir.path().join("metadata.redb");
        let mut config = native_config(dir.path());
        config.native.owners = 1;
        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let store = BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();
        let put = store.put_raw(&incompressible_bytes(512 * 1024)).unwrap();
        store.garbage_collect(&HashSet::new()).unwrap();
        assert!(!store.has(&put.cid).unwrap());
        store.backend.native().unwrap().compact_now().unwrap();
        let segment_root = config.locations[0].path.join("segments").join("owner-0");
        assert_eq!(fs::read_dir(&segment_root).unwrap().count(), 0);
        drop(store);

        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let reopened = BlockStore::open_with_config(metadata, &config, 4 * 1024 * 1024).unwrap();
        assert!(!reopened.has(&put.cid).unwrap());
        assert_eq!(reopened.list_blocks().unwrap().len(), 0);
    }

    #[test]
    fn native_aligned_range_read_avoids_full_block_io() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = native_config(dir.path());
        config.native.segment_bytes = 8 * 1024 * 1024;
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let store = BlockStore::open_with_config(metadata, &config, 8 * 1024 * 1024).unwrap();
        let payload = incompressible_bytes(4 * 1024 * 1024);
        let put = store.put_raw(&payload).unwrap();
        let start = 1024 * 1024;
        let end = 2 * 1024 * 1024;
        let meta = store.get_meta(&put.cid).unwrap().unwrap();
        let (range, physical) = read_native_raw_block_range(
            store.backend.native().unwrap(),
            &put.cid,
            store.max_block_bytes,
            meta.size_bytes,
            start as u64,
            end as u64,
            meta.stored_size_bytes,
        )
        .unwrap()
        .unwrap();
        assert_eq!(range, payload[start..end]);
        assert!(
            physical < 2 * 1024 * 1024,
            "one MiB range physically read {physical} bytes"
        );
    }

    #[test]
    fn compression_probe_rejects_noise_and_accepts_repetition() {
        let mut noise = vec![0u8; 1024 * 1024];
        let mut state = 1u64;
        for chunk in noise.chunks_mut(8) {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        assert!(!compression_probe_accepts(&noise).unwrap());
        assert!(compression_probe_accepts(&vec![b'a'; noise.len()]).unwrap());
    }

    #[test]
    fn put_get_has_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let location = StorageLocationConfig {
            path: dir.path().join("store"),
            max_capacity_bytes: 1024 * 1024,
        };
        let store = BlockStore::open(metadata, &[location]).unwrap();
        let put = store.put_raw(b"hello").unwrap();
        assert!(store.has(&put.cid).unwrap());
        let block = store.get(&put.cid).unwrap();
        assert_eq!(block.payload, b"hello");
        let put_again = store.put_raw(b"hello").unwrap();
        assert_eq!(put.cid, put_again.cid);
        assert!(put_again.already_existed);
    }

    #[test]
    fn raw_envelope_range_reads_verify_only_covering_checksum_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let store = BlockStore::open(
            metadata,
            &[StorageLocationConfig {
                path: dir.path().join("store"),
                max_capacity_bytes: 8 * 1024 * 1024,
            }],
        )
        .unwrap();
        let logical = incompressible_bytes(4 * 1024 * 1024);
        let put = store.put_raw(&logical).unwrap();
        let start = 2 * 1024 * 1024;
        let end = start + 1024 * 1024;
        assert_eq!(
            store.get_range(&put.cid, start as u64, end as u64).unwrap(),
            logical[start..end]
        );

        let meta = store.get_meta(&put.cid).unwrap().unwrap();
        let path = store.block_path(&meta);
        let mut bytes = fs::read(&path).unwrap();
        let layout = parse_block_envelope(
            &bytes,
            bytes.len(),
            &put.cid,
            store.max_block_bytes,
            Some(logical.len() as u64),
        )
        .unwrap();
        bytes[layout.payload_offset + start] ^= 0xff;
        fs::write(path, bytes).unwrap();
        assert!(matches!(
            store.get_range(&put.cid, start as u64, end as u64),
            Err(StorageError::HashMismatch(_))
        ));
    }

    #[test]
    fn compresses_once_and_replica_stores_identical_encoded_bytes() {
        let source_dir = tempfile::tempdir().unwrap();
        let source_metadata = Arc::new(
            MetadataStore::open_or_create(source_dir.path().join("metadata.redb")).unwrap(),
        );
        let source = BlockStore::open(
            source_metadata,
            &[StorageLocationConfig {
                path: source_dir.path().join("store"),
                max_capacity_bytes: 8 * 1024 * 1024,
            }],
        )
        .unwrap();
        let logical = vec![b'a'; 1024 * 1024];
        let (puts, encoded) = source
            .put_batch_with_encoded(&[(CODEC_RAW, logical.clone())])
            .unwrap();
        assert_eq!(puts.len(), 1);
        assert_eq!(encoded[0].bytes()[9], BLOCK_ENCODING_ZSTD);
        assert!(encoded[0].bytes().len() < logical.len() / 10);
        let source_meta = source.get_meta(&puts[0].cid).unwrap().unwrap();
        assert_eq!(
            fs::read(source.block_path(&source_meta)).unwrap(),
            encoded[0].bytes()
        );

        let replica_dir = tempfile::tempdir().unwrap();
        let replica_metadata = Arc::new(
            MetadataStore::open_or_create(replica_dir.path().join("metadata.redb")).unwrap(),
        );
        let replica = BlockStore::open(
            replica_metadata,
            &[StorageLocationConfig {
                path: replica_dir.path().join("store"),
                max_capacity_bytes: 8 * 1024 * 1024,
            }],
        )
        .unwrap();
        let replica_puts = replica
            .put_replica_encoded_wire_batch(vec![(
                puts[0].cid.clone(),
                logical.len() as u64,
                encoded[0].bytes().to_vec(),
            )])
            .unwrap();
        let replica_meta = replica.get_meta(&replica_puts[0].cid).unwrap().unwrap();
        assert_eq!(
            fs::read(replica.block_path(&replica_meta)).unwrap(),
            encoded[0].bytes()
        );
        assert_eq!(replica.get(&puts[0].cid).unwrap().payload, logical);
    }

    #[test]
    fn incompressible_blocks_use_raw_envelope_encoding() {
        let dir = tempfile::tempdir().unwrap();
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let store = BlockStore::open(
            metadata,
            &[StorageLocationConfig {
                path: dir.path().join("store"),
                max_capacity_bytes: 8 * 1024 * 1024,
            }],
        )
        .unwrap();
        let logical = incompressible_bytes(1024 * 1024);
        let (_, encoded) = store
            .put_batch_with_encoded(&[(CODEC_RAW, logical.clone())])
            .unwrap();
        assert_eq!(encoded[0].bytes()[9], BLOCK_ENCODING_RAW);
        assert!(encoded[0].bytes().len() > logical.len());
        assert_eq!(store.get(encoded[0].cid()).unwrap().payload, logical);
    }

    #[test]
    fn preverified_erasure_shard_uses_one_raw_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let store = BlockStore::open(
            metadata,
            &[StorageLocationConfig {
                path: dir.path().join("store"),
                max_capacity_bytes: 8 * 1024 * 1024,
            }],
        )
        .unwrap();
        let logical = vec![0x5a; 1024 * 1024];
        let cid = Cid::new(CODEC_RAW, &logical);
        let encoded = store.encode_preverified_raw(cid.clone(), &logical).unwrap();
        assert_eq!(encoded.cid(), &cid);
        assert_eq!(encoded.bytes()[9], BLOCK_ENCODING_RAW);
        store.put_encoded(&encoded).unwrap();
        assert_eq!(store.get(&cid).unwrap().payload, logical);

        let wrong = store
            .encode_preverified_raw(Cid::new(CODEC_RAW, b"wrong"), b"payload")
            .unwrap();
        assert!(matches!(
            store.put_encoded(&wrong),
            Err(StorageError::HashMismatch(_))
        ));
    }

    #[test]
    fn batch_put_roundtrips_and_deduplicates_in_one_metadata_commit() {
        let dir = tempfile::tempdir().unwrap();
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let location = StorageLocationConfig {
            path: dir.path().join("store"),
            max_capacity_bytes: 1024 * 1024,
        };
        let store = BlockStore::open(metadata, &[location]).unwrap();
        let blocks = vec![
            (CODEC_RAW, b"alpha".to_vec()),
            (CODEC_RAW, b"beta".to_vec()),
            (CODEC_RAW, b"alpha".to_vec()),
        ];
        let puts = store.put_replica_batch(&blocks).unwrap();
        assert_eq!(puts.len(), 3);
        assert_eq!(puts[0].cid, puts[2].cid);
        assert!(!puts[0].already_existed);
        assert!(puts[2].already_existed);
        assert_eq!(store.get(&puts[0].cid).unwrap().payload, b"alpha");
        assert_eq!(store.get(&puts[1].cid).unwrap().payload, b"beta");
        assert!(store.storage_summary().unwrap().used_bytes > 9);
    }

    #[test]
    fn internal_blocks_are_inlined_atomically_and_survive_restart_and_gc() {
        let dir = tempfile::tempdir().unwrap();
        let metadata_path = dir.path().join("metadata.redb");
        let location = StorageLocationConfig {
            path: dir.path().join("store"),
            max_capacity_bytes: 1024 * 1024,
        };
        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let store = BlockStore::open(metadata, std::slice::from_ref(&location)).unwrap();
        let blocks = vec![
            (CODEC_MERKLE_NODE, b"merkle-node".to_vec()),
            (CODEC_NAMESPACE_COMMIT, b"namespace-commit".to_vec()),
        ];
        let puts = store.put_batch(&blocks).unwrap();
        for (put, (_, payload)) in puts.iter().zip(&blocks) {
            let meta = store.get_meta(&put.cid).unwrap().unwrap();
            assert!(meta.inline);
            assert!(meta.relative_path.is_empty());
            assert!(store.has(&put.cid).unwrap());
            assert_eq!(store.get(&put.cid).unwrap().payload, *payload);
        }
        assert_eq!(
            directory_regular_file_bytes(&location.path.join("blocks")).unwrap(),
            0
        );
        drop(store);

        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let reopened = BlockStore::open(metadata, &[location]).unwrap();
        for (put, (_, payload)) in puts.iter().zip(&blocks) {
            assert_eq!(reopened.get(&put.cid).unwrap().payload, *payload);
        }
        let report = reopened.garbage_collect(&HashSet::new()).unwrap();
        assert_eq!(report.deleted_blocks, 2);
        for put in puts {
            assert!(!reopened.has(&put.cid).unwrap());
        }
        assert_eq!(reopened.storage_summary().unwrap().used_bytes, 0);
    }

    #[test]
    fn inline_storage_is_limited_to_small_internal_codecs() {
        let dir = tempfile::tempdir().unwrap();
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let store = BlockStore::open(
            metadata,
            &[StorageLocationConfig {
                path: dir.path().join("store"),
                max_capacity_bytes: 2 * 1024 * 1024,
            }],
        )
        .unwrap();
        let raw = store.put(CODEC_RAW, b"small user block").unwrap();
        let large = store
            .put(
                CODEC_MERKLE_NODE,
                &vec![0x5a; INLINE_INTERNAL_BLOCK_MAX_BYTES as usize + 1],
            )
            .unwrap();
        assert!(!store.get_meta(&raw.cid).unwrap().unwrap().inline);
        assert!(!store.get_meta(&large.cid).unwrap().unwrap().inline);
    }

    #[test]
    fn inventory_is_paginated_stable_and_payload_free() {
        let dir = tempfile::tempdir().unwrap();
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let location = StorageLocationConfig {
            path: dir.path().join("store"),
            max_capacity_bytes: 1024 * 1024,
        };
        let store = BlockStore::open(metadata, &[location]).unwrap();
        for payload in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
            store.put_raw(payload).unwrap();
        }
        let first = store.inventory_page(None, 2).unwrap();
        assert_eq!(first.entries.len(), 2);
        assert!(
            first
                .entries
                .iter()
                .all(|entry| entry.integrity_state == "verified")
        );
        assert!(first.entries.iter().all(|entry| {
            entry
                .stored_size_bytes
                .is_some_and(|stored| stored > entry.logical_size_bytes)
        }));
        let cursor = Cid::from_str(first.next_cursor.as_deref().unwrap()).unwrap();
        let second = store.inventory_page(Some(&cursor), 2).unwrap();
        assert_eq!(second.entries.len(), 1);
        assert!(second.next_cursor.is_none());
        let all = first
            .entries
            .into_iter()
            .chain(second.entries)
            .map(|entry| entry.cid.to_string())
            .collect::<Vec<_>>();
        let mut sorted = all.clone();
        sorted.sort();
        assert_eq!(all, sorted);
    }

    #[test]
    fn detects_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let location = StorageLocationConfig {
            path: dir.path().join("store"),
            max_capacity_bytes: 1024 * 1024,
        };
        let store = BlockStore::open(metadata, &[location]).unwrap();
        let put = store.put_raw(b"hello").unwrap();
        let meta = store.get_meta(&put.cid).unwrap().unwrap();
        fs::write(store.block_path(&meta), b"corrupt").unwrap();
        assert!(matches!(
            store.get(&put.cid),
            Err(StorageError::HashMismatch(_))
        ));
        let repaired = store.put_raw(b"hello").unwrap();
        assert_eq!(repaired.cid, put.cid);
        assert!(!repaired.already_existed);
        assert_eq!(store.get(&put.cid).unwrap().payload, b"hello");
    }

    #[test]
    fn detects_corrupt_compressed_file() {
        let dir = tempfile::tempdir().unwrap();
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let location = StorageLocationConfig {
            path: dir.path().join("store"),
            max_capacity_bytes: 8 * 1024 * 1024,
        };
        let store = BlockStore::open(metadata, &[location]).unwrap();
        let put = store.put_raw(&vec![b'a'; 1024 * 1024]).unwrap();
        let meta = store.get_meta(&put.cid).unwrap().unwrap();
        let path = store.block_path(&meta);
        let mut stored = fs::read(&path).unwrap();
        let last = stored.last_mut().unwrap();
        *last ^= 0xff;
        fs::write(path, stored).unwrap();
        assert!(matches!(
            store.get(&put.cid),
            Err(StorageError::HashMismatch(_))
        ));
        assert!(store.get_meta(&put.cid).unwrap().unwrap().corrupt);
    }

    #[test]
    fn startup_quarantines_unknown_block_files_and_accounts_for_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let location = StorageLocationConfig {
            path: dir.path().join("store"),
            max_capacity_bytes: 1024 * 1024,
        };
        fs::create_dir_all(location.path.join("blocks/b3/aa/bb")).unwrap();
        let invalid = location.path.join("blocks/b3/aa/bb/not-a-block.blk");
        fs::write(&invalid, b"invalid").unwrap();
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let store = BlockStore::open(metadata, std::slice::from_ref(&location)).unwrap();
        assert!(!invalid.exists());
        assert_eq!(store.storage_summary().unwrap().used_bytes, 7);
        let report = store.purge_quarantine().unwrap();
        assert_eq!(report.reclaimed_bytes, 7);
        assert_eq!(store.storage_summary().unwrap().used_bytes, 0);
    }

    #[cfg(unix)]
    #[test]
    fn startup_quarantines_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let location = StorageLocationConfig {
            path: dir.path().join("store"),
            max_capacity_bytes: 1024 * 1024,
        };
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let outside_file = outside.join("must-remain");
        fs::write(&outside_file, b"host data").unwrap();
        fs::create_dir_all(location.path.join("blocks")).unwrap();
        symlink(&outside, location.path.join("blocks/link")).unwrap();
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let _store = BlockStore::open(metadata, &[location]).unwrap();
        assert_eq!(fs::read(&outside_file).unwrap(), b"host data");
    }

    #[test]
    fn startup_quarantines_oversized_candidate_blocks_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let location = StorageLocationConfig {
            path: dir.path().join("store"),
            max_capacity_bytes: 1024 * 1024,
        };
        let payload = [b'x'; 9];
        let cid = Cid::new(CODEC_RAW, &payload);
        let path = location.path.join(relative_block_path(&cid));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, payload).unwrap();
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let store = BlockStore::open_with_limit(metadata, &[location], 8).unwrap();
        assert!(!path.exists());
        assert!(!store.has(&cid).unwrap());
    }

    #[test]
    fn rejects_a_storage_location_already_locked_by_another_store() {
        let dir = tempfile::tempdir().unwrap();
        let location = StorageLocationConfig {
            path: dir.path().join("store"),
            max_capacity_bytes: 1024 * 1024,
        };
        let first_metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("first.redb")).unwrap());
        let _first = BlockStore::open(first_metadata, std::slice::from_ref(&location)).unwrap();
        let second_metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("second.redb")).unwrap());
        assert!(matches!(
            BlockStore::open(second_metadata, &[location]),
            Err(StorageError::LocationLocked(_))
        ));
    }

    #[test]
    fn block_paths_are_sharded_by_digest_prefix() {
        let cid = Cid::new(CODEC_RAW, b"hello");
        let digest = hex::encode(cid.digest);
        let relative = relative_block_path(&cid);
        let parts = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(parts[0], "blocks");
        assert_eq!(parts[1], cid.hash_alg.code());
        assert_eq!(parts[2], digest[0..2]);
        assert_eq!(parts[3], digest[2..4]);
        assert!(parts[4].contains(&digest));
    }

    #[test]
    fn startup_reconciliation_removes_missing_file_metadata_and_temps() {
        let dir = tempfile::tempdir().unwrap();
        let metadata_path = dir.path().join("metadata.redb");
        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let location = StorageLocationConfig {
            path: dir.path().join("store"),
            max_capacity_bytes: 1024 * 1024,
        };
        let store = BlockStore::open(metadata, std::slice::from_ref(&location)).unwrap();
        let put = store.put_raw(b"hello").unwrap();
        let meta = store.get_meta(&put.cid).unwrap().unwrap();
        fs::remove_file(store.block_path(&meta)).unwrap();
        let temp_file = location.path.join("tmp/orphan.tmp");
        fs::write(&temp_file, b"partial").unwrap();
        drop(store);

        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let reopened = BlockStore::open(metadata, &[location]).unwrap();
        assert!(!reopened.has(&put.cid).unwrap());
        assert!(reopened.get_meta(&put.cid).unwrap().is_none());
        assert!(!temp_file.exists());
    }

    #[test]
    fn capacity_limit_rejects_writes_without_corrupting_existing_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let location = StorageLocationConfig {
            path: dir.path().join("store"),
            max_capacity_bytes: 245,
        };
        let store = BlockStore::open(metadata, &[location]).unwrap();
        let put = store.put_raw(b"1234567").unwrap();
        assert!(matches!(
            store.put_raw(b"xy"),
            Err(StorageError::CapacityExceeded { .. })
        ));
        assert_eq!(store.get(&put.cid).unwrap().payload, b"1234567");
    }

    #[test]
    fn normal_writes_stop_at_hard_pressure_but_repair_can_fill_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let metadata =
            Arc::new(MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap());
        let location = StorageLocationConfig {
            path: dir.path().join("store"),
            max_capacity_bytes: 990,
        };
        let store = BlockStore::open(metadata, &[location]).unwrap();
        store.put_raw(&[b'a'; 700]).unwrap();
        assert!(matches!(
            store.put_raw(&[b'b'; 6]),
            Err(StorageError::CapacityExceeded { .. })
        ));
        let replica = store.put_replica(CODEC_RAW, &[b'c'; 6]).unwrap();
        assert_eq!(store.get(&replica.cid).unwrap().payload, [b'c'; 6]);
    }

    #[test]
    fn startup_reconciliation_reconstructs_missing_metadata_for_valid_files() {
        let dir = tempfile::tempdir().unwrap();
        let metadata_path = dir.path().join("metadata.redb");
        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let location = StorageLocationConfig {
            path: dir.path().join("store"),
            max_capacity_bytes: 1024 * 1024,
        };
        let store = BlockStore::open(metadata, std::slice::from_ref(&location)).unwrap();
        let put = store.put_raw(b"hello").unwrap();
        let meta = store.get_meta(&put.cid).unwrap().unwrap();
        let block_path = store.block_path(&meta);
        store.remove_block_meta(&meta).unwrap();
        assert!(block_path.exists());
        assert!(store.get_meta(&put.cid).unwrap().is_none());
        drop(store);

        let metadata = Arc::new(MetadataStore::open_or_create(&metadata_path).unwrap());
        let reopened = BlockStore::open(metadata, &[location]).unwrap();
        assert_eq!(reopened.get(&put.cid).unwrap().payload, b"hello");
        assert!(reopened.get_meta(&put.cid).unwrap().is_some());
    }
}
