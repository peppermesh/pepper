// SPDX-License-Identifier: Apache-2.0

use fs2::FileExt;
use pepper_config::StorageLocationConfig;
use pepper_metadata::MetadataStore;
use pepper_types::{
    Block, BlockStatResponse, CODEC_RAW, Cid, Codec, GcReport, HashAlg, PutBlockResponse,
};
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
};
use thiserror::Error;

const BLOCKS: TableDefinition<&str, &[u8]> = TableDefinition::new("blocks");
const BLOCKS_BY_RETENTION: TableDefinition<&str, &str> =
    TableDefinition::new("blocks_by_retention");
const BLOCKS_BY_LAST_ACCESSED: TableDefinition<&str, &str> =
    TableDefinition::new("blocks_by_last_accessed");
const STORAGE_LOCATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("storage_locations");
const STORAGE_LOCATIONS_BY_PATH: TableDefinition<&str, &str> =
    TableDefinition::new("storage_locations_by_path");
const SOFT_PRESSURE_PERCENT: u64 = 85;
const HARD_PRESSURE_PERCENT: u64 = 95;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockMeta {
    cid: Cid,
    codec: Codec,
    hash_alg: HashAlg,
    size_bytes: u64,
    storage_location_id: String,
    storage_location_path: String,
    relative_path: String,
    created_at_unix_seconds: u64,
    last_accessed_at_unix_seconds: Option<u64>,
    pin_state: String,
    replica_state: String,
    retention_class: String,
    verified_at_unix_seconds: Option<u64>,
    corrupt: bool,
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

#[derive(Clone)]
pub struct BlockStore {
    metadata: Arc<MetadataStore>,
    locations: Arc<Vec<StorageLocationRuntime>>,
    max_block_bytes: u64,
    write_lock: Arc<Mutex<()>>,
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
        let store = Self {
            metadata,
            locations: Arc::new(runtimes),
            max_block_bytes,
            write_lock: Arc::new(Mutex::new(())),
        };
        store.reconcile_metadata_with_files()?;
        Ok(store)
    }

    pub fn put_raw(&self, payload: &[u8]) -> Result<PutBlockResponse, StorageError> {
        self.put(CODEC_RAW, payload)
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

    fn put_with_intent(
        &self,
        codec: Codec,
        payload: &[u8],
        intent: WriteIntent,
    ) -> Result<PutBlockResponse, StorageError> {
        let size = payload.len() as u64;
        if size > self.max_block_bytes {
            return Err(StorageError::BlockTooLarge {
                size_bytes: size,
                max_bytes: self.max_block_bytes,
            });
        }
        let _write_guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let cid = Cid::new(codec, payload);
        if let Some(meta) = self.get_meta(&cid)? {
            let path = self.block_path(&meta);
            let existing_valid = if meta.corrupt {
                false
            } else {
                match verify_file(&path, &cid, self.max_block_bytes) {
                    Ok(valid) => valid,
                    Err(StorageError::BlockTooLarge { .. }) => false,
                    Err(error) => return Err(error),
                }
            };
            if existing_valid {
                return Ok(meta.to_put_response(true));
            }
            if path.exists() {
                fs::remove_file(&path).map_err(|source| StorageError::Io {
                    path: path.display().to_string(),
                    source,
                })?;
            }
            self.remove_block_meta(&meta)?;
        }

        let location = self.select_location(size, intent)?;
        let relative_path = relative_block_path(&cid);
        let final_path = location.path.join(&relative_path);
        let temp_path = location.path.join("tmp").join(format!(
            "write-{}-{}.tmp",
            unix_nanos(),
            std::process::id()
        ));

        write_temp_file(&temp_path, payload)?;
        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent).map_err(|source| StorageError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }

        let final_valid = if final_path.exists() {
            match verify_file(&final_path, &cid, self.max_block_bytes) {
                Ok(valid) => valid,
                Err(StorageError::BlockTooLarge { .. }) => false,
                Err(error) => return Err(error),
            }
        } else {
            false
        };
        if final_valid {
            fs::remove_file(&temp_path).map_err(|source| StorageError::Io {
                path: temp_path.display().to_string(),
                source,
            })?;
        } else {
            if final_path.exists() {
                fs::remove_file(&final_path).map_err(|source| StorageError::Io {
                    path: final_path.display().to_string(),
                    source,
                })?;
            }
            fs::rename(&temp_path, &final_path).map_err(|source| StorageError::Io {
                path: final_path.display().to_string(),
                source,
            })?;
            fsync_parent(&final_path)?;
        }

        let meta = BlockMeta {
            cid: cid.clone(),
            codec,
            hash_alg: HashAlg::Blake3,
            size_bytes: size,
            storage_location_id: location.id.clone(),
            storage_location_path: location.path.display().to_string(),
            relative_path: relative_path.display().to_string(),
            created_at_unix_seconds: unix_seconds(),
            last_accessed_at_unix_seconds: None,
            pin_state: "none".to_string(),
            replica_state: "none".to_string(),
            retention_class: "cache".to_string(),
            verified_at_unix_seconds: Some(unix_seconds()),
            corrupt: false,
        };
        self.insert_block_meta(&meta)?;
        Ok(meta.to_put_response(false))
    }

    pub fn get(&self, cid: &Cid) -> Result<Block, StorageError> {
        let meta = self
            .get_meta(cid)?
            .ok_or_else(|| StorageError::NotFound(cid.clone()))?;
        let path = self.block_path(&meta);
        if meta.size_bytes > self.max_block_bytes {
            return Err(StorageError::BlockTooLarge {
                size_bytes: meta.size_bytes,
                max_bytes: self.max_block_bytes,
            });
        }
        let payload =
            read_regular_file_bounded(&path, self.max_block_bytes, Some(meta.size_bytes))?;
        if !cid.verify(&payload) {
            self.mark_corrupt(cid)?;
            return Err(StorageError::HashMismatch(cid.clone()));
        }
        self.update_last_accessed(cid)?;
        Ok(Block {
            cid: cid.clone(),
            codec: meta.codec,
            size: payload.len() as u64,
            payload,
        })
    }

    pub fn has(&self, cid: &Cid) -> Result<bool, StorageError> {
        let Some(meta) = self.get_meta(cid)? else {
            return Ok(false);
        };
        if meta.corrupt || meta.size_bytes > self.max_block_bytes {
            return Ok(false);
        }
        let path = self.block_path(&meta);
        let Ok(file_meta) = path.symlink_metadata() else {
            return Ok(false);
        };
        Ok(file_meta.is_file() && file_meta.len() == meta.size_bytes)
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
        if path.exists()
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
            .filter(|meta| !meta.corrupt && self.block_path(meta).exists())
            .map(|meta| meta.to_stat_response())
            .collect())
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
                let path = self.block_path(&meta);
                if path.exists() {
                    fs::remove_file(&path).map_err(|source| StorageError::Io {
                        path: path.display().to_string(),
                        source,
                    })?;
                }
                self.remove_block_meta(&meta)?;
            }
            deleted_blocks += 1;
            reclaimed_bytes = reclaimed_bytes.saturating_add(meta.size_bytes);
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
            if !self.block_path(&meta).exists() {
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
                if file_meta.len() > self.max_block_bytes {
                    quarantine_file(location, &path)?;
                    continue;
                }
                let payload =
                    read_regular_file_bounded(&path, self.max_block_bytes, Some(file_meta.len()))?;
                if !cid.verify(&payload) {
                    quarantine_file(location, &path)?;
                    continue;
                }
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
                    storage_location_id: location.id.clone(),
                    storage_location_path: location.path.display().to_string(),
                    relative_path,
                    created_at_unix_seconds: unix_seconds(),
                    last_accessed_at_unix_seconds: None,
                    pin_state: "none".to_string(),
                    replica_state: "none".to_string(),
                    retention_class: "cache".to_string(),
                    verified_at_unix_seconds: Some(unix_seconds()),
                    corrupt: false,
                };
                self.insert_block_meta(&meta)?;
            }
        }
        Ok(())
    }

    fn rebuild_storage_location_usage(&self) -> Result<(), StorageError> {
        let mut used_by_location = HashMap::<String, u64>::new();
        for meta in self.list_block_metas()? {
            if self.block_path(&meta).exists() && !meta.corrupt {
                *used_by_location
                    .entry(meta.storage_location_id.clone())
                    .or_default() += meta.size_bytes;
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

    fn select_location(
        &self,
        size_bytes: u64,
        intent: WriteIntent,
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
            let used = meta.used_bytes.saturating_add(meta.reserved_bytes);
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
        let write_txn = self
            .metadata
            .database()
            .begin_write()
            .map_err(|source| StorageError::Transaction(Box::new(source)))?;
        {
            let mut blocks = write_txn
                .open_table(BLOCKS)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            if blocks
                .get(meta.cid.to_string().as_str())
                .map_err(|source| StorageError::RedbStorage(Box::new(source)))?
                .is_some()
            {
                return Ok(());
            }
            let meta_bytes = serde_json::to_vec(meta)?;
            blocks
                .insert(meta.cid.to_string().as_str(), meta_bytes.as_slice())
                .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
        }
        {
            let mut retention = write_txn
                .open_table(BLOCKS_BY_RETENTION)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            retention
                .insert(
                    format!("{}:{}", meta.retention_class, meta.cid).as_str(),
                    "",
                )
                .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
        }
        {
            let mut locations = write_txn
                .open_table(STORAGE_LOCATIONS)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            let mut location: StorageLocationMeta = {
                let Some(location_value) = locations
                    .get(meta.storage_location_id.as_str())
                    .map_err(|source| StorageError::RedbStorage(Box::new(source)))?
                else {
                    return Err(StorageError::NoStorageLocations);
                };
                serde_json::from_slice(location_value.value())?
            };
            location.used_bytes = location.used_bytes.saturating_add(meta.size_bytes);
            let location_bytes = serde_json::to_vec(&location)?;
            locations
                .insert(meta.storage_location_id.as_str(), location_bytes.as_slice())
                .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
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
        {
            let mut retention = write_txn
                .open_table(BLOCKS_BY_RETENTION)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            retention
                .remove(format!("{}:{}", meta.retention_class, meta.cid).as_str())
                .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
        }
        if let Some(last_accessed) = meta.last_accessed_at_unix_seconds {
            let mut last_accessed_index = write_txn
                .open_table(BLOCKS_BY_LAST_ACCESSED)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            last_accessed_index
                .remove(format!("{}:{}", last_accessed, meta.cid).as_str())
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
                location.used_bytes = location.used_bytes.saturating_sub(meta.size_bytes);
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

    fn update_last_accessed(&self, cid: &Cid) -> Result<(), StorageError> {
        let Some(mut meta) = self.get_meta(cid)? else {
            return Ok(());
        };
        let old_index_key = meta
            .last_accessed_at_unix_seconds
            .map(|ts| format!("{}:{}", ts, cid));
        meta.last_accessed_at_unix_seconds = Some(unix_seconds());
        let new_index_key = format!(
            "{}:{}",
            meta.last_accessed_at_unix_seconds.unwrap_or_default(),
            cid
        );
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
        {
            let mut index = write_txn
                .open_table(BLOCKS_BY_LAST_ACCESSED)
                .map_err(|source| StorageError::Table(Box::new(source)))?;
            if let Some(old_key) = old_index_key {
                index
                    .remove(old_key.as_str())
                    .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
            }
            index
                .insert(new_index_key.as_str(), "")
                .map_err(|source| StorageError::RedbStorage(Box::new(source)))?;
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
            last_accessed_at_unix_seconds: self.last_accessed_at_unix_seconds,
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
        write_txn
            .open_table(BLOCKS_BY_LAST_ACCESSED)
            .map_err(|source| StorageError::Table(Box::new(source)))?;
    }
    write_txn
        .commit()
        .map_err(|source| StorageError::Commit(Box::new(source)))?;

    Ok(StorageLocationRuntime {
        id,
        path: canonical,
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

fn read_regular_file_bounded(
    path: &Path,
    max_bytes: u64,
    _expected_bytes: Option<u64>,
) -> Result<Vec<u8>, StorageError> {
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

fn verify_file(path: &Path, cid: &Cid, max_bytes: u64) -> Result<bool, StorageError> {
    if !path.exists() {
        return Ok(false);
    }
    let payload = read_regular_file_bounded(path, max_bytes, None)?;
    Ok(cid.verify(&payload))
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

fn write_temp_file(path: &Path, payload: &[u8]) -> Result<(), StorageError> {
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
    file.sync_all().map_err(|source| StorageError::Io {
        path: path.display().to_string(),
        source,
    })?;
    Ok(())
}

fn fsync_parent(path: &Path) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|source| StorageError::Io {
                path: parent.display().to_string(),
                source,
            })?;
    }
    Ok(())
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
            max_capacity_bytes: 8,
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
            max_capacity_bytes: 100,
        };
        let store = BlockStore::open(metadata, &[location]).unwrap();
        store.put_raw(&[b'a'; 90]).unwrap();
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
