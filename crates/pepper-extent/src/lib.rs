// SPDX-License-Identifier: Apache-2.0

//! Product-neutral append extents. Active record identity is supplied by the
//! product and never requires a content hash.

use pepper_buffer::{BufferChain, Checksum, OwnedBuffer};
use pepper_durability::{
    BarrierTarget, DeviceId, DurabilityClass, DurabilityReceipt, DurabilityRequest,
    DurabilityScheduler, OrderingKey, Priority, SchedulerConfig, SchedulerSnapshot,
};
use pepper_observability::{CostMetric, OperationStage, add_current_cost, observe_current_stage};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File, OpenOptions},
    io::{IoSlice, Seek, SeekFrom, Write},
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const EXTENT_MAGIC: &[u8; 8] = b"PEPEXT01";
const RECORD_MAGIC: &[u8; 8] = b"PEPEXREC";
const FORMAT_VERSION: u16 = 1;
const RECORD_DATA: u8 = 1;
const RECORD_COMMIT: u8 = 2;
const RECORD_SEAL: u8 = 3;
const FIXED_HEADER_BYTES: usize = 96;
const MAX_RECORD_ID_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExtentId([u8; 16]);

impl ExtentId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Display for ExtentId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RecordId(Vec<u8>);

impl RecordId {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, ExtentError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_RECORD_ID_BYTES {
            return Err(ExtentError::InvalidRecordIdLength(bytes.len()));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Compression {
    None,
    Zstd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Encryption {
    None,
    Aes256Gcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageClass {
    Hot,
    Warm,
    Cold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordMetadata {
    pub compression: Compression,
    pub encryption: Encryption,
    pub storage_class: StorageClass,
    pub live: bool,
}

impl Default for RecordMetadata {
    fn default() -> Self {
        Self {
            compression: Compression::None,
            encryption: Encryption::None,
            storage_class: StorageClass::Hot,
            live: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppendPlan {
    pub extent_id: ExtentId,
    pub record_id: RecordId,
    pub payload: BufferChain,
    pub logical_len: u64,
    pub checksum: Option<Checksum>,
    pub metadata: RecordMetadata,
}

#[derive(Debug, Clone)]
pub struct ReplacementRecord {
    pub record_id: RecordId,
    pub payload: BufferChain,
    pub logical_len: u64,
    pub checksum: Option<Checksum>,
    pub metadata: RecordMetadata,
}

impl From<AppendPlan> for ReplacementRecord {
    fn from(plan: AppendPlan) -> Self {
        Self {
            record_id: plan.record_id,
            payload: plan.payload,
            logical_len: plan.logical_len,
            checksum: plan.checksum,
            metadata: plan.metadata,
        }
    }
}

impl AppendPlan {
    pub fn new(extent_id: ExtentId, record_id: RecordId, payload: BufferChain) -> Self {
        let logical_len = payload.logical_len();
        Self {
            extent_id,
            record_id,
            payload,
            logical_len,
            checksum: None,
            metadata: RecordMetadata::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendReceipt {
    pub extent_id: ExtentId,
    pub record_id: RecordId,
    pub record_index: u64,
    pub payload_offset: u64,
    pub encoded_len: u64,
    pub logical_len: u64,
    pub checksum: Checksum,
    pub durability: DurabilityReceipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendReservation {
    token: u64,
    pub extent_id: ExtentId,
    pub maximum_records: usize,
    pub maximum_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeRead {
    pub extent_id: ExtentId,
    pub record_index: u64,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordInspection {
    pub record_id: RecordId,
    pub record_index: u64,
    pub payload_offset: u64,
    pub encoded_len: u64,
    pub logical_len: u64,
    pub checksum: Checksum,
    pub metadata: RecordMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentInspection {
    pub extent_id: ExtentId,
    pub committed_end: u64,
    pub sealed: bool,
    pub digest: Option<[u8; 32]>,
    pub ignored_tail_bytes: u64,
    pub records: Vec<RecordInspection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedExtent {
    pub extent_id: ExtentId,
    pub committed_len: u64,
    pub record_count: u64,
    pub digest: [u8; 32],
    pub durability: DurabilityReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    pub sealed: SealedExtent,
    pub active: ExtentId,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExtentStats {
    pub appended_records: u64,
    pub appended_bytes: u64,
    pub read_operations: u64,
    pub read_bytes: u64,
    pub recovered_records: u64,
    pub ignored_tail_bytes: u64,
    pub sealed_extents: u64,
    pub device_queue: SchedulerSnapshot,
}

pub trait ExtentStore: Send + Sync {
    fn create(&self) -> Result<ExtentId, ExtentError>;
    fn extent_ids(&self) -> Result<Vec<ExtentId>, ExtentError>;
    fn reserve(
        &self,
        extent_id: ExtentId,
        maximum_records: usize,
        maximum_bytes: u64,
    ) -> Result<AppendReservation, ExtentError>;
    fn commit(
        &self,
        reservation: AppendReservation,
        plans: Vec<AppendPlan>,
    ) -> Result<Vec<AppendReceipt>, ExtentError>;
    fn append(&self, plan: AppendPlan) -> Result<AppendReceipt, ExtentError>;
    fn append_batch(&self, plans: Vec<AppendPlan>) -> Result<Vec<AppendReceipt>, ExtentError>;
    fn read_range(&self, request: RangeRead) -> Result<OwnedBuffer, ExtentError>;
    fn read_vectored(&self, requests: &[RangeRead]) -> Result<Vec<OwnedBuffer>, ExtentError>;
    fn seal(&self, extent_id: ExtentId) -> Result<SealedExtent, ExtentError>;
    /// Atomically replace one sealed extent with a newly sealed extent.
    ///
    /// The implementation must stage the replacement outside the live extent
    /// namespace and persist a recoverable intent before installing it.
    fn replace_sealed(
        &self,
        extent_id: ExtentId,
        records: Vec<ReplacementRecord>,
    ) -> Result<SealedExtent, ExtentError>;
    fn rotate(&self, extent_id: ExtentId) -> Result<Rotation, ExtentError>;
    fn inspect(&self, extent_id: ExtentId) -> Result<ExtentInspection, ExtentError>;
    fn recover(&self, extent_id: ExtentId) -> Result<ExtentInspection, ExtentError>;
    /// Truncate an active extent at a committed append-batch boundary.
    ///
    /// Products must authenticate and epoch-fence the recovery command before
    /// calling this storage primitive. The extent layer enforces that a
    /// committed append batch is never torn in half.
    fn truncate(
        &self,
        extent_id: ExtentId,
        record_count: u64,
    ) -> Result<ExtentInspection, ExtentError>;
    /// Physically reclaim a sealed extent after its owning catalog has
    /// durably made the extent unreachable.
    fn reclaim(&self, extent_id: ExtentId) -> Result<(), ExtentError>;
}

#[derive(Debug, Clone, Copy)]
pub struct FileExtentConfig {
    pub alignment: usize,
    pub maximum_extent_bytes: u64,
    pub maximum_batch_bytes: u64,
    pub maximum_batch_records: usize,
    pub group_commit_delay: Duration,
    pub group_commit_max_requests: usize,
}

impl Default for FileExtentConfig {
    fn default() -> Self {
        Self {
            alignment: 4096,
            maximum_extent_bytes: 1024 * 1024 * 1024,
            maximum_batch_bytes: 16 * 1024 * 1024,
            maximum_batch_records: 4096,
            group_commit_delay: Duration::from_micros(200),
            group_commit_max_requests: 256,
        }
    }
}

#[derive(Debug, Error)]
pub enum ExtentError {
    #[error("invalid extent configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid record ID length {0}; expected 1..={MAX_RECORD_ID_BYTES}")]
    InvalidRecordIdLength(usize),
    #[error("extent not found: {0}")]
    NotFound(ExtentId),
    #[error("extent is sealed: {0}")]
    Sealed(ExtentId),
    #[error("extent is active and cannot be reclaimed: {0}")]
    ActiveExtent(ExtentId),
    #[error("extent has an active read lease and cannot yet be reclaimed: {0}")]
    ExtentLeased(ExtentId),
    #[error("record count {record_count} is not an append-batch boundary in extent {extent_id}")]
    InvalidTruncation {
        extent_id: ExtentId,
        record_count: u64,
    },
    #[error("append batch is empty")]
    EmptyBatch,
    #[error("append batch mixes extent IDs")]
    MixedExtents,
    #[error("append has {records} records and {bytes} bytes, exceeding reservation")]
    ReservationExceeded { records: usize, bytes: u64 },
    #[error("append reservation is invalid or already consumed")]
    InvalidReservation,
    #[error("extent capacity exceeded: append ends at {end}, maximum is {maximum}")]
    CapacityExceeded { end: u64, maximum: u64 },
    #[error("record index {record_index} does not exist in extent {extent_id}")]
    RecordNotFound {
        extent_id: ExtentId,
        record_index: u64,
    },
    #[error("invalid record range {offset}..{end} for encoded length {length}")]
    InvalidRange { offset: u64, end: u64, length: u64 },
    #[error("checksum does not match record {0:?}")]
    ChecksumMismatch(RecordId),
    #[error("extent format is corrupt at {path}: {message}")]
    Corrupt { path: String, message: String },
    #[error("extent I/O failed at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("durability failed: {0}")]
    Durability(String),
    #[error("extent lock is poisoned")]
    LockPoisoned,
}

struct RecordLocation {
    inspection: RecordInspection,
    batch_end: u64,
}

struct ExtentState {
    committed_end: u64,
    next_batch_id: u64,
    sealed: bool,
    ignored_tail_bytes: u64,
    records: Vec<RecordLocation>,
}

struct ExtentHandle {
    path: PathBuf,
    file: Arc<File>,
    state: Mutex<ExtentState>,
}

struct ReservationState {
    extent_id: ExtentId,
    maximum_records: usize,
    maximum_bytes: u64,
}

#[derive(Default)]
struct Metrics {
    appended_records: AtomicU64,
    appended_bytes: AtomicU64,
    read_operations: AtomicU64,
    read_bytes: AtomicU64,
    recovered_records: AtomicU64,
    ignored_tail_bytes: AtomicU64,
    sealed_extents: AtomicU64,
}

pub struct FileExtentStore {
    root: PathBuf,
    config: FileExtentConfig,
    extents: RwLock<HashMap<ExtentId, Arc<ExtentHandle>>>,
    next_id: AtomicU64,
    next_reservation: AtomicU64,
    reservations: Mutex<HashMap<u64, ReservationState>>,
    durability: DurabilityScheduler,
    metrics: Metrics,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReplacementIntent {
    old_extent: ExtentId,
    new_extent: ExtentId,
    staging_directory: String,
}

impl FileExtentStore {
    pub fn open(root: impl AsRef<Path>, config: FileExtentConfig) -> Result<Self, ExtentError> {
        validate_config(config)?;
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|source| ExtentError::Io {
            path: root.display().to_string(),
            source,
        })?;
        let durability = DurabilityScheduler::start(
            "pepper-extent-durability",
            SchedulerConfig {
                maximum_group_delay: config.group_commit_delay,
                maximum_batch_bytes: config.maximum_batch_bytes,
                maximum_requests: config.group_commit_max_requests,
                queue_depth: config.group_commit_max_requests.saturating_mul(4),
            },
        )
        .map_err(|error| ExtentError::Durability(error.to_string()))?;
        let store = Self {
            root,
            config,
            extents: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            next_reservation: AtomicU64::new(1),
            reservations: Mutex::new(HashMap::new()),
            durability,
            metrics: Metrics::default(),
        };
        store.recover_replacements()?;
        store.recover_all()?;
        Ok(store)
    }

    fn recover_replacements(&self) -> Result<(), ExtentError> {
        let mut intents = fs::read_dir(&self.root)
            .map_err(|source| ExtentError::Io {
                path: self.root.display().to_string(),
                source,
            })?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with(".replacement-") && name.ends_with(".json")
                    })
            })
            .collect::<Vec<_>>();
        intents.sort();
        for path in intents {
            let intent: ReplacementIntent =
                serde_json::from_slice(&fs::read(&path).map_err(|source| ExtentError::Io {
                    path: path.display().to_string(),
                    source,
                })?)
                .map_err(|error| ExtentError::Corrupt {
                    path: path.display().to_string(),
                    message: error.to_string(),
                })?;
            let staging = self.root.join(&intent.staging_directory);
            let staged = staging.join(format!("{}.extent", intent.new_extent));
            let installed = self.root.join(format!("{}.extent", intent.new_extent));
            if !installed.exists() {
                fs::rename(&staged, &installed).map_err(|source| ExtentError::Io {
                    path: staged.display().to_string(),
                    source,
                })?;
            }
            let old = self.root.join(format!("{}.extent", intent.old_extent));
            if old.exists() {
                fs::remove_file(&old).map_err(|source| ExtentError::Io {
                    path: old.display().to_string(),
                    source,
                })?;
            }
            if staging.exists() {
                fs::remove_dir_all(&staging).map_err(|source| ExtentError::Io {
                    path: staging.display().to_string(),
                    source,
                })?;
            }
            fs::remove_file(&path).map_err(|source| ExtentError::Io {
                path: path.display().to_string(),
                source,
            })?;
            File::open(&self.root)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| ExtentError::Io {
                    path: self.root.display().to_string(),
                    source,
                })?;
        }
        Ok(())
    }

    pub fn stats(&self) -> ExtentStats {
        ExtentStats {
            appended_records: self.metrics.appended_records.load(Ordering::Relaxed),
            appended_bytes: self.metrics.appended_bytes.load(Ordering::Relaxed),
            read_operations: self.metrics.read_operations.load(Ordering::Relaxed),
            read_bytes: self.metrics.read_bytes.load(Ordering::Relaxed),
            recovered_records: self.metrics.recovered_records.load(Ordering::Relaxed),
            ignored_tail_bytes: self.metrics.ignored_tail_bytes.load(Ordering::Relaxed),
            sealed_extents: self.metrics.sealed_extents.load(Ordering::Relaxed),
            device_queue: self.durability.snapshot(),
        }
    }

    fn recover_all(&self) -> Result<(), ExtentError> {
        let mut paths = fs::read_dir(&self.root)
            .map_err(|source| ExtentError::Io {
                path: self.root.display().to_string(),
                source,
            })?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "extent")
            })
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            let id = parse_extent_filename(&path)?;
            let file = Arc::new(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .map_err(|source| ExtentError::Io {
                        path: path.display().to_string(),
                        source,
                    })?,
            );
            let state = recover_file(id, &path, &file, self.config)?;
            self.metrics
                .recovered_records
                .fetch_add(state.records.len() as u64, Ordering::Relaxed);
            self.metrics
                .ignored_tail_bytes
                .fetch_add(state.ignored_tail_bytes, Ordering::Relaxed);
            self.extents
                .write()
                .map_err(|_| ExtentError::LockPoisoned)?
                .insert(
                    id,
                    Arc::new(ExtentHandle {
                        path,
                        file,
                        state: Mutex::new(state),
                    }),
                );
        }
        Ok(())
    }

    fn handle(&self, id: ExtentId) -> Result<Arc<ExtentHandle>, ExtentError> {
        self.extents
            .read()
            .map_err(|_| ExtentError::LockPoisoned)?
            .get(&id)
            .cloned()
            .ok_or(ExtentError::NotFound(id))
    }

    fn append_internal(&self, plans: Vec<AppendPlan>) -> Result<Vec<AppendReceipt>, ExtentError> {
        if plans.is_empty() {
            return Err(ExtentError::EmptyBatch);
        }
        let extent_id = plans[0].extent_id;
        if plans.iter().any(|plan| plan.extent_id != extent_id) {
            return Err(ExtentError::MixedExtents);
        }
        if plans.len() > self.config.maximum_batch_records {
            return Err(ExtentError::ReservationExceeded {
                records: plans.len(),
                bytes: plans
                    .iter()
                    .map(|plan| plan.payload.encoded_len() as u64)
                    .sum(),
            });
        }
        let encoded_bytes = plans
            .iter()
            .map(|plan| plan.payload.encoded_len() as u64)
            .sum::<u64>();
        if encoded_bytes > self.config.maximum_batch_bytes {
            return Err(ExtentError::ReservationExceeded {
                records: plans.len(),
                bytes: encoded_bytes,
            });
        }
        let handle = self.handle(extent_id)?;
        let mut state = handle.state.lock().map_err(|_| ExtentError::LockPoisoned)?;
        if state.sealed {
            return Err(ExtentError::Sealed(extent_id));
        }
        let batch_id = state.next_batch_id;
        let first_index = state.records.len() as u64;
        let mut headers = Vec::with_capacity(plans.len() + 1);
        let mut physical_checksums = Vec::with_capacity(plans.len());
        let mut padded_lengths = Vec::with_capacity(plans.len());
        let mut cursor = state.committed_end;
        let mut locations = Vec::with_capacity(plans.len());
        let mut digest = blake3::Hasher::new();
        for (position, plan) in plans.iter().enumerate() {
            let checksum = chain_crc32c(&plan.payload);
            validate_declared_checksum(plan, checksum)?;
            let encoded_len = plan.payload.encoded_len() as u64;
            let padded_len = align_up_u64(encoded_len, self.config.alignment as u64);
            let record_index = first_index + position as u64;
            let payload_offset = cursor + self.config.alignment as u64;
            let header = encode_record_header(
                self.config.alignment,
                RECORD_DATA,
                batch_id,
                record_index,
                &plan.record_id,
                plan.logical_len,
                encoded_len,
                padded_len,
                checksum,
                plan.metadata,
                None,
            )?;
            update_batch_digest(
                &mut digest,
                record_index,
                &plan.record_id,
                plan.logical_len,
                encoded_len,
                checksum,
            );
            headers.push(header);
            physical_checksums.push(Checksum::Crc32c(checksum));
            padded_lengths.push(padded_len);
            locations.push(RecordLocation {
                inspection: RecordInspection {
                    record_id: plan.record_id.clone(),
                    record_index,
                    payload_offset,
                    encoded_len,
                    logical_len: plan.logical_len,
                    checksum: Checksum::Crc32c(checksum),
                    metadata: plan.metadata,
                },
                batch_end: 0,
            });
            cursor = payload_offset + padded_len;
        }
        let batch_digest = *digest.finalize().as_bytes();
        headers.push(encode_record_header(
            self.config.alignment,
            RECORD_COMMIT,
            batch_id,
            plans.len() as u64,
            &RecordId(vec![b'c']),
            plans.len() as u64,
            0,
            0,
            0,
            RecordMetadata::default(),
            Some(batch_digest),
        )?);
        cursor += self.config.alignment as u64;
        for location in &mut locations {
            location.batch_end = cursor;
        }
        if cursor > self.config.maximum_extent_bytes {
            return Err(ExtentError::CapacityExceeded {
                end: cursor,
                maximum: self.config.maximum_extent_bytes,
            });
        }

        write_batch_vectored(
            &handle.file,
            state.committed_end,
            &headers,
            &plans,
            &padded_lengths,
            self.config.alignment,
            &handle.path,
        )?;
        let durability = self.make_durable(
            &handle,
            extent_id,
            encoded_bytes,
            DurabilityClass::LocalDurable,
        )?;
        state.committed_end = cursor;
        state.next_batch_id = state.next_batch_id.saturating_add(1);
        state.records.extend(locations);

        self.metrics
            .appended_records
            .fetch_add(plans.len() as u64, Ordering::Relaxed);
        self.metrics
            .appended_bytes
            .fetch_add(encoded_bytes, Ordering::Relaxed);
        observe_current_stage(OperationStage::Storage);
        add_current_cost(CostMetric::StorageOperations, plans.len() as u64);
        add_current_cost(CostMetric::StorageBytes, encoded_bytes);

        Ok(plans
            .into_iter()
            .enumerate()
            .map(|(position, plan)| {
                let location = &state.records[first_index as usize + position];
                AppendReceipt {
                    extent_id,
                    record_id: plan.record_id,
                    record_index: location.inspection.record_index,
                    payload_offset: location.inspection.payload_offset,
                    encoded_len: location.inspection.encoded_len,
                    logical_len: location.inspection.logical_len,
                    checksum: physical_checksums[position],
                    durability: durability.clone(),
                }
            })
            .collect())
    }

    fn make_durable(
        &self,
        handle: &ExtentHandle,
        _extent_id: ExtentId,
        bytes: u64,
        class: DurabilityClass,
    ) -> Result<DurabilityReceipt, ExtentError> {
        let device = handle
            .file
            .metadata()
            .map_err(|source| ExtentError::Io {
                path: handle.path.display().to_string(),
                source,
            })?
            .dev();
        let target = Arc::new(FileDeviceBarrier {
            device: DeviceId(device),
            file: Arc::clone(&handle.file),
        });
        let mut request = DurabilityRequest::local_durable(
            // Per-extent mutexes preserve record order. Independent extents
            // therefore share this physical append ordering class and can
            // safely join one device-wide barrier.
            OrderingKey(u64::from_le_bytes(*b"extent01")),
            bytes,
            vec![target],
        );
        request.class = class;
        request.maximum_group_delay = self.config.group_commit_delay;
        request.priority = Priority::Foreground;
        self.durability
            .submit(request)
            .map_err(|error| ExtentError::Durability(error.to_string()))
    }

    #[cfg(test)]
    fn append_uncommitted_for_test(&self, plan: AppendPlan) -> Result<(), ExtentError> {
        let handle = self.handle(plan.extent_id)?;
        let state = handle.state.lock().map_err(|_| ExtentError::LockPoisoned)?;
        let checksum = chain_crc32c(&plan.payload);
        let padded_len = align_up_u64(
            plan.payload.encoded_len() as u64,
            self.config.alignment as u64,
        );
        let header = encode_record_header(
            self.config.alignment,
            RECORD_DATA,
            state.next_batch_id,
            state.records.len() as u64,
            &plan.record_id,
            plan.logical_len,
            plan.payload.encoded_len() as u64,
            padded_len,
            checksum,
            plan.metadata,
            None,
        )?;
        write_batch_vectored(
            &handle.file,
            state.committed_end,
            &[header],
            &[plan],
            &[padded_len],
            self.config.alignment,
            &handle.path,
        )
    }
}

impl ExtentStore for FileExtentStore {
    fn create(&self) -> Result<ExtentId, ExtentError> {
        let sequence = self.next_id.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut material = [0u8; 24];
        material[..16].copy_from_slice(&now.to_le_bytes());
        material[16..].copy_from_slice(&sequence.to_le_bytes());
        let digest = blake3::hash(&material);
        let id = ExtentId::from_bytes(digest.as_bytes()[..16].try_into().expect("fixed digest"));
        let path = self.root.join(format!("{id}.extent"));
        let file = Arc::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|source| ExtentError::Io {
                    path: path.display().to_string(),
                    source,
                })?,
        );
        let header = extent_header(id, self.config.alignment)?;
        file.write_all_at(&header, 0)
            .map_err(|source| ExtentError::Io {
                path: path.display().to_string(),
                source,
            })?;
        let handle = Arc::new(ExtentHandle {
            path: path.clone(),
            file,
            state: Mutex::new(ExtentState {
                committed_end: self.config.alignment as u64,
                next_batch_id: 1,
                sealed: false,
                ignored_tail_bytes: 0,
                records: Vec::new(),
            }),
        });
        self.make_durable(
            &handle,
            id,
            header.len() as u64,
            DurabilityClass::LocalDurable,
        )?;
        self.extents
            .write()
            .map_err(|_| ExtentError::LockPoisoned)?
            .insert(id, handle);
        Ok(id)
    }

    fn extent_ids(&self) -> Result<Vec<ExtentId>, ExtentError> {
        let mut ids = self
            .extents
            .read()
            .map_err(|_| ExtentError::LockPoisoned)?
            .keys()
            .copied()
            .collect::<Vec<_>>();
        ids.sort();
        Ok(ids)
    }

    fn reclaim(&self, extent_id: ExtentId) -> Result<(), ExtentError> {
        let mut extents = self
            .extents
            .write()
            .map_err(|_| ExtentError::LockPoisoned)?;
        let handle = extents
            .remove(&extent_id)
            .ok_or(ExtentError::NotFound(extent_id))?;
        let sealed = handle
            .state
            .lock()
            .map_err(|_| ExtentError::LockPoisoned)?
            .sealed;
        if !sealed {
            extents.insert(extent_id, handle);
            return Err(ExtentError::ActiveExtent(extent_id));
        }
        // The catalog reference and this local reference are the only normal
        // owners. Any additional reference is a read/inspection lease.
        if Arc::strong_count(&handle) != 1 {
            extents.insert(extent_id, handle);
            return Err(ExtentError::ExtentLeased(extent_id));
        }
        if let Err(source) = fs::remove_file(&handle.path) {
            let path = handle.path.display().to_string();
            extents.insert(extent_id, handle);
            return Err(ExtentError::Io { path, source });
        }
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| ExtentError::Io {
                path: self.root.display().to_string(),
                source,
            })?;
        Ok(())
    }

    fn reserve(
        &self,
        extent_id: ExtentId,
        maximum_records: usize,
        maximum_bytes: u64,
    ) -> Result<AppendReservation, ExtentError> {
        let handle = self.handle(extent_id)?;
        if handle
            .state
            .lock()
            .map_err(|_| ExtentError::LockPoisoned)?
            .sealed
        {
            return Err(ExtentError::Sealed(extent_id));
        }
        if maximum_records == 0
            || maximum_records > self.config.maximum_batch_records
            || maximum_bytes == 0
            || maximum_bytes > self.config.maximum_batch_bytes
        {
            return Err(ExtentError::ReservationExceeded {
                records: maximum_records,
                bytes: maximum_bytes,
            });
        }
        let token = self.next_reservation.fetch_add(1, Ordering::Relaxed);
        self.reservations
            .lock()
            .map_err(|_| ExtentError::LockPoisoned)?
            .insert(
                token,
                ReservationState {
                    extent_id,
                    maximum_records,
                    maximum_bytes,
                },
            );
        Ok(AppendReservation {
            token,
            extent_id,
            maximum_records,
            maximum_bytes,
        })
    }

    fn commit(
        &self,
        reservation: AppendReservation,
        plans: Vec<AppendPlan>,
    ) -> Result<Vec<AppendReceipt>, ExtentError> {
        let state = self
            .reservations
            .lock()
            .map_err(|_| ExtentError::LockPoisoned)?
            .remove(&reservation.token)
            .ok_or(ExtentError::InvalidReservation)?;
        let bytes = plans
            .iter()
            .map(|plan| plan.payload.encoded_len() as u64)
            .sum();
        if state.extent_id != reservation.extent_id
            || plans.iter().any(|plan| plan.extent_id != state.extent_id)
            || plans.len() > state.maximum_records
            || bytes > state.maximum_bytes
        {
            return Err(ExtentError::ReservationExceeded {
                records: plans.len(),
                bytes,
            });
        }
        self.append_internal(plans)
    }

    fn append(&self, plan: AppendPlan) -> Result<AppendReceipt, ExtentError> {
        self.append_internal(vec![plan])?
            .pop()
            .ok_or(ExtentError::EmptyBatch)
    }

    fn append_batch(&self, plans: Vec<AppendPlan>) -> Result<Vec<AppendReceipt>, ExtentError> {
        self.append_internal(plans)
    }

    fn read_range(&self, request: RangeRead) -> Result<OwnedBuffer, ExtentError> {
        let handle = self.handle(request.extent_id)?;
        let (payload_offset, encoded_len, checksum) = {
            let state = handle.state.lock().map_err(|_| ExtentError::LockPoisoned)?;
            let record = state.records.get(request.record_index as usize).ok_or(
                ExtentError::RecordNotFound {
                    extent_id: request.extent_id,
                    record_index: request.record_index,
                },
            )?;
            (
                record.inspection.payload_offset,
                record.inspection.encoded_len,
                record.inspection.checksum,
            )
        };
        let end = request.offset.saturating_add(request.length);
        if end > encoded_len {
            return Err(ExtentError::InvalidRange {
                offset: request.offset,
                end,
                length: encoded_len,
            });
        }
        let mut bytes = vec![0u8; request.length as usize];
        handle
            .file
            .read_exact_at(&mut bytes, payload_offset + request.offset)
            .map_err(|source| ExtentError::Io {
                path: handle.path.display().to_string(),
                source,
            })?;
        self.metrics.read_operations.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .read_bytes
            .fetch_add(request.length, Ordering::Relaxed);
        observe_current_stage(OperationStage::Storage);
        add_current_cost(CostMetric::StorageOperations, 1);
        add_current_cost(CostMetric::StorageBytes, request.length);
        let mut output = OwnedBuffer::from_vec(bytes);
        if request.offset == 0 && request.length == encoded_len {
            output = output.with_checksum(checksum);
        }
        Ok(output)
    }

    fn read_vectored(&self, requests: &[RangeRead]) -> Result<Vec<OwnedBuffer>, ExtentError> {
        requests
            .iter()
            .copied()
            .map(|request| self.read_range(request))
            .collect()
    }

    fn seal(&self, extent_id: ExtentId) -> Result<SealedExtent, ExtentError> {
        let handle = self.handle(extent_id)?;
        let mut state = handle.state.lock().map_err(|_| ExtentError::LockPoisoned)?;
        if state.sealed {
            return sealed_from_state(
                extent_id,
                &state,
                self.make_durable(&handle, extent_id, 0, DurabilityClass::LocalDurable)?,
            );
        }
        let digest = extent_digest(&state.records);
        let header = encode_record_header(
            self.config.alignment,
            RECORD_SEAL,
            state.next_batch_id,
            state.records.len() as u64,
            &RecordId(vec![b's']),
            state.records.len() as u64,
            0,
            0,
            0,
            RecordMetadata::default(),
            Some(digest),
        )?;
        handle
            .file
            .write_all_at(&header, state.committed_end)
            .map_err(|source| ExtentError::Io {
                path: handle.path.display().to_string(),
                source,
            })?;
        let durability = self.make_durable(
            &handle,
            extent_id,
            header.len() as u64,
            DurabilityClass::LocalDurable,
        )?;
        state.committed_end += self.config.alignment as u64;
        state.next_batch_id = state.next_batch_id.saturating_add(1);
        state.sealed = true;
        handle
            .file
            .set_len(state.committed_end)
            .map_err(|source| ExtentError::Io {
                path: handle.path.display().to_string(),
                source,
            })?;
        self.metrics.sealed_extents.fetch_add(1, Ordering::Relaxed);
        Ok(SealedExtent {
            extent_id,
            committed_len: state.committed_end,
            record_count: state.records.len() as u64,
            digest,
            durability,
        })
    }

    fn replace_sealed(
        &self,
        extent_id: ExtentId,
        records: Vec<ReplacementRecord>,
    ) -> Result<SealedExtent, ExtentError> {
        if records.is_empty() {
            return Err(ExtentError::EmptyBatch);
        }
        let old_handle = self.handle(extent_id)?;
        if !old_handle
            .state
            .lock()
            .map_err(|_| ExtentError::LockPoisoned)?
            .sealed
        {
            return Err(ExtentError::ActiveExtent(extent_id));
        }
        if Arc::strong_count(&old_handle) != 2 {
            return Err(ExtentError::ExtentLeased(extent_id));
        }

        let sequence = self.next_id.fetch_add(1, Ordering::Relaxed);
        let staging_name = format!(".replacement-{extent_id}-{sequence}");
        let staging_directory = self.root.join(&staging_name);
        let staging = FileExtentStore::open(&staging_directory, self.config)?;
        let new_extent = staging.create()?;
        for record in records {
            staging.append(AppendPlan {
                extent_id: new_extent,
                record_id: record.record_id,
                payload: record.payload,
                logical_len: record.logical_len,
                checksum: record.checksum,
                metadata: record.metadata,
            })?;
        }
        staging.seal(new_extent)?;
        drop(staging);

        let intent = ReplacementIntent {
            old_extent: extent_id,
            new_extent,
            staging_directory: staging_name,
        };
        let intent_path = self.root.join(format!(".replacement-{extent_id}.json"));
        let temporary_intent = intent_path.with_extension("tmp");
        let intent_bytes = serde_json::to_vec(&intent).map_err(|error| ExtentError::Corrupt {
            path: intent_path.display().to_string(),
            message: error.to_string(),
        })?;
        fs::write(&temporary_intent, intent_bytes).map_err(|source| ExtentError::Io {
            path: temporary_intent.display().to_string(),
            source,
        })?;
        File::open(&temporary_intent)
            .and_then(|file| file.sync_all())
            .map_err(|source| ExtentError::Io {
                path: temporary_intent.display().to_string(),
                source,
            })?;
        fs::rename(&temporary_intent, &intent_path).map_err(|source| ExtentError::Io {
            path: intent_path.display().to_string(),
            source,
        })?;
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| ExtentError::Io {
                path: self.root.display().to_string(),
                source,
            })?;

        let staged = staging_directory.join(format!("{new_extent}.extent"));
        let installed = self.root.join(format!("{new_extent}.extent"));
        fs::rename(&staged, &installed).map_err(|source| ExtentError::Io {
            path: staged.display().to_string(),
            source,
        })?;
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| ExtentError::Io {
                path: self.root.display().to_string(),
                source,
            })?;

        let file = Arc::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&installed)
                .map_err(|source| ExtentError::Io {
                    path: installed.display().to_string(),
                    source,
                })?,
        );
        let state = recover_file(new_extent, &installed, &file, self.config)?;
        let new_handle = Arc::new(ExtentHandle {
            path: installed,
            file,
            state: Mutex::new(state),
        });
        {
            let mut extents = self
                .extents
                .write()
                .map_err(|_| ExtentError::LockPoisoned)?;
            let removed = extents
                .remove(&extent_id)
                .ok_or(ExtentError::NotFound(extent_id))?;
            if Arc::strong_count(&removed) != 2 {
                extents.insert(extent_id, removed);
                return Err(ExtentError::ExtentLeased(extent_id));
            }
            extents.insert(new_extent, new_handle);
        }
        fs::remove_file(&old_handle.path).map_err(|source| ExtentError::Io {
            path: old_handle.path.display().to_string(),
            source,
        })?;
        if staging_directory.exists() {
            fs::remove_dir_all(&staging_directory).map_err(|source| ExtentError::Io {
                path: staging_directory.display().to_string(),
                source,
            })?;
        }
        fs::remove_file(&intent_path).map_err(|source| ExtentError::Io {
            path: intent_path.display().to_string(),
            source,
        })?;
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| ExtentError::Io {
                path: self.root.display().to_string(),
                source,
            })?;
        self.seal(new_extent)
    }

    fn rotate(&self, extent_id: ExtentId) -> Result<Rotation, ExtentError> {
        let sealed = self.seal(extent_id)?;
        let active = self.create()?;
        Ok(Rotation { sealed, active })
    }

    fn inspect(&self, extent_id: ExtentId) -> Result<ExtentInspection, ExtentError> {
        let handle = self.handle(extent_id)?;
        let state = handle.state.lock().map_err(|_| ExtentError::LockPoisoned)?;
        Ok(inspection_from_state(extent_id, &state))
    }

    fn recover(&self, extent_id: ExtentId) -> Result<ExtentInspection, ExtentError> {
        let handle = self.handle(extent_id)?;
        let recovered = recover_file(extent_id, &handle.path, &handle.file, self.config)?;
        let inspection = inspection_from_state(extent_id, &recovered);
        *handle.state.lock().map_err(|_| ExtentError::LockPoisoned)? = recovered;
        Ok(inspection)
    }

    fn truncate(
        &self,
        extent_id: ExtentId,
        record_count: u64,
    ) -> Result<ExtentInspection, ExtentError> {
        let handle = self.handle(extent_id)?;
        let mut state = handle.state.lock().map_err(|_| ExtentError::LockPoisoned)?;
        if state.sealed {
            return Err(ExtentError::Sealed(extent_id));
        }
        let keep = usize::try_from(record_count).map_err(|_| ExtentError::InvalidTruncation {
            extent_id,
            record_count,
        })?;
        if keep > state.records.len()
            || (keep > 0
                && keep < state.records.len()
                && state.records[keep - 1].batch_end == state.records[keep].batch_end)
        {
            return Err(ExtentError::InvalidTruncation {
                extent_id,
                record_count,
            });
        }
        let committed_end = if keep == 0 {
            self.config.alignment as u64
        } else {
            state.records[keep - 1].batch_end
        };
        handle
            .file
            .set_len(committed_end)
            .and_then(|()| handle.file.sync_data())
            .map_err(|source| ExtentError::Io {
                path: handle.path.display().to_string(),
                source,
            })?;
        state.records.truncate(keep);
        state.committed_end = committed_end;
        state.ignored_tail_bytes = 0;
        Ok(inspection_from_state(extent_id, &state))
    }
}

struct FileDeviceBarrier {
    device: DeviceId,
    file: Arc<File>,
}

impl BarrierTarget for FileDeviceBarrier {
    fn device_id(&self) -> DeviceId {
        self.device
    }

    fn description(&self) -> &str {
        "extent-device"
    }

    fn barrier(&self) -> Result<(), String> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        rustix::fs::syncfs(&self.file).map_err(|error| error.to_string())?;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        self.file.sync_data().map_err(|error| error.to_string())?;
        Ok(())
    }
}

fn validate_config(config: FileExtentConfig) -> Result<(), ExtentError> {
    if config.alignment < FIXED_HEADER_BYTES
        || !config.alignment.is_power_of_two()
        || config.maximum_extent_bytes < config.alignment as u64 * 3
        || config.maximum_batch_bytes == 0
        || config.maximum_batch_records == 0
        || config.group_commit_max_requests == 0
    {
        return Err(ExtentError::InvalidConfiguration(format!("{config:?}")));
    }
    Ok(())
}

fn extent_header(id: ExtentId, alignment: usize) -> Result<Vec<u8>, ExtentError> {
    let mut header = vec![0u8; alignment];
    header[..8].copy_from_slice(EXTENT_MAGIC);
    header[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    header[16..32].copy_from_slice(id.as_bytes());
    header[32..40].copy_from_slice(&(alignment as u64).to_le_bytes());
    let crc = crc32c::crc32c(&header[..alignment - 4]);
    header[alignment - 4..].copy_from_slice(&crc.to_le_bytes());
    Ok(header)
}

#[allow(clippy::too_many_arguments)]
fn encode_record_header(
    alignment: usize,
    kind: u8,
    batch_id: u64,
    record_index: u64,
    record_id: &RecordId,
    logical_len: u64,
    encoded_len: u64,
    padded_len: u64,
    payload_crc: u32,
    metadata: RecordMetadata,
    digest: Option<[u8; 32]>,
) -> Result<Vec<u8>, ExtentError> {
    if record_id.as_bytes().len() > alignment.saturating_sub(FIXED_HEADER_BYTES) {
        return Err(ExtentError::InvalidRecordIdLength(
            record_id.as_bytes().len(),
        ));
    }
    let mut header = vec![0u8; alignment];
    header[..8].copy_from_slice(RECORD_MAGIC);
    header[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    header[10] = kind;
    header[11] = metadata_flags(metadata);
    header[12..14].copy_from_slice(&(record_id.as_bytes().len() as u16).to_le_bytes());
    header[16..24].copy_from_slice(&batch_id.to_le_bytes());
    header[24..32].copy_from_slice(&record_index.to_le_bytes());
    header[32..40].copy_from_slice(&logical_len.to_le_bytes());
    header[40..48].copy_from_slice(&encoded_len.to_le_bytes());
    header[48..56].copy_from_slice(&padded_len.to_le_bytes());
    header[56..60].copy_from_slice(&payload_crc.to_le_bytes());
    if let Some(digest) = digest {
        header[60..92].copy_from_slice(&digest);
    }
    header[FIXED_HEADER_BYTES..FIXED_HEADER_BYTES + record_id.as_bytes().len()]
        .copy_from_slice(record_id.as_bytes());
    let crc = crc32c::crc32c(&header[..alignment - 4]);
    header[alignment - 4..].copy_from_slice(&crc.to_le_bytes());
    Ok(header)
}

fn metadata_flags(metadata: RecordMetadata) -> u8 {
    let compression = match metadata.compression {
        Compression::None => 0,
        Compression::Zstd => 1,
    };
    let encryption = match metadata.encryption {
        Encryption::None => 0,
        Encryption::Aes256Gcm => 1,
    };
    let storage = match metadata.storage_class {
        StorageClass::Hot => 0,
        StorageClass::Warm => 1,
        StorageClass::Cold => 2,
    };
    compression | (encryption << 2) | (storage << 4) | (u8::from(metadata.live) << 7)
}

fn parse_metadata_flags(flags: u8) -> Result<RecordMetadata, String> {
    let compression = match flags & 0b11 {
        0 => Compression::None,
        1 => Compression::Zstd,
        _ => return Err("unknown compression flag".to_string()),
    };
    let encryption = match (flags >> 2) & 0b11 {
        0 => Encryption::None,
        1 => Encryption::Aes256Gcm,
        _ => return Err("unknown encryption flag".to_string()),
    };
    let storage_class = match (flags >> 4) & 0b111 {
        0 => StorageClass::Hot,
        1 => StorageClass::Warm,
        2 => StorageClass::Cold,
        _ => return Err("unknown storage-class flag".to_string()),
    };
    Ok(RecordMetadata {
        compression,
        encryption,
        storage_class,
        live: flags & 0x80 != 0,
    })
}

struct ParsedHeader {
    kind: u8,
    metadata: RecordMetadata,
    batch_id: u64,
    record_index: u64,
    record_id: RecordId,
    logical_len: u64,
    encoded_len: u64,
    padded_len: u64,
    payload_crc: u32,
    digest: [u8; 32],
}

fn parse_record_header(header: &[u8], alignment: usize) -> Result<ParsedHeader, String> {
    if header.len() != alignment || &header[..8] != RECORD_MAGIC {
        return Err("record magic mismatch".to_string());
    }
    if u16::from_le_bytes(header[8..10].try_into().expect("fixed")) != FORMAT_VERSION {
        return Err("record version mismatch".to_string());
    }
    let expected = u32::from_le_bytes(header[alignment - 4..].try_into().expect("fixed checksum"));
    if crc32c::crc32c(&header[..alignment - 4]) != expected {
        return Err("record header checksum mismatch".to_string());
    }
    let id_len = u16::from_le_bytes(header[12..14].try_into().expect("fixed")) as usize;
    if id_len == 0 || id_len > MAX_RECORD_ID_BYTES || FIXED_HEADER_BYTES + id_len > alignment - 4 {
        return Err("record ID length is invalid".to_string());
    }
    Ok(ParsedHeader {
        kind: header[10],
        metadata: parse_metadata_flags(header[11])?,
        batch_id: u64::from_le_bytes(header[16..24].try_into().expect("fixed")),
        record_index: u64::from_le_bytes(header[24..32].try_into().expect("fixed")),
        record_id: RecordId(header[FIXED_HEADER_BYTES..FIXED_HEADER_BYTES + id_len].to_vec()),
        logical_len: u64::from_le_bytes(header[32..40].try_into().expect("fixed")),
        encoded_len: u64::from_le_bytes(header[40..48].try_into().expect("fixed")),
        padded_len: u64::from_le_bytes(header[48..56].try_into().expect("fixed")),
        payload_crc: u32::from_le_bytes(header[56..60].try_into().expect("fixed")),
        digest: header[60..92].try_into().expect("fixed"),
    })
}

fn write_batch_vectored(
    file: &File,
    offset: u64,
    headers: &[Vec<u8>],
    plans: &[AppendPlan],
    padded_lengths: &[u64],
    alignment: usize,
    path: &Path,
) -> Result<(), ExtentError> {
    let zeroes = vec![0u8; alignment];
    let mut slices = Vec::new();
    for (index, plan) in plans.iter().enumerate() {
        slices.push(IoSlice::new(&headers[index]));
        slices.extend(plan.payload.io_slices());
        let padding = padded_lengths[index] as usize - plan.payload.encoded_len();
        if padding > 0 {
            slices.push(IoSlice::new(&zeroes[..padding]));
        }
    }
    if headers.len() > plans.len() {
        slices.push(IoSlice::new(&headers[headers.len() - 1]));
    }
    let mut writer = file;
    writer
        .seek(SeekFrom::Start(offset))
        .map_err(|source| ExtentError::Io {
            path: path.display().to_string(),
            source,
        })?;
    let mut remaining = slices.as_mut_slice();
    while !remaining.is_empty() {
        let written = writer
            .write_vectored(remaining)
            .map_err(|source| ExtentError::Io {
                path: path.display().to_string(),
                source,
            })?;
        if written == 0 {
            return Err(ExtentError::Io {
                path: path.display().to_string(),
                source: std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "vectored extent append made no progress",
                ),
            });
        }
        IoSlice::advance_slices(&mut remaining, written);
    }
    Ok(())
}

fn recover_file(
    id: ExtentId,
    path: &Path,
    file: &File,
    config: FileExtentConfig,
) -> Result<ExtentState, ExtentError> {
    let file_len = file
        .metadata()
        .map_err(|source| ExtentError::Io {
            path: path.display().to_string(),
            source,
        })?
        .len();
    let mut extent_header_bytes = vec![0u8; config.alignment];
    file.read_exact_at(&mut extent_header_bytes, 0)
        .map_err(|source| ExtentError::Io {
            path: path.display().to_string(),
            source,
        })?;
    validate_extent_header(id, &extent_header_bytes, config.alignment).map_err(|message| {
        ExtentError::Corrupt {
            path: path.display().to_string(),
            message,
        }
    })?;
    let mut offset = config.alignment as u64;
    let mut committed_end = offset;
    let mut next_batch_id = 1u64;
    let mut records = Vec::new();
    let mut pending = BTreeMap::<u64, Vec<RecordLocation>>::new();
    let mut sealed = false;
    while offset + config.alignment as u64 <= file_len {
        let mut header = vec![0u8; config.alignment];
        if file.read_exact_at(&mut header, offset).is_err() {
            break;
        }
        let parsed = match parse_record_header(&header, config.alignment) {
            Ok(parsed) => parsed,
            Err(_) => break,
        };
        next_batch_id = next_batch_id.max(parsed.batch_id.saturating_add(1));
        if parsed.kind == RECORD_DATA {
            if parsed.encoded_len > parsed.padded_len
                || parsed.padded_len % config.alignment as u64 != 0
                || offset
                    .saturating_add(config.alignment as u64)
                    .saturating_add(parsed.padded_len)
                    > file_len
            {
                break;
            }
            let payload_offset = offset + config.alignment as u64;
            let mut payload = vec![0u8; parsed.encoded_len as usize];
            if file.read_exact_at(&mut payload, payload_offset).is_err()
                || crc32c::crc32c(&payload) != parsed.payload_crc
            {
                break;
            }
            pending
                .entry(parsed.batch_id)
                .or_default()
                .push(RecordLocation {
                    inspection: RecordInspection {
                        record_id: parsed.record_id,
                        record_index: parsed.record_index,
                        payload_offset,
                        encoded_len: parsed.encoded_len,
                        logical_len: parsed.logical_len,
                        checksum: Checksum::Crc32c(parsed.payload_crc),
                        metadata: parsed.metadata,
                    },
                    batch_end: 0,
                });
            offset = payload_offset + parsed.padded_len;
        } else if parsed.kind == RECORD_COMMIT {
            let Some(mut batch) = pending.remove(&parsed.batch_id) else {
                break;
            };
            if batch.len() as u64 != parsed.logical_len || extent_digest(&batch) != parsed.digest {
                break;
            }
            offset += config.alignment as u64;
            committed_end = offset;
            for location in &mut batch {
                location.batch_end = committed_end;
            }
            records.extend(batch);
        } else if parsed.kind == RECORD_SEAL {
            if !pending.is_empty()
                || parsed.record_index != records.len() as u64
                || extent_digest(&records) != parsed.digest
            {
                break;
            }
            offset += config.alignment as u64;
            committed_end = offset;
            sealed = true;
            break;
        } else {
            break;
        }
    }
    let ignored_tail_bytes = file_len.saturating_sub(committed_end);
    if ignored_tail_bytes > 0 {
        file.set_len(committed_end)
            .and_then(|()| file.sync_data())
            .map_err(|source| ExtentError::Io {
                path: path.display().to_string(),
                source,
            })?;
    }
    Ok(ExtentState {
        committed_end,
        next_batch_id,
        sealed,
        ignored_tail_bytes,
        records,
    })
}

fn validate_extent_header(id: ExtentId, header: &[u8], alignment: usize) -> Result<(), String> {
    if header.len() != alignment || &header[..8] != EXTENT_MAGIC {
        return Err("extent magic mismatch".to_string());
    }
    if u16::from_le_bytes(header[8..10].try_into().expect("fixed")) != FORMAT_VERSION {
        return Err("extent version mismatch".to_string());
    }
    if &header[16..32] != id.as_bytes() {
        return Err("extent identity mismatch".to_string());
    }
    if u64::from_le_bytes(header[32..40].try_into().expect("fixed")) != alignment as u64 {
        return Err("extent alignment mismatch".to_string());
    }
    let expected = u32::from_le_bytes(header[alignment - 4..].try_into().expect("fixed"));
    if crc32c::crc32c(&header[..alignment - 4]) != expected {
        return Err("extent header checksum mismatch".to_string());
    }
    Ok(())
}

fn validate_declared_checksum(plan: &AppendPlan, crc: u32) -> Result<(), ExtentError> {
    match plan.checksum {
        None => Ok(()),
        Some(Checksum::Crc32c(expected)) if expected == crc => Ok(()),
        Some(Checksum::Crc32c(_)) => Err(ExtentError::ChecksumMismatch(plan.record_id.clone())),
        Some(Checksum::Blake3(expected)) => {
            let mut hasher = blake3::Hasher::new();
            for segment in plan.payload.segments() {
                hasher.update(segment.bytes());
            }
            if hasher.finalize().as_bytes() == &expected {
                Ok(())
            } else {
                Err(ExtentError::ChecksumMismatch(plan.record_id.clone()))
            }
        }
    }
}

fn chain_crc32c(chain: &BufferChain) -> u32 {
    chain.segments().iter().fold(0, |crc, segment| {
        crc32c::crc32c_append(crc, segment.bytes())
    })
}

fn update_batch_digest(
    digest: &mut blake3::Hasher,
    index: u64,
    id: &RecordId,
    logical_len: u64,
    encoded_len: u64,
    crc: u32,
) {
    digest.update(&index.to_le_bytes());
    digest.update(&(id.as_bytes().len() as u64).to_le_bytes());
    digest.update(id.as_bytes());
    digest.update(&logical_len.to_le_bytes());
    digest.update(&encoded_len.to_le_bytes());
    digest.update(&crc.to_le_bytes());
}

fn extent_digest(records: &[RecordLocation]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    for record in records {
        let crc = match record.inspection.checksum {
            Checksum::Crc32c(crc) => crc,
            Checksum::Blake3(_) => 0,
        };
        update_batch_digest(
            &mut digest,
            record.inspection.record_index,
            &record.inspection.record_id,
            record.inspection.logical_len,
            record.inspection.encoded_len,
            crc,
        );
    }
    *digest.finalize().as_bytes()
}

fn inspection_from_state(id: ExtentId, state: &ExtentState) -> ExtentInspection {
    ExtentInspection {
        extent_id: id,
        committed_end: state.committed_end,
        sealed: state.sealed,
        digest: state.sealed.then(|| extent_digest(&state.records)),
        ignored_tail_bytes: state.ignored_tail_bytes,
        records: state
            .records
            .iter()
            .map(|record| record.inspection.clone())
            .collect(),
    }
}

fn sealed_from_state(
    id: ExtentId,
    state: &ExtentState,
    durability: DurabilityReceipt,
) -> Result<SealedExtent, ExtentError> {
    Ok(SealedExtent {
        extent_id: id,
        committed_len: state.committed_end,
        record_count: state.records.len() as u64,
        digest: extent_digest(&state.records),
        durability,
    })
}

fn parse_extent_filename(path: &Path) -> Result<ExtentId, ExtentError> {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| ExtentError::Corrupt {
            path: path.display().to_string(),
            message: "extent filename is not UTF-8".to_string(),
        })?;
    let bytes = hex::decode(stem).map_err(|error| ExtentError::Corrupt {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    let id = bytes.try_into().map_err(|_| ExtentError::Corrupt {
        path: path.display().to_string(),
        message: "extent filename must contain a 128-bit ID".to_string(),
    })?;
    Ok(ExtentId::from_bytes(id))
}

fn align_up_u64(value: u64, alignment: u64) -> u64 {
    value
        .saturating_add(alignment.saturating_sub(1))
        .checked_div(alignment)
        .unwrap_or(0)
        .saturating_mul(alignment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn plan(id: ExtentId, record: &[u8], segments: &[&'static [u8]]) -> AppendPlan {
        let payload = BufferChain::from_segments(
            segments
                .iter()
                .map(|bytes| OwnedBuffer::new(Bytes::from_static(bytes))),
        )
        .unwrap();
        AppendPlan::new(id, RecordId::new(record.to_vec()).unwrap(), payload)
    }

    #[test]
    fn append_batch_range_read_seal_rotate_and_inspection() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileExtentStore::open(directory.path(), FileExtentConfig::default()).unwrap();
        let extent = store.create().unwrap();
        let reservation = store.reserve(extent, 2, 1024).unwrap();
        let receipts = store
            .commit(
                reservation,
                vec![
                    plan(extent, b"first", &[b"ab", b"cd"]),
                    plan(extent, b"second", &[b"efgh"]),
                ],
            )
            .unwrap();
        assert_eq!(receipts.len(), 2);
        let range = store
            .read_range(RangeRead {
                extent_id: extent,
                record_index: 0,
                offset: 1,
                length: 2,
            })
            .unwrap();
        assert_eq!(range.bytes(), b"bc".as_slice());
        let vectored = store
            .read_vectored(&[
                RangeRead {
                    extent_id: extent,
                    record_index: 0,
                    offset: 0,
                    length: 4,
                },
                RangeRead {
                    extent_id: extent,
                    record_index: 1,
                    offset: 0,
                    length: 4,
                },
            ])
            .unwrap();
        assert_eq!(vectored[0].bytes(), b"abcd".as_slice());
        assert_eq!(vectored[1].bytes(), b"efgh".as_slice());
        let rotation = store.rotate(extent).unwrap();
        assert_eq!(rotation.sealed.record_count, 2);
        assert_ne!(rotation.active, extent);
        assert!(matches!(
            store.append(plan(extent, b"third", &[b"no"])),
            Err(ExtentError::Sealed(id)) if id == extent
        ));
        let inspection = store.inspect(extent).unwrap();
        assert!(inspection.sealed);
        assert_eq!(
            inspection
                .records
                .iter()
                .map(|record| record.record_index)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
    }

    #[test]
    fn torn_tail_is_never_exposed_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let config = FileExtentConfig::default();
        let extent = {
            let store = FileExtentStore::open(directory.path(), config).unwrap();
            let extent = store.create().unwrap();
            store
                .append(plan(extent, b"committed", &[b"safe"]))
                .unwrap();
            store
                .append_uncommitted_for_test(plan(extent, b"abandoned", &[b"unsafe"]))
                .unwrap();
            extent
        };
        let reopened = FileExtentStore::open(directory.path(), config).unwrap();
        let inspection = reopened.inspect(extent).unwrap();
        assert_eq!(inspection.records.len(), 1);
        assert_eq!(inspection.records[0].record_id.as_bytes(), b"committed");
        assert!(inspection.ignored_tail_bytes > 0);
        reopened
            .append(plan(extent, b"after-recovery", &[b"new"]))
            .unwrap();
        assert_eq!(reopened.inspect(extent).unwrap().records.len(), 2);
    }

    #[test]
    fn truncation_requires_a_complete_append_batch_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let config = FileExtentConfig::default();
        let extent = {
            let store = FileExtentStore::open(directory.path(), config).unwrap();
            let extent = store.create().unwrap();
            store
                .append_batch(vec![
                    plan(extent, b"first", &[b"a"]),
                    plan(extent, b"second", &[b"b"]),
                ])
                .unwrap();
            store.append(plan(extent, b"third", &[b"c"])).unwrap();
            assert!(matches!(
                store.truncate(extent, 1),
                Err(ExtentError::InvalidTruncation { .. })
            ));
            assert_eq!(store.truncate(extent, 2).unwrap().records.len(), 2);
            extent
        };
        let reopened = FileExtentStore::open(directory.path(), config).unwrap();
        let inspection = reopened.inspect(extent).unwrap();
        assert_eq!(inspection.records.len(), 2);
        assert_eq!(
            reopened
                .read_range(RangeRead {
                    extent_id: extent,
                    record_index: 1,
                    offset: 0,
                    length: 1,
                })
                .unwrap()
                .bytes(),
            b"b".as_slice()
        );
    }

    #[test]
    fn recovery_is_deterministic_at_every_encoded_frame_boundary() {
        let source = tempfile::tempdir().unwrap();
        let config = FileExtentConfig::default();
        let extent = {
            let store = FileExtentStore::open(source.path(), config).unwrap();
            let extent = store.create().unwrap();
            for (id, bytes) in [
                (b"a".as_slice(), b"one".as_slice()),
                (b"b".as_slice(), b"two".as_slice()),
                (b"c".as_slice(), b"three".as_slice()),
            ] {
                let owned: &'static [u8] = Box::leak(bytes.to_vec().into_boxed_slice());
                store.append(plan(extent, id, &[owned])).unwrap();
            }
            extent
        };
        let filename = format!("{extent}.extent");
        let source_bytes = fs::read(source.path().join(&filename)).unwrap();
        let alignment = config.alignment as u64;
        assert_eq!(source_bytes.len() as u64, alignment * 10);

        for frame_boundary in 1u64..=10 {
            let directory = tempfile::tempdir().unwrap();
            let length = usize::try_from(frame_boundary * alignment).unwrap();
            fs::write(directory.path().join(&filename), &source_bytes[..length]).unwrap();
            let reopened = FileExtentStore::open(directory.path(), config).unwrap();
            let inspection = reopened.inspect(extent).unwrap();
            let expected_records = ((frame_boundary - 1) / 3).min(3) as usize;
            assert_eq!(
                inspection.records.len(),
                expected_records,
                "frame boundary {frame_boundary}"
            );
            assert_eq!(
                inspection.committed_end,
                alignment * (1 + expected_records as u64 * 3)
            );
        }
    }

    #[test]
    fn checksum_and_reservation_limits_are_enforced() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileExtentStore::open(directory.path(), FileExtentConfig::default()).unwrap();
        let extent = store.create().unwrap();
        let mut bad = plan(extent, b"bad", &[b"payload"]);
        bad.checksum = Some(Checksum::Crc32c(1));
        assert!(matches!(
            store.append(bad),
            Err(ExtentError::ChecksumMismatch(_))
        ));
        let reservation = store.reserve(extent, 1, 2).unwrap();
        assert!(matches!(
            store.commit(reservation, vec![plan(extent, b"large", &[b"three"])]),
            Err(ExtentError::ReservationExceeded { .. })
        ));
    }

    #[test]
    fn replacement_intent_recovers_before_and_after_install() {
        for install_before_reopen in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let config = FileExtentConfig::default();
            let old = {
                let store = FileExtentStore::open(directory.path(), config).unwrap();
                let old = store.create().unwrap();
                store.append(plan(old, b"old", &[b"old"])).unwrap();
                store.seal(old).unwrap();
                old
            };
            let staging_name = format!(".replacement-{old}-test");
            let staging_path = directory.path().join(&staging_name);
            let new = {
                let staging = FileExtentStore::open(&staging_path, config).unwrap();
                let new = staging.create().unwrap();
                staging.append(plan(new, b"new", &[b"new"])).unwrap();
                staging.seal(new).unwrap();
                new
            };
            let intent = ReplacementIntent {
                old_extent: old,
                new_extent: new,
                staging_directory: staging_name,
            };
            let intent_path = directory.path().join(format!(".replacement-{old}.json"));
            fs::write(&intent_path, serde_json::to_vec(&intent).unwrap()).unwrap();
            if install_before_reopen {
                fs::rename(
                    staging_path.join(format!("{new}.extent")),
                    directory.path().join(format!("{new}.extent")),
                )
                .unwrap();
            }
            let recovered = FileExtentStore::open(directory.path(), config).unwrap();
            assert_eq!(recovered.extent_ids().unwrap(), vec![new]);
            assert_eq!(
                recovered
                    .read_range(RangeRead {
                        extent_id: new,
                        record_index: 0,
                        offset: 0,
                        length: 3,
                    })
                    .unwrap()
                    .bytes(),
                b"new".as_slice()
            );
            assert!(!intent_path.exists());
            assert!(!staging_path.exists());
        }
    }

    #[test]
    fn independent_extents_share_a_device_barrier() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FileExtentStore::open(
                directory.path(),
                FileExtentConfig {
                    group_commit_delay: Duration::from_millis(20),
                    ..FileExtentConfig::default()
                },
            )
            .unwrap(),
        );
        let first = store.create().unwrap();
        let second = store.create().unwrap();
        let before = store.stats().device_queue;
        let start = Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for (extent, record) in [(first, b"first".as_slice()), (second, b"second".as_slice())] {
            let store = Arc::clone(&store);
            let start = Arc::clone(&start);
            workers.push(std::thread::spawn(move || {
                start.wait();
                store.append(plan(extent, record, &[b"payload"])).unwrap();
            }));
        }
        start.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        let after = store.stats().device_queue;
        assert_eq!(after.grouped_requests - before.grouped_requests, 2);
        assert_eq!(after.device_barriers - before.device_barriers, 1);
    }
}
