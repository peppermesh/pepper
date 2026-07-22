// SPDX-License-Identifier: Apache-2.0

//! Linux-oriented append-only segment engine.
//!
//! A segment is a sequence of aligned data/tombstone records followed by a
//! commit record. Recovery exposes only batches with a valid commit digest;
//! an interrupted tail is ignored. Each CID maps to one owner shard, giving
//! every shard its own writer and submission ring. Independent owner writes
//! join a bounded device-level group durability barrier before publication.

use super::*;
use pepper_config::NativeStorageConfig;
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    collections::{BTreeMap, HashMap, HashSet},
    fs::{File, OpenOptions},
    io,
    ptr::NonNull,
    sync::{RwLock, Weak, mpsc},
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use io_uring::{IoUring, opcode, squeue, types};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, OpenOptionsExt};

const ALIGNMENT: usize = 4096;
const SEGMENT_HEADER_BYTES: usize = ALIGNMENT;
const RECORD_HEADER_BYTES: usize = ALIGNMENT;
const SEGMENT_MAGIC: &[u8; 8] = b"PEPNVME1";
const RECORD_MAGIC: &[u8; 8] = b"PEPNVREC";
const FORMAT_VERSION: u16 = 1;
const RECORD_DATA: u8 = 1;
const RECORD_TOMBSTONE: u8 = 2;
const RECORD_COMMIT: u8 = 3;
const MAX_CID_BYTES: usize = 512;

static NATIVE_WRITES: AtomicU64 = AtomicU64::new(0);
static NATIVE_WRITE_BYTES: AtomicU64 = AtomicU64::new(0);
static NATIVE_READS: AtomicU64 = AtomicU64::new(0);
static NATIVE_READ_BYTES: AtomicU64 = AtomicU64::new(0);
static NATIVE_DURABILITY_BARRIERS: AtomicU64 = AtomicU64::new(0);
static NATIVE_DURABILITY_GROUPS: AtomicU64 = AtomicU64::new(0);
static NATIVE_DURABILITY_GROUP_REQUESTS: AtomicU64 = AtomicU64::new(0);
static NATIVE_URING_SUBMISSIONS: AtomicU64 = AtomicU64::new(0);
static NATIVE_SYNC_FALLBACKS: AtomicU64 = AtomicU64::new(0);
static NATIVE_RECOVERED_RECORDS: AtomicU64 = AtomicU64::new(0);
static NATIVE_TORN_TAILS: AtomicU64 = AtomicU64::new(0);
static NATIVE_COMPACTIONS: AtomicU64 = AtomicU64::new(0);
static NATIVE_COMPACTED_BYTES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeStats {
    pub writes: u64,
    pub write_bytes: u64,
    pub reads: u64,
    pub read_bytes: u64,
    pub durability_barriers: u64,
    pub durability_groups: u64,
    pub durability_group_requests: u64,
    pub uring_submissions: u64,
    pub sync_fallbacks: u64,
    pub recovered_records: u64,
    pub torn_tails: u64,
    pub compactions: u64,
    pub compacted_bytes: u64,
}

pub(crate) fn stats() -> NativeStats {
    NativeStats {
        writes: NATIVE_WRITES.load(Ordering::Relaxed),
        write_bytes: NATIVE_WRITE_BYTES.load(Ordering::Relaxed),
        reads: NATIVE_READS.load(Ordering::Relaxed),
        read_bytes: NATIVE_READ_BYTES.load(Ordering::Relaxed),
        durability_barriers: NATIVE_DURABILITY_BARRIERS.load(Ordering::Relaxed),
        durability_groups: NATIVE_DURABILITY_GROUPS.load(Ordering::Relaxed),
        durability_group_requests: NATIVE_DURABILITY_GROUP_REQUESTS.load(Ordering::Relaxed),
        uring_submissions: NATIVE_URING_SUBMISSIONS.load(Ordering::Relaxed),
        sync_fallbacks: NATIVE_SYNC_FALLBACKS.load(Ordering::Relaxed),
        recovered_records: NATIVE_RECOVERED_RECORDS.load(Ordering::Relaxed),
        torn_tails: NATIVE_TORN_TAILS.load(Ordering::Relaxed),
        compactions: NATIVE_COMPACTIONS.load(Ordering::Relaxed),
        compacted_bytes: NATIVE_COMPACTED_BYTES.load(Ordering::Relaxed),
    }
}

#[derive(Clone)]
struct SegmentHandle {
    path: PathBuf,
    file: Arc<File>,
    generation: u64,
    segment_id: u64,
}

#[derive(Clone)]
struct RecordLocation {
    cid: Cid,
    logical_size: u64,
    stored_size: u64,
    payload_offset: u64,
    padded_size: u64,
    owner: usize,
    location_index: usize,
    segment: SegmentHandle,
}

#[derive(Debug, Clone)]
pub(crate) struct NativeRecord {
    pub cid: Cid,
    pub logical_size: u64,
    pub stored_size: u64,
    pub owner: usize,
    pub location_index: usize,
    pub generation: u64,
    pub segment_id: u64,
    pub payload_offset: u64,
    pub already_existed: bool,
}

impl From<&RecordLocation> for NativeRecord {
    fn from(value: &RecordLocation) -> Self {
        Self::from_location(value, false)
    }
}

impl NativeRecord {
    fn from_location(value: &RecordLocation, already_existed: bool) -> Self {
        Self {
            cid: value.cid.clone(),
            logical_size: value.logical_size,
            stored_size: value.stored_size,
            owner: value.owner,
            location_index: value.location_index,
            generation: value.segment.generation,
            segment_id: value.segment.segment_id,
            payload_offset: value.payload_offset,
            already_existed,
        }
    }
}

struct SegmentWriter {
    handle: SegmentHandle,
    offset: u64,
    location_index: usize,
}

struct OwnerState {
    /// Serializes log rewrites with foreground mutations for this owner. Reads
    /// remain lock-free apart from the owner's submission queue.
    maintenance: Mutex<()>,
    writer: Mutex<Option<SegmentWriter>>,
    io: Mutex<SubmissionBackend>,
}

struct NativeInner {
    locations: Arc<Vec<StorageLocationRuntime>>,
    config: NativeStorageConfig,
    segment_directory: String,
    owners: Vec<OwnerState>,
    index: RwLock<HashMap<Cid, RecordLocation>>,
    next_generation: AtomicU64,
    next_segment_id: AtomicU64,
    live_bytes: AtomicU64,
    dead_bytes: AtomicU64,
    #[cfg(test)]
    device_barriers: Arc<AtomicU64>,
    durability: mpsc::SyncSender<DurabilityRequest>,
    allocated_by_location: Vec<AtomicU64>,
}

struct DurabilityRequest {
    files: Vec<(i32, Arc<File>)>,
    result: mpsc::SyncSender<Result<(), String>>,
}

#[derive(Clone)]
pub(crate) struct NativeEngine {
    inner: Arc<NativeInner>,
    compact: mpsc::SyncSender<()>,
}

impl NativeEngine {
    pub(crate) fn open(
        locations: Arc<Vec<StorageLocationRuntime>>,
        config: NativeStorageConfig,
        segment_directory: &str,
        thread_name: &str,
    ) -> Result<Self, StorageError> {
        if segment_directory.is_empty()
            || !segment_directory
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(StorageError::Native(
                "native segment directory must be a safe relative name".to_string(),
            ));
        }
        let owner_count = if config.owners == 0 {
            std::thread::available_parallelism()
                .map_or(1, usize::from)
                .clamp(1, 32)
        } else {
            config.owners
        };
        let mut owners = Vec::with_capacity(owner_count);
        for _ in 0..owner_count {
            owners.push(OwnerState {
                maintenance: Mutex::new(()),
                writer: Mutex::new(None),
                io: Mutex::new(SubmissionBackend::new(&config)?),
            });
        }
        let location_count = locations.len();
        let group_delay = Duration::from_micros(config.group_commit_delay_microseconds);
        let group_max = config.group_commit_max_requests;
        let queue_depth = group_max.saturating_mul(4).max(1);
        let (durability, durability_receiver) = mpsc::sync_channel(queue_depth);
        let device_barriers = Arc::new(AtomicU64::new(0));
        let inner = Arc::new(NativeInner {
            locations,
            config,
            segment_directory: segment_directory.to_string(),
            owners,
            index: RwLock::new(HashMap::new()),
            next_generation: AtomicU64::new(1),
            next_segment_id: AtomicU64::new(1),
            live_bytes: AtomicU64::new(0),
            dead_bytes: AtomicU64::new(0),
            #[cfg(test)]
            device_barriers: Arc::clone(&device_barriers),
            durability,
            allocated_by_location: (0..location_count).map(|_| AtomicU64::new(0)).collect(),
        });
        inner.recover()?;
        inner.sync_segment_directories()?;
        std::thread::Builder::new()
            .name(format!("pepper-{thread_name}-durability"))
            .spawn(move || {
                durability_loop(durability_receiver, group_delay, group_max, device_barriers)
            })
            .map_err(|error| StorageError::Native(error.to_string()))?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let weak = Arc::downgrade(&inner);
        std::thread::Builder::new()
            .name(format!("pepper-{thread_name}-compactor"))
            .spawn(move || compactor_loop(weak, receiver))
            .map_err(|error| StorageError::Native(error.to_string()))?;
        Ok(Self {
            inner,
            compact: sender,
        })
    }

    pub(crate) fn records(&self) -> Result<Vec<NativeRecord>, StorageError> {
        let index = self
            .inner
            .index
            .read()
            .map_err(|_| StorageError::LockPoisoned)?;
        Ok(index.values().map(NativeRecord::from).collect())
    }

    pub(crate) fn contains(&self, cid: &Cid) -> Result<bool, StorageError> {
        self.inner
            .index
            .read()
            .map(|index| index.contains_key(cid))
            .map_err(|_| StorageError::LockPoisoned)
    }

    pub(crate) fn allocated_bytes(&self, location_index: usize) -> u64 {
        self.inner
            .allocated_by_location
            .get(location_index)
            .map_or(0, |value| value.load(Ordering::Relaxed))
    }

    pub(crate) fn put_batch(
        &self,
        blocks: &[EncodedBlock],
    ) -> Result<Vec<NativeRecord>, StorageError> {
        let mut grouped = BTreeMap::<usize, Vec<(usize, &EncodedBlock)>>::new();
        for (position, block) in blocks.iter().enumerate() {
            grouped
                .entry(self.inner.owner_for(block.cid()))
                .or_default()
                .push((position, block));
        }

        // Lock owners in deterministic order through write completion,
        // device durability, and index publication. This prevents racing PUTs
        // from appending the same CID and ensures no reader observes a record
        // before its shared durability barrier succeeds.
        let mut owner_guards = Vec::with_capacity(grouped.len());
        for owner in grouped.keys() {
            owner_guards.push(
                self.inner.owners[*owner]
                    .maintenance
                    .lock()
                    .map_err(|_| StorageError::LockPoisoned)?,
            );
        }

        let mut results = vec![None; blocks.len()];
        let mut missing = BTreeMap::<usize, Vec<(usize, &EncodedBlock)>>::new();
        let mut first_missing = HashMap::<Cid, usize>::new();
        let mut duplicates = Vec::new();
        {
            let index = self
                .inner
                .index
                .read()
                .map_err(|_| StorageError::LockPoisoned)?;
            for (position, block) in blocks.iter().enumerate() {
                if let Some(existing) = index.get(block.cid()) {
                    results[position] = Some(NativeRecord::from_location(existing, true));
                } else if let Some(first_position) = first_missing.get(block.cid()) {
                    duplicates.push((position, *first_position));
                } else {
                    first_missing.insert(block.cid().clone(), position);
                    missing
                        .entry(self.inner.owner_for(block.cid()))
                        .or_default()
                        .push((position, block));
                }
            }
        }

        let mut staged = Vec::new();
        for (owner, group) in missing {
            staged.extend(self.inner.write_data_exclusive(owner, &group)?);
        }
        if !staged.is_empty() {
            self.inner.durability_barrier(&staged)?;
            for (position, record) in self.inner.install_records(&staged)? {
                results[position] = Some(record);
            }
        }
        for (position, first_position) in duplicates {
            let mut record = results[first_position]
                .clone()
                .ok_or(StorageError::BatchResultMissing)?;
            record.already_existed = true;
            results[position] = Some(record);
        }
        drop(owner_guards);
        results
            .into_iter()
            .map(|result| result.ok_or(StorageError::BatchResultMissing))
            .collect()
    }

    pub(crate) fn read(&self, cid: &Cid) -> Result<Vec<u8>, StorageError> {
        let record = self
            .inner
            .index
            .read()
            .map_err(|_| StorageError::LockPoisoned)?
            .get(cid)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(cid.clone()))?;
        self.inner.read_record(&record)
    }

    pub(crate) fn read_slice(
        &self,
        cid: &Cid,
        start: usize,
        end: usize,
    ) -> Result<(Vec<u8>, u64), StorageError> {
        let record = self
            .inner
            .index
            .read()
            .map_err(|_| StorageError::LockPoisoned)?
            .get(cid)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(cid.clone()))?;
        if start > end || end > record.stored_size as usize {
            return Err(StorageError::InvalidRange {
                start: start as u64,
                end: end as u64,
                size: record.stored_size,
            });
        }
        let aligned_start = start / ALIGNMENT * ALIGNMENT;
        let aligned_end = align_up(end, ALIGNMENT).min(record.padded_size as usize);
        let mut aligned = AlignedBuffer::new(aligned_end.saturating_sub(aligned_start))?;
        self.inner.owners[record.owner]
            .io
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?
            .read_exact(
                &record.segment.file,
                record.payload_offset + aligned_start as u64,
                &mut aligned,
            )?;
        let relative_start = start - aligned_start;
        let relative_end = relative_start + (end - start);
        let physical = aligned.layout.size() as u64;
        NATIVE_READS.fetch_add(1, Ordering::Relaxed);
        NATIVE_READ_BYTES.fetch_add(physical, Ordering::Relaxed);
        Ok((
            aligned.as_slice()[relative_start..relative_end].to_vec(),
            physical,
        ))
    }

    pub(crate) fn delete(&self, cid: &Cid) -> Result<(), StorageError> {
        let owner = self.inner.owner_for(cid);
        if !self.contains(cid)? {
            return Ok(());
        }
        self.inner.append_tombstone(owner, cid)?;
        let _ = self.compact.try_send(());
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn compact_now(&self) -> Result<(), StorageError> {
        self.inner.compact_all()
    }

    #[cfg(test)]
    pub(crate) fn device_barriers(&self) -> u64 {
        self.inner.device_barriers.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn owner_for_test(&self, cid: &Cid) -> usize {
        self.inner.owner_for(cid)
    }

    #[cfg(test)]
    pub(crate) fn append_uncommitted_for_test(
        &self,
        block: &EncodedBlock,
    ) -> Result<(), StorageError> {
        let owner = self.inner.owner_for(block.cid());
        let _maintenance = self.inner.owners[owner]
            .maintenance
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let mut writer = self.inner.owners[owner]
            .writer
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let batch_id = self.inner.next_segment_id.fetch_add(1, Ordering::Relaxed);
        let encoded = encode_batch(batch_id, std::iter::once(block))?;
        let incomplete = &encoded.bytes[..encoded.bytes.len() - RECORD_HEADER_BYTES];
        self.inner
            .ensure_writer(owner, &mut writer, incomplete.len() as u64)?;
        let current = writer.as_mut().expect("writer was ensured");
        self.inner
            .write_aligned(owner, &current.handle.file, current.offset, incomplete)?;
        current.offset += incomplete.len() as u64;
        Ok(())
    }
}

impl NativeInner {
    fn owner_for(&self, cid: &Cid) -> usize {
        let digest = blake3::hash(cid.to_string().as_bytes());
        let mut word = [0u8; 8];
        word.copy_from_slice(&digest.as_bytes()[..8]);
        (u64::from_le_bytes(word) as usize) % self.owners.len()
    }

    /// Write unique records while the owner's maintenance lock is held. The
    /// caller must complete a device barrier before installing these locations
    /// in the visible index.
    fn write_data_exclusive(
        &self,
        owner: usize,
        blocks: &[(usize, &EncodedBlock)],
    ) -> Result<Vec<(usize, RecordLocation)>, StorageError> {
        if blocks.is_empty() {
            return Ok(Vec::new());
        }
        let mut writer = self.owners[owner]
            .writer
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let mut inserted = Vec::with_capacity(blocks.len());
        let maximum_batch = self
            .config
            .segment_bytes
            .saturating_sub(SEGMENT_HEADER_BYTES as u64);
        let mut cursor = 0;
        while cursor < blocks.len() {
            let mut end = cursor;
            let mut encoded_size = RECORD_HEADER_BYTES as u64; // commit record
            while end < blocks.len() {
                let payload = blocks[end].1.bytes().len();
                let record_size = RECORD_HEADER_BYTES as u64 + align_up(payload, ALIGNMENT) as u64;
                if encoded_size.saturating_add(record_size) > maximum_batch {
                    break;
                }
                encoded_size += record_size;
                end += 1;
            }
            if end == cursor {
                return Err(StorageError::Native(format!(
                    "encoded block of {} bytes exceeds native segment payload capacity {maximum_batch}",
                    blocks[cursor].1.bytes().len()
                )));
            }

            let chunk = &blocks[cursor..end];
            let batch_id = self.next_segment_id.fetch_add(1, Ordering::Relaxed);
            let encoded = encode_batch(batch_id, chunk.iter().map(|(_, block)| *block))?;
            self.ensure_writer(owner, &mut writer, encoded.bytes.len() as u64)?;
            let current = writer.as_mut().expect("writer was ensured");
            let start = current.offset;
            self.write_aligned_buffered(owner, &current.handle.file, start, &encoded.bytes)?;
            current.offset += encoded.bytes.len() as u64;

            for (((position, block), relative), padded_size) in chunk
                .iter()
                .zip(encoded.payload_offsets)
                .zip(encoded.padded_sizes)
            {
                let record = RecordLocation {
                    cid: block.cid().clone(),
                    logical_size: block.logical_size_bytes(),
                    stored_size: block.bytes().len() as u64,
                    payload_offset: start + relative,
                    padded_size,
                    owner,
                    location_index: current.location_index,
                    segment: current.handle.clone(),
                };
                inserted.push((*position, record));
            }
            cursor = end;
        }
        Ok(inserted)
    }

    fn install_records(
        &self,
        staged: &[(usize, RecordLocation)],
    ) -> Result<Vec<(usize, NativeRecord)>, StorageError> {
        let mut installed = Vec::with_capacity(staged.len());
        let mut index = self.index.write().map_err(|_| StorageError::LockPoisoned)?;
        for (position, record) in staged {
            if let Some(previous) = index.insert(record.cid.clone(), record.clone()) {
                self.live_bytes
                    .fetch_sub(previous.padded_size, Ordering::Relaxed);
                self.dead_bytes
                    .fetch_add(previous.padded_size, Ordering::Relaxed);
            }
            self.live_bytes
                .fetch_add(record.padded_size, Ordering::Relaxed);
            installed.push((*position, NativeRecord::from(record)));
        }
        NATIVE_WRITES.fetch_add(staged.len() as u64, Ordering::Relaxed);
        NATIVE_WRITE_BYTES.fetch_add(
            staged.iter().map(|(_, record)| record.stored_size).sum(),
            Ordering::Relaxed,
        );
        Ok(installed)
    }

    fn append_tombstone(&self, owner: usize, cid: &Cid) -> Result<(), StorageError> {
        let _maintenance = self.owners[owner]
            .maintenance
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let mut writer = self.owners[owner]
            .writer
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let batch_id = self.next_segment_id.fetch_add(1, Ordering::Relaxed);
        let encoded = encode_tombstone_batch(batch_id, cid)?;
        self.ensure_writer(owner, &mut writer, encoded.len() as u64)?;
        let current = writer.as_mut().expect("writer was ensured");
        self.write_aligned(owner, &current.handle.file, current.offset, &encoded)?;
        current.offset += encoded.len() as u64;
        if let Some(previous) = self
            .index
            .write()
            .map_err(|_| StorageError::LockPoisoned)?
            .remove(cid)
        {
            self.live_bytes
                .fetch_sub(previous.padded_size, Ordering::Relaxed);
            self.dead_bytes
                .fetch_add(previous.padded_size, Ordering::Relaxed);
        }
        Ok(())
    }

    fn ensure_writer(
        &self,
        owner: usize,
        writer: &mut Option<SegmentWriter>,
        required: u64,
    ) -> Result<(), StorageError> {
        if required + SEGMENT_HEADER_BYTES as u64 > self.config.segment_bytes {
            return Err(StorageError::Native(format!(
                "native batch of {required} bytes exceeds segment size {}",
                self.config.segment_bytes
            )));
        }
        if writer
            .as_ref()
            .is_some_and(|writer| writer.offset + required <= self.config.segment_bytes)
        {
            return Ok(());
        }
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let segment_id = self.next_segment_id.fetch_add(1, Ordering::Relaxed);
        let location_index = self.reserve_segment_location(owner, generation)?;
        let location = &self.locations[location_index];
        let directory = location
            .path
            .join(&self.segment_directory)
            .join(format!("owner-{owner}"));
        fs::create_dir_all(&directory).map_err(|source| StorageError::Io {
            path: directory.display().to_string(),
            source,
        })?;
        let path = directory.join(format!("segment-{generation:020}-{segment_id:020}.pepper"));
        let file = match open_segment_file(&path, self.config.direct_io, true).and_then(|file| {
            preallocate(&file, &path, self.config.segment_bytes)?;
            Ok(file)
        }) {
            Ok(file) => file,
            Err(error) => {
                self.allocated_by_location[location_index]
                    .fetch_sub(self.config.segment_bytes, Ordering::Relaxed);
                return Err(error);
            }
        };
        let initialization = segment_header(owner, generation, segment_id).and_then(|header| {
            self.write_aligned(owner, &file, 0, &header)?;
            sync_native_directory(&directory)
        });
        if let Err(error) = initialization {
            let _ = fs::remove_file(&path);
            self.allocated_by_location[location_index]
                .fetch_sub(self.config.segment_bytes, Ordering::Relaxed);
            return Err(error);
        }
        let handle = SegmentHandle {
            path,
            file: Arc::new(file),
            generation,
            segment_id,
        };
        *writer = Some(SegmentWriter {
            handle,
            offset: SEGMENT_HEADER_BYTES as u64,
            location_index,
        });
        Ok(())
    }

    fn reserve_segment_location(
        &self,
        owner: usize,
        generation: u64,
    ) -> Result<usize, StorageError> {
        let start = (owner + generation as usize) % self.locations.len();
        for offset in 0..self.locations.len() {
            let index = (start + offset) % self.locations.len();
            let capacity = self.locations[index].max_capacity_bytes;
            let reserved = &self.allocated_by_location[index];
            if reserved
                .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                    (current.saturating_add(self.config.segment_bytes) <= capacity)
                        .then_some(current + self.config.segment_bytes)
                })
                .is_ok()
            {
                return Ok(index);
            }
        }
        Err(StorageError::CapacityExceeded {
            size_bytes: self.config.segment_bytes,
        })
    }

    fn sync_segment_directories(&self) -> Result<(), StorageError> {
        for location in self.locations.iter() {
            sync_native_directory(&location.path)?;
            sync_native_directory(&location.path.join(&self.segment_directory))?;
        }
        Ok(())
    }

    fn write_aligned(
        &self,
        owner: usize,
        file: &File,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        debug_assert_eq!(offset % ALIGNMENT as u64, 0);
        debug_assert_eq!(bytes.len() % ALIGNMENT, 0);
        let mut aligned = AlignedBuffer::new(bytes.len())?;
        aligned.as_mut_slice().copy_from_slice(bytes);
        self.owners[owner]
            .io
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?
            .write_and_sync(file, offset, &aligned)
    }

    fn write_aligned_buffered(
        &self,
        owner: usize,
        file: &File,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        debug_assert_eq!(offset % ALIGNMENT as u64, 0);
        debug_assert_eq!(bytes.len() % ALIGNMENT, 0);
        let mut aligned = AlignedBuffer::new(bytes.len())?;
        aligned.as_mut_slice().copy_from_slice(bytes);
        self.owners[owner]
            .io
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?
            .write(file, offset, &aligned)
    }

    fn durability_barrier(&self, staged: &[(usize, RecordLocation)]) -> Result<(), StorageError> {
        let mut files = BTreeMap::<i32, Arc<File>>::new();
        for (_, record) in staged {
            files
                .entry(record.segment.file.as_raw_fd())
                .or_insert_with(|| record.segment.file.clone());
        }
        let (result, receiver) = mpsc::sync_channel(1);
        self.durability
            .send(DurabilityRequest {
                files: files.into_iter().collect(),
                result,
            })
            .map_err(|_| StorageError::Native("durability coordinator stopped".to_string()))?;
        receiver
            .recv()
            .map_err(|_| StorageError::Native("durability coordinator stopped".to_string()))?
            .map_err(StorageError::Native)
    }

    fn read_record(&self, record: &RecordLocation) -> Result<Vec<u8>, StorageError> {
        let mut aligned = AlignedBuffer::new(record.padded_size as usize)?;
        self.owners[record.owner]
            .io
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?
            .read_exact(&record.segment.file, record.payload_offset, &mut aligned)?;
        let bytes = aligned.as_slice()[..record.stored_size as usize].to_vec();
        NATIVE_READS.fetch_add(1, Ordering::Relaxed);
        NATIVE_READ_BYTES.fetch_add(record.padded_size, Ordering::Relaxed);
        Ok(bytes)
    }

    fn recover(&self) -> Result<(), StorageError> {
        let mut segments = Vec::new();
        for (location_index, location) in self.locations.iter().enumerate() {
            let root = location.path.join(&self.segment_directory);
            fs::create_dir_all(&root).map_err(|source| StorageError::Io {
                path: root.display().to_string(),
                source,
            })?;
            for owner in 0..self.owners.len() {
                let directory = root.join(format!("owner-{owner}"));
                fs::create_dir_all(&directory).map_err(|source| StorageError::Io {
                    path: directory.display().to_string(),
                    source,
                })?;
                for entry in fs::read_dir(&directory).map_err(|source| StorageError::Io {
                    path: directory.display().to_string(),
                    source,
                })? {
                    let entry = entry.map_err(|source| StorageError::Io {
                        path: directory.display().to_string(),
                        source,
                    })?;
                    if let Some((generation, segment_id)) = parse_segment_name(&entry.file_name()) {
                        segments.push((
                            generation,
                            segment_id,
                            owner,
                            location_index,
                            entry.path(),
                        ));
                    }
                }
            }
        }
        segments.sort_by_key(|(generation, segment, ..)| (*generation, *segment));
        let mut newest = HashMap::<usize, SegmentWriter>::new();
        for (generation, segment_id, owner, location_index, path) in segments {
            let allocated = self.allocated_by_location[location_index]
                .fetch_add(self.config.segment_bytes, Ordering::Relaxed)
                .saturating_add(self.config.segment_bytes);
            if allocated > self.locations[location_index].max_capacity_bytes {
                return Err(StorageError::CapacityExceeded {
                    size_bytes: self.config.segment_bytes,
                });
            }
            let file = open_segment_file(&path, self.config.direct_io, false)?;
            let handle = SegmentHandle {
                path: path.clone(),
                file: Arc::new(file),
                generation,
                segment_id,
            };
            let end = self.recover_segment(owner, location_index, &handle)?;
            let writable = open_segment_file(&path, self.config.direct_io, false)?;
            newest.insert(
                owner,
                SegmentWriter {
                    handle: SegmentHandle {
                        file: Arc::new(writable),
                        ..handle
                    },
                    offset: end,
                    location_index,
                },
            );
            self.next_generation
                .fetch_max(generation.saturating_add(1), Ordering::Relaxed);
            self.next_segment_id
                .fetch_max(segment_id.saturating_add(1), Ordering::Relaxed);
        }
        for (owner, writer) in newest {
            if writer.offset < self.config.segment_bytes {
                *self.owners[owner]
                    .writer
                    .lock()
                    .map_err(|_| StorageError::LockPoisoned)? = Some(writer);
            }
        }
        Ok(())
    }

    fn recover_segment(
        &self,
        owner: usize,
        location_index: usize,
        handle: &SegmentHandle,
    ) -> Result<u64, StorageError> {
        let mut header = AlignedBuffer::new(SEGMENT_HEADER_BYTES)?;
        read_aligned_sync(&handle.file, 0, &mut header)?;
        validate_segment_header(
            header.as_slice(),
            owner,
            handle.generation,
            handle.segment_id,
        )?;
        let mut offset = SEGMENT_HEADER_BYTES as u64;
        let mut committed_end = offset;
        let mut torn_tail = false;
        let mut pending = HashMap::<u64, Vec<RecoveredRecord>>::new();
        while offset + RECORD_HEADER_BYTES as u64 <= self.config.segment_bytes {
            let mut record_header = AlignedBuffer::new(RECORD_HEADER_BYTES)?;
            if read_aligned_sync(&handle.file, offset, &mut record_header).is_err() {
                torn_tail = true;
                break;
            }
            if record_header.as_slice().iter().all(|byte| *byte == 0) {
                torn_tail = !pending.is_empty();
                break;
            }
            let parsed = match parse_record_header(record_header.as_slice()) {
                Ok(parsed) => parsed,
                Err(_) => {
                    torn_tail = true;
                    break;
                }
            };
            let record_start = offset;
            offset = offset.saturating_add(RECORD_HEADER_BYTES as u64);
            if parsed.kind == RECORD_DATA {
                if parsed.stored_size > parsed.padded_size
                    || parsed.padded_size == 0
                    || parsed.padded_size % ALIGNMENT as u64 != 0
                    || offset.saturating_add(parsed.padded_size) > self.config.segment_bytes
                {
                    torn_tail = true;
                    break;
                }
                let mut payload = AlignedBuffer::new(parsed.padded_size as usize)?;
                if read_aligned_sync(&handle.file, offset, &mut payload).is_err()
                    || crc32c::crc32c(&payload.as_slice()[..parsed.stored_size as usize])
                        != parsed.payload_crc
                {
                    torn_tail = true;
                    break;
                }
                pending
                    .entry(parsed.batch_id)
                    .or_default()
                    .push(RecoveredRecord {
                        parsed: parsed.clone(),
                        payload_offset: offset,
                    });
                offset += parsed.padded_size;
            } else if parsed.kind == RECORD_TOMBSTONE {
                pending
                    .entry(parsed.batch_id)
                    .or_default()
                    .push(RecoveredRecord {
                        parsed: parsed.clone(),
                        payload_offset: offset,
                    });
            } else if parsed.kind == RECORD_COMMIT {
                let Some(records) = pending.remove(&parsed.batch_id) else {
                    torn_tail = true;
                    break;
                };
                if records.len() as u64 != parsed.logical_size
                    || batch_digest(records.iter().map(|record| &record.parsed))
                        != parsed.commit_digest
                {
                    torn_tail = true;
                    break;
                }
                let mut index = self.index.write().map_err(|_| StorageError::LockPoisoned)?;
                for record in records {
                    if record.parsed.kind == RECORD_TOMBSTONE {
                        if let Some(previous) = index.remove(&record.parsed.cid) {
                            self.live_bytes
                                .fetch_sub(previous.padded_size, Ordering::Relaxed);
                            self.dead_bytes
                                .fetch_add(previous.padded_size, Ordering::Relaxed);
                        }
                        continue;
                    }
                    let location = RecordLocation {
                        cid: record.parsed.cid,
                        logical_size: record.parsed.logical_size,
                        stored_size: record.parsed.stored_size,
                        payload_offset: record.payload_offset,
                        padded_size: record.parsed.padded_size,
                        owner,
                        location_index,
                        segment: handle.clone(),
                    };
                    if let Some(previous) = index.insert(location.cid.clone(), location.clone()) {
                        self.live_bytes
                            .fetch_sub(previous.padded_size, Ordering::Relaxed);
                        self.dead_bytes
                            .fetch_add(previous.padded_size, Ordering::Relaxed);
                    }
                    self.live_bytes
                        .fetch_add(location.padded_size, Ordering::Relaxed);
                    NATIVE_RECOVERED_RECORDS.fetch_add(1, Ordering::Relaxed);
                }
                // Only a validated commit record advances the restart point.
                // An interrupted batch is overwritten from this boundary.
                committed_end = offset;
            } else {
                torn_tail = true;
                break;
            }
            if offset <= record_start {
                return Err(StorageError::Native(
                    "native recovery made no progress".to_string(),
                ));
            }
        }
        if torn_tail || !pending.is_empty() {
            NATIVE_TORN_TAILS.fetch_add(1, Ordering::Relaxed);
            if committed_end + RECORD_HEADER_BYTES as u64 <= self.config.segment_bytes {
                // Make the recovered boundary durable before accepting new
                // writes. Otherwise a second crash before the next append
                // could expose stale bytes from the abandoned batch again.
                self.write_aligned(
                    owner,
                    &handle.file,
                    committed_end,
                    &vec![0; RECORD_HEADER_BYTES],
                )?;
            }
        }
        Ok(committed_end)
    }

    fn compact_all(&self) -> Result<(), StorageError> {
        let live = self.live_bytes.load(Ordering::Relaxed);
        let dead_before = self.dead_bytes.load(Ordering::Relaxed);
        if dead_before == 0
            || dead_before.saturating_mul(100)
                < live
                    .saturating_add(dead_before)
                    .saturating_mul(u64::from(self.config.compaction_dead_percent))
        {
            return Ok(());
        }
        // Compaction is deliberately owner-at-a-time. Foreground work for
        // other owners proceeds while this owner copies its immutable records.
        let mut rewritten_padded_bytes = 0u64;
        for owner in 0..self.owners.len() {
            rewritten_padded_bytes =
                rewritten_padded_bytes.saturating_add(self.compact_owner(owner)?);
        }
        // Rewriting a live record temporarily marks its old location dead.
        // Remove both that exact amount and the dead bytes observed before
        // this pass. Mutations racing on owners already compacted remain in
        // the counter and trigger a later pass.
        let reclaimed = dead_before.saturating_add(rewritten_padded_bytes);
        let _ = self
            .dead_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(reclaimed))
            });
        NATIVE_COMPACTIONS.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn compact_owner(&self, owner: usize) -> Result<u64, StorageError> {
        let _maintenance = self.owners[owner]
            .maintenance
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        let mut writer = self.owners[owner]
            .writer
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        // Rotate away from the foreground segment before taking the snapshot.
        // The owner maintenance lock prevents a newer PUT or tombstone from
        // being reordered behind a copied stale value.
        *writer = None;
        drop(writer);

        let old_paths = self.owner_segment_paths(owner)?;
        let snapshot = self
            .index
            .read()
            .map_err(|_| StorageError::LockPoisoned)?
            .values()
            .filter(|record| record.owner == owner)
            .cloned()
            .collect::<Vec<_>>();

        // Bound compactor memory independently of segment size. One legal
        // large block may exceed this target, but is still processed alone.
        const COMPACTION_BUFFER_BYTES: u64 = 64 * 1024 * 1024;
        let mut cursor = 0;
        let mut rewritten_padded_bytes = 0u64;
        let mut compacted_bytes = 0u64;
        while cursor < snapshot.len() {
            let mut end = cursor;
            let mut buffered = 0u64;
            while end < snapshot.len() {
                let candidate = snapshot[end].stored_size;
                if end > cursor && buffered.saturating_add(candidate) > COMPACTION_BUFFER_BYTES {
                    break;
                }
                buffered = buffered.saturating_add(candidate);
                end += 1;
            }
            let mut blocks = Vec::with_capacity(end - cursor);
            for record in &snapshot[cursor..end] {
                let bytes = self.read_record(record)?;
                compacted_bytes = compacted_bytes.saturating_add(bytes.len() as u64);
                rewritten_padded_bytes = rewritten_padded_bytes.saturating_add(record.padded_size);
                blocks.push(EncodedBlock {
                    cid: record.cid.clone(),
                    logical_size_bytes: record.logical_size,
                    bytes,
                });
            }
            let indexed = blocks.iter().enumerate().collect::<Vec<_>>();
            let staged = self.write_data_exclusive(owner, &indexed)?;
            self.durability_barrier(&staged)?;
            self.install_records(&staged)?;
            cursor = end;
        }
        let new_paths = self
            .index
            .read()
            .map_err(|_| StorageError::LockPoisoned)?
            .values()
            .filter(|record| record.owner == owner)
            .map(|record| record.segment.path.clone())
            .collect::<HashSet<_>>();
        let mut modified_directories = HashSet::new();
        for (path, location_index) in old_paths {
            if new_paths.contains(&path) {
                continue;
            }
            match fs::remove_file(&path) {
                Ok(()) => {
                    if let Some(parent) = path.parent() {
                        modified_directories.insert(parent.to_path_buf());
                    }
                    self.allocated_by_location[location_index]
                        .fetch_sub(self.config.segment_bytes, Ordering::Relaxed);
                }
                Err(source) if source.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(StorageError::Io {
                        path: path.display().to_string(),
                        source,
                    });
                }
            }
        }
        // Without a directory barrier, a crash can resurrect an unlinked old
        // segment whose data records predate a compacted-away tombstone.
        for directory in modified_directories {
            sync_native_directory(&directory)?;
        }
        NATIVE_COMPACTED_BYTES.fetch_add(compacted_bytes, Ordering::Relaxed);
        Ok(rewritten_padded_bytes)
    }

    fn owner_segment_paths(&self, owner: usize) -> Result<Vec<(PathBuf, usize)>, StorageError> {
        let mut paths = Vec::new();
        for (location_index, location) in self.locations.iter().enumerate() {
            let directory = location
                .path
                .join(&self.segment_directory)
                .join(format!("owner-{owner}"));
            for entry in fs::read_dir(&directory).map_err(|source| StorageError::Io {
                path: directory.display().to_string(),
                source,
            })? {
                let entry = entry.map_err(|source| StorageError::Io {
                    path: directory.display().to_string(),
                    source,
                })?;
                if parse_segment_name(&entry.file_name()).is_some() {
                    paths.push((entry.path(), location_index));
                }
            }
        }
        Ok(paths)
    }
}

fn durability_loop(
    receiver: mpsc::Receiver<DurabilityRequest>,
    delay: Duration,
    maximum_requests: usize,
    device_barriers: Arc<AtomicU64>,
) {
    while let Ok(first) = receiver.recv() {
        let mut requests = vec![first];
        let deadline = Instant::now() + delay;
        let mut disconnected = false;
        while requests.len() < maximum_requests {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match receiver.recv_timeout(remaining) {
                Ok(request) => requests.push(request),
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }

        let mut files = BTreeMap::<i32, Arc<File>>::new();
        for request in &requests {
            for (descriptor, file) in &request.files {
                files.entry(*descriptor).or_insert_with(|| Arc::clone(file));
            }
        }
        let outcome = sync_native_files(files.into_values(), &device_barriers);
        if outcome.is_ok() {
            NATIVE_DURABILITY_GROUPS.fetch_add(1, Ordering::Relaxed);
            NATIVE_DURABILITY_GROUP_REQUESTS.fetch_add(requests.len() as u64, Ordering::Relaxed);
        }
        for request in requests {
            let _ = request.result.send(outcome.clone());
        }
        if disconnected {
            break;
        }
    }
}

fn sync_native_files(
    files: impl IntoIterator<Item = Arc<File>>,
    device_barriers: &AtomicU64,
) -> Result<(), String> {
    for file in files {
        file.sync_data()
            .map_err(|error| format!("native segment data sync failed: {error}"))?;
    }
    device_barriers.fetch_add(1, Ordering::Relaxed);
    NATIVE_DURABILITY_BARRIERS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn compactor_loop(inner: Weak<NativeInner>, receiver: mpsc::Receiver<()>) {
    while receiver.recv().is_ok() {
        let Some(inner) = inner.upgrade() else {
            break;
        };
        let _ = inner.compact_all();
    }
}

struct EncodedBatch {
    bytes: Vec<u8>,
    payload_offsets: Vec<u64>,
    padded_sizes: Vec<u64>,
}

fn encode_batch<'a>(
    batch_id: u64,
    blocks: impl Iterator<Item = &'a EncodedBlock>,
) -> Result<EncodedBatch, StorageError> {
    let blocks = blocks.collect::<Vec<_>>();
    let mut bytes = Vec::new();
    let mut offsets = Vec::with_capacity(blocks.len());
    let mut padded_sizes = Vec::with_capacity(blocks.len());
    let mut parsed = Vec::with_capacity(blocks.len());
    for block in &blocks {
        let stored_size = block.bytes().len() as u64;
        let padded = align_up(stored_size as usize, ALIGNMENT) as u64;
        let crc = crc32c::crc32c(block.bytes());
        let header = record_header(
            RECORD_DATA,
            batch_id,
            block.cid(),
            block.logical_size_bytes(),
            stored_size,
            padded,
            crc,
            &[],
        )?;
        bytes.extend_from_slice(&header);
        offsets.push(bytes.len() as u64);
        bytes.extend_from_slice(block.bytes());
        bytes.resize(bytes.len() + (padded as usize - block.bytes().len()), 0);
        padded_sizes.push(padded);
        parsed.push(ParsedHeader {
            kind: RECORD_DATA,
            batch_id,
            cid: block.cid().clone(),
            logical_size: block.logical_size_bytes(),
            stored_size,
            padded_size: padded,
            payload_crc: crc,
            commit_digest: [0; 32],
        });
    }
    let digest = batch_digest(parsed.iter());
    bytes.extend_from_slice(&record_header(
        RECORD_COMMIT,
        batch_id,
        &Cid::new(CODEC_RAW, &digest),
        blocks.len() as u64,
        0,
        0,
        0,
        &digest,
    )?);
    Ok(EncodedBatch {
        bytes,
        payload_offsets: offsets,
        padded_sizes,
    })
}

fn encode_tombstone_batch(batch_id: u64, cid: &Cid) -> Result<Vec<u8>, StorageError> {
    let tombstone = ParsedHeader {
        kind: RECORD_TOMBSTONE,
        batch_id,
        cid: cid.clone(),
        logical_size: 0,
        stored_size: 0,
        padded_size: 0,
        payload_crc: 0,
        commit_digest: [0; 32],
    };
    let digest = batch_digest(std::iter::once(&tombstone));
    let mut bytes = record_header(RECORD_TOMBSTONE, batch_id, cid, 0, 0, 0, 0, &[])?;
    bytes.extend_from_slice(&record_header(
        RECORD_COMMIT,
        batch_id,
        &Cid::new(CODEC_RAW, &digest),
        1,
        0,
        0,
        0,
        &digest,
    )?);
    Ok(bytes)
}

#[derive(Clone)]
struct ParsedHeader {
    kind: u8,
    batch_id: u64,
    cid: Cid,
    logical_size: u64,
    stored_size: u64,
    padded_size: u64,
    payload_crc: u32,
    commit_digest: [u8; 32],
}

struct RecoveredRecord {
    parsed: ParsedHeader,
    payload_offset: u64,
}

fn segment_header(owner: usize, generation: u64, segment_id: u64) -> Result<Vec<u8>, StorageError> {
    let owner = u32::try_from(owner)
        .map_err(|_| StorageError::Native("native owner exceeds u32".to_string()))?;
    let mut header = vec![0u8; SEGMENT_HEADER_BYTES];
    header[..8].copy_from_slice(SEGMENT_MAGIC);
    header[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    header[12..16].copy_from_slice(&owner.to_le_bytes());
    header[16..24].copy_from_slice(&generation.to_le_bytes());
    header[24..32].copy_from_slice(&segment_id.to_le_bytes());
    let crc = crc32c::crc32c(&header[..32]);
    header[32..36].copy_from_slice(&crc.to_le_bytes());
    Ok(header)
}

fn validate_segment_header(
    header: &[u8],
    owner: usize,
    generation: u64,
    segment_id: u64,
) -> Result<(), StorageError> {
    if header.len() != SEGMENT_HEADER_BYTES
        || &header[..8] != SEGMENT_MAGIC
        || u16::from_le_bytes(header[8..10].try_into().unwrap()) != FORMAT_VERSION
        || u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize != owner
        || u64::from_le_bytes(header[16..24].try_into().unwrap()) != generation
        || u64::from_le_bytes(header[24..32].try_into().unwrap()) != segment_id
        || u32::from_le_bytes(header[32..36].try_into().unwrap()) != crc32c::crc32c(&header[..32])
    {
        return Err(StorageError::Native(
            "invalid native segment header".to_string(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_header(
    kind: u8,
    batch_id: u64,
    cid: &Cid,
    logical_size: u64,
    stored_size: u64,
    padded_size: u64,
    payload_crc: u32,
    commit_digest: &[u8],
) -> Result<Vec<u8>, StorageError> {
    let cid = cid.to_string();
    if cid.len() > MAX_CID_BYTES {
        return Err(StorageError::Native(
            "CID exceeds native record limit".to_string(),
        ));
    }
    let mut header = vec![0u8; RECORD_HEADER_BYTES];
    header[..8].copy_from_slice(RECORD_MAGIC);
    header[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    header[10] = kind;
    header[16..24].copy_from_slice(&batch_id.to_le_bytes());
    header[24..32].copy_from_slice(&logical_size.to_le_bytes());
    header[32..40].copy_from_slice(&stored_size.to_le_bytes());
    header[40..48].copy_from_slice(&padded_size.to_le_bytes());
    header[48..50].copy_from_slice(&(cid.len() as u16).to_le_bytes());
    header[52..56].copy_from_slice(&payload_crc.to_le_bytes());
    header[64..64 + cid.len()].copy_from_slice(cid.as_bytes());
    if !commit_digest.is_empty() {
        header[576..608].copy_from_slice(commit_digest);
    }
    let crc = crc32c::crc32c(&header);
    header[56..60].copy_from_slice(&crc.to_le_bytes());
    Ok(header)
}

fn parse_record_header(header: &[u8]) -> Result<ParsedHeader, StorageError> {
    if header.len() != RECORD_HEADER_BYTES || &header[..8] != RECORD_MAGIC {
        return Err(StorageError::Native(
            "invalid native record magic".to_string(),
        ));
    }
    let mut checked = header.to_vec();
    let expected = u32::from_le_bytes(checked[56..60].try_into().unwrap());
    checked[56..60].fill(0);
    if expected != crc32c::crc32c(&checked)
        || u16::from_le_bytes(header[8..10].try_into().unwrap()) != FORMAT_VERSION
    {
        return Err(StorageError::Native(
            "invalid native record checksum/version".to_string(),
        ));
    }
    let kind = header[10];
    let cid_len = u16::from_le_bytes(header[48..50].try_into().unwrap()) as usize;
    if cid_len == 0 || cid_len > MAX_CID_BYTES {
        return Err(StorageError::Native(
            "invalid native record CID length".to_string(),
        ));
    }
    let cid = std::str::from_utf8(&header[64..64 + cid_len])
        .map_err(|error| StorageError::Native(error.to_string()))?
        .parse::<Cid>()?;
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&header[576..608]);
    Ok(ParsedHeader {
        kind,
        batch_id: u64::from_le_bytes(header[16..24].try_into().unwrap()),
        cid,
        logical_size: u64::from_le_bytes(header[24..32].try_into().unwrap()),
        stored_size: u64::from_le_bytes(header[32..40].try_into().unwrap()),
        padded_size: u64::from_le_bytes(header[40..48].try_into().unwrap()),
        payload_crc: u32::from_le_bytes(header[52..56].try_into().unwrap()),
        commit_digest: digest,
    })
}

fn batch_digest<'a>(records: impl Iterator<Item = &'a ParsedHeader>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for record in records {
        hasher.update(&[record.kind]);
        hasher.update(record.cid.to_string().as_bytes());
        hasher.update(&record.logical_size.to_le_bytes());
        hasher.update(&record.stored_size.to_le_bytes());
        hasher.update(&record.payload_crc.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn align_up(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

fn parse_segment_name(name: &std::ffi::OsStr) -> Option<(u64, u64)> {
    let name = name.to_str()?;
    let body = name.strip_prefix("segment-")?.strip_suffix(".pepper")?;
    let (generation, segment) = body.split_once('-')?;
    Some((generation.parse().ok()?, segment.parse().ok()?))
}

fn sync_native_directory(path: &Path) -> Result<(), StorageError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| StorageError::Io {
            path: path.display().to_string(),
            source,
        })?;
    NATIVE_DURABILITY_BARRIERS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn open_segment_file(path: &Path, direct: bool, create_new: bool) -> Result<File, StorageError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create_new {
        options.create_new(true);
    }
    #[cfg(target_os = "linux")]
    if direct {
        options.custom_flags(libc::O_DIRECT);
    }
    options.open(path).map_err(|source| StorageError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn preallocate(file: &File, path: &Path, bytes: u64) -> Result<(), StorageError> {
    #[cfg(target_os = "linux")]
    {
        let result = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, bytes as libc::off_t) };
        if result != 0 {
            return Err(StorageError::Io {
                path: path.display().to_string(),
                source: io::Error::from_raw_os_error(result),
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    file.set_len(bytes).map_err(|source| StorageError::Io {
        path: path.display().to_string(),
        source,
    })?;
    Ok(())
}

struct AlignedBuffer {
    pointer: NonNull<u8>,
    layout: Layout,
}

impl AlignedBuffer {
    fn new(bytes: usize) -> Result<Self, StorageError> {
        let bytes = align_up(bytes.max(1), ALIGNMENT);
        let layout = Layout::from_size_align(bytes, ALIGNMENT)
            .map_err(|error| StorageError::Native(error.to_string()))?;
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) })
            .ok_or_else(|| StorageError::Native("aligned allocation failed".to_string()))?;
        Ok(Self { pointer, layout })
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), self.layout.size()) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.layout.size()) }
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

enum SubmissionBackend {
    #[cfg(target_os = "linux")]
    Uring(Box<IoUring>),
    Sync,
}

impl SubmissionBackend {
    fn new(config: &NativeStorageConfig) -> Result<Self, StorageError> {
        #[cfg(target_os = "linux")]
        match IoUring::new(config.io_uring_entries) {
            Ok(ring) => return Ok(Self::Uring(Box::new(ring))),
            Err(error) if config.require_io_uring => {
                return Err(StorageError::Native(format!(
                    "io_uring is required but unavailable: {error}"
                )));
            }
            Err(_) => {
                NATIVE_SYNC_FALLBACKS.fetch_add(1, Ordering::Relaxed);
            }
        }
        #[cfg(not(target_os = "linux"))]
        if config.require_io_uring {
            return Err(StorageError::Native(
                "io_uring is required but this is not Linux".to_string(),
            ));
        }
        Ok(Self::Sync)
    }

    fn write(
        &mut self,
        file: &File,
        offset: u64,
        buffer: &AlignedBuffer,
    ) -> Result<(), StorageError> {
        #[cfg(target_os = "linux")]
        if let Self::Uring(ring) = self {
            let write = opcode::Write::new(
                types::Fd(file.as_raw_fd()),
                buffer.pointer.as_ptr(),
                buffer.layout.size() as u32,
            )
            .offset(offset)
            .build()
            .user_data(4);
            unsafe {
                ring.submission().push(&write).map_err(|_| {
                    StorageError::Native("io_uring write queue is full".to_string())
                })?;
            }
            ring.submit_and_wait(1)
                .map_err(|error| StorageError::Native(error.to_string()))?;
            let completion = ring.completion().next().ok_or_else(|| {
                StorageError::Native("io_uring write did not complete".to_string())
            })?;
            if completion.result() != buffer.layout.size() as i32 {
                return Err(StorageError::Native(format!(
                    "io_uring short write: {} of {}",
                    completion.result(),
                    buffer.layout.size()
                )));
            }
            NATIVE_URING_SUBMISSIONS.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        file.write_all_at(buffer.as_slice(), offset)
            .map_err(|source| StorageError::Io {
                path: "native segment".to_string(),
                source,
            })
    }

    fn write_and_sync(
        &mut self,
        file: &File,
        offset: u64,
        buffer: &AlignedBuffer,
    ) -> Result<(), StorageError> {
        #[cfg(target_os = "linux")]
        if let Self::Uring(ring) = self {
            let write = opcode::Write::new(
                types::Fd(file.as_raw_fd()),
                buffer.pointer.as_ptr(),
                buffer.layout.size() as u32,
            )
            .offset(offset)
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(1);
            let fsync = opcode::Fsync::new(types::Fd(file.as_raw_fd()))
                .build()
                .user_data(2);
            unsafe {
                ring.submission().push(&write).map_err(|_| {
                    StorageError::Native("io_uring write queue is full".to_string())
                })?;
                ring.submission().push(&fsync).map_err(|_| {
                    StorageError::Native("io_uring fsync queue is full".to_string())
                })?;
            }
            ring.submit_and_wait(2)
                .map_err(|error| StorageError::Native(error.to_string()))?;
            let mut completions = 0;
            for completion in ring.completion() {
                if completion.result() < 0 {
                    return Err(StorageError::Native(format!(
                        "io_uring operation {} failed: {}",
                        completion.user_data(),
                        io::Error::from_raw_os_error(-completion.result())
                    )));
                }
                completions += 1;
            }
            if completions != 2 {
                return Err(StorageError::Native(
                    "io_uring write/fsync completion count mismatch".to_string(),
                ));
            }
            NATIVE_URING_SUBMISSIONS.fetch_add(2, Ordering::Relaxed);
            NATIVE_DURABILITY_BARRIERS.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        file.write_all_at(buffer.as_slice(), offset)
            .and_then(|()| file.sync_data())
            .map_err(|source| StorageError::Io {
                path: "native segment".to_string(),
                source,
            })?;
        NATIVE_DURABILITY_BARRIERS.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn read_exact(
        &mut self,
        file: &File,
        offset: u64,
        buffer: &mut AlignedBuffer,
    ) -> Result<(), StorageError> {
        #[cfg(target_os = "linux")]
        if let Self::Uring(ring) = self {
            let read = opcode::Read::new(
                types::Fd(file.as_raw_fd()),
                buffer.pointer.as_ptr(),
                buffer.layout.size() as u32,
            )
            .offset(offset)
            .build()
            .user_data(3);
            unsafe {
                ring.submission()
                    .push(&read)
                    .map_err(|_| StorageError::Native("io_uring read queue is full".to_string()))?;
            }
            ring.submit_and_wait(1)
                .map_err(|error| StorageError::Native(error.to_string()))?;
            let completion = ring.completion().next().ok_or_else(|| {
                StorageError::Native("io_uring read did not complete".to_string())
            })?;
            if completion.result() != buffer.layout.size() as i32 {
                return Err(StorageError::Native(format!(
                    "io_uring short read: {} of {}",
                    completion.result(),
                    buffer.layout.size()
                )));
            }
            NATIVE_URING_SUBMISSIONS.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        read_aligned_sync(file, offset, buffer)
    }
}

fn read_aligned_sync(
    file: &File,
    offset: u64,
    buffer: &mut AlignedBuffer,
) -> Result<(), StorageError> {
    file.read_exact_at(buffer.as_mut_slice(), offset)
        .map_err(|source| StorageError::Io {
            path: "native segment".to_string(),
            source,
        })
}
