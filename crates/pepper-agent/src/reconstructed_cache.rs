// SPDX-License-Identifier: Apache-2.0

//! Disposable, scan-resistant disk cache for verified reconstructed EC stripes.

use axum::body::Bytes;
use memmap2::MmapOptions;
use pepper_config::ReconstructedCacheConfig;
use pepper_types::{CID_VERSION, CODEC_RAW, Cid, HashAlg};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::Write,
    ops::Range,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_CONCURRENT_WRITES: usize = 4;

static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);
static ADMISSIONS: AtomicU64 = AtomicU64::new(0);
static EVICTIONS: AtomicU64 = AtomicU64::new(0);
static BYPASSES: AtomicU64 = AtomicU64::new(0);
static INTEGRITY_FAILURES: AtomicU64 = AtomicU64::new(0);
static READ_BYTES: AtomicU64 = AtomicU64::new(0);
static WRITE_BYTES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct ReconstructedCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub admissions: u64,
    pub evictions: u64,
    pub bypasses: u64,
    pub integrity_failures: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

pub(super) fn process_stats() -> ReconstructedCacheStats {
    ReconstructedCacheStats {
        hits: HITS.load(Ordering::Relaxed),
        misses: MISSES.load(Ordering::Relaxed),
        admissions: ADMISSIONS.load(Ordering::Relaxed),
        evictions: EVICTIONS.load(Ordering::Relaxed),
        bypasses: BYPASSES.load(Ordering::Relaxed),
        integrity_failures: INTEGRITY_FAILURES.load(Ordering::Relaxed),
        read_bytes: READ_BYTES.load(Ordering::Relaxed),
        write_bytes: WRITE_BYTES.load(Ordering::Relaxed),
    }
}

#[derive(Debug)]
struct CacheEntry {
    size: u64,
    frequency: u64,
    last_access: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AdmissionCandidate {
    cid: Cid,
    start: usize,
    end: usize,
}

#[derive(Debug, Default)]
struct CacheState {
    entries: HashMap<Cid, CacheEntry>,
    pending: HashSet<Cid>,
    candidates: HashMap<AdmissionCandidate, u8>,
    used_bytes: u64,
    clock: u64,
}

#[derive(Debug)]
pub(super) struct ReconstructedStripeCache {
    root: PathBuf,
    capacity_bytes: u64,
    admission_hits: u8,
    write_slots: Arc<Semaphore>,
    state: Mutex<CacheState>,
}

impl ReconstructedStripeCache {
    pub(super) fn open(config: &ReconstructedCacheConfig) -> Result<Option<Self>, String> {
        let Some(root) = &config.path else {
            return Ok(None);
        };
        fs::create_dir_all(root)
            .map_err(|error| format!("failed to create reconstructed cache: {error}"))?;
        let cache = Self {
            root: root.clone(),
            capacity_bytes: config.max_capacity_bytes,
            admission_hits: config.admission_hits,
            write_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_WRITES)),
            state: Mutex::new(CacheState::default()),
        };
        cache.reconcile()?;
        Ok(Some(cache))
    }

    pub(super) fn try_write_slot(&self) -> Option<OwnedSemaphorePermit> {
        self.write_slots.clone().try_acquire_owned().ok()
    }

    pub(super) fn record_write_saturation_bypass(&self) {
        BYPASSES.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn get(&self, cid: &Cid, expected_size: usize) -> Option<Bytes> {
        let path = self.path(cid);
        {
            let mut state = self.state.lock().ok()?;
            let Some(entry) = state.entries.get(cid) else {
                MISSES.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            if entry.size != expected_size as u64 {
                self.remove_locked(&mut state, cid, &path, true);
                MISSES.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => {
                if let Ok(mut state) = self.state.lock() {
                    self.remove_locked(&mut state, cid, &path, false);
                }
                MISSES.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        // Cache files are immutable after their atomic rename. Eviction only
        // unlinks a path, which leaves an existing mapping valid until the last
        // response Bytes drops it. No code path mutates a published cache file.
        let bytes = match unsafe { MmapOptions::new().map(&file) } {
            Ok(mapping) => Bytes::from_owner(mapping),
            Err(_) => {
                if let Ok(mut state) = self.state.lock() {
                    self.remove_locked(&mut state, cid, &path, false);
                }
                MISSES.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        if bytes.len() != expected_size || !cid.verify(&bytes) {
            if let Ok(mut state) = self.state.lock() {
                self.remove_locked(&mut state, cid, &path, true);
            }
            MISSES.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let mut state = self.state.lock().ok()?;
        state.clock = state.clock.saturating_add(1);
        let clock = state.clock;
        if let Some(entry) = state.entries.get_mut(cid) {
            entry.frequency = entry.frequency.saturating_add(1);
            entry.last_access = clock;
        }
        HITS.fetch_add(1, Ordering::Relaxed);
        READ_BYTES.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Some(bytes)
    }

    #[cfg(test)]
    pub(super) fn observe_and_maybe_put(&self, cid: &Cid, bytes: &[u8]) {
        self.observe_range_and_maybe_put(cid, bytes, 0..bytes.len());
    }

    pub(super) fn observe_range_and_maybe_put(
        &self,
        cid: &Cid,
        bytes: &[u8],
        observation: Range<usize>,
    ) {
        self.observe_and_maybe_put_segments(cid, bytes.len(), &[bytes], observation);
    }

    pub(super) fn observe_and_maybe_put_frames(&self, cid: &Cid, segments: &[Bytes], size: usize) {
        self.observe_range_and_maybe_put_frames(cid, segments, size, 0..size);
    }

    pub(super) fn observe_range_and_maybe_put_frames(
        &self,
        cid: &Cid,
        segments: &[Bytes],
        size: usize,
        observation: Range<usize>,
    ) {
        let segments = segments.iter().map(Bytes::as_ref).collect::<Vec<_>>();
        self.observe_and_maybe_put_segments(cid, size, &segments, observation);
    }

    fn observe_and_maybe_put_segments(
        &self,
        cid: &Cid,
        size: usize,
        segments: &[&[u8]],
        observation: Range<usize>,
    ) {
        if cid.codec != CODEC_RAW
            || size as u64 > self.capacity_bytes
            || segments.iter().map(|segment| segment.len()).sum::<usize>() != size
            || observation.start >= observation.end
            || observation.end > size
        {
            BYPASSES.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            BYPASSES.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if state.entries.contains_key(cid) || state.pending.contains(cid) {
            return;
        }
        let candidate = AdmissionCandidate {
            cid: cid.clone(),
            start: observation.start,
            end: observation.end,
        };
        let observations = state.candidates.entry(candidate.clone()).or_default();
        *observations = observations.saturating_add(1);
        if *observations < self.admission_hits {
            BYPASSES.fetch_add(1, Ordering::Relaxed);
            if state.candidates.len() > 100_000 {
                state.candidates.clear();
            }
            return;
        }
        state.candidates.remove(&candidate);
        state
            .candidates
            .retain(|candidate, _| candidate.cid != *cid);
        while state.used_bytes.saturating_add(size as u64) > self.capacity_bytes {
            let Some(victim) = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| (entry.frequency, entry.last_access))
                .map(|(cid, _)| cid.clone())
            else {
                break;
            };
            let path = self.path(&victim);
            self.remove_locked(&mut state, &victim, &path, false);
            EVICTIONS.fetch_add(1, Ordering::Relaxed);
        }
        if state.used_bytes.saturating_add(size as u64) > self.capacity_bytes {
            BYPASSES.fetch_add(1, Ordering::Relaxed);
            return;
        }
        state.used_bytes = state.used_bytes.saturating_add(size as u64);
        state.pending.insert(cid.clone());
        drop(state);
        let path = self.path(cid);
        let Some(parent) = path.parent() else {
            self.cancel_pending(cid, size as u64);
            BYPASSES.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if fs::create_dir_all(parent).is_err() {
            self.cancel_pending(cid, size as u64);
            BYPASSES.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let temp = path.with_extension(format!("tmp-{}", std::process::id()));
        let write_result = File::create(&temp).and_then(|mut file| {
            for segment in segments {
                file.write_all(segment)?;
            }
            Ok(())
        });
        if write_result.is_err() || fs::rename(&temp, &path).is_err() {
            let _ = fs::remove_file(temp);
            self.cancel_pending(cid, size as u64);
            BYPASSES.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            let _ = fs::remove_file(path);
            BYPASSES.fetch_add(1, Ordering::Relaxed);
            return;
        };
        state.pending.remove(cid);
        state.clock = state.clock.saturating_add(1);
        let clock = state.clock;
        state.entries.insert(
            cid.clone(),
            CacheEntry {
                size: size as u64,
                frequency: u64::from(self.admission_hits),
                last_access: clock,
            },
        );
        ADMISSIONS.fetch_add(1, Ordering::Relaxed);
        WRITE_BYTES.fetch_add(size as u64, Ordering::Relaxed);
    }

    fn reconcile(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "reconstructed cache lock poisoned".to_string())?;
        for first in fs::read_dir(&self.root)
            .map_err(|error| format!("failed to scan reconstructed cache: {error}"))?
        {
            let Ok(first) = first else { continue };
            let Ok(file_type) = first.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                let _ = fs::remove_file(first.path());
                continue;
            }
            let Ok(files) = fs::read_dir(first.path()) else {
                continue;
            };
            for file in files.flatten() {
                let path = file.path();
                let Some(cid) = cid_from_cache_path(&path) else {
                    let _ = fs::remove_file(path);
                    continue;
                };
                let Ok(metadata) = file.metadata() else {
                    continue;
                };
                if !metadata.is_file() || metadata.len() > self.capacity_bytes {
                    let _ = fs::remove_file(path);
                    continue;
                }
                state.clock = state.clock.saturating_add(1);
                let clock = state.clock;
                state.used_bytes = state.used_bytes.saturating_add(metadata.len());
                state.entries.insert(
                    cid,
                    CacheEntry {
                        size: metadata.len(),
                        frequency: 1,
                        last_access: clock,
                    },
                );
            }
        }
        while state.used_bytes > self.capacity_bytes {
            let Some(victim) = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_access)
                .map(|(cid, _)| cid.clone())
            else {
                break;
            };
            let path = self.path(&victim);
            self.remove_locked(&mut state, &victim, &path, false);
        }
        Ok(())
    }

    fn path(&self, cid: &Cid) -> PathBuf {
        let digest = hex::encode(cid.digest);
        self.root
            .join(&digest[..2])
            .join(format!("{}-{digest}.cache", cid.codec.0))
    }

    fn remove_locked(&self, state: &mut CacheState, cid: &Cid, path: &Path, corrupt: bool) {
        if let Some(entry) = state.entries.remove(cid) {
            state.used_bytes = state.used_bytes.saturating_sub(entry.size);
        }
        let _ = fs::remove_file(path);
        if corrupt {
            INTEGRITY_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn cancel_pending(&self, cid: &Cid, bytes: u64) {
        if let Ok(mut state) = self.state.lock()
            && state.pending.remove(cid)
        {
            state.used_bytes = state.used_bytes.saturating_sub(bytes);
        }
    }
}

fn cid_from_cache_path(path: &Path) -> Option<Cid> {
    let name = path.file_name()?.to_str()?.strip_suffix(".cache")?;
    let (codec, digest) = name.split_once('-')?;
    let codec = codec.parse::<u64>().ok()?;
    let digest = hex::decode(digest).ok()?;
    let digest: [u8; 32] = digest.try_into().ok()?;
    Some(Cid {
        version: CID_VERSION,
        codec: pepper_types::Codec(codec),
        hash_alg: HashAlg::Blake3,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_on_second_observation_and_rejects_corruption() {
        let root = tempfile::tempdir().unwrap();
        let cache = ReconstructedStripeCache::open(&ReconstructedCacheConfig {
            path: Some(root.path().to_path_buf()),
            max_capacity_bytes: 1024,
            admission_hits: 2,
        })
        .unwrap()
        .unwrap();
        let bytes = vec![7u8; 256];
        let cid = Cid::new(CODEC_RAW, &bytes);
        assert!(cache.get(&cid, bytes.len()).is_none());
        cache.observe_and_maybe_put(&cid, &bytes);
        assert!(cache.get(&cid, bytes.len()).is_none());
        cache.observe_and_maybe_put(&cid, &bytes);
        assert_eq!(cache.get(&cid, bytes.len()).unwrap(), bytes);
        fs::write(cache.path(&cid), b"bad").unwrap();
        assert!(cache.get(&cid, 256).is_none());
    }

    #[test]
    fn distinct_ranges_do_not_look_like_reuse() {
        let root = tempfile::tempdir().unwrap();
        let cache = ReconstructedStripeCache::open(&ReconstructedCacheConfig {
            path: Some(root.path().to_path_buf()),
            max_capacity_bytes: 1024,
            admission_hits: 2,
        })
        .unwrap()
        .unwrap();
        let bytes = vec![7u8; 256];
        let cid = Cid::new(CODEC_RAW, &bytes);

        cache.observe_range_and_maybe_put(&cid, &bytes, 0..64);
        cache.observe_range_and_maybe_put(&cid, &bytes, 64..128);
        assert!(cache.get(&cid, bytes.len()).is_none());

        cache.observe_range_and_maybe_put(&cid, &bytes, 0..64);
        assert_eq!(cache.get(&cid, bytes.len()).unwrap(), bytes);
    }

    #[test]
    fn bounds_concurrent_cache_writes() {
        let root = tempfile::tempdir().unwrap();
        let cache = ReconstructedStripeCache::open(&ReconstructedCacheConfig {
            path: Some(root.path().to_path_buf()),
            max_capacity_bytes: 1024,
            admission_hits: 1,
        })
        .unwrap()
        .unwrap();
        let slots = (0..MAX_CONCURRENT_WRITES)
            .map(|_| cache.try_write_slot().expect("configured cache write slot"))
            .collect::<Vec<_>>();
        assert!(cache.try_write_slot().is_none());
        drop(slots);
        assert!(cache.try_write_slot().is_some());
    }

    #[test]
    fn evicts_low_frequency_entries_at_capacity() {
        let root = tempfile::tempdir().unwrap();
        let cache = ReconstructedStripeCache::open(&ReconstructedCacheConfig {
            path: Some(root.path().to_path_buf()),
            max_capacity_bytes: 512,
            admission_hits: 1,
        })
        .unwrap()
        .unwrap();
        let first = vec![1u8; 256];
        let second = vec![2u8; 256];
        let third = vec![3u8; 256];
        let first_cid = Cid::new(CODEC_RAW, &first);
        let second_cid = Cid::new(CODEC_RAW, &second);
        let third_cid = Cid::new(CODEC_RAW, &third);
        cache.observe_and_maybe_put(&first_cid, &first);
        cache.observe_and_maybe_put(&second_cid, &second);
        assert!(cache.get(&first_cid, first.len()).is_some());
        cache.observe_and_maybe_put(&third_cid, &third);
        assert!(cache.get(&first_cid, first.len()).is_some());
        assert!(cache.get(&third_cid, third.len()).is_some());
        assert!(cache.get(&second_cid, second.len()).is_none());
    }

    #[test]
    fn reconciles_disposable_entries_after_restart() {
        let root = tempfile::tempdir().unwrap();
        let config = ReconstructedCacheConfig {
            path: Some(root.path().to_path_buf()),
            max_capacity_bytes: 1024,
            admission_hits: 1,
        };
        let bytes = vec![9u8; 256];
        let cid = Cid::new(CODEC_RAW, &bytes);
        {
            let cache = ReconstructedStripeCache::open(&config).unwrap().unwrap();
            cache.observe_and_maybe_put(&cid, &bytes);
        }
        let cache = ReconstructedStripeCache::open(&config).unwrap().unwrap();
        assert_eq!(cache.get(&cid, bytes.len()).unwrap(), bytes);
    }
}
