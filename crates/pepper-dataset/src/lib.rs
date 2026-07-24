// SPDX-License-Identifier: Apache-2.0

//! Product-neutral contracts for versioned immutable datasets.
//!
//! A dataset publishes a small root descriptor over an immutable sparse or
//! fixed-fanout index. Products retain their own canonical formats and policy;
//! this crate owns exact-base, changed-frontier, bulk-read, pack-read, and
//! snapshot-retention invariants.

use async_trait::async_trait;
use pepper_types::Cid;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DatasetError {
    #[error("invalid dataset: {0}")]
    Invalid(String),
    #[error("dataset limit exceeded: {0}")]
    Limit(String),
    #[error("dataset storage failed: {0}")]
    Storage(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndexKind {
    SparseMerkle,
    FixedFanout { fanout: u16, depth: u8 },
}

impl IndexKind {
    pub fn depth(self) -> usize {
        match self {
            Self::SparseMerkle => 256,
            Self::FixedFanout { depth, .. } => usize::from(depth),
        }
    }

    fn validate(self) -> Result<(), DatasetError> {
        match self {
            Self::SparseMerkle => Ok(()),
            Self::FixedFanout { fanout, depth }
                if fanout >= 2 && depth > 0 && fanout.is_power_of_two() =>
            {
                Ok(())
            }
            Self::FixedFanout { .. } => Err(DatasetError::Invalid(
                "fixed-fanout index requires a power-of-two fanout and nonzero depth".into(),
            )),
        }
    }
}

/// Product-independent projection of a canonical root descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetRoot {
    pub product: String,
    pub format_version: u32,
    pub generation: u64,
    pub index_kind: IndexKind,
    pub index_root: Cid,
    pub previous_root: Option<Cid>,
    pub logical_bytes: u64,
}

impl DatasetRoot {
    pub fn validate(&self) -> Result<(), DatasetError> {
        if self.product.is_empty()
            || self.product.len() > 64
            || self.format_version == 0
            || self.generation == 0
        {
            return Err(DatasetError::Invalid(
                "invalid root descriptor header".into(),
            ));
        }
        self.index_kind.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactBase {
    pub generation: u64,
    pub root: Cid,
}

/// The only immutable objects that incremental validation may inspect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationFrontier {
    pub changed_keys: usize,
    pub index_depth: usize,
    pub candidate_index_root: Cid,
    pub new_index_nodes: Vec<Cid>,
    pub new_data_roots: Vec<Cid>,
    pub verified_descendants: Vec<Cid>,
}

impl MutationFrontier {
    pub fn validate(&self) -> Result<FrontierStats, DatasetError> {
        if self.index_depth == 0 || self.index_depth > 65_536 {
            return Err(DatasetError::Limit("index depth".into()));
        }
        let maximum_nodes = 1usize
            .checked_add(
                self.changed_keys
                    .checked_mul(self.index_depth)
                    .ok_or_else(|| DatasetError::Limit("frontier node bound".into()))?,
            )
            .ok_or_else(|| DatasetError::Limit("frontier node bound".into()))?;
        if self.new_index_nodes.len() > maximum_nodes {
            return Err(DatasetError::Limit(format!(
                "index frontier contains {} nodes, bound is {maximum_nodes}",
                self.new_index_nodes.len()
            )));
        }
        if self.changed_keys == 0 {
            if !self.new_index_nodes.is_empty() || !self.new_data_roots.is_empty() {
                return Err(DatasetError::Invalid(
                    "unchanged frontier declares new objects".into(),
                ));
            }
        } else if !self.new_index_nodes.contains(&self.candidate_index_root) {
            return Err(DatasetError::Invalid(
                "changed candidate index root is absent from its frontier".into(),
            ));
        }

        let mut unique = HashSet::new();
        for cid in self
            .new_index_nodes
            .iter()
            .chain(&self.new_data_roots)
            .chain(&self.verified_descendants)
        {
            if !unique.insert(cid.clone()) {
                return Err(DatasetError::Invalid(
                    "frontier categories overlap or contain duplicates".into(),
                ));
            }
        }
        Ok(FrontierStats {
            changed_keys: self.changed_keys,
            index_nodes: self.new_index_nodes.len(),
            data_roots: self.new_data_roots.len(),
            verified_descendants: self.verified_descendants.len(),
            validation_objects: 1 + unique.len(),
            maximum_index_nodes: maximum_nodes,
        })
    }

    /// Exact durability set for a newly encoded outer root.
    pub fn required_objects(&self, outer_root: Cid) -> Result<Vec<Cid>, DatasetError> {
        self.validate()?;
        let mut required = Vec::with_capacity(
            1 + self.new_index_nodes.len()
                + self.new_data_roots.len()
                + self.verified_descendants.len(),
        );
        required.push(outer_root);
        required.extend(self.new_index_nodes.iter().cloned());
        required.extend(self.new_data_roots.iter().cloned());
        required.extend(self.verified_descendants.iter().cloned());
        let mut seen = HashSet::new();
        if required.iter().any(|cid| !seen.insert(cid.clone())) {
            return Err(DatasetError::Invalid(
                "outer root overlaps its strong-link frontier".into(),
            ));
        }
        Ok(required)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrontierStats {
    pub changed_keys: usize,
    pub index_nodes: usize,
    pub data_roots: usize,
    pub verified_descendants: usize,
    pub validation_objects: usize,
    pub maximum_index_nodes: usize,
}

/// A candidate whose immutable bytes exist but whose authoritative pointer has
/// not yet moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedDatasetArtifact {
    pub exact_base: ExactBase,
    pub candidate_root: Cid,
    pub descriptor: DatasetRoot,
    pub frontier: MutationFrontier,
}

impl PreparedDatasetArtifact {
    pub fn validate(&self) -> Result<FrontierStats, DatasetError> {
        self.descriptor.validate()?;
        if self.descriptor.generation != self.exact_base.generation.saturating_add(1)
            || self.descriptor.previous_root.as_ref() != Some(&self.exact_base.root)
            || self.descriptor.index_root != self.frontier.candidate_index_root
            || self.candidate_root == self.exact_base.root
        {
            return Err(DatasetError::Invalid(
                "candidate does not advance the exact protected base".into(),
            ));
        }
        self.frontier.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkRead<V> {
    pub values: Vec<Option<V>>,
    pub unique_index_nodes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexUpdate<R> {
    pub root: R,
    pub frontier: MutationFrontier,
}

/// Adapter boundary implemented by product-owned sparse and dense index
/// formats. Results must preserve caller order and read a physical node at
/// most once within a bulk operation.
#[async_trait]
pub trait IndexAdapter: Send + Sync {
    type Root: Send + Sync;
    type Key: Send + Sync;
    type Value: Send;
    type Mutation: Send;

    fn kind(&self) -> IndexKind;

    async fn get_many(
        &self,
        root: &Self::Root,
        keys: &[Self::Key],
    ) -> Result<BulkRead<Self::Value>, DatasetError>;

    async fn apply(
        &self,
        root: &Self::Root,
        mutations: Vec<Self::Mutation>,
    ) -> Result<IndexUpdate<Self::Root>, DatasetError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackSlice {
    pub output_index: usize,
    pub pack: Cid,
    pub offset: u32,
    pub length: u32,
    pub blake3_hex: Option<String>,
}

/// Request-scoped plan that groups immutable slices by backing pack while
/// retaining the caller's output order.
#[derive(Debug, Clone)]
pub struct PackReadPlan {
    slices: Vec<PackSlice>,
    packs: Vec<Cid>,
    output_bytes: usize,
}

impl PackReadPlan {
    pub fn build(
        mut slices: Vec<PackSlice>,
        maximum_slices: usize,
        maximum_output_bytes: usize,
    ) -> Result<Self, DatasetError> {
        if slices.is_empty() || slices.len() > maximum_slices {
            return Err(DatasetError::Limit("pack slice count".into()));
        }
        slices.sort_by_key(|slice| slice.output_index);
        let mut output_bytes = 0usize;
        for (expected, slice) in slices.iter().enumerate() {
            if slice.output_index != expected || slice.length == 0 {
                return Err(DatasetError::Invalid(
                    "pack slices must cover each output position exactly once".into(),
                ));
            }
            slice
                .offset
                .checked_add(slice.length)
                .ok_or_else(|| DatasetError::Limit("pack slice range".into()))?;
            if let Some(digest) = &slice.blake3_hex
                && (digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
            {
                return Err(DatasetError::Invalid("invalid BLAKE3 digest".into()));
            }
            output_bytes = output_bytes
                .checked_add(slice.length as usize)
                .ok_or_else(|| DatasetError::Limit("pack output bytes".into()))?;
        }
        if output_bytes > maximum_output_bytes {
            return Err(DatasetError::Limit("pack output bytes".into()));
        }
        let mut seen = HashSet::new();
        let mut packs = Vec::new();
        for slice in &slices {
            if seen.insert(slice.pack.clone()) {
                packs.push(slice.pack.clone());
            }
        }
        Ok(Self {
            slices,
            packs,
            output_bytes,
        })
    }

    pub fn packs(&self) -> &[Cid] {
        &self.packs
    }

    pub fn distinct_pack_count(&self) -> usize {
        self.packs.len()
    }

    pub fn output_bytes(&self) -> usize {
        self.output_bytes
    }

    pub fn assemble(&self, packs: &HashMap<Cid, Vec<u8>>) -> Result<Vec<u8>, DatasetError> {
        let mut output = Vec::with_capacity(self.output_bytes);
        for slice in &self.slices {
            let pack = packs
                .get(&slice.pack)
                .ok_or_else(|| DatasetError::Storage(format!("missing pack {}", slice.pack)))?;
            let start = slice.offset as usize;
            let end = start
                .checked_add(slice.length as usize)
                .filter(|end| *end <= pack.len())
                .ok_or_else(|| {
                    DatasetError::Invalid("pack slice exceeds its backing pack".into())
                })?;
            let bytes = &pack[start..end];
            if let Some(expected) = &slice.blake3_hex
                && blake3::hash(bytes).to_hex().as_str() != expected
            {
                return Err(DatasetError::Invalid(format!(
                    "pack slice {} failed verification",
                    slice.output_index
                )));
            }
            output.extend_from_slice(bytes);
        }
        Ok(output)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheAdmission {
    ReuseExpected,
    Scan,
}

#[derive(Debug)]
struct CacheEntry {
    bytes: Arc<Vec<u8>>,
    snapshots: HashSet<Cid>,
}

#[derive(Debug)]
struct CacheState {
    entries: HashMap<Cid, CacheEntry>,
    order: VecDeque<Cid>,
    active_snapshots: HashMap<Cid, usize>,
    scan_ghosts: HashSet<Cid>,
    bytes: usize,
}

#[derive(Debug)]
struct SnapshotCacheInner {
    maximum_bytes: usize,
    state: Mutex<CacheState>,
}

/// Bounded immutable cache whose eviction policy understands snapshot leases.
/// One-pass scans are ghosted instead of admitted, preventing cache pollution.
#[derive(Debug, Clone)]
pub struct SnapshotCache {
    inner: Arc<SnapshotCacheInner>,
}

impl SnapshotCache {
    pub fn new(maximum_bytes: usize) -> Self {
        Self {
            inner: Arc::new(SnapshotCacheInner {
                maximum_bytes,
                state: Mutex::new(CacheState {
                    entries: HashMap::new(),
                    order: VecDeque::new(),
                    active_snapshots: HashMap::new(),
                    scan_ghosts: HashSet::new(),
                    bytes: 0,
                }),
            }),
        }
    }

    pub fn lease(&self, snapshot: Cid) -> SnapshotLease {
        if let Ok(mut state) = self.inner.state.lock() {
            *state.active_snapshots.entry(snapshot.clone()).or_default() += 1;
        }
        SnapshotLease {
            snapshot,
            inner: self.inner.clone(),
        }
    }

    pub fn get(&self, cid: &Cid) -> Option<Arc<Vec<u8>>> {
        let mut state = self.inner.state.lock().ok()?;
        let bytes = state.entries.get(cid)?.bytes.clone();
        touch(&mut state.order, cid);
        Some(bytes)
    }

    /// Associate an already admitted immutable entry with a snapshot so an
    /// active lease protects it from eviction.
    pub fn retain_for_snapshot(&self, snapshot: Cid, cid: &Cid) -> bool {
        let Ok(mut state) = self.inner.state.lock() else {
            return false;
        };
        let Some(entry) = state.entries.get_mut(cid) else {
            return false;
        };
        entry.snapshots.insert(snapshot);
        true
    }

    pub fn insert_verified(
        &self,
        snapshot: Option<Cid>,
        cid: Cid,
        bytes: Vec<u8>,
        admission: CacheAdmission,
    ) -> bool {
        if !cid.verify(&bytes) {
            return false;
        }
        self.insert(snapshot, cid, bytes, admission)
    }

    pub fn insert_resolved(
        &self,
        snapshot: Option<Cid>,
        cid: Cid,
        bytes: Vec<u8>,
        admission: CacheAdmission,
    ) -> bool {
        self.insert(snapshot, cid, bytes, admission)
    }

    fn insert(
        &self,
        snapshot: Option<Cid>,
        cid: Cid,
        bytes: Vec<u8>,
        admission: CacheAdmission,
    ) -> bool {
        if bytes.len() > self.inner.maximum_bytes {
            return false;
        }
        let Ok(mut state) = self.inner.state.lock() else {
            return false;
        };
        if let Some(entry) = state.entries.get_mut(&cid) {
            if let Some(snapshot) = snapshot {
                entry.snapshots.insert(snapshot);
            }
            touch(&mut state.order, &cid);
            return true;
        }
        if admission == CacheAdmission::Scan && !state.scan_ghosts.remove(&cid) {
            state.scan_ghosts.insert(cid);
            return false;
        }
        while state.bytes.saturating_add(bytes.len()) > self.inner.maximum_bytes {
            let Some(victim_index) = state.order.iter().position(|candidate| {
                state.entries.get(candidate).is_some_and(|entry| {
                    entry
                        .snapshots
                        .iter()
                        .all(|snapshot| !state.active_snapshots.contains_key(snapshot))
                })
            }) else {
                return false;
            };
            let victim = state.order.remove(victim_index).expect("victim exists");
            if let Some(removed) = state.entries.remove(&victim) {
                state.bytes = state.bytes.saturating_sub(removed.bytes.len());
            }
        }
        let mut snapshots = HashSet::new();
        if let Some(snapshot) = snapshot {
            snapshots.insert(snapshot);
        }
        state.bytes += bytes.len();
        state.order.push_back(cid.clone());
        state.entries.insert(
            cid,
            CacheEntry {
                bytes: Arc::new(bytes),
                snapshots,
            },
        );
        true
    }

    pub fn current_bytes(&self) -> usize {
        self.inner.state.lock().map_or(0, |state| state.bytes)
    }
}

fn touch(order: &mut VecDeque<Cid>, cid: &Cid) {
    if let Some(index) = order.iter().position(|item| item == cid) {
        order.remove(index);
    }
    order.push_back(cid.clone());
}

#[derive(Debug)]
pub struct SnapshotLease {
    snapshot: Cid,
    inner: Arc<SnapshotCacheInner>,
}

impl Clone for SnapshotLease {
    fn clone(&self) -> Self {
        if let Ok(mut state) = self.inner.state.lock() {
            *state
                .active_snapshots
                .entry(self.snapshot.clone())
                .or_default() += 1;
        }
        Self {
            snapshot: self.snapshot.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl Drop for SnapshotLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.state.lock()
            && let Some(count) = state.active_snapshots.get_mut(&self.snapshot)
        {
            *count -= 1;
            if *count == 0 {
                state.active_snapshots.remove(&self.snapshot);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_types::{CODEC_RAW, CODEC_SQLITE_PAGE_TABLE};

    fn cid(marker: u8) -> Cid {
        Cid::new(CODEC_SQLITE_PAGE_TABLE, &[marker])
    }

    #[test]
    fn frontier_work_is_changed_path_bounded_and_history_independent() {
        for retained_roots in [1usize, 1_000] {
            for changed in [1usize, 16, 256] {
                let node_count = 1 + changed * 4;
                let new_index_nodes = (0..node_count)
                    .map(|index| Cid::new(CODEC_SQLITE_PAGE_TABLE, &index.to_be_bytes()))
                    .collect::<Vec<_>>();
                let frontier = MutationFrontier {
                    changed_keys: changed,
                    index_depth: 4,
                    candidate_index_root: new_index_nodes[0].clone(),
                    new_index_nodes,
                    new_data_roots: Vec::new(),
                    verified_descendants: Vec::new(),
                };
                let stats = frontier.validate().unwrap();
                assert_eq!(stats.maximum_index_nodes, node_count);
                assert_eq!(stats.index_nodes, node_count);
                assert!(retained_roots >= 1); // history is deliberately not an input.
            }
        }
    }

    #[test]
    fn prepared_artifact_requires_exact_base_and_changed_root() {
        let base = Cid::new(CODEC_RAW, b"base");
        let root = Cid::new(CODEC_RAW, b"root");
        let index = cid(7);
        let artifact = PreparedDatasetArtifact {
            exact_base: ExactBase {
                generation: 8,
                root: base.clone(),
            },
            candidate_root: root,
            descriptor: DatasetRoot {
                product: "sqlite".into(),
                format_version: 1,
                generation: 9,
                index_kind: IndexKind::FixedFanout {
                    fanout: 256,
                    depth: 4,
                },
                index_root: index.clone(),
                previous_root: Some(base),
                logical_bytes: 4096,
            },
            frontier: MutationFrontier {
                changed_keys: 1,
                index_depth: 4,
                candidate_index_root: index.clone(),
                new_index_nodes: vec![index],
                new_data_roots: Vec::new(),
                verified_descendants: Vec::new(),
            },
        };
        assert_eq!(artifact.validate().unwrap().changed_keys, 1);
    }

    #[test]
    fn pack_plan_fetches_each_pack_once_and_restores_order() {
        let first_bytes = b"aaaabbbb".to_vec();
        let second_bytes = b"cccc".to_vec();
        let first = Cid::new(CODEC_RAW, &first_bytes);
        let second = Cid::new(CODEC_RAW, &second_bytes);
        let plan = PackReadPlan::build(
            vec![
                PackSlice {
                    output_index: 2,
                    pack: first.clone(),
                    offset: 4,
                    length: 4,
                    blake3_hex: Some(blake3::hash(b"bbbb").to_hex().to_string()),
                },
                PackSlice {
                    output_index: 0,
                    pack: first.clone(),
                    offset: 0,
                    length: 4,
                    blake3_hex: Some(blake3::hash(b"aaaa").to_hex().to_string()),
                },
                PackSlice {
                    output_index: 1,
                    pack: second.clone(),
                    offset: 0,
                    length: 4,
                    blake3_hex: None,
                },
            ],
            256,
            1024,
        )
        .unwrap();
        assert_eq!(plan.distinct_pack_count(), 2);
        let packs = HashMap::from([(first, first_bytes), (second, second_bytes)]);
        assert_eq!(plan.assemble(&packs).unwrap(), b"aaaaccccbbbb");
    }

    #[test]
    fn cache_leases_bound_eviction_and_scan_pollution() {
        let cache = SnapshotCache::new(8);
        let snapshot = Cid::new(CODEC_RAW, b"snapshot");
        let hot = Cid::new(CODEC_RAW, b"aaaa");
        let other = Cid::new(CODEC_RAW, b"bbbb");
        let scan = Cid::new(CODEC_RAW, b"cccc");
        let lease = cache.lease(snapshot.clone());
        assert!(cache.insert_verified(
            Some(snapshot),
            hot.clone(),
            b"aaaa".to_vec(),
            CacheAdmission::ReuseExpected,
        ));
        assert!(cache.insert_verified(
            None,
            other.clone(),
            b"bbbb".to_vec(),
            CacheAdmission::ReuseExpected,
        ));
        assert!(
            !cache.insert_verified(None, scan.clone(), b"cccc".to_vec(), CacheAdmission::Scan,)
        );
        assert!(cache.get(&hot).is_some());
        assert!(cache.get(&other).is_some());
        assert!(cache.current_bytes() <= 8);
        drop(lease);
        assert!(cache.insert_verified(None, scan.clone(), b"cccc".to_vec(), CacheAdmission::Scan,));
        assert!(cache.current_bytes() <= 8);
        assert!(cache.get(&scan).is_some());
    }
}
