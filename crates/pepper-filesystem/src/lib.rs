// SPDX-License-Identifier: Apache-2.0

//! Canonical immutable snapshot-filesystem descriptors and tree operations.

use async_trait::async_trait;
use pepper_dag::{DagCodecHandler, DagError, TraversalLimits};
use pepper_dataset::{
    BulkRead, DatasetError, DatasetRoot, ExactBase, IndexAdapter, IndexKind, IndexUpdate,
    MutationFrontier, PreparedDatasetArtifact,
};
use pepper_merkle::{
    MapEntry, MerkleLimits, MerkleReadStore, MerkleValue, MerkleWriteStore, Mutation, ScanQuery,
    apply_batch, build_from_sorted, empty_root, get, get_many, scan,
};
use pepper_types::{CODEC_FILESYSTEM_INODE, CODEC_FILESYSTEM_ROOT, Cid, Codec};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    future::Future,
    pin::Pin,
    sync::Mutex,
};
use thiserror::Error;

const ROOT_TYPE: &str = "pepper.filesystem_root";
const INODE_TYPE: &str = "pepper.filesystem_inode";
const VERSION: u32 = 1;
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy)]
pub struct FilesystemLimits {
    pub max_descriptor_bytes: usize,
    pub max_entries: usize,
    pub max_path_bytes: usize,
    pub max_name_bytes: usize,
    pub max_depth: usize,
    pub max_total_bytes: u64,
}
impl Default for FilesystemLimits {
    fn default() -> Self {
        Self {
            max_descriptor_bytes: 1024 * 1024,
            max_entries: 100_000,
            max_path_bytes: 4096,
            max_name_bytes: 255,
            max_depth: 256,
            max_total_bytes: 1 << 40,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InodeKind {
    RegularFile,
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FilesystemMetadataDescriptor {
    pub mode: u32,
}
impl FilesystemMetadataDescriptor {
    pub fn validate(&self) -> Result<(), FilesystemError> {
        if self.mode & !0o777 != 0 {
            return Err(FilesystemError::Invalid("unsupported mode bits".into()));
        }
        Ok(())
    }
}

/// Canonical logical directory entry. The name and inode CID are encoded by
/// the directory Merkle map, avoiding another immutable block per entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntryDescriptor {
    pub name: String,
    pub inode_cid: Cid,
}
impl DirectoryEntryDescriptor {
    pub fn validate(&self, limits: FilesystemLimits) -> Result<(), FilesystemError> {
        validate_path(&self.name, limits)?;
        if self.name.contains('/') || self.inode_cid.codec != CODEC_FILESYSTEM_INODE {
            return Err(FilesystemError::Invalid("invalid directory entry".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InodeDescriptor {
    #[serde(rename = "type")]
    pub descriptor_type: String,
    pub version: u32,
    pub kind: InodeKind,
    pub mode: u32,
    pub logical_size: u64,
    pub content_cid: Option<Cid>,
    pub directory_root_cid: Option<Cid>,
}
impl InodeDescriptor {
    pub fn file(content_cid: Cid, logical_size: u64, mode: u32) -> Self {
        Self {
            descriptor_type: INODE_TYPE.into(),
            version: VERSION,
            kind: InodeKind::RegularFile,
            mode,
            logical_size,
            content_cid: Some(content_cid),
            directory_root_cid: None,
        }
    }
    pub fn directory(root: Cid, mode: u32) -> Self {
        Self {
            descriptor_type: INODE_TYPE.into(),
            version: VERSION,
            kind: InodeKind::Directory,
            mode,
            logical_size: 0,
            content_cid: None,
            directory_root_cid: Some(root),
        }
    }
    pub fn validate(&self) -> Result<(), FilesystemError> {
        if self.descriptor_type != INODE_TYPE
            || self.version != VERSION
            || (FilesystemMetadataDescriptor { mode: self.mode })
                .validate()
                .is_err()
        {
            return Err(FilesystemError::Invalid(
                "unsupported inode type, version, or mode".into(),
            ));
        }
        match self.kind {
            InodeKind::RegularFile
                if self.content_cid.is_some() && self.directory_root_cid.is_none() =>
            {
                Ok(())
            }
            InodeKind::Directory
                if self.content_cid.is_none()
                    && self.directory_root_cid.is_some()
                    && self.logical_size == 0 =>
            {
                Ok(())
            }
            _ => Err(FilesystemError::Invalid("inconsistent inode links".into())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FilesystemRootDescriptor {
    #[serde(rename = "type")]
    pub descriptor_type: String,
    pub version: u32,
    pub root_inode_cid: Cid,
    pub creation_revision: u64,
    pub file_count: u64,
    pub directory_count: u64,
    pub logical_bytes: u64,
    pub previous_root_cid: Option<Cid>,
}

impl FilesystemRootDescriptor {
    pub fn dataset_root(&self) -> DatasetRoot {
        DatasetRoot {
            product: "filesystem".into(),
            format_version: self.version,
            generation: self.creation_revision,
            index_kind: IndexKind::SparseMerkle,
            index_root: self.root_inode_cid.clone(),
            previous_root: self.previous_root_cid.clone(),
            logical_bytes: self.logical_bytes,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TreeInputEntry {
    pub path: String,
    pub kind: InodeKind,
    pub mode: u32,
    pub logical_size: u64,
    pub content_cid: Option<Cid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeMutation {
    Put { entry: TreeInputEntry },
    Delete { path: String },
}

impl TreeMutation {
    fn path(&self) -> &str {
        match self {
            Self::Put { entry } => &entry.path,
            Self::Delete { path } => path,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreeEntry {
    pub path: String,
    pub inode_cid: Cid,
    pub inode: InodeDescriptor,
}

#[derive(Debug, Clone)]
pub struct FilesystemBuild {
    pub root_cid: Cid,
    pub descriptor: FilesystemRootDescriptor,
    /// A validated exact-base artifact for every non-initial snapshot.
    pub prepared_artifact: Option<PreparedDatasetArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    Added,
    Removed,
    Modified,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffEntry {
    pub path: String,
    pub kind: DiffKind,
}

#[derive(Debug, Error)]
pub enum FilesystemError {
    #[error("invalid filesystem descriptor: {0}")]
    Invalid(String),
    #[error("filesystem descriptor is not canonical")]
    NonCanonical,
    #[error("filesystem storage failed: {0}")]
    Storage(String),
    #[error("filesystem tree exceeds configured limits")]
    Limit,
}

/// Sparse-Merkle adapter used by filesystem directories. It adds
/// request-scoped bulk-read deduplication and reports the exact immutable
/// write frontier without changing the canonical Merkle representation.
pub struct FilesystemIndexAdapter<'a, S: MerkleWriteStore + ?Sized> {
    store: &'a S,
    limits: MerkleLimits,
}

impl<'a, S: MerkleWriteStore + ?Sized> FilesystemIndexAdapter<'a, S> {
    pub fn new(store: &'a S, limits: MerkleLimits) -> Self {
        Self { store, limits }
    }
}

struct TrackingMerkleStore<'a, S: MerkleWriteStore + ?Sized> {
    inner: &'a S,
    writes: Mutex<Vec<Cid>>,
}

struct TrackingFilesystemStore<'a, S: MerkleWriteStore + ?Sized> {
    inner: &'a S,
    writes: Mutex<Vec<Cid>>,
}

#[async_trait]
impl<S: MerkleWriteStore + ?Sized> MerkleReadStore for TrackingFilesystemStore<'_, S> {
    async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
        self.inner.get(cid).await
    }
}

#[async_trait]
impl<S: MerkleWriteStore + ?Sized> MerkleWriteStore for TrackingFilesystemStore<'_, S> {
    async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
        let cid = self.inner.put(codec, payload).await?;
        self.writes
            .lock()
            .map_err(|_| "filesystem build write tracker poisoned".to_string())?
            .push(cid.clone());
        Ok(cid)
    }
}

#[async_trait]
impl<S: MerkleWriteStore + ?Sized> MerkleReadStore for TrackingMerkleStore<'_, S> {
    async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
        self.inner.get(cid).await
    }
}

#[async_trait]
impl<S: MerkleWriteStore + ?Sized> MerkleWriteStore for TrackingMerkleStore<'_, S> {
    async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
        let cid = self.inner.put(codec, payload).await?;
        self.writes
            .lock()
            .map_err(|_| "filesystem index write tracker poisoned".to_string())?
            .push(cid.clone());
        Ok(cid)
    }
}

#[async_trait]
impl<S: MerkleWriteStore + ?Sized> IndexAdapter for FilesystemIndexAdapter<'_, S> {
    type Root = Cid;
    type Key = Vec<u8>;
    type Value = MerkleValue;
    type Mutation = Mutation;

    fn kind(&self) -> IndexKind {
        IndexKind::SparseMerkle
    }

    async fn get_many(
        &self,
        root: &Self::Root,
        keys: &[Self::Key],
    ) -> Result<BulkRead<Self::Value>, DatasetError> {
        let result = get_many(self.store, root, keys, self.limits)
            .await
            .map_err(|error| DatasetError::Storage(error.to_string()))?;
        Ok(BulkRead {
            values: result.values,
            unique_index_nodes: result.unique_nodes_read,
        })
    }

    async fn apply(
        &self,
        root: &Self::Root,
        mutations: Vec<Self::Mutation>,
    ) -> Result<IndexUpdate<Self::Root>, DatasetError> {
        let changed_keys = mutations.len();
        let mut new_data_roots = mutations
            .iter()
            .filter_map(|mutation| match mutation {
                Mutation::Put { value, .. } => Some(value.cid.clone()),
                Mutation::Delete { .. } => None,
            })
            .collect::<Vec<_>>();
        new_data_roots.sort_by_key(ToString::to_string);
        new_data_roots.dedup();
        let tracking = TrackingMerkleStore {
            inner: self.store,
            writes: Mutex::new(Vec::new()),
        };
        let candidate = pepper_merkle::apply_batch(&tracking, root, &mutations, self.limits)
            .await
            .map_err(|error| DatasetError::Storage(error.to_string()))?;
        let mut new_index_nodes = tracking
            .writes
            .into_inner()
            .map_err(|_| DatasetError::Storage("filesystem write tracker poisoned".into()))?;
        let mut seen = HashSet::new();
        new_index_nodes.retain(|cid| seen.insert(cid.clone()));
        let frontier = MutationFrontier {
            changed_keys,
            index_depth: self.limits.max_depth,
            candidate_index_root: candidate.clone(),
            new_index_nodes,
            new_data_roots,
            verified_descendants: Vec::new(),
        };
        frontier.validate()?;
        Ok(IndexUpdate {
            root: candidate,
            frontier,
        })
    }
}

fn validate_path(path: &str, limits: FilesystemLimits) -> Result<(), FilesystemError> {
    if path.is_empty()
        || path.len() > limits.max_path_bytes
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains('\0')
    {
        return Err(FilesystemError::Invalid(format!("unsafe path {path:?}")));
    }
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() > limits.max_depth
        || parts.iter().any(|part| {
            part.is_empty() || *part == "." || *part == ".." || part.len() > limits.max_name_bytes
        })
    {
        return Err(FilesystemError::Invalid(format!("unsafe path {path:?}")));
    }
    Ok(())
}
fn parent_name(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}
fn encode<T: Serialize>(value: &T, max: usize) -> Result<Vec<u8>, FilesystemError> {
    let bytes = serde_json::to_vec(value).map_err(|e| FilesystemError::Invalid(e.to_string()))?;
    if bytes.len() > max {
        return Err(FilesystemError::Limit);
    }
    Ok(bytes)
}
fn decode<T: DeserializeOwned + Serialize>(
    payload: &[u8],
    max: usize,
) -> Result<T, FilesystemError> {
    if payload.len() > max {
        return Err(FilesystemError::Limit);
    }
    let value =
        serde_json::from_slice(payload).map_err(|e| FilesystemError::Invalid(e.to_string()))?;
    if encode(&value, max)? != payload {
        return Err(FilesystemError::NonCanonical);
    }
    Ok(value)
}
async fn put_typed<S: MerkleWriteStore + ?Sized, T: Serialize>(
    store: &S,
    codec: Codec,
    value: &T,
    limits: FilesystemLimits,
) -> Result<Cid, FilesystemError> {
    let bytes = encode(value, limits.max_descriptor_bytes)?;
    let expected = Cid::new(codec, &bytes);
    let actual = store
        .put(codec, bytes)
        .await
        .map_err(FilesystemError::Storage)?;
    if actual != expected {
        return Err(FilesystemError::Storage(
            "store returned a different CID".into(),
        ));
    }
    Ok(actual)
}
async fn get_typed<S: MerkleReadStore + ?Sized, T: DeserializeOwned + Serialize>(
    store: &S,
    cid: &Cid,
    codec: Codec,
    limits: FilesystemLimits,
) -> Result<T, FilesystemError> {
    if cid.codec != codec {
        return Err(FilesystemError::Invalid(
            "unexpected descriptor codec".into(),
        ));
    }
    let payload = store.get(cid).await.map_err(FilesystemError::Storage)?;
    if !cid.verify(&payload) {
        return Err(FilesystemError::Storage("CID verification failed".into()));
    }
    decode(&payload, limits.max_descriptor_bytes)
}
pub async fn put_inode<S: MerkleWriteStore + ?Sized>(
    store: &S,
    inode: &InodeDescriptor,
    limits: FilesystemLimits,
) -> Result<Cid, FilesystemError> {
    inode.validate()?;
    put_typed(store, CODEC_FILESYSTEM_INODE, inode, limits).await
}
pub async fn get_inode<S: MerkleReadStore + ?Sized>(
    store: &S,
    cid: &Cid,
    limits: FilesystemLimits,
) -> Result<InodeDescriptor, FilesystemError> {
    let inode: InodeDescriptor = get_typed(store, cid, CODEC_FILESYSTEM_INODE, limits).await?;
    inode.validate()?;
    Ok(inode)
}
pub async fn put_root<S: MerkleWriteStore + ?Sized>(
    store: &S,
    root: &FilesystemRootDescriptor,
    limits: FilesystemLimits,
) -> Result<Cid, FilesystemError> {
    if root.descriptor_type != ROOT_TYPE
        || root.version != VERSION
        || root.root_inode_cid.codec != CODEC_FILESYSTEM_INODE
    {
        return Err(FilesystemError::Invalid("invalid filesystem root".into()));
    }
    put_typed(store, CODEC_FILESYSTEM_ROOT, root, limits).await
}
pub async fn get_root<S: MerkleReadStore + ?Sized>(
    store: &S,
    cid: &Cid,
    limits: FilesystemLimits,
) -> Result<FilesystemRootDescriptor, FilesystemError> {
    let root: FilesystemRootDescriptor =
        get_typed(store, cid, CODEC_FILESYSTEM_ROOT, limits).await?;
    if root.descriptor_type != ROOT_TYPE
        || root.version != VERSION
        || root.root_inode_cid.codec != CODEC_FILESYSTEM_INODE
    {
        return Err(FilesystemError::Invalid("invalid filesystem root".into()));
    }
    Ok(root)
}

pub async fn build_tree<S: MerkleReadStore + MerkleWriteStore + ?Sized>(
    store: &S,
    entries: Vec<TreeInputEntry>,
    creation_revision: u64,
    previous_root_cid: Option<Cid>,
    root_mode: u32,
    limits: FilesystemLimits,
) -> Result<(Cid, FilesystemRootDescriptor), FilesystemError> {
    let build = build_tree_prepared(
        store,
        entries,
        creation_revision,
        previous_root_cid,
        root_mode,
        limits,
    )
    .await?;
    Ok((build.root_cid, build.descriptor))
}

pub async fn build_tree_prepared<S: MerkleReadStore + MerkleWriteStore + ?Sized>(
    store: &S,
    entries: Vec<TreeInputEntry>,
    creation_revision: u64,
    previous_root_cid: Option<Cid>,
    root_mode: u32,
    limits: FilesystemLimits,
) -> Result<FilesystemBuild, FilesystemError> {
    let protected_base = match &previous_root_cid {
        Some(base) => {
            let descriptor = get_root(store, base, limits).await?;
            if creation_revision != descriptor.creation_revision.saturating_add(1) {
                return Err(FilesystemError::Invalid(
                    "filesystem candidate does not immediately follow its protected base".into(),
                ));
            }
            Some(descriptor)
        }
        None => None,
    };
    let changed_keys = entries.len().max(1);
    let mut verified_descendants = entries
        .iter()
        .filter_map(|entry| entry.content_cid.clone())
        .collect::<Vec<_>>();
    verified_descendants.sort_by_key(ToString::to_string);
    verified_descendants.dedup();
    let tracking = TrackingFilesystemStore {
        inner: store,
        writes: Mutex::new(Vec::new()),
    };
    let (root_cid, descriptor) = build_tree_inner(
        &tracking,
        entries,
        creation_revision,
        previous_root_cid.clone(),
        root_mode,
        limits,
    )
    .await?;
    let mut writes = tracking
        .writes
        .into_inner()
        .map_err(|_| FilesystemError::Storage("filesystem build tracker poisoned".into()))?;
    let mut seen = HashSet::new();
    writes.retain(|cid| seen.insert(cid.clone()));
    let new_index_nodes = writes
        .into_iter()
        .filter(|cid| {
            matches!(
                cid.codec,
                pepper_types::CODEC_MERKLE_NODE | CODEC_FILESYSTEM_INODE
            )
        })
        .collect::<Vec<_>>();
    let prepared_artifact = previous_root_cid
        .map(|base| {
            let artifact = PreparedDatasetArtifact {
                exact_base: ExactBase {
                    generation: protected_base
                        .as_ref()
                        .expect("base descriptor loaded")
                        .creation_revision,
                    root: base,
                },
                candidate_root: root_cid.clone(),
                descriptor: descriptor.dataset_root(),
                frontier: MutationFrontier {
                    changed_keys,
                    index_depth: limits.max_depth,
                    candidate_index_root: descriptor.root_inode_cid.clone(),
                    new_index_nodes,
                    new_data_roots: Vec::new(),
                    verified_descendants,
                },
            };
            artifact
                .validate()
                .map_err(|error| FilesystemError::Invalid(error.to_string()))?;
            Ok::<_, FilesystemError>(artifact)
        })
        .transpose()?;
    Ok(FilesystemBuild {
        root_cid,
        descriptor,
        prepared_artifact,
    })
}

async fn build_tree_inner<S: MerkleReadStore + MerkleWriteStore + ?Sized>(
    store: &S,
    mut entries: Vec<TreeInputEntry>,
    creation_revision: u64,
    previous_root_cid: Option<Cid>,
    root_mode: u32,
    limits: FilesystemLimits,
) -> Result<(Cid, FilesystemRootDescriptor), FilesystemError> {
    if entries.len() > limits.max_entries {
        return Err(FilesystemError::Limit);
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let mut paths = BTreeSet::new();
    for entry in &entries {
        validate_path(&entry.path, limits)?;
        if !paths.insert(entry.path.clone()) || entry.mode & !0o777 != 0 {
            return Err(FilesystemError::Invalid(
                "duplicate path or unsupported mode bits".into(),
            ));
        }
    }
    let directory_paths = entries
        .iter()
        .filter(|entry| entry.kind == InodeKind::Directory)
        .map(|entry| entry.path.as_str())
        .collect::<BTreeSet<_>>();
    FilesystemMetadataDescriptor { mode: root_mode }.validate()?;
    let mut directories = BTreeMap::from([(String::new(), root_mode)]);
    let mut children = BTreeMap::<String, Vec<(String, Cid)>>::new();
    let mut bytes = 0u64;
    let mut files = 0u64;
    for entry in &entries {
        let mut parent = parent_name(&entry.path).0;
        while !parent.is_empty() {
            if !directory_paths.contains(parent) {
                return Err(FilesystemError::Invalid(format!(
                    "missing parent directory {parent}"
                )));
            }
            parent = parent_name(parent).0;
        }
        match entry.kind {
            InodeKind::RegularFile => {
                let content = entry
                    .content_cid
                    .clone()
                    .ok_or_else(|| FilesystemError::Invalid("file content CID missing".into()))?;
                bytes = bytes
                    .checked_add(entry.logical_size)
                    .ok_or(FilesystemError::Limit)?;
                if bytes > limits.max_total_bytes {
                    return Err(FilesystemError::Limit);
                }
                files += 1;
                let inode_cid = put_inode(
                    store,
                    &InodeDescriptor::file(content, entry.logical_size, entry.mode),
                    limits,
                )
                .await?;
                let (parent, name) = parent_name(&entry.path);
                children
                    .entry(parent.to_string())
                    .or_default()
                    .push((name.to_string(), inode_cid));
            }
            InodeKind::Directory => {
                if entry.content_cid.is_some() || entry.logical_size != 0 {
                    return Err(FilesystemError::Invalid(
                        "directory contains file fields".into(),
                    ));
                }
                directories.insert(entry.path.clone(), entry.mode);
            }
        }
    }
    let mut directory_paths = directories.keys().cloned().collect::<Vec<_>>();
    directory_paths.sort_by_key(|path| {
        std::cmp::Reverse(path.matches('/').count() + usize::from(!path.is_empty()))
    });
    let mut root_inode_cid = None;
    for directory in directory_paths {
        let mut directory_children = children.remove(&directory).unwrap_or_default();
        directory_children.sort_by(|left, right| left.0.cmp(&right.0));
        let entries = directory_children
            .into_iter()
            .map(|(name, inode_cid)| {
                let entry = DirectoryEntryDescriptor { name, inode_cid };
                entry.validate(limits)?;
                Ok(MapEntry {
                    key: entry.name.as_bytes().to_vec(),
                    value: MerkleValue {
                        cid: entry.inode_cid,
                        generation: 1,
                        value_kind: "filesystem_inode".into(),
                        metadata: BTreeMap::new(),
                    },
                })
            })
            .collect::<Result<Vec<_>, FilesystemError>>()?;
        let map_root = build_from_sorted(store, &entries, MerkleLimits::default())
            .await
            .map_err(|e| FilesystemError::Storage(e.to_string()))?;
        let inode_cid = put_inode(
            store,
            &InodeDescriptor::directory(map_root, directories[&directory]),
            limits,
        )
        .await?;
        if directory.is_empty() {
            root_inode_cid = Some(inode_cid);
        } else {
            let (parent, name) = parent_name(&directory);
            children
                .entry(parent.to_string())
                .or_default()
                .push((name.to_string(), inode_cid));
        }
    }
    let descriptor = FilesystemRootDescriptor {
        descriptor_type: ROOT_TYPE.into(),
        version: VERSION,
        root_inode_cid: root_inode_cid
            .ok_or_else(|| FilesystemError::Invalid("filesystem root inode missing".into()))?,
        creation_revision,
        file_count: files,
        directory_count: directories.len() as u64,
        logical_bytes: bytes,
        previous_root_cid,
    };
    let cid = put_root(store, &descriptor, limits).await?;
    Ok((cid, descriptor))
}

/// Apply a bounded changed-path set by rewriting only affected directory
/// maps and ancestor inodes. Unrelated subtrees are never traversed.
pub async fn apply_tree_mutations<S: MerkleReadStore + MerkleWriteStore + ?Sized>(
    store: &S,
    base_root_cid: Cid,
    mutations: Vec<TreeMutation>,
    creation_revision: u64,
    limits: FilesystemLimits,
) -> Result<FilesystemBuild, FilesystemError> {
    if mutations.is_empty() || mutations.len() > limits.max_entries {
        return Err(FilesystemError::Invalid(
            "filesystem mutation batch must be nonempty and bounded".into(),
        ));
    }
    let mut paths = BTreeSet::new();
    for mutation in &mutations {
        validate_path(mutation.path(), limits)?;
        if !paths.insert(mutation.path().to_string()) {
            return Err(FilesystemError::Invalid(
                "filesystem mutation paths must be unique".into(),
            ));
        }
    }
    let base = get_root(store, &base_root_cid, limits).await?;
    if creation_revision != base.creation_revision.saturating_add(1) {
        return Err(FilesystemError::Invalid(
            "filesystem candidate does not immediately follow its protected base".into(),
        ));
    }
    let tracking = TrackingFilesystemStore {
        inner: store,
        writes: Mutex::new(Vec::new()),
    };
    let mut root_inode_cid = base.root_inode_cid.clone();
    let mut file_count = base.file_count;
    let mut directory_count = base.directory_count;
    let mut logical_bytes = base.logical_bytes;
    let mut verified_descendants = Vec::new();

    for mutation in &mutations {
        let components = mutation.path().split('/').collect::<Vec<_>>();
        let mut directory_stack = Vec::<InodeDescriptor>::with_capacity(components.len());
        let mut current = get_inode(&tracking, &root_inode_cid, limits).await?;
        if current.kind != InodeKind::Directory {
            return Err(FilesystemError::Invalid(
                "filesystem root is not a directory".into(),
            ));
        }
        directory_stack.push(current.clone());
        for component in &components[..components.len() - 1] {
            let directory_root = current
                .directory_root_cid
                .as_ref()
                .expect("validated directory");
            let value = get(
                &tracking,
                directory_root,
                component.as_bytes(),
                MerkleLimits::default(),
            )
            .await
            .map_err(|error| FilesystemError::Storage(error.to_string()))?
            .ok_or_else(|| {
                FilesystemError::Invalid(format!(
                    "missing parent directory while mutating {}",
                    mutation.path()
                ))
            })?;
            current = get_inode(&tracking, &value.cid, limits).await?;
            if current.kind != InodeKind::Directory {
                return Err(FilesystemError::Invalid(format!(
                    "parent component {component:?} is not a directory"
                )));
            }
            directory_stack.push(current.clone());
        }

        let target_name = components.last().expect("validated nonempty path");
        let parent = directory_stack.last().expect("root directory exists");
        let parent_root = parent
            .directory_root_cid
            .as_ref()
            .expect("validated directory");
        let existing = get(
            &tracking,
            parent_root,
            target_name.as_bytes(),
            MerkleLimits::default(),
        )
        .await
        .map_err(|error| FilesystemError::Storage(error.to_string()))?;
        let existing_inode = match &existing {
            Some(value) => Some(get_inode(&tracking, &value.cid, limits).await?),
            None => None,
        };
        if existing_inode
            .as_ref()
            .is_some_and(|inode| inode.kind == InodeKind::Directory)
            && matches!(
                mutation,
                TreeMutation::Put {
                    entry: TreeInputEntry {
                        kind: InodeKind::RegularFile,
                        ..
                    }
                }
            )
        {
            let inode = existing_inode.as_ref().expect("checked directory");
            let page = scan(
                &tracking,
                inode
                    .directory_root_cid
                    .as_ref()
                    .expect("validated directory"),
                ScanQuery {
                    limit: 1,
                    ..ScanQuery::default()
                },
                MerkleLimits::default(),
            )
            .await
            .map_err(|error| FilesystemError::Storage(error.to_string()))?;
            if !page.entries.is_empty() {
                return Err(FilesystemError::Invalid(
                    "nonempty directory replacement requires explicit child deletions".into(),
                ));
            }
        }

        let replacement = match mutation {
            TreeMutation::Put { entry } => {
                if entry.mode & !0o777 != 0 {
                    return Err(FilesystemError::Invalid("unsupported mode bits".into()));
                }
                match entry.kind {
                    InodeKind::RegularFile => {
                        let content = entry.content_cid.clone().ok_or_else(|| {
                            FilesystemError::Invalid("file content CID missing".into())
                        })?;
                        verified_descendants.push(content.clone());
                        Some(
                            put_inode(
                                &tracking,
                                &InodeDescriptor::file(content, entry.logical_size, entry.mode),
                                limits,
                            )
                            .await?,
                        )
                    }
                    InodeKind::Directory => {
                        if entry.content_cid.is_some() || entry.logical_size != 0 {
                            return Err(FilesystemError::Invalid(
                                "directory contains file fields".into(),
                            ));
                        }
                        let directory_root = match &existing_inode {
                            Some(inode) if inode.kind == InodeKind::Directory => inode
                                .directory_root_cid
                                .clone()
                                .expect("validated directory"),
                            _ => empty_root(&tracking, MerkleLimits::default())
                                .await
                                .map_err(|error| FilesystemError::Storage(error.to_string()))?,
                        };
                        Some(
                            put_inode(
                                &tracking,
                                &InodeDescriptor::directory(directory_root, entry.mode),
                                limits,
                            )
                            .await?,
                        )
                    }
                }
            }
            TreeMutation::Delete { .. } => {
                let Some(inode) = &existing_inode else {
                    return Err(FilesystemError::Invalid(format!(
                        "cannot delete missing path {}",
                        mutation.path()
                    )));
                };
                if inode.kind == InodeKind::Directory {
                    let page = scan(
                        &tracking,
                        inode
                            .directory_root_cid
                            .as_ref()
                            .expect("validated directory"),
                        ScanQuery {
                            limit: 1,
                            ..ScanQuery::default()
                        },
                        MerkleLimits::default(),
                    )
                    .await
                    .map_err(|error| FilesystemError::Storage(error.to_string()))?;
                    if !page.entries.is_empty() {
                        return Err(FilesystemError::Invalid(
                            "nonempty directory deletion requires explicit child deletions".into(),
                        ));
                    }
                }
                None
            }
        };

        if let Some(inode) = &existing_inode {
            match inode.kind {
                InodeKind::RegularFile => {
                    file_count = file_count.checked_sub(1).ok_or(FilesystemError::Limit)?;
                    logical_bytes = logical_bytes
                        .checked_sub(inode.logical_size)
                        .ok_or(FilesystemError::Limit)?;
                }
                InodeKind::Directory => {
                    directory_count = directory_count
                        .checked_sub(1)
                        .ok_or(FilesystemError::Limit)?;
                }
            }
        }
        if let TreeMutation::Put { entry } = mutation {
            match entry.kind {
                InodeKind::RegularFile => {
                    file_count = file_count.checked_add(1).ok_or(FilesystemError::Limit)?;
                    logical_bytes = logical_bytes
                        .checked_add(entry.logical_size)
                        .filter(|bytes| *bytes <= limits.max_total_bytes)
                        .ok_or(FilesystemError::Limit)?;
                }
                InodeKind::Directory => {
                    directory_count = directory_count
                        .checked_add(1)
                        .ok_or(FilesystemError::Limit)?;
                }
            }
        }
        let total_entries = file_count
            .checked_add(directory_count.saturating_sub(1))
            .ok_or(FilesystemError::Limit)?;
        if total_entries > limits.max_entries as u64 {
            return Err(FilesystemError::Limit);
        }

        let mut child = replacement;
        for level in (0..directory_stack.len()).rev() {
            let directory = &directory_stack[level];
            let key = components[level].as_bytes().to_vec();
            let index_mutation = match child {
                Some(cid) => Mutation::Put {
                    key,
                    value: MerkleValue {
                        cid,
                        generation: 1,
                        value_kind: "filesystem_inode".into(),
                        metadata: BTreeMap::new(),
                    },
                },
                None => Mutation::Delete { key },
            };
            let map_root = apply_batch(
                &tracking,
                directory
                    .directory_root_cid
                    .as_ref()
                    .expect("validated directory"),
                &[index_mutation],
                MerkleLimits::default(),
            )
            .await
            .map_err(|error| FilesystemError::Storage(error.to_string()))?;
            child = Some(
                put_inode(
                    &tracking,
                    &InodeDescriptor::directory(map_root, directory.mode),
                    limits,
                )
                .await?,
            );
        }
        root_inode_cid = child.expect("rewritten root inode");
    }

    let descriptor = FilesystemRootDescriptor {
        descriptor_type: ROOT_TYPE.into(),
        version: VERSION,
        root_inode_cid,
        creation_revision,
        file_count,
        directory_count,
        logical_bytes,
        previous_root_cid: Some(base_root_cid.clone()),
    };
    let root_cid = put_root(&tracking, &descriptor, limits).await?;
    let mut writes = tracking
        .writes
        .into_inner()
        .map_err(|_| FilesystemError::Storage("filesystem mutation tracker poisoned".into()))?;
    let mut seen = HashSet::new();
    writes.retain(|cid| seen.insert(cid.clone()));
    let new_index_nodes = writes
        .into_iter()
        .filter(|cid| {
            matches!(
                cid.codec,
                pepper_types::CODEC_MERKLE_NODE | CODEC_FILESYSTEM_INODE
            )
        })
        .collect::<Vec<_>>();
    verified_descendants.sort_by_key(ToString::to_string);
    verified_descendants.dedup();
    let artifact = PreparedDatasetArtifact {
        exact_base: ExactBase {
            generation: base.creation_revision,
            root: base_root_cid,
        },
        candidate_root: root_cid.clone(),
        descriptor: descriptor.dataset_root(),
        frontier: MutationFrontier {
            changed_keys: mutations.len(),
            index_depth: limits.max_path_bytes.saturating_add(limits.max_depth),
            candidate_index_root: descriptor.root_inode_cid.clone(),
            new_index_nodes,
            new_data_roots: Vec::new(),
            verified_descendants,
        },
    };
    artifact
        .validate()
        .map_err(|error| FilesystemError::Invalid(error.to_string()))?;
    Ok(FilesystemBuild {
        root_cid,
        descriptor,
        prepared_artifact: Some(artifact),
    })
}

fn walk_inode<'a, S: MerkleReadStore + ?Sized>(
    store: &'a S,
    cid: Cid,
    path: String,
    output: &'a mut Vec<TreeEntry>,
    limits: FilesystemLimits,
) -> BoxFuture<'a, Result<(), FilesystemError>> {
    Box::pin(async move {
        if output.len() >= limits.max_entries {
            return Err(FilesystemError::Limit);
        }
        let inode = get_inode(store, &cid, limits).await?;
        if !path.is_empty() {
            output.push(TreeEntry {
                path: path.clone(),
                inode_cid: cid,
                inode: inode.clone(),
            });
        }
        if let Some(root) = inode.directory_root_cid {
            let mut cursor = None;
            loop {
                let page = scan(
                    store,
                    &root,
                    ScanQuery {
                        limit: limits.max_entries.min(10_000),
                        cursor,
                        ..ScanQuery::default()
                    },
                    MerkleLimits::default(),
                )
                .await
                .map_err(|e| FilesystemError::Storage(e.to_string()))?;
                for child in page.entries {
                    let name = String::from_utf8(child.key).map_err(|_| {
                        FilesystemError::Invalid("directory name is not UTF-8".into())
                    })?;
                    validate_path(&name, limits)?;
                    let child_path = if path.is_empty() {
                        name
                    } else {
                        format!("{path}/{name}")
                    };
                    validate_path(&child_path, limits)?;
                    walk_inode(store, child.value.cid, child_path, output, limits).await?;
                }
                cursor = page.next_cursor;
                if cursor.is_none() {
                    break;
                }
            }
        }
        Ok(())
    })
}
pub async fn flatten_tree<S: MerkleReadStore + ?Sized>(
    store: &S,
    root_cid: &Cid,
    limits: FilesystemLimits,
) -> Result<Vec<TreeEntry>, FilesystemError> {
    let root = get_root(store, root_cid, limits).await?;
    let mut output = Vec::new();
    walk_inode(
        store,
        root.root_inode_cid,
        String::new(),
        &mut output,
        limits,
    )
    .await?;
    output.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(output)
}
pub async fn diff_trees<S: MerkleReadStore + ?Sized>(
    store: &S,
    left: &Cid,
    right: &Cid,
    limits: FilesystemLimits,
) -> Result<Vec<DiffEntry>, FilesystemError> {
    let left = flatten_tree(store, left, limits)
        .await?
        .into_iter()
        .map(|e| (e.path, e.inode_cid))
        .collect::<BTreeMap<_, _>>();
    let right = flatten_tree(store, right, limits)
        .await?
        .into_iter()
        .map(|e| (e.path, e.inode_cid))
        .collect::<BTreeMap<_, _>>();
    let keys = left
        .keys()
        .chain(right.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    Ok(keys
        .into_iter()
        .filter_map(|path| match (left.get(&path), right.get(&path)) {
            (None, Some(_)) => Some(DiffEntry {
                path,
                kind: DiffKind::Added,
            }),
            (Some(_), None) => Some(DiffEntry {
                path,
                kind: DiffKind::Removed,
            }),
            (Some(a), Some(b)) if a != b => Some(DiffEntry {
                path,
                kind: DiffKind::Modified,
            }),
            _ => None,
        })
        .collect())
}

#[derive(Debug, Clone, Copy)]
pub struct FilesystemRootCodecHandler;
impl DagCodecHandler for FilesystemRootCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_FILESYSTEM_ROOT
    }
    fn links(&self, payload: &[u8], limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        let root: FilesystemRootDescriptor =
            decode(payload, limits.max_payload_bytes).map_err(|e| DagError::InvalidPayload {
                codec: CODEC_FILESYSTEM_ROOT.canonical_display(),
                message: e.to_string(),
            })?;
        // The previous-root link is weak: namespace retention independently
        // protects retained revisions and may retire old filesystem snapshots.
        Ok(vec![root.root_inode_cid])
    }
}
#[derive(Debug, Clone, Copy)]
pub struct FilesystemInodeCodecHandler;
impl DagCodecHandler for FilesystemInodeCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_FILESYSTEM_INODE
    }
    fn links(&self, payload: &[u8], limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        let inode: InodeDescriptor =
            decode(payload, limits.max_payload_bytes).map_err(|e| DagError::InvalidPayload {
                codec: CODEC_FILESYSTEM_INODE.canonical_display(),
                message: e.to_string(),
            })?;
        inode.validate().map_err(|e| DagError::InvalidPayload {
            codec: CODEC_FILESYSTEM_INODE.canonical_display(),
            message: e.to_string(),
        })?;
        Ok(inode
            .content_cid
            .into_iter()
            .chain(inode.directory_root_cid)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use pepper_types::CODEC_RAW;
    use std::sync::Mutex;
    #[derive(Default)]
    struct Store(Mutex<BTreeMap<String, Vec<u8>>>);
    #[async_trait]
    impl MerkleReadStore for Store {
        async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
            self.0
                .lock()
                .unwrap()
                .get(&cid.to_string())
                .cloned()
                .ok_or_else(|| "missing".into())
        }
    }
    #[async_trait]
    impl MerkleWriteStore for Store {
        async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
            let cid = Cid::new(codec, &payload);
            self.0.lock().unwrap().insert(cid.to_string(), payload);
            Ok(cid)
        }
    }
    #[tokio::test]
    async fn tree_roundtrip_diff_sharing_and_vectors() {
        let store = Store::default();
        let content = Cid::new(CODEC_RAW, b"hello");
        let entries = vec![
            TreeInputEntry {
                path: "bin".into(),
                kind: InodeKind::Directory,
                mode: 0o755,
                logical_size: 0,
                content_cid: None,
            },
            TreeInputEntry {
                path: "bin/hello".into(),
                kind: InodeKind::RegularFile,
                mode: 0o755,
                logical_size: 5,
                content_cid: Some(content),
            },
        ];
        let (first, _) = build_tree(
            &store,
            entries.clone(),
            1,
            None,
            0o755,
            FilesystemLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            flatten_tree(&store, &first, FilesystemLimits::default())
                .await
                .unwrap()
                .len(),
            2
        );
        let (second, second_descriptor) = build_tree(
            &store,
            entries,
            2,
            Some(first.clone()),
            0o755,
            FilesystemLimits::default(),
        )
        .await
        .unwrap();
        assert!(
            diff_trees(&store, &first, &second, FilesystemLimits::default())
                .await
                .unwrap()
                .is_empty()
        );
        let first_descriptor = get_root(&store, &first, FilesystemLimits::default())
            .await
            .unwrap();
        assert_eq!(
            first_descriptor.root_inode_cid,
            second_descriptor.root_inode_cid
        );
        assert_eq!(
            first.to_string(),
            "cid://pepper-v1:0xc:b3:6a37bd02cc338218db1381abf9654ff6e4c50104c2ff77794e8d0cb5356d657f"
        );
    }
    #[tokio::test]
    async fn generated_tree_roundtrips_bytes_metadata_and_changes() {
        let store = Store::default();
        let mut entries = Vec::new();
        for directory in 0..32 {
            entries.push(TreeInputEntry {
                path: format!("d{directory:02}"),
                kind: InodeKind::Directory,
                mode: if directory % 2 == 0 { 0o755 } else { 0o700 },
                logical_size: 0,
                content_cid: None,
            });
            for file in 0..8 {
                let payload = format!("payload-{directory}-{file}");
                entries.push(TreeInputEntry {
                    path: format!("d{directory:02}/f{file:02}"),
                    kind: InodeKind::RegularFile,
                    mode: if file % 2 == 0 { 0o644 } else { 0o755 },
                    logical_size: payload.len() as u64,
                    content_cid: Some(Cid::new(CODEC_RAW, payload.as_bytes())),
                });
            }
        }
        let (first, _) = build_tree(
            &store,
            entries.clone(),
            1,
            None,
            0o755,
            FilesystemLimits::default(),
        )
        .await
        .unwrap();
        let flattened = flatten_tree(&store, &first, FilesystemLimits::default())
            .await
            .unwrap();
        assert_eq!(flattened.len(), entries.len());
        entries.last_mut().unwrap().mode = 0o600;
        let (second, _) = build_tree(
            &store,
            entries,
            2,
            Some(first.clone()),
            0o755,
            FilesystemLimits::default(),
        )
        .await
        .unwrap();
        let changes = diff_trees(&store, &first, &second, FilesystemLimits::default())
            .await
            .unwrap();
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|change| change.path == "d31/f07"));
    }

    #[tokio::test]
    async fn incremental_mutations_match_full_rebuild_and_touch_only_changed_paths() {
        let store = Store::default();
        let mut entries = vec![
            TreeInputEntry {
                path: "a".into(),
                kind: InodeKind::Directory,
                mode: 0o755,
                logical_size: 0,
                content_cid: None,
            },
            TreeInputEntry {
                path: "a/b".into(),
                kind: InodeKind::Directory,
                mode: 0o700,
                logical_size: 0,
                content_cid: None,
            },
        ];
        for index in 0..256 {
            let payload = format!("old-{index}");
            entries.push(TreeInputEntry {
                path: format!("a/b/f{index:03}"),
                kind: InodeKind::RegularFile,
                mode: 0o644,
                logical_size: payload.len() as u64,
                content_cid: Some(Cid::new(CODEC_RAW, payload.as_bytes())),
            });
        }
        let (base, _) = build_tree(
            &store,
            entries.clone(),
            1,
            None,
            0o755,
            FilesystemLimits::default(),
        )
        .await
        .unwrap();
        let replacement = b"replacement";
        let changed = TreeInputEntry {
            path: "a/b/f127".into(),
            kind: InodeKind::RegularFile,
            mode: 0o600,
            logical_size: replacement.len() as u64,
            content_cid: Some(Cid::new(CODEC_RAW, replacement)),
        };
        let incremental = apply_tree_mutations(
            &store,
            base.clone(),
            vec![TreeMutation::Put {
                entry: changed.clone(),
            }],
            2,
            FilesystemLimits::default(),
        )
        .await
        .unwrap();
        let entry = entries
            .iter_mut()
            .find(|entry| entry.path == changed.path)
            .unwrap();
        *entry = changed;
        let rebuilt = build_tree_prepared(
            &store,
            entries,
            2,
            Some(base),
            0o755,
            FilesystemLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(incremental.root_cid, rebuilt.root_cid);
        assert_eq!(incremental.descriptor, rebuilt.descriptor);
        let frontier = &incremental.prepared_artifact.as_ref().unwrap().frontier;
        assert_eq!(frontier.changed_keys, 1);
        assert!(frontier.new_index_nodes.len() <= 1 + frontier.index_depth);
        assert_eq!(
            flatten_tree(&store, &incremental.root_cid, FilesystemLimits::default())
                .await
                .unwrap()
                .len(),
            258
        );
    }

    #[tokio::test]
    async fn incremental_delete_rejects_nonempty_directory() {
        let store = Store::default();
        let content = Cid::new(CODEC_RAW, b"x");
        let (base, _) = build_tree(
            &store,
            vec![
                TreeInputEntry {
                    path: "dir".into(),
                    kind: InodeKind::Directory,
                    mode: 0o755,
                    logical_size: 0,
                    content_cid: None,
                },
                TreeInputEntry {
                    path: "dir/file".into(),
                    kind: InodeKind::RegularFile,
                    mode: 0o644,
                    logical_size: 1,
                    content_cid: Some(content),
                },
            ],
            1,
            None,
            0o755,
            FilesystemLimits::default(),
        )
        .await
        .unwrap();
        assert!(
            apply_tree_mutations(
                &store,
                base,
                vec![TreeMutation::Delete { path: "dir".into() }],
                2,
                FilesystemLimits::default(),
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_escape_paths() {
        let store = Store::default();
        let result = build_tree(
            &store,
            vec![TreeInputEntry {
                path: "../escape".into(),
                kind: InodeKind::RegularFile,
                mode: 0o644,
                logical_size: 0,
                content_cid: Some(Cid::new(CODEC_RAW, b"")),
            }],
            1,
            None,
            0o755,
            FilesystemLimits::default(),
        )
        .await;
        assert!(result.is_err());
    }
}
