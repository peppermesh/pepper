// SPDX-License-Identifier: Apache-2.0

//! Canonical immutable snapshot-filesystem descriptors and tree operations.

use pepper_dag::{DagCodecHandler, DagError, TraversalLimits};
use pepper_merkle::{
    MerkleLimits, MerkleReadStore, MerkleValue, MerkleWriteStore, Mutation, ScanQuery, apply_batch,
    empty_root, scan,
};
use pepper_types::{CODEC_FILESYSTEM_INODE, CODEC_FILESYSTEM_ROOT, Cid, Codec};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
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
pub struct TreeEntry {
    pub path: String,
    pub inode_cid: Cid,
    pub inode: InodeDescriptor,
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
    let mut nodes = BTreeMap::<String, Cid>::new();
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
                nodes.insert(
                    entry.path.clone(),
                    put_inode(
                        store,
                        &InodeDescriptor::file(content, entry.logical_size, entry.mode),
                        limits,
                    )
                    .await?,
                );
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
    for directory in directory_paths {
        let mut mutations = Vec::new();
        for (path, cid) in &nodes {
            let (parent, name) = parent_name(path);
            if parent == directory {
                let entry = DirectoryEntryDescriptor {
                    name: name.to_string(),
                    inode_cid: cid.clone(),
                };
                entry.validate(limits)?;
                mutations.push(Mutation::Put {
                    key: entry.name.as_bytes().to_vec(),
                    value: MerkleValue {
                        cid: entry.inode_cid,
                        generation: 1,
                        value_kind: "filesystem_inode".into(),
                        metadata: BTreeMap::new(),
                    },
                });
            }
        }
        let empty = empty_root(store, MerkleLimits::default())
            .await
            .map_err(|e| FilesystemError::Storage(e.to_string()))?;
        let map_root = apply_batch(store, &empty, &mutations, MerkleLimits::default())
            .await
            .map_err(|e| FilesystemError::Storage(e.to_string()))?;
        let inode_cid = put_inode(
            store,
            &InodeDescriptor::directory(map_root, directories[&directory]),
            limits,
        )
        .await?;
        nodes.insert(directory, inode_cid);
    }
    let descriptor = FilesystemRootDescriptor {
        descriptor_type: ROOT_TYPE.into(),
        version: VERSION,
        root_inode_cid: nodes[""].clone(),
        creation_revision,
        file_count: files,
        directory_count: directories.len() as u64,
        logical_bytes: bytes,
        previous_root_cid,
    };
    let cid = put_root(store, &descriptor, limits).await?;
    Ok((cid, descriptor))
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
