// SPDX-License-Identifier: Apache-2.0

//! Persistent ordered Merkle radix map.
//!
//! The compressed radix representation is canonical for a given set of
//! key/value records, independent of insertion order. Updates copy only the
//! nodes on affected key paths and immutable child subtrees remain shared.

use async_trait::async_trait;
use pepper_dag::{DagCodecHandler, DagError, TraversalLimits};
use pepper_types::{CODEC_MERKLE_NODE, Cid, Codec};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
};
use thiserror::Error;

const NODE_TYPE: &str = "pepper.merkle_radix_node";
const NODE_VERSION: u32 = 1;
const CURSOR_VERSION: u32 = 1;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleLimits {
    pub max_key_bytes: usize,
    pub max_value_kind_bytes: usize,
    pub max_metadata_entries: usize,
    pub max_metadata_bytes: usize,
    pub max_node_bytes: usize,
    pub max_children: usize,
    pub max_depth: usize,
    pub max_validation_nodes: usize,
    pub max_scan_entries: usize,
    pub max_scan_nodes: usize,
}

impl Default for MerkleLimits {
    fn default() -> Self {
        Self {
            max_key_bytes: 1_024,
            max_value_kind_bytes: 64,
            max_metadata_entries: 64,
            max_metadata_bytes: 16 * 1024,
            max_node_bytes: 1024 * 1024,
            max_children: 256,
            max_depth: 1_024,
            max_validation_nodes: 2_000_000,
            max_scan_entries: 10_000,
            max_scan_nodes: 2_000_000,
        }
    }
}

impl MerkleLimits {
    pub fn validate(self) -> Result<Self, MerkleError> {
        if self.max_key_bytes == 0
            || self.max_value_kind_bytes == 0
            || self.max_metadata_entries == 0
            || self.max_metadata_bytes == 0
            || self.max_node_bytes == 0
            || self.max_children == 0
            || self.max_children > 256
            || self.max_depth == 0
            || self.max_validation_nodes == 0
            || self.max_scan_entries == 0
            || self.max_scan_nodes == 0
        {
            return Err(MerkleError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleValue {
    pub cid: Cid,
    pub generation: u64,
    pub value_kind: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutation {
    Put { key: Vec<u8>, value: MerkleValue },
    Delete { key: Vec<u8> },
}

impl Mutation {
    pub fn key(&self) -> &[u8] {
        match self {
            Self::Put { key, .. } | Self::Delete { key } => key,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapEntry {
    pub key: Vec<u8>,
    pub value: MerkleValue,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanQuery {
    pub start: Option<Vec<u8>>,
    pub end: Option<Vec<u8>>,
    pub prefix: Option<Vec<u8>>,
    pub limit: usize,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanPage {
    pub root: Cid,
    pub entries: Vec<MapEntry>,
    pub next_cursor: Option<String>,
    pub nodes_read: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub nodes: usize,
    pub entries: usize,
    pub max_depth: usize,
}

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("invalid Merkle-map limits")]
    InvalidLimits,
    #[error("invalid Merkle node codec {0}")]
    InvalidCodec(String),
    #[error("failed to read Merkle block {cid}: {message}")]
    Read { cid: String, message: String },
    #[error("failed to write Merkle block: {0}")]
    Write(String),
    #[error("Merkle store returned CID {actual}, expected {expected}")]
    WrongStoredCid { expected: String, actual: String },
    #[error("Merkle block {0} failed CID verification")]
    HashMismatch(String),
    #[error("invalid Merkle node: {0}")]
    InvalidNode(String),
    #[error("non-canonical Merkle node encoding")]
    NonCanonicalNode,
    #[error("Merkle node is {actual} bytes, limit is {limit}")]
    NodeTooLarge { actual: usize, limit: usize },
    #[error("key is {actual} bytes, limit is {limit}")]
    KeyTooLarge { actual: usize, limit: usize },
    #[error("invalid Merkle value: {0}")]
    InvalidValue(String),
    #[error("mutation batch must be strictly sorted by unique key")]
    UnsortedMutations,
    #[error("scan limit must be between 1 and {0}")]
    InvalidScanLimit(usize),
    #[error("invalid scan range")]
    InvalidRange,
    #[error("invalid scan cursor: {0}")]
    InvalidCursor(String),
    #[error("scan cursor belongs to root {cursor_root}, not {requested_root}")]
    CursorRootMismatch {
        cursor_root: String,
        requested_root: String,
    },
    #[error("scan cursor query does not match the requested range")]
    CursorQueryMismatch,
    #[error("Merkle traversal exceeds depth limit {0}")]
    TooDeep(usize),
    #[error("Merkle traversal exceeds node limit {0}")]
    TooManyNodes(usize),
    #[error("cycle or duplicate node reference detected at {0}")]
    DuplicateNode(String),
}

#[async_trait]
pub trait MerkleReadStore: Send + Sync {
    async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String>;
}

#[async_trait]
pub trait MerkleWriteStore: MerkleReadStore {
    async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MerkleIoStats {
    pub nodes_read: u64,
    pub nodes_written: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkGetResult {
    /// Values in exactly the same order as the requested keys.
    pub values: Vec<Option<MerkleValue>>,
    /// Distinct immutable index nodes fetched from the backing store.
    pub unique_nodes_read: usize,
}

/// Store decorator used by production metrics and benchmarks. Taking two
/// snapshots around an operation exposes its immutable-node read/write cost.
pub fn structural_sharing_ratio(total_nodes: usize, nodes_written: u64) -> f64 {
    if total_nodes == 0 {
        return 1.0;
    }
    let rewritten = usize::try_from(nodes_written)
        .unwrap_or(usize::MAX)
        .min(total_nodes);
    total_nodes.saturating_sub(rewritten) as f64 / total_nodes as f64
}

static PROCESS_NODES_READ: AtomicU64 = AtomicU64::new(0);
static PROCESS_NODES_WRITTEN: AtomicU64 = AtomicU64::new(0);
static PROCESS_MUTATIONS: AtomicU64 = AtomicU64::new(0);

pub fn process_io_stats() -> (MerkleIoStats, u64) {
    (
        MerkleIoStats {
            nodes_read: PROCESS_NODES_READ.load(Ordering::Relaxed),
            nodes_written: PROCESS_NODES_WRITTEN.load(Ordering::Relaxed),
        },
        PROCESS_MUTATIONS.load(Ordering::Relaxed),
    )
}

pub struct InstrumentedStore<S> {
    inner: S,
    nodes_read: AtomicU64,
    nodes_written: AtomicU64,
}

impl<S> InstrumentedStore<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            nodes_read: AtomicU64::new(0),
            nodes_written: AtomicU64::new(0),
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn stats(&self) -> MerkleIoStats {
        MerkleIoStats {
            nodes_read: self.nodes_read.load(Ordering::Relaxed),
            nodes_written: self.nodes_written.load(Ordering::Relaxed),
        }
    }
}

#[async_trait]
impl<S> MerkleReadStore for InstrumentedStore<S>
where
    S: MerkleReadStore,
{
    async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
        let result = self.inner.get(cid).await;
        if result.is_ok() {
            self.nodes_read.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}

#[async_trait]
impl<S> MerkleWriteStore for InstrumentedStore<S>
where
    S: MerkleWriteStore,
{
    async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
        let result = self.inner.put(codec, payload).await;
        if result.is_ok() {
            self.nodes_written.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Node {
    #[serde(rename = "type")]
    node_type: String,
    version: u32,
    prefix_hex: String,
    value: Option<MerkleValue>,
    children: Vec<Child>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Child {
    edge: u8,
    cid: Cid,
}

impl Node {
    fn new(prefix: Vec<u8>, value: Option<MerkleValue>, children: Vec<Child>) -> Self {
        Self {
            node_type: NODE_TYPE.to_string(),
            version: NODE_VERSION,
            prefix_hex: hex::encode(prefix),
            value,
            children,
        }
    }

    fn prefix(&self) -> Result<Vec<u8>, MerkleError> {
        hex::decode(&self.prefix_hex)
            .map_err(|error| MerkleError::InvalidNode(format!("invalid prefix hex: {error}")))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CursorRecord {
    version: u32,
    root: Cid,
    after_key_hex: String,
    start_hex: Option<String>,
    end_hex: Option<String>,
    prefix_hex: Option<String>,
}

pub async fn empty_root<S>(store: &S, limits: MerkleLimits) -> Result<Cid, MerkleError>
where
    S: MerkleWriteStore + ?Sized,
{
    let limits = limits.validate()?;
    store_node(store, Node::new(Vec::new(), None, Vec::new()), &limits).await
}

pub async fn get<S>(
    store: &S,
    root: &Cid,
    key: &[u8],
    limits: MerkleLimits,
) -> Result<Option<MerkleValue>, MerkleError>
where
    S: MerkleReadStore + ?Sized,
{
    let limits = limits.validate()?;
    validate_key(key, &limits)?;
    let mut cid = root.clone();
    let mut offset = 0usize;
    let mut depth = 0usize;
    loop {
        if depth > limits.max_depth {
            return Err(MerkleError::TooDeep(limits.max_depth));
        }
        let node = load_node(store, &cid, &limits).await?;
        let prefix = node.prefix()?;
        if !key[offset..].starts_with(&prefix) {
            return Ok(None);
        }
        offset += prefix.len();
        if offset == key.len() {
            return Ok(node.value);
        }
        let edge = key[offset];
        let Ok(index) = node
            .children
            .binary_search_by_key(&edge, |child| child.edge)
        else {
            return Ok(None);
        };
        cid = node.children[index].cid.clone();
        depth += 1;
    }
}

/// Resolve a bounded key set with one request-scoped immutable-node cache.
/// Shared prefixes and duplicate keys therefore fetch each physical node at
/// most once while results retain caller order.
pub async fn get_many<S>(
    store: &S,
    root: &Cid,
    keys: &[Vec<u8>],
    limits: MerkleLimits,
) -> Result<BulkGetResult, MerkleError>
where
    S: MerkleReadStore + ?Sized,
{
    let limits = limits.validate()?;
    if keys.len() > limits.max_scan_entries {
        return Err(MerkleError::TooManyNodes(limits.max_scan_entries));
    }
    for key in keys {
        validate_key(key, &limits)?;
    }
    let mut cache = HashMap::<Cid, Node>::new();
    let mut values = Vec::with_capacity(keys.len());
    for key in keys {
        let mut cid = root.clone();
        let mut offset = 0usize;
        let mut depth = 0usize;
        let value = loop {
            if depth > limits.max_depth {
                return Err(MerkleError::TooDeep(limits.max_depth));
            }
            if !cache.contains_key(&cid) {
                let node = load_node(store, &cid, &limits).await?;
                cache.insert(cid.clone(), node);
            }
            let node = cache.get(&cid).expect("request node cached");
            let prefix = node.prefix()?;
            if !key[offset..].starts_with(&prefix) {
                break None;
            }
            offset += prefix.len();
            if offset == key.len() {
                break node.value.clone();
            }
            let edge = key[offset];
            let Ok(index) = node
                .children
                .binary_search_by_key(&edge, |child| child.edge)
            else {
                break None;
            };
            cid = node.children[index].cid.clone();
            depth += 1;
        };
        values.push(value);
    }
    Ok(BulkGetResult {
        values,
        unique_nodes_read: cache.len(),
    })
}

pub async fn apply_batch<S>(
    store: &S,
    root: &Cid,
    mutations: &[Mutation],
    limits: MerkleLimits,
) -> Result<Cid, MerkleError>
where
    S: MerkleWriteStore + ?Sized,
{
    let limits = limits.validate()?;
    validate_mutations(mutations, &limits)?;
    PROCESS_MUTATIONS.fetch_add(mutations.len() as u64, Ordering::Relaxed);
    let mut current = root.clone();
    // Validate the initial root even for an empty mutation list.
    load_node(store, &current, &limits).await?;
    for mutation in mutations {
        current = match mutation {
            Mutation::Put { key, value } => {
                insert_at(store, &current, key, value.clone(), 0, 0, &limits).await?
            }
            Mutation::Delete { key } => {
                match delete_at(store, &current, key, 0, 0, &limits).await? {
                    Some(cid) => cid,
                    None => empty_root(store, limits).await?,
                }
            }
        };
    }
    Ok(current)
}

/// Build a canonical map efficiently from strictly sorted unique entries.
pub async fn build_from_sorted<S>(
    store: &S,
    entries: &[MapEntry],
    limits: MerkleLimits,
) -> Result<Cid, MerkleError>
where
    S: MerkleWriteStore + ?Sized,
{
    let limits = limits.validate()?;
    for (index, entry) in entries.iter().enumerate() {
        validate_key(&entry.key, &limits)?;
        validate_value(&entry.value, &limits)?;
        if index > 0 && entries[index - 1].key >= entry.key {
            return Err(MerkleError::UnsortedMutations);
        }
    }
    if entries.is_empty() {
        return empty_root(store, limits).await;
    }
    build_subtree(store, entries, 0, 0, &limits).await
}

pub async fn scan<S>(
    store: &S,
    root: &Cid,
    query: ScanQuery,
    limits: MerkleLimits,
) -> Result<ScanPage, MerkleError>
where
    S: MerkleReadStore + ?Sized,
{
    let limits = limits.validate()?;
    if query.limit == 0 || query.limit > limits.max_scan_entries {
        return Err(MerkleError::InvalidScanLimit(limits.max_scan_entries));
    }
    if query
        .start
        .as_ref()
        .zip(query.end.as_ref())
        .is_some_and(|(start, end)| start >= end)
    {
        return Err(MerkleError::InvalidRange);
    }
    if let Some(key) = &query.start {
        validate_key(key, &limits)?;
    }
    if let Some(key) = &query.end {
        validate_key(key, &limits)?;
    }
    if let Some(prefix) = &query.prefix {
        validate_key(prefix, &limits)?;
    }

    let after = if let Some(cursor) = &query.cursor {
        let cursor = decode_cursor(cursor)?;
        if &cursor.root != root {
            return Err(MerkleError::CursorRootMismatch {
                cursor_root: cursor.root.to_string(),
                requested_root: root.to_string(),
            });
        }
        if cursor.start_hex != encode_optional(&query.start)
            || cursor.end_hex != encode_optional(&query.end)
            || cursor.prefix_hex != encode_optional(&query.prefix)
        {
            return Err(MerkleError::CursorQueryMismatch);
        }
        Some(
            hex::decode(cursor.after_key_hex)
                .map_err(|error| MerkleError::InvalidCursor(error.to_string()))?,
        )
    } else {
        None
    };

    let mut stack = vec![(root.clone(), Vec::<u8>::new(), 0usize)];
    let mut entries = Vec::with_capacity(query.limit.saturating_add(1));
    let mut nodes_read = 0usize;
    while let Some((cid, parent_key, depth)) = stack.pop() {
        if depth > limits.max_depth {
            return Err(MerkleError::TooDeep(limits.max_depth));
        }
        nodes_read += 1;
        if nodes_read > limits.max_scan_nodes {
            return Err(MerkleError::TooManyNodes(limits.max_scan_nodes));
        }
        let node = load_node(store, &cid, &limits).await?;
        let mut key = parent_key;
        key.extend(node.prefix()?);
        if let Some(value) = node.value
            && key_matches(&key, &query, after.as_deref())
        {
            entries.push(MapEntry {
                key: key.clone(),
                value,
            });
            if entries.len() > query.limit {
                break;
            }
        }
        for child in node.children.into_iter().rev() {
            stack.push((child.cid, key.clone(), depth + 1));
        }
    }

    let has_more = entries.len() > query.limit;
    if has_more {
        entries.truncate(query.limit);
    }
    let next_cursor = if has_more {
        entries
            .last()
            .map(|entry| {
                encode_cursor(&CursorRecord {
                    version: CURSOR_VERSION,
                    root: root.clone(),
                    after_key_hex: hex::encode(&entry.key),
                    start_hex: encode_optional(&query.start),
                    end_hex: encode_optional(&query.end),
                    prefix_hex: encode_optional(&query.prefix),
                })
            })
            .transpose()?
    } else {
        None
    };

    Ok(ScanPage {
        root: root.clone(),
        entries,
        next_cursor,
        nodes_read,
    })
}

pub async fn validate_tree<S>(
    store: &S,
    root: &Cid,
    limits: MerkleLimits,
) -> Result<ValidationReport, MerkleError>
where
    S: MerkleReadStore + ?Sized,
{
    let limits = limits.validate()?;
    let mut stack = vec![(root.clone(), Vec::<u8>::new(), 0usize, true)];
    let mut seen = HashSet::new();
    let mut entries = 0usize;
    let mut max_depth = 0usize;
    while let Some((cid, parent_key, depth, is_root)) = stack.pop() {
        if depth > limits.max_depth {
            return Err(MerkleError::TooDeep(limits.max_depth));
        }
        if !seen.insert(cid.clone()) {
            return Err(MerkleError::DuplicateNode(cid.to_string()));
        }
        if seen.len() > limits.max_validation_nodes {
            return Err(MerkleError::TooManyNodes(limits.max_validation_nodes));
        }
        max_depth = max_depth.max(depth);
        let node = load_node(store, &cid, &limits).await?;
        let prefix = node.prefix()?;
        if !is_root && prefix.is_empty() {
            return Err(MerkleError::InvalidNode(
                "non-root node has an empty prefix".to_string(),
            ));
        }
        if node.value.is_none() && node.children.len() == 1 {
            return Err(MerkleError::InvalidNode(
                "compressible single-child node".to_string(),
            ));
        }
        if !is_root && node.value.is_none() && node.children.is_empty() {
            return Err(MerkleError::InvalidNode("empty non-root node".to_string()));
        }
        let mut key = parent_key;
        key.extend(&prefix);
        validate_key(&key, &limits)?;
        if node.value.is_some() {
            entries += 1;
        }
        for child in node.children.into_iter().rev() {
            let child_node = load_node(store, &child.cid, &limits).await?;
            let child_prefix = child_node.prefix()?;
            if child_prefix.first() != Some(&child.edge) {
                return Err(MerkleError::InvalidNode(format!(
                    "child edge {} does not match child prefix",
                    child.edge
                )));
            }
            stack.push((child.cid, key.clone(), depth + 1, false));
        }
    }
    Ok(ValidationReport {
        nodes: seen.len(),
        entries,
        max_depth,
    })
}

fn insert_at<'a, S>(
    store: &'a S,
    cid: &'a Cid,
    key: &'a [u8],
    value: MerkleValue,
    offset: usize,
    depth: usize,
    limits: &'a MerkleLimits,
) -> BoxFuture<'a, Result<Cid, MerkleError>>
where
    S: MerkleWriteStore + ?Sized + 'a,
{
    Box::pin(async move {
        if depth > limits.max_depth || offset > key.len() {
            return Err(MerkleError::TooDeep(limits.max_depth));
        }
        validate_value(&value, limits)?;
        let mut node = load_node(store, cid, limits).await?;
        let prefix = node.prefix()?;
        let remaining = &key[offset..];
        let common = common_prefix_len(&prefix, remaining);
        if common < prefix.len() {
            let existing_prefix = prefix[common..].to_vec();
            node.prefix_hex = hex::encode(&existing_prefix);
            let existing_edge = existing_prefix[0];
            let existing_cid = store_node(store, node, limits).await?;
            let mut parent = Node::new(
                prefix[..common].to_vec(),
                if common == remaining.len() {
                    Some(value.clone())
                } else {
                    None
                },
                vec![Child {
                    edge: existing_edge,
                    cid: existing_cid,
                }],
            );
            if common < remaining.len() {
                let new_prefix = remaining[common..].to_vec();
                let edge = new_prefix[0];
                let new_cid = store_node(
                    store,
                    Node::new(new_prefix, Some(value), Vec::new()),
                    limits,
                )
                .await?;
                insert_child_sorted(&mut parent.children, Child { edge, cid: new_cid })?;
            }
            return store_node(store, parent, limits).await;
        }

        let next_offset = offset + prefix.len();
        if next_offset == key.len() {
            node.value = Some(value);
            return store_node(store, node, limits).await;
        }
        let edge = key[next_offset];
        match node
            .children
            .binary_search_by_key(&edge, |child| child.edge)
        {
            Ok(index) => {
                let child_cid = node.children[index].cid.clone();
                node.children[index].cid = insert_at(
                    store,
                    &child_cid,
                    key,
                    value,
                    next_offset,
                    depth + 1,
                    limits,
                )
                .await?;
            }
            Err(index) => {
                let child = Node::new(key[next_offset..].to_vec(), Some(value), Vec::new());
                let child_cid = store_node(store, child, limits).await?;
                node.children.insert(
                    index,
                    Child {
                        edge,
                        cid: child_cid,
                    },
                );
            }
        }
        normalize_and_store(store, node, limits)
            .await?
            .ok_or_else(|| MerkleError::InvalidNode("insert produced an empty tree".to_string()))
    })
}

fn delete_at<'a, S>(
    store: &'a S,
    cid: &'a Cid,
    key: &'a [u8],
    offset: usize,
    depth: usize,
    limits: &'a MerkleLimits,
) -> BoxFuture<'a, Result<Option<Cid>, MerkleError>>
where
    S: MerkleWriteStore + ?Sized + 'a,
{
    Box::pin(async move {
        if depth > limits.max_depth {
            return Err(MerkleError::TooDeep(limits.max_depth));
        }
        let mut node = load_node(store, cid, limits).await?;
        let prefix = node.prefix()?;
        if !key[offset..].starts_with(&prefix) {
            return Ok(Some(cid.clone()));
        }
        let next_offset = offset + prefix.len();
        if next_offset == key.len() {
            if node.value.is_none() {
                return Ok(Some(cid.clone()));
            }
            node.value = None;
        } else {
            let edge = key[next_offset];
            let Ok(index) = node
                .children
                .binary_search_by_key(&edge, |child| child.edge)
            else {
                return Ok(Some(cid.clone()));
            };
            let child_cid = node.children[index].cid.clone();
            match delete_at(store, &child_cid, key, next_offset, depth + 1, limits).await? {
                Some(updated) => node.children[index].cid = updated,
                None => {
                    node.children.remove(index);
                }
            }
        }
        normalize_and_store(store, node, limits).await
    })
}

fn normalize_and_store<'a, S>(
    store: &'a S,
    mut node: Node,
    limits: &'a MerkleLimits,
) -> BoxFuture<'a, Result<Option<Cid>, MerkleError>>
where
    S: MerkleWriteStore + ?Sized + 'a,
{
    Box::pin(async move {
        if node.value.is_none() && node.children.is_empty() {
            return Ok(None);
        }
        if node.value.is_none() && node.children.len() == 1 {
            let child = load_node(store, &node.children[0].cid, limits).await?;
            let mut prefix = node.prefix()?;
            prefix.extend(child.prefix()?);
            node = Node::new(prefix, child.value, child.children);
        }
        store_node(store, node, limits).await.map(Some)
    })
}

fn build_subtree<'a, S>(
    store: &'a S,
    entries: &'a [MapEntry],
    offset: usize,
    depth: usize,
    limits: &'a MerkleLimits,
) -> BoxFuture<'a, Result<Cid, MerkleError>>
where
    S: MerkleWriteStore + ?Sized + 'a,
{
    Box::pin(async move {
        if depth > limits.max_depth {
            return Err(MerkleError::TooDeep(limits.max_depth));
        }
        let prefix_len = common_prefix_for_entries(entries, offset);
        let prefix = entries[0].key[offset..offset + prefix_len].to_vec();
        let position = offset + prefix_len;
        let mut value = None;
        let mut group_start = 0usize;
        if entries[0].key.len() == position {
            value = Some(entries[0].value.clone());
            group_start = 1;
        }
        let mut children = Vec::new();
        let mut index = group_start;
        while index < entries.len() {
            let edge = entries[index].key[position];
            let start = index;
            index += 1;
            while index < entries.len()
                && entries[index].key.len() > position
                && entries[index].key[position] == edge
            {
                index += 1;
            }
            let cid =
                build_subtree(store, &entries[start..index], position, depth + 1, limits).await?;
            children.push(Child { edge, cid });
        }
        store_node(store, Node::new(prefix, value, children), limits).await
    })
}

async fn load_node<S>(store: &S, cid: &Cid, limits: &MerkleLimits) -> Result<Node, MerkleError>
where
    S: MerkleReadStore + ?Sized,
{
    if cid.codec != CODEC_MERKLE_NODE {
        return Err(MerkleError::InvalidCodec(cid.codec.canonical_display()));
    }
    let payload = store.get(cid).await.map_err(|message| MerkleError::Read {
        cid: cid.to_string(),
        message,
    })?;
    PROCESS_NODES_READ.fetch_add(1, Ordering::Relaxed);
    if !cid.verify(&payload) {
        return Err(MerkleError::HashMismatch(cid.to_string()));
    }
    decode_node(&payload, limits)
}

async fn store_node<S>(store: &S, node: Node, limits: &MerkleLimits) -> Result<Cid, MerkleError>
where
    S: MerkleWriteStore + ?Sized,
{
    validate_node_shallow(&node, limits)?;
    let payload =
        serde_json::to_vec(&node).map_err(|error| MerkleError::InvalidNode(error.to_string()))?;
    if payload.len() > limits.max_node_bytes {
        return Err(MerkleError::NodeTooLarge {
            actual: payload.len(),
            limit: limits.max_node_bytes,
        });
    }
    let expected = Cid::new(CODEC_MERKLE_NODE, &payload);
    let actual = store
        .put(CODEC_MERKLE_NODE, payload)
        .await
        .map_err(MerkleError::Write)?;
    PROCESS_NODES_WRITTEN.fetch_add(1, Ordering::Relaxed);
    if actual != expected {
        return Err(MerkleError::WrongStoredCid {
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(actual)
}

fn decode_node(payload: &[u8], limits: &MerkleLimits) -> Result<Node, MerkleError> {
    if payload.len() > limits.max_node_bytes {
        return Err(MerkleError::NodeTooLarge {
            actual: payload.len(),
            limit: limits.max_node_bytes,
        });
    }
    let node: Node = serde_json::from_slice(payload)
        .map_err(|error| MerkleError::InvalidNode(error.to_string()))?;
    validate_node_shallow(&node, limits)?;
    let canonical =
        serde_json::to_vec(&node).map_err(|error| MerkleError::InvalidNode(error.to_string()))?;
    if canonical != payload {
        return Err(MerkleError::NonCanonicalNode);
    }
    Ok(node)
}

fn validate_node_shallow(node: &Node, limits: &MerkleLimits) -> Result<(), MerkleError> {
    if node.node_type != NODE_TYPE {
        return Err(MerkleError::InvalidNode("wrong type".to_string()));
    }
    if node.version != NODE_VERSION {
        return Err(MerkleError::InvalidNode(format!(
            "unsupported version {}",
            node.version
        )));
    }
    let prefix = node.prefix()?;
    if prefix.len() > limits.max_key_bytes {
        return Err(MerkleError::KeyTooLarge {
            actual: prefix.len(),
            limit: limits.max_key_bytes,
        });
    }
    if let Some(value) = &node.value {
        validate_value(value, limits)?;
    }
    if node.children.len() > limits.max_children {
        return Err(MerkleError::InvalidNode(format!(
            "{} children exceeds limit {}",
            node.children.len(),
            limits.max_children
        )));
    }
    let mut previous = None;
    for child in &node.children {
        if child.cid.codec != CODEC_MERKLE_NODE {
            return Err(MerkleError::InvalidCodec(
                child.cid.codec.canonical_display(),
            ));
        }
        if previous.is_some_and(|edge| edge >= child.edge) {
            return Err(MerkleError::InvalidNode(
                "child edges are not strictly sorted".to_string(),
            ));
        }
        previous = Some(child.edge);
    }
    Ok(())
}

fn validate_key(key: &[u8], limits: &MerkleLimits) -> Result<(), MerkleError> {
    if key.len() > limits.max_key_bytes {
        return Err(MerkleError::KeyTooLarge {
            actual: key.len(),
            limit: limits.max_key_bytes,
        });
    }
    Ok(())
}

fn validate_value(value: &MerkleValue, limits: &MerkleLimits) -> Result<(), MerkleError> {
    if value.generation == 0 {
        return Err(MerkleError::InvalidValue(
            "generation must be greater than zero".to_string(),
        ));
    }
    if value.value_kind.is_empty() || value.value_kind.len() > limits.max_value_kind_bytes {
        return Err(MerkleError::InvalidValue(
            "value kind is empty or too long".to_string(),
        ));
    }
    if value.metadata.len() > limits.max_metadata_entries {
        return Err(MerkleError::InvalidValue(
            "too many metadata entries".to_string(),
        ));
    }
    let metadata_bytes = value
        .metadata
        .iter()
        .try_fold(0usize, |total, (key, value)| {
            if key.is_empty() {
                return Err(MerkleError::InvalidValue(
                    "metadata key must not be empty".to_string(),
                ));
            }
            Ok(total.saturating_add(key.len()).saturating_add(value.len()))
        })?;
    if metadata_bytes > limits.max_metadata_bytes {
        return Err(MerkleError::InvalidValue(
            "metadata exceeds byte limit".to_string(),
        ));
    }
    Ok(())
}

fn validate_mutations(mutations: &[Mutation], limits: &MerkleLimits) -> Result<(), MerkleError> {
    for (index, mutation) in mutations.iter().enumerate() {
        validate_key(mutation.key(), limits)?;
        if let Mutation::Put { value, .. } = mutation {
            validate_value(value, limits)?;
        }
        if index > 0 && mutations[index - 1].key() >= mutation.key() {
            return Err(MerkleError::UnsortedMutations);
        }
    }
    Ok(())
}

fn insert_child_sorted(children: &mut Vec<Child>, child: Child) -> Result<(), MerkleError> {
    match children.binary_search_by_key(&child.edge, |existing| existing.edge) {
        Ok(_) => Err(MerkleError::InvalidNode("duplicate child edge".to_string())),
        Err(index) => {
            children.insert(index, child);
            Ok(())
        }
    }
}

fn common_prefix_len(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right)
        .take_while(|(left, right)| left == right)
        .count()
}

fn common_prefix_for_entries(entries: &[MapEntry], offset: usize) -> usize {
    let first = &entries[0].key[offset..];
    let last = &entries[entries.len() - 1].key[offset..];
    common_prefix_len(first, last)
}

fn key_matches(key: &[u8], query: &ScanQuery, after: Option<&[u8]>) -> bool {
    after.is_none_or(|after| key > after)
        && query
            .start
            .as_ref()
            .is_none_or(|start| key >= start.as_slice())
        && query.end.as_ref().is_none_or(|end| key < end.as_slice())
        && query
            .prefix
            .as_ref()
            .is_none_or(|prefix| key.starts_with(prefix))
}

fn encode_optional(value: &Option<Vec<u8>>) -> Option<String> {
    value.as_ref().map(hex::encode)
}

fn encode_cursor(cursor: &CursorRecord) -> Result<String, MerkleError> {
    serde_json::to_vec(cursor)
        .map(hex::encode)
        .map_err(|error| MerkleError::InvalidCursor(error.to_string()))
}

fn decode_cursor(cursor: &str) -> Result<CursorRecord, MerkleError> {
    let bytes =
        hex::decode(cursor).map_err(|error| MerkleError::InvalidCursor(error.to_string()))?;
    let decoded: CursorRecord = serde_json::from_slice(&bytes)
        .map_err(|error| MerkleError::InvalidCursor(error.to_string()))?;
    let canonical = serde_json::to_vec(&decoded)
        .map_err(|error| MerkleError::InvalidCursor(error.to_string()))?;
    if canonical != bytes {
        return Err(MerkleError::InvalidCursor(
            "non-canonical encoding".to_string(),
        ));
    }
    if decoded.version != CURSOR_VERSION {
        return Err(MerkleError::InvalidCursor(format!(
            "unsupported version {}",
            decoded.version
        )));
    }
    Ok(decoded)
}

pub struct MerkleNodeCodecHandler;

impl DagCodecHandler for MerkleNodeCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_MERKLE_NODE
    }

    fn links(&self, payload: &[u8], _limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        let node = decode_node(payload, &MerkleLimits::default()).map_err(|error| {
            DagError::InvalidPayload {
                codec: CODEC_MERKLE_NODE.canonical_display(),
                message: error.to_string(),
            }
        })?;
        let mut links = node
            .children
            .into_iter()
            .map(|child| child.cid)
            .collect::<Vec<_>>();
        if let Some(value) = node.value {
            links.push(value.cid);
        }
        Ok(links)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct MemoryStore {
        blocks: Mutex<BTreeMap<String, Vec<u8>>>,
        puts: Mutex<usize>,
        gets: Mutex<usize>,
    }

    impl MemoryStore {
        fn put_count(&self) -> usize {
            *self.puts.lock().unwrap()
        }

        fn get_count(&self) -> usize {
            *self.gets.lock().unwrap()
        }

        fn corrupt(&self, cid: &Cid, payload: Vec<u8>) {
            self.blocks.lock().unwrap().insert(cid.to_string(), payload);
        }
    }

    #[async_trait]
    impl MerkleReadStore for MemoryStore {
        async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
            *self.gets.lock().unwrap() += 1;
            self.blocks
                .lock()
                .unwrap()
                .get(&cid.to_string())
                .cloned()
                .ok_or_else(|| "missing".to_string())
        }
    }

    #[async_trait]
    impl MerkleWriteStore for MemoryStore {
        async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
            let cid = Cid::new(codec, &payload);
            self.blocks.lock().unwrap().insert(cid.to_string(), payload);
            *self.puts.lock().unwrap() += 1;
            Ok(cid)
        }
    }

    fn value(name: &str, generation: u64) -> MerkleValue {
        MerkleValue {
            cid: Cid::new(pepper_types::CODEC_RAW, name.as_bytes()),
            generation,
            value_kind: "raw".to_string(),
            metadata: BTreeMap::new(),
        }
    }

    fn puts(entries: &[(&str, &str)]) -> Vec<Mutation> {
        entries
            .iter()
            .map(|(key, name)| Mutation::Put {
                key: key.as_bytes().to_vec(),
                value: value(name, 1),
            })
            .collect()
    }

    #[tokio::test]
    async fn put_get_delete_and_prefix_split_merge() {
        let store = MemoryStore::default();
        let limits = MerkleLimits::default();
        let empty = empty_root(&store, limits).await.unwrap();
        let root = apply_batch(
            &store,
            &empty,
            &puts(&[("app", "a"), ("apple", "b"), ("banana", "c")]),
            limits,
        )
        .await
        .unwrap();
        assert_eq!(
            get(&store, &root, b"app", limits).await.unwrap(),
            Some(value("a", 1))
        );
        assert_eq!(
            get(&store, &root, b"apple", limits).await.unwrap(),
            Some(value("b", 1))
        );
        assert_eq!(get(&store, &root, b"missing", limits).await.unwrap(), None);

        let root = apply_batch(
            &store,
            &root,
            &[Mutation::Delete {
                key: b"app".to_vec(),
            }],
            limits,
        )
        .await
        .unwrap();
        assert_eq!(get(&store, &root, b"app", limits).await.unwrap(), None);
        assert!(
            get(&store, &root, b"apple", limits)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            validate_tree(&store, &root, limits).await.unwrap().entries,
            2
        );
    }

    #[tokio::test]
    async fn bulk_get_deduplicates_shared_nodes_and_preserves_order() {
        let store = MemoryStore::default();
        let limits = MerkleLimits::default();
        let root = build_from_sorted(
            &store,
            &[
                MapEntry {
                    key: b"alpha".to_vec(),
                    value: value("a", 1),
                },
                MapEntry {
                    key: b"alpine".to_vec(),
                    value: value("b", 1),
                },
                MapEntry {
                    key: b"beta".to_vec(),
                    value: value("c", 1),
                },
            ],
            limits,
        )
        .await
        .unwrap();
        let before = store.get_count();
        let result = get_many(
            &store,
            &root,
            &[
                b"beta".to_vec(),
                b"alpha".to_vec(),
                b"missing".to_vec(),
                b"alpha".to_vec(),
            ],
            limits,
        )
        .await
        .unwrap();
        assert_eq!(
            result.values,
            vec![
                Some(value("c", 1)),
                Some(value("a", 1)),
                None,
                Some(value("a", 1)),
            ]
        );
        assert_eq!(store.get_count() - before, result.unique_nodes_read);
        assert!(result.unique_nodes_read < 4 * 3);
    }

    #[tokio::test]
    async fn sparse_frontier_scales_with_changes_not_retained_history() {
        let store = MemoryStore::default();
        let limits = MerkleLimits::default();
        let entries = (0..65_536u32)
            .map(|index| MapEntry {
                key: format!("key-{index:05}").into_bytes(),
                value: value(&format!("old-{index}"), 1),
            })
            .collect::<Vec<_>>();
        let root = build_from_sorted(&store, &entries, limits).await.unwrap();
        let mut observations = BTreeMap::<usize, (Cid, usize)>::new();
        for retained_history in [1usize, 1_000] {
            let retained = vec![root.clone(); retained_history];
            for changed in [1usize, 16, 256] {
                let mutations = (0..changed)
                    .map(|index| Mutation::Put {
                        key: format!("key-{:05}", index * 257).into_bytes(),
                        value: value(&format!("new-{index}"), 2),
                    })
                    .collect::<Vec<_>>();
                let before = store.put_count();
                let candidate = apply_batch(&store, &root, &mutations, limits)
                    .await
                    .unwrap();
                let written = store.put_count() - before;
                assert!(written <= 1 + changed * limits.max_depth);
                if let Some((expected_root, expected_written)) = observations.get(&changed) {
                    assert_eq!(&candidate, expected_root);
                    assert_eq!(written, *expected_written);
                } else {
                    observations.insert(changed, (candidate, written));
                }
                assert_eq!(retained.len(), retained_history);
            }
        }
    }

    #[tokio::test]
    async fn roots_are_canonical_independent_of_insertion_history() {
        let store_a = MemoryStore::default();
        let store_b = MemoryStore::default();
        let limits = MerkleLimits::default();
        let empty_a = empty_root(&store_a, limits).await.unwrap();
        let root_a = apply_batch(
            &store_a,
            &empty_a,
            &puts(&[("a", "1"), ("ab", "2"), ("b", "3"), ("z", "4")]),
            limits,
        )
        .await
        .unwrap();

        let entries = vec![
            MapEntry {
                key: b"a".to_vec(),
                value: value("1", 1),
            },
            MapEntry {
                key: b"ab".to_vec(),
                value: value("2", 1),
            },
            MapEntry {
                key: b"b".to_vec(),
                value: value("3", 1),
            },
            MapEntry {
                key: b"z".to_vec(),
                value: value("4", 1),
            },
        ];
        let root_b = build_from_sorted(&store_b, &entries, limits).await.unwrap();
        assert_eq!(root_a, root_b);
    }

    #[tokio::test]
    async fn mutation_shares_unaffected_subtrees() {
        let store = MemoryStore::default();
        let limits = MerkleLimits::default();
        let root = build_from_sorted(
            &store,
            &[
                MapEntry {
                    key: b"alpha".to_vec(),
                    value: value("a", 1),
                },
                MapEntry {
                    key: b"beta".to_vec(),
                    value: value("b", 1),
                },
                MapEntry {
                    key: b"gamma".to_vec(),
                    value: value("g", 1),
                },
            ],
            limits,
        )
        .await
        .unwrap();
        let before = decode_node(&store.get(&root).await.unwrap(), &limits).unwrap();
        let beta_before = before
            .children
            .iter()
            .find(|child| child.edge == b'b')
            .unwrap()
            .cid
            .clone();
        let puts_before = store.put_count();
        let updated = apply_batch(
            &store,
            &root,
            &[Mutation::Put {
                key: b"alpha".to_vec(),
                value: value("new", 2),
            }],
            limits,
        )
        .await
        .unwrap();
        let after = decode_node(&store.get(&updated).await.unwrap(), &limits).unwrap();
        let beta_after = after
            .children
            .iter()
            .find(|child| child.edge == b'b')
            .unwrap()
            .cid
            .clone();
        assert_eq!(beta_before, beta_after);
        assert!(store.put_count() - puts_before <= b"alpha".len() + 1);
    }

    #[tokio::test]
    async fn scans_ranges_and_binds_cursors_to_root_and_query() {
        let store = MemoryStore::default();
        let limits = MerkleLimits::default();
        let entries = (0..20)
            .map(|index| MapEntry {
                key: format!("item/{index:02}").into_bytes(),
                value: value(&index.to_string(), 1),
            })
            .collect::<Vec<_>>();
        let root = build_from_sorted(&store, &entries, limits).await.unwrap();
        let query = ScanQuery {
            prefix: Some(b"item/".to_vec()),
            limit: 7,
            ..ScanQuery::default()
        };
        let first = scan(&store, &root, query.clone(), limits).await.unwrap();
        assert_eq!(first.entries.len(), 7);
        let second = scan(
            &store,
            &root,
            ScanQuery {
                cursor: first.next_cursor.clone(),
                ..query.clone()
            },
            limits,
        )
        .await
        .unwrap();
        assert_eq!(second.entries[0].key, b"item/07");
        let range = scan(
            &store,
            &root,
            ScanQuery {
                start: Some(b"item/05".to_vec()),
                end: Some(b"item/09".to_vec()),
                limit: 10,
                ..ScanQuery::default()
            },
            limits,
        )
        .await
        .unwrap();
        assert_eq!(
            range
                .entries
                .iter()
                .map(|entry| String::from_utf8_lossy(&entry.key).into_owned())
                .collect::<Vec<_>>(),
            ["item/05", "item/06", "item/07", "item/08"]
        );

        let other = apply_batch(
            &store,
            &root,
            &[Mutation::Put {
                key: b"z".to_vec(),
                value: value("z", 1),
            }],
            limits,
        )
        .await
        .unwrap();
        assert!(matches!(
            scan(
                &store,
                &other,
                ScanQuery {
                    cursor: first.next_cursor.clone(),
                    ..query.clone()
                },
                limits
            )
            .await,
            Err(MerkleError::CursorRootMismatch { .. })
        ));
        assert!(matches!(
            scan(
                &store,
                &root,
                ScanQuery {
                    prefix: Some(b"other".to_vec()),
                    cursor: first.next_cursor,
                    ..query
                },
                limits
            )
            .await,
            Err(MerkleError::CursorQueryMismatch)
        ));
    }

    #[tokio::test]
    async fn instrumented_store_counts_node_io() {
        let store = InstrumentedStore::new(MemoryStore::default());
        let limits = MerkleLimits::default();
        let empty = empty_root(&store, limits).await.unwrap();
        let after_empty = store.stats();
        assert_eq!(after_empty.nodes_written, 1);
        let root = apply_batch(&store, &empty, &puts(&[("key", "value")]), limits)
            .await
            .unwrap();
        let _ = get(&store, &root, b"key", limits).await.unwrap();
        let stats = store.stats();
        assert!(stats.nodes_written > after_empty.nodes_written);
        assert!(stats.nodes_read >= 2);
        assert_eq!(structural_sharing_ratio(10, 2), 0.8);
    }

    #[tokio::test]
    async fn validates_limits_batches_and_corruption() {
        let store = MemoryStore::default();
        let limits = MerkleLimits {
            max_key_bytes: 4,
            ..MerkleLimits::default()
        };
        let empty = empty_root(&store, limits).await.unwrap();
        assert!(matches!(
            apply_batch(&store, &empty, &puts(&[("toolong", "x")]), limits).await,
            Err(MerkleError::KeyTooLarge { .. })
        ));
        assert!(matches!(
            apply_batch(&store, &empty, &puts(&[("b", "1"), ("a", "2")]), limits).await,
            Err(MerkleError::UnsortedMutations)
        ));

        store.corrupt(&empty, b"{}".to_vec());
        assert!(matches!(
            get(&store, &empty, b"", limits).await,
            Err(MerkleError::HashMismatch(_))
        ));
    }

    #[tokio::test]
    async fn dag_handler_exposes_merkle_children() {
        let store = MemoryStore::default();
        let limits = MerkleLimits::default();
        let root = build_from_sorted(
            &store,
            &[
                MapEntry {
                    key: b"a".to_vec(),
                    value: value("a", 1),
                },
                MapEntry {
                    key: b"b".to_vec(),
                    value: value("b", 1),
                },
            ],
            limits,
        )
        .await
        .unwrap();
        let payload = store.get(&root).await.unwrap();
        let links = MerkleNodeCodecHandler
            .links(&payload, &TraversalLimits::default())
            .unwrap();
        assert_eq!(links.len(), 2);
    }

    #[tokio::test]
    async fn randomized_operations_match_btree_reference_model() {
        let store = MemoryStore::default();
        let limits = MerkleLimits::default();
        let mut root = empty_root(&store, limits).await.unwrap();
        let mut model = BTreeMap::<Vec<u8>, MerkleValue>::new();
        let mut seed = 0x5eed_u64;
        for step in 0..500u64 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let key = format!("key/{:03}", seed % 120).into_bytes();
            let mutation = if seed & 3 == 0 {
                model.remove(&key);
                Mutation::Delete { key }
            } else {
                let next = model.get(&key).map_or(1, |value| value.generation + 1);
                let next_value = value(&format!("value-{step}"), next);
                model.insert(key.clone(), next_value.clone());
                Mutation::Put {
                    key,
                    value: next_value,
                }
            };
            root = apply_batch(&store, &root, &[mutation], limits)
                .await
                .unwrap();

            if step % 25 == 0 {
                let expected = model
                    .iter()
                    .map(|(key, value)| MapEntry {
                        key: key.clone(),
                        value: value.clone(),
                    })
                    .collect::<Vec<_>>();
                let rebuilt = build_from_sorted(&MemoryStore::default(), &expected, limits)
                    .await
                    .unwrap();
                assert_eq!(root, rebuilt, "non-canonical root after step {step}");
                let page = scan(
                    &store,
                    &root,
                    ScanQuery {
                        limit: limits.max_scan_entries,
                        ..ScanQuery::default()
                    },
                    limits,
                )
                .await
                .unwrap();
                assert_eq!(page.entries, expected);
            }
        }
    }

    #[tokio::test]
    async fn canonical_root_has_stable_vector() {
        let store = MemoryStore::default();
        let root = build_from_sorted(
            &store,
            &[
                MapEntry {
                    key: b"a".to_vec(),
                    value: value("one", 1),
                },
                MapEntry {
                    key: b"ab".to_vec(),
                    value: value("two", 2),
                },
                MapEntry {
                    key: b"b".to_vec(),
                    value: value("three", 3),
                },
            ],
            MerkleLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            root.to_string(),
            "cid://pepper-v1:0x7:b3:9050335b7585dfec43bc8f70095ad31a14f173504e8b710919e541155e4411f2"
        );
    }

    #[tokio::test]
    async fn real_block_store_adapter_roundtrips_and_survives_dag_gc() {
        use pepper_config::StorageLocationConfig;
        use pepper_metadata::MetadataStore;
        use pepper_storage::BlockStore;

        struct Adapter(Arc<BlockStore>);
        #[async_trait]
        impl MerkleReadStore for Adapter {
            async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
                self.0
                    .get(cid)
                    .map(|block| block.payload)
                    .map_err(|error| error.to_string())
            }
        }
        #[async_trait]
        impl MerkleWriteStore for Adapter {
            async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
                self.0
                    .put(codec, &payload)
                    .map(|result| result.cid)
                    .map_err(|error| error.to_string())
            }
        }
        #[async_trait]
        impl pepper_dag::BlockResolver for Adapter {
            async fn resolve(&self, cid: &Cid) -> Result<Vec<u8>, String> {
                self.0
                    .get(cid)
                    .map(|block| block.payload)
                    .map_err(|error| error.to_string())
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let metadata =
            Arc::new(MetadataStore::open_or_create(directory.path().join("meta.redb")).unwrap());
        let blocks = Arc::new(
            BlockStore::open(
                metadata,
                &[StorageLocationConfig {
                    path: directory.path().join("storage"),
                    max_capacity_bytes: 16 * 1024 * 1024,
                }],
            )
            .unwrap(),
        );
        let value_cid = blocks.put_raw(b"stored value").unwrap().cid;
        let unprotected = blocks.put_raw(b"unprotected").unwrap().cid;
        let stored_value = MerkleValue {
            cid: value_cid.clone(),
            generation: 1,
            value_kind: "raw".to_string(),
            metadata: BTreeMap::new(),
        };
        let adapter = Adapter(blocks);
        let root = build_from_sorted(
            &adapter,
            &[MapEntry {
                key: b"key".to_vec(),
                value: stored_value.clone(),
            }],
            MerkleLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            get(&adapter, &root, b"key", MerkleLimits::default())
                .await
                .unwrap(),
            Some(stored_value)
        );

        let mut registry = pepper_dag::builtin_registry();
        registry.register(MerkleNodeCodecHandler).unwrap();
        let protected = pepper_dag::traverse(
            &registry,
            &adapter,
            root.clone(),
            TraversalLimits::default(),
        )
        .await
        .unwrap()
        .into_set();
        adapter.0.garbage_collect(&protected).unwrap();
        assert!(adapter.0.has(&root).unwrap());
        assert!(adapter.0.has(&value_cid).unwrap());
        assert!(!adapter.0.has(&unprotected).unwrap());
    }
}
