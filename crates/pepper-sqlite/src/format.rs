// SPDX-License-Identifier: Apache-2.0

use crate::SqliteError;
use pepper_dag::{DagCodecHandler, DagError, TraversalLimits};
use pepper_dataset::{DatasetRoot, IndexKind};
use pepper_types::{
    CODEC_ERASURE_MANIFEST, CODEC_OBJECT_MANIFEST, CODEC_SMALL_OBJECT, CODEC_SQLITE_DATABASE,
    CODEC_SQLITE_PAGE_TABLE, CODEC_SQLITE_SNAPSHOT, Cid, Codec,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::HashSet;

pub const FORMAT_VERSION: u32 = 1;
pub const DATABASE_TYPE: &str = "pepper.sqlite_database";
pub const SNAPSHOT_TYPE: &str = "pepper.sqlite_snapshot";
pub const PAGE_TABLE_TYPE: &str = "pepper.sqlite_page_table";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliteFormatLimits {
    pub max_descriptor_bytes: usize,
    pub max_page_table_node_bytes: usize,
    pub max_page_count: u32,
    pub max_logical_bytes: u64,
    pub max_page_size: u32,
    pub max_pack_bytes: u32,
}

impl Default for SqliteFormatLimits {
    fn default() -> Self {
        Self {
            max_descriptor_bytes: 64 * 1024,
            max_page_table_node_bytes: 256 * 1024,
            // Bound both axes: many tiny pages stress page-table traversal,
            // while fewer large pages stress pack traversal.
            max_page_count: 33_554_432,
            max_logical_bytes: 128 * 1024 * 1024 * 1024,
            max_page_size: 65_536,
            max_pack_bytes: 4 * 1024 * 1024,
        }
    }
}

impl SqliteFormatLimits {
    pub fn validate(self) -> Result<Self, SqliteError> {
        if self.max_descriptor_bytes == 0
            || self.max_page_table_node_bytes == 0
            || self.max_page_count == 0
            || self.max_logical_bytes == 0
            || self.max_page_size < 512
            || !self.max_page_size.is_power_of_two()
            || self.max_pack_bytes == 0
        {
            return Err(SqliteError::Invalid("invalid format limits".into()));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PageStoragePolicy {
    Replicated {
        replicas: u16,
    },
    Erasure {
        data_shards: u16,
        parity_shards: u16,
        shard_copies: u16,
    },
    Adaptive {
        small_commit_replicas: u16,
        large_commit_data_shards: u16,
        large_commit_parity_shards: u16,
        large_commit_shard_copies: u16,
        threshold_bytes: u32,
    },
}

impl PageStoragePolicy {
    pub fn validate(&self, max_pack_bytes: u32) -> Result<(), SqliteError> {
        let valid_shards = |data: u16, parity: u16, copies: u16| {
            data > 0
                && parity > 0
                && copies > 0
                && data.checked_add(parity).is_some_and(|total| total <= 32)
        };
        match self {
            Self::Replicated { replicas } if (1..=16).contains(replicas) => Ok(()),
            Self::Erasure {
                data_shards,
                parity_shards,
                shard_copies,
            } if valid_shards(*data_shards, *parity_shards, *shard_copies) => Ok(()),
            Self::Adaptive {
                small_commit_replicas,
                large_commit_data_shards,
                large_commit_parity_shards,
                large_commit_shard_copies,
                threshold_bytes,
            } if (1..=16).contains(small_commit_replicas)
                && valid_shards(
                    *large_commit_data_shards,
                    *large_commit_parity_shards,
                    *large_commit_shard_copies,
                )
                && *threshold_bytes > 0
                && *threshold_bytes <= max_pack_bytes =>
            {
                Ok(())
            }
            _ => Err(SqliteError::Invalid("invalid page storage policy".into())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CachePolicyBounds {
    pub minimum_bytes: u64,
    pub maximum_bytes: u64,
}

impl CachePolicyBounds {
    fn validate(&self, page_size: u32) -> Result<(), SqliteError> {
        if self.minimum_bytes < u64::from(page_size)
            || self.maximum_bytes < self.minimum_bytes
            || self.maximum_bytes > 64 * 1024 * 1024 * 1024
        {
            return Err(SqliteError::Invalid("invalid cache policy bounds".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DatabaseDescriptor {
    #[serde(rename = "type")]
    pub descriptor_type: String,
    pub version: u32,
    pub page_size: u32,
    pub max_page_count: u32,
    pub page_pack_target_bytes: u32,
    pub storage_policy: PageStoragePolicy,
    pub cache_policy_bounds: CachePolicyBounds,
    pub created_at_unix_seconds: i64,
    pub creator_identity: String,
}

impl DatabaseDescriptor {
    pub fn new(
        page_size: u32,
        max_page_count: u32,
        page_pack_target_bytes: u32,
        storage_policy: PageStoragePolicy,
        cache_policy_bounds: CachePolicyBounds,
        created_at_unix_seconds: i64,
        creator_identity: impl Into<String>,
    ) -> Self {
        Self {
            descriptor_type: DATABASE_TYPE.into(),
            version: FORMAT_VERSION,
            page_size,
            max_page_count,
            page_pack_target_bytes,
            storage_policy,
            cache_policy_bounds,
            created_at_unix_seconds,
            creator_identity: creator_identity.into(),
        }
    }

    pub fn validate(&self, limits: SqliteFormatLimits) -> Result<(), SqliteError> {
        let limits = limits.validate()?;
        if self.descriptor_type != DATABASE_TYPE || self.version != FORMAT_VERSION {
            return Err(SqliteError::Invalid(
                "unsupported database descriptor type or version".into(),
            ));
        }
        if self.page_size < 512
            || self.page_size > limits.max_page_size
            || !self.page_size.is_power_of_two()
            || self.max_page_count == 0
            || self.max_page_count > limits.max_page_count
            || u64::from(self.max_page_count) * u64::from(self.page_size) > limits.max_logical_bytes
            || self.page_pack_target_bytes < self.page_size
            || self.page_pack_target_bytes > limits.max_pack_bytes
            || self.page_pack_target_bytes % self.page_size != 0
            || self.created_at_unix_seconds < 0
            || self.creator_identity.is_empty()
            || self.creator_identity.len() > 1024
        {
            return Err(SqliteError::Invalid(
                "invalid page size, page count, or pack target".into(),
            ));
        }
        self.storage_policy.validate(limits.max_pack_bytes)?;
        self.cache_policy_bounds.validate(self.page_size)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDescriptor {
    #[serde(rename = "type")]
    pub descriptor_type: String,
    pub version: u32,
    pub database_cid: Cid,
    pub page_table_root_cid: Cid,
    pub page_size: u32,
    pub page_count: u32,
    pub logical_size: u64,
    /// Weak history link. It is intentionally not traversed by the DAG handler.
    pub base_snapshot_cid: Option<Cid>,
}

impl SnapshotDescriptor {
    pub fn dataset_root(&self, generation: u64) -> DatasetRoot {
        DatasetRoot {
            product: "sqlite".into(),
            format_version: self.version,
            generation,
            index_kind: IndexKind::FixedFanout {
                fanout: 256,
                depth: 4,
            },
            index_root: self.page_table_root_cid.clone(),
            previous_root: self.base_snapshot_cid.clone(),
            logical_bytes: self.logical_size,
        }
    }

    pub fn validate(&self, limits: SqliteFormatLimits) -> Result<(), SqliteError> {
        let limits = limits.validate()?;
        if self.descriptor_type != SNAPSHOT_TYPE
            || self.version != FORMAT_VERSION
            || self.database_cid.codec != CODEC_SQLITE_DATABASE
            || self.page_table_root_cid.codec != CODEC_SQLITE_PAGE_TABLE
            || self
                .base_snapshot_cid
                .as_ref()
                .is_some_and(|cid| cid.codec != CODEC_SQLITE_SNAPSHOT)
            || self.page_size < 512
            || self.page_size > limits.max_page_size
            || !self.page_size.is_power_of_two()
            || self.page_count > limits.max_page_count
            || self.logical_size > limits.max_logical_bytes
            || self.logical_size != u64::from(self.page_count) * u64::from(self.page_size)
        {
            return Err(SqliteError::Invalid("invalid snapshot descriptor".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PageReference {
    /// SQLite page number. Page zero does not exist.
    pub page_number: u32,
    pub pack_cid: Cid,
    pub offset: u32,
    pub length: u32,
    /// Lowercase BLAKE3 digest of the uncompressed page bytes.
    pub page_hash: String,
}

impl PageReference {
    pub fn validate(
        &self,
        expected_page_size: u32,
        limits: SqliteFormatLimits,
    ) -> Result<(), SqliteError> {
        if self.page_number == 0
            || self.page_number > limits.max_page_count
            || self.length != expected_page_size
            || self.length < 512
            || self.length > limits.max_page_size
            || !self.length.is_power_of_two()
            || self.offset % expected_page_size != 0
            || self.offset.checked_add(self.length).is_none()
            || self.offset + self.length > limits.max_pack_bytes
            || !matches!(
                self.pack_cid.codec,
                CODEC_SMALL_OBJECT | CODEC_OBJECT_MANIFEST | CODEC_ERASURE_MANIFEST
            )
            || self.page_hash.len() != 64
            || !self
                .page_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SqliteError::Invalid(format!(
                "invalid page reference {}",
                self.page_number
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PageTableNodeKind {
    Internal,
    Leaf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PageTableChild {
    pub edge: u8,
    pub cid: Cid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PageTableNode {
    #[serde(rename = "type")]
    pub descriptor_type: String,
    pub version: u32,
    pub kind: PageTableNodeKind,
    /// Internal levels are 0, 1, and 2. Leaves use level 3.
    pub level: u8,
    /// Big-endian page-number prefix consumed before this node, as lowercase hex.
    pub prefix: String,
    pub children: Vec<PageTableChild>,
    pub pages: Vec<PageReference>,
}

impl PageTableNode {
    pub fn empty_root() -> Self {
        Self::internal(0, Vec::new(), Vec::new())
    }

    pub fn internal(level: u8, prefix: Vec<u8>, children: Vec<PageTableChild>) -> Self {
        Self {
            descriptor_type: PAGE_TABLE_TYPE.into(),
            version: FORMAT_VERSION,
            kind: PageTableNodeKind::Internal,
            level,
            prefix: hex_prefix(&prefix),
            children,
            pages: Vec::new(),
        }
    }

    pub fn leaf(prefix: [u8; 3], pages: Vec<PageReference>) -> Self {
        Self {
            descriptor_type: PAGE_TABLE_TYPE.into(),
            version: FORMAT_VERSION,
            kind: PageTableNodeKind::Leaf,
            level: 3,
            prefix: hex_prefix(&prefix),
            children: Vec::new(),
            pages,
        }
    }

    pub fn validate(&self, limits: SqliteFormatLimits) -> Result<(), SqliteError> {
        if self.descriptor_type != PAGE_TABLE_TYPE
            || self.version != FORMAT_VERSION
            || self.prefix.len() != usize::from(self.level) * 2
            || !self
                .prefix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SqliteError::Invalid("invalid page-table header".into()));
        }
        match self.kind {
            PageTableNodeKind::Internal => {
                if self.level > 2 || !self.pages.is_empty() || self.children.len() > 256 {
                    return Err(SqliteError::Invalid(
                        "invalid page-table internal node".into(),
                    ));
                }
                let mut prior = None;
                let mut child_cids = HashSet::new();
                for child in &self.children {
                    if prior.is_some_and(|edge| edge >= child.edge)
                        || child.cid.codec != CODEC_SQLITE_PAGE_TABLE
                        || !child_cids.insert(child.cid.clone())
                    {
                        return Err(SqliteError::Invalid(
                            "unsorted or invalid page-table child".into(),
                        ));
                    }
                    prior = Some(child.edge);
                }
            }
            PageTableNodeKind::Leaf => {
                if self.level != 3 || !self.children.is_empty() || self.pages.len() > 256 {
                    return Err(SqliteError::Invalid("invalid page-table leaf".into()));
                }
                let prefix = u32::from_str_radix(&self.prefix, 16)
                    .map_err(|_| SqliteError::Invalid("invalid leaf prefix".into()))?;
                let mut prior = None;
                for page in &self.pages {
                    if page.page_number.to_be_bytes()[..3]
                        != [(prefix >> 16) as u8, (prefix >> 8) as u8, prefix as u8]
                        || prior.is_some_and(|number| number >= page.page_number)
                    {
                        return Err(SqliteError::Invalid(
                            "unsorted page or page outside leaf prefix".into(),
                        ));
                    }
                    page.validate(page.length, limits)?;
                    prior = Some(page.page_number);
                }
            }
        }
        Ok(())
    }

    pub fn links(&self) -> Vec<Cid> {
        let mut links = match self.kind {
            PageTableNodeKind::Internal => self
                .children
                .iter()
                .map(|child| child.cid.clone())
                .collect::<Vec<_>>(),
            PageTableNodeKind::Leaf => self
                .pages
                .iter()
                .map(|page| page.pack_cid.clone())
                .collect::<Vec<_>>(),
        };
        links.sort_by_key(ToString::to_string);
        links.dedup();
        links
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn encode_canonical<T: Serialize>(value: &T, max_bytes: usize) -> Result<Vec<u8>, SqliteError> {
    let payload =
        serde_json::to_vec(value).map_err(|error| SqliteError::Invalid(error.to_string()))?;
    if payload.len() > max_bytes {
        return Err(SqliteError::Limit(format!(
            "encoded block is {} bytes, limit is {max_bytes}",
            payload.len()
        )));
    }
    Ok(payload)
}

pub fn decode_canonical<T: DeserializeOwned + Serialize>(
    payload: &[u8],
    max_bytes: usize,
) -> Result<T, SqliteError> {
    if payload.len() > max_bytes {
        return Err(SqliteError::Limit(format!(
            "encoded block is {} bytes, limit is {max_bytes}",
            payload.len()
        )));
    }
    let value: T =
        serde_json::from_slice(payload).map_err(|error| SqliteError::Invalid(error.to_string()))?;
    if encode_canonical(&value, max_bytes)? != payload {
        return Err(SqliteError::NonCanonical);
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy)]
pub struct SqliteDatabaseCodecHandler;
impl DagCodecHandler for SqliteDatabaseCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_SQLITE_DATABASE
    }
    fn links(&self, payload: &[u8], limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        let value: DatabaseDescriptor = decode_dag(payload, limits, self.codec())?;
        value
            .validate(SqliteFormatLimits::default())
            .map_err(|e| invalid_dag(self.codec(), e))?;
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SqliteSnapshotCodecHandler;
impl DagCodecHandler for SqliteSnapshotCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_SQLITE_SNAPSHOT
    }
    fn links(&self, payload: &[u8], limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        let value: SnapshotDescriptor = decode_dag(payload, limits, self.codec())?;
        value
            .validate(SqliteFormatLimits::default())
            .map_err(|e| invalid_dag(self.codec(), e))?;
        Ok(vec![value.database_cid, value.page_table_root_cid])
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SqlitePageTableCodecHandler;
impl DagCodecHandler for SqlitePageTableCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_SQLITE_PAGE_TABLE
    }
    fn links(&self, payload: &[u8], limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        let value: PageTableNode = decode_dag(payload, limits, self.codec())?;
        value
            .validate(SqliteFormatLimits::default())
            .map_err(|e| invalid_dag(self.codec(), e))?;
        let links = value.links();
        if links.len() > limits.max_links_per_block {
            return Err(DagError::TooManyLinks {
                cid: self.codec().canonical_display(),
                actual: links.len(),
                limit: limits.max_links_per_block,
            });
        }
        Ok(links)
    }
}

fn decode_dag<T: DeserializeOwned + Serialize>(
    payload: &[u8],
    limits: &TraversalLimits,
    codec: Codec,
) -> Result<T, DagError> {
    decode_canonical(payload, limits.max_payload_bytes).map_err(|error| invalid_dag(codec, error))
}

fn invalid_dag(codec: Codec, error: SqliteError) -> DagError {
    DagError::InvalidPayload {
        codec: codec.canonical_display(),
        message: error.to_string(),
    }
}

pub fn ensure_unique_links(links: &[Cid]) -> Result<(), SqliteError> {
    let mut seen = HashSet::new();
    if links.iter().any(|cid| !seen.insert(cid)) {
        return Err(SqliteError::Invalid("duplicate strong link".into()));
    }
    Ok(())
}
