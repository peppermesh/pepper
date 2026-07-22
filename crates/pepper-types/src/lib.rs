// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};
use time::OffsetDateTime;

pub const SCHEMA_VERSION: u32 = 4;
pub const CID_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Codec(pub u64);

pub const CODEC_RAW: Codec = Codec(0x01);
pub const CODEC_OBJECT_MANIFEST: Codec = Codec(0x02);
pub const CODEC_DIR_MANIFEST: Codec = Codec(0x03);
pub const CODEC_COMPUTE_JOB: Codec = Codec(0x04);
pub const CODEC_COMPUTE_RECEIPT: Codec = Codec(0x05);
pub const CODEC_ERASURE_MANIFEST: Codec = Codec(0x06);
pub const CODEC_MERKLE_NODE: Codec = Codec(0x07);
pub const CODEC_NAMESPACE_DESCRIPTOR: Codec = Codec(0x08);
pub const CODEC_NAMESPACE_CHECKPOINT: Codec = Codec(0x09);
pub const CODEC_NAMESPACE_COMMIT: Codec = Codec(0x0a);
pub const CODEC_BUCKET_OBJECT: Codec = Codec(0x0b);
pub const CODEC_FILESYSTEM_ROOT: Codec = Codec(0x0c);
pub const CODEC_FILESYSTEM_INODE: Codec = Codec(0x0d);
pub const CODEC_BUCKET_PARTITION_BARRIER: Codec = Codec(0x0e);
/// Canonical direct payload record for an object that fits the small-object
/// segment-log threshold. The CID identifies the user bytes directly.
pub const CODEC_SMALL_OBJECT: Codec = Codec(0x0f);
/// Replicated metadata for one packed small-object extent. The descriptor
/// links the EC extent and indexes its bounded record set so compaction can
/// enumerate dirty extents instead of scanning every object in a bucket.
pub const CODEC_SMALL_OBJECT_EXTENT_INDEX: Codec = Codec(0x10);

/// Stable machine-readable error categories shared by HTTP, CLI, and future
/// namespace services. New variants may be added; existing serialized names
/// are part of the public API contract.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    NotFound,
    Conflict,
    Unauthorized,
    Forbidden,
    PayloadTooLarge,
    CapacityExceeded,
    RateLimited,
    IntegrityFailure,
    Unavailable,
    UpstreamFailure,
    UnsupportedCodec,
    GenerationConflict,
    NamespaceUnavailable,
    NotLeader,
    StaleMembership,
    DurabilityNotMet,
    TransactionExpired,
    InvalidCursor,
    StagingUnavailable,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorResponse {
    pub code: ErrorCode,
    pub error: String,
}

impl Codec {
    pub fn canonical_display(self) -> String {
        format!("0x{:x}", self.0)
    }
}

impl FromStr for Codec {
    type Err = CidParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_codec(value)
    }
}

impl Serialize for Codec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.canonical_display())
    }
}

impl<'de> Deserialize<'de> for Codec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        parse_codec(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum HashAlg {
    Blake3,
}

impl HashAlg {
    pub fn code(self) -> &'static str {
        match self {
            Self::Blake3 => "b3",
        }
    }
}

impl FromStr for HashAlg {
    type Err = CidParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "b3" => Ok(Self::Blake3),
            other => Err(CidParseError::UnsupportedHashAlg(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cid {
    pub version: u8,
    pub codec: Codec,
    pub hash_alg: HashAlg,
    pub digest: [u8; 32],
}

/// Incremental verifier for a CID whose payload arrives in bounded chunks.
/// The declared size is part of Pepper's CID digest, so callers must provide
/// it before accepting any bytes.
pub struct CidStreamVerifier {
    expected: Cid,
    expected_size: u64,
    seen: u64,
    hasher: blake3::Hasher,
    invalid: bool,
}

impl Cid {
    pub fn new(codec: Codec, payload: &[u8]) -> Self {
        let digest = compute_digest(CID_VERSION, codec, payload);
        Self {
            version: CID_VERSION,
            codec,
            hash_alg: HashAlg::Blake3,
            digest,
        }
    }

    pub fn verify(&self, payload: &[u8]) -> bool {
        self.version == CID_VERSION
            && self.hash_alg == HashAlg::Blake3
            && compute_digest(self.version, self.codec, payload) == self.digest
    }

    pub fn verify_segments(&self, segments: &[&[u8]]) -> bool {
        if self.version != CID_VERSION || self.hash_alg != HashAlg::Blake3 {
            return false;
        }
        let Some(size) = segments.iter().try_fold(0u64, |total, segment| {
            total.checked_add(segment.len() as u64)
        }) else {
            return false;
        };
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[self.version]);
        hasher.update(&encode_u64_varint(self.codec.0));
        hasher.update(&size.to_be_bytes());
        for segment in segments {
            hasher.update(segment);
        }
        *hasher.finalize().as_bytes() == self.digest
    }

    pub fn stream_verifier(&self, expected_size: u64) -> Option<CidStreamVerifier> {
        if self.version != CID_VERSION || self.hash_alg != HashAlg::Blake3 {
            return None;
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[self.version]);
        hasher.update(&encode_u64_varint(self.codec.0));
        hasher.update(&expected_size.to_be_bytes());
        Some(CidStreamVerifier {
            expected: self.clone(),
            expected_size,
            seen: 0,
            hasher,
            invalid: false,
        })
    }
}

impl CidStreamVerifier {
    pub fn update(&mut self, chunk: &[u8]) {
        let Some(seen) = self.seen.checked_add(chunk.len() as u64) else {
            self.invalid = true;
            return;
        };
        if seen > self.expected_size {
            self.invalid = true;
            return;
        }
        self.seen = seen;
        self.hasher.update(chunk);
    }

    pub fn finish(self) -> bool {
        !self.invalid
            && self.seen == self.expected_size
            && *self.hasher.finalize().as_bytes() == self.expected.digest
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let version = match self.version {
            1 => "pepper-v1".to_string(),
            other => format!("pepper-v{other}"),
        };
        write!(
            f,
            "cid://{}:{}:{}:{}",
            version,
            self.codec.canonical_display(),
            self.hash_alg.code(),
            hex::encode(self.digest)
        )
    }
}

impl FromStr for Cid {
    type Err = CidParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let rest = value
            .strip_prefix("cid://")
            .ok_or(CidParseError::InvalidPrefix)?;
        let mut parts = rest.split(':');
        let version = parse_version(parts.next().ok_or(CidParseError::MissingPart("version"))?)?;
        let codec = parse_codec(parts.next().ok_or(CidParseError::MissingPart("codec"))?)?;
        let hash_alg =
            HashAlg::from_str(parts.next().ok_or(CidParseError::MissingPart("hash_alg"))?)?;
        let digest_hex = parts.next().ok_or(CidParseError::MissingPart("digest"))?;
        if parts.next().is_some() {
            return Err(CidParseError::TooManyParts);
        }
        if version != CID_VERSION {
            return Err(CidParseError::UnsupportedVersion(version));
        }
        let digest_bytes = hex::decode(digest_hex)
            .map_err(|error| CidParseError::InvalidDigest(error.to_string()))?;
        let digest = digest_bytes
            .try_into()
            .map_err(|_| CidParseError::InvalidDigest("digest must be 32 bytes".to_string()))?;
        Ok(Self {
            version,
            codec,
            hash_alg,
            digest,
        })
    }
}

impl Serialize for Cid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Cid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CidParseError {
    #[error("CID must start with cid://")]
    InvalidPrefix,
    #[error("CID is missing {0}")]
    MissingPart(&'static str),
    #[error("CID has too many parts")]
    TooManyParts,
    #[error("unsupported CID version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported hash algorithm {0}")]
    UnsupportedHashAlg(String),
    #[error("invalid codec: {0}")]
    InvalidCodec(String),
    #[error("invalid digest: {0}")]
    InvalidDigest(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    pub cid: Cid,
    pub codec: Codec,
    pub size: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PutBlockResponse {
    pub cid: Cid,
    pub codec: Codec,
    pub size: u64,
    pub already_existed: bool,
    pub storage_location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderRecord {
    pub cid: Cid,
    pub node_id: String,
    pub addresses: Vec<String>,
    pub expires_at_unix_seconds: i64,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PlacementRole {
    Replicated,
    ErasureShard,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct PlacementReference {
    pub epoch: u64,
    pub role: PlacementRole,
    pub seed: Cid,
    pub index: u16,
    pub replicas: u16,
}

impl PlacementReference {
    pub fn replicated(epoch: u64, cid: Cid, replicas: u16) -> Self {
        Self {
            epoch,
            role: PlacementRole::Replicated,
            seed: cid,
            index: 0,
            replicas,
        }
    }

    pub fn erasure_shard(epoch: u64, stripe_cid: Cid, shard_index: u16) -> Self {
        Self {
            epoch,
            role: PlacementRole::ErasureShard,
            seed: stripe_cid,
            index: shard_index,
            replicas: 1,
        }
    }

    pub fn validate(&self) -> Result<(), PlacementReferenceError> {
        if self.epoch == 0 || self.replicas == 0 || self.replicas > 32 {
            return Err(PlacementReferenceError::InvalidBounds);
        }
        match self.role {
            PlacementRole::Replicated if self.index == 0 => Ok(()),
            PlacementRole::ErasureShard if self.replicas == 1 => Ok(()),
            _ => Err(PlacementReferenceError::InvalidRole),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlacementReferenceError {
    #[error("placement reference has invalid epoch or replica bounds")]
    InvalidBounds,
    #[error("placement reference fields do not match its role")]
    InvalidRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlacedCid {
    pub cid: Cid,
    pub placement: PlacementReference,
}

impl PlacedCid {
    pub fn new(cid: Cid, placement: PlacementReference) -> Result<Self, PlacementReferenceError> {
        placement.validate()?;
        if placement.role == PlacementRole::Replicated && placement.seed != cid {
            return Err(PlacementReferenceError::InvalidRole);
        }
        Ok(Self { cid, placement })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurabilityReceipt {
    pub cid: Cid,
    /// Authoritative placement used for this block. Control-plane bootstrap
    /// records may omit this before the first placement map is committed.
    pub placement: Option<PlacementReference>,
    pub codec: Codec,
    pub size: u64,
    pub replicas_accepted: usize,
    pub replica_nodes: Vec<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectChunk {
    pub offset: u64,
    pub size: u64,
    pub cid: Cid,
    pub placement: PlacementReference,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectManifest {
    pub size: u64,
    pub chunk_size: u64,
    pub chunks: Vec<ObjectChunk>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ErasureShard {
    pub index: u16,
    pub cid: Cid,
    pub size: u64,
    pub placement: PlacementReference,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErasureStripeEncoding {
    Raw,
    Zstd,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ErasureStripe {
    pub offset: u64,
    pub size: u64,
    pub logical_cid: Cid,
    pub encoding: ErasureStripeEncoding,
    pub encoded_size: u64,
    pub shard_size: u64,
    pub shards: Vec<ErasureShard>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ErasureManifest {
    pub size: u64,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub stripe_size: u64,
    pub stripes: Vec<ErasureStripe>,
}

impl ObjectManifest {
    pub fn new(size: u64, chunk_size: u64, chunks: Vec<ObjectChunk>) -> Self {
        Self {
            size,
            chunk_size,
            chunks,
        }
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.chunk_size == 0 {
            return Err(ManifestError::InvalidChunkLayout);
        }
        if self.size == 0 && !self.chunks.is_empty() {
            return Err(ManifestError::InvalidChunkLayout);
        }
        let mut expected = 0u64;
        for chunk in &self.chunks {
            if chunk.offset != expected
                || chunk.size == 0
                || chunk.size > self.chunk_size
                || chunk.cid.codec != CODEC_RAW
                || chunk.placement.seed != chunk.cid
                || chunk.placement.validate().is_err()
                || chunk.placement.role != PlacementRole::Replicated
            {
                return Err(ManifestError::InvalidChunkLayout);
            }
            expected = expected
                .checked_add(chunk.size)
                .ok_or(ManifestError::InvalidChunkLayout)?;
        }
        if expected != self.size {
            return Err(ManifestError::InvalidChunkLayout);
        }
        Ok(())
    }
}

impl ErasureManifest {
    pub fn new(
        size: u64,
        data_shards: u16,
        parity_shards: u16,
        stripe_size: u64,
        stripes: Vec<ErasureStripe>,
    ) -> Self {
        Self {
            size,
            data_shards,
            parity_shards,
            stripe_size,
            stripes,
        }
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.data_shards == 0
            || self.parity_shards == 0
            || self.parity_shards > self.data_shards
            || self.stripe_size == 0
        {
            return Err(ManifestError::InvalidErasureLayout);
        }
        let total = self.data_shards.saturating_add(self.parity_shards);
        if total > 32 || (self.size == 0) != self.stripes.is_empty() {
            return Err(ManifestError::InvalidErasureLayout);
        }
        let mut expected_offset = 0u64;
        for stripe in &self.stripes {
            let expected_shard_size = stripe.encoded_size.div_ceil(u64::from(self.data_shards));
            if stripe.offset != expected_offset
                || stripe.size == 0
                || stripe.size > self.stripe_size
                || stripe.encoded_size == 0
                || stripe.encoded_size > stripe.size
                || stripe.logical_cid.codec != CODEC_RAW
                || (stripe.encoding == ErasureStripeEncoding::Raw
                    && stripe.encoded_size != stripe.size)
                || (stripe.encoding == ErasureStripeEncoding::Zstd
                    && stripe.encoded_size >= stripe.size)
                || stripe.shard_size != expected_shard_size
                || stripe.shards.len() != total as usize
            {
                return Err(ManifestError::InvalidErasureLayout);
            }
            let mut seen = vec![false; total as usize];
            for (position, shard) in stripe.shards.iter().enumerate() {
                if shard.index >= total
                    || shard.index as usize != position
                    || shard.size != stripe.shard_size
                    || shard.cid.codec != CODEC_RAW
                    || shard.placement.seed != stripe.logical_cid
                    || shard.placement.index != shard.index
                    || shard.placement.validate().is_err()
                    || shard.placement.role != PlacementRole::ErasureShard
                {
                    return Err(ManifestError::InvalidErasureLayout);
                }
                let seen_slot = &mut seen[shard.index as usize];
                if *seen_slot {
                    return Err(ManifestError::InvalidErasureLayout);
                }
                *seen_slot = true;
            }
            expected_offset = expected_offset
                .checked_add(stripe.size)
                .ok_or(ManifestError::InvalidErasureLayout)?;
        }
        if expected_offset != self.size {
            return Err(ManifestError::InvalidErasureLayout);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirEntry {
    pub path: String,
    pub kind: String,
    pub mode: u32,
    pub size: Option<u64>,
    pub cid: Option<Cid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirManifest {
    pub entries: Vec<DirEntry>,
}

impl DirManifest {
    pub fn new(entries: Vec<DirEntry>) -> Self {
        Self { entries }
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        let mut previous: Option<&str> = None;
        for entry in &self.entries {
            if entry.mode & !0o777 != 0 {
                return Err(ManifestError::InvalidDirectoryEntry(entry.path.clone()));
            }
            if entry.path.is_empty()
                || entry.path.starts_with('/')
                || entry.path.contains('\\')
                || entry
                    .path
                    .split('/')
                    .any(|part| part == ".." || part == "." || part.is_empty())
            {
                return Err(ManifestError::InvalidPath(entry.path.clone()));
            }
            if let Some(previous) = previous
                && previous >= entry.path.as_str()
            {
                return Err(ManifestError::EntriesNotSorted);
            }
            previous = Some(&entry.path);
            match entry.kind.as_str() {
                "file" => {
                    if entry.size.is_none()
                        || !entry.cid.as_ref().is_some_and(|cid| {
                            matches!(
                                cid.codec,
                                CODEC_RAW
                                    | CODEC_OBJECT_MANIFEST
                                    | CODEC_ERASURE_MANIFEST
                                    | CODEC_SMALL_OBJECT
                            )
                        })
                    {
                        return Err(ManifestError::InvalidDirectoryEntry(entry.path.clone()));
                    }
                }
                "directory" => {
                    if entry.cid.is_some() || entry.size.is_some() {
                        return Err(ManifestError::InvalidDirectoryEntry(entry.path.clone()));
                    }
                }
                _ => return Err(ManifestError::InvalidDirectoryEntry(entry.path.clone())),
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("invalid object chunk layout")]
    InvalidChunkLayout,
    #[error("invalid erasure manifest layout")]
    InvalidErasureLayout,
    #[error("invalid directory path {0}")]
    InvalidPath(String),
    #[error("directory entries are not sorted")]
    EntriesNotSorted,
    #[error("invalid directory entry {0}")]
    InvalidDirectoryEntry(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinCreateRequest {
    pub root_cid: Cid,
    pub replication_factor: Option<u16>,
    pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinRecord {
    pub pin_id: String,
    pub root_cid: Cid,
    pub owner: String,
    pub replication_factor: u16,
    pub created_at_unix_seconds: i64,
    pub expires_at_unix_seconds: Option<i64>,
    pub status: String,
    #[serde(default)]
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinStatusResponse {
    pub root_cid: Cid,
    pub pins: Vec<PinRecord>,
    pub reachable_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GcReport {
    pub protected_blocks: usize,
    pub deleted_blocks: usize,
    pub reclaimed_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeInput {
    pub mount: String,
    pub cid: Cid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeOutput {
    pub path: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeResources {
    pub timeout_seconds: Option<u64>,
    pub max_input_bytes: Option<u64>,
    pub max_output_bytes: Option<u64>,
    pub memory_mib: Option<u64>,
    pub cpu_millis: Option<u64>,
    pub pids_max: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeJobSpec {
    #[serde(rename = "type")]
    pub job_type: Option<String>,
    pub version: Option<u32>,
    pub runtime: Option<String>,
    pub rootfs_cid: Option<Cid>,
    pub command: Vec<String>,
    #[serde(default)]
    pub inputs: Vec<ComputeInput>,
    #[serde(default)]
    pub outputs: Vec<ComputeOutput>,
    pub resources: Option<ComputeResources>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeReceipt {
    pub job_id: String,
    pub status: String,
    pub node_id: String,
    pub exit_code: Option<i32>,
    pub stdout_cid: Option<Cid>,
    pub stderr_cid: Option<Cid>,
    pub output_root_cid: Option<Cid>,
    pub started_at_unix_seconds: i64,
    pub finished_at_unix_seconds: i64,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeAttempt {
    pub node_id: String,
    pub address: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub started_at_unix_seconds: i64,
    pub finished_at_unix_seconds: Option<i64>,
    #[serde(default)]
    pub events: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeJobStatus {
    pub job_id: String,
    pub status: String,
    pub spec: ComputeJobSpec,
    pub created_at_unix_seconds: i64,
    pub started_at_unix_seconds: Option<i64>,
    pub finished_at_unix_seconds: Option<i64>,
    pub exit_code: Option<i32>,
    pub stdout_cid: Option<Cid>,
    pub stderr_cid: Option<Cid>,
    pub output_root_cid: Option<Cid>,
    pub error: Option<String>,
    pub receipt: Option<ComputeReceipt>,
    #[serde(default)]
    pub firecracker_error_class: Option<String>,
    #[serde(default)]
    pub cancel_requested_at_unix_seconds: Option<i64>,
    #[serde(default)]
    pub cancel_delivered_at_unix_seconds: Option<i64>,
    #[serde(default)]
    pub cancel_acknowledged_at_unix_seconds: Option<i64>,
    #[serde(default)]
    pub guest_exited_after_cancel: bool,
    #[serde(default)]
    pub vm_killed_after_cancel: bool,
    #[serde(default)]
    pub assigned_node_id: Option<String>,
    #[serde(default)]
    pub assigned_address: Option<String>,
    #[serde(default)]
    pub attempts: Vec<ComputeAttempt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmitComputeResponse {
    pub job_id: String,
    pub status: String,
    #[serde(default)]
    pub assigned_node_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeOffer {
    pub accepted: bool,
    pub node_id: String,
    pub address: Option<String>,
    pub estimated_queue_delay_seconds: u64,
    pub local_input_bytes: u64,
    pub total_input_bytes: u64,
    pub available_parallelism: u32,
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeLogsResponse {
    pub job_id: String,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockStatResponse {
    pub cid: Cid,
    pub codec: Codec,
    pub size: u64,
    pub storage_location: String,
    pub created_at_unix_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageLocationStatus {
    pub path: String,
    pub max_capacity_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigSummary {
    pub config_path: String,
    pub data_path: String,
    pub listen_addr: String,
    pub api_bind_addr: String,
    pub storage_locations: Vec<StorageLocationStatus>,
    pub bootstrap_peers: Vec<String>,
    #[serde(default)]
    pub namespace_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeStatus {
    pub name: String,
    pub node_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    pub uptime_seconds: u64,
    pub schema_version: u32,
    pub config: ConfigSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitStatus {
    pub name: String,
    pub node_id: String,
    pub data_path: String,
    pub identity_key_path: String,
    pub metadata_path: String,
    pub schema_version: u32,
}

fn compute_digest(version: u8, codec: Codec, payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[version]);
    hasher.update(&encode_u64_varint(codec.0));
    hasher.update(&(payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn encode_u64_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return out;
        }
    }
}

fn parse_version(value: &str) -> Result<u8, CidParseError> {
    let number = value
        .strip_prefix("pepper-v")
        .ok_or_else(|| CidParseError::InvalidDigest("version must be pepper-vN".to_string()))?;
    number
        .parse::<u8>()
        .map_err(|error| CidParseError::InvalidDigest(error.to_string()))
}

fn parse_codec(value: &str) -> Result<Codec, CidParseError> {
    let hex_value = value.strip_prefix("0x").ok_or_else(|| {
        CidParseError::InvalidCodec("codec must use canonical 0x hex form".to_string())
    })?;
    if hex_value.is_empty() {
        return Err(CidParseError::InvalidCodec(
            "codec hex value must not be empty".to_string(),
        ));
    }
    if hex_value != "0" && hex_value.starts_with('0') {
        return Err(CidParseError::InvalidCodec(
            "codec hex value must not contain leading zeroes".to_string(),
        ));
    }
    if hex_value.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(CidParseError::InvalidCodec(
            "codec hex value must be lowercase".to_string(),
        ));
    }
    u64::from_str_radix(hex_value, 16)
        .map(Codec)
        .map_err(|error| CidParseError::InvalidCodec(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_response_has_stable_machine_code() {
        let response = ErrorResponse {
            code: ErrorCode::GenerationConflict,
            error: "changed".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&response).unwrap(),
            r#"{"code":"generation_conflict","error":"changed"}"#
        );
    }

    #[test]
    fn cid_roundtrips() {
        let cid = Cid::new(CODEC_RAW, b"hello");
        let parsed = Cid::from_str(&cid.to_string()).unwrap();
        assert_eq!(cid, parsed);
        assert!(parsed.verify(b"hello"));
        assert!(!parsed.verify(b"goodbye"));
        assert!(parsed.verify_segments(&[b"he", b"ll", b"o"]));
        assert!(!parsed.verify_segments(&[b"he", b"lp"]));

        let mut verifier = parsed.stream_verifier(5).unwrap();
        verifier.update(b"he");
        verifier.update(b"ll");
        verifier.update(b"o");
        assert!(verifier.finish());

        let mut wrong_size = parsed.stream_verifier(4).unwrap();
        wrong_size.update(b"hello");
        assert!(!wrong_size.finish());
    }

    #[test]
    fn codec_changes_cid() {
        let raw = Cid::new(CODEC_RAW, b"{}");
        let manifest = Cid::new(CODEC_OBJECT_MANIFEST, b"{}");
        assert_ne!(raw, manifest);
    }

    #[test]
    fn hash_vector_for_raw_hello_is_stable() {
        let cid = Cid::new(CODEC_RAW, b"hello");
        assert_eq!(
            cid.to_string(),
            "cid://pepper-v1:0x1:b3:f2e70d903bca6483e2856aff3f3b09db126045b78dd335c4c10c8da3020eb94a"
        );
    }

    #[test]
    fn rejects_noncanonical_codec() {
        let cid = Cid::new(CODEC_RAW, b"hello").to_string();
        let noncanonical = cid.replace("0x1", "0x01");
        assert!(Cid::from_str(&noncanonical).is_err());
    }

    #[test]
    fn validates_object_manifest_layout() {
        let chunk_cid = Cid::new(CODEC_RAW, b"hello");
        let chunk = ObjectChunk {
            offset: 0,
            size: 5,
            cid: chunk_cid.clone(),
            placement: PlacementReference::replicated(1, chunk_cid, 3),
        };
        ObjectManifest::new(5, 1024, vec![chunk.clone()])
            .validate()
            .expect("valid manifest");

        let mut invalid = ObjectManifest::new(6, 1024, vec![chunk.clone()]);
        assert!(matches!(
            invalid.validate(),
            Err(ManifestError::InvalidChunkLayout)
        ));
        invalid = ObjectManifest::new(5, 1024, vec![ObjectChunk { offset: 1, ..chunk }]);
        assert!(matches!(
            invalid.validate(),
            Err(ManifestError::InvalidChunkLayout)
        ));
        assert!(
            ObjectManifest::new(
                0,
                1024,
                vec![ObjectChunk {
                    offset: 0,
                    size: 0,
                    cid: Cid::new(CODEC_RAW, b""),
                    placement: PlacementReference::replicated(1, Cid::new(CODEC_RAW, b""), 3,),
                }],
            )
            .validate()
            .is_err()
        );
        assert!(ObjectManifest::new(0, 0, Vec::new()).validate().is_err());
    }

    #[test]
    fn manifests_have_one_codec_selected_shape() {
        let chunk_cid = Cid::new(CODEC_RAW, b"hello");
        let manifest = ObjectManifest::new(
            5,
            1024,
            vec![ObjectChunk {
                offset: 0,
                size: 5,
                cid: chunk_cid.clone(),
                placement: PlacementReference::replicated(1, chunk_cid, 3),
            }],
        );
        let canonical = serde_json::to_value(&manifest).unwrap();
        assert_eq!(
            canonical.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["chunk_size", "chunks", "size"]
        );

        for extra in [("type", "pepper.object_manifest"), ("version", "1")] {
            let mut old_shape = canonical.clone();
            old_shape.as_object_mut().unwrap().insert(
                extra.0.to_string(),
                serde_json::Value::String(extra.1.into()),
            );
            assert!(serde_json::from_value::<ObjectManifest>(old_shape).is_err());
        }
    }

    #[test]
    fn validates_erasure_manifest_layout() {
        let logical_cid = Cid::new(CODEC_RAW, &[0; 24]);
        let shards = (0..5)
            .map(|index| ErasureShard {
                index,
                cid: Cid::new(CODEC_RAW, &[index as u8]),
                size: 8,
                placement: PlacementReference::erasure_shard(1, logical_cid.clone(), index),
            })
            .collect::<Vec<_>>();
        let manifest = ErasureManifest::new(
            24,
            3,
            2,
            24,
            vec![ErasureStripe {
                offset: 0,
                size: 24,
                logical_cid,
                encoding: ErasureStripeEncoding::Raw,
                encoded_size: 24,
                shard_size: 8,
                shards,
            }],
        );
        manifest.validate().unwrap();

        let mut invalid = manifest.clone();
        invalid.stripes[0].shards[0].index = 1;
        assert_eq!(invalid.validate(), Err(ManifestError::InvalidErasureLayout));

        let invalid_logical_cid = Cid::new(CODEC_RAW, &[0; 16]);
        let shards = (0..5)
            .map(|index| ErasureShard {
                index,
                cid: Cid::new(CODEC_RAW, &[index as u8]),
                size: 8,
                placement: PlacementReference::erasure_shard(1, invalid_logical_cid.clone(), index),
            })
            .collect();
        let invalid = ErasureManifest::new(
            16,
            2,
            3,
            16,
            vec![ErasureStripe {
                offset: 0,
                size: 16,
                logical_cid: invalid_logical_cid,
                encoding: ErasureStripeEncoding::Raw,
                encoded_size: 16,
                shard_size: 8,
                shards,
            }],
        );
        assert_eq!(invalid.validate(), Err(ManifestError::InvalidErasureLayout));
    }

    #[test]
    fn validates_multi_gib_striped_erasure_manifest() {
        let size = 4 * 1024 * 1024 * 1024u64;
        let stripe_size = 24 * 1024 * 1024u64;
        let mut offset = 0u64;
        let mut stripes = Vec::new();
        while offset < size {
            let logical_size = stripe_size.min(size - offset);
            let shard_size = logical_size.div_ceil(6);
            let stripe_index = stripes.len();
            let logical_cid = Cid::new(CODEC_RAW, format!("stripe-{stripe_index}").as_bytes());
            let shards = (0..9)
                .map(|index| ErasureShard {
                    index,
                    cid: Cid::new(
                        CODEC_RAW,
                        format!("stripe-{stripe_index}-shard-{index}").as_bytes(),
                    ),
                    size: shard_size,
                    placement: PlacementReference::erasure_shard(1, logical_cid.clone(), index),
                })
                .collect();
            stripes.push(ErasureStripe {
                offset,
                size: logical_size,
                logical_cid,
                encoding: ErasureStripeEncoding::Raw,
                encoded_size: logical_size,
                shard_size,
                shards,
            });
            offset += logical_size;
        }
        ErasureManifest::new(size, 6, 3, stripe_size, stripes)
            .validate()
            .expect("a multi-GiB object is bounded by stripes, not a whole-object limit");
    }

    #[test]
    fn validates_directory_manifest_entries() {
        let file = DirEntry {
            path: "file.txt".to_string(),
            kind: "file".to_string(),
            mode: 0o644,
            size: Some(5),
            cid: Some(Cid::new(CODEC_RAW, b"hello")),
        };
        DirManifest::new(vec![file.clone()])
            .validate()
            .expect("valid directory manifest");

        let mut invalid = DirManifest::new(vec![DirEntry {
            path: "../bad".to_string(),
            ..file.clone()
        }]);
        assert!(matches!(
            invalid.validate(),
            Err(ManifestError::InvalidPath(_))
        ));

        invalid = DirManifest::new(vec![DirEntry {
            mode: 0o4755,
            ..file.clone()
        }]);
        assert!(matches!(
            invalid.validate(),
            Err(ManifestError::InvalidDirectoryEntry(_))
        ));

        invalid = DirManifest::new(vec![
            DirEntry {
                path: "z".to_string(),
                ..file.clone()
            },
            DirEntry {
                path: "a".to_string(),
                ..file
            },
        ]);
        assert!(matches!(
            invalid.validate(),
            Err(ManifestError::EntriesNotSorted)
        ));
    }
}
