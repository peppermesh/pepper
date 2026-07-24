// SPDX-License-Identifier: Apache-2.0

//! Deterministic transactional namespace state machine.
//!
//! This crate intentionally contains no networking or concrete consensus
//! implementation. Identical prior state and command envelopes produce the
//! same Merkle root, commit CID, response, and retention intents.

use async_trait::async_trait;
use pepper_dag::{DagCodecHandler, DagError, TraversalLimits};
use pepper_merkle::{
    MerkleError, MerkleLimits, MerkleReadStore, MerkleValue, MerkleWriteStore, Mutation, ScanPage,
    ScanQuery,
};
use pepper_types::{
    CODEC_NAMESPACE_CHECKPOINT, CODEC_NAMESPACE_COMMIT, CODEC_NAMESPACE_DESCRIPTOR, CODEC_RAW, Cid,
    Codec,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const DESCRIPTOR_TYPE: &str = "pepper.namespace_descriptor";
const COMMIT_TYPE: &str = "pepper.namespace_commit";
const CHECKPOINT_TYPE: &str = "pepper.namespace_checkpoint";
const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct NamespaceId(pub Cid);

impl std::fmt::Display for NamespaceId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl NamespaceId {
    pub fn new(cid: Cid) -> Result<Self, NamespaceError> {
        if cid.codec != CODEC_NAMESPACE_DESCRIPTOR {
            return Err(NamespaceError::InvalidCodec(cid.codec.canonical_display()));
        }
        Ok(Self(cid))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceKind {
    Kv,
    Bucket,
    Filesystem,
    Sqlite,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DurabilityPolicy {
    pub replicas: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicy {
    /// Current revision is always retained; this includes it.
    pub keep_last: u32,
    pub max_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamespaceDescriptor {
    #[serde(rename = "type")]
    pub descriptor_type: String,
    pub version: u32,
    pub kind: NamespaceKind,
    pub initial_replica_set: Vec<String>,
    pub consensus_protocol_version: u32,
    pub replication_factor: u16,
    pub placement_constraints: BTreeMap<String, String>,
    pub durability: DurabilityPolicy,
    pub retention: RetentionPolicy,
    pub authorization_policy_cid: Option<Cid>,
    pub created_at_unix_seconds: i64,
    pub creator_identity: String,
    pub creator_signature_hex: String,
}

impl NamespaceDescriptor {
    pub fn new(
        kind: NamespaceKind,
        mut initial_replica_set: Vec<String>,
        creator_identity: impl Into<String>,
        creator_signature_hex: impl Into<String>,
        created_at_unix_seconds: i64,
    ) -> Self {
        initial_replica_set.sort();
        let replication_factor = u16::try_from(initial_replica_set.len()).unwrap_or(u16::MAX);
        Self {
            descriptor_type: DESCRIPTOR_TYPE.to_string(),
            version: FORMAT_VERSION,
            kind,
            initial_replica_set,
            consensus_protocol_version: 1,
            replication_factor,
            placement_constraints: BTreeMap::new(),
            durability: DurabilityPolicy {
                replicas: replication_factor,
            },
            retention: RetentionPolicy {
                keep_last: 64,
                max_age_seconds: None,
            },
            authorization_policy_cid: None,
            created_at_unix_seconds,
            creator_identity: creator_identity.into(),
            creator_signature_hex: creator_signature_hex.into(),
        }
    }

    pub fn validate(&self, limits: &NamespaceLimits) -> Result<(), NamespaceError> {
        if self.descriptor_type != DESCRIPTOR_TYPE || self.version != FORMAT_VERSION {
            return Err(NamespaceError::InvalidDescriptor(
                "unsupported type or version".to_string(),
            ));
        }
        if !matches!(self.initial_replica_set.len(), 1 | 3)
            || usize::from(self.replication_factor) != self.initial_replica_set.len()
            || self.durability.replicas == 0
        {
            return Err(NamespaceError::InvalidDescriptor(
                "namespaces require either one demo voter or exactly three Raft replicas"
                    .to_string(),
            ));
        }
        if self
            .initial_replica_set
            .windows(2)
            .any(|nodes| nodes[0] >= nodes[1])
            || self
                .initial_replica_set
                .iter()
                .any(|node| node.is_empty() || node.len() > limits.max_identity_bytes)
        {
            return Err(NamespaceError::InvalidDescriptor(
                "replica IDs must be non-empty, unique, and sorted".to_string(),
            ));
        }
        if self.creator_identity.is_empty()
            || self.creator_identity.len() > limits.max_identity_bytes
            || !valid_hex_field(&self.creator_signature_hex, limits.max_signature_bytes)
            || self.created_at_unix_seconds < 0
        {
            return Err(NamespaceError::InvalidDescriptor(
                "invalid creator identity, signature, or timestamp".to_string(),
            ));
        }
        if self.retention.keep_last == 0
            || self.retention.keep_last > limits.max_retained_revisions as u32
        {
            return Err(NamespaceError::InvalidDescriptor(
                "retention keep_last is outside configured limits".to_string(),
            ));
        }
        if self
            .placement_constraints
            .iter()
            .any(|(key, value)| key.is_empty() || value.is_empty())
        {
            return Err(NamespaceError::InvalidDescriptor(
                "placement constraints must be non-empty".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceLimits {
    pub max_transaction_mutations: usize,
    pub max_transaction_key_bytes: usize,
    pub max_message_bytes: usize,
    pub max_identity_bytes: usize,
    pub max_signature_bytes: usize,
    pub max_request_id_bytes: usize,
    pub max_snapshot_name_bytes: usize,
    pub max_named_snapshots: usize,
    pub max_retained_revisions: usize,
    pub max_idempotency_records: usize,
    pub max_rollback_entries: usize,
}

impl Default for NamespaceLimits {
    fn default() -> Self {
        Self {
            max_transaction_mutations: 10_000,
            max_transaction_key_bytes: 8 * 1024 * 1024,
            max_message_bytes: 4 * 1024,
            max_identity_bytes: 256,
            max_signature_bytes: 1024,
            max_request_id_bytes: 128,
            max_snapshot_name_bytes: 256,
            max_named_snapshots: 10_000,
            max_retained_revisions: 100_000,
            max_idempotency_records: 100_000,
            max_rollback_entries: 1_000_000,
        }
    }
}

impl NamespaceLimits {
    pub fn validate(self) -> Result<Self, NamespaceError> {
        if self.max_transaction_mutations == 0
            || self.max_transaction_key_bytes == 0
            || self.max_message_bytes == 0
            || self.max_identity_bytes == 0
            || self.max_signature_bytes == 0
            || self.max_request_id_bytes == 0
            || self.max_snapshot_name_bytes == 0
            || self.max_named_snapshots == 0
            || self.max_retained_revisions == 0
            || self.max_idempotency_records == 0
            || self.max_rollback_entries == 0
        {
            return Err(NamespaceError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyPrecondition {
    Absent,
    Match { generation: u64, cid: Cid },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum NamespaceMutation {
    /// Verify a key at the transaction's linearization point without changing it.
    /// This is used by higher-level protocols to fence a data mutation against
    /// a separately committed routing epoch.
    Assert {
        key_hex: String,
        precondition: KeyPrecondition,
    },
    Put {
        key_hex: String,
        value_cid: Cid,
        value_kind: String,
        #[serde(default)]
        metadata: BTreeMap<String, String>,
        precondition: KeyPrecondition,
    },
    Delete {
        key_hex: String,
        precondition: KeyPrecondition,
    },
}

impl NamespaceMutation {
    fn key(&self) -> Result<Vec<u8>, NamespaceError> {
        let key_hex = match self {
            Self::Assert { key_hex, .. }
            | Self::Put { key_hex, .. }
            | Self::Delete { key_hex, .. } => key_hex,
        };
        hex::decode(key_hex).map_err(|error| NamespaceError::InvalidMutation(error.to_string()))
    }

    fn precondition(&self) -> &KeyPrecondition {
        match self {
            Self::Assert { precondition, .. }
            | Self::Put { precondition, .. }
            | Self::Delete { precondition, .. } => precondition,
        }
    }
}

#[derive(Debug, Clone)]
enum PendingMutation {
    Put {
        value: MerkleValue,
        precondition: KeyPrecondition,
    },
    Delete {
        precondition: KeyPrecondition,
    },
}

/// Client-side snapshot transaction builder. Reads always use the immutable
/// base root and consult the local write set first, providing read-your-writes
/// without holding server-side mutable transaction state.
#[derive(Debug, Clone)]
pub struct SnapshotTransaction {
    base_revision: u64,
    base_root_cid: Cid,
    observed: BTreeMap<Vec<u8>, Option<MerkleValue>>,
    pending: BTreeMap<Vec<u8>, PendingMutation>,
}

impl SnapshotTransaction {
    pub fn new(state: &NamespaceState) -> Self {
        Self {
            base_revision: state.current_revision,
            base_root_cid: state.current_root_cid.clone(),
            observed: BTreeMap::new(),
            pending: BTreeMap::new(),
        }
    }

    pub fn base_revision(&self) -> u64 {
        self.base_revision
    }

    pub fn base_root_cid(&self) -> &Cid {
        &self.base_root_cid
    }

    pub async fn get<S>(
        &mut self,
        store: &S,
        key: &[u8],
        merkle_limits: MerkleLimits,
    ) -> Result<Option<MerkleValue>, NamespaceError>
    where
        S: MerkleReadStore + ?Sized,
    {
        if let Some(pending) = self.pending.get(key) {
            return Ok(match pending {
                PendingMutation::Put { value, .. } => Some(value.clone()),
                PendingMutation::Delete { .. } => None,
            });
        }
        self.observe(store, key, merkle_limits).await
    }

    pub async fn put<S>(
        &mut self,
        store: &S,
        key: Vec<u8>,
        value_cid: Cid,
        value_kind: String,
        metadata: BTreeMap<String, String>,
        merkle_limits: MerkleLimits,
    ) -> Result<(), NamespaceError>
    where
        S: MerkleReadStore + ?Sized,
    {
        let observed = self.observe(store, &key, merkle_limits).await?;
        let generation = observed.as_ref().map_or(1, |value| value.generation + 1);
        self.pending.insert(
            key,
            PendingMutation::Put {
                value: MerkleValue {
                    cid: value_cid,
                    generation,
                    value_kind,
                    metadata,
                },
                precondition: precondition_for(observed.as_ref()),
            },
        );
        Ok(())
    }

    pub async fn delete<S>(
        &mut self,
        store: &S,
        key: Vec<u8>,
        merkle_limits: MerkleLimits,
    ) -> Result<(), NamespaceError>
    where
        S: MerkleReadStore + ?Sized,
    {
        let observed = self.observe(store, &key, merkle_limits).await?;
        if observed.is_none() {
            self.pending.remove(&key);
        } else {
            self.pending.insert(
                key,
                PendingMutation::Delete {
                    precondition: precondition_for(observed.as_ref()),
                },
            );
        }
        Ok(())
    }

    pub fn into_command(self, message: Option<String>) -> TransactionCommand {
        let mutations = self
            .pending
            .into_iter()
            .map(|(key, pending)| match pending {
                PendingMutation::Put {
                    value,
                    precondition,
                } => NamespaceMutation::Put {
                    key_hex: hex::encode(key),
                    value_cid: value.cid,
                    value_kind: value.value_kind,
                    metadata: value.metadata,
                    precondition,
                },
                PendingMutation::Delete { precondition } => NamespaceMutation::Delete {
                    key_hex: hex::encode(key),
                    precondition,
                },
            })
            .collect();
        TransactionCommand {
            base_revision: self.base_revision,
            base_root_cid: self.base_root_cid,
            mutations,
            message,
        }
    }

    async fn observe<S>(
        &mut self,
        store: &S,
        key: &[u8],
        merkle_limits: MerkleLimits,
    ) -> Result<Option<MerkleValue>, NamespaceError>
    where
        S: MerkleReadStore + ?Sized,
    {
        if let Some(value) = self.observed.get(key) {
            return Ok(value.clone());
        }
        let value = pepper_merkle::get(store, &self.base_root_cid, key, merkle_limits).await?;
        self.observed.insert(key.to_vec(), value.clone());
        Ok(value)
    }
}

fn precondition_for(value: Option<&MerkleValue>) -> KeyPrecondition {
    value.map_or(KeyPrecondition::Absent, |value| KeyPrecondition::Match {
        generation: value.generation,
        cid: value.cid.clone(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransactionCommand {
    pub base_revision: u64,
    pub base_root_cid: Cid,
    pub mutations: Vec<NamespaceMutation>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum NamespaceCommand {
    ApplyTransaction {
        transaction: TransactionCommand,
    },
    CreateSnapshot {
        name: String,
        revision: Option<u64>,
    },
    DeleteSnapshot {
        name: String,
    },
    Rollback {
        revision: u64,
        message: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandEnvelope {
    pub request_id: String,
    pub writer_identity: String,
    pub timestamp_unix_seconds: i64,
    pub signature_hex: String,
    pub command: NamespaceCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangedKey {
    pub key_hex: String,
    pub generation: Option<u64>,
    pub value_cid: Option<Cid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitResponse {
    pub namespace_id: NamespaceId,
    pub namespace_revision: u64,
    pub root_cid: Cid,
    pub commit_cid: Cid,
    pub changed_keys: Vec<ChangedKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotResponse {
    pub namespace_id: NamespaceId,
    pub name: String,
    pub revision: u64,
    pub root_cid: Cid,
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CommandResponse {
    Commit(CommitResponse),
    Snapshot(SnapshotResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinIntent {
    pub cid: Cid,
    pub action: PinAction,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PinAction {
    Protect,
    Release,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApplyResult {
    pub response: CommandResponse,
    pub pin_intents: Vec<PinIntent>,
    pub replayed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevisionRecord {
    pub revision: u64,
    pub root_cid: Cid,
    pub commit_cid: Option<Cid>,
    pub committed_at_unix_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamedSnapshot {
    pub name: String,
    pub revision: u64,
    pub root_cid: Cid,
    pub commit_cid: Option<Cid>,
    pub created_at_unix_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IdempotencyRecord {
    command_fingerprint: Cid,
    response: CommandResponse,
    pin_intents: Vec<PinIntent>,
    applied_revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceState {
    pub namespace_id: NamespaceId,
    pub descriptor: NamespaceDescriptor,
    pub current_revision: u64,
    pub current_root_cid: Cid,
    pub head_commit_cid: Option<Cid>,
    pub history: BTreeMap<u64, RevisionRecord>,
    pub named_snapshots: BTreeMap<String, NamedSnapshot>,
    idempotency: BTreeMap<String, IdempotencyRecord>,
}

impl NamespaceState {
    pub fn into_head_projection(mut self) -> Self {
        self.history.clear();
        self.named_snapshots.clear();
        self.idempotency.clear();
        self
    }

    pub fn idempotent_response_for(
        &self,
        envelope: &CommandEnvelope,
    ) -> Result<Option<CommandResponse>, NamespaceError> {
        let Some(record) = self.idempotency.get(&envelope.request_id) else {
            return Ok(None);
        };
        let fingerprint = idempotency_fingerprint(&self.namespace_id, envelope)?;
        if record.command_fingerprint != fingerprint {
            return Err(NamespaceError::IdempotencyConflict);
        }
        Ok(Some(record.response.clone()))
    }

    /// Reconstruct the exact applied result after a caller loses an ambiguous
    /// commit response. The command fingerprint prevents an idempotency key
    /// from being reused for a different transition.
    pub fn idempotent_apply_result_for(
        &self,
        envelope: &CommandEnvelope,
    ) -> Result<Option<ApplyResult>, NamespaceError> {
        let Some(record) = self.idempotency.get(&envelope.request_id) else {
            return Ok(None);
        };
        let fingerprint = idempotency_fingerprint(&self.namespace_id, envelope)?;
        if record.command_fingerprint != fingerprint {
            return Err(NamespaceError::IdempotencyConflict);
        }
        Ok(Some(ApplyResult {
            response: record.response.clone(),
            pin_intents: record.pin_intents.clone(),
            replayed: true,
        }))
    }

    /// Read-only status lookup for a request whose original envelope may no
    /// longer be available after a client loses the commit response.
    pub fn idempotent_response(&self, request_id: &str) -> Option<&CommandResponse> {
        self.idempotency
            .get(request_id)
            .map(|record| &record.response)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamespaceCommit {
    #[serde(rename = "type")]
    pub commit_type: String,
    pub version: u32,
    pub namespace_id: NamespaceId,
    pub new_root_cid: Cid,
    /// Weak history reference: not followed by the DAG handler so retention can expire roots.
    pub parent_commit_cid: Option<Cid>,
    pub base_namespace_revision: u64,
    pub new_namespace_revision: u64,
    pub changed_keys: Vec<ChangedKey>,
    pub committed_at_unix_seconds: i64,
    pub writer_identity: String,
    pub request_id: String,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamespaceCheckpoint {
    #[serde(rename = "type")]
    pub checkpoint_type: String,
    pub version: u32,
    pub state: NamespaceState,
    pub created_at_unix_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedNamespace {
    pub namespace_id: NamespaceId,
    pub descriptor_cid: Cid,
    pub root_cid: Cid,
    pub checkpoint_cid: Cid,
    pub state: NamespaceState,
    pub pin_intents: Vec<PinIntent>,
}

#[derive(Debug, Error)]
pub enum NamespaceError {
    #[error("invalid namespace limits")]
    InvalidLimits,
    #[error("invalid namespace codec {0}")]
    InvalidCodec(String),
    #[error("invalid namespace descriptor: {0}")]
    InvalidDescriptor(String),
    #[error("invalid namespace command: {0}")]
    InvalidCommand(String),
    #[error("invalid namespace mutation: {0}")]
    InvalidMutation(String),
    #[error("namespace command is not authorized: {0}")]
    Unauthorized(String),
    #[error("namespace store read failed for {cid}: {message}")]
    Read { cid: String, message: String },
    #[error("namespace store write failed: {0}")]
    Write(String),
    #[error("namespace store returned CID {actual}, expected {expected}")]
    WrongStoredCid { expected: String, actual: String },
    #[error("non-canonical namespace payload")]
    NonCanonical,
    #[error("namespace payload is invalid: {0}")]
    InvalidPayload(String),
    #[error("Merkle operation failed: {0}")]
    Merkle(String),
    #[error("snapshot revision {0} is not known")]
    UnknownRevision(u64),
    #[error("transaction base revision/root is stale or mismatched")]
    StaleSnapshot,
    #[error("generation conflict for key {0}")]
    GenerationConflict(String),
    #[error("transaction contains no mutations")]
    EmptyTransaction,
    #[error("transaction produced no state change")]
    NoChanges,
    #[error("request ID was previously used for a different command")]
    IdempotencyConflict,
    #[error("named snapshot {0} already exists")]
    SnapshotExists(String),
    #[error("named snapshot {0} does not exist")]
    SnapshotNotFound(String),
    #[error("rollback exceeds the {0}-entry limit")]
    RollbackTooLarge(usize),
}

impl From<MerkleError> for NamespaceError {
    fn from(error: MerkleError) -> Self {
        Self::Merkle(error.to_string())
    }
}

#[async_trait]
pub trait NamespaceStore: MerkleWriteStore {}

impl<T> NamespaceStore for T where T: MerkleWriteStore + ?Sized {}

pub trait CommandAuthorizer: Send + Sync {
    fn verify(
        &self,
        namespace_id: &NamespaceId,
        writer_identity: &str,
        signing_payload: &[u8],
        signature_hex: &str,
    ) -> Result<(), String>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAllAuthorizer;

impl CommandAuthorizer for AllowAllAuthorizer {
    fn verify(
        &self,
        _namespace_id: &NamespaceId,
        _writer_identity: &str,
        _signing_payload: &[u8],
        _signature_hex: &str,
    ) -> Result<(), String> {
        Ok(())
    }
}

pub async fn create_namespace<S>(
    store: &S,
    descriptor: NamespaceDescriptor,
    namespace_limits: NamespaceLimits,
    merkle_limits: MerkleLimits,
) -> Result<CreatedNamespace, NamespaceError>
where
    S: NamespaceStore + ?Sized,
{
    let namespace_limits = namespace_limits.validate()?;
    descriptor.validate(&namespace_limits)?;
    let descriptor_bytes = canonical_bytes(&descriptor)?;
    let descriptor_cid = put_canonical(store, CODEC_NAMESPACE_DESCRIPTOR, descriptor_bytes).await?;
    let namespace_id = NamespaceId::new(descriptor_cid.clone())?;
    let root_cid = pepper_merkle::empty_root(store, merkle_limits).await?;
    let initial = RevisionRecord {
        revision: 0,
        root_cid: root_cid.clone(),
        commit_cid: None,
        committed_at_unix_seconds: descriptor.created_at_unix_seconds,
    };
    let state = NamespaceState {
        namespace_id: namespace_id.clone(),
        descriptor,
        current_revision: 0,
        current_root_cid: root_cid.clone(),
        head_commit_cid: None,
        history: BTreeMap::from([(0, initial)]),
        named_snapshots: BTreeMap::new(),
        idempotency: BTreeMap::new(),
    };
    let checkpoint_cid =
        write_checkpoint(store, &state, state.descriptor.created_at_unix_seconds).await?;
    Ok(CreatedNamespace {
        namespace_id,
        descriptor_cid,
        root_cid,
        pin_intents: vec![PinIntent {
            cid: checkpoint_cid.clone(),
            action: PinAction::Protect,
            reason: "namespace_genesis_checkpoint".to_string(),
        }],
        checkpoint_cid,
        state,
    })
}

pub struct NamespaceStateMachine<S, A = AllowAllAuthorizer> {
    store: S,
    authorizer: A,
    state: NamespaceState,
    namespace_limits: NamespaceLimits,
    merkle_limits: MerkleLimits,
}

impl<S> NamespaceStateMachine<S, AllowAllAuthorizer> {
    pub fn new(store: S, state: NamespaceState) -> Result<Self, NamespaceError> {
        Self::with_authorizer(
            store,
            state,
            AllowAllAuthorizer,
            NamespaceLimits::default(),
            MerkleLimits::default(),
        )
    }
}

impl<S, A> NamespaceStateMachine<S, A> {
    pub fn with_authorizer(
        store: S,
        state: NamespaceState,
        authorizer: A,
        namespace_limits: NamespaceLimits,
        merkle_limits: MerkleLimits,
    ) -> Result<Self, NamespaceError> {
        let namespace_limits = namespace_limits.validate()?;
        state.descriptor.validate(&namespace_limits)?;
        validate_namespace_state(&state, &namespace_limits)?;
        Ok(Self {
            store,
            authorizer,
            state,
            namespace_limits,
            merkle_limits,
        })
    }

    pub fn state(&self) -> &NamespaceState {
        &self.state
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn begin_transaction(&self) -> SnapshotTransaction {
        SnapshotTransaction::new(&self.state)
    }

    pub fn into_parts(self) -> (S, NamespaceState) {
        (self.store, self.state)
    }
}

impl<S, A> NamespaceStateMachine<S, A>
where
    S: NamespaceStore,
    A: CommandAuthorizer,
{
    pub async fn apply(
        &mut self,
        envelope: CommandEnvelope,
    ) -> Result<ApplyResult, NamespaceError> {
        validate_envelope(&envelope, &self.namespace_limits)?;
        let signing_payload = canonical_signing_payload(&self.state.namespace_id, &envelope)?;
        self.authorizer
            .verify(
                &self.state.namespace_id,
                &envelope.writer_identity,
                &signing_payload,
                &envelope.signature_hex,
            )
            .map_err(NamespaceError::Unauthorized)?;
        let fingerprint = idempotency_fingerprint(&self.state.namespace_id, &envelope)?;
        if let Some(existing) = self.state.idempotency.get(&envelope.request_id) {
            if existing.command_fingerprint != fingerprint {
                return Err(NamespaceError::IdempotencyConflict);
            }
            return Ok(ApplyResult {
                response: existing.response.clone(),
                pin_intents: existing.pin_intents.clone(),
                replayed: true,
            });
        }

        // Concurrent commands can reach the leader in one order and be committed
        // in another. Preserve the authenticated client timestamp in the
        // idempotency fingerprint, but derive a monotonic commit timestamp from
        // consensus order so an otherwise valid command is never rejected merely
        // because another gateway observed a later wall clock first.
        let mut applied_envelope = envelope.clone();
        if let Some(record) = self.state.history.get(&self.state.current_revision) {
            applied_envelope.timestamp_unix_seconds = applied_envelope
                .timestamp_unix_seconds
                .max(record.committed_at_unix_seconds);
        }
        let before = protected_roots(&self.state);
        let mut next = self.state.clone();
        let response = match &applied_envelope.command {
            NamespaceCommand::ApplyTransaction { transaction } => CommandResponse::Commit(
                apply_transaction(
                    &self.store,
                    &mut next,
                    transaction,
                    &applied_envelope,
                    &self.namespace_limits,
                    self.merkle_limits,
                )
                .await?,
            ),
            NamespaceCommand::CreateSnapshot { name, revision } => {
                CommandResponse::Snapshot(create_snapshot(
                    &mut next,
                    name,
                    *revision,
                    applied_envelope.timestamp_unix_seconds,
                    &self.namespace_limits,
                )?)
            }
            NamespaceCommand::DeleteSnapshot { name } => {
                CommandResponse::Snapshot(delete_snapshot(&mut next, name)?)
            }
            NamespaceCommand::Rollback { revision, message } => CommandResponse::Commit(
                rollback(
                    &self.store,
                    &mut next,
                    *revision,
                    message.clone(),
                    &applied_envelope,
                    &self.namespace_limits,
                    self.merkle_limits,
                )
                .await?,
            ),
        };
        let after = protected_roots(&next);
        let pin_intents = diff_pin_intents(before, after);
        next.idempotency.insert(
            envelope.request_id.clone(),
            IdempotencyRecord {
                command_fingerprint: fingerprint,
                response: response.clone(),
                pin_intents: pin_intents.clone(),
                applied_revision: next.current_revision,
            },
        );
        prune_idempotency(&mut next, self.namespace_limits.max_idempotency_records);
        self.state = next;
        Ok(ApplyResult {
            response,
            pin_intents,
            replayed: false,
        })
    }

    pub async fn get(
        &self,
        revision: Option<u64>,
        key: &[u8],
    ) -> Result<Option<MerkleValue>, NamespaceError> {
        let root = revision_root(&self.state, revision)?;
        pepper_merkle::get(&self.store, &root, key, self.merkle_limits)
            .await
            .map_err(Into::into)
    }

    pub async fn scan(
        &self,
        revision: Option<u64>,
        query: ScanQuery,
    ) -> Result<ScanPage, NamespaceError> {
        let root = revision_root(&self.state, revision)?;
        pepper_merkle::scan(&self.store, &root, query, self.merkle_limits)
            .await
            .map_err(Into::into)
    }

    pub async fn checkpoint(&self, created_at_unix_seconds: i64) -> Result<Cid, NamespaceError> {
        write_checkpoint(&self.store, &self.state, created_at_unix_seconds).await
    }
}

async fn apply_transaction<S>(
    store: &S,
    state: &mut NamespaceState,
    transaction: &TransactionCommand,
    envelope: &CommandEnvelope,
    limits: &NamespaceLimits,
    merkle_limits: MerkleLimits,
) -> Result<CommitResponse, NamespaceError>
where
    S: NamespaceStore + ?Sized,
{
    validate_transaction(state, transaction, limits)?;
    let mut merkle_mutations = Vec::with_capacity(transaction.mutations.len());
    let mut changed = Vec::with_capacity(transaction.mutations.len());
    for mutation in &transaction.mutations {
        let key = mutation.key()?;
        let current =
            pepper_merkle::get(store, &state.current_root_cid, &key, merkle_limits).await?;
        check_precondition(&key, current.as_ref(), mutation.precondition())?;
        match mutation {
            NamespaceMutation::Assert { .. } => {}
            NamespaceMutation::Put {
                value_cid,
                value_kind,
                metadata,
                ..
            } => {
                let generation = current.as_ref().map_or(1, |value| value.generation + 1);
                let value = MerkleValue {
                    cid: value_cid.clone(),
                    generation,
                    value_kind: value_kind.clone(),
                    metadata: metadata.clone(),
                };
                merkle_mutations.push(Mutation::Put {
                    key: key.clone(),
                    value,
                });
                changed.push(ChangedKey {
                    key_hex: hex::encode(key),
                    generation: Some(generation),
                    value_cid: Some(value_cid.clone()),
                });
            }
            NamespaceMutation::Delete { .. } => {
                if current.is_none() {
                    return Err(NamespaceError::NoChanges);
                }
                merkle_mutations.push(Mutation::Delete { key: key.clone() });
                changed.push(ChangedKey {
                    key_hex: hex::encode(key),
                    generation: None,
                    value_cid: None,
                });
            }
        }
    }
    commit_merkle_mutations(
        store,
        state,
        CommitDraft {
            mutations: merkle_mutations,
            changed_keys: changed,
            base_revision: transaction.base_revision,
            message: transaction.message.clone(),
        },
        envelope,
        merkle_limits,
    )
    .await
}

struct CommitDraft {
    mutations: Vec<Mutation>,
    changed_keys: Vec<ChangedKey>,
    base_revision: u64,
    message: Option<String>,
}

async fn commit_merkle_mutations<S>(
    store: &S,
    state: &mut NamespaceState,
    draft: CommitDraft,
    envelope: &CommandEnvelope,
    merkle_limits: MerkleLimits,
) -> Result<CommitResponse, NamespaceError>
where
    S: NamespaceStore + ?Sized,
{
    if draft.mutations.is_empty() {
        return Err(NamespaceError::NoChanges);
    }
    let new_root = pepper_merkle::apply_batch(
        store,
        &state.current_root_cid,
        &draft.mutations,
        merkle_limits,
    )
    .await?;
    let new_revision = state.current_revision.saturating_add(1);
    let commit = NamespaceCommit {
        commit_type: COMMIT_TYPE.to_string(),
        version: FORMAT_VERSION,
        namespace_id: state.namespace_id.clone(),
        new_root_cid: new_root.clone(),
        parent_commit_cid: state.head_commit_cid.clone(),
        base_namespace_revision: draft.base_revision,
        new_namespace_revision: new_revision,
        changed_keys: draft.changed_keys.clone(),
        committed_at_unix_seconds: envelope.timestamp_unix_seconds,
        writer_identity: envelope.writer_identity.clone(),
        request_id: envelope.request_id.clone(),
        message: draft.message,
    };
    let commit_cid =
        put_canonical(store, CODEC_NAMESPACE_COMMIT, canonical_bytes(&commit)?).await?;
    state.current_revision = new_revision;
    state.current_root_cid = new_root.clone();
    state.head_commit_cid = Some(commit_cid.clone());
    state.history.insert(
        new_revision,
        RevisionRecord {
            revision: new_revision,
            root_cid: new_root.clone(),
            commit_cid: Some(commit_cid.clone()),
            committed_at_unix_seconds: envelope.timestamp_unix_seconds,
        },
    );
    Ok(CommitResponse {
        namespace_id: state.namespace_id.clone(),
        namespace_revision: new_revision,
        root_cid: new_root,
        commit_cid,
        changed_keys: draft.changed_keys,
    })
}

fn validate_transaction(
    state: &NamespaceState,
    transaction: &TransactionCommand,
    limits: &NamespaceLimits,
) -> Result<(), NamespaceError> {
    if transaction.mutations.is_empty() {
        return Err(NamespaceError::EmptyTransaction);
    }
    if transaction.mutations.len() > limits.max_transaction_mutations {
        return Err(NamespaceError::InvalidCommand(
            "too many transaction mutations".to_string(),
        ));
    }
    if transaction
        .message
        .as_ref()
        .is_some_and(|message| message.len() > limits.max_message_bytes)
    {
        return Err(NamespaceError::InvalidCommand(
            "commit message exceeds limit".to_string(),
        ));
    }
    let Some(base) = state.history.get(&transaction.base_revision) else {
        return Err(NamespaceError::StaleSnapshot);
    };
    if base.root_cid != transaction.base_root_cid
        || transaction.base_revision > state.current_revision
    {
        return Err(NamespaceError::StaleSnapshot);
    }
    let mut previous: Option<Vec<u8>> = None;
    let mut total_key_bytes = 0usize;
    for mutation in &transaction.mutations {
        let key = mutation.key()?;
        total_key_bytes = total_key_bytes.saturating_add(key.len());
        if previous.as_ref().is_some_and(|previous| previous >= &key) {
            return Err(NamespaceError::InvalidMutation(
                "mutations must be strictly sorted by unique key".to_string(),
            ));
        }
        previous = Some(key);
    }
    if total_key_bytes > limits.max_transaction_key_bytes {
        return Err(NamespaceError::InvalidMutation(
            "transaction key bytes exceed limit".to_string(),
        ));
    }
    Ok(())
}

fn check_precondition(
    key: &[u8],
    current: Option<&MerkleValue>,
    precondition: &KeyPrecondition,
) -> Result<(), NamespaceError> {
    let matches = match precondition {
        KeyPrecondition::Absent => current.is_none(),
        KeyPrecondition::Match { generation, cid } => {
            current.is_some_and(|current| current.generation == *generation && current.cid == *cid)
        }
    };
    if matches {
        Ok(())
    } else {
        Err(NamespaceError::GenerationConflict(hex::encode(key)))
    }
}

fn create_snapshot(
    state: &mut NamespaceState,
    name: &str,
    revision: Option<u64>,
    created_at_unix_seconds: i64,
    limits: &NamespaceLimits,
) -> Result<SnapshotResponse, NamespaceError> {
    validate_snapshot_name(name, limits)?;
    if state.named_snapshots.contains_key(name) {
        return Err(NamespaceError::SnapshotExists(name.to_string()));
    }
    if state.named_snapshots.len() >= limits.max_named_snapshots {
        return Err(NamespaceError::InvalidCommand(
            "named snapshot limit reached".to_string(),
        ));
    }
    let revision = revision.unwrap_or(state.current_revision);
    let record = state
        .history
        .get(&revision)
        .ok_or(NamespaceError::UnknownRevision(revision))?;
    let snapshot = NamedSnapshot {
        name: name.to_string(),
        revision,
        root_cid: record.root_cid.clone(),
        commit_cid: record.commit_cid.clone(),
        created_at_unix_seconds,
    };
    state
        .named_snapshots
        .insert(name.to_string(), snapshot.clone());
    Ok(SnapshotResponse {
        namespace_id: state.namespace_id.clone(),
        name: name.to_string(),
        revision,
        root_cid: snapshot.root_cid,
        deleted: false,
    })
}

fn delete_snapshot(
    state: &mut NamespaceState,
    name: &str,
) -> Result<SnapshotResponse, NamespaceError> {
    let snapshot = state
        .named_snapshots
        .remove(name)
        .ok_or_else(|| NamespaceError::SnapshotNotFound(name.to_string()))?;
    Ok(SnapshotResponse {
        namespace_id: state.namespace_id.clone(),
        name: name.to_string(),
        revision: snapshot.revision,
        root_cid: snapshot.root_cid,
        deleted: true,
    })
}

async fn rollback<S>(
    store: &S,
    state: &mut NamespaceState,
    revision: u64,
    message: Option<String>,
    envelope: &CommandEnvelope,
    limits: &NamespaceLimits,
    merkle_limits: MerkleLimits,
) -> Result<CommitResponse, NamespaceError>
where
    S: NamespaceStore + ?Sized,
{
    let target = state
        .history
        .get(&revision)
        .ok_or(NamespaceError::UnknownRevision(revision))?
        .clone();
    let current = read_all(
        store,
        &state.current_root_cid,
        limits.max_rollback_entries,
        merkle_limits,
    )
    .await?;
    let target_values = read_all(
        store,
        &target.root_cid,
        limits.max_rollback_entries,
        merkle_limits,
    )
    .await?;
    let keys = current
        .keys()
        .chain(target_values.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    if keys.len() > limits.max_rollback_entries {
        return Err(NamespaceError::RollbackTooLarge(
            limits.max_rollback_entries,
        ));
    }
    let mut mutations = Vec::new();
    let mut changed = Vec::new();
    for key in keys {
        let current_value = current.get(&key);
        let target_value = target_values.get(&key);
        if same_logical_value(current_value, target_value) {
            continue;
        }
        match target_value {
            Some(target_value) => {
                let generation = current_value.map_or(1, |value| value.generation + 1);
                mutations.push(Mutation::Put {
                    key: key.clone(),
                    value: MerkleValue {
                        cid: target_value.cid.clone(),
                        generation,
                        value_kind: target_value.value_kind.clone(),
                        metadata: target_value.metadata.clone(),
                    },
                });
                changed.push(ChangedKey {
                    key_hex: hex::encode(&key),
                    generation: Some(generation),
                    value_cid: Some(target_value.cid.clone()),
                });
            }
            None => {
                mutations.push(Mutation::Delete { key: key.clone() });
                changed.push(ChangedKey {
                    key_hex: hex::encode(&key),
                    generation: None,
                    value_cid: None,
                });
            }
        }
    }
    commit_merkle_mutations(
        store,
        state,
        CommitDraft {
            mutations,
            changed_keys: changed,
            base_revision: state.current_revision,
            message: message.or_else(|| Some(format!("rollback to revision {revision}"))),
        },
        envelope,
        merkle_limits,
    )
    .await
}

async fn read_all<S>(
    store: &S,
    root: &Cid,
    limit: usize,
    merkle_limits: MerkleLimits,
) -> Result<BTreeMap<Vec<u8>, MerkleValue>, NamespaceError>
where
    S: MerkleReadStore + ?Sized,
{
    let mut values = BTreeMap::new();
    let mut cursor = None;
    loop {
        let remaining = limit.saturating_add(1).saturating_sub(values.len());
        if remaining == 0 {
            return Err(NamespaceError::RollbackTooLarge(limit));
        }
        let page = pepper_merkle::scan(
            store,
            root,
            ScanQuery {
                limit: remaining.min(merkle_limits.max_scan_entries),
                cursor,
                ..ScanQuery::default()
            },
            merkle_limits,
        )
        .await?;
        for entry in page.entries {
            values.insert(entry.key, entry.value);
        }
        if values.len() > limit {
            return Err(NamespaceError::RollbackTooLarge(limit));
        }
        let Some(next) = page.next_cursor else {
            break;
        };
        cursor = Some(next);
    }
    Ok(values)
}

fn same_logical_value(left: Option<&MerkleValue>, right: Option<&MerkleValue>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.cid == right.cid
                && left.value_kind == right.value_kind
                && left.metadata == right.metadata
        }
        _ => false,
    }
}

fn validate_envelope(
    envelope: &CommandEnvelope,
    limits: &NamespaceLimits,
) -> Result<(), NamespaceError> {
    if envelope.request_id.is_empty() || envelope.request_id.len() > limits.max_request_id_bytes {
        return Err(NamespaceError::InvalidCommand(
            "invalid request ID".to_string(),
        ));
    }
    if envelope.writer_identity.is_empty()
        || envelope.writer_identity.len() > limits.max_identity_bytes
        || !valid_hex_field(&envelope.signature_hex, limits.max_signature_bytes)
        || envelope.timestamp_unix_seconds < 0
    {
        return Err(NamespaceError::InvalidCommand(
            "invalid writer identity, signature, or timestamp".to_string(),
        ));
    }
    Ok(())
}

fn valid_hex_field(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.len() % 2 == 0
        && hex::decode(value).is_ok()
}

fn validate_snapshot_name(name: &str, limits: &NamespaceLimits) -> Result<(), NamespaceError> {
    if name.is_empty()
        || name.len() > limits.max_snapshot_name_bytes
        || name.chars().any(char::is_control)
    {
        return Err(NamespaceError::InvalidCommand(
            "invalid snapshot name".to_string(),
        ));
    }
    Ok(())
}

pub fn decode_command_envelope(payload: &[u8]) -> Result<CommandEnvelope, NamespaceError> {
    let envelope: CommandEnvelope = decode_canonical(payload)?;
    validate_envelope(&envelope, &NamespaceLimits::default())?;
    Ok(envelope)
}

fn canonical_signing_payload(
    namespace_id: &NamespaceId,
    envelope: &CommandEnvelope,
) -> Result<Vec<u8>, NamespaceError> {
    #[derive(Serialize)]
    struct SigningPayload<'a> {
        domain: &'static str,
        namespace_id: &'a NamespaceId,
        request_id: &'a str,
        writer_identity: &'a str,
        timestamp_unix_seconds: i64,
        command: &'a NamespaceCommand,
    }
    canonical_bytes(&SigningPayload {
        domain: "pepper.namespace_command.v1",
        namespace_id,
        request_id: &envelope.request_id,
        writer_identity: &envelope.writer_identity,
        timestamp_unix_seconds: envelope.timestamp_unix_seconds,
        command: &envelope.command,
    })
}

fn idempotency_fingerprint(
    namespace_id: &NamespaceId,
    envelope: &CommandEnvelope,
) -> Result<Cid, NamespaceError> {
    #[derive(Serialize)]
    #[serde(tag = "op", rename_all = "snake_case")]
    enum IntentMutation<'a> {
        Assert {
            key_hex: &'a str,
        },
        Put {
            key_hex: &'a str,
            value_cid: &'a Cid,
            value_kind: &'a str,
            metadata: &'a BTreeMap<String, String>,
        },
        Delete {
            key_hex: &'a str,
        },
    }
    #[derive(Serialize)]
    #[serde(tag = "command", rename_all = "snake_case")]
    enum IntentCommand<'a> {
        ApplyTransaction {
            mutations: Vec<IntentMutation<'a>>,
            message: &'a Option<String>,
        },
        CreateSnapshot {
            name: &'a str,
            revision: Option<u64>,
        },
        DeleteSnapshot {
            name: &'a str,
        },
        Rollback {
            revision: u64,
            message: &'a Option<String>,
        },
    }
    #[derive(Serialize)]
    struct IdempotencyPayload<'a> {
        domain: &'static str,
        namespace_id: &'a NamespaceId,
        request_id: &'a str,
        writer_identity: &'a str,
        command: IntentCommand<'a>,
    }
    let command = match &envelope.command {
        NamespaceCommand::ApplyTransaction { transaction } => IntentCommand::ApplyTransaction {
            mutations: transaction
                .mutations
                .iter()
                .map(|mutation| match mutation {
                    NamespaceMutation::Assert { key_hex, .. } => IntentMutation::Assert { key_hex },
                    NamespaceMutation::Put {
                        key_hex,
                        value_cid,
                        value_kind,
                        metadata,
                        ..
                    } => IntentMutation::Put {
                        key_hex,
                        value_cid,
                        value_kind,
                        metadata,
                    },
                    NamespaceMutation::Delete { key_hex, .. } => IntentMutation::Delete { key_hex },
                })
                .collect(),
            message: &transaction.message,
        },
        NamespaceCommand::CreateSnapshot { name, revision } => IntentCommand::CreateSnapshot {
            name,
            revision: *revision,
        },
        NamespaceCommand::DeleteSnapshot { name } => IntentCommand::DeleteSnapshot { name },
        NamespaceCommand::Rollback { revision, message } => IntentCommand::Rollback {
            revision: *revision,
            message,
        },
    };
    let payload = canonical_bytes(&IdempotencyPayload {
        domain: "pepper.namespace_idempotency.v1",
        namespace_id,
        request_id: &envelope.request_id,
        writer_identity: &envelope.writer_identity,
        command,
    })?;
    Ok(Cid::new(CODEC_RAW, &payload))
}

fn revision_root(state: &NamespaceState, revision: Option<u64>) -> Result<Cid, NamespaceError> {
    let revision = revision.unwrap_or(state.current_revision);
    state
        .history
        .get(&revision)
        .map(|record| record.root_cid.clone())
        .ok_or(NamespaceError::UnknownRevision(revision))
}

fn protected_roots(state: &NamespaceState) -> BTreeMap<String, String> {
    let mut protected = BTreeMap::new();
    protected.insert(
        state.current_root_cid.to_string(),
        "namespace_head".to_string(),
    );
    if let Some(commit) = &state.head_commit_cid {
        protected.insert(commit.to_string(), "namespace_head_commit".to_string());
    }
    let keep_last = state.descriptor.retention.keep_last as u64;
    let first = state
        .current_revision
        .saturating_add(1)
        .saturating_sub(keep_last);
    let cutoff = state.descriptor.retention.max_age_seconds.map(|age| {
        state
            .history
            .get(&state.current_revision)
            .map_or(0, |record| record.committed_at_unix_seconds)
            .saturating_sub(age as i64)
    });
    for record in state.history.values() {
        if record.revision >= first
            || cutoff.is_some_and(|cutoff| record.committed_at_unix_seconds >= cutoff)
        {
            protected.insert(
                record.root_cid.to_string(),
                format!("retained_revision:{}", record.revision),
            );
            if let Some(commit) = &record.commit_cid {
                protected.insert(
                    commit.to_string(),
                    format!("retained_commit:{}", record.revision),
                );
            }
        }
    }
    for snapshot in state.named_snapshots.values() {
        protected.insert(
            snapshot.root_cid.to_string(),
            format!("named_snapshot:{}", snapshot.name),
        );
        if let Some(commit) = &snapshot.commit_cid {
            protected.insert(
                commit.to_string(),
                format!("named_snapshot_commit:{}", snapshot.name),
            );
        }
    }
    protected
}

fn diff_pin_intents(
    before: BTreeMap<String, String>,
    after: BTreeMap<String, String>,
) -> Vec<PinIntent> {
    let mut intents = Vec::new();
    for (cid, reason) in &after {
        if !before.contains_key(cid)
            && let Ok(cid) = cid.parse()
        {
            intents.push(PinIntent {
                cid,
                action: PinAction::Protect,
                reason: reason.clone(),
            });
        }
    }
    for (cid, reason) in &before {
        if !after.contains_key(cid)
            && let Ok(cid) = cid.parse()
        {
            intents.push(PinIntent {
                cid,
                action: PinAction::Release,
                reason: reason.clone(),
            });
        }
    }
    intents.sort_by_key(|intent| (intent.cid.to_string(), intent.action as u8));
    intents
}

fn prune_idempotency(state: &mut NamespaceState, limit: usize) {
    while state.idempotency.len() > limit {
        let Some(key) = state
            .idempotency
            .iter()
            .min_by_key(|(request_id, record)| (record.applied_revision, *request_id))
            .map(|(request_id, _)| request_id.clone())
        else {
            break;
        };
        state.idempotency.remove(&key);
    }
}

pub async fn write_checkpoint<S>(
    store: &S,
    state: &NamespaceState,
    created_at_unix_seconds: i64,
) -> Result<Cid, NamespaceError>
where
    S: NamespaceStore + ?Sized,
{
    if created_at_unix_seconds < 0 {
        return Err(NamespaceError::InvalidCommand(
            "invalid checkpoint timestamp".to_string(),
        ));
    }
    let checkpoint = NamespaceCheckpoint {
        checkpoint_type: CHECKPOINT_TYPE.to_string(),
        version: FORMAT_VERSION,
        state: state.clone(),
        created_at_unix_seconds,
    };
    put_canonical(
        store,
        CODEC_NAMESPACE_CHECKPOINT,
        canonical_bytes(&checkpoint)?,
    )
    .await
}

pub async fn load_checkpoint<S>(
    store: &S,
    cid: &Cid,
    namespace_limits: NamespaceLimits,
) -> Result<NamespaceState, NamespaceError>
where
    S: MerkleReadStore + ?Sized,
{
    if cid.codec != CODEC_NAMESPACE_CHECKPOINT {
        return Err(NamespaceError::InvalidCodec(cid.codec.canonical_display()));
    }
    let payload = store
        .get(cid)
        .await
        .map_err(|message| NamespaceError::Read {
            cid: cid.to_string(),
            message,
        })?;
    if !cid.verify(&payload) {
        return Err(NamespaceError::InvalidPayload(
            "checkpoint CID mismatch".to_string(),
        ));
    }
    let checkpoint: NamespaceCheckpoint = decode_canonical(&payload)?;
    if checkpoint.checkpoint_type != CHECKPOINT_TYPE || checkpoint.version != FORMAT_VERSION {
        return Err(NamespaceError::InvalidPayload(
            "unsupported checkpoint".to_string(),
        ));
    }
    let namespace_limits = namespace_limits.validate()?;
    validate_namespace_state(&checkpoint.state, &namespace_limits)?;
    Ok(checkpoint.state)
}

async fn put_canonical<S>(store: &S, codec: Codec, payload: Vec<u8>) -> Result<Cid, NamespaceError>
where
    S: MerkleWriteStore + ?Sized,
{
    let expected = Cid::new(codec, &payload);
    let actual = store
        .put(codec, payload)
        .await
        .map_err(NamespaceError::Write)?;
    if actual != expected {
        return Err(NamespaceError::WrongStoredCid {
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(actual)
}

fn validate_namespace_state(
    state: &NamespaceState,
    limits: &NamespaceLimits,
) -> Result<(), NamespaceError> {
    state.descriptor.validate(limits)?;
    let descriptor_cid = Cid::new(
        CODEC_NAMESPACE_DESCRIPTOR,
        &canonical_bytes(&state.descriptor)?,
    );
    if state.namespace_id.0 != descriptor_cid
        || state.current_root_cid.codec != pepper_types::CODEC_MERKLE_NODE
        || state
            .history
            .get(&state.current_revision)
            .is_none_or(|record| record.root_cid != state.current_root_cid)
        || state.history.iter().any(|(revision, record)| {
            *revision != record.revision
                || record.root_cid.codec != pepper_types::CODEC_MERKLE_NODE
                || record
                    .commit_cid
                    .as_ref()
                    .is_some_and(|cid| cid.codec != CODEC_NAMESPACE_COMMIT)
        })
        || state.named_snapshots.iter().any(|(name, snapshot)| {
            name != &snapshot.name
                || snapshot.root_cid.codec != pepper_types::CODEC_MERKLE_NODE
                || snapshot
                    .commit_cid
                    .as_ref()
                    .is_some_and(|cid| cid.codec != CODEC_NAMESPACE_COMMIT)
        })
    {
        return Err(NamespaceError::InvalidPayload(
            "namespace state is inconsistent".to_string(),
        ));
    }
    Ok(())
}

fn validate_commit_record(commit: &NamespaceCommit) -> Result<(), NamespaceError> {
    if commit.commit_type != COMMIT_TYPE
        || commit.version != FORMAT_VERSION
        || commit.namespace_id.0.codec != CODEC_NAMESPACE_DESCRIPTOR
        || commit.new_root_cid.codec != pepper_types::CODEC_MERKLE_NODE
        || commit
            .parent_commit_cid
            .as_ref()
            .is_some_and(|cid| cid.codec != CODEC_NAMESPACE_COMMIT)
        || commit.new_namespace_revision <= commit.base_namespace_revision
        || commit.committed_at_unix_seconds < 0
        || commit.changed_keys.is_empty()
        || commit.writer_identity.is_empty()
        || commit.request_id.is_empty()
        || commit
            .changed_keys
            .windows(2)
            .any(|entries| entries[0].key_hex.as_bytes() >= entries[1].key_hex.as_bytes())
        || commit.changed_keys.iter().any(|entry| {
            hex::decode(&entry.key_hex).is_err()
                || (entry.generation.is_some() != entry.value_cid.is_some())
                || entry.generation == Some(0)
        })
    {
        return Err(NamespaceError::InvalidPayload(
            "namespace commit is inconsistent".to_string(),
        ));
    }
    Ok(())
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, NamespaceError> {
    serde_json::to_vec(value).map_err(|error| NamespaceError::InvalidPayload(error.to_string()))
}

fn decode_canonical<T>(payload: &[u8]) -> Result<T, NamespaceError>
where
    T: Serialize + DeserializeOwned,
{
    let value: T = serde_json::from_slice(payload)
        .map_err(|error| NamespaceError::InvalidPayload(error.to_string()))?;
    if canonical_bytes(&value)? != payload {
        return Err(NamespaceError::NonCanonical);
    }
    Ok(value)
}

pub struct NamespaceDescriptorCodecHandler;
pub struct NamespaceCommitCodecHandler;
pub struct NamespaceCheckpointCodecHandler;

impl DagCodecHandler for NamespaceDescriptorCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_NAMESPACE_DESCRIPTOR
    }

    fn links(&self, payload: &[u8], _limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        let descriptor: NamespaceDescriptor = decode_for_dag(payload, self.codec())?;
        descriptor
            .validate(&NamespaceLimits::default())
            .map_err(|error| DagError::InvalidPayload {
                codec: self.codec().canonical_display(),
                message: error.to_string(),
            })?;
        Ok(descriptor.authorization_policy_cid.into_iter().collect())
    }
}

impl DagCodecHandler for NamespaceCommitCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_NAMESPACE_COMMIT
    }

    fn links(&self, payload: &[u8], _limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        let commit: NamespaceCommit = decode_for_dag(payload, self.codec())?;
        validate_commit_record(&commit).map_err(|error| DagError::InvalidPayload {
            codec: self.codec().canonical_display(),
            message: error.to_string(),
        })?;
        // parent_commit_cid is intentionally weak so retention may expire history.
        Ok(vec![commit.new_root_cid])
    }
}

impl DagCodecHandler for NamespaceCheckpointCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_NAMESPACE_CHECKPOINT
    }

    fn links(&self, payload: &[u8], _limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        let checkpoint: NamespaceCheckpoint = decode_for_dag(payload, self.codec())?;
        if checkpoint.checkpoint_type != CHECKPOINT_TYPE || checkpoint.version != FORMAT_VERSION {
            return Err(DagError::InvalidPayload {
                codec: self.codec().canonical_display(),
                message: "unsupported checkpoint type or version".to_string(),
            });
        }
        validate_namespace_state(&checkpoint.state, &NamespaceLimits::default()).map_err(
            |error| DagError::InvalidPayload {
                codec: self.codec().canonical_display(),
                message: error.to_string(),
            },
        )?;
        let mut links = BTreeMap::<String, Cid>::new();
        links.insert(
            checkpoint.state.namespace_id.to_string(),
            checkpoint.state.namespace_id.0.clone(),
        );
        for cid in protected_roots(&checkpoint.state).keys() {
            if let Ok(cid) = cid.parse::<Cid>() {
                links.insert(cid.to_string(), cid);
            }
        }
        Ok(links.into_values().collect())
    }
}

fn decode_for_dag<T>(payload: &[u8], codec: Codec) -> Result<T, DagError>
where
    T: Serialize + DeserializeOwned,
{
    decode_canonical(payload).map_err(|error| DagError::InvalidPayload {
        codec: codec.canonical_display(),
        message: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    #[derive(Default)]
    struct MemoryStore(Mutex<BTreeMap<String, Vec<u8>>>);

    #[async_trait]
    impl MerkleReadStore for MemoryStore {
        async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
            self.0
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
            self.0.lock().unwrap().insert(cid.to_string(), payload);
            Ok(cid)
        }
    }

    #[derive(Default)]
    struct FailCommitStore {
        inner: MemoryStore,
        fail_commit: AtomicBool,
    }

    #[async_trait]
    impl MerkleReadStore for FailCommitStore {
        async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
            self.inner.get(cid).await
        }
    }

    #[async_trait]
    impl MerkleWriteStore for FailCommitStore {
        async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
            if codec == CODEC_NAMESPACE_COMMIT && self.fail_commit.load(Ordering::Relaxed) {
                return Err("injected commit failure".to_string());
            }
            self.inner.put(codec, payload).await
        }
    }

    fn descriptor() -> NamespaceDescriptor {
        NamespaceDescriptor::new(
            NamespaceKind::Kv,
            vec!["node-c".into(), "node-a".into(), "node-b".into()],
            "creator",
            "00",
            1,
        )
    }

    async fn machine() -> NamespaceStateMachine<MemoryStore> {
        let store = MemoryStore::default();
        let created = create_namespace(
            &store,
            descriptor(),
            NamespaceLimits::default(),
            MerkleLimits::default(),
        )
        .await
        .unwrap();
        NamespaceStateMachine::new(store, created.state).unwrap()
    }

    #[tokio::test]
    async fn assertions_fence_a_mutation_without_changing_the_asserted_key() {
        let mut machine = machine().await;
        machine
            .apply(put_command(
                machine.state(),
                "fence-1",
                "z-fence",
                "epoch-1",
                KeyPrecondition::Absent,
                2,
            ))
            .await
            .unwrap();
        let fence = machine.get(None, b"z-fence").await.unwrap().unwrap();
        let command = CommandEnvelope {
            request_id: "fenced-write".to_string(),
            writer_identity: "writer".to_string(),
            timestamp_unix_seconds: 3,
            signature_hex: "00".to_string(),
            command: NamespaceCommand::ApplyTransaction {
                transaction: TransactionCommand {
                    base_revision: machine.state().current_revision,
                    base_root_cid: machine.state().current_root_cid.clone(),
                    mutations: vec![
                        NamespaceMutation::Put {
                            key_hex: hex::encode("a-object"),
                            value_cid: Cid::new(CODEC_RAW, b"value"),
                            value_kind: "raw".to_string(),
                            metadata: BTreeMap::new(),
                            precondition: KeyPrecondition::Absent,
                        },
                        NamespaceMutation::Assert {
                            key_hex: hex::encode("z-fence"),
                            precondition: KeyPrecondition::Match {
                                generation: fence.generation,
                                cid: fence.cid.clone(),
                            },
                        },
                    ],
                    message: None,
                },
            },
        };
        machine.apply(command).await.unwrap();
        let unchanged = machine.get(None, b"z-fence").await.unwrap().unwrap();
        assert_eq!(unchanged, fence);

        machine
            .apply(put_command(
                machine.state(),
                "fence-2",
                "z-fence",
                "epoch-2",
                KeyPrecondition::Match {
                    generation: fence.generation,
                    cid: fence.cid.clone(),
                },
                4,
            ))
            .await
            .unwrap();
        let mut stale = put_command(
            machine.state(),
            "stale-fenced-write",
            "a-second",
            "value",
            KeyPrecondition::Absent,
            5,
        );
        let NamespaceCommand::ApplyTransaction { transaction } = &mut stale.command else {
            unreachable!();
        };
        transaction.mutations.push(NamespaceMutation::Assert {
            key_hex: hex::encode("z-fence"),
            precondition: KeyPrecondition::Match {
                generation: fence.generation,
                cid: fence.cid,
            },
        });
        assert!(matches!(
            machine.apply(stale).await,
            Err(NamespaceError::GenerationConflict(_))
        ));
        assert!(machine.get(None, b"a-second").await.unwrap().is_none());
    }

    fn put_command(
        state: &NamespaceState,
        request_id: &str,
        key: &str,
        value: &str,
        precondition: KeyPrecondition,
        timestamp: i64,
    ) -> CommandEnvelope {
        CommandEnvelope {
            request_id: request_id.to_string(),
            writer_identity: "writer".to_string(),
            timestamp_unix_seconds: timestamp,
            signature_hex: "00".to_string(),
            command: NamespaceCommand::ApplyTransaction {
                transaction: TransactionCommand {
                    base_revision: state.current_revision,
                    base_root_cid: state.current_root_cid.clone(),
                    mutations: vec![NamespaceMutation::Put {
                        key_hex: hex::encode(key),
                        value_cid: Cid::new(CODEC_RAW, value.as_bytes()),
                        value_kind: "raw".to_string(),
                        metadata: BTreeMap::new(),
                        precondition,
                    }],
                    message: Some(format!("put {key}")),
                },
            },
        }
    }

    #[tokio::test]
    async fn creation_is_deterministic_and_checkpoint_roundtrips() {
        let left = MemoryStore::default();
        let right = MemoryStore::default();
        let a = create_namespace(
            &left,
            descriptor(),
            NamespaceLimits::default(),
            MerkleLimits::default(),
        )
        .await
        .unwrap();
        let b = create_namespace(
            &right,
            descriptor(),
            NamespaceLimits::default(),
            MerkleLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(a.namespace_id, b.namespace_id);
        assert_eq!(a.root_cid, b.root_cid);
        assert_eq!(a.checkpoint_cid, b.checkpoint_cid);
        assert_eq!(
            a.descriptor_cid.to_string(),
            "cid://pepper-v1:0x8:b3:595ba8951a3b4c593da6f8b9b5627cfc734432faa266bfb42e2ed8e246cb56d0"
        );
        assert_eq!(
            a.checkpoint_cid.to_string(),
            "cid://pepper-v1:0x9:b3:38fde77711d2c29049b12558fe0d1ae8cdd308b432c43f9a094d123bc7555eb6"
        );
        assert_eq!(
            load_checkpoint(&left, &a.checkpoint_cid, NamespaceLimits::default())
                .await
                .unwrap(),
            a.state
        );
    }

    #[tokio::test]
    async fn transaction_builder_reads_its_writes_and_emits_sorted_preconditions() {
        let mut machine = machine().await;
        let mut transaction = machine.begin_transaction();
        transaction
            .put(
                machine.store(),
                b"beta".to_vec(),
                Cid::new(CODEC_RAW, b"beta"),
                "raw".to_string(),
                BTreeMap::new(),
                MerkleLimits::default(),
            )
            .await
            .unwrap();
        transaction
            .put(
                machine.store(),
                b"alpha".to_vec(),
                Cid::new(CODEC_RAW, b"alpha"),
                "raw".to_string(),
                BTreeMap::new(),
                MerkleLimits::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            transaction
                .get(machine.store(), b"alpha", MerkleLimits::default())
                .await
                .unwrap()
                .unwrap()
                .generation,
            1
        );
        transaction
            .delete(machine.store(), b"beta".to_vec(), MerkleLimits::default())
            .await
            .unwrap();
        assert!(
            transaction
                .get(machine.store(), b"beta", MerkleLimits::default())
                .await
                .unwrap()
                .is_none()
        );
        let command = transaction.into_command(Some("builder".to_string()));
        assert_eq!(command.mutations.len(), 1);
        let envelope = CommandEnvelope {
            request_id: "builder".to_string(),
            writer_identity: "writer".to_string(),
            timestamp_unix_seconds: 2,
            signature_hex: "00".to_string(),
            command: NamespaceCommand::ApplyTransaction {
                transaction: command,
            },
        };
        machine.apply(envelope).await.unwrap();
        assert!(machine.get(None, b"alpha").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn replicas_replay_identical_commands_deterministically() {
        let mut left = machine().await;
        let mut right = machine().await;
        let command = put_command(
            left.state(),
            "request-1",
            "alpha",
            "one",
            KeyPrecondition::Absent,
            2,
        );
        let left_result = left.apply(command.clone()).await.unwrap();
        let right_result = right.apply(command).await.unwrap();
        assert_eq!(left_result, right_result);
        let CommandResponse::Commit(commit) = &left_result.response else {
            panic!("expected commit response");
        };
        assert_eq!(
            commit.commit_cid.to_string(),
            "cid://pepper-v1:0xa:b3:59eaed72c9df9cd0ae4a6585bf730cff7d08b63662deffcd7fbfdaece24f7e8b"
        );
        assert_eq!(left.state(), right.state());
        assert_eq!(
            left.get(None, b"alpha").await.unwrap().unwrap().generation,
            1
        );
    }

    #[tokio::test]
    async fn consensus_order_clamps_out_of_order_client_timestamps() {
        let mut machine = machine().await;
        let first = put_command(
            machine.state(),
            "timestamp-newer",
            "alpha",
            "one",
            KeyPrecondition::Absent,
            20,
        );
        machine.apply(first).await.unwrap();
        let second = put_command(
            machine.state(),
            "timestamp-older",
            "beta",
            "two",
            KeyPrecondition::Absent,
            10,
        );
        machine.apply(second).await.unwrap();
        assert_eq!(machine.state().current_revision, 2);
        assert_eq!(machine.state().history[&2].committed_at_unix_seconds, 20);
        assert!(machine.get(None, b"beta").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn concurrent_same_key_conflicts_but_disjoint_stale_writes_commit() {
        let mut machine = machine().await;
        let base = machine.state().clone();
        let first = put_command(&base, "first", "alpha", "one", KeyPrecondition::Absent, 2);
        let stale_same = put_command(&base, "same", "alpha", "two", KeyPrecondition::Absent, 3);
        let stale_disjoint =
            put_command(&base, "other", "beta", "three", KeyPrecondition::Absent, 4);
        machine.apply(first).await.unwrap();
        assert!(matches!(
            machine.apply(stale_same).await,
            Err(NamespaceError::GenerationConflict(_))
        ));
        machine.apply(stale_disjoint).await.unwrap();
        assert_eq!(machine.state().current_revision, 2);
        assert!(machine.get(None, b"alpha").await.unwrap().is_some());
        assert!(machine.get(None, b"beta").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn idempotency_replays_once_and_rejects_reuse() {
        let mut machine = machine().await;
        let command = put_command(
            machine.state(),
            "request",
            "key",
            "value",
            KeyPrecondition::Absent,
            2,
        );
        let projected_command = command.clone();
        let first = machine.apply(command.clone()).await.unwrap();
        let replay = machine.apply(command).await.unwrap();
        assert!(!first.replayed);
        assert!(replay.replayed);
        assert_eq!(first.response, replay.response);
        assert_eq!(machine.state().current_revision, 1);

        let head = machine.state().clone().into_head_projection();
        assert!(head.history.is_empty());
        assert!(head.named_snapshots.is_empty());
        assert_eq!(head.current_root_cid, machine.state().current_root_cid);
        assert!(
            head.idempotent_response_for(&projected_command)
                .unwrap()
                .is_none()
        );

        let conflicting = put_command(
            machine.state(),
            "request",
            "other",
            "value",
            KeyPrecondition::Absent,
            3,
        );
        assert!(matches!(
            machine.apply(conflicting).await,
            Err(NamespaceError::IdempotencyConflict)
        ));
    }

    #[tokio::test]
    async fn atomic_multi_key_commit_and_snapshot_reads() {
        let mut machine = machine().await;
        let state = machine.state().clone();
        let command = CommandEnvelope {
            request_id: "multi".into(),
            writer_identity: "writer".into(),
            timestamp_unix_seconds: 2,
            signature_hex: "00".into(),
            command: NamespaceCommand::ApplyTransaction {
                transaction: TransactionCommand {
                    base_revision: 0,
                    base_root_cid: state.current_root_cid,
                    mutations: vec![
                        NamespaceMutation::Put {
                            key_hex: hex::encode("a"),
                            value_cid: Cid::new(CODEC_RAW, b"a"),
                            value_kind: "raw".into(),
                            metadata: BTreeMap::new(),
                            precondition: KeyPrecondition::Absent,
                        },
                        NamespaceMutation::Put {
                            key_hex: hex::encode("b"),
                            value_cid: Cid::new(CODEC_RAW, b"b"),
                            value_kind: "raw".into(),
                            metadata: BTreeMap::new(),
                            precondition: KeyPrecondition::Absent,
                        },
                    ],
                    message: None,
                },
            },
        };
        machine.apply(command).await.unwrap();
        assert!(machine.get(Some(0), b"a").await.unwrap().is_none());
        assert!(machine.get(Some(1), b"a").await.unwrap().is_some());
        assert!(machine.get(Some(1), b"b").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn named_snapshots_and_rollback_create_new_revision_with_new_generations() {
        let mut machine = machine().await;
        machine
            .apply(put_command(
                machine.state(),
                "one",
                "key",
                "one",
                KeyPrecondition::Absent,
                2,
            ))
            .await
            .unwrap();
        let first_value = machine.get(None, b"key").await.unwrap().unwrap();
        let snapshot = CommandEnvelope {
            request_id: "snapshot".into(),
            writer_identity: "writer".into(),
            timestamp_unix_seconds: 3,
            signature_hex: "00".into(),
            command: NamespaceCommand::CreateSnapshot {
                name: "v1".into(),
                revision: Some(1),
            },
        };
        machine.apply(snapshot).await.unwrap();
        assert!(machine.state().named_snapshots.contains_key("v1"));
        machine
            .apply(put_command(
                machine.state(),
                "two",
                "key",
                "two",
                KeyPrecondition::Match {
                    generation: first_value.generation,
                    cid: first_value.cid,
                },
                4,
            ))
            .await
            .unwrap();
        machine
            .apply(CommandEnvelope {
                request_id: "rollback".into(),
                writer_identity: "writer".into(),
                timestamp_unix_seconds: 5,
                signature_hex: "00".into(),
                command: NamespaceCommand::Rollback {
                    revision: 1,
                    message: None,
                },
            })
            .await
            .unwrap();
        let restored = machine.get(None, b"key").await.unwrap().unwrap();
        assert_eq!(restored.cid, Cid::new(CODEC_RAW, b"one"));
        assert_eq!(restored.generation, 3);
        assert_eq!(machine.state().current_revision, 3);
    }

    #[tokio::test]
    async fn failed_commit_never_mutates_published_state() {
        let store = FailCommitStore::default();
        let created = create_namespace(
            &store,
            descriptor(),
            NamespaceLimits::default(),
            MerkleLimits::default(),
        )
        .await
        .unwrap();
        store.fail_commit.store(true, Ordering::Relaxed);
        let mut machine = NamespaceStateMachine::new(store, created.state.clone()).unwrap();
        let command = put_command(
            machine.state(),
            "failure",
            "key",
            "value",
            KeyPrecondition::Absent,
            2,
        );
        assert!(matches!(
            machine.apply(command).await,
            Err(NamespaceError::Write(_))
        ));
        assert_eq!(machine.state(), &created.state);
        assert!(machine.get(None, b"key").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn age_retention_extends_keep_last_then_releases_expired_history() {
        let store = MemoryStore::default();
        let mut descriptor = descriptor();
        descriptor.retention.keep_last = 1;
        descriptor.retention.max_age_seconds = Some(5);
        let created = create_namespace(
            &store,
            descriptor,
            NamespaceLimits::default(),
            MerkleLimits::default(),
        )
        .await
        .unwrap();
        let mut machine = NamespaceStateMachine::new(store, created.state).unwrap();
        machine
            .apply(put_command(
                machine.state(),
                "age-one",
                "one",
                "one",
                KeyPrecondition::Absent,
                10,
            ))
            .await
            .unwrap();
        let first = machine.state().history.get(&1).unwrap().clone();
        let recent = machine
            .apply(put_command(
                machine.state(),
                "age-two",
                "two",
                "two",
                KeyPrecondition::Absent,
                12,
            ))
            .await
            .unwrap();
        assert!(
            !recent.pin_intents.iter().any(|intent| {
                intent.action == PinAction::Release && intent.cid == first.root_cid
            })
        );
        let expired = machine
            .apply(put_command(
                machine.state(),
                "age-three",
                "three",
                "three",
                KeyPrecondition::Absent,
                30,
            ))
            .await
            .unwrap();
        assert!(
            expired.pin_intents.iter().any(|intent| {
                intent.action == PinAction::Release && intent.cid == first.root_cid
            })
        );
    }

    #[tokio::test]
    async fn named_snapshot_prevents_retention_release_until_deleted() {
        let store = MemoryStore::default();
        let mut descriptor = descriptor();
        descriptor.retention.keep_last = 1;
        let created = create_namespace(
            &store,
            descriptor,
            NamespaceLimits::default(),
            MerkleLimits::default(),
        )
        .await
        .unwrap();
        let mut machine = NamespaceStateMachine::new(store, created.state).unwrap();
        machine
            .apply(put_command(
                machine.state(),
                "one",
                "key",
                "one",
                KeyPrecondition::Absent,
                2,
            ))
            .await
            .unwrap();
        let revision_one = machine.state().history.get(&1).unwrap().clone();
        machine
            .apply(CommandEnvelope {
                request_id: "snapshot".into(),
                writer_identity: "writer".into(),
                timestamp_unix_seconds: 3,
                signature_hex: "00".into(),
                command: NamespaceCommand::CreateSnapshot {
                    name: "hold".into(),
                    revision: Some(1),
                },
            })
            .await
            .unwrap();
        let current = machine.get(None, b"key").await.unwrap().unwrap();
        let commit = machine
            .apply(put_command(
                machine.state(),
                "two",
                "key",
                "two",
                KeyPrecondition::Match {
                    generation: current.generation,
                    cid: current.cid,
                },
                4,
            ))
            .await
            .unwrap();
        assert!(!commit.pin_intents.iter().any(|intent| {
            intent.action == PinAction::Release && intent.cid == revision_one.root_cid
        }));
        let deleted = machine
            .apply(CommandEnvelope {
                request_id: "delete-snapshot".into(),
                writer_identity: "writer".into(),
                timestamp_unix_seconds: 5,
                signature_hex: "00".into(),
                command: NamespaceCommand::DeleteSnapshot {
                    name: "hold".into(),
                },
            })
            .await
            .unwrap();
        assert!(deleted.pin_intents.iter().any(|intent| {
            intent.action == PinAction::Release && intent.cid == revision_one.root_cid
        }));
    }

    struct RejectAll;
    impl CommandAuthorizer for RejectAll {
        fn verify(
            &self,
            _namespace_id: &NamespaceId,
            _writer_identity: &str,
            _signing_payload: &[u8],
            _signature_hex: &str,
        ) -> Result<(), String> {
            Err("rejected".to_string())
        }
    }

    #[tokio::test]
    async fn rejects_non_hex_and_empty_signatures_before_authorization() {
        let mut invalid_descriptor = descriptor();
        invalid_descriptor.creator_signature_hex = "not-hex".to_string();
        assert!(matches!(
            create_namespace(
                &MemoryStore::default(),
                invalid_descriptor,
                NamespaceLimits::default(),
                MerkleLimits::default()
            )
            .await,
            Err(NamespaceError::InvalidDescriptor(_))
        ));

        let mut machine = machine().await;
        let mut command = put_command(
            machine.state(),
            "request",
            "key",
            "value",
            KeyPrecondition::Absent,
            2,
        );
        command.signature_hex.clear();
        assert!(matches!(
            machine.apply(command).await,
            Err(NamespaceError::InvalidCommand(_))
        ));
        assert_eq!(machine.state().current_revision, 0);
    }

    #[tokio::test]
    async fn authorizer_rejects_without_mutating_state() {
        let base = machine().await;
        let (store, state) = base.into_parts();
        let before = state.clone();
        let mut machine = NamespaceStateMachine::with_authorizer(
            store,
            state,
            RejectAll,
            NamespaceLimits::default(),
            MerkleLimits::default(),
        )
        .unwrap();
        let command = put_command(
            machine.state(),
            "request",
            "key",
            "value",
            KeyPrecondition::Absent,
            2,
        );
        assert!(matches!(
            machine.apply(command).await,
            Err(NamespaceError::Unauthorized(_))
        ));
        assert_eq!(machine.state(), &before);
    }

    #[tokio::test]
    async fn real_block_store_checkpoint_protects_namespace_and_value_dag() {
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
                MerkleReadStore::get(self, cid).await
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let metadata = Arc::new(
            MetadataStore::open_or_create(directory.path().join("metadata.redb")).unwrap(),
        );
        let blocks = Arc::new(
            BlockStore::open(
                metadata,
                &[StorageLocationConfig {
                    path: directory.path().join("storage"),
                    max_capacity_bytes: 32 * 1024 * 1024,
                }],
            )
            .unwrap(),
        );
        let value_cid = blocks.put_raw(b"namespace value").unwrap().cid;
        let unprotected = blocks.put_raw(b"collect this").unwrap().cid;
        let adapter = Adapter(blocks);
        let created = create_namespace(
            &adapter,
            descriptor(),
            NamespaceLimits::default(),
            MerkleLimits::default(),
        )
        .await
        .unwrap();
        let mut machine = NamespaceStateMachine::new(adapter, created.state).unwrap();
        let mut command = put_command(
            machine.state(),
            "commit",
            "key",
            "placeholder",
            KeyPrecondition::Absent,
            2,
        );
        let NamespaceCommand::ApplyTransaction { transaction } = &mut command.command else {
            unreachable!();
        };
        let NamespaceMutation::Put {
            value_cid: command_value,
            ..
        } = &mut transaction.mutations[0]
        else {
            unreachable!();
        };
        *command_value = value_cid.clone();
        machine.apply(command).await.unwrap();
        let checkpoint = machine.checkpoint(3).await.unwrap();

        let mut registry = pepper_dag::builtin_registry();
        registry
            .register(pepper_merkle::MerkleNodeCodecHandler)
            .unwrap();
        registry.register(NamespaceDescriptorCodecHandler).unwrap();
        registry.register(NamespaceCommitCodecHandler).unwrap();
        registry.register(NamespaceCheckpointCodecHandler).unwrap();
        let protected = pepper_dag::traverse(
            &registry,
            &machine.store,
            checkpoint.clone(),
            TraversalLimits::default(),
        )
        .await
        .unwrap()
        .into_set();
        machine.store.0.garbage_collect(&protected).unwrap();
        assert!(machine.store.0.has(&checkpoint).unwrap());
        assert!(machine.store.0.has(&value_cid).unwrap());
        assert!(!machine.store.0.has(&unprotected).unwrap());
    }

    #[tokio::test]
    async fn codec_handlers_expose_strong_links_but_not_weak_parent_history() {
        let store = MemoryStore::default();
        let created = create_namespace(
            &store,
            descriptor(),
            NamespaceLimits::default(),
            MerkleLimits::default(),
        )
        .await
        .unwrap();
        let checkpoint = store.get(&created.checkpoint_cid).await.unwrap();
        let links = NamespaceCheckpointCodecHandler
            .links(&checkpoint, &TraversalLimits::default())
            .unwrap();
        assert!(links.contains(&created.descriptor_cid));
        assert!(links.contains(&created.root_cid));

        let mut machine = NamespaceStateMachine::new(store, created.state).unwrap();
        let result = machine
            .apply(put_command(
                machine.state(),
                "commit",
                "key",
                "value",
                KeyPrecondition::Absent,
                2,
            ))
            .await
            .unwrap();
        let CommandResponse::Commit(response) = result.response else {
            panic!("expected commit");
        };
        let payload = machine.store.get(&response.commit_cid).await.unwrap();
        let links = NamespaceCommitCodecHandler
            .links(&payload, &TraversalLimits::default())
            .unwrap();
        assert_eq!(links, vec![response.root_cid]);
    }
}
