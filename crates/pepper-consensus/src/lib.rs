// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::result_large_err)] // OpenRaft's required StorageError is intentionally rich.

//! Durable, multi-group Raft runtime for Pepper namespaces.
//!
//! Phase 4 provides redb-backed OpenRaft storage and an in-process transport
//! used by deterministic integration tests. QUIC transport and discovery are
//! deliberately implemented in Phase 5.

use async_trait::async_trait;
use openraft::{
    BasicNode, Config as RaftConfig, Entry, EntryPayload, LogId, LogState, Raft, RaftLogReader,
    RaftNetwork, RaftNetworkFactory, RaftSnapshotBuilder, Snapshot, SnapshotMeta, SnapshotPolicy,
    StorageError, StorageIOError, StoredMembership, Vote,
    error::{InstallSnapshotError, RPCError, RaftError, RemoteError, Unreachable},
    network::RPCOption,
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, ClientWriteResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
    storage::{LogFlushed, RaftLogStorage, RaftStateMachine},
};
use pepper_dag::BlockResolver;
use pepper_merkle::{MerkleReadStore, MerkleWriteStore};
use pepper_metadata::MetadataStore;
use pepper_namespace::{
    ApplyResult, CommandEnvelope, NamespaceCommand, NamespaceError, NamespaceId, NamespaceMutation,
    NamespaceState, NamespaceStateMachine, PinAction, PinIntent, load_checkpoint, write_checkpoint,
};
use pepper_network::{NetworkError, NetworkHandle, NetworkNamespaceService, proto};
use pepper_placement::{
    ConsensusPlacementNode, select_namespace_replacement, select_namespace_replicas,
};
use pepper_types::{Cid, Codec};
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::Debug,
    io::Cursor,
    net::SocketAddr,
    ops::RangeBounds,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};

const PROPOSAL_BATCH_MAX_COMMANDS: usize = 32;
const PROPOSAL_BATCH_MAX_DELAY: Duration = Duration::from_micros(250);
const PROPOSAL_BATCH_CHANNEL_CAPACITY: usize = 256;
const INITIAL_MEMBERSHIP_EPOCH: u64 = 1;

const NAMESPACE_GROUPS: TableDefinition<&str, &[u8]> = TableDefinition::new("namespace_groups");
const NAMESPACE_RAFT_VOTE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("namespace_raft_vote");
const NAMESPACE_RAFT_LOG: TableDefinition<&str, &[u8]> = TableDefinition::new("namespace_raft_log");
const NAMESPACE_RAFT_MEMBERSHIP: TableDefinition<&str, &[u8]> =
    TableDefinition::new("namespace_raft_membership");
const NAMESPACE_STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("namespace_state");
const NAMESPACE_CHECKPOINTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("namespace_checkpoints");

static LOG_APPEND_OBSERVATIONS: AtomicU64 = AtomicU64::new(0);
static LOG_APPEND_ENTRIES: AtomicU64 = AtomicU64::new(0);
static LOG_APPEND_QUEUE_MICROS: AtomicU64 = AtomicU64::new(0);
static LOG_APPEND_EXECUTION_MICROS: AtomicU64 = AtomicU64::new(0);
static STATE_APPLY_OBSERVATIONS: AtomicU64 = AtomicU64::new(0);
static STATE_APPLY_ENTRIES: AtomicU64 = AtomicU64::new(0);
static STATE_APPLY_QUEUE_MICROS: AtomicU64 = AtomicU64::new(0);
static STATE_APPLY_EXECUTION_MICROS: AtomicU64 = AtomicU64::new(0);
static PROPOSAL_REQUESTS: AtomicU64 = AtomicU64::new(0);
static PROPOSAL_BATCHES: AtomicU64 = AtomicU64::new(0);
static PROPOSAL_BATCH_SIZE_MAX: AtomicU64 = AtomicU64::new(0);
static PROPOSAL_QUEUE_MICROS: AtomicU64 = AtomicU64::new(0);
static PROPOSAL_EXECUTION_MICROS: AtomicU64 = AtomicU64::new(0);
static LINEARIZABLE_READ_LEASE_HITS: AtomicU64 = AtomicU64::new(0);
static LINEARIZABLE_READ_PROOFS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConsensusIoStats {
    pub log_append_observations: u64,
    pub log_append_entries: u64,
    pub log_append_queue_micros: u64,
    pub log_append_execution_micros: u64,
    pub state_apply_observations: u64,
    pub state_apply_entries: u64,
    pub state_apply_queue_micros: u64,
    pub state_apply_execution_micros: u64,
    pub proposal_requests: u64,
    pub proposal_batches: u64,
    pub proposal_batch_size_max: u64,
    pub proposal_queue_micros: u64,
    pub proposal_execution_micros: u64,
    pub linearizable_read_lease_hits: u64,
    pub linearizable_read_proofs: u64,
}

pub fn process_io_stats() -> ConsensusIoStats {
    ConsensusIoStats {
        log_append_observations: LOG_APPEND_OBSERVATIONS.load(Ordering::Relaxed),
        log_append_entries: LOG_APPEND_ENTRIES.load(Ordering::Relaxed),
        log_append_queue_micros: LOG_APPEND_QUEUE_MICROS.load(Ordering::Relaxed),
        log_append_execution_micros: LOG_APPEND_EXECUTION_MICROS.load(Ordering::Relaxed),
        state_apply_observations: STATE_APPLY_OBSERVATIONS.load(Ordering::Relaxed),
        state_apply_entries: STATE_APPLY_ENTRIES.load(Ordering::Relaxed),
        state_apply_queue_micros: STATE_APPLY_QUEUE_MICROS.load(Ordering::Relaxed),
        state_apply_execution_micros: STATE_APPLY_EXECUTION_MICROS.load(Ordering::Relaxed),
        proposal_requests: PROPOSAL_REQUESTS.load(Ordering::Relaxed),
        proposal_batches: PROPOSAL_BATCHES.load(Ordering::Relaxed),
        proposal_batch_size_max: PROPOSAL_BATCH_SIZE_MAX.load(Ordering::Relaxed),
        proposal_queue_micros: PROPOSAL_QUEUE_MICROS.load(Ordering::Relaxed),
        proposal_execution_micros: PROPOSAL_EXECUTION_MICROS.load(Ordering::Relaxed),
        linearizable_read_lease_hits: LINEARIZABLE_READ_LEASE_HITS.load(Ordering::Relaxed),
        linearizable_read_proofs: LINEARIZABLE_READ_PROOFS.load(Ordering::Relaxed),
    }
}

struct ProcessTimer {
    started: Instant,
    total_micros: &'static AtomicU64,
}

impl ProcessTimer {
    fn start(total_micros: &'static AtomicU64) -> Self {
        Self {
            started: Instant::now(),
            total_micros,
        }
    }
}

impl Drop for ProcessTimer {
    fn drop(&mut self) {
        self.total_micros.fetch_add(
            self.started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }
}

pub type NodeId = u64;

pub fn raft_node_id(identity: &str) -> NodeId {
    let digest = blake3::hash(identity.as_bytes());
    u64::from_be_bytes(digest.as_bytes()[..8].try_into().expect("eight-byte slice"))
}

pub fn raft_members(identities: &[String]) -> Result<BTreeMap<NodeId, BasicNode>, ConsensusError> {
    let mut members = BTreeMap::new();
    for identity in identities {
        let id = raft_node_id(identity);
        if members.insert(id, BasicNode::new(identity)).is_some() {
            return Err(ConsensusError::InvalidConfig(
                "replica identities collide in the Raft node-id space".to_string(),
            ));
        }
    }
    Ok(members)
}

openraft::declare_raft_types!(
    pub TypeConfig:
        D = ConsensusCommandBatch,
        R = ConsensusBatchResponse,
        NodeId = NodeId,
        Node = BasicNode,
        Entry = Entry<TypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusCommandBatch {
    pub commands: Vec<CommandEnvelope>,
}

pub fn namespace_log_contains(
    metadata: &MetadataStore,
    namespace_id: &NamespaceId,
    log_index: u64,
) -> Result<bool, ConsensusError> {
    let read = metadata
        .database()
        .begin_read()
        .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
    let table = read
        .open_table(NAMESPACE_RAFT_LOG)
        .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
    table
        .get(format!("{}|log|{log_index:020}", namespace_id).as_str())
        .map(|value| value.is_some())
        .map_err(|error| ConsensusError::Metadata(error.to_string()))
}

pub type NamespaceRaft = Raft<TypeConfig>;
pub type NamespaceClientWriteResponse = ClientWriteResponse<TypeConfig>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicationIntentRecord {
    pub intent_id: String,
    pub namespace_id: NamespaceId,
    pub log_index: u64,
    pub request_id: String,
    pub cid: Cid,
    pub action: PinAction,
    pub reason: String,
    pub status: String,
    pub created_at_unix_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusResponse {
    pub result: Option<ApplyResult>,
    pub error_code: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusBatchResponse {
    pub responses: Vec<ConsensusResponse>,
}

impl ConsensusResponse {
    fn application_error(error: NamespaceError) -> Self {
        Self {
            result: None,
            error_code: Some(namespace_error_code(&error).to_string()),
            error: Some(error.to_string()),
        }
    }
}

impl ConsensusBatchResponse {
    fn blank() -> Self {
        Self {
            responses: Vec::new(),
        }
    }
}

fn namespace_error_code(error: &NamespaceError) -> &'static str {
    match error {
        NamespaceError::GenerationConflict(_) => "generation_conflict",
        NamespaceError::IdempotencyConflict => "idempotency_conflict",
        NamespaceError::StaleSnapshot => "stale_snapshot",
        NamespaceError::Unauthorized(_) => "unauthorized",
        NamespaceError::UnknownRevision(_) => "unknown_revision",
        NamespaceError::SnapshotExists(_) => "snapshot_exists",
        NamespaceError::SnapshotNotFound(_) => "snapshot_not_found",
        NamespaceError::EmptyTransaction | NamespaceError::NoChanges => "no_changes",
        _ => "invalid_namespace_command",
    }
}

#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("invalid consensus configuration: {0}")]
    InvalidConfig(String),
    #[error("namespace group {0} is already running")]
    GroupAlreadyRunning(String),
    #[error("namespace group {0} is not running")]
    GroupNotRunning(String),
    #[error("local node is not an assigned replica for namespace {0}")]
    NotAssigned(String),
    #[error("namespace group limit {0} reached")]
    GroupLimit(usize),
    #[error("namespace write-rate limit exceeded")]
    WriteRateLimited,
    #[error("namespace consensus command exceeds {0} bytes")]
    CommandTooLarge(u64),
    #[error("metadata operation failed: {0}")]
    Metadata(String),
    #[error("serialization failed: {0}")]
    Serde(String),
    #[error("Raft startup failed: {0}")]
    RaftStart(String),
    #[error("Raft operation failed: {0}")]
    Raft(String),
    #[error("replica replacement is invalid: {0}")]
    InvalidReplacement(String),
    #[error("unsafe recovery confirmation is required")]
    RecoveryConfirmationRequired,
    #[error("namespace replica placement failed: {0}")]
    Placement(String),
}

#[async_trait]
pub trait ConsensusDataBackend: Send + Sync + 'static {
    async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String>;
    async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String>;

    async fn put_batch(&self, blocks: Vec<(Codec, Vec<u8>)>) -> Result<Vec<Cid>, String> {
        let mut cids = Vec::with_capacity(blocks.len());
        for (codec, payload) in blocks {
            cids.push(self.put(codec, payload).await?);
        }
        Ok(cids)
    }
}

#[derive(Clone)]
pub struct ConsensusDataStore(Arc<dyn ConsensusDataBackend>);

impl Debug for ConsensusDataStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ConsensusDataStore").finish()
    }
}

impl ConsensusDataStore {
    pub fn new<B>(backend: B) -> Self
    where
        B: ConsensusDataBackend,
    {
        Self(Arc::new(backend))
    }

    pub fn from_block_store(block_store: Arc<pepper_storage::BlockStore>) -> Self {
        Self::new(BlockStoreDataBackend(block_store))
    }

    pub fn from_networked_block_store(
        block_store: Arc<pepper_storage::BlockStore>,
        network: NetworkHandle,
    ) -> Self {
        Self::new(NetworkBlockStoreDataBackend {
            block_store,
            network,
        })
    }

    async fn put_batch(&self, blocks: Vec<(Codec, Vec<u8>)>) -> Result<Vec<Cid>, String> {
        self.0.put_batch(blocks).await
    }
}

type BufferedBlocks = BTreeMap<String, (Codec, Vec<u8>)>;

#[derive(Clone)]
struct BufferedConsensusDataStore {
    base: ConsensusDataStore,
    blocks: Arc<Mutex<BufferedBlocks>>,
}

impl BufferedConsensusDataStore {
    fn new(base: ConsensusDataStore) -> Self {
        Self {
            base,
            blocks: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    async fn flush(&self) -> Result<(), String> {
        let blocks = {
            let mut pending = self.blocks.lock().await;
            std::mem::take(&mut *pending)
                .into_values()
                .collect::<Vec<_>>()
        };
        if blocks.is_empty() {
            return Ok(());
        }
        let expected = blocks
            .iter()
            .map(|(codec, payload)| Cid::new(*codec, payload))
            .collect::<Vec<_>>();
        let actual = self.base.put_batch(blocks).await?;
        if actual != expected {
            return Err("batch store returned a CID different from the buffered block".to_string());
        }
        Ok(())
    }
}

#[async_trait]
impl MerkleReadStore for BufferedConsensusDataStore {
    async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
        if let Some((_, payload)) = self.blocks.lock().await.get(&cid.to_string()) {
            return Ok(payload.clone());
        }
        MerkleReadStore::get(&self.base, cid).await
    }
}

#[async_trait]
impl MerkleWriteStore for BufferedConsensusDataStore {
    async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
        let cid = Cid::new(codec, &payload);
        self.blocks
            .lock()
            .await
            .insert(cid.to_string(), (codec, payload));
        Ok(cid)
    }
}

#[async_trait]
impl BlockResolver for ConsensusDataStore {
    async fn resolve(&self, cid: &Cid) -> Result<Vec<u8>, String> {
        self.0.get(cid).await
    }
}

#[async_trait]
impl MerkleReadStore for ConsensusDataStore {
    async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
        self.0.get(cid).await
    }
}

#[async_trait]
impl MerkleWriteStore for ConsensusDataStore {
    async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
        self.0.put(codec, payload).await
    }
}

#[derive(Clone)]
pub struct NetworkBlockStoreDataBackend {
    pub block_store: Arc<pepper_storage::BlockStore>,
    pub network: NetworkHandle,
}

#[async_trait]
impl ConsensusDataBackend for NetworkBlockStoreDataBackend {
    async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
        if let Ok(block) = self.block_store.get(cid) {
            return Ok(block.payload);
        }
        let payload = self
            .network
            .get_block_from_any_peer(cid)
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "checkpoint block is unavailable from Pepper providers".to_string())?;
        if !cid.verify(&payload) {
            return Err("checkpoint block failed CID verification".to_string());
        }
        self.block_store
            .put(cid.codec, &payload)
            .map_err(|error| error.to_string())?;
        Ok(payload)
    }

    async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
        self.block_store
            .put(codec, &payload)
            .map(|response| response.cid)
            .map_err(|error| error.to_string())
    }

    async fn put_batch(&self, blocks: Vec<(Codec, Vec<u8>)>) -> Result<Vec<Cid>, String> {
        self.block_store
            .put_batch(&blocks)
            .map(|responses| responses.into_iter().map(|response| response.cid).collect())
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone)]
pub struct BlockStoreDataBackend(pub Arc<pepper_storage::BlockStore>);

#[async_trait]
impl ConsensusDataBackend for BlockStoreDataBackend {
    async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
        self.0
            .get(cid)
            .map(|block| block.payload)
            .map_err(|error| error.to_string())
    }

    async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
        self.0
            .put(codec, &payload)
            .map(|response| response.cid)
            .map_err(|error| error.to_string())
    }

    async fn put_batch(&self, blocks: Vec<(Codec, Vec<u8>)>) -> Result<Vec<Cid>, String> {
        self.0
            .put_batch(&blocks)
            .map(|responses| responses.into_iter().map(|response| response.cid).collect())
            .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Default)]
pub struct MemoryDataBackend(Mutex<BTreeMap<String, Vec<u8>>>);

#[async_trait]
impl ConsensusDataBackend for MemoryDataBackend {
    async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
        self.0
            .lock()
            .await
            .get(&cid.to_string())
            .cloned()
            .ok_or_else(|| "block not found".to_string())
    }

    async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
        let cid = Cid::new(codec, &payload);
        self.0.lock().await.insert(cid.to_string(), payload);
        Ok(cid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupMetadata {
    pub namespace_id: NamespaceId,
    pub membership_epoch: u64,
    pub local_node_identity: String,
    pub local_raft_node_id: NodeId,
    pub members: Vec<String>,
    pub learners: Vec<String>,
    pub status: String,
    pub created_at_unix_seconds: i64,
}

#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    pub max_namespace_groups: usize,
    pub max_consensus_log_bytes: u64,
    pub max_namespace_write_rate: u64,
    pub max_command_bytes: u64,
    pub heartbeat_interval_ms: u64,
    pub election_timeout_min_ms: u64,
    pub election_timeout_max_ms: u64,
    pub snapshot_after_logs: u64,
    pub max_logs_after_snapshot: u64,
    pub checkpoint_log_bytes: u64,
    pub checkpoint_restore_target_ms: u64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            max_namespace_groups: 128,
            max_consensus_log_bytes: 256 * 1024 * 1024,
            max_namespace_write_rate: 1_000,
            max_command_bytes: 1024 * 1024,
            heartbeat_interval_ms: 100,
            election_timeout_min_ms: 1_000,
            election_timeout_max_ms: 2_000,
            snapshot_after_logs: 1_000,
            max_logs_after_snapshot: 128,
            checkpoint_log_bytes: 64 * 1024 * 1024,
            checkpoint_restore_target_ms: 2_000,
        }
    }
}

impl ConsensusConfig {
    pub fn validate(&self) -> Result<(), ConsensusError> {
        if self.max_namespace_groups == 0
            || self.max_consensus_log_bytes == 0
            || self.max_namespace_write_rate == 0
            || self.max_command_bytes == 0
            || self.max_command_bytes >= self.max_consensus_log_bytes
            || self.heartbeat_interval_ms == 0
            || self.election_timeout_min_ms <= self.heartbeat_interval_ms
            || self.election_timeout_max_ms <= self.election_timeout_min_ms
            || self.snapshot_after_logs == 0
            || self.max_logs_after_snapshot >= self.snapshot_after_logs
            || self.checkpoint_log_bytes == 0
            || self.checkpoint_log_bytes >= self.max_consensus_log_bytes
            || self.checkpoint_restore_target_ms == 0
        {
            return Err(ConsensusError::InvalidConfig(
                "invalid group, log, rate, timing, or snapshot limits".to_string(),
            ));
        }
        Ok(())
    }

    fn raft_config(&self, namespace_id: &NamespaceId) -> Result<Arc<RaftConfig>, ConsensusError> {
        let config = RaftConfig {
            cluster_name: namespace_id.to_string(),
            heartbeat_interval: self.heartbeat_interval_ms,
            election_timeout_min: self.election_timeout_min_ms,
            election_timeout_max: self.election_timeout_max_ms,
            snapshot_policy: SnapshotPolicy::LogsSinceLast(self.snapshot_after_logs),
            max_in_snapshot_log_to_keep: self.max_logs_after_snapshot,
            purge_batch_size: 1,
            ..RaftConfig::default()
        };
        config
            .validate()
            .map(Arc::new)
            .map_err(|error| ConsensusError::InvalidConfig(error.to_string()))
    }
}

#[derive(Clone)]
pub struct RedbLogStore {
    metadata: Arc<MetadataStore>,
    group: String,
    io_lock: Arc<Mutex<()>>,
    max_log_bytes: u64,
}

impl Debug for RedbLogStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedbLogStore")
            .field("group", &self.group)
            .finish()
    }
}

impl RedbLogStore {
    fn new(
        metadata: Arc<MetadataStore>,
        group: String,
        io_lock: Arc<Mutex<()>>,
        max_log_bytes: u64,
    ) -> Self {
        Self {
            metadata,
            group,
            io_lock,
            max_log_bytes,
        }
    }

    fn state_key(&self, name: &str) -> String {
        format!("{}|{}", self.group, name)
    }

    fn log_key(&self, index: u64) -> String {
        format!("{}|log|{index:020}", self.group)
    }

    fn log_prefix(&self) -> String {
        format!("{}|log|", self.group)
    }

    fn read_value<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<Option<T>, StorageError<NodeId>> {
        let read = self
            .metadata
            .database()
            .begin_read()
            .map_err(read_logs_error)?;
        let table = read
            .open_table(NAMESPACE_RAFT_VOTE)
            .map_err(read_logs_error)?;
        table
            .get(key)
            .map_err(read_logs_error)?
            .map(|value| serde_json::from_slice(value.value()).map_err(read_logs_error))
            .transpose()
    }

    fn write_value<T: Serialize>(&self, key: &str, value: &T) -> Result<(), StorageError<NodeId>> {
        let bytes = serde_json::to_vec(value).map_err(write_logs_error)?;
        let write = self
            .metadata
            .database()
            .begin_write()
            .map_err(write_logs_error)?;
        {
            let mut table = write
                .open_table(NAMESPACE_RAFT_VOTE)
                .map_err(write_logs_error)?;
            table
                .insert(key, bytes.as_slice())
                .map_err(write_logs_error)?;
        }
        write.commit().map_err(write_logs_error)
    }

    fn read_logs<RB>(&self, range: RB) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>>
    where
        RB: RangeBounds<u64>,
    {
        let read = self
            .metadata
            .database()
            .begin_read()
            .map_err(read_logs_error)?;
        let table = read
            .open_table(NAMESPACE_RAFT_LOG)
            .map_err(read_logs_error)?;
        let prefix = self.log_prefix();
        let mut entries = Vec::new();
        for item in table.iter().map_err(read_logs_error)? {
            let (key, value) = item.map_err(read_logs_error)?;
            let key = key.value();
            let Some(index) = key
                .strip_prefix(&prefix)
                .and_then(|index| index.parse::<u64>().ok())
            else {
                continue;
            };
            if range.contains(&index) {
                entries.push(serde_json::from_slice(value.value()).map_err(read_logs_error)?);
            }
        }
        entries.sort_by_key(|entry: &Entry<TypeConfig>| entry.log_id.index);
        Ok(entries)
    }

    fn log_bytes(&self) -> Result<u64, StorageError<NodeId>> {
        let read = self
            .metadata
            .database()
            .begin_read()
            .map_err(read_logs_error)?;
        let table = read
            .open_table(NAMESPACE_RAFT_LOG)
            .map_err(read_logs_error)?;
        let prefix = self.log_prefix();
        let mut bytes = 0u64;
        for item in table.iter().map_err(read_logs_error)? {
            let (key, value) = item.map_err(read_logs_error)?;
            if key.value().starts_with(&prefix) {
                bytes = bytes.saturating_add(value.value().len() as u64);
            }
        }
        Ok(bytes)
    }
}

impl RaftLogReader<TypeConfig> for RedbLogStore {
    async fn try_get_log_entries<RB>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>>
    where
        RB: RangeBounds<u64> + Clone + Debug + Send,
    {
        self.read_logs(range)
    }
}

impl RaftLogStorage<TypeConfig> for RedbLogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let last_purged_log_id = self.read_value(&self.state_key("last_purged"))?;
        let last_log_id = self
            .read_logs(..)?
            .last()
            .map(|entry| entry.log_id)
            .or(last_purged_log_id);
        Ok(LogState {
            last_purged_log_id,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        let _guard = self.io_lock.lock().await;
        self.write_value(&self.state_key("vote"), vote)
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        self.read_value(&self.state_key("vote"))
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        let _guard = self.io_lock.lock().await;
        self.write_value(&self.state_key("committed"), &committed)
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        self.read_value(&self.state_key("committed"))
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let entries = entries.into_iter().collect::<Vec<_>>();
        LOG_APPEND_OBSERVATIONS.fetch_add(1, Ordering::Relaxed);
        LOG_APPEND_ENTRIES.fetch_add(entries.len() as u64, Ordering::Relaxed);
        let queued_at = Instant::now();
        let _guard = self.io_lock.lock().await;
        LOG_APPEND_QUEUE_MICROS.fetch_add(
            queued_at.elapsed().as_micros().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        let _execution_timer = ProcessTimer::start(&LOG_APPEND_EXECUTION_MICROS);
        let encoded = entries
            .iter()
            .map(|entry| serde_json::to_vec(entry).map_err(write_logs_error))
            .collect::<Result<Vec<_>, _>>()?;
        let added = encoded.iter().map(|bytes| bytes.len() as u64).sum::<u64>();
        if self.log_bytes()?.saturating_add(added) > self.max_log_bytes {
            let message = "consensus log byte limit exceeded";
            callback.log_io_completed(Err(std::io::Error::other(message)));
            return Err(write_logs_error(std::io::Error::other(message)));
        }
        let proposal_intents = entries
            .iter()
            .flat_map(|entry| proposal_protection_intents(&self.group, entry))
            .collect::<Vec<_>>();
        let write = self
            .metadata
            .database()
            .begin_write()
            .map_err(write_logs_error)?;
        {
            let mut table = write
                .open_table(NAMESPACE_RAFT_LOG)
                .map_err(write_logs_error)?;
            for (entry, bytes) in entries.iter().zip(encoded) {
                table
                    .insert(self.log_key(entry.log_id.index).as_str(), bytes.as_slice())
                    .map_err(write_logs_error)?;
            }
        }
        if !proposal_intents.is_empty() {
            let mut table = write
                .open_table(pepper_metadata::NAMESPACE_PUBLICATION_INTENTS)
                .map_err(write_logs_error)?;
            for intent in proposal_intents {
                let bytes = serde_json::to_vec(&intent).map_err(write_logs_error)?;
                table
                    .insert(intent.intent_id.as_str(), bytes.as_slice())
                    .map_err(write_logs_error)?;
            }
        }
        let result = write.commit().map_err(write_logs_error);
        match result {
            Ok(()) => {
                callback.log_io_completed(Ok(()));
                Ok(())
            }
            Err(error) => {
                callback.log_io_completed(Err(std::io::Error::other(error.to_string())));
                Err(error)
            }
        }
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let _guard = self.io_lock.lock().await;
        delete_logs(&self.metadata, &self.log_prefix(), log_id.index..)
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let _guard = self.io_lock.lock().await;
        let write = self
            .metadata
            .database()
            .begin_write()
            .map_err(write_logs_error)?;
        {
            let mut logs = write
                .open_table(NAMESPACE_RAFT_LOG)
                .map_err(write_logs_error)?;
            let prefix = self.log_prefix();
            let keys = logs
                .iter()
                .map_err(read_logs_error)?
                .filter_map(|item| {
                    let (key, _) = item.ok()?;
                    let key = key.value();
                    let index = key.strip_prefix(&prefix)?.parse::<u64>().ok()?;
                    (index <= log_id.index).then(|| key.to_string())
                })
                .collect::<Vec<_>>();
            for key in keys {
                logs.remove(key.as_str()).map_err(write_logs_error)?;
            }
        }
        {
            let mut state = write
                .open_table(NAMESPACE_RAFT_VOTE)
                .map_err(write_logs_error)?;
            let bytes = serde_json::to_vec(&log_id).map_err(write_logs_error)?;
            state
                .insert(self.state_key("last_purged").as_str(), bytes.as_slice())
                .map_err(write_logs_error)?;
        }
        write.commit().map_err(write_logs_error)
    }
}

fn committed_publication_intent(
    namespace_id: &NamespaceId,
    log_index: u64,
    request_id: &str,
    intent: &PinIntent,
) -> PublicationIntentRecord {
    let action = match intent.action {
        PinAction::Protect => "protect",
        PinAction::Release => "release",
    };
    let request_hash = blake3::hash(request_id.as_bytes()).to_hex();
    PublicationIntentRecord {
        intent_id: format!(
            "{}|{:016x}|committed|{}|{}|{}",
            namespace_id, log_index, request_hash, action, intent.cid
        ),
        namespace_id: namespace_id.clone(),
        log_index,
        request_id: request_id.to_string(),
        cid: intent.cid.clone(),
        action: intent.action,
        reason: intent.reason.clone(),
        status: "pending".to_string(),
        created_at_unix_seconds: unix_seconds(),
    }
}

fn proposal_protection_intents(
    group: &str,
    entry: &Entry<TypeConfig>,
) -> Vec<PublicationIntentRecord> {
    let EntryPayload::Normal(command) = &entry.payload else {
        return Vec::new();
    };
    let Ok(namespace_id) = parse_namespace_id(group) else {
        return Vec::new();
    };
    command
        .commands
        .iter()
        .flat_map(|envelope| {
            let NamespaceCommand::ApplyTransaction { transaction } = &envelope.command else {
                return Vec::new();
            };
            let request_hash = blake3::hash(envelope.request_id.as_bytes()).to_hex();
            transaction
                .mutations
                .iter()
                .filter_map(|mutation| match mutation {
                    NamespaceMutation::Put { value_cid, .. } => Some(value_cid.clone()),
                    NamespaceMutation::Delete { .. } => None,
                })
                .map(|cid| PublicationIntentRecord {
                    intent_id: format!(
                        "{}|{:016x}|proposal|{}|{}",
                        group, entry.log_id.index, request_hash, cid
                    ),
                    namespace_id: namespace_id.clone(),
                    log_index: entry.log_id.index,
                    request_id: envelope.request_id.clone(),
                    cid,
                    action: PinAction::Protect,
                    reason: "proposal-input".to_string(),
                    status: "pending".to_string(),
                    created_at_unix_seconds: unix_seconds(),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn delete_logs<R>(
    metadata: &MetadataStore,
    prefix: &str,
    range: R,
) -> Result<(), StorageError<NodeId>>
where
    R: RangeBounds<u64>,
{
    let write = metadata
        .database()
        .begin_write()
        .map_err(write_logs_error)?;
    {
        let mut logs = write
            .open_table(NAMESPACE_RAFT_LOG)
            .map_err(write_logs_error)?;
        let keys = logs
            .iter()
            .map_err(read_logs_error)?
            .filter_map(|item| {
                let (key, _) = item.ok()?;
                let key = key.value();
                let index = key.strip_prefix(prefix)?.parse::<u64>().ok()?;
                range.contains(&index).then(|| key.to_string())
            })
            .collect::<Vec<_>>();
        for key in keys {
            logs.remove(key.as_str()).map_err(write_logs_error)?;
        }
    }
    write.commit().map_err(write_logs_error)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedStateMachine {
    last_applied_log: Option<LogId<NodeId>>,
    membership_epoch: u64,
    membership: StoredMembership<NodeId, BasicNode>,
    namespace_state: NamespaceState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotPointer {
    checkpoint_cid: Cid,
    membership_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSnapshotRecord {
    meta: SnapshotMeta<NodeId, BasicNode>,
    pointer: SnapshotPointer,
}

#[derive(Clone)]
pub struct RedbStateMachineStore {
    metadata: Arc<MetadataStore>,
    group: String,
    io_lock: Arc<Mutex<()>>,
    data_store: ConsensusDataStore,
    state: Arc<RwLock<PersistedStateMachine>>,
    current_snapshot: Arc<RwLock<Option<StoredSnapshotRecord>>>,
    membership_epoch: Arc<AtomicU64>,
}

impl Debug for RedbStateMachineStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedbStateMachineStore")
            .field("group", &self.group)
            .finish()
    }
}

impl RedbStateMachineStore {
    fn open(
        metadata: Arc<MetadataStore>,
        group: String,
        io_lock: Arc<Mutex<()>>,
        data_store: ConsensusDataStore,
        initial_state: NamespaceState,
    ) -> Result<Self, ConsensusError> {
        let state = read_json_table::<PersistedStateMachine>(&metadata, NAMESPACE_STATE, &group)?
            .unwrap_or(PersistedStateMachine {
                last_applied_log: None,
                membership_epoch: INITIAL_MEMBERSHIP_EPOCH,
                membership: StoredMembership::default(),
                namespace_state: initial_state,
            });
        let current_snapshot =
            read_json_table::<StoredSnapshotRecord>(&metadata, NAMESPACE_CHECKPOINTS, &group)?;
        let persisted_state = state.clone();
        let membership_epoch = Arc::new(AtomicU64::new(state.membership_epoch));
        let store = Self {
            metadata,
            group,
            io_lock,
            data_store,
            state: Arc::new(RwLock::new(state)),
            current_snapshot: Arc::new(RwLock::new(current_snapshot)),
            membership_epoch,
        };
        store.persist_state_sync(&persisted_state)?;
        Ok(store)
    }

    pub async fn namespace_state(&self) -> NamespaceState {
        self.state.read().await.namespace_state.clone()
    }

    fn persist_state_sync(&self, state: &PersistedStateMachine) -> Result<(), ConsensusError> {
        self.persist_state_and_intents_sync(state, &[], &[])
    }

    fn persist_state_and_intents_sync(
        &self,
        state: &PersistedStateMachine,
        intents: &[PublicationIntentRecord],
        resolved_log_indexes: &[u64],
    ) -> Result<(), ConsensusError> {
        let state_bytes =
            serde_json::to_vec(state).map_err(|error| ConsensusError::Serde(error.to_string()))?;
        let membership_bytes = serde_json::to_vec(&state.membership)
            .map_err(|error| ConsensusError::Serde(error.to_string()))?;
        let write = self
            .metadata
            .database()
            .begin_write()
            .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        {
            let mut table = write
                .open_table(NAMESPACE_STATE)
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
            table
                .insert(self.group.as_str(), state_bytes.as_slice())
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        }
        {
            let mut table = write
                .open_table(NAMESPACE_RAFT_MEMBERSHIP)
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
            table
                .insert(self.group.as_str(), membership_bytes.as_slice())
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        }
        if !intents.is_empty() || !resolved_log_indexes.is_empty() {
            let mut table = write
                .open_table(pepper_metadata::NAMESPACE_PUBLICATION_INTENTS)
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
            for log_index in resolved_log_indexes {
                let prefix = format!("{}|{:016x}|proposal|", self.group, log_index);
                let records = table
                    .iter()
                    .map_err(|error| ConsensusError::Metadata(error.to_string()))?
                    .filter_map(|item| item.ok())
                    .filter(|(key, _)| key.value().starts_with(&prefix))
                    .map(|(key, value)| {
                        let record =
                            serde_json::from_slice::<PublicationIntentRecord>(value.value())
                                .map_err(|error| ConsensusError::Serde(error.to_string()))?;
                        Ok((key.value().to_string(), record))
                    })
                    .collect::<Result<Vec<_>, ConsensusError>>()?;
                for (key, mut record) in records {
                    record.status = "resolved".to_string();
                    let bytes = serde_json::to_vec(&record)
                        .map_err(|error| ConsensusError::Serde(error.to_string()))?;
                    table
                        .insert(key.as_str(), bytes.as_slice())
                        .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
                }
            }
            for intent in intents {
                let bytes = serde_json::to_vec(intent)
                    .map_err(|error| ConsensusError::Serde(error.to_string()))?;
                table
                    .insert(intent.intent_id.as_str(), bytes.as_slice())
                    .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
            }
        }
        write
            .commit()
            .map_err(|error| ConsensusError::Metadata(error.to_string()))
    }

    fn persist_snapshot_sync(
        &self,
        snapshot: &StoredSnapshotRecord,
        previous: Option<&StoredSnapshotRecord>,
    ) -> Result<(), ConsensusError> {
        let bytes = serde_json::to_vec(snapshot)
            .map_err(|error| ConsensusError::Serde(error.to_string()))?;
        let namespace_id = parse_namespace_id(&self.group)
            .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        let log_index = snapshot.meta.last_log_id.map_or(0, |log_id| log_id.index);
        let intent = PublicationIntentRecord {
            intent_id: format!(
                "{}|{:016x}|checkpoint|{}",
                self.group, log_index, snapshot.pointer.checkpoint_cid
            ),
            namespace_id,
            log_index,
            request_id: format!("checkpoint-{}", snapshot.meta.snapshot_id),
            cid: snapshot.pointer.checkpoint_cid.clone(),
            action: PinAction::Protect,
            reason: "namespace_checkpoint".to_string(),
            status: "pending".to_string(),
            created_at_unix_seconds: unix_seconds(),
        };
        let intent_bytes = serde_json::to_vec(&intent)
            .map_err(|error| ConsensusError::Serde(error.to_string()))?;
        let release = previous
            .filter(|previous| previous.pointer.checkpoint_cid != snapshot.pointer.checkpoint_cid)
            .map(|previous| PublicationIntentRecord {
                intent_id: format!(
                    "{}|{:016x}|checkpoint-release|{}",
                    self.group, log_index, previous.pointer.checkpoint_cid
                ),
                namespace_id: intent.namespace_id.clone(),
                log_index,
                request_id: intent.request_id.clone(),
                cid: previous.pointer.checkpoint_cid.clone(),
                action: PinAction::Release,
                reason: "namespace_checkpoint".to_string(),
                status: "pending".to_string(),
                created_at_unix_seconds: unix_seconds(),
            });
        let release_bytes = release
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|error| ConsensusError::Serde(error.to_string()))?;
        let write = self
            .metadata
            .database()
            .begin_write()
            .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        {
            let mut table = write
                .open_table(NAMESPACE_CHECKPOINTS)
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
            table
                .insert(self.group.as_str(), bytes.as_slice())
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        }
        {
            let mut table = write
                .open_table(pepper_metadata::NAMESPACE_PUBLICATION_INTENTS)
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
            table
                .insert(intent.intent_id.as_str(), intent_bytes.as_slice())
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
            if let (Some(release), Some(bytes)) = (&release, &release_bytes) {
                table
                    .insert(release.intent_id.as_str(), bytes.as_slice())
                    .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
            }
        }
        write
            .commit()
            .map_err(|error| ConsensusError::Metadata(error.to_string()))
    }

    fn persist_installed_snapshot_sync(
        &self,
        state: &PersistedStateMachine,
        snapshot: &StoredSnapshotRecord,
        previous: Option<&StoredSnapshotRecord>,
    ) -> Result<(), ConsensusError> {
        let state_bytes =
            serde_json::to_vec(state).map_err(|error| ConsensusError::Serde(error.to_string()))?;
        let membership_bytes = serde_json::to_vec(&state.membership)
            .map_err(|error| ConsensusError::Serde(error.to_string()))?;
        let snapshot_bytes = serde_json::to_vec(snapshot)
            .map_err(|error| ConsensusError::Serde(error.to_string()))?;
        let namespace_id = state.namespace_state.namespace_id.clone();
        let log_index = snapshot.meta.last_log_id.map_or(0, |log_id| log_id.index);
        let checkpoint_intent = PublicationIntentRecord {
            intent_id: format!(
                "{}|{:016x}|checkpoint|{}",
                self.group, log_index, snapshot.pointer.checkpoint_cid
            ),
            namespace_id,
            log_index,
            request_id: format!("checkpoint-{}", snapshot.meta.snapshot_id),
            cid: snapshot.pointer.checkpoint_cid.clone(),
            action: PinAction::Protect,
            reason: "namespace_checkpoint".to_string(),
            status: "pending".to_string(),
            created_at_unix_seconds: unix_seconds(),
        };
        let checkpoint_intent_bytes = serde_json::to_vec(&checkpoint_intent)
            .map_err(|error| ConsensusError::Serde(error.to_string()))?;
        let release = previous
            .filter(|previous| previous.pointer.checkpoint_cid != snapshot.pointer.checkpoint_cid)
            .map(|previous| PublicationIntentRecord {
                intent_id: format!(
                    "{}|{:016x}|checkpoint-release|{}",
                    self.group, log_index, previous.pointer.checkpoint_cid
                ),
                namespace_id: checkpoint_intent.namespace_id.clone(),
                log_index,
                request_id: checkpoint_intent.request_id.clone(),
                cid: previous.pointer.checkpoint_cid.clone(),
                action: PinAction::Release,
                reason: "namespace_checkpoint".to_string(),
                status: "pending".to_string(),
                created_at_unix_seconds: unix_seconds(),
            });
        let release_bytes = release
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|error| ConsensusError::Serde(error.to_string()))?;
        let write = self
            .metadata
            .database()
            .begin_write()
            .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        {
            let mut table = write
                .open_table(NAMESPACE_STATE)
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
            table
                .insert(self.group.as_str(), state_bytes.as_slice())
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        }
        {
            let mut table = write
                .open_table(NAMESPACE_RAFT_MEMBERSHIP)
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
            table
                .insert(self.group.as_str(), membership_bytes.as_slice())
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        }
        {
            let mut table = write
                .open_table(NAMESPACE_CHECKPOINTS)
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
            table
                .insert(self.group.as_str(), snapshot_bytes.as_slice())
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        }
        {
            let mut table = write
                .open_table(pepper_metadata::NAMESPACE_PUBLICATION_INTENTS)
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
            table
                .insert(
                    checkpoint_intent.intent_id.as_str(),
                    checkpoint_intent_bytes.as_slice(),
                )
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
            if let (Some(release), Some(bytes)) = (&release, &release_bytes) {
                table
                    .insert(release.intent_id.as_str(), bytes.as_slice())
                    .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
            }
        }
        write
            .commit()
            .map_err(|error| ConsensusError::Metadata(error.to_string()))
    }
}

impl RaftSnapshotBuilder<TypeConfig> for RedbStateMachineStore {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        let state = self.state.read().await.clone();
        let timestamp = state
            .namespace_state
            .history
            .get(&state.namespace_state.current_revision)
            .map_or(0, |record| record.committed_at_unix_seconds);
        let checkpoint_cid = write_checkpoint(&self.data_store, &state.namespace_state, timestamp)
            .await
            .map_err(write_snapshot_error)?;
        let pointer = SnapshotPointer {
            checkpoint_cid: checkpoint_cid.clone(),
            membership_epoch: state.membership_epoch,
        };
        let data = serde_json::to_vec(&pointer).map_err(write_snapshot_error)?;
        let meta = SnapshotMeta {
            last_log_id: state.last_applied_log,
            last_membership: state.membership.clone(),
            snapshot_id: format!(
                "{}-{}",
                state
                    .last_applied_log
                    .as_ref()
                    .map_or_else(|| "none".to_string(), ToString::to_string),
                checkpoint_cid
            ),
        };
        let record = StoredSnapshotRecord {
            meta: meta.clone(),
            pointer,
        };
        let previous = self.current_snapshot.read().await.clone();
        self.persist_snapshot_sync(&record, previous.as_ref())
            .map_err(write_snapshot_error)?;
        *self.current_snapshot.write().await = Some(record);
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl RaftStateMachine<TypeConfig> for RedbStateMachineStore {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, BasicNode>), StorageError<NodeId>>
    {
        let state = self.state.read().await;
        Ok((state.last_applied_log, state.membership.clone()))
    }

    async fn apply<I>(
        &mut self,
        entries: I,
    ) -> Result<Vec<ConsensusBatchResponse>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let entries = entries.into_iter().collect::<Vec<_>>();
        STATE_APPLY_OBSERVATIONS.fetch_add(1, Ordering::Relaxed);
        STATE_APPLY_ENTRIES.fetch_add(entries.len() as u64, Ordering::Relaxed);
        let queued_at = Instant::now();
        let _guard = self.io_lock.lock().await;
        STATE_APPLY_QUEUE_MICROS.fetch_add(
            queued_at.elapsed().as_micros().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        let _execution_timer = ProcessTimer::start(&STATE_APPLY_EXECUTION_MICROS);
        let mut next = self.state.read().await.clone();
        let mut responses = Vec::new();
        let mut publication_intents = Vec::new();
        let mut resolved_log_indexes = Vec::new();
        for entry in entries {
            let log_index = entry.log_id.index;
            next.last_applied_log = Some(entry.log_id);
            match entry.payload {
                EntryPayload::Blank => responses.push(ConsensusBatchResponse::blank()),
                EntryPayload::Membership(membership) => {
                    next.membership_epoch = next.membership_epoch.saturating_add(1);
                    next.membership = StoredMembership::new(Some(entry.log_id), membership);
                    responses.push(ConsensusBatchResponse::blank());
                }
                EntryPayload::Normal(command) => {
                    resolved_log_indexes.push(log_index);
                    let buffered_store = BufferedConsensusDataStore::new(self.data_store.clone());
                    let mut command_responses = Vec::with_capacity(command.commands.len());
                    for command in command.commands {
                        let request_id = command.request_id.clone();
                        let mut machine = NamespaceStateMachine::new(
                            buffered_store.clone(),
                            next.namespace_state.clone(),
                        )
                        .map_err(|error| apply_error(&entry.log_id, error))?;
                        match machine.apply(command).await {
                            Ok(result) => {
                                next.namespace_state = machine.state().clone();
                                publication_intents.extend(result.pin_intents.iter().map(
                                    |intent| {
                                        committed_publication_intent(
                                            &next.namespace_state.namespace_id,
                                            log_index,
                                            &request_id,
                                            intent,
                                        )
                                    },
                                ));
                                command_responses.push(ConsensusResponse {
                                    result: Some(result),
                                    error_code: None,
                                    error: None,
                                });
                            }
                            Err(error) => {
                                command_responses.push(ConsensusResponse::application_error(error))
                            }
                        }
                    }
                    buffered_store
                        .flush()
                        .await
                        .map_err(|error| apply_error(&entry.log_id, error))?;
                    responses.push(ConsensusBatchResponse {
                        responses: command_responses,
                    });
                }
            }
        }
        self.persist_state_and_intents_sync(&next, &publication_intents, &resolved_log_indexes)
            .map_err(write_state_error)?;
        self.membership_epoch
            .store(next.membership_epoch, Ordering::Release);
        *self.state.write().await = next;
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let _guard = self.io_lock.lock().await;
        if snapshot.get_ref().len() > 1_024 {
            return Err(read_snapshot_error(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "snapshot pointer exceeds 1024 bytes",
            )));
        }
        let pointer: SnapshotPointer =
            serde_json::from_slice(snapshot.get_ref()).map_err(read_snapshot_error)?;
        let namespace_state = load_checkpoint(
            &self.data_store,
            &pointer.checkpoint_cid,
            pepper_namespace::NamespaceLimits::default(),
        )
        .await
        .map_err(read_snapshot_error)?;
        let next = PersistedStateMachine {
            last_applied_log: meta.last_log_id,
            membership_epoch: pointer.membership_epoch,
            membership: meta.last_membership.clone(),
            namespace_state,
        };
        let record = StoredSnapshotRecord {
            meta: meta.clone(),
            pointer,
        };
        let previous = self.current_snapshot.read().await.clone();
        self.persist_installed_snapshot_sync(&next, &record, previous.as_ref())
            .map_err(write_snapshot_error)?;
        self.membership_epoch
            .store(next.membership_epoch, Ordering::Release);
        *self.state.write().await = next;
        *self.current_snapshot.write().await = Some(record);
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        let snapshot = self.current_snapshot.read().await.clone();
        snapshot
            .map(|record| {
                let data = serde_json::to_vec(&record.pointer).map_err(read_snapshot_error)?;
                Ok(Snapshot {
                    meta: record.meta,
                    snapshot: Box::new(Cursor::new(data)),
                })
            })
            .transpose()
    }
}

#[derive(Clone)]
pub struct StorageBundle {
    pub log_store: RedbLogStore,
    pub state_machine: RedbStateMachineStore,
}

impl StorageBundle {
    pub fn open(
        metadata: Arc<MetadataStore>,
        namespace_id: &NamespaceId,
        initial_state: NamespaceState,
        data_store: ConsensusDataStore,
        max_log_bytes: u64,
    ) -> Result<Self, ConsensusError> {
        let group = namespace_id.to_string();
        let io_lock = Arc::new(Mutex::new(()));
        Ok(Self {
            log_store: RedbLogStore::new(
                metadata.clone(),
                group.clone(),
                io_lock.clone(),
                max_log_bytes,
            ),
            state_machine: RedbStateMachineStore::open(
                metadata,
                group,
                io_lock,
                data_store,
                initial_state,
            )?,
        })
    }
}

#[derive(Clone, Default)]
pub struct InProcessRouter {
    routes: Arc<RwLock<HashMap<(String, NodeId), NamespaceRaft>>>,
}

impl InProcessRouter {
    async fn register(&self, group: String, node: NodeId, raft: NamespaceRaft) {
        self.routes.write().await.insert((group, node), raft);
    }

    async fn unregister(&self, group: &str, node: &NodeId) {
        self.routes
            .write()
            .await
            .remove(&(group.to_string(), *node));
    }

    async fn get(&self, group: &str, node: &NodeId) -> Option<NamespaceRaft> {
        self.routes
            .read()
            .await
            .get(&(group.to_string(), *node))
            .cloned()
    }
}

#[derive(Clone)]
struct InProcessNetworkFactory {
    router: InProcessRouter,
    group: String,
}

struct InProcessConnection {
    router: InProcessRouter,
    group: String,
    target: NodeId,
}

type RpcError<E = openraft::error::Infallible> = RPCError<NodeId, BasicNode, RaftError<NodeId, E>>;

impl RaftNetworkFactory<TypeConfig> for InProcessNetworkFactory {
    type Network = InProcessConnection;

    async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> Self::Network {
        InProcessConnection {
            router: self.router.clone(),
            group: self.group.clone(),
            target,
        }
    }
}

impl RaftNetwork<TypeConfig> for InProcessConnection {
    async fn append_entries(
        &mut self,
        request: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RpcError> {
        let raft = self.raft().await?;
        raft.append_entries(request)
            .await
            .map_err(|error| RemoteError::new(self.target, error).into())
    }

    async fn install_snapshot(
        &mut self,
        request: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<InstallSnapshotResponse<NodeId>, RpcError<InstallSnapshotError>> {
        let raft = self.raft().await?;
        raft.install_snapshot(request)
            .await
            .map_err(|error| RemoteError::new(self.target, error).into())
    }

    async fn vote(
        &mut self,
        request: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RpcError> {
        let raft = self.raft().await?;
        raft.vote(request)
            .await
            .map_err(|error| RemoteError::new(self.target, error).into())
    }
}

impl InProcessConnection {
    async fn raft<E>(&self) -> Result<NamespaceRaft, RpcError<E>>
    where
        E: std::error::Error + Clone + 'static,
    {
        self.router
            .get(&self.group, &self.target)
            .await
            .ok_or_else(|| {
                let error = std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    format!("node {} is unavailable", self.target),
                );
                Unreachable::new(&error).into()
            })
    }
}

#[derive(Clone)]
struct QuicNetworkFactory {
    network: NetworkHandle,
    group: String,
    sender_identity: String,
    membership_epoch: Arc<AtomicU64>,
}

struct QuicConnection {
    network: NetworkHandle,
    group: String,
    sender_identity: String,
    target_identity: String,
    membership_epoch: Arc<AtomicU64>,
}

impl RaftNetworkFactory<TypeConfig> for QuicNetworkFactory {
    type Network = QuicConnection;

    async fn new_client(&mut self, _target: NodeId, node: &BasicNode) -> Self::Network {
        QuicConnection {
            network: self.network.clone(),
            group: self.group.clone(),
            sender_identity: self.sender_identity.clone(),
            target_identity: node.addr.clone(),
            membership_epoch: self.membership_epoch.clone(),
        }
    }
}

impl QuicConnection {
    async fn peer<E>(&self) -> Result<SocketAddr, RpcError<E>>
    where
        E: std::error::Error + Clone + 'static,
    {
        self.network
            .peer_address(&self.target_identity)
            .await
            .ok_or_else(|| unreachable_rpc(format!("node {} is unreachable", self.target_identity)))
    }

    fn request<T: Serialize>(
        &self,
        term: u64,
        value: &T,
    ) -> Result<proto::NamespaceRaftRequest, String> {
        Ok(proto::NamespaceRaftRequest {
            context: Some(proto::NamespaceRpcContext {
                namespace_id: self.group.clone(),
                namespace_protocol_version: 1,
                membership_epoch: self.membership_epoch.load(Ordering::Acquire),
                term,
                sender_identity: self.sender_identity.clone(),
                request_id: String::new(),
            }),
            request_json: serde_json::to_vec(value).map_err(|error| error.to_string())?,
        })
    }
}

impl RaftNetwork<TypeConfig> for QuicConnection {
    async fn append_entries(
        &mut self,
        request: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RpcError> {
        let peer = self.peer().await?;
        let term = request.vote.leader_id().term;
        let wire = self.request(term, &request).map_err(unreachable_rpc)?;
        let response = self
            .network
            .namespace_raft_append(peer, wire)
            .await
            .map_err(unreachable_rpc)?;
        serde_json::from_slice(&response).map_err(unreachable_rpc)
    }

    async fn install_snapshot(
        &mut self,
        request: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<InstallSnapshotResponse<NodeId>, RpcError<InstallSnapshotError>> {
        let peer = self.peer().await?;
        let term = request.vote.leader_id().term;
        let wire = self.request(term, &request).map_err(unreachable_rpc)?;
        let response = self
            .network
            .namespace_raft_install_snapshot(peer, wire)
            .await
            .map_err(unreachable_rpc)?;
        serde_json::from_slice(&response).map_err(unreachable_rpc)
    }

    async fn vote(
        &mut self,
        request: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RpcError> {
        let peer = self.peer().await?;
        let term = request.vote.leader_id().term;
        let wire = self.request(term, &request).map_err(unreachable_rpc)?;
        let response = self
            .network
            .namespace_raft_vote(peer, wire)
            .await
            .map_err(unreachable_rpc)?;
        serde_json::from_slice(&response).map_err(unreachable_rpc)
    }
}

fn unreachable_rpc<E>(error: impl std::fmt::Display) -> RpcError<E>
where
    E: std::error::Error + Clone + 'static,
{
    Unreachable::new(&std::io::Error::new(
        std::io::ErrorKind::NotConnected,
        error.to_string(),
    ))
    .into()
}

#[derive(Debug)]
struct RateBucket {
    second: u64,
    count: u64,
}

struct PendingProposal {
    command: CommandEnvelope,
    encoded_bytes: usize,
    queued_at: Instant,
    response: oneshot::Sender<Result<ConsensusResponse, String>>,
}

#[derive(Clone)]
struct ProposalBatcher {
    sender: mpsc::Sender<PendingProposal>,
}

impl ProposalBatcher {
    fn spawn(raft: NamespaceRaft, max_command_bytes: u64) -> Self {
        let (sender, receiver) = mpsc::channel(PROPOSAL_BATCH_CHANNEL_CAPACITY);
        tokio::spawn(run_proposal_batcher(raft, max_command_bytes, receiver));
        Self { sender }
    }

    async fn submit(
        &self,
        command: CommandEnvelope,
        encoded_bytes: usize,
    ) -> Result<ConsensusResponse, ConsensusError> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(PendingProposal {
                command,
                encoded_bytes,
                queued_at: Instant::now(),
                response,
            })
            .await
            .map_err(|_| ConsensusError::Raft("namespace proposal batcher stopped".to_string()))?;
        result
            .await
            .map_err(|_| ConsensusError::Raft("namespace proposal response dropped".to_string()))?
            .map_err(ConsensusError::Raft)
    }
}

async fn run_proposal_batcher(
    raft: NamespaceRaft,
    max_command_bytes: u64,
    mut receiver: mpsc::Receiver<PendingProposal>,
) {
    let mut carry = None;
    loop {
        let first = match carry.take() {
            Some(request) => request,
            None => match receiver.recv().await {
                Some(request) => request,
                None => break,
            },
        };
        let mut encoded_bytes = first.encoded_bytes.saturating_add(32);
        let mut requests = vec![first];
        let deadline = tokio::time::Instant::now() + PROPOSAL_BATCH_MAX_DELAY;
        while requests.len() < PROPOSAL_BATCH_MAX_COMMANDS {
            let next = match tokio::time::timeout_at(deadline, receiver.recv()).await {
                Ok(Some(request)) => request,
                Ok(None) | Err(_) => break,
            };
            let next_bytes = encoded_bytes
                .saturating_add(next.encoded_bytes)
                .saturating_add(1);
            if next_bytes as u64 > max_command_bytes {
                carry = Some(next);
                break;
            }
            encoded_bytes = next_bytes;
            requests.push(next);
        }

        let request_count = requests.len() as u64;
        PROPOSAL_REQUESTS.fetch_add(request_count, Ordering::Relaxed);
        PROPOSAL_BATCHES.fetch_add(1, Ordering::Relaxed);
        PROPOSAL_BATCH_SIZE_MAX.fetch_max(request_count, Ordering::Relaxed);
        let submitted_at = Instant::now();
        for request in &requests {
            PROPOSAL_QUEUE_MICROS.fetch_add(
                request
                    .queued_at
                    .elapsed()
                    .as_micros()
                    .min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
        }
        let payload = ConsensusCommandBatch {
            commands: requests
                .iter()
                .map(|request| request.command.clone())
                .collect(),
        };
        let result = raft.client_write(payload).await;
        PROPOSAL_EXECUTION_MICROS.fetch_add(
            submitted_at.elapsed().as_micros().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        match result {
            Ok(response) if response.data.responses.len() == requests.len() => {
                for (request, response) in requests.into_iter().zip(response.data.responses) {
                    let _ = request.response.send(Ok(response));
                }
            }
            Ok(response) => {
                let error = format!(
                    "namespace proposal batch response count mismatch: expected {}, got {}",
                    requests.len(),
                    response.data.responses.len()
                );
                for request in requests {
                    let _ = request.response.send(Err(error.clone()));
                }
            }
            Err(error) => {
                let error = error.to_string();
                for request in requests {
                    let _ = request.response.send(Err(error.clone()));
                }
            }
        }
    }
}

pub struct GroupHandle {
    pub namespace_id: NamespaceId,
    pub raft: NamespaceRaft,
    pub log_store: RedbLogStore,
    pub state_machine: RedbStateMachineStore,
    membership_epoch: Arc<AtomicU64>,
    rate: Mutex<RateBucket>,
    initialize_lock: Mutex<()>,
    linearizable_arrivals: AtomicU64,
    linearizable_covered: AtomicU64,
    linearizable_lock: Mutex<()>,
    last_known_leader: RwLock<Option<(NodeId, u64)>>,
    proposal_batcher: ProposalBatcher,
}

fn project_namespace_state(
    state: NamespaceState,
    projection: proto::NamespaceStateProjection,
) -> NamespaceState {
    if projection == proto::NamespaceStateProjection::Head {
        return state.into_head_projection();
    }
    state
}

fn leader_read_lease_current(
    local_node: NodeId,
    current_leader: Option<NodeId>,
    millis_since_quorum_ack: Option<u64>,
    heartbeat_interval_ms: u64,
    last_applied_index: Option<u64>,
    last_log_index: Option<u64>,
) -> bool {
    current_leader == Some(local_node)
        && millis_since_quorum_ack.is_some_and(|millis| millis <= heartbeat_interval_ms)
        && last_applied_index >= last_log_index
}

impl GroupHandle {
    pub async fn namespace_state(&self) -> NamespaceState {
        self.state_machine.namespace_state().await
    }

    pub async fn durability_replicas(&self) -> u16 {
        self.state_machine
            .state
            .read()
            .await
            .namespace_state
            .descriptor
            .durability
            .replicas
    }

    async fn applied_log_id(&self) -> Option<LogId<NodeId>> {
        self.state_machine.state.read().await.last_applied_log
    }

    async fn wait_for_applied_index(&self, target: u64, timeout: Duration) -> bool {
        let mut metrics = self.raft.metrics();
        tokio::time::timeout(timeout, async {
            loop {
                if metrics
                    .borrow()
                    .last_applied
                    .is_some_and(|log_id| log_id.index >= target)
                {
                    return true;
                }
                if metrics.changed().await.is_err() {
                    return false;
                }
            }
        })
        .await
        .unwrap_or(false)
    }

    pub fn membership_epoch(&self) -> u64 {
        self.membership_epoch.load(Ordering::Acquire)
    }

    /// Confirm leadership once for every overlapping batch of linearizable
    /// reads. OpenRaft implements this as an empty AppendEntries round to the
    /// voters. Without single-flight coalescing, concurrent S3 GET/HEAD/PUT
    /// requests each start their own quorum round and can exhaust the QUIC
    /// stream budget that Raft heartbeats also need.
    pub async fn ensure_linearizable(&self) -> Result<(), ConsensusError> {
        let arrival = self.linearizable_arrivals.fetch_add(1, Ordering::AcqRel) + 1;
        let _guard = self.linearizable_lock.lock().await;
        if self.linearizable_covered.load(Ordering::Acquire) >= arrival {
            return Ok(());
        }
        // Give concurrently arriving reads a small window to join this quorum
        // confirmation. The arrival watermark is captured after the window, so
        // a request that begins after the proof starts can never reuse it.
        tokio::time::sleep(Duration::from_millis(2)).await;
        let cover_through = self.linearizable_arrivals.load(Ordering::Acquire);
        self.raft
            .ensure_linearizable()
            .await
            .map_err(|error| ConsensusError::Raft(error.to_string()))?;
        self.linearizable_covered
            .store(cover_through, Ordering::Release);
        Ok(())
    }

    pub async fn voter_identities(&self) -> Vec<String> {
        let state = self.state_machine.state.read().await;
        let voters = state.membership.voter_ids().collect::<BTreeSet<_>>();
        let mut identities = state
            .membership
            .nodes()
            .filter(|(node_id, _)| voters.contains(node_id))
            .map(|(_, node)| node.addr.clone())
            .collect::<Vec<_>>();
        if identities.is_empty() {
            identities = state.namespace_state.descriptor.initial_replica_set.clone();
        }
        identities.sort();
        identities
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusCommandMetric {
    pub command_class: String,
    pub count: u64,
    pub total_encoded_bytes: u64,
    pub max_encoded_bytes: u64,
}

#[derive(Debug, Clone, Default)]
struct ConsensusCommandAccumulator {
    count: u64,
    total_encoded_bytes: u64,
    max_encoded_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceOperationalStatus {
    pub namespace_id: NamespaceId,
    pub membership_epoch: u64,
    pub current_revision: u64,
    pub current_root_cid: Cid,
    pub role: String,
    pub term: u64,
    pub leader_raft_id: Option<NodeId>,
    pub last_log_index: Option<u64>,
    pub commit_index: Option<u64>,
    pub applied_index: Option<u64>,
    pub snapshot_index: Option<u64>,
    pub log_lag: u64,
    pub quorum_recently_acknowledged: bool,
    pub millis_since_quorum_ack: Option<u64>,
    pub voter_count: usize,
    pub voter_raft_ids: Vec<NodeId>,
    pub learner_raft_ids: Vec<NodeId>,
    pub local_raft_id: NodeId,
    pub local_voting: bool,
    pub membership_joint: bool,
    pub replication_match_indexes: BTreeMap<NodeId, Option<u64>>,
    pub checkpoint_cid: Option<Cid>,
    pub checkpoint_verified: bool,
    pub running: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceBackupRecord {
    pub namespace_id: NamespaceId,
    pub descriptor_cid: Cid,
    pub checkpoint_cid: Option<Cid>,
    pub current_revision: u64,
    pub current_root_cid: Cid,
    pub applied_index: Option<u64>,
    pub membership_epoch: u64,
}

pub fn inspect_namespace_backup_records(
    metadata: &Arc<MetadataStore>,
) -> Result<Vec<NamespaceBackupRecord>, ConsensusError> {
    let read = metadata
        .database()
        .begin_read()
        .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
    let table = match read.open_table(NAMESPACE_STATE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(error) => return Err(ConsensusError::Metadata(error.to_string())),
    };
    let mut records = Vec::new();
    for entry in table
        .iter()
        .map_err(|error| ConsensusError::Metadata(error.to_string()))?
    {
        let (key, value) = entry.map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        let state: PersistedStateMachine = serde_json::from_slice(value.value())
            .map_err(|error| ConsensusError::Serde(error.to_string()))?;
        let snapshot =
            read_json_table::<StoredSnapshotRecord>(metadata, NAMESPACE_CHECKPOINTS, key.value())?;
        records.push(NamespaceBackupRecord {
            namespace_id: state.namespace_state.namespace_id.clone(),
            descriptor_cid: state.namespace_state.namespace_id.0.clone(),
            checkpoint_cid: snapshot.map(|record| record.pointer.checkpoint_cid),
            current_revision: state.namespace_state.current_revision,
            current_root_cid: state.namespace_state.current_root_cid,
            applied_index: state.last_applied_log.map(|log| log.index),
            membership_epoch: state.membership_epoch,
        });
    }
    records.sort_by_key(|record| record.namespace_id.to_string());
    Ok(records)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisasterRecoveryReport {
    pub namespace_id: NamespaceId,
    pub previous_membership_epoch: u64,
    pub new_membership_epoch: u64,
    pub fork_risk: bool,
    pub warning: String,
}

pub struct NamespaceGroupManager {
    node_identity: String,
    node_id: NodeId,
    metadata: Arc<MetadataStore>,
    router: InProcessRouter,
    network: Option<NetworkHandle>,
    default_data_store: Option<ConsensusDataStore>,
    config: ConsensusConfig,
    groups: RwLock<HashMap<String, Arc<GroupHandle>>>,
    command_metrics: Mutex<BTreeMap<String, ConsensusCommandAccumulator>>,
}

impl NamespaceGroupManager {
    pub fn new(
        node_identity: String,
        metadata: Arc<MetadataStore>,
        router: InProcessRouter,
        config: ConsensusConfig,
    ) -> Result<Self, ConsensusError> {
        config.validate()?;
        let node_id = raft_node_id(&node_identity);
        Ok(Self {
            node_identity,
            node_id,
            metadata,
            router,
            network: None,
            default_data_store: None,
            config,
            groups: RwLock::new(HashMap::new()),
            command_metrics: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn new_networked(
        node_identity: String,
        metadata: Arc<MetadataStore>,
        network: NetworkHandle,
        config: ConsensusConfig,
    ) -> Result<Self, ConsensusError> {
        config.validate()?;
        let node_id = raft_node_id(&node_identity);
        Ok(Self {
            node_identity,
            node_id,
            metadata,
            router: InProcessRouter::default(),
            network: Some(network),
            default_data_store: None,
            config,
            groups: RwLock::new(HashMap::new()),
            command_metrics: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn new_networked_with_data_store(
        node_identity: String,
        metadata: Arc<MetadataStore>,
        network: NetworkHandle,
        data_store: ConsensusDataStore,
        config: ConsensusConfig,
    ) -> Result<Self, ConsensusError> {
        let mut manager = Self::new_networked(node_identity, metadata, network, config)?;
        manager.default_data_store = Some(data_store);
        Ok(manager)
    }

    pub async fn start_group(
        &self,
        state: NamespaceState,
        data_store: ConsensusDataStore,
    ) -> Result<Arc<GroupHandle>, ConsensusError> {
        let group = state.namespace_id.to_string();
        let previous_metadata =
            read_json_table::<GroupMetadata>(&self.metadata, NAMESPACE_GROUPS, &group)?;
        let persisted_state =
            read_json_table::<PersistedStateMachine>(&self.metadata, NAMESPACE_STATE, &group)?;
        let authoritative_assignment = persisted_state.as_ref().and_then(|persisted| {
            (!persisted.membership.nodes().collect::<Vec<_>>().is_empty()).then(|| {
                persisted
                    .membership
                    .nodes()
                    .any(|(node_id, _)| *node_id == self.node_id)
            })
        });
        let assigned = authoritative_assignment.unwrap_or_else(|| {
            state
                .descriptor
                .initial_replica_set
                .contains(&self.node_identity)
                || previous_metadata.as_ref().is_some_and(|metadata| {
                    metadata.members.contains(&self.node_identity)
                        || metadata.learners.contains(&self.node_identity)
                })
        });
        if !assigned {
            return Err(ConsensusError::NotAssigned(group));
        }
        let mut groups = self.groups.write().await;
        if groups.contains_key(&group) {
            return Err(ConsensusError::GroupAlreadyRunning(group));
        }
        if groups.len() >= self.config.max_namespace_groups {
            return Err(ConsensusError::GroupLimit(self.config.max_namespace_groups));
        }
        let restore_started = std::time::Instant::now();
        let bundle = StorageBundle::open(
            self.metadata.clone(),
            &state.namespace_id,
            state.clone(),
            data_store,
            self.config.max_consensus_log_bytes,
        )?;
        let membership_epoch = bundle.state_machine.membership_epoch.clone();
        let raft_config = self.config.raft_config(&state.namespace_id)?;
        let raft = if let Some(network) = &self.network {
            Raft::new(
                self.node_id,
                raft_config,
                QuicNetworkFactory {
                    network: network.clone(),
                    group: group.clone(),
                    sender_identity: self.node_identity.clone(),
                    membership_epoch: membership_epoch.clone(),
                },
                bundle.log_store.clone(),
                bundle.state_machine.clone(),
            )
            .await
        } else {
            Raft::new(
                self.node_id,
                raft_config,
                InProcessNetworkFactory {
                    router: self.router.clone(),
                    group: group.clone(),
                },
                bundle.log_store.clone(),
                bundle.state_machine.clone(),
            )
            .await
        }
        .map_err(|error| ConsensusError::RaftStart(error.to_string()))?;
        if self.network.is_none() {
            self.router
                .register(group.clone(), self.node_id, raft.clone())
                .await;
        }
        let metadata = GroupMetadata {
            namespace_id: state.namespace_id.clone(),
            membership_epoch: membership_epoch.load(Ordering::Acquire),
            local_node_identity: self.node_identity.clone(),
            local_raft_node_id: self.node_id,
            members: previous_metadata.as_ref().map_or_else(
                || state.descriptor.initial_replica_set.clone(),
                |metadata| metadata.members.clone(),
            ),
            learners: previous_metadata
                .as_ref()
                .map_or_else(Vec::new, |metadata| metadata.learners.clone()),
            status: "running".to_string(),
            created_at_unix_seconds: unix_seconds(),
        };
        write_json_table(&self.metadata, NAMESPACE_GROUPS, &group, &metadata)?;
        let proposal_batcher = ProposalBatcher::spawn(raft.clone(), self.config.max_command_bytes);
        let handle = Arc::new(GroupHandle {
            namespace_id: state.namespace_id,
            raft,
            log_store: bundle.log_store,
            state_machine: bundle.state_machine,
            membership_epoch,
            rate: Mutex::new(RateBucket {
                second: 0,
                count: 0,
            }),
            initialize_lock: Mutex::new(()),
            linearizable_arrivals: AtomicU64::new(0),
            linearizable_covered: AtomicU64::new(0),
            linearizable_lock: Mutex::new(()),
            last_known_leader: RwLock::new(None),
            proposal_batcher,
        });
        if restore_started.elapsed().as_millis()
            > u128::from(self.config.checkpoint_restore_target_ms)
        {
            let _ = handle.raft.trigger().snapshot().await;
        }
        groups.insert(group, handle.clone());
        if let Some(network) = &self.network {
            network.update_namespace_group_count(groups.len() as u64);
        }
        Ok(handle)
    }

    pub async fn prepare_learner_group(
        &self,
        state: NamespaceState,
        data_store: ConsensusDataStore,
        membership_epoch: u64,
        current_voters: Vec<String>,
    ) -> Result<Arc<GroupHandle>, ConsensusError> {
        if membership_epoch == 0
            || current_voters.len() != 3
            || current_voters.contains(&self.node_identity)
        {
            return Err(ConsensusError::InvalidReplacement(
                "learner bootstrap must name three current voters and a new local replica"
                    .to_string(),
            ));
        }
        let group = state.namespace_id.to_string();
        let metadata = GroupMetadata {
            namespace_id: state.namespace_id.clone(),
            membership_epoch,
            local_node_identity: self.node_identity.clone(),
            local_raft_node_id: self.node_id,
            members: current_voters,
            learners: vec![self.node_identity.clone()],
            status: "learner".to_string(),
            created_at_unix_seconds: unix_seconds(),
        };
        write_json_table(&self.metadata, NAMESPACE_GROUPS, &group, &metadata)?;
        let persisted = PersistedStateMachine {
            last_applied_log: None,
            membership_epoch,
            membership: StoredMembership::default(),
            namespace_state: state.clone(),
        };
        write_json_table(&self.metadata, NAMESPACE_STATE, &group, &persisted)?;
        self.start_group(state, data_store).await
    }

    pub async fn replace_replica(
        &self,
        namespace_id: &NamespaceId,
        failed_identity: &str,
        replacement_identity: &str,
    ) -> Result<(), ConsensusError> {
        if failed_identity == replacement_identity {
            return Err(ConsensusError::InvalidReplacement(
                "failed and replacement identities are equal".to_string(),
            ));
        }
        let group = self.group(namespace_id).await?;
        group.ensure_linearizable().await?;
        let key = namespace_id.to_string();
        let mut metadata =
            read_json_table::<GroupMetadata>(&self.metadata, NAMESPACE_GROUPS, &key)?
                .ok_or_else(|| ConsensusError::Metadata("group metadata missing".to_string()))?;
        if metadata.members.len() != 3
            || !metadata
                .members
                .iter()
                .any(|member| member == failed_identity)
            || metadata
                .members
                .iter()
                .any(|member| member == replacement_identity)
        {
            return Err(ConsensusError::InvalidReplacement(
                "replacement must exchange one current voter for one new node".to_string(),
            ));
        }
        let replacement_id = raft_node_id(replacement_identity);
        if metadata
            .members
            .iter()
            .any(|identity| raft_node_id(identity) == replacement_id)
        {
            return Err(ConsensusError::InvalidReplacement(
                "replacement Raft node ID collides with a current member".to_string(),
            ));
        }
        group
            .raft
            .add_learner(replacement_id, BasicNode::new(replacement_identity), true)
            .await
            .map_err(|error| ConsensusError::Raft(error.to_string()))?;
        let voters = metadata
            .members
            .iter()
            .filter(|identity| identity.as_str() != failed_identity)
            .map(|identity| raft_node_id(identity))
            .chain(std::iter::once(replacement_id))
            .collect::<BTreeSet<_>>();
        if voters.len() != 3 {
            return Err(ConsensusError::InvalidReplacement(
                "replacement did not produce exactly three voters".to_string(),
            ));
        }
        group
            .raft
            .change_membership(voters, false)
            .await
            .map_err(|error| ConsensusError::Raft(error.to_string()))?;
        metadata
            .members
            .retain(|identity| identity != failed_identity);
        metadata.members.push(replacement_identity.to_string());
        metadata.members.sort();
        metadata.learners.clear();
        metadata.membership_epoch = group.membership_epoch.load(Ordering::Acquire);
        write_json_table(&self.metadata, NAMESPACE_GROUPS, &key, &metadata)
    }

    pub async fn prepare_disaster_recovery(
        &self,
        state: NamespaceState,
        data_store: ConsensusDataStore,
        mut new_members: Vec<String>,
        confirmation: &str,
    ) -> Result<(Arc<GroupHandle>, DisasterRecoveryReport), ConsensusError> {
        if confirmation != "I_ACCEPT_NAMESPACE_FORK_RISK" {
            return Err(ConsensusError::RecoveryConfirmationRequired);
        }
        if self
            .groups
            .read()
            .await
            .contains_key(&state.namespace_id.to_string())
        {
            return Err(ConsensusError::InvalidReplacement(
                "stop the existing group before disaster recovery".to_string(),
            ));
        }
        new_members.sort();
        new_members.dedup();
        if new_members.len() != 3 || !new_members.contains(&self.node_identity) {
            return Err(ConsensusError::InvalidReplacement(
                "recovery requires exactly three unique members including the local node"
                    .to_string(),
            ));
        }
        let group = state.namespace_id.to_string();
        let previous_epoch =
            read_json_table::<PersistedStateMachine>(&self.metadata, NAMESPACE_STATE, &group)?
                .map_or(INITIAL_MEMBERSHIP_EPOCH, |stored| stored.membership_epoch);
        let new_epoch = previous_epoch.saturating_add(1);
        clear_consensus_group(&self.metadata, &group)?;
        let persisted = PersistedStateMachine {
            last_applied_log: None,
            membership_epoch: new_epoch,
            membership: StoredMembership::default(),
            namespace_state: state.clone(),
        };
        write_json_table(&self.metadata, NAMESPACE_STATE, &group, &persisted)?;
        write_json_table(
            &self.metadata,
            NAMESPACE_GROUPS,
            &group,
            &GroupMetadata {
                namespace_id: state.namespace_id.clone(),
                membership_epoch: new_epoch,
                local_node_identity: self.node_identity.clone(),
                local_raft_node_id: self.node_id,
                members: new_members,
                learners: Vec::new(),
                status: "recovery_pending".to_string(),
                created_at_unix_seconds: unix_seconds(),
            },
        )?;
        let handle = self.start_group(state.clone(), data_store).await?;
        Ok((
            handle,
            DisasterRecoveryReport {
                namespace_id: state.namespace_id,
                previous_membership_epoch: previous_epoch,
                new_membership_epoch: new_epoch,
                fork_risk: true,
                warning: "quorum-loss recovery can fork from surviving replicas of an older epoch"
                    .to_string(),
            },
        ))
    }

    pub async fn initialize(
        &self,
        namespace_id: &NamespaceId,
        members: BTreeMap<NodeId, BasicNode>,
    ) -> Result<(), ConsensusError> {
        let group = self.group(namespace_id).await?;
        let _initialize_guard = group.initialize_lock.lock().await;
        let metadata = read_json_table::<GroupMetadata>(
            &self.metadata,
            NAMESPACE_GROUPS,
            &namespace_id.to_string(),
        )?
        .ok_or_else(|| ConsensusError::Metadata("group metadata missing".to_string()))?;
        let expected = raft_members(&metadata.members)?;
        if members != expected {
            return Err(ConsensusError::InvalidConfig(
                "initial Raft membership does not match the namespace descriptor".to_string(),
            ));
        }
        let existing = {
            let state = group.state_machine.state.read().await;
            state
                .membership
                .nodes()
                .map(|(node_id, node)| (*node_id, node.clone()))
                .collect::<BTreeMap<_, _>>()
        };
        if !existing.is_empty() {
            return if existing == members {
                Ok(())
            } else {
                Err(ConsensusError::InvalidConfig(
                    "namespace is already initialized with different members".to_string(),
                ))
            };
        }
        group
            .raft
            .initialize(members)
            .await
            .map_err(|error| ConsensusError::Raft(error.to_string()))
    }

    pub async fn linearizable_namespace_state(
        &self,
        namespace_id: &NamespaceId,
    ) -> Result<NamespaceState, ConsensusError> {
        self.routed_linearizable_namespace_state(namespace_id).await
    }

    pub async fn linearizable_namespace_head(
        &self,
        namespace_id: &NamespaceId,
    ) -> Result<NamespaceState, ConsensusError> {
        self.routed_linearizable_namespace_head(namespace_id).await
    }

    pub async fn command_metrics(&self) -> Vec<ConsensusCommandMetric> {
        self.command_metrics
            .lock()
            .await
            .iter()
            .map(|(command_class, metric)| ConsensusCommandMetric {
                command_class: command_class.clone(),
                count: metric.count,
                total_encoded_bytes: metric.total_encoded_bytes,
                max_encoded_bytes: metric.max_encoded_bytes,
            })
            .collect()
    }

    pub async fn client_write(
        &self,
        namespace_id: &NamespaceId,
        command: CommandEnvelope,
    ) -> Result<NamespaceClientWriteResponse, ConsensusError> {
        let (group, _) = self.admit_write(namespace_id, &command).await?;
        let response = group
            .raft
            .client_write(ConsensusCommandBatch {
                commands: vec![command],
            })
            .await
            .map_err(|error| ConsensusError::Raft(error.to_string()))?;
        self.maybe_checkpoint(&group).await?;
        Ok(response)
    }

    async fn batched_client_write(
        &self,
        namespace_id: &NamespaceId,
        command: CommandEnvelope,
    ) -> Result<ConsensusResponse, ConsensusError> {
        let (group, encoded_bytes) = self.admit_write(namespace_id, &command).await?;
        let response = group
            .proposal_batcher
            .submit(command, encoded_bytes)
            .await?;
        self.maybe_checkpoint(&group).await?;
        Ok(response)
    }

    async fn admit_write(
        &self,
        namespace_id: &NamespaceId,
        command: &CommandEnvelope,
    ) -> Result<(Arc<GroupHandle>, usize), ConsensusError> {
        let command_bytes = serde_json::to_vec(&command)
            .map_err(|error| ConsensusError::Serde(error.to_string()))?;
        let command_class = match &command.command {
            NamespaceCommand::ApplyTransaction { .. } => "apply_transaction",
            NamespaceCommand::CreateSnapshot { .. } => "create_snapshot",
            NamespaceCommand::DeleteSnapshot { .. } => "delete_snapshot",
            NamespaceCommand::Rollback { .. } => "rollback",
        };
        {
            let mut metrics = self.command_metrics.lock().await;
            let metric = metrics.entry(command_class.to_string()).or_default();
            metric.count = metric.count.saturating_add(1);
            metric.total_encoded_bytes = metric
                .total_encoded_bytes
                .saturating_add(command_bytes.len().min(u64::MAX as usize) as u64);
            metric.max_encoded_bytes = metric.max_encoded_bytes.max(command_bytes.len() as u64);
        }
        if command_bytes.len() as u64 > self.config.max_command_bytes {
            return Err(ConsensusError::CommandTooLarge(
                self.config.max_command_bytes,
            ));
        }
        let group = self.group(namespace_id).await?;
        {
            let now = unix_seconds_u64();
            let mut rate = group.rate.lock().await;
            if rate.second != now {
                rate.second = now;
                rate.count = 0;
            }
            if rate.count >= self.config.max_namespace_write_rate {
                return Err(ConsensusError::WriteRateLimited);
            }
            rate.count += 1;
        }
        Ok((group, command_bytes.len()))
    }

    async fn maybe_checkpoint(&self, group: &GroupHandle) -> Result<(), ConsensusError> {
        if group
            .log_store
            .log_bytes()
            .map_err(|error| ConsensusError::Metadata(error.to_string()))?
            >= self.config.checkpoint_log_bytes
        {
            let _ = group.raft.trigger().snapshot().await;
        }
        Ok(())
    }

    pub async fn select_replica_set(
        &self,
        placement_seed: &Cid,
        required_log_bytes: u64,
    ) -> Result<Vec<String>, ConsensusError> {
        let network = self.network.as_ref().ok_or_else(|| {
            ConsensusError::Placement("networked placement is disabled".to_string())
        })?;
        let local = network.local_descriptor();
        let mut candidates = vec![ConsensusPlacementNode {
            node_id: local.node_id,
            addresses: local.addresses,
            reachable: true,
            failure_domain: (!local.failure_domain.is_empty()).then_some(local.failure_domain),
            consensus_enabled: local.namespace_consensus_enabled,
            namespace_group_capacity: local.namespace_group_capacity,
            namespace_group_count: local.namespace_group_count,
            max_consensus_log_bytes: local.max_consensus_log_bytes,
        }];
        candidates.extend(
            network
                .peers()
                .await
                .into_iter()
                .map(|peer| ConsensusPlacementNode {
                    node_id: peer.node_id,
                    addresses: peer.addresses,
                    reachable: peer.connected,
                    failure_domain: peer.failure_domain,
                    consensus_enabled: peer.namespace_consensus_enabled,
                    namespace_group_capacity: peer.namespace_group_capacity,
                    namespace_group_count: peer.namespace_group_count,
                    max_consensus_log_bytes: peer.max_consensus_log_bytes,
                }),
        );
        let replicas = select_namespace_replicas(placement_seed, &candidates, required_log_bytes)
            .map_err(|error| ConsensusError::Placement(error.to_string()))?;
        Ok(replicas.into_iter().map(|node| node.node_id).collect())
    }

    pub async fn select_replacement(
        &self,
        placement_seed: &Cid,
        retained_node_ids: &[String],
        required_log_bytes: u64,
    ) -> Result<String, ConsensusError> {
        let network = self.network.as_ref().ok_or_else(|| {
            ConsensusError::Placement("networked placement is disabled".to_string())
        })?;
        let local = network.local_descriptor();
        let mut candidates = vec![ConsensusPlacementNode {
            node_id: local.node_id,
            addresses: local.addresses,
            reachable: true,
            failure_domain: (!local.failure_domain.is_empty()).then_some(local.failure_domain),
            consensus_enabled: local.namespace_consensus_enabled,
            namespace_group_capacity: local.namespace_group_capacity,
            namespace_group_count: local.namespace_group_count,
            max_consensus_log_bytes: local.max_consensus_log_bytes,
        }];
        candidates.extend(
            network
                .peers()
                .await
                .into_iter()
                .map(|peer| ConsensusPlacementNode {
                    node_id: peer.node_id,
                    addresses: peer.addresses,
                    reachable: peer.connected,
                    failure_domain: peer.failure_domain,
                    consensus_enabled: peer.namespace_consensus_enabled,
                    namespace_group_capacity: peer.namespace_group_capacity,
                    namespace_group_count: peer.namespace_group_count,
                    max_consensus_log_bytes: peer.max_consensus_log_bytes,
                }),
        );
        select_namespace_replacement(
            placement_seed,
            &candidates,
            retained_node_ids,
            required_log_bytes,
        )
        .map(|node| node.node_id)
        .map_err(|error| ConsensusError::Placement(error.to_string()))
    }

    pub async fn routed_linearizable_namespace_state(
        &self,
        namespace_id: &NamespaceId,
    ) -> Result<NamespaceState, ConsensusError> {
        self.routed_linearizable_namespace_state_projection(
            namespace_id,
            proto::NamespaceStateProjection::Full,
        )
        .await
    }

    pub async fn routed_linearizable_namespace_head(
        &self,
        namespace_id: &NamespaceId,
    ) -> Result<NamespaceState, ConsensusError> {
        self.routed_linearizable_namespace_state_projection(
            namespace_id,
            proto::NamespaceStateProjection::Head,
        )
        .await
    }

    async fn routed_linearizable_namespace_state_projection(
        &self,
        namespace_id: &NamespaceId,
        projection: proto::NamespaceStateProjection,
    ) -> Result<NamespaceState, ConsensusError> {
        if let Ok(group) = self.group(namespace_id).await {
            if let Some(state) = self.linearizable_local_namespace_state(&group).await {
                return Ok(project_namespace_state(state, projection));
            }
        }
        let network = self.network.as_ref().ok_or_else(|| {
            ConsensusError::Raft("networked namespace routing is disabled".to_string())
        })?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(group) = self.group(namespace_id).await {
                if let Some(state) = self.linearizable_local_namespace_state(&group).await {
                    return Ok(project_namespace_state(state, projection));
                }
                if let Some(state) = self
                    .namespace_state_from_local_leader(network, namespace_id, &group, projection)
                    .await
                {
                    return Ok(state);
                }
            }

            let cached_candidates = self
                .discovery_records(&namespace_id.to_string())
                .map_err(|error| ConsensusError::Raft(error.to_string()))?;
            if let Some(state) = self
                .namespace_state_from_candidates(
                    network,
                    namespace_id,
                    cached_candidates,
                    projection,
                )
                .await
            {
                return Ok(state);
            }

            let peers = network.peers().await;
            let mut discoveries = tokio::task::JoinSet::new();
            for peer in &peers {
                for address in &peer.addresses {
                    let Ok(address) = address.parse::<SocketAddr>() else {
                        continue;
                    };
                    let network = network.clone();
                    let namespace_id = namespace_id.to_string();
                    discoveries.spawn(async move {
                        tokio::time::timeout(
                            Duration::from_secs(1),
                            network.namespace_discover(address, namespace_id),
                        )
                        .await
                        .ok()
                        .and_then(Result::ok)
                    });
                }
            }

            let mut candidates = self
                .discovery_records(&namespace_id.to_string())
                .map_err(|error| ConsensusError::Raft(error.to_string()))?;
            while let Some(result) = discoveries.join_next().await {
                if let Ok(Some(records)) = result {
                    for record in records {
                        let _ = self.persist_discovery_record(record.clone());
                        candidates.push(record);
                    }
                }
            }
            // An election may complete while discovery is in flight. Check the
            // local group again before routing to remote candidates.
            if let Ok(group) = self.group(namespace_id).await {
                if let Some(state) = self.linearizable_local_namespace_state(&group).await {
                    return Ok(project_namespace_state(state, projection));
                }
            }

            if let Some(state) = self
                .namespace_state_from_candidates(network, namespace_id, candidates, projection)
                .await
            {
                return Ok(state);
            }

            if tokio::time::Instant::now() >= deadline || peers.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(ConsensusError::Raft(
            "namespace leader unavailable after bounded rediscovery".into(),
        ))
    }

    async fn linearizable_local_namespace_state(
        &self,
        group: &GroupHandle,
    ) -> Option<NamespaceState> {
        let metrics = group.raft.metrics().borrow().clone();
        let leader = if let Some(leader) = metrics.current_leader {
            *group.last_known_leader.write().await = Some((leader, metrics.current_term));
            leader
        } else {
            group
                .last_known_leader
                .read()
                .await
                .filter(|(_, term)| *term == metrics.current_term)
                .map(|(leader, _)| leader)?
        };
        if leader != self.node_id {
            return None;
        }
        // A quorum acknowledgement resets the election timer on enough voters
        // that another leader cannot be elected before the minimum election
        // timeout. Reuse only the much shorter heartbeat interval, and only
        // when this leader has applied its complete local log. This preserves
        // linearizability while removing a quorum RPC from the common read.
        let lease_current = leader_read_lease_current(
            self.node_id,
            metrics.current_leader,
            metrics.millis_since_quorum_ack,
            self.config.heartbeat_interval_ms,
            metrics.last_applied.map(|log| log.index),
            metrics.last_log_index,
        );
        if lease_current {
            LINEARIZABLE_READ_LEASE_HITS.fetch_add(1, Ordering::Relaxed);
            return Some(group.namespace_state().await);
        }
        LINEARIZABLE_READ_PROOFS.fetch_add(1, Ordering::Relaxed);
        if group.ensure_linearizable().await.is_err() {
            return None;
        }
        let confirmed = group.raft.metrics().borrow().clone();
        if confirmed.current_leader != Some(self.node_id)
            || confirmed.current_term != metrics.current_term
        {
            return None;
        }
        *group.last_known_leader.write().await = Some((self.node_id, confirmed.current_term));
        Some(group.namespace_state().await)
    }

    async fn namespace_state_from_local_leader(
        &self,
        network: &NetworkHandle,
        namespace_id: &NamespaceId,
        group: &GroupHandle,
        projection: proto::NamespaceStateProjection,
    ) -> Option<NamespaceState> {
        let metrics = group.raft.metrics().borrow().clone();
        let leader = if let Some(leader) = metrics.current_leader {
            *group.last_known_leader.write().await = Some((leader, metrics.current_term));
            leader
        } else {
            group
                .last_known_leader
                .read()
                .await
                .filter(|(_, term)| *term == metrics.current_term)
                .map(|(leader, _)| leader)?
        };
        if leader == self.node_id {
            return None;
        }
        let state = group.state_machine.state.read().await;
        let leader_identity = state
            .membership
            .nodes()
            .find(|(node_id, _)| **node_id == leader)
            .map(|(_, node)| node.addr.clone())
            .or_else(|| {
                state
                    .namespace_state
                    .descriptor
                    .initial_replica_set
                    .iter()
                    .find(|identity| raft_node_id(identity) == leader)
                    .cloned()
            })?;
        drop(state);
        let peer = network.peer_address(&leader_identity).await?;
        let request = proto::NamespaceStateRequest {
            context: Some(proto::NamespaceRpcContext {
                namespace_id: namespace_id.to_string(),
                namespace_protocol_version: 1,
                membership_epoch: group.membership_epoch(),
                term: metrics.current_term,
                sender_identity: self.node_identity.clone(),
                request_id: String::new(),
            }),
            projection: proto::NamespaceStateProjection::AppliedIndex as i32,
        };
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            network.namespace_state(peer, request),
        )
        .await
        .ok()?
        .ok()?;
        if response.has_applied_index
            && group
                .wait_for_applied_index(response.applied_index, Duration::from_secs(2))
                .await
        {
            return Some(project_namespace_state(
                group.namespace_state().await,
                projection,
            ));
        }
        None
    }

    async fn namespace_state_from_candidates(
        &self,
        network: &NetworkHandle,
        namespace_id: &NamespaceId,
        mut candidates: Vec<proto::NamespaceDiscoveryRecord>,
        projection: proto::NamespaceStateProjection,
    ) -> Option<NamespaceState> {
        candidates.sort_by(|left, right| {
            right
                .membership_epoch
                .cmp(&left.membership_epoch)
                .then_with(|| right.leader_term.cmp(&left.leader_term))
        });
        candidates.dedup_by(|left, right| {
            left.membership_epoch == right.membership_epoch
                && left.leader_node_id == right.leader_node_id
        });

        for record in candidates.into_iter().take(3) {
            if record.leader_node_id.is_empty() || record.leader_node_id == self.node_identity {
                continue;
            }
            let Some(peer) = network.peer_address(&record.leader_node_id).await else {
                continue;
            };
            let request = proto::NamespaceStateRequest {
                context: Some(proto::NamespaceRpcContext {
                    namespace_id: namespace_id.to_string(),
                    namespace_protocol_version: 1,
                    membership_epoch: record.membership_epoch,
                    term: record.leader_term,
                    sender_identity: self.node_identity.clone(),
                    request_id: String::new(),
                }),
                projection: projection as i32,
            };
            if let Some(response) = tokio::time::timeout(
                Duration::from_millis(500),
                network.namespace_state(peer, request),
            )
            .await
            .ok()
            .and_then(Result::ok)
                && let Ok(state) = serde_json::from_slice(&response.state_json)
            {
                return Some(state);
            }
        }
        None
    }

    pub async fn routed_write(
        &self,
        namespace_id: &NamespaceId,
        command: CommandEnvelope,
    ) -> Result<ConsensusResponse, ConsensusError> {
        if let Ok(group) = self.group(namespace_id).await {
            let metrics = group.raft.metrics().borrow().clone();
            if metrics.current_leader == Some(self.node_id) {
                return self.batched_client_write(namespace_id, command).await;
            }
        }
        let network = self.network.as_ref().ok_or_else(|| {
            ConsensusError::Raft("networked namespace routing is disabled".to_string())
        })?;
        let command_json = serde_json::to_vec(&command)
            .map_err(|error| ConsensusError::Serde(error.to_string()))?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(group) = self.group(namespace_id).await {
                let metrics = group.raft.metrics().borrow().clone();
                if metrics.current_leader == Some(self.node_id) {
                    return self
                        .batched_client_write(namespace_id, command.clone())
                        .await;
                }
            }
            let peers = network.peers().await;
            let mut discoveries = tokio::task::JoinSet::new();
            for peer in &peers {
                for address in &peer.addresses {
                    let Ok(address) = address.parse::<SocketAddr>() else {
                        continue;
                    };
                    let network = network.clone();
                    let namespace_id = namespace_id.to_string();
                    discoveries.spawn(async move {
                        tokio::time::timeout(
                            Duration::from_secs(1),
                            network.namespace_discover(address, namespace_id),
                        )
                        .await
                        .ok()
                        .and_then(Result::ok)
                    });
                }
            }
            let mut candidates = self
                .discovery_records(&namespace_id.to_string())
                .map_err(|error| ConsensusError::Raft(error.to_string()))?;
            while let Some(result) = discoveries.join_next().await {
                if let Ok(Some(records)) = result {
                    for record in records {
                        let _ = self.persist_discovery_record(record.clone());
                        candidates.push(record);
                    }
                }
            }
            candidates.sort_by(|left, right| {
                right
                    .membership_epoch
                    .cmp(&left.membership_epoch)
                    .then_with(|| right.leader_term.cmp(&left.leader_term))
            });
            candidates.dedup_by(|left, right| {
                left.membership_epoch == right.membership_epoch
                    && left.leader_node_id == right.leader_node_id
            });

            let mut forwards = tokio::task::JoinSet::new();
            for record in candidates.into_iter().take(3) {
                if record.leader_node_id.is_empty() || record.leader_node_id == self.node_identity {
                    continue;
                }
                let Some(peer) = network.peer_address(&record.leader_node_id).await else {
                    continue;
                };
                let network = network.clone();
                let request = proto::NamespaceForwardRequest {
                    context: Some(proto::NamespaceRpcContext {
                        namespace_id: namespace_id.to_string(),
                        namespace_protocol_version: 1,
                        membership_epoch: record.membership_epoch,
                        term: record.leader_term,
                        sender_identity: self.node_identity.clone(),
                        request_id: String::new(),
                    }),
                    command_json: command_json.clone(),
                };
                forwards.spawn(async move {
                    tokio::time::timeout(
                        Duration::from_secs(3),
                        network.namespace_forward(peer, request),
                    )
                    .await
                    .ok()
                    .and_then(Result::ok)
                });
            }
            while let Some(result) = forwards.join_next().await {
                if let Ok(Some(response)) = result
                    && let Ok(result) = serde_json::from_slice(&response.response_json)
                {
                    return Ok(result);
                }
            }
            if tokio::time::Instant::now() >= deadline || peers.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(ConsensusError::Raft(
            "namespace leader unavailable after bounded rediscovery".to_string(),
        ))
    }

    pub async fn announce_group(&self, namespace_id: &NamespaceId) -> Result<(), ConsensusError> {
        let network = self.network.as_ref().ok_or_else(|| {
            ConsensusError::Raft("networked namespace announcements are disabled".to_string())
        })?;
        let records =
            NetworkNamespaceService::discover(self, &self.node_identity, namespace_id.to_string())
                .await
                .map_err(|error| ConsensusError::Raft(error.to_string()))?;
        let Some(record) = records.into_iter().next() else {
            return Err(ConsensusError::Raft(
                "namespace discovery record unavailable".to_string(),
            ));
        };
        for peer in network.peers().await {
            for address in peer.addresses {
                if let Ok(address) = address.parse()
                    && network
                        .namespace_announce(address, record.clone())
                        .await
                        .is_ok()
                {
                    break;
                }
            }
        }
        Ok(())
    }

    pub async fn group(
        &self,
        namespace_id: &NamespaceId,
    ) -> Result<Arc<GroupHandle>, ConsensusError> {
        self.groups
            .read()
            .await
            .get(&namespace_id.to_string())
            .cloned()
            .ok_or_else(|| ConsensusError::GroupNotRunning(namespace_id.to_string()))
    }

    pub async fn shutdown_group(&self, namespace_id: &NamespaceId) -> Result<(), ConsensusError> {
        let group_key = namespace_id.to_string();
        let handle = self
            .groups
            .write()
            .await
            .remove(&group_key)
            .ok_or_else(|| ConsensusError::GroupNotRunning(group_key.clone()))?;
        self.router.unregister(&group_key, &self.node_id).await;
        handle
            .raft
            .shutdown()
            .await
            .map_err(|error| ConsensusError::Raft(error.to_string()))?;
        let mut metadata =
            read_json_table::<GroupMetadata>(&self.metadata, NAMESPACE_GROUPS, &group_key)?
                .ok_or_else(|| ConsensusError::Metadata("group metadata missing".to_string()))?;
        metadata.status = "stopped".to_string();
        write_json_table(&self.metadata, NAMESPACE_GROUPS, &group_key, &metadata)?;
        if let Some(network) = &self.network {
            network.update_namespace_group_count(self.group_count().await as u64);
        }
        Ok(())
    }

    pub async fn group_count(&self) -> usize {
        self.groups.read().await.len()
    }

    pub async fn operational_statuses(&self) -> Vec<NamespaceOperationalStatus> {
        let groups = self
            .groups
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut statuses = Vec::with_capacity(groups.len());
        for group in groups {
            let metrics = group.raft.metrics().borrow().clone();
            let last_log_index = metrics.last_log_index;
            let applied_index = metrics.last_applied.map(|log| log.index);
            let commit_index = group
                .log_store
                .clone()
                .read_committed()
                .await
                .ok()
                .flatten()
                .map(|log| log.index);
            let membership = metrics.membership_config.membership();
            let voter_raft_ids = membership.voter_ids().collect::<Vec<_>>();
            let learner_raft_ids = membership.learner_ids().collect::<Vec<_>>();
            let local_voting = voter_raft_ids.contains(&self.node_id);
            let replication_match_indexes = metrics
                .replication
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|(node_id, log)| (node_id, log.map(|log| log.index)))
                .collect();
            let namespace_state = group.namespace_state().await;
            let checkpoint_cid = group
                .state_machine
                .current_snapshot
                .read()
                .await
                .as_ref()
                .map(|snapshot| snapshot.pointer.checkpoint_cid.clone());
            statuses.push(NamespaceOperationalStatus {
                namespace_id: group.namespace_id.clone(),
                membership_epoch: group.membership_epoch(),
                current_revision: namespace_state.current_revision,
                current_root_cid: namespace_state.current_root_cid,
                role: format!("{:?}", metrics.state).to_lowercase(),
                term: metrics.current_term,
                leader_raft_id: metrics.current_leader,
                last_log_index,
                commit_index,
                applied_index,
                snapshot_index: metrics.snapshot.map(|log| log.index),
                log_lag: last_log_index
                    .unwrap_or(0)
                    .saturating_sub(applied_index.unwrap_or(0)),
                quorum_recently_acknowledged: metrics.millis_since_quorum_ack.is_some_and(
                    |millis| millis <= self.config.election_timeout_max_ms.saturating_mul(2),
                ),
                millis_since_quorum_ack: metrics.millis_since_quorum_ack,
                voter_count: voter_raft_ids.len(),
                voter_raft_ids,
                learner_raft_ids,
                local_raft_id: self.node_id,
                local_voting,
                membership_joint: membership.get_joint_config().len() > 1,
                replication_match_indexes,
                checkpoint_verified: checkpoint_cid.is_some(),
                checkpoint_cid,
                running: metrics.running_state.is_ok(),
            });
        }
        statuses.sort_by_key(|status| status.namespace_id.to_string());
        statuses
    }

    /// Restart every locally assigned persisted group before the node serves
    /// namespace traffic. Storage recovery verifies checkpoint CIDs and replays
    /// committed logs before each handle is returned.
    pub async fn recover_assigned_groups(&self) -> Result<usize, ConsensusError> {
        let data_store = self.default_data_store.clone().ok_or_else(|| {
            ConsensusError::Metadata("default consensus data store is unavailable".into())
        })?;
        let read = self
            .metadata
            .database()
            .begin_read()
            .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        let table = match read.open_table(NAMESPACE_STATE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(error) => return Err(ConsensusError::Metadata(error.to_string())),
        };
        let persisted = table
            .iter()
            .map_err(|error| ConsensusError::Metadata(error.to_string()))?
            .map(|entry| {
                let (_, value) =
                    entry.map_err(|error| ConsensusError::Metadata(error.to_string()))?;
                serde_json::from_slice::<PersistedStateMachine>(value.value())
                    .map_err(|error| ConsensusError::Serde(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        drop(table);
        drop(read);
        let mut recovered = 0usize;
        for state in persisted {
            let assigned = state
                .membership
                .nodes()
                .any(|(node_id, _)| *node_id == self.node_id)
                || state
                    .namespace_state
                    .descriptor
                    .initial_replica_set
                    .contains(&self.node_identity);
            if assigned
                && self
                    .group(&state.namespace_state.namespace_id)
                    .await
                    .is_err()
            {
                self.start_group(state.namespace_state, data_store.clone())
                    .await?;
                recovered += 1;
            }
        }
        Ok(recovered)
    }

    pub async fn backup_records(&self) -> Vec<NamespaceBackupRecord> {
        let groups = self.groups.read().await;
        let mut records = Vec::new();
        for group in groups.values() {
            let state = group.namespace_state().await;
            let metrics = group.raft.metrics().borrow().clone();
            let checkpoint_cid = group
                .state_machine
                .current_snapshot
                .read()
                .await
                .as_ref()
                .map(|snapshot| snapshot.pointer.checkpoint_cid.clone());
            records.push(NamespaceBackupRecord {
                namespace_id: state.namespace_id.clone(),
                descriptor_cid: state.namespace_id.0.clone(),
                checkpoint_cid,
                current_revision: state.current_revision,
                current_root_cid: state.current_root_cid,
                applied_index: metrics.last_applied.map(|log| log.index),
                membership_epoch: group.membership_epoch(),
            });
        }
        records.sort_by_key(|record| record.namespace_id.to_string());
        records
    }

    pub fn metadata(&self) -> &Arc<MetadataStore> {
        &self.metadata
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredDiscoveryRecord {
    namespace_id: String,
    namespace_protocol_version: u32,
    membership_epoch: u64,
    replica_node_ids: Vec<String>,
    leader_node_id: String,
    leader_term: u64,
    expires_at_unix_seconds: i64,
    announcer_node_id: String,
    signature_hex: String,
}

impl From<proto::NamespaceDiscoveryRecord> for StoredDiscoveryRecord {
    fn from(record: proto::NamespaceDiscoveryRecord) -> Self {
        Self {
            namespace_id: record.namespace_id,
            namespace_protocol_version: record.namespace_protocol_version,
            membership_epoch: record.membership_epoch,
            replica_node_ids: record.replica_node_ids,
            leader_node_id: record.leader_node_id,
            leader_term: record.leader_term,
            expires_at_unix_seconds: record.expires_at_unix_seconds,
            announcer_node_id: record.announcer_node_id,
            signature_hex: record.signature_hex,
        }
    }
}

impl From<StoredDiscoveryRecord> for proto::NamespaceDiscoveryRecord {
    fn from(record: StoredDiscoveryRecord) -> Self {
        Self {
            namespace_id: record.namespace_id,
            namespace_protocol_version: record.namespace_protocol_version,
            membership_epoch: record.membership_epoch,
            replica_node_ids: record.replica_node_ids,
            leader_node_id: record.leader_node_id,
            leader_term: record.leader_term,
            expires_at_unix_seconds: record.expires_at_unix_seconds,
            announcer_node_id: record.announcer_node_id,
            signature_hex: record.signature_hex,
        }
    }
}

impl NamespaceGroupManager {
    async fn validate_rpc_context(
        &self,
        authenticated_node: &str,
        context: Option<&proto::NamespaceRpcContext>,
        allow_membership_transition: bool,
    ) -> Result<Arc<GroupHandle>, NetworkError> {
        let context = context.ok_or_else(|| namespace_network_error("missing RPC context"))?;
        if context.namespace_protocol_version != 1
            || context.sender_identity != authenticated_node
            || context.membership_epoch == 0
        {
            return Err(NetworkError::Unauthenticated);
        }
        let namespace_id = parse_namespace_id(&context.namespace_id)?;
        let group = self
            .group(&namespace_id)
            .await
            .map_err(namespace_network_error)?;
        let current_epoch = group.membership_epoch.load(Ordering::Acquire);
        let epoch_valid = if allow_membership_transition {
            context.membership_epoch >= current_epoch.saturating_sub(4)
                && context.membership_epoch <= current_epoch.saturating_add(4)
        } else {
            context.membership_epoch == current_epoch
        };
        if !epoch_valid {
            return Err(namespace_network_error("stale namespace membership epoch"));
        }
        Ok(group)
    }

    fn persist_discovery_record(
        &self,
        record: proto::NamespaceDiscoveryRecord,
    ) -> Result<(), NetworkError> {
        let key = format!(
            "{}|{:016x}|{}",
            record.namespace_id, record.membership_epoch, record.announcer_node_id
        );
        write_json_table(
            &self.metadata,
            pepper_metadata::NAMESPACE_DISCOVERY_RECORDS,
            &key,
            &StoredDiscoveryRecord::from(record),
        )
        .map_err(namespace_network_error)
    }

    fn discovery_records(
        &self,
        namespace_id: &str,
    ) -> Result<Vec<proto::NamespaceDiscoveryRecord>, NetworkError> {
        let now = unix_seconds();
        let prefix = format!("{namespace_id}|");
        let read = self
            .metadata
            .database()
            .begin_read()
            .map_err(namespace_network_error)?;
        let table = read
            .open_table(pepper_metadata::NAMESPACE_DISCOVERY_RECORDS)
            .map_err(namespace_network_error)?;
        let mut records = Vec::new();
        let mut expired = Vec::new();
        for item in table.iter().map_err(namespace_network_error)? {
            let (key, value) = item.map_err(namespace_network_error)?;
            if !key.value().starts_with(&prefix) {
                continue;
            }
            let record: StoredDiscoveryRecord =
                serde_json::from_slice(value.value()).map_err(namespace_network_error)?;
            if record.expires_at_unix_seconds > now {
                records.push(record.into());
            } else {
                expired.push(key.value().to_string());
            }
        }
        drop(table);
        drop(read);
        if !expired.is_empty() {
            let write = self
                .metadata
                .database()
                .begin_write()
                .map_err(namespace_network_error)?;
            {
                let mut table = write
                    .open_table(pepper_metadata::NAMESPACE_DISCOVERY_RECORDS)
                    .map_err(namespace_network_error)?;
                for key in expired {
                    table
                        .remove(key.as_str())
                        .map_err(namespace_network_error)?;
                }
            }
            write.commit().map_err(namespace_network_error)?;
        }
        records.sort_by(|left: &proto::NamespaceDiscoveryRecord, right| {
            right
                .membership_epoch
                .cmp(&left.membership_epoch)
                .then_with(|| right.leader_term.cmp(&left.leader_term))
                .then_with(|| left.announcer_node_id.cmp(&right.announcer_node_id))
        });
        records.truncate(16);
        Ok(records)
    }
}

#[async_trait]
impl NetworkNamespaceService for NamespaceGroupManager {
    async fn discover(
        &self,
        _authenticated_node: &str,
        namespace_id: String,
    ) -> Result<Vec<proto::NamespaceDiscoveryRecord>, NetworkError> {
        let parsed = parse_namespace_id(&namespace_id)?;
        if let Ok(group) = self.group(&parsed).await
            && let Some(network) = &self.network
        {
            let metrics = group.raft.metrics().borrow().clone();
            let metadata =
                read_json_table::<GroupMetadata>(&self.metadata, NAMESPACE_GROUPS, &namespace_id)
                    .map_err(namespace_network_error)?
                    .ok_or_else(|| {
                        namespace_network_error("namespace group metadata is missing")
                    })?;
            let applied = group.state_machine.state.read().await;
            let voters = applied.membership.voter_ids().collect::<BTreeSet<_>>();
            let mut committed_members = applied
                .membership
                .nodes()
                .filter(|(node_id, _)| voters.contains(node_id))
                .map(|(_, node)| node.addr.clone())
                .collect::<Vec<_>>();
            if committed_members.is_empty() {
                committed_members = metadata.members;
            }
            committed_members.sort();
            let leader_node_id = metrics
                .current_leader
                .and_then(|leader| {
                    committed_members
                        .iter()
                        .find(|identity| raft_node_id(identity) == leader)
                        .cloned()
                })
                .unwrap_or_default();
            drop(applied);
            let record = network.make_namespace_discovery_record(
                namespace_id.clone(),
                group.membership_epoch.load(Ordering::Acquire),
                committed_members,
                leader_node_id,
                metrics.current_term,
                unix_seconds().saturating_add(60),
            );
            self.persist_discovery_record(record)?;
        }
        self.discovery_records(&namespace_id)
    }

    async fn announce(
        &self,
        authenticated_node: &str,
        record: proto::NamespaceDiscoveryRecord,
    ) -> Result<(), NetworkError> {
        if record.announcer_node_id != authenticated_node
            || record.expires_at_unix_seconds <= unix_seconds()
        {
            return Err(NetworkError::Unauthenticated);
        }
        parse_namespace_id(&record.namespace_id)?;
        self.persist_discovery_record(record)
    }

    async fn raft_vote(
        &self,
        authenticated_node: &str,
        request: proto::NamespaceRaftRequest,
    ) -> Result<Vec<u8>, NetworkError> {
        let group = self
            .validate_rpc_context(authenticated_node, request.context.as_ref(), false)
            .await?;
        let vote: VoteRequest<NodeId> =
            serde_json::from_slice(&request.request_json).map_err(namespace_network_error)?;
        let term = request.context.as_ref().map_or(0, |context| context.term);
        if vote.vote.leader_id().term != term {
            return Err(NetworkError::Unauthenticated);
        }
        let response = group
            .raft
            .vote(vote)
            .await
            .map_err(namespace_network_error)?;
        serde_json::to_vec(&response).map_err(namespace_network_error)
    }

    async fn raft_append(
        &self,
        authenticated_node: &str,
        request: proto::NamespaceRaftRequest,
    ) -> Result<Vec<u8>, NetworkError> {
        let group = self
            .validate_rpc_context(authenticated_node, request.context.as_ref(), true)
            .await?;
        let append: AppendEntriesRequest<TypeConfig> =
            serde_json::from_slice(&request.request_json).map_err(namespace_network_error)?;
        let term = request.context.as_ref().map_or(0, |context| context.term);
        if append.vote.leader_id().term != term {
            return Err(NetworkError::Unauthenticated);
        }
        let response = group
            .raft
            .append_entries(append)
            .await
            .map_err(namespace_network_error)?;
        serde_json::to_vec(&response).map_err(namespace_network_error)
    }

    async fn raft_install_snapshot(
        &self,
        authenticated_node: &str,
        request: proto::NamespaceRaftRequest,
    ) -> Result<Vec<u8>, NetworkError> {
        let group = self
            .validate_rpc_context(authenticated_node, request.context.as_ref(), true)
            .await?;
        let install: InstallSnapshotRequest<TypeConfig> =
            serde_json::from_slice(&request.request_json).map_err(namespace_network_error)?;
        let term = request.context.as_ref().map_or(0, |context| context.term);
        if install.vote.leader_id().term != term || install.data.len() > 1_024 {
            return Err(NetworkError::Unauthenticated);
        }
        let response = group
            .raft
            .install_snapshot(install)
            .await
            .map_err(namespace_network_error)?;
        serde_json::to_vec(&response).map_err(namespace_network_error)
    }

    async fn forward(
        &self,
        authenticated_node: &str,
        request: proto::NamespaceForwardRequest,
    ) -> Result<proto::NamespaceForwardResponse, NetworkError> {
        let group = self
            .validate_rpc_context(authenticated_node, request.context.as_ref(), false)
            .await?;
        let context = request
            .context
            .as_ref()
            .ok_or_else(|| namespace_network_error("missing forward context"))?;
        let current = group.raft.metrics().borrow().clone();
        if current.current_leader != Some(self.node_id) || current.current_term != context.term {
            return Err(namespace_network_error("stale namespace leader hint"));
        }
        let command: CommandEnvelope =
            serde_json::from_slice(&request.command_json).map_err(namespace_network_error)?;
        let response = self
            .batched_client_write(&group.namespace_id, command)
            .await
            .map_err(namespace_network_error)?;
        let metrics = group.raft.metrics().borrow().clone();
        let metadata = read_json_table::<GroupMetadata>(
            &self.metadata,
            NAMESPACE_GROUPS,
            &group.namespace_id.to_string(),
        )
        .map_err(namespace_network_error)?;
        let leader_node_id = metrics.current_leader.and_then(|leader| {
            metadata.as_ref().and_then(|metadata| {
                metadata
                    .members
                    .iter()
                    .find(|identity| raft_node_id(identity) == leader)
                    .cloned()
            })
        });
        Ok(proto::NamespaceForwardResponse {
            response_json: serde_json::to_vec(&response).map_err(namespace_network_error)?,
            leader_node_id: leader_node_id.unwrap_or_default(),
            leader_term: metrics.current_term,
        })
    }

    async fn state(
        &self,
        authenticated_node: &str,
        request: proto::NamespaceStateRequest,
    ) -> Result<proto::NamespaceStateResponse, NetworkError> {
        let group = self
            .validate_rpc_context(authenticated_node, request.context.as_ref(), false)
            .await?;
        let context = request
            .context
            .as_ref()
            .ok_or_else(|| namespace_network_error("missing state context"))?;
        let metrics = group.raft.metrics().borrow().clone();
        if metrics.current_term != context.term {
            return Err(namespace_network_error("stale namespace leader hint"));
        }
        if self
            .linearizable_local_namespace_state(&group)
            .await
            .is_none()
        {
            return Err(namespace_network_error("stale namespace leader hint"));
        }
        let applied = group.applied_log_id().await;
        let projection = proto::NamespaceStateProjection::try_from(request.projection)
            .map_err(|_| namespace_network_error("invalid namespace state projection"))?;
        if projection == proto::NamespaceStateProjection::AppliedIndex {
            return Ok(proto::NamespaceStateResponse {
                state_json: Vec::new(),
                applied_index: applied.map_or(0, |log_id| log_id.index),
                applied_term: applied.map_or(0, |log_id| log_id.leader_id.term),
                has_applied_index: applied.is_some(),
            });
        }
        let state = project_namespace_state(group.namespace_state().await, projection);
        Ok(proto::NamespaceStateResponse {
            state_json: serde_json::to_vec(&state).map_err(namespace_network_error)?,
            applied_index: applied.map_or(0, |log_id| log_id.index),
            applied_term: applied.map_or(0, |log_id| log_id.leader_id.term),
            has_applied_index: applied.is_some(),
        })
    }

    async fn bootstrap(
        &self,
        _authenticated_node: &str,
        request: proto::NamespaceBootstrapRequest,
    ) -> Result<proto::NamespaceBootstrapResponse, NetworkError> {
        let namespace_id = parse_namespace_id(&request.namespace_id)?;
        let checkpoint_cid = request
            .checkpoint_cid
            .parse::<Cid>()
            .map_err(namespace_network_error)?;
        let data_store = self
            .default_data_store
            .clone()
            .ok_or_else(|| namespace_network_error("namespace bootstrap is disabled"))?;
        let state = load_checkpoint(
            &data_store,
            &checkpoint_cid,
            pepper_namespace::NamespaceLimits::default(),
        )
        .await
        .map_err(namespace_network_error)?;
        if state.namespace_id != namespace_id {
            return Err(namespace_network_error(
                "checkpoint does not belong to requested namespace",
            ));
        }
        if request.recovery {
            if self.group(&namespace_id).await.is_ok() {
                self.shutdown_group(&namespace_id)
                    .await
                    .map_err(namespace_network_error)?;
            }
            self.prepare_disaster_recovery(
                state.clone(),
                data_store,
                request.current_voters.clone(),
                &request.recovery_confirmation,
            )
            .await
            .map_err(namespace_network_error)?;
            if request.initialize {
                self.initialize(
                    &namespace_id,
                    raft_members(&request.current_voters).map_err(namespace_network_error)?,
                )
                .await
                .map_err(namespace_network_error)?;
            }
            return Ok(proto::NamespaceBootstrapResponse {
                started: true,
                initialized: request.initialize,
            });
        }
        let started = if self.group(&namespace_id).await.is_ok() {
            false
        } else if request.learner {
            self.prepare_learner_group(
                state.clone(),
                data_store,
                request.membership_epoch,
                request.current_voters.clone(),
            )
            .await
            .map_err(namespace_network_error)?;
            true
        } else {
            self.start_group(state.clone(), data_store)
                .await
                .map_err(namespace_network_error)?;
            true
        };
        if request.initialize {
            self.initialize(
                &namespace_id,
                raft_members(&state.descriptor.initial_replica_set)
                    .map_err(namespace_network_error)?,
            )
            .await
            .map_err(namespace_network_error)?;
        }
        Ok(proto::NamespaceBootstrapResponse {
            started,
            initialized: request.initialize,
        })
    }
}

fn parse_namespace_id(value: &str) -> Result<NamespaceId, NetworkError> {
    let cid = value.parse::<Cid>().map_err(namespace_network_error)?;
    NamespaceId::new(cid).map_err(namespace_network_error)
}

fn namespace_network_error(error: impl std::fmt::Display) -> NetworkError {
    NetworkError::BlockService(error.to_string())
}

fn clear_consensus_group(metadata: &MetadataStore, group: &str) -> Result<(), ConsensusError> {
    let write = metadata
        .database()
        .begin_write()
        .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
    {
        let mut table = write
            .open_table(NAMESPACE_RAFT_LOG)
            .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        let prefix = format!("{group}|");
        let keys = table
            .iter()
            .map_err(|error| ConsensusError::Metadata(error.to_string()))?
            .filter_map(|item| item.ok())
            .map(|(key, _)| key.value().to_string())
            .filter(|key| key.starts_with(&prefix))
            .collect::<Vec<_>>();
        for key in keys {
            table
                .remove(key.as_str())
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        }
    }
    {
        let mut table = write
            .open_table(NAMESPACE_RAFT_VOTE)
            .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        let prefix = format!("{group}|");
        let keys = table
            .iter()
            .map_err(|error| ConsensusError::Metadata(error.to_string()))?
            .filter_map(|item| item.ok())
            .map(|(key, _)| key.value().to_string())
            .filter(|key| key.starts_with(&prefix))
            .collect::<Vec<_>>();
        for key in keys {
            table
                .remove(key.as_str())
                .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        }
    }
    for definition in [
        NAMESPACE_RAFT_MEMBERSHIP,
        NAMESPACE_STATE,
        NAMESPACE_CHECKPOINTS,
    ] {
        let mut table = write
            .open_table(definition)
            .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        table
            .remove(group)
            .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
    }
    write
        .commit()
        .map_err(|error| ConsensusError::Metadata(error.to_string()))
}

fn write_json_table<T: Serialize>(
    metadata: &MetadataStore,
    definition: TableDefinition<&str, &[u8]>,
    key: &str,
    value: &T,
) -> Result<(), ConsensusError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| ConsensusError::Serde(error.to_string()))?;
    let write = metadata
        .database()
        .begin_write()
        .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
    {
        let mut table = write
            .open_table(definition)
            .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
        table
            .insert(key, bytes.as_slice())
            .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
    }
    write
        .commit()
        .map_err(|error| ConsensusError::Metadata(error.to_string()))
}

fn read_json_table<T: for<'de> Deserialize<'de>>(
    metadata: &MetadataStore,
    definition: TableDefinition<&str, &[u8]>,
    key: &str,
) -> Result<Option<T>, ConsensusError> {
    let read = metadata
        .database()
        .begin_read()
        .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
    let table = read
        .open_table(definition)
        .map_err(|error| ConsensusError::Metadata(error.to_string()))?;
    table
        .get(key)
        .map_err(|error| ConsensusError::Metadata(error.to_string()))?
        .map(|value| {
            serde_json::from_slice(value.value())
                .map_err(|error| ConsensusError::Serde(error.to_string()))
        })
        .transpose()
}

fn read_logs_error(error: impl std::fmt::Display) -> StorageError<NodeId> {
    let error = std::io::Error::other(error.to_string());
    StorageIOError::read_logs(&error).into()
}

fn write_logs_error(error: impl std::fmt::Display) -> StorageError<NodeId> {
    let error = std::io::Error::other(error.to_string());
    StorageIOError::write_logs(&error).into()
}

fn write_state_error(error: impl std::fmt::Display) -> StorageError<NodeId> {
    let error = std::io::Error::other(error.to_string());
    StorageIOError::write_state_machine(&error).into()
}

fn apply_error(log_id: &LogId<NodeId>, error: impl std::fmt::Display) -> StorageError<NodeId> {
    let error = std::io::Error::other(error.to_string());
    StorageIOError::apply(*log_id, &error).into()
}

fn write_snapshot_error(error: impl std::fmt::Display) -> StorageError<NodeId> {
    let error = std::io::Error::other(error.to_string());
    StorageIOError::write_snapshot(None, &error).into()
}

fn read_snapshot_error(error: impl std::fmt::Display) -> StorageError<NodeId> {
    let error = std::io::Error::other(error.to_string());
    StorageIOError::read_snapshot(None, &error).into()
}

fn unix_seconds() -> i64 {
    unix_seconds_u64() as i64
}

fn unix_seconds_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openraft::storage::{RaftLogStorage, RaftStateMachine};
    use pepper_config::StorageLocationConfig;
    use pepper_crypto::NodeIdentity;
    use pepper_merkle::MerkleLimits;
    use pepper_namespace::{
        KeyPrecondition, NamespaceCommand, NamespaceDescriptor, NamespaceKind, NamespaceLimits,
        NamespaceMutation, TransactionCommand, create_namespace,
    };
    use pepper_network::{NetworkBlockService, NetworkConfig as PeerNetworkConfig};
    use pepper_storage::BlockStore;
    use pepper_types::{CODEC_RAW, PutBlockResponse};
    use std::time::Duration;

    #[test]
    fn leader_read_lease_requires_current_leader_quorum_and_complete_apply() {
        assert!(leader_read_lease_current(
            7,
            Some(7),
            Some(100),
            100,
            Some(42),
            Some(42),
        ));
        assert!(!leader_read_lease_current(
            7,
            Some(8),
            Some(1),
            100,
            Some(42),
            Some(42),
        ));
        assert!(!leader_read_lease_current(
            7,
            Some(7),
            Some(101),
            100,
            Some(42),
            Some(42),
        ));
        assert!(!leader_read_lease_current(
            7,
            Some(7),
            Some(1),
            100,
            Some(41),
            Some(42),
        ));
    }

    #[derive(Clone)]
    struct TestBlockService(Arc<BlockStore>);

    #[async_trait]
    impl NetworkBlockService for TestBlockService {
        async fn has_block(&self, cid: &Cid) -> Result<bool, NetworkError> {
            self.0
                .has(cid)
                .map_err(|error| NetworkError::BlockService(error.to_string()))
        }

        async fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, NetworkError> {
            self.0
                .get(cid)
                .map(|block| block.payload)
                .map_err(|error| NetworkError::BlockService(error.to_string()))
        }

        async fn put_replica(
            &self,
            codec: Codec,
            payload: Vec<u8>,
        ) -> Result<PutBlockResponse, NetworkError> {
            self.0
                .put(codec, &payload)
                .map_err(|error| NetworkError::BlockService(error.to_string()))
        }
    }

    struct NetworkTestNode {
        _directory: tempfile::TempDir,
        identity: String,
        address: SocketAddr,
        network: NetworkHandle,
        manager: Arc<NamespaceGroupManager>,
        data_store: ConsensusDataStore,
    }

    fn free_address() -> SocketAddr {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap()
    }

    async fn network_test_node(name: &str) -> NetworkTestNode {
        let directory = tempfile::tempdir().unwrap();
        let metadata = Arc::new(
            MetadataStore::open_or_create(directory.path().join("metadata.redb")).unwrap(),
        );
        let block_store = Arc::new(
            BlockStore::open(
                metadata.clone(),
                &[StorageLocationConfig {
                    path: directory.path().join("blocks"),
                    max_capacity_bytes: 64 * 1024 * 1024,
                }],
            )
            .unwrap(),
        );
        let identity = NodeIdentity::generate_and_store(directory.path().join("identity")).unwrap();
        let identity_string = identity.node_id().to_string();
        let address = free_address();
        let network = NetworkHandle::start(
            PeerNetworkConfig {
                node_name: name.to_string(),
                listen_addr: address,
                advertise_addr: address,
                bootstrap_peers: Vec::new(),
                cluster_secret: Some(vec![7; 32]),
                requests_per_minute: None,
                failure_domain: Some(name.to_string()),
                placement_labels: HashMap::new(),
                storage_capacity_bytes: 64 * 1024 * 1024,
                storage_available_bytes: 64 * 1024 * 1024,
                namespace_consensus_enabled: true,
                namespace_group_capacity: 16,
                namespace_group_count: 0,
                max_consensus_log_bytes: 16 * 1024 * 1024,
                max_namespace_write_rate: 1_000,
            },
            identity,
            metadata.clone(),
            Arc::new(TestBlockService(block_store.clone())),
        )
        .await
        .unwrap();
        let manager = Arc::new(
            NamespaceGroupManager::new_networked(
                identity_string.clone(),
                metadata,
                network.clone(),
                ConsensusConfig {
                    max_consensus_log_bytes: 16 * 1024 * 1024,
                    checkpoint_log_bytes: 4 * 1024 * 1024,
                    snapshot_after_logs: 3,
                    max_logs_after_snapshot: 1,
                    ..ConsensusConfig::default()
                },
            )
            .unwrap(),
        );
        network.set_namespace_service(manager.clone()).await;
        let data_store =
            ConsensusDataStore::from_networked_block_store(block_store, network.clone());
        NetworkTestNode {
            _directory: directory,
            identity: identity_string,
            address,
            network,
            manager,
            data_store,
        }
    }

    async fn connect_network_nodes(nodes: &[&NetworkTestNode]) {
        for source in nodes {
            for target in nodes {
                if source.identity != target.identity {
                    source.network.node_info(target.address).await.unwrap();
                }
            }
        }
    }

    struct TestNode {
        _directory: tempfile::TempDir,
        manager: Arc<NamespaceGroupManager>,
        data_store: ConsensusDataStore,
        initial_state: NamespaceState,
    }

    async fn test_node(
        identity: &str,
        router: InProcessRouter,
        descriptor: NamespaceDescriptor,
        config: ConsensusConfig,
    ) -> TestNode {
        let directory = tempfile::tempdir().unwrap();
        let metadata = Arc::new(
            MetadataStore::open_or_create(directory.path().join("metadata.redb")).unwrap(),
        );
        let data_store = ConsensusDataStore::new(MemoryDataBackend::default());
        let created = create_namespace(
            &data_store,
            descriptor,
            NamespaceLimits::default(),
            MerkleLimits::default(),
        )
        .await
        .unwrap();
        let manager = Arc::new(
            NamespaceGroupManager::new(identity.to_string(), metadata, router, config).unwrap(),
        );
        manager
            .start_group(created.state.clone(), data_store.clone())
            .await
            .unwrap();
        TestNode {
            _directory: directory,
            manager,
            data_store,
            initial_state: created.state,
        }
    }

    fn descriptor(created_at: i64) -> NamespaceDescriptor {
        NamespaceDescriptor::new(
            NamespaceKind::Kv,
            vec!["node-c".into(), "node-a".into(), "node-b".into()],
            "creator",
            "00",
            created_at,
        )
    }

    fn members() -> BTreeMap<NodeId, BasicNode> {
        raft_members(&["node-a".into(), "node-b".into(), "node-c".into()]).unwrap()
    }

    fn put_command(state: &NamespaceState, request_id: &str, key: &str) -> CommandEnvelope {
        CommandEnvelope {
            request_id: request_id.to_string(),
            writer_identity: "writer".to_string(),
            timestamp_unix_seconds: state.current_revision as i64 + 2,
            signature_hex: "00".to_string(),
            command: NamespaceCommand::ApplyTransaction {
                transaction: TransactionCommand {
                    base_revision: state.current_revision,
                    base_root_cid: state.current_root_cid.clone(),
                    mutations: vec![NamespaceMutation::Put {
                        key_hex: hex::encode(key),
                        value_cid: Cid::new(CODEC_RAW, key.as_bytes()),
                        value_kind: "raw".to_string(),
                        metadata: BTreeMap::new(),
                        precondition: KeyPrecondition::Absent,
                    }],
                    message: None,
                },
            },
        }
    }

    #[tokio::test]
    async fn consensus_command_uses_uniform_batch_wire_shape() {
        let store = ConsensusDataStore::new(MemoryDataBackend::default());
        let state = create_namespace(
            &store,
            descriptor(1),
            NamespaceLimits::default(),
            MerkleLimits::default(),
        )
        .await
        .unwrap()
        .state;
        let command = put_command(&state, "canonical-wire-shape", "key");
        let payload = ConsensusCommandBatch {
            commands: vec![command.clone()],
        };
        let encoded = serde_json::to_value(&payload).unwrap();
        assert_eq!(encoded["commands"].as_array().unwrap().len(), 1);
        assert_eq!(
            serde_json::from_value::<ConsensusCommandBatch>(encoded).unwrap(),
            payload
        );
    }

    async fn wait_for_leader(nodes: &[&TestNode]) -> NodeId {
        for _ in 0..100 {
            for node in nodes {
                let namespace_id = &node.initial_state.namespace_id;
                let handle = node.manager.group(namespace_id).await.unwrap();
                if let Some(leader) = handle.raft.metrics().borrow().current_leader {
                    return leader;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("leader was not elected");
    }

    async fn wait_for_new_leader(nodes: &[&TestNode], previous: NodeId) -> NodeId {
        for _ in 0..100 {
            for node in nodes {
                let handle = node
                    .manager
                    .group(&node.initial_state.namespace_id)
                    .await
                    .unwrap();
                if let Some(leader) = handle.raft.metrics().borrow().current_leader
                    && leader != previous
                {
                    return leader;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("replacement leader was not elected");
    }

    async fn wait_for_revision(node: &TestNode, revision: u64) {
        for _ in 0..100 {
            let handle = node
                .manager
                .group(&node.initial_state.namespace_id)
                .await
                .unwrap();
            if handle.namespace_state().await.current_revision >= revision {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("revision {revision} was not applied");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "release benchmark; run explicitly on documented hardware"]
    async fn release_namespace_benchmark_report() {
        let router = InProcessRouter::default();
        let config = ConsensusConfig {
            snapshot_after_logs: 1_000,
            ..ConsensusConfig::default()
        };
        let a = test_node("node-a", router.clone(), descriptor(1), config.clone()).await;
        let b = test_node("node-b", router.clone(), descriptor(1), config.clone()).await;
        let c = test_node("node-c", router, descriptor(1), config).await;
        let namespace_id = a.initial_state.namespace_id.clone();
        a.manager
            .initialize(&namespace_id, members())
            .await
            .unwrap();
        let leader_id = wait_for_leader(&[&a, &b, &c]).await;
        let leader = if leader_id == raft_node_id("node-a") {
            &a
        } else if leader_id == raft_node_id("node-b") {
            &b
        } else {
            &c
        };
        let started = std::time::Instant::now();
        let mut latencies = Vec::new();
        for index in 0..200u64 {
            let state = leader
                .manager
                .linearizable_namespace_state(&namespace_id)
                .await
                .unwrap();
            let operation = std::time::Instant::now();
            leader
                .manager
                .client_write(
                    &namespace_id,
                    put_command(
                        &state,
                        &format!("bench-{index}"),
                        &format!("key-{index:08}"),
                    ),
                )
                .await
                .unwrap();
            latencies.push(operation.elapsed().as_micros() as u64);
        }
        latencies.sort_unstable();
        let percentile = |percent: usize| latencies[(latencies.len() - 1) * percent / 100];
        let elapsed = started.elapsed();
        let read_started = std::time::Instant::now();
        for _ in 0..1_000 {
            leader
                .manager
                .linearizable_namespace_state(&namespace_id)
                .await
                .unwrap();
        }
        let read_micros = read_started.elapsed().as_micros() as u64 / 1_000;
        println!(
            "{{\"commits\":200,\"throughput_per_second\":{:.2},\"commit_p50_us\":{},\"commit_p95_us\":{},\"commit_p99_us\":{},\"linearizable_read_avg_us\":{}}}",
            200.0 / elapsed.as_secs_f64(),
            percentile(50),
            percentile(95),
            percentile(99),
            read_micros
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn three_node_group_commits_fails_over_snapshots_and_recovers() {
        let router = InProcessRouter::default();
        let config = ConsensusConfig {
            snapshot_after_logs: 3,
            max_logs_after_snapshot: 1,
            ..ConsensusConfig::default()
        };
        let a = test_node("node-a", router.clone(), descriptor(1), config.clone()).await;
        let b = test_node("node-b", router.clone(), descriptor(1), config.clone()).await;
        let c = test_node("node-c", router.clone(), descriptor(1), config.clone()).await;
        let namespace_id = a.initial_state.namespace_id.clone();
        a.manager
            .initialize(&namespace_id, members())
            .await
            .unwrap();
        let first_leader = wait_for_leader(&[&a, &b, &c]).await;
        let leader = if first_leader == raft_node_id("node-a") {
            &a
        } else if first_leader == raft_node_id("node-b") {
            &b
        } else {
            &c
        };
        let state = leader
            .manager
            .group(&namespace_id)
            .await
            .unwrap()
            .namespace_state()
            .await;
        let response = leader
            .manager
            .client_write(&namespace_id, put_command(&state, "request-1", "alpha"))
            .await
            .unwrap();
        assert!(response.data.responses[0].result.is_some());
        let command_metrics = leader.manager.command_metrics().await;
        assert_eq!(command_metrics.len(), 1);
        assert_eq!(command_metrics[0].command_class, "apply_transaction");
        assert_eq!(command_metrics[0].count, 1);
        assert!(command_metrics[0].total_encoded_bytes > 0);
        assert_eq!(
            command_metrics[0].total_encoded_bytes,
            command_metrics[0].max_encoded_bytes
        );
        wait_for_revision(&a, 1).await;
        wait_for_revision(&b, 1).await;
        wait_for_revision(&c, 1).await;

        let leader_handle = leader.manager.group(&namespace_id).await.unwrap();
        leader_handle.raft.trigger().snapshot().await.unwrap();
        for _ in 0..100 {
            let mut state_machine = leader_handle.state_machine.clone();
            if state_machine
                .get_current_snapshot()
                .await
                .unwrap()
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let snapshot = leader_handle
            .state_machine
            .clone()
            .get_current_snapshot()
            .await
            .unwrap()
            .expect("snapshot should be persisted");
        assert!(snapshot.snapshot.get_ref().len() < 512);
        let operational = leader.manager.operational_statuses().await;
        let status = operational
            .iter()
            .find(|status| status.namespace_id == namespace_id)
            .expect("namespace operational status should exist");
        assert_eq!(
            status
                .checkpoint_cid
                .as_ref()
                .expect("checkpoint CID should be reported")
                .codec,
            pepper_types::CODEC_NAMESPACE_CHECKPOINT
        );
        assert!(status.checkpoint_verified);

        leader.manager.shutdown_group(&namespace_id).await.unwrap();
        let survivors = if first_leader == raft_node_id("node-a") {
            [&b, &c]
        } else if first_leader == raft_node_id("node-b") {
            [&a, &c]
        } else {
            [&a, &b]
        };
        let next_leader = wait_for_new_leader(&survivors, first_leader).await;
        let next = if next_leader == raft_node_id("node-a") {
            &a
        } else if next_leader == raft_node_id("node-b") {
            &b
        } else {
            &c
        };
        let state = next
            .manager
            .group(&namespace_id)
            .await
            .unwrap()
            .namespace_state()
            .await;
        next.manager
            .client_write(&namespace_id, put_command(&state, "request-2", "beta"))
            .await
            .unwrap();
        for survivor in survivors {
            wait_for_revision(survivor, 2).await;
        }
        let committed_root = next
            .manager
            .group(&namespace_id)
            .await
            .unwrap()
            .namespace_state()
            .await
            .current_root_cid;

        // Restart every Raft instance from its redb state. The former leader
        // rejoins from revision one and catches revision two from the quorum.
        for survivor in survivors {
            survivor
                .manager
                .shutdown_group(&namespace_id)
                .await
                .unwrap();
        }
        for node in [&a, &b, &c] {
            node.manager
                .start_group(node.initial_state.clone(), node.data_store.clone())
                .await
                .unwrap();
        }
        let _ = wait_for_leader(&[&a, &b, &c]).await;
        wait_for_revision(&a, 2).await;
        wait_for_revision(&b, 2).await;
        wait_for_revision(&c, 2).await;
        for node in [&a, &b, &c] {
            assert_eq!(
                node.manager
                    .group(&namespace_id)
                    .await
                    .unwrap()
                    .namespace_state()
                    .await
                    .current_root_cid,
                committed_root
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    #[ignore = "manual focused protocol smoke; system replacements are NS-002, RAFT-001, and RAFT-002"]
    async fn authenticated_quic_discovers_routes_fails_over_and_stops_without_quorum() {
        let a = network_test_node("rack-a").await;
        let b = network_test_node("rack-b").await;
        let c = network_test_node("rack-c").await;
        let observer = network_test_node("observer").await;
        connect_network_nodes(&[&a, &b, &c, &observer]).await;
        assert_eq!(
            observer
                .manager
                .select_replica_set(&Cid::new(CODEC_RAW, b"placement-seed"), 1024)
                .await
                .unwrap()
                .len(),
            3
        );

        let identities = vec![a.identity.clone(), b.identity.clone(), c.identity.clone()];
        let descriptor =
            NamespaceDescriptor::new(NamespaceKind::Kv, identities.clone(), "creator", "00", 1);
        let mut states = Vec::new();
        for node in [&a, &b, &c] {
            let created = create_namespace(
                &node.data_store,
                descriptor.clone(),
                NamespaceLimits::default(),
                MerkleLimits::default(),
            )
            .await
            .unwrap();
            node.manager
                .start_group(created.state.clone(), node.data_store.clone())
                .await
                .unwrap();
            states.push(created.state);
        }
        let namespace_id = states[0].namespace_id.clone();
        a.manager
            .initialize(&namespace_id, raft_members(&identities).unwrap())
            .await
            .unwrap();

        let nodes = [&a, &b, &c];
        let mut leader_index = None;
        for _ in 0..120 {
            for (index, node) in nodes.iter().enumerate() {
                let metrics = node
                    .manager
                    .group(&namespace_id)
                    .await
                    .unwrap()
                    .raft
                    .metrics()
                    .borrow()
                    .clone();
                if metrics.current_leader == Some(raft_node_id(&node.identity)) {
                    leader_index = Some(index);
                    break;
                }
            }
            if leader_index.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let leader_index = leader_index.expect("QUIC group should elect a leader");
        let response = observer
            .manager
            .routed_write(&namespace_id, put_command(&states[0], "quic-1", "alpha"))
            .await
            .unwrap();
        assert!(response.result.is_some());
        for node in nodes {
            for _ in 0..100 {
                if node
                    .manager
                    .group(&namespace_id)
                    .await
                    .unwrap()
                    .namespace_state()
                    .await
                    .current_revision
                    == 1
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            assert_eq!(
                node.manager
                    .group(&namespace_id)
                    .await
                    .unwrap()
                    .namespace_state()
                    .await
                    .current_revision,
                1
            );
        }
        assert_eq!(observer.manager.group_count().await, 0);

        nodes[leader_index]
            .manager
            .shutdown_group(&namespace_id)
            .await
            .unwrap();
        let survivors = nodes
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != leader_index)
            .map(|(_, node)| *node)
            .collect::<Vec<_>>();
        let mut new_leader = None;
        for _ in 0..120 {
            for node in &survivors {
                let metrics = node
                    .manager
                    .group(&namespace_id)
                    .await
                    .unwrap()
                    .raft
                    .metrics()
                    .borrow()
                    .clone();
                if metrics.current_leader == Some(raft_node_id(&node.identity)) {
                    new_leader = Some(*node);
                    break;
                }
            }
            if new_leader.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let new_leader = new_leader.expect("majority should replace the failed leader");
        let current = new_leader
            .manager
            .group(&namespace_id)
            .await
            .unwrap()
            .namespace_state()
            .await;
        observer
            .manager
            .routed_write(&namespace_id, put_command(&current, "quic-2", "beta"))
            .await
            .unwrap();

        let minority = survivors
            .into_iter()
            .find(|node| node.identity != new_leader.identity)
            .unwrap();
        minority
            .manager
            .shutdown_group(&namespace_id)
            .await
            .unwrap();
        let current = new_leader
            .manager
            .group(&namespace_id)
            .await
            .unwrap()
            .namespace_state()
            .await;
        let result = tokio::time::timeout(
            Duration::from_millis(750),
            new_leader
                .manager
                .client_write(&namespace_id, put_command(&current, "minority", "gamma")),
        )
        .await;
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(
            new_leader
                .manager
                .group(&namespace_id)
                .await
                .unwrap()
                .namespace_state()
                .await
                .current_revision,
            2
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    #[ignore = "manual topology replacement gate; system replacement is RAFT-004"]
    async fn learner_replacement_catches_up_during_writes_and_promotes_safely() {
        let a = network_test_node("replace-a").await;
        let b = network_test_node("replace-b").await;
        let c = network_test_node("replace-c").await;
        let replacement = network_test_node("replace-d").await;
        connect_network_nodes(&[&a, &b, &c, &replacement]).await;
        let original = [&a, &b, &c];
        let identities = original
            .iter()
            .map(|node| node.identity.clone())
            .collect::<Vec<_>>();
        let descriptor =
            NamespaceDescriptor::new(NamespaceKind::Kv, identities.clone(), "creator", "00", 10);
        let mut initial_states = Vec::new();
        for node in original {
            let created = create_namespace(
                &node.data_store,
                descriptor.clone(),
                NamespaceLimits::default(),
                MerkleLimits::default(),
            )
            .await
            .unwrap();
            node.manager
                .start_group(created.state.clone(), node.data_store.clone())
                .await
                .unwrap();
            initial_states.push(created.state);
        }
        let replacement_state = create_namespace(
            &replacement.data_store,
            descriptor,
            NamespaceLimits::default(),
            MerkleLimits::default(),
        )
        .await
        .unwrap()
        .state;
        let namespace_id = initial_states[0].namespace_id.clone();
        a.manager
            .initialize(&namespace_id, raft_members(&identities).unwrap())
            .await
            .unwrap();
        let mut leader = None;
        for _ in 0..120 {
            for node in original {
                let metrics = node
                    .manager
                    .group(&namespace_id)
                    .await
                    .unwrap()
                    .raft
                    .metrics()
                    .borrow()
                    .clone();
                if metrics.current_leader == Some(raft_node_id(&node.identity)) {
                    leader = Some(node);
                    break;
                }
            }
            if leader.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let leader = leader.unwrap();
        let failed = original
            .iter()
            .find(|node| node.identity != leader.identity)
            .unwrap();
        let leader_group = leader.manager.group(&namespace_id).await.unwrap();
        leader
            .manager
            .client_write(
                &namespace_id,
                put_command(&initial_states[0], "seed", "seed"),
            )
            .await
            .unwrap();
        leader_group.raft.trigger().snapshot().await.unwrap();
        for _ in 0..120 {
            let mut state_machine = leader_group.state_machine.clone();
            let snapshot = state_machine.get_current_snapshot().await.unwrap();
            let mut log_store = leader_group.log_store.clone();
            let compacted = log_store
                .get_log_state()
                .await
                .unwrap()
                .last_purged_log_id
                .is_some();
            if let Some(snapshot) = snapshot {
                if compacted {
                    break;
                }
                if let Some(last_log_id) = snapshot.meta.last_log_id {
                    log_store.purge(last_log_id).await.unwrap();
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            leader_group
                .log_store
                .clone()
                .get_log_state()
                .await
                .unwrap()
                .last_purged_log_id
                .is_some()
        );
        let epoch = leader_group.membership_epoch.load(Ordering::Acquire);
        replacement
            .manager
            .prepare_learner_group(
                replacement_state,
                replacement.data_store.clone(),
                epoch,
                identities.clone(),
            )
            .await
            .unwrap();
        assert_ne!(
            format!(
                "{:?}",
                replacement
                    .manager
                    .group(&namespace_id)
                    .await
                    .unwrap()
                    .raft
                    .metrics()
                    .borrow()
                    .state
            ),
            "Leader"
        );

        let writer = leader.manager.clone();
        let write_namespace = namespace_id.clone();
        let base = initial_states[0].clone();
        let writes = tokio::spawn(async move {
            let mut committed = 0;
            for index in 0..8 {
                let command =
                    put_command(&base, &format!("replace-{index}"), &format!("key-{index}"));
                if writer.client_write(&write_namespace, command).await.is_ok() {
                    committed += 1;
                }
            }
            committed
        });
        leader
            .manager
            .replace_replica(&namespace_id, &failed.identity, &replacement.identity)
            .await
            .unwrap();
        let committed = writes.await.unwrap();
        assert_eq!(committed, 8);
        for _ in 0..160 {
            let leader_revision = leader_group.namespace_state().await.current_revision;
            let replacement_revision = replacement
                .manager
                .group(&namespace_id)
                .await
                .unwrap()
                .namespace_state()
                .await
                .current_revision;
            let replacement_is_voter = replacement
                .manager
                .group(&namespace_id)
                .await
                .unwrap()
                .state_machine
                .state
                .read()
                .await
                .membership
                .voter_ids()
                .any(|node_id| node_id == raft_node_id(&replacement.identity));
            if replacement_revision == leader_revision
                && replacement_revision == 9
                && replacement_is_voter
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let replacement_group = replacement.manager.group(&namespace_id).await.unwrap();
        assert_eq!(
            replacement_group.namespace_state().await.current_root_cid,
            leader_group.namespace_state().await.current_root_cid
        );
        let applied = replacement_group.state_machine.state.read().await;
        let voters = applied.membership.voter_ids().collect::<BTreeSet<_>>();
        assert!(voters.contains(&raft_node_id(&replacement.identity)));
        assert!(!voters.contains(&raft_node_id(&failed.identity)));
        assert_eq!(voters.len(), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persisted_vote_log_state_and_namespace_survive_restart() {
        let directory = tempfile::tempdir().unwrap();
        let metadata = Arc::new(
            MetadataStore::open_or_create(directory.path().join("metadata.redb")).unwrap(),
        );
        let data_store = ConsensusDataStore::new(MemoryDataBackend::default());
        let created = create_namespace(
            &data_store,
            descriptor(1),
            NamespaceLimits::default(),
            MerkleLimits::default(),
        )
        .await
        .unwrap();
        let bundle = StorageBundle::open(
            metadata.clone(),
            &created.namespace_id,
            created.state.clone(),
            data_store.clone(),
            1024 * 1024,
        )
        .unwrap();
        let mut log = bundle.log_store.clone();
        let vote = Vote::new(7, raft_node_id("node-a"));
        log.save_vote(&vote).await.unwrap();
        log.save_committed(None).await.unwrap();
        drop(bundle);

        let reopened = StorageBundle::open(
            metadata,
            &created.namespace_id,
            created.state.clone(),
            data_store,
            1024 * 1024,
        )
        .unwrap();
        let mut reopened_log = reopened.log_store.clone();
        assert_eq!(reopened_log.read_vote().await.unwrap(), Some(vote));
        assert_eq!(
            reopened.state_machine.namespace_state().await,
            created.state
        );

        let mut state_machine = reopened.state_machine.clone();
        let valid = state_machine.build_snapshot().await.unwrap();
        let valid_id = valid.meta.snapshot_id.clone();
        let invalid = Box::new(std::io::Cursor::new(b"not a snapshot pointer".to_vec()));
        assert!(
            state_machine
                .install_snapshot(&valid.meta, invalid)
                .await
                .is_err()
        );
        assert_eq!(
            state_machine
                .get_current_snapshot()
                .await
                .unwrap()
                .unwrap()
                .meta
                .snapshot_id,
            valid_id
        );
        let backup = inspect_namespace_backup_records(&state_machine.metadata).unwrap();
        assert_eq!(backup.len(), 1);
        assert_eq!(backup[0].namespace_id, created.namespace_id);
        assert!(backup[0].checkpoint_cid.is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn nodes_host_multiple_isolated_groups() {
        let router = InProcessRouter::default();
        let config = ConsensusConfig {
            max_namespace_groups: 2,
            ..ConsensusConfig::default()
        };
        let a = test_node("node-a", router.clone(), descriptor(1), config.clone()).await;
        let b = test_node("node-b", router.clone(), descriptor(1), config.clone()).await;
        let c = test_node("node-c", router, descriptor(1), config).await;
        let first_id = a.initial_state.namespace_id.clone();

        let mut second_states = Vec::new();
        for node in [&a, &b, &c] {
            let store = ConsensusDataStore::new(MemoryDataBackend::default());
            let second = create_namespace(
                &store,
                descriptor(2),
                NamespaceLimits::default(),
                MerkleLimits::default(),
            )
            .await
            .unwrap();
            node.manager
                .start_group(second.state.clone(), store)
                .await
                .unwrap();
            second_states.push(second.state);
        }
        let second_id = second_states[0].namespace_id.clone();
        a.manager.initialize(&first_id, members()).await.unwrap();
        a.manager.initialize(&second_id, members()).await.unwrap();
        let first_leader = wait_for_leader(&[&a, &b, &c]).await;
        let leader = if first_leader == raft_node_id("node-a") {
            &a
        } else if first_leader == raft_node_id("node-b") {
            &b
        } else {
            &c
        };
        let first_state = leader
            .manager
            .group(&first_id)
            .await
            .unwrap()
            .namespace_state()
            .await;
        leader
            .manager
            .client_write(&first_id, put_command(&first_state, "first", "alpha"))
            .await
            .unwrap();
        for node in [&a, &b, &c] {
            wait_for_revision(node, 1).await;
            assert_eq!(
                node.manager
                    .group(&second_id)
                    .await
                    .unwrap()
                    .namespace_state()
                    .await
                    .current_revision,
                0
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disaster_recovery_requires_confirmation_and_creates_new_epoch() {
        let router = InProcessRouter::default();
        let node = test_node("node-a", router, descriptor(1), ConsensusConfig::default()).await;
        let namespace_id = node.initial_state.namespace_id.clone();
        node.manager.shutdown_group(&namespace_id).await.unwrap();
        assert!(matches!(
            node.manager
                .prepare_disaster_recovery(
                    node.initial_state.clone(),
                    node.data_store.clone(),
                    vec!["node-a".into(), "node-b".into(), "node-c".into()],
                    "no",
                )
                .await,
            Err(ConsensusError::RecoveryConfirmationRequired)
        ));
        let (_, report) = node
            .manager
            .prepare_disaster_recovery(
                node.initial_state.clone(),
                node.data_store.clone(),
                vec!["node-a".into(), "node-b".into(), "node-c".into()],
                "I_ACCEPT_NAMESPACE_FORK_RISK",
            )
            .await
            .unwrap();
        assert!(report.fork_risk);
        assert!(report.new_membership_epoch > report.previous_membership_epoch);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn manager_enforces_assignment_group_and_rate_limits() {
        let router = InProcessRouter::default();
        let config = ConsensusConfig {
            max_namespace_groups: 1,
            max_namespace_write_rate: 1,
            ..ConsensusConfig::default()
        };
        let node = test_node("node-a", router, descriptor(1), config).await;
        assert_eq!(node.manager.group_count().await, 1);

        let other_store = ConsensusDataStore::new(MemoryDataBackend::default());
        let other = create_namespace(
            &other_store,
            descriptor(2),
            NamespaceLimits::default(),
            MerkleLimits::default(),
        )
        .await
        .unwrap();
        assert!(matches!(
            node.manager.start_group(other.state, other_store).await,
            Err(ConsensusError::GroupLimit(1))
        ));

        let namespace_id = &node.initial_state.namespace_id;
        let mut oversized = put_command(&node.initial_state, "large", "alpha");
        oversized.signature_hex = "x".repeat(1024 * 1024);
        assert!(matches!(
            node.manager.client_write(namespace_id, oversized).await,
            Err(ConsensusError::CommandTooLarge(_))
        ));
        {
            let group = node.manager.group(namespace_id).await.unwrap();
            let mut rate = group.rate.lock().await;
            rate.second = unix_seconds_u64();
            rate.count = 1;
        }
        assert!(matches!(
            node.manager
                .client_write(
                    namespace_id,
                    put_command(&node.initial_state, "two", "beta"),
                )
                .await,
            Err(ConsensusError::WriteRateLimited)
        ));
    }
}
