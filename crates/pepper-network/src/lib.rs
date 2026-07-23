// SPDX-License-Identifier: Apache-2.0

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pepper_crypto::{NodeIdentity, derive_node_id, verify_signature};
use pepper_metadata::MetadataStore;
use pepper_types::{CODEC_RAW, Cid, Codec, ProviderRecord, PutBlockResponse};
use prost::Message;
use quinn::{
    ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig,
    VarInt,
};
use redb::{ReadableTable, TableDefinition};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    future::Future,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{
        Arc, Mutex, Once,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};
use thiserror::Error;
use tokio::sync::{Mutex as AsyncMutex, RwLock, Semaphore, mpsc};
use tracing::{debug, info, warn};

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/pepper.v1.rs"));
}

pub type ErasureChunkReceiver = mpsc::Receiver<Vec<u8>>;

const PROTOCOL_VERSION: u32 = 14;
const MAX_FRAME_BYTES: usize = 68 * 1024 * 1024;
pub const MAX_BLOCK_HAS_BATCH_CIDS: usize = 512;
const ERASURE_STREAM_CHUNK_BYTES: usize = 256 * 1024;
const NODES: TableDefinition<&str, &[u8]> = TableDefinition::new("nodes");
const PROVIDERS: TableDefinition<&str, &[u8]> = TableDefinition::new("providers");
const PROVIDERS_BY_CID: TableDefinition<&str, &str> = TableDefinition::new("providers_by_cid");
const KADEMLIA_BUCKET_SIZE: usize = 20;
const KADEMLIA_ALPHA: usize = 3;
const KADEMLIA_LOOKUP_LIMIT: usize = 128;
const REPLAY_BUCKET_SECONDS: i64 = 5;
const REPLAY_WINDOW_SECONDS: i64 = 60;
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);
static RUSTLS_PROVIDER: Once = Once::new();

fn is_raft_method(method: &str) -> bool {
    matches!(
        method,
        "/namespace/raft/vote" | "/namespace/raft/append" | "/namespace/raft/install_snapshot"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RpcClass {
    Raft,
    Control,
    Bulk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportLane {
    Control,
    Bulk,
}

type ConnectionKey = (SocketAddr, RpcClass);
type ConnectionPool = Arc<AsyncMutex<HashMap<ConnectionKey, PooledConnection>>>;
type DialPool = Arc<AsyncMutex<HashMap<ConnectionKey, Arc<AsyncMutex<()>>>>>;

fn rpc_class(method: &str) -> RpcClass {
    if is_raft_method(method) {
        RpcClass::Raft
    } else if is_bulk_method(method) {
        RpcClass::Bulk
    } else {
        RpcClass::Control
    }
}

fn is_bulk_method(method: &str) -> bool {
    matches!(
        method,
        "/block/get_stream"
            | "/block/get_range_stream"
            | "/block/put_replica_stream"
            | "/erasure/encode_parity"
            | "/erasure/store_stripe_stream"
    )
}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("invalid peer address {address}: {source}")]
    InvalidPeerAddress {
        address: String,
        #[source]
        source: std::net::AddrParseError,
    },
    #[error("peer {0} has no authenticated bulk transport address")]
    BulkAddressUnavailable(SocketAddr),
    #[error("QUIC connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("QUIC connect error: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("QUIC write error: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("QUIC stream closed: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error("QUIC read error: {0}")]
    Read(#[from] quinn::ReadError),
    #[error("QUIC read exact error: {0}")]
    ReadExact(#[from] quinn::ReadExactError),
    #[error("protobuf encode/decode error: {0}")]
    ProstDecode(#[from] prost::DecodeError),
    #[error("protobuf encode error: {0}")]
    ProstEncode(#[from] prost::EncodeError),
    #[error("TLS config error: {0}")]
    TlsConfig(String),
    #[error("transport task failed: {0}")]
    TransportTask(String),
    #[error("RPC error {code}: {message}")]
    Rpc { code: String, message: String },
    #[error("invalid peer descriptor: {0}")]
    InvalidDescriptor(String),
    #[error("metadata transaction failed: {0}")]
    Transaction(#[from] Box<redb::TransactionError>),
    #[error("metadata table operation failed: {0}")]
    Table(#[from] Box<redb::TableError>),
    #[error("metadata storage operation failed: {0}")]
    RedbStorage(#[from] Box<redb::StorageError>),
    #[error("metadata commit failed: {0}")]
    Commit(#[from] Box<redb::CommitError>),
    #[error("metadata serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("block service error: {0}")]
    BlockService(String),
    #[error("unsupported RPC method: {0}")]
    UnsupportedMethod(String),
    #[error("unauthenticated RPC request")]
    Unauthenticated,
    #[error("RPC request rate limit exceeded")]
    RateLimited,
    #[error("RPC deadline exceeded")]
    DeadlineExceeded,
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub node_name: String,
    pub listen_addr: SocketAddr,
    pub advertise_addr: SocketAddr,
    pub bulk_listen_addr: SocketAddr,
    pub bulk_advertise_addr: SocketAddr,
    pub bulk_worker_threads: usize,
    pub bulk_inbound_connections: usize,
    pub bulk_streams_per_connection: usize,
    pub bulk_send_window_bytes: u64,
    pub bulk_connection_receive_window_bytes: u64,
    pub bulk_stream_receive_window_bytes: u64,
    pub bulk_request_timeout_seconds: u64,
    pub bulk_max_bytes_per_second: u64,
    pub bulk_bandwidth_burst_bytes: u64,
    pub bootstrap_peers: Vec<String>,
    pub cluster_secret: Option<Vec<u8>>,
    pub requests_per_minute: Option<u64>,
    pub failure_domain: Option<String>,
    pub placement_labels: HashMap<String, String>,
    pub storage_capacity_bytes: u64,
    pub storage_available_bytes: u64,
    pub namespace_consensus_enabled: bool,
    pub namespace_group_capacity: u64,
    pub namespace_group_count: u64,
    pub max_consensus_log_bytes: u64,
    pub max_namespace_write_rate: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockResolution {
    pub payload: Vec<u8>,
    pub source_node_id: String,
    pub route: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcMetric {
    pub peer_id: String,
    pub method: String,
    pub direction: String,
    pub requests: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportMetrics {
    pub control_connections_active: usize,
    pub bulk_connections_active: usize,
    pub control_connections_total: u64,
    pub bulk_connections_total: u64,
    pub control_streams_active: usize,
    pub bulk_streams_active: usize,
    pub bulk_stream_capacity: usize,
    pub bulk_stream_queue_ewma_microseconds: u64,
    pub control_streams_total: u64,
    pub bulk_streams_total: u64,
    pub control_errors_total: u64,
    pub bulk_errors_total: u64,
    pub control_cancellations_total: u64,
    pub bulk_cancellations_total: u64,
    pub bulk_bytes_sent_total: u64,
    pub bulk_bytes_received_total: u64,
    pub bulk_throttle_microseconds_total: u64,
}

#[derive(Default)]
struct TransportCounters {
    control_connections_active: AtomicUsize,
    bulk_connections_active: AtomicUsize,
    control_connections_total: AtomicU64,
    bulk_connections_total: AtomicU64,
    control_streams_active: AtomicUsize,
    bulk_streams_active: AtomicUsize,
    bulk_stream_queue_ewma_microseconds: AtomicU64,
    control_streams_total: AtomicU64,
    bulk_streams_total: AtomicU64,
    control_errors_total: AtomicU64,
    bulk_errors_total: AtomicU64,
    control_cancellations_total: AtomicU64,
    bulk_cancellations_total: AtomicU64,
    bulk_bytes_sent_total: AtomicU64,
    bulk_bytes_received_total: AtomicU64,
    bulk_throttle_microseconds_total: AtomicU64,
}

struct BandwidthState {
    tokens: u64,
    updated_at: std::time::Instant,
}

struct BandwidthLimiter {
    bytes_per_second: u64,
    burst_bytes: u64,
    state: AsyncMutex<BandwidthState>,
    counters: Arc<TransportCounters>,
}

impl BandwidthLimiter {
    fn new(
        bytes_per_second: u64,
        burst_bytes: u64,
        counters: Arc<TransportCounters>,
    ) -> Option<Arc<Self>> {
        (bytes_per_second > 0).then(|| {
            Arc::new(Self {
                bytes_per_second,
                burst_bytes,
                state: AsyncMutex::new(BandwidthState {
                    tokens: burst_bytes,
                    updated_at: std::time::Instant::now(),
                }),
                counters,
            })
        })
    }

    async fn reserve(&self, bytes: usize) {
        let bytes = (bytes as u64).min(self.burst_bytes);
        let mut state = self.state.lock().await;
        let now = std::time::Instant::now();
        let replenished = (now.duration_since(state.updated_at).as_nanos()
            * u128::from(self.bytes_per_second)
            / 1_000_000_000)
            .min(u128::from(u64::MAX)) as u64;
        state.tokens = state
            .tokens
            .saturating_add(replenished)
            .min(self.burst_bytes);
        state.updated_at = now;
        if state.tokens >= bytes {
            state.tokens -= bytes;
            return;
        }
        let missing = bytes - state.tokens;
        state.tokens = 0;
        let wait_nanos = u128::from(missing)
            .saturating_mul(1_000_000_000)
            .div_ceil(u128::from(self.bytes_per_second))
            .min(u128::from(u64::MAX)) as u64;
        let wait = std::time::Duration::from_nanos(wait_nanos);
        tokio::time::sleep(wait).await;
        state.updated_at = std::time::Instant::now();
        self.counters.bulk_throttle_microseconds_total.fetch_add(
            wait.as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
    }
}

struct BulkRuntime {
    handle: tokio::runtime::Handle,
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
}

impl BulkRuntime {
    fn new(worker_threads: usize) -> Result<Self, NetworkError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(worker_threads)
            .thread_name("pepper-bulk")
            .build()
            .map_err(|error| NetworkError::TlsConfig(error.to_string()))?;
        Ok(Self {
            handle: runtime.handle().clone(),
            runtime: Mutex::new(Some(runtime)),
        })
    }

    fn spawn<F>(&self, future: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.handle.spawn(future);
    }
}

impl Drop for BulkRuntime {
    fn drop(&mut self) {
        let runtime = self
            .runtime
            .lock()
            .expect("bulk runtime lock poisoned")
            .take();
        if let Some(runtime) = runtime {
            // Tokio forbids dropping a runtime from another runtime's async
            // context. Final shutdown hands ownership to a plain OS thread.
            if let Ok(handle) = std::thread::Builder::new()
                .name("pepper-bulk-shutdown".to_string())
                .spawn(move || drop(runtime))
            {
                let _ = handle.join();
            }
        }
    }
}

struct ActiveCounterGuard<'a>(&'a AtomicUsize);

impl<'a> ActiveCounterGuard<'a> {
    fn enter(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

impl Drop for ActiveCounterGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Default)]
struct RpcMetricAccumulator {
    requests: u64,
    request_bytes: u64,
    response_bytes: u64,
    errors: u64,
}

type RpcMetricMap = BTreeMap<(String, String, String), RpcMetricAccumulator>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerStatus {
    pub node_id: String,
    pub name: String,
    pub addresses: Vec<String>,
    #[serde(default)]
    pub bulk_addresses: Vec<String>,
    pub last_seen_unix_seconds: i64,
    pub connected: bool,
    pub failure_domain: Option<String>,
    pub placement_labels: HashMap<String, String>,
    pub storage_capacity_bytes: u64,
    pub storage_available_bytes: u64,
    pub namespace_consensus_enabled: bool,
    pub namespace_group_capacity: u64,
    pub namespace_group_count: u64,
    pub max_consensus_log_bytes: u64,
    pub max_namespace_write_rate: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredPeer {
    node_id: String,
    name: String,
    addresses: Vec<String>,
    #[serde(default)]
    bulk_addresses: Vec<String>,
    public_key_hex: String,
    #[serde(default)]
    tls_certificate_digest_hex: String,
    last_seen_unix_seconds: i64,
    failure_domain: Option<String>,
    #[serde(default)]
    placement_labels: HashMap<String, String>,
    #[serde(default)]
    storage_capacity_bytes: u64,
    #[serde(default)]
    storage_available_bytes: u64,
    #[serde(default)]
    namespace_consensus_enabled: bool,
    #[serde(default)]
    namespace_group_capacity: u64,
    #[serde(default)]
    namespace_group_count: u64,
    #[serde(default)]
    max_consensus_log_bytes: u64,
    #[serde(default)]
    max_namespace_write_rate: u64,
}

#[async_trait]
pub trait NetworkBlockService: Send + Sync + 'static {
    async fn has_block(&self, cid: &Cid) -> Result<bool, NetworkError>;
    async fn has_blocks(&self, cids: &[Cid]) -> Result<Vec<bool>, NetworkError> {
        let mut present = Vec::with_capacity(cids.len());
        for cid in cids {
            present.push(self.has_block(cid).await?);
        }
        Ok(present)
    }
    async fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, NetworkError>;
    async fn get_block_range(
        &self,
        cid: &Cid,
        start: u64,
        end: u64,
    ) -> Result<Vec<u8>, NetworkError> {
        let payload = self.get_block(cid).await?;
        let start = usize::try_from(start).map_err(|_| {
            NetworkError::BlockService("block range start does not fit usize".to_string())
        })?;
        let end = usize::try_from(end).map_err(|_| {
            NetworkError::BlockService("block range end does not fit usize".to_string())
        })?;
        payload
            .get(start..end)
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                NetworkError::BlockService("block range exceeds stored payload".to_string())
            })
    }
    async fn put_replica(
        &self,
        codec: Codec,
        payload: Vec<u8>,
    ) -> Result<PutBlockResponse, NetworkError>;

    async fn put_verified_replica(
        &self,
        codec: Codec,
        expected_cid: &Cid,
        payload: Vec<u8>,
    ) -> Result<PutBlockResponse, NetworkError> {
        let put = self.put_replica(codec, payload).await?;
        if put.cid != *expected_cid {
            return Err(NetworkError::BlockService(
                "stored replica does not match preverified CID".to_string(),
            ));
        }
        Ok(put)
    }

    async fn put_encoded_verified_replica(
        &self,
        _codec: Codec,
        _expected_cid: &Cid,
        _logical_size: u64,
        _payload: Vec<u8>,
    ) -> Result<PutBlockResponse, NetworkError> {
        Err(NetworkError::BlockService(
            "encoded replica storage is unsupported".to_string(),
        ))
    }
}

#[async_trait]
pub trait NetworkErasureService: Send + Sync + 'static {
    async fn push_repair_inventory(
        &self,
        authenticated_node: &str,
        inventory_json: String,
    ) -> Result<(), NetworkError>;

    async fn execute_repair(
        &self,
        authenticated_node: &str,
        task_json: String,
    ) -> Result<proto::RepairExecuteResponse, NetworkError>;

    async fn cleanup_repair_extra(
        &self,
        authenticated_node: &str,
        exception_json: String,
    ) -> Result<bool, NetworkError>;

    async fn encode_parity(
        &self,
        authenticated_node: &str,
        request: proto::ErasureTransferRequest,
    ) -> Result<proto::ErasureTransferResponse, NetworkError>;

    async fn store_stripe_stream(
        &self,
        authenticated_node: &str,
        request: proto::ErasureTransferRequest,
        chunks: ErasureChunkReceiver,
    ) -> Result<proto::ErasureTransferResponse, NetworkError>;
}

#[async_trait]
pub trait NetworkPinService: Send + Sync + 'static {
    async fn apply(
        &self,
        authenticated_node: &str,
        pin_record_json: String,
    ) -> Result<(), NetworkError>;
}

#[async_trait]
pub trait NetworkNamespaceAliasService: Send + Sync + 'static {
    async fn resolve(
        &self,
        authenticated_node: &str,
        alias: String,
    ) -> Result<Option<String>, NetworkError>;
    async fn list(&self, authenticated_node: &str) -> Result<Vec<(String, String)>, NetworkError>;
}

#[async_trait]
pub trait NetworkNamespaceService: Send + Sync + 'static {
    async fn discover(
        &self,
        authenticated_node: &str,
        namespace_id: String,
    ) -> Result<Vec<proto::NamespaceDiscoveryRecord>, NetworkError>;
    async fn announce(
        &self,
        authenticated_node: &str,
        record: proto::NamespaceDiscoveryRecord,
    ) -> Result<(), NetworkError>;
    async fn raft_vote(
        &self,
        authenticated_node: &str,
        request: proto::NamespaceRaftRequest,
    ) -> Result<Vec<u8>, NetworkError>;
    async fn raft_append(
        &self,
        authenticated_node: &str,
        request: proto::NamespaceRaftRequest,
    ) -> Result<Vec<u8>, NetworkError>;
    async fn raft_install_snapshot(
        &self,
        authenticated_node: &str,
        request: proto::NamespaceRaftRequest,
    ) -> Result<Vec<u8>, NetworkError>;
    async fn forward(
        &self,
        authenticated_node: &str,
        request: proto::NamespaceForwardRequest,
    ) -> Result<proto::NamespaceForwardResponse, NetworkError>;
    async fn sqlite_writer(
        &self,
        authenticated_node: &str,
        request: proto::NamespaceSqliteWriterRequest,
    ) -> Result<proto::NamespaceSqliteWriterResponse, NetworkError>;
    async fn state(
        &self,
        authenticated_node: &str,
        request: proto::NamespaceStateRequest,
    ) -> Result<proto::NamespaceStateResponse, NetworkError>;
    async fn bootstrap(
        &self,
        authenticated_node: &str,
        request: proto::NamespaceBootstrapRequest,
    ) -> Result<proto::NamespaceBootstrapResponse, NetworkError>;
}

#[async_trait]
pub trait NetworkComputeService: Send + Sync + 'static {
    async fn offer(&self, spec_json: String) -> Result<proto::ComputeOfferResponse, NetworkError>;
    async fn submit(
        &self,
        job_id: String,
        spec_json: String,
    ) -> Result<proto::ComputeSubmitResponse, NetworkError>;
    async fn status(&self, job_id: String) -> Result<proto::ComputeStatusResponse, NetworkError>;
    async fn logs(&self, job_id: String) -> Result<proto::ComputeLogsResponse, NetworkError>;
    async fn cancel(&self, job_id: String) -> Result<proto::ComputeCancelResponse, NetworkError>;
}

#[derive(Clone)]
pub struct NetworkHandle {
    /// Authenticated control/Raft endpoint. Bulk bytes never use this socket.
    endpoint: Endpoint,
    /// Dedicated bulk endpoint with independent UDP queues and flow control.
    bulk_endpoint: Endpoint,
    bulk_runtime: Arc<BulkRuntime>,
    bulk_client_config: ClientConfig,
    bulk_request_timeout: std::time::Duration,
    bulk_streams_per_connection: usize,
    /// NICs are full-duplex: ingress and egress each receive the configured
    /// bulk budget. Sharing one token bucket here made relay and parity nodes
    /// benchmark like half-duplex links and cut a streaming pipeline's ceiling
    /// in half.
    bulk_send_bandwidth: Option<Arc<BandwidthLimiter>>,
    bulk_receive_bandwidth: Option<Arc<BandwidthLimiter>>,
    descriptor: Arc<ArcSwap<proto::NodeDescriptor>>,
    identity: NodeIdentity,
    metadata: Arc<MetadataStore>,
    peers: Arc<RwLock<HashMap<String, PeerStatus>>>,
    /// Current TLS incarnation for each stable node identity. ArcSwap keeps
    /// the ordinary pooled-I/O check lock-free while allowing a restarted
    /// node's fresh signed descriptor to invalidate stale QUIC connections.
    peer_tls_digests: Arc<ArcSwap<HashMap<String, String>>>,
    compute_service: Arc<RwLock<Option<Arc<dyn NetworkComputeService>>>>,
    erasure_service: Arc<RwLock<Option<Arc<dyn NetworkErasureService>>>>,
    pin_service: Arc<RwLock<Option<Arc<dyn NetworkPinService>>>>,
    namespace_alias_service: Arc<RwLock<Option<Arc<dyn NetworkNamespaceAliasService>>>>,
    namespace_service: Arc<RwLock<Option<Arc<dyn NetworkNamespaceService>>>>,
    cluster_secret: Option<Arc<[u8]>>,
    requests_per_minute: Option<u64>,
    rate_limits: Arc<Mutex<HashMap<String, RateLimitBucket>>>,
    bulk_rate_limits: Arc<Mutex<HashMap<String, RateLimitBucket>>>,
    seen_requests: Arc<Mutex<ReplayWindow>>,
    bulk_seen_requests: Arc<Mutex<ReplayWindow>>,
    replay_capacity: usize,
    inbound_connections: Arc<Semaphore>,
    inbound_bulk_connections: Arc<Semaphore>,
    outbound_replica_streams: Arc<Semaphore>,
    outbound_replica_stream_capacity: usize,
    outbound_control_connections: ConnectionPool,
    outbound_bulk_connections: ConnectionPool,
    outbound_control_dials: DialPool,
    outbound_bulk_dials: DialPool,
    rpc_metrics: Arc<Mutex<RpcMetricMap>>,
    bulk_rpc_metrics: Arc<Mutex<RpcMetricMap>>,
    logged_rpc_failures: Arc<Mutex<HashSet<(String, String)>>>,
    transport_counters: Arc<TransportCounters>,
}

#[derive(Clone)]
struct PooledConnection {
    connection: Connection,
    peer_node_id: String,
    peer_tls_certificate_digest_hex: String,
}

#[derive(Clone)]
struct StreamContext {
    block_service: Arc<dyn NetworkBlockService>,
    authenticated_node: Arc<RwLock<Option<String>>>,
    data_stream_slots: Arc<Semaphore>,
    raft_stream_slots: Arc<Semaphore>,
    lane: TransportLane,
}

#[derive(Debug, Clone)]
struct RateLimitBucket {
    window_start_unix_seconds: i64,
    count: u64,
}

#[derive(Debug, Default)]
struct ReplayWindow {
    buckets: BTreeMap<i64, HashSet<[u8; 16]>>,
    entries: usize,
}

impl ReplayWindow {
    fn admit(&mut self, now: i64, key: [u8; 16], capacity: usize) -> Result<(), NetworkError> {
        let bucket = now.div_euclid(REPLAY_BUCKET_SECONDS);
        let oldest = (now - REPLAY_WINDOW_SECONDS).div_euclid(REPLAY_BUCKET_SECONDS);
        let expired = self
            .buckets
            .range(..oldest)
            .map(|(bucket, _)| *bucket)
            .collect::<Vec<_>>();
        for bucket in expired {
            if let Some(entries) = self.buckets.remove(&bucket) {
                self.entries = self.entries.saturating_sub(entries.len());
            }
        }
        if self.buckets.values().any(|entries| entries.contains(&key)) {
            return Err(NetworkError::Unauthenticated);
        }
        if self.entries >= capacity {
            return Err(NetworkError::RateLimited);
        }
        self.buckets.entry(bucket).or_default().insert(key);
        self.entries += 1;
        Ok(())
    }
}

impl NetworkHandle {
    pub fn local_transport_addr(&self) -> Option<SocketAddr> {
        self.endpoint.local_addr().ok()
    }

    pub fn local_bulk_transport_addr(&self) -> Option<SocketAddr> {
        self.bulk_endpoint.local_addr().ok()
    }

    /// Clone the shared routing/authentication state with an independent
    /// client UDP endpoint, outbound connection cache, and replica-stream
    /// budget. Per-core data owners use distinct source ports so NIC RSS can
    /// distribute their flows, and never share the control plane's socket or
    /// connection-pool mutex on ordinary I/O.
    pub fn isolated_data_endpoint(&self, replica_streams: usize) -> Result<Self, NetworkError> {
        let local = self
            .endpoint
            .local_addr()
            .map_err(|error| NetworkError::TlsConfig(error.to_string()))?;
        let bind = if local.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let mut endpoint =
            Endpoint::client(bind).map_err(|error| NetworkError::TlsConfig(error.to_string()))?;
        endpoint.set_default_client_config(client_config(TransportProfile::Control)?);
        let mut bulk_endpoint =
            Endpoint::client(bind).map_err(|error| NetworkError::TlsConfig(error.to_string()))?;
        bulk_endpoint.set_default_client_config(self.bulk_client_config.clone());
        let mut isolated = self.clone();
        isolated.endpoint = endpoint;
        isolated.bulk_endpoint = bulk_endpoint;
        isolated.outbound_replica_streams = Arc::new(Semaphore::new(replica_streams.max(1)));
        isolated.outbound_replica_stream_capacity = replica_streams.max(1);
        isolated.outbound_control_connections = Arc::new(AsyncMutex::new(HashMap::new()));
        isolated.outbound_bulk_connections = Arc::new(AsyncMutex::new(HashMap::new()));
        isolated.outbound_control_dials = Arc::new(AsyncMutex::new(HashMap::new()));
        isolated.outbound_bulk_dials = Arc::new(AsyncMutex::new(HashMap::new()));
        Ok(isolated)
    }

    pub async fn start(
        config: NetworkConfig,
        identity: NodeIdentity,
        metadata: Arc<MetadataStore>,
        block_service: Arc<dyn NetworkBlockService>,
    ) -> Result<Self, NetworkError> {
        let (mut server_config, tls_certificate_digest_hex) = server_config()?;
        server_config.transport_config(transport_config(TransportProfile::Control)?);
        let mut bulk_server_config = server_config.clone();
        bulk_server_config.transport_config(transport_config(TransportProfile::Bulk {
            send_window_bytes: config.bulk_send_window_bytes,
            connection_receive_window_bytes: config.bulk_connection_receive_window_bytes,
            stream_receive_window_bytes: config.bulk_stream_receive_window_bytes,
            streams_per_connection: config.bulk_streams_per_connection,
        })?);
        let mut endpoint = Endpoint::server(server_config, config.listen_addr)
            .map_err(|error| NetworkError::TlsConfig(error.to_string()))?;
        endpoint.set_default_client_config(client_config(TransportProfile::Control)?);
        let bulk_runtime = Arc::new(BulkRuntime::new(config.bulk_worker_threads)?);
        // Quinn installs its UDP driver on the current Tokio runtime while the
        // endpoint is constructed. Enter the dedicated runtime so packet I/O,
        // not merely request handlers, remains off the control runtime.
        let mut bulk_endpoint = {
            let _runtime = bulk_runtime.handle.enter();
            Endpoint::server(bulk_server_config, config.bulk_listen_addr)
                .map_err(|error| NetworkError::TlsConfig(error.to_string()))?
        };
        let bulk_client_config = client_config(TransportProfile::Bulk {
            send_window_bytes: config.bulk_send_window_bytes,
            connection_receive_window_bytes: config.bulk_connection_receive_window_bytes,
            stream_receive_window_bytes: config.bulk_stream_receive_window_bytes,
            streams_per_connection: config.bulk_streams_per_connection,
        })?;
        bulk_endpoint.set_default_client_config(bulk_client_config.clone());

        let descriptor = make_descriptor(&config, &identity, tls_certificate_digest_hex);
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let peer_tls_digests = Arc::new(ArcSwap::from_pointee(HashMap::new()));
        let replay_capacity = config
            .requests_per_minute
            .unwrap_or(100_000)
            .clamp(100_000, 2_000_000) as usize;
        let transport_counters = Arc::new(TransportCounters::default());
        let bulk_send_bandwidth = BandwidthLimiter::new(
            config.bulk_max_bytes_per_second,
            config.bulk_bandwidth_burst_bytes,
            transport_counters.clone(),
        );
        let bulk_receive_bandwidth = BandwidthLimiter::new(
            config.bulk_max_bytes_per_second,
            config.bulk_bandwidth_burst_bytes,
            transport_counters.clone(),
        );
        let handle = Self {
            endpoint,
            bulk_endpoint,
            bulk_runtime,
            bulk_client_config,
            bulk_request_timeout: std::time::Duration::from_secs(
                config.bulk_request_timeout_seconds,
            ),
            bulk_streams_per_connection: config.bulk_streams_per_connection,
            bulk_send_bandwidth,
            bulk_receive_bandwidth,
            descriptor: Arc::new(ArcSwap::from_pointee(descriptor)),
            identity,
            metadata,
            peers,
            peer_tls_digests,
            compute_service: Arc::new(RwLock::new(None)),
            erasure_service: Arc::new(RwLock::new(None)),
            pin_service: Arc::new(RwLock::new(None)),
            namespace_alias_service: Arc::new(RwLock::new(None)),
            namespace_service: Arc::new(RwLock::new(None)),
            cluster_secret: config.cluster_secret.map(Arc::from),
            requests_per_minute: config.requests_per_minute,
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            bulk_rate_limits: Arc::new(Mutex::new(HashMap::new())),
            seen_requests: Arc::new(Mutex::new(ReplayWindow::default())),
            bulk_seen_requests: Arc::new(Mutex::new(ReplayWindow::default())),
            replay_capacity,
            inbound_connections: Arc::new(Semaphore::new(256)),
            inbound_bulk_connections: Arc::new(Semaphore::new(config.bulk_inbound_connections)),
            outbound_replica_streams: Arc::new(Semaphore::new(8)),
            outbound_replica_stream_capacity: 8,
            outbound_control_connections: Arc::new(AsyncMutex::new(HashMap::new())),
            outbound_bulk_connections: Arc::new(AsyncMutex::new(HashMap::new())),
            outbound_control_dials: Arc::new(AsyncMutex::new(HashMap::new())),
            outbound_bulk_dials: Arc::new(AsyncMutex::new(HashMap::new())),
            rpc_metrics: Arc::new(Mutex::new(BTreeMap::new())),
            bulk_rpc_metrics: Arc::new(Mutex::new(BTreeMap::new())),
            logged_rpc_failures: Arc::new(Mutex::new(HashSet::new())),
            transport_counters,
        };

        handle.load_persisted_peers().await?;
        handle.prune_routing_table().await;
        let mut bootstrap_peers = config.bootstrap_peers;
        bootstrap_peers.extend(
            handle
                .peers()
                .await
                .into_iter()
                .flat_map(|peer| peer.addresses),
        );
        bootstrap_peers.sort();
        bootstrap_peers.dedup();
        handle.spawn_accept_loop(block_service.clone(), TransportLane::Control);
        handle.spawn_accept_loop(block_service, TransportLane::Bulk);
        handle.spawn_bootstrap(bootstrap_peers);
        handle.spawn_gossip_loop();
        Ok(handle)
    }

    pub fn shutdown(&self) {
        self.endpoint.close(0u32.into(), b"agent shutdown");
        self.bulk_endpoint
            .close(0u32.into(), b"agent bulk shutdown");
    }

    pub async fn set_compute_service(&self, service: Arc<dyn NetworkComputeService>) {
        *self.compute_service.write().await = Some(service);
    }

    pub async fn set_erasure_service(&self, service: Arc<dyn NetworkErasureService>) {
        *self.erasure_service.write().await = Some(service);
    }

    pub async fn set_pin_service(&self, service: Arc<dyn NetworkPinService>) {
        *self.pin_service.write().await = Some(service);
    }

    pub async fn set_namespace_alias_service(
        &self,
        service: Arc<dyn NetworkNamespaceAliasService>,
    ) {
        *self.namespace_alias_service.write().await = Some(service);
    }

    pub async fn set_namespace_service(&self, service: Arc<dyn NetworkNamespaceService>) {
        *self.namespace_service.write().await = Some(service);
    }

    pub fn local_descriptor(&self) -> proto::NodeDescriptor {
        self.descriptor.load().as_ref().clone()
    }

    pub fn update_storage_advertisement(&self, capacity_bytes: u64, available_bytes: u64) {
        self.descriptor.rcu(|current| {
            let mut descriptor = current.as_ref().clone();
            descriptor.storage_capacity_bytes = capacity_bytes;
            descriptor.storage_available_bytes = available_bytes;
            descriptor.signature_hex.clear();
            let signature = self
                .identity
                .sign(&descriptor_signature_payload(&descriptor));
            descriptor.signature_hex = hex::encode(signature);
            Arc::new(descriptor)
        });
    }

    pub fn update_namespace_group_count(&self, group_count: u64) {
        self.descriptor.rcu(|current| {
            let mut descriptor = current.as_ref().clone();
            descriptor.namespace_group_count = group_count;
            descriptor.signature_hex.clear();
            let signature = self
                .identity
                .sign(&descriptor_signature_payload(&descriptor));
            descriptor.signature_hex = hex::encode(signature);
            Arc::new(descriptor)
        });
    }

    pub fn rpc_metrics(&self) -> Vec<RpcMetric> {
        let metric = |((peer_id, method, direction), metric): (
            &(String, String, String),
            &RpcMetricAccumulator,
        )| RpcMetric {
            peer_id: peer_id.clone(),
            method: method.clone(),
            direction: direction.clone(),
            requests: metric.requests,
            request_bytes: metric.request_bytes,
            response_bytes: metric.response_bytes,
            errors: metric.errors,
        };
        let mut metrics = self
            .rpc_metrics
            .lock()
            .expect("RPC metrics lock poisoned")
            .iter()
            .take(512)
            .map(metric)
            .collect::<Vec<_>>();
        metrics.extend(
            self.bulk_rpc_metrics
                .lock()
                .expect("bulk RPC metrics lock poisoned")
                .iter()
                .take(512)
                .map(metric),
        );
        metrics
    }

    pub fn transport_metrics(&self) -> TransportMetrics {
        let counters = &self.transport_counters;
        let outbound_active = self
            .outbound_replica_stream_capacity
            .saturating_sub(self.outbound_replica_streams.available_permits());
        TransportMetrics {
            control_connections_active: counters.control_connections_active.load(Ordering::Relaxed),
            bulk_connections_active: counters.bulk_connections_active.load(Ordering::Relaxed),
            control_connections_total: counters.control_connections_total.load(Ordering::Relaxed),
            bulk_connections_total: counters.bulk_connections_total.load(Ordering::Relaxed),
            control_streams_active: counters.control_streams_active.load(Ordering::Relaxed),
            bulk_streams_active: counters
                .bulk_streams_active
                .load(Ordering::Relaxed)
                .saturating_add(outbound_active),
            bulk_stream_capacity: self.outbound_replica_stream_capacity,
            bulk_stream_queue_ewma_microseconds: counters
                .bulk_stream_queue_ewma_microseconds
                .load(Ordering::Relaxed),
            control_streams_total: counters.control_streams_total.load(Ordering::Relaxed),
            bulk_streams_total: counters.bulk_streams_total.load(Ordering::Relaxed),
            control_errors_total: counters.control_errors_total.load(Ordering::Relaxed),
            bulk_errors_total: counters.bulk_errors_total.load(Ordering::Relaxed),
            control_cancellations_total: counters
                .control_cancellations_total
                .load(Ordering::Relaxed),
            bulk_cancellations_total: counters.bulk_cancellations_total.load(Ordering::Relaxed),
            bulk_bytes_sent_total: counters.bulk_bytes_sent_total.load(Ordering::Relaxed),
            bulk_bytes_received_total: counters.bulk_bytes_received_total.load(Ordering::Relaxed),
            bulk_throttle_microseconds_total: counters
                .bulk_throttle_microseconds_total
                .load(Ordering::Relaxed),
        }
    }

    fn record_rpc(
        &self,
        peer_id: &str,
        method: &str,
        direction: &str,
        request_bytes: usize,
        response_bytes: usize,
        error: bool,
    ) {
        let peer_id = if peer_id.len() == 64 && peer_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            peer_id
        } else {
            "unauthenticated"
        };
        let method = normalize_rpc_method(method);
        let metrics = if is_bulk_method(method) {
            &self.bulk_rpc_metrics
        } else {
            &self.rpc_metrics
        };
        let mut metrics = metrics.lock().expect("RPC metrics lock poisoned");
        if metrics.len() >= 512
            && !metrics.contains_key(&(
                peer_id.to_string(),
                method.to_string(),
                direction.to_string(),
            ))
        {
            return;
        }
        let metric = metrics
            .entry((
                peer_id.to_string(),
                method.to_string(),
                direction.to_string(),
            ))
            .or_default();
        metric.requests = metric.requests.saturating_add(1);
        metric.request_bytes = metric
            .request_bytes
            .saturating_add(request_bytes.min(u64::MAX as usize) as u64);
        metric.response_bytes = metric
            .response_bytes
            .saturating_add(response_bytes.min(u64::MAX as usize) as u64);
        metric.errors = metric.errors.saturating_add(u64::from(error));
    }

    fn log_rpc_failure_once(&self, method: &str, error: &NetworkError) {
        let reason = error.to_string();
        let mut logged = self
            .logged_rpc_failures
            .lock()
            .expect("RPC failure log lock poisoned");
        if logged.len() < 64 && logged.insert((method.to_string(), reason)) {
            warn!(method, %error, "RPC request failed");
        }
    }

    pub fn local_provider_record(&self, cid: &Cid) -> ProviderRecord {
        let descriptor = self.local_descriptor();
        make_provider_record(&descriptor, &self.identity, cid)
    }

    pub fn verify_node_signature(
        &self,
        node_id: &str,
        message: &[u8],
        signature_hex: &str,
    ) -> Result<(), NetworkError> {
        let public_key_hex = if node_id == self.local_descriptor().node_id {
            self.local_descriptor().public_key_hex
        } else {
            self.peer_public_key_hex(node_id)?.ok_or_else(|| {
                NetworkError::InvalidDescriptor(format!("unknown signing node {node_id}"))
            })?
        };
        let public_key: [u8; 32] = hex::decode(public_key_hex)
            .map_err(|error| NetworkError::InvalidDescriptor(error.to_string()))?
            .try_into()
            .map_err(|_| {
                NetworkError::InvalidDescriptor("public key must be 32 bytes".to_string())
            })?;
        let signature: [u8; 64] = hex::decode(signature_hex)
            .map_err(|error| NetworkError::InvalidDescriptor(error.to_string()))?
            .try_into()
            .map_err(|_| {
                NetworkError::InvalidDescriptor("signature must be 64 bytes".to_string())
            })?;
        if verify_signature(&public_key, message, &signature) {
            Ok(())
        } else {
            Err(NetworkError::InvalidDescriptor(
                "node signature verification failed".to_string(),
            ))
        }
    }

    pub fn persist_provider_record(&self, record: &ProviderRecord) -> Result<(), NetworkError> {
        self.validate_provider_record(record)?;
        persist_provider_record(&self.metadata, record)
    }

    pub fn persist_provider_records(&self, records: &[ProviderRecord]) -> Result<(), NetworkError> {
        for record in records {
            self.validate_provider_record(record)?;
        }
        persist_provider_records(&self.metadata, records)
    }

    pub fn local_provider_records(&self, cid: &Cid) -> Result<Vec<ProviderRecord>, NetworkError> {
        provider_records_for_cid(&self.metadata, cid)
    }

    pub async fn announce_provider_to_peers(&self, record: &ProviderRecord) {
        for peer in self.peers().await {
            for address in peer.addresses {
                let Ok(addr) = address.parse::<SocketAddr>() else {
                    continue;
                };
                if let Err(error) = self.announce_provider(addr, record).await {
                    debug!(%addr, %error, "provider announcement failed");
                }
            }
        }
    }

    pub async fn announce_providers_to_peers(&self, records: &[ProviderRecord]) {
        if records.is_empty() {
            return;
        }
        let records = Arc::new(records.to_vec());
        let mut announcements = tokio::task::JoinSet::new();
        for peer in self.peers().await {
            let Some(address) = sorted_routable_addresses(peer.addresses)
                .into_iter()
                .find_map(|address| address.parse::<SocketAddr>().ok())
            else {
                continue;
            };
            let network = self.clone();
            let records = records.clone();
            announcements.spawn(async move {
                if let Err(error) = network.announce_provider_batch(address, &records).await {
                    debug!(%address, %error, "provider batch announcement failed");
                }
            });
        }
        while announcements.join_next().await.is_some() {}
    }

    pub fn cleanup_expired_provider_records(&self) -> Result<usize, NetworkError> {
        cleanup_expired_provider_records(&self.metadata)
    }

    pub async fn find_providers(&self, cid: &Cid) -> Result<Vec<ProviderRecord>, NetworkError> {
        let mut providers = self.local_provider_records(cid)?;
        let mut queue = routing_queue_for_cid(self.peers().await, cid);
        let mut queued = queue.iter().cloned().collect::<HashSet<_>>();
        let mut queried = HashSet::<String>::new();
        let mut active = tokio::task::JoinSet::new();

        loop {
            while active.len() < KADEMLIA_ALPHA
                && queried.len() < KADEMLIA_LOOKUP_LIMIT
                && let Some(address) = queue.pop_front()
            {
                queued.remove(&address);
                if !queried.insert(address.clone()) {
                    continue;
                }
                let this = self.clone();
                let cid = cid.clone();
                active.spawn(async move { this.query_dht_peer(address, cid).await });
            }

            let Some(joined) = active.join_next().await else {
                break;
            };
            match joined {
                Ok(Ok((remote_providers, remote_peers))) => {
                    providers.extend(remote_providers);
                    for address in routing_addresses_for_cid(remote_peers, cid) {
                        if !queried.contains(&address) && queued.insert(address.clone()) {
                            insert_routing_candidate(&mut queue, address, cid);
                        }
                    }
                }
                Ok(Err(error)) => debug!(%error, "DHT peer query failed"),
                Err(error) => debug!(%error, "DHT peer query task failed"),
            }
        }

        providers.retain(|record| record.expires_at_unix_seconds > unix_seconds());
        providers.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        providers.dedup_by(|left, right| left.node_id == right.node_id && left.cid == right.cid);
        Ok(providers)
    }

    async fn query_dht_peer(
        &self,
        address: String,
        cid: Cid,
    ) -> Result<(Vec<ProviderRecord>, Vec<PeerStatus>), NetworkError> {
        let addr =
            address
                .parse::<SocketAddr>()
                .map_err(|source| NetworkError::InvalidPeerAddress {
                    address: address.clone(),
                    source,
                })?;
        let providers = match self.block_providers(addr, &cid).await {
            Ok(providers) => providers,
            Err(error) => {
                debug!(%addr, %error, "DHT provider lookup failed");
                Vec::new()
            }
        };
        let peers = match self.node_peers(addr).await {
            Ok(peers) => peers,
            Err(error) => {
                debug!(%addr, %error, "DHT peer lookup failed");
                Vec::new()
            }
        };
        Ok((providers, peers))
    }

    pub async fn peers(&self) -> Vec<PeerStatus> {
        let mut peers = self
            .peers
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        peers
    }

    pub async fn mark_peer_disconnected(&self, node_id: &str) {
        if let Some(peer) = self.peers.write().await.get_mut(node_id) {
            peer.connected = false;
        }
    }

    async fn load_persisted_peers(&self) -> Result<(), NetworkError> {
        let read_txn = self
            .metadata
            .database()
            .begin_read()
            .map_err(|source| NetworkError::Transaction(Box::new(source)))?;
        let table = match read_txn.open_table(NODES) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
            Err(source) => return Err(NetworkError::Table(Box::new(source))),
        };
        let mut loaded = HashMap::new();
        let mut loaded_tls_digests = HashMap::new();
        for item in table
            .iter()
            .map_err(|source| NetworkError::RedbStorage(Box::new(source)))?
        {
            let (_, value) = item.map_err(|source| NetworkError::RedbStorage(Box::new(source)))?;
            let peer: StoredPeer = serde_json::from_slice(value.value())?;
            if peer.node_id == self.local_descriptor().node_id {
                continue;
            }
            if !peer.tls_certificate_digest_hex.is_empty() {
                loaded_tls_digests.insert(
                    peer.node_id.clone(),
                    peer.tls_certificate_digest_hex.clone(),
                );
            }
            loaded.insert(
                peer.node_id.clone(),
                PeerStatus {
                    node_id: peer.node_id,
                    name: peer.name,
                    addresses: sorted_routable_addresses(peer.addresses),
                    bulk_addresses: sorted_routable_addresses(peer.bulk_addresses),
                    last_seen_unix_seconds: peer.last_seen_unix_seconds,
                    connected: false,
                    failure_domain: peer.failure_domain,
                    placement_labels: peer.placement_labels,
                    storage_capacity_bytes: peer.storage_capacity_bytes,
                    storage_available_bytes: peer.storage_available_bytes,
                    namespace_consensus_enabled: peer.namespace_consensus_enabled,
                    namespace_group_capacity: peer.namespace_group_capacity,
                    namespace_group_count: peer.namespace_group_count,
                    max_consensus_log_bytes: peer.max_consensus_log_bytes,
                    max_namespace_write_rate: peer.max_namespace_write_rate,
                },
            );
        }
        self.peers.write().await.extend(loaded);
        self.peer_tls_digests.store(Arc::new(loaded_tls_digests));
        Ok(())
    }

    async fn prune_routing_table(&self) {
        let local = node_id_bytes(&self.local_descriptor().node_id);
        let mut peers = self.peers.write().await;
        let mut by_bucket = HashMap::<usize, Vec<PeerStatus>>::new();
        for peer in peers.values().cloned() {
            let distance = xor_distance(&local, &node_id_bytes(&peer.node_id));
            by_bucket
                .entry(kademlia_bucket(&distance))
                .or_default()
                .push(peer);
        }
        peers.clear();
        for (_, mut bucket) in by_bucket {
            bucket.sort_by(|left, right| {
                right
                    .connected
                    .cmp(&left.connected)
                    .then_with(|| {
                        right
                            .last_seen_unix_seconds
                            .cmp(&left.last_seen_unix_seconds)
                    })
                    .then_with(|| left.node_id.cmp(&right.node_id))
            });
            for peer in bucket.into_iter().take(KADEMLIA_BUCKET_SIZE) {
                peers.insert(peer.node_id.clone(), peer);
            }
        }
    }

    pub async fn get_block_from_any_peer(
        &self,
        cid: &Cid,
    ) -> Result<Option<Vec<u8>>, NetworkError> {
        Ok(self
            .get_block_from_any_peer_with_source(cid)
            .await?
            .map(|resolution| resolution.payload))
    }

    pub async fn get_block_from_any_peer_with_source(
        &self,
        cid: &Cid,
    ) -> Result<Option<BlockResolution>, NetworkError> {
        for record in self.find_providers(cid).await? {
            let mut definitive_direct_response = false;
            for address in sorted_routable_addresses(record.addresses.clone()) {
                let Ok(addr) = SocketAddr::from_str(&address) else {
                    continue;
                };
                match self.block_get(addr, cid).await {
                    Ok(payload) => {
                        return Ok(Some(BlockResolution {
                            payload,
                            source_node_id: record.node_id.clone(),
                            route: "direct_provider".to_string(),
                        }));
                    }
                    Err(error) => {
                        definitive_direct_response |= matches!(
                            error,
                            NetworkError::Rpc { .. }
                                | NetworkError::BlockService(_)
                                | NetworkError::UnsupportedMethod(_)
                                | NetworkError::Unauthenticated
                                | NetworkError::RateLimited
                        );
                        debug!(%addr, %error, "provider block get failed");
                    }
                }
            }
            // A direct request reached the authoritative provider. Retrying the
            // same missing block through every relay cannot change that answer
            // and makes erasure recovery scale quadratically with node count.
            // Relay only when the provider has no directly usable address.
            if !definitive_direct_response {
                match self.get_block_via_relays(&record.node_id, cid).await {
                    Ok(Some(payload)) => {
                        return Ok(Some(BlockResolution {
                            payload,
                            source_node_id: record.node_id.clone(),
                            route: "relay_provider".to_string(),
                        }));
                    }
                    Ok(None) => {}
                    Err(error) => {
                        debug!(%error, target_node_id = %record.node_id, "relayed block get failed")
                    }
                }
            }
        }
        let mut probes = tokio::task::JoinSet::new();
        for peer in self.peers().await {
            let Some(addr) = sorted_routable_addresses(peer.addresses)
                .into_iter()
                .find_map(|address| SocketAddr::from_str(&address).ok())
            else {
                continue;
            };
            let network = self.clone();
            let cid = cid.clone();
            probes.spawn(async move {
                let result = network.block_get(addr, &cid).await;
                (peer.node_id, addr, result)
            });
        }
        while let Some(result) = probes.join_next().await {
            let Ok((node_id, addr, result)) = result else {
                continue;
            };
            match result {
                Ok(payload) => {
                    probes.abort_all();
                    return Ok(Some(BlockResolution {
                        payload,
                        source_node_id: node_id,
                        route: "peer_fallback".to_string(),
                    }));
                }
                Err(error) => debug!(%addr, %error, "peer block get failed"),
            }
        }
        Ok(None)
    }

    async fn get_block_via_relays(
        &self,
        target_node_id: &str,
        cid: &Cid,
    ) -> Result<Option<Vec<u8>>, NetworkError> {
        for relay in self.peers().await {
            if relay.node_id == target_node_id {
                continue;
            }
            for address in sorted_routable_addresses(relay.addresses) {
                let Ok(addr) = SocketAddr::from_str(&address) else {
                    continue;
                };
                match self.relay_block_get(addr, target_node_id, cid).await {
                    Ok(payload) => return Ok(Some(payload)),
                    Err(error) => debug!(%addr, %error, "relay block get failed"),
                }
            }
        }
        Ok(None)
    }

    pub async fn node_info(&self, peer: SocketAddr) -> Result<proto::NodeDescriptor, NetworkError> {
        let request = proto::NodeInfoRequest {};
        let response: proto::NodeInfoResponse = self.rpc(peer, "/node/info", request).await?;
        let descriptor = response.descriptor.ok_or_else(|| {
            NetworkError::InvalidDescriptor("missing node descriptor".to_string())
        })?;
        self.record_descriptor(&descriptor).await?;
        Ok(descriptor)
    }

    pub async fn node_peers(&self, peer: SocketAddr) -> Result<Vec<PeerStatus>, NetworkError> {
        let response: proto::ListPeersResponse = self
            .rpc(peer, "/node/peers", proto::ListPeersRequest {})
            .await?;
        let mut peers = Vec::new();
        for peer in response.peers.into_iter().take(256) {
            let mut verified = false;
            for address in sorted_routable_addresses(peer.addresses.clone()) {
                if let Ok(addr) = address.parse::<SocketAddr>()
                    && let Ok(descriptor) = self.node_info(addr).await
                    && descriptor.node_id == peer.node_id
                {
                    verified = true;
                    break;
                }
            }
            if verified {
                peers.push(PeerStatus {
                    node_id: peer.node_id,
                    name: peer.name,
                    addresses: sorted_routable_addresses(peer.addresses),
                    bulk_addresses: sorted_routable_addresses(peer.bulk_addresses),
                    last_seen_unix_seconds: peer.last_seen_unix_seconds,
                    connected: peer.connected,
                    failure_domain: if peer.failure_domain.is_empty() {
                        None
                    } else {
                        Some(peer.failure_domain)
                    },
                    placement_labels: peer.placement_labels,
                    storage_capacity_bytes: peer.storage_capacity_bytes,
                    storage_available_bytes: peer.storage_available_bytes,
                    namespace_consensus_enabled: peer.namespace_consensus_enabled,
                    namespace_group_capacity: peer.namespace_group_capacity,
                    namespace_group_count: peer.namespace_group_count,
                    max_consensus_log_bytes: peer.max_consensus_log_bytes,
                    max_namespace_write_rate: peer.max_namespace_write_rate,
                });
            }
        }
        Ok(peers)
    }

    pub async fn refresh_routing_table(&self) {
        let peers = self.peers().await;
        for peer in peers {
            for address in sorted_routable_addresses(peer.addresses) {
                let Ok(addr) = address.parse::<SocketAddr>() else {
                    continue;
                };
                if let Err(error) = self.node_peers(addr).await {
                    debug!(%addr, %error, "peer gossip refresh failed");
                }
            }
        }
    }

    pub async fn block_has(&self, peer: SocketAddr, cid: &Cid) -> Result<bool, NetworkError> {
        let request = proto::BlockHasRequest {
            cid: cid.to_string(),
        };
        let response: proto::BlockHasResponse = self.rpc(peer, "/block/has", request).await?;
        Ok(response.has)
    }

    pub async fn block_has_batch(
        &self,
        peer: SocketAddr,
        cids: &[Cid],
    ) -> Result<Vec<bool>, NetworkError> {
        if cids.is_empty() || cids.len() > MAX_BLOCK_HAS_BATCH_CIDS {
            return Err(NetworkError::BlockService(format!(
                "block health batch must contain between 1 and {MAX_BLOCK_HAS_BATCH_CIDS} CIDs"
            )));
        }
        let request = proto::BlockHasBatchRequest {
            cids: cids.iter().map(ToString::to_string).collect(),
        };
        let response: proto::BlockHasBatchResponse =
            self.rpc(peer, "/block/has_batch", request).await?;
        if response.present.len() != cids.len() {
            return Err(NetworkError::BlockService(
                "block health batch response length does not match request".to_string(),
            ));
        }
        Ok(response.present)
    }

    pub async fn block_get(&self, peer: SocketAddr, cid: &Cid) -> Result<Vec<u8>, NetworkError> {
        self.with_peer_timeout(
            peer,
            RpcClass::Bulk,
            self.bulk_request_timeout,
            self.block_get_stream_inner(peer, cid),
        )
        .await
    }

    async fn block_get_stream_inner(
        &self,
        peer: SocketAddr,
        cid: &Cid,
    ) -> Result<Vec<u8>, NetworkError> {
        let request = proto::BlockGetRequest {
            cid: cid.to_string(),
        };
        let mut request_payload = Vec::with_capacity(request.encoded_len());
        request.encode(&mut request_payload)?;
        let request_id = next_request_id();
        let envelope = self.authenticated_envelope(
            request_id.clone(),
            "/block/get_stream".to_string(),
            request_payload,
        );
        let request_wire_bytes = envelope.encoded_len();
        let (pooled, mut send, mut recv) = self.open_rpc_stream(peer, RpcClass::Bulk).await?;
        write_frame(&mut send, &envelope).await?;
        let response = read_frame::<proto::ResponseEnvelope>(&mut recv).await?;
        verify_response_envelope(&response, &request_id)?;
        if response.node_id != pooled.peer_node_id {
            return Err(NetworkError::Unauthenticated);
        }
        if !response.ok {
            self.record_rpc(
                &pooled.peer_node_id,
                "/block/get_stream",
                "outbound",
                request_wire_bytes,
                response.encoded_len(),
                true,
            );
            return Err(NetworkError::Rpc {
                code: response.error_code,
                message: response.error_message,
            });
        }
        let metadata = proto::BlockGetStreamResponse::decode(response.payload.as_slice())?;
        if metadata.cid != cid.to_string() || metadata.size > 64 * 1024 * 1024 {
            return Err(NetworkError::BlockService(
                "invalid streamed block response metadata".to_string(),
            ));
        }
        let size = usize::try_from(metadata.size).map_err(|_| {
            NetworkError::BlockService("streamed block size does not fit usize".to_string())
        })?;
        if let Some(limiter) = &self.bulk_receive_bandwidth {
            limiter.reserve(size).await;
        }
        let mut payload = vec![0u8; size];
        recv.read_exact(&mut payload).await?;
        if !cid.verify(&payload) {
            return Err(NetworkError::BlockService(
                "remote block hash mismatch".to_string(),
            ));
        }
        self.transport_counters
            .bulk_bytes_received_total
            .fetch_add(metadata.size, Ordering::Relaxed);
        self.record_rpc(
            &pooled.peer_node_id,
            "/block/get_stream",
            "outbound",
            request_wire_bytes,
            response.encoded_len().saturating_add(size),
            false,
        );
        Ok(payload)
    }

    pub async fn block_get_range(
        &self,
        peer: SocketAddr,
        cid: &Cid,
        start: u64,
        end: u64,
    ) -> Result<Vec<u8>, NetworkError> {
        if start >= end || end > 64 * 1024 * 1024 {
            return Err(NetworkError::BlockService(
                "invalid streamed block range".to_string(),
            ));
        }
        self.with_peer_timeout(
            peer,
            RpcClass::Bulk,
            self.bulk_request_timeout,
            self.block_get_range_stream_inner(peer, cid, start, end),
        )
        .await
    }

    async fn block_get_range_stream_inner(
        &self,
        peer: SocketAddr,
        cid: &Cid,
        start: u64,
        end: u64,
    ) -> Result<Vec<u8>, NetworkError> {
        let request = proto::BlockGetRangeRequest {
            cid: cid.to_string(),
            start,
            end,
        };
        let mut request_payload = Vec::with_capacity(request.encoded_len());
        request.encode(&mut request_payload)?;
        let request_id = next_request_id();
        let envelope = self.authenticated_envelope(
            request_id.clone(),
            "/block/get_range_stream".to_string(),
            request_payload,
        );
        let request_wire_bytes = envelope.encoded_len();
        let (pooled, mut send, mut recv) = self.open_rpc_stream(peer, RpcClass::Bulk).await?;
        write_frame(&mut send, &envelope).await?;
        let response = read_frame::<proto::ResponseEnvelope>(&mut recv).await?;
        verify_response_envelope(&response, &request_id)?;
        if response.node_id != pooled.peer_node_id {
            return Err(NetworkError::Unauthenticated);
        }
        if !response.ok {
            self.record_rpc(
                &pooled.peer_node_id,
                "/block/get_range_stream",
                "outbound",
                request_wire_bytes,
                response.encoded_len(),
                true,
            );
            return Err(NetworkError::Rpc {
                code: response.error_code,
                message: response.error_message,
            });
        }
        let metadata = proto::BlockGetRangeStreamResponse::decode(response.payload.as_slice())?;
        let expected_size = end - start;
        if metadata.cid != cid.to_string()
            || metadata.start != start
            || metadata.end != end
            || metadata.size != expected_size
        {
            return Err(NetworkError::BlockService(
                "invalid streamed block-range response metadata".to_string(),
            ));
        }
        let size = usize::try_from(metadata.size).map_err(|_| {
            NetworkError::BlockService("streamed block range does not fit usize".to_string())
        })?;
        if let Some(limiter) = &self.bulk_receive_bandwidth {
            limiter.reserve(size).await;
        }
        let mut payload = vec![0u8; size];
        recv.read_exact(&mut payload).await?;
        self.transport_counters
            .bulk_bytes_received_total
            .fetch_add(metadata.size, Ordering::Relaxed);
        self.record_rpc(
            &pooled.peer_node_id,
            "/block/get_range_stream",
            "outbound",
            request_wire_bytes,
            response.encoded_len().saturating_add(size),
            false,
        );
        Ok(payload)
    }

    pub async fn relay_block_get(
        &self,
        relay: SocketAddr,
        target_node_id: &str,
        cid: &Cid,
    ) -> Result<Vec<u8>, NetworkError> {
        let request = proto::RelayBlockGetRequest {
            target_node_id: target_node_id.to_string(),
            cid: cid.to_string(),
        };
        let response: proto::RelayBlockGetResponse =
            self.rpc(relay, "/relay/block_get", request).await?;
        if !cid.verify(&response.payload) {
            return Err(NetworkError::BlockService(
                "relayed block hash mismatch".to_string(),
            ));
        }
        Ok(response.payload)
    }

    pub async fn block_put_replica(
        &self,
        peer: SocketAddr,
        codec: Codec,
        payload: Vec<u8>,
    ) -> Result<proto::BlockPutReplicaResponse, NetworkError> {
        let request = proto::BlockPutReplicaRequest {
            payload,
            codec: codec.canonical_display(),
        };
        self.rpc(peer, "/block/put_replica", request).await
    }

    /// Store a replica without copying its bytes through nested protobuf
    /// messages. The authenticated envelope signs the expected CID and size;
    /// the receiver verifies the streamed bytes before acknowledging them.
    pub async fn block_put_replica_stream(
        &self,
        peer: SocketAddr,
        codec: Codec,
        cid: &Cid,
        logical_size: u64,
        payload: Arc<[u8]>,
    ) -> Result<proto::BlockPutReplicaResponse, NetworkError> {
        self.with_peer_timeout(
            peer,
            RpcClass::Bulk,
            self.bulk_request_timeout,
            self.block_put_replica_stream_inner(peer, codec, cid, logical_size, payload),
        )
        .await
    }

    async fn block_put_replica_stream_inner(
        &self,
        peer: SocketAddr,
        codec: Codec,
        cid: &Cid,
        logical_size: u64,
        payload: Arc<[u8]>,
    ) -> Result<proto::BlockPutReplicaResponse, NetworkError> {
        let queue_started = std::time::Instant::now();
        let _replica_stream_permit = self
            .outbound_replica_streams
            .acquire()
            .await
            .map_err(|_| NetworkError::RateLimited)?;
        self.record_bulk_stream_queue(queue_started.elapsed());
        if payload.len() > 64 * 1024 * 1024 + 1024 {
            return Err(NetworkError::BlockService(
                "streamed replica payload exceeds limit".to_string(),
            ));
        }
        let metadata = proto::BlockPutReplicaStreamRequest {
            cid: cid.to_string(),
            codec: codec.canonical_display(),
            size: logical_size,
            encoded_size: payload.len() as u64,
        };
        let mut metadata_payload = Vec::with_capacity(metadata.encoded_len());
        metadata.encode(&mut metadata_payload)?;
        let request_id = next_request_id();
        let envelope = self.authenticated_envelope(
            request_id.clone(),
            "/block/put_replica_stream".to_string(),
            metadata_payload,
        );
        let request_wire_bytes = envelope.encoded_len().saturating_add(payload.len());
        let (pooled, mut send, mut recv) = self.open_rpc_stream(peer, RpcClass::Bulk).await?;
        write_frame_open(&mut send, &envelope).await?;
        if let Some(limiter) = &self.bulk_send_bandwidth {
            limiter.reserve(payload.len()).await;
        }
        send.write_all(payload.as_ref()).await?;
        self.transport_counters
            .bulk_bytes_sent_total
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        send.finish()?;

        let response = read_frame::<proto::ResponseEnvelope>(&mut recv).await?;
        verify_response_envelope(&response, &request_id)?;
        if response.node_id != pooled.peer_node_id {
            self.record_rpc(
                &pooled.peer_node_id,
                "/block/put_replica_stream",
                "outbound",
                request_wire_bytes,
                response.encoded_len(),
                true,
            );
            return Err(NetworkError::Unauthenticated);
        }
        self.record_rpc(
            &pooled.peer_node_id,
            "/block/put_replica_stream",
            "outbound",
            request_wire_bytes,
            response.encoded_len(),
            !response.ok,
        );
        if !response.ok {
            return Err(NetworkError::Rpc {
                code: response.error_code,
                message: response.error_message,
            });
        }
        proto::BlockPutReplicaResponse::decode(response.payload.as_slice())
            .map_err(NetworkError::from)
    }

    pub async fn erasure_encode_parity(
        &self,
        peer: SocketAddr,
        request: proto::ErasureTransferRequest,
    ) -> Result<proto::ErasureTransferResponse, NetworkError> {
        self.rpc(peer, "/erasure/encode_parity", request).await
    }

    pub async fn push_repair_inventory(
        &self,
        peer: SocketAddr,
        inventory_json: String,
    ) -> Result<(), NetworkError> {
        let response: proto::RepairInventoryPushResponse = self
            .rpc(
                peer,
                "/repair/inventory_push",
                proto::RepairInventoryPushRequest { inventory_json },
            )
            .await?;
        if !response.accepted {
            return Err(NetworkError::BlockService(
                "repair inventory was not accepted".to_string(),
            ));
        }
        Ok(())
    }

    pub async fn execute_repair(
        &self,
        peer: SocketAddr,
        task_json: String,
    ) -> Result<proto::RepairExecuteResponse, NetworkError> {
        self.with_peer_timeout(
            peer,
            RpcClass::Control,
            self.bulk_request_timeout
                .max(std::time::Duration::from_secs(30)),
            self.rpc_inner(
                peer,
                "/repair/execute",
                proto::RepairExecuteRequest { task_json },
                None,
            ),
        )
        .await
    }

    pub async fn cleanup_repair_extra(
        &self,
        peer: SocketAddr,
        exception_json: String,
    ) -> Result<bool, NetworkError> {
        let response: proto::RepairCleanupExtraResponse = self
            .rpc(
                peer,
                "/repair/cleanup_extra",
                proto::RepairCleanupExtraRequest { exception_json },
            )
            .await?;
        Ok(response.removed)
    }

    pub async fn erasure_store_stripe_stream(
        &self,
        peer: SocketAddr,
        request: proto::ErasureTransferRequest,
        encoded: Arc<[u8]>,
    ) -> Result<proto::ErasureTransferResponse, NetworkError> {
        self.with_peer_timeout(
            peer,
            RpcClass::Bulk,
            self.bulk_request_timeout,
            self.erasure_store_stripe_stream_inner(peer, request, encoded),
        )
        .await
    }

    async fn erasure_store_stripe_stream_inner(
        &self,
        peer: SocketAddr,
        request: proto::ErasureTransferRequest,
        encoded: Arc<[u8]>,
    ) -> Result<proto::ErasureTransferResponse, NetworkError> {
        let queue_started = std::time::Instant::now();
        let _replica_stream_permit = self
            .outbound_replica_streams
            .acquire()
            .await
            .map_err(|_| NetworkError::RateLimited)?;
        self.record_bulk_stream_queue(queue_started.elapsed());
        if encoded.len() > 512 * 1024 * 1024 || request.encoded_size != encoded.len() as u64 {
            return Err(NetworkError::BlockService(
                "adaptive erasure stripe payload exceeds limit or metadata size".to_string(),
            ));
        }
        let mut metadata_payload = Vec::with_capacity(request.encoded_len());
        request.encode(&mut metadata_payload)?;
        let request_id = next_request_id();
        let envelope = self.authenticated_envelope(
            request_id.clone(),
            "/erasure/store_stripe_stream".to_string(),
            metadata_payload,
        );
        let request_wire_bytes = envelope.encoded_len().saturating_add(encoded.len());
        let (pooled, mut send, mut recv) = self.open_rpc_stream(peer, RpcClass::Bulk).await?;
        write_frame_open(&mut send, &envelope).await?;
        for chunk in encoded.chunks(ERASURE_STREAM_CHUNK_BYTES) {
            if let Some(limiter) = &self.bulk_send_bandwidth {
                limiter.reserve(chunk.len()).await;
            }
            send.write_all(chunk).await?;
        }
        self.transport_counters
            .bulk_bytes_sent_total
            .fetch_add(encoded.len() as u64, Ordering::Relaxed);
        send.finish()?;

        let response = read_frame::<proto::ResponseEnvelope>(&mut recv).await?;
        verify_response_envelope(&response, &request_id)?;
        let failed = response.node_id != pooled.peer_node_id || !response.ok;
        self.record_rpc(
            &pooled.peer_node_id,
            "/erasure/store_stripe_stream",
            "outbound",
            request_wire_bytes,
            response.encoded_len(),
            failed,
        );
        if response.node_id != pooled.peer_node_id {
            return Err(NetworkError::Unauthenticated);
        }
        if !response.ok {
            return Err(NetworkError::Rpc {
                code: response.error_code,
                message: response.error_message,
            });
        }
        proto::ErasureTransferResponse::decode(response.payload.as_slice())
            .map_err(NetworkError::from)
    }

    pub async fn erasure_relay_stripe_stream(
        &self,
        peer: SocketAddr,
        request: proto::ErasureTransferRequest,
        chunks: ErasureChunkReceiver,
    ) -> Result<proto::ErasureTransferResponse, NetworkError> {
        self.with_peer_timeout(
            peer,
            RpcClass::Bulk,
            self.bulk_request_timeout,
            self.erasure_relay_stripe_stream_inner(peer, request, chunks),
        )
        .await
    }

    async fn erasure_relay_stripe_stream_inner(
        &self,
        peer: SocketAddr,
        request: proto::ErasureTransferRequest,
        mut chunks: ErasureChunkReceiver,
    ) -> Result<proto::ErasureTransferResponse, NetworkError> {
        let queue_started = std::time::Instant::now();
        let _replica_stream_permit = self
            .outbound_replica_streams
            .acquire()
            .await
            .map_err(|_| NetworkError::RateLimited)?;
        self.record_bulk_stream_queue(queue_started.elapsed());
        let encoded_size = usize::try_from(request.encoded_size).map_err(|_| {
            NetworkError::BlockService("erasure stripe size does not fit usize".to_string())
        })?;
        if encoded_size == 0 || encoded_size > 512 * 1024 * 1024 {
            return Err(NetworkError::BlockService(
                "adaptive erasure stripe payload exceeds limit".to_string(),
            ));
        }
        let mut metadata_payload = Vec::with_capacity(request.encoded_len());
        request.encode(&mut metadata_payload)?;
        let request_id = next_request_id();
        let envelope = self.authenticated_envelope(
            request_id.clone(),
            "/erasure/store_stripe_stream".to_string(),
            metadata_payload,
        );
        let request_wire_bytes = envelope.encoded_len().saturating_add(encoded_size);
        let (pooled, mut send, mut recv) = self.open_rpc_stream(peer, RpcClass::Bulk).await?;
        write_frame_open(&mut send, &envelope).await?;
        let mut sent = 0usize;
        while let Some(chunk) = chunks.recv().await {
            sent = sent.checked_add(chunk.len()).ok_or_else(|| {
                NetworkError::BlockService("erasure relay size overflow".to_string())
            })?;
            if sent > encoded_size {
                return Err(NetworkError::BlockService(
                    "erasure relay exceeded declared size".to_string(),
                ));
            }
            if let Some(limiter) = &self.bulk_send_bandwidth {
                limiter.reserve(chunk.len()).await;
            }
            send.write_all(&chunk).await?;
            self.transport_counters
                .bulk_bytes_sent_total
                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
        if sent != encoded_size {
            return Err(NetworkError::BlockService(
                "erasure relay ended before declared size".to_string(),
            ));
        }
        send.finish()?;

        let response = read_frame::<proto::ResponseEnvelope>(&mut recv).await?;
        verify_response_envelope(&response, &request_id)?;
        let failed = response.node_id != pooled.peer_node_id || !response.ok;
        self.record_rpc(
            &pooled.peer_node_id,
            "/erasure/store_stripe_stream",
            "outbound",
            request_wire_bytes,
            response.encoded_len(),
            failed,
        );
        if response.node_id != pooled.peer_node_id {
            return Err(NetworkError::Unauthenticated);
        }
        if !response.ok {
            return Err(NetworkError::Rpc {
                code: response.error_code,
                message: response.error_message,
            });
        }
        proto::ErasureTransferResponse::decode(response.payload.as_slice())
            .map_err(NetworkError::from)
    }

    fn record_bulk_stream_queue(&self, elapsed: std::time::Duration) {
        let sample = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
        let _ = self
            .transport_counters
            .bulk_stream_queue_ewma_microseconds
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                Some(if old == 0 {
                    sample
                } else {
                    old.saturating_mul(7).saturating_add(sample) / 8
                })
            });
    }

    pub async fn block_providers(
        &self,
        peer: SocketAddr,
        cid: &Cid,
    ) -> Result<Vec<ProviderRecord>, NetworkError> {
        let request = proto::BlockProvidersRequest {
            cid: cid.to_string(),
        };
        let response: proto::BlockProvidersResponse =
            self.rpc(peer, "/block/providers", request).await?;
        let mut providers = Vec::new();
        for json in response.provider_record_json.into_iter().take(256) {
            let record: ProviderRecord = serde_json::from_str(&json)?;
            if self.validate_provider_record(&record).is_ok() {
                let _ = self.persist_provider_record(&record);
                providers.push(record);
            }
        }
        Ok(providers)
    }

    async fn announce_provider_batch(
        &self,
        peer: SocketAddr,
        records: &[ProviderRecord],
    ) -> Result<(), NetworkError> {
        let request = proto::BlockAnnounceProviderBatchRequest {
            provider_record_json: records
                .iter()
                .map(serde_json::to_string)
                .collect::<Result<Vec<_>, _>>()?,
        };
        let response: proto::BlockAnnounceProviderBatchResponse = self
            .rpc(peer, "/block/announce_provider_batch", request)
            .await?;
        if response.accepted != records.len() as u64 {
            return Err(NetworkError::BlockService(
                "peer did not accept every provider record in the batch".to_string(),
            ));
        }
        Ok(())
    }

    pub async fn announce_provider(
        &self,
        peer: SocketAddr,
        record: &ProviderRecord,
    ) -> Result<bool, NetworkError> {
        let request = proto::BlockAnnounceProviderRequest {
            provider_record_json: serde_json::to_string(record)?,
        };
        let response: proto::BlockAnnounceProviderResponse =
            self.rpc(peer, "/block/announce_provider", request).await?;
        Ok(response.accepted)
    }

    pub async fn apply_pin(
        &self,
        peer: SocketAddr,
        pin_record_json: String,
    ) -> Result<(), NetworkError> {
        let response: proto::PinApplyResponse = self
            .rpc(
                peer,
                "/pin/apply",
                proto::PinApplyRequest { pin_record_json },
            )
            .await?;
        if !response.accepted {
            return Err(NetworkError::BlockService(
                "peer rejected pin record".to_string(),
            ));
        }
        Ok(())
    }

    pub async fn compute_offer(
        &self,
        peer: SocketAddr,
        spec_json: String,
    ) -> Result<proto::ComputeOfferResponse, NetworkError> {
        self.rpc(
            peer,
            "/compute/offer",
            proto::ComputeOfferRequest { spec_json },
        )
        .await
    }

    pub async fn compute_submit(
        &self,
        peer: SocketAddr,
        job_id: String,
        spec_json: String,
    ) -> Result<proto::ComputeSubmitResponse, NetworkError> {
        self.rpc(
            peer,
            "/compute/submit",
            proto::ComputeSubmitRequest { job_id, spec_json },
        )
        .await
    }

    pub async fn compute_status(
        &self,
        peer: SocketAddr,
        job_id: String,
    ) -> Result<proto::ComputeStatusResponse, NetworkError> {
        self.rpc(
            peer,
            "/compute/status",
            proto::ComputeStatusRequest { job_id },
        )
        .await
    }

    pub async fn compute_logs(
        &self,
        peer: SocketAddr,
        job_id: String,
    ) -> Result<proto::ComputeLogsResponse, NetworkError> {
        self.rpc(peer, "/compute/logs", proto::ComputeLogsRequest { job_id })
            .await
    }

    pub async fn compute_cancel(
        &self,
        peer: SocketAddr,
        job_id: String,
    ) -> Result<proto::ComputeCancelResponse, NetworkError> {
        self.rpc(
            peer,
            "/compute/cancel",
            proto::ComputeCancelRequest { job_id },
        )
        .await
    }

    pub fn make_namespace_discovery_record(
        &self,
        namespace_id: String,
        membership_epoch: u64,
        mut replica_node_ids: Vec<String>,
        leader_node_id: String,
        leader_term: u64,
        expires_at_unix_seconds: i64,
    ) -> proto::NamespaceDiscoveryRecord {
        replica_node_ids.sort();
        replica_node_ids.dedup();
        let mut record = proto::NamespaceDiscoveryRecord {
            namespace_id,
            namespace_protocol_version: 1,
            membership_epoch,
            replica_node_ids,
            leader_node_id,
            leader_term,
            expires_at_unix_seconds,
            announcer_node_id: self.local_descriptor().node_id,
            signature_hex: String::new(),
        };
        record.signature_hex = hex::encode(
            self.identity
                .sign(&namespace_discovery_signature_payload(&record)),
        );
        record
    }

    pub fn verify_namespace_discovery_record(
        &self,
        record: &proto::NamespaceDiscoveryRecord,
    ) -> Result<(), NetworkError> {
        if record.namespace_protocol_version != 1
            || record.membership_epoch == 0
            || record.namespace_id.is_empty()
            || record.namespace_id.len() > 256
            || record.replica_node_ids.len() != 3
            || record.expires_at_unix_seconds <= unix_seconds()
            || record.expires_at_unix_seconds > unix_seconds().saturating_add(300)
        {
            return Err(NetworkError::InvalidDescriptor(
                "invalid namespace discovery record".to_string(),
            ));
        }
        let mut replicas = record.replica_node_ids.clone();
        replicas.sort();
        replicas.dedup();
        if replicas != record.replica_node_ids {
            return Err(NetworkError::InvalidDescriptor(
                "namespace replicas must be sorted and unique".to_string(),
            ));
        }
        self.verify_node_signature(
            &record.announcer_node_id,
            &namespace_discovery_signature_payload(record),
            &record.signature_hex,
        )
    }

    pub async fn namespace_discover(
        &self,
        peer: SocketAddr,
        namespace_id: String,
    ) -> Result<Vec<proto::NamespaceDiscoveryRecord>, NetworkError> {
        let response: proto::NamespaceDiscoverResponse = self
            .rpc(
                peer,
                "/namespace/discover",
                proto::NamespaceDiscoverRequest { namespace_id },
            )
            .await?;
        Ok(response
            .records
            .into_iter()
            .filter(|record| self.verify_namespace_discovery_record(record).is_ok())
            .take(16)
            .collect())
    }

    pub async fn namespace_announce(
        &self,
        peer: SocketAddr,
        record: proto::NamespaceDiscoveryRecord,
    ) -> Result<(), NetworkError> {
        let response: proto::NamespaceAnnounceResponse = self
            .rpc(
                peer,
                "/namespace/announce",
                proto::NamespaceAnnounceRequest {
                    record: Some(record),
                },
            )
            .await?;
        if response.accepted {
            Ok(())
        } else {
            Err(NetworkError::BlockService(
                "namespace announcement rejected".to_string(),
            ))
        }
    }

    pub async fn namespace_raft_vote(
        &self,
        peer: SocketAddr,
        mut request: proto::NamespaceRaftRequest,
    ) -> Result<Vec<u8>, NetworkError> {
        let request_id = next_request_id();
        request
            .context
            .as_mut()
            .ok_or_else(|| NetworkError::BlockService("missing namespace context".to_string()))?
            .request_id = request_id.clone();
        let response: proto::NamespaceRaftResponse = self
            .rpc_identified(peer, "/namespace/raft/vote", request, request_id)
            .await?;
        Ok(response.response_json)
    }

    pub async fn namespace_raft_append(
        &self,
        peer: SocketAddr,
        mut request: proto::NamespaceRaftRequest,
    ) -> Result<Vec<u8>, NetworkError> {
        let request_id = next_request_id();
        request
            .context
            .as_mut()
            .ok_or_else(|| NetworkError::BlockService("missing namespace context".to_string()))?
            .request_id = request_id.clone();
        let response: proto::NamespaceRaftResponse = self
            .rpc_identified(peer, "/namespace/raft/append", request, request_id)
            .await?;
        Ok(response.response_json)
    }

    pub async fn namespace_raft_install_snapshot(
        &self,
        peer: SocketAddr,
        mut request: proto::NamespaceRaftRequest,
    ) -> Result<Vec<u8>, NetworkError> {
        let request_id = next_request_id();
        request
            .context
            .as_mut()
            .ok_or_else(|| NetworkError::BlockService("missing namespace context".to_string()))?
            .request_id = request_id.clone();
        let response: proto::NamespaceRaftResponse = self
            .rpc_identified(
                peer,
                "/namespace/raft/install_snapshot",
                request,
                request_id,
            )
            .await?;
        Ok(response.response_json)
    }

    pub async fn namespace_forward(
        &self,
        peer: SocketAddr,
        mut request: proto::NamespaceForwardRequest,
    ) -> Result<proto::NamespaceForwardResponse, NetworkError> {
        let request_id = next_request_id();
        request
            .context
            .as_mut()
            .ok_or_else(|| NetworkError::BlockService("missing namespace context".to_string()))?
            .request_id = request_id.clone();
        self.rpc_identified(peer, "/namespace/forward", request, request_id)
            .await
    }

    pub async fn namespace_sqlite_writer(
        &self,
        peer: SocketAddr,
        mut request: proto::NamespaceSqliteWriterRequest,
    ) -> Result<proto::NamespaceSqliteWriterResponse, NetworkError> {
        let request_id = next_request_id();
        request
            .context
            .as_mut()
            .ok_or_else(|| NetworkError::BlockService("missing namespace context".to_string()))?
            .request_id = request_id.clone();
        self.rpc_identified(peer, "/namespace/sqlite-writer", request, request_id)
            .await
    }

    pub async fn namespace_state(
        &self,
        peer: SocketAddr,
        mut request: proto::NamespaceStateRequest,
    ) -> Result<proto::NamespaceStateResponse, NetworkError> {
        let request_id = next_request_id();
        request
            .context
            .as_mut()
            .ok_or_else(|| NetworkError::BlockService("missing namespace context".to_string()))?
            .request_id = request_id.clone();
        self.rpc_identified(peer, "/namespace/state", request, request_id)
            .await
    }

    pub async fn namespace_bootstrap(
        &self,
        peer: SocketAddr,
        request: proto::NamespaceBootstrapRequest,
    ) -> Result<proto::NamespaceBootstrapResponse, NetworkError> {
        self.rpc(peer, "/namespace/bootstrap", request).await
    }

    pub async fn namespace_alias_resolve(
        &self,
        peer: SocketAddr,
        alias: String,
    ) -> Result<proto::NamespaceAliasResolveResponse, NetworkError> {
        self.rpc(
            peer,
            "/namespace/alias/resolve",
            proto::NamespaceAliasResolveRequest { alias },
        )
        .await
    }

    pub async fn namespace_alias_list(
        &self,
        peer: SocketAddr,
    ) -> Result<proto::NamespaceAliasListResponse, NetworkError> {
        self.rpc(
            peer,
            "/namespace/alias/list",
            proto::NamespaceAliasListRequest {},
        )
        .await
    }

    pub async fn peer_address(&self, node_id: &str) -> Option<SocketAddr> {
        self.peers()
            .await
            .into_iter()
            .find(|peer| peer.node_id == node_id)
            .and_then(|peer| {
                sorted_routable_addresses(peer.addresses)
                    .into_iter()
                    .find_map(|address| address.parse().ok())
            })
    }

    fn authenticated_envelope(
        &self,
        request_id: String,
        method: String,
        payload: Vec<u8>,
    ) -> proto::RequestEnvelope {
        let mut envelope = proto::RequestEnvelope {
            request_id,
            protocol_version: PROTOCOL_VERSION,
            node_id: self.local_descriptor().node_id,
            method,
            payload,
            auth_timestamp_unix_seconds: unix_seconds(),
            auth_signature_hex: String::new(),
            public_key_hex: hex::encode(self.identity.public_key_bytes()),
            identity_signature_hex: String::new(),
        };
        if let Some(secret) = &self.cluster_secret {
            envelope.auth_signature_hex = sign_request_envelope(secret, &envelope);
        }
        envelope.identity_signature_hex =
            hex::encode(self.identity.sign(&request_identity_payload(&envelope)));
        envelope
    }

    async fn rpc<Req, Resp>(
        &self,
        peer: SocketAddr,
        method: &str,
        request: Req,
    ) -> Result<Resp, NetworkError>
    where
        Req: Message,
        Resp: Message + Default,
    {
        let class = rpc_class(method);
        let timeout = if class == RpcClass::Bulk {
            self.bulk_request_timeout
        } else {
            std::time::Duration::from_secs(10)
        };
        self.with_peer_timeout(
            peer,
            class,
            timeout,
            self.rpc_inner(peer, method, request, None),
        )
        .await
    }

    async fn rpc_identified<Req, Resp>(
        &self,
        peer: SocketAddr,
        method: &str,
        request: Req,
        request_id: String,
    ) -> Result<Resp, NetworkError>
    where
        Req: Message,
        Resp: Message + Default,
    {
        let class = rpc_class(method);
        let timeout = if class == RpcClass::Bulk {
            self.bulk_request_timeout
        } else {
            std::time::Duration::from_secs(10)
        };
        self.with_peer_timeout(
            peer,
            class,
            timeout,
            self.rpc_inner(peer, method, request, Some(request_id)),
        )
        .await
    }

    async fn with_peer_timeout<T, F>(
        &self,
        peer: SocketAddr,
        class: RpcClass,
        timeout: std::time::Duration,
        operation: F,
    ) -> Result<T, NetworkError>
    where
        F: Future<Output = Result<T, NetworkError>>,
    {
        match tokio::time::timeout(timeout, operation).await {
            Ok(result) => result,
            Err(_) => {
                // QUIC may not publish a close reason until another packet is
                // exchanged. A timed-out connection to a restarted peer can
                // therefore look reusable indefinitely. Remove only this
                // peer/lane entry (without closing other in-flight clones) so
                // the next request performs a fresh authenticated dial.
                self.connection_pool(class)
                    .lock()
                    .await
                    .remove(&(peer, class));
                Err(NetworkError::DeadlineExceeded)
            }
        }
    }

    async fn rpc_inner<Req, Resp>(
        &self,
        peer: SocketAddr,
        method: &str,
        request: Req,
        request_id: Option<String>,
    ) -> Result<Resp, NetworkError>
    where
        Req: Message,
        Resp: Message + Default,
    {
        let _replica_stream_permit = if method == "/block/put_replica" {
            Some(
                self.outbound_replica_streams
                    .acquire()
                    .await
                    .map_err(|_| NetworkError::RateLimited)?,
            )
        } else {
            None
        };
        let (pooled, mut send, mut recv) = self.open_rpc_stream(peer, rpc_class(method)).await?;
        let mut payload = Vec::new();
        request.encode(&mut payload)?;
        let request_id = request_id.unwrap_or_else(next_request_id);
        let envelope = self.authenticated_envelope(request_id.clone(), method.to_string(), payload);
        let request_wire_bytes = envelope.encoded_len();
        write_frame(&mut send, &envelope).await?;
        let response = read_frame::<proto::ResponseEnvelope>(&mut recv).await?;
        verify_response_envelope(&response, &request_id)?;
        if response.node_id != pooled.peer_node_id {
            self.record_rpc(
                &pooled.peer_node_id,
                method,
                "outbound",
                request_wire_bytes,
                response.encoded_len(),
                true,
            );
            return Err(NetworkError::Unauthenticated);
        }
        self.record_rpc(
            &pooled.peer_node_id,
            method,
            "outbound",
            request_wire_bytes,
            response.encoded_len(),
            !response.ok,
        );
        if !response.ok {
            return Err(NetworkError::Rpc {
                code: response.error_code,
                message: response.error_message,
            });
        }
        Resp::decode(response.payload.as_slice()).map_err(NetworkError::from)
    }

    async fn pooled_connection(
        &self,
        peer: SocketAddr,
        class: RpcClass,
    ) -> Result<PooledConnection, NetworkError> {
        let pool = self.connection_pool(class);
        {
            let mut connections = pool.lock().await;
            if let Some(connection) = connections.get(&(peer, class))
                && self.pooled_connection_is_current(connection)
            {
                return Ok(connection.clone());
            }
            connections.remove(&(peer, class));
        }
        // Coalesce only dials for this exact peer/lane. We deliberately do not
        // hold a lane-wide pool lock across DNS, QUIC setup, or authentication:
        // a dead bulk target must not serialize unrelated storage peers.
        let dial_lock = {
            let mut dials = self.connection_dial_pool(class).lock().await;
            dials
                .entry((peer, class))
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        // The dial task is detached from the requesting stream. Hedged reads
        // routinely cancel losing requests; without this shield cancellation
        // aborts the QUIC handshake and the next block dials again.
        let this = self.clone();
        tokio::spawn(async move { this.dial_pooled_connection(peer, class, dial_lock).await })
            .await
            .map_err(|error| NetworkError::TransportTask(error.to_string()))?
    }

    async fn dial_pooled_connection(
        &self,
        peer: SocketAddr,
        class: RpcClass,
        dial_lock: Arc<AsyncMutex<()>>,
    ) -> Result<PooledConnection, NetworkError> {
        let _dial = dial_lock.lock().await;
        let pool = self.connection_pool(class);
        {
            let mut connections = pool.lock().await;
            if let Some(connection) = connections.get(&(peer, class))
                && self.pooled_connection_is_current(connection)
            {
                return Ok(connection.clone());
            }
            connections.remove(&(peer, class));
        }
        // Dial and authenticate without holding the global pool lock. A slow or
        // unreachable data peer must never prevent Raft from opening its
        // independent heartbeat connection to another peer.
        let target = self.connection_target(peer, class).await?;
        let endpoint = if class == RpcClass::Bulk {
            &self.bulk_endpoint
        } else {
            &self.endpoint
        };
        let connection = endpoint.connect(target, "pepper.local")?.await?;
        let peer_node_id = self.handshake_connection(&connection).await?;
        let pooled = PooledConnection {
            peer_tls_certificate_digest_hex: peer_certificate_digest(&connection)?,
            connection,
            peer_node_id,
        };
        let mut connections = pool.lock().await;
        if let Some(existing) = connections.get(&(peer, class))
            && self.pooled_connection_is_current(existing)
        {
            return Ok(existing.clone());
        }
        connections.insert((peer, class), pooled.clone());
        Ok(pooled)
    }

    fn pooled_connection_is_current(&self, connection: &PooledConnection) -> bool {
        if connection.connection.close_reason().is_some() {
            return false;
        }
        self.peer_tls_digests
            .load()
            .get(&connection.peer_node_id)
            .is_none_or(|current| current == &connection.peer_tls_certificate_digest_hex)
    }

    fn connection_pool(&self, class: RpcClass) -> &ConnectionPool {
        if class == RpcClass::Bulk {
            &self.outbound_bulk_connections
        } else {
            &self.outbound_control_connections
        }
    }

    fn connection_dial_pool(&self, class: RpcClass) -> &DialPool {
        if class == RpcClass::Bulk {
            &self.outbound_bulk_dials
        } else {
            &self.outbound_control_dials
        }
    }

    async fn connection_target(
        &self,
        control_peer: SocketAddr,
        class: RpcClass,
    ) -> Result<SocketAddr, NetworkError> {
        if class != RpcClass::Bulk {
            return Ok(control_peer);
        }
        let peers = self.peers.read().await;
        for peer in peers.values() {
            if !peer.addresses.iter().any(|address| {
                address
                    .parse::<SocketAddr>()
                    .is_ok_and(|address| address == control_peer)
            }) {
                continue;
            }
            if let Some(address) = sorted_routable_addresses(peer.bulk_addresses.clone())
                .into_iter()
                .find_map(|address| address.parse::<SocketAddr>().ok())
            {
                return Ok(address);
            }
        }
        Err(NetworkError::BulkAddressUnavailable(control_peer))
    }

    async fn open_rpc_stream(
        &self,
        peer: SocketAddr,
        class: RpcClass,
    ) -> Result<(PooledConnection, SendStream, RecvStream), NetworkError> {
        for _ in 0..2 {
            let pooled = self.pooled_connection(peer, class).await?;
            match pooled.connection.open_bi().await {
                Ok((send, recv)) => return Ok((pooled, send, recv)),
                Err(error) => {
                    let mut connections = self.connection_pool(class).lock().await;
                    if connections.get(&(peer, class)).is_some_and(|current| {
                        current.connection.stable_id() == pooled.connection.stable_id()
                    }) {
                        connections.remove(&(peer, class));
                    }
                    if pooled.connection.close_reason().is_none() {
                        return Err(NetworkError::Connection(error));
                    }
                }
            }
        }
        Err(NetworkError::DeadlineExceeded)
    }

    async fn handshake_connection(&self, connection: &Connection) -> Result<String, NetworkError> {
        let request = proto::HandshakeRequest {
            descriptor: Some(self.local_descriptor()),
        };
        let (mut send, mut recv) = connection.open_bi().await?;
        let mut payload = Vec::new();
        request.encode(&mut payload)?;
        let request_id = next_request_id();
        let envelope =
            self.authenticated_envelope(request_id.clone(), "/handshake".to_string(), payload);
        let request_wire_bytes = envelope.encoded_len();
        write_frame(&mut send, &envelope).await?;
        let response = read_frame::<proto::ResponseEnvelope>(&mut recv).await?;
        self.record_rpc(
            &response.node_id,
            "/handshake",
            "outbound",
            request_wire_bytes,
            response.encoded_len(),
            !response.ok,
        );
        verify_response_envelope(&response, &request_id)?;
        if !response.ok {
            return Err(NetworkError::Rpc {
                code: response.error_code,
                message: response.error_message,
            });
        }
        let handshake = proto::HandshakeResponse::decode(response.payload.as_slice())?;
        if let Some(descriptor) = handshake.descriptor {
            if descriptor.node_id != response.node_id
                || descriptor.tls_certificate_digest_hex != peer_certificate_digest(connection)?
            {
                return Err(NetworkError::Unauthenticated);
            }
            self.record_descriptor(&descriptor).await?;
            Ok(descriptor.node_id)
        } else {
            Err(NetworkError::InvalidDescriptor(
                "missing handshake response descriptor".to_string(),
            ))
        }
    }

    fn spawn_accept_loop(&self, block_service: Arc<dyn NetworkBlockService>, lane: TransportLane) {
        let endpoint = match lane {
            TransportLane::Control => self.endpoint.clone(),
            TransportLane::Bulk => self.bulk_endpoint.clone(),
        };
        let this = self.clone();
        let accept = async move {
            while let Some(incoming) = endpoint.accept().await {
                let this = this.clone();
                let block_service = block_service.clone();
                let slots = match lane {
                    TransportLane::Control => this.inbound_connections.clone(),
                    TransportLane::Bulk => this.inbound_bulk_connections.clone(),
                };
                let permit = match slots.acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    match tokio::time::timeout(std::time::Duration::from_secs(10), incoming).await {
                        Ok(Ok(connection)) => {
                            if let Err(error) = this
                                .handle_connection(connection, block_service, lane)
                                .await
                            {
                                match lane {
                                    TransportLane::Control => this
                                        .transport_counters
                                        .control_errors_total
                                        .fetch_add(1, Ordering::Relaxed),
                                    TransportLane::Bulk => this
                                        .transport_counters
                                        .bulk_errors_total
                                        .fetch_add(1, Ordering::Relaxed),
                                };
                                warn!(?lane, %error, "connection handler failed");
                            }
                        }
                        Ok(Err(error)) => warn!(?lane, %error, "incoming QUIC connection failed"),
                        Err(_) => warn!(?lane, "incoming QUIC handshake timed out"),
                    }
                });
            }
        };
        match lane {
            TransportLane::Control => {
                tokio::spawn(accept);
            }
            TransportLane::Bulk => {
                self.bulk_runtime.spawn(accept);
            }
        }
    }

    fn spawn_bootstrap(&self, bootstrap_peers: Vec<String>) {
        let this = self.clone();
        tokio::spawn(async move {
            for peer in bootstrap_peers {
                let addr = match peer.parse::<SocketAddr>() {
                    Ok(addr) => addr,
                    Err(error) => {
                        warn!(%peer, %error, "invalid bootstrap peer address");
                        continue;
                    }
                };
                match this.pooled_connection(addr, RpcClass::Control).await {
                    Ok(_) => info!(%addr, "bootstrap peer connected"),
                    Err(error) => warn!(%addr, %error, "bootstrap connection failed"),
                }
            }
        });
    }

    fn spawn_gossip_loop(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                this.refresh_routing_table().await;
            }
        });
    }

    async fn handle_connection(
        &self,
        connection: Connection,
        block_service: Arc<dyn NetworkBlockService>,
        lane: TransportLane,
    ) -> Result<(), NetworkError> {
        let _connection = match lane {
            TransportLane::Control => {
                self.transport_counters
                    .control_connections_total
                    .fetch_add(1, Ordering::Relaxed);
                ActiveCounterGuard::enter(&self.transport_counters.control_connections_active)
            }
            TransportLane::Bulk => {
                self.transport_counters
                    .bulk_connections_total
                    .fetch_add(1, Ordering::Relaxed);
                ActiveCounterGuard::enter(&self.transport_counters.bulk_connections_active)
            }
        };
        let authenticated_node = Arc::new(RwLock::new(None::<String>));
        let data_stream_slots = Arc::new(Semaphore::new(match lane {
            TransportLane::Control => 48,
            TransportLane::Bulk => self.bulk_streams_per_connection,
        }));
        let raft_stream_slots = Arc::new(Semaphore::new(32));
        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let this = self.clone();
                    let context = StreamContext {
                        block_service: block_service.clone(),
                        authenticated_node: authenticated_node.clone(),
                        data_stream_slots: data_stream_slots.clone(),
                        raft_stream_slots: raft_stream_slots.clone(),
                        lane,
                    };
                    tokio::spawn(async move {
                        if let Err(error) = this.handle_stream(send, recv, context).await {
                            if is_expected_stream_cancellation(&error) {
                                match lane {
                                    TransportLane::Control => this
                                        .transport_counters
                                        .control_cancellations_total
                                        .fetch_add(1, Ordering::Relaxed),
                                    TransportLane::Bulk => this
                                        .transport_counters
                                        .bulk_cancellations_total
                                        .fetch_add(1, Ordering::Relaxed),
                                };
                                debug!(?lane, %error, "losing raced stream cancelled");
                            } else {
                                match lane {
                                    TransportLane::Control => this
                                        .transport_counters
                                        .control_errors_total
                                        .fetch_add(1, Ordering::Relaxed),
                                    TransportLane::Bulk => this
                                        .transport_counters
                                        .bulk_errors_total
                                        .fetch_add(1, Ordering::Relaxed),
                                };
                                warn!(?lane, %error, "stream handler failed");
                            }
                        }
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => return Ok(()),
                Err(quinn::ConnectionError::LocallyClosed) => return Ok(()),
                Err(error) => return Err(NetworkError::Connection(error)),
            }
        }
    }

    async fn handle_stream(
        &self,
        mut send: SendStream,
        mut recv: RecvStream,
        context: StreamContext,
    ) -> Result<(), NetworkError> {
        let request = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            read_frame::<proto::RequestEnvelope>(&mut recv),
        )
        .await
        .map_err(|_| NetworkError::DeadlineExceeded)??;
        let valid_lane = request.method == "/handshake"
            || matches!(context.lane, TransportLane::Bulk) == is_bulk_method(&request.method);
        if !valid_lane {
            return Err(NetworkError::UnsupportedMethod(request.method));
        }
        let _active_stream = match context.lane {
            TransportLane::Control => {
                self.transport_counters
                    .control_streams_total
                    .fetch_add(1, Ordering::Relaxed);
                ActiveCounterGuard::enter(&self.transport_counters.control_streams_active)
            }
            TransportLane::Bulk => {
                self.transport_counters
                    .bulk_streams_total
                    .fetch_add(1, Ordering::Relaxed);
                ActiveCounterGuard::enter(&self.transport_counters.bulk_streams_active)
            }
        };
        let _stream_permit = if is_raft_method(&request.method) {
            context.raft_stream_slots.acquire_owned().await
        } else {
            context.data_stream_slots.acquire_owned().await
        }
        .map_err(|_| NetworkError::RateLimited)?;
        let streamed_size = match request.method.as_str() {
            "/block/put_replica_stream" => {
                proto::BlockPutReplicaStreamRequest::decode(request.payload.as_slice())
                    .ok()
                    .and_then(|metadata| usize::try_from(metadata.encoded_size).ok())
                    .unwrap_or_default()
            }
            "/erasure/store_stripe_stream" => {
                proto::ErasureTransferRequest::decode(request.payload.as_slice())
                    .ok()
                    .and_then(|metadata| usize::try_from(metadata.encoded_size).ok())
                    .unwrap_or_default()
            }
            _ => 0,
        };
        let request_wire_bytes = request.encoded_len().saturating_add(streamed_size);
        if request.method == "/block/get_stream" {
            return self
                .process_streamed_get(
                    &request,
                    &mut send,
                    context.block_service,
                    &context.authenticated_node,
                    request_wire_bytes,
                )
                .await;
        }
        if request.method == "/block/get_range_stream" {
            return self
                .process_streamed_range_get(
                    &request,
                    &mut send,
                    context.block_service,
                    &context.authenticated_node,
                    request_wire_bytes,
                )
                .await;
        }
        let processed = match request.method.as_str() {
            "/block/put_replica_stream" => {
                self.process_streamed_replica(
                    &request,
                    &mut recv,
                    context.block_service,
                    &context.authenticated_node,
                )
                .await
            }
            "/erasure/store_stripe_stream" => {
                self.process_streamed_erasure(&request, &mut recv, &context.authenticated_node)
                    .await
            }
            _ => {
                self.process_request(&request, context.block_service, &context.authenticated_node)
                    .await
            }
        };
        if let Err(error) = &processed {
            self.log_rpc_failure_once(&request.method, error);
        }
        let mut response = match processed {
            Ok(payload) => proto::ResponseEnvelope {
                request_id: request.request_id,
                ok: true,
                error_code: String::new(),
                error_message: String::new(),
                payload,
                node_id: self.local_descriptor().node_id,
                public_key_hex: hex::encode(self.identity.public_key_bytes()),
                signature_hex: String::new(),
            },
            Err(error) => proto::ResponseEnvelope {
                request_id: request.request_id,
                ok: false,
                error_code: error_code(&error).to_string(),
                error_message: error.to_string(),
                payload: Vec::new(),
                node_id: self.local_descriptor().node_id,
                public_key_hex: hex::encode(self.identity.public_key_bytes()),
                signature_hex: String::new(),
            },
        };
        self.record_rpc(
            &request.node_id,
            &request.method,
            "inbound",
            request_wire_bytes,
            response.encoded_len(),
            !response.ok,
        );
        response.signature_hex =
            hex::encode(self.identity.sign(&response_signature_payload(&response)));
        write_frame(&mut send, &response).await?;
        Ok(())
    }

    async fn process_streamed_replica(
        &self,
        request: &proto::RequestEnvelope,
        recv: &mut RecvStream,
        block_service: Arc<dyn NetworkBlockService>,
        authenticated_node: &RwLock<Option<String>>,
    ) -> Result<Vec<u8>, NetworkError> {
        self.validate_request(request, authenticated_node).await?;
        let metadata = proto::BlockPutReplicaStreamRequest::decode(request.payload.as_slice())?;
        let expected_cid = Cid::from_str(&metadata.cid)
            .map_err(|error| NetworkError::BlockService(error.to_string()))?;
        let codec = if metadata.codec.is_empty() {
            CODEC_RAW
        } else {
            Codec::from_str(&metadata.codec)
                .map_err(|error| NetworkError::BlockService(error.to_string()))?
        };
        if expected_cid.codec != codec
            || metadata.size > 64 * 1024 * 1024
            || metadata.encoded_size > 64 * 1024 * 1024 + 1024
        {
            return Err(NetworkError::BlockService(
                "invalid streamed replica metadata".to_string(),
            ));
        }
        let encoded_size = usize::try_from(metadata.encoded_size).map_err(|_| {
            NetworkError::BlockService("streamed replica size does not fit usize".to_string())
        })?;
        if let Some(limiter) = &self.bulk_receive_bandwidth {
            limiter.reserve(encoded_size).await;
        }
        let mut payload = vec![0u8; encoded_size];
        tokio::time::timeout(self.bulk_request_timeout, recv.read_exact(&mut payload))
            .await
            .map_err(|_| NetworkError::DeadlineExceeded)??;
        self.transport_counters
            .bulk_bytes_received_total
            .fetch_add(encoded_size as u64, Ordering::Relaxed);
        let put = block_service
            .put_encoded_verified_replica(codec, &expected_cid, metadata.size, payload)
            .await?;
        if put.cid != expected_cid || put.size != metadata.size {
            return Err(NetworkError::BlockService(
                "stored streamed replica does not match request".to_string(),
            ));
        }
        let provider_record =
            make_provider_record(&self.local_descriptor(), &self.identity, &put.cid);
        encode_payload(proto::BlockPutReplicaResponse {
            cid: put.cid.to_string(),
            codec: put.codec.canonical_display(),
            size: put.size,
            already_existed: put.already_existed,
            provider_record_json: serde_json::to_string(&provider_record)?,
        })
    }

    async fn process_streamed_erasure(
        &self,
        request: &proto::RequestEnvelope,
        recv: &mut RecvStream,
        authenticated_node: &RwLock<Option<String>>,
    ) -> Result<Vec<u8>, NetworkError> {
        self.validate_request(request, authenticated_node).await?;
        let metadata = proto::ErasureTransferRequest::decode(request.payload.as_slice())?;
        validate_erasure_transfer_request(&metadata, true)?;
        let encoded_size = usize::try_from(metadata.encoded_size).map_err(|_| {
            NetworkError::BlockService("erasure stripe size does not fit usize".to_string())
        })?;
        let service = self.erasure_service.read().await.clone().ok_or_else(|| {
            NetworkError::BlockService("adaptive erasure service is disabled".to_string())
        })?;
        let (sender, receiver) = mpsc::channel(4);
        let producer = async {
            let mut remaining = encoded_size;
            while remaining > 0 {
                let chunk_len = remaining.min(ERASURE_STREAM_CHUNK_BYTES);
                if let Some(limiter) = &self.bulk_receive_bandwidth {
                    limiter.reserve(chunk_len).await;
                }
                let mut chunk = vec![0u8; chunk_len];
                tokio::time::timeout(self.bulk_request_timeout, recv.read_exact(&mut chunk))
                    .await
                    .map_err(|_| NetworkError::DeadlineExceeded)??;
                self.transport_counters
                    .bulk_bytes_received_total
                    .fetch_add(chunk_len as u64, Ordering::Relaxed);
                sender.send(chunk).await.map_err(|_| {
                    NetworkError::TransportTask("erasure stream consumer closed".to_string())
                })?;
                remaining -= chunk_len;
            }
            // `try_join!` retains the completed producer future until the
            // consumer finishes. Close the channel explicitly so a consumer
            // waiting for end-of-stream cannot deadlock with that retention.
            drop(sender);
            Ok::<_, NetworkError>(())
        };
        let consumer = service.store_stripe_stream(&request.node_id, metadata, receiver);
        let (_, response) = tokio::try_join!(producer, consumer)?;
        encode_payload(response)
    }

    async fn process_streamed_get(
        &self,
        request: &proto::RequestEnvelope,
        send: &mut SendStream,
        block_service: Arc<dyn NetworkBlockService>,
        authenticated_node: &RwLock<Option<String>>,
        request_wire_bytes: usize,
    ) -> Result<(), NetworkError> {
        let processed = async {
            self.validate_request(request, authenticated_node).await?;
            let request = proto::BlockGetRequest::decode(request.payload.as_slice())?;
            let cid = Cid::from_str(&request.cid)
                .map_err(|error| NetworkError::BlockService(error.to_string()))?;
            let payload = block_service.get_block(&cid).await?;
            if payload.len() > 64 * 1024 * 1024 || !cid.verify(&payload) {
                return Err(NetworkError::BlockService(
                    "bulk block service returned an invalid payload".to_string(),
                ));
            }
            let metadata = encode_payload(proto::BlockGetStreamResponse {
                cid: cid.to_string(),
                size: payload.len() as u64,
            })?;
            Ok::<_, NetworkError>((metadata, payload))
        }
        .await;
        if let Err(error) = &processed {
            self.log_rpc_failure_once(&request.method, error);
        }
        let (ok, payload, bulk_payload, error_code_value, error_message) = match processed {
            Ok((metadata, payload)) => {
                (true, metadata, Some(payload), String::new(), String::new())
            }
            Err(error) => (
                false,
                Vec::new(),
                None,
                error_code(&error).to_string(),
                error.to_string(),
            ),
        };
        let mut response = proto::ResponseEnvelope {
            request_id: request.request_id.clone(),
            ok,
            error_code: error_code_value,
            error_message,
            payload,
            node_id: self.local_descriptor().node_id,
            public_key_hex: hex::encode(self.identity.public_key_bytes()),
            signature_hex: String::new(),
        };
        response.signature_hex =
            hex::encode(self.identity.sign(&response_signature_payload(&response)));
        let response_bytes = response
            .encoded_len()
            .saturating_add(bulk_payload.as_ref().map_or(0, Vec::len));
        self.record_rpc(
            &request.node_id,
            &request.method,
            "inbound",
            request_wire_bytes,
            response_bytes,
            !ok,
        );
        write_frame_open(send, &response).await?;
        if let Some(payload) = bulk_payload {
            if let Some(limiter) = &self.bulk_send_bandwidth {
                limiter.reserve(payload.len()).await;
            }
            send.write_all(&payload).await?;
            self.transport_counters
                .bulk_bytes_sent_total
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
        }
        send.finish()?;
        Ok(())
    }

    async fn process_streamed_range_get(
        &self,
        request: &proto::RequestEnvelope,
        send: &mut SendStream,
        block_service: Arc<dyn NetworkBlockService>,
        authenticated_node: &RwLock<Option<String>>,
        request_wire_bytes: usize,
    ) -> Result<(), NetworkError> {
        let processed = async {
            self.validate_request(request, authenticated_node).await?;
            let range = proto::BlockGetRangeRequest::decode(request.payload.as_slice())?;
            let cid = Cid::from_str(&range.cid)
                .map_err(|error| NetworkError::BlockService(error.to_string()))?;
            if range.start >= range.end || range.end > 64 * 1024 * 1024 {
                return Err(NetworkError::BlockService(
                    "invalid streamed block range".to_string(),
                ));
            }
            let payload = block_service
                .get_block_range(&cid, range.start, range.end)
                .await?;
            if payload.len() as u64 != range.end - range.start {
                return Err(NetworkError::BlockService(
                    "bulk block service returned an invalid range length".to_string(),
                ));
            }
            let metadata = encode_payload(proto::BlockGetRangeStreamResponse {
                cid: cid.to_string(),
                start: range.start,
                end: range.end,
                size: payload.len() as u64,
            })?;
            Ok::<_, NetworkError>((metadata, payload))
        }
        .await;
        if let Err(error) = &processed {
            self.log_rpc_failure_once(&request.method, error);
        }
        let (ok, payload, bulk_payload, error_code_value, error_message) = match processed {
            Ok((metadata, payload)) => {
                (true, metadata, Some(payload), String::new(), String::new())
            }
            Err(error) => (
                false,
                Vec::new(),
                None,
                error_code(&error).to_string(),
                error.to_string(),
            ),
        };
        let mut response = proto::ResponseEnvelope {
            request_id: request.request_id.clone(),
            ok,
            error_code: error_code_value,
            error_message,
            payload,
            node_id: self.local_descriptor().node_id,
            public_key_hex: hex::encode(self.identity.public_key_bytes()),
            signature_hex: String::new(),
        };
        response.signature_hex =
            hex::encode(self.identity.sign(&response_signature_payload(&response)));
        let response_bytes = response
            .encoded_len()
            .saturating_add(bulk_payload.as_ref().map_or(0, Vec::len));
        self.record_rpc(
            &request.node_id,
            &request.method,
            "inbound",
            request_wire_bytes,
            response_bytes,
            !ok,
        );
        write_frame_open(send, &response).await?;
        if let Some(payload) = bulk_payload {
            if let Some(limiter) = &self.bulk_send_bandwidth {
                limiter.reserve(payload.len()).await;
            }
            send.write_all(&payload).await?;
            self.transport_counters
                .bulk_bytes_sent_total
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
        }
        send.finish()?;
        Ok(())
    }

    async fn process_request(
        &self,
        request: &proto::RequestEnvelope,
        block_service: Arc<dyn NetworkBlockService>,
        authenticated_node: &RwLock<Option<String>>,
    ) -> Result<Vec<u8>, NetworkError> {
        self.validate_request(request, authenticated_node).await?;
        self.dispatch_request(request, block_service, authenticated_node)
            .await
    }

    async fn validate_request(
        &self,
        request: &proto::RequestEnvelope,
        authenticated_node: &RwLock<Option<String>>,
    ) -> Result<(), NetworkError> {
        if request.protocol_version != PROTOCOL_VERSION {
            return Err(NetworkError::Rpc {
                code: "unsupported_protocol".to_string(),
                message: format!("unsupported protocol version {}", request.protocol_version),
            });
        }
        self.verify_request_auth(request)?;
        if !is_raft_method(&request.method) {
            self.check_rate_limit(&request.node_id, is_bulk_method(&request.method))?;
        }
        self.check_replay(request)?;
        let method_payload_limit = if request.method == "/block/put_replica" {
            65 * 1024 * 1024
        } else {
            4 * 1024 * 1024
        };
        if request.payload.len() > method_payload_limit {
            return Err(NetworkError::BlockService(
                "RPC method payload exceeds limit".to_string(),
            ));
        }
        if request.method != "/handshake" {
            let authenticated = authenticated_node.read().await;
            if authenticated.as_deref() != Some(request.node_id.as_str()) {
                return Err(NetworkError::Unauthenticated);
            }
        }
        Ok(())
    }

    async fn dispatch_request(
        &self,
        request: &proto::RequestEnvelope,
        block_service: Arc<dyn NetworkBlockService>,
        authenticated_node: &RwLock<Option<String>>,
    ) -> Result<Vec<u8>, NetworkError> {
        match request.method.as_str() {
            "/handshake" => {
                let handshake = proto::HandshakeRequest::decode(request.payload.as_slice())?;
                let descriptor = handshake.descriptor.ok_or_else(|| {
                    NetworkError::InvalidDescriptor("missing descriptor".to_string())
                })?;
                if descriptor.node_id != request.node_id {
                    return Err(NetworkError::Unauthenticated);
                }
                self.record_descriptor(&descriptor).await?;
                *authenticated_node.write().await = Some(descriptor.node_id.clone());
                encode_payload(proto::HandshakeResponse {
                    descriptor: Some(self.local_descriptor()),
                })
            }
            "/node/info" => encode_payload(proto::NodeInfoResponse {
                descriptor: Some(self.local_descriptor()),
            }),
            "/node/peers" => {
                let peers = self
                    .peers()
                    .await
                    .into_iter()
                    .map(|peer| proto::PeerInfo {
                        node_id: peer.node_id,
                        name: peer.name,
                        addresses: peer.addresses,
                        bulk_addresses: peer.bulk_addresses,
                        last_seen_unix_seconds: peer.last_seen_unix_seconds,
                        connected: peer.connected,
                        failure_domain: peer.failure_domain.unwrap_or_default(),
                        placement_labels: peer.placement_labels,
                        storage_capacity_bytes: peer.storage_capacity_bytes,
                        storage_available_bytes: peer.storage_available_bytes,
                        namespace_consensus_enabled: peer.namespace_consensus_enabled,
                        namespace_group_capacity: peer.namespace_group_capacity,
                        namespace_group_count: peer.namespace_group_count,
                        max_consensus_log_bytes: peer.max_consensus_log_bytes,
                        max_namespace_write_rate: peer.max_namespace_write_rate,
                    })
                    .collect();
                encode_payload(proto::ListPeersResponse { peers })
            }
            "/namespace/discover" => {
                let namespace_request =
                    proto::NamespaceDiscoverRequest::decode(request.payload.as_slice())?;
                let service = self.namespace_service.read().await.clone().ok_or_else(|| {
                    NetworkError::BlockService("namespace service is disabled".to_string())
                })?;
                let records = service
                    .discover(&request.node_id, namespace_request.namespace_id)
                    .await?;
                encode_payload(proto::NamespaceDiscoverResponse { records })
            }
            "/namespace/announce" => {
                let namespace_request =
                    proto::NamespaceAnnounceRequest::decode(request.payload.as_slice())?;
                let record = namespace_request.record.ok_or_else(|| {
                    NetworkError::BlockService("missing namespace discovery record".to_string())
                })?;
                if record.announcer_node_id != request.node_id {
                    return Err(NetworkError::Unauthenticated);
                }
                self.verify_namespace_discovery_record(&record)?;
                let service = self.namespace_service.read().await.clone().ok_or_else(|| {
                    NetworkError::BlockService("namespace service is disabled".to_string())
                })?;
                service.announce(&request.node_id, record).await?;
                encode_payload(proto::NamespaceAnnounceResponse { accepted: true })
            }
            "/namespace/alias/resolve" => {
                let alias_request =
                    proto::NamespaceAliasResolveRequest::decode(request.payload.as_slice())?;
                if alias_request.alias.is_empty() || alias_request.alias.len() > 256 {
                    return Err(NetworkError::BlockService(
                        "invalid namespace alias lookup".to_string(),
                    ));
                }
                let service = self
                    .namespace_alias_service
                    .read()
                    .await
                    .clone()
                    .ok_or_else(|| {
                        NetworkError::BlockService(
                            "namespace alias service is disabled".to_string(),
                        )
                    })?;
                let namespace_id = service
                    .resolve(&request.node_id, alias_request.alias)
                    .await?;
                encode_payload(proto::NamespaceAliasResolveResponse {
                    found: namespace_id.is_some(),
                    namespace_id: namespace_id.unwrap_or_default(),
                })
            }
            "/namespace/alias/list" => {
                let _ = proto::NamespaceAliasListRequest::decode(request.payload.as_slice())?;
                let service = self
                    .namespace_alias_service
                    .read()
                    .await
                    .clone()
                    .ok_or_else(|| {
                        NetworkError::BlockService(
                            "namespace alias service is disabled".to_string(),
                        )
                    })?;
                let aliases = service
                    .list(&request.node_id)
                    .await?
                    .into_iter()
                    .map(|(alias, namespace_id)| proto::NamespaceAliasRecord {
                        alias,
                        namespace_id,
                    })
                    .collect();
                encode_payload(proto::NamespaceAliasListResponse { aliases })
            }
            "/namespace/raft/vote"
            | "/namespace/raft/append"
            | "/namespace/raft/install_snapshot" => {
                let namespace_request =
                    proto::NamespaceRaftRequest::decode(request.payload.as_slice())?;
                validate_namespace_context(request, namespace_request.context.as_ref())?;
                if namespace_request.request_json.len() > 1024 * 1024 {
                    return Err(NetworkError::BlockService(
                        "namespace Raft request exceeds limit".to_string(),
                    ));
                }
                let service = self.namespace_service.read().await.clone().ok_or_else(|| {
                    NetworkError::BlockService("namespace service is disabled".to_string())
                })?;
                let response_json = match request.method.as_str() {
                    "/namespace/raft/vote" => {
                        service
                            .raft_vote(&request.node_id, namespace_request)
                            .await?
                    }
                    "/namespace/raft/append" => {
                        service
                            .raft_append(&request.node_id, namespace_request)
                            .await?
                    }
                    _ => {
                        service
                            .raft_install_snapshot(&request.node_id, namespace_request)
                            .await?
                    }
                };
                encode_payload(proto::NamespaceRaftResponse { response_json })
            }
            "/namespace/bootstrap" => {
                let namespace_request =
                    proto::NamespaceBootstrapRequest::decode(request.payload.as_slice())?;
                if namespace_request.namespace_id.len() > 256
                    || namespace_request.checkpoint_cid.len() > 256
                    || namespace_request.membership_epoch == 0
                {
                    return Err(NetworkError::BlockService(
                        "invalid namespace bootstrap request".to_string(),
                    ));
                }
                let service = self.namespace_service.read().await.clone().ok_or_else(|| {
                    NetworkError::BlockService("namespace service is disabled".to_string())
                })?;
                let response = service
                    .bootstrap(&request.node_id, namespace_request)
                    .await?;
                encode_payload(response)
            }
            "/namespace/forward" => {
                let namespace_request =
                    proto::NamespaceForwardRequest::decode(request.payload.as_slice())?;
                validate_namespace_context(request, namespace_request.context.as_ref())?;
                if namespace_request.command_json.len() > 1024 * 1024
                    || namespace_request.application_guard_json.len() > 64 * 1024
                {
                    return Err(NetworkError::BlockService(
                        "namespace forwarded command exceeds limit".to_string(),
                    ));
                }
                let service = self.namespace_service.read().await.clone().ok_or_else(|| {
                    NetworkError::BlockService("namespace service is disabled".to_string())
                })?;
                let response = service.forward(&request.node_id, namespace_request).await?;
                encode_payload(response)
            }
            "/namespace/sqlite-writer" => {
                let namespace_request =
                    proto::NamespaceSqliteWriterRequest::decode(request.payload.as_slice())?;
                validate_namespace_context(request, namespace_request.context.as_ref())?;
                if namespace_request.request_json.len() > 64 * 1024 {
                    return Err(NetworkError::BlockService(
                        "SQLite writer request exceeds limit".to_string(),
                    ));
                }
                let service = self.namespace_service.read().await.clone().ok_or_else(|| {
                    NetworkError::BlockService("namespace service is disabled".to_string())
                })?;
                let response = service
                    .sqlite_writer(&request.node_id, namespace_request)
                    .await?;
                if response.response_json.len() > 64 * 1024 {
                    return Err(NetworkError::BlockService(
                        "SQLite writer response exceeds limit".to_string(),
                    ));
                }
                encode_payload(response)
            }
            "/namespace/state" => {
                let namespace_request =
                    proto::NamespaceStateRequest::decode(request.payload.as_slice())?;
                validate_namespace_context(request, namespace_request.context.as_ref())?;
                let service = self.namespace_service.read().await.clone().ok_or_else(|| {
                    NetworkError::BlockService("namespace service is disabled".to_string())
                })?;
                let response = service.state(&request.node_id, namespace_request).await?;
                encode_payload(response)
            }
            "/erasure/encode_parity" => {
                let transfer = proto::ErasureTransferRequest::decode(request.payload.as_slice())?;
                validate_erasure_transfer_request(&transfer, false)?;
                let service = self.erasure_service.read().await.clone().ok_or_else(|| {
                    NetworkError::BlockService("adaptive erasure service is disabled".to_string())
                })?;
                encode_payload(service.encode_parity(&request.node_id, transfer).await?)
            }
            "/repair/inventory_push" => {
                let push = proto::RepairInventoryPushRequest::decode(request.payload.as_slice())?;
                if push.inventory_json.len() > 1024 * 1024 {
                    return Err(NetworkError::BlockService(
                        "repair inventory exceeds limit".to_string(),
                    ));
                }
                let service = self.erasure_service.read().await.clone().ok_or_else(|| {
                    NetworkError::BlockService("repair service is disabled".to_string())
                })?;
                service
                    .push_repair_inventory(&request.node_id, push.inventory_json)
                    .await?;
                encode_payload(proto::RepairInventoryPushResponse { accepted: true })
            }
            "/repair/execute" => {
                let execute = proto::RepairExecuteRequest::decode(request.payload.as_slice())?;
                if execute.task_json.len() > 4 * 1024 * 1024 {
                    return Err(NetworkError::BlockService(
                        "repair task exceeds limit".to_string(),
                    ));
                }
                let service = self.erasure_service.read().await.clone().ok_or_else(|| {
                    NetworkError::BlockService("repair service is disabled".to_string())
                })?;
                encode_payload(
                    service
                        .execute_repair(&request.node_id, execute.task_json)
                        .await?,
                )
            }
            "/repair/cleanup_extra" => {
                let cleanup = proto::RepairCleanupExtraRequest::decode(request.payload.as_slice())?;
                if cleanup.exception_json.len() > 1024 * 1024 {
                    return Err(NetworkError::BlockService(
                        "repair cleanup record exceeds limit".to_string(),
                    ));
                }
                let service = self.erasure_service.read().await.clone().ok_or_else(|| {
                    NetworkError::BlockService("repair service is disabled".to_string())
                })?;
                let removed = service
                    .cleanup_repair_extra(&request.node_id, cleanup.exception_json)
                    .await?;
                encode_payload(proto::RepairCleanupExtraResponse { removed })
            }
            "/block/has" => {
                let block_request = proto::BlockHasRequest::decode(request.payload.as_slice())?;
                let cid = Cid::from_str(&block_request.cid)
                    .map_err(|error| NetworkError::BlockService(error.to_string()))?;
                encode_payload(proto::BlockHasResponse {
                    has: block_service.has_block(&cid).await?,
                })
            }
            "/block/has_batch" => {
                let block_request =
                    proto::BlockHasBatchRequest::decode(request.payload.as_slice())?;
                if block_request.cids.is_empty()
                    || block_request.cids.len() > MAX_BLOCK_HAS_BATCH_CIDS
                {
                    return Err(NetworkError::BlockService(format!(
                        "block health batch must contain between 1 and {MAX_BLOCK_HAS_BATCH_CIDS} CIDs"
                    )));
                }
                let cids = block_request
                    .cids
                    .iter()
                    .map(|cid| {
                        Cid::from_str(cid)
                            .map_err(|error| NetworkError::BlockService(error.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let present = block_service.has_blocks(&cids).await?;
                if present.len() != cids.len() {
                    return Err(NetworkError::BlockService(
                        "block service returned an invalid health batch length".to_string(),
                    ));
                }
                encode_payload(proto::BlockHasBatchResponse { present })
            }
            "/block/get" => {
                let block_request = proto::BlockGetRequest::decode(request.payload.as_slice())?;
                let cid = Cid::from_str(&block_request.cid)
                    .map_err(|error| NetworkError::BlockService(error.to_string()))?;
                let payload = block_service.get_block(&cid).await?;
                encode_payload(proto::BlockGetResponse {
                    cid: cid.to_string(),
                    codec: cid.codec.canonical_display(),
                    payload,
                })
            }
            "/relay/block_get" => {
                let relay_request =
                    proto::RelayBlockGetRequest::decode(request.payload.as_slice())?;
                let cid = Cid::from_str(&relay_request.cid)
                    .map_err(|error| NetworkError::BlockService(error.to_string()))?;
                let target = self
                    .peers()
                    .await
                    .into_iter()
                    .find(|peer| peer.node_id == relay_request.target_node_id)
                    .ok_or_else(|| {
                        NetworkError::BlockService("relay target not found".to_string())
                    })?;
                for address in sorted_routable_addresses(target.addresses) {
                    let Ok(addr) = address.parse::<SocketAddr>() else {
                        continue;
                    };
                    match self.block_get(addr, &cid).await {
                        Ok(payload) => {
                            return encode_payload(proto::RelayBlockGetResponse {
                                cid: cid.to_string(),
                                payload,
                            });
                        }
                        Err(error) => debug!(%addr, %error, "relay target block get failed"),
                    }
                }
                Err(NetworkError::BlockService(
                    "relay target block unavailable".to_string(),
                ))
            }
            "/block/put_replica" => {
                let block_request =
                    proto::BlockPutReplicaRequest::decode(request.payload.as_slice())?;
                let codec = if block_request.codec.is_empty() {
                    CODEC_RAW
                } else {
                    Codec::from_str(&block_request.codec)
                        .map_err(|error| NetworkError::BlockService(error.to_string()))?
                };
                let put = block_service
                    .put_replica(codec, block_request.payload)
                    .await?;
                let provider_record =
                    make_provider_record(&self.local_descriptor(), &self.identity, &put.cid);
                self.persist_provider_record(&provider_record)?;
                encode_payload(proto::BlockPutReplicaResponse {
                    cid: put.cid.to_string(),
                    codec: put.codec.canonical_display(),
                    size: put.size,
                    already_existed: put.already_existed,
                    provider_record_json: serde_json::to_string(&provider_record)?,
                })
            }
            "/block/providers" => {
                let provider_request =
                    proto::BlockProvidersRequest::decode(request.payload.as_slice())?;
                let cid = Cid::from_str(&provider_request.cid)
                    .map_err(|error| NetworkError::BlockService(error.to_string()))?;
                let mut provider_records = self.local_provider_records(&cid)?;
                if block_service.has_block(&cid).await? {
                    provider_records.push(make_provider_record(
                        &self.local_descriptor(),
                        &self.identity,
                        &cid,
                    ));
                }
                provider_records.sort_by(|left, right| left.node_id.cmp(&right.node_id));
                provider_records
                    .dedup_by(|left, right| left.node_id == right.node_id && left.cid == right.cid);
                let provider_record_json = provider_records
                    .into_iter()
                    .filter(|record| record.expires_at_unix_seconds > unix_seconds())
                    .map(|record| serde_json::to_string(&record))
                    .collect::<Result<Vec<_>, _>>()?;
                encode_payload(proto::BlockProvidersResponse {
                    provider_record_json,
                })
            }
            "/block/announce_provider" => {
                let announce =
                    proto::BlockAnnounceProviderRequest::decode(request.payload.as_slice())?;
                let record: ProviderRecord = serde_json::from_str(&announce.provider_record_json)?;
                self.persist_provider_record(&record)?;
                encode_payload(proto::BlockAnnounceProviderResponse { accepted: true })
            }
            "/block/announce_provider_batch" => {
                let request =
                    proto::BlockAnnounceProviderBatchRequest::decode(request.payload.as_slice())?;
                if request.provider_record_json.is_empty()
                    || request.provider_record_json.len() > 64
                {
                    return Err(NetworkError::BlockService(
                        "provider batch must contain between 1 and 64 records".to_string(),
                    ));
                }
                let records = request
                    .provider_record_json
                    .into_iter()
                    .map(|record| serde_json::from_str::<ProviderRecord>(&record))
                    .collect::<Result<Vec<_>, _>>()?;
                self.persist_provider_records(&records)?;
                encode_payload(proto::BlockAnnounceProviderBatchResponse {
                    accepted: records.len() as u64,
                })
            }
            "/pin/apply" => {
                let pin_service =
                    self.pin_service
                        .read()
                        .await
                        .clone()
                        .ok_or_else(|| NetworkError::Rpc {
                            code: "pin_unavailable".to_string(),
                            message: "pin service is not available".to_string(),
                        })?;
                let apply = proto::PinApplyRequest::decode(request.payload.as_slice())?;
                pin_service
                    .apply(&request.node_id, apply.pin_record_json)
                    .await?;
                encode_payload(proto::PinApplyResponse { accepted: true })
            }
            "/compute/offer" => {
                let compute =
                    self.compute_service
                        .read()
                        .await
                        .clone()
                        .ok_or_else(|| NetworkError::Rpc {
                            code: "compute_unavailable".to_string(),
                            message: "compute service is not available".to_string(),
                        })?;
                let offer = proto::ComputeOfferRequest::decode(request.payload.as_slice())?;
                encode_payload(compute.offer(offer.spec_json).await?)
            }
            "/compute/submit" => {
                let compute =
                    self.compute_service
                        .read()
                        .await
                        .clone()
                        .ok_or_else(|| NetworkError::Rpc {
                            code: "compute_unavailable".to_string(),
                            message: "compute service is not available".to_string(),
                        })?;
                let submit = proto::ComputeSubmitRequest::decode(request.payload.as_slice())?;
                encode_payload(compute.submit(submit.job_id, submit.spec_json).await?)
            }
            "/compute/status" => {
                let compute =
                    self.compute_service
                        .read()
                        .await
                        .clone()
                        .ok_or_else(|| NetworkError::Rpc {
                            code: "compute_unavailable".to_string(),
                            message: "compute service is not available".to_string(),
                        })?;
                let status = proto::ComputeStatusRequest::decode(request.payload.as_slice())?;
                encode_payload(compute.status(status.job_id).await?)
            }
            "/compute/logs" => {
                let compute =
                    self.compute_service
                        .read()
                        .await
                        .clone()
                        .ok_or_else(|| NetworkError::Rpc {
                            code: "compute_unavailable".to_string(),
                            message: "compute service is not available".to_string(),
                        })?;
                let logs = proto::ComputeLogsRequest::decode(request.payload.as_slice())?;
                encode_payload(compute.logs(logs.job_id).await?)
            }
            "/compute/cancel" => {
                let compute =
                    self.compute_service
                        .read()
                        .await
                        .clone()
                        .ok_or_else(|| NetworkError::Rpc {
                            code: "compute_unavailable".to_string(),
                            message: "compute service is not available".to_string(),
                        })?;
                let cancel = proto::ComputeCancelRequest::decode(request.payload.as_slice())?;
                encode_payload(compute.cancel(cancel.job_id).await?)
            }
            other => Err(NetworkError::UnsupportedMethod(other.to_string())),
        }
    }

    fn check_rate_limit(&self, key: &str, bulk: bool) -> Result<(), NetworkError> {
        let Some(limit) = self.requests_per_minute else {
            return Ok(());
        };
        let now = unix_seconds();
        let window_start = now - now.rem_euclid(60);
        let limits = if bulk {
            &self.bulk_rate_limits
        } else {
            &self.rate_limits
        };
        let mut limits = limits
            .lock()
            .map_err(|_| NetworkError::BlockService("rate limiter lock poisoned".to_string()))?;
        limits.retain(|_, bucket| bucket.window_start_unix_seconds >= window_start - 60);
        if !limits.contains_key(key) && limits.len() >= 10_000 {
            return Err(NetworkError::RateLimited);
        }
        let bucket = limits.entry(key.to_string()).or_insert(RateLimitBucket {
            window_start_unix_seconds: window_start,
            count: 0,
        });
        if bucket.window_start_unix_seconds != window_start {
            bucket.window_start_unix_seconds = window_start;
            bucket.count = 0;
        }
        bucket.count = bucket.count.saturating_add(1);
        if bucket.count > limit {
            return Err(NetworkError::RateLimited);
        }
        Ok(())
    }

    fn verify_request_auth(&self, request: &proto::RequestEnvelope) -> Result<(), NetworkError> {
        let now = unix_seconds();
        if (now - request.auth_timestamp_unix_seconds).abs() > 60 {
            return Err(NetworkError::Unauthenticated);
        }
        let public_key = hex::decode(&request.public_key_hex)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(NetworkError::Unauthenticated)?;
        if derive_node_id(&public_key) != request.node_id {
            return Err(NetworkError::Unauthenticated);
        }
        let signature = hex::decode(&request.identity_signature_hex)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(NetworkError::Unauthenticated)?;
        if !verify_signature(&public_key, &request_identity_payload(request), &signature) {
            return Err(NetworkError::Unauthenticated);
        }
        if let Some(secret) = &self.cluster_secret {
            if request.auth_signature_hex.is_empty() {
                return Err(NetworkError::Unauthenticated);
            }
            let expected = sign_request_envelope(secret, request);
            if !constant_time_eq(expected.as_bytes(), request.auth_signature_hex.as_bytes()) {
                return Err(NetworkError::Unauthenticated);
            }
        }
        Ok(())
    }

    fn check_replay(&self, request: &proto::RequestEnvelope) -> Result<(), NetworkError> {
        let now = unix_seconds();
        let mut hasher = blake3::Hasher::new();
        hasher.update(request.node_id.as_bytes());
        hasher.update(&[0]);
        hasher.update(request.request_id.as_bytes());
        let mut key = [0u8; 16];
        key.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        let seen = if is_bulk_method(&request.method) {
            &self.bulk_seen_requests
        } else {
            &self.seen_requests
        };
        let mut seen = seen.lock().map_err(|_| NetworkError::Unauthenticated)?;
        seen.admit(now, key, self.replay_capacity)
    }

    async fn record_descriptor(
        &self,
        descriptor: &proto::NodeDescriptor,
    ) -> Result<(), NetworkError> {
        verify_descriptor(descriptor)?;
        let node_id = descriptor.node_id.clone();
        let tls_digest = descriptor.tls_certificate_digest_hex.clone();
        self.peer_tls_digests.rcu(|current| {
            let mut updated = (**current).clone();
            updated.insert(node_id.clone(), tls_digest.clone());
            Arc::new(updated)
        });
        // Main endpoint pools can be pruned eagerly. Isolated per-core pools
        // share `peer_tls_digests` and reject the old incarnation lazily on
        // their next lock-free lookup.
        for pool in [
            &self.outbound_control_connections,
            &self.outbound_bulk_connections,
        ] {
            pool.lock().await.retain(|_, connection| {
                connection.peer_node_id != descriptor.node_id
                    || connection.peer_tls_certificate_digest_hex
                        == descriptor.tls_certificate_digest_hex
            });
        }
        let status = PeerStatus {
            node_id: descriptor.node_id.clone(),
            name: descriptor.name.clone(),
            addresses: descriptor.addresses.clone(),
            bulk_addresses: descriptor.bulk_addresses.clone(),
            last_seen_unix_seconds: unix_seconds(),
            connected: true,
            failure_domain: if descriptor.failure_domain.is_empty() {
                None
            } else {
                Some(descriptor.failure_domain.clone())
            },
            placement_labels: descriptor.placement_labels.clone(),
            storage_capacity_bytes: descriptor.storage_capacity_bytes,
            storage_available_bytes: descriptor.storage_available_bytes,
            namespace_consensus_enabled: descriptor.namespace_consensus_enabled,
            namespace_group_capacity: descriptor.namespace_group_capacity,
            namespace_group_count: descriptor.namespace_group_count,
            max_consensus_log_bytes: descriptor.max_consensus_log_bytes,
            max_namespace_write_rate: descriptor.max_namespace_write_rate,
        };
        self.peers
            .write()
            .await
            .insert(descriptor.node_id.clone(), status.clone());
        self.persist_peer(descriptor, status.last_seen_unix_seconds)?;
        self.prune_routing_table().await;
        Ok(())
    }

    fn persist_peer(
        &self,
        descriptor: &proto::NodeDescriptor,
        last_seen_unix_seconds: i64,
    ) -> Result<(), NetworkError> {
        let write_txn = self
            .metadata
            .database()
            .begin_write()
            .map_err(|source| NetworkError::Transaction(Box::new(source)))?;
        {
            let mut nodes = write_txn
                .open_table(NODES)
                .map_err(|source| NetworkError::Table(Box::new(source)))?;
            let stored = StoredPeer {
                node_id: descriptor.node_id.clone(),
                name: descriptor.name.clone(),
                addresses: descriptor.addresses.clone(),
                bulk_addresses: descriptor.bulk_addresses.clone(),
                public_key_hex: descriptor.public_key_hex.clone(),
                tls_certificate_digest_hex: descriptor.tls_certificate_digest_hex.clone(),
                last_seen_unix_seconds,
                failure_domain: if descriptor.failure_domain.is_empty() {
                    None
                } else {
                    Some(descriptor.failure_domain.clone())
                },
                placement_labels: descriptor.placement_labels.clone(),
                storage_capacity_bytes: descriptor.storage_capacity_bytes,
                storage_available_bytes: descriptor.storage_available_bytes,
                namespace_consensus_enabled: descriptor.namespace_consensus_enabled,
                namespace_group_capacity: descriptor.namespace_group_capacity,
                namespace_group_count: descriptor.namespace_group_count,
                max_consensus_log_bytes: descriptor.max_consensus_log_bytes,
                max_namespace_write_rate: descriptor.max_namespace_write_rate,
            };
            let bytes = serde_json::to_vec(&stored)?;
            nodes
                .insert(descriptor.node_id.as_str(), bytes.as_slice())
                .map_err(|source| NetworkError::RedbStorage(Box::new(source)))?;
        }
        write_txn
            .commit()
            .map_err(|source| NetworkError::Commit(Box::new(source)))?;
        Ok(())
    }

    fn validate_provider_record(&self, record: &ProviderRecord) -> Result<(), NetworkError> {
        if record.expires_at_unix_seconds <= unix_seconds()
            || record.expires_at_unix_seconds > unix_seconds() + 48 * 60 * 60
            || record.addresses.len() > 16
            || record
                .addresses
                .iter()
                .any(|address| !is_usable_address(address))
        {
            return Err(NetworkError::InvalidDescriptor(
                "provider record is expired".to_string(),
            ));
        }
        let public_key_hex = if record.node_id == self.local_descriptor().node_id {
            self.local_descriptor().public_key_hex
        } else {
            self.peer_public_key_hex(&record.node_id)?.ok_or_else(|| {
                NetworkError::InvalidDescriptor(format!(
                    "provider node {} is unknown",
                    record.node_id
                ))
            })?
        };
        let public_key = hex::decode(&public_key_hex).map_err(|error| {
            NetworkError::InvalidDescriptor(format!("invalid provider public key: {error}"))
        })?;
        let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
            NetworkError::InvalidDescriptor("provider public key must be 32 bytes".to_string())
        })?;
        let signature = hex::decode(&record.signature_hex).map_err(|error| {
            NetworkError::InvalidDescriptor(format!("invalid provider signature: {error}"))
        })?;
        let signature: [u8; 64] = signature.try_into().map_err(|_| {
            NetworkError::InvalidDescriptor("provider signature must be 64 bytes".to_string())
        })?;
        if !verify_signature(
            &public_key,
            &provider_record_signature_payload(record),
            &signature,
        ) {
            return Err(NetworkError::InvalidDescriptor(
                "provider record signature verification failed".to_string(),
            ));
        }
        Ok(())
    }

    fn peer_public_key_hex(&self, node_id: &str) -> Result<Option<String>, NetworkError> {
        let read_txn = self
            .metadata
            .database()
            .begin_read()
            .map_err(|source| NetworkError::Transaction(Box::new(source)))?;
        let table = read_txn
            .open_table(NODES)
            .map_err(|source| NetworkError::Table(Box::new(source)))?;
        let value = table
            .get(node_id)
            .map_err(|source| NetworkError::RedbStorage(Box::new(source)))?;
        value
            .map(|value| {
                serde_json::from_slice::<StoredPeer>(value.value()).map(|peer| peer.public_key_hex)
            })
            .transpose()
            .map_err(NetworkError::from)
    }
}

fn is_expected_stream_cancellation(error: &NetworkError) -> bool {
    matches!(
        error,
        NetworkError::Write(quinn::WriteError::Stopped(code)) if code.into_inner() == 0
    )
}

fn make_descriptor(
    config: &NetworkConfig,
    identity: &NodeIdentity,
    tls_certificate_digest_hex: String,
) -> proto::NodeDescriptor {
    let public_key_hex = hex::encode(identity.public_key_bytes());
    let mut descriptor = proto::NodeDescriptor {
        node_id: identity.node_id().to_string(),
        name: config.node_name.clone(),
        addresses: vec![config.advertise_addr.to_string()],
        public_key_hex,
        signature_hex: String::new(),
        failure_domain: config.failure_domain.clone().unwrap_or_default(),
        placement_labels: config.placement_labels.clone(),
        storage_capacity_bytes: config.storage_capacity_bytes,
        storage_available_bytes: config.storage_available_bytes,
        tls_certificate_digest_hex,
        namespace_consensus_enabled: config.namespace_consensus_enabled,
        namespace_group_capacity: config.namespace_group_capacity,
        namespace_group_count: config.namespace_group_count,
        max_consensus_log_bytes: config.max_consensus_log_bytes,
        max_namespace_write_rate: config.max_namespace_write_rate,
        bulk_addresses: vec![config.bulk_advertise_addr.to_string()],
    };
    let signature = identity.sign(&descriptor_signature_payload(&descriptor));
    descriptor.signature_hex = hex::encode(signature);
    descriptor
}

fn make_provider_record(
    descriptor: &proto::NodeDescriptor,
    identity: &NodeIdentity,
    cid: &Cid,
) -> ProviderRecord {
    let mut record = ProviderRecord {
        cid: cid.clone(),
        node_id: descriptor.node_id.clone(),
        addresses: descriptor.addresses.clone(),
        expires_at_unix_seconds: unix_seconds() + 24 * 60 * 60,
        signature_hex: String::new(),
    };
    let signature = identity.sign(&provider_record_signature_payload(&record));
    record.signature_hex = hex::encode(signature);
    record
}

fn append_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

pub fn provider_record_signature_payload(record: &ProviderRecord) -> Vec<u8> {
    let mut out = Vec::new();
    append_len_prefixed(&mut out, record.cid.to_string().as_bytes());
    append_len_prefixed(&mut out, record.node_id.as_bytes());
    out.extend_from_slice(&(record.addresses.len() as u64).to_be_bytes());
    for address in &record.addresses {
        append_len_prefixed(&mut out, address.as_bytes());
    }
    out.extend_from_slice(&record.expires_at_unix_seconds.to_be_bytes());
    out
}

pub fn persist_provider_record(
    metadata: &MetadataStore,
    record: &ProviderRecord,
) -> Result<(), NetworkError> {
    persist_provider_records(metadata, std::slice::from_ref(record))
}

pub fn persist_provider_records(
    metadata: &MetadataStore,
    records: &[ProviderRecord],
) -> Result<(), NetworkError> {
    let write_txn = metadata
        .database()
        .begin_write()
        .map_err(|source| NetworkError::Transaction(Box::new(source)))?;
    {
        let mut providers = write_txn
            .open_table(PROVIDERS)
            .map_err(|source| NetworkError::Table(Box::new(source)))?;
        for record in records {
            let key = format!("{}:{}", record.cid, record.node_id);
            let bytes = serde_json::to_vec(record)?;
            providers
                .insert(key.as_str(), bytes.as_slice())
                .map_err(|source| NetworkError::RedbStorage(Box::new(source)))?;
        }
    }
    {
        let mut by_cid = write_txn
            .open_table(PROVIDERS_BY_CID)
            .map_err(|source| NetworkError::Table(Box::new(source)))?;
        for record in records {
            let key = format!("{}:{}", record.cid, record.node_id);
            by_cid
                .insert(key.as_str(), record.node_id.as_str())
                .map_err(|source| NetworkError::RedbStorage(Box::new(source)))?;
        }
    }
    write_txn
        .commit()
        .map_err(|source| NetworkError::Commit(Box::new(source)))?;
    Ok(())
}

pub fn cleanup_expired_provider_records(metadata: &MetadataStore) -> Result<usize, NetworkError> {
    let now = unix_seconds();
    let read_txn = metadata
        .database()
        .begin_read()
        .map_err(|source| NetworkError::Transaction(Box::new(source)))?;
    let table = match read_txn.open_table(PROVIDERS) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
        Err(source) => return Err(NetworkError::Table(Box::new(source))),
    };
    let mut expired = Vec::new();
    for item in table
        .iter()
        .map_err(|source| NetworkError::RedbStorage(Box::new(source)))?
    {
        let (key, value) = item.map_err(|source| NetworkError::RedbStorage(Box::new(source)))?;
        let record: ProviderRecord = serde_json::from_slice(value.value())?;
        if record.expires_at_unix_seconds <= now {
            expired.push(key.value().to_string());
        }
    }
    drop(table);
    drop(read_txn);

    if expired.is_empty() {
        return Ok(0);
    }
    let write_txn = metadata
        .database()
        .begin_write()
        .map_err(|source| NetworkError::Transaction(Box::new(source)))?;
    {
        let mut providers = write_txn
            .open_table(PROVIDERS)
            .map_err(|source| NetworkError::Table(Box::new(source)))?;
        for key in &expired {
            providers
                .remove(key.as_str())
                .map_err(|source| NetworkError::RedbStorage(Box::new(source)))?;
        }
    }
    {
        let mut by_cid = write_txn
            .open_table(PROVIDERS_BY_CID)
            .map_err(|source| NetworkError::Table(Box::new(source)))?;
        for key in &expired {
            by_cid
                .remove(key.as_str())
                .map_err(|source| NetworkError::RedbStorage(Box::new(source)))?;
        }
    }
    write_txn
        .commit()
        .map_err(|source| NetworkError::Commit(Box::new(source)))?;
    Ok(expired.len())
}

pub fn provider_records_for_cid(
    metadata: &MetadataStore,
    cid: &Cid,
) -> Result<Vec<ProviderRecord>, NetworkError> {
    let read_txn = metadata
        .database()
        .begin_read()
        .map_err(|source| NetworkError::Transaction(Box::new(source)))?;
    let table = match read_txn.open_table(PROVIDERS) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(source) => return Err(NetworkError::Table(Box::new(source))),
    };
    let mut records = Vec::new();
    let prefix = format!("{cid}:");
    for item in table
        .range(prefix.as_str()..)
        .map_err(|source| NetworkError::RedbStorage(Box::new(source)))?
    {
        let (key, value) = item.map_err(|source| NetworkError::RedbStorage(Box::new(source)))?;
        if !key.value().starts_with(&prefix) {
            break;
        }
        let record: ProviderRecord = serde_json::from_slice(value.value())?;
        if record.expires_at_unix_seconds > unix_seconds() {
            records.push(record);
        }
    }
    Ok(records)
}

fn validate_erasure_transfer_request(
    request: &proto::ErasureTransferRequest,
    streamed: bool,
) -> Result<(), NetworkError> {
    let logical_cid = Cid::from_str(&request.logical_cid)
        .map_err(|error| NetworkError::BlockService(error.to_string()))?;
    let encoded_cid = Cid::from_str(&request.encoded_cid)
        .map_err(|error| NetworkError::BlockService(error.to_string()))?;
    let data_shards = usize::try_from(request.data_shards)
        .map_err(|_| NetworkError::BlockService("invalid data shard count".to_string()))?;
    let parity_shards = usize::try_from(request.parity_shards)
        .map_err(|_| NetworkError::BlockService("invalid parity shard count".to_string()))?;
    if logical_cid.codec != CODEC_RAW
        || encoded_cid.codec != CODEC_RAW
        || request.placement_epoch == 0
        || request.logical_size == 0
        || data_shards == 0
        || parity_shards == 0
        || parity_shards > data_shards
        || data_shards.saturating_add(parity_shards) > 32
        || request.encoded_size == 0
        || request.encoded_size > 512 * 1024 * 1024
        || request.shard_size == 0
        || request.shard_size > 64 * 1024 * 1024
        || request.shard_size
            != request
                .encoded_size
                .div_ceil(u64::from(request.data_shards))
        || request.data_cids.len() != data_shards
        || !matches!(request.encoding.as_str(), "raw" | "zstd")
        || (request.encoding == "raw"
            && (request.logical_size != request.encoded_size || encoded_cid != logical_cid))
    {
        return Err(NetworkError::BlockService(
            "invalid adaptive erasure transfer geometry".to_string(),
        ));
    }
    for cid in &request.data_cids {
        if Cid::from_str(cid).map_or(true, |cid| cid.codec != CODEC_RAW) {
            return Err(NetworkError::BlockService(
                "invalid adaptive erasure data CID".to_string(),
            ));
        }
    }
    let expected_plan = if streamed {
        matches!(request.plan.as_str(), "hierarchical" | "pipelined")
    } else {
        request.plan == "distributed-parity"
    };
    if !expected_plan {
        return Err(NetworkError::BlockService(
            "adaptive erasure transfer used the wrong transport lane".to_string(),
        ));
    }
    if request.pipeline.len() > data_shards {
        return Err(NetworkError::BlockService(
            "adaptive erasure pipeline exceeds data-shard count".to_string(),
        ));
    }
    let mut indices = HashSet::new();
    let mut nodes = HashSet::new();
    for hop in &request.pipeline {
        if hop.index >= request.data_shards
            || hop.node_id.is_empty()
            || !indices.insert(hop.index)
            || !nodes.insert(hop.node_id.as_str())
        {
            return Err(NetworkError::BlockService(
                "adaptive erasure pipeline is not unique and bounded".to_string(),
            ));
        }
    }
    let mut completed = HashSet::new();
    for index in &request.completed_indices {
        if *index >= request.data_shards || !completed.insert(*index) || indices.contains(index) {
            return Err(NetworkError::BlockService(
                "adaptive erasure completed indices are invalid".to_string(),
            ));
        }
    }
    Ok(())
}

fn verify_descriptor(descriptor: &proto::NodeDescriptor) -> Result<(), NetworkError> {
    if descriptor.name.len() > 256
        || descriptor.addresses.is_empty()
        || descriptor.addresses.len() > 16
        || descriptor.bulk_addresses.is_empty()
        || descriptor.bulk_addresses.len() > 16
        || descriptor.placement_labels.len() > 64
        || descriptor.addresses.iter().any(|address| {
            address.parse::<SocketAddr>().map_or(true, |address| {
                address.ip().is_unspecified() || address.ip().is_multicast()
            })
        })
        || descriptor.bulk_addresses.iter().any(|address| {
            address.parse::<SocketAddr>().map_or(true, |address| {
                address.ip().is_unspecified() || address.ip().is_multicast()
            })
        })
    {
        return Err(NetworkError::InvalidDescriptor(
            "descriptor fields exceed limits or contain invalid addresses".to_string(),
        ));
    }
    let tls_digest = hex::decode(&descriptor.tls_certificate_digest_hex).map_err(|error| {
        NetworkError::InvalidDescriptor(format!("invalid TLS certificate digest: {error}"))
    })?;
    if tls_digest.len() != 32 {
        return Err(NetworkError::InvalidDescriptor(
            "TLS certificate digest must be 32 bytes".to_string(),
        ));
    }
    let public_key = hex::decode(&descriptor.public_key_hex)
        .map_err(|error| NetworkError::InvalidDescriptor(format!("invalid public key: {error}")))?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| NetworkError::InvalidDescriptor("public key must be 32 bytes".to_string()))?;
    let expected_node_id = derive_node_id(&public_key);
    if expected_node_id != descriptor.node_id {
        return Err(NetworkError::InvalidDescriptor(
            "node_id does not match public key".to_string(),
        ));
    }
    let signature = hex::decode(&descriptor.signature_hex)
        .map_err(|error| NetworkError::InvalidDescriptor(format!("invalid signature: {error}")))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| NetworkError::InvalidDescriptor("signature must be 64 bytes".to_string()))?;
    if !verify_signature(
        &public_key,
        &descriptor_signature_payload(descriptor),
        &signature,
    ) {
        return Err(NetworkError::InvalidDescriptor(
            "descriptor signature verification failed".to_string(),
        ));
    }
    Ok(())
}

fn namespace_discovery_signature_payload(record: &proto::NamespaceDiscoveryRecord) -> Vec<u8> {
    let mut out = b"pepper/namespace/discovery/v1".to_vec();
    append_len_prefixed(&mut out, record.namespace_id.as_bytes());
    out.extend_from_slice(&record.namespace_protocol_version.to_be_bytes());
    out.extend_from_slice(&record.membership_epoch.to_be_bytes());
    out.extend_from_slice(&(record.replica_node_ids.len() as u64).to_be_bytes());
    for replica in &record.replica_node_ids {
        append_len_prefixed(&mut out, replica.as_bytes());
    }
    append_len_prefixed(&mut out, record.leader_node_id.as_bytes());
    out.extend_from_slice(&record.leader_term.to_be_bytes());
    out.extend_from_slice(&record.expires_at_unix_seconds.to_be_bytes());
    append_len_prefixed(&mut out, record.announcer_node_id.as_bytes());
    out
}

fn descriptor_signature_payload(descriptor: &proto::NodeDescriptor) -> Vec<u8> {
    let mut out = Vec::new();
    append_len_prefixed(&mut out, descriptor.node_id.as_bytes());
    append_len_prefixed(&mut out, descriptor.name.as_bytes());
    out.extend_from_slice(&(descriptor.addresses.len() as u64).to_be_bytes());
    for address in &descriptor.addresses {
        append_len_prefixed(&mut out, address.as_bytes());
    }
    append_len_prefixed(&mut out, descriptor.public_key_hex.as_bytes());
    append_len_prefixed(&mut out, descriptor.failure_domain.as_bytes());
    let mut labels = descriptor.placement_labels.iter().collect::<Vec<_>>();
    labels.sort_by_key(|(key, _)| *key);
    out.extend_from_slice(&(labels.len() as u64).to_be_bytes());
    for (key, value) in labels {
        append_len_prefixed(&mut out, key.as_bytes());
        append_len_prefixed(&mut out, value.as_bytes());
    }
    out.extend_from_slice(&descriptor.storage_capacity_bytes.to_be_bytes());
    out.extend_from_slice(&descriptor.storage_available_bytes.to_be_bytes());
    append_len_prefixed(&mut out, descriptor.tls_certificate_digest_hex.as_bytes());
    out.push(u8::from(descriptor.namespace_consensus_enabled));
    out.extend_from_slice(&descriptor.namespace_group_capacity.to_be_bytes());
    out.extend_from_slice(&descriptor.namespace_group_count.to_be_bytes());
    out.extend_from_slice(&descriptor.max_consensus_log_bytes.to_be_bytes());
    out.extend_from_slice(&descriptor.max_namespace_write_rate.to_be_bytes());
    out.extend_from_slice(&(descriptor.bulk_addresses.len() as u64).to_be_bytes());
    for address in &descriptor.bulk_addresses {
        append_len_prefixed(&mut out, address.as_bytes());
    }
    out
}

fn validate_namespace_context(
    envelope: &proto::RequestEnvelope,
    context: Option<&proto::NamespaceRpcContext>,
) -> Result<(), NetworkError> {
    let context = context
        .ok_or_else(|| NetworkError::BlockService("missing namespace RPC context".to_string()))?;
    if context.namespace_protocol_version != 1
        || context.namespace_id.is_empty()
        || context.namespace_id.len() > 256
        || context.sender_identity != envelope.node_id
        || context.request_id != envelope.request_id
        || context.membership_epoch == 0
    {
        return Err(NetworkError::Unauthenticated);
    }
    Ok(())
}

fn encode_payload(message: impl Message) -> Result<Vec<u8>, NetworkError> {
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(payload)
}

async fn write_frame(send: &mut SendStream, message: &impl Message) -> Result<(), NetworkError> {
    write_frame_open(send, message).await?;
    send.finish()?;
    Ok(())
}

async fn write_frame_open(
    send: &mut SendStream,
    message: &impl Message,
) -> Result<(), NetworkError> {
    let mut bytes = Vec::new();
    message.encode(&mut bytes)?;
    let len = bytes.len();
    if len > MAX_FRAME_BYTES {
        return Err(NetworkError::BlockService(format!(
            "frame too large: {len} bytes"
        )));
    }
    send.write_all(&(len as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

async fn read_frame<T: Message + Default>(recv: &mut RecvStream) -> Result<T, NetworkError> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(NetworkError::BlockService(format!(
            "frame too large: {len} bytes"
        )));
    }
    let mut bytes = vec![0u8; len];
    recv.read_exact(&mut bytes).await?;
    T::decode(bytes.as_slice()).map_err(NetworkError::from)
}

fn server_config() -> Result<(ServerConfig, String), NetworkError> {
    ensure_rustls_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["pepper.local".to_string()])
        .map_err(|error| NetworkError::TlsConfig(error.to_string()))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let digest = hex::encode(blake3::hash(cert_der.as_ref()).as_bytes());
    let config = ServerConfig::with_single_cert(vec![cert_der], key_der.into())
        .map_err(|error| NetworkError::TlsConfig(error.to_string()))?;
    Ok((config, digest))
}

#[derive(Debug, Clone, Copy)]
enum TransportProfile {
    Control,
    Bulk {
        send_window_bytes: u64,
        connection_receive_window_bytes: u64,
        stream_receive_window_bytes: u64,
        streams_per_connection: usize,
    },
}

fn client_config(profile: TransportProfile) -> Result<ClientConfig, NetworkError> {
    ensure_rustls_provider();
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|error| NetworkError::TlsConfig(error.to_string()))?;
    let mut config = ClientConfig::new(Arc::new(quic_crypto));
    config.transport_config(transport_config(profile)?);
    Ok(config)
}

fn transport_config(profile: TransportProfile) -> Result<Arc<TransportConfig>, NetworkError> {
    let mut transport = TransportConfig::default();
    let (send_window, receive_window, stream_receive_window, streams) = match profile {
        TransportProfile::Control => (16 * 1024 * 1024, 32 * 1024 * 1024, 2 * 1024 * 1024, 64),
        TransportProfile::Bulk {
            send_window_bytes,
            connection_receive_window_bytes,
            stream_receive_window_bytes,
            streams_per_connection,
        } => (
            send_window_bytes,
            connection_receive_window_bytes,
            stream_receive_window_bytes,
            streams_per_connection,
        ),
    };
    transport
        .send_window(send_window)
        .receive_window(VarInt::from_u32(receive_window as u32))
        .stream_receive_window(VarInt::from_u32(stream_receive_window as u32));
    let idle_timeout = std::time::Duration::from_secs(120)
        .try_into()
        .map_err(|error: quinn::VarIntBoundsExceeded| NetworkError::TlsConfig(error.to_string()))?;
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(streams.min(u32::MAX as usize) as u32))
        .max_idle_timeout(Some(idle_timeout))
        .keep_alive_interval(Some(std::time::Duration::from_secs(1)));
    Ok(Arc::new(transport))
}

fn ensure_rustls_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

fn normalize_rpc_method(method: &str) -> &str {
    if method.len() <= 96
        && method.starts_with('/')
        && method
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-'))
    {
        method
    } else {
        "/other"
    }
}

fn next_request_id() -> String {
    let mut nonce = [0u8; 16];
    if getrandom::fill(&mut nonce).is_ok() {
        hex::encode(nonce)
    } else {
        format!(
            "{}-{}-{}",
            unix_seconds(),
            std::process::id(),
            REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn routing_queue_for_cid(peers: Vec<PeerStatus>, cid: &Cid) -> VecDeque<String> {
    routing_addresses_for_cid(peers, cid).into_iter().collect()
}

fn routing_addresses_for_cid(peers: Vec<PeerStatus>, cid: &Cid) -> Vec<String> {
    let mut bucket_counts = HashMap::<usize, usize>::new();
    let mut scored = peers
        .into_iter()
        .flat_map(|peer| {
            let distance = xor_distance(&node_id_bytes(&peer.node_id), &cid.digest);
            let bucket = kademlia_bucket(&distance);
            sorted_routable_addresses(peer.addresses)
                .into_iter()
                .map(move |address| (bucket, distance, address_score(&address), address))
        })
        .collect::<Vec<_>>();
    scored.sort_by(|left, right| {
        left.1
            .cmp(&right.1)
            .then_with(|| left.2.cmp(&right.2))
            .then_with(|| left.3.cmp(&right.3))
    });
    let mut selected = Vec::new();
    for (bucket, _, _, address) in scored {
        let count = bucket_counts.entry(bucket).or_default();
        if *count >= KADEMLIA_BUCKET_SIZE {
            continue;
        }
        *count += 1;
        selected.push(address);
    }
    selected
}

fn insert_routing_candidate(queue: &mut VecDeque<String>, address: String, cid: &Cid) {
    let score = routing_address_sort_key(&address, cid);
    let position = queue
        .iter()
        .position(|existing| score < routing_address_sort_key(existing, cid))
        .unwrap_or(queue.len());
    queue.insert(position, address);
}

fn routing_address_sort_key(address: &str, cid: &Cid) -> ([u8; 32], u16, String) {
    // Address-only candidates do not always carry a node ID. Hash the socket address as a stable
    // fallback so indirect discoveries can still be ordered near the lookup key.
    let nodeish = blake3::hash(address.as_bytes());
    (
        xor_distance(nodeish.as_bytes(), &cid.digest),
        address_score(address),
        address.to_string(),
    )
}

fn sorted_routable_addresses(mut addresses: Vec<String>) -> Vec<String> {
    addresses.retain(|address| is_usable_address(address));
    addresses.sort_by(|left, right| {
        address_score(left)
            .cmp(&address_score(right))
            .then_with(|| left.cmp(right))
    });
    addresses.dedup();
    addresses
}

fn is_usable_address(address: &str) -> bool {
    let Ok(socket) = address.parse::<SocketAddr>() else {
        return false;
    };
    match socket.ip() {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast(),
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

fn address_score(address: &str) -> u16 {
    let Ok(socket) = address.parse::<SocketAddr>() else {
        return u16::MAX;
    };
    match socket.ip() {
        IpAddr::V4(ip) if is_global_v4(ip) => 0,
        IpAddr::V6(ip) if is_global_v6(ip) => 0,
        IpAddr::V4(ip) if ip.is_private() => 10,
        IpAddr::V6(ip) if (ip.segments()[0] & 0xfe00) == 0xfc00 => 10,
        IpAddr::V4(ip) if ip.is_loopback() => 20,
        IpAddr::V6(ip) if ip.is_loopback() => 20,
        IpAddr::V4(ip) if ip.is_link_local() => 30,
        IpAddr::V6(ip) if (ip.segments()[0] & 0xffc0) == 0xfe80 => 30,
        _ => 40,
    }
}

fn is_global_v4(ip: std::net::Ipv4Addr) -> bool {
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_broadcast()
        && !ip.is_documentation()
        && !ip.is_unspecified()
        && !ip.is_multicast()
}

fn is_global_v6(ip: std::net::Ipv6Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && (ip.segments()[0] & 0xfe00) != 0xfc00
        && (ip.segments()[0] & 0xffc0) != 0xfe80
}

fn node_id_bytes(node_id: &str) -> [u8; 32] {
    hex::decode(node_id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or_else(|| *blake3::hash(node_id.as_bytes()).as_bytes())
}

fn xor_distance(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut distance = [0u8; 32];
    for (index, (left, right)) in left.iter().zip(right.iter()).enumerate() {
        distance[index] = left ^ right;
    }
    distance
}

fn kademlia_bucket(distance: &[u8; 32]) -> usize {
    for (byte_index, byte) in distance.iter().enumerate() {
        if *byte != 0 {
            return byte_index * 8 + byte.leading_zeros() as usize;
        }
    }
    256
}

fn request_identity_payload(envelope: &proto::RequestEnvelope) -> Vec<u8> {
    let mut out = Vec::new();
    append_len_prefixed(&mut out, envelope.request_id.as_bytes());
    out.extend_from_slice(&envelope.protocol_version.to_be_bytes());
    append_len_prefixed(&mut out, envelope.node_id.as_bytes());
    append_len_prefixed(&mut out, envelope.method.as_bytes());
    out.extend_from_slice(&envelope.auth_timestamp_unix_seconds.to_be_bytes());
    append_len_prefixed(&mut out, &envelope.payload);
    append_len_prefixed(&mut out, envelope.auth_signature_hex.as_bytes());
    out
}

fn response_signature_payload(response: &proto::ResponseEnvelope) -> Vec<u8> {
    let mut out = Vec::new();
    append_len_prefixed(&mut out, response.request_id.as_bytes());
    out.push(response.ok as u8);
    append_len_prefixed(&mut out, response.error_code.as_bytes());
    append_len_prefixed(&mut out, response.error_message.as_bytes());
    append_len_prefixed(&mut out, &response.payload);
    append_len_prefixed(&mut out, response.node_id.as_bytes());
    append_len_prefixed(&mut out, response.public_key_hex.as_bytes());
    out
}

fn verify_response_envelope(
    response: &proto::ResponseEnvelope,
    expected_request_id: &str,
) -> Result<(), NetworkError> {
    if response.request_id != expected_request_id {
        return Err(NetworkError::Unauthenticated);
    }
    let public_key: [u8; 32] = hex::decode(&response.public_key_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(NetworkError::Unauthenticated)?;
    if derive_node_id(&public_key) != response.node_id {
        return Err(NetworkError::Unauthenticated);
    }
    let signature: [u8; 64] = hex::decode(&response.signature_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(NetworkError::Unauthenticated)?;
    if !verify_signature(
        &public_key,
        &response_signature_payload(response),
        &signature,
    ) {
        return Err(NetworkError::Unauthenticated);
    }
    Ok(())
}

fn peer_certificate_digest(connection: &Connection) -> Result<String, NetworkError> {
    let identity = connection.peer_identity().ok_or_else(|| {
        NetworkError::TlsConfig("QUIC peer did not provide a certificate".to_string())
    })?;
    let certificates = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| NetworkError::TlsConfig("unexpected QUIC peer identity type".to_string()))?;
    let certificate = certificates.first().ok_or_else(|| {
        NetworkError::TlsConfig("QUIC peer certificate chain is empty".to_string())
    })?;
    Ok(hex::encode(blake3::hash(certificate.as_ref()).as_bytes()))
}

fn sign_request_envelope(secret: &[u8], envelope: &proto::RequestEnvelope) -> String {
    let mut payload = Vec::new();
    append_len_prefixed(&mut payload, envelope.request_id.as_bytes());
    payload.extend_from_slice(&envelope.protocol_version.to_be_bytes());
    append_len_prefixed(&mut payload, envelope.node_id.as_bytes());
    append_len_prefixed(&mut payload, envelope.method.as_bytes());
    payload.extend_from_slice(&envelope.auth_timestamp_unix_seconds.to_be_bytes());
    append_len_prefixed(&mut payload, &envelope.payload);
    let key = blake3::hash(secret);
    let mut hasher = blake3::Hasher::new_keyed(key.as_bytes());
    hasher.update(&payload);
    hex::encode(hasher.finalize().as_bytes())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

fn error_code(error: &NetworkError) -> &'static str {
    match error {
        NetworkError::UnsupportedMethod(_) => "unsupported_method",
        NetworkError::InvalidDescriptor(_) => "invalid_descriptor",
        NetworkError::BlockService(_) => "block_service_error",
        NetworkError::Rpc { .. } => "rpc_error",
        NetworkError::Unauthenticated => "unauthenticated",
        NetworkError::RateLimited => "rate_limited",
        NetworkError::DeadlineExceeded => "deadline_exceeded",
        _ => "internal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_erasure_request(plan: &str) -> proto::ErasureTransferRequest {
        let encoded = b"abcdefghijkl";
        proto::ErasureTransferRequest {
            logical_cid: Cid::new(CODEC_RAW, encoded).to_string(),
            placement_epoch: 7,
            data_shards: 3,
            parity_shards: 2,
            encoded_size: encoded.len() as u64,
            shard_size: 4,
            data_cids: encoded
                .chunks(4)
                .map(|shard| Cid::new(CODEC_RAW, shard).to_string())
                .collect(),
            pipeline: Vec::new(),
            plan: plan.to_string(),
            logical_size: encoded.len() as u64,
            encoding: "raw".to_string(),
            completed_indices: Vec::new(),
            encoded_cid: Cid::new(CODEC_RAW, encoded).to_string(),
        }
    }

    #[test]
    fn adaptive_erasure_requests_are_geometry_bounded_and_lane_separated() {
        let distributed = test_erasure_request("distributed-parity");
        assert!(validate_erasure_transfer_request(&distributed, false).is_ok());
        assert!(validate_erasure_transfer_request(&distributed, true).is_err());

        let hierarchical = test_erasure_request("hierarchical");
        assert!(validate_erasure_transfer_request(&hierarchical, true).is_ok());
        assert!(validate_erasure_transfer_request(&hierarchical, false).is_err());

        let mut duplicate_pipeline = test_erasure_request("pipelined");
        duplicate_pipeline.pipeline = vec![
            proto::ErasurePipelineHop {
                index: 0,
                node_id: "node-a".to_string(),
            },
            proto::ErasurePipelineHop {
                index: 0,
                node_id: "node-b".to_string(),
            },
        ];
        assert!(validate_erasure_transfer_request(&duplicate_pipeline, true).is_err());

        let mut overlapping = test_erasure_request("pipelined");
        overlapping.pipeline = vec![proto::ErasurePipelineHop {
            index: 1,
            node_id: "node-a".to_string(),
        }];
        overlapping.completed_indices = vec![1];
        assert!(validate_erasure_transfer_request(&overlapping, true).is_err());

        let mut changed_layout = test_erasure_request("hierarchical");
        changed_layout.encoded_cid = Cid::new(CODEC_RAW, b"different").to_string();
        assert!(validate_erasure_transfer_request(&changed_layout, true).is_err());
    }

    #[derive(Default)]
    struct TestBlockService {
        blocks: Mutex<HashMap<String, Vec<u8>>>,
        blocking_read_delay: std::time::Duration,
    }

    #[async_trait]
    impl NetworkBlockService for TestBlockService {
        async fn has_block(&self, cid: &Cid) -> Result<bool, NetworkError> {
            Ok(self.blocks.lock().unwrap().contains_key(&cid.to_string()))
        }

        async fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, NetworkError> {
            if !self.blocking_read_delay.is_zero() {
                std::thread::sleep(self.blocking_read_delay);
            }
            self.blocks
                .lock()
                .unwrap()
                .get(&cid.to_string())
                .cloned()
                .ok_or_else(|| NetworkError::BlockService("test block not found".to_string()))
        }

        async fn put_replica(
            &self,
            codec: Codec,
            payload: Vec<u8>,
        ) -> Result<PutBlockResponse, NetworkError> {
            let cid = Cid::new(codec, &payload);
            let already_existed = self
                .blocks
                .lock()
                .unwrap()
                .insert(cid.to_string(), payload.clone())
                .is_some();
            Ok(PutBlockResponse {
                cid,
                codec,
                size: payload.len() as u64,
                already_existed,
                storage_location: "test-memory".to_string(),
            })
        }

        async fn put_encoded_verified_replica(
            &self,
            codec: Codec,
            expected_cid: &Cid,
            logical_size: u64,
            payload: Vec<u8>,
        ) -> Result<PutBlockResponse, NetworkError> {
            if codec != CODEC_RAW
                || logical_size != payload.len() as u64
                || !expected_cid.verify(&payload)
            {
                return Err(NetworkError::BlockService(
                    "invalid test replica".to_string(),
                ));
            }
            self.put_replica(codec, payload).await
        }
    }

    struct TestNetworkNode {
        _directory: tempfile::TempDir,
        control_addr: SocketAddr,
        bulk_addr: SocketAddr,
        network: NetworkHandle,
        service: Arc<TestBlockService>,
    }

    fn free_udp_addresses(count: usize) -> Vec<SocketAddr> {
        let sockets = (0..count)
            .map(|_| std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect::<Vec<_>>();
        sockets
            .iter()
            .map(|socket| socket.local_addr().unwrap())
            .collect()
    }

    async fn test_network_node(
        name: &str,
        control_addr: SocketAddr,
        bulk_addr: SocketAddr,
        blocking_read_delay: std::time::Duration,
    ) -> TestNetworkNode {
        let directory = tempfile::tempdir().unwrap();
        let identity =
            NodeIdentity::generate_and_store(directory.path().join("identity.ed25519")).unwrap();
        let metadata = Arc::new(
            MetadataStore::open_or_create(directory.path().join("metadata.redb")).unwrap(),
        );
        let service = Arc::new(TestBlockService {
            blocks: Mutex::new(HashMap::new()),
            blocking_read_delay,
        });
        let network = NetworkHandle::start(
            NetworkConfig {
                node_name: name.to_string(),
                listen_addr: control_addr,
                advertise_addr: control_addr,
                bulk_listen_addr: bulk_addr,
                bulk_advertise_addr: bulk_addr,
                bulk_worker_threads: 2,
                bulk_inbound_connections: 32,
                bulk_streams_per_connection: 32,
                bulk_send_window_bytes: 128 * 1024 * 1024,
                bulk_connection_receive_window_bytes: 128 * 1024 * 1024,
                bulk_stream_receive_window_bytes: 68 * 1024 * 1024,
                bulk_request_timeout_seconds: 30,
                bulk_max_bytes_per_second: 0,
                bulk_bandwidth_burst_bytes: 128 * 1024 * 1024,
                bootstrap_peers: Vec::new(),
                cluster_secret: Some(vec![7; 32]),
                requests_per_minute: None,
                failure_domain: Some(name.to_string()),
                placement_labels: HashMap::new(),
                storage_capacity_bytes: 1024 * 1024 * 1024,
                storage_available_bytes: 1024 * 1024 * 1024,
                namespace_consensus_enabled: true,
                namespace_group_capacity: 16,
                namespace_group_count: 0,
                max_consensus_log_bytes: 16 * 1024 * 1024,
                max_namespace_write_rate: 1_000,
            },
            identity,
            metadata,
            service.clone(),
        )
        .await
        .unwrap();
        TestNetworkNode {
            _directory: directory,
            control_addr,
            bulk_addr,
            network,
            service,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dedicated_bulk_plane_streams_raw_bytes_without_delaying_control() {
        let addresses = free_udp_addresses(4);
        let source = test_network_node(
            "source",
            addresses[0],
            addresses[1],
            std::time::Duration::ZERO,
        )
        .await;
        let target = test_network_node(
            "target",
            addresses[2],
            addresses[3],
            std::time::Duration::from_millis(250),
        )
        .await;
        source.network.node_info(target.control_addr).await.unwrap();
        let payload = vec![0x5a; 4 * 1024 * 1024];
        let cid = Cid::new(CODEC_RAW, &payload);
        target
            .service
            .blocks
            .lock()
            .unwrap()
            .insert(cid.to_string(), payload.clone());

        let mut reads = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let network = source.network.clone();
            let cid = cid.clone();
            let peer = target.control_addr;
            reads.spawn(async move { network.block_get(peer, &cid).await });
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut max_control_latency = std::time::Duration::ZERO;
        for _ in 0..8 {
            let started = std::time::Instant::now();
            let descriptor = source.network.node_info(target.control_addr).await.unwrap();
            assert_eq!(
                descriptor.bulk_addresses,
                vec![target.bulk_addr.to_string()]
            );
            max_control_latency = max_control_latency.max(started.elapsed());
        }
        assert!(
            max_control_latency < std::time::Duration::from_millis(500),
            "control RPC was delayed by saturated bulk workers: {max_control_latency:?}"
        );
        while let Some(result) = reads.join_next().await {
            assert_eq!(result.unwrap().unwrap(), payload);
        }
        let range = source
            .network
            .block_get_range(target.control_addr, &cid, 123_456, 1_172_032)
            .await
            .unwrap();
        assert_eq!(range, payload[123_456..1_172_032]);

        let second = vec![0xa5; 1024 * 1024];
        let second_cid = Cid::new(CODEC_RAW, &second);
        source
            .network
            .block_put_replica_stream(
                target.control_addr,
                CODEC_RAW,
                &second_cid,
                second.len() as u64,
                Arc::from(second.clone()),
            )
            .await
            .unwrap();
        assert_eq!(
            target
                .service
                .blocks
                .lock()
                .unwrap()
                .get(&second_cid.to_string()),
            Some(&second)
        );
        let missing_cid = Cid::new(CODEC_RAW, b"not-stored");
        assert_eq!(
            source
                .network
                .block_has_batch(
                    target.control_addr,
                    &[cid.clone(), missing_cid, second_cid.clone()],
                )
                .await
                .unwrap(),
            vec![true, false, true]
        );
        assert!(
            source
                .network
                .block_has_batch(target.control_addr, &[])
                .await
                .is_err()
        );
        let source_transport = source.network.transport_metrics();
        let target_transport = target.network.transport_metrics();
        assert!(source_transport.bulk_bytes_received_total >= 8 * payload.len() as u64);
        assert!(source_transport.bulk_bytes_sent_total >= second.len() as u64);
        assert!(target_transport.control_streams_total >= 9);
        assert!(target_transport.bulk_streams_total >= 10);
        assert_eq!(target_transport.bulk_connections_total, 1);
        assert!(source.network.rpc_metrics().iter().any(|metric| {
            metric.method == "/block/get_stream" && metric.response_bytes > payload.len() as u64
        }));
        assert!(source.network.rpc_metrics().iter().any(|metric| {
            metric.method == "/block/get_range_stream"
                && metric.response_bytes >= 1_172_032 - 123_456
                && metric.response_bytes < payload.len() as u64
        }));
        assert!(
            !source
                .network
                .rpc_metrics()
                .iter()
                .any(|metric| metric.method == "/block/get")
        );
        source.network.shutdown();
        target.network.shutdown();
    }

    #[tokio::test]
    async fn configured_bulk_budget_is_bounded_and_observable() {
        let counters = Arc::new(TransportCounters::default());
        let limiter = BandwidthLimiter::new(1_000, 10, counters.clone()).unwrap();
        limiter.reserve(10).await;
        let started = std::time::Instant::now();
        limiter.reserve(10).await;
        assert!(started.elapsed() >= std::time::Duration::from_millis(8));
        assert!(
            counters
                .bulk_throttle_microseconds_total
                .load(Ordering::Relaxed)
                >= 8_000
        );
    }

    #[test]
    fn provider_record_signature_verifies_and_detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let identity =
            NodeIdentity::generate_and_store(dir.path().join("identity.ed25519")).unwrap();
        let config = NetworkConfig {
            node_name: "test-node".to_string(),
            listen_addr: "127.0.0.1:9000".parse().unwrap(),
            advertise_addr: "127.0.0.1:9000".parse().unwrap(),
            bulk_listen_addr: "127.0.0.1:9001".parse().unwrap(),
            bulk_advertise_addr: "127.0.0.1:9001".parse().unwrap(),
            bulk_worker_threads: 1,
            bulk_inbound_connections: 8,
            bulk_streams_per_connection: 8,
            bulk_send_window_bytes: 128 * 1024 * 1024,
            bulk_connection_receive_window_bytes: 128 * 1024 * 1024,
            bulk_stream_receive_window_bytes: 68 * 1024 * 1024,
            bulk_request_timeout_seconds: 60,
            bulk_max_bytes_per_second: 0,
            bulk_bandwidth_burst_bytes: 128 * 1024 * 1024,
            bootstrap_peers: Vec::new(),
            cluster_secret: None,
            requests_per_minute: None,
            failure_domain: None,
            placement_labels: HashMap::new(),
            storage_capacity_bytes: 0,
            storage_available_bytes: 0,
            namespace_consensus_enabled: false,
            namespace_group_capacity: 0,
            namespace_group_count: 0,
            max_consensus_log_bytes: 0,
            max_namespace_write_rate: 0,
        };
        let descriptor = make_descriptor(&config, &identity, "test-tls-digest".to_string());
        let cid = Cid::new(CODEC_RAW, b"hello");
        let mut record = make_provider_record(&descriptor, &identity, &cid);
        let public_key = identity.public_key_bytes();
        let signature: [u8; 64] = hex::decode(&record.signature_hex)
            .unwrap()
            .try_into()
            .unwrap();
        assert!(verify_signature(
            &public_key,
            &provider_record_signature_payload(&record),
            &signature
        ));

        record.addresses.push("127.0.0.1:9001".to_string());
        assert!(!verify_signature(
            &public_key,
            &provider_record_signature_payload(&record),
            &signature
        ));
    }

    #[test]
    fn namespace_discovery_signature_binds_group_epoch_and_term() {
        let directory = tempfile::tempdir().unwrap();
        let identity =
            NodeIdentity::generate_and_store(directory.path().join("identity.ed25519")).unwrap();
        let mut record = proto::NamespaceDiscoveryRecord {
            namespace_id: "namespace-a".to_string(),
            namespace_protocol_version: 1,
            membership_epoch: 3,
            replica_node_ids: vec!["a".into(), "b".into(), "c".into()],
            leader_node_id: "a".to_string(),
            leader_term: 7,
            expires_at_unix_seconds: unix_seconds() + 60,
            announcer_node_id: identity.node_id().to_string(),
            signature_hex: String::new(),
        };
        let signature = identity.sign(&namespace_discovery_signature_payload(&record));
        assert!(verify_signature(
            &identity.public_key_bytes(),
            &namespace_discovery_signature_payload(&record),
            &signature
        ));
        record.membership_epoch += 1;
        assert!(!verify_signature(
            &identity.public_key_bytes(),
            &namespace_discovery_signature_payload(&record),
            &signature
        ));
    }

    #[test]
    fn routing_prefers_closer_peer_ids() {
        let cid = Cid {
            version: pepper_types::CID_VERSION,
            codec: CODEC_RAW,
            hash_alg: pepper_types::HashAlg::Blake3,
            digest: [0u8; 32],
        };
        let far = PeerStatus {
            node_id: format!("80{}", "00".repeat(31)),
            name: "far".to_string(),
            addresses: vec!["127.0.0.1:9001".to_string()],
            bulk_addresses: vec!["127.0.0.1:9101".to_string()],
            last_seen_unix_seconds: 1,
            connected: true,
            failure_domain: None,
            placement_labels: HashMap::new(),
            storage_capacity_bytes: 0,
            storage_available_bytes: 0,
            namespace_consensus_enabled: false,
            namespace_group_capacity: 0,
            namespace_group_count: 0,
            max_consensus_log_bytes: 0,
            max_namespace_write_rate: 0,
        };
        let near = PeerStatus {
            node_id: format!("{}01", "00".repeat(31)),
            name: "near".to_string(),
            addresses: vec!["127.0.0.1:9002".to_string()],
            bulk_addresses: vec!["127.0.0.1:9102".to_string()],
            last_seen_unix_seconds: 1,
            connected: true,
            failure_domain: None,
            placement_labels: HashMap::new(),
            storage_capacity_bytes: 0,
            storage_available_bytes: 0,
            namespace_consensus_enabled: false,
            namespace_group_capacity: 0,
            namespace_group_count: 0,
            max_consensus_log_bytes: 0,
            max_namespace_write_rate: 0,
        };
        let addresses = routing_addresses_for_cid(vec![far, near], &cid);
        assert_eq!(addresses[0], "127.0.0.1:9002");
    }

    #[test]
    fn nat_aware_address_sort_filters_unusable_and_prefers_private_before_loopback() {
        let addresses = sorted_routable_addresses(vec![
            "0.0.0.0:9000".to_string(),
            "127.0.0.1:9000".to_string(),
            "10.0.0.5:9000".to_string(),
            "224.0.0.1:9000".to_string(),
        ]);
        assert_eq!(
            addresses,
            vec!["10.0.0.5:9000".to_string(), "127.0.0.1:9000".to_string()]
        );
    }

    #[test]
    fn node_identity_signature_covers_request_contents() {
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::generate_and_store(dir.path().join("node.key")).unwrap();
        let mut envelope = proto::RequestEnvelope {
            request_id: "req-identity".to_string(),
            protocol_version: PROTOCOL_VERSION,
            node_id: identity.node_id().to_string(),
            method: "/node/info".to_string(),
            payload: vec![1, 2, 3],
            auth_timestamp_unix_seconds: 123,
            auth_signature_hex: String::new(),
            public_key_hex: hex::encode(identity.public_key_bytes()),
            identity_signature_hex: String::new(),
        };
        let signature = identity.sign(&request_identity_payload(&envelope));
        assert!(verify_signature(
            &identity.public_key_bytes(),
            &request_identity_payload(&envelope),
            &signature
        ));
        envelope.method = "/compute/submit".to_string();
        assert!(!verify_signature(
            &identity.public_key_bytes(),
            &request_identity_payload(&envelope),
            &signature
        ));
    }

    #[test]
    fn authenticated_envelope_signature_is_stable_and_tamper_evident() {
        let secret = b"cluster-secret";
        let mut envelope = proto::RequestEnvelope {
            request_id: "req-1".to_string(),
            protocol_version: PROTOCOL_VERSION,
            node_id: "node".to_string(),
            method: "/node/info".to_string(),
            payload: vec![1, 2, 3],
            auth_timestamp_unix_seconds: 123,
            auth_signature_hex: String::new(),
            public_key_hex: String::new(),
            identity_signature_hex: String::new(),
        };
        let signature = sign_request_envelope(secret, &envelope);
        envelope.auth_signature_hex = signature.clone();
        assert_eq!(signature, sign_request_envelope(secret, &envelope));
        envelope.payload.push(4);
        assert_ne!(signature, sign_request_envelope(secret, &envelope));
    }

    #[test]
    fn replay_window_rejects_duplicates_bounds_capacity_and_expires_buckets() {
        let mut window = ReplayWindow::default();
        let first = [1u8; 16];
        let second = [2u8; 16];
        window.admit(100, first, 1).unwrap();
        assert!(matches!(
            window.admit(101, first, 1),
            Err(NetworkError::Unauthenticated)
        ));
        assert!(matches!(
            window.admit(101, second, 1),
            Err(NetworkError::RateLimited)
        ));
        window.admit(166, second, 1).unwrap();
        assert_eq!(window.entries, 1);
    }

    #[test]
    fn only_clean_peer_stream_stop_is_classified_as_cancellation() {
        let clean_stop =
            NetworkError::Write(quinn::WriteError::Stopped(quinn::VarInt::from_u32(0)));
        let failed_stop =
            NetworkError::Write(quinn::WriteError::Stopped(quinn::VarInt::from_u32(1)));

        assert!(is_expected_stream_cancellation(&clean_stop));
        assert!(!is_expected_stream_cancellation(&failed_stop));
    }
}
