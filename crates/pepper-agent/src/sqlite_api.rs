// SPDX-License-Identifier: Apache-2.0

//! Production SQLite page service, local VFS protocol, and administrative API.
//!
//! The explicitly marked whole-file handlers at the end of this module remain
//! feasibility-only compatibility endpoints; production writes use the
//! page-granular guarded transaction path.

use super::*;
use axum::http::HeaderName;
use pepper_merkle::{MerkleLimits, MerkleValue};
use pepper_namespace::{
    CommandEnvelope, KeyPrecondition, NamespaceCommand, NamespaceKind, NamespaceMutation,
    NamespaceState, NamespaceStateMachine, TransactionCommand,
};
use pepper_publication::ReadLease;
use pepper_sqlite::{
    AcquisitionStatus, CachePolicyBounds, CommitRecord, DatabaseDescriptor, GuardedCommitRequest,
    IncrementalDurabilityProof, IncrementalProofInput, PagePackStore, PagePackWrite,
    PageStoragePolicy, PageTable, SnapshotDescriptor, SqliteBlockStore, SqliteError,
    SqliteFormatLimits, WriterControlRequest, WriterControlResponse, WriterTicket,
    build_incremental_snapshot_stream, export_snapshot,
    format::{decode_canonical, encode_canonical},
    import_snapshot,
    protocol::{
        LocalFrame, LocalMessage, LocalProtocolLimits, LocalRequest, LocalResponse,
        PagePayloadLayout, ServerHello, frame_body_lengths,
    },
    validate_sqlite_file,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::io::{ReaderStream, StreamReader};

#[cfg(unix)]
use std::io::{Seek, SeekFrom, Write};

const SQLITE_CONFIG_KEY: &[u8] = b"\xffsqlite/config";
const SQLITE_HEAD_KEY: &[u8] = b"\xffsqlite/head";
const EXPERIMENTAL_HEADER: &str = "whole-file-v1";

fn validate_sqlite_import_with_upstream(
    path: &std::path::Path,
    expected_page_size: u32,
) -> Result<(), String> {
    let connection = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("SQLite could not open the import: {error}"))?;
    let page_size = connection
        .query_row("PRAGMA page_size", [], |row| row.get::<_, u32>(0))
        .map_err(|error| format!("SQLite could not read the import page size: {error}"))?;
    if page_size != expected_page_size {
        return Err(format!(
            "SQLite import page size {page_size} does not match database page size {expected_page_size}"
        ));
    }
    let integrity = connection
        .query_row("PRAGMA integrity_check(100)", [], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|error| format!("SQLite integrity check failed to run: {error}"))?;
    if integrity != "ok" {
        return Err(format!("SQLite integrity check failed: {integrity}"));
    }
    Ok(())
}

struct SqliteCommitMetric {
    succeeded: bool,
}

impl SqliteCommitMetric {
    fn begin() -> Self {
        Self { succeeded: false }
    }

    fn succeed(&mut self) {
        self.succeeded = true;
    }
}

impl Drop for SqliteCommitMetric {
    fn drop(&mut self) {
        if !self.succeeded {
            SQLITE_COMMIT_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

struct SqliteCompactionMetric {
    succeeded: bool,
}

impl SqliteCompactionMetric {
    fn begin() -> Self {
        Self { succeeded: false }
    }

    fn succeed(&mut self) {
        self.succeeded = true;
        SQLITE_COMPACTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Drop for SqliteCompactionMetric {
    fn drop(&mut self) {
        if !self.succeeded {
            SQLITE_COMPACTION_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct SqliteReadSession {
    database: String,
    namespace_id: pepper_namespace::NamespaceId,
    revision: u64,
    snapshot_cid: Cid,
    snapshot: SnapshotDescriptor,
    lease_id: String,
    expires_at_unix_seconds: i64,
}

#[derive(Clone)]
struct AgentSqliteStore {
    state: AppState,
    receipts: Arc<Mutex<Vec<DurabilityReceipt>>>,
}

#[derive(Clone)]
struct AgentSqliteProposer {
    state: AppState,
}

#[async_trait]
impl pepper_publication::GuardedNamespaceProposer for AgentSqliteProposer {
    async fn propose(
        &self,
        namespace: &pepper_namespace::NamespaceId,
        guard: &pepper_publication::PublicationGuard,
        command: CommandEnvelope,
    ) -> Result<pepper_consensus::ConsensusResponse, pepper_publication::PublicationError> {
        let pepper_publication::PublicationGuard::Application { kind, payload } = guard else {
            return Err(pepper_publication::PublicationError::Application {
                code: "sqlite_guard_required".into(),
                message: "SQLite publication requires a writer guard".into(),
            });
        };
        if kind != "pepper.sqlite_writer.v1" {
            return Err(pepper_publication::PublicationError::Application {
                code: "invalid_sqlite_guard".into(),
                message: "unknown SQLite publication guard".into(),
            });
        }
        let guard: GuardedCommitRequest = serde_json::from_slice(payload).map_err(|_| {
            pepper_publication::PublicationError::Application {
                code: "invalid_sqlite_guard".into(),
                message: "invalid SQLite publication guard payload".into(),
            }
        })?;
        self.state
            .namespace_groups
            .as_ref()
            .ok_or_else(|| {
                pepper_publication::PublicationError::Namespace(
                    "namespace consensus is disabled".into(),
                )
            })?
            .routed_sqlite_guarded_write(namespace, guard, command)
            .await
            .map_err(|error| pepper_publication::PublicationError::Namespace(error.to_string()))
    }
}

impl AgentSqliteStore {
    fn new(state: AppState) -> Self {
        Self {
            state,
            receipts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn receipts(&self) -> Result<Vec<DurabilityReceipt>, SqliteError> {
        self.receipts
            .lock()
            .map(|receipts| receipts.clone())
            .map_err(|_| SqliteError::Storage("SQLite receipt lock poisoned".into()))
    }

    fn record(&self, receipts: &[DurabilityReceipt]) -> Result<(), SqliteError> {
        self.receipts
            .lock()
            .map_err(|_| SqliteError::Storage("SQLite receipt lock poisoned".into()))?
            .extend_from_slice(receipts);
        Ok(())
    }
}

#[async_trait]
impl SqliteBlockStore for AgentSqliteStore {
    async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
        get_block_resolved(&self.state, cid)
            .await
            .map(|block| block.payload)
            .map_err(|error| error.message)
    }

    async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
        let receipt = put_replicated_block(&self.state, codec, payload)
            .await
            .map_err(|error| error.message)?;
        self.record(std::slice::from_ref(&receipt))
            .map_err(|error| error.to_string())?;
        Ok(receipt.cid)
    }
}

#[async_trait]
impl PagePackStore for AgentSqliteStore {
    async fn put_page_pack(
        &self,
        payload: Vec<u8>,
        policy: &PageStoragePolicy,
    ) -> Result<PagePackWrite, String> {
        let payload_bytes = payload.len() as u64;
        let object_policy = match policy {
            PageStoragePolicy::Replicated { replicas }
                if *replicas == self.state.replication_factor as u16 =>
            {
                ObjectWritePolicy::Replicated
            }
            PageStoragePolicy::Replicated { .. } => {
                return Err("SQLite replica count must match namespace durability".into());
            }
            PageStoragePolicy::Erasure {
                data_shards,
                parity_shards,
                shard_copies: 1,
            } => ObjectWritePolicy::Erasure {
                data_shards: *data_shards,
                parity_shards: *parity_shards,
            },
            PageStoragePolicy::Erasure { .. } => {
                return Err("SQLite EC shard copies other than one are not supported".into());
            }
            PageStoragePolicy::Adaptive {
                small_commit_replicas,
                large_commit_data_shards,
                large_commit_parity_shards,
                large_commit_shard_copies: 1,
                threshold_bytes,
            } if *small_commit_replicas == self.state.replication_factor as u16
                && payload.len() as u64 >= u64::from(*threshold_bytes) =>
            {
                ObjectWritePolicy::Erasure {
                    data_shards: *large_commit_data_shards,
                    parity_shards: *large_commit_parity_shards,
                }
            }
            PageStoragePolicy::Adaptive {
                small_commit_replicas,
                large_commit_shard_copies: 1,
                ..
            } if *small_commit_replicas == self.state.replication_factor as u16 => {
                ObjectWritePolicy::Replicated
            }
            PageStoragePolicy::Adaptive { .. } => {
                return Err(
                    "SQLite adaptive replica count must match namespace durability and shard copies must be one"
                        .into(),
                );
            }
        };
        let stored = ObjectWriteService::new(self.state.clone())
            .write_bytes(payload, object_policy)
            .await
            .map_err(|error| error.message)?;
        SQLITE_PAGE_PACK_WRITES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        SQLITE_PAGE_PACK_WRITE_BYTES.fetch_add(payload_bytes, std::sync::atomic::Ordering::Relaxed);
        if matches!(object_policy, ObjectWritePolicy::Erasure { .. }) {
            SQLITE_EC_PAGE_PACK_WRITES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let root = stored.receipt.cid.clone();
        let mut descendants = stored
            .blocks
            .iter()
            .filter(|receipt| receipt.cid != root)
            .map(|receipt| receipt.cid.clone())
            .collect::<Vec<_>>();
        descendants.sort_by_key(ToString::to_string);
        descendants.dedup();
        self.record(&stored.blocks)
            .map_err(|error| error.to_string())?;
        Ok(PagePackWrite {
            root,
            verified_descendants: descendants,
        })
    }

    async fn get_page_pack(&self, root: &Cid) -> Result<Vec<u8>, String> {
        if let Some(bytes) = self.state.sqlite_pack_cache.get(root) {
            SQLITE_PAGE_CACHE_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok((*bytes).clone());
        }
        let fetch = {
            let mut fetches = self.state.sqlite_pack_fetches.lock().await;
            fetches
                .entry(root.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _fetch_guard = fetch.lock().await;
        if let Some(bytes) = self.state.sqlite_pack_cache.get(root) {
            SQLITE_PAGE_CACHE_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok((*bytes).clone());
        }
        SQLITE_PAGE_CACHE_MISSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let resolved = async {
            let response = get_object_at_placement(self.state.clone(), root.clone(), None, None)
                .await
                .map_err(|error| error.message)?;
            let limit = SqliteFormatLimits::default().max_pack_bytes as usize;
            axum::body::to_bytes(response.into_body(), limit)
                .await
                .map_err(|error| error.to_string())
                .map(|bytes| bytes.to_vec())
        }
        .await;
        if let Ok(bytes) = &resolved {
            self.state
                .sqlite_pack_cache
                .insert_resolved(root.clone(), bytes.clone());
        }
        let mut fetches = self.state.sqlite_pack_fetches.lock().await;
        if fetches
            .get(root)
            .is_some_and(|active| Arc::ptr_eq(active, &fetch))
        {
            fetches.remove(root);
        }
        resolved
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WholeFileCreateRequest {
    database: String,
    request_id: String,
    page_size: Option<u32>,
    max_page_count: Option<u32>,
    page_pack_target_bytes: Option<u32>,
    storage_policy: Option<PageStoragePolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WholeFileCommitQuery {
    request_id: String,
    base_revision: u64,
    base_generation: u64,
    base_cid: Cid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SqliteCreateRequest {
    database: String,
    request_id: String,
    page_size: Option<u32>,
    max_page_count: Option<u32>,
    page_pack_target_bytes: Option<u32>,
    storage_policy: Option<PageStoragePolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SqliteImportQuery {
    request_id: String,
    base_revision: u64,
    base_generation: u64,
    base_snapshot: Cid,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct SqliteSnapshotSelection {
    snapshot: Option<Cid>,
    revision: Option<u64>,
    root_cid: Option<Cid>,
    checkpoint_cid: Option<Cid>,
    named_snapshot: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct SqliteSessionCreateRequest {
    #[serde(flatten)]
    selection: SqliteSnapshotSelection,
}

#[derive(Debug, Deserialize)]
pub(super) struct SqlitePageQuery {
    pages: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SqliteWriterAcquireRequest {
    session_id: String,
    acquisition_id: String,
    base_snapshot: Cid,
    base_generation: u64,
    wait_timeout_millis: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SqliteWriterTicketRequest {
    ticket: WriterTicket,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct SqliteCompactRequest {
    request_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SqliteRollbackRequest {
    revision: u64,
    request_id: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SqliteIncrementalCommitQuery {
    request_id: String,
    base_revision: u64,
    base_generation: u64,
    base_snapshot: Cid,
    new_logical_size: u64,
    pages: String,
    ticket_id: String,
    acquisition_id: String,
    holder: String,
    leader_term: u64,
    lease_epoch: u64,
    expires_at_millis: u64,
}

fn sqlite_config(state: &AppState) -> Result<&pepper_config::SqliteConfig, ApiError> {
    state.sqlite_config.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "SQLite service is disabled",
        )
    })
}

fn sqlite_error(error: SqliteError) -> ApiError {
    match error {
        SqliteError::Limit(message) => ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::PayloadTooLarge,
            message,
        ),
        SqliteError::GenerationConflict { .. } | SqliteError::Busy | SqliteError::Fenced => {
            ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::GenerationConflict,
                error.to_string(),
            )
        }
        SqliteError::Storage(message) => ApiError::internal(message),
        _ => ApiError::bad_request(error.to_string()),
    }
}

async fn sqlite_namespace(
    state: &AppState,
    database: &str,
) -> Result<(pepper_namespace::NamespaceId, NamespaceState), ApiError> {
    let namespace_id = match parse_namespace(state, database) {
        Ok(namespace) => namespace,
        Err(error) if error.code == ErrorCode::NotFound => {
            let mut discovered = None;
            'peers: for peer in state.network.peers().await {
                for address in peer.addresses {
                    let Ok(address) = address.parse() else {
                        continue;
                    };
                    let Ok(response) = state
                        .network
                        .namespace_alias_resolve(address, database.to_string())
                        .await
                    else {
                        continue;
                    };
                    if !response.found {
                        continue;
                    }
                    let cid = response
                        .namespace_id
                        .parse::<Cid>()
                        .map_err(|error| ApiError::bad_request(error.to_string()))?;
                    let namespace =
                        pepper_namespace::NamespaceId::new(cid).map_err(namespace_error)?;
                    cache_alias(state, database, &namespace)?;
                    discovered = Some(namespace);
                    break 'peers;
                }
            }
            discovered.ok_or(error)?
        }
        Err(error) => return Err(error),
    };
    let namespace = namespace_manager(state)?
        .linearizable_namespace_state(&namespace_id)
        .await
        .map_err(consensus_error)?;
    if namespace.descriptor.kind != NamespaceKind::Sqlite {
        return Err(ApiError::bad_request("namespace is not a SQLite database"));
    }
    Ok((namespace_id, namespace))
}

async fn sqlite_values(
    state: &AppState,
    namespace: NamespaceState,
) -> Result<(MerkleValue, MerkleValue), ApiError> {
    let machine = NamespaceStateMachine::new(state.namespace_data_store.clone(), namespace)
        .map_err(namespace_error)?;
    let config = machine
        .get(None, SQLITE_CONFIG_KEY)
        .await
        .map_err(namespace_error)?
        .ok_or_else(|| ApiError::not_found("SQLite database has no configuration"))?;
    let head = machine
        .get(None, SQLITE_HEAD_KEY)
        .await
        .map_err(namespace_error)?
        .ok_or_else(|| ApiError::not_found("SQLite database has no head"))?;
    Ok((config, head))
}

async fn database_descriptor(
    state: &AppState,
    value: &MerkleValue,
) -> Result<DatabaseDescriptor, ApiError> {
    if value.cid.codec != pepper_types::CODEC_SQLITE_DATABASE {
        return Err(ApiError::bad_request(
            "SQLite configuration has an unexpected codec",
        ));
    }
    let block = get_block_resolved(state, &value.cid).await?;
    let descriptor: DatabaseDescriptor = decode_canonical(
        &block.payload,
        SqliteFormatLimits::default().max_descriptor_bytes,
    )
    .map_err(sqlite_error)?;
    descriptor
        .validate(SqliteFormatLimits::default())
        .map_err(sqlite_error)?;
    Ok(descriptor)
}

async fn snapshot_descriptor(state: &AppState, cid: &Cid) -> Result<SnapshotDescriptor, ApiError> {
    if cid.codec != pepper_types::CODEC_SQLITE_SNAPSHOT {
        return Err(ApiError::bad_request("SQLite head has an unexpected codec"));
    }
    let block = get_block_resolved(state, cid).await?;
    let descriptor: SnapshotDescriptor = decode_canonical(
        &block.payload,
        SqliteFormatLimits::default().max_descriptor_bytes,
    )
    .map_err(sqlite_error)?;
    descriptor
        .validate(SqliteFormatLimits::default())
        .map_err(sqlite_error)?;
    Ok(descriptor)
}

pub(super) async fn sqlite_create(
    State(state): State<AppState>,
    Json(request): Json<SqliteCreateRequest>,
) -> Result<Response, ApiError> {
    let configured = sqlite_config(&state)?;
    if request.request_id.is_empty() || request.request_id.len() > 128 {
        return Err(ApiError::bad_request(
            "request_id must contain 1 to 128 bytes",
        ));
    }
    pepper_sqlite::PepperDatabaseUri::parse(&format!("pepper:{}?mode=rwc", request.database))
        .map_err(sqlite_error)?;
    let limits = SqliteFormatLimits::default();
    let page_size = request.page_size.unwrap_or(configured.default_page_size);
    let max_page_count = request.max_page_count.unwrap_or_else(|| {
        limits
            .max_page_count
            .min((limits.max_logical_bytes / u64::from(page_size)) as u32)
    });
    let page_pack_target_bytes = request
        .page_pack_target_bytes
        .unwrap_or(configured.page_pack_target_bytes);
    let storage_policy = request
        .storage_policy
        .unwrap_or(PageStoragePolicy::Replicated {
            replicas: state.replication_factor as u16,
        });
    match &storage_policy {
        PageStoragePolicy::Replicated { replicas }
            if *replicas == state.replication_factor as u16 => {}
        PageStoragePolicy::Erasure {
            shard_copies: 1, ..
        } => {}
        PageStoragePolicy::Adaptive {
            small_commit_replicas,
            large_commit_shard_copies: 1,
            ..
        } if *small_commit_replicas == state.replication_factor as u16 => {}
        _ => {
            return Err(ApiError::bad_request(
                "SQLite replicated policies must match namespace durability and EC shard copies must be one",
            ));
        }
    }
    let descriptor = DatabaseDescriptor::new(
        page_size,
        max_page_count,
        page_pack_target_bytes,
        storage_policy,
        CachePolicyBounds {
            minimum_bytes: u64::from(page_pack_target_bytes),
            maximum_bytes: configured.page_cache_bytes,
        },
        unix_seconds(),
        state.status.node_id.clone(),
    );
    descriptor.validate(limits).map_err(sqlite_error)?;

    let created = super::namespace_api::namespace_create(
        State(state.clone()),
        Json(super::namespace_api::CreateNamespaceRequest {
            kind: NamespaceKind::Sqlite,
            alias: Some(request.database.clone()),
            request_id: Some(request.request_id.clone()),
            retention_keep_last: None,
            retention_max_age_seconds: None,
        }),
    )
    .await?
    .0;
    let store = AgentSqliteStore::new(state.clone());
    let config_payload =
        encode_canonical(&descriptor, limits.max_descriptor_bytes).map_err(sqlite_error)?;
    let config_cid = store
        .put(pepper_types::CODEC_SQLITE_DATABASE, config_payload)
        .await
        .map_err(|error| sqlite_error(SqliteError::Storage(error)))?;
    let page_table_root = PageTable { limits }
        .empty_root(&store)
        .await
        .map_err(sqlite_error)?;
    let snapshot = SnapshotDescriptor {
        descriptor_type: "pepper.sqlite_snapshot".into(),
        version: 1,
        database_cid: config_cid.clone(),
        page_table_root_cid: page_table_root,
        page_size,
        page_count: 0,
        logical_size: 0,
        base_snapshot_cid: None,
    };
    let snapshot_payload =
        encode_canonical(&snapshot, limits.max_descriptor_bytes).map_err(sqlite_error)?;
    let snapshot_cid = store
        .put(pepper_types::CODEC_SQLITE_SNAPSHOT, snapshot_payload)
        .await
        .map_err(|error| sqlite_error(SqliteError::Storage(error)))?;
    let base = namespace_manager(&state)?
        .linearizable_namespace_state(&created.namespace_id)
        .await
        .map_err(consensus_error)?;
    let command = CommandEnvelope {
        request_id: request.request_id,
        writer_identity: "sqlite-http".into(),
        timestamp_unix_seconds: unix_seconds(),
        signature_hex: "00".into(),
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: base.current_revision,
                base_root_cid: base.current_root_cid,
                mutations: vec![
                    NamespaceMutation::Put {
                        key_hex: hex::encode(SQLITE_CONFIG_KEY),
                        value_cid: config_cid.clone(),
                        value_kind: "sqlite_database_config".into(),
                        metadata: BTreeMap::new(),
                        precondition: KeyPrecondition::Absent,
                    },
                    NamespaceMutation::Put {
                        key_hex: hex::encode(SQLITE_HEAD_KEY),
                        value_cid: snapshot_cid.clone(),
                        value_kind: "sqlite_snapshot".into(),
                        metadata: BTreeMap::from([
                            ("logical_size".into(), "0".into()),
                            ("page_count".into(), "0".into()),
                        ]),
                        precondition: KeyPrecondition::Absent,
                    },
                ],
                message: Some("initialize SQLite database".into()),
            },
        },
    };
    let namespace = apply_command(
        &state,
        created.namespace_id.clone(),
        command,
        vec![snapshot_cid.clone()],
        store.receipts().map_err(sqlite_error)?,
        0,
        false,
    )
    .await?
    .0;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "database": request.database,
            "namespace_id": created.namespace_id,
            "configuration_cid": config_cid,
            "snapshot_cid": snapshot_cid,
            "head_generation": 1,
            "namespace": namespace,
        })),
    )
        .into_response())
}

pub(super) async fn sqlite_info(
    State(state): State<AppState>,
    Path(database): Path<String>,
) -> Result<Response, ApiError> {
    sqlite_config(&state)?;
    let (namespace_id, namespace) = sqlite_namespace(&state, &database).await?;
    let revision = namespace.current_revision;
    let (config_value, head) = sqlite_values(&state, namespace).await?;
    let descriptor = database_descriptor(&state, &config_value).await?;
    let snapshot = snapshot_descriptor(&state, &head.cid).await?;
    if snapshot.database_cid != config_value.cid || snapshot.page_size != descriptor.page_size {
        return Err(ApiError::internal(
            "SQLite snapshot does not match its database configuration",
        ));
    }
    Ok(Json(serde_json::json!({
        "database": database,
        "namespace_id": namespace_id,
        "namespace_revision": revision,
        "configuration_cid": config_value.cid,
        "configuration": descriptor,
        "snapshot_cid": head.cid,
        "head_generation": head.generation,
        "snapshot": snapshot,
    }))
    .into_response())
}

pub(super) async fn sqlite_check(
    State(state): State<AppState>,
    Path(database): Path<String>,
) -> Result<Response, ApiError> {
    sqlite_config(&state)?;
    let (_, namespace) = sqlite_namespace(&state, &database).await?;
    let (_, head) = sqlite_values(&state, namespace).await?;
    let snapshot = snapshot_descriptor(&state, &head.cid).await?;
    let store = AgentSqliteStore::new(state);
    let validation = PageTable::default()
        .validate_complete(
            &store,
            &snapshot.page_table_root_cid,
            snapshot.page_size,
            snapshot.page_count,
            true,
        )
        .await
        .map_err(sqlite_error)?;
    Ok(Json(serde_json::json!({
        "database": database,
        "snapshot_cid": head.cid,
        "head_generation": head.generation,
        "page_count": validation.page_count,
        "page_table_nodes": validation.node_cids.len(),
        "page_pack_roots": validation.page_pack_roots.len(),
        "status": "ok"
    }))
    .into_response())
}

pub(super) async fn admin_sqlite_status(State(state): State<AppState>) -> Response {
    let sessions = state
        .sqlite_sessions
        .lock()
        .map_or(0, |sessions| sessions.len());
    let namespace_statuses = match &state.namespace_groups {
        Some(manager) => manager.operational_statuses().await,
        None => Vec::new(),
    };
    let write_quorum_ready = namespace_statuses.iter().all(|status| {
        status.running
            && status.leader_raft_id.is_some()
            && status.voter_count == 3
            && !status.membership_joint
            && (status.role != "leader" || status.quorum_recently_acknowledged)
    });
    let runtime_ready = state
        .sqlite_ready
        .load(std::sync::atomic::Ordering::Relaxed);
    Json(serde_json::json!({
        "enabled": state.sqlite_enabled,
        "ready": runtime_ready && write_quorum_ready,
        "runtime_ready": runtime_ready,
        "write_quorum_ready": write_quorum_ready,
        "read_only_degraded": runtime_ready && !write_quorum_ready,
        "access_mode": if !runtime_ready { "unavailable" } else if write_quorum_ready { "read_write" } else { "read_only_degraded" },
        "open_sessions": sessions,
        "page_cache_bytes": state.sqlite_pack_cache.current_bytes(),
        "socket_path": state.sqlite_socket_path,
    }))
    .into_response()
}

pub(super) async fn admin_sqlite_sessions(
    State(state): State<AppState>,
) -> Result<Response, ApiError> {
    let sessions = state
        .sqlite_sessions
        .lock()
        .map_err(|_| ApiError::internal("SQLite session lock poisoned"))?;
    let mut records = sessions
        .iter()
        .take(1024)
        .map(|(session_id, session)| {
            serde_json::json!({
                "session_id": session_id,
                "database": session.database,
                "snapshot_cid": session.snapshot_cid,
                "expires_at_unix_seconds": session.expires_at_unix_seconds,
            })
        })
        .collect::<Vec<_>>();
    records.sort_by_key(|record| {
        record["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    });
    Ok(Json(serde_json::json!({"sessions": records})).into_response())
}

pub(super) async fn admin_sqlite_locks(
    State(state): State<AppState>,
) -> Result<Response, ApiError> {
    let locks = namespace_manager(&state)?.sqlite_writer_diagnostics().await;
    Ok(Json(serde_json::json!({"locks": locks})).into_response())
}

pub(super) async fn admin_sqlite_staging(
    State(state): State<AppState>,
) -> Result<Response, ApiError> {
    let leases = state
        .publication_repository
        .active_staging(unix_seconds())
        .map_err(|error| ApiError::internal(error.to_string()))?
        .into_iter()
        .filter(|lease| {
            lease
                .roots
                .iter()
                .any(|root| root.codec == pepper_types::CODEC_SQLITE_SNAPSHOT)
        })
        .take(1024)
        .collect::<Vec<_>>();
    let staged_bytes = leases.iter().map(|lease| lease.staged_bytes).sum::<u64>();
    let active_leases = leases.len();
    Ok(Json(serde_json::json!({
        "leases": leases,
        "active_leases": active_leases,
        "staged_bytes": staged_bytes,
    }))
    .into_response())
}

pub(super) async fn admin_sqlite_repair(
    State(state): State<AppState>,
) -> Result<Response, ApiError> {
    let result = run_repair(State(state)).await?;
    Ok(Json(serde_json::json!({
        "application": "sqlite",
        "scope": "shared_content_addressed_storage",
        "result": result.0,
    }))
    .into_response())
}

pub(super) async fn sqlite_import(
    State(state): State<AppState>,
    Path(database): Path<String>,
    Query(query): Query<SqliteImportQuery>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let configured = sqlite_config(&state)?;
    if query.request_id.is_empty() || query.request_id.len() > 128 {
        return Err(ApiError::bad_request(
            "request_id must contain 1 to 128 bytes",
        ));
    }
    let logical_size = headers
        .get(header::CONTENT_LENGTH)
        .ok_or_else(|| ApiError::bad_request("SQLite import requires Content-Length"))?
        .to_str()
        .map_err(|error| ApiError::bad_request(error.to_string()))?
        .parse::<u64>()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    enforce_size_limit(
        Some(configured.max_staged_bytes_per_transaction),
        logical_size,
        "SQLite import",
    )?;
    let (namespace_id, namespace) = sqlite_namespace(&state, &database).await?;
    let (config_value, head) = sqlite_values(&state, namespace.clone()).await?;
    let replaying = namespace.idempotent_response(&query.request_id).is_some();
    if !replaying && (head.cid != query.base_snapshot || head.generation != query.base_generation) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::GenerationConflict,
            format!(
                "SQLite head changed: current CID {}, generation {}",
                head.cid, head.generation
            ),
        ));
    }
    let database_descriptor = database_descriptor(&state, &config_value).await?;
    let store = AgentSqliteStore::new(state.clone());
    let temporary = tempfile::NamedTempFile::new()
        .map_err(|error| ApiError::internal(format!("failed to stage SQLite import: {error}")))?;
    let mut staged = tokio::fs::File::from_std(temporary.reopen().map_err(|error| {
        ApiError::internal(format!("failed to open staged SQLite import: {error}"))
    })?);
    let stream = body
        .into_data_stream()
        .map_err(|error| std::io::Error::other(error.to_string()));
    let reader = StreamReader::new(stream);
    let received = tokio::io::copy(
        &mut reader.take(logical_size.saturating_add(1)),
        &mut staged,
    )
    .await
    .map_err(|error| ApiError::bad_request(format!("failed to receive SQLite import: {error}")))?;
    if received != logical_size {
        return Err(ApiError::bad_request(format!(
            "SQLite import Content-Length is {logical_size} bytes but received {received} bytes"
        )));
    }
    staged
        .flush()
        .await
        .map_err(|error| ApiError::internal(format!("failed to flush SQLite import: {error}")))?;
    staged
        .sync_all()
        .await
        .map_err(|error| ApiError::internal(format!("failed to sync SQLite import: {error}")))?;
    drop(staged);

    let validation_path = temporary.path().to_owned();
    let expected_page_size = database_descriptor.page_size;
    tokio::task::spawn_blocking(move || {
        validate_sqlite_import_with_upstream(&validation_path, expected_page_size)
    })
    .await
    .map_err(|error| ApiError::internal(format!("SQLite integrity task failed: {error}")))?
    .map_err(ApiError::bad_request)?;

    let mut reader = tokio::fs::File::from_std(temporary.reopen().map_err(|error| {
        ApiError::internal(format!("failed to reopen staged SQLite import: {error}"))
    })?);
    let imported = import_snapshot(
        &store,
        &mut reader,
        logical_size,
        config_value.cid.clone(),
        &database_descriptor,
        Some(query.base_snapshot.clone()),
        SqliteFormatLimits::default(),
    )
    .await
    .map_err(sqlite_error)?;
    let command = CommandEnvelope {
        request_id: query.request_id.clone(),
        writer_identity: "sqlite-http".into(),
        timestamp_unix_seconds: unix_seconds(),
        signature_hex: "00".into(),
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: query.base_revision,
                base_root_cid: if namespace.current_revision == query.base_revision {
                    namespace.current_root_cid.clone()
                } else {
                    namespace
                        .history
                        .get(&query.base_revision)
                        .map(|record| record.root_cid.clone())
                        .ok_or_else(|| ApiError::not_found("SQLite base revision not retained"))?
                },
                mutations: vec![NamespaceMutation::Put {
                    key_hex: hex::encode(SQLITE_HEAD_KEY),
                    value_cid: imported.snapshot_cid.clone(),
                    value_kind: "sqlite_snapshot".into(),
                    metadata: BTreeMap::from([
                        ("logical_size".into(), logical_size.to_string()),
                        (
                            "page_count".into(),
                            imported.descriptor.page_count.to_string(),
                        ),
                    ]),
                    precondition: KeyPrecondition::Match {
                        generation: query.base_generation,
                        cid: query.base_snapshot,
                    },
                }],
                message: Some("import SQLite snapshot".into()),
            },
        },
    };
    let namespace = apply_command(
        &state,
        namespace_id,
        command,
        vec![imported.snapshot_cid.clone()],
        store.receipts().map_err(sqlite_error)?,
        logical_size,
        false,
    )
    .await?
    .0;
    Ok(Json(serde_json::json!({
        "request_id": query.request_id,
        "snapshot_cid": imported.snapshot_cid,
        "head_generation": query.base_generation.saturating_add(1),
        "snapshot": imported.descriptor,
        "namespace": namespace,
    }))
    .into_response())
}

async fn selected_snapshot(
    state: &AppState,
    database: &str,
    selection: SqliteSnapshotSelection,
) -> Result<(pepper_namespace::NamespaceId, u64, Cid, SnapshotDescriptor), ApiError> {
    let (namespace_id, namespace) = sqlite_namespace(state, database).await?;
    let selected_count = usize::from(selection.snapshot.is_some())
        + usize::from(selection.revision.is_some())
        + usize::from(selection.root_cid.is_some())
        + usize::from(selection.checkpoint_cid.is_some())
        + usize::from(selection.named_snapshot.is_some());
    if selected_count > 1 {
        return Err(ApiError::bad_request(
            "choose only one SQLite snapshot selector",
        ));
    }
    let (config, current_head) = sqlite_values(state, namespace.clone()).await?;
    let mut revision = namespace.current_revision;
    let snapshot_cid = if let Some(snapshot) = selection.snapshot {
        snapshot
    } else {
        let selected_root = if let Some(selected_revision) = selection.revision {
            revision = selected_revision;
            if selected_revision == namespace.current_revision {
                Some(namespace.current_root_cid.clone())
            } else {
                namespace
                    .history
                    .get(&selected_revision)
                    .map(|record| record.root_cid.clone())
                    .map(Some)
                    .ok_or_else(|| ApiError::not_found("SQLite revision is not retained"))?
            }
        } else if let Some(root) = selection.root_cid {
            revision = namespace
                .history
                .iter()
                .find_map(|(revision, record)| (record.root_cid == root).then_some(*revision))
                .or_else(|| {
                    (namespace.current_root_cid == root).then_some(namespace.current_revision)
                })
                .ok_or_else(|| ApiError::not_found("SQLite namespace root is not retained"))?;
            Some(root)
        } else if let Some(checkpoint) = selection.checkpoint_cid {
            let loaded = pepper_namespace::load_checkpoint(
                &state.namespace_data_store,
                &checkpoint,
                pepper_namespace::NamespaceLimits::default(),
            )
            .await
            .map_err(namespace_error)?;
            if loaded.namespace_id != namespace_id {
                return Err(ApiError::bad_request(
                    "SQLite checkpoint namespace mismatch",
                ));
            }
            revision = loaded.current_revision;
            Some(loaded.current_root_cid)
        } else if let Some(name) = selection.named_snapshot {
            let named = namespace
                .named_snapshots
                .get(&name)
                .ok_or_else(|| ApiError::not_found("SQLite named snapshot not found"))?;
            revision = named.revision;
            Some(named.root_cid.clone())
        } else {
            None
        };
        if let Some(selected_root) = selected_root {
            pepper_merkle::get(
                &state.namespace_data_store,
                &selected_root,
                SQLITE_HEAD_KEY,
                MerkleLimits::default(),
            )
            .await
            .map_err(|error| ApiError::bad_request(error.to_string()))?
            .ok_or_else(|| ApiError::not_found("selected namespace state has no SQLite head"))?
            .cid
        } else {
            current_head.cid
        }
    };
    let snapshot = snapshot_descriptor(state, &snapshot_cid).await?;
    if snapshot.database_cid != config.cid {
        return Err(ApiError::bad_request(
            "selected snapshot belongs to a different SQLite database",
        ));
    }
    Ok((namespace_id, revision, snapshot_cid, snapshot))
}

pub(super) async fn sqlite_export(
    State(state): State<AppState>,
    Path(database): Path<String>,
    Query(query): Query<SqliteSnapshotSelection>,
) -> Result<Response, ApiError> {
    sqlite_config(&state)?;
    let (namespace_id, revision, snapshot_cid, snapshot) =
        selected_snapshot(&state, &database, query).await?;
    let lease_id = format!("sqlite-export-{}", request_id());
    let now = unix_seconds();
    let lease = ReadLease {
        lease_id: lease_id.clone(),
        namespace_id,
        root_cid: snapshot_cid.clone(),
        revision,
        created_at_unix_seconds: now,
        expires_at_unix_seconds: now.saturating_add(300),
    };
    publication_coordinator(&state)?
        .acquire_read_lease(lease)
        .await
        .map_err(publication_error)?;
    let (reader, mut writer) = tokio::io::duplex(256 * 1024);
    let task_state = state.clone();
    tokio::spawn(async move {
        let store = AgentSqliteStore::new(task_state.clone());
        let result = export_snapshot(
            &store,
            &snapshot,
            &mut writer,
            SqliteFormatLimits::default(),
        )
        .await;
        drop(writer);
        if let Ok(coordinator) = publication_coordinator(&task_state) {
            let _ = coordinator.release_read_lease(&lease_id).await;
        }
        if let Err(error) = result {
            warn!(%error, "SQLite snapshot export failed");
        }
    });
    let body = Body::from_stream(ReaderStream::new(reader));
    let mut response = body.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.sqlite3"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-pepper-sqlite-snapshot"),
        HeaderValue::from_str(&snapshot_cid.to_string()).map_err(ApiError::header)?,
    );
    Ok(response)
}

pub(super) async fn sqlite_session_create(
    State(state): State<AppState>,
    Path(database): Path<String>,
    Json(request): Json<SqliteSessionCreateRequest>,
) -> Result<Response, ApiError> {
    let configured = sqlite_config(&state)?;
    let (namespace_id, revision, snapshot_cid, snapshot) =
        selected_snapshot(&state, &database, request.selection).await?;
    {
        let sessions = state
            .sqlite_sessions
            .lock()
            .map_err(|_| ApiError::internal("SQLite session lock poisoned"))?;
        if sessions.len() >= configured.max_open_sessions
            || sessions
                .values()
                .filter(|session| session.database == database)
                .count()
                >= configured.max_sessions_per_database
        {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Unavailable,
                "SQLite session limit reached",
            ));
        }
    }
    let session_id = format!("sqlite-session-{}", request_id());
    let lease_id = format!("{session_id}-read");
    let now = unix_seconds();
    let expires_at = now.saturating_add(configured.max_transaction_seconds as i64);
    publication_coordinator(&state)?
        .acquire_read_lease(ReadLease {
            lease_id: lease_id.clone(),
            namespace_id: namespace_id.clone(),
            root_cid: snapshot_cid.clone(),
            revision,
            created_at_unix_seconds: now,
            expires_at_unix_seconds: expires_at,
        })
        .await
        .map_err(publication_error)?;
    let session = SqliteReadSession {
        database,
        namespace_id,
        revision,
        snapshot_cid: snapshot_cid.clone(),
        snapshot: snapshot.clone(),
        lease_id,
        expires_at_unix_seconds: expires_at,
    };
    state
        .sqlite_sessions
        .lock()
        .map_err(|_| ApiError::internal("SQLite session lock poisoned"))?
        .insert(session_id.clone(), session);
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "session_id": session_id,
            "snapshot_cid": snapshot_cid,
            "page_size": snapshot.page_size,
            "page_count": snapshot.page_count,
            "logical_size": snapshot.logical_size,
            "expires_at_unix_seconds": expires_at,
        })),
    )
        .into_response())
}

pub(super) async fn sqlite_session_pages(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Query(query): Query<SqlitePageQuery>,
) -> Result<Response, ApiError> {
    let configured = sqlite_config(&state)?;
    let mut session = state
        .sqlite_sessions
        .lock()
        .map_err(|_| ApiError::internal("SQLite session lock poisoned"))?
        .get(&session_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("SQLite session not found"))?;
    if session.expires_at_unix_seconds <= unix_seconds() {
        state
            .sqlite_sessions
            .lock()
            .map_err(|_| ApiError::internal("SQLite session lock poisoned"))?
            .remove(&session_id);
        publication_coordinator(&state)?
            .release_read_lease(&session.lease_id)
            .await
            .map_err(publication_error)?;
        return Err(ApiError::not_found("SQLite session expired"));
    }
    let now = unix_seconds();
    if session.expires_at_unix_seconds.saturating_sub(now)
        <= configured.max_transaction_seconds as i64 / 2
    {
        let expires = now.saturating_add(configured.max_transaction_seconds as i64);
        publication_coordinator(&state)?
            .acquire_read_lease(ReadLease {
                lease_id: session.lease_id.clone(),
                namespace_id: session.namespace_id.clone(),
                root_cid: session.snapshot_cid.clone(),
                revision: session.revision,
                created_at_unix_seconds: now,
                expires_at_unix_seconds: expires,
            })
            .await
            .map_err(publication_error)?;
        session.expires_at_unix_seconds = expires;
        if let Some(stored) = state
            .sqlite_sessions
            .lock()
            .map_err(|_| ApiError::internal("SQLite session lock poisoned"))?
            .get_mut(&session_id)
        {
            stored.expires_at_unix_seconds = expires;
        }
    }
    let page_numbers = query
        .pages
        .split(',')
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| ApiError::bad_request("pages must be comma-separated integers"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if page_numbers.is_empty() || page_numbers.len() > 256 {
        return Err(ApiError::bad_request(
            "page batches must contain 1 through 256 pages",
        ));
    }
    if page_numbers
        .iter()
        .any(|number| *number == 0 || *number > session.snapshot.page_count)
    {
        return Err(ApiError::bad_request(
            "requested page is outside the snapshot",
        ));
    }
    let store = AgentSqliteStore::new(state.clone());
    let references = PageTable::default()
        .get_many(&store, &session.snapshot.page_table_root_cid, &page_numbers)
        .await
        .map_err(sqlite_error)?;
    let mut payload = Vec::with_capacity(
        page_numbers.len() * usize::try_from(session.snapshot.page_size).unwrap_or(65_536),
    );
    for (number, reference) in page_numbers.iter().zip(references) {
        let reference = reference.ok_or_else(|| {
            ApiError::internal(format!("SQLite snapshot is missing page {number}"))
        })?;
        let pack = store
            .get_page_pack(&reference.pack_cid)
            .await
            .map_err(|error| sqlite_error(SqliteError::Storage(error)))?;
        let start = reference.offset as usize;
        let end = start
            .checked_add(reference.length as usize)
            .filter(|end| *end <= pack.len())
            .ok_or_else(|| ApiError::internal("SQLite page reference exceeds its pack"))?;
        let page = &pack[start..end];
        if blake3::hash(page).to_hex().as_str() != reference.page_hash {
            return Err(ApiError::internal(format!(
                "SQLite page {number} failed verification"
            )));
        }
        payload.extend_from_slice(page);
    }
    SQLITE_PAGE_READS.fetch_add(
        page_numbers.len() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );
    SQLITE_PAGE_READ_BYTES.fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
    let mut response = Body::from(payload).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-pepper-sqlite-snapshot"),
        HeaderValue::from_str(&session.snapshot_cid.to_string()).map_err(ApiError::header)?,
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-pepper-sqlite-page-size"),
        HeaderValue::from_str(&session.snapshot.page_size.to_string()).map_err(ApiError::header)?,
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-pepper-sqlite-pages"),
        HeaderValue::from_str(&query.pages).map_err(ApiError::header)?,
    );
    Ok(response)
}

pub(super) async fn sqlite_session_close(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    sqlite_config(&state)?;
    let session = state
        .sqlite_sessions
        .lock()
        .map_err(|_| ApiError::internal("SQLite session lock poisoned"))?
        .remove(&session_id);
    let Some(session) = session else {
        return Ok(StatusCode::NO_CONTENT);
    };
    publication_coordinator(&state)?
        .release_read_lease(&session.lease_id)
        .await
        .map_err(publication_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn sqlite_now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

pub(super) async fn sqlite_writer_acquire(
    State(state): State<AppState>,
    Path(database): Path<String>,
    Json(request): Json<SqliteWriterAcquireRequest>,
) -> Result<Json<AcquisitionStatus>, ApiError> {
    let configured = sqlite_config(&state)?;
    if request.wait_timeout_millis > configured.max_transaction_seconds.saturating_mul(1000) {
        return Err(ApiError::bad_request(
            "writer wait timeout exceeds the limit",
        ));
    }
    let (namespace_id, namespace) = sqlite_namespace(&state, &database).await?;
    let (_, head) = sqlite_values(&state, namespace).await?;
    snapshot_descriptor(&state, &head.cid).await?;
    let response = namespace_manager(&state)?
        .routed_sqlite_writer(
            &namespace_id,
            WriterControlRequest::Acquire {
                acquisition_id: request.acquisition_id,
                session_id: request.session_id,
                base_snapshot_cid: request.base_snapshot,
                base_generation: request.base_generation,
                now_millis: sqlite_now_millis(),
                wait_timeout_millis: request.wait_timeout_millis,
                lease_millis: configured.max_transaction_seconds.saturating_mul(1000),
                max_waiters: configured.max_writer_waiters_per_database,
            },
        )
        .await
        .map_err(consensus_error)?;
    let WriterControlResponse::Acquisition { status } = response else {
        return Err(ApiError::internal("invalid SQLite writer response"));
    };
    Ok(Json(status))
}

pub(super) async fn sqlite_writer_renew(
    State(state): State<AppState>,
    Path(database): Path<String>,
    Json(request): Json<SqliteWriterTicketRequest>,
) -> Result<Json<WriterTicket>, ApiError> {
    sqlite_config(&state)?;
    let (namespace_id, _) = sqlite_namespace(&state, &database).await?;
    let response = namespace_manager(&state)?
        .routed_sqlite_writer(
            &namespace_id,
            WriterControlRequest::Renew {
                ticket: request.ticket,
                now_millis: sqlite_now_millis(),
            },
        )
        .await
        .map_err(consensus_error)?;
    let WriterControlResponse::Renewed { ticket } = response else {
        return Err(ApiError::internal("invalid SQLite writer response"));
    };
    Ok(Json(ticket))
}

pub(super) async fn sqlite_writer_release(
    State(state): State<AppState>,
    Path(database): Path<String>,
    Json(request): Json<SqliteWriterTicketRequest>,
) -> Result<StatusCode, ApiError> {
    sqlite_config(&state)?;
    let (namespace_id, _) = sqlite_namespace(&state, &database).await?;
    let response = namespace_manager(&state)?
        .routed_sqlite_writer(
            &namespace_id,
            WriterControlRequest::Release {
                ticket: request.ticket,
                now_millis: sqlite_now_millis(),
            },
        )
        .await
        .map_err(consensus_error)?;
    if !matches!(response, WriterControlResponse::Released) {
        return Err(ApiError::internal("invalid SQLite writer response"));
    }
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn sqlite_commit_status(
    State(state): State<AppState>,
    Path((database, idempotency_key)): Path<(String, String)>,
) -> Result<Json<CommitRecord>, ApiError> {
    sqlite_config(&state)?;
    if idempotency_key.is_empty() || idempotency_key.len() > 128 {
        return Err(ApiError::bad_request(
            "commit ID must contain 1 to 128 bytes",
        ));
    }
    let (namespace_id, _) = sqlite_namespace(&state, &database).await?;
    let response = namespace_manager(&state)?
        .routed_sqlite_writer(
            &namespace_id,
            WriterControlRequest::CommitStatus { idempotency_key },
        )
        .await
        .map_err(consensus_error)?;
    let WriterControlResponse::Commit { record } = response else {
        return Err(ApiError::internal("invalid SQLite writer response"));
    };
    Ok(Json(record.ok_or_else(|| {
        ApiError::not_found("SQLite commit ID not found")
    })?))
}

pub(super) async fn sqlite_compact(
    State(state): State<AppState>,
    Path(database): Path<String>,
    Json(request): Json<SqliteCompactRequest>,
) -> Result<Response, ApiError> {
    let configured = sqlite_config(&state)?;
    let request_id = request
        .request_id
        .unwrap_or_else(|| format!("sqlite-compact-{}", request_id()));
    if request_id.is_empty() || request_id.len() > 128 {
        return Err(ApiError::bad_request(
            "request_id must contain 1 to 128 bytes",
        ));
    }
    let (namespace_id, namespace) = sqlite_namespace(&state, &database).await?;
    if namespace.idempotent_response(&request_id).is_some() {
        let response = namespace_manager(&state)?
            .routed_sqlite_writer(
                &namespace_id,
                WriterControlRequest::CommitStatus {
                    idempotency_key: request_id.clone(),
                },
            )
            .await
            .map_err(consensus_error)?;
        let WriterControlResponse::Commit {
            record: Some(commit),
        } = response
        else {
            return Err(ApiError::internal(
                "committed SQLite compaction has no status record",
            ));
        };
        return Ok(Json(serde_json::json!({
            "commit": commit,
            "durability": "durable",
            "replayed": true,
        }))
        .into_response());
    }
    let mut compaction_metric = SqliteCompactionMetric::begin();
    let (_, head) = sqlite_values(&state, namespace.clone()).await?;
    let snapshot = snapshot_descriptor(&state, &head.cid).await?;
    enforce_size_limit(
        Some(configured.max_staged_bytes_per_transaction),
        snapshot.logical_size,
        "SQLite compaction",
    )?;
    let acquisition_id = format!("{request_id}:writer");
    let writer = namespace_manager(&state)?
        .routed_sqlite_writer(
            &namespace_id,
            WriterControlRequest::Acquire {
                acquisition_id,
                session_id: request_id.clone(),
                base_snapshot_cid: head.cid.clone(),
                base_generation: head.generation,
                now_millis: sqlite_now_millis(),
                wait_timeout_millis: 0,
                lease_millis: configured.max_transaction_seconds.saturating_mul(1000),
                max_waiters: configured.max_writer_waiters_per_database,
            },
        )
        .await
        .map_err(consensus_error)?;
    let WriterControlResponse::Acquisition {
        status: AcquisitionStatus::Granted { ticket },
    } = writer
    else {
        return Err(sqlite_error(SqliteError::Busy));
    };

    let (mut writer, reader) = tokio::io::duplex(256 * 1024);
    let export_store = AgentSqliteStore::new(state.clone());
    let export_snapshot_descriptor = snapshot.clone();
    let export = tokio::spawn(async move {
        export_snapshot(
            &export_store,
            &export_snapshot_descriptor,
            &mut writer,
            SqliteFormatLimits::default(),
        )
        .await
    });
    let pages = (1..=snapshot.page_count)
        .map(|page| page.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let result = sqlite_incremental_commit(
        State(state),
        Path(database),
        Query(SqliteIncrementalCommitQuery {
            request_id,
            base_revision: namespace.current_revision,
            base_generation: head.generation,
            base_snapshot: head.cid,
            new_logical_size: snapshot.logical_size,
            pages,
            ticket_id: ticket.ticket_id,
            acquisition_id: ticket.acquisition_id,
            holder: ticket.holder,
            leader_term: ticket.leader_term,
            lease_epoch: ticket.lease_epoch,
            expires_at_millis: ticket.expires_at_millis,
        }),
        Body::from_stream(ReaderStream::new(reader)),
    )
    .await;
    export
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .map_err(sqlite_error)?;
    if result.is_ok() {
        compaction_metric.succeed();
    }
    result
}

pub(super) async fn sqlite_rollback(
    State(state): State<AppState>,
    Path(database): Path<String>,
    Json(request): Json<SqliteRollbackRequest>,
) -> Result<Response, ApiError> {
    let mut commit_metric = SqliteCommitMetric::begin();
    let configured = sqlite_config(&state)?;
    if request.request_id.is_empty() || request.request_id.len() > 128 {
        return Err(ApiError::bad_request(
            "request_id must contain 1 to 128 bytes",
        ));
    }
    let (namespace_id, namespace) = sqlite_namespace(&state, &database).await?;
    if request.revision >= namespace.current_revision {
        return Err(ApiError::bad_request(
            "rollback revision must precede the current revision",
        ));
    }
    let (_, current_head) = sqlite_values(&state, namespace.clone()).await?;
    let historical_machine =
        NamespaceStateMachine::new(state.namespace_data_store.clone(), namespace.clone())
            .map_err(namespace_error)?;
    let historical_head = historical_machine
        .get(Some(request.revision), SQLITE_HEAD_KEY)
        .await
        .map_err(namespace_error)?
        .ok_or_else(|| ApiError::not_found("historical revision has no SQLite head"))?;
    snapshot_descriptor(&state, &historical_head.cid).await?;
    let writer = namespace_manager(&state)?
        .routed_sqlite_writer(
            &namespace_id,
            WriterControlRequest::Acquire {
                acquisition_id: format!("{}:rollback", request.request_id),
                session_id: request.request_id.clone(),
                base_snapshot_cid: current_head.cid.clone(),
                base_generation: current_head.generation,
                now_millis: sqlite_now_millis(),
                wait_timeout_millis: 0,
                lease_millis: configured.max_transaction_seconds.saturating_mul(1000),
                max_waiters: configured.max_writer_waiters_per_database,
            },
        )
        .await
        .map_err(consensus_error)?;
    let WriterControlResponse::Acquisition {
        status: AcquisitionStatus::Granted { ticket },
    } = writer
    else {
        return Err(sqlite_error(SqliteError::Busy));
    };
    let command = CommandEnvelope {
        request_id: request.request_id.clone(),
        writer_identity: ticket.holder.clone(),
        timestamp_unix_seconds: unix_seconds(),
        signature_hex: "00".into(),
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: namespace.current_revision,
                base_root_cid: namespace.current_root_cid,
                mutations: vec![NamespaceMutation::Put {
                    key_hex: hex::encode(SQLITE_HEAD_KEY),
                    value_cid: historical_head.cid.clone(),
                    value_kind: "sqlite_snapshot".into(),
                    metadata: BTreeMap::from([
                        ("rollback_revision".into(), request.revision.to_string()),
                        ("leader_term".into(), ticket.leader_term.to_string()),
                    ]),
                    precondition: KeyPrecondition::Match {
                        generation: current_head.generation,
                        cid: current_head.cid.clone(),
                    },
                }],
                message: Some(format!("rollback SQLite to revision {}", request.revision)),
            },
        },
    };
    let guard = GuardedCommitRequest {
        ticket: ticket.clone(),
        base_snapshot_cid: current_head.cid.clone(),
        base_generation: current_head.generation,
        new_snapshot_cid: historical_head.cid.clone(),
        idempotency_key: request.request_id.clone(),
        now_millis: sqlite_now_millis(),
    };
    let result = apply_command_guarded(
        &state,
        namespace_id,
        command,
        CommandPublicationInputs {
            uploaded_roots: Vec::new(),
            preverified_durability: Vec::new(),
            metadata_only_cids: Vec::new(),
            staged_bytes: 0,
            retain_uploaded_on_conflict: false,
        },
        pepper_publication::PublicationGuard::Application {
            kind: "pepper.sqlite_writer.v1".into(),
            payload: serde_json::to_vec(&guard).map_err(ApiError::serde)?,
        },
        Arc::new(AgentSqliteProposer {
            state: state.clone(),
        }),
    )
    .await?
    .0;
    let head_generation = current_head
        .generation
        .checked_add(1)
        .ok_or_else(|| ApiError::bad_request("SQLite head generation overflow"))?;
    SQLITE_COMMITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    commit_metric.succeed();
    Ok(Json(serde_json::json!({
        "commit_id": request.request_id,
        "rolled_back_from_snapshot": current_head.cid,
        "snapshot_cid": historical_head.cid,
        "head_generation": head_generation,
        "source_revision": request.revision,
        "namespace": result,
        "durability": "durable"
    }))
    .into_response())
}

pub(super) async fn sqlite_incremental_commit(
    State(state): State<AppState>,
    Path(database): Path<String>,
    Query(query): Query<SqliteIncrementalCommitQuery>,
    body: Body,
) -> Result<Response, ApiError> {
    let mut commit_metric = SqliteCommitMetric::begin();
    let configured = sqlite_config(&state)?;
    if query.request_id.is_empty() || query.request_id.len() > 128 {
        return Err(ApiError::bad_request(
            "request_id must contain 1 to 128 bytes",
        ));
    }
    let (namespace_id, namespace) = sqlite_namespace(&state, &database).await?;
    let (config_value, head) = sqlite_values(&state, namespace.clone()).await?;
    let database_descriptor = database_descriptor(&state, &config_value).await?;
    let base_descriptor = snapshot_descriptor(&state, &query.base_snapshot).await?;
    let page_numbers = query
        .pages
        .split(',')
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| ApiError::bad_request("pages must be comma-separated integers"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if page_numbers.len() > configured.max_dirty_pages_per_transaction as usize {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::PayloadTooLarge,
            "dirty page count exceeds the configured limit",
        ));
    }
    let expected_bytes = (page_numbers.len() as u64)
        .checked_mul(u64::from(database_descriptor.page_size))
        .ok_or_else(|| ApiError::bad_request("dirty page byte count overflow"))?;
    enforce_size_limit(
        Some(configured.max_staged_bytes_per_transaction),
        expected_bytes,
        "SQLite transaction",
    )?;
    let ticket = WriterTicket {
        ticket_id: query.ticket_id,
        acquisition_id: query.acquisition_id,
        database: namespace_id.to_string(),
        holder: query.holder,
        base_snapshot_cid: query.base_snapshot.clone(),
        base_generation: query.base_generation,
        leader_term: query.leader_term,
        lease_epoch: query.lease_epoch,
        expires_at_millis: query.expires_at_millis,
    };
    if head.cid != query.base_snapshot || head.generation != query.base_generation {
        return Err(sqlite_error(SqliteError::GenerationConflict {
            current_generation: head.generation,
        }));
    }
    let store = AgentSqliteStore::new(state.clone());
    let stream = body
        .into_data_stream()
        .map_err(|error| std::io::Error::other(error.to_string()));
    let mut reader = StreamReader::new(stream);
    let candidate = build_incremental_snapshot_stream(
        &store,
        config_value.cid,
        &database_descriptor,
        query.base_snapshot.clone(),
        &base_descriptor,
        page_numbers,
        &mut reader,
        query.new_logical_size,
        SqliteFormatLimits::default(),
    )
    .await
    .map_err(sqlite_error)?;
    let required = std::iter::once(&candidate.snapshot_cid)
        .chain(candidate.new_page_table_nodes.iter())
        .chain(candidate.new_page_pack_roots.iter())
        .chain(candidate.verified_descendants.iter())
        .cloned()
        .collect::<HashSet<_>>();
    let receipts = store
        .receipts()
        .map_err(sqlite_error)?
        .into_iter()
        .filter(|receipt| required.contains(&receipt.cid))
        .collect::<Vec<_>>();
    let proof = IncrementalDurabilityProof::build(
        IncrementalProofInput {
            protected_base_snapshot: query.base_snapshot.clone(),
            protected_base_descriptor: base_descriptor,
            new_snapshot: candidate.snapshot_cid.clone(),
            new_snapshot_descriptor: candidate.descriptor.clone(),
            new_page_table_nodes: candidate.new_page_table_nodes.clone(),
            new_page_pack_roots: candidate.new_page_pack_roots.clone(),
            verified_descendants: candidate.verified_descendants.clone(),
            durability_receipts: receipts.clone(),
            builder_identity: state.status.node_id.clone(),
        },
        state.replication_factor,
        SqliteFormatLimits::default(),
    )
    .map_err(sqlite_error)?;
    debug_assert_eq!(proof.new_snapshot(), &candidate.snapshot_cid);
    let command = CommandEnvelope {
        request_id: query.request_id.clone(),
        writer_identity: ticket.holder.clone(),
        timestamp_unix_seconds: unix_seconds(),
        signature_hex: "00".into(),
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: query.base_revision,
                base_root_cid: if namespace.current_revision == query.base_revision {
                    namespace.current_root_cid
                } else {
                    namespace
                        .history
                        .get(&query.base_revision)
                        .map(|record| record.root_cid.clone())
                        .ok_or_else(|| ApiError::not_found("SQLite base revision not retained"))?
                },
                mutations: vec![NamespaceMutation::Put {
                    key_hex: hex::encode(SQLITE_HEAD_KEY),
                    value_cid: candidate.snapshot_cid.clone(),
                    value_kind: "sqlite_snapshot".into(),
                    metadata: BTreeMap::from([
                        (
                            "logical_size".into(),
                            candidate.descriptor.logical_size.to_string(),
                        ),
                        (
                            "page_count".into(),
                            candidate.descriptor.page_count.to_string(),
                        ),
                        ("leader_term".into(), ticket.leader_term.to_string()),
                    ]),
                    precondition: KeyPrecondition::Match {
                        generation: query.base_generation,
                        cid: query.base_snapshot.clone(),
                    },
                }],
                message: Some("incremental SQLite commit".into()),
            },
        },
    };
    let guard = GuardedCommitRequest {
        ticket: ticket.clone(),
        base_snapshot_cid: query.base_snapshot.clone(),
        base_generation: query.base_generation,
        new_snapshot_cid: candidate.snapshot_cid.clone(),
        idempotency_key: query.request_id.clone(),
        now_millis: sqlite_now_millis(),
    };
    let guard_payload = serde_json::to_vec(&guard).map_err(ApiError::serde)?;
    let namespace_result = apply_command_guarded(
        &state,
        namespace_id.clone(),
        command,
        CommandPublicationInputs {
            uploaded_roots: vec![candidate.snapshot_cid.clone()],
            preverified_durability: receipts,
            metadata_only_cids: Vec::new(),
            staged_bytes: expected_bytes,
            retain_uploaded_on_conflict: false,
        },
        pepper_publication::PublicationGuard::Application {
            kind: "pepper.sqlite_writer.v1".into(),
            payload: guard_payload,
        },
        Arc::new(AgentSqliteProposer {
            state: state.clone(),
        }),
    )
    .await?
    .0;
    let commit = CommitRecord {
        idempotency_key: query.request_id,
        base_snapshot_cid: query.base_snapshot,
        base_generation: query.base_generation,
        snapshot_cid: candidate.snapshot_cid,
        generation: query
            .base_generation
            .checked_add(1)
            .ok_or_else(|| ApiError::bad_request("SQLite generation overflow"))?,
        leader_term: ticket.leader_term,
    };
    SQLITE_COMMITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    commit_metric.succeed();
    Ok(Json(serde_json::json!({
        "commit": commit,
        "snapshot": candidate.descriptor,
        "namespace": namespace_result,
        "durability": "durable",
    }))
    .into_response())
}

#[cfg(unix)]
struct ProtocolCommit {
    database: String,
    session_id: String,
    transaction_id: String,
    idempotency_key: String,
    ticket: WriterTicket,
    base_snapshot: Cid,
    base_generation: u64,
    page_size: u32,
    final_page_count: u32,
    dirty_page_count: u32,
    dirty_bytes: u64,
    page_numbers: Vec<u32>,
    received_bytes: u64,
    staged_pages: std::fs::File,
}

#[cfg(unix)]
pub(super) async fn spawn_sqlite_protocol_server(state: AppState) -> anyhow::Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    let path = state
        .sqlite_socket_path
        .clone()
        .ok_or_else(|| anyhow::anyhow!("SQLite socket path is unavailable"))?;
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        anyhow::ensure!(
            metadata.file_type().is_socket(),
            "refusing to replace non-socket SQLite path {}",
            path.display()
        );
        std::fs::remove_file(&path)
            .with_context(|| format!("failed to remove stale SQLite socket {}", path.display()))?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = tokio::net::UnixListener::bind(&path)
        .with_context(|| format!("failed to bind SQLite socket {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    state.sqlite_ready.store(true, Ordering::Relaxed);
    let task_state = state.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(error) => {
                    warn!(%error, "SQLite local protocol accept failed");
                    continue;
                }
            };
            #[cfg(target_os = "linux")]
            if stream
                .peer_cred()
                .ok()
                .is_none_or(|credential| credential.uid() != unsafe { libc::geteuid() })
            {
                warn!("rejected SQLite local protocol peer with another uid");
                continue;
            }
            let connection_state = task_state.clone();
            tokio::spawn(async move {
                if let Err(error) = serve_sqlite_protocol_connection(connection_state, stream).await
                {
                    warn!(%error, "SQLite local protocol connection failed");
                }
            });
        }
    });
    Ok(())
}

#[cfg(unix)]
async fn read_protocol_frame(
    stream: &mut tokio::net::UnixStream,
) -> Result<Option<LocalFrame>, SqliteError> {
    let mut prefix = [0u8; 16];
    match stream.read_exact(&mut prefix).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(SqliteError::Storage(error.to_string())),
    }
    let limits = LocalProtocolLimits::default();
    let (header, payload) = frame_body_lengths(&prefix, limits)?;
    let total = 16usize
        .checked_add(header)
        .and_then(|value| value.checked_add(payload))
        .ok_or_else(|| SqliteError::Limit("local protocol frame".into()))?;
    let mut encoded = Vec::with_capacity(total);
    encoded.extend_from_slice(&prefix);
    encoded.resize(total, 0);
    stream
        .read_exact(&mut encoded[16..])
        .await
        .map_err(|error| SqliteError::Storage(error.to_string()))?;
    LocalFrame::decode(&encoded, limits).map(Some)
}

#[cfg(unix)]
async fn write_protocol_frame(
    stream: &mut tokio::net::UnixStream,
    frame: LocalFrame,
) -> Result<(), SqliteError> {
    let encoded = frame.encode(LocalProtocolLimits::default())?;
    stream
        .write_all(&encoded)
        .await
        .map_err(|error| SqliteError::Storage(error.to_string()))
}

#[cfg(unix)]
fn protocol_error(error: SqliteError) -> LocalResponse {
    let (code, retryable, current_generation) = match &error {
        SqliteError::Busy => ("busy", true, None),
        SqliteError::Timeout => ("timeout", true, None),
        SqliteError::Fenced => ("fenced", true, None),
        SqliteError::GenerationConflict { current_generation } => {
            ("busy_snapshot", true, Some(*current_generation))
        }
        SqliteError::AmbiguousCommit { .. } => ("ambiguous_commit", true, None),
        SqliteError::Unsupported(_) => ("unsupported", false, None),
        SqliteError::Limit(_) => ("limit", false, None),
        _ => ("error", false, None),
    };
    LocalResponse::Error {
        code: code.into(),
        message: error.to_string(),
        retryable,
        current_snapshot: None,
        current_generation,
    }
}

#[cfg(unix)]
async fn serve_sqlite_protocol_connection(
    state: AppState,
    mut stream: tokio::net::UnixStream,
) -> Result<(), SqliteError> {
    let mut greeted = false;
    let mut pending: Option<ProtocolCommit> = None;
    while let Some(frame) = read_protocol_frame(&mut stream).await? {
        let request_id = frame.request_id;
        let request = match frame.message {
            LocalMessage::Request(request) => request,
            _ => return Err(SqliteError::Invalid("client sent a response frame".into())),
        };
        if !greeted && !matches!(request, LocalRequest::Hello { .. }) {
            return Err(SqliteError::Invalid(
                "local protocol hello is required".into(),
            ));
        }
        let result = handle_protocol_request(&state, request, frame.payload, &mut pending).await;
        let (response, payload) = match result {
            Ok(value) => value,
            Err(error) => (protocol_error(error), Vec::new()),
        };
        if matches!(response, LocalResponse::Hello { .. }) {
            greeted = true;
        }
        write_protocol_frame(
            &mut stream,
            LocalFrame {
                request_id,
                deadline_unix_millis: None,
                message: LocalMessage::Response(response),
                payload,
            },
        )
        .await?;
    }
    Ok(())
}

#[cfg(unix)]
async fn handle_protocol_request(
    state: &AppState,
    request: LocalRequest,
    payload: Vec<u8>,
    pending: &mut Option<ProtocolCommit>,
) -> Result<(LocalResponse, Vec<u8>), SqliteError> {
    match request {
        LocalRequest::Hello { hello } => {
            if hello.minimum_version > 1 || hello.maximum_version < 1 {
                return Err(SqliteError::Unsupported("local protocol version".into()));
            }
            Ok((
                LocalResponse::Hello {
                    hello: ServerHello {
                        selected_version: 1,
                        agent_identity: state.status.node_id.clone(),
                        enabled_features: [
                            pepper_sqlite::contract::FEATURE_BATCH_ATOMIC,
                            pepper_sqlite::contract::FEATURE_PAGE_READS,
                            pepper_sqlite::contract::FEATURE_WRITER_FENCING,
                            pepper_sqlite::contract::FEATURE_COMMIT_STATUS,
                        ]
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                        max_header_bytes: LocalProtocolLimits::default().max_header_bytes as u32,
                        max_payload_bytes: LocalProtocolLimits::default().max_payload_bytes as u32,
                        max_read_pages: 256,
                        max_dirty_pages: sqlite_config(state)
                            .map_err(|error| SqliteError::Storage(error.message))?
                            .max_dirty_pages_per_transaction,
                    },
                },
                Vec::new(),
            ))
        }
        LocalRequest::Open {
            database,
            mode,
            snapshot,
            ..
        } => {
            let configured =
                sqlite_config(state).map_err(|error| SqliteError::Storage(error.message))?;
            let writable = !matches!(mode, pepper_sqlite::protocol::OpenMode::ReadOnly);
            if writable && snapshot.is_some() {
                return Err(SqliteError::Invalid(
                    "historical snapshots are read-only".into(),
                ));
            }
            {
                let sessions = state
                    .sqlite_sessions
                    .lock()
                    .map_err(|_| SqliteError::Storage("SQLite session lock poisoned".into()))?;
                if sessions.len() >= configured.max_open_sessions
                    || sessions
                        .values()
                        .filter(|session| session.database == database)
                        .count()
                        >= configured.max_sessions_per_database
                {
                    return Err(SqliteError::Limit("SQLite session count".into()));
                }
            }
            let (namespace_id, revision, snapshot_cid, descriptor) = selected_snapshot(
                state,
                &database,
                SqliteSnapshotSelection {
                    snapshot,
                    ..SqliteSnapshotSelection::default()
                },
            )
            .await
            .map_err(|error| SqliteError::Storage(error.message))?;
            let (_, namespace) = sqlite_namespace(state, &database)
                .await
                .map_err(|error| SqliteError::Storage(error.message))?;
            let (_, head) = sqlite_values(state, namespace)
                .await
                .map_err(|error| SqliteError::Storage(error.message))?;
            let generation = if head.cid == snapshot_cid {
                head.generation
            } else {
                0
            };
            let session_id = format!("sqlite-local-{}", request_id());
            let lease_id = format!("{session_id}-read");
            let now = unix_seconds();
            let expires = now.saturating_add(configured.max_transaction_seconds as i64);
            publication_coordinator(state)
                .map_err(|error| SqliteError::Storage(error.message))?
                .acquire_read_lease(ReadLease {
                    lease_id: lease_id.clone(),
                    namespace_id: namespace_id.clone(),
                    root_cid: snapshot_cid.clone(),
                    revision,
                    created_at_unix_seconds: now,
                    expires_at_unix_seconds: expires,
                })
                .await
                .map_err(|error| SqliteError::Storage(error.to_string()))?;
            state
                .sqlite_sessions
                .lock()
                .map_err(|_| SqliteError::Storage("SQLite session lock poisoned".into()))?
                .insert(
                    session_id.clone(),
                    SqliteReadSession {
                        database: database.clone(),
                        namespace_id,
                        revision,
                        snapshot_cid: snapshot_cid.clone(),
                        snapshot: descriptor.clone(),
                        lease_id,
                        expires_at_unix_seconds: expires,
                    },
                );
            Ok((
                LocalResponse::Opened {
                    session_id,
                    database,
                    snapshot: snapshot_cid,
                    generation,
                    page_size: descriptor.page_size,
                    page_count: descriptor.page_count,
                    writable,
                },
                Vec::new(),
            ))
        }
        LocalRequest::Close { session_id } => {
            sqlite_session_close(State(state.clone()), Path(session_id))
                .await
                .map_err(|error| SqliteError::Storage(error.message))?;
            Ok((LocalResponse::Closed, Vec::new()))
        }
        LocalRequest::ReadPages {
            session_id,
            snapshot,
            page_numbers,
        } => {
            if page_numbers.is_empty() || page_numbers.len() > 256 {
                return Err(SqliteError::Limit("page read batch".into()));
            }
            let session = state
                .sqlite_sessions
                .lock()
                .map_err(|_| SqliteError::Storage("SQLite session lock poisoned".into()))?
                .get(&session_id)
                .cloned()
                .ok_or(SqliteError::Fenced)?;
            if session.snapshot_cid != snapshot {
                return Err(SqliteError::Fenced);
            }
            let response = sqlite_session_pages(
                State(state.clone()),
                Path(session_id),
                Query(SqlitePageQuery {
                    pages: page_numbers
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                }),
            )
            .await
            .map_err(|error| SqliteError::Storage(error.message))?;
            let bytes = axum::body::to_bytes(
                response.into_body(),
                LocalProtocolLimits::default().max_payload_bytes,
            )
            .await
            .map_err(|error| SqliteError::Storage(error.to_string()))?
            .to_vec();
            let page_size = session.snapshot.page_size as usize;
            let pages = page_numbers
                .into_iter()
                .enumerate()
                .map(|(index, page_number)| {
                    let page = &bytes[index * page_size..(index + 1) * page_size];
                    PagePayloadLayout {
                        page_number,
                        payload_offset: (index * page_size) as u32,
                        payload_length: page_size as u32,
                        page_hash: blake3::hash(page).to_hex().to_string(),
                    }
                })
                .collect();
            Ok((LocalResponse::Pages { snapshot, pages }, bytes))
        }
        LocalRequest::AcquireWriter {
            session_id,
            acquisition_id,
            base_snapshot,
            base_generation,
            wait_timeout_millis,
        } => {
            let session = state
                .sqlite_sessions
                .lock()
                .map_err(|_| SqliteError::Storage("SQLite session lock poisoned".into()))?
                .get(&session_id)
                .cloned()
                .ok_or(SqliteError::Fenced)?;
            let status = sqlite_writer_acquire(
                State(state.clone()),
                Path(session.database),
                Json(SqliteWriterAcquireRequest {
                    session_id,
                    acquisition_id,
                    base_snapshot,
                    base_generation,
                    wait_timeout_millis,
                }),
            )
            .await
            .map_err(|error| SqliteError::Storage(error.message))?
            .0;
            match status {
                AcquisitionStatus::Granted { ticket } => {
                    Ok((LocalResponse::Writer { ticket }, Vec::new()))
                }
                AcquisitionStatus::Queued { position } => {
                    Ok((LocalResponse::Queued { position }, Vec::new()))
                }
                AcquisitionStatus::Busy => Err(SqliteError::Busy),
                AcquisitionStatus::TimedOut => Err(SqliteError::Timeout),
                AcquisitionStatus::Stale {
                    current_generation, ..
                } => Err(SqliteError::GenerationConflict { current_generation }),
                AcquisitionStatus::Released | AcquisitionStatus::Fenced => Err(SqliteError::Fenced),
            }
        }
        LocalRequest::WriterStatus {
            session_id,
            acquisition_id,
        } => {
            let session = state
                .sqlite_sessions
                .lock()
                .map_err(|_| SqliteError::Storage("SQLite session lock poisoned".into()))?
                .get(&session_id)
                .cloned()
                .ok_or(SqliteError::Fenced)?;
            let (namespace_id, _) = sqlite_namespace(state, &session.database)
                .await
                .map_err(|error| SqliteError::Storage(error.message))?;
            let response = namespace_manager(state)
                .map_err(|error| SqliteError::Storage(error.message))?
                .routed_sqlite_writer(
                    &namespace_id,
                    WriterControlRequest::Status {
                        acquisition_id,
                        now_millis: sqlite_now_millis(),
                    },
                )
                .await
                .map_err(|error| SqliteError::Storage(error.to_string()))?;
            let WriterControlResponse::Acquisition { status } = response else {
                return Err(SqliteError::Storage(
                    "invalid SQLite writer response".into(),
                ));
            };
            match status {
                AcquisitionStatus::Granted { ticket } => {
                    Ok((LocalResponse::Writer { ticket }, Vec::new()))
                }
                AcquisitionStatus::Queued { position } => {
                    Ok((LocalResponse::Queued { position }, Vec::new()))
                }
                AcquisitionStatus::Busy => Err(SqliteError::Busy),
                AcquisitionStatus::TimedOut => Err(SqliteError::Timeout),
                AcquisitionStatus::Stale {
                    current_generation, ..
                } => Err(SqliteError::GenerationConflict { current_generation }),
                AcquisitionStatus::Released | AcquisitionStatus::Fenced => Err(SqliteError::Fenced),
            }
        }
        LocalRequest::RenewWriter { session_id, ticket } => {
            let session = state
                .sqlite_sessions
                .lock()
                .map_err(|_| SqliteError::Storage("SQLite session lock poisoned".into()))?
                .get(&session_id)
                .cloned()
                .ok_or(SqliteError::Fenced)?;
            let renewed = sqlite_writer_renew(
                State(state.clone()),
                Path(session.database),
                Json(SqliteWriterTicketRequest { ticket }),
            )
            .await
            .map_err(|error| SqliteError::Storage(error.message))?
            .0;
            Ok((LocalResponse::Writer { ticket: renewed }, Vec::new()))
        }
        LocalRequest::ReleaseWriter { session_id, ticket } => {
            let session = state
                .sqlite_sessions
                .lock()
                .map_err(|_| SqliteError::Storage("SQLite session lock poisoned".into()))?
                .get(&session_id)
                .cloned()
                .ok_or(SqliteError::Fenced)?;
            sqlite_writer_release(
                State(state.clone()),
                Path(session.database),
                Json(SqliteWriterTicketRequest { ticket }),
            )
            .await
            .map_err(|error| SqliteError::Storage(error.message))?;
            Ok((LocalResponse::Closed, Vec::new()))
        }
        LocalRequest::BeginCommit {
            session_id,
            transaction_id,
            idempotency_key,
            ticket,
            base_snapshot,
            base_generation,
            page_size,
            final_page_count,
            dirty_page_count,
            dirty_bytes,
        } => {
            if pending.is_some()
                || dirty_page_count
                    > sqlite_config(state)
                        .map_err(|error| SqliteError::Storage(error.message))?
                        .max_dirty_pages_per_transaction
                || dirty_bytes != u64::from(dirty_page_count) * u64::from(page_size)
            {
                return Err(SqliteError::Invalid("invalid commit header".into()));
            }
            let session = state
                .sqlite_sessions
                .lock()
                .map_err(|_| SqliteError::Storage("SQLite session lock poisoned".into()))?
                .get(&session_id)
                .cloned()
                .ok_or(SqliteError::Fenced)?;
            if session.snapshot_cid != base_snapshot || session.snapshot.page_size != page_size {
                return Err(SqliteError::Fenced);
            }
            *pending = Some(ProtocolCommit {
                database: session.database,
                session_id,
                transaction_id,
                idempotency_key,
                ticket,
                base_snapshot,
                base_generation,
                page_size,
                final_page_count,
                dirty_page_count,
                dirty_bytes,
                page_numbers: Vec::with_capacity(dirty_page_count as usize),
                received_bytes: 0,
                staged_pages: tempfile::tempfile()
                    .map_err(|error| SqliteError::Storage(error.to_string()))?,
            });
            Ok((LocalResponse::CommitReady, Vec::new()))
        }
        LocalRequest::CommitPage {
            transaction_id,
            page_number,
            page_hash,
        } => {
            let commit = pending.as_mut().ok_or_else(|| {
                SqliteError::Invalid("commit page without active transaction".into())
            })?;
            if commit.transaction_id != transaction_id
                || payload.len() != commit.page_size as usize
                || blake3::hash(&payload).to_hex().as_str() != page_hash
                || page_number == 0
                || page_number > commit.final_page_count
                || commit
                    .page_numbers
                    .last()
                    .is_some_and(|prior| *prior >= page_number)
                || commit.page_numbers.len() >= commit.dirty_page_count as usize
                || commit.received_bytes.saturating_add(payload.len() as u64) > commit.dirty_bytes
            {
                return Err(SqliteError::Invalid("invalid commit page".into()));
            }
            commit
                .staged_pages
                .write_all(&payload)
                .map_err(|error| SqliteError::Storage(error.to_string()))?;
            commit.page_numbers.push(page_number);
            commit.received_bytes = commit.received_bytes.saturating_add(payload.len() as u64);
            Ok((LocalResponse::PageAccepted, Vec::new()))
        }
        LocalRequest::FinishCommit { transaction_id } => {
            let commit = pending
                .take()
                .ok_or_else(|| SqliteError::Invalid("finish without active transaction".into()))?;
            if commit.transaction_id != transaction_id
                || commit.page_numbers.len() != commit.dirty_page_count as usize
                || commit.received_bytes != commit.dirty_bytes
            {
                return Err(SqliteError::Invalid("incomplete commit".into()));
            }
            let (_, namespace) = sqlite_namespace(state, &commit.database)
                .await
                .map_err(|error| SqliteError::Storage(error.message))?;
            let pages = commit
                .page_numbers
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let mut staged_pages = commit.staged_pages;
            staged_pages
                .seek(SeekFrom::Start(0))
                .map_err(|error| SqliteError::Storage(error.to_string()))?;
            let body =
                Body::from_stream(ReaderStream::new(tokio::fs::File::from_std(staged_pages)));
            let database = commit.database.clone();
            let session_id = commit.session_id.clone();
            sqlite_incremental_commit(
                State(state.clone()),
                Path(database.clone()),
                Query(SqliteIncrementalCommitQuery {
                    request_id: commit.idempotency_key.clone(),
                    base_revision: namespace.current_revision,
                    base_generation: commit.base_generation,
                    base_snapshot: commit.base_snapshot,
                    new_logical_size: u64::from(commit.final_page_count)
                        * u64::from(commit.page_size),
                    pages,
                    ticket_id: commit.ticket.ticket_id.clone(),
                    acquisition_id: commit.ticket.acquisition_id.clone(),
                    holder: commit.ticket.holder.clone(),
                    leader_term: commit.ticket.leader_term,
                    lease_epoch: commit.ticket.lease_epoch,
                    expires_at_millis: commit.ticket.expires_at_millis,
                }),
                body,
            )
            .await
            .map_err(|error| SqliteError::Storage(error.message))?;
            let (_, current) = sqlite_namespace(state, &database)
                .await
                .map_err(|error| SqliteError::Storage(error.message))?;
            let current_revision = current.current_revision;
            let (_, head) = sqlite_values(state, current)
                .await
                .map_err(|error| SqliteError::Storage(error.message))?;
            let descriptor = snapshot_descriptor(state, &head.cid)
                .await
                .map_err(|error| SqliteError::Storage(error.message))?;
            if let Some(session) = state
                .sqlite_sessions
                .lock()
                .map_err(|_| SqliteError::Storage("SQLite session lock poisoned".into()))?
                .get_mut(&session_id)
            {
                session.snapshot_cid = head.cid.clone();
                session.snapshot = descriptor;
                session.revision = current_revision;
            }
            let record = CommitRecord {
                idempotency_key: commit.idempotency_key,
                base_snapshot_cid: commit.ticket.base_snapshot_cid,
                base_generation: commit.base_generation,
                snapshot_cid: head.cid,
                generation: head.generation,
                leader_term: commit.ticket.leader_term,
            };
            Ok((LocalResponse::Committed { commit: record }, Vec::new()))
        }
        LocalRequest::AbortCommit { transaction_id } => {
            if pending
                .as_ref()
                .is_some_and(|commit| commit.transaction_id == transaction_id)
            {
                *pending = None;
            }
            Ok((LocalResponse::Aborted, Vec::new()))
        }
        LocalRequest::CommitStatus {
            database,
            idempotency_key,
        } => {
            let (namespace_id, _) = sqlite_namespace(state, &database)
                .await
                .map_err(|error| SqliteError::Storage(error.message))?;
            let response = namespace_manager(state)
                .map_err(|error| SqliteError::Storage(error.message))?
                .routed_sqlite_writer(
                    &namespace_id,
                    WriterControlRequest::CommitStatus {
                        idempotency_key: idempotency_key.clone(),
                    },
                )
                .await
                .map_err(|error| SqliteError::Storage(error.to_string()))?;
            let WriterControlResponse::Commit { record } = response else {
                return Err(SqliteError::Storage(
                    "invalid SQLite writer response".into(),
                ));
            };
            let record = record.ok_or(SqliteError::AmbiguousCommit { idempotency_key })?;
            Ok((LocalResponse::Committed { commit: record }, Vec::new()))
        }
        LocalRequest::Cancel { .. } => Ok((LocalResponse::Cancelled, Vec::new())),
    }
}

pub(super) async fn sqlite_whole_file_create(
    State(state): State<AppState>,
    Json(request): Json<WholeFileCreateRequest>,
) -> Result<Response, ApiError> {
    let configured = sqlite_config(&state)?;
    if request.request_id.is_empty() || request.request_id.len() > 128 {
        return Err(ApiError::bad_request(
            "request_id must contain 1 to 128 bytes",
        ));
    }
    pepper_sqlite::PepperDatabaseUri::parse(&format!("pepper:{}?mode=rwc", request.database))
        .map_err(sqlite_error)?;
    let limits = SqliteFormatLimits::default();
    let page_size = request.page_size.unwrap_or(configured.default_page_size);
    if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(ApiError::bad_request(
            "page_size must be a power of two from 512 through 65536",
        ));
    }
    let max_page_count = request.max_page_count.unwrap_or_else(|| {
        limits
            .max_page_count
            .min((limits.max_logical_bytes / u64::from(page_size)) as u32)
    });
    let page_pack_target_bytes = request
        .page_pack_target_bytes
        .unwrap_or(configured.page_pack_target_bytes);
    let storage_policy = request
        .storage_policy
        .unwrap_or(PageStoragePolicy::Adaptive {
            small_commit_replicas: state.replication_factor as u16,
            large_commit_data_shards: state.erasure_data_shards,
            large_commit_parity_shards: state.erasure_parity_shards,
            large_commit_shard_copies: 1,
            threshold_bytes: state
                .erasure_min_size_bytes
                .min(u64::from(page_pack_target_bytes)) as u32,
        });
    let descriptor = DatabaseDescriptor::new(
        page_size,
        max_page_count,
        page_pack_target_bytes,
        storage_policy,
        CachePolicyBounds {
            minimum_bytes: u64::from(page_pack_target_bytes),
            maximum_bytes: configured.page_cache_bytes,
        },
        unix_seconds(),
        state.status.node_id.clone(),
    );
    descriptor.validate(limits).map_err(sqlite_error)?;

    let created = super::namespace_api::namespace_create(
        State(state.clone()),
        Json(super::namespace_api::CreateNamespaceRequest {
            kind: NamespaceKind::Sqlite,
            alias: Some(request.database.clone()),
            request_id: Some(request.request_id.clone()),
            retention_keep_last: None,
            retention_max_age_seconds: None,
        }),
    )
    .await?
    .0;

    let descriptor_bytes =
        encode_canonical(&descriptor, limits.max_descriptor_bytes).map_err(sqlite_error)?;
    let descriptor_receipt = put_replicated_block(
        &state,
        pepper_types::CODEC_SQLITE_DATABASE,
        descriptor_bytes,
    )
    .await?;
    let whole_file = ObjectWriteService::new(state.clone())
        .write_bytes(Vec::new(), ObjectWritePolicy::Configured)
        .await?;
    let base = namespace_manager(&state)?
        .linearizable_namespace_state(&created.namespace_id)
        .await
        .map_err(consensus_error)?;
    let command = CommandEnvelope {
        request_id: request.request_id,
        writer_identity: "sqlite-whole-file-http".into(),
        timestamp_unix_seconds: unix_seconds(),
        signature_hex: "00".into(),
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: base.current_revision,
                base_root_cid: base.current_root_cid,
                mutations: vec![
                    NamespaceMutation::Put {
                        key_hex: hex::encode(SQLITE_CONFIG_KEY),
                        value_cid: descriptor_receipt.cid.clone(),
                        value_kind: "sqlite_database_config".into(),
                        metadata: BTreeMap::new(),
                        precondition: KeyPrecondition::Absent,
                    },
                    NamespaceMutation::Put {
                        key_hex: hex::encode(SQLITE_HEAD_KEY),
                        value_cid: whole_file.receipt.cid.clone(),
                        value_kind: "sqlite_whole_file_experimental".into(),
                        metadata: BTreeMap::from([("logical_size".into(), "0".into())]),
                        precondition: KeyPrecondition::Absent,
                    },
                ],
                message: Some("initialize experimental SQLite whole-file head".into()),
            },
        },
    };
    let mut receipts = whole_file.blocks;
    receipts.push(descriptor_receipt.clone());
    let result = apply_command(
        &state,
        created.namespace_id.clone(),
        command,
        vec![
            descriptor_receipt.cid.clone(),
            whole_file.receipt.cid.clone(),
        ],
        receipts,
        0,
        false,
    )
    .await?
    .0;
    Ok((
        StatusCode::CREATED,
        [(
            HeaderName::from_static("x-pepper-experimental"),
            HeaderValue::from_static(EXPERIMENTAL_HEADER),
        )],
        Json(serde_json::json!({
            "experimental": EXPERIMENTAL_HEADER,
            "database": request.database,
            "namespace_id": created.namespace_id,
            "configuration_cid": descriptor_receipt.cid,
            "head_cid": whole_file.receipt.cid,
            "head_generation": 1,
            "namespace": result,
        })),
    )
        .into_response())
}

pub(super) async fn sqlite_whole_file_info(
    State(state): State<AppState>,
    Path(database): Path<String>,
) -> Result<Response, ApiError> {
    sqlite_config(&state)?;
    let (namespace_id, namespace) = sqlite_namespace(&state, &database).await?;
    let revision = namespace.current_revision;
    let (config_value, head) = sqlite_values(&state, namespace).await?;
    let descriptor = database_descriptor(&state, &config_value).await?;
    Ok((
        [(
            HeaderName::from_static("x-pepper-experimental"),
            HeaderValue::from_static(EXPERIMENTAL_HEADER),
        )],
        Json(serde_json::json!({
            "experimental": EXPERIMENTAL_HEADER,
            "database": database,
            "namespace_id": namespace_id,
            "namespace_revision": revision,
            "configuration_cid": config_value.cid,
            "configuration": descriptor,
            "head_cid": head.cid,
            "head_generation": head.generation,
            "logical_size": head.metadata.get("logical_size").and_then(|value| value.parse::<u64>().ok()).unwrap_or(0),
        })),
    )
        .into_response())
}

pub(super) async fn sqlite_whole_file_commit(
    State(state): State<AppState>,
    Path(database): Path<String>,
    Query(query): Query<WholeFileCommitQuery>,
    body: Body,
) -> Result<Response, ApiError> {
    let configured = sqlite_config(&state)?;
    if query.request_id.is_empty() || query.request_id.len() > 128 {
        return Err(ApiError::bad_request(
            "request_id must contain 1 to 128 bytes",
        ));
    }
    let bytes = read_body_limited(
        body,
        Some(configured.max_staged_bytes_per_transaction),
        "SQLite whole-file commit",
    )
    .await?;
    let (namespace_id, namespace) = sqlite_namespace(&state, &database).await?;
    let (config_value, head) = sqlite_values(&state, namespace.clone()).await?;
    let replaying = namespace.idempotent_response(&query.request_id).is_some();
    if !replaying && (head.cid != query.base_cid || head.generation != query.base_generation) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::GenerationConflict,
            format!(
                "SQLite head changed: current CID {}, generation {}",
                head.cid, head.generation
            ),
        ));
    }
    let descriptor = database_descriptor(&state, &config_value).await?;
    let metadata = validate_sqlite_file(
        &bytes,
        descriptor.page_size,
        descriptor.max_page_count,
        SqliteFormatLimits::default().max_logical_bytes,
    )
    .map_err(sqlite_error)?;
    let policy = match descriptor.storage_policy {
        PageStoragePolicy::Replicated { .. } => ObjectWritePolicy::Replicated,
        PageStoragePolicy::Erasure {
            data_shards,
            parity_shards,
            ..
        } => ObjectWritePolicy::Erasure {
            data_shards,
            parity_shards,
        },
        PageStoragePolicy::Adaptive {
            large_commit_data_shards,
            large_commit_parity_shards,
            threshold_bytes,
            ..
        } if bytes.len() as u64 >= u64::from(threshold_bytes) => ObjectWritePolicy::Erasure {
            data_shards: large_commit_data_shards,
            parity_shards: large_commit_parity_shards,
        },
        PageStoragePolicy::Adaptive { .. } => ObjectWritePolicy::Replicated,
    };
    let logical_size = bytes.len() as u64;
    let stored = ObjectWriteService::new(state.clone())
        .write_bytes(bytes, policy)
        .await?;
    let command = CommandEnvelope {
        request_id: query.request_id.clone(),
        writer_identity: "sqlite-whole-file-http".into(),
        timestamp_unix_seconds: unix_seconds(),
        signature_hex: "00".into(),
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: query.base_revision,
                base_root_cid: if namespace.current_revision == query.base_revision {
                    namespace.current_root_cid.clone()
                } else {
                    namespace
                        .history
                        .get(&query.base_revision)
                        .map(|record| record.root_cid.clone())
                        .ok_or_else(|| ApiError::not_found("SQLite base revision not retained"))?
                },
                mutations: vec![NamespaceMutation::Put {
                    key_hex: hex::encode(SQLITE_HEAD_KEY),
                    value_cid: stored.receipt.cid.clone(),
                    value_kind: "sqlite_whole_file_experimental".into(),
                    metadata: BTreeMap::from([
                        ("logical_size".into(), logical_size.to_string()),
                        ("page_count".into(), metadata.page_count.to_string()),
                    ]),
                    precondition: KeyPrecondition::Match {
                        generation: query.base_generation,
                        cid: query.base_cid,
                    },
                }],
                message: Some("experimental SQLite whole-file commit".into()),
            },
        },
    };
    let root = stored.receipt.cid.clone();
    let result = apply_command(
        &state,
        namespace_id,
        command,
        vec![root.clone()],
        stored.blocks,
        logical_size,
        false,
    )
    .await?
    .0;
    Ok((
        [(
            HeaderName::from_static("x-pepper-experimental"),
            HeaderValue::from_static(EXPERIMENTAL_HEADER),
        )],
        Json(serde_json::json!({
            "experimental": EXPERIMENTAL_HEADER,
            "request_id": query.request_id,
            "head_cid": root,
            "head_generation": query.base_generation.saturating_add(1),
            "file": metadata,
            "namespace": result,
        })),
    )
        .into_response())
}

pub(super) async fn sqlite_whole_file_export(
    State(state): State<AppState>,
    Path(database): Path<String>,
) -> Result<Response, ApiError> {
    sqlite_config(&state)?;
    let (_, namespace) = sqlite_namespace(&state, &database).await?;
    let (_, head) = sqlite_values(&state, namespace).await?;
    let guard = Some(Arc::new(state.operation_lock.clone().read_owned().await));
    let mut response = get_object_at_placement(state, head.cid.clone(), None, guard).await?;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.sqlite3"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-pepper-experimental"),
        HeaderValue::from_static(EXPERIMENTAL_HEADER),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-pepper-sqlite-head"),
        HeaderValue::from_str(&head.cid.to_string())
            .map_err(|error| ApiError::internal(error.to_string()))?,
    );
    Ok(response)
}

pub(super) async fn sqlite_whole_file_commit_status(
    State(state): State<AppState>,
    Path((database, request_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    sqlite_config(&state)?;
    let (_, namespace) = sqlite_namespace(&state, &database).await?;
    let Some(response) = namespace.idempotent_response(&request_id) else {
        return Err(ApiError::not_found("SQLite commit ID not found"));
    };
    Ok((
        [(
            HeaderName::from_static("x-pepper-experimental"),
            HeaderValue::from_static(EXPERIMENTAL_HEADER),
        )],
        Json(serde_json::json!({
            "experimental": EXPERIMENTAL_HEADER,
            "database": database,
            "request_id": request_id,
            "result": response,
        })),
    )
        .into_response())
}

#[cfg(test)]
mod sqlite_import_tests {
    use super::*;

    #[test]
    fn upstream_import_validation_accepts_valid_and_rejects_corrupt_sqlite() {
        let temporary = tempfile::NamedTempFile::new().expect("create SQLite fixture");
        {
            let connection = rusqlite::Connection::open(temporary.path()).expect("open fixture");
            connection
                .execute_batch(
                    "PRAGMA page_size=4096; CREATE TABLE items(value TEXT); \
                     INSERT INTO items VALUES ('durable');",
                )
                .expect("populate fixture");
        }
        validate_sqlite_import_with_upstream(temporary.path(), 4096).expect("valid SQLite fixture");

        let mut file = temporary.reopen().expect("reopen fixture");
        std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(100)).expect("seek first page");
        std::io::Write::write_all(&mut file, &[0xff]).expect("corrupt first page");
        file.sync_all().expect("sync corruption");
        assert!(validate_sqlite_import_with_upstream(temporary.path(), 4096).is_err());
    }
}
