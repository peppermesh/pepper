// SPDX-License-Identifier: Apache-2.0

//! Transactional namespace and KV HTTP service.

use super::*;
use pepper_merkle::{MerkleLimits, ScanQuery};
use pepper_namespace::{
    CommandEnvelope, CommandResponse, CreatedNamespace, KeyPrecondition, NamespaceCommand,
    NamespaceDescriptor, NamespaceId, NamespaceKind, NamespaceLimits, NamespaceMutation,
    NamespaceState, TransactionCommand, create_namespace, load_checkpoint,
};
use pepper_publication::{
    DurabilityBackend, PublicationCoordinator, PublicationError, PublicationRequest, ReadLease,
};
use redb::TableDefinition;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const NAMESPACE_ALIASES: TableDefinition<&str, &str> = TableDefinition::new("namespace_aliases");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateNamespaceRequest {
    pub(super) kind: NamespaceKind,
    pub(super) alias: Option<String>,
    #[serde(default)]
    pub(super) request_id: Option<String>,
    #[serde(skip)]
    pub(super) retention_keep_last: Option<u32>,
    #[serde(skip)]
    pub(super) retention_max_age_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(super) struct CreateNamespaceResponse {
    pub(super) namespace_id: NamespaceId,
    pub(super) descriptor_cid: Cid,
    pub(super) namespace_revision: u64,
    pub(super) root_cid: Cid,
    pub(super) checkpoint_cid: Cid,
    pub(super) replica_nodes: Vec<String>,
    pub(super) quorum_status: String,
    pub(super) alias: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct ConsistencyRequest {
    #[serde(default)]
    consistency: Option<String>,
    revision: Option<u64>,
    root_cid: Option<Cid>,
    checkpoint_cid: Option<Cid>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KvGetRequest {
    namespace: String,
    key_hex: String,
    #[serde(flatten)]
    consistency: ConsistencyRequest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KvScanRequest {
    namespace: String,
    prefix_hex: Option<String>,
    start_hex: Option<String>,
    end_hex: Option<String>,
    #[serde(default = "default_scan_limit")]
    limit: usize,
    cursor: Option<String>,
    #[serde(flatten)]
    consistency: ConsistencyRequest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KvMutationRequest {
    namespace: String,
    key_hex: String,
    value_cid: Option<Cid>,
    #[serde(default = "default_value_kind")]
    value_kind: String,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
    if_generation: Option<u64>,
    if_cid: Option<Cid>,
    request_id: String,
    #[serde(default = "default_writer")]
    writer_identity: String,
    #[serde(default = "default_signature")]
    signature_hex: String,
    #[serde(default)]
    staged_bytes: u64,
    #[serde(default)]
    uploaded_roots: Vec<Cid>,
    #[serde(default)]
    retain_uploaded_on_conflict: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TransactionApplyRequest {
    version: u32,
    namespace: String,
    request_id: String,
    writer_identity: String,
    signature_hex: String,
    base_revision: u64,
    base_root_cid: Cid,
    mutations: Vec<NamespaceMutation>,
    message: Option<String>,
    #[serde(default)]
    staged_bytes: u64,
    #[serde(default)]
    uploaded_roots: Vec<Cid>,
    #[serde(default)]
    retain_uploaded_on_conflict: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct RollbackRequest {
    pub(super) revision: u64,
    pub(super) request_id: String,
    #[serde(default = "default_writer")]
    pub(super) writer_identity: String,
    #[serde(default = "default_signature")]
    pub(super) signature_hex: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SnapshotMutationRequest {
    action: String,
    name: String,
    revision: Option<u64>,
    request_id: String,
    #[serde(default = "default_writer")]
    writer_identity: String,
    #[serde(default = "default_signature")]
    signature_hex: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct DiffRequest {
    revision_a: u64,
    revision_b: u64,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReplaceReplicaRequest {
    failed_node: String,
    replacement_node: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RecoverRequest {
    checkpoint_cid: Cid,
    members: Vec<String>,
    confirmation: String,
}

fn request_id() -> String {
    format!(
        "api-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}

fn default_scan_limit() -> usize {
    100
}
fn default_value_kind() -> String {
    "raw".to_string()
}
fn default_writer() -> String {
    "http-client".to_string()
}
fn default_signature() -> String {
    "00".to_string()
}

pub(super) fn namespace_manager(state: &AppState) -> Result<Arc<NamespaceGroupManager>, ApiError> {
    state.namespace_groups.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::NamespaceUnavailable,
            "namespace service is disabled",
        )
    })
}

pub(super) fn parse_namespace(state: &AppState, value: &str) -> Result<NamespaceId, ApiError> {
    if let Ok(cid) = value.parse::<Cid>() {
        return NamespaceId::new(cid).map_err(namespace_error);
    }
    namespace_alias(state, value)
}

pub(super) fn namespace_alias(state: &AppState, value: &str) -> Result<NamespaceId, ApiError> {
    let read = state
        .metadata
        .database()
        .begin_read()
        .map_err(ApiError::redb_transaction)?;
    let table = match read.open_table(NAMESPACE_ALIASES) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Err(ApiError::not_found("namespace alias not found"));
        }
        Err(error) => return Err(ApiError::redb_table(error)),
    };
    let id = table
        .get(value)
        .map_err(ApiError::redb_storage)?
        .ok_or_else(|| ApiError::not_found("namespace alias not found"))?
        .value()
        .to_string();
    let cid = id
        .parse::<Cid>()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    NamespaceId::new(cid).map_err(namespace_error)
}

pub(super) fn namespace_aliases(state: &AppState) -> Result<Vec<(String, NamespaceId)>, ApiError> {
    let read = state
        .metadata
        .database()
        .begin_read()
        .map_err(ApiError::redb_transaction)?;
    let table = match read.open_table(NAMESPACE_ALIASES) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(error) => return Err(ApiError::redb_table(error)),
    };
    let mut aliases = Vec::new();
    for entry in table.iter().map_err(ApiError::redb_storage)? {
        let (alias, namespace) = entry.map_err(ApiError::redb_storage)?;
        let cid = namespace
            .value()
            .parse::<Cid>()
            .map_err(|error| ApiError::bad_request(error.to_string()))?;
        aliases.push((
            alias.value().to_string(),
            NamespaceId::new(cid).map_err(namespace_error)?,
        ));
    }
    aliases.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(aliases)
}

pub(super) fn persist_alias(
    state: &AppState,
    alias: &str,
    namespace_id: &NamespaceId,
) -> Result<(), ApiError> {
    if alias.is_empty() || alias.len() > 256 {
        return Err(ApiError::bad_request("alias must contain 1 to 256 bytes"));
    }
    let write = state
        .metadata
        .database()
        .begin_write()
        .map_err(ApiError::redb_transaction)?;
    {
        let mut table = write
            .open_table(NAMESPACE_ALIASES)
            .map_err(ApiError::redb_table)?;
        if let Some(existing) = table.get(alias).map_err(ApiError::redb_storage)? {
            if existing.value() == namespace_id.to_string() {
                return Ok(());
            }
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "namespace alias already exists",
            ));
        }
        table
            .insert(alias, namespace_id.to_string().as_str())
            .map_err(ApiError::redb_storage)?;
    }
    write.commit().map_err(ApiError::redb_commit)
}

pub(super) fn cache_alias(
    state: &AppState,
    alias: &str,
    namespace_id: &NamespaceId,
) -> Result<(), ApiError> {
    if alias.is_empty() || alias.len() > 256 {
        return Err(ApiError::bad_request("alias must contain 1 to 256 bytes"));
    }
    let write = state
        .metadata
        .database()
        .begin_write()
        .map_err(ApiError::redb_transaction)?;
    {
        let mut table = write
            .open_table(NAMESPACE_ALIASES)
            .map_err(ApiError::redb_table)?;
        table
            .insert(alias, namespace_id.to_string().as_str())
            .map_err(ApiError::redb_storage)?;
    }
    write.commit().map_err(ApiError::redb_commit)
}

pub(super) async fn bootstrap_namespace_group(
    state: &AppState,
    descriptor: NamespaceDescriptor,
) -> Result<CreatedNamespace, ApiError> {
    let manager = namespace_manager(state)?;
    let replicas = descriptor.initial_replica_set.clone();
    if replicas.len() != 3 {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::NamespaceUnavailable,
            "exactly three consensus replicas are required",
        ));
    }
    let created = create_namespace(
        &state.namespace_data_store,
        descriptor,
        NamespaceLimits::default(),
        MerkleLimits::default(),
    )
    .await
    .map_err(namespace_error)?;
    for cid in [
        &created.descriptor_cid,
        &created.root_cid,
        &created.checkpoint_cid,
    ] {
        let block = state.block_store.get(cid)?;
        let mut accepted = 0;
        for replica in &replicas {
            if replica == &state.status.node_id {
                accepted += 1;
                continue;
            }
            let Some(address) = state.network.peer_address(replica).await else {
                continue;
            };
            let mut stored = false;
            for _ in 0..5 {
                if let Ok(response) = state
                    .network
                    .block_put_replica(address, cid.codec, block.payload.clone())
                    .await
                    && response.cid == cid.to_string()
                {
                    stored = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            accepted += usize::from(stored);
        }
        if accepted < 3 {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::DurabilityNotMet,
                format!(
                    "namespace bootstrap durability not met for {cid}: accepted {accepted} of 3"
                ),
            ));
        }
    }

    for replica in &replicas {
        if replica == &state.status.node_id {
            if manager.group(&created.namespace_id).await.is_err() {
                manager
                    .start_group(created.state.clone(), state.namespace_data_store.clone())
                    .await
                    .map_err(consensus_error)?;
            }
        } else {
            let address = state.network.peer_address(replica).await.ok_or_else(|| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::NamespaceUnavailable,
                    format!("replica {replica} is unreachable"),
                )
            })?;
            state
                .network
                .namespace_bootstrap(
                    address,
                    proto::NamespaceBootstrapRequest {
                        namespace_id: created.namespace_id.to_string(),
                        checkpoint_cid: created.checkpoint_cid.to_string(),
                        membership_epoch: 1,
                        initialize: false,
                        learner: false,
                        current_voters: Vec::new(),
                        recovery: false,
                        recovery_confirmation: String::new(),
                    },
                )
                .await
                .map_err(ApiError::network)?;
        }
    }
    let initializer = &replicas[0];
    if initializer == &state.status.node_id {
        manager
            .initialize(
                &created.namespace_id,
                pepper_consensus::raft_members(&replicas).map_err(consensus_error)?,
            )
            .await
            .map_err(consensus_error)?;
    } else {
        let address = state
            .network
            .peer_address(initializer)
            .await
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::NamespaceUnavailable,
                    "initializer unavailable",
                )
            })?;
        state
            .network
            .namespace_bootstrap(
                address,
                proto::NamespaceBootstrapRequest {
                    namespace_id: created.namespace_id.to_string(),
                    checkpoint_cid: created.checkpoint_cid.to_string(),
                    membership_epoch: 1,
                    initialize: true,
                    learner: false,
                    current_voters: Vec::new(),
                    recovery: false,
                    recovery_confirmation: String::new(),
                },
            )
            .await
            .map_err(ApiError::network)?;
    }
    Ok(created)
}

pub(super) async fn namespace_create(
    State(state): State<AppState>,
    Json(request): Json<CreateNamespaceRequest>,
) -> Result<Json<CreateNamespaceResponse>, ApiError> {
    let manager = namespace_manager(&state)?;
    let seed = Cid::new(
        CODEC_RAW,
        format!(
            "{}:{}:{}",
            state.status.node_id,
            request.request_id.as_deref().unwrap_or("create"),
            unix_seconds()
        )
        .as_bytes(),
    );
    let replicas = manager
        .select_replica_set(&seed, state.namespace_log_bytes)
        .await
        .map_err(consensus_error)?;
    if replicas.len() != 3 {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::NamespaceUnavailable,
            "exactly three consensus replicas are required",
        ));
    }
    let mut descriptor = NamespaceDescriptor::new(
        request.kind,
        replicas.clone(),
        state.status.node_id.clone(),
        "00",
        unix_seconds(),
    );
    if let Some(keep_last) = request.retention_keep_last {
        descriptor.retention.keep_last = keep_last;
    }
    if request.retention_max_age_seconds.is_some() {
        descriptor.retention.max_age_seconds = request.retention_max_age_seconds;
    }
    let created = bootstrap_namespace_group(&state, descriptor).await?;
    if let Some(alias) = &request.alias {
        persist_alias(&state, alias, &created.namespace_id)?;
    }
    Ok(Json(CreateNamespaceResponse {
        namespace_id: created.namespace_id,
        descriptor_cid: created.descriptor_cid,
        namespace_revision: 0,
        root_cid: created.root_cid,
        checkpoint_cid: created.checkpoint_cid,
        replica_nodes: replicas,
        quorum_status: "initializing".to_string(),
        alias: request.alias,
    }))
}

pub(super) async fn namespace_inspect(
    State(state): State<AppState>,
    Path(namespace): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_namespace(&state, &namespace)?;
    let manager = namespace_manager(&state)?;
    let namespace_state = manager
        .linearizable_namespace_state(&id)
        .await
        .map_err(consensus_error)?;
    Ok(Json(serde_json::json!({
        "namespace_id": id,
        "descriptor_cid": id,
        "descriptor": namespace_state.descriptor,
        "namespace_revision": namespace_state.current_revision,
        "root_cid": namespace_state.current_root_cid,
        "commit_cid": namespace_state.head_commit_cid,
        "stale": false
    })))
}

pub(super) async fn namespace_status(
    State(state): State<AppState>,
    Path(namespace): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_namespace(&state, &namespace)?;
    let group = namespace_manager(&state)?
        .group(&id)
        .await
        .map_err(consensus_error)?;
    let metrics = group.raft.metrics().borrow().clone();
    Ok(Json(serde_json::json!({
        "namespace_id": id,
        "leader_id": metrics.current_leader,
        "term": metrics.current_term,
        "last_log_index": metrics.last_log_index,
        "last_applied": metrics.last_applied,
        "state": format!("{:?}", metrics.state),
        "quorum_available": metrics.current_leader.is_some()
    })))
}

pub(super) async fn namespace_replicas(
    State(state): State<AppState>,
    Path(namespace): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_namespace(&state, &namespace)?;
    let group = namespace_manager(&state)?
        .group(&id)
        .await
        .map_err(consensus_error)?;
    let voters = group.voter_identities().await;
    let nodes = voters
        .iter()
        .map(|node| serde_json::json!({"node_id": node, "raft_id": pepper_consensus::raft_node_id(node)}))
        .collect::<Vec<_>>();
    Ok(Json(
        serde_json::json!({"namespace_id": id, "replicas": nodes}),
    ))
}

pub(super) async fn namespace_history(
    State(state): State<AppState>,
    Path(namespace): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_namespace(&state, &namespace)?;
    let namespace_state = namespace_manager(&state)?
        .linearizable_namespace_state(&id)
        .await
        .map_err(consensus_error)?;
    Ok(Json(
        serde_json::json!({"namespace_id": id, "history": namespace_state.history}),
    ))
}

pub(super) async fn namespace_diff(
    State(state): State<AppState>,
    Path(namespace): Path<String>,
    Json(request): Json<DiffRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_namespace(&state, &namespace)?;
    let namespace_state = namespace_manager(&state)?
        .linearizable_namespace_state(&id)
        .await
        .map_err(consensus_error)?;
    let a = namespace_state
        .history
        .get(&request.revision_a)
        .ok_or_else(|| ApiError::not_found("revision-a not found"))?;
    let b = namespace_state
        .history
        .get(&request.revision_b)
        .ok_or_else(|| ApiError::not_found("revision-b not found"))?;
    let entries_a = scan_root_entries(&state.namespace_data_store, &a.root_cid).await?;
    let entries_b = scan_root_entries(&state.namespace_data_store, &b.root_cid).await?;
    let mut keys = entries_a
        .keys()
        .chain(entries_b.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let total_candidates = keys.len();
    let changed_keys = keys
        .iter()
        .filter(|key| entries_a.get(*key) != entries_b.get(*key))
        .take(10_000)
        .map(hex::encode)
        .collect::<Vec<_>>();
    keys.clear();
    Ok(Json(serde_json::json!({
        "namespace_id": id,
        "revision_a": request.revision_a,
        "root_a": a.root_cid,
        "revision_b": request.revision_b,
        "root_b": b.root_cid,
        "changed": a.root_cid != b.root_cid,
        "changed_keys_hex": changed_keys,
        "truncated": total_candidates > 10_000
    })))
}

fn publication_coordinator(
    state: &AppState,
) -> Result<PublicationCoordinator<AgentDurabilityBackend, AgentProtectionBackend>, ApiError> {
    PublicationCoordinator::new(
        namespace_manager(state)?,
        state.namespace_data_store.clone(),
        state.dag_registry.clone(),
        state.publication_repository.clone(),
        Arc::new(AgentDurabilityBackend(state.clone())),
        Arc::new(AgentProtectionBackend::from_state(state)),
        state._publication_limits,
    )
    .map_err(publication_error)
}

pub(super) async fn apply_command(
    state: &AppState,
    namespace_id: NamespaceId,
    command: CommandEnvelope,
    uploaded_roots: Vec<Cid>,
    staged_bytes: u64,
    retain_uploaded_on_conflict: bool,
) -> Result<Json<serde_json::Value>, ApiError> {
    let current = namespace_manager(state)?
        .linearizable_namespace_state(&namespace_id)
        .await
        .map_err(consensus_error)?;
    if let Some(response) = current
        .idempotent_response_for(&command)
        .map_err(namespace_error)?
    {
        let (revision, root, commit) = match &response {
            CommandResponse::Commit(commit) => (
                commit.namespace_revision,
                commit.root_cid.clone(),
                Some(commit.commit_cid.clone()),
            ),
            CommandResponse::Snapshot(snapshot) => {
                (snapshot.revision, snapshot.root_cid.clone(), None)
            }
        };
        return Ok(Json(serde_json::json!({
            "namespace_id": namespace_id,
            "namespace_revision": revision,
            "root_cid": root,
            "commit_cid": commit,
            "result": response,
            "replayed": true,
            "durability": "durable",
            "durability_receipts": []
        })));
    }
    let coordinator = publication_coordinator(state)?;
    let started = std::time::Instant::now();
    let published = coordinator
        .publish(
            PublicationRequest {
                namespace_id: namespace_id.clone(),
                command,
                uploaded_roots,
                staged_bytes,
                staging_ttl_seconds: state._publication_limits.max_staging_ttl_seconds,
                retain_uploaded_on_conflict,
            },
            unix_seconds(),
        )
        .await;
    NAMESPACE_COMMIT_LATENCY_MICROS.fetch_add(
        started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
    let result = match published {
        Ok(result) => {
            NAMESPACE_COMMITS.fetch_add(1, Ordering::Relaxed);
            result
        }
        Err(error) => {
            NAMESPACE_COMMIT_FAILURES.fetch_add(1, Ordering::Relaxed);
            if matches!(
                error,
                PublicationError::Conflict(_) | PublicationError::Application { .. }
            ) {
                NAMESPACE_CONFLICTS.fetch_add(1, Ordering::Relaxed);
            }
            if matches!(
                error,
                PublicationError::DurabilityNotMet(_) | PublicationError::Protection(_)
            ) {
                NAMESPACE_DURABILITY_FAILURES.fetch_add(1, Ordering::Relaxed);
            }
            return Err(publication_error(error));
        }
    };
    let (revision, root, commit) = match &result.apply.response {
        CommandResponse::Commit(commit) => (
            commit.namespace_revision,
            commit.root_cid.clone(),
            Some(commit.commit_cid.clone()),
        ),
        CommandResponse::Snapshot(snapshot) => (snapshot.revision, snapshot.root_cid.clone(), None),
    };
    Ok(Json(serde_json::json!({
        "namespace_id": namespace_id,
        "namespace_revision": revision,
        "root_cid": root,
        "commit_cid": commit,
        "result": result.apply.response,
        "replayed": result.apply.replayed,
        "durability": "durable",
        "durability_receipts": result.durability
    })))
}

pub(super) async fn kv_put(
    State(state): State<AppState>,
    Json(request): Json<KvMutationRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_namespace(&state, &request.namespace)?;
    let value_cid = request
        .value_cid
        .clone()
        .ok_or_else(|| ApiError::bad_request("value_cid is required"))?;
    let current = current_value(&state, &id, &request.key_hex).await?;
    let precondition = precondition(current, request.if_generation, request.if_cid)?;
    let base = namespace_manager(&state)?
        .linearizable_namespace_state(&id)
        .await
        .map_err(consensus_error)?;
    let command = CommandEnvelope {
        request_id: request.request_id,
        writer_identity: request.writer_identity,
        timestamp_unix_seconds: unix_seconds(),
        signature_hex: request.signature_hex,
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: base.current_revision,
                base_root_cid: base.current_root_cid,
                mutations: vec![NamespaceMutation::Put {
                    key_hex: request.key_hex,
                    value_cid,
                    value_kind: request.value_kind,
                    metadata: request.metadata,
                    precondition,
                }],
                message: None,
            },
        },
    };
    apply_command(
        &state,
        id,
        command,
        request.uploaded_roots,
        request.staged_bytes,
        request.retain_uploaded_on_conflict,
    )
    .await
}

pub(super) async fn kv_delete(
    State(state): State<AppState>,
    Json(request): Json<KvMutationRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_namespace(&state, &request.namespace)?;
    let current = current_value(&state, &id, &request.key_hex).await?;
    let precondition = precondition(current, request.if_generation, request.if_cid)?;
    let base = namespace_manager(&state)?
        .linearizable_namespace_state(&id)
        .await
        .map_err(consensus_error)?;
    let command = CommandEnvelope {
        request_id: request.request_id,
        writer_identity: request.writer_identity,
        timestamp_unix_seconds: unix_seconds(),
        signature_hex: request.signature_hex,
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: base.current_revision,
                base_root_cid: base.current_root_cid,
                mutations: vec![NamespaceMutation::Delete {
                    key_hex: request.key_hex,
                    precondition,
                }],
                message: None,
            },
        },
    };
    apply_command(&state, id, command, Vec::new(), 0, false).await
}

pub(super) async fn kv_transaction(
    State(state): State<AppState>,
    Json(request): Json<TransactionApplyRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.version != 1 {
        return Err(ApiError::bad_request("transaction file version must be 1"));
    }
    let id = parse_namespace(&state, &request.namespace)?;
    let command = CommandEnvelope {
        request_id: request.request_id,
        writer_identity: request.writer_identity,
        timestamp_unix_seconds: unix_seconds(),
        signature_hex: request.signature_hex,
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: request.base_revision,
                base_root_cid: request.base_root_cid,
                mutations: request.mutations,
                message: request.message,
            },
        },
    };
    apply_command(
        &state,
        id,
        command,
        request.uploaded_roots,
        request.staged_bytes,
        request.retain_uploaded_on_conflict,
    )
    .await
}

pub(super) async fn kv_get(
    State(state): State<AppState>,
    Json(request): Json<KvGetRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_namespace(&state, &request.namespace)?;
    let key =
        hex::decode(&request.key_hex).map_err(|error| ApiError::bad_request(error.to_string()))?;
    let (namespace_state, root, revision, stale) =
        resolve_read(&state, &id, &request.consistency).await?;
    let read_lease = stale.then(|| ReadLease {
        lease_id: format!("http-read-{}", request_id()),
        namespace_id: id.clone(),
        root_cid: root.clone(),
        revision,
        created_at_unix_seconds: unix_seconds(),
        expires_at_unix_seconds: unix_seconds().saturating_add(60),
    });
    let coordinator = publication_coordinator(&state)?;
    if let Some(lease) = &read_lease {
        coordinator
            .acquire_read_lease(lease.clone())
            .await
            .map_err(publication_error)?;
    }
    let value_result = pepper_merkle::get(
        &state.namespace_data_store,
        &root,
        &key,
        MerkleLimits::default(),
    )
    .await;
    if let Some(lease) = &read_lease {
        coordinator
            .release_read_lease(&lease.lease_id)
            .await
            .map_err(publication_error)?;
    }
    let value = value_result.map_err(|error| ApiError::bad_request(error.to_string()))?;
    Ok(Json(
        serde_json::json!({"namespace_id": id, "namespace_revision": revision, "root_cid": root, "value": value, "stale": stale, "head_revision": namespace_state.current_revision}),
    ))
}

pub(super) async fn kv_scan(
    State(state): State<AppState>,
    Json(request): Json<KvScanRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.limit == 0 || request.limit > 10_000 {
        return Err(ApiError::bad_request(
            "scan limit must be between 1 and 10000",
        ));
    }
    let id = parse_namespace(&state, &request.namespace)?;
    let (_, root, revision, stale) = resolve_read(&state, &id, &request.consistency).await?;
    let decode = |value: Option<String>| -> Result<Option<Vec<u8>>, ApiError> {
        value
            .map(|value| {
                hex::decode(value).map_err(|error| ApiError::bad_request(error.to_string()))
            })
            .transpose()
    };
    let read_lease = stale.then(|| ReadLease {
        lease_id: format!("http-scan-{}", request_id()),
        namespace_id: id.clone(),
        root_cid: root.clone(),
        revision,
        created_at_unix_seconds: unix_seconds(),
        expires_at_unix_seconds: unix_seconds().saturating_add(60),
    });
    let coordinator = publication_coordinator(&state)?;
    if let Some(lease) = &read_lease {
        coordinator
            .acquire_read_lease(lease.clone())
            .await
            .map_err(publication_error)?;
    }
    let page_result = pepper_merkle::scan(
        &state.namespace_data_store,
        &root,
        ScanQuery {
            start: decode(request.start_hex)?,
            end: decode(request.end_hex)?,
            prefix: decode(request.prefix_hex)?,
            limit: request.limit,
            cursor: request.cursor,
        },
        MerkleLimits::default(),
    )
    .await;
    if let Some(lease) = &read_lease {
        coordinator
            .release_read_lease(&lease.lease_id)
            .await
            .map_err(publication_error)?;
    }
    let page = page_result.map_err(|error| {
        if error.to_string().contains("cursor") {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidCursor,
                error.to_string(),
            )
        } else {
            ApiError::bad_request(error.to_string())
        }
    })?;
    let entries = page
        .entries
        .into_iter()
        .map(|entry| serde_json::json!({"key_hex": hex::encode(entry.key), "value": entry.value}))
        .collect::<Vec<_>>();
    Ok(Json(
        serde_json::json!({"namespace_id": id, "namespace_revision": revision, "root_cid": root, "entries": entries, "next_cursor": page.next_cursor, "stale": stale}),
    ))
}

async fn scan_root_entries(
    store: &ConsensusDataStore,
    root: &Cid,
) -> Result<BTreeMap<Vec<u8>, pepper_merkle::MerkleValue>, ApiError> {
    let mut entries = BTreeMap::new();
    let mut cursor = None;
    loop {
        let page = pepper_merkle::scan(
            store,
            root,
            ScanQuery {
                limit: 10_000,
                cursor,
                ..ScanQuery::default()
            },
            MerkleLimits::default(),
        )
        .await
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
        entries.extend(
            page.entries
                .into_iter()
                .map(|entry| (entry.key, entry.value)),
        );
        cursor = page.next_cursor;
        if cursor.is_none() || entries.len() >= 100_000 {
            break;
        }
    }
    Ok(entries)
}

pub(super) async fn current_value(
    state: &AppState,
    id: &NamespaceId,
    key_hex: &str,
) -> Result<Option<pepper_merkle::MerkleValue>, ApiError> {
    let key = hex::decode(key_hex).map_err(|error| ApiError::bad_request(error.to_string()))?;
    let current = namespace_manager(state)?
        .linearizable_namespace_state(id)
        .await
        .map_err(consensus_error)?;
    pepper_merkle::get(
        &state.namespace_data_store,
        &current.current_root_cid,
        &key,
        MerkleLimits::default(),
    )
    .await
    .map_err(|error| ApiError::bad_request(error.to_string()))
}

pub(super) fn precondition(
    current: Option<pepper_merkle::MerkleValue>,
    generation: Option<u64>,
    cid: Option<Cid>,
) -> Result<KeyPrecondition, ApiError> {
    match current {
        None if generation.is_none() && cid.is_none() => Ok(KeyPrecondition::Absent),
        None => Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::GenerationConflict,
            "key is absent",
        )),
        Some(value) => {
            if generation.is_some_and(|expected| expected != value.generation)
                || cid.as_ref().is_some_and(|expected| expected != &value.cid)
            {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    ErrorCode::GenerationConflict,
                    "key precondition does not match",
                ));
            }
            Ok(KeyPrecondition::Match {
                generation: value.generation,
                cid: value.cid,
            })
        }
    }
}

pub(super) async fn resolve_read(
    state: &AppState,
    id: &NamespaceId,
    request: &ConsistencyRequest,
) -> Result<(NamespaceState, Cid, u64, bool), ApiError> {
    let _read_timer = NamespaceReadTimer::start();
    let selected = usize::from(request.revision.is_some())
        + usize::from(request.root_cid.is_some())
        + usize::from(request.checkpoint_cid.is_some());
    if selected > 1 {
        return Err(ApiError::bad_request(
            "choose only one of revision, root_cid, or checkpoint_cid",
        ));
    }
    if let Some(checkpoint) = &request.checkpoint_cid {
        let loaded = load_checkpoint(
            &state.namespace_data_store,
            checkpoint,
            NamespaceLimits::default(),
        )
        .await
        .map_err(namespace_error)?;
        if &loaded.namespace_id != id {
            return Err(ApiError::bad_request("checkpoint namespace mismatch"));
        }
        return Ok((
            loaded.clone(),
            loaded.current_root_cid.clone(),
            loaded.current_revision,
            true,
        ));
    }
    let current = namespace_manager(state)?
        .linearizable_namespace_state(id)
        .await
        .map_err(consensus_error)?;
    if let Some(root) = &request.root_cid {
        return Ok((
            current.clone(),
            root.clone(),
            current.current_revision,
            true,
        ));
    }
    if let Some(revision) = request.revision {
        let record = current
            .history
            .get(&revision)
            .ok_or_else(|| ApiError::not_found("revision not found"))?;
        return Ok((current.clone(), record.root_cid.clone(), revision, true));
    }
    if request
        .consistency
        .as_deref()
        .is_some_and(|value| value != "linearizable")
    {
        return Err(ApiError::bad_request("unsupported consistency"));
    }
    Ok((
        current.clone(),
        current.current_root_cid.clone(),
        current.current_revision,
        false,
    ))
}

pub(super) async fn namespace_rollback(
    State(state): State<AppState>,
    Path(namespace): Path<String>,
    Json(request): Json<RollbackRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_namespace(&state, &namespace)?;
    apply_command(
        &state,
        id,
        CommandEnvelope {
            request_id: request.request_id,
            writer_identity: request.writer_identity,
            timestamp_unix_seconds: unix_seconds(),
            signature_hex: request.signature_hex,
            command: NamespaceCommand::Rollback {
                revision: request.revision,
                message: None,
            },
        },
        Vec::new(),
        0,
        false,
    )
    .await
}

pub(super) async fn namespace_snapshots(
    State(state): State<AppState>,
    Path(namespace): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_namespace(&state, &namespace)?;
    let current = namespace_manager(&state)?
        .linearizable_namespace_state(&id)
        .await
        .map_err(consensus_error)?;
    Ok(Json(
        serde_json::json!({"namespace_id": id, "snapshots": current.named_snapshots}),
    ))
}

pub(super) async fn namespace_snapshot_mutate(
    State(state): State<AppState>,
    Path(namespace): Path<String>,
    Json(request): Json<SnapshotMutationRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_namespace(&state, &namespace)?;
    let command = match request.action.as_str() {
        "create" => NamespaceCommand::CreateSnapshot {
            name: request.name,
            revision: request.revision,
        },
        "delete" => NamespaceCommand::DeleteSnapshot { name: request.name },
        _ => {
            return Err(ApiError::bad_request(
                "snapshot action must be create or delete",
            ));
        }
    };
    apply_command(
        &state,
        id,
        CommandEnvelope {
            request_id: request.request_id,
            writer_identity: request.writer_identity,
            timestamp_unix_seconds: unix_seconds(),
            signature_hex: request.signature_hex,
            command,
        },
        Vec::new(),
        0,
        false,
    )
    .await
}

pub(super) async fn admin_namespace_checkpoint(
    State(state): State<AppState>,
    Path(namespace): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_namespace(&state, &namespace)?;
    let group = namespace_manager(&state)?
        .group(&id)
        .await
        .map_err(consensus_error)?;
    group
        .raft
        .trigger()
        .snapshot()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok(Json(
        serde_json::json!({"namespace_id": id, "checkpoint_requested": true}),
    ))
}

pub(super) async fn admin_namespace_rebalance(
    State(state): State<AppState>,
    Path(namespace): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_namespace(&state, &namespace)?;
    let group = namespace_manager(&state)?
        .group(&id)
        .await
        .map_err(consensus_error)?;
    group.ensure_linearizable().await.map_err(consensus_error)?;
    let reachable = state
        .network
        .peers()
        .await
        .into_iter()
        .filter(|peer| peer.connected)
        .map(|peer| peer.node_id)
        .chain(std::iter::once(state.status.node_id.clone()))
        .collect::<HashSet<_>>();
    let Some(failed_node) = group
        .voter_identities()
        .await
        .iter()
        .find(|node| !reachable.contains(*node))
        .cloned()
    else {
        return Ok(Json(serde_json::json!({
            "namespace_id": id,
            "status": "balanced"
        })));
    };
    admin_namespace_replace(
        State(state),
        Path(namespace),
        Json(ReplaceReplicaRequest {
            failed_node,
            replacement_node: None,
        }),
    )
    .await
}

pub(super) async fn admin_namespace_replace(
    State(state): State<AppState>,
    Path(namespace): Path<String>,
    Json(request): Json<ReplaceReplicaRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_namespace(&state, &namespace)?;
    let manager = namespace_manager(&state)?;
    let group = manager.group(&id).await.map_err(consensus_error)?;
    let current = group.namespace_state().await;
    let replacement = if let Some(replacement) = request.replacement_node {
        replacement
    } else {
        let retained = group
            .voter_identities()
            .await
            .into_iter()
            .filter(|node| node != &request.failed_node)
            .collect::<Vec<_>>();
        manager
            .select_replacement(&id.0, &retained, state.namespace_log_bytes)
            .await
            .map_err(consensus_error)?
    };
    let checkpoint =
        pepper_namespace::write_checkpoint(&state.namespace_data_store, &current, unix_seconds())
            .await
            .map_err(namespace_error)?;
    AgentDurabilityBackend(state.clone())
        .ensure_durable(&checkpoint, 3)
        .await
        .map_err(publication_error)?;
    let target = state
        .network
        .peer_address(&replacement)
        .await
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::NamespaceUnavailable,
                "replacement node unavailable",
            )
        })?;
    state
        .network
        .namespace_bootstrap(
            target,
            proto::NamespaceBootstrapRequest {
                namespace_id: id.to_string(),
                checkpoint_cid: checkpoint.to_string(),
                membership_epoch: group.membership_epoch(),
                initialize: false,
                learner: true,
                current_voters: group.voter_identities().await,
                recovery: false,
                recovery_confirmation: String::new(),
            },
        )
        .await
        .map_err(ApiError::network)?;
    manager
        .replace_replica(&id, &request.failed_node, &replacement)
        .await
        .map_err(consensus_error)?;
    Ok(Json(
        serde_json::json!({"namespace_id": id, "removed": request.failed_node, "replacement": replacement, "status": "completed"}),
    ))
}

pub(super) async fn admin_namespace_recover(
    State(state): State<AppState>,
    Path(namespace): Path<String>,
    Json(request): Json<RecoverRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = parse_namespace(&state, &namespace)?;
    let loaded = load_checkpoint(
        &state.namespace_data_store,
        &request.checkpoint_cid,
        NamespaceLimits::default(),
    )
    .await
    .map_err(namespace_error)?;
    if loaded.namespace_id != id {
        return Err(ApiError::bad_request("checkpoint namespace mismatch"));
    }
    if request.members.len() != 3 || !request.members.contains(&state.status.node_id) {
        return Err(ApiError::bad_request(
            "recovery requires exactly three members including this node",
        ));
    }
    AgentDurabilityBackend(state.clone())
        .ensure_durable(&request.checkpoint_cid, 3)
        .await
        .map_err(publication_error)?;
    let manager = namespace_manager(&state)?;
    let initializer = request.members[0].clone();
    let mut local_report = None;
    for member in &request.members {
        let initialize = member == &initializer;
        if member == &state.status.node_id {
            if manager.group(&id).await.is_ok() {
                manager.shutdown_group(&id).await.map_err(consensus_error)?;
            }
            let (_, report) = manager
                .prepare_disaster_recovery(
                    loaded.clone(),
                    state.namespace_data_store.clone(),
                    request.members.clone(),
                    &request.confirmation,
                )
                .await
                .map_err(consensus_error)?;
            if initialize {
                manager
                    .initialize(
                        &id,
                        pepper_consensus::raft_members(&request.members)
                            .map_err(consensus_error)?,
                    )
                    .await
                    .map_err(consensus_error)?;
            }
            local_report = Some(report);
        } else {
            let address = state.network.peer_address(member).await.ok_or_else(|| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::NamespaceUnavailable,
                    format!("recovery member {member} is unavailable"),
                )
            })?;
            state
                .network
                .namespace_bootstrap(
                    address,
                    proto::NamespaceBootstrapRequest {
                        namespace_id: id.to_string(),
                        checkpoint_cid: request.checkpoint_cid.to_string(),
                        membership_epoch: 1,
                        initialize,
                        learner: false,
                        current_voters: request.members.clone(),
                        recovery: true,
                        recovery_confirmation: request.confirmation.clone(),
                    },
                )
                .await
                .map_err(ApiError::network)?;
        }
    }
    Ok(Json(serde_json::json!({
        "namespace_id": id,
        "status": "recovery_started",
        "report": local_report
    })))
}

pub(super) fn namespace_error(error: pepper_namespace::NamespaceError) -> ApiError {
    let text = error.to_string();
    if matches!(
        error,
        pepper_namespace::NamespaceError::GenerationConflict(_)
    ) {
        ApiError::new(StatusCode::CONFLICT, ErrorCode::GenerationConflict, text)
    } else if text.contains("cursor") {
        ApiError::new(StatusCode::BAD_REQUEST, ErrorCode::InvalidCursor, text)
    } else {
        ApiError::bad_request(text)
    }
}

pub(super) fn consensus_error(error: pepper_consensus::ConsensusError) -> ApiError {
    if matches!(
        error,
        pepper_consensus::ConsensusError::GroupLimit(_)
            | pepper_consensus::ConsensusError::Placement(_)
    ) {
        NAMESPACE_GROUP_ADMISSION_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    let text = error.to_string();
    match error {
        pepper_consensus::ConsensusError::GroupNotRunning(_)
        | pepper_consensus::ConsensusError::Raft(_) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::NamespaceUnavailable,
            text,
        ),
        pepper_consensus::ConsensusError::NotAssigned(_) => {
            ApiError::new(StatusCode::TEMPORARY_REDIRECT, ErrorCode::NotLeader, text)
        }
        _ => ApiError::bad_request(text),
    }
}

pub(super) fn publication_error(error: PublicationError) -> ApiError {
    let text = error.to_string();
    match error {
        PublicationError::DurabilityNotMet(_) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::DurabilityNotMet,
            text,
        ),
        PublicationError::StagingUnavailable => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::StagingUnavailable,
            text,
        ),
        PublicationError::TransactionExpired => {
            ApiError::new(StatusCode::GONE, ErrorCode::TransactionExpired, text)
        }
        PublicationError::Conflict(_) => {
            ApiError::new(StatusCode::CONFLICT, ErrorCode::GenerationConflict, text)
        }
        PublicationError::Application { ref code, .. } if code == "generation_conflict" => {
            ApiError::new(StatusCode::CONFLICT, ErrorCode::GenerationConflict, text)
        }
        PublicationError::Application { ref code, .. } if code == "stale_snapshot" => {
            ApiError::new(StatusCode::CONFLICT, ErrorCode::Conflict, text)
        }
        PublicationError::Application { .. } => {
            ApiError::new(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, text)
        }
        _ => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::NamespaceUnavailable,
            text,
        ),
    }
}
