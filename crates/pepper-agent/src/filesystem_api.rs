// SPDX-License-Identifier: Apache-2.0

//! Snapshot filesystem HTTP application over transactional namespaces.

use super::*;
use pepper_filesystem::{
    FilesystemError, FilesystemLimits, InodeKind, TreeInputEntry, build_tree, diff_trees,
    flatten_tree, get_inode, get_root,
};
use pepper_namespace::{
    CommandEnvelope, KeyPrecondition, NamespaceCommand, NamespaceKind, NamespaceMutation,
    NamespaceStateMachine, TransactionCommand,
};
use serde::Deserialize;

const ROOT_KEY: &[u8] = b"root";
fn default_root_mode() -> u32 {
    0o755
}

#[derive(Debug, Deserialize)]
pub(super) struct FsCreateRequest {
    alias: Option<String>,
}
#[derive(Debug, Deserialize)]
pub(super) struct FsCommitRequest {
    filesystem: String,
    base_revision: u64,
    entries: Vec<TreeInputEntry>,
    #[serde(default = "default_root_mode")]
    root_mode: u32,
    message: Option<String>,
    request_id: String,
}
#[derive(Debug, Deserialize)]
pub(super) struct FsRevisionRequest {
    filesystem: String,
    revision: Option<u64>,
}
#[derive(Debug, Deserialize)]
pub(super) struct FsDiffRequest {
    filesystem: String,
    revision_a: u64,
    revision_b: u64,
}
#[derive(Debug, Deserialize)]
pub(super) struct FsRollbackRequest {
    filesystem: String,
    revision: u64,
    request_id: String,
}
#[derive(Debug, Deserialize)]
pub(super) struct FsCloneRequest {
    filesystem: String,
    root_cid: Cid,
    request_id: String,
}

pub(super) async fn fs_create(
    State(state): State<AppState>,
    Json(request): Json<FsCreateRequest>,
) -> Result<Json<super::namespace_api::CreateNamespaceResponse>, ApiError> {
    super::namespace_api::namespace_create(
        State(state),
        Json(super::namespace_api::CreateNamespaceRequest {
            kind: NamespaceKind::Filesystem,
            alias: request.alias,
            request_id: None,
            retention_keep_last: None,
            retention_max_age_seconds: None,
        }),
    )
    .await
}

async fn namespace_value(
    state: &AppState,
    namespace_id: &pepper_namespace::NamespaceId,
    revision: Option<u64>,
) -> Result<Option<pepper_merkle::MerkleValue>, ApiError> {
    let namespace_state = namespace_manager(state)?
        .linearizable_namespace_state(namespace_id)
        .await
        .map_err(consensus_error)?;
    if namespace_state.descriptor.kind != NamespaceKind::Filesystem {
        return Err(ApiError::bad_request("namespace is not a filesystem"));
    }
    let machine = NamespaceStateMachine::new(state.namespace_data_store.clone(), namespace_state)
        .map_err(namespace_error)?;
    machine
        .get(revision, ROOT_KEY)
        .await
        .map_err(namespace_error)
}

async fn filesystem_root_for_revision(
    state: &AppState,
    namespace_id: &pepper_namespace::NamespaceId,
    revision: Option<u64>,
) -> Result<Cid, ApiError> {
    namespace_value(state, namespace_id, revision)
        .await?
        .map(|value| value.cid)
        .ok_or_else(|| ApiError::not_found("filesystem has no committed root at this revision"))
}

pub(super) async fn fs_commit(
    State(state): State<AppState>,
    Json(request): Json<FsCommitRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let namespace_id = parse_namespace(&state, &request.filesystem)?;
    let namespace_state = namespace_manager(&state)?
        .linearizable_namespace_state(&namespace_id)
        .await
        .map_err(consensus_error)?;
    let base_root = if request.base_revision == namespace_state.current_revision {
        namespace_state.current_root_cid.clone()
    } else {
        namespace_state
            .history
            .get(&request.base_revision)
            .map(|record| record.root_cid.clone())
            .ok_or_else(|| ApiError::not_found("base revision not found"))?
    };
    let base_value = namespace_value(&state, &namespace_id, Some(request.base_revision)).await?;
    let precondition = match &base_value {
        Some(value) => KeyPrecondition::Match {
            generation: value.generation,
            cid: value.cid.clone(),
        },
        None => KeyPrecondition::Absent,
    };
    let previous = base_value.map(|value| value.cid);
    let staged_bytes = request
        .entries
        .iter()
        .map(|entry| entry.logical_size)
        .try_fold(0u64, u64::checked_add)
        .ok_or_else(|| ApiError::bad_request("filesystem size overflow"))?;
    let (filesystem_root, descriptor) = build_tree(
        &state.namespace_data_store,
        request.entries,
        namespace_state.current_revision.saturating_add(1),
        previous,
        request.root_mode,
        FilesystemLimits::default(),
    )
    .await
    .map_err(filesystem_error)?;
    let command = CommandEnvelope {
        request_id: request.request_id,
        writer_identity: "filesystem-http".into(),
        timestamp_unix_seconds: unix_seconds(),
        signature_hex: "00".into(),
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: request.base_revision,
                base_root_cid: base_root,
                mutations: vec![NamespaceMutation::Put {
                    key_hex: hex::encode(ROOT_KEY),
                    value_cid: filesystem_root.clone(),
                    value_kind: "filesystem_root".into(),
                    metadata: BTreeMap::new(),
                    precondition,
                }],
                message: request.message,
            },
        },
    };
    let mut response = apply_command(
        &state,
        namespace_id,
        command,
        vec![filesystem_root.clone()],
        Vec::new(),
        staged_bytes,
        true,
    )
    .await?
    .0;
    response["filesystem_root_cid"] = serde_json::json!(filesystem_root);
    response["filesystem"] = serde_json::to_value(descriptor).map_err(ApiError::serde)?;
    Ok(Json(response))
}

pub(super) async fn fs_checkout(
    State(state): State<AppState>,
    Json(request): Json<FsRevisionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let namespace_id = parse_namespace(&state, &request.filesystem)?;
    let root = filesystem_root_for_revision(&state, &namespace_id, request.revision).await?;
    let current_revision = namespace_manager(&state)?
        .linearizable_namespace_state(&namespace_id)
        .await
        .map_err(consensus_error)?
        .current_revision;
    let descriptor = get_root(
        &state.namespace_data_store,
        &root,
        FilesystemLimits::default(),
    )
    .await
    .map_err(filesystem_error)?;
    let root_inode = get_inode(
        &state.namespace_data_store,
        &descriptor.root_inode_cid,
        FilesystemLimits::default(),
    )
    .await
    .map_err(filesystem_error)?;
    let entries = flatten_tree(
        &state.namespace_data_store,
        &root,
        FilesystemLimits::default(),
    )
    .await
    .map_err(filesystem_error)?;
    Ok(Json(
        serde_json::json!({"namespace_id":namespace_id,"namespace_revision":request.revision.unwrap_or(current_revision),"filesystem_root_cid":root,"filesystem":descriptor,"root_inode":root_inode,"entries":entries,"stale":request.revision.is_some()}),
    ))
}

pub(super) async fn fs_history(
    State(state): State<AppState>,
    Path(filesystem): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    super::namespace_api::namespace_history(State(state), Path(filesystem)).await
}

pub(super) async fn fs_diff(
    State(state): State<AppState>,
    Json(request): Json<FsDiffRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let namespace_id = parse_namespace(&state, &request.filesystem)?;
    let left =
        filesystem_root_for_revision(&state, &namespace_id, Some(request.revision_a)).await?;
    let right =
        filesystem_root_for_revision(&state, &namespace_id, Some(request.revision_b)).await?;
    let changes = diff_trees(
        &state.namespace_data_store,
        &left,
        &right,
        FilesystemLimits::default(),
    )
    .await
    .map_err(filesystem_error)?;
    Ok(Json(
        serde_json::json!({"namespace_id":namespace_id,"revision_a":request.revision_a,"revision_b":request.revision_b,"root_a":left,"root_b":right,"changes":changes,"stale":true}),
    ))
}

pub(super) async fn fs_rollback(
    State(state): State<AppState>,
    Json(request): Json<FsRollbackRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    super::namespace_api::namespace_rollback(
        State(state),
        Path(request.filesystem),
        Json(super::namespace_api::RollbackRequest {
            revision: request.revision,
            request_id: request.request_id,
            writer_identity: "filesystem-http".into(),
            signature_hex: "00".into(),
        }),
    )
    .await
}

pub(super) async fn fs_clone_root(
    State(state): State<AppState>,
    Json(request): Json<FsCloneRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let namespace_id = parse_namespace(&state, &request.filesystem)?;
    let namespace_state = namespace_manager(&state)?
        .linearizable_namespace_state(&namespace_id)
        .await
        .map_err(consensus_error)?;
    if namespace_value(&state, &namespace_id, None)
        .await?
        .is_some()
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::Conflict,
            "filesystem already has a root",
        ));
    }
    get_root(
        &state.namespace_data_store,
        &request.root_cid,
        FilesystemLimits::default(),
    )
    .await
    .map_err(filesystem_error)?;
    flatten_tree(
        &state.namespace_data_store,
        &request.root_cid,
        FilesystemLimits::default(),
    )
    .await
    .map_err(filesystem_error)?;
    let command = CommandEnvelope {
        request_id: request.request_id,
        writer_identity: "filesystem-http".into(),
        timestamp_unix_seconds: unix_seconds(),
        signature_hex: "00".into(),
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: namespace_state.current_revision,
                base_root_cid: namespace_state.current_root_cid,
                mutations: vec![NamespaceMutation::Put {
                    key_hex: hex::encode(ROOT_KEY),
                    value_cid: request.root_cid.clone(),
                    value_kind: "filesystem_root".into(),
                    metadata: BTreeMap::new(),
                    precondition: KeyPrecondition::Absent,
                }],
                message: Some("clone from immutable filesystem root".into()),
            },
        },
    };
    let mut response = apply_command(
        &state,
        namespace_id,
        command,
        vec![request.root_cid.clone()],
        Vec::new(),
        0,
        false,
    )
    .await?
    .0;
    response["filesystem_root_cid"] = serde_json::json!(request.root_cid);
    Ok(Json(response))
}

fn filesystem_error(error: FilesystemError) -> ApiError {
    ApiError::bad_request(error.to_string())
}

#[allow(dead_code)]
fn _explicitly_unsupported_types() -> (InodeKind, &'static str) {
    (
        InodeKind::RegularFile,
        "symlinks, hard links, sparse files, devices, sockets, ownership mappings, ACLs, and platform attributes are unsupported",
    )
}
