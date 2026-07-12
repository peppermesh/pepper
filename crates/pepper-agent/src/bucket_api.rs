// SPDX-License-Identifier: Apache-2.0

//! Versioned object bucket HTTP application over transactional namespaces.

use super::*;
use pepper_bucket::{
    BucketLimits, BucketObjectDescriptor, get_descriptor, put_descriptor, versions,
};
use pepper_merkle::{MerkleLimits, ScanQuery};
use pepper_namespace::{
    CommandEnvelope, NamespaceCommand, NamespaceKind, NamespaceMutation, NamespaceStateMachine,
    TransactionCommand,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct BucketCreateRequest {
    alias: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct BucketPutRequest {
    bucket: String,
    key_hex: String,
    content_cid: Cid,
    logical_size: u64,
    #[serde(default = "default_content_type")]
    content_type: String,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
    if_generation: Option<u64>,
    if_cid: Option<Cid>,
    request_id: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct BucketKeyRequest {
    bucket: String,
    key_hex: String,
    revision: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct BucketDeleteRequest {
    bucket: String,
    key_hex: String,
    if_generation: Option<u64>,
    if_cid: Option<Cid>,
    request_id: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct BucketListRequest {
    bucket: String,
    prefix_hex: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
    cursor: Option<String>,
    revision: Option<u64>,
    #[serde(default)]
    include_tombstones: bool,
}

fn default_content_type() -> String {
    "application/octet-stream".to_string()
}
fn default_limit() -> usize {
    100
}

pub(super) async fn bucket_create(
    State(state): State<AppState>,
    Json(request): Json<BucketCreateRequest>,
) -> Result<Json<super::namespace_api::CreateNamespaceResponse>, ApiError> {
    super::namespace_api::namespace_create(
        State(state),
        Json(super::namespace_api::CreateNamespaceRequest {
            kind: NamespaceKind::Bucket,
            alias: request.alias,
            request_id: None,
        }),
    )
    .await
}

pub(super) async fn bucket_put(
    State(state): State<AppState>,
    Json(request): Json<BucketPutRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let namespace_id = parse_namespace(&state, &request.bucket)?;
    let current = current_value(&state, &namespace_id, &request.key_hex).await?;
    let precondition = precondition(current.clone(), request.if_generation, request.if_cid)?;
    let previous = current.map(|value| value.cid);
    let base = namespace_manager(&state)?
        .linearizable_namespace_state(&namespace_id)
        .await
        .map_err(consensus_error)?;
    let descriptor = BucketObjectDescriptor::object(
        request.content_cid.clone(),
        request.logical_size,
        request.content_type,
        request.metadata,
        base.current_revision.saturating_add(1),
        previous,
    );
    let descriptor_cid = put_descriptor(
        &state.namespace_data_store,
        &descriptor,
        BucketLimits::default(),
    )
    .await
    .map_err(bucket_error)?;
    let command = CommandEnvelope {
        request_id: request.request_id,
        writer_identity: "bucket-http".to_string(),
        timestamp_unix_seconds: unix_seconds(),
        signature_hex: "00".to_string(),
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: base.current_revision,
                base_root_cid: base.current_root_cid,
                mutations: vec![NamespaceMutation::Put {
                    key_hex: request.key_hex,
                    value_cid: descriptor_cid.clone(),
                    value_kind: "bucket_object".to_string(),
                    metadata: BTreeMap::new(),
                    precondition,
                }],
                message: None,
            },
        },
    };
    let mut response = apply_command(
        &state,
        namespace_id,
        command,
        vec![request.content_cid],
        request.logical_size,
        true,
    )
    .await?
    .0;
    response["object_descriptor_cid"] = serde_json::json!(descriptor_cid);
    response["object"] = serde_json::to_value(descriptor).map_err(ApiError::serde)?;
    Ok(Json(response))
}

pub(super) async fn bucket_get(
    State(state): State<AppState>,
    Json(request): Json<BucketKeyRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let namespace_id = parse_namespace(&state, &request.bucket)?;
    let namespace_state = namespace_manager(&state)?
        .linearizable_namespace_state(&namespace_id)
        .await
        .map_err(consensus_error)?;
    let key =
        hex::decode(request.key_hex).map_err(|error| ApiError::bad_request(error.to_string()))?;
    let machine =
        NamespaceStateMachine::new(state.namespace_data_store.clone(), namespace_state.clone())
            .map_err(namespace_error)?;
    let value = machine
        .get(request.revision, &key)
        .await
        .map_err(namespace_error)?
        .ok_or_else(|| ApiError::not_found("bucket key not found"))?;
    let descriptor = get_descriptor(
        &state.namespace_data_store,
        &value.cid,
        BucketLimits::default(),
    )
    .await
    .map_err(bucket_error)?;
    if descriptor.tombstone {
        return Err(ApiError::not_found("bucket key is deleted"));
    }
    Ok(Json(serde_json::json!({
        "namespace_id": namespace_id,
        "namespace_revision": request.revision.unwrap_or(namespace_state.current_revision),
        "key_generation": value.generation,
        "object_descriptor_cid": value.cid,
        "object": descriptor,
        "stale": request.revision.is_some()
    })))
}

pub(super) async fn bucket_head(
    state: State<AppState>,
    request: Json<BucketKeyRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    bucket_get(state, request).await
}

pub(super) async fn bucket_delete(
    State(state): State<AppState>,
    Json(request): Json<BucketDeleteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let namespace_id = parse_namespace(&state, &request.bucket)?;
    let current = current_value(&state, &namespace_id, &request.key_hex).await?;
    let precondition = precondition(current.clone(), request.if_generation, request.if_cid)?;
    let previous = current.map(|value| value.cid);
    let base = namespace_manager(&state)?
        .linearizable_namespace_state(&namespace_id)
        .await
        .map_err(consensus_error)?;
    let descriptor =
        BucketObjectDescriptor::tombstone(base.current_revision.saturating_add(1), previous);
    let descriptor_cid = put_descriptor(
        &state.namespace_data_store,
        &descriptor,
        BucketLimits::default(),
    )
    .await
    .map_err(bucket_error)?;
    let command = CommandEnvelope {
        request_id: request.request_id,
        writer_identity: "bucket-http".to_string(),
        timestamp_unix_seconds: unix_seconds(),
        signature_hex: "00".to_string(),
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: base.current_revision,
                base_root_cid: base.current_root_cid,
                mutations: vec![NamespaceMutation::Put {
                    key_hex: request.key_hex,
                    value_cid: descriptor_cid.clone(),
                    value_kind: "bucket_object".to_string(),
                    metadata: BTreeMap::new(),
                    precondition,
                }],
                message: Some("bucket tombstone".to_string()),
            },
        },
    };
    let mut response = apply_command(&state, namespace_id, command, Vec::new(), 0, false)
        .await?
        .0;
    response["object_descriptor_cid"] = serde_json::json!(descriptor_cid);
    response["tombstone"] = serde_json::json!(true);
    Ok(Json(response))
}

pub(super) async fn bucket_list(
    State(state): State<AppState>,
    Json(request): Json<BucketListRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.limit == 0 || request.limit > 10_000 {
        return Err(ApiError::bad_request(
            "bucket list limit must be 1 to 10000",
        ));
    }
    let namespace_id = parse_namespace(&state, &request.bucket)?;
    let namespace_state = namespace_manager(&state)?
        .linearizable_namespace_state(&namespace_id)
        .await
        .map_err(consensus_error)?;
    let root = request
        .revision
        .map(|revision| {
            namespace_state
                .history
                .get(&revision)
                .map(|record| record.root_cid.clone())
                .ok_or_else(|| ApiError::not_found("bucket revision not found"))
        })
        .transpose()?
        .unwrap_or_else(|| namespace_state.current_root_cid.clone());
    let prefix = request
        .prefix_hex
        .map(hex::decode)
        .transpose()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let page = pepper_merkle::scan(
        &state.namespace_data_store,
        &root,
        ScanQuery {
            prefix,
            limit: request.limit,
            cursor: request.cursor,
            ..ScanQuery::default()
        },
        MerkleLimits::default(),
    )
    .await
    .map_err(|error| {
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
    let mut objects = Vec::new();
    for entry in page.entries {
        let descriptor = get_descriptor(
            &state.namespace_data_store,
            &entry.value.cid,
            BucketLimits::default(),
        )
        .await
        .map_err(bucket_error)?;
        if request.include_tombstones || !descriptor.tombstone {
            objects.push(serde_json::json!({
                "key_hex": hex::encode(entry.key),
                "generation": entry.value.generation,
                "object_descriptor_cid": entry.value.cid,
                "object": descriptor
            }));
        }
    }
    Ok(Json(serde_json::json!({
        "namespace_id": namespace_id,
        "namespace_revision": request.revision.unwrap_or(namespace_state.current_revision),
        "root_cid": root,
        "objects": objects,
        "next_cursor": page.next_cursor,
        "stale": request.revision.is_some()
    })))
}

pub(super) async fn bucket_versions(
    State(state): State<AppState>,
    Json(request): Json<BucketKeyRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let namespace_id = parse_namespace(&state, &request.bucket)?;
    let current = current_value(&state, &namespace_id, &request.key_hex)
        .await?
        .ok_or_else(|| ApiError::not_found("bucket key not found"))?;
    let history = versions(
        &state.namespace_data_store,
        &current.cid,
        BucketLimits::default(),
    )
    .await
    .map_err(bucket_error)?
    .into_iter()
    .map(|(cid, descriptor)| serde_json::json!({"descriptor_cid":cid, "object":descriptor}))
    .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({
        "namespace_id": namespace_id,
        "key_hex": request.key_hex,
        "versions": history
    })))
}

fn bucket_error(error: pepper_bucket::BucketError) -> ApiError {
    ApiError::bad_request(error.to_string())
}
