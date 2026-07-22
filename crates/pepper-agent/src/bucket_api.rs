// SPDX-License-Identifier: Apache-2.0

//! Versioned object bucket HTTP application over transactional namespaces.

use super::*;
use pepper_bucket::{
    BucketLimits, BucketObjectDescriptor, decode_descriptor, encode_descriptor, versions,
};
use pepper_merkle::{MerkleLimits, ScanQuery};
use pepper_namespace::{
    CommandEnvelope, KeyPrecondition, NamespaceCommand, NamespaceKind, NamespaceMutation,
    NamespaceStateMachine, TransactionCommand,
};
use pepper_types::CODEC_BUCKET_OBJECT;
use serde::Deserialize;

pub(super) const BUCKET_DESCRIPTOR_PLACEMENT_METADATA: &str = "placement";

pub(super) fn placement_from_merkle_value(
    value: &pepper_merkle::MerkleValue,
) -> Result<PlacementReference, ApiError> {
    let encoded = value
        .metadata
        .get(BUCKET_DESCRIPTOR_PLACEMENT_METADATA)
        .ok_or_else(|| ApiError::bad_request("bucket descriptor placement is missing"))?;
    let placement: PlacementReference = serde_json::from_str(encoded).map_err(ApiError::serde)?;
    if placement.seed != value.cid || placement.validate().is_err() {
        return Err(ApiError::bad_request(
            "bucket descriptor placement does not match descriptor CID",
        ));
    }
    Ok(placement)
}

pub(super) async fn descriptor_from_merkle_value(
    state: &AppState,
    value: &pepper_merkle::MerkleValue,
) -> Result<BucketObjectDescriptor, ApiError> {
    let placement = placement_from_merkle_value(value)?;
    let block = get_block_at_placement(state, &value.cid, &placement).await?;
    decode_descriptor(&block.payload, BucketLimits::default()).map_err(bucket_error)
}

#[derive(Debug, Deserialize)]
pub(super) struct BucketCreateRequest {
    pub(super) alias: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct BucketPutRequest {
    pub(super) bucket: String,
    pub(super) key_hex: String,
    pub(super) content_cid: Cid,
    pub(super) content_placement: Option<PlacementReference>,
    pub(super) logical_size: u64,
    #[serde(default = "default_content_type")]
    pub(super) content_type: String,
    #[serde(default)]
    pub(super) metadata: BTreeMap<String, String>,
    pub(super) if_generation: Option<u64>,
    pub(super) if_cid: Option<Cid>,
    pub(super) request_id: String,
    #[serde(skip)]
    pub(super) preverified_durability: Vec<DurabilityReceipt>,
    #[serde(skip)]
    pub(super) partition_fence: Option<PartitionFence>,
}

#[derive(Debug, Deserialize)]
pub(super) struct BucketKeyRequest {
    pub(super) bucket: String,
    pub(super) key_hex: String,
    pub(super) revision: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct BucketDeleteRequest {
    pub(super) bucket: String,
    pub(super) key_hex: String,
    pub(super) if_generation: Option<u64>,
    pub(super) if_cid: Option<Cid>,
    pub(super) request_id: String,
    #[serde(skip)]
    pub(super) partition_fence: Option<PartitionFence>,
}

#[derive(Debug, Clone)]
pub(super) struct PartitionFence {
    pub(super) generation: u64,
    pub(super) cid: Cid,
}

#[derive(Debug, Deserialize)]
pub(super) struct BucketListRequest {
    pub(super) bucket: String,
    pub(super) prefix_hex: Option<String>,
    #[serde(default = "default_limit")]
    pub(super) limit: usize,
    pub(super) cursor: Option<String>,
    pub(super) revision: Option<u64>,
    #[serde(default)]
    pub(super) include_tombstones: bool,
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
            retention_keep_last: None,
            retention_max_age_seconds: None,
        }),
    )
    .await
}

pub(super) async fn bucket_put(
    State(state): State<AppState>,
    Json(request): Json<BucketPutRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    reject_reserved_s3_key_hex(&request.key_hex)?;
    let namespace_id = parse_namespace(&state, &request.bucket)?;
    let key =
        hex::decode(&request.key_hex).map_err(|error| ApiError::bad_request(error.to_string()))?;
    let base = namespace_manager(&state)?
        .linearizable_namespace_state(&namespace_id)
        .await
        .map_err(consensus_error)?;
    let namespace_store = super::s3_api::direct_namespace_store(&state, &base).await;
    let current = pepper_merkle::get(
        &namespace_store,
        &base.current_root_cid,
        &key,
        MerkleLimits::default(),
    )
    .await
    .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let previous_content_cid = match current.as_ref() {
        Some(value) => {
            descriptor_from_merkle_value(&state, value)
                .await?
                .content_cid
        }
        None => None,
    };
    let precondition = precondition(current.clone(), request.if_generation, request.if_cid)?;
    let previous = current.as_ref().map(|value| value.cid.clone());
    let previous_placement = current
        .as_ref()
        .map(placement_from_merkle_value)
        .transpose()?;
    let committed_at_unix_seconds = unix_seconds();
    let content_placement = request
        .content_placement
        .clone()
        .or_else(|| {
            request
                .preverified_durability
                .iter()
                .find(|receipt| receipt.cid == request.content_cid)
                .and_then(|receipt| receipt.placement.clone())
        })
        .or_else(|| {
            state.placement.current_map().map(|map| {
                PlacementReference::replicated(
                    map.epoch,
                    request.content_cid.clone(),
                    state.replication_factor as u16,
                )
            })
        })
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Unavailable,
                "authoritative placement map is not loaded",
            )
        })?;
    if request
        .preverified_durability
        .iter()
        .find(|receipt| receipt.cid == request.content_cid)
        .is_some_and(|receipt| receipt.placement.as_ref() != Some(&content_placement))
    {
        return Err(ApiError::bad_request(
            "content placement does not match its durability receipt",
        ));
    }
    let content = PlacedCid::new(request.content_cid.clone(), content_placement)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let previous = previous
        .zip(previous_placement)
        .map(|(cid, placement)| PlacedCid { cid, placement });
    let descriptor = BucketObjectDescriptor::object(
        content,
        request.logical_size,
        request.content_type,
        request.metadata,
        base.current_revision.saturating_add(1),
        committed_at_unix_seconds,
        previous,
    );
    let descriptor_bytes =
        encode_descriptor(&descriptor, BucketLimits::default()).map_err(bucket_error)?;
    let descriptor_receipt =
        put_replicated_block(&state, CODEC_BUCKET_OBJECT, descriptor_bytes).await?;
    let descriptor_cid = descriptor_receipt.cid.clone();
    let descriptor_placement = descriptor_receipt.placement.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "bucket descriptor was stored without authoritative placement",
        )
    })?;
    let mut descriptor_metadata = BTreeMap::new();
    descriptor_metadata.insert(
        BUCKET_DESCRIPTOR_PLACEMENT_METADATA.to_string(),
        serde_json::to_string(&descriptor_placement).map_err(ApiError::serde)?,
    );
    let mut mutations = vec![NamespaceMutation::Put {
        key_hex: request.key_hex,
        value_cid: descriptor_cid.clone(),
        value_kind: "bucket_object".to_string(),
        metadata: descriptor_metadata,
        precondition,
    }];
    mutations.push(repair_inventory_mutation(
        base.current_revision.saturating_add(1),
        PlacedCid {
            cid: descriptor_cid.clone(),
            placement: descriptor_placement.clone(),
        },
        descriptor
            .content_cid
            .clone()
            .zip(descriptor.content_placement.clone())
            .map(|(cid, placement)| PlacedCid { cid, placement }),
        descriptor.logical_size,
        committed_at_unix_seconds,
    )?);
    let mut cleanup_durability = Vec::new();
    if let Some(pending) = small_object_pending_mutation(
        &state,
        &base,
        &key,
        descriptor
            .content_cid
            .as_ref()
            .expect("object descriptors always contain a content CID"),
        descriptor
            .content_placement
            .as_ref()
            .expect("object descriptors always bind placement"),
        descriptor.logical_size,
    )
    .await?
    {
        mutations.push(pending);
    }
    if let Some(previous_content_cid) = previous_content_cid
        && descriptor.content_cid.as_ref() != Some(&previous_content_cid)
    {
        let (cleanup_mutations, receipts) =
            small_object_marker_cleanup_mutations(&state, &base, &key, &previous_content_cid)
                .await?;
        mutations.extend(cleanup_mutations);
        cleanup_durability.extend(receipts);
    }
    if let Some(fence) = request.partition_fence {
        mutations.push(NamespaceMutation::Assert {
            key_hex: hex::encode(S3_BUCKET_PARTITION_FENCE_KEY),
            precondition: KeyPrecondition::Match {
                generation: fence.generation,
                cid: fence.cid,
            },
        });
    }
    sort_bucket_mutations(&mut mutations);
    let command = CommandEnvelope {
        request_id: request.request_id,
        writer_identity: "bucket-http".to_string(),
        timestamp_unix_seconds: committed_at_unix_seconds,
        signature_hex: "00".to_string(),
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: base.current_revision,
                base_root_cid: base.current_root_cid,
                mutations,
                message: None,
            },
        },
    };
    let mut preverified_durability = request.preverified_durability;
    preverified_durability.extend(cleanup_durability);
    if !preverified_durability
        .iter()
        .any(|receipt| receipt.cid == request.content_cid)
    {
        let content_placement = descriptor
            .content_placement
            .as_ref()
            .expect("object descriptors always bind placement");
        let required = usize::from(content_placement.replicas);
        if let Some(receipt) = state
            .publication_repository
            .durable_receipt(
                &request.content_cid,
                Some(content_placement),
                required,
                unix_seconds(),
            )
            .map_err(|error| ApiError::internal(error.to_string()))?
        {
            preverified_durability.push(receipt);
        } else {
            preverified_durability.push(
                AgentDurabilityBackend(state.clone())
                    .ensure_at_placement(&request.content_cid, required, content_placement.clone())
                    .await
                    .map_err(publication_error)?,
            );
        }
    }
    preverified_durability.push(descriptor_receipt);
    let mut response = apply_command(
        &state,
        namespace_id,
        command,
        vec![request.content_cid],
        preverified_durability,
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
    reject_reserved_s3_key_hex(&request.key_hex)?;
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
    let descriptor = descriptor_from_merkle_value(&state, &value).await?;
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
    reject_reserved_s3_key_hex(&request.key_hex)?;
    let namespace_id = parse_namespace(&state, &request.bucket)?;
    let base = namespace_manager(&state)?
        .linearizable_namespace_state(&namespace_id)
        .await
        .map_err(consensus_error)?;
    let key =
        hex::decode(&request.key_hex).map_err(|error| ApiError::bad_request(error.to_string()))?;
    let current = pepper_merkle::get(
        &super::s3_api::direct_namespace_store(&state, &base).await,
        &base.current_root_cid,
        &key,
        MerkleLimits::default(),
    )
    .await
    .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let previous_content_cid = match current.as_ref() {
        Some(value) => {
            descriptor_from_merkle_value(&state, value)
                .await?
                .content_cid
        }
        None => None,
    };
    let precondition = precondition(current.clone(), request.if_generation, request.if_cid)?;
    let previous = current.as_ref().map(|value| value.cid.clone());
    let previous_placement = current
        .as_ref()
        .map(placement_from_merkle_value)
        .transpose()?;
    let committed_at_unix_seconds = unix_seconds();
    let previous = previous
        .zip(previous_placement)
        .map(|(cid, placement)| PlacedCid { cid, placement });
    let descriptor = BucketObjectDescriptor::tombstone(
        base.current_revision.saturating_add(1),
        committed_at_unix_seconds,
        previous,
    );
    let descriptor_bytes =
        encode_descriptor(&descriptor, BucketLimits::default()).map_err(bucket_error)?;
    let descriptor_receipt =
        put_replicated_block(&state, CODEC_BUCKET_OBJECT, descriptor_bytes).await?;
    let descriptor_cid = descriptor_receipt.cid.clone();
    let descriptor_placement = descriptor_receipt.placement.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "bucket tombstone was stored without authoritative placement",
        )
    })?;
    let mut descriptor_metadata = BTreeMap::new();
    descriptor_metadata.insert(
        BUCKET_DESCRIPTOR_PLACEMENT_METADATA.to_string(),
        serde_json::to_string(&descriptor_placement).map_err(ApiError::serde)?,
    );
    let mut mutations = vec![NamespaceMutation::Put {
        key_hex: request.key_hex,
        value_cid: descriptor_cid.clone(),
        value_kind: "bucket_tombstone".to_string(),
        metadata: descriptor_metadata,
        precondition,
    }];
    mutations.push(repair_inventory_mutation(
        base.current_revision.saturating_add(1),
        PlacedCid {
            cid: descriptor_cid.clone(),
            placement: descriptor_placement.clone(),
        },
        None,
        0,
        committed_at_unix_seconds,
    )?);
    let mut cleanup_durability = Vec::new();
    if let Some(previous_content_cid) = previous_content_cid {
        let (cleanup_mutations, receipts) =
            small_object_marker_cleanup_mutations(&state, &base, &key, &previous_content_cid)
                .await?;
        mutations.extend(cleanup_mutations);
        cleanup_durability.extend(receipts);
    }
    if let Some(fence) = request.partition_fence {
        mutations.push(NamespaceMutation::Assert {
            key_hex: hex::encode(S3_BUCKET_PARTITION_FENCE_KEY),
            precondition: KeyPrecondition::Match {
                generation: fence.generation,
                cid: fence.cid,
            },
        });
    }
    sort_bucket_mutations(&mut mutations);
    let command = CommandEnvelope {
        request_id: request.request_id,
        writer_identity: "bucket-http".to_string(),
        timestamp_unix_seconds: committed_at_unix_seconds,
        signature_hex: "00".to_string(),
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: base.current_revision,
                base_root_cid: base.current_root_cid,
                mutations,
                message: Some("bucket tombstone".to_string()),
            },
        },
    };
    let mut response = apply_command(
        &state,
        namespace_id,
        command,
        vec![descriptor_cid.clone()],
        {
            cleanup_durability.push(descriptor_receipt);
            cleanup_durability
        },
        0,
        false,
    )
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
    if prefix
        .as_deref()
        .is_some_and(|prefix| prefix.starts_with(S3_INTERNAL_KEY_PREFIX))
    {
        return Err(ApiError::bad_request(
            "bucket key prefix is reserved for internal S3 state",
        ));
    }
    let page = pepper_merkle::scan(
        &super::s3_api::direct_namespace_store(&state, &namespace_state).await,
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
        if entry.key.starts_with(S3_INTERNAL_KEY_PREFIX) {
            continue;
        }
        let descriptor = descriptor_from_merkle_value(&state, &entry.value).await?;
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
    reject_reserved_s3_key_hex(&request.key_hex)?;
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

fn reject_reserved_s3_key_hex(key_hex: &str) -> Result<(), ApiError> {
    let key = hex::decode(key_hex).map_err(|error| ApiError::bad_request(error.to_string()))?;
    if key.starts_with(S3_INTERNAL_KEY_PREFIX) {
        return Err(ApiError::bad_request(
            "bucket key is reserved for internal S3 state",
        ));
    }
    Ok(())
}

fn sort_bucket_mutations(mutations: &mut [NamespaceMutation]) {
    mutations.sort_by(|left, right| bucket_mutation_key(left).cmp(bucket_mutation_key(right)));
}

fn bucket_mutation_key(mutation: &NamespaceMutation) -> &str {
    match mutation {
        NamespaceMutation::Assert { key_hex, .. }
        | NamespaceMutation::Put { key_hex, .. }
        | NamespaceMutation::Delete { key_hex, .. } => key_hex,
    }
}

fn bucket_error(error: pepper_bucket::BucketError) -> ApiError {
    ApiError::bad_request(error.to_string())
}
