// SPDX-License-Identifier: Apache-2.0

//! Immutable object and directory HTTP service boundary.

use super::*;

pub(super) async fn put_object(
    State(state): State<AppState>,
    Query(query): Query<ObjectPutQuery>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<DurabilityReceipt>, ApiError> {
    let _guard = state.operation_lock.read().await;
    let content_length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if let Some(length) = content_length {
        enforce_size_limit(state.max_object_bytes, length, "object")?;
    }
    let explicit_erasure =
        query.erasure_data_shards.is_some() || query.erasure_parity_shards.is_some();
    let receipt = if explicit_erasure {
        put_erasure_object_stream_receipts(
            &state,
            body,
            query
                .erasure_data_shards
                .unwrap_or(state.erasure_data_shards),
            query
                .erasure_parity_shards
                .unwrap_or(state.erasure_parity_shards),
        )
        .await?
        .receipt
    } else {
        put_policy_object_stream_receipts(&state, body, content_length, false)
            .await?
            .receipt
    };
    if query.pin.unwrap_or(true) {
        ensure_implicit_pin(&state, &receipt.cid).await?;
    }
    Ok(Json(receipt))
}

pub(super) async fn get_object(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> Result<Response, ApiError> {
    let guard = Some(Arc::new(state.operation_lock.clone().read_owned().await));
    let cid = BlockStore::parse_cid(&cid)?;
    if !matches!(
        cid.codec,
        CODEC_SMALL_OBJECT | CODEC_OBJECT_MANIFEST | CODEC_ERASURE_MANIFEST
    ) {
        return Err(ApiError::bad_request("CID is not an object manifest"));
    }
    get_object_at_placement(state, cid, None, guard).await
}

pub(super) async fn get_object_at_placement(
    state: AppState,
    cid: Cid,
    placement: Option<PlacementReference>,
    guard: Option<Arc<tokio::sync::OwnedRwLockReadGuard<()>>>,
) -> Result<Response, ApiError> {
    let body = if cid.codec == CODEC_SMALL_OBJECT {
        let block = match placement.as_ref() {
            Some(placement) => get_block_at_placement(&state, &cid, placement).await?,
            None => get_block_resolved(&state, &cid).await?,
        };
        Body::from(block.payload)
    } else if cid.codec == CODEC_ERASURE_MANIFEST {
        let manifest_block = match placement.as_ref() {
            Some(placement) => get_block_at_placement(&state, &cid, placement).await?,
            None => get_block_resolved(&state, &cid).await?,
        };
        let manifest: ErasureManifest =
            serde_json::from_slice(&manifest_block.payload).map_err(ApiError::serde)?;
        validate_erasure_resource_limits(&state, &manifest)?;
        let data_shards = manifest.data_shards;
        let parity_shards = manifest.parity_shards;
        let mut stripes = manifest.stripes.into_iter();
        let Some(first_stripe) = stripes.next() else {
            return Ok((
                [(header::CONTENT_TYPE, "application/octet-stream")],
                Body::empty(),
            )
                .into_response());
        };
        let first_frames = erasure_stripe_frames(&state, data_shards, parity_shards, &first_stripe)
            .await
            .map_err(|error| {
                warn!(
                    ?error,
                    offset = first_stripe.offset,
                    "erasure GET first stripe failed"
                );
                error
            })?;
        let remaining_stream = stream::iter(stripes.map(move |stripe| {
            let state = state.clone();
            let guard = guard.clone();
            async move {
                let _guard = guard;
                erasure_stripe_frames(&state, data_shards, parity_shards, &stripe)
                    .await
                    .map_err(|error| {
                        warn!(?error, offset = stripe.offset, "erasure GET stripe failed");
                        std::io::Error::other(error.message)
                    })
            }
        }))
        .buffered(4)
        .map_ok(|frames| stream::iter(frames.into_iter().map(Ok::<Bytes, std::io::Error>)))
        .try_flatten();
        let first_stream = stream::iter(first_frames.into_iter().map(Ok::<Bytes, std::io::Error>));
        Body::from_stream(first_stream.chain(remaining_stream))
    } else {
        let manifest_block = match placement.as_ref() {
            Some(placement) => get_block_at_placement(&state, &cid, placement).await?,
            None => get_block_resolved(&state, &cid).await?,
        };
        let manifest: ObjectManifest =
            serde_json::from_slice(&manifest_block.payload).map_err(ApiError::serde)?;
        validate_object_resource_limits(&state, &manifest)?;
        if manifest.chunks.len() > 1_000_000 {
            return Err(ApiError::bad_request(
                "object manifest contains too many chunks",
            ));
        }
        let mut chunks = manifest.chunks.into_iter();
        let Some(first_chunk) = chunks.next() else {
            return Ok((
                [(header::CONTENT_TYPE, "application/octet-stream")],
                Body::empty(),
            )
                .into_response());
        };
        let first_block =
            get_block_at_placement(&state, &first_chunk.cid, &first_chunk.placement).await?;
        if first_block.payload.len() as u64 != first_chunk.size {
            return Err(ApiError::internal("object chunk size mismatch"));
        }
        let first_stream =
            stream::once(
                async move { Ok::<Bytes, std::io::Error>(Bytes::from(first_block.payload)) },
            );
        let body_stream = stream::iter(chunks.map(move |chunk| {
            let state = state.clone();
            let guard = guard.clone();
            async move {
                let _guard = guard;
                let block = get_block_at_placement(&state, &chunk.cid, &chunk.placement)
                    .await
                    .map_err(|error| std::io::Error::other(error.message))?;
                if block.payload.len() as u64 != chunk.size {
                    return Err(std::io::Error::other("object chunk size mismatch"));
                }
                Ok::<Bytes, std::io::Error>(Bytes::from(block.payload))
            }
        }))
        .buffered(16);
        Body::from_stream(first_stream.chain(body_stream))
    };
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response())
}

pub(super) async fn put_dir(
    State(state): State<AppState>,
    body: Body,
) -> Result<Json<DurabilityReceipt>, ApiError> {
    let _guard = state.operation_lock.read().await;
    let body = read_body_limited(body, state.max_block_bytes, "directory manifest").await?;
    let manifest: DirManifest = serde_json::from_slice(&body).map_err(ApiError::serde)?;
    manifest.validate().map_err(ApiError::manifest)?;
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(ApiError::serde)?;
    let mut receipt = put_replicated_block(&state, CODEC_DIR_MANIFEST, manifest_bytes).await?;
    let mut children_durable = true;
    for root in manifest
        .entries
        .iter()
        .filter_map(|entry| entry.cid.clone())
    {
        for cid in traverse_reachable(&state, root).await? {
            let providers = state.network.find_providers(&cid).await?;
            if healthy_provider_node_ids(&state, &cid, providers)
                .await
                .len()
                < state.replication_factor
            {
                children_durable = false;
                break;
            }
        }
        if !children_durable {
            break;
        }
    }
    if !children_durable {
        receipt.status = "degraded".to_string();
    }
    ensure_implicit_pin(&state, &receipt.cid).await?;
    Ok(Json(receipt))
}

pub(super) async fn get_dir(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> Result<Json<DirManifest>, ApiError> {
    let _guard = state.operation_lock.read().await;
    let cid = BlockStore::parse_cid(&cid)?;
    if cid.codec != CODEC_DIR_MANIFEST {
        return Err(ApiError::bad_request("CID is not a directory manifest"));
    }
    let manifest_block = get_block_resolved(&state, &cid).await?;
    let manifest: DirManifest =
        serde_json::from_slice(&manifest_block.payload).map_err(ApiError::serde)?;
    manifest.validate().map_err(ApiError::manifest)?;
    Ok(Json(manifest))
}

pub(super) fn validate_object_resource_limits(
    state: &AppState,
    manifest: &ObjectManifest,
) -> Result<(), ApiError> {
    manifest.validate().map_err(ApiError::manifest)?;
    enforce_size_limit(state.max_object_bytes, manifest.size, "object manifest")?;
    let max_block = state.max_block_bytes.unwrap_or(DEFAULT_MAX_BLOCK_BYTES);
    if manifest.chunk_size > max_block || manifest.chunks.iter().any(|chunk| chunk.size > max_block)
    {
        return Err(ApiError::bad_request(
            "object manifest chunk size exceeds the local block limit",
        ));
    }
    if manifest.chunks.len() > 1_000_000 {
        return Err(ApiError::bad_request(
            "object manifest contains too many chunks",
        ));
    }
    Ok(())
}

pub(super) fn validate_erasure_resource_limits(
    state: &AppState,
    manifest: &ErasureManifest,
) -> Result<(), ApiError> {
    manifest.validate().map_err(ApiError::manifest)?;
    enforce_size_limit(
        state.max_object_bytes,
        manifest.size,
        "erasure object manifest",
    )?;
    let max_block = state.max_block_bytes.unwrap_or(DEFAULT_MAX_BLOCK_BYTES);
    if manifest
        .stripes
        .iter()
        .any(|stripe| stripe.shard_size > max_block)
    {
        return Err(ApiError::bad_request(
            "erasure manifest shard size exceeds the local block limit",
        ));
    }
    let total = u64::from(manifest.data_shards) + u64::from(manifest.parity_shards);
    if manifest.stripes.iter().any(|stripe| {
        stripe
            .shard_size
            .checked_mul(total)
            .is_none_or(|encoded| encoded > 512 * 1024 * 1024)
    }) {
        return Err(ApiError::bad_request(
            "an erasure stripe exceeds the 512 MiB reconstruction working-set limit",
        ));
    }
    if manifest.stripes.len() > 1_000_000 {
        return Err(ApiError::bad_request(
            "erasure manifest contains too many stripes",
        ));
    }
    Ok(())
}

pub(super) async fn fetch_object_chunks_parallel(
    state: AppState,
    chunks: Vec<ObjectChunk>,
) -> Result<Vec<Vec<u8>>, ApiError> {
    if chunks.len() > 1_000_000 {
        return Err(ApiError::bad_request(
            "object manifest contains too many chunks",
        ));
    }
    let mut fetches = stream::iter(chunks.into_iter().map(|chunk| {
        let state = state.clone();
        async move {
            let block = get_block_at_placement(&state, &chunk.cid, &chunk.placement).await?;
            if block.payload.len() as u64 != chunk.size {
                return Err(ApiError::bad_request("object chunk size mismatch"));
            }
            Ok::<_, ApiError>(block.payload)
        }
    }))
    .buffered(16);
    let mut results = Vec::new();
    while let Some(result) = fetches.next().await {
        results.push(result?);
    }
    Ok(results)
}
