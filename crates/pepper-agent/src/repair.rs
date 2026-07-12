// SPDX-License-Identifier: Apache-2.0

//! Replica and erasure repair service boundary.

use super::*;

pub(super) fn spawn_repair_loop(state: AppState) {
    tokio::spawn(async move {
        let mut interval = time::interval(state.repair_interval);
        loop {
            interval.tick().await;
            if let Err(error) = run_repair_once(&state).await {
                warn!(?error, "repair loop iteration failed");
            }
        }
    });
}

pub(super) async fn healthy_provider_node_ids(
    state: &AppState,
    cid: &Cid,
    providers: Vec<ProviderRecord>,
) -> Vec<String> {
    let local_node_id = &state.status.node_id;
    let mut healthy = Vec::new();
    for provider in providers {
        if &provider.node_id == local_node_id {
            if state.block_store.has(cid).unwrap_or(false) {
                healthy.push(provider.node_id);
            }
            continue;
        }
        let mut provider_healthy = false;
        for address in provider.addresses {
            let Ok(peer) = address.parse::<SocketAddr>() else {
                continue;
            };
            if matches!(
                time::timeout(
                    Duration::from_millis(500),
                    state.network.block_has(peer, cid)
                )
                .await,
                Ok(Ok(true))
            ) {
                provider_healthy = true;
                break;
            }
        }
        if provider_healthy {
            healthy.push(provider.node_id);
        }
    }
    healthy.sort();
    healthy.dedup();
    healthy
}

pub(super) async fn run_repair_once(state: &AppState) -> Result<(), ApiError> {
    let _repair_permit = state
        .repair_semaphore
        .acquire()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let _ = state.network.cleanup_expired_provider_records()?;

    for peer in state.network.peers().await {
        let mut healthy = false;
        for address in peer.addresses {
            let Ok(address) = address.parse() else {
                continue;
            };
            match time::timeout(Duration::from_millis(500), state.network.node_info(address)).await
            {
                Ok(Ok(_)) => {
                    healthy = true;
                    break;
                }
                Ok(Err(error)) => {
                    warn!(%error, node_id = %peer.node_id, %address, "peer liveness probe failed");
                }
                Err(_) => {
                    warn!(node_id = %peer.node_id, %address, "peer liveness probe timed out");
                }
            }
        }
        if !healthy {
            state.network.remove_peer(&peer.node_id).await;
        }
    }

    for pin in all_pin_records(state)?
        .into_iter()
        .filter(|pin| pin.owner == state.status.node_id)
    {
        if let Err(error) = broadcast_pin(state, &pin).await {
            warn!(pin_id = %pin.pin_id, error = %error.message, "failed to resynchronize pin record");
        }
    }

    let candidates = placement_candidates(state, state.network.peers().await);
    let mut pinned_replication = HashMap::<Cid, usize>::new();
    for pin in active_pins(state)? {
        for cid in traverse_reachable(state, pin.root_cid).await? {
            pinned_replication
                .entry(cid)
                .and_modify(|factor| *factor = (*factor).max(pin.replication_factor as usize))
                .or_insert(pin.replication_factor as usize);
        }
    }
    for root in state
        .publication_repository
        .protected_roots(unix_seconds())
        .map_err(|error| ApiError::internal(error.to_string()))?
    {
        for cid in traverse_reachable(state, root).await? {
            pinned_replication
                .entry(cid)
                .and_modify(|factor| *factor = (*factor).max(state.replication_factor))
                .or_insert(state.replication_factor);
        }
    }

    for stat in state.block_store.list_blocks()? {
        let desired_replication = pinned_replication.get(&stat.cid).copied().unwrap_or(0);
        if desired_replication == 0 {
            continue;
        }
        let local_record_fresh = state
            .network
            .local_provider_records(&stat.cid)?
            .into_iter()
            .any(|record| {
                record.node_id == state.status.node_id
                    && record.expires_at_unix_seconds > unix_seconds() + 12 * 60 * 60
            });
        if !local_record_fresh {
            let local_provider = state.network.local_provider_record(&stat.cid);
            state.network.persist_provider_record(&local_provider)?;
            state
                .network
                .announce_provider_to_peers(&local_provider)
                .await;
        }

        if stat.codec == CODEC_ERASURE_MANIFEST {
            match state.block_store.get(&stat.cid) {
                Ok(block) => match serde_json::from_slice::<ErasureManifest>(&block.payload) {
                    Ok(manifest) => {
                        if let Err(error) =
                            repair_erasure_manifest(state, &candidates, &manifest).await
                        {
                            warn!(?error, cid = %stat.cid, "erasure repair failed");
                        }
                    }
                    Err(error) => {
                        warn!(%error, cid = %stat.cid, "invalid erasure manifest during repair")
                    }
                },
                Err(error) => {
                    warn!(%error, cid = %stat.cid, "could not read erasure manifest during repair")
                }
            }
        }

        let providers = match time::timeout(
            Duration::from_secs(1),
            state.network.find_providers(&stat.cid),
        )
        .await
        {
            Ok(Ok(providers)) => providers,
            Ok(Err(error)) => {
                warn!(%error, cid = %stat.cid, "provider lookup failed during repair");
                state.network.local_provider_records(&stat.cid)?
            }
            Err(_) => {
                warn!(cid = %stat.cid, "provider lookup timed out during repair");
                state.network.local_provider_records(&stat.cid)?
            }
        };
        let mut healthy_provider_node_ids =
            healthy_provider_node_ids(state, &stat.cid, providers).await;
        if healthy_provider_node_ids.len() >= desired_replication {
            continue;
        }

        let block = state.block_store.get(&stat.cid)?;
        let selected = select_replicas(&stat.cid, &candidates, candidates.len());
        for node in selected {
            if node.is_local || healthy_provider_node_ids.contains(&node.node_id) {
                continue;
            }
            let Some(address) = node
                .addresses
                .iter()
                .find_map(|address| address.parse().ok())
            else {
                continue;
            };
            match time::timeout(
                Duration::from_secs(1),
                state
                    .network
                    .block_put_replica(address, stat.codec, block.payload.clone()),
            )
            .await
            {
                Ok(Ok(ack)) => match validate_replica_ack(
                    state,
                    &node.node_id,
                    &stat.cid,
                    stat.codec,
                    block.size,
                    &ack,
                ) {
                    Ok(record) => {
                        healthy_provider_node_ids.push(node.node_id.clone());
                        state.network.announce_provider_to_peers(&record).await;
                    }
                    Err(error) => {
                        warn!(%error.message, node_id = %node.node_id, "repair acknowledgement validation failed")
                    }
                },
                Ok(Err(error)) => {
                    warn!(%error, node_id = %node.node_id, "repair replica write failed")
                }
                Err(_) => warn!(node_id = %node.node_id, "repair replica write timed out"),
            }
            healthy_provider_node_ids.sort();
            healthy_provider_node_ids.dedup();
            if healthy_provider_node_ids.len() >= desired_replication {
                break;
            }
        }
    }
    Ok(())
}

pub(super) async fn repair_erasure_manifest(
    state: &AppState,
    candidates: &[PlacementNode],
    manifest: &ErasureManifest,
) -> Result<(), ApiError> {
    validate_erasure_resource_limits(state, manifest)?;
    let mut missing = Vec::new();
    let mut healthy_by_index = HashMap::new();
    for shard in &manifest.shards {
        let healthy = healthy_providers_for_cid(state, &shard.cid).await;
        if healthy.is_empty() {
            missing.push(shard.index);
        }
        healthy_by_index.insert(shard.index, healthy);
    }

    if !missing.is_empty() {
        let mut reconstructed = reconstruct_erasure_shards(state, manifest).await?;
        for index in missing {
            let shard_payload = reconstructed
                .get_mut(index as usize)
                .and_then(Option::take)
                .ok_or_else(|| ApiError::internal("erasure repair missing reconstructed shard"))?;
            let shard_cid = manifest
                .shards
                .iter()
                .find(|shard| shard.index == index)
                .map(|shard| shard.cid.clone())
                .ok_or_else(|| ApiError::internal("erasure repair missing shard metadata"))?;
            let _permit = state
                .erasure_repair_semaphore
                .acquire()
                .await
                .map_err(|error| ApiError::internal(error.to_string()))?;
            throttle_erasure_repair(state, shard_payload.len()).await;
            store_erasure_shard(
                state,
                candidates,
                shard_cid,
                shard_payload,
                &HashSet::new(),
                &HashSet::new(),
            )
            .await?;
            ERASURE_SHARD_REPAIRS.fetch_add(1, Ordering::Relaxed);
        }
        healthy_by_index.clear();
        for shard in &manifest.shards {
            healthy_by_index.insert(
                shard.index,
                healthy_providers_for_cid(state, &shard.cid).await,
            );
        }
    }

    rebalance_erasure_manifest(state, candidates, manifest, &healthy_by_index).await
}

pub(super) async fn rebalance_erasure_manifest(
    state: &AppState,
    candidates: &[PlacementNode],
    manifest: &ErasureManifest,
    healthy_by_index: &HashMap<u16, Vec<ProviderRecord>>,
) -> Result<(), ApiError> {
    let mut used_nodes = HashSet::new();
    let mut used_constraint_values = HashSet::new();
    let mut shards = manifest.shards.clone();
    shards.sort_by_key(|shard| shard.index);

    for shard in shards {
        let Some(target) = select_erasure_target(
            &shard.cid,
            candidates,
            &used_nodes,
            &used_constraint_values,
            shard.size,
        ) else {
            continue;
        };
        used_nodes.insert(target.node_id.clone());
        used_constraint_values.extend(placement_constraint_values(&target));

        let healthy = healthy_by_index
            .get(&shard.index)
            .cloned()
            .unwrap_or_default();
        if healthy
            .iter()
            .any(|provider| provider.node_id == target.node_id)
        {
            continue;
        }
        if healthy.is_empty() {
            continue;
        }

        let payload = match get_block_resolved(state, &shard.cid).await {
            Ok(block) if block.payload.len() == shard.size as usize => block.payload,
            Ok(block) => {
                warn!(
                    cid = %shard.cid,
                    actual = block.payload.len(),
                    expected = shard.size,
                    "skipping erasure shard rebalance with unexpected shard size"
                );
                continue;
            }
            Err(error) => {
                warn!(?error, cid = %shard.cid, "skipping erasure shard rebalance; shard unavailable");
                continue;
            }
        };
        let _permit = state
            .erasure_repair_semaphore
            .acquire()
            .await
            .map_err(|error| ApiError::internal(error.to_string()))?;
        throttle_erasure_repair(state, payload.len()).await;
        match copy_erasure_shard_to_node(state, &target, &shard.cid, payload).await {
            Ok(()) => {
                ERASURE_SHARD_REBALANCES.fetch_add(1, Ordering::Relaxed);
                info!(
                    cid = %shard.cid,
                    shard_index = shard.index,
                    target_node = %target.node_id,
                    target_failure_domain = %candidate_failure_domain(&target.node_id, candidates),
                    "rebalanced erasure shard to preferred placement target"
                );
            }
            Err(error) => warn!(
                ?error,
                cid = %shard.cid,
                shard_index = shard.index,
                target_node = %target.node_id,
                "erasure shard rebalance copy failed"
            ),
        }
    }
    Ok(())
}

pub(super) async fn throttle_erasure_repair(state: &AppState, bytes: usize) {
    if let Some(bytes_per_second) = state.erasure_repair_bytes_per_second {
        let millis = ((bytes as u128) * 1000).div_ceil(bytes_per_second as u128) as u64;
        if millis > 0 {
            time::sleep(Duration::from_millis(millis)).await;
        }
    }
}

pub(super) async fn healthy_providers_for_cid(state: &AppState, cid: &Cid) -> Vec<ProviderRecord> {
    let providers =
        match time::timeout(Duration::from_secs(1), state.network.find_providers(cid)).await {
            Ok(Ok(providers)) => providers,
            Ok(Err(error)) => {
                warn!(%error, %cid, "erasure shard provider lookup failed");
                state
                    .network
                    .local_provider_records(cid)
                    .unwrap_or_default()
            }
            Err(_) => {
                warn!(%cid, "erasure shard provider lookup timed out");
                state
                    .network
                    .local_provider_records(cid)
                    .unwrap_or_default()
            }
        };
    let mut healthy = Vec::new();
    let mut seen = HashSet::new();
    if state.block_store.get(cid).is_ok() {
        let local = state.network.local_provider_record(cid);
        seen.insert(local.node_id.clone());
        healthy.push(local);
    }
    for provider in providers {
        if !seen.insert(provider.node_id.clone()) {
            continue;
        }
        if provider.node_id == state.status.node_id {
            if state.block_store.get(cid).is_ok() {
                healthy.push(provider);
            }
            continue;
        }
        let mut provider_healthy = false;
        for address in provider
            .addresses
            .iter()
            .filter_map(|address| address.parse().ok())
        {
            if matches!(
                time::timeout(
                    Duration::from_millis(500),
                    state.network.block_has(address, cid)
                )
                .await,
                Ok(Ok(true))
            ) {
                provider_healthy = true;
                break;
            }
        }
        if provider_healthy {
            healthy.push(provider);
        }
    }
    healthy
}

pub(super) async fn has_healthy_provider(state: &AppState, cid: &Cid) -> bool {
    !healthy_providers_for_cid(state, cid).await.is_empty()
}

pub(super) async fn reconstruct_erasure_shards(
    state: &AppState,
    manifest: &ErasureManifest,
) -> Result<Vec<Option<Vec<u8>>>, ApiError> {
    let data_shards = manifest.data_shards as usize;
    let parity_shards = manifest.parity_shards as usize;
    let total_shards = data_shards + parity_shards;
    let shard_size = manifest.shard_size as usize;
    let mut shards = vec![None::<Vec<u8>>; total_shards];
    let mut available = 0usize;
    for shard in &manifest.shards {
        match get_block_resolved(state, &shard.cid).await {
            Ok(block) if block.payload.len() == shard_size => {
                let slot = &mut shards[shard.index as usize];
                if slot.is_none() {
                    *slot = Some(block.payload);
                    available += 1;
                }
            }
            Ok(_) => warn!(cid = %shard.cid, "erasure repair shard size mismatch"),
            Err(error) => warn!(?error, cid = %shard.cid, "erasure repair shard unavailable"),
        }
    }
    if available < data_shards {
        ERASURE_RECONSTRUCTION_FAILURES.fetch_add(1, Ordering::Relaxed);
        return Err(ApiError::internal(
            "not enough erasure shards to repair object",
        ));
    }
    ReedSolomon::new(data_shards, parity_shards)
        .map_err(|error| ApiError::internal(error.to_string()))?
        .reconstruct(&mut shards)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok(shards)
}

pub(super) async fn run_repair(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    run_repair_once(&state).await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}
