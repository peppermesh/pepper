// SPDX-License-Identifier: Apache-2.0

//! Pin, retention, and pin-publication service boundary.

use super::*;

pub(super) async fn ensure_implicit_pin(state: &AppState, root_cid: &Cid) -> Result<(), ApiError> {
    ensure_implicit_pin_with_factor(state, root_cid, state.replication_factor).await
}

pub(super) async fn ensure_implicit_pin_with_factor(
    state: &AppState,
    root_cid: &Cid,
    replication_factor: usize,
) -> Result<(), ApiError> {
    if replication_factor == 0 || replication_factor > u16::MAX as usize {
        return Err(ApiError::bad_request(
            "invalid implicit pin replication factor",
        ));
    }
    if active_pins_for_root(state, root_cid)?
        .iter()
        .any(|pin| pin.owner == state.status.node_id && pin.expires_at_unix_seconds.is_none())
    {
        return Ok(());
    }
    let now = unix_seconds();
    let mut pin = PinRecord {
        pin_id: next_pin_id(),
        root_cid: root_cid.clone(),
        owner: state.status.node_id.clone(),
        replication_factor: replication_factor as u16,
        created_at_unix_seconds: now,
        expires_at_unix_seconds: None,
        status: "active".to_string(),
        signature_hex: String::new(),
    };
    sign_pin(state, &mut pin)?;
    persist_pin(state, &pin)?;
    broadcast_pin(state, &pin).await?;
    Ok(())
}

pub(super) async fn broadcast_pin(state: &AppState, pin: &PinRecord) -> Result<(), ApiError> {
    let json = serde_json::to_string(pin).map_err(ApiError::serde)?;
    let mut failed = Vec::new();
    for peer in state.network.peers().await {
        let mut applied = false;
        for address in peer.addresses {
            let Ok(address) = address.parse() else {
                continue;
            };
            if state.network.apply_pin(address, json.clone()).await.is_ok() {
                applied = true;
                break;
            }
        }
        if !applied {
            failed.push(peer.node_id);
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(ApiError::internal(format!(
            "failed to synchronize pin {} to peers: {}",
            pin.pin_id,
            failed.join(", ")
        )))
    }
}

pub(super) async fn create_pin(
    State(state): State<AppState>,
    Json(request): Json<PinCreateRequest>,
) -> Result<Json<PinStatusResponse>, ApiError> {
    let _guard = state.operation_lock.read().await;
    if request.ttl_seconds.is_some_and(|ttl| ttl <= 0) {
        return Err(ApiError::bad_request(
            "pin ttl_seconds must be greater than zero",
        ));
    }
    let replication_factor = request
        .replication_factor
        .unwrap_or(state.replication_factor as u16);
    if replication_factor == 0 {
        return Err(ApiError::bad_request(
            "pin replication factor must be greater than zero",
        ));
    }
    let reachable = traverse_reachable(&state, request.root_cid.clone()).await?;
    for cid in &reachable {
        let block = get_block_resolved(&state, cid).await?;
        let receipt = put_replicated_block_with_factor(
            &state,
            cid.codec,
            block.payload,
            replication_factor as usize,
        )
        .await?;
        if receipt.replicas_accepted < replication_factor as usize {
            return Err(ApiError::internal(format!(
                "pin durability not met for {cid}: accepted {}, requested {replication_factor}",
                receipt.replicas_accepted
            )));
        }
    }
    let now = unix_seconds();
    let mut pin = PinRecord {
        pin_id: next_pin_id(),
        root_cid: request.root_cid.clone(),
        owner: state.status.node_id.clone(),
        replication_factor,
        created_at_unix_seconds: now,
        expires_at_unix_seconds: request.ttl_seconds.map(|ttl| now.saturating_add(ttl)),
        status: "active".to_string(),
        signature_hex: String::new(),
    };
    sign_pin(&state, &mut pin)?;
    persist_pin(&state, &pin)?;
    broadcast_pin(&state, &pin).await?;
    Ok(Json(PinStatusResponse {
        root_cid: request.root_cid,
        pins: active_pins_for_root(&state, &pin.root_cid)?,
        reachable_count: reachable.len(),
    }))
}

pub(super) async fn pin_status(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> Result<Json<PinStatusResponse>, ApiError> {
    let root_cid = BlockStore::parse_cid(&cid)?;
    let pins = active_pins_for_root(&state, &root_cid)?;
    let reachable_count = if pins.is_empty() {
        0
    } else {
        traverse_reachable(&state, root_cid.clone()).await?.len()
    };
    Ok(Json(PinStatusResponse {
        root_cid,
        pins,
        reachable_count,
    }))
}

pub(super) async fn delete_pin(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> Result<Json<PinStatusResponse>, ApiError> {
    let root_cid = BlockStore::parse_cid(&cid)?;
    let deleted = deactivate_pins_for_root(&state, &root_cid)?;
    for pin in &deleted {
        broadcast_pin(&state, pin).await?;
    }
    let pins = active_pins_for_root(&state, &root_cid)?;
    let reachable_count = if pins.is_empty() {
        0
    } else {
        traverse_reachable(&state, root_cid.clone()).await?.len()
    };
    Ok(Json(PinStatusResponse {
        root_cid,
        pins,
        reachable_count,
    }))
}

pub(super) fn pin_signature_payload(pin: &PinRecord) -> Result<Vec<u8>, ApiError> {
    let mut unsigned = pin.clone();
    unsigned.signature_hex.clear();
    serde_json::to_vec(&unsigned).map_err(ApiError::serde)
}

pub(super) fn sign_pin(state: &AppState, pin: &mut PinRecord) -> Result<(), ApiError> {
    pin.signature_hex = hex::encode(state.identity.sign(&pin_signature_payload(pin)?));
    Ok(())
}

pub(super) fn verify_pin(state: &AppState, pin: &PinRecord) -> Result<(), ApiError> {
    let payload = pin_signature_payload(pin)?;
    let valid = if pin.owner == "local" {
        let signature = hex::decode(&pin.signature_hex)
            .ok()
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok());
        signature.is_some_and(|signature| {
            verify_signature(&state.identity.public_key_bytes(), &payload, &signature)
        })
    } else {
        state
            .network
            .verify_node_signature(&pin.owner, &payload, &pin.signature_hex)
            .is_ok()
    };
    if !valid {
        return Err(ApiError::bad_request("pin signature verification failed"));
    }
    Ok(())
}

pub(super) fn persist_pin(state: &AppState, pin: &PinRecord) -> Result<(), ApiError> {
    verify_pin(state, pin)?;
    if let Some(existing) = state
        .metadata
        .pins()
        .all()
        .map_err(ApiError::metadata)?
        .into_iter()
        .find(|existing| existing.pin_id == pin.pin_id)
    {
        // Continue to distrust metadata loaded from disk before repository-level
        // immutable-field validation.
        verify_pin(state, &existing)?;
    }
    state.metadata.pins().put(pin).map_err(ApiError::metadata)
}

pub(super) fn active_pins_for_root(
    state: &AppState,
    root: &Cid,
) -> Result<Vec<PinRecord>, ApiError> {
    Ok(active_pins(state)?
        .into_iter()
        .filter(|pin| &pin.root_cid == root)
        .collect())
}

pub(super) fn all_pin_records(state: &AppState) -> Result<Vec<PinRecord>, ApiError> {
    let pins = state.metadata.pins().all().map_err(ApiError::metadata)?;
    for pin in &pins {
        verify_pin(state, pin)?;
    }
    Ok(pins)
}

pub(super) fn active_pins(state: &AppState) -> Result<Vec<PinRecord>, ApiError> {
    let now = unix_seconds();
    Ok(all_pin_records(state)?
        .into_iter()
        .filter(|pin| {
            pin.status == "active"
                // Namespace protection is replicated by the namespace consensus
                // log and reconciled independently on every replica. Remote
                // mirrors created by older gossiping nodes are not authoritative
                // and may otherwise retain stale roots indefinitely.
                && (!pin.pin_id.starts_with("namespace-")
                    || pin.owner == state.status.node_id)
                && pin
                    .expires_at_unix_seconds
                    .is_none_or(|expiry| expiry > now)
        })
        .collect())
}

pub(super) fn deactivate_pins_for_root(
    state: &AppState,
    root: &Cid,
) -> Result<Vec<PinRecord>, ApiError> {
    let active = active_pins_for_root(state, root)?;
    let mut pins = active
        .iter()
        .filter(|pin| pin.owner == state.status.node_id || pin.owner == "local")
        .cloned()
        .collect::<Vec<_>>();
    if pins.is_empty() && !active.is_empty() {
        return Err(ApiError::bad_request(
            "pin must be deleted through the node that created it",
        ));
    }
    for pin in &mut pins {
        pin.status = "deleted".to_string();
        sign_pin(state, pin)?;
    }
    state
        .metadata
        .pins()
        .replace(&pins)
        .map_err(ApiError::metadata)?;
    Ok(pins)
}
