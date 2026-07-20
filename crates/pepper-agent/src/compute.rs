// SPDX-License-Identifier: Apache-2.0

//! Compute scheduling, persistence, and Firecracker runtime boundary.

use super::*;

pub(super) async fn submit_compute_job(
    State(state): State<AppState>,
    Json(spec): Json<ComputeJobSpec>,
) -> Result<Json<SubmitComputeResponse>, ApiError> {
    let response = schedule_compute_job(state, next_job_id(), spec).await?;
    Ok(Json(response))
}

pub(super) async fn compute_job_status(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<ComputeJobStatus>, ApiError> {
    let job = load_job(&state, &job_id)?.ok_or_else(|| ApiError::not_found("job not found"))?;
    if job.status == "delegated"
        && let Some(address) = &job.assigned_address
        && let Ok(peer) = address.parse::<SocketAddr>()
    {
        let response = state
            .network
            .compute_status(peer, job_id.clone())
            .await
            .map_err(ApiError::network)?;
        let remote: ComputeJobStatus =
            serde_json::from_str(&response.job_status_json).map_err(ApiError::serde)?;
        if remote.receipt.is_some() {
            verify_compute_receipt(&state, &remote)?;
        }
        if matches!(
            remote.status.as_str(),
            "succeeded" | "failed" | "timed_out" | "canceled"
        ) {
            let mut updated = remote.clone();
            updated.assigned_address = job.assigned_address.clone();
            updated.attempts = job.attempts.clone();
            persist_job(&state, &updated)?;
        }
        return Ok(Json(remote));
    }
    Ok(Json(job))
}

pub(super) async fn compute_job_logs(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<ComputeLogsResponse>, ApiError> {
    let logs = compute_logs_for_job(&state, &job_id).await?;
    Ok(Json(logs))
}

pub(super) async fn cancel_compute_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<ComputeJobStatus>, ApiError> {
    let job = cancel_compute_job_by_id(&state, &job_id).await?;
    Ok(Json(job))
}

async fn schedule_compute_job(
    state: AppState,
    job_id: String,
    spec: ComputeJobSpec,
) -> Result<SubmitComputeResponse, ApiError> {
    if !state.compute_enabled {
        return Err(ApiError::bad_request("compute is disabled"));
    }
    validate_job_spec(&spec).map_err(|error| ApiError::bad_request(error.to_string()))?;
    enforce_compute_limits(&state, &spec)?;
    let mut offers = collect_compute_offers(&state, &spec).await?;
    let rejection_reasons = offers
        .iter()
        .filter(|offer| !offer.accepted)
        .filter_map(|offer| {
            offer
                .rejection_reason
                .as_ref()
                .map(|reason| format!("{}:{reason}", offer.node_id))
        })
        .collect::<Vec<_>>();
    offers.retain(|offer| offer.accepted);
    offers.sort_by(|left, right| {
        right
            .local_input_bytes
            .cmp(&left.local_input_bytes)
            .then_with(|| {
                left.estimated_queue_delay_seconds
                    .cmp(&right.estimated_queue_delay_seconds)
            })
            .then_with(|| right.available_parallelism.cmp(&left.available_parallelism))
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    if offers.is_empty() {
        let detail = if rejection_reasons.is_empty() {
            "no compute node accepted the job".to_string()
        } else {
            format!(
                "no compute node accepted the job: {}",
                rejection_reasons.join(", ")
            )
        };
        return Err(ApiError::bad_request(detail));
    }

    let mut attempts = Vec::new();
    for offer in offers {
        let started = unix_seconds();
        if offer.node_id == state.status.node_id {
            let mut job = new_compute_job(
                job_id.clone(),
                spec.clone(),
                "queued",
                Some(offer.node_id.clone()),
                None,
            );
            job.attempts = attempts;
            job.attempts.push(ComputeAttempt {
                node_id: offer.node_id.clone(),
                address: None,
                status: "accepted".to_string(),
                error: None,
                started_at_unix_seconds: started,
                finished_at_unix_seconds: None,
                events: Vec::new(),
            });
            persist_job(&state, &job)?;
            if let Err(error) = spawn_compute_job(state.clone(), job_id.clone()) {
                job.status = "failed".to_string();
                job.finished_at_unix_seconds = Some(unix_seconds());
                job.error = Some(error.message.clone());
                persist_job(&state, &job)?;
                return Err(error);
            }
            COMPUTE_SCHEDULED_LOCAL.fetch_add(1, Ordering::Relaxed);
            return Ok(SubmitComputeResponse {
                job_id,
                status: "queued".to_string(),
                assigned_node_id: Some(offer.node_id),
            });
        }

        let Some(address) = offer.address.clone() else {
            continue;
        };
        let peer = match address.parse::<SocketAddr>() {
            Ok(peer) => peer,
            Err(error) => {
                attempts.push(ComputeAttempt {
                    node_id: offer.node_id,
                    address: Some(address),
                    status: "failed".to_string(),
                    error: Some(error.to_string()),
                    started_at_unix_seconds: started,
                    finished_at_unix_seconds: Some(unix_seconds()),
                    events: Vec::new(),
                });
                continue;
            }
        };
        let spec_json = serde_json::to_string(&spec).map_err(ApiError::serde)?;
        match state
            .network
            .compute_submit(peer, job_id.clone(), spec_json)
            .await
        {
            Ok(response) => {
                let remote: ComputeJobStatus =
                    serde_json::from_str(&response.job_status_json).map_err(ApiError::serde)?;
                let mut proxy = new_compute_job(
                    job_id.clone(),
                    spec.clone(),
                    "delegated",
                    Some(
                        remote
                            .assigned_node_id
                            .clone()
                            .unwrap_or(offer.node_id.clone()),
                    ),
                    Some(address.clone()),
                );
                proxy.attempts = attempts;
                proxy.attempts.push(ComputeAttempt {
                    node_id: offer.node_id.clone(),
                    address: Some(address),
                    status: "accepted".to_string(),
                    error: None,
                    started_at_unix_seconds: started,
                    finished_at_unix_seconds: None,
                    events: Vec::new(),
                });
                persist_job(&state, &proxy)?;
                COMPUTE_SCHEDULED_REMOTE.fetch_add(1, Ordering::Relaxed);
                return Ok(SubmitComputeResponse {
                    job_id,
                    status: remote.status,
                    assigned_node_id: Some(offer.node_id),
                });
            }
            Err(error) => {
                COMPUTE_SCHEDULE_RETRIES.fetch_add(1, Ordering::Relaxed);
                attempts.push(ComputeAttempt {
                    node_id: offer.node_id,
                    address: Some(address),
                    status: "failed".to_string(),
                    error: Some(error.to_string()),
                    started_at_unix_seconds: started,
                    finished_at_unix_seconds: Some(unix_seconds()),
                    events: Vec::new(),
                })
            }
        }
    }

    Err(ApiError::bad_request("all compute submit attempts failed"))
}

fn verify_compute_receipt(state: &AppState, job: &ComputeJobStatus) -> Result<(), ApiError> {
    let receipt = job
        .receipt
        .as_ref()
        .ok_or_else(|| ApiError::bad_request("compute receipt is missing"))?;
    if receipt.job_id != job.job_id
        || receipt.status != job.status
        || receipt.node_id
            != job
                .assigned_node_id
                .clone()
                .unwrap_or_else(|| receipt.node_id.clone())
    {
        return Err(ApiError::bad_request(
            "compute receipt does not match job status",
        ));
    }
    let mut unsigned = receipt.clone();
    let signature = std::mem::take(&mut unsigned.signature_hex);
    let payload = serde_json::to_vec(&unsigned).map_err(ApiError::serde)?;
    state
        .network
        .verify_node_signature(&receipt.node_id, &payload, &signature)
        .map_err(ApiError::network)
}

pub(super) fn enforce_size_limit(
    limit: Option<u64>,
    actual: u64,
    name: &str,
) -> Result<(), ApiError> {
    if let Some(limit) = limit
        && actual > limit
    {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::PayloadTooLarge,
            format!("{name} size {actual} exceeds configured limit {limit}"),
        ));
    }
    Ok(())
}

fn enforce_compute_limits(state: &AppState, spec: &ComputeJobSpec) -> Result<(), ApiError> {
    if let Some(rootfs_cid) = &spec.rootfs_cid
        && !state.firecracker_allow_untrusted_rootfs
        && !state.firecracker_allowed_rootfs_cids.contains(rootfs_cid)
    {
        return Err(ApiError::bad_request(
            "rootfs_cid is not in compute.firecracker_allowed_rootfs_cids",
        ));
    }
    if let Some(resources) = &spec.resources {
        if resources
            .memory_mib
            .is_some_and(|value| value > state.firecracker_memory_mib as u64)
        {
            return Err(ApiError::bad_request(format!(
                "compute memory exceeds node limit of {} MiB",
                state.firecracker_memory_mib
            )));
        }
        let cpu_limit = state.firecracker_vcpu_count as u64 * 1000;
        if resources.cpu_millis.is_some_and(|value| value > cpu_limit) {
            return Err(ApiError::bad_request(format!(
                "compute CPU exceeds node limit of {cpu_limit} millicores"
            )));
        }
        if resources
            .max_input_bytes
            .is_some_and(|value| value > state.firecracker_max_input_bytes)
        {
            return Err(ApiError::bad_request(
                "compute input limit exceeds node policy",
            ));
        }
        if resources
            .max_output_bytes
            .is_some_and(|value| value > state.firecracker_max_output_bytes)
        {
            return Err(ApiError::bad_request(
                "compute output limit exceeds node policy",
            ));
        }
    }
    if let Some(limit) = state.max_compute_timeout_seconds {
        let requested = spec
            .resources
            .as_ref()
            .and_then(|resources| resources.timeout_seconds)
            .unwrap_or(600);
        if requested > limit {
            return Err(ApiError::bad_request(format!(
                "compute timeout {requested}s exceeds configured limit {limit}s"
            )));
        }
    }
    Ok(())
}

pub(super) fn new_compute_job(
    job_id: String,
    spec: ComputeJobSpec,
    status: &str,
    assigned_node_id: Option<String>,
    assigned_address: Option<String>,
) -> ComputeJobStatus {
    ComputeJobStatus {
        job_id,
        status: status.to_string(),
        spec,
        created_at_unix_seconds: unix_seconds(),
        started_at_unix_seconds: None,
        finished_at_unix_seconds: None,
        exit_code: None,
        stdout_cid: None,
        stderr_cid: None,
        output_root_cid: None,
        error: None,
        receipt: None,
        firecracker_error_class: None,
        cancel_requested_at_unix_seconds: None,
        cancel_delivered_at_unix_seconds: None,
        cancel_acknowledged_at_unix_seconds: None,
        guest_exited_after_cancel: false,
        vm_killed_after_cancel: false,
        assigned_node_id,
        assigned_address,
        attempts: Vec::new(),
    }
}

pub(super) fn recover_compute_jobs(state: &AppState) -> Result<(), ApiError> {
    let read_txn = state
        .metadata
        .database()
        .begin_read()
        .map_err(ApiError::redb_transaction)?;
    let table = match read_txn.open_table(JOBS) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
        Err(error) => return Err(ApiError::redb_table(error)),
    };
    let mut queued = Vec::new();
    let mut interrupted = Vec::new();
    for row in table.iter().map_err(ApiError::redb_storage)? {
        let (_, value) = row.map_err(ApiError::redb_storage)?;
        let job: ComputeJobStatus =
            serde_json::from_slice(value.value()).map_err(ApiError::serde)?;
        match job.status.as_str() {
            "queued" => queued.push(job.job_id),
            "running" => interrupted.push(job),
            _ => {}
        }
    }
    drop(table);
    drop(read_txn);
    for mut job in interrupted {
        if validate_job_id(&job.job_id).is_ok() {
            let _ = std::fs::remove_dir_all(state.compute_work_dir.join(&job.job_id));
        }
        job.status = "failed".to_string();
        job.finished_at_unix_seconds = Some(unix_seconds());
        job.error = Some("agent restarted while job was running".to_string());
        persist_job(state, &job)?;
    }
    for job_id in queued {
        if let Err(error) = spawn_compute_job(state.clone(), job_id.clone())
            && let Some(mut job) = load_job(state, &job_id)?
        {
            job.status = "failed".to_string();
            job.finished_at_unix_seconds = Some(unix_seconds());
            job.error = Some(error.message);
            persist_job(state, &job)?;
        }
    }
    Ok(())
}

pub(super) fn spawn_compute_job(state: AppState, job_id: String) -> Result<(), ApiError> {
    let queue_permit = state
        .compute_queue_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::bad_request("compute queue is full"))?;
    let (start_tx, start_rx) = oneshot::channel();
    let task_state = state.clone();
    let task_job_id = job_id.clone();
    let handle = tokio::spawn(async move {
        let _queue_permit = queue_permit;
        if start_rx.await.is_err() {
            return;
        }
        if let Err(error) = execute_compute_job(task_state.clone(), task_job_id.clone()).await
            && let Ok(Some(mut failed)) = load_job(&task_state, &task_job_id)
            && failed.status != "canceled"
        {
            failed.status = "failed".to_string();
            failed.finished_at_unix_seconds = Some(unix_seconds());
            failed.error = Some(error.message);
            let _ = persist_job(&task_state, &failed);
        }
        if let Ok(mut tasks) = task_state.compute_tasks.lock() {
            tasks.remove(&task_job_id);
        }
    });
    let abort_handle = handle.abort_handle();
    {
        let mut tasks = state
            .compute_tasks
            .lock()
            .map_err(|_| ApiError::internal("compute task map lock poisoned"))?;
        if tasks.insert(job_id, abort_handle).is_some() {
            handle.abort();
            return Err(ApiError::bad_request("compute job is already running"));
        }
    }
    let _ = start_tx.send(());
    Ok(())
}

async fn collect_compute_offers(
    state: &AppState,
    spec: &ComputeJobSpec,
) -> Result<Vec<ComputeOffer>, ApiError> {
    let mut offers = Vec::new();
    offers.push(local_compute_offer(state, spec, None)?);

    let mut candidates = Vec::new();
    for input in &spec.inputs {
        if let Ok(providers) = state.network.find_providers(&input.cid).await {
            for provider in providers {
                if provider.node_id == state.status.node_id {
                    continue;
                }
                for address in provider.addresses {
                    candidates.push((provider.node_id.clone(), address));
                }
            }
        }
    }
    for peer in state.network.peers().await {
        for address in peer.addresses {
            candidates.push((peer.node_id.clone(), address));
        }
    }
    candidates.sort();
    candidates.dedup();

    let spec_json = serde_json::to_string(spec).map_err(ApiError::serde)?;
    for (node_id, address) in candidates {
        let Ok(peer) = address.parse::<SocketAddr>() else {
            continue;
        };
        match state.network.compute_offer(peer, spec_json.clone()).await {
            Ok(response) => offers.push(ComputeOffer {
                accepted: response.accepted,
                node_id: if response.node_id.is_empty() {
                    node_id
                } else {
                    response.node_id
                },
                address: Some(address),
                estimated_queue_delay_seconds: response.estimated_queue_delay_seconds,
                local_input_bytes: response.local_input_bytes,
                total_input_bytes: response.total_input_bytes,
                available_parallelism: response.available_parallelism,
                rejection_reason: if response.rejection_reason.is_empty() {
                    None
                } else {
                    Some(response.rejection_reason)
                },
            }),
            Err(error) => warn!(%peer, %error, "compute offer request failed"),
        }
    }
    Ok(offers)
}

pub(super) fn local_compute_offer(
    state: &AppState,
    spec: &ComputeJobSpec,
    address: Option<String>,
) -> Result<ComputeOffer, ApiError> {
    let queue_available = state.compute_queue_slots.available_permits();
    let rejection_reason = if !state.compute_enabled {
        Some("compute is disabled".to_string())
    } else if queue_available == 0 {
        Some("compute queue is full".to_string())
    } else if let Err(error) = validate_job_spec(spec) {
        Some(error.to_string())
    } else if let Err(error) = enforce_compute_limits(state, spec) {
        Some(error.message)
    } else if spec.runtime.as_deref().unwrap_or(&state.compute_runtime) == "firecracker"
        && spec.rootfs_cid.is_none()
    {
        Some("firecracker compute jobs must set rootfs_cid".to_string())
    } else if spec.runtime.as_deref().unwrap_or(&state.compute_runtime) == "firecracker"
        && let Err(error) = ensure_firecracker_available(state)
    {
        Some(error.message)
    } else {
        None
    };
    let (local_input_bytes, total_input_bytes) = estimate_job_input_locality(state, spec);
    let available = state.compute_semaphore.available_permits() as u32;
    Ok(ComputeOffer {
        accepted: rejection_reason.is_none(),
        node_id: state.status.node_id.clone(),
        address,
        estimated_queue_delay_seconds: if available > 0 { 0 } else { 1 },
        local_input_bytes,
        total_input_bytes,
        available_parallelism: available,
        rejection_reason,
    })
}

fn estimate_job_input_locality(state: &AppState, spec: &ComputeJobSpec) -> (u64, u64) {
    let mut local = 0u64;
    let mut total = 0u64;
    let mut visited = HashSet::new();
    if let Some(rootfs_cid) = &spec.rootfs_cid {
        let (rootfs_local, rootfs_total) =
            estimate_cid_locality(state, rootfs_cid, &mut visited, 128);
        local = local.saturating_add(rootfs_local);
        total = total.saturating_add(rootfs_total);
    }
    for input in &spec.inputs {
        let (input_local, input_total) =
            estimate_cid_locality(state, &input.cid, &mut visited, 128);
        local = local.saturating_add(input_local);
        total = total.saturating_add(input_total);
    }
    (local, total)
}

fn estimate_cid_locality(
    state: &AppState,
    cid: &Cid,
    visited: &mut HashSet<Cid>,
    remaining: usize,
) -> (u64, u64) {
    if remaining == 0 || visited.len() >= 4096 || !visited.insert(cid.clone()) {
        return (0, 0);
    }
    let has_local = state.block_store.has(cid).unwrap_or(false);
    match cid.codec {
        CODEC_RAW => {
            let size = state
                .block_store
                .stat(cid)
                .map(|stat| stat.size)
                .unwrap_or(0);
            (if has_local { size } else { 0 }, size)
        }
        CODEC_OBJECT_MANIFEST if has_local => {
            let Ok(block) = state.block_store.get(cid) else {
                return (0, 0);
            };
            if state
                .dag_registry
                .links(cid.codec, &block.payload, &TraversalLimits::default())
                .is_err()
            {
                return (0, 0);
            }
            let Ok(manifest) = serde_json::from_slice::<ObjectManifest>(&block.payload) else {
                return (0, 0);
            };
            let mut local = 0u64;
            let mut total = manifest.size;
            for chunk in manifest.chunks {
                if state.block_store.has(&chunk.cid).unwrap_or(false) {
                    local = local.saturating_add(chunk.size);
                }
            }
            if total == 0 {
                total = local;
            }
            (local, total)
        }
        CODEC_ERASURE_MANIFEST if has_local => {
            let Ok(block) = state.block_store.get(cid) else {
                return (0, 0);
            };
            if state
                .dag_registry
                .links(cid.codec, &block.payload, &TraversalLimits::default())
                .is_err()
            {
                return (0, 0);
            }
            let Ok(manifest) = serde_json::from_slice::<ErasureManifest>(&block.payload) else {
                return (0, 0);
            };
            if manifest.validate().is_err() {
                return (0, 0);
            }
            let local = manifest
                .stripes
                .iter()
                .map(|stripe| {
                    let local_shards = stripe
                        .shards
                        .iter()
                        .filter(|shard| state.block_store.has(&shard.cid).unwrap_or(false))
                        .count();
                    if local_shards >= manifest.data_shards as usize {
                        stripe.size
                    } else {
                        (local_shards as u64)
                            .saturating_mul(stripe.shard_size)
                            .min(stripe.size)
                    }
                })
                .sum();
            (local, manifest.size)
        }
        CODEC_DIR_MANIFEST if has_local => {
            let Ok(block) = state.block_store.get(cid) else {
                return (0, 0);
            };
            if state
                .dag_registry
                .links(cid.codec, &block.payload, &TraversalLimits::default())
                .is_err()
            {
                return (0, 0);
            }
            let Ok(manifest) = serde_json::from_slice::<DirManifest>(&block.payload) else {
                return (0, 0);
            };
            let mut local = 0u64;
            let mut total = 0u64;
            for entry in manifest.entries {
                if let Some(child) = entry.cid {
                    let (child_local, child_total) =
                        estimate_cid_locality(state, &child, visited, remaining.saturating_sub(1));
                    local = local.saturating_add(child_local);
                    total = total.saturating_add(child_total.max(entry.size.unwrap_or(0)));
                }
            }
            (local, total)
        }
        _ => (0, 0),
    }
}

fn record_attempt_event(job: &mut ComputeJobStatus, event: impl Into<String>) {
    const MAX_EVENTS: usize = 256;
    const MAX_EVENT_BYTES: usize = 1024;
    if let Some(attempt) = job.attempts.last_mut() {
        if attempt.events.len() >= MAX_EVENTS {
            return;
        }
        let mut event = event.into();
        event.truncate(
            event
                .char_indices()
                .take_while(|(index, _)| *index < MAX_EVENT_BYTES)
                .last()
                .map(|(index, ch)| index + ch.len_utf8())
                .unwrap_or(0),
        );
        attempt.events.push(format!("{}:{event}", unix_seconds()));
    }
}

pub(super) async fn cancel_compute_job_by_id(
    state: &AppState,
    job_id: &str,
) -> Result<ComputeJobStatus, ApiError> {
    let mut job = load_job(state, job_id)?.ok_or_else(|| ApiError::not_found("job not found"))?;
    if job.status == "delegated"
        && let Some(address) = &job.assigned_address
        && let Ok(peer) = address.parse::<SocketAddr>()
    {
        let response = state
            .network
            .compute_cancel(peer, job_id.to_string())
            .await
            .map_err(ApiError::network)?;
        let remote: ComputeJobStatus =
            serde_json::from_str(&response.job_status_json).map_err(ApiError::serde)?;
        job.status = remote.status.clone();
        job.finished_at_unix_seconds = remote.finished_at_unix_seconds;
        job.error = remote.error.clone();
        persist_job(state, &job)?;
        return Ok(remote);
    }

    let _state_guard = state.compute_state_lock.lock().await;
    job = load_job(state, job_id)?.ok_or_else(|| ApiError::not_found("job not found"))?;
    match job.status.as_str() {
        "queued" => {
            job.status = "canceled".to_string();
            job.finished_at_unix_seconds = Some(unix_seconds());
            job.error = Some("job canceled before execution".to_string());
            if let Some(attempt) = job.attempts.last_mut()
                && attempt.finished_at_unix_seconds.is_none()
            {
                attempt.status = "canceled".to_string();
                attempt.finished_at_unix_seconds = Some(unix_seconds());
            }
            persist_job(state, &job)?;
            if let Ok(mut tasks) = state.compute_tasks.lock()
                && let Some(handle) = tasks.remove(job_id)
            {
                handle.abort();
            }
            Ok(job)
        }
        "running" => {
            let mut cancel_detail = "running job canceled".to_string();
            if job
                .spec
                .runtime
                .as_deref()
                .unwrap_or(&state.compute_runtime)
                == "firecracker"
            {
                let requested_at = unix_seconds();
                job.cancel_requested_at_unix_seconds = Some(requested_at);
                record_attempt_event(&mut job, "cancel_requested");
                match send_firecracker_cancel(state, &job).await {
                    Ok(outcome) => {
                        if outcome.delivered {
                            job.cancel_delivered_at_unix_seconds = Some(unix_seconds());
                        }
                        if outcome.acknowledged {
                            job.cancel_acknowledged_at_unix_seconds = Some(unix_seconds());
                        }
                        for event in outcome.events() {
                            record_attempt_event(&mut job, event);
                        }
                        cancel_detail = outcome.description();
                    }
                    Err(error) => {
                        record_attempt_event(
                            &mut job,
                            format!("cancel_vsock_failed:{}", error.message),
                        );
                        warn!(?error, job_id = %job.job_id, "firecracker vsock cancel request failed; falling back to VM process-group termination");
                        cancel_detail = format!(
                            "firecracker cancel fell back to VM termination after vsock error: {}",
                            error.message
                        );
                    }
                }
                time::sleep(Duration::from_secs(2)).await;
                let current = load_job(state, job_id)?;
                if let Some(current) = current
                    && matches!(
                        current.status.as_str(),
                        "succeeded" | "failed" | "timed_out" | "canceled"
                    )
                {
                    return Ok(current);
                }
                let guest_finished = false;
                job.guest_exited_after_cancel = guest_finished;
                job.vm_killed_after_cancel = !guest_finished;
                record_attempt_event(
                    &mut job,
                    if guest_finished {
                        "guest_exited_after_cancel"
                    } else {
                        "vm_killed_after_cancel"
                    },
                );
            }
            if let Ok(mut tasks) = state.compute_tasks.lock()
                && let Some(handle) = tasks.remove(job_id)
            {
                handle.abort();
            }
            job.status = "canceled".to_string();
            job.finished_at_unix_seconds = Some(unix_seconds());
            job.error = Some(cancel_detail);
            if let Some(attempt) = job.attempts.last_mut()
                && attempt.finished_at_unix_seconds.is_none()
            {
                attempt.status = "canceled".to_string();
                attempt.finished_at_unix_seconds = Some(unix_seconds());
            }
            persist_job(state, &job)?;
            Ok(job)
        }
        "canceled" | "succeeded" | "failed" | "timed_out" => Ok(job),
        _ => Err(ApiError::bad_request(
            "job cannot be canceled in current state",
        )),
    }
}

pub(super) async fn compute_logs_for_job(
    state: &AppState,
    job_id: &str,
) -> Result<ComputeLogsResponse, ApiError> {
    let job = load_job(state, job_id)?.ok_or_else(|| ApiError::not_found("job not found"))?;
    if job.status == "delegated"
        && let Some(address) = &job.assigned_address
        && let Ok(peer) = address.parse::<SocketAddr>()
    {
        let response = state
            .network
            .compute_logs(peer, job_id.to_string())
            .await
            .map_err(ApiError::network)?;
        return serde_json::from_str(&response.logs_json).map_err(ApiError::serde);
    }
    let stdout = if let Some(cid) = &job.stdout_cid {
        String::from_utf8_lossy(&get_block_resolved(state, cid).await?.payload).to_string()
    } else {
        String::new()
    };
    let stderr = if let Some(cid) = &job.stderr_cid {
        String::from_utf8_lossy(&get_block_resolved(state, cid).await?.payload).to_string()
    } else {
        String::new()
    };
    Ok(ComputeLogsResponse {
        job_id: job_id.to_string(),
        stdout,
        stderr,
    })
}

async fn execute_compute_job(state: AppState, job_id: String) -> Result<(), ApiError> {
    let _permit = state
        .compute_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let _guard = state.operation_lock.read().await;
    let job = {
        let _state_guard = state.compute_state_lock.lock().await;
        let mut job =
            load_job(&state, &job_id)?.ok_or_else(|| ApiError::not_found("job not found"))?;
        if job.status == "canceled" {
            return Ok(());
        }
        job.status = "running".to_string();
        job.started_at_unix_seconds = Some(unix_seconds());
        persist_job(&state, &job)?;
        job
    };

    let runtime = job
        .spec
        .runtime
        .clone()
        .unwrap_or_else(|| state.compute_runtime.clone());
    if runtime != "firecracker" {
        return Err(ApiError::bad_request(format!(
            "unsupported compute runtime {runtime}; only firecracker is supported"
        )));
    }
    execute_firecracker_job(state.clone(), job).await
}

async fn execute_firecracker_job(
    state: AppState,
    mut job: ComputeJobStatus,
) -> Result<(), ApiError> {
    ensure_firecracker_available(&state)?;
    let rootfs_cid = job
        .spec
        .rootfs_cid
        .clone()
        .ok_or_else(|| ApiError::bad_request("firecracker compute jobs must set rootfs_cid"))?;
    let job_id = job.job_id.clone();
    validate_job_id(&job_id)?;
    let work_dir = state.compute_work_dir.join(&job_id);
    let root_dir = work_dir.join("firecracker-root");
    let input_dir = work_dir.join("firecracker-input");
    let extract_dir = work_dir.join("firecracker-extract");
    let rootfs = work_dir.join("rootfs.ext4");
    let inputfs = work_dir.join("inputs.ext4");
    let outputfs = work_dir.join("outputs.ext4");
    let vsock_path = work_dir.join("vsock.sock");
    let guest_cid_guard = allocate_firecracker_guest_cid(&state, &job_id)?;
    let guest_cid = guest_cid_guard.cid;
    let config_path = work_dir.join("firecracker.json");
    std::fs::create_dir(&work_dir).map_err(|error| {
        ApiError::internal(format!(
            "failed to create fresh compute work directory {}: {error}",
            work_dir.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&work_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| ApiError::internal(error.to_string()))?;
    }
    let _cleanup_guard = FirecrackerCleanupGuard {
        work_dir: work_dir.clone(),
        root_dir: root_dir.clone(),
        input_dir: input_dir.clone(),
        rootfs: rootfs.clone(),
        inputfs: Some(inputfs.clone()),
        outputfs: Some(outputfs.clone()),
        vsock_path: Some(vsock_path.clone()),
        config_path: config_path.clone(),
        jail_dir: state.firecracker_enable_jailer.then(|| {
            state
                .firecracker_jailer_chroot_base
                .join("firecracker")
                .join(safe_jailer_id(&job_id))
        }),
    };
    std::fs::create_dir_all(&root_dir).map_err(|error| ApiError::internal(error.to_string()))?;
    std::fs::create_dir_all(&input_dir).map_err(|error| ApiError::internal(error.to_string()))?;
    std::fs::create_dir_all(root_dir.join("pepper_runtime"))
        .map_err(|error| ApiError::internal(error.to_string()))?;

    let input_limit = job
        .spec
        .resources
        .as_ref()
        .and_then(|resources| resources.max_input_bytes)
        .unwrap_or(state.firecracker_max_input_bytes);
    let mut declared_input_bytes = 0u64;
    for input in &job.spec.inputs {
        declared_input_bytes = declared_input_bytes
            .checked_add(logical_cid_size(&state, &input.cid).await?)
            .ok_or_else(|| ApiError::bad_request("compute input size overflow"))?;
        enforce_size_limit(Some(input_limit), declared_input_bytes, "compute inputs")?;
    }
    let declared_rootfs_bytes = logical_cid_size(&state, &rootfs_cid).await?;
    enforce_size_limit(
        Some(input_limit),
        declared_rootfs_bytes,
        "firecracker rootfs",
    )?;

    for input in &job.spec.inputs {
        let target = safe_join(&input_dir, &input.mount)?;
        materialize_cid_to_path(&state, &input.cid, &target).await?;
    }
    tokio::task::block_in_place(|| {
        enforce_firecracker_input_limit(&state, &job, &input_dir)?;
        create_ext4_rootfs(&input_dir, &inputfs)
    })?;
    let output_limit = firecracker_output_limit(&state, &job);
    tokio::task::block_in_place(|| create_empty_ext4_image(&outputfs, output_limit))?;
    write_firecracker_mount_script(&root_dir, &job.spec.inputs)?;

    let command_line = job
        .spec
        .command
        .iter()
        .map(|part| shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ");
    write_executable(
        &root_dir.join("job.sh"),
        format!("#!/bin/sh\nexport PATH=/bin:/sbin:/usr/bin:/usr/sbin\ncd /\n{command_line}\n")
            .as_bytes(),
    )?;
    write_executable(&root_dir.join("init"), firecracker_guest_init_script())?;
    write_bytes(&root_dir.join("pepper_job_id"), job_id.as_bytes())?;

    let rootfs_bytes = rootfs_image_bytes(&state, &rootfs_cid).await?;
    let rootfs_limit = job
        .spec
        .resources
        .as_ref()
        .and_then(|resources| resources.max_input_bytes)
        .unwrap_or(state.firecracker_max_input_bytes);
    enforce_size_limit(
        Some(rootfs_limit),
        rootfs_bytes.len() as u64,
        "firecracker rootfs",
    )?;
    std::fs::write(&rootfs, rootfs_bytes).map_err(|error| ApiError::internal(error.to_string()))?;
    if let Err(error) = tokio::task::block_in_place(|| validate_firecracker_rootfs_image(&rootfs)) {
        FIRECRACKER_ROOTFS_VALIDATION_FAILURES.fetch_add(1, Ordering::Relaxed);
        job.firecracker_error_class = Some("rootfs_validation".to_string());
        job.status = "failed".to_string();
        job.finished_at_unix_seconds = Some(unix_seconds());
        job.error = Some(error.message.clone());
        persist_job(&state, &job)?;
        return Err(error);
    }
    tokio::task::block_in_place(|| {
        debugfs_write_tree(&rootfs, &root_dir)?;
        debugfs_runtime_symlinks(&rootfs)
    })?;
    let kernel = state
        .firecracker_kernel_image
        .clone()
        .unwrap_or_else(default_firecracker_kernel_image);
    let config_kernel_path = if state.firecracker_enable_jailer {
        PathBuf::from("/vmlinux")
    } else {
        kernel.clone()
    };
    let config_rootfs_path = if state.firecracker_enable_jailer {
        PathBuf::from("/rootfs.ext4")
    } else {
        rootfs.clone()
    };
    let config_inputfs_path = if state.firecracker_enable_jailer {
        PathBuf::from("/inputs.ext4")
    } else {
        inputfs.clone()
    };
    let config_outputfs_path = if state.firecracker_enable_jailer {
        PathBuf::from("/outputs.ext4")
    } else {
        outputfs.clone()
    };
    let config_vsock_path = if state.firecracker_enable_jailer {
        PathBuf::from("/vsock.sock")
    } else {
        vsock_path.clone()
    };
    let vm_memory_mib = job
        .spec
        .resources
        .as_ref()
        .and_then(|resources| resources.memory_mib)
        .unwrap_or(state.firecracker_memory_mib as u64)
        .min(u32::MAX as u64) as u32;
    let firecracker_config = serde_json::json!({
        "boot-source": {
            "kernel_image_path": config_kernel_path,
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off nomodules random.trust_cpu=on root=/dev/vda ro init=/init"
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": config_rootfs_path,
                "is_root_device": true,
                "is_read_only": true
            },
            {
                "drive_id": "inputs",
                "path_on_host": config_inputfs_path,
                "is_root_device": false,
                "is_read_only": true
            },
            {
                "drive_id": "outputs",
                "path_on_host": config_outputfs_path,
                "is_root_device": false,
                "is_read_only": false
            }
        ],
        "machine-config": {
            "vcpu_count": state.firecracker_vcpu_count,
            "mem_size_mib": vm_memory_mib,
            "smt": false,
            "track_dirty_pages": false
        },
        "vsock": {
            "guest_cid": guest_cid,
            "uds_path": config_vsock_path
        }
    });
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&firecracker_config).map_err(ApiError::serde)?,
    )
    .map_err(|error| ApiError::internal(error.to_string()))?;

    let timeout = Duration::from_secs(
        job.spec
            .resources
            .as_ref()
            .and_then(|resources| resources.timeout_seconds)
            .unwrap_or(600),
    );
    let firecracker_paths = FirecrackerRuntimePaths {
        rootfs: &rootfs,
        inputfs: &inputfs,
        outputfs: &outputfs,
        vsock_path: &vsock_path,
        kernel: &kernel,
        config_path: &config_path,
    };
    let firecracker_command = prepare_firecracker_command(&state, &job_id, &firecracker_paths)?;
    let mut firecracker = firecracker_command;
    FIRECRACKER_VM_STARTS.fetch_add(1, Ordering::Relaxed);
    let child = firecracker.spawn().map_err(|error| {
        FIRECRACKER_VM_FAILURES.fetch_add(1, Ordering::Relaxed);
        job.firecracker_error_class = Some("vm_start".to_string());
        job.status = "failed".to_string();
        job.finished_at_unix_seconds = Some(unix_seconds());
        job.error = Some(error.to_string());
        let _ = persist_job(&state, &job);
        ApiError::internal(error.to_string())
    })?;
    let mut process_guard = ProcessGroupGuard::new(child.id());
    let _cgroup_guard = apply_firecracker_cgroup(&state, &job, child.id())?;
    let host_vsock_path = firecracker_host_vsock_path(&state, &job_id, &vsock_path);
    let poll_handle = spawn_firecracker_control_stream(
        state.clone(),
        job_id.clone(),
        host_vsock_path,
        work_dir.clone(),
        timeout,
    );
    let output = match time::timeout(timeout, child.wait_with_output()).await {
        Ok(result) => result.map_err(|error| ApiError::internal(error.to_string()))?,
        Err(_) => {
            job.status = "timed_out".to_string();
            job.firecracker_error_class = Some("timeout".to_string());
            job.finished_at_unix_seconds = Some(unix_seconds());
            job.error = Some("firecracker job timed out".to_string());
            merge_current_attempt_events(&state, &mut job)?;
            persist_job(&state, &job)?;
            FIRECRACKER_VM_FAILURES.fetch_add(1, Ordering::Relaxed);
            FIRECRACKER_HEARTBEAT_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            poll_handle.abort();
            process_guard.terminate();
            cleanup_firecracker_temp(
                &root_dir,
                &input_dir,
                &rootfs,
                Some(&inputfs),
                Some(&outputfs),
                Some(&vsock_path),
                &config_path,
            );
            return Ok(());
        }
    };
    poll_handle.abort();
    process_guard.disarm();

    let runtime_outputfs = firecracker_runtime_outputfs(&state, &job_id, &outputfs);
    std::fs::create_dir_all(&extract_dir).map_err(|error| ApiError::internal(error.to_string()))?;
    let stdout_bytes = tokio::task::block_in_place(|| {
        debugfs_dump(&runtime_outputfs, "/fc_stdout", 16 * 1024 * 1024).unwrap_or_else(|_| {
            std::fs::read(work_dir.join("vsock_stdout.log"))
                .unwrap_or_else(|_| output.stdout.clone())
        })
    });
    let stderr_bytes = tokio::task::block_in_place(|| {
        debugfs_dump(&runtime_outputfs, "/fc_stderr", 16 * 1024 * 1024).unwrap_or_else(|_| {
            std::fs::read(work_dir.join("vsock_stderr.log"))
                .unwrap_or_else(|_| output.stderr.clone())
        })
    });
    let exit_code =
        tokio::task::block_in_place(|| debugfs_dump(&runtime_outputfs, "/exit_code", 64))
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|text| text.trim().parse::<i32>().ok())
            .unwrap_or_else(|| output.status.code().unwrap_or(1));
    if let Err(error) =
        tokio::task::block_in_place(|| debugfs_rdump(&runtime_outputfs, "/output", &extract_dir))
    {
        FIRECRACKER_OUTPUT_EXTRACTION_FAILURES.fetch_add(1, Ordering::Relaxed);
        job.firecracker_error_class = Some("output_extraction".to_string());
        job.status = "failed".to_string();
        job.finished_at_unix_seconds = Some(unix_seconds());
        job.error = Some(error.message.clone());
        persist_job(&state, &job)?;
        return Err(error);
    }
    tokio::task::block_in_place(|| enforce_firecracker_output_limit(&state, &job, &extract_dir))?;

    let stdout_receipt = put_replicated_block(&state, CODEC_RAW, stdout_bytes).await?;
    let stderr_receipt = put_replicated_block(&state, CODEC_RAW, stderr_bytes).await?;
    let output_root_cid = collect_compute_output(&state, &extract_dir, &job.spec.outputs).await?;
    let finished_at = unix_seconds();
    let status = if exit_code == 0 {
        FIRECRACKER_VM_SUCCESSES.fetch_add(1, Ordering::Relaxed);
        "succeeded"
    } else {
        FIRECRACKER_VM_FAILURES.fetch_add(1, Ordering::Relaxed);
        "failed"
    }
    .to_string();
    let _state_guard = state.compute_state_lock.lock().await;
    let current_status = load_job(&state, &job_id)?.map(|current| current.status);
    let final_status = if current_status.as_deref() == Some("canceled") {
        "canceled".to_string()
    } else {
        status
    };
    let mut receipt = ComputeReceipt {
        job_id: job_id.clone(),
        status: final_status.clone(),
        node_id: state.status.node_id.clone(),
        exit_code: Some(exit_code),
        stdout_cid: Some(stdout_receipt.cid),
        stderr_cid: Some(stderr_receipt.cid),
        output_root_cid: output_root_cid.clone(),
        started_at_unix_seconds: job.started_at_unix_seconds.unwrap_or(finished_at),
        finished_at_unix_seconds: finished_at,
        signature_hex: String::new(),
    };
    let receipt_payload = serde_json::to_vec(&receipt).map_err(ApiError::serde)?;
    receipt.signature_hex = hex::encode(state.identity.sign(&receipt_payload));

    job.status = final_status;
    if job.status == "canceled" {
        job.guest_exited_after_cancel = true;
    }
    job.finished_at_unix_seconds = Some(finished_at);
    job.exit_code = Some(exit_code);
    job.stdout_cid = receipt.stdout_cid.clone();
    job.stderr_cid = receipt.stderr_cid.clone();
    job.output_root_cid = output_root_cid;
    job.receipt = Some(receipt);
    merge_current_attempt_events(&state, &mut job)?;
    if exit_code != 0 && job.status != "canceled" {
        job.firecracker_error_class = Some("job_failure".to_string());
        job.error = Some(format!("firecracker process exited with {exit_code}"));
    }
    persist_job(&state, &job)?;
    cleanup_firecracker_temp(
        &root_dir,
        &input_dir,
        &rootfs,
        Some(&inputfs),
        Some(&outputfs),
        Some(&vsock_path),
        &config_path,
    );
    Ok(())
}

const FIRECRACKER_CONTROL_PORT: u32 = 1024;
const FIRECRACKER_CONTROL_PROTOCOL_VERSION: u32 = 1;

fn firecracker_guest_init_script() -> &'static [u8] {
    br#"#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /pepper_inputs /pepper_runtime
if ! mount -o ro /dev/vdb /pepper_inputs 2>/dev/null; then
  echo "failed to mount input disk" >&2
  poweroff -f
fi
if ! mount /dev/vdc /pepper_runtime 2>/dev/null; then
  echo "failed to mount runtime output disk" >&2
  poweroff -f
fi
mkdir -p /pepper_runtime/output
[ -f /pepper_mounts.sh ] && /bin/sh /pepper_mounts.sh || true
export PEPPER_INPUT=/pepper_inputs
export PEPPER_OUTPUT=/pepper_runtime/output
export PEPPER_VSOCK_PORT=1024
job_id_arg=
if [ -f /pepper_job_id ]; then
  job_id_arg="--job-id $(cat /pepper_job_id)"
fi
/pepper-guest-agent --port 1024 --cancel-file /pepper_runtime/pepper_cancel --status-file /pepper_runtime/pepper_status --progress-file /pepper_runtime/pepper_progress --stdout-file /pepper_runtime/fc_stdout --stderr-file /pepper_runtime/fc_stderr $job_id_arg >/pepper_runtime/pepper_agent_stdout 2>/pepper_runtime/pepper_agent_stderr &
guest_agent_pid=$!
echo job_started > /pepper_runtime/pepper_status
( /bin/sh /job.sh > /pepper_runtime/fc_stdout 2> /pepper_runtime/fc_stderr ) &
job_pid=$!
trap 'kill -TERM $job_pid 2>/dev/null || true; kill -TERM $guest_agent_pid 2>/dev/null || true; echo 130 > /pepper_runtime/exit_code; echo cancel_completed > /pepper_runtime/pepper_status; sync; poweroff -f' INT TERM
while kill -0 $job_pid 2>/dev/null; do
  if [ -f /pepper_runtime/pepper_cancel ]; then
    kill -TERM $job_pid 2>/dev/null || true
    sleep 1
    kill -KILL $job_pid 2>/dev/null || true
    wait $job_pid 2>/dev/null || true
    kill -TERM $guest_agent_pid 2>/dev/null || true
    echo 130 > /pepper_runtime/exit_code
    echo cancel_completed > /pepper_runtime/pepper_status
    sync
    poweroff -f
  fi
  sleep 1
done
wait $job_pid
code=$?
echo $code > /pepper_runtime/exit_code
if [ "$code" = "0" ]; then echo job_exited:succeeded > /pepper_runtime/pepper_status; else echo job_exited:failed > /pepper_runtime/pepper_status; fi
kill -TERM $guest_agent_pid 2>/dev/null || true
sync
poweroff -f
reboot -f
"#
}

fn write_firecracker_mount_script(
    root_dir: &FsPath,
    inputs: &[pepper_types::ComputeInput],
) -> Result<(), ApiError> {
    let mut script = String::from("#!/bin/sh\nmkdir -p /pepper_inputs /output\n");
    for input in inputs {
        let guest_mount = guest_safe_path(&input.mount)?;
        let input_path = guest_safe_path(&format!(
            "pepper_inputs/{}",
            input.mount.trim_start_matches('/')
        ))?;
        if let Some(parent) = FsPath::new(&guest_mount).parent()
            && parent != FsPath::new("")
        {
            script.push_str(&format!(
                "mkdir -p {}\n",
                shell_quote(&parent.display().to_string())
            ));
        }
        script.push_str(&format!(
            "rm -rf {} 2>/dev/null || true\nln -s {} {} 2>/dev/null || true\n",
            shell_quote(&guest_mount),
            shell_quote(&input_path),
            shell_quote(&guest_mount)
        ));
    }
    write_executable(&root_dir.join("pepper_mounts.sh"), script.as_bytes())
}

fn guest_safe_path(path: &str) -> Result<String, ApiError> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty()
        || trimmed
            .split('/')
            .any(|part| part.is_empty() || part == "..")
    {
        return Err(ApiError::bad_request(
            "guest path must be relative and must not contain ..",
        ));
    }
    Ok(format!("/{trimmed}"))
}

#[derive(Debug, Clone)]
struct FirecrackerCancelOutcome {
    delivered: bool,
    acknowledged: bool,
    response: Option<String>,
}

impl FirecrackerCancelOutcome {
    fn description(&self) -> String {
        match (self.delivered, self.acknowledged, self.response.as_deref()) {
            (true, true, Some(response)) => {
                format!("firecracker cancel delivered and acknowledged over vsock: {response}; VM termination fallback scheduled if still running")
            }
            (true, true, None) => "firecracker cancel delivered and acknowledged over vsock; VM termination fallback scheduled if still running".to_string(),
            (true, false, _) => "firecracker cancel delivered over vsock without acknowledgement; VM termination fallback scheduled if still running".to_string(),
            _ => "firecracker cancel requested; VM termination fallback scheduled".to_string(),
        }
    }

    fn events(&self) -> Vec<String> {
        let mut events = Vec::new();
        if self.delivered {
            events.push("cancel_delivered".to_string());
        }
        if self.acknowledged {
            events.push("cancel_acknowledged".to_string());
        }
        if let Some(response) = &self.response {
            events.push(format!("cancel_response:{response}"));
        }
        events
    }
}

fn spawn_firecracker_control_stream(
    state: AppState,
    job_id: String,
    vsock_path: PathBuf,
    work_dir: PathBuf,
    timeout: Duration,
) -> AbortHandle {
    tokio::spawn(async move {
        let deadline = time::Instant::now() + timeout;
        let mut stdout_offset = 0usize;
        let mut stderr_offset = 0usize;
        while time::Instant::now() < deadline {
            let should_continue = load_job(&state, &job_id)
                .ok()
                .flatten()
                .is_some_and(|job| job.status == "running");
            if !should_continue {
                break;
            }
            let stream_state = state.clone();
            let stream_job_id = job_id.clone();
            let stream_work_dir = work_dir.clone();
            let stream_vsock_path = vsock_path.clone();
            let stream_result = tokio::task::spawn_blocking(move || {
                firecracker_stream_session(
                    &stream_state,
                    &stream_job_id,
                    &stream_vsock_path,
                    &stream_work_dir,
                )
            })
            .await;
            match stream_result {
                Ok(Ok(())) => break,
                Ok(Err(error)) => {
                    warn!(?error, job_id = %job_id, "firecracker long-lived vsock stream failed; falling back to one-shot polling");
                }
                Err(error) => warn!(?error, job_id = %job_id, "firecracker stream task failed"),
            }
            time::sleep(Duration::from_secs(1)).await;
            if let Ok(Some(status)) = firecracker_status_request(&job_id, &vsock_path).await {
                FIRECRACKER_HEARTBEATS.fetch_add(1, Ordering::Relaxed);
                let _ = append_attempt_event_by_job_id(
                    &state,
                    &job_id,
                    format!("guest_status:{status}"),
                );
            }
            match firecracker_logs_request(
                &job_id,
                &vsock_path,
                stdout_offset,
                stderr_offset,
            )
            .await
            {
                Ok(Some(logs)) => {
                    stdout_offset = logs.stdout_offset;
                    stderr_offset = logs.stderr_offset;
                    if !logs.stdout.is_empty() {
                        let _ = append_file(&work_dir.join("vsock_stdout.log"), logs.stdout.as_bytes());
                    }
                    if !logs.stderr.is_empty() {
                        let _ = append_file(&work_dir.join("vsock_stderr.log"), logs.stderr.as_bytes());
                    }
                }
                Ok(None) => {}
                Err(error) => warn!(?error, job_id = %job_id, "firecracker vsock log poll failed"),
            }
        }
    })
    .abort_handle()
}

fn append_file(path: &FsPath, bytes: &[u8]) -> Result<(), ApiError> {
    use std::io::Write;
    const MAX_STREAMED_LOG_BYTES: u64 = 16 * 1024 * 1024;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| ApiError::internal(error.to_string()))?;
    }
    let existing = std::fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    if existing.saturating_add(bytes.len() as u64) > MAX_STREAMED_LOG_BYTES {
        return Err(ApiError::bad_request(
            "streamed guest logs exceed the 16 MiB host limit",
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    file.write_all(bytes)
        .map_err(|error| ApiError::internal(error.to_string()))
}

fn append_attempt_event_by_job_id(
    state: &AppState,
    job_id: &str,
    event: impl Into<String>,
) -> Result<(), ApiError> {
    let mut job = load_job(state, job_id)?.ok_or_else(|| ApiError::not_found("job not found"))?;
    record_attempt_event(&mut job, event);
    persist_job(state, &job)
}

fn merge_current_attempt_events(
    state: &AppState,
    job: &mut ComputeJobStatus,
) -> Result<(), ApiError> {
    let Some(current) = load_job(state, &job.job_id)? else {
        return Ok(());
    };
    let Some(current_attempt) = current.attempts.last() else {
        return Ok(());
    };
    let Some(job_attempt) = job.attempts.last_mut() else {
        return Ok(());
    };
    for event in &current_attempt.events {
        if !job_attempt.events.contains(event) {
            job_attempt.events.push(event.clone());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn firecracker_stream_session(
    state: &AppState,
    job_id: &str,
    vsock_path: &FsPath,
    work_dir: &FsPath,
) -> Result<(), ApiError> {
    use std::io::{BufRead, BufReader, Read, Write};
    let mut socket = firecracker_vsock_connect(vsock_path, FIRECRACKER_CONTROL_PORT)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let payload = serde_json::json!({
        "protocol_version": FIRECRACKER_CONTROL_PROTOCOL_VERSION,
        "type": "stream",
        "job_id": job_id,
    })
    .to_string()
        + "\n";
    socket
        .write_all(payload.as_bytes())
        .map_err(|error| ApiError::internal(error.to_string()))?;
    socket
        .flush()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    const MAX_CONTROL_LINE_BYTES: u64 = 64 * 1024;
    let mut reader = BufReader::new(socket);
    loop {
        let mut line = String::new();
        let read = reader
            .by_ref()
            .take(MAX_CONTROL_LINE_BYTES + 1)
            .read_line(&mut line)
            .map_err(|error| ApiError::internal(error.to_string()))?;
        if line.len() as u64 > MAX_CONTROL_LINE_BYTES || (read > 0 && !line.ends_with('\n')) {
            return Err(ApiError::bad_request(
                "guest control message exceeds the 64 KiB limit",
            ));
        }
        if read == 0 {
            break;
        }
        handle_firecracker_stream_line(state, job_id, work_dir, line.trim())?;
        let running = load_job(state, job_id)
            .ok()
            .flatten()
            .is_some_and(|job| job.status == "running");
        if !running {
            break;
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn firecracker_stream_session(
    _state: &AppState,
    _job_id: &str,
    _vsock_path: &FsPath,
    _work_dir: &FsPath,
) -> Result<(), ApiError> {
    Err(ApiError::internal(
        "Firecracker vsock control is only supported on Linux",
    ))
}

fn handle_firecracker_stream_line(
    state: &AppState,
    job_id: &str,
    work_dir: &FsPath,
    line: &str,
) -> Result<(), ApiError> {
    if line.is_empty() {
        return Ok(());
    }
    let value: serde_json::Value = serde_json::from_str(line).map_err(ApiError::serde)?;
    match value.get("type").and_then(|value| value.as_str()) {
        Some("status") => {
            FIRECRACKER_HEARTBEATS.fetch_add(1, Ordering::Relaxed);
            let status = value
                .get("status")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            append_attempt_event_by_job_id(state, job_id, format!("guest_status:{status}"))?;
            if let Some(progress) = value.get("progress").and_then(|value| value.as_str())
                && !progress.is_empty()
            {
                append_attempt_event_by_job_id(
                    state,
                    job_id,
                    format!("guest_progress:{progress}"),
                )?;
            }
        }
        Some("log_chunk") => {
            if let Some(stdout) = value.get("stdout").and_then(|value| value.as_str())
                && !stdout.is_empty()
            {
                append_file(&work_dir.join("vsock_stdout.log"), stdout.as_bytes())?;
            }
            if let Some(stderr) = value.get("stderr").and_then(|value| value.as_str())
                && !stderr.is_empty()
            {
                append_file(&work_dir.join("vsock_stderr.log"), stderr.as_bytes())?;
            }
        }
        Some("lifecycle") => {
            if let Some(event) = value.get("event").and_then(|value| value.as_str()) {
                append_attempt_event_by_job_id(state, job_id, format!("guest_lifecycle:{event}"))?;
            }
        }
        Some("error") => {
            if let Some(error) = value.get("error").and_then(|value| value.as_str()) {
                append_attempt_event_by_job_id(state, job_id, format!("guest_error:{error}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct FirecrackerLogPoll {
    stdout: String,
    stderr: String,
    stdout_offset: usize,
    stderr_offset: usize,
}

async fn firecracker_status_request(
    job_id: &str,
    vsock_path: &FsPath,
) -> Result<Option<String>, ApiError> {
    let payload = serde_json::json!({
        "protocol_version": FIRECRACKER_CONTROL_PROTOCOL_VERSION,
        "type": "status",
        "job_id": job_id,
    })
    .to_string()
        + "\n";
    let vsock_path = vsock_path.to_path_buf();
    let task = tokio::task::spawn_blocking(move || {
        firecracker_vsock_request(&vsock_path, FIRECRACKER_CONTROL_PORT, payload.as_bytes())
    });
    match time::timeout(Duration::from_millis(500), task).await {
        Ok(Ok(Ok(response))) => Ok(response),
        Ok(Ok(Err(error))) => Err(ApiError::internal(error.to_string())),
        Ok(Err(error)) => Err(ApiError::internal(error.to_string())),
        Err(_) => Err(ApiError::internal("firecracker vsock status timed out")),
    }
}

async fn firecracker_logs_request(
    job_id: &str,
    vsock_path: &FsPath,
    stdout_offset: usize,
    stderr_offset: usize,
) -> Result<Option<FirecrackerLogPoll>, ApiError> {
    let payload = serde_json::json!({
        "protocol_version": FIRECRACKER_CONTROL_PROTOCOL_VERSION,
        "type": "logs",
        "job_id": job_id,
        "stdout_offset": stdout_offset,
        "stderr_offset": stderr_offset,
    })
    .to_string()
        + "\n";
    let vsock_path = vsock_path.to_path_buf();
    let task = tokio::task::spawn_blocking(move || {
        firecracker_vsock_request(&vsock_path, FIRECRACKER_CONTROL_PORT, payload.as_bytes())
    });
    let response = match time::timeout(Duration::from_millis(500), task).await {
        Ok(Ok(Ok(response))) => response,
        Ok(Ok(Err(error))) => return Err(ApiError::internal(error.to_string())),
        Ok(Err(error)) => return Err(ApiError::internal(error.to_string())),
        Err(_) => return Err(ApiError::internal("firecracker vsock logs timed out")),
    };
    let Some(response) = response else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_str(&response).map_err(ApiError::serde)?;
    Ok(Some(FirecrackerLogPoll {
        stdout: value
            .get("stdout")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        stderr: value
            .get("stderr")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        stdout_offset: value
            .get("stdout_offset")
            .and_then(|value| value.as_u64())
            .unwrap_or(stdout_offset as u64) as usize,
        stderr_offset: value
            .get("stderr_offset")
            .and_then(|value| value.as_u64())
            .unwrap_or(stderr_offset as u64) as usize,
    }))
}

async fn send_firecracker_cancel(
    state: &AppState,
    job: &ComputeJobStatus,
) -> Result<FirecrackerCancelOutcome, ApiError> {
    let configured_vsock_path = state.compute_work_dir.join(&job.job_id).join("vsock.sock");
    let vsock_path = firecracker_host_vsock_path(state, &job.job_id, &configured_vsock_path);
    let payload = serde_json::json!({
        "protocol_version": FIRECRACKER_CONTROL_PROTOCOL_VERSION,
        "type": "cancel",
        "job_id": job.job_id,
    })
    .to_string()
        + "\n";
    let task = tokio::task::spawn_blocking(move || {
        firecracker_vsock_request(&vsock_path, FIRECRACKER_CONTROL_PORT, payload.as_bytes())
    });
    match time::timeout(Duration::from_millis(750), task).await {
        Ok(Ok(Ok(response))) => {
            FIRECRACKER_VSOCK_CANCEL_DELIVERED.fetch_add(1, Ordering::Relaxed);
            let acknowledged = response
                .as_deref()
                .is_some_and(|response| response.contains("cancel_ack"));
            if acknowledged {
                FIRECRACKER_VSOCK_CANCEL_ACKS.fetch_add(1, Ordering::Relaxed);
            }
            Ok(FirecrackerCancelOutcome {
                delivered: true,
                acknowledged,
                response,
            })
        }
        Ok(Ok(Err(error))) => {
            FIRECRACKER_VSOCK_CANCEL_FALLBACKS.fetch_add(1, Ordering::Relaxed);
            Err(ApiError::internal(error.to_string()))
        }
        Ok(Err(error)) => {
            FIRECRACKER_VSOCK_CANCEL_FALLBACKS.fetch_add(1, Ordering::Relaxed);
            Err(ApiError::internal(error.to_string()))
        }
        Err(_) => {
            FIRECRACKER_VSOCK_CANCEL_FALLBACKS.fetch_add(1, Ordering::Relaxed);
            Err(ApiError::internal("firecracker vsock cancel timed out"))
        }
    }
}

struct FirecrackerGuestCidGuard {
    cid: u32,
    active: Arc<Mutex<HashMap<u32, String>>>,
}

impl Drop for FirecrackerGuestCidGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock()
            && active.get(&self.cid).is_some()
        {
            active.remove(&self.cid);
        }
    }
}

fn allocate_firecracker_guest_cid(
    state: &AppState,
    job_id: &str,
) -> Result<FirecrackerGuestCidGuard, ApiError> {
    const CID_RANGE: u32 = 2_000_000_000;
    let digest = blake3::hash(job_id.as_bytes());
    let mut prefix = [0u8; 4];
    prefix.copy_from_slice(&digest.as_bytes()[0..4]);
    let mut candidate = 3 + (u32::from_le_bytes(prefix) % CID_RANGE);
    let mut active = state
        .active_guest_cids
        .lock()
        .map_err(|_| ApiError::internal("guest CID allocator lock poisoned"))?;
    for _ in 0..=state.compute_queue_limit {
        if let std::collections::hash_map::Entry::Vacant(entry) = active.entry(candidate) {
            entry.insert(job_id.to_string());
            return Ok(FirecrackerGuestCidGuard {
                cid: candidate,
                active: state.active_guest_cids.clone(),
            });
        }
        candidate = 3 + ((candidate - 2) % CID_RANGE);
    }
    Err(ApiError::internal(
        "could not allocate a unique Firecracker guest CID",
    ))
}

trait FirecrackerControlStream: std::io::Read + std::io::Write + Send {}
impl<T: std::io::Read + std::io::Write + Send> FirecrackerControlStream for T {}

#[cfg(target_os = "linux")]
fn firecracker_vsock_connect(
    path: &FsPath,
    port: u32,
) -> std::io::Result<Box<dyn FirecrackerControlStream>> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    stream.write_all(format!("CONNECT {port}\n").as_bytes())?;
    stream.flush()?;
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while response.len() <= 64 {
        let read = stream.read(&mut byte)?;
        if read == 0 {
            break;
        }
        response.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    let response = String::from_utf8_lossy(&response);
    if !response.starts_with("OK ") {
        return Err(std::io::Error::other(format!(
            "Firecracker vsock CONNECT failed: {}",
            response.trim()
        )));
    }
    Ok(Box::new(stream))
}

#[cfg(not(target_os = "linux"))]
fn firecracker_vsock_connect(
    _path: &FsPath,
    _port: u32,
) -> std::io::Result<Box<dyn FirecrackerControlStream>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Firecracker vsock control requires Linux",
    ))
}

fn firecracker_vsock_request(
    path: &FsPath,
    port: u32,
    payload: &[u8],
) -> std::io::Result<Option<String>> {
    use std::io::{Read, Write};
    const MAX_RESPONSE_BYTES: usize = 64 * 1024;
    let mut stream = firecracker_vsock_connect(path, port)?;
    stream.write_all(payload)?;
    stream.flush()?;
    let mut response = Vec::new();
    let mut buffer = [0u8; 1024];
    while response.len() <= MAX_RESPONSE_BYTES {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                response.extend_from_slice(&buffer[..read]);
                if response.contains(&b'\n') {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => return Err(error),
        }
    }
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(std::io::Error::other(
            "Firecracker guest response exceeds 64 KiB",
        ));
    }
    if response.is_empty() {
        Ok(None)
    } else {
        Ok(Some(String::from_utf8_lossy(&response).trim().to_string()))
    }
}

async fn rootfs_image_bytes(state: &AppState, cid: &Cid) -> Result<Vec<u8>, ApiError> {
    match cid.codec {
        CODEC_RAW => Ok(get_block_resolved(state, cid).await?.payload),
        CODEC_OBJECT_MANIFEST | CODEC_ERASURE_MANIFEST => object_bytes(state, cid).await,
        _ => Err(ApiError::bad_request(
            "firecracker rootfs_cid must be raw, object, or erasure object data",
        )),
    }
}

struct FirecrackerRuntimePaths<'a> {
    rootfs: &'a FsPath,
    inputfs: &'a FsPath,
    outputfs: &'a FsPath,
    vsock_path: &'a FsPath,
    kernel: &'a FsPath,
    config_path: &'a FsPath,
}

fn prepare_firecracker_command(
    state: &AppState,
    job_id: &str,
    paths: &FirecrackerRuntimePaths<'_>,
) -> Result<TokioCommand, ApiError> {
    if state.firecracker_enable_jailer {
        if let Err(error) = prepare_firecracker_jail(state, job_id, paths) {
            FIRECRACKER_JAILER_SETUP_FAILURES.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
        let mut command = TokioCommand::new(&state.firecracker_jailer_binary);
        command
            .kill_on_drop(true)
            .arg("--id")
            .arg(safe_jailer_id(job_id))
            .arg("--exec-file")
            .arg(&state.firecracker_binary)
            .arg("--uid")
            .arg(state.firecracker_jailer_uid.to_string())
            .arg("--gid")
            .arg(state.firecracker_jailer_gid.to_string())
            .arg("--chroot-base-dir")
            .arg(&state.firecracker_jailer_chroot_base)
            .arg("--")
            .arg("--no-api")
            .arg("--config-file")
            .arg("/firecracker.json");
        if state.firecracker_strict_sandbox {
            command.arg("--seccomp-level").arg("2");
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        configure_sandbox_process(&mut command);
        return Ok(command);
    }

    let mut command = TokioCommand::new(&state.firecracker_binary);
    command
        .kill_on_drop(true)
        .arg("--no-api")
        .arg("--config-file")
        .arg(paths.config_path);
    if state.firecracker_strict_sandbox {
        command.arg("--seccomp-level").arg("2");
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    configure_sandbox_process(&mut command);
    Ok(command)
}

fn prepare_firecracker_jail(
    state: &AppState,
    job_id: &str,
    paths: &FirecrackerRuntimePaths<'_>,
) -> Result<(), ApiError> {
    let jail_instance = firecracker_jail_instance_root(state, job_id);
    let jail_root = firecracker_jail_root(state, job_id);
    validate_or_create_jailer_base(state)?;
    if jail_instance.exists() {
        return Err(ApiError::internal(format!(
            "firecracker jail directory already exists: {}",
            jail_instance.display()
        )));
    }
    std::fs::create_dir(&jail_instance).map_err(|error| ApiError::internal(error.to_string()))?;
    std::fs::create_dir(&jail_root).map_err(|error| ApiError::internal(error.to_string()))?;
    std::fs::copy(paths.rootfs, jail_root.join("rootfs.ext4"))
        .map_err(|error| ApiError::internal(error.to_string()))?;
    std::fs::copy(paths.inputfs, jail_root.join("inputs.ext4"))
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let jailed_output = jail_root.join("outputs.ext4");
    std::fs::copy(paths.outputfs, &jailed_output)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    set_path_owner(
        &jail_root,
        state.firecracker_jailer_uid,
        state.firecracker_jailer_gid,
    )?;
    set_path_owner(
        &jailed_output,
        state.firecracker_jailer_uid,
        state.firecracker_jailer_gid,
    )?;
    let _ = std::fs::remove_file(jail_root.join("vsock.sock"));
    if let Some(parent) = paths.vsock_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| ApiError::internal(error.to_string()))?;
    }
    std::fs::copy(paths.kernel, jail_root.join("vmlinux"))
        .map_err(|error| ApiError::internal(error.to_string()))?;
    std::fs::copy(paths.config_path, jail_root.join("firecracker.json"))
        .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok(())
}

#[cfg(unix)]
fn set_path_owner(path: &FsPath, uid: u32, gid: u32) -> Result<(), ApiError> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| ApiError::internal("path contains a NUL byte"))?;
    if unsafe { chown(path.as_ptr(), uid, gid) } != 0 {
        return Err(ApiError::internal(format!(
            "failed to set jail ownership: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_path_owner(_path: &FsPath, _uid: u32, _gid: u32) -> Result<(), ApiError> {
    Err(ApiError::internal("Firecracker jailer requires Unix"))
}

fn validate_or_create_jailer_base(state: &AppState) -> Result<(), ApiError> {
    let base = state.firecracker_jailer_chroot_base.join("firecracker");
    std::fs::create_dir_all(&base).map_err(|error| ApiError::internal(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata =
            std::fs::metadata(&base).map_err(|error| ApiError::internal(error.to_string()))?;
        if metadata.mode() & 0o002 != 0 {
            return Err(ApiError::internal(format!(
                "firecracker jailer base {} must not be world-writable",
                base.display()
            )));
        }
    }
    Ok(())
}

fn firecracker_jail_instance_root(state: &AppState, job_id: &str) -> PathBuf {
    state
        .firecracker_jailer_chroot_base
        .join("firecracker")
        .join(safe_jailer_id(job_id))
}

fn firecracker_jail_root(state: &AppState, job_id: &str) -> PathBuf {
    firecracker_jail_instance_root(state, job_id).join("root")
}

fn firecracker_runtime_outputfs(state: &AppState, job_id: &str, outputfs: &FsPath) -> PathBuf {
    if state.firecracker_enable_jailer {
        firecracker_jail_root(state, job_id).join("outputs.ext4")
    } else {
        outputfs.to_path_buf()
    }
}

fn firecracker_host_vsock_path(
    state: &AppState,
    job_id: &str,
    configured_path: &FsPath,
) -> PathBuf {
    if state.firecracker_enable_jailer {
        firecracker_jail_root(state, job_id).join("vsock.sock")
    } else {
        configured_path.to_path_buf()
    }
}

fn safe_jailer_id(job_id: &str) -> String {
    job_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .take(64)
        .collect::<String>()
}

struct FirecrackerCgroupGuard {
    path: Option<PathBuf>,
}

impl Drop for FirecrackerCgroupGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = std::fs::remove_dir(path);
        }
    }
}

fn apply_firecracker_cgroup(
    state: &AppState,
    job: &ComputeJobStatus,
    pid: Option<u32>,
) -> Result<FirecrackerCgroupGuard, ApiError> {
    let Some(pid) = pid else {
        return Ok(FirecrackerCgroupGuard { path: None });
    };
    if !state.firecracker_cgroup_enabled {
        return Ok(FirecrackerCgroupGuard { path: None });
    }
    let base = &state.firecracker_cgroup_base;
    if let Some(parent) = base.parent()
        && !parent.exists()
    {
        return Err(ApiError::internal(format!(
            "cgroup enforcement is enabled but parent {} is unavailable",
            parent.display()
        )));
    }
    std::fs::create_dir_all(base).map_err(|error| ApiError::internal(error.to_string()))?;
    let cgroup_path = base.join(safe_jailer_id(&job.job_id));
    if cgroup_path.exists() {
        let _ = std::fs::remove_dir(&cgroup_path);
    }
    std::fs::create_dir(&cgroup_path).map_err(|error| ApiError::internal(error.to_string()))?;
    let memory_mib = job
        .spec
        .resources
        .as_ref()
        .and_then(|resources| resources.memory_mib)
        .unwrap_or(state.firecracker_memory_mib as u64)
        .saturating_add(128);
    let memory_bytes = memory_mib.saturating_mul(1024 * 1024);
    std::fs::write(cgroup_path.join("memory.max"), memory_bytes.to_string()).map_err(|error| {
        ApiError::internal(format!("failed to enforce cgroup memory.max: {error}"))
    })?;
    if let Some(cpu_millis) = job
        .spec
        .resources
        .as_ref()
        .and_then(|resources| resources.cpu_millis)
    {
        let quota = cpu_millis.max(1).saturating_mul(100);
        std::fs::write(cgroup_path.join("cpu.max"), format!("{quota} 100000")).map_err(
            |error| ApiError::internal(format!("failed to enforce cgroup cpu.max: {error}")),
        )?;
    }
    std::fs::write(cgroup_path.join("cgroup.procs"), pid.to_string())
        .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok(FirecrackerCgroupGuard {
        path: Some(cgroup_path),
    })
}

struct ProcessGroupGuard {
    pid: Option<u32>,
    active: bool,
}

impl ProcessGroupGuard {
    fn new(pid: Option<u32>) -> Self {
        Self { pid, active: true }
    }

    fn disarm(&mut self) {
        self.active = false;
    }

    fn terminate(&mut self) {
        #[cfg(unix)]
        if self.active
            && let Some(pid) = self.pid
        {
            kill_process_group(pid);
        }
        self.active = false;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.active
            && let Some(pid) = self.pid
        {
            kill_process_group(pid);
        }
    }
}

#[cfg(unix)]
fn configure_sandbox_process(command: &mut TokioCommand) {
    unsafe {
        command.pre_exec(|| {
            if set_process_group() != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if set_no_new_privs() != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_sandbox_process(_command: &mut TokioCommand) {}

#[cfg(unix)]
fn set_process_group() -> i32 {
    unsafe { setpgid(0, 0) }
}

#[cfg(unix)]
fn set_no_new_privs() -> i32 {
    unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }
}

#[cfg(unix)]
fn kill_process_group(pid: u32) {
    unsafe {
        let _ = kill(-(pid as i32), SIGKILL);
    }
}

#[cfg(unix)]
const SIGKILL: i32 = 9;

#[cfg(unix)]
const PR_SET_NO_NEW_PRIVS: i32 = 38;

#[cfg(unix)]
unsafe extern "C" {
    fn setpgid(pid: i32, pgid: i32) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> i32;
    fn chown(path: *const std::ffi::c_char, owner: u32, group: u32) -> i32;
}

struct FirecrackerCleanupGuard {
    work_dir: PathBuf,
    root_dir: PathBuf,
    input_dir: PathBuf,
    rootfs: PathBuf,
    inputfs: Option<PathBuf>,
    outputfs: Option<PathBuf>,
    vsock_path: Option<PathBuf>,
    config_path: PathBuf,
    jail_dir: Option<PathBuf>,
}

impl Drop for FirecrackerCleanupGuard {
    fn drop(&mut self) {
        cleanup_firecracker_temp(
            &self.root_dir,
            &self.input_dir,
            &self.rootfs,
            self.inputfs.as_deref(),
            self.outputfs.as_deref(),
            self.vsock_path.as_deref(),
            &self.config_path,
        );
        if let Some(jail_dir) = &self.jail_dir {
            let _ = std::fs::remove_dir_all(jail_dir);
        }
        let _ = std::fs::remove_dir_all(&self.work_dir);
    }
}

fn cleanup_firecracker_temp(
    root_dir: &FsPath,
    input_dir: &FsPath,
    rootfs: &FsPath,
    inputfs: Option<&FsPath>,
    outputfs: Option<&FsPath>,
    vsock_path: Option<&FsPath>,
    config_path: &FsPath,
) {
    let _ = std::fs::remove_dir_all(root_dir);
    let _ = std::fs::remove_dir_all(input_dir);
    let _ = std::fs::remove_file(rootfs);
    if let Some(inputfs) = inputfs {
        let _ = std::fs::remove_file(inputfs);
    }
    if let Some(outputfs) = outputfs {
        let _ = std::fs::remove_file(outputfs);
    }
    if let Some(vsock_path) = vsock_path {
        let _ = std::fs::remove_file(vsock_path);
    }
    for suffix in ["fc_stdout", "fc_stderr", "exit_code"] {
        let _ = std::fs::remove_file(rootfs.with_extension(format!("dump-{suffix}")));
        if let Some(outputfs) = outputfs {
            let _ = std::fs::remove_file(outputfs.with_extension(format!("dump-{suffix}")));
        }
    }
    let _ = std::fs::remove_file(config_path);
}

fn ensure_firecracker_available(state: &AppState) -> Result<(), ApiError> {
    if !state.firecracker_binary.exists() {
        return Err(ApiError::bad_request(format!(
            "firecracker binary not found at {}",
            state.firecracker_binary.display()
        )));
    }
    if state.firecracker_enable_jailer && !state.firecracker_jailer_binary.exists() {
        return Err(ApiError::bad_request(format!(
            "firecracker jailer binary not found at {}",
            state.firecracker_jailer_binary.display()
        )));
    }
    if std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_err()
    {
        return Err(ApiError::bad_request(
            "/dev/kvm is not available or not accessible",
        ));
    }
    let kernel = state
        .firecracker_kernel_image
        .clone()
        .unwrap_or_else(default_firecracker_kernel_image);
    if std::fs::File::open(&kernel).is_err() {
        return Err(ApiError::bad_request(format!(
            "firecracker kernel image is not readable at {}",
            kernel.display()
        )));
    }
    if state.firecracker_strict_sandbox && !state.firecracker_enable_jailer {
        warn!(
            "Firecracker strict sandbox requested without jailer; enforcing no network, no API, process-group cleanup, and seccomp level 2 only"
        );
    }
    Ok(())
}

fn default_firecracker_kernel_image() -> PathBuf {
    std::env::var_os("PEPPER_FIRECRACKER_KERNEL_IMAGE")
        .map(PathBuf::from)
        .or_else(|| {
            [
                "/boot/vmlinux",
                "/boot/vmlinuz",
                "/usr/share/firecracker/vmlinux",
            ]
            .iter()
            .map(PathBuf::from)
            .find(|path| std::fs::File::open(path).is_ok())
        })
        .unwrap_or_else(|| PathBuf::from("/boot/vmlinux"))
}

fn write_executable(path: &FsPath, bytes: &[u8]) -> Result<(), ApiError> {
    write_bytes(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(path)
            .map_err(|error| ApiError::internal(error.to_string()))?
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions)
            .map_err(|error| ApiError::internal(error.to_string()))?;
    }
    Ok(())
}

fn enforce_firecracker_input_limit(
    state: &AppState,
    job: &ComputeJobStatus,
    input_dir: &FsPath,
) -> Result<(), ApiError> {
    let limit = job
        .spec
        .resources
        .as_ref()
        .and_then(|resources| resources.max_input_bytes)
        .unwrap_or(state.firecracker_max_input_bytes);
    let size = directory_size_bytes(input_dir)?;
    if size > limit {
        return Err(ApiError::bad_request(format!(
            "firecracker input size {size} exceeds limit {limit}"
        )));
    }
    Ok(())
}

fn firecracker_output_limit(state: &AppState, job: &ComputeJobStatus) -> u64 {
    job.spec
        .resources
        .as_ref()
        .and_then(|resources| resources.max_output_bytes)
        .unwrap_or(state.firecracker_max_output_bytes)
}

fn enforce_firecracker_output_limit(
    state: &AppState,
    job: &ComputeJobStatus,
    output_dir: &FsPath,
) -> Result<(), ApiError> {
    let limit = firecracker_output_limit(state, job);
    let size = directory_size_bytes(output_dir)?;
    if size > limit {
        return Err(ApiError::bad_request(format!(
            "firecracker output size {size} exceeds limit {limit}"
        )));
    }
    Ok(())
}

fn create_ext4_rootfs(root: &FsPath, image: &FsPath) -> Result<(), ApiError> {
    let content_bytes = directory_size_bytes(root)?;
    let image_mib = std::cmp::max(
        128,
        content_bytes
            .div_ceil(1024 * 1024)
            .saturating_mul(2)
            .saturating_add(64),
    );
    let status = std::process::Command::new("mkfs.ext4")
        .arg("-q")
        .arg("-d")
        .arg(root)
        .arg(image)
        .arg(format!("{image_mib}M"))
        .status()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    if !status.success() {
        return Err(ApiError::internal("mkfs.ext4 failed"));
    }
    Ok(())
}

fn create_empty_ext4_image(image: &FsPath, requested_bytes: u64) -> Result<(), ApiError> {
    let image_mib = std::cmp::max(64, requested_bytes.div_ceil(1024 * 1024).saturating_add(16));
    let file =
        std::fs::File::create(image).map_err(|error| ApiError::internal(error.to_string()))?;
    file.set_len(image_mib.saturating_mul(1024 * 1024))
        .map_err(|error| ApiError::internal(error.to_string()))?;
    drop(file);
    let status = std::process::Command::new("mkfs.ext4")
        .arg("-q")
        .arg("-F")
        .arg(image)
        .status()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    if !status.success() {
        return Err(ApiError::internal("mkfs.ext4 failed"));
    }
    Ok(())
}

pub(super) fn directory_size_bytes(root: &FsPath) -> Result<u64, ApiError> {
    let mut total = 0u64;
    let mut stack = VecDeque::from([root.to_path_buf()]);
    while let Some(path) = stack.pop_front() {
        for entry in
            std::fs::read_dir(&path).map_err(|error| ApiError::internal(error.to_string()))?
        {
            let entry = entry.map_err(|error| ApiError::internal(error.to_string()))?;
            let metadata = entry
                .path()
                .symlink_metadata()
                .map_err(|error| ApiError::internal(error.to_string()))?;
            if metadata.file_type().is_symlink() {
                return Err(ApiError::bad_request(
                    "filesystem trees must not contain symlinks",
                ));
            }
            if metadata.is_dir() {
                stack.push_back(entry.path());
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            } else {
                return Err(ApiError::bad_request(
                    "filesystem trees must contain only regular files and directories",
                ));
            }
        }
    }
    Ok(total)
}

fn validate_firecracker_rootfs_image(image: &FsPath) -> Result<(), ApiError> {
    let required_commands = [
        "sh", "mount", "mkdir", "ln", "rm", "kill", "sleep", "sync", "poweroff",
    ];
    for command in required_commands {
        if !debugfs_command_exists(image, command) {
            return Err(ApiError::bad_request(format!(
                "firecracker rootfs image is missing required guest command '{command}' in /bin, /sbin, /usr/bin, or /usr/sbin"
            )));
        }
    }
    if !debugfs_path_exists(image, "/pepper-guest-agent") {
        return Err(ApiError::bad_request(
            "firecracker rootfs image must contain /pepper-guest-agent for the vsock control plane",
        ));
    }
    if !debugfs_path_is_executable(image, "/pepper-guest-agent") {
        return Err(ApiError::bad_request(
            "firecracker rootfs /pepper-guest-agent must be executable",
        ));
    }
    Ok(())
}

fn debugfs_command_exists(image: &FsPath, command: &str) -> bool {
    ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
        .iter()
        .any(|dir| debugfs_path_is_executable(image, &format!("{dir}/{command}")))
}

fn debugfs_path_exists(image: &FsPath, path: &str) -> bool {
    debugfs_stat(image, path).is_some()
}

fn debugfs_path_is_executable(image: &FsPath, path: &str) -> bool {
    let Some(stat) = debugfs_stat(image, path) else {
        return false;
    };
    [
        "0755", "0775", "0777", "0555", "0700", "0711", "0750", "0511",
    ]
    .iter()
    .any(|mode| stat.contains(mode))
}

fn debugfs_stat(image: &FsPath, path: &str) -> Option<String> {
    let output = std::process::Command::new("debugfs")
        .arg("-R")
        .arg(format!("stat {path}"))
        .arg(image)
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}

fn debugfs_dump(image: &FsPath, source: &str, max_bytes: u64) -> Result<Vec<u8>, ApiError> {
    let temp = image.with_extension(format!("dump-{}", source.trim_start_matches('/')));
    let status = std::process::Command::new("debugfs")
        .arg("-R")
        .arg(format!(
            "dump {source} {}",
            debugfs_quote(&temp.display().to_string())
        ))
        .arg(image)
        .status()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    if !status.success() {
        return Err(ApiError::internal("debugfs dump failed"));
    }
    let metadata =
        std::fs::metadata(&temp).map_err(|error| ApiError::internal(error.to_string()))?;
    if metadata.len() > max_bytes {
        let _ = std::fs::remove_file(&temp);
        return Err(ApiError::bad_request(format!(
            "debugfs output {source} exceeds limit {max_bytes}"
        )));
    }
    let bytes = std::fs::read(&temp).map_err(|error| ApiError::internal(error.to_string()))?;
    let _ = std::fs::remove_file(&temp);
    Ok(bytes)
}

fn debugfs_rdump(image: &FsPath, source: &str, target: &FsPath) -> Result<(), ApiError> {
    let status = std::process::Command::new("debugfs")
        .arg("-R")
        .arg(format!(
            "rdump {source} {}",
            debugfs_quote(&target.display().to_string())
        ))
        .arg(image)
        .status()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    if !status.success() {
        return Err(ApiError::internal("debugfs rdump failed"));
    }
    Ok(())
}

fn debugfs_runtime_symlinks(image: &FsPath) -> Result<(), ApiError> {
    for (link, target) in [
        ("/output", "/pepper_runtime/output"),
        ("/pepper_progress", "/pepper_runtime/pepper_progress"),
        ("/pepper_status", "/pepper_runtime/pepper_status"),
        ("/pepper_cancel", "/pepper_runtime/pepper_cancel"),
    ] {
        if !debugfs_path_exists(image, link) {
            debugfs_command(image, &format!("symlink {link} {target}"))?;
        }
    }
    Ok(())
}

fn debugfs_write_tree(image: &FsPath, source_root: &FsPath) -> Result<(), ApiError> {
    let mut stack = VecDeque::from([source_root.to_path_buf()]);
    while let Some(path) = stack.pop_front() {
        for entry in
            std::fs::read_dir(&path).map_err(|error| ApiError::internal(error.to_string()))?
        {
            let entry = entry.map_err(|error| ApiError::internal(error.to_string()))?;
            let path = entry.path();
            let relative = path
                .strip_prefix(source_root)
                .map_err(|error| ApiError::internal(error.to_string()))?;
            let guest_path = format!("/{}", relative.display());
            if path.is_dir() {
                let _ = debugfs_command(image, &format!("mkdir {guest_path}"));
                stack.push_back(path);
            } else if path.is_file() {
                if debugfs_path_exists(image, &guest_path) {
                    debugfs_command(image, &format!("rm {guest_path}"))?;
                }
                debugfs_command(
                    image,
                    &format!(
                        "write {} {guest_path}",
                        debugfs_quote(&path.display().to_string())
                    ),
                )?;
                if guest_path == "/init" || guest_path == "/job.sh" {
                    debugfs_command(image, &format!("sif {guest_path} mode 0100755"))?;
                }
            }
        }
    }
    Ok(())
}

fn debugfs_command(image: &FsPath, command: &str) -> Result<(), ApiError> {
    let status = std::process::Command::new("debugfs")
        .arg("-w")
        .arg("-R")
        .arg(command)
        .arg(image)
        .status()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    if !status.success() {
        return Err(ApiError::internal(format!(
            "debugfs command failed: {command}"
        )));
    }
    Ok(())
}

fn debugfs_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('\"', "\\\""))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
async fn logical_cid_size(state: &AppState, root: &Cid) -> Result<u64, ApiError> {
    let mut total = 0u64;
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([root.clone()]);
    while let Some(cid) = queue.pop_front() {
        if !seen.insert(cid.clone()) {
            continue;
        }
        if seen.len() > 100_000 {
            return Err(ApiError::bad_request(
                "compute input DAG exceeds the 100000-block safety limit",
            ));
        }
        match cid.codec {
            CODEC_RAW => {
                let block = get_block_resolved(state, &cid).await?;
                total = total
                    .checked_add(block.size)
                    .ok_or_else(|| ApiError::bad_request("compute input size overflow"))?;
            }
            CODEC_OBJECT_MANIFEST => {
                let block = get_block_resolved(state, &cid).await?;
                let manifest: ObjectManifest =
                    serde_json::from_slice(&block.payload).map_err(ApiError::serde)?;
                validate_object_resource_limits(state, &manifest)?;
                total = total
                    .checked_add(manifest.size)
                    .ok_or_else(|| ApiError::bad_request("compute input size overflow"))?;
            }
            CODEC_ERASURE_MANIFEST => {
                let block = get_block_resolved(state, &cid).await?;
                let manifest: ErasureManifest =
                    serde_json::from_slice(&block.payload).map_err(ApiError::serde)?;
                validate_erasure_resource_limits(state, &manifest)?;
                total = total
                    .checked_add(manifest.size)
                    .ok_or_else(|| ApiError::bad_request("compute input size overflow"))?;
            }
            CODEC_DIR_MANIFEST => {
                let block = get_block_resolved(state, &cid).await?;
                let manifest: DirManifest =
                    serde_json::from_slice(&block.payload).map_err(ApiError::serde)?;
                manifest.validate().map_err(ApiError::manifest)?;
                queue.extend(manifest.entries.into_iter().filter_map(|entry| entry.cid));
            }
            _ => return Err(ApiError::bad_request("unsupported compute input codec")),
        }
    }
    Ok(total)
}

async fn materialize_cid_to_path(
    state: &AppState,
    cid: &Cid,
    path: &FsPath,
) -> Result<(), ApiError> {
    match cid.codec {
        CODEC_DIR_MANIFEST => restore_dir_manifest(state, cid, path).await,
        CODEC_OBJECT_MANIFEST | CODEC_ERASURE_MANIFEST => {
            let bytes = object_bytes(state, cid).await?;
            write_bytes(path, &bytes)
        }
        CODEC_RAW => {
            let block = get_block_resolved(state, cid).await?;
            write_bytes(path, &block.payload)
        }
        _ => Err(ApiError::bad_request("unsupported compute input codec")),
    }
}
