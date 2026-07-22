// SPDX-License-Identifier: Apache-2.0

//! Authenticated, bounded, payload-redacted operational diagnostics.

use super::*;
use serde::Serialize;

const DIAGNOSTIC_VERSION: u8 = 1;
const DEFAULT_PAGE_LIMIT: usize = 100;
const MAX_PAGE_LIMIT: usize = 256;
const MAX_PROTECTION_ROOTS: usize = 128;

struct LocalDiagnosticResolver<'a> {
    state: &'a AppState,
}

#[async_trait]
impl DagBlockResolver for LocalDiagnosticResolver<'_> {
    async fn resolve(&self, cid: &Cid) -> Result<Vec<u8>, String> {
        self.state
            .block_store
            .get(cid)
            .map(|block| block.payload)
            .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct PageQuery {
    limit: Option<usize>,
    after: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct IntentQuery {
    limit: Option<usize>,
    after: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct RepairQuery {
    limit: Option<usize>,
    after: Option<u64>,
}

#[derive(Debug, Serialize)]
struct DiagnosticEnvelope<T> {
    diagnostic_version: u8,
    node_id: String,
    observed_at_unix_seconds: i64,
    consistency: &'static str,
    data: T,
}

fn envelope<T: Serialize>(state: &AppState, data: T) -> Json<DiagnosticEnvelope<T>> {
    Json(DiagnosticEnvelope {
        diagnostic_version: DIAGNOSTIC_VERSION,
        node_id: state.status.node_id.clone(),
        observed_at_unix_seconds: unix_seconds(),
        consistency: "local",
        data,
    })
}

fn bounded_text(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

fn page_limit(limit: Option<usize>) -> Result<usize, ApiError> {
    let limit = limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if !(1..=MAX_PAGE_LIMIT).contains(&limit) {
        return Err(ApiError::bad_request(format!(
            "diagnostic page limit must be between 1 and {MAX_PAGE_LIMIT}"
        )));
    }
    Ok(limit)
}

pub(super) async fn block_inventory(
    State(state): State<AppState>,
    Query(query): Query<PageQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let limit = page_limit(query.limit)?;
    let after = query
        .after
        .as_deref()
        .map(BlockStore::parse_cid)
        .transpose()?;
    let page = state.block_store.inventory_page(after.as_ref(), limit)?;
    Ok(envelope(&state, page))
}

#[derive(Debug, Serialize)]
struct ProtectionReason {
    class: &'static str,
    root_cid: Cid,
    relation: &'static str,
    detail: String,
}

pub(super) async fn gc_explain(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let cid = BlockStore::parse_cid(&cid)?;
    let pins = active_pins(&state)?;
    let staging = state
        .publication_repository
        .active_staging(unix_seconds())
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let reads = state
        .publication_repository
        .active_read_leases(unix_seconds())
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let publication_roots = state
        .publication_repository
        .protected_roots(unix_seconds())
        .map_err(|error| ApiError::internal(error.to_string()))?;

    let mut roots = Vec::<(&'static str, Cid, String)>::new();
    roots.extend(
        pins.into_iter()
            .map(|pin| ("pin", pin.root_cid, format!("active pin {}", pin.pin_id))),
    );
    roots.extend(staging.into_iter().flat_map(|lease| {
        lease.roots.into_iter().map(move |root| {
            (
                "staging_lease",
                root,
                format!("active staging lease {}", lease.lease_id),
            )
        })
    }));
    roots.extend(reads.into_iter().map(|lease| {
        (
            "read_lease",
            lease.root_cid,
            format!("active read lease {}", lease.lease_id),
        )
    }));
    roots.extend(publication_roots.into_iter().map(|root| {
        (
            "namespace_publication",
            root,
            "active publication protection".to_string(),
        )
    }));
    roots.sort_by(|left, right| {
        left.0
            .cmp(right.0)
            .then_with(|| left.1.to_string().cmp(&right.1.to_string()))
    });
    roots.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
    let truncated = roots.len() > MAX_PROTECTION_ROOTS;
    roots.truncate(MAX_PROTECTION_ROOTS);

    let mut reasons = Vec::new();
    let mut timed_out = false;
    let mut incomplete = false;
    for (class, root, detail) in &roots {
        let relation = if root == &cid {
            Some("root")
        } else {
            match tokio::time::timeout(
                Duration::from_secs(2),
                pepper_dag::traverse(
                    &state.dag_registry,
                    &LocalDiagnosticResolver { state: &state },
                    root.clone(),
                    TraversalLimits {
                        max_blocks: 100_000,
                        max_depth: 1_024,
                        max_links_per_block: 1_000_000,
                        max_total_links: 1_000_000,
                        max_payload_bytes: state.max_block_bytes.unwrap_or(DEFAULT_MAX_BLOCK_BYTES)
                            as usize,
                        max_total_payload_bytes: 1024 * 1024 * 1024,
                    },
                ),
            )
            .await
            {
                Ok(Ok(traversal)) if traversal.cids.contains(&cid) => Some("descendant"),
                Ok(Ok(_)) => None,
                Ok(Err(_)) => {
                    incomplete = true;
                    None
                }
                Err(_) => {
                    timed_out = true;
                    None
                }
            }
        };
        if let Some(relation) = relation {
            reasons.push(ProtectionReason {
                class,
                root_cid: root.clone(),
                relation,
                detail: detail.clone(),
            });
        }
    }
    let determination = if !reasons.is_empty() {
        "protected"
    } else if truncated || timed_out || incomplete {
        "indeterminate"
    } else {
        "unprotected"
    };
    Ok(envelope(
        &state,
        serde_json::json!({
            "cid":cid,
            "local_present":state.block_store.has(&cid)?,
            "determination":determination,
            "reasons":reasons,
            "roots_examined":roots.len(),
            "truncated":truncated,
            "timed_out":timed_out,
            "incomplete":incomplete
        }),
    ))
}

#[derive(Debug, Serialize)]
struct IntentDiagnostic {
    intent_id: String,
    namespace_id: NamespaceId,
    log_index: u64,
    cid: Cid,
    action: PinAction,
    reason: String,
    status: String,
    created_at_unix_seconds: i64,
}

pub(super) async fn publication_intents(
    State(state): State<AppState>,
    Query(query): Query<IntentQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let limit = page_limit(query.limit)?;
    if query
        .after
        .as_ref()
        .is_some_and(|cursor| cursor.len() > 256)
    {
        return Err(ApiError::bad_request(
            "publication diagnostic cursor exceeds 256 bytes",
        ));
    }
    if query
        .status
        .as_deref()
        .is_some_and(|status| !matches!(status, "pending" | "applied" | "resolved"))
    {
        return Err(ApiError::bad_request(
            "publication status must be pending, applied, or resolved",
        ));
    }
    let all = state
        .publication_repository
        .all_intents()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let mut status_counts = BTreeMap::<String, usize>::new();
    for intent in &all {
        let status = if matches!(intent.status.as_str(), "pending" | "applied" | "resolved") {
            intent.status.clone()
        } else {
            "unknown".to_string()
        };
        *status_counts.entry(status).or_default() += 1;
    }
    let mut selected = all
        .into_iter()
        .filter(|intent| {
            query
                .status
                .as_ref()
                .is_none_or(|status| &intent.status == status)
                && query
                    .after
                    .as_ref()
                    .is_none_or(|after| &intent.intent_id > after)
        })
        .take(limit + 1)
        .collect::<Vec<_>>();
    let has_more = selected.len() > limit;
    selected.truncate(limit);
    let entries = selected
        .into_iter()
        .map(|intent| IntentDiagnostic {
            intent_id: bounded_text(intent.intent_id, 256),
            namespace_id: intent.namespace_id,
            log_index: intent.log_index,
            cid: intent.cid,
            action: intent.action,
            reason: bounded_text(intent.reason, 128),
            status: bounded_text(intent.status, 32),
            created_at_unix_seconds: intent.created_at_unix_seconds,
        })
        .collect::<Vec<_>>();
    let next_cursor = has_more
        .then(|| entries.last().map(|intent| intent.intent_id.clone()))
        .flatten();
    Ok(envelope(
        &state,
        serde_json::json!({
            "entries":entries,
            "next_cursor":next_cursor,
            "status_counts":status_counts
        }),
    ))
}

pub(super) async fn provider_diagnostic(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let cid = BlockStore::parse_cid(&cid)?;
    let now = unix_seconds();
    let peers = state
        .network
        .peers()
        .await
        .into_iter()
        .map(|peer| (peer.node_id.clone(), peer))
        .collect::<HashMap<_, _>>();
    let providers = state
        .network
        .local_provider_records(&cid)?
        .into_iter()
        .take(MAX_PAGE_LIMIT)
        .map(|provider| {
            let peer = peers.get(&provider.node_id);
            serde_json::json!({
                "node_id":provider.node_id,
                "addresses":provider.addresses.into_iter().take(8).collect::<Vec<_>>(),
                "expires_at_unix_seconds":provider.expires_at_unix_seconds,
                "not_expired":provider.expires_at_unix_seconds > now,
                "known_peer":peer.is_some() || provider.node_id == state.status.node_id,
                "connected":peer.is_some_and(|peer| peer.connected),
                "failure_domain":peer.and_then(|peer| peer.failure_domain.clone())
            })
        })
        .collect::<Vec<_>>();
    Ok(envelope(
        &state,
        serde_json::json!({
            "cid":cid,
            "local_present":state.block_store.has(&cid)?,
            "providers":providers
        }),
    ))
}

pub(super) async fn erasure_diagnostic(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let cid = BlockStore::parse_cid(&cid)?;
    if cid.codec != CODEC_ERASURE_MANIFEST {
        return Err(ApiError::bad_request("CID is not an erasure manifest"));
    }
    let block = state.block_store.get(&cid)?;
    let manifest: ErasureManifest =
        serde_json::from_slice(&block.payload).map_err(ApiError::serde)?;
    manifest.validate().map_err(ApiError::manifest)?;
    let now = unix_seconds();
    let peers = state
        .network
        .peers()
        .await
        .into_iter()
        .map(|peer| (peer.node_id.clone(), peer))
        .collect::<HashMap<_, _>>();
    let mut shards = Vec::with_capacity(
        manifest
            .stripes
            .iter()
            .map(|stripe| stripe.shards.len())
            .sum(),
    );
    for (stripe_index, stripe) in manifest.stripes.iter().enumerate() {
        for shard in &stripe.shards {
            let local_present = state.block_store.has(&shard.cid)?;
            let local_verified = if local_present {
                state
                    .block_store
                    .get(&shard.cid)
                    .is_ok_and(|block| block.size == shard.size && shard.cid.verify(&block.payload))
            } else {
                false
            };
            let providers = state
                .network
                .local_provider_records(&shard.cid)?
                .into_iter()
                .take(MAX_PAGE_LIMIT)
                .map(|provider| {
                    let peer = peers.get(&provider.node_id);
                    serde_json::json!({
                        "node_id":provider.node_id,
                        "expires_at_unix_seconds":provider.expires_at_unix_seconds,
                        "not_expired":provider.expires_at_unix_seconds > now,
                        "connected":peer.is_some_and(|peer| peer.connected),
                        "failure_domain":peer.and_then(|peer| peer.failure_domain.clone())
                    })
                })
                .collect::<Vec<_>>();
            shards.push(serde_json::json!({
                "stripe_index":stripe_index,
                "stripe_offset":stripe.offset,
                "index":shard.index,
                "cid":shard.cid,
                "expected_size_bytes":shard.size,
                "local_present":local_present,
                "local_verified":local_verified,
                "providers":providers
            }));
        }
    }
    Ok(envelope(
        &state,
        serde_json::json!({
            "manifest_cid":cid,
            "logical_size_bytes":manifest.size,
            "data_shards":manifest.data_shards,
            "parity_shards":manifest.parity_shards,
            "stripe_size_bytes":manifest.stripe_size,
            "stripe_count":manifest.stripes.len(),
            "shards":shards
        }),
    ))
}

pub(super) async fn read_resolution_diagnostic(
    State(state): State<AppState>,
    Path(cid): Path<String>,
    Query(query): Query<RepairQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let cid = BlockStore::parse_cid(&cid)?;
    let limit = page_limit(query.limit)?;
    let mut records = state
        .read_diagnostics
        .lock()
        .map_err(|_| ApiError::internal("read diagnostic lock poisoned"))?
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    if let Some(runtime) = &state.fast_path {
        records.extend(runtime.read_diagnostics());
    }
    records.sort_by_key(|record| record.sequence);
    let mut entries = records
        .into_iter()
        .filter(|record| {
            record.cid == cid && query.after.is_none_or(|after| record.sequence > after)
        })
        .take(limit.saturating_add(1))
        .collect::<Vec<_>>();
    let has_more = entries.len() > limit;
    entries.truncate(limit);
    let next_cursor = has_more
        .then(|| entries.last().map(|record| record.sequence))
        .flatten();
    Ok(envelope(
        &state,
        serde_json::json!({"entries":entries,"next_cursor":next_cursor,"retained_capacity":512}),
    ))
}

pub(super) async fn repair_diagnostic(
    State(state): State<AppState>,
    Query(query): Query<RepairQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let limit = page_limit(query.limit)?;
    let records = state
        .repair_diagnostics
        .lock()
        .map_err(|_| ApiError::internal("repair diagnostic lock poisoned"))?;
    let mut entries = records
        .iter()
        .filter(|record| query.after.is_none_or(|after| record.sequence > after))
        .take(limit.saturating_add(1))
        .cloned()
        .collect::<Vec<_>>();
    let has_more = entries.len() > limit;
    entries.truncate(limit);
    let next_cursor = has_more
        .then(|| entries.last().map(|record| record.sequence))
        .flatten();
    Ok(envelope(
        &state,
        serde_json::json!({
            "entries":entries,
            "next_cursor":next_cursor,
            "retained_capacity":512,
        }),
    ))
}

pub(super) async fn network_rpc_diagnostic(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(envelope(
        &state,
        serde_json::json!({"metrics":state.network.rpc_metrics()}),
    ))
}

pub(super) async fn namespace_replica_diagnostic(
    State(state): State<AppState>,
    Query(query): Query<PageQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let limit = page_limit(query.limit)?;
    let after = query
        .after
        .as_deref()
        .map(BlockStore::parse_cid)
        .transpose()?
        .map(NamespaceId::new)
        .transpose()
        .map_err(namespace_error)?
        .map(|namespace_id| namespace_id.to_string());
    let (mut groups, command_metrics) = if let Some(manager) = &state.namespace_groups {
        (
            manager.operational_statuses().await,
            manager.command_metrics().await,
        )
    } else {
        (Vec::new(), Vec::new())
    };
    if let Some(after) = after {
        groups.retain(|group| group.namespace_id.to_string() > after);
    }
    let has_more = groups.len() > limit;
    groups.truncate(limit);
    let next_cursor = has_more
        .then(|| groups.last().map(|group| group.namespace_id.to_string()))
        .flatten();
    Ok(envelope(
        &state,
        serde_json::json!({
            "groups":groups,
            "next_cursor":next_cursor,
            "command_metrics":command_metrics,
            "commands_redacted":true
        }),
    ))
}
