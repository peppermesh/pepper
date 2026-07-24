// SPDX-License-Identifier: Apache-2.0

//! Replica and erasure repair service boundary.

use super::*;
use pepper_merkle::ScanQuery;
use pepper_namespace::{
    CommandEnvelope, KeyPrecondition, NamespaceCommand, NamespaceKind, NamespaceMutation,
    TransactionCommand,
};
use pepper_placement::{
    DEFAULT_REPAIR_OWNER_COUNT, select_repair_owners, select_repair_replacement,
};
use std::{collections::BTreeSet, future::Future, pin::Pin};
use tracing::debug;

const REPAIR_INVENTORY_PREFIX: &[u8] = b"\xffs3/repair/inventory/v1/";
const REPAIR_INVENTORY_DESCRIPTOR_PLACEMENT: &str = "descriptor_placement";
const REPAIR_INVENTORY_CONTENT_CID: &str = "content_cid";
const REPAIR_INVENTORY_CONTENT_PLACEMENT: &str = "content_placement";
const REPAIR_INVENTORY_LOGICAL_SIZE: &str = "logical_size";
const REPAIR_INVENTORY_COMMITTED_AT: &str = "committed_at_unix_seconds";
const LOCAL_REPAIR_INVENTORY: TableDefinition<&str, &[u8]> =
    TableDefinition::new("placement_repair_inventory");
const LOCAL_REPAIR_INVENTORY_CURSORS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("placement_repair_inventory_cursors");
const REPAIR_LEASE_PREFIX: &[u8] = b"\xffs3/repair/lease/v1/";
const REPAIR_LEASE_RECORD_METADATA: &str = "repair_lease";
const REPAIR_LEASE_SECONDS: i64 = 60;
const REPAIR_LEASE_RENEWAL_SECONDS: u64 = 20;
const REPAIR_HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

fn repair_request_id() -> String {
    let mut nonce = [0u8; 16];
    if getrandom::fill(&mut nonce).is_ok() {
        return format!("pepper-repair-{}", hex::encode(nonce));
    }
    format!("pepper-repair-{}", unix_seconds())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RepairInventoryCursor {
    placement_epoch: u64,
    last_event_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RepairLeaseRecord {
    inventory_key: String,
    task_id: String,
    owner_node_id: String,
    placement_epoch: u64,
    fence: u64,
    acquired_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
enum PlacementRepairTask {
    Replicated {
        block: PlacedCid,
        destination_node_id: String,
        temporary: bool,
    },
    ErasureShard {
        manifest: PlacedCid,
        repair_reference: PlacementReference,
        stripe_index: usize,
        shard_index: u16,
        destination_node_id: String,
        temporary: bool,
    },
}

#[derive(Debug)]
struct ErasureRepairTarget {
    block: PlacedCid,
    repair_reference: PlacementReference,
    stripe_index: usize,
    shard_index: u16,
}

#[derive(Debug)]
enum RepairInventoryLayout {
    Direct,
    Object(Vec<PlacedCid>),
    Erasure(Vec<ErasureRepairTarget>),
}

#[derive(Debug)]
struct RepairInventoryPlan {
    inventory: RepairInventoryRecord,
    layout: RepairInventoryLayout,
}

impl RepairInventoryPlan {
    fn placed_blocks(&self) -> Vec<&PlacedCid> {
        let mut blocks = vec![&self.inventory.descriptor];
        if let Some(content) = self.inventory.content.as_ref() {
            blocks.push(content);
        }
        match &self.layout {
            RepairInventoryLayout::Direct => {}
            RepairInventoryLayout::Object(chunks) => blocks.extend(chunks.iter()),
            RepairInventoryLayout::Erasure(shards) => {
                blocks.extend(shards.iter().map(|target| &target.block));
            }
        }
        blocks
    }
}

#[derive(Default)]
struct RepairHealthSnapshot {
    present: HashMap<(String, Cid), bool>,
}

impl RepairHealthSnapshot {
    fn contains(&self, node_id: &str, cid: &Cid) -> bool {
        self.present
            .get(&(node_id.to_string(), cid.clone()))
            .copied()
            .unwrap_or(false)
    }
}

impl PlacementRepairTask {
    fn destination_node_id(&self) -> &str {
        match self {
            Self::Replicated {
                destination_node_id,
                ..
            }
            | Self::ErasureShard {
                destination_node_id,
                ..
            } => destination_node_id,
        }
    }

    fn task_id(&self) -> Result<String, ApiError> {
        let encoded = serde_json::to_vec(self).map_err(ApiError::serde)?;
        Ok(hex::encode(blake3::hash(&encoded).as_bytes()))
    }

    fn temporary(&self) -> bool {
        match self {
            Self::Replicated { temporary, .. } | Self::ErasureShard { temporary, .. } => *temporary,
        }
    }

    fn owner_reference(&self) -> &PlacementReference {
        match self {
            Self::Replicated { block, .. } => &block.placement,
            Self::ErasureShard {
                repair_reference, ..
            } => repair_reference,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RepairLeaseToken {
    namespace_id: NamespaceId,
    lease_key: Vec<u8>,
    generation: u64,
    value_cid: Cid,
    lease: RepairLeaseRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct RepairExecutionRequest {
    inventory: RepairInventoryRecord,
    lease: RepairLeaseToken,
    task: PlacementRepairTask,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct RepairInventoryRecord {
    pub(super) namespace_id: NamespaceId,
    pub(super) event_key: Vec<u8>,
    pub(super) revision: u64,
    pub(super) descriptor: PlacedCid,
    pub(super) content: Option<PlacedCid>,
    pub(super) logical_size: u64,
    pub(super) committed_at_unix_seconds: i64,
}

impl RepairInventoryRecord {
    fn cache_key(&self) -> String {
        format!("{}:{}", self.namespace_id, hex::encode(&self.event_key))
    }
}

pub(super) fn initialize_repair_inventory_tables(state: &AppState) -> Result<(), ApiError> {
    let write = state
        .metadata
        .database()
        .begin_write()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    {
        let _inventory = write
            .open_table(LOCAL_REPAIR_INVENTORY)
            .map_err(|error| ApiError::internal(error.to_string()))?;
        let _cursors = write
            .open_table(LOCAL_REPAIR_INVENTORY_CURSORS)
            .map_err(|error| ApiError::internal(error.to_string()))?;
    }
    write
        .commit()
        .map_err(|error| ApiError::internal(error.to_string()))
}

fn persist_local_repair_inventory(
    state: &AppState,
    record: &RepairInventoryRecord,
) -> Result<bool, ApiError> {
    Ok(persist_local_repair_inventory_batch(state, std::slice::from_ref(record))? > 0)
}

fn persist_local_repair_inventory_batch(
    state: &AppState,
    records: &[RepairInventoryRecord],
) -> Result<u64, ApiError> {
    if records.is_empty() {
        return Ok(0);
    }
    let encoded = records
        .iter()
        .map(|record| {
            Ok((
                record.cache_key(),
                serde_json::to_vec(record).map_err(ApiError::serde)?,
            ))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let write = state
        .metadata
        .database()
        .begin_write()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let inserted = {
        let mut table = write
            .open_table(LOCAL_REPAIR_INVENTORY)
            .map_err(|error| ApiError::internal(error.to_string()))?;
        let mut inserted = 0u64;
        for (cache_key, encoded) in &encoded {
            let existed = table
                .get(cache_key.as_str())
                .map_err(|error| ApiError::internal(error.to_string()))?
                .is_some();
            table
                .insert(cache_key.as_str(), encoded.as_slice())
                .map_err(|error| ApiError::internal(error.to_string()))?;
            inserted = inserted.saturating_add(u64::from(!existed));
        }
        inserted
    };
    write
        .commit()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok(inserted)
}

fn local_repair_inventory(state: &AppState) -> Result<Vec<RepairInventoryRecord>, ApiError> {
    let read = state
        .metadata
        .database()
        .begin_read()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let table = read
        .open_table(LOCAL_REPAIR_INVENTORY)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let mut records = Vec::<RepairInventoryRecord>::new();
    for entry in table
        .iter()
        .map_err(|error| ApiError::internal(error.to_string()))?
    {
        let (_, value) = entry.map_err(|error| ApiError::internal(error.to_string()))?;
        records.push(serde_json::from_slice(value.value()).map_err(ApiError::serde)?);
    }
    records.sort_by_key(RepairInventoryRecord::cache_key);
    Ok(records)
}

fn local_repair_inventory_record(
    state: &AppState,
    cache_key: &str,
) -> Result<Option<RepairInventoryRecord>, ApiError> {
    let read = state
        .metadata
        .database()
        .begin_read()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let table = read
        .open_table(LOCAL_REPAIR_INVENTORY)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    table
        .get(cache_key)
        .map_err(|error| ApiError::internal(error.to_string()))?
        .map(|value| serde_json::from_slice(value.value()).map_err(ApiError::serde))
        .transpose()
}

fn repair_inventory_cursor(
    state: &AppState,
    namespace_id: &NamespaceId,
) -> Result<Option<RepairInventoryCursor>, ApiError> {
    let read = state
        .metadata
        .database()
        .begin_read()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let table = read
        .open_table(LOCAL_REPAIR_INVENTORY_CURSORS)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    table
        .get(namespace_id.to_string().as_str())
        .map_err(|error| ApiError::internal(error.to_string()))?
        .map(|value| serde_json::from_slice(value.value()).map_err(ApiError::serde))
        .transpose()
}

fn persist_repair_inventory_cursor(
    state: &AppState,
    namespace_id: &NamespaceId,
    cursor: &RepairInventoryCursor,
) -> Result<(), ApiError> {
    let encoded = serde_json::to_vec(cursor).map_err(ApiError::serde)?;
    let key = namespace_id.to_string();
    let write = state
        .metadata
        .database()
        .begin_write()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    {
        let mut table = write
            .open_table(LOCAL_REPAIR_INVENTORY_CURSORS)
            .map_err(|error| ApiError::internal(error.to_string()))?;
        table
            .insert(key.as_str(), encoded.as_slice())
            .map_err(|error| ApiError::internal(error.to_string()))?;
    }
    write
        .commit()
        .map_err(|error| ApiError::internal(error.to_string()))
}

pub(super) fn repair_inventory_mutation(
    revision: u64,
    descriptor: PlacedCid,
    content: Option<PlacedCid>,
    logical_size: u64,
    committed_at_unix_seconds: i64,
) -> Result<NamespaceMutation, ApiError> {
    if revision == 0 {
        return Err(ApiError::internal(
            "repair inventory revision must be nonzero",
        ));
    }
    descriptor
        .placement
        .validate()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    if descriptor.placement.seed != descriptor.cid {
        return Err(ApiError::bad_request(
            "repair inventory descriptor placement does not match its CID",
        ));
    }
    if let Some(content) = &content {
        content
            .placement
            .validate()
            .map_err(|error| ApiError::bad_request(error.to_string()))?;
        if content.placement.role == PlacementRole::Replicated
            && content.placement.seed != content.cid
        {
            return Err(ApiError::bad_request(
                "repair inventory content placement does not match its CID",
            ));
        }
    }
    let mut key = REPAIR_INVENTORY_PREFIX.to_vec();
    key.extend_from_slice(format!("{revision:016x}/{}", descriptor.cid).as_bytes());
    let mut metadata = BTreeMap::from([
        (
            REPAIR_INVENTORY_DESCRIPTOR_PLACEMENT.to_string(),
            serde_json::to_string(&descriptor.placement).map_err(ApiError::serde)?,
        ),
        (
            REPAIR_INVENTORY_LOGICAL_SIZE.to_string(),
            logical_size.to_string(),
        ),
        (
            REPAIR_INVENTORY_COMMITTED_AT.to_string(),
            committed_at_unix_seconds.to_string(),
        ),
    ]);
    if let Some(content) = content {
        metadata.insert(
            REPAIR_INVENTORY_CONTENT_CID.to_string(),
            content.cid.to_string(),
        );
        metadata.insert(
            REPAIR_INVENTORY_CONTENT_PLACEMENT.to_string(),
            serde_json::to_string(&content.placement).map_err(ApiError::serde)?,
        );
    }
    Ok(NamespaceMutation::Put {
        key_hex: hex::encode(key),
        value_cid: descriptor.cid,
        value_kind: "repair_inventory".to_string(),
        metadata,
        precondition: KeyPrecondition::Absent,
    })
}

fn repair_inventory_from_entry(
    namespace_id: &NamespaceId,
    key: Vec<u8>,
    value: &pepper_merkle::MerkleValue,
) -> Result<RepairInventoryRecord, ApiError> {
    if value.value_kind != "repair_inventory" || !key.starts_with(REPAIR_INVENTORY_PREFIX) {
        return Err(ApiError::internal("invalid repair inventory entry"));
    }
    let suffix = &key[REPAIR_INVENTORY_PREFIX.len()..];
    let revision_end = suffix
        .iter()
        .position(|byte| *byte == b'/')
        .ok_or_else(|| ApiError::internal("repair inventory key omits revision"))?;
    let revision = std::str::from_utf8(&suffix[..revision_end])
        .ok()
        .and_then(|encoded| u64::from_str_radix(encoded, 16).ok())
        .filter(|revision| *revision > 0)
        .ok_or_else(|| ApiError::internal("repair inventory key has invalid revision"))?;
    let descriptor_placement: PlacementReference = serde_json::from_str(
        value
            .metadata
            .get(REPAIR_INVENTORY_DESCRIPTOR_PLACEMENT)
            .ok_or_else(|| ApiError::internal("repair inventory omits descriptor placement"))?,
    )
    .map_err(ApiError::serde)?;
    let descriptor = PlacedCid::new(value.cid.clone(), descriptor_placement)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let content = match (
        value.metadata.get(REPAIR_INVENTORY_CONTENT_CID),
        value.metadata.get(REPAIR_INVENTORY_CONTENT_PLACEMENT),
    ) {
        (None, None) => None,
        (Some(cid), Some(placement)) => {
            let cid = cid
                .parse::<Cid>()
                .map_err(|error| ApiError::internal(error.to_string()))?;
            let placement =
                serde_json::from_str::<PlacementReference>(placement).map_err(ApiError::serde)?;
            Some(
                PlacedCid::new(cid, placement)
                    .map_err(|error| ApiError::internal(error.to_string()))?,
            )
        }
        _ => {
            return Err(ApiError::internal(
                "repair inventory content reference is incomplete",
            ));
        }
    };
    let logical_size = value
        .metadata
        .get(REPAIR_INVENTORY_LOGICAL_SIZE)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| ApiError::internal("repair inventory has invalid logical size"))?;
    let committed_at_unix_seconds = value
        .metadata
        .get(REPAIR_INVENTORY_COMMITTED_AT)
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| ApiError::internal("repair inventory has invalid commit time"))?;
    Ok(RepairInventoryRecord {
        namespace_id: namespace_id.clone(),
        event_key: key,
        revision,
        descriptor,
        content,
        logical_size,
        committed_at_unix_seconds,
    })
}

/// Return every independently coordinated repair unit reachable from one
/// partition inventory event. Replicated blocks retain their own reference;
/// every erasure stripe contributes one index-normalized reference shared by
/// all of its shards. This list drives inventory delivery and authorization,
/// so no stripe depends on the coordinator chosen for its manifest.
async fn inventory_repair_references(
    state: &AppState,
    inventory: &RepairInventoryRecord,
) -> Result<Vec<PlacementReference>, ApiError> {
    let mut references = vec![inventory.descriptor.placement.clone()];
    let Some(content) = inventory.content.as_ref() else {
        return Ok(references);
    };
    references.push(content.placement.clone());
    if !matches!(
        content.cid.codec,
        CODEC_OBJECT_MANIFEST | CODEC_ERASURE_MANIFEST
    ) {
        return Ok(references);
    }
    let (root, _) = fetch_repair_source(state, content, &state.status.node_id).await?;
    match root.codec {
        CODEC_OBJECT_MANIFEST => {
            let manifest: ObjectManifest =
                serde_json::from_slice(&root.payload).map_err(ApiError::serde)?;
            manifest
                .validate()
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            references.extend(manifest.chunks.into_iter().map(|chunk| chunk.placement));
        }
        CODEC_ERASURE_MANIFEST => {
            let manifest: ErasureManifest =
                serde_json::from_slice(&root.payload).map_err(ApiError::serde)?;
            validate_erasure_resource_limits(state, &manifest)?;
            for stripe in manifest.stripes {
                let epoch = stripe
                    .shards
                    .first()
                    .ok_or_else(|| ApiError::internal("erasure stripe has no shards"))?
                    .placement
                    .epoch;
                references.push(PlacementReference::erasure_shard(
                    epoch,
                    stripe.logical_cid,
                    0,
                ));
            }
        }
        _ => {}
    }
    let mut seen = HashSet::new();
    references.retain(|reference| seen.insert(reference.clone()));
    let role_rank = |role: PlacementRole| match role {
        PlacementRole::Replicated => 0u8,
        PlacementRole::ErasureShard => 1u8,
    };
    references.sort_by(|left, right| {
        left.epoch
            .cmp(&right.epoch)
            .then_with(|| role_rank(left.role).cmp(&role_rank(right.role)))
            .then_with(|| left.seed.to_string().cmp(&right.seed.to_string()))
            .then_with(|| left.index.cmp(&right.index))
            .then_with(|| left.replicas.cmp(&right.replicas))
    });
    Ok(references)
}

pub(super) async fn accept_repair_inventory(
    state: &AppState,
    authenticated_node: &str,
    inventory_json: &str,
) -> Result<(), ApiError> {
    let proposed: Vec<RepairInventoryRecord> =
        serde_json::from_str(inventory_json).map_err(ApiError::serde)?;
    if proposed.is_empty() || proposed.len() > 512 {
        return Err(ApiError::bad_request(
            "repair inventory batch must contain between 1 and 512 records",
        ));
    }
    let namespace_id = proposed[0].namespace_id.clone();
    if proposed.iter().any(|record| {
        record.namespace_id != namespace_id
            || !record.event_key.starts_with(REPAIR_INVENTORY_PREFIX)
    }) {
        return Err(ApiError::bad_request(
            "repair inventory batch mixes namespaces or contains an invalid event key",
        ));
    }
    let manager = namespace_manager(state)?;
    let namespace = manager
        .linearizable_namespace_state(&namespace_id)
        .await
        .map_err(consensus_error)?;
    let store = super::s3_api::direct_namespace_store(state, &namespace).await;
    let (_, voters) = manager.known_namespace_route(&namespace_id).await;
    let sender_is_voter = voters.iter().any(|node| node == authenticated_node);
    let map = if sender_is_voter {
        None
    } else {
        Some(
            state
                .placement
                .current_map()
                .ok_or_else(|| ApiError::internal("authoritative placement map is not loaded"))?,
        )
    };
    let mut committed_batch = Vec::with_capacity(proposed.len());
    for proposed in proposed {
        let value = pepper_merkle::get(
            &store,
            &namespace.current_root_cid,
            &proposed.event_key,
            pepper_merkle::MerkleLimits::default(),
        )
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or_else(|| ApiError::bad_request("repair inventory event is not committed"))?;
        let committed = repair_inventory_from_entry(
            &proposed.namespace_id,
            proposed.event_key.clone(),
            &value,
        )?;
        if committed != proposed {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "repair inventory does not match committed partition state",
            ));
        }
        if !sender_is_voter {
            let selected_owner = inventory_repair_references(state, &committed)
                .await?
                .iter()
                .any(|reference| {
                    select_repair_owners(
                        map.as_deref().expect("non-voter map is loaded"),
                        reference,
                        DEFAULT_REPAIR_OWNER_COUNT,
                    )
                    .is_ok_and(|owners| owners.iter().any(|node| node == authenticated_node))
                });
            if !selected_owner {
                return Err(ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    ErrorCode::Unauthorized,
                    "repair inventory sender is neither a namespace voter nor a selected block/stripe repair owner",
                ));
            }
        }
        committed_batch.push(committed);
    }
    let inserted = persist_local_repair_inventory_batch(state, &committed_batch)?;
    metrics::PLACEMENT_REPAIR_INVENTORY_EVENTS.fetch_add(inserted, Ordering::Relaxed);
    Ok(())
}

async fn dispatch_repair_inventory_batch(
    state: &AppState,
    records: &[RepairInventoryRecord],
) -> Result<(), ApiError> {
    if records.is_empty() {
        return Ok(());
    }
    let inserted = persist_local_repair_inventory_batch(state, records)?;
    metrics::PLACEMENT_REPAIR_INVENTORY_EVENTS.fetch_add(inserted, Ordering::Relaxed);
    let map = state.placement.current_map().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "authoritative placement map is not loaded",
        )
    })?;
    let mut records_by_owner = BTreeMap::<String, Vec<RepairInventoryRecord>>::new();
    for record in records {
        let mut owners = BTreeSet::new();
        for reference in inventory_repair_references(state, record).await? {
            owners.extend(
                select_repair_owners(&map, &reference, DEFAULT_REPAIR_OWNER_COUNT)
                    .map_err(authoritative_placement_error)?,
            );
        }
        for owner in owners {
            records_by_owner
                .entry(owner)
                .or_default()
                .push(record.clone());
        }
    }
    let mut unavailable = Vec::new();
    for (owner, owner_records) in records_by_owner {
        if owner == state.status.node_id {
            continue;
        }
        let Some(address) = state.network.peer_address(&owner).await else {
            unavailable.push(owner);
            continue;
        };
        let encoded = serde_json::to_string(&owner_records).map_err(ApiError::serde)?;
        match time::timeout(
            Duration::from_secs(10),
            state.network.push_repair_inventory(address, encoded),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                metrics::PLACEMENT_REPAIR_INVENTORY_PUSH_ERRORS.fetch_add(1, Ordering::Relaxed);
                warn!(%error, owner_node = %owner, "repair inventory push failed");
                unavailable.push(owner);
            }
            Err(_) => {
                metrics::PLACEMENT_REPAIR_INVENTORY_PUSH_ERRORS.fetch_add(1, Ordering::Relaxed);
                warn!(owner_node = %owner, "repair inventory push timed out");
                unavailable.push(owner);
            }
        }
    }
    if unavailable.is_empty() {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            format!(
                "repair inventory standby delivery is incomplete: {}",
                unavailable.join(",")
            ),
        ))
    }
}

async fn sync_namespace_repair_inventory(
    state: &AppState,
    namespace: &NamespaceState,
) -> Result<u64, ApiError> {
    let placement_epoch = state
        .placement
        .current_map()
        .ok_or_else(|| ApiError::internal("authoritative placement map is not loaded"))?
        .epoch;
    let saved = repair_inventory_cursor(state, &namespace.namespace_id)?;
    let mut last_event_key = saved
        .filter(|cursor| cursor.placement_epoch == placement_epoch)
        .map_or_else(
            || REPAIR_INVENTORY_PREFIX.to_vec(),
            |cursor| cursor.last_event_key,
        );
    let mut start = last_event_key.clone();
    start.push(0);
    let store = super::s3_api::direct_namespace_store(state, namespace).await;
    let mut page_cursor = None;
    let mut dispatched = 0u64;
    loop {
        let page = pepper_merkle::scan(
            &store,
            &namespace.current_root_cid,
            ScanQuery {
                start: Some(start.clone()),
                prefix: Some(REPAIR_INVENTORY_PREFIX.to_vec()),
                limit: 512,
                cursor: page_cursor,
                ..ScanQuery::default()
            },
            pepper_merkle::MerkleLimits::default(),
        )
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
        let next_cursor = page.next_cursor;
        let mut records = Vec::with_capacity(page.entries.len());
        for entry in page.entries {
            records.push(repair_inventory_from_entry(
                &namespace.namespace_id,
                entry.key.clone(),
                &entry.value,
            )?);
            last_event_key = entry.key;
        }
        dispatch_repair_inventory_batch(state, &records).await?;
        dispatched = dispatched.saturating_add(records.len() as u64);
        persist_repair_inventory_cursor(
            state,
            &namespace.namespace_id,
            &RepairInventoryCursor {
                placement_epoch,
                last_event_key: last_event_key.clone(),
            },
        )?;
        let Some(next) = next_cursor else {
            break;
        };
        page_cursor = Some(next);
    }
    Ok(dispatched)
}

async fn sync_partition_repair_inventory(state: &AppState) -> Result<u64, ApiError> {
    let Some(groups) = state.namespace_groups.as_ref() else {
        return Ok(0);
    };
    let mut dispatched = 0u64;
    for namespace in groups.local_leader_namespace_states().await {
        if namespace.descriptor.kind != NamespaceKind::Bucket {
            continue;
        }
        dispatched =
            dispatched.saturating_add(sync_namespace_repair_inventory(state, &namespace).await?);
    }
    Ok(dispatched)
}

async fn committed_repair_lease(
    state: &AppState,
    namespace: &NamespaceState,
    lease_key: &[u8],
) -> Result<Option<(pepper_merkle::MerkleValue, RepairLeaseRecord)>, ApiError> {
    let Some(value) = pepper_merkle::get(
        &super::s3_api::direct_namespace_store(state, namespace).await,
        &namespace.current_root_cid,
        lease_key,
        pepper_merkle::MerkleLimits::default(),
    )
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?
    else {
        return Ok(None);
    };
    if value.value_kind != "repair_lease" {
        return Err(ApiError::internal(
            "repair lease key contains an unexpected value kind",
        ));
    }
    let lease: RepairLeaseRecord = serde_json::from_str(
        value
            .metadata
            .get(REPAIR_LEASE_RECORD_METADATA)
            .ok_or_else(|| ApiError::internal("repair lease metadata is missing"))?,
    )
    .map_err(ApiError::serde)?;
    let encoded = serde_json::to_vec(&lease).map_err(ApiError::serde)?;
    if Cid::new(CODEC_RAW, &encoded) != value.cid {
        return Err(ApiError::internal("repair lease CID is invalid"));
    }
    Ok(Some((value, lease)))
}

fn repair_lease_key(task_id: &str) -> Vec<u8> {
    let mut key = REPAIR_LEASE_PREFIX.to_vec();
    key.extend_from_slice(task_id.as_bytes());
    key
}

fn next_repair_fence(current: Option<&RepairLeaseRecord>, now: i64) -> Option<u64> {
    if current.is_some_and(|lease| lease.expires_at_unix_seconds > now) {
        return None;
    }
    Some(current.map_or(1, |lease| lease.fence.saturating_add(1)))
}

async fn acquire_repair_lease(
    state: &AppState,
    inventory: &RepairInventoryRecord,
    task: &PlacementRepairTask,
) -> Result<Option<RepairLeaseToken>, ApiError> {
    let task_id = task.task_id()?;
    let lease_key = repair_lease_key(&task_id);
    for _ in 0..8 {
        let placement_map = state
            .placement
            .current_map()
            .ok_or_else(|| ApiError::internal("authoritative placement map is not loaded"))?;
        let repair_owners = select_repair_owners(
            &placement_map,
            task.owner_reference(),
            DEFAULT_REPAIR_OWNER_COUNT,
        )
        .map_err(authoritative_placement_error)?;
        if !repair_owners.contains(&state.status.node_id) {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                ErrorCode::Unauthorized,
                "node is not a selected repair owner for this block or stripe",
            ));
        }
        let base = namespace_manager(state)?
            .linearizable_namespace_state(&inventory.namespace_id)
            .await
            .map_err(consensus_error)?;
        let current = committed_repair_lease(state, &base, &lease_key).await?;
        let now = unix_seconds();
        let Some(fence) = next_repair_fence(current.as_ref().map(|(_, lease)| lease), now) else {
            return Ok(None);
        };
        let lease = RepairLeaseRecord {
            inventory_key: inventory.cache_key(),
            task_id: task_id.clone(),
            owner_node_id: state.status.node_id.clone(),
            placement_epoch: placement_map.epoch,
            fence,
            acquired_at_unix_seconds: now,
            expires_at_unix_seconds: now.saturating_add(REPAIR_LEASE_SECONDS),
        };
        let encoded = serde_json::to_vec(&lease).map_err(ApiError::serde)?;
        let value_cid = Cid::new(CODEC_RAW, &encoded);
        let precondition = current
            .as_ref()
            .map_or(KeyPrecondition::Absent, |(value, _)| {
                KeyPrecondition::Match {
                    generation: value.generation,
                    cid: value.cid.clone(),
                }
            });
        let command = CommandEnvelope {
            request_id: repair_request_id(),
            writer_identity: "placement-repair-owner".to_string(),
            timestamp_unix_seconds: now,
            signature_hex: "00".to_string(),
            command: NamespaceCommand::ApplyTransaction {
                transaction: TransactionCommand {
                    base_revision: base.current_revision,
                    base_root_cid: base.current_root_cid,
                    mutations: vec![NamespaceMutation::Put {
                        key_hex: hex::encode(&lease_key),
                        value_cid: value_cid.clone(),
                        value_kind: "repair_lease".to_string(),
                        metadata: BTreeMap::from([(
                            REPAIR_LEASE_RECORD_METADATA.to_string(),
                            serde_json::to_string(&lease).map_err(ApiError::serde)?,
                        )]),
                        precondition,
                    }],
                    message: Some("placement repair lease".to_string()),
                },
            },
        };
        match apply_command_with_metadata_only(
            state,
            inventory.namespace_id.clone(),
            command,
            CommandPublicationInputs {
                uploaded_roots: Vec::new(),
                preverified_durability: Vec::new(),
                metadata_only_cids: vec![value_cid],
                staged_bytes: encoded.len() as u64,
                retain_uploaded_on_conflict: false,
            },
        )
        .await
        {
            Ok(_) => {
                let committed_state = namespace_manager(state)?
                    .linearizable_namespace_state(&inventory.namespace_id)
                    .await
                    .map_err(consensus_error)?;
                let (value, committed) =
                    committed_repair_lease(state, &committed_state, &lease_key)
                        .await?
                        .ok_or_else(|| ApiError::internal("committed repair lease is missing"))?;
                if committed != lease {
                    return Ok(None);
                }
                metrics::PLACEMENT_REPAIR_LEASES_ACQUIRED.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(RepairLeaseToken {
                    namespace_id: inventory.namespace_id.clone(),
                    lease_key,
                    generation: value.generation,
                    value_cid: value.cid,
                    lease: committed,
                }));
            }
            Err(error)
                if matches!(
                    error.code,
                    ErrorCode::Conflict | ErrorCode::GenerationConflict
                ) =>
            {
                metrics::PLACEMENT_REPAIR_LEASE_CONFLICTS.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

async fn renew_repair_lease(
    state: &AppState,
    token: &RepairLeaseToken,
) -> Result<RepairLeaseToken, ApiError> {
    for _ in 0..8 {
        let base = namespace_manager(state)?
            .linearizable_namespace_state(&token.namespace_id)
            .await
            .map_err(consensus_error)?;
        let Some((value, current)) = committed_repair_lease(state, &base, &token.lease_key).await?
        else {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "repair lease disappeared before renewal",
            ));
        };
        let now = unix_seconds();
        if current.owner_node_id != token.lease.owner_node_id
            || current.inventory_key != token.lease.inventory_key
            || current.task_id != token.lease.task_id
            || current.placement_epoch != token.lease.placement_epoch
            || current.fence != token.lease.fence
            || current.expires_at_unix_seconds <= now
        {
            metrics::PLACEMENT_REPAIR_FENCE_REJECTIONS.fetch_add(1, Ordering::Relaxed);
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "repair lease was fenced before renewal",
            ));
        }
        let renewed = RepairLeaseRecord {
            expires_at_unix_seconds: now.saturating_add(REPAIR_LEASE_SECONDS),
            ..current
        };
        let encoded = serde_json::to_vec(&renewed).map_err(ApiError::serde)?;
        let value_cid = Cid::new(CODEC_RAW, &encoded);
        let command = CommandEnvelope {
            request_id: repair_request_id(),
            writer_identity: "placement-repair-owner".to_string(),
            timestamp_unix_seconds: now,
            signature_hex: "00".to_string(),
            command: NamespaceCommand::ApplyTransaction {
                transaction: TransactionCommand {
                    base_revision: base.current_revision,
                    base_root_cid: base.current_root_cid,
                    mutations: vec![NamespaceMutation::Put {
                        key_hex: hex::encode(&token.lease_key),
                        value_cid: value_cid.clone(),
                        value_kind: "repair_lease".to_string(),
                        metadata: BTreeMap::from([(
                            REPAIR_LEASE_RECORD_METADATA.to_string(),
                            serde_json::to_string(&renewed).map_err(ApiError::serde)?,
                        )]),
                        precondition: KeyPrecondition::Match {
                            generation: value.generation,
                            cid: value.cid,
                        },
                    }],
                    message: Some("placement repair lease renewal".to_string()),
                },
            },
        };
        match apply_command_with_metadata_only(
            state,
            token.namespace_id.clone(),
            command,
            CommandPublicationInputs {
                uploaded_roots: Vec::new(),
                preverified_durability: Vec::new(),
                metadata_only_cids: vec![value_cid],
                staged_bytes: encoded.len() as u64,
                retain_uploaded_on_conflict: false,
            },
        )
        .await
        {
            Ok(_) => {
                let committed_state = namespace_manager(state)?
                    .linearizable_namespace_state(&token.namespace_id)
                    .await
                    .map_err(consensus_error)?;
                let (value, lease) =
                    committed_repair_lease(state, &committed_state, &token.lease_key)
                        .await?
                        .ok_or_else(|| ApiError::internal("renewed repair lease is missing"))?;
                if lease != renewed {
                    return Err(ApiError::new(
                        StatusCode::CONFLICT,
                        ErrorCode::Conflict,
                        "repair lease renewal was superseded",
                    ));
                }
                metrics::PLACEMENT_REPAIR_LEASE_RENEWALS.fetch_add(1, Ordering::Relaxed);
                return Ok(RepairLeaseToken {
                    namespace_id: token.namespace_id.clone(),
                    lease_key: token.lease_key.clone(),
                    generation: value.generation,
                    value_cid: value.cid,
                    lease,
                });
            }
            Err(error)
                if matches!(
                    error.code,
                    ErrorCode::Conflict | ErrorCode::GenerationConflict
                ) =>
            {
                metrics::PLACEMENT_REPAIR_LEASE_CONFLICTS.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => return Err(error),
        }
    }
    Err(ApiError::new(
        StatusCode::CONFLICT,
        ErrorCode::Conflict,
        "repair lease renewal remained busy",
    ))
}

async fn validate_repair_execution(
    state: &AppState,
    authenticated_node: &str,
    request: &RepairExecutionRequest,
) -> Result<(), ApiError> {
    if request.task.destination_node_id() != state.status.node_id
        || request.lease.namespace_id != request.inventory.namespace_id
        || request.lease.lease.owner_node_id != authenticated_node
        || request.lease.lease.inventory_key != request.inventory.cache_key()
        || request.lease.lease.task_id != request.task.task_id()?
        || request.lease.lease_key != repair_lease_key(&request.lease.lease.task_id)
        || Cid::new(
            CODEC_RAW,
            &serde_json::to_vec(&request.lease.lease).map_err(ApiError::serde)?,
        ) != request.lease.value_cid
    {
        metrics::PLACEMENT_REPAIR_FENCE_REJECTIONS.fetch_add(1, Ordering::Relaxed);
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Unauthorized,
            "repair execution lease is invalid",
        ));
    }
    let lease_map = state
        .placement
        .map(request.lease.lease.placement_epoch)
        .ok_or_else(|| ApiError::internal("repair lease placement map is unavailable"))?;
    let selected_owner = select_repair_owners(
        &lease_map,
        request.task.owner_reference(),
        DEFAULT_REPAIR_OWNER_COUNT,
    )
    .map_err(authoritative_placement_error)?
    .into_iter()
    .any(|owner| owner == authenticated_node);
    if !selected_owner {
        metrics::PLACEMENT_REPAIR_FENCE_REJECTIONS.fetch_add(1, Ordering::Relaxed);
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Unauthorized,
            "repair lease owner is not selected for this block or stripe",
        ));
    }
    if local_repair_inventory_record(state, &request.inventory.cache_key())?.as_ref()
        != Some(&request.inventory)
    {
        metrics::PLACEMENT_REPAIR_FENCE_REJECTIONS.fetch_add(1, Ordering::Relaxed);
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::Conflict,
            "repair inventory is not installed on the destination",
        ));
    }
    let namespace = namespace_manager(state)?
        .linearizable_namespace_state(&request.lease.namespace_id)
        .await
        .map_err(consensus_error)?;
    let (value, lease) = committed_repair_lease(state, &namespace, &request.lease.lease_key)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "repair lease is no longer committed",
            )
        })?;
    if value.generation < request.lease.generation
        || lease.owner_node_id != request.lease.lease.owner_node_id
        || lease.inventory_key != request.lease.lease.inventory_key
        || lease.task_id != request.lease.lease.task_id
        || lease.placement_epoch != request.lease.lease.placement_epoch
        || lease.fence != request.lease.lease.fence
        || lease.expires_at_unix_seconds <= unix_seconds()
    {
        metrics::PLACEMENT_REPAIR_FENCE_REJECTIONS.fetch_add(1, Ordering::Relaxed);
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::Conflict,
            "repair lease was superseded",
        ));
    }
    Ok(())
}

fn repair_source_affinity(
    map: &PlacementMap,
    source_node_id: &str,
    destination_node_id: &str,
) -> usize {
    let Some(source) = map.nodes.iter().find(|node| node.node_id == source_node_id) else {
        return 0;
    };
    let Some(destination) = map
        .nodes
        .iter()
        .find(|node| node.node_id == destination_node_id)
    else {
        return 0;
    };
    map.failure_domain_levels
        .iter()
        .take_while(|level| {
            source.failure_domains.get(*level) == destination.failure_domains.get(*level)
        })
        .count()
}

async fn fetch_repair_source(
    state: &AppState,
    block: &PlacedCid,
    destination_node_id: &str,
) -> Result<(pepper_types::Block, String), ApiError> {
    if state.placement.map(block.placement.epoch).is_none() && state.s3.is_some() {
        s3_api::ensure_s3_placement_epoch_loaded(state, block.placement.epoch).await?;
    }
    metrics::PLACEMENT_CALCULATIONS.fetch_add(1, Ordering::Relaxed);
    let mut source_nodes = state
        .placement
        .decide(&block.placement)
        .map_err(authoritative_placement_error)?
        .node_ids;
    if let Some(exception) = state
        .placement
        .exception(&block.placement, unix_seconds())
        .filter(|exception| exception.block_cid == block.cid)
    {
        for node_id in exception.node_ids {
            if !source_nodes.contains(&node_id) {
                source_nodes.push(node_id);
            }
        }
    }
    let topology = state
        .placement
        .current_map()
        .or_else(|| state.placement.map(block.placement.epoch))
        .ok_or_else(|| ApiError::internal("repair source placement map is unavailable"))?;
    source_nodes.sort_by(|left, right| {
        repair_source_affinity(&topology, right, destination_node_id)
            .cmp(&repair_source_affinity(
                &topology,
                left,
                destination_node_id,
            ))
            .then_with(|| left.cmp(right))
    });
    let mut failures = Vec::new();
    for source_node_id in source_nodes {
        if source_node_id == state.status.node_id {
            match state.block_store.get(&block.cid) {
                Ok(block) => return Ok((block, source_node_id)),
                Err(error) => {
                    failures.push(format!("{source_node_id}:{error}"));
                    continue;
                }
            }
        }
        let Some(address) = state.network.peer_address(&source_node_id).await else {
            failures.push(format!("{source_node_id}:no-address"));
            continue;
        };
        metrics::PLACEMENT_DIRECT_TARGET_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        match time::timeout(
            Duration::from_secs(5),
            state.network.block_get(address, &block.cid),
        )
        .await
        {
            Ok(Ok(payload)) if block.cid.verify(&payload) => {
                metrics::PLACEMENT_DIRECT_TARGET_BYTES
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                return Ok((
                    pepper_types::Block {
                        cid: block.cid.clone(),
                        codec: block.cid.codec,
                        size: payload.len() as u64,
                        payload,
                    },
                    source_node_id,
                ));
            }
            Ok(Ok(_)) => failures.push(format!("{source_node_id}:hash-mismatch")),
            Ok(Err(error)) => failures.push(format!("{source_node_id}:{error}")),
            Err(_) => failures.push(format!("{source_node_id}:timeout")),
        }
    }
    metrics::PLACEMENT_DIRECT_TARGET_ERRORS.fetch_add(1, Ordering::Relaxed);
    Err(ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::Unavailable,
        format!(
            "no canonical or exception repair source holds {}: {}",
            block.cid,
            failures.join(",")
        ),
    ))
}

fn local_is_repair_destination(
    state: &AppState,
    block_cid: &Cid,
    placement: &PlacementReference,
    temporary: bool,
) -> Result<bool, ApiError> {
    let canonical = state
        .placement
        .decide(placement)
        .map_err(authoritative_placement_error)?
        .node_ids;
    if canonical.contains(&state.status.node_id) {
        return Ok(true);
    }
    if state
        .placement
        .exception(placement, unix_seconds())
        .filter(|exception| exception.block_cid == *block_cid)
        .is_some_and(|exception| exception.node_ids.contains(&state.status.node_id))
    {
        return Ok(true);
    }
    if !temporary {
        return Ok(false);
    }
    let map = state
        .placement
        .current_map()
        .ok_or_else(|| ApiError::internal("authoritative placement map is not loaded"))?;
    Ok(select_repair_replacement(&map, placement, &canonical)
        .map_err(authoritative_placement_error)?
        == state.status.node_id)
}

pub(super) async fn execute_placement_repair(
    state: &AppState,
    authenticated_node: &str,
    request: RepairExecutionRequest,
) -> Result<proto::RepairExecuteResponse, ApiError> {
    validate_repair_execution(state, authenticated_node, &request).await?;
    let _permit = state
        .erasure_repair_semaphore
        .acquire()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    match &request.task {
        PlacementRepairTask::Replicated {
            block, temporary, ..
        } => {
            if !local_is_repair_destination(state, &block.cid, &block.placement, *temporary)? {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    ErrorCode::Conflict,
                    "repair destination is not canonical or an explicit exception",
                ));
            }
            if state.block_store.has(&block.cid)? {
                return Ok(proto::RepairExecuteResponse {
                    repaired: false,
                    already_healthy: true,
                    verified_bytes: 0,
                    source_node_ids: Vec::new(),
                });
            }
            let (source, source_node_id) =
                fetch_repair_source(state, block, &state.status.node_id).await?;
            throttle_erasure_repair(state, source.payload.len()).await;
            validate_repair_execution(state, authenticated_node, &request).await?;
            let put = state
                .repair_block_writer
                .put_verified(source.codec, source.payload, block.cid.clone())
                .await
                .map_err(ApiError::internal)?;
            if put.cid != block.cid {
                return Err(ApiError::internal(
                    "replicated repair stored an unexpected CID",
                ));
            }
            Ok(proto::RepairExecuteResponse {
                repaired: !put.already_existed,
                already_healthy: put.already_existed,
                verified_bytes: put.size,
                source_node_ids: vec![source_node_id],
            })
        }
        PlacementRepairTask::ErasureShard {
            manifest,
            repair_reference,
            stripe_index,
            shard_index,
            temporary,
            ..
        } => {
            let (manifest_block, manifest_source) =
                fetch_repair_source(state, manifest, &state.status.node_id).await?;
            let manifest_value: ErasureManifest =
                serde_json::from_slice(&manifest_block.payload).map_err(ApiError::serde)?;
            validate_erasure_resource_limits(state, &manifest_value)?;
            let stripe = manifest_value
                .stripes
                .get(*stripe_index)
                .ok_or_else(|| ApiError::bad_request("repair stripe index is invalid"))?;
            let target = stripe
                .shards
                .iter()
                .find(|shard| shard.index == *shard_index)
                .ok_or_else(|| ApiError::bad_request("repair shard index is invalid"))?;
            let expected_repair_reference = PlacementReference::erasure_shard(
                target.placement.epoch,
                stripe.logical_cid.clone(),
                0,
            );
            if repair_reference != &expected_repair_reference {
                return Err(ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    ErrorCode::Unauthorized,
                    "repair task coordinator does not match its erasure stripe",
                ));
            }
            if !local_is_repair_destination(state, &target.cid, &target.placement, *temporary)? {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    ErrorCode::Conflict,
                    "erasure repair destination is not canonical or an explicit exception",
                ));
            }
            if state.block_store.has(&target.cid)? {
                return Ok(proto::RepairExecuteResponse {
                    repaired: false,
                    already_healthy: true,
                    verified_bytes: 0,
                    source_node_ids: vec![manifest_source],
                });
            }
            let data_shards = manifest_value.data_shards as usize;
            let parity_shards = manifest_value.parity_shards as usize;
            let mut shards = vec![None::<Vec<u8>>; data_shards + parity_shards];
            let mut source_node_ids = vec![manifest_source];
            let mut fetched_bytes = 0usize;
            for shard in &stripe.shards {
                if shard.index == *shard_index || shards.iter().flatten().count() >= data_shards {
                    continue;
                }
                let placed = PlacedCid {
                    cid: shard.cid.clone(),
                    placement: shard.placement.clone(),
                };
                if let Ok((source, source_node_id)) =
                    fetch_repair_source(state, &placed, &state.status.node_id).await
                {
                    if source.payload.len() != stripe.shard_size as usize {
                        continue;
                    }
                    fetched_bytes = fetched_bytes.saturating_add(source.payload.len());
                    shards[shard.index as usize] = Some(source.payload);
                    source_node_ids.push(source_node_id);
                }
            }
            if shards.iter().flatten().count() < data_shards {
                return Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::Unavailable,
                    "not enough canonical or exception shards for destination reconstruction",
                ));
            }
            ReedSolomon::new(data_shards, parity_shards)
                .map_err(|error| ApiError::internal(error.to_string()))?
                .reconstruct(&mut shards)
                .map_err(|error| ApiError::internal(error.to_string()))?;
            let payload = shards
                .get_mut(*shard_index as usize)
                .and_then(Option::take)
                .ok_or_else(|| ApiError::internal("destination reconstruction omitted shard"))?;
            if !target.cid.verify(&payload) {
                return Err(ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::IntegrityFailure,
                    "destination reconstruction produced an invalid shard",
                ));
            }
            throttle_erasure_repair(state, fetched_bytes.saturating_add(payload.len())).await;
            validate_repair_execution(state, authenticated_node, &request).await?;
            let put = state
                .repair_block_writer
                .put_verified(target.cid.codec, payload, target.cid.clone())
                .await
                .map_err(ApiError::internal)?;
            source_node_ids.sort();
            source_node_ids.dedup();
            ERASURE_SHARD_REPAIRS.fetch_add(1, Ordering::Relaxed);
            metrics::PLACEMENT_REPAIR_DESTINATION_RECONSTRUCTIONS.fetch_add(1, Ordering::Relaxed);
            Ok(proto::RepairExecuteResponse {
                repaired: !put.already_existed,
                already_healthy: put.already_existed,
                verified_bytes: put.size,
                source_node_ids,
            })
        }
    }
}

pub(super) async fn cleanup_expired_repair_extra(
    state: &AppState,
    exception: PlacementException,
) -> Result<bool, ApiError> {
    if exception.expires_at_unix_seconds > unix_seconds()
        || !exception.node_ids.contains(&state.status.node_id)
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::Conflict,
            "repair extra is not an expired local exception",
        ));
    }
    let committed = committed_placement_exception(state, &exception.reference).await?;
    if committed.as_ref() != Some(&exception) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::Conflict,
            "repair exception was renewed or superseded",
        ));
    }
    if state.placement.map(exception.reference.epoch).is_none() {
        s3_api::ensure_s3_placement_epoch_loaded(state, exception.reference.epoch).await?;
    }
    let canonical = state
        .placement
        .decide(&exception.reference)
        .map_err(authoritative_placement_error)?
        .node_ids;
    if canonical.contains(&state.status.node_id) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::Conflict,
            "repair extra became canonical and cannot be collected",
        ));
    }
    for node_id in canonical {
        if !placement_target_is_healthy(state, &node_id, &exception.block_cid).await? {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Unavailable,
                "canonical placement is not healthy enough to collect repair extra",
            ));
        }
    }
    let removed = state
        .block_store
        .delete_repair_extra(&exception.block_cid)?;
    if removed {
        metrics::PLACEMENT_REPAIR_STALE_EXTRAS_COLLECTED.fetch_add(1, Ordering::Relaxed);
    }
    Ok(removed)
}

pub(super) async fn collect_expired_repair_exception(
    state: &AppState,
    exception: &PlacementException,
) -> Result<u64, ApiError> {
    if exception.expires_at_unix_seconds > unix_seconds() {
        return Err(ApiError::bad_request(
            "active repair exception cannot be collected",
        ));
    }
    let encoded = serde_json::to_string(exception).map_err(ApiError::serde)?;
    let mut removed = 0u64;
    for node_id in &exception.node_ids {
        if node_id == &state.status.node_id {
            removed = removed.saturating_add(u64::from(
                cleanup_expired_repair_extra(state, exception.clone()).await?,
            ));
            continue;
        }
        let address = state.network.peer_address(node_id).await.ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Unavailable,
                format!("repair exception node {node_id} is unreachable"),
            )
        })?;
        let deleted = state
            .network
            .cleanup_repair_extra(address, encoded.clone())
            .await
            .map_err(|error| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::Unavailable,
                    error.to_string(),
                )
            })?;
        removed = removed.saturating_add(u64::from(deleted));
    }
    Ok(removed)
}

async fn placement_target_is_healthy(
    state: &AppState,
    node_id: &str,
    cid: &Cid,
) -> Result<bool, ApiError> {
    if node_id == state.status.node_id {
        return state.block_store.has(cid).map_err(ApiError::from);
    }
    let Some(address) = state.network.peer_address(node_id).await else {
        return Ok(false);
    };
    metrics::PLACEMENT_DIRECT_TARGET_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    match time::timeout(
        Duration::from_secs(2),
        state.network.block_has(address, cid),
    )
    .await
    {
        Ok(Ok(healthy)) => Ok(healthy),
        Ok(Err(error)) => {
            warn!(%error, %cid, target_node = %node_id, "repair health probe failed");
            Ok(false)
        }
        Err(_) => {
            warn!(%cid, target_node = %node_id, "repair health probe timed out");
            Ok(false)
        }
    }
}

/// Check an authoritative placement directly, without consulting the legacy
/// provider directory.  Operational diagnostics use the same placement map
/// and bounded exception table as foreground reads and repair planning so a
/// health scrape cannot reintroduce discovery traffic proportional to the
/// number of shards in the cluster.
pub(super) async fn placed_block_is_healthy(
    state: &AppState,
    cid: &Cid,
    reference: &PlacementReference,
) -> Result<bool, ApiError> {
    // Generic block/namespace deployments created without the S3 placement
    // catalog retain their legacy provider-backed erasure manifests. Keep the
    // compatibility diagnostic scoped to those deployments; S3 manifests are
    // always checked from their authoritative placement reference below.
    if state.s3.is_none() && state.placement.map(reference.epoch).is_none() {
        return Ok(!healthy_providers_for_cid(state, cid).await.is_empty());
    }
    if state.placement.map(reference.epoch).is_none() {
        s3_api::ensure_s3_placement_epoch_loaded(state, reference.epoch).await?;
    }
    metrics::PLACEMENT_CALCULATIONS.fetch_add(1, Ordering::Relaxed);
    let canonical = state
        .placement
        .decide(reference)
        .map_err(authoritative_placement_error)?
        .node_ids;
    for node_id in canonical {
        if placement_target_is_healthy(state, &node_id, cid).await? {
            return Ok(true);
        }
    }
    if let Some(exception) = state
        .placement
        .exception(reference, unix_seconds())
        .filter(|exception| exception.block_cid == *cid)
    {
        for node_id in exception.node_ids {
            if placement_target_is_healthy(state, &node_id, cid).await? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

async fn placement_node_is_reachable(state: &AppState, node_id: &str) -> bool {
    if node_id == state.status.node_id {
        return true;
    }
    let Some(address) = state.network.peer_address(node_id).await else {
        return false;
    };
    matches!(
        time::timeout(REPAIR_HEALTH_PROBE_TIMEOUT, state.network.node_info(address)).await,
        Ok(Ok(info)) if info.node_id == node_id
    )
}

async fn repair_plan_for_inventory(
    state: &AppState,
    inventory: RepairInventoryRecord,
) -> Result<RepairInventoryPlan, ApiError> {
    let Some(content) = inventory.content.as_ref() else {
        return Ok(RepairInventoryPlan {
            inventory,
            layout: RepairInventoryLayout::Direct,
        });
    };
    if !matches!(
        content.cid.codec,
        CODEC_OBJECT_MANIFEST | CODEC_ERASURE_MANIFEST
    ) {
        return Ok(RepairInventoryPlan {
            inventory,
            layout: RepairInventoryLayout::Direct,
        });
    }
    let (root, _) = fetch_repair_source(state, content, &state.status.node_id).await?;
    let layout = match root.codec {
        CODEC_OBJECT_MANIFEST => {
            let manifest: ObjectManifest =
                serde_json::from_slice(&root.payload).map_err(ApiError::serde)?;
            manifest
                .validate()
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            RepairInventoryLayout::Object(
                manifest
                    .chunks
                    .into_iter()
                    .map(|chunk| PlacedCid {
                        cid: chunk.cid,
                        placement: chunk.placement,
                    })
                    .collect(),
            )
        }
        CODEC_ERASURE_MANIFEST => {
            let manifest: ErasureManifest =
                serde_json::from_slice(&root.payload).map_err(ApiError::serde)?;
            validate_erasure_resource_limits(state, &manifest)?;
            let mut targets = Vec::new();
            for (stripe_index, stripe) in manifest.stripes.into_iter().enumerate() {
                for shard in stripe.shards {
                    let repair_reference = PlacementReference::erasure_shard(
                        shard.placement.epoch,
                        stripe.logical_cid.clone(),
                        0,
                    );
                    targets.push(ErasureRepairTarget {
                        block: PlacedCid {
                            cid: shard.cid,
                            placement: shard.placement,
                        },
                        repair_reference,
                        stripe_index,
                        shard_index: shard.index,
                    });
                }
            }
            RepairInventoryLayout::Erasure(targets)
        }
        _ => RepairInventoryLayout::Direct,
    };
    Ok(RepairInventoryPlan { inventory, layout })
}

async fn build_repair_health_snapshot(
    state: &AppState,
    plans: &[RepairInventoryPlan],
) -> Result<RepairHealthSnapshot, ApiError> {
    let mut epochs = BTreeSet::new();
    for block in plans.iter().flat_map(RepairInventoryPlan::placed_blocks) {
        epochs.insert(block.placement.epoch);
    }
    for epoch in epochs {
        if state.placement.map(epoch).is_none() {
            s3_api::ensure_s3_placement_epoch_loaded(state, epoch).await?;
        }
    }

    let mut probes = HashMap::<String, HashSet<Cid>>::new();
    let now = unix_seconds();
    for block in plans.iter().flat_map(RepairInventoryPlan::placed_blocks) {
        metrics::PLACEMENT_CALCULATIONS.fetch_add(1, Ordering::Relaxed);
        for node_id in state
            .placement
            .decide(&block.placement)
            .map_err(authoritative_placement_error)?
            .node_ids
        {
            probes.entry(node_id).or_default().insert(block.cid.clone());
        }
        if let Some(exception) = state
            .placement
            .exception(&block.placement, now)
            .filter(|exception| exception.block_cid == block.cid)
        {
            for node_id in exception.node_ids {
                probes.entry(node_id).or_default().insert(block.cid.clone());
            }
        }
    }

    let mut snapshot = RepairHealthSnapshot::default();
    let mut nodes = probes.into_iter().collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.0.cmp(&right.0));
    let mut remote_batches = Vec::<(String, SocketAddr, Vec<Cid>)>::new();
    for (node_id, cids) in nodes {
        let mut cids = cids.into_iter().collect::<Vec<_>>();
        cids.sort_by_key(ToString::to_string);
        if node_id == state.status.node_id {
            for cid in cids {
                snapshot
                    .present
                    .insert((node_id.clone(), cid.clone()), state.block_store.has(&cid)?);
            }
            continue;
        }
        let Some(address) = state.network.peer_address(&node_id).await else {
            for cid in cids {
                snapshot.present.insert((node_id.clone(), cid), false);
            }
            continue;
        };
        remote_batches.extend(
            cids.chunks(pepper_network::MAX_BLOCK_HAS_BATCH_CIDS)
                .map(|batch| (node_id.clone(), address, batch.to_vec())),
        );
    }

    let results = stream::iter(remote_batches)
        .map(|(node_id, address, cids)| async move {
            metrics::PLACEMENT_DIRECT_TARGET_ATTEMPTS
                .fetch_add(cids.len() as u64, Ordering::Relaxed);
            metrics::PLACEMENT_REPAIR_HEALTH_BATCHES.fetch_add(1, Ordering::Relaxed);
            metrics::PLACEMENT_REPAIR_HEALTH_BLOCKS.fetch_add(cids.len() as u64, Ordering::Relaxed);
            let result = time::timeout(
                REPAIR_HEALTH_PROBE_TIMEOUT,
                state.network.block_has_batch(address, &cids),
            )
            .await;
            (node_id, cids, result)
        })
        .buffer_unordered(16)
        .collect::<Vec<_>>()
        .await;
    for (node_id, cids, result) in results {
        match result {
            Ok(Ok(present)) => {
                for (cid, present) in cids.into_iter().zip(present) {
                    snapshot.present.insert((node_id.clone(), cid), present);
                }
            }
            Ok(Err(error)) => {
                metrics::PLACEMENT_REPAIR_HEALTH_BATCH_ERRORS.fetch_add(1, Ordering::Relaxed);
                warn!(%error, target_node = %node_id, blocks = cids.len(), "repair health batch failed");
                for cid in cids {
                    snapshot.present.insert((node_id.clone(), cid), false);
                }
            }
            Err(_) => {
                metrics::PLACEMENT_REPAIR_HEALTH_BATCH_ERRORS.fetch_add(1, Ordering::Relaxed);
                warn!(target_node = %node_id, blocks = cids.len(), "repair health batch timed out");
                for cid in cids {
                    snapshot.present.insert((node_id.clone(), cid), false);
                }
            }
        }
    }
    Ok(snapshot)
}

async fn repair_destination_for_missing(
    state: &AppState,
    health: &RepairHealthSnapshot,
    block: &PlacedCid,
    canonical_node_ids: &[String],
    missing_canonical_node_id: String,
) -> Result<Option<(String, bool)>, ApiError> {
    if placement_node_is_reachable(state, &missing_canonical_node_id).await {
        return Ok(Some((missing_canonical_node_id, false)));
    }
    if let Some(exception) = state
        .placement
        .exception(&block.placement, unix_seconds())
        .filter(|exception| exception.block_cid == block.cid)
    {
        let renewal_window = i64::try_from(state.repair_interval.as_secs().saturating_mul(2))
            .unwrap_or(i64::MAX)
            .max(30);
        for node_id in exception.node_ids {
            if health.contains(&node_id, &block.cid) {
                if exception.expires_at_unix_seconds > unix_seconds().saturating_add(renewal_window)
                {
                    return Ok(None);
                }
                return Ok(Some((node_id, true)));
            }
            if placement_node_is_reachable(state, &node_id).await {
                return Ok(Some((node_id, true)));
            }
        }
    }
    let map = state
        .placement
        .current_map()
        .ok_or_else(|| ApiError::internal("authoritative placement map is not loaded"))?;
    let replacement = select_repair_replacement(&map, &block.placement, canonical_node_ids)
        .map_err(authoritative_placement_error)?;
    Ok(Some((replacement, true)))
}

async fn missing_canonical_targets(
    state: &AppState,
    health: &RepairHealthSnapshot,
    block: &PlacedCid,
) -> Result<Vec<(String, bool)>, ApiError> {
    if state.placement.map(block.placement.epoch).is_none() {
        s3_api::ensure_s3_placement_epoch_loaded(state, block.placement.epoch).await?;
    }
    metrics::PLACEMENT_CALCULATIONS.fetch_add(1, Ordering::Relaxed);
    let targets = state
        .placement
        .decide(&block.placement)
        .map_err(authoritative_placement_error)?
        .node_ids;
    let mut missing = Vec::new();
    for target in &targets {
        if !health.contains(target, &block.cid) {
            if let Some(destination) =
                repair_destination_for_missing(state, health, block, &targets, target.clone())
                    .await?
            {
                missing.push(destination);
            }
        }
    }
    Ok(missing)
}

async fn repair_tasks_for_placed_block(
    state: &AppState,
    health: &RepairHealthSnapshot,
    block: &PlacedCid,
    tasks: &mut Vec<PlacementRepairTask>,
) -> Result<(), ApiError> {
    for (destination_node_id, temporary) in missing_canonical_targets(state, health, block).await? {
        tasks.push(PlacementRepairTask::Replicated {
            block: block.clone(),
            destination_node_id,
            temporary,
        });
    }
    Ok(())
}

async fn repair_tasks_for_inventory(
    state: &AppState,
    health: &RepairHealthSnapshot,
    plan: &RepairInventoryPlan,
) -> Result<Vec<PlacementRepairTask>, ApiError> {
    let mut tasks = Vec::new();
    repair_tasks_for_placed_block(state, health, &plan.inventory.descriptor, &mut tasks).await?;
    let Some(content) = plan.inventory.content.as_ref() else {
        return Ok(tasks);
    };
    repair_tasks_for_placed_block(state, health, content, &mut tasks).await?;
    match &plan.layout {
        RepairInventoryLayout::Direct => {}
        RepairInventoryLayout::Object(chunks) => {
            for chunk in chunks {
                repair_tasks_for_placed_block(state, health, chunk, &mut tasks).await?;
            }
        }
        RepairInventoryLayout::Erasure(shards) => {
            for shard in shards {
                let canonical = state
                    .placement
                    .decide(&shard.block.placement)
                    .map_err(authoritative_placement_error)?
                    .node_ids;
                let canonical_target = canonical.first().cloned().ok_or_else(|| {
                    ApiError::internal("erasure shard has no canonical destination")
                })?;
                if health.contains(&canonical_target, &shard.block.cid) {
                    continue;
                }
                if let Some((destination_node_id, temporary)) = repair_destination_for_missing(
                    state,
                    health,
                    &shard.block,
                    &canonical,
                    canonical_target,
                )
                .await?
                {
                    tasks.push(PlacementRepairTask::ErasureShard {
                        manifest: content.clone(),
                        repair_reference: shard.repair_reference.clone(),
                        stripe_index: shard.stripe_index,
                        shard_index: shard.shard_index,
                        destination_node_id,
                        temporary,
                    });
                }
            }
        }
    }
    let mut seen = HashSet::new();
    tasks.retain(|task| task.task_id().is_ok_and(|task_id| seen.insert(task_id)));
    Ok(tasks)
}

async fn ensure_inventory_on_destination(
    state: &AppState,
    inventory: &RepairInventoryRecord,
    destination_node_id: &str,
) -> Result<(), ApiError> {
    if destination_node_id == state.status.node_id {
        let _ = persist_local_repair_inventory(state, inventory)?;
        return Ok(());
    }
    let address = state
        .network
        .peer_address(destination_node_id)
        .await
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Unavailable,
                "repair destination has no authenticated address",
            )
        })?;
    let encoded =
        serde_json::to_string(std::slice::from_ref(inventory)).map_err(ApiError::serde)?;
    state
        .network
        .push_repair_inventory(address, encoded)
        .await
        .map_err(|error| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Unavailable,
                error.to_string(),
            )
        })
}

async fn dispatch_placement_repair_task(
    state: &AppState,
    inventory: &RepairInventoryRecord,
    task: PlacementRepairTask,
) -> Result<bool, ApiError> {
    let Some(lease) = acquire_repair_lease(state, inventory, &task).await? else {
        return Ok(false);
    };
    metrics::PLACEMENT_REPAIR_TASKS_STARTED.fetch_add(1, Ordering::Relaxed);
    let destination = task.destination_node_id().to_string();
    ensure_inventory_on_destination(state, inventory, &destination).await?;
    let request = RepairExecutionRequest {
        inventory: inventory.clone(),
        lease,
        task,
    };
    let execution: Pin<
        Box<dyn Future<Output = Result<proto::RepairExecuteResponse, ApiError>> + Send>,
    > = if destination == state.status.node_id {
        let execution_state = state.clone();
        let execution_request = request.clone();
        let authenticated_node = state.status.node_id.clone();
        Box::pin(async move {
            execute_placement_repair(&execution_state, &authenticated_node, execution_request).await
        })
    } else {
        let address = state
            .network
            .peer_address(&destination)
            .await
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::Unavailable,
                    "repair destination became unreachable",
                )
            })?;
        let encoded = serde_json::to_string(&request).map_err(ApiError::serde)?;
        let network = state.network.clone();
        Box::pin(async move {
            network
                .execute_repair(address, encoded)
                .await
                .map_err(|error| {
                    ApiError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        ErrorCode::Unavailable,
                        error.to_string(),
                    )
                })
        })
    };
    let mut execution = execution;
    let renewal_interval = Duration::from_secs(REPAIR_LEASE_RENEWAL_SECONDS);
    let first_renewal = time::Instant::now() + renewal_interval;
    let mut renewals = time::interval_at(first_renewal, renewal_interval);
    renewals.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let mut renewal_token = request.lease.clone();
    let response_result = loop {
        tokio::select! {
            response = &mut execution => break response,
            _ = renewals.tick() => {
                match renew_repair_lease(state, &renewal_token).await {
                    Ok(renewed) => renewal_token = renewed,
                    Err(error) => break Err(error),
                }
            }
        }
    };
    let response = match response_result {
        Ok(response) => response,
        Err(error) if repair_lease_contention(&error) => {
            debug!(
                task = %request.lease.lease.task_id,
                error = %error.message,
                "placement repair yielded to a newer lease owner"
            );
            return Ok(false);
        }
        Err(error) => {
            metrics::PLACEMENT_REPAIR_TASK_ERRORS.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
    };
    if response.repaired {
        metrics::PLACEMENT_REPAIR_TASKS_COMPLETED.fetch_add(1, Ordering::Relaxed);
    } else if response.already_healthy {
        metrics::PLACEMENT_REPAIR_TASKS_ALREADY_HEALTHY.fetch_add(1, Ordering::Relaxed);
    }
    let (cid, placement) = match &request.task {
        PlacementRepairTask::Replicated { block, .. } => {
            (block.cid.clone(), block.placement.clone())
        }
        PlacementRepairTask::ErasureShard {
            manifest,
            stripe_index,
            shard_index,
            ..
        } => {
            let (block, _) = fetch_repair_source(state, manifest, &state.status.node_id).await?;
            let manifest: ErasureManifest =
                serde_json::from_slice(&block.payload).map_err(ApiError::serde)?;
            let shard = manifest.stripes[*stripe_index]
                .shards
                .iter()
                .find(|shard| shard.index == *shard_index)
                .ok_or_else(|| ApiError::internal("repaired shard is absent from manifest"))?;
            (shard.cid.clone(), shard.placement.clone())
        }
    };
    if request.task.temporary() && (response.repaired || response.already_healthy) {
        let exception_ttl = i64::try_from(state.repair_interval.as_secs().saturating_mul(3))
            .unwrap_or(i64::MAX)
            .max(60 * 60);
        commit_preverified_repair_exception(
            state,
            placement,
            cid.clone(),
            vec![destination.clone()],
            "repair_temporary_owner_loss".to_string(),
            exception_ttl,
        )
        .await?;
        metrics::PLACEMENT_REPAIR_TEMPORARY_EXCEPTIONS.fetch_add(1, Ordering::Relaxed);
    }
    if response.repaired {
        record_repair(
            state,
            RepairDiagnosticRecord {
                sequence: 0,
                cid,
                repair_kind: match request.task {
                    PlacementRepairTask::Replicated { .. } => "replica".to_string(),
                    PlacementRepairTask::ErasureShard { .. } => "erasure_shard".to_string(),
                },
                reason: "authoritative_inventory_missing".to_string(),
                source_node: response.source_node_ids.first().cloned(),
                destination_node: Some(destination),
                result: "verified".to_string(),
                verified_bytes: response.verified_bytes,
                timestamp_unix_seconds: 0,
            },
        );
    }
    Ok(response.repaired)
}

fn repair_lease_contention(error: &ApiError) -> bool {
    error.message.contains("repair lease")
        && matches!(
            error.code,
            ErrorCode::Conflict | ErrorCode::GenerationConflict | ErrorCode::Unavailable
        )
}

async fn run_placement_owned_repair(state: &AppState) -> Result<u64, ApiError> {
    let map = state
        .placement
        .current_map()
        .ok_or_else(|| ApiError::internal("authoritative placement map is not loaded"))?;
    let mut plans = Vec::new();
    for inventory in local_repair_inventory(state)? {
        plans.push(repair_plan_for_inventory(state, inventory).await?);
    }
    let health = build_repair_health_snapshot(state, &plans).await?;
    let mut repairs = 0u64;
    for plan in plans {
        let tasks = repair_tasks_for_inventory(state, &health, &plan).await?;
        for task in tasks {
            let owners =
                select_repair_owners(&map, task.owner_reference(), DEFAULT_REPAIR_OWNER_COUNT)
                    .map_err(authoritative_placement_error)?;
            let Some(local_rank) = owners
                .iter()
                .position(|owner| owner == &state.status.node_id)
            else {
                continue;
            };
            if local_rank > 0 {
                // Ordered standbys wait before attempting the same committed
                // lease. The primary normally wins, while a reachable but
                // stalled primary cannot suppress failover forever: a later
                // pass can advance the fence as soon as its lease expires.
                metrics::PLACEMENT_REPAIR_STANDBY_DEFERRALS.fetch_add(1, Ordering::Relaxed);
                time::sleep(Duration::from_millis(
                    250u64.saturating_mul(local_rank as u64),
                ))
                .await;
            }
            metrics::PLACEMENT_REPAIR_OWNER_RUNS.fetch_add(1, Ordering::Relaxed);
            debug!(
                inventory = %plan.inventory.cache_key(),
                descriptor = %plan.inventory.descriptor.cid,
                content = ?plan.inventory.content.as_ref().map(|content| content.cid.to_string()),
                repair_reference = ?task.owner_reference(),
                owner_rank = local_rank,
                "authoritative repair owner evaluated block or stripe"
            );
            repairs = repairs.saturating_add(u64::from(
                dispatch_placement_repair_task(state, &plan.inventory, task).await?,
            ));
        }
    }
    Ok(repairs)
}

pub(super) fn record_repair(state: &AppState, mut record: RepairDiagnosticRecord) {
    let mut records = state
        .repair_diagnostics
        .lock()
        .expect("repair diagnostic lock poisoned");
    let sequence = records
        .back()
        .map_or(1, |record| record.sequence.saturating_add(1));
    if records.len() == 512 {
        records.pop_front();
    }
    record.sequence = sequence;
    record.timestamp_unix_seconds = unix_seconds();
    records.push_back(record);
}

pub(super) fn spawn_repair_loop(state: AppState) {
    tokio::spawn(async move {
        let digest = blake3::hash(state.status.node_id.as_bytes());
        let jitter_slots = u64::from_le_bytes(
            digest.as_bytes()[..8]
                .try_into()
                .expect("BLAKE3 digest contains eight bytes"),
        );
        let interval_millis = state.repair_interval.as_millis().max(1) as u64;
        let first_tick = time::Instant::now()
            + state.repair_interval
            + Duration::from_millis(jitter_slots % interval_millis);
        let mut interval = time::interval_at(first_tick, state.repair_interval);
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
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
    if state.s3.is_some() {
        s3_api::ensure_s3_current_placement_loaded(state).await?;
        let inventory_sync = sync_partition_repair_inventory(state).await;
        if let Ok(dispatched) = inventory_sync.as_ref()
            && *dispatched > 0
        {
            info!(dispatched, "distributed partition repair inventory deltas");
        }
        let repaired = run_placement_owned_repair(state).await?;
        if repaired > 0 {
            info!(repaired, "completed placement-owned repairs");
        }
        return inventory_sync.map(|_| ());
    }
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
            // A short foreground-traffic delay is not proof that the node has
            // disappeared. Retain its signed, persisted addresses so Raft can
            // reconnect after a transient miss; a later handshake marks it
            // connected again.
            state.network.mark_peer_disconnected(&peer.node_id).await;
        }
    }

    for pin in all_pin_records(state)?
        .into_iter()
        .filter(|pin| pin.owner == state.status.node_id && !pin.pin_id.starts_with("namespace-"))
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

    // Erasure shards are independently sufficient at one healthy placement;
    // replicating every shard at the namespace replication factor defeats the
    // 6+3 layout and creates a repair storm. The manifest itself remains
    // replicated according to the enclosing pin policy.
    let erasure_manifests = pinned_replication
        .keys()
        .filter(|cid| cid.codec == CODEC_ERASURE_MANIFEST)
        .cloned()
        .collect::<Vec<_>>();
    for cid in erasure_manifests {
        let block = get_block_resolved(state, &cid).await?;
        let manifest: ErasureManifest = serde_json::from_slice(&block.payload)
            .map_err(|error| ApiError::bad_request(error.to_string()))?;
        validate_erasure_resource_limits(state, &manifest)?;
        for shard in manifest
            .stripes
            .iter()
            .flat_map(|stripe| stripe.shards.iter())
        {
            pinned_replication.insert(shard.cid.clone(), 1);
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

        // A locally present one-copy shard is already healthy. Avoid a DHT
        // lookup for every shard on every cycle.
        if desired_replication == 1 && stat.codec != CODEC_ERASURE_MANIFEST {
            continue;
        }

        let cached_providers = state.network.local_provider_records(&stat.cid)?;
        let mut healthy_nodes = healthy_provider_node_ids(state, &stat.cid, cached_providers).await;
        if healthy_nodes.len() < desired_replication {
            let providers = match time::timeout(
                Duration::from_secs(1),
                state.network.find_providers(&stat.cid),
            )
            .await
            {
                Ok(Ok(providers)) => providers,
                Ok(Err(error)) => {
                    warn!(%error, cid = %stat.cid, "provider lookup failed during repair");
                    Vec::new()
                }
                Err(_) => {
                    warn!(cid = %stat.cid, "provider lookup timed out during repair");
                    Vec::new()
                }
            };
            healthy_nodes.extend(healthy_provider_node_ids(state, &stat.cid, providers).await);
            healthy_nodes.sort();
            healthy_nodes.dedup();
        }
        let repair_coordinator = healthy_nodes.first();
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
        if healthy_nodes.len() >= desired_replication {
            continue;
        }
        if repair_coordinator != Some(&state.status.node_id) {
            continue;
        }

        let encoded = state.block_store.get_encoded(&stat.cid)?;
        let encoded_payload = BufferChain::from_buffer(OwnedBuffer::from_vec(encoded.into_bytes()));
        let selected = select_replicas(&stat.cid, &candidates, candidates.len());
        for node in selected {
            if node.is_local || healthy_nodes.contains(&node.node_id) {
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
                state.network.block_put_replica_buffer_chain(
                    address,
                    stat.codec,
                    &stat.cid,
                    stat.size,
                    encoded_payload.clone(),
                ),
            )
            .await
            {
                Ok(Ok(ack)) => match validate_replica_ack(
                    state,
                    &node.node_id,
                    &stat.cid,
                    stat.codec,
                    stat.size,
                    &ack,
                ) {
                    Ok(record) => {
                        healthy_nodes.push(node.node_id.clone());
                        state.network.announce_provider_to_peers(&record).await;
                        record_repair(
                            state,
                            RepairDiagnosticRecord {
                                sequence: 0,
                                cid: stat.cid.clone(),
                                repair_kind: "replica".to_string(),
                                reason: "under_replicated".to_string(),
                                source_node: Some(state.status.node_id.clone()),
                                destination_node: Some(node.node_id.clone()),
                                result: "verified".to_string(),
                                verified_bytes: stat.size,
                                timestamp_unix_seconds: 0,
                            },
                        );
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
            healthy_nodes.sort();
            healthy_nodes.dedup();
            if healthy_nodes.len() >= desired_replication {
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
    for stripe in &manifest.stripes {
        repair_erasure_stripe(state, candidates, manifest, stripe).await?;
    }
    Ok(())
}

async fn repair_erasure_stripe(
    state: &AppState,
    candidates: &[PlacementNode],
    manifest: &ErasureManifest,
    stripe: &ErasureStripe,
) -> Result<(), ApiError> {
    if state.s3.is_none() && state.placement.current_map().is_none() {
        return repair_erasure_stripe_legacy(state, candidates, manifest, stripe).await;
    }
    let mut missing = Vec::new();
    for shard in &stripe.shards {
        metrics::PLACEMENT_CALCULATIONS.fetch_add(1, Ordering::Relaxed);
        let target = state
            .placement
            .decide(&shard.placement)
            .map_err(authoritative_placement_error)?
            .node_ids
            .into_iter()
            .next()
            .ok_or_else(|| ApiError::internal("erasure placement returned no repair owner"))?;
        let healthy = if target == state.status.node_id {
            state.block_store.has(&shard.cid)?
        } else if let Some(address) = state.network.peer_address(&target).await {
            metrics::PLACEMENT_DIRECT_TARGET_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
            matches!(
                time::timeout(
                    Duration::from_secs(5),
                    state.network.block_has(address, &shard.cid)
                )
                .await,
                Ok(Ok(true))
            )
        } else {
            false
        };
        if !healthy {
            missing.push(shard.index);
        }
    }

    if !missing.is_empty() {
        let repair_bytes = usize::try_from(stripe.shard_size)
            .unwrap_or(usize::MAX)
            .saturating_mul(manifest.data_shards as usize + missing.len());
        throttle_erasure_repair(state, repair_bytes).await;
        let mut reconstructed = reconstruct_erasure_shards(state, manifest, stripe).await?;
        for index in missing {
            let shard_payload = reconstructed
                .get_mut(index as usize)
                .and_then(Option::take)
                .ok_or_else(|| ApiError::internal("erasure repair missing reconstructed shard"))?;
            let shard = stripe
                .shards
                .iter()
                .find(|shard| shard.index == index)
                .cloned()
                .ok_or_else(|| ApiError::internal("erasure repair missing shard metadata"))?;
            let shard_cid = shard.cid.clone();
            let _permit = state
                .erasure_repair_semaphore
                .acquire()
                .await
                .map_err(|error| ApiError::internal(error.to_string()))?;
            let verified_bytes = shard_payload.len() as u64;
            let (destination, _) = store_erasure_shard(
                state,
                candidates,
                shard_cid.clone(),
                shard_payload,
                shard.placement,
            )
            .await?;
            record_repair(
                state,
                RepairDiagnosticRecord {
                    sequence: 0,
                    cid: shard_cid,
                    repair_kind: "erasure_shard".to_string(),
                    reason: "missing_shard".to_string(),
                    source_node: None,
                    destination_node: Some(destination),
                    result: "verified".to_string(),
                    verified_bytes,
                    timestamp_unix_seconds: 0,
                },
            );
            ERASURE_SHARD_REPAIRS.fetch_add(1, Ordering::Relaxed);
        }
    }
    Ok(())
}

async fn repair_erasure_stripe_legacy(
    state: &AppState,
    candidates: &[PlacementNode],
    manifest: &ErasureManifest,
    stripe: &ErasureStripe,
) -> Result<(), ApiError> {
    let mut missing = Vec::new();
    let mut healthy_by_index = HashMap::new();
    for shard in &stripe.shards {
        let healthy = healthy_providers_for_cid(state, &shard.cid).await;
        if healthy.is_empty() {
            missing.push(shard.index);
        }
        healthy_by_index.insert(shard.index, healthy);
    }
    if !missing.is_empty() {
        let repair_bytes = usize::try_from(stripe.shard_size)
            .unwrap_or(usize::MAX)
            .saturating_mul(manifest.data_shards as usize + missing.len());
        throttle_erasure_repair(state, repair_bytes).await;
        let mut reconstructed = reconstruct_erasure_shards(state, manifest, stripe).await?;
        for index in missing {
            let shard_payload = reconstructed
                .get_mut(index as usize)
                .and_then(Option::take)
                .ok_or_else(|| ApiError::internal("erasure repair missing reconstructed shard"))?;
            let shard = stripe
                .shards
                .iter()
                .find(|shard| shard.index == index)
                .ok_or_else(|| ApiError::internal("erasure repair missing shard metadata"))?;
            let _permit = state
                .erasure_repair_semaphore
                .acquire()
                .await
                .map_err(|error| ApiError::internal(error.to_string()))?;
            let verified_bytes = shard_payload.len() as u64;
            let (destination, _, _) = store_erasure_shard_legacy(
                state,
                candidates,
                shard.cid.clone(),
                shard_payload,
                &HashSet::new(),
                &HashSet::new(),
                shard.placement.clone(),
            )
            .await?;
            record_repair(
                state,
                RepairDiagnosticRecord {
                    sequence: 0,
                    cid: shard.cid.clone(),
                    repair_kind: "erasure_shard".to_string(),
                    reason: "missing_shard".to_string(),
                    source_node: None,
                    destination_node: Some(destination),
                    result: "verified".to_string(),
                    verified_bytes,
                    timestamp_unix_seconds: 0,
                },
            );
            ERASURE_SHARD_REPAIRS.fetch_add(1, Ordering::Relaxed);
        }
        healthy_by_index.clear();
        for shard in &stripe.shards {
            healthy_by_index.insert(
                shard.index,
                healthy_providers_for_cid(state, &shard.cid).await,
            );
        }
    }
    rebalance_erasure_stripe_legacy(state, candidates, stripe, &healthy_by_index).await
}

async fn rebalance_erasure_stripe_legacy(
    state: &AppState,
    candidates: &[PlacementNode],
    stripe: &ErasureStripe,
    healthy_by_index: &HashMap<u16, Vec<ProviderRecord>>,
) -> Result<(), ApiError> {
    let mut used_nodes = HashSet::new();
    let mut used_constraint_values = HashSet::new();
    let mut shards = stripe.shards.clone();
    shards.sort_by_key(|shard| shard.index);
    for shard in shards {
        let Some(target) = select_erasure_target_legacy(
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
            || healthy.is_empty()
        {
            continue;
        }
        let payload = match get_block_resolved(state, &shard.cid).await {
            Ok(block) if block.payload.len() == shard.size as usize => block.payload,
            Ok(_) | Err(_) => continue,
        };
        let _permit = state
            .erasure_repair_semaphore
            .acquire()
            .await
            .map_err(|error| ApiError::internal(error.to_string()))?;
        throttle_erasure_repair(state, payload.len()).await;
        if copy_erasure_shard_to_node(state, &target, &shard.cid, payload)
            .await
            .is_ok()
        {
            ERASURE_SHARD_REBALANCES.fetch_add(1, Ordering::Relaxed);
            info!(
                cid = %shard.cid,
                shard_index = shard.index,
                target_node = %target.node_id,
                target_failure_domain = %primary_failure_domain_key(&target),
                "rebalanced compatibility erasure shard"
            );
        }
    }
    Ok(())
}

pub(super) async fn throttle_erasure_repair(state: &AppState, bytes: usize) {
    let millis =
        ((bytes as u128) * 1000).div_ceil(state.erasure_repair_bytes_per_second as u128) as u64;
    if millis > 0 {
        metrics::ERASURE_REPAIR_THROTTLE_MICROS
            .fetch_add(millis.saturating_mul(1_000), Ordering::Relaxed);
        time::sleep(Duration::from_millis(millis)).await;
    }
}

pub(super) async fn healthy_providers_for_cid(state: &AppState, cid: &Cid) -> Vec<ProviderRecord> {
    let cached = state
        .network
        .local_provider_records(cid)
        .unwrap_or_default();
    let mut healthy = verified_healthy_providers(state, cid, cached).await;
    if !healthy.is_empty() {
        return healthy;
    }
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
    healthy = verified_healthy_providers(state, cid, providers).await;
    healthy
}

async fn verified_healthy_providers(
    state: &AppState,
    cid: &Cid,
    providers: Vec<ProviderRecord>,
) -> Vec<ProviderRecord> {
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

pub(super) async fn reconstruct_erasure_shards(
    state: &AppState,
    manifest: &ErasureManifest,
    stripe: &ErasureStripe,
) -> Result<Vec<Option<Vec<u8>>>, ApiError> {
    let _read_slot = acquire_erasure_stripe_read_slot(state).await?;
    let data_shards = manifest.data_shards as usize;
    let parity_shards = manifest.parity_shards as usize;
    let total_shards = data_shards + parity_shards;
    let shard_size = stripe.shard_size as usize;
    let mut shards = vec![None::<Vec<u8>>; total_shards];
    let mut available = 0usize;
    for shard in &stripe.shards {
        // The manifest is the authoritative shard inventory.  Repair must
        // calculate the recorded destination directly; provider records are
        // advisory and may be stale precisely when repair is needed.
        match get_block_at_placement(state, &shard.cid, &shard.placement).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_placement::PlacementMapNode;

    #[test]
    fn repair_sources_are_ordered_same_rack_then_same_zone_then_remote_zone() {
        let node = |node_id: &str, zone: &str, rack: &str| PlacementMapNode {
            node_id: node_id.to_string(),
            weight: 1,
            state: PlacementMapNodeState::In,
            failure_domains: BTreeMap::from([
                ("zone".to_string(), zone.to_string()),
                ("rack".to_string(), rack.to_string()),
            ]),
        };
        let map = PlacementMap {
            epoch: 9,
            failure_domain_levels: vec!["zone".to_string(), "rack".to_string()],
            nodes: vec![
                node("destination", "zone-a", "rack-a"),
                node("same-rack", "zone-a", "rack-a"),
                node("same-zone", "zone-a", "rack-b"),
                node("remote-zone", "zone-b", "rack-c"),
            ],
        };
        let mut sources = vec![
            "remote-zone".to_string(),
            "same-zone".to_string(),
            "same-rack".to_string(),
        ];
        sources.sort_by(|left, right| {
            repair_source_affinity(&map, right, "destination")
                .cmp(&repair_source_affinity(&map, left, "destination"))
                .then_with(|| left.cmp(right))
        });
        assert_eq!(sources, ["same-rack", "same-zone", "remote-zone"]);
    }

    #[test]
    fn active_repair_lease_is_exclusive_and_expiry_advances_the_fence() {
        let lease = RepairLeaseRecord {
            inventory_key: "inventory".to_string(),
            task_id: "task".to_string(),
            owner_node_id: "owner".to_string(),
            placement_epoch: 7,
            fence: 41,
            acquired_at_unix_seconds: 90,
            expires_at_unix_seconds: 100,
        };
        assert_eq!(next_repair_fence(Some(&lease), 99), None);
        assert_eq!(next_repair_fence(Some(&lease), 100), Some(42));
        assert_eq!(next_repair_fence(Some(&lease), 101), Some(42));
        assert_eq!(next_repair_fence(None, 99), Some(1));
    }
}
