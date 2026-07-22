// SPDX-License-Identifier: Apache-2.0

//! Durable small-object transition from replicated append records to
//! partition-indexed erasure-coded extents.

use super::*;
use pepper_merkle::{MerkleLimits, MerkleValue, ScanQuery};
use pepper_namespace::{
    CommandEnvelope, KeyPrecondition, NamespaceCommand, NamespaceKind, NamespaceMutation,
    TransactionCommand,
};
use serde::{Deserialize, Serialize};

const SMALL_OBJECT_PENDING_PREFIX: &[u8] = b"\xffs3/small/pending/";
const SMALL_OBJECT_INDEX_PREFIX: &[u8] = b"\xffs3/small/index/";
const SMALL_OBJECT_EXTENT_PREFIX: &[u8] = b"\xffs3/small/extent/";
const SMALL_OBJECT_DIRTY_EXTENT_PREFIX: &[u8] = b"\xffs3/small/dirty/";
const SMALL_OBJECT_PLACEMENT_METADATA: &str = "content_placement";
const SMALL_OBJECT_SIZE_METADATA: &str = "logical_size";
const SMALL_OBJECT_ENQUEUED_METADATA: &str = "enqueued_at_unix_seconds";
const SMALL_OBJECT_KEY_METADATA: &str = "object_key_hex";
const SMALL_OBJECT_EXTENT_PLACEMENT_METADATA: &str = "extent_placement";
const SMALL_OBJECT_EXTENT_CID_METADATA: &str = "extent_cid";
const SMALL_OBJECT_EXTENT_OFFSET_METADATA: &str = "extent_offset";
const SMALL_OBJECT_EXTENT_LENGTH_METADATA: &str = "extent_length";
const SMALL_OBJECT_EXTENT_TOTAL_BYTES_METADATA: &str = "extent_total_bytes";
const SMALL_OBJECT_EXTENT_RECORDS_METADATA: &str = "extent_records";
const SMALL_OBJECT_LOGICAL_LENGTH_METADATA: &str = "logical_length";
const SMALL_OBJECT_LOGICAL_CID_METADATA: &str = "logical_cid";
const SMALL_OBJECT_RECORD_ENCODING_METADATA: &str = "record_encoding";
const SMALL_OBJECT_EXTENT_INDEX_CID_METADATA: &str = "extent_index_cid";
const SMALL_OBJECT_EXTENT_INDEX_PLACEMENT_METADATA: &str = "extent_index_placement";
const SMALL_OBJECT_LOCATION_METADATA: &str = "p";
const SMALL_OBJECT_PACK_POLL_SECONDS: u64 = 5;
const SMALL_OBJECT_PACK_FLUSH_SECONDS: i64 = 30;
const SMALL_OBJECT_PACK_FETCH_CONCURRENCY: usize = 32;
const SMALL_OBJECT_PACK_TRANSITION_RETRIES: usize = 8;
const SMALL_OBJECT_EXTENT_INDEX_VERSION: u8 = 1;
const SMALL_OBJECT_EXTENT_INDEX_MAX_BYTES: usize = 4 * 1024 * 1024;
const SMALL_OBJECT_EXTENT_INDEX_MAX_RECORDS: usize = 4_096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SmallObjectExtentIndex {
    version: u8,
    extent_cid: Cid,
    extent_placement: PlacementReference,
    total_bytes: u64,
    records: Vec<SmallObjectExtentIndexRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SmallObjectExtentIndexRecord {
    index_key_hex: String,
    object_key_hex: String,
    logical_cid: Cid,
    logical_size: u64,
    offset: u64,
    stored_length: u64,
    encoding: ErasureStripeEncoding,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PackedSmallObjectMetadata {
    #[serde(rename = "v")]
    version: u8,
    #[serde(rename = "e")]
    placement_epoch: u64,
    #[serde(rename = "r")]
    placement_replicas: u16,
    #[serde(rename = "c")]
    extent_cid: Cid,
    #[serde(rename = "o")]
    offset: u64,
    #[serde(rename = "l")]
    stored_length: u64,
    #[serde(rename = "z")]
    encoding: u8,
}

pub(super) struct SmallObjectExtentIndexCodecHandler;

impl DagCodecHandler for SmallObjectExtentIndexCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_SMALL_OBJECT_EXTENT_INDEX
    }

    fn links(&self, payload: &[u8], _limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        decode_extent_index(payload)
            .map(|index| vec![index.extent_cid])
            .map_err(|error| DagError::InvalidPayload {
                codec: CODEC_SMALL_OBJECT_EXTENT_INDEX.canonical_display(),
                message: error.message,
            })
    }
}

#[derive(Clone, Debug)]
struct PendingSmallObject {
    key: Vec<u8>,
    object_key: Vec<u8>,
    value: MerkleValue,
    placement: PlacementReference,
    logical_size: u64,
    enqueued_at_unix_seconds: i64,
}

#[derive(Clone, Debug)]
struct FetchedSmallObject {
    pending: PendingSmallObject,
    offset: u64,
    stored_payload: Vec<u8>,
    encoding: ErasureStripeEncoding,
}

#[derive(Clone, Debug)]
struct LiveExtentRecord {
    key: Vec<u8>,
    object_key: Vec<u8>,
    logical_cid: Cid,
    value: MerkleValue,
    logical_size: u64,
    stored_length: u64,
    extent_total_bytes: u64,
    extent_records: u64,
}

#[derive(Clone, Debug)]
struct DirtyExtentCandidate {
    dirty_key: Vec<u8>,
    dirty_value: MerkleValue,
    catalog_key: Vec<u8>,
    catalog_value: MerkleValue,
    descriptor: SmallObjectExtentIndex,
    live: Vec<LiveExtentRecord>,
}

#[derive(Clone, Debug)]
struct RepackedExtentRecord {
    live: LiveExtentRecord,
    offset: u64,
    stored_payload: Vec<u8>,
    encoding: ErasureStripeEncoding,
}

#[derive(Clone, Debug)]
struct StoredSmallObjectExtentIndex {
    receipt: DurabilityReceipt,
}

#[derive(Clone, Debug)]
pub(super) struct PackedSmallObjectLocation {
    pub(super) extent_cid: Cid,
    pub(super) extent_placement: PlacementReference,
    pub(super) offset: u64,
    pub(super) stored_length: u64,
    pub(super) logical_length: u64,
    pub(super) encoding: ErasureStripeEncoding,
}

#[derive(Clone, Debug, Default, Serialize)]
pub(super) struct SmallObjectPackReport {
    namespaces_examined: u64,
    pending_records_examined: u64,
    extents_written: u64,
    records_transitioned: u64,
    logical_bytes_transitioned: u64,
    encoded_bytes_written: u64,
    extents_compacted: u64,
    records_compacted: u64,
    bytes_reclaimed: u64,
    extent_cids: Vec<Cid>,
}

fn scoped_key(prefix: &[u8], object_key: &[u8], cid: &Cid) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(hex::encode(object_key).as_bytes());
    key.push(b'/');
    key.extend_from_slice(cid.to_string().as_bytes());
    key
}

fn pending_key(object_key: &[u8], cid: &Cid) -> Vec<u8> {
    scoped_key(SMALL_OBJECT_PENDING_PREFIX, object_key, cid)
}

fn index_key(object_key: &[u8], cid: &Cid) -> Vec<u8> {
    scoped_key(SMALL_OBJECT_INDEX_PREFIX, object_key, cid)
}

fn extent_state_key(prefix: &[u8], index_cid: &Cid) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(index_cid.to_string().as_bytes());
    key
}

pub(super) fn extent_catalog_key(index_cid: &Cid) -> Vec<u8> {
    extent_state_key(SMALL_OBJECT_EXTENT_PREFIX, index_cid)
}

pub(super) fn dirty_extent_key(index_cid: &Cid) -> Vec<u8> {
    extent_state_key(SMALL_OBJECT_DIRTY_EXTENT_PREFIX, index_cid)
}

fn validate_extent_index(index: &SmallObjectExtentIndex) -> Result<(), ApiError> {
    if index.version != SMALL_OBJECT_EXTENT_INDEX_VERSION
        || index.extent_cid.codec != CODEC_ERASURE_MANIFEST
        || index.extent_placement.seed != index.extent_cid
        || index.extent_placement.validate().is_err()
        || index.total_bytes == 0
        || index.records.is_empty()
        || index.records.len() > SMALL_OBJECT_EXTENT_INDEX_MAX_RECORDS
    {
        return Err(ApiError::bad_request(
            "invalid packed small-object extent index",
        ));
    }
    let mut previous_key = None::<&str>;
    let mut previous_end = 0u64;
    for record in &index.records {
        if previous_key.is_some_and(|previous| previous >= record.index_key_hex.as_str())
            || record.logical_cid.codec != CODEC_SMALL_OBJECT
            || record.logical_size == 0
            || record.stored_length == 0
        {
            return Err(ApiError::bad_request(
                "invalid packed small-object extent record",
            ));
        }
        let object_key = hex::decode(&record.object_key_hex)
            .map_err(|error| ApiError::bad_request(error.to_string()))?;
        if hex::encode(index_key(&object_key, &record.logical_cid)) != record.index_key_hex
            || record.offset < previous_end
        {
            return Err(ApiError::bad_request(
                "packed small-object extent record identity is invalid",
            ));
        }
        previous_end = record
            .offset
            .checked_add(record.stored_length)
            .filter(|end| *end <= index.total_bytes)
            .ok_or_else(|| ApiError::bad_request("packed extent record exceeds its payload"))?;
        previous_key = Some(&record.index_key_hex);
    }
    Ok(())
}

fn encode_extent_index(index: &SmallObjectExtentIndex) -> Result<Vec<u8>, ApiError> {
    validate_extent_index(index)?;
    let payload = serde_json::to_vec(index).map_err(ApiError::serde)?;
    if payload.len() > SMALL_OBJECT_EXTENT_INDEX_MAX_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::PayloadTooLarge,
            "packed small-object extent index exceeds its byte limit",
        ));
    }
    Ok(payload)
}

fn decode_extent_index(payload: &[u8]) -> Result<SmallObjectExtentIndex, ApiError> {
    if payload.len() > SMALL_OBJECT_EXTENT_INDEX_MAX_BYTES {
        return Err(ApiError::bad_request(
            "packed small-object extent index exceeds its byte limit",
        ));
    }
    let index: SmallObjectExtentIndex = serde_json::from_slice(payload).map_err(ApiError::serde)?;
    validate_extent_index(&index)?;
    if serde_json::to_vec(&index).map_err(ApiError::serde)? != payload {
        return Err(ApiError::bad_request(
            "packed small-object extent index is not canonical",
        ));
    }
    Ok(index)
}

pub(super) async fn small_object_pending_mutation(
    state: &AppState,
    namespace: &NamespaceState,
    object_key: &[u8],
    cid: &Cid,
    placement: &PlacementReference,
    logical_size: u64,
) -> Result<Option<NamespaceMutation>, ApiError> {
    if cid.codec != CODEC_SMALL_OBJECT {
        return Ok(None);
    }
    if placement.seed != *cid || placement.validate().is_err() {
        return Err(ApiError::bad_request(
            "small-object placement does not match its CID",
        ));
    }
    let store = direct_namespace_store(state, namespace).await;
    if pepper_merkle::get(
        &store,
        &namespace.current_root_cid,
        &index_key(object_key, cid),
        MerkleLimits::default(),
    )
    .await
    .map_err(|error| ApiError::bad_request(error.to_string()))?
    .is_some()
    {
        return Ok(None);
    }
    let key = pending_key(object_key, cid);
    if pepper_merkle::get(
        &store,
        &namespace.current_root_cid,
        &key,
        MerkleLimits::default(),
    )
    .await
    .map_err(|error| ApiError::bad_request(error.to_string()))?
    .is_some()
    {
        return Ok(None);
    }
    let mut metadata = BTreeMap::new();
    metadata.insert(
        SMALL_OBJECT_PLACEMENT_METADATA.to_string(),
        serde_json::to_string(placement).map_err(ApiError::serde)?,
    );
    metadata.insert(
        SMALL_OBJECT_SIZE_METADATA.to_string(),
        logical_size.to_string(),
    );
    metadata.insert(
        SMALL_OBJECT_ENQUEUED_METADATA.to_string(),
        unix_seconds().to_string(),
    );
    metadata.insert(
        SMALL_OBJECT_KEY_METADATA.to_string(),
        hex::encode(object_key),
    );
    Ok(Some(NamespaceMutation::Put {
        key_hex: hex::encode(key),
        value_cid: cid.clone(),
        value_kind: "small_object_pending".to_string(),
        metadata,
        precondition: KeyPrecondition::Absent,
    }))
}

pub(super) async fn small_object_marker_cleanup_mutations(
    state: &AppState,
    namespace: &NamespaceState,
    object_key: &[u8],
    cid: &Cid,
) -> Result<(Vec<NamespaceMutation>, Vec<DurabilityReceipt>), ApiError> {
    if cid.codec != CODEC_SMALL_OBJECT {
        return Ok((Vec::new(), Vec::new()));
    }
    let store = direct_namespace_store(state, namespace).await;
    let mut mutations = Vec::new();
    let mut durability = Vec::new();
    let pending = pending_key(object_key, cid);
    if let Some(value) = pepper_merkle::get(
        &store,
        &namespace.current_root_cid,
        &pending,
        MerkleLimits::default(),
    )
    .await
    .map_err(|error| ApiError::bad_request(error.to_string()))?
    {
        mutations.push(NamespaceMutation::Delete {
            key_hex: hex::encode(pending),
            precondition: KeyPrecondition::Match {
                generation: value.generation,
                cid: value.cid,
            },
        });
    }
    let index = index_key(object_key, cid);
    if let Some(value) = pepper_merkle::get(
        &store,
        &namespace.current_root_cid,
        &index,
        MerkleLimits::default(),
    )
    .await
    .map_err(|error| ApiError::bad_request(error.to_string()))?
    {
        mutations.push(NamespaceMutation::Delete {
            key_hex: hex::encode(index),
            precondition: KeyPrecondition::Match {
                generation: value.generation,
                cid: value.cid.clone(),
            },
        });
        let extent_index_cid = value
            .metadata
            .get(SMALL_OBJECT_EXTENT_INDEX_CID_METADATA)
            .ok_or_else(|| ApiError::internal("packed extent index CID is missing"))?
            .parse::<Cid>()
            .map_err(|error| ApiError::internal(error.to_string()))?;
        let extent_index_placement: PlacementReference = serde_json::from_str(
            value
                .metadata
                .get(SMALL_OBJECT_EXTENT_INDEX_PLACEMENT_METADATA)
                .ok_or_else(|| ApiError::internal("packed extent index placement is missing"))?,
        )
        .map_err(ApiError::serde)?;
        if extent_index_cid.codec != CODEC_SMALL_OBJECT_EXTENT_INDEX
            || extent_index_placement.seed != extent_index_cid
            || extent_index_placement.validate().is_err()
        {
            return Err(ApiError::internal(
                "packed extent index reference is invalid",
            ));
        }
        let dirty_key = dirty_extent_key(&extent_index_cid);
        if pepper_merkle::get(
            &store,
            &namespace.current_root_cid,
            &dirty_key,
            MerkleLimits::default(),
        )
        .await
        .map_err(|error| ApiError::bad_request(error.to_string()))?
        .is_none()
        {
            // The catalog already commits this descriptor and its EC extent.
            // Authenticate the descriptor block itself so publication can
            // treat its links as committed history instead of re-walking and
            // requiring every EC shard for a metadata-only replace/delete.
            // The index precondition below makes that reuse atomic with the
            // reference transfer from the object index to the dirty marker.
            let required = usize::from(extent_index_placement.replicas);
            let receipt = if let Some(receipt) = state
                .publication_repository
                .durable_receipt(
                    &extent_index_cid,
                    Some(&extent_index_placement),
                    required,
                    unix_seconds(),
                )
                .map_err(|error| ApiError::internal(error.to_string()))?
            {
                receipt
            } else {
                AgentDurabilityBackend(state.clone())
                    .ensure_at_placement(
                        &extent_index_cid,
                        required,
                        extent_index_placement.clone(),
                    )
                    .await
                    .map_err(publication_error)?
            };
            durability.push(receipt);
            mutations.push(NamespaceMutation::Put {
                key_hex: hex::encode(dirty_key),
                value_cid: extent_index_cid,
                value_kind: "small_object_dirty_extent".to_string(),
                metadata: BTreeMap::from([(
                    BUCKET_DESCRIPTOR_PLACEMENT_METADATA.to_string(),
                    serde_json::to_string(&extent_index_placement).map_err(ApiError::serde)?,
                )]),
                precondition: KeyPrecondition::Absent,
            });
        }
    }
    Ok((mutations, durability))
}

pub(super) async fn packed_small_object_location(
    state: &AppState,
    namespace: &NamespaceState,
    object_key: &[u8],
    logical_cid: &Cid,
) -> Result<Option<PackedSmallObjectLocation>, ApiError> {
    if logical_cid.codec != CODEC_SMALL_OBJECT {
        return Ok(None);
    }
    let value = pepper_merkle::get(
        &direct_namespace_store(state, namespace).await,
        &namespace.current_root_cid,
        &index_key(object_key, logical_cid),
        MerkleLimits::default(),
    )
    .await
    .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let Some(value) = value else {
        metrics::SMALL_OBJECT_PACK_INDEX_MISSES.fetch_add(1, Ordering::Relaxed);
        return Ok(None);
    };
    parse_packed_location(state, &value, logical_cid).map(Some)
}

pub(super) fn packed_small_object_location_from_object_value(
    state: &AppState,
    value: &MerkleValue,
    logical_cid: &Cid,
    logical_length: u64,
) -> Result<Option<PackedSmallObjectLocation>, ApiError> {
    let Some(encoded) = value.metadata.get(SMALL_OBJECT_LOCATION_METADATA) else {
        return Ok(None);
    };
    let packed: PackedSmallObjectMetadata =
        serde_json::from_str(encoded).map_err(ApiError::serde)?;
    let placement = PlacementReference::replicated(
        packed.placement_epoch,
        packed.extent_cid.clone(),
        packed.placement_replicas,
    );
    let encoding = match packed.encoding {
        0 => ErasureStripeEncoding::Raw,
        1 => ErasureStripeEncoding::Zstd,
        _ => {
            return Err(ApiError::internal(
                "small-object location has invalid record encoding",
            ));
        }
    };
    if packed.version != 1
        || logical_cid.codec != CODEC_SMALL_OBJECT
        || placement.validate().is_err()
        || packed.stored_length == 0
        || logical_length == 0
        || logical_length > state.small_object_max_bytes.unwrap_or(0)
    {
        return Err(ApiError::internal("small-object location is invalid"));
    }
    metrics::SMALL_OBJECT_PACK_INDEX_HITS.fetch_add(1, Ordering::Relaxed);
    Ok(Some(PackedSmallObjectLocation {
        extent_cid: packed.extent_cid,
        extent_placement: placement,
        offset: packed.offset,
        stored_length: packed.stored_length,
        logical_length,
        encoding,
    }))
}

fn parse_packed_location(
    state: &AppState,
    value: &MerkleValue,
    logical_cid: &Cid,
) -> Result<PackedSmallObjectLocation, ApiError> {
    let recorded_logical_cid = value
        .metadata
        .get(SMALL_OBJECT_LOGICAL_CID_METADATA)
        .ok_or_else(|| ApiError::internal("small-object extent omitted logical CID"))?
        .parse::<Cid>()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    if &recorded_logical_cid != logical_cid {
        return Err(ApiError::internal(
            "small-object extent location does not match object content CID",
        ));
    }
    let placement =
        metadata_json::<PlacementReference>(value, SMALL_OBJECT_EXTENT_PLACEMENT_METADATA)?;
    let extent_cid = value
        .metadata
        .get(SMALL_OBJECT_EXTENT_CID_METADATA)
        .map(|encoded| {
            encoded
                .parse::<Cid>()
                .map_err(|error| ApiError::internal(error.to_string()))
        })
        .transpose()?
        .unwrap_or_else(|| value.cid.clone());
    if placement.seed != extent_cid || placement.validate().is_err() {
        return Err(ApiError::internal(
            "small-object extent index has invalid placement",
        ));
    }
    let offset = metadata_u64(value, SMALL_OBJECT_EXTENT_OFFSET_METADATA)?;
    let stored_length = metadata_u64(value, SMALL_OBJECT_EXTENT_LENGTH_METADATA)?;
    let logical_length = metadata_u64(value, SMALL_OBJECT_LOGICAL_LENGTH_METADATA)?;
    let encoding = match value
        .metadata
        .get(SMALL_OBJECT_RECORD_ENCODING_METADATA)
        .map(String::as_str)
    {
        Some("raw") => ErasureStripeEncoding::Raw,
        Some("zstd") => ErasureStripeEncoding::Zstd,
        _ => {
            return Err(ApiError::internal(
                "small-object extent index has invalid record encoding",
            ));
        }
    };
    if stored_length == 0
        || logical_length == 0
        || logical_length > state.small_object_max_bytes.unwrap_or(0)
    {
        return Err(ApiError::internal(
            "small-object extent index has invalid record length",
        ));
    }
    metrics::SMALL_OBJECT_PACK_INDEX_HITS.fetch_add(1, Ordering::Relaxed);
    Ok(PackedSmallObjectLocation {
        extent_cid,
        extent_placement: placement,
        offset,
        stored_length,
        logical_length,
        encoding,
    })
}

fn metadata_json<T: serde::de::DeserializeOwned>(
    value: &MerkleValue,
    name: &str,
) -> Result<T, ApiError> {
    let encoded = value
        .metadata
        .get(name)
        .ok_or_else(|| ApiError::internal(format!("small-object index omitted {name}")))?;
    serde_json::from_str(encoded).map_err(ApiError::serde)
}

pub(super) fn extent_placement_from_value(
    value: &MerkleValue,
) -> Result<Option<PlacementReference>, ApiError> {
    let Some(encoded) = value.metadata.get(SMALL_OBJECT_EXTENT_PLACEMENT_METADATA) else {
        return Ok(None);
    };
    let placement: PlacementReference = serde_json::from_str(encoded).map_err(ApiError::serde)?;
    if placement.seed != value.cid || placement.validate().is_err() {
        return Err(ApiError::internal(
            "small-object extent index has invalid placement",
        ));
    }
    Ok(Some(placement))
}

fn metadata_u64(value: &MerkleValue, name: &str) -> Result<u64, ApiError> {
    value
        .metadata
        .get(name)
        .ok_or_else(|| ApiError::internal(format!("small-object index omitted {name}")))?
        .parse::<u64>()
        .map_err(|error| ApiError::internal(error.to_string()))
}

fn parse_pending(key: Vec<u8>, value: MerkleValue) -> Result<PendingSmallObject, ApiError> {
    if value.cid.codec != CODEC_SMALL_OBJECT {
        return Err(ApiError::internal(
            "small-object pending record references a non-small CID",
        ));
    }
    let placement = metadata_json::<PlacementReference>(&value, SMALL_OBJECT_PLACEMENT_METADATA)?;
    if placement.seed != value.cid || placement.validate().is_err() {
        return Err(ApiError::internal(
            "small-object pending record has invalid placement",
        ));
    }
    let logical_size = metadata_u64(&value, SMALL_OBJECT_SIZE_METADATA)?;
    let enqueued_at_unix_seconds = value
        .metadata
        .get(SMALL_OBJECT_ENQUEUED_METADATA)
        .ok_or_else(|| ApiError::internal("small-object pending record omitted enqueue time"))?
        .parse::<i64>()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let object_key = value
        .metadata
        .get(SMALL_OBJECT_KEY_METADATA)
        .ok_or_else(|| ApiError::internal("small-object pending record omitted object key"))
        .and_then(|encoded| {
            hex::decode(encoded).map_err(|error| ApiError::internal(error.to_string()))
        })?;
    if pending_key(&object_key, &value.cid) != key {
        return Err(ApiError::internal(
            "small-object pending key does not match its object identity",
        ));
    }
    Ok(PendingSmallObject {
        key,
        object_key,
        value,
        placement,
        logical_size,
        enqueued_at_unix_seconds,
    })
}

async fn scan_pending(
    state: &AppState,
    namespace: &NamespaceState,
    limit: usize,
) -> Result<Vec<PendingSmallObject>, ApiError> {
    let page = pepper_merkle::scan(
        &direct_namespace_store(state, namespace).await,
        &namespace.current_root_cid,
        ScanQuery {
            prefix: Some(SMALL_OBJECT_PENDING_PREFIX.to_vec()),
            limit,
            ..ScanQuery::default()
        },
        MerkleLimits::default(),
    )
    .await
    .map_err(|error| ApiError::bad_request(error.to_string()))?;
    page.entries
        .into_iter()
        .map(|entry| parse_pending(entry.key, entry.value))
        .collect()
}

fn parse_live_extent_record(
    key: Vec<u8>,
    value: MerkleValue,
) -> Result<LiveExtentRecord, ApiError> {
    if value.cid.codec != CODEC_ERASURE_MANIFEST {
        return Err(ApiError::internal(
            "small-object extent index references a non-EC extent",
        ));
    }
    let object_key = value
        .metadata
        .get(SMALL_OBJECT_KEY_METADATA)
        .ok_or_else(|| ApiError::internal("small-object extent omitted object key"))
        .and_then(|encoded| {
            hex::decode(encoded).map_err(|error| ApiError::internal(error.to_string()))
        })?;
    let logical_cid = value
        .metadata
        .get(SMALL_OBJECT_LOGICAL_CID_METADATA)
        .ok_or_else(|| ApiError::internal("small-object extent omitted logical CID"))?
        .parse::<Cid>()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    if logical_cid.codec != CODEC_SMALL_OBJECT || index_key(&object_key, &logical_cid) != key {
        return Err(ApiError::internal(
            "small-object extent index key does not match its logical identity",
        ));
    }
    let logical_size = metadata_u64(&value, SMALL_OBJECT_LOGICAL_LENGTH_METADATA)?;
    let stored_length = metadata_u64(&value, SMALL_OBJECT_EXTENT_LENGTH_METADATA)?;
    let extent_total_bytes = metadata_u64(&value, SMALL_OBJECT_EXTENT_TOTAL_BYTES_METADATA)?;
    let extent_records = metadata_u64(&value, SMALL_OBJECT_EXTENT_RECORDS_METADATA)?;
    if logical_size == 0
        || stored_length == 0
        || extent_total_bytes < stored_length
        || extent_records == 0
    {
        return Err(ApiError::internal(
            "small-object extent index contains invalid compaction metadata",
        ));
    }
    Ok(LiveExtentRecord {
        key,
        object_key,
        logical_cid,
        value,
        logical_size,
        stored_length,
        extent_total_bytes,
        extent_records,
    })
}

async fn scan_dirty_extent_candidates(
    state: &AppState,
    namespace: &NamespaceState,
) -> Result<Vec<DirtyExtentCandidate>, ApiError> {
    let mut cursor = None;
    let mut candidates = Vec::new();
    let store = direct_namespace_store(state, namespace).await;
    loop {
        let page = pepper_merkle::scan(
            &store,
            &namespace.current_root_cid,
            ScanQuery {
                prefix: Some(SMALL_OBJECT_DIRTY_EXTENT_PREFIX.to_vec()),
                limit: 1_000,
                cursor,
                ..ScanQuery::default()
            },
            MerkleLimits::default(),
        )
        .await
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
        for entry in page.entries {
            if entry.key != dirty_extent_key(&entry.value.cid)
                || entry.value.cid.codec != CODEC_SMALL_OBJECT_EXTENT_INDEX
            {
                return Err(ApiError::internal(
                    "dirty small-object extent entry is invalid",
                ));
            }
            let placement = placement_from_merkle_value(&entry.value)?;
            let block = get_block_at_placement(state, &entry.value.cid, &placement).await?;
            let descriptor = decode_extent_index(&block.payload)?;
            let catalog_key = extent_catalog_key(&entry.value.cid);
            let catalog_value = pepper_merkle::get(
                &store,
                &namespace.current_root_cid,
                &catalog_key,
                MerkleLimits::default(),
            )
            .await
            .map_err(|error| ApiError::bad_request(error.to_string()))?
            .ok_or_else(|| ApiError::internal("dirty extent omitted its catalog entry"))?;
            if catalog_value.cid != entry.value.cid {
                return Err(ApiError::internal(
                    "dirty extent catalog references a different index",
                ));
            }
            let mut live = Vec::new();
            for record in &descriptor.records {
                let key = hex::decode(&record.index_key_hex)
                    .map_err(|error| ApiError::bad_request(error.to_string()))?;
                let Some(value) = pepper_merkle::get(
                    &store,
                    &namespace.current_root_cid,
                    &key,
                    MerkleLimits::default(),
                )
                .await
                .map_err(|error| ApiError::bad_request(error.to_string()))?
                else {
                    continue;
                };
                if value.cid != descriptor.extent_cid
                    || value.metadata.get(SMALL_OBJECT_EXTENT_INDEX_CID_METADATA)
                        != Some(&entry.value.cid.to_string())
                {
                    continue;
                }
                live.push(parse_live_extent_record(key, value)?);
            }
            candidates.push(DirtyExtentCandidate {
                dirty_key: entry.key,
                dirty_value: entry.value,
                catalog_key,
                catalog_value,
                descriptor,
                live,
            });
        }
        if candidates.len() > 10_000 {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::RateLimited,
                "dirty small-object extent scan exceeded its bounded budget",
            ));
        }
        let Some(next) = page.next_cursor else {
            break;
        };
        cursor = Some(next);
    }
    Ok(candidates)
}

fn select_pending(
    mut pending: Vec<PendingSmallObject>,
    config: &SmallObjectPackConfig,
    force: bool,
) -> Vec<PendingSmallObject> {
    pending.sort_by(|left, right| left.key.cmp(&right.key));
    let mut selected = Vec::new();
    let mut bytes = 0u64;
    for record in pending.into_iter().take(config.group_commit_max_requests) {
        if !selected.is_empty() && bytes.saturating_add(record.logical_size) > config.segment_bytes
        {
            break;
        }
        bytes = bytes.saturating_add(record.logical_size);
        selected.push(record);
    }
    let old_enough = selected.first().is_some_and(|record| {
        unix_seconds().saturating_sub(record.enqueued_at_unix_seconds)
            >= SMALL_OBJECT_PACK_FLUSH_SECONDS
    });
    if !force && bytes < config.segment_bytes && !old_enough {
        Vec::new()
    } else {
        selected
    }
}

async fn fetch_pending(
    state: &AppState,
    selected: Vec<PendingSmallObject>,
) -> Result<(Vec<FetchedSmallObject>, Vec<u8>), ApiError> {
    let mut fetched = stream::iter(selected.into_iter().map(|pending| {
        let state = state.clone();
        async move {
            let block =
                get_block_at_placement(&state, &pending.value.cid, &pending.placement).await?;
            if block.payload.len() as u64 != pending.logical_size {
                return Err(ApiError::internal(
                    "small-object pending record size does not match content",
                ));
            }
            let (encoding, stored_payload, _) = tokio::task::spawn_blocking(move || {
                encode_erasure_stripe_payload(block.payload, Vec::new())
            })
            .await
            .map_err(|error| {
                ApiError::internal(format!("small-object compressor task failed: {error}"))
            })??;
            Ok::<_, ApiError>((pending, encoding, stored_payload))
        }
    }))
    .buffer_unordered(SMALL_OBJECT_PACK_FETCH_CONCURRENCY)
    .collect::<Vec<_>>()
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    fetched.sort_by(|left, right| left.0.key.cmp(&right.0.key));
    let total_bytes = fetched.iter().try_fold(0usize, |total, (_, _, payload)| {
        total
            .checked_add(payload.len())
            .ok_or_else(|| ApiError::internal("small-object extent size overflow"))
    })?;
    let mut extent = Vec::with_capacity(total_bytes);
    let mut records = Vec::with_capacity(fetched.len());
    for (pending, encoding, stored_payload) in fetched {
        let offset = extent.len() as u64;
        extent.extend_from_slice(&stored_payload);
        records.push(FetchedSmallObject {
            pending,
            offset,
            stored_payload,
            encoding,
        });
    }
    Ok((records, extent))
}

async fn store_extent_index(
    state: &AppState,
    descriptor: SmallObjectExtentIndex,
) -> Result<StoredSmallObjectExtentIndex, ApiError> {
    let payload = encode_extent_index(&descriptor)?;
    let receipt = put_replicated_block(state, CODEC_SMALL_OBJECT_EXTENT_INDEX, payload).await?;
    if receipt.cid.codec != CODEC_SMALL_OBJECT_EXTENT_INDEX || receipt.placement.is_none() {
        return Err(ApiError::internal(
            "small-object extent index omitted durable placement",
        ));
    }
    Ok(StoredSmallObjectExtentIndex { receipt })
}

async fn store_fetched_extent_index(
    state: &AppState,
    records: &[FetchedSmallObject],
    extent: &ObjectWriteReceipts,
) -> Result<StoredSmallObjectExtentIndex, ApiError> {
    let extent_placement = extent
        .receipt
        .placement
        .clone()
        .ok_or_else(|| ApiError::internal("small-object extent placement is missing"))?;
    let descriptor = SmallObjectExtentIndex {
        version: SMALL_OBJECT_EXTENT_INDEX_VERSION,
        extent_cid: extent.receipt.cid.clone(),
        extent_placement,
        total_bytes: records
            .iter()
            .map(|record| record.stored_payload.len() as u64)
            .sum(),
        records: records
            .iter()
            .map(|record| SmallObjectExtentIndexRecord {
                index_key_hex: hex::encode(index_key(
                    &record.pending.object_key,
                    &record.pending.value.cid,
                )),
                object_key_hex: hex::encode(&record.pending.object_key),
                logical_cid: record.pending.value.cid.clone(),
                logical_size: record.pending.logical_size,
                offset: record.offset,
                stored_length: record.stored_payload.len() as u64,
                encoding: record.encoding,
            })
            .collect(),
    };
    store_extent_index(state, descriptor).await
}

async fn store_repacked_extent_index(
    state: &AppState,
    records: &[RepackedExtentRecord],
    extent: &ObjectWriteReceipts,
) -> Result<StoredSmallObjectExtentIndex, ApiError> {
    let extent_placement = extent
        .receipt
        .placement
        .clone()
        .ok_or_else(|| ApiError::internal("compacted extent placement is missing"))?;
    let descriptor = SmallObjectExtentIndex {
        version: SMALL_OBJECT_EXTENT_INDEX_VERSION,
        extent_cid: extent.receipt.cid.clone(),
        extent_placement,
        total_bytes: records
            .iter()
            .map(|record| record.stored_payload.len() as u64)
            .sum(),
        records: records
            .iter()
            .map(|record| SmallObjectExtentIndexRecord {
                index_key_hex: hex::encode(&record.live.key),
                object_key_hex: hex::encode(&record.live.object_key),
                logical_cid: record.live.logical_cid.clone(),
                logical_size: record.live.logical_size,
                offset: record.offset,
                stored_length: record.stored_payload.len() as u64,
                encoding: record.encoding,
            })
            .collect(),
    };
    store_extent_index(state, descriptor).await
}

fn extent_state_metadata(
    extent_index: &StoredSmallObjectExtentIndex,
) -> Result<BTreeMap<String, String>, ApiError> {
    let placement = extent_index
        .receipt
        .placement
        .as_ref()
        .ok_or_else(|| ApiError::internal("extent index placement is missing"))?;
    Ok(BTreeMap::from([(
        BUCKET_DESCRIPTOR_PLACEMENT_METADATA.to_string(),
        serde_json::to_string(placement).map_err(ApiError::serde)?,
    )]))
}

struct ExtentIndexMetadataInput<'a> {
    placement: &'a PlacementReference,
    extent_index: &'a StoredSmallObjectExtentIndex,
    offset: u64,
    stored_length: u64,
    extent_total_bytes: u64,
    extent_records: u64,
    logical_length: u64,
    logical_cid: &'a Cid,
    encoding: ErasureStripeEncoding,
    object_key: &'a [u8],
}

fn extent_index_metadata(
    input: ExtentIndexMetadataInput<'_>,
) -> Result<BTreeMap<String, String>, ApiError> {
    let ExtentIndexMetadataInput {
        placement,
        extent_index,
        offset,
        stored_length,
        extent_total_bytes,
        extent_records,
        logical_length,
        logical_cid,
        encoding,
        object_key,
    } = input;
    let mut metadata = BTreeMap::new();
    metadata.insert(
        SMALL_OBJECT_EXTENT_PLACEMENT_METADATA.to_string(),
        serde_json::to_string(placement).map_err(ApiError::serde)?,
    );
    metadata.insert(
        SMALL_OBJECT_EXTENT_CID_METADATA.to_string(),
        placement.seed.to_string(),
    );
    metadata.insert(
        SMALL_OBJECT_EXTENT_INDEX_CID_METADATA.to_string(),
        extent_index.receipt.cid.to_string(),
    );
    metadata.insert(
        SMALL_OBJECT_EXTENT_INDEX_PLACEMENT_METADATA.to_string(),
        serde_json::to_string(
            extent_index
                .receipt
                .placement
                .as_ref()
                .ok_or_else(|| ApiError::internal("extent index placement is missing"))?,
        )
        .map_err(ApiError::serde)?,
    );
    metadata.insert(
        SMALL_OBJECT_EXTENT_OFFSET_METADATA.to_string(),
        offset.to_string(),
    );
    metadata.insert(
        SMALL_OBJECT_EXTENT_LENGTH_METADATA.to_string(),
        stored_length.to_string(),
    );
    metadata.insert(
        SMALL_OBJECT_EXTENT_TOTAL_BYTES_METADATA.to_string(),
        extent_total_bytes.to_string(),
    );
    metadata.insert(
        SMALL_OBJECT_EXTENT_RECORDS_METADATA.to_string(),
        extent_records.to_string(),
    );
    metadata.insert(
        SMALL_OBJECT_LOGICAL_LENGTH_METADATA.to_string(),
        logical_length.to_string(),
    );
    metadata.insert(
        SMALL_OBJECT_LOGICAL_CID_METADATA.to_string(),
        logical_cid.to_string(),
    );
    metadata.insert(
        SMALL_OBJECT_RECORD_ENCODING_METADATA.to_string(),
        match encoding {
            ErasureStripeEncoding::Raw => "raw",
            ErasureStripeEncoding::Zstd => "zstd",
        }
        .to_string(),
    );
    metadata.insert(
        SMALL_OBJECT_KEY_METADATA.to_string(),
        hex::encode(object_key),
    );
    Ok(metadata)
}

fn object_location_metadata(
    placement: &PlacementReference,
    offset: u64,
    stored_length: u64,
    encoding: ErasureStripeEncoding,
) -> Result<BTreeMap<String, String>, ApiError> {
    if placement.role != PlacementRole::Replicated || placement.seed.codec != CODEC_ERASURE_MANIFEST
    {
        return Err(ApiError::internal(
            "small-object extent has invalid object placement",
        ));
    }
    let packed = PackedSmallObjectMetadata {
        version: 1,
        placement_epoch: placement.epoch,
        placement_replicas: placement.replicas,
        extent_cid: placement.seed.clone(),
        offset,
        stored_length,
        encoding: match encoding {
            ErasureStripeEncoding::Raw => 0,
            ErasureStripeEncoding::Zstd => 1,
        },
    };
    Ok(BTreeMap::from([(
        SMALL_OBJECT_LOCATION_METADATA.to_string(),
        serde_json::to_string(&packed).map_err(ApiError::serde)?,
    )]))
}

async fn preverify_object_values(
    state: &AppState,
    values: Vec<MerkleValue>,
    replication_factor: usize,
) -> Result<Vec<DurabilityReceipt>, ApiError> {
    let mut seen = HashSet::new();
    let unique = values
        .into_iter()
        .filter(|value| seen.insert(value.cid.clone()))
        .collect::<Vec<_>>();
    stream::iter(unique.into_iter().map(|value| {
        let state = state.clone();
        async move {
            let placement = placement_from_merkle_value(&value)?;
            AgentDurabilityBackend(state)
                .ensure_at_placement(&value.cid, replication_factor, placement)
                .await
                .map_err(|error| ApiError::internal(error.to_string()))
        }
    }))
    .buffer_unordered(SMALL_OBJECT_PACK_FETCH_CONCURRENCY)
    .collect::<Vec<_>>()
    .await
    .into_iter()
    .collect()
}

async fn transition_extent(
    state: &AppState,
    namespace_id: &NamespaceId,
    records: &[FetchedSmallObject],
    extent: &ObjectWriteReceipts,
    extent_index: &StoredSmallObjectExtentIndex,
) -> Result<(u64, u64), ApiError> {
    let extent_placement =
        extent.receipt.placement.clone().ok_or_else(|| {
            ApiError::internal("small-object extent omitted authoritative placement")
        })?;
    let extent_total_bytes = records
        .iter()
        .map(|record| record.stored_payload.len() as u64)
        .sum::<u64>();
    let extent_records = records.len() as u64;
    for _ in 0..SMALL_OBJECT_PACK_TRANSITION_RETRIES {
        let base = namespace_manager(state)?
            .linearizable_namespace_state(namespace_id)
            .await
            .map_err(consensus_error)?;
        let store = direct_namespace_store(state, &base).await;
        let mut mutations = Vec::with_capacity(records.len().saturating_mul(3).saturating_add(1));
        let mut transitioned_bytes = 0u64;
        let mut transitioned = 0u64;
        let mut object_values = Vec::with_capacity(records.len());
        for record in records {
            let current = pepper_merkle::get(
                &store,
                &base.current_root_cid,
                &record.pending.key,
                MerkleLimits::default(),
            )
            .await
            .map_err(|error| ApiError::bad_request(error.to_string()))?;
            if current.as_ref() != Some(&record.pending.value) {
                continue;
            }
            if pepper_merkle::get(
                &store,
                &base.current_root_cid,
                &index_key(&record.pending.object_key, &record.pending.value.cid),
                MerkleLimits::default(),
            )
            .await
            .map_err(|error| ApiError::bad_request(error.to_string()))?
            .is_some()
            {
                continue;
            }
            let metadata = extent_index_metadata(ExtentIndexMetadataInput {
                placement: &extent_placement,
                extent_index,
                offset: record.offset,
                stored_length: record.stored_payload.len() as u64,
                extent_total_bytes,
                extent_records,
                logical_length: record.pending.logical_size,
                logical_cid: &record.pending.value.cid,
                encoding: record.encoding,
                object_key: &record.pending.object_key,
            })?;
            let object_value = pepper_merkle::get(
                &store,
                &base.current_root_cid,
                &record.pending.object_key,
                MerkleLimits::default(),
            )
            .await
            .map_err(|error| ApiError::bad_request(error.to_string()))?
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    ErrorCode::Conflict,
                    "small-object descriptor disappeared during pack transition",
                )
            })?;
            mutations.push(NamespaceMutation::Put {
                key_hex: hex::encode(index_key(
                    &record.pending.object_key,
                    &record.pending.value.cid,
                )),
                value_cid: extent.receipt.cid.clone(),
                value_kind: "small_object_extent".to_string(),
                metadata: metadata.clone(),
                precondition: KeyPrecondition::Absent,
            });
            let mut object_metadata = object_value.metadata.clone();
            object_metadata.extend(object_location_metadata(
                &extent_placement,
                record.offset,
                record.stored_payload.len() as u64,
                record.encoding,
            )?);
            object_values.push(object_value.clone());
            mutations.push(NamespaceMutation::Put {
                key_hex: hex::encode(&record.pending.object_key),
                value_cid: object_value.cid.clone(),
                value_kind: object_value.value_kind.clone(),
                metadata: object_metadata,
                precondition: KeyPrecondition::Match {
                    generation: object_value.generation,
                    cid: object_value.cid,
                },
            });
            mutations.push(NamespaceMutation::Delete {
                key_hex: hex::encode(&record.pending.key),
                precondition: KeyPrecondition::Match {
                    generation: record.pending.value.generation,
                    cid: record.pending.value.cid.clone(),
                },
            });
            transitioned_bytes = transitioned_bytes.saturating_add(record.pending.logical_size);
            transitioned = transitioned.saturating_add(1);
        }
        if mutations.is_empty() {
            return Ok((0, 0));
        }
        mutations.push(NamespaceMutation::Put {
            key_hex: hex::encode(extent_catalog_key(&extent_index.receipt.cid)),
            value_cid: extent_index.receipt.cid.clone(),
            value_kind: "small_object_extent_index".to_string(),
            metadata: extent_state_metadata(extent_index)?,
            precondition: KeyPrecondition::Absent,
        });
        mutations.push(repair_inventory_mutation(
            base.current_revision.saturating_add(1),
            PlacedCid {
                cid: extent_index.receipt.cid.clone(),
                placement: extent_index
                    .receipt
                    .placement
                    .clone()
                    .ok_or_else(|| ApiError::internal("extent index placement is missing"))?,
            },
            Some(PlacedCid {
                cid: extent.receipt.cid.clone(),
                placement: extent_placement.clone(),
            }),
            extent_total_bytes,
            unix_seconds(),
        )?);
        mutations.sort_by(|left, right| mutation_key(left).cmp(mutation_key(right)));
        let mut preverified_durability = extent.blocks.clone();
        preverified_durability.push(extent_index.receipt.clone());
        preverified_durability.extend(
            preverify_object_values(
                state,
                object_values,
                usize::from(base.descriptor.durability.replicas),
            )
            .await?,
        );
        let command = CommandEnvelope {
            request_id: format!(
                "small-pack-{}-{}-{}",
                hex::encode(&namespace_id.0.digest[..8]),
                hex::encode(&extent.receipt.cid.digest[..8]),
                base.current_revision
            ),
            writer_identity: "small-object-packer".to_string(),
            timestamp_unix_seconds: unix_seconds(),
            signature_hex: "00".to_string(),
            command: NamespaceCommand::ApplyTransaction {
                transaction: TransactionCommand {
                    base_revision: base.current_revision,
                    base_root_cid: base.current_root_cid,
                    mutations,
                    message: Some("small-object extent transition".to_string()),
                },
            },
        };
        match apply_command(
            state,
            namespace_id.clone(),
            command,
            vec![extent.receipt.cid.clone(), extent_index.receipt.cid.clone()],
            preverified_durability,
            transitioned_bytes,
            true,
        )
        .await
        {
            Ok(_) => return Ok((transitioned, transitioned_bytes)),
            Err(error) if error.code == ErrorCode::Conflict => continue,
            Err(error) => return Err(error),
        }
    }
    Err(ApiError::new(
        StatusCode::CONFLICT,
        ErrorCode::Conflict,
        "small-object extent transition remained busy after bounded retries",
    ))
}

fn select_extent_for_compaction(
    candidates: Vec<DirtyExtentCandidate>,
    dead_percent_threshold: u8,
) -> Result<Option<DirtyExtentCandidate>, ApiError> {
    let mut eligible = Vec::new();
    for mut candidate in candidates {
        candidate
            .live
            .sort_by(|left, right| left.key.cmp(&right.key));
        let total_bytes = candidate.descriptor.total_bytes;
        let total_records = candidate.descriptor.records.len() as u64;
        if candidate.live.iter().any(|record| {
            record.value.cid != candidate.descriptor.extent_cid
                || record.extent_total_bytes != total_bytes
                || record.extent_records != total_records
        }) {
            return Err(ApiError::internal(format!(
                "small-object extent {} has inconsistent compaction metadata",
                candidate.descriptor.extent_cid
            )));
        }
        let live_bytes = candidate
            .live
            .iter()
            .map(|record| record.stored_length)
            .sum::<u64>();
        if live_bytes > total_bytes || candidate.live.len() as u64 > total_records {
            return Err(ApiError::internal(format!(
                "small-object extent {} live accounting exceeds its original extent",
                candidate.descriptor.extent_cid
            )));
        }
        let dead_bytes = total_bytes.saturating_sub(live_bytes);
        if dead_bytes > 0
            && dead_bytes.saturating_mul(100)
                >= total_bytes.saturating_mul(u64::from(dead_percent_threshold))
        {
            eligible.push((dead_bytes, candidate));
        }
    }
    eligible.sort_by(|left, right| {
        right.0.cmp(&left.0).then_with(|| {
            left.1
                .descriptor
                .extent_cid
                .to_string()
                .cmp(&right.1.descriptor.extent_cid.to_string())
        })
    });
    Ok(eligible.into_iter().next().map(|(_, candidate)| candidate))
}

async fn fetch_live_extent_records(
    state: &AppState,
    namespace: &NamespaceState,
    selected: Vec<LiveExtentRecord>,
) -> Result<(Vec<RepackedExtentRecord>, Vec<u8>), ApiError> {
    let mut fetched = stream::iter(selected.into_iter().map(|live| {
        let state = state.clone();
        let namespace = namespace.clone();
        async move {
            let payload = super::s3_api::packed_small_object_payload(
                &state,
                &namespace,
                &live.object_key,
                &live.logical_cid,
                live.logical_size,
                None,
            )
            .await?
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    ErrorCode::Conflict,
                    "small-object extent index changed during compaction",
                )
            })?;
            let (encoding, stored_payload, _) = tokio::task::spawn_blocking(move || {
                encode_erasure_stripe_payload(payload.to_vec(), Vec::new())
            })
            .await
            .map_err(|error| {
                ApiError::internal(format!("small-object compactor task failed: {error}"))
            })??;
            Ok::<_, ApiError>((live, encoding, stored_payload))
        }
    }))
    .buffer_unordered(SMALL_OBJECT_PACK_FETCH_CONCURRENCY)
    .collect::<Vec<_>>()
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    fetched.sort_by(|left, right| left.0.key.cmp(&right.0.key));
    let total_bytes = fetched.iter().try_fold(0usize, |total, (_, _, payload)| {
        total
            .checked_add(payload.len())
            .ok_or_else(|| ApiError::internal("compacted extent size overflow"))
    })?;
    let mut extent = Vec::with_capacity(total_bytes);
    let mut records = Vec::with_capacity(fetched.len());
    for (live, encoding, stored_payload) in fetched {
        let offset = extent.len() as u64;
        extent.extend_from_slice(&stored_payload);
        records.push(RepackedExtentRecord {
            live,
            offset,
            stored_payload,
            encoding,
        });
    }
    Ok((records, extent))
}

async fn transition_compacted_extent(
    state: &AppState,
    namespace_id: &NamespaceId,
    old: &DirtyExtentCandidate,
    records: &[RepackedExtentRecord],
    extent: &ObjectWriteReceipts,
    extent_index: &StoredSmallObjectExtentIndex,
) -> Result<bool, ApiError> {
    let extent_placement =
        extent.receipt.placement.clone().ok_or_else(|| {
            ApiError::internal("compacted extent omitted authoritative placement")
        })?;
    let extent_total_bytes = records
        .iter()
        .map(|record| record.stored_payload.len() as u64)
        .sum::<u64>();
    let extent_records = records.len() as u64;
    for _ in 0..SMALL_OBJECT_PACK_TRANSITION_RETRIES {
        let base = namespace_manager(state)?
            .linearizable_namespace_state(namespace_id)
            .await
            .map_err(consensus_error)?;
        let store = direct_namespace_store(state, &base).await;
        if pepper_merkle::get(
            &store,
            &base.current_root_cid,
            &old.dirty_key,
            MerkleLimits::default(),
        )
        .await
        .map_err(|error| ApiError::bad_request(error.to_string()))?
        .as_ref()
            != Some(&old.dirty_value)
            || pepper_merkle::get(
                &store,
                &base.current_root_cid,
                &old.catalog_key,
                MerkleLimits::default(),
            )
            .await
            .map_err(|error| ApiError::bad_request(error.to_string()))?
            .as_ref()
                != Some(&old.catalog_value)
        {
            return Ok(false);
        }
        let mut mutations = Vec::with_capacity(records.len().saturating_mul(2).saturating_add(3));
        let mut object_values = Vec::with_capacity(records.len());
        for record in records {
            let current = pepper_merkle::get(
                &store,
                &base.current_root_cid,
                &record.live.key,
                MerkleLimits::default(),
            )
            .await
            .map_err(|error| ApiError::bad_request(error.to_string()))?;
            if current.as_ref() != Some(&record.live.value) {
                return Ok(false);
            }
            let metadata = extent_index_metadata(ExtentIndexMetadataInput {
                placement: &extent_placement,
                extent_index,
                offset: record.offset,
                stored_length: record.stored_payload.len() as u64,
                extent_total_bytes,
                extent_records,
                logical_length: record.live.logical_size,
                logical_cid: &record.live.logical_cid,
                encoding: record.encoding,
                object_key: &record.live.object_key,
            })?;
            let object_value = pepper_merkle::get(
                &store,
                &base.current_root_cid,
                &record.live.object_key,
                MerkleLimits::default(),
            )
            .await
            .map_err(|error| ApiError::bad_request(error.to_string()))?
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    ErrorCode::Conflict,
                    "small-object descriptor disappeared during extent compaction",
                )
            })?;
            let Some(old_location) = packed_small_object_location_from_object_value(
                state,
                &object_value,
                &record.live.logical_cid,
                record.live.logical_size,
            )?
            else {
                return Ok(false);
            };
            if old_location.extent_cid != record.live.value.cid {
                return Ok(false);
            }
            object_values.push(object_value.clone());
            mutations.push(NamespaceMutation::Put {
                key_hex: hex::encode(&record.live.key),
                value_cid: extent.receipt.cid.clone(),
                value_kind: "small_object_extent".to_string(),
                metadata: metadata.clone(),
                precondition: KeyPrecondition::Match {
                    generation: record.live.value.generation,
                    cid: record.live.value.cid.clone(),
                },
            });
            let mut object_metadata = object_value.metadata.clone();
            object_metadata.extend(object_location_metadata(
                &extent_placement,
                record.offset,
                record.stored_payload.len() as u64,
                record.encoding,
            )?);
            mutations.push(NamespaceMutation::Put {
                key_hex: hex::encode(&record.live.object_key),
                value_cid: object_value.cid.clone(),
                value_kind: object_value.value_kind.clone(),
                metadata: object_metadata,
                precondition: KeyPrecondition::Match {
                    generation: object_value.generation,
                    cid: object_value.cid,
                },
            });
        }
        mutations.push(NamespaceMutation::Delete {
            key_hex: hex::encode(&old.dirty_key),
            precondition: KeyPrecondition::Match {
                generation: old.dirty_value.generation,
                cid: old.dirty_value.cid.clone(),
            },
        });
        mutations.push(NamespaceMutation::Delete {
            key_hex: hex::encode(&old.catalog_key),
            precondition: KeyPrecondition::Match {
                generation: old.catalog_value.generation,
                cid: old.catalog_value.cid.clone(),
            },
        });
        mutations.push(NamespaceMutation::Put {
            key_hex: hex::encode(extent_catalog_key(&extent_index.receipt.cid)),
            value_cid: extent_index.receipt.cid.clone(),
            value_kind: "small_object_extent_index".to_string(),
            metadata: extent_state_metadata(extent_index)?,
            precondition: KeyPrecondition::Absent,
        });
        mutations.push(repair_inventory_mutation(
            base.current_revision.saturating_add(1),
            PlacedCid {
                cid: extent_index.receipt.cid.clone(),
                placement: extent_index
                    .receipt
                    .placement
                    .clone()
                    .ok_or_else(|| ApiError::internal("extent index placement is missing"))?,
            },
            Some(PlacedCid {
                cid: extent.receipt.cid.clone(),
                placement: extent_placement.clone(),
            }),
            extent_total_bytes,
            unix_seconds(),
        )?);
        mutations.sort_by(|left, right| mutation_key(left).cmp(mutation_key(right)));
        let mut preverified_durability = extent.blocks.clone();
        preverified_durability.push(extent_index.receipt.clone());
        preverified_durability.extend(
            preverify_object_values(
                state,
                object_values,
                usize::from(base.descriptor.durability.replicas),
            )
            .await?,
        );
        let command = CommandEnvelope {
            request_id: format!(
                "small-compact-{}-{}-{}",
                hex::encode(&namespace_id.0.digest[..8]),
                hex::encode(&extent.receipt.cid.digest[..8]),
                base.current_revision
            ),
            writer_identity: "small-object-compactor".to_string(),
            timestamp_unix_seconds: unix_seconds(),
            signature_hex: "00".to_string(),
            command: NamespaceCommand::ApplyTransaction {
                transaction: TransactionCommand {
                    base_revision: base.current_revision,
                    base_root_cid: base.current_root_cid,
                    mutations,
                    message: Some("small-object extent compaction".to_string()),
                },
            },
        };
        match apply_command(
            state,
            namespace_id.clone(),
            command,
            vec![extent.receipt.cid.clone(), extent_index.receipt.cid.clone()],
            preverified_durability,
            extent_total_bytes,
            true,
        )
        .await
        {
            Ok(_) => return Ok(true),
            Err(error) if error.code == ErrorCode::Conflict => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

async fn retire_empty_extent(
    state: &AppState,
    namespace_id: &NamespaceId,
    extent: &DirtyExtentCandidate,
) -> Result<bool, ApiError> {
    for _ in 0..SMALL_OBJECT_PACK_TRANSITION_RETRIES {
        let base = namespace_manager(state)?
            .linearizable_namespace_state(namespace_id)
            .await
            .map_err(consensus_error)?;
        let store = direct_namespace_store(state, &base).await;
        if pepper_merkle::get(
            &store,
            &base.current_root_cid,
            &extent.dirty_key,
            MerkleLimits::default(),
        )
        .await
        .map_err(|error| ApiError::bad_request(error.to_string()))?
        .as_ref()
            != Some(&extent.dirty_value)
            || pepper_merkle::get(
                &store,
                &base.current_root_cid,
                &extent.catalog_key,
                MerkleLimits::default(),
            )
            .await
            .map_err(|error| ApiError::bad_request(error.to_string()))?
            .as_ref()
                != Some(&extent.catalog_value)
        {
            return Ok(false);
        }
        let mut mutations = vec![
            NamespaceMutation::Delete {
                key_hex: hex::encode(&extent.dirty_key),
                precondition: KeyPrecondition::Match {
                    generation: extent.dirty_value.generation,
                    cid: extent.dirty_value.cid.clone(),
                },
            },
            NamespaceMutation::Delete {
                key_hex: hex::encode(&extent.catalog_key),
                precondition: KeyPrecondition::Match {
                    generation: extent.catalog_value.generation,
                    cid: extent.catalog_value.cid.clone(),
                },
            },
        ];
        mutations.sort_by(|left, right| mutation_key(left).cmp(mutation_key(right)));
        let command = CommandEnvelope {
            request_id: format!(
                "small-retire-{}-{}-{}",
                hex::encode(&namespace_id.0.digest[..8]),
                hex::encode(&extent.descriptor.extent_cid.digest[..8]),
                base.current_revision
            ),
            writer_identity: "small-object-compactor".to_string(),
            timestamp_unix_seconds: unix_seconds(),
            signature_hex: "00".to_string(),
            command: NamespaceCommand::ApplyTransaction {
                transaction: TransactionCommand {
                    base_revision: base.current_revision,
                    base_root_cid: base.current_root_cid,
                    mutations,
                    message: Some("retire empty small-object extent".to_string()),
                },
            },
        };
        match apply_command(
            state,
            namespace_id.clone(),
            command,
            Vec::new(),
            Vec::new(),
            0,
            true,
        )
        .await
        {
            Ok(_) => return Ok(true),
            Err(error) if error.code == ErrorCode::Conflict => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

async fn clear_clean_dirty_extent(
    state: &AppState,
    namespace_id: &NamespaceId,
    extent: &DirtyExtentCandidate,
) -> Result<bool, ApiError> {
    for _ in 0..SMALL_OBJECT_PACK_TRANSITION_RETRIES {
        let base = namespace_manager(state)?
            .linearizable_namespace_state(namespace_id)
            .await
            .map_err(consensus_error)?;
        let current = pepper_merkle::get(
            &direct_namespace_store(state, &base).await,
            &base.current_root_cid,
            &extent.dirty_key,
            MerkleLimits::default(),
        )
        .await
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
        if current.as_ref() != Some(&extent.dirty_value) {
            return Ok(false);
        }
        let command = CommandEnvelope {
            request_id: format!(
                "small-clean-{}-{}-{}",
                hex::encode(&namespace_id.0.digest[..8]),
                hex::encode(&extent.descriptor.extent_cid.digest[..8]),
                base.current_revision
            ),
            writer_identity: "small-object-compactor".to_string(),
            timestamp_unix_seconds: unix_seconds(),
            signature_hex: "00".to_string(),
            command: NamespaceCommand::ApplyTransaction {
                transaction: TransactionCommand {
                    base_revision: base.current_revision,
                    base_root_cid: base.current_root_cid,
                    mutations: vec![NamespaceMutation::Delete {
                        key_hex: hex::encode(&extent.dirty_key),
                        precondition: KeyPrecondition::Match {
                            generation: extent.dirty_value.generation,
                            cid: extent.dirty_value.cid.clone(),
                        },
                    }],
                    message: Some("clear clean small-object extent marker".to_string()),
                },
            },
        };
        match apply_command(
            state,
            namespace_id.clone(),
            command,
            Vec::new(),
            Vec::new(),
            0,
            true,
        )
        .await
        {
            Ok(_) => return Ok(true),
            Err(error) if error.code == ErrorCode::Conflict => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

async fn compact_small_object_extent(
    state: &AppState,
    namespace: &NamespaceState,
    dead_percent_threshold: u8,
) -> Result<SmallObjectPackReport, ApiError> {
    let mut current = namespace.clone();
    let mut clean_markers_cleared = 0usize;
    let candidates = loop {
        let candidates = scan_dirty_extent_candidates(state, &current).await?;
        let clean = candidates.iter().find(|candidate| {
            candidate.live.len() == candidate.descriptor.records.len()
                && candidate
                    .live
                    .iter()
                    .map(|record| record.stored_length)
                    .sum::<u64>()
                    == candidate.descriptor.total_bytes
        });
        let Some(clean) = clean else {
            break candidates;
        };
        if clean_markers_cleared >= 1_024 {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::RateLimited,
                "clean small-object extent cleanup exceeded its bounded budget",
            ));
        }
        if !clear_clean_dirty_extent(state, &current.namespace_id, clean).await? {
            return Ok(SmallObjectPackReport::default());
        }
        clean_markers_cleared += 1;
        current = namespace_manager(state)?
            .linearizable_namespace_state(&current.namespace_id)
            .await
            .map_err(consensus_error)?;
    };
    let Some(selected) = select_extent_for_compaction(candidates, dead_percent_threshold)? else {
        return Ok(SmallObjectPackReport::default());
    };
    let old_total_bytes = selected.descriptor.total_bytes;
    if selected.live.is_empty() {
        if !retire_empty_extent(state, &namespace.namespace_id, &selected).await? {
            return Ok(SmallObjectPackReport::default());
        }
        metrics::SMALL_OBJECT_PACK_EXTENTS_COMPACTED.fetch_add(1, Ordering::Relaxed);
        metrics::SMALL_OBJECT_PACK_BYTES_RECLAIMED.fetch_add(old_total_bytes, Ordering::Relaxed);
        return Ok(SmallObjectPackReport {
            extents_compacted: 1,
            bytes_reclaimed: old_total_bytes,
            ..SmallObjectPackReport::default()
        });
    }
    let (records, payload) =
        fetch_live_extent_records(state, namespace, selected.live.clone()).await?;
    let new_total_bytes = payload.len() as u64;
    let extent = put_erasure_object_stream_receipts_with_compression(
        state,
        Body::from(payload),
        state.erasure_data_shards,
        state.erasure_parity_shards,
        false,
    )
    .await?;
    let extent_index = store_repacked_extent_index(state, &records, &extent).await?;
    if !transition_compacted_extent(
        state,
        &namespace.namespace_id,
        &selected,
        &records,
        &extent,
        &extent_index,
    )
    .await?
    {
        return Ok(SmallObjectPackReport::default());
    }
    let reclaimed = old_total_bytes.saturating_sub(new_total_bytes);
    metrics::SMALL_OBJECT_PACK_EXTENTS_WRITTEN.fetch_add(1, Ordering::Relaxed);
    metrics::SMALL_OBJECT_PACK_EXTENT_BYTES.fetch_add(new_total_bytes, Ordering::Relaxed);
    metrics::SMALL_OBJECT_PACK_EXTENTS_COMPACTED.fetch_add(1, Ordering::Relaxed);
    metrics::SMALL_OBJECT_PACK_RECORDS_COMPACTED.fetch_add(records.len() as u64, Ordering::Relaxed);
    metrics::SMALL_OBJECT_PACK_BYTES_RECLAIMED.fetch_add(reclaimed, Ordering::Relaxed);
    Ok(SmallObjectPackReport {
        extents_written: 1,
        encoded_bytes_written: new_total_bytes,
        extents_compacted: 1,
        records_compacted: records.len() as u64,
        bytes_reclaimed: reclaimed,
        extent_cids: vec![extent.receipt.cid],
        ..SmallObjectPackReport::default()
    })
}

pub(super) fn mutation_key(mutation: &NamespaceMutation) -> &str {
    match mutation {
        NamespaceMutation::Assert { key_hex, .. }
        | NamespaceMutation::Put { key_hex, .. }
        | NamespaceMutation::Delete { key_hex, .. } => key_hex,
    }
}

pub(super) fn small_object_pack_entry_object_key(
    key: &[u8],
    value: &MerkleValue,
) -> Option<Vec<u8>> {
    (key.starts_with(SMALL_OBJECT_PENDING_PREFIX) || key.starts_with(SMALL_OBJECT_INDEX_PREFIX))
        .then(|| value.metadata.get(SMALL_OBJECT_KEY_METADATA))
        .flatten()
        .and_then(|encoded| hex::decode(encoded).ok())
}

pub(super) fn repartition_extent_indices(
    entries: &[pepper_merkle::MapEntry],
) -> Result<Vec<(Cid, PlacementReference)>, ApiError> {
    let mut seen = HashSet::new();
    let mut indices = Vec::new();
    for entry in entries
        .iter()
        .filter(|entry| entry.value.value_kind == "small_object_extent")
    {
        let cid = entry
            .value
            .metadata
            .get(SMALL_OBJECT_EXTENT_INDEX_CID_METADATA)
            .ok_or_else(|| ApiError::internal("packed extent index CID is missing"))?
            .parse::<Cid>()
            .map_err(|error| ApiError::internal(error.to_string()))?;
        let placement: PlacementReference = serde_json::from_str(
            entry
                .value
                .metadata
                .get(SMALL_OBJECT_EXTENT_INDEX_PLACEMENT_METADATA)
                .ok_or_else(|| ApiError::internal("packed extent index placement is missing"))?,
        )
        .map_err(ApiError::serde)?;
        if cid.codec != CODEC_SMALL_OBJECT_EXTENT_INDEX
            || placement.seed != cid
            || placement.validate().is_err()
        {
            return Err(ApiError::internal(
                "packed extent index reference is invalid",
            ));
        }
        if seen.insert(cid.clone()) {
            indices.push((cid, placement));
        }
    }
    indices.sort_by_key(|left| left.0.to_string());
    Ok(indices)
}

pub(super) async fn pack_small_objects_in_namespace(
    state: &AppState,
    namespace_id: &NamespaceId,
    force: bool,
) -> Result<SmallObjectPackReport, ApiError> {
    let mut report = SmallObjectPackReport {
        namespaces_examined: 1,
        ..SmallObjectPackReport::default()
    };
    let Some(config) = state.small_object_pack.as_ref() else {
        return Ok(report);
    };
    if !state.erasure_enabled {
        return Ok(report);
    }
    let namespace = namespace_manager(state)?
        .linearizable_namespace_state(namespace_id)
        .await
        .map_err(consensus_error)?;
    if namespace.descriptor.kind != NamespaceKind::Bucket {
        return Ok(report);
    }
    let pending = scan_pending(state, &namespace, config.group_commit_max_requests).await?;
    report.pending_records_examined = pending.len() as u64;
    let selected = select_pending(pending, config, force);
    if !selected.is_empty() {
        let (records, payload) = fetch_pending(state, selected).await?;
        let extent = put_erasure_object_stream_receipts_with_compression(
            state,
            Body::from(payload),
            state.erasure_data_shards,
            state.erasure_parity_shards,
            false,
        )
        .await?;
        let extent_index = store_fetched_extent_index(state, &records, &extent).await?;
        metrics::SMALL_OBJECT_PACK_EXTENTS_WRITTEN.fetch_add(1, Ordering::Relaxed);
        metrics::SMALL_OBJECT_PACK_EXTENT_BYTES.fetch_add(
            records
                .iter()
                .map(|record| record.stored_payload.len() as u64)
                .sum(),
            Ordering::Relaxed,
        );
        #[cfg(debug_assertions)]
        if force
            && let Ok(delay) = std::env::var("PEPPER_TEST_SMALL_PACK_TRANSITION_DELAY_MS")
            && let Ok(delay) = delay.parse::<u64>()
            && delay > 0
        {
            time::sleep(Duration::from_millis(delay.min(60_000))).await;
        }
        let (transitioned, transitioned_bytes) =
            transition_extent(state, namespace_id, &records, &extent, &extent_index).await?;
        if transitioned > 0 {
            report.extents_written = 1;
            report.records_transitioned = transitioned;
            report.logical_bytes_transitioned = transitioned_bytes;
            report.encoded_bytes_written = records
                .iter()
                .map(|record| record.stored_payload.len() as u64)
                .sum();
            report.extent_cids.push(extent.receipt.cid.clone());
            metrics::SMALL_OBJECT_PACK_RECORDS_TRANSITIONED
                .fetch_add(transitioned, Ordering::Relaxed);
            metrics::SMALL_OBJECT_PACK_LOGICAL_BYTES_TRANSITIONED
                .fetch_add(transitioned_bytes, Ordering::Relaxed);
        }
    }
    let latest = namespace_manager(state)?
        .linearizable_namespace_state(namespace_id)
        .await
        .map_err(consensus_error)?;
    report += compact_small_object_extent(state, &latest, config.compaction_dead_percent).await?;
    Ok(report)
}

pub(super) async fn compact_repartitioned_small_object_extents(
    state: &AppState,
    namespace_id: &NamespaceId,
) -> Result<SmallObjectPackReport, ApiError> {
    let mut report = SmallObjectPackReport::default();
    if state.small_object_pack.is_none() || !state.erasure_enabled {
        return Ok(report);
    }
    for _ in 0..1_024 {
        let namespace = namespace_manager(state)?
            .linearizable_namespace_state(namespace_id)
            .await
            .map_err(consensus_error)?;
        let compacted = compact_small_object_extent(state, &namespace, 1).await?;
        if compacted.extents_compacted == 0 {
            break;
        }
        report += compacted;
    }
    Ok(report)
}

pub(super) fn spawn_small_object_pack_loop(state: AppState) {
    if state.small_object_pack.is_none() || !state.erasure_enabled {
        return;
    }
    #[cfg(debug_assertions)]
    if std::env::var_os("PEPPER_TEST_DISABLE_SMALL_PACK_BACKGROUND").is_some() {
        return;
    }
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(SMALL_OBJECT_PACK_POLL_SECONDS));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            let Some(groups) = state.namespace_groups.as_ref() else {
                return;
            };
            for namespace in groups.local_leader_namespace_states().await {
                if namespace.descriptor.kind != NamespaceKind::Bucket {
                    continue;
                }
                if let Err(error) =
                    pack_small_objects_in_namespace(&state, &namespace.namespace_id, false).await
                {
                    metrics::SMALL_OBJECT_PACK_FAILURES.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        namespace_id = %namespace.namespace_id,
                        error = %error.message,
                        "small-object background pack failed"
                    );
                }
            }
        }
    });
}

impl std::ops::AddAssign for SmallObjectPackReport {
    fn add_assign(&mut self, other: Self) {
        self.namespaces_examined = self
            .namespaces_examined
            .saturating_add(other.namespaces_examined);
        self.pending_records_examined = self
            .pending_records_examined
            .saturating_add(other.pending_records_examined);
        self.extents_written = self.extents_written.saturating_add(other.extents_written);
        self.records_transitioned = self
            .records_transitioned
            .saturating_add(other.records_transitioned);
        self.logical_bytes_transitioned = self
            .logical_bytes_transitioned
            .saturating_add(other.logical_bytes_transitioned);
        self.encoded_bytes_written = self
            .encoded_bytes_written
            .saturating_add(other.encoded_bytes_written);
        self.extents_compacted = self
            .extents_compacted
            .saturating_add(other.extents_compacted);
        self.records_compacted = self
            .records_compacted
            .saturating_add(other.records_compacted);
        self.bytes_reclaimed = self.bytes_reclaimed.saturating_add(other.bytes_reclaimed);
        self.extent_cids.extend(other.extent_cids);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extent_fixture() -> SmallObjectExtentIndex {
        let extent_cid = Cid::new(CODEC_ERASURE_MANIFEST, b"extent");
        let logical_cid = Cid::new(CODEC_SMALL_OBJECT, b"record");
        let object_key = b"key";
        SmallObjectExtentIndex {
            version: SMALL_OBJECT_EXTENT_INDEX_VERSION,
            extent_placement: PlacementReference::replicated(1, extent_cid.clone(), 3),
            extent_cid,
            total_bytes: 64,
            records: vec![SmallObjectExtentIndexRecord {
                index_key_hex: hex::encode(index_key(object_key, &logical_cid)),
                object_key_hex: hex::encode(object_key),
                logical_cid,
                logical_size: 64,
                offset: 0,
                stored_length: 64,
                encoding: ErasureStripeEncoding::Raw,
            }],
        }
    }

    #[test]
    fn extent_index_is_canonical_and_bounded() {
        let fixture = extent_fixture();
        let payload = encode_extent_index(&fixture).unwrap();
        assert_eq!(decode_extent_index(&payload).unwrap(), fixture);

        let mut out_of_bounds = fixture.clone();
        out_of_bounds.records[0].stored_length = 65;
        assert!(encode_extent_index(&out_of_bounds).is_err());

        let mut unknown = serde_json::to_value(&fixture).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("legacy".to_string(), serde_json::json!(true));
        assert!(decode_extent_index(&serde_json::to_vec(&unknown).unwrap()).is_err());
    }

    #[test]
    fn object_location_metadata_excludes_compactor_state() {
        let extent_cid = Cid::new(CODEC_ERASURE_MANIFEST, b"extent");
        let placement = PlacementReference::replicated(7, extent_cid.clone(), 3);
        let metadata =
            object_location_metadata(&placement, 4_096, 2_048, ErasureStripeEncoding::Zstd)
                .unwrap();
        assert_eq!(metadata.len(), 1);
        let encoded = metadata.get(SMALL_OBJECT_LOCATION_METADATA).unwrap();
        assert!(encoded.len() < 256);
        let decoded: PackedSmallObjectMetadata = serde_json::from_str(encoded).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.extent_cid, extent_cid);
        assert_eq!(decoded.offset, 4_096);
        assert_eq!(decoded.stored_length, 2_048);
        assert_eq!(decoded.encoding, 1);
        assert!(!metadata.contains_key(SMALL_OBJECT_EXTENT_INDEX_CID_METADATA));
        assert!(!metadata.contains_key(SMALL_OBJECT_EXTENT_TOTAL_BYTES_METADATA));
    }
}
