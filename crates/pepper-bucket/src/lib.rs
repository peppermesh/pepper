// SPDX-License-Identifier: Apache-2.0

//! Canonical immutable descriptors used by the versioned bucket application.

use pepper_dag::{DagCodecHandler, DagError, TraversalLimits};
use pepper_merkle::{MerkleReadStore, MerkleWriteStore};
use pepper_namespace::NamespaceId;
use pepper_types::{
    CODEC_BUCKET_OBJECT, CODEC_SMALL_OBJECT, Cid, Codec, PlacedCid, PlacementReference,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;

pub const BUCKET_PARTITION_FORMAT_VERSION: u32 = 1;
pub const DEFAULT_BUCKET_PARTITIONS: usize = 16;
pub const MAX_BUCKET_PARTITIONS: usize = 256;
pub const BUCKET_HASH_SPACE: u32 = 1 << 16;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BucketPartitionMapState {
    Active,
    Reconfiguring,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BucketPartition {
    pub partition_id: u32,
    pub hash_start: u32,
    pub hash_end: u32,
    pub namespace_id: NamespaceId,
    pub fence_generation: u64,
    pub fence_cid: Cid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BucketPartitionMap {
    pub version: u32,
    pub epoch: u64,
    pub state: BucketPartitionMapState,
    pub partitions: Vec<BucketPartition>,
}

impl BucketPartitionMap {
    pub fn new(epoch: u64, mut partitions: Vec<BucketPartition>) -> Result<Self, BucketError> {
        partitions.sort_by_key(|partition| partition.hash_start);
        let map = Self {
            version: BUCKET_PARTITION_FORMAT_VERSION,
            epoch,
            state: BucketPartitionMapState::Active,
            partitions,
        };
        map.validate()?;
        Ok(map)
    }

    pub fn validate(&self) -> Result<(), BucketError> {
        if self.version != BUCKET_PARTITION_FORMAT_VERSION
            || self.epoch == 0
            || self.partitions.is_empty()
            || self.partitions.len() > MAX_BUCKET_PARTITIONS
        {
            return Err(BucketError::InvalidPartitionMap(
                "unsupported version, epoch, or partition count".into(),
            ));
        }
        let mut expected_start = 0u32;
        let mut ids = HashSet::new();
        for partition in &self.partitions {
            if partition.hash_start != expected_start
                || partition.hash_end <= partition.hash_start
                || partition.hash_end > BUCKET_HASH_SPACE
                || partition.fence_generation == 0
                || !ids.insert(partition.partition_id)
            {
                return Err(BucketError::InvalidPartitionMap(
                    "partition ranges must uniquely and continuously cover the hash space".into(),
                ));
            }
            expected_start = partition.hash_end;
        }
        if expected_start != BUCKET_HASH_SPACE {
            return Err(BucketError::InvalidPartitionMap(
                "partition ranges do not cover the hash space".into(),
            ));
        }
        Ok(())
    }

    pub fn partition_for_key(&self, normalized_key: &[u8]) -> &BucketPartition {
        let digest = Cid::new(pepper_types::CODEC_RAW, normalized_key).digest;
        let point = u32::from(u16::from_be_bytes([digest[0], digest[1]]));
        self.partitions
            .iter()
            .find(|partition| point >= partition.hash_start && point < partition.hash_end)
            .expect("validated partition maps cover the complete hash space")
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BucketLimits {
    pub max_descriptor_bytes: usize,
    pub max_content_type_bytes: usize,
    pub max_metadata_entries: usize,
    pub max_metadata_bytes: usize,
    pub max_versions: usize,
}

impl Default for BucketLimits {
    fn default() -> Self {
        Self {
            max_descriptor_bytes: 1024 * 1024,
            max_content_type_bytes: 1024,
            max_metadata_entries: 256,
            max_metadata_bytes: 64 * 1024,
            max_versions: 10_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BucketObjectDescriptor {
    pub content_cid: Option<Cid>,
    pub content_placement: Option<PlacementReference>,
    pub logical_size: u64,
    pub content_type: String,
    pub metadata: BTreeMap<String, String>,
    pub creation_revision: u64,
    pub committed_at_unix_seconds: i64,
    pub integrity_id: String,
    pub previous_version_cid: Option<Cid>,
    pub previous_version_placement: Option<PlacementReference>,
    pub tombstone: bool,
}

impl BucketObjectDescriptor {
    pub fn object(
        content: PlacedCid,
        logical_size: u64,
        content_type: impl Into<String>,
        metadata: BTreeMap<String, String>,
        creation_revision: u64,
        committed_at_unix_seconds: i64,
        previous_version: Option<PlacedCid>,
    ) -> Self {
        let PlacedCid {
            cid: content_cid,
            placement: content_placement,
        } = content;
        let (previous_version_cid, previous_version_placement) = previous_version
            .map(|previous| (Some(previous.cid), Some(previous.placement)))
            .unwrap_or((None, None));
        let integrity_id = content_cid.to_string();
        Self {
            content_cid: Some(content_cid),
            content_placement: Some(content_placement),
            logical_size,
            content_type: content_type.into(),
            metadata,
            creation_revision,
            committed_at_unix_seconds,
            integrity_id,
            previous_version_cid,
            previous_version_placement,
            tombstone: false,
        }
    }

    pub fn tombstone(
        creation_revision: u64,
        committed_at_unix_seconds: i64,
        previous_version: Option<PlacedCid>,
    ) -> Self {
        let (previous_version_cid, previous_version_placement) = previous_version
            .map(|previous| (Some(previous.cid), Some(previous.placement)))
            .unwrap_or((None, None));
        Self {
            content_cid: None,
            content_placement: None,
            logical_size: 0,
            content_type: "application/x.pepper-tombstone".to_string(),
            metadata: BTreeMap::new(),
            creation_revision,
            committed_at_unix_seconds,
            integrity_id: "tombstone".to_string(),
            previous_version_cid,
            previous_version_placement,
            tombstone: true,
        }
    }

    pub fn validate(&self, limits: BucketLimits) -> Result<(), BucketError> {
        if self.content_type.is_empty() || self.content_type.len() > limits.max_content_type_bytes {
            return Err(BucketError::InvalidDescriptor(
                "invalid content type".into(),
            ));
        }
        if self.metadata.len() > limits.max_metadata_entries
            || self
                .metadata
                .iter()
                .map(|(key, value)| key.len() + value.len())
                .sum::<usize>()
                > limits.max_metadata_bytes
            || self.metadata.iter().any(|(key, _)| key.is_empty())
        {
            return Err(BucketError::InvalidDescriptor(
                "metadata exceeds limits".into(),
            ));
        }
        if self.tombstone {
            if self.content_cid.is_some()
                || self.content_placement.is_some()
                || self.logical_size != 0
                || self.integrity_id != "tombstone"
            {
                return Err(BucketError::InvalidDescriptor("invalid tombstone".into()));
            }
        } else {
            let content = self.content_cid.as_ref().ok_or_else(|| {
                BucketError::InvalidDescriptor("object content CID is missing".into())
            })?;
            if self.integrity_id != content.to_string() {
                return Err(BucketError::InvalidDescriptor(
                    "integrity ID does not match content CID".into(),
                ));
            }
            let placement = self.content_placement.as_ref().ok_or_else(|| {
                BucketError::InvalidDescriptor("object content placement is missing".into())
            })?;
            if placement.seed != *content || placement.validate().is_err() {
                return Err(BucketError::InvalidDescriptor(
                    "object content placement does not match content CID".into(),
                ));
            }
        }
        match (
            self.previous_version_cid.as_ref(),
            self.previous_version_placement.as_ref(),
        ) {
            (None, None) => {}
            (Some(cid), Some(placement))
                if placement.seed == *cid && placement.validate().is_ok() => {}
            _ => {
                return Err(BucketError::InvalidDescriptor(
                    "previous version placement does not match its CID".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum BucketError {
    #[error("invalid bucket descriptor: {0}")]
    InvalidDescriptor(String),
    #[error("bucket descriptor is not canonical")]
    NonCanonical,
    #[error("bucket storage failed: {0}")]
    Storage(String),
    #[error("bucket version chain exceeds limits or contains a cycle")]
    InvalidVersionChain,
    #[error("invalid bucket partition map: {0}")]
    InvalidPartitionMap(String),
}

pub fn encode_descriptor(
    descriptor: &BucketObjectDescriptor,
    limits: BucketLimits,
) -> Result<Vec<u8>, BucketError> {
    descriptor.validate(limits)?;
    let bytes = serde_json::to_vec(descriptor)
        .map_err(|error| BucketError::InvalidDescriptor(error.to_string()))?;
    if bytes.len() > limits.max_descriptor_bytes {
        return Err(BucketError::InvalidDescriptor(
            "descriptor exceeds byte limit".into(),
        ));
    }
    Ok(bytes)
}

pub fn decode_descriptor(
    payload: &[u8],
    limits: BucketLimits,
) -> Result<BucketObjectDescriptor, BucketError> {
    if payload.len() > limits.max_descriptor_bytes {
        return Err(BucketError::InvalidDescriptor(
            "descriptor exceeds byte limit".into(),
        ));
    }
    let descriptor: BucketObjectDescriptor = serde_json::from_slice(payload)
        .map_err(|error| BucketError::InvalidDescriptor(error.to_string()))?;
    descriptor.validate(limits)?;
    if encode_descriptor(&descriptor, limits)? != payload {
        return Err(BucketError::NonCanonical);
    }
    Ok(descriptor)
}

pub async fn put_descriptor<S: MerkleWriteStore + ?Sized>(
    store: &S,
    descriptor: &BucketObjectDescriptor,
    limits: BucketLimits,
) -> Result<Cid, BucketError> {
    let bytes = encode_descriptor(descriptor, limits)?;
    let expected = Cid::new(CODEC_BUCKET_OBJECT, &bytes);
    let actual = store
        .put(CODEC_BUCKET_OBJECT, bytes)
        .await
        .map_err(BucketError::Storage)?;
    if actual != expected {
        return Err(BucketError::Storage(
            "store returned a different CID".into(),
        ));
    }
    Ok(actual)
}

pub async fn get_descriptor<S: MerkleReadStore + ?Sized>(
    store: &S,
    cid: &Cid,
    limits: BucketLimits,
) -> Result<BucketObjectDescriptor, BucketError> {
    if cid.codec != CODEC_BUCKET_OBJECT {
        return Err(BucketError::InvalidDescriptor(
            "CID is not a bucket descriptor".into(),
        ));
    }
    let payload = store.get(cid).await.map_err(BucketError::Storage)?;
    if !cid.verify(&payload) {
        return Err(BucketError::Storage(
            "descriptor CID verification failed".into(),
        ));
    }
    decode_descriptor(&payload, limits)
}

pub async fn versions<S: MerkleReadStore + ?Sized>(
    store: &S,
    head: &Cid,
    limits: BucketLimits,
) -> Result<Vec<(Cid, BucketObjectDescriptor)>, BucketError> {
    let mut versions = Vec::new();
    let mut current = Some(head.clone());
    let mut seen = HashSet::new();
    while let Some(cid) = current {
        if versions.len() >= limits.max_versions || !seen.insert(cid.clone()) {
            return Err(BucketError::InvalidVersionChain);
        }
        let descriptor = get_descriptor(store, &cid, limits).await?;
        current = descriptor.previous_version_cid.clone();
        versions.push((cid, descriptor));
    }
    Ok(versions)
}

#[derive(Debug, Clone, Copy)]
pub struct BucketObjectCodecHandler;

impl DagCodecHandler for BucketObjectCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_BUCKET_OBJECT
    }

    fn links(&self, payload: &[u8], limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        let descriptor = decode_descriptor(
            payload,
            BucketLimits {
                max_descriptor_bytes: limits.max_payload_bytes,
                ..BucketLimits::default()
            },
        )
        .map_err(|error| DagError::InvalidPayload {
            codec: CODEC_BUCKET_OBJECT.canonical_display(),
            message: error.to_string(),
        })?;
        let mut links = Vec::new();
        // Direct small records are rooted by an atomic pending marker in the
        // bucket partition. The pack transition replaces that marker with an
        // EC-extent index entry, so retaining this descriptor link would keep
        // the replicated staging record alive forever.
        if let Some(content) = descriptor
            .content_cid
            .filter(|content| content.codec != CODEC_SMALL_OBJECT)
        {
            links.push(content);
        }
        if let Some(previous) = descriptor.previous_version_cid {
            links.push(previous);
        }
        links.sort_by_key(ToString::to_string);
        Ok(links)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use pepper_types::CODEC_RAW;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Store(Mutex<BTreeMap<String, Vec<u8>>>);
    #[async_trait]
    impl MerkleReadStore for Store {
        async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
            self.0
                .lock()
                .unwrap()
                .get(&cid.to_string())
                .cloned()
                .ok_or_else(|| "missing".into())
        }
    }
    #[async_trait]
    impl MerkleWriteStore for Store {
        async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
            let cid = Cid::new(codec, &payload);
            self.0.lock().unwrap().insert(cid.to_string(), payload);
            Ok(cid)
        }
    }

    #[tokio::test]
    async fn canonical_versions_and_dag_links() {
        let store = Store::default();
        let content = Cid::new(CODEC_RAW, b"hello");
        let first = BucketObjectDescriptor::object(
            PlacedCid::new(
                content.clone(),
                PlacementReference::replicated(1, content.clone(), 3),
            )
            .unwrap(),
            5,
            "text/plain",
            BTreeMap::new(),
            1,
            1_700_000_001,
            None,
        );
        let first_cid = put_descriptor(&store, &first, BucketLimits::default())
            .await
            .unwrap();
        let second = BucketObjectDescriptor::object(
            PlacedCid::new(
                content.clone(),
                PlacementReference::replicated(1, content.clone(), 3),
            )
            .unwrap(),
            5,
            "text/plain",
            BTreeMap::new(),
            2,
            1_700_000_002,
            Some(
                PlacedCid::new(
                    first_cid.clone(),
                    PlacementReference::replicated(1, first_cid.clone(), 3),
                )
                .unwrap(),
            ),
        );
        let second_cid = put_descriptor(&store, &second, BucketLimits::default())
            .await
            .unwrap();
        assert_eq!(
            second_cid.to_string(),
            "cid://pepper-v1:0xb:b3:592c1deb3389b3b059b38cca902943373cedceedd84bb3a2635533a3fd99f1c5"
        );
        let history = versions(&store, &second_cid, BucketLimits::default())
            .await
            .unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(
            decode_descriptor(
                &encode_descriptor(&second, BucketLimits::default()).unwrap(),
                BucketLimits::default()
            )
            .unwrap(),
            second
        );
        let links = BucketObjectCodecHandler
            .links(
                &encode_descriptor(&second, BucketLimits::default()).unwrap(),
                &TraversalLimits::default(),
            )
            .unwrap();
        assert!(links.contains(&content));
        assert!(links.contains(&first_cid));
    }

    #[test]
    fn partition_maps_cover_and_route_the_hash_space_canonically() {
        let partitions = (0..4)
            .map(|index| BucketPartition {
                partition_id: index,
                hash_start: index * 16_384,
                hash_end: (index + 1) * 16_384,
                namespace_id: NamespaceId::new(Cid::new(
                    pepper_types::CODEC_NAMESPACE_DESCRIPTOR,
                    format!("partition-{index}").as_bytes(),
                ))
                .unwrap(),
                fence_generation: 1,
                fence_cid: Cid::new(CODEC_RAW, format!("fence-{index}").as_bytes()),
            })
            .collect();
        let map = BucketPartitionMap::new(1, partitions).unwrap();
        assert_eq!(
            map.partition_for_key(b"same-key"),
            map.partition_for_key(b"same-key")
        );
        let selected = (0..10_000)
            .map(|index| {
                map.partition_for_key(format!("key-{index}").as_bytes())
                    .partition_id
            })
            .collect::<HashSet<_>>();
        assert_eq!(selected.len(), 4);

        let mut invalid = map.clone();
        invalid.partitions[1].hash_start += 1;
        assert!(invalid.validate().is_err());
    }
}
