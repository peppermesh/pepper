// SPDX-License-Identifier: Apache-2.0

//! Canonical immutable descriptors used by the versioned bucket application.

use pepper_dag::{DagCodecHandler, DagError, TraversalLimits};
use pepper_merkle::{MerkleReadStore, MerkleWriteStore};
use pepper_types::{CODEC_BUCKET_OBJECT, Cid, Codec};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;

const BUCKET_OBJECT_TYPE: &str = "pepper.bucket_object";
const FORMAT_VERSION: u32 = 1;

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
    #[serde(rename = "type")]
    pub descriptor_type: String,
    pub version: u32,
    pub content_cid: Option<Cid>,
    pub logical_size: u64,
    pub content_type: String,
    pub metadata: BTreeMap<String, String>,
    pub creation_revision: u64,
    pub integrity_id: String,
    pub previous_version_cid: Option<Cid>,
    pub tombstone: bool,
}

impl BucketObjectDescriptor {
    pub fn object(
        content_cid: Cid,
        logical_size: u64,
        content_type: impl Into<String>,
        metadata: BTreeMap<String, String>,
        creation_revision: u64,
        previous_version_cid: Option<Cid>,
    ) -> Self {
        let integrity_id = content_cid.to_string();
        Self {
            descriptor_type: BUCKET_OBJECT_TYPE.to_string(),
            version: FORMAT_VERSION,
            content_cid: Some(content_cid),
            logical_size,
            content_type: content_type.into(),
            metadata,
            creation_revision,
            integrity_id,
            previous_version_cid,
            tombstone: false,
        }
    }

    pub fn tombstone(creation_revision: u64, previous_version_cid: Option<Cid>) -> Self {
        Self {
            descriptor_type: BUCKET_OBJECT_TYPE.to_string(),
            version: FORMAT_VERSION,
            content_cid: None,
            logical_size: 0,
            content_type: "application/x.pepper-tombstone".to_string(),
            metadata: BTreeMap::new(),
            creation_revision,
            integrity_id: "tombstone".to_string(),
            previous_version_cid,
            tombstone: true,
        }
    }

    pub fn validate(&self, limits: BucketLimits) -> Result<(), BucketError> {
        if self.descriptor_type != BUCKET_OBJECT_TYPE || self.version != FORMAT_VERSION {
            return Err(BucketError::InvalidDescriptor(
                "unsupported type or version".into(),
            ));
        }
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
        if let Some(content) = descriptor.content_cid {
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
            content.clone(),
            5,
            "text/plain",
            BTreeMap::new(),
            1,
            None,
        );
        let first_cid = put_descriptor(&store, &first, BucketLimits::default())
            .await
            .unwrap();
        let second = BucketObjectDescriptor::object(
            content.clone(),
            5,
            "text/plain",
            BTreeMap::new(),
            2,
            Some(first_cid.clone()),
        );
        let second_cid = put_descriptor(&store, &second, BucketLimits::default())
            .await
            .unwrap();
        assert_eq!(
            second_cid.to_string(),
            "cid://pepper-v1:0xb:b3:3f75987f9e835b8aefbc64cf9e0600267de3ebc394df0de5d53dadbabeaea273"
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
}
