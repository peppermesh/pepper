// SPDX-License-Identifier: Apache-2.0

//! Typed, bounded traversal of Pepper content-addressed DAGs.
//!
//! The registry is the single interpretation boundary used by retention and
//! garbage collection. Unknown codecs remain valid block codecs, but cannot be
//! traversed until a handler is registered.

use async_trait::async_trait;
use pepper_types::{
    CODEC_DIR_MANIFEST, CODEC_ERASURE_MANIFEST, CODEC_OBJECT_MANIFEST, CODEC_RAW, Cid, Codec,
    DirManifest, ErasureManifest, ObjectManifest,
};
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    sync::Arc,
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraversalLimits {
    pub max_depth: usize,
    pub max_blocks: usize,
    pub max_links_per_block: usize,
    pub max_total_links: usize,
    pub max_payload_bytes: usize,
    pub max_total_payload_bytes: u64,
}

impl Default for TraversalLimits {
    fn default() -> Self {
        Self {
            max_depth: 1_024,
            max_blocks: 2_000_000,
            max_links_per_block: 100_000,
            max_total_links: 4_000_000,
            max_payload_bytes: 16 * 1024 * 1024,
            max_total_payload_bytes: 1024 * 1024 * 1024,
        }
    }
}

impl TraversalLimits {
    pub fn validate(self) -> Result<Self, DagError> {
        if self.max_blocks == 0
            || self.max_links_per_block == 0
            || self.max_total_links == 0
            || self.max_payload_bytes == 0
            || self.max_total_payload_bytes == 0
        {
            return Err(DagError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DagError {
    #[error("invalid zero-valued DAG traversal limit")]
    InvalidLimits,
    #[error("no DAG handler is registered for codec {0}")]
    UnsupportedCodec(String),
    #[error("a DAG handler is already registered for codec {0}")]
    DuplicateCodec(String),
    #[error("failed to resolve DAG block {cid}: {message}")]
    Resolve { cid: String, message: String },
    #[error("invalid {codec} DAG payload: {message}")]
    InvalidPayload { codec: String, message: String },
    #[error("DAG payload for codec {codec} is {actual} bytes, limit is {limit}")]
    PayloadTooLarge {
        codec: String,
        actual: usize,
        limit: usize,
    },
    #[error("DAG block {cid} has {actual} links, limit is {limit}")]
    TooManyLinks {
        cid: String,
        actual: usize,
        limit: usize,
    },
    #[error("DAG traversal exceeds the {limit}-block limit")]
    TooManyBlocks { limit: usize },
    #[error("DAG traversal exceeds the {limit}-link limit")]
    TooManyTotalLinks { limit: usize },
    #[error("DAG traversal exceeds the {limit}-byte decoded payload limit")]
    TooManyPayloadBytes { limit: u64 },
    #[error("DAG traversal reached depth {depth}, limit is {limit}")]
    TooDeep { depth: usize, limit: usize },
}

pub trait DagCodecHandler: Send + Sync + 'static {
    fn codec(&self) -> Codec;

    /// Whether traversal must resolve and decode this block. Leaf codecs return
    /// false so raw data need not be loaded merely to establish reachability.
    fn requires_payload(&self) -> bool {
        true
    }

    /// Validate one bounded payload and return every directly linked CID.
    fn links(&self, payload: &[u8], limits: &TraversalLimits) -> Result<Vec<Cid>, DagError>;
}

#[derive(Clone, Default)]
pub struct DagCodecRegistry {
    handlers: BTreeMap<Codec, Arc<dyn DagCodecHandler>>,
}

impl DagCodecRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<H>(&mut self, handler: H) -> Result<(), DagError>
    where
        H: DagCodecHandler,
    {
        self.register_arc(Arc::new(handler))
    }

    pub fn register_arc(&mut self, handler: Arc<dyn DagCodecHandler>) -> Result<(), DagError> {
        let codec = handler.codec();
        if self.handlers.contains_key(&codec) {
            return Err(DagError::DuplicateCodec(codec.canonical_display()));
        }
        self.handlers.insert(codec, handler);
        Ok(())
    }

    pub fn handler(&self, codec: Codec) -> Result<&dyn DagCodecHandler, DagError> {
        self.handlers
            .get(&codec)
            .map(AsRef::as_ref)
            .ok_or_else(|| DagError::UnsupportedCodec(codec.canonical_display()))
    }

    pub fn links(
        &self,
        codec: Codec,
        payload: &[u8],
        limits: &TraversalLimits,
    ) -> Result<Vec<Cid>, DagError> {
        let handler = self.handler(codec)?;
        validate_payload_size(codec, payload, limits)?;
        let links = handler.links(payload, limits)?;
        if links.len() > limits.max_links_per_block {
            return Err(DagError::TooManyLinks {
                cid: codec.canonical_display(),
                actual: links.len(),
                limit: limits.max_links_per_block,
            });
        }
        Ok(links)
    }

    pub fn codecs(&self) -> impl Iterator<Item = Codec> + '_ {
        self.handlers.keys().copied()
    }
}

pub fn builtin_registry() -> DagCodecRegistry {
    let mut registry = DagCodecRegistry::new();
    registry
        .register(RawCodecHandler)
        .expect("unique raw codec");
    registry
        .register(ObjectManifestCodecHandler)
        .expect("unique object codec");
    registry
        .register(ErasureManifestCodecHandler)
        .expect("unique erasure codec");
    registry
        .register(DirectoryManifestCodecHandler)
        .expect("unique directory codec");
    registry
}

#[async_trait]
pub trait BlockResolver: Send + Sync {
    /// Resolve verified payload bytes for the requested CID.
    async fn resolve(&self, cid: &Cid) -> Result<Vec<u8>, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Traversal {
    /// Deterministic breadth-first order, including the root.
    pub cids: Vec<Cid>,
    pub decoded_payload_bytes: u64,
    pub links_examined: usize,
}

impl Traversal {
    pub fn into_set(self) -> HashSet<Cid> {
        self.cids.into_iter().collect()
    }
}

pub async fn traverse<R>(
    registry: &DagCodecRegistry,
    resolver: &R,
    root: Cid,
    limits: TraversalLimits,
) -> Result<Traversal, DagError>
where
    R: BlockResolver + ?Sized,
{
    let limits = limits.validate()?;
    let mut seen = HashSet::new();
    let mut ordered = Vec::new();
    let mut queue = VecDeque::from([(root, 0usize)]);
    let mut decoded_payload_bytes = 0u64;
    let mut links_examined = 0usize;

    while let Some((cid, depth)) = queue.pop_front() {
        if !seen.insert(cid.clone()) {
            continue;
        }
        if depth > limits.max_depth {
            return Err(DagError::TooDeep {
                depth,
                limit: limits.max_depth,
            });
        }
        if seen.len() > limits.max_blocks {
            return Err(DagError::TooManyBlocks {
                limit: limits.max_blocks,
            });
        }

        let handler = registry.handler(cid.codec)?;
        ordered.push(cid.clone());
        if !handler.requires_payload() {
            continue;
        }

        let payload = resolver
            .resolve(&cid)
            .await
            .map_err(|message| DagError::Resolve {
                cid: cid.to_string(),
                message,
            })?;
        validate_payload_size(cid.codec, &payload, &limits)?;
        decoded_payload_bytes = decoded_payload_bytes.saturating_add(payload.len() as u64);
        if decoded_payload_bytes > limits.max_total_payload_bytes {
            return Err(DagError::TooManyPayloadBytes {
                limit: limits.max_total_payload_bytes,
            });
        }

        let mut links = handler.links(&payload, &limits)?;
        if links.len() > limits.max_links_per_block {
            return Err(DagError::TooManyLinks {
                cid: cid.to_string(),
                actual: links.len(),
                limit: limits.max_links_per_block,
            });
        }
        links_examined = links_examined.saturating_add(links.len());
        if links_examined > limits.max_total_links {
            return Err(DagError::TooManyTotalLinks {
                limit: limits.max_total_links,
            });
        }

        links.sort_by_key(Cid::to_string);
        queue.extend(links.into_iter().map(|child| (child, depth + 1)));
    }

    Ok(Traversal {
        cids: ordered,
        decoded_payload_bytes,
        links_examined,
    })
}

fn validate_payload_size(
    codec: Codec,
    payload: &[u8],
    limits: &TraversalLimits,
) -> Result<(), DagError> {
    if payload.len() > limits.max_payload_bytes {
        return Err(DagError::PayloadTooLarge {
            codec: codec.canonical_display(),
            actual: payload.len(),
            limit: limits.max_payload_bytes,
        });
    }
    Ok(())
}

fn invalid_payload(codec: Codec, error: impl ToString) -> DagError {
    DagError::InvalidPayload {
        codec: codec.canonical_display(),
        message: error.to_string(),
    }
}

pub struct RawCodecHandler;

impl DagCodecHandler for RawCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_RAW
    }

    fn requires_payload(&self) -> bool {
        false
    }

    fn links(&self, _payload: &[u8], _limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        Ok(Vec::new())
    }
}

pub struct ObjectManifestCodecHandler;

impl DagCodecHandler for ObjectManifestCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_OBJECT_MANIFEST
    }

    fn links(&self, payload: &[u8], _limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        let manifest: ObjectManifest = serde_json::from_slice(payload)
            .map_err(|error| invalid_payload(self.codec(), error))?;
        manifest
            .validate()
            .map_err(|error| invalid_payload(self.codec(), error))?;
        Ok(manifest.chunks.into_iter().map(|chunk| chunk.cid).collect())
    }
}

pub struct ErasureManifestCodecHandler;

impl DagCodecHandler for ErasureManifestCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_ERASURE_MANIFEST
    }

    fn links(&self, payload: &[u8], _limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        let manifest: ErasureManifest = serde_json::from_slice(payload)
            .map_err(|error| invalid_payload(self.codec(), error))?;
        manifest
            .validate()
            .map_err(|error| invalid_payload(self.codec(), error))?;
        Ok(manifest
            .stripes
            .into_iter()
            .flat_map(|stripe| stripe.shards.into_iter().map(|shard| shard.cid))
            .collect())
    }
}

pub struct DirectoryManifestCodecHandler;

impl DagCodecHandler for DirectoryManifestCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_DIR_MANIFEST
    }

    fn links(&self, payload: &[u8], _limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        let manifest: DirManifest = serde_json::from_slice(payload)
            .map_err(|error| invalid_payload(self.codec(), error))?;
        manifest
            .validate()
            .map_err(|error| invalid_payload(self.codec(), error))?;
        Ok(manifest
            .entries
            .into_iter()
            .filter_map(|entry| entry.cid)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_types::{DirEntry, ObjectChunk};
    use std::{collections::HashMap, sync::Mutex};

    #[derive(Default)]
    struct MemoryResolver {
        blocks: Mutex<HashMap<Cid, Vec<u8>>>,
    }

    impl MemoryResolver {
        fn insert_json<T: serde::Serialize>(&self, codec: Codec, value: &T) -> Cid {
            let payload = serde_json::to_vec(value).unwrap();
            let cid = Cid::new(codec, &payload);
            self.blocks.lock().unwrap().insert(cid.clone(), payload);
            cid
        }
    }

    #[async_trait]
    impl BlockResolver for MemoryResolver {
        async fn resolve(&self, cid: &Cid) -> Result<Vec<u8>, String> {
            self.blocks
                .lock()
                .unwrap()
                .get(cid)
                .cloned()
                .ok_or_else(|| "missing".to_string())
        }
    }

    #[tokio::test]
    async fn traverses_builtin_manifests_in_deterministic_order() {
        let resolver = MemoryResolver::default();
        let a = Cid::new(CODEC_RAW, b"a");
        let b = Cid::new(CODEC_RAW, b"b");
        let object = ObjectManifest::new(
            2,
            1,
            vec![
                ObjectChunk {
                    offset: 0,
                    size: 1,
                    cid: b.clone(),
                },
                ObjectChunk {
                    offset: 1,
                    size: 1,
                    cid: a.clone(),
                },
            ],
        );
        let object_cid = resolver.insert_json(CODEC_OBJECT_MANIFEST, &object);
        let directory = DirManifest::new(vec![DirEntry {
            path: "file".to_string(),
            kind: "file".to_string(),
            mode: 0o644,
            size: Some(2),
            cid: Some(object_cid.clone()),
        }]);
        let root = resolver.insert_json(CODEC_DIR_MANIFEST, &directory);

        let traversal = traverse(
            &builtin_registry(),
            &resolver,
            root.clone(),
            TraversalLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(traversal.cids, vec![root, object_cid, a, b]);
        assert_eq!(traversal.links_examined, 3);
    }

    #[tokio::test]
    async fn raw_leaf_does_not_require_resolution() {
        let root = Cid::new(CODEC_RAW, b"not in resolver");
        let traversal = traverse(
            &builtin_registry(),
            &MemoryResolver::default(),
            root.clone(),
            TraversalLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(traversal.cids, vec![root]);
        assert_eq!(traversal.decoded_payload_bytes, 0);
    }

    #[tokio::test]
    async fn rejects_unknown_and_malformed_codecs() {
        let unknown = Cid::new(Codec(0xff), b"unknown");
        assert!(matches!(
            traverse(
                &builtin_registry(),
                &MemoryResolver::default(),
                unknown,
                TraversalLimits::default()
            )
            .await,
            Err(DagError::UnsupportedCodec(_))
        ));

        let resolver = MemoryResolver::default();
        let payload = b"not-json".to_vec();
        let malformed = Cid::new(CODEC_OBJECT_MANIFEST, &payload);
        resolver
            .blocks
            .lock()
            .unwrap()
            .insert(malformed.clone(), payload);
        assert!(matches!(
            traverse(
                &builtin_registry(),
                &resolver,
                malformed,
                TraversalLimits::default()
            )
            .await,
            Err(DagError::InvalidPayload { .. })
        ));
    }

    struct LinkCodec {
        codec: Codec,
        links: Vec<Cid>,
    }

    impl DagCodecHandler for LinkCodec {
        fn codec(&self) -> Codec {
            self.codec
        }

        fn links(&self, _payload: &[u8], _limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
            Ok(self.links.clone())
        }
    }

    #[tokio::test]
    async fn enforces_block_link_depth_and_payload_limits() {
        let leaf = Cid::new(CODEC_RAW, b"leaf");
        let codec = Codec(0x80);
        let payload = vec![0; 8];
        let root = Cid::new(codec, &payload);
        let resolver = MemoryResolver::default();
        resolver
            .blocks
            .lock()
            .unwrap()
            .insert(root.clone(), payload);
        let mut registry = builtin_registry();
        registry
            .register(LinkCodec {
                codec,
                links: vec![leaf.clone(), leaf],
            })
            .unwrap();

        let limits = TraversalLimits {
            max_links_per_block: 1,
            ..TraversalLimits::default()
        };
        assert!(matches!(
            traverse(&registry, &resolver, root.clone(), limits).await,
            Err(DagError::TooManyLinks { .. })
        ));

        let limits = TraversalLimits {
            max_payload_bytes: 4,
            ..TraversalLimits::default()
        };
        assert!(matches!(
            traverse(&registry, &resolver, root, limits).await,
            Err(DagError::PayloadTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn detects_cycles_and_enforces_depth_without_looping() {
        let resolver = MemoryResolver::default();
        let codec_a = Codec(0x81);
        let codec_b = Codec(0x82);
        let codec_c = Codec(0x83);
        let payload_a = b"a".to_vec();
        let payload_b = b"b".to_vec();
        let payload_c = b"c".to_vec();
        let a = Cid::new(codec_a, &payload_a);
        let b = Cid::new(codec_b, &payload_b);
        let c = Cid::new(codec_c, &payload_c);
        {
            let mut blocks = resolver.blocks.lock().unwrap();
            blocks.insert(a.clone(), payload_a);
            blocks.insert(b.clone(), payload_b);
            blocks.insert(c.clone(), payload_c);
        }
        let mut registry = builtin_registry();
        registry
            .register(LinkCodec {
                codec: codec_a,
                links: vec![b.clone()],
            })
            .unwrap();
        registry
            .register(LinkCodec {
                codec: codec_b,
                links: vec![a.clone(), c.clone()],
            })
            .unwrap();
        registry
            .register(LinkCodec {
                codec: codec_c,
                links: Vec::new(),
            })
            .unwrap();

        let traversal = traverse(&registry, &resolver, a.clone(), TraversalLimits::default())
            .await
            .unwrap();
        assert_eq!(traversal.cids, vec![a.clone(), b, c]);

        let limits = TraversalLimits {
            max_depth: 1,
            ..TraversalLimits::default()
        };
        assert!(matches!(
            traverse(&registry, &resolver, a, limits).await,
            Err(DagError::TooDeep { depth: 2, limit: 1 })
        ));
    }

    #[tokio::test]
    async fn registered_codec_marks_children_for_storage_gc() {
        use pepper_config::StorageLocationConfig;
        use pepper_metadata::MetadataStore;
        use pepper_storage::BlockStore;

        struct StoreResolver<'a>(&'a BlockStore);
        #[async_trait]
        impl BlockResolver for StoreResolver<'_> {
            async fn resolve(&self, cid: &Cid) -> Result<Vec<u8>, String> {
                self.0
                    .get(cid)
                    .map(|block| block.payload)
                    .map_err(|error| error.to_string())
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let metadata = Arc::new(
            MetadataStore::open_or_create(directory.path().join("metadata.redb")).unwrap(),
        );
        let store = BlockStore::open(
            metadata,
            &[StorageLocationConfig {
                path: directory.path().join("storage"),
                max_capacity_bytes: 1024 * 1024,
            }],
        )
        .unwrap();
        let leaf = store.put_raw(b"protected leaf").unwrap().cid;
        let unprotected = store.put_raw(b"collect me").unwrap().cid;
        let codec = Codec(0x90);
        let root = store.put(codec, b"custom root").unwrap().cid;
        let mut registry = builtin_registry();
        registry
            .register(LinkCodec {
                codec,
                links: vec![leaf.clone()],
            })
            .unwrap();
        let protected = traverse(
            &registry,
            &StoreResolver(&store),
            root.clone(),
            TraversalLimits::default(),
        )
        .await
        .unwrap()
        .into_set();

        store.garbage_collect(&protected).unwrap();
        assert!(store.has(&root).unwrap());
        assert!(store.has(&leaf).unwrap());
        assert!(!store.has(&unprotected).unwrap());
    }

    #[test]
    fn rejects_duplicate_registration_and_zero_limits() {
        let mut registry = builtin_registry();
        assert!(matches!(
            registry.register(RawCodecHandler),
            Err(DagError::DuplicateCodec(_))
        ));
        assert_eq!(
            TraversalLimits {
                max_blocks: 0,
                ..TraversalLimits::default()
            }
            .validate(),
            Err(DagError::InvalidLimits)
        );
    }
}
