// SPDX-License-Identifier: Apache-2.0

//! Pepper-backed SQLite format and service boundaries.
//!
//! The crate deliberately has no dependency on SQLite's C ABI, networking, or
//! agent persistence. It owns transport-neutral DTOs and immutable formats;
//! `pepper-sqlite-vfs` owns SQLite integration and the agent owns publication.

use async_trait::async_trait;
use pepper_types::Cid;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod cache;
pub mod contract;
pub mod format;
pub mod page_table;
pub mod proof;
pub mod protocol;
pub mod snapshot;
pub mod transaction;
pub mod whole_file;
pub mod writer;

pub use cache::ImmutableBlockCache;
pub use contract::{PepperDatabaseUri, SqliteOpenMode, SqliteStatusCode};
pub use format::{
    CachePolicyBounds, DatabaseDescriptor, PageReference, PageStoragePolicy, PageTableNode,
    SnapshotDescriptor, SqliteFormatLimits,
};
pub use page_table::{
    PageMutation, PageTable, PageTableBulkRead, PageTableUpdate, PageTableValidation,
    SqliteIndexAdapter,
};
pub use proof::{IncrementalDurabilityProof, IncrementalProofInput};
pub use protocol::{LocalFrame, LocalMessage, LocalProtocolLimits};
pub use snapshot::{
    ImportedSnapshot, PagePackStore, PagePackWrite, export_snapshot, import_snapshot,
};
pub use transaction::{
    DirtyPage, IncrementalSnapshot, build_incremental_snapshot, build_incremental_snapshot_stream,
};
pub use whole_file::{SqliteFileMetadata, validate_sqlite_file};
pub use writer::{
    AcquisitionStatus, CommitAttempt, CommitRecord, GuardedCommitRequest, WriterControlRequest,
    WriterControlResponse, WriterCoordinator, WriterTicket,
};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SqliteError {
    #[error("invalid SQLite request: {0}")]
    Invalid(String),
    #[error("SQLite format is not canonical")]
    NonCanonical,
    #[error("SQLite format limit exceeded: {0}")]
    Limit(String),
    #[error("SQLite storage failed: {0}")]
    Storage(String),
    #[error("SQLite generation conflict; current generation is {current_generation}")]
    GenerationConflict { current_generation: u64 },
    #[error("SQLite writer is busy")]
    Busy,
    #[error("SQLite operation timed out")]
    Timeout,
    #[error("SQLite session or writer ticket is fenced")]
    Fenced,
    #[error("SQLite commit outcome is ambiguous; query idempotency key {idempotency_key}")]
    AmbiguousCommit { idempotency_key: String },
    #[error("unsupported SQLite operation: {0}")]
    Unsupported(String),
}

/// Minimal immutable block boundary used by the format/page-table library.
#[async_trait]
pub trait SqliteBlockStore: Send + Sync {
    async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String>;

    async fn put(&self, codec: pepper_types::Codec, payload: Vec<u8>) -> Result<Cid, String>;
}

/// Transport-neutral application/agent boundary. Concrete protocol DTOs are
/// added only after the local protocol contract is frozen.
#[async_trait]
pub trait SqliteService: Send + Sync {
    async fn current_snapshot(&self, database: &str) -> Result<(Cid, u64), SqliteError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SqliteSessionInfo {
    pub session_id: String,
    pub database: String,
    pub snapshot_cid: Cid,
    pub generation: u64,
}

#[async_trait]
pub trait SqliteSessionClient: Send + Sync {
    async fn open(&self, database: &str, writable: bool) -> Result<SqliteSessionInfo, SqliteError>;
    async fn close(&self, session_id: &str) -> Result<(), SqliteError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{
        DATABASE_TYPE, FORMAT_VERSION, PAGE_TABLE_TYPE, PageTableNodeKind,
        SqlitePageTableCodecHandler, SqliteSnapshotCodecHandler, encode_canonical,
    };
    use async_trait::async_trait;
    use pepper_dag::{DagCodecHandler, TraversalLimits};
    use pepper_dataset::IndexAdapter;
    use pepper_types::{
        CODEC_SMALL_OBJECT, CODEC_SQLITE_DATABASE, CODEC_SQLITE_PAGE_TABLE, CODEC_SQLITE_SNAPSHOT,
        Codec,
    };
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Default)]
    struct MemoryStore {
        blocks: Arc<Mutex<HashMap<Cid, Vec<u8>>>>,
    }

    #[async_trait]
    impl SqliteBlockStore for MemoryStore {
        async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
            self.blocks
                .lock()
                .expect("store lock")
                .get(cid)
                .cloned()
                .ok_or_else(|| format!("missing {cid}"))
        }

        async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
            let cid = Cid::new(codec, &payload);
            self.blocks
                .lock()
                .expect("store lock")
                .insert(cid.clone(), payload);
            Ok(cid)
        }
    }

    fn page(page_number: u32, marker: u8) -> PageReference {
        PageReference {
            page_number,
            pack_cid: Cid::new(CODEC_SMALL_OBJECT, &[marker; 8]),
            offset: 0,
            length: 4096,
            page_hash: format!("{marker:02x}").repeat(32),
        }
    }

    #[test]
    fn canonical_database_vector_is_stable() {
        let descriptor = DatabaseDescriptor::new(
            4096,
            262_144,
            4_194_304,
            PageStoragePolicy::Adaptive {
                small_commit_replicas: 3,
                large_commit_data_shards: 6,
                large_commit_parity_shards: 3,
                large_commit_shard_copies: 1,
                threshold_bytes: 1_048_576,
            },
            CachePolicyBounds {
                minimum_bytes: 4_194_304,
                maximum_bytes: 1_073_741_824,
            },
            1_753_200_000,
            "node:test",
        );
        descriptor.validate(SqliteFormatLimits::default()).unwrap();
        let bytes = encode_canonical(&descriptor, 64 * 1024).unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            r#"{"type":"pepper.sqlite_database","version":1,"page_size":4096,"max_page_count":262144,"page_pack_target_bytes":4194304,"storage_policy":{"kind":"adaptive","small_commit_replicas":3,"large_commit_data_shards":6,"large_commit_parity_shards":3,"large_commit_shard_copies":1,"threshold_bytes":1048576},"cache_policy_bounds":{"minimum_bytes":4194304,"maximum_bytes":1073741824},"created_at_unix_seconds":1753200000,"creator_identity":"node:test"}"#
        );
        assert_eq!(
            Cid::new(CODEC_SQLITE_DATABASE, &bytes).to_string(),
            "cid://pepper-v1:0x11:b3:8c7e90df16465ffaf3cd18bc0e084a0be297c84d789e202cd16a79e33139dd74"
        );
    }

    #[test]
    fn codec_values_and_empty_root_vector_are_stable() {
        assert_eq!(CODEC_SQLITE_DATABASE.0, 0x11);
        assert_eq!(CODEC_SQLITE_SNAPSHOT.0, 0x12);
        assert_eq!(CODEC_SQLITE_PAGE_TABLE.0, 0x13);
        let root = PageTableNode::empty_root();
        assert_eq!(root.descriptor_type, PAGE_TABLE_TYPE);
        assert_eq!(root.version, FORMAT_VERSION);
        assert_eq!(root.kind, PageTableNodeKind::Internal);
        let bytes = encode_canonical(&root, 256 * 1024).unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            r#"{"type":"pepper.sqlite_page_table","version":1,"kind":"internal","level":0,"prefix":"","children":[],"pages":[]}"#
        );
        assert_eq!(
            Cid::new(CODEC_SQLITE_PAGE_TABLE, &bytes).to_string(),
            "cid://pepper-v1:0x13:b3:ea61257c950a92424a9516b0288a455954d0b1e9d9251bcfe58198f7973fc2e3"
        );
    }

    #[test]
    fn dag_snapshot_links_are_strong_but_history_is_weak() {
        let database = Cid::new(CODEC_SQLITE_DATABASE, b"database");
        let table = Cid::new(CODEC_SQLITE_PAGE_TABLE, b"table");
        let history = Cid::new(CODEC_SQLITE_SNAPSHOT, b"history");
        let snapshot = SnapshotDescriptor {
            descriptor_type: "pepper.sqlite_snapshot".into(),
            version: 1,
            database_cid: database.clone(),
            page_table_root_cid: table.clone(),
            page_size: 4096,
            page_count: 2,
            logical_size: 8192,
            base_snapshot_cid: Some(history),
        };
        let payload = encode_canonical(&snapshot, 64 * 1024).unwrap();
        let links = SqliteSnapshotCodecHandler
            .links(&payload, &TraversalLimits::default())
            .unwrap();
        assert_eq!(links, vec![database, table]);
    }

    #[test]
    fn leaf_handler_deduplicates_pack_links() {
        let pack = Cid::new(CODEC_SMALL_OBJECT, b"pack");
        let mut first = page(1, 1);
        first.pack_cid = pack.clone();
        let mut second = page(2, 2);
        second.pack_cid = pack.clone();
        second.offset = 4096;
        let leaf = PageTableNode::leaf([0, 0, 0], vec![first, second]);
        let payload = encode_canonical(&leaf, 256 * 1024).unwrap();
        assert_eq!(
            SqlitePageTableCodecHandler
                .links(&payload, &TraversalLimits::default())
                .unwrap(),
            vec![pack]
        );
    }

    #[test]
    fn page_references_require_page_aligned_pack_offsets() {
        let mut reference = page(1, 1);
        reference.offset = 1;
        assert!(
            reference
                .validate(4096, SqliteFormatLimits::default())
                .is_err()
        );
    }

    #[test]
    fn fully_populated_leaf_stays_below_format_target() {
        let pages = (0..=255u32)
            .map(|slot| page(0x0001_0200 + slot, (slot % 16) as u8))
            .collect::<Vec<_>>();
        let leaf = PageTableNode::leaf([0, 1, 2], pages);
        let payload = encode_canonical(&leaf, 256 * 1024).unwrap();
        assert!(
            payload.len() <= 64 * 1024,
            "leaf is {} bytes",
            payload.len()
        );
    }

    #[tokio::test]
    async fn copy_on_write_updates_only_affected_paths() {
        let store = MemoryStore::default();
        let table = PageTable::default();
        let empty = table.empty_root(&store).await.unwrap();
        let initial = table
            .apply(
                &store,
                &empty,
                4096,
                vec![
                    PageMutation::Put(page(1, 1)),
                    PageMutation::Put(page(0x0001_0203, 2)),
                ],
            )
            .await
            .unwrap();
        assert_eq!(
            table.get(&store, &initial.root, 1).await.unwrap(),
            Some(page(1, 1))
        );
        assert_eq!(
            table.get(&store, &initial.root, 0x0001_0203).await.unwrap(),
            Some(page(0x0001_0203, 2))
        );

        let changed = table
            .apply(
                &store,
                &initial.root,
                4096,
                vec![PageMutation::Put(page(1, 3))],
            )
            .await
            .unwrap();
        assert_eq!(changed.written_nodes.len(), 4);
        assert_eq!(
            table.get(&store, &changed.root, 1).await.unwrap(),
            Some(page(1, 3))
        );
        assert_eq!(
            table.get(&store, &changed.root, 0x0001_0203).await.unwrap(),
            Some(page(0x0001_0203, 2))
        );
    }

    #[tokio::test]
    async fn delete_to_empty_reuses_canonical_empty_root() {
        let store = MemoryStore::default();
        let table = PageTable::default();
        let empty = table.empty_root(&store).await.unwrap();
        let populated = table
            .apply(&store, &empty, 4096, vec![PageMutation::Put(page(1, 1))])
            .await
            .unwrap();
        let deleted = table
            .apply(&store, &populated.root, 4096, vec![PageMutation::Delete(1)])
            .await
            .unwrap();
        assert_eq!(deleted.root, empty);
        assert_eq!(table.get(&store, &deleted.root, 1).await.unwrap(), None);
    }

    #[tokio::test]
    async fn bulk_builder_handles_sparse_prefixes_canonically() {
        let store = MemoryStore::default();
        let table = PageTable::default();
        let mut builder = table.bulk_builder(&store, 4096).unwrap();
        for number in [1, 2, 0x0001_0203, 0x0100_0001] {
            builder
                .push(page(number, (number % 15) as u8))
                .await
                .unwrap();
        }
        let built = builder.finish().await.unwrap();
        for number in [1, 2, 0x0001_0203, 0x0100_0001] {
            assert_eq!(
                table.get(&store, &built.root, number).await.unwrap(),
                Some(page(number, (number % 15) as u8))
            );
        }
        assert_eq!(table.get(&store, &built.root, 3).await.unwrap(), None);
    }

    #[tokio::test]
    async fn truncate_prunes_subtrees_and_keeps_boundary_page() {
        let store = MemoryStore::default();
        let table = PageTable::default();
        let mut builder = table.bulk_builder(&store, 4096).unwrap();
        let pages = [1, 255, 256, 257, 65_536, 65_537, 0x0100_0001];
        for number in pages {
            builder.push(page(number, 1)).await.unwrap();
        }
        let built = builder.finish().await.unwrap();
        let truncated = table
            .truncate(&store, &built.root, 4096, 0x0100_0001, 256)
            .await
            .unwrap();
        for number in [1, 255, 256] {
            assert!(
                table
                    .get(&store, &truncated.root, number)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        for number in [257, 65_536, 65_537, 0x0100_0001] {
            assert_eq!(
                table.get(&store, &truncated.root, number).await.unwrap(),
                None
            );
        }
    }

    #[tokio::test]
    async fn randomized_updates_match_a_btree_model() {
        let store = MemoryStore::default();
        let table = PageTable::default();
        let mut root = table.empty_root(&store).await.unwrap();
        let mut model = std::collections::BTreeMap::new();
        let mut seed = 0x1234_5678u64;
        for step in 0..250u8 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let number = (seed % 64 + 1) as u32;
            let mutation = if seed & 3 == 0 {
                model.remove(&number);
                PageMutation::Delete(number)
            } else {
                let value = page(number, step % 16);
                model.insert(number, value.clone());
                PageMutation::Put(value)
            };
            root = table
                .apply(&store, &root, 4096, vec![mutation])
                .await
                .unwrap()
                .root;
        }
        for number in 1..=64 {
            assert_eq!(
                table.get(&store, &root, number).await.unwrap(),
                model.get(&number).cloned()
            );
        }
    }

    #[tokio::test]
    async fn bounded_batch_lookup_and_complete_validation() {
        let store = MemoryStore::default();
        let table = PageTable::default();
        let mut builder = table.bulk_builder(&store, 4096).unwrap();
        for number in 1..=3 {
            builder.push(page(number, number as u8)).await.unwrap();
        }
        let built = builder.finish().await.unwrap();
        assert_eq!(
            table
                .get_many(&store, &built.root, &[3, 1, 4])
                .await
                .unwrap(),
            vec![Some(page(3, 3)), Some(page(1, 1)), None]
        );
        assert_eq!(
            table
                .validate_complete(&store, &built.root, 4096, 3, true)
                .await
                .unwrap()
                .page_count,
            3
        );
        assert!(
            table
                .get_many(&store, &built.root, &vec![1; 257])
                .await
                .is_err()
        );
        assert!(
            table
                .validate_complete(&store, &built.root, 8192, 3, true)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn fixed_fanout_frontier_and_bulk_reads_scale_with_changed_keys() {
        let store = MemoryStore::default();
        let table = PageTable::default();
        let mut builder = table.bulk_builder(&store, 4096).unwrap();
        for number in 1..=65_536 {
            builder
                .push(page(number, (number % 251) as u8))
                .await
                .unwrap();
        }
        let root = builder.finish().await.unwrap().root;
        let bulk = table
            .get_many_with_stats(
                &store,
                &root,
                &(0..256).map(|index| 65_536 - index).collect::<Vec<_>>(),
            )
            .await
            .unwrap();
        assert_eq!(bulk.values.len(), 256);
        assert!(bulk.values.iter().all(Option::is_some));
        assert!(bulk.unique_nodes_read <= 1 + 256 * 4);

        for retained_history in [1usize, 1_000] {
            let retained = vec![root.clone(); retained_history];
            for changed in [1usize, 16, 256] {
                let mutations = (0..changed)
                    .map(|index| {
                        let number = 1 + (index as u32) * 257;
                        PageMutation::Put(page(number, 252 + (index % 3) as u8))
                    })
                    .collect::<Vec<_>>();
                let update = SqliteIndexAdapter::new(&store, 4096, SqliteFormatLimits::default())
                    .apply(&root, mutations)
                    .await
                    .unwrap();
                assert_eq!(update.frontier.changed_keys, changed);
                assert!(
                    update.frontier.new_index_nodes.len()
                        <= 1 + changed * update.frontier.index_depth
                );
                assert_eq!(retained.len(), retained_history);
            }
        }
    }

    #[tokio::test]
    async fn invalid_truncate_does_not_write_blocks() {
        let store = MemoryStore::default();
        let table = PageTable::default();
        let root = table.empty_root(&store).await.unwrap();
        let before = store.blocks.lock().unwrap().len();
        assert!(table.truncate(&store, &root, 1000, 1, 0).await.is_err());
        assert_eq!(store.blocks.lock().unwrap().len(), before);
    }

    #[test]
    fn database_type_constant_is_stable() {
        assert_eq!(DATABASE_TYPE, "pepper.sqlite_database");
    }
}
