// SPDX-License-Identifier: Apache-2.0

//! Streaming SQLite image import/export over immutable page packs.

use crate::{
    DatabaseDescriptor, PageReference, PageStoragePolicy, PageTable, SnapshotDescriptor,
    SqliteBlockStore, SqliteError, SqliteFormatLimits,
    format::{PAGE_TABLE_TYPE, PageTableNodeKind, encode_canonical},
    whole_file::validate_sqlite_header,
};
use async_trait::async_trait;
use pepper_types::{CODEC_SQLITE_SNAPSHOT, Cid};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagePackWrite {
    pub root: Cid,
    /// Newly written descendants under the root, excluding the root itself.
    pub verified_descendants: Vec<Cid>,
}

#[async_trait]
pub trait PagePackStore: SqliteBlockStore {
    async fn put_page_pack(
        &self,
        payload: Vec<u8>,
        policy: &PageStoragePolicy,
    ) -> Result<PagePackWrite, String>;

    async fn get_page_pack(&self, root: &Cid) -> Result<Vec<u8>, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedSnapshot {
    pub snapshot_cid: Cid,
    pub descriptor: SnapshotDescriptor,
    pub new_page_table_nodes: Vec<Cid>,
    pub new_page_pack_roots: Vec<Cid>,
    pub verified_descendants: Vec<Cid>,
}

pub async fn import_snapshot<S, R>(
    store: &S,
    source: &mut R,
    logical_size: u64,
    database_cid: Cid,
    database: &DatabaseDescriptor,
    base_snapshot_cid: Option<Cid>,
    limits: SqliteFormatLimits,
) -> Result<ImportedSnapshot, SqliteError>
where
    S: PagePackStore + ?Sized,
    R: AsyncRead + Unpin + Send,
{
    database.validate(limits)?;
    if database_cid.codec != pepper_types::CODEC_SQLITE_DATABASE
        || logical_size > limits.max_logical_bytes
        || logical_size % u64::from(database.page_size) != 0
    {
        return Err(SqliteError::Invalid(
            "invalid database CID or import length".into(),
        ));
    }
    let page_count = u32::try_from(logical_size / u64::from(database.page_size))
        .map_err(|_| SqliteError::Limit("SQLite import page count".into()))?;
    if page_count > database.max_page_count || page_count > limits.max_page_count {
        return Err(SqliteError::Limit("SQLite import page count".into()));
    }

    let table = PageTable { limits };
    let mut builder = table.bulk_builder(store, database.page_size)?;
    let target = database.page_pack_target_bytes as usize;
    let mut remaining = logical_size;
    let mut page_number = 1u32;
    let mut first = true;
    let mut pack_roots = Vec::new();
    let mut descendants = Vec::new();
    while remaining > 0 {
        let amount = remaining.min(target as u64) as usize;
        let mut pack = vec![0; amount];
        source
            .read_exact(&mut pack)
            .await
            .map_err(|error| SqliteError::Storage(error.to_string()))?;
        if first {
            validate_sqlite_header(
                &pack,
                logical_size,
                database.page_size,
                database.max_page_count,
                limits.max_logical_bytes,
            )?;
            first = false;
        }
        let stored = store
            .put_page_pack(pack.clone(), &database.storage_policy)
            .await
            .map_err(SqliteError::Storage)?;
        let pack_cid = stored.root;
        pack_roots.push(pack_cid.clone());
        descendants.extend(stored.verified_descendants);
        for (index, page) in pack.chunks_exact(database.page_size as usize).enumerate() {
            builder
                .push(PageReference {
                    page_number,
                    pack_cid: pack_cid.clone(),
                    offset: (index * database.page_size as usize) as u32,
                    length: database.page_size,
                    page_hash: blake3::hash(page).to_hex().to_string(),
                })
                .await?;
            page_number = page_number
                .checked_add(1)
                .ok_or_else(|| SqliteError::Limit("SQLite page number".into()))?;
        }
        remaining -= amount as u64;
    }
    let mut extra = [0u8; 1];
    if source
        .read(&mut extra)
        .await
        .map_err(|error| SqliteError::Storage(error.to_string()))?
        != 0
    {
        return Err(SqliteError::Invalid(
            "SQLite import stream exceeds declared length".into(),
        ));
    }
    let page_table = builder.finish().await?;
    let descriptor = SnapshotDescriptor {
        descriptor_type: "pepper.sqlite_snapshot".into(),
        version: 1,
        database_cid,
        page_table_root_cid: page_table.root,
        page_size: database.page_size,
        page_count,
        logical_size,
        base_snapshot_cid,
    };
    descriptor.validate(limits)?;
    let payload = encode_canonical(&descriptor, limits.max_descriptor_bytes)?;
    let expected = Cid::new(CODEC_SQLITE_SNAPSHOT, &payload);
    let actual = store
        .put(CODEC_SQLITE_SNAPSHOT, payload)
        .await
        .map_err(SqliteError::Storage)?;
    if actual != expected {
        return Err(SqliteError::Storage(
            "store returned a different snapshot CID".into(),
        ));
    }
    Ok(ImportedSnapshot {
        snapshot_cid: actual,
        descriptor,
        new_page_table_nodes: page_table.written_nodes,
        new_page_pack_roots: pack_roots,
        verified_descendants: descendants,
    })
}

pub async fn export_snapshot<S, W>(
    store: &S,
    snapshot: &SnapshotDescriptor,
    destination: &mut W,
    limits: SqliteFormatLimits,
) -> Result<(), SqliteError>
where
    S: PagePackStore + ?Sized,
    W: AsyncWrite + Unpin + Send,
{
    snapshot.validate(limits)?;
    let table = PageTable { limits };
    let root = table.get_node(store, &snapshot.page_table_root_cid).await?;
    table.expect_node(&root, PageTableNodeKind::Internal, 0, &[])?;
    if root.descriptor_type != PAGE_TABLE_TYPE {
        return Err(SqliteError::Invalid("invalid page-table root".into()));
    }
    let mut expected_page = 1u32;
    let mut cached_pack: Option<(Cid, Vec<u8>)> = None;
    for child0 in &root.children {
        let level_one = table.get_node(store, &child0.cid).await?;
        table.expect_node(&level_one, PageTableNodeKind::Internal, 1, &[child0.edge])?;
        for child1 in &level_one.children {
            let level_two = table.get_node(store, &child1.cid).await?;
            table.expect_node(
                &level_two,
                PageTableNodeKind::Internal,
                2,
                &[child0.edge, child1.edge],
            )?;
            for child2 in &level_two.children {
                let leaf = table.get_node(store, &child2.cid).await?;
                table.expect_node(
                    &leaf,
                    PageTableNodeKind::Leaf,
                    3,
                    &[child0.edge, child1.edge, child2.edge],
                )?;
                for page in &leaf.pages {
                    if page.page_number != expected_page
                        || page.length != snapshot.page_size
                        || page.page_number > snapshot.page_count
                    {
                        return Err(SqliteError::Invalid(
                            "snapshot page table is sparse or inconsistent".into(),
                        ));
                    }
                    if cached_pack
                        .as_ref()
                        .is_none_or(|(cid, _)| cid != &page.pack_cid)
                    {
                        cached_pack = Some((
                            page.pack_cid.clone(),
                            store
                                .get_page_pack(&page.pack_cid)
                                .await
                                .map_err(SqliteError::Storage)?,
                        ));
                    }
                    let pack = &cached_pack.as_ref().expect("pack loaded").1;
                    let start = page.offset as usize;
                    let end = start
                        .checked_add(page.length as usize)
                        .filter(|end| *end <= pack.len())
                        .ok_or_else(|| {
                            SqliteError::Invalid("page reference exceeds page pack".into())
                        })?;
                    let bytes = &pack[start..end];
                    if blake3::hash(bytes).to_hex().as_str() != page.page_hash {
                        return Err(SqliteError::Storage(format!(
                            "page {} failed BLAKE3 verification",
                            page.page_number
                        )));
                    }
                    destination
                        .write_all(bytes)
                        .await
                        .map_err(|error| SqliteError::Storage(error.to_string()))?;
                    expected_page = expected_page
                        .checked_add(1)
                        .ok_or_else(|| SqliteError::Limit("SQLite page number".into()))?;
                }
            }
        }
    }
    if expected_page != snapshot.page_count.saturating_add(1) {
        return Err(SqliteError::Invalid(
            "snapshot page count does not match page table".into(),
        ));
    }
    destination
        .flush()
        .await
        .map_err(|error| SqliteError::Storage(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CachePolicyBounds, PageStoragePolicy};
    use pepper_types::{CODEC_SMALL_OBJECT, CODEC_SQLITE_DATABASE, Codec};
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Default)]
    struct MemoryStore(Arc<Mutex<HashMap<Cid, Vec<u8>>>>);

    #[async_trait]
    impl SqliteBlockStore for MemoryStore {
        async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
            self.0
                .lock()
                .unwrap()
                .get(cid)
                .cloned()
                .ok_or_else(|| format!("missing {cid}"))
        }
        async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
            let cid = Cid::new(codec, &payload);
            self.0.lock().unwrap().insert(cid.clone(), payload);
            Ok(cid)
        }
    }

    #[async_trait]
    impl PagePackStore for MemoryStore {
        async fn put_page_pack(
            &self,
            payload: Vec<u8>,
            _policy: &PageStoragePolicy,
        ) -> Result<PagePackWrite, String> {
            let root = self.put(CODEC_SMALL_OBJECT, payload).await?;
            Ok(PagePackWrite {
                root,
                verified_descendants: Vec::new(),
            })
        }
        async fn get_page_pack(&self, root: &Cid) -> Result<Vec<u8>, String> {
            self.get(root).await
        }
    }

    fn database() -> DatabaseDescriptor {
        DatabaseDescriptor::new(
            4096,
            1024,
            8192,
            PageStoragePolicy::Replicated { replicas: 3 },
            CachePolicyBounds {
                minimum_bytes: 4096,
                maximum_bytes: 1024 * 1024,
            },
            1,
            "test",
        )
    }

    fn sqlite_bytes() -> Vec<u8> {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.db");
        {
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "PRAGMA page_size=4096; PRAGMA journal_mode=DELETE;\
                     CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT);\
                     INSERT INTO records(value) VALUES ('one'),('two'),('three');",
                )
                .unwrap();
        }
        std::fs::read(path).unwrap()
    }

    #[tokio::test]
    async fn streaming_import_and_export_are_deterministic_and_exact() {
        let bytes = sqlite_bytes();
        let db = database();
        let db_cid = Cid::new(CODEC_SQLITE_DATABASE, b"database");
        let first_store = MemoryStore::default();
        let second_store = MemoryStore::default();
        let mut first_source = bytes.as_slice();
        let mut second_source = bytes.as_slice();
        let first = import_snapshot(
            &first_store,
            &mut first_source,
            bytes.len() as u64,
            db_cid.clone(),
            &db,
            None,
            SqliteFormatLimits::default(),
        )
        .await
        .unwrap();
        let second = import_snapshot(
            &second_store,
            &mut second_source,
            bytes.len() as u64,
            db_cid,
            &db,
            None,
            SqliteFormatLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(first.snapshot_cid, second.snapshot_cid);
        assert_eq!(
            first.descriptor.page_count as u64 * 4096,
            bytes.len() as u64
        );
        let mut exported = Vec::new();
        export_snapshot(
            &first_store,
            &first.descriptor,
            &mut exported,
            SqliteFormatLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(exported, bytes);
    }

    #[tokio::test]
    async fn export_rejects_corrupted_pack_bytes() {
        let bytes = sqlite_bytes();
        let db = database();
        let store = MemoryStore::default();
        let mut source = bytes.as_slice();
        let imported = import_snapshot(
            &store,
            &mut source,
            bytes.len() as u64,
            Cid::new(CODEC_SQLITE_DATABASE, b"database"),
            &db,
            None,
            SqliteFormatLimits::default(),
        )
        .await
        .unwrap();
        let pack = imported.new_page_pack_roots[0].clone();
        store.0.lock().unwrap().get_mut(&pack).unwrap()[100] ^= 1;
        let mut exported = Vec::new();
        assert!(
            export_snapshot(
                &store,
                &imported.descriptor,
                &mut exported,
                SqliteFormatLimits::default()
            )
            .await
            .is_err()
        );
    }
}
