// SPDX-License-Identifier: Apache-2.0

//! Agent-side incremental snapshot construction from final dirty pages.

use crate::{
    DatabaseDescriptor, PageMutation, PagePackStore, PageReference, PageTable, SnapshotDescriptor,
    SqliteError, SqliteFormatLimits, format::encode_canonical,
};
use pepper_types::{CODEC_SQLITE_DATABASE, CODEC_SQLITE_SNAPSHOT, Cid};
use std::collections::{BTreeMap, HashMap, HashSet};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirtyPage {
    pub page_number: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalSnapshot {
    pub snapshot_cid: Cid,
    pub descriptor: SnapshotDescriptor,
    pub new_page_table_nodes: Vec<Cid>,
    pub new_page_pack_roots: Vec<Cid>,
    pub verified_descendants: Vec<Cid>,
}

// These inputs are deliberately explicit at the durability boundary: replacing
// them with an options bag would make it easier to mix values from two heads.
#[allow(clippy::too_many_arguments)]
pub async fn build_incremental_snapshot<S: PagePackStore + ?Sized>(
    store: &S,
    database_cid: Cid,
    database: &DatabaseDescriptor,
    base_snapshot_cid: Cid,
    base: &SnapshotDescriptor,
    dirty_pages: Vec<DirtyPage>,
    new_logical_size: u64,
    limits: SqliteFormatLimits,
) -> Result<IncrementalSnapshot, SqliteError> {
    let mut sorted = BTreeMap::new();
    for dirty in dirty_pages {
        if sorted.insert(dirty.page_number, dirty.bytes).is_some() {
            return Err(SqliteError::Invalid(
                "dirty pages must be unique, in range, and page-sized".into(),
            ));
        }
    }
    let page_numbers = sorted.keys().copied().collect::<Vec<_>>();
    let bytes = sorted.into_values().flatten().collect::<Vec<_>>();
    build_incremental_snapshot_stream(
        store,
        database_cid,
        database,
        base_snapshot_cid,
        base,
        page_numbers,
        &mut bytes.as_slice(),
        new_logical_size,
        limits,
    )
    .await
}

/// Build a snapshot while retaining no more than one configured page pack of
/// dirty page bytes. `page_numbers` must be strictly increasing and the reader
/// must contain exactly one page image for each number, in the same order.
#[allow(clippy::too_many_arguments)]
pub async fn build_incremental_snapshot_stream<S, R>(
    store: &S,
    database_cid: Cid,
    database: &DatabaseDescriptor,
    base_snapshot_cid: Cid,
    base: &SnapshotDescriptor,
    page_numbers: Vec<u32>,
    dirty_page_bytes: &mut R,
    new_logical_size: u64,
    limits: SqliteFormatLimits,
) -> Result<IncrementalSnapshot, SqliteError>
where
    S: PagePackStore + ?Sized,
    R: AsyncRead + Unpin + Send,
{
    database.validate(limits)?;
    base.validate(limits)?;
    if database_cid.codec != CODEC_SQLITE_DATABASE
        || base_snapshot_cid.codec != CODEC_SQLITE_SNAPSHOT
        || base.database_cid != database_cid
        || base.page_size != database.page_size
        || new_logical_size > limits.max_logical_bytes
        || new_logical_size % u64::from(database.page_size) != 0
    {
        return Err(SqliteError::Invalid(
            "incremental transaction does not match its base database".into(),
        ));
    }
    let new_page_count = u32::try_from(new_logical_size / u64::from(database.page_size))
        .map_err(|_| SqliteError::Limit("SQLite transaction page count".into()))?;
    if new_page_count > database.max_page_count || new_page_count > limits.max_page_count {
        return Err(SqliteError::Limit("SQLite transaction page count".into()));
    }
    if page_numbers.is_empty() && new_page_count == base.page_count {
        return Err(SqliteError::Invalid("empty SQLite transaction".into()));
    }
    if page_numbers.iter().enumerate().any(|(index, page_number)| {
        *page_number == 0
            || *page_number > new_page_count
            || index
                .checked_sub(1)
                .is_some_and(|prior| page_numbers[prior] >= *page_number)
    }) {
        return Err(SqliteError::Invalid(
            "dirty pages must be strictly increasing and in range".into(),
        ));
    }

    let pages_per_pack = database.page_pack_target_bytes / database.page_size;
    let mut mutations = Vec::with_capacity(page_numbers.len());
    let mut created_packs = HashMap::<Cid, Vec<Cid>>::new();
    for group in page_numbers.chunks(pages_per_pack as usize) {
        let payload_bytes = group.len() * database.page_size as usize;
        let mut payload = vec![0; payload_bytes];
        dirty_page_bytes
            .read_exact(&mut payload)
            .await
            .map_err(|error| SqliteError::Storage(error.to_string()))?;
        let page_hashes = payload
            .chunks_exact(database.page_size as usize)
            .map(|page| blake3::hash(page).to_hex().to_string())
            .collect::<Vec<_>>();
        let stored = store
            .put_page_pack(payload, &database.storage_policy)
            .await
            .map_err(SqliteError::Storage)?;
        for (offset, (page_number, page_hash)) in group.iter().zip(page_hashes).enumerate() {
            let start = offset * database.page_size as usize;
            mutations.push(PageMutation::Put(PageReference {
                page_number: *page_number,
                pack_cid: stored.root.clone(),
                offset: start as u32,
                length: database.page_size,
                page_hash,
            }));
        }
        created_packs.insert(stored.root, stored.verified_descendants);
    }
    let mut trailing = [0u8; 1];
    if dirty_page_bytes
        .read(&mut trailing)
        .await
        .map_err(|error| SqliteError::Storage(error.to_string()))?
        != 0
    {
        return Err(SqliteError::Invalid(
            "dirty-page stream exceeds its declared page count".into(),
        ));
    }

    let table = PageTable { limits };
    let base_reachable = table
        .validate_complete(
            store,
            &base.page_table_root_cid,
            database.page_size,
            base.page_count,
            true,
        )
        .await?;
    let inherited_nodes = base_reachable.node_cids.into_iter().collect::<HashSet<_>>();
    let inherited_packs = base_reachable
        .page_pack_roots
        .into_iter()
        .collect::<HashSet<_>>();
    let mut root = base.page_table_root_cid.clone();
    let mut written_nodes = Vec::new();
    if new_page_count < base.page_count {
        let update = table
            .truncate(
                store,
                &root,
                database.page_size,
                base.page_count,
                new_page_count,
            )
            .await?;
        root = update.root;
        written_nodes.extend(update.written_nodes);
    }
    if !mutations.is_empty() {
        let update = table
            .apply(store, &root, database.page_size, mutations)
            .await?;
        root = update.root;
        written_nodes.extend(update.written_nodes);
    }
    let reachable = table
        .validate_complete(store, &root, database.page_size, new_page_count, true)
        .await?;
    let reachable_nodes = reachable.node_cids.into_iter().collect::<HashSet<_>>();
    written_nodes.retain(|cid| reachable_nodes.contains(cid) && !inherited_nodes.contains(cid));
    written_nodes.sort_by_key(ToString::to_string);
    written_nodes.dedup();

    let reachable_packs = reachable
        .page_pack_roots
        .into_iter()
        .collect::<HashSet<_>>();
    let mut pack_roots = created_packs
        .keys()
        .filter(|cid| reachable_packs.contains(*cid) && !inherited_packs.contains(*cid))
        .cloned()
        .collect::<Vec<_>>();
    pack_roots.sort_by_key(ToString::to_string);
    let mut descendants = pack_roots
        .iter()
        .flat_map(|root| created_packs.get(root).into_iter().flatten().cloned())
        .collect::<Vec<_>>();
    descendants.sort_by_key(ToString::to_string);
    descendants.dedup();

    let descriptor = SnapshotDescriptor {
        descriptor_type: "pepper.sqlite_snapshot".into(),
        version: 1,
        database_cid,
        page_table_root_cid: root,
        page_size: database.page_size,
        page_count: new_page_count,
        logical_size: new_logical_size,
        base_snapshot_cid: Some(base_snapshot_cid),
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
            "store returned a different incremental snapshot CID".into(),
        ));
    }
    Ok(IncrementalSnapshot {
        snapshot_cid: actual,
        descriptor,
        new_page_table_nodes: written_nodes,
        new_page_pack_roots: pack_roots,
        verified_descendants: descendants,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CachePolicyBounds, PagePackWrite, PageStoragePolicy, SqliteBlockStore, export_snapshot,
        import_snapshot,
    };
    use async_trait::async_trait;
    use pepper_types::{CODEC_SMALL_OBJECT, Codec};
    use std::sync::{Arc, Mutex};

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
            Ok(PagePackWrite {
                root: self.put(CODEC_SMALL_OBJECT, payload).await?,
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
            PageStoragePolicy::Replicated { replicas: 1 },
            CachePolicyBounds {
                minimum_bytes: 4096,
                maximum_bytes: 1024 * 1024,
            },
            1,
            "test",
        )
    }

    async fn empty_snapshot(store: &MemoryStore, database_cid: Cid) -> (Cid, SnapshotDescriptor) {
        let root = PageTable::default().empty_root(store).await.unwrap();
        let descriptor = SnapshotDescriptor {
            descriptor_type: "pepper.sqlite_snapshot".into(),
            version: 1,
            database_cid,
            page_table_root_cid: root,
            page_size: 4096,
            page_count: 0,
            logical_size: 0,
            base_snapshot_cid: None,
        };
        let payload = encode_canonical(&descriptor, 64 * 1024).unwrap();
        let cid = store.put(CODEC_SQLITE_SNAPSHOT, payload).await.unwrap();
        (cid, descriptor)
    }

    #[tokio::test]
    async fn incremental_growth_update_and_truncation_are_exact() {
        let store = MemoryStore::default();
        let database = database();
        let database_payload = encode_canonical(&database, 64 * 1024).unwrap();
        let database_cid = Cid::new(CODEC_SQLITE_DATABASE, &database_payload);
        let (empty_cid, empty) = empty_snapshot(&store, database_cid.clone()).await;
        let grown = build_incremental_snapshot(
            &store,
            database_cid.clone(),
            &database,
            empty_cid,
            &empty,
            vec![
                DirtyPage {
                    page_number: 1,
                    bytes: vec![1; 4096],
                },
                DirtyPage {
                    page_number: 2,
                    bytes: vec![2; 4096],
                },
            ],
            8192,
            SqliteFormatLimits::default(),
        )
        .await
        .unwrap();
        let updated = build_incremental_snapshot(
            &store,
            database_cid.clone(),
            &database,
            grown.snapshot_cid.clone(),
            &grown.descriptor,
            vec![DirtyPage {
                page_number: 2,
                bytes: vec![3; 4096],
            }],
            8192,
            SqliteFormatLimits::default(),
        )
        .await
        .unwrap();
        let mut bytes = Vec::new();
        export_snapshot(
            &store,
            &updated.descriptor,
            &mut bytes,
            SqliteFormatLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(&bytes[..4096], vec![1; 4096]);
        assert_eq!(&bytes[4096..], vec![3; 4096]);

        let truncated = build_incremental_snapshot(
            &store,
            database_cid,
            &database,
            updated.snapshot_cid,
            &updated.descriptor,
            Vec::new(),
            4096,
            SqliteFormatLimits::default(),
        )
        .await
        .unwrap();
        let validation = PageTable::default()
            .validate_complete(
                &store,
                &truncated.descriptor.page_table_root_cid,
                4096,
                1,
                true,
            )
            .await
            .unwrap();
        assert_eq!(validation.page_count, 1);
    }

    #[tokio::test]
    async fn incremental_real_sqlite_update_exports_byte_identically() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("database.db");
        {
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "PRAGMA page_size=4096; PRAGMA journal_mode=DELETE; \
                     CREATE TABLE records(value TEXT NOT NULL); \
                     INSERT INTO records VALUES ('base');",
                )
                .unwrap();
        }
        let base_bytes = std::fs::read(&path).unwrap();
        let store = MemoryStore::default();
        let database = database();
        let database_payload = encode_canonical(&database, 64 * 1024).unwrap();
        let database_cid = Cid::new(CODEC_SQLITE_DATABASE, &database_payload);
        let imported = import_snapshot(
            &store,
            &mut base_bytes.as_slice(),
            base_bytes.len() as u64,
            database_cid.clone(),
            &database,
            None,
            SqliteFormatLimits::default(),
        )
        .await
        .unwrap();
        {
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute("UPDATE records SET value='changed'", [])
                .unwrap();
        }
        let next_bytes = std::fs::read(&path).unwrap();
        let dirty = next_bytes
            .chunks_exact(4096)
            .zip(base_bytes.chunks_exact(4096))
            .enumerate()
            .filter(|(_, (next, base))| next != base)
            .map(|(index, (next, _))| DirtyPage {
                page_number: index as u32 + 1,
                bytes: next.to_vec(),
            })
            .collect();
        let updated = build_incremental_snapshot(
            &store,
            database_cid,
            &database,
            imported.snapshot_cid,
            &imported.descriptor,
            dirty,
            next_bytes.len() as u64,
            SqliteFormatLimits::default(),
        )
        .await
        .unwrap();
        let mut exported = Vec::new();
        export_snapshot(
            &store,
            &updated.descriptor,
            &mut exported,
            SqliteFormatLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(exported, next_bytes);
    }
}
