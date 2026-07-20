// SPDX-License-Identifier: Apache-2.0

use pepper_types::{PinRecord, SCHEMA_VERSION};
use redb::{Database, ReadableTable, TableDefinition};
use std::path::{Path, PathBuf};
use thiserror::Error;

const SCHEMA_META: TableDefinition<&str, &str> = TableDefinition::new("schema_meta");
const PINS: TableDefinition<&str, &[u8]> = TableDefinition::new("pins");
const PINS_BY_ROOT: TableDefinition<&str, &str> = TableDefinition::new("pins_by_root");
const NAMESPACE_GROUPS: TableDefinition<&str, &[u8]> = TableDefinition::new("namespace_groups");
const NAMESPACE_RAFT_VOTE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("namespace_raft_vote");
const NAMESPACE_RAFT_LOG: TableDefinition<&str, &[u8]> = TableDefinition::new("namespace_raft_log");
const NAMESPACE_RAFT_MEMBERSHIP: TableDefinition<&str, &[u8]> =
    TableDefinition::new("namespace_raft_membership");
const NAMESPACE_STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("namespace_state");
const NAMESPACE_CHECKPOINTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("namespace_checkpoints");
const NAMESPACE_IDEMPOTENCY: TableDefinition<&str, &[u8]> =
    TableDefinition::new("namespace_idempotency");
pub const NAMESPACE_STAGING_LEASES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("namespace_staging_leases");
pub const NAMESPACE_READ_LEASES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("namespace_read_leases");
pub const NAMESPACE_PUBLICATION_INTENTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("namespace_publication_intents");
pub const NAMESPACE_DURABILITY_RECEIPTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("namespace_durability_receipts");
pub const NAMESPACE_DISCOVERY_RECORDS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("namespace_discovery_records");
const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_CREATED_AT: &str = "created_at_unix_seconds";
const KEY_UPDATED_AT: &str = "updated_at_unix_seconds";

#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("failed to create metadata parent directory for {path}: {source}")]
    CreateParent {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to open redb metadata database {path}: {source}")]
    Open {
        path: String,
        #[source]
        source: Box<redb::DatabaseError>,
    },
    #[error("failed metadata transaction for {path}: {source}")]
    Transaction {
        path: String,
        #[source]
        source: Box<redb::TransactionError>,
    },
    #[error("failed metadata table operation for {path}: {source}")]
    Table {
        path: String,
        #[source]
        source: Box<redb::TableError>,
    },
    #[error("failed metadata storage operation for {path}: {source}")]
    Storage {
        path: String,
        #[source]
        source: Box<redb::StorageError>,
    },
    #[error("failed metadata commit for {path}: {source}")]
    Commit {
        path: String,
        #[source]
        source: Box<redb::CommitError>,
    },
    #[error("failed to encode or decode metadata for {path}: {source}")]
    Serde {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to inspect metadata file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("metadata schema version value is invalid: {0}")]
    InvalidSchemaVersion(String),
    #[error("metadata schema verification failed: expected {expected}, found {found}")]
    SchemaVerification { expected: u32, found: u32 },
    #[error("pin update attempted to change immutable fields")]
    ImmutablePinFields,
    #[error("deleted pin records cannot be reactivated")]
    PinReactivation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataBackupInfo {
    pub path: PathBuf,
    pub schema_version: u32,
    pub file_bytes: u64,
}

pub struct MetadataStore {
    path: PathBuf,
    db: Database,
    schema_version: u32,
}

impl MetadataStore {
    pub fn open_or_create(path: impl AsRef<Path>) -> Result<Self, MetadataError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| MetadataError::CreateParent {
                path: path.display().to_string(),
                source,
            })?;
        }
        let db = Database::create(&path).map_err(|source| MetadataError::Open {
            path: path.display().to_string(),
            source: Box::new(source),
        })?;
        let schema_version = initialize_schema(&path, &db)?;
        let store = Self {
            path,
            db,
            schema_version,
        };
        store.verify()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn database(&self) -> &Database {
        &self.db
    }

    /// Verify the persisted schema marker before backup, restore, or service startup.
    pub fn verify(&self) -> Result<(), MetadataError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|source| self.transaction(source))?;
        let table = read_txn
            .open_table(SCHEMA_META)
            .map_err(|source| self.table(source))?;
        let found = table
            .get(KEY_SCHEMA_VERSION)
            .map_err(|source| self.storage(source))?
            .ok_or_else(|| MetadataError::InvalidSchemaVersion("missing".to_string()))
            .and_then(|value| parse_schema_version(value.value()))?;
        if found != self.schema_version || found != SCHEMA_VERSION {
            return Err(MetadataError::SchemaVerification {
                expected: SCHEMA_VERSION,
                found,
            });
        }
        Ok(())
    }

    pub fn backup_info(&self) -> Result<MetadataBackupInfo, MetadataError> {
        self.verify()?;
        let file_bytes = std::fs::metadata(&self.path)
            .map_err(|source| MetadataError::Io {
                path: self.path.display().to_string(),
                source,
            })?
            .len();
        Ok(MetadataBackupInfo {
            path: self.path.clone(),
            schema_version: self.schema_version,
            file_bytes,
        })
    }

    pub fn pins(&self) -> PinRepository<'_> {
        PinRepository { store: self }
    }

    fn transaction(&self, source: redb::TransactionError) -> MetadataError {
        MetadataError::Transaction {
            path: self.path.display().to_string(),
            source: Box::new(source),
        }
    }

    fn table(&self, source: redb::TableError) -> MetadataError {
        MetadataError::Table {
            path: self.path.display().to_string(),
            source: Box::new(source),
        }
    }

    fn storage(&self, source: redb::StorageError) -> MetadataError {
        MetadataError::Storage {
            path: self.path.display().to_string(),
            source: Box::new(source),
        }
    }

    fn commit(&self, source: redb::CommitError) -> MetadataError {
        MetadataError::Commit {
            path: self.path.display().to_string(),
            source: Box::new(source),
        }
    }

    fn serde(&self, source: serde_json::Error) -> MetadataError {
        MetadataError::Serde {
            path: self.path.display().to_string(),
            source,
        }
    }
}

/// Persistence boundary for pin records. Signature verification and signing remain
/// policy owned by the agent; this repository owns atomic storage and indexes.
pub struct PinRepository<'a> {
    store: &'a MetadataStore,
}

impl PinRepository<'_> {
    pub fn put(&self, pin: &PinRecord) -> Result<(), MetadataError> {
        let write_txn = self
            .store
            .db
            .begin_write()
            .map_err(|source| self.store.transaction(source))?;
        {
            let mut pins = write_txn
                .open_table(PINS)
                .map_err(|source| self.store.table(source))?;
            if let Some(existing) = pins
                .get(pin.pin_id.as_str())
                .map_err(|source| self.store.storage(source))?
            {
                let existing: PinRecord = serde_json::from_slice(existing.value())
                    .map_err(|source| self.store.serde(source))?;
                validate_pin_update(&existing, pin)?;
            }
            let bytes = serde_json::to_vec(pin).map_err(|source| self.store.serde(source))?;
            pins.insert(pin.pin_id.as_str(), bytes.as_slice())
                .map_err(|source| self.store.storage(source))?;
        }
        {
            let mut by_root = write_txn
                .open_table(PINS_BY_ROOT)
                .map_err(|source| self.store.table(source))?;
            by_root
                .insert(
                    format!("{}:{}", pin.root_cid, pin.pin_id).as_str(),
                    pin.pin_id.as_str(),
                )
                .map_err(|source| self.store.storage(source))?;
        }
        write_txn
            .commit()
            .map_err(|source| self.store.commit(source))?;
        Ok(())
    }

    pub fn replace(&self, pins: &[PinRecord]) -> Result<(), MetadataError> {
        if pins.is_empty() {
            return Ok(());
        }
        let write_txn = self
            .store
            .db
            .begin_write()
            .map_err(|source| self.store.transaction(source))?;
        {
            let mut table = write_txn
                .open_table(PINS)
                .map_err(|source| self.store.table(source))?;
            for pin in pins {
                if let Some(existing) = table
                    .get(pin.pin_id.as_str())
                    .map_err(|source| self.store.storage(source))?
                {
                    let existing: PinRecord = serde_json::from_slice(existing.value())
                        .map_err(|source| self.store.serde(source))?;
                    validate_pin_update(&existing, pin)?;
                }
                let bytes = serde_json::to_vec(pin).map_err(|source| self.store.serde(source))?;
                table
                    .insert(pin.pin_id.as_str(), bytes.as_slice())
                    .map_err(|source| self.store.storage(source))?;
            }
        }
        write_txn
            .commit()
            .map_err(|source| self.store.commit(source))?;
        Ok(())
    }

    pub fn all(&self) -> Result<Vec<PinRecord>, MetadataError> {
        let read_txn = self
            .store
            .db
            .begin_read()
            .map_err(|source| self.store.transaction(source))?;
        let table = match read_txn.open_table(PINS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(source) => return Err(self.store.table(source)),
        };
        let mut pins = Vec::new();
        for item in table.iter().map_err(|source| self.store.storage(source))? {
            let (_, value) = item.map_err(|source| self.store.storage(source))?;
            pins.push(
                serde_json::from_slice(value.value()).map_err(|source| self.store.serde(source))?,
            );
        }
        Ok(pins)
    }
}

fn validate_pin_update(existing: &PinRecord, pin: &PinRecord) -> Result<(), MetadataError> {
    if existing.owner != pin.owner
        || existing.root_cid != pin.root_cid
        || existing.replication_factor != pin.replication_factor
        || existing.created_at_unix_seconds != pin.created_at_unix_seconds
        || existing.expires_at_unix_seconds != pin.expires_at_unix_seconds
    {
        return Err(MetadataError::ImmutablePinFields);
    }
    if existing.status == "deleted" && pin.status != "deleted" {
        return Err(MetadataError::PinReactivation);
    }
    Ok(())
}

fn initialize_schema(path: &Path, db: &Database) -> Result<u32, MetadataError> {
    let write_txn = db
        .begin_write()
        .map_err(|source| MetadataError::Transaction {
            path: path.display().to_string(),
            source: Box::new(source),
        })?;

    let now = unix_seconds().to_string();
    {
        let mut table = write_txn
            .open_table(SCHEMA_META)
            .map_err(|source| map_table(path, source))?;
        let existing = table
            .get(KEY_SCHEMA_VERSION)
            .map_err(|source| map_storage(path, source))?
            .map(|value| parse_schema_version(value.value()))
            .transpose()?;
        if let Some(found) = existing {
            if found != SCHEMA_VERSION {
                return Err(MetadataError::SchemaVerification {
                    expected: SCHEMA_VERSION,
                    found,
                });
            }
        } else {
            let version = SCHEMA_VERSION.to_string();
            table
                .insert(KEY_SCHEMA_VERSION, version.as_str())
                .map_err(|source| map_storage(path, source))?;
            table
                .insert(KEY_CREATED_AT, now.as_str())
                .map_err(|source| map_storage(path, source))?;
        }
    }
    write_txn
        .open_table(PINS)
        .map_err(|source| map_table(path, source))?;
    write_txn
        .open_table(PINS_BY_ROOT)
        .map_err(|source| map_table(path, source))?;
    write_txn
        .open_table(NAMESPACE_GROUPS)
        .map_err(|source| map_table(path, source))?;
    write_txn
        .open_table(NAMESPACE_RAFT_VOTE)
        .map_err(|source| map_table(path, source))?;
    write_txn
        .open_table(NAMESPACE_RAFT_LOG)
        .map_err(|source| map_table(path, source))?;
    write_txn
        .open_table(NAMESPACE_RAFT_MEMBERSHIP)
        .map_err(|source| map_table(path, source))?;
    write_txn
        .open_table(NAMESPACE_STATE)
        .map_err(|source| map_table(path, source))?;
    write_txn
        .open_table(NAMESPACE_CHECKPOINTS)
        .map_err(|source| map_table(path, source))?;
    write_txn
        .open_table(NAMESPACE_IDEMPOTENCY)
        .map_err(|source| map_table(path, source))?;
    write_txn
        .open_table(NAMESPACE_STAGING_LEASES)
        .map_err(|source| map_table(path, source))?;
    write_txn
        .open_table(NAMESPACE_READ_LEASES)
        .map_err(|source| map_table(path, source))?;
    write_txn
        .open_table(NAMESPACE_DISCOVERY_RECORDS)
        .map_err(|source| map_table(path, source))?;
    write_txn
        .open_table(NAMESPACE_PUBLICATION_INTENTS)
        .map_err(|source| map_table(path, source))?;
    write_txn
        .open_table(NAMESPACE_DURABILITY_RECEIPTS)
        .map_err(|source| map_table(path, source))?;
    {
        let mut table = write_txn
            .open_table(SCHEMA_META)
            .map_err(|source| map_table(path, source))?;
        table
            .insert(KEY_UPDATED_AT, now.as_str())
            .map_err(|source| map_storage(path, source))?;
    }
    write_txn.commit().map_err(|source| MetadataError::Commit {
        path: path.display().to_string(),
        source: Box::new(source),
    })?;
    Ok(SCHEMA_VERSION)
}

fn map_table(path: &Path, source: redb::TableError) -> MetadataError {
    MetadataError::Table {
        path: path.display().to_string(),
        source: Box::new(source),
    }
}

fn map_storage(path: &Path, source: redb::StorageError) -> MetadataError {
    MetadataError::Storage {
        path: path.display().to_string(),
        source: Box::new(source),
    }
}

fn parse_schema_version(value: &str) -> Result<u32, MetadataError> {
    value
        .parse::<u32>()
        .map_err(|e| MetadataError::InvalidSchemaVersion(e.to_string()))
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_types::{CODEC_RAW, Cid};

    fn pin(id: &str) -> PinRecord {
        PinRecord {
            pin_id: id.to_string(),
            root_cid: Cid::new(CODEC_RAW, id.as_bytes()),
            owner: "node-a".to_string(),
            replication_factor: 3,
            created_at_unix_seconds: 1,
            expires_at_unix_seconds: None,
            status: "active".to_string(),
            signature_hex: "signature".to_string(),
        }
    }

    #[test]
    fn opens_and_initializes_current_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.redb");
        let store = MetadataStore::open_or_create(&path).unwrap();
        assert_eq!(store.schema_version(), SCHEMA_VERSION);
        assert_eq!(store.path(), path.as_path());
        store.verify().unwrap();
        assert_eq!(store.backup_info().unwrap().schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn rejects_non_current_schema_without_modifying_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.redb");
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut schema = txn.open_table(SCHEMA_META).unwrap();
                schema.insert(KEY_SCHEMA_VERSION, "1").unwrap();
                schema.insert(KEY_CREATED_AT, "1").unwrap();
            }
            txn.commit().unwrap();
        }
        assert!(matches!(
            MetadataStore::open_or_create(&path),
            Err(MetadataError::SchemaVerification {
                expected: SCHEMA_VERSION,
                found: 1
            })
        ));
        let db = Database::create(&path).unwrap();
        let read = db.begin_read().unwrap();
        let schema = read.open_table(SCHEMA_META).unwrap();
        assert_eq!(
            schema.get(KEY_SCHEMA_VERSION).unwrap().unwrap().value(),
            "1"
        );
    }

    #[test]
    fn pin_repository_enforces_immutable_fields_and_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let store = MetadataStore::open_or_create(dir.path().join("metadata.redb")).unwrap();
        let original = pin("pin-1");
        store.pins().put(&original).unwrap();
        assert_eq!(store.pins().all().unwrap(), vec![original.clone()]);

        let mut changed = original.clone();
        changed.replication_factor = 2;
        assert!(matches!(
            store.pins().put(&changed),
            Err(MetadataError::ImmutablePinFields)
        ));

        let mut deleted = original.clone();
        deleted.status = "deleted".to_string();
        store.pins().replace(&[deleted.clone()]).unwrap();
        assert_eq!(store.pins().all().unwrap(), vec![deleted.clone()]);
        assert!(matches!(
            store.pins().put(&original),
            Err(MetadataError::PinReactivation)
        ));
    }
}
