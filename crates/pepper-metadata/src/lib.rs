// SPDX-License-Identifier: Apache-2.0

use pepper_types::SCHEMA_VERSION;
use redb::{Database, ReadableTable, TableDefinition};
use std::path::{Path, PathBuf};
use thiserror::Error;

const SCHEMA_META: TableDefinition<&str, &str> = TableDefinition::new("schema_meta");
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
    #[error("metadata schema version {found} is newer than supported version {supported}")]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("metadata schema version {found} requires a migration to version {supported}")]
    MigrationRequired { found: u32, supported: u32 },
    #[error("metadata schema version value is invalid: {0}")]
    InvalidSchemaVersion(String),
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
        Ok(Self {
            path,
            db,
            schema_version,
        })
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
}

fn initialize_schema(path: &Path, db: &Database) -> Result<u32, MetadataError> {
    let write_txn = db
        .begin_write()
        .map_err(|source| MetadataError::Transaction {
            path: path.display().to_string(),
            source: Box::new(source),
        })?;

    let now = unix_seconds().to_string();
    let schema_version = {
        let mut table =
            write_txn
                .open_table(SCHEMA_META)
                .map_err(|source| MetadataError::Table {
                    path: path.display().to_string(),
                    source: Box::new(source),
                })?;
        let existing_version = {
            let existing =
                table
                    .get(KEY_SCHEMA_VERSION)
                    .map_err(|source| MetadataError::Storage {
                        path: path.display().to_string(),
                        source: Box::new(source),
                    })?;
            existing
                .map(|value| parse_schema_version(value.value()))
                .transpose()?
        };
        let version = if let Some(version) = existing_version {
            version
        } else {
            let schema_version = SCHEMA_VERSION.to_string();
            table
                .insert(KEY_SCHEMA_VERSION, schema_version.as_str())
                .map_err(|source| MetadataError::Storage {
                    path: path.display().to_string(),
                    source: Box::new(source),
                })?;
            table
                .insert(KEY_CREATED_AT, now.as_str())
                .map_err(|source| MetadataError::Storage {
                    path: path.display().to_string(),
                    source: Box::new(source),
                })?;
            SCHEMA_VERSION
        };
        table
            .insert(KEY_UPDATED_AT, now.as_str())
            .map_err(|source| MetadataError::Storage {
                path: path.display().to_string(),
                source: Box::new(source),
            })?;
        version
    };

    if schema_version > SCHEMA_VERSION {
        return Err(MetadataError::UnsupportedSchema {
            found: schema_version,
            supported: SCHEMA_VERSION,
        });
    }
    if schema_version < SCHEMA_VERSION {
        return Err(MetadataError::MigrationRequired {
            found: schema_version,
            supported: SCHEMA_VERSION,
        });
    }

    write_txn.commit().map_err(|source| MetadataError::Commit {
        path: path.display().to_string(),
        source: Box::new(source),
    })?;

    Ok(schema_version)
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

    #[test]
    fn opens_and_initializes_schema_meta() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.redb");
        let store = MetadataStore::open_or_create(&path).unwrap();
        assert_eq!(store.schema_version(), SCHEMA_VERSION);
        assert_eq!(store.path(), path.as_path());
    }
}
