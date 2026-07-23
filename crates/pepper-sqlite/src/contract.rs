// SPDX-License-Identifier: Apache-2.0

//! Stable v1 URI, feature, and SQLite error contract.

use crate::{SqliteError, protocol::OpenMode};
use pepper_types::{CODEC_SQLITE_SNAPSHOT, Cid};
use std::{collections::HashMap, fmt, str::FromStr};

pub const FEATURE_BATCH_ATOMIC: &str = "batch_atomic_v1";
pub const FEATURE_PAGE_READS: &str = "page_reads_v1";
pub const FEATURE_WRITER_FENCING: &str = "writer_fencing_v1";
pub const FEATURE_COMMIT_STATUS: &str = "commit_status_v1";

/// VFS-specific `sqlite3_file_control` operations. SQLite reserves operation
/// numbers at or above `SQLITE_FCNTL_USER` (100) for VFS implementations.
pub const PEPPER_FCNTL_LAST_COMMIT: i32 = 0x500;
pub const PEPPER_FCNTL_COMMIT_STATUS: i32 = 0x501;
pub const PEPPER_FCNTL_REFRESH_SNAPSHOT: i32 = 0x502;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliteOpenMode {
    ReadOnly,
    ReadWrite,
    ReadWriteCreate,
}

impl SqliteOpenMode {
    pub fn protocol_mode(self) -> OpenMode {
        match self {
            Self::ReadOnly => OpenMode::ReadOnly,
            Self::ReadWrite => OpenMode::ReadWrite,
            Self::ReadWriteCreate => OpenMode::Create,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PepperDatabaseUri {
    pub database: String,
    pub mode: SqliteOpenMode,
    pub snapshot: Option<Cid>,
    pub busy_timeout_millis: u64,
}

impl PepperDatabaseUri {
    pub fn parse(value: &str) -> Result<Self, SqliteError> {
        let Some(rest) = value.strip_prefix("pepper:") else {
            return Err(SqliteError::Invalid(
                "SQLite filename must start with pepper:".into(),
            ));
        };
        if rest.contains('#') {
            return Err(SqliteError::Invalid(
                "pepper URI fragments are not supported".into(),
            ));
        }
        let (database, query) = rest.split_once('?').unwrap_or((rest, ""));
        validate_database_name(database)?;
        let mut parameters = HashMap::new();
        if !query.is_empty() {
            for pair in query.split('&') {
                let Some((key, value)) = pair.split_once('=') else {
                    return Err(SqliteError::Invalid(
                        "pepper URI parameters require key=value".into(),
                    ));
                };
                if key.is_empty() || value.is_empty() || parameters.insert(key, value).is_some() {
                    return Err(SqliteError::Invalid(
                        "pepper URI has an empty or duplicate parameter".into(),
                    ));
                }
            }
        }
        if parameters
            .keys()
            .any(|key| !["mode", "snapshot", "busy_timeout_ms"].contains(key))
        {
            return Err(SqliteError::Invalid(
                "pepper URI contains an unsupported parameter".into(),
            ));
        }
        let mode = match parameters.get("mode").copied().unwrap_or("rw") {
            "ro" => SqliteOpenMode::ReadOnly,
            "rw" => SqliteOpenMode::ReadWrite,
            "rwc" => SqliteOpenMode::ReadWriteCreate,
            _ => return Err(SqliteError::Invalid("invalid pepper URI mode".into())),
        };
        let snapshot = parameters
            .get("snapshot")
            .map(|value| Cid::from_str(value))
            .transpose()
            .map_err(|error| SqliteError::Invalid(error.to_string()))?;
        if snapshot
            .as_ref()
            .is_some_and(|cid| cid.codec != CODEC_SQLITE_SNAPSHOT)
            || (snapshot.is_some() && mode != SqliteOpenMode::ReadOnly)
        {
            return Err(SqliteError::Invalid(
                "snapshot opens require a SQLite snapshot CID and mode=ro".into(),
            ));
        }
        let busy_timeout_millis = parameters
            .get("busy_timeout_ms")
            .map(|value| value.parse::<u64>())
            .transpose()
            .map_err(|_| SqliteError::Invalid("invalid busy timeout".into()))?
            .unwrap_or(5_000);
        if busy_timeout_millis > 300_000 {
            return Err(SqliteError::Invalid(
                "busy timeout exceeds 300000 milliseconds".into(),
            ));
        }
        Ok(Self {
            database: database.into(),
            mode,
            snapshot,
            busy_timeout_millis,
        })
    }

    pub fn canonical_uri(&self) -> String {
        let mode = match self.mode {
            SqliteOpenMode::ReadOnly => "ro",
            SqliteOpenMode::ReadWrite => "rw",
            SqliteOpenMode::ReadWriteCreate => "rwc",
        };
        let mut uri = format!(
            "pepper:{}?mode={mode}&busy_timeout_ms={}",
            self.database, self.busy_timeout_millis
        );
        if let Some(snapshot) = &self.snapshot {
            uri.push_str("&snapshot=");
            uri.push_str(&snapshot.to_string());
        }
        uri
    }
}

fn validate_database_name(value: &str) -> Result<(), SqliteError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(SqliteError::Invalid(
            "database name must be 1-128 ASCII letters, digits, dots, underscores, or hyphens and start with a letter or digit".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliteStatusCode {
    pub primary: i32,
    pub extended: i32,
}

impl fmt::Display for SqliteStatusCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({})", self.primary, self.extended)
    }
}

impl SqliteStatusCode {
    pub const ERROR: Self = Self {
        primary: 1,
        extended: 1,
    };
    pub const BUSY: Self = Self {
        primary: 5,
        extended: 5,
    };
    pub const BUSY_SNAPSHOT: Self = Self {
        primary: 5,
        extended: 5 | (2 << 8),
    };
    pub const BUSY_TIMEOUT: Self = Self {
        primary: 5,
        extended: 5 | (3 << 8),
    };
    pub const IOERR: Self = Self {
        primary: 10,
        extended: 10,
    };
    pub const IOERR_FSYNC: Self = Self {
        primary: 10,
        extended: 10 | (4 << 8),
    };
    pub const CORRUPT: Self = Self {
        primary: 11,
        extended: 11,
    };
    pub const FULL: Self = Self {
        primary: 13,
        extended: 13,
    };
    pub const PROTOCOL: Self = Self {
        primary: 15,
        extended: 15,
    };

    pub fn from_error(error: &SqliteError) -> Self {
        match error {
            SqliteError::Invalid(_) | SqliteError::Unsupported(_) => Self::ERROR,
            SqliteError::NonCanonical => Self::CORRUPT,
            SqliteError::Limit(_) => Self::FULL,
            SqliteError::Storage(_) => Self::IOERR,
            SqliteError::GenerationConflict { .. } | SqliteError::Fenced => Self::BUSY_SNAPSHOT,
            SqliteError::Busy => Self::BUSY,
            SqliteError::Timeout => Self::BUSY_TIMEOUT,
            SqliteError::AmbiguousCommit { .. } => Self::IOERR_FSYNC,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_defaults_and_canonical_form_are_stable() {
        let uri = PepperDatabaseUri::parse("pepper:orders").unwrap();
        assert_eq!(uri.database, "orders");
        assert_eq!(uri.mode, SqliteOpenMode::ReadWrite);
        assert_eq!(uri.busy_timeout_millis, 5000);
        assert_eq!(
            uri.canonical_uri(),
            "pepper:orders?mode=rw&busy_timeout_ms=5000"
        );
    }

    #[test]
    fn immutable_snapshot_requires_read_only_mode() {
        let snapshot = Cid::new(CODEC_SQLITE_SNAPSHOT, b"snapshot");
        let valid = format!("pepper:orders?mode=ro&snapshot={snapshot}&busy_timeout_ms=10");
        assert_eq!(
            PepperDatabaseUri::parse(&valid).unwrap().snapshot,
            Some(snapshot.clone())
        );
        let invalid = format!("pepper:orders?mode=rw&snapshot={snapshot}");
        assert!(PepperDatabaseUri::parse(&invalid).is_err());
    }

    #[test]
    fn uri_rejects_unknown_duplicate_and_unsafe_input() {
        for value in [
            "file:orders",
            "pepper:",
            "pepper:/orders",
            "pepper:orders?mode=rw&mode=ro",
            "pepper:orders?token=secret",
            "pepper:orders#fragment",
            "pepper:orders?busy_timeout_ms=300001",
        ] {
            assert!(PepperDatabaseUri::parse(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn distributed_failures_have_stable_sqlite_codes() {
        assert_eq!(
            SqliteStatusCode::from_error(&SqliteError::GenerationConflict {
                current_generation: 4
            }),
            SqliteStatusCode::BUSY_SNAPSHOT
        );
        assert_eq!(
            SqliteStatusCode::from_error(&SqliteError::Timeout),
            SqliteStatusCode::BUSY_TIMEOUT
        );
        assert_eq!(
            SqliteStatusCode::from_error(&SqliteError::AmbiguousCommit {
                idempotency_key: "commit".into()
            }),
            SqliteStatusCode::IOERR_FSYNC
        );
    }
}
