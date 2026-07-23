// SPDX-License-Identifier: Apache-2.0

//! Bounded validation used by the experimental whole-file import path.

use crate::SqliteError;
use serde::{Deserialize, Serialize};

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SqliteFileMetadata {
    pub page_size: u32,
    pub page_count: u32,
    pub logical_size: u64,
    pub schema_format: u32,
}

/// Validate a clean, closed SQLite main-database image. A zero-byte image is
/// SQLite's canonical never-written database and uses the configured page size.
pub fn validate_sqlite_file(
    bytes: &[u8],
    configured_page_size: u32,
    maximum_page_count: u32,
    maximum_logical_bytes: u64,
) -> Result<SqliteFileMetadata, SqliteError> {
    validate_page_size(configured_page_size)?;
    if bytes.is_empty() {
        return Ok(SqliteFileMetadata {
            page_size: configured_page_size,
            page_count: 0,
            logical_size: 0,
            schema_format: 0,
        });
    }
    validate_sqlite_header(
        bytes,
        bytes.len() as u64,
        configured_page_size,
        maximum_page_count,
        maximum_logical_bytes,
    )
}

/// Validate the first 100 or more bytes when the total stream length is known.
pub fn validate_sqlite_header(
    header: &[u8],
    logical_size: u64,
    configured_page_size: u32,
    maximum_page_count: u32,
    maximum_logical_bytes: u64,
) -> Result<SqliteFileMetadata, SqliteError> {
    validate_page_size(configured_page_size)?;
    if logical_size == 0 {
        return Ok(SqliteFileMetadata {
            page_size: configured_page_size,
            page_count: 0,
            logical_size: 0,
            schema_format: 0,
        });
    }
    if header.len() < 100 || &header[..16] != SQLITE_HEADER {
        return Err(SqliteError::Invalid(
            "input is not a SQLite 3 main database".into(),
        ));
    }
    let encoded_page_size = u16::from_be_bytes([header[16], header[17]]);
    let page_size = if encoded_page_size == 1 {
        65_536
    } else {
        u32::from(encoded_page_size)
    };
    validate_page_size(page_size)?;
    if page_size != configured_page_size || logical_size % u64::from(page_size) != 0 {
        return Err(SqliteError::Invalid(
            "SQLite image page size or file length does not match the database configuration"
                .into(),
        ));
    }
    if !matches!(header[18], 1 | 2)
        || !matches!(header[19], 1 | 2)
        || u32::from(header[20]) > page_size.saturating_sub(480)
    {
        return Err(SqliteError::Invalid(
            "invalid SQLite header format bytes".into(),
        ));
    }
    let change_counter = read_u32(header, 24);
    let header_page_count = read_u32(header, 28);
    let schema_format = read_u32(header, 44);
    let version_valid_for = read_u32(header, 92);
    if change_counter != version_valid_for || !(1..=4).contains(&schema_format) {
        return Err(SqliteError::Invalid(
            "SQLite image is not a clean, supported main database".into(),
        ));
    }
    let actual_page_count = u32::try_from(logical_size / u64::from(page_size))
        .map_err(|_| SqliteError::Limit("SQLite page count".into()))?;
    if header_page_count != actual_page_count
        || actual_page_count > maximum_page_count
        || logical_size > maximum_logical_bytes
    {
        return Err(SqliteError::Limit(
            "SQLite image exceeds or disagrees with configured page bounds".into(),
        ));
    }
    Ok(SqliteFileMetadata {
        page_size,
        page_count: actual_page_count,
        logical_size,
        schema_format,
    })
}

fn validate_page_size(page_size: u32) -> Result<(), SqliteError> {
    if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(SqliteError::Invalid(
            "SQLite page size must be a power of two from 512 through 65536".into(),
        ));
    }
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("header bounds"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_page() -> Vec<u8> {
        let mut bytes = vec![0; 4096];
        bytes[..16].copy_from_slice(SQLITE_HEADER);
        bytes[16..18].copy_from_slice(&4096u16.to_be_bytes());
        bytes[18] = 1;
        bytes[19] = 1;
        bytes[20] = 0;
        bytes[24..28].copy_from_slice(&1u32.to_be_bytes());
        bytes[28..32].copy_from_slice(&1u32.to_be_bytes());
        bytes[44..48].copy_from_slice(&4u32.to_be_bytes());
        bytes[92..96].copy_from_slice(&1u32.to_be_bytes());
        bytes
    }

    #[test]
    fn validates_empty_and_clean_images() {
        assert_eq!(
            validate_sqlite_file(&[], 4096, 100, 1024 * 1024)
                .unwrap()
                .page_count,
            0
        );
        let page = minimal_page();
        assert_eq!(
            validate_sqlite_file(&page, 4096, 100, 1024 * 1024).unwrap(),
            SqliteFileMetadata {
                page_size: 4096,
                page_count: 1,
                logical_size: 4096,
                schema_format: 4,
            }
        );
    }

    #[test]
    fn rejects_hot_mismatched_and_oversized_images() {
        let mut hot = minimal_page();
        hot[92..96].copy_from_slice(&2u32.to_be_bytes());
        assert!(validate_sqlite_file(&hot, 4096, 100, 1024 * 1024).is_err());
        assert!(validate_sqlite_file(&minimal_page(), 8192, 100, 1024 * 1024).is_err());
        assert!(validate_sqlite_file(&minimal_page(), 4096, 0, 1024 * 1024).is_err());
    }

    #[test]
    fn validates_a_database_written_by_upstream_sqlite() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("upstream.db");
        {
            let mut connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "PRAGMA page_size=4096; PRAGMA journal_mode=DELETE;\
                     CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT NOT NULL);",
                )
                .unwrap();
            let transaction = connection.transaction().unwrap();
            transaction
                .execute("INSERT INTO records(value) VALUES ('committed')", [])
                .unwrap();
            transaction.commit().unwrap();
        }
        let bytes = std::fs::read(path).unwrap();
        let metadata = validate_sqlite_file(&bytes, 4096, 1024, 4 * 1024 * 1024).unwrap();
        assert!(metadata.page_count > 0);
        assert_eq!(metadata.logical_size, bytes.len() as u64);
    }
}
