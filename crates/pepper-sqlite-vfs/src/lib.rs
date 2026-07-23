// SPDX-License-Identifier: Apache-2.0

//! SQLite VFS integration for Pepper.
//!
//! The initial exported API is an instrumented wrapper used to prove that the
//! selected SQLite build exercises the documented batch-atomic file-control
//! contract. It is deliberately not the production Pepper storage VFS.

use std::ffi::c_int;

use thiserror::Error;

mod production;
pub use production::{
    BackendOpen, PEPPER_VFS_NAME, PepperVfsBackend, last_pepper_vfs_error, register_pepper_vfs,
    unregister_pepper_vfs,
};
#[cfg(unix)]
mod unix_client;
#[cfg(unix)]
pub use unix_client::UnixSocketBackend;

/// Registered name of the feasibility VFS.
pub const BATCH_SPIKE_VFS_NAME: &str = "pepper-batch-spike";

unsafe extern "C" {
    fn pepper_batch_spike_register() -> c_int;
    fn pepper_batch_spike_unregister() -> c_int;
    fn pepper_batch_spike_reset();
    fn pepper_batch_spike_fail_next_commit();
    fn pepper_batch_spike_exit_on_batch_write();
    fn pepper_batch_spike_begin_count() -> c_int;
    fn pepper_batch_spike_commit_count() -> c_int;
    fn pepper_batch_spike_rollback_count() -> c_int;
    fn pepper_batch_spike_event_count() -> c_int;
    fn pepper_batch_spike_event_at(index: c_int) -> c_int;
}

#[derive(Debug, Error)]
pub enum VfsRegistrationError {
    #[error("SQLite VFS registration failed with code {0}")]
    Sqlite(c_int),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BatchAtomicCounts {
    pub begin: u32,
    pub commit: u32,
    pub rollback: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchAtomicEvent {
    Begin,
    Commit,
    Rollback,
}

/// Register the instrumented feasibility VFS as a non-default VFS.
pub fn register_batch_spike_vfs() -> Result<(), VfsRegistrationError> {
    // SAFETY: The C shim owns a process-lifetime VFS allocation and the
    // function accepts no pointers from Rust.
    let result = unsafe { pepper_batch_spike_register() };
    if result == libsqlite3_sys::SQLITE_OK {
        Ok(())
    } else {
        Err(VfsRegistrationError::Sqlite(result))
    }
}

/// Unregister the feasibility VFS. Open SQLite handles must be closed first.
pub fn unregister_batch_spike_vfs() -> Result<(), VfsRegistrationError> {
    // SAFETY: The function accepts no pointers. Tests close all connections
    // before unregistering the VFS.
    let result = unsafe { pepper_batch_spike_unregister() };
    if result == libsqlite3_sys::SQLITE_OK {
        Ok(())
    } else {
        Err(VfsRegistrationError::Sqlite(result))
    }
}

pub fn reset_batch_spike() {
    // SAFETY: This only resets process-global atomic counters and injection.
    unsafe { pepper_batch_spike_reset() }
}

pub fn fail_next_batch_commit() {
    // SAFETY: This only sets a process-global atomic injection flag.
    unsafe { pepper_batch_spike_fail_next_commit() }
}

/// Terminate the current process from the first batch-buffered `xWrite`.
///
/// This exists only for the feasibility crash test. The C shim exits with
/// status 86 after SQLite begins an atomic batch but before it can commit it.
#[doc(hidden)]
pub fn exit_on_next_batch_write() {
    // SAFETY: This only sets a process-global atomic injection flag. The
    // process does not return once the injected write is reached.
    unsafe { pepper_batch_spike_exit_on_batch_write() }
}

pub fn batch_atomic_counts() -> BatchAtomicCounts {
    // SAFETY: These functions only read process-global atomic counters.
    unsafe {
        BatchAtomicCounts {
            begin: pepper_batch_spike_begin_count().max(0) as u32,
            commit: pepper_batch_spike_commit_count().max(0) as u32,
            rollback: pepper_batch_spike_rollback_count().max(0) as u32,
        }
    }
}

pub fn batch_atomic_events() -> Vec<BatchAtomicEvent> {
    // SAFETY: The C functions only read a fixed process-global atomic event
    // buffer. Negative or unknown values are ignored defensively.
    unsafe {
        let count = pepper_batch_spike_event_count().clamp(0, 64);
        (0..count)
            .filter_map(|index| match pepper_batch_spike_event_at(index) {
                1 => Some(BatchAtomicEvent::Begin),
                2 => Some(BatchAtomicEvent::Commit),
                3 => Some(BatchAtomicEvent::Rollback),
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        process::Command,
        sync::{Mutex, MutexGuard},
    };

    use rusqlite::{Connection, OpenFlags, params};

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct RegisteredVfs {
        _guard: MutexGuard<'static, ()>,
    }

    impl RegisteredVfs {
        fn new() -> Self {
            let guard = TEST_LOCK.lock().expect("test VFS lock");
            register_batch_spike_vfs().expect("register spike VFS");
            reset_batch_spike();
            Self { _guard: guard }
        }
    }

    impl Drop for RegisteredVfs {
        fn drop(&mut self) {
            unregister_batch_spike_vfs().expect("unregister spike VFS");
        }
    }

    fn open(path: &std::path::Path) -> Connection {
        Connection::open_with_flags_and_vfs(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            BATCH_SPIKE_VFS_NAME,
        )
        .expect("open with spike VFS")
    }

    #[test]
    fn bundled_sqlite_enables_batch_atomic_writes() {
        let connection = Connection::open_in_memory().expect("in-memory SQLite");
        let enabled: bool = connection
            .query_row(
                "SELECT sqlite_compileoption_used('ENABLE_BATCH_ATOMIC_WRITE')",
                [],
                |row| row.get(0),
            )
            .expect("compile option query");
        assert!(enabled, "SQLite must compile the batch-atomic pager path");
    }

    #[test]
    fn sqlite_uses_begin_and_commit_file_controls() {
        let _registered = RegisteredVfs::new();
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("batch.db");
        let mut connection = open(&path);
        connection
            .execute_batch(
                "PRAGMA journal_mode=DELETE;\
                 PRAGMA synchronous=FULL;\
                 CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT NOT NULL);",
            )
            .expect("initialize database");

        reset_batch_spike();
        let transaction = connection.transaction().expect("begin transaction");
        for id in 0..256_i64 {
            transaction
                .execute(
                    "INSERT INTO records(id, value) VALUES (?1, ?2)",
                    params![id, format!("value-{id:04}")],
                )
                .expect("insert row");
        }
        transaction.commit().expect("batch-atomic commit");

        let counts = batch_atomic_counts();
        assert!(counts.begin >= 1, "missing BEGIN_ATOMIC_WRITE: {counts:?}");
        assert!(
            counts.commit >= 1,
            "missing COMMIT_ATOMIC_WRITE: {counts:?}"
        );
        assert_eq!(counts.rollback, 0, "unexpected rollback: {counts:?}");
        assert_eq!(
            batch_atomic_events(),
            [BatchAtomicEvent::Begin, BatchAtomicEvent::Commit]
        );
        let rows: i64 = connection
            .query_row("SELECT count(*) FROM records", [], |row| row.get(0))
            .expect("count rows");
        assert_eq!(rows, 256);
    }

    #[test]
    fn failed_batch_commit_invokes_rollback_and_preserves_old_state() {
        let _registered = RegisteredVfs::new();
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("rollback.db");
        let mut connection = open(&path);
        connection
            .execute_batch(
                "PRAGMA journal_mode=DELETE;\
                 PRAGMA synchronous=FULL;\
                 CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT NOT NULL);\
                 INSERT INTO records(value) VALUES ('committed');",
            )
            .expect("initialize database");

        reset_batch_spike();
        fail_next_batch_commit();
        let transaction = connection.transaction().expect("begin transaction");
        transaction
            .execute("INSERT INTO records(value) VALUES ('must-rollback')", [])
            .expect("stage row");
        let error = transaction.commit().expect_err("commit must fail");
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DiskFull)
        );

        let counts = batch_atomic_counts();
        assert!(counts.begin >= 1, "missing BEGIN_ATOMIC_WRITE: {counts:?}");
        assert!(counts.commit >= 1, "missing injected commit: {counts:?}");
        assert!(
            counts.rollback >= 1,
            "missing rollback callback: {counts:?}"
        );
        assert_eq!(
            batch_atomic_events(),
            [
                BatchAtomicEvent::Begin,
                BatchAtomicEvent::Commit,
                BatchAtomicEvent::Rollback
            ]
        );
        let rows: i64 = connection
            .query_row("SELECT count(*) FROM records", [], |row| row.get(0))
            .expect("count rows after rollback");
        assert_eq!(rows, 1);
    }

    #[test]
    fn child_exits_during_batch_write() {
        let Ok(path) = std::env::var("PEPPER_BATCH_SPIKE_CRASH_PATH") else {
            return;
        };
        let _registered = RegisteredVfs::new();
        let mut connection = open(std::path::Path::new(&path));
        exit_on_next_batch_write();
        let transaction = connection.transaction().expect("begin crash transaction");
        transaction
            .execute("INSERT INTO records(value) VALUES ('not-committed')", [])
            .expect("stage crash row");
        let _ = transaction.commit();
        panic!("batch-write exit injection did not terminate the process");
    }

    #[test]
    fn process_termination_between_begin_and_commit_preserves_old_state() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("process-crash.db");
        {
            let _registered = RegisteredVfs::new();
            let connection = open(&path);
            connection
                .execute_batch(
                    "PRAGMA journal_mode=DELETE;\
                     PRAGMA synchronous=FULL;\
                     CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT NOT NULL);\
                     INSERT INTO records(value) VALUES ('committed');",
                )
                .expect("initialize crash database");
        }

        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("tests::child_exits_during_batch_write")
            .arg("--nocapture")
            .env("PEPPER_BATCH_SPIKE_CRASH_PATH", &path)
            .status()
            .expect("run crash subprocess");
        assert_eq!(status.code(), Some(86));

        let _registered = RegisteredVfs::new();
        let connection = open(&path);
        let values = connection
            .prepare("SELECT value FROM records ORDER BY id")
            .expect("prepare post-crash query")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query post-crash rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect post-crash rows");
        assert_eq!(values, ["committed"]);
    }
}
