// SPDX-License-Identifier: Apache-2.0

//! Small VFS-enabled SQLite compatibility shell.
//!
//! This intentionally delegates SQL parsing and execution to upstream SQLite.

use pepper_sqlite_vfs::{
    UnixSocketBackend, last_pepper_vfs_error, register_pepper_vfs, unregister_pepper_vfs,
};
use rusqlite::{Connection, ErrorCode, OpenFlags, types::ValueRef};
use std::{
    env,
    error::Error,
    io::Read,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    let mut socket = env::var_os("PEPPER_SQLITE_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./data/sqlite.sock"));
    let mut read_only = false;
    let mut positional = Vec::new();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--socket" => {
                socket = PathBuf::from(arguments.next().ok_or("--socket requires a path")?);
            }
            "--read-only" => read_only = true,
            "--help" | "-h" => {
                println!(
                    "usage: pepper-sqlite [--socket PATH] [--read-only] DATABASE [SQL]\n\
                     SQL is read from stdin when omitted. DATABASE is a Pepper alias."
                );
                return Ok(());
            }
            _ => positional.push(argument),
        }
    }
    let database = positional.first().ok_or("database argument is required")?;
    let sql = if positional.len() > 1 {
        positional[1..].join(" ")
    } else {
        let mut sql = String::new();
        std::io::stdin().read_to_string(&mut sql)?;
        sql
    };
    let backend = Arc::new(UnixSocketBackend::new(socket, Duration::from_secs(30)));
    register_pepper_vfs(backend)?;
    let mode = if read_only { "ro" } else { "rw" };
    let uri = format!("file:pepper%3A{database}?mode={mode}&vfs=pepper&busy_timeout_ms=30000");
    let flags = OpenFlags::SQLITE_OPEN_URI
        | if read_only {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        };
    let result = execute_with_retry(&uri, flags, &sql, Duration::from_secs(30));
    let unregister = unregister_pepper_vfs();
    if let Err(error) = result {
        return Err(format!("{error}; {}", last_pepper_vfs_error()).into());
    }
    unregister?;
    Ok(())
}

fn execute_with_retry(
    uri: &str,
    flags: OpenFlags,
    sql: &str,
    timeout: Duration,
) -> Result<(), rusqlite::Error> {
    let deadline = Instant::now().checked_add(timeout);
    loop {
        match execute(uri, flags, sql) {
            Ok(()) => return Ok(()),
            Err(error)
                if matches!(
                    error.sqlite_error_code(),
                    Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
                ) && deadline.is_some_and(|deadline| Instant::now() < deadline) =>
            {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    }
}

fn execute(uri: &str, flags: OpenFlags, sql: &str) -> Result<(), rusqlite::Error> {
    let connection = Connection::open_with_flags(uri, flags)?;
    let mut statement = connection.prepare(sql)?;
    let columns = statement.column_count();
    if columns == 0 {
        statement.execute([])?;
    } else {
        let names = statement.column_names();
        println!("{}", names.join("\t"));
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let values = (0..columns)
                .map(|column| render(row.get_ref(column).unwrap_or(ValueRef::Null)))
                .collect::<Vec<_>>();
            println!("{}", values.join("\t"));
        }
    }
    Ok(())
}

fn render(value: ValueRef<'_>) -> String {
    match value {
        ValueRef::Null => "NULL".into(),
        ValueRef::Integer(value) => value.to_string(),
        ValueRef::Real(value) => value.to_string(),
        ValueRef::Text(value) => String::from_utf8_lossy(value).into_owned(),
        ValueRef::Blob(value) => format!("x'{}'", hex(value)),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
