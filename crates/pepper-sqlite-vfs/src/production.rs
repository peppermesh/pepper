// SPDX-License-Identifier: Apache-2.0

use pepper_sqlite::{DirtyPage, PepperDatabaseUri, SqliteError, SqliteStatusCode, WriterTicket};
use pepper_types::Cid;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    ffi::{CStr, c_char, c_int, c_void},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const PEPPER_VFS_NAME: &str = "pepper";
const CACHE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct BackendOpen {
    pub session_id: String,
    pub database: String,
    pub snapshot_cid: Cid,
    pub generation: u64,
    pub page_size: u32,
    pub page_count: u32,
    pub writable: bool,
}

pub trait PepperVfsBackend: Send + Sync + 'static {
    fn open(&self, uri: &PepperDatabaseUri) -> Result<BackendOpen, SqliteError>;
    fn close(&self, session_id: &str) -> Result<(), SqliteError>;
    fn read_pages(
        &self,
        session_id: &str,
        snapshot: &Cid,
        page_numbers: &[u32],
    ) -> Result<Vec<Vec<u8>>, SqliteError>;
    fn acquire_writer(
        &self,
        session_id: &str,
        database: &str,
        base_snapshot: &Cid,
        base_generation: u64,
        busy_timeout_millis: u64,
    ) -> Result<WriterTicket, SqliteError>;
    fn renew_writer(
        &self,
        session_id: &str,
        ticket: &WriterTicket,
    ) -> Result<WriterTicket, SqliteError>;
    fn release_writer(&self, session_id: &str, ticket: &WriterTicket) -> Result<(), SqliteError>;
    // The commit boundary keeps all fencing and snapshot preconditions visible.
    #[allow(clippy::too_many_arguments)]
    fn commit(
        &self,
        session_id: &str,
        idempotency_key: &str,
        ticket: &WriterTicket,
        base_snapshot: &Cid,
        base_generation: u64,
        dirty_pages: Vec<DirtyPage>,
        new_logical_size: u64,
    ) -> Result<BackendOpen, SqliteError>;
}

enum WorkerRequest {
    Open {
        uri: PepperDatabaseUri,
        response: mpsc::SyncSender<Result<BackendOpen, SqliteError>>,
    },
    Close {
        session_id: String,
        response: mpsc::SyncSender<Result<(), SqliteError>>,
    },
    ReadPages {
        session_id: String,
        snapshot: Cid,
        page_numbers: Vec<u32>,
        response: mpsc::SyncSender<Result<Vec<Vec<u8>>, SqliteError>>,
    },
    AcquireWriter {
        session_id: String,
        database: String,
        base_snapshot: Cid,
        base_generation: u64,
        busy_timeout_millis: u64,
        response: mpsc::SyncSender<Result<WriterTicket, SqliteError>>,
    },
    RenewWriter {
        session_id: String,
        ticket: WriterTicket,
        response: mpsc::SyncSender<Result<WriterTicket, SqliteError>>,
    },
    ReleaseWriter {
        session_id: String,
        ticket: WriterTicket,
        response: mpsc::SyncSender<Result<(), SqliteError>>,
    },
    Commit {
        session_id: String,
        idempotency_key: String,
        ticket: WriterTicket,
        base_snapshot: Cid,
        base_generation: u64,
        dirty_pages: Vec<DirtyPage>,
        new_logical_size: u64,
        response: mpsc::SyncSender<Result<BackendOpen, SqliteError>>,
    },
}

struct WorkerBackend {
    sender: mpsc::SyncSender<WorkerRequest>,
    active_tickets: Arc<Mutex<HashMap<String, Arc<Mutex<WriterTicket>>>>>,
    shutdown: Arc<AtomicBool>,
    heartbeat: Option<std::thread::JoinHandle<()>>,
}

impl WorkerBackend {
    fn new(inner: Arc<dyn PepperVfsBackend>) -> Result<Self, super::VfsRegistrationError> {
        let (sender, receiver) = mpsc::sync_channel::<WorkerRequest>(256);
        let receiver = Arc::new(Mutex::new(receiver));
        let active_tickets = Arc::new(Mutex::new(
            HashMap::<String, Arc<Mutex<WriterTicket>>>::new(),
        ));
        let shutdown = Arc::new(AtomicBool::new(false));
        for index in 0..4 {
            let receiver = receiver.clone();
            let inner = inner.clone();
            std::thread::Builder::new()
                .name(format!("pepper-sqlite-vfs-{index}"))
                .spawn(move || {
                    loop {
                        let request = {
                            let Ok(receiver) = receiver.lock() else {
                                return;
                            };
                            let Ok(request) = receiver.recv() else {
                                return;
                            };
                            request
                        };
                        match request {
                            WorkerRequest::Open { uri, response } => {
                                let _ = response.send(inner.open(&uri));
                            }
                            WorkerRequest::Close {
                                session_id,
                                response,
                            } => {
                                let _ = response.send(inner.close(&session_id));
                            }
                            WorkerRequest::ReadPages {
                                session_id,
                                snapshot,
                                page_numbers,
                                response,
                            } => {
                                let _ = response.send(inner.read_pages(
                                    &session_id,
                                    &snapshot,
                                    &page_numbers,
                                ));
                            }
                            WorkerRequest::AcquireWriter {
                                session_id,
                                database,
                                base_snapshot,
                                base_generation,
                                busy_timeout_millis,
                                response,
                            } => {
                                let _ = response.send(inner.acquire_writer(
                                    &session_id,
                                    &database,
                                    &base_snapshot,
                                    base_generation,
                                    busy_timeout_millis,
                                ));
                            }
                            WorkerRequest::RenewWriter {
                                session_id,
                                ticket,
                                response,
                            } => {
                                let _ = response.send(inner.renew_writer(&session_id, &ticket));
                            }
                            WorkerRequest::ReleaseWriter {
                                session_id,
                                ticket,
                                response,
                            } => {
                                let _ = response.send(inner.release_writer(&session_id, &ticket));
                            }
                            WorkerRequest::Commit {
                                session_id,
                                idempotency_key,
                                ticket,
                                base_snapshot,
                                base_generation,
                                dirty_pages,
                                new_logical_size,
                                response,
                            } => {
                                let _ = response.send(inner.commit(
                                    &session_id,
                                    &idempotency_key,
                                    &ticket,
                                    &base_snapshot,
                                    base_generation,
                                    dirty_pages,
                                    new_logical_size,
                                ));
                            }
                        }
                    }
                })
                .map_err(|_| {
                    super::VfsRegistrationError::Sqlite(libsqlite3_sys::SQLITE_CANTOPEN)
                })?;
        }
        let heartbeat_tickets = active_tickets.clone();
        let heartbeat_shutdown = shutdown.clone();
        let heartbeat_inner = inner;
        let heartbeat = std::thread::Builder::new()
            .name("pepper-sqlite-vfs-heartbeat".into())
            .spawn(move || {
                while !heartbeat_shutdown.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(250));
                    let now = unix_millis();
                    let candidates = heartbeat_tickets
                        .lock()
                        .map(|tickets| {
                            tickets
                                .iter()
                                .map(|(session, ticket)| (session.clone(), ticket.clone()))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    let due = candidates.into_iter().filter(|(_, ticket)| {
                        ticket
                            .lock()
                            .map(|ticket| ticket.expires_at_millis <= now.saturating_add(5_000))
                            .unwrap_or(false)
                    });
                    for (session, shared_ticket) in due {
                        let Ok(mut ticket) = shared_ticket.lock() else {
                            return;
                        };
                        let still_active = heartbeat_tickets
                            .lock()
                            .map(|tickets| {
                                tickets
                                    .get(&session)
                                    .is_some_and(|active| Arc::ptr_eq(active, &shared_ticket))
                            })
                            .unwrap_or(false);
                        if !still_active {
                            continue;
                        }
                        match heartbeat_inner.renew_writer(&session, &ticket) {
                            Ok(renewed) => {
                                *ticket = renewed;
                            }
                            Err(_) => {
                                if let Ok(mut tickets) = heartbeat_tickets.lock() {
                                    tickets.remove(&session);
                                }
                            }
                        }
                    }
                }
            })
            .map_err(|_| super::VfsRegistrationError::Sqlite(libsqlite3_sys::SQLITE_CANTOPEN))?;
        Ok(Self {
            sender,
            active_tickets,
            shutdown,
            heartbeat: Some(heartbeat),
        })
    }

    fn channel_error() -> SqliteError {
        SqliteError::Storage("SQLite VFS worker is unavailable".into())
    }
}

impl Drop for WorkerBackend {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(heartbeat) = self.heartbeat.take() {
            let _ = heartbeat.join();
        }
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

impl PepperVfsBackend for WorkerBackend {
    fn open(&self, uri: &PepperDatabaseUri) -> Result<BackendOpen, SqliteError> {
        let (response, result) = mpsc::sync_channel(1);
        self.sender
            .send(WorkerRequest::Open {
                uri: uri.clone(),
                response,
            })
            .map_err(|_| Self::channel_error())?;
        result.recv().map_err(|_| Self::channel_error())?
    }

    fn close(&self, session_id: &str) -> Result<(), SqliteError> {
        let (response, result) = mpsc::sync_channel(1);
        self.sender
            .send(WorkerRequest::Close {
                session_id: session_id.into(),
                response,
            })
            .map_err(|_| Self::channel_error())?;
        result.recv().map_err(|_| Self::channel_error())?
    }

    fn read_pages(
        &self,
        session_id: &str,
        snapshot: &Cid,
        page_numbers: &[u32],
    ) -> Result<Vec<Vec<u8>>, SqliteError> {
        let (response, result) = mpsc::sync_channel(1);
        self.sender
            .send(WorkerRequest::ReadPages {
                session_id: session_id.into(),
                snapshot: snapshot.clone(),
                page_numbers: page_numbers.to_vec(),
                response,
            })
            .map_err(|_| Self::channel_error())?;
        result.recv().map_err(|_| Self::channel_error())?
    }

    fn acquire_writer(
        &self,
        session_id: &str,
        database: &str,
        base_snapshot: &Cid,
        base_generation: u64,
        busy_timeout_millis: u64,
    ) -> Result<WriterTicket, SqliteError> {
        let (response, result) = mpsc::sync_channel(1);
        self.sender
            .send(WorkerRequest::AcquireWriter {
                session_id: session_id.into(),
                database: database.into(),
                base_snapshot: base_snapshot.clone(),
                base_generation,
                busy_timeout_millis,
                response,
            })
            .map_err(|_| Self::channel_error())?;
        let ticket = result.recv().map_err(|_| Self::channel_error())??;
        self.active_tickets
            .lock()
            .map_err(|_| Self::channel_error())?
            .insert(session_id.into(), Arc::new(Mutex::new(ticket.clone())));
        Ok(ticket)
    }

    fn renew_writer(
        &self,
        session_id: &str,
        ticket: &WriterTicket,
    ) -> Result<WriterTicket, SqliteError> {
        let shared = self
            .active_tickets
            .lock()
            .map_err(|_| Self::channel_error())?
            .get(session_id)
            .cloned()
            .ok_or(SqliteError::Fenced)?;
        let mut current = shared.lock().map_err(|_| Self::channel_error())?;
        if current.ticket_id != ticket.ticket_id {
            return Err(SqliteError::Fenced);
        }
        let (response, result) = mpsc::sync_channel(1);
        self.sender
            .send(WorkerRequest::RenewWriter {
                session_id: session_id.into(),
                ticket: current.clone(),
                response,
            })
            .map_err(|_| Self::channel_error())?;
        let renewed = result.recv().map_err(|_| Self::channel_error())??;
        *current = renewed.clone();
        Ok(renewed)
    }

    fn release_writer(&self, session_id: &str, ticket: &WriterTicket) -> Result<(), SqliteError> {
        let shared = self
            .active_tickets
            .lock()
            .map_err(|_| Self::channel_error())?
            .get(session_id)
            .cloned()
            .ok_or(SqliteError::Fenced)?;
        let current = shared.lock().map_err(|_| Self::channel_error())?;
        if current.ticket_id != ticket.ticket_id {
            return Err(SqliteError::Fenced);
        }
        let (response, result) = mpsc::sync_channel(1);
        self.sender
            .send(WorkerRequest::ReleaseWriter {
                session_id: session_id.into(),
                ticket: current.clone(),
                response,
            })
            .map_err(|_| Self::channel_error())?;
        result.recv().map_err(|_| Self::channel_error())??;
        self.active_tickets
            .lock()
            .map_err(|_| Self::channel_error())?
            .remove(session_id);
        Ok(())
    }

    fn commit(
        &self,
        session_id: &str,
        idempotency_key: &str,
        ticket: &WriterTicket,
        base_snapshot: &Cid,
        base_generation: u64,
        dirty_pages: Vec<DirtyPage>,
        new_logical_size: u64,
    ) -> Result<BackendOpen, SqliteError> {
        let shared = self
            .active_tickets
            .lock()
            .map_err(|_| Self::channel_error())?
            .get(session_id)
            .cloned()
            .ok_or(SqliteError::Fenced)?;
        let current = shared.lock().map_err(|_| Self::channel_error())?;
        if current.ticket_id != ticket.ticket_id {
            return Err(SqliteError::Fenced);
        }
        let (response, result) = mpsc::sync_channel(1);
        self.sender
            .send(WorkerRequest::Commit {
                session_id: session_id.into(),
                idempotency_key: idempotency_key.into(),
                ticket: current.clone(),
                base_snapshot: base_snapshot.clone(),
                base_generation,
                dirty_pages,
                new_logical_size,
                response,
            })
            .map_err(|_| Self::channel_error())?;
        let opened = result.recv().map_err(|_| Self::channel_error())??;
        self.active_tickets
            .lock()
            .map_err(|_| Self::channel_error())?
            .remove(session_id);
        Ok(opened)
    }
}

static BACKEND: OnceLock<Mutex<Option<Arc<dyn PepperVfsBackend>>>> = OnceLock::new();
static LAST_ERROR: OnceLock<Mutex<String>> = OnceLock::new();

pub fn last_pepper_vfs_error() -> String {
    LAST_ERROR
        .get_or_init(|| Mutex::new(String::new()))
        .lock()
        .map(|value| value.clone())
        .unwrap_or_else(|_| "Pepper VFS error lock poisoned".into())
}

unsafe extern "C" {
    fn pepper_production_vfs_register() -> c_int;
    fn pepper_production_vfs_unregister() -> c_int;
}

pub fn register_pepper_vfs(
    backend: Arc<dyn PepperVfsBackend>,
) -> Result<(), super::VfsRegistrationError> {
    let backend: Arc<dyn PepperVfsBackend> = Arc::new(WorkerBackend::new(backend)?);
    let slot = BACKEND.get_or_init(|| Mutex::new(None));
    *slot.lock().expect("Pepper VFS backend lock") = Some(backend);
    // SAFETY: the C function takes no pointers and registers process-lifetime
    // method tables. All callback state is owned by Rust boxes.
    let result = unsafe { pepper_production_vfs_register() };
    if result == libsqlite3_sys::SQLITE_OK {
        Ok(())
    } else {
        *slot.lock().expect("Pepper VFS backend lock") = None;
        Err(super::VfsRegistrationError::Sqlite(result))
    }
}

pub fn unregister_pepper_vfs() -> Result<(), super::VfsRegistrationError> {
    // SAFETY: callers must close SQLite handles first, matching SQLite's VFS
    // unregister contract.
    let result = unsafe { pepper_production_vfs_unregister() };
    if result == libsqlite3_sys::SQLITE_OK {
        if let Some(slot) = BACKEND.get() {
            *slot.lock().expect("Pepper VFS backend lock") = None;
        }
        Ok(())
    } else {
        Err(super::VfsRegistrationError::Sqlite(result))
    }
}

#[derive(Debug, Clone)]
struct Segment {
    offset: u64,
    bytes: Vec<u8>,
}

struct RemoteFile {
    backend: Arc<dyn PepperVfsBackend>,
    uri: PepperDatabaseUri,
    opened: BackendOpen,
    ticket: Option<WriterTicket>,
    in_batch: bool,
    implicit_batch: bool,
    writes: Vec<Segment>,
    truncate_size: Option<u64>,
    cache: HashMap<u32, Arc<Vec<u8>>>,
    cache_order: VecDeque<u32>,
    cache_bytes: usize,
    commit_sequence: u64,
}

impl RemoteFile {
    fn logical_size(&self) -> u64 {
        self.truncate_size
            .unwrap_or(u64::from(self.opened.page_count) * u64::from(self.opened.page_size))
            .max(
                self.writes
                    .iter()
                    .map(|write| write.offset.saturating_add(write.bytes.len() as u64))
                    .max()
                    .unwrap_or(0),
            )
    }

    fn page(&mut self, page_number: u32) -> Result<Vec<u8>, SqliteError> {
        if page_number == 0 {
            return Err(SqliteError::Invalid("SQLite page zero".into()));
        }
        if page_number > self.opened.page_count {
            return Ok(vec![0; self.opened.page_size as usize]);
        }
        if let Some(page) = self.cache.get(&page_number) {
            return Ok((**page).clone());
        }
        let mut pages = self.backend.read_pages(
            &self.opened.session_id,
            &self.opened.snapshot_cid,
            &[page_number],
        )?;
        if pages.len() != 1 || pages[0].len() != self.opened.page_size as usize {
            return Err(SqliteError::Storage(
                "agent returned an invalid page batch".into(),
            ));
        }
        let page = pages.remove(0);
        self.cache_insert(page_number, page.clone());
        Ok(page)
    }

    fn cache_insert(&mut self, page_number: u32, page: Vec<u8>) {
        while self.cache_bytes.saturating_add(page.len()) > CACHE_BYTES {
            let Some(oldest) = self.cache_order.pop_front() else {
                break;
            };
            if let Some(removed) = self.cache.remove(&oldest) {
                self.cache_bytes = self.cache_bytes.saturating_sub(removed.len());
            }
        }
        self.cache_bytes = self.cache_bytes.saturating_add(page.len());
        self.cache_order.push_back(page_number);
        self.cache.insert(page_number, Arc::new(page));
    }

    fn read(&mut self, output: &mut [u8], offset: u64) -> Result<bool, SqliteError> {
        output.fill(0);
        let logical_size = self.logical_size();
        let available_end = offset.saturating_add(output.len() as u64).min(logical_size);
        if offset < available_end {
            let page_size = u64::from(self.opened.page_size);
            let first = offset / page_size + 1;
            let last = (available_end - 1) / page_size + 1;
            for number in first..=last {
                let page_number = u32::try_from(number)
                    .map_err(|_| SqliteError::Limit("SQLite page number".into()))?;
                let page = self.page(page_number)?;
                let page_start = (number - 1) * page_size;
                let start = page_start.max(offset);
                let end = page_start.saturating_add(page_size).min(available_end);
                output[(start - offset) as usize..(end - offset) as usize].copy_from_slice(
                    &page[(start - page_start) as usize..(end - page_start) as usize],
                );
            }
        }
        for write in &self.writes {
            let start = write.offset.max(offset);
            let end = write
                .offset
                .saturating_add(write.bytes.len() as u64)
                .min(offset.saturating_add(output.len() as u64));
            if start < end {
                output[(start - offset) as usize..(end - offset) as usize].copy_from_slice(
                    &write.bytes[(start - write.offset) as usize..(end - write.offset) as usize],
                );
            }
        }
        Ok(offset.saturating_add(output.len() as u64) > logical_size)
    }

    fn begin(&mut self) -> Result<(), SqliteError> {
        if self.in_batch || !self.opened.writable || self.ticket.is_none() {
            return Err(SqliteError::Fenced);
        }
        self.writes.clear();
        self.truncate_size = None;
        self.in_batch = true;
        self.implicit_batch = false;
        Ok(())
    }

    fn commit(&mut self) -> Result<(), SqliteError> {
        if !self.in_batch {
            return Err(SqliteError::Invalid("atomic batch is not active".into()));
        }
        let ticket = self.ticket.clone().ok_or(SqliteError::Fenced)?;
        let page_size = u64::from(self.opened.page_size);
        let logical_size = self.logical_size();
        if logical_size % page_size != 0 {
            return Err(SqliteError::Invalid(
                "SQLite file size is not page-aligned".into(),
            ));
        }
        let final_count = u32::try_from(logical_size / page_size)
            .map_err(|_| SqliteError::Limit("SQLite page count".into()))?;
        let mut affected = BTreeSet::new();
        for write in &self.writes {
            if write.bytes.is_empty() {
                continue;
            }
            let first = write.offset / page_size + 1;
            let last = (write.offset + write.bytes.len() as u64 - 1) / page_size + 1;
            for number in first..=last {
                let number = u32::try_from(number)
                    .map_err(|_| SqliteError::Limit("SQLite page number".into()))?;
                if number <= final_count {
                    affected.insert(number);
                }
            }
        }
        let mut pages = BTreeMap::new();
        for number in affected {
            pages.insert(number, self.page(number)?);
        }
        for write in &self.writes {
            let write_start = write.offset;
            let write_end = write_start.saturating_add(write.bytes.len() as u64);
            for (number, page) in &mut pages {
                let page_start = (u64::from(*number) - 1) * page_size;
                let start = page_start.max(write_start);
                let end = page_start.saturating_add(page_size).min(write_end);
                if start < end {
                    page[(start - page_start) as usize..(end - page_start) as usize]
                        .copy_from_slice(
                            &write.bytes
                                [(start - write_start) as usize..(end - write_start) as usize],
                        );
                }
            }
        }
        self.commit_sequence = self.commit_sequence.saturating_add(1);
        let idempotency_key = format!("{}-{}", self.opened.session_id, self.commit_sequence);
        let opened = self.backend.commit(
            &self.opened.session_id,
            &idempotency_key,
            &ticket,
            &self.opened.snapshot_cid,
            self.opened.generation,
            pages
                .into_iter()
                .map(|(page_number, bytes)| DirtyPage { page_number, bytes })
                .collect(),
            logical_size,
        )?;
        self.opened = opened;
        self.ticket = None;
        self.writes.clear();
        self.truncate_size = None;
        self.in_batch = false;
        self.implicit_batch = false;
        self.cache.clear();
        self.cache_order.clear();
        self.cache_bytes = 0;
        Ok(())
    }

    fn rollback(&mut self) {
        self.writes.clear();
        self.truncate_size = None;
        self.in_batch = false;
        self.implicit_batch = false;
    }
}

fn backend() -> Result<Arc<dyn PepperVfsBackend>, SqliteError> {
    BACKEND
        .get()
        .and_then(|slot| slot.lock().ok()?.clone())
        .ok_or_else(|| SqliteError::Storage("Pepper VFS is not configured".into()))
}

fn status(error: &SqliteError) -> c_int {
    SqliteStatusCode::from_error(error).extended
}

fn ffi(operation: impl FnOnce() -> Result<c_int, SqliteError>) -> c_int {
    match catch_unwind(AssertUnwindSafe(operation)).unwrap_or(Err(SqliteError::Storage(
        "panic in Pepper VFS callback".into(),
    ))) {
        Ok(code) => code,
        Err(error) => {
            if let Ok(mut last) = LAST_ERROR.get_or_init(|| Mutex::new(String::new())).lock() {
                *last = error.to_string();
            }
            #[cfg(test)]
            eprintln!("Pepper VFS callback error: {error}");
            status(&error)
        }
    }
}

unsafe fn file_mut<'a>(file: *mut c_void) -> Result<&'a mut RemoteFile, SqliteError> {
    if file.is_null() {
        return Err(SqliteError::Invalid("null Pepper VFS file".into()));
    }
    // SAFETY: pointers originate exclusively from Box::into_raw below and C
    // serializes calls for one sqlite3_file handle.
    Ok(unsafe { &mut *(file.cast::<RemoteFile>()) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pepper_rust_open(
    name: *const c_char,
    flags: c_int,
    out: *mut *mut c_void,
) -> c_int {
    ffi(|| {
        if let Ok(mut last) = LAST_ERROR.get_or_init(|| Mutex::new(String::new())).lock() {
            last.clear();
        }
        if name.is_null() || out.is_null() {
            return Err(SqliteError::Invalid("null SQLite open argument".into()));
        }
        // SAFETY: SQLite guarantees a NUL-terminated filename for xOpen.
        let name = unsafe { CStr::from_ptr(name) }
            .to_str()
            .map_err(|_| SqliteError::Invalid("SQLite filename is not UTF-8".into()))?;
        let name = name.strip_prefix("file:").unwrap_or(name);
        let uri = PepperDatabaseUri::parse(name)?;
        let wants_write = flags & libsqlite3_sys::SQLITE_OPEN_READWRITE != 0;
        if wants_write && matches!(uri.mode, pepper_sqlite::SqliteOpenMode::ReadOnly) {
            return Err(SqliteError::Invalid(
                "read-only Pepper URI opened writable".into(),
            ));
        }
        let backend = backend()?;
        let opened = backend.open(&uri)?;
        if opened.database != uri.database || (wants_write && !opened.writable) {
            return Err(SqliteError::Storage(
                "agent open response does not match URI".into(),
            ));
        }
        let file = Box::new(RemoteFile {
            backend,
            uri,
            opened,
            ticket: None,
            in_batch: false,
            implicit_batch: false,
            writes: Vec::new(),
            truncate_size: None,
            cache: HashMap::new(),
            cache_order: VecDeque::new(),
            cache_bytes: 0,
            commit_sequence: 0,
        });
        // SAFETY: out was checked and ownership transfers to pepper_rust_close.
        unsafe { *out = Box::into_raw(file).cast() };
        Ok(libsqlite3_sys::SQLITE_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pepper_rust_close(file: *mut c_void) -> c_int {
    ffi(|| {
        if file.is_null() {
            return Err(SqliteError::Invalid("null Pepper VFS file".into()));
        }
        // SAFETY: C calls xClose exactly once for a successfully opened file.
        let mut file = unsafe { Box::from_raw(file.cast::<RemoteFile>()) };
        if let Some(ticket) = file.ticket.take() {
            let _ = file
                .backend
                .release_writer(&file.opened.session_id, &ticket);
        }
        file.backend.close(&file.opened.session_id)?;
        Ok(libsqlite3_sys::SQLITE_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pepper_rust_read(
    file: *mut c_void,
    buffer: *mut c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    ffi(|| {
        if buffer.is_null() || amount < 0 || offset < 0 {
            return Err(SqliteError::Invalid("invalid SQLite read argument".into()));
        }
        let file = unsafe { file_mut(file)? };
        // SAFETY: SQLite supplies a writable buffer of exactly amount bytes.
        let output =
            unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), amount as usize) };
        if file.read(output, offset as u64)? {
            Ok(libsqlite3_sys::SQLITE_IOERR_SHORT_READ)
        } else {
            Ok(libsqlite3_sys::SQLITE_OK)
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pepper_rust_write(
    file: *mut c_void,
    buffer: *const c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    ffi(|| {
        if buffer.is_null() || amount < 0 || offset < 0 {
            return Err(SqliteError::Invalid("invalid SQLite write argument".into()));
        }
        let file = unsafe { file_mut(file)? };
        if !file.in_batch {
            if !file.opened.writable || file.ticket.is_none() {
                return Err(SqliteError::Unsupported(
                    "write outside atomic batch".into(),
                ));
            }
            file.in_batch = true;
            file.implicit_batch = true;
            file.writes.clear();
            file.truncate_size = None;
        }
        // SAFETY: SQLite supplies a readable buffer of exactly amount bytes.
        let bytes = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), amount as usize) };
        file.writes.push(Segment {
            offset: offset as u64,
            bytes: bytes.to_vec(),
        });
        Ok(libsqlite3_sys::SQLITE_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pepper_rust_sync(file: *mut c_void) -> c_int {
    ffi(|| {
        let file = unsafe { file_mut(file)? };
        if file.in_batch && file.implicit_batch {
            file.commit()?;
        }
        Ok(libsqlite3_sys::SQLITE_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pepper_rust_truncate(file: *mut c_void, size: i64) -> c_int {
    ffi(|| {
        let file = unsafe { file_mut(file)? };
        if !file.in_batch || size < 0 {
            return Err(SqliteError::Unsupported(
                "truncate outside atomic batch".into(),
            ));
        }
        file.truncate_size = Some(size as u64);
        Ok(libsqlite3_sys::SQLITE_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pepper_rust_file_size(file: *mut c_void, size: *mut i64) -> c_int {
    ffi(|| {
        if size.is_null() {
            return Err(SqliteError::Invalid("null SQLite file-size output".into()));
        }
        let file = unsafe { file_mut(file)? };
        let value = i64::try_from(file.logical_size())
            .map_err(|_| SqliteError::Limit("SQLite file size".into()))?;
        // SAFETY: output pointer was checked.
        unsafe { *size = value };
        Ok(libsqlite3_sys::SQLITE_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pepper_rust_lock(file: *mut c_void, level: c_int) -> c_int {
    ffi(|| {
        let file = unsafe { file_mut(file)? };
        if level >= libsqlite3_sys::SQLITE_LOCK_RESERVED && file.ticket.is_none() {
            file.ticket = Some(file.backend.acquire_writer(
                &file.opened.session_id,
                &file.opened.database,
                &file.opened.snapshot_cid,
                file.opened.generation,
                file.uri.busy_timeout_millis,
            )?);
        }
        Ok(libsqlite3_sys::SQLITE_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pepper_rust_unlock(file: *mut c_void, level: c_int) -> c_int {
    ffi(|| {
        let file = unsafe { file_mut(file)? };
        if level == libsqlite3_sys::SQLITE_LOCK_NONE && !file.in_batch {
            if let Some(ticket) = file.ticket.take() {
                file.backend
                    .release_writer(&file.opened.session_id, &ticket)?;
            }
        }
        Ok(libsqlite3_sys::SQLITE_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pepper_rust_file_control(file: *mut c_void, operation: c_int) -> c_int {
    ffi(|| {
        let file = unsafe { file_mut(file)? };
        match operation {
            libsqlite3_sys::SQLITE_FCNTL_BEGIN_ATOMIC_WRITE => file.begin()?,
            libsqlite3_sys::SQLITE_FCNTL_COMMIT_ATOMIC_WRITE => file.commit()?,
            libsqlite3_sys::SQLITE_FCNTL_ROLLBACK_ATOMIC_WRITE => file.rollback(),
            libsqlite3_sys::SQLITE_FCNTL_MMAP_SIZE => {
                return Err(SqliteError::Unsupported("SQLite mmap is disabled".into()));
            }
            _ => return Ok(libsqlite3_sys::SQLITE_NOTFOUND),
        }
        Ok(libsqlite3_sys::SQLITE_OK)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_types::CODEC_SQLITE_SNAPSHOT;
    use rusqlite::{Connection, OpenFlags};

    #[derive(Default)]
    struct State {
        bytes: Vec<u8>,
        snapshot: Option<Cid>,
        generation: u64,
        ticket: Option<WriterTicket>,
        commits: u64,
        renewals: u64,
        short_leases: bool,
    }

    #[derive(Default)]
    struct MockBackend(Mutex<State>);

    impl MockBackend {
        fn opened(state: &State, writable: bool) -> BackendOpen {
            BackendOpen {
                session_id: "session".into(),
                database: "test".into(),
                snapshot_cid: state
                    .snapshot
                    .clone()
                    .unwrap_or_else(|| Cid::new(CODEC_SQLITE_SNAPSHOT, b"empty")),
                generation: state.generation,
                page_size: 4096,
                page_count: (state.bytes.len() / 4096) as u32,
                writable,
            }
        }
    }

    impl PepperVfsBackend for MockBackend {
        fn open(&self, uri: &PepperDatabaseUri) -> Result<BackendOpen, SqliteError> {
            Ok(Self::opened(
                &self.0.lock().unwrap(),
                !matches!(uri.mode, pepper_sqlite::SqliteOpenMode::ReadOnly),
            ))
        }

        fn close(&self, _session_id: &str) -> Result<(), SqliteError> {
            Ok(())
        }

        fn read_pages(
            &self,
            _session_id: &str,
            snapshot: &Cid,
            page_numbers: &[u32],
        ) -> Result<Vec<Vec<u8>>, SqliteError> {
            let state = self.0.lock().unwrap();
            if state.snapshot.as_ref() != Some(snapshot) {
                return Err(SqliteError::Fenced);
            }
            page_numbers
                .iter()
                .map(|number| {
                    let start = (*number as usize - 1) * 4096;
                    state
                        .bytes
                        .get(start..start + 4096)
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| SqliteError::Storage("missing mock page".into()))
                })
                .collect()
        }

        fn acquire_writer(
            &self,
            session_id: &str,
            _database: &str,
            base_snapshot: &Cid,
            base_generation: u64,
            _busy_timeout_millis: u64,
        ) -> Result<WriterTicket, SqliteError> {
            let mut state = self.0.lock().unwrap();
            let opened = Self::opened(&state, true);
            if state.ticket.is_some()
                || &opened.snapshot_cid != base_snapshot
                || opened.generation != base_generation
            {
                return Err(SqliteError::Busy);
            }
            let ticket = WriterTicket {
                ticket_id: format!("ticket-{}", state.generation),
                acquisition_id: format!("acquire-{}", state.generation),
                database: "test".into(),
                holder: session_id.into(),
                base_snapshot_cid: base_snapshot.clone(),
                base_generation,
                leader_term: 1,
                lease_epoch: 1,
                expires_at_millis: if state.short_leases {
                    unix_millis().saturating_add(100)
                } else {
                    u64::MAX
                },
            };
            state.ticket = Some(ticket.clone());
            Ok(ticket)
        }

        fn release_writer(
            &self,
            _session_id: &str,
            ticket: &WriterTicket,
        ) -> Result<(), SqliteError> {
            let mut state = self.0.lock().unwrap();
            if state.ticket.as_ref() == Some(ticket) {
                state.ticket = None;
                Ok(())
            } else {
                Err(SqliteError::Fenced)
            }
        }

        fn renew_writer(
            &self,
            _session_id: &str,
            ticket: &WriterTicket,
        ) -> Result<WriterTicket, SqliteError> {
            let mut state = self.0.lock().unwrap();
            if state.ticket.as_ref() != Some(ticket) {
                return Err(SqliteError::Fenced);
            }
            let mut renewed = ticket.clone();
            renewed.lease_epoch = renewed.lease_epoch.saturating_add(1);
            renewed.expires_at_millis = if state.short_leases {
                unix_millis().saturating_add(10_000)
            } else {
                u64::MAX
            };
            state.renewals = state.renewals.saturating_add(1);
            state.ticket = Some(renewed.clone());
            Ok(renewed)
        }

        fn commit(
            &self,
            _session_id: &str,
            _idempotency_key: &str,
            ticket: &WriterTicket,
            base_snapshot: &Cid,
            base_generation: u64,
            dirty_pages: Vec<DirtyPage>,
            new_logical_size: u64,
        ) -> Result<BackendOpen, SqliteError> {
            let mut state = self.0.lock().unwrap();
            if state.ticket.as_ref() != Some(ticket)
                || ticket.base_snapshot_cid != *base_snapshot
                || ticket.base_generation != base_generation
            {
                return Err(SqliteError::Fenced);
            }
            state.bytes.resize(new_logical_size as usize, 0);
            for page in dirty_pages {
                let start = (page.page_number as usize - 1) * 4096;
                state.bytes[start..start + 4096].copy_from_slice(&page.bytes);
            }
            state.commits += 1;
            state.generation += 1;
            state.snapshot = Some(Cid::new(CODEC_SQLITE_SNAPSHOT, &state.bytes));
            state.ticket = None;
            Ok(Self::opened(&state, true))
        }
    }

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn worker_heartbeats_and_uses_the_renewed_ticket() {
        let backend = Arc::new(MockBackend::default());
        backend.0.lock().unwrap().short_leases = true;
        let worker = WorkerBackend::new(backend.clone()).unwrap();
        let snapshot = Cid::new(CODEC_SQLITE_SNAPSHOT, b"empty");
        let original = worker
            .acquire_writer("session", "test", &snapshot, 0, 0)
            .unwrap();
        std::thread::sleep(Duration::from_millis(400));
        worker.release_writer("session", &original).unwrap();
        assert!(backend.0.lock().unwrap().renewals >= 1);
    }

    #[test]
    fn upstream_sqlite_transactions_run_through_page_overlay() {
        let _guard = TEST_LOCK.lock().unwrap();
        let backend = Arc::new(MockBackend::default());
        register_pepper_vfs(backend.clone()).unwrap();
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_URI;
        let mut connection =
            Connection::open_with_flags("file:pepper%3Atest?mode=rwc&vfs=pepper", flags).unwrap();
        connection
            .execute_batch(
                "PRAGMA page_size=4096; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; \
                 CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT NOT NULL); \
                 CREATE INDEX records_value ON records(value); \
                 CREATE TRIGGER records_no_empty BEFORE INSERT ON records \
                 WHEN new.value='' BEGIN SELECT RAISE(ABORT, 'empty'); END;",
            )
            .unwrap();
        {
            let transaction = connection.transaction().unwrap();
            transaction
                .execute("INSERT INTO records(value) VALUES ('committed')", [])
                .unwrap();
            assert_eq!(
                transaction
                    .query_row("SELECT count(*) FROM records", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                1
            );
            transaction.commit().unwrap();
        }
        {
            let transaction = connection.transaction().unwrap();
            transaction
                .execute("INSERT INTO records(value) VALUES ('rolled-back')", [])
                .unwrap();
            transaction.rollback().unwrap();
        }
        assert_eq!(
            connection
                .query_row("SELECT value FROM records", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "committed"
        );
        drop(connection);
        assert!(backend.0.lock().unwrap().commits >= 2);
        unregister_pepper_vfs().unwrap();
    }
}
