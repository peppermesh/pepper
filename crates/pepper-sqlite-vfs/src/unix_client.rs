// SPDX-License-Identifier: Apache-2.0

use crate::{BackendOpen, PepperVfsBackend};
use pepper_sqlite::{
    DirtyPage, PepperDatabaseUri, SqliteError, WriterTicket,
    contract::{
        FEATURE_BATCH_ATOMIC, FEATURE_COMMIT_STATUS, FEATURE_PAGE_READS, FEATURE_WRITER_FENCING,
    },
    protocol::{
        ClientHello, LocalFrame, LocalMessage, LocalProtocolLimits, LocalRequest, LocalResponse,
        frame_body_lengths,
    },
};
use pepper_types::Cid;
use std::{
    collections::{BTreeSet, HashMap},
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

pub struct UnixSocketBackend {
    path: PathBuf,
    timeout: Duration,
    next_request: AtomicU64,
    sessions: Mutex<HashMap<String, BackendOpen>>,
}

impl UnixSocketBackend {
    pub fn new(path: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            path: path.into(),
            timeout,
            next_request: AtomicU64::new(1),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.path
    }

    fn connect(&self) -> Result<UnixStream, SqliteError> {
        let mut stream = UnixStream::connect(&self.path)
            .map_err(|error| SqliteError::Storage(error.to_string()))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|_| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|error| SqliteError::Storage(error.to_string()))?;
        let hello = LocalRequest::Hello {
            hello: ClientHello {
                minimum_version: 1,
                maximum_version: 1,
                client_instance_id: format!("process-{}", std::process::id()),
                requested_features: [
                    FEATURE_BATCH_ATOMIC,
                    FEATURE_PAGE_READS,
                    FEATURE_WRITER_FENCING,
                    FEATURE_COMMIT_STATUS,
                ]
                .into_iter()
                .map(str::to_string)
                .collect::<BTreeSet<_>>(),
            },
        };
        let response = self.exchange(&mut stream, hello, Vec::new())?;
        if !matches!(
            response.message,
            LocalMessage::Response(LocalResponse::Hello { .. })
        ) {
            return Err(SqliteError::Storage("invalid agent hello response".into()));
        }
        Ok(stream)
    }

    fn exchange(
        &self,
        stream: &mut UnixStream,
        request: LocalRequest,
        payload: Vec<u8>,
    ) -> Result<LocalFrame, SqliteError> {
        let request_id = self.next_request.fetch_add(1, Ordering::Relaxed);
        let frame = LocalFrame {
            request_id,
            deadline_unix_millis: None,
            message: LocalMessage::Request(request),
            payload,
        };
        let encoded = frame.encode(LocalProtocolLimits::default())?;
        stream
            .write_all(&encoded)
            .map_err(|error| SqliteError::Storage(error.to_string()))?;
        let response = read_frame(stream)?;
        if response.request_id != request_id {
            return Err(SqliteError::Storage("agent response ID mismatch".into()));
        }
        if let LocalMessage::Response(LocalResponse::Error { code, message, .. }) =
            &response.message
        {
            return Err(match code.as_str() {
                "busy" => SqliteError::Busy,
                "busy_snapshot" | "fenced" => SqliteError::Fenced,
                "timeout" => SqliteError::Timeout,
                "ambiguous_commit" => SqliteError::AmbiguousCommit {
                    idempotency_key: message.clone(),
                },
                "unsupported" => SqliteError::Unsupported(message.clone()),
                _ => SqliteError::Storage(message.clone()),
            });
        }
        Ok(response)
    }
}

fn read_frame(stream: &mut UnixStream) -> Result<LocalFrame, SqliteError> {
    let mut prefix = [0u8; 16];
    stream
        .read_exact(&mut prefix)
        .map_err(|error| SqliteError::Storage(error.to_string()))?;
    let (header, payload) = frame_body_lengths(&prefix, LocalProtocolLimits::default())?;
    let total = 16usize
        .checked_add(header)
        .and_then(|value| value.checked_add(payload))
        .ok_or_else(|| SqliteError::Limit("local protocol frame".into()))?;
    let mut encoded = Vec::with_capacity(total);
    encoded.extend_from_slice(&prefix);
    encoded.resize(total, 0);
    stream
        .read_exact(&mut encoded[16..])
        .map_err(|error| SqliteError::Storage(error.to_string()))?;
    LocalFrame::decode(&encoded, LocalProtocolLimits::default())
}

impl PepperVfsBackend for UnixSocketBackend {
    fn open(&self, uri: &PepperDatabaseUri) -> Result<BackendOpen, SqliteError> {
        let mut stream = self.connect()?;
        let response = self.exchange(
            &mut stream,
            LocalRequest::Open {
                database: uri.database.clone(),
                mode: uri.mode.protocol_mode(),
                busy_timeout_millis: uri.busy_timeout_millis,
                snapshot: uri.snapshot.clone(),
            },
            Vec::new(),
        )?;
        let LocalMessage::Response(LocalResponse::Opened {
            session_id,
            database,
            snapshot,
            generation,
            page_size,
            page_count,
            writable,
        }) = response.message
        else {
            return Err(SqliteError::Storage("invalid agent open response".into()));
        };
        let opened = BackendOpen {
            session_id: session_id.clone(),
            database,
            snapshot_cid: snapshot,
            generation,
            page_size,
            page_count,
            writable,
        };
        self.sessions
            .lock()
            .map_err(|_| SqliteError::Storage("session lock poisoned".into()))?
            .insert(session_id, opened.clone());
        Ok(opened)
    }

    fn close(&self, session_id: &str) -> Result<(), SqliteError> {
        let mut stream = self.connect()?;
        let response = self.exchange(
            &mut stream,
            LocalRequest::Close {
                session_id: session_id.into(),
            },
            Vec::new(),
        )?;
        if !matches!(
            response.message,
            LocalMessage::Response(LocalResponse::Closed)
        ) {
            return Err(SqliteError::Storage("invalid agent close response".into()));
        }
        self.sessions
            .lock()
            .map_err(|_| SqliteError::Storage("session lock poisoned".into()))?
            .remove(session_id);
        Ok(())
    }

    fn read_pages(
        &self,
        session_id: &str,
        snapshot: &Cid,
        page_numbers: &[u32],
    ) -> Result<Vec<Vec<u8>>, SqliteError> {
        let mut stream = self.connect()?;
        let response = self.exchange(
            &mut stream,
            LocalRequest::ReadPages {
                session_id: session_id.into(),
                snapshot: snapshot.clone(),
                page_numbers: page_numbers.to_vec(),
            },
            Vec::new(),
        )?;
        let LocalMessage::Response(LocalResponse::Pages {
            snapshot: actual,
            pages,
        }) = response.message
        else {
            return Err(SqliteError::Storage("invalid agent page response".into()));
        };
        if actual != *snapshot || pages.len() != page_numbers.len() {
            return Err(SqliteError::Storage("agent page response mismatch".into()));
        }
        let mut result = Vec::with_capacity(pages.len());
        for (layout, expected_number) in pages.into_iter().zip(page_numbers) {
            if layout.page_number != *expected_number {
                return Err(SqliteError::Storage("agent page order mismatch".into()));
            }
            let start = layout.payload_offset as usize;
            let end = start
                .checked_add(layout.payload_length as usize)
                .filter(|end| *end <= response.payload.len())
                .ok_or_else(|| SqliteError::Storage("agent page layout exceeds payload".into()))?;
            let bytes = response.payload[start..end].to_vec();
            if blake3::hash(&bytes).to_hex().as_str() != layout.page_hash {
                return Err(SqliteError::Storage("agent page hash mismatch".into()));
            }
            result.push(bytes);
        }
        Ok(result)
    }

    fn acquire_writer(
        &self,
        session_id: &str,
        _database: &str,
        base_snapshot: &Cid,
        base_generation: u64,
        busy_timeout_millis: u64,
    ) -> Result<WriterTicket, SqliteError> {
        let mut stream = self.connect()?;
        let acquisition_id = format!(
            "{}-{}",
            session_id,
            self.next_request.load(Ordering::Relaxed)
        );
        let response = self.exchange(
            &mut stream,
            LocalRequest::AcquireWriter {
                session_id: session_id.into(),
                acquisition_id: acquisition_id.clone(),
                base_snapshot: base_snapshot.clone(),
                base_generation,
                wait_timeout_millis: busy_timeout_millis,
            },
            Vec::new(),
        )?;
        if let LocalMessage::Response(LocalResponse::Writer { ticket }) = &response.message {
            return Ok(ticket.clone());
        }
        if !matches!(
            response.message,
            LocalMessage::Response(LocalResponse::Queued { .. })
        ) {
            return Err(SqliteError::Storage("invalid agent writer response".into()));
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(busy_timeout_millis))
            .ok_or_else(|| SqliteError::Invalid("busy timeout overflow".into()))?;
        loop {
            if Instant::now() >= deadline {
                return Err(SqliteError::Busy);
            }
            std::thread::sleep(Duration::from_millis(10));
            let response = self.exchange(
                &mut stream,
                LocalRequest::WriterStatus {
                    session_id: session_id.into(),
                    acquisition_id: acquisition_id.clone(),
                },
                Vec::new(),
            )?;
            match response.message {
                LocalMessage::Response(LocalResponse::Writer { ticket }) => return Ok(ticket),
                LocalMessage::Response(LocalResponse::Queued { .. }) => {}
                _ => {
                    return Err(SqliteError::Storage(
                        "invalid agent writer status response".into(),
                    ));
                }
            }
        }
    }

    fn release_writer(&self, session_id: &str, ticket: &WriterTicket) -> Result<(), SqliteError> {
        let mut stream = self.connect()?;
        let response = self.exchange(
            &mut stream,
            LocalRequest::ReleaseWriter {
                session_id: session_id.into(),
                ticket: ticket.clone(),
            },
            Vec::new(),
        )?;
        if matches!(
            response.message,
            LocalMessage::Response(LocalResponse::Closed | LocalResponse::Aborted)
        ) {
            Ok(())
        } else {
            Err(SqliteError::Storage(
                "invalid agent release response".into(),
            ))
        }
    }

    fn renew_writer(
        &self,
        session_id: &str,
        ticket: &WriterTicket,
    ) -> Result<WriterTicket, SqliteError> {
        let mut stream = self.connect()?;
        let response = self.exchange(
            &mut stream,
            LocalRequest::RenewWriter {
                session_id: session_id.into(),
                ticket: ticket.clone(),
            },
            Vec::new(),
        )?;
        let LocalMessage::Response(LocalResponse::Writer { ticket }) = response.message else {
            return Err(SqliteError::Storage(
                "invalid agent renewal response".into(),
            ));
        };
        Ok(ticket)
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
        let mut stream = self.connect()?;
        let current = self
            .sessions
            .lock()
            .map_err(|_| SqliteError::Storage("session lock poisoned".into()))?
            .get(session_id)
            .cloned()
            .ok_or(SqliteError::Fenced)?;
        let transaction_id = format!("transaction-{idempotency_key}");
        let dirty_bytes = dirty_pages.iter().map(|page| page.bytes.len() as u64).sum();
        let response = self.exchange(
            &mut stream,
            LocalRequest::BeginCommit {
                session_id: session_id.into(),
                transaction_id: transaction_id.clone(),
                idempotency_key: idempotency_key.into(),
                ticket: ticket.clone(),
                base_snapshot: base_snapshot.clone(),
                base_generation,
                page_size: current.page_size,
                final_page_count: (new_logical_size / u64::from(current.page_size)) as u32,
                dirty_page_count: dirty_pages.len() as u32,
                dirty_bytes,
            },
            Vec::new(),
        )?;
        if !matches!(
            response.message,
            LocalMessage::Response(LocalResponse::CommitReady)
        ) {
            return Err(SqliteError::Storage("agent did not accept commit".into()));
        }
        for page in dirty_pages {
            let response = self.exchange(
                &mut stream,
                LocalRequest::CommitPage {
                    transaction_id: transaction_id.clone(),
                    page_number: page.page_number,
                    page_hash: blake3::hash(&page.bytes).to_hex().to_string(),
                },
                page.bytes,
            )?;
            if !matches!(
                response.message,
                LocalMessage::Response(LocalResponse::PageAccepted)
            ) {
                return Err(SqliteError::Storage("agent rejected commit page".into()));
            }
        }
        let commit = match self.exchange(
            &mut stream,
            LocalRequest::FinishCommit { transaction_id },
            Vec::new(),
        ) {
            Ok(LocalFrame {
                message: LocalMessage::Response(LocalResponse::Committed { commit }),
                ..
            }) => commit,
            _ => {
                // A transport failure after Finish may have lost only the
                // response. Resolve the replicated idempotency record through
                // a fresh connection before reporting a failed SQLite commit.
                let mut status_stream = self.connect()?;
                let status = self.exchange(
                    &mut status_stream,
                    LocalRequest::CommitStatus {
                        database: current.database.clone(),
                        idempotency_key: idempotency_key.into(),
                    },
                    Vec::new(),
                )?;
                let LocalMessage::Response(LocalResponse::Committed { commit }) = status.message
                else {
                    return Err(SqliteError::AmbiguousCommit {
                        idempotency_key: idempotency_key.into(),
                    });
                };
                commit
            }
        };
        let opened = BackendOpen {
            session_id: session_id.into(),
            database: current.database,
            snapshot_cid: commit.snapshot_cid,
            generation: commit.generation,
            page_size: current.page_size,
            page_count: (new_logical_size / u64::from(current.page_size)) as u32,
            writable: true,
        };
        self.sessions
            .lock()
            .map_err(|_| SqliteError::Storage("session lock poisoned".into()))?
            .insert(session_id.into(), opened.clone());
        Ok(opened)
    }
}
