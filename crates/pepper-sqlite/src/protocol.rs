// SPDX-License-Identifier: Apache-2.0

//! Transport-neutral framed local protocol between the synchronous SQLite VFS
//! and the Pepper agent. Unix-domain sockets are the v1 carrier.

use crate::{CommitRecord, SqliteError, WriterTicket};
use pepper_types::Cid;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const LOCAL_PROTOCOL_VERSION: u16 = 1;
const MAGIC: [u8; 4] = *b"PSQL";
const PREFIX_BYTES: usize = 16;

pub fn frame_body_lengths(
    prefix: &[u8; 16],
    limits: LocalProtocolLimits,
) -> Result<(usize, usize), SqliteError> {
    let limits = limits.validate()?;
    if prefix[..4] != MAGIC
        || u16::from_be_bytes([prefix[4], prefix[5]]) != LOCAL_PROTOCOL_VERSION
        || u16::from_be_bytes([prefix[6], prefix[7]]) != 0
    {
        return Err(SqliteError::Invalid("invalid local protocol prefix".into()));
    }
    let header = u32::from_be_bytes(prefix[8..12].try_into().expect("fixed prefix")) as usize;
    let payload = u32::from_be_bytes(prefix[12..16].try_into().expect("fixed prefix")) as usize;
    if header > limits.max_header_bytes || payload > limits.max_payload_bytes {
        return Err(SqliteError::Limit("local protocol frame".into()));
    }
    Ok((header, payload))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalProtocolLimits {
    pub max_header_bytes: usize,
    pub max_payload_bytes: usize,
}

impl Default for LocalProtocolLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: 1024 * 1024,
            max_payload_bytes: 64 * 1024 * 1024,
        }
    }
}

impl LocalProtocolLimits {
    pub fn validate(self) -> Result<Self, SqliteError> {
        if self.max_header_bytes == 0
            || self.max_header_bytes > u32::MAX as usize
            || self.max_payload_bytes == 0
            || self.max_payload_bytes > u32::MAX as usize
        {
            return Err(SqliteError::Invalid("invalid local protocol limits".into()));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenMode {
    ReadOnly,
    ReadWrite,
    Create,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientHello {
    pub minimum_version: u16,
    pub maximum_version: u16,
    pub client_instance_id: String,
    pub requested_features: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerHello {
    pub selected_version: u16,
    pub agent_identity: String,
    pub enabled_features: BTreeSet<String>,
    pub max_header_bytes: u32,
    pub max_payload_bytes: u32,
    pub max_read_pages: u32,
    pub max_dirty_pages: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PagePayloadLayout {
    pub page_number: u32,
    pub payload_offset: u32,
    pub payload_length: u32,
    pub page_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalRequest {
    Hello {
        hello: ClientHello,
    },
    Open {
        database: String,
        mode: OpenMode,
        busy_timeout_millis: u64,
        snapshot: Option<Cid>,
    },
    Close {
        session_id: String,
    },
    ReadPages {
        session_id: String,
        snapshot: Cid,
        page_numbers: Vec<u32>,
    },
    AcquireWriter {
        session_id: String,
        acquisition_id: String,
        base_snapshot: Cid,
        base_generation: u64,
        wait_timeout_millis: u64,
    },
    WriterStatus {
        session_id: String,
        acquisition_id: String,
    },
    RenewWriter {
        session_id: String,
        ticket: WriterTicket,
    },
    ReleaseWriter {
        session_id: String,
        ticket: WriterTicket,
    },
    BeginCommit {
        session_id: String,
        transaction_id: String,
        idempotency_key: String,
        ticket: WriterTicket,
        base_snapshot: Cid,
        base_generation: u64,
        page_size: u32,
        final_page_count: u32,
        dirty_page_count: u32,
        dirty_bytes: u64,
    },
    /// The frame payload contains exactly one final page image.
    CommitPage {
        transaction_id: String,
        page_number: u32,
        page_hash: String,
    },
    FinishCommit {
        transaction_id: String,
    },
    AbortCommit {
        transaction_id: String,
    },
    CommitStatus {
        database: String,
        idempotency_key: String,
    },
    Cancel {
        target_request_id: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalResponse {
    Hello {
        hello: ServerHello,
    },
    Opened {
        session_id: String,
        database: String,
        snapshot: Cid,
        generation: u64,
        page_size: u32,
        page_count: u32,
        writable: bool,
    },
    Closed,
    Pages {
        snapshot: Cid,
        pages: Vec<PagePayloadLayout>,
    },
    Writer {
        ticket: WriterTicket,
    },
    Queued {
        position: usize,
    },
    CommitReady,
    PageAccepted,
    Committed {
        commit: CommitRecord,
    },
    CommitPending,
    Aborted,
    Cancelled,
    Error {
        code: String,
        message: String,
        retryable: bool,
        current_snapshot: Option<Cid>,
        current_generation: Option<u64>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "direction", content = "body", rename_all = "snake_case")]
pub enum LocalMessage {
    Request(LocalRequest),
    Response(LocalResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FrameHeader {
    request_id: u64,
    deadline_unix_millis: Option<u64>,
    message: LocalMessage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFrame {
    pub request_id: u64,
    pub deadline_unix_millis: Option<u64>,
    pub message: LocalMessage,
    /// Raw page bytes. Its meaning and exact expected length are determined by
    /// the typed message; most messages require an empty payload.
    pub payload: Vec<u8>,
}

impl LocalFrame {
    pub fn encode(&self, limits: LocalProtocolLimits) -> Result<Vec<u8>, SqliteError> {
        let limits = limits.validate()?;
        validate_payload_contract(&self.message, &self.payload)?;
        let header = FrameHeader {
            request_id: self.request_id,
            deadline_unix_millis: self.deadline_unix_millis,
            message: self.message.clone(),
        };
        let header =
            serde_json::to_vec(&header).map_err(|error| SqliteError::Invalid(error.to_string()))?;
        if header.len() > limits.max_header_bytes || self.payload.len() > limits.max_payload_bytes {
            return Err(SqliteError::Limit("local protocol frame".into()));
        }
        let header_len = u32::try_from(header.len())
            .map_err(|_| SqliteError::Limit("local protocol header".into()))?;
        let payload_len = u32::try_from(self.payload.len())
            .map_err(|_| SqliteError::Limit("local protocol payload".into()))?;
        let mut out = Vec::with_capacity(PREFIX_BYTES + header.len() + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&LOCAL_PROTOCOL_VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&header_len.to_be_bytes());
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(encoded: &[u8], limits: LocalProtocolLimits) -> Result<Self, SqliteError> {
        let limits = limits.validate()?;
        if encoded.len() < PREFIX_BYTES || encoded[..4] != MAGIC {
            return Err(SqliteError::Invalid("invalid local protocol magic".into()));
        }
        let version = u16::from_be_bytes([encoded[4], encoded[5]]);
        let flags = u16::from_be_bytes([encoded[6], encoded[7]]);
        let header_len =
            u32::from_be_bytes(encoded[8..12].try_into().expect("fixed header slice")) as usize;
        let payload_len =
            u32::from_be_bytes(encoded[12..16].try_into().expect("fixed header slice")) as usize;
        if version != LOCAL_PROTOCOL_VERSION
            || flags != 0
            || header_len > limits.max_header_bytes
            || payload_len > limits.max_payload_bytes
            || PREFIX_BYTES
                .checked_add(header_len)
                .and_then(|size| size.checked_add(payload_len))
                != Some(encoded.len())
        {
            return Err(SqliteError::Invalid(
                "unsupported or malformed local protocol frame".into(),
            ));
        }
        let header_bytes = &encoded[PREFIX_BYTES..PREFIX_BYTES + header_len];
        let header: FrameHeader = serde_json::from_slice(header_bytes)
            .map_err(|error| SqliteError::Invalid(error.to_string()))?;
        if serde_json::to_vec(&header).map_err(|error| SqliteError::Invalid(error.to_string()))?
            != header_bytes
        {
            return Err(SqliteError::NonCanonical);
        }
        let payload = encoded[PREFIX_BYTES + header_len..].to_vec();
        validate_payload_contract(&header.message, &payload)?;
        Ok(Self {
            request_id: header.request_id,
            deadline_unix_millis: header.deadline_unix_millis,
            message: header.message,
            payload,
        })
    }
}

fn validate_payload_contract(message: &LocalMessage, payload: &[u8]) -> Result<(), SqliteError> {
    let expected = match message {
        LocalMessage::Request(LocalRequest::CommitPage { .. }) => true,
        LocalMessage::Response(LocalResponse::Pages { pages, .. }) => {
            let mut expected_offset = 0u32;
            for page in pages {
                if page.payload_offset != expected_offset || page.payload_length == 0 {
                    return Err(SqliteError::Invalid("invalid page payload layout".into()));
                }
                expected_offset = expected_offset
                    .checked_add(page.payload_length)
                    .ok_or_else(|| SqliteError::Invalid("page payload layout overflow".into()))?;
            }
            if usize::try_from(expected_offset).ok() != Some(payload.len()) {
                return Err(SqliteError::Invalid(
                    "page payload length does not match layout".into(),
                ));
            }
            return Ok(());
        }
        _ => false,
    };
    if expected == payload.is_empty() {
        return Err(SqliteError::Invalid(
            "message has an unexpected local protocol payload".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_types::{CODEC_SQLITE_SNAPSHOT, Cid};

    #[test]
    fn canonical_frame_roundtrips_with_raw_page_payload() {
        let page = vec![7u8; 4096];
        let frame = LocalFrame {
            request_id: 42,
            deadline_unix_millis: Some(1000),
            message: LocalMessage::Request(LocalRequest::CommitPage {
                transaction_id: "txn".into(),
                page_number: 1,
                page_hash: "07".repeat(32),
            }),
            payload: page,
        };
        let encoded = frame.encode(LocalProtocolLimits::default()).unwrap();
        assert_eq!(
            LocalFrame::decode(&encoded, LocalProtocolLimits::default()).unwrap(),
            frame
        );
    }

    #[test]
    fn page_batch_layout_must_exactly_cover_payload() {
        let snapshot = Cid::new(CODEC_SQLITE_SNAPSHOT, b"snapshot");
        let frame = LocalFrame {
            request_id: 7,
            deadline_unix_millis: None,
            message: LocalMessage::Response(LocalResponse::Pages {
                snapshot,
                pages: vec![PagePayloadLayout {
                    page_number: 1,
                    payload_offset: 0,
                    payload_length: 4096,
                    page_hash: "00".repeat(32),
                }],
            }),
            payload: vec![0; 4096],
        };
        let encoded = frame.encode(LocalProtocolLimits::default()).unwrap();
        assert_eq!(
            LocalFrame::decode(&encoded, LocalProtocolLimits::default()).unwrap(),
            frame
        );

        let mut invalid = frame;
        invalid.payload.pop();
        assert!(invalid.encode(LocalProtocolLimits::default()).is_err());
    }

    #[test]
    fn limits_version_flags_and_trailing_bytes_are_rejected() {
        let frame = LocalFrame {
            request_id: 1,
            deadline_unix_millis: None,
            message: LocalMessage::Request(LocalRequest::Cancel {
                target_request_id: 9,
            }),
            payload: Vec::new(),
        };
        let encoded = frame.encode(LocalProtocolLimits::default()).unwrap();
        let mut bad_version = encoded.clone();
        bad_version[5] = 2;
        assert!(LocalFrame::decode(&bad_version, LocalProtocolLimits::default()).is_err());
        let mut bad_flags = encoded.clone();
        bad_flags[7] = 1;
        assert!(LocalFrame::decode(&bad_flags, LocalProtocolLimits::default()).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(LocalFrame::decode(&trailing, LocalProtocolLimits::default()).is_err());
    }
}
