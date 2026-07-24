// SPDX-License-Identifier: Apache-2.0

//! Bounded Kafka client-protocol framing for Pepper.
//!
//! Schemas are generated from Apache Kafka message definitions by the
//! `kafka-protocol` crate. Pepper keeps a closed advertised version table and
//! adds stricter frame, nesting, and record-batch limits around those schemas.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use kafka_protocol::{
    messages::{ApiKey, RequestHeader, RequestKind, ResponseHeader, ResponseKind},
    protocol::{Decodable, Encodable, HeaderVersion},
};
use pepper_buffer::{BufferChain, OwnedBuffer};
use thiserror::Error;

pub use kafka_protocol;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolLimits {
    pub maximum_frame_bytes: usize,
    pub maximum_array_elements: usize,
    pub maximum_string_bytes: usize,
    pub maximum_record_batches: usize,
    pub maximum_records_per_batch: usize,
    pub maximum_headers_per_record: usize,
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            maximum_frame_bytes: 100 * 1024 * 1024,
            maximum_array_elements: 100_000,
            maximum_string_bytes: 32 * 1024,
            maximum_record_batches: 10_000,
            maximum_records_per_batch: 1_000_000,
            maximum_headers_per_record: 10_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiVersion {
    pub api_key: i16,
    pub minimum: i16,
    pub maximum: i16,
}

pub const ADVERTISED_APIS: &[ApiVersion] = &[
    ApiVersion {
        api_key: 0,
        minimum: 3,
        maximum: 3,
    },
    ApiVersion {
        api_key: 1,
        minimum: 4,
        maximum: 4,
    },
    ApiVersion {
        api_key: 2,
        minimum: 1,
        maximum: 1,
    },
    ApiVersion {
        api_key: 3,
        minimum: 1,
        maximum: 1,
    },
    ApiVersion {
        api_key: 8,
        minimum: 2,
        maximum: 2,
    },
    ApiVersion {
        api_key: 9,
        minimum: 1,
        maximum: 1,
    },
    ApiVersion {
        api_key: 10,
        minimum: 0,
        maximum: 1,
    },
    ApiVersion {
        api_key: 11,
        minimum: 0,
        maximum: 2,
    },
    ApiVersion {
        api_key: 12,
        minimum: 0,
        maximum: 1,
    },
    ApiVersion {
        api_key: 13,
        minimum: 0,
        maximum: 1,
    },
    ApiVersion {
        api_key: 14,
        minimum: 0,
        maximum: 1,
    },
    ApiVersion {
        api_key: 15,
        minimum: 0,
        maximum: 0,
    },
    ApiVersion {
        api_key: 16,
        minimum: 0,
        maximum: 0,
    },
    ApiVersion {
        api_key: 17,
        minimum: 0,
        maximum: 1,
    },
    ApiVersion {
        api_key: 18,
        minimum: 0,
        maximum: 3,
    },
    ApiVersion {
        api_key: 19,
        minimum: 0,
        maximum: 2,
    },
    ApiVersion {
        api_key: 20,
        minimum: 0,
        maximum: 1,
    },
    ApiVersion {
        api_key: 22,
        minimum: 0,
        maximum: 0,
    },
    ApiVersion {
        api_key: 24,
        minimum: 0,
        maximum: 0,
    },
    ApiVersion {
        api_key: 25,
        minimum: 0,
        maximum: 0,
    },
    ApiVersion {
        api_key: 26,
        minimum: 0,
        maximum: 0,
    },
    ApiVersion {
        api_key: 28,
        minimum: 0,
        maximum: 0,
    },
    ApiVersion {
        api_key: 32,
        minimum: 0,
        maximum: 1,
    },
    ApiVersion {
        api_key: 33,
        minimum: 0,
        maximum: 0,
    },
    ApiVersion {
        api_key: 36,
        minimum: 0,
        maximum: 0,
    },
    ApiVersion {
        api_key: 60,
        minimum: 0,
        maximum: 0,
    },
];

pub fn supported_version(api_key: i16, version: i16) -> bool {
    ADVERTISED_APIS
        .iter()
        .any(|api| api.api_key == api_key && (api.minimum..=api.maximum).contains(&version))
        // kafka-python-ng pipelines this legacy probe with ApiVersions v0
        // before it has consumed the advertised table. Accept it without
        // claiming it as part of Pepper's supported surface.
        || (api_key == ApiKey::Metadata as i16 && version == 0)
}

pub struct FrameDecoder {
    limits: ProtocolLimits,
    buffered: BytesMut,
}

impl FrameDecoder {
    pub fn new(limits: ProtocolLimits) -> Self {
        Self {
            limits,
            buffered: BytesMut::new(),
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Bytes>, ProtocolError> {
        if self.buffered.len().saturating_add(bytes.len())
            > self.limits.maximum_frame_bytes.saturating_add(4)
        {
            return Err(ProtocolError::FrameTooLarge(
                self.buffered.len().saturating_add(bytes.len()),
            ));
        }
        self.buffered.extend_from_slice(bytes);
        let mut frames = Vec::new();
        loop {
            if self.buffered.len() < 4 {
                break;
            }
            let length = i32::from_be_bytes(self.buffered[..4].try_into().expect("fixed"));
            if length < 0 {
                return Err(ProtocolError::NegativeFrameLength(length));
            }
            let length = length as usize;
            if length > self.limits.maximum_frame_bytes {
                return Err(ProtocolError::FrameTooLarge(length));
            }
            if self.buffered.len() < length + 4 {
                break;
            }
            self.buffered.advance(4);
            frames.push(self.buffered.split_to(length).freeze());
        }
        Ok(frames)
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered.len()
    }
}

#[derive(Debug)]
pub struct DecodedRequest {
    pub header: RequestHeader,
    pub api_key: ApiKey,
    pub body: RequestKind,
}

pub fn decode_request(
    mut frame: Bytes,
    limits: ProtocolLimits,
) -> Result<DecodedRequest, ProtocolError> {
    if frame.len() > limits.maximum_frame_bytes {
        return Err(ProtocolError::FrameTooLarge(frame.len()));
    }
    if frame.len() < 8 {
        return Err(ProtocolError::Malformed(
            "request header is truncated".into(),
        ));
    }
    let api_key_number = i16::from_be_bytes(frame[..2].try_into().expect("fixed"));
    let version = i16::from_be_bytes(frame[2..4].try_into().expect("fixed"));
    let api_key =
        ApiKey::try_from(api_key_number).map_err(|_| ProtocolError::UnknownApi(api_key_number))?;
    if !supported_version(api_key_number, version) {
        return Err(ProtocolError::UnsupportedVersion {
            api_key: api_key_number,
            version,
            correlation_id: i32::from_be_bytes(frame[4..8].try_into().expect("fixed")),
        });
    }
    let header = RequestHeader::decode(&mut frame, api_key.request_header_version(version))
        .map_err(|error| ProtocolError::Malformed(error.to_string()))?;
    if header
        .client_id
        .as_ref()
        .is_some_and(|client| client.len() > limits.maximum_string_bytes)
    {
        return Err(ProtocolError::Limit("client ID"));
    }
    preflight_request_body(api_key, version, &frame, limits)?;
    let body = RequestKind::decode(api_key, &mut frame, version)
        .map_err(|error| ProtocolError::Malformed(error.to_string()))?;
    if frame.has_remaining() {
        return Err(ProtocolError::TrailingBytes(frame.remaining()));
    }
    validate_request_limits(&body, limits)?;
    Ok(DecodedRequest {
        header,
        api_key,
        body,
    })
}

fn preflight_request_body(
    api_key: ApiKey,
    version: i16,
    body: &Bytes,
    limits: ProtocolLimits,
) -> Result<(), ProtocolError> {
    let mut scan = WireScan::new(body, limits);
    match api_key {
        ApiKey::Produce => {
            scan.nullable_string()?;
            scan.skip(6)?;
            let topics = scan.array(false)?;
            for _ in 0..topics {
                scan.string()?;
                let partitions = scan.array(false)?;
                for _ in 0..partitions {
                    scan.skip(4)?;
                    scan.nullable_bytes()?;
                }
            }
        }
        ApiKey::Fetch => {
            scan.skip(17)?;
            let topics = scan.array(false)?;
            for _ in 0..topics {
                scan.string()?;
                let partitions = scan.array(false)?;
                for _ in 0..partitions {
                    scan.skip(16)?;
                }
            }
        }
        ApiKey::ListOffsets => {
            scan.skip(4)?;
            let topics = scan.array(false)?;
            for _ in 0..topics {
                scan.string()?;
                let partitions = scan.array(false)?;
                for _ in 0..partitions {
                    scan.skip(12)?;
                }
            }
        }
        ApiKey::Metadata => {
            let topics = scan.array(true)?;
            for _ in 0..topics {
                scan.string()?;
            }
        }
        ApiKey::OffsetCommit => {
            scan.string()?;
            scan.skip(4)?;
            scan.string()?;
            scan.skip(8)?;
            let topics = scan.array(false)?;
            for _ in 0..topics {
                scan.string()?;
                let partitions = scan.array(false)?;
                for _ in 0..partitions {
                    scan.skip(12)?;
                    scan.nullable_string()?;
                }
            }
        }
        ApiKey::OffsetFetch => {
            scan.string()?;
            let topics = scan.array(true)?;
            for _ in 0..topics {
                scan.string()?;
                let partitions = scan.array(false)?;
                scan.skip(
                    partitions
                        .checked_mul(4)
                        .ok_or_else(|| malformed("partition array length overflow"))?,
                )?;
            }
        }
        ApiKey::FindCoordinator => {
            scan.string()?;
            if version >= 1 {
                scan.skip(1)?;
            }
        }
        ApiKey::JoinGroup => {
            scan.string()?;
            scan.skip(4)?;
            if version >= 1 {
                scan.skip(4)?;
            }
            scan.string()?;
            scan.string()?;
            let protocols = scan.array(false)?;
            for _ in 0..protocols {
                scan.string()?;
                scan.bytes()?;
            }
        }
        ApiKey::Heartbeat => {
            scan.string()?;
            scan.skip(4)?;
            scan.string()?;
        }
        ApiKey::LeaveGroup => {
            scan.string()?;
            scan.string()?;
        }
        ApiKey::SyncGroup => {
            scan.string()?;
            scan.skip(4)?;
            scan.string()?;
            let assignments = scan.array(false)?;
            for _ in 0..assignments {
                scan.string()?;
                scan.bytes()?;
            }
        }
        ApiKey::DescribeGroups => {
            let groups = scan.array(false)?;
            for _ in 0..groups {
                scan.string()?;
            }
        }
        ApiKey::ListGroups => {}
        ApiKey::SaslHandshake => {
            scan.string()?;
        }
        ApiKey::SaslAuthenticate => {
            scan.bytes()?;
        }
        ApiKey::InitProducerId => {
            scan.nullable_string()?;
            scan.skip(4)?;
        }
        ApiKey::AddPartitionsToTxn => {
            scan.string()?;
            scan.skip(10)?;
            let topics = scan.array(false)?;
            for _ in 0..topics {
                scan.string()?;
                let partitions = scan.array(false)?;
                scan.skip(
                    partitions
                        .checked_mul(4)
                        .ok_or_else(|| malformed("partition array length overflow"))?,
                )?;
            }
        }
        ApiKey::AddOffsetsToTxn => {
            scan.string()?;
            scan.skip(10)?;
            scan.string()?;
        }
        ApiKey::EndTxn => {
            scan.string()?;
            scan.skip(11)?;
        }
        ApiKey::TxnOffsetCommit => {
            scan.string()?;
            scan.string()?;
            scan.skip(10)?;
            let topics = scan.array(false)?;
            for _ in 0..topics {
                scan.string()?;
                let partitions = scan.array(false)?;
                for _ in 0..partitions {
                    scan.skip(12)?;
                    scan.nullable_string()?;
                }
            }
        }
        ApiKey::ApiVersions if version >= 3 => {
            scan.compact_string()?;
            scan.compact_string()?;
            scan.tagged_fields()?;
        }
        ApiKey::ApiVersions => {}
        ApiKey::CreateTopics => {
            let topics = scan.array(false)?;
            for _ in 0..topics {
                scan.string()?;
                scan.skip(6)?;
                let assignments = scan.array(false)?;
                for _ in 0..assignments {
                    scan.skip(4)?;
                    let brokers = scan.array(false)?;
                    scan.skip(
                        brokers
                            .checked_mul(4)
                            .ok_or_else(|| malformed("broker array length overflow"))?,
                    )?;
                }
                let configs = scan.array(false)?;
                for _ in 0..configs {
                    scan.string()?;
                    scan.nullable_string()?;
                }
            }
            scan.skip(4)?;
            if version >= 1 {
                scan.skip(1)?;
            }
        }
        ApiKey::DeleteTopics => {
            let topics = scan.array(false)?;
            for _ in 0..topics {
                scan.string()?;
            }
            scan.skip(4)?;
        }
        ApiKey::DescribeConfigs => {
            let resources = scan.array(false)?;
            for _ in 0..resources {
                scan.skip(1)?;
                scan.string()?;
                let keys = scan.array(true)?;
                for _ in 0..keys {
                    scan.string()?;
                }
            }
            if version >= 1 {
                scan.skip(1)?;
            }
        }
        ApiKey::AlterConfigs => {
            let resources = scan.array(false)?;
            for _ in 0..resources {
                scan.skip(1)?;
                scan.string()?;
                let configs = scan.array(false)?;
                for _ in 0..configs {
                    scan.string()?;
                    scan.nullable_string()?;
                }
            }
            scan.skip(1)?;
        }
        ApiKey::DescribeCluster => {
            scan.skip(1)?;
            scan.tagged_fields()?;
        }
        _ => {}
    }
    Ok(())
}

struct WireScan<'a> {
    bytes: &'a [u8],
    cursor: usize,
    limits: ProtocolLimits,
}

impl<'a> WireScan<'a> {
    fn new(bytes: &'a [u8], limits: ProtocolLimits) -> Self {
        Self {
            bytes,
            cursor: 0,
            limits,
        }
    }

    fn skip(&mut self, length: usize) -> Result<(), ProtocolError> {
        self.cursor = self
            .cursor
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| malformed("request field is truncated"))?;
        Ok(())
    }

    fn i16(&mut self) -> Result<i16, ProtocolError> {
        let value = self
            .bytes
            .get(self.cursor..self.cursor + 2)
            .ok_or_else(|| malformed("string length is truncated"))?;
        self.cursor += 2;
        Ok(i16::from_be_bytes(value.try_into().expect("fixed")))
    }

    fn i32(&mut self) -> Result<i32, ProtocolError> {
        let value = self
            .bytes
            .get(self.cursor..self.cursor + 4)
            .ok_or_else(|| malformed("array length is truncated"))?;
        self.cursor += 4;
        Ok(i32::from_be_bytes(value.try_into().expect("fixed")))
    }

    fn string(&mut self) -> Result<(), ProtocolError> {
        let length = self.i16()?;
        if length < 0 {
            return Err(malformed("non-null string has invalid length"));
        }
        self.bounded_bytes(length as usize, "string")
    }

    fn nullable_string(&mut self) -> Result<(), ProtocolError> {
        let length = self.i16()?;
        match length {
            -1 => Ok(()),
            value if value >= 0 => self.bounded_bytes(value as usize, "string"),
            _ => Err(malformed("nullable string has invalid length")),
        }
    }

    fn compact_string(&mut self) -> Result<(), ProtocolError> {
        let encoded = self.unsigned_varint()?;
        if encoded == 0 {
            return Err(malformed("compact string is null"));
        }
        self.bounded_bytes((encoded - 1) as usize, "string")
    }

    fn nullable_bytes(&mut self) -> Result<(), ProtocolError> {
        let length = self.i32()?;
        match length {
            -1 => Ok(()),
            value if value >= 0 => self.bounded_bytes(value as usize, "record set"),
            _ => Err(malformed("nullable bytes have invalid length")),
        }
    }

    fn bytes(&mut self) -> Result<(), ProtocolError> {
        let length = self.i32()?;
        if length < 0 {
            return Err(malformed("non-null bytes have invalid length"));
        }
        self.bounded_bytes(length as usize, "record set")
    }

    fn bounded_bytes(&mut self, length: usize, label: &'static str) -> Result<(), ProtocolError> {
        let maximum = if label == "record set" {
            self.limits.maximum_frame_bytes
        } else {
            self.limits.maximum_string_bytes
        };
        bounded(length, maximum, label)?;
        self.skip(length)
    }

    fn array(&mut self, nullable: bool) -> Result<usize, ProtocolError> {
        let count = self.i32()?;
        match count {
            -1 if nullable => Ok(0),
            value if value >= 0 => {
                let count = value as usize;
                bounded(
                    count,
                    self.limits.maximum_array_elements.min(self.bytes.len()),
                    "array",
                )?;
                Ok(count)
            }
            _ => Err(malformed("array has invalid length")),
        }
    }

    fn unsigned_varint(&mut self) -> Result<u32, ProtocolError> {
        let mut value = 0u32;
        for shift in 0..5 {
            let byte = *self
                .bytes
                .get(self.cursor)
                .ok_or_else(|| malformed("unsigned varint is truncated"))?;
            self.cursor += 1;
            value |= u32::from(byte & 0x7f) << (shift * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(malformed("unsigned varint is too long"))
    }

    fn tagged_fields(&mut self) -> Result<(), ProtocolError> {
        let count = self.unsigned_varint()? as usize;
        bounded(count, self.limits.maximum_array_elements, "tagged fields")?;
        for _ in 0..count {
            let _tag = self.unsigned_varint()?;
            let size = self.unsigned_varint()? as usize;
            bounded(size, self.limits.maximum_frame_bytes, "tagged field")?;
            self.skip(size)?;
        }
        Ok(())
    }
}

fn malformed(message: &'static str) -> ProtocolError {
    ProtocolError::Malformed(message.into())
}

pub fn encode_response<R>(
    correlation_id: i32,
    version: i16,
    response: &R,
) -> Result<Bytes, ProtocolError>
where
    R: Encodable + HeaderVersion,
{
    let mut payload = BytesMut::new();
    payload.put_i32(0);
    ResponseHeader::default()
        .with_correlation_id(correlation_id)
        .encode(&mut payload, R::header_version(version))
        .map_err(|error| ProtocolError::Encode(error.to_string()))?;
    response
        .encode(&mut payload, version)
        .map_err(|error| ProtocolError::Encode(error.to_string()))?;
    let length = i32::try_from(payload.len() - 4)
        .map_err(|_| ProtocolError::FrameTooLarge(payload.len() - 4))?;
    payload[..4].copy_from_slice(&length.to_be_bytes());
    Ok(payload.freeze())
}

pub fn encode_response_kind(
    api_key: ApiKey,
    correlation_id: i32,
    version: i16,
    response: &ResponseKind,
) -> Result<Bytes, ProtocolError> {
    let mut payload = BytesMut::new();
    payload.put_i32(0);
    ResponseHeader::default()
        .with_correlation_id(correlation_id)
        .encode(&mut payload, api_key.response_header_version(version))
        .map_err(|error| ProtocolError::Encode(error.to_string()))?;
    response
        .encode(&mut payload, version)
        .map_err(|error| ProtocolError::Encode(error.to_string()))?;
    let length = i32::try_from(payload.len() - 4)
        .map_err(|_| ProtocolError::FrameTooLarge(payload.len() - 4))?;
    payload[..4].copy_from_slice(&length.to_be_bytes());
    Ok(payload.freeze())
}

fn validate_request_limits(
    request: &RequestKind,
    limits: ProtocolLimits,
) -> Result<(), ProtocolError> {
    use RequestKind::*;
    match request {
        Produce(request) => {
            bounded(
                request.topic_data.len(),
                limits.maximum_array_elements,
                "topics",
            )?;
            for topic in &request.topic_data {
                bounded(
                    topic.name.0.len(),
                    limits.maximum_string_bytes,
                    "topic name",
                )?;
                bounded(
                    topic.partition_data.len(),
                    limits.maximum_array_elements,
                    "partitions",
                )?;
                for partition in &topic.partition_data {
                    if let Some(records) = &partition.records {
                        bounded(records.len(), limits.maximum_frame_bytes, "record set")?;
                    }
                }
            }
        }
        Fetch(request) => {
            bounded(
                request.topics.len(),
                limits.maximum_array_elements,
                "topics",
            )?;
            for topic in &request.topics {
                bounded(
                    topic.topic.0.len(),
                    limits.maximum_string_bytes,
                    "topic name",
                )?;
                bounded(
                    topic.partitions.len(),
                    limits.maximum_array_elements,
                    "partitions",
                )?;
            }
        }
        Metadata(request) => {
            if let Some(topics) = &request.topics {
                bounded(topics.len(), limits.maximum_array_elements, "topics")?;
                for topic in topics {
                    if let Some(name) = &topic.name {
                        bounded(name.0.len(), limits.maximum_string_bytes, "topic name")?;
                    }
                }
            }
        }
        SaslHandshake(request) => {
            bounded(
                request.mechanism.len(),
                limits.maximum_string_bytes,
                "SASL mechanism",
            )?;
        }
        SaslAuthenticate(request) => {
            bounded(
                request.auth_bytes.len(),
                limits.maximum_string_bytes,
                "SASL authentication message",
            )?;
        }
        ListOffsets(request) => {
            bounded(
                request.topics.len(),
                limits.maximum_array_elements,
                "topics",
            )?;
            for topic in &request.topics {
                bounded(
                    topic.name.0.len(),
                    limits.maximum_string_bytes,
                    "topic name",
                )?;
                bounded(
                    topic.partitions.len(),
                    limits.maximum_array_elements,
                    "partitions",
                )?;
            }
        }
        CreateTopics(request) => {
            bounded(
                request.topics.len(),
                limits.maximum_array_elements,
                "topics",
            )?;
            for topic in &request.topics {
                bounded(
                    topic.name.0.len(),
                    limits.maximum_string_bytes,
                    "topic name",
                )?;
                bounded(
                    topic.assignments.len(),
                    limits.maximum_array_elements,
                    "assignments",
                )?;
                bounded(
                    topic.configs.len(),
                    limits.maximum_array_elements,
                    "configs",
                )?;
            }
        }
        DeleteTopics(request) => {
            bounded(
                request.topic_names.len(),
                limits.maximum_array_elements,
                "topics",
            )?;
        }
        DescribeConfigs(request) => {
            bounded(
                request.resources.len(),
                limits.maximum_array_elements,
                "resources",
            )?;
        }
        AlterConfigs(request) => {
            bounded(
                request.resources.len(),
                limits.maximum_array_elements,
                "resources",
            )?;
        }
        OffsetCommit(request) => {
            bounded(
                request.group_id.0.len(),
                limits.maximum_string_bytes,
                "group ID",
            )?;
            bounded(
                request.topics.len(),
                limits.maximum_array_elements,
                "topics",
            )?;
        }
        OffsetFetch(request) => {
            bounded(
                request.group_id.0.len(),
                limits.maximum_string_bytes,
                "group ID",
            )?;
            if let Some(topics) = &request.topics {
                bounded(topics.len(), limits.maximum_array_elements, "topics")?;
            }
        }
        FindCoordinator(request) => {
            bounded(
                request.key.len(),
                limits.maximum_string_bytes,
                "coordinator key",
            )?;
        }
        JoinGroup(request) => {
            bounded(
                request.group_id.0.len(),
                limits.maximum_string_bytes,
                "group ID",
            )?;
            bounded(
                request.member_id.len(),
                limits.maximum_string_bytes,
                "member ID",
            )?;
            bounded(
                request.protocols.len(),
                limits.maximum_array_elements,
                "protocols",
            )?;
        }
        Heartbeat(request) => {
            bounded(
                request.group_id.0.len(),
                limits.maximum_string_bytes,
                "group ID",
            )?;
            bounded(
                request.member_id.len(),
                limits.maximum_string_bytes,
                "member ID",
            )?;
        }
        LeaveGroup(request) => {
            bounded(
                request.group_id.0.len(),
                limits.maximum_string_bytes,
                "group ID",
            )?;
            bounded(
                request.member_id.len(),
                limits.maximum_string_bytes,
                "member ID",
            )?;
        }
        SyncGroup(request) => {
            bounded(
                request.group_id.0.len(),
                limits.maximum_string_bytes,
                "group ID",
            )?;
            bounded(
                request.assignments.len(),
                limits.maximum_array_elements,
                "assignments",
            )?;
        }
        DescribeGroups(request) => {
            bounded(
                request.groups.len(),
                limits.maximum_array_elements,
                "groups",
            )?;
        }
        InitProducerId(request) => {
            if let Some(transactional_id) = &request.transactional_id {
                bounded(
                    transactional_id.len(),
                    limits.maximum_string_bytes,
                    "transactional ID",
                )?;
            }
        }
        AddPartitionsToTxn(request) => {
            bounded(
                request.v3_and_below_transactional_id.len(),
                limits.maximum_string_bytes,
                "transactional ID",
            )?;
            bounded(
                request.v3_and_below_topics.len(),
                limits.maximum_array_elements,
                "topics",
            )?;
        }
        AddOffsetsToTxn(request) => {
            bounded(
                request.transactional_id.len(),
                limits.maximum_string_bytes,
                "transactional ID",
            )?;
            bounded(
                request.group_id.0.len(),
                limits.maximum_string_bytes,
                "group ID",
            )?;
        }
        EndTxn(request) => {
            bounded(
                request.transactional_id.len(),
                limits.maximum_string_bytes,
                "transactional ID",
            )?;
        }
        TxnOffsetCommit(request) => {
            bounded(
                request.transactional_id.len(),
                limits.maximum_string_bytes,
                "transactional ID",
            )?;
            bounded(
                request.group_id.0.len(),
                limits.maximum_string_bytes,
                "group ID",
            )?;
            bounded(
                request.topics.len(),
                limits.maximum_array_elements,
                "topics",
            )?;
        }
        ApiVersions(_) | DescribeCluster(_) | ListGroups(_) => {}
        _ => return Err(ProtocolError::Malformed("API is not advertised".into())),
    }
    Ok(())
}

fn bounded(value: usize, maximum: usize, label: &'static str) -> Result<(), ProtocolError> {
    if value > maximum {
        Err(ProtocolError::Limit(label))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordBatchIdentity {
    pub transactional: bool,
    pub control: bool,
    pub producer_id: i64,
    pub producer_epoch: i16,
    pub base_sequence: i32,
    pub record_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSetSummary {
    pub batches: usize,
    pub records: usize,
    pub offset_span: u64,
    pub maximum_timestamp: i64,
    pub identities: Vec<RecordBatchIdentity>,
}

pub fn validate_record_set(
    records: &Bytes,
    limits: ProtocolLimits,
) -> Result<RecordSetSummary, ProtocolError> {
    let bytes = records.as_ref();
    let mut cursor = 0usize;
    let mut batches = 0usize;
    let mut total_records = 0usize;
    let mut offset_span = 0u64;
    let mut maximum_timestamp = i64::MIN;
    let mut identities = Vec::new();
    while cursor < bytes.len() {
        if bytes.len() - cursor < 61 {
            return Err(ProtocolError::InvalidRecordBatch(
                "batch header is truncated",
            ));
        }
        batches += 1;
        bounded(batches, limits.maximum_record_batches, "record batches")?;
        let batch_length = i32::from_be_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap());
        if batch_length < 49 {
            return Err(ProtocolError::InvalidRecordBatch("invalid batch length"));
        }
        let end = cursor
            .checked_add(12)
            .and_then(|value| value.checked_add(batch_length as usize))
            .ok_or(ProtocolError::InvalidRecordBatch("batch length overflow"))?;
        if end > bytes.len() {
            return Err(ProtocolError::InvalidRecordBatch(
                "batch exceeds record set",
            ));
        }
        if bytes[cursor + 16] != 2 {
            return Err(ProtocolError::InvalidRecordBatch("record magic must be 2"));
        }
        let supplied_crc = u32::from_be_bytes(bytes[cursor + 17..cursor + 21].try_into().unwrap());
        if crc32c::crc32c(&bytes[cursor + 21..end]) != supplied_crc {
            return Err(ProtocolError::InvalidRecordBatch("CRC32C mismatch"));
        }
        let attributes = i16::from_be_bytes(bytes[cursor + 21..cursor + 23].try_into().unwrap());
        if attributes & 0x7 != 0 {
            return Err(ProtocolError::InvalidRecordBatch(
                "compressed batches are not enabled in the Phase 8 floor",
            ));
        }
        if attributes & !0x7f != 0 {
            return Err(ProtocolError::InvalidRecordBatch(
                "reserved attributes are set",
            ));
        }
        let last_delta = i32::from_be_bytes(bytes[cursor + 23..cursor + 27].try_into().unwrap());
        let maximum = i64::from_be_bytes(bytes[cursor + 35..cursor + 43].try_into().unwrap());
        maximum_timestamp = maximum_timestamp.max(maximum);
        let record_count = i32::from_be_bytes(bytes[cursor + 57..cursor + 61].try_into().unwrap());
        if record_count < 0 || last_delta < 0 {
            return Err(ProtocolError::InvalidRecordBatch(
                "negative record metadata",
            ));
        }
        let record_count = record_count as usize;
        identities.push(RecordBatchIdentity {
            transactional: attributes & 0x10 != 0,
            control: attributes & 0x20 != 0,
            producer_id: i64::from_be_bytes(bytes[cursor + 43..cursor + 51].try_into().unwrap()),
            producer_epoch: i16::from_be_bytes(bytes[cursor + 51..cursor + 53].try_into().unwrap()),
            base_sequence: i32::from_be_bytes(bytes[cursor + 53..cursor + 57].try_into().unwrap()),
            record_count: record_count as u32,
        });
        bounded(
            record_count,
            limits.maximum_records_per_batch,
            "records per batch",
        )?;
        if record_count > 0 && last_delta < record_count.saturating_sub(1) as i32 {
            return Err(ProtocolError::InvalidRecordBatch(
                "last offset delta is smaller than record count",
            ));
        }
        let mut record_cursor = cursor + 61;
        for _ in 0..record_count {
            let encoded_length = read_varint(bytes, &mut record_cursor)?;
            if encoded_length < 0 {
                return Err(ProtocolError::InvalidRecordBatch("negative record length"));
            }
            let record_end = record_cursor
                .checked_add(encoded_length as usize)
                .ok_or(ProtocolError::InvalidRecordBatch("record length overflow"))?;
            if record_end > end {
                return Err(ProtocolError::InvalidRecordBatch("record exceeds batch"));
            }
            parse_record(&bytes[..record_end], &mut record_cursor, limits)?;
            if record_cursor != record_end {
                return Err(ProtocolError::InvalidRecordBatch("record length mismatch"));
            }
        }
        if record_cursor != end {
            return Err(ProtocolError::InvalidRecordBatch(
                "record count does not consume batch",
            ));
        }
        total_records = total_records.saturating_add(record_count);
        offset_span = offset_span.saturating_add(last_delta as u64 + 1);
        cursor = end;
    }
    Ok(RecordSetSummary {
        batches,
        records: total_records,
        offset_span,
        maximum_timestamp: if batches == 0 { -1 } else { maximum_timestamp },
        identities,
    })
}

fn parse_record(
    bytes: &[u8],
    cursor: &mut usize,
    limits: ProtocolLimits,
) -> Result<(), ProtocolError> {
    take(bytes, cursor, 1)?;
    read_varlong(bytes, cursor)?;
    read_varint(bytes, cursor)?;
    take_nullable_varbytes(bytes, cursor)?;
    take_nullable_varbytes(bytes, cursor)?;
    let headers = read_varint(bytes, cursor)?;
    if headers < 0 {
        return Err(ProtocolError::InvalidRecordBatch("negative header count"));
    }
    bounded(
        headers as usize,
        limits.maximum_headers_per_record,
        "headers per record",
    )?;
    for _ in 0..headers {
        let key_length = read_varint(bytes, cursor)?;
        if key_length < 0 {
            return Err(ProtocolError::InvalidRecordBatch("null header key"));
        }
        take(bytes, cursor, key_length as usize)?;
        take_nullable_varbytes(bytes, cursor)?;
    }
    Ok(())
}

fn take_nullable_varbytes(bytes: &[u8], cursor: &mut usize) -> Result<(), ProtocolError> {
    let length = read_varint(bytes, cursor)?;
    if length >= 0 {
        take(bytes, cursor, length as usize)?;
    } else if length != -1 {
        return Err(ProtocolError::InvalidRecordBatch("invalid nullable length"));
    }
    Ok(())
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], ProtocolError> {
    let end = cursor
        .checked_add(length)
        .ok_or(ProtocolError::InvalidRecordBatch("field length overflow"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ProtocolError::InvalidRecordBatch("field is truncated"))?;
    *cursor = end;
    Ok(value)
}

fn read_varint(bytes: &[u8], cursor: &mut usize) -> Result<i32, ProtocolError> {
    let value = read_unsigned_varint(bytes, cursor, 5)?;
    Ok(((value >> 1) as i32) ^ (-((value & 1) as i32)))
}

fn read_varlong(bytes: &[u8], cursor: &mut usize) -> Result<i64, ProtocolError> {
    let value = read_unsigned_varint(bytes, cursor, 10)?;
    Ok(((value >> 1) as i64) ^ (-((value & 1) as i64)))
}

fn read_unsigned_varint(
    bytes: &[u8],
    cursor: &mut usize,
    maximum_bytes: usize,
) -> Result<u64, ProtocolError> {
    let mut value = 0u64;
    for shift in 0..maximum_bytes {
        let byte = *take(bytes, cursor, 1)?
            .first()
            .expect("one byte was requested");
        value |= u64::from(byte & 0x7f) << (shift * 7);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(ProtocolError::InvalidRecordBatch("varint is too long"))
}

/// Represent broker-assigned fields as small owned patch segments around the
/// borrowed record bytes. Both fields are outside the record-batch CRC, and
/// the record payload itself is never copied.
pub fn assign_record_offsets(
    records: &Bytes,
    base_offset: i64,
    leader_epoch: i32,
) -> Result<BufferChain, ProtocolError> {
    let mut segments = Vec::new();
    let mut cursor = 0usize;
    let mut next_offset = base_offset;
    while cursor < records.len() {
        let batch_length = i32::from_be_bytes(records[cursor + 8..cursor + 12].try_into().unwrap());
        let end = cursor + 12 + batch_length as usize;
        let last_delta = i32::from_be_bytes(records[cursor + 23..cursor + 27].try_into().unwrap());
        segments.push(OwnedBuffer::new(Bytes::copy_from_slice(
            &next_offset.to_be_bytes(),
        )));
        segments.push(OwnedBuffer::new(records.slice(cursor + 8..cursor + 12)));
        segments.push(OwnedBuffer::new(Bytes::copy_from_slice(
            &leader_epoch.to_be_bytes(),
        )));
        segments.push(OwnedBuffer::new(records.slice(cursor + 16..end)));
        next_offset = next_offset.saturating_add(i64::from(last_delta) + 1);
        cursor = end;
    }
    BufferChain::from_segments(segments)
        .map_err(|_| ProtocolError::InvalidRecordBatch("assigned buffer length overflow"))
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Kafka frame length is negative: {0}")]
    NegativeFrameLength(i32),
    #[error("Kafka frame is too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("unknown Kafka API key {0}")]
    UnknownApi(i16),
    #[error("unsupported Kafka API key {api_key} version {version}")]
    UnsupportedVersion {
        api_key: i16,
        version: i16,
        correlation_id: i32,
    },
    #[error("malformed Kafka request: {0}")]
    Malformed(String),
    #[error("Kafka request has {0} trailing bytes")]
    TrailingBytes(usize),
    #[error("Kafka request exceeds configured {0} limit")]
    Limit(&'static str),
    #[error("invalid Kafka record batch: {0}")]
    InvalidRecordBatch(&'static str),
    #[error("Kafka response encoding failed: {0}")]
    Encode(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use kafka_protocol::{
        messages::{
            AddOffsetsToTxnRequest, AddOffsetsToTxnResponse, AddPartitionsToTxnRequest,
            AddPartitionsToTxnResponse, AlterConfigsRequest, AlterConfigsResponse,
            ApiVersionsRequest, ApiVersionsResponse, CreateTopicsRequest, CreateTopicsResponse,
            DeleteTopicsRequest, DeleteTopicsResponse, DescribeClusterRequest,
            DescribeClusterResponse, DescribeConfigsRequest, DescribeConfigsResponse,
            DescribeGroupsRequest, DescribeGroupsResponse, EndTxnRequest, EndTxnResponse,
            FetchRequest, FetchResponse, FindCoordinatorRequest, FindCoordinatorResponse,
            HeartbeatRequest, HeartbeatResponse, InitProducerIdRequest, InitProducerIdResponse,
            JoinGroupRequest, JoinGroupResponse, LeaveGroupRequest, LeaveGroupResponse,
            ListGroupsRequest, ListGroupsResponse, ListOffsetsRequest, ListOffsetsResponse,
            MetadataRequest, MetadataResponse, OffsetCommitRequest, OffsetCommitResponse,
            OffsetFetchRequest, OffsetFetchResponse, ProduceRequest, ProduceResponse,
            SaslAuthenticateRequest, SaslAuthenticateResponse, SaslHandshakeRequest,
            SaslHandshakeResponse, SyncGroupRequest, SyncGroupResponse, TxnOffsetCommitRequest,
            TxnOffsetCommitResponse, create_topics_request::CreatableTopic,
        },
        protocol::{Encodable, StrBytes},
        records::{Compression, Record, RecordBatchEncoder, RecordEncodeOptions, TimestampType},
    };

    fn encoded_request(api_key: ApiKey, version: i16, request: RequestKind) -> Bytes {
        let mut bytes = BytesMut::new();
        let header = RequestHeader::default()
            .with_request_api_key(api_key as i16)
            .with_request_api_version(version)
            .with_correlation_id(91);
        header
            .encode(&mut bytes, api_key.request_header_version(version))
            .unwrap();
        request.encode(&mut bytes, version).unwrap();
        bytes.freeze()
    }

    fn hexadecimal(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn hard_coded_api_versions_v0_golden_frame_decodes() {
        let golden = Bytes::from_static(&[
            0x00, 0x12, // ApiVersions
            0x00, 0x00, // v0
            0x00, 0x00, 0x00, 0x07, // correlation
            0xff, 0xff, // null client ID
        ]);
        let decoded = decode_request(golden, ProtocolLimits::default()).unwrap();
        assert_eq!(decoded.header.correlation_id, 7);
        assert!(matches!(decoded.body, RequestKind::ApiVersions(_)));
    }

    #[test]
    fn every_advertised_request_floor_round_trips_and_rejects_truncation() {
        let requests = [
            (
                ApiKey::Produce,
                3,
                RequestKind::Produce(ProduceRequest::default()),
            ),
            (
                ApiKey::Fetch,
                4,
                RequestKind::Fetch(FetchRequest::default()),
            ),
            (
                ApiKey::ListOffsets,
                1,
                RequestKind::ListOffsets(ListOffsetsRequest::default()),
            ),
            (
                ApiKey::Metadata,
                1,
                RequestKind::Metadata(MetadataRequest::default()),
            ),
            (
                ApiKey::OffsetCommit,
                2,
                RequestKind::OffsetCommit(OffsetCommitRequest::default()),
            ),
            (
                ApiKey::OffsetFetch,
                1,
                RequestKind::OffsetFetch(OffsetFetchRequest::default()),
            ),
            (
                ApiKey::FindCoordinator,
                0,
                RequestKind::FindCoordinator(FindCoordinatorRequest::default()),
            ),
            (
                ApiKey::JoinGroup,
                0,
                RequestKind::JoinGroup(JoinGroupRequest::default()),
            ),
            (
                ApiKey::Heartbeat,
                0,
                RequestKind::Heartbeat(HeartbeatRequest::default()),
            ),
            (
                ApiKey::LeaveGroup,
                0,
                RequestKind::LeaveGroup(LeaveGroupRequest::default()),
            ),
            (
                ApiKey::SyncGroup,
                0,
                RequestKind::SyncGroup(SyncGroupRequest::default()),
            ),
            (
                ApiKey::DescribeGroups,
                0,
                RequestKind::DescribeGroups(DescribeGroupsRequest::default()),
            ),
            (
                ApiKey::ListGroups,
                0,
                RequestKind::ListGroups(ListGroupsRequest::default()),
            ),
            (
                ApiKey::SaslHandshake,
                0,
                RequestKind::SaslHandshake(SaslHandshakeRequest::default()),
            ),
            (
                ApiKey::SaslAuthenticate,
                0,
                RequestKind::SaslAuthenticate(SaslAuthenticateRequest::default()),
            ),
            (
                ApiKey::InitProducerId,
                0,
                RequestKind::InitProducerId(InitProducerIdRequest::default()),
            ),
            (
                ApiKey::AddPartitionsToTxn,
                0,
                RequestKind::AddPartitionsToTxn(AddPartitionsToTxnRequest::default()),
            ),
            (
                ApiKey::AddOffsetsToTxn,
                0,
                RequestKind::AddOffsetsToTxn(AddOffsetsToTxnRequest::default()),
            ),
            (
                ApiKey::EndTxn,
                0,
                RequestKind::EndTxn(EndTxnRequest::default()),
            ),
            (
                ApiKey::TxnOffsetCommit,
                0,
                RequestKind::TxnOffsetCommit(TxnOffsetCommitRequest::default()),
            ),
            (
                ApiKey::ApiVersions,
                0,
                RequestKind::ApiVersions(ApiVersionsRequest::default()),
            ),
            (
                ApiKey::ApiVersions,
                3,
                RequestKind::ApiVersions(ApiVersionsRequest::default()),
            ),
            (
                ApiKey::CreateTopics,
                0,
                RequestKind::CreateTopics(CreateTopicsRequest::default()),
            ),
            (
                ApiKey::DeleteTopics,
                0,
                RequestKind::DeleteTopics(DeleteTopicsRequest::default()),
            ),
            (
                ApiKey::DescribeConfigs,
                0,
                RequestKind::DescribeConfigs(DescribeConfigsRequest::default()),
            ),
            (
                ApiKey::AlterConfigs,
                0,
                RequestKind::AlterConfigs(AlterConfigsRequest::default()),
            ),
            (
                ApiKey::DescribeCluster,
                0,
                RequestKind::DescribeCluster(DescribeClusterRequest::default()),
            ),
        ];
        for (api_key, version, request) in requests {
            let encoded = encoded_request(api_key, version, request);
            let decoded = decode_request(encoded.clone(), ProtocolLimits::default()).unwrap();
            assert_eq!(decoded.api_key, api_key);
            for length in 0..encoded.len() {
                assert!(
                    decode_request(encoded.slice(..length), ProtocolLimits::default()).is_err(),
                    "{api_key:?} v{version} accepted truncation at {length}"
                );
            }
        }
    }

    #[test]
    fn every_advertised_boundary_has_a_stable_request_and_response_vector() {
        let cases = [
            (
                ApiKey::Produce,
                3,
                RequestKind::Produce(ProduceRequest::default()),
                ResponseKind::Produce(ProduceResponse::default()),
            ),
            (
                ApiKey::Fetch,
                4,
                RequestKind::Fetch(FetchRequest::default()),
                ResponseKind::Fetch(FetchResponse::default()),
            ),
            (
                ApiKey::ListOffsets,
                1,
                RequestKind::ListOffsets(ListOffsetsRequest::default()),
                ResponseKind::ListOffsets(ListOffsetsResponse::default()),
            ),
            (
                ApiKey::Metadata,
                1,
                RequestKind::Metadata(MetadataRequest::default()),
                ResponseKind::Metadata(MetadataResponse::default()),
            ),
            (
                ApiKey::OffsetCommit,
                2,
                RequestKind::OffsetCommit(OffsetCommitRequest::default()),
                ResponseKind::OffsetCommit(OffsetCommitResponse::default()),
            ),
            (
                ApiKey::OffsetFetch,
                1,
                RequestKind::OffsetFetch(OffsetFetchRequest::default()),
                ResponseKind::OffsetFetch(OffsetFetchResponse::default()),
            ),
            (
                ApiKey::FindCoordinator,
                0,
                RequestKind::FindCoordinator(FindCoordinatorRequest::default()),
                ResponseKind::FindCoordinator(FindCoordinatorResponse::default()),
            ),
            (
                ApiKey::FindCoordinator,
                1,
                RequestKind::FindCoordinator(FindCoordinatorRequest::default()),
                ResponseKind::FindCoordinator(FindCoordinatorResponse::default()),
            ),
            (
                ApiKey::JoinGroup,
                0,
                RequestKind::JoinGroup(JoinGroupRequest::default()),
                ResponseKind::JoinGroup(JoinGroupResponse::default()),
            ),
            (
                ApiKey::JoinGroup,
                2,
                RequestKind::JoinGroup(JoinGroupRequest::default()),
                ResponseKind::JoinGroup(JoinGroupResponse::default()),
            ),
            (
                ApiKey::Heartbeat,
                0,
                RequestKind::Heartbeat(HeartbeatRequest::default()),
                ResponseKind::Heartbeat(HeartbeatResponse::default()),
            ),
            (
                ApiKey::Heartbeat,
                1,
                RequestKind::Heartbeat(HeartbeatRequest::default()),
                ResponseKind::Heartbeat(HeartbeatResponse::default()),
            ),
            (
                ApiKey::LeaveGroup,
                0,
                RequestKind::LeaveGroup(LeaveGroupRequest::default()),
                ResponseKind::LeaveGroup(LeaveGroupResponse::default()),
            ),
            (
                ApiKey::LeaveGroup,
                1,
                RequestKind::LeaveGroup(LeaveGroupRequest::default()),
                ResponseKind::LeaveGroup(LeaveGroupResponse::default()),
            ),
            (
                ApiKey::SyncGroup,
                0,
                RequestKind::SyncGroup(SyncGroupRequest::default()),
                ResponseKind::SyncGroup(SyncGroupResponse::default()),
            ),
            (
                ApiKey::SyncGroup,
                1,
                RequestKind::SyncGroup(SyncGroupRequest::default()),
                ResponseKind::SyncGroup(SyncGroupResponse::default()),
            ),
            (
                ApiKey::DescribeGroups,
                0,
                RequestKind::DescribeGroups(DescribeGroupsRequest::default()),
                ResponseKind::DescribeGroups(DescribeGroupsResponse::default()),
            ),
            (
                ApiKey::ListGroups,
                0,
                RequestKind::ListGroups(ListGroupsRequest::default()),
                ResponseKind::ListGroups(ListGroupsResponse::default()),
            ),
            (
                ApiKey::SaslHandshake,
                0,
                RequestKind::SaslHandshake(SaslHandshakeRequest::default()),
                ResponseKind::SaslHandshake(SaslHandshakeResponse::default()),
            ),
            (
                ApiKey::SaslHandshake,
                1,
                RequestKind::SaslHandshake(SaslHandshakeRequest::default()),
                ResponseKind::SaslHandshake(SaslHandshakeResponse::default()),
            ),
            (
                ApiKey::SaslAuthenticate,
                0,
                RequestKind::SaslAuthenticate(SaslAuthenticateRequest::default()),
                ResponseKind::SaslAuthenticate(SaslAuthenticateResponse::default()),
            ),
            (
                ApiKey::InitProducerId,
                0,
                RequestKind::InitProducerId(InitProducerIdRequest::default()),
                ResponseKind::InitProducerId(InitProducerIdResponse::default()),
            ),
            (
                ApiKey::AddPartitionsToTxn,
                0,
                RequestKind::AddPartitionsToTxn(AddPartitionsToTxnRequest::default()),
                ResponseKind::AddPartitionsToTxn(AddPartitionsToTxnResponse::default()),
            ),
            (
                ApiKey::AddOffsetsToTxn,
                0,
                RequestKind::AddOffsetsToTxn(AddOffsetsToTxnRequest::default()),
                ResponseKind::AddOffsetsToTxn(AddOffsetsToTxnResponse::default()),
            ),
            (
                ApiKey::EndTxn,
                0,
                RequestKind::EndTxn(EndTxnRequest::default()),
                ResponseKind::EndTxn(EndTxnResponse::default()),
            ),
            (
                ApiKey::TxnOffsetCommit,
                0,
                RequestKind::TxnOffsetCommit(TxnOffsetCommitRequest::default()),
                ResponseKind::TxnOffsetCommit(TxnOffsetCommitResponse::default()),
            ),
            (
                ApiKey::ApiVersions,
                0,
                RequestKind::ApiVersions(ApiVersionsRequest::default()),
                ResponseKind::ApiVersions(ApiVersionsResponse::default()),
            ),
            (
                ApiKey::ApiVersions,
                3,
                RequestKind::ApiVersions(ApiVersionsRequest::default()),
                ResponseKind::ApiVersions(ApiVersionsResponse::default()),
            ),
            (
                ApiKey::CreateTopics,
                0,
                RequestKind::CreateTopics(CreateTopicsRequest::default()),
                ResponseKind::CreateTopics(CreateTopicsResponse::default()),
            ),
            (
                ApiKey::CreateTopics,
                2,
                RequestKind::CreateTopics(CreateTopicsRequest::default()),
                ResponseKind::CreateTopics(CreateTopicsResponse::default()),
            ),
            (
                ApiKey::DeleteTopics,
                0,
                RequestKind::DeleteTopics(DeleteTopicsRequest::default()),
                ResponseKind::DeleteTopics(DeleteTopicsResponse::default()),
            ),
            (
                ApiKey::DeleteTopics,
                1,
                RequestKind::DeleteTopics(DeleteTopicsRequest::default()),
                ResponseKind::DeleteTopics(DeleteTopicsResponse::default()),
            ),
            (
                ApiKey::DescribeConfigs,
                0,
                RequestKind::DescribeConfigs(DescribeConfigsRequest::default()),
                ResponseKind::DescribeConfigs(DescribeConfigsResponse::default()),
            ),
            (
                ApiKey::DescribeConfigs,
                1,
                RequestKind::DescribeConfigs(DescribeConfigsRequest::default()),
                ResponseKind::DescribeConfigs(DescribeConfigsResponse::default()),
            ),
            (
                ApiKey::AlterConfigs,
                0,
                RequestKind::AlterConfigs(AlterConfigsRequest::default()),
                ResponseKind::AlterConfigs(AlterConfigsResponse::default()),
            ),
            (
                ApiKey::DescribeCluster,
                0,
                RequestKind::DescribeCluster(DescribeClusterRequest::default()),
                ResponseKind::DescribeCluster(DescribeClusterResponse::default()),
            ),
        ];
        let expected = [
            "000000030000005b0000ffff00000000000000000000:0000000c0000005b0000000000000000",
            "000100040000005b0000ffffffff00000000000000007fffffff0000000000:0000000c0000005b0000000000000000",
            "000200010000005b00000000000000000000:000000080000005b00000000",
            "000300010000005b000000000000:000000100000005b00000000ffffffff00000000",
            "000800020000005b00000000ffffffff0000ffffffffffffffff00000000:000000080000005b00000000",
            "000900010000005b0000000000000000:000000080000005b00000000",
            "000a00000000005b00000000:000000100000005b000000000000000000000000",
            "000a00010000005b0000000000:000000160000005b000000000000000000000000000000000000",
            "000b00000000005b00000000000000000000000000000000:000000140000005b0000ffffffff00000000000000000000",
            "000b00020000005b0000000000000000ffffffff0000000000000000:000000180000005b000000000000ffffffff00000000000000000000",
            "000c00000000005b00000000000000000000:000000060000005b0000",
            "000c00010000005b00000000000000000000:0000000a0000005b000000000000",
            "000d00000000005b000000000000:000000060000005b0000",
            "000d00010000005b000000000000:0000000a0000005b000000000000",
            "000e00000000005b0000000000000000000000000000:0000000a0000005b000000000000",
            "000e00010000005b0000000000000000000000000000:0000000e0000005b00000000000000000000",
            "000f00000000005b000000000000:000000080000005b00000000",
            "001000000000005b0000:0000000a0000005b000000000000",
            "001100000000005b00000000:0000000a0000005b000000000000",
            "001100010000005b00000000:0000000a0000005b000000000000",
            "002400000000005b000000000000:0000000c0000005b0000000000000000",
            "001600000000005b0000000000000000:000000140000005b000000000000ffffffffffffffff0000",
            "001800000000005b000000000000000000000000000000000000:0000000c0000005b0000000000000000",
            "001900000000005b00000000000000000000000000000000:0000000a0000005b000000000000",
            "001a00000000005b000000000000000000000000000000:0000000a0000005b000000000000",
            "001c00000000005b0000000000000000000000000000000000000000:0000000c0000005b0000000000000000",
            "001200000000005b0000:0000000a0000005b000000000000",
            "001200030000005b000000010100:0000000c0000005b0000010000000000",
            "001300000000005b0000000000000000ea60:000000080000005b00000000",
            "001300020000005b0000000000000000ea6000:0000000c0000005b0000000000000000",
            "001400000000005b00000000000000000000:000000080000005b00000000",
            "001400010000005b00000000000000000000:0000000c0000005b0000000000000000",
            "002000000000005b000000000000:0000000c0000005b0000000000000000",
            "002000010000005b00000000000000:0000000c0000005b0000000000000000",
            "002100000000005b00000000000000:0000000c0000005b0000000000000000",
            "003c00000000005b0000000000:000000170000005b000000000000000001ffffffff018000000000",
        ];
        let mut actual = Vec::new();
        for (api_key, version, request, response) in cases {
            let request = encoded_request(api_key, version, request);
            decode_request(request.clone(), ProtocolLimits::default()).unwrap();
            let response = encode_response_kind(api_key, 91, version, &response).unwrap();
            let vector = format!("{}:{}", hexadecimal(&request), hexadecimal(&response));
            actual.push(vector);
        }
        assert_eq!(actual, expected);
    }

    #[test]
    fn incremental_framing_handles_partial_and_pipelined_frames() {
        let first = encoded_request(
            ApiKey::ApiVersions,
            0,
            RequestKind::ApiVersions(ApiVersionsRequest::default()),
        );
        let second = encoded_request(
            ApiKey::Metadata,
            1,
            RequestKind::Metadata(MetadataRequest::default()),
        );
        let mut wire = BytesMut::new();
        wire.put_i32(first.len() as i32);
        wire.extend_from_slice(&first);
        wire.put_i32(second.len() as i32);
        wire.extend_from_slice(&second);
        let mut decoder = FrameDecoder::new(ProtocolLimits::default());
        let split = wire.len() / 3;
        assert!(decoder.push(&wire[..split]).unwrap().is_empty());
        let frames = decoder.push(&wire[split..]).unwrap();
        assert_eq!(frames, vec![first, second]);
        assert_eq!(decoder.buffered_bytes(), 0);
    }

    #[test]
    fn record_batch_crc_structure_and_assigned_fields_are_validated() {
        let record = Record {
            transactional: false,
            control: false,
            partition_leader_epoch: -1,
            producer_id: -1,
            producer_epoch: -1,
            timestamp_type: TimestampType::Creation,
            timestamp: 100,
            sequence: -1,
            offset: 0,
            key: Some(Bytes::from_static(b"k")),
            value: Some(Bytes::from_static(b"value")),
            headers: Default::default(),
        };
        let mut encoded = BytesMut::new();
        RecordBatchEncoder::encode(
            &mut encoded,
            [&record],
            &RecordEncodeOptions {
                version: 2,
                compression: Compression::None,
            },
        )
        .unwrap();
        let records = encoded.freeze();
        let summary = validate_record_set(&records, ProtocolLimits::default()).unwrap();
        assert_eq!(
            (summary.batches, summary.records, summary.offset_span),
            (1, 1, 1)
        );
        let assigned = assign_record_offsets(&records, 42, 7).unwrap();
        assert_eq!(assigned.encoded_len(), records.len());
        assert_eq!(assigned.segment_count(), 4);
        let assigned = assigned.coalesce(records.len()).unwrap().into_bytes();
        assert_eq!(i64::from_be_bytes(assigned[..8].try_into().unwrap()), 42);
        assert_eq!(i32::from_be_bytes(assigned[12..16].try_into().unwrap()), 7);
        validate_record_set(&assigned, ProtocolLimits::default()).unwrap();
        let mut corrupt = BytesMut::from(records.as_ref());
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(matches!(
            validate_record_set(&corrupt.freeze(), ProtocolLimits::default()),
            Err(ProtocolError::InvalidRecordBatch("CRC32C mismatch"))
        ));
    }

    #[test]
    fn deterministic_100000_frame_malformed_corpus_never_panics() {
        let valid = [
            encoded_request(
                ApiKey::Produce,
                3,
                RequestKind::Produce(ProduceRequest::default()),
            ),
            encoded_request(
                ApiKey::Fetch,
                4,
                RequestKind::Fetch(FetchRequest::default()),
            ),
            encoded_request(
                ApiKey::ListOffsets,
                1,
                RequestKind::ListOffsets(ListOffsetsRequest::default()),
            ),
            encoded_request(
                ApiKey::Metadata,
                1,
                RequestKind::Metadata(MetadataRequest::default()),
            ),
            encoded_request(
                ApiKey::OffsetCommit,
                2,
                RequestKind::OffsetCommit(OffsetCommitRequest::default()),
            ),
            encoded_request(
                ApiKey::OffsetFetch,
                1,
                RequestKind::OffsetFetch(OffsetFetchRequest::default()),
            ),
            encoded_request(
                ApiKey::FindCoordinator,
                0,
                RequestKind::FindCoordinator(FindCoordinatorRequest::default()),
            ),
            encoded_request(
                ApiKey::FindCoordinator,
                1,
                RequestKind::FindCoordinator(FindCoordinatorRequest::default()),
            ),
            encoded_request(
                ApiKey::JoinGroup,
                0,
                RequestKind::JoinGroup(JoinGroupRequest::default()),
            ),
            encoded_request(
                ApiKey::Heartbeat,
                0,
                RequestKind::Heartbeat(HeartbeatRequest::default()),
            ),
            encoded_request(
                ApiKey::LeaveGroup,
                0,
                RequestKind::LeaveGroup(LeaveGroupRequest::default()),
            ),
            encoded_request(
                ApiKey::SyncGroup,
                0,
                RequestKind::SyncGroup(SyncGroupRequest::default()),
            ),
            encoded_request(
                ApiKey::DescribeGroups,
                0,
                RequestKind::DescribeGroups(DescribeGroupsRequest::default()),
            ),
            encoded_request(
                ApiKey::ListGroups,
                0,
                RequestKind::ListGroups(ListGroupsRequest::default()),
            ),
            encoded_request(
                ApiKey::SaslHandshake,
                1,
                RequestKind::SaslHandshake(SaslHandshakeRequest::default()),
            ),
            encoded_request(
                ApiKey::SaslAuthenticate,
                0,
                RequestKind::SaslAuthenticate(SaslAuthenticateRequest::default()),
            ),
            encoded_request(
                ApiKey::InitProducerId,
                0,
                RequestKind::InitProducerId(InitProducerIdRequest::default()),
            ),
            encoded_request(
                ApiKey::AddPartitionsToTxn,
                0,
                RequestKind::AddPartitionsToTxn(AddPartitionsToTxnRequest::default()),
            ),
            encoded_request(
                ApiKey::AddOffsetsToTxn,
                0,
                RequestKind::AddOffsetsToTxn(AddOffsetsToTxnRequest::default()),
            ),
            encoded_request(
                ApiKey::EndTxn,
                0,
                RequestKind::EndTxn(EndTxnRequest::default()),
            ),
            encoded_request(
                ApiKey::TxnOffsetCommit,
                0,
                RequestKind::TxnOffsetCommit(TxnOffsetCommitRequest::default()),
            ),
            encoded_request(
                ApiKey::ApiVersions,
                3,
                RequestKind::ApiVersions(ApiVersionsRequest::default()),
            ),
            encoded_request(
                ApiKey::CreateTopics,
                2,
                RequestKind::CreateTopics(CreateTopicsRequest::default()),
            ),
            encoded_request(
                ApiKey::DeleteTopics,
                1,
                RequestKind::DeleteTopics(DeleteTopicsRequest::default()),
            ),
            encoded_request(
                ApiKey::DescribeConfigs,
                1,
                RequestKind::DescribeConfigs(DescribeConfigsRequest::default()),
            ),
            encoded_request(
                ApiKey::AlterConfigs,
                0,
                RequestKind::AlterConfigs(AlterConfigsRequest::default()),
            ),
            encoded_request(
                ApiKey::DescribeCluster,
                0,
                RequestKind::DescribeCluster(DescribeClusterRequest::default()),
            ),
        ];
        let mut state = 0x4d595df4d0f33173u64;
        for iteration in 0..100_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let valid = &valid[iteration % valid.len()];
            let length = (state as usize) % (valid.len() + 1);
            let mut candidate = BytesMut::from(&valid[..length]);
            if !candidate.is_empty() {
                let index = (state.rotate_left(19) as usize) % candidate.len();
                candidate[index] ^= (iteration as u8).wrapping_mul(31);
            }
            let _ = decode_request(candidate.freeze(), ProtocolLimits::default());
        }
    }

    #[test]
    fn impossible_top_level_array_is_rejected_before_schema_allocation() {
        let mut request = encoded_request(
            ApiKey::CreateTopics,
            0,
            RequestKind::CreateTopics(CreateTopicsRequest::default()),
        )
        .to_vec();
        // Header v1 is ten bytes, followed by the top-level topic count.
        request[10..14].copy_from_slice(&i32::MAX.to_be_bytes());
        assert!(matches!(
            decode_request(Bytes::from(request), ProtocolLimits::default()),
            Err(ProtocolError::Limit("array"))
        ));
    }

    #[test]
    fn impossible_nested_array_is_rejected_before_schema_allocation() {
        let topic = CreatableTopic::default()
            .with_name(StrBytes::from_static_str("x").into())
            .with_num_partitions(1)
            .with_replication_factor(1);
        let mut request = encoded_request(
            ApiKey::CreateTopics,
            0,
            RequestKind::CreateTopics(
                CreateTopicsRequest::default()
                    .with_topics(vec![topic])
                    .with_timeout_ms(1),
            ),
        )
        .to_vec();
        // Header v1 (10), topic count (4), one-byte string (3),
        // partition count (4), replication factor (2), then assignments.
        request[23..27].copy_from_slice(&i32::MAX.to_be_bytes());
        assert!(matches!(
            decode_request(Bytes::from(request), ProtocolLimits::default()),
            Err(ProtocolError::Limit("array"))
        ));
    }
}
