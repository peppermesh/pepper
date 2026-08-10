// SPDX-License-Identifier: Apache-2.0

//! Kafka produce durability system tests.
//!
//! This is the multi-node analog of the crate-level guards
//! `pepper-kafka::every_acknowledged_record_survives_reopen`,
//! `pepper-kafka::concurrent_acknowledged_produces_all_survive_reopen`, and
//! `pepper-ordered-log::recovery_preserves_exactly_the_committed_prefix`.
//! It brings up a Kafka-enabled topology, produces `acks=all` records
//! concurrently, SIGKILLs every node, restarts them, and consumes the recovered
//! log to prove `SAF-KAFKA-001`: every acknowledged offset is present,
//! contiguous, and ordered.

use super::bootstrap_cluster;
use crate::harness::{
    cluster::ClusterSpec,
    context::ScenarioContext,
    scenario::{Scenario, ScenarioRequirements},
    wait::eventually,
};
use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use kafka_protocol::{
    messages::{
        ApiKey, CreateTopicsRequest, CreateTopicsResponse, FetchRequest, FetchResponse,
        MetadataRequest, MetadataResponse, ProduceRequest, ProduceResponse, RequestHeader,
        ResponseHeader,
        create_topics_request::CreatableTopic,
        fetch_request::{FetchPartition, FetchTopic},
        metadata_request::MetadataRequestTopic,
        produce_request::{PartitionProduceData, TopicProduceData},
    },
    protocol::{Decodable, Encodable, HeaderVersion, StrBytes},
    records::{
        Compression, Record, RecordBatchDecoder, RecordBatchEncoder, RecordEncodeOptions,
        TimestampType,
    },
};
use serde_json::json;
use std::{collections::BTreeSet, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const TOPIC: &str = "kafka-durable";
const PARTITION: i32 = 0;
const ACKNOWLEDGED_RECORDS: usize = 32;

pub struct KafkaProduceDurabilityScenario;

fn requirements() -> ScenarioRequirements {
    ScenarioRequirements {
        minimum_nodes: 3,
        ..ScenarioRequirements::default()
    }
}

#[async_trait]
impl Scenario for KafkaProduceDurabilityScenario {
    fn id(&self) -> &'static str {
        "KAFKA-001"
    }
    fn name(&self) -> &'static str {
        "kafka-produce-crash-durability"
    }
    fn requirements(&self) -> ScenarioRequirements {
        requirements()
    }

    async fn run(&self, context: &mut ScenarioContext) -> Result<()> {
        let mut spec = ClusterSpec::three_node(context.run.seed);
        spec.kafka_enabled = true;
        let client = bootstrap_cluster(context, spec).await?;
        let cluster = context.cluster.as_ref().expect("cluster exists");
        let nodes = cluster.nodes.values().cloned().collect::<Vec<_>>();

        // All produce/consume traffic targets the single broker that owns the
        // topic. Per-broker topic isolation means only the owning broker can
        // report the durable log, so we consume from the exact broker we
        // acknowledged against.
        let ingress = nodes[0].clone();
        let broker: SocketAddr = format!("{}:{}", ingress.address, ingress.kafka_port)
            .parse()
            .context("kafka broker address")?;

        // Create the single-partition topic and wait until its leader is ready.
        eventually(
            "kafka topic creation",
            Duration::from_secs(30),
            Duration::from_millis(250),
            || async { Ok(create_topic(broker).await?.then_some(())) },
        )
        .await?;
        wait_partition_leader(broker).await?;

        // Fire acks=all produces concurrently at the one partition. Each success
        // returns a distinct base offset; the broker must serialize them into a
        // contiguous 0..N range with no gaps.
        let mut set = tokio::task::JoinSet::new();
        for index in 0..ACKNOWLEDGED_RECORDS {
            set.spawn(async move { produce_one(broker, index as u64).await });
        }
        let mut acknowledged = BTreeSet::new();
        while let Some(joined) = set.join_next().await {
            let offset = joined.context("produce task panicked")??;
            ensure!(
                acknowledged.insert(offset),
                "broker acknowledged offset {offset} twice"
            );
        }
        let expected: BTreeSet<i64> = (0..ACKNOWLEDGED_RECORDS as i64).collect();
        ensure!(
            acknowledged == expected,
            "acknowledged offsets are not the contiguous range 0..{}: {acknowledged:?}",
            ACKNOWLEDGED_RECORDS
        );

        // Crash the whole topology hard, then bring every node back.
        for node in &nodes {
            cluster.backend.kill(&node.id).await?;
        }
        for node in &nodes {
            cluster.backend.start(&node.id).await?;
        }
        for node in &nodes {
            eventually(
                &format!("{} post-crash readiness", node.id),
                Duration::from_secs(45),
                Duration::from_millis(200),
                || async {
                    Ok((client.health(node).await? && client.ready(node).await?).then_some(()))
                },
            )
            .await?;
        }

        // Consume the recovered log by counting records, not by trusting an
        // offset-listing API. Every acknowledged record must reappear at its
        // original offset, in order, at or below the recovered high watermark.
        let recovered = eventually(
            "kafka recovered acknowledged prefix",
            Duration::from_secs(60),
            Duration::from_millis(500),
            || async {
                let consumed = consume_all(broker).await?;
                Ok((consumed.offsets.len() == ACKNOWLEDGED_RECORDS).then_some(consumed))
            },
        )
        .await?;

        let recovered_offsets: BTreeSet<i64> = recovered.offsets.iter().copied().collect();
        ensure!(
            recovered_offsets == expected,
            "recovered offsets differ from acknowledged set: {recovered_offsets:?}"
        );
        ensure!(
            is_strictly_increasing(&recovered.offsets),
            "recovered records are not in strictly increasing offset order: {:?}",
            recovered.offsets
        );
        ensure!(
            recovered.high_watermark >= ACKNOWLEDGED_RECORDS as i64,
            "recovered high watermark {} does not cover {} acknowledged records",
            recovered.high_watermark,
            ACKNOWLEDGED_RECORDS
        );

        context.run.events.record(
            "invariant",
            json!({
                "invariant_id":"SAF-KAFKA-001","invariant_result":"pass",
                "details":{
                    "seed":context.run.seed,
                    "broker":ingress.node_identity,
                    "topic":TOPIC,
                    "acknowledged":ACKNOWLEDGED_RECORDS,
                    "recovered":recovered.offsets.len(),
                    "high_watermark":recovered.high_watermark,
                    "contiguous":true,
                    "ordered":true,
                    "crash":"sigkill-all-nodes"
                }
            }),
        )?;
        Ok(())
    }
}

struct Consumed {
    offsets: Vec<i64>,
    high_watermark: i64,
}

fn is_strictly_increasing(offsets: &[i64]) -> bool {
    offsets.windows(2).all(|pair| pair[0] < pair[1])
}

fn topic_name() -> StrBytes {
    StrBytes::from_static_str(TOPIC)
}

/// Create the single-partition, single-replica topic. Returns `true` once the
/// topic exists (fresh creation or already present), `false` on a retryable
/// error so the caller can poll while the broker finishes coming up.
async fn create_topic(broker: SocketAddr) -> Result<bool> {
    let request = CreateTopicsRequest::default()
        .with_topics(vec![
            CreatableTopic::default()
                .with_name(topic_name().into())
                .with_num_partitions(1)
                .with_replication_factor(1),
        ])
        .with_timeout_ms(5_000);
    let response: CreateTopicsResponse = match send(broker, ApiKey::CreateTopics, 0, request).await
    {
        Ok(response) => response,
        Err(_) => return Ok(false),
    };
    let topic = response
        .topics
        .first()
        .context("create-topics response is empty")?;
    // 0 = success, 36 = TOPIC_ALREADY_EXISTS (idempotent on retry).
    Ok(matches!(topic.error_code, 0 | 36))
}

/// Poll cluster metadata until the partition reports a valid leader.
async fn wait_partition_leader(broker: SocketAddr) -> Result<()> {
    eventually(
        "kafka partition leader election",
        Duration::from_secs(30),
        Duration::from_millis(250),
        || async {
            let request = MetadataRequest::default().with_topics(Some(vec![
                MetadataRequestTopic::default().with_name(Some(topic_name().into())),
            ]));
            let response: MetadataResponse = match send(broker, ApiKey::Metadata, 1, request).await
            {
                Ok(response) => response,
                Err(_) => return Ok(None),
            };
            let ready = response.topics.first().is_some_and(|topic| {
                topic.error_code == 0
                    && topic
                        .partitions
                        .iter()
                        .any(|partition| partition.error_code == 0 && partition.leader_id.0 >= 0)
            });
            Ok(ready.then_some(()))
        },
    )
    .await
}

/// Produce one record with `acks=all` and return its assigned base offset.
async fn produce_one(broker: SocketAddr, sequence: u64) -> Result<i64> {
    let request = ProduceRequest::default()
        .with_acks(-1)
        .with_timeout_ms(10_000)
        .with_topic_data(vec![
            TopicProduceData::default()
                .with_name(topic_name().into())
                .with_partition_data(vec![
                    PartitionProduceData::default()
                        .with_index(PARTITION)
                        .with_records(Some(record_batch(sequence))),
                ]),
        ]);
    let response: ProduceResponse = send(broker, ApiKey::Produce, 3, request).await?;
    let partition = response
        .responses
        .first()
        .and_then(|topic| topic.partition_responses.first())
        .context("produce response missing partition")?;
    ensure!(
        partition.error_code == 0,
        "acks=all produce failed with error code {}",
        partition.error_code
    );
    Ok(partition.base_offset)
}

/// Fetch the whole partition from offset 0 and decode every record.
async fn consume_all(broker: SocketAddr) -> Result<Consumed> {
    let request = FetchRequest::default()
        .with_replica_id((-1).into())
        .with_max_wait_ms(500)
        .with_min_bytes(1)
        .with_max_bytes(64 * 1024 * 1024)
        .with_topics(vec![
            FetchTopic::default()
                .with_topic(topic_name().into())
                .with_partitions(vec![
                    FetchPartition::default()
                        .with_partition(PARTITION)
                        .with_fetch_offset(0)
                        .with_partition_max_bytes(64 * 1024 * 1024),
                ]),
        ]);
    let response: FetchResponse = send(broker, ApiKey::Fetch, 4, request).await?;
    let partition = response
        .responses
        .first()
        .and_then(|topic| topic.partitions.first())
        .context("fetch response missing partition")?;
    ensure!(
        partition.error_code == 0,
        "fetch failed with error code {}",
        partition.error_code
    );
    let mut offsets = Vec::new();
    if let Some(records) = &partition.records {
        let mut buffer = records.clone();
        let record_sets = RecordBatchDecoder::decode_all(&mut buffer)
            .map_err(|error| anyhow::anyhow!("record batch decode failed: {error}"))?;
        for record in record_sets.into_iter().flat_map(|set| set.records) {
            offsets.push(record.offset);
        }
    }
    Ok(Consumed {
        offsets,
        high_watermark: partition.high_watermark,
    })
}

fn record_batch(sequence: u64) -> Bytes {
    let mut value = BytesMut::new();
    value.put_u64(sequence);
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
        key: None,
        value: Some(value.freeze()),
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
    .expect("record batch encodes");
    encoded.freeze()
}

/// Issue one Kafka request over a fresh TCP connection and decode the response.
async fn send<T, R>(broker: SocketAddr, api_key: ApiKey, version: i16, body: T) -> Result<R>
where
    T: Encodable + HeaderVersion,
    R: Decodable + HeaderVersion,
{
    let mut stream = TcpStream::connect(broker)
        .await
        .with_context(|| format!("connect to kafka broker {broker}"))?;
    let mut payload = BytesMut::new();
    RequestHeader::default()
        .with_request_api_key(api_key as i16)
        .with_request_api_version(version)
        .with_correlation_id(1)
        .with_client_id(Some(StrBytes::from_static_str("pepper-system-test")))
        .encode(&mut payload, T::header_version(version))
        .map_err(|error| anyhow::anyhow!("request header encode failed: {error}"))?;
    body.encode(&mut payload, version)
        .map_err(|error| anyhow::anyhow!("request body encode failed: {error}"))?;
    let mut frame = BytesMut::with_capacity(payload.len() + 4);
    frame.put_i32(payload.len() as i32);
    frame.extend_from_slice(&payload);
    stream.write_all(&frame).await?;
    stream.flush().await?;

    let size = stream.read_i32().await?;
    if size < 4 {
        bail!("kafka response frame too small: {size}");
    }
    let mut response = BytesMut::zeroed(size as usize);
    stream.read_exact(&mut response).await?;
    let _header = ResponseHeader::decode(&mut response, R::header_version(version))
        .map_err(|error| anyhow::anyhow!("response header decode failed: {error}"))?;
    let decoded = R::decode(&mut response, version)
        .map_err(|error| anyhow::anyhow!("response body decode failed: {error}"))?;
    Ok(decoded)
}
