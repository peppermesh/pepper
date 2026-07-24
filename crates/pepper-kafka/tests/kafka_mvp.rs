// SPDX-License-Identifier: Apache-2.0

use bytes::{Buf, BufMut, Bytes, BytesMut};
use kafka_protocol::{
    messages::{
        AddOffsetsToTxnRequest, AddOffsetsToTxnResponse, AddPartitionsToTxnRequest,
        AddPartitionsToTxnResponse, ApiKey, ApiVersionsRequest, ApiVersionsResponse,
        ConsumerProtocolAssignment, CreateTopicsRequest, CreateTopicsResponse,
        DescribeGroupsRequest, DescribeGroupsResponse, EndTxnRequest, EndTxnResponse, FetchRequest,
        FetchResponse, GroupId, HeartbeatRequest, HeartbeatResponse, InitProducerIdRequest,
        InitProducerIdResponse, JoinGroupRequest, JoinGroupResponse, LeaveGroupRequest,
        LeaveGroupResponse, ListGroupsRequest, ListGroupsResponse, MetadataRequest,
        MetadataResponse, OffsetCommitRequest, OffsetCommitResponse, OffsetFetchRequest,
        OffsetFetchResponse, ProduceRequest, ProduceResponse, RequestHeader, ResponseHeader,
        SyncGroupRequest, SyncGroupResponse, TransactionalId, TxnOffsetCommitRequest,
        TxnOffsetCommitResponse,
        add_partitions_to_txn_request::AddPartitionsToTxnTopic,
        consumer_protocol_assignment::TopicPartition,
        create_topics_request::CreatableTopic,
        fetch_request::{FetchPartition, FetchTopic},
        join_group_request::JoinGroupRequestProtocol,
        metadata_request::MetadataRequestTopic,
        offset_commit_request::{OffsetCommitRequestPartition, OffsetCommitRequestTopic},
        offset_fetch_request::OffsetFetchRequestTopic,
        produce_request::{PartitionProduceData, TopicProduceData},
        sync_group_request::SyncGroupRequestAssignment,
        txn_offset_commit_request::{TxnOffsetCommitRequestPartition, TxnOffsetCommitRequestTopic},
    },
    protocol::{Decodable, Encodable, HeaderVersion, StrBytes},
    records::{Compression, Record, RecordBatchEncoder, RecordEncodeOptions, TimestampType},
};
use pepper_config::StorageLocationConfig;
use pepper_kafka::{
    KafkaCluster, KafkaError,
    server::{KafkaServer, KafkaServerConfig},
    tiering::ColdTier,
};
use pepper_kafka_protocol::{ADVERTISED_APIS, ProtocolLimits};
use pepper_metadata::MetadataStore;
use pepper_storage::BlockStore;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

async fn request<T, R>(
    address: SocketAddr,
    api_key: ApiKey,
    version: i16,
    correlation_id: i32,
    body: T,
    partial: bool,
) -> (ResponseHeader, R)
where
    T: Encodable + HeaderVersion,
    R: Decodable + HeaderVersion,
{
    let mut stream = TcpStream::connect(address).await.unwrap();
    let mut payload = BytesMut::new();
    RequestHeader::default()
        .with_request_api_key(api_key as i16)
        .with_request_api_version(version)
        .with_correlation_id(correlation_id)
        .with_client_id(Some(StrBytes::from_static_str("pepper-test")))
        .encode(&mut payload, T::header_version(version))
        .unwrap();
    body.encode(&mut payload, version).unwrap();
    let mut frame = BytesMut::with_capacity(payload.len() + 4);
    frame.put_i32(payload.len() as i32);
    frame.extend_from_slice(&payload);
    if partial {
        for chunk in frame.chunks(3) {
            stream.write_all(chunk).await.unwrap();
            tokio::task::yield_now().await;
        }
    } else {
        stream.write_all(&frame).await.unwrap();
    }
    receive::<R>(&mut stream, version).await
}

async fn receive<R: Decodable + HeaderVersion>(
    stream: &mut TcpStream,
    version: i16,
) -> (ResponseHeader, R) {
    let size = stream.read_i32().await.unwrap();
    assert!(size >= 4);
    let mut payload = BytesMut::zeroed(size as usize);
    stream.read_exact(&mut payload).await.unwrap();
    let header = ResponseHeader::decode(&mut payload, R::header_version(version)).unwrap();
    let response = R::decode(&mut payload, version).unwrap();
    assert!(!payload.has_remaining());
    (header, response)
}

fn frame<T: Encodable + HeaderVersion>(
    api_key: ApiKey,
    version: i16,
    correlation_id: i32,
    body: T,
) -> Bytes {
    let mut payload = BytesMut::new();
    RequestHeader::default()
        .with_request_api_key(api_key as i16)
        .with_request_api_version(version)
        .with_correlation_id(correlation_id)
        .with_client_id(Some(StrBytes::from_static_str("pepper-pipeline")))
        .encode(&mut payload, T::header_version(version))
        .unwrap();
    body.encode(&mut payload, version).unwrap();
    let mut frame = BytesMut::with_capacity(payload.len() + 4);
    frame.put_i32(payload.len() as i32);
    frame.extend_from_slice(&payload);
    frame.freeze()
}

fn record_batch(value: &'static [u8]) -> Bytes {
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
        value: Some(Bytes::from_static(value)),
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
    encoded.freeze()
}

fn keyed_record_batch(key: &'static [u8], value: Option<&'static [u8]>) -> Bytes {
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
        key: Some(Bytes::from_static(key)),
        value: value.map(Bytes::from_static),
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
    encoded.freeze()
}

fn producer_record_batch(
    value: &'static [u8],
    producer_id: i64,
    producer_epoch: i16,
    sequence: i32,
    transactional: bool,
) -> Bytes {
    let record = Record {
        transactional,
        control: false,
        partition_leader_epoch: -1,
        producer_id,
        producer_epoch,
        timestamp_type: TimestampType::Creation,
        timestamp: 100,
        sequence,
        offset: 0,
        key: None,
        value: Some(Bytes::from_static(value)),
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
    encoded.freeze()
}

fn extent_file_count(root: &std::path::Path) -> usize {
    std::fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .map(|path| {
            if path.is_dir() {
                extent_file_count(&path)
            } else {
                usize::from(
                    path.extension()
                        .is_some_and(|extension| extension == "extent"),
                )
            }
        })
        .sum()
}

async fn start_cluster() -> (
    TempDir,
    Arc<KafkaCluster>,
    Vec<SocketAddr>,
    Vec<JoinHandle<()>>,
) {
    let directory = tempfile::tempdir().unwrap();
    let mut listeners = Vec::new();
    let mut addresses = Vec::new();
    for _ in 0..3 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        addresses.push(listener.local_addr().unwrap());
        listeners.push(listener);
    }
    let brokers = addresses
        .iter()
        .enumerate()
        .map(|(id, address)| (id as i32, address.ip().to_string(), address.port()))
        .collect();
    let cluster = KafkaCluster::open(
        directory.path(),
        "pepper-phase8",
        0,
        brokers,
        ProtocolLimits::default(),
    )
    .await
    .unwrap();
    let mut tasks = Vec::new();
    for (broker_id, listener) in listeners.into_iter().enumerate() {
        let server = Arc::new(
            KafkaServer::new(
                broker_id as i32,
                Arc::clone(&cluster),
                KafkaServerConfig {
                    request_timeout: Duration::from_secs(2),
                    write_timeout: Duration::from_secs(2),
                    ..KafkaServerConfig::default()
                },
            )
            .unwrap(),
        );
        tasks.push(tokio::spawn(async move {
            let _ = server.serve(listener).await;
        }));
    }
    (directory, cluster, addresses, tasks)
}

#[tokio::test]
async fn tcp_client_flow_and_failover_preserve_the_acknowledged_prefix() {
    let (_directory, cluster, addresses, tasks) = start_cluster().await;

    let (header, versions): (_, ApiVersionsResponse) = request(
        addresses[0],
        ApiKey::ApiVersions,
        3,
        11,
        ApiVersionsRequest::default()
            .with_client_software_name(StrBytes::from_static_str("pepper-test"))
            .with_client_software_version(StrBytes::from_static_str("1")),
        true,
    )
    .await;
    assert_eq!(header.correlation_id, 11);
    assert_eq!(versions.error_code, 0);
    assert_eq!(versions.api_keys.len(), ADVERTISED_APIS.len());

    let (_, created): (_, CreateTopicsResponse) = request(
        addresses[0],
        ApiKey::CreateTopics,
        0,
        12,
        CreateTopicsRequest::default()
            .with_topics(vec![
                CreatableTopic::default()
                    .with_name(StrBytes::from_static_str("events").into())
                    .with_num_partitions(1)
                    .with_replication_factor(3),
            ])
            .with_timeout_ms(5_000),
        false,
    )
    .await;
    assert_eq!(created.topics[0].error_code, 0);

    let first = record_batch(b"first");
    let (_, produced): (_, ProduceResponse) = request(
        addresses[0],
        ApiKey::Produce,
        3,
        13,
        ProduceRequest::default()
            .with_acks(-1)
            .with_timeout_ms(5_000)
            .with_topic_data(vec![
                TopicProduceData::default()
                    .with_name(StrBytes::from_static_str("events").into())
                    .with_partition_data(vec![
                        PartitionProduceData::default()
                            .with_index(0)
                            .with_records(Some(first)),
                    ]),
            ]),
        false,
    )
    .await;
    assert_eq!(produced.responses[0].partition_responses[0].error_code, 0);
    assert_eq!(produced.responses[0].partition_responses[0].base_offset, 0);

    let (_, fetched): (_, FetchResponse) = request(
        addresses[0],
        ApiKey::Fetch,
        4,
        14,
        FetchRequest::default()
            .with_replica_id((-1).into())
            .with_max_wait_ms(100)
            .with_min_bytes(1)
            .with_max_bytes(1024 * 1024)
            .with_topics(vec![
                FetchTopic::default()
                    .with_topic(StrBytes::from_static_str("events").into())
                    .with_partitions(vec![
                        FetchPartition::default()
                            .with_partition(0)
                            .with_fetch_offset(0)
                            .with_partition_max_bytes(1024 * 1024),
                    ]),
            ]),
        false,
    )
    .await;
    let partition = &fetched.responses[0].partitions[0];
    assert_eq!(partition.error_code, 0);
    assert_eq!(partition.high_watermark, 1);
    assert!(
        partition
            .records
            .as_ref()
            .is_some_and(|records| !records.is_empty())
    );

    cluster.elect_leader("events", 0, 1).await.unwrap();
    let (_, stale): (_, ProduceResponse) = request(
        addresses[0],
        ApiKey::Produce,
        3,
        15,
        ProduceRequest::default()
            .with_acks(-1)
            .with_timeout_ms(5_000)
            .with_topic_data(vec![
                TopicProduceData::default()
                    .with_name(StrBytes::from_static_str("events").into())
                    .with_partition_data(vec![
                        PartitionProduceData::default()
                            .with_index(0)
                            .with_records(Some(record_batch(b"stale"))),
                    ]),
            ]),
        false,
    )
    .await;
    assert_eq!(stale.responses[0].partition_responses[0].error_code, 6);

    let (_, metadata): (_, MetadataResponse) = request(
        addresses[0],
        ApiKey::Metadata,
        1,
        16,
        MetadataRequest::default().with_topics(Some(vec![
            MetadataRequestTopic::default()
                .with_name(Some(StrBytes::from_static_str("events").into())),
        ])),
        false,
    )
    .await;
    assert_eq!(metadata.topics[0].partitions[0].leader_id, 1);

    let (_, second): (_, ProduceResponse) = request(
        addresses[1],
        ApiKey::Produce,
        3,
        17,
        ProduceRequest::default()
            .with_acks(-1)
            .with_timeout_ms(5_000)
            .with_topic_data(vec![
                TopicProduceData::default()
                    .with_name(StrBytes::from_static_str("events").into())
                    .with_partition_data(vec![
                        PartitionProduceData::default()
                            .with_index(0)
                            .with_records(Some(record_batch(b"second"))),
                    ]),
            ]),
        false,
    )
    .await;
    assert_eq!(second.responses[0].partition_responses[0].base_offset, 1);

    let direct = cluster.fetch(1, "events", 0, 0, 1024 * 1024).await.unwrap();
    assert_eq!(direct.high_watermark, 2);
    assert_eq!(direct.batches.len(), 2);

    for task in tasks {
        task.abort();
    }
}

#[tokio::test]
async fn tcp_classic_group_lifecycle_fences_and_persists_offsets() {
    let (_directory, cluster, addresses, tasks) = start_cluster().await;
    let group: GroupId = StrBytes::from_static_str("phase10-group").into();

    let (_, joined): (_, JoinGroupResponse) = request(
        addresses[1],
        ApiKey::JoinGroup,
        0,
        101,
        JoinGroupRequest::default()
            .with_group_id(group.clone())
            .with_session_timeout_ms(10_000)
            .with_member_id(StrBytes::from_static_str(""))
            .with_protocol_type(StrBytes::from_static_str("consumer"))
            .with_protocols(vec![
                JoinGroupRequestProtocol::default()
                    .with_name(StrBytes::from_static_str("range"))
                    .with_metadata(Bytes::from_static(b"subscription")),
            ]),
        false,
    )
    .await;
    assert_eq!(joined.error_code, 0);
    assert_eq!(joined.generation_id, 1);
    assert!(!joined.member_id.is_empty());

    let mut assignment = BytesMut::new();
    assignment.put_i16(0);
    ConsumerProtocolAssignment::default()
        .with_assigned_partitions(vec![
            TopicPartition::default()
                .with_topic(StrBytes::from_static_str("events").into())
                .with_partitions(vec![0]),
        ])
        .encode(&mut assignment, 0)
        .unwrap();
    let assignment = assignment.freeze();

    let (_, synced): (_, SyncGroupResponse) = request(
        addresses[2],
        ApiKey::SyncGroup,
        0,
        102,
        SyncGroupRequest::default()
            .with_group_id(group.clone())
            .with_generation_id(joined.generation_id)
            .with_member_id(joined.member_id.clone())
            .with_assignments(vec![
                SyncGroupRequestAssignment::default()
                    .with_member_id(joined.member_id.clone())
                    .with_assignment(assignment.clone()),
            ]),
        false,
    )
    .await;
    assert_eq!(synced.error_code, 0);
    assert_eq!(synced.assignment, assignment);

    let (_, heartbeat): (_, HeartbeatResponse) = request(
        addresses[0],
        ApiKey::Heartbeat,
        0,
        103,
        HeartbeatRequest::default()
            .with_group_id(group.clone())
            .with_generation_id(joined.generation_id)
            .with_member_id(joined.member_id.clone()),
        false,
    )
    .await;
    assert_eq!(heartbeat.error_code, 0);
    let (_, fenced): (_, HeartbeatResponse) = request(
        addresses[0],
        ApiKey::Heartbeat,
        0,
        104,
        HeartbeatRequest::default()
            .with_group_id(group.clone())
            .with_generation_id(joined.generation_id + 1)
            .with_member_id(joined.member_id.clone()),
        false,
    )
    .await;
    assert_eq!(fenced.error_code, 22);

    let (_, committed): (_, OffsetCommitResponse) = request(
        addresses[0],
        ApiKey::OffsetCommit,
        2,
        105,
        OffsetCommitRequest::default()
            .with_group_id(group.clone())
            .with_generation_id_or_member_epoch(joined.generation_id)
            .with_member_id(joined.member_id.clone())
            .with_retention_time_ms(60_000)
            .with_topics(vec![
                OffsetCommitRequestTopic::default()
                    .with_name(StrBytes::from_static_str("events").into())
                    .with_partitions(vec![
                        OffsetCommitRequestPartition::default()
                            .with_partition_index(0)
                            .with_committed_offset(42)
                            .with_committed_metadata(Some(StrBytes::from_static_str("checkpoint"))),
                    ]),
            ]),
        false,
    )
    .await;
    assert_eq!(committed.topics[0].partitions[0].error_code, 0);

    let (_, fetched): (_, OffsetFetchResponse) = request(
        addresses[2],
        ApiKey::OffsetFetch,
        1,
        106,
        OffsetFetchRequest::default()
            .with_group_id(group.clone())
            .with_topics(Some(vec![
                OffsetFetchRequestTopic::default()
                    .with_name(StrBytes::from_static_str("events").into())
                    .with_partition_indexes(vec![0]),
            ])),
        false,
    )
    .await;
    assert_eq!(fetched.topics[0].partitions[0].committed_offset, 42);

    let (_, described): (_, DescribeGroupsResponse) = request(
        addresses[0],
        ApiKey::DescribeGroups,
        0,
        107,
        DescribeGroupsRequest::default().with_groups(vec![group.clone()]),
        false,
    )
    .await;
    assert_eq!(described.groups[0].error_code, 0);
    assert_eq!(described.groups[0].group_state.as_str(), "Stable");
    let (_, listed): (_, ListGroupsResponse) = request(
        addresses[0],
        ApiKey::ListGroups,
        0,
        108,
        ListGroupsRequest::default(),
        false,
    )
    .await;
    assert!(listed.groups.iter().any(|listed| listed.group_id == group));

    let (_, left): (_, LeaveGroupResponse) = request(
        addresses[0],
        ApiKey::LeaveGroup,
        0,
        109,
        LeaveGroupRequest::default()
            .with_group_id(group)
            .with_member_id(joined.member_id),
        false,
    )
    .await;
    assert_eq!(left.error_code, 0);
    assert_eq!(
        cluster.groups().offsets("phase10-group").await.unwrap()
            [&pepper_kafka::groups::OffsetKey {
                group: "phase10-group".into(),
                topic: "events".into(),
                partition: 0,
            }]
            .offset,
        42
    );
    for task in tasks {
        task.abort();
    }
}

#[tokio::test]
async fn idempotent_retry_epoch_fence_and_read_committed_abort_are_exact() {
    let (_directory, cluster, addresses, tasks) = start_cluster().await;
    cluster
        .create_topic("transactions".into(), 1, 3, Default::default(), false)
        .await
        .unwrap();
    let producer = cluster
        .transactions()
        .init_producer(Some("phase11".into()), 60_000, 0)
        .await
        .unwrap();
    cluster
        .transactions()
        .add_partitions(
            producer,
            [pepper_kafka::transactions::TransactionPartition::new(
                "transactions",
                0,
            )],
            0,
        )
        .await
        .unwrap();
    let batch = producer_record_batch(
        b"aborted",
        producer.producer_id,
        producer.producer_epoch,
        0,
        true,
    );
    let first = cluster
        .produce(
            0,
            "transactions",
            0,
            1,
            batch.clone(),
            pepper_ordered_log::Acknowledgments::All,
        )
        .await
        .unwrap();
    let duplicate = cluster
        .produce(
            0,
            "transactions",
            0,
            1,
            batch.clone(),
            pepper_ordered_log::Acknowledgments::All,
        )
        .await
        .unwrap();
    assert_eq!(first.result.base_offset, 0);
    assert_eq!(duplicate.result.base_offset, 0);
    assert_eq!(duplicate.result.durable_media_appends, 0);
    assert_eq!(cluster.offsets(0, "transactions", 0).await.unwrap().2, 1);

    let fetch = FetchRequest::default()
        .with_max_wait_ms(0)
        .with_min_bytes(0)
        .with_max_bytes(1024 * 1024)
        .with_isolation_level(1)
        .with_topics(vec![
            FetchTopic::default()
                .with_topic(StrBytes::from_static_str("transactions").into())
                .with_partitions(vec![
                    FetchPartition::default()
                        .with_partition(0)
                        .with_fetch_offset(0)
                        .with_partition_max_bytes(1024 * 1024),
                ]),
        ]);
    let (_, pending): (_, FetchResponse) =
        request(addresses[0], ApiKey::Fetch, 4, 201, fetch.clone(), false).await;
    assert_eq!(pending.responses[0].partitions[0].last_stable_offset, 0);
    assert!(
        pending.responses[0].partitions[0]
            .records
            .as_ref()
            .is_none_or(Bytes::is_empty)
    );

    cluster
        .transactions()
        .end_transaction(producer, false)
        .await
        .unwrap();
    let (_, aborted): (_, FetchResponse) =
        request(addresses[0], ApiKey::Fetch, 4, 202, fetch, false).await;
    let partition = &aborted.responses[0].partitions[0];
    assert_eq!(partition.last_stable_offset, 1);
    let aborted_transactions = partition.aborted_transactions.as_ref().unwrap();
    assert_eq!(aborted_transactions.len(), 1);
    assert_eq!(aborted_transactions[0].producer_id.0, producer.producer_id);
    assert_eq!(aborted_transactions[0].first_offset, 0);
    assert!(
        partition
            .records
            .as_ref()
            .is_some_and(|records| !records.is_empty())
    );

    let next = cluster
        .transactions()
        .init_producer(Some("phase11".into()), 60_000, 0)
        .await
        .unwrap();
    assert!(matches!(
        cluster
            .produce(
                0,
                "transactions",
                0,
                2,
                batch,
                pepper_ordered_log::Acknowledgments::All,
            )
            .await,
        Err(KafkaError::Transaction(
            pepper_kafka::transactions::TransactionError::FencedProducer
        ))
    ));
    assert_eq!(next.producer_id, producer.producer_id);
    for task in tasks {
        task.abort();
    }
}

#[tokio::test]
async fn tcp_transactional_offset_commit_is_visible_only_after_end_txn() {
    let (_directory, _cluster, addresses, tasks) = start_cluster().await;
    let transactional_id: TransactionalId = StrBytes::from_static_str("phase11-offsets").into();
    let (_, initialized): (_, InitProducerIdResponse) = request(
        addresses[0],
        ApiKey::InitProducerId,
        0,
        301,
        InitProducerIdRequest::default()
            .with_transactional_id(Some(transactional_id.clone()))
            .with_transaction_timeout_ms(60_000),
        false,
    )
    .await;
    assert_eq!(initialized.error_code, 0);

    let (_, added): (_, AddPartitionsToTxnResponse) = request(
        addresses[0],
        ApiKey::AddPartitionsToTxn,
        0,
        302,
        AddPartitionsToTxnRequest::default()
            .with_v3_and_below_transactional_id(transactional_id.clone())
            .with_v3_and_below_producer_id(initialized.producer_id)
            .with_v3_and_below_producer_epoch(initialized.producer_epoch)
            .with_v3_and_below_topics(vec![
                AddPartitionsToTxnTopic::default()
                    .with_name(StrBytes::from_static_str("events").into())
                    .with_partitions(vec![0]),
            ]),
        false,
    )
    .await;
    assert_eq!(
        added.results_by_topic_v3_and_below[0].results_by_partition[0].partition_error_code,
        0
    );

    let (_, offsets_added): (_, AddOffsetsToTxnResponse) = request(
        addresses[0],
        ApiKey::AddOffsetsToTxn,
        0,
        303,
        AddOffsetsToTxnRequest::default()
            .with_transactional_id(transactional_id.clone())
            .with_producer_id(initialized.producer_id)
            .with_producer_epoch(initialized.producer_epoch)
            .with_group_id(StrBytes::from_static_str("phase11-group").into()),
        false,
    )
    .await;
    assert_eq!(offsets_added.error_code, 0);

    let (_, staged): (_, TxnOffsetCommitResponse) = request(
        addresses[0],
        ApiKey::TxnOffsetCommit,
        0,
        304,
        TxnOffsetCommitRequest::default()
            .with_transactional_id(transactional_id.clone())
            .with_group_id(StrBytes::from_static_str("phase11-group").into())
            .with_producer_id(initialized.producer_id)
            .with_producer_epoch(initialized.producer_epoch)
            .with_topics(vec![
                TxnOffsetCommitRequestTopic::default()
                    .with_name(StrBytes::from_static_str("events").into())
                    .with_partitions(vec![
                        TxnOffsetCommitRequestPartition::default()
                            .with_partition_index(0)
                            .with_committed_offset(42)
                            .with_committed_metadata(Some(StrBytes::from_static_str("atomic"))),
                    ]),
            ]),
        false,
    )
    .await;
    assert_eq!(staged.topics[0].partitions[0].error_code, 0);

    let offset_request = OffsetFetchRequest::default()
        .with_group_id(StrBytes::from_static_str("phase11-group").into())
        .with_topics(Some(vec![
            OffsetFetchRequestTopic::default()
                .with_name(StrBytes::from_static_str("events").into())
                .with_partition_indexes(vec![0]),
        ]));
    let (_, before): (_, OffsetFetchResponse) = request(
        addresses[0],
        ApiKey::OffsetFetch,
        1,
        305,
        offset_request.clone(),
        false,
    )
    .await;
    assert_eq!(before.topics[0].partitions[0].committed_offset, -1);

    let (_, ended): (_, EndTxnResponse) = request(
        addresses[0],
        ApiKey::EndTxn,
        0,
        306,
        EndTxnRequest::default()
            .with_transactional_id(transactional_id)
            .with_producer_id(initialized.producer_id)
            .with_producer_epoch(initialized.producer_epoch)
            .with_committed(true),
        false,
    )
    .await;
    assert_eq!(ended.error_code, 0);
    let (_, after): (_, OffsetFetchResponse) = request(
        addresses[0],
        ApiKey::OffsetFetch,
        1,
        307,
        offset_request,
        false,
    )
    .await;
    assert_eq!(after.topics[0].partitions[0].committed_offset, 42);
    assert_eq!(
        after.topics[0].partitions[0]
            .metadata
            .as_ref()
            .map(StrBytes::as_str),
        Some("atomic")
    );
    for task in tasks {
        task.abort();
    }
}

#[tokio::test]
async fn controller_and_partition_state_survive_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let brokers = vec![(0, "127.0.0.1".to_string(), 19092)];
    let cluster = KafkaCluster::open(
        directory.path(),
        "restart",
        0,
        brokers.clone(),
        ProtocolLimits::default(),
    )
    .await
    .unwrap();
    let topic = cluster
        .create_topic("durable".into(), 1, 1, Default::default(), false)
        .await
        .unwrap();
    cluster
        .produce(
            0,
            "durable",
            0,
            1,
            record_batch(b"persisted"),
            pepper_ordered_log::Acknowledgments::All,
        )
        .await
        .unwrap();
    let topic_id = topic.topic_id;
    drop(cluster);

    let reopened = KafkaCluster::open(
        directory.path(),
        "restart",
        0,
        brokers,
        ProtocolLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.controller_state().await.topics["durable"].topic_id,
        topic_id
    );
    let fetched = reopened
        .fetch(0, "durable", 0, 0, 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(fetched.high_watermark, 1);
    assert_eq!(fetched.batches.len(), 1);
}

#[tokio::test]
async fn tcp_connection_matrix_pipeline_and_timeout_are_bounded() {
    let (_directory, _cluster, addresses, tasks) = start_cluster().await;
    for concurrency in [1usize, 8, 32, 256] {
        let mut clients = Vec::new();
        for correlation in 0..concurrency {
            let address = addresses[0];
            clients.push(tokio::spawn(async move {
                let (header, response): (_, ApiVersionsResponse) = request(
                    address,
                    ApiKey::ApiVersions,
                    0,
                    correlation as i32,
                    ApiVersionsRequest::default(),
                    correlation % 2 == 0,
                )
                .await;
                assert_eq!(header.correlation_id, correlation as i32);
                assert_eq!(response.error_code, 0);
            }));
        }
        for client in clients {
            client.await.unwrap();
        }
    }

    let mut stream = TcpStream::connect(addresses[0]).await.unwrap();
    let first = frame(ApiKey::ApiVersions, 0, 700, ApiVersionsRequest::default());
    let second = frame(ApiKey::ApiVersions, 0, 701, ApiVersionsRequest::default());
    let mut pipeline = BytesMut::new();
    pipeline.extend_from_slice(&first);
    pipeline.extend_from_slice(&second);
    stream.write_all(&pipeline).await.unwrap();
    let (first_header, _): (_, ApiVersionsResponse) = receive(&mut stream, 0).await;
    let (second_header, _): (_, ApiVersionsResponse) = receive(&mut stream, 0).await;
    assert_eq!(
        (first_header.correlation_id, second_header.correlation_id),
        (700, 701)
    );

    let idle_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let idle_address = idle_listener.local_addr().unwrap();
    let idle_root = tempfile::tempdir().unwrap();
    let idle_cluster = KafkaCluster::open(
        idle_root.path(),
        "idle-timeout",
        0,
        vec![(0, "127.0.0.1".into(), idle_address.port())],
        ProtocolLimits::default(),
    )
    .await
    .unwrap();
    let idle_server = Arc::new(
        KafkaServer::new(
            0,
            idle_cluster,
            KafkaServerConfig {
                maximum_connections: 1,
                request_timeout: Duration::from_millis(25),
                write_timeout: Duration::from_millis(25),
                ..KafkaServerConfig::default()
            },
        )
        .unwrap(),
    );
    let idle_task = tokio::spawn(async move {
        let _ = idle_server.serve(idle_listener).await;
    });
    let mut idle = TcpStream::connect(idle_address).await.unwrap();
    tokio::time::sleep(Duration::from_millis(75)).await;
    let mut closed = [0u8; 1];
    assert_eq!(idle.read(&mut closed).await.unwrap(), 0);
    let (_, response): (_, ApiVersionsResponse) = request(
        idle_address,
        ApiKey::ApiVersions,
        0,
        702,
        ApiVersionsRequest::default(),
        false,
    )
    .await;
    assert_eq!(response.error_code, 0);
    idle_task.abort();

    for task in tasks {
        task.abort();
    }
}

#[tokio::test]
async fn configured_retention_advances_the_visible_log_start() {
    let directory = tempfile::tempdir().unwrap();
    let cluster = KafkaCluster::open(
        directory.path(),
        "retention",
        0,
        vec![(0, "127.0.0.1".into(), 19092)],
        ProtocolLimits::default(),
    )
    .await
    .unwrap();
    cluster
        .create_topic(
            "retained".into(),
            1,
            1,
            [
                ("segment.bytes".into(), "1".into()),
                ("retention.bytes".into(), "0".into()),
            ]
            .into_iter()
            .collect(),
            false,
        )
        .await
        .unwrap();
    for timestamp in [1, 2] {
        cluster
            .produce(
                0,
                "retained",
                0,
                timestamp,
                record_batch(b"retained"),
                pepper_ordered_log::Acknowledgments::All,
            )
            .await
            .unwrap();
    }
    assert_eq!(cluster.offsets(0, "retained", 0).await.unwrap().0, 1);
    assert!(matches!(
        cluster.fetch(0, "retained", 0, 0, 1024).await,
        Err(KafkaError::OrderedLog(
            pepper_ordered_log::OrderedLogError::OffsetBeforeLogStart {
                offset: 0,
                log_start: 1
            }
        ))
    ));
    assert_eq!(
        cluster
            .fetch(0, "retained", 0, 1, 1024)
            .await
            .unwrap()
            .batches
            .len(),
        1
    );
    assert_eq!(extent_file_count(directory.path()), 1);
    drop(cluster);
    let reopened = KafkaCluster::open(
        directory.path(),
        "retention",
        0,
        vec![(0, "127.0.0.1".into(), 19092)],
        ProtocolLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(reopened.offsets(0, "retained", 0).await.unwrap(), (1, 2, 2));
    assert_eq!(
        reopened
            .fetch(0, "retained", 0, 1, 1024)
            .await
            .unwrap()
            .batches
            .len(),
        1
    );
}

#[tokio::test]
async fn kafka_compaction_preserves_boundaries_and_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let brokers = vec![
        (0, "127.0.0.1".into(), 19092),
        (1, "127.0.0.1".into(), 19093),
        (2, "127.0.0.1".into(), 19094),
    ];
    let cluster = KafkaCluster::open(
        directory.path(),
        "compaction",
        0,
        brokers.clone(),
        ProtocolLimits::default(),
    )
    .await
    .unwrap();
    cluster
        .create_topic(
            "compacted".into(),
            1,
            3,
            [
                ("segment.bytes".into(), "280".into()),
                ("cleanup.policy".into(), "compact".into()),
                ("delete.retention.ms".into(), "1000".into()),
            ]
            .into_iter()
            .collect(),
            false,
        )
        .await
        .unwrap();
    for (timestamp, key, value) in [
        (1, b"a".as_slice(), Some(b"old-a".as_slice())),
        (2, b"b".as_slice(), Some(b"old-b".as_slice())),
        (3, b"c".as_slice(), Some(b"old-c".as_slice())),
        (4, b"a".as_slice(), Some(b"new-a".as_slice())),
        (5, b"b".as_slice(), Some(b"new-b".as_slice())),
        (6, b"c".as_slice(), Some(b"new-c".as_slice())),
        (7, b"tail".as_slice(), Some(b"tail".as_slice())),
    ] {
        cluster
            .produce(
                0,
                "compacted",
                0,
                timestamp,
                keyed_record_batch(key, value),
                pepper_ordered_log::Acknowledgments::All,
            )
            .await
            .unwrap();
    }
    let before = cluster.offsets(0, "compacted", 0).await.unwrap();
    let report = cluster
        .compact_partition("compacted", 0, 10_000)
        .await
        .unwrap();
    assert_eq!(
        (report.high_watermark_before, report.high_watermark_after),
        (before.1, before.1)
    );
    assert!(report.rewritten_replicas >= 3);
    assert!(report.reclaimed_payload_bytes > 0);
    let cold_root = tempfile::tempdir().unwrap();
    let cold_store = Arc::new(
        BlockStore::open(
            Arc::new(
                MetadataStore::open_or_create(cold_root.path().join("metadata.redb")).unwrap(),
            ),
            &[StorageLocationConfig {
                path: cold_root.path().join("blocks"),
                max_capacity_bytes: 64 * 1024 * 1024,
            }],
        )
        .unwrap(),
    );
    let cold = ColdTier::open(cold_root.path().join("catalog"), cold_store, 1024 * 1024).unwrap();
    let archived = cluster
        .archive_sealed_segment(&cold, "compacted", 0, 0, Some((3, 2)))
        .await
        .unwrap();
    assert!(archived.hot_replica_retained);
    assert_eq!(&cold.recall(&archived.key).unwrap()[..8], b"PEPKCOLD");
    drop(cluster);
    let reopened = KafkaCluster::open(
        directory.path(),
        "compaction",
        0,
        brokers,
        ProtocolLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(reopened.offsets(0, "compacted", 0).await.unwrap(), before);
    let fetched = reopened
        .fetch(0, "compacted", 0, 0, u64::MAX)
        .await
        .unwrap();
    assert!(fetched.batches.len() < 7);
}

#[tokio::test]
async fn long_poll_wakes_on_append_and_cleans_registration() {
    let (_directory, cluster, addresses, tasks) = start_cluster().await;
    cluster
        .create_topic("long-poll".into(), 1, 3, Default::default(), false)
        .await
        .unwrap();
    let address = addresses[0];
    let started = tokio::time::Instant::now();
    let fetch = tokio::spawn(async move {
        request::<_, FetchResponse>(
            address,
            ApiKey::Fetch,
            4,
            800,
            FetchRequest::default()
                .with_replica_id((-1).into())
                .with_max_wait_ms(2_000)
                .with_min_bytes(1)
                .with_max_bytes(1024 * 1024)
                .with_topics(vec![
                    FetchTopic::default()
                        .with_topic(StrBytes::from_static_str("long-poll").into())
                        .with_partitions(vec![
                            FetchPartition::default()
                                .with_partition(0)
                                .with_fetch_offset(0)
                                .with_partition_max_bytes(1024 * 1024),
                        ]),
                ]),
            false,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    cluster
        .produce(
            0,
            "long-poll",
            0,
            10,
            record_batch(b"wake"),
            pepper_ordered_log::Acknowledgments::All,
        )
        .await
        .unwrap();
    let (_, response) = fetch.await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(
        response.responses[0].partitions[0]
            .records
            .as_ref()
            .is_some_and(|records| !records.is_empty())
    );
    assert_eq!(cluster.fetch_waiters().snapshot().registered, 0);
    for task in tasks {
        task.abort();
    }
}

#[tokio::test]
async fn replica_recovery_reassignment_and_rolling_restart_preserve_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let cluster = KafkaCluster::open(
        directory.path(),
        "operations",
        0,
        vec![
            (0, "127.0.0.1".into(), 19092),
            (1, "127.0.0.1".into(), 19093),
            (2, "127.0.0.1".into(), 19094),
        ],
        ProtocolLimits::default(),
    )
    .await
    .unwrap();
    cluster
        .create_topic("operations".into(), 1, 3, Default::default(), false)
        .await
        .unwrap();
    cluster
        .produce(
            0,
            "operations",
            0,
            1,
            record_batch(b"one"),
            pepper_ordered_log::Acknowledgments::All,
        )
        .await
        .unwrap();
    cluster
        .set_replica_online("operations", 0, 2, false)
        .await
        .unwrap();
    let second = cluster
        .produce(
            0,
            "operations",
            0,
            2,
            record_batch(b"two"),
            pepper_ordered_log::Acknowledgments::Leader,
        )
        .await
        .unwrap();
    assert_eq!(second.result.high_watermark, 2);
    cluster
        .set_replica_online("operations", 0, 2, true)
        .await
        .unwrap();
    cluster
        .rolling_restart_replica("operations", 0, 1)
        .await
        .unwrap();
    let updated = cluster
        .reassign_partition("operations", 0, vec![0, 1])
        .await
        .unwrap();
    assert_eq!(updated.replicas, vec![0, 1]);
    let diagnostics = cluster.diagnostics(10).await.unwrap();
    assert_eq!(diagnostics.partitions[0].high_watermark, 2);
    assert_eq!(diagnostics.partitions[0].in_sync_replicas, vec![0, 1]);
    let third = cluster
        .produce(
            0,
            "operations",
            0,
            3,
            record_batch(b"three"),
            pepper_ordered_log::Acknowledgments::All,
        )
        .await
        .unwrap();
    assert!(third.acknowledged);
    assert_eq!(
        cluster
            .fetch(0, "operations", 0, 0, 1024 * 1024)
            .await
            .unwrap()
            .batches
            .len(),
        3
    );
}
