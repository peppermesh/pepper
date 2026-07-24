// SPDX-License-Identifier: Apache-2.0

//! Kafka TCP listener and request dispatcher.

use crate::{
    KafkaCluster, KafkaError,
    groups::{GroupCommand, GroupError, GroupPhase, GroupResponse},
    operations::{PartitionKey, QuotaConfig, QuotaManager, QuotaSnapshot, WaiterSnapshot},
    security::{AclOperation, KafkaSecurity, ResourceType, SaslSession, SecurityError},
    transactions::{PendingOffset, ProducerIdentity, TransactionError, TransactionPartition},
};
use bytes::{BufMut, Bytes, BytesMut};
use kafka_protocol::{
    ResponseError,
    messages::{
        RequestKind, ResponseKind,
        add_offsets_to_txn_response::AddOffsetsToTxnResponse,
        add_partitions_to_txn_response::{
            AddPartitionsToTxnPartitionResult, AddPartitionsToTxnResponse,
            AddPartitionsToTxnTopicResult,
        },
        alter_configs_response::{AlterConfigsResourceResponse, AlterConfigsResponse},
        api_versions_response::{ApiVersion, ApiVersionsResponse},
        create_topics_response::{CreatableTopicResult, CreateTopicsResponse},
        delete_topics_response::{DeletableTopicResult, DeleteTopicsResponse},
        describe_cluster_response::{DescribeClusterBroker, DescribeClusterResponse},
        describe_configs_response::{
            DescribeConfigsResourceResult, DescribeConfigsResponse, DescribeConfigsResult,
        },
        describe_groups_response::{DescribeGroupsResponse, DescribedGroup, DescribedGroupMember},
        end_txn_response::EndTxnResponse,
        find_coordinator_response::FindCoordinatorResponse,
        heartbeat_response::HeartbeatResponse,
        init_producer_id_response::InitProducerIdResponse,
        join_group_response::{JoinGroupResponse, JoinGroupResponseMember},
        leave_group_response::LeaveGroupResponse,
        list_groups_response::{ListGroupsResponse, ListedGroup},
        list_offsets_response::{
            ListOffsetsPartitionResponse, ListOffsetsResponse, ListOffsetsTopicResponse,
        },
        metadata_response::{
            MetadataResponse, MetadataResponseBroker, MetadataResponsePartition,
            MetadataResponseTopic,
        },
        offset_commit_response::{
            OffsetCommitResponse, OffsetCommitResponsePartition, OffsetCommitResponseTopic,
        },
        offset_fetch_response::{
            OffsetFetchResponse, OffsetFetchResponsePartition, OffsetFetchResponseTopic,
        },
        produce_response::{PartitionProduceResponse, ProduceResponse, TopicProduceResponse},
        sasl_authenticate_response::SaslAuthenticateResponse,
        sasl_handshake_response::SaslHandshakeResponse,
        sync_group_response::SyncGroupResponse,
        txn_offset_commit_response::{
            TxnOffsetCommitResponse, TxnOffsetCommitResponsePartition, TxnOffsetCommitResponseTopic,
        },
    },
    protocol::StrBytes,
};
use pepper_buffer::{AtomicByteBudget, BufferError, ByteBudgetSnapshot};
use pepper_kafka_protocol::{
    ADVERTISED_APIS, DecodedRequest, ProtocolError, decode_request, encode_response,
    encode_response_kind,
};
use pepper_ordered_log::Acknowledgments;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

#[derive(Clone)]
pub struct KafkaTlsConfig {
    server: Arc<rustls::ServerConfig>,
}

impl std::fmt::Debug for KafkaTlsConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KafkaTlsConfig")
            .field("protocol", &"TLSv1.3")
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl KafkaTlsConfig {
    pub fn from_der(
        certificate_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
    ) -> Result<Self, ServerError> {
        install_crypto_provider();
        let certificates = certificate_chain
            .into_iter()
            .map(rustls::pki_types::CertificateDer::from)
            .collect();
        let private_key = rustls::pki_types::PrivateKeyDer::try_from(private_key)
            .map_err(|_| ServerError::InvalidTls)?;
        let server =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(certificates, private_key)
                .map_err(|_| ServerError::InvalidTls)?;
        Ok(Self {
            server: Arc::new(server),
        })
    }

    pub fn from_der_with_client_roots(
        certificate_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
        client_roots: rustls::RootCertStore,
    ) -> Result<Self, ServerError> {
        install_crypto_provider();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|_| ServerError::InvalidTls)?;
        let certificates = certificate_chain
            .into_iter()
            .map(rustls::pki_types::CertificateDer::from)
            .collect();
        let private_key = rustls::pki_types::PrivateKeyDer::try_from(private_key)
            .map_err(|_| ServerError::InvalidTls)?;
        let server =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_client_cert_verifier(verifier)
                .with_single_cert(certificates, private_key)
                .map_err(|_| ServerError::InvalidTls)?;
        Ok(Self {
            server: Arc::new(server),
        })
    }
}

#[derive(Debug, Clone)]
pub struct KafkaServerConfig {
    pub maximum_connections: usize,
    pub request_timeout: Duration,
    pub write_timeout: Duration,
    pub maximum_inflight_response_bytes: usize,
    pub quota: QuotaConfig,
    /// Qualification hook for measuring the exact admission cost. Production
    /// configurations must leave this enabled.
    pub enforce_response_budget: bool,
    pub tls: Option<KafkaTlsConfig>,
    pub security: Option<Arc<KafkaSecurity>>,
}

impl Default for KafkaServerConfig {
    fn default() -> Self {
        Self {
            maximum_connections: 10_000,
            request_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            maximum_inflight_response_bytes: 512 * 1024 * 1024,
            quota: QuotaConfig::default(),
            enforce_response_budget: true,
            tls: None,
            security: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct KafkaServerMetrics {
    pub accepted_connections: AtomicU64,
    pub rejected_connections: AtomicU64,
    pub active_connections: AtomicU64,
    pub completed_requests: AtomicU64,
    pub failed_requests: AtomicU64,
    pub ingress_bytes: AtomicU64,
    pub egress_bytes: AtomicU64,
    pub quota_throttles: AtomicU64,
    pub protocol_payload_copies: AtomicU64,
}

pub struct KafkaServer {
    broker_id: i32,
    cluster: Arc<KafkaCluster>,
    config: KafkaServerConfig,
    connections: Arc<Semaphore>,
    metrics: Arc<KafkaServerMetrics>,
    response_budget: AtomicByteBudget,
    unreserved_response_bytes: usize,
    quotas: QuotaManager,
    tls: Option<TlsAcceptor>,
    security: Option<Arc<KafkaSecurity>>,
}

impl KafkaServer {
    pub fn new(
        broker_id: i32,
        cluster: Arc<KafkaCluster>,
        config: KafkaServerConfig,
    ) -> Result<Self, ServerError> {
        if config.maximum_connections == 0
            || config.request_timeout.is_zero()
            || config.write_timeout.is_zero()
            || config.maximum_inflight_response_bytes == 0
        {
            return Err(ServerError::InvalidConfiguration);
        }
        if config.security.is_some() && config.tls.is_none() {
            return Err(ServerError::SecurityRequiresTls);
        }
        let maximum_frame_bytes = cluster.protocol_limits().maximum_frame_bytes;
        if config.maximum_inflight_response_bytes < maximum_frame_bytes {
            return Err(ServerError::InvalidConfiguration);
        }
        let unreserved_response_bytes = config
            .maximum_inflight_response_bytes
            .saturating_sub(maximum_frame_bytes)
            / config.maximum_connections;
        let dynamic_response_bytes = config
            .maximum_inflight_response_bytes
            .saturating_sub(unreserved_response_bytes.saturating_mul(config.maximum_connections));
        let response_budget = AtomicByteBudget::new(dynamic_response_bytes)?;
        let quotas = QuotaManager::new(config.quota);
        let tls = config
            .tls
            .as_ref()
            .map(|tls| TlsAcceptor::from(Arc::clone(&tls.server)));
        let security = config.security.clone();
        Ok(Self {
            broker_id,
            cluster,
            connections: Arc::new(Semaphore::new(config.maximum_connections)),
            config,
            metrics: Arc::new(KafkaServerMetrics::default()),
            response_budget,
            unreserved_response_bytes,
            quotas,
            tls,
            security,
        })
    }

    pub fn metrics(&self) -> Arc<KafkaServerMetrics> {
        Arc::clone(&self.metrics)
    }

    pub fn operations_snapshot(&self) -> (WaiterSnapshot, QuotaSnapshot, ByteBudgetSnapshot) {
        (
            self.cluster.fetch_waiters().snapshot(),
            self.quotas.snapshot(),
            self.response_budget.snapshot(),
        )
    }

    /// Bounded-cardinality broker metrics suitable for Pepper's Prometheus
    /// collector. Per-partition detail remains in the on-demand diagnostics
    /// snapshot instead of becoming an unbounded metric label.
    pub fn prometheus_metrics(&self) -> String {
        let (waiters, quotas, responses) = self.operations_snapshot();
        format!(
            concat!(
                "pepper_kafka_connections_active {}\n",
                "pepper_kafka_connections_rejected_total {}\n",
                "pepper_kafka_requests_completed_total {}\n",
                "pepper_kafka_requests_failed_total {}\n",
                "pepper_kafka_ingress_bytes_total {}\n",
                "pepper_kafka_egress_bytes_total {}\n",
                "pepper_kafka_fetch_waiters {}\n",
                "pepper_kafka_fetch_waiter_wakeups_total {}\n",
                "pepper_kafka_fetch_waiter_deadlines_total {}\n",
                "pepper_kafka_quota_throttles_total {}\n",
                "pepper_kafka_response_bytes_inflight {}\n",
                "pepper_kafka_response_bytes_high_water {}\n",
                "pepper_kafka_response_budget_rejections_total {}\n",
                "pepper_kafka_protocol_payload_copies_total {}\n"
            ),
            self.metrics.active_connections.load(Ordering::Relaxed),
            self.metrics.rejected_connections.load(Ordering::Relaxed),
            self.metrics.completed_requests.load(Ordering::Relaxed),
            self.metrics.failed_requests.load(Ordering::Relaxed),
            self.metrics.ingress_bytes.load(Ordering::Relaxed),
            self.metrics.egress_bytes.load(Ordering::Relaxed),
            waiters.registered,
            waiters.data_wakeups,
            waiters.deadline_wakeups,
            quotas.throttled_requests,
            responses.in_use_bytes,
            responses.high_water_bytes,
            responses.rejections,
            self.metrics.protocol_payload_copies.load(Ordering::Relaxed),
        )
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<(), ServerError> {
        loop {
            let (stream, peer) = listener.accept().await?;
            stream.set_nodelay(true)?;
            let permit = match Arc::clone(&self.connections).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    self.metrics
                        .rejected_connections
                        .fetch_add(1, Ordering::Relaxed);
                    drop(stream);
                    continue;
                }
            };
            self.metrics
                .accepted_connections
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .active_connections
                .fetch_add(1, Ordering::Relaxed);
            let server = Arc::clone(&self);
            tokio::spawn(async move {
                let result = if let Some(acceptor) = &server.tls {
                    match timeout(server.config.request_timeout, acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => {
                            let principal = stream
                                .get_ref()
                                .1
                                .peer_certificates()
                                .and_then(|certificates| certificates.first())
                                .map(|certificate| {
                                    format!(
                                        "mtls:{}",
                                        hex::encode(blake3::hash(certificate.as_ref()).as_bytes())
                                    )
                                });
                            server.connection(stream, peer, permit, principal).await
                        }
                        Ok(Err(_)) => Err(ServerError::TlsHandshake),
                        Err(_) => Err(ServerError::RequestTimeout),
                    }
                } else {
                    server.connection(stream, peer, permit, None).await
                };
                let _ = result;
                server
                    .metrics
                    .active_connections
                    .fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    async fn connection<S>(
        &self,
        mut stream: S,
        _peer: SocketAddr,
        _permit: OwnedSemaphorePermit,
        initial_principal: Option<String>,
    ) -> Result<(), ServerError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut context = ConnectionContext {
            sasl: initial_principal.map_or_else(SaslSession::default, |principal| {
                SaslSession::Authenticated { principal }
            }),
            legacy_sasl_tokens: false,
        };
        loop {
            let mut length = [0u8; 4];
            match timeout(self.config.request_timeout, stream.read_exact(&mut length)).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(());
                }
                Ok(Err(error)) => return Err(ServerError::Io(error)),
                Err(_) => return Err(ServerError::RequestTimeout),
            }
            let frame_length = i32::from_be_bytes(length);
            if frame_length < 0
                || frame_length as usize > self.cluster.protocol_limits().maximum_frame_bytes
            {
                return Err(ServerError::Protocol(ProtocolError::FrameTooLarge(
                    frame_length.max(0) as usize,
                )));
            }
            let mut frame = vec![0u8; frame_length as usize];
            timeout(self.config.request_timeout, stream.read_exact(&mut frame))
                .await
                .map_err(|_| ServerError::RequestTimeout)??;
            self.metrics
                .ingress_bytes
                .fetch_add(frame.len() as u64 + 4, Ordering::Relaxed);
            let ingress = frame.len() as u64 + 4;
            let response = if context.legacy_sasl_tokens
                && matches!(
                    context.sasl,
                    SaslSession::Ready | SaslSession::Challenge { .. }
                ) {
                let security = self
                    .security
                    .as_ref()
                    .ok_or(ServerError::AuthenticationRequired)?;
                let step = security.authenticate(&mut context.sasl, &frame)?;
                let mut response = BytesMut::with_capacity(step.bytes.len() + 4);
                response.put_i32(
                    i32::try_from(step.bytes.len())
                        .map_err(|_| ProtocolError::FrameTooLarge(step.bytes.len()))?,
                );
                response.extend_from_slice(&step.bytes);
                Ok(Some(ResponseFrame::contiguous(response.freeze())))
            } else {
                match decode_request(Bytes::from(frame), self.cluster.protocol_limits()) {
                    Ok(request) => {
                        if let Some(security) = &self.security
                            && !matches!(
                                &request.body,
                                RequestKind::ApiVersions(_)
                                    | RequestKind::SaslHandshake(_)
                                    | RequestKind::SaslAuthenticate(_)
                            )
                        {
                            let principal = context
                                .sasl
                                .principal()
                                .ok_or(ServerError::AuthenticationRequired)?;
                            security.admit(principal, ingress, 0)?;
                            authorize_request(security, principal, &request.body)?;
                        }
                        self.dispatch(request, &mut context).await
                    }
                    Err(ProtocolError::UnsupportedVersion {
                        api_key: 18,
                        version: _,
                        correlation_id,
                    }) => Ok(Some(ResponseFrame::contiguous(unsupported_api_versions(
                        correlation_id,
                    )?))),
                    Err(error) => Err(ServerError::Protocol(error)),
                }
            };
            match response {
                Ok(Some(response)) => {
                    if let Some(security) = &self.security
                        && let Some(principal) = context.sasl.principal()
                    {
                        security.admit_egress(principal, response.length as u64)?;
                    }
                    let _response_permit = if self.config.enforce_response_budget {
                        let dynamic = response
                            .length
                            .saturating_sub(self.unreserved_response_bytes);
                        if dynamic == 0 {
                            None
                        } else {
                            Some(
                                self.response_budget
                                    .try_acquire(dynamic)
                                    .map_err(ServerError::Buffer)?,
                            )
                        }
                    } else {
                        None
                    };
                    timeout(self.config.write_timeout, async {
                        for segment in &response.segments {
                            stream.write_all(segment).await?;
                        }
                        Ok::<_, std::io::Error>(())
                    })
                    .await
                    .map_err(|_| ServerError::WriteTimeout)??;
                    self.metrics
                        .egress_bytes
                        .fetch_add(response.length as u64, Ordering::Relaxed);
                    self.metrics
                        .completed_requests
                        .fetch_add(1, Ordering::Relaxed);
                }
                Ok(None) => {
                    self.metrics
                        .completed_requests
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => {
                    self.metrics.failed_requests.fetch_add(1, Ordering::Relaxed);
                    return Err(error);
                }
            }
        }
    }

    async fn dispatch(
        &self,
        request: DecodedRequest,
        context: &mut ConnectionContext,
    ) -> Result<Option<ResponseFrame>, ServerError> {
        let version = request.header.request_api_version;
        let correlation = request.header.correlation_id;
        let api_key = request.api_key;
        let body = match request.body {
            RequestKind::Fetch(request) => {
                return Ok(Some(self.fetch_frame(request, correlation).await?));
            }
            body => body,
        };
        let response = match body {
            RequestKind::ApiVersions(_) => ResponseKind::ApiVersions(api_versions_response()),
            RequestKind::SaslHandshake(request) => {
                context.legacy_sasl_tokens = version == 0;
                let response = match &self.security {
                    Some(security) => {
                        match security.handshake(&mut context.sasl, request.mechanism.as_str()) {
                            Ok(()) => SaslHandshakeResponse::default()
                                .with_error_code(0)
                                .with_mechanisms(vec![StrBytes::from_static_str("SCRAM-SHA-256")]),
                            Err(_) => SaslHandshakeResponse::default()
                                .with_error_code(33)
                                .with_mechanisms(vec![StrBytes::from_static_str("SCRAM-SHA-256")]),
                        }
                    }
                    None => SaslHandshakeResponse::default().with_error_code(33),
                };
                ResponseKind::SaslHandshake(response)
            }
            RequestKind::SaslAuthenticate(request) => {
                let response = match &self.security {
                    Some(security) => {
                        match security.authenticate(&mut context.sasl, &request.auth_bytes) {
                            Ok(step) => SaslAuthenticateResponse::default()
                                .with_error_code(0)
                                .with_auth_bytes(Bytes::from(step.bytes)),
                            Err(_) => SaslAuthenticateResponse::default()
                                .with_error_code(58)
                                .with_error_message(Some(StrBytes::from_static_str(
                                    "authentication failed",
                                ))),
                        }
                    }
                    None => SaslAuthenticateResponse::default()
                        .with_error_code(58)
                        .with_error_message(Some(StrBytes::from_static_str(
                            "authentication failed",
                        ))),
                };
                ResponseKind::SaslAuthenticate(response)
            }
            RequestKind::Metadata(request) => ResponseKind::Metadata(self.metadata(request).await),
            RequestKind::Produce(request) => {
                let no_response = request.acks == 0;
                let response = self.produce(request).await;
                if no_response {
                    return Ok(None);
                }
                ResponseKind::Produce(response)
            }
            RequestKind::ListOffsets(request) => {
                ResponseKind::ListOffsets(self.list_offsets(request).await)
            }
            RequestKind::OffsetCommit(request) => {
                ResponseKind::OffsetCommit(self.offset_commit(request).await)
            }
            RequestKind::OffsetFetch(request) => {
                ResponseKind::OffsetFetch(self.offset_fetch(request).await)
            }
            RequestKind::FindCoordinator(request) => {
                ResponseKind::FindCoordinator(self.find_coordinator(request).await)
            }
            RequestKind::JoinGroup(request) => {
                ResponseKind::JoinGroup(self.join_group(request).await)
            }
            RequestKind::Heartbeat(request) => {
                ResponseKind::Heartbeat(self.heartbeat(request).await)
            }
            RequestKind::LeaveGroup(request) => {
                ResponseKind::LeaveGroup(self.leave_group(request).await)
            }
            RequestKind::SyncGroup(request) => {
                ResponseKind::SyncGroup(self.sync_group(request).await)
            }
            RequestKind::DescribeGroups(request) => {
                ResponseKind::DescribeGroups(self.describe_groups(request).await)
            }
            RequestKind::ListGroups(_) => ResponseKind::ListGroups(self.list_groups().await),
            RequestKind::InitProducerId(request) => {
                ResponseKind::InitProducerId(self.init_producer_id(request).await)
            }
            RequestKind::AddPartitionsToTxn(request) => {
                ResponseKind::AddPartitionsToTxn(self.add_partitions_to_txn(request).await)
            }
            RequestKind::AddOffsetsToTxn(request) => {
                ResponseKind::AddOffsetsToTxn(self.add_offsets_to_txn(request).await)
            }
            RequestKind::EndTxn(request) => ResponseKind::EndTxn(self.end_txn(request).await),
            RequestKind::TxnOffsetCommit(request) => {
                ResponseKind::TxnOffsetCommit(self.txn_offset_commit(request).await)
            }
            RequestKind::CreateTopics(request) => {
                ResponseKind::CreateTopics(self.create_topics(request).await)
            }
            RequestKind::DeleteTopics(request) => {
                ResponseKind::DeleteTopics(self.delete_topics(request).await)
            }
            RequestKind::DescribeConfigs(request) => {
                ResponseKind::DescribeConfigs(self.describe_configs(request).await)
            }
            RequestKind::AlterConfigs(request) => {
                ResponseKind::AlterConfigs(self.alter_configs(request).await)
            }
            RequestKind::DescribeCluster(_) => {
                ResponseKind::DescribeCluster(self.describe_cluster().await)
            }
            _ => return Err(ServerError::UnsupportedApi),
        };
        Ok(Some(ResponseFrame::contiguous(encode_response_kind(
            api_key,
            correlation,
            version,
            &response,
        )?)))
    }

    async fn metadata(
        &self,
        request: kafka_protocol::messages::MetadataRequest,
    ) -> MetadataResponse {
        let state = self.cluster.controller_state().await;
        let brokers = state
            .brokers
            .values()
            .map(metadata_broker)
            .collect::<Vec<_>>();
        let requested = request.topics.map(|topics| {
            topics
                .into_iter()
                .filter_map(|topic| topic.name.map(|name| name.0.to_string()))
                .collect::<Vec<_>>()
        });
        let mut topics = Vec::new();
        let names = requested.unwrap_or_else(|| state.topics.keys().cloned().collect());
        for name in names {
            if let Some(topic) = state.topics.get(&name) {
                topics.push(metadata_topic(topic));
            } else {
                topics.push(
                    MetadataResponseTopic::default()
                        .with_error_code(ResponseError::UnknownTopicOrPartition.code())
                        .with_name(Some(StrBytes::from_string(name).into())),
                );
            }
        }
        MetadataResponse::default()
            .with_brokers(brokers)
            .with_controller_id(state.controller_id.into())
            .with_topics(topics)
    }

    async fn produce(&self, request: kafka_protocol::messages::ProduceRequest) -> ProduceResponse {
        let acknowledgments = match request.acks {
            -1 => Some(Acknowledgments::All),
            1 => Some(Acknowledgments::Leader),
            0 => Some(Acknowledgments::None),
            _ => None,
        };
        let mut responses = Vec::new();
        for topic in request.topic_data {
            let topic_name = topic.name.0.to_string();
            let mut partitions = Vec::new();
            for partition in topic.partition_data {
                let quota_key = PartitionKey::new(topic_name.as_str(), partition.index);
                let record_bytes = partition
                    .records
                    .as_ref()
                    .map_or(0, |records| records.len() as u64);
                let result = match (&partition.records, acknowledgments) {
                    (Some(_), Some(_))
                        if !self.quotas.admit(
                            &quota_key,
                            record_bytes,
                            tokio::time::Instant::now(),
                        ) =>
                    {
                        self.metrics.quota_throttles.fetch_add(1, Ordering::Relaxed);
                        Err(KafkaError::QuotaExceeded)
                    }
                    (Some(records), Some(acknowledgments)) => {
                        self.cluster
                            .produce(
                                self.broker_id,
                                &topic_name,
                                partition.index,
                                now_millis(),
                                records.clone(),
                                acknowledgments,
                            )
                            .await
                    }
                    _ => Err(KafkaError::InvalidRequest("records or acks are invalid")),
                };
                partitions.push(match result {
                    Ok(result) if result.acknowledged || request.acks != -1 => {
                        PartitionProduceResponse::default()
                            .with_index(partition.index)
                            .with_error_code(0)
                            .with_base_offset(result.result.base_offset as i64)
                            .with_log_append_time_ms(-1)
                            .with_log_start_offset(0)
                    }
                    Ok(_) => PartitionProduceResponse::default()
                        .with_index(partition.index)
                        .with_error_code(ResponseError::NotEnoughReplicasAfterAppend.code())
                        .with_base_offset(-1),
                    Err(error) => PartitionProduceResponse::default()
                        .with_index(partition.index)
                        .with_error_code(error_code(&error))
                        .with_base_offset(-1),
                });
            }
            responses.push(
                TopicProduceResponse::default()
                    .with_name(topic.name)
                    .with_partition_responses(partitions),
            );
        }
        ProduceResponse::default().with_responses(responses)
    }

    async fn fetch_frame(
        &self,
        request: kafka_protocol::messages::FetchRequest,
        correlation_id: i32,
    ) -> Result<ResponseFrame, ServerError> {
        let minimum_bytes = request.min_bytes.max(0) as u64;
        let maximum_wait = Duration::from_millis(request.max_wait_ms.max(0) as u64);
        if minimum_bytes == 0 || maximum_wait.is_zero() {
            return self
                .fetch_attempt(request, correlation_id)
                .await
                .map(|(frame, _)| frame);
        }
        let keys = request.topics.iter().flat_map(|topic| {
            let name: Arc<str> = Arc::from(topic.topic.0.as_str());
            topic
                .partitions
                .iter()
                .map(move |partition| PartitionKey::new(Arc::clone(&name), partition.partition))
        });
        // Register before the first read so a concurrent append cannot be
        // lost between observing an empty log and parking the request.
        let waiter = self.cluster.fetch_waiters().register(keys, maximum_wait);
        let (frame, bytes) = self.fetch_attempt(request.clone(), correlation_id).await?;
        if bytes >= minimum_bytes {
            drop(waiter);
            return Ok(frame);
        }
        let _ = waiter.ready().await;
        self.fetch_attempt(request, correlation_id)
            .await
            .map(|(frame, _)| frame)
    }

    async fn fetch_attempt(
        &self,
        request: kafka_protocol::messages::FetchRequest,
        correlation_id: i32,
    ) -> Result<(ResponseFrame, u64), ServerError> {
        let mut remaining = request.max_bytes.max(0) as u64;
        let mut returned = 0u64;
        let mut segments = Vec::new();
        let mut prefix = BytesMut::new();
        prefix.put_i32(0);
        prefix.put_i32(correlation_id);
        prefix.put_i32(0);
        prefix.put_i32(request.topics.len() as i32);
        for topic in request.topics {
            let topic_name = topic.topic.0.to_string();
            let topic_bytes = topic_name.as_bytes();
            prefix.put_i16(
                i16::try_from(topic_bytes.len()).map_err(|_| ProtocolError::Limit("topic name"))?,
            );
            prefix.extend_from_slice(topic_bytes);
            prefix.put_i32(topic.partitions.len() as i32);
            for partition in topic.partitions {
                let maximum = remaining.min(partition.partition_max_bytes.max(0) as u64);
                let result = self
                    .cluster
                    .fetch(
                        self.broker_id,
                        &topic_name,
                        partition.partition,
                        partition.fetch_offset.max(0) as u64,
                        maximum,
                    )
                    .await;
                prefix.put_i32(partition.partition);
                match result {
                    Ok(mut result) => {
                        let transaction_partition =
                            TransactionPartition::new(topic_name.clone(), partition.partition);
                        let read_committed = request.isolation_level == 1;
                        let last_stable_offset = if read_committed {
                            self.cluster
                                .transactions()
                                .last_stable_offset(&transaction_partition, result.high_watermark)
                                .await
                        } else {
                            result.high_watermark
                        };
                        if read_committed {
                            result
                                .batches
                                .retain(|batch| batch.last_offset < last_stable_offset);
                        }
                        let aborted = if read_committed {
                            self.cluster
                                .transactions()
                                .aborted_ranges(
                                    &transaction_partition,
                                    partition.fetch_offset.max(0) as u64,
                                    last_stable_offset,
                                )
                                .await
                        } else {
                            Vec::new()
                        };
                        let record_bytes = result
                            .batches
                            .iter()
                            .map(|batch| batch.bytes.encoded_len())
                            .sum::<usize>();
                        let quota_key = PartitionKey::new(topic_name.as_str(), partition.partition);
                        if !self.quotas.admit(
                            &quota_key,
                            record_bytes as u64,
                            tokio::time::Instant::now(),
                        ) {
                            self.metrics.quota_throttles.fetch_add(1, Ordering::Relaxed);
                            prefix.put_i16(89);
                            prefix.put_i64(result.high_watermark as i64);
                            prefix.put_i64(last_stable_offset as i64);
                            prefix.put_i32(aborted.len() as i32);
                            for range in &aborted {
                                prefix.put_i64(range.producer_id);
                                prefix.put_i64(range.first_offset as i64);
                            }
                            prefix.put_i32(-1);
                            continue;
                        }
                        remaining = remaining.saturating_sub(record_bytes as u64);
                        returned = returned.saturating_add(record_bytes as u64);
                        prefix.put_i16(0);
                        prefix.put_i64(result.high_watermark as i64);
                        prefix.put_i64(last_stable_offset as i64);
                        prefix.put_i32(aborted.len() as i32);
                        for range in aborted {
                            prefix.put_i64(range.producer_id);
                            prefix.put_i64(range.first_offset as i64);
                        }
                        prefix.put_i32(
                            i32::try_from(record_bytes)
                                .map_err(|_| ProtocolError::FrameTooLarge(record_bytes))?,
                        );
                        segments.push(prefix.split().freeze());
                        for batch in result.batches {
                            segments.push(batch.bytes.bytes().clone());
                        }
                    }
                    Err(error) => {
                        prefix.put_i16(error_code(&error));
                        prefix.put_i64(-1);
                        prefix.put_i64(-1);
                        prefix.put_i32(0);
                        prefix.put_i32(-1);
                    }
                }
            }
        }
        if !prefix.is_empty() {
            segments.push(prefix.freeze());
        }
        ResponseFrame::vectored(segments, self.cluster.protocol_limits().maximum_frame_bytes)
            .map(|frame| (frame, returned))
    }

    async fn list_offsets(
        &self,
        request: kafka_protocol::messages::ListOffsetsRequest,
    ) -> ListOffsetsResponse {
        let mut topics = Vec::new();
        for topic in request.topics {
            let name = topic.name.0.to_string();
            let mut partitions = Vec::new();
            for partition in topic.partitions {
                let result = self
                    .cluster
                    .offsets(self.broker_id, &name, partition.partition_index)
                    .await;
                partitions.push(match result {
                    Ok((start, _high_watermark, end)) => {
                        let offset = match partition.timestamp {
                            -2 => start as i64,
                            -1 => end as i64,
                            _ => -1,
                        };
                        ListOffsetsPartitionResponse::default()
                            .with_partition_index(partition.partition_index)
                            .with_error_code(0)
                            .with_timestamp(partition.timestamp)
                            .with_offset(offset)
                    }
                    Err(error) => ListOffsetsPartitionResponse::default()
                        .with_partition_index(partition.partition_index)
                        .with_error_code(error_code(&error))
                        .with_timestamp(-1)
                        .with_offset(-1),
                });
            }
            topics.push(
                ListOffsetsTopicResponse::default()
                    .with_name(topic.name)
                    .with_partitions(partitions),
            );
        }
        ListOffsetsResponse::default().with_topics(topics)
    }

    async fn find_coordinator(
        &self,
        request: kafka_protocol::messages::FindCoordinatorRequest,
    ) -> FindCoordinatorResponse {
        let state = self.cluster.controller_state().await;
        if !matches!(request.key_type, 0 | 1) || request.key.is_empty() {
            return FindCoordinatorResponse::default()
                .with_error_code(ResponseError::InvalidRequest.code())
                .with_node_id((-1).into())
                .with_host(StrBytes::from_static_str(""))
                .with_port(-1);
        }
        let brokers = state.brokers.values().collect::<Vec<_>>();
        let digest = blake3::hash(request.key.as_bytes());
        let hash = u64::from_be_bytes(digest.as_bytes()[..8].try_into().expect("fixed"));
        let Some(broker) = brokers.get(hash as usize % brokers.len()) else {
            return FindCoordinatorResponse::default()
                .with_error_code(15)
                .with_node_id((-1).into())
                .with_host(StrBytes::from_static_str(""))
                .with_port(-1);
        };
        FindCoordinatorResponse::default()
            .with_error_code(0)
            .with_node_id(broker.broker_id.into())
            .with_host(StrBytes::from_string(broker.host.clone()))
            .with_port(i32::from(broker.port))
    }

    async fn join_group(
        &self,
        request: kafka_protocol::messages::JoinGroupRequest,
    ) -> JoinGroupResponse {
        let group = request.group_id.0.to_string();
        let protocols = request
            .protocols
            .into_iter()
            .map(|protocol| (protocol.name.to_string(), protocol.metadata.to_vec()))
            .collect();
        match self
            .cluster
            .groups()
            .apply(
                &group,
                GroupCommand::Join {
                    group: group.clone(),
                    member_id: request.member_id.to_string(),
                    client_id: "kafka-client".into(),
                    client_host: "unknown".into(),
                    protocol_type: request.protocol_type.to_string(),
                    protocols,
                    session_timeout_ms: request.session_timeout_ms.max(1) as u64,
                    now_ms: now_millis(),
                },
            )
            .await
        {
            Ok(GroupResponse::Joined {
                generation,
                protocol_name,
                leader,
                member_id,
                members,
            }) => JoinGroupResponse::default()
                .with_error_code(0)
                .with_generation_id(generation)
                .with_protocol_name(Some(StrBytes::from_string(protocol_name)))
                .with_leader(StrBytes::from_string(leader))
                .with_member_id(StrBytes::from_string(member_id))
                .with_members(
                    members
                        .into_iter()
                        .map(|(member, metadata)| {
                            JoinGroupResponseMember::default()
                                .with_member_id(StrBytes::from_string(member))
                                .with_metadata(Bytes::from(metadata))
                        })
                        .collect(),
                ),
            Err(error) => JoinGroupResponse::default()
                .with_error_code(group_error_code(&error))
                .with_generation_id(-1),
            _ => JoinGroupResponse::default().with_error_code(1),
        }
    }

    async fn sync_group(
        &self,
        request: kafka_protocol::messages::SyncGroupRequest,
    ) -> SyncGroupResponse {
        let group = request.group_id.0.to_string();
        let assignments = request
            .assignments
            .into_iter()
            .map(|assignment| {
                (
                    assignment.member_id.to_string(),
                    assignment.assignment.to_vec(),
                )
            })
            .collect();
        match self
            .cluster
            .groups()
            .apply(
                &group,
                GroupCommand::Sync {
                    group: group.clone(),
                    generation: request.generation_id,
                    member_id: request.member_id.to_string(),
                    assignments,
                },
            )
            .await
        {
            Ok(GroupResponse::Assignment(assignment)) => SyncGroupResponse::default()
                .with_error_code(0)
                .with_assignment(Bytes::from(assignment)),
            Err(error) => SyncGroupResponse::default().with_error_code(group_error_code(&error)),
            _ => SyncGroupResponse::default().with_error_code(1),
        }
    }

    async fn heartbeat(
        &self,
        request: kafka_protocol::messages::HeartbeatRequest,
    ) -> HeartbeatResponse {
        let group = request.group_id.0.to_string();
        match self
            .cluster
            .groups()
            .apply(
                &group,
                GroupCommand::Heartbeat {
                    group: group.clone(),
                    generation: request.generation_id,
                    member_id: request.member_id.to_string(),
                    now_ms: now_millis(),
                },
            )
            .await
        {
            Ok(_) => HeartbeatResponse::default().with_error_code(0),
            Err(error) => HeartbeatResponse::default().with_error_code(group_error_code(&error)),
        }
    }

    async fn leave_group(
        &self,
        request: kafka_protocol::messages::LeaveGroupRequest,
    ) -> LeaveGroupResponse {
        let group = request.group_id.0.to_string();
        match self
            .cluster
            .groups()
            .apply(
                &group,
                GroupCommand::Leave {
                    group: group.clone(),
                    member_id: request.member_id.to_string(),
                },
            )
            .await
        {
            Ok(_) => LeaveGroupResponse::default().with_error_code(0),
            Err(error) => LeaveGroupResponse::default().with_error_code(group_error_code(&error)),
        }
    }

    async fn offset_commit(
        &self,
        request: kafka_protocol::messages::OffsetCommitRequest,
    ) -> OffsetCommitResponse {
        let group = request.group_id.0.to_string();
        let requested = request.topics.clone();
        let offsets = request
            .topics
            .into_iter()
            .flat_map(|topic| {
                let name = topic.name.0.to_string();
                topic.partitions.into_iter().map(move |partition| {
                    (
                        name.clone(),
                        partition.partition_index,
                        partition.committed_offset,
                        partition
                            .committed_metadata
                            .map_or_else(String::new, |metadata| metadata.to_string()),
                    )
                })
            })
            .collect();
        let error = self
            .cluster
            .groups()
            .apply(
                &group,
                GroupCommand::CommitOffsets {
                    group: group.clone(),
                    generation: request.generation_id_or_member_epoch,
                    member_id: request.member_id.to_string(),
                    offsets,
                    retention_ms: (request.retention_time_ms >= 0)
                        .then_some(request.retention_time_ms as u64),
                    now_ms: now_millis(),
                },
            )
            .await
            .err()
            .map_or(0, |error| group_error_code(&error));
        OffsetCommitResponse::default().with_topics(
            requested
                .into_iter()
                .map(|topic| {
                    OffsetCommitResponseTopic::default()
                        .with_name(topic.name)
                        .with_partitions(
                            topic
                                .partitions
                                .into_iter()
                                .map(|partition| {
                                    OffsetCommitResponsePartition::default()
                                        .with_partition_index(partition.partition_index)
                                        .with_error_code(error)
                                })
                                .collect(),
                        )
                })
                .collect(),
        )
    }

    async fn offset_fetch(
        &self,
        request: kafka_protocol::messages::OffsetFetchRequest,
    ) -> OffsetFetchResponse {
        let group = request.group_id.0.to_string();
        let offsets = self
            .cluster
            .groups()
            .offsets(&group)
            .await
            .unwrap_or_default();
        let requested = request.topics.unwrap_or_else(|| {
            let mut topics = BTreeMap::<String, Vec<i32>>::new();
            for key in offsets.keys() {
                topics.entry(key.topic.clone()).or_default().push(key.partition);
            }
            topics
                .into_iter()
                .map(|(name, partition_indexes)| {
                    kafka_protocol::messages::offset_fetch_request::OffsetFetchRequestTopic::default()
                        .with_name(StrBytes::from_string(name).into())
                        .with_partition_indexes(partition_indexes)
                })
                .collect()
        });
        OffsetFetchResponse::default()
            .with_error_code(0)
            .with_topics(
                requested
                    .into_iter()
                    .map(|topic| {
                        let name = topic.name.0.to_string();
                        OffsetFetchResponseTopic::default()
                            .with_name(topic.name)
                            .with_partitions(
                                topic
                                    .partition_indexes
                                    .into_iter()
                                    .map(|partition| {
                                        let record = offsets.get(&crate::groups::OffsetKey {
                                            group: group.clone(),
                                            topic: name.clone(),
                                            partition,
                                        });
                                        OffsetFetchResponsePartition::default()
                                            .with_partition_index(partition)
                                            .with_committed_offset(
                                                record.map_or(-1, |record| record.offset),
                                            )
                                            .with_metadata(record.map(|record| {
                                                StrBytes::from_string(record.metadata.clone())
                                            }))
                                            .with_error_code(0)
                                    })
                                    .collect(),
                            )
                    })
                    .collect(),
            )
    }

    async fn describe_groups(
        &self,
        request: kafka_protocol::messages::DescribeGroupsRequest,
    ) -> DescribeGroupsResponse {
        let mut groups = Vec::new();
        for group_id in request.groups {
            let name = group_id.0.to_string();
            match self.cluster.groups().group(&name).await {
                Ok(Some(group)) => {
                    let state = match group.phase {
                        GroupPhase::Empty => "Empty",
                        GroupPhase::PreparingRebalance => "PreparingRebalance",
                        GroupPhase::Stable => "Stable",
                    };
                    let protocol_name = group.protocol_name.clone();
                    groups.push(
                        DescribedGroup::default()
                            .with_error_code(0)
                            .with_group_id(group_id)
                            .with_group_state(StrBytes::from_static_str(state))
                            .with_protocol_type(StrBytes::from_string(group.protocol_type))
                            .with_protocol_data(StrBytes::from_string(protocol_name.clone()))
                            .with_members(
                                group
                                    .members
                                    .into_values()
                                    .map(|member| {
                                        DescribedGroupMember::default()
                                            .with_member_id(StrBytes::from_string(member.member_id))
                                            .with_client_id(StrBytes::from_string(member.client_id))
                                            .with_client_host(StrBytes::from_string(
                                                member.client_host,
                                            ))
                                            .with_member_metadata(Bytes::from(
                                                member.protocols[&protocol_name].clone(),
                                            ))
                                            .with_member_assignment(Bytes::from(member.assignment))
                                    })
                                    .collect(),
                            ),
                    );
                }
                _ => groups.push(
                    DescribedGroup::default()
                        .with_error_code(69)
                        .with_group_id(group_id),
                ),
            }
        }
        DescribeGroupsResponse::default().with_groups(groups)
    }

    async fn list_groups(&self) -> ListGroupsResponse {
        ListGroupsResponse::default()
            .with_error_code(0)
            .with_groups(
                self.cluster
                    .groups()
                    .groups()
                    .await
                    .into_iter()
                    .map(|(name, group)| {
                        ListedGroup::default()
                            .with_group_id(StrBytes::from_string(name).into())
                            .with_protocol_type(StrBytes::from_string(group.protocol_type))
                    })
                    .collect(),
            )
    }

    async fn init_producer_id(
        &self,
        request: kafka_protocol::messages::InitProducerIdRequest,
    ) -> InitProducerIdResponse {
        match self
            .cluster
            .transactions()
            .init_producer(
                request
                    .transactional_id
                    .map(|transactional_id| transactional_id.0.to_string()),
                request.transaction_timeout_ms.max(1) as u64,
                now_millis(),
            )
            .await
        {
            Ok(identity) => InitProducerIdResponse::default()
                .with_error_code(0)
                .with_producer_id(identity.producer_id.into())
                .with_producer_epoch(identity.producer_epoch),
            Err(error) => InitProducerIdResponse::default()
                .with_error_code(transaction_error_code(&error))
                .with_producer_id((-1).into())
                .with_producer_epoch(-1),
        }
    }

    async fn add_partitions_to_txn(
        &self,
        request: kafka_protocol::messages::AddPartitionsToTxnRequest,
    ) -> AddPartitionsToTxnResponse {
        let identity = ProducerIdentity {
            producer_id: request.v3_and_below_producer_id.0,
            producer_epoch: request.v3_and_below_producer_epoch,
        };
        let requested = request.v3_and_below_topics;
        let partitions = requested
            .iter()
            .flat_map(|topic| {
                let name = topic.name.0.to_string();
                topic
                    .partitions
                    .iter()
                    .map(move |partition| TransactionPartition::new(name.clone(), *partition))
            })
            .collect::<Vec<_>>();
        let error = self
            .cluster
            .transactions()
            .add_partitions(identity, partitions, now_millis())
            .await
            .err()
            .map_or(0, |error| transaction_error_code(&error));
        AddPartitionsToTxnResponse::default().with_results_by_topic_v3_and_below(
            requested
                .into_iter()
                .map(|topic| {
                    AddPartitionsToTxnTopicResult::default()
                        .with_name(topic.name)
                        .with_results_by_partition(
                            topic
                                .partitions
                                .into_iter()
                                .map(|partition| {
                                    AddPartitionsToTxnPartitionResult::default()
                                        .with_partition_index(partition)
                                        .with_partition_error_code(error)
                                })
                                .collect(),
                        )
                })
                .collect(),
        )
    }

    async fn add_offsets_to_txn(
        &self,
        request: kafka_protocol::messages::AddOffsetsToTxnRequest,
    ) -> AddOffsetsToTxnResponse {
        let result = self
            .cluster
            .transactions()
            .validate_transaction(
                ProducerIdentity {
                    producer_id: request.producer_id.0,
                    producer_epoch: request.producer_epoch,
                },
                request.transactional_id.0.as_str(),
            )
            .await;
        AddOffsetsToTxnResponse::default()
            .with_error_code(result.as_ref().err().map_or(0, transaction_error_code))
    }

    async fn txn_offset_commit(
        &self,
        request: kafka_protocol::messages::TxnOffsetCommitRequest,
    ) -> TxnOffsetCommitResponse {
        let identity = ProducerIdentity {
            producer_id: request.producer_id.0,
            producer_epoch: request.producer_epoch,
        };
        let requested = request.topics.clone();
        let group = request.group_id.0.to_string();
        let offsets = request
            .topics
            .into_iter()
            .flat_map(|topic| {
                let group = group.clone();
                let name = topic.name.0.to_string();
                topic
                    .partitions
                    .into_iter()
                    .map(move |partition| PendingOffset {
                        group: group.clone(),
                        topic: name.clone(),
                        partition: partition.partition_index,
                        offset: partition.committed_offset,
                        metadata: partition
                            .committed_metadata
                            .map_or_else(String::new, |metadata| metadata.to_string()),
                    })
            })
            .collect();
        let error = self
            .cluster
            .transactions()
            .stage_offsets(identity, offsets)
            .await
            .err()
            .map_or(0, |error| transaction_error_code(&error));
        TxnOffsetCommitResponse::default().with_topics(
            requested
                .into_iter()
                .map(|topic| {
                    TxnOffsetCommitResponseTopic::default()
                        .with_name(topic.name)
                        .with_partitions(
                            topic
                                .partitions
                                .into_iter()
                                .map(|partition| {
                                    TxnOffsetCommitResponsePartition::default()
                                        .with_partition_index(partition.partition_index)
                                        .with_error_code(error)
                                })
                                .collect(),
                        )
                })
                .collect(),
        )
    }

    async fn end_txn(&self, request: kafka_protocol::messages::EndTxnRequest) -> EndTxnResponse {
        let identity = ProducerIdentity {
            producer_id: request.producer_id.0,
            producer_epoch: request.producer_epoch,
        };
        let pending = match self
            .cluster
            .transactions()
            .end_transaction(identity, request.committed)
            .await
        {
            Ok(pending) => pending,
            Err(error) => {
                return EndTxnResponse::default().with_error_code(transaction_error_code(&error));
            }
        };
        if request.committed && !pending.is_empty() {
            let mut groups = BTreeMap::<String, Vec<(String, i32, i64, String)>>::new();
            for offset in pending {
                groups.entry(offset.group).or_default().push((
                    offset.topic,
                    offset.partition,
                    offset.offset,
                    offset.metadata,
                ));
            }
            for (group, offsets) in groups {
                if let Err(error) = self
                    .cluster
                    .groups()
                    .apply(
                        &group,
                        GroupCommand::CommitTransactionalOffsets {
                            group: group.clone(),
                            offsets,
                            now_ms: now_millis(),
                        },
                    )
                    .await
                {
                    return EndTxnResponse::default().with_error_code(group_error_code(&error));
                }
            }
            if let Err(error) = self
                .cluster
                .transactions()
                .mark_offsets_applied(identity)
                .await
            {
                return EndTxnResponse::default().with_error_code(transaction_error_code(&error));
            }
        }
        EndTxnResponse::default().with_error_code(0)
    }

    async fn create_topics(
        &self,
        request: kafka_protocol::messages::CreateTopicsRequest,
    ) -> CreateTopicsResponse {
        let mut results = Vec::new();
        for requested in request.topics {
            let name = requested.name.0.to_string();
            let configs = requested
                .configs
                .iter()
                .filter_map(|config| {
                    config
                        .value
                        .as_ref()
                        .map(|value| (config.name.to_string(), value.to_string()))
                })
                .collect();
            let result = if requested.assignments.is_empty() {
                self.cluster
                    .create_topic(
                        name,
                        requested.num_partitions.max(0) as u32,
                        requested.replication_factor.max(0) as u16,
                        configs,
                        request.validate_only,
                    )
                    .await
            } else {
                Err(KafkaError::InvalidRequest(
                    "explicit replica assignments are not supported",
                ))
            };
            results.push(match result {
                Ok(topic) => CreatableTopicResult::default()
                    .with_name(requested.name)
                    .with_topic_id(Uuid::from_bytes(topic.topic_id))
                    .with_error_code(0)
                    .with_num_partitions(topic.partitions.len() as i32)
                    .with_replication_factor(
                        topic.partitions.first().map_or(0, |p| p.replicas.len()) as i16,
                    ),
                Err(error) => CreatableTopicResult::default()
                    .with_name(requested.name)
                    .with_error_code(error_code(&error))
                    .with_num_partitions(-1)
                    .with_replication_factor(-1),
            });
        }
        CreateTopicsResponse::default().with_topics(results)
    }

    async fn delete_topics(
        &self,
        request: kafka_protocol::messages::DeleteTopicsRequest,
    ) -> DeleteTopicsResponse {
        let mut responses = Vec::new();
        for topic in request.topic_names {
            let name = topic.0.to_string();
            responses.push(match self.cluster.delete_topic(&name).await {
                Ok(topic_id) => DeletableTopicResult::default()
                    .with_name(Some(topic))
                    .with_topic_id(Uuid::from_bytes(topic_id))
                    .with_error_code(0),
                Err(error) => DeletableTopicResult::default()
                    .with_name(Some(topic))
                    .with_error_code(error_code(&error)),
            });
        }
        DeleteTopicsResponse::default().with_responses(responses)
    }

    async fn describe_configs(
        &self,
        request: kafka_protocol::messages::DescribeConfigsRequest,
    ) -> DescribeConfigsResponse {
        let state = self.cluster.controller_state().await;
        let mut results = Vec::new();
        for resource in request.resources {
            let name = resource.resource_name.to_string();
            if resource.resource_type != 2 {
                results.push(
                    DescribeConfigsResult::default()
                        .with_resource_type(resource.resource_type)
                        .with_resource_name(resource.resource_name)
                        .with_error_code(ResponseError::InvalidRequest.code()),
                );
                continue;
            }
            match state.topics.get(&name) {
                Some(topic) => {
                    let selected = resource.configuration_keys.as_ref();
                    let configs = topic
                        .configs
                        .iter()
                        .filter(|(key, _)| {
                            selected
                                .is_none_or(|keys| keys.iter().any(|name| name.as_str() == *key))
                        })
                        .map(|(name, value)| {
                            DescribeConfigsResourceResult::default()
                                .with_name(StrBytes::from_string(name.clone()))
                                .with_value(Some(StrBytes::from_string(value.clone())))
                                .with_read_only(false)
                                .with_is_sensitive(false)
                                .with_config_source(1)
                        })
                        .collect();
                    results.push(
                        DescribeConfigsResult::default()
                            .with_resource_type(2)
                            .with_resource_name(resource.resource_name)
                            .with_error_code(0)
                            .with_configs(configs),
                    );
                }
                None => results.push(
                    DescribeConfigsResult::default()
                        .with_resource_type(2)
                        .with_resource_name(resource.resource_name)
                        .with_error_code(ResponseError::UnknownTopicOrPartition.code()),
                ),
            }
        }
        DescribeConfigsResponse::default().with_results(results)
    }

    async fn alter_configs(
        &self,
        request: kafka_protocol::messages::AlterConfigsRequest,
    ) -> AlterConfigsResponse {
        let mut responses = Vec::new();
        for resource in request.resources {
            let name = resource.resource_name.to_string();
            let result = if resource.resource_type == 2 {
                let configs = resource
                    .configs
                    .iter()
                    .filter_map(|config| {
                        config
                            .value
                            .as_ref()
                            .map(|value| (config.name.to_string(), value.to_string()))
                    })
                    .collect::<BTreeMap<_, _>>();
                self.cluster
                    .alter_topic_configs(&name, configs, request.validate_only)
                    .await
                    .map(|_| ())
            } else {
                Err(KafkaError::InvalidRequest("unsupported config resource"))
            };
            responses.push(
                AlterConfigsResourceResponse::default()
                    .with_resource_type(resource.resource_type)
                    .with_resource_name(resource.resource_name)
                    .with_error_code(result.as_ref().err().map_or(0, error_code)),
            );
        }
        AlterConfigsResponse::default().with_responses(responses)
    }

    async fn describe_cluster(&self) -> DescribeClusterResponse {
        let state = self.cluster.controller_state().await;
        let brokers = state
            .brokers
            .values()
            .map(|broker| {
                DescribeClusterBroker::default()
                    .with_broker_id(broker.broker_id.into())
                    .with_host(StrBytes::from_string(broker.host.clone()))
                    .with_port(i32::from(broker.port))
                    .with_rack(broker.rack.clone().map(StrBytes::from_string))
            })
            .collect();
        DescribeClusterResponse::default()
            .with_error_code(0)
            .with_cluster_id(StrBytes::from_string(state.cluster_id))
            .with_controller_id(state.controller_id.into())
            .with_brokers(brokers)
            .with_cluster_authorized_operations(i32::MIN)
    }
}

fn api_versions_response() -> ApiVersionsResponse {
    ApiVersionsResponse::default()
        .with_error_code(0)
        .with_api_keys(
            ADVERTISED_APIS
                .iter()
                .map(|api| {
                    ApiVersion::default()
                        .with_api_key(api.api_key)
                        .with_min_version(api.minimum)
                        .with_max_version(api.maximum)
                })
                .collect(),
        )
        .with_throttle_time_ms(0)
}

fn unsupported_api_versions(correlation_id: i32) -> Result<Bytes, ProtocolError> {
    let response = ApiVersionsResponse::default()
        .with_error_code(ResponseError::UnsupportedVersion.code())
        .with_api_keys(Vec::new());
    encode_response(correlation_id, 0, &response)
}

fn metadata_broker(broker: &crate::controller::BrokerRegistration) -> MetadataResponseBroker {
    MetadataResponseBroker::default()
        .with_node_id(broker.broker_id.into())
        .with_host(StrBytes::from_string(broker.host.clone()))
        .with_port(i32::from(broker.port))
        .with_rack(broker.rack.clone().map(StrBytes::from_string))
}

fn metadata_topic(topic: &crate::controller::TopicRecord) -> MetadataResponseTopic {
    MetadataResponseTopic::default()
        .with_error_code(0)
        .with_name(Some(StrBytes::from_string(topic.name.clone()).into()))
        .with_topic_id(Uuid::from_bytes(topic.topic_id))
        .with_is_internal(false)
        .with_partitions(
            topic
                .partitions
                .iter()
                .map(|partition| {
                    MetadataResponsePartition::default()
                        .with_error_code(0)
                        .with_partition_index(partition.partition_id)
                        .with_leader_id(partition.leader_id.into())
                        .with_leader_epoch(partition.leader_epoch as i32)
                        .with_replica_nodes(
                            partition
                                .replicas
                                .iter()
                                .map(|node| (*node).into())
                                .collect(),
                        )
                        .with_isr_nodes(
                            partition
                                .replicas
                                .iter()
                                .map(|node| (*node).into())
                                .collect(),
                        )
                        .with_offline_replicas(Vec::new())
                })
                .collect(),
        )
}

fn error_code(error: &KafkaError) -> i16 {
    match error {
        KafkaError::Controller(crate::controller::ControllerError::TopicExists) => {
            ResponseError::TopicAlreadyExists.code()
        }
        KafkaError::Controller(crate::controller::ControllerError::InvalidReplication) => {
            ResponseError::InvalidReplicationFactor.code()
        }
        KafkaError::Controller(crate::controller::ControllerError::UnknownTopic)
        | KafkaError::UnknownPartition => ResponseError::UnknownTopicOrPartition.code(),
        KafkaError::NotLeader { .. } => ResponseError::NotLeaderOrFollower.code(),
        KafkaError::Protocol(ProtocolError::InvalidRecordBatch(_)) => {
            ResponseError::CorruptMessage.code()
        }
        KafkaError::OrderedLog(pepper_ordered_log::OrderedLogError::OffsetBeforeLogStart {
            ..
        }) => ResponseError::OffsetOutOfRange.code(),
        KafkaError::InvalidRequest(_) => ResponseError::InvalidRequest.code(),
        KafkaError::QuotaExceeded => 89,
        KafkaError::OrderedLog(_) | KafkaError::Extent(_) | KafkaError::Io(_) => {
            ResponseError::KafkaStorageError.code()
        }
        _ => ResponseError::UnknownServerError.code(),
    }
}

fn group_error_code(error: &GroupError) -> i16 {
    match error {
        GroupError::IllegalGeneration => 22,
        GroupError::InconsistentProtocol => 23,
        GroupError::UnknownMember => 25,
        GroupError::RebalanceInProgress => 27,
        GroupError::InvalidAssignment | GroupError::DuplicateAssignment => 42,
        GroupError::UnknownGroup => 69,
        GroupError::FencedCoordinator => 16,
        GroupError::Invalid => ResponseError::InvalidRequest.code(),
        GroupError::Codec(_) | GroupError::Io(_) => 1,
    }
}

fn transaction_error_code(error: &TransactionError) -> i16 {
    match error {
        TransactionError::FencedProducer => 90,
        TransactionError::OutOfOrderSequence => 45,
        TransactionError::InvalidTransactionState | TransactionError::NotTransactional => 48,
        TransactionError::UnknownProducer => 59,
        TransactionError::InvalidRecordBatch => ResponseError::InvalidRequest.code(),
        TransactionError::Codec(_) | TransactionError::Io(_) => {
            ResponseError::KafkaStorageError.code()
        }
    }
}

struct ConnectionContext {
    sasl: SaslSession,
    legacy_sasl_tokens: bool,
}

fn authorize_request(
    security: &KafkaSecurity,
    principal: &str,
    request: &RequestKind,
) -> Result<(), ServerError> {
    let authorize = |resource_type, resource: &str, operation| {
        security
            .authorize(principal, resource_type, resource, operation)
            .map_err(ServerError::from)
    };
    match request {
        RequestKind::Produce(request) => {
            for topic in &request.topic_data {
                authorize(
                    ResourceType::Topic,
                    topic.name.0.as_str(),
                    AclOperation::Write,
                )?;
            }
        }
        RequestKind::Fetch(request) => {
            for topic in &request.topics {
                authorize(
                    ResourceType::Topic,
                    topic.topic.0.as_str(),
                    AclOperation::Read,
                )?;
            }
        }
        RequestKind::ListOffsets(request) => {
            for topic in &request.topics {
                authorize(
                    ResourceType::Topic,
                    topic.name.0.as_str(),
                    AclOperation::Read,
                )?;
            }
        }
        RequestKind::Metadata(request) => match &request.topics {
            Some(topics) => {
                for topic in topics {
                    if let Some(name) = &topic.name {
                        authorize(ResourceType::Topic, name.0.as_str(), AclOperation::Describe)?;
                    }
                }
            }
            None => authorize(
                ResourceType::Cluster,
                "kafka-cluster",
                AclOperation::Describe,
            )?,
        },
        RequestKind::OffsetCommit(request) => authorize(
            ResourceType::Group,
            request.group_id.0.as_str(),
            AclOperation::Write,
        )?,
        RequestKind::OffsetFetch(request) => authorize(
            ResourceType::Group,
            request.group_id.0.as_str(),
            AclOperation::Read,
        )?,
        RequestKind::FindCoordinator(request) => authorize(
            if request.key_type == 1 {
                ResourceType::TransactionalId
            } else {
                ResourceType::Group
            },
            request.key.as_str(),
            AclOperation::Describe,
        )?,
        RequestKind::JoinGroup(request) => authorize(
            ResourceType::Group,
            request.group_id.0.as_str(),
            AclOperation::Write,
        )?,
        RequestKind::Heartbeat(request) => authorize(
            ResourceType::Group,
            request.group_id.0.as_str(),
            AclOperation::Write,
        )?,
        RequestKind::LeaveGroup(request) => authorize(
            ResourceType::Group,
            request.group_id.0.as_str(),
            AclOperation::Write,
        )?,
        RequestKind::SyncGroup(request) => authorize(
            ResourceType::Group,
            request.group_id.0.as_str(),
            AclOperation::Write,
        )?,
        RequestKind::DescribeGroups(request) => {
            for group in &request.groups {
                authorize(
                    ResourceType::Group,
                    group.0.as_str(),
                    AclOperation::Describe,
                )?;
            }
        }
        RequestKind::ListGroups(_) => authorize(
            ResourceType::Cluster,
            "kafka-cluster",
            AclOperation::Describe,
        )?,
        RequestKind::InitProducerId(request) => {
            if let Some(transactional_id) = &request.transactional_id {
                authorize(
                    ResourceType::TransactionalId,
                    transactional_id.0.as_str(),
                    AclOperation::Write,
                )?;
            }
        }
        RequestKind::AddPartitionsToTxn(request) => authorize(
            ResourceType::TransactionalId,
            request.v3_and_below_transactional_id.0.as_str(),
            AclOperation::Write,
        )?,
        RequestKind::AddOffsetsToTxn(request) => authorize(
            ResourceType::TransactionalId,
            request.transactional_id.0.as_str(),
            AclOperation::Write,
        )?,
        RequestKind::EndTxn(request) => authorize(
            ResourceType::TransactionalId,
            request.transactional_id.0.as_str(),
            AclOperation::Write,
        )?,
        RequestKind::TxnOffsetCommit(request) => {
            authorize(
                ResourceType::TransactionalId,
                request.transactional_id.0.as_str(),
                AclOperation::Write,
            )?;
            authorize(
                ResourceType::Group,
                request.group_id.0.as_str(),
                AclOperation::Write,
            )?;
        }
        RequestKind::CreateTopics(request) => {
            for topic in &request.topics {
                authorize(
                    ResourceType::Topic,
                    topic.name.0.as_str(),
                    AclOperation::Create,
                )?;
                security.audit_administrative_request(
                    principal,
                    "create_topic",
                    ResourceType::Topic,
                    topic.name.0.as_str(),
                );
            }
        }
        RequestKind::DeleteTopics(request) => {
            for topic in &request.topic_names {
                authorize(ResourceType::Topic, topic.0.as_str(), AclOperation::Delete)?;
                security.audit_administrative_request(
                    principal,
                    "delete_topic",
                    ResourceType::Topic,
                    topic.0.as_str(),
                );
            }
        }
        RequestKind::DescribeConfigs(request) => {
            for resource in &request.resources {
                authorize(
                    ResourceType::Topic,
                    resource.resource_name.as_str(),
                    AclOperation::Describe,
                )?;
            }
        }
        RequestKind::AlterConfigs(request) => {
            for resource in &request.resources {
                authorize(
                    ResourceType::Topic,
                    resource.resource_name.as_str(),
                    AclOperation::Alter,
                )?;
                security.audit_administrative_request(
                    principal,
                    "alter_config",
                    ResourceType::Topic,
                    resource.resource_name.as_str(),
                );
            }
        }
        RequestKind::DescribeCluster(_) => authorize(
            ResourceType::Cluster,
            "kafka-cluster",
            AclOperation::Describe,
        )?,
        RequestKind::ApiVersions(_)
        | RequestKind::SaslHandshake(_)
        | RequestKind::SaslAuthenticate(_) => {}
        _ => authorize(ResourceType::Cluster, "kafka-cluster", AclOperation::All)?,
    }
    Ok(())
}

fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

struct ResponseFrame {
    segments: Vec<Bytes>,
    length: usize,
}

impl ResponseFrame {
    fn contiguous(bytes: Bytes) -> Self {
        let length = bytes.len();
        Self {
            segments: vec![bytes],
            length,
        }
    }

    fn vectored(mut segments: Vec<Bytes>, maximum_frame_bytes: usize) -> Result<Self, ServerError> {
        let length = segments.iter().map(Bytes::len).sum::<usize>();
        let payload = length
            .checked_sub(4)
            .ok_or_else(|| ProtocolError::Malformed("response frame is truncated".into()))?;
        if payload > maximum_frame_bytes {
            return Err(ProtocolError::FrameTooLarge(payload).into());
        }
        let encoded = i32::try_from(payload).map_err(|_| ProtocolError::FrameTooLarge(payload))?;
        let first = segments
            .first_mut()
            .ok_or_else(|| ProtocolError::Malformed("response frame is empty".into()))?;
        let mut header = BytesMut::from(first.as_ref());
        header[..4].copy_from_slice(&encoded.to_be_bytes());
        *first = header.freeze();
        Ok(Self { segments, length })
    }
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("invalid Kafka server configuration")]
    InvalidConfiguration,
    #[error("Kafka security requires a TLS listener")]
    SecurityRequiresTls,
    #[error("invalid Kafka TLS configuration")]
    InvalidTls,
    #[error("Kafka TLS handshake failed")]
    TlsHandshake,
    #[error("Kafka authentication is required")]
    AuthenticationRequired,
    #[error("Kafka security check failed: {0}")]
    Security(#[from] SecurityError),
    #[error("Kafka listener I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Kafka protocol failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Kafka request timed out")]
    RequestTimeout,
    #[error("Kafka response write timed out")]
    WriteTimeout,
    #[error("Kafka broker response budget is exhausted: {0}")]
    Buffer(#[from] BufferError),
    #[error("unsupported Kafka API")]
    UnsupportedApi,
}
