// SPDX-License-Identifier: Apache-2.0

//! Kafka logical broker runtime over Pepper's ordered-log and RSM contracts.

pub mod compaction;
pub mod controller;
pub mod groups;
pub mod operations;
pub mod security;
pub mod server;
pub mod tiering;
pub mod transactions;

use bytes::Bytes;
use compaction::{CompactionBatch, select_retained_batches};
use controller::{
    ControllerCommand, ControllerError, ControllerMachine, ControllerResponse, ControllerState,
    TopicRecord,
};
use groups::GroupCoordinator;
use operations::{FetchWaiterRegistry, PartitionKey};
use pepper_extent::{FileExtentConfig, FileExtentStore};
use pepper_kafka_protocol::{ProtocolLimits, assign_record_offsets, validate_record_set};
use pepper_ordered_log::{
    Acknowledgments, OrderedLog, OrderedLogConfig, RecoveryState, ReplicatedAppend,
    ReplicatedPartition, RetentionPolicy,
};
use pepper_rsm::{DeterministicHost, ReplicatedStateMachine};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;
use tiering::{ColdSegmentKey, ColdSegmentRecord, ColdTier};
use tokio::sync::{Mutex, RwLock, Semaphore};
use transactions::{AppendDecision, TransactionCoordinator, TransactionPartition};

struct PartitionRuntime {
    descriptor: RwLock<controller::PartitionRecord>,
    replication: Mutex<ReplicatedPartition>,
    replicas: BTreeMap<i32, Arc<OrderedLog>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionDiagnostics {
    pub topic: String,
    pub partition: i32,
    pub leader_id: i32,
    pub leader_epoch: u64,
    pub assignment_epoch: u64,
    pub replicas: Vec<i32>,
    pub in_sync_replicas: Vec<i32>,
    pub online_replicas: Vec<i32>,
    pub log_start_offset: u64,
    pub high_watermark: u64,
    pub log_end_offset: u64,
    pub retained_sealed_bytes: u64,
    pub reclaimable_sealed_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerDiagnostics {
    pub cluster_id: String,
    pub controller_id: i32,
    pub controller_revision: u64,
    pub brokers: usize,
    pub topics: usize,
    pub partitions: Vec<PartitionDiagnostics>,
    pub fetch_waiters: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KafkaCompactionReport {
    pub topic: String,
    pub partition: i32,
    pub input_batches: u64,
    pub retained_batches: u64,
    pub obsolete_batches: u64,
    pub reclaimed_payload_bytes: u64,
    pub rewritten_replicas: usize,
    pub high_watermark_before: u64,
    pub high_watermark_after: u64,
}

pub struct KafkaCluster {
    root: PathBuf,
    controller: Arc<DeterministicHost<ControllerMachine>>,
    partitions: RwLock<BTreeMap<(String, i32), Arc<PartitionRuntime>>>,
    protocol_limits: ProtocolLimits,
    fetch_waiters: FetchWaiterRegistry,
    groups: Arc<GroupCoordinator>,
    transactions: Arc<TransactionCoordinator>,
    cleaner_gate: Arc<Semaphore>,
}

const KAFKA_FORMAT_FILE: &str = "kafka-format.json";
const KAFKA_FORMAT_VERSION: u32 = 13;
const KAFKA_MINIMUM_READER_VERSION: u32 = 8;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct KafkaFormatMarker {
    format_version: u32,
    minimum_reader_version: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct PartitionCheckpoint {
    high_watermark: u64,
    log_start_offset: u64,
}

impl KafkaCluster {
    pub async fn open(
        root: impl AsRef<Path>,
        cluster_id: impl Into<String>,
        controller_id: i32,
        brokers: Vec<(i32, String, u16)>,
        protocol_limits: ProtocolLimits,
    ) -> Result<Arc<Self>, KafkaError> {
        if brokers.is_empty() {
            return Err(KafkaError::InvalidRequest(
                "at least one broker is required",
            ));
        }
        let cluster_id = cluster_id.into();
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(KafkaError::Io)?;
        let format_path = root.join(KAFKA_FORMAT_FILE);
        if format_path.exists() {
            let marker: KafkaFormatMarker =
                serde_json::from_slice(&std::fs::read(&format_path)?)
                    .map_err(|error| KafkaError::FormatMarker(error.to_string()))?;
            if marker.format_version > KAFKA_FORMAT_VERSION
                || marker.minimum_reader_version > KAFKA_FORMAT_VERSION
                || marker.format_version < marker.minimum_reader_version
            {
                return Err(KafkaError::UnsupportedFormat {
                    found: marker.format_version,
                    supported: KAFKA_FORMAT_VERSION,
                });
            }
        }
        let controller_path = root.join("controller.json");
        let initial_state = if controller_path.exists() {
            let encoded = std::fs::read(&controller_path)?;
            let state: ControllerState = serde_json::from_slice(&encoded)
                .map_err(|error| KafkaError::ControllerState(error.to_string()))?;
            if state.cluster_id != cluster_id || state.controller_id != controller_id {
                return Err(KafkaError::InvalidRequest(
                    "persisted Kafka cluster identity does not match configuration",
                ));
            }
            state
        } else {
            ControllerState::new(cluster_id, controller_id)
        };
        let host = Arc::new(DeterministicHost::new(
            Arc::new(ControllerMachine),
            initial_state,
        ));
        for (broker_id, host_name, port) in brokers {
            let existing = host.state().await.brokers.get(&broker_id).cloned();
            if existing
                .as_ref()
                .is_some_and(|broker| broker.host == host_name && broker.port == port)
            {
                continue;
            }
            host.apply_batch([ControllerCommand::RegisterBroker {
                broker_id,
                host: host_name,
                port,
                rack: None,
                expected_epoch: existing.map(|broker| broker.broker_epoch),
            }])
            .await?;
        }
        let groups = GroupCoordinator::open(root.join("groups"), 32).await?;
        let transactions = Arc::new(TransactionCoordinator::open(root.join("transactions"))?);
        let cluster = Arc::new(Self {
            root,
            controller: host,
            partitions: RwLock::new(BTreeMap::new()),
            protocol_limits,
            fetch_waiters: FetchWaiterRegistry::new(),
            groups,
            transactions,
            cleaner_gate: Arc::new(Semaphore::new(1)),
        });
        let weak_transactions = Arc::downgrade(&cluster.transactions);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let Some(transactions) = weak_transactions.upgrade() else {
                    return;
                };
                let _ = transactions.expire(now_millis()).await;
            }
        });
        let state = cluster.controller.state().await;
        let mut runtimes = Vec::new();
        for topic in state.topics.values() {
            for descriptor in &topic.partitions {
                runtimes.push((
                    (topic.name.clone(), descriptor.partition_id),
                    cluster.open_partition(topic, descriptor).await?,
                ));
            }
        }
        cluster.partitions.write().await.extend(runtimes);
        cluster.recover_transaction_state().await?;
        cluster.recover_transactional_offsets().await?;
        cluster.persist_controller().await?;
        persist_format_marker(&format_path)?;
        Ok(cluster)
    }

    pub async fn controller_state(&self) -> ControllerState {
        self.controller.state().await
    }

    async fn recover_transaction_state(&self) -> Result<(), KafkaError> {
        let partitions = self.partitions.read().await.clone();
        for ((topic, partition), runtime) in partitions {
            let descriptor = runtime.descriptor.read().await.clone();
            let leader = runtime
                .replicas
                .get(&descriptor.leader_id)
                .ok_or(KafkaError::UnknownPartition)?;
            let progress = leader.progress(0)?;
            let fetched = leader.fetch(progress.log_start_offset, u64::MAX, true)?;
            let mut batches = Vec::new();
            for batch in fetched.batches {
                let summary = validate_record_set(batch.bytes.bytes(), self.protocol_limits)?;
                if summary.identities.len() == 1 {
                    batches.push((summary.identities[0], batch.base_offset, batch.last_offset));
                }
            }
            self.transactions
                .recover_partition(TransactionPartition::new(topic, partition), batches)
                .await?;
        }
        Ok(())
    }

    async fn recover_transactional_offsets(&self) -> Result<(), KafkaError> {
        for (identity, pending) in self.transactions.pending_committed_offsets().await {
            let mut grouped = BTreeMap::<String, Vec<(String, i32, i64, String)>>::new();
            for offset in pending {
                grouped.entry(offset.group).or_default().push((
                    offset.topic,
                    offset.partition,
                    offset.offset,
                    offset.metadata,
                ));
            }
            for (group, offsets) in grouped {
                self.groups
                    .apply(
                        &group,
                        groups::GroupCommand::CommitTransactionalOffsets {
                            group: group.clone(),
                            offsets,
                            now_ms: now_millis(),
                        },
                    )
                    .await?;
            }
            self.transactions.mark_offsets_applied(identity).await?;
        }
        Ok(())
    }

    pub async fn create_topic(
        &self,
        name: String,
        partitions: u32,
        replication_factor: u16,
        configs: BTreeMap<String, String>,
        validate_only: bool,
    ) -> Result<TopicRecord, KafkaError> {
        let minimum_isr = configs
            .get("min.insync.replicas")
            .and_then(|value| value.parse().ok())
            .unwrap_or(if replication_factor > 1 { 2 } else { 1 });
        if validate_only {
            let mut state = self.controller.state().await;
            let response = ControllerMachine
                .apply(
                    &mut state,
                    ControllerCommand::CreateTopic {
                        name,
                        partitions,
                        replication_factor,
                        minimum_in_sync_replicas: minimum_isr,
                        configs,
                    },
                )
                .await?;
            return topic_response(response);
        }
        let response = self
            .controller
            .apply_batch([ControllerCommand::CreateTopic {
                name,
                partitions,
                replication_factor,
                minimum_in_sync_replicas: minimum_isr,
                configs,
            }])
            .await?
            .pop()
            .ok_or(KafkaError::ControllerResponse)?;
        let topic = topic_response(response)?;
        let mut runtimes = Vec::new();
        for descriptor in &topic.partitions {
            runtimes.push((
                (topic.name.clone(), descriptor.partition_id),
                self.open_partition(&topic, descriptor).await?,
            ));
        }
        self.partitions.write().await.extend(runtimes);
        self.persist_controller().await?;
        Ok(topic)
    }

    async fn open_partition(
        &self,
        topic: &TopicRecord,
        descriptor: &controller::PartitionRecord,
    ) -> Result<Arc<PartitionRuntime>, KafkaError> {
        let mut replicas = BTreeMap::new();
        for broker_id in &descriptor.replicas {
            let directory = self
                .root
                .join(format!("broker-{broker_id}"))
                .join(hex_id(topic.topic_id))
                .join(descriptor.partition_id.to_string());
            let checkpoint = read_checkpoint(&directory)?;
            let store = Arc::new(FileExtentStore::open(
                &directory,
                FileExtentConfig::default(),
            )?);
            let mut partition_material = Vec::from(topic.topic_id);
            partition_material.extend_from_slice(&descriptor.partition_id.to_le_bytes());
            let digest = blake3::hash(&partition_material);
            let log = Arc::new(OrderedLog::open(
                store,
                OrderedLogConfig {
                    partition_key: digest.as_bytes()[..16].try_into().expect("fixed"),
                    maximum_segment_bytes: topic
                        .configs
                        .get("segment.bytes")
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(OrderedLogConfig::default().maximum_segment_bytes),
                    ..OrderedLogConfig::default()
                },
                RecoveryState {
                    promised_epoch: descriptor.leader_epoch.saturating_sub(1),
                    high_watermark: checkpoint.high_watermark,
                    log_start_offset: checkpoint.log_start_offset,
                },
            )?);
            replicas.insert(*broker_id as u32, log);
        }
        let leader = descriptor.leader_id as u32;
        let replication = ReplicatedPartition::new(
            replicas.clone(),
            leader,
            descriptor.leader_epoch,
            descriptor.assignment_epoch,
            usize::from(descriptor.minimum_in_sync_replicas),
        )?;
        Ok(Arc::new(PartitionRuntime {
            descriptor: RwLock::new(descriptor.clone()),
            replication: Mutex::new(replication),
            replicas: replicas
                .into_iter()
                .map(|(node, log)| (node as i32, log))
                .collect(),
        }))
    }

    pub async fn delete_topic(&self, name: &str) -> Result<[u8; 16], KafkaError> {
        let state = self.controller.state().await;
        let topic = state
            .topics
            .get(name)
            .ok_or(ControllerError::UnknownTopic)?;
        let epoch = topic.epoch;
        let response = self
            .controller
            .apply_batch([ControllerCommand::DeleteTopic {
                name: name.to_string(),
                expected_epoch: Some(epoch),
            }])
            .await?
            .pop()
            .ok_or(KafkaError::ControllerResponse)?;
        let ControllerResponse::Deleted { topic_id, .. } = response else {
            return Err(KafkaError::ControllerResponse);
        };
        self.partitions
            .write()
            .await
            .retain(|(topic, _), _| topic != name);
        self.persist_controller().await?;
        Ok(topic_id)
    }

    pub async fn alter_topic_configs(
        &self,
        name: &str,
        configs: BTreeMap<String, String>,
        validate_only: bool,
    ) -> Result<TopicRecord, KafkaError> {
        let response = self
            .controller
            .apply_batch([ControllerCommand::AlterTopicConfigs {
                name: name.to_string(),
                configs,
                validate_only,
            }])
            .await?
            .pop()
            .ok_or(KafkaError::ControllerResponse)?;
        let topic = topic_response(response)?;
        if !validate_only {
            self.persist_controller().await?;
        }
        Ok(topic)
    }

    pub async fn produce(
        &self,
        broker_id: i32,
        topic: &str,
        partition: i32,
        timestamp_ms: u64,
        records: Bytes,
        acknowledgments: Acknowledgments,
    ) -> Result<ReplicatedAppend, KafkaError> {
        let summary = validate_record_set(&records, self.protocol_limits)?;
        if summary.offset_span == 0 || summary.offset_span > u64::from(u32::MAX) {
            return Err(KafkaError::InvalidRequest("empty or oversized record set"));
        }
        let runtime = self.partition(topic, partition).await?;
        let descriptor = runtime.descriptor.read().await.clone();
        if descriptor.leader_id != broker_id {
            return Err(KafkaError::NotLeader {
                leader_id: descriptor.leader_id,
                leader_epoch: descriptor.leader_epoch,
            });
        }
        let mut replication = runtime.replication.lock().await;
        let leader = runtime
            .replicas
            .get(&descriptor.leader_id)
            .ok_or(KafkaError::UnknownPartition)?;
        let base_offset = leader.progress(0)?.log_end_offset;
        let base_offset_i64 = i64::try_from(base_offset).map_err(|_| KafkaError::OffsetOverflow)?;
        let assigned = assign_record_offsets(
            &records,
            base_offset_i64,
            i32::try_from(descriptor.leader_epoch).unwrap_or(i32::MAX),
        )?;
        let transaction_partition = TransactionPartition::new(topic, partition);
        let idempotent_identity = summary
            .identities
            .iter()
            .find(|identity| identity.producer_id >= 0)
            .copied();
        if idempotent_identity.is_some() && summary.identities.len() != 1 {
            return Err(KafkaError::InvalidRequest(
                "idempotent requests must contain one record batch",
            ));
        }
        if let Some(identity) = idempotent_identity {
            match self
                .transactions
                .prepare_append(transaction_partition.clone(), identity)
                .await?
            {
                AppendDecision::Duplicate { base_offset } => {
                    let progress = leader.progress(0)?;
                    return Ok(ReplicatedAppend {
                        result: pepper_ordered_log::AppendResult {
                            base_offset,
                            last_offset: base_offset
                                .saturating_add(u64::from(identity.record_count))
                                .saturating_sub(1),
                            leader_epoch: descriptor.leader_epoch,
                            high_watermark: progress.high_watermark,
                            durable_media_appends: 0,
                        },
                        durable_replicas: BTreeSet::new(),
                        acknowledged: true,
                    });
                }
                AppendDecision::Append => {}
                AppendDecision::NonIdempotent => unreachable!("producer identity is present"),
            }
        }
        let appended = match replication.append(
            descriptor.leader_id as u32,
            descriptor.leader_epoch,
            timestamp_ms,
            summary.offset_span as u32,
            assigned,
            acknowledgments,
        ) {
            Ok(appended) => appended,
            Err(error) => {
                if let Some(identity) = idempotent_identity {
                    self.transactions
                        .cancel_append(&transaction_partition, identity)
                        .await?;
                }
                return Err(error.into());
            }
        };
        if let Some(identity) = idempotent_identity {
            self.transactions
                .complete_append(
                    transaction_partition,
                    identity,
                    appended.result.base_offset,
                    appended.result.last_offset,
                )
                .await?;
        }
        self.persist_partition(&runtime).await?;
        drop(replication);
        self.apply_retention(topic, partition, timestamp_ms).await?;
        self.fetch_waiters
            .notify(&PartitionKey::new(topic, partition));
        Ok(appended)
    }

    pub async fn fetch(
        &self,
        broker_id: i32,
        topic: &str,
        partition: i32,
        offset: u64,
        maximum_bytes: u64,
    ) -> Result<pepper_ordered_log::FetchResult, KafkaError> {
        let runtime = self.partition(topic, partition).await?;
        let descriptor = runtime.descriptor.read().await;
        if descriptor.leader_id != broker_id {
            return Err(KafkaError::NotLeader {
                leader_id: descriptor.leader_id,
                leader_epoch: descriptor.leader_epoch,
            });
        }
        runtime
            .replicas
            .get(&descriptor.leader_id)
            .ok_or(KafkaError::UnknownPartition)?
            .fetch(offset, maximum_bytes, true)
            .map_err(KafkaError::from)
    }

    pub async fn offsets(
        &self,
        broker_id: i32,
        topic: &str,
        partition: i32,
    ) -> Result<(u64, u64, u64), KafkaError> {
        let runtime = self.partition(topic, partition).await?;
        let descriptor = runtime.descriptor.read().await;
        if descriptor.leader_id != broker_id {
            return Err(KafkaError::NotLeader {
                leader_id: descriptor.leader_id,
                leader_epoch: descriptor.leader_epoch,
            });
        }
        let progress = runtime
            .replicas
            .get(&descriptor.leader_id)
            .ok_or(KafkaError::UnknownPartition)?
            .progress(0)?;
        Ok((
            progress.log_start_offset,
            progress.high_watermark,
            progress.log_end_offset,
        ))
    }

    pub async fn elect_leader(
        &self,
        topic: &str,
        partition: i32,
        candidate: i32,
    ) -> Result<TopicRecord, KafkaError> {
        let runtime = self.partition(topic, partition).await?;
        let descriptor = runtime.descriptor.read().await.clone();
        let response = self
            .controller
            .apply_batch([ControllerCommand::ElectLeader {
                topic: topic.to_string(),
                partition,
                leader_id: candidate,
                expected_assignment_epoch: descriptor.assignment_epoch,
            }])
            .await?
            .pop()
            .ok_or(KafkaError::ControllerResponse)?;
        let topic_record = topic_response(response)?;
        let updated = topic_record
            .partitions
            .get(partition as usize)
            .ok_or(KafkaError::UnknownPartition)?
            .clone();
        let voters = updated
            .replicas
            .iter()
            .map(|node| *node as u32)
            .collect::<BTreeSet<_>>();
        runtime.replication.lock().await.elect(
            candidate as u32,
            updated.leader_epoch,
            updated.assignment_epoch,
            &voters,
        )?;
        *runtime.descriptor.write().await = updated;
        self.persist_controller().await?;
        self.persist_partition(&runtime).await?;
        Ok(topic_record)
    }

    async fn partition(
        &self,
        topic: &str,
        partition: i32,
    ) -> Result<Arc<PartitionRuntime>, KafkaError> {
        self.partitions
            .read()
            .await
            .get(&(topic.to_string(), partition))
            .cloned()
            .ok_or(KafkaError::UnknownPartition)
    }

    pub fn protocol_limits(&self) -> ProtocolLimits {
        self.protocol_limits
    }

    pub fn fetch_waiters(&self) -> FetchWaiterRegistry {
        self.fetch_waiters.clone()
    }

    pub fn groups(&self) -> Arc<GroupCoordinator> {
        Arc::clone(&self.groups)
    }

    pub fn transactions(&self) -> Arc<TransactionCoordinator> {
        Arc::clone(&self.transactions)
    }

    pub async fn apply_retention(
        &self,
        topic: &str,
        partition: i32,
        now_ms: u64,
    ) -> Result<Option<u64>, KafkaError> {
        let state = self.controller.state().await;
        let topic_record = state
            .topics
            .get(topic)
            .ok_or(KafkaError::UnknownPartition)?;
        let retention_ms = topic_record
            .configs
            .get("retention.ms")
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value >= 0)
            .map(|value| value as u64);
        let retention_bytes = topic_record
            .configs
            .get("retention.bytes")
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value >= 0)
            .map(|value| value as u64);
        if retention_ms.is_none() && retention_bytes.is_none() {
            return Ok(None);
        }
        let runtime = self.partition(topic, partition).await?;
        let _replication = runtime.replication.lock().await;
        let descriptor = runtime.descriptor.read().await.clone();
        let leader = runtime
            .replicas
            .get(&descriptor.leader_id)
            .ok_or(KafkaError::UnknownPartition)?;
        let candidates = leader.retention_candidates(RetentionPolicy {
            retain_after_timestamp_ms: retention_ms.map(|duration| now_ms.saturating_sub(duration)),
            maximum_sealed_bytes: retention_bytes,
        })?;
        let Some(log_start) = candidates.last().map(|manifest| manifest.end_offset) else {
            return Ok(None);
        };
        for log in runtime.replicas.values() {
            log.advance_log_start(descriptor.assignment_epoch, log_start)?;
        }
        drop(state);
        self.persist_partition(&runtime).await?;
        for log in runtime.replicas.values() {
            match log.reclaim_below_log_start() {
                Ok(_) => {}
                Err(pepper_ordered_log::OrderedLogError::Extent(
                    pepper_extent::ExtentError::ExtentLeased(_),
                )) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(Some(log_start))
    }

    pub async fn compact_partition(
        &self,
        topic: &str,
        partition: i32,
        now_ms: u64,
    ) -> Result<KafkaCompactionReport, KafkaError> {
        let _cleaner = self
            .cleaner_gate
            .acquire()
            .await
            .map_err(|_| KafkaError::InvalidRequest("cleaner scheduler stopped"))?;
        let cleaner_started = tokio::time::Instant::now();
        let controller = self.controller.state().await;
        let topic_record = controller
            .topics
            .get(topic)
            .ok_or(KafkaError::UnknownPartition)?;
        let compact_enabled = topic_record
            .configs
            .get("cleanup.policy")
            .is_some_and(|policy| policy.split(',').any(|part| part.trim() == "compact"));
        if !compact_enabled {
            return Err(KafkaError::InvalidRequest(
                "topic cleanup.policy does not include compact",
            ));
        }
        let delete_retention_ms = topic_record
            .configs
            .get("delete.retention.ms")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(24 * 60 * 60 * 1_000);
        let runtime = self.partition(topic, partition).await?;
        let descriptor = runtime.descriptor.read().await.clone();
        let leader = runtime
            .replicas
            .get(&descriptor.leader_id)
            .ok_or(KafkaError::UnknownPartition)?;
        let before = leader.progress(0)?;
        let manifests = leader.sealed_manifests()?;
        let mut batches = Vec::new();
        for manifest in &manifests {
            let fetched =
                leader.fetch(manifest.base_offset, manifest.payload_bytes.max(1), true)?;
            batches.extend(
                fetched
                    .batches
                    .into_iter()
                    .filter(|batch| batch.base_offset < manifest.end_offset)
                    .map(|batch| CompactionBatch {
                        base_offset: batch.base_offset,
                        timestamp_ms: batch.timestamp_ms,
                        bytes: batch.bytes.into_bytes(),
                    }),
            );
        }
        let selection = select_retained_batches(&batches, now_ms, delete_retention_ms);
        let mut retained_batches = 0;
        let mut reclaimed_payload_bytes = 0;
        let mut rewritten_replicas = 0;
        for (replica_id, replica) in &runtime.replicas {
            let replica_manifests = replica.sealed_manifests()?;
            for logical in &manifests {
                let replica_manifest = replica_manifests
                    .iter()
                    .find(|candidate| {
                        candidate.base_offset == logical.base_offset
                            && candidate.end_offset == logical.end_offset
                    })
                    .ok_or(KafkaError::InvalidRequest(
                        "replica sealed-segment layout is inconsistent",
                    ))?;
                let result = replica
                    .compact_sealed(replica_manifest.extent_id, &selection.retained_offsets)?;
                if result.reclaimed_payload_bytes > 0 {
                    rewritten_replicas += 1;
                }
                if *replica_id == descriptor.leader_id {
                    retained_batches += result.retained_batches;
                    reclaimed_payload_bytes += result.reclaimed_payload_bytes;
                }
            }
        }
        let after = leader.progress(0)?;
        if before.high_watermark != after.high_watermark
            || before.log_end_offset != after.log_end_offset
        {
            return Err(KafkaError::InvalidRequest(
                "compaction changed the committed log boundary",
            ));
        }
        let report = KafkaCompactionReport {
            topic: topic.to_string(),
            partition,
            input_batches: selection.input_batches as u64,
            retained_batches,
            obsolete_batches: selection.obsolete_batches as u64,
            reclaimed_payload_bytes,
            rewritten_replicas,
            high_watermark_before: before.high_watermark,
            high_watermark_after: after.high_watermark,
        };
        const CLEANER_BYTES_PER_SECOND: u64 = 50 * 1024 * 1024;
        let target = std::time::Duration::from_secs_f64(
            batches
                .iter()
                .map(|batch| batch.bytes.len() as u64)
                .sum::<u64>() as f64
                / CLEANER_BYTES_PER_SECOND as f64,
        );
        if let Some(remaining) = target.checked_sub(cleaner_started.elapsed()) {
            tokio::time::sleep(remaining).await;
        }
        Ok(report)
    }

    pub async fn archive_sealed_segment(
        &self,
        cold: &ColdTier,
        topic: &str,
        partition: i32,
        base_offset: u64,
        erasure: Option<(usize, usize)>,
    ) -> Result<ColdSegmentRecord, KafkaError> {
        let runtime = self.partition(topic, partition).await?;
        let descriptor = runtime.descriptor.read().await.clone();
        let leader = runtime
            .replicas
            .get(&descriptor.leader_id)
            .ok_or(KafkaError::UnknownPartition)?;
        let manifest = leader
            .sealed_manifests()?
            .into_iter()
            .find(|manifest| manifest.base_offset == base_offset)
            .ok_or(KafkaError::InvalidRequest("sealed segment not found"))?;
        let image = leader.sealed_segment_image(manifest.extent_id)?;
        let key = ColdSegmentKey {
            topic: topic.to_string(),
            partition,
            base_offset: manifest.base_offset,
            end_offset: manifest.end_offset,
        };
        match erasure {
            Some((data, parity)) => cold.archive_erasure(key, &image, data, parity),
            None => cold.archive_replicated(key, &image),
        }
        .map_err(KafkaError::from)
    }

    pub async fn set_replica_online(
        &self,
        topic: &str,
        partition: i32,
        broker_id: i32,
        online: bool,
    ) -> Result<(), KafkaError> {
        let runtime = self.partition(topic, partition).await?;
        let mut replication = runtime.replication.lock().await;
        if online {
            replication.recover_replica(broker_id as u32)?;
        } else {
            replication.set_online(broker_id as u32, false)?;
        }
        self.persist_partition(&runtime).await
    }

    pub async fn rolling_restart_replica(
        &self,
        topic: &str,
        partition: i32,
        broker_id: i32,
    ) -> Result<(), KafkaError> {
        self.set_replica_online(topic, partition, broker_id, false)
            .await?;
        self.set_replica_online(topic, partition, broker_id, true)
            .await
    }

    pub async fn reassign_partition(
        &self,
        topic: &str,
        partition: i32,
        replicas: Vec<i32>,
    ) -> Result<controller::PartitionRecord, KafkaError> {
        let runtime = self.partition(topic, partition).await?;
        let current = runtime.descriptor.read().await.clone();
        let command = ControllerCommand::ReassignPartition {
            topic: topic.to_string(),
            partition,
            replicas: replicas.clone(),
            expected_assignment_epoch: current.assignment_epoch,
        };
        let mut preview = self.controller.state().await;
        let response = ControllerMachine
            .apply(&mut preview, command.clone())
            .await?;
        let preview_topic = topic_response(response)?;
        let updated = preview_topic
            .partitions
            .get(partition as usize)
            .cloned()
            .ok_or(KafkaError::UnknownPartition)?;
        runtime.replication.lock().await.reconfigure(
            replicas
                .iter()
                .map(|broker| *broker as u32)
                .collect::<BTreeSet<_>>(),
            updated.leader_epoch,
            updated.assignment_epoch,
        )?;
        let response = self
            .controller
            .apply_batch([command])
            .await?
            .pop()
            .ok_or(KafkaError::ControllerResponse)?;
        let committed = topic_response(response)?
            .partitions
            .get(partition as usize)
            .cloned()
            .ok_or(KafkaError::UnknownPartition)?;
        *runtime.descriptor.write().await = committed.clone();
        self.persist_controller().await?;
        self.persist_partition(&runtime).await?;
        Ok(committed)
    }

    pub async fn diagnostics(&self, now_ms: u64) -> Result<BrokerDiagnostics, KafkaError> {
        let state = self.controller.state().await;
        let runtimes = self.partitions.read().await.clone();
        let mut partitions = Vec::with_capacity(runtimes.len());
        for ((topic, partition), runtime) in runtimes {
            let descriptor = runtime.descriptor.read().await.clone();
            let replication = runtime.replication.lock().await;
            let status = replication.status();
            let leader = runtime
                .replicas
                .get(&descriptor.leader_id)
                .ok_or(KafkaError::UnknownPartition)?;
            let progress = leader.progress(0)?;
            let manifests = leader.sealed_manifests()?;
            let retained_sealed_bytes = manifests
                .iter()
                .map(|manifest| manifest.payload_bytes)
                .sum();
            let topic_record = state
                .topics
                .get(&topic)
                .ok_or(KafkaError::UnknownPartition)?;
            let retention_ms = topic_record
                .configs
                .get("retention.ms")
                .and_then(|value| value.parse::<i64>().ok())
                .filter(|value| *value >= 0)
                .map(|value| value as u64);
            let retention_bytes = topic_record
                .configs
                .get("retention.bytes")
                .and_then(|value| value.parse::<i64>().ok())
                .filter(|value| *value >= 0)
                .map(|value| value as u64);
            let reclaimable_sealed_bytes = leader
                .retention_candidates(RetentionPolicy {
                    retain_after_timestamp_ms: retention_ms
                        .map(|duration| now_ms.saturating_sub(duration)),
                    maximum_sealed_bytes: retention_bytes,
                })?
                .iter()
                .map(|manifest| manifest.payload_bytes)
                .sum();
            partitions.push(PartitionDiagnostics {
                topic,
                partition,
                leader_id: descriptor.leader_id,
                leader_epoch: descriptor.leader_epoch,
                assignment_epoch: descriptor.assignment_epoch,
                replicas: descriptor.replicas,
                in_sync_replicas: status
                    .in_sync_replicas
                    .into_iter()
                    .map(|node| node as i32)
                    .collect(),
                online_replicas: status
                    .online_replicas
                    .into_iter()
                    .map(|node| node as i32)
                    .collect(),
                log_start_offset: progress.log_start_offset,
                high_watermark: progress.high_watermark,
                log_end_offset: progress.log_end_offset,
                retained_sealed_bytes,
                reclaimable_sealed_bytes,
            });
        }
        Ok(BrokerDiagnostics {
            cluster_id: state.cluster_id.clone(),
            controller_id: state.controller_id,
            controller_revision: state.revision,
            brokers: state.brokers.len(),
            topics: state.topics.len(),
            partitions,
            fetch_waiters: self.fetch_waiters.snapshot().registered,
        })
    }

    async fn persist_controller(&self) -> Result<(), KafkaError> {
        let encoded = serde_json::to_vec(&self.controller.state().await)
            .map_err(|error| KafkaError::ControllerState(error.to_string()))?;
        persist_atomic(&self.root.join("controller.json"), &encoded)
    }

    async fn persist_partition(&self, runtime: &Arc<PartitionRuntime>) -> Result<(), KafkaError> {
        let descriptor = runtime.descriptor.read().await.clone();
        let state = self.controller.state().await;
        let topic = state
            .topics
            .values()
            .find(|topic| {
                topic.partitions.iter().any(|partition| {
                    partition.partition_id == descriptor.partition_id
                        && partition.assignment_epoch == descriptor.assignment_epoch
                })
            })
            .ok_or(KafkaError::UnknownPartition)?;
        for (broker_id, log) in &runtime.replicas {
            let progress = log.progress(0)?;
            let checkpoint = PartitionCheckpoint {
                high_watermark: progress.high_watermark,
                log_start_offset: progress.log_start_offset,
            };
            let encoded = serde_json::to_vec(&checkpoint)
                .map_err(|error| KafkaError::ControllerState(error.to_string()))?;
            let directory = self
                .root
                .join(format!("broker-{broker_id}"))
                .join(hex_id(topic.topic_id))
                .join(descriptor.partition_id.to_string());
            persist_atomic(&directory.join("recovery.json"), &encoded)?;
        }
        Ok(())
    }
}

fn read_checkpoint(directory: &Path) -> Result<PartitionCheckpoint, KafkaError> {
    let path = directory.join("recovery.json");
    if !path.exists() {
        return Ok(PartitionCheckpoint {
            high_watermark: 0,
            log_start_offset: 0,
        });
    }
    serde_json::from_slice(&std::fs::read(path)?)
        .map_err(|error| KafkaError::ControllerState(error.to_string()))
}

fn persist_atomic(path: &Path, encoded: &[u8]) -> Result<(), KafkaError> {
    use std::io::Write;

    let temporary = path.with_extension("tmp");
    let mut file = std::fs::File::create(&temporary)?;
    file.write_all(encoded)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn topic_response(response: ControllerResponse) -> Result<TopicRecord, KafkaError> {
    match response {
        ControllerResponse::Topic(topic) => Ok(topic),
        _ => Err(KafkaError::ControllerResponse),
    }
}

fn hex_id(id: [u8; 16]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn persist_format_marker(path: &Path) -> Result<(), KafkaError> {
    let marker = KafkaFormatMarker {
        format_version: KAFKA_FORMAT_VERSION,
        minimum_reader_version: KAFKA_MINIMUM_READER_VERSION,
    };
    let encoded = serde_json::to_vec_pretty(&marker)
        .map_err(|error| KafkaError::FormatMarker(error.to_string()))?;
    let staging = path.with_extension("json.next");
    std::fs::write(&staging, encoded)?;
    let file = std::fs::File::open(&staging)?;
    file.sync_all()?;
    std::fs::rename(&staging, path)?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum KafkaError {
    #[error("controller operation failed: {0}")]
    Controller(#[from] ControllerError),
    #[error("unexpected controller response")]
    ControllerResponse,
    #[error("invalid persisted controller state: {0}")]
    ControllerState(String),
    #[error("invalid Kafka format marker: {0}")]
    FormatMarker(String),
    #[error("unsupported Kafka format {found}; this binary supports through {supported}")]
    UnsupportedFormat { found: u32, supported: u32 },
    #[error("ordered-log operation failed: {0}")]
    OrderedLog(#[from] pepper_ordered_log::OrderedLogError),
    #[error("extent operation failed: {0}")]
    Extent(#[from] pepper_extent::ExtentError),
    #[error("Kafka protocol operation failed: {0}")]
    Protocol(#[from] pepper_kafka_protocol::ProtocolError),
    #[error("consumer group operation failed: {0}")]
    Group(#[from] groups::GroupError),
    #[error("transaction operation failed: {0}")]
    Transaction(#[from] transactions::TransactionError),
    #[error("cold-tier operation failed: {0}")]
    ColdTier(#[from] tiering::ColdTierError),
    #[error("unknown topic or partition")]
    UnknownPartition,
    #[error("broker is not leader; leader={leader_id} epoch={leader_epoch}")]
    NotLeader { leader_id: i32, leader_epoch: u64 },
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("offset overflow")]
    OffsetOverflow,
    #[error("Kafka quota exceeded")]
    QuotaExceeded,
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
}
