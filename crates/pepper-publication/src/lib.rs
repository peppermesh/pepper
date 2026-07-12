// SPDX-License-Identifier: Apache-2.0

//! Shared publication barrier for namespace-backed KV, bucket, and filesystem writes.

use async_trait::async_trait;
use pepper_consensus::{
    ConsensusDataStore, ConsensusResponse, NamespaceGroupManager, PublicationIntentRecord,
    namespace_log_contains,
};
use pepper_dag::{DagCodecRegistry, TraversalLimits, traverse};
use pepper_metadata::{
    MetadataStore, NAMESPACE_DURABILITY_RECEIPTS, NAMESPACE_PUBLICATION_INTENTS,
    NAMESPACE_READ_LEASES, NAMESPACE_STAGING_LEASES,
};
use pepper_namespace::{
    ApplyResult, CommandEnvelope, CommandResponse, NamespaceCommand, NamespaceId,
    NamespaceMutation, NamespaceStateMachine, PinAction,
};
use pepper_types::{Cid, DurabilityReceipt};
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};
use thiserror::Error;

#[derive(Debug, Clone, Copy)]
pub struct PublicationLimits {
    pub max_staging_leases: usize,
    pub max_staging_roots: usize,
    pub max_staging_bytes: u64,
    pub max_staging_ttl_seconds: i64,
    pub max_read_ttl_seconds: i64,
    pub max_dag_blocks: usize,
    pub max_dag_depth: usize,
    pub max_dag_links: usize,
    pub max_dag_payload_bytes: u64,
}

impl Default for PublicationLimits {
    fn default() -> Self {
        Self {
            max_staging_leases: 10_000,
            max_staging_roots: 10_000,
            max_staging_bytes: 16 * 1024 * 1024 * 1024,
            max_staging_ttl_seconds: 15 * 60,
            max_read_ttl_seconds: 60 * 60,
            max_dag_blocks: 1_000_000,
            max_dag_depth: 1_024,
            max_dag_links: 4_000_000,
            max_dag_payload_bytes: 16 * 1024 * 1024 * 1024,
        }
    }
}

impl PublicationLimits {
    pub fn validate(self) -> Result<Self, PublicationError> {
        if self.max_staging_leases == 0
            || self.max_staging_roots == 0
            || self.max_staging_bytes == 0
            || self.max_staging_ttl_seconds <= 0
            || self.max_read_ttl_seconds <= 0
            || self.max_dag_blocks == 0
            || self.max_dag_depth == 0
            || self.max_dag_links == 0
            || self.max_dag_payload_bytes == 0
        {
            return Err(PublicationError::InvalidLimits);
        }
        Ok(self)
    }

    fn traversal(self) -> TraversalLimits {
        TraversalLimits {
            max_blocks: self.max_dag_blocks,
            max_depth: self.max_dag_depth,
            max_links_per_block: self.max_dag_links,
            max_total_links: self.max_dag_links,
            max_payload_bytes: self.max_dag_payload_bytes.min(usize::MAX as u64) as usize,
            max_total_payload_bytes: self.max_dag_payload_bytes,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StagingLease {
    pub lease_id: String,
    pub namespace_id: NamespaceId,
    pub request_id: String,
    pub roots: Vec<Cid>,
    pub staged_bytes: u64,
    pub created_at_unix_seconds: i64,
    pub expires_at_unix_seconds: i64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadLease {
    pub lease_id: String,
    pub namespace_id: NamespaceId,
    pub root_cid: Cid,
    pub revision: u64,
    pub created_at_unix_seconds: i64,
    pub expires_at_unix_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredDurabilityReceipt {
    pub namespace_id: NamespaceId,
    pub request_id: String,
    pub receipt: DurabilityReceipt,
    pub verified_at_unix_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicationOperationalStats {
    pub active_staging_leases: usize,
    pub active_staging_bytes: u64,
    pub active_read_leases: usize,
    pub pending_pin_intents: usize,
    pub durability_receipts: usize,
}

#[derive(Debug, Clone)]
pub struct PublicationRequest {
    pub namespace_id: NamespaceId,
    pub command: CommandEnvelope,
    pub uploaded_roots: Vec<Cid>,
    pub staged_bytes: u64,
    pub staging_ttl_seconds: i64,
    pub retain_uploaded_on_conflict: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicationResult {
    pub apply: ApplyResult,
    pub durability: Vec<DurabilityReceipt>,
    pub staging_lease_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationFaultPoint {
    ValueDurability,
    CandidateRoot,
    StagingLease,
    LeaderValidation,
    LocalLogPersistence,
    FollowerLogPersistence,
    QuorumCommit,
    StateMachineApply,
    PinIntentApply,
    CheckpointPublication,
    StagingRelease,
    OldRootRetirement,
}

pub trait PublicationFaultInjector: Send + Sync + 'static {
    fn hit(&self, point: PublicationFaultPoint) -> Result<(), PublicationError>;
}

struct NoFaults;

impl PublicationFaultInjector for NoFaults {
    fn hit(&self, _point: PublicationFaultPoint) -> Result<(), PublicationError> {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum PublicationError {
    #[error("invalid publication limits")]
    InvalidLimits,
    #[error("staging lease limit exceeded")]
    StagingUnavailable,
    #[error("staging lease is invalid or expired")]
    TransactionExpired,
    #[error("durability requirement was not met for {0}")]
    DurabilityNotMet(Cid),
    #[error("namespace publication conflict: {0}")]
    Conflict(String),
    #[error("namespace application error {code}: {message}")]
    Application { code: String, message: String },
    #[error("publication storage failed: {0}")]
    Storage(String),
    #[error("publication protection failed: {0}")]
    Protection(String),
    #[error("publication traversal failed: {0}")]
    Traversal(String),
    #[error("namespace publication failed: {0}")]
    Namespace(String),
    #[error("publication fault injected at {0:?}")]
    Injected(PublicationFaultPoint),
}

#[async_trait]
pub trait DurabilityBackend: Send + Sync + 'static {
    async fn ensure_durable(
        &self,
        cid: &Cid,
        replication_factor: usize,
    ) -> Result<DurabilityReceipt, PublicationError>;
}

#[async_trait]
pub trait ProtectionBackend: Send + Sync + 'static {
    async fn protect(
        &self,
        namespace_id: &NamespaceId,
        cid: &Cid,
        reason: &str,
        expires_at_unix_seconds: Option<i64>,
    ) -> Result<(), PublicationError>;
    async fn release(
        &self,
        namespace_id: &NamespaceId,
        cid: &Cid,
        reason: &str,
    ) -> Result<(), PublicationError>;
}

#[derive(Clone)]
pub struct PublicationRepository {
    metadata: Arc<MetadataStore>,
    limits: PublicationLimits,
}

impl PublicationRepository {
    pub fn new(
        metadata: Arc<MetadataStore>,
        limits: PublicationLimits,
    ) -> Result<Self, PublicationError> {
        Ok(Self {
            metadata,
            limits: limits.validate()?,
        })
    }

    pub fn put_staging(&self, lease: &StagingLease) -> Result<(), PublicationError> {
        if lease.roots.is_empty()
            || lease.roots.len() > self.limits.max_staging_roots
            || lease.staged_bytes > self.limits.max_staging_bytes
            || lease.expires_at_unix_seconds <= lease.created_at_unix_seconds
            || lease.expires_at_unix_seconds - lease.created_at_unix_seconds
                > self.limits.max_staging_ttl_seconds
            || self.active_staging(lease.created_at_unix_seconds)?.len()
                >= self.limits.max_staging_leases
        {
            return Err(PublicationError::StagingUnavailable);
        }
        write_record(
            &self.metadata,
            NAMESPACE_STAGING_LEASES,
            &lease.lease_id,
            lease,
        )
    }

    pub fn update_staging(&self, lease: &StagingLease) -> Result<(), PublicationError> {
        write_record(
            &self.metadata,
            NAMESPACE_STAGING_LEASES,
            &lease.lease_id,
            lease,
        )
    }

    pub fn staging(&self, lease_id: &str) -> Result<Option<StagingLease>, PublicationError> {
        read_record(&self.metadata, NAMESPACE_STAGING_LEASES, lease_id)
    }

    pub fn active_staging(&self, now: i64) -> Result<Vec<StagingLease>, PublicationError> {
        Ok(
            read_all::<StagingLease>(&self.metadata, NAMESPACE_STAGING_LEASES)?
                .into_iter()
                .filter(|lease| lease.status == "active" && lease.expires_at_unix_seconds > now)
                .collect(),
        )
    }

    pub fn put_read_lease(&self, lease: &ReadLease) -> Result<(), PublicationError> {
        if lease.expires_at_unix_seconds <= lease.created_at_unix_seconds
            || lease.expires_at_unix_seconds - lease.created_at_unix_seconds
                > self.limits.max_read_ttl_seconds
        {
            return Err(PublicationError::TransactionExpired);
        }
        write_record(
            &self.metadata,
            NAMESPACE_READ_LEASES,
            &lease.lease_id,
            lease,
        )
    }

    pub fn read_lease(&self, lease_id: &str) -> Result<Option<ReadLease>, PublicationError> {
        read_record(&self.metadata, NAMESPACE_READ_LEASES, lease_id)
    }

    pub fn release_read_lease(&self, lease_id: &str) -> Result<(), PublicationError> {
        delete_record(&self.metadata, NAMESPACE_READ_LEASES, lease_id)
    }

    pub fn operational_stats(
        &self,
        now: i64,
    ) -> Result<PublicationOperationalStats, PublicationError> {
        let staging = read_all::<StagingLease>(&self.metadata, NAMESPACE_STAGING_LEASES)?
            .into_iter()
            .filter(|lease| lease.expires_at_unix_seconds >= now && lease.status == "active")
            .collect::<Vec<_>>();
        let read_leases = self.active_read_leases(now)?;
        let pending_pin_intents =
            read_all::<PublicationIntentRecord>(&self.metadata, NAMESPACE_PUBLICATION_INTENTS)?
                .into_iter()
                .filter(|intent| intent.status != "applied" && intent.status != "released")
                .count();
        let durability_receipts =
            read_all::<StoredDurabilityReceipt>(&self.metadata, NAMESPACE_DURABILITY_RECEIPTS)?
                .len();
        Ok(PublicationOperationalStats {
            active_staging_leases: staging.len(),
            active_staging_bytes: staging.iter().map(|lease| lease.staged_bytes).sum(),
            active_read_leases: read_leases.len(),
            pending_pin_intents,
            durability_receipts,
        })
    }

    pub fn active_read_leases(&self, now: i64) -> Result<Vec<ReadLease>, PublicationError> {
        Ok(
            read_all::<ReadLease>(&self.metadata, NAMESPACE_READ_LEASES)?
                .into_iter()
                .filter(|lease| lease.expires_at_unix_seconds > now)
                .collect(),
        )
    }

    pub fn pending_intents(&self) -> Result<Vec<PublicationIntentRecord>, PublicationError> {
        Ok(
            read_all::<PublicationIntentRecord>(&self.metadata, NAMESPACE_PUBLICATION_INTENTS)?
                .into_iter()
                .filter(|intent| intent.status == "pending")
                .collect(),
        )
    }

    pub fn mark_intent_resolved(
        &self,
        intent: &PublicationIntentRecord,
    ) -> Result<(), PublicationError> {
        let mut resolved = intent.clone();
        resolved.status = "resolved".to_string();
        write_record(
            &self.metadata,
            NAMESPACE_PUBLICATION_INTENTS,
            &resolved.intent_id,
            &resolved,
        )
    }

    pub fn mark_intent_applied(
        &self,
        intent: &PublicationIntentRecord,
    ) -> Result<(), PublicationError> {
        let mut applied = intent.clone();
        applied.status = "applied".to_string();
        write_record(
            &self.metadata,
            NAMESPACE_PUBLICATION_INTENTS,
            &applied.intent_id,
            &applied,
        )
    }

    pub fn durable_receipt(
        &self,
        cid: &Cid,
        required: usize,
        now: i64,
    ) -> Result<Option<DurabilityReceipt>, PublicationError> {
        Ok(
            read_all::<StoredDurabilityReceipt>(&self.metadata, NAMESPACE_DURABILITY_RECEIPTS)?
                .into_iter()
                .filter(|record| {
                    &record.receipt.cid == cid
                        && record.receipt.replicas_accepted >= required
                        && record.receipt.status == "durable"
                        && record.verified_at_unix_seconds >= now.saturating_sub(60 * 60)
                })
                .max_by_key(|record| record.verified_at_unix_seconds)
                .map(|record| record.receipt),
        )
    }

    pub fn put_durability(&self, record: &StoredDurabilityReceipt) -> Result<(), PublicationError> {
        let key = format!(
            "{}|{}|{}",
            record.namespace_id, record.request_id, record.receipt.cid
        );
        write_record(&self.metadata, NAMESPACE_DURABILITY_RECEIPTS, &key, record)
    }

    pub fn protected_roots(&self, now: i64) -> Result<HashSet<Cid>, PublicationError> {
        let mut roots = HashSet::new();
        for lease in self.active_staging(now)? {
            roots.extend(lease.roots);
        }
        roots.extend(
            self.active_read_leases(now)?
                .into_iter()
                .map(|lease| lease.root_cid),
        );
        roots.extend(
            read_all::<PublicationIntentRecord>(&self.metadata, NAMESPACE_PUBLICATION_INTENTS)?
                .into_iter()
                .filter(|intent| {
                    intent.action == PinAction::Protect
                        && (intent.status == "pending" || intent.status == "applied")
                })
                .map(|intent| intent.cid),
        );
        Ok(roots)
    }
}

pub struct PublicationCoordinator<D, P> {
    manager: Arc<NamespaceGroupManager>,
    data_store: ConsensusDataStore,
    registry: Arc<DagCodecRegistry>,
    repository: PublicationRepository,
    durability: Arc<D>,
    protection: Arc<P>,
    limits: PublicationLimits,
    fault_injector: Arc<dyn PublicationFaultInjector>,
}

impl<D, P> PublicationCoordinator<D, P>
where
    D: DurabilityBackend,
    P: ProtectionBackend,
{
    pub fn new(
        manager: Arc<NamespaceGroupManager>,
        data_store: ConsensusDataStore,
        registry: Arc<DagCodecRegistry>,
        repository: PublicationRepository,
        durability: Arc<D>,
        protection: Arc<P>,
        limits: PublicationLimits,
    ) -> Result<Self, PublicationError> {
        Ok(Self {
            manager,
            data_store,
            registry,
            repository,
            durability,
            protection,
            limits: limits.validate()?,
            fault_injector: Arc::new(NoFaults),
        })
    }

    pub fn with_fault_injector(
        mut self,
        fault_injector: Arc<dyn PublicationFaultInjector>,
    ) -> Self {
        self.fault_injector = fault_injector;
        self
    }

    fn fault(&self, point: PublicationFaultPoint) -> Result<(), PublicationError> {
        self.fault_injector.hit(point)
    }

    pub async fn acquire_read_lease(&self, lease: ReadLease) -> Result<(), PublicationError> {
        self.repository.put_read_lease(&lease)?;
        self.protection
            .protect(
                &lease.namespace_id,
                &lease.root_cid,
                &format!("namespace-read:{}", lease.lease_id),
                Some(lease.expires_at_unix_seconds),
            )
            .await
    }

    pub async fn release_read_lease(&self, lease_id: &str) -> Result<(), PublicationError> {
        let Some(lease) = self.repository.read_lease(lease_id)? else {
            return Ok(());
        };
        self.protection
            .release(
                &lease.namespace_id,
                &lease.root_cid,
                &format!("namespace-read:{}", lease.lease_id),
            )
            .await?;
        self.repository.release_read_lease(lease_id)
    }

    pub async fn publish(
        &self,
        request: PublicationRequest,
        now: i64,
    ) -> Result<PublicationResult, PublicationError> {
        let lease_id = format!("{}:{}", request.namespace_id, request.command.request_id);
        let expires = now
            .checked_add(request.staging_ttl_seconds)
            .ok_or(PublicationError::StagingUnavailable)?;
        let mut roots = command_value_cids(&request.command);
        roots.extend(request.uploaded_roots.iter().cloned());
        roots.sort_by_key(ToString::to_string);
        roots.dedup();
        let mut lease = StagingLease {
            lease_id: lease_id.clone(),
            namespace_id: request.namespace_id.clone(),
            request_id: request.command.request_id.clone(),
            roots,
            staged_bytes: request.staged_bytes,
            created_at_unix_seconds: now,
            expires_at_unix_seconds: expires,
            status: "active".to_string(),
        };
        self.repository.put_staging(&lease)?;
        self.fault(PublicationFaultPoint::StagingLease)?;
        let staging_reason = format!("namespace-staging:{}", lease.lease_id);
        for root in &lease.roots {
            self.protection
                .protect(&request.namespace_id, root, &staging_reason, Some(expires))
                .await?;
        }

        let result = self.publish_staged(&request, &mut lease, now).await;
        if result.is_ok() {
            // Permanent distributed protection must be visible before temporary
            // staging pins are withdrawn.
            self.reconcile_pin_intents().await?;
        }
        if result.is_err() && request.retain_uploaded_on_conflict {
            for root in &request.uploaded_roots {
                self.protection
                    .protect(
                        &request.namespace_id,
                        root,
                        "uploaded-publication-conflict",
                        None,
                    )
                    .await?;
            }
        }
        self.release_staging(&mut lease).await?;
        result.map(|(apply, durability)| PublicationResult {
            apply,
            durability,
            staging_lease_id: lease_id,
        })
    }

    async fn publish_staged(
        &self,
        request: &PublicationRequest,
        lease: &mut StagingLease,
        now: i64,
    ) -> Result<(ApplyResult, Vec<DurabilityReceipt>), PublicationError> {
        let initial = self
            .manager
            .linearizable_namespace_state(&request.namespace_id)
            .await
            .map_err(|error| PublicationError::Namespace(error.to_string()))?;
        self.fault(PublicationFaultPoint::LeaderValidation)?;
        let mut preview = NamespaceStateMachine::new(self.data_store.clone(), initial.clone())
            .map_err(|error| PublicationError::Namespace(error.to_string()))?;
        let preview_result = preview
            .apply(request.command.clone())
            .await
            .map_err(|error| PublicationError::Conflict(error.to_string()))?;
        self.fault(PublicationFaultPoint::CandidateRoot)?;

        let mut durable_cids = command_value_cids(&request.command);
        match &preview_result.response {
            CommandResponse::Commit(commit) => {
                durable_cids.push(commit.root_cid.clone());
                durable_cids.push(commit.commit_cid.clone());
            }
            CommandResponse::Snapshot(snapshot) => durable_cids.push(snapshot.root_cid.clone()),
        }
        let roots_to_walk = durable_cids.clone();
        for root in roots_to_walk {
            let traversal = traverse(
                &self.registry,
                &self.data_store,
                root,
                self.limits.traversal(),
            )
            .await
            .map_err(|error| PublicationError::Traversal(error.to_string()))?;
            durable_cids.extend(traversal.cids);
        }
        durable_cids.sort_by_key(ToString::to_string);
        durable_cids.dedup();
        for cid in &durable_cids {
            if !lease.roots.contains(cid) {
                lease.roots.push(cid.clone());
                self.protection
                    .protect(
                        &request.namespace_id,
                        cid,
                        &format!("namespace-candidate:{}", lease.lease_id),
                        Some(lease.expires_at_unix_seconds),
                    )
                    .await?;
            }
        }
        lease.roots.sort_by_key(ToString::to_string);
        lease.roots.dedup();
        self.repository.update_staging(lease)?;

        let required = initial.descriptor.durability.replicas as usize;
        let mut receipts = Vec::new();
        for cid in durable_cids {
            let receipt =
                if let Some(receipt) = self.repository.durable_receipt(&cid, required, now)? {
                    receipt
                } else {
                    self.durability.ensure_durable(&cid, required).await?
                };
            if receipt.replicas_accepted < required || receipt.status != "durable" {
                return Err(PublicationError::DurabilityNotMet(cid));
            }
            self.repository.put_durability(&StoredDurabilityReceipt {
                namespace_id: request.namespace_id.clone(),
                request_id: request.command.request_id.clone(),
                receipt: receipt.clone(),
                verified_at_unix_seconds: now,
            })?;
            receipts.push(receipt);
        }
        self.fault(PublicationFaultPoint::ValueDurability)?;

        let current = self
            .manager
            .linearizable_namespace_state(&request.namespace_id)
            .await
            .map_err(|error| PublicationError::Namespace(error.to_string()))?;
        if current.current_revision != initial.current_revision
            || current.current_root_cid != initial.current_root_cid
        {
            return Err(PublicationError::Conflict(
                "leader state changed during durability barrier".to_string(),
            ));
        }
        self.fault(PublicationFaultPoint::LocalLogPersistence)?;
        self.fault(PublicationFaultPoint::FollowerLogPersistence)?;
        let response = self
            .manager
            .routed_write(&request.namespace_id, request.command.clone())
            .await
            .map_err(|error| PublicationError::Namespace(error.to_string()))?;
        self.fault(PublicationFaultPoint::QuorumCommit)?;
        self.fault(PublicationFaultPoint::StateMachineApply)?;
        self.fault(PublicationFaultPoint::CheckpointPublication)?;
        response_to_apply(response).map(|apply| (apply, receipts))
    }

    async fn release_staging(&self, lease: &mut StagingLease) -> Result<(), PublicationError> {
        self.fault(PublicationFaultPoint::StagingRelease)?;
        lease.status = "released".to_string();
        self.repository.update_staging(lease)?;
        for root in &lease.roots {
            self.protection
                .release(
                    &lease.namespace_id,
                    root,
                    &format!("namespace-staging:{}", lease.lease_id),
                )
                .await?;
            self.protection
                .release(
                    &lease.namespace_id,
                    root,
                    &format!("namespace-candidate:{}", lease.lease_id),
                )
                .await?;
        }
        Ok(())
    }

    pub async fn reconcile_pin_intents(&self) -> Result<usize, PublicationError> {
        self.fault(PublicationFaultPoint::PinIntentApply)?;
        let applied = reconcile_pin_intents(&self.repository, self.protection.as_ref()).await?;
        self.fault(PublicationFaultPoint::OldRootRetirement)?;
        Ok(applied)
    }

    pub async fn expire_staging(&self, now: i64) -> Result<usize, PublicationError> {
        expire_staging_leases(&self.repository, self.protection.as_ref(), now).await
    }
}

pub async fn expire_staging_leases<P: ProtectionBackend + ?Sized>(
    repository: &PublicationRepository,
    protection: &P,
    now: i64,
) -> Result<usize, PublicationError> {
    let committed = repository.protected_roots(now)?;
    let leases = read_all::<StagingLease>(&repository.metadata, NAMESPACE_STAGING_LEASES)?;
    let mut expired = 0;
    for mut lease in leases
        .into_iter()
        .filter(|lease| lease.status == "active" && lease.expires_at_unix_seconds <= now)
    {
        let proposals = repository
            .pending_intents()?
            .into_iter()
            .filter(|intent| {
                intent.request_id == lease.request_id && intent.reason == "proposal-input"
            })
            .collect::<Vec<_>>();
        let mut proposal_can_commit = false;
        for intent in &proposals {
            if namespace_log_contains(&repository.metadata, &intent.namespace_id, intent.log_index)
                .map_err(|error| PublicationError::Storage(error.to_string()))?
            {
                proposal_can_commit = true;
            } else {
                repository.mark_intent_resolved(intent)?;
            }
        }
        if proposal_can_commit {
            continue;
        }
        lease.status = "expired".to_string();
        repository.update_staging(&lease)?;
        for root in &lease.roots {
            if !committed.contains(root) {
                protection
                    .release(
                        &lease.namespace_id,
                        root,
                        &format!("namespace-staging:{}", lease.lease_id),
                    )
                    .await?;
                protection
                    .release(
                        &lease.namespace_id,
                        root,
                        &format!("namespace-candidate:{}", lease.lease_id),
                    )
                    .await?;
            }
        }
        expired += 1;
    }
    Ok(expired)
}

pub async fn reconcile_pin_intents<P: ProtectionBackend + ?Sized>(
    repository: &PublicationRepository,
    protection: &P,
) -> Result<usize, PublicationError> {
    let intents = repository.pending_intents()?;
    let mut applied = 0;
    for intent in intents {
        match intent.action {
            PinAction::Protect => {
                protection
                    .protect(&intent.namespace_id, &intent.cid, &intent.reason, None)
                    .await?;
            }
            PinAction::Release => {
                protection
                    .release(&intent.namespace_id, &intent.cid, &intent.reason)
                    .await?;
            }
        }
        repository.mark_intent_applied(&intent)?;
        applied += 1;
    }
    Ok(applied)
}

fn command_value_cids(command: &CommandEnvelope) -> Vec<Cid> {
    let NamespaceCommand::ApplyTransaction { transaction } = &command.command else {
        return Vec::new();
    };
    transaction
        .mutations
        .iter()
        .filter_map(|mutation| match mutation {
            NamespaceMutation::Put { value_cid, .. } => Some(value_cid.clone()),
            NamespaceMutation::Delete { .. } => None,
        })
        .collect()
}

fn response_to_apply(response: ConsensusResponse) -> Result<ApplyResult, PublicationError> {
    if let Some(message) = response.error {
        return Err(PublicationError::Application {
            code: response
                .error_code
                .unwrap_or_else(|| "invalid_namespace_command".to_string()),
            message,
        });
    }
    response.result.ok_or_else(|| {
        PublicationError::Namespace("consensus returned no namespace result".to_string())
    })
}

fn write_record<T: Serialize>(
    metadata: &MetadataStore,
    table: TableDefinition<&str, &[u8]>,
    key: &str,
    value: &T,
) -> Result<(), PublicationError> {
    let bytes = serde_json::to_vec(value).map_err(storage_error)?;
    let write = metadata.database().begin_write().map_err(storage_error)?;
    {
        let mut table = write.open_table(table).map_err(storage_error)?;
        table.insert(key, bytes.as_slice()).map_err(storage_error)?;
    }
    write.commit().map_err(storage_error)
}

fn delete_record(
    metadata: &MetadataStore,
    definition: TableDefinition<&str, &[u8]>,
    key: &str,
) -> Result<(), PublicationError> {
    let write = metadata.database().begin_write().map_err(storage_error)?;
    {
        let mut table = write.open_table(definition).map_err(storage_error)?;
        table.remove(key).map_err(storage_error)?;
    }
    write.commit().map_err(storage_error)
}

fn read_record<T: for<'de> Deserialize<'de>>(
    metadata: &MetadataStore,
    table: TableDefinition<&str, &[u8]>,
    key: &str,
) -> Result<Option<T>, PublicationError> {
    let read = metadata.database().begin_read().map_err(storage_error)?;
    let table = read.open_table(table).map_err(storage_error)?;
    table
        .get(key)
        .map_err(storage_error)?
        .map(|value| serde_json::from_slice(value.value()).map_err(storage_error))
        .transpose()
}

fn read_all<T: for<'de> Deserialize<'de>>(
    metadata: &MetadataStore,
    definition: TableDefinition<&str, &[u8]>,
) -> Result<Vec<T>, PublicationError> {
    let read = metadata.database().begin_read().map_err(storage_error)?;
    let table = read.open_table(definition).map_err(storage_error)?;
    table
        .iter()
        .map_err(storage_error)?
        .map(|item| {
            let (_, value) = item.map_err(storage_error)?;
            serde_json::from_slice(value.value()).map_err(storage_error)
        })
        .collect()
}

fn storage_error(error: impl std::fmt::Display) -> PublicationError {
    PublicationError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_config::StorageLocationConfig;
    use pepper_consensus::{InProcessRouter, MemoryDataBackend, raft_members};
    use pepper_merkle::{MerkleLimits, MerkleNodeCodecHandler, MerkleWriteStore};
    use pepper_namespace::{
        KeyPrecondition, NamespaceCommitCodecHandler, NamespaceDescriptor,
        NamespaceDescriptorCodecHandler, NamespaceKind, NamespaceLimits, NamespaceMutation,
        TransactionCommand, create_namespace,
    };
    use pepper_storage::BlockStore;
    use pepper_types::{CODEC_RAW, ProviderRecord};
    use std::{collections::HashMap, sync::Mutex};

    struct InjectAt(PublicationFaultPoint);

    impl PublicationFaultInjector for InjectAt {
        fn hit(&self, point: PublicationFaultPoint) -> Result<(), PublicationError> {
            if point == self.0 {
                Err(PublicationError::Injected(point))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct MockDurability;

    #[async_trait]
    impl DurabilityBackend for MockDurability {
        async fn ensure_durable(
            &self,
            cid: &Cid,
            replication_factor: usize,
        ) -> Result<DurabilityReceipt, PublicationError> {
            Ok(DurabilityReceipt {
                cid: cid.clone(),
                codec: cid.codec,
                size: 1,
                replicas_accepted: replication_factor,
                replica_nodes: (0..replication_factor)
                    .map(|index| format!("node-{index}"))
                    .collect(),
                status: "durable".to_string(),
                providers: Vec::<ProviderRecord>::new(),
            })
        }
    }

    #[derive(Default)]
    struct MockProtection(Mutex<HashMap<String, bool>>);

    #[async_trait]
    impl ProtectionBackend for MockProtection {
        async fn protect(
            &self,
            namespace_id: &NamespaceId,
            cid: &Cid,
            reason: &str,
            _expires_at_unix_seconds: Option<i64>,
        ) -> Result<(), PublicationError> {
            self.0
                .lock()
                .unwrap()
                .insert(format!("{namespace_id}|{cid}|{reason}"), true);
            Ok(())
        }

        async fn release(
            &self,
            namespace_id: &NamespaceId,
            cid: &Cid,
            reason: &str,
        ) -> Result<(), PublicationError> {
            self.0
                .lock()
                .unwrap()
                .insert(format!("{namespace_id}|{cid}|{reason}"), false);
            Ok(())
        }
    }

    fn descriptor() -> NamespaceDescriptor {
        let mut descriptor = NamespaceDescriptor::new(
            NamespaceKind::Kv,
            vec!["node-c".into(), "node-a".into(), "node-b".into()],
            "creator",
            "00",
            1,
        );
        descriptor.retention.keep_last = 1;
        descriptor
    }

    fn command(
        state: &pepper_namespace::NamespaceState,
        request_id: &str,
        key: &str,
        value: Cid,
    ) -> CommandEnvelope {
        CommandEnvelope {
            request_id: request_id.to_string(),
            writer_identity: "writer".to_string(),
            timestamp_unix_seconds: 2,
            signature_hex: "00".to_string(),
            command: NamespaceCommand::ApplyTransaction {
                transaction: TransactionCommand {
                    base_revision: state.current_revision,
                    base_root_cid: state.current_root_cid.clone(),
                    mutations: vec![NamespaceMutation::Put {
                        key_hex: hex::encode(key),
                        value_cid: value,
                        value_kind: "raw".to_string(),
                        metadata: Default::default(),
                        precondition: KeyPrecondition::Absent,
                    }],
                    message: None,
                },
            },
        }
    }

    #[tokio::test]
    async fn active_and_expiring_leases_form_a_gc_barrier() {
        let directory = tempfile::tempdir().unwrap();
        let metadata = Arc::new(
            MetadataStore::open_or_create(directory.path().join("metadata.redb")).unwrap(),
        );
        let store = BlockStore::open(
            metadata.clone(),
            &[StorageLocationConfig {
                path: directory.path().join("blocks"),
                max_capacity_bytes: 1024 * 1024,
            }],
        )
        .unwrap();
        let protected = store.put(CODEC_RAW, b"protected").unwrap().cid;
        let garbage = store.put(CODEC_RAW, b"garbage").unwrap().cid;
        let namespace = NamespaceId::new(Cid::new(
            pepper_types::CODEC_NAMESPACE_DESCRIPTOR,
            b"namespace",
        ))
        .unwrap();
        let repository =
            PublicationRepository::new(metadata, PublicationLimits::default()).unwrap();
        repository
            .put_staging(&StagingLease {
                lease_id: "lease".to_string(),
                namespace_id: namespace,
                request_id: "request".to_string(),
                roots: vec![protected.clone()],
                staged_bytes: 9,
                created_at_unix_seconds: 1,
                expires_at_unix_seconds: 10,
                status: "active".to_string(),
            })
            .unwrap();
        let roots = repository.protected_roots(2).unwrap();
        store.garbage_collect(&roots).unwrap();
        assert!(store.has(&protected).unwrap());
        assert!(!store.has(&garbage).unwrap());

        let protection = MockProtection::default();
        assert_eq!(
            expire_staging_leases(&repository, &protection, 11)
                .await
                .unwrap(),
            1
        );
        let roots = repository.protected_roots(11).unwrap();
        store.garbage_collect(&roots).unwrap();
        assert!(!store.has(&protected).unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn durability_barrier_staging_intents_retention_and_conflict_cleanup() {
        let router = InProcessRouter::default();
        let mut managers = Vec::new();
        let mut stores = Vec::new();
        let mut directories = Vec::new();
        let mut initial_state = None;
        for identity in ["node-a", "node-b", "node-c"] {
            let directory = tempfile::tempdir().unwrap();
            let metadata = Arc::new(
                MetadataStore::open_or_create(directory.path().join("metadata.redb")).unwrap(),
            );
            let store = ConsensusDataStore::new(MemoryDataBackend::default());
            let created = create_namespace(
                &store,
                descriptor(),
                NamespaceLimits::default(),
                MerkleLimits::default(),
            )
            .await
            .unwrap();
            let manager = Arc::new(
                NamespaceGroupManager::new(
                    identity.to_string(),
                    metadata,
                    router.clone(),
                    Default::default(),
                )
                .unwrap(),
            );
            manager
                .start_group(created.state.clone(), store.clone())
                .await
                .unwrap();
            initial_state.get_or_insert(created.state);
            managers.push(manager);
            stores.push(store);
            directories.push(directory);
        }
        let state = initial_state.unwrap();
        managers[0]
            .initialize(
                &state.namespace_id,
                raft_members(&["node-a".into(), "node-b".into(), "node-c".into()]).unwrap(),
            )
            .await
            .unwrap();
        let mut leader_index = None;
        for _ in 0..100 {
            for (index, manager) in managers.iter().enumerate() {
                let metrics = manager
                    .group(&state.namespace_id)
                    .await
                    .unwrap()
                    .raft
                    .metrics()
                    .borrow()
                    .clone();
                if metrics.current_leader.is_some()
                    && metrics.current_leader
                        == Some(pepper_consensus::raft_node_id(
                            ["node-a", "node-b", "node-c"][index],
                        ))
                {
                    leader_index = Some(index);
                    break;
                }
            }
            if leader_index.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let leader_index = leader_index.unwrap();
        let metadata = managers[leader_index].metadata().clone();
        let repository =
            PublicationRepository::new(metadata, PublicationLimits::default()).unwrap();
        let mut registry = pepper_dag::builtin_registry();
        registry.register(MerkleNodeCodecHandler).unwrap();
        registry.register(NamespaceDescriptorCodecHandler).unwrap();
        registry.register(NamespaceCommitCodecHandler).unwrap();
        let protection = Arc::new(MockProtection::default());
        let registry = Arc::new(registry);
        let coordinator = PublicationCoordinator::new(
            managers[leader_index].clone(),
            stores[leader_index].clone(),
            registry.clone(),
            repository.clone(),
            Arc::new(MockDurability),
            protection.clone(),
            PublicationLimits::default(),
        )
        .unwrap();

        let value_payload = b"value".to_vec();
        let value = stores[leader_index]
            .put(CODEC_RAW, value_payload)
            .await
            .unwrap();
        let published = coordinator
            .publish(
                PublicationRequest {
                    namespace_id: state.namespace_id.clone(),
                    command: command(&state, "request-1", "alpha", value.clone()),
                    uploaded_roots: vec![value.clone()],
                    staged_bytes: 5,
                    staging_ttl_seconds: 60,
                    retain_uploaded_on_conflict: true,
                },
                10,
            )
            .await
            .unwrap();
        assert!(!published.durability.is_empty());
        assert_eq!(repository.active_staging(11).unwrap().len(), 0);
        assert_eq!(coordinator.reconcile_pin_intents().await.unwrap(), 0);
        assert!(repository.protected_roots(11).unwrap().contains(
            &match &published.apply.response {
                CommandResponse::Commit(commit) => commit.root_cid.clone(),
                _ => panic!("expected commit"),
            }
        ));

        let stale = command(&state, "request-conflict", "alpha", value.clone());
        assert!(matches!(
            coordinator
                .publish(
                    PublicationRequest {
                        namespace_id: state.namespace_id.clone(),
                        command: stale,
                        uploaded_roots: vec![value.clone()],
                        staged_bytes: 5,
                        staging_ttl_seconds: 60,
                        retain_uploaded_on_conflict: true,
                    },
                    20,
                )
                .await,
            Err(PublicationError::Conflict(_))
        ));
        assert!(protection.0.lock().unwrap().iter().any(|(key, active)| {
            *active
                && key.contains("uploaded-publication-conflict")
                && key.contains(&value.to_string())
        }));

        let fault_points = [
            PublicationFaultPoint::ValueDurability,
            PublicationFaultPoint::CandidateRoot,
            PublicationFaultPoint::StagingLease,
            PublicationFaultPoint::LeaderValidation,
            PublicationFaultPoint::LocalLogPersistence,
            PublicationFaultPoint::FollowerLogPersistence,
            PublicationFaultPoint::QuorumCommit,
            PublicationFaultPoint::StateMachineApply,
            PublicationFaultPoint::CheckpointPublication,
            PublicationFaultPoint::PinIntentApply,
            PublicationFaultPoint::StagingRelease,
            PublicationFaultPoint::OldRootRetirement,
        ];
        for (index, point) in fault_points.into_iter().enumerate() {
            let request = PublicationRequest {
                namespace_id: state.namespace_id.clone(),
                command: command(
                    &state,
                    &format!("fault-{index}"),
                    &format!("fault-key-{index}"),
                    value.clone(),
                ),
                uploaded_roots: vec![value.clone()],
                staged_bytes: 5,
                staging_ttl_seconds: 60,
                retain_uploaded_on_conflict: true,
            };
            let injected = PublicationCoordinator::new(
                managers[leader_index].clone(),
                stores[leader_index].clone(),
                registry.clone(),
                repository.clone(),
                Arc::new(MockDurability),
                protection.clone(),
                PublicationLimits::default(),
            )
            .unwrap()
            .with_fault_injector(Arc::new(InjectAt(point)));
            assert!(matches!(
                injected.publish(request.clone(), 100 + index as i64).await,
                Err(PublicationError::Injected(actual)) if actual == point
            ));
            let retry = PublicationCoordinator::new(
                managers[leader_index].clone(),
                stores[leader_index].clone(),
                registry.clone(),
                repository.clone(),
                Arc::new(MockDurability),
                protection.clone(),
                PublicationLimits::default(),
            )
            .unwrap()
            .publish(request, 200 + index as i64)
            .await;
            assert!(
                retry.is_ok(),
                "idempotent recovery failed after {point:?}: {retry:?}"
            );
        }
        drop(directories);
    }
}
