// SPDX-License-Identifier: Apache-2.0

//! Namespace publication pin reconciliation and lease expiry.

use super::*;
use futures_util::{StreamExt, stream};
use pepper_publication::{
    DurabilityBackend, ProtectionBackend, PublicationError, expire_staging_leases,
    reconcile_pin_intents,
};

static PIN_BROADCAST_LIMIT: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(64)));

#[derive(Clone)]
#[allow(dead_code)]
pub(super) struct AgentDurabilityBackend(pub(super) AppState);

#[async_trait]
impl DurabilityBackend for AgentDurabilityBackend {
    async fn ensure_durable(
        &self,
        cid: &Cid,
        replication_factor: usize,
    ) -> Result<DurabilityReceipt, PublicationError> {
        let block = get_block_resolved(&self.0, cid)
            .await
            .map_err(|error| PublicationError::Storage(error.message))?;
        let payload = block.payload;

        // Object ingestion already persists signed provider records for every
        // acknowledged replica. Confirm those replicas with a cheap authenticated
        // BlockHas request before transferring the complete block again. This is
        // particularly important for multipart publication, which walks every
        // part chunk immediately after the upload path replicated it.
        let local_provider = self.0.network.local_provider_record(cid);
        self.0
            .network
            .persist_provider_record(&local_provider)
            .map_err(|error| PublicationError::Protection(error.to_string()))?;
        let local_node_id = self.0.status.node_id.clone();
        let provider_records = if replication_factor > 1 {
            self.0
                .network
                .local_provider_records(cid)
                .map_err(|error| PublicationError::Protection(error.to_string()))?
        } else {
            Vec::new()
        };
        let probes = provider_records
            .into_iter()
            .filter(|record| record.node_id != local_node_id)
            .map(|record| {
                let network = self.0.network.clone();
                async move {
                    let mut confirmed = false;
                    for address in &record.addresses {
                        let Ok(address) = address.parse::<SocketAddr>() else {
                            continue;
                        };
                        if matches!(
                            time::timeout(
                                Duration::from_secs(5),
                                network.block_has(address, &record.cid),
                            )
                            .await,
                            Ok(Ok(true))
                        ) {
                            confirmed = true;
                            break;
                        }
                    }
                    confirmed.then_some(record)
                }
            });
        let mut probes = stream::iter(probes).buffer_unordered(8);
        let mut providers = vec![local_provider];
        while let Some(provider) = probes.next().await {
            if let Some(provider) = provider {
                providers.push(provider);
                if providers.len() >= replication_factor {
                    break;
                }
            }
        }
        providers.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        providers.dedup_by(|left, right| left.node_id == right.node_id);
        if providers.len() >= replication_factor {
            return Ok(DurabilityReceipt {
                cid: cid.clone(),
                codec: cid.codec,
                size: payload.len() as u64,
                replicas_accepted: providers.len(),
                replica_nodes: providers
                    .iter()
                    .map(|provider| provider.node_id.clone())
                    .collect(),
                status: "durable".to_string(),
                providers,
            });
        }

        let attempted = time::timeout(
            Duration::from_secs(12),
            put_replicated_block_with_factor(
                &self.0,
                cid.codec,
                payload.clone(),
                replication_factor,
            ),
        )
        .await;
        let mut receipt = match attempted {
            Ok(Ok(receipt)) => receipt,
            Ok(Err(error)) => return Err(PublicationError::Protection(error.message)),
            Err(_) => {
                let provider = self.0.network.local_provider_record(cid);
                self.0
                    .network
                    .persist_provider_record(&provider)
                    .map_err(|error| PublicationError::Protection(error.to_string()))?;
                DurabilityReceipt {
                    cid: cid.clone(),
                    codec: cid.codec,
                    size: payload.len() as u64,
                    replicas_accepted: 1,
                    replica_nodes: vec![self.0.status.node_id.clone()],
                    status: "degraded".to_string(),
                    providers: vec![provider],
                }
            }
        };
        if receipt.replicas_accepted < replication_factor {
            for peer in self.0.network.peers().await {
                if receipt.replica_nodes.contains(&peer.node_id) {
                    continue;
                }
                let Some(address) = peer
                    .addresses
                    .iter()
                    .find_map(|address| address.parse::<SocketAddr>().ok())
                else {
                    continue;
                };
                let Ok(Ok(ack)) = time::timeout(
                    Duration::from_secs(12),
                    self.0
                        .network
                        .block_put_replica(address, cid.codec, payload.clone()),
                )
                .await
                else {
                    continue;
                };
                if let Ok(provider) = validate_replica_ack(
                    &self.0,
                    &peer.node_id,
                    cid,
                    cid.codec,
                    payload.len() as u64,
                    &ack,
                ) {
                    receipt.replica_nodes.push(peer.node_id);
                    receipt.providers.push(provider);
                }
            }
            receipt.replica_nodes.sort();
            receipt.replica_nodes.dedup();
            receipt.replicas_accepted = receipt.replica_nodes.len();
            receipt.status = if receipt.replicas_accepted >= replication_factor {
                "durable"
            } else {
                "degraded"
            }
            .to_string();
        }
        Ok(receipt)
    }
}

#[derive(Clone)]
pub(super) struct AgentProtectionBackend {
    metadata: Arc<MetadataStore>,
    network: NetworkHandle,
    identity: NodeIdentity,
    node_id: String,
    replication_factor: u16,
}

impl AgentProtectionBackend {
    pub(super) fn from_state(state: &AppState) -> Self {
        Self {
            metadata: state.metadata.clone(),
            network: state.network.clone(),
            identity: state.identity.clone(),
            node_id: state.status.node_id.clone(),
            replication_factor: state.replication_factor as u16,
        }
    }

    fn pin_prefix(
        &self,
        namespace_id: &pepper_namespace::NamespaceId,
        cid: &Cid,
        reason: &str,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pepper-namespace-pin-v1");
        hasher.update(namespace_id.to_string().as_bytes());
        hasher.update(cid.to_string().as_bytes());
        hasher.update(reason.as_bytes());
        format!("namespace-{}", hasher.finalize().to_hex())
    }

    fn sign(&self, pin: &mut PinRecord) -> Result<(), PublicationError> {
        let mut unsigned = pin.clone();
        unsigned.signature_hex.clear();
        let payload = serde_json::to_vec(&unsigned)
            .map_err(|error| PublicationError::Protection(error.to_string()))?;
        pin.signature_hex = hex::encode(self.identity.sign(&payload));
        Ok(())
    }

    fn schedule_broadcast(&self, pin: PinRecord) {
        let Ok(permit) = PIN_BROADCAST_LIMIT.clone().try_acquire_owned() else {
            warn!(pin_id = %pin.pin_id, "namespace pin broadcast concurrency limit reached; periodic repair will retry");
            return;
        };
        let backend = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = backend.broadcast(&pin).await {
                warn!(pin_id = %pin.pin_id, %error, "namespace pin broadcast failed; reconciliation will retry");
            }
        });
    }

    async fn broadcast(&self, pin: &PinRecord) -> Result<(), PublicationError> {
        let json = serde_json::to_string(pin)
            .map_err(|error| PublicationError::Protection(error.to_string()))?;
        let peers = self
            .network
            .peers()
            .await
            .into_iter()
            // Gossip may teach a node its own signed descriptor. Local pin
            // persistence already happened before broadcast, so never dial
            // ourselves as a synchronization target.
            .filter(|peer| peer.node_id != self.node_id)
            .collect::<Vec<_>>();
        let failed = stream::iter(peers)
            .map(|peer| {
                let network = self.network.clone();
                let json = json.clone();
                async move {
                    for address in peer.addresses {
                        let Ok(address) = address.parse() else {
                            continue;
                        };
                        if matches!(
                            time::timeout(
                                Duration::from_millis(500),
                                network.apply_pin(address, json.clone())
                            )
                            .await,
                            Ok(Ok(()))
                        ) {
                            return None;
                        }
                    }
                    Some(peer.node_id)
                }
            })
            .buffer_unordered(8)
            .filter_map(|node| async move { node })
            .collect::<Vec<_>>()
            .await;
        if !failed.is_empty() {
            warn!(
                pin_id = %pin.pin_id,
                failed_nodes = %failed.join(","),
                "namespace pin synchronization is incomplete; reconciliation will retry"
            );
        }
        Ok(())
    }
}

#[async_trait]
impl ProtectionBackend for AgentProtectionBackend {
    async fn protect(
        &self,
        namespace_id: &pepper_namespace::NamespaceId,
        cid: &Cid,
        reason: &str,
        expires_at_unix_seconds: Option<i64>,
    ) -> Result<(), PublicationError> {
        let prefix = self.pin_prefix(namespace_id, cid, reason);
        if let Some(existing) = self
            .metadata
            .pins()
            .all()
            .map_err(|error| PublicationError::Protection(error.to_string()))?
            .into_iter()
            .find(|pin| {
                pin.pin_id.starts_with(&prefix)
                    && pin.owner == self.node_id
                    && pin.status == "active"
                    && pin.expires_at_unix_seconds == expires_at_unix_seconds
            })
        {
            self.schedule_broadcast(existing);
            return Ok(());
        }
        // Every namespace replica reconciles the same durable intent. Keep the
        // deterministic pin identity owner-scoped so independently created,
        // signed records never collide in a peer's metadata store.
        let mut pin = PinRecord {
            pin_id: format!(
                "{}-{}-{}",
                prefix,
                expires_at_unix_seconds
                    .map_or_else(|| "permanent".to_string(), |value| value.to_string()),
                self.node_id
            ),
            root_cid: cid.clone(),
            owner: self.node_id.clone(),
            replication_factor: self.replication_factor,
            created_at_unix_seconds: unix_seconds(),
            expires_at_unix_seconds,
            status: "active".to_string(),
            signature_hex: String::new(),
        };
        self.sign(&mut pin)?;
        self.metadata
            .pins()
            .put(&pin)
            .map_err(|error| PublicationError::Protection(error.to_string()))?;
        self.schedule_broadcast(pin);
        Ok(())
    }

    async fn release(
        &self,
        namespace_id: &pepper_namespace::NamespaceId,
        cid: &Cid,
        reason: &str,
    ) -> Result<(), PublicationError> {
        let prefix = self.pin_prefix(namespace_id, cid, reason);
        let mut pins = self
            .metadata
            .pins()
            .all()
            .map_err(|error| PublicationError::Protection(error.to_string()))?
            .into_iter()
            .filter(|pin| {
                pin.pin_id.starts_with(&prefix)
                    && pin.owner == self.node_id
                    && pin.status == "active"
            })
            .collect::<Vec<_>>();
        for pin in &mut pins {
            pin.status = "deleted".to_string();
            self.sign(pin)?;
        }
        self.metadata
            .pins()
            .replace(&pins)
            .map_err(|error| PublicationError::Protection(error.to_string()))?;
        for pin in pins {
            self.schedule_broadcast(pin);
        }
        Ok(())
    }
}

pub(super) fn spawn_publication_reconciler(state: AppState) {
    tokio::spawn(async move {
        let protection = AgentProtectionBackend::from_state(&state);
        let mut interval = time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;
            if let Err(error) =
                reconcile_pin_intents(&state.publication_repository, &protection).await
            {
                warn!(%error, "namespace pin-intent reconciliation failed");
            }
            if let Err(error) =
                expire_staging_leases(&state.publication_repository, &protection, unix_seconds())
                    .await
            {
                warn!(%error, "namespace staging-lease expiry failed");
            }
        }
    });
}
