// SPDX-License-Identifier: Apache-2.0

//! Namespace publication pin reconciliation and lease expiry.

use super::*;
use pepper_publication::{
    DurabilityBackend, ProtectionBackend, PublicationError, expire_staging_leases,
    reconcile_pin_intents,
};

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
        let attempted = time::timeout(
            Duration::from_secs(2),
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
                    Duration::from_secs(2),
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

    async fn broadcast(&self, pin: &PinRecord) -> Result<(), PublicationError> {
        let json = serde_json::to_string(pin)
            .map_err(|error| PublicationError::Protection(error.to_string()))?;
        let mut failed = Vec::new();
        for peer in self.network.peers().await {
            let mut accepted = false;
            for address in peer.addresses {
                let Ok(address) = address.parse() else {
                    continue;
                };
                if matches!(
                    time::timeout(
                        Duration::from_millis(250),
                        self.network.apply_pin(address, json.clone())
                    )
                    .await,
                    Ok(Ok(()))
                ) {
                    accepted = true;
                    break;
                }
            }
            if !accepted {
                failed.push(peer.node_id);
            }
        }
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
                    && pin.status == "active"
                    && pin.expires_at_unix_seconds == expires_at_unix_seconds
            })
        {
            return self.broadcast(&existing).await;
        }
        let mut pin = PinRecord {
            pin_id: format!(
                "{}-{}",
                prefix,
                expires_at_unix_seconds
                    .map_or_else(|| "permanent".to_string(), |value| value.to_string())
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
        self.broadcast(&pin).await
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
            .filter(|pin| pin.pin_id.starts_with(&prefix) && pin.status == "active")
            .collect::<Vec<_>>();
        for pin in &mut pins {
            pin.status = "deleted".to_string();
            self.sign(pin)?;
        }
        self.metadata
            .pins()
            .replace(&pins)
            .map_err(|error| PublicationError::Protection(error.to_string()))?;
        for pin in &pins {
            self.broadcast(pin).await?;
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
