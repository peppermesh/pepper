// SPDX-License-Identifier: Apache-2.0

//! Namespace publication pin reconciliation and lease expiry.

use super::*;
use futures_util::{StreamExt, stream};
use pepper_publication::{
    DurabilityBackend, ProtectionBackend, PublicationError, expire_staging_leases,
    reconcile_pin_intents,
};

#[derive(Clone)]
#[allow(dead_code)]
pub(super) struct AgentDurabilityBackend(pub(super) AppState);

impl AgentDurabilityBackend {
    pub(super) async fn ensure_at_placement(
        &self,
        cid: &Cid,
        replication_factor: usize,
        placement: PlacementReference,
    ) -> Result<DurabilityReceipt, PublicationError> {
        let block = get_block_at_placement(&self.0, cid, &placement)
            .await
            .map_err(|error| PublicationError::Storage(error.message))?;
        let decision = self
            .0
            .placement
            .decide(&placement)
            .map_err(|error| PublicationError::Protection(error.to_string()))?;
        let target_node_ids = decision.node_ids;
        let payload = block.payload;
        let encoded = self
            .0
            .block_store
            .get_encoded(cid)
            .or_else(|_| self.0.block_store.encode(cid.codec, &payload))
            .map_err(|error| PublicationError::Storage(error.to_string()))?;
        let encoded_size = encoded.logical_size_bytes();
        let encoded_payload = BufferChain::from_buffer(OwnedBuffer::from_vec(encoded.into_bytes()));

        let local_node_id = self.0.status.node_id.clone();
        let local_selected = target_node_ids.contains(&local_node_id);
        let mut replica_nodes = Vec::new();
        if local_selected && self.0.block_store.has(cid).unwrap_or(false) {
            replica_nodes.push(local_node_id.clone());
        }
        let probes = target_node_ids
            .clone()
            .into_iter()
            .filter(|node_id| node_id != &local_node_id)
            .map(|node_id| {
                let network = self.0.network.clone();
                let cid = cid.clone();
                async move {
                    let address = fast_path::peer_address(&network, &node_id).await?;
                    matches!(
                        time::timeout(Duration::from_secs(5), network.block_has(address, &cid))
                            .await,
                        Ok(Ok(true))
                    )
                    .then_some((node_id, address))
                }
            });
        let mut probes = stream::iter(probes).buffer_unordered(8);
        while let Some(confirmed) = probes.next().await {
            if let Some((node_id, _)) = confirmed {
                replica_nodes.push(node_id);
            }
        }
        replica_nodes.sort();
        replica_nodes.dedup();
        if replica_nodes.len() >= replication_factor {
            return Ok(DurabilityReceipt {
                cid: cid.clone(),
                placement: Some(placement),
                codec: cid.codec,
                size: payload.len() as u64,
                replicas_accepted: replica_nodes.len(),
                replica_nodes,
                status: "durable".to_string(),
            });
        }

        // A failed node must not delay every CID in a namespace publication.
        // Send missing replicas concurrently and stop as soon as the durability
        // threshold is met; dropping the remaining futures cancels transfers to
        // unavailable peers.
        let confirmed_nodes = replica_nodes
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        let transfers = target_node_ids
            .into_iter()
            .filter(|node_id| !confirmed_nodes.contains(node_id) && node_id != &local_node_id)
            .map(|node_id| {
                let state = self.0.clone();
                let cid = cid.clone();
                let encoded_payload = encoded_payload.clone();
                async move {
                    let transfer = async {
                        let address = fast_path::peer_address(&state.network, &node_id).await?;
                        let ack = state
                            .network
                            .block_put_replica_buffer_chain(
                                address,
                                cid.codec,
                                &cid,
                                encoded_size,
                                encoded_payload,
                            )
                            .await
                            .ok()?;
                        parse_replica_ack(&node_id, &cid, cid.codec, encoded_size, &ack)
                            .ok()
                            .map(|provider| (node_id, provider))
                    };
                    time::timeout(Duration::from_secs(12), transfer)
                        .await
                        .ok()
                        .flatten()
                }
            });
        let mut transfers = stream::iter(transfers).buffer_unordered(8);
        while let Some(confirmed) = transfers.next().await {
            if let Some((node_id, _provider)) = confirmed {
                replica_nodes.push(node_id);
                replica_nodes.sort();
                replica_nodes.dedup();
                if replica_nodes.len() >= replication_factor {
                    break;
                }
            }
        }
        let replicas_accepted = replica_nodes.len();
        Ok(DurabilityReceipt {
            cid: cid.clone(),
            placement: Some(placement),
            codec: cid.codec,
            size: payload.len() as u64,
            replicas_accepted,
            replica_nodes,
            status: if replicas_accepted >= replication_factor {
                "durable"
            } else {
                "degraded"
            }
            .to_string(),
        })
    }

    async fn ensure_legacy_durable(
        &self,
        cid: &Cid,
        replication_factor: usize,
    ) -> Result<DurabilityReceipt, PublicationError> {
        let block = get_block_resolved(&self.0, cid)
            .await
            .map_err(|error| PublicationError::Storage(error.message))?;
        let payload = block.payload;
        let encoded = self
            .0
            .block_store
            .get_encoded(cid)
            .or_else(|_| self.0.block_store.encode(cid.codec, &payload))
            .map_err(|error| PublicationError::Storage(error.to_string()))?;
        let encoded_size = encoded.logical_size_bytes();
        let encoded_payload = BufferChain::from_buffer(OwnedBuffer::from_vec(encoded.into_bytes()));

        let local_provider = self.0.network.local_provider_record(cid);
        self.0
            .network
            .persist_provider_record(&local_provider)
            .map_err(|error| PublicationError::Protection(error.to_string()))?;
        let local_node_id = self.0.status.node_id.clone();
        let provider_records = if replication_factor > 1 {
            self.0
                .network
                .find_providers(cid)
                .await
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
                            return Some(record);
                        }
                    }
                    None
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
        if providers.len() < replication_factor {
            let confirmed_nodes = providers
                .iter()
                .map(|provider| provider.node_id.clone())
                .collect::<std::collections::HashSet<_>>();
            let transfers = self
                .0
                .network
                .peers()
                .await
                .into_iter()
                .filter(|peer| !confirmed_nodes.contains(&peer.node_id))
                .map(|peer| {
                    let state = self.0.clone();
                    let cid = cid.clone();
                    let encoded_payload = encoded_payload.clone();
                    async move {
                        let transfer = async {
                            for address in &peer.addresses {
                                let Ok(address) = address.parse::<SocketAddr>() else {
                                    continue;
                                };
                                let Ok(ack) = state
                                    .network
                                    .block_put_replica_buffer_chain(
                                        address,
                                        cid.codec,
                                        &cid,
                                        encoded_size,
                                        encoded_payload.clone(),
                                    )
                                    .await
                                else {
                                    continue;
                                };
                                if let Ok(provider) = validate_replica_ack(
                                    &state,
                                    &peer.node_id,
                                    &cid,
                                    cid.codec,
                                    encoded_size,
                                    &ack,
                                ) {
                                    return Some(provider);
                                }
                            }
                            None
                        };
                        time::timeout(Duration::from_secs(12), transfer)
                            .await
                            .ok()
                            .flatten()
                    }
                });
            let mut transfers = stream::iter(transfers).buffer_unordered(8);
            while let Some(provider) = transfers.next().await {
                if let Some(provider) = provider {
                    providers.push(provider);
                    providers.sort_by(|left, right| left.node_id.cmp(&right.node_id));
                    providers.dedup_by(|left, right| left.node_id == right.node_id);
                    if providers.len() >= replication_factor {
                        break;
                    }
                }
            }
        }
        let replicas_accepted = providers.len();
        Ok(DurabilityReceipt {
            cid: cid.clone(),
            placement: None,
            codec: cid.codec,
            size: payload.len() as u64,
            replicas_accepted,
            replica_nodes: providers
                .into_iter()
                .map(|provider| provider.node_id)
                .collect(),
            status: if replicas_accepted >= replication_factor {
                "durable"
            } else {
                "degraded"
            }
            .to_string(),
        })
    }
}

#[async_trait]
impl DurabilityBackend for AgentDurabilityBackend {
    async fn ensure_durable(
        &self,
        cid: &Cid,
        replication_factor: usize,
        placement: Option<&PlacementReference>,
    ) -> Result<DurabilityReceipt, PublicationError> {
        observe_current_stage(OperationStage::Durability);
        observe_current_stage(OperationStage::Replication);
        let Some(map) = self.0.placement.current_map() else {
            if self.0.s3.is_some() {
                return Err(PublicationError::Protection(
                    "authoritative placement map is not loaded".to_string(),
                ));
            }
            return self.ensure_legacy_durable(cid, replication_factor).await;
        };
        if let Some(placement) = placement {
            return self
                .ensure_at_placement(cid, replication_factor, placement.clone())
                .await;
        }
        let replicas = u16::try_from(replication_factor).map_err(|_| {
            PublicationError::Protection("replication factor exceeds placement bounds".to_string())
        })?;
        self.ensure_at_placement(
            cid,
            replication_factor,
            PlacementReference::replicated(map.epoch, cid.clone(), replicas),
        )
        .await
    }
}

#[derive(Clone)]
pub(super) struct AgentProtectionBackend {
    metadata: Arc<MetadataStore>,
    identity: NodeIdentity,
    node_id: String,
    replication_factor: u16,
}

impl AgentProtectionBackend {
    pub(super) fn from_state(state: &AppState) -> Self {
        Self {
            metadata: state.metadata.clone(),
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
        if self
            .metadata
            .pins()
            .all()
            .map_err(|error| PublicationError::Protection(error.to_string()))?
            .into_iter()
            .any(|pin| {
                pin.pin_id.starts_with(&prefix)
                    && pin.owner == self.node_id
                    && pin.status == "active"
                    && pin.expires_at_unix_seconds == expires_at_unix_seconds
            })
        {
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
        Ok(())
    }

    async fn protect_many(
        &self,
        namespace_id: &pepper_namespace::NamespaceId,
        cids: &[Cid],
        reason: &str,
        expires_at_unix_seconds: Option<i64>,
    ) -> Result<(), PublicationError> {
        let active_pin_ids = self
            .metadata
            .pins()
            .all()
            .map_err(|error| PublicationError::Protection(error.to_string()))?
            .into_iter()
            .filter(|pin| pin.owner == self.node_id && pin.status == "active")
            .map(|pin| pin.pin_id)
            .collect::<HashSet<_>>();
        let created_at_unix_seconds = unix_seconds();
        let mut pins = Vec::with_capacity(cids.len());
        for cid in cids {
            let prefix = self.pin_prefix(namespace_id, cid, reason);
            let pin_id = format!(
                "{}-{}-{}",
                prefix,
                expires_at_unix_seconds
                    .map_or_else(|| "permanent".to_string(), |value| value.to_string()),
                self.node_id
            );
            if active_pin_ids.contains(&pin_id) {
                continue;
            }
            let mut pin = PinRecord {
                pin_id,
                root_cid: cid.clone(),
                owner: self.node_id.clone(),
                replication_factor: self.replication_factor,
                created_at_unix_seconds,
                expires_at_unix_seconds,
                status: "active".to_string(),
                signature_hex: String::new(),
            };
            self.sign(&mut pin)?;
            pins.push(pin);
        }
        self.metadata
            .pins()
            .replace(&pins)
            .map_err(|error| PublicationError::Protection(error.to_string()))
    }

    async fn release_many(
        &self,
        namespace_id: &pepper_namespace::NamespaceId,
        cids: &[Cid],
        reason: &str,
    ) -> Result<(), PublicationError> {
        let prefixes = cids
            .iter()
            .map(|cid| format!("{}-", self.pin_prefix(namespace_id, cid, reason)))
            .collect::<HashSet<_>>();
        let mut pins = self
            .metadata
            .pins()
            .all()
            .map_err(|error| PublicationError::Protection(error.to_string()))?
            .into_iter()
            .filter(|pin| {
                pin.owner == self.node_id
                    && pin.status == "active"
                    && prefixes.iter().any(|prefix| pin.pin_id.starts_with(prefix))
            })
            .collect::<Vec<_>>();
        for pin in &mut pins {
            pin.status = "deleted".to_string();
            self.sign(pin)?;
        }
        self.metadata
            .pins()
            .replace(&pins)
            .map_err(|error| PublicationError::Protection(error.to_string()))
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
