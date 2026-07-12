// SPDX-License-Identifier: Apache-2.0

//! Adapters between the network RPC layer and agent domain services.

use super::*;

pub(super) struct AgentBlockService {
    pub(super) block_store: Arc<BlockStore>,
    pub(super) operation_lock: Arc<RwLock<()>>,
}

#[async_trait]
impl NetworkBlockService for AgentBlockService {
    async fn has_block(&self, cid: &Cid) -> Result<bool, NetworkError> {
        let _guard = self.operation_lock.read().await;
        tokio::task::block_in_place(|| self.block_store.has(cid))
            .map_err(|error| NetworkError::BlockService(error.to_string()))
    }

    async fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, NetworkError> {
        let _guard = self.operation_lock.read().await;
        tokio::task::block_in_place(|| self.block_store.get(cid))
            .map(|block| block.payload)
            .map_err(|error| NetworkError::BlockService(error.to_string()))
    }

    async fn put_replica(
        &self,
        codec: Codec,
        payload: Vec<u8>,
    ) -> Result<PutBlockResponse, NetworkError> {
        let _guard = self.operation_lock.read().await;
        tokio::task::block_in_place(|| self.block_store.put_replica(codec, &payload))
            .map_err(|error| NetworkError::BlockService(error.to_string()))
    }
}

pub(super) struct AgentPinService {
    pub(super) state: AppState,
}

#[async_trait]
impl NetworkPinService for AgentPinService {
    async fn apply(
        &self,
        authenticated_node: &str,
        pin_record_json: String,
    ) -> Result<(), NetworkError> {
        let pin: PinRecord = serde_json::from_str(&pin_record_json)?;
        if pin.owner != authenticated_node {
            return Err(NetworkError::Unauthenticated);
        }
        persist_pin(&self.state, &pin).map_err(|error| NetworkError::BlockService(error.message))
    }
}

pub(super) struct AgentComputeService {
    pub(super) state: AppState,
}

#[async_trait]
impl NetworkComputeService for AgentComputeService {
    async fn offer(&self, spec_json: String) -> Result<proto::ComputeOfferResponse, NetworkError> {
        let spec: ComputeJobSpec = serde_json::from_str(&spec_json)?;
        let offer = local_compute_offer(&self.state, &spec, None)
            .map_err(|error| NetworkError::BlockService(error.message))?;
        Ok(proto::ComputeOfferResponse {
            accepted: offer.accepted,
            node_id: offer.node_id,
            estimated_queue_delay_seconds: offer.estimated_queue_delay_seconds,
            local_input_bytes: offer.local_input_bytes,
            total_input_bytes: offer.total_input_bytes,
            available_parallelism: offer.available_parallelism,
            rejection_reason: offer.rejection_reason.unwrap_or_default(),
        })
    }

    async fn submit(
        &self,
        job_id: String,
        spec_json: String,
    ) -> Result<proto::ComputeSubmitResponse, NetworkError> {
        validate_job_id(&job_id).map_err(|error| NetworkError::BlockService(error.message))?;
        let spec: ComputeJobSpec = serde_json::from_str(&spec_json)?;
        if let Some(existing) = load_job(&self.state, &job_id)
            .map_err(|error| NetworkError::BlockService(error.message))?
        {
            if existing.spec != spec {
                return Err(NetworkError::Rpc {
                    code: "idempotency_conflict".to_string(),
                    message: "job ID already exists with a different specification".to_string(),
                });
            }
            return Ok(proto::ComputeSubmitResponse {
                job_status_json: serde_json::to_string(&existing)?,
            });
        }
        let offer = local_compute_offer(&self.state, &spec, None)
            .map_err(|error| NetworkError::BlockService(error.message))?;
        if !offer.accepted {
            return Err(NetworkError::Rpc {
                code: "compute_rejected".to_string(),
                message: offer
                    .rejection_reason
                    .unwrap_or_else(|| "compute offer rejected".to_string()),
            });
        }
        let mut job = new_compute_job(
            job_id.clone(),
            spec,
            "queued",
            Some(self.state.status.node_id.clone()),
            None,
        );
        job.attempts.push(ComputeAttempt {
            node_id: self.state.status.node_id.clone(),
            address: None,
            status: "accepted".to_string(),
            error: None,
            started_at_unix_seconds: unix_seconds(),
            finished_at_unix_seconds: None,
            events: Vec::new(),
        });
        persist_job(&self.state, &job)
            .map_err(|error| NetworkError::BlockService(error.message))?;
        if let Err(error) = spawn_compute_job(self.state.clone(), job_id) {
            job.status = "failed".to_string();
            job.finished_at_unix_seconds = Some(unix_seconds());
            job.error = Some(error.message.clone());
            let _ = persist_job(&self.state, &job);
            return Err(NetworkError::BlockService(error.message));
        }
        Ok(proto::ComputeSubmitResponse {
            job_status_json: serde_json::to_string(&job)?,
        })
    }

    async fn status(&self, job_id: String) -> Result<proto::ComputeStatusResponse, NetworkError> {
        let job = load_job(&self.state, &job_id)
            .map_err(|error| NetworkError::BlockService(error.message))?
            .ok_or_else(|| NetworkError::BlockService("job not found".to_string()))?;
        Ok(proto::ComputeStatusResponse {
            job_status_json: serde_json::to_string(&job)?,
        })
    }

    async fn logs(&self, job_id: String) -> Result<proto::ComputeLogsResponse, NetworkError> {
        let logs = compute_logs_for_job(&self.state, &job_id)
            .await
            .map_err(|error| NetworkError::BlockService(error.message))?;
        Ok(proto::ComputeLogsResponse {
            logs_json: serde_json::to_string(&logs)?,
        })
    }

    async fn cancel(&self, job_id: String) -> Result<proto::ComputeCancelResponse, NetworkError> {
        let job = cancel_compute_job_by_id(&self.state, &job_id)
            .await
            .map_err(|error| NetworkError::BlockService(error.message))?;
        Ok(proto::ComputeCancelResponse {
            job_status_json: serde_json::to_string(&job)?,
        })
    }
}
