// SPDX-License-Identifier: Apache-2.0

//! Adapters between the network RPC layer and agent domain services.

use super::*;

const BLOCK_WRITE_BATCH_SIZE: usize = 4;
const BLOCK_WRITE_BATCH_DELAY: Duration = Duration::from_micros(250);
struct BlockBatchMetrics {
    requests: AtomicU64,
    batches: AtomicU64,
    coalesced_batches: AtomicU64,
    max_batch_size: AtomicU64,
    queue_micros: AtomicU64,
    execution_micros: AtomicU64,
}

impl BlockBatchMetrics {
    const fn new() -> Self {
        Self {
            requests: AtomicU64::new(0),
            batches: AtomicU64::new(0),
            coalesced_batches: AtomicU64::new(0),
            max_batch_size: AtomicU64::new(0),
            queue_micros: AtomicU64::new(0),
            execution_micros: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> BlockBatchStats {
        BlockBatchStats {
            requests: self.requests.load(Ordering::Relaxed),
            batches: self.batches.load(Ordering::Relaxed),
            coalesced_batches: self.coalesced_batches.load(Ordering::Relaxed),
            max_batch_size: self.max_batch_size.load(Ordering::Relaxed),
            queue_micros: self.queue_micros.load(Ordering::Relaxed),
            execution_micros: self.execution_micros.load(Ordering::Relaxed),
        }
    }
}

static NORMAL_BLOCK_BATCH_METRICS: BlockBatchMetrics = BlockBatchMetrics::new();
static REPLICA_BLOCK_BATCH_METRICS: BlockBatchMetrics = BlockBatchMetrics::new();

#[derive(Clone, Copy)]
pub(super) struct BlockBatchStats {
    pub(super) requests: u64,
    pub(super) batches: u64,
    pub(super) coalesced_batches: u64,
    pub(super) max_batch_size: u64,
    pub(super) queue_micros: u64,
    pub(super) execution_micros: u64,
}

pub(super) fn block_batch_stats(replica: bool) -> BlockBatchStats {
    if replica {
        REPLICA_BLOCK_BATCH_METRICS.snapshot()
    } else {
        NORMAL_BLOCK_BATCH_METRICS.snapshot()
    }
}

struct BlockWriteRequest {
    codec: Codec,
    payload: Vec<u8>,
    verified_cid: Option<Cid>,
    encoded_logical_size: Option<u64>,
    enqueued_at: time::Instant,
    response: oneshot::Sender<Result<(PutBlockResponse, Vec<u8>), String>>,
}

#[derive(Clone)]
pub(super) struct BlockBatchWriter {
    sender: tokio::sync::mpsc::Sender<BlockWriteRequest>,
}

impl BlockBatchWriter {
    pub(super) fn normal(block_store: Arc<BlockStore>) -> Self {
        Self::spawn(block_store, false)
    }

    pub(super) fn replica(block_store: Arc<BlockStore>) -> Self {
        Self::spawn(block_store, true)
    }

    fn spawn(block_store: Arc<BlockStore>, replica: bool) -> Self {
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<BlockWriteRequest>(256);
        tokio::spawn(async move {
            while let Some(first) = receiver.recv().await {
                let mut requests = Vec::with_capacity(BLOCK_WRITE_BATCH_SIZE);
                requests.push(first);
                let deadline = time::sleep(BLOCK_WRITE_BATCH_DELAY);
                tokio::pin!(deadline);
                while requests.len() < BLOCK_WRITE_BATCH_SIZE {
                    tokio::select! {
                        request = receiver.recv() => {
                            let Some(request) = request else {
                                break;
                            };
                            requests.push(request);
                        }
                        _ = &mut deadline => break,
                    }
                }

                let metrics = if replica {
                    &REPLICA_BLOCK_BATCH_METRICS
                } else {
                    &NORMAL_BLOCK_BATCH_METRICS
                };
                metrics
                    .requests
                    .fetch_add(requests.len() as u64, Ordering::Relaxed);
                metrics.batches.fetch_add(1, Ordering::Relaxed);
                if requests.len() > 1 {
                    metrics.coalesced_batches.fetch_add(1, Ordering::Relaxed);
                }
                metrics
                    .max_batch_size
                    .fetch_max(requests.len() as u64, Ordering::Relaxed);
                let now = time::Instant::now();
                let queue_micros = requests
                    .iter()
                    .map(|request| {
                        now.duration_since(request.enqueued_at)
                            .as_micros()
                            .min(u64::MAX as u128) as u64
                    })
                    .sum::<u64>();
                metrics
                    .queue_micros
                    .fetch_add(queue_micros, Ordering::Relaxed);

                let mut responses = Vec::with_capacity(requests.len());
                let mut blocks = Vec::with_capacity(requests.len());
                let mut verified_cids = Vec::with_capacity(requests.len());
                let mut encoded_logical_sizes = Vec::with_capacity(requests.len());
                for request in requests {
                    blocks.push((request.codec, request.payload));
                    verified_cids.push(request.verified_cid);
                    encoded_logical_sizes.push(request.encoded_logical_size);
                    responses.push(request.response);
                }
                let store = block_store.clone();
                let execution_started = time::Instant::now();
                let result = tokio::task::spawn_blocking(move || {
                    let all_encoded = encoded_logical_sizes.iter().all(Option::is_some);
                    let any_encoded = encoded_logical_sizes.iter().any(Option::is_some);
                    if replica && all_encoded {
                        let wire_blocks = blocks
                            .into_iter()
                            .zip(verified_cids)
                            .zip(encoded_logical_sizes)
                            .map(|(((codec, payload), cid), logical_size)| {
                                let cid = cid.ok_or_else(|| {
                                    "encoded replica is missing its CID".to_string()
                                })?;
                                if cid.codec != codec {
                                    return Err("encoded replica codec mismatch".to_string());
                                }
                                Ok((
                                    cid,
                                    logical_size.expect("all encoded sizes were checked"),
                                    payload,
                                ))
                            })
                            .collect::<Result<Vec<_>, String>>();
                        let result = wire_blocks.and_then(|blocks| {
                            store
                                .put_replica_encoded_wire_batch(blocks)
                                .map_err(|error| error.to_string())
                        });
                        let payloads = (0..result.as_ref().map_or(0, Vec::len))
                            .map(|_| Vec::new())
                            .collect();
                        return (result, payloads);
                    }
                    if any_encoded {
                        return (
                            Err("cannot mix encoded and logical blocks in one batch".to_string()),
                            Vec::new(),
                        );
                    }
                    let result = if !replica {
                        store
                            .put_batch_with_encoded(&blocks)
                            .map(|(puts, encoded)| {
                                let payloads = encoded
                                    .into_iter()
                                    .map(pepper_storage::EncodedBlock::into_bytes)
                                    .collect::<Vec<_>>();
                                (puts, payloads)
                            })
                            .map_err(|error| error.to_string())
                    } else if blocks.len() == 1 {
                        let (codec, payload) = &blocks[0];
                        let puts = if let Some(cid) = &verified_cids[0] {
                            store
                                .put_replica_verified(*codec, payload, cid)
                                .map(|put| vec![put])
                        } else {
                            store.put_replica(*codec, payload).map(|put| vec![put])
                        };
                        puts.map(|puts| (puts, vec![Vec::new()]))
                            .map_err(|error| error.to_string())
                    } else {
                        if let Some(cids) =
                            verified_cids.iter().cloned().collect::<Option<Vec<_>>>()
                        {
                            store.put_replica_batch_verified(&blocks, &cids)
                        } else {
                            store.put_replica_batch(&blocks)
                        }
                        .map(|puts| {
                            let payloads = (0..puts.len()).map(|_| Vec::new()).collect();
                            (puts, payloads)
                        })
                        .map_err(|error| error.to_string())
                    };
                    match result {
                        Ok(result) => (Ok(result.0), result.1),
                        Err(error) => (Err(error), Vec::new()),
                    }
                })
                .await;
                metrics.execution_micros.fetch_add(
                    execution_started
                        .elapsed()
                        .as_micros()
                        .min(u64::MAX as u128) as u64,
                    Ordering::Relaxed,
                );
                match result {
                    Ok((Ok(puts), payloads))
                        if puts.len() == responses.len() && payloads.len() == responses.len() =>
                    {
                        for ((response, put), payload) in
                            responses.into_iter().zip(puts).zip(payloads)
                        {
                            let _ = response.send(Ok((put, payload)));
                        }
                    }
                    Ok((Ok(_), _)) => {
                        for response in responses {
                            let _ =
                                response
                                    .send(Err("block batch result length does not match request"
                                        .to_string()));
                        }
                    }
                    Ok((Err(error), _)) => {
                        let error = error.to_string();
                        for response in responses {
                            let _ = response.send(Err(error.clone()));
                        }
                    }
                    Err(error) => {
                        let error = format!("block batch worker failed: {error}");
                        for response in responses {
                            let _ = response.send(Err(error.clone()));
                        }
                    }
                }
            }
        });
        Self { sender }
    }

    pub(super) async fn put(
        &self,
        codec: Codec,
        payload: Vec<u8>,
    ) -> Result<PutBlockResponse, String> {
        self.put_with_payload(codec, payload)
            .await
            .map(|(put, _)| put)
    }

    pub(super) async fn put_with_payload(
        &self,
        codec: Codec,
        payload: Vec<u8>,
    ) -> Result<(PutBlockResponse, Vec<u8>), String> {
        self.put_with_payload_and_cid(codec, payload, None).await
    }

    pub(super) async fn put_verified(
        &self,
        codec: Codec,
        payload: Vec<u8>,
        cid: Cid,
    ) -> Result<PutBlockResponse, String> {
        self.put_with_payload_and_cid(codec, payload, Some(cid))
            .await
            .map(|(put, _)| put)
    }

    async fn put_with_payload_and_cid(
        &self,
        codec: Codec,
        payload: Vec<u8>,
        verified_cid: Option<Cid>,
    ) -> Result<(PutBlockResponse, Vec<u8>), String> {
        let (response, receive) = oneshot::channel();
        self.sender
            .send(BlockWriteRequest {
                codec,
                payload,
                verified_cid,
                encoded_logical_size: None,
                enqueued_at: time::Instant::now(),
                response,
            })
            .await
            .map_err(|_| "block batch writer is unavailable".to_string())?;
        receive
            .await
            .map_err(|_| "block batch writer stopped before replying".to_string())?
    }

    pub(super) async fn put_encoded_verified(
        &self,
        codec: Codec,
        payload: Vec<u8>,
        cid: Cid,
        logical_size: u64,
    ) -> Result<PutBlockResponse, String> {
        let (response, receive) = oneshot::channel();
        self.sender
            .send(BlockWriteRequest {
                codec,
                payload,
                verified_cid: Some(cid),
                encoded_logical_size: Some(logical_size),
                enqueued_at: time::Instant::now(),
                response,
            })
            .await
            .map_err(|_| "block batch writer is unavailable".to_string())?;
        receive
            .await
            .map_err(|_| "block batch writer stopped before replying".to_string())?
            .map(|(put, _)| put)
    }
}

pub(super) struct AgentBlockService {
    pub(super) block_store: Arc<BlockStore>,
    pub(super) replica_writer: BlockBatchWriter,
    pub(super) operation_lock: Arc<RwLock<()>>,
}

#[async_trait]
impl NetworkBlockService for AgentBlockService {
    async fn has_block(&self, cid: &Cid) -> Result<bool, NetworkError> {
        let _guard = self.operation_lock.read().await;
        tokio::task::block_in_place(|| self.block_store.has(cid))
            .map_err(|error| NetworkError::BlockService(error.to_string()))
    }

    async fn has_blocks(&self, cids: &[Cid]) -> Result<Vec<bool>, NetworkError> {
        let _guard = self.operation_lock.read().await;
        tokio::task::block_in_place(|| {
            cids.iter()
                .map(|cid| self.block_store.has(cid))
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|error| NetworkError::BlockService(error.to_string()))
    }

    async fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, NetworkError> {
        let _guard = self.operation_lock.read().await;
        tokio::task::block_in_place(|| self.block_store.get(cid))
            .map(|block| block.payload)
            .map_err(|error| NetworkError::BlockService(error.to_string()))
    }

    async fn get_block_range(
        &self,
        cid: &Cid,
        start: u64,
        end: u64,
    ) -> Result<Vec<u8>, NetworkError> {
        let _guard = self.operation_lock.read().await;
        tokio::task::block_in_place(|| self.block_store.get_range(cid, start, end))
            .map_err(|error| NetworkError::BlockService(error.to_string()))
    }

    async fn put_replica(
        &self,
        codec: Codec,
        payload: Vec<u8>,
    ) -> Result<PutBlockResponse, NetworkError> {
        let _guard = self.operation_lock.read().await;
        self.replica_writer
            .put(codec, payload)
            .await
            .map_err(|error| NetworkError::BlockService(error.to_string()))
    }

    async fn put_verified_replica(
        &self,
        codec: Codec,
        expected_cid: &Cid,
        payload: Vec<u8>,
    ) -> Result<PutBlockResponse, NetworkError> {
        let _guard = self.operation_lock.read().await;
        self.replica_writer
            .put_verified(codec, payload, expected_cid.clone())
            .await
            .map_err(|error| NetworkError::BlockService(error.to_string()))
    }

    async fn put_encoded_verified_replica(
        &self,
        codec: Codec,
        expected_cid: &Cid,
        logical_size: u64,
        payload: Vec<u8>,
    ) -> Result<PutBlockResponse, NetworkError> {
        let _guard = self.operation_lock.read().await;
        self.replica_writer
            .put_encoded_verified(codec, payload, expected_cid.clone(), logical_size)
            .await
            .map_err(|error| NetworkError::BlockService(error.to_string()))
    }
}

pub(super) struct AgentErasureService {
    pub(super) state: AppState,
}

#[async_trait]
impl NetworkErasureService for AgentErasureService {
    async fn push_repair_inventory(
        &self,
        authenticated_node: &str,
        inventory_json: String,
    ) -> Result<(), NetworkError> {
        accept_repair_inventory(&self.state, authenticated_node, &inventory_json)
            .await
            .map_err(|error| NetworkError::BlockService(error.message))
    }

    async fn execute_repair(
        &self,
        authenticated_node: &str,
        task_json: String,
    ) -> Result<proto::RepairExecuteResponse, NetworkError> {
        let request: RepairExecutionRequest = serde_json::from_str(&task_json)?;
        execute_placement_repair(&self.state, authenticated_node, request)
            .await
            .map_err(|error| NetworkError::BlockService(error.message))
    }

    async fn cleanup_repair_extra(
        &self,
        _authenticated_node: &str,
        exception_json: String,
    ) -> Result<bool, NetworkError> {
        let exception: PlacementException = serde_json::from_str(&exception_json)?;
        cleanup_expired_repair_extra(&self.state, exception)
            .await
            .map_err(|error| NetworkError::BlockService(error.message))
    }

    async fn encode_parity(
        &self,
        _authenticated_node: &str,
        request: proto::ErasureTransferRequest,
    ) -> Result<proto::ErasureTransferResponse, NetworkError> {
        execute_distributed_parity(&self.state, request)
            .await
            .map_err(|error| NetworkError::BlockService(error.message))
    }

    async fn store_stripe_stream(
        &self,
        _authenticated_node: &str,
        request: proto::ErasureTransferRequest,
        mut chunks: ErasureChunkReceiver,
    ) -> Result<proto::ErasureTransferResponse, NetworkError> {
        if request.plan == EcTransferPlan::Pipelined.as_str() {
            return execute_pipelined_erasure_transfer(&self.state, request, chunks)
                .await
                .map_err(|error| NetworkError::BlockService(error.message));
        }
        let capacity = usize::try_from(request.encoded_size).map_err(|_| {
            NetworkError::BlockService("encoded size does not fit usize".to_string())
        })?;
        let mut encoded = Vec::with_capacity(capacity);
        while let Some(chunk) = chunks.recv().await {
            if encoded.len().saturating_add(chunk.len()) > capacity {
                return Err(NetworkError::BlockService(
                    "erasure stream exceeded declared size".to_string(),
                ));
            }
            encoded.extend_from_slice(&chunk);
        }
        execute_remote_erasure_transfer(&self.state, request, encoded)
            .await
            .map_err(|error| NetworkError::BlockService(error.message))
    }
}

pub(super) struct AgentPinService {
    pub(super) state: AppState,
}

pub(super) struct AgentNamespaceAliasService {
    pub(super) state: AppState,
}

#[async_trait]
impl NetworkNamespaceAliasService for AgentNamespaceAliasService {
    async fn resolve(
        &self,
        _authenticated_node: &str,
        alias: String,
    ) -> Result<Option<String>, NetworkError> {
        match namespace_alias(&self.state, &alias) {
            Ok(namespace) => Ok(Some(namespace.to_string())),
            Err(error) if error.code == ErrorCode::NotFound => Ok(None),
            Err(error) => Err(NetworkError::BlockService(error.message)),
        }
    }

    async fn list(&self, _authenticated_node: &str) -> Result<Vec<(String, String)>, NetworkError> {
        local_s3_bucket_catalog_namespace(&self.state)
            .await
            .map(|namespace| {
                namespace
                    .into_iter()
                    .map(|namespace| (S3_BUCKET_CATALOG_ALIAS.to_string(), namespace.to_string()))
                    .collect()
            })
            .map_err(|error| NetworkError::BlockService(error.message))
    }
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
