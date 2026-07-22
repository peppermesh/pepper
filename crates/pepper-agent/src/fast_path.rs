// SPDX-License-Identifier: Apache-2.0

//! Per-core ownership for ordinary S3 requests.
//!
//! The HTTP/control runtime performs authentication and hands an owned request
//! future to exactly one stable worker. Each worker has a bounded ingress queue,
//! local admission budgets, a local storage submission batcher, and an isolated
//! one-thread Tokio scheduler. Response bodies are drained on the owner and
//! transferred back as bounded `Bytes` frames, preserving streaming backpressure.

use super::*;
use crate::placement::PlacementSnapshot;
use axum::body::HttpBody;
use pepper_config::FastPathConfig;
use std::{
    future::Future,
    pin::Pin,
    sync::OnceLock,
    sync::atomic::{AtomicBool, AtomicUsize},
    thread::JoinHandle,
};

type S3Future = Pin<Box<dyn Future<Output = Result<Response, S3Error>> + Send + 'static>>;

tokio::task_local! {
    static OWNER: Arc<OwnerContext>;
}

struct WorkItem {
    enqueued_at: time::Instant,
    future: S3Future,
    response: oneshot::Sender<Result<Response, S3Error>>,
}

enum OwnerCommand {
    Execute(WorkItem),
    Shutdown,
}

struct OwnerMetrics {
    requests: AtomicU64,
    active: AtomicU64,
    queue_micros: AtomicU64,
    execution_micros: AtomicU64,
    response_bytes: AtomicU64,
    buffer_hits: AtomicU64,
    buffer_misses: AtomicU64,
}

const OWNER_MANIFEST_CACHE_ENTRIES: usize = 1_024;

#[derive(Default)]
struct OwnerManifestCache {
    entries: HashMap<Cid, Arc<ErasureManifest>>,
    insertion_order: VecDeque<Cid>,
}

impl OwnerManifestCache {
    fn get(&self, cid: &Cid) -> Option<Arc<ErasureManifest>> {
        self.entries.get(cid).cloned()
    }

    fn insert(&mut self, cid: Cid, manifest: Arc<ErasureManifest>) {
        if self.entries.contains_key(&cid) {
            return;
        }
        while self.entries.len() >= OWNER_MANIFEST_CACHE_ENTRIES {
            let Some(expired) = self.insertion_order.pop_front() else {
                break;
            };
            self.entries.remove(&expired);
        }
        self.insertion_order.push_back(cid.clone());
        self.entries.insert(cid, manifest);
    }
}

impl OwnerMetrics {
    const fn new() -> Self {
        Self {
            requests: AtomicU64::new(0),
            active: AtomicU64::new(0),
            queue_micros: AtomicU64::new(0),
            execution_micros: AtomicU64::new(0),
            response_bytes: AtomicU64::new(0),
            buffer_hits: AtomicU64::new(0),
            buffer_misses: AtomicU64::new(0),
        }
    }
}

pub(super) struct OwnerContext {
    cpu_id: usize,
    network: OnceLock<NetworkHandle>,
    local_block_writer: OnceLock<BlockBatchWriter>,
    write_slots: Arc<Semaphore>,
    write_capacity: usize,
    replication_slots: Arc<Semaphore>,
    stripe_read_slots: Arc<Semaphore>,
    response_frames: usize,
    placement: std::sync::RwLock<Arc<PlacementSnapshot>>,
    peer_addresses: tokio::sync::RwLock<HashMap<String, SocketAddr>>,
    read_diagnostics: std::sync::Mutex<VecDeque<ReadDiagnosticRecord>>,
    buffers: std::sync::Mutex<Vec<Vec<u8>>>,
    bucket_namespaces: std::sync::RwLock<HashMap<String, NamespaceId>>,
    erasure_manifests: std::sync::Mutex<OwnerManifestCache>,
    metrics: Arc<OwnerMetrics>,
}

struct OwnerHandle {
    id: usize,
    cpu_id: usize,
    sender: tokio::sync::mpsc::Sender<OwnerCommand>,
    healthy: Arc<AtomicBool>,
    context: Arc<OwnerContext>,
    metrics: Arc<OwnerMetrics>,
}

struct OwnerBootstrap {
    healthy: Arc<AtomicBool>,
    requests_per_worker: usize,
    pin_cpus: bool,
    block_store: Arc<BlockStore>,
    network: Option<NetworkHandle>,
    replica_streams: usize,
    ready: std::sync::mpsc::SyncSender<Result<(), String>>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct OwnerSnapshot {
    pub(super) id: usize,
    pub(super) cpu_id: usize,
    pub(super) data_port: u16,
    pub(super) healthy: bool,
    pub(super) queue_depth: usize,
    pub(super) requests: u64,
    pub(super) active: u64,
    pub(super) queue_micros: u64,
    pub(super) execution_micros: u64,
    pub(super) response_bytes: u64,
    pub(super) buffer_hits: u64,
    pub(super) buffer_misses: u64,
}

pub(super) struct FastPathRuntime {
    owners: Vec<OwnerHandle>,
    _threads: Vec<JoinHandle<()>>,
    reserved_control_cores: usize,
    cpu_pinning_enabled: bool,
    dispatches: AtomicU64,
    rejections: AtomicU64,
    failovers: AtomicU64,
    cross_core_hops: AtomicU64,
}

impl Drop for FastPathRuntime {
    fn drop(&mut self) {
        for owner in &self.owners {
            let _ = owner.sender.try_send(OwnerCommand::Shutdown);
        }
    }
}

impl FastPathRuntime {
    pub(super) fn start(
        config: &FastPathConfig,
        block_store: Arc<BlockStore>,
        placement: PlacementSnapshot,
        network: Option<&NetworkHandle>,
    ) -> Result<Arc<Self>> {
        let cpu_ids = available_cpu_ids();
        let reserved = config.control_cores.min(cpu_ids.len().saturating_sub(1));
        let mut owner_cpus = cpu_ids.iter().copied().skip(reserved).collect::<Vec<_>>();
        if owner_cpus.is_empty() {
            owner_cpus.push(*cpu_ids.first().unwrap_or(&0));
        }
        let environment_cap = std::env::var("PEPPER_FAST_PATH_WORKERS")
            .ok()
            .or_else(|| std::env::var("TOKIO_WORKER_THREADS").ok())
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0);
        let desired = if config.workers == 0 {
            environment_cap
                .unwrap_or(owner_cpus.len())
                .min(owner_cpus.len())
        } else {
            config.workers.min(owner_cpus.len())
        }
        .max(1);
        owner_cpus.truncate(desired);

        let mut owners = Vec::with_capacity(desired);
        let mut threads = Vec::with_capacity(desired);
        for (id, cpu_id) in owner_cpus.into_iter().enumerate() {
            let (sender, receiver) = tokio::sync::mpsc::channel(config.queue_depth);
            let healthy = Arc::new(AtomicBool::new(true));
            let metrics = Arc::new(OwnerMetrics::new());
            let context = Arc::new(OwnerContext {
                cpu_id,
                network: OnceLock::new(),
                local_block_writer: OnceLock::new(),
                write_slots: Arc::new(Semaphore::new(config.writes_per_worker)),
                write_capacity: config.writes_per_worker,
                replication_slots: Arc::new(Semaphore::new(config.replications_per_worker)),
                stripe_read_slots: Arc::new(Semaphore::new(config.stripe_reads_per_worker)),
                response_frames: config.response_frames,
                placement: std::sync::RwLock::new(Arc::new(placement.clone())),
                peer_addresses: tokio::sync::RwLock::new(HashMap::new()),
                read_diagnostics: std::sync::Mutex::new(VecDeque::with_capacity(512)),
                buffers: std::sync::Mutex::new(Vec::with_capacity(16)),
                bucket_namespaces: std::sync::RwLock::new(HashMap::new()),
                erasure_manifests: std::sync::Mutex::new(OwnerManifestCache::default()),
                metrics: metrics.clone(),
            });
            let worker_healthy = healthy.clone();
            let worker_context = context.clone();
            let pin_cpus = config.pin_cpus;
            let requests_per_worker = config.requests_per_worker;
            let owner_block_store = block_store.clone();
            let owner_network = network.cloned();
            let replica_streams = config.replications_per_worker;
            let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
            let thread = std::thread::Builder::new()
                .name(format!("pepper-s3-owner-{id}"))
                .spawn(move || {
                    run_owner(
                        worker_context,
                        receiver,
                        OwnerBootstrap {
                            healthy: worker_healthy,
                            requests_per_worker,
                            pin_cpus,
                            block_store: owner_block_store,
                            network: owner_network,
                            replica_streams,
                            ready: ready_sender,
                        },
                    );
                })
                .map_err(|error| anyhow::anyhow!("failed to spawn S3 owner {id}: {error}"))?;
            match ready_receiver.recv_timeout(Duration::from_secs(10)) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    let _ = thread.join();
                    return Err(anyhow::anyhow!(
                        "failed to initialize S3 owner {id}: {error}"
                    ));
                }
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "timed out initializing S3 owner {id}: {error}"
                    ));
                }
            }
            owners.push(OwnerHandle {
                id,
                cpu_id,
                sender,
                healthy,
                context,
                metrics,
            });
            threads.push(thread);
        }
        Ok(Arc::new(Self {
            owners,
            _threads: threads,
            reserved_control_cores: reserved,
            cpu_pinning_enabled: config.pin_cpus,
            dispatches: AtomicU64::new(0),
            rejections: AtomicU64::new(0),
            failovers: AtomicU64::new(0),
            cross_core_hops: AtomicU64::new(0),
        }))
    }

    pub(super) fn owner_count(&self) -> usize {
        self.owners.len()
    }

    pub(super) fn reserved_control_cores(&self) -> usize {
        self.reserved_control_cores
    }

    pub(super) fn cpu_pinning_enabled(&self) -> bool {
        self.cpu_pinning_enabled
    }

    pub(super) fn refresh_placement(&self, placement: PlacementSnapshot) {
        let placement = Arc::new(placement);
        for owner in &self.owners {
            *owner
                .context
                .placement
                .write()
                .expect("owner placement lock poisoned") = placement.clone();
        }
    }

    pub(super) fn cache_bucket_namespace(&self, bucket: &str, namespace_id: NamespaceId) {
        for owner in &self.owners {
            owner
                .context
                .bucket_namespaces
                .write()
                .expect("owner bucket cache lock poisoned")
                .insert(bucket.to_string(), namespace_id.clone());
        }
    }

    pub(super) fn invalidate_bucket_namespace(&self, bucket: &str) {
        for owner in &self.owners {
            owner
                .context
                .bucket_namespaces
                .write()
                .expect("owner bucket cache lock poisoned")
                .remove(bucket);
        }
    }

    pub(super) fn owner_for(&self, affinity: &[u8]) -> usize {
        let digest = blake3::hash(affinity);
        let mut encoded = [0u8; 8];
        encoded.copy_from_slice(&digest.as_bytes()[..8]);
        (u64::from_le_bytes(encoded) as usize) % self.owners.len()
    }

    pub(super) async fn execute<F>(
        &self,
        affinity: &[u8],
        resource: &str,
        future: F,
    ) -> Result<Response, S3Error>
    where
        F: Future<Output = Result<Response, S3Error>> + Send + 'static,
    {
        let preferred = self.owner_for(affinity);
        let (response, receive) = oneshot::channel();
        let mut item = WorkItem {
            enqueued_at: time::Instant::now(),
            future: Box::pin(future),
            response,
        };
        let mut selected = None;
        for offset in 0..self.owners.len() {
            let index = (preferred + offset) % self.owners.len();
            let owner = &self.owners[index];
            if !owner.healthy.load(Ordering::Acquire) {
                continue;
            }
            match owner.sender.try_send(OwnerCommand::Execute(item)) {
                Ok(()) => {
                    selected = Some(index);
                    break;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_returned)) => {
                    self.rejections.fetch_add(1, Ordering::Relaxed);
                    return Err(S3Error::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "SlowDown",
                        format!("S3 owner {index} admission queue is full"),
                        resource,
                    )
                    .with_retry_after(1));
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(returned)) => {
                    owner.healthy.store(false, Ordering::Release);
                    item = match returned {
                        OwnerCommand::Execute(item) => item,
                        OwnerCommand::Shutdown => unreachable!("execute never sends shutdown"),
                    };
                }
            }
        }
        let Some(selected) = selected else {
            self.rejections.fetch_add(1, Ordering::Relaxed);
            return Err(S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "all per-core S3 owners are unavailable",
                resource,
            ));
        };
        if selected != preferred {
            self.failovers.fetch_add(1, Ordering::Relaxed);
        }
        self.dispatches.fetch_add(1, Ordering::Relaxed);
        self.cross_core_hops.fetch_add(1, Ordering::Relaxed);
        let result = receive.await.map_err(|_| {
            self.owners[selected]
                .healthy
                .store(false, Ordering::Release);
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                format!("S3 owner {selected} stopped before replying"),
                resource,
            )
        })?;
        self.cross_core_hops.fetch_add(1, Ordering::Relaxed);
        result
    }

    pub(super) fn snapshots(&self) -> Vec<OwnerSnapshot> {
        self.owners
            .iter()
            .map(|owner| OwnerSnapshot {
                id: owner.id,
                cpu_id: owner.cpu_id,
                data_port: owner
                    .context
                    .network
                    .get()
                    .and_then(NetworkHandle::local_transport_addr)
                    .map_or(0, |address| address.port()),
                healthy: owner.healthy.load(Ordering::Acquire),
                queue_depth: owner.sender.max_capacity() - owner.sender.capacity(),
                requests: owner.metrics.requests.load(Ordering::Relaxed),
                active: owner.metrics.active.load(Ordering::Relaxed),
                queue_micros: owner.metrics.queue_micros.load(Ordering::Relaxed),
                execution_micros: owner.metrics.execution_micros.load(Ordering::Relaxed),
                response_bytes: owner.metrics.response_bytes.load(Ordering::Relaxed),
                buffer_hits: owner.metrics.buffer_hits.load(Ordering::Relaxed),
                buffer_misses: owner.metrics.buffer_misses.load(Ordering::Relaxed),
            })
            .collect()
    }

    pub(super) fn totals(&self) -> (u64, u64, u64, u64) {
        (
            self.dispatches.load(Ordering::Relaxed),
            self.rejections.load(Ordering::Relaxed),
            self.failovers.load(Ordering::Relaxed),
            self.cross_core_hops.load(Ordering::Relaxed),
        )
    }

    pub(super) fn read_diagnostics(&self) -> Vec<ReadDiagnosticRecord> {
        let mut records = self
            .owners
            .iter()
            .flat_map(|owner| {
                owner
                    .context
                    .read_diagnostics
                    .lock()
                    .expect("owner read diagnostic lock poisoned")
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        records.sort_by_key(|record| record.sequence);
        records
    }

    #[cfg(test)]
    async fn shutdown_owner(&self, owner: usize) {
        self.owners[owner]
            .sender
            .send(OwnerCommand::Shutdown)
            .await
            .unwrap();
        for _ in 0..100 {
            if !self.owners[owner].healthy.load(Ordering::Acquire) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("owner did not stop");
    }
}

fn run_owner(
    context: Arc<OwnerContext>,
    mut receiver: tokio::sync::mpsc::Receiver<OwnerCommand>,
    bootstrap: OwnerBootstrap,
) {
    let OwnerBootstrap {
        healthy,
        requests_per_worker,
        pin_cpus,
        block_store,
        network,
        replica_streams,
        ready,
    } = bootstrap;
    let cpu_id = context.cpu_id;
    let next_thread = Arc::new(AtomicUsize::new(0));
    let affinity_counter = next_thread.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(4)
        .thread_name(format!("pepper-s3-core-{cpu_id}"))
        .on_thread_start(move || {
            if pin_cpus {
                let _ = affinity_counter.fetch_add(1, Ordering::Relaxed);
                pin_current_thread(cpu_id);
            }
        })
        .enable_all()
        .build();
    let Ok(runtime) = runtime else {
        healthy.store(false, Ordering::Release);
        let _ = ready.send(Err("Tokio runtime creation failed".to_string()));
        return;
    };
    let request_slots = Arc::new(Semaphore::new(requests_per_worker));
    runtime.block_on(async move {
        if let Some(network) = network {
            let isolated = match network.isolated_data_endpoint(replica_streams) {
                Ok(isolated) => isolated,
                Err(error) => {
                    healthy.store(false, Ordering::Release);
                    let _ = ready.send(Err(error.to_string()));
                    return;
                }
            };
            assert!(
                context.network.set(isolated).is_ok(),
                "owner data endpoint is initialized exactly once"
            );
        }
        assert!(
            context
                .local_block_writer
                .set(BlockBatchWriter::normal(block_store))
                .is_ok(),
            "owner block writer is initialized exactly once"
        );
        let _ = ready.send(Ok(()));
        while let Ok(permit) = request_slots.clone().acquire_owned().await {
            let Some(command) = receiver.recv().await else {
                break;
            };
            let item = match command {
                OwnerCommand::Execute(item) => item,
                OwnerCommand::Shutdown => break,
            };
            let owner = context.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let queue_elapsed = item.enqueued_at.elapsed();
                owner.metrics.queue_micros.fetch_add(
                    queue_elapsed.as_micros().min(u128::from(u64::MAX)) as u64,
                    Ordering::Relaxed,
                );
                owner.metrics.requests.fetch_add(1, Ordering::Relaxed);
                owner.metrics.active.fetch_add(1, Ordering::Relaxed);
                let started = time::Instant::now();
                let scoped_owner = owner.clone();
                let response = OWNER
                    .scope(owner.clone(), async move {
                        match item.future.await {
                            Ok(response) => Ok(detach_response_body(response, &scoped_owner).await),
                            Err(error) => Err(error),
                        }
                    })
                    .await;
                owner.metrics.execution_micros.fetch_add(
                    started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
                    Ordering::Relaxed,
                );
                owner.metrics.active.fetch_sub(1, Ordering::Relaxed);
                let _ = item.response.send(response);
            });
        }
        healthy.store(false, Ordering::Release);
    });
}

async fn detach_response_body(response: Response, owner: &Arc<OwnerContext>) -> Response {
    let (parts, body) = response.into_parts();
    if body.is_end_stream() {
        return Response::from_parts(parts, body);
    }
    let small_response = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length <= 64 * 1024);
    if small_response {
        return match axum::body::to_bytes(body, 64 * 1024).await {
            Ok(bytes) => {
                owner
                    .metrics
                    .response_bytes
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                Response::from_parts(parts, Body::from(bytes))
            }
            Err(error) => {
                let stream = futures_util::stream::once(async move {
                    Err::<Bytes, std::io::Error>(std::io::Error::other(error.to_string()))
                });
                Response::from_parts(parts, Body::from_stream(stream))
            }
        };
    }
    let (sender, receiver) = tokio::sync::mpsc::channel(owner.response_frames);
    let metrics = owner.metrics.clone();
    tokio::spawn(async move {
        let mut stream = body.into_data_stream();
        while let Some(frame) = stream.next().await {
            let frame = frame.map_err(|error| std::io::Error::other(error.to_string()));
            if let Ok(bytes) = &frame {
                metrics
                    .response_bytes
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
            if sender.send(frame).await.is_err() {
                break;
            }
        }
    });
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|frame| (frame, receiver))
    });
    Response::from_parts(parts, Body::from_stream(stream))
}

pub(super) fn local_block_writer() -> Option<BlockBatchWriter> {
    OWNER
        .try_with(|owner| owner.local_block_writer.get().cloned())
        .ok()
        .flatten()
}

pub(super) fn io_network(fallback: &NetworkHandle) -> NetworkHandle {
    OWNER
        .try_with(|owner| owner.network.get().cloned())
        .ok()
        .flatten()
        .unwrap_or_else(|| fallback.clone())
}

pub(super) fn write_slots() -> Option<Arc<Semaphore>> {
    OWNER.try_with(|owner| owner.write_slots.clone()).ok()
}

pub(super) fn write_pressure_milli() -> Option<u16> {
    OWNER
        .try_with(|owner| {
            let active = owner
                .write_capacity
                .saturating_sub(owner.write_slots.available_permits());
            pressure_milli(active, owner.write_capacity)
        })
        .ok()
}

fn pressure_milli(active: usize, capacity: usize) -> u16 {
    if capacity == 0 {
        return 0;
    }
    active
        .saturating_mul(1_000)
        .checked_div(capacity)
        .unwrap_or(1_000)
        .min(1_000) as u16
}

pub(super) fn replication_slots() -> Option<Arc<Semaphore>> {
    OWNER.try_with(|owner| owner.replication_slots.clone()).ok()
}

pub(super) fn stripe_read_slots() -> Option<Arc<Semaphore>> {
    OWNER.try_with(|owner| owner.stripe_read_slots.clone()).ok()
}

pub(super) fn cached_erasure_manifest(cid: &Cid) -> Option<Arc<ErasureManifest>> {
    OWNER
        .try_with(|owner| {
            let manifest = owner
                .erasure_manifests
                .lock()
                .expect("owner manifest cache lock poisoned")
                .get(cid);
            if manifest.is_some() {
                owner.metrics.buffer_hits.fetch_add(1, Ordering::Relaxed);
            } else {
                owner.metrics.buffer_misses.fetch_add(1, Ordering::Relaxed);
            }
            manifest
        })
        .ok()
        .flatten()
}

pub(super) fn cache_erasure_manifest(cid: Cid, manifest: Arc<ErasureManifest>) {
    let _ = OWNER.try_with(|owner| {
        owner
            .erasure_manifests
            .lock()
            .expect("owner manifest cache lock poisoned")
            .insert(cid, manifest);
    });
}

pub(super) fn local_current_placement_map()
-> Result<Option<Arc<pepper_placement::PlacementMap>>, ()> {
    OWNER
        .try_with(|owner| {
            owner
                .placement
                .read()
                .expect("owner placement lock poisoned")
                .current_map()
        })
        .map_err(|_| ())
}

pub(super) fn local_placement_map(
    epoch: u64,
) -> Result<Option<Arc<pepper_placement::PlacementMap>>, ()> {
    OWNER
        .try_with(|owner| {
            owner
                .placement
                .read()
                .expect("owner placement lock poisoned")
                .map(epoch)
        })
        .map_err(|_| ())
}

pub(super) fn local_placement_exception(
    reference: &PlacementReference,
    now_unix_seconds: i64,
) -> Result<Option<pepper_placement::PlacementException>, ()> {
    OWNER
        .try_with(|owner| {
            owner
                .placement
                .read()
                .expect("owner placement lock poisoned")
                .exception(reference, now_unix_seconds)
        })
        .map_err(|_| ())
}

pub(super) async fn peer_address(network: &NetworkHandle, node_id: &str) -> Option<SocketAddr> {
    let owner = OWNER.try_with(Arc::clone).ok();
    if let Some(owner) = owner {
        if let Some(address) = owner.peer_addresses.read().await.get(node_id).copied() {
            return Some(address);
        }
        let address = network.peer_address(node_id).await?;
        owner
            .peer_addresses
            .write()
            .await
            .insert(node_id.to_string(), address);
        return Some(address);
    }
    network.peer_address(node_id).await
}

pub(super) fn record_read_diagnostic(
    record: ReadDiagnosticRecord,
) -> Result<(), ReadDiagnosticRecord> {
    let owner = OWNER.try_with(Arc::clone).map_err(|_| record.clone())?;
    let mut records = owner
        .read_diagnostics
        .lock()
        .expect("owner read diagnostic lock poisoned");
    if records.len() == 512 {
        records.pop_front();
    }
    records.push_back(record);
    Ok(())
}

pub(super) fn take_buffer(minimum_capacity: usize) -> Vec<u8> {
    let Ok(owner) = OWNER.try_with(Arc::clone) else {
        return Vec::with_capacity(minimum_capacity);
    };
    let mut buffers = owner
        .buffers
        .lock()
        .expect("owner buffer pool lock poisoned");
    if let Some(index) = buffers
        .iter()
        .position(|buffer| buffer.capacity() >= minimum_capacity)
    {
        owner.metrics.buffer_hits.fetch_add(1, Ordering::Relaxed);
        let mut buffer = buffers.swap_remove(index);
        buffer.clear();
        return buffer;
    }
    owner.metrics.buffer_misses.fetch_add(1, Ordering::Relaxed);
    Vec::with_capacity(minimum_capacity)
}

pub(super) fn recycle_buffer(mut buffer: Vec<u8>) {
    if buffer.capacity() > 64 * 1024 * 1024 {
        return;
    }
    let Ok(owner) = OWNER.try_with(Arc::clone) else {
        return;
    };
    buffer.clear();
    let mut buffers = owner
        .buffers
        .lock()
        .expect("owner buffer pool lock poisoned");
    if buffers.len() < 16 {
        buffers.push(buffer);
    }
}

pub(super) fn local_bucket_namespace(bucket: &str) -> Option<NamespaceId> {
    OWNER
        .try_with(|owner| {
            owner
                .bucket_namespaces
                .read()
                .expect("owner bucket cache lock poisoned")
                .get(bucket)
                .cloned()
        })
        .ok()
        .flatten()
}

#[cfg(target_os = "linux")]
pub(super) fn available_cpu_ids() -> Vec<usize> {
    // SAFETY: `cpu_set_t` is initialized before it is passed to
    // `sched_getaffinity`, and libc's CPU helpers receive valid pointers.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) == 0 {
            let cpus = (0..libc::CPU_SETSIZE as usize)
                .filter(|cpu| libc::CPU_ISSET(*cpu, &set))
                .collect::<Vec<_>>();
            if !cpus.is_empty() {
                return cpus;
            }
        }
    }
    (0..std::thread::available_parallelism().map_or(1, usize::from)).collect()
}

#[cfg(not(target_os = "linux"))]
pub(super) fn available_cpu_ids() -> Vec<usize> {
    (0..std::thread::available_parallelism().map_or(1, usize::from)).collect()
}

#[cfg(target_os = "linux")]
pub(super) fn pin_current_thread(cpu_id: usize) {
    // SAFETY: the set is initialized and only the current thread's affinity is
    // changed. Failure is non-fatal because containers may forbid affinity.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu_id, &mut set);
        let _ = libc::pthread_setaffinity_np(
            libc::pthread_self(),
            std::mem::size_of::<libc::cpu_set_t>(),
            &set,
        );
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn pin_current_thread(_cpu_id: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_thread_can_be_pinned_to_its_assigned_cpu() {
        let cpu = available_cpu_ids()[0];
        let observed = std::thread::spawn(move || {
            pin_current_thread(cpu);
            // SAFETY: sched_getcpu has no preconditions and returns the CPU
            // currently executing this thread.
            unsafe { libc::sched_getcpu() }
        })
        .join()
        .unwrap();
        assert_eq!(observed, cpu as i32);
    }

    #[tokio::test]
    async fn affinity_is_stable_and_distributes_keys() {
        let temp = tempfile::tempdir().unwrap();
        let metadata = Arc::new(
            pepper_metadata::MetadataStore::open_or_create(temp.path().join("metadata.redb"))
                .unwrap(),
        );
        let store = Arc::new(
            BlockStore::open(
                metadata,
                &[pepper_config::StorageLocationConfig {
                    path: temp.path().to_path_buf(),
                    max_capacity_bytes: 1024 * 1024,
                }],
            )
            .unwrap(),
        );
        let config = FastPathConfig {
            workers: 2,
            control_cores: 1,
            pin_cpus: false,
            ..FastPathConfig::default()
        };
        let runtime =
            FastPathRuntime::start(&config, store, PlacementSnapshot::default(), None).unwrap();
        let first = runtime.owner_for(b"bucket\0key-a");
        assert_eq!(first, runtime.owner_for(b"bucket\0key-a"));
        let distinct = (0..128)
            .map(|index| runtime.owner_for(format!("key-{index}").as_bytes()))
            .collect::<HashSet<_>>();
        assert_eq!(distinct.len(), runtime.owner_count().min(2));
    }

    #[tokio::test]
    async fn unhealthy_owner_uses_deterministic_standby() {
        let temp = tempfile::tempdir().unwrap();
        let metadata = Arc::new(
            pepper_metadata::MetadataStore::open_or_create(temp.path().join("metadata.redb"))
                .unwrap(),
        );
        let store = Arc::new(
            BlockStore::open(
                metadata,
                &[pepper_config::StorageLocationConfig {
                    path: temp.path().to_path_buf(),
                    max_capacity_bytes: 1024 * 1024,
                }],
            )
            .unwrap(),
        );
        let config = FastPathConfig {
            workers: 2,
            control_cores: 1,
            pin_cpus: false,
            ..FastPathConfig::default()
        };
        let runtime =
            FastPathRuntime::start(&config, store, PlacementSnapshot::default(), None).unwrap();
        let affinity = b"bucket\0owner-failover";
        let preferred = runtime.owner_for(affinity);
        runtime.shutdown_owner(preferred).await;
        let response = runtime
            .execute(affinity, "/bucket/key", async {
                Ok(StatusCode::NO_CONTENT.into_response())
            })
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(runtime.totals().2, 1);
    }

    #[tokio::test]
    async fn skewed_key_load_remains_on_one_owner() {
        let temp = tempfile::tempdir().unwrap();
        let metadata = Arc::new(
            pepper_metadata::MetadataStore::open_or_create(temp.path().join("metadata.redb"))
                .unwrap(),
        );
        let store = Arc::new(
            BlockStore::open(
                metadata,
                &[pepper_config::StorageLocationConfig {
                    path: temp.path().to_path_buf(),
                    max_capacity_bytes: 1024 * 1024,
                }],
            )
            .unwrap(),
        );
        let config = FastPathConfig {
            workers: 2,
            control_cores: 1,
            pin_cpus: false,
            ..FastPathConfig::default()
        };
        let runtime =
            FastPathRuntime::start(&config, store, PlacementSnapshot::default(), None).unwrap();
        let affinity = b"hot-bucket\0one-hot-key";
        let owner = runtime.owner_for(affinity);
        for _ in 0..64 {
            runtime
                .execute(affinity, "/hot-bucket/one-hot-key", async {
                    Ok(StatusCode::NO_CONTENT.into_response())
                })
                .await
                .unwrap();
        }
        let snapshots = runtime.snapshots();
        assert_eq!(snapshots[owner].requests, 64);
        assert!(
            snapshots
                .iter()
                .enumerate()
                .all(|(index, snapshot)| index == owner || snapshot.requests == 0)
        );
    }
}
