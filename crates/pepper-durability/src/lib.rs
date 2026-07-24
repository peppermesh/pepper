// SPDX-License-Identifier: Apache-2.0

//! Bounded per-device group durability shared by block, extent, database, and
//! log products.

use pepper_observability::{
    CostMetric, OperationScope, OperationStage, WorkloadClass, current_operation, process_metrics,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OrderingKey(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DurabilityClass {
    Volatile,
    LocalBuffered,
    LocalDurable,
    ReplicaOne,
    ReplicaQuorum,
    ReplicaAllInSync,
    ErasureKOfN,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Priority {
    Control,
    Foreground,
    Replication,
    Repair,
    Compaction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AcknowledgmentPolicy {
    AfterRequestedDurability,
    AfterLocalBuffering,
}

/// A target must make all writes issued before `barrier` durable for its
/// physical device. Device-wide implementations allow independent files to
/// share exactly one barrier.
pub trait BarrierTarget: Send + Sync + 'static {
    fn device_id(&self) -> DeviceId;
    fn description(&self) -> &str;
    fn barrier(&self) -> Result<(), String>;
}

#[derive(Debug, Clone)]
pub struct DurabilityRequest {
    pub class: DurabilityClass,
    pub ordering: OrderingKey,
    pub maximum_group_delay: Duration,
    pub bytes: u64,
    pub priority: Priority,
    pub acknowledgment: AcknowledgmentPolicy,
    pub placement_epoch: Option<u64>,
    pub assignment_epoch: Option<u64>,
    pub deadline: Option<Instant>,
    pub cancellation: Cancellation,
    pub targets: Vec<Arc<dyn BarrierTarget>>,
}

impl DurabilityRequest {
    pub fn local_durable(
        ordering: OrderingKey,
        bytes: u64,
        targets: Vec<Arc<dyn BarrierTarget>>,
    ) -> Self {
        Self {
            class: DurabilityClass::LocalDurable,
            ordering,
            maximum_group_delay: Duration::from_micros(200),
            bytes,
            priority: Priority::Foreground,
            acknowledgment: AcknowledgmentPolicy::AfterRequestedDurability,
            placement_epoch: None,
            assignment_epoch: None,
            deadline: None,
            cancellation: Cancellation::default(),
            targets,
        }
    }
}

impl fmt::Debug for dyn BarrierTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BarrierTarget")
            .field("device_id", &self.device_id())
            .field("description", &self.description())
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BarrierProof {
    pub device_id: DeviceId,
    pub ordering: OrderingKey,
    pub barrier_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurabilityReceipt {
    pub class: DurabilityClass,
    pub bytes: u64,
    pub placement_epoch: Option<u64>,
    pub assignment_epoch: Option<u64>,
    pub barriers: Vec<BarrierProof>,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DurabilityError {
    #[error("durability scheduler is closed")]
    Closed,
    #[error("durability request was cancelled")]
    Cancelled,
    #[error("durability deadline elapsed")]
    DeadlineExceeded,
    #[error("durability request requires at least one device target")]
    MissingTarget,
    #[error("durability barrier failed on device {device_id:?}: {message}")]
    Barrier {
        device_id: DeviceId,
        message: String,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct SchedulerConfig {
    pub maximum_group_delay: Duration,
    pub maximum_batch_bytes: u64,
    pub maximum_requests: usize,
    pub queue_depth: usize,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            maximum_group_delay: Duration::from_micros(200),
            maximum_batch_bytes: 16 * 1024 * 1024,
            maximum_requests: 256,
            queue_depth: 1_024,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SchedulerSnapshot {
    pub submitted_requests: u64,
    pub completed_requests: u64,
    pub failed_requests: u64,
    pub grouped_batches: u64,
    pub grouped_requests: u64,
    pub submitted_bytes: u64,
    pub device_barriers: u64,
    pub queue_microseconds: u64,
    pub execution_microseconds: u64,
    pub cancellations: u64,
    pub deadline_expirations: u64,
}

#[derive(Default)]
struct SchedulerMetrics {
    submitted_requests: AtomicU64,
    completed_requests: AtomicU64,
    failed_requests: AtomicU64,
    grouped_batches: AtomicU64,
    grouped_requests: AtomicU64,
    submitted_bytes: AtomicU64,
    device_barriers: AtomicU64,
    queue_microseconds: AtomicU64,
    execution_microseconds: AtomicU64,
    cancellations: AtomicU64,
    deadline_expirations: AtomicU64,
}

impl SchedulerMetrics {
    fn snapshot(&self) -> SchedulerSnapshot {
        SchedulerSnapshot {
            submitted_requests: self.submitted_requests.load(Ordering::Relaxed),
            completed_requests: self.completed_requests.load(Ordering::Relaxed),
            failed_requests: self.failed_requests.load(Ordering::Relaxed),
            grouped_batches: self.grouped_batches.load(Ordering::Relaxed),
            grouped_requests: self.grouped_requests.load(Ordering::Relaxed),
            submitted_bytes: self.submitted_bytes.load(Ordering::Relaxed),
            device_barriers: self.device_barriers.load(Ordering::Relaxed),
            queue_microseconds: self.queue_microseconds.load(Ordering::Relaxed),
            execution_microseconds: self.execution_microseconds.load(Ordering::Relaxed),
            cancellations: self.cancellations.load(Ordering::Relaxed),
            deadline_expirations: self.deadline_expirations.load(Ordering::Relaxed),
        }
    }
}

struct QueuedRequest {
    request: DurabilityRequest,
    enqueued: Instant,
    operation: Option<Arc<OperationScope>>,
    response: mpsc::SyncSender<Result<DurabilityReceipt, DurabilityError>>,
}

#[derive(Clone)]
pub struct DurabilityScheduler {
    sender: mpsc::SyncSender<QueuedRequest>,
    metrics: Arc<SchedulerMetrics>,
}

impl DurabilityScheduler {
    pub fn start(
        thread_name: impl Into<String>,
        config: SchedulerConfig,
    ) -> Result<Self, DurabilityError> {
        let config = SchedulerConfig {
            maximum_requests: config.maximum_requests.max(1),
            maximum_batch_bytes: config.maximum_batch_bytes.max(1),
            queue_depth: config.queue_depth.max(1),
            ..config
        };
        let (sender, receiver) = mpsc::sync_channel(config.queue_depth);
        let metrics = Arc::new(SchedulerMetrics::default());
        let worker_metrics = Arc::clone(&metrics);
        std::thread::Builder::new()
            .name(thread_name.into())
            .spawn(move || scheduler_loop(receiver, config, worker_metrics))
            .map_err(|_| DurabilityError::Closed)?;
        Ok(Self { sender, metrics })
    }

    pub fn submit(&self, request: DurabilityRequest) -> Result<DurabilityReceipt, DurabilityError> {
        if request.targets.is_empty()
            && !matches!(
                request.class,
                DurabilityClass::Volatile | DurabilityClass::LocalBuffered
            )
        {
            return Err(DurabilityError::MissingTarget);
        }
        if request.cancellation.is_cancelled() {
            return Err(DurabilityError::Cancelled);
        }
        if request
            .deadline
            .is_some_and(|deadline| deadline <= Instant::now())
        {
            return Err(DurabilityError::DeadlineExceeded);
        }
        self.metrics
            .submitted_requests
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .submitted_bytes
            .fetch_add(request.bytes, Ordering::Relaxed);
        let (response, receiver) = mpsc::sync_channel(1);
        self.sender
            .send(QueuedRequest {
                request,
                enqueued: Instant::now(),
                operation: current_operation(),
                response,
            })
            .map_err(|_| DurabilityError::Closed)?;
        receiver.recv().map_err(|_| DurabilityError::Closed)?
    }

    pub fn snapshot(&self) -> SchedulerSnapshot {
        self.metrics.snapshot()
    }
}

fn scheduler_loop(
    receiver: mpsc::Receiver<QueuedRequest>,
    config: SchedulerConfig,
    metrics: Arc<SchedulerMetrics>,
) {
    let mut deferred = None;
    loop {
        let first = match deferred.take() {
            Some(request) => request,
            None => match receiver.recv() {
                Ok(request) => request,
                Err(_) => break,
            },
        };
        let mut batch = vec![first];
        let mut batch_bytes = batch[0].request.bytes;
        let mut group_deadline = Instant::now()
            + config
                .maximum_group_delay
                .min(batch[0].request.maximum_group_delay);
        let mut disconnected = false;
        while batch.len() < config.maximum_requests {
            let remaining = group_deadline.saturating_duration_since(Instant::now());
            match receiver.recv_timeout(remaining) {
                Ok(candidate) => {
                    if batch_bytes.saturating_add(candidate.request.bytes)
                        > config.maximum_batch_bytes
                    {
                        deferred = Some(candidate);
                        break;
                    }
                    batch_bytes = batch_bytes.saturating_add(candidate.request.bytes);
                    group_deadline = group_deadline.min(
                        Instant::now()
                            + config
                                .maximum_group_delay
                                .min(candidate.request.maximum_group_delay),
                    );
                    batch.push(candidate);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        execute_batch(&batch, &metrics);
        if disconnected {
            break;
        }
    }
}

fn execute_batch(batch: &[QueuedRequest], metrics: &SchedulerMetrics) {
    metrics.grouped_batches.fetch_add(1, Ordering::Relaxed);
    metrics
        .grouped_requests
        .fetch_add(batch.len() as u64, Ordering::Relaxed);
    let execution_started = Instant::now();
    let now = Instant::now();
    let mut groups = BTreeMap::<(DeviceId, OrderingKey), Arc<dyn BarrierTarget>>::new();
    for queued in batch {
        if queued.request.cancellation.is_cancelled()
            || queued
                .request
                .deadline
                .is_some_and(|deadline| deadline <= now)
        {
            continue;
        }
        for target in &queued.request.targets {
            groups
                .entry((target.device_id(), queued.request.ordering))
                .or_insert_with(|| Arc::clone(target));
        }
    }

    let mut outcomes = BTreeMap::new();
    for ((device, ordering), target) in groups {
        let outcome = target.barrier().map(|()| {
            let sequence = metrics
                .device_barriers
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1);
            BarrierProof {
                device_id: device,
                ordering,
                barrier_sequence: sequence,
            }
        });
        outcomes.insert((device, ordering), outcome);
    }
    let execution_micros = execution_started
        .elapsed()
        .as_micros()
        .min(u128::from(u64::MAX)) as u64;
    metrics
        .execution_microseconds
        .fetch_add(execution_micros, Ordering::Relaxed);

    for queued in batch {
        let queue_micros = queued
            .enqueued
            .elapsed()
            .as_micros()
            .min(u128::from(u64::MAX)) as u64;
        metrics
            .queue_microseconds
            .fetch_add(queue_micros, Ordering::Relaxed);
        let result = if queued.request.cancellation.is_cancelled() {
            metrics.cancellations.fetch_add(1, Ordering::Relaxed);
            Err(DurabilityError::Cancelled)
        } else if queued
            .request
            .deadline
            .is_some_and(|deadline| deadline <= Instant::now())
        {
            metrics.deadline_expirations.fetch_add(1, Ordering::Relaxed);
            Err(DurabilityError::DeadlineExceeded)
        } else {
            let mut proofs = Vec::with_capacity(queued.request.targets.len());
            let mut error = None;
            for target in &queued.request.targets {
                match outcomes.get(&(target.device_id(), queued.request.ordering)) {
                    Some(Ok(proof)) => {
                        if !proofs.contains(proof) {
                            proofs.push(proof.clone());
                        }
                    }
                    Some(Err(message)) => {
                        error = Some(DurabilityError::Barrier {
                            device_id: target.device_id(),
                            message: message.clone(),
                        });
                        break;
                    }
                    None => {
                        error = Some(DurabilityError::Closed);
                        break;
                    }
                }
            }
            match error {
                Some(error) => Err(error),
                None => Ok(DurabilityReceipt {
                    class: queued.request.class,
                    bytes: queued.request.bytes,
                    placement_epoch: queued.request.placement_epoch,
                    assignment_epoch: queued.request.assignment_epoch,
                    barriers: proofs,
                }),
            }
        };
        match &result {
            Ok(receipt) => {
                metrics.completed_requests.fetch_add(1, Ordering::Relaxed);
                if let Some(operation) = &queued.operation {
                    operation.observe(OperationStage::Durability);
                    operation.add(CostMetric::QueueMicroseconds, queue_micros);
                    operation.add(CostMetric::ExecutionMicroseconds, execution_micros);
                    operation.add(
                        CostMetric::DurabilityBarriers,
                        receipt.barriers.len() as u64,
                    );
                } else {
                    process_metrics().add(
                        WorkloadClass::Background,
                        CostMetric::DurabilityBarriers,
                        receipt.barriers.len() as u64,
                    );
                }
            }
            Err(_) => {
                metrics.failed_requests.fetch_add(1, Ordering::Relaxed);
            }
        }
        let _ = queued.response.send(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    struct CountingTarget {
        device: DeviceId,
        calls: AtomicU64,
    }

    impl BarrierTarget for CountingTarget {
        fn device_id(&self) -> DeviceId {
            self.device
        }

        fn description(&self) -> &str {
            "counting-device"
        }

        fn barrier(&self) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn concurrent_eligible_requests_share_one_device_barrier() {
        let scheduler = DurabilityScheduler::start(
            "durability-share-test",
            SchedulerConfig {
                maximum_group_delay: Duration::from_millis(20),
                ..SchedulerConfig::default()
            },
        )
        .unwrap();
        let target = Arc::new(CountingTarget {
            device: DeviceId(7),
            calls: AtomicU64::new(0),
        });
        let start = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let scheduler = scheduler.clone();
            let target = Arc::clone(&target);
            let start = Arc::clone(&start);
            workers.push(std::thread::spawn(move || {
                start.wait();
                scheduler
                    .submit(DurabilityRequest::local_durable(
                        OrderingKey(9),
                        4096,
                        vec![target],
                    ))
                    .unwrap()
            }));
        }
        start.wait();
        let first = workers.remove(0).join().unwrap();
        let second = workers.remove(0).join().unwrap();
        assert_eq!(first.barriers, second.barriers);
        assert_eq!(target.calls.load(Ordering::Relaxed), 1);
        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.grouped_requests, 2);
        assert_eq!(snapshot.device_barriers, 1);
    }

    #[test]
    fn ordering_classes_do_not_share_barriers() {
        let scheduler = DurabilityScheduler::start(
            "durability-ordering-test",
            SchedulerConfig {
                maximum_group_delay: Duration::ZERO,
                ..SchedulerConfig::default()
            },
        )
        .unwrap();
        let target = Arc::new(CountingTarget {
            device: DeviceId(1),
            calls: AtomicU64::new(0),
        });
        for ordering in [OrderingKey(1), OrderingKey(2)] {
            scheduler
                .submit(DurabilityRequest::local_durable(
                    ordering,
                    1,
                    vec![target.clone()],
                ))
                .unwrap();
        }
        assert_eq!(target.calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn cancellation_and_deadline_are_explicit() {
        let scheduler =
            DurabilityScheduler::start("durability-cancel-test", SchedulerConfig::default())
                .unwrap();
        let target = Arc::new(CountingTarget {
            device: DeviceId(1),
            calls: AtomicU64::new(0),
        });
        let cancellation = Cancellation::default();
        cancellation.cancel();
        let mut cancelled =
            DurabilityRequest::local_durable(OrderingKey(1), 1, vec![target.clone()]);
        cancelled.cancellation = cancellation;
        assert_eq!(
            scheduler.submit(cancelled).unwrap_err(),
            DurabilityError::Cancelled
        );

        let mut expired = DurabilityRequest::local_durable(OrderingKey(1), 1, vec![target]);
        expired.deadline = Some(Instant::now());
        assert_eq!(
            scheduler.submit(expired).unwrap_err(),
            DurabilityError::DeadlineExceeded
        );
    }
}
