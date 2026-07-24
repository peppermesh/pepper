// SPDX-License-Identifier: Apache-2.0

//! Product-neutral keyed execution and hierarchical resource governance.
//!
//! The dispatcher keeps its ordinary admission path free of mutexes and
//! semaphores. Fixed-cardinality, hash-sharded atomic budgets bound memory at
//! key, tenant, product, operation, worker, and process scopes. Workers retain
//! ordering for a key while scheduling unrelated keys concurrently.

use pepper_observability::WorkKey;
use std::{
    array,
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

const DRAINING: u64 = 1 << 63;
const WORKER_MASK: u64 = u32::MAX as u64;
const FAIR_CYCLE: [WorkClass; 13] = [
    WorkClass::Control,
    WorkClass::Control,
    WorkClass::Control,
    WorkClass::Control,
    WorkClass::Control,
    WorkClass::Control,
    WorkClass::Control,
    WorkClass::Control,
    WorkClass::Foreground,
    WorkClass::Foreground,
    WorkClass::Foreground,
    WorkClass::Foreground,
    WorkClass::Background,
];

/// Scheduling class. Reservations ensure lower classes cannot occupy every
/// execution slot, while weighted round-robin prevents starvation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(usize)]
pub enum WorkClass {
    Control = 0,
    Foreground = 1,
    Background = 2,
}

impl WorkClass {
    const fn index(self) -> usize {
        self as usize
    }
}

/// Stable bounded-cardinality identifier for a resource-governor scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopeId(u64);

impl ScopeId {
    pub const UNKNOWN: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn from_bytes(value: &[u8]) -> Self {
        let key = WorkKey::from_bytes(value);
        Self(u64::from_le_bytes(
            key.as_bytes()[..8].try_into().expect("fixed work key"),
        ))
    }
}

/// Admission metadata supplied by every operation.
#[derive(Debug, Clone, Copy)]
pub struct Admission {
    pub class: WorkClass,
    pub bytes: u64,
    pub requests: u64,
    pub tenant: ScopeId,
    pub product: ScopeId,
    pub operation: ScopeId,
    pub deadline: Instant,
}

impl Admission {
    pub fn foreground(bytes: u64, deadline: Instant) -> Self {
        Self {
            class: WorkClass::Foreground,
            bytes,
            requests: 1,
            tenant: ScopeId::UNKNOWN,
            product: ScopeId::UNKNOWN,
            operation: ScopeId::UNKNOWN,
            deadline,
        }
    }
}

/// A request/byte limit. `u64::MAX` disables that dimension.
#[derive(Debug, Clone, Copy)]
pub struct BudgetLimit {
    pub requests: u64,
    pub bytes: u64,
}

impl BudgetLimit {
    pub const UNLIMITED: Self = Self {
        requests: u64::MAX,
        bytes: u64::MAX,
    };
}

/// Runtime limits. Slot counts use conservative hash sharding: collisions can
/// reduce available capacity, but can never exceed a configured bound.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub queue_depth_per_worker: usize,
    pub active_per_worker: usize,
    pub reserved_control_slots: usize,
    pub reserved_foreground_slots: usize,
    pub key_slots: usize,
    pub tenant_slots: usize,
    pub product_slots: usize,
    pub operation_slots: usize,
    pub key_limit: BudgetLimit,
    pub tenant_limit: BudgetLimit,
    pub product_limit: BudgetLimit,
    pub operation_limit: BudgetLimit,
    pub worker_limit: BudgetLimit,
    pub global_limit: BudgetLimit,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            queue_depth_per_worker: 1_024,
            active_per_worker: 32,
            reserved_control_slots: 1,
            reserved_foreground_slots: 1,
            key_slots: 4_096,
            tenant_slots: 1_024,
            product_slots: 64,
            operation_slots: 256,
            key_limit: BudgetLimit {
                requests: 64,
                bytes: 64 * 1024 * 1024,
            },
            tenant_limit: BudgetLimit {
                requests: 4_096,
                bytes: 2 * 1024 * 1024 * 1024,
            },
            product_limit: BudgetLimit {
                requests: 16_384,
                bytes: 8 * 1024 * 1024 * 1024,
            },
            operation_limit: BudgetLimit {
                requests: 4_096,
                bytes: 2 * 1024 * 1024 * 1024,
            },
            worker_limit: BudgetLimit {
                requests: 1_024,
                bytes: 1024 * 1024 * 1024,
            },
            global_limit: BudgetLimit {
                requests: 65_536,
                bytes: 32 * 1024 * 1024 * 1024,
            },
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigError {
    #[error("keyed runtime requires at least one worker")]
    NoWorkers,
    #[error("{0} must be greater than zero")]
    Zero(&'static str),
    #[error("reserved execution slots must leave one background slot")]
    InvalidReservations,
    #[error("per-key request limit must be lower than a worker queue depth")]
    KeyCanExhaustWorkerQueue,
}

impl RuntimeConfig {
    fn validate(&self, workers: usize) -> Result<(), ConfigError> {
        if workers == 0 {
            return Err(ConfigError::NoWorkers);
        }
        for (name, value) in [
            ("queue_depth_per_worker", self.queue_depth_per_worker),
            ("active_per_worker", self.active_per_worker),
            ("key_slots", self.key_slots),
            ("tenant_slots", self.tenant_slots),
            ("product_slots", self.product_slots),
            ("operation_slots", self.operation_slots),
        ] {
            if value == 0 {
                return Err(ConfigError::Zero(name));
            }
        }
        if self
            .reserved_control_slots
            .saturating_add(self.reserved_foreground_slots)
            >= self.active_per_worker
        {
            return Err(ConfigError::InvalidReservations);
        }
        if self.key_limit.requests >= self.queue_depth_per_worker as u64 {
            return Err(ConfigError::KeyCanExhaustWorkerQueue);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DispatchError {
    #[error("admission deadline elapsed")]
    Deadline,
    #[error("the selected key is draining for ownership movement")]
    KeyDraining,
    #[error("{0:?} resource budget is exhausted")]
    BudgetExhausted(BudgetScope),
    #[error("worker admission queue is closed")]
    WorkerClosed,
    #[error("runtime is shutting down")]
    ShuttingDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetScope {
    Key,
    Tenant,
    Product,
    Operation,
    Worker,
    Global,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RemapError {
    #[error("target worker is out of range")]
    InvalidWorker,
    #[error("key slot is already draining")]
    AlreadyDraining,
    #[error("ownership movement deadline elapsed")]
    Deadline,
    #[error("worker stopped during ownership movement")]
    WorkerClosed,
}

/// Optional physical placement metadata. Affinity is an optimization only;
/// the stable worker ID remains the correctness boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerDescriptor {
    pub id: usize,
    pub cpu_affinity: Option<usize>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkerSnapshot {
    pub queued: u64,
    pub active: u64,
    pub queued_by_class: [u64; 3],
    pub active_by_class: [u64; 3],
    pub completed: u64,
    pub queue_microseconds: u64,
    pub service_microseconds: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    pub dispatched: u64,
    pub rejected: u64,
    pub key_budget_rejections: u64,
    pub remaps: u64,
    pub draining_slots: u64,
}

struct Usage {
    requests: AtomicU64,
    bytes: AtomicU64,
}

impl Usage {
    const fn new() -> Self {
        Self {
            requests: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        }
    }

    fn reserve(&self, amount: u64, bytes: u64, limit: BudgetLimit) -> bool {
        if !reserve_atomic(&self.requests, amount, limit.requests) {
            return false;
        }
        if !reserve_atomic(&self.bytes, bytes, limit.bytes) {
            self.requests.fetch_sub(amount, Ordering::AcqRel);
            return false;
        }
        true
    }

    fn release(&self, amount: u64, bytes: u64) {
        self.bytes.fetch_sub(bytes, Ordering::AcqRel);
        self.requests.fetch_sub(amount, Ordering::AcqRel);
    }
}

fn reserve_atomic(counter: &AtomicU64, amount: u64, limit: u64) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let Some(next) = current.checked_add(amount) else {
            return false;
        };
        if next > limit {
            return false;
        }
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

struct BudgetTable {
    key: Vec<Usage>,
    tenant: Vec<Usage>,
    product: Vec<Usage>,
    operation: Vec<Usage>,
    worker: Vec<Usage>,
    global: Usage,
    config: RuntimeConfig,
}

#[derive(Clone, Copy)]
struct Reservation {
    scope: BudgetScope,
    index: usize,
}

struct AdmissionPermit {
    table: Arc<BudgetTable>,
    reservations: Vec<Reservation>,
    requests: u64,
    bytes: u64,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        for reservation in self.reservations.iter().rev() {
            self.table
                .usage(reservation.scope, reservation.index)
                .release(self.requests, self.bytes);
        }
    }
}

impl BudgetTable {
    fn new(config: RuntimeConfig, workers: usize) -> Self {
        fn usages(length: usize) -> Vec<Usage> {
            (0..length).map(|_| Usage::new()).collect()
        }
        Self {
            key: usages(config.key_slots),
            tenant: usages(config.tenant_slots),
            product: usages(config.product_slots),
            operation: usages(config.operation_slots),
            worker: usages(workers),
            global: Usage::new(),
            config,
        }
    }

    fn usage(&self, scope: BudgetScope, index: usize) -> &Usage {
        match scope {
            BudgetScope::Key => &self.key[index],
            BudgetScope::Tenant => &self.tenant[index],
            BudgetScope::Product => &self.product[index],
            BudgetScope::Operation => &self.operation[index],
            BudgetScope::Worker => &self.worker[index],
            BudgetScope::Global => &self.global,
        }
    }

    fn limit(&self, scope: BudgetScope) -> BudgetLimit {
        match scope {
            BudgetScope::Key => self.config.key_limit,
            BudgetScope::Tenant => self.config.tenant_limit,
            BudgetScope::Product => self.config.product_limit,
            BudgetScope::Operation => self.config.operation_limit,
            BudgetScope::Worker => self.config.worker_limit,
            BudgetScope::Global => self.config.global_limit,
        }
    }

    fn reserve(
        self: &Arc<Self>,
        key_slot: usize,
        worker: usize,
        admission: Admission,
    ) -> Result<AdmissionPermit, BudgetScope> {
        let scopes = [
            Reservation {
                scope: BudgetScope::Key,
                index: key_slot,
            },
            Reservation {
                scope: BudgetScope::Tenant,
                index: shard(admission.tenant.0, self.tenant.len()),
            },
            Reservation {
                scope: BudgetScope::Product,
                index: shard(admission.product.0, self.product.len()),
            },
            Reservation {
                scope: BudgetScope::Operation,
                index: shard(admission.operation.0, self.operation.len()),
            },
            Reservation {
                scope: BudgetScope::Worker,
                index: worker,
            },
            Reservation {
                scope: BudgetScope::Global,
                index: 0,
            },
        ];
        let mut acquired: Vec<Reservation> = Vec::with_capacity(scopes.len());
        for reservation in scopes {
            if !self.usage(reservation.scope, reservation.index).reserve(
                admission.requests,
                admission.bytes,
                self.limit(reservation.scope),
            ) {
                for prior in acquired.iter().rev() {
                    self.usage(prior.scope, prior.index)
                        .release(admission.requests, admission.bytes);
                }
                return Err(reservation.scope);
            }
            acquired.push(reservation);
        }
        Ok(AdmissionPermit {
            table: self.clone(),
            reservations: acquired,
            requests: admission.requests,
            bytes: admission.bytes,
        })
    }
}

fn shard(value: u64, slots: usize) -> usize {
    (value as usize) % slots
}

struct RuntimeMetrics {
    dispatched: AtomicU64,
    rejected: AtomicU64,
    key_budget_rejections: AtomicU64,
    remaps: AtomicU64,
    draining_slots: AtomicU64,
}

impl RuntimeMetrics {
    const fn new() -> Self {
        Self {
            dispatched: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            key_budget_rejections: AtomicU64::new(0),
            remaps: AtomicU64::new(0),
            draining_slots: AtomicU64::new(0),
        }
    }
}

struct WorkerMetrics {
    queued: AtomicU64,
    active: AtomicU64,
    queued_by_class: [AtomicU64; 3],
    active_by_class: [AtomicU64; 3],
    completed: AtomicU64,
    queue_microseconds: AtomicU64,
    service_microseconds: AtomicU64,
}

impl WorkerMetrics {
    fn new() -> Self {
        Self {
            queued: AtomicU64::new(0),
            active: AtomicU64::new(0),
            queued_by_class: array::from_fn(|_| AtomicU64::new(0)),
            active_by_class: array::from_fn(|_| AtomicU64::new(0)),
            completed: AtomicU64::new(0),
            queue_microseconds: AtomicU64::new(0),
            service_microseconds: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> WorkerSnapshot {
        WorkerSnapshot {
            queued: self.queued.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
            queued_by_class: array::from_fn(|index| {
                self.queued_by_class[index].load(Ordering::Relaxed)
            }),
            active_by_class: array::from_fn(|index| {
                self.active_by_class[index].load(Ordering::Relaxed)
            }),
            completed: self.completed.load(Ordering::Relaxed),
            queue_microseconds: self.queue_microseconds.load(Ordering::Relaxed),
            service_microseconds: self.service_microseconds.load(Ordering::Relaxed),
        }
    }
}

struct Job<T> {
    key: WorkKey,
    key_slot: usize,
    admission: Admission,
    enqueued: Instant,
    item: T,
    _permit: AdmissionPermit,
}

enum WorkerMessage<T> {
    Job(Job<T>),
    DrainBarrier {
        key_slot: usize,
        response: oneshot::Sender<()>,
    },
    Shutdown,
}

struct Inner<T> {
    senders: Vec<mpsc::Sender<WorkerMessage<T>>>,
    descriptors: Vec<WorkerDescriptor>,
    worker_metrics: Vec<Arc<WorkerMetrics>>,
    budgets: Arc<BudgetTable>,
    mapping: Vec<AtomicU64>,
    dispatch_inflight: Vec<AtomicUsize>,
    metrics: RuntimeMetrics,
    shutting_down: AtomicBool,
}

/// Cloneable, product-neutral dispatcher. It contains no product request type
/// beyond the generic `T` envelope selected by its caller.
pub struct KeyedDispatcher<T> {
    inner: Arc<Inner<T>>,
}

impl<T> Clone for KeyedDispatcher<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// One worker-side receiver. Products decide where the worker future runs and
/// may therefore apply optional CPU affinity without making it a correctness
/// dependency.
pub struct KeyedWorker<T> {
    descriptor: WorkerDescriptor,
    receiver: mpsc::Receiver<WorkerMessage<T>>,
    metrics: Arc<WorkerMetrics>,
    config: RuntimeConfig,
}

/// Builds a dispatcher and exactly one receiver for each worker descriptor.
pub fn build<T: Send + 'static>(
    config: RuntimeConfig,
    descriptors: Vec<WorkerDescriptor>,
) -> Result<(KeyedDispatcher<T>, Vec<KeyedWorker<T>>), ConfigError> {
    config.validate(descriptors.len())?;
    let mut senders = Vec::with_capacity(descriptors.len());
    let mut receivers = Vec::with_capacity(descriptors.len());
    let mut worker_metrics = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors.iter().copied() {
        let (sender, receiver) = mpsc::channel(config.queue_depth_per_worker);
        let metrics = Arc::new(WorkerMetrics::new());
        senders.push(sender);
        receivers.push(KeyedWorker {
            descriptor,
            receiver,
            metrics: metrics.clone(),
            config: config.clone(),
        });
        worker_metrics.push(metrics);
    }
    let mapping = (0..config.key_slots).map(|_| AtomicU64::new(0)).collect();
    let dispatch_inflight = (0..config.key_slots).map(|_| AtomicUsize::new(0)).collect();
    let inner = Arc::new(Inner {
        senders,
        descriptors,
        worker_metrics,
        budgets: Arc::new(BudgetTable::new(config, receivers.len())),
        mapping,
        dispatch_inflight,
        metrics: RuntimeMetrics::new(),
        shutting_down: AtomicBool::new(false),
    });
    Ok((KeyedDispatcher { inner }, receivers))
}

impl<T: Send + 'static> KeyedDispatcher<T> {
    pub fn worker_count(&self) -> usize {
        self.inner.senders.len()
    }

    pub fn descriptor(&self, worker: usize) -> Option<WorkerDescriptor> {
        self.inner.descriptors.get(worker).copied()
    }

    pub fn owner_for(&self, key: WorkKey) -> usize {
        let slot = key_slot(key, self.inner.mapping.len());
        owner_from_state(
            self.inner.mapping[slot].load(Ordering::Acquire),
            key,
            self.worker_count(),
        )
    }

    pub async fn dispatch(
        &self,
        key: WorkKey,
        admission: Admission,
        item: T,
    ) -> Result<(), DispatchError> {
        if self.inner.shutting_down.load(Ordering::Acquire) {
            self.reject();
            return Err(DispatchError::ShuttingDown);
        }
        if admission.deadline <= Instant::now() {
            self.reject();
            return Err(DispatchError::Deadline);
        }
        let slot = key_slot(key, self.inner.mapping.len());
        self.inner.dispatch_inflight[slot].fetch_add(1, Ordering::AcqRel);
        let state = self.inner.mapping[slot].load(Ordering::Acquire);
        if state & DRAINING != 0 {
            self.inner.dispatch_inflight[slot].fetch_sub(1, Ordering::AcqRel);
            self.reject();
            return Err(DispatchError::KeyDraining);
        }
        let worker = owner_from_state(state, key, self.worker_count());
        let permit = match self.inner.budgets.reserve(slot, worker, admission) {
            Ok(permit) => permit,
            Err(scope) => {
                self.inner.dispatch_inflight[slot].fetch_sub(1, Ordering::AcqRel);
                self.reject();
                if scope == BudgetScope::Key {
                    self.inner
                        .metrics
                        .key_budget_rejections
                        .fetch_add(1, Ordering::Relaxed);
                }
                return Err(DispatchError::BudgetExhausted(scope));
            }
        };
        let message = WorkerMessage::Job(Job {
            key,
            key_slot: slot,
            admission,
            enqueued: Instant::now(),
            item,
            _permit: permit,
        });
        let send = tokio::time::timeout_at(
            tokio::time::Instant::from_std(admission.deadline),
            self.inner.senders[worker].send(message),
        )
        .await;
        self.inner.dispatch_inflight[slot].fetch_sub(1, Ordering::AcqRel);
        match send {
            Ok(Ok(())) => {
                self.inner
                    .metrics
                    .dispatched
                    .fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Ok(Err(_)) => {
                self.reject();
                Err(DispatchError::WorkerClosed)
            }
            Err(_) => {
                self.reject();
                Err(DispatchError::Deadline)
            }
        }
    }

    /// Compatibility adapter for callers that do not yet supply resource
    /// dimensions. It still receives keyed ordering and bounded defaults.
    pub async fn dispatch_compat(
        &self,
        key: WorkKey,
        deadline: Instant,
        item: T,
    ) -> Result<(), DispatchError> {
        self.dispatch(key, Admission::foreground(0, deadline), item)
            .await
    }

    pub async fn drain_and_remap(
        &self,
        key: WorkKey,
        target_worker: usize,
        deadline: Instant,
    ) -> Result<(), RemapError> {
        if target_worker >= self.worker_count() {
            return Err(RemapError::InvalidWorker);
        }
        let slot = key_slot(key, self.inner.mapping.len());
        let mapping = &self.inner.mapping[slot];
        let mut state = mapping.load(Ordering::Acquire);
        loop {
            if state & DRAINING != 0 {
                return Err(RemapError::AlreadyDraining);
            }
            let draining = state | DRAINING;
            match mapping.compare_exchange(state, draining, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(observed) => state = observed,
            }
        }
        self.inner
            .metrics
            .draining_slots
            .fetch_add(1, Ordering::Relaxed);
        let old_worker = owner_from_state(state, key, self.worker_count());
        let result = async {
            while self.inner.dispatch_inflight[slot].load(Ordering::Acquire) != 0 {
                if Instant::now() >= deadline {
                    return Err(RemapError::Deadline);
                }
                tokio::task::yield_now().await;
            }
            let (response, receive) = oneshot::channel();
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.inner.senders[old_worker].send(WorkerMessage::DrainBarrier {
                    key_slot: slot,
                    response,
                }),
            )
            .await
            .map_err(|_| RemapError::Deadline)?
            .map_err(|_| RemapError::WorkerClosed)?;
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), receive)
                .await
                .map_err(|_| RemapError::Deadline)?
                .map_err(|_| RemapError::WorkerClosed)?;
            Ok(())
        }
        .await;
        if result.is_ok() {
            mapping.store((target_worker as u64) + 1, Ordering::Release);
            self.inner.metrics.remaps.fetch_add(1, Ordering::Relaxed);
        } else {
            mapping.store(state, Ordering::Release);
        }
        self.inner
            .metrics
            .draining_slots
            .fetch_sub(1, Ordering::Relaxed);
        result
    }

    pub async fn shutdown(&self) {
        if self.inner.shutting_down.swap(true, Ordering::AcqRel) {
            return;
        }
        for sender in &self.inner.senders {
            let _ = sender.send(WorkerMessage::Shutdown).await;
        }
    }

    pub fn try_shutdown(&self) {
        if self.inner.shutting_down.swap(true, Ordering::AcqRel) {
            return;
        }
        for sender in &self.inner.senders {
            let _ = sender.try_send(WorkerMessage::Shutdown);
        }
    }

    pub async fn shutdown_worker(&self, worker: usize) -> Result<(), RemapError> {
        let Some(sender) = self.inner.senders.get(worker) else {
            return Err(RemapError::InvalidWorker);
        };
        sender
            .send(WorkerMessage::Shutdown)
            .await
            .map_err(|_| RemapError::WorkerClosed)
    }

    pub fn snapshot(&self) -> RuntimeSnapshot {
        RuntimeSnapshot {
            dispatched: self.inner.metrics.dispatched.load(Ordering::Relaxed),
            rejected: self.inner.metrics.rejected.load(Ordering::Relaxed),
            key_budget_rejections: self
                .inner
                .metrics
                .key_budget_rejections
                .load(Ordering::Relaxed),
            remaps: self.inner.metrics.remaps.load(Ordering::Relaxed),
            draining_slots: self.inner.metrics.draining_slots.load(Ordering::Relaxed),
        }
    }

    pub fn worker_snapshot(&self, worker: usize) -> Option<WorkerSnapshot> {
        self.inner
            .worker_metrics
            .get(worker)
            .map(|metrics| metrics.snapshot())
    }

    fn reject(&self) {
        self.inner.metrics.rejected.fetch_add(1, Ordering::Relaxed);
    }
}

fn key_u64(key: WorkKey) -> u64 {
    u64::from_le_bytes(
        key.as_bytes()[..8]
            .try_into()
            .expect("work key always contains 16 bytes"),
    )
}

fn key_slot(key: WorkKey, slots: usize) -> usize {
    shard(key_u64(key), slots)
}

fn owner_from_state(state: u64, key: WorkKey, workers: usize) -> usize {
    let override_worker = state & WORKER_MASK;
    if override_worker == 0 {
        shard(key_u64(key), workers)
    } else {
        ((override_worker - 1) as usize) % workers
    }
}

struct KeyQueue<T> {
    key_slot: usize,
    jobs: VecDeque<Job<T>>,
}

struct Completion {
    key: WorkKey,
    class: WorkClass,
    queue_micros: u64,
    service_micros: u64,
}

impl<T: Send + 'static> KeyedWorker<T> {
    pub fn descriptor(&self) -> WorkerDescriptor {
        self.descriptor
    }

    pub async fn run<H, F>(mut self, handler: H)
    where
        H: Fn(T) -> F + Clone + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let mut keys: HashMap<WorkKey, KeyQueue<T>> = HashMap::new();
        let mut active_keys = HashSet::new();
        let mut ready: [VecDeque<WorkKey>; 3] = array::from_fn(|_| VecDeque::new());
        let mut active_by_class = [0usize; 3];
        let mut tasks = JoinSet::new();
        let mut barriers: HashMap<usize, Vec<oneshot::Sender<()>>> = HashMap::new();
        let mut fairness_cursor = 0usize;
        let mut shutting_down = false;

        loop {
            while tasks.len() < self.config.active_per_worker {
                let Some((key, job)) = take_ready(
                    &mut keys,
                    &active_keys,
                    &mut ready,
                    &active_by_class,
                    &self.config,
                    &mut fairness_cursor,
                ) else {
                    break;
                };
                active_keys.insert(key);
                active_by_class[job.admission.class.index()] += 1;
                self.metrics.queued.fetch_sub(1, Ordering::Relaxed);
                self.metrics.queued_by_class[job.admission.class.index()]
                    .fetch_sub(1, Ordering::Relaxed);
                self.metrics.active.fetch_add(1, Ordering::Relaxed);
                self.metrics.active_by_class[job.admission.class.index()]
                    .fetch_add(1, Ordering::Relaxed);
                let handler = handler.clone();
                tasks.spawn(async move {
                    let queue_micros = micros(job.enqueued.elapsed());
                    let started = Instant::now();
                    let Job {
                        admission,
                        item,
                        _permit,
                        ..
                    } = job;
                    handler(item).await;
                    drop(_permit);
                    Completion {
                        key,
                        class: admission.class,
                        queue_micros,
                        service_micros: micros(started.elapsed()),
                    }
                });
            }

            notify_drained(&keys, &active_keys, &mut barriers);
            if shutting_down && keys.values().all(|queue| queue.jobs.is_empty()) && tasks.is_empty()
            {
                break;
            }

            tokio::select! {
                biased;
                completion = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Ok(completion)) = completion {
                        active_keys.remove(&completion.key);
                        active_by_class[completion.class.index()] =
                            active_by_class[completion.class.index()].saturating_sub(1);
                        self.metrics.active.fetch_sub(1, Ordering::Relaxed);
                        self.metrics.active_by_class[completion.class.index()]
                            .fetch_sub(1, Ordering::Relaxed);
                        self.metrics.completed.fetch_add(1, Ordering::Relaxed);
                        self.metrics.queue_microseconds
                            .fetch_add(completion.queue_micros, Ordering::Relaxed);
                        self.metrics.service_microseconds
                            .fetch_add(completion.service_micros, Ordering::Relaxed);
                        make_ready(&keys, &active_keys, &mut ready, completion.key);
                        if keys.get(&completion.key).is_some_and(|queue| queue.jobs.is_empty()) {
                            keys.remove(&completion.key);
                        }
                    }
                }
                message = self.receiver.recv(), if !shutting_down => {
                    match message {
                        Some(WorkerMessage::Job(job)) => {
                            let key = job.key;
                            let class = job.admission.class;
                            let queue = keys.entry(key).or_insert_with(|| KeyQueue {
                                key_slot: job.key_slot,
                                jobs: VecDeque::new(),
                            });
                            let was_empty = queue.jobs.is_empty();
                            queue.jobs.push_back(job);
                            self.metrics.queued.fetch_add(1, Ordering::Relaxed);
                            self.metrics.queued_by_class[class.index()]
                                .fetch_add(1, Ordering::Relaxed);
                            if was_empty && !active_keys.contains(&key) {
                                ready[class.index()].push_back(key);
                            }
                        }
                        Some(WorkerMessage::DrainBarrier { key_slot, response }) => {
                            barriers.entry(key_slot).or_default().push(response);
                        }
                        Some(WorkerMessage::Shutdown) | None => {
                            shutting_down = true;
                        }
                    }
                }
            }
        }
        notify_drained(&keys, &active_keys, &mut barriers);
    }
}

fn class_limit(class: WorkClass, config: &RuntimeConfig) -> usize {
    match class {
        WorkClass::Control => config.active_per_worker,
        WorkClass::Foreground => config
            .active_per_worker
            .saturating_sub(config.reserved_control_slots),
        WorkClass::Background => config
            .active_per_worker
            .saturating_sub(config.reserved_control_slots)
            .saturating_sub(config.reserved_foreground_slots),
    }
    .max(1)
}

fn take_ready<T>(
    keys: &mut HashMap<WorkKey, KeyQueue<T>>,
    active_keys: &HashSet<WorkKey>,
    ready: &mut [VecDeque<WorkKey>; 3],
    active_by_class: &[usize; 3],
    config: &RuntimeConfig,
    fairness_cursor: &mut usize,
) -> Option<(WorkKey, Job<T>)> {
    for _ in 0..FAIR_CYCLE.len() {
        let class = FAIR_CYCLE[*fairness_cursor % FAIR_CYCLE.len()];
        *fairness_cursor = (*fairness_cursor).wrapping_add(1);
        if active_by_class[class.index()] >= class_limit(class, config) {
            continue;
        }
        while let Some(key) = ready[class.index()].pop_front() {
            if active_keys.contains(&key) {
                continue;
            }
            let Some(queue) = keys.get_mut(&key) else {
                continue;
            };
            if queue.jobs.front().map(|job| job.admission.class) != Some(class) {
                continue;
            }
            let job = queue.jobs.pop_front().expect("front was present");
            return Some((key, job));
        }
    }
    None
}

fn make_ready<T>(
    keys: &HashMap<WorkKey, KeyQueue<T>>,
    active_keys: &HashSet<WorkKey>,
    ready: &mut [VecDeque<WorkKey>; 3],
    key: WorkKey,
) {
    if active_keys.contains(&key) {
        return;
    }
    if let Some(class) = keys
        .get(&key)
        .and_then(|queue| queue.jobs.front())
        .map(|job| job.admission.class)
    {
        ready[class.index()].push_back(key);
    }
}

fn notify_drained<T>(
    keys: &HashMap<WorkKey, KeyQueue<T>>,
    active_keys: &HashSet<WorkKey>,
    barriers: &mut HashMap<usize, Vec<oneshot::Sender<()>>>,
) {
    barriers.retain(|slot, waiters| {
        let busy = keys.iter().any(|(key, queue)| {
            queue.key_slot == *slot && (!queue.jobs.is_empty() || active_keys.contains(key))
        });
        if busy {
            true
        } else {
            for waiter in waiters.drain(..) {
                let _ = waiter.send(());
            }
            false
        }
    });
}

fn micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn test_config() -> RuntimeConfig {
        RuntimeConfig {
            queue_depth_per_worker: 32,
            active_per_worker: 3,
            key_slots: 64,
            tenant_slots: 16,
            product_slots: 8,
            operation_slots: 8,
            key_limit: BudgetLimit {
                requests: 4,
                bytes: 4_096,
            },
            ..RuntimeConfig::default()
        }
    }

    fn admission(class: WorkClass, bytes: u64) -> Admission {
        Admission {
            class,
            bytes,
            requests: 1,
            tenant: ScopeId::new(1),
            product: ScopeId::new(2),
            operation: ScopeId::new(3),
            deadline: Instant::now() + Duration::from_secs(2),
        }
    }

    #[tokio::test]
    async fn preserves_in_key_order_with_cross_key_concurrency() {
        let (dispatcher, mut workers) = build(
            test_config(),
            vec![WorkerDescriptor {
                id: 0,
                cpu_affinity: None,
            }],
        )
        .unwrap();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let worker_observed = observed.clone();
        let worker = workers.pop().unwrap();
        let task = tokio::spawn(worker.run(move |(key, value, delay): (u8, u8, u64)| {
            let observed = worker_observed.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                observed.lock().unwrap().push((key, value));
            }
        }));
        let one = WorkKey::from_bytes(b"one");
        let two = WorkKey::from_bytes(b"two");
        dispatcher
            .dispatch(one, admission(WorkClass::Foreground, 1), (1, 1, 30))
            .await
            .unwrap();
        dispatcher
            .dispatch(one, admission(WorkClass::Control, 1), (1, 2, 0))
            .await
            .unwrap();
        dispatcher
            .dispatch(two, admission(WorkClass::Foreground, 1), (2, 1, 0))
            .await
            .unwrap();
        for _ in 0..100 {
            if observed.lock().unwrap().len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        dispatcher.shutdown().await;
        task.await.unwrap();
        let values = observed.lock().unwrap().clone();
        let one_values = values
            .iter()
            .filter(|(key, _)| *key == 1)
            .map(|(_, value)| *value)
            .collect::<Vec<_>>();
        assert_eq!(one_values, vec![1, 2]);
        assert_eq!(values.first(), Some(&(2, 1)));
    }

    #[tokio::test]
    async fn hot_key_is_bounded_without_consuming_other_key_budget() {
        let (dispatcher, mut workers) = build(
            test_config(),
            vec![WorkerDescriptor {
                id: 0,
                cpu_affinity: None,
            }],
        )
        .unwrap();
        let task = tokio::spawn(workers.pop().unwrap().run(move |_: ()| async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }));
        let hot = WorkKey::from_bytes(b"hot");
        for _ in 0..4 {
            dispatcher
                .dispatch(hot, admission(WorkClass::Background, 1), ())
                .await
                .unwrap();
        }
        assert_eq!(
            dispatcher
                .dispatch(hot, admission(WorkClass::Background, 1), ())
                .await,
            Err(DispatchError::BudgetExhausted(BudgetScope::Key))
        );
        dispatcher
            .dispatch(
                WorkKey::from_bytes(b"cold"),
                admission(WorkClass::Control, 1),
                (),
            )
            .await
            .unwrap();
        assert_eq!(dispatcher.snapshot().key_budget_rejections, 1);
        dispatcher.shutdown().await;
        task.await.unwrap();
    }

    #[tokio::test]
    async fn hierarchical_tenant_budget_is_independent_and_released() {
        let mut config = test_config();
        config.tenant_limit = BudgetLimit {
            requests: 2,
            bytes: 4_096,
        };
        let (dispatcher, mut workers) = build(
            config,
            vec![WorkerDescriptor {
                id: 0,
                cpu_affinity: None,
            }],
        )
        .unwrap();
        let task = tokio::spawn(workers.pop().unwrap().run(move |_: ()| async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }));
        let mut same_tenant = admission(WorkClass::Foreground, 1);
        same_tenant.tenant = ScopeId::new(7);
        for key in [b"tenant-a-1".as_slice(), b"tenant-a-2".as_slice()] {
            dispatcher
                .dispatch(WorkKey::from_bytes(key), same_tenant, ())
                .await
                .unwrap();
        }
        assert_eq!(
            dispatcher
                .dispatch(WorkKey::from_bytes(b"tenant-a-3"), same_tenant, (),)
                .await,
            Err(DispatchError::BudgetExhausted(BudgetScope::Tenant))
        );
        let mut other_tenant = same_tenant;
        other_tenant.tenant = ScopeId::new(8);
        dispatcher
            .dispatch(WorkKey::from_bytes(b"tenant-b-1"), other_tenant, ())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        dispatcher
            .dispatch(
                WorkKey::from_bytes(b"tenant-a-after-release"),
                same_tenant,
                (),
            )
            .await
            .unwrap();
        dispatcher.shutdown().await;
        task.await.unwrap();
    }

    #[tokio::test]
    async fn control_slot_survives_background_saturation() {
        let (dispatcher, mut workers) = build(
            test_config(),
            vec![WorkerDescriptor {
                id: 0,
                cpu_affinity: None,
            }],
        )
        .unwrap();
        let (completed, mut receive) = mpsc::channel(8);
        let task = tokio::spawn(workers.pop().unwrap().run(
            move |(name, delay): (&'static str, u64)| {
                let completed = completed.clone();
                async move {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    let _ = completed.send(name).await;
                }
            },
        ));
        for index in 0..4 {
            dispatcher
                .dispatch(
                    WorkKey::from_bytes(format!("bulk-{index}").as_bytes()),
                    admission(WorkClass::Background, 1),
                    ("bulk", 100),
                )
                .await
                .unwrap();
        }
        dispatcher
            .dispatch(
                WorkKey::from_bytes(b"control"),
                admission(WorkClass::Control, 1),
                ("control", 0),
            )
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(30), receive.recv())
                .await
                .unwrap(),
            Some("control")
        );
        dispatcher.shutdown().await;
        task.await.unwrap();
    }

    #[tokio::test]
    async fn remap_waits_for_old_owner_and_routes_future_work() {
        let descriptors = vec![
            WorkerDescriptor {
                id: 0,
                cpu_affinity: Some(2),
            },
            WorkerDescriptor {
                id: 1,
                cpu_affinity: Some(3),
            },
        ];
        let (dispatcher, workers) = build(test_config(), descriptors).unwrap();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for worker in workers {
            let id = worker.descriptor().id;
            let observed = observed.clone();
            tasks.push(tokio::spawn(worker.run(move |value: u8| {
                let observed = observed.clone();
                async move {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    observed.lock().unwrap().push((id, value));
                }
            })));
        }
        let key = WorkKey::from_bytes(b"move-me");
        let original = dispatcher.owner_for(key);
        let target = (original + 1) % 2;
        dispatcher
            .dispatch(key, admission(WorkClass::Foreground, 1), 1)
            .await
            .unwrap();
        dispatcher
            .drain_and_remap(key, target, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(dispatcher.owner_for(key), target);
        dispatcher
            .dispatch(key, admission(WorkClass::Foreground, 1), 2)
            .await
            .unwrap();
        for _ in 0..100 {
            if observed.lock().unwrap().len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(*observed.lock().unwrap(), vec![(original, 1), (target, 2)]);
        dispatcher.shutdown().await;
        for task in tasks {
            task.await.unwrap();
        }
    }
}
