// SPDX-License-Identifier: Apache-2.0

//! Bounded broker-operability primitives shared by Kafka request paths.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, BinaryHeap},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, oneshot},
    time::Instant,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PartitionKey {
    topic: Arc<str>,
    partition: i32,
}

impl PartitionKey {
    pub fn new(topic: impl Into<Arc<str>>, partition: i32) -> Self {
        Self {
            topic: topic.into(),
            partition,
        }
    }

    pub fn topic(&self) -> &str {
        &self.topic
    }

    pub const fn partition(&self) -> i32 {
        self.partition
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    DataAvailable,
    Deadline,
}

struct Waiter {
    keys: Vec<PartitionKey>,
    sender: oneshot::Sender<WaitOutcome>,
}

#[derive(Default)]
struct WaiterState {
    next_id: u64,
    by_id: BTreeMap<u64, Waiter>,
    by_partition: BTreeMap<PartitionKey, BTreeSet<u64>>,
    deadlines: BinaryHeap<Reverse<(Instant, u64)>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WaiterSnapshot {
    pub registered: u64,
    pub partition_keys: u64,
    pub registrations_total: u64,
    pub data_wakeups: u64,
    pub deadline_wakeups: u64,
    pub cancellations: u64,
    pub partition_notifications: u64,
}

struct FetchWaiterInner {
    state: Mutex<WaiterState>,
    changed: Notify,
    active: AtomicU64,
    registrations_total: AtomicU64,
    data_wakeups: AtomicU64,
    deadline_wakeups: AtomicU64,
    cancellations: AtomicU64,
    partition_notifications: AtomicU64,
}

/// One registry and one deadline scheduler serve every partition on a broker.
///
/// A registration owns only a one-shot sender plus its requested partition
/// keys. It creates no task, timer, or file descriptor.
#[derive(Clone)]
pub struct FetchWaiterRegistry {
    inner: Arc<FetchWaiterInner>,
}

impl FetchWaiterRegistry {
    pub fn new() -> Self {
        let inner = Arc::new(FetchWaiterInner {
            state: Mutex::new(WaiterState::default()),
            changed: Notify::new(),
            active: AtomicU64::new(0),
            registrations_total: AtomicU64::new(0),
            data_wakeups: AtomicU64::new(0),
            deadline_wakeups: AtomicU64::new(0),
            cancellations: AtomicU64::new(0),
            partition_notifications: AtomicU64::new(0),
        });
        tokio::spawn(deadline_scheduler(Arc::downgrade(&inner)));
        Self { inner }
    }

    pub fn register(
        &self,
        keys: impl IntoIterator<Item = PartitionKey>,
        maximum_wait: Duration,
    ) -> FetchWait {
        let mut keys = keys.into_iter().collect::<Vec<_>>();
        keys.sort();
        keys.dedup();
        let deadline = Instant::now() + maximum_wait;
        let (sender, receiver) = oneshot::channel();
        let mut state = self.inner.state.lock().expect("waiter registry poisoned");
        state.next_id = state.next_id.wrapping_add(1).max(1);
        let id = state.next_id;
        for key in &keys {
            state
                .by_partition
                .entry(key.clone())
                .or_default()
                .insert(id);
        }
        state.deadlines.push(Reverse((deadline, id)));
        state.by_id.insert(id, Waiter { keys, sender });
        self.inner.active.fetch_add(1, Ordering::Release);
        drop(state);
        self.inner
            .registrations_total
            .fetch_add(1, Ordering::Relaxed);
        self.inner.changed.notify_one();
        FetchWait {
            id,
            registry: Arc::downgrade(&self.inner),
            receiver: Some(receiver),
        }
    }

    pub fn notify(&self, key: &PartitionKey) -> usize {
        if self.inner.active.load(Ordering::Acquire) == 0 {
            return 0;
        }
        self.inner
            .partition_notifications
            .fetch_add(1, Ordering::Relaxed);
        let mut state = self.inner.state.lock().expect("waiter registry poisoned");
        let ids = state.by_partition.get(key).cloned().unwrap_or_default();
        let mut senders = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(waiter) = remove_waiter(&mut state, id) {
                senders.push(waiter.sender);
            }
        }
        drop(state);
        let count = senders.len();
        for sender in senders {
            let _ = sender.send(WaitOutcome::DataAvailable);
        }
        self.inner
            .data_wakeups
            .fetch_add(count as u64, Ordering::Relaxed);
        self.inner.active.fetch_sub(count as u64, Ordering::Release);
        count
    }

    pub fn snapshot(&self) -> WaiterSnapshot {
        let state = self.inner.state.lock().expect("waiter registry poisoned");
        WaiterSnapshot {
            registered: state.by_id.len() as u64,
            partition_keys: state.by_partition.len() as u64,
            registrations_total: self.inner.registrations_total.load(Ordering::Relaxed),
            data_wakeups: self.inner.data_wakeups.load(Ordering::Relaxed),
            deadline_wakeups: self.inner.deadline_wakeups.load(Ordering::Relaxed),
            cancellations: self.inner.cancellations.load(Ordering::Relaxed),
            partition_notifications: self.inner.partition_notifications.load(Ordering::Relaxed),
        }
    }
}

impl Default for FetchWaiterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub struct FetchWait {
    id: u64,
    registry: Weak<FetchWaiterInner>,
    receiver: Option<oneshot::Receiver<WaitOutcome>>,
}

impl FetchWait {
    pub async fn ready(mut self) -> WaitOutcome {
        let receiver = self.receiver.take().expect("wait receiver consumed once");
        receiver.await.unwrap_or(WaitOutcome::Deadline)
    }
}

impl Drop for FetchWait {
    fn drop(&mut self) {
        let Some(inner) = self.registry.upgrade() else {
            return;
        };
        let mut state = inner.state.lock().expect("waiter registry poisoned");
        if remove_waiter(&mut state, self.id).is_some() {
            inner.cancellations.fetch_add(1, Ordering::Relaxed);
            inner.active.fetch_sub(1, Ordering::Release);
        }
    }
}

fn remove_waiter(state: &mut WaiterState, id: u64) -> Option<Waiter> {
    let waiter = state.by_id.remove(&id)?;
    for key in &waiter.keys {
        let remove_key = if let Some(ids) = state.by_partition.get_mut(key) {
            ids.remove(&id);
            ids.is_empty()
        } else {
            false
        };
        if remove_key {
            state.by_partition.remove(key);
        }
    }
    Some(waiter)
}

async fn deadline_scheduler(inner: Weak<FetchWaiterInner>) {
    loop {
        let Some(inner) = inner.upgrade() else {
            return;
        };
        let next = {
            let mut state = inner.state.lock().expect("waiter registry poisoned");
            while state
                .deadlines
                .peek()
                .is_some_and(|Reverse((_, id))| !state.by_id.contains_key(id))
            {
                state.deadlines.pop();
            }
            state
                .deadlines
                .peek()
                .map(|Reverse((deadline, _))| *deadline)
        };
        match next {
            Some(deadline) => {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => {
                        let now = Instant::now();
                        let mut state = inner.state.lock().expect("waiter registry poisoned");
                        let mut senders = Vec::new();
                        while let Some(Reverse((deadline, id))) = state.deadlines.peek().copied() {
                            if deadline > now {
                                break;
                            }
                            state.deadlines.pop();
                            if let Some(waiter) = remove_waiter(&mut state, id) {
                                senders.push(waiter.sender);
                            }
                        }
                        drop(state);
                        let count = senders.len();
                        for sender in senders {
                            let _ = sender.send(WaitOutcome::Deadline);
                        }
                        inner.deadline_wakeups.fetch_add(count as u64, Ordering::Relaxed);
                        inner.active.fetch_sub(count as u64, Ordering::Release);
                    }
                    _ = inner.changed.notified() => {}
                }
            }
            None => inner.changed.notified().await,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaConfig {
    pub broker_bytes_per_second: u64,
    pub partition_bytes_per_second: u64,
    pub burst_bytes: u64,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            broker_bytes_per_second: 0,
            partition_bytes_per_second: 0,
            burst_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: u64,
    last: Instant,
}

#[derive(Default)]
struct QuotaState {
    broker: Option<Bucket>,
    partitions: BTreeMap<PartitionKey, Bucket>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuotaSnapshot {
    pub admitted_bytes: u64,
    pub throttled_requests: u64,
    pub tracked_partitions: u64,
}

/// Independent broker and partition token buckets keep a hot key from
/// consuming the cold-key budget.
pub struct QuotaManager {
    config: QuotaConfig,
    state: Mutex<QuotaState>,
    admitted_bytes: AtomicU64,
    throttled_requests: AtomicU64,
}

impl QuotaManager {
    pub fn new(config: QuotaConfig) -> Self {
        Self {
            config,
            state: Mutex::new(QuotaState::default()),
            admitted_bytes: AtomicU64::new(0),
            throttled_requests: AtomicU64::new(0),
        }
    }

    pub fn admit(&self, key: &PartitionKey, bytes: u64, now: Instant) -> bool {
        if self.config.broker_bytes_per_second == 0 && self.config.partition_bytes_per_second == 0 {
            return true;
        }
        let mut state = self.state.lock().expect("quota state poisoned");
        let broker_allowed = take(
            &mut state.broker,
            self.config.broker_bytes_per_second,
            self.config.burst_bytes,
            bytes,
            now,
        );
        let partition_allowed = take_bucket(
            state.partitions.entry(key.clone()).or_insert(Bucket {
                tokens: self.config.burst_bytes,
                last: now,
            }),
            self.config.partition_bytes_per_second,
            self.config.burst_bytes,
            bytes,
            now,
        );
        if broker_allowed && partition_allowed {
            self.admitted_bytes.fetch_add(bytes, Ordering::Relaxed);
            true
        } else {
            self.throttled_requests.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    pub fn snapshot(&self) -> QuotaSnapshot {
        let state = self.state.lock().expect("quota state poisoned");
        QuotaSnapshot {
            admitted_bytes: self.admitted_bytes.load(Ordering::Relaxed),
            throttled_requests: self.throttled_requests.load(Ordering::Relaxed),
            tracked_partitions: state.partitions.len() as u64,
        }
    }
}

fn take(bucket: &mut Option<Bucket>, rate: u64, burst: u64, bytes: u64, now: Instant) -> bool {
    if rate == 0 {
        return true;
    }
    let bucket = bucket.get_or_insert(Bucket {
        tokens: burst,
        last: now,
    });
    take_bucket(bucket, rate, burst, bytes, now)
}

fn take_bucket(bucket: &mut Bucket, rate: u64, burst: u64, bytes: u64, now: Instant) -> bool {
    if rate == 0 {
        return true;
    }
    let refill = now
        .saturating_duration_since(bucket.last)
        .as_nanos()
        .saturating_mul(u128::from(rate))
        / 1_000_000_000;
    bucket.tokens = bucket
        .tokens
        .saturating_add(refill.min(u128::from(u64::MAX)) as u64)
        .min(burst);
    bucket.last = now;
    if bucket.tokens < bytes {
        return false;
    }
    bucket.tokens -= bytes;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn one_scheduler_handles_one_hundred_thousand_partition_waiters() {
        let registry = FetchWaiterRegistry::new();
        let mut waits = Vec::with_capacity(100_000);
        for partition in 0..100_000 {
            waits.push(registry.register(
                [PartitionKey::new("idle", partition)],
                Duration::from_secs(60),
            ));
        }
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.registered, 100_000);
        assert_eq!(snapshot.partition_keys, 100_000);
        assert!(std::mem::size_of::<Waiter>() + std::mem::size_of::<(Instant, u64)>() < 512);
        assert_eq!(registry.notify(&PartitionKey::new("idle", 77_777)), 1);
        assert_eq!(
            waits.swap_remove(77_777).ready().await,
            WaitOutcome::DataAvailable
        );
        drop(waits);
        assert_eq!(registry.snapshot().registered, 0);
    }

    #[tokio::test]
    async fn deadlines_and_cancellation_remove_every_index_entry() {
        let registry = FetchWaiterRegistry::new();
        let cancelled =
            registry.register([PartitionKey::new("events", 0)], Duration::from_millis(5));
        drop(cancelled);
        let deadline =
            registry.register([PartitionKey::new("events", 1)], Duration::from_millis(5));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(deadline.ready().await, WaitOutcome::Deadline);
        assert_eq!(registry.snapshot().registered, 0);
    }

    #[test]
    fn hot_partition_does_not_consume_cold_partition_bucket() {
        let manager = QuotaManager::new(QuotaConfig {
            broker_bytes_per_second: 0,
            partition_bytes_per_second: 100,
            burst_bytes: 100,
        });
        let now = Instant::now();
        let hot = PartitionKey::new("events", 0);
        let cold = PartitionKey::new("events", 1);
        assert!(manager.admit(&hot, 100, now));
        assert!(!manager.admit(&hot, 1, now));
        assert!(manager.admit(&cold, 100, now));
    }
}
