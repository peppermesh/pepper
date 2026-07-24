// SPDX-License-Identifier: Apache-2.0

//! Product-neutral primitives for hosting replicated state machines.
//!
//! This crate deliberately does not select a consensus algorithm or storage
//! backend. It defines deterministic application, typed group identity and
//! registration, linearizable-read coalescing, guarded proposals, and a lazy
//! batch executor that consumes no task or timer while idle.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    fmt::{Debug, Display},
    hash::Hash,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use tokio::sync::{Mutex, oneshot};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HostError {
    #[error("product and group identifiers must be non-empty portable ASCII")]
    InvalidGroupId,
    #[error("replicated state-machine group already exists")]
    GroupExists,
    #[error("replicated state-machine group is not registered")]
    GroupMissing,
    #[error("replicated state-machine group limit {0} reached")]
    GroupLimit(usize),
    #[error("snapshot digest mismatch")]
    SnapshotDigest,
    #[error("state-machine codec failed: {0}")]
    Codec(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupId {
    product: String,
    group: String,
}

impl GroupId {
    pub fn new(product: impl Into<String>, group: impl Into<String>) -> Result<Self, HostError> {
        let product = product.into();
        let group = group.into();
        if !portable_id(&product) || !group_component(&group) {
            return Err(HostError::InvalidGroupId);
        }
        Ok(Self { product, group })
    }

    pub fn product(&self) -> &str {
        &self.product
    }

    pub fn group(&self) -> &str {
        &self.group
    }
}

fn portable_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn group_component(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// A collision-free storage prefix for one product and logical consensus
/// group. Storage backends append their own record class and key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageScope {
    prefix: String,
}

impl StorageScope {
    pub fn new(id: &GroupId) -> Self {
        Self {
            prefix: format!(
                "rsm/{}/{}/",
                length_prefix(id.product()),
                length_prefix(id.group())
            ),
        }
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn key(&self, record_class: &str, suffix: &str) -> Result<String, HostError> {
        if !portable_id(record_class) {
            return Err(HostError::InvalidGroupId);
        }
        Ok(format!("{}{record_class}/{suffix}", self.prefix))
    }
}

fn length_prefix(value: &str) -> String {
    format!("{}:{value}", value.len())
}

/// Product adapter for deterministic command application and snapshot bytes.
/// Consensus membership, logs, transports, and durability remain host policy.
#[async_trait]
pub trait ReplicatedStateMachine: Send + Sync + 'static {
    type State: Clone + Send + Sync + 'static;
    type Command: Send + 'static;
    type Response: Send + 'static;
    type Error: Display + Send + Sync + 'static;

    async fn apply(
        &self,
        state: &mut Self::State,
        command: Self::Command,
    ) -> Result<Self::Response, Self::Error>;

    fn encode_state(&self, state: &Self::State) -> Result<Vec<u8>, Self::Error>;

    fn decode_state(&self, encoded: &[u8]) -> Result<Self::State, Self::Error>;

    fn command_class(&self, _command: &Self::Command) -> &'static str {
        "command"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSnapshot {
    pub applied_index: u64,
    pub state_bytes: Vec<u8>,
    pub digest: [u8; 32],
}

/// A deterministic, single-group state host used by product adapters and
/// tests. A failed batch leaves both state and applied index unchanged.
pub struct DeterministicHost<M: ReplicatedStateMachine> {
    machine: Arc<M>,
    state: Mutex<HostedState<M::State>>,
}

struct HostedState<S> {
    applied_index: u64,
    value: S,
}

impl<M: ReplicatedStateMachine> DeterministicHost<M> {
    pub fn new(machine: Arc<M>, initial_state: M::State) -> Self {
        Self {
            machine,
            state: Mutex::new(HostedState {
                applied_index: 0,
                value: initial_state,
            }),
        }
    }

    pub async fn apply_batch(
        &self,
        commands: impl IntoIterator<Item = M::Command>,
    ) -> Result<Vec<M::Response>, M::Error> {
        let mut hosted = self.state.lock().await;
        let mut next = hosted.value.clone();
        let mut responses = Vec::new();
        for command in commands {
            responses.push(self.machine.apply(&mut next, command).await?);
        }
        hosted.applied_index = hosted
            .applied_index
            .saturating_add(responses.len().try_into().unwrap_or(u64::MAX));
        hosted.value = next;
        Ok(responses)
    }

    pub async fn state(&self) -> M::State {
        self.state.lock().await.value.clone()
    }

    pub async fn snapshot(&self) -> Result<StateSnapshot, HostError> {
        let hosted = self.state.lock().await;
        let state_bytes = self
            .machine
            .encode_state(&hosted.value)
            .map_err(|error| HostError::Codec(error.to_string()))?;
        Ok(StateSnapshot {
            applied_index: hosted.applied_index,
            digest: *blake3::hash(&state_bytes).as_bytes(),
            state_bytes,
        })
    }

    pub async fn restore(&self, snapshot: StateSnapshot) -> Result<(), HostError> {
        if blake3::hash(&snapshot.state_bytes).as_bytes() != &snapshot.digest {
            return Err(HostError::SnapshotDigest);
        }
        let value = self
            .machine
            .decode_state(&snapshot.state_bytes)
            .map_err(|error| HostError::Codec(error.to_string()))?;
        *self.state.lock().await = HostedState {
            applied_index: snapshot.applied_index,
            value,
        };
        Ok(())
    }
}

/// Product-defined optimistic or conditional proposal validation.
pub trait ProposalGuard<S, C>: Send + Sync {
    type Error;

    fn validate(&self, state: &S, command: &C) -> Result<(), Self::Error>;
}

/// A bounded typed registry. Registration itself creates no task, timer, file,
/// or socket; lifecycle remains explicit in the stored handle.
pub struct GroupRegistry<H> {
    capacity: usize,
    groups: RwLock<HashMap<GroupId, Arc<H>>>,
}

impl<H> GroupRegistry<H> {
    pub fn new(capacity: usize) -> Result<Self, HostError> {
        if capacity == 0 {
            return Err(HostError::GroupLimit(0));
        }
        Ok(Self {
            capacity,
            groups: RwLock::new(HashMap::with_capacity(capacity.min(4096))),
        })
    }

    pub fn insert(&self, id: GroupId, handle: Arc<H>) -> Result<(), HostError> {
        let mut groups = self.groups.write().expect("RSM group registry poisoned");
        if groups.contains_key(&id) {
            return Err(HostError::GroupExists);
        }
        if groups.len() >= self.capacity {
            return Err(HostError::GroupLimit(self.capacity));
        }
        groups.insert(id, handle);
        Ok(())
    }

    pub fn get(&self, id: &GroupId) -> Result<Arc<H>, HostError> {
        self.groups
            .read()
            .expect("RSM group registry poisoned")
            .get(id)
            .cloned()
            .ok_or(HostError::GroupMissing)
    }

    pub fn remove(&self, id: &GroupId) -> Result<Arc<H>, HostError> {
        self.groups
            .write()
            .expect("RSM group registry poisoned")
            .remove(id)
            .ok_or(HostError::GroupMissing)
    }

    pub fn len(&self) -> usize {
        self.groups
            .read()
            .expect("RSM group registry poisoned")
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn handles(&self) -> Vec<Arc<H>> {
        self.groups
            .read()
            .expect("RSM group registry poisoned")
            .values()
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadLease {
    pub local_node: u64,
    pub current_leader: Option<u64>,
    pub millis_since_quorum_ack: Option<u64>,
    pub maximum_age_millis: u64,
    pub last_applied_index: Option<u64>,
    pub last_log_index: Option<u64>,
}

impl ReadLease {
    pub fn is_current(self) -> bool {
        self.current_leader == Some(self.local_node)
            && self
                .millis_since_quorum_ack
                .is_some_and(|millis| millis <= self.maximum_age_millis)
            && self.last_applied_index >= self.last_log_index
    }
}

/// Coalesces overlapping quorum proofs. It contains no background task.
pub struct LinearizableReadGate {
    arrivals: AtomicU64,
    covered: AtomicU64,
    lock: Mutex<()>,
    join_window: Duration,
}

impl LinearizableReadGate {
    pub fn new(join_window: Duration) -> Self {
        Self {
            arrivals: AtomicU64::new(0),
            covered: AtomicU64::new(0),
            lock: Mutex::new(()),
            join_window,
        }
    }

    pub async fn ensure<F, Fut, E>(&self, proof: F) -> Result<(), E>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), E>>,
    {
        let arrival = self.arrivals.fetch_add(1, Ordering::AcqRel) + 1;
        let _guard = self.lock.lock().await;
        if self.covered.load(Ordering::Acquire) >= arrival {
            return Ok(());
        }
        if !self.join_window.is_zero() {
            tokio::time::sleep(self.join_window).await;
        }
        let cover_through = self.arrivals.load(Ordering::Acquire);
        proof().await?;
        self.covered.store(cover_through, Ordering::Release);
        Ok(())
    }
}

#[async_trait]
pub trait BatchProcessor: Send + Sync + 'static {
    type Input: Send + 'static;
    type Output: Send + 'static;
    type Error: Clone + Display + Send + Sync + 'static;

    async fn process(&self, inputs: Vec<Self::Input>) -> Result<Vec<Self::Output>, Self::Error>;
}

#[derive(Debug, Error)]
pub enum BatchError<E: Display> {
    #[error("batch processor failed: {0}")]
    Processor(E),
    #[error("batch output count mismatch: expected {expected}, got {actual}")]
    OutputCount { expected: usize, actual: usize },
    #[error("batch response was dropped")]
    ResponseDropped,
    #[error("batch queue limit {0} reached")]
    QueueFull(usize),
}

struct BatchJob<I, O, E: Display> {
    input: I,
    encoded_bytes: usize,
    response: oneshot::Sender<Result<O, BatchError<E>>>,
}

struct BatchState<I, O, E: Display> {
    running: bool,
    queue: VecDeque<BatchJob<I, O, E>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BatchStats {
    pub submitted: u64,
    pub batches: u64,
    pub maximum_batch_size: u64,
    pub active_runners: u64,
}

/// Demand-driven bounded batch execution. The first submitter drains the
/// queue; when it empties, no runner task or timer remains.
pub struct LazyBatcher<P: BatchProcessor> {
    processor: Arc<P>,
    maximum_items: usize,
    maximum_bytes: usize,
    maximum_queued: usize,
    maximum_delay: Duration,
    state: Mutex<BatchState<P::Input, P::Output, P::Error>>,
    submitted: AtomicU64,
    batches: AtomicU64,
    maximum_batch_size: AtomicU64,
    active_runners: AtomicU64,
}

impl<P: BatchProcessor> LazyBatcher<P> {
    pub fn new(
        processor: Arc<P>,
        maximum_items: usize,
        maximum_bytes: usize,
        maximum_delay: Duration,
    ) -> Result<Arc<Self>, HostError> {
        if maximum_items == 0 || maximum_bytes == 0 {
            return Err(HostError::GroupLimit(0));
        }
        Ok(Arc::new(Self {
            processor,
            maximum_items,
            maximum_bytes,
            maximum_queued: maximum_items.saturating_mul(8),
            maximum_delay,
            state: Mutex::new(BatchState {
                running: false,
                queue: VecDeque::new(),
            }),
            submitted: AtomicU64::new(0),
            batches: AtomicU64::new(0),
            maximum_batch_size: AtomicU64::new(0),
            active_runners: AtomicU64::new(0),
        }))
    }

    pub async fn submit(
        self: &Arc<Self>,
        input: P::Input,
        encoded_bytes: usize,
    ) -> Result<P::Output, BatchError<P::Error>> {
        let (response, result) = oneshot::channel();
        let lead = {
            let mut state = self.state.lock().await;
            if state.queue.len() >= self.maximum_queued {
                return Err(BatchError::QueueFull(self.maximum_queued));
            }
            state.queue.push_back(BatchJob {
                input,
                encoded_bytes,
                response,
            });
            if state.running {
                false
            } else {
                state.running = true;
                true
            }
        };
        self.submitted.fetch_add(1, Ordering::Relaxed);
        if lead {
            let batcher = self.clone();
            tokio::spawn(async move {
                batcher.drain().await;
            });
        }
        result.await.map_err(|_| BatchError::ResponseDropped)?
    }

    async fn drain(&self) {
        self.active_runners.fetch_add(1, Ordering::Relaxed);
        loop {
            if !self.maximum_delay.is_zero() {
                tokio::time::sleep(self.maximum_delay).await;
            }
            let jobs = {
                let mut state = self.state.lock().await;
                let mut bytes = 0usize;
                let mut jobs = Vec::with_capacity(self.maximum_items);
                while jobs.len() < self.maximum_items {
                    let Some(next) = state.queue.front() else {
                        break;
                    };
                    let next_bytes = bytes.saturating_add(next.encoded_bytes);
                    if !jobs.is_empty() && next_bytes > self.maximum_bytes {
                        break;
                    }
                    bytes = next_bytes;
                    jobs.push(state.queue.pop_front().expect("front was present"));
                }
                jobs
            };
            if jobs.is_empty() {
                let mut state = self.state.lock().await;
                if state.queue.is_empty() {
                    state.running = false;
                    self.active_runners.fetch_sub(1, Ordering::Relaxed);
                    break;
                }
                continue;
            }
            self.batches.fetch_add(1, Ordering::Relaxed);
            self.maximum_batch_size
                .fetch_max(jobs.len() as u64, Ordering::Relaxed);
            let expected = jobs.len();
            let (raw_inputs, responders): (Vec<_>, Vec<_>) = jobs
                .into_iter()
                .map(|job| (job.input, job.response))
                .unzip();
            match self.processor.process(raw_inputs).await {
                Ok(outputs) if outputs.len() == expected => {
                    for (response, output) in responders.into_iter().zip(outputs) {
                        let _ = response.send(Ok(output));
                    }
                }
                Ok(outputs) => {
                    let actual = outputs.len();
                    for response in responders {
                        let _ = response.send(Err(BatchError::OutputCount { expected, actual }));
                    }
                }
                Err(error) => {
                    for response in responders {
                        let _ = response.send(Err(BatchError::Processor(error.clone())));
                    }
                }
            }
        }
    }

    pub fn stats(&self) -> BatchStats {
        BatchStats {
            submitted: self.submitted.load(Ordering::Relaxed),
            batches: self.batches.load(Ordering::Relaxed),
            maximum_batch_size: self.maximum_batch_size.load(Ordering::Relaxed),
            active_runners: self.active_runners.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicUsize, Ordering},
        time::Instant,
    };

    #[derive(Debug)]
    struct MapMachine;

    #[async_trait]
    impl ReplicatedStateMachine for MapMachine {
        type State = BTreeMap<String, u64>;
        type Command = (String, u64);
        type Response = Option<u64>;
        type Error = serde_json::Error;

        async fn apply(
            &self,
            state: &mut Self::State,
            (key, value): Self::Command,
        ) -> Result<Self::Response, Self::Error> {
            Ok(state.insert(key, value))
        }

        fn encode_state(&self, state: &Self::State) -> Result<Vec<u8>, Self::Error> {
            serde_json::to_vec(state)
        }

        fn decode_state(&self, encoded: &[u8]) -> Result<Self::State, Self::Error> {
            serde_json::from_slice(encoded)
        }
    }

    #[tokio::test]
    async fn deterministic_replay_and_snapshot_restore_are_byte_identical() {
        let left = DeterministicHost::new(Arc::new(MapMachine), BTreeMap::new());
        let right = DeterministicHost::new(Arc::new(MapMachine), BTreeMap::new());
        let commands = vec![("b".into(), 2), ("a".into(), 1), ("b".into(), 3)];
        left.apply_batch(commands.clone()).await.unwrap();
        right.apply_batch(commands).await.unwrap();
        let left_snapshot = left.snapshot().await.unwrap();
        let right_snapshot = right.snapshot().await.unwrap();
        assert_eq!(left_snapshot, right_snapshot);

        let restored = DeterministicHost::new(Arc::new(MapMachine), BTreeMap::new());
        restored.restore(left_snapshot.clone()).await.unwrap();
        assert_eq!(restored.snapshot().await.unwrap(), left_snapshot);
    }

    #[tokio::test]
    async fn corrupt_snapshot_is_rejected_without_changing_state() {
        let host = DeterministicHost::new(Arc::new(MapMachine), BTreeMap::new());
        host.apply_batch([("a".into(), 1)]).await.unwrap();
        let before = host.snapshot().await.unwrap();
        let mut corrupt = before.clone();
        corrupt.state_bytes.push(0);
        assert_eq!(host.restore(corrupt).await, Err(HostError::SnapshotDigest));
        assert_eq!(host.snapshot().await.unwrap(), before);
    }

    #[test]
    fn typed_registry_and_storage_scopes_isolate_ten_thousand_groups() {
        let registry = GroupRegistry::new(10_000).unwrap();
        for index in 0..10_000 {
            let id = GroupId::new("test-metadata", format!("shard-{index}")).unwrap();
            let scope = StorageScope::new(&id);
            assert!(scope.key("log", "1").unwrap().contains("test-metadata"));
            registry.insert(id, Arc::new(index)).unwrap();
        }
        assert_eq!(registry.len(), 10_000);
        let id = GroupId::new("test-metadata", "shard-9999").unwrap();
        assert_eq!(*registry.get(&id).unwrap(), 9999);
        assert!(matches!(
            registry.insert(GroupId::new("test", "overflow").unwrap(), Arc::new(0)),
            Err(HostError::GroupLimit(10_000))
        ));
    }

    #[tokio::test]
    async fn overlapping_linearizable_reads_share_one_proof() {
        let gate = Arc::new(LinearizableReadGate::new(Duration::from_millis(2)));
        let proofs = Arc::new(AtomicUsize::new(0));
        let mut reads = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let gate = gate.clone();
            let proofs = proofs.clone();
            reads.spawn(async move {
                gate.ensure(|| async move {
                    proofs.fetch_add(1, Ordering::Relaxed);
                    Ok::<_, ()>(())
                })
                .await
            });
        }
        while let Some(result) = reads.join_next().await {
            result.unwrap().unwrap();
        }
        assert_eq!(proofs.load(Ordering::Relaxed), 1);
    }

    struct DelayProcessor(Duration);

    #[async_trait]
    impl BatchProcessor for DelayProcessor {
        type Input = u64;
        type Output = u64;
        type Error = String;

        async fn process(
            &self,
            inputs: Vec<Self::Input>,
        ) -> Result<Vec<Self::Output>, Self::Error> {
            tokio::time::sleep(self.0).await;
            Ok(inputs)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overloaded_group_does_not_delay_an_independent_group() {
        let slow = LazyBatcher::new(
            Arc::new(DelayProcessor(Duration::from_millis(100))),
            32,
            1024,
            Duration::ZERO,
        )
        .unwrap();
        let fast = LazyBatcher::new(
            Arc::new(DelayProcessor(Duration::ZERO)),
            32,
            1024,
            Duration::ZERO,
        )
        .unwrap();
        let slow_task = tokio::spawn({
            let slow = slow.clone();
            async move { slow.submit(1, 8).await }
        });
        tokio::task::yield_now().await;
        let started = Instant::now();
        assert_eq!(fast.submit(2, 8).await.unwrap(), 2);
        assert!(started.elapsed() < Duration::from_millis(30));
        assert_eq!(slow_task.await.unwrap().unwrap(), 1);
        while slow.stats().active_runners != 0 || fast.stats().active_runners != 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(slow.stats().active_runners, 0);
        assert_eq!(fast.stats().active_runners, 0);
    }

    #[test]
    fn leader_lease_requires_local_current_fully_applied_leader() {
        assert!(
            ReadLease {
                local_node: 1,
                current_leader: Some(1),
                millis_since_quorum_ack: Some(10),
                maximum_age_millis: 100,
                last_applied_index: Some(7),
                last_log_index: Some(7),
            }
            .is_current()
        );
    }
}
