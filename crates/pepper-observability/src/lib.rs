// SPDX-License-Identifier: Apache-2.0

//! Product-neutral operation identity, bounded-cardinality cost telemetry, and
//! deterministic fault boundaries.
//!
//! Operation and work-key values are deliberately excluded from metric labels.
//! They are correlation fields for structured events; metrics use only closed
//! enums whose cardinality is fixed at compile time.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{
    fmt,
    future::Future,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

pub const OPERATION_ID_HEADER: &str = "x-pepper-operation-id";
const OPERATION_ID_BYTES: usize = 16;
const OPERATION_ID_HEX_BYTES: usize = OPERATION_ID_BYTES * 2;

static PROCESS_NONCE: OnceLock<u64> = OnceLock::new();
static NEXT_OPERATION: AtomicU64 = AtomicU64::new(1);

/// A cross-product correlation identifier. It is unique enough for telemetry,
/// but is not a security token and must never be used for authorization.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OperationId([u8; OPERATION_ID_BYTES]);

impl OperationId {
    pub fn generate() -> Self {
        let nonce = *PROCESS_NONCE.get_or_init(|| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let mut material = [0u8; 24];
            material[..16].copy_from_slice(&now.to_le_bytes());
            material[16..20].copy_from_slice(&std::process::id().to_le_bytes());
            let stack_address = (&material as *const [u8; 24]) as usize as u64;
            material[16..24].copy_from_slice(&stack_address.to_le_bytes());
            let digest = blake3::hash(&material);
            u64::from_le_bytes(digest.as_bytes()[..8].try_into().expect("fixed digest"))
        });
        let sequence = NEXT_OPERATION.fetch_add(1, Ordering::Relaxed);
        let mut bytes = [0u8; OPERATION_ID_BYTES];
        bytes[..8].copy_from_slice(&nonce.to_be_bytes());
        bytes[8..].copy_from_slice(&sequence.to_be_bytes());
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; OPERATION_ID_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; OPERATION_ID_BYTES] {
        &self.0
    }

    pub fn parse(value: &str) -> Result<Self, ParseOperationIdError> {
        if value.len() != OPERATION_ID_HEX_BYTES {
            return Err(ParseOperationIdError::Length(value.len()));
        }
        let mut bytes = [0u8; OPERATION_ID_BYTES];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let start = index * 2;
            *byte = u8::from_str_radix(&value[start..start + 2], 16)
                .map_err(|_| ParseOperationIdError::Hex)?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "OperationId({self})")
    }
}

impl Serialize for OperationId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for OperationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseOperationIdError {
    #[error("operation ID must contain 32 hexadecimal characters, got {0}")]
    Length(usize),
    #[error("operation ID contains non-hexadecimal characters")]
    Hex,
}

/// A stable, opaque scheduling key. Raw tenant/object/database/topic names do
/// not escape through this type.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkKey([u8; 16]);

impl WorkKey {
    pub fn from_bytes(value: &[u8]) -> Self {
        let digest = blake3::hash(value);
        Self(digest.as_bytes()[..16].try_into().expect("fixed digest"))
    }

    pub fn combine(parts: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        for part in parts {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        let digest = hasher.finalize();
        Self(digest.as_bytes()[..16].try_into().expect("fixed digest"))
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for WorkKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WorkKey(<opaque>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum WorkloadClass {
    S3Put,
    S3Get,
    FilesystemCommit,
    FilesystemCheckout,
    SqliteCommit,
    SqliteRead,
    KafkaProduce,
    KafkaFetch,
    Control,
    Background,
    Unknown,
}

impl WorkloadClass {
    pub const ALL: [Self; 11] = [
        Self::S3Put,
        Self::S3Get,
        Self::FilesystemCommit,
        Self::FilesystemCheckout,
        Self::SqliteCommit,
        Self::SqliteRead,
        Self::KafkaProduce,
        Self::KafkaFetch,
        Self::Control,
        Self::Background,
        Self::Unknown,
    ];

    pub const fn as_label(self) -> &'static str {
        match self {
            Self::S3Put => "s3_put",
            Self::S3Get => "s3_get",
            Self::FilesystemCommit => "filesystem_commit",
            Self::FilesystemCheckout => "filesystem_checkout",
            Self::SqliteCommit => "sqlite_commit",
            Self::SqliteRead => "sqlite_read",
            Self::KafkaProduce => "kafka_produce",
            Self::KafkaFetch => "kafka_fetch",
            Self::Control => "control",
            Self::Background => "background",
            Self::Unknown => "unknown",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CostMetric {
    Operations,
    Failures,
    WallMicroseconds,
    QueueMicroseconds,
    ExecutionMicroseconds,
    OwnedBytes,
    CopyOperations,
    CopyBytes,
    StorageOperations,
    StorageBytes,
    DurabilityBarriers,
    PeerBytes,
    CacheHits,
    CacheMisses,
    StateMachineOperations,
    StateMachineEntries,
}

impl CostMetric {
    pub const ALL: [Self; 16] = [
        Self::Operations,
        Self::Failures,
        Self::WallMicroseconds,
        Self::QueueMicroseconds,
        Self::ExecutionMicroseconds,
        Self::OwnedBytes,
        Self::CopyOperations,
        Self::CopyBytes,
        Self::StorageOperations,
        Self::StorageBytes,
        Self::DurabilityBarriers,
        Self::PeerBytes,
        Self::CacheHits,
        Self::CacheMisses,
        Self::StateMachineOperations,
        Self::StateMachineEntries,
    ];

    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Operations => "operations",
            Self::Failures => "failures",
            Self::WallMicroseconds => "wall_microseconds",
            Self::QueueMicroseconds => "queue_microseconds",
            Self::ExecutionMicroseconds => "execution_microseconds",
            Self::OwnedBytes => "owned_bytes",
            Self::CopyOperations => "copy_operations",
            Self::CopyBytes => "copy_bytes",
            Self::StorageOperations => "storage_operations",
            Self::StorageBytes => "storage_bytes",
            Self::DurabilityBarriers => "durability_barriers",
            Self::PeerBytes => "peer_bytes",
            Self::CacheHits => "cache_hits",
            Self::CacheMisses => "cache_misses",
            Self::StateMachineOperations => "state_machine_operations",
            Self::StateMachineEntries => "state_machine_entries",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

const METRIC_COUNT: usize = CostMetric::ALL.len();
const WORKLOAD_COUNT: usize = WorkloadClass::ALL.len();
const CELL_COUNT: usize = METRIC_COUNT * WORKLOAD_COUNT;

pub struct OperationMetrics {
    cells: [AtomicU64; CELL_COUNT],
}

impl Default for OperationMetrics {
    fn default() -> Self {
        Self {
            cells: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl OperationMetrics {
    pub fn add(&self, class: WorkloadClass, metric: CostMetric, value: u64) {
        self.cells[class.index() * METRIC_COUNT + metric.index()]
            .fetch_add(value, Ordering::Relaxed);
    }

    pub fn get(&self, class: WorkloadClass, metric: CostMetric) -> u64 {
        self.cells[class.index() * METRIC_COUNT + metric.index()].load(Ordering::Relaxed)
    }

    pub fn render_prometheus(&self) -> String {
        let mut output = String::from(
            "# HELP pepper_operation_cost_total Product-neutral operation cost by bounded workload and metric.\n\
             # TYPE pepper_operation_cost_total counter\n",
        );
        for class in WorkloadClass::ALL {
            for metric in CostMetric::ALL {
                output.push_str(&format!(
                    "pepper_operation_cost_total{{workload=\"{}\",metric=\"{}\"}} {}\n",
                    class.as_label(),
                    metric.as_label(),
                    self.get(class, metric)
                ));
            }
        }
        output
    }
}

static PROCESS_METRICS: OnceLock<OperationMetrics> = OnceLock::new();

pub fn process_metrics() -> &'static OperationMetrics {
    PROCESS_METRICS.get_or_init(OperationMetrics::default)
}

#[derive(Debug, Clone, Copy)]
pub struct OperationContext {
    pub id: OperationId,
    pub class: WorkloadClass,
    pub work_key: WorkKey,
}

const LOCAL_COST_COUNT: usize = METRIC_COUNT;

pub struct OperationScope {
    context: OperationContext,
    started: Instant,
    costs: [AtomicU64; LOCAL_COST_COUNT],
    observed_stages: AtomicU64,
    fault_injector: Arc<dyn FaultInjector>,
    completed: AtomicBool,
}

impl OperationScope {
    pub fn begin(
        class: WorkloadClass,
        work_key: WorkKey,
        incoming: Option<OperationId>,
    ) -> Arc<Self> {
        Self::begin_with_faults(class, work_key, incoming, Arc::new(NoFaults))
    }

    pub fn begin_with_faults(
        class: WorkloadClass,
        work_key: WorkKey,
        incoming: Option<OperationId>,
        fault_injector: Arc<dyn FaultInjector>,
    ) -> Arc<Self> {
        Arc::new(Self {
            context: OperationContext {
                id: incoming.unwrap_or_else(OperationId::generate),
                class,
                work_key,
            },
            started: Instant::now(),
            costs: std::array::from_fn(|_| AtomicU64::new(0)),
            observed_stages: AtomicU64::new(0),
            fault_injector,
            completed: AtomicBool::new(false),
        })
    }

    pub const fn context(&self) -> OperationContext {
        self.context
    }

    pub fn add(&self, metric: CostMetric, value: u64) {
        self.costs[metric.index()].fetch_add(value, Ordering::Relaxed);
    }

    pub fn observe(&self, stage: OperationStage) {
        self.observed_stages
            .fetch_or(1u64 << stage.index(), Ordering::Relaxed);
        tracing::debug!(
            operation_id = %self.context.id,
            workload = self.context.class.as_label(),
            stage = stage.as_label(),
            "operation stage"
        );
    }

    pub fn observed(&self, stage: OperationStage) -> bool {
        self.observed_stages.load(Ordering::Relaxed) & (1u64 << stage.index()) != 0
    }

    pub fn finish(&self, success: bool) {
        if self.completed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.add(CostMetric::Operations, 1);
        if !success {
            self.add(CostMetric::Failures, 1);
        }
        self.add(
            CostMetric::WallMicroseconds,
            duration_micros(self.started.elapsed()),
        );
        for metric in CostMetric::ALL {
            let value = self.costs[metric.index()].load(Ordering::Relaxed);
            process_metrics().add(self.context.class, metric, value);
        }
        tracing::debug!(
            operation_id = %self.context.id,
            workload = self.context.class.as_label(),
            success,
            "operation completed"
        );
    }
}

impl Drop for OperationScope {
    fn drop(&mut self) {
        self.finish(false);
    }
}

tokio::task_local! {
    static CURRENT_OPERATION: Arc<OperationScope>;
}

pub async fn scope_operation<F>(scope: Arc<OperationScope>, future: F) -> F::Output
where
    F: Future,
{
    CURRENT_OPERATION.scope(scope, future).await
}

pub fn current_operation() -> Option<Arc<OperationScope>> {
    CURRENT_OPERATION.try_with(Arc::clone).ok()
}

pub fn add_current_cost(metric: CostMetric, value: u64) {
    if let Some(scope) = current_operation() {
        scope.add(metric, value);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OperationStage {
    Ingress,
    OwnerQueue,
    OwnerExecution,
    Storage,
    Replication,
    Durability,
    Publication,
    StateApplication,
    Response,
}

impl OperationStage {
    pub const ALL: [Self; 9] = [
        Self::Ingress,
        Self::OwnerQueue,
        Self::OwnerExecution,
        Self::Storage,
        Self::Replication,
        Self::Durability,
        Self::Publication,
        Self::StateApplication,
        Self::Response,
    ];

    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::OwnerQueue => "owner_queue",
            Self::OwnerExecution => "owner_execution",
            Self::Storage => "storage",
            Self::Replication => "replication",
            Self::Durability => "durability",
            Self::Publication => "publication",
            Self::StateApplication => "state_application",
            Self::Response => "response",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

pub fn observe_current_stage(stage: OperationStage) {
    if let Some(scope) = current_operation() {
        scope.observe(stage);
    }
}

pub struct CostTimer {
    metric: CostMetric,
    started: Instant,
}

impl CostTimer {
    pub fn start(metric: CostMetric) -> Self {
        Self {
            metric,
            started: Instant::now(),
        }
    }
}

impl Drop for CostTimer {
    fn drop(&mut self) {
        add_current_cost(self.metric, duration_micros(self.started.elapsed()));
    }
}

fn duration_micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FaultBoundary {
    StorageBefore,
    StorageAfter,
    ReplicationBefore,
    ReplicationAfter,
    DurabilityBefore,
    DurabilityAfter,
    PublicationBefore,
    PublicationAfter,
    StateApplicationBefore,
    StateApplicationAfter,
}

impl FaultBoundary {
    pub const ALL: [Self; 10] = [
        Self::StorageBefore,
        Self::StorageAfter,
        Self::ReplicationBefore,
        Self::ReplicationAfter,
        Self::DurabilityBefore,
        Self::DurabilityAfter,
        Self::PublicationBefore,
        Self::PublicationAfter,
        Self::StateApplicationBefore,
        Self::StateApplicationAfter,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultAction {
    Continue,
    Fail,
    Delay(Duration),
}

pub trait FaultInjector: Send + Sync + 'static {
    fn action(&self, operation: OperationContext, boundary: FaultBoundary) -> FaultAction;
}

#[derive(Debug, Default)]
pub struct NoFaults;

impl FaultInjector for NoFaults {
    fn action(&self, _operation: OperationContext, _boundary: FaultBoundary) -> FaultAction {
        FaultAction::Continue
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("fault injected at {boundary:?} for operation {operation_id}")]
pub struct InjectedFault {
    pub operation_id: OperationId,
    pub boundary: FaultBoundary,
}

pub async fn apply_fault(
    injector: &dyn FaultInjector,
    boundary: FaultBoundary,
) -> Result<(), InjectedFault> {
    let Some(scope) = current_operation() else {
        return Ok(());
    };
    match injector.action(scope.context(), boundary) {
        FaultAction::Continue => Ok(()),
        FaultAction::Fail => Err(InjectedFault {
            operation_id: scope.context().id,
            boundary,
        }),
        FaultAction::Delay(duration) => {
            tokio::time::sleep(duration).await;
            Ok(())
        }
    }
}

pub async fn apply_current_fault(boundary: FaultBoundary) -> Result<(), InjectedFault> {
    let Some(scope) = current_operation() else {
        return Ok(());
    };
    match scope.fault_injector.action(scope.context(), boundary) {
        FaultAction::Continue => Ok(()),
        FaultAction::Fail => Err(InjectedFault {
            operation_id: scope.context().id,
            boundary,
        }),
        FaultAction::Delay(duration) => {
            tokio::time::sleep(duration).await;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::hint::black_box;

    #[test]
    fn operation_id_round_trips_through_json_and_header_form() {
        let id = OperationId::generate();
        let encoded = id.to_string();
        assert_eq!(encoded.len(), 32);
        assert_eq!(OperationId::parse(&encoded), Ok(id));
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<OperationId>(&json).unwrap(), id);
        assert!(matches!(
            OperationId::parse("short"),
            Err(ParseOperationIdError::Length(5))
        ));
        assert!(matches!(
            OperationId::parse("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
            Err(ParseOperationIdError::Hex)
        ));
    }

    #[test]
    fn workload_and_metric_labels_are_closed_and_unique() {
        let workloads = WorkloadClass::ALL
            .into_iter()
            .map(WorkloadClass::as_label)
            .collect::<BTreeSet<_>>();
        let metrics = CostMetric::ALL
            .into_iter()
            .map(CostMetric::as_label)
            .collect::<BTreeSet<_>>();
        assert_eq!(workloads.len(), WorkloadClass::ALL.len());
        assert_eq!(metrics.len(), CostMetric::ALL.len());
        assert!(!workloads.iter().any(|label| label.contains('{')));
        assert!(!metrics.iter().any(|label| label.contains('{')));
    }

    #[test]
    fn work_keys_are_stable_delimited_and_redacted() {
        let first = WorkKey::combine(&[b"tenant", b"object"]);
        let same = WorkKey::combine(&[b"tenant", b"object"]);
        let ambiguous_without_lengths = WorkKey::combine(&[b"ten", b"antobject"]);
        assert_eq!(first, same);
        assert_ne!(first, ambiguous_without_lengths);
        assert_eq!(format!("{first:?}"), "WorkKey(<opaque>)");
    }

    #[tokio::test]
    async fn operation_identity_and_cost_follow_cross_layer_flow() {
        let incoming =
            OperationId::parse("00112233445566778899aabbccddeeff").expect("valid fixture");
        for class in [
            WorkloadClass::S3Put,
            WorkloadClass::FilesystemCommit,
            WorkloadClass::SqliteCommit,
            WorkloadClass::KafkaProduce,
        ] {
            let operations_before = process_metrics().get(class, CostMetric::Operations);
            let storage_bytes_before = process_metrics().get(class, CostMetric::StorageBytes);
            let scope =
                OperationScope::begin(class, WorkKey::from_bytes(b"same-work"), Some(incoming));
            let observed = scope_operation(scope.clone(), async {
                let id_at_ingress = current_operation().unwrap().context().id;
                observe_current_stage(OperationStage::Ingress);
                add_current_cost(CostMetric::QueueMicroseconds, 2);
                observe_current_stage(OperationStage::OwnerQueue);
                let id_at_owner = current_operation().unwrap().context().id;
                observe_current_stage(OperationStage::OwnerExecution);
                add_current_cost(CostMetric::OwnedBytes, 4096);
                observe_current_stage(OperationStage::Storage);
                add_current_cost(CostMetric::StorageOperations, 1);
                add_current_cost(CostMetric::StorageBytes, 4096);
                let id_at_storage = current_operation().unwrap().context().id;
                observe_current_stage(OperationStage::Replication);
                add_current_cost(CostMetric::PeerBytes, 8192);
                observe_current_stage(OperationStage::Durability);
                add_current_cost(CostMetric::DurabilityBarriers, 1);
                observe_current_stage(OperationStage::Publication);
                observe_current_stage(OperationStage::StateApplication);
                add_current_cost(CostMetric::StateMachineOperations, 1);
                add_current_cost(CostMetric::StateMachineEntries, 1);
                observe_current_stage(OperationStage::Response);
                [id_at_ingress, id_at_owner, id_at_storage]
            })
            .await;
            assert!(observed.into_iter().all(|id| id == incoming));
            scope.finish(true);
            assert_eq!(
                process_metrics().get(class, CostMetric::Operations) - operations_before,
                1
            );
            assert_eq!(
                process_metrics().get(class, CostMetric::StorageBytes) - storage_bytes_before,
                4096
            );
            assert!(
                OperationStage::ALL
                    .into_iter()
                    .all(|stage| scope.observed(stage))
            );
        }
    }

    struct FailAt(FaultBoundary);

    impl FaultInjector for FailAt {
        fn action(&self, _operation: OperationContext, boundary: FaultBoundary) -> FaultAction {
            if boundary == self.0 {
                FaultAction::Fail
            } else {
                FaultAction::Continue
            }
        }
    }

    #[tokio::test]
    async fn every_fault_boundary_preserves_operation_identity() {
        for boundary in FaultBoundary::ALL {
            let scope = OperationScope::begin_with_faults(
                WorkloadClass::Unknown,
                WorkKey::from_bytes(b"filesystem"),
                None,
                Arc::new(FailAt(boundary)),
            );
            let expected = scope.context().id;
            let error = scope_operation(scope.clone(), async {
                apply_current_fault(boundary).await.unwrap_err()
            })
            .await;
            assert_eq!(error.operation_id, expected);
            assert_eq!(error.boundary, boundary);
            scope.finish(false);
        }
    }

    #[test]
    fn prometheus_output_has_only_bounded_labels() {
        let metrics = OperationMetrics::default();
        metrics.add(WorkloadClass::S3Put, CostMetric::OwnedBytes, 42);
        let output = metrics.render_prometheus();
        assert!(output.contains(
            "pepper_operation_cost_total{workload=\"s3_put\",metric=\"owned_bytes\"} 42"
        ));
        assert_eq!(
            output
                .lines()
                .filter(|line| line.starts_with("pepper_operation_cost_total{"))
                .count(),
            WORKLOAD_COUNT * METRIC_COUNT
        );
    }

    #[derive(Serialize)]
    struct OverheadCell {
        throughput_operations_per_second: f64,
        p99_microseconds: f64,
    }

    fn overhead_cell(payload: &[u8], iterations: usize, enabled: bool) -> OverheadCell {
        let started = Instant::now();
        let mut latencies = Vec::with_capacity(iterations);
        for iteration in 0..iterations {
            let operation_started = Instant::now();
            if enabled {
                let scope = OperationScope::begin(
                    WorkloadClass::S3Put,
                    WorkKey::from_bytes(&(iteration as u64).to_le_bytes()),
                    None,
                );
                scope.add(CostMetric::OwnedBytes, payload.len() as u64);
                scope.observe(OperationStage::Ingress);
                black_box(blake3::hash(black_box(payload)));
                scope.observe(OperationStage::Storage);
                scope.finish(true);
            } else {
                black_box(blake3::hash(black_box(payload)));
            }
            latencies.push(operation_started.elapsed().as_nanos() as u64);
        }
        let elapsed = started.elapsed().as_secs_f64();
        latencies.sort_unstable();
        let p99_index = ((latencies.len() - 1) as f64 * 0.99).round() as usize;
        OverheadCell {
            throughput_operations_per_second: iterations as f64 / elapsed,
            p99_microseconds: latencies[p99_index] as f64 / 1_000.0,
        }
    }

    fn median(values: &mut [f64]) -> f64 {
        values.sort_by(f64::total_cmp);
        values[values.len() / 2]
    }

    #[test]
    #[ignore = "release-mode Phase 1 observability overhead qualification"]
    #[allow(clippy::assertions_on_constants)]
    fn phase1_observability_overhead() {
        assert!(
            !cfg!(debug_assertions),
            "overhead qualification must run with --release"
        );
        let iterations = std::env::var("PEPPER_OBSERVABILITY_OVERHEAD_ITERATIONS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(2_000)
            .max(100);
        let trials = std::env::var("PEPPER_OBSERVABILITY_OVERHEAD_TRIALS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(7)
            .max(3);
        let payload = vec![0x5au8; 1024 * 1024];
        let mut baseline = Vec::with_capacity(trials);
        let mut enabled = Vec::with_capacity(trials);
        for trial in 0..trials {
            if trial % 2 == 0 {
                baseline.push(overhead_cell(&payload, iterations, false));
                enabled.push(overhead_cell(&payload, iterations, true));
            } else {
                enabled.push(overhead_cell(&payload, iterations, true));
                baseline.push(overhead_cell(&payload, iterations, false));
            }
        }
        let baseline_throughput = median(
            &mut baseline
                .iter()
                .map(|cell| cell.throughput_operations_per_second)
                .collect::<Vec<_>>(),
        );
        let enabled_throughput = median(
            &mut enabled
                .iter()
                .map(|cell| cell.throughput_operations_per_second)
                .collect::<Vec<_>>(),
        );
        let baseline_p99 = median(
            &mut baseline
                .iter()
                .map(|cell| cell.p99_microseconds)
                .collect::<Vec<_>>(),
        );
        let enabled_p99 = median(
            &mut enabled
                .iter()
                .map(|cell| cell.p99_microseconds)
                .collect::<Vec<_>>(),
        );
        let throughput_overhead_percent =
            ((baseline_throughput - enabled_throughput) / baseline_throughput * 100.0).max(0.0);
        let p99_overhead_percent = ((enabled_p99 - baseline_p99) / baseline_p99 * 100.0).max(0.0);
        let report = serde_json::json!({
            "schema_version": 1,
            "payload_bytes": payload.len(),
            "iterations_per_trial": iterations,
            "trials": trials,
            "baseline": {
                "median_throughput_operations_per_second": baseline_throughput,
                "median_p99_microseconds": baseline_p99,
            },
            "observability_enabled": {
                "median_throughput_operations_per_second": enabled_throughput,
                "median_p99_microseconds": enabled_p99,
            },
            "throughput_overhead_percent": throughput_overhead_percent,
            "p99_overhead_percent": p99_overhead_percent,
            "passes_3_percent_gate": throughput_overhead_percent < 3.0 && p99_overhead_percent < 3.0,
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        assert!(
            throughput_overhead_percent < 3.0,
            "throughput overhead {throughput_overhead_percent:.3}% exceeds 3%"
        );
        assert!(
            p99_overhead_percent < 3.0,
            "p99 overhead {p99_overhead_percent:.3}% exceeds 3%"
        );
    }
}
