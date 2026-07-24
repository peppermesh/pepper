// SPDX-License-Identifier: Apache-2.0

//! Metric counters and Prometheus rendering boundary.

use super::*;

pub(super) static COMPUTE_SCHEDULED_LOCAL: AtomicU64 = AtomicU64::new(0);
pub(super) static COMPUTE_SCHEDULED_REMOTE: AtomicU64 = AtomicU64::new(0);
pub(super) static COMPUTE_SCHEDULE_RETRIES: AtomicU64 = AtomicU64::new(0);
pub(super) static FIRECRACKER_VM_STARTS: AtomicU64 = AtomicU64::new(0);
pub(super) static FIRECRACKER_VM_SUCCESSES: AtomicU64 = AtomicU64::new(0);
pub(super) static FIRECRACKER_VM_FAILURES: AtomicU64 = AtomicU64::new(0);
pub(super) static FIRECRACKER_ROOTFS_VALIDATION_FAILURES: AtomicU64 = AtomicU64::new(0);
pub(super) static FIRECRACKER_VSOCK_CANCEL_DELIVERED: AtomicU64 = AtomicU64::new(0);
pub(super) static FIRECRACKER_VSOCK_CANCEL_ACKS: AtomicU64 = AtomicU64::new(0);
pub(super) static FIRECRACKER_VSOCK_CANCEL_FALLBACKS: AtomicU64 = AtomicU64::new(0);
pub(super) static FIRECRACKER_JAILER_SETUP_FAILURES: AtomicU64 = AtomicU64::new(0);
pub(super) static FIRECRACKER_OUTPUT_EXTRACTION_FAILURES: AtomicU64 = AtomicU64::new(0);
pub(super) static FIRECRACKER_HEARTBEATS: AtomicU64 = AtomicU64::new(0);
pub(super) static FIRECRACKER_HEARTBEAT_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
pub(super) static SQLITE_COMMITS: AtomicU64 = AtomicU64::new(0);
pub(super) static SQLITE_COMMIT_FAILURES: AtomicU64 = AtomicU64::new(0);
pub(super) static SQLITE_PAGE_READS: AtomicU64 = AtomicU64::new(0);
pub(super) static SQLITE_PAGE_READ_BYTES: AtomicU64 = AtomicU64::new(0);
pub(super) static SQLITE_PAGE_PACK_WRITES: AtomicU64 = AtomicU64::new(0);
pub(super) static SQLITE_PAGE_PACK_WRITE_BYTES: AtomicU64 = AtomicU64::new(0);
pub(super) static SQLITE_EC_PAGE_PACK_WRITES: AtomicU64 = AtomicU64::new(0);
pub(super) static SQLITE_PAGE_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
pub(super) static SQLITE_PAGE_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
pub(super) static SQLITE_COMPACTIONS: AtomicU64 = AtomicU64::new(0);
pub(super) static SQLITE_COMPACTION_FAILURES: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_OBJECT_WRITES: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_OBJECT_READS: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_SHARD_REPAIRS: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_SHARD_REBALANCES: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_RECONSTRUCTION_FAILURES: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_REPAIR_THROTTLE_MICROS: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_STRIPES_ENCODED: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_STRIPES_COMPRESSED: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_STRIPE_LOGICAL_BYTES: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_STRIPE_ENCODED_BYTES: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_STRIPE_ENCODING_MICROS: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_SHARD_READ_HEDGES: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_SHARD_FETCH_EWMA_MICROS: AtomicU64 = AtomicU64::new(10_000);
pub(super) static ERASURE_ACTIVE_STRIPE_READS: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_READ_ADMISSION_QUEUE_MICROS: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_READ_ADMISSION_OBSERVATIONS: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_ZERO_COPY_STREAMED_BYTES: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_STREAMED_DECOMPRESSION_BYTES: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_SYSTEMATIC_RANGE_BYTES: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_COMMITS: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_COMMIT_FAILURES: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_CONFLICTS: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_DURABILITY_FAILURES: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_COMMIT_LATENCY_MICROS: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_READS: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_READ_LATENCY_MICROS: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_GROUP_ADMISSION_FAILURES: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_REQUEST_STREAMING_PHASES: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_REQUEST_STREAMING_MICROS: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_BLOCK_HASH_STORAGE_PHASES: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_BLOCK_HASH_STORAGE_MICROS: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_REPLICA_TRANSFER_PHASES: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_REPLICA_TRANSFER_MICROS: AtomicU64 = AtomicU64::new(0);
pub(super) static EXPLICIT_PAYLOAD_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
pub(super) static EXPLICIT_PAYLOAD_ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
pub(super) static EXPLICIT_PAYLOAD_COPY_OPERATIONS: AtomicU64 = AtomicU64::new(0);
pub(super) static EXPLICIT_PAYLOAD_COPY_BYTES: AtomicU64 = AtomicU64::new(0);
pub(super) static SHARED_PAYLOAD_REFERENCES: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_WRITE_ADMISSION_REJECTIONS: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_WRITE_ADMISSION_QUEUE_MICROS: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_HTTP_ADMISSION_REJECTIONS: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_LIST_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_LIST_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_LIST_CACHE_COALESCED: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_PARTITION_ROUTES: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_LIST_BARRIERS: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_LIST_PARTITIONS_SCANNED: AtomicU64 = AtomicU64::new(0);
pub(super) static S3_PARTITION_RECONFIGURATIONS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_CALCULATIONS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_DIRECT_TARGET_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_DIRECT_TARGET_ERRORS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_DIRECT_TARGET_BYTES: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_EXCEPTION_HITS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_MAP_REFRESHES: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_MAP_REFRESH_FAILURES: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_INVENTORY_EVENTS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_INVENTORY_PUSH_ERRORS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_HEALTH_BATCHES: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_HEALTH_BLOCKS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_HEALTH_BATCH_ERRORS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_OWNER_RUNS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_STANDBY_DEFERRALS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_LEASES_ACQUIRED: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_LEASE_RENEWALS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_LEASE_CONFLICTS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_FENCE_REJECTIONS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_TASKS_STARTED: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_TASKS_COMPLETED: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_TASKS_ALREADY_HEALTHY: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_TASK_ERRORS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_DESTINATION_RECONSTRUCTIONS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_TEMPORARY_EXCEPTIONS: AtomicU64 = AtomicU64::new(0);
pub(super) static PLACEMENT_REPAIR_STALE_EXTRAS_COLLECTED: AtomicU64 = AtomicU64::new(0);
pub(super) static SMALL_OBJECT_PACK_EXTENTS_WRITTEN: AtomicU64 = AtomicU64::new(0);
pub(super) static SMALL_OBJECT_PACK_EXTENT_BYTES: AtomicU64 = AtomicU64::new(0);
pub(super) static SMALL_OBJECT_PACK_RECORDS_TRANSITIONED: AtomicU64 = AtomicU64::new(0);
pub(super) static SMALL_OBJECT_PACK_LOGICAL_BYTES_TRANSITIONED: AtomicU64 = AtomicU64::new(0);
pub(super) static SMALL_OBJECT_PACK_EXTENTS_COMPACTED: AtomicU64 = AtomicU64::new(0);
pub(super) static SMALL_OBJECT_PACK_RECORDS_COMPACTED: AtomicU64 = AtomicU64::new(0);
pub(super) static SMALL_OBJECT_PACK_BYTES_RECLAIMED: AtomicU64 = AtomicU64::new(0);
pub(super) static SMALL_OBJECT_PACK_INDEX_HITS: AtomicU64 = AtomicU64::new(0);
pub(super) static SMALL_OBJECT_PACK_INDEX_MISSES: AtomicU64 = AtomicU64::new(0);
pub(super) static SMALL_OBJECT_PACK_FAILURES: AtomicU64 = AtomicU64::new(0);

pub(super) fn observe_phase(counter: &AtomicU64, total_micros: &AtomicU64, elapsed: Duration) {
    counter.fetch_add(1, Ordering::Relaxed);
    total_micros.fetch_add(
        elapsed.as_micros().min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
}

pub(super) fn observe_payload_allocation(bytes: usize) {
    EXPLICIT_PAYLOAD_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    EXPLICIT_PAYLOAD_ALLOCATED_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    add_current_cost(OperationCostMetric::OwnedBytes, bytes as u64);
}

pub(super) fn observe_payload_copy(bytes: usize) {
    EXPLICIT_PAYLOAD_COPY_OPERATIONS.fetch_add(1, Ordering::Relaxed);
    EXPLICIT_PAYLOAD_COPY_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    add_current_cost(OperationCostMetric::CopyOperations, 1);
    add_current_cost(OperationCostMetric::CopyBytes, bytes as u64);
}

pub(super) fn observe_shared_payload_reference() {
    SHARED_PAYLOAD_REFERENCES.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn record_erasure_stripe_encoding(
    logical_bytes: u64,
    encoded_bytes: u64,
    encoding: ErasureStripeEncoding,
    elapsed: Duration,
) {
    ERASURE_STRIPES_ENCODED.fetch_add(1, Ordering::Relaxed);
    if encoding == ErasureStripeEncoding::Zstd {
        ERASURE_STRIPES_COMPRESSED.fetch_add(1, Ordering::Relaxed);
    }
    ERASURE_STRIPE_LOGICAL_BYTES.fetch_add(logical_bytes, Ordering::Relaxed);
    ERASURE_STRIPE_ENCODED_BYTES.fetch_add(encoded_bytes, Ordering::Relaxed);
    ERASURE_STRIPE_ENCODING_MICROS.fetch_add(
        elapsed.as_micros().min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
}

pub(super) struct NamespaceReadTimer(std::time::Instant);
impl NamespaceReadTimer {
    pub(super) fn start() -> Self {
        Self(std::time::Instant::now())
    }
}
impl Drop for NamespaceReadTimer {
    fn drop(&mut self) {
        NAMESPACE_READS.fetch_add(1, Ordering::Relaxed);
        NAMESPACE_READ_LATENCY_MICROS.fetch_add(
            self.0.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
    }
}

pub(super) async fn metrics(State(state): State<AppState>) -> Response {
    let uptime_seconds = (OffsetDateTime::now_utc() - state.status.started_at)
        .whole_seconds()
        .max(0);
    let queue_depth = compute_queue_depth(&state).unwrap_or(0);
    let mut body = format!(
        "# HELP pepper_agent_uptime_seconds Agent uptime in seconds.\n\
         # TYPE pepper_agent_uptime_seconds gauge\n\
         pepper_agent_uptime_seconds {uptime_seconds}\n\
         # HELP pepper_metadata_schema_version Local metadata schema version.\n\
         # TYPE pepper_metadata_schema_version gauge\n\
         pepper_metadata_schema_version {}\n\
         # HELP pepper_compute_queue_depth Queued or delegated compute jobs.\n\
         # TYPE pepper_compute_queue_depth gauge\n\
         pepper_compute_queue_depth {queue_depth}\n\
         # HELP pepper_compute_scheduled_local_total Compute jobs scheduled on this node.\n\
         # TYPE pepper_compute_scheduled_local_total counter\n\
         pepper_compute_scheduled_local_total {}\n\
         # HELP pepper_compute_scheduled_remote_total Compute jobs scheduled on a peer.\n\
         # TYPE pepper_compute_scheduled_remote_total counter\n\
         pepper_compute_scheduled_remote_total {}\n\
         # HELP pepper_compute_schedule_retries_total Failed remote scheduling attempts.\n\
         # TYPE pepper_compute_schedule_retries_total counter\n\
         pepper_compute_schedule_retries_total {}\n\
         # HELP pepper_firecracker_vm_starts_total Firecracker VM starts attempted.\n\
         # TYPE pepper_firecracker_vm_starts_total counter\n\
         pepper_firecracker_vm_starts_total {}\n\
         # HELP pepper_firecracker_vm_successes_total Firecracker VMs that completed successfully.\n\
         # TYPE pepper_firecracker_vm_successes_total counter\n\
         pepper_firecracker_vm_successes_total {}\n\
         # HELP pepper_firecracker_vm_failures_total Firecracker VM failures.\n\
         # TYPE pepper_firecracker_vm_failures_total counter\n\
         pepper_firecracker_vm_failures_total {}\n\
         # HELP pepper_firecracker_rootfs_validation_failures_total Firecracker rootfs validation failures.\n\
         # TYPE pepper_firecracker_rootfs_validation_failures_total counter\n\
         pepper_firecracker_rootfs_validation_failures_total {}\n\
         # HELP pepper_firecracker_vsock_cancel_delivered_total Firecracker cancel requests delivered over vsock.\n\
         # TYPE pepper_firecracker_vsock_cancel_delivered_total counter\n\
         pepper_firecracker_vsock_cancel_delivered_total {}\n\
         # HELP pepper_firecracker_vsock_cancel_acks_total Firecracker cancel acknowledgements received over vsock.\n\
         # TYPE pepper_firecracker_vsock_cancel_acks_total counter\n\
         pepper_firecracker_vsock_cancel_acks_total {}\n\
         # HELP pepper_firecracker_vsock_cancel_fallbacks_total Firecracker cancels that fell back after vsock failure.\n\
         # TYPE pepper_firecracker_vsock_cancel_fallbacks_total counter\n\
         pepper_firecracker_vsock_cancel_fallbacks_total {}\n\
         # HELP pepper_firecracker_jailer_setup_failures_total Firecracker jailer setup failures.\n\
         # TYPE pepper_firecracker_jailer_setup_failures_total counter\n\
         pepper_firecracker_jailer_setup_failures_total {}\n\
         # HELP pepper_firecracker_output_extraction_failures_total Firecracker output extraction failures.\n\
         # TYPE pepper_firecracker_output_extraction_failures_total counter\n\
         pepper_firecracker_output_extraction_failures_total {}\n\
         # HELP pepper_firecracker_heartbeats_total Firecracker guest heartbeat/status responses received.\n\
         # TYPE pepper_firecracker_heartbeats_total counter\n\
         pepper_firecracker_heartbeats_total {}\n\
         # HELP pepper_firecracker_heartbeat_timeouts_total Firecracker heartbeat/job timeout failures.\n\
         # TYPE pepper_firecracker_heartbeat_timeouts_total counter\n\
         pepper_firecracker_heartbeat_timeouts_total {}\n\
         # HELP pepper_erasure_object_writes_total Erasure-coded objects written.\n\
         # TYPE pepper_erasure_object_writes_total counter\n\
         pepper_erasure_object_writes_total {}\n\
         # HELP pepper_erasure_object_reads_total Erasure-coded objects reconstructed for reads.\n\
         # TYPE pepper_erasure_object_reads_total counter\n\
         pepper_erasure_object_reads_total {}\n\
         # HELP pepper_erasure_shard_repairs_total Erasure shards repaired.\n\
         # TYPE pepper_erasure_shard_repairs_total counter\n\
         pepper_erasure_shard_repairs_total {}\n\
         # HELP pepper_erasure_shard_rebalances_total Erasure shards proactively copied to preferred placement targets.\n\
         # TYPE pepper_erasure_shard_rebalances_total counter\n\
         pepper_erasure_shard_rebalances_total {}\n\
         # HELP pepper_erasure_reconstruction_failures_total Erasure reconstruction failures.\n\
         # TYPE pepper_erasure_reconstruction_failures_total counter\n\
         pepper_erasure_reconstruction_failures_total {}\n\
         # HELP pepper_erasure_repair_throttle_microseconds_total Time deliberately reserved for foreground work by the repair bandwidth limiter.\n\
         # TYPE pepper_erasure_repair_throttle_microseconds_total counter\n\
         pepper_erasure_repair_throttle_microseconds_total {}\n\
         # HELP pepper_erasure_stripes_encoded_total Erasure stripes encoded.\n\
         # TYPE pepper_erasure_stripes_encoded_total counter\n\
         pepper_erasure_stripes_encoded_total {}\n\
         # HELP pepper_erasure_stripes_compressed_total Erasure stripes compressed before Reed-Solomon encoding.\n\
         # TYPE pepper_erasure_stripes_compressed_total counter\n\
         pepper_erasure_stripes_compressed_total {}\n\
         # HELP pepper_erasure_stripe_logical_bytes_total Logical bytes entering erasure stripe encoding.\n\
         # TYPE pepper_erasure_stripe_logical_bytes_total counter\n\
         pepper_erasure_stripe_logical_bytes_total {}\n\
         # HELP pepper_erasure_stripe_encoded_bytes_total Bytes entering Reed-Solomon after optional compression.\n\
         # TYPE pepper_erasure_stripe_encoded_bytes_total counter\n\
         pepper_erasure_stripe_encoded_bytes_total {}\n\
         # HELP pepper_erasure_stripe_encoding_microseconds_total Time spent probing, compressing, and erasure encoding stripes.\n\
         # TYPE pepper_erasure_stripe_encoding_microseconds_total counter\n\
         pepper_erasure_stripe_encoding_microseconds_total {}\n\
         # HELP pepper_erasure_shard_read_hedges_total Speculative parity fetches issued after the dynamic shard delay.\n\
         # TYPE pepper_erasure_shard_read_hedges_total counter\n\
         pepper_erasure_shard_read_hedges_total {}\n\
         # HELP pepper_erasure_shard_fetch_ewma_microseconds Dynamic shard-fetch latency estimate used for hedging.\n\
         # TYPE pepper_erasure_shard_fetch_ewma_microseconds gauge\n\
         pepper_erasure_shard_fetch_ewma_microseconds {}\n\
         # HELP pepper_erasure_active_stripe_reads Current cache-miss stripe reads.\n\
         # TYPE pepper_erasure_active_stripe_reads gauge\n\
         pepper_erasure_active_stripe_reads {}\n\
         # HELP pepper_erasure_read_admission_queue_microseconds_total Time stripe reads waited for bounded data-plane admission.\n\
         # TYPE pepper_erasure_read_admission_queue_microseconds_total counter\n\
         pepper_erasure_read_admission_queue_microseconds_total {}\n\
         # HELP pepper_erasure_read_admission_observations_total Stripe reads admitted by the bounded data-plane scheduler.\n\
         # TYPE pepper_erasure_read_admission_observations_total counter\n\
         pepper_erasure_read_admission_observations_total {}\n\
         # HELP pepper_erasure_zero_copy_streamed_bytes_total Verified raw systematic bytes streamed without stripe concatenation.\n\
         # TYPE pepper_erasure_zero_copy_streamed_bytes_total counter\n\
         pepper_erasure_zero_copy_streamed_bytes_total {}\n\
         # HELP pepper_erasure_streamed_decompression_bytes_total Verified logical bytes decompressed from shard slices into response frames.\n\
         # TYPE pepper_erasure_streamed_decompression_bytes_total counter\n\
         pepper_erasure_streamed_decompression_bytes_total {}\n\
         # HELP pepper_erasure_systematic_range_bytes_total Raw range bytes served directly from systematic shards without full-stripe reconstruction.\n\
         # TYPE pepper_erasure_systematic_range_bytes_total counter\n\
         pepper_erasure_systematic_range_bytes_total {}\n",
        state.status.schema_version,
        COMPUTE_SCHEDULED_LOCAL.load(Ordering::Relaxed),
        COMPUTE_SCHEDULED_REMOTE.load(Ordering::Relaxed),
        COMPUTE_SCHEDULE_RETRIES.load(Ordering::Relaxed),
        FIRECRACKER_VM_STARTS.load(Ordering::Relaxed),
        FIRECRACKER_VM_SUCCESSES.load(Ordering::Relaxed),
        FIRECRACKER_VM_FAILURES.load(Ordering::Relaxed),
        FIRECRACKER_ROOTFS_VALIDATION_FAILURES.load(Ordering::Relaxed),
        FIRECRACKER_VSOCK_CANCEL_DELIVERED.load(Ordering::Relaxed),
        FIRECRACKER_VSOCK_CANCEL_ACKS.load(Ordering::Relaxed),
        FIRECRACKER_VSOCK_CANCEL_FALLBACKS.load(Ordering::Relaxed),
        FIRECRACKER_JAILER_SETUP_FAILURES.load(Ordering::Relaxed),
        FIRECRACKER_OUTPUT_EXTRACTION_FAILURES.load(Ordering::Relaxed),
        FIRECRACKER_HEARTBEATS.load(Ordering::Relaxed),
        FIRECRACKER_HEARTBEAT_TIMEOUTS.load(Ordering::Relaxed),
        ERASURE_OBJECT_WRITES.load(Ordering::Relaxed),
        ERASURE_OBJECT_READS.load(Ordering::Relaxed),
        ERASURE_SHARD_REPAIRS.load(Ordering::Relaxed),
        ERASURE_SHARD_REBALANCES.load(Ordering::Relaxed),
        ERASURE_RECONSTRUCTION_FAILURES.load(Ordering::Relaxed),
        ERASURE_REPAIR_THROTTLE_MICROS.load(Ordering::Relaxed),
        ERASURE_STRIPES_ENCODED.load(Ordering::Relaxed),
        ERASURE_STRIPES_COMPRESSED.load(Ordering::Relaxed),
        ERASURE_STRIPE_LOGICAL_BYTES.load(Ordering::Relaxed),
        ERASURE_STRIPE_ENCODED_BYTES.load(Ordering::Relaxed),
        ERASURE_STRIPE_ENCODING_MICROS.load(Ordering::Relaxed),
        ERASURE_SHARD_READ_HEDGES.load(Ordering::Relaxed),
        ERASURE_SHARD_FETCH_EWMA_MICROS.load(Ordering::Relaxed),
        ERASURE_ACTIVE_STRIPE_READS.load(Ordering::Relaxed),
        ERASURE_READ_ADMISSION_QUEUE_MICROS.load(Ordering::Relaxed),
        ERASURE_READ_ADMISSION_OBSERVATIONS.load(Ordering::Relaxed),
        ERASURE_ZERO_COPY_STREAMED_BYTES.load(Ordering::Relaxed),
        ERASURE_STREAMED_DECOMPRESSION_BYTES.load(Ordering::Relaxed),
        ERASURE_SYSTEMATIC_RANGE_BYTES.load(Ordering::Relaxed)
    );
    body.push_str(&format!(
        "# HELP pepper_s3_partition_routes_total S3 object operations routed to one committed bucket partition.\n\
         # TYPE pepper_s3_partition_routes_total counter\n\
         pepper_s3_partition_routes_total {}\n\
         # HELP pepper_s3_list_barriers_total Cross-partition S3 LIST root vectors committed by the bucket control group.\n\
         # TYPE pepper_s3_list_barriers_total counter\n\
         pepper_s3_list_barriers_total {}\n\
         # HELP pepper_s3_list_partitions_scanned_total Partition roots scanned by cross-partition S3 LIST requests.\n\
         # TYPE pepper_s3_list_partitions_scanned_total counter\n\
         pepper_s3_list_partitions_scanned_total {}\n\
         # HELP pepper_s3_partition_reconfigurations_total Successful explicit bucket split, merge, move, or abort operations.\n\
         # TYPE pepper_s3_partition_reconfigurations_total counter\n\
         pepper_s3_partition_reconfigurations_total {}\n",
        S3_PARTITION_ROUTES.load(Ordering::Relaxed),
        S3_LIST_BARRIERS.load(Ordering::Relaxed),
        S3_LIST_PARTITIONS_SCANNED.load(Ordering::Relaxed),
        S3_PARTITION_RECONFIGURATIONS.load(Ordering::Relaxed),
    ));
    let commit_count = NAMESPACE_COMMITS.load(Ordering::Relaxed);
    let read_count = NAMESPACE_READS.load(Ordering::Relaxed);
    let (merkle, merkle_mutations) = pepper_merkle::process_io_stats();
    let storage = pepper_storage::process_io_stats();
    let storage_encoding = pepper_storage::process_encoding_stats();
    let native_storage = pepper_storage::process_native_stats();
    let consensus_io = pepper_consensus::process_io_stats();
    let normal_block_batches = block_batch_stats(false);
    let replica_block_batches = block_batch_stats(true);
    let publication_phases = pepper_publication::process_phase_stats();
    let publication = state
        .publication_repository
        .operational_stats(unix_seconds())
        .ok();
    body.push_str(&format!(
        "# HELP pepper_namespace_commits_total Successfully published namespace commands.\n\
         # TYPE pepper_namespace_commits_total counter\npepper_namespace_commits_total {commit_count}\n\
         # HELP pepper_namespace_commit_failures_total Failed namespace publications.\n\
         # TYPE pepper_namespace_commit_failures_total counter\npepper_namespace_commit_failures_total {}\n\
         # HELP pepper_namespace_conflicts_total Namespace generation and idempotency conflicts.\n\
         # TYPE pepper_namespace_conflicts_total counter\npepper_namespace_conflicts_total {}\n\
         # HELP pepper_namespace_durability_failures_total Namespace durability barrier failures.\n\
         # TYPE pepper_namespace_durability_failures_total counter\npepper_namespace_durability_failures_total {}\n\
         # HELP pepper_namespace_commit_latency_microseconds_total Cumulative namespace publication latency.\n\
         # TYPE pepper_namespace_commit_latency_microseconds_total counter\npepper_namespace_commit_latency_microseconds_total {}\n\
         # HELP pepper_namespace_commit_latency_microseconds_avg Process-lifetime average namespace publication latency.\n\
         # TYPE pepper_namespace_commit_latency_microseconds_avg gauge\npepper_namespace_commit_latency_microseconds_avg {}\n\
         # HELP pepper_namespace_reads_total Namespace read resolutions.\n\
         # TYPE pepper_namespace_reads_total counter\npepper_namespace_reads_total {read_count}\n\
         # HELP pepper_namespace_read_latency_microseconds_avg Process-lifetime average namespace read latency.\n\
         # TYPE pepper_namespace_read_latency_microseconds_avg gauge\npepper_namespace_read_latency_microseconds_avg {}\n\
         # HELP pepper_namespace_read_latency_microseconds_total Cumulative namespace read latency.\n\
         # TYPE pepper_namespace_read_latency_microseconds_total counter\npepper_namespace_read_latency_microseconds_total {}\n\
         # HELP pepper_namespace_group_admission_failures_total Namespace group admission failures.\n\
         # TYPE pepper_namespace_group_admission_failures_total counter\npepper_namespace_group_admission_failures_total {}\n\
         # HELP pepper_merkle_nodes_read_total Merkle nodes decoded by this process.\n\
         # TYPE pepper_merkle_nodes_read_total counter\npepper_merkle_nodes_read_total {}\n\
         # HELP pepper_merkle_nodes_written_total Merkle node writes by this process.\n\
         # TYPE pepper_merkle_nodes_written_total counter\npepper_merkle_nodes_written_total {}\n\
         # HELP pepper_merkle_mutations_total Merkle mutations applied by this process.\n\
         # TYPE pepper_merkle_mutations_total counter\npepper_merkle_mutations_total {merkle_mutations}\n\
         # HELP pepper_storage_block_reads_total Successful block-store reads by this process.\n\
         # TYPE pepper_storage_block_reads_total counter\npepper_storage_block_reads_total {}\n\
         # HELP pepper_storage_block_read_bytes_total Physical envelope and payload bytes read or materialized by successful block-store reads.\n\
         # TYPE pepper_storage_block_read_bytes_total counter\npepper_storage_block_read_bytes_total {}\n\
         # HELP pepper_storage_inline_block_writes_total Small internal blocks committed inline with block metadata.\n\
         # TYPE pepper_storage_inline_block_writes_total counter\npepper_storage_inline_block_writes_total {}\n\
         # HELP pepper_storage_inline_block_write_bytes_total Encoded bytes committed in inline internal blocks.\n\
         # TYPE pepper_storage_inline_block_write_bytes_total counter\npepper_storage_inline_block_write_bytes_total {}\n\
         # HELP pepper_storage_packed_block_writes_total Content-addressed records appended to the small-object segment log.\n\
         # TYPE pepper_storage_packed_block_writes_total counter\npepper_storage_packed_block_writes_total {}\n\
         # HELP pepper_storage_packed_block_write_bytes_total Encoded record bytes appended to the small-object segment log.\n\
         # TYPE pepper_storage_packed_block_write_bytes_total counter\npepper_storage_packed_block_write_bytes_total {}\n\
         # HELP pepper_storage_packed_block_reads_total Small-object segment record reads.\n\
         # TYPE pepper_storage_packed_block_reads_total counter\npepper_storage_packed_block_reads_total {}\n\
         # HELP pepper_storage_packed_block_read_bytes_total Verified bytes materialized by small-object segment reads.\n\
         # TYPE pepper_storage_packed_block_read_bytes_total counter\npepper_storage_packed_block_read_bytes_total {}\n\
         # HELP pepper_storage_data_durability_barriers_total Filesystem data and metadata durability barriers completed by block batches.\n\
         # TYPE pepper_storage_data_durability_barriers_total counter\npepper_storage_data_durability_barriers_total {}\n\
         # HELP pepper_storage_data_files_durable_total File-backed blocks covered by data durability barriers.\n\
         # TYPE pepper_storage_data_files_durable_total counter\npepper_storage_data_files_durable_total {}\n\
         # HELP pepper_storage_directory_durability_barriers_total Directory durability barriers completed after block renames.\n\
         # TYPE pepper_storage_directory_durability_barriers_total counter\npepper_storage_directory_durability_barriers_total {}\n\
         # HELP pepper_storage_block_encoding_attempts_total Blocks evaluated for physical encoding.\n\
         # TYPE pepper_storage_block_encoding_attempts_total counter\npepper_storage_block_encoding_attempts_total {}\n\
         # HELP pepper_storage_block_encoding_blocks_total Selected physical block encodings.\n\
         # TYPE pepper_storage_block_encoding_blocks_total counter\n\
         pepper_storage_block_encoding_blocks_total{{encoding=\"raw\"}} {}\n\
         pepper_storage_block_encoding_blocks_total{{encoding=\"zstd\"}} {}\n\
         # HELP pepper_storage_block_encoding_bytes_total Logical and encoded bytes produced by block encoding attempts.\n\
         # TYPE pepper_storage_block_encoding_bytes_total counter\n\
         pepper_storage_block_encoding_bytes_total{{kind=\"logical\"}} {}\n\
         pepper_storage_block_encoding_bytes_total{{kind=\"stored\"}} {}\n\
         # HELP pepper_storage_block_encoding_microseconds_total Time spent choosing and producing block encodings.\n\
         # TYPE pepper_storage_block_encoding_microseconds_total counter\npepper_storage_block_encoding_microseconds_total {}\n\
         # HELP pepper_block_write_batch_requests_total Block writes submitted to the group-commit coordinator.\n\
         # TYPE pepper_block_write_batch_requests_total counter\n\
         pepper_block_write_batch_requests_total{{intent=\"normal\"}} {}\n\
         pepper_block_write_batch_requests_total{{intent=\"replica\"}} {}\n\
         # HELP pepper_block_write_batches_total Durable block-store batch executions.\n\
         # TYPE pepper_block_write_batches_total counter\n\
         pepper_block_write_batches_total{{intent=\"normal\"}} {}\n\
         pepper_block_write_batches_total{{intent=\"replica\"}} {}\n\
         # TYPE pepper_block_write_coalesced_batches_total counter\n\
         pepper_block_write_coalesced_batches_total{{intent=\"normal\"}} {}\n\
         pepper_block_write_coalesced_batches_total{{intent=\"replica\"}} {}\n\
         # TYPE pepper_block_write_batch_size_max gauge\n\
         pepper_block_write_batch_size_max{{intent=\"normal\"}} {}\n\
         pepper_block_write_batch_size_max{{intent=\"replica\"}} {}\n\
         # TYPE pepper_block_write_queue_microseconds_total counter\n\
         pepper_block_write_queue_microseconds_total{{intent=\"normal\"}} {}\n\
         pepper_block_write_queue_microseconds_total{{intent=\"replica\"}} {}\n\
         # TYPE pepper_block_write_execution_microseconds_total counter\n\
         pepper_block_write_execution_microseconds_total{{intent=\"normal\"}} {}\n\
         pepper_block_write_execution_microseconds_total{{intent=\"replica\"}} {}\n\
         # HELP pepper_raft_storage_operations_total Durable Raft storage operations by phase.\n\
         # TYPE pepper_raft_storage_operations_total counter\n\
         pepper_raft_storage_operations_total{{phase=\"log_append\"}} {}\n\
         pepper_raft_storage_operations_total{{phase=\"state_apply\"}} {}\n\
         # HELP pepper_raft_storage_entries_total Raft entries handled by durable storage phase.\n\
         # TYPE pepper_raft_storage_entries_total counter\n\
         pepper_raft_storage_entries_total{{phase=\"log_append\"}} {}\n\
         pepper_raft_storage_entries_total{{phase=\"state_apply\"}} {}\n\
         # HELP pepper_raft_storage_queue_microseconds_total Time awaiting the namespace Raft I/O lock.\n\
         # TYPE pepper_raft_storage_queue_microseconds_total counter\n\
         pepper_raft_storage_queue_microseconds_total{{phase=\"log_append\"}} {}\n\
         pepper_raft_storage_queue_microseconds_total{{phase=\"state_apply\"}} {}\n\
         # HELP pepper_raft_storage_execution_microseconds_total Time executing durable Raft storage work after admission.\n\
         # TYPE pepper_raft_storage_execution_microseconds_total counter\n\
         pepper_raft_storage_execution_microseconds_total{{phase=\"log_append\"}} {}\n\
         pepper_raft_storage_execution_microseconds_total{{phase=\"state_apply\"}} {}\n\
         # HELP pepper_raft_proposal_requests_total Namespace commands submitted to the ordered proposal batcher.\n\
         # TYPE pepper_raft_proposal_requests_total counter\n\
         pepper_raft_proposal_requests_total {}\n\
         # HELP pepper_raft_proposal_batches_total Raft proposals emitted by the ordered proposal batcher.\n\
         # TYPE pepper_raft_proposal_batches_total counter\n\
         pepper_raft_proposal_batches_total {}\n\
         # TYPE pepper_raft_proposal_batch_size_max gauge\n\
         pepper_raft_proposal_batch_size_max {}\n\
         # TYPE pepper_raft_proposal_queue_microseconds_total counter\n\
         pepper_raft_proposal_queue_microseconds_total {}\n\
         # TYPE pepper_raft_proposal_execution_microseconds_total counter\n\
         pepper_raft_proposal_execution_microseconds_total {}\n\
         # HELP pepper_namespace_linearizable_reads_total Linearizable namespace reads by confirmation path.\n\
         # TYPE pepper_namespace_linearizable_reads_total counter\n\
         pepper_namespace_linearizable_reads_total{{path=\"leader_lease\"}} {}\n\
         pepper_namespace_linearizable_reads_total{{path=\"quorum_proof\"}} {}\n\
         # HELP pepper_s3_put_phase_duration_microseconds_total Cumulative S3 PUT phase time.\n\
         # TYPE pepper_s3_put_phase_duration_microseconds_total counter\n\
         pepper_s3_put_phase_duration_microseconds_total{{phase=\"request_streaming\"}} {}\n\
         pepper_s3_put_phase_duration_microseconds_total{{phase=\"block_hash_storage\"}} {}\n\
         pepper_s3_put_phase_duration_microseconds_total{{phase=\"replica_transfer\"}} {}\n\
         pepper_s3_put_phase_duration_microseconds_total{{phase=\"durability_fsync_barrier\"}} {}\n\
         pepper_s3_put_phase_duration_microseconds_total{{phase=\"merkle_update\"}} {}\n\
         pepper_s3_put_phase_duration_microseconds_total{{phase=\"raft_namespace_publication\"}} {}\n\
         # HELP pepper_s3_put_phase_observations_total Number of S3 PUT phase observations.\n\
         # TYPE pepper_s3_put_phase_observations_total counter\n\
         pepper_s3_put_phase_observations_total{{phase=\"request_streaming\"}} {}\n\
         pepper_s3_put_phase_observations_total{{phase=\"block_hash_storage\"}} {}\n\
         pepper_s3_put_phase_observations_total{{phase=\"replica_transfer\"}} {}\n\
         pepper_s3_put_phase_observations_total{{phase=\"durability_fsync_barrier\"}} {}\n\
         pepper_s3_put_phase_observations_total{{phase=\"merkle_update\"}} {}\n\
         pepper_s3_put_phase_observations_total{{phase=\"raft_namespace_publication\"}} {}\n\
         # HELP pepper_explicit_payload_allocations_total Explicit full or partial payload-buffer allocations at reviewed product boundaries.\n\
         # TYPE pepper_explicit_payload_allocations_total counter\n\
         pepper_explicit_payload_allocations_total {}\n\
         # HELP pepper_explicit_payload_allocated_bytes_total Capacity bytes requested by reviewed explicit payload-buffer allocations.\n\
         # TYPE pepper_explicit_payload_allocated_bytes_total counter\n\
         pepper_explicit_payload_allocated_bytes_total {}\n\
         # HELP pepper_explicit_payload_copy_operations_total Reviewed explicit payload copy operations.\n\
         # TYPE pepper_explicit_payload_copy_operations_total counter\n\
         pepper_explicit_payload_copy_operations_total {}\n\
         # HELP pepper_explicit_payload_copy_bytes_total Bytes passed through reviewed explicit payload copy operations.\n\
         # TYPE pepper_explicit_payload_copy_bytes_total counter\n\
         pepper_explicit_payload_copy_bytes_total {}\n\
         # HELP pepper_shared_payload_references_total Reference-counted payload handles created without copying payload bytes.\n\
         # TYPE pepper_shared_payload_references_total counter\n\
         pepper_shared_payload_references_total {}\n\
         # HELP pepper_namespace_durability_receipt_sources_total Durability receipts by verification source.\n\
         # TYPE pepper_namespace_durability_receipt_sources_total counter\n\
         pepper_namespace_durability_receipt_sources_total{{source=\"preverified\"}} {}\n\
         pepper_namespace_durability_receipt_sources_total{{source=\"cache\"}} {}\n\
         pepper_namespace_durability_receipt_sources_total{{source=\"backend\"}} {}\n\
         # TYPE pepper_namespace_durability_preverified_rejections_total counter\n\
         pepper_namespace_durability_preverified_rejections_total{{reason=\"missing\"}} {}\n\
         pepper_namespace_durability_preverified_rejections_total{{reason=\"invalid\"}} {}\n",
        NAMESPACE_COMMIT_FAILURES.load(Ordering::Relaxed),
        NAMESPACE_CONFLICTS.load(Ordering::Relaxed),
        NAMESPACE_DURABILITY_FAILURES.load(Ordering::Relaxed),
        NAMESPACE_COMMIT_LATENCY_MICROS.load(Ordering::Relaxed),
        NAMESPACE_COMMIT_LATENCY_MICROS.load(Ordering::Relaxed) / commit_count.max(1),
        NAMESPACE_READ_LATENCY_MICROS.load(Ordering::Relaxed) / read_count.max(1),
        NAMESPACE_READ_LATENCY_MICROS.load(Ordering::Relaxed),
        NAMESPACE_GROUP_ADMISSION_FAILURES.load(Ordering::Relaxed),
        merkle.nodes_read,
        merkle.nodes_written,
        storage.block_reads,
        storage.block_read_bytes,
        storage.inline_block_writes,
        storage.inline_block_write_bytes,
        storage.packed_block_writes,
        storage.packed_block_write_bytes,
        storage.packed_block_reads,
        storage.packed_block_read_bytes,
        storage.data_durability_barriers,
        storage.data_files_durable,
        storage.directory_durability_barriers,
        storage_encoding.attempts,
        storage_encoding.raw_blocks,
        storage_encoding.zstd_blocks,
        storage_encoding.logical_bytes,
        storage_encoding.stored_bytes,
        storage_encoding.encoding_micros,
        normal_block_batches.requests,
        replica_block_batches.requests,
        normal_block_batches.batches,
        replica_block_batches.batches,
        normal_block_batches.coalesced_batches,
        replica_block_batches.coalesced_batches,
        normal_block_batches.max_batch_size,
        replica_block_batches.max_batch_size,
        normal_block_batches.queue_micros,
        replica_block_batches.queue_micros,
        normal_block_batches.execution_micros,
        replica_block_batches.execution_micros,
        consensus_io.log_append_observations,
        consensus_io.state_apply_observations,
        consensus_io.log_append_entries,
        consensus_io.state_apply_entries,
        consensus_io.log_append_queue_micros,
        consensus_io.state_apply_queue_micros,
        consensus_io.log_append_execution_micros,
        consensus_io.state_apply_execution_micros,
        consensus_io.proposal_requests,
        consensus_io.proposal_batches,
        consensus_io.proposal_batch_size_max,
        consensus_io.proposal_queue_micros,
        consensus_io.proposal_execution_micros,
        consensus_io.linearizable_read_lease_hits,
        consensus_io.linearizable_read_proofs,
        S3_REQUEST_STREAMING_MICROS.load(Ordering::Relaxed),
        S3_BLOCK_HASH_STORAGE_MICROS.load(Ordering::Relaxed),
        S3_REPLICA_TRANSFER_MICROS.load(Ordering::Relaxed),
        publication_phases.durability_micros,
        publication_phases.merkle_update_micros,
        publication_phases.raft_publication_micros,
        S3_REQUEST_STREAMING_PHASES.load(Ordering::Relaxed),
        S3_BLOCK_HASH_STORAGE_PHASES.load(Ordering::Relaxed),
        S3_REPLICA_TRANSFER_PHASES.load(Ordering::Relaxed),
        publication_phases.durability_observations,
        publication_phases.merkle_update_observations,
        publication_phases.raft_publication_observations,
        EXPLICIT_PAYLOAD_ALLOCATIONS.load(Ordering::Relaxed),
        EXPLICIT_PAYLOAD_ALLOCATED_BYTES.load(Ordering::Relaxed),
        EXPLICIT_PAYLOAD_COPY_OPERATIONS.load(Ordering::Relaxed),
        EXPLICIT_PAYLOAD_COPY_BYTES.load(Ordering::Relaxed),
        SHARED_PAYLOAD_REFERENCES.load(Ordering::Relaxed),
        publication_phases.durability_preverified_receipts,
        publication_phases.durability_cached_receipts,
        publication_phases.durability_backend_receipts,
        publication_phases.durability_missing_preverified_receipts,
        publication_phases.durability_invalid_preverified_receipts,
    ));
    body.push_str(&format!(
        "# HELP pepper_commit_engine_transitions_total Shared prepared-artifact commit transitions by stage.\n\
         # TYPE pepper_commit_engine_transitions_total counter\n\
         pepper_commit_engine_transitions_total{{stage=\"prepared\"}} {}\n\
         pepper_commit_engine_transitions_total{{stage=\"staged\"}} {}\n\
         pepper_commit_engine_transitions_total{{stage=\"durable\"}} {}\n\
         pepper_commit_engine_transitions_total{{stage=\"proposed\"}} {}\n\
         pepper_commit_engine_transitions_total{{stage=\"ambiguous\"}} {}\n\
         pepper_commit_engine_transitions_total{{stage=\"recovered\"}} {}\n\
         pepper_commit_engine_transitions_total{{stage=\"reconciled\"}} {}\n\
         pepper_commit_engine_transitions_total{{stage=\"finalized\"}} {}\n",
        publication_phases.commit_engine_prepared,
        publication_phases.commit_engine_staged,
        publication_phases.commit_engine_durable,
        publication_phases.commit_engine_proposed,
        publication_phases.commit_engine_ambiguous,
        publication_phases.commit_engine_recovered,
        publication_phases.commit_engine_reconciled,
        publication_phases.commit_engine_finalized,
    ));
    body.push_str(&format!(
        "# HELP pepper_storage_native_writes_total Records durably appended by the native segment backend.\n\
         # TYPE pepper_storage_native_writes_total counter\npepper_storage_native_writes_total {}\n\
         # HELP pepper_storage_native_write_bytes_total Encoded payload bytes appended by the native segment backend.\n\
         # TYPE pepper_storage_native_write_bytes_total counter\npepper_storage_native_write_bytes_total {}\n\
         # HELP pepper_storage_native_reads_total Native segment payload read operations.\n\
         # TYPE pepper_storage_native_reads_total counter\npepper_storage_native_reads_total {}\n\
         # HELP pepper_storage_native_read_bytes_total Aligned physical bytes read from native segments.\n\
         # TYPE pepper_storage_native_read_bytes_total counter\npepper_storage_native_read_bytes_total {}\n\
         # HELP pepper_storage_native_durability_barriers_total Native segment durability barriers completed.\n\
         # TYPE pepper_storage_native_durability_barriers_total counter\npepper_storage_native_durability_barriers_total {}\n\
         # HELP pepper_storage_native_durability_groups_total Native cross-request durability groups completed.\n\
         # TYPE pepper_storage_native_durability_groups_total counter\npepper_storage_native_durability_groups_total {}\n\
         # HELP pepper_storage_native_durability_group_requests_total Storage requests joined to native durability groups.\n\
         # TYPE pepper_storage_native_durability_group_requests_total counter\npepper_storage_native_durability_group_requests_total {}\n\
         # HELP pepper_storage_native_io_uring_submissions_total Native read, write, and fsync operations submitted through io_uring.\n\
         # TYPE pepper_storage_native_io_uring_submissions_total counter\npepper_storage_native_io_uring_submissions_total {}\n\
         # HELP pepper_storage_native_sync_fallbacks_total Native owner queues that fell back because io_uring was unavailable.\n\
         # TYPE pepper_storage_native_sync_fallbacks_total counter\npepper_storage_native_sync_fallbacks_total {}\n\
         # HELP pepper_storage_native_recovered_records_total Committed native records reconstructed during startup.\n\
         # TYPE pepper_storage_native_recovered_records_total counter\npepper_storage_native_recovered_records_total {}\n\
         # HELP pepper_storage_native_torn_tails_total Invalid or uncommitted native segment tails discarded during recovery.\n\
         # TYPE pepper_storage_native_torn_tails_total counter\npepper_storage_native_torn_tails_total {}\n\
         # HELP pepper_storage_native_compactions_total Completed native segment compaction passes.\n\
         # TYPE pepper_storage_native_compactions_total counter\npepper_storage_native_compactions_total {}\n\
         # HELP pepper_storage_native_compacted_bytes_total Live encoded bytes rewritten by native compaction.\n\
         # TYPE pepper_storage_native_compacted_bytes_total counter\npepper_storage_native_compacted_bytes_total {}\n",
        native_storage.writes,
        native_storage.write_bytes,
        native_storage.reads,
        native_storage.read_bytes,
        native_storage.durability_barriers,
        native_storage.durability_groups,
        native_storage.durability_group_requests,
        native_storage.uring_submissions,
        native_storage.sync_fallbacks,
        native_storage.recovered_records,
        native_storage.torn_tails,
        native_storage.compactions,
        native_storage.compacted_bytes,
    ));
    let cache = reconstructed_cache::process_stats();
    body.push_str(&format!(
        "# HELP pepper_reconstructed_cache_requests_total Reconstructed stripe cache lookups by result.\n\
         # TYPE pepper_reconstructed_cache_requests_total counter\n\
         pepper_reconstructed_cache_requests_total{{result=\"hit\"}} {}\n\
         pepper_reconstructed_cache_requests_total{{result=\"miss\"}} {}\n\
         # HELP pepper_reconstructed_cache_admissions_total Verified reconstructed stripes admitted to the cache.\n\
         # TYPE pepper_reconstructed_cache_admissions_total counter\n\
         pepper_reconstructed_cache_admissions_total {}\n\
         # HELP pepper_reconstructed_cache_evictions_total Reconstructed cache capacity evictions.\n\
         # TYPE pepper_reconstructed_cache_evictions_total counter\n\
         pepper_reconstructed_cache_evictions_total {}\n\
         # HELP pepper_reconstructed_cache_bypasses_total Reconstructed stripes bypassed by admission or capacity policy.\n\
         # TYPE pepper_reconstructed_cache_bypasses_total counter\n\
         pepper_reconstructed_cache_bypasses_total {}\n\
         # HELP pepper_reconstructed_cache_integrity_failures_total Invalid cached stripes removed.\n\
         # TYPE pepper_reconstructed_cache_integrity_failures_total counter\n\
         pepper_reconstructed_cache_integrity_failures_total {}\n\
         # HELP pepper_reconstructed_cache_bytes_total Reconstructed cache data-plane bytes.\n\
         # TYPE pepper_reconstructed_cache_bytes_total counter\n\
         pepper_reconstructed_cache_bytes_total{{direction=\"read\"}} {}\n\
         pepper_reconstructed_cache_bytes_total{{direction=\"write\"}} {}\n\
         # HELP pepper_s3_write_admission_rejections_total S3 writes rejected before work because the bounded admission wait expired.\n\
         # TYPE pepper_s3_write_admission_rejections_total counter\n\
         pepper_s3_write_admission_rejections_total {}\n\
         # HELP pepper_s3_write_admission_queue_microseconds_total Time admitted S3 writes spent waiting for a pipeline slot.\n\
         # TYPE pepper_s3_write_admission_queue_microseconds_total counter\n\
         pepper_s3_write_admission_queue_microseconds_total {}\n\
         # HELP pepper_s3_write_service_ewma_microseconds Current S3 write-pipeline service-time EWMA used for Retry-After.\n\
         # TYPE pepper_s3_write_service_ewma_microseconds gauge\n\
         pepper_s3_write_service_ewma_microseconds {}\n\
         # HELP pepper_s3_http_admission_rejections_total S3 requests rejected before dispatch because the response-lifetime concurrency bound was full.\n\
         # TYPE pepper_s3_http_admission_rejections_total counter\n\
         pepper_s3_http_admission_rejections_total {}\n\
         # HELP pepper_s3_list_cache_hits_total S3 LIST results served from the immutable namespace-root cache.\n\
         # TYPE pepper_s3_list_cache_hits_total counter\n\
         pepper_s3_list_cache_hits_total {}\n\
         # HELP pepper_s3_list_cache_misses_total S3 LIST results built for a new namespace-root and query.\n\
         # TYPE pepper_s3_list_cache_misses_total counter\n\
         pepper_s3_list_cache_misses_total {}\n\
         # HELP pepper_s3_list_cache_coalesced_total S3 LIST requests joined to an in-flight identical immutable scan.\n\
         # TYPE pepper_s3_list_cache_coalesced_total counter\n\
         pepper_s3_list_cache_coalesced_total {}\n",
        cache.hits,
        cache.misses,
        cache.admissions,
        cache.evictions,
        cache.bypasses,
        cache.integrity_failures,
        cache.read_bytes,
        cache.write_bytes,
        S3_WRITE_ADMISSION_REJECTIONS.load(Ordering::Relaxed),
        S3_WRITE_ADMISSION_QUEUE_MICROS.load(Ordering::Relaxed),
        state.s3_write_service_micros.load(Ordering::Relaxed),
        S3_HTTP_ADMISSION_REJECTIONS.load(Ordering::Relaxed),
        S3_LIST_CACHE_HITS.load(Ordering::Relaxed),
        S3_LIST_CACHE_MISSES.load(Ordering::Relaxed),
        S3_LIST_CACHE_COALESCED.load(Ordering::Relaxed),
        ));
    body.push_str(&format!(
        "# HELP pepper_placement_calculations_total Deterministic authoritative placement calculations.\n\
         # TYPE pepper_placement_calculations_total counter\n\
         pepper_placement_calculations_total {}\n\
         # HELP pepper_placement_direct_target_attempts_total Direct requests to computed data owners.\n\
         # TYPE pepper_placement_direct_target_attempts_total counter\n\
         pepper_placement_direct_target_attempts_total {}\n\
         # HELP pepper_placement_direct_target_errors_total Failed direct requests to computed data owners.\n\
         # TYPE pepper_placement_direct_target_errors_total counter\n\
         pepper_placement_direct_target_errors_total {}\n\
         # HELP pepper_placement_direct_target_bytes_total Verified bytes received from or sent to computed owners.\n\
         # TYPE pepper_placement_direct_target_bytes_total counter\n\
         pepper_placement_direct_target_bytes_total {}\n\
         # HELP pepper_placement_exception_hits_total Reads that consulted an active committed placement exception.\n\
         # TYPE pepper_placement_exception_hits_total counter\n\
         pepper_placement_exception_hits_total {}\n\
         # HELP pepper_placement_map_refreshes_total Successful background placement-control refreshes.\n\
         # TYPE pepper_placement_map_refreshes_total counter\n\
         pepper_placement_map_refreshes_total {}\n\
         # HELP pepper_placement_map_refresh_failures_total Failed background placement-control refreshes.\n\
         # TYPE pepper_placement_map_refresh_failures_total counter\n\
         pepper_placement_map_refresh_failures_total {}\n\
         # HELP pepper_placement_repair_inventory_events_total Committed partition inventory deltas installed by repair owners.\n\
         # TYPE pepper_placement_repair_inventory_events_total counter\n\
         pepper_placement_repair_inventory_events_total {}\n\
         # HELP pepper_placement_repair_inventory_push_errors_total Failed owner or standby inventory deliveries.\n\
         # TYPE pepper_placement_repair_inventory_push_errors_total counter\n\
         pepper_placement_repair_inventory_push_errors_total {}\n\
         # HELP pepper_placement_repair_health_batches_total Bounded remote placement-health batches issued by repair passes.\n\
         # TYPE pepper_placement_repair_health_batches_total counter\n\
         pepper_placement_repair_health_batches_total {}\n\
         # HELP pepper_placement_repair_health_blocks_total Authoritative block placements covered by remote health batches.\n\
         # TYPE pepper_placement_repair_health_blocks_total counter\n\
         pepper_placement_repair_health_blocks_total {}\n\
         # HELP pepper_placement_repair_health_batch_errors_total Failed or timed-out remote placement-health batches.\n\
         # TYPE pepper_placement_repair_health_batch_errors_total counter\n\
         pepper_placement_repair_health_batch_errors_total {}\n\
         # HELP pepper_placement_repair_owner_runs_total Inventory records examined by their active authoritative owner.\n\
         # TYPE pepper_placement_repair_owner_runs_total counter\n\
         pepper_placement_repair_owner_runs_total {}\n\
         # HELP pepper_placement_repair_standby_deferrals_total Ordered standby delays before fenced lease contention.\n\
         # TYPE pepper_placement_repair_standby_deferrals_total counter\n\
         pepper_placement_repair_standby_deferrals_total {}\n\
         # HELP pepper_placement_repair_leases_acquired_total Committed repair leases or fence epochs acquired.\n\
         # TYPE pepper_placement_repair_leases_acquired_total counter\n\
         pepper_placement_repair_leases_acquired_total {}\n\
         # HELP pepper_placement_repair_lease_renewals_total Same-fence lease extensions for long-running repairs.\n\
         # TYPE pepper_placement_repair_lease_renewals_total counter\n\
         pepper_placement_repair_lease_renewals_total {}\n\
         # HELP pepper_placement_repair_lease_conflicts_total Concurrent lease attempts rejected by partition consensus.\n\
         # TYPE pepper_placement_repair_lease_conflicts_total counter\n\
         pepper_placement_repair_lease_conflicts_total {}\n\
         # HELP pepper_placement_repair_fence_rejections_total Destination executions rejected after their lease was superseded or expired.\n\
         # TYPE pepper_placement_repair_fence_rejections_total counter\n\
         pepper_placement_repair_fence_rejections_total {}\n\
         # HELP pepper_placement_repair_tasks_started_total Fenced repair tasks dispatched to canonical or explicit temporary destinations.\n\
         # TYPE pepper_placement_repair_tasks_started_total counter\n\
         pepper_placement_repair_tasks_started_total {}\n\
         # HELP pepper_placement_repair_tasks_completed_total Repair tasks that durably restored verified content.\n\
         # TYPE pepper_placement_repair_tasks_completed_total counter\n\
         pepper_placement_repair_tasks_completed_total {}\n\
         # HELP pepper_placement_repair_tasks_already_healthy_total Fenced tasks that found their destination already healthy.\n\
         # TYPE pepper_placement_repair_tasks_already_healthy_total counter\n\
         pepper_placement_repair_tasks_already_healthy_total {}\n\
         # HELP pepper_placement_repair_task_errors_total Placement-owned repair task failures.\n\
         # TYPE pepper_placement_repair_task_errors_total counter\n\
         pepper_placement_repair_task_errors_total {}\n\
         # HELP pepper_placement_repair_destination_reconstructions_total EC shards reconstructed on the destination rather than the coordinator.\n\
         # TYPE pepper_placement_repair_destination_reconstructions_total counter\n\
         pepper_placement_repair_destination_reconstructions_total {}\n\
         # HELP pepper_placement_repair_temporary_exceptions_total Explicit temporary placement records committed after owner loss.\n\
         # TYPE pepper_placement_repair_temporary_exceptions_total counter\n\
         pepper_placement_repair_temporary_exceptions_total {}\n\
         # HELP pepper_placement_repair_stale_extras_collected_total Expired temporary copies removed after canonical health was restored.\n\
         # TYPE pepper_placement_repair_stale_extras_collected_total counter\n\
         pepper_placement_repair_stale_extras_collected_total {}\n",
        PLACEMENT_CALCULATIONS.load(Ordering::Relaxed),
        PLACEMENT_DIRECT_TARGET_ATTEMPTS.load(Ordering::Relaxed),
        PLACEMENT_DIRECT_TARGET_ERRORS.load(Ordering::Relaxed),
        PLACEMENT_DIRECT_TARGET_BYTES.load(Ordering::Relaxed),
        PLACEMENT_EXCEPTION_HITS.load(Ordering::Relaxed),
        PLACEMENT_MAP_REFRESHES.load(Ordering::Relaxed),
        PLACEMENT_MAP_REFRESH_FAILURES.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_INVENTORY_EVENTS.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_INVENTORY_PUSH_ERRORS.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_HEALTH_BATCHES.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_HEALTH_BLOCKS.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_HEALTH_BATCH_ERRORS.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_OWNER_RUNS.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_STANDBY_DEFERRALS.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_LEASES_ACQUIRED.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_LEASE_RENEWALS.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_LEASE_CONFLICTS.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_FENCE_REJECTIONS.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_TASKS_STARTED.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_TASKS_COMPLETED.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_TASKS_ALREADY_HEALTHY.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_TASK_ERRORS.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_DESTINATION_RECONSTRUCTIONS.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_TEMPORARY_EXCEPTIONS.load(Ordering::Relaxed),
        PLACEMENT_REPAIR_STALE_EXTRAS_COLLECTED.load(Ordering::Relaxed),
    ));
    body.push_str(&format!(
        "# HELP pepper_small_object_pack_extents_written_total EC-protected small-object extents written.\n\
         # TYPE pepper_small_object_pack_extents_written_total counter\n\
         pepper_small_object_pack_extents_written_total {}\n\
         # HELP pepper_small_object_pack_extent_bytes_total Logical payload bytes encoded into small-object extents.\n\
         # TYPE pepper_small_object_pack_extent_bytes_total counter\n\
         pepper_small_object_pack_extent_bytes_total {}\n\
         # HELP pepper_small_object_pack_records_transitioned_total Replicated records atomically indexed into EC extents.\n\
         # TYPE pepper_small_object_pack_records_transitioned_total counter\n\
         pepper_small_object_pack_records_transitioned_total {}\n\
         # HELP pepper_small_object_pack_logical_bytes_transitioned_total Logical bytes made authoritative through extent indexes.\n\
         # TYPE pepper_small_object_pack_logical_bytes_transitioned_total counter\n\
         pepper_small_object_pack_logical_bytes_transitioned_total {}\n\
         # HELP pepper_small_object_pack_extents_compacted_total Partially dead EC extents atomically rewritten with live records only.\n\
         # TYPE pepper_small_object_pack_extents_compacted_total counter\n\
         pepper_small_object_pack_extents_compacted_total {}\n\
         # HELP pepper_small_object_pack_records_compacted_total Live records moved by EC extent compaction.\n\
         # TYPE pepper_small_object_pack_records_compacted_total counter\n\
         pepper_small_object_pack_records_compacted_total {}\n\
         # HELP pepper_small_object_pack_bytes_reclaimed_total Dead encoded bytes removed from authoritative EC extents.\n\
         # TYPE pepper_small_object_pack_bytes_reclaimed_total counter\n\
         pepper_small_object_pack_bytes_reclaimed_total {}\n\
         # HELP pepper_small_object_pack_index_hits_total Small-object reads resolved through a partition extent index.\n\
         # TYPE pepper_small_object_pack_index_hits_total counter\n\
         pepper_small_object_pack_index_hits_total {}\n\
         # HELP pepper_small_object_pack_index_misses_total Small-object reads served from their replicated staging record.\n\
         # TYPE pepper_small_object_pack_index_misses_total counter\n\
         pepper_small_object_pack_index_misses_total {}\n\
         # HELP pepper_small_object_pack_failures_total Background extent attempts that failed before an authoritative transition.\n\
         # TYPE pepper_small_object_pack_failures_total counter\n\
         pepper_small_object_pack_failures_total {}\n",
        SMALL_OBJECT_PACK_EXTENTS_WRITTEN.load(Ordering::Relaxed),
        SMALL_OBJECT_PACK_EXTENT_BYTES.load(Ordering::Relaxed),
        SMALL_OBJECT_PACK_RECORDS_TRANSITIONED.load(Ordering::Relaxed),
        SMALL_OBJECT_PACK_LOGICAL_BYTES_TRANSITIONED.load(Ordering::Relaxed),
        SMALL_OBJECT_PACK_EXTENTS_COMPACTED.load(Ordering::Relaxed),
        SMALL_OBJECT_PACK_RECORDS_COMPACTED.load(Ordering::Relaxed),
        SMALL_OBJECT_PACK_BYTES_RECLAIMED.load(Ordering::Relaxed),
        SMALL_OBJECT_PACK_INDEX_HITS.load(Ordering::Relaxed),
        SMALL_OBJECT_PACK_INDEX_MISSES.load(Ordering::Relaxed),
        SMALL_OBJECT_PACK_FAILURES.load(Ordering::Relaxed),
    ));
    if let Some(runtime) = &state.fast_path {
        let (dispatches, rejections, failovers, cross_core_hops) = runtime.totals();
        let governor = runtime.governor_snapshot();
        body.push_str(&format!(
            "# HELP pepper_fast_path_enabled Whether per-core S3 execution ownership is enabled.\n\
             # TYPE pepper_fast_path_enabled gauge\n\
             pepper_fast_path_enabled 1\n\
             # HELP pepper_fast_path_workers Number of per-core S3 owners.\n\
             # TYPE pepper_fast_path_workers gauge\n\
             pepper_fast_path_workers {}\n\
             # HELP pepper_fast_path_reserved_control_cores Cores reserved for Raft and control-plane work.\n\
             # TYPE pepper_fast_path_reserved_control_cores gauge\n\
             pepper_fast_path_reserved_control_cores {}\n\
             # HELP pepper_fast_path_cpu_pinning_enabled Whether control and owner threads are pinned to their assigned CPUs.\n\
             # TYPE pepper_fast_path_cpu_pinning_enabled gauge\n\
             pepper_fast_path_cpu_pinning_enabled {}\n\
             # HELP pepper_fast_path_dispatches_total Ordinary S3 requests handed to a stable owner.\n\
             # TYPE pepper_fast_path_dispatches_total counter\n\
             pepper_fast_path_dispatches_total {dispatches}\n\
             # HELP pepper_fast_path_rejections_total Requests rejected by a bounded owner queue.\n\
             # TYPE pepper_fast_path_rejections_total counter\n\
             pepper_fast_path_rejections_total {rejections}\n\
             # HELP pepper_fast_path_owner_failovers_total Requests sent to a standby owner because the preferred owner was unavailable.\n\
             # TYPE pepper_fast_path_owner_failovers_total counter\n\
             pepper_fast_path_owner_failovers_total {failovers}\n\
             # HELP pepper_fast_path_cross_core_hops_total Explicit request and response ownership transfers.\n\
             # TYPE pepper_fast_path_cross_core_hops_total counter\n\
             pepper_fast_path_cross_core_hops_total {cross_core_hops}\n\
             # HELP pepper_keyed_runtime_key_budget_rejections_total Operations rejected by a bounded per-key budget.\n\
             # TYPE pepper_keyed_runtime_key_budget_rejections_total counter\n\
             pepper_keyed_runtime_key_budget_rejections_total {}\n\
             # HELP pepper_keyed_runtime_remaps_total Safely drained key-slot ownership movements.\n\
             # TYPE pepper_keyed_runtime_remaps_total counter\n\
             pepper_keyed_runtime_remaps_total {}\n\
             # HELP pepper_keyed_runtime_draining_slots Key slots currently fenced while ownership moves.\n\
             # TYPE pepper_keyed_runtime_draining_slots gauge\n\
             pepper_keyed_runtime_draining_slots {}\n",
            runtime.owner_count(),
            runtime.reserved_control_cores(),
            u8::from(runtime.cpu_pinning_enabled()),
            governor.key_budget_rejections,
            governor.remaps,
            governor.draining_slots,
        ));
        body.push_str(
            "# TYPE pepper_fast_path_owner_healthy gauge\n\
             # TYPE pepper_fast_path_owner_cpu gauge\n\
             # TYPE pepper_fast_path_owner_data_port gauge\n\
             # TYPE pepper_fast_path_owner_queue_depth gauge\n\
             # TYPE pepper_fast_path_owner_requests_total counter\n\
             # TYPE pepper_fast_path_owner_active gauge\n\
             # TYPE pepper_fast_path_owner_queue_microseconds_total counter\n\
             # TYPE pepper_fast_path_owner_execution_microseconds_total counter\n\
             # TYPE pepper_fast_path_owner_response_bytes_total counter\n\
             # TYPE pepper_fast_path_owner_buffer_hits_total counter\n\
             # TYPE pepper_fast_path_owner_buffer_misses_total counter\n\
             # TYPE pepper_keyed_runtime_owner_queued gauge\n\
             # TYPE pepper_keyed_runtime_owner_active gauge\n\
             # TYPE pepper_keyed_runtime_owner_queue_microseconds_total counter\n\
             # TYPE pepper_keyed_runtime_owner_service_microseconds_total counter\n",
        );
        for owner in runtime.snapshots() {
            body.push_str(&format!(
                "pepper_fast_path_owner_healthy{{owner=\"{}\"}} {}\n\
                 pepper_fast_path_owner_cpu{{owner=\"{}\"}} {}\n\
                 pepper_fast_path_owner_data_port{{owner=\"{}\"}} {}\n\
                 pepper_fast_path_owner_queue_depth{{owner=\"{}\"}} {}\n\
                 pepper_fast_path_owner_requests_total{{owner=\"{}\"}} {}\n\
                 pepper_fast_path_owner_active{{owner=\"{}\"}} {}\n\
                 pepper_fast_path_owner_queue_microseconds_total{{owner=\"{}\"}} {}\n\
                 pepper_fast_path_owner_execution_microseconds_total{{owner=\"{}\"}} {}\n\
                 pepper_fast_path_owner_response_bytes_total{{owner=\"{}\"}} {}\n\
                 pepper_fast_path_owner_buffer_hits_total{{owner=\"{}\"}} {}\n\
                 pepper_fast_path_owner_buffer_misses_total{{owner=\"{}\"}} {}\n\
                 pepper_keyed_runtime_owner_queued{{owner=\"{}\",class=\"control\"}} {}\n\
                 pepper_keyed_runtime_owner_queued{{owner=\"{}\",class=\"foreground\"}} {}\n\
                 pepper_keyed_runtime_owner_queued{{owner=\"{}\",class=\"background\"}} {}\n\
                 pepper_keyed_runtime_owner_active{{owner=\"{}\",class=\"control\"}} {}\n\
                 pepper_keyed_runtime_owner_active{{owner=\"{}\",class=\"foreground\"}} {}\n\
                 pepper_keyed_runtime_owner_active{{owner=\"{}\",class=\"background\"}} {}\n\
                 pepper_keyed_runtime_owner_queue_microseconds_total{{owner=\"{}\"}} {}\n\
                 pepper_keyed_runtime_owner_service_microseconds_total{{owner=\"{}\"}} {}\n",
                owner.id,
                u8::from(owner.healthy),
                owner.id,
                owner.cpu_id,
                owner.id,
                owner.data_port,
                owner.id,
                owner.queue_depth,
                owner.id,
                owner.requests,
                owner.id,
                owner.active,
                owner.id,
                owner.queue_micros,
                owner.id,
                owner.execution_micros,
                owner.id,
                owner.response_bytes,
                owner.id,
                owner.buffer_hits,
                owner.id,
                owner.buffer_misses,
                owner.id,
                owner.scheduler_queued_by_class[0],
                owner.id,
                owner.scheduler_queued_by_class[1],
                owner.id,
                owner.scheduler_queued_by_class[2],
                owner.id,
                owner.scheduler_active_by_class[0],
                owner.id,
                owner.scheduler_active_by_class[1],
                owner.id,
                owner.scheduler_active_by_class[2],
                owner.id,
                owner.scheduler_queue_micros,
                owner.id,
                owner.scheduler_service_micros,
            ));
        }
    } else {
        body.push_str(
            "# HELP pepper_fast_path_enabled Whether per-core S3 execution ownership is enabled.\n\
             # TYPE pepper_fast_path_enabled gauge\n\
             pepper_fast_path_enabled 0\n",
        );
    }
    if let Some(publication) = publication {
        body.push_str(&format!(
            "# TYPE pepper_namespace_staging_leases gauge\npepper_namespace_staging_leases {}\n\
             # TYPE pepper_namespace_staging_bytes gauge\npepper_namespace_staging_bytes {}\n\
             # TYPE pepper_namespace_read_leases gauge\npepper_namespace_read_leases {}\n\
             # TYPE pepper_namespace_pending_pin_intents gauge\npepper_namespace_pending_pin_intents {}\n\
             # TYPE pepper_namespace_durability_receipts gauge\npepper_namespace_durability_receipts {}\n",
            publication.active_staging_leases,
            publication.active_staging_bytes,
            publication.active_read_leases,
            publication.pending_pin_intents,
            publication.durability_receipts,
        ));
    }
    if state.sqlite_enabled {
        let open_sessions = state
            .sqlite_sessions
            .lock()
            .map_or(0, |sessions| sessions.len());
        let writer_diagnostics = match &state.namespace_groups {
            Some(manager) => manager.sqlite_writer_diagnostics().await,
            None => Vec::new(),
        };
        let writer_waiters = writer_diagnostics
            .iter()
            .map(|diagnostic| diagnostic.waiters)
            .sum::<usize>();
        let active_writers = writer_diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.active)
            .count();
        body.push_str(&format!(
            "# HELP pepper_sqlite_enabled Whether the Pepper SQLite application is enabled.\n\
             # TYPE pepper_sqlite_enabled gauge\n\
             pepper_sqlite_enabled 1\n\
             # HELP pepper_sqlite_ready Whether the local SQLite socket/session runtime is ready.\n\
             # TYPE pepper_sqlite_ready gauge\n\
             pepper_sqlite_ready {}\n\
             # TYPE pepper_sqlite_open_sessions gauge\n\
             pepper_sqlite_open_sessions {}\n\
             # TYPE pepper_sqlite_active_writers gauge\n\
             pepper_sqlite_active_writers {}\n\
             # TYPE pepper_sqlite_writer_waiters gauge\n\
             pepper_sqlite_writer_waiters {}\n\
             # TYPE pepper_sqlite_commits_total counter\n\
             pepper_sqlite_commits_total {}\n\
             # TYPE pepper_sqlite_commit_failures_total counter\n\
             pepper_sqlite_commit_failures_total {}\n\
             # TYPE pepper_sqlite_page_reads_total counter\n\
             pepper_sqlite_page_reads_total {}\n\
             # TYPE pepper_sqlite_page_read_bytes_total counter\n\
             pepper_sqlite_page_read_bytes_total {}\n\
             # TYPE pepper_sqlite_page_pack_writes_total counter\n\
             pepper_sqlite_page_pack_writes_total {}\n\
             # TYPE pepper_sqlite_page_pack_write_bytes_total counter\n\
             pepper_sqlite_page_pack_write_bytes_total {}\n\
             # TYPE pepper_sqlite_ec_page_pack_writes_total counter\n\
             pepper_sqlite_ec_page_pack_writes_total {}\n\
             # TYPE pepper_sqlite_page_cache_hits_total counter\n\
             pepper_sqlite_page_cache_hits_total {}\n\
             # TYPE pepper_sqlite_page_cache_misses_total counter\n\
             pepper_sqlite_page_cache_misses_total {}\n\
             # TYPE pepper_sqlite_compactions_total counter\n\
             pepper_sqlite_compactions_total {}\n\
             # TYPE pepper_sqlite_compaction_failures_total counter\n\
             pepper_sqlite_compaction_failures_total {}\n\
             # TYPE pepper_sqlite_page_cache_bytes gauge\n\
             pepper_sqlite_page_cache_bytes {}\n",
            u8::from(state.sqlite_ready.load(Ordering::Relaxed)),
            open_sessions,
            active_writers,
            writer_waiters,
            SQLITE_COMMITS.load(Ordering::Relaxed),
            SQLITE_COMMIT_FAILURES.load(Ordering::Relaxed),
            SQLITE_PAGE_READS.load(Ordering::Relaxed),
            SQLITE_PAGE_READ_BYTES.load(Ordering::Relaxed),
            SQLITE_PAGE_PACK_WRITES.load(Ordering::Relaxed),
            SQLITE_PAGE_PACK_WRITE_BYTES.load(Ordering::Relaxed),
            SQLITE_EC_PAGE_PACK_WRITES.load(Ordering::Relaxed),
            SQLITE_PAGE_CACHE_HITS.load(Ordering::Relaxed),
            SQLITE_PAGE_CACHE_MISSES.load(Ordering::Relaxed),
            SQLITE_COMPACTIONS.load(Ordering::Relaxed),
            SQLITE_COMPACTION_FAILURES.load(Ordering::Relaxed),
            state.sqlite_pack_cache.current_bytes(),
        ));
    }
    let transport = state.network.transport_metrics();
    body.push_str(&format!(
        "# HELP pepper_transport_connections_active Active authenticated connections by isolated transport lane.\n\
         # TYPE pepper_transport_connections_active gauge\n\
         pepper_transport_connections_active{{lane=\"control\"}} {}\n\
         pepper_transport_connections_active{{lane=\"bulk\"}} {}\n\
         # TYPE pepper_transport_connections_total counter\n\
         pepper_transport_connections_total{{lane=\"control\"}} {}\n\
         pepper_transport_connections_total{{lane=\"bulk\"}} {}\n\
         # HELP pepper_transport_streams_active Active RPC streams by isolated transport lane.\n\
         # TYPE pepper_transport_streams_active gauge\n\
         pepper_transport_streams_active{{lane=\"control\"}} {}\n\
         pepper_transport_streams_active{{lane=\"bulk\"}} {}\n\
         # HELP pepper_transport_bulk_stream_capacity Bounded outbound bulk stream capacity for this data-plane endpoint.\n\
         # TYPE pepper_transport_bulk_stream_capacity gauge\n\
         pepper_transport_bulk_stream_capacity {}\n\
         # HELP pepper_transport_bulk_stream_queue_ewma_microseconds Recent time waiting for an outbound bulk stream slot.\n\
         # TYPE pepper_transport_bulk_stream_queue_ewma_microseconds gauge\n\
         pepper_transport_bulk_stream_queue_ewma_microseconds {}\n\
         # TYPE pepper_transport_streams_total counter\n\
         pepper_transport_streams_total{{lane=\"control\"}} {}\n\
         pepper_transport_streams_total{{lane=\"bulk\"}} {}\n\
         # TYPE pepper_transport_errors_total counter\n\
         pepper_transport_errors_total{{lane=\"control\"}} {}\n\
         pepper_transport_errors_total{{lane=\"bulk\"}} {}\n\
         # HELP pepper_transport_control_cancellations_total Losing hedged or raced control streams cancelled after another response completed.\n\
         # TYPE pepper_transport_control_cancellations_total counter\n\
         pepper_transport_control_cancellations_total {}\n\
         # HELP pepper_transport_bulk_cancellations_total Losing hedged or raced bulk streams cancelled after another replica completed.\n\
         # TYPE pepper_transport_bulk_cancellations_total counter\n\
         pepper_transport_bulk_cancellations_total {}\n\
         # HELP pepper_transport_bulk_bytes_total Raw payload bytes transferred outside protobuf envelopes.\n\
         # TYPE pepper_transport_bulk_bytes_total counter\n\
         pepper_transport_bulk_bytes_total{{direction=\"sent\"}} {}\n\
         pepper_transport_bulk_bytes_total{{direction=\"received\"}} {}\n\
         # TYPE pepper_transport_bulk_throttle_microseconds_total counter\n\
         pepper_transport_bulk_throttle_microseconds_total {}\n",
        transport.control_connections_active,
        transport.bulk_connections_active,
        transport.control_connections_total,
        transport.bulk_connections_total,
        transport.control_streams_active,
        transport.bulk_streams_active,
        transport.bulk_stream_capacity,
        transport.bulk_stream_queue_ewma_microseconds,
        transport.control_streams_total,
        transport.bulk_streams_total,
        transport.control_errors_total,
        transport.bulk_errors_total,
        transport.control_cancellations_total,
        transport.bulk_cancellations_total,
        transport.bulk_bytes_sent_total,
        transport.bulk_bytes_received_total,
        transport.bulk_throttle_microseconds_total,
    ));
    body.push_str(
        "# HELP pepper_erasure_transfer_plan_selected_total Request transfer plans selected after hysteresis.\n\
         # TYPE pepper_erasure_transfer_plan_selected_total counter\n\
         # TYPE pepper_erasure_transfer_plan_completed_total counter\n\
         # TYPE pepper_erasure_transfer_plan_failures_total counter\n\
         # TYPE pepper_erasure_transfer_plan_fallback_total counter\n\
         # TYPE pepper_erasure_transfer_plan_completion_microseconds_total counter\n\
         # TYPE pepper_erasure_transfer_plan_logical_bytes_total counter\n\
         # TYPE pepper_erasure_transfer_plan_gateway_bytes_total counter\n\
         # TYPE pepper_erasure_transfer_plan_internal_bytes_total counter\n\
         # TYPE pepper_erasure_transfer_plan_cross_domain_bytes_total counter\n",
    );
    let plan_metrics = state.erasure_planner.metrics();
    for (plan, metric) in EcTransferPlan::ALL.into_iter().zip(plan_metrics) {
        body.push_str(&format!(
            "pepper_erasure_transfer_plan_selected_total{{plan=\"{}\"}} {}\n\
             pepper_erasure_transfer_plan_completed_total{{plan=\"{}\"}} {}\n\
             pepper_erasure_transfer_plan_failures_total{{plan=\"{}\"}} {}\n\
             pepper_erasure_transfer_plan_fallback_total{{plan=\"{}\"}} {}\n\
             pepper_erasure_transfer_plan_completion_microseconds_total{{plan=\"{}\"}} {}\n\
             pepper_erasure_transfer_plan_logical_bytes_total{{plan=\"{}\"}} {}\n\
             pepper_erasure_transfer_plan_gateway_bytes_total{{plan=\"{}\"}} {}\n\
             pepper_erasure_transfer_plan_internal_bytes_total{{plan=\"{}\"}} {}\n\
             pepper_erasure_transfer_plan_cross_domain_bytes_total{{plan=\"{}\"}} {}\n",
            plan,
            metric.selected,
            plan,
            metric.completed,
            plan,
            metric.failures,
            plan,
            metric.fallback,
            plan,
            metric.completion_microseconds,
            plan,
            metric.logical_bytes,
            plan,
            metric.gateway_bytes,
            plan,
            metric.internal_bytes,
            plan,
            metric.cross_domain_bytes,
        ));
    }
    body.push_str(
        "# TYPE pepper_rpc_requests_total counter\n\
         # TYPE pepper_rpc_request_bytes_total counter\n\
         # TYPE pepper_rpc_response_bytes_total counter\n\
         # TYPE pepper_rpc_errors_total counter\n",
    );
    for metric in state.network.rpc_metrics() {
        body.push_str(&format!(
            "pepper_rpc_requests_total{{peer=\"{}\",method=\"{}\",direction=\"{}\"}} {}\n\
             pepper_rpc_request_bytes_total{{peer=\"{}\",method=\"{}\",direction=\"{}\"}} {}\n\
             pepper_rpc_response_bytes_total{{peer=\"{}\",method=\"{}\",direction=\"{}\"}} {}\n\
             pepper_rpc_errors_total{{peer=\"{}\",method=\"{}\",direction=\"{}\"}} {}\n",
            metric.peer_id,
            metric.method,
            metric.direction,
            metric.requests,
            metric.peer_id,
            metric.method,
            metric.direction,
            metric.request_bytes,
            metric.peer_id,
            metric.method,
            metric.direction,
            metric.response_bytes,
            metric.peer_id,
            metric.method,
            metric.direction,
            metric.errors,
        ));
    }
    body.push_str(
        "# TYPE pepper_raft_command_encoded_bytes_total counter\n\
         # TYPE pepper_raft_command_encoded_bytes_max gauge\n\
         # TYPE pepper_raft_commands_total counter\n",
    );
    if let Some(manager) = &state.namespace_groups {
        let statuses = manager.operational_statuses().await;
        body.push_str(&format!(
            "# TYPE pepper_namespace_groups_hosted gauge\n\
             pepper_namespace_groups_hosted {}\n\
             # HELP pepper_rsm_groups_hosted Product-neutral replicated state-machine groups hosted by this process.\n\
             # TYPE pepper_rsm_groups_hosted gauge\n\
             pepper_rsm_groups_hosted{{product=\"namespace\"}} {}\n\
             # HELP pepper_rsm_active_batch_runners Demand-driven proposal batch runners; idle groups retain none.\n\
             # TYPE pepper_rsm_active_batch_runners gauge\n\
             pepper_rsm_active_batch_runners{{product=\"namespace\"}} {}\n",
            statuses.len(),
            statuses.len(),
            manager.active_proposal_runners(),
        ));
        for status in statuses {
            let namespace = status.namespace_id.to_string();
            body.push_str(&format!(
                "pepper_namespace_term{{namespace=\"{namespace}\"}} {}\npepper_namespace_commit_index{{namespace=\"{namespace}\"}} {}\npepper_namespace_applied_index{{namespace=\"{namespace}\"}} {}\npepper_namespace_log_lag{{namespace=\"{namespace}\"}} {}\npepper_namespace_quorum_healthy{{namespace=\"{namespace}\"}} {}\npepper_namespace_checkpoint_index{{namespace=\"{namespace}\"}} {}\npepper_namespace_role{{namespace=\"{namespace}\",role=\"{}\"}} 1\n",
                status.term,
                status.last_log_index.unwrap_or(0),
                status.applied_index.unwrap_or(0),
                status.log_lag,
                u8::from(status.quorum_recently_acknowledged),
                status.snapshot_index.unwrap_or(0),
                status.role,
            ));
        }
        for metric in manager.command_metrics().await {
            body.push_str(&format!(
                "pepper_raft_commands_total{{class=\"{}\"}} {}\n\
                 pepper_raft_command_encoded_bytes_total{{class=\"{}\"}} {}\n\
                 pepper_raft_command_encoded_bytes_max{{class=\"{}\"}} {}\n",
                metric.command_class,
                metric.count,
                metric.command_class,
                metric.total_encoded_bytes,
                metric.command_class,
                metric.max_encoded_bytes,
            ));
        }
    }
    body.push_str(&pepper_observability::process_metrics().render_prometheus());
    body.into_response()
}
