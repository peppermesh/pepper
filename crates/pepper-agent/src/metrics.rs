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
pub(super) static ERASURE_OBJECT_WRITES: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_OBJECT_READS: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_SHARD_REPAIRS: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_SHARD_REBALANCES: AtomicU64 = AtomicU64::new(0);
pub(super) static ERASURE_RECONSTRUCTION_FAILURES: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_COMMITS: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_COMMIT_FAILURES: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_CONFLICTS: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_DURABILITY_FAILURES: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_COMMIT_LATENCY_MICROS: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_READS: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_READ_LATENCY_MICROS: AtomicU64 = AtomicU64::new(0);
pub(super) static NAMESPACE_GROUP_ADMISSION_FAILURES: AtomicU64 = AtomicU64::new(0);

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
         pepper_erasure_reconstruction_failures_total {}\n",
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
        ERASURE_RECONSTRUCTION_FAILURES.load(Ordering::Relaxed)
    );
    let commit_count = NAMESPACE_COMMITS.load(Ordering::Relaxed);
    let read_count = NAMESPACE_READS.load(Ordering::Relaxed);
    let (merkle, merkle_mutations) = pepper_merkle::process_io_stats();
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
         # HELP pepper_namespace_group_admission_failures_total Namespace group admission failures.\n\
         # TYPE pepper_namespace_group_admission_failures_total counter\npepper_namespace_group_admission_failures_total {}\n\
         # HELP pepper_merkle_nodes_read_total Merkle nodes decoded by this process.\n\
         # TYPE pepper_merkle_nodes_read_total counter\npepper_merkle_nodes_read_total {}\n\
         # HELP pepper_merkle_nodes_written_total Merkle node writes by this process.\n\
         # TYPE pepper_merkle_nodes_written_total counter\npepper_merkle_nodes_written_total {}\n\
         # HELP pepper_merkle_mutations_total Merkle mutations applied by this process.\n\
         # TYPE pepper_merkle_mutations_total counter\npepper_merkle_mutations_total {merkle_mutations}\n",
        NAMESPACE_COMMIT_FAILURES.load(Ordering::Relaxed),
        NAMESPACE_CONFLICTS.load(Ordering::Relaxed),
        NAMESPACE_DURABILITY_FAILURES.load(Ordering::Relaxed),
        NAMESPACE_COMMIT_LATENCY_MICROS.load(Ordering::Relaxed),
        NAMESPACE_COMMIT_LATENCY_MICROS.load(Ordering::Relaxed) / commit_count.max(1),
        NAMESPACE_READ_LATENCY_MICROS.load(Ordering::Relaxed) / read_count.max(1),
        NAMESPACE_GROUP_ADMISSION_FAILURES.load(Ordering::Relaxed),
        merkle.nodes_read,
        merkle.nodes_written,
    ));
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
    if let Some(manager) = &state.namespace_groups {
        let statuses = manager.operational_statuses().await;
        body.push_str(&format!(
            "# TYPE pepper_namespace_groups_hosted gauge\npepper_namespace_groups_hosted {}\n",
            statuses.len()
        ));
        for status in statuses {
            let namespace = status.namespace_id.to_string();
            body.push_str(&format!(
                "pepper_namespace_term{{namespace=\"{namespace}\"}} {}\npepper_namespace_commit_index{{namespace=\"{namespace}\"}} {}\npepper_namespace_applied_index{{namespace=\"{namespace}\"}} {}\npepper_namespace_log_lag{{namespace=\"{namespace}\"}} {}\npepper_namespace_quorum_healthy{{namespace=\"{namespace}\"}} {}\npepper_namespace_checkpoint_index{{namespace=\"{namespace}\"}} {}\n",
                status.term,
                status.last_log_index.unwrap_or(0),
                status.applied_index.unwrap_or(0),
                status.log_lag,
                u8::from(status.quorum_recently_acknowledged),
                status.snapshot_index.unwrap_or(0),
            ));
        }
    }
    body.into_response()
}
