// SPDX-License-Identifier: Apache-2.0

//! HTTP composition boundary. Handlers remain in their domain modules during
//! the Phase 0 behavior-preserving refactor; this module owns the public route
//! table and middleware ordering.

use super::*;

pub(super) fn router(state: AppState) -> Router {
    let s3_enabled = state.s3.is_some();
    let mut router = Router::new()
        .route("/v1/node/status", get(node_status))
        .route("/v1/node/peers", get(node_peers))
        .route("/v1/blocks", post(put_block))
        .route("/v1/blocks/{cid}", get(get_block).head(has_block))
        .route("/v1/objects", post(put_object))
        .route("/v1/objects/{cid}", get(get_object))
        .route("/v1/dirs", post(put_dir))
        .route("/v1/dirs/{cid}", get(get_dir))
        .route("/v1/pins", post(create_pin))
        .route("/v1/pins/{cid}", get(pin_status).delete(delete_pin))
        .route("/v1/namespaces", post(namespace_create))
        .route("/v1/namespaces/{namespace}", get(namespace_inspect))
        .route("/v1/namespaces/{namespace}/status", get(namespace_status))
        .route(
            "/v1/namespaces/{namespace}/replicas",
            get(namespace_replicas),
        )
        .route("/v1/namespaces/{namespace}/history", get(namespace_history))
        .route("/v1/namespaces/{namespace}/diff", post(namespace_diff))
        .route(
            "/v1/namespaces/{namespace}/rollback",
            post(namespace_rollback),
        )
        .route(
            "/v1/namespaces/{namespace}/snapshots",
            get(namespace_snapshots).post(namespace_snapshot_mutate),
        )
        .route("/v1/kv/get", post(kv_get))
        .route("/v1/kv/scan", post(kv_scan))
        .route("/v1/kv/put", post(kv_put))
        .route("/v1/kv/delete", post(kv_delete))
        .route("/v1/kv/transactions", post(kv_transaction))
        .route("/v1/buckets", post(bucket_create))
        .route("/v1/bucket/put", post(bucket_put))
        .route("/v1/bucket/get", post(bucket_get))
        .route("/v1/bucket/head", post(bucket_head))
        .route("/v1/bucket/delete", post(bucket_delete))
        .route("/v1/bucket/list", post(bucket_list))
        .route("/v1/bucket/versions", post(bucket_versions))
        .route("/v1/filesystems", post(fs_create))
        .route("/v1/fs/commit", post(fs_commit))
        .route("/v1/fs/checkout", post(fs_checkout))
        .route("/v1/fs/restore", post(fs_checkout))
        .route("/v1/fs/history/{filesystem}", get(fs_history))
        .route("/v1/fs/diff", post(fs_diff))
        .route("/v1/fs/rollback", post(fs_rollback))
        .route("/v1/fs/clone", post(fs_clone_root))
        .route(
            "/v1/admin/namespaces/{namespace}/checkpoint",
            post(admin_namespace_checkpoint),
        )
        .route(
            "/v1/admin/namespaces/{namespace}/rebalance",
            post(admin_namespace_rebalance),
        )
        .route(
            "/v1/admin/namespaces/{namespace}/replace-replica",
            post(admin_namespace_replace),
        )
        .route(
            "/v1/admin/namespaces/{namespace}/recover",
            post(admin_namespace_recover),
        )
        .route("/v1/admin/gc", post(run_gc))
        .route("/v1/admin/repair", post(run_repair))
        .route("/v1/admin/status", get(admin_status))
        .route("/v1/admin/storage", get(admin_storage))
        .route("/v1/admin/placement", get(admin_placement_status))
        .route("/v1/admin/placement/maps", post(admin_placement_map_update))
        .route(
            "/v1/admin/s3/buckets/{bucket}/partitions",
            get(admin_bucket_partitions).post(admin_bucket_partition_change),
        )
        .route(
            "/v1/admin/s3/buckets/{bucket}/pack",
            post(admin_small_object_pack),
        )
        .route(
            "/v1/admin/placement/exceptions",
            post(admin_placement_exception_put),
        )
        .route(
            "/v1/admin/placement/exceptions/delete",
            post(admin_placement_exception_delete),
        )
        .route(
            "/v1/admin/diagnostics/blocks",
            get(diagnostics::block_inventory),
        )
        .route(
            "/v1/admin/diagnostics/gc/{cid}",
            get(diagnostics::gc_explain),
        )
        .route(
            "/v1/admin/diagnostics/publication-intents",
            get(diagnostics::publication_intents),
        )
        .route(
            "/v1/admin/diagnostics/providers/{cid}",
            get(diagnostics::provider_diagnostic),
        )
        .route(
            "/v1/admin/diagnostics/erasure/{cid}",
            get(diagnostics::erasure_diagnostic),
        )
        .route(
            "/v1/admin/diagnostics/reads/{cid}",
            get(diagnostics::read_resolution_diagnostic),
        )
        .route(
            "/v1/admin/diagnostics/repairs",
            get(diagnostics::repair_diagnostic),
        )
        .route(
            "/v1/admin/diagnostics/network-rpc",
            get(diagnostics::network_rpc_diagnostic),
        )
        .route(
            "/v1/admin/diagnostics/namespaces",
            get(diagnostics::namespace_replica_diagnostic),
        )
        .route("/v1/admin/erasure", get(admin_erasure))
        .route("/v1/admin/dag/{cid}", get(admin_dag_inspect))
        .route("/v1/admin/corruption-scan", post(admin_corruption_scan))
        .route("/v1/admin/quarantine/purge", post(admin_quarantine_purge))
        .route("/v1/compute/jobs", post(submit_compute_job))
        .route("/v1/compute/jobs/{job_id}", get(compute_job_status))
        .route("/v1/compute/jobs/{job_id}/logs", get(compute_job_logs))
        .route("/v1/compute/jobs/{job_id}/cancel", post(cancel_compute_job))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics));
    if s3_enabled {
        router = router
            .route("/", any(s3_dispatch))
            .route("/{*s3_path}", any(s3_dispatch));
    }
    router
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_http_auth_and_rate_limit,
        ))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
