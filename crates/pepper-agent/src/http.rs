// SPDX-License-Identifier: Apache-2.0

//! HTTP composition boundary. Handlers remain in their domain modules during
//! the Phase 0 behavior-preserving refactor; this module owns the public route
//! table and middleware ordering.

use super::*;

pub(super) fn router(state: AppState) -> Router {
    let s3_enabled = state.s3.is_some();
    let sqlite_enabled = state.sqlite_enabled;
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
        .route("/v1/admin/sqlite", get(admin_sqlite_status))
        .route("/v1/admin/sqlite/sessions", get(admin_sqlite_sessions))
        .route("/v1/admin/sqlite/locks", get(admin_sqlite_locks))
        .route("/v1/admin/sqlite/staging", get(admin_sqlite_staging))
        .route("/v1/admin/sqlite/repair", post(admin_sqlite_repair))
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
    if sqlite_enabled {
        router = router
            .route("/v1/sqlite/databases", post(sqlite_create))
            .route("/v1/sqlite/databases/{database}", get(sqlite_info))
            .route("/v1/sqlite/databases/{database}/check", get(sqlite_check))
            .route(
                "/v1/sqlite/databases/{database}/import",
                post(sqlite_import),
            )
            .route("/v1/sqlite/databases/{database}/export", get(sqlite_export))
            .route(
                "/v1/sqlite/databases/{database}/sessions",
                post(sqlite_session_create),
            )
            .route(
                "/v1/sqlite/databases/{database}/writer/acquire",
                post(sqlite_writer_acquire),
            )
            .route(
                "/v1/sqlite/databases/{database}/writer/renew",
                post(sqlite_writer_renew),
            )
            .route(
                "/v1/sqlite/databases/{database}/writer/release",
                post(sqlite_writer_release),
            )
            .route(
                "/v1/sqlite/databases/{database}/transactions",
                post(sqlite_incremental_commit).layer(DefaultBodyLimit::disable()),
            )
            .route(
                "/v1/sqlite/databases/{database}/commits/{request_id}",
                get(sqlite_commit_status),
            )
            .route(
                "/v1/sqlite/databases/{database}/compact",
                post(sqlite_compact),
            )
            .route(
                "/v1/sqlite/databases/{database}/rollback",
                post(sqlite_rollback),
            )
            .route(
                "/v1/sqlite/sessions/{session_id}/pages",
                get(sqlite_session_pages),
            )
            .route(
                "/v1/sqlite/sessions/{session_id}",
                axum::routing::delete(sqlite_session_close),
            )
            .route(
                "/v1/sqlite/experimental/databases",
                post(sqlite_whole_file_create),
            )
            .route(
                "/v1/sqlite/experimental/databases/{database}",
                get(sqlite_whole_file_info),
            )
            .route(
                "/v1/sqlite/experimental/databases/{database}/file",
                get(sqlite_whole_file_export).put(sqlite_whole_file_commit),
            )
            .route(
                "/v1/sqlite/experimental/databases/{database}/commits/{request_id}",
                get(sqlite_whole_file_commit_status),
            );
    }
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
        .layer(middleware::from_fn(operation_identity))
        .with_state(state)
}

async fn operation_identity(request: Request<Body>, next: Next) -> Response {
    let incoming = match request
        .headers()
        .get(pepper_observability::OPERATION_ID_HEADER)
    {
        Some(value) => match value
            .to_str()
            .ok()
            .and_then(|value| OperationId::parse(value).ok())
        {
            Some(id) => Some(id),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    "x-pepper-operation-id must contain 32 hexadecimal characters",
                )
                    .into_response();
            }
        },
        None => None,
    };
    let class = classify_http_workload(request.method(), request.uri().path());
    let work_key = WorkKey::combine(&[
        request.method().as_str().as_bytes(),
        request.uri().path().as_bytes(),
    ]);
    let content_length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let scope = OperationScope::begin(class, work_key, incoming);
    let operation_id = scope.context().id;
    let mut response = scope_operation(scope.clone(), async move {
        observe_current_stage(OperationStage::Ingress);
        if content_length > 0 {
            add_current_cost(OperationCostMetric::OwnedBytes, content_length);
        }
        let response = next.run(request).await;
        observe_current_stage(OperationStage::Response);
        response
    })
    .await;
    scope.finish(response.status().is_success() || response.status().is_redirection());
    response.headers_mut().insert(
        pepper_observability::OPERATION_ID_HEADER,
        HeaderValue::from_str(&operation_id.to_string())
            .expect("operation ID is always a valid HTTP header"),
    );
    response
}

fn classify_http_workload(method: &Method, path: &str) -> WorkloadClass {
    if path == "/v1/fs/commit" {
        WorkloadClass::FilesystemCommit
    } else if path == "/v1/fs/checkout" || path == "/v1/fs/restore" {
        WorkloadClass::FilesystemCheckout
    } else if path.starts_with("/v1/sqlite/") && path.ends_with("/transactions") {
        WorkloadClass::SqliteCommit
    } else if path.starts_with("/v1/sqlite/") {
        WorkloadClass::SqliteRead
    } else if path.starts_with("/v1/") || path == "/healthz" || path == "/readyz" {
        WorkloadClass::Control
    } else if *method == Method::PUT || *method == Method::POST {
        WorkloadClass::S3Put
    } else if *method == Method::GET || *method == Method::HEAD {
        WorkloadClass::S3Get
    } else {
        WorkloadClass::Unknown
    }
}

#[cfg(test)]
mod operation_identity_tests {
    use super::*;
    use axum::{Router, body::Body, http::Request, routing::put};
    use pepper_observability::{CostMetric, process_metrics};
    use tower::ServiceExt;

    #[test]
    fn workload_classification_is_closed_and_route_aware() {
        assert_eq!(
            classify_http_workload(&Method::POST, "/v1/fs/commit"),
            WorkloadClass::FilesystemCommit
        );
        assert_eq!(
            classify_http_workload(&Method::POST, "/v1/sqlite/databases/example/transactions"),
            WorkloadClass::SqliteCommit
        );
        assert_eq!(
            classify_http_workload(&Method::PUT, "/bucket/key"),
            WorkloadClass::S3Put
        );
        assert_eq!(
            classify_http_workload(&Method::GET, "/bucket/key"),
            WorkloadClass::S3Get
        );
    }

    #[tokio::test]
    async fn middleware_generates_preserves_and_validates_operation_ids() {
        let app = Router::new()
            .route("/bucket/key", put(|| async { StatusCode::NO_CONTENT }))
            .layer(middleware::from_fn(operation_identity));

        let operations_before = process_metrics().get(WorkloadClass::S3Put, CostMetric::Operations);
        let generated = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/bucket/key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(generated.status(), StatusCode::NO_CONTENT);
        let generated_id = generated
            .headers()
            .get(pepper_observability::OPERATION_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        OperationId::parse(generated_id).unwrap();

        let supplied = "00112233445566778899aabbccddeeff";
        let preserved = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/bucket/key")
                    .header(pepper_observability::OPERATION_ID_HEADER, supplied)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(preserved.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            preserved
                .headers()
                .get(pepper_observability::OPERATION_ID_HEADER)
                .unwrap(),
            supplied
        );

        let malformed = app
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/bucket/key")
                    .header(pepper_observability::OPERATION_ID_HEADER, "not-an-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert!(
            malformed
                .headers()
                .get(pepper_observability::OPERATION_ID_HEADER)
                .is_none()
        );
        assert!(
            process_metrics().get(WorkloadClass::S3Put, CostMetric::Operations)
                >= operations_before + 2
        );
    }
}
