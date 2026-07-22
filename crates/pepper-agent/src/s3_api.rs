// SPDX-License-Identifier: Apache-2.0

//! Opt-in S3 REST compatibility over Pepper buckets.

use super::*;
use ::time::{PrimitiveDateTime, format_description::well_known::Rfc3339};
use axum::{
    extract::OriginalUri,
    http::{Method, Uri},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac};
use md5::Md5;
use pepper_bucket::{BucketLimits, BucketObjectDescriptor};
use pepper_merkle::{MerkleLimits, MerkleReadStore, MerkleValue, ScanQuery};
use pepper_namespace::{
    CommandEnvelope, KeyPrecondition, NamespaceCommand, NamespaceDescriptor, NamespaceKind,
    NamespaceMutation, TransactionCommand,
};
use pepper_types::CODEC_BUCKET_OBJECT;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::sync::{OnceLock, atomic::AtomicU64};

type HmacSha256 = Hmac<Sha256>;

static S3_REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);
static S3_REQUEST_PREFIX: OnceLock<String> = OnceLock::new();
const S3_MULTIPART_CONTROL_KEY: &[u8] = b"\xffs3/multipart-control";
const S3_BUCKET_DELETED_KEY: &[u8] = b"\xffs3/deleted";
const S3_BUCKET_PARTITION_MAP_KEY: &[u8] = b"\xffs3/partitions/map";
pub(super) const S3_BUCKET_PARTITION_FENCE_KEY: &[u8] = b"\xffs3/partition/fence";
const S3_BUCKET_LIST_BARRIER_PREFIX: &[u8] = b"\xffs3/list-barriers/";
const S3_BUCKET_PARTITION_CREATOR: &str = "pepper-s3-bucket-partition-v1";
const S3_BUCKET_TAGGING_KEY: &[u8] = b"\xffs3/tagging";
const S3_BUCKET_CORS_KEY: &[u8] = b"\xffs3/cors";
const S3_BUCKET_LIFECYCLE_KEY: &[u8] = b"\xffs3/lifecycle";
const S3_MULTIPART_COMPLETION_PREFIX: &[u8] = b"completion/";
const S3_MULTIPART_UPLOAD_PREFIX: &[u8] = b"upload/";
const S3_MULTIPART_PART_PREFIX: &[u8] = b"part/";
const S3_MIN_MULTIPART_PART_BYTES: u64 = 5 * 1024 * 1024;
const S3_MAX_MULTIPART_PARTS: u32 = 10_000;
const S3_MULTIPART_CLEANUP_BATCH: usize = 9_000;
const S3_MAX_DISCOVERED_BUCKETS: usize = 10_000;
const S3_LIST_CACHE_MAX_ENTRIES: usize = 128;
const S3_LIST_CACHE_MAX_BYTES: usize = 32 * 1024 * 1024;
pub(super) const S3_BUCKET_CATALOG_ALIAS: &str = "__pepper_s3_bucket_catalog_v1";
const S3_BUCKET_CATALOG_CREATOR: &str = "pepper.s3.bucket.catalog.v1";
const S3_BUCKET_CATALOG_KEY_PREFIX: &[u8] = b"bucket/";
const S3_PLACEMENT_MAP_CURRENT_KEY: &[u8] = b"\xffplacement/map/current";
const S3_PLACEMENT_MAP_EPOCH_PREFIX: &[u8] = b"\xffplacement/map/epoch/";
const S3_PLACEMENT_EXCEPTION_PREFIX: &[u8] = b"\xffplacement/exception/";
const S3_PLACEMENT_MAP_METADATA: &str = "placement_map";

pub(super) struct DirectNamespaceReadStore<'a> {
    state: &'a AppState,
    namespace_id: String,
    local_node_id: String,
    local_is_replica: bool,
    replica_node_ids: Vec<String>,
    preferred_node_id: Option<String>,
}

#[async_trait]
impl MerkleReadStore for DirectNamespaceReadStore<'_> {
    async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
        if self.local_is_replica {
            match tokio::task::block_in_place(|| self.state.block_store.get(cid)) {
                Ok(block) => return Ok(block.payload),
                Err(StorageError::NotFound(_)) | Err(StorageError::HashMismatch(_)) => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        let mut remote_node_ids = self
            .replica_node_ids
            .iter()
            .filter(|node_id| *node_id != &self.local_node_id)
            .cloned()
            .collect::<Vec<_>>();
        if let Some(preferred) = self.preferred_node_id.as_ref()
            && let Some(index) = remote_node_ids
                .iter()
                .position(|node_id| node_id == preferred)
        {
            remote_node_ids.swap(0, index);
        }
        fetch_block_from_ordered_replica_targets(
            self.state,
            &self.namespace_id,
            cid,
            remote_node_ids,
            Duration::from_secs(5),
        )
        .await
        .map(|(_, payload)| payload)
    }
}

pub(super) async fn direct_namespace_store<'a>(
    state: &'a AppState,
    namespace: &NamespaceState,
) -> DirectNamespaceReadStore<'a> {
    let (known_leader, known_replicas) = match namespace_manager(state) {
        Ok(manager) => manager.known_namespace_route(&namespace.namespace_id).await,
        Err(_) => (None, Vec::new()),
    };
    let preferred_node_id = known_leader.or_else(|| {
        namespace
            .descriptor
            .placement_constraints
            .get("initial_leader")
            .cloned()
    });
    let replica_node_ids = if known_replicas.is_empty() {
        namespace.descriptor.initial_replica_set.clone()
    } else {
        known_replicas
    };
    let local_node_id = state.network.local_descriptor().node_id;
    let local_is_replica = replica_node_ids.contains(&local_node_id);
    DirectNamespaceReadStore {
        state,
        namespace_id: namespace.namespace_id.to_string(),
        local_node_id,
        local_is_replica,
        replica_node_ids,
        preferred_node_id,
    }
}

async fn s3_current_value(
    state: &AppState,
    namespace_id: &NamespaceId,
    key_hex: &str,
) -> Result<Option<MerkleValue>, ApiError> {
    let key = hex::decode(key_hex).map_err(|error| ApiError::bad_request(error.to_string()))?;
    let namespace = namespace_manager(state)?
        .linearizable_namespace_head(namespace_id)
        .await
        .map_err(consensus_error)?;
    pepper_merkle::get(
        &direct_namespace_store(state, &namespace).await,
        &namespace.current_root_cid,
        &key,
        MerkleLimits::default(),
    )
    .await
    .map_err(|error| ApiError::bad_request(error.to_string()))
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct S3ListCacheKey {
    bucket: String,
    root: String,
    prefix: Vec<u8>,
    delimiter: Option<Vec<u8>>,
    start_after: Option<String>,
    continuation_token: Option<String>,
    max_keys: usize,
    encoding_url: bool,
    fetch_owner: bool,
}

#[derive(Default)]
struct S3ListCacheState {
    entries: HashMap<S3ListCacheKey, Bytes>,
    order: VecDeque<S3ListCacheKey>,
    bytes: usize,
    flights: HashMap<S3ListCacheKey, std::sync::Weak<tokio::sync::Mutex<()>>>,
}

#[derive(Default)]
pub(super) struct S3ListCache {
    state: tokio::sync::Mutex<S3ListCacheState>,
}

impl S3ListCache {
    async fn get(&self, key: &S3ListCacheKey) -> Option<Bytes> {
        self.state.lock().await.entries.get(key).cloned()
    }

    async fn flight(&self, key: &S3ListCacheKey) -> Arc<tokio::sync::Mutex<()>> {
        let mut state = self.state.lock().await;
        if let Some(flight) = state.flights.get(key).and_then(std::sync::Weak::upgrade) {
            return flight;
        }
        let flight = Arc::new(tokio::sync::Mutex::new(()));
        state.flights.insert(key.clone(), Arc::downgrade(&flight));
        flight
    }

    async fn insert(&self, key: S3ListCacheKey, body: Bytes) {
        let mut state = self.state.lock().await;
        if let Some(previous) = state.entries.remove(&key) {
            state.bytes = state.bytes.saturating_sub(previous.len());
            state.order.retain(|existing| existing != &key);
        }
        state.bytes = state.bytes.saturating_add(body.len());
        state.order.push_back(key.clone());
        state.entries.insert(key.clone(), body);
        state.flights.remove(&key);
        while state.entries.len() > S3_LIST_CACHE_MAX_ENTRIES
            || state.bytes > S3_LIST_CACHE_MAX_BYTES
        {
            let Some(oldest) = state.order.pop_front() else {
                break;
            };
            if let Some(removed) = state.entries.remove(&oldest) {
                state.bytes = state.bytes.saturating_sub(removed.len());
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct S3RuntimeConfig {
    pub(super) region: String,
    pub(super) access_key_id: String,
    pub(super) secret_access_key: Vec<u8>,
    pub(super) max_clock_skew_seconds: u64,
    pub(super) bucket_partitions: usize,
    pub(super) bucket_create_lock: Arc<tokio::sync::Mutex<()>>,
    pub(super) bucket_catalog_lock: Arc<tokio::sync::Mutex<()>>,
    pub(super) placement_map_lock: Arc<tokio::sync::Mutex<()>>,
    pub(super) multipart_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Debug)]
struct S3AuthContext {
    payload_hash: PayloadHash,
    aws_chunked: Option<AwsChunkedAuth>,
    request_id: String,
}

#[derive(Debug)]
enum PayloadHash {
    Unsigned,
    Sha256([u8; 32]),
    Streaming,
}

#[derive(Clone, Debug)]
struct AwsChunkedAuth {
    signing_key: Vec<u8>,
    prior_signature: String,
    amz_date: String,
    credential_scope: String,
    signed_trailers: bool,
}

#[derive(Debug)]
pub(super) struct S3Error {
    status: StatusCode,
    code: &'static str,
    message: String,
    resource: String,
    request_id: String,
    retry_after_seconds: Option<u64>,
}

impl S3Error {
    pub(super) fn new(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            resource: resource.into(),
            request_id: request_id(),
            retry_after_seconds: None,
        }
    }

    pub(super) fn with_retry_after(mut self, seconds: u64) -> Self {
        self.retry_after_seconds = Some(seconds.max(1));
        self
    }

    fn invalid(message: impl Into<String>, resource: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            message,
            resource,
        )
    }

    fn no_bucket(bucket: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
            format!("/{bucket}"),
        )
    }

    fn no_key(bucket: &str, key: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            "The specified key does not exist",
            format!("/{bucket}/{key}"),
        )
    }

    fn no_upload(bucket: &str, key: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "The specified multipart upload does not exist",
            format!("/{bucket}/{key}"),
        )
    }

    fn not_implemented(message: impl Into<String>, resource: impl Into<String>) -> Self {
        Self::new(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            message,
            resource,
        )
    }
}

impl IntoResponse for S3Error {
    fn into_response(self) -> Response {
        if self.status.is_server_error() || self.status == StatusCode::CONFLICT {
            warn!(
                status = self.status.as_u16(),
                code = self.code,
                resource = self.resource,
                request_id = self.request_id,
                error = self.message,
                "S3 request failed"
            );
        }
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{}</Code><Message>{}</Message><Resource>{}</Resource><RequestId>{}</RequestId></Error>",
            self.code,
            xml_escape(&self.message),
            xml_escape(&self.resource),
            xml_escape(&self.request_id),
        );
        let mut response = (self.status, xml).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );
        if let Ok(value) = HeaderValue::from_str(&self.request_id) {
            response.headers_mut().insert("x-amz-request-id", value);
        }
        if self.status == StatusCode::SERVICE_UNAVAILABLE {
            let seconds = self.retry_after_seconds.unwrap_or(1).to_string();
            if let Ok(value) = HeaderValue::from_str(&seconds) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct S3BucketQuery {
    #[serde(rename = "list-type")]
    list_type: Option<u8>,
    prefix: Option<String>,
    delimiter: Option<String>,
    #[serde(rename = "max-keys")]
    max_keys: Option<usize>,
    #[serde(rename = "continuation-token")]
    continuation_token: Option<String>,
    #[serde(rename = "start-after")]
    start_after: Option<String>,
    #[serde(rename = "encoding-type")]
    encoding_type: Option<String>,
    #[serde(rename = "fetch-owner")]
    fetch_owner: Option<bool>,
    versions: Option<String>,
    uploads: Option<String>,
    #[serde(rename = "max-uploads")]
    max_uploads: Option<usize>,
    #[serde(rename = "key-marker")]
    key_marker: Option<String>,
    #[serde(rename = "upload-id-marker")]
    upload_id_marker: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct S3ObjectQuery {
    #[serde(rename = "versionId")]
    version_id: Option<String>,
    #[serde(rename = "uploadId")]
    upload_id: Option<String>,
    uploads: Option<String>,
    #[serde(rename = "partNumber")]
    part_number: Option<u32>,
    #[serde(rename = "max-parts")]
    max_parts: Option<usize>,
    #[serde(rename = "part-number-marker")]
    part_number_marker: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct S3MultipartUpload {
    upload_id: String,
    bucket: String,
    bucket_namespace_id: String,
    control_namespace_id: String,
    key: String,
    content_type: String,
    metadata: BTreeMap<String, String>,
    initiated_at_unix_seconds: i64,
    status: String,
    completion_hash: Option<String>,
    final_content_cid: Option<Cid>,
    final_content_placement: Option<PlacementReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct S3MultipartPart {
    upload_id: String,
    part_number: u32,
    content_cid: Cid,
    content_placement: PlacementReference,
    size: u64,
    etag: String,
    durability_status: String,
    uploaded_at_unix_seconds: i64,
    durability: Vec<DurabilityReceipt>,
}

struct StoredMultipartUpload {
    control_namespace_id: NamespaceId,
    value: MerkleValue,
    upload: S3MultipartUpload,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "CompleteMultipartUpload")]
struct CompleteMultipartUploadRequest {
    #[serde(rename = "Part", default)]
    parts: Vec<CompletedPartRequest>,
}

#[derive(Debug, Deserialize)]
struct CompletedPartRequest {
    #[serde(rename = "PartNumber")]
    part_number: u32,
    #[serde(rename = "ETag")]
    etag: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Delete")]
struct DeleteObjectsRequest {
    #[serde(rename = "Object", default)]
    objects: Vec<DeleteObjectRequest>,
    #[serde(rename = "Quiet", default)]
    quiet: bool,
}

#[derive(Debug, Deserialize)]
struct DeleteObjectRequest {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "VersionId")]
    version_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Tagging")]
struct BucketTagging {
    #[serde(rename = "TagSet")]
    tag_set: BucketTagSet,
}

#[derive(Debug, Deserialize)]
struct BucketTagSet {
    #[serde(rename = "Tag", default)]
    tags: Vec<BucketTag>,
}

#[derive(Debug, Deserialize)]
struct BucketTag {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Value")]
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "CORSConfiguration")]
struct BucketCorsConfiguration {
    #[serde(rename = "CORSRule", default)]
    rules: Vec<BucketCorsRule>,
}

#[derive(Debug, Deserialize)]
struct BucketCorsRule {
    #[serde(rename = "AllowedMethod", default)]
    allowed_methods: Vec<String>,
    #[serde(rename = "AllowedOrigin", default)]
    allowed_origins: Vec<String>,
    #[serde(rename = "AllowedHeader", default)]
    allowed_headers: Vec<String>,
    #[serde(rename = "ExposeHeader", default)]
    expose_headers: Vec<String>,
    #[serde(rename = "MaxAgeSeconds")]
    max_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "LifecycleConfiguration")]
struct BucketLifecycleConfiguration {
    #[serde(rename = "Rule", default)]
    rules: Vec<BucketLifecycleRule>,
}

#[derive(Debug, Clone, Deserialize)]
struct BucketLifecycleRule {
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "AbortIncompleteMultipartUpload")]
    abort_incomplete_multipart_upload: Option<AbortIncompleteMultipartUpload>,
}

#[derive(Debug, Clone, Deserialize)]
struct AbortIncompleteMultipartUpload {
    #[serde(rename = "DaysAfterInitiation")]
    days_after_initiation: u64,
}

#[derive(Clone, Copy)]
enum BucketSubresource {
    Tagging,
    Cors,
    Lifecycle,
}

pub(super) fn spawn_s3_lifecycle_reconciler(state: AppState) {
    if state.s3.is_none() {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            if let Err(error) = reconcile_s3_lifecycle(&state).await {
                warn!(error = %error.message, "S3 lifecycle reconciliation failed");
            }
            tokio::time::sleep(Duration::from_secs(60 * 60)).await;
        }
    });
}

async fn reconcile_s3_lifecycle(state: &AppState) -> Result<(), S3Error> {
    reconcile_completed_multipart_uploads(state).await?;
    let aliases = catalog_s3_buckets(state, "/").await?;
    for (bucket, namespace_id) in aliases {
        let Some(body) = get_bucket_internal_raw(state, &namespace_id, S3_BUCKET_LIFECYCLE_KEY)
            .await
            .map_err(|error| map_api_error(error, &format!("/{bucket}")))?
        else {
            continue;
        };
        let lifecycle: BucketLifecycleConfiguration = quick_xml::de::from_reader(body.as_slice())
            .map_err(|_| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "stored lifecycle configuration is invalid",
                format!("/{bucket}"),
            )
        })?;
        let Some(days) = lifecycle
            .rules
            .iter()
            .filter(|rule| rule.status == "Enabled")
            .filter_map(|rule| rule.abort_incomplete_multipart_upload.as_ref())
            .map(|abort| abort.days_after_initiation)
            .min()
        else {
            continue;
        };
        let Some(control_namespace_id) =
            multipart_control_namespace(state, &namespace_id, &format!("/{bucket}")).await?
        else {
            continue;
        };
        let cutoff = unix_seconds().saturating_sub((days.saturating_mul(86_400)) as i64);
        for upload in all_multipart_uploads(state, &control_namespace_id).await? {
            if upload.status != "open" || upload.initiated_at_unix_seconds > cutoff {
                continue;
            }
            if let Some(stored) =
                multipart_upload(state, &upload.upload_id, &format!("/{bucket}")).await?
            {
                match delete_multipart_upload(state, &stored, &format!("/{bucket}")).await {
                    Ok(()) => {
                        info!(bucket, upload_id = %upload.upload_id, "aborted expired multipart upload")
                    }
                    Err(error) => {
                        warn!(bucket, upload_id = %upload.upload_id, error = %error.message, "failed to abort expired multipart upload")
                    }
                }
            }
        }
    }
    Ok(())
}

async fn reconcile_completed_multipart_uploads(state: &AppState) -> Result<(), S3Error> {
    let aliases = catalog_s3_buckets(state, "/").await?;
    for (bucket, namespace_id) in aliases {
        let resource = format!("/{bucket}");
        let Some(control_namespace_id) =
            multipart_control_namespace(state, &namespace_id, &resource).await?
        else {
            continue;
        };
        for upload in all_multipart_uploads(state, &control_namespace_id)
            .await?
            .into_iter()
            .filter(|upload| upload.status == "completing")
        {
            let Some(expected_cid) = upload.final_content_cid.as_ref() else {
                continue;
            };
            if !completed_multipart_object_is_published(
                state,
                &namespace_id,
                &upload.key,
                expected_cid,
                &resource,
            )
            .await?
            {
                continue;
            }
            let Some(stored) = multipart_upload(state, &upload.upload_id, &resource).await? else {
                continue;
            };
            match delete_multipart_upload(state, &stored, &resource).await {
                Ok(()) => info!(
                    bucket,
                    upload_id = %upload.upload_id,
                    "reconciled completed multipart upload"
                ),
                Err(error) => warn!(
                    bucket,
                    upload_id = %upload.upload_id,
                    error = %error.message,
                    "failed to reconcile completed multipart upload"
                ),
            }
        }
    }
    Ok(())
}

impl BucketSubresource {
    fn query_name(self) -> &'static str {
        match self {
            Self::Tagging => "tagging",
            Self::Cors => "cors",
            Self::Lifecycle => "lifecycle",
        }
    }

    fn key(self) -> &'static [u8] {
        match self {
            Self::Tagging => S3_BUCKET_TAGGING_KEY,
            Self::Cors => S3_BUCKET_CORS_KEY,
            Self::Lifecycle => S3_BUCKET_LIFECYCLE_KEY,
        }
    }
}

struct S3ObjectReadRequest {
    bucket: String,
    key: String,
    query: S3ObjectQuery,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    head_only: bool,
}

struct S3UploadPartRequest {
    bucket: String,
    key: String,
    query: S3ObjectQuery,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
    auth: S3AuthContext,
}

/// Routes both path-style (`/bucket/key`) and AWS virtual-hosted
/// (`bucket.s3.example/key`) requests through the same operation handlers.
pub(super) async fn s3_dispatch(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, S3Error> {
    let (bucket, key) = s3_request_target(&uri, &headers)?;
    let ordinary_object_request = key.is_some()
        && matches!(
            method,
            Method::GET | Method::HEAD | Method::PUT | Method::POST | Method::DELETE
        );
    if ordinary_object_request && let Some(runtime) = state.fast_path.clone() {
        let mut affinity = bucket.as_deref().unwrap_or_default().as_bytes().to_vec();
        affinity.push(0);
        affinity.extend_from_slice(key.as_deref().unwrap_or_default().as_bytes());
        let resource = uri.path().to_string();
        return runtime
            .execute(&affinity, &resource, async move {
                s3_dispatch_inner(state, uri, method, headers, body, bucket, key).await
            })
            .await;
    }
    s3_dispatch_inner(state, uri, method, headers, body, bucket, key).await
}

async fn s3_dispatch_inner(
    state: AppState,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    body: Body,
    bucket: Option<String>,
    key: Option<String>,
) -> Result<Response, S3Error> {
    match (method.clone(), bucket, key) {
        (Method::GET, None, None) => {
            s3_list_buckets(State(state), OriginalUri(uri), method, headers).await
        }
        (Method::OPTIONS, Some(bucket), key) => {
            s3_options_request(&state, &bucket, key.as_deref(), &uri, &headers).await
        }
        (Method::PUT, Some(bucket), None) if bucket_subresource(uri.query())?.is_some() => {
            s3_bucket_subresource(
                State(state),
                Path(bucket),
                OriginalUri(uri),
                method,
                headers,
                body,
            )
            .await
        }
        (Method::PUT, Some(bucket), None) => {
            s3_create_bucket(
                State(state),
                Path(bucket),
                OriginalUri(uri),
                method,
                headers,
                body,
            )
            .await
        }
        (Method::HEAD, Some(bucket), None) => {
            s3_head_bucket(
                State(state),
                Path(bucket),
                OriginalUri(uri),
                method,
                headers,
            )
            .await
        }
        (Method::GET, Some(bucket), None) if bucket_subresource(uri.query())?.is_some() => {
            s3_bucket_subresource(
                State(state),
                Path(bucket),
                OriginalUri(uri),
                method,
                headers,
                body,
            )
            .await
        }
        (Method::GET, Some(bucket), None) => {
            let Query(query) = Query::<S3BucketQuery>::try_from_uri(&uri)
                .map_err(|_| S3Error::invalid("invalid bucket query parameters", uri.path()))?;
            s3_list_objects_v2(
                State(state),
                Path(bucket),
                Query(query),
                OriginalUri(uri),
                method,
                headers,
            )
            .await
        }
        (Method::POST, Some(bucket), None)
            if headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("multipart/form-data"))
                && !has_query_parameter(uri.query(), "delete") =>
        {
            s3_post_form_upload(State(state), Path(bucket), OriginalUri(uri), headers, body).await
        }
        (Method::POST, Some(bucket), None) => {
            s3_post_bucket(
                State(state),
                Path(bucket),
                OriginalUri(uri),
                method,
                headers,
                body,
            )
            .await
        }
        (Method::DELETE, Some(bucket), None) if bucket_subresource(uri.query())?.is_some() => {
            s3_bucket_subresource(
                State(state),
                Path(bucket),
                OriginalUri(uri),
                method,
                headers,
                body,
            )
            .await
        }
        (Method::DELETE, Some(bucket), None) => {
            s3_delete_bucket(
                State(state),
                Path(bucket),
                OriginalUri(uri),
                method,
                headers,
            )
            .await
        }
        (Method::PUT, Some(bucket), Some(key)) => {
            let Query(query) = Query::<S3ObjectQuery>::try_from_uri(&uri)
                .map_err(|_| S3Error::invalid("invalid object query parameters", uri.path()))?;
            s3_put_object(
                State(state),
                Path((bucket, key)),
                Query(query),
                OriginalUri(uri),
                method,
                headers,
                body,
            )
            .await
        }
        (Method::POST, Some(bucket), Some(key)) => {
            let Query(query) = Query::<S3ObjectQuery>::try_from_uri(&uri)
                .map_err(|_| S3Error::invalid("invalid object query parameters", uri.path()))?;
            s3_post_object(
                State(state),
                Path((bucket, key)),
                Query(query),
                OriginalUri(uri),
                method,
                headers,
                body,
            )
            .await
        }
        (Method::GET, Some(bucket), Some(key)) => {
            let Query(query) = Query::<S3ObjectQuery>::try_from_uri(&uri)
                .map_err(|_| S3Error::invalid("invalid object query parameters", uri.path()))?;
            s3_get_object(
                State(state),
                Path((bucket, key)),
                Query(query),
                OriginalUri(uri),
                method,
                headers,
            )
            .await
        }
        (Method::HEAD, Some(bucket), Some(key)) => {
            let Query(query) = Query::<S3ObjectQuery>::try_from_uri(&uri)
                .map_err(|_| S3Error::invalid("invalid object query parameters", uri.path()))?;
            s3_head_object(
                State(state),
                Path((bucket, key)),
                Query(query),
                OriginalUri(uri),
                method,
                headers,
            )
            .await
        }
        (Method::DELETE, Some(bucket), Some(key)) => {
            let Query(query) = Query::<S3ObjectQuery>::try_from_uri(&uri)
                .map_err(|_| S3Error::invalid("invalid object query parameters", uri.path()))?;
            s3_delete_object(
                State(state),
                Path((bucket, key)),
                Query(query),
                OriginalUri(uri),
                method,
                headers,
            )
            .await
        }
        (_, Some(_), None) => Err(S3Error::not_implemented(
            "this bucket operation is not implemented",
            uri.path(),
        )),
        _ => Err(S3Error::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource",
            uri.path(),
        )),
    }
}

fn s3_request_target(
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<(Option<String>, Option<String>), S3Error> {
    let virtual_bucket = header_text(headers, header::HOST)?.and_then(virtual_host_bucket);
    let decoded = percent_decode(uri.path().trim_start_matches('/'))?;
    let path = String::from_utf8(decoded)
        .map_err(|_| S3Error::invalid("S3 bucket and object names must be UTF-8", uri.path()))?;
    if let Some(bucket) = virtual_bucket {
        return Ok((Some(bucket), (!path.is_empty()).then_some(path)));
    }
    if path.is_empty() {
        return Ok((None, None));
    }
    let (bucket, key) = path
        .split_once('/')
        .map_or((path.as_str(), None), |(bucket, key)| {
            (bucket, (!key.is_empty()).then_some(key))
        });
    Ok((Some(bucket.to_string()), key.map(ToString::to_string)))
}

fn virtual_host_bucket(host: &str) -> Option<String> {
    let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    let marker = host.find(".s3.").or_else(|| host.find(".s3-"))?;
    let bucket = &host[..marker];
    validate_bucket_name(bucket).ok()?;
    Some(bucket.to_string())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct S3ContinuationToken {
    version: u32,
    control_namespace_id: String,
    bucket_epoch: u64,
    barrier_id: String,
    prefix_hex: String,
    delimiter_hex: Option<String>,
    last_key_hex: String,
    skip_common_prefix_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
struct S3PartitionRoot {
    partition_id: u32,
    namespace_id: String,
    revision: u64,
    root_cid: Cid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct S3ListBarrier {
    version: u32,
    bucket_epoch: u64,
    barrier_id: String,
    created_at_unix_seconds: i64,
    partition_roots: Vec<S3PartitionRoot>,
}

pub(super) struct S3ListBarrierCodecHandler;

impl DagCodecHandler for S3ListBarrierCodecHandler {
    fn codec(&self) -> Codec {
        CODEC_BUCKET_PARTITION_BARRIER
    }

    fn links(&self, payload: &[u8], _limits: &TraversalLimits) -> Result<Vec<Cid>, DagError> {
        let barrier: S3ListBarrier =
            serde_json::from_slice(payload).map_err(|error| DagError::InvalidPayload {
                codec: self.codec().canonical_display(),
                message: error.to_string(),
            })?;
        if barrier.version != 1 || barrier.partition_roots.is_empty() {
            return Err(DagError::InvalidPayload {
                codec: self.codec().canonical_display(),
                message: "invalid bucket partition barrier".to_string(),
            });
        }
        Ok(barrier
            .partition_roots
            .into_iter()
            .map(|partition| partition.root_cid)
            .collect())
    }
}

pub(super) async fn s3_list_buckets(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, S3Error> {
    let auth = authorize(&state, &method, &uri, &headers)?;
    verify_empty_payload(&auth, uri.path())?;
    let manager = namespace_manager(&state).map_err(|error| map_api_error(error, uri.path()))?;
    let mut buckets = Vec::new();
    for (alias, namespace_id) in catalog_s3_buckets(&state, uri.path()).await? {
        let namespace = manager
            .linearizable_namespace_head(&namespace_id)
            .await
            .map_err(|error| {
                S3Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ServiceUnavailable",
                    error.to_string(),
                    uri.path(),
                )
            })?;
        if namespace.descriptor.kind == NamespaceKind::Bucket {
            buckets.push((alias, namespace.descriptor.created_at_unix_seconds));
        }
    }
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Owner><ID>pepper</ID><DisplayName>pepper</DisplayName></Owner><Buckets>",
    );
    for (name, created_at) in buckets {
        xml.push_str("<Bucket><Name>");
        xml.push_str(&xml_escape(&name));
        xml.push_str("</Name><CreationDate>");
        xml.push_str(&xml_escape(&iso_timestamp(created_at)));
        xml.push_str("</CreationDate></Bucket>");
    }
    xml.push_str("</Buckets></ListAllMyBucketsResult>");
    Ok(xml_response(StatusCode::OK, xml, &auth.request_id))
}

pub(super) async fn s3_create_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, S3Error> {
    let auth = authorize(&state, &method, &uri, &headers)?;
    validate_bucket_name(&bucket)?;
    reject_query_parameters(uri.query(), &["x-id"], uri.path())?;
    reject_unsupported_control_headers(&headers, uri.path())?;
    let bytes = read_body_limited(body, Some(64 * 1024), "S3 CreateBucket body")
        .await
        .map_err(|error| map_api_error(error, uri.path()))?;
    verify_buffered_payload(&auth, &bytes, uri.path())?;
    verify_buffered_checksums(&headers, &bytes, uri.path())?;
    validate_location_constraint(&state, &bytes, uri.path())?;
    let create_lock = state
        .s3
        .as_ref()
        .ok_or_else(|| S3Error::no_bucket(&bucket))?
        .bucket_create_lock
        .clone();
    let _create_guard = create_lock.lock().await;

    let catalog_namespace_id = ensure_s3_bucket_catalog(&state, uri.path()).await?;
    ensure_s3_placement_map(&state, &catalog_namespace_id, uri.path()).await?;
    if let Some(namespace_id) =
        s3_catalog_lookup(&state, &catalog_namespace_id, &bucket, uri.path()).await?
    {
        let namespace = namespace_manager(&state)
            .map_err(|error| map_api_error(error, uri.path()))?
            .linearizable_namespace_head(&namespace_id)
            .await
            .map_err(|error| {
                S3Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ServiceUnavailable",
                    error.to_string(),
                    uri.path(),
                )
            })?;
        if namespace.descriptor.kind == NamespaceKind::Bucket
            && bucket_deleted(&state, &namespace_id)
                .await
                .map_err(|error| map_api_error(error, uri.path()))?
        {
            clear_bucket_deleted(&state, &namespace_id, uri.path()).await?;
            cache_alias(&state, &bucket, &namespace_id)
                .map_err(|error| map_api_error(error, uri.path()))?;
            cache_fast_path_bucket(&state, &bucket, &namespace_id);
            let mut response = StatusCode::OK.into_response();
            response.headers_mut().insert(
                header::LOCATION,
                HeaderValue::from_str(&format!("/{bucket}"))
                    .map_err(ApiError::header)
                    .map_err(|error| map_api_error(error, uri.path()))?,
            );
            add_s3_headers(&mut response, &auth.request_id, Some(&state));
            return Ok(response);
        }
        if namespace.descriptor.kind == NamespaceKind::Bucket
            && get_bucket_internal_raw(&state, &namespace_id, S3_BUCKET_PARTITION_MAP_KEY)
                .await
                .map_err(|error| map_api_error(error, uri.path()))?
                .is_none()
        {
            initialize_partitioned_bucket(&state, &namespace_id, uri.path()).await?;
            cache_alias(&state, &bucket, &namespace_id)
                .map_err(|error| map_api_error(error, uri.path()))?;
            cache_fast_path_bucket(&state, &bucket, &namespace_id);
            let mut response = StatusCode::OK.into_response();
            response.headers_mut().insert(
                header::LOCATION,
                HeaderValue::from_str(&format!("/{bucket}"))
                    .map_err(ApiError::header)
                    .map_err(|error| map_api_error(error, uri.path()))?,
            );
            add_s3_headers(&mut response, &auth.request_id, Some(&state));
            return Ok(response);
        }
        let code = if namespace.descriptor.kind == NamespaceKind::Bucket {
            "BucketAlreadyOwnedByYou"
        } else {
            "BucketAlreadyExists"
        };
        return Err(S3Error::new(
            StatusCode::CONFLICT,
            code,
            "The requested bucket name is not available",
            uri.path(),
        ));
    }

    let created = bucket_create(
        State(state.clone()),
        Json(BucketCreateRequest { alias: None }),
    )
    .await
    .map_err(|error| map_api_error(error, uri.path()))?
    .0;
    let winner = claim_s3_catalog_entry(
        &state,
        &catalog_namespace_id,
        &bucket,
        &created.namespace_id,
        uri.path(),
    )
    .await?;
    if winner != created.namespace_id {
        let _ = mark_bucket_deleted(&state, &created.namespace_id, uri.path()).await;
        return Err(S3Error::new(
            StatusCode::CONFLICT,
            "BucketAlreadyExists",
            "The requested bucket name is not available",
            uri.path(),
        ));
    }
    initialize_partitioned_bucket(&state, &created.namespace_id, uri.path()).await?;
    cache_alias(&state, &bucket, &created.namespace_id)
        .map_err(|error| map_api_error(error, uri.path()))?;
    cache_fast_path_bucket(&state, &bucket, &created.namespace_id);
    let mut response = StatusCode::OK.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&format!("/{bucket}"))
            .map_err(ApiError::header)
            .map_err(|error| map_api_error(error, uri.path()))?,
    );
    add_s3_headers(&mut response, &auth.request_id, Some(&state));
    Ok(response)
}

pub(super) async fn s3_post_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, S3Error> {
    let auth = authorize(&state, &method, &uri, &headers)?;
    reject_query_parameters(uri.query(), &["delete", "x-id"], uri.path())?;
    if !has_query_parameter(uri.query(), "delete") {
        return Err(S3Error::not_implemented(
            "only DeleteObjects is implemented for bucket POST requests",
            uri.path(),
        ));
    }
    reject_unsupported_control_headers(&headers, uri.path())?;
    let body = read_body_limited(body, Some(1024 * 1024), "S3 DeleteObjects body")
        .await
        .map_err(|error| map_api_error(error, uri.path()))?;
    verify_buffered_payload(&auth, &body, uri.path())?;
    verify_buffered_checksums(&headers, &body, uri.path())?;
    let request: DeleteObjectsRequest =
        quick_xml::de::from_reader(body.as_slice()).map_err(|_| {
            S3Error::new(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "The XML provided was not well-formed or did not validate",
                uri.path(),
            )
        })?;
    if request.objects.is_empty() || request.objects.len() > 1000 {
        return Err(S3Error::invalid(
            "DeleteObjects must contain between 1 and 1000 objects",
            uri.path(),
        ));
    }
    if request.objects.iter().any(|object| {
        object
            .version_id
            .as_deref()
            .is_some_and(|value| value != "null")
    }) {
        return Err(S3Error::not_implemented(
            "version-specific deletion is not implemented",
            uri.path(),
        ));
    }
    let mut deleted = Vec::with_capacity(request.objects.len());
    for object in request.objects {
        validate_object_identity(&bucket, &object.key, uri.path())?;
        let partition = bucket_partition_state(&state, &bucket, object.key.as_bytes()).await?;
        let _ = bucket_delete(
            State(state.clone()),
            Json(BucketDeleteRequest {
                bucket: partition.partition.namespace_id.to_string(),
                key_hex: hex::encode(object.key.as_bytes()),
                if_generation: None,
                if_cid: None,
                request_id: request_id(),
                partition_fence: Some(partition.write_fence()),
            }),
        )
        .await
        .map_err(|error| map_api_error(error, uri.path()))?;
        deleted.push(object.key);
    }
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    if !request.quiet {
        for key in deleted {
            xml.push_str("<Deleted><Key>");
            xml.push_str(&xml_escape(&key));
            xml.push_str("</Key></Deleted>");
        }
    }
    xml.push_str("</DeleteResult>");
    Ok(xml_response(StatusCode::OK, xml, &auth.request_id))
}

pub(super) async fn s3_post_form_upload(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, S3Error> {
    validate_bucket_name(&bucket)?;
    reject_query_parameters(uri.query(), &["x-id"], uri.path())?;
    bucket_namespace(&state, &bucket).await?;
    let content_type = header_text(&headers, header::CONTENT_TYPE)?
        .ok_or_else(|| S3Error::invalid("Content-Type is required", uri.path()))?;
    let boundary = multer::parse_boundary(content_type)
        .map_err(|_| S3Error::invalid("multipart/form-data boundary is invalid", uri.path()))?;
    let mut multipart = multer::Multipart::new(body.into_data_stream(), boundary);
    let mut fields = BTreeMap::<String, String>::new();
    let mut uploaded = None;
    while let Some(mut field) = multipart.next_field().await.map_err(|error| {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "MalformedPOSTRequest",
            error.to_string(),
            uri.path(),
        )
    })? {
        let name = field
            .name()
            .ok_or_else(|| S3Error::invalid("POST form field name is missing", uri.path()))?
            .to_string();
        if name != "file" {
            if uploaded.is_some() {
                return Err(S3Error::invalid(
                    "the file field must be the final POST form field",
                    uri.path(),
                ));
            }
            let mut value = Vec::new();
            while let Some(chunk) = field.chunk().await.map_err(|error| {
                S3Error::new(
                    StatusCode::BAD_REQUEST,
                    "MalformedPOSTRequest",
                    error.to_string(),
                    uri.path(),
                )
            })? {
                if value.len().saturating_add(chunk.len()) > 64 * 1024 {
                    return Err(S3Error::invalid("POST form field is too large", uri.path()));
                }
                value.extend_from_slice(&chunk);
            }
            let value = String::from_utf8(value)
                .map_err(|_| S3Error::invalid("POST form field is not UTF-8", uri.path()))?;
            if fields.insert(name, value).is_some() {
                return Err(S3Error::invalid(
                    "POST form field was supplied more than once",
                    uri.path(),
                ));
            }
            continue;
        }
        if uploaded.is_some() {
            return Err(S3Error::invalid(
                "POST form contains more than one file field",
                uri.path(),
            ));
        }
        let filename = field.file_name().unwrap_or_default().to_string();
        let key_template = fields
            .get("key")
            .ok_or_else(|| S3Error::invalid("POST form key is required", uri.path()))?;
        let key = key_template.replace("${filename}", &filename);
        validate_object_identity(&bucket, &key, uri.path())?;
        let policy = validate_post_policy(&state, &bucket, &key, &fields, uri.path())?;
        let byte_count = Arc::new(AtomicU64::new(0));
        let stream_count = byte_count.clone();
        let stream = field.map(move |item| {
            if let Ok(bytes) = &item {
                stream_count.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
            item
        });
        let receipt =
            put_policy_object_stream_receipts(&state, Body::from_stream(stream), None, false)
                .await
                .map_err(|error| map_api_error(error, uri.path()))?
                .receipt;
        let size = byte_count.load(Ordering::Relaxed);
        if size < policy.min_content_length || size > policy.max_content_length {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "EntityTooLarge",
                "the uploaded file does not satisfy content-length-range",
                uri.path(),
            ));
        }
        uploaded = Some((key, receipt, size));
    }
    let (key, receipt, size) =
        uploaded.ok_or_else(|| S3Error::invalid("POST form file field is required", uri.path()))?;
    let partition = bucket_partition_state(&state, &bucket, key.as_bytes()).await?;
    let content_type = fields
        .get("Content-Type")
        .or_else(|| fields.get("content-type"))
        .cloned()
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let metadata = fields
        .iter()
        .filter_map(|(name, value)| {
            name.strip_prefix("x-amz-meta-")
                .map(|name| (name.to_string(), value.clone()))
        })
        .collect();
    let published = bucket_put(
        State(state.clone()),
        Json(BucketPutRequest {
            bucket: partition.partition.namespace_id.to_string(),
            key_hex: hex::encode(key.as_bytes()),
            content_cid: receipt.cid.clone(),
            content_placement: receipt.placement.clone(),
            logical_size: size,
            content_type,
            metadata,
            if_generation: None,
            if_cid: None,
            request_id: request_id(),
            preverified_durability: vec![receipt.clone()],
            partition_fence: Some(partition.write_fence()),
        }),
    )
    .await
    .map_err(|error| map_api_error(error, uri.path()))?
    .0;
    let etag = quoted_etag(&receipt.cid.to_string());
    let location = format!("/{bucket}/{}", aws_uri_encode(key.as_bytes(), false));
    let status = fields
        .get("success_action_status")
        .map(String::as_str)
        .unwrap_or("204");
    let response_request_id = request_id();
    let mut response = match status {
        "200" => StatusCode::OK.into_response(),
        "201" => xml_response(
            StatusCode::CREATED,
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><PostResponse><Location>{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag></PostResponse>",
                xml_escape(&location),
                xml_escape(&bucket),
                xml_escape(&key),
                xml_escape(&etag),
            ),
            &response_request_id,
        ),
        "204" => StatusCode::NO_CONTENT.into_response(),
        _ => {
            return Err(S3Error::invalid(
                "success_action_status must be 200, 201, or 204",
                uri.path(),
            ));
        }
    };
    insert_header(&mut response, header::ETAG, &etag, uri.path())?;
    insert_header(&mut response, header::LOCATION, &location, uri.path())?;
    if let Some(version) = published["object_descriptor_cid"].as_str() {
        insert_header(&mut response, "x-amz-version-id", version, uri.path())?;
    }
    add_s3_headers(&mut response, &response_request_id, Some(&state));
    Ok(response)
}

struct ValidatedPostPolicy {
    min_content_length: u64,
    max_content_length: u64,
}

fn validate_post_policy(
    state: &AppState,
    bucket: &str,
    key: &str,
    fields: &BTreeMap<String, String>,
    resource: &str,
) -> Result<ValidatedPostPolicy, S3Error> {
    let config = state
        .s3
        .as_ref()
        .ok_or_else(|| S3Error::no_bucket(bucket))?;
    let policy_text = fields
        .get("policy")
        .ok_or_else(|| S3Error::invalid("POST policy is required", resource))?;
    let policy_bytes = BASE64
        .decode(policy_text)
        .map_err(|_| S3Error::invalid("POST policy is not valid base64", resource))?;
    let policy: serde_json::Value = serde_json::from_slice(&policy_bytes)
        .map_err(|_| S3Error::invalid("POST policy is not valid JSON", resource))?;
    let expiration = policy["expiration"]
        .as_str()
        .ok_or_else(|| S3Error::invalid("POST policy expiration is required", resource))?;
    let expiration = OffsetDateTime::parse(expiration, &Rfc3339)
        .map_err(|_| S3Error::invalid("POST policy expiration is invalid", resource))?;
    if OffsetDateTime::now_utc() > expiration {
        return Err(S3Error::new(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "POST policy has expired",
            resource,
        ));
    }
    let algorithm = fields
        .get("x-amz-algorithm")
        .ok_or_else(|| S3Error::invalid("x-amz-algorithm is required", resource))?;
    if algorithm != "AWS4-HMAC-SHA256" {
        return Err(S3Error::invalid(
            "unsupported POST signing algorithm",
            resource,
        ));
    }
    let credential = fields
        .get("x-amz-credential")
        .ok_or_else(|| S3Error::invalid("x-amz-credential is required", resource))?;
    let amz_date = fields
        .get("x-amz-date")
        .ok_or_else(|| S3Error::invalid("x-amz-date is required", resource))?;
    let signature = fields
        .get("x-amz-signature")
        .ok_or_else(|| S3Error::invalid("x-amz-signature is required", resource))?;
    let scope = credential.split('/').collect::<Vec<_>>();
    if scope.len() != 5
        || scope[0] != config.access_key_id
        || scope[2] != config.region
        || scope[3] != "s3"
        || scope[4] != "aws4_request"
        || !amz_date.starts_with(scope[1])
    {
        return Err(S3Error::new(
            StatusCode::FORBIDDEN,
            "InvalidAccessKeyId",
            "POST credential scope is invalid",
            resource,
        ));
    }
    let mut root_key = b"AWS4".to_vec();
    root_key.extend_from_slice(&config.secret_access_key);
    let date_key = hmac_bytes(&root_key, scope[1].as_bytes())?;
    let region_key = hmac_bytes(&date_key, config.region.as_bytes())?;
    let service_key = hmac_bytes(&region_key, b"s3")?;
    let signing_key = hmac_bytes(&service_key, b"aws4_request")?;
    let supplied = hex::decode(signature).map_err(|_| {
        S3Error::new(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "POST policy signature is invalid",
            resource,
        )
    })?;
    let mut mac = HmacSha256::new_from_slice(&signing_key).map_err(|_| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "failed to construct signing key",
            resource,
        )
    })?;
    mac.update(policy_text.as_bytes());
    mac.verify_slice(&supplied).map_err(|_| {
        S3Error::new(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "POST policy signature does not match",
            resource,
        )
    })?;

    let mut effective = fields.clone();
    effective.insert("bucket".to_string(), bucket.to_string());
    effective.insert("key".to_string(), key.to_string());
    let conditions = policy["conditions"]
        .as_array()
        .ok_or_else(|| S3Error::invalid("POST policy conditions are required", resource))?;
    let mut min_content_length = 0;
    let mut max_content_length = state.max_object_bytes.unwrap_or(u64::MAX);
    let mut covered_fields = HashSet::new();
    for condition in conditions {
        if let Some(exact) = condition.as_object() {
            for (name, expected) in exact {
                covered_fields.insert(name.to_string());
                let expected = expected.as_str().ok_or_else(|| {
                    S3Error::invalid("POST policy condition is invalid", resource)
                })?;
                if effective.get(name).map(String::as_str) != Some(expected) {
                    return Err(S3Error::new(
                        StatusCode::FORBIDDEN,
                        "AccessDenied",
                        format!("POST policy condition for {name} was not satisfied"),
                        resource,
                    ));
                }
            }
            continue;
        }
        let condition = condition
            .as_array()
            .ok_or_else(|| S3Error::invalid("POST policy condition is invalid", resource))?;
        let operation = condition
            .first()
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if operation == "content-length-range" {
            min_content_length = condition
                .get(1)
                .and_then(|value| value.as_u64())
                .ok_or_else(|| S3Error::invalid("content-length-range is invalid", resource))?;
            max_content_length = condition
                .get(2)
                .and_then(|value| value.as_u64())
                .ok_or_else(|| S3Error::invalid("content-length-range is invalid", resource))?
                .min(max_content_length);
            continue;
        }
        let name = condition
            .get(1)
            .and_then(|value| value.as_str())
            .and_then(|name| name.strip_prefix('$'))
            .ok_or_else(|| S3Error::invalid("POST policy field condition is invalid", resource))?;
        covered_fields.insert(name.to_string());
        let expected = condition
            .get(2)
            .and_then(|value| value.as_str())
            .ok_or_else(|| S3Error::invalid("POST policy field condition is invalid", resource))?;
        let actual = effective.get(name).map(String::as_str).unwrap_or_default();
        let satisfied = match operation {
            "eq" => actual == expected,
            "starts-with" => actual.starts_with(expected),
            _ => {
                return Err(S3Error::invalid(
                    "POST policy operation is unsupported",
                    resource,
                ));
            }
        };
        if !satisfied {
            return Err(S3Error::new(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                format!("POST policy condition for {name} was not satisfied"),
                resource,
            ));
        }
    }
    if min_content_length > max_content_length {
        return Err(S3Error::invalid(
            "content-length-range is invalid",
            resource,
        ));
    }
    for name in fields.keys() {
        if matches!(name.as_str(), "policy" | "x-amz-signature" | "submit")
            || name.starts_with("x-ignore-")
        {
            continue;
        }
        if !covered_fields.contains(name) {
            return Err(S3Error::new(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                format!("POST form field {name} is not covered by the policy"),
                resource,
            ));
        }
    }
    Ok(ValidatedPostPolicy {
        min_content_length,
        max_content_length,
    })
}

pub(super) async fn s3_delete_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, S3Error> {
    let auth = authorize(&state, &method, &uri, &headers)?;
    verify_empty_payload(&auth, uri.path())?;
    reject_query_parameters(uri.query(), &["x-id"], uri.path())?;
    reject_unsupported_control_headers(&headers, uri.path())?;
    let resolved = bucket_namespace_state(&state, &bucket).await?;
    if resolved.partition_map.state != BucketPartitionMapState::Active {
        return Err(S3Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "SlowDown",
            "bucket metadata is being repartitioned",
            uri.path(),
        )
        .with_retry_after(1));
    }
    let namespace_id = resolved.control_namespace_id;
    ensure_bucket_empty(&state, &namespace_id, uri.path()).await?;
    mark_bucket_deleted(&state, &namespace_id, uri.path()).await?;
    invalidate_fast_path_bucket(&state, &bucket);
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_s3_headers(&mut response, &auth.request_id, Some(&state));
    Ok(response)
}

fn bucket_subresource(query: Option<&str>) -> Result<Option<BucketSubresource>, S3Error> {
    let mut selected = None;
    for subresource in [
        BucketSubresource::Tagging,
        BucketSubresource::Cors,
        BucketSubresource::Lifecycle,
    ] {
        if has_query_parameter(query, subresource.query_name()) {
            if selected.is_some() {
                return Err(S3Error::invalid(
                    "only one bucket subresource may be requested",
                    "/",
                ));
            }
            selected = Some(subresource);
        }
    }
    Ok(selected)
}

pub(super) async fn s3_bucket_subresource(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, S3Error> {
    let auth = authorize(&state, &method, &uri, &headers)?;
    let subresource = bucket_subresource(uri.query())?
        .ok_or_else(|| S3Error::invalid("bucket subresource is required", uri.path()))?;
    reject_query_parameters(uri.query(), &[subresource.query_name(), "x-id"], uri.path())?;
    reject_unsupported_control_headers(&headers, uri.path())?;
    let namespace_id = bucket_namespace(&state, &bucket).await?;
    match method {
        Method::GET => {
            verify_empty_payload(&auth, uri.path())?;
            let body = get_bucket_internal_raw(&state, &namespace_id, subresource.key())
                .await
                .map_err(|error| map_api_error(error, uri.path()))?
                .ok_or_else(|| {
                    let (code, message) = match subresource {
                        BucketSubresource::Tagging => ("NoSuchTagSet", "The TagSet does not exist"),
                        BucketSubresource::Cors => (
                            "NoSuchCORSConfiguration",
                            "The CORS configuration does not exist",
                        ),
                        BucketSubresource::Lifecycle => (
                            "NoSuchLifecycleConfiguration",
                            "The lifecycle configuration does not exist",
                        ),
                    };
                    S3Error::new(StatusCode::NOT_FOUND, code, message, uri.path())
                })?;
            let body = String::from_utf8(body).map_err(|_| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "stored bucket configuration is not UTF-8",
                    uri.path(),
                )
            })?;
            Ok(xml_response(StatusCode::OK, body, &auth.request_id))
        }
        Method::PUT => {
            let body = read_body_limited(body, Some(1024 * 1024), "S3 bucket configuration")
                .await
                .map_err(|error| map_api_error(error, uri.path()))?;
            verify_buffered_payload(&auth, &body, uri.path())?;
            verify_buffered_checksums(&headers, &body, uri.path())?;
            validate_bucket_subresource(subresource, &body, uri.path())?;
            put_bucket_internal_raw(&state, &namespace_id, subresource.key(), body, uri.path())
                .await?;
            let mut response = StatusCode::OK.into_response();
            add_s3_headers(&mut response, &auth.request_id, Some(&state));
            Ok(response)
        }
        Method::DELETE => {
            verify_empty_payload(&auth, uri.path())?;
            delete_bucket_internal(&state, &namespace_id, subresource.key(), uri.path()).await?;
            let mut response = StatusCode::NO_CONTENT.into_response();
            add_s3_headers(&mut response, &auth.request_id, Some(&state));
            Ok(response)
        }
        _ => Err(S3Error::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource",
            uri.path(),
        )),
    }
}

fn validate_bucket_subresource(
    subresource: BucketSubresource,
    body: &[u8],
    resource: &str,
) -> Result<(), S3Error> {
    let malformed = || {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "The XML provided was not well-formed or did not validate",
            resource,
        )
    };
    match subresource {
        BucketSubresource::Tagging => {
            let tagging: BucketTagging =
                quick_xml::de::from_reader(body).map_err(|_| malformed())?;
            if tagging.tag_set.tags.len() > 10 {
                return Err(S3Error::invalid(
                    "a bucket may have at most 10 tags",
                    resource,
                ));
            }
            let mut keys = HashSet::new();
            for tag in tagging.tag_set.tags {
                if tag.key.is_empty()
                    || tag.key.len() > 128
                    || tag.value.len() > 256
                    || !keys.insert(tag.key)
                {
                    return Err(S3Error::invalid("the bucket TagSet is invalid", resource));
                }
            }
        }
        BucketSubresource::Cors => {
            let cors: BucketCorsConfiguration =
                quick_xml::de::from_reader(body).map_err(|_| malformed())?;
            if cors.rules.is_empty() || cors.rules.len() > 100 {
                return Err(S3Error::invalid(
                    "CORSConfiguration must contain 1 to 100 rules",
                    resource,
                ));
            }
            for rule in cors.rules {
                if rule.allowed_origins.is_empty()
                    || rule.allowed_methods.is_empty()
                    || rule.allowed_methods.iter().any(|method| {
                        !matches!(method.as_str(), "GET" | "PUT" | "HEAD" | "POST" | "DELETE")
                    })
                {
                    return Err(S3Error::invalid("the CORS rule is invalid", resource));
                }
            }
        }
        BucketSubresource::Lifecycle => {
            let lifecycle: BucketLifecycleConfiguration =
                quick_xml::de::from_reader(body).map_err(|_| malformed())?;
            if lifecycle.rules.is_empty() || lifecycle.rules.len() > 1000 {
                return Err(S3Error::invalid(
                    "LifecycleConfiguration must contain 1 to 1000 rules",
                    resource,
                ));
            }
            if lifecycle.rules.iter().any(|rule| {
                !matches!(rule.status.as_str(), "Enabled" | "Disabled")
                    || rule
                        .abort_incomplete_multipart_upload
                        .as_ref()
                        .is_some_and(|abort| abort.days_after_initiation == 0)
            }) {
                return Err(S3Error::invalid("the lifecycle rule is invalid", resource));
            }
        }
    }
    Ok(())
}

async fn s3_options_request(
    state: &AppState,
    bucket: &str,
    _key: Option<&str>,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<Response, S3Error> {
    let origin = header_text(headers, header::ORIGIN)?
        .ok_or_else(|| S3Error::invalid("Origin is required", uri.path()))?;
    let requested_method = header_text(headers, "access-control-request-method")?
        .ok_or_else(|| S3Error::invalid("Access-Control-Request-Method is required", uri.path()))?;
    let requested_headers = header_text(headers, "access-control-request-headers")?
        .map(|value| {
            value
                .split(',')
                .map(|name| name.trim().to_ascii_lowercase())
                .filter(|name| !name.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let namespace_id = bucket_namespace(state, bucket).await?;
    let body = get_bucket_internal_raw(state, &namespace_id, S3_BUCKET_CORS_KEY)
        .await
        .map_err(|error| map_api_error(error, uri.path()))?
        .ok_or_else(|| {
            S3Error::new(
                StatusCode::FORBIDDEN,
                "AccessForbidden",
                "CORS is not enabled for this bucket",
                uri.path(),
            )
        })?;
    let cors: BucketCorsConfiguration =
        quick_xml::de::from_reader(body.as_slice()).map_err(|_| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "stored CORS configuration is invalid",
                uri.path(),
            )
        })?;
    let rule = cors.rules.into_iter().find(|rule| {
        rule.allowed_origins
            .iter()
            .any(|allowed| allowed == "*" || allowed == origin)
            && rule
                .allowed_methods
                .iter()
                .any(|allowed| allowed == requested_method)
            && requested_headers.iter().all(|requested| {
                rule.allowed_headers
                    .iter()
                    .any(|allowed| cors_header_matches(&allowed.to_ascii_lowercase(), requested))
            })
    });
    let rule = rule.ok_or_else(|| {
        S3Error::new(
            StatusCode::FORBIDDEN,
            "AccessForbidden",
            "The CORS request is not allowed",
            uri.path(),
        )
    })?;
    let mut response = StatusCode::OK.into_response();
    insert_header(
        &mut response,
        "access-control-allow-origin",
        origin,
        uri.path(),
    )?;
    insert_header(
        &mut response,
        "access-control-allow-methods",
        &rule.allowed_methods.join(", "),
        uri.path(),
    )?;
    if !requested_headers.is_empty() {
        insert_header(
            &mut response,
            "access-control-allow-headers",
            &requested_headers.join(", "),
            uri.path(),
        )?;
    }
    if !rule.expose_headers.is_empty() {
        insert_header(
            &mut response,
            "access-control-expose-headers",
            &rule.expose_headers.join(", "),
            uri.path(),
        )?;
    }
    if let Some(max_age) = rule.max_age_seconds {
        insert_header(
            &mut response,
            "access-control-max-age",
            &max_age.to_string(),
            uri.path(),
        )?;
    }
    insert_header(&mut response, header::VARY, "Origin", uri.path())?;
    add_s3_headers(&mut response, &request_id(), Some(state));
    Ok(response)
}

fn cors_header_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == value {
        return true;
    }
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return false;
    };
    value.starts_with(prefix) && value.ends_with(suffix)
}

pub(super) async fn s3_head_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, S3Error> {
    let auth = authorize(&state, &method, &uri, &headers)?;
    verify_empty_payload(&auth, uri.path())?;
    reject_query_parameters(uri.query(), &["x-id"], uri.path())?;
    bucket_namespace(&state, &bucket).await?;
    let mut response = StatusCode::OK.into_response();
    add_s3_headers(&mut response, &auth.request_id, Some(&state));
    Ok(response)
}

pub(super) async fn s3_put_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<S3ObjectQuery>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, S3Error> {
    let auth = authorize(&state, &method, &uri, &headers)?;
    if query.upload_id.is_some() || query.part_number.is_some() {
        return s3_upload_part(
            state,
            S3UploadPartRequest {
                bucket,
                key,
                query,
                uri,
                headers,
                body,
                auth,
            },
        )
        .await;
    }
    validate_object_route(&bucket, &key, &query, uri.path())?;
    reject_object_query(uri.query(), uri.path())?;
    if headers.contains_key("x-amz-copy-source") {
        return s3_copy_object(&state, &bucket, &key, &uri, &headers, &auth).await;
    }
    reject_unsupported_put_headers(&headers, uri.path())?;
    // Bound complete object pipelines, not individual HTTP connections. Excess
    // writers backpressure at the body stream instead of each retaining four
    // multi-megabyte chunks while waiting for replica publication slots.
    let admission_started = time::Instant::now();
    let retry_after_seconds = s3_write_retry_after_seconds(&state);
    let owner_write_slots = fast_path::write_slots();
    let queue_permit = if owner_write_slots.is_some() {
        None
    } else {
        Some(state.s3_write_queue_slots.try_acquire().map_err(|_| {
            metrics::S3_WRITE_ADMISSION_REJECTIONS.fetch_add(1, Ordering::Relaxed);
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "SlowDown",
                "the bounded S3 write admission queue is full",
                uri.path(),
            )
            .with_retry_after(retry_after_seconds)
        })?)
    };
    let write_slots = owner_write_slots.unwrap_or_else(|| state.s3_write_slots.clone());
    let _write_permit = time::timeout(state.s3_write_queue_timeout, write_slots.acquire_owned())
        .await
        .map_err(|_| {
            metrics::S3_WRITE_ADMISSION_REJECTIONS.fetch_add(1, Ordering::Relaxed);
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "SlowDown",
                "the bounded S3 write admission queue is full",
                uri.path(),
            )
            .with_retry_after(retry_after_seconds)
        })?
        .map_err(|_| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "the S3 write admission queue is unavailable",
                uri.path(),
            )
        })?;
    drop(queue_permit);
    let _service_sample = S3WriteServiceSample::new(&state);
    metrics::S3_WRITE_ADMISSION_QUEUE_MICROS.fetch_add(
        admission_started
            .elapsed()
            .as_micros()
            .min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
    let (partition, current) =
        current_bucket_descriptor_snapshot(&state, &bucket, key.as_bytes()).await?;
    let namespace_id = partition.partition.namespace_id.clone();
    let mut if_cid = None;
    if headers.contains_key(header::IF_MATCH) && headers.contains_key(header::IF_NONE_MATCH) {
        return Err(S3Error::invalid(
            "If-Match and If-None-Match cannot be combined",
            uri.path(),
        ));
    }
    if let Some(expected) = header_text(&headers, header::IF_MATCH)? {
        let Some((value, descriptor)) = current.as_ref() else {
            return Err(precondition_failed(uri.path()));
        };
        if descriptor.tombstone || unquote_etag(expected) != descriptor_etag(descriptor) {
            return Err(precondition_failed(uri.path()));
        }
        if_cid = Some(value.cid.clone());
    } else if let Some(expected) = header_text(&headers, header::IF_NONE_MATCH)? {
        if expected != "*" {
            return Err(S3Error::invalid(
                "PutObject supports only If-None-Match: *",
                uri.path(),
            ));
        }
        if let Some((value, descriptor)) = current.as_ref() {
            if !descriptor.tombstone {
                return Err(precondition_failed(uri.path()));
            }
            if_cid = Some(value.cid.clone());
        }
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let metadata = user_metadata(&headers, uri.path())?;
    let (receipt, logical_size, preverified_durability) =
        upload_s3_body(&state, body, &headers, &auth, false, uri.path()).await?;
    let conditional = if_cid.is_some();
    let mut published = None;
    let mut last_conflict = None;
    for attempt in 0..64u64 {
        match bucket_put(
            State(state.clone()),
            Json(BucketPutRequest {
                bucket: namespace_id.to_string(),
                key_hex: hex::encode(key.as_bytes()),
                content_cid: receipt.cid.clone(),
                content_placement: receipt.placement.clone(),
                logical_size,
                content_type: content_type.clone(),
                metadata: metadata.clone(),
                if_generation: None,
                if_cid: if_cid.clone(),
                request_id: request_id(),
                preverified_durability: preverified_durability.clone(),
                partition_fence: Some(partition.write_fence()),
            }),
        )
        .await
        {
            Ok(response) => {
                published = Some(response.0);
                break;
            }
            Err(error)
                if !conditional
                    && matches!(
                        error.code,
                        ErrorCode::GenerationConflict | ErrorCode::Conflict
                    ) =>
            {
                last_conflict = Some(error);
                time::sleep(Duration::from_millis(
                    (attempt.saturating_add(1) * 5).min(100),
                ))
                .await;
            }
            Err(error) => return Err(map_api_error(error, uri.path())),
        }
    }
    let published = published.ok_or_else(|| {
        map_api_error(
            last_conflict.unwrap_or_else(|| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    ErrorCode::Conflict,
                    "S3 object publication did not converge",
                )
            }),
            uri.path(),
        )
    })?;

    let descriptor_cid = published["object_descriptor_cid"].as_str().ok_or_else(|| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "bucket publication omitted descriptor CID",
            uri.path(),
        )
    })?;
    let mut response = StatusCode::OK.into_response();
    insert_header(
        &mut response,
        header::ETAG,
        &quoted_etag(&receipt.cid.to_string()),
        uri.path(),
    )?;
    insert_header(
        &mut response,
        "x-amz-version-id",
        descriptor_cid,
        uri.path(),
    )?;
    add_s3_headers(&mut response, &auth.request_id, Some(&state));
    Ok(response)
}

struct S3WriteServiceSample {
    started: time::Instant,
    service_micros: Arc<AtomicU64>,
}

impl S3WriteServiceSample {
    fn new(state: &AppState) -> Self {
        Self {
            started: time::Instant::now(),
            service_micros: Arc::clone(&state.s3_write_service_micros),
        }
    }
}

impl Drop for S3WriteServiceSample {
    fn drop(&mut self) {
        let sample = self
            .started
            .elapsed()
            .as_micros()
            .clamp(1, u128::from(u64::MAX)) as u64;
        let mut current = self.service_micros.load(Ordering::Relaxed);
        loop {
            let next = ((u128::from(current) * 7 + u128::from(sample)) / 8)
                .min(u128::from(u64::MAX)) as u64;
            match self.service_micros.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }
}

fn s3_write_retry_after_seconds(state: &AppState) -> u64 {
    state
        .s3_write_service_micros
        .load(Ordering::Relaxed)
        .div_ceil(1_000_000)
        .clamp(1, 30)
}

pub(super) async fn s3_post_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<S3ObjectQuery>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, S3Error> {
    let auth = authorize(&state, &method, &uri, &headers)?;
    validate_object_identity(&bucket, &key, uri.path())?;
    reject_query_parameters(uri.query(), &["uploads", "uploadId", "x-id"], uri.path())?;
    reject_unsupported_control_headers(&headers, uri.path())?;
    let bytes = read_body_limited(body, Some(1024 * 1024), "S3 multipart request")
        .await
        .map_err(|error| map_api_error(error, uri.path()))?;
    verify_buffered_payload(&auth, &bytes, uri.path())?;
    verify_buffered_checksums(&headers, &bytes, uri.path())?;

    if has_query_parameter(uri.query(), "uploads") && query.upload_id.is_none() {
        reject_unsupported_put_headers(&headers, uri.path())?;
        if !bytes.is_empty() {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "CreateMultipartUpload does not accept a request body",
                uri.path(),
            ));
        }
        let bucket_namespace_id = bucket_namespace(&state, &bucket).await?;
        let control_namespace_id =
            ensure_multipart_control_namespace(&state, &bucket_namespace_id, uri.path()).await?;
        if all_multipart_uploads(&state, &control_namespace_id)
            .await?
            .len()
            >= state._publication_limits.max_staging_leases
        {
            return Err(S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "SlowDown",
                "the active multipart upload limit has been reached",
                uri.path(),
            ));
        }
        let upload_id = next_multipart_upload_id(&control_namespace_id);
        let upload = S3MultipartUpload {
            upload_id,
            bucket: bucket.clone(),
            bucket_namespace_id: bucket_namespace_id.to_string(),
            control_namespace_id: control_namespace_id.to_string(),
            key: key.clone(),
            content_type: headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string(),
            metadata: user_metadata(&headers, uri.path())?,
            initiated_at_unix_seconds: unix_seconds(),
            status: "open".to_string(),
            completion_hash: None,
            final_content_cid: None,
            final_content_placement: None,
        };
        put_multipart_upload(&state, &control_namespace_id, &upload, uri.path()).await?;
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId></InitiateMultipartUploadResult>",
            xml_escape(&bucket),
            xml_escape(&key),
            xml_escape(&upload.upload_id),
        );
        return Ok(xml_response(StatusCode::OK, xml, &auth.request_id));
    }

    let upload_id = query.upload_id.as_deref().ok_or_else(|| {
        S3Error::not_implemented(
            "only CreateMultipartUpload and CompleteMultipartUpload are implemented for POST",
            uri.path(),
        )
    })?;
    complete_multipart_upload(
        &state,
        &bucket,
        &key,
        upload_id,
        &bytes,
        &auth.request_id,
        uri.path(),
    )
    .await
}

async fn s3_upload_part(
    state: AppState,
    request: S3UploadPartRequest,
) -> Result<Response, S3Error> {
    let S3UploadPartRequest {
        bucket,
        key,
        query,
        uri,
        headers,
        body,
        auth,
    } = request;
    validate_object_identity(&bucket, &key, uri.path())?;
    reject_query_parameters(uri.query(), &["uploadId", "partNumber", "x-id"], uri.path())?;
    let upload_id = query
        .upload_id
        .as_deref()
        .ok_or_else(|| S3Error::invalid("uploadId is required", uri.path()))?;
    let part_number = query
        .part_number
        .ok_or_else(|| S3Error::invalid("partNumber is required", uri.path()))?;
    validate_part_number(part_number, uri.path())?;
    let stored_upload = get_matching_upload(&state, &bucket, &key, upload_id).await?;
    if stored_upload.upload.status != "open" {
        return Err(S3Error::new(
            StatusCode::CONFLICT,
            "OperationAborted",
            "the multipart upload is no longer accepting parts",
            uri.path(),
        ));
    }

    if headers.contains_key("x-amz-copy-source") {
        return s3_upload_part_copy(&state, &stored_upload, part_number, &uri, &headers, &auth)
            .await;
    }
    reject_unsupported_put_headers(&headers, uri.path())?;

    let (receipt, size, preverified_durability) =
        upload_s3_body(&state, body, &headers, &auth, true, uri.path()).await?;
    let part = S3MultipartPart {
        upload_id: stored_upload.upload.upload_id.clone(),
        part_number,
        content_cid: receipt.cid.clone(),
        content_placement: receipt.placement.clone().ok_or_else(|| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "multipart part was stored without authoritative placement",
                uri.path(),
            )
        })?,
        size,
        etag: receipt.cid.to_string(),
        durability_status: receipt.status,
        uploaded_at_unix_seconds: unix_seconds(),
        durability: preverified_durability,
    };
    put_multipart_part(&state, &stored_upload, &part, uri.path()).await?;
    let mut response = StatusCode::OK.into_response();
    insert_header(
        &mut response,
        header::ETAG,
        &quoted_etag(&part.etag),
        uri.path(),
    )?;
    add_s3_headers(&mut response, &auth.request_id, Some(&state));
    Ok(response)
}

async fn s3_copy_object(
    state: &AppState,
    bucket: &str,
    key: &str,
    uri: &Uri,
    headers: &HeaderMap,
    auth: &S3AuthContext,
) -> Result<Response, S3Error> {
    verify_empty_payload(auth, uri.path())?;
    verify_buffered_checksums(headers, &[], uri.path())?;
    reject_unsupported_control_headers(headers, uri.path())?;
    if headers.contains_key("x-amz-copy-source-range") {
        return Err(S3Error::invalid(
            "x-amz-copy-source-range is valid only for UploadPartCopy",
            uri.path(),
        ));
    }
    let (source_bucket, source_key) = copy_source(headers, uri.path())?;
    let (_, source) = current_bucket_descriptor(state, &source_bucket, source_key.as_bytes())
        .await?
        .filter(|(_, descriptor)| !descriptor.tombstone)
        .ok_or_else(|| S3Error::no_key(&source_bucket, &source_key))?;
    apply_copy_preconditions(headers, &source, uri.path())?;
    let content_cid = source
        .content_cid
        .clone()
        .ok_or_else(|| S3Error::no_key(&source_bucket, &source_key))?;
    let partition = bucket_partition_state(state, bucket, key.as_bytes()).await?;
    let directive = header_text(headers, "x-amz-metadata-directive")?.unwrap_or("COPY");
    let (content_type, metadata) = match directive {
        "COPY" => (source.content_type.clone(), source.metadata.clone()),
        "REPLACE" => (
            header_text(headers, header::CONTENT_TYPE)?
                .unwrap_or("application/octet-stream")
                .to_string(),
            user_metadata(headers, uri.path())?,
        ),
        _ => {
            return Err(S3Error::invalid(
                "x-amz-metadata-directive must be COPY or REPLACE",
                uri.path(),
            ));
        }
    };
    let published = bucket_put(
        State(state.clone()),
        Json(BucketPutRequest {
            bucket: partition.partition.namespace_id.to_string(),
            key_hex: hex::encode(key.as_bytes()),
            content_cid,
            content_placement: source.content_placement.clone(),
            logical_size: source.logical_size,
            content_type,
            metadata,
            if_generation: None,
            if_cid: None,
            request_id: request_id(),
            preverified_durability: Vec::new(),
            partition_fence: Some(partition.write_fence()),
        }),
    )
    .await
    .map_err(|error| map_api_error(error, uri.path()))?
    .0;
    let version = published["object_descriptor_cid"]
        .as_str()
        .unwrap_or_default();
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CopyObjectResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LastModified>{}</LastModified><ETag>{}</ETag></CopyObjectResult>",
        iso_timestamp(unix_seconds()),
        xml_escape(&quoted_etag(&descriptor_etag(&source))),
    );
    let mut response = xml_response(StatusCode::OK, xml, &auth.request_id);
    insert_header(&mut response, "x-amz-version-id", version, uri.path())?;
    add_s3_headers(&mut response, &auth.request_id, Some(state));
    Ok(response)
}

async fn s3_upload_part_copy(
    state: &AppState,
    upload: &StoredMultipartUpload,
    part_number: u32,
    uri: &Uri,
    headers: &HeaderMap,
    auth: &S3AuthContext,
) -> Result<Response, S3Error> {
    verify_empty_payload(auth, uri.path())?;
    verify_buffered_checksums(headers, &[], uri.path())?;
    reject_unsupported_control_headers(headers, uri.path())?;
    let (source_bucket, source_key) = copy_source(headers, uri.path())?;
    let (_, source) = current_bucket_descriptor(state, &source_bucket, source_key.as_bytes())
        .await?
        .filter(|(_, descriptor)| !descriptor.tombstone)
        .ok_or_else(|| S3Error::no_key(&source_bucket, &source_key))?;
    apply_copy_preconditions(headers, &source, uri.path())?;
    let source_cid = source
        .content_cid
        .clone()
        .ok_or_else(|| S3Error::no_key(&source_bucket, &source_key))?;
    let source_placement = source
        .content_placement
        .clone()
        .ok_or_else(|| S3Error::no_key(&source_bucket, &source_key))?;
    let requested_range = header_text(headers, "x-amz-copy-source-range")?
        .map(|value| parse_byte_range(value, source.logical_size, uri.path()))
        .transpose()?;
    let (content_cid, content_placement, size, durability_status, durability) =
        if requested_range.is_none() && !state.erasure_enabled {
            (
                source_cid,
                source_placement,
                source.logical_size,
                "durable".to_string(),
                Vec::new(),
            )
        } else {
            let range = requested_range.unwrap_or(S3ByteRange {
                start: 0,
                end: source.logical_size.saturating_sub(1),
            });
            let size = if source.logical_size == 0 {
                0
            } else {
                range.len()
            };
            let body = if size == 0 {
                Body::empty()
            } else {
                object_range_body(state.clone(), &source_cid, &source_placement, range)
                    .await
                    .map_err(|error| map_api_error(error, uri.path()))?
            };
            let receipts = put_policy_object_stream_receipts(state, body, Some(size), true)
                .await
                .map_err(|error| map_api_error(error, uri.path()))?;
            (
                receipts.receipt.cid.clone(),
                receipts.receipt.placement.clone().ok_or_else(|| {
                    S3Error::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "ServiceUnavailable",
                        "copied multipart part was stored without authoritative placement",
                        uri.path(),
                    )
                })?,
                size,
                receipts.receipt.status,
                receipts.blocks,
            )
        };
    let part = S3MultipartPart {
        upload_id: upload.upload.upload_id.clone(),
        part_number,
        etag: content_cid.to_string(),
        content_cid,
        content_placement,
        size,
        uploaded_at_unix_seconds: unix_seconds(),
        durability_status,
        durability,
    };
    put_multipart_part(state, upload, &part, uri.path()).await?;
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CopyPartResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LastModified>{}</LastModified><ETag>{}</ETag></CopyPartResult>",
        iso_timestamp(part.uploaded_at_unix_seconds),
        xml_escape(&quoted_etag(&part.etag)),
    );
    Ok(xml_response(StatusCode::OK, xml, &auth.request_id))
}

fn copy_source(headers: &HeaderMap, resource: &str) -> Result<(String, String), S3Error> {
    let source = header_text(headers, "x-amz-copy-source")?
        .ok_or_else(|| S3Error::invalid("x-amz-copy-source is required", resource))?;
    let source = source.split_once('?').map_or(source, |(path, _)| path);
    let decoded = percent_decode(source.trim_start_matches('/'))?;
    let decoded = String::from_utf8(decoded)
        .map_err(|_| S3Error::invalid("copy source must be UTF-8", resource))?;
    let (bucket, key) = decoded
        .split_once('/')
        .ok_or_else(|| S3Error::invalid("copy source must name a bucket and key", resource))?;
    validate_object_identity(bucket, key, resource)?;
    Ok((bucket.to_string(), key.to_string()))
}

fn apply_copy_preconditions(
    headers: &HeaderMap,
    descriptor: &BucketObjectDescriptor,
    resource: &str,
) -> Result<(), S3Error> {
    let etag = descriptor_etag(descriptor);
    if let Some(expected) = header_text(headers, "x-amz-copy-source-if-match")?
        && expected != "*"
        && unquote_etag(expected) != etag
    {
        return Err(precondition_failed(resource));
    }
    if let Some(expected) = header_text(headers, "x-amz-copy-source-if-none-match")?
        && (expected == "*" || unquote_etag(expected) == etag)
    {
        return Err(precondition_failed(resource));
    }
    Ok(())
}

pub(super) async fn s3_get_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<S3ObjectQuery>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, S3Error> {
    if query.upload_id.is_some() {
        return s3_list_parts(state, bucket, key, query, uri, method, headers).await;
    }
    object_response(
        state,
        S3ObjectReadRequest {
            bucket,
            key,
            query,
            uri,
            method,
            headers,
            head_only: false,
        },
    )
    .await
}

pub(super) async fn s3_head_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<S3ObjectQuery>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, S3Error> {
    object_response(
        state,
        S3ObjectReadRequest {
            bucket,
            key,
            query,
            uri,
            method,
            headers,
            head_only: true,
        },
    )
    .await
}

async fn object_response(
    state: AppState,
    request: S3ObjectReadRequest,
) -> Result<Response, S3Error> {
    let S3ObjectReadRequest {
        bucket,
        key,
        query,
        uri,
        method,
        headers,
        head_only,
    } = request;
    let auth = authorize(&state, &method, &uri, &headers)?;
    validate_object_route(&bucket, &key, &query, uri.path())?;
    reject_object_query(uri.query(), uri.path())?;
    verify_empty_payload(&auth, uri.path())?;
    let (resolved, current) =
        current_bucket_descriptor_snapshot(&state, &bucket, key.as_bytes()).await?;
    let (value, descriptor) = current
        .filter(|(_, descriptor)| !descriptor.tombstone)
        .ok_or_else(|| S3Error::no_key(&bucket, &key))?;
    let content_cid = descriptor
        .content_cid
        .clone()
        .ok_or_else(|| S3Error::no_key(&bucket, &key))?;
    let content_placement = descriptor
        .content_placement
        .clone()
        .ok_or_else(|| S3Error::no_key(&bucket, &key))?;
    apply_read_preconditions(&headers, &descriptor, uri.path())?;

    let requested_range = header_text(&headers, header::RANGE)?
        .map(|value| parse_byte_range(value, descriptor.logical_size, uri.path()))
        .transpose()?;
    let packed_payload = if !head_only && content_cid.codec == CODEC_SMALL_OBJECT {
        packed_small_object_payload(
            &state,
            &resolved.namespace,
            key.as_bytes(),
            &content_cid,
            descriptor.logical_size,
            Some(&value),
        )
        .await
        .map_err(|error| map_api_error(error, uri.path()))?
    } else {
        None
    };
    let mut response = match requested_range {
        Some(_) if head_only => StatusCode::PARTIAL_CONTENT.into_response(),
        Some(range) if packed_payload.is_some() => {
            let payload = packed_payload.expect("packed payload was checked above");
            let start = usize::try_from(range.start)
                .map_err(|_| S3Error::invalid("range start is too large", uri.path()))?;
            let end = usize::try_from(range.end.saturating_add(1))
                .map_err(|_| S3Error::invalid("range end is too large", uri.path()))?;
            (
                StatusCode::PARTIAL_CONTENT,
                Body::from(payload.slice(start..end)),
            )
                .into_response()
        }
        Some(range) => {
            let body = object_range_body(state.clone(), &content_cid, &content_placement, range)
                .await
                .map_err(|error| map_api_error(error, uri.path()))?;
            (StatusCode::PARTIAL_CONTENT, body).into_response()
        }
        None if head_only => StatusCode::OK.into_response(),
        None if packed_payload.is_some() => (
            StatusCode::OK,
            Body::from(packed_payload.expect("packed payload was checked above")),
        )
            .into_response(),
        None => get_object_at_placement(
            state.clone(),
            content_cid.clone(),
            Some(content_placement),
            None,
        )
        .await
        .map_err(|error| map_api_error(error, uri.path()))?,
    };
    insert_header(
        &mut response,
        header::CONTENT_TYPE,
        &descriptor.content_type,
        uri.path(),
    )?;
    insert_header(
        &mut response,
        header::CONTENT_LENGTH,
        &requested_range
            .map(|range| range.len())
            .unwrap_or(descriptor.logical_size)
            .to_string(),
        uri.path(),
    )?;
    insert_header(&mut response, header::ACCEPT_RANGES, "bytes", uri.path())?;
    if let Some(range) = requested_range {
        insert_header(
            &mut response,
            header::CONTENT_RANGE,
            &format!(
                "bytes {}-{}/{}",
                range.start, range.end, descriptor.logical_size
            ),
            uri.path(),
        )?;
    }
    insert_header(
        &mut response,
        header::ETAG,
        &quoted_etag(&descriptor_etag(&descriptor)),
        uri.path(),
    )?;
    let descriptor_cid = value.cid.to_string();
    insert_header(
        &mut response,
        "x-amz-version-id",
        &descriptor_cid,
        uri.path(),
    )?;
    for (name, value) in &descriptor.metadata {
        insert_header(
            &mut response,
            format!("x-amz-meta-{name}"),
            value,
            uri.path(),
        )?;
    }
    insert_header(
        &mut response,
        header::LAST_MODIFIED,
        &http_timestamp(descriptor.committed_at_unix_seconds),
        uri.path(),
    )?;
    add_s3_headers(&mut response, &auth.request_id, Some(&state));
    Ok(response)
}

pub(super) async fn packed_small_object_payload(
    state: &AppState,
    namespace: &NamespaceState,
    object_key: &[u8],
    logical_cid: &Cid,
    logical_size: u64,
    object_value: Option<&MerkleValue>,
) -> Result<Option<Bytes>, ApiError> {
    let location = match object_value {
        Some(value) => {
            packed_small_object_location_from_object_value(state, value, logical_cid, logical_size)?
        }
        None => None,
    };
    let location = match location {
        Some(location) => Some(location),
        None => packed_small_object_location(state, namespace, object_key, logical_cid).await?,
    };
    let Some(location) = location else {
        return Ok(None);
    };
    if location.logical_length != logical_size {
        return Err(ApiError::internal(
            "small-object extent length does not match its descriptor",
        ));
    }
    let end = location
        .offset
        .checked_add(location.stored_length)
        .and_then(|exclusive| exclusive.checked_sub(1))
        .ok_or_else(|| ApiError::internal("small-object extent range overflow"))?;
    let body = object_range_body(
        state.clone(),
        &location.extent_cid,
        &location.extent_placement,
        S3ByteRange {
            start: location.offset,
            end,
        },
    )
    .await?;
    let stored = read_body_limited(
        body,
        Some(location.stored_length),
        "packed small object record",
    )
    .await?;
    let payload = match location.encoding {
        ErasureStripeEncoding::Raw => stored,
        ErasureStripeEncoding::Zstd => {
            let logical_length = usize::try_from(location.logical_length)
                .map_err(|_| ApiError::internal("packed small-object length is too large"))?;
            tokio::task::spawn_blocking(move || zstd::bulk::decompress(&stored, logical_length))
                .await
                .map_err(|error| {
                    ApiError::internal(format!(
                        "packed small-object decompressor task failed: {error}"
                    ))
                })?
                .map_err(|error| {
                    ApiError::internal(format!("packed small-object decompression failed: {error}"))
                })?
        }
    };
    if payload.len() as u64 != location.logical_length
        || Cid::new(CODEC_SMALL_OBJECT, &payload) != *logical_cid
    {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::IntegrityFailure,
            "packed small-object CID verification failed",
        ));
    }
    Ok(Some(Bytes::from(payload)))
}

pub(super) async fn admin_small_object_pack(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Result<Json<SmallObjectPackReport>, ApiError> {
    let resolved = bucket_namespace_state(&state, &bucket)
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    let mut report = SmallObjectPackReport::default();
    for partition in resolved.partition_map.partitions {
        let mut attempt = 0u32;
        loop {
            match pack_small_objects_in_namespace(&state, &partition.namespace_id, true).await {
                Ok(partition_report) => {
                    report += partition_report;
                    break;
                }
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::Conflict | ErrorCode::GenerationConflict
                    ) && attempt < 7 =>
                {
                    attempt += 1;
                    // Background packing, repair leases, and object writes all
                    // legitimately advance the partition root. A forced pack
                    // is idempotent, so re-resolve after bounded backoff rather
                    // than exposing an internal optimistic-CAS race.
                    time::sleep(Duration::from_millis(10u64 << attempt.min(6))).await;
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(Json(report))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct S3ByteRange {
    start: u64,
    end: u64,
}

impl S3ByteRange {
    fn len(self) -> u64 {
        self.end - self.start + 1
    }
}

#[derive(Debug)]
struct ObjectRangeChunk {
    chunk: ObjectChunk,
    start: usize,
    end: usize,
}

fn object_manifest_range_chunks(
    manifest: &ObjectManifest,
    range: S3ByteRange,
) -> Result<Vec<ObjectRangeChunk>, ApiError> {
    let range_end = range
        .end
        .checked_add(1)
        .ok_or_else(|| ApiError::bad_request("object range end overflow"))?;
    manifest
        .chunks
        .iter()
        .filter_map(|chunk| {
            let chunk_end = chunk.offset.checked_add(chunk.size)?;
            let overlap_start = chunk.offset.max(range.start);
            let overlap_end = chunk_end.min(range_end);
            (overlap_start < overlap_end).then_some((chunk, overlap_start, overlap_end))
        })
        .map(|(chunk, overlap_start, overlap_end)| {
            Ok(ObjectRangeChunk {
                chunk: chunk.clone(),
                start: usize::try_from(overlap_start - chunk.offset)
                    .map_err(|_| ApiError::bad_request("object range start is too large"))?,
                end: usize::try_from(overlap_end - chunk.offset)
                    .map_err(|_| ApiError::bad_request("object range end is too large"))?,
            })
        })
        .collect()
}

async fn object_range_body(
    state: AppState,
    cid: &Cid,
    placement: &PlacementReference,
    range: S3ByteRange,
) -> Result<Body, ApiError> {
    if cid.codec == CODEC_SMALL_OBJECT {
        let bytes = get_block_range_at_placement(
            &state,
            cid,
            placement,
            range.start,
            range.end.saturating_add(1),
        )
        .await?;
        return Ok(Body::from(bytes));
    }
    if cid.codec == CODEC_ERASURE_MANIFEST {
        let manifest = if let Some(manifest) = fast_path::cached_erasure_manifest(cid) {
            manifest
        } else {
            let manifest_block = get_block_at_placement(&state, cid, placement).await?;
            let manifest: ErasureManifest =
                serde_json::from_slice(&manifest_block.payload).map_err(ApiError::serde)?;
            validate_erasure_resource_limits(&state, &manifest)?;
            let manifest = Arc::new(manifest);
            fast_path::cache_erasure_manifest(cid.clone(), manifest.clone());
            manifest
        };
        let range_end = range
            .end
            .checked_add(1)
            .ok_or_else(|| ApiError::bad_request("object range end overflow"))?;
        let selected = manifest
            .stripes
            .iter()
            .filter_map(|stripe| {
                let stripe_end = stripe.offset.checked_add(stripe.size)?;
                let overlap_start = stripe.offset.max(range.start);
                let overlap_end = stripe_end.min(range_end);
                (overlap_start < overlap_end).then(|| {
                    (
                        stripe.clone(),
                        (overlap_start - stripe.offset) as usize,
                        (overlap_end - stripe.offset) as usize,
                    )
                })
            })
            .collect::<Vec<_>>();
        if let [(stripe, start, end)] = selected.as_slice() {
            let bytes = erasure_stripe_range_bytes(
                &state,
                manifest.data_shards,
                manifest.parity_shards,
                stripe,
                *start..*end,
            )
            .await?;
            return Ok(Body::from(bytes));
        }
        let body_stream = stream::iter(selected.into_iter().map(move |(stripe, start, end)| {
            let state = state.clone();
            let manifest = manifest.clone();
            async move {
                let bytes = erasure_stripe_range_bytes(
                    &state,
                    manifest.data_shards,
                    manifest.parity_shards,
                    &stripe,
                    start..end,
                )
                .await
                .map_err(|error| {
                    warn!(
                        ?error,
                        offset = stripe.offset,
                        "erasure range stripe failed"
                    );
                    std::io::Error::other(error.message)
                })?;
                Ok::<Bytes, std::io::Error>(bytes)
            }
        }))
        .buffered(4);
        return Ok(Body::from_stream(body_stream));
    }
    if cid.codec != CODEC_OBJECT_MANIFEST {
        return Err(ApiError::bad_request("CID is not an object manifest"));
    }
    let manifest_block = get_block_at_placement(&state, cid, placement).await?;
    let manifest: ObjectManifest =
        serde_json::from_slice(&manifest_block.payload).map_err(ApiError::serde)?;
    validate_object_resource_limits(&state, &manifest)?;
    let chunks = object_manifest_range_chunks(&manifest, range)?;
    let body_stream = stream::iter(chunks.into_iter().map(move |selected| {
        let state = state.clone();
        async move {
            let payload = get_block_range_at_placement(
                &state,
                &selected.chunk.cid,
                &selected.chunk.placement,
                selected.start as u64,
                selected.end as u64,
            )
            .await
            .map_err(|error| std::io::Error::other(error.message))?;
            Ok::<Bytes, std::io::Error>(Bytes::from(payload))
        }
    }))
    .buffered(16);
    Ok(Body::from_stream(body_stream))
}

fn parse_byte_range(value: &str, size: u64, resource: &str) -> Result<S3ByteRange, S3Error> {
    let spec = value.strip_prefix("bytes=").ok_or_else(|| {
        S3Error::new(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "InvalidRange",
            "The requested range is not satisfiable",
            resource,
        )
    })?;
    if size == 0 || spec.contains(',') {
        return Err(S3Error::new(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "InvalidRange",
            "Only one satisfiable byte range may be requested",
            resource,
        ));
    }
    let (start, end) = spec.split_once('-').ok_or_else(|| {
        S3Error::new(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "InvalidRange",
            "The requested range is not satisfiable",
            resource,
        )
    })?;
    if start.is_empty() {
        let suffix = end.parse::<u64>().map_err(|_| {
            S3Error::new(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "InvalidRange",
                "The requested suffix range is invalid",
                resource,
            )
        })?;
        if suffix == 0 {
            return Err(S3Error::new(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "InvalidRange",
                "The requested suffix range is empty",
                resource,
            ));
        }
        return Ok(S3ByteRange {
            start: size.saturating_sub(suffix),
            end: size - 1,
        });
    }
    let start = start.parse::<u64>().map_err(|_| {
        S3Error::new(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "InvalidRange",
            "The requested range start is invalid",
            resource,
        )
    })?;
    if start >= size {
        return Err(S3Error::new(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "InvalidRange",
            "The requested range starts beyond the object",
            resource,
        ));
    }
    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>().map_err(|_| {
            S3Error::new(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "InvalidRange",
                "The requested range end is invalid",
                resource,
            )
        })?
    };
    if end < start {
        return Err(S3Error::new(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "InvalidRange",
            "The requested range end precedes its start",
            resource,
        ));
    }
    Ok(S3ByteRange {
        start,
        end: end.min(size - 1),
    })
}

pub(super) async fn s3_delete_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<S3ObjectQuery>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, S3Error> {
    let auth = authorize(&state, &method, &uri, &headers)?;
    if query.upload_id.is_some() {
        return abort_multipart_upload(&state, &bucket, &key, &query, &uri, &headers, &auth).await;
    }
    validate_object_route(&bucket, &key, &query, uri.path())?;
    reject_object_query(uri.query(), uri.path())?;
    reject_unsupported_control_headers(&headers, uri.path())?;
    verify_empty_payload(&auth, uri.path())?;
    let (partition, current) =
        current_bucket_descriptor_snapshot(&state, &bucket, key.as_bytes()).await?;
    let mut if_cid = None;
    if let Some(expected) = header_text(&headers, header::IF_MATCH)? {
        let Some((value, descriptor)) = current.as_ref() else {
            return Err(precondition_failed(uri.path()));
        };
        if descriptor.tombstone || unquote_etag(expected) != descriptor_etag(descriptor) {
            return Err(precondition_failed(uri.path()));
        }
        if_cid = Some(value.cid.clone());
    }
    let deleted = bucket_delete(
        State(state.clone()),
        Json(BucketDeleteRequest {
            bucket: partition.partition.namespace_id.to_string(),
            key_hex: hex::encode(key.as_bytes()),
            if_generation: None,
            if_cid,
            request_id: request_id(),
            partition_fence: Some(partition.write_fence()),
        }),
    )
    .await
    .map_err(|error| map_api_error(error, uri.path()))?
    .0;
    let version = deleted["object_descriptor_cid"]
        .as_str()
        .unwrap_or_default();
    let mut response = StatusCode::NO_CONTENT.into_response();
    insert_header(&mut response, "x-amz-delete-marker", "true", uri.path())?;
    insert_header(&mut response, "x-amz-version-id", version, uri.path())?;
    add_s3_headers(&mut response, &auth.request_id, Some(&state));
    Ok(response)
}

async fn s3_list_parts(
    state: AppState,
    bucket: String,
    key: String,
    query: S3ObjectQuery,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, S3Error> {
    let auth = authorize(&state, &method, &uri, &headers)?;
    verify_empty_payload(&auth, uri.path())?;
    validate_object_identity(&bucket, &key, uri.path())?;
    reject_query_parameters(
        uri.query(),
        &["uploadId", "max-parts", "part-number-marker", "x-id"],
        uri.path(),
    )?;
    let upload_id = query
        .upload_id
        .as_deref()
        .ok_or_else(|| S3Error::invalid("uploadId is required", uri.path()))?;
    let stored_upload = get_matching_upload(&state, &bucket, &key, upload_id).await?;
    let max_parts = query.max_parts.unwrap_or(1000);
    if max_parts > 1000 {
        return Err(S3Error::invalid("max-parts cannot exceed 1000", uri.path()));
    }
    let marker = query.part_number_marker.unwrap_or(0);
    let mut parts = multipart_parts(&state, &stored_upload.control_namespace_id, upload_id)
        .await?
        .into_iter()
        .filter(|part| part.part_number > marker)
        .collect::<Vec<_>>();
    parts.sort_by_key(|part| part.part_number);
    let truncated = max_parts > 0 && parts.len() > max_parts;
    parts.truncate(max_parts);
    let next_marker = truncated
        .then(|| parts.last().map(|part| part.part_number))
        .flatten();
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListPartsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId><Initiator><ID>pepper</ID><DisplayName>pepper</DisplayName></Initiator><Owner><ID>pepper</ID><DisplayName>pepper</DisplayName></Owner><StorageClass>STANDARD</StorageClass><PartNumberMarker>{marker}</PartNumberMarker>",
        xml_escape(&stored_upload.upload.bucket),
        xml_escape(&stored_upload.upload.key),
        xml_escape(&stored_upload.upload.upload_id),
    );
    if let Some(next_marker) = next_marker {
        xml.push_str(&format!(
            "<NextPartNumberMarker>{next_marker}</NextPartNumberMarker>"
        ));
    }
    xml.push_str(&format!(
        "<MaxParts>{max_parts}</MaxParts><IsTruncated>{truncated}</IsTruncated>"
    ));
    for part in parts {
        xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size></Part>",
            part.part_number,
            iso_timestamp(part.uploaded_at_unix_seconds),
            xml_escape(&quoted_etag(&part.etag)),
            part.size,
        ));
    }
    xml.push_str("</ListPartsResult>");
    Ok(xml_response(StatusCode::OK, xml, &auth.request_id))
}

async fn abort_multipart_upload(
    state: &AppState,
    bucket: &str,
    key: &str,
    query: &S3ObjectQuery,
    uri: &Uri,
    headers: &HeaderMap,
    auth: &S3AuthContext,
) -> Result<Response, S3Error> {
    verify_empty_payload(auth, uri.path())?;
    validate_object_identity(bucket, key, uri.path())?;
    reject_query_parameters(uri.query(), &["uploadId", "x-id"], uri.path())?;
    reject_unsupported_control_headers(headers, uri.path())?;
    let upload_id = query
        .upload_id
        .as_deref()
        .ok_or_else(|| S3Error::invalid("uploadId is required", uri.path()))?;
    let upload = get_matching_upload(state, bucket, key, upload_id).await?;
    if upload.upload.status != "open" {
        return Err(S3Error::new(
            StatusCode::CONFLICT,
            "OperationAborted",
            "the multipart upload is being completed",
            uri.path(),
        ));
    }
    delete_multipart_upload(state, &upload, uri.path()).await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_s3_headers(&mut response, &auth.request_id, Some(state));
    Ok(response)
}

async fn s3_list_multipart_uploads(
    state: &AppState,
    bucket: &str,
    query: &S3BucketQuery,
    uri: &Uri,
    auth: &S3AuthContext,
) -> Result<Response, S3Error> {
    reject_query_parameters(
        uri.query(),
        &[
            "uploads",
            "prefix",
            "delimiter",
            "max-uploads",
            "key-marker",
            "upload-id-marker",
            "encoding-type",
            "x-id",
        ],
        uri.path(),
    )?;
    if query
        .delimiter
        .as_deref()
        .is_some_and(|value| !value.is_empty())
    {
        return Err(S3Error::not_implemented(
            "delimiter grouping for ListMultipartUploads is not implemented",
            uri.path(),
        ));
    }
    if query
        .encoding_type
        .as_deref()
        .is_some_and(|value| value != "url")
    {
        return Err(S3Error::invalid("encoding-type must be url", uri.path()));
    }
    let bucket_namespace_id = bucket_namespace(state, bucket).await?;
    let max_uploads = query.max_uploads.unwrap_or(1000);
    if max_uploads > 1000 {
        return Err(S3Error::invalid(
            "max-uploads cannot exceed 1000",
            uri.path(),
        ));
    }
    let prefix = query.prefix.as_deref().unwrap_or_default();
    let key_marker = query.key_marker.as_deref().unwrap_or_default();
    let upload_marker = query.upload_id_marker.as_deref().unwrap_or_default();
    let control_namespace_id =
        multipart_control_namespace(state, &bucket_namespace_id, uri.path()).await?;
    let uploads = if let Some(control_namespace_id) = control_namespace_id {
        all_multipart_uploads(state, &control_namespace_id).await?
    } else {
        Vec::new()
    };
    let mut uploads = uploads
        .into_iter()
        .filter(|upload| multipart_upload_is_listed(upload, bucket, prefix))
        .filter(|upload| {
            upload.key.as_str() > key_marker
                || (upload.key == key_marker && upload.upload_id.as_str() > upload_marker)
        })
        .collect::<Vec<_>>();
    uploads.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| left.upload_id.cmp(&right.upload_id))
    });
    let truncated = max_uploads > 0 && uploads.len() > max_uploads;
    uploads.truncate(max_uploads);
    let next = truncated.then(|| uploads.last().cloned()).flatten();
    let encode_key = |value: &str| {
        if query.encoding_type.as_deref() == Some("url") {
            aws_uri_encode(value.as_bytes(), false)
        } else {
            xml_escape(value)
        }
    };
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{}</Bucket><KeyMarker>{}</KeyMarker><UploadIdMarker>{}</UploadIdMarker>",
        xml_escape(bucket),
        encode_key(key_marker),
        xml_escape(upload_marker),
    );
    if let Some(next) = &next {
        xml.push_str(&format!(
            "<NextKeyMarker>{}</NextKeyMarker><NextUploadIdMarker>{}</NextUploadIdMarker>",
            encode_key(&next.key),
            xml_escape(&next.upload_id),
        ));
    }
    xml.push_str(&format!(
        "<MaxUploads>{max_uploads}</MaxUploads><IsTruncated>{truncated}</IsTruncated><Prefix>{}</Prefix>",
        encode_key(prefix),
    ));
    if query.encoding_type.as_deref() == Some("url") {
        xml.push_str("<EncodingType>url</EncodingType>");
    }
    for upload in uploads {
        xml.push_str(&format!(
            "<Upload><Key>{}</Key><UploadId>{}</UploadId><Initiator><ID>pepper</ID><DisplayName>pepper</DisplayName></Initiator><Owner><ID>pepper</ID><DisplayName>pepper</DisplayName></Owner><StorageClass>STANDARD</StorageClass><Initiated>{}</Initiated></Upload>",
            encode_key(&upload.key),
            xml_escape(&upload.upload_id),
            iso_timestamp(upload.initiated_at_unix_seconds),
        ));
    }
    xml.push_str("</ListMultipartUploadsResult>");
    Ok(xml_response(StatusCode::OK, xml, &auth.request_id))
}

fn multipart_upload_is_listed(upload: &S3MultipartUpload, bucket: &str, prefix: &str) -> bool {
    // `completing` is an internal recovery state: the destination object may
    // already be committed while cleanup of the multipart-control record is
    // retried. S3 clients must not see that record as an active upload after
    // CompleteMultipartUpload has succeeded.
    upload.status == "open" && upload.bucket == bucket && upload.key.starts_with(prefix)
}

async fn decode_bucket_list_barrier_value(
    state: &AppState,
    value: &MerkleValue,
    resource: &str,
) -> Result<Option<S3ListBarrier>, S3Error> {
    let placement =
        placement_from_merkle_value(value).map_err(|error| map_api_error(error, resource))?;
    let block = get_block_at_placement(state, &value.cid, &placement)
        .await
        .map_err(|error| map_api_error(error, resource))?;
    if block.codec != CODEC_BUCKET_PARTITION_BARRIER {
        return Ok(None);
    }
    serde_json::from_slice(&block.payload)
        .map(Some)
        .map_err(|error| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                error.to_string(),
                resource,
            )
        })
}

async fn capture_bucket_list_barrier(
    state: &AppState,
    bucket: &ResolvedS3Bucket,
    resource: &str,
) -> Result<S3ListBarrier, S3Error> {
    let map_value = s3_current_value(
        state,
        &bucket.control_namespace_id,
        &hex::encode(S3_BUCKET_PARTITION_MAP_KEY),
    )
    .await
    .map_err(|error| map_api_error(error, resource))?
    .ok_or_else(|| {
        S3Error::new(
            StatusCode::CONFLICT,
            "InvalidBucketState",
            "bucket partition map is missing",
            resource,
        )
    })?;
    let map_placement =
        placement_from_merkle_value(&map_value).map_err(|error| map_api_error(error, resource))?;
    let map_block = get_block_at_placement(state, &map_value.cid, &map_placement)
        .await
        .map_err(|error| map_api_error(error, resource))?;
    let observed_map: BucketPartitionMap =
        serde_json::from_slice(&map_block.payload).map_err(|error| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                error.to_string(),
                resource,
            )
        })?;
    if observed_map != bucket.partition_map || observed_map.state != BucketPartitionMapState::Active
    {
        return Err(S3Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "SlowDown",
            "bucket partition map changed while establishing a LIST barrier",
            resource,
        )
        .with_retry_after(1));
    }
    let manager = namespace_manager(state).map_err(|error| map_api_error(error, resource))?;
    let mut partition_roots = stream::iter(bucket.partition_map.partitions.iter().cloned())
        .map(|partition| {
            let manager = manager.clone();
            async move {
                let namespace = manager
                    .linearizable_namespace_head(&partition.namespace_id)
                    .await
                    .map_err(|error| error.to_string())?;
                Ok::<_, String>(S3PartitionRoot {
                    partition_id: partition.partition_id,
                    namespace_id: partition.namespace_id.to_string(),
                    revision: namespace.current_revision,
                    root_cid: namespace.current_root_cid,
                })
            }
        })
        .buffer_unordered(bucket.partition_map.partitions.len())
        .try_collect::<Vec<_>>()
        .await
        .map_err(|error| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                error,
                resource,
            )
        })?;
    partition_roots.sort_by_key(|root| root.partition_id);
    let mut latest_key = S3_BUCKET_LIST_BARRIER_PREFIX.to_vec();
    latest_key.extend_from_slice(b"latest");
    let current = s3_current_value(
        state,
        &bucket.control_namespace_id,
        &hex::encode(&latest_key),
    )
    .await
    .map_err(|error| map_api_error(error, resource))?;
    if let Some(value) = &current {
        if let Some(previous) = decode_bucket_list_barrier_value(state, value, resource).await? {
            if previous.bucket_epoch == bucket.partition_map.epoch
                && previous.partition_roots == partition_roots
            {
                return Ok(previous);
            }
        }
    }
    let created_at_unix_seconds = unix_seconds();
    let identity_bytes = serde_json::to_vec(&(bucket.partition_map.epoch, &partition_roots))
        .map_err(|error| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                error.to_string(),
                resource,
            )
        })?;
    let barrier_id = hex::encode(blake3::hash(&identity_bytes).as_bytes());
    let barrier = S3ListBarrier {
        version: 1,
        bucket_epoch: bucket.partition_map.epoch,
        barrier_id,
        created_at_unix_seconds,
        partition_roots,
    };
    let body = serde_json::to_vec(&barrier).map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            error.to_string(),
            resource,
        )
    })?;
    let receipt = put_namespace_replicated_block(
        state,
        &bucket.control_namespace_id,
        CODEC_BUCKET_PARTITION_BARRIER,
        body,
    )
    .await
    .map_err(|error| map_api_error(error, resource))?;
    let metadata = placement_control_metadata(
        &receipt,
        "s3_bucket_list_barrier_placement",
        &barrier.bucket_epoch,
    )
    .map_err(|error| map_api_error(error, resource))?;
    let mut retained_key = S3_BUCKET_LIST_BARRIER_PREFIX.to_vec();
    retained_key.extend_from_slice(barrier.barrier_id.as_bytes());
    let commit = apply_multipart_transaction_preverified(
        state,
        &bucket.control_namespace_id,
        vec![
            NamespaceMutation::Put {
                key_hex: hex::encode(retained_key),
                value_cid: receipt.cid.clone(),
                value_kind: "s3_bucket_list_barrier".to_string(),
                metadata: metadata.clone(),
                precondition: KeyPrecondition::Absent,
            },
            NamespaceMutation::Put {
                key_hex: hex::encode(&latest_key),
                value_cid: receipt.cid.clone(),
                value_kind: "s3_bucket_list_barrier".to_string(),
                metadata,
                precondition: current
                    .as_ref()
                    .map(value_precondition)
                    .unwrap_or(KeyPrecondition::Absent),
            },
            NamespaceMutation::Assert {
                key_hex: hex::encode(S3_BUCKET_PARTITION_MAP_KEY),
                precondition: value_precondition(&map_value),
            },
        ],
        vec![receipt.cid.clone()],
        vec![receipt],
        0,
        resource,
    )
    .await;
    if let Err(error) = commit {
        if error.code == "ConditionalRequestConflict" {
            // Concurrent LIST requests commonly observe the same immutable
            // partition-root vector before either commits it. Exactly one CAS
            // wins; after that conflict, a linearizable read can safely reuse
            // the winner instead of leaking an internal race as an S3 retry.
            let latest = s3_current_value(
                state,
                &bucket.control_namespace_id,
                &hex::encode(&latest_key),
            )
            .await
            .map_err(|read_error| map_api_error(read_error, resource))?;
            if let Some(value) = latest.as_ref()
                && let Some(winner) =
                    decode_bucket_list_barrier_value(state, value, resource).await?
                && winner.bucket_epoch == barrier.bucket_epoch
                && winner.partition_roots == barrier.partition_roots
            {
                return Ok(winner);
            }
        }
        return Err(error);
    }
    metrics::S3_LIST_BARRIERS.fetch_add(1, Ordering::Relaxed);
    Ok(barrier)
}

async fn load_bucket_list_barrier(
    state: &AppState,
    control_namespace_id: &NamespaceId,
    barrier_id: &str,
    resource: &str,
) -> Result<S3ListBarrier, S3Error> {
    if barrier_id.len() != 64 || !barrier_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "continuation token contains an invalid barrier",
            resource,
        ));
    }
    let mut key = S3_BUCKET_LIST_BARRIER_PREFIX.to_vec();
    key.extend_from_slice(barrier_id.as_bytes());
    let value = s3_current_value(state, control_namespace_id, &hex::encode(key))
        .await
        .map_err(|error| map_api_error(error, resource))?
        .ok_or_else(|| {
            S3Error::new(
                StatusCode::BAD_REQUEST,
                "InvalidToken",
                "continuation token barrier is no longer retained",
                resource,
            )
        })?;
    let placement =
        placement_from_merkle_value(&value).map_err(|error| map_api_error(error, resource))?;
    let block = get_block_at_placement(state, &value.cid, &placement)
        .await
        .map_err(|error| map_api_error(error, resource))?;
    if block.codec != CODEC_BUCKET_PARTITION_BARRIER {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "continuation token barrier has an invalid codec",
            resource,
        ));
    }
    let barrier: S3ListBarrier = serde_json::from_slice(&block.payload).map_err(|_| {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "continuation token barrier is invalid",
            resource,
        )
    })?;
    if barrier.barrier_id != barrier_id || barrier.version != 1 {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "continuation token barrier does not match",
            resource,
        ));
    }
    Ok(barrier)
}

pub(super) async fn s3_list_objects_v2(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(query): Query<S3BucketQuery>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, S3Error> {
    let auth = authorize(&state, &method, &uri, &headers)?;
    verify_empty_payload(&auth, uri.path())?;
    if query.uploads.is_some() || has_query_parameter(uri.query(), "uploads") {
        return s3_list_multipart_uploads(&state, &bucket, &query, &uri, &auth).await;
    }
    reject_query_parameters(
        uri.query(),
        &[
            "list-type",
            "prefix",
            "delimiter",
            "max-keys",
            "continuation-token",
            "start-after",
            "encoding-type",
            "fetch-owner",
            "versions",
            "x-id",
        ],
        uri.path(),
    )?;
    if query.versions.is_some() {
        return Err(S3Error::not_implemented(
            "ListObjectVersions is not implemented",
            uri.path(),
        ));
    }
    if query.list_type != Some(2) {
        return Err(S3Error::not_implemented(
            "only ListObjectsV2 (list-type=2) is implemented",
            uri.path(),
        ));
    }
    if query
        .encoding_type
        .as_deref()
        .is_some_and(|value| value != "url")
    {
        return Err(S3Error::invalid("encoding-type must be url", uri.path()));
    }
    let max_keys = query.max_keys.unwrap_or(1000);
    if max_keys > 1000 {
        return Err(S3Error::invalid("max-keys cannot exceed 1000", uri.path()));
    }
    if query.continuation_token.is_some() && query.start_after.is_some() {
        return Err(S3Error::invalid(
            "continuation-token and start-after cannot be combined",
            uri.path(),
        ));
    }
    let resolved = bucket_namespace_state(&state, &bucket).await?;
    let control_namespace_id = resolved.control_namespace_id.clone();
    if max_keys == 0 {
        let encode_key = |value: &str| {
            if query.encoding_type.as_deref() == Some("url") {
                aws_uri_encode(value.as_bytes(), false)
            } else {
                xml_escape(value)
            }
        };
        let mut xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{}</Name><Prefix>{}</Prefix><KeyCount>0</KeyCount><MaxKeys>0</MaxKeys>",
            xml_escape(&bucket),
            encode_key(query.prefix.as_deref().unwrap_or_default()),
        );
        if let Some(delimiter) = &query.delimiter {
            xml.push_str(&format!("<Delimiter>{}</Delimiter>", encode_key(delimiter)));
        }
        if let Some(start_after) = &query.start_after {
            xml.push_str(&format!(
                "<StartAfter>{}</StartAfter>",
                encode_key(start_after)
            ));
        }
        if let Some(token) = &query.continuation_token {
            xml.push_str(&format!(
                "<ContinuationToken>{}</ContinuationToken>",
                xml_escape(token)
            ));
        }
        if query.encoding_type.as_deref() == Some("url") {
            xml.push_str("<EncodingType>url</EncodingType>");
        }
        xml.push_str("<IsTruncated>false</IsTruncated></ListBucketResult>");
        return Ok(xml_response(StatusCode::OK, xml, &auth.request_id));
    }
    let prefix = query.prefix.clone().unwrap_or_default().into_bytes();
    let delimiter = query.delimiter.clone().map(String::into_bytes);
    let token = query
        .continuation_token
        .as_deref()
        .map(decode_token)
        .transpose()?;
    if let Some(token) = &token {
        if token.control_namespace_id != control_namespace_id.to_string()
            || token.prefix_hex != hex::encode(&prefix)
            || token.delimiter_hex != delimiter.as_ref().map(hex::encode)
        {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "InvalidToken",
                "The continuation token does not match this listing",
                uri.path(),
            ));
        }
    }
    let (bucket_epoch, barrier_id, partition_roots) = if let Some(token) = &token {
        let barrier =
            load_bucket_list_barrier(&state, &control_namespace_id, &token.barrier_id, uri.path())
                .await?;
        if barrier.bucket_epoch != token.bucket_epoch {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "InvalidToken",
                "continuation token epoch does not match its barrier",
                uri.path(),
            ));
        }
        (
            token.bucket_epoch,
            token.barrier_id.clone(),
            barrier.partition_roots,
        )
    } else {
        let barrier = capture_bucket_list_barrier(&state, &resolved, uri.path()).await?;
        (
            barrier.bucket_epoch,
            barrier.barrier_id,
            barrier.partition_roots,
        )
    };
    let root_identity = hex::encode(
        blake3::hash(
            &serde_json::to_vec(&(bucket_epoch, &barrier_id, &partition_roots)).map_err(
                |error| {
                    S3Error::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        error.to_string(),
                        uri.path(),
                    )
                },
            )?,
        )
        .as_bytes(),
    );
    let initial_after = token
        .as_ref()
        .map(|token| hex::decode(&token.last_key_hex))
        .transpose()
        .map_err(|_| S3Error::invalid("invalid continuation token key", uri.path()))?
        .or_else(|| query.start_after.clone().map(String::into_bytes));
    let skip_common = token
        .as_ref()
        .and_then(|token| token.skip_common_prefix_hex.as_ref())
        .map(hex::decode)
        .transpose()
        .map_err(|_| S3Error::invalid("invalid continuation token prefix", uri.path()))?;
    let start = initial_after.as_deref().and_then(exclusive_start);

    let list_cache_key = S3ListCacheKey {
        bucket: bucket.clone(),
        root: root_identity,
        prefix: prefix.clone(),
        delimiter: delimiter.clone(),
        start_after: query.start_after.clone(),
        continuation_token: query.continuation_token.clone(),
        max_keys,
        encoding_url: query.encoding_type.as_deref() == Some("url"),
        fetch_owner: query.fetch_owner == Some(true),
    };
    if let Some(body) = state.s3_list_cache.get(&list_cache_key).await {
        S3_LIST_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
        return Ok(xml_bytes_response(StatusCode::OK, body, &auth.request_id));
    }
    let flight = state.s3_list_cache.flight(&list_cache_key).await;
    let list_guard = match flight.clone().try_lock_owned() {
        Ok(guard) => guard,
        Err(_) => {
            S3_LIST_CACHE_COALESCED.fetch_add(1, Ordering::Relaxed);
            flight.lock_owned().await
        }
    };
    if let Some(body) = state.s3_list_cache.get(&list_cache_key).await {
        S3_LIST_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
        return Ok(xml_bytes_response(StatusCode::OK, body, &auth.request_id));
    }
    S3_LIST_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);

    let mut candidates = Vec::new();
    let mut source_more = false;
    for partition_root in &partition_roots {
        metrics::S3_LIST_PARTITIONS_SCANNED.fetch_add(1, Ordering::Relaxed);
        let namespace_id = partition_root
            .namespace_id
            .parse::<Cid>()
            .ok()
            .and_then(|cid| NamespaceId::new(cid).ok())
            .ok_or_else(|| {
                S3Error::new(
                    StatusCode::BAD_REQUEST,
                    "InvalidToken",
                    "continuation token contains an invalid partition namespace",
                    uri.path(),
                )
            })?;
        let namespace = namespace_manager(&state)
            .map_err(|error| map_api_error(error, uri.path()))?
            .linearizable_namespace_head(&namespace_id)
            .await
            .map_err(|error| {
                S3Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ServiceUnavailable",
                    error.to_string(),
                    uri.path(),
                )
            })?;
        let namespace_store = direct_namespace_store(&state, &namespace).await;
        let mut cursor = None;
        let mut accepted = 0usize;
        let mut scanned = 0usize;
        loop {
            let page = pepper_merkle::scan(
                &namespace_store,
                &partition_root.root_cid,
                ScanQuery {
                    prefix: Some(prefix.clone()),
                    start: start.clone(),
                    end: Some(S3_INTERNAL_KEY_PREFIX.to_vec()),
                    limit: 10_000,
                    cursor: cursor.clone(),
                },
                MerkleLimits::default(),
            )
            .await
            .map_err(|error| {
                S3Error::new(
                    StatusCode::BAD_REQUEST,
                    "InvalidToken",
                    error.to_string(),
                    uri.path(),
                )
            })?;
            for entry in page.entries {
                scanned += 1;
                if entry.key.starts_with(S3_INTERNAL_KEY_PREFIX)
                    || entry.value.value_kind == "bucket_tombstone"
                {
                    continue;
                }
                candidates.push(entry);
                accepted += 1;
                if accepted > max_keys {
                    source_more = true;
                    break;
                }
            }
            if accepted > max_keys {
                break;
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
            if scanned >= 100_000 {
                source_more = true;
                break;
            }
        }
    }
    candidates.sort_by(|left, right| left.key.cmp(&right.key));
    let mut contents = Vec::new();
    let mut common_prefixes = Vec::<Vec<u8>>::new();
    let mut last_key = None;
    let mut last_common = skip_common.clone();
    let mut truncated = source_more;
    for entry in candidates {
        let descriptor = descriptor_from_merkle_value(&state, &entry.value)
            .await
            .map_err(|error| map_api_error(error, uri.path()))?;
        if descriptor.tombstone {
            continue;
        }
        if let Some(common) = common_prefix(&entry.key, &prefix, delimiter.as_deref()) {
            if last_common.as_ref() == Some(&common) {
                last_key = Some(entry.key);
                continue;
            }
            last_common = Some(common.clone());
            last_key = Some(entry.key);
            common_prefixes.push(common);
        } else {
            last_common = None;
            last_key = Some(entry.key.clone());
            contents.push((entry.key, entry.value.cid, descriptor));
        }
        if contents.len() + common_prefixes.len() >= max_keys {
            truncated = true;
            break;
        }
    }
    let next_token = if truncated {
        last_key
            .as_ref()
            .map(|last_key| {
                encode_token(&S3ContinuationToken {
                    version: 2,
                    control_namespace_id: control_namespace_id.to_string(),
                    bucket_epoch,
                    barrier_id: barrier_id.clone(),
                    prefix_hex: hex::encode(&prefix),
                    delimiter_hex: delimiter.as_ref().map(hex::encode),
                    last_key_hex: hex::encode(last_key),
                    skip_common_prefix_hex: last_common.as_ref().map(hex::encode),
                })
            })
            .transpose()
    } else {
        Ok(None)
    }?;

    let encode_key = |bytes: &[u8]| -> String {
        if query.encoding_type.as_deref() == Some("url") {
            aws_uri_encode(bytes, false)
        } else {
            let text = String::from_utf8_lossy(bytes);
            xml_escape(&text)
        }
    };
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{}</Name><Prefix>{}</Prefix><KeyCount>{}</KeyCount><MaxKeys>{}</MaxKeys>",
        xml_escape(&bucket),
        encode_key(&prefix),
        contents.len() + common_prefixes.len(),
        max_keys,
    );
    if let Some(delimiter) = delimiter.as_deref() {
        xml.push_str(&format!("<Delimiter>{}</Delimiter>", encode_key(delimiter)));
    }
    if let Some(start_after) = &query.start_after {
        xml.push_str(&format!(
            "<StartAfter>{}</StartAfter>",
            xml_escape(start_after)
        ));
    }
    if let Some(token) = &query.continuation_token {
        xml.push_str(&format!(
            "<ContinuationToken>{}</ContinuationToken>",
            xml_escape(token)
        ));
    }
    if query.encoding_type.as_deref() == Some("url") {
        xml.push_str("<EncodingType>url</EncodingType>");
    }
    xml.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
    for (key, _descriptor_cid, descriptor) in contents {
        xml.push_str("<Contents><Key>");
        xml.push_str(&encode_key(&key));
        xml.push_str("</Key><LastModified>");
        xml.push_str(&iso_timestamp(descriptor.committed_at_unix_seconds));
        xml.push_str("</LastModified><ETag>");
        xml.push_str(&xml_escape(&quoted_etag(&descriptor_etag(&descriptor))));
        xml.push_str("</ETag><Size>");
        xml.push_str(&descriptor.logical_size.to_string());
        xml.push_str("</Size><StorageClass>STANDARD</StorageClass>");
        if query.fetch_owner == Some(true) {
            xml.push_str("<Owner><ID>pepper</ID><DisplayName>pepper</DisplayName></Owner>");
        }
        xml.push_str("</Contents>");
    }
    for common in common_prefixes {
        xml.push_str("<CommonPrefixes><Prefix>");
        xml.push_str(&encode_key(&common));
        xml.push_str("</Prefix></CommonPrefixes>");
    }
    if let Some(token) = next_token {
        xml.push_str("<NextContinuationToken>");
        xml.push_str(&xml_escape(&token));
        xml.push_str("</NextContinuationToken>");
    }
    xml.push_str("</ListBucketResult>");
    let body = Bytes::from(xml);
    state
        .s3_list_cache
        .insert(list_cache_key, body.clone())
        .await;
    drop(list_guard);
    Ok(xml_bytes_response(StatusCode::OK, body, &auth.request_id))
}

async fn complete_multipart_upload(
    state: &AppState,
    bucket: &str,
    key: &str,
    upload_id: &str,
    body: &[u8],
    auth_request_id: &str,
    resource: &str,
) -> Result<Response, S3Error> {
    let request: CompleteMultipartUploadRequest =
        quick_xml::de::from_reader(body).map_err(|_| {
            S3Error::new(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "The XML provided was not well-formed or did not validate",
                resource,
            )
        })?;
    if request.parts.is_empty() || request.parts.len() > S3_MAX_MULTIPART_PARTS as usize {
        return Err(S3Error::invalid(
            "CompleteMultipartUpload must contain 1 to 10000 parts",
            resource,
        ));
    }
    let mut previous_number = 0;
    for part in &request.parts {
        validate_part_number(part.part_number, resource)?;
        if part.part_number <= previous_number {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "InvalidPartOrder",
                "The list of parts was not in ascending order",
                resource,
            ));
        }
        previous_number = part.part_number;
    }

    let completion_hash = hex::encode(Sha256::digest(body));
    let mut stored_upload = get_matching_upload(state, bucket, key, upload_id).await?;
    match stored_upload.upload.status.as_str() {
        "open" => {}
        "completing"
            if stored_upload.upload.completion_hash.as_deref() == Some(&completion_hash) => {}
        "completing" => {
            return Err(S3Error::new(
                StatusCode::CONFLICT,
                "OperationAborted",
                "CompleteMultipartUpload was already started with a different part list",
                resource,
            ));
        }
        _ => return Err(S3Error::no_upload(bucket, key)),
    }
    let control_namespace_id = stored_upload
        .upload
        .bucket_namespace_id
        .parse::<Cid>()
        .map_err(|_| S3Error::no_upload(bucket, key))
        .and_then(|cid| NamespaceId::new(cid).map_err(|_| S3Error::no_upload(bucket, key)))?;
    if bucket_namespace(state, bucket).await? != control_namespace_id {
        return Err(S3Error::no_upload(bucket, key));
    }
    let partition = bucket_partition_state(state, bucket, key.as_bytes()).await?;
    let namespace_id = partition.partition.namespace_id.clone();
    let stored_parts = multipart_parts(state, &stored_upload.control_namespace_id, upload_id)
        .await?
        .into_iter()
        .map(|part| (part.part_number, part))
        .collect::<BTreeMap<_, _>>();
    let mut selected = Vec::with_capacity(request.parts.len());
    for requested in &request.parts {
        let part = stored_parts.get(&requested.part_number).ok_or_else(|| {
            S3Error::new(
                StatusCode::BAD_REQUEST,
                "InvalidPart",
                "One or more of the specified parts could not be found",
                resource,
            )
        })?;
        if unquote_etag(&requested.etag) != part.etag {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "InvalidPart",
                "A supplied part ETag did not match the uploaded part",
                resource,
            ));
        }
        selected.push(part.clone());
    }
    validate_multipart_part_sizes(&selected, resource)?;
    if selected
        .iter()
        .any(|part| part.durability_status != "durable")
    {
        return Err(S3Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "one or more multipart parts have not reached their storage durability policy",
            resource,
        ));
    }

    let mut chunks = Vec::new();
    let mut stripes = Vec::new();
    let mut erasure_layout = None::<(u16, u16, u64)>;
    let mut replicated_layout = false;
    let mut total = 0u64;
    let mut chunk_size = 1u64;
    for part in &selected {
        let block = get_block_at_placement(state, &part.content_cid, &part.content_placement)
            .await
            .map_err(|error| map_api_error(error, resource))?;
        match block.codec {
            CODEC_OBJECT_MANIFEST if erasure_layout.is_none() => {
                replicated_layout = true;
                let manifest: ObjectManifest =
                    serde_json::from_slice(&block.payload).map_err(|error| {
                        S3Error::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            error.to_string(),
                            resource,
                        )
                    })?;
                validate_object_resource_limits(state, &manifest)
                    .map_err(|error| map_api_error(error, resource))?;
                if manifest.size != part.size {
                    return Err(S3Error::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        "multipart part size does not match its object manifest",
                        resource,
                    ));
                }
                chunk_size = chunk_size.max(manifest.chunk_size);
                for chunk in manifest.chunks {
                    chunks.push(ObjectChunk {
                        offset: total.checked_add(chunk.offset).ok_or_else(|| {
                            S3Error::new(
                                StatusCode::BAD_REQUEST,
                                "EntityTooLarge",
                                "completed object size overflow",
                                resource,
                            )
                        })?,
                        size: chunk.size,
                        cid: chunk.cid,
                        placement: chunk.placement,
                    });
                }
            }
            CODEC_ERASURE_MANIFEST if !replicated_layout => {
                let manifest: ErasureManifest =
                    serde_json::from_slice(&block.payload).map_err(|error| {
                        S3Error::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            error.to_string(),
                            resource,
                        )
                    })?;
                validate_erasure_resource_limits(state, &manifest)
                    .map_err(|error| map_api_error(error, resource))?;
                if manifest.size != part.size {
                    return Err(S3Error::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        "multipart part size does not match its erasure manifest",
                        resource,
                    ));
                }
                let layout = (
                    manifest.data_shards,
                    manifest.parity_shards,
                    manifest.stripe_size,
                );
                if erasure_layout.is_some_and(|existing| existing != layout) {
                    return Err(S3Error::new(
                        StatusCode::BAD_REQUEST,
                        "InvalidRequest",
                        "multipart parts use different erasure layouts",
                        resource,
                    ));
                }
                erasure_layout = Some(layout);
                for mut stripe in manifest.stripes {
                    stripe.offset = total.checked_add(stripe.offset).ok_or_else(|| {
                        S3Error::new(
                            StatusCode::BAD_REQUEST,
                            "EntityTooLarge",
                            "completed object size overflow",
                            resource,
                        )
                    })?;
                    stripes.push(stripe);
                }
            }
            _ => {
                return Err(S3Error::new(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "multipart parts use incompatible storage layouts",
                    resource,
                ));
            }
        }
        total = total.checked_add(part.size).ok_or_else(|| {
            S3Error::new(
                StatusCode::BAD_REQUEST,
                "EntityTooLarge",
                "completed object size overflow",
                resource,
            )
        })?;
        enforce_size_limit(state.max_object_bytes, total, "multipart object")
            .map_err(|error| map_api_error(error, resource))?;
    }
    let (manifest_codec, manifest_bytes) = if let Some((data, parity, stripe_size)) = erasure_layout
    {
        let manifest = ErasureManifest::new(total, data, parity, stripe_size, stripes);
        validate_erasure_resource_limits(state, &manifest)
            .map_err(|error| map_api_error(error, resource))?;
        (
            CODEC_ERASURE_MANIFEST,
            serde_json::to_vec(&manifest).map_err(|error| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    error.to_string(),
                    resource,
                )
            })?,
        )
    } else {
        let manifest = ObjectManifest::new(total, chunk_size, chunks);
        validate_object_resource_limits(state, &manifest)
            .map_err(|error| map_api_error(error, resource))?;
        (
            CODEC_OBJECT_MANIFEST,
            serde_json::to_vec(&manifest).map_err(|error| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    error.to_string(),
                    resource,
                )
            })?,
        )
    };
    let receipt =
        put_namespace_replicated_block(state, &namespace_id, manifest_codec, manifest_bytes)
            .await
            .map_err(|error| map_api_error(error, resource))?;
    let mut completion_durability = selected
        .iter()
        .flat_map(|part| part.durability.iter().cloned())
        .collect::<Vec<_>>();
    completion_durability.push(receipt.clone());
    if stored_upload.upload.status == "open" {
        let mut completing = stored_upload.upload.clone();
        completing.status = "completing".to_string();
        completing.completion_hash = Some(completion_hash.clone());
        completing.final_content_cid = Some(receipt.cid.clone());
        completing.final_content_placement = receipt.placement.clone();
        stored_upload = replace_multipart_upload(
            state,
            &stored_upload,
            completing,
            completion_durability.clone(),
            resource,
        )
        .await?;
    } else if stored_upload.upload.final_content_cid.as_ref() != Some(&receipt.cid) {
        return Err(S3Error::new(
            StatusCode::CONFLICT,
            "OperationAborted",
            "the multipart completion no longer matches its staged object",
            resource,
        ));
    }

    let existing = current_bucket_descriptor_by_namespace(state, &namespace_id, key.as_bytes())
        .await
        .map_err(|error| map_api_error(error, resource))?;
    let descriptor_cid = if let Some((value, descriptor)) = existing.filter(|(_, descriptor)| {
        !descriptor.tombstone
            && descriptor.content_cid.as_ref() == Some(&receipt.cid)
            && descriptor.logical_size == total
            && descriptor.content_type == stored_upload.upload.content_type
            && descriptor.metadata == stored_upload.upload.metadata
    }) {
        let _ = descriptor;
        value.cid.to_string()
    } else {
        let published = bucket_put(
            State(state.clone()),
            Json(BucketPutRequest {
                bucket: namespace_id.to_string(),
                key_hex: hex::encode(key.as_bytes()),
                content_cid: receipt.cid.clone(),
                content_placement: receipt.placement.clone(),
                logical_size: total,
                content_type: stored_upload.upload.content_type.clone(),
                metadata: stored_upload.upload.metadata.clone(),
                if_generation: None,
                if_cid: None,
                request_id: format!(
                    "s3-complete-{}",
                    hex::encode(Sha256::digest(
                        format!("{upload_id}:{completion_hash}").as_bytes()
                    ))
                ),
                preverified_durability: completion_durability,
                partition_fence: Some(partition.write_fence()),
            }),
        )
        .await
        .map_err(|error| map_api_error(error, resource))?
        .0;
        published["object_descriptor_cid"]
            .as_str()
            .ok_or_else(|| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "bucket publication omitted descriptor CID",
                    resource,
                )
            })?
            .to_string()
    };

    if let Err(error) = delete_multipart_upload(state, &stored_upload, resource).await {
        warn!(
            upload_id,
            error = %error.message,
            "multipart object committed but distributed multipart cleanup failed"
        );
        spawn_completed_multipart_cleanup(
            state.clone(),
            namespace_id,
            key.to_string(),
            upload_id.to_string(),
            receipt.cid.clone(),
        );
    }
    let etag = receipt.cid.to_string();
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Location>{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag></CompleteMultipartUploadResult>",
        xml_escape(resource),
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(&quoted_etag(&etag)),
    );
    let mut response = xml_response(StatusCode::OK, xml, auth_request_id);
    insert_header(&mut response, "x-amz-version-id", &descriptor_cid, resource)?;
    Ok(response)
}

fn spawn_completed_multipart_cleanup(
    state: AppState,
    bucket_namespace_id: NamespaceId,
    key: String,
    upload_id: String,
    expected_cid: Cid,
) {
    tokio::spawn(async move {
        let resource = format!("/{key}");
        for attempt in 0..10u64 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(250 * attempt)).await;
            }
            let published = completed_multipart_object_is_published(
                &state,
                &bucket_namespace_id,
                &key,
                &expected_cid,
                &resource,
            )
            .await;
            if !matches!(published, Ok(true)) {
                continue;
            }
            let stored = match multipart_upload(&state, &upload_id, &resource).await {
                Ok(Some(stored)) if stored.upload.status == "completing" => stored,
                Ok(_) => return,
                Err(_) => continue,
            };
            if delete_multipart_upload(&state, &stored, &resource)
                .await
                .is_ok()
            {
                info!(upload_id, "reconciled completed multipart upload");
                return;
            }
        }
        warn!(
            upload_id,
            "completed multipart upload cleanup remains pending"
        );
    });
}

async fn completed_multipart_object_is_published(
    state: &AppState,
    bucket_namespace_id: &NamespaceId,
    key: &str,
    expected_cid: &Cid,
    resource: &str,
) -> Result<bool, S3Error> {
    Ok(
        current_bucket_descriptor_by_namespace(state, bucket_namespace_id, key.as_bytes())
            .await
            .map_err(|error| map_api_error(error, resource))?
            .is_some_and(|(_, descriptor)| {
                !descriptor.tombstone && descriptor.content_cid.as_ref() == Some(expected_cid)
            }),
    )
}

fn validate_multipart_part_sizes(parts: &[S3MultipartPart], resource: &str) -> Result<(), S3Error> {
    if parts
        .iter()
        .take(parts.len().saturating_sub(1))
        .any(|part| part.size < S3_MIN_MULTIPART_PART_BYTES)
    {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "EntityTooSmall",
            "All parts except the last must be at least 5 MiB",
            resource,
        ));
    }
    Ok(())
}

async fn upload_s3_body(
    state: &AppState,
    body: Body,
    headers: &HeaderMap,
    auth: &S3AuthContext,
    force_erasure: bool,
    resource: &str,
) -> Result<(DurabilityReceipt, u64, Vec<DurabilityReceipt>), S3Error> {
    let content_length = headers
        .get("x-amz-decoded-content-length")
        .or_else(|| headers.get(header::CONTENT_LENGTH))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let has_aws_chunked_encoding = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|part| part.trim() == "aws-chunked"));
    if has_aws_chunked_encoding != auth.aws_chunked.is_some() {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "aws-chunked Content-Encoding and streaming SigV4 payload mode must be used together",
            resource,
        ));
    }
    let trailer_headers = Arc::new(Mutex::new(BTreeMap::<String, String>::new()));
    let body = if let Some(chunked) = auth.aws_chunked.clone() {
        aws_chunked_body(body, chunked, trailer_headers.clone())
    } else {
        body
    };
    let checksums = Arc::new(Mutex::new(S3BodyChecksums::default()));
    let byte_count = Arc::new(AtomicU64::new(0));
    let stream_checksums = checksums.clone();
    let stream_count = byte_count.clone();
    let stream = body.into_data_stream().map(move |item| {
        if let Ok(bytes) = &item {
            if let Ok(mut checksums) = stream_checksums.lock() {
                checksums.update(bytes);
            }
            stream_count.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }
        item
    });
    let body = Body::from_stream(stream);
    let receipts = put_policy_object_stream_receipts(state, body, content_length, force_erasure)
        .await
        .map_err(|error| map_api_error(error, resource))?;
    if let PayloadHash::Sha256(expected) = &auth.payload_hash {
        let actual: [u8; 32] = checksums
            .lock()
            .map_err(|_| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "payload digest lock poisoned",
                    resource,
                )
            })?
            .sha256
            .clone()
            .finalize()
            .into();
        if actual != *expected {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "XAmzContentSHA256Mismatch",
                "The provided x-amz-content-sha256 does not match the request body",
                resource,
            ));
        }
    }
    let mut checksum_headers = headers.clone();
    for (name, value) in trailer_headers
        .lock()
        .map_err(|_| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "aws-chunked trailer lock poisoned",
                resource,
            )
        })?
        .iter()
    {
        let name = axum::http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| S3Error::invalid("aws-chunked trailer name is invalid", resource))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| S3Error::invalid("aws-chunked trailer value is invalid", resource))?;
        checksum_headers.insert(name, value);
    }
    verify_request_checksums(
        &checksum_headers,
        &checksums
            .lock()
            .map_err(|_| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "payload checksum lock poisoned",
                    resource,
                )
            })?
            .clone(),
        resource,
    )?;
    let size = byte_count.load(Ordering::Relaxed);
    if let Some(expected) = header_text(headers, "x-amz-decoded-content-length")? {
        let expected = expected
            .parse::<u64>()
            .map_err(|_| S3Error::invalid("x-amz-decoded-content-length is invalid", resource))?;
        if expected != size {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "BadDigest",
                "x-amz-decoded-content-length did not match the decoded body",
                resource,
            ));
        }
    }
    Ok((receipts.receipt, size, receipts.blocks))
}

struct AwsChunkedDecoder {
    stream: futures_util::stream::BoxStream<'static, Result<Bytes, axum::Error>>,
    buffer: Vec<u8>,
    auth: AwsChunkedAuth,
    trailers: Arc<Mutex<BTreeMap<String, String>>>,
    chunk_count: usize,
}

fn aws_chunked_body(
    body: Body,
    auth: AwsChunkedAuth,
    trailers: Arc<Mutex<BTreeMap<String, String>>>,
) -> Body {
    let decoder = AwsChunkedDecoder {
        stream: body.into_data_stream().boxed(),
        buffer: Vec::new(),
        auth,
        trailers,
        chunk_count: 0,
    };
    Body::from_stream(futures_util::stream::try_unfold(
        decoder,
        |mut decoder| async move {
            match decoder.next_chunk().await? {
                Some(bytes) => Ok::<_, std::io::Error>(Some((bytes, decoder))),
                None => Ok::<_, std::io::Error>(None),
            }
        },
    ))
}

impl AwsChunkedDecoder {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, std::io::Error> {
        self.chunk_count = self.chunk_count.saturating_add(1);
        if self.chunk_count > 1_000_000 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "aws-chunked payload contains too many chunks",
            ));
        }
        let header = self.read_line().await?;
        let header = std::str::from_utf8(&header).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "aws-chunked header is not UTF-8",
            )
        })?;
        let mut fields = header.split(';');
        let size = usize::from_str_radix(fields.next().unwrap_or_default(), 16).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "aws-chunked size is invalid",
            )
        })?;
        let signature = fields
            .find_map(|field| field.strip_prefix("chunk-signature="))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "aws-chunked signature is missing",
                )
            })?
            .to_string();
        if size == 0 {
            self.verify_payload_signature(&[], &signature)?;
            self.read_trailers().await?;
            return Ok(None);
        }
        self.fill(size + 2).await?;
        let data = self.buffer.drain(..size).collect::<Vec<_>>();
        if self.buffer.drain(..2).collect::<Vec<_>>() != b"\r\n" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "aws-chunked data is not terminated by CRLF",
            ));
        }
        self.verify_payload_signature(&data, &signature)?;
        Ok(Some(Bytes::from(data)))
    }

    async fn fill(&mut self, size: usize) -> Result<(), std::io::Error> {
        while self.buffer.len() < size {
            let Some(chunk) = self.stream.next().await else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "aws-chunked payload ended early",
                ));
            };
            self.buffer
                .extend_from_slice(&chunk.map_err(std::io::Error::other)?);
        }
        Ok(())
    }

    async fn read_line(&mut self) -> Result<Vec<u8>, std::io::Error> {
        loop {
            if let Some(position) = self.buffer.windows(2).position(|bytes| bytes == b"\r\n") {
                let line = self.buffer.drain(..position).collect::<Vec<_>>();
                self.buffer.drain(..2);
                return Ok(line);
            }
            if self.buffer.len() > 16 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "aws-chunked header is too large",
                ));
            }
            let Some(chunk) = self.stream.next().await else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "aws-chunked payload ended before CRLF",
                ));
            };
            self.buffer
                .extend_from_slice(&chunk.map_err(std::io::Error::other)?);
        }
    }

    fn verify_payload_signature(
        &mut self,
        data: &[u8],
        signature: &str,
    ) -> Result<(), std::io::Error> {
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
            self.auth.amz_date,
            self.auth.credential_scope,
            self.auth.prior_signature,
            hex::encode(Sha256::digest([])),
            hex::encode(Sha256::digest(data)),
        );
        self.verify_signature(&string_to_sign, signature)?;
        self.auth.prior_signature = signature.to_string();
        Ok(())
    }

    fn verify_signature(&self, value: &str, signature: &str) -> Result<(), std::io::Error> {
        let signature = hex::decode(signature).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "aws-chunked signature is not hexadecimal",
            )
        })?;
        let mut mac = HmacSha256::new_from_slice(&self.auth.signing_key)
            .map_err(|_| std::io::Error::other("failed to construct aws-chunked signing key"))?;
        mac.update(value.as_bytes());
        mac.verify_slice(&signature).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "aws-chunked signature does not match",
            )
        })
    }

    async fn read_trailers(&mut self) -> Result<(), std::io::Error> {
        let mut trailers = BTreeMap::new();
        loop {
            let line = self.read_line().await?;
            if line.is_empty() {
                break;
            }
            let line = std::str::from_utf8(&line).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "aws-chunked trailer is not UTF-8",
                )
            })?;
            let (name, value) = line.split_once(':').ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "aws-chunked trailer is invalid",
                )
            })?;
            let name = name.to_ascii_lowercase();
            if trailers.insert(name, value.trim().to_string()).is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "aws-chunked trailer is duplicated",
                ));
            }
        }
        let signature = trailers.remove("x-amz-trailer-signature");
        if self.auth.signed_trailers {
            let signature = signature.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "x-amz-trailer-signature is missing",
                )
            })?;
            let canonical = trailers
                .iter()
                .map(|(name, value)| format!("{name}:{}\n", normalize_header_value(value)))
                .collect::<String>();
            let string_to_sign = format!(
                "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
                self.auth.amz_date,
                self.auth.credential_scope,
                self.auth.prior_signature,
                hex::encode(Sha256::digest(canonical.as_bytes())),
            );
            self.verify_signature(&string_to_sign, &signature)?;
        } else if signature.is_some() || !trailers.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsigned aws-chunked trailers are not allowed",
            ));
        }
        *self
            .trailers
            .lock()
            .map_err(|_| std::io::Error::other("aws-chunked trailer lock poisoned"))? = trailers;
        Ok(())
    }
}

#[derive(Clone)]
struct S3BodyChecksums {
    md5: Md5,
    sha1: Sha1,
    sha256: Sha256,
    crc32: crc32fast::Hasher,
    crc32c: u32,
}

impl Default for S3BodyChecksums {
    fn default() -> Self {
        Self {
            md5: Md5::new(),
            sha1: Sha1::new(),
            sha256: Sha256::new(),
            crc32: crc32fast::Hasher::new(),
            crc32c: 0,
        }
    }
}

impl S3BodyChecksums {
    fn update(&mut self, bytes: &[u8]) {
        self.md5.update(bytes);
        self.sha1.update(bytes);
        self.sha256.update(bytes);
        self.crc32.update(bytes);
        self.crc32c = crc32c::crc32c_append(self.crc32c, bytes);
    }
}

fn verify_request_checksums(
    headers: &HeaderMap,
    checksums: &S3BodyChecksums,
    resource: &str,
) -> Result<(), S3Error> {
    let expected = [
        ("content-md5", checksums.md5.clone().finalize().to_vec()),
        (
            "x-amz-checksum-sha1",
            checksums.sha1.clone().finalize().to_vec(),
        ),
        (
            "x-amz-checksum-sha256",
            checksums.sha256.clone().finalize().to_vec(),
        ),
        (
            "x-amz-checksum-crc32",
            checksums.crc32.clone().finalize().to_be_bytes().to_vec(),
        ),
        (
            "x-amz-checksum-crc32c",
            checksums.crc32c.to_be_bytes().to_vec(),
        ),
    ];
    for (name, actual) in expected {
        let Some(value) = header_text(headers, name)? else {
            continue;
        };
        let supplied = BASE64.decode(value).map_err(|_| {
            S3Error::new(
                StatusCode::BAD_REQUEST,
                "InvalidDigest",
                format!("{name} is not valid base64"),
                resource,
            )
        })?;
        if supplied != actual {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "BadDigest",
                format!("The {name} value did not match the request body"),
                resource,
            ));
        }
    }
    if let Some(algorithm) = header_text(headers, "x-amz-sdk-checksum-algorithm")? {
        let checksum_header = format!("x-amz-checksum-{}", algorithm.to_ascii_lowercase());
        if !headers.contains_key(&checksum_header) {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                format!("checksum algorithm {algorithm} requires {checksum_header}"),
                resource,
            ));
        }
    }
    Ok(())
}

fn verify_buffered_checksums(
    headers: &HeaderMap,
    body: &[u8],
    resource: &str,
) -> Result<(), S3Error> {
    let mut checksums = S3BodyChecksums::default();
    checksums.update(body);
    verify_request_checksums(headers, &checksums, resource)
}

fn multipart_lock(state: &AppState) -> Result<Arc<tokio::sync::Mutex<()>>, S3Error> {
    state
        .s3
        .as_ref()
        .map(|config| config.multipart_lock.clone())
        .ok_or_else(|| {
            S3Error::new(
                StatusCode::NOT_FOUND,
                "NoSuchService",
                "The S3-compatible endpoint is disabled",
                "/",
            )
        })
}

fn next_multipart_upload_id(control_namespace_id: &NamespaceId) -> String {
    let mut nonce = [0u8; 32];
    let nonce = if getrandom::fill(&mut nonce).is_ok() {
        hex::encode(nonce)
    } else {
        hex::encode(Sha256::digest(request_id().as_bytes()))
    };
    format!(
        "v1.{}.{}",
        hex::encode(control_namespace_id.to_string()),
        nonce
    )
}

fn validate_part_number(part_number: u32, resource: &str) -> Result<(), S3Error> {
    if !(1..=S3_MAX_MULTIPART_PARTS).contains(&part_number) {
        return Err(S3Error::invalid(
            "partNumber must be between 1 and 10000",
            resource,
        ));
    }
    Ok(())
}

fn multipart_upload_key(upload_id: &str) -> Vec<u8> {
    [S3_MULTIPART_UPLOAD_PREFIX, upload_id.as_bytes()].concat()
}

fn multipart_completion_key(upload_id: &str) -> Vec<u8> {
    [S3_MULTIPART_COMPLETION_PREFIX, upload_id.as_bytes()].concat()
}

fn multipart_part_prefix(upload_id: &str) -> Vec<u8> {
    [S3_MULTIPART_PART_PREFIX, upload_id.as_bytes(), b"/"].concat()
}

fn multipart_part_key(upload_id: &str, part_number: u32) -> Vec<u8> {
    [
        multipart_part_prefix(upload_id),
        format!("{part_number:05}").into_bytes(),
    ]
    .concat()
}

fn value_precondition(value: &MerkleValue) -> KeyPrecondition {
    KeyPrecondition::Match {
        generation: value.generation,
        cid: value.cid.clone(),
    }
}

fn control_namespace_from_upload_id(upload_id: &str) -> Option<NamespaceId> {
    if upload_id.len() > 512 {
        return None;
    }
    let mut fields = upload_id.split('.');
    if fields.next()? != "v1" {
        return None;
    }
    let namespace = fields.next()?;
    let nonce = fields.next()?;
    if fields.next().is_some()
        || nonce.len() != 64
        || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let namespace = String::from_utf8(hex::decode(namespace).ok()?).ok()?;
    NamespaceId::new(namespace.parse().ok()?).ok()
}

async fn apply_multipart_transaction(
    state: &AppState,
    namespace_id: &NamespaceId,
    mutations: Vec<NamespaceMutation>,
    uploaded_roots: Vec<Cid>,
    staged_bytes: u64,
    resource: &str,
) -> Result<(), S3Error> {
    apply_multipart_transaction_preverified(
        state,
        namespace_id,
        mutations,
        uploaded_roots,
        Vec::new(),
        staged_bytes,
        resource,
    )
    .await
}

async fn apply_multipart_transaction_preverified(
    state: &AppState,
    namespace_id: &NamespaceId,
    mutations: Vec<NamespaceMutation>,
    uploaded_roots: Vec<Cid>,
    preverified_durability: Vec<DurabilityReceipt>,
    staged_bytes: u64,
    resource: &str,
) -> Result<(), S3Error> {
    let base = namespace_manager(state)
        .map_err(|error| map_api_error(error, resource))?
        .linearizable_namespace_head(namespace_id)
        .await
        .map_err(|error| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                error.to_string(),
                resource,
            )
        })?;
    let command = CommandEnvelope {
        request_id: request_id(),
        writer_identity: "s3-multipart".to_string(),
        timestamp_unix_seconds: unix_seconds(),
        signature_hex: "00".to_string(),
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: base.current_revision,
                base_root_cid: base.current_root_cid,
                mutations,
                message: Some("S3 multipart control update".to_string()),
            },
        },
    };
    let _ = apply_command(
        state,
        namespace_id.clone(),
        command,
        uploaded_roots,
        preverified_durability,
        staged_bytes,
        false,
    )
    .await
    .map_err(|error| map_api_error(error, resource))?;
    Ok(())
}

async fn apply_metadata_only_transaction(
    state: &AppState,
    namespace_id: &NamespaceId,
    mutations: Vec<NamespaceMutation>,
    metadata_only_cids: Vec<Cid>,
    staged_bytes: u64,
    resource: &str,
) -> Result<(), S3Error> {
    let base = namespace_manager(state)
        .map_err(|error| map_api_error(error, resource))?
        .linearizable_namespace_head(namespace_id)
        .await
        .map_err(|error| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                error.to_string(),
                resource,
            )
        })?;
    let command = CommandEnvelope {
        request_id: request_id(),
        writer_identity: "s3-metadata-control".to_string(),
        timestamp_unix_seconds: unix_seconds(),
        signature_hex: "00".to_string(),
        command: NamespaceCommand::ApplyTransaction {
            transaction: TransactionCommand {
                base_revision: base.current_revision,
                base_root_cid: base.current_root_cid,
                mutations,
                message: Some("S3 inline metadata control update".to_string()),
            },
        },
    };
    let _ = apply_command_with_metadata_only(
        state,
        namespace_id.clone(),
        command,
        CommandPublicationInputs {
            uploaded_roots: Vec::new(),
            preverified_durability: Vec::new(),
            metadata_only_cids,
            staged_bytes,
            retain_uploaded_on_conflict: false,
        },
    )
    .await
    .map_err(|error| map_api_error(error, resource))?;
    Ok(())
}

async fn scan_namespace_prefix(
    state: &AppState,
    namespace_id: &NamespaceId,
    prefix: Vec<u8>,
    resource: &str,
) -> Result<Vec<(Vec<u8>, MerkleValue)>, S3Error> {
    let namespace = namespace_manager(state)
        .map_err(|error| map_api_error(error, resource))?
        .linearizable_namespace_head(namespace_id)
        .await
        .map_err(|error| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                error.to_string(),
                resource,
            )
        })?;
    let mut cursor = None;
    let mut entries = Vec::new();
    let store = direct_namespace_store(state, &namespace).await;
    loop {
        let page = pepper_merkle::scan(
            &store,
            &namespace.current_root_cid,
            ScanQuery {
                prefix: Some(prefix.clone()),
                limit: 10_000,
                cursor,
                ..ScanQuery::default()
            },
            MerkleLimits::default(),
        )
        .await
        .map_err(|error| S3Error::invalid(error.to_string(), resource))?;
        entries.extend(
            page.entries
                .into_iter()
                .map(|entry| (entry.key, entry.value)),
        );
        if entries.len() > 100_000 {
            return Err(S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "SlowDown",
                "multipart control scan exceeded its bounded budget",
                resource,
            ));
        }
        let Some(next) = page.next_cursor else {
            break;
        };
        cursor = Some(next);
    }
    Ok(entries)
}

async fn multipart_control_namespace(
    state: &AppState,
    bucket_namespace_id: &NamespaceId,
    resource: &str,
) -> Result<Option<NamespaceId>, S3Error> {
    let Some(value) = s3_current_value(
        state,
        bucket_namespace_id,
        &hex::encode(S3_MULTIPART_CONTROL_KEY),
    )
    .await
    .map_err(|error| map_api_error(error, resource))?
    else {
        return Ok(None);
    };
    let namespace_id = NamespaceId::new(value.cid).map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("invalid multipart control namespace reference: {error}"),
            resource,
        )
    })?;
    let namespace = namespace_manager(state)
        .map_err(|error| map_api_error(error, resource))?
        .linearizable_namespace_head(&namespace_id)
        .await
        .map_err(|error| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                error.to_string(),
                resource,
            )
        })?;
    if namespace.descriptor.kind != NamespaceKind::Kv {
        return Err(S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "multipart control reference is not a KV namespace",
            resource,
        ));
    }
    Ok(Some(namespace_id))
}

async fn bucket_deleted(state: &AppState, namespace_id: &NamespaceId) -> Result<bool, ApiError> {
    Ok(
        s3_current_value(state, namespace_id, &hex::encode(S3_BUCKET_DELETED_KEY))
            .await?
            .is_some(),
    )
}

async fn get_bucket_internal_raw(
    state: &AppState,
    namespace_id: &NamespaceId,
    key: &[u8],
) -> Result<Option<Vec<u8>>, ApiError> {
    let Some(value) = s3_current_value(state, namespace_id, &hex::encode(key)).await? else {
        return Ok(None);
    };
    let placement = placement_from_merkle_value(&value)?;
    let block = get_block_at_placement(state, &value.cid, &placement).await?;
    if block.codec != CODEC_RAW {
        return Err(ApiError::internal(
            "S3 bucket configuration is not a raw block",
        ));
    }
    Ok(Some(block.payload))
}

async fn put_namespace_replicated_block(
    state: &AppState,
    namespace_id: &NamespaceId,
    codec: Codec,
    payload: Vec<u8>,
) -> Result<DurabilityReceipt, ApiError> {
    let namespace = namespace_manager(state)?
        .linearizable_namespace_head(namespace_id)
        .await
        .map_err(consensus_error)?;
    let replication_factor = usize::from(namespace.descriptor.durability.replicas);
    put_replicated_block_with_factor(state, codec, payload, replication_factor).await
}

async fn put_bucket_internal_raw(
    state: &AppState,
    namespace_id: &NamespaceId,
    key: &[u8],
    body: Vec<u8>,
    resource: &str,
) -> Result<(), S3Error> {
    let current = s3_current_value(state, namespace_id, &hex::encode(key))
        .await
        .map_err(|error| map_api_error(error, resource))?;
    let receipt = put_namespace_replicated_block(state, namespace_id, CODEC_RAW, body)
        .await
        .map_err(|error| map_api_error(error, resource))?;
    let metadata = placement_control_metadata(
        &receipt,
        "s3_bucket_configuration_placement",
        receipt
            .placement
            .as_ref()
            .expect("validated placement receipt"),
    )
    .map_err(|error| map_api_error(error, resource))?;
    apply_multipart_transaction_preverified(
        state,
        namespace_id,
        vec![NamespaceMutation::Put {
            key_hex: hex::encode(key),
            value_cid: receipt.cid.clone(),
            value_kind: "s3_bucket_configuration".to_string(),
            metadata,
            precondition: current
                .as_ref()
                .map(value_precondition)
                .unwrap_or(KeyPrecondition::Absent),
        }],
        vec![receipt.cid.clone()],
        vec![receipt],
        0,
        resource,
    )
    .await
}

fn partition_fence_body(bucket_epoch: u64, partition_id: u32, active: bool) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "bucket_epoch": bucket_epoch,
        "partition_id": partition_id,
        "state": if active { "active" } else { "frozen" },
    }))
    .expect("partition fence JSON is infallible")
}

async fn initialize_partitioned_bucket(
    state: &AppState,
    control_namespace_id: &NamespaceId,
    resource: &str,
) -> Result<BucketPartitionMap, S3Error> {
    if get_bucket_internal_raw(state, control_namespace_id, S3_BUCKET_PARTITION_MAP_KEY)
        .await
        .map_err(|error| map_api_error(error, resource))?
        .is_some()
    {
        return load_bucket_partition_map(state, control_namespace_id, resource).await;
    }
    let partition_count = state
        .s3
        .as_ref()
        .map_or(DEFAULT_BUCKET_PARTITIONS, |config| config.bucket_partitions);
    let width = pepper_bucket::BUCKET_HASH_SPACE / partition_count as u32;
    let mut partitions = Vec::with_capacity(partition_count);
    for index in 0..partition_count {
        let created = super::namespace_api::namespace_create(
            State(state.clone()),
            Json(super::namespace_api::CreateNamespaceRequest {
                kind: NamespaceKind::Bucket,
                alias: None,
                request_id: Some(format!(
                    "s3p-{S3_BUCKET_PARTITION_CREATOR}-{}-{index}",
                    hex::encode(&control_namespace_id.0.digest[..8])
                )),
                retention_keep_last: None,
                retention_max_age_seconds: None,
            }),
        )
        .await
        .map_err(|error| map_api_error(error, resource))?
        .0;
        put_bucket_internal_raw(
            state,
            &created.namespace_id,
            S3_BUCKET_PARTITION_FENCE_KEY,
            partition_fence_body(1, index as u32, true),
            resource,
        )
        .await?;
        let fence = s3_current_value(
            state,
            &created.namespace_id,
            &hex::encode(S3_BUCKET_PARTITION_FENCE_KEY),
        )
        .await
        .map_err(|error| map_api_error(error, resource))?
        .ok_or_else(|| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "partition fence was not committed",
                resource,
            )
        })?;
        partitions.push(BucketPartition {
            partition_id: index as u32,
            hash_start: index as u32 * width,
            hash_end: if index + 1 == partition_count {
                pepper_bucket::BUCKET_HASH_SPACE
            } else {
                (index as u32 + 1) * width
            },
            namespace_id: created.namespace_id,
            fence_generation: fence.generation,
            fence_cid: fence.cid,
        });
    }
    let map = BucketPartitionMap::new(1, partitions).map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            error.to_string(),
            resource,
        )
    })?;
    store_bucket_partition_map(state, control_namespace_id, &map, resource).await?;
    Ok(map)
}

async fn store_bucket_partition_map(
    state: &AppState,
    control_namespace_id: &NamespaceId,
    map: &BucketPartitionMap,
    resource: &str,
) -> Result<(), S3Error> {
    map.validate().map_err(|error| {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            error.to_string(),
            resource,
        )
    })?;
    let body = serde_json::to_vec(map).map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            error.to_string(),
            resource,
        )
    })?;
    put_bucket_internal_raw(
        state,
        control_namespace_id,
        S3_BUCKET_PARTITION_MAP_KEY,
        body,
        resource,
    )
    .await
}

async fn load_bucket_partition_map(
    state: &AppState,
    control_namespace_id: &NamespaceId,
    resource: &str,
) -> Result<BucketPartitionMap, S3Error> {
    let body = get_bucket_internal_raw(state, control_namespace_id, S3_BUCKET_PARTITION_MAP_KEY)
        .await
        .map_err(|error| map_api_error(error, resource))?
        .ok_or_else(|| {
            S3Error::new(
                StatusCode::CONFLICT,
                "InvalidBucketState",
                "bucket does not contain the partitioned metadata format",
                resource,
            )
        })?;
    let map: BucketPartitionMap = serde_json::from_slice(&body).map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            error.to_string(),
            resource,
        )
    })?;
    map.validate().map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            error.to_string(),
            resource,
        )
    })?;
    Ok(map)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BucketPartitionOperation {
    Split,
    Merge,
    Move,
    Abort,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BucketPartitionChangeRequest {
    operation: BucketPartitionOperation,
    partition_id: Option<u32>,
}

async fn create_bucket_data_partition(
    state: &AppState,
    control_namespace_id: &NamespaceId,
    partition_id: u32,
    hash_start: u32,
    hash_end: u32,
    epoch: u64,
    resource: &str,
) -> Result<BucketPartition, S3Error> {
    let created = super::namespace_api::namespace_create(
        State(state.clone()),
        Json(super::namespace_api::CreateNamespaceRequest {
            kind: NamespaceKind::Bucket,
            alias: None,
            request_id: Some(format!(
                "s3p-{}-{epoch}-{partition_id}",
                hex::encode(&control_namespace_id.0.digest[..8])
            )),
            retention_keep_last: None,
            retention_max_age_seconds: None,
        }),
    )
    .await
    .map_err(|error| map_api_error(error, resource))?
    .0;
    put_bucket_internal_raw(
        state,
        &created.namespace_id,
        S3_BUCKET_PARTITION_FENCE_KEY,
        partition_fence_body(epoch, partition_id, true),
        resource,
    )
    .await?;
    let fence = s3_current_value(
        state,
        &created.namespace_id,
        &hex::encode(S3_BUCKET_PARTITION_FENCE_KEY),
    )
    .await
    .map_err(|error| map_api_error(error, resource))?
    .ok_or_else(|| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "new partition fence is missing",
            resource,
        )
    })?;
    Ok(BucketPartition {
        partition_id,
        hash_start,
        hash_end,
        namespace_id: created.namespace_id,
        fence_generation: fence.generation,
        fence_cid: fence.cid,
    })
}

async fn freeze_bucket_partition(
    state: &AppState,
    partition: &BucketPartition,
    epoch: u64,
    resource: &str,
) -> Result<S3PartitionRoot, S3Error> {
    put_bucket_internal_raw(
        state,
        &partition.namespace_id,
        S3_BUCKET_PARTITION_FENCE_KEY,
        partition_fence_body(epoch, partition.partition_id, false),
        resource,
    )
    .await?;
    let namespace = namespace_manager(state)
        .map_err(|error| map_api_error(error, resource))?
        .linearizable_namespace_head(&partition.namespace_id)
        .await
        .map_err(|error| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                error.to_string(),
                resource,
            )
        })?;
    Ok(S3PartitionRoot {
        partition_id: partition.partition_id,
        namespace_id: partition.namespace_id.to_string(),
        revision: namespace.current_revision,
        root_cid: namespace.current_root_cid,
    })
}

async fn copy_partition_snapshot(
    state: &AppState,
    source: &S3PartitionRoot,
    targets: &[BucketPartition],
    resource: &str,
) -> Result<u64, S3Error> {
    let source_namespace_id = source
        .namespace_id
        .parse::<Cid>()
        .ok()
        .and_then(|cid| NamespaceId::new(cid).ok())
        .ok_or_else(|| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "invalid source partition",
                resource,
            )
        })?;
    let source_namespace = namespace_manager(state)
        .map_err(|error| map_api_error(error, resource))?
        .linearizable_namespace_head(&source_namespace_id)
        .await
        .map_err(|error| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                error.to_string(),
                resource,
            )
        })?;
    let source_store = direct_namespace_store(state, &source_namespace).await;
    let mut cursor = None;
    let mut copied = 0u64;
    loop {
        let page = pepper_merkle::scan(
            &source_store,
            &source.root_cid,
            ScanQuery {
                limit: 1_000,
                cursor,
                ..ScanQuery::default()
            },
            MerkleLimits::default(),
        )
        .await
        .map_err(|error| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                error.to_string(),
                resource,
            )
        })?;
        let mut grouped = BTreeMap::<u32, Vec<pepper_merkle::MapEntry>>::new();
        for entry in page.entries {
            let routing_key = if entry.key.starts_with(S3_INTERNAL_KEY_PREFIX) {
                let Some(object_key) = small_object_pack_entry_object_key(&entry.key, &entry.value)
                else {
                    continue;
                };
                object_key
            } else {
                entry.key.clone()
            };
            let digest = Cid::new(CODEC_RAW, &routing_key).digest;
            let point = u32::from(u16::from_be_bytes([digest[0], digest[1]]));
            let target = targets
                .iter()
                .find(|target| point >= target.hash_start && point < target.hash_end)
                .ok_or_else(|| {
                    S3Error::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        "repartition target does not cover an object key",
                        resource,
                    )
                })?;
            grouped.entry(target.partition_id).or_default().push(entry);
        }
        for (partition_id, entries) in grouped {
            let target = targets
                .iter()
                .find(|target| target.partition_id == partition_id)
                .expect("grouped target exists");
            let extent_indices = small_object_pack::repartition_extent_indices(&entries)
                .map_err(|error| map_api_error(error, resource))?;
            let mut preverified_durability = preverify_partition_copy_erasure_roots(
                state,
                &entries,
                usize::from(source_namespace.descriptor.durability.replicas),
                resource,
            )
            .await?;
            let mut roots = entries
                .iter()
                .map(|entry| entry.value.cid.clone())
                .collect::<Vec<_>>();
            let mut mutations = entries
                .into_iter()
                .map(|entry| NamespaceMutation::Put {
                    key_hex: hex::encode(entry.key),
                    value_cid: entry.value.cid,
                    value_kind: entry.value.value_kind,
                    metadata: entry.value.metadata,
                    precondition: KeyPrecondition::Absent,
                })
                .collect::<Vec<_>>();
            for (index_cid, placement) in extent_indices {
                preverified_durability.push(
                    AgentDurabilityBackend(state.clone())
                        .ensure_at_placement(
                            &index_cid,
                            usize::from(placement.replicas),
                            placement.clone(),
                        )
                        .await
                        .map_err(|error| {
                            S3Error::new(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "ServiceUnavailable",
                                error.to_string(),
                                resource,
                            )
                        })?,
                );
                roots.push(index_cid.clone());
                let metadata = BTreeMap::from([(
                    BUCKET_DESCRIPTOR_PLACEMENT_METADATA.to_string(),
                    serde_json::to_string(&placement).map_err(|error| {
                        S3Error::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            error.to_string(),
                            resource,
                        )
                    })?,
                )]);
                for (key, kind) in [
                    (
                        small_object_pack::extent_catalog_key(&index_cid),
                        "small_object_extent_index",
                    ),
                    (
                        small_object_pack::dirty_extent_key(&index_cid),
                        "small_object_dirty_extent",
                    ),
                ] {
                    if s3_current_value(state, &target.namespace_id, &hex::encode(&key))
                        .await
                        .map_err(|error| map_api_error(error, resource))?
                        .is_none()
                    {
                        mutations.push(NamespaceMutation::Put {
                            key_hex: hex::encode(key),
                            value_cid: index_cid.clone(),
                            value_kind: kind.to_string(),
                            metadata: metadata.clone(),
                            precondition: KeyPrecondition::Absent,
                        });
                    }
                }
            }
            mutations.sort_by(|left, right| mutation_key(left).cmp(mutation_key(right)));
            roots.sort_by_key(ToString::to_string);
            roots.dedup();
            copied = copied.saturating_add(mutations.len() as u64);
            apply_multipart_transaction_preverified(
                state,
                &target.namespace_id,
                mutations,
                roots,
                preverified_durability,
                0,
                resource,
            )
            .await?;
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    Ok(copied)
}

async fn preverify_partition_copy_erasure_roots(
    state: &AppState,
    entries: &[pepper_merkle::MapEntry],
    replication_factor: usize,
    resource: &str,
) -> Result<Vec<DurabilityReceipt>, S3Error> {
    let backend = AgentDurabilityBackend(state.clone());
    let mut verified = Vec::new();
    let mut seen = HashSet::new();
    // A direct-small descriptor deliberately has no DAG link to its RF
    // staging record: the colocated pending/index marker is authoritative for
    // that lifetime transition. Verify the descriptor at its exact placement
    // so repartition does not invoke the legacy provider resolver merely to
    // discover that it has no links.
    for entry in entries
        .iter()
        .filter(|entry| entry.value.cid.codec == CODEC_BUCKET_OBJECT)
    {
        if seen.contains(&entry.value.cid) {
            continue;
        }
        let placement = placement_from_merkle_value(&entry.value)
            .map_err(|error| map_api_error(error, resource))?;
        let block = get_block_at_placement(state, &entry.value.cid, &placement)
            .await
            .map_err(|error| map_api_error(error, resource))?;
        let descriptor = pepper_bucket::decode_descriptor(&block.payload, BucketLimits::default())
            .map_err(|error| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    error.to_string(),
                    resource,
                )
            })?;
        if descriptor
            .content_cid
            .as_ref()
            .is_some_and(|cid| cid.codec == CODEC_SMALL_OBJECT)
            && descriptor.previous_version_cid.is_none()
        {
            seen.insert(entry.value.cid.clone());
            verified.push(
                backend
                    .ensure_at_placement(&entry.value.cid, replication_factor, placement)
                    .await
                    .map_err(|error| {
                        S3Error::new(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "ServiceUnavailable",
                            error.to_string(),
                            resource,
                        )
                    })?,
            );
        }
    }
    for entry in entries
        .iter()
        .filter(|entry| entry.value.cid.codec == CODEC_ERASURE_MANIFEST)
    {
        if !seen.insert(entry.value.cid.clone()) {
            continue;
        }
        let placement = match small_object_pack::extent_placement_from_value(&entry.value)
            .map_err(|error| map_api_error(error, resource))?
        {
            Some(placement) => placement,
            None => placement_from_merkle_value(&entry.value)
                .map_err(|error| map_api_error(error, resource))?,
        };
        let receipt = backend
            .ensure_at_placement(&entry.value.cid, replication_factor, placement.clone())
            .await
            .map_err(|error| {
                S3Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ServiceUnavailable",
                    error.to_string(),
                    resource,
                )
            })?;
        let block = get_block_at_placement(state, &entry.value.cid, &placement)
            .await
            .map_err(|error| map_api_error(error, resource))?;
        let manifest: ErasureManifest =
            serde_json::from_slice(&block.payload).map_err(|error| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    error.to_string(),
                    resource,
                )
            })?;
        manifest.validate().map_err(|error| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                error.to_string(),
                resource,
            )
        })?;
        verified.push(receipt);
        for shard in manifest
            .stripes
            .into_iter()
            .flat_map(|stripe| stripe.shards)
        {
            if !seen.insert(shard.cid.clone()) {
                continue;
            }
            verified.push(
                backend
                    .ensure_at_placement(&shard.cid, 1, shard.placement)
                    .await
                    .map_err(|error| {
                        S3Error::new(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "ServiceUnavailable",
                            error.to_string(),
                            resource,
                        )
                    })?,
            );
        }
    }
    Ok(verified)
}

pub(super) async fn admin_bucket_partitions(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Result<Json<serde_json::Value>, S3Error> {
    let resolved = bucket_namespace_state(&state, &bucket).await?;
    let manager =
        namespace_manager(&state).map_err(|error| map_api_error(error, &format!("/{bucket}")))?;
    let mut partitions = Vec::new();
    for partition in &resolved.partition_map.partitions {
        if let Ok(group) = manager.group(&partition.namespace_id).await {
            let metrics = group.raft.metrics().borrow().clone();
            partitions.push(serde_json::json!({
                "partition": partition,
                "leader_id": metrics.current_leader,
                "term": metrics.current_term,
                "last_log_index": metrics.last_log_index,
                "last_applied": metrics.last_applied,
                "locally_hosted": true,
            }));
        } else {
            // The partition map in the control namespace is authoritative for
            // topology.  Status must remain available from gateways that are
            // not voters for every data partition; forcing a linearizable read
            // of each remote partition makes this diagnostic an accidental
            // all-partitions availability barrier.
            partitions.push(serde_json::json!({
                "partition": partition,
                "leader_id": null,
                "term": null,
                "last_log_index": null,
                "last_applied": null,
                "locally_hosted": false,
            }));
        }
    }
    Ok(Json(serde_json::json!({
        "bucket": bucket,
        "control_namespace_id": resolved.control_namespace_id,
        "epoch": resolved.partition_map.epoch,
        "state": resolved.partition_map.state,
        "partitions": partitions,
    })))
}

pub(super) async fn admin_bucket_partition_change(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Json(request): Json<BucketPartitionChangeRequest>,
) -> Result<Json<serde_json::Value>, S3Error> {
    let resource = format!("/v1/admin/s3/buckets/{bucket}/partitions");
    let lock = state
        .s3
        .as_ref()
        .ok_or_else(|| S3Error::no_bucket(&bucket))?
        .bucket_create_lock
        .clone();
    let _guard = lock.lock().await;
    let resolved = bucket_namespace_state(&state, &bucket).await?;
    let old = resolved.partition_map;
    let next_epoch = old.epoch.saturating_add(1);
    if matches!(request.operation, BucketPartitionOperation::Abort) {
        if old.state != BucketPartitionMapState::Reconfiguring {
            return Ok(Json(
                serde_json::json!({"bucket": bucket, "status": "active", "epoch": old.epoch}),
            ));
        }
        let mut restored = old.clone();
        restored.state = BucketPartitionMapState::Active;
        restored.epoch = next_epoch;
        for partition in &mut restored.partitions {
            put_bucket_internal_raw(
                &state,
                &partition.namespace_id,
                S3_BUCKET_PARTITION_FENCE_KEY,
                partition_fence_body(next_epoch, partition.partition_id, true),
                &resource,
            )
            .await?;
            let fence = s3_current_value(
                &state,
                &partition.namespace_id,
                &hex::encode(S3_BUCKET_PARTITION_FENCE_KEY),
            )
            .await
            .map_err(|error| map_api_error(error, &resource))?
            .expect("restored fence was committed");
            partition.fence_generation = fence.generation;
            partition.fence_cid = fence.cid;
        }
        store_bucket_partition_map(&state, &resolved.control_namespace_id, &restored, &resource)
            .await?;
        metrics::S3_PARTITION_RECONFIGURATIONS.fetch_add(1, Ordering::Relaxed);
        return Ok(Json(
            serde_json::json!({"bucket": bucket, "status": "aborted", "epoch": restored.epoch}),
        ));
    }
    if old.state != BucketPartitionMapState::Active {
        return Err(S3Error::new(
            StatusCode::CONFLICT,
            "OperationAborted",
            "bucket has an unfinished repartition; issue abort before retrying",
            &resource,
        ));
    }
    let partition_id = request
        .partition_id
        .ok_or_else(|| S3Error::invalid("partition_id is required", &resource))?;
    let source_index = old
        .partitions
        .iter()
        .position(|partition| partition.partition_id == partition_id)
        .ok_or_else(|| S3Error::invalid("partition_id does not exist", &resource))?;
    let mut sources = vec![old.partitions[source_index].clone()];
    let next_id = old
        .partitions
        .iter()
        .map(|partition| partition.partition_id)
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let targets = match request.operation {
        BucketPartitionOperation::Split => {
            if old.partitions.len() >= MAX_BUCKET_PARTITIONS {
                return Err(S3Error::invalid(
                    "maximum bucket partition count reached",
                    &resource,
                ));
            }
            let source = &sources[0];
            let midpoint = source.hash_start + (source.hash_end - source.hash_start) / 2;
            if midpoint == source.hash_start {
                return Err(S3Error::invalid(
                    "partition range cannot be split further",
                    &resource,
                ));
            }
            vec![
                create_bucket_data_partition(
                    &state,
                    &resolved.control_namespace_id,
                    next_id,
                    source.hash_start,
                    midpoint,
                    next_epoch,
                    &resource,
                )
                .await?,
                create_bucket_data_partition(
                    &state,
                    &resolved.control_namespace_id,
                    next_id + 1,
                    midpoint,
                    source.hash_end,
                    next_epoch,
                    &resource,
                )
                .await?,
            ]
        }
        BucketPartitionOperation::Merge => {
            let adjacent = old
                .partitions
                .get(source_index + 1)
                .cloned()
                .ok_or_else(|| {
                    S3Error::invalid("merge requires the next adjacent partition", &resource)
                })?;
            sources.push(adjacent.clone());
            vec![
                create_bucket_data_partition(
                    &state,
                    &resolved.control_namespace_id,
                    next_id,
                    sources[0].hash_start,
                    adjacent.hash_end,
                    next_epoch,
                    &resource,
                )
                .await?,
            ]
        }
        BucketPartitionOperation::Move => vec![
            create_bucket_data_partition(
                &state,
                &resolved.control_namespace_id,
                next_id,
                sources[0].hash_start,
                sources[0].hash_end,
                next_epoch,
                &resource,
            )
            .await?,
        ],
        BucketPartitionOperation::Abort => unreachable!(),
    };
    let mut transition = old.clone();
    transition.epoch = next_epoch;
    transition.state = BucketPartitionMapState::Reconfiguring;
    store_bucket_partition_map(
        &state,
        &resolved.control_namespace_id,
        &transition,
        &resource,
    )
    .await?;
    let mut copied = 0u64;
    for source in &sources {
        let snapshot = freeze_bucket_partition(&state, source, next_epoch, &resource).await?;
        copied = copied
            .saturating_add(copy_partition_snapshot(&state, &snapshot, &targets, &resource).await?);
    }
    // A split can leave one immutable extent referenced by multiple target
    // partitions. Localize those live records before activating the new map so
    // later per-partition churn accounting never mistakes records owned by a
    // sibling partition for dead bytes.
    let mut small_object_repack = SmallObjectPackReport::default();
    for target in &targets {
        small_object_repack += small_object_pack::compact_repartitioned_small_object_extents(
            &state,
            &target.namespace_id,
        )
        .await
        .map_err(|error| map_api_error(error, &resource))?;
    }
    let source_ids = sources
        .iter()
        .map(|partition| partition.partition_id)
        .collect::<HashSet<_>>();
    let mut final_partitions = old
        .partitions
        .into_iter()
        .filter(|partition| !source_ids.contains(&partition.partition_id))
        .collect::<Vec<_>>();
    final_partitions.extend(targets);
    let final_map = BucketPartitionMap::new(next_epoch, final_partitions).map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            error.to_string(),
            &resource,
        )
    })?;
    store_bucket_partition_map(
        &state,
        &resolved.control_namespace_id,
        &final_map,
        &resource,
    )
    .await?;
    metrics::S3_PARTITION_RECONFIGURATIONS.fetch_add(1, Ordering::Relaxed);
    Ok(Json(serde_json::json!({
        "bucket": bucket,
        "status": "active",
        "epoch": final_map.epoch,
        "partition_count": final_map.partitions.len(),
        "objects_copied": copied,
        "small_object_repack": small_object_repack,
    })))
}

async fn delete_bucket_internal(
    state: &AppState,
    namespace_id: &NamespaceId,
    key: &[u8],
    resource: &str,
) -> Result<(), S3Error> {
    let Some(current) = s3_current_value(state, namespace_id, &hex::encode(key))
        .await
        .map_err(|error| map_api_error(error, resource))?
    else {
        return Ok(());
    };
    apply_multipart_transaction(
        state,
        namespace_id,
        vec![NamespaceMutation::Delete {
            key_hex: hex::encode(key),
            precondition: value_precondition(&current),
        }],
        Vec::new(),
        0,
        resource,
    )
    .await
}

async fn mark_bucket_deleted(
    state: &AppState,
    namespace_id: &NamespaceId,
    resource: &str,
) -> Result<(), S3Error> {
    if bucket_deleted(state, namespace_id)
        .await
        .map_err(|error| map_api_error(error, resource))?
    {
        return Ok(());
    }
    let receipt = put_namespace_replicated_block(state, namespace_id, CODEC_RAW, b"1".to_vec())
        .await
        .map_err(|error| map_api_error(error, resource))?;
    let mut mutations = vec![NamespaceMutation::Put {
        key_hex: hex::encode(S3_BUCKET_DELETED_KEY),
        value_cid: receipt.cid.clone(),
        value_kind: "s3_bucket_deleted".to_string(),
        metadata: BTreeMap::new(),
        precondition: KeyPrecondition::Absent,
    }];
    for key in [
        S3_BUCKET_TAGGING_KEY,
        S3_BUCKET_CORS_KEY,
        S3_BUCKET_LIFECYCLE_KEY,
    ] {
        if let Some(value) = s3_current_value(state, namespace_id, &hex::encode(key))
            .await
            .map_err(|error| map_api_error(error, resource))?
        {
            mutations.push(NamespaceMutation::Delete {
                key_hex: hex::encode(key),
                precondition: value_precondition(&value),
            });
        }
    }
    mutations.sort_by(|left, right| {
        let left_key = match left {
            NamespaceMutation::Assert { key_hex, .. }
            | NamespaceMutation::Put { key_hex, .. }
            | NamespaceMutation::Delete { key_hex, .. } => key_hex,
        };
        let right_key = match right {
            NamespaceMutation::Assert { key_hex, .. }
            | NamespaceMutation::Put { key_hex, .. }
            | NamespaceMutation::Delete { key_hex, .. } => key_hex,
        };
        left_key.cmp(right_key)
    });
    apply_multipart_transaction(
        state,
        namespace_id,
        mutations,
        vec![receipt.cid],
        0,
        resource,
    )
    .await
}

async fn clear_bucket_deleted(
    state: &AppState,
    namespace_id: &NamespaceId,
    resource: &str,
) -> Result<(), S3Error> {
    let Some(value) = s3_current_value(state, namespace_id, &hex::encode(S3_BUCKET_DELETED_KEY))
        .await
        .map_err(|error| map_api_error(error, resource))?
    else {
        return Ok(());
    };
    apply_multipart_transaction(
        state,
        namespace_id,
        vec![NamespaceMutation::Delete {
            key_hex: hex::encode(S3_BUCKET_DELETED_KEY),
            precondition: value_precondition(&value),
        }],
        Vec::new(),
        0,
        resource,
    )
    .await
}

async fn ensure_bucket_empty(
    state: &AppState,
    namespace_id: &NamespaceId,
    resource: &str,
) -> Result<(), S3Error> {
    let map = load_bucket_partition_map(state, namespace_id, resource).await?;
    for partition in map.partitions {
        let namespace = namespace_manager(state)
            .map_err(|error| map_api_error(error, resource))?
            .linearizable_namespace_head(&partition.namespace_id)
            .await
            .map_err(|error| {
                S3Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ServiceUnavailable",
                    error.to_string(),
                    resource,
                )
            })?;
        let mut cursor = None;
        let namespace_store = direct_namespace_store(state, &namespace).await;
        loop {
            let page = pepper_merkle::scan(
                &namespace_store,
                &namespace.current_root_cid,
                ScanQuery {
                    end: Some(S3_INTERNAL_KEY_PREFIX.to_vec()),
                    limit: 10_000,
                    cursor,
                    ..ScanQuery::default()
                },
                MerkleLimits::default(),
            )
            .await
            .map_err(|error| S3Error::invalid(error.to_string(), resource))?;
            for entry in page.entries {
                if entry.key.starts_with(S3_INTERNAL_KEY_PREFIX) {
                    continue;
                }
                let descriptor = descriptor_from_merkle_value(state, &entry.value)
                    .await
                    .map_err(|error| map_api_error(error, resource))?;
                if !descriptor.tombstone {
                    return Err(S3Error::new(
                        StatusCode::CONFLICT,
                        "BucketNotEmpty",
                        "The bucket you tried to delete is not empty",
                        resource,
                    ));
                }
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
    }
    if let Some(control_namespace_id) =
        multipart_control_namespace(state, namespace_id, resource).await?
        && all_multipart_uploads(state, &control_namespace_id)
            .await?
            .iter()
            .any(|upload| upload.status == "open" || upload.status == "completing")
    {
        return Err(S3Error::new(
            StatusCode::CONFLICT,
            "BucketNotEmpty",
            "The bucket has active multipart uploads",
            resource,
        ));
    }
    Ok(())
}

async fn ensure_multipart_control_namespace(
    state: &AppState,
    bucket_namespace_id: &NamespaceId,
    resource: &str,
) -> Result<NamespaceId, S3Error> {
    if let Some(namespace_id) =
        multipart_control_namespace(state, bucket_namespace_id, resource).await?
    {
        return Ok(namespace_id);
    }
    let lock = multipart_lock(state)?;
    let _guard = lock.lock().await;
    if let Some(namespace_id) =
        multipart_control_namespace(state, bucket_namespace_id, resource).await?
    {
        return Ok(namespace_id);
    }
    let created = namespace_create(
        State(state.clone()),
        Json(CreateNamespaceRequest {
            kind: NamespaceKind::Kv,
            alias: None,
            request_id: Some(format!("s3-multipart-control-{bucket_namespace_id}")),
            retention_keep_last: Some(1),
            retention_max_age_seconds: None,
        }),
    )
    .await
    .map_err(|error| map_api_error(error, resource))?
    .0;
    for _ in 0..20 {
        if namespace_manager(state)
            .map_err(|error| map_api_error(error, resource))?
            .linearizable_namespace_head(&created.namespace_id)
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let current = s3_current_value(
        state,
        bucket_namespace_id,
        &hex::encode(S3_MULTIPART_CONTROL_KEY),
    )
    .await
    .map_err(|error| map_api_error(error, resource))?;
    if current.is_none() {
        let mutation = NamespaceMutation::Put {
            key_hex: hex::encode(S3_MULTIPART_CONTROL_KEY),
            value_cid: created.namespace_id.0.clone(),
            value_kind: "s3_multipart_control".to_string(),
            metadata: BTreeMap::new(),
            precondition: KeyPrecondition::Absent,
        };
        if let Err(error) = apply_multipart_transaction(
            state,
            bucket_namespace_id,
            vec![mutation],
            vec![created.namespace_id.0.clone()],
            0,
            resource,
        )
        .await
        {
            if let Some(namespace_id) =
                multipart_control_namespace(state, bucket_namespace_id, resource).await?
            {
                return Ok(namespace_id);
            }
            return Err(error);
        }
    }
    Ok(created.namespace_id)
}

async fn put_multipart_upload(
    state: &AppState,
    control_namespace_id: &NamespaceId,
    upload: &S3MultipartUpload,
    resource: &str,
) -> Result<(), S3Error> {
    let bytes = serde_json::to_vec(upload).map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            error.to_string(),
            resource,
        )
    })?;
    let receipt = put_namespace_replicated_block(state, control_namespace_id, CODEC_RAW, bytes)
        .await
        .map_err(|error| map_api_error(error, resource))?;
    let metadata = placement_control_metadata(
        &receipt,
        "s3_multipart_upload_placement",
        receipt
            .placement
            .as_ref()
            .expect("validated placement receipt"),
    )
    .map_err(|error| map_api_error(error, resource))?;
    apply_multipart_transaction_preverified(
        state,
        control_namespace_id,
        vec![NamespaceMutation::Put {
            key_hex: hex::encode(multipart_upload_key(&upload.upload_id)),
            value_cid: receipt.cid.clone(),
            value_kind: "s3_multipart_upload".to_string(),
            metadata,
            precondition: KeyPrecondition::Absent,
        }],
        vec![receipt.cid.clone()],
        vec![receipt],
        0,
        resource,
    )
    .await
}

async fn replace_multipart_upload(
    state: &AppState,
    stored: &StoredMultipartUpload,
    upload: S3MultipartUpload,
    mut preverified_durability: Vec<DurabilityReceipt>,
    resource: &str,
) -> Result<StoredMultipartUpload, S3Error> {
    let bytes = serde_json::to_vec(&upload).map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            error.to_string(),
            resource,
        )
    })?;
    let record =
        put_namespace_replicated_block(state, &stored.control_namespace_id, CODEC_RAW, bytes)
            .await
            .map_err(|error| map_api_error(error, resource))?;
    preverified_durability.push(record.clone());
    let record_metadata = placement_control_metadata(
        &record,
        "s3_multipart_upload_placement",
        record
            .placement
            .as_ref()
            .expect("validated placement receipt"),
    )
    .map_err(|error| map_api_error(error, resource))?;
    let mut mutations = Vec::new();
    let mut uploaded_roots = vec![record.cid.clone()];
    if let Some(final_content_cid) = &upload.final_content_cid {
        let final_placement = upload.final_content_placement.as_ref().ok_or_else(|| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "multipart completion placement is missing",
                resource,
            )
        })?;
        let mut completion_metadata = BTreeMap::new();
        completion_metadata.insert(
            BUCKET_DESCRIPTOR_PLACEMENT_METADATA.to_string(),
            serde_json::to_string(final_placement).map_err(|error| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    error.to_string(),
                    resource,
                )
            })?,
        );
        let completion_key = multipart_completion_key(&upload.upload_id);
        let current = s3_current_value(
            state,
            &stored.control_namespace_id,
            &hex::encode(&completion_key),
        )
        .await
        .map_err(|error| map_api_error(error, resource))?;
        mutations.push(NamespaceMutation::Put {
            key_hex: hex::encode(completion_key),
            value_cid: final_content_cid.clone(),
            value_kind: "s3_multipart_completion".to_string(),
            metadata: completion_metadata,
            precondition: current
                .as_ref()
                .map_or(KeyPrecondition::Absent, value_precondition),
        });
        uploaded_roots.push(final_content_cid.clone());
    }
    mutations.push(NamespaceMutation::Put {
        key_hex: hex::encode(multipart_upload_key(&upload.upload_id)),
        value_cid: record.cid,
        value_kind: "s3_multipart_upload".to_string(),
        metadata: record_metadata,
        precondition: value_precondition(&stored.value),
    });
    apply_multipart_transaction_preverified(
        state,
        &stored.control_namespace_id,
        mutations,
        uploaded_roots,
        preverified_durability,
        0,
        resource,
    )
    .await?;
    multipart_upload(state, &upload.upload_id, resource)
        .await?
        .ok_or_else(|| S3Error::no_upload(&upload.bucket, &upload.key))
}

async fn multipart_upload(
    state: &AppState,
    upload_id: &str,
    resource: &str,
) -> Result<Option<StoredMultipartUpload>, S3Error> {
    let Some(control_namespace_id) = control_namespace_from_upload_id(upload_id) else {
        return Ok(None);
    };
    let Some(value) = s3_current_value(
        state,
        &control_namespace_id,
        &hex::encode(multipart_upload_key(upload_id)),
    )
    .await
    .map_err(|error| map_api_error(error, resource))?
    else {
        return Ok(None);
    };
    let placement =
        placement_from_merkle_value(&value).map_err(|error| map_api_error(error, resource))?;
    let block = get_block_at_placement(state, &value.cid, &placement)
        .await
        .map_err(|error| map_api_error(error, resource))?;
    if block.codec != CODEC_RAW {
        return Err(S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "multipart upload record is not a raw block",
            resource,
        ));
    }
    let upload: S3MultipartUpload = serde_json::from_slice(&block.payload).map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            error.to_string(),
            resource,
        )
    })?;
    if upload.upload_id != upload_id
        || upload.control_namespace_id != control_namespace_id.to_string()
    {
        return Err(S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "multipart upload record does not match its namespace key",
            resource,
        ));
    }
    Ok(Some(StoredMultipartUpload {
        control_namespace_id,
        value,
        upload,
    }))
}

async fn get_matching_upload(
    state: &AppState,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Result<StoredMultipartUpload, S3Error> {
    multipart_upload(state, upload_id, &format!("/{bucket}/{key}"))
        .await?
        .filter(|stored| stored.upload.bucket == bucket && stored.upload.key == key)
        .ok_or_else(|| S3Error::no_upload(bucket, key))
}

async fn all_multipart_uploads(
    state: &AppState,
    control_namespace_id: &NamespaceId,
) -> Result<Vec<S3MultipartUpload>, S3Error> {
    let entries = scan_namespace_prefix(
        state,
        control_namespace_id,
        S3_MULTIPART_UPLOAD_PREFIX.to_vec(),
        "/",
    )
    .await?;
    let mut uploads = Vec::with_capacity(entries.len());
    for (_, value) in entries {
        let placement =
            placement_from_merkle_value(&value).map_err(|error| map_api_error(error, "/"))?;
        let block = get_block_at_placement(state, &value.cid, &placement)
            .await
            .map_err(|error| map_api_error(error, "/"))?;
        if block.codec != CODEC_RAW {
            return Err(S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "multipart upload record is not a raw block",
                "/",
            ));
        }
        uploads.push(serde_json::from_slice(&block.payload).map_err(|error| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                error.to_string(),
                "/",
            )
        })?);
    }
    Ok(uploads)
}

async fn put_multipart_part(
    state: &AppState,
    stored_upload: &StoredMultipartUpload,
    part: &S3MultipartPart,
    resource: &str,
) -> Result<(), S3Error> {
    let existing =
        multipart_parts(state, &stored_upload.control_namespace_id, &part.upload_id).await?;
    let previous_size = existing
        .iter()
        .find(|existing| existing.part_number == part.part_number)
        .map_or(0, |existing| existing.size);
    let staged_bytes = existing.iter().try_fold(0u64, |total, existing| {
        total.checked_add(existing.size).ok_or_else(|| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "SlowDown",
                "multipart staged byte accounting overflow",
                resource,
            )
        })
    })?;
    let projected = staged_bytes
        .saturating_sub(previous_size)
        .checked_add(part.size)
        .ok_or_else(|| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "SlowDown",
                "multipart staged byte accounting overflow",
                resource,
            )
        })?;
    if projected > state._publication_limits.max_staging_bytes {
        return Err(S3Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "SlowDown",
            "the multipart staged byte limit has been reached",
            resource,
        ));
    }
    let part_key = multipart_part_key(&part.upload_id, part.part_number);
    let current_part = s3_current_value(
        state,
        &stored_upload.control_namespace_id,
        &hex::encode(&part_key),
    )
    .await
    .map_err(|error| map_api_error(error, resource))?;
    let mut part_metadata = BTreeMap::new();
    part_metadata.insert("size".to_string(), part.size.to_string());
    part_metadata.insert(
        "uploaded_at".to_string(),
        part.uploaded_at_unix_seconds.to_string(),
    );
    part_metadata.insert("durability".to_string(), part.durability_status.clone());
    part_metadata.insert(
        BUCKET_DESCRIPTOR_PLACEMENT_METADATA.to_string(),
        serde_json::to_string(&part.content_placement).map_err(|error| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                error.to_string(),
                resource,
            )
        })?,
    );
    let durability_bytes = serde_json::to_vec(&part.durability).map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            error.to_string(),
            resource,
        )
    })?;
    let durability_record = put_namespace_replicated_block(
        state,
        &stored_upload.control_namespace_id,
        CODEC_RAW,
        durability_bytes,
    )
    .await
    .map_err(|error| map_api_error(error, resource))?;
    part_metadata.insert(
        "durability_receipts_cid".to_string(),
        durability_record.cid.to_string(),
    );
    let durability_placement = durability_record.placement.as_ref().ok_or_else(|| {
        S3Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "multipart durability record was stored without authoritative placement",
            resource,
        )
    })?;
    part_metadata.insert(
        "durability_receipts_placement".to_string(),
        serde_json::to_string(durability_placement).map_err(|error| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                error.to_string(),
                resource,
            )
        })?,
    );
    let mutations = vec![
        NamespaceMutation::Put {
            key_hex: hex::encode(part_key),
            value_cid: part.content_cid.clone(),
            value_kind: "s3_multipart_part".to_string(),
            metadata: part_metadata,
            precondition: current_part
                .as_ref()
                .map_or(KeyPrecondition::Absent, value_precondition),
        },
        NamespaceMutation::Put {
            key_hex: hex::encode(multipart_upload_key(&part.upload_id)),
            value_cid: stored_upload.value.cid.clone(),
            value_kind: "s3_multipart_upload".to_string(),
            metadata: stored_upload.value.metadata.clone(),
            precondition: value_precondition(&stored_upload.value),
        },
    ];
    let mut preverified_durability = part.durability.clone();
    preverified_durability.push(durability_record.clone());
    apply_multipart_transaction_preverified(
        state,
        &stored_upload.control_namespace_id,
        mutations,
        vec![part.content_cid.clone(), durability_record.cid],
        preverified_durability,
        part.size,
        resource,
    )
    .await
}

async fn multipart_part_entries(
    state: &AppState,
    control_namespace_id: &NamespaceId,
    upload_id: &str,
) -> Result<Vec<(Vec<u8>, MerkleValue)>, S3Error> {
    scan_namespace_prefix(
        state,
        control_namespace_id,
        multipart_part_prefix(upload_id),
        "/",
    )
    .await
}

async fn multipart_parts(
    state: &AppState,
    control_namespace_id: &NamespaceId,
    upload_id: &str,
) -> Result<Vec<S3MultipartPart>, S3Error> {
    let entries = multipart_part_entries(state, control_namespace_id, upload_id).await?;
    let prefix = multipart_part_prefix(upload_id);
    let mut parts = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let part_number = std::str::from_utf8(&key[prefix.len()..])
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "invalid multipart part namespace key",
                    "/",
                )
            })?;
        let size = value
            .metadata
            .get("size")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "multipart part size metadata is missing or invalid",
                    "/",
                )
            })?;
        let uploaded_at_unix_seconds = value
            .metadata
            .get("uploaded_at")
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or_else(|| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "multipart part timestamp metadata is missing or invalid",
                    "/",
                )
            })?;
        let durability_status = value.metadata.get("durability").cloned().ok_or_else(|| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "multipart part durability metadata is missing",
                "/",
            )
        })?;
        let durability_cid = value
            .metadata
            .get("durability_receipts_cid")
            .ok_or_else(|| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "multipart part durability receipt metadata is missing",
                    "/",
                )
            })?
            .parse::<Cid>()
            .map_err(|_| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "multipart part durability receipt CID is invalid",
                    "/",
                )
            })?;
        let durability_placement: PlacementReference = serde_json::from_str(
            value
                .metadata
                .get("durability_receipts_placement")
                .ok_or_else(|| {
                    S3Error::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        "multipart durability receipt placement is missing",
                        "/",
                    )
                })?,
        )
        .map_err(|error| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                error.to_string(),
                "/",
            )
        })?;
        let durability_block =
            get_block_at_placement(state, &durability_cid, &durability_placement)
                .await
                .map_err(|error| map_api_error(error, "/"))?;
        if durability_block.codec != CODEC_RAW {
            return Err(S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "multipart part durability receipt block is not raw",
                "/",
            ));
        }
        let durability = serde_json::from_slice::<Vec<DurabilityReceipt>>(
            &durability_block.payload,
        )
        .map_err(|error| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                error.to_string(),
                "/",
            )
        })?;
        let content_placement = durability
            .iter()
            .find(|receipt| receipt.cid == value.cid)
            .and_then(|receipt| receipt.placement.clone())
            .ok_or_else(|| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "multipart part durability record omitted content placement",
                    "/",
                )
            })?;
        parts.push(S3MultipartPart {
            upload_id: upload_id.to_string(),
            part_number,
            content_cid: value.cid.clone(),
            content_placement,
            size,
            etag: value.cid.to_string(),
            durability_status,
            uploaded_at_unix_seconds,
            durability,
        });
    }
    parts.sort_by_key(|part| part.part_number);
    Ok(parts)
}

async fn delete_multipart_upload(
    state: &AppState,
    stored_upload: &StoredMultipartUpload,
    resource: &str,
) -> Result<(), S3Error> {
    let completion_key = multipart_completion_key(&stored_upload.upload.upload_id);
    let completion = s3_current_value(
        state,
        &stored_upload.control_namespace_id,
        &hex::encode(&completion_key),
    )
    .await
    .map_err(|error| map_api_error(error, resource))?;
    let mut fence_mutations = Vec::new();
    if let Some(completion) = completion {
        fence_mutations.push(NamespaceMutation::Delete {
            key_hex: hex::encode(completion_key),
            precondition: value_precondition(&completion),
        });
    }
    fence_mutations.push(NamespaceMutation::Delete {
        key_hex: hex::encode(multipart_upload_key(&stored_upload.upload.upload_id)),
        precondition: value_precondition(&stored_upload.value),
    });
    apply_multipart_transaction(
        state,
        &stored_upload.control_namespace_id,
        fence_mutations,
        Vec::new(),
        0,
        resource,
    )
    .await?;

    let entries = multipart_part_entries(
        state,
        &stored_upload.control_namespace_id,
        &stored_upload.upload.upload_id,
    )
    .await?;
    for batch in entries.chunks(S3_MULTIPART_CLEANUP_BATCH) {
        let mutations = batch
            .iter()
            .map(|(key, value)| NamespaceMutation::Delete {
                key_hex: hex::encode(key),
                precondition: value_precondition(value),
            })
            .collect();
        if let Err(error) = apply_multipart_transaction(
            state,
            &stored_upload.control_namespace_id,
            mutations,
            Vec::new(),
            0,
            resource,
        )
        .await
        {
            warn!(
                upload_id = stored_upload.upload.upload_id,
                error = %error.message,
                "multipart record was removed but distributed part cleanup failed"
            );
            break;
        }
    }
    Ok(())
}

fn has_query_parameter(query: Option<&str>, parameter: &str) -> bool {
    query.is_some_and(|query| {
        query.split('&').any(|field| {
            let name = field.split_once('=').map_or(field, |(name, _)| name);
            percent_decode(name)
                .ok()
                .is_some_and(|name| name == parameter.as_bytes())
        })
    })
}

fn is_s3_catalog_descriptor(descriptor: &NamespaceDescriptor) -> bool {
    descriptor.kind == NamespaceKind::Kv
        && descriptor.creator_identity == S3_BUCKET_CATALOG_CREATOR
        && descriptor.creator_signature_hex == "00"
        && descriptor.created_at_unix_seconds == 0
}

pub(super) async fn local_s3_bucket_catalog_namespace(
    state: &AppState,
) -> Result<Option<NamespaceId>, ApiError> {
    let manager = namespace_manager(state)?;
    match namespace_alias(state, S3_BUCKET_CATALOG_ALIAS) {
        Ok(namespace_id) => {
            let namespace = manager
                .linearizable_namespace_head(&namespace_id)
                .await
                .map_err(consensus_error)?;
            if is_s3_catalog_descriptor(&namespace.descriptor) {
                return Ok(Some(namespace_id));
            }
            return Err(ApiError::internal(
                "reserved S3 bucket catalog alias has an invalid descriptor",
            ));
        }
        Err(error) if error.code == ErrorCode::NotFound => {}
        Err(error) => return Err(error),
    }
    for status in manager.operational_statuses().await {
        let namespace_id = status.namespace_id;
        let Ok(group) = manager.group(&namespace_id).await else {
            continue;
        };
        if is_s3_catalog_descriptor(&group.namespace_state().await.descriptor) {
            cache_alias(state, S3_BUCKET_CATALOG_ALIAS, &namespace_id)?;
            return Ok(Some(namespace_id));
        }
    }
    Ok(None)
}

async fn ensure_s3_bucket_catalog(
    state: &AppState,
    resource: &str,
) -> Result<NamespaceId, S3Error> {
    let catalog_lock = state
        .s3
        .as_ref()
        .ok_or_else(|| S3Error::no_bucket(""))?
        .bucket_catalog_lock
        .clone();
    let _catalog_guard = catalog_lock.lock().await;
    if let Some(namespace_id) = discover_s3_bucket_catalog(state, resource).await? {
        return Ok(namespace_id);
    }

    create_s3_bucket_catalog(state, resource).await
}

async fn discover_s3_bucket_catalog(
    state: &AppState,
    resource: &str,
) -> Result<Option<NamespaceId>, S3Error> {
    if let Some(namespace_id) = local_s3_bucket_catalog_namespace(state)
        .await
        .map_err(|error| map_api_error(error, resource))?
    {
        return Ok(Some(namespace_id));
    }
    for peer in state.network.peers().await {
        for address in peer.addresses {
            let Ok(address) = address.parse() else {
                continue;
            };
            let Ok(response) = state
                .network
                .namespace_alias_resolve(address, S3_BUCKET_CATALOG_ALIAS.to_string())
                .await
            else {
                continue;
            };
            if !response.found {
                continue;
            }
            let cid = response.namespace_id.parse::<Cid>().map_err(|_| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "peer returned an invalid S3 bucket catalog namespace ID",
                    resource,
                )
            })?;
            let namespace_id = NamespaceId::new(cid).map_err(|_| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "peer returned a non-namespace S3 bucket catalog ID",
                    resource,
                )
            })?;
            let namespace = namespace_manager(state)
                .map_err(|error| map_api_error(error, resource))?
                .linearizable_namespace_head(&namespace_id)
                .await
                .map_err(|error| {
                    S3Error::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "ServiceUnavailable",
                        error.to_string(),
                        resource,
                    )
                })?;
            if !is_s3_catalog_descriptor(&namespace.descriptor) {
                return Err(S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "peer returned an invalid S3 bucket catalog namespace",
                    resource,
                ));
            }
            cache_alias(state, S3_BUCKET_CATALOG_ALIAS, &namespace_id)
                .map_err(|error| map_api_error(error, resource))?;
            return Ok(Some(namespace_id));
        }
    }
    Ok(None)
}

async fn create_s3_bucket_catalog(
    state: &AppState,
    resource: &str,
) -> Result<NamespaceId, S3Error> {
    let manager = namespace_manager(state).map_err(|error| map_api_error(error, resource))?;
    let seed = Cid::new(CODEC_RAW, S3_BUCKET_CATALOG_CREATOR.as_bytes());
    let replicas = manager
        .select_replica_set(&seed, state.namespace_log_bytes)
        .await
        .map_err(|error| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                error.to_string(),
                resource,
            )
        })?;
    let descriptor = NamespaceDescriptor::new(
        NamespaceKind::Kv,
        replicas,
        S3_BUCKET_CATALOG_CREATOR,
        "00",
        0,
    );
    let created = bootstrap_namespace_group(state, descriptor)
        .await
        .map_err(|error| map_api_error(error, resource))?;
    cache_alias(state, S3_BUCKET_CATALOG_ALIAS, &created.namespace_id)
        .map_err(|error| map_api_error(error, resource))?;
    let deadline = time::Instant::now() + Duration::from_secs(10);
    loop {
        if manager
            .linearizable_namespace_head(&created.namespace_id)
            .await
            .is_ok()
        {
            return Ok(created.namespace_id);
        }
        if time::Instant::now() >= deadline {
            return Err(S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "S3 bucket catalog did not establish quorum before the deadline",
                resource,
            ));
        }
        time::sleep(Duration::from_millis(100)).await;
    }
}

fn s3_placement_map_epoch_key(epoch: u64) -> Vec<u8> {
    let mut key = S3_PLACEMENT_MAP_EPOCH_PREFIX.to_vec();
    key.extend_from_slice(format!("{epoch:020}").as_bytes());
    key
}

fn s3_placement_exception_key(reference: &PlacementReference) -> Result<Vec<u8>, ApiError> {
    let encoded = serde_json::to_vec(reference).map_err(ApiError::serde)?;
    let mut key = S3_PLACEMENT_EXCEPTION_PREFIX.to_vec();
    key.extend_from_slice(hex::encode(blake3::hash(&encoded).as_bytes()).as_bytes());
    Ok(key)
}

async fn s3_control_value(
    state: &AppState,
    catalog_namespace_id: &NamespaceId,
    key: &[u8],
    resource: &str,
) -> Result<Option<MerkleValue>, S3Error> {
    let namespace = namespace_manager(state)
        .map_err(|error| map_api_error(error, resource))?
        .linearizable_namespace_head(catalog_namespace_id)
        .await
        .map_err(|error| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                error.to_string(),
                resource,
            )
        })?;
    pepper_merkle::get(
        &direct_namespace_store(state, &namespace).await,
        &namespace.current_root_cid,
        key,
        MerkleLimits::default(),
    )
    .await
    .map_err(|error| S3Error::invalid(error.to_string(), resource))
}

fn placement_control_metadata(
    receipt: &DurabilityReceipt,
    field: &str,
    value: &impl Serialize,
) -> Result<BTreeMap<String, String>, ApiError> {
    let placement = receipt.placement.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Unavailable,
            "placement control block was stored without authoritative placement",
        )
    })?;
    let mut metadata = BTreeMap::new();
    metadata.insert(
        BUCKET_DESCRIPTOR_PLACEMENT_METADATA.to_string(),
        serde_json::to_string(placement).map_err(ApiError::serde)?,
    );
    metadata.insert(
        field.to_string(),
        serde_json::to_string(value).map_err(ApiError::serde)?,
    );
    Ok(metadata)
}

pub(super) async fn admin_placement_status(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let catalog = ensure_s3_bucket_catalog(&state, "/v1/admin/placement")
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    ensure_s3_placement_map(&state, &catalog, "/v1/admin/placement")
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    refresh_s3_placement_control(&state, &catalog, "/v1/admin/placement")
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    Ok(Json(serde_json::json!({
        "current_map": state.placement.current_map(),
        "exceptions": state.placement.exceptions(unix_seconds()),
    })))
}

pub(super) async fn admin_placement_map_update(
    State(state): State<AppState>,
    Json(map): Json<PlacementMap>,
) -> Result<Json<serde_json::Value>, ApiError> {
    map.validate().map_err(authoritative_placement_error)?;
    let catalog = ensure_s3_bucket_catalog(&state, "/v1/admin/placement/maps")
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    let current = ensure_s3_placement_map(&state, &catalog, "/v1/admin/placement/maps")
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    if map.epoch != current.epoch.saturating_add(1) {
        return Err(ApiError::bad_request(format!(
            "placement map epoch must be {}",
            current.epoch.saturating_add(1)
        )));
    }
    let current_value = s3_control_value(
        &state,
        &catalog,
        S3_PLACEMENT_MAP_CURRENT_KEY,
        "/v1/admin/placement/maps",
    )
    .await
    .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?
    .ok_or_else(|| ApiError::internal("current placement map pointer is missing"))?;
    let payload = serde_json::to_vec(&map).map_err(ApiError::serde)?;
    let receipt = put_namespace_replicated_block(&state, &catalog, CODEC_RAW, payload).await?;
    let mut metadata = placement_control_metadata(&receipt, S3_PLACEMENT_MAP_METADATA, &map)?;
    metadata.insert("placement_epoch".to_string(), map.epoch.to_string());
    apply_multipart_transaction_preverified(
        &state,
        &catalog,
        vec![
            NamespaceMutation::Put {
                key_hex: hex::encode(S3_PLACEMENT_MAP_CURRENT_KEY),
                value_cid: receipt.cid.clone(),
                value_kind: "placement_map".to_string(),
                metadata: metadata.clone(),
                precondition: value_precondition(&current_value),
            },
            NamespaceMutation::Put {
                key_hex: hex::encode(s3_placement_map_epoch_key(map.epoch)),
                value_cid: receipt.cid.clone(),
                value_kind: "placement_map".to_string(),
                metadata,
                precondition: KeyPrecondition::Absent,
            },
        ],
        vec![receipt.cid.clone()],
        vec![receipt],
        0,
        "/v1/admin/placement/maps",
    )
    .await
    .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    let installed = state
        .placement
        .install_map(map)
        .map_err(authoritative_placement_error)?;
    refresh_fast_path_placement(&state);
    Ok(Json(serde_json::json!({"map": installed})))
}

fn decode_placement_exception_value(value: &MerkleValue) -> Result<PlacementException, String> {
    if value.value_kind != "placement_exception" {
        return Err("placement exception value kind is invalid".to_string());
    }
    let encoded = value
        .metadata
        .get("placement_exception")
        .ok_or_else(|| "placement exception metadata is missing".to_string())?;
    let exception: PlacementException =
        serde_json::from_str(encoded).map_err(|error| error.to_string())?;
    exception.validate().map_err(|error| error.to_string())?;
    let canonical = serde_json::to_vec(&exception).map_err(|error| error.to_string())?;
    if Cid::new(CODEC_RAW, &canonical) != value.cid {
        return Err("placement exception metadata does not match its CID".to_string());
    }
    Ok(exception)
}

pub(super) async fn admin_placement_exception_put(
    State(state): State<AppState>,
    Json(exception): Json<PlacementException>,
) -> Result<Json<serde_json::Value>, ApiError> {
    exception
        .validate()
        .map_err(authoritative_placement_error)?;
    state
        .placement
        .ensure_exception_capacity(&exception.reference, unix_seconds())
        .map_err(authoritative_placement_error)?;
    state
        .placement
        .decide(&exception.reference)
        .map_err(authoritative_placement_error)?;
    let target = state.placement.map(exception.target_epoch).ok_or_else(|| {
        authoritative_placement_error(AuthoritativePlacementError::EpochMismatch {
            reference: exception.target_epoch,
            map: state.placement.current_map().map_or(0, |map| map.epoch),
        })
    })?;
    if exception.node_ids.iter().any(|node_id| {
        !target
            .nodes
            .iter()
            .any(|node| node.node_id == *node_id && node.state == PlacementMapNodeState::In)
    }) {
        return Err(ApiError::bad_request(
            "placement exception contains a node outside the target map",
        ));
    }
    let block = get_block_at_placement(&state, &exception.block_cid, &exception.reference).await?;
    let encoded = tokio::task::block_in_place(|| {
        state
            .block_store
            .get_encoded(&exception.block_cid)
            .or_else(|_| state.block_store.encode(block.codec, &block.payload))
    })?;
    let local_node_id = state.network.local_descriptor().node_id;
    for node_id in &exception.node_ids {
        if node_id == &local_node_id {
            tokio::task::block_in_place(|| state.block_store.put_encoded(&encoded))?;
            continue;
        }
        let address = state.network.peer_address(node_id).await.ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Unavailable,
                format!("placement exception target {node_id} has no routable address"),
            )
        })?;
        metrics::PLACEMENT_DIRECT_TARGET_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        let ack = state
            .network
            .block_put_replica_stream(
                address,
                block.codec,
                &exception.block_cid,
                encoded.logical_size_bytes(),
                Arc::from(encoded.bytes()),
            )
            .await
            .map_err(|error| {
                metrics::PLACEMENT_DIRECT_TARGET_ERRORS.fetch_add(1, Ordering::Relaxed);
                ApiError::network(error)
            })?;
        parse_replica_ack(
            node_id,
            &exception.block_cid,
            block.codec,
            encoded.logical_size_bytes(),
            &ack,
        )?;
        metrics::PLACEMENT_DIRECT_TARGET_BYTES
            .fetch_add(encoded.logical_size_bytes(), Ordering::Relaxed);
    }
    let catalog = ensure_s3_bucket_catalog(&state, "/v1/admin/placement/exceptions")
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    let key = s3_placement_exception_key(&exception.reference)?;
    let existing = s3_control_value(&state, &catalog, &key, "/v1/admin/placement/exceptions")
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    if let Some(value) = &existing {
        let current = decode_placement_exception_value(value).map_err(ApiError::internal)?;
        if exception.generation != current.generation.saturating_add(1) {
            return Err(ApiError::bad_request(format!(
                "placement exception generation must be {}",
                current.generation.saturating_add(1)
            )));
        }
    } else if exception.generation != 1 {
        return Err(ApiError::bad_request(
            "a new placement exception must have generation 1",
        ));
    }
    let encoded = serde_json::to_vec(&exception).map_err(ApiError::serde)?;
    let value_cid = Cid::new(CODEC_RAW, &encoded);
    let metadata = BTreeMap::from([(
        "placement_exception".to_string(),
        serde_json::to_string(&exception).map_err(ApiError::serde)?,
    )]);
    apply_metadata_only_transaction(
        &state,
        &catalog,
        vec![NamespaceMutation::Put {
            key_hex: hex::encode(key),
            value_cid: value_cid.clone(),
            value_kind: "placement_exception".to_string(),
            metadata,
            precondition: existing
                .as_ref()
                .map_or(KeyPrecondition::Absent, value_precondition),
        }],
        vec![value_cid],
        encoded.len() as u64,
        "/v1/admin/placement/exceptions",
    )
    .await
    .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    state
        .placement
        .install_exception(exception.clone())
        .map_err(authoritative_placement_error)?;
    refresh_fast_path_placement(&state);
    Ok(Json(serde_json::json!({"exception": exception})))
}

pub(super) async fn commit_preverified_repair_exception(
    state: &AppState,
    reference: PlacementReference,
    block_cid: Cid,
    node_ids: Vec<String>,
    reason: String,
    ttl_seconds: i64,
) -> Result<PlacementException, ApiError> {
    reference
        .validate()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    if ttl_seconds <= 0 || node_ids.is_empty() {
        return Err(ApiError::bad_request(
            "repair exception requires destinations and a positive TTL",
        ));
    }
    let now = unix_seconds();
    let target_map = state
        .placement
        .current_map()
        .ok_or_else(|| ApiError::internal("authoritative placement map is not loaded"))?;
    if target_map.epoch < reference.epoch
        || node_ids.iter().any(|node_id| {
            !target_map
                .nodes
                .iter()
                .any(|node| node.node_id == *node_id && node.state == PlacementMapNodeState::In)
        })
    {
        return Err(ApiError::bad_request(
            "repair exception target is outside the current placement map",
        ));
    }
    for node_id in &node_ids {
        let healthy = if node_id == &state.status.node_id {
            state.block_store.has(&block_cid)?
        } else if let Some(address) = state.network.peer_address(node_id).await {
            matches!(
                time::timeout(
                    Duration::from_secs(5),
                    state.network.block_has(address, &block_cid)
                )
                .await,
                Ok(Ok(true))
            )
        } else {
            false
        };
        if !healthy {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Unavailable,
                format!("repair exception target {node_id} does not hold {block_cid}"),
            ));
        }
    }
    let catalog = ensure_s3_bucket_catalog(state, "/v1/admin/placement/exceptions")
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    let key = s3_placement_exception_key(&reference)?;
    let existing = s3_control_value(state, &catalog, &key, "/v1/admin/placement/exceptions")
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    let generation = if let Some(value) = &existing {
        let current = decode_placement_exception_value(value).map_err(ApiError::internal)?;
        if current.block_cid == block_cid
            && current.node_ids == node_ids
            && current.reason == reason
            && current.expires_at_unix_seconds > now.saturating_add(ttl_seconds / 2)
        {
            return Ok(current);
        }
        current.generation.saturating_add(1)
    } else {
        1
    };
    let exception = PlacementException {
        reference: reference.clone(),
        block_cid,
        source_epoch: reference.epoch,
        target_epoch: target_map.epoch,
        generation,
        node_ids,
        reason,
        created_at_unix_seconds: now,
        expires_at_unix_seconds: now.saturating_add(ttl_seconds),
    };
    exception
        .validate()
        .map_err(authoritative_placement_error)?;
    state
        .placement
        .ensure_exception_capacity(&reference, now)
        .map_err(authoritative_placement_error)?;
    let encoded = serde_json::to_vec(&exception).map_err(ApiError::serde)?;
    let value_cid = Cid::new(CODEC_RAW, &encoded);
    let metadata = BTreeMap::from([(
        "placement_exception".to_string(),
        serde_json::to_string(&exception).map_err(ApiError::serde)?,
    )]);
    apply_metadata_only_transaction(
        state,
        &catalog,
        vec![NamespaceMutation::Put {
            key_hex: hex::encode(key),
            value_cid: value_cid.clone(),
            value_kind: "placement_exception".to_string(),
            metadata,
            precondition: existing
                .as_ref()
                .map_or(KeyPrecondition::Absent, value_precondition),
        }],
        vec![value_cid],
        encoded.len() as u64,
        "/v1/admin/placement/exceptions",
    )
    .await
    .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    state
        .placement
        .install_exception(exception.clone())
        .map_err(authoritative_placement_error)?;
    refresh_fast_path_placement(state);
    Ok(exception)
}

pub(super) async fn committed_placement_exception(
    state: &AppState,
    reference: &PlacementReference,
) -> Result<Option<PlacementException>, ApiError> {
    let catalog = ensure_s3_bucket_catalog(state, "/v1/admin/placement/exceptions")
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    let key = s3_placement_exception_key(reference)?;
    let Some(value) = s3_control_value(state, &catalog, &key, "/v1/admin/placement/exceptions")
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?
    else {
        return Ok(None);
    };
    let exception = decode_placement_exception_value(&value).map_err(ApiError::internal)?;
    if &exception.reference != reference {
        return Err(ApiError::internal(
            "placement exception key/reference mismatch",
        ));
    }
    Ok(Some(exception))
}

#[derive(Debug, Deserialize)]
pub(super) struct PlacementExceptionDeleteRequest {
    reference: PlacementReference,
    generation: u64,
}

pub(super) async fn admin_placement_exception_delete(
    State(state): State<AppState>,
    Json(request): Json<PlacementExceptionDeleteRequest>,
) -> Result<StatusCode, ApiError> {
    let catalog = ensure_s3_bucket_catalog(&state, "/v1/admin/placement/exceptions/delete")
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    let key = s3_placement_exception_key(&request.reference)?;
    let value = s3_control_value(
        &state,
        &catalog,
        &key,
        "/v1/admin/placement/exceptions/delete",
    )
    .await
    .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?
    .ok_or_else(|| ApiError::not_found("placement exception not found"))?;
    let current = decode_placement_exception_value(&value).map_err(ApiError::internal)?;
    if current.generation != request.generation {
        return Err(ApiError::bad_request(
            "placement exception generation does not match",
        ));
    }
    apply_multipart_transaction(
        &state,
        &catalog,
        vec![NamespaceMutation::Delete {
            key_hex: hex::encode(key),
            precondition: value_precondition(&value),
        }],
        Vec::new(),
        0,
        "/v1/admin/placement/exceptions/delete",
    )
    .await
    .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    state.placement.remove_exception(&request.reference);
    refresh_fast_path_placement(&state);
    Ok(StatusCode::NO_CONTENT)
}

async fn decode_s3_placement_map(
    state: &AppState,
    value: &MerkleValue,
    resource: &str,
) -> Result<Arc<PlacementMap>, S3Error> {
    let encoded = value
        .metadata
        .get(S3_PLACEMENT_MAP_METADATA)
        .ok_or_else(|| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "placement map metadata is missing",
                resource,
            )
        })?;
    let map: PlacementMap = serde_json::from_str(encoded).map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("invalid placement map: {error}"),
            resource,
        )
    })?;
    let installed = state.placement.install_map(map).map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("rejected placement map: {error}"),
            resource,
        )
    })?;
    refresh_fast_path_placement(state);
    Ok(installed)
}

async fn load_s3_placement_map(
    state: &AppState,
    catalog_namespace_id: &NamespaceId,
    resource: &str,
) -> Result<Option<Arc<PlacementMap>>, S3Error> {
    let namespace = namespace_manager(state)
        .map_err(|error| map_api_error(error, resource))?
        .linearizable_namespace_head(catalog_namespace_id)
        .await
        .map_err(|error| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                error.to_string(),
                resource,
            )
        })?;
    let store = direct_namespace_store(state, &namespace).await;
    let value = pepper_merkle::get(
        &store,
        &namespace.current_root_cid,
        S3_PLACEMENT_MAP_CURRENT_KEY,
        MerkleLimits::default(),
    )
    .await
    .map_err(|error| S3Error::invalid(error.to_string(), resource))?;
    match value {
        Some(value) => decode_s3_placement_map(state, &value, resource)
            .await
            .map(Some),
        None => Ok(None),
    }
}

pub(super) async fn ensure_s3_placement_epoch_loaded(
    state: &AppState,
    epoch: u64,
) -> Result<(), ApiError> {
    if state.placement.map(epoch).is_some() {
        return Ok(());
    }
    let resource = "/placement-epoch";
    let catalog = ensure_s3_bucket_catalog(state, resource)
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    let value = s3_control_value(
        state,
        &catalog,
        &s3_placement_map_epoch_key(epoch),
        resource,
    )
    .await
    .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?
    .ok_or_else(|| {
        authoritative_placement_error(AuthoritativePlacementError::EpochMismatch {
            reference: epoch,
            map: state.placement.current_map().map_or(0, |map| map.epoch),
        })
    })?;
    let map = decode_s3_placement_map(state, &value, resource)
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    if map.epoch != epoch {
        return Err(ApiError::internal(
            "placement epoch catalog key does not match its map",
        ));
    }
    Ok(())
}

pub(super) async fn ensure_s3_current_placement_loaded(state: &AppState) -> Result<(), ApiError> {
    if state.placement.current_map().is_some() {
        return Ok(());
    }
    let resource = "/maintenance-placement";
    let catalog = ensure_s3_bucket_catalog(state, resource)
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    ensure_s3_placement_map(state, &catalog, resource)
        .await
        .map_err(|error| ApiError::new(error.status, ErrorCode::Unavailable, error.message))?;
    Ok(())
}

async fn refresh_s3_placement_control(
    state: &AppState,
    catalog_namespace_id: &NamespaceId,
    resource: &str,
) -> Result<(), S3Error> {
    let namespace = namespace_manager(state)
        .map_err(|error| map_api_error(error, resource))?
        .linearizable_namespace_head(catalog_namespace_id)
        .await
        .map_err(|error| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                error.to_string(),
                resource,
            )
        })?;
    let store = direct_namespace_store(state, &namespace).await;
    let mut exceptions = Vec::new();
    let mut expired_exceptions = Vec::new();
    let now = unix_seconds();
    for prefix in [S3_PLACEMENT_MAP_EPOCH_PREFIX, S3_PLACEMENT_EXCEPTION_PREFIX] {
        let mut cursor = None;
        loop {
            let page = pepper_merkle::scan(
                &store,
                &namespace.current_root_cid,
                ScanQuery {
                    prefix: Some(prefix.to_vec()),
                    limit: 4096,
                    cursor,
                    ..ScanQuery::default()
                },
                MerkleLimits::default(),
            )
            .await
            .map_err(|error| S3Error::invalid(error.to_string(), resource))?;
            for entry in page.entries {
                if prefix == S3_PLACEMENT_MAP_EPOCH_PREFIX {
                    decode_s3_placement_map(state, &entry.value, resource).await?;
                } else {
                    let exception =
                        decode_placement_exception_value(&entry.value).map_err(|error| {
                            S3Error::new(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "InternalError",
                                error,
                                resource,
                            )
                        })?;
                    if exception.expires_at_unix_seconds <= now {
                        expired_exceptions.push((entry.key, entry.value, exception));
                    } else {
                        exceptions.push(exception);
                    }
                }
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
    }
    state
        .placement
        .replace_exceptions(exceptions)
        .map_err(|error| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                error.to_string(),
                resource,
            )
        })?;
    refresh_fast_path_placement(state);
    let mut collected_exceptions = Vec::new();
    for (key, value, exception) in expired_exceptions {
        match super::repair::collect_expired_repair_exception(state, &exception).await {
            Ok(_) => collected_exceptions.push((key, value)),
            Err(error) => {
                warn!(
                    message = %error.message,
                    reference = ?exception.reference,
                    "expired placement exception remains committed until every extra is safe to collect"
                );
            }
        }
    }
    for chunk in collected_exceptions.chunks(32) {
        let mutations = chunk
            .iter()
            .map(|(key, value)| NamespaceMutation::Delete {
                key_hex: hex::encode(key),
                precondition: value_precondition(value),
            })
            .collect::<Vec<_>>();
        if let Err(error) = apply_multipart_transaction(
            state,
            catalog_namespace_id,
            mutations,
            Vec::new(),
            0,
            resource,
        )
        .await
        {
            warn!(
                message = %error.message,
                count = chunk.len(),
                "expired placement exception cleanup will retry"
            );
            break;
        }
    }
    metrics::PLACEMENT_MAP_REFRESHES.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

pub(super) fn spawn_s3_placement_refresh_loop(state: AppState) {
    if state.s3.is_none() {
        return;
    }
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            // Refresh is maintenance, not catalog creation. Creating the
            // singleton catalog concurrently on every gateway can select
            // different three-node replica sets while membership is still
            // converging. Only an explicit S3/control-plane operation creates
            // it; background workers discover and cache that authoritative ID.
            let Ok(Some(catalog)) = discover_s3_bucket_catalog(&state, "/placement-refresh").await
            else {
                continue;
            };
            if ensure_s3_placement_map(&state, &catalog, "/placement-refresh")
                .await
                .is_err()
            {
                continue;
            }
            if let Err(error) =
                refresh_s3_placement_control(&state, &catalog, "/placement-refresh").await
            {
                metrics::PLACEMENT_MAP_REFRESH_FAILURES.fetch_add(1, Ordering::Relaxed);
                warn!(message = %error.message, "placement control refresh failed");
            }
        }
    });
}

async fn ensure_s3_placement_map(
    state: &AppState,
    catalog_namespace_id: &NamespaceId,
    resource: &str,
) -> Result<Arc<PlacementMap>, S3Error> {
    if let Some(map) = state.placement.current_map() {
        return Ok(map);
    }
    let lock = state
        .s3
        .as_ref()
        .ok_or_else(|| S3Error::no_bucket(""))?
        .placement_map_lock
        .clone();
    let _guard = lock.lock().await;
    if let Some(map) = state.placement.current_map() {
        return Ok(map);
    }
    if let Some(map) = load_s3_placement_map(state, catalog_namespace_id, resource).await? {
        return Ok(map);
    }

    // The first committed epoch is authoritative for every object written
    // against it. Never let startup discovery races permanently create an
    // epoch too small for the configured durability policy. Concurrent
    // gateways may race this transaction, but each candidate map is complete
    // and deterministically sorted before one wins the catalog CAS.
    let required_nodes = required_initial_placement_nodes(state);
    let discovery_deadline = time::Instant::now() + Duration::from_secs(30);
    let candidates = loop {
        state.network.refresh_routing_table().await;
        let candidates = placement_candidates(state, state.network.peers().await);
        let distinct_nodes = candidates
            .iter()
            .map(|candidate| candidate.node_id.as_str())
            .collect::<HashSet<_>>()
            .len();
        if distinct_nodes >= required_nodes {
            break candidates;
        }
        if time::Instant::now() >= discovery_deadline {
            return Err(S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                format!(
                    "cannot create placement map: durability policy requires {required_nodes} nodes but only {distinct_nodes} authenticated nodes were discovered"
                ),
                resource,
            ));
        }
        time::sleep(Duration::from_millis(100)).await;
    };
    let map = placement_map_from_candidates(1, &candidates);
    map.validate().map_err(|error| {
        S3Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            format!("cannot create placement map: {error}"),
            resource,
        )
    })?;
    let payload = serde_json::to_vec(&map).map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            error.to_string(),
            resource,
        )
    })?;
    let catalog = namespace_manager(state)
        .map_err(|error| map_api_error(error, resource))?
        .linearizable_namespace_head(catalog_namespace_id)
        .await
        .map_err(|error| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                error.to_string(),
                resource,
            )
        })?;
    let catalog_durability = usize::from(catalog.descriptor.durability.replicas);
    // This is the sole bootstrap write that precedes authoritative placement.
    // Its consensus entry makes the map discoverable. It must satisfy the
    // catalog's own durability policy up front because no committed placement
    // map exists yet for the publication barrier to repair an undersized
    // receipt. Every subsequent S3 data write is routed by the committed map.
    let receipt = put_replicated_block_with_placement_map(
        state,
        CODEC_RAW,
        payload,
        catalog_durability,
        Some(Arc::new(map.clone())),
    )
    .await
    .map_err(|error| map_api_error(error, resource))?;
    let mut metadata = BTreeMap::new();
    metadata.insert("placement_epoch".to_string(), map.epoch.to_string());
    metadata.insert(
        S3_PLACEMENT_MAP_METADATA.to_string(),
        serde_json::to_string(&map).map_err(|error| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                error.to_string(),
                resource,
            )
        })?,
    );
    let placement = receipt.placement.as_ref().ok_or_else(|| {
        S3Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "placement map block was stored without authoritative placement",
            resource,
        )
    })?;
    metadata.insert(
        BUCKET_DESCRIPTOR_PLACEMENT_METADATA.to_string(),
        serde_json::to_string(placement).map_err(|error| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                error.to_string(),
                resource,
            )
        })?,
    );
    let mutations = vec![
        NamespaceMutation::Put {
            key_hex: hex::encode(S3_PLACEMENT_MAP_CURRENT_KEY),
            value_cid: receipt.cid.clone(),
            value_kind: "placement_map".to_string(),
            metadata: metadata.clone(),
            precondition: KeyPrecondition::Absent,
        },
        NamespaceMutation::Put {
            key_hex: hex::encode(s3_placement_map_epoch_key(map.epoch)),
            value_cid: receipt.cid.clone(),
            value_kind: "placement_map".to_string(),
            metadata,
            precondition: KeyPrecondition::Absent,
        },
    ];
    let result = apply_multipart_transaction_preverified(
        state,
        catalog_namespace_id,
        mutations,
        vec![receipt.cid.clone()],
        vec![receipt],
        0,
        resource,
    )
    .await;
    if result.is_ok() {
        let installed = state.placement.install_map(map).map_err(|error| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                error.to_string(),
                resource,
            )
        })?;
        refresh_fast_path_placement(state);
        return Ok(installed);
    }
    if let Some(map) = load_s3_placement_map(state, catalog_namespace_id, resource).await? {
        return Ok(map);
    }
    result?;
    unreachable!("successful placement-map transaction returns above")
}

fn required_initial_placement_nodes(state: &AppState) -> usize {
    let erasure_nodes = if state.erasure_enabled {
        usize::from(
            state
                .erasure_data_shards
                .saturating_add(state.erasure_parity_shards),
        )
    } else {
        0
    };
    state.replication_factor.max(erasure_nodes).max(1)
}

fn s3_catalog_key(bucket: &str) -> Vec<u8> {
    let mut key = S3_BUCKET_CATALOG_KEY_PREFIX.to_vec();
    key.extend_from_slice(bucket.as_bytes());
    key
}

async fn decode_s3_catalog_value(
    state: &AppState,
    value: &MerkleValue,
    resource: &str,
) -> Result<NamespaceId, S3Error> {
    let placement =
        placement_from_merkle_value(value).map_err(|error| map_api_error(error, resource))?;
    let block = get_block_at_placement(state, &value.cid, &placement)
        .await
        .map_err(|error| map_api_error(error, resource))?;
    if block.codec != CODEC_RAW {
        return Err(S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "S3 bucket catalog value is not a raw block",
            resource,
        ));
    }
    let namespace_id = String::from_utf8(block.payload)
        .map_err(|_| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "S3 bucket catalog value is not UTF-8",
                resource,
            )
        })?
        .parse::<Cid>()
        .map_err(|_| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "S3 bucket catalog value is not a namespace ID",
                resource,
            )
        })?;
    NamespaceId::new(namespace_id).map_err(|_| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "S3 bucket catalog value is not a bucket namespace ID",
            resource,
        )
    })
}

async fn s3_catalog_lookup(
    state: &AppState,
    catalog_namespace_id: &NamespaceId,
    bucket: &str,
    resource: &str,
) -> Result<Option<NamespaceId>, S3Error> {
    // Catalog entries are immutable: delete/recreate retains the same bucket
    // namespace and records deletion inside that namespace. Once the local
    // Raft replica has applied an entry it is therefore safe to serve that hit
    // without another quorum round trip. Absence still uses a linearizable read
    // so concurrent CreateBucket requests cannot claim different namespaces.
    if let Ok(group) = namespace_manager(state)
        .map_err(|error| map_api_error(error, resource))?
        .group(catalog_namespace_id)
        .await
    {
        let namespace = group.namespace_state().await;
        let store = direct_namespace_store(state, &namespace).await;
        let value = pepper_merkle::get(
            &store,
            &namespace.current_root_cid,
            &s3_catalog_key(bucket),
            MerkleLimits::default(),
        )
        .await
        .map_err(|error| S3Error::invalid(error.to_string(), resource))?;
        if let Some(value) = value {
            return decode_s3_catalog_value(state, &value, resource)
                .await
                .map(Some);
        }
    }
    let value = s3_current_value(
        state,
        catalog_namespace_id,
        &hex::encode(s3_catalog_key(bucket)),
    )
    .await
    .map_err(|error| map_api_error(error, resource))?;
    match value {
        Some(value) => decode_s3_catalog_value(state, &value, resource)
            .await
            .map(Some),
        None => Ok(None),
    }
}

async fn claim_s3_catalog_entry(
    state: &AppState,
    catalog_namespace_id: &NamespaceId,
    bucket: &str,
    bucket_namespace_id: &NamespaceId,
    resource: &str,
) -> Result<NamespaceId, S3Error> {
    if let Some(existing) = s3_catalog_lookup(state, catalog_namespace_id, bucket, resource).await?
    {
        return Ok(existing);
    }
    let receipt = put_namespace_replicated_block(
        state,
        catalog_namespace_id,
        CODEC_RAW,
        bucket_namespace_id.to_string().into_bytes(),
    )
    .await
    .map_err(|error| map_api_error(error, resource))?;
    let placement = receipt.placement.clone().ok_or_else(|| {
        S3Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "bucket catalog entry was stored without authoritative placement",
            resource,
        )
    })?;
    let mut metadata = BTreeMap::new();
    metadata.insert(
        BUCKET_DESCRIPTOR_PLACEMENT_METADATA.to_string(),
        serde_json::to_string(&placement).map_err(|error| {
            S3Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                error.to_string(),
                resource,
            )
        })?,
    );
    let result = apply_multipart_transaction_preverified(
        state,
        catalog_namespace_id,
        vec![NamespaceMutation::Put {
            key_hex: hex::encode(s3_catalog_key(bucket)),
            value_cid: receipt.cid.clone(),
            value_kind: "s3_bucket_catalog_entry".to_string(),
            metadata,
            precondition: KeyPrecondition::Absent,
        }],
        vec![receipt.cid.clone()],
        vec![receipt],
        0,
        resource,
    )
    .await;
    if result.is_ok() {
        return Ok(bucket_namespace_id.clone());
    }
    if let Some(existing) = s3_catalog_lookup(state, catalog_namespace_id, bucket, resource).await?
    {
        return Ok(existing);
    }
    result.map(|_| bucket_namespace_id.clone())
}

async fn s3_catalog_aliases(
    state: &AppState,
    catalog_namespace_id: &NamespaceId,
    resource: &str,
) -> Result<Vec<(String, NamespaceId)>, S3Error> {
    let entries = scan_namespace_prefix(
        state,
        catalog_namespace_id,
        S3_BUCKET_CATALOG_KEY_PREFIX.to_vec(),
        resource,
    )
    .await?;
    if entries.len() > S3_MAX_DISCOVERED_BUCKETS {
        return Err(S3Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "SlowDown",
            "S3 bucket catalog exceeded its bounded size",
            resource,
        ));
    }
    let mut aliases = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let bucket = std::str::from_utf8(&key[S3_BUCKET_CATALOG_KEY_PREFIX.len()..])
            .map_err(|_| {
                S3Error::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "S3 bucket catalog contains an invalid name",
                    resource,
                )
            })?
            .to_string();
        validate_bucket_name(&bucket)?;
        let namespace_id = decode_s3_catalog_value(state, &value, resource).await?;
        aliases.push((bucket, namespace_id));
    }
    Ok(aliases)
}

async fn catalog_s3_buckets(
    state: &AppState,
    resource: &str,
) -> Result<Vec<(String, NamespaceId)>, S3Error> {
    let catalog_namespace_id = ensure_s3_bucket_catalog(state, resource).await?;
    ensure_s3_placement_map(state, &catalog_namespace_id, resource).await?;
    let mut aliases = Vec::new();
    for (alias, namespace_id) in s3_catalog_aliases(state, &catalog_namespace_id, resource).await? {
        let namespace = namespace_manager(state)
            .map_err(|error| map_api_error(error, resource))?
            .linearizable_namespace_head(&namespace_id)
            .await
            .map_err(|error| {
                S3Error::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ServiceUnavailable",
                    error.to_string(),
                    resource,
                )
            })?;
        if namespace.descriptor.kind == NamespaceKind::Bucket
            && !bucket_deleted(state, &namespace_id)
                .await
                .map_err(|error| map_api_error(error, resource))?
        {
            aliases.push((alias, namespace_id));
        }
    }
    Ok(aliases)
}

async fn resolve_s3_bucket_namespace(
    state: &AppState,
    bucket: &str,
    resource: &str,
) -> Result<Option<NamespaceId>, S3Error> {
    if let Some(namespace_id) = fast_path::local_bucket_namespace(bucket) {
        return Ok(Some(namespace_id));
    }
    let catalog_namespace_id = ensure_s3_bucket_catalog(state, resource).await?;
    ensure_s3_placement_map(state, &catalog_namespace_id, resource).await?;
    let namespace_id = s3_catalog_lookup(state, &catalog_namespace_id, bucket, resource).await?;
    if let Some(namespace_id) = &namespace_id {
        cache_alias(state, bucket, namespace_id).map_err(|error| map_api_error(error, resource))?;
        cache_fast_path_bucket(state, bucket, namespace_id);
    }
    Ok(namespace_id)
}

struct ResolvedS3Bucket {
    control_namespace_id: NamespaceId,
    partition_map: BucketPartitionMap,
}

struct ResolvedS3Partition {
    partition: BucketPartition,
    namespace: NamespaceState,
}

impl ResolvedS3Partition {
    fn write_fence(&self) -> PartitionFence {
        PartitionFence {
            generation: self.partition.fence_generation,
            cid: self.partition.fence_cid.clone(),
        }
    }
}

async fn bucket_namespace_state(
    state: &AppState,
    bucket: &str,
) -> Result<ResolvedS3Bucket, S3Error> {
    validate_bucket_name(bucket)?;
    let namespace_id = resolve_s3_bucket_namespace(state, bucket, &format!("/{bucket}"))
        .await?
        .ok_or_else(|| S3Error::no_bucket(bucket))?;
    let namespace = namespace_manager(state)
        .map_err(|error| map_api_error(error, &format!("/{bucket}")))?
        .linearizable_namespace_head(&namespace_id)
        .await
        .map_err(|error| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                error.to_string(),
                format!("/{bucket}"),
            )
        })?;
    if namespace.descriptor.kind != NamespaceKind::Bucket {
        return Err(S3Error::no_bucket(bucket));
    }
    let namespace_store = direct_namespace_store(state, &namespace).await;
    if pepper_merkle::get(
        &namespace_store,
        &namespace.current_root_cid,
        S3_BUCKET_DELETED_KEY,
        MerkleLimits::default(),
    )
    .await
    .map_err(|error| S3Error::invalid(error.to_string(), format!("/{bucket}")))?
    .is_some()
    {
        return Err(S3Error::no_bucket(bucket));
    }
    let partition_map =
        load_bucket_partition_map(state, &namespace_id, &format!("/{bucket}")).await?;
    Ok(ResolvedS3Bucket {
        control_namespace_id: namespace_id,
        partition_map,
    })
}

async fn bucket_namespace(state: &AppState, bucket: &str) -> Result<NamespaceId, S3Error> {
    Ok(bucket_namespace_state(state, bucket)
        .await?
        .control_namespace_id)
}

async fn bucket_partition_state(
    state: &AppState,
    bucket: &str,
    key: &[u8],
) -> Result<ResolvedS3Partition, S3Error> {
    let resolved = bucket_namespace_state(state, bucket).await?;
    if resolved.partition_map.state != BucketPartitionMapState::Active {
        return Err(S3Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "SlowDown",
            "bucket metadata is being repartitioned",
            format!("/{bucket}"),
        )
        .with_retry_after(1));
    }
    let partition = resolved.partition_map.partition_for_key(key).clone();
    let namespace = namespace_manager(state)
        .map_err(|error| map_api_error(error, &format!("/{bucket}")))?
        .linearizable_namespace_head(&partition.namespace_id)
        .await
        .map_err(|error| {
            S3Error::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                error.to_string(),
                format!("/{bucket}"),
            )
        })?;
    metrics::S3_PARTITION_ROUTES.fetch_add(1, Ordering::Relaxed);
    Ok(ResolvedS3Partition {
        partition,
        namespace,
    })
}

async fn current_bucket_descriptor(
    state: &AppState,
    bucket: &str,
    key: &[u8],
) -> Result<Option<(pepper_merkle::MerkleValue, BucketObjectDescriptor)>, S3Error> {
    Ok(current_bucket_descriptor_snapshot(state, bucket, key)
        .await?
        .1)
}

async fn current_bucket_descriptor_snapshot(
    state: &AppState,
    bucket: &str,
    key: &[u8],
) -> Result<
    (
        ResolvedS3Partition,
        Option<(pepper_merkle::MerkleValue, BucketObjectDescriptor)>,
    ),
    S3Error,
> {
    let resolved = bucket_partition_state(state, bucket, key).await?;
    let current = current_bucket_descriptor_at_root(state, &resolved.namespace, key)
        .await
        .map_err(|error| map_api_error(error, &format!("/{bucket}")))?;
    Ok((resolved, current))
}

async fn current_bucket_descriptor_at_root(
    state: &AppState,
    namespace: &NamespaceState,
    key: &[u8],
) -> Result<Option<(MerkleValue, BucketObjectDescriptor)>, ApiError> {
    let store = direct_namespace_store(state, namespace).await;
    let value = pepper_merkle::get(
        &store,
        &namespace.current_root_cid,
        key,
        MerkleLimits::default(),
    )
    .await
    .map_err(|error| ApiError::bad_request(error.to_string()))?;
    decode_current_bucket_descriptor(state, value).await
}

async fn current_bucket_descriptor_by_namespace(
    state: &AppState,
    namespace_id: &NamespaceId,
    key: &[u8],
) -> Result<Option<(MerkleValue, BucketObjectDescriptor)>, ApiError> {
    let value = s3_current_value(state, namespace_id, &hex::encode(key)).await?;
    decode_current_bucket_descriptor(state, value).await
}

async fn decode_current_bucket_descriptor(
    state: &AppState,
    value: Option<MerkleValue>,
) -> Result<Option<(MerkleValue, BucketObjectDescriptor)>, ApiError> {
    match value {
        Some(value) => {
            let descriptor = descriptor_from_merkle_value(state, &value).await?;
            Ok(Some((value, descriptor)))
        }
        None => Ok(None),
    }
}

fn validate_object_route(
    bucket: &str,
    key: &str,
    query: &S3ObjectQuery,
    resource: &str,
) -> Result<(), S3Error> {
    validate_object_identity(bucket, key, resource)?;
    if query.version_id.is_some() {
        return Err(S3Error::not_implemented(
            "versionId reads and deletes are not implemented yet",
            resource,
        ));
    }
    if query.upload_id.is_some() || query.uploads.is_some() || query.part_number.is_some() {
        return Err(S3Error::not_implemented(
            "this multipart operation is not valid for the requested HTTP method",
            resource,
        ));
    }
    Ok(())
}

fn validate_object_identity(bucket: &str, key: &str, resource: &str) -> Result<(), S3Error> {
    validate_bucket_name(bucket)?;
    if key.is_empty() || key.len() > 1024 {
        return Err(S3Error::invalid(
            "object keys must contain 1 to 1024 UTF-8 bytes",
            resource,
        ));
    }
    Ok(())
}

fn validate_bucket_name(bucket: &str) -> Result<(), S3Error> {
    let valid_len = (3..=63).contains(&bucket.len());
    let valid_chars = bucket.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
    });
    let valid_edges = bucket
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && bucket
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    let reserved = bucket.starts_with("xn--")
        || bucket.starts_with("sthree-")
        || bucket.starts_with("amzn_s3_demo_")
        || bucket.ends_with("-s3alias")
        || bucket.ends_with("--ol-s3")
        || bucket.ends_with(".mrap")
        || bucket.ends_with("--x-s3")
        || bucket.ends_with("--table-s3");
    let looks_like_ip =
        bucket.split('.').count() == 4 && bucket.split('.').all(|part| part.parse::<u8>().is_ok());
    if !valid_len
        || !valid_chars
        || !valid_edges
        || bucket.contains("..")
        || bucket.contains(".-")
        || bucket.contains("-.")
        || reserved
        || looks_like_ip
    {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidBucketName",
            "The specified bucket is not valid",
            format!("/{bucket}"),
        ));
    }
    Ok(())
}

fn reject_object_query(query: Option<&str>, resource: &str) -> Result<(), S3Error> {
    reject_query_parameters(
        query,
        &[
            "versionId",
            "uploadId",
            "uploads",
            "partNumber",
            "max-parts",
            "part-number-marker",
            "x-id",
        ],
        resource,
    )
}

fn reject_query_parameters(
    query: Option<&str>,
    allowed: &[&str],
    resource: &str,
) -> Result<(), S3Error> {
    let Some(query) = query else {
        return Ok(());
    };
    for field in query.split('&') {
        let name = field.split_once('=').map_or(field, |(name, _)| name);
        let decoded = percent_decode(name)?;
        let decoded = std::str::from_utf8(&decoded)
            .map_err(|_| S3Error::invalid("query parameter names must be UTF-8", resource))?;
        if !allowed.contains(&decoded) {
            return Err(S3Error::not_implemented(
                format!("query parameter or subresource {decoded} is not implemented"),
                resource,
            ));
        }
    }
    Ok(())
}

fn validate_location_constraint(
    state: &AppState,
    body: &[u8],
    resource: &str,
) -> Result<(), S3Error> {
    if body.is_empty() {
        return Ok(());
    }
    let text = std::str::from_utf8(body)
        .map_err(|_| S3Error::invalid("CreateBucket body must be UTF-8 XML", resource))?;
    let start_tag = "<LocationConstraint";
    let Some(tag_start) = text.find(start_tag) else {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "missing LocationConstraint",
            resource,
        ));
    };
    let Some(content_start) = text[tag_start..]
        .find('>')
        .map(|offset| tag_start + offset + 1)
    else {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "invalid LocationConstraint",
            resource,
        ));
    };
    let Some(content_end) = text[content_start..]
        .find("</LocationConstraint>")
        .map(|offset| content_start + offset)
    else {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "invalid LocationConstraint",
            resource,
        ));
    };
    if text[content_start..content_end].trim()
        != state
            .s3
            .as_ref()
            .map(|config| config.region.as_str())
            .unwrap_or_default()
    {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidLocationConstraint",
            "The specified location constraint does not match this endpoint",
            resource,
        ));
    }
    Ok(())
}

fn reject_unsupported_put_headers(headers: &HeaderMap, resource: &str) -> Result<(), S3Error> {
    reject_unsupported_control_headers(headers, resource)?;
    if headers.contains_key("x-amz-copy-source") {
        return Err(S3Error::not_implemented(
            "CopyObject is not implemented",
            resource,
        ));
    }
    if headers
        .get("x-amz-storage-class")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value != "STANDARD")
    {
        return Err(S3Error::not_implemented(
            "only the STANDARD storage class is implemented",
            resource,
        ));
    }
    for name in headers.keys() {
        let name = name.as_str();
        if name.starts_with("x-amz-server-side-encryption")
            || name.starts_with("x-amz-object-lock")
            || name.starts_with("x-amz-grant-")
            || name == "x-amz-tagging"
        {
            return Err(S3Error::not_implemented(
                format!("request header {name} is not implemented"),
                resource,
            ));
        }
    }
    Ok(())
}

fn reject_unsupported_control_headers(headers: &HeaderMap, resource: &str) -> Result<(), S3Error> {
    if let Some(acl) = headers
        .get("x-amz-acl")
        .and_then(|value| value.to_str().ok())
        && acl != "bucket-owner-full-control"
    {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "AccessControlListNotSupported",
            "Pepper buckets do not support ACLs",
            resource,
        ));
    }
    for name in headers.keys() {
        let name = name.as_str();
        if name.starts_with("x-amz-object-lock")
            || name.starts_with("x-amz-grant-")
            || name == "x-amz-bypass-governance-retention"
            || name == "x-amz-bucket-object-lock-enabled"
        {
            return Err(S3Error::not_implemented(
                format!("request header {name} is not implemented"),
                resource,
            ));
        }
    }
    Ok(())
}

fn user_metadata(headers: &HeaderMap, resource: &str) -> Result<BTreeMap<String, String>, S3Error> {
    let mut metadata = BTreeMap::new();
    let mut bytes = 0usize;
    for (name, value) in headers {
        let Some(name) = name.as_str().strip_prefix("x-amz-meta-") else {
            continue;
        };
        if name.is_empty() || name.len() > 128 || metadata.len() >= 256 {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "MetadataTooLarge",
                "object metadata exceeds Pepper limits",
                resource,
            ));
        }
        let value = value
            .to_str()
            .map_err(|_| S3Error::invalid("object metadata must be visible ASCII", resource))?;
        bytes = bytes.saturating_add(name.len() + value.len());
        if bytes > 64 * 1024 {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "MetadataTooLarge",
                "object metadata exceeds Pepper limits",
                resource,
            ));
        }
        metadata.insert(name.to_string(), value.to_string());
    }
    Ok(metadata)
}

fn apply_read_preconditions(
    headers: &HeaderMap,
    descriptor: &BucketObjectDescriptor,
    resource: &str,
) -> Result<(), S3Error> {
    let etag = descriptor_etag(descriptor);
    if let Some(expected) = header_text(headers, header::IF_MATCH)?
        && expected != "*"
        && unquote_etag(expected) != etag
    {
        return Err(precondition_failed(resource));
    }
    if let Some(expected) = header_text(headers, header::IF_NONE_MATCH)?
        && (expected == "*" || unquote_etag(expected) == etag)
    {
        return Err(S3Error::new(
            StatusCode::NOT_MODIFIED,
            "NotModified",
            "Not modified",
            resource,
        ));
    }
    Ok(())
}

fn descriptor_etag(descriptor: &BucketObjectDescriptor) -> String {
    descriptor
        .content_cid
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| descriptor.integrity_id.clone())
}

fn quoted_etag(etag: &str) -> String {
    format!("\"{etag}\"")
}

fn unquote_etag(etag: &str) -> &str {
    etag.trim().trim_matches('"')
}

fn precondition_failed(resource: &str) -> S3Error {
    S3Error::new(
        StatusCode::PRECONDITION_FAILED,
        "PreconditionFailed",
        "At least one of the preconditions you specified did not hold",
        resource,
    )
}

fn common_prefix(key: &[u8], prefix: &[u8], delimiter: Option<&[u8]>) -> Option<Vec<u8>> {
    let delimiter = delimiter.filter(|value| !value.is_empty())?;
    let suffix = key.strip_prefix(prefix)?;
    let position = suffix
        .windows(delimiter.len())
        .position(|window| window == delimiter)?;
    Some(key[..prefix.len() + position + delimiter.len()].to_vec())
}

fn exclusive_start(key: &[u8]) -> Option<Vec<u8>> {
    if key.len() < 1024 {
        let mut start = key.to_vec();
        start.push(0);
        return Some(start);
    }
    let mut start = key.to_vec();
    for index in (0..start.len()).rev() {
        if start[index] != u8::MAX {
            start[index] += 1;
            start.truncate(index + 1);
            return Some(start);
        }
    }
    None
}

fn encode_token(token: &S3ContinuationToken) -> Result<String, S3Error> {
    serde_json::to_vec(token).map(hex::encode).map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            error.to_string(),
            "/",
        )
    })
}

fn decode_token(value: &str) -> Result<S3ContinuationToken, S3Error> {
    if value.len() > 16 * 1024 {
        return Err(S3Error::invalid("continuation token is too large", "/"));
    }
    let bytes = hex::decode(value).map_err(|_| {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "The continuation token is invalid",
            "/",
        )
    })?;
    let token: S3ContinuationToken = serde_json::from_slice(&bytes).map_err(|_| {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "The continuation token is invalid",
            "/",
        )
    })?;
    if token.version != 2 {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "The continuation token version is unsupported",
            "/",
        ));
    }
    Ok(token)
}

fn authorize(
    state: &AppState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<S3AuthContext, S3Error> {
    let resource = uri.path();
    let config = state.s3.as_ref().ok_or_else(|| {
        S3Error::new(
            StatusCode::NOT_FOUND,
            "NoSuchService",
            "The S3-compatible endpoint is disabled",
            resource,
        )
    })?;
    authorize_at(config, method, uri, headers, OffsetDateTime::now_utc())
}

fn authorize_at(
    config: &S3RuntimeConfig,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Result<S3AuthContext, S3Error> {
    let resource = uri.path();
    if !headers.contains_key(header::AUTHORIZATION)
        && has_query_parameter(uri.query(), "X-Amz-Algorithm")
    {
        return authorize_presigned_at(config, method, uri, headers, now);
    }
    if headers.contains_key("x-amz-security-token") {
        return Err(S3Error::not_implemented(
            "temporary session credentials are not implemented",
            resource,
        ));
    }
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            S3Error::new(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                "AWS Signature Version 4 authorization is required",
                resource,
            )
        })?;
    let fields = authorization
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or_else(|| {
            S3Error::new(
                StatusCode::BAD_REQUEST,
                "AuthorizationHeaderMalformed",
                "only AWS4-HMAC-SHA256 is supported",
                resource,
            )
        })?;
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for field in fields.split(',') {
        let (name, value) = field.trim().split_once('=').ok_or_else(|| {
            S3Error::new(
                StatusCode::BAD_REQUEST,
                "AuthorizationHeaderMalformed",
                "invalid Authorization field",
                resource,
            )
        })?;
        match name {
            "Credential" => credential = Some(value),
            "SignedHeaders" => signed_headers = Some(value),
            "Signature" => signature = Some(value),
            _ => {
                return Err(S3Error::new(
                    StatusCode::BAD_REQUEST,
                    "AuthorizationHeaderMalformed",
                    "unknown Authorization field",
                    resource,
                ));
            }
        }
    }
    let credential = credential.ok_or_else(|| {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationHeaderMalformed",
            "Credential is missing",
            resource,
        )
    })?;
    let signed_headers = signed_headers.ok_or_else(|| {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationHeaderMalformed",
            "SignedHeaders is missing",
            resource,
        )
    })?;
    let signature = signature.ok_or_else(|| {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationHeaderMalformed",
            "Signature is missing",
            resource,
        )
    })?;
    let scope = credential.split('/').collect::<Vec<_>>();
    if scope.len() != 5 {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationHeaderMalformed",
            "credential scope is invalid",
            resource,
        ));
    }
    if scope[0] != config.access_key_id {
        return Err(S3Error::new(
            StatusCode::FORBIDDEN,
            "InvalidAccessKeyId",
            "The access key ID does not exist",
            resource,
        ));
    }
    if scope[2] != config.region || scope[3] != "s3" || scope[4] != "aws4_request" {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationHeaderMalformed",
            "credential scope must match the configured region and s3 service",
            resource,
        ));
    }
    let amz_date = header_text(headers, "x-amz-date")?.ok_or_else(|| {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "AccessDenied",
            "x-amz-date is required",
            resource,
        )
    })?;
    if amz_date.len() != 16 || !amz_date.starts_with(scope[1]) {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationHeaderMalformed",
            "credential date does not match x-amz-date",
            resource,
        ));
    }
    let parsed = PrimitiveDateTime::parse(
        amz_date,
        ::time::macros::format_description!("[year][month][day]T[hour][minute][second]Z"),
    )
    .map_err(|_| {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "AccessDenied",
            "x-amz-date is invalid",
            resource,
        )
    })?
    .assume_utc();
    let skew = (now.unix_timestamp() - parsed.unix_timestamp()).unsigned_abs();
    if skew > config.max_clock_skew_seconds {
        return Err(S3Error::new(
            StatusCode::FORBIDDEN,
            "RequestTimeTooSkewed",
            "The difference between the request time and the server time is too large",
            resource,
        ));
    }
    let payload_text = header_text(headers, "x-amz-content-sha256")?.ok_or_else(|| {
        S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "x-amz-content-sha256 is required",
            resource,
        )
    })?;
    let streaming_payload = matches!(
        payload_text,
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" | "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
    );
    let payload_hash = if payload_text == "UNSIGNED-PAYLOAD" {
        PayloadHash::Unsigned
    } else if streaming_payload {
        PayloadHash::Streaming
    } else {
        let bytes = hex::decode(payload_text).map_err(|_| {
            S3Error::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "x-amz-content-sha256 must be a lowercase SHA-256 digest",
                resource,
            )
        })?;
        let digest: [u8; 32] = bytes.try_into().map_err(|_| {
            S3Error::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "x-amz-content-sha256 must be a SHA-256 digest",
                resource,
            )
        })?;
        if hex::encode(digest) != payload_text {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "x-amz-content-sha256 must use canonical lowercase hexadecimal",
                resource,
            ));
        }
        PayloadHash::Sha256(digest)
    };

    let signed = signed_headers.split(';').collect::<Vec<_>>();
    if signed.is_empty()
        || signed.windows(2).any(|pair| pair[0] >= pair[1])
        || !signed.contains(&"host")
        || !signed.contains(&"x-amz-date")
        || signed
            .iter()
            .any(|name| name.is_empty() || name.bytes().any(|byte| byte.is_ascii_uppercase()))
    {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationHeaderMalformed",
            "SignedHeaders must be sorted lowercase names including host and x-amz-date",
            resource,
        ));
    }
    let mut canonical_headers = String::new();
    for name in &signed {
        let values = headers.get_all(*name);
        let normalized = values
            .iter()
            .map(|value| value.to_str().map(normalize_header_value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                S3Error::new(
                    StatusCode::BAD_REQUEST,
                    "AuthorizationHeaderMalformed",
                    "a signed header is not valid text",
                    resource,
                )
            })?;
        if normalized.is_empty() {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "AuthorizationHeaderMalformed",
                format!("signed header {name} is missing"),
                resource,
            ));
        }
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(&normalized.join(","));
        canonical_headers.push('\n');
    }
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_uri(uri.path())?,
        canonical_query(uri.query().unwrap_or_default())?,
        canonical_headers,
        signed_headers,
        payload_text,
    );
    let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let credential_scope = format!("{}/{}/s3/aws4_request", scope[1], config.region);
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_hash}");
    let mut root_key = b"AWS4".to_vec();
    root_key.extend_from_slice(&config.secret_access_key);
    let date_key = hmac_bytes(&root_key, scope[1].as_bytes())?;
    let region_key = hmac_bytes(&date_key, config.region.as_bytes())?;
    let service_key = hmac_bytes(&region_key, b"s3")?;
    let signing_key = hmac_bytes(&service_key, b"aws4_request")?;
    let signature_bytes = hex::decode(signature).map_err(|_| {
        S3Error::new(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "The request signature is invalid",
            resource,
        )
    })?;
    let mut mac = HmacSha256::new_from_slice(&signing_key).map_err(|_| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "failed to construct signing key",
            resource,
        )
    })?;
    mac.update(string_to_sign.as_bytes());
    mac.verify_slice(&signature_bytes).map_err(|_| {
        S3Error::new(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided",
            resource,
        )
    })?;
    let aws_chunked = streaming_payload.then(|| AwsChunkedAuth {
        signing_key,
        prior_signature: signature.to_string(),
        amz_date: amz_date.to_string(),
        credential_scope,
        signed_trailers: payload_text.ends_with("-TRAILER"),
    });
    Ok(S3AuthContext {
        payload_hash,
        aws_chunked,
        request_id: request_id(),
    })
}

fn authorize_presigned_at(
    config: &S3RuntimeConfig,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Result<S3AuthContext, S3Error> {
    let resource = uri.path();
    let query = uri.query().unwrap_or_default();
    let algorithm = query_parameter_value(query, "X-Amz-Algorithm", resource)?
        .ok_or_else(|| S3Error::invalid("X-Amz-Algorithm is required", resource))?;
    if algorithm != "AWS4-HMAC-SHA256" {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationQueryParametersError",
            "only AWS4-HMAC-SHA256 presigning is supported",
            resource,
        ));
    }
    if query_parameter_value(query, "X-Amz-Security-Token", resource)?.is_some()
        || headers.contains_key("x-amz-security-token")
    {
        return Err(S3Error::not_implemented(
            "temporary session credentials are not implemented",
            resource,
        ));
    }
    let credential = query_parameter_value(query, "X-Amz-Credential", resource)?
        .ok_or_else(|| S3Error::invalid("X-Amz-Credential is required", resource))?;
    let amz_date = query_parameter_value(query, "X-Amz-Date", resource)?
        .ok_or_else(|| S3Error::invalid("X-Amz-Date is required", resource))?;
    let expires = query_parameter_value(query, "X-Amz-Expires", resource)?
        .ok_or_else(|| S3Error::invalid("X-Amz-Expires is required", resource))?
        .parse::<u64>()
        .map_err(|_| S3Error::invalid("X-Amz-Expires must be an integer", resource))?;
    if expires > 604_800 {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationQueryParametersError",
            "X-Amz-Expires must not exceed 604800 seconds",
            resource,
        ));
    }
    let signed_headers = query_parameter_value(query, "X-Amz-SignedHeaders", resource)?
        .ok_or_else(|| S3Error::invalid("X-Amz-SignedHeaders is required", resource))?;
    let signature = query_parameter_value(query, "X-Amz-Signature", resource)?
        .ok_or_else(|| S3Error::invalid("X-Amz-Signature is required", resource))?;
    let scope = credential.split('/').collect::<Vec<_>>();
    if scope.len() != 5
        || scope[0] != config.access_key_id
        || scope[2] != config.region
        || scope[3] != "s3"
        || scope[4] != "aws4_request"
    {
        return Err(S3Error::new(
            StatusCode::FORBIDDEN,
            "InvalidAccessKeyId",
            "The credential scope is invalid for this endpoint",
            resource,
        ));
    }
    if amz_date.len() != 16 || !amz_date.starts_with(scope[1]) {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationQueryParametersError",
            "credential date does not match X-Amz-Date",
            resource,
        ));
    }
    let parsed = PrimitiveDateTime::parse(
        &amz_date,
        ::time::macros::format_description!("[year][month][day]T[hour][minute][second]Z"),
    )
    .map_err(|_| S3Error::invalid("X-Amz-Date is invalid", resource))?
    .assume_utc();
    if now.unix_timestamp() < parsed.unix_timestamp() - config.max_clock_skew_seconds as i64 {
        return Err(S3Error::new(
            StatusCode::FORBIDDEN,
            "RequestTimeTooSkewed",
            "The presigned request date is in the future",
            resource,
        ));
    }
    if now.unix_timestamp() > parsed.unix_timestamp() + expires as i64 {
        return Err(S3Error::new(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "Request has expired",
            resource,
        ));
    }
    let signed = signed_headers.split(';').collect::<Vec<_>>();
    if signed.is_empty()
        || signed.windows(2).any(|pair| pair[0] >= pair[1])
        || !signed.contains(&"host")
        || signed
            .iter()
            .any(|name| name.is_empty() || name.bytes().any(|byte| byte.is_ascii_uppercase()))
    {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationQueryParametersError",
            "X-Amz-SignedHeaders must be sorted lowercase names including host",
            resource,
        ));
    }
    let mut canonical_headers = String::new();
    for name in &signed {
        let normalized = headers
            .get_all(*name)
            .iter()
            .map(|value| value.to_str().map(normalize_header_value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| S3Error::invalid("a signed header is not valid text", resource))?;
        if normalized.is_empty() {
            return Err(S3Error::invalid(
                format!("signed header {name} is missing"),
                resource,
            ));
        }
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(&normalized.join(","));
        canonical_headers.push('\n');
    }
    let payload_text = header_text(headers, "x-amz-content-sha256")?.unwrap_or("UNSIGNED-PAYLOAD");
    let payload_hash = if payload_text == "UNSIGNED-PAYLOAD" {
        PayloadHash::Unsigned
    } else {
        let digest: [u8; 32] = hex::decode(payload_text)
            .map_err(|_| S3Error::invalid("invalid payload SHA-256", resource))?
            .try_into()
            .map_err(|_| S3Error::invalid("invalid payload SHA-256", resource))?;
        PayloadHash::Sha256(digest)
    };
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_uri(uri.path())?,
        canonical_query_excluding(query, "X-Amz-Signature")?,
        canonical_headers,
        signed_headers,
        payload_text,
    );
    let credential_scope = format!("{}/{}/s3/aws4_request", scope[1], config.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let mut root_key = b"AWS4".to_vec();
    root_key.extend_from_slice(&config.secret_access_key);
    let date_key = hmac_bytes(&root_key, scope[1].as_bytes())?;
    let region_key = hmac_bytes(&date_key, config.region.as_bytes())?;
    let service_key = hmac_bytes(&region_key, b"s3")?;
    let signing_key = hmac_bytes(&service_key, b"aws4_request")?;
    let signature = hex::decode(signature).map_err(|_| {
        S3Error::new(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "The request signature is invalid",
            resource,
        )
    })?;
    let mut mac = HmacSha256::new_from_slice(&signing_key).map_err(|_| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "failed to construct signing key",
            resource,
        )
    })?;
    mac.update(string_to_sign.as_bytes());
    mac.verify_slice(&signature).map_err(|_| {
        S3Error::new(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided",
            resource,
        )
    })?;
    Ok(S3AuthContext {
        payload_hash,
        aws_chunked: None,
        request_id: request_id(),
    })
}

fn query_parameter_value(
    query: &str,
    parameter: &str,
    resource: &str,
) -> Result<Option<String>, S3Error> {
    let mut found = None;
    for field in query.split('&').filter(|field| !field.is_empty()) {
        let (name, value) = field.split_once('=').unwrap_or((field, ""));
        if percent_decode(name)? == parameter.as_bytes() {
            if found.is_some() {
                return Err(S3Error::invalid(
                    format!("query parameter {parameter} was supplied more than once"),
                    resource,
                ));
            }
            found = Some(
                String::from_utf8(percent_decode(value)?)
                    .map_err(|_| S3Error::invalid("query parameter is not UTF-8", resource))?,
            );
        }
    }
    Ok(found)
}

fn hmac_bytes(key: &[u8], value: &[u8]) -> Result<Vec<u8>, S3Error> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "failed to construct HMAC",
            "/",
        )
    })?;
    mac.update(value);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn canonical_uri(path: &str) -> Result<String, S3Error> {
    Ok(aws_uri_encode(&percent_decode(path)?, false))
}

fn canonical_query(query: &str) -> Result<String, S3Error> {
    canonical_query_excluding(query, "")
}

fn canonical_query_excluding(query: &str, excluded: &str) -> Result<String, S3Error> {
    let mut values = Vec::new();
    if !query.is_empty() {
        for field in query.split('&') {
            let (name, value) = field.split_once('=').unwrap_or((field, ""));
            if !excluded.is_empty() && percent_decode(name)? == excluded.as_bytes() {
                continue;
            }
            values.push((
                aws_uri_encode(&percent_decode(name)?, true),
                aws_uri_encode(&percent_decode(value)?, true),
            ));
        }
    }
    values.sort();
    Ok(values
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&"))
}

fn percent_decode(value: &str) -> Result<Vec<u8>, S3Error> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(S3Error::invalid("invalid percent encoding", value));
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3])
                .map_err(|_| S3Error::invalid("invalid percent encoding", value))?;
            decoded.push(
                u8::from_str_radix(hex, 16)
                    .map_err(|_| S3Error::invalid("invalid percent encoding", value))?,
            );
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Ok(decoded)
}

fn aws_uri_encode(bytes: &[u8], encode_slash: bool) -> String {
    let mut encoded = String::with_capacity(bytes.len());
    for byte in bytes {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (*byte == b'/' && !encode_slash)
        {
            encoded.push(*byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn normalize_header_value(value: &str) -> String {
    value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

fn verify_empty_payload(auth: &S3AuthContext, resource: &str) -> Result<(), S3Error> {
    verify_buffered_payload(auth, &[], resource)
}

fn verify_buffered_payload(
    auth: &S3AuthContext,
    body: &[u8],
    resource: &str,
) -> Result<(), S3Error> {
    if let PayloadHash::Sha256(expected) = auth.payload_hash {
        let actual: [u8; 32] = Sha256::digest(body).into();
        if actual != expected {
            return Err(S3Error::new(
                StatusCode::BAD_REQUEST,
                "XAmzContentSHA256Mismatch",
                "The provided x-amz-content-sha256 does not match the request body",
                resource,
            ));
        }
    }
    if matches!(auth.payload_hash, PayloadHash::Streaming) {
        return Err(S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "aws-chunked framing is valid only for streaming object uploads",
            resource,
        ));
    }
    Ok(())
}

fn header_text<N>(headers: &HeaderMap, name: N) -> Result<Option<&str>, S3Error>
where
    N: axum::http::header::AsHeaderName,
{
    headers
        .get(name)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| S3Error::invalid("request header is not valid text", "/"))
        })
        .transpose()
}

fn insert_header<N>(
    response: &mut Response,
    name: N,
    value: &str,
    resource: &str,
) -> Result<(), S3Error>
where
    N: TryInto<axum::http::HeaderName>,
    N::Error: std::fmt::Display,
{
    let name = name.try_into().map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            error.to_string(),
            resource,
        )
    })?;
    let value = HeaderValue::from_str(value).map_err(|error| {
        S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            error.to_string(),
            resource,
        )
    })?;
    response.headers_mut().insert(name, value);
    Ok(())
}

fn map_api_error(error: ApiError, resource: &str) -> S3Error {
    match error.code {
        ErrorCode::GenerationConflict | ErrorCode::Conflict => S3Error::new(
            StatusCode::CONFLICT,
            "ConditionalRequestConflict",
            error.message,
            resource,
        ),
        ErrorCode::DurabilityNotMet
        | ErrorCode::NamespaceUnavailable
        | ErrorCode::NotLeader
        | ErrorCode::StaleMembership
        | ErrorCode::Unavailable
        | ErrorCode::UpstreamFailure => S3Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            error.message,
            resource,
        ),
        ErrorCode::PayloadTooLarge | ErrorCode::CapacityExceeded => {
            S3Error::new(error.status, "EntityTooLarge", error.message, resource)
        }
        ErrorCode::RateLimited => S3Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "SlowDown",
            error.message,
            resource,
        ),
        ErrorCode::NotFound => {
            S3Error::new(StatusCode::NOT_FOUND, "NoSuchKey", error.message, resource)
        }
        ErrorCode::Internal => S3Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            error.message,
            resource,
        ),
        _ => S3Error::new(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            error.message,
            resource,
        ),
    }
}

fn xml_response(status: StatusCode, xml: String, request_id: &str) -> Response {
    xml_bytes_response(status, Bytes::from(xml), request_id)
}

fn xml_bytes_response(status: StatusCode, xml: Bytes, request_id: &str) -> Response {
    let mut response = (status, xml).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert("x-amz-request-id", value);
    }
    response
}

fn add_s3_headers(response: &mut Response, request_id: &str, state: Option<&AppState>) {
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert("x-amz-request-id", value);
    }
    if let Some(region) = state
        .and_then(|state| state.s3.as_ref())
        .map(|config| config.region.as_str())
        .and_then(|region| HeaderValue::from_str(region).ok())
    {
        response.headers_mut().insert("x-amz-bucket-region", region);
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn iso_timestamp(timestamp: i64) -> String {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn http_timestamp(timestamp: i64) -> String {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .format(&::time::format_description::well_known::Rfc2822)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".to_string())
        .replace("+0000", "GMT")
}

fn request_id() -> String {
    let prefix = S3_REQUEST_PREFIX.get_or_init(|| {
        let mut nonce = [0u8; 16];
        if getrandom::fill(&mut nonce).is_ok() {
            return hex::encode(nonce);
        }
        let started_at_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let fallback = format!("{}:{started_at_nanos}", std::process::id());
        hex::encode(&blake3::hash(fallback.as_bytes()).as_bytes()[..16])
    });
    format!(
        "pepper-s3-{prefix}-{:016x}",
        S3_REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_request_ids_are_process_scoped_monotonic_and_bounded() {
        let first = request_id();
        let second = request_id();
        assert_ne!(first, second);
        assert_eq!(
            first.rsplit_once('-').unwrap().0,
            second.rsplit_once('-').unwrap().0
        );
        let limit = pepper_namespace::NamespaceLimits::default().max_request_id_bytes;
        assert!(first.len() <= limit);
        assert!(second.len() <= limit);
    }

    fn list_cache_key(bucket: &str) -> S3ListCacheKey {
        S3ListCacheKey {
            bucket: bucket.to_string(),
            root: "root".to_string(),
            prefix: Vec::new(),
            delimiter: None,
            start_after: None,
            continuation_token: None,
            max_keys: 1000,
            encoding_url: false,
            fetch_owner: false,
        }
    }

    #[tokio::test]
    async fn list_cache_coalesces_and_bounds_immutable_results() {
        let cache = S3ListCache::default();
        let key = list_cache_key("bucket");
        let first_flight = cache.flight(&key).await;
        let second_flight = cache.flight(&key).await;
        assert!(Arc::ptr_eq(&first_flight, &second_flight));

        cache
            .insert(key.clone(), Bytes::from_static(b"<result/>"))
            .await;
        assert_eq!(cache.get(&key).await.unwrap(), "<result/>");

        for index in 0..=S3_LIST_CACHE_MAX_ENTRIES {
            cache
                .insert(
                    list_cache_key(&format!("bucket-{index}")),
                    Bytes::from_static(b"x"),
                )
                .await;
        }
        assert!(cache.get(&key).await.is_none());
        assert_eq!(
            cache.state.lock().await.entries.len(),
            S3_LIST_CACHE_MAX_ENTRIES
        );
    }

    #[test]
    fn retryable_s3_errors_include_retry_after() {
        let response = S3Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "SlowDown",
            "bounded queue is full",
            "/bucket/key",
        )
        .into_response();
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "1");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let response = S3Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "SlowDown",
            "bounded queue is full",
            "/bucket/key",
        )
        .with_retry_after(7)
        .into_response();
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "7");
    }

    #[test]
    fn canonical_query_sorts_and_encodes_values() {
        assert_eq!(
            canonical_query("prefix=some%20prefix&list-type=2&delimiter=%2F").unwrap(),
            "delimiter=%2F&list-type=2&prefix=some%20prefix"
        );
        assert_eq!(
            canonical_query_excluding("X-Amz-Signature=deadbeef&a=b", "X-Amz-Signature").unwrap(),
            "a=b"
        );
    }

    #[test]
    fn multipart_listing_hides_internal_completion_records() {
        let mut upload = S3MultipartUpload {
            upload_id: "upload-1".to_string(),
            bucket: "example-bucket".to_string(),
            bucket_namespace_id: "bucket-namespace".to_string(),
            control_namespace_id: "control-namespace".to_string(),
            key: "prefix/object.bin".to_string(),
            content_type: "application/octet-stream".to_string(),
            metadata: BTreeMap::new(),
            initiated_at_unix_seconds: 0,
            status: "open".to_string(),
            completion_hash: None,
            final_content_cid: None,
            final_content_placement: None,
        };
        assert!(multipart_upload_is_listed(
            &upload,
            "example-bucket",
            "prefix/"
        ));
        upload.status = "completing".to_string();
        assert!(!multipart_upload_is_listed(
            &upload,
            "example-bucket",
            "prefix/"
        ));
    }

    #[test]
    fn parses_all_supported_single_byte_ranges() {
        assert_eq!(
            parse_byte_range("bytes=2-4", 10, "/").unwrap(),
            S3ByteRange { start: 2, end: 4 }
        );
        assert_eq!(
            parse_byte_range("bytes=8-", 10, "/").unwrap(),
            S3ByteRange { start: 8, end: 9 }
        );
        assert_eq!(
            parse_byte_range("bytes=-3", 10, "/").unwrap(),
            S3ByteRange { start: 7, end: 9 }
        );
        assert_eq!(
            parse_byte_range("bytes=8-99", 10, "/").unwrap(),
            S3ByteRange { start: 8, end: 9 }
        );
        assert_eq!(
            parse_byte_range("bytes=10-", 10, "/").unwrap_err().code,
            "InvalidRange"
        );
    }

    #[test]
    fn object_range_selects_only_overlapping_manifest_chunks() {
        const CHUNK_SIZE: u64 = 4 * 1024 * 1024;
        let chunks = (0..800u64)
            .map(|index| ObjectChunk {
                offset: index * CHUNK_SIZE,
                size: CHUNK_SIZE,
                cid: Cid::new(CODEC_RAW, &index.to_le_bytes()),
                placement: PlacementReference::replicated(
                    1,
                    Cid::new(CODEC_RAW, &index.to_le_bytes()),
                    3,
                ),
            })
            .collect::<Vec<_>>();
        let manifest = ObjectManifest::new(800 * CHUNK_SIZE, CHUNK_SIZE, chunks);
        let range = S3ByteRange {
            start: manifest.size - 256 * 1024,
            end: manifest.size - 1,
        };

        let selected = object_manifest_range_chunks(&manifest, range).unwrap();

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].chunk.offset, 799 * CHUNK_SIZE);
        assert_eq!(selected[0].start, (CHUNK_SIZE - 256 * 1024) as usize);
        assert_eq!(selected[0].end, CHUNK_SIZE as usize);
    }

    #[test]
    fn recognizes_aws_virtual_host_bucket_names() {
        assert_eq!(
            virtual_host_bucket("photos.s3.us-east-1.example.test:9000").as_deref(),
            Some("photos")
        );
        assert_eq!(
            virtual_host_bucket("archive.s3-us-east-1.example.test").as_deref(),
            Some("archive")
        );
        assert!(virtual_host_bucket("node1:9000").is_none());
    }

    #[test]
    fn validates_standard_s3_checksum_headers() {
        let body = b"pepper";
        let mut checksums = S3BodyChecksums::default();
        checksums.update(body);
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-md5",
            HeaderValue::from_str(&BASE64.encode(Md5::digest(body))).unwrap(),
        );
        headers.insert(
            "x-amz-checksum-sha256",
            HeaderValue::from_str(&BASE64.encode(Sha256::digest(body))).unwrap(),
        );
        assert!(verify_request_checksums(&headers, &checksums, "/").is_ok());
        headers.insert(
            "content-md5",
            HeaderValue::from_static("AAAAAAAAAAAAAAAAAAAAAA=="),
        );
        assert_eq!(
            verify_request_checksums(&headers, &checksums, "/")
                .unwrap_err()
                .code,
            "BadDigest"
        );
    }

    #[tokio::test]
    async fn decodes_and_verifies_aws_chunked_payloads() {
        let signing_key = b"aws-chunked-test-key".to_vec();
        let mut prior = "0".repeat(64);
        let amz_date = "20260101T000000Z";
        let scope = "20260101/us-east-1/s3/aws4_request";
        let sign = |prior: &str, bytes: &[u8]| {
            let string_to_sign = format!(
                "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{prior}\n{}\n{}",
                hex::encode(Sha256::digest([])),
                hex::encode(Sha256::digest(bytes)),
            );
            hex::encode(hmac_bytes(&signing_key, string_to_sign.as_bytes()).unwrap())
        };
        let data_signature = sign(&prior, b"pepper");
        prior.clone_from(&data_signature);
        let final_signature = sign(&prior, b"");
        let encoded = format!(
            "6;chunk-signature={data_signature}\r\npepper\r\n0;chunk-signature={final_signature}\r\n\r\n"
        );
        let auth = AwsChunkedAuth {
            signing_key,
            prior_signature: "0".repeat(64),
            amz_date: amz_date.to_string(),
            credential_scope: scope.to_string(),
            signed_trailers: false,
        };
        let trailers = Arc::new(Mutex::new(BTreeMap::new()));
        let mut stream = aws_chunked_body(Body::from(encoded), auth, trailers).into_data_stream();
        let mut decoded = Vec::new();
        while let Some(chunk) = stream.next().await {
            decoded.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(decoded, b"pepper");
    }

    #[test]
    fn accepts_aws_sigv4_get_object_test_vector() {
        let config = S3RuntimeConfig {
            region: "us-east-1".to_string(),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_vec(),
            max_clock_skew_seconds: 900,
            bucket_partitions: DEFAULT_BUCKET_PARTITIONS,
            bucket_create_lock: Arc::new(tokio::sync::Mutex::new(())),
            bucket_catalog_lock: Arc::new(tokio::sync::Mutex::new(())),
            placement_map_lock: Arc::new(tokio::sync::Mutex::new(())),
            multipart_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        let uri = Uri::from_static("/test.txt");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            HeaderValue::from_static("examplebucket.s3.amazonaws.com"),
        );
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=0-9"));
        headers.insert(
            "x-amz-content-sha256",
            HeaderValue::from_static(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
        );
        headers.insert("x-amz-date", HeaderValue::from_static("20130524T000000Z"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static(
                "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
            ),
        );

        let auth = authorize_at(
            &config,
            &Method::GET,
            &uri,
            &headers,
            ::time::macros::datetime!(2013-05-24 0:00 UTC),
        )
        .unwrap();
        assert!(matches!(auth.payload_hash, PayloadHash::Sha256(_)));
    }

    #[test]
    fn accepts_a_valid_presigned_sigv4_request() {
        let config = S3RuntimeConfig {
            region: "us-east-1".to_string(),
            access_key_id: "pepper-test".to_string(),
            secret_access_key: b"pepper-secret".to_vec(),
            max_clock_skew_seconds: 900,
            bucket_partitions: DEFAULT_BUCKET_PARTITIONS,
            bucket_create_lock: Arc::new(tokio::sync::Mutex::new(())),
            bucket_catalog_lock: Arc::new(tokio::sync::Mutex::new(())),
            placement_map_lock: Arc::new(tokio::sync::Mutex::new(())),
            multipart_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        let unsigned_query = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=pepper-test%2F20260101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260101T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host";
        let unsigned_uri: Uri = format!("/bucket/key?{unsigned_query}").parse().unwrap();
        let canonical_request = format!(
            "GET\n/bucket/key\n{}\nhost:example.test\n\nhost\nUNSIGNED-PAYLOAD",
            canonical_query(unsigned_query).unwrap()
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n20260101T000000Z\n20260101/us-east-1/s3/aws4_request\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let mut root_key = b"AWS4".to_vec();
        root_key.extend_from_slice(&config.secret_access_key);
        let date = hmac_bytes(&root_key, b"20260101").unwrap();
        let region = hmac_bytes(&date, b"us-east-1").unwrap();
        let service = hmac_bytes(&region, b"s3").unwrap();
        let signing = hmac_bytes(&service, b"aws4_request").unwrap();
        let signature = hex::encode(hmac_bytes(&signing, string_to_sign.as_bytes()).unwrap());
        let uri: Uri = format!("{}&X-Amz-Signature={signature}", unsigned_uri)
            .parse()
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("example.test"));
        assert!(
            authorize_at(
                &config,
                &Method::GET,
                &uri,
                &headers,
                ::time::macros::datetime!(2026-01-01 0:01 UTC),
            )
            .is_ok()
        );
    }

    #[test]
    fn continuation_tokens_are_canonical_and_root_bound() {
        let token = S3ContinuationToken {
            version: 2,
            control_namespace_id: "namespace".to_string(),
            bucket_epoch: 7,
            barrier_id: "ab".repeat(32),
            prefix_hex: "61".to_string(),
            delimiter_hex: Some("2f".to_string()),
            last_key_hex: "6162".to_string(),
            skip_common_prefix_hex: None,
        };
        let encoded = encode_token(&token).unwrap();
        let decoded = decode_token(&encoded).unwrap();
        assert_eq!(decoded.control_namespace_id, token.control_namespace_id);
        assert_eq!(decoded.barrier_id, token.barrier_id);
        assert_eq!(decoded.last_key_hex, token.last_key_hex);
    }

    #[test]
    fn bucket_names_follow_s3_dns_rules() {
        assert!(validate_bucket_name("pepper-bucket-1").is_ok());
        assert!(validate_bucket_name("Bad_Bucket").is_err());
        assert!(validate_bucket_name("127.0.0.1").is_err());
        assert!(validate_bucket_name("a..b").is_err());
    }

    #[test]
    fn exclusive_scan_start_preserves_prefix_ordering() {
        assert_eq!(exclusive_start(b"a"), Some(vec![b'a', 0]));
        assert!(exclusive_start(&vec![u8::MAX; 1024]).is_none());
    }

    #[test]
    fn unsupported_object_subresources_never_fall_through() {
        assert!(reject_object_query(Some("x-id=PutObject"), "/bucket/key").is_ok());
        let error = reject_object_query(Some("acl"), "/bucket/key").unwrap_err();
        assert_eq!(error.status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(error.code, "NotImplemented");
    }

    #[test]
    fn multipart_completion_requires_nonfinal_parts_to_be_five_mib() {
        let part = |part_number, size| {
            let content_cid = Cid::new(CODEC_RAW, format!("part-{part_number}").as_bytes());
            S3MultipartPart {
                upload_id: "upload".to_string(),
                part_number,
                content_cid: content_cid.clone(),
                content_placement: PlacementReference::replicated(1, content_cid, 3),
                size,
                etag: format!("etag-{part_number}"),
                durability_status: "durable".to_string(),
                uploaded_at_unix_seconds: 0,
                durability: Vec::new(),
            }
        };
        let final_part = part(2, 1);

        let error = validate_multipart_part_sizes(
            &[part(1, S3_MIN_MULTIPART_PART_BYTES - 1), final_part.clone()],
            "/bucket/key",
        )
        .unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "EntityTooSmall");

        assert!(
            validate_multipart_part_sizes(
                &[part(1, S3_MIN_MULTIPART_PART_BYTES), final_part],
                "/bucket/key",
            )
            .is_ok()
        );
        assert!(validate_multipart_part_sizes(&[part(1, 1)], "/bucket/key").is_ok());
    }

    #[test]
    fn multipart_upload_ids_route_to_their_control_namespace() {
        let namespace_id = NamespaceId::new(Cid::new(
            pepper_types::CODEC_NAMESPACE_DESCRIPTOR,
            b"multipart-control",
        ))
        .unwrap();
        let upload_id = next_multipart_upload_id(&namespace_id);
        assert_eq!(
            control_namespace_from_upload_id(&upload_id),
            Some(namespace_id)
        );
        assert!(control_namespace_from_upload_id("local-only-id").is_none());
    }
}
