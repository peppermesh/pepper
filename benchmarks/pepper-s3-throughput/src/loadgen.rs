// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use clap::{Args, ValueEnum};
use futures_util::{StreamExt, stream};
use hmac::{Hmac, Mac};
use reqwest::{Client, Method, StatusCode, header};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    error::Error as _,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339, macros::format_description};
use tokio::task::JoinSet;

const STREAM_CHUNK_BYTES: usize = 1024 * 1024;
const MULTIPART_PART_BYTES: u64 = 256 * 1024 * 1024;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    S3,
    Raw,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    Put,
    MultipartPut,
    Get,
    RangeGet,
    Head,
    List,
    Mixed,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PayloadProfile {
    Incompressible,
    #[value(name = "compressible-2x")]
    Compressible2x,
    #[value(name = "compressible-4x")]
    Compressible4x,
    #[value(name = "compressible-10x")]
    Compressible10x,
    #[value(name = "compressible-20x")]
    Compressible20x,
}

impl PayloadProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Incompressible => "incompressible",
            Self::Compressible2x => "compressible-2x",
            Self::Compressible4x => "compressible-4x",
            Self::Compressible10x => "compressible-10x",
            Self::Compressible20x => "compressible-20x",
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct LoadgenArgs {
    #[arg(long, value_enum)]
    pub backend: BackendKind,
    #[arg(long, value_enum)]
    pub operation: Operation,
    #[arg(long)]
    pub size: u64,
    #[arg(long)]
    pub concurrency: usize,
    #[arg(long, default_value_t = 60)]
    pub duration: u64,
    #[arg(long)]
    pub allow_short: bool,
    #[arg(long)]
    pub object_count: u64,
    #[arg(long, default_value_t = 1024 * 1024)]
    pub range_bytes: u64,
    #[arg(long)]
    pub prepare: bool,
    #[arg(long)]
    pub prepare_only: bool,
    #[arg(long)]
    pub output: Option<PathBuf>,
    #[arg(long, value_delimiter = ',', default_value = "http://127.0.0.1:29080")]
    pub endpoints: Vec<String>,
    #[arg(long, default_value = "pepper-s3-throughput")]
    pub bucket: String,
    #[arg(long, env = "AWS_ACCESS_KEY_ID", default_value = "pepper-benchmark")]
    pub access_key: String,
    #[arg(
        long,
        env = "AWS_SECRET_ACCESS_KEY",
        default_value = "pepper-benchmark-secret-v1"
    )]
    pub secret_key: String,
    #[arg(long, default_value = "us-east-1")]
    pub region: String,
    #[arg(long, default_value_t = 300)]
    pub timeout: u64,
    /// Maximum time an operation already in flight at the cell deadline may
    /// take to finish before it is cancelled.
    #[arg(long, default_value_t = 60)]
    pub drain_timeout: u64,
    /// Maximum retries for transient S3 transport and service failures.
    #[arg(long, default_value_t = 3)]
    pub retries: u32,
    /// Raw-backend data root; required when --backend raw is selected.
    #[arg(long)]
    pub raw_root: Option<PathBuf>,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub raw_fsync: bool,
    #[arg(long)]
    pub quiet: bool,
    #[arg(long, value_enum, default_value = "incompressible")]
    pub payload_profile: PayloadProfile,
}

#[derive(Debug, Clone)]
struct RequestResult {
    success: bool,
    status: u16,
    transferred: u64,
    retries: u64,
    retry_after: Option<Duration>,
    error: Option<String>,
    attempt_errors: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct GeneratedRequest {
    size: u64,
    range_bytes: u64,
    seed: u64,
    payload_profile: PayloadProfile,
}

#[derive(Debug, Clone, Copy)]
struct WorkerConfig {
    operation: Operation,
    request: GeneratedRequest,
    object_count: u64,
    deadline: Instant,
    drain_deadline: Instant,
}

#[derive(Clone)]
enum Backend {
    S3(Arc<S3Backend>),
    Raw(Arc<RawBackend>),
}

#[derive(Debug)]
struct S3Backend {
    client: Client,
    endpoints: Vec<String>,
    bucket: String,
    access_key: String,
    secret_key: String,
    region: String,
    retries: u32,
    route_counter: AtomicU64,
}

#[derive(Debug)]
struct RawBackend {
    root: PathBuf,
    fsync: bool,
}

#[derive(Debug, Default)]
struct WorkerResult {
    attempts: u64,
    retries: u64,
    failures: u64,
    logical_bytes: u64,
    latencies_micros: Vec<u64>,
    statuses: BTreeMap<u16, u64>,
    errors: BTreeMap<String, u64>,
    final_errors: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    started_at: String,
    config: ReportConfig,
    results: ReportResults,
}

#[derive(Debug, Serialize)]
struct ReportConfig {
    backend: BackendKind,
    operation: Operation,
    object_size_bytes: u64,
    concurrency: usize,
    requested_duration_seconds: u64,
    drain_timeout_seconds: u64,
    object_count: u64,
    range_bytes: u64,
    payload_profile: PayloadProfile,
    max_retries: u32,
    endpoints: Vec<String>,
    raw_fsync: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ReportResults {
    elapsed_seconds: f64,
    attempts: u64,
    successes: u64,
    failures: u64,
    retries: u64,
    failure_rate: f64,
    logical_bytes: u64,
    logical_mb_per_second: f64,
    operations_per_second: f64,
    latency_ms: LatencyReport,
    http_status_counts: BTreeMap<u16, u64>,
    error_counts: BTreeMap<String, u64>,
    final_error_counts: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize)]
struct LatencyReport {
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
}

impl Backend {
    async fn ensure_bucket(&self) -> Result<()> {
        match self {
            Self::S3(backend) => backend.ensure_bucket().await,
            Self::Raw(backend) => {
                fs::create_dir_all(&backend.root)
                    .with_context(|| format!("failed to create {}", backend.root.display()))?;
                Ok(())
            }
        }
    }

    async fn request(
        &self,
        operation: Operation,
        key: String,
        size: u64,
        range_bytes: u64,
        seed: u64,
        payload_profile: PayloadProfile,
    ) -> RequestResult {
        match self {
            Self::S3(backend) => {
                backend
                    .request(operation, &key, size, range_bytes, seed, payload_profile)
                    .await
            }
            Self::Raw(backend) => {
                backend
                    .request(operation, key, size, range_bytes, seed, payload_profile)
                    .await
            }
        }
    }
}

impl S3Backend {
    fn endpoint(&self) -> &str {
        let index = self.route_counter.fetch_add(1, Ordering::Relaxed) as usize;
        &self.endpoints[index % self.endpoints.len()]
    }

    async fn ensure_bucket(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let endpoint = self.endpoint();
            let path = format!("/{}", aws_encode(&self.bucket, false));
            let headers = signed_headers(
                Method::PUT,
                endpoint,
                &path,
                "",
                &self.access_key,
                &self.secret_key,
                &self.region,
            );
            let response = self
                .client
                .put(format!("{endpoint}{path}"))
                .headers(headers)
                .send()
                .await;
            let status = response
                .as_ref()
                .map_or(0, |response| response.status().as_u16());
            if response.is_ok_and(|response| response.status().is_success())
                || status == StatusCode::CONFLICT.as_u16()
            {
                break;
            }
            if !matches!(status, 0 | 503) || Instant::now() >= deadline {
                bail!("CreateBucket failed with HTTP {status}");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // A matrix cell may route its first request to any configured gateway.
        // Do not count cluster bootstrap/catalog catch-up as data-path latency.
        // This is also an explicit correctness gate for the replicated bucket
        // catalog: every selected healthy gateway must resolve the bucket.
        loop {
            let mut pending = Vec::new();
            for endpoint in &self.endpoints {
                let path = format!("/{}", aws_encode(&self.bucket, false));
                let headers = signed_headers(
                    Method::HEAD,
                    endpoint,
                    &path,
                    "",
                    &self.access_key,
                    &self.secret_key,
                    &self.region,
                );
                let status = self
                    .client
                    .head(format!("{endpoint}{path}"))
                    .headers(headers)
                    .send()
                    .await
                    .map_or(0, |response| response.status().as_u16());
                if status != StatusCode::OK.as_u16() {
                    pending.push(format!("{endpoint}=HTTP {status}"));
                }
            }
            if pending.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "bucket was not visible through every selected gateway before the deadline: {}",
                    pending.join(", ")
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn request(
        &self,
        operation: Operation,
        key: &str,
        size: u64,
        range_bytes: u64,
        seed: u64,
        payload_profile: PayloadProfile,
    ) -> RequestResult {
        let mut retries = 0u64;
        let mut attempt_errors = Vec::new();
        loop {
            let mut result = self
                .request_once(operation, key, size, range_bytes, seed, payload_profile)
                .await;
            result.retries = retries;
            if !result.success {
                attempt_errors.push(result.error.clone().unwrap_or_else(|| {
                    format!("HTTP {} without a retained error body", result.status)
                }));
            }
            if result.success || retries >= u64::from(self.retries) || !retryable_s3_result(&result)
            {
                result.attempt_errors = attempt_errors;
                return result;
            }
            let delay = result.retry_after.unwrap_or_else(|| {
                Duration::from_millis(25u64.saturating_mul(1u64 << retries.min(6)))
            });
            let jitter =
                Duration::from_millis(seed.wrapping_add(retries.wrapping_mul(0x9e37_79b9)) % 251);
            tokio::time::sleep(delay.saturating_add(jitter)).await;
            retries += 1;
        }
    }

    async fn request_once(
        &self,
        operation: Operation,
        key: &str,
        size: u64,
        range_bytes: u64,
        seed: u64,
        payload_profile: PayloadProfile,
    ) -> RequestResult {
        if operation == Operation::MultipartPut {
            return self.multipart_put(key, size, seed, payload_profile).await;
        }
        let endpoint = self.endpoint();
        let mut path = format!("/{}", aws_encode(&self.bucket, false));
        if !key.is_empty() {
            path.push('/');
            path.push_str(&aws_encode(key, true));
        }
        let (method, query) = match operation {
            Operation::Put => (Method::PUT, ""),
            Operation::Get | Operation::RangeGet => (Method::GET, ""),
            Operation::Head => (Method::HEAD, ""),
            Operation::List => (Method::GET, "list-type=2&max-keys=1000"),
            Operation::MultipartPut | Operation::Mixed => {
                unreachable!("multipart and mixed are resolved before single-request dispatch")
            }
        };
        let target = if query.is_empty() {
            format!("{endpoint}{path}")
        } else {
            format!("{endpoint}{path}?{query}")
        };
        let mut request = self
            .client
            .request(method.clone(), target)
            .headers(signed_headers(
                method.clone(),
                endpoint,
                &path,
                query,
                &self.access_key,
                &self.secret_key,
                &self.region,
            ));
        if operation == Operation::Put {
            request = request
                .header(header::EXPECT, "100-continue")
                .header(header::CONTENT_LENGTH, size)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(generated_body(size, seed, payload_profile));
        }
        if operation == Operation::RangeGet {
            let requested = range_bytes.min(size);
            request = request.header(
                header::RANGE,
                format!("bytes=0-{}", requested.saturating_sub(1)),
            );
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                return RequestResult {
                    success: false,
                    status: 0,
                    transferred: 0,
                    retries: 0,
                    retry_after: None,
                    error: Some(reqwest_error_summary("request", &error)),
                    attempt_errors: Vec::new(),
                };
            }
        };
        let status = response.status();
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs);
        let mut transferred = 0u64;
        let mut error_body = Vec::new();
        let mut body = response.bytes_stream();
        while let Some(chunk) = body.next().await {
            match chunk {
                Ok(chunk) => {
                    transferred = transferred.saturating_add(chunk.len() as u64);
                    if !status.is_success() && error_body.len() < 4096 {
                        let take = (4096 - error_body.len()).min(chunk.len());
                        error_body.extend_from_slice(&chunk[..take]);
                    }
                }
                Err(error) => {
                    return RequestResult {
                        success: false,
                        status: status.as_u16(),
                        transferred,
                        retries: 0,
                        retry_after,
                        error: Some(reqwest_error_summary("response_body", &error)),
                        attempt_errors: Vec::new(),
                    };
                }
            }
        }
        RequestResult {
            success: status.is_success(),
            status: status.as_u16(),
            transferred,
            retries: 0,
            retry_after,
            error: (!status.is_success()).then(|| s3_error_summary(&error_body)),
            attempt_errors: Vec::new(),
        }
    }

    async fn multipart_put(
        &self,
        key: &str,
        size: u64,
        seed: u64,
        payload_profile: PayloadProfile,
    ) -> RequestResult {
        let endpoint = self.endpoint();
        let path = format!(
            "/{}/{}",
            aws_encode(&self.bucket, false),
            aws_encode(key, true)
        );
        let initiate_query = "uploads=";
        let initiate = self
            .client
            .post(format!("{endpoint}{path}?{initiate_query}"))
            .headers(signed_headers(
                Method::POST,
                endpoint,
                &path,
                initiate_query,
                &self.access_key,
                &self.secret_key,
                &self.region,
            ))
            .send()
            .await;
        let Ok(initiate) = initiate else {
            return failed_request(0);
        };
        let initiate_status = initiate.status();
        let Ok(initiate_body) = initiate.text().await else {
            return failed_request(initiate_status.as_u16());
        };
        let Some(upload_id) = xml_element(&initiate_body, "UploadId") else {
            return failed_request(initiate_status.as_u16());
        };
        if !initiate_status.is_success() {
            return failed_request(initiate_status.as_u16());
        }

        let mut parts = Vec::new();
        let mut offset = 0u64;
        let mut part_number = 1u64;
        while offset < size {
            let part_size = (size - offset).min(MULTIPART_PART_BYTES);
            let query = format!(
                "partNumber={part_number}&uploadId={}",
                aws_encode(&upload_id, false)
            );
            let request = self
                .client
                .put(format!("{endpoint}{path}?{query}"))
                .headers(signed_headers(
                    Method::PUT,
                    endpoint,
                    &path,
                    &query,
                    &self.access_key,
                    &self.secret_key,
                    &self.region,
                ))
                .header(header::CONTENT_LENGTH, part_size)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(generated_body_at(
                    part_size,
                    seed,
                    offset / STREAM_CHUNK_BYTES as u64,
                    payload_profile,
                ))
                .send()
                .await;
            let Ok(response) = request else {
                self.abort_multipart(endpoint, &path, &upload_id).await;
                return failed_request(0);
            };
            let status = response.status();
            let etag = response
                .headers()
                .get(header::ETAG)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            if response.bytes().await.is_err() || !status.is_success() || etag.is_none() {
                self.abort_multipart(endpoint, &path, &upload_id).await;
                return failed_request(status.as_u16());
            }
            parts.push((part_number, etag.expect("successful part has an ETag")));
            offset += part_size;
            part_number += 1;
        }

        let complete_body = format!(
            "<CompleteMultipartUpload>{}</CompleteMultipartUpload>",
            parts
                .iter()
                .map(|(number, etag)| format!(
                    "<Part><PartNumber>{number}</PartNumber><ETag>{etag}</ETag></Part>"
                ))
                .collect::<String>()
        );
        let query = format!("uploadId={}", aws_encode(&upload_id, false));
        let complete = self
            .client
            .post(format!("{endpoint}{path}?{query}"))
            .headers(signed_headers(
                Method::POST,
                endpoint,
                &path,
                &query,
                &self.access_key,
                &self.secret_key,
                &self.region,
            ))
            .header(header::CONTENT_TYPE, "application/xml")
            .body(complete_body)
            .send()
            .await;
        let Ok(complete) = complete else {
            self.abort_multipart(endpoint, &path, &upload_id).await;
            return failed_request(0);
        };
        let status = complete.status();
        let body_ok = complete.bytes().await.is_ok();
        if status.is_success() && body_ok {
            RequestResult {
                success: true,
                status: status.as_u16(),
                transferred: size,
                retries: 0,
                retry_after: None,
                error: None,
                attempt_errors: Vec::new(),
            }
        } else {
            self.abort_multipart(endpoint, &path, &upload_id).await;
            failed_request(status.as_u16())
        }
    }

    async fn abort_multipart(&self, endpoint: &str, path: &str, upload_id: &str) {
        let query = format!("uploadId={}", aws_encode(upload_id, false));
        let _ = self
            .client
            .delete(format!("{endpoint}{path}?{query}"))
            .headers(signed_headers(
                Method::DELETE,
                endpoint,
                path,
                &query,
                &self.access_key,
                &self.secret_key,
                &self.region,
            ))
            .send()
            .await;
    }
}

fn failed_request(status: u16) -> RequestResult {
    RequestResult {
        success: false,
        status,
        transferred: 0,
        retries: 0,
        retry_after: None,
        error: None,
        attempt_errors: Vec::new(),
    }
}

fn s3_error_summary(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let code = xml_element(&text, "Code");
    let message = xml_element(&text, "Message");
    let summary = match (code, message) {
        (Some(code), Some(message)) => format!("{code}: {message}"),
        (Some(code), None) => code,
        _ => text.split_whitespace().collect::<Vec<_>>().join(" "),
    };
    if summary.is_empty() {
        "empty error response".to_string()
    } else {
        summary.chars().take(512).collect()
    }
}

fn reqwest_error_summary(phase: &str, error: &reqwest::Error) -> String {
    let kind = if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() {
        "body"
    } else if error.is_decode() {
        "decode"
    } else if error.is_request() {
        "request"
    } else {
        "transport"
    };
    let mut causes = Vec::new();
    let mut source = error.source();
    while let Some(cause) = source {
        causes.push(cause.to_string());
        source = cause.source();
    }
    let detail = if causes.is_empty() {
        error.to_string()
    } else {
        causes.join(": ")
    };
    format!("{phase} {kind}: {detail}")
        .chars()
        .take(512)
        .collect()
}

fn xml_element(body: &str, name: &str) -> Option<String> {
    let start_tag = format!("<{name}>");
    let end_tag = format!("</{name}>");
    let start = body.find(&start_tag)? + start_tag.len();
    let end = body[start..].find(&end_tag)? + start;
    Some(body[start..end].to_string())
}

fn retryable_s3_result(result: &RequestResult) -> bool {
    !result.success
        && (result.status == 0
            || (200..300).contains(&result.status)
            || matches!(result.status, 409 | 429 | 500 | 502 | 503 | 504))
}

impl RawBackend {
    async fn request(
        &self,
        operation: Operation,
        key: String,
        size: u64,
        range_bytes: u64,
        seed: u64,
        payload_profile: PayloadProfile,
    ) -> RequestResult {
        let root = self.root.clone();
        let fsync = self.fsync;
        tokio::task::spawn_blocking(move || {
            raw_request(
                &root,
                fsync,
                operation,
                &key,
                GeneratedRequest {
                    size,
                    range_bytes,
                    seed,
                    payload_profile,
                },
            )
        })
        .await
        .unwrap_or(RequestResult {
            success: false,
            status: 0,
            transferred: 0,
            retries: 0,
            retry_after: None,
            error: Some("raw backend task failed".to_string()),
            attempt_errors: Vec::new(),
        })
    }
}

fn raw_request(
    root: &Path,
    fsync: bool,
    operation: Operation,
    key: &str,
    request: GeneratedRequest,
) -> RequestResult {
    let GeneratedRequest {
        size,
        range_bytes,
        seed,
        payload_profile,
    } = request;
    let result = (|| -> Result<(u16, u64)> {
        let path = root.join(key);
        match operation {
            Operation::Put | Operation::MultipartPut => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut output = File::create(path)?;
                write_generated(&mut output, size, seed, payload_profile)?;
                if fsync {
                    output.sync_data()?;
                }
                Ok((200, 0))
            }
            Operation::Get | Operation::RangeGet => {
                let mut input = File::open(path)?;
                let mut remaining = if operation == Operation::RangeGet {
                    Some(range_bytes.min(size))
                } else {
                    None
                };
                let mut transferred = 0u64;
                let mut buffer = vec![0; STREAM_CHUNK_BYTES];
                loop {
                    let limit = remaining.map_or(buffer.len(), |value| {
                        value.min(buffer.len() as u64) as usize
                    });
                    if limit == 0 {
                        break;
                    }
                    let read = input.read(&mut buffer[..limit])?;
                    if read == 0 {
                        break;
                    }
                    transferred += read as u64;
                    if let Some(value) = &mut remaining {
                        *value -= read as u64;
                    }
                }
                Ok((
                    if operation == Operation::RangeGet {
                        206
                    } else {
                        200
                    },
                    transferred,
                ))
            }
            Operation::Head => {
                fs::metadata(path)?;
                Ok((200, 0))
            }
            Operation::List => {
                let _ = count_files(root)?;
                Ok((200, 0))
            }
            Operation::Mixed => unreachable!("mixed is resolved before backend dispatch"),
        }
    })();
    match result {
        Ok((status, transferred)) => RequestResult {
            success: true,
            status,
            transferred,
            retries: 0,
            retry_after: None,
            error: None,
            attempt_errors: Vec::new(),
        },
        Err(_) => RequestResult {
            success: false,
            status: 0,
            transferred: 0,
            retries: 0,
            retry_after: None,
            error: Some("raw operation failed".to_string()),
            attempt_errors: Vec::new(),
        },
    }
}

fn count_files(root: &Path) -> Result<u64> {
    let mut count = 0u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else if entry.file_type()?.is_file() {
                count += 1;
            }
        }
    }
    Ok(count)
}

fn generated_chunk(
    seed: u64,
    chunk_index: u64,
    size: usize,
    payload_profile: PayloadProfile,
) -> Vec<u8> {
    // SplitMix64 is deterministic and fast enough to keep the load generator
    // out of the storage hot path. Including the chunk index prevents Pepper's
    // content addressing from collapsing every block in a large object into a
    // single physical block, while the pseudorandom output avoids compression.
    let mut state = seed
        .wrapping_add(chunk_index.wrapping_mul(0x9e37_79b9_7f4a_7c15))
        .wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut chunk = vec![0u8; size];
    for output in chunk.chunks_mut(std::mem::size_of::<u64>()) {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^= value >> 31;
        output.copy_from_slice(&value.to_le_bytes()[..output.len()]);
    }
    let (period, random_bytes) = match payload_profile {
        PayloadProfile::Incompressible => return chunk,
        PayloadProfile::Compressible2x => (16, 8),
        PayloadProfile::Compressible4x => (32, 8),
        PayloadProfile::Compressible10x => (80, 8),
        PayloadProfile::Compressible20x => (160, 8),
    };
    for group in chunk.chunks_mut(period) {
        let zero_bytes = group.len().saturating_sub(random_bytes.min(group.len()));
        group[..zero_bytes].fill(0);
    }
    chunk
}

fn write_generated(
    output: &mut File,
    mut remaining: u64,
    seed: u64,
    payload_profile: PayloadProfile,
) -> Result<()> {
    let mut chunk_index = 0u64;
    while remaining > 0 {
        let take = remaining.min(STREAM_CHUNK_BYTES as u64) as usize;
        let chunk = generated_chunk(seed, chunk_index, take, payload_profile);
        output.write_all(&chunk)?;
        remaining -= take as u64;
        chunk_index += 1;
    }
    Ok(())
}

fn generated_body(size: u64, seed: u64, payload_profile: PayloadProfile) -> reqwest::Body {
    generated_body_at(size, seed, 0, payload_profile)
}

fn generated_body_at(
    size: u64,
    seed: u64,
    first_chunk_index: u64,
    payload_profile: PayloadProfile,
) -> reqwest::Body {
    let body = stream::unfold(
        (size, seed, first_chunk_index, payload_profile),
        |(remaining, seed, chunk_index, payload_profile)| async move {
            if remaining == 0 {
                None
            } else {
                let take = remaining.min(STREAM_CHUNK_BYTES as u64) as usize;
                let bytes = Bytes::from(generated_chunk(seed, chunk_index, take, payload_profile));
                Some((
                    Ok::<_, std::io::Error>(bytes),
                    (
                        remaining - take as u64,
                        seed,
                        chunk_index + 1,
                        payload_profile,
                    ),
                ))
            }
        },
    );
    reqwest::Body::wrap_stream(body)
}

pub(crate) fn aws_encode(value: &str, preserve_slash: bool) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (preserve_slash && byte == b'/')
        {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

fn hmac(key: &[u8], value: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(value.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

pub(crate) fn signed_headers(
    method: Method,
    endpoint: &str,
    path: &str,
    query: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
) -> header::HeaderMap {
    let now = OffsetDateTime::now_utc();
    let amz_date = now
        .format(format_description!(
            "[year][month][day]T[hour][minute][second]Z"
        ))
        .expect("static time format is valid");
    let date = now
        .format(format_description!("[year][month][day]"))
        .expect("static time format is valid");
    let host = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .unwrap_or(endpoint);
    let payload_hash = "UNSIGNED-PAYLOAD";
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let signed = "host;x-amz-content-sha256;x-amz-date";
    let canonical = format!(
        "{}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}",
        method.as_str()
    );
    let scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    );
    let date_key = hmac(format!("AWS4{secret_key}").as_bytes(), &date);
    let region_key = hmac(&date_key, region);
    let service_key = hmac(&region_key, "s3");
    let signing_key = hmac(&service_key, "aws4_request");
    let signature = hex::encode(hmac(&signing_key, &string_to_sign));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}"
    );
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::HOST,
        host.parse().expect("endpoint host is a header value"),
    );
    headers.insert(
        "x-amz-content-sha256",
        payload_hash.parse().expect("static header value"),
    );
    headers.insert(
        "x-amz-date",
        amz_date.parse().expect("time is a header value"),
    );
    headers.insert(
        header::AUTHORIZATION,
        authorization.parse().expect("signature is a header value"),
    );
    headers
}

fn object_key(size: u64, index: u64, payload_profile: PayloadProfile) -> String {
    format!(
        "objects/{}/{size}/{index:012}.bin",
        payload_profile.as_str()
    )
}

fn write_object_key(
    size: u64,
    worker_id: usize,
    iteration: u64,
    payload_profile: PayloadProfile,
) -> String {
    format!(
        "writes/{}/{size}/{worker_id:06}/{iteration:020}.bin",
        payload_profile.as_str()
    )
}

async fn prepare(
    backend: Backend,
    size: u64,
    count: u64,
    concurrency: usize,
    quiet: bool,
    payload_profile: PayloadProfile,
) -> Result<()> {
    let mut writes = stream::iter(0..count)
        .map(|index| {
            let backend = backend.clone();
            async move {
                let result = backend
                    .request(
                        Operation::Put,
                        object_key(size, index, payload_profile),
                        size,
                        0,
                        index,
                        payload_profile,
                    )
                    .await;
                ensure!(
                    result.success,
                    "preload PUT {index} failed with status {}: {}",
                    result.status,
                    result.error.as_deref().unwrap_or("no error body")
                );
                Ok::<_, anyhow::Error>(())
            }
        })
        .buffer_unordered(concurrency);
    let mut completed = 0u64;
    while let Some(result) = writes.next().await {
        result?;
        completed += 1;
        if !quiet && completed % 1000 == 0 {
            eprintln!("prepared {completed}/{count}");
        }
    }
    Ok(())
}

fn percentile(sorted: &[u64], numerator: usize) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = (sorted.len() * numerator).div_ceil(100).saturating_sub(1);
    sorted[index.min(sorted.len() - 1)] as f64 / 1000.0
}

async fn worker(worker_id: usize, backend: Backend, config: WorkerConfig) -> WorkerResult {
    let WorkerConfig {
        operation,
        request,
        object_count,
        deadline,
        drain_deadline,
    } = config;
    let GeneratedRequest {
        size,
        range_bytes,
        payload_profile,
        ..
    } = request;
    let mut result = WorkerResult::default();
    let mut iteration = 0u64;
    let mut random = worker_id as u64 + 1;
    while Instant::now() < deadline {
        let index = (worker_id as u64 + iteration.saturating_mul(131)) % object_count;
        let selected = if operation == Operation::Mixed {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            if random % 10 < 3 {
                Operation::Put
            } else {
                Operation::Get
            }
        } else {
            operation
        };
        let key = match selected {
            Operation::List => String::new(),
            Operation::Put | Operation::MultipartPut => {
                write_object_key(size, worker_id, iteration, payload_profile)
            }
            _ => object_key(size, index, payload_profile),
        };
        let started = Instant::now();
        let Ok(mut request) = tokio::time::timeout(
            drain_deadline.saturating_duration_since(Instant::now()),
            backend.request(
                selected,
                key,
                size,
                range_bytes,
                ((worker_id as u64) << 32) | iteration,
                payload_profile,
            ),
        )
        .await
        else {
            // Stop a genuinely stuck final request after the bounded drain
            // window. Healthy requests that crossed the launch deadline are
            // allowed to finish, avoiding synthetic server-side stream errors.
            break;
        };
        request.success &= match selected {
            Operation::Get => request.transferred == size,
            Operation::RangeGet => request.transferred == range_bytes.min(size),
            _ => true,
        };
        result
            .latencies_micros
            .push(started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64);
        *result.statuses.entry(request.status).or_default() += 1;
        result.attempts += 1;
        result.retries = result.retries.saturating_add(request.retries);
        for error in request.attempt_errors {
            *result.errors.entry(error).or_default() += 1;
        }
        if !request.success {
            result.failures += 1;
            if let Some(error) = request.error {
                *result.final_errors.entry(error).or_default() += 1;
            }
        } else if matches!(selected, Operation::Put | Operation::MultipartPut) {
            result.logical_bytes = result.logical_bytes.saturating_add(size);
        } else if matches!(selected, Operation::Get | Operation::RangeGet) {
            result.logical_bytes = result.logical_bytes.saturating_add(request.transferred);
        }
        iteration += 1;
    }
    result
}

pub async fn run(args: LoadgenArgs) -> Result<()> {
    ensure!(args.size > 0, "size must be positive");
    ensure!(args.concurrency > 0, "concurrency must be positive");
    ensure!(args.object_count > 0, "object-count must be positive");
    ensure!(args.range_bytes > 0, "range-bytes must be positive");
    if args.duration < 60 && !args.allow_short && !args.prepare_only {
        bail!(
            "timed cells must run for at least 60 seconds; use --allow-short only for smoke tests"
        );
    }
    let backend = match args.backend {
        BackendKind::S3 => {
            ensure!(
                !args.endpoints.is_empty(),
                "at least one S3 endpoint is required"
            );
            let client = Client::builder()
                .pool_max_idle_per_host(args.concurrency.max(1))
                .timeout(Duration::from_secs(args.timeout))
                .build()?;
            Backend::S3(Arc::new(S3Backend {
                client,
                endpoints: args
                    .endpoints
                    .iter()
                    .map(|value| value.trim_end_matches('/').to_string())
                    .collect(),
                bucket: args.bucket.clone(),
                access_key: args.access_key.clone(),
                secret_key: args.secret_key.clone(),
                region: args.region.clone(),
                retries: args.retries,
                route_counter: AtomicU64::new(0),
            }))
        }
        BackendKind::Raw => {
            let root = args
                .raw_root
                .clone()
                .context("--raw-root is required when --backend raw is selected")?;
            Backend::Raw(Arc::new(RawBackend {
                root,
                fsync: args.raw_fsync,
            }))
        }
    };
    backend.ensure_bucket().await?;
    if args.prepare {
        prepare(
            backend.clone(),
            args.size,
            args.object_count,
            args.concurrency,
            args.quiet,
            args.payload_profile,
        )
        .await?;
    }
    if args.prepare_only {
        return Ok(());
    }

    let started_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(args.duration);
    let drain_deadline = deadline + Duration::from_secs(args.drain_timeout);
    let mut workers = JoinSet::new();
    for worker_id in 0..args.concurrency {
        workers.spawn(worker(
            worker_id,
            backend.clone(),
            WorkerConfig {
                operation: args.operation,
                request: GeneratedRequest {
                    size: args.size,
                    range_bytes: args.range_bytes,
                    seed: 0,
                    payload_profile: args.payload_profile,
                },
                object_count: args.object_count,
                deadline,
                drain_deadline,
            },
        ));
    }
    let mut combined = WorkerResult::default();
    while let Some(result) = workers.join_next().await {
        let result = result?;
        combined.attempts += result.attempts;
        combined.retries = combined.retries.saturating_add(result.retries);
        combined.failures += result.failures;
        combined.logical_bytes = combined.logical_bytes.saturating_add(result.logical_bytes);
        combined.latencies_micros.extend(result.latencies_micros);
        for (status, count) in result.statuses {
            *combined.statuses.entry(status).or_default() += count;
        }
        for (error, count) in result.errors {
            *combined.errors.entry(error).or_default() += count;
        }
        for (error, count) in result.final_errors {
            *combined.final_errors.entry(error).or_default() += count;
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    combined.latencies_micros.sort_unstable();
    let report = Report {
        schema_version: 5,
        started_at,
        config: ReportConfig {
            backend: args.backend,
            operation: args.operation,
            object_size_bytes: args.size,
            concurrency: args.concurrency,
            requested_duration_seconds: args.duration,
            drain_timeout_seconds: args.drain_timeout,
            object_count: args.object_count,
            range_bytes: args.range_bytes,
            payload_profile: args.payload_profile,
            max_retries: if args.backend == BackendKind::S3 {
                args.retries
            } else {
                0
            },
            endpoints: if args.backend == BackendKind::S3 {
                args.endpoints.clone()
            } else {
                Vec::new()
            },
            raw_fsync: (args.backend == BackendKind::Raw).then_some(args.raw_fsync),
        },
        results: ReportResults {
            elapsed_seconds: elapsed,
            attempts: combined.attempts,
            successes: combined.attempts.saturating_sub(combined.failures),
            failures: combined.failures,
            retries: combined.retries,
            failure_rate: combined.failures as f64 / combined.attempts.max(1) as f64,
            logical_bytes: combined.logical_bytes,
            logical_mb_per_second: combined.logical_bytes as f64 / 1_000_000.0 / elapsed,
            operations_per_second: combined.attempts as f64 / elapsed,
            latency_ms: LatencyReport {
                p50: percentile(&combined.latencies_micros, 50),
                p95: percentile(&combined.latencies_micros, 95),
                p99: percentile(&combined.latencies_micros, 99),
                max: combined.latencies_micros.last().copied().unwrap_or(0) as f64 / 1000.0,
            },
            http_status_counts: combined.statuses,
            error_counts: combined.errors,
            final_error_counts: combined.final_errors,
        },
    };
    let encoded = serde_json::to_string_pretty(&report)? + "\n";
    if let Some(output) = &args.output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(output, &encoded)?;
    }
    if !args.quiet {
        print!("{encoded}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_result(success: bool, status: u16) -> RequestResult {
        RequestResult {
            success,
            status,
            transferred: 0,
            retries: 0,
            retry_after: None,
            error: None,
            attempt_errors: Vec::new(),
        }
    }

    #[test]
    fn retries_only_transient_s3_outcomes() {
        for status in [0, 200, 206, 409, 429, 500, 502, 503, 504] {
            assert!(retryable_s3_result(&request_result(false, status)));
        }
        for status in [400, 403, 404, 412, 501] {
            assert!(!retryable_s3_result(&request_result(false, status)));
        }
        assert!(!retryable_s3_result(&request_result(true, 200)));
    }

    #[test]
    fn generated_chunks_are_deterministic_unique_and_nonrepeating() {
        let first = generated_chunk(7, 0, STREAM_CHUNK_BYTES, PayloadProfile::Incompressible);
        assert_eq!(
            first,
            generated_chunk(7, 0, STREAM_CHUNK_BYTES, PayloadProfile::Incompressible)
        );
        assert_ne!(
            first,
            generated_chunk(7, 1, STREAM_CHUNK_BYTES, PayloadProfile::Incompressible)
        );
        assert_ne!(
            first,
            generated_chunk(8, 0, STREAM_CHUNK_BYTES, PayloadProfile::Incompressible)
        );
        assert_ne!(&first[..64 * 1024], &first[64 * 1024..128 * 1024]);
    }

    #[test]
    fn compressible_profiles_remain_unique() {
        for profile in [
            PayloadProfile::Compressible2x,
            PayloadProfile::Compressible4x,
            PayloadProfile::Compressible10x,
            PayloadProfile::Compressible20x,
        ] {
            let first = generated_chunk(7, 0, STREAM_CHUNK_BYTES, profile);
            assert_ne!(first, generated_chunk(7, 1, STREAM_CHUNK_BYTES, profile));
            assert_ne!(first, generated_chunk(8, 0, STREAM_CHUNK_BYTES, profile));
            assert!(first.iter().filter(|byte| **byte == 0).count() > first.len() / 3);
        }
    }

    #[test]
    fn high_compression_profiles_have_expected_sparse_shape() {
        for (profile, minimum_zero_fraction) in [
            (PayloadProfile::Compressible10x, 0.85),
            (PayloadProfile::Compressible20x, 0.92),
        ] {
            let chunk = generated_chunk(7, 0, STREAM_CHUNK_BYTES, profile);
            let other = generated_chunk(7, 1, STREAM_CHUNK_BYTES, profile);
            assert_ne!(chunk, other);
            let zero_fraction =
                chunk.iter().filter(|byte| **byte == 0).count() as f64 / chunk.len() as f64;
            assert!(zero_fraction >= minimum_zero_fraction);
        }
    }

    #[test]
    fn timed_writes_have_worker_local_unique_keys() {
        let first = write_object_key(4096, 0, 0, PayloadProfile::Incompressible);
        assert_ne!(
            first,
            write_object_key(4096, 1, 0, PayloadProfile::Incompressible)
        );
        assert_ne!(
            first,
            write_object_key(4096, 0, 1, PayloadProfile::Incompressible)
        );
        assert!(first.starts_with("writes/incompressible/4096/"));
    }
}
