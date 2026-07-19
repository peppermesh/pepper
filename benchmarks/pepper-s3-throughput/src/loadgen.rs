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
    Get,
    RangeGet,
    Head,
    List,
    Mixed,
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
    #[arg(long, default_value = "/tmp/pepper-s3-throughput/raw")]
    pub raw_root: PathBuf,
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub raw_fsync: bool,
    #[arg(long)]
    pub quiet: bool,
}

#[derive(Debug, Clone)]
struct RequestResult {
    success: bool,
    status: u16,
    transferred: u64,
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
    failures: u64,
    logical_bytes: u64,
    latencies_micros: Vec<u64>,
    statuses: BTreeMap<u16, u64>,
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
    object_count: u64,
    range_bytes: u64,
    endpoints: Vec<String>,
    raw_fsync: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ReportResults {
    elapsed_seconds: f64,
    attempts: u64,
    successes: u64,
    failures: u64,
    failure_rate: f64,
    logical_bytes: u64,
    logical_mb_per_second: f64,
    operations_per_second: f64,
    latency_ms: LatencyReport,
    http_status_counts: BTreeMap<u16, u64>,
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
    ) -> RequestResult {
        match self {
            Self::S3(backend) => {
                backend
                    .request(operation, &key, size, range_bytes, seed)
                    .await
            }
            Self::Raw(backend) => {
                backend
                    .request(operation, key, size, range_bytes, seed)
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
                return Ok(());
            }
            if !matches!(status, 0 | 503) || Instant::now() >= deadline {
                bail!("CreateBucket failed with HTTP {status}");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn request(
        &self,
        operation: Operation,
        key: &str,
        size: u64,
        range_bytes: u64,
        seed: u64,
    ) -> RequestResult {
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
            Operation::Mixed => unreachable!("mixed is resolved before backend dispatch"),
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
                .header(header::CONTENT_LENGTH, size)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(generated_body(size, seed));
        }
        if operation == Operation::RangeGet {
            let requested = range_bytes.min(size);
            request = request.header(
                header::RANGE,
                format!("bytes=0-{}", requested.saturating_sub(1)),
            );
        }
        let Ok(response) = request.send().await else {
            return RequestResult {
                success: false,
                status: 0,
                transferred: 0,
            };
        };
        let status = response.status();
        let mut transferred = 0u64;
        let mut body = response.bytes_stream();
        while let Some(chunk) = body.next().await {
            match chunk {
                Ok(chunk) => transferred = transferred.saturating_add(chunk.len() as u64),
                Err(_) => {
                    return RequestResult {
                        success: false,
                        status: status.as_u16(),
                        transferred,
                    };
                }
            }
        }
        RequestResult {
            success: status.is_success(),
            status: status.as_u16(),
            transferred,
        }
    }
}

impl RawBackend {
    async fn request(
        &self,
        operation: Operation,
        key: String,
        size: u64,
        range_bytes: u64,
        seed: u64,
    ) -> RequestResult {
        let root = self.root.clone();
        let fsync = self.fsync;
        tokio::task::spawn_blocking(move || {
            raw_request(&root, fsync, operation, &key, size, range_bytes, seed)
        })
        .await
        .unwrap_or(RequestResult {
            success: false,
            status: 0,
            transferred: 0,
        })
    }
}

fn raw_request(
    root: &Path,
    fsync: bool,
    operation: Operation,
    key: &str,
    size: u64,
    range_bytes: u64,
    seed: u64,
) -> RequestResult {
    let result = (|| -> Result<(u16, u64)> {
        let path = root.join(key);
        match operation {
            Operation::Put => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut output = File::create(path)?;
                write_generated(&mut output, size, seed)?;
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
        },
        Err(_) => RequestResult {
            success: false,
            status: 0,
            transferred: 0,
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

fn generated_chunk(seed: u64) -> Vec<u8> {
    let digest = Sha256::digest(seed.to_string().as_bytes());
    digest
        .iter()
        .copied()
        .cycle()
        .take(STREAM_CHUNK_BYTES)
        .collect()
}

fn write_generated(output: &mut File, mut remaining: u64, seed: u64) -> Result<()> {
    let chunk = generated_chunk(seed);
    while remaining > 0 {
        let take = remaining.min(chunk.len() as u64) as usize;
        output.write_all(&chunk[..take])?;
        remaining -= take as u64;
    }
    Ok(())
}

fn generated_body(size: u64, seed: u64) -> reqwest::Body {
    let chunk = Arc::new(generated_chunk(seed));
    let body = stream::unfold((size, chunk), |(remaining, chunk)| async move {
        if remaining == 0 {
            None
        } else {
            let take = remaining.min(chunk.len() as u64) as usize;
            let bytes = Bytes::copy_from_slice(&chunk[..take]);
            Some((
                Ok::<_, std::io::Error>(bytes),
                (remaining - take as u64, chunk),
            ))
        }
    });
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

fn object_key(size: u64, index: u64) -> String {
    format!("objects/{size}/{index:012}.bin")
}

async fn prepare(
    backend: Backend,
    size: u64,
    count: u64,
    concurrency: usize,
    quiet: bool,
) -> Result<()> {
    let mut writes = stream::iter(0..count)
        .map(|index| {
            let backend = backend.clone();
            async move {
                let result = backend
                    .request(Operation::Put, object_key(size, index), size, 0, index)
                    .await;
                ensure!(
                    result.success,
                    "preload PUT {index} failed with status {}",
                    result.status
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

async fn worker(
    worker_id: usize,
    backend: Backend,
    operation: Operation,
    size: u64,
    range_bytes: u64,
    object_count: u64,
    deadline: Instant,
) -> WorkerResult {
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
        let key = if selected == Operation::List {
            String::new()
        } else {
            object_key(size, index)
        };
        let started = Instant::now();
        let mut request = backend
            .request(
                selected,
                key,
                size,
                range_bytes,
                ((worker_id as u64) << 32) | iteration,
            )
            .await;
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
        if !request.success {
            result.failures += 1;
        } else if selected == Operation::Put {
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
                route_counter: AtomicU64::new(0),
            }))
        }
        BackendKind::Raw => Backend::Raw(Arc::new(RawBackend {
            root: args.raw_root.clone(),
            fsync: args.raw_fsync,
        })),
    };
    backend.ensure_bucket().await?;
    if args.prepare {
        prepare(
            backend.clone(),
            args.size,
            args.object_count,
            args.concurrency,
            args.quiet,
        )
        .await?;
    }
    if args.prepare_only {
        return Ok(());
    }

    let started_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(args.duration);
    let mut workers = JoinSet::new();
    for worker_id in 0..args.concurrency {
        workers.spawn(worker(
            worker_id,
            backend.clone(),
            args.operation,
            args.size,
            args.range_bytes,
            args.object_count,
            deadline,
        ));
    }
    let mut combined = WorkerResult::default();
    while let Some(result) = workers.join_next().await {
        let result = result?;
        combined.attempts += result.attempts;
        combined.failures += result.failures;
        combined.logical_bytes = combined.logical_bytes.saturating_add(result.logical_bytes);
        combined.latencies_micros.extend(result.latencies_micros);
        for (status, count) in result.statuses {
            *combined.statuses.entry(status).or_default() += count;
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    combined.latencies_micros.sort_unstable();
    let report = Report {
        schema_version: 1,
        started_at,
        config: ReportConfig {
            backend: args.backend,
            operation: args.operation,
            object_size_bytes: args.size,
            concurrency: args.concurrency,
            requested_duration_seconds: args.duration,
            object_count: args.object_count,
            range_bytes: args.range_bytes,
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
