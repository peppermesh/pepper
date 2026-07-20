// SPDX-License-Identifier: Apache-2.0

use crate::{
    loadgen::{aws_encode, signed_headers},
    matrix,
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use clap::Args;
use futures_util::{StreamExt, stream};
use reqwest::{Client, Method, StatusCode, header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    fs::File,
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

const BLOCK_BYTES: u64 = 8 * 1024 * 1024;
const DEFAULT_DATASET: &str = "32x536870912,16x1073741824,8x4294967296";
const DEFAULT_CONCURRENCY: &str = "1,4,16,32,64,96";
const DEFAULT_ROUTING: &str = "leader,follower";
const DEFAULT_SCENARIOS: &str = "independent-cold,workload-cache-fill,diagnostic";
const BUCKET: &str = "pepper-s3-throughput";
const ACCESS_KEY: &str = "pepper-benchmark";
const SECRET_KEY: &str = "pepper-benchmark-secret-v1";
const REGION: &str = "us-east-1";
const GENERATOR: &str = "sha256-seeded-xoshiro256starstar-v1";

unsafe extern "C" {
    fn posix_fadvise(fd: i32, offset: i64, len: i64, advice: i32) -> i32;
}
const POSIX_FADV_DONTNEED: i32 = 4;

#[derive(Debug, Args)]
pub struct CacheFillArgs {
    /// Bulk-data root on a dedicated XFS filesystem (never the OS root filesystem).
    #[arg(long)]
    root: Option<PathBuf>,
    #[arg(long)]
    artifacts: Option<PathBuf>,
    #[arg(long, default_value = "three")]
    topology: String,
    #[arg(long, default_value = DEFAULT_DATASET)]
    dataset_spec: String,
    #[arg(long, default_value = DEFAULT_CONCURRENCY)]
    concurrency: String,
    #[arg(long, default_value = DEFAULT_ROUTING)]
    routing: String,
    #[arg(long, default_value = DEFAULT_SCENARIOS)]
    scenarios: String,
    #[arg(long, default_value_t = 43)]
    query_limit: usize,
    #[arg(long, default_value_t = 2)]
    upload_concurrency: usize,
    #[arg(long, default_value_t = 3)]
    retries: usize,
    #[arg(long, default_value_t = 3600)]
    timeout: u64,
    #[arg(long, default_value_t = 0x5eed_cafe_d15c_cace)]
    seed: u64,
    #[arg(long)]
    fresh: bool,
    #[arg(long)]
    prepare_only: bool,
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
pub struct CacheFillSummaryArgs {
    pub artifacts: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DatasetManifest {
    schema_version: u32,
    block_size_bytes: u64,
    generator: String,
    bucket: String,
    objects: Vec<ObjectManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ObjectManifest {
    index: usize,
    key: String,
    size_bytes: u64,
    block_sha256: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct BlockId {
    object: usize,
    block: usize,
}

#[derive(Debug, Clone, Serialize)]
struct QuerySpec {
    index: usize,
    class: &'static str,
    target_overlap_percent: u8,
    blocks: Vec<BlockId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    IndependentCold,
    WorkloadCacheFill,
    DiagnosticCold,
    DiagnosticWarm,
}

impl Scenario {
    fn name(self) -> &'static str {
        match self {
            Self::IndependentCold => "independent-cold",
            Self::WorkloadCacheFill => "workload-cache-fill",
            Self::DiagnosticCold => "diagnostic-cold",
            Self::DiagnosticWarm => "diagnostic-warm",
        }
    }

    fn simulated_cache(self) -> bool {
        matches!(self, Self::IndependentCold | Self::WorkloadCacheFill)
    }
}

#[derive(Clone)]
struct S3Client {
    client: Client,
    endpoints: Arc<Vec<String>>,
}

#[derive(Debug, Default)]
struct FetchResult {
    success: bool,
    retries: usize,
    latencies_micros: Vec<u64>,
    statuses: Vec<u16>,
}

#[derive(Debug, Serialize)]
struct QueryReport {
    query_index: usize,
    class: &'static str,
    target_overlap_percent: u8,
    selected_blocks: usize,
    selected_bytes: u64,
    metadata_lookups: usize,
    metadata_errors: usize,
    requested_reads: usize,
    suppressed_reads: usize,
    successful_reads: usize,
    errors: usize,
    retries: usize,
    logical_bytes: u64,
    cache_fill_latency_ms: f64,
}

#[derive(Debug, Serialize)]
struct WorkloadReport {
    schema_version: u32,
    scenario: &'static str,
    concurrency: usize,
    routing: String,
    query_count: usize,
    elapsed_seconds: f64,
    queries: Vec<QueryReport>,
    results: Value,
}

#[derive(Debug, Default)]
struct ClientCache {
    objects: BTreeSet<usize>,
    blocks: BTreeSet<BlockId>,
}

struct Measurement<'a> {
    root: &'a Path,
    topology: &'a str,
    http: &'a Client,
    manifest: &'a DatasetManifest,
    queries: &'a [QuerySpec],
    retries: usize,
}

#[derive(Debug, Clone, Copy)]
struct Prng([u64; 4]);

impl Prng {
    fn seeded(domain: u64, first: u64, second: u64) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"pepper-synthetic-s3-cache-fill-v1");
        hash.update(domain.to_le_bytes());
        hash.update(first.to_le_bytes());
        hash.update(second.to_le_bytes());
        let bytes = hash.finalize();
        let mut words = [0u64; 4];
        for (index, word) in words.iter_mut().enumerate() {
            *word = u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap());
        }
        Self(words)
    }

    fn next(&mut self) -> u64 {
        let result = self.0[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let temporary = self.0[1] << 17;
        self.0[2] ^= self.0[0];
        self.0[3] ^= self.0[1];
        self.0[1] ^= self.0[2];
        self.0[0] ^= self.0[3];
        self.0[2] ^= temporary;
        self.0[3] = self.0[3].rotate_left(45);
        result
    }
}

fn generated_block(object: usize, block: usize, size: usize) -> Vec<u8> {
    let mut random = Prng::seeded(0x6461_7461, object as u64, block as u64);
    let mut bytes = vec![0u8; size];
    for chunk in bytes.chunks_mut(8) {
        let value = random.next().to_le_bytes();
        let length = chunk.len();
        chunk.copy_from_slice(&value[..length]);
    }
    bytes
}

fn parse_dataset(value: &str) -> Result<Vec<u64>> {
    let mut sizes = Vec::new();
    for group in value.split(',') {
        let (count, size) = group
            .split_once('x')
            .with_context(|| format!("invalid dataset group {group:?}; expected COUNTxBYTES"))?;
        let count = count.parse::<usize>()?;
        let size = size.parse::<u64>()?;
        ensure!(count > 0, "dataset object count must be positive");
        ensure!(
            size > 0 && size % BLOCK_BYTES == 0,
            "dataset object sizes must be positive multiples of 8 MiB"
        );
        sizes.extend(std::iter::repeat_n(size, count));
    }
    ensure!(!sizes.is_empty(), "dataset cannot be empty");
    Ok(sizes)
}

fn parse_list<T>(value: &str) -> Result<Vec<T>>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    value
        .split(',')
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()
        .map_err(Into::into)
}

fn expected_objects(sizes: &[u64]) -> Vec<ObjectManifest> {
    sizes
        .iter()
        .enumerate()
        .map(|(index, size)| ObjectManifest {
            index,
            key: format!("synthetic-cache-fill/v1/object-{index:03}-{size}.bin"),
            size_bytes: *size,
            block_sha256: Vec::new(),
        })
        .collect()
}

impl S3Client {
    fn new(endpoints: Vec<String>, concurrency: usize, timeout: u64) -> Result<Self> {
        ensure!(
            !endpoints.is_empty(),
            "at least one S3 endpoint is required"
        );
        Ok(Self {
            client: Client::builder()
                .pool_max_idle_per_host(concurrency.max(1))
                .timeout(Duration::from_secs(timeout))
                .build()?,
            endpoints: Arc::new(endpoints),
        })
    }

    fn endpoint(&self, key: &str) -> &str {
        let digest = Sha256::digest(key.as_bytes());
        let index = u64::from_le_bytes(digest[..8].try_into().unwrap()) as usize;
        &self.endpoints[index % self.endpoints.len()]
    }

    fn object_path(key: &str) -> String {
        format!("/{}/{}", aws_encode(BUCKET, false), aws_encode(key, true))
    }

    async fn head(&self, key: &str) -> Result<Option<u64>> {
        let endpoint = self.endpoint(key);
        let path = Self::object_path(key);
        let response = self
            .client
            .head(format!("{endpoint}{path}"))
            .headers(signed_headers(
                Method::HEAD,
                endpoint,
                &path,
                "",
                ACCESS_KEY,
                SECRET_KEY,
                REGION,
            ))
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let response = response.error_for_status()?;
        Ok(response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok()))
    }

    async fn upload(&self, object: &ObjectManifest, retries: usize) -> Result<Vec<String>> {
        let mut last = None;
        for attempt in 0..=retries {
            let endpoint = self.endpoint(&object.key);
            let path = Self::object_path(&object.key);
            let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
            let size = object.size_bytes;
            let object_index = object.index;
            let body = stream::unfold(0u64, move |offset| {
                let sender = sender.clone();
                async move {
                    if offset >= size {
                        return None;
                    }
                    let block_index = (offset / BLOCK_BYTES) as usize;
                    let length = (size - offset).min(BLOCK_BYTES) as usize;
                    let bytes = generated_block(object_index, block_index, length);
                    let checksum = hex::encode(Sha256::digest(&bytes));
                    let _ = sender.send((block_index, checksum));
                    Some((
                        Ok::<Bytes, std::io::Error>(Bytes::from(bytes)),
                        offset + length as u64,
                    ))
                }
            });
            let response = self
                .client
                .put(format!("{endpoint}{path}"))
                .headers(signed_headers(
                    Method::PUT,
                    endpoint,
                    &path,
                    "",
                    ACCESS_KEY,
                    SECRET_KEY,
                    REGION,
                ))
                .header(header::CONTENT_LENGTH, object.size_bytes)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(reqwest::Body::wrap_stream(body))
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => {
                    let mut checksums = BTreeMap::new();
                    while let Ok((index, checksum)) = receiver.try_recv() {
                        checksums.insert(index, checksum);
                    }
                    ensure!(
                        checksums.len() == object.size_bytes.div_ceil(BLOCK_BYTES) as usize,
                        "upload stream ended without checksums for every block of {}",
                        object.key
                    );
                    return Ok(checksums.into_values().collect());
                }
                Ok(response) => {
                    last = Some(anyhow::anyhow!(
                        "upload {} returned HTTP {}",
                        object.key,
                        response.status()
                    ))
                }
                Err(error) => last = Some(error.into()),
            }
            if attempt < retries {
                tokio::time::sleep(Duration::from_millis(100 * (attempt + 1) as u64)).await;
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("upload failed")))
    }

    async fn range(&self, object: &ObjectManifest, block: usize) -> Result<(u16, Bytes)> {
        let endpoint = self.endpoint(&object.key);
        let path = Self::object_path(&object.key);
        let start = block as u64 * BLOCK_BYTES;
        let end = (start + BLOCK_BYTES).min(object.size_bytes) - 1;
        let response = self
            .client
            .get(format!("{endpoint}{path}"))
            .headers(signed_headers(
                Method::GET,
                endpoint,
                &path,
                "",
                ACCESS_KEY,
                SECRET_KEY,
                REGION,
            ))
            .header(header::RANGE, format!("bytes={start}-{end}"))
            .send()
            .await?;
        let status = response.status().as_u16();
        let bytes = response.bytes().await?;
        Ok((status, bytes))
    }
}

fn write_manifest(path: &Path, manifest: &DatasetManifest) -> Result<()> {
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_string_pretty(manifest)? + "\n")?;
    fs::rename(temporary, path)?;
    Ok(())
}

async fn prepare_dataset(
    client: S3Client,
    path: &Path,
    sizes: &[u64],
    concurrency: usize,
    retries: usize,
) -> Result<DatasetManifest> {
    let expected = expected_objects(sizes);
    let mut manifest = if path.exists() {
        serde_json::from_slice::<DatasetManifest>(&fs::read(path)?)?
    } else {
        DatasetManifest {
            schema_version: 1,
            block_size_bytes: BLOCK_BYTES,
            generator: GENERATOR.to_string(),
            bucket: BUCKET.to_string(),
            objects: expected.clone(),
        }
    };
    ensure!(
        manifest.schema_version == 1
            && manifest.block_size_bytes == BLOCK_BYTES
            && manifest.generator == GENERATOR
            && manifest.bucket == BUCKET,
        "dataset manifest is incompatible with this benchmark version"
    );
    ensure!(
        manifest
            .objects
            .iter()
            .map(|object| (&object.key, object.size_bytes))
            .eq(expected
                .iter()
                .map(|object| (&object.key, object.size_bytes))),
        "dataset manifest does not match --dataset-spec"
    );
    let objects = manifest.objects.clone();
    let work = objects.into_iter().enumerate().map(|(index, object)| {
        let client = client.clone();
        async move {
            let block_count = object.size_bytes.div_ceil(BLOCK_BYTES) as usize;
            if object.block_sha256.len() == block_count
                && client.head(&object.key).await? == Some(object.size_bytes)
            {
                return Ok::<_, anyhow::Error>((index, None));
            }
            eprintln!("uploading {} ({} bytes)", object.key, object.size_bytes);
            let checksums = client.upload(&object, retries).await?;
            Ok((index, Some(checksums)))
        }
    });
    let mut work = stream::iter(work).buffer_unordered(concurrency);
    while let Some(result) = work.next().await {
        let (index, checksums) = result?;
        if let Some(checksums) = checksums {
            manifest.objects[index].block_sha256 = checksums;
            write_manifest(path, &manifest)?;
        }
    }
    write_manifest(path, &manifest)?;
    Ok(manifest)
}

fn block_from_global(objects: &[ObjectManifest], mut index: usize) -> BlockId {
    for object in objects {
        let blocks = object.block_sha256.len();
        if index < blocks {
            return BlockId {
                object: object.index,
                block: index,
            };
        }
        index -= blocks;
    }
    unreachable!("global block index is bounded by dataset block count")
}

fn generate_queries(manifest: &DatasetManifest, seed: u64) -> Vec<QuerySpec> {
    let classes = [
        ("highly-selective", 10usize, 8usize, 32usize),
        ("selective-aggregation", 12, 32, 128),
        ("broad-aggregation", 12, 128, 512),
        ("wide-scan", 6, 512, 2048),
        (
            "high-fanout-metadata",
            3,
            manifest.objects.len(),
            manifest.objects.len(),
        ),
    ];
    let total_blocks = manifest
        .objects
        .iter()
        .map(|object| object.block_sha256.len())
        .sum::<usize>();
    let overlap_levels = [0u8, 25, 50, 75];
    let mut previous = Vec::<BlockId>::new();
    let mut queries = Vec::with_capacity(43);
    for (class, count, minimum, maximum) in classes {
        for _ in 0..count {
            let query_index = queries.len();
            let overlap = if class == "high-fanout-metadata" {
                0
            } else {
                overlap_levels[query_index % overlap_levels.len()]
            };
            let mut random = Prng::seeded(seed, query_index as u64, total_blocks as u64);
            let target =
                (minimum + (random.next() as usize % (maximum - minimum + 1))).min(total_blocks);
            let overlap_count = (target * overlap as usize / 100).min(previous.len());
            let mut selected = BTreeSet::new();
            if !previous.is_empty() {
                let cursor = random.next() as usize % previous.len();
                for offset in 0..overlap_count {
                    selected.insert(previous[(cursor + offset) % previous.len()]);
                }
            }
            if class == "high-fanout-metadata" {
                for object in &manifest.objects {
                    let block = random.next() as usize % object.block_sha256.len();
                    selected.insert(BlockId {
                        object: object.index,
                        block,
                    });
                }
            } else {
                while selected.len() < target {
                    selected.insert(block_from_global(
                        &manifest.objects,
                        random.next() as usize % total_blocks,
                    ));
                }
            }
            previous = selected.iter().copied().collect();
            queries.push(QuerySpec {
                index: query_index,
                class,
                target_overlap_percent: overlap,
                blocks: previous.clone(),
            });
        }
    }
    queries
}

fn percentile(sorted: &[u64], percentile: usize) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = (sorted.len() * percentile)
        .div_ceil(100)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[index] as f64 / 1000.0
}

async fn fetch_block(
    client: S3Client,
    object: ObjectManifest,
    block: usize,
    retries: usize,
) -> FetchResult {
    let expected = object.block_sha256[block].clone();
    let expected_size = (object.size_bytes - block as u64 * BLOCK_BYTES).min(BLOCK_BYTES) as usize;
    let mut result = FetchResult::default();
    for attempt in 0..=retries {
        let started = Instant::now();
        let response = client.range(&object, block).await;
        result
            .latencies_micros
            .push(started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64);
        match response {
            Ok((status, bytes)) => {
                result.statuses.push(status);
                if status == StatusCode::PARTIAL_CONTENT.as_u16()
                    && bytes.len() == expected_size
                    && hex::encode(Sha256::digest(&bytes)) == expected
                {
                    result.success = true;
                    result.retries = attempt;
                    return result;
                }
            }
            Err(_) => result.statuses.push(0),
        }
        if attempt < retries {
            tokio::time::sleep(Duration::from_millis(50 * (attempt + 1) as u64)).await;
        }
    }
    result.retries = retries;
    result
}

async fn execute_workload(
    client: S3Client,
    manifest: &DatasetManifest,
    queries: &[QuerySpec],
    scenario: Scenario,
    concurrency: usize,
    routing: &str,
    retries: usize,
) -> WorkloadReport {
    let workload_started = Instant::now();
    let mut cache = ClientCache::default();
    let mut query_reports = Vec::with_capacity(queries.len());
    let mut all_latencies = Vec::new();
    let mut total_requested = 0usize;
    let mut total_suppressed = 0usize;
    let mut total_successes = 0usize;
    let mut total_errors = 0usize;
    let mut total_retries = 0usize;
    let mut total_logical = 0u64;
    let mut statuses = BTreeMap::<u16, usize>::new();
    for query in queries {
        if scenario == Scenario::IndependentCold || !scenario.simulated_cache() {
            cache = ClientCache::default();
        }
        let query_started = Instant::now();
        let referenced = query
            .blocks
            .iter()
            .map(|block| block.object)
            .collect::<BTreeSet<_>>();
        let metadata = referenced
            .iter()
            .filter(|object| !cache.objects.contains(object))
            .copied()
            .collect::<Vec<_>>();
        let metadata_work = metadata.iter().map(|index| {
            let client = client.clone();
            let object = manifest.objects[*index].clone();
            async move {
                for attempt in 0..=retries {
                    if client
                        .head(&object.key)
                        .await
                        .is_ok_and(|size| size == Some(object.size_bytes))
                    {
                        return (index, true, attempt);
                    }
                    if attempt < retries {
                        tokio::time::sleep(Duration::from_millis(50 * (attempt + 1) as u64)).await;
                    }
                }
                (index, false, retries)
            }
        });
        let metadata_results = stream::iter(metadata_work)
            .buffer_unordered(concurrency)
            .collect::<Vec<_>>()
            .await;
        let metadata_errors = metadata_results
            .iter()
            .filter(|(_, success, _)| !success)
            .count();
        let metadata_retries = metadata_results
            .iter()
            .map(|(_, _, retries)| *retries)
            .sum::<usize>();
        for (index, success, _) in metadata_results {
            if success {
                cache.objects.insert(*index);
            }
        }
        let (suppressed, fetches): (Vec<_>, Vec<_>) = query
            .blocks
            .iter()
            .copied()
            .partition(|block| scenario.simulated_cache() && cache.blocks.contains(block));
        let fetch_work = fetches.iter().copied().map(|block| {
            let client = client.clone();
            let object = manifest.objects[block.object].clone();
            async move {
                (
                    block,
                    fetch_block(client, object, block.block, retries).await,
                )
            }
        });
        let results = stream::iter(fetch_work)
            .buffer_unordered(concurrency)
            .collect::<Vec<_>>()
            .await;
        let mut successes = 0usize;
        let mut errors = metadata_errors;
        let mut query_retries = metadata_retries;
        let mut logical = 0u64;
        for (block, result) in results {
            all_latencies.extend(&result.latencies_micros);
            for status in result.statuses {
                *statuses.entry(status).or_default() += 1;
            }
            query_retries += result.retries;
            if result.success {
                successes += 1;
                logical += (manifest.objects[block.object].size_bytes
                    - block.block as u64 * BLOCK_BYTES)
                    .min(BLOCK_BYTES);
                if scenario.simulated_cache() {
                    cache.blocks.insert(block);
                }
            } else {
                errors += 1;
            }
        }
        total_requested += fetches.len();
        total_suppressed += suppressed.len();
        total_successes += successes;
        total_errors += errors;
        total_retries += query_retries;
        total_logical += logical;
        query_reports.push(QueryReport {
            query_index: query.index,
            class: query.class,
            target_overlap_percent: query.target_overlap_percent,
            selected_blocks: query.blocks.len(),
            selected_bytes: query.blocks.len() as u64 * BLOCK_BYTES,
            metadata_lookups: metadata.len(),
            metadata_errors,
            requested_reads: fetches.len(),
            suppressed_reads: suppressed.len(),
            successful_reads: successes,
            errors,
            retries: query_retries,
            logical_bytes: logical,
            cache_fill_latency_ms: query_started.elapsed().as_secs_f64() * 1000.0,
        });
    }
    let elapsed = workload_started.elapsed().as_secs_f64();
    all_latencies.sort_unstable();
    WorkloadReport {
        schema_version: 1,
        scenario: scenario.name(),
        concurrency,
        routing: routing.to_string(),
        query_count: queries.len(),
        elapsed_seconds: elapsed,
        queries: query_reports,
        results: json!({"requested_reads": total_requested, "suppressed_reads": total_suppressed,
            "successful_reads": total_successes, "errors": total_errors, "retries": total_retries,
            "logical_requested_bytes": total_requested as u64 * BLOCK_BYTES,
            "logical_requested_mb_per_second": total_requested as f64 * BLOCK_BYTES as f64 / 1e6 / elapsed,
            "logical_bytes": total_logical, "logical_mb_per_second": total_logical as f64 / 1e6 / elapsed,
            "range_latency_ms": {"p50": percentile(&all_latencies, 50), "p95": percentile(&all_latencies, 95),
                "p99": percentile(&all_latencies, 99), "max": all_latencies.last().copied().unwrap_or(0) as f64 / 1000.0},
            "status_counts": statuses}),
    }
}

fn metric_delta(before: &matrix::Scrape, after: &matrix::Scrape, name: &str) -> f64 {
    let start: f64 = before
        .values()
        .map(|values| matrix::metric_sum(values, name))
        .sum();
    let end: f64 = after
        .values()
        .map(|values| matrix::metric_sum(values, name))
        .sum();
    (end - start).max(0.0)
}

fn labelled_delta<F>(
    before: &matrix::Scrape,
    after: &matrix::Scrape,
    name: &str,
    predicate: F,
) -> f64
where
    F: Fn(&str) -> bool,
{
    let keys = after
        .values()
        .flat_map(|values| matrix::family(values, name).map(|(key, _)| key.clone()))
        .collect::<BTreeSet<_>>();
    keys.iter()
        .filter(|key| predicate(key))
        .map(|key| {
            let start: f64 = before
                .values()
                .map(|values| values.get(key).copied().unwrap_or(0.0))
                .sum();
            let end: f64 = after
                .values()
                .map(|values| values.get(key).copied().unwrap_or(0.0))
                .sum();
            (end - start).max(0.0)
        })
        .sum()
}

fn raft_term_changes(before: &matrix::Scrape, after: &matrix::Scrape) -> u64 {
    after
        .iter()
        .flat_map(|(endpoint, values)| {
            matrix::family(values, "pepper_namespace_term").map(move |(key, value)| {
                let before_value = before
                    .get(endpoint)
                    .and_then(|metrics| metrics.get(key))
                    .copied()
                    .unwrap_or(*value);
                value.max(before_value) - before_value
            })
        })
        .sum::<f64>() as u64
}

fn network_bytes(pids: &[u32]) -> (u64, u64) {
    pids.iter()
        .filter_map(|pid| fs::read_to_string(format!("/proc/{pid}/net/dev")).ok())
        .fold((0, 0), |totals, text| {
            text.lines()
                .filter_map(|line| line.split_once(':'))
                .filter(|(name, _)| name.trim() != "lo")
                .fold(totals, |(rx, tx), (_, values)| {
                    let fields = values.split_whitespace().collect::<Vec<_>>();
                    (
                        rx + fields
                            .first()
                            .and_then(|value| value.parse::<u64>().ok())
                            .unwrap_or(0),
                        tx + fields
                            .get(8)
                            .and_then(|value| value.parse::<u64>().ok())
                            .unwrap_or(0),
                    )
                })
        })
}

fn make_data_readable(root: &Path, topology: &str) -> Result<()> {
    for service in matrix::topology_services(topology) {
        let mut command = matrix::docker(root);
        command.args([
            "--profile",
            topology,
            "run",
            "--rm",
            "--no-deps",
            "--user",
            "0",
            "--entrypoint",
            "/bin/chmod",
            service,
            "-R",
            "a+rX",
            "/var/lib/pepper/metadata",
            "/var/lib/pepper/storage",
        ]);
        matrix::run_command(&mut command)?;
        if topology == "nine-ec" {
            matrix::run_command(matrix::docker(root).args([
                "--profile",
                topology,
                "run",
                "--rm",
                "--no-deps",
                "--user",
                "0",
                "--entrypoint",
                "/bin/chmod",
                service,
                "-R",
                "a+rwX",
                "/var/lib/pepper/reconstructed-cache",
            ]))?;
        }
    }
    Ok(())
}

fn clear_reconstructed_cache(root: &Path, topology: &str) -> Result<()> {
    if topology != "nine-ec" {
        return Ok(());
    }
    for name in matrix::topology_services(topology) {
        let path = root.join(name).join("reconstructed-cache");
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o777))?;
    }
    Ok(())
}

fn evict_page_cache(root: &Path, topology: &str) -> Result<Value> {
    let mut pending = matrix::topology_services(topology)
        .into_iter()
        .flat_map(|name| {
            let mut paths = vec![
                root.join(name).join("metadata"),
                root.join(name).join("storage"),
            ];
            if topology == "nine-ec" {
                paths.push(root.join(name).join("reconstructed-cache"));
            }
            paths
        })
        .collect::<Vec<_>>();
    let mut files = 0u64;
    let mut bytes = 0u64;
    let mut errors = 0u64;
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = entry.metadata()?;
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                match File::open(&path) {
                    Ok(file) => {
                        // SAFETY: fd is valid for the duration of the call; offset/length zero means the whole file.
                        let status =
                            unsafe { posix_fadvise(file.as_raw_fd(), 0, 0, POSIX_FADV_DONTNEED) };
                        if status == 0 {
                            files += 1;
                            bytes += metadata.len();
                        } else {
                            errors += 1;
                        }
                    }
                    Err(_) => errors += 1,
                }
            }
        }
    }
    ensure!(
        files > 0,
        "no Pepper data files were available for page-cache eviction"
    );
    Ok(json!({"files": files, "bytes": bytes, "errors": errors}))
}

async fn measured_cell(
    measurement: &Measurement<'_>,
    endpoints: Vec<String>,
    scenario: Scenario,
    concurrency: usize,
    routing: &str,
) -> Result<Value> {
    let pids = matrix::container_pids(measurement.topology, measurement.root)?;
    let all_endpoints = matrix::topology_endpoints(measurement.topology);
    let (before, _) = matrix::scrape(measurement.http, &all_endpoints).await;
    let disk_before = matrix::block_stats(measurement.root)?;
    let cpu_before = matrix::host_cpu()?;
    let ticks_before = matrix::proc_ticks(&pids);
    let network_before = network_bytes(&pids);
    let started = Instant::now();
    let report = execute_workload(
        S3Client::new(endpoints, concurrency, 3600)?,
        measurement.manifest,
        measurement.queries,
        scenario,
        concurrency,
        routing,
        measurement.retries,
    )
    .await;
    let elapsed = started.elapsed().as_secs_f64();
    let network_after = network_bytes(&pids);
    let ticks_after = matrix::proc_ticks(&pids);
    let cpu_after = matrix::host_cpu()?;
    let disk_after = matrix::block_stats(measurement.root)?;
    let (after, _) = matrix::scrape(measurement.http, &all_endpoints).await;
    let successful = report.results["successful_reads"].as_u64().unwrap_or(0);
    let logical = report.results["logical_bytes"].as_u64().unwrap_or(0);
    let storage_bytes = metric_delta(&before, &after, "pepper_storage_block_read_bytes_total");
    let namespace_rpc_delta = |method: &str| {
        labelled_delta(&before, &after, "pepper_rpc_requests_total", |key| {
            key.contains("direction=\"outbound\"") && key.contains(&format!("method=\"{method}\""))
        })
    };
    let namespace_state_rpcs = namespace_rpc_delta("/namespace/state");
    let namespace_discovery_rpcs = namespace_rpc_delta("/namespace/discover");
    let namespace_alias_resolve_rpcs = namespace_rpc_delta("/namespace/alias/resolve");
    let namespace_alias_list_rpcs = namespace_rpc_delta("/namespace/alias/list");
    let namespace_rpcs = namespace_state_rpcs
        + namespace_discovery_rpcs
        + namespace_alias_resolve_rpcs
        + namespace_alias_list_rpcs;
    let block_rpc_bytes =
        labelled_delta(&before, &after, "pepper_rpc_response_bytes_total", |key| {
            key.contains("direction=\"outbound\"")
                && (key.contains("method=\"/block/get\"")
                    || key.contains("method=\"/relay/block_get\""))
        });
    let rpc_errors = labelled_delta(&before, &after, "pepper_rpc_errors_total", |key| {
        key.contains("direction=\"outbound\"")
    });
    let cache_hits = labelled_delta(
        &before,
        &after,
        "pepper_reconstructed_cache_requests_total",
        |key| key.contains("result=\"hit\""),
    );
    let cache_misses = labelled_delta(
        &before,
        &after,
        "pepper_reconstructed_cache_requests_total",
        |key| key.contains("result=\"miss\""),
    );
    let cache_admissions = metric_delta(
        &before,
        &after,
        "pepper_reconstructed_cache_admissions_total",
    );
    let cache_evictions = metric_delta(
        &before,
        &after,
        "pepper_reconstructed_cache_evictions_total",
    );
    let cache_bypasses = metric_delta(&before, &after, "pepper_reconstructed_cache_bypasses_total");
    let cache_integrity_failures = metric_delta(
        &before,
        &after,
        "pepper_reconstructed_cache_integrity_failures_total",
    );
    let cache_read_bytes = labelled_delta(
        &before,
        &after,
        "pepper_reconstructed_cache_bytes_total",
        |key| key.contains("direction=\"read\""),
    );
    let cache_write_bytes = labelled_delta(
        &before,
        &after,
        "pepper_reconstructed_cache_bytes_total",
        |key| key.contains("direction=\"write\""),
    );
    let systematic_range_bytes = metric_delta(
        &before,
        &after,
        "pepper_erasure_systematic_range_bytes_total",
    );
    let term_changes = raft_term_changes(&before, &after);
    let max_log_lag = after
        .values()
        .flat_map(|values| matrix::family(values, "pepper_namespace_log_lag"))
        .map(|(_, value)| *value)
        .fold(0.0, f64::max);
    let unhealthy_quorums = matrix::unhealthy_quorum_count(&after);
    let tick_rate = String::from_utf8(
        matrix::run_command(std::process::Command::new("getconf").arg("CLK_TCK"))?.stdout,
    )?
    .trim()
    .parse::<f64>()?;
    let total_cpu = cpu_after
        .iter()
        .sum::<u64>()
        .saturating_sub(cpu_before.iter().sum());
    let idle = cpu_after
        .get(3..5)
        .unwrap_or(&[])
        .iter()
        .sum::<u64>()
        .saturating_sub(cpu_before.get(3..5).unwrap_or(&[]).iter().sum());
    let mut value = serde_json::to_value(report)?;
    value["telemetry"] = json!({
        "pepper_cpu_cores": ticks_after.saturating_sub(ticks_before) as f64 / tick_rate / elapsed,
        "host_cpu_percent": if total_cpu > 0 { 100.0 * (total_cpu - idle) as f64 / total_cpu as f64 } else { 0.0 },
        "nvme": matrix::disk_delta(&disk_before, &disk_after, elapsed),
        "network": {"rx_bytes": network_after.0.saturating_sub(network_before.0), "tx_bytes": network_after.1.saturating_sub(network_before.1),
            "rx_mb_per_second": network_after.0.saturating_sub(network_before.0) as f64 / 1e6 / elapsed,
            "tx_mb_per_second": network_after.1.saturating_sub(network_before.1) as f64 / 1e6 / elapsed},
        "namespace_state_discovery_rpcs": namespace_rpcs,
        "namespace_state_discovery_rpcs_per_get": if successful > 0 { Some(namespace_rpcs / successful as f64) } else { None },
        "namespace_state_rpcs": namespace_state_rpcs,
        "namespace_discovery_rpcs": namespace_discovery_rpcs,
        "namespace_alias_resolve_rpcs": namespace_alias_resolve_rpcs,
        "namespace_alias_list_rpcs": namespace_alias_list_rpcs,
        "block_store_read_bytes": storage_bytes, "remote_block_rpc_response_bytes": block_rpc_bytes,
        "internal_read_bytes": storage_bytes + block_rpc_bytes,
        "logical_to_internal_byte_amplification": if logical > 0 { Some((storage_bytes + block_rpc_bytes) / logical as f64) } else { None },
        "systematic_range_bytes": systematic_range_bytes,
        "reconstructed_cache": {
            "hits": cache_hits,
            "misses": cache_misses,
            "hit_rate": if cache_hits + cache_misses > 0.0 { Some(cache_hits / (cache_hits + cache_misses)) } else { None },
            "admissions": cache_admissions,
            "evictions": cache_evictions,
            "bypasses": cache_bypasses,
            "integrity_failures": cache_integrity_failures,
            "read_bytes": cache_read_bytes,
            "write_bytes": cache_write_bytes,
        },
        "raft_term_changes": term_changes,
        "max_log_lag": max_log_lag,
        "unhealthy_quorums_at_end": unhealthy_quorums,
        "rpc_errors": rpc_errors,
    });
    Ok(value)
}

fn scenario_selection(value: &str) -> Result<BTreeSet<String>> {
    let selected = value
        .split(',')
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    for name in &selected {
        ensure!(
            ["independent-cold", "workload-cache-fill", "diagnostic"].contains(&name.as_str()),
            "unknown scenario {name}"
        );
    }
    Ok(selected)
}

pub async fn run(args: CacheFillArgs) -> Result<()> {
    ensure!(
        ["single", "three", "nine-ec"].contains(&args.topology.as_str()),
        "topology must be single, three, or nine-ec"
    );
    ensure!(
        args.upload_concurrency > 0,
        "upload-concurrency must be positive"
    );
    let sizes = parse_dataset(&args.dataset_spec)?;
    let concurrencies = parse_list::<usize>(&args.concurrency)?;
    ensure!(
        concurrencies.iter().all(|value| *value > 0),
        "concurrency must be positive"
    );
    let routings = args
        .routing
        .split(',')
        .map(str::to_string)
        .collect::<Vec<_>>();
    ensure!(
        routings
            .iter()
            .all(|value| value == "leader" || value == "follower"),
        "routing must contain leader and/or follower"
    );
    let scenarios = scenario_selection(&args.scenarios)?;
    let empty_manifest = DatasetManifest {
        schema_version: 1,
        block_size_bytes: BLOCK_BYTES,
        generator: GENERATOR.to_string(),
        bucket: BUCKET.to_string(),
        objects: expected_objects(&sizes)
            .into_iter()
            .map(|mut object| {
                object.block_sha256 =
                    vec![String::new(); object.size_bytes.div_ceil(BLOCK_BYTES) as usize];
                object
            })
            .collect(),
    };
    let queries = generate_queries(&empty_manifest, args.seed);
    let queries = &queries[..args.query_limit.min(queries.len())];
    let cell_count = concurrencies.len()
        * routings.len()
        * (usize::from(scenarios.contains("independent-cold"))
            + usize::from(scenarios.contains("workload-cache-fill"))
            + 2 * usize::from(scenarios.contains("diagnostic")));
    if args.dry_run {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"dataset_objects": sizes.len(), "dataset_bytes": sizes.iter().sum::<u64>(),
            "blocks": sizes.iter().sum::<u64>() / BLOCK_BYTES, "queries": queries.len(), "cells": cell_count,
            "concurrency": concurrencies, "routing": routings, "scenarios": scenarios})
            )?
        );
        return Ok(());
    }
    let requested_root = args
        .root
        .as_deref()
        .context("--root is required for a benchmark run; select a dedicated XFS data mount")?;
    let root = matrix::prepare_benchmark_root(requested_root)?;
    let filesystem = String::from_utf8(
        matrix::run_command(
            std::process::Command::new("findmnt")
                .args(["-n", "-o", "FSTYPE", "-T"])
                .arg(&root),
        )?
        .stdout,
    )?
    .trim()
    .to_string();
    ensure!(
        filesystem.eq_ignore_ascii_case("xfs"),
        "benchmark root must be on XFS, found {filesystem:?}"
    );
    for name in [
        "single", "single2", "single3", "node1", "node2", "node3", "ec1", "ec2", "ec3", "ec4",
        "ec5", "ec6", "ec7", "ec8", "ec9", "control",
    ] {
        let path = root.join(name);
        fs::create_dir_all(&path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o777))?;
    }
    let artifacts = args.artifacts.clone().unwrap_or_else(|| {
        root.join("artifacts")
            .join(time::OffsetDateTime::now_utc().unix_timestamp().to_string())
    });
    fs::create_dir_all(artifacts.join("cells"))?;
    matrix::stop_topology(&root);
    matrix::build_topology(&args.topology, &root)?;
    if args.fresh {
        matrix::reset_data(&args.topology, &root)?;
    }
    let http = Client::new();
    let result = async {
        matrix::start_topology(&http, &args.topology, &root).await?;
        let all_endpoints = matrix::topology_endpoints(&args.topology);
        matrix::ensure_bucket(&all_endpoints)?;
        matrix::wait_quorum(&http, &all_endpoints).await?;
        let upload_endpoints = matrix::routed_endpoints(&http, &args.topology, "leader", &all_endpoints).await;
        let manifest_path = root.join("dataset-manifest.json");
        let manifest = prepare_dataset(S3Client::new(upload_endpoints, args.upload_concurrency, args.timeout)?, &manifest_path, &sizes, args.upload_concurrency, args.retries).await?;
        fs::copy(&manifest_path, artifacts.join("dataset-manifest.json"))?;
        fs::write(artifacts.join("query-manifest.json"), serde_json::to_string_pretty(queries)? + "\n")?;
        let git_diff = std::process::Command::new("git").args(["diff", "--binary"]).output()?.stdout;
        fs::write(artifacts.join("manifest.json"), serde_json::to_string_pretty(&json!({"schema_version": 1,
            "git_commit": matrix::run_command(std::process::Command::new("git").args(["rev-parse", "HEAD"])) .ok().map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string()).unwrap_or_default(),
            "git_diff_sha256": hex::encode(Sha256::digest(git_diff)), "generator": GENERATOR,
            "endpoint_routing": "sha256-object-affinity-v1",
            "block_size_bytes": BLOCK_BYTES, "query_seed": args.seed, "filesystem": filesystem,
            "topology": args.topology, "dataset_spec": args.dataset_spec, "dataset_bytes": sizes.iter().sum::<u64>(),
            "query_count": queries.len(), "concurrency": concurrencies, "routing": routings, "scenarios": scenarios}))? + "\n")?;
        if args.prepare_only { return Ok(()); }
        let measurement = Measurement {
            root: &root,
            topology: &args.topology,
            http: &http,
            manifest: &manifest,
            queries,
            retries: args.retries,
        };
        for concurrency in &concurrencies {
            for routing in &routings {
                for (selected, scenario) in [("independent-cold", Scenario::IndependentCold), ("workload-cache-fill", Scenario::WorkloadCacheFill)] {
                    if !scenarios.contains(selected) { continue; }
                    let cell = format!("{}-c{}-{}", scenario.name(), concurrency, routing);
                    let path = artifacts.join("cells").join(format!("{cell}.json"));
                    if path.exists() { continue; }
                    let endpoints = matrix::routed_endpoints(&http, &args.topology, routing, &all_endpoints).await;
                    eprintln!("running {cell}");
                    let report = measured_cell(&measurement, endpoints, scenario, *concurrency, routing).await?;
                    fs::write(path, serde_json::to_string_pretty(&report)? + "\n")?;
                }
                if scenarios.contains("diagnostic") {
                    let warm_path = artifacts.join("cells").join(format!("diagnostic-warm-c{}-{}.json", concurrency, routing));
                    if warm_path.exists() { continue; }
                    matrix::stop_topology(&root);
                    make_data_readable(&root, &args.topology)?;
                    clear_reconstructed_cache(&root, &args.topology)?;
                    let eviction = evict_page_cache(&root, &args.topology)?;
                    matrix::start_topology(&http, &args.topology, &root).await?;
                    matrix::wait_quorum(&http, &all_endpoints).await?;
                    let endpoints = matrix::routed_endpoints(&http, &args.topology, routing, &all_endpoints).await;
                    eprintln!("running diagnostic-cold-c{}-{}", concurrency, routing);
                    let mut cold = measured_cell(&measurement, endpoints.clone(), Scenario::DiagnosticCold, *concurrency, routing).await?;
                    cold["page_cache_eviction"] = eviction;
                    fs::write(artifacts.join("cells").join(format!("diagnostic-cold-c{}-{}.json", concurrency, routing)), serde_json::to_string_pretty(&cold)? + "\n")?;
                    eprintln!("running diagnostic-warm-c{}-{}", concurrency, routing);
                    let warm = measured_cell(&measurement, endpoints, Scenario::DiagnosticWarm, *concurrency, routing).await?;
                    fs::write(warm_path, serde_json::to_string_pretty(&warm)? + "\n")?;
                }
            }
        }
        Ok(())
    }.await;
    matrix::stop_topology(&root);
    if result.is_ok() && !args.prepare_only {
        matrix::reclaim_data(&args.topology, &root)
            .context("failed to reclaim cache-fill benchmark data after a successful run")?;
        let manifest_path = root.join("dataset-manifest.json");
        if manifest_path.exists() {
            fs::remove_file(manifest_path)?;
        }
    }
    result
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(value, |current, key| current.get(key))
}

fn csv_value(value: Option<&Value>) -> String {
    let text = match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(text)) => text.clone(),
        Some(value) => value.to_string(),
    };
    if text.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text
    }
}

pub fn summarize(args: CacheFillSummaryArgs) -> Result<()> {
    let cell_fields: &[(&str, &[&str])] = &[
        ("scenario", &["scenario"]),
        ("routing", &["routing"]),
        ("concurrency", &["concurrency"]),
        ("query_count", &["query_count"]),
        ("elapsed_seconds", &["elapsed_seconds"]),
        ("requested_reads", &["results", "requested_reads"]),
        ("suppressed_reads", &["results", "suppressed_reads"]),
        ("successful_reads", &["results", "successful_reads"]),
        ("errors", &["results", "errors"]),
        ("retries", &["results", "retries"]),
        (
            "logical_requested_mb_per_second",
            &["results", "logical_requested_mb_per_second"],
        ),
        (
            "range_latency_p50_ms",
            &["results", "range_latency_ms", "p50"],
        ),
        (
            "range_latency_p95_ms",
            &["results", "range_latency_ms", "p95"],
        ),
        (
            "range_latency_p99_ms",
            &["results", "range_latency_ms", "p99"],
        ),
        ("pepper_cpu_cores", &["telemetry", "pepper_cpu_cores"]),
        (
            "nvme_read_mb_per_second",
            &["telemetry", "nvme", "read_mb_per_second"],
        ),
        (
            "nvme_write_mb_per_second",
            &["telemetry", "nvme", "write_mb_per_second"],
        ),
        ("nvme_busy_percent", &["telemetry", "nvme", "busy_percent"]),
        (
            "network_rx_mb_per_second",
            &["telemetry", "network", "rx_mb_per_second"],
        ),
        (
            "network_tx_mb_per_second",
            &["telemetry", "network", "tx_mb_per_second"],
        ),
        (
            "namespace_state_discovery_rpcs_per_get",
            &["telemetry", "namespace_state_discovery_rpcs_per_get"],
        ),
        (
            "logical_to_internal_byte_amplification",
            &["telemetry", "logical_to_internal_byte_amplification"],
        ),
        (
            "reconstructed_cache_hits",
            &["telemetry", "reconstructed_cache", "hits"],
        ),
        (
            "reconstructed_cache_misses",
            &["telemetry", "reconstructed_cache", "misses"],
        ),
        (
            "reconstructed_cache_hit_rate",
            &["telemetry", "reconstructed_cache", "hit_rate"],
        ),
        (
            "reconstructed_cache_admissions",
            &["telemetry", "reconstructed_cache", "admissions"],
        ),
        (
            "reconstructed_cache_evictions",
            &["telemetry", "reconstructed_cache", "evictions"],
        ),
        (
            "reconstructed_cache_bypasses",
            &["telemetry", "reconstructed_cache", "bypasses"],
        ),
        (
            "reconstructed_cache_integrity_failures",
            &["telemetry", "reconstructed_cache", "integrity_failures"],
        ),
        ("raft_term_changes", &["telemetry", "raft_term_changes"]),
        ("max_log_lag", &["telemetry", "max_log_lag"]),
        (
            "unhealthy_quorums_at_end",
            &["telemetry", "unhealthy_quorums_at_end"],
        ),
        ("rpc_errors", &["telemetry", "rpc_errors"]),
    ];
    let query_fields: &[(&str, &[&str])] = &[
        ("query_index", &["query_index"]),
        ("class", &["class"]),
        ("target_overlap_percent", &["target_overlap_percent"]),
        ("selected_blocks", &["selected_blocks"]),
        ("metadata_lookups", &["metadata_lookups"]),
        ("metadata_errors", &["metadata_errors"]),
        ("requested_reads", &["requested_reads"]),
        ("suppressed_reads", &["suppressed_reads"]),
        ("successful_reads", &["successful_reads"]),
        ("errors", &["errors"]),
        ("retries", &["retries"]),
        ("logical_bytes", &["logical_bytes"]),
        ("cache_fill_latency_ms", &["cache_fill_latency_ms"]),
    ];
    let mut paths = fs::read_dir(args.artifacts.join("cells"))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    let mut cells = vec![
        cell_fields
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(","),
    ];
    let mut queries = vec![
        std::iter::once("scenario")
            .chain(std::iter::once("routing"))
            .chain(std::iter::once("concurrency"))
            .chain(query_fields.iter().map(|(name, _)| *name))
            .collect::<Vec<_>>()
            .join(","),
    ];
    for path in paths {
        let report: Value = serde_json::from_slice(&fs::read(path)?)?;
        cells.push(
            cell_fields
                .iter()
                .map(|(_, path)| csv_value(value_at(&report, path)))
                .collect::<Vec<_>>()
                .join(","),
        );
        for query in report["queries"].as_array().into_iter().flatten() {
            let mut row = vec![
                csv_value(report.get("scenario")),
                csv_value(report.get("routing")),
                csv_value(report.get("concurrency")),
            ];
            row.extend(
                query_fields
                    .iter()
                    .map(|(_, path)| csv_value(value_at(query, path))),
            );
            queries.push(row.join(","));
        }
    }
    fs::write(
        args.artifacts.join("cache-fill-summary.csv"),
        cells.join("\n") + "\n",
    )?;
    fs::write(
        args.artifacts.join("cache-fill-queries.csv"),
        queries.join("\n") + "\n",
    )?;
    println!(
        "wrote {} cells and {} queries",
        cells.len() - 1,
        queries.len() - 1
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_blocks_are_deterministic_and_unique() {
        let first = generated_block(1, 2, 1024);
        assert_eq!(first, generated_block(1, 2, 1024));
        assert_ne!(first, generated_block(1, 3, 1024));
        assert!(first.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn object_routes_are_stable_across_requests() {
        let client = S3Client::new(
            vec!["http://one".to_string(), "http://two".to_string()],
            2,
            1,
        )
        .unwrap();
        let first = client.endpoint("object-a").to_string();
        assert_eq!(client.endpoint("object-a"), first);
        assert_eq!(client.endpoint("object-a"), first);
    }

    #[test]
    fn default_query_mix_has_expected_shape() {
        let sizes = parse_dataset(DEFAULT_DATASET).unwrap();
        let manifest = DatasetManifest {
            schema_version: 1,
            block_size_bytes: BLOCK_BYTES,
            generator: GENERATOR.to_string(),
            bucket: BUCKET.to_string(),
            objects: expected_objects(&sizes)
                .into_iter()
                .map(|mut object| {
                    object.block_sha256 =
                        vec![String::new(); object.size_bytes.div_ceil(BLOCK_BYTES) as usize];
                    object
                })
                .collect(),
        };
        let queries = generate_queries(&manifest, 7);
        assert_eq!(queries.len(), 43);
        assert_eq!(
            queries
                .iter()
                .filter(|query| query.class == "highly-selective")
                .count(),
            10
        );
        assert_eq!(
            queries
                .iter()
                .filter(|query| query.class == "selective-aggregation")
                .count(),
            12
        );
        assert_eq!(
            queries
                .iter()
                .filter(|query| query.class == "broad-aggregation")
                .count(),
            12
        );
        assert_eq!(
            queries
                .iter()
                .filter(|query| query.class == "wide-scan")
                .count(),
            6
        );
        assert_eq!(
            queries
                .iter()
                .filter(|query| query.class == "high-fanout-metadata")
                .count(),
            3
        );
        assert!(
            queries
                .iter()
                .flat_map(|query| &query.blocks)
                .all(|block| block.block < manifest.objects[block.object].block_sha256.len())
        );
    }
}
