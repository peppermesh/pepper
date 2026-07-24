// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, ensure};
use clap::Parser;
use futures_util::{StreamExt, stream};
use pepper_filesystem::{InodeKind, TreeEntry, TreeInputEntry};
use pepper_types::{Cid, DurabilityReceipt};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Parser)]
#[command(name = "pepper-filesystem-benchmark")]
#[command(about = "Measure Pepper filesystem upload, commit, checkout, and materialization")]
struct Args {
    #[arg(long, env = "PEPPER_API", default_value = "http://127.0.0.1:9080")]
    api: String,

    #[arg(long, env = "PEPPER_API_TOKEN")]
    api_token: Option<String>,

    /// Existing disk-backed directory used for checkout materialization.
    #[arg(long)]
    scratch_directory: PathBuf,

    #[arg(long, default_value_t = 1_000)]
    files: u32,

    #[arg(long, default_value_t = 4_096)]
    file_bytes: u32,

    #[arg(long, default_value_t = 16)]
    files_per_directory: u32,

    /// Percent of files replaced before each measured commit.
    #[arg(long, default_value_t = 10)]
    mutation_percent: u32,

    #[arg(long, default_value_t = 10)]
    iterations: u32,

    #[arg(long, default_value_t = 16)]
    upload_concurrency: usize,

    #[arg(long)]
    output: PathBuf,

    #[arg(long, default_value = "unspecified")]
    environment_label: String,
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    generated_at_unix_millis: u128,
    environment_label: String,
    configuration: Configuration,
    filesystem_alias: String,
    namespace_id: String,
    initial_upload: Workload,
    initial_commit: Workload,
    mutation_upload: Workload,
    mutation_commit: Workload,
    checkout_resolution: Workload,
    checkout_materialization: Workload,
    end_to_end_mutation_commit: Workload,
    mutation_wall_time_attribution: WallTimeAttribution,
    final_revision: u64,
    final_root_cid: String,
    final_file_count: u64,
    final_logical_bytes: u64,
    verified_files: u64,
    verified_bytes: u64,
    metrics_delta: BTreeMap<String, f64>,
    metrics_before: String,
    metrics_after: String,
}

#[derive(Debug, Serialize)]
struct Configuration {
    api: String,
    scratch_directory: String,
    files: u32,
    file_bytes: u32,
    files_per_directory: u32,
    mutation_percent: u32,
    mutated_files_per_iteration: u32,
    iterations: u32,
    upload_concurrency: usize,
}

#[derive(Debug, Serialize)]
struct Workload {
    samples: usize,
    operations: u64,
    elapsed_seconds: f64,
    operations_per_second: f64,
    latency_microseconds: Latency,
}

#[derive(Debug, Serialize)]
struct Latency {
    minimum: f64,
    p50: f64,
    p95: f64,
    p99: f64,
    maximum: f64,
    mean: f64,
}

#[derive(Debug, Serialize)]
struct WallTimeAttribution {
    end_to_end_microseconds: f64,
    named_upload_microseconds: f64,
    named_commit_microseconds: f64,
    attributed_microseconds: f64,
    coverage_percent: f64,
    passes_95_percent_gate: bool,
}

#[derive(Debug, Clone)]
struct FileState {
    path: String,
    cid: Cid,
    generation: u32,
}

#[derive(Debug, serde::Deserialize)]
struct CreateResponse {
    namespace_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct CommitResponse {
    namespace_revision: u64,
    filesystem_root_cid: Cid,
    filesystem: pepper_filesystem::FilesystemRootDescriptor,
}

#[derive(Debug, serde::Deserialize)]
struct CheckoutResponse {
    namespace_revision: u64,
    filesystem_root_cid: Cid,
    filesystem: pepper_filesystem::FilesystemRootDescriptor,
    entries: Vec<TreeEntry>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    validate(&args)?;
    let scratch = prepare_scratch(&args.scratch_directory)?;
    let result = run(&args, &scratch).await;
    let cleanup = fs::remove_dir_all(&scratch)
        .with_context(|| format!("remove benchmark scratch {}", scratch.display()));
    result.and(cleanup)
}

async fn run(args: &Args, scratch: &Path) -> Result<()> {
    let client = client(args.api_token.as_deref())?;
    let metrics_before = get_text(&client, &format!("{}/metrics", base(&args.api))).await?;
    let alias = format!("phase0-fs-{}", unix_millis()?);
    let create: CreateResponse = post_json(
        &client,
        &format!("{}/v1/filesystems", base(&args.api)),
        &serde_json::json!({"alias": alias}),
    )
    .await?;

    let initial_started = Instant::now();
    let files = upload_files(&client, args, 0, 0..args.files).await?;
    let initial_upload_elapsed = initial_started.elapsed();
    let initial_upload = workload(
        &[initial_upload_elapsed],
        u64::from(args.files),
        initial_upload_elapsed,
    );

    let entries = tree_entries(&files, args.files_per_directory, args.file_bytes);
    let commit_started = Instant::now();
    let mut committed = commit(&client, args, &alias, 0, &entries, "initial").await?;
    let initial_commit_elapsed = commit_started.elapsed();
    let initial_commit = workload(&[initial_commit_elapsed], 1, initial_commit_elapsed);

    let mutated_files = mutated_files(args);
    let mut state = files;
    let mut upload_samples = Vec::with_capacity(args.iterations as usize);
    let mut commit_samples = Vec::with_capacity(args.iterations as usize);
    let mut total_samples = Vec::with_capacity(args.iterations as usize);
    let mut checkout_samples = Vec::with_capacity(args.iterations as usize);
    let mut materialize_samples = Vec::with_capacity(args.iterations as usize);
    let mut verified_files = 0;
    let mut verified_bytes = 0;

    for iteration in 1..=args.iterations {
        let selected = mutation_indices(args.files, mutated_files, iteration);
        let total_started = Instant::now();
        let upload_started = Instant::now();
        let replacements = upload_files(&client, args, iteration, selected.iter().copied()).await?;
        upload_samples.push(upload_started.elapsed());
        for (index, replacement) in replacements {
            state.insert(index, replacement);
        }

        let entries = tree_entries(&state, args.files_per_directory, args.file_bytes);
        let commit_started = Instant::now();
        committed = commit(
            &client,
            args,
            &alias,
            committed.namespace_revision,
            &entries,
            &format!("iteration-{iteration}"),
        )
        .await?;
        commit_samples.push(commit_started.elapsed());
        total_samples.push(total_started.elapsed());

        let checkout_started = Instant::now();
        let checkout: CheckoutResponse = post_json(
            &client,
            &format!("{}/v1/fs/checkout", base(&args.api)),
            &serde_json::json!({"filesystem": alias, "revision": committed.namespace_revision}),
        )
        .await?;
        checkout_samples.push(checkout_started.elapsed());
        ensure!(
            checkout.namespace_revision == committed.namespace_revision
                && checkout.filesystem_root_cid == committed.filesystem_root_cid
                && checkout.filesystem == committed.filesystem,
            "checkout returned a different committed revision"
        );

        let destination = scratch.join(format!("checkout-{iteration:04}"));
        let materialize_started = Instant::now();
        let verified = materialize_and_verify(
            &client,
            &args.api,
            &destination,
            &checkout.entries,
            &state,
            args.upload_concurrency,
        )
        .await?;
        materialize_samples.push(materialize_started.elapsed());
        verified_files += verified.0;
        verified_bytes += verified.1;
        fs::remove_dir_all(&destination)
            .with_context(|| format!("remove {}", destination.display()))?;
    }

    let metrics_after = get_text(&client, &format!("{}/metrics", base(&args.api))).await?;
    let metrics_delta = selected_metric_delta(&metrics_before, &metrics_after);
    let end_to_end_micros = sum(&total_samples).as_secs_f64() * 1_000_000.0;
    let named_upload_micros = sum(&upload_samples).as_secs_f64() * 1_000_000.0;
    let named_commit_micros = sum(&commit_samples).as_secs_f64() * 1_000_000.0;
    let attributed_micros = (named_upload_micros + named_commit_micros).min(end_to_end_micros);
    let attribution_percent = if end_to_end_micros > 0.0 {
        100.0 * attributed_micros / end_to_end_micros
    } else {
        0.0
    };
    ensure!(
        committed.filesystem.file_count == u64::from(args.files),
        "final file count differs"
    );
    ensure!(
        committed.filesystem.logical_bytes == u64::from(args.files) * u64::from(args.file_bytes),
        "final logical byte count differs"
    );
    let report = Report {
        schema_version: 1,
        generated_at_unix_millis: unix_millis()?,
        environment_label: args.environment_label.clone(),
        configuration: Configuration {
            api: args.api.clone(),
            scratch_directory: args.scratch_directory.display().to_string(),
            files: args.files,
            file_bytes: args.file_bytes,
            files_per_directory: args.files_per_directory,
            mutation_percent: args.mutation_percent,
            mutated_files_per_iteration: mutated_files,
            iterations: args.iterations,
            upload_concurrency: args.upload_concurrency,
        },
        filesystem_alias: alias,
        namespace_id: create.namespace_id,
        initial_upload,
        initial_commit,
        mutation_upload: workload(
            &upload_samples,
            u64::from(mutated_files) * u64::from(args.iterations),
            sum(&upload_samples),
        ),
        mutation_commit: workload(
            &commit_samples,
            u64::from(args.iterations),
            sum(&commit_samples),
        ),
        checkout_resolution: workload(
            &checkout_samples,
            u64::from(args.iterations),
            sum(&checkout_samples),
        ),
        checkout_materialization: workload(
            &materialize_samples,
            u64::from(args.files) * u64::from(args.iterations),
            sum(&materialize_samples),
        ),
        end_to_end_mutation_commit: workload(
            &total_samples,
            u64::from(args.iterations),
            sum(&total_samples),
        ),
        mutation_wall_time_attribution: WallTimeAttribution {
            end_to_end_microseconds: end_to_end_micros,
            named_upload_microseconds: named_upload_micros,
            named_commit_microseconds: named_commit_micros,
            attributed_microseconds: attributed_micros,
            coverage_percent: attribution_percent,
            passes_95_percent_gate: attribution_percent >= 95.0,
        },
        final_revision: committed.namespace_revision,
        final_root_cid: committed.filesystem_root_cid.to_string(),
        final_file_count: committed.filesystem.file_count,
        final_logical_bytes: committed.filesystem.logical_bytes,
        verified_files,
        verified_bytes,
        metrics_delta,
        metrics_before,
        metrics_after,
    };
    if let Some(parent) = args
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(&args.output, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("write {}", args.output.display()))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn validate(args: &Args) -> Result<()> {
    ensure!(args.files > 0, "--files must be positive");
    ensure!(args.file_bytes > 0, "--file-bytes must be positive");
    ensure!(
        args.files_per_directory > 0,
        "--files-per-directory must be positive"
    );
    ensure!(
        (1..=100).contains(&args.mutation_percent),
        "--mutation-percent must be between 1 and 100"
    );
    ensure!(args.iterations > 0, "--iterations must be positive");
    ensure!(
        args.upload_concurrency > 0,
        "--upload-concurrency must be positive"
    );
    ensure!(
        args.scratch_directory.is_dir(),
        "scratch directory does not exist or is not a directory"
    );
    ensure!(
        !args.output.as_os_str().is_empty(),
        "--output must not be empty"
    );
    Ok(())
}

fn prepare_scratch(parent: &Path) -> Result<PathBuf> {
    let path = parent.join(format!(
        "pepper-filesystem-benchmark-{}-{}",
        std::process::id(),
        unix_millis()?
    ));
    fs::create_dir(&path).with_context(|| format!("create {}", path.display()))?;
    Ok(path)
}

async fn upload_files<I>(
    client: &reqwest::Client,
    args: &Args,
    generation: u32,
    indices: I,
) -> Result<BTreeMap<u32, FileState>>
where
    I: IntoIterator<Item = u32>,
{
    let api = args.api.clone();
    let file_bytes = args.file_bytes;
    let files_per_directory = args.files_per_directory;
    let uploads = stream::iter(indices.into_iter().map(|index| {
        let client = client.clone();
        let api = api.clone();
        async move {
            let payload = file_payload(index, generation, file_bytes);
            let receipt = client
                .post(format!("{}/v1/objects?pin=false", base(&api)))
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .header(reqwest::header::CONTENT_LENGTH, payload.len())
                .body(payload)
                .send()
                .await
                .context("upload filesystem benchmark content")?
                .error_for_status()
                .context("Pepper rejected filesystem benchmark content")?
                .json::<DurabilityReceipt>()
                .await
                .context("decode filesystem content receipt")?;
            Ok::<_, anyhow::Error>((
                index,
                FileState {
                    path: file_path(index, files_per_directory),
                    cid: receipt.cid,
                    generation,
                },
            ))
        }
    }))
    .buffer_unordered(args.upload_concurrency);
    tokio::pin!(uploads);
    let mut output = BTreeMap::new();
    while let Some(result) = uploads.next().await {
        let (index, state) = result?;
        output.insert(index, state);
    }
    Ok(output)
}

fn tree_entries(
    files: &BTreeMap<u32, FileState>,
    files_per_directory: u32,
    file_bytes: u32,
) -> Vec<TreeInputEntry> {
    let directory_count = files
        .len()
        .div_ceil(usize::try_from(files_per_directory).unwrap());
    let mut entries = (0..directory_count)
        .map(|directory| TreeInputEntry {
            path: format!("dir-{directory:06}"),
            kind: InodeKind::Directory,
            mode: 0o755,
            logical_size: 0,
            content_cid: None,
        })
        .collect::<Vec<_>>();
    entries.extend(files.values().map(|file| TreeInputEntry {
        path: file.path.clone(),
        kind: InodeKind::RegularFile,
        mode: 0o644,
        logical_size: u64::from(file_bytes),
        content_cid: Some(file.cid.clone()),
    }));
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries
}

async fn commit(
    client: &reqwest::Client,
    args: &Args,
    alias: &str,
    base_revision: u64,
    entries: &[TreeInputEntry],
    message: &str,
) -> Result<CommitResponse> {
    post_json(
        client,
        &format!("{}/v1/fs/commit", base(&args.api)),
        &serde_json::json!({
            "filesystem": alias,
            "base_revision": base_revision,
            "entries": entries,
            "root_mode": 0o755,
            "message": message,
            "request_id": format!("phase0-fs-{alias}-{base_revision}")
        }),
    )
    .await
}

async fn materialize_and_verify(
    client: &reqwest::Client,
    api: &str,
    destination: &Path,
    entries: &[TreeEntry],
    expected: &BTreeMap<u32, FileState>,
    concurrency: usize,
) -> Result<(u64, u64)> {
    fs::create_dir(destination)?;
    for entry in entries
        .iter()
        .filter(|entry| entry.inode.kind == InodeKind::Directory)
    {
        fs::create_dir_all(destination.join(&entry.path))?;
    }
    let expected_by_path = expected
        .values()
        .map(|file| (file.path.clone(), file.clone()))
        .collect::<BTreeMap<_, _>>();
    let downloads = stream::iter(
        entries
            .iter()
            .filter(|entry| entry.inode.kind == InodeKind::RegularFile)
            .cloned()
            .map(|entry| {
                let client = client.clone();
                let api = api.to_string();
                let destination = destination.to_path_buf();
                let expected = expected_by_path.get(&entry.path).cloned();
                async move {
                    let expected = expected.context("checkout returned unexpected file")?;
                    ensure!(
                        entry.inode.content_cid.as_ref() == Some(&expected.cid),
                        "checkout content CID differs for {}",
                        entry.path
                    );
                    let payload = get_bytes(&client, &object_url(&api, &expected.cid)?).await?;
                    ensure!(
                        payload.len() as u64 == entry.inode.logical_size,
                        "checkout length differs for {}",
                        entry.path
                    );
                    let correct = file_payload(
                        file_index_from_path(&expected.path)?,
                        expected.generation,
                        u32::try_from(entry.inode.logical_size).context("payload too large")?,
                    );
                    ensure!(
                        payload == correct,
                        "checkout bytes differ for {}",
                        entry.path
                    );
                    let target = destination.join(&entry.path);
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&target, &payload)?;
                    Ok::<_, anyhow::Error>((1u64, payload.len() as u64))
                }
            }),
    )
    .buffer_unordered(concurrency);
    tokio::pin!(downloads);
    let mut files = 0;
    let mut bytes = 0;
    while let Some(result) = downloads.next().await {
        let verified = result?;
        files += verified.0;
        bytes += verified.1;
    }
    ensure!(
        usize::try_from(files).ok() == Some(expected.len()),
        "checkout file count differs"
    );
    Ok((files, bytes))
}

fn file_payload(index: u32, generation: u32, bytes: u32) -> Vec<u8> {
    let mut output = Vec::with_capacity(bytes as usize);
    let mut counter = 0u64;
    while output.len() < bytes as usize {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pepper-filesystem-benchmark-v1");
        hasher.update(&index.to_le_bytes());
        hasher.update(&generation.to_le_bytes());
        hasher.update(&counter.to_le_bytes());
        output.extend_from_slice(hasher.finalize().as_bytes());
        counter += 1;
    }
    output.truncate(bytes as usize);
    output
}

fn file_path(index: u32, files_per_directory: u32) -> String {
    format!("dir-{:06}/file-{index:09}.bin", index / files_per_directory)
}

fn file_index_from_path(path: &str) -> Result<u32> {
    let name = path
        .rsplit('/')
        .next()
        .context("file path has no final component")?;
    name.strip_prefix("file-")
        .and_then(|name| name.strip_suffix(".bin"))
        .context("unexpected benchmark file path")?
        .parse()
        .context("invalid benchmark file index")
}

fn mutation_indices(files: u32, mutated: u32, iteration: u32) -> Vec<u32> {
    let start = (iteration.wrapping_mul(mutated)) % files;
    (0..mutated)
        .map(|offset| (start + offset) % files)
        .collect()
}

fn mutated_files(args: &Args) -> u32 {
    (u64::from(args.files) * u64::from(args.mutation_percent))
        .div_ceil(100)
        .max(1) as u32
}

fn workload(samples: &[Duration], operations: u64, elapsed: Duration) -> Workload {
    let mut micros = samples
        .iter()
        .map(|sample| sample.as_secs_f64() * 1_000_000.0)
        .collect::<Vec<_>>();
    micros.sort_by(f64::total_cmp);
    let elapsed_seconds = elapsed.as_secs_f64();
    Workload {
        samples: samples.len(),
        operations,
        elapsed_seconds,
        operations_per_second: if elapsed_seconds == 0.0 {
            0.0
        } else {
            operations as f64 / elapsed_seconds
        },
        latency_microseconds: Latency {
            minimum: micros.first().copied().unwrap_or_default(),
            p50: percentile(&micros, 0.50),
            p95: percentile(&micros, 0.95),
            p99: percentile(&micros, 0.99),
            maximum: micros.last().copied().unwrap_or_default(),
            mean: if micros.is_empty() {
                0.0
            } else {
                micros.iter().sum::<f64>() / micros.len() as f64
            },
        },
    }
}

fn percentile(sorted: &[f64], quantile: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() - 1) as f64 * quantile).ceil() as usize;
    sorted[index]
}

fn sum(samples: &[Duration]) -> Duration {
    samples.iter().copied().sum()
}

fn client(token: Option<&str>) -> Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(token) = token {
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))?,
        );
    }
    reqwest::Client::builder()
        .default_headers(headers)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30 * 60))
        .build()
        .context("build HTTP client")
}

async fn post_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    body: &serde_json::Value,
) -> Result<T> {
    client
        .post(url)
        .json(body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper rejected POST {url}"))?
        .json()
        .await
        .with_context(|| format!("decode POST {url}"))
}

async fn get_text(client: &reqwest::Client, url: &str) -> Result<String> {
    client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper rejected GET {url}"))?
        .text()
        .await
        .with_context(|| format!("read GET {url}"))
}

async fn get_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    Ok(client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper rejected GET {url}"))?
        .bytes()
        .await
        .with_context(|| format!("read GET {url}"))?
        .to_vec())
}

fn base(api: &str) -> &str {
    api.trim_end_matches('/')
}

const COST_METRICS: &[&str] = &[
    "pepper_explicit_payload_allocations_total",
    "pepper_explicit_payload_allocated_bytes_total",
    "pepper_explicit_payload_copy_operations_total",
    "pepper_explicit_payload_copy_bytes_total",
    "pepper_shared_payload_references_total",
    "pepper_storage_data_durability_barriers_total",
    "pepper_storage_directory_durability_barriers_total",
    "pepper_storage_native_durability_barriers_total",
    "pepper_storage_native_write_bytes_total",
    "pepper_rpc_request_bytes_total",
    "pepper_rpc_response_bytes_total",
    "pepper_merkle_nodes_read_total",
    "pepper_merkle_nodes_written_total",
    "pepper_namespace_commit_latency_microseconds_total",
    "pepper_raft_proposal_queue_microseconds_total",
    "pepper_raft_proposal_execution_microseconds_total",
];

fn selected_metric_delta(before: &str, after: &str) -> BTreeMap<String, f64> {
    COST_METRICS
        .iter()
        .map(|name| {
            (
                (*name).to_string(),
                (metric_total(after, name) - metric_total(before, name)).max(0.0),
            )
        })
        .collect()
}

fn metric_total(text: &str, name: &str) -> f64 {
    let mut exact = None;
    let mut labelled = 0.0;
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let Some((key, value)) = line.rsplit_once(' ') else {
            continue;
        };
        let Ok(value) = value.parse::<f64>() else {
            continue;
        };
        if key == name {
            exact = Some(value);
        } else if key
            .strip_prefix(name)
            .is_some_and(|suffix| suffix.starts_with('{'))
        {
            labelled += value;
        }
    }
    exact.unwrap_or(labelled)
}

fn object_url(api: &str, cid: &Cid) -> Result<String> {
    let mut url = reqwest::Url::parse(base(api)).context("parse Pepper API URL")?;
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("Pepper API URL cannot be a base URL"))?
        .extend(["v1", "objects", &cid.to_string()]);
    Ok(url.into())
}

fn unix_millis() -> Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time precedes Unix epoch")?
        .as_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_url_encodes_cid_as_one_path_segment() {
        let cid = Cid::new(pepper_types::CODEC_RAW, b"payload");
        let url = object_url("http://127.0.0.1:9080/", &cid).unwrap();

        assert!(url.starts_with("http://127.0.0.1:9080/v1/objects/cid:"));
        assert!(!url["http://127.0.0.1:9080/v1/objects/".len()..].contains('/'));
        assert!(url.contains("%2F%2F"));
    }

    #[test]
    fn metric_total_prefers_explicit_family_total() {
        let metrics = "metric_total 7\nmetric_total{kind=\"a\"} 3\nmetric_total{kind=\"b\"} 4\n";
        assert_eq!(metric_total(metrics, "metric_total"), 7.0);
        assert_eq!(
            metric_total(
                "only_labels{kind=\"a\"} 3\nonly_labels{kind=\"b\"} 4\n",
                "only_labels"
            ),
            7.0
        );
    }
}
