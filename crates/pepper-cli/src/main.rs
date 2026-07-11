// SPDX-License-Identifier: Apache-2.0

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pepper_network::PeerStatus;
use pepper_types::{
    CODEC_RAW, ComputeJobStatus, ComputeLogsResponse, DirEntry, DirManifest, DurabilityReceipt,
    GcReport, NodeStatus, PinCreateRequest, PinStatusResponse, SubmitComputeResponse,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};

static API_TOKEN: OnceLock<Option<String>> = OnceLock::new();

#[derive(Debug, Parser)]
#[command(name = "pepper", about = "Pepper command-line client")]
struct Args {
    /// Local Pepper agent API base URL.
    #[arg(
        long,
        global = true,
        env = "PEPPER_API",
        default_value = "http://127.0.0.1:9080"
    )]
    api: String,

    /// Emit JSON instead of human-readable output.
    #[arg(long, global = true)]
    json: bool,

    /// Bearer token for agents configured with auth.api_bearer_token.
    #[arg(long, global = true, env = "PEPPER_API_TOKEN")]
    api_token: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Node(NodeCommand),
    Block(BlockCommand),
    Object(ObjectCommand),
    Dir(DirCommand),
    Pin(PinCommand),
    Compute(ComputeCommand),
    Admin(AdminCommand),
}

#[derive(Debug, Parser)]
struct NodeCommand {
    #[command(subcommand)]
    command: NodeSubcommand,
}

#[derive(Debug, Subcommand)]
enum NodeSubcommand {
    /// Show local agent status.
    Status,
    /// Show P2P peers known by the local agent.
    Peers,
}

#[derive(Debug, Parser)]
struct ComputeCommand {
    #[command(subcommand)]
    command: ComputeSubcommand,
}

#[derive(Debug, Subcommand)]
enum ComputeSubcommand {
    /// Submit a local-runtime compute job JSON spec.
    Submit { path: PathBuf },
    /// Show compute job status.
    Status { job_id: String },
    /// Show compute job logs.
    Logs { job_id: String },
    /// Cancel a queued or delegated compute job.
    Cancel { job_id: String },
    /// Print output root CID for a compute job.
    Output { job_id: String },
}

#[derive(Debug, Parser)]
struct PinCommand {
    #[command(subcommand)]
    command: PinSubcommand,
}

#[derive(Debug, Subcommand)]
enum PinSubcommand {
    /// Pin a root CID for retention.
    Create {
        cid: String,
        #[arg(long)]
        replicas: Option<u16>,
    },
    /// Show pin status for a root CID.
    Status { cid: String },
    /// Delete pins for a root CID.
    Delete { cid: String },
}

#[derive(Debug, Parser)]
struct AdminCommand {
    #[command(subcommand)]
    command: AdminSubcommand,
}

#[derive(Debug, Subcommand)]
enum AdminSubcommand {
    /// Run local garbage collection.
    Gc {
        /// Report candidates without deleting them.
        #[arg(long)]
        dry_run: bool,
    },
    /// Run provider repair immediately.
    Repair,
    /// Show admin subsystem status.
    Status,
    /// Show storage summary.
    Storage,
    /// Show erasure-coding health and policy summary.
    Erasure,
    /// Verify local blocks and report corruption.
    CorruptionScan,
    /// Permanently remove quarantined invalid block files.
    QuarantinePurge,
}

#[derive(Debug, Parser)]
struct ObjectCommand {
    #[command(subcommand)]
    command: ObjectSubcommand,
}

#[derive(Debug, Subcommand)]
enum ObjectSubcommand {
    /// Store a file as a chunked object.
    Put {
        path: PathBuf,
        /// Store object data with Reed-Solomon erasure coding as DATA:PARITY shards.
        #[arg(long, value_name = "DATA:PARITY")]
        erasure: Option<String>,
    },
    /// Retrieve an object by root manifest CID.
    Get {
        cid: String,
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Debug, Parser)]
struct DirCommand {
    #[command(subcommand)]
    command: DirSubcommand,
}

#[derive(Debug, Subcommand)]
enum DirSubcommand {
    /// Store a directory snapshot.
    Put { path: PathBuf },
    /// Restore a directory snapshot.
    Get { cid: String, output: PathBuf },
}

#[derive(Debug, Parser)]
struct BlockCommand {
    #[command(subcommand)]
    command: BlockSubcommand,
}

#[derive(Debug, Subcommand)]
enum BlockSubcommand {
    /// Store a file as a raw immutable block.
    Put { path: PathBuf },
    /// Retrieve a block by CID.
    Get {
        cid: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Check whether the local agent has a block.
    Has { cid: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let _ = API_TOKEN.set(args.api_token.clone());
    match args.command {
        Command::Node(node) => match node.command {
            NodeSubcommand::Status => node_status(&args.api, args.json).await,
            NodeSubcommand::Peers => node_peers(&args.api, args.json).await,
        },
        Command::Block(block) => match block.command {
            BlockSubcommand::Put { path } => block_put(&args.api, args.json, path).await,
            BlockSubcommand::Get { cid, output } => block_get(&args.api, cid, output).await,
            BlockSubcommand::Has { cid } => block_has(&args.api, args.json, cid).await,
        },
        Command::Object(object) => match object.command {
            ObjectSubcommand::Put { path, erasure } => {
                object_put(&args.api, args.json, path, erasure).await
            }
            ObjectSubcommand::Get { cid, output } => object_get(&args.api, cid, output).await,
        },
        Command::Dir(dir) => match dir.command {
            DirSubcommand::Put { path } => dir_put(&args.api, args.json, path).await,
            DirSubcommand::Get { cid, output } => dir_get(&args.api, cid, output).await,
        },
        Command::Pin(pin) => match pin.command {
            PinSubcommand::Create { cid, replicas } => {
                pin_create(&args.api, args.json, cid, replicas).await
            }
            PinSubcommand::Status { cid } => pin_status(&args.api, args.json, cid).await,
            PinSubcommand::Delete { cid } => pin_delete(&args.api, args.json, cid).await,
        },
        Command::Compute(compute) => match compute.command {
            ComputeSubcommand::Submit { path } => compute_submit(&args.api, args.json, path).await,
            ComputeSubcommand::Status { job_id } => {
                compute_status(&args.api, args.json, job_id).await
            }
            ComputeSubcommand::Logs { job_id } => compute_logs(&args.api, args.json, job_id).await,
            ComputeSubcommand::Cancel { job_id } => {
                compute_cancel(&args.api, args.json, job_id).await
            }
            ComputeSubcommand::Output { job_id } => compute_output(&args.api, job_id).await,
        },
        Command::Admin(admin) => match admin.command {
            AdminSubcommand::Gc { dry_run } => admin_gc(&args.api, args.json, dry_run).await,
            AdminSubcommand::Repair => {
                admin_json_post(&args.api, args.json, &["v1", "admin", "repair"]).await
            }
            AdminSubcommand::Status => {
                admin_json_get(&args.api, args.json, &["v1", "admin", "status"]).await
            }
            AdminSubcommand::Storage => {
                admin_json_get(&args.api, args.json, &["v1", "admin", "storage"]).await
            }
            AdminSubcommand::Erasure => {
                admin_json_get(&args.api, args.json, &["v1", "admin", "erasure"]).await
            }
            AdminSubcommand::CorruptionScan => {
                admin_json_post(&args.api, args.json, &["v1", "admin", "corruption-scan"]).await
            }
            AdminSubcommand::QuarantinePurge => {
                admin_json_post(
                    &args.api,
                    args.json,
                    &["v1", "admin", "quarantine", "purge"],
                )
                .await
            }
        },
    }
}

fn http_client() -> Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(Some(token)) = API_TOKEN.get() {
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                .context("invalid API token header value")?,
        );
    }
    reqwest::Client::builder()
        .default_headers(headers)
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30 * 60))
        .build()
        .context("failed to build HTTP client")
}

async fn node_status(api: &str, json: bool) -> Result<()> {
    let url = format!("{}/v1/node/status", api.trim_end_matches('/'));
    let status = http_client()?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<NodeStatus>()
        .await
        .context("failed to decode node status response")?;

    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Node:        {}", status.name);
        println!("Node ID:     {}", status.node_id);
        println!("Uptime:      {}s", status.uptime_seconds);
        println!("Data path:   {}", status.config.data_path);
        println!("API:         {}", status.config.api_bind_addr);
        println!("P2P listen:  {}", status.config.listen_addr);
        println!("Schema:      {}", status.schema_version);
        println!("Storage locations:");
        if status.config.storage_locations.is_empty() {
            println!("  none configured");
        } else {
            for location in status.config.storage_locations {
                println!(
                    "  {} (max {} bytes)",
                    location.path, location.max_capacity_bytes
                );
            }
        }
        println!("Bootstrap peers: {}", status.config.bootstrap_peers.len());
    }

    Ok(())
}

async fn node_peers(api: &str, json: bool) -> Result<()> {
    let url = format!("{}/v1/node/peers", api.trim_end_matches('/'));
    let peers = http_client()?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<Vec<PeerStatus>>()
        .await
        .context("failed to decode peer status response")?;

    if json {
        println!("{}", serde_json::to_string_pretty(&peers)?);
    } else if peers.is_empty() {
        println!("No peers known");
    } else {
        for peer in peers {
            println!(
                "{} {} connected={} last_seen={}",
                peer.node_id, peer.name, peer.connected, peer.last_seen_unix_seconds
            );
            for address in peer.addresses {
                println!("  {address}");
            }
        }
    }
    Ok(())
}

async fn block_put(api: &str, json: bool, path: PathBuf) -> Result<()> {
    let bytes = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let url = format!("{}/v1/blocks", api.trim_end_matches('/'));
    let response = http_client()?
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .body(bytes)
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<DurabilityReceipt>()
        .await
        .context("failed to decode block put response")?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("CID:        {}", response.cid);
        println!("Size:       {} bytes", response.size);
        println!("Codec:      {}", response.codec.canonical_display());
        println!("Status:     {}", response.status);
        println!("Replicas:   {}", response.replicas_accepted);
        println!("Nodes:      {}", response.replica_nodes.join(", "));
    }
    Ok(())
}

async fn block_get(api: &str, cid: String, output: PathBuf) -> Result<()> {
    let url = block_url(api, &cid)?;
    download_to_file(url, &output).await?;
    println!("Wrote {}", output.display());
    Ok(())
}

async fn block_has(api: &str, json: bool, cid: String) -> Result<()> {
    let url = block_url(api, &cid)?;
    let status = http_client()?
        .head(url.clone())
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .status();
    let has_block = status.is_success();
    if json {
        println!("{}", serde_json::json!({ "cid": cid, "has": has_block }));
    } else if has_block {
        println!("yes");
    } else {
        println!("no");
    }
    if has_block {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

async fn compute_submit(api: &str, json: bool, path: PathBuf) -> Result<()> {
    let body = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let url = resource_url(api, &["v1", "compute", "jobs"])?;
    let response = http_client()?
        .post(url.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<SubmitComputeResponse>()
        .await
        .context("failed to decode compute submit response")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("Job ID: {}", response.job_id);
        println!("Status: {}", response.status);
    }
    Ok(())
}

async fn compute_status(api: &str, json: bool, job_id: String) -> Result<()> {
    let status = fetch_compute_status(api, &job_id).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Job ID: {}", status.job_id);
        println!("Status: {}", status.status);
        if let Some(code) = status.exit_code {
            println!("Exit:   {code}");
        }
        if let Some(cid) = status.output_root_cid {
            println!("Output: {cid}");
        }
        if let Some(error) = status.error {
            println!("Error:  {error}");
        }
    }
    Ok(())
}

async fn compute_cancel(api: &str, json: bool, job_id: String) -> Result<()> {
    let url = resource_url(api, &["v1", "compute", "jobs", &job_id, "cancel"])?;
    let status = http_client()?
        .post(url.clone())
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<ComputeJobStatus>()
        .await
        .context("failed to decode compute cancel response")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Job ID: {}", status.job_id);
        println!("Status: {}", status.status);
    }
    Ok(())
}

async fn compute_logs(api: &str, json: bool, job_id: String) -> Result<()> {
    let url = resource_url(api, &["v1", "compute", "jobs", &job_id, "logs"])?;
    let logs = http_client()?
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<ComputeLogsResponse>()
        .await
        .context("failed to decode compute logs response")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&logs)?);
    } else {
        println!("--- stdout ---\n{}", logs.stdout);
        println!("--- stderr ---\n{}", logs.stderr);
    }
    Ok(())
}

async fn compute_output(api: &str, job_id: String) -> Result<()> {
    let status = fetch_compute_status(api, &job_id).await?;
    if let Some(cid) = status.output_root_cid {
        println!("{cid}");
    }
    Ok(())
}

async fn fetch_compute_status(api: &str, job_id: &str) -> Result<ComputeJobStatus> {
    let url = resource_url(api, &["v1", "compute", "jobs", job_id])?;
    http_client()?
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<ComputeJobStatus>()
        .await
        .context("failed to decode compute status response")
}

async fn pin_create(api: &str, json: bool, cid: String, replicas: Option<u16>) -> Result<()> {
    let url = resource_url(api, &["v1", "pins"])?;
    let request = PinCreateRequest {
        root_cid: cid.parse()?,
        replication_factor: replicas,
        ttl_seconds: None,
    };
    let response = http_client()?
        .post(url.clone())
        .json(&request)
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<PinStatusResponse>()
        .await
        .context("failed to decode pin response")?;
    print_pin_status(&response, json)
}

async fn pin_status(api: &str, json: bool, cid: String) -> Result<()> {
    let url = resource_url(api, &["v1", "pins", &cid])?;
    let response = http_client()?
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<PinStatusResponse>()
        .await
        .context("failed to decode pin response")?;
    print_pin_status(&response, json)
}

async fn pin_delete(api: &str, json: bool, cid: String) -> Result<()> {
    let url = resource_url(api, &["v1", "pins", &cid])?;
    let response = http_client()?
        .delete(url.clone())
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<PinStatusResponse>()
        .await
        .context("failed to decode pin response")?;
    print_pin_status(&response, json)
}

async fn admin_json_get(api: &str, _json: bool, path: &[&str]) -> Result<()> {
    let url = resource_url(api, path)?;
    let response = http_client()?
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<serde_json::Value>()
        .await
        .context("failed to decode admin response")?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn admin_json_post(api: &str, _json: bool, path: &[&str]) -> Result<()> {
    let url = resource_url(api, path)?;
    let response = http_client()?
        .post(url.clone())
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<serde_json::Value>()
        .await
        .context("failed to decode admin response")?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn admin_gc(api: &str, json: bool, dry_run: bool) -> Result<()> {
    let mut url = resource_url(api, &["v1", "admin", "gc"])?;
    if dry_run {
        url.query_pairs_mut().append_pair("dry_run", "true");
    }
    let response = http_client()?
        .post(url.clone())
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<GcReport>()
        .await
        .context("failed to decode GC response")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("Protected: {}", response.protected_blocks);
        println!("Deleted:   {}", response.deleted_blocks);
        println!("Reclaimed: {} bytes", response.reclaimed_bytes);
    }
    Ok(())
}

fn print_pin_status(response: &PinStatusResponse, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(response)?);
    } else {
        println!("Root:      {}", response.root_cid);
        println!("Pins:      {}", response.pins.len());
        println!("Reachable: {}", response.reachable_count);
        for pin in &response.pins {
            println!(
                "  {} replicas={} status={}",
                pin.pin_id, pin.replication_factor, pin.status
            );
        }
    }
    Ok(())
}

async fn object_put(api: &str, json: bool, path: PathBuf, erasure: Option<String>) -> Result<()> {
    let response = put_object_file(api, &path, erasure.as_deref()).await?;
    print_receipt(&response, json)?;
    Ok(())
}

async fn object_get(api: &str, cid: String, output: PathBuf) -> Result<()> {
    let url = resource_url(api, &["v1", "objects", &cid])?;
    download_to_file(url, &output).await?;
    println!("Wrote {}", output.display());
    Ok(())
}

async fn dir_put(api: &str, json: bool, path: PathBuf) -> Result<()> {
    let mut entries = Vec::new();
    collect_dir_entries(api, &path, &path, &mut entries).await?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = DirManifest::new(entries);
    manifest.validate()?;
    let url = resource_url(api, &["v1", "dirs"])?;
    let response = http_client()?
        .post(url.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&manifest)?)
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<DurabilityReceipt>()
        .await
        .context("failed to decode directory put response")?;
    print_receipt(&response, json)?;
    Ok(())
}

async fn dir_get(api: &str, cid: String, output: PathBuf) -> Result<()> {
    #[cfg(unix)]
    if unsafe { geteuid() } == 0
        && std::env::var_os("PEPPER_ALLOW_ROOT_RESTORE").as_deref()
            != Some(std::ffi::OsStr::new("1"))
    {
        anyhow::bail!(
            "refusing directory restore as root; set PEPPER_ALLOW_ROOT_RESTORE=1 only for a trusted manifest and destination"
        );
    }
    let url = resource_url(api, &["v1", "dirs", &cid])?;
    let manifest = http_client()?
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<DirManifest>()
        .await
        .context("failed to decode directory manifest")?;
    manifest.validate()?;
    fs::create_dir_all(&output)
        .with_context(|| format!("failed to create {}", output.display()))?;
    let output = fs::canonicalize(&output)
        .with_context(|| format!("failed to resolve {}", output.display()))?;
    let mut directory_modes = Vec::new();
    for entry in manifest.entries {
        let target = safe_restore_path(&output, &entry.path)?;
        match entry.kind.as_str() {
            "directory" => {
                fs::create_dir_all(&target)
                    .with_context(|| format!("failed to create {}", target.display()))?;
                directory_modes.push((target, entry.mode));
            }
            "file" => {
                let cid = entry.cid.context("file entry missing cid")?;
                let cid_text = cid.to_string();
                let url = if cid.codec == CODEC_RAW {
                    resource_url(api, &["v1", "blocks", &cid_text])?
                } else {
                    resource_url(api, &["v1", "objects", &cid_text])?
                };
                download_to_file(url, &target).await?;
                set_mode(&target, entry.mode)?;
            }
            _ => {}
        }
    }
    directory_modes.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, mode) in directory_modes {
        set_mode(&path, mode)?;
    }
    println!("Restored {}", output.display());
    Ok(())
}

fn safe_restore_path(root: &Path, relative: &str) -> Result<PathBuf> {
    let mut current = root.to_path_buf();
    for component in relative.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            anyhow::bail!("unsafe directory manifest path: {relative}");
        }
        current.push(component);
        if current.exists() && fs::symlink_metadata(&current)?.file_type().is_symlink() {
            anyhow::bail!("refusing to restore through symlink {}", current.display());
        }
    }
    Ok(current)
}

fn parse_erasure_policy(value: &str) -> Result<(u16, u16)> {
    let (data, parity) = value
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("erasure policy must be DATA:PARITY"))?;
    let data = data
        .parse::<u16>()
        .context("invalid erasure data shard count")?;
    let parity = parity
        .parse::<u16>()
        .context("invalid erasure parity shard count")?;
    if data == 0 || parity == 0 || data.saturating_add(parity) > 32 {
        anyhow::bail!("erasure data/parity counts must be > 0 and sum to <= 32");
    }
    Ok((data, parity))
}

async fn put_object_file(
    api: &str,
    path: &Path,
    erasure: Option<&str>,
) -> Result<DurabilityReceipt> {
    let mut url = resource_url(api, &["v1", "objects"])?;
    if let Some(erasure) = erasure {
        let (data, parity) = parse_erasure_policy(erasure)?;
        url.query_pairs_mut()
            .append_pair("erasure_data_shards", &data.to_string())
            .append_pair("erasure_parity_shards", &parity.to_string());
    }
    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("failed to open {}", path.display()))?;
    let length = file
        .metadata()
        .await
        .with_context(|| format!("failed to stat {}", path.display()))?
        .len();
    let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file));
    http_client()?
        .post(url.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .header(reqwest::header::CONTENT_LENGTH, length)
        .body(body)
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?
        .json::<DurabilityReceipt>()
        .await
        .context("failed to decode object put response")
}

async fn collect_dir_entries(
    api: &str,
    root: &Path,
    current: &Path,
    entries: &mut Vec<DirEntry>,
) -> Result<()> {
    let mut stack = vec![current.to_path_buf()];
    while let Some(path) = stack.pop() {
        for child in
            fs::read_dir(&path).with_context(|| format!("failed to read {}", path.display()))?
        {
            let child = child?.path();
            let metadata = fs::symlink_metadata(&child)?;
            let relative = child
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            if metadata.is_dir() {
                entries.push(DirEntry {
                    path: relative,
                    kind: "directory".to_string(),
                    mode: mode(&metadata),
                    size: None,
                    cid: None,
                });
                stack.push(child);
            } else if metadata.is_file() {
                let receipt = put_object_file(api, &child, None).await?;
                entries.push(DirEntry {
                    path: relative,
                    kind: "file".to_string(),
                    mode: mode(&metadata),
                    size: Some(metadata.len()),
                    cid: Some(receipt.cid),
                });
            }
        }
    }
    Ok(())
}

fn print_receipt(response: &DurabilityReceipt, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(response)?);
    } else {
        println!("CID:        {}", response.cid);
        println!("Size:       {} bytes", response.size);
        println!("Codec:      {}", response.codec.canonical_display());
        println!("Status:     {}", response.status);
        println!("Replicas:   {}", response.replicas_accepted);
        println!("Nodes:      {}", response.replica_nodes.join(", "));
    }
    Ok(())
}

async fn download_to_file(url: reqwest::Url, path: &Path) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut response = http_client()?
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?
        .error_for_status()
        .with_context(|| format!("Pepper agent returned an error for {url}"))?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = path.with_extension(format!("pepper-tmp-{}-{nonce}", std::process::id()));
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .await
        .with_context(|| format!("failed to create {}", temp.display()))?;
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read response body")?
    {
        file.write_all(&chunk).await?;
    }
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(&temp, path)
        .await
        .with_context(|| format!("failed to install {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode(_metadata: &fs::Metadata) -> u32 {
    0o644
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(mode & 0o777);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
unsafe extern "C" {
    fn geteuid() -> u32;
}

fn resource_url(api: &str, segments: &[&str]) -> Result<reqwest::Url> {
    let mut base = reqwest::Url::parse(api.trim_end_matches('/'))?;
    base.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("agent API URL cannot be a base for path segments"))?
        .extend(segments.iter().copied());
    Ok(base)
}

fn block_url(api: &str, cid: &str) -> Result<reqwest::Url> {
    let mut base = reqwest::Url::parse(api.trim_end_matches('/'))?;
    base.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("agent API URL cannot be a base for path segments"))?
        .extend(["v1", "blocks", cid]);
    Ok(base)
}
