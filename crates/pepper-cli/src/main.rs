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
static JSON_OUTPUT: OnceLock<bool> = OnceLock::new();

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
    Namespace(NamespaceCliCommand),
    Kv(KvCommand),
    Bucket(BucketCommand),
    Fs(FsCommand),
    Sqlite(SqliteCommand),
    Admin(AdminCommand),
}

#[derive(Debug, Parser)]
struct SqliteCommand {
    #[command(subcommand)]
    command: SqliteSubcommand,
}

#[derive(Debug, Subcommand)]
enum SqliteSubcommand {
    Create {
        database: String,
        #[arg(long)]
        page_size: Option<u32>,
        #[arg(long)]
        request_id: Option<String>,
    },
    Info {
        database: String,
    },
    Import {
        database: String,
        path: PathBuf,
        #[arg(long)]
        request_id: Option<String>,
    },
    Export {
        database: String,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        snapshot: Option<String>,
        #[arg(long, conflicts_with_all = ["snapshot", "root_cid", "checkpoint_cid", "named_snapshot"])]
        revision: Option<u64>,
        #[arg(long, conflicts_with_all = ["snapshot", "revision", "checkpoint_cid", "named_snapshot"])]
        root_cid: Option<String>,
        #[arg(long, conflicts_with_all = ["snapshot", "revision", "root_cid", "named_snapshot"])]
        checkpoint_cid: Option<String>,
        #[arg(long, conflicts_with_all = ["snapshot", "revision", "root_cid", "checkpoint_cid"])]
        named_snapshot: Option<String>,
    },
    History {
        database: String,
    },
    Snapshot {
        #[command(subcommand)]
        command: SnapshotSubcommand,
    },
    Rollback {
        database: String,
        revision: u64,
        #[arg(long)]
        request_id: Option<String>,
    },
    Check {
        database: String,
    },
    Compact {
        database: String,
        #[arg(long)]
        request_id: Option<String>,
    },
    CommitStatus {
        database: String,
        commit_id: String,
    },
}

#[derive(Debug, Parser)]
struct NamespaceCliCommand {
    #[command(subcommand)]
    command: NamespaceSubcommand,
}

#[derive(Debug, Subcommand)]
enum NamespaceSubcommand {
    Create {
        #[arg(long)]
        kind: String,
        #[arg(long)]
        alias: Option<String>,
    },
    Inspect {
        namespace: String,
    },
    Status {
        namespace: String,
    },
    Replicas {
        namespace: String,
    },
    History {
        namespace: String,
    },
    Diff {
        namespace: String,
        revision_a: u64,
        revision_b: u64,
    },
    Rollback {
        namespace: String,
        revision: u64,
        #[arg(long)]
        request_id: Option<String>,
    },
    Snapshot {
        #[command(subcommand)]
        command: SnapshotSubcommand,
    },
}

#[derive(Debug, Subcommand)]
enum SnapshotSubcommand {
    Create {
        namespace: String,
        name: String,
        #[arg(long)]
        revision: Option<u64>,
        #[arg(long)]
        request_id: Option<String>,
    },
    Delete {
        namespace: String,
        name: String,
        #[arg(long)]
        request_id: Option<String>,
    },
    List {
        namespace: String,
    },
}

#[derive(Debug, Parser)]
struct KvCommand {
    #[command(subcommand)]
    command: KvSubcommand,
}

#[derive(Debug, Subcommand)]
enum KvSubcommand {
    Get {
        namespace: String,
        key: String,
        #[arg(long)]
        revision: Option<u64>,
        #[arg(long)]
        root: Option<String>,
        #[arg(long)]
        checkpoint: Option<String>,
    },
    Put {
        namespace: String,
        key: String,
        #[arg(long)]
        cid: String,
        #[arg(long)]
        if_generation: Option<u64>,
        #[arg(long)]
        if_cid: Option<String>,
        #[arg(long)]
        request_id: Option<String>,
    },
    Delete {
        namespace: String,
        key: String,
        #[arg(long)]
        if_generation: Option<u64>,
        #[arg(long)]
        if_cid: Option<String>,
        #[arg(long)]
        request_id: Option<String>,
    },
    Scan {
        namespace: String,
        #[arg(long)]
        prefix: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long)]
        revision: Option<u64>,
    },
    PutFile {
        namespace: String,
        key: String,
        path: PathBuf,
        #[arg(long)]
        if_generation: Option<u64>,
        #[arg(long)]
        if_cid: Option<String>,
        #[arg(long)]
        request_id: Option<String>,
    },
    Txn {
        #[command(subcommand)]
        command: TxnSubcommand,
    },
}

#[derive(Debug, Subcommand)]
enum TxnSubcommand {
    Apply {
        namespace: String,
        path: PathBuf,
        #[arg(long)]
        request_id: Option<String>,
    },
}

#[derive(Debug, Parser)]
struct BucketCommand {
    #[command(subcommand)]
    command: BucketSubcommand,
}

#[derive(Debug, Subcommand)]
enum BucketSubcommand {
    Create {
        alias: String,
    },
    Put {
        bucket: String,
        key: String,
        path: PathBuf,
        #[arg(long)]
        content_type: Option<String>,
        #[arg(long)]
        if_generation: Option<u64>,
        #[arg(long)]
        if_cid: Option<String>,
        #[arg(long)]
        request_id: Option<String>,
    },
    Get {
        bucket: String,
        key: String,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        revision: Option<u64>,
    },
    Head {
        bucket: String,
        key: String,
        #[arg(long)]
        revision: Option<u64>,
    },
    Delete {
        bucket: String,
        key: String,
        #[arg(long)]
        if_generation: Option<u64>,
        #[arg(long)]
        if_cid: Option<String>,
        #[arg(long)]
        request_id: Option<String>,
    },
    List {
        bucket: String,
        #[arg(long)]
        prefix: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long)]
        revision: Option<u64>,
    },
    Versions {
        bucket: String,
        key: String,
    },
}

#[derive(Debug, Parser)]
struct FsCommand {
    #[command(subcommand)]
    command: FsSubcommand,
}

#[derive(Debug, Subcommand)]
enum FsSubcommand {
    Create {
        alias: String,
    },
    Checkout {
        filesystem: String,
        destination: PathBuf,
        #[arg(long)]
        revision: Option<u64>,
    },
    Commit {
        filesystem: String,
        source: PathBuf,
        #[arg(long)]
        base_revision: u64,
        #[arg(long)]
        message: Option<String>,
        #[arg(long)]
        request_id: Option<String>,
    },
    History {
        filesystem: String,
    },
    Diff {
        filesystem: String,
        revision_a: u64,
        revision_b: u64,
    },
    Restore {
        filesystem: String,
        revision: u64,
        destination: PathBuf,
    },
    Rollback {
        filesystem: String,
        revision: u64,
        #[arg(long)]
        request_id: Option<String>,
    },
    CloneFromRoot {
        filesystem: String,
        root_cid: String,
        #[arg(long)]
        request_id: Option<String>,
    },
    Mount {
        filesystem: String,
        mountpoint: PathBuf,
    },
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
    Namespace {
        #[command(subcommand)]
        command: AdminNamespaceSubcommand,
    },
    Sqlite {
        #[command(subcommand)]
        command: AdminSqliteSubcommand,
    },
}

#[derive(Debug, Subcommand)]
enum AdminSqliteSubcommand {
    Status,
    Sessions,
    Locks,
    Staging,
    Repair,
}

#[derive(Debug, Subcommand)]
enum AdminNamespaceSubcommand {
    Checkpoint {
        namespace: String,
    },
    Rebalance {
        namespace: String,
    },
    ReplaceReplica {
        namespace: String,
        failed_node: String,
        #[arg(long)]
        replacement_node: Option<String>,
    },
    Recover {
        namespace: String,
        checkpoint_cid: String,
        #[arg(long, num_args = 3)]
        members: Vec<String>,
        #[arg(long)]
        confirm_fork_risk: bool,
    },
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
    Put {
        path: PathBuf,
        /// Override the configured durability factor for this block.
        #[arg(long)]
        replicas: Option<usize>,
    },
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
async fn main() {
    if let Err(error) = run().await {
        let message = error.to_string();
        eprintln!("{message}");
        let code = if message.contains("GenerationConflict")
            || message.contains("generation_conflict")
        {
            20
        } else if message.contains("NamespaceUnavailable")
            || message.contains("NotLeader")
            || message.contains("namespace_unavailable")
            || message.contains("not_leader")
        {
            21
        } else if message.contains("DurabilityNotMet") || message.contains("durability_not_met") {
            22
        } else if message.contains("Unauthorized")
            || message.contains("Forbidden")
            || message.contains("unauthorized")
            || message.contains("forbidden")
        {
            23
        } else if message.contains("InvalidCursor")
            || message.contains("InvalidRequest")
            || message.contains("invalid_cursor")
            || message.contains("invalid_request")
        {
            24
        } else {
            1
        };
        std::process::exit(code);
    }
}

async fn run() -> Result<()> {
    let args = Args::parse();
    let _ = API_TOKEN.set(args.api_token.clone());
    let _ = JSON_OUTPUT.set(args.json);
    match args.command {
        Command::Node(node) => match node.command {
            NodeSubcommand::Status => node_status(&args.api, args.json).await,
            NodeSubcommand::Peers => node_peers(&args.api, args.json).await,
        },
        Command::Block(block) => match block.command {
            BlockSubcommand::Put { path, replicas } => {
                block_put(&args.api, args.json, path, replicas).await
            }
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
        Command::Namespace(namespace) => {
            namespace_command(&args.api, args.json, namespace.command).await
        }
        Command::Kv(kv) => kv_command(&args.api, args.json, kv.command).await,
        Command::Bucket(bucket) => bucket_command(&args.api, args.json, bucket.command).await,
        Command::Fs(fs) => fs_command(&args.api, args.json, fs.command).await,
        Command::Sqlite(sqlite) => sqlite_command(&args.api, args.json, sqlite.command).await,
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
            AdminSubcommand::Namespace { command } => {
                admin_namespace_command(&args.api, args.json, command).await
            }
            AdminSubcommand::Sqlite { command } => {
                let (method, path): (reqwest::Method, &[&str]) = match command {
                    AdminSqliteSubcommand::Status => {
                        (reqwest::Method::GET, &["v1", "admin", "sqlite"])
                    }
                    AdminSqliteSubcommand::Sessions => {
                        (reqwest::Method::GET, &["v1", "admin", "sqlite", "sessions"])
                    }
                    AdminSqliteSubcommand::Locks => {
                        (reqwest::Method::GET, &["v1", "admin", "sqlite", "locks"])
                    }
                    AdminSqliteSubcommand::Staging => {
                        (reqwest::Method::GET, &["v1", "admin", "sqlite", "staging"])
                    }
                    AdminSqliteSubcommand::Repair => {
                        (reqwest::Method::POST, &["v1", "admin", "sqlite", "repair"])
                    }
                };
                let value = send_json(&args.api, method, path, None).await?;
                print_namespace_json(&value, args.json)
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

fn request_id() -> String {
    format!(
        "cli-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}

async fn send_json(
    api: &str,
    method: reqwest::Method,
    path: &[&str],
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    let url = resource_url(api, path)?;
    let mut request = http_client()?.request(method, url.clone());
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .with_context(|| format!("failed to connect to Pepper agent at {url}"))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .context("failed to read agent response")?;
    if !status.is_success() {
        if let Ok(error) = serde_json::from_slice::<pepper_types::ErrorResponse>(&bytes) {
            if JSON_OUTPUT.get().copied().unwrap_or(false) {
                anyhow::bail!("{}", serde_json::to_string(&error)?);
            }
            anyhow::bail!("{:?}: {}", error.code, error.error);
        }
        anyhow::bail!(
            "agent returned HTTP {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
    }
    serde_json::from_slice(&bytes).context("failed to decode agent JSON response")
}

fn print_namespace_json(value: &serde_json::Value, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else if let Some(object) = value.as_object() {
        for (key, value) in object {
            println!(
                "{key}: {}",
                value
                    .as_str()
                    .map_or_else(|| value.to_string(), str::to_string)
            );
        }
    } else {
        println!("{value}");
    }
    Ok(())
}

async fn namespace_command(api: &str, json: bool, command: NamespaceSubcommand) -> Result<()> {
    let value = match command {
        NamespaceSubcommand::Create { kind, alias } => send_json(
            api,
            reqwest::Method::POST,
            &["v1", "namespaces"],
            Some(serde_json::json!({"kind": kind, "alias": alias, "request_id": request_id()})),
        ).await?,
        NamespaceSubcommand::Inspect { namespace } => send_json(api, reqwest::Method::GET, &["v1", "namespaces", &namespace], None).await?,
        NamespaceSubcommand::Status { namespace } => send_json(api, reqwest::Method::GET, &["v1", "namespaces", &namespace, "status"], None).await?,
        NamespaceSubcommand::Replicas { namespace } => send_json(api, reqwest::Method::GET, &["v1", "namespaces", &namespace, "replicas"], None).await?,
        NamespaceSubcommand::History { namespace } => send_json(api, reqwest::Method::GET, &["v1", "namespaces", &namespace, "history"], None).await?,
        NamespaceSubcommand::Diff { namespace, revision_a, revision_b } => send_json(api, reqwest::Method::POST, &["v1", "namespaces", &namespace, "diff"], Some(serde_json::json!({"revision_a": revision_a, "revision_b": revision_b}))).await?,
        NamespaceSubcommand::Rollback { namespace, revision, request_id: id } => send_json(api, reqwest::Method::POST, &["v1", "namespaces", &namespace, "rollback"], Some(serde_json::json!({"revision": revision, "request_id": id.unwrap_or_else(request_id)}))).await?,
        NamespaceSubcommand::Snapshot { command } => match command {
            SnapshotSubcommand::List { namespace } => send_json(api, reqwest::Method::GET, &["v1", "namespaces", &namespace, "snapshots"], None).await?,
            SnapshotSubcommand::Create { namespace, name, revision, request_id: id } => send_json(api, reqwest::Method::POST, &["v1", "namespaces", &namespace, "snapshots"], Some(serde_json::json!({"action":"create", "name":name, "revision":revision, "request_id":id.unwrap_or_else(request_id)}))).await?,
            SnapshotSubcommand::Delete { namespace, name, request_id: id } => send_json(api, reqwest::Method::POST, &["v1", "namespaces", &namespace, "snapshots"], Some(serde_json::json!({"action":"delete", "name":name, "request_id":id.unwrap_or_else(request_id)}))).await?,
        },
    };
    print_namespace_json(&value, json)
}

async fn sqlite_command(api: &str, json: bool, command: SqliteSubcommand) -> Result<()> {
    let value = match command {
        SqliteSubcommand::Create {
            database,
            page_size,
            request_id: id,
        } => {
            send_json(
                api,
                reqwest::Method::POST,
                &["v1", "sqlite", "databases"],
                Some(serde_json::json!({
                    "database": database,
                    "page_size": page_size,
                    "request_id": id.unwrap_or_else(request_id)
                })),
            )
            .await?
        }
        SqliteSubcommand::Info { database } => {
            send_json(
                api,
                reqwest::Method::GET,
                &["v1", "sqlite", "databases", &database],
                None,
            )
            .await?
        }
        SqliteSubcommand::Import {
            database,
            path,
            request_id: id,
        } => {
            let info = send_json(
                api,
                reqwest::Method::GET,
                &["v1", "sqlite", "databases", &database],
                None,
            )
            .await?;
            let file = tokio::fs::File::open(&path)
                .await
                .with_context(|| format!("failed to open {}", path.display()))?;
            let length = file
                .metadata()
                .await
                .with_context(|| format!("failed to stat {}", path.display()))?
                .len();
            let mut url = resource_url(api, &["v1", "sqlite", "databases", &database, "import"])?;
            url.query_pairs_mut()
                .append_pair("request_id", &id.unwrap_or_else(request_id))
                .append_pair(
                    "base_revision",
                    &info["namespace_revision"]
                        .as_u64()
                        .context("missing namespace revision")?
                        .to_string(),
                )
                .append_pair(
                    "base_generation",
                    &info["head_generation"]
                        .as_u64()
                        .context("missing head generation")?
                        .to_string(),
                )
                .append_pair(
                    "base_snapshot",
                    info["snapshot_cid"]
                        .as_str()
                        .context("missing snapshot CID")?,
                );
            let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file));
            let response = http_client()?
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/vnd.sqlite3")
                .header(reqwest::header::CONTENT_LENGTH, length)
                .body(body)
                .send()
                .await?;
            decode_json_response(response).await?
        }
        SqliteSubcommand::Export {
            database,
            output,
            snapshot,
            revision,
            root_cid,
            checkpoint_cid,
            named_snapshot,
        } => {
            let mut url = resource_url(api, &["v1", "sqlite", "databases", &database, "export"])?;
            if let Some(snapshot) = snapshot {
                url.query_pairs_mut().append_pair("snapshot", &snapshot);
            }
            if let Some(revision) = revision {
                url.query_pairs_mut()
                    .append_pair("revision", &revision.to_string());
            }
            if let Some(root) = root_cid {
                url.query_pairs_mut().append_pair("root_cid", &root);
            }
            if let Some(checkpoint) = checkpoint_cid {
                url.query_pairs_mut()
                    .append_pair("checkpoint_cid", &checkpoint);
            }
            if let Some(name) = named_snapshot {
                url.query_pairs_mut().append_pair("named_snapshot", &name);
            }
            download_to_file(url, &output).await?;
            serde_json::json!({"database":database,"output":output,"status":"exported"})
        }
        SqliteSubcommand::History { database } => {
            let info = sqlite_info_for_namespace(api, &database).await?;
            send_json(
                api,
                reqwest::Method::GET,
                &["v1", "namespaces", &info, "history"],
                None,
            )
            .await?
        }
        SqliteSubcommand::Snapshot { command } => match command {
            SnapshotSubcommand::List {
                namespace: database,
            } => {
                let namespace = sqlite_info_for_namespace(api, &database).await?;
                send_json(
                    api,
                    reqwest::Method::GET,
                    &["v1", "namespaces", &namespace, "snapshots"],
                    None,
                )
                .await?
            }
            SnapshotSubcommand::Create {
                namespace: database,
                name,
                revision,
                request_id: id,
            } => {
                let namespace = sqlite_info_for_namespace(api, &database).await?;
                send_json(
                    api,
                    reqwest::Method::POST,
                    &["v1", "namespaces", &namespace, "snapshots"],
                    Some(serde_json::json!({"action":"create","name":name,"revision":revision,"request_id":id.unwrap_or_else(request_id)})),
                )
                .await?
            }
            SnapshotSubcommand::Delete {
                namespace: database,
                name,
                request_id: id,
            } => {
                let namespace = sqlite_info_for_namespace(api, &database).await?;
                send_json(
                    api,
                    reqwest::Method::POST,
                    &["v1", "namespaces", &namespace, "snapshots"],
                    Some(serde_json::json!({"action":"delete","name":name,"request_id":id.unwrap_or_else(request_id)})),
                )
                .await?
            }
        },
        SqliteSubcommand::Rollback {
            database,
            revision,
            request_id: id,
        } => send_json(
            api,
            reqwest::Method::POST,
            &["v1", "sqlite", "databases", &database, "rollback"],
            Some(
                serde_json::json!({"revision":revision,"request_id":id.unwrap_or_else(request_id)}),
            ),
        )
        .await?,
        SqliteSubcommand::Check { database } => {
            send_json(
                api,
                reqwest::Method::GET,
                &["v1", "sqlite", "databases", &database, "check"],
                None,
            )
            .await?
        }
        SqliteSubcommand::Compact {
            database,
            request_id: id,
        } => {
            send_json(
                api,
                reqwest::Method::POST,
                &["v1", "sqlite", "databases", &database, "compact"],
                Some(serde_json::json!({"request_id":id.unwrap_or_else(request_id)})),
            )
            .await?
        }
        SqliteSubcommand::CommitStatus {
            database,
            commit_id,
        } => {
            send_json(
                api,
                reqwest::Method::GET,
                &[
                    "v1",
                    "sqlite",
                    "databases",
                    &database,
                    "commits",
                    &commit_id,
                ],
                None,
            )
            .await?
        }
    };
    print_namespace_json(&value, json)
}

async fn sqlite_info_for_namespace(api: &str, database: &str) -> Result<String> {
    let info = send_json(
        api,
        reqwest::Method::GET,
        &["v1", "sqlite", "databases", database],
        None,
    )
    .await?;
    info["namespace_id"]
        .as_str()
        .map(str::to_string)
        .context("SQLite info response is missing namespace_id")
}

async fn decode_json_response(response: reqwest::Response) -> Result<serde_json::Value> {
    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        if let Ok(error) = serde_json::from_slice::<pepper_types::ErrorResponse>(&bytes) {
            anyhow::bail!("{:?}: {}", error.code, error.error);
        }
        anyhow::bail!(
            "agent returned HTTP {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
    }
    serde_json::from_slice(&bytes).context("failed to decode agent JSON response")
}

fn mutation_body(
    namespace: String,
    key: String,
    value_cid: Option<String>,
    if_generation: Option<u64>,
    if_cid: Option<String>,
    id: Option<String>,
) -> serde_json::Value {
    serde_json::json!({
        "namespace": namespace,
        "key_hex": hex::encode(key.as_bytes()),
        "value_cid": value_cid,
        "if_generation": if_generation,
        "if_cid": if_cid,
        "request_id": id.unwrap_or_else(request_id)
    })
}

async fn kv_command(api: &str, json: bool, command: KvSubcommand) -> Result<()> {
    let value = match command {
        KvSubcommand::Get { namespace, key, revision, root, checkpoint } => send_json(api, reqwest::Method::POST, &["v1", "kv", "get"], Some(serde_json::json!({"namespace":namespace, "key_hex":hex::encode(key.as_bytes()), "consistency":"linearizable", "revision":revision, "root_cid":root, "checkpoint_cid":checkpoint}))).await?,
        KvSubcommand::Put { namespace, key, cid, if_generation, if_cid, request_id: id } => send_json(api, reqwest::Method::POST, &["v1", "kv", "put"], Some(mutation_body(namespace, key, Some(cid), if_generation, if_cid, id))).await?,
        KvSubcommand::Delete { namespace, key, if_generation, if_cid, request_id: id } => send_json(api, reqwest::Method::POST, &["v1", "kv", "delete"], Some(mutation_body(namespace, key, None, if_generation, if_cid, id))).await?,
        KvSubcommand::Scan { namespace, prefix, limit, cursor, revision } => send_json(api, reqwest::Method::POST, &["v1", "kv", "scan"], Some(serde_json::json!({"namespace":namespace, "prefix_hex":prefix.map(|value| hex::encode(value.as_bytes())), "limit":limit, "cursor":cursor, "revision":revision, "consistency":"linearizable"}))).await?,
        KvSubcommand::PutFile { namespace, key, path, if_generation, if_cid, request_id: id } => {
            let receipt = put_object_file(api, &path, None, true).await?;
            let uploaded = receipt.cid.to_string();
            let mut body = mutation_body(namespace, key, Some(uploaded.clone()), if_generation, if_cid, id);
            body["uploaded_roots"] = serde_json::json!([uploaded]);
            body["staged_bytes"] = serde_json::json!(receipt.size);
            body["retain_uploaded_on_conflict"] = serde_json::json!(true);
            match send_json(api, reqwest::Method::POST, &["v1", "kv", "put"], Some(body)).await {
                Ok(mut value) => { value["uploaded_object_cid"] = serde_json::json!(receipt.cid); value },
                Err(error) => anyhow::bail!("{error}; uploaded_object_cid={}", receipt.cid),
            }
        }
        KvSubcommand::Txn { command: TxnSubcommand::Apply { namespace, path, request_id: id } } => {
            let bytes = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
            let mut transaction: serde_json::Value = serde_json::from_slice(&bytes).context("invalid transaction JSON")?;
            if transaction.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
                anyhow::bail!("transaction file version must be 1");
            }
            if !transaction.get("mutations").is_some_and(serde_json::Value::is_array) {
                anyhow::bail!("transaction file mutations must be an array");
            }
            transaction["namespace"] = serde_json::json!(namespace);
            if transaction.get("request_id").is_none() {
                transaction["request_id"] = serde_json::json!(id.unwrap_or_else(request_id));
            }
            if transaction.get("writer_identity").is_none() { transaction["writer_identity"] = serde_json::json!("cli"); }
            if transaction.get("signature_hex").is_none() { transaction["signature_hex"] = serde_json::json!("00"); }
            send_json(api, reqwest::Method::POST, &["v1", "kv", "transactions"], Some(transaction)).await?
        }
    };
    print_namespace_json(&value, json)
}

async fn bucket_command(api: &str, json: bool, command: BucketSubcommand) -> Result<()> {
    let value = match command {
        BucketSubcommand::Create { alias } => send_json(
            api,
            reqwest::Method::POST,
            &["v1", "buckets"],
            Some(serde_json::json!({"alias": alias})),
        )
        .await?,
        BucketSubcommand::Put {
            bucket,
            key,
            path,
            content_type,
            if_generation,
            if_cid,
            request_id: id,
        } => {
            let receipt = put_object_file(api, &path, None, true).await?;
            let mut value = send_json(
                api,
                reqwest::Method::POST,
                &["v1", "bucket", "put"],
                Some(serde_json::json!({
                    "bucket": bucket,
                    "key_hex": hex::encode(key.as_bytes()),
                    "content_cid": receipt.cid,
                    "logical_size": receipt.size,
                    "content_type": content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                    "if_generation": if_generation,
                    "if_cid": if_cid,
                    "request_id": id.unwrap_or_else(request_id)
                })),
            )
            .await
            .with_context(|| format!("uploaded_object_cid={}", receipt.cid))?;
            value["uploaded_object_cid"] = serde_json::json!(receipt.cid);
            value
        }
        BucketSubcommand::Get { bucket, key, output, revision } => {
            let value = send_json(
                api,
                reqwest::Method::POST,
                &["v1", "bucket", "get"],
                Some(serde_json::json!({"bucket":bucket, "key_hex":hex::encode(key.as_bytes()), "revision":revision})),
            )
            .await?;
            let cid = value["object"]["content_cid"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("bucket response is missing content CID"))?;
            object_get(api, cid.to_string(), output).await?;
            value
        }
        BucketSubcommand::Head { bucket, key, revision } => send_json(
            api,
            reqwest::Method::POST,
            &["v1", "bucket", "head"],
            Some(serde_json::json!({"bucket":bucket, "key_hex":hex::encode(key.as_bytes()), "revision":revision})),
        ).await?,
        BucketSubcommand::Delete { bucket, key, if_generation, if_cid, request_id: id } => send_json(
            api,
            reqwest::Method::POST,
            &["v1", "bucket", "delete"],
            Some(serde_json::json!({"bucket":bucket, "key_hex":hex::encode(key.as_bytes()), "if_generation":if_generation, "if_cid":if_cid, "request_id":id.unwrap_or_else(request_id)})),
        ).await?,
        BucketSubcommand::List { bucket, prefix, limit, cursor, revision } => send_json(
            api,
            reqwest::Method::POST,
            &["v1", "bucket", "list"],
            Some(serde_json::json!({"bucket":bucket, "prefix_hex":prefix.map(|value| hex::encode(value.as_bytes())), "limit":limit, "cursor":cursor, "revision":revision})),
        ).await?,
        BucketSubcommand::Versions { bucket, key } => send_json(
            api,
            reqwest::Method::POST,
            &["v1", "bucket", "versions"],
            Some(serde_json::json!({"bucket":bucket, "key_hex":hex::encode(key.as_bytes())})),
        ).await?,
    };
    print_namespace_json(&value, json)
}

async fn fs_command(api: &str, json: bool, command: FsSubcommand) -> Result<()> {
    match command {
        FsSubcommand::Create { alias } => {
            let value = send_json(
                api,
                reqwest::Method::POST,
                &["v1", "filesystems"],
                Some(serde_json::json!({"alias":alias})),
            )
            .await?;
            print_namespace_json(&value, json)
        }
        FsSubcommand::Commit {
            filesystem,
            source,
            base_revision,
            message,
            request_id: id,
        } => {
            let (root_mode, entries) = collect_filesystem_entries(api, &source).await?;
            if !json {
                eprintln!(
                    "Note: ownership, ACLs, extended attributes, and platform-specific attributes are unsupported and are not committed"
                );
            }
            let value = send_json(api, reqwest::Method::POST, &["v1", "fs", "commit"], Some(serde_json::json!({"filesystem":filesystem,"base_revision":base_revision,"root_mode":root_mode,"entries":entries,"message":message,"request_id":id.unwrap_or_else(request_id)}))).await?;
            print_namespace_json(&value, json)
        }
        FsSubcommand::Checkout {
            filesystem,
            destination,
            revision,
        } => {
            let value = send_json(
                api,
                reqwest::Method::POST,
                &["v1", "fs", "checkout"],
                Some(serde_json::json!({"filesystem":filesystem,"revision":revision})),
            )
            .await?;
            restore_filesystem_response(api, &value, &destination).await?;
            print_namespace_json(&value, json)
        }
        FsSubcommand::Restore {
            filesystem,
            revision,
            destination,
        } => {
            let value = send_json(
                api,
                reqwest::Method::POST,
                &["v1", "fs", "restore"],
                Some(serde_json::json!({"filesystem":filesystem,"revision":revision})),
            )
            .await?;
            restore_filesystem_response(api, &value, &destination).await?;
            print_namespace_json(&value, json)
        }
        FsSubcommand::History { filesystem } => {
            let value = send_json(
                api,
                reqwest::Method::GET,
                &["v1", "fs", "history", &filesystem],
                None,
            )
            .await?;
            print_namespace_json(&value, json)
        }
        FsSubcommand::Diff {
            filesystem,
            revision_a,
            revision_b,
        } => {
            let value = send_json(api, reqwest::Method::POST, &["v1", "fs", "diff"], Some(serde_json::json!({"filesystem":filesystem,"revision_a":revision_a,"revision_b":revision_b}))).await?;
            print_namespace_json(&value, json)
        }
        FsSubcommand::Rollback {
            filesystem,
            revision,
            request_id: id,
        } => {
            let value = send_json(api, reqwest::Method::POST, &["v1", "fs", "rollback"], Some(serde_json::json!({"filesystem":filesystem,"revision":revision,"request_id":id.unwrap_or_else(request_id)}))).await?;
            print_namespace_json(&value, json)
        }
        FsSubcommand::CloneFromRoot {
            filesystem,
            root_cid,
            request_id: id,
        } => {
            let value = send_json(api, reqwest::Method::POST, &["v1", "fs", "clone"], Some(serde_json::json!({"filesystem":filesystem,"root_cid":root_cid,"request_id":id.unwrap_or_else(request_id)}))).await?;
            print_namespace_json(&value, json)
        }
        FsSubcommand::Mount {
            filesystem,
            mountpoint,
        } => anyhow::bail!(
            "experimental FUSE support is not enabled; {filesystem} was not mounted at {}. Use checkout/edit/commit instead",
            mountpoint.display()
        ),
    }
}

async fn collect_filesystem_entries(
    api: &str,
    root: &Path,
) -> Result<(u32, Vec<pepper_filesystem::TreeInputEntry>)> {
    use pepper_filesystem::{InodeKind, TreeInputEntry};
    let root_metadata =
        fs::symlink_metadata(root).with_context(|| format!("failed to stat {}", root.display()))?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        anyhow::bail!("filesystem source must be a real directory");
    }
    #[cfg(unix)]
    let root_mode = {
        use std::os::unix::fs::MetadataExt;
        if root_metadata.mode() & 0o7000 != 0 {
            anyhow::bail!("setuid, setgid, and sticky bits are unsupported on the root directory");
        }
        root_metadata.mode() & 0o777
    };
    #[cfg(not(unix))]
    let root_mode = 0o755;
    let mut output = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let mut children = fs::read_dir(&directory)
            .with_context(|| format!("failed to read {}", directory.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children.into_iter().rev() {
            let path = child.path();
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("failed to stat {}", path.display()))?;
            let relative = path
                .strip_prefix(root)?
                .components()
                .map(|component| {
                    component
                        .as_os_str()
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("filesystem paths must be UTF-8"))
                })
                .collect::<Result<Vec<_>>>()?
                .join("/");
            if metadata.file_type().is_symlink() {
                anyhow::bail!("symlinks are unsupported: {relative}");
            }
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::MetadataExt;
                if metadata.mode() & 0o7000 != 0 {
                    anyhow::bail!("setuid, setgid, and sticky bits are unsupported: {relative}");
                }
                if metadata.is_file() && metadata.nlink() > 1 {
                    anyhow::bail!("hard links are unsupported: {relative}");
                }
                if metadata.is_file()
                    && metadata.len() > 0
                    && metadata.blocks().saturating_mul(512) < metadata.len()
                {
                    anyhow::bail!("sparse files are unsupported: {relative}");
                }
                metadata.mode() & 0o777
            };
            #[cfg(not(unix))]
            let mode = if metadata.is_dir() {
                0o755
            } else if metadata.permissions().readonly() {
                0o444
            } else {
                0o644
            };
            if metadata.is_dir() {
                output.push(TreeInputEntry {
                    path: relative,
                    kind: InodeKind::Directory,
                    mode,
                    logical_size: 0,
                    content_cid: None,
                });
                stack.push(path);
            } else if metadata.is_file() {
                let receipt = put_object_file(api, &path, None, true).await?;
                output.push(TreeInputEntry {
                    path: relative,
                    kind: InodeKind::RegularFile,
                    mode,
                    logical_size: metadata.len(),
                    content_cid: Some(receipt.cid),
                });
            } else {
                anyhow::bail!(
                    "devices, sockets, and other special files are unsupported: {relative}"
                );
            }
        }
    }
    output.sort_by(|left, right| left.path.cmp(&right.path));
    Ok((root_mode, output))
}

async fn restore_filesystem_response(
    api: &str,
    value: &serde_json::Value,
    destination: &Path,
) -> Result<()> {
    if destination.exists() {
        anyhow::bail!("destination already exists: {}", destination.display());
    }
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid destination"))?;
    let temporary = parent.join(format!(".{name}.pepper-tmp-{}", std::process::id()));
    if temporary.exists() {
        fs::remove_dir_all(&temporary)?;
    }
    fs::create_dir(&temporary)?;
    let root = fs::canonicalize(&temporary)?;
    let result: Result<()> = async {
        let entries = value["entries"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("filesystem response is missing entries"))?;
        let mut directory_modes = Vec::new();
        for entry in entries {
            let path = entry["path"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("filesystem entry is missing path"))?;
            let target = safe_restore_path(&root, path)?;
            let kind = entry["inode"]["kind"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("filesystem entry is missing kind"))?;
            let mode = entry["inode"]["mode"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("filesystem entry is missing mode"))?
                as u32;
            match kind {
                "directory" => {
                    fs::create_dir_all(&target)?;
                    directory_modes.push((target, mode));
                }
                "regular_file" => {
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let cid = entry["inode"]["content_cid"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("file content CID is missing"))?;
                    let parsed = cid.parse::<pepper_types::Cid>()?;
                    let url = if parsed.codec == CODEC_RAW {
                        resource_url(api, &["v1", "blocks", cid])?
                    } else {
                        resource_url(api, &["v1", "objects", cid])?
                    };
                    let file_tmp = target.with_extension("pepper-part");
                    download_to_file(url, &file_tmp).await?;
                    fs::rename(&file_tmp, &target)?;
                    set_mode(&target, mode)?;
                }
                other => anyhow::bail!("unsupported filesystem inode kind {other}"),
            }
        }
        directory_modes.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
        for (path, mode) in directory_modes {
            set_mode(&path, mode)?;
        }
        let root_mode = value["root_inode"]["mode"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("filesystem response is missing root mode"))?
            as u32;
        set_mode(&root, root_mode)?;
        Ok(())
    }
    .await;
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }
    fs::rename(&temporary, destination)
        .with_context(|| format!("failed to atomically publish {}", destination.display()))?;
    eprintln!("Restored {}", destination.display());
    Ok(())
}

async fn admin_namespace_command(
    api: &str,
    json: bool,
    command: AdminNamespaceSubcommand,
) -> Result<()> {
    let value = match command {
        AdminNamespaceSubcommand::Checkpoint { namespace } => {
            send_json(
                api,
                reqwest::Method::POST,
                &["v1", "admin", "namespaces", &namespace, "checkpoint"],
                Some(serde_json::json!({})),
            )
            .await?
        }
        AdminNamespaceSubcommand::Rebalance { namespace } => {
            send_json(
                api,
                reqwest::Method::POST,
                &["v1", "admin", "namespaces", &namespace, "rebalance"],
                Some(serde_json::json!({})),
            )
            .await?
        }
        AdminNamespaceSubcommand::ReplaceReplica {
            namespace,
            failed_node,
            replacement_node,
        } => send_json(
            api,
            reqwest::Method::POST,
            &["v1", "admin", "namespaces", &namespace, "replace-replica"],
            Some(
                serde_json::json!({"failed_node":failed_node, "replacement_node":replacement_node}),
            ),
        )
        .await?,
        AdminNamespaceSubcommand::Recover {
            namespace,
            checkpoint_cid,
            members,
            confirm_fork_risk,
        } => {
            if !confirm_fork_risk {
                anyhow::bail!("recovery requires --confirm-fork-risk");
            }
            send_json(api, reqwest::Method::POST, &["v1", "admin", "namespaces", &namespace, "recover"], Some(serde_json::json!({"checkpoint_cid":checkpoint_cid, "members":members, "confirmation":"I_ACCEPT_NAMESPACE_FORK_RISK"}))).await?
        }
    };
    print_namespace_json(&value, json)
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

async fn block_put(api: &str, json: bool, path: PathBuf, replicas: Option<usize>) -> Result<()> {
    let bytes = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut url = format!("{}/v1/blocks", api.trim_end_matches('/'));
    if let Some(replicas) = replicas {
        url.push_str(&format!("?replication_factor={replicas}"));
    }
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
    let response = put_object_file(api, &path, erasure.as_deref(), true).await?;
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
    pin: bool,
) -> Result<DurabilityReceipt> {
    let mut url = resource_url(api, &["v1", "objects"])?;
    if let Some(erasure) = erasure {
        let (data, parity) = parse_erasure_policy(erasure)?;
        url.query_pairs_mut()
            .append_pair("erasure_data_shards", &data.to_string())
            .append_pair("erasure_parity_shards", &parity.to_string());
    }
    if !pin {
        url.query_pairs_mut().append_pair("pin", "false");
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
                let receipt = put_object_file(api, &child, None, false).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_export_accepts_each_historical_selector() {
        for selector in [
            vec!["--snapshot", "cid://snapshot"],
            vec!["--revision", "7"],
            vec!["--root-cid", "cid://root"],
            vec!["--checkpoint-cid", "cid://checkpoint"],
            vec!["--named-snapshot", "release"],
        ] {
            let mut arguments = vec!["pepper", "sqlite", "export", "db", "--output", "db.sqlite"];
            arguments.extend(selector);
            assert!(Args::try_parse_from(arguments).is_ok());
        }
    }

    #[test]
    fn sqlite_export_rejects_ambiguous_historical_selectors() {
        assert!(
            Args::try_parse_from([
                "pepper",
                "sqlite",
                "export",
                "db",
                "--output",
                "db.sqlite",
                "--revision",
                "7",
                "--named-snapshot",
                "release",
            ])
            .is_err()
        );
    }

    #[test]
    fn sqlite_rollback_requires_database_and_revision() {
        assert!(Args::try_parse_from(["pepper", "sqlite", "rollback", "db", "7"]).is_ok());
        assert!(Args::try_parse_from(["pepper", "sqlite", "rollback", "db"]).is_err());
    }

    #[test]
    fn sqlite_admin_surface_includes_staging_and_repair() {
        for command in ["status", "sessions", "locks", "staging", "repair"] {
            assert!(Args::try_parse_from(["pepper", "admin", "sqlite", command]).is_ok());
        }
    }
}
