// SPDX-License-Identifier: Apache-2.0

#[cfg(unix)]
mod unix {
    use anyhow::{Context, Result, bail, ensure};
    use clap::{Parser, ValueEnum};
    use pepper_sqlite_vfs::{
        UnixSocketBackend, last_pepper_vfs_error, register_pepper_vfs, unregister_pepper_vfs,
    };
    use rusqlite::{Connection, OpenFlags, params};
    use serde::Serialize;
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
        sync::Arc,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
    enum TargetSelection {
        Both,
        Filesystem,
        Pepper,
    }

    impl TargetSelection {
        fn filesystem(self) -> bool {
            matches!(self, Self::Both | Self::Filesystem)
        }

        fn pepper(self) -> bool {
            matches!(self, Self::Both | Self::Pepper)
        }
    }

    #[derive(Debug, Parser)]
    #[command(name = "pepper-sqlite-benchmark")]
    #[command(about = "Compare stock filesystem SQLite with the Pepper SQLite VFS")]
    struct Args {
        /// Benchmark both backends or only one backend.
        #[arg(long, value_enum, default_value_t = TargetSelection::Both)]
        target: TargetSelection,

        /// Pepper agent HTTP base URL used to create the benchmark database.
        #[arg(long, env = "PEPPER_API", default_value = "http://127.0.0.1:9080")]
        api: String,

        /// Local Pepper SQLite protocol socket for the selected ingress peer.
        #[arg(
            long,
            env = "PEPPER_SQLITE_SOCKET",
            default_value = "./data/sqlite.sock"
        )]
        socket: PathBuf,

        /// Optional bearer token for the Pepper HTTP API.
        #[arg(long, env = "PEPPER_API_TOKEN")]
        api_token: Option<String>,

        /// Existing disk-backed directory for the private filesystem database.
        #[arg(long, required_if_eq_any = [("target", "both"), ("target", "filesystem")])]
        filesystem_directory: Option<PathBuf>,

        /// Pepper database alias. A unique alias is generated when omitted.
        #[arg(long)]
        database: Option<String>,

        /// Use an existing Pepper database and replace its benchmark table.
        #[arg(long, requires = "database")]
        reuse_database: bool,

        /// SQLite database page size for both backends.
        #[arg(long, default_value_t = 4096)]
        page_size: u32,

        /// Rows loaded before measured operations begin.
        #[arg(long, default_value_t = 10_000)]
        seed_rows: u64,

        /// Payload bytes stored in each row.
        #[arg(long, default_value_t = 256)]
        payload_bytes: u32,

        /// Number of warm-cache point lookups.
        #[arg(long, default_value_t = 2_000)]
        point_reads: u64,

        /// Number of full-table scans.
        #[arg(long, default_value_t = 3)]
        scans: u64,

        /// Number of point reads that each open a new connection.
        #[arg(long, default_value_t = 25)]
        reopen_reads: u64,

        /// Insert counts in each measured write transaction.
        #[arg(long, value_delimiter = ',', default_value = "1,10,100,1000")]
        batch_sizes: Vec<u64>,

        /// Measured transactions for every batch size.
        #[arg(long, default_value_t = 10)]
        transactions_per_batch: u64,

        /// SQLite page-cache budget, in KiB, applied to both backends.
        #[arg(long, default_value_t = 8_192)]
        sqlite_cache_kib: u32,

        /// Optional machine-readable JSON result path.
        #[arg(long)]
        output: Option<PathBuf>,

        /// Free-form environment or hardware label recorded in JSON.
        #[arg(long, default_value = "unspecified")]
        environment_label: String,
    }

    #[derive(Debug, Serialize)]
    struct Report {
        schema_version: u32,
        generated_at_unix_millis: u128,
        environment_label: String,
        host: HostMetadata,
        sqlite_version: String,
        pepper_database: Option<String>,
        pepper_api: Option<String>,
        pepper_socket: Option<String>,
        filesystem_directory: Option<String>,
        pepper_database_info: Option<serde_json::Value>,
        configuration: Configuration,
        backends: Vec<BackendReport>,
        comparison: Vec<Comparison>,
    }

    #[derive(Debug, Serialize)]
    struct HostMetadata {
        operating_system: &'static str,
        architecture: &'static str,
        logical_cpus: usize,
        build_profile: &'static str,
        process_id: u32,
    }

    #[derive(Debug, Serialize)]
    struct Configuration {
        page_size: u32,
        seed_rows: u64,
        payload_bytes: u32,
        point_reads: u64,
        scans: u64,
        reopen_reads: u64,
        batch_sizes: Vec<u64>,
        transactions_per_batch: u64,
        sqlite_cache_kib: u32,
        journal_mode: &'static str,
        synchronous: &'static str,
        mmap_size: u32,
    }

    #[derive(Debug, Serialize)]
    struct BackendReport {
        backend: &'static str,
        setup_seconds: f64,
        effective_pragmas: BTreeMap<String, String>,
        final_rows: u64,
        integrity_check: String,
        workloads: Vec<WorkloadReport>,
    }

    #[derive(Debug, Clone, Serialize)]
    struct WorkloadReport {
        name: String,
        sample_unit: &'static str,
        samples: u64,
        operations: u64,
        operations_per_sample: u64,
        elapsed_seconds: f64,
        throughput_operations_per_second: f64,
        latency_microseconds: Latency,
    }

    #[derive(Debug, Clone, Serialize)]
    struct Latency {
        minimum: f64,
        p50: f64,
        p95: f64,
        p99: f64,
        maximum: f64,
        mean: f64,
    }

    #[derive(Debug, Serialize)]
    struct Comparison {
        workload: String,
        filesystem_p50_microseconds: f64,
        pepper_p50_microseconds: f64,
        pepper_to_filesystem_p50_ratio: f64,
        filesystem_operations_per_second: f64,
        pepper_operations_per_second: f64,
        pepper_to_filesystem_throughput_ratio: f64,
    }

    #[derive(Clone)]
    enum DatabaseTarget {
        Filesystem(PathBuf),
        Pepper(String),
    }

    impl DatabaseTarget {
        fn open(&self) -> Result<Connection> {
            match self {
                Self::Filesystem(path) => Connection::open(path)
                    .with_context(|| format!("open filesystem database {}", path.display())),
                Self::Pepper(database) => {
                    let uri = format!(
                        "file:pepper%3A{database}?mode=rw&vfs=pepper&busy_timeout_ms=30000"
                    );
                    Connection::open_with_flags(
                        uri,
                        OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_READ_WRITE,
                    )
                    .with_context(|| format!("open Pepper database {database}"))
                }
            }
        }
    }

    struct VfsRegistration;

    impl Drop for VfsRegistration {
        fn drop(&mut self) {
            let _ = unregister_pepper_vfs();
        }
    }

    pub async fn main() -> Result<()> {
        let args = Args::parse();
        validate_args(&args)?;
        if cfg!(debug_assertions) {
            eprintln!("warning: debug build; use cargo run --release for publishable measurements");
        }
        let generated_at_unix_millis = unix_millis();
        let pepper_database = args.target.pepper().then(|| {
            args.database.clone().unwrap_or_else(|| {
                format!(
                    "sqlite-bench-{}-{generated_at_unix_millis}",
                    std::process::id()
                )
            })
        });

        if let Some(database) = pepper_database.as_deref() {
            prepare_pepper_database(&args, database).await?;
        }

        let temporary = match args.filesystem_directory.as_deref() {
            Some(directory) if args.target.filesystem() => {
                std::fs::create_dir_all(directory).with_context(|| {
                    format!(
                        "create filesystem benchmark directory {}",
                        directory.display()
                    )
                })?;
                Some(
                    tempfile::Builder::new()
                        .prefix("pepper-sqlite-filesystem-")
                        .tempdir_in(directory)
                        .with_context(|| {
                            format!(
                                "create private filesystem database directory in {}",
                                directory.display()
                            )
                        })?,
                )
            }
            _ => None,
        };
        let mut backends = Vec::new();
        if args.target.filesystem() {
            backends.push(run_backend(
                "filesystem",
                DatabaseTarget::Filesystem(
                    temporary
                        .as_ref()
                        .context("--filesystem-directory is required for filesystem benchmarks")?
                        .path()
                        .join("filesystem.sqlite"),
                ),
                &args,
            )?);
        }

        let mut vfs_registration = None;
        if let Some(database) = pepper_database.as_deref() {
            let backend = Arc::new(UnixSocketBackend::new(
                args.socket.clone(),
                Duration::from_secs(30),
            ));
            register_pepper_vfs(backend).context("register Pepper SQLite VFS")?;
            vfs_registration = Some(VfsRegistration);
            backends.push(run_backend(
                "pepper_vfs",
                DatabaseTarget::Pepper(database.to_string()),
                &args,
            )?);
        }

        drop(vfs_registration);
        let pepper_database_info = match pepper_database.as_deref() {
            Some(database) => Some(fetch_pepper_database_info(&args, database).await?),
            None => None,
        };
        let comparison = comparisons(&backends);
        print_table(&backends, &comparison);
        let report = Report {
            schema_version: 1,
            generated_at_unix_millis,
            environment_label: args.environment_label.clone(),
            host: HostMetadata {
                operating_system: std::env::consts::OS,
                architecture: std::env::consts::ARCH,
                logical_cpus: std::thread::available_parallelism().map_or(1, usize::from),
                build_profile: if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                },
                process_id: std::process::id(),
            },
            sqlite_version: rusqlite::version().to_string(),
            pepper_database,
            pepper_api: args.target.pepper().then(|| args.api.clone()),
            pepper_socket: args
                .target
                .pepper()
                .then(|| args.socket.display().to_string()),
            filesystem_directory: args
                .filesystem_directory
                .as_deref()
                .map(|path| path.canonicalize().unwrap_or_else(|_| path.to_path_buf()))
                .map(|path| path.display().to_string()),
            pepper_database_info,
            configuration: Configuration {
                page_size: args.page_size,
                seed_rows: args.seed_rows,
                payload_bytes: args.payload_bytes,
                point_reads: args.point_reads,
                scans: args.scans,
                reopen_reads: args.reopen_reads,
                batch_sizes: args.batch_sizes.clone(),
                transactions_per_batch: args.transactions_per_batch,
                sqlite_cache_kib: args.sqlite_cache_kib,
                journal_mode: "DELETE",
                synchronous: "FULL",
                mmap_size: 0,
            },
            backends,
            comparison,
        };
        if let Some(path) = args.output.as_deref() {
            write_report(path, &report)?;
            println!("\nJSON: {}", path.display());
        }
        Ok(())
    }

    fn validate_args(args: &Args) -> Result<()> {
        ensure!(args.seed_rows > 0, "--seed-rows must be greater than zero");
        ensure!(
            !args.target.filesystem() || args.filesystem_directory.is_some(),
            "--filesystem-directory is required when benchmarking the filesystem"
        );
        ensure!(
            args.payload_bytes > 0,
            "--payload-bytes must be greater than zero"
        );
        ensure!(
            args.point_reads > 0,
            "--point-reads must be greater than zero"
        );
        ensure!(args.scans > 0, "--scans must be greater than zero");
        ensure!(
            args.sqlite_cache_kib > 0,
            "--sqlite-cache-kib must be greater than zero"
        );
        ensure!(
            args.transactions_per_batch > 0,
            "--transactions-per-batch must be greater than zero"
        );
        ensure!(
            !args.batch_sizes.is_empty() && args.batch_sizes.iter().all(|size| *size > 0),
            "--batch-sizes must contain positive values"
        );
        let inserted_rows = args
            .batch_sizes
            .iter()
            .try_fold(0_u64, |total, size| {
                total.checked_add(size.checked_mul(args.transactions_per_batch)?)
            })
            .context("requested write workload row count overflows u64")?;
        ensure!(
            args.seed_rows
                .checked_add(inserted_rows)
                .is_some_and(|rows| rows <= i64::MAX as u64),
            "requested final row count exceeds SQLite's signed integer range"
        );
        ensure!(
            matches!(
                args.page_size,
                512 | 1024 | 2048 | 4096 | 8192 | 16384 | 32768 | 65536
            ),
            "--page-size must be a SQLite-supported power of two from 512 through 65536"
        );
        Ok(())
    }

    async fn prepare_pepper_database(args: &Args, database: &str) -> Result<()> {
        let client = pepper_http_client(args)?;
        let base = args.api.trim_end_matches('/');
        if args.reuse_database {
            fetch_pepper_database_info_with_client(&client, base, database).await?;
            return Ok(());
        }
        let request_id = format!(
            "sqlite-bench-create-{}-{}",
            std::process::id(),
            unix_millis()
        );
        let response = client
            .post(format!("{base}/v1/sqlite/databases"))
            .json(&serde_json::json!({
                "database": database,
                "request_id": request_id,
                "page_size": args.page_size,
            }))
            .send()
            .await
            .context("create Pepper benchmark database")?;
        response_json(response, "create Pepper benchmark database").await?;
        Ok(())
    }

    fn pepper_http_client(args: &Args) -> Result<reqwest::Client> {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(token) = &args.api_token {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                    .context("invalid API token")?,
            );
        }
        reqwest::Client::builder()
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(5 * 60))
            .build()
            .context("build Pepper HTTP client")
    }

    async fn fetch_pepper_database_info(args: &Args, database: &str) -> Result<serde_json::Value> {
        let client = pepper_http_client(args)?;
        fetch_pepper_database_info_with_client(&client, args.api.trim_end_matches('/'), database)
            .await
    }

    async fn fetch_pepper_database_info_with_client(
        client: &reqwest::Client,
        base: &str,
        database: &str,
    ) -> Result<serde_json::Value> {
        let response = client
            .get(format!("{base}/v1/sqlite/databases/{database}"))
            .send()
            .await
            .context("query Pepper benchmark database")?;
        response_json(response, "query Pepper benchmark database").await
    }

    async fn response_json(
        response: reqwest::Response,
        operation: &str,
    ) -> Result<serde_json::Value> {
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        if !status.is_success() {
            bail!(
                "{operation} returned HTTP {status}: {}",
                String::from_utf8_lossy(&body)
            );
        }
        serde_json::from_slice(&body).with_context(|| format!("decode {operation} response"))
    }

    fn run_backend(
        backend: &'static str,
        target: DatabaseTarget,
        args: &Args,
    ) -> Result<BackendReport> {
        let mut connection = target.open().map_err(with_vfs_detail)?;
        let setup_started = Instant::now();
        configure(&connection, args)?;
        connection.execute_batch(
            "DROP TABLE IF EXISTS benchmark_rows;
             CREATE TABLE benchmark_rows(
                 id INTEGER PRIMARY KEY,
                 lookup_key INTEGER NOT NULL UNIQUE,
                 payload BLOB NOT NULL
             );",
        )?;
        seed(&mut connection, args.seed_rows, args.payload_bytes)?;
        let setup_seconds = setup_started.elapsed().as_secs_f64();
        let effective_pragmas = effective_pragmas(&connection)?;

        warm_point_reads(&connection, args.seed_rows, args.point_reads)?;
        let mut workloads = vec![
            measure_point_reads(&connection, args.seed_rows, args.point_reads)?,
            measure_scans(&connection, args.seed_rows, args.scans)?,
        ];
        if args.reopen_reads > 0 {
            workloads.push(measure_reopen_reads(
                &target,
                args.seed_rows,
                args.reopen_reads,
            )?);
        }

        let mut next_lookup_key = args.seed_rows.saturating_add(1);
        for batch_size in &args.batch_sizes {
            workloads.push(measure_writes(
                &mut connection,
                *batch_size,
                args.transactions_per_batch,
                args.payload_bytes,
                &mut next_lookup_key,
            )?);
        }

        let final_rows = u64::try_from(connection.query_row(
            "SELECT count(*) FROM benchmark_rows",
            [],
            |row| row.get::<_, i64>(0),
        )?)?;
        let expected_rows = args.seed_rows.saturating_add(
            args.batch_sizes
                .iter()
                .map(|size| size.saturating_mul(args.transactions_per_batch))
                .sum::<u64>(),
        );
        ensure!(
            final_rows == expected_rows,
            "{backend} final row count {final_rows} differs from expected {expected_rows}"
        );
        let integrity_check =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))?;
        ensure!(
            integrity_check == "ok",
            "{backend} integrity_check failed: {integrity_check}"
        );
        drop(connection);
        Ok(BackendReport {
            backend,
            setup_seconds,
            effective_pragmas,
            final_rows,
            integrity_check,
            workloads,
        })
    }

    fn with_vfs_detail(error: anyhow::Error) -> anyhow::Error {
        let detail = last_pepper_vfs_error();
        if detail.is_empty() {
            error
        } else {
            error.context(detail)
        }
    }

    fn configure(connection: &Connection, args: &Args) -> Result<()> {
        connection.busy_timeout(Duration::from_secs(30))?;
        connection.execute_batch(&format!(
            "PRAGMA page_size={};
             PRAGMA journal_mode=DELETE;
             PRAGMA synchronous=FULL;
             PRAGMA mmap_size=0;
             PRAGMA temp_store=MEMORY;
             PRAGMA cache_size=-{};",
            args.page_size, args.sqlite_cache_kib
        ))?;
        Ok(())
    }

    fn seed(connection: &mut Connection, rows: u64, payload_bytes: u32) -> Result<()> {
        let transaction = connection.transaction()?;
        {
            let mut statement = transaction.prepare(
                "INSERT INTO benchmark_rows(lookup_key, payload) VALUES (?1, zeroblob(?2))",
            )?;
            for lookup_key in 1..=rows {
                statement.execute(params![i64::try_from(lookup_key)?, payload_bytes])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn effective_pragmas(connection: &Connection) -> Result<BTreeMap<String, String>> {
        let mut pragmas = BTreeMap::new();
        for (name, query) in [
            ("page_size", "PRAGMA page_size"),
            ("journal_mode", "PRAGMA journal_mode"),
            ("synchronous", "PRAGMA synchronous"),
            ("mmap_size", "PRAGMA mmap_size"),
            ("cache_size", "PRAGMA cache_size"),
        ] {
            let value = connection.query_row(query, [], |row| {
                let value = row.get_ref(0)?;
                Ok(match value {
                    rusqlite::types::ValueRef::Integer(value) => value.to_string(),
                    rusqlite::types::ValueRef::Real(value) => value.to_string(),
                    rusqlite::types::ValueRef::Text(value) => {
                        String::from_utf8_lossy(value).into_owned()
                    }
                    rusqlite::types::ValueRef::Null => "null".into(),
                    rusqlite::types::ValueRef::Blob(value) => format!("{} bytes", value.len()),
                })
            })?;
            pragmas.insert(name.to_string(), value);
        }
        Ok(pragmas)
    }

    fn warm_point_reads(connection: &Connection, rows: u64, count: u64) -> Result<()> {
        let mut statement =
            connection.prepare("SELECT length(payload) FROM benchmark_rows WHERE lookup_key=?1")?;
        for index in 0..count {
            let key = i64::try_from(lookup_key(index, rows))?;
            let _: u32 = statement.query_row([key], |row| row.get(0))?;
        }
        Ok(())
    }

    fn measure_point_reads(
        connection: &Connection,
        rows: u64,
        count: u64,
    ) -> Result<WorkloadReport> {
        let mut latencies = Vec::with_capacity(count as usize);
        let mut statement =
            connection.prepare("SELECT length(payload) FROM benchmark_rows WHERE lookup_key=?1")?;
        for index in 0..count {
            let started = Instant::now();
            let key = i64::try_from(lookup_key(index, rows))?;
            let value: u32 = statement.query_row([key], |row| row.get(0))?;
            ensure!(value > 0, "point read returned an empty payload");
            latencies.push(started.elapsed());
        }
        Ok(workload(
            "point_read_connection_cache",
            "query",
            count,
            1,
            latencies,
        ))
    }

    fn measure_scans(connection: &Connection, rows: u64, scans: u64) -> Result<WorkloadReport> {
        let mut latencies = Vec::with_capacity(scans as usize);
        for _ in 0..scans {
            let started = Instant::now();
            let bytes: i64 = connection.query_row(
                "SELECT coalesce(sum(length(payload)), 0) FROM benchmark_rows",
                [],
                |row| row.get(0),
            )?;
            ensure!(bytes > 0, "sequential scan returned no payload bytes");
            latencies.push(started.elapsed());
        }
        Ok(workload(
            "sequential_scan_connection_cache",
            "scan",
            scans,
            rows,
            latencies,
        ))
    }

    fn measure_reopen_reads(
        target: &DatabaseTarget,
        rows: u64,
        count: u64,
    ) -> Result<WorkloadReport> {
        let mut latencies = Vec::with_capacity(count as usize);
        for index in 0..count {
            let started = Instant::now();
            let connection = target.open().map_err(with_vfs_detail)?;
            connection.busy_timeout(Duration::from_secs(30))?;
            let key = i64::try_from(lookup_key(index, rows))?;
            let value: u32 = connection.query_row(
                "SELECT length(payload) FROM benchmark_rows WHERE lookup_key=?1",
                [key],
                |row| row.get(0),
            )?;
            ensure!(value > 0, "reopen point read returned an empty payload");
            drop(connection);
            latencies.push(started.elapsed());
        }
        Ok(workload(
            "point_read_reopen",
            "open/query/close",
            count,
            1,
            latencies,
        ))
    }

    fn measure_writes(
        connection: &mut Connection,
        batch_size: u64,
        transactions: u64,
        payload_bytes: u32,
        next_lookup_key: &mut u64,
    ) -> Result<WorkloadReport> {
        let mut latencies = Vec::with_capacity(transactions as usize);
        for _ in 0..transactions {
            let started = Instant::now();
            if batch_size == 1 {
                connection.execute(
                    "INSERT INTO benchmark_rows(lookup_key, payload) VALUES (?1, zeroblob(?2))",
                    params![i64::try_from(*next_lookup_key)?, payload_bytes],
                )?;
                *next_lookup_key = next_lookup_key.saturating_add(1);
            } else {
                let transaction = connection.transaction()?;
                {
                    let mut statement = transaction.prepare(
                        "INSERT INTO benchmark_rows(lookup_key, payload) VALUES (?1, zeroblob(?2))",
                    )?;
                    for _ in 0..batch_size {
                        statement
                            .execute(params![i64::try_from(*next_lookup_key)?, payload_bytes])?;
                        *next_lookup_key = next_lookup_key.saturating_add(1);
                    }
                }
                transaction.commit()?;
            }
            latencies.push(started.elapsed());
        }
        let name = if batch_size == 1 {
            "insert_autocommit_1".to_string()
        } else {
            format!("insert_transaction_{batch_size}")
        };
        Ok(workload(
            name,
            "transaction",
            transactions,
            batch_size,
            latencies,
        ))
    }

    fn lookup_key(index: u64, rows: u64) -> u64 {
        index
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407)
            % rows
            + 1
    }

    fn workload(
        name: impl Into<String>,
        sample_unit: &'static str,
        samples: u64,
        operations_per_sample: u64,
        latencies: Vec<Duration>,
    ) -> WorkloadReport {
        let operations = samples.saturating_mul(operations_per_sample);
        let elapsed_seconds = latencies.iter().map(Duration::as_secs_f64).sum::<f64>();
        let throughput = if elapsed_seconds == 0.0 {
            0.0
        } else {
            operations as f64 / elapsed_seconds
        };
        WorkloadReport {
            name: name.into(),
            sample_unit,
            samples,
            operations,
            operations_per_sample,
            elapsed_seconds,
            throughput_operations_per_second: throughput,
            latency_microseconds: latency(&latencies),
        }
    }

    fn latency(values: &[Duration]) -> Latency {
        let mut micros = values
            .iter()
            .map(|value| value.as_secs_f64() * 1_000_000.0)
            .collect::<Vec<_>>();
        micros.sort_by(f64::total_cmp);
        let mean = micros.iter().sum::<f64>() / micros.len().max(1) as f64;
        Latency {
            minimum: *micros.first().unwrap_or(&0.0),
            p50: percentile(&micros, 50),
            p95: percentile(&micros, 95),
            p99: percentile(&micros, 99),
            maximum: *micros.last().unwrap_or(&0.0),
            mean,
        }
    }

    fn percentile(sorted: &[f64], percentile: usize) -> f64 {
        if sorted.is_empty() {
            return 0.0;
        }
        let rank = (sorted.len() * percentile).div_ceil(100).max(1);
        sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
    }

    fn comparisons(backends: &[BackendReport]) -> Vec<Comparison> {
        let Some(filesystem) = backends.iter().find(|value| value.backend == "filesystem") else {
            return Vec::new();
        };
        let Some(pepper) = backends.iter().find(|value| value.backend == "pepper_vfs") else {
            return Vec::new();
        };
        filesystem
            .workloads
            .iter()
            .filter_map(|local| {
                let remote = pepper
                    .workloads
                    .iter()
                    .find(|value| value.name == local.name)?;
                Some(Comparison {
                    workload: local.name.clone(),
                    filesystem_p50_microseconds: local.latency_microseconds.p50,
                    pepper_p50_microseconds: remote.latency_microseconds.p50,
                    pepper_to_filesystem_p50_ratio: ratio(
                        remote.latency_microseconds.p50,
                        local.latency_microseconds.p50,
                    ),
                    filesystem_operations_per_second: local.throughput_operations_per_second,
                    pepper_operations_per_second: remote.throughput_operations_per_second,
                    pepper_to_filesystem_throughput_ratio: ratio(
                        remote.throughput_operations_per_second,
                        local.throughput_operations_per_second,
                    ),
                })
            })
            .collect()
    }

    fn ratio(numerator: f64, denominator: f64) -> f64 {
        if denominator == 0.0 {
            0.0
        } else {
            numerator / denominator
        }
    }

    fn print_table(backends: &[BackendReport], comparison: &[Comparison]) {
        for backend in backends {
            println!(
                "\n{} (setup {:.3}s, final rows {}, integrity {})",
                backend.backend, backend.setup_seconds, backend.final_rows, backend.integrity_check
            );
            println!(
                "{:<30} {:>12} {:>12} {:>12} {:>14}",
                "workload", "p50 us", "p95 us", "p99 us", "operations/s"
            );
            for workload in &backend.workloads {
                println!(
                    "{:<30} {:>12.1} {:>12.1} {:>12.1} {:>14.1}",
                    workload.name,
                    workload.latency_microseconds.p50,
                    workload.latency_microseconds.p95,
                    workload.latency_microseconds.p99,
                    workload.throughput_operations_per_second,
                );
            }
        }
        if !comparison.is_empty() {
            println!("\nPepper / filesystem comparison");
            println!(
                "{:<30} {:>16} {:>20}",
                "workload", "p50 latency x", "throughput x"
            );
            for value in comparison {
                println!(
                    "{:<30} {:>16.2} {:>20.3}",
                    value.workload,
                    value.pepper_to_filesystem_p50_ratio,
                    value.pepper_to_filesystem_throughput_ratio,
                );
            }
        }
    }

    fn write_report(path: &Path, report: &Report) -> Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create result directory {}", parent.display()))?;
        }
        let bytes = serde_json::to_vec_pretty(report)?;
        std::fs::write(path, bytes)
            .with_context(|| format!("write benchmark report {}", path.display()))
    }

    fn unix_millis() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn percentile_uses_nearest_rank() {
            let values = (1..=100).map(|value| value as f64).collect::<Vec<_>>();
            assert_eq!(percentile(&values, 50), 50.0);
            assert_eq!(percentile(&values, 95), 95.0);
            assert_eq!(percentile(&values, 99), 99.0);
        }

        #[test]
        fn filesystem_workload_smoke_test() {
            let temporary = tempfile::tempdir().unwrap();
            let args = Args {
                target: TargetSelection::Filesystem,
                api: "http://127.0.0.1:9080".into(),
                socket: PathBuf::from("unused"),
                api_token: None,
                filesystem_directory: Some(temporary.path().to_path_buf()),
                database: None,
                reuse_database: false,
                page_size: 4096,
                seed_rows: 32,
                payload_bytes: 32,
                point_reads: 16,
                scans: 2,
                reopen_reads: 2,
                batch_sizes: vec![1, 4],
                transactions_per_batch: 2,
                sqlite_cache_kib: 1024,
                output: None,
                environment_label: "test".into(),
            };
            let report = run_backend(
                "filesystem",
                DatabaseTarget::Filesystem(temporary.path().join("test.sqlite")),
                &args,
            )
            .unwrap();
            assert_eq!(report.final_rows, 42);
            assert_eq!(report.integrity_check, "ok");
            assert_eq!(report.workloads.len(), 5);
        }
    }
}

#[cfg(unix)]
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(error) = unix::main().await {
        eprintln!("{error:#}");
        let detail = pepper_sqlite_vfs::last_pepper_vfs_error();
        if !detail.is_empty() {
            eprintln!("Pepper VFS: {detail}");
        }
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("pepper-sqlite-benchmark requires the Unix-domain-socket Pepper VFS client");
    std::process::exit(2);
}
