// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use pepper_buffer::{BufferChain, OwnedBuffer};
use pepper_extent::{
    AppendPlan, ExtentId, ExtentStore, FileExtentConfig, FileExtentStore, RangeRead, RecordId,
};
use pepper_ordered_log::{
    Acknowledgments, OrderedLog, OrderedLogConfig, RecoveryState, ReplicatedPartition,
    ReplicationSpike, replication_spike,
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    env, fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::Instant,
};
use tempfile::TempDir;

#[derive(Debug, Serialize)]
struct Report {
    schema: &'static str,
    repetitions: usize,
    cases: Vec<CaseReport>,
    spike_direct: pepper_ordered_log::SpikeReport,
    spike_data_bearing_single_write: pepper_ordered_log::SpikeReport,
    spike_data_bearing_double_write_rejected: pepper_ordered_log::SpikeReport,
    all_pass: bool,
}

#[derive(Debug, Serialize)]
struct CaseReport {
    batch_bytes: usize,
    concurrency: usize,
    batches: usize,
    raw: Vec<Sample>,
    ordered: Vec<Sample>,
    append_throughput_regression_percent: f64,
    append_p99_regression_percent: f64,
    fetch_throughput_regression_percent: f64,
    fetch_p99_regression_percent: f64,
    append_pass: bool,
    fetch_pass: bool,
}

#[derive(Debug, Clone, Serialize)]
struct Sample {
    append_operations_per_second: f64,
    append_p99_us: f64,
    fetch_mebibytes_per_second: f64,
    fetch_p99_us: f64,
    durable_record_appends: u64,
    fetched_bytes: u64,
}

struct RawPartition {
    _directories: Vec<TempDir>,
    stores: Vec<Arc<FileExtentStore>>,
    extents: Vec<ExtentId>,
    next_id: u64,
}

impl RawPartition {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut directories = Vec::new();
        let mut stores = Vec::new();
        let mut extents = Vec::new();
        for _ in 0..3 {
            let directory = TempDir::new()?;
            let store = Arc::new(FileExtentStore::open(
                directory.path(),
                FileExtentConfig::default(),
            )?);
            extents.push(store.create()?);
            stores.push(store);
            directories.push(directory);
        }
        Ok(Self {
            _directories: directories,
            stores,
            extents,
            next_id: 0,
        })
    }

    fn append(&mut self, payload: BufferChain) -> Result<(), Box<dyn std::error::Error>> {
        let id = self.next_id.to_le_bytes();
        self.next_id += 1;
        for (store, extent) in self.stores.iter().zip(&self.extents) {
            store.append(AppendPlan::new(
                *extent,
                RecordId::new(id.to_vec())?,
                payload.clone(),
            ))?;
        }
        Ok(())
    }

    fn fetch(
        &self,
        batches: usize,
        batch_bytes: usize,
    ) -> Result<Vec<f64>, Box<dyn std::error::Error>> {
        let mut latencies = Vec::with_capacity(batches);
        for record_index in 0..batches as u64 {
            let started = Instant::now();
            let bytes = self.stores[0].read_range(RangeRead {
                extent_id: self.extents[0],
                record_index,
                offset: 0,
                length: batch_bytes as u64,
            })?;
            if bytes.encoded_len() != batch_bytes {
                return Err("raw fetch length mismatch".into());
            }
            latencies.push(started.elapsed().as_secs_f64() * 1_000_000.0);
        }
        Ok(latencies)
    }
}

struct OrderedPartition {
    _directories: Vec<TempDir>,
    partition: ReplicatedPartition,
    leader: Arc<OrderedLog>,
}

impl OrderedPartition {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut directories = Vec::new();
        let mut replicas = BTreeMap::new();
        for node in 0..3 {
            let directory = TempDir::new()?;
            let store = Arc::new(FileExtentStore::open(
                directory.path(),
                FileExtentConfig::default(),
            )?);
            let log = Arc::new(OrderedLog::open(
                store,
                OrderedLogConfig {
                    partition_key: [11; 16],
                    ..OrderedLogConfig::default()
                },
                RecoveryState::default(),
            )?);
            replicas.insert(node, log);
            directories.push(directory);
        }
        let leader = Arc::clone(&replicas[&0]);
        Ok(Self {
            _directories: directories,
            partition: ReplicatedPartition::new(replicas, 0, 1, 1, 2)?,
            leader,
        })
    }

    fn append(&mut self, payload: BufferChain) -> Result<(), Box<dyn std::error::Error>> {
        let result = self
            .partition
            .append(0, 1, 0, 1, payload, Acknowledgments::All)?;
        if !result.acknowledged || result.result.durable_media_appends != 3 {
            return Err("ordered append did not durably acknowledge all replicas".into());
        }
        Ok(())
    }

    fn fetch(
        &self,
        batches: usize,
        batch_bytes: usize,
    ) -> Result<Vec<f64>, Box<dyn std::error::Error>> {
        let mut latencies = Vec::with_capacity(batches);
        for offset in 0..batches as u64 {
            let started = Instant::now();
            let result = self.leader.fetch(offset, batch_bytes as u64, true)?;
            if result.batches.len() != 1 || result.batches[0].bytes.encoded_len() != batch_bytes {
                return Err("ordered fetch result mismatch".into());
            }
            latencies.push(started.elapsed().as_secs_f64() * 1_000_000.0);
        }
        Ok(latencies)
    }
}

fn run_raw(
    batch_bytes: usize,
    concurrency: usize,
    batches: usize,
) -> Result<Sample, Box<dyn std::error::Error>> {
    let partition = Arc::new(Mutex::new(RawPartition::new()?));
    run_workload(
        partition,
        batch_bytes,
        concurrency,
        batches,
        |partition, bytes| partition.append(bytes),
        |partition| partition.fetch(batches, batch_bytes),
    )
}

fn run_ordered(
    batch_bytes: usize,
    concurrency: usize,
    batches: usize,
) -> Result<Sample, Box<dyn std::error::Error>> {
    let partition = Arc::new(Mutex::new(OrderedPartition::new()?));
    run_workload(
        partition,
        batch_bytes,
        concurrency,
        batches,
        |partition, bytes| partition.append(bytes),
        |partition| partition.fetch(batches, batch_bytes),
    )
}

fn run_workload<T, A, F>(
    partition: Arc<Mutex<T>>,
    batch_bytes: usize,
    concurrency: usize,
    batches: usize,
    append: A,
    fetch: F,
) -> Result<Sample, Box<dyn std::error::Error>>
where
    T: Send + 'static,
    A: Fn(&mut T, BufferChain) -> Result<(), Box<dyn std::error::Error>>
        + Send
        + Sync
        + Copy
        + 'static,
    F: Fn(&T) -> Result<Vec<f64>, Box<dyn std::error::Error>>,
{
    let payload = BufferChain::from(OwnedBuffer::new(Bytes::from(vec![0x5a; batch_bytes])));
    let started = Instant::now();
    let mut workers = Vec::new();
    for worker in 0..concurrency {
        let partition = Arc::clone(&partition);
        let payload = payload.clone();
        workers.push(thread::spawn(move || -> Result<Vec<f64>, String> {
            let mut latencies = Vec::new();
            let mut index = worker;
            while index < batches {
                let operation = Instant::now();
                append(
                    &mut *partition.lock().map_err(|_| "lock poisoned")?,
                    payload.clone(),
                )
                .map_err(|error| error.to_string())?;
                latencies.push(operation.elapsed().as_secs_f64() * 1_000_000.0);
                index += concurrency;
            }
            Ok(latencies)
        }));
    }
    let mut append_latencies = Vec::with_capacity(batches);
    for worker in workers {
        append_latencies.extend(worker.join().map_err(|_| "worker panicked")??);
    }
    let append_seconds = started.elapsed().as_secs_f64();

    let fetch_started = Instant::now();
    let mut fetch_latencies = fetch(&*partition.lock().map_err(|_| "lock poisoned")?)?;
    let fetch_seconds = fetch_started.elapsed().as_secs_f64();
    append_latencies.sort_by(f64::total_cmp);
    fetch_latencies.sort_by(f64::total_cmp);
    Ok(Sample {
        append_operations_per_second: batches as f64 / append_seconds,
        append_p99_us: percentile(&append_latencies, 0.99),
        fetch_mebibytes_per_second: (batches * batch_bytes) as f64
            / (1024.0 * 1024.0)
            / fetch_seconds,
        fetch_p99_us: percentile(&fetch_latencies, 0.99),
        durable_record_appends: batches as u64 * 3,
        fetched_bytes: (batches * batch_bytes) as u64,
    })
}

fn percentile(values: &[f64], percentile: f64) -> f64 {
    let index = ((values.len().saturating_sub(1)) as f64 * percentile).ceil() as usize;
    values[index.min(values.len().saturating_sub(1))]
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

fn regression(current: f64, baseline: f64, higher_is_better: bool) -> f64 {
    if higher_is_better {
        (baseline - current) / baseline * 100.0
    } else {
        (current - baseline) / baseline * 100.0
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut output = None::<PathBuf>;
    let mut repetitions = 5usize;
    let mut quick = false;
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--output" => {
                index += 1;
                output = Some(PathBuf::from(
                    arguments.get(index).ok_or("missing output path")?,
                ));
            }
            "--repetitions" => {
                index += 1;
                repetitions = arguments.get(index).ok_or("missing repetitions")?.parse()?;
            }
            "--quick" => quick = true,
            unknown => return Err(format!("unknown argument {unknown}").into()),
        }
        index += 1;
    }

    let mut cases = Vec::new();
    for batch_bytes in [1024usize, 16 * 1024, 1024 * 1024] {
        for concurrency in [1usize, 8, 32] {
            let batches = if quick {
                4
            } else if batch_bytes >= 1024 * 1024 {
                16
            } else {
                96
            };
            // One unmeasured warm-up per frozen budget.
            let _ = run_raw(batch_bytes, concurrency, 2)?;
            let _ = run_ordered(batch_bytes, concurrency, 2)?;
            let mut raw = Vec::new();
            let mut ordered = Vec::new();
            for _ in 0..repetitions {
                raw.push(run_raw(batch_bytes, concurrency, batches)?);
                ordered.push(run_ordered(batch_bytes, concurrency, batches)?);
            }
            let append_throughput_regression_percent = regression(
                median(
                    ordered
                        .iter()
                        .map(|sample| sample.append_operations_per_second)
                        .collect(),
                ),
                median(
                    raw.iter()
                        .map(|sample| sample.append_operations_per_second)
                        .collect(),
                ),
                true,
            );
            let append_p99_regression_percent = regression(
                median(ordered.iter().map(|sample| sample.append_p99_us).collect()),
                median(raw.iter().map(|sample| sample.append_p99_us).collect()),
                false,
            );
            let fetch_throughput_regression_percent = regression(
                median(
                    ordered
                        .iter()
                        .map(|sample| sample.fetch_mebibytes_per_second)
                        .collect(),
                ),
                median(
                    raw.iter()
                        .map(|sample| sample.fetch_mebibytes_per_second)
                        .collect(),
                ),
                true,
            );
            let ordered_fetch_p99 =
                median(ordered.iter().map(|sample| sample.fetch_p99_us).collect());
            let raw_fetch_p99 = median(raw.iter().map(|sample| sample.fetch_p99_us).collect());
            let fetch_p99_regression_percent = regression(ordered_fetch_p99, raw_fetch_p99, false);
            let append_pass = append_throughput_regression_percent <= 10.0
                && append_p99_regression_percent <= 15.0;
            let fetch_pass = if raw_fetch_p99 < 1000.0 {
                // The frozen budget substitutes an absolute allowance for
                // noisy sub-millisecond operations.
                ordered_fetch_p99 - raw_fetch_p99 <= 250.0
            } else {
                fetch_throughput_regression_percent <= 10.0 && fetch_p99_regression_percent <= 15.0
            };
            cases.push(CaseReport {
                batch_bytes,
                concurrency,
                batches,
                raw,
                ordered,
                append_throughput_regression_percent,
                append_p99_regression_percent,
                fetch_throughput_regression_percent,
                fetch_p99_regression_percent,
                append_pass,
                fetch_pass,
            });
        }
    }
    let spike_direct = replication_spike(
        ReplicationSpike::DirectLeaderFollower,
        10_000,
        3,
        16 * 1024,
        true,
    );
    let spike_data_bearing_single_write = replication_spike(
        ReplicationSpike::DataBearingConsensus,
        10_000,
        3,
        16 * 1024,
        true,
    );
    let spike_data_bearing_double_write_rejected = replication_spike(
        ReplicationSpike::DataBearingConsensus,
        10_000,
        3,
        16 * 1024,
        false,
    );
    let all_pass = cases.iter().all(|case| case.append_pass && case.fetch_pass)
        && spike_direct.record_copies_per_replica == 1
        && spike_data_bearing_single_write.record_copies_per_replica == 1
        && spike_data_bearing_double_write_rejected.record_copies_per_replica == 2;
    let report = Report {
        schema: "pepper.phase7.qualification.v1",
        repetitions,
        cases,
        spike_direct,
        spike_data_bearing_single_write,
        spike_data_bearing_double_write_rejected,
        all_pass,
    };
    let json = serde_json::to_vec_pretty(&report)?;
    if let Some(output) = output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(output, &json)?;
    }
    println!("{}", String::from_utf8(json)?);
    if !report.all_pass {
        std::process::exit(2);
    }
    Ok(())
}
