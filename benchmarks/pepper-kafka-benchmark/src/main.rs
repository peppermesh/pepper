// SPDX-License-Identifier: Apache-2.0

use bytes::{Buf, BufMut, Bytes, BytesMut};
use kafka_protocol::{
    messages::{
        ApiKey, FetchRequest, FetchResponse, ProduceRequest, ProduceResponse, RequestHeader,
        ResponseHeader,
        fetch_request::{FetchPartition, FetchTopic},
        produce_request::{PartitionProduceData, TopicProduceData},
    },
    protocol::{Decodable, Encodable, HeaderVersion, StrBytes},
    records::{Compression, Record, RecordBatchEncoder, RecordEncodeOptions, TimestampType},
};
use pepper_kafka::{
    KafkaCluster,
    server::{KafkaServer, KafkaServerConfig},
};
use pepper_kafka_protocol::ProtocolLimits;
use pepper_ordered_log::Acknowledgments;
use serde::Serialize;
use std::{
    env, fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[derive(Debug, Serialize)]
struct Report {
    schema: &'static str,
    repetitions: usize,
    cases: Vec<CaseReport>,
    all_pass: bool,
}

#[derive(Debug, Serialize)]
struct CaseReport {
    batch_bytes: usize,
    concurrency: usize,
    batches: usize,
    direct: Vec<Sample>,
    protocol: Vec<Sample>,
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
    fetched_bytes: u64,
}

fn record_batch(target_bytes: usize) -> Bytes {
    let value_bytes = target_bytes.saturating_sub(70);
    let record = Record {
        transactional: false,
        control: false,
        partition_leader_epoch: -1,
        producer_id: -1,
        producer_epoch: -1,
        timestamp_type: TimestampType::Creation,
        timestamp: 100,
        sequence: -1,
        offset: 0,
        key: None,
        value: Some(Bytes::from(vec![0x5a; value_bytes])),
        headers: Default::default(),
    };
    let mut encoded = BytesMut::new();
    RecordBatchEncoder::encode(
        &mut encoded,
        [&record],
        &RecordEncodeOptions {
            version: 2,
            compression: Compression::None,
        },
    )
    .expect("record batch");
    encoded.freeze()
}

async fn cluster(
    root: &TempDir,
    port: u16,
    topic: &str,
) -> Result<Arc<KafkaCluster>, Box<dyn std::error::Error>> {
    let cluster = KafkaCluster::open(
        root.path(),
        format!("phase8-{topic}"),
        0,
        vec![(0, "127.0.0.1".into(), port)],
        ProtocolLimits::default(),
    )
    .await?;
    cluster
        .create_topic(topic.into(), 1, 1, Default::default(), false)
        .await?;
    Ok(cluster)
}

async fn run_direct(
    target_bytes: usize,
    concurrency: usize,
    batches: usize,
) -> Result<Sample, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let cluster = cluster(&root, address.port(), "direct").await?;
    let raw_task = tokio::spawn(serve_raw(listener, Arc::clone(&cluster)));
    let records = record_batch(target_bytes);
    let mut append_frame = BytesMut::with_capacity(records.len() + 5);
    append_frame.put_u32((records.len() + 1) as u32);
    append_frame.put_u8(0);
    append_frame.extend_from_slice(&records);
    let append_frame = append_frame.freeze();
    let next = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    let mut workers = Vec::new();
    for _ in 0..concurrency {
        let append_frame = append_frame.clone();
        let next = Arc::clone(&next);
        workers.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(address)
                .await
                .map_err(|error| error.to_string())?;
            stream
                .set_nodelay(true)
                .map_err(|error| error.to_string())?;
            let mut latencies = Vec::new();
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= batches {
                    break;
                }
                let operation = Instant::now();
                stream
                    .write_all(&append_frame)
                    .await
                    .map_err(|error| error.to_string())?;
                let length = stream.read_u32().await.map_err(|error| error.to_string())?;
                if length != 9 || stream.read_u8().await.map_err(|error| error.to_string())? != 0 {
                    return Err("raw append failed".to_string());
                }
                let _base_offset = stream.read_u64().await.map_err(|error| error.to_string())?;
                latencies.push(operation.elapsed().as_secs_f64() * 1_000_000.0);
            }
            Ok::<_, String>(latencies)
        }));
    }
    let mut append_latencies = Vec::new();
    for worker in workers {
        append_latencies.extend(worker.await??);
    }
    let append_seconds = started.elapsed().as_secs_f64();

    let fetch_started = Instant::now();
    let mut stream = TcpStream::connect(address).await?;
    stream.set_nodelay(true)?;
    let mut fetch_latencies = Vec::with_capacity(batches);
    let mut fetched_bytes = 0u64;
    for offset in 0..batches as u64 {
        let mut frame = BytesMut::with_capacity(17);
        frame.put_u32(13);
        frame.put_u8(1);
        frame.put_u64(offset);
        frame.put_u32(records.len() as u32);
        let operation = Instant::now();
        stream.write_all(&frame).await?;
        let length = stream.read_u32().await?;
        if length < 13 || stream.read_u8().await? != 0 {
            return Err("raw fetch failed".into());
        }
        let _high_watermark = stream.read_u64().await?;
        let record_bytes = stream.read_u32().await? as usize;
        let mut payload = vec![0u8; record_bytes];
        stream.read_exact(&mut payload).await?;
        fetched_bytes += record_bytes as u64;
        fetch_latencies.push(operation.elapsed().as_secs_f64() * 1_000_000.0);
    }
    let fetch_seconds = fetch_started.elapsed().as_secs_f64();
    raw_task.abort();
    Ok(sample(
        batches,
        append_seconds,
        append_latencies,
        fetched_bytes,
        fetch_seconds,
        fetch_latencies,
    ))
}

async fn serve_raw(listener: TcpListener, cluster: Arc<KafkaCluster>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        let cluster = Arc::clone(&cluster);
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            while let Ok(length) = stream.read_u32().await {
                let length = length as usize;
                if length == 0 || length > ProtocolLimits::default().maximum_frame_bytes {
                    break;
                }
                let mut request = vec![0u8; length];
                if stream.read_exact(&mut request).await.is_err() {
                    break;
                }
                match request[0] {
                    0 => {
                        let records = Bytes::from(request).slice(1..);
                        let result = cluster
                            .produce(0, "direct", 0, 100, records, Acknowledgments::All)
                            .await;
                        let mut response = BytesMut::with_capacity(13);
                        response.put_u32(9);
                        match result {
                            Ok(result) => {
                                response.put_u8(0);
                                response.put_u64(result.result.base_offset);
                            }
                            Err(error) => {
                                eprintln!("raw append failed: {error}");
                                response.put_u8(1);
                                response.put_u64(0);
                            }
                        }
                        if stream.write_all(&response).await.is_err() {
                            break;
                        }
                    }
                    1 if request.len() == 13 => {
                        let offset = u64::from_be_bytes(request[1..9].try_into().unwrap());
                        let maximum = u32::from_be_bytes(request[9..13].try_into().unwrap()) as u64;
                        match cluster.fetch(0, "direct", 0, offset, maximum).await {
                            Ok(result) => {
                                let record_bytes = result
                                    .batches
                                    .iter()
                                    .map(|batch| batch.bytes.encoded_len())
                                    .sum::<usize>();
                                let mut header = BytesMut::with_capacity(17);
                                header.put_u32((13 + record_bytes) as u32);
                                header.put_u8(0);
                                header.put_u64(result.high_watermark);
                                header.put_u32(record_bytes as u32);
                                if stream.write_all(&header).await.is_err() {
                                    break;
                                }
                                let mut failed = false;
                                for batch in result.batches {
                                    if stream.write_all(batch.bytes.bytes()).await.is_err() {
                                        failed = true;
                                        break;
                                    }
                                }
                                if failed {
                                    break;
                                }
                            }
                            Err(_) => {
                                let mut response = BytesMut::with_capacity(17);
                                response.put_u32(13);
                                response.put_u8(1);
                                response.put_u64(0);
                                response.put_u32(0);
                                if stream.write_all(&response).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    _ => break,
                }
            }
        });
    }
}

fn request_frame<T: Encodable + HeaderVersion>(
    key: ApiKey,
    version: i16,
    correlation: i32,
    body: T,
) -> Bytes {
    let mut payload = BytesMut::new();
    RequestHeader::default()
        .with_request_api_key(key as i16)
        .with_request_api_version(version)
        .with_correlation_id(correlation)
        .with_client_id(Some(StrBytes::from_static_str("phase8-benchmark")))
        .encode(&mut payload, T::header_version(version))
        .expect("request header");
    body.encode(&mut payload, version).expect("request body");
    let mut framed = BytesMut::with_capacity(payload.len() + 4);
    framed.put_i32(payload.len() as i32);
    framed.extend_from_slice(&payload);
    framed.freeze()
}

async fn exchange<R: Decodable + HeaderVersion>(
    stream: &mut TcpStream,
    frame: &Bytes,
    version: i16,
) -> Result<(ResponseHeader, R), String> {
    stream
        .write_all(frame)
        .await
        .map_err(|error| error.to_string())?;
    let length = stream.read_i32().await.map_err(|error| error.to_string())?;
    if length < 4 {
        return Err("short response".into());
    }
    let mut payload = BytesMut::zeroed(length as usize);
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|error| error.to_string())?;
    let header = ResponseHeader::decode(&mut payload, R::header_version(version))
        .map_err(|error| error.to_string())?;
    let response = R::decode(&mut payload, version).map_err(|error| error.to_string())?;
    if payload.has_remaining() {
        return Err("response has trailing bytes".into());
    }
    Ok((header, response))
}

async fn run_protocol(
    target_bytes: usize,
    concurrency: usize,
    batches: usize,
    enforce_response_budget: bool,
) -> Result<Sample, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let cluster = cluster(&root, address.port(), "protocol").await?;
    let server = Arc::new(KafkaServer::new(
        0,
        cluster,
        KafkaServerConfig {
            enforce_response_budget,
            ..KafkaServerConfig::default()
        },
    )?);
    let task = tokio::spawn(async move {
        let _ = server.serve(listener).await;
    });
    let records = record_batch(target_bytes);
    let next = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    let mut workers = Vec::new();
    for worker_id in 0..concurrency {
        let records = records.clone();
        let next = Arc::clone(&next);
        workers.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(address)
                .await
                .map_err(|error| error.to_string())?;
            stream
                .set_nodelay(true)
                .map_err(|error| error.to_string())?;
            let mut latencies = Vec::new();
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= batches {
                    break;
                }
                let body = ProduceRequest::default()
                    .with_acks(-1)
                    .with_timeout_ms(30_000)
                    .with_topic_data(vec![
                        TopicProduceData::default()
                            .with_name(StrBytes::from_static_str("protocol").into())
                            .with_partition_data(vec![
                                PartitionProduceData::default()
                                    .with_index(0)
                                    .with_records(Some(records.clone())),
                            ]),
                    ]);
                let frame = request_frame(
                    ApiKey::Produce,
                    3,
                    (worker_id * batches + index) as i32,
                    body,
                );
                let operation = Instant::now();
                let (_, response): (_, ProduceResponse) = exchange(&mut stream, &frame, 3)
                    .await
                    .map_err(|error| error.to_string())?;
                if response.responses[0].partition_responses[0].error_code != 0 {
                    return Err("produce response failed".to_string());
                }
                latencies.push(operation.elapsed().as_secs_f64() * 1_000_000.0);
            }
            Ok::<_, String>(latencies)
        }));
    }
    let mut append_latencies = Vec::new();
    for worker in workers {
        append_latencies.extend(worker.await??);
    }
    let append_seconds = started.elapsed().as_secs_f64();

    let mut stream = TcpStream::connect(address).await?;
    stream.set_nodelay(true)?;
    let fetch_started = Instant::now();
    let mut fetch_latencies = Vec::with_capacity(batches);
    let mut fetched_bytes = 0u64;
    for offset in 0..batches {
        let body = FetchRequest::default()
            .with_replica_id((-1).into())
            .with_max_wait_ms(0)
            .with_min_bytes(1)
            .with_max_bytes(records.len() as i32)
            .with_topics(vec![
                FetchTopic::default()
                    .with_topic(StrBytes::from_static_str("protocol").into())
                    .with_partitions(vec![
                        FetchPartition::default()
                            .with_partition(0)
                            .with_fetch_offset(offset as i64)
                            .with_partition_max_bytes(records.len() as i32),
                    ]),
            ]);
        let frame = request_frame(ApiKey::Fetch, 4, offset as i32, body);
        let operation = Instant::now();
        let (_, response): (_, FetchResponse) = exchange(&mut stream, &frame, 4).await?;
        let partition = &response.responses[0].partitions[0];
        if partition.error_code != 0 {
            return Err("fetch response failed".into());
        }
        fetched_bytes += partition.records.as_ref().map_or(0, |bytes| bytes.len()) as u64;
        fetch_latencies.push(operation.elapsed().as_secs_f64() * 1_000_000.0);
    }
    let fetch_seconds = fetch_started.elapsed().as_secs_f64();
    task.abort();
    Ok(sample(
        batches,
        append_seconds,
        append_latencies,
        fetched_bytes,
        fetch_seconds,
        fetch_latencies,
    ))
}

fn sample(
    batches: usize,
    append_seconds: f64,
    append_latencies: Vec<f64>,
    fetched_bytes: u64,
    fetch_seconds: f64,
    fetch_latencies: Vec<f64>,
) -> Sample {
    Sample {
        append_operations_per_second: batches as f64 / append_seconds,
        append_p99_us: percentile(append_latencies, 0.99),
        fetch_mebibytes_per_second: fetched_bytes as f64 / (1024.0 * 1024.0) / fetch_seconds,
        fetch_p99_us: percentile(fetch_latencies, 0.99),
        fetched_bytes,
    }
}

fn percentile(mut values: Vec<f64>, quantile: f64) -> f64 {
    values.sort_by(f64::total_cmp);
    let index = ((values.len().saturating_sub(1)) as f64 * quantile).round() as usize;
    values[index]
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

fn regression(candidate: f64, baseline: f64, higher_is_better: bool) -> f64 {
    if higher_is_better {
        ((baseline - candidate) / baseline * 100.0).max(0.0)
    } else {
        ((candidate - baseline) / baseline * 100.0).max(0.0)
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut output = None::<PathBuf>;
    let mut repetitions = 5usize;
    let mut quick = false;
    let mut phase9_paired = false;
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
            "--phase9-paired" => phase9_paired = true,
            unknown => return Err(format!("unknown argument {unknown}").into()),
        }
        index += 1;
    }

    let mut cases = Vec::new();
    for batch_bytes in [1024usize, 16 * 1024, 1024 * 1024] {
        for concurrency in [1usize, 8, 32] {
            let batches = if quick {
                4
            } else if phase9_paired && batch_bytes >= 1024 * 1024 {
                128
            } else if phase9_paired && batch_bytes >= 16 * 1024 {
                1_024
            } else if phase9_paired {
                4_096
            } else if batch_bytes >= 1024 * 1024 {
                64
            } else {
                96
            };
            let _ = run_direct(batch_bytes, concurrency, 2).await?;
            let _ = run_protocol(batch_bytes, concurrency, 2, true).await?;
            let mut direct = Vec::new();
            let mut protocol = Vec::new();
            for repetition in 0..repetitions {
                if repetition % 2 == 0 {
                    if phase9_paired {
                        direct.push(run_protocol(batch_bytes, concurrency, batches, false).await?);
                    } else {
                        direct.push(run_direct(batch_bytes, concurrency, batches).await?);
                    }
                    protocol.push(run_protocol(batch_bytes, concurrency, batches, true).await?);
                } else {
                    protocol.push(run_protocol(batch_bytes, concurrency, batches, true).await?);
                    if phase9_paired {
                        direct.push(run_protocol(batch_bytes, concurrency, batches, false).await?);
                    } else {
                        direct.push(run_direct(batch_bytes, concurrency, batches).await?);
                    }
                }
            }
            let append_throughput_regression_percent = regression(
                median(
                    protocol
                        .iter()
                        .map(|sample| sample.append_operations_per_second)
                        .collect(),
                ),
                median(
                    direct
                        .iter()
                        .map(|sample| sample.append_operations_per_second)
                        .collect(),
                ),
                true,
            );
            let direct_append_p99 =
                median(direct.iter().map(|sample| sample.append_p99_us).collect());
            let protocol_append_p99 =
                median(protocol.iter().map(|sample| sample.append_p99_us).collect());
            let append_p99_regression_percent =
                regression(protocol_append_p99, direct_append_p99, false);
            let fetch_throughput_regression_percent = regression(
                median(
                    protocol
                        .iter()
                        .map(|sample| sample.fetch_mebibytes_per_second)
                        .collect(),
                ),
                median(
                    direct
                        .iter()
                        .map(|sample| sample.fetch_mebibytes_per_second)
                        .collect(),
                ),
                true,
            );
            let direct_fetch_p99 =
                median(direct.iter().map(|sample| sample.fetch_p99_us).collect());
            let protocol_fetch_p99 =
                median(protocol.iter().map(|sample| sample.fetch_p99_us).collect());
            let fetch_p99_regression_percent =
                regression(protocol_fetch_p99, direct_fetch_p99, false);
            let append_pass = append_throughput_regression_percent <= 10.0
                && (append_p99_regression_percent <= 10.0
                    || (direct_append_p99 < 1000.0
                        && protocol_append_p99 - direct_append_p99 <= 250.0));
            let fetch_pass = if direct_fetch_p99 < 1000.0 {
                protocol_fetch_p99 - direct_fetch_p99 <= 250.0
            } else {
                fetch_throughput_regression_percent <= 10.0 && fetch_p99_regression_percent <= 10.0
            };
            cases.push(CaseReport {
                batch_bytes,
                concurrency,
                batches,
                direct,
                protocol,
                append_throughput_regression_percent,
                append_p99_regression_percent,
                fetch_throughput_regression_percent,
                fetch_p99_regression_percent,
                append_pass,
                fetch_pass,
            });
        }
    }
    let all_pass = cases.iter().all(|case| case.append_pass && case.fetch_pass);
    let report = Report {
        schema: if phase9_paired {
            "pepper.phase9.paired-kafka.v1"
        } else {
            "pepper.phase8.qualification.v1"
        },
        repetitions,
        cases,
        all_pass,
    };
    let json = serde_json::to_vec_pretty(&report)?;
    if let Some(output) = output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(output, &json)?;
    } else {
        println!("{}", String::from_utf8(json)?);
    }
    if !all_pass {
        return Err("Phase 8 qualification failed".into());
    }
    Ok(())
}
