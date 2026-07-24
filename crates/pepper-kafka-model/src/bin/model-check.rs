// SPDX-License-Identifier: Apache-2.0

use pepper_kafka_model::{
    GroupModel, ModelError, PartitionModel, ProduceOutcome, ProducerState, TransactionModel,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::PathBuf,
};

#[derive(Debug, Serialize)]
struct ModelCheckReport {
    schema_version: u32,
    partition_traces_checked: u64,
    producer_traces_checked: u64,
    group_traces_checked: u64,
    transaction_traces_checked: u64,
    invariants: Vec<&'static str>,
    result: &'static str,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = parse_output()?;
    let partition_traces_checked = check_partitions()?;
    let producer_traces_checked = check_producers()?;
    let group_traces_checked = check_groups()?;
    let transaction_traces_checked = check_transactions()?;
    let report = ModelCheckReport {
        schema_version: 1,
        partition_traces_checked,
        producer_traces_checked,
        group_traces_checked,
        transaction_traces_checked,
        invariants: vec![
            "committed offsets form an immutable prefix",
            "stale leaders cannot append to a promised quorum",
            "producer retries reconstruct the original result",
            "old group generations are fenced",
            "read_committed visibility requires all commit markers",
        ],
        result: "pass",
    };
    let json = serde_json::to_vec_pretty(&report)?;
    if let Some(path) = output {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, &json)?;
    }
    println!("{}", String::from_utf8(json)?);
    Ok(())
}

fn parse_output() -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    match args.next() {
        None => Ok(None),
        Some(flag) if flag == "--output" => {
            let path = args.next().ok_or("--output requires a path")?;
            if args.next().is_some() {
                return Err("unexpected arguments".into());
            }
            Ok(Some(path.into()))
        }
        Some(_) => Err("usage: model-check [--output PATH]".into()),
    }
}

fn check_partitions() -> Result<u64, ModelError> {
    let mut traces = 0;
    for first_digest in 0..4 {
        for leader in 1..=3 {
            let mut model = PartitionModel::new([1, 2, 3])?;
            let follower = if leader == 1 { 2 } else { 1 };
            let voters = BTreeSet::from([leader, follower]);
            model.elect(leader, 1, &voters)?;
            let entry = model.append(first_digest)?;
            model.replicate(follower, &entry)?;
            model.commit(0)?;
            model.propagate_commit(follower, 0)?;
            model.check_invariants()?;
            traces += 1;

            for next_leader in 1..=3 {
                if next_leader == leader {
                    continue;
                }
                let other = if next_leader == follower { 3 } else { follower };
                let mut failed_over = model.clone();
                failed_over.leader = None;
                if failed_over
                    .elect(next_leader, 2, &BTreeSet::from([next_leader, other]))
                    .is_ok()
                {
                    failed_over.check_invariants()?;
                    traces += 1;
                }
            }
        }
    }
    Ok(traces)
}

fn check_producers() -> Result<u64, ModelError> {
    let mut traces = 0;
    for count in 1..=8 {
        let mut producer = ProducerState::new(1);
        let first = producer.produce(1, 0, count, u64::from(count), 10)?;
        let retry = producer.produce(1, 0, count, u64::from(count), 100)?;
        if !matches!(
            (first, retry),
            (ProduceOutcome::Appended(_), ProduceOutcome::Duplicate(_))
        ) {
            return Err(ModelError::DuplicateSequenceConflict);
        }
        if producer.produce(1, count + 1, 1, 99, 100).is_ok() {
            return Err(ModelError::OutOfOrderSequence);
        }
        traces += 1;
    }
    Ok(traces)
}

fn check_groups() -> Result<u64, ModelError> {
    let mut traces = 0;
    for member_count in 1..=4 {
        let mut group = GroupModel::new();
        for index in 0..member_count {
            group.join(format!("member-{index}"))?;
        }
        let generation = group.generation;
        let members = group.members.iter().cloned().collect::<Vec<_>>();
        let assignments = (0..8)
            .map(|partition| {
                (
                    partition,
                    members[usize::try_from(partition).unwrap() % members.len()].clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let leader = group.leader.clone().ok_or(ModelError::MissingGroupLeader)?;
        group.sync(&leader, generation, assignments)?;
        group.check_invariants()?;
        traces += 1;
    }
    Ok(traces)
}

fn check_transactions() -> Result<u64, ModelError> {
    let mut traces = 0;
    for commit in [false, true] {
        for partition_count in 0..=4 {
            let mut transaction = TransactionModel::new(1, 1);
            transaction.begin(1)?;
            for partition in 0..partition_count {
                let offset = u64::from(partition) * 10;
                transaction.append(1, partition, offset, offset + 1)?;
            }
            transaction.prepare(1, commit)?;
            for partition in 0..partition_count {
                transaction.record_marker(1, partition, commit)?;
            }
            transaction.complete(1)?;
            if transaction.read_committed_visible() != commit {
                return Err(ModelError::InvalidTransactionTransition);
            }
            traces += 1;
        }
    }
    Ok(traces)
}
