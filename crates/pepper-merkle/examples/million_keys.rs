// SPDX-License-Identifier: Apache-2.0

//! Manual scale benchmark required by the Phase 2 release plan.
//!
//! ```text
//! cargo run --release -p pepper-merkle --example million_keys
//! ```
//!
//! Override the default million keys with `PEPPER_MERKLE_BENCH_KEYS` for quick
//! development runs.

use async_trait::async_trait;
use pepper_merkle::{
    MapEntry, MerkleLimits, MerkleReadStore, MerkleValue, MerkleWriteStore, build_from_sorted,
    validate_tree,
};
use pepper_types::{CODEC_RAW, Cid, Codec};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Default)]
struct MemoryStore {
    blocks: Mutex<HashMap<String, Vec<u8>>>,
}

#[async_trait]
impl MerkleReadStore for MemoryStore {
    async fn get(&self, cid: &Cid) -> Result<Vec<u8>, String> {
        self.blocks
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?
            .get(&cid.to_string())
            .cloned()
            .ok_or_else(|| "missing block".to_string())
    }
}

#[async_trait]
impl MerkleWriteStore for MemoryStore {
    async fn put(&self, codec: Codec, payload: Vec<u8>) -> Result<Cid, String> {
        let cid = Cid::new(codec, &payload);
        self.blocks
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?
            .insert(cid.to_string(), payload);
        Ok(cid)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let count = std::env::var("PEPPER_MERKLE_BENCH_KEYS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1_000_000);
    let started = Instant::now();
    let entries = (0..count)
        .map(|index| {
            let key = format!("key/{index:016}").into_bytes();
            MapEntry {
                value: MerkleValue {
                    cid: Cid::new(CODEC_RAW, &key),
                    generation: 1,
                    value_kind: "raw".to_string(),
                    metadata: Default::default(),
                },
                key,
            }
        })
        .collect::<Vec<_>>();
    let generated_in = started.elapsed();
    let store = MemoryStore::default();
    let build_started = Instant::now();
    let root = build_from_sorted(&store, &entries, MerkleLimits::default()).await?;
    let built_in = build_started.elapsed();
    let validation_started = Instant::now();
    let report = validate_tree(&store, &root, MerkleLimits::default()).await?;
    let validated_in = validation_started.elapsed();
    let blocks = store
        .blocks
        .lock()
        .map_err(|_| "store lock poisoned")?
        .len();

    println!(
        "keys={count} root={root} nodes={} blocks={} generate={} build={} validate={}",
        report.nodes,
        blocks,
        display_duration(generated_in),
        display_duration(built_in),
        display_duration(validated_in),
    );
    Ok(())
}

fn display_duration(duration: Duration) -> String {
    format!("{:.3}s", duration.as_secs_f64())
}
