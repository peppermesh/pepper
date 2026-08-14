// SPDX-License-Identifier: Apache-2.0

//! Bounded in-memory cache for immutable, content-addressed blocks.
//!
//! Blocks are keyed by CID and never change, so this cache needs no
//! invalidation to stay consistent — the only policy is the byte budget. The
//! read path measured ~4.4 KiB of peer fetches per S3 GET (RF=1 payloads
//! usually live on a peer node); serving repeat reads from gateway memory
//! removes that cross-node hop without touching any consistency contract.
//!
//! Eviction is FIFO over insertion order (hits do not reorder), which is
//! cheap, bounded, and adequate for hot-set read workloads; entries larger
//! than `MAX_CACHEABLE_BLOCK_BYTES` bypass the cache entirely so large
//! streamed objects cannot churn it.

use pepper_types::{Block, Cid};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const MAX_CACHEABLE_BLOCK_BYTES: usize = 256 * 1024;
const DEFAULT_BUDGET_BYTES: u64 = 256 * 1024 * 1024;

pub(super) static BLOCK_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
pub(super) static BLOCK_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);

struct BlockCacheState {
    entries: HashMap<String, Block>,
    order: VecDeque<String>,
    bytes: u64,
}

pub(super) struct BlockPayloadCache {
    budget_bytes: u64,
    state: Mutex<BlockCacheState>,
}

impl Default for BlockPayloadCache {
    fn default() -> Self {
        Self {
            budget_bytes: DEFAULT_BUDGET_BYTES,
            state: Mutex::new(BlockCacheState {
                entries: HashMap::new(),
                order: VecDeque::new(),
                bytes: 0,
            }),
        }
    }
}

impl BlockPayloadCache {
    pub(super) fn get(&self, cid: &Cid) -> Option<Block> {
        let state = self.state.lock().expect("block cache lock poisoned");
        let block = state.entries.get(&cid.to_string()).cloned();
        drop(state);
        if block.is_some() {
            BLOCK_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
        } else {
            BLOCK_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
        }
        block
    }

    pub(super) fn put(&self, block: &Block) {
        if block.payload.len() > MAX_CACHEABLE_BLOCK_BYTES {
            return;
        }
        let key = block.cid.to_string();
        let mut state = self.state.lock().expect("block cache lock poisoned");
        if state.entries.contains_key(&key) {
            return;
        }
        state.bytes = state.bytes.saturating_add(block.payload.len() as u64);
        state.entries.insert(key.clone(), block.clone());
        state.order.push_back(key);
        while state.bytes > self.budget_bytes {
            let Some(evicted) = state.order.pop_front() else {
                break;
            };
            if let Some(block) = state.entries.remove(&evicted) {
                state.bytes = state.bytes.saturating_sub(block.payload.len() as u64);
            }
        }
    }
}
