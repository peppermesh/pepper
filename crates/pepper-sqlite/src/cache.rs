// SPDX-License-Identifier: Apache-2.0

//! Bounded cache for verified immutable blocks and page packs.

use pepper_types::Cid;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

#[derive(Debug)]
struct CacheState {
    entries: HashMap<Cid, Arc<Vec<u8>>>,
    order: VecDeque<Cid>,
    bytes: usize,
}

#[derive(Debug)]
pub struct ImmutableBlockCache {
    maximum_bytes: usize,
    state: Mutex<CacheState>,
}

impl ImmutableBlockCache {
    pub fn new(maximum_bytes: usize) -> Self {
        Self {
            maximum_bytes,
            state: Mutex::new(CacheState {
                entries: HashMap::new(),
                order: VecDeque::new(),
                bytes: 0,
            }),
        }
    }

    pub fn get(&self, cid: &Cid) -> Option<Arc<Vec<u8>>> {
        let mut state = self.state.lock().ok()?;
        let value = state.entries.get(cid)?.clone();
        if let Some(index) = state.order.iter().position(|item| item == cid) {
            state.order.remove(index);
        }
        state.order.push_back(cid.clone());
        Some(value)
    }

    /// Insert bytes only when their content verifies against the key.
    pub fn insert_verified(&self, cid: Cid, bytes: Vec<u8>) -> bool {
        if !cid.verify(&bytes) || bytes.len() > self.maximum_bytes {
            return false;
        }
        self.insert(cid, bytes)
    }

    /// Insert logical object bytes returned by a trusted resolver. Manifest
    /// CIDs commit to their child graph rather than directly to these bytes.
    pub fn insert_resolved(&self, cid: Cid, bytes: Vec<u8>) -> bool {
        if bytes.len() > self.maximum_bytes {
            return false;
        }
        self.insert(cid, bytes)
    }

    fn insert(&self, cid: Cid, bytes: Vec<u8>) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.entries.contains_key(&cid) {
            return true;
        }
        while state.bytes.saturating_add(bytes.len()) > self.maximum_bytes {
            let Some(oldest) = state.order.pop_front() else {
                break;
            };
            if let Some(removed) = state.entries.remove(&oldest) {
                state.bytes = state.bytes.saturating_sub(removed.len());
            }
        }
        state.bytes = state.bytes.saturating_add(bytes.len());
        state.order.push_back(cid.clone());
        state.entries.insert(cid, Arc::new(bytes));
        true
    }

    pub fn current_bytes(&self) -> usize {
        self.state.lock().map_or(0, |state| state.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_types::CODEC_SMALL_OBJECT;

    #[test]
    fn cache_is_cid_keyed_verified_and_bounded() {
        let cache = ImmutableBlockCache::new(8);
        let first = Cid::new(CODEC_SMALL_OBJECT, b"aaaa");
        let second = Cid::new(CODEC_SMALL_OBJECT, b"bbbbbb");
        assert!(!cache.insert_verified(first.clone(), b"wrong".to_vec()));
        assert!(cache.insert_verified(first.clone(), b"aaaa".to_vec()));
        assert_eq!(&**cache.get(&first).unwrap(), b"aaaa");
        assert!(cache.insert_verified(second.clone(), b"bbbbbb".to_vec()));
        assert!(cache.get(&first).is_none());
        assert_eq!(&**cache.get(&second).unwrap(), b"bbbbbb");
        assert!(cache.current_bytes() <= 8);
    }
}
