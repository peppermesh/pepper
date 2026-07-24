// SPDX-License-Identifier: Apache-2.0

//! Bounded cache for verified immutable blocks and page packs.

use pepper_dataset::{CacheAdmission, SnapshotCache, SnapshotLease};
use pepper_types::Cid;
use std::sync::Arc;

#[derive(Debug)]
pub struct ImmutableBlockCache {
    cache: SnapshotCache,
}

impl ImmutableBlockCache {
    pub fn new(maximum_bytes: usize) -> Self {
        Self {
            cache: SnapshotCache::new(maximum_bytes),
        }
    }

    pub fn get(&self, cid: &Cid) -> Option<Arc<Vec<u8>>> {
        self.cache.get(cid)
    }

    /// Insert bytes only when their content verifies against the key.
    pub fn insert_verified(&self, cid: Cid, bytes: Vec<u8>) -> bool {
        self.cache
            .insert_verified(None, cid, bytes, CacheAdmission::ReuseExpected)
    }

    /// Insert logical object bytes returned by a trusted resolver. Manifest
    /// CIDs commit to their child graph rather than directly to these bytes.
    pub fn insert_resolved(&self, cid: Cid, bytes: Vec<u8>) -> bool {
        self.cache
            .insert_resolved(None, cid, bytes, CacheAdmission::ReuseExpected)
    }

    pub fn lease_snapshot(&self, snapshot: Cid) -> SnapshotLease {
        self.cache.lease(snapshot)
    }

    pub fn retain_for_snapshot(&self, snapshot: Cid, cid: &Cid) -> bool {
        self.cache.retain_for_snapshot(snapshot, cid)
    }

    pub fn insert_resolved_for_snapshot(
        &self,
        snapshot: Cid,
        cid: Cid,
        bytes: Vec<u8>,
        scan: bool,
    ) -> bool {
        self.cache.insert_resolved(
            Some(snapshot),
            cid,
            bytes,
            if scan {
                CacheAdmission::Scan
            } else {
                CacheAdmission::ReuseExpected
            },
        )
    }

    pub fn current_bytes(&self) -> usize {
        self.cache.current_bytes()
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
