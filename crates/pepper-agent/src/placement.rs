// SPDX-License-Identifier: Apache-2.0

//! Authoritative placement maps and bounded migration/repair exceptions.

use pepper_placement::{
    AuthoritativePlacementError, PlacementDecision, PlacementException, PlacementMap,
    PlacementMapNode, PlacementMapNodeState, PlacementNode, select_authoritative,
};
use pepper_types::PlacementReference;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, RwLock},
};

const MAX_PLACEMENT_EXCEPTIONS: usize = 4096;
const FAILURE_DOMAIN_LEVELS: [&str; 4] = ["region", "zone", "rack", "failure_domain"];

#[derive(Clone, Default)]
pub(super) struct PlacementSnapshot {
    maps: BTreeMap<u64, Arc<PlacementMap>>,
    exceptions: HashMap<PlacementReference, PlacementException>,
}

impl PlacementSnapshot {
    pub(super) fn current_map(&self) -> Option<Arc<PlacementMap>> {
        self.maps.last_key_value().map(|(_, map)| map.clone())
    }

    pub(super) fn map(&self, epoch: u64) -> Option<Arc<PlacementMap>> {
        self.maps.get(&epoch).cloned()
    }

    pub(super) fn exception(
        &self,
        reference: &PlacementReference,
        now_unix_seconds: i64,
    ) -> Option<PlacementException> {
        self.exceptions
            .get(reference)
            .filter(|exception| exception.expires_at_unix_seconds > now_unix_seconds)
            .cloned()
    }
}

pub(super) fn placement_map_from_candidates(
    epoch: u64,
    candidates: &[PlacementNode],
) -> PlacementMap {
    let failure_domain_levels = FAILURE_DOMAIN_LEVELS
        .iter()
        .filter(|level| {
            candidates.iter().any(|node| {
                node.placement_labels.contains_key(**level)
                    || (**level == "failure_domain" && node.failure_domain.is_some())
            })
        })
        .map(|level| (*level).to_string())
        .collect::<Vec<_>>();
    let mut nodes = candidates
        .iter()
        .map(|node| {
            let mut failure_domains = BTreeMap::new();
            for level in &failure_domain_levels {
                if let Some(value) = node.placement_labels.get(level).cloned().or_else(|| {
                    (level == "failure_domain")
                        .then(|| node.failure_domain.clone())
                        .flatten()
                }) {
                    failure_domains.insert(level.clone(), value);
                }
            }
            PlacementMapNode {
                node_id: node.node_id.clone(),
                // Dynamic capacity is deliberately excluded. Weight changes
                // require a new committed placement-map epoch.
                weight: 1,
                state: PlacementMapNodeState::In,
                failure_domains,
            }
        })
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    PlacementMap {
        epoch,
        failure_domain_levels,
        nodes,
    }
}

#[derive(Default)]
pub(super) struct PlacementRuntime {
    maps: RwLock<BTreeMap<u64, Arc<PlacementMap>>>,
    exceptions: RwLock<HashMap<PlacementReference, PlacementException>>,
}

impl PlacementRuntime {
    pub(super) fn snapshot(&self) -> PlacementSnapshot {
        PlacementSnapshot {
            maps: self
                .maps
                .read()
                .expect("placement map lock poisoned")
                .clone(),
            exceptions: self
                .exceptions
                .read()
                .expect("placement exception lock poisoned")
                .clone(),
        }
    }

    pub(super) fn install_map(
        &self,
        map: PlacementMap,
    ) -> Result<Arc<PlacementMap>, AuthoritativePlacementError> {
        map.validate()?;
        let mut maps = self.maps.write().expect("placement map lock poisoned");
        if let Some(existing) = maps.get(&map.epoch) {
            if existing.as_ref() != &map {
                return Err(AuthoritativePlacementError::InvalidEpoch);
            }
            return Ok(existing.clone());
        }
        let map = Arc::new(map);
        maps.insert(map.epoch, map.clone());
        Ok(map)
    }

    pub(super) fn current_map(&self) -> Option<Arc<PlacementMap>> {
        if let Ok(map) = crate::fast_path::local_current_placement_map() {
            return map;
        }
        self.maps
            .read()
            .expect("placement map lock poisoned")
            .last_key_value()
            .map(|(_, map)| map.clone())
    }

    pub(super) fn map(&self, epoch: u64) -> Option<Arc<PlacementMap>> {
        if let Ok(map) = crate::fast_path::local_placement_map(epoch) {
            return map;
        }
        self.maps
            .read()
            .expect("placement map lock poisoned")
            .get(&epoch)
            .cloned()
    }

    /// Return every locally committed placement epoch, newest first.
    ///
    /// Durable DAG roots created before a placement-map transition do not
    /// encode their own replicated-block reference. Maintenance therefore
    /// tries the bounded retained epoch history directly instead of falling
    /// back to provider discovery. Ordinary object chunks and erasure shards
    /// carry their exact placement reference in their manifest.
    pub(super) fn epochs_descending(&self) -> Vec<u64> {
        self.maps
            .read()
            .expect("placement map lock poisoned")
            .keys()
            .rev()
            .copied()
            .collect()
    }

    pub(super) fn decide(
        &self,
        reference: &PlacementReference,
    ) -> Result<PlacementDecision, AuthoritativePlacementError> {
        let map = self
            .map(reference.epoch)
            .ok_or(AuthoritativePlacementError::EpochMismatch {
                reference: reference.epoch,
                map: self.current_map().map_or(0, |map| map.epoch),
            })?;
        select_authoritative(&map, reference)
    }

    pub(super) fn install_exception(
        &self,
        exception: PlacementException,
    ) -> Result<(), AuthoritativePlacementError> {
        exception.validate()?;
        let mut exceptions = self
            .exceptions
            .write()
            .expect("placement exception lock poisoned");
        if !exceptions.contains_key(&exception.reference)
            && exceptions.len() >= MAX_PLACEMENT_EXCEPTIONS
        {
            return Err(AuthoritativePlacementError::InvalidException);
        }
        if let Some(current) = exceptions.get(&exception.reference) {
            if current.generation > exception.generation
                || (current.generation == exception.generation && current != &exception)
            {
                return Err(AuthoritativePlacementError::InvalidException);
            }
            if current == &exception {
                return Ok(());
            }
        }
        exceptions.insert(exception.reference.clone(), exception);
        Ok(())
    }

    pub(super) fn ensure_exception_capacity(
        &self,
        reference: &PlacementReference,
        now_unix_seconds: i64,
    ) -> Result<(), AuthoritativePlacementError> {
        let mut exceptions = self
            .exceptions
            .write()
            .expect("placement exception lock poisoned");
        exceptions.retain(|_, exception| exception.expires_at_unix_seconds > now_unix_seconds);
        if !exceptions.contains_key(reference) && exceptions.len() >= MAX_PLACEMENT_EXCEPTIONS {
            return Err(AuthoritativePlacementError::InvalidException);
        }
        Ok(())
    }

    pub(super) fn exception(
        &self,
        reference: &PlacementReference,
        now_unix_seconds: i64,
    ) -> Option<PlacementException> {
        if let Ok(exception) =
            crate::fast_path::local_placement_exception(reference, now_unix_seconds)
        {
            return exception;
        }
        self.exceptions
            .read()
            .expect("placement exception lock poisoned")
            .get(reference)
            .filter(|exception| exception.expires_at_unix_seconds > now_unix_seconds)
            .cloned()
    }

    pub(super) fn exceptions(&self, now_unix_seconds: i64) -> Vec<PlacementException> {
        let mut values = self
            .exceptions
            .read()
            .expect("placement exception lock poisoned")
            .values()
            .filter(|exception| exception.expires_at_unix_seconds > now_unix_seconds)
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.reference
                .epoch
                .cmp(&right.reference.epoch)
                .then_with(|| {
                    left.reference
                        .seed
                        .to_string()
                        .cmp(&right.reference.seed.to_string())
                })
                .then_with(|| left.reference.index.cmp(&right.reference.index))
        });
        values
    }

    pub(super) fn remove_exception(&self, reference: &PlacementReference) {
        self.exceptions
            .write()
            .expect("placement exception lock poisoned")
            .remove(reference);
    }

    pub(super) fn replace_exceptions(
        &self,
        values: Vec<PlacementException>,
    ) -> Result<(), AuthoritativePlacementError> {
        if values.len() > MAX_PLACEMENT_EXCEPTIONS {
            return Err(AuthoritativePlacementError::InvalidException);
        }
        let mut replacement = HashMap::with_capacity(values.len());
        for exception in values {
            exception.validate()?;
            if replacement
                .insert(exception.reference.clone(), exception)
                .is_some()
            {
                return Err(AuthoritativePlacementError::InvalidException);
            }
        }
        *self
            .exceptions
            .write()
            .expect("placement exception lock poisoned") = replacement;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_placement::{PlacementMapNode, PlacementMapNodeState};
    use pepper_types::{CODEC_RAW, Cid};

    #[test]
    fn conflicting_epoch_is_rejected_and_exception_is_bounded_by_generation() {
        let runtime = PlacementRuntime::default();
        let map = PlacementMap {
            epoch: 1,
            failure_domain_levels: Vec::new(),
            nodes: vec![PlacementMapNode {
                node_id: "node-a".to_string(),
                weight: 1,
                state: PlacementMapNodeState::In,
                failure_domains: BTreeMap::new(),
            }],
        };
        runtime.install_map(map.clone()).unwrap();
        let unknown = PlacementReference::replicated(2, Cid::new(CODEC_RAW, b"unknown"), 1);
        assert_eq!(
            runtime.decide(&unknown),
            Err(AuthoritativePlacementError::EpochMismatch {
                reference: 2,
                map: 1,
            })
        );
        let mut conflicting = map;
        conflicting.nodes[0].weight = 2;
        assert!(runtime.install_map(conflicting).is_err());

        let reference = PlacementReference::replicated(1, Cid::new(CODEC_RAW, b"x"), 1);
        let exception = PlacementException {
            reference: reference.clone(),
            block_cid: reference.seed.clone(),
            source_epoch: 1,
            target_epoch: 1,
            generation: 2,
            node_ids: vec!["node-b".to_string()],
            reason: "repair".to_string(),
            created_at_unix_seconds: 10,
            expires_at_unix_seconds: 20,
        };
        runtime.install_exception(exception.clone()).unwrap();
        let mut stale = exception;
        stale.generation = 1;
        assert!(runtime.install_exception(stale).is_err());
        let mut conflicting = runtime.exception(&reference, 15).unwrap();
        conflicting.reason = "conflicting same-generation update".to_string();
        assert!(runtime.install_exception(conflicting).is_err());
        assert!(runtime.exception(&reference, 15).is_some());
        assert!(runtime.exception(&reference, 20).is_none());
        runtime.ensure_exception_capacity(&reference, 20).unwrap();
        assert!(runtime.exceptions(0).is_empty());
        runtime.replace_exceptions(Vec::new()).unwrap();
        assert!(runtime.exception(&reference, 15).is_none());
    }
}
