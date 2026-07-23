// SPDX-License-Identifier: Apache-2.0

use pepper_types::{Cid, PlacementReference, PlacementRole};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const MAX_PLACEMENT_WEIGHT: u32 = 1_000_000;
pub const DEFAULT_REPAIR_OWNER_COUNT: usize = 3;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlacementMapNodeState {
    In,
    Out,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlacementMapNode {
    pub node_id: String,
    pub weight: u32,
    pub state: PlacementMapNodeState,
    pub failure_domains: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlacementMap {
    pub epoch: u64,
    pub failure_domain_levels: Vec<String>,
    pub nodes: Vec<PlacementMapNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlacementDecision {
    pub reference: PlacementReference,
    pub node_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlacementException {
    pub reference: PlacementReference,
    pub block_cid: Cid,
    pub source_epoch: u64,
    pub target_epoch: u64,
    pub generation: u64,
    pub node_ids: Vec<String>,
    pub reason: String,
    pub created_at_unix_seconds: i64,
    pub expires_at_unix_seconds: i64,
}

impl PlacementException {
    pub fn validate(&self) -> Result<(), AuthoritativePlacementError> {
        self.reference
            .validate()
            .map_err(|error| AuthoritativePlacementError::InvalidReference(error.to_string()))?;
        let unique = self.node_ids.iter().collect::<BTreeSet<_>>();
        if self.generation == 0
            || self.source_epoch != self.reference.epoch
            || self.target_epoch == 0
            || self.target_epoch < self.source_epoch
            || self.node_ids.is_empty()
            || self.node_ids.iter().any(|node| node.is_empty())
            || unique.len() != self.node_ids.len()
            || self.reason.is_empty()
            || self.expires_at_unix_seconds <= self.created_at_unix_seconds
            || (self.reference.role == PlacementRole::Replicated
                && self.block_cid != self.reference.seed)
        {
            return Err(AuthoritativePlacementError::InvalidException);
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthoritativePlacementError {
    #[error("placement map epoch must be nonzero")]
    InvalidEpoch,
    #[error("placement map failure-domain levels must be unique and nonempty")]
    InvalidFailureDomainLevels,
    #[error("placement map node IDs must be unique and nonempty")]
    InvalidNodeIds,
    #[error("placement node weight must be between 1 and {MAX_PLACEMENT_WEIGHT}")]
    InvalidWeight,
    #[error("placement reference is invalid: {0}")]
    InvalidReference(String),
    #[error("placement reference epoch {reference} does not match map epoch {map}")]
    EpochMismatch { reference: u64, map: u64 },
    #[error("placement map does not contain enough eligible nodes")]
    InsufficientEligibleNodes,
    #[error("repair owner count must be greater than zero")]
    InvalidRepairOwnerCount,
    #[error("placement exception is invalid")]
    InvalidException,
}

impl PlacementMap {
    pub fn validate(&self) -> Result<(), AuthoritativePlacementError> {
        if self.epoch == 0 {
            return Err(AuthoritativePlacementError::InvalidEpoch);
        }
        let mut levels = BTreeSet::new();
        if self
            .failure_domain_levels
            .iter()
            .any(|level| level.is_empty() || !levels.insert(level))
        {
            return Err(AuthoritativePlacementError::InvalidFailureDomainLevels);
        }
        let mut node_ids = BTreeSet::new();
        for node in &self.nodes {
            if node.node_id.is_empty() || !node_ids.insert(&node.node_id) {
                return Err(AuthoritativePlacementError::InvalidNodeIds);
            }
            if node.weight == 0 || node.weight > MAX_PLACEMENT_WEIGHT {
                return Err(AuthoritativePlacementError::InvalidWeight);
            }
            if node
                .failure_domains
                .iter()
                .any(|(level, value)| level.is_empty() || value.is_empty())
            {
                return Err(AuthoritativePlacementError::InvalidFailureDomainLevels);
            }
        }
        Ok(())
    }
}

pub fn select_authoritative(
    map: &PlacementMap,
    reference: &PlacementReference,
) -> Result<PlacementDecision, AuthoritativePlacementError> {
    map.validate()?;
    reference
        .validate()
        .map_err(|error| AuthoritativePlacementError::InvalidReference(error.to_string()))?;
    if reference.epoch != map.epoch {
        return Err(AuthoritativePlacementError::EpochMismatch {
            reference: reference.epoch,
            map: map.epoch,
        });
    }
    let node_ids = match reference.role {
        PlacementRole::Replicated => {
            select_distinct_nodes(map, reference, &[], reference.replicas)?
        }
        PlacementRole::ErasureShard => {
            let mut prior = Vec::with_capacity(reference.index as usize);
            for index in 0..=reference.index {
                let mut indexed = reference.clone();
                indexed.index = index;
                let selected = select_distinct_nodes(map, &indexed, &prior, 1)?;
                if index == reference.index {
                    return Ok(PlacementDecision {
                        reference: reference.clone(),
                        node_ids: selected,
                    });
                }
                prior.extend(selected);
            }
            unreachable!("inclusive erasure shard loop always returns")
        }
    };
    Ok(PlacementDecision {
        reference: reference.clone(),
        node_ids,
    })
}

/// Select the authoritative repair coordinator followed by deterministic
/// standbys. Erasure shard references for the same stripe intentionally
/// produce the same order: a stripe has one repair owner, not one competing
/// owner per shard.
pub fn select_repair_owners(
    map: &PlacementMap,
    reference: &PlacementReference,
    limit: usize,
) -> Result<Vec<String>, AuthoritativePlacementError> {
    map.validate()?;
    reference
        .validate()
        .map_err(|error| AuthoritativePlacementError::InvalidReference(error.to_string()))?;
    if limit == 0 {
        return Err(AuthoritativePlacementError::InvalidRepairOwnerCount);
    }
    let eligible = map
        .nodes
        .iter()
        .filter(|node| node.state == PlacementMapNodeState::In)
        .count();
    if eligible == 0 {
        return Err(AuthoritativePlacementError::InsufficientEligibleNodes);
    }
    let mut selected = Vec::with_capacity(limit.min(eligible));
    let mut used_domains = map
        .failure_domain_levels
        .iter()
        .map(|level| (level.clone(), BTreeSet::<String>::new()))
        .collect::<BTreeMap<_, _>>();
    while selected.len() < limit.min(eligible) {
        let candidate = map
            .nodes
            .iter()
            .filter(|node| {
                node.state == PlacementMapNodeState::In && !selected.contains(&node.node_id)
            })
            .min_by(|left, right| {
                compare_repair_candidate(map, reference, left, right, &used_domains)
            })
            .ok_or(AuthoritativePlacementError::InsufficientEligibleNodes)?;
        selected.push(candidate.node_id.clone());
        record_domains(map, candidate, &mut used_domains);
    }
    Ok(selected)
}

/// Select one explicit temporary/migration destination outside the canonical
/// owner set while preserving as much configured failure-domain diversity as
/// possible. The result is deterministic and must be recorded as a placement
/// exception before it is used as an authoritative read source.
pub fn select_repair_replacement(
    map: &PlacementMap,
    reference: &PlacementReference,
    excluded_node_ids: &[String],
) -> Result<String, AuthoritativePlacementError> {
    map.validate()?;
    reference
        .validate()
        .map_err(|error| AuthoritativePlacementError::InvalidReference(error.to_string()))?;
    let excluded = excluded_node_ids.iter().collect::<BTreeSet<_>>();
    let mut used_domains = map
        .failure_domain_levels
        .iter()
        .map(|level| (level.clone(), BTreeSet::<String>::new()))
        .collect::<BTreeMap<_, _>>();
    for node_id in &excluded {
        if let Some(node) = map.nodes.iter().find(|node| &node.node_id == *node_id) {
            record_domains(map, node, &mut used_domains);
        }
    }
    map.nodes
        .iter()
        .filter(|node| node.state == PlacementMapNodeState::In && !excluded.contains(&node.node_id))
        .min_by(|left, right| compare_repair_candidate(map, reference, left, right, &used_domains))
        .map(|node| node.node_id.clone())
        .ok_or(AuthoritativePlacementError::InsufficientEligibleNodes)
}

fn select_distinct_nodes(
    map: &PlacementMap,
    reference: &PlacementReference,
    excluded: &[String],
    count: u16,
) -> Result<Vec<String>, AuthoritativePlacementError> {
    let excluded = excluded.iter().collect::<BTreeSet<_>>();
    let mut selected = Vec::with_capacity(count as usize);
    let mut used_domains = map
        .failure_domain_levels
        .iter()
        .map(|level| (level.clone(), BTreeSet::<String>::new()))
        .collect::<BTreeMap<_, _>>();
    for node_id in excluded.iter().copied() {
        if let Some(node) = map.nodes.iter().find(|node| &node.node_id == node_id) {
            record_domains(map, node, &mut used_domains);
        }
    }
    while selected.len() < count as usize {
        let candidate = map
            .nodes
            .iter()
            .filter(|node| {
                node.state == PlacementMapNodeState::In
                    && !excluded.contains(&node.node_id)
                    && !selected.contains(&node.node_id)
            })
            .min_by(|left, right| compare_candidate(map, reference, left, right, &used_domains))
            .ok_or(AuthoritativePlacementError::InsufficientEligibleNodes)?;
        selected.push(candidate.node_id.clone());
        record_domains(map, candidate, &mut used_domains);
    }
    Ok(selected)
}

fn compare_candidate(
    map: &PlacementMap,
    reference: &PlacementReference,
    left: &PlacementMapNode,
    right: &PlacementMapNode,
    used_domains: &BTreeMap<String, BTreeSet<String>>,
) -> std::cmp::Ordering {
    for level in &map.failure_domain_levels {
        let used = &used_domains[level];
        let left_new = !used.contains(&domain_value(left, level));
        let right_new = !used.contains(&domain_value(right, level));
        match right_new.cmp(&left_new) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    weighted_cost(reference, left)
        .cmp(&weighted_cost(reference, right))
        .then_with(|| left.node_id.cmp(&right.node_id))
}

fn compare_repair_candidate(
    map: &PlacementMap,
    reference: &PlacementReference,
    left: &PlacementMapNode,
    right: &PlacementMapNode,
    used_domains: &BTreeMap<String, BTreeSet<String>>,
) -> std::cmp::Ordering {
    for level in &map.failure_domain_levels {
        let used = &used_domains[level];
        let left_new = !used.contains(&domain_value(left, level));
        let right_new = !used.contains(&domain_value(right, level));
        match right_new.cmp(&left_new) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    repair_weighted_cost(reference, left)
        .cmp(&repair_weighted_cost(reference, right))
        .then_with(|| left.node_id.cmp(&right.node_id))
}

fn record_domains(
    map: &PlacementMap,
    node: &PlacementMapNode,
    used_domains: &mut BTreeMap<String, BTreeSet<String>>,
) {
    for level in &map.failure_domain_levels {
        used_domains
            .get_mut(level)
            .expect("validated placement level exists")
            .insert(domain_value(node, level));
    }
}

fn domain_value(node: &PlacementMapNode, level: &str) -> String {
    node.failure_domains
        .get(level)
        .cloned()
        .unwrap_or_else(|| format!("node:{}", node.node_id))
}

fn weighted_cost(reference: &PlacementReference, node: &PlacementMapNode) -> u128 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pepper-authoritative-placement-v1");
    hasher.update(&reference.epoch.to_be_bytes());
    hasher.update(&[match reference.role {
        PlacementRole::Replicated => 0,
        PlacementRole::ErasureShard => 1,
    }]);
    hasher.update(reference.seed.to_string().as_bytes());
    hasher.update(&reference.index.to_be_bytes());
    hasher.update(node.node_id.as_bytes());
    let digest = hasher.finalize();
    let random = u128::from_be_bytes(
        digest.as_bytes()[..16]
            .try_into()
            .expect("BLAKE3 digest contains sixteen bytes"),
    );
    (u128::MAX - random) / u128::from(node.weight)
}

fn repair_weighted_cost(reference: &PlacementReference, node: &PlacementMapNode) -> u128 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pepper-authoritative-repair-owner-v1");
    hasher.update(&reference.epoch.to_be_bytes());
    hasher.update(&[match reference.role {
        PlacementRole::Replicated => 0,
        PlacementRole::ErasureShard => 1,
    }]);
    hasher.update(reference.seed.to_string().as_bytes());
    // All shard references with the same stripe seed deliberately share one
    // coordinator order. Replicated references have only index zero.
    hasher.update(&0u16.to_be_bytes());
    hasher.update(node.node_id.as_bytes());
    let digest = hasher.finalize();
    let random = u128::from_be_bytes(
        digest.as_bytes()[..16]
            .try_into()
            .expect("BLAKE3 digest contains sixteen bytes"),
    );
    (u128::MAX - random) / u128::from(node.weight)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementNode {
    pub node_id: String,
    pub addresses: Vec<String>,
    pub is_local: bool,
    pub failure_domain: Option<String>,
    pub placement_labels: BTreeMap<String, String>,
    pub storage_capacity_bytes: Option<u64>,
    pub storage_available_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusPlacementNode {
    pub node_id: String,
    pub addresses: Vec<String>,
    pub reachable: bool,
    pub failure_domain: Option<String>,
    pub consensus_enabled: bool,
    pub namespace_group_capacity: u64,
    pub namespace_group_count: u64,
    pub max_consensus_log_bytes: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsensusPlacementError {
    #[error("the required number of capable namespace replicas is unavailable")]
    InsufficientCapableNodes,
    #[error("three distinct failure domains are unavailable")]
    InsufficientFailureDomains,
}

pub fn select_namespace_replicas(
    namespace_id: &Cid,
    nodes: &[ConsensusPlacementNode],
    required_log_bytes: u64,
) -> Result<[ConsensusPlacementNode; 3], ConsensusPlacementError> {
    select_namespace_replicas_with_count(namespace_id, nodes, required_log_bytes, 3)?
        .try_into()
        .map_err(|_| ConsensusPlacementError::InsufficientCapableNodes)
}

pub fn select_namespace_replicas_with_count(
    namespace_id: &Cid,
    nodes: &[ConsensusPlacementNode],
    required_log_bytes: u64,
    replica_count: usize,
) -> Result<Vec<ConsensusPlacementNode>, ConsensusPlacementError> {
    if !matches!(replica_count, 1 | 3) {
        return Err(ConsensusPlacementError::InsufficientCapableNodes);
    }
    let mut candidates = nodes
        .iter()
        .filter(|node| {
            node.consensus_enabled
                && node.reachable
                && (!node.addresses.is_empty())
                && node.namespace_group_count < node.namespace_group_capacity
                && node.max_consensus_log_bytes >= required_log_bytes
        })
        .cloned()
        .map(|node| (placement_score(namespace_id, &node.node_id), node))
        .collect::<Vec<_>>();
    candidates.sort_by(|(left_score, left_node), (right_score, right_node)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_node.node_id.cmp(&right_node.node_id))
    });
    if candidates.len() < replica_count {
        return Err(ConsensusPlacementError::InsufficientCapableNodes);
    }
    let mut domains = BTreeSet::new();
    let mut selected = Vec::new();
    for (_, node) in &candidates {
        let domain = node
            .failure_domain
            .clone()
            .unwrap_or_else(|| format!("node:{}", node.node_id));
        if domains.insert(domain) {
            selected.push(node.clone());
        }
        if selected.len() == replica_count {
            break;
        }
    }
    if selected.len() < replica_count {
        for (_, node) in candidates {
            if !selected
                .iter()
                .any(|selected| selected.node_id == node.node_id)
            {
                selected.push(node);
            }
            if selected.len() == replica_count {
                break;
            }
        }
    }
    Ok(selected)
}

pub fn select_namespace_replacement(
    namespace_id: &Cid,
    nodes: &[ConsensusPlacementNode],
    retained_node_ids: &[String],
    required_log_bytes: u64,
) -> Result<ConsensusPlacementNode, ConsensusPlacementError> {
    let retained = retained_node_ids.iter().collect::<BTreeSet<_>>();
    let retained_domains = nodes
        .iter()
        .filter(|node| retained.contains(&node.node_id))
        .map(|node| {
            node.failure_domain
                .clone()
                .unwrap_or_else(|| format!("node:{}", node.node_id))
        })
        .collect::<BTreeSet<_>>();
    let mut candidates = nodes
        .iter()
        .filter(|node| {
            !retained.contains(&node.node_id)
                && node.consensus_enabled
                && node.reachable
                && !node.addresses.is_empty()
                && node.namespace_group_count < node.namespace_group_capacity
                && node.max_consensus_log_bytes >= required_log_bytes
        })
        .cloned()
        .map(|node| {
            let domain = node
                .failure_domain
                .clone()
                .unwrap_or_else(|| format!("node:{}", node.node_id));
            let diverse = !retained_domains.contains(&domain);
            (diverse, placement_score(namespace_id, &node.node_id), node)
        })
        .collect::<Vec<_>>();
    candidates.sort_by(
        |(left_diverse, left_score, left_node), (right_diverse, right_score, right_node)| {
            right_diverse
                .cmp(left_diverse)
                .then_with(|| right_score.cmp(left_score))
                .then_with(|| left_node.node_id.cmp(&right_node.node_id))
        },
    );
    candidates
        .into_iter()
        .next()
        .map(|(_, _, node)| node)
        .ok_or(ConsensusPlacementError::InsufficientCapableNodes)
}

pub fn select_replicas(
    cid: &Cid,
    nodes: &[PlacementNode],
    replication_factor: usize,
) -> Vec<PlacementNode> {
    let mut scored = nodes
        .iter()
        .cloned()
        .map(|node| {
            let score = placement_score(cid, &node.node_id);
            (score, node)
        })
        .collect::<Vec<_>>();
    scored.sort_by(|(left_score, left_node), (right_score, right_node)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_node.node_id.cmp(&right_node.node_id))
    });
    scored
        .into_iter()
        .take(replication_factor)
        .map(|(_, node)| node)
        .collect()
}

fn placement_score(cid: &Cid, node_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pepper-placement-v1");
    hasher.update(cid.to_string().as_bytes());
    hasher.update(node_id.as_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_types::{CODEC_RAW, PlacementReference};

    fn authoritative_map() -> PlacementMap {
        PlacementMap {
            epoch: 7,
            failure_domain_levels: vec!["zone".to_string(), "rack".to_string()],
            nodes: (0..6)
                .map(|index| PlacementMapNode {
                    node_id: format!("node-{index}"),
                    weight: if index == 5 { 2 } else { 1 },
                    state: PlacementMapNodeState::In,
                    failure_domains: BTreeMap::from([
                        ("zone".to_string(), format!("zone-{}", index / 3)),
                        ("rack".to_string(), format!("rack-{index}")),
                    ]),
                })
                .collect(),
        }
    }

    #[test]
    fn authoritative_selection_is_order_independent_and_epoch_bound() {
        let map = authoritative_map();
        let reference =
            PlacementReference::replicated(map.epoch, Cid::new(CODEC_RAW, b"authoritative"), 3);
        let selected = select_authoritative(&map, &reference).unwrap();
        assert_eq!(
            selected.node_ids,
            ["node-2", "node-3", "node-5"].map(str::to_string),
            "canonical placement vector changed"
        );
        let mut reversed = map.clone();
        reversed.nodes.reverse();
        assert_eq!(
            selected,
            select_authoritative(&reversed, &reference).unwrap()
        );

        let wrong_epoch = PlacementReference::replicated(
            map.epoch + 1,
            reference.seed.clone(),
            reference.replicas,
        );
        assert_eq!(
            select_authoritative(&map, &wrong_epoch),
            Err(AuthoritativePlacementError::EpochMismatch {
                reference: map.epoch + 1,
                map: map.epoch,
            })
        );
    }

    #[test]
    fn authoritative_selection_prefers_failure_domain_diversity() {
        let map = authoritative_map();
        let reference =
            PlacementReference::replicated(map.epoch, Cid::new(CODEC_RAW, b"diversity"), 3);
        let selected = select_authoritative(&map, &reference).unwrap();
        let zones = selected
            .node_ids
            .iter()
            .map(|node_id| {
                map.nodes
                    .iter()
                    .find(|node| &node.node_id == node_id)
                    .unwrap()
                    .failure_domains["zone"]
                    .clone()
            })
            .collect::<BTreeSet<_>>();
        let racks = selected
            .node_ids
            .iter()
            .map(|node_id| {
                map.nodes
                    .iter()
                    .find(|node| &node.node_id == node_id)
                    .unwrap()
                    .failure_domains["rack"]
                    .clone()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(zones.len(), 2);
        assert_eq!(racks.len(), 3);
    }

    #[test]
    fn erasure_shards_compute_distinct_owners_independently() {
        let map = authoritative_map();
        let stripe = Cid::new(CODEC_RAW, b"stripe");
        let owners = (0..6)
            .map(|index| {
                select_authoritative(
                    &map,
                    &PlacementReference::erasure_shard(map.epoch, stripe.clone(), index),
                )
                .unwrap()
                .node_ids[0]
                    .clone()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(owners.len(), 6);
    }

    #[test]
    fn repair_owner_order_is_deterministic_diverse_and_stripe_scoped() {
        let map = authoritative_map();
        let stripe = Cid::new(CODEC_RAW, b"repair-stripe");
        let first = PlacementReference::erasure_shard(map.epoch, stripe.clone(), 0);
        let last = PlacementReference::erasure_shard(map.epoch, stripe, 8);
        let selected = select_repair_owners(&map, &first, DEFAULT_REPAIR_OWNER_COUNT).unwrap();
        assert_eq!(selected.len(), DEFAULT_REPAIR_OWNER_COUNT);
        assert_eq!(
            selected,
            select_repair_owners(&map, &last, DEFAULT_REPAIR_OWNER_COUNT).unwrap(),
            "every shard in one stripe must have one coordinator order"
        );
        let zones = selected
            .iter()
            .map(|node_id| {
                map.nodes
                    .iter()
                    .find(|node| &node.node_id == node_id)
                    .unwrap()
                    .failure_domains["zone"]
                    .clone()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(zones.len(), 2);

        let mut reversed = map.clone();
        reversed.nodes.reverse();
        assert_eq!(
            selected,
            select_repair_owners(&reversed, &first, DEFAULT_REPAIR_OWNER_COUNT).unwrap()
        );
    }

    #[test]
    fn repair_owner_selection_uses_available_standbys_and_rejects_zero_limit() {
        let mut map = authoritative_map();
        for node in map.nodes.iter_mut().skip(2) {
            node.state = PlacementMapNodeState::Out;
        }
        let reference =
            PlacementReference::replicated(map.epoch, Cid::new(CODEC_RAW, b"repair"), 1);
        assert_eq!(select_repair_owners(&map, &reference, 3).unwrap().len(), 2);
        assert_eq!(
            select_repair_owners(&map, &reference, 0),
            Err(AuthoritativePlacementError::InvalidRepairOwnerCount)
        );
    }

    #[test]
    fn repair_replacement_excludes_canonical_nodes_and_is_order_independent() {
        let map = authoritative_map();
        let reference =
            PlacementReference::replicated(map.epoch, Cid::new(CODEC_RAW, b"replacement"), 3);
        let canonical = select_authoritative(&map, &reference).unwrap().node_ids;
        let replacement = select_repair_replacement(&map, &reference, &canonical).unwrap();
        assert!(!canonical.contains(&replacement));
        let mut reversed = map.clone();
        reversed.nodes.reverse();
        assert_eq!(
            replacement,
            select_repair_replacement(&reversed, &reference, &canonical).unwrap()
        );
    }

    #[test]
    fn authoritative_selection_excludes_out_nodes_and_fails_closed() {
        let mut map = authoritative_map();
        map.nodes[0].state = PlacementMapNodeState::Out;
        let reference =
            PlacementReference::replicated(map.epoch, Cid::new(CODEC_RAW, b"out-node"), 6);
        assert_eq!(
            select_authoritative(&map, &reference),
            Err(AuthoritativePlacementError::InsufficientEligibleNodes)
        );
    }

    #[test]
    fn rendezvous_selection_is_deterministic_independent_of_input_order() {
        let cid = Cid::new(CODEC_RAW, b"hello");
        let nodes = vec![
            PlacementNode {
                node_id: "a".to_string(),
                addresses: vec![],
                is_local: false,
                failure_domain: None,
                placement_labels: BTreeMap::new(),
                storage_capacity_bytes: None,
                storage_available_bytes: None,
            },
            PlacementNode {
                node_id: "b".to_string(),
                addresses: vec![],
                is_local: false,
                failure_domain: None,
                placement_labels: BTreeMap::new(),
                storage_capacity_bytes: None,
                storage_available_bytes: None,
            },
            PlacementNode {
                node_id: "c".to_string(),
                addresses: vec![],
                is_local: false,
                failure_domain: None,
                placement_labels: BTreeMap::new(),
                storage_capacity_bytes: None,
                storage_available_bytes: None,
            },
            PlacementNode {
                node_id: "d".to_string(),
                addresses: vec![],
                is_local: false,
                failure_domain: None,
                placement_labels: BTreeMap::new(),
                storage_capacity_bytes: None,
                storage_available_bytes: None,
            },
        ];
        let mut reversed = nodes.clone();
        reversed.reverse();
        assert_eq!(
            select_replicas(&cid, &nodes, 3),
            select_replicas(&cid, &reversed, 3)
        );
    }

    #[test]
    fn namespace_selection_requires_capacity_and_maximizes_domain_diversity() {
        let namespace = Cid::new(CODEC_RAW, b"namespace");
        let nodes = (0..5)
            .map(|index| ConsensusPlacementNode {
                node_id: format!("node-{index}"),
                addresses: vec![format!("127.0.0.1:{}", 9000 + index)],
                reachable: index != 4,
                failure_domain: Some(format!("rack-{index}")),
                consensus_enabled: index != 3,
                namespace_group_capacity: 10,
                namespace_group_count: 0,
                max_consensus_log_bytes: 1024,
            })
            .collect::<Vec<_>>();
        let selected = select_namespace_replicas(&namespace, &nodes, 512).unwrap();
        assert_eq!(selected.len(), 3);
        assert_eq!(
            select_namespace_replicas_with_count(&namespace, &nodes, 512, 1)
                .unwrap()
                .len(),
            1
        );
        assert!(selected.iter().all(|node| node.node_id != "node-3"));
        assert!(selected.iter().all(|node| node.node_id != "node-4"));
        let replacement = select_namespace_replacement(
            &namespace,
            &nodes,
            &["node-0".to_string(), "node-1".to_string()],
            512,
        )
        .unwrap();
        assert_eq!(replacement.node_id, "node-2");
        assert_eq!(
            select_namespace_replicas(&namespace, &nodes, 2048),
            Err(ConsensusPlacementError::InsufficientCapableNodes)
        );

        let one_domain = nodes
            .into_iter()
            .map(|mut node| {
                node.failure_domain = Some("rack-a".to_string());
                node
            })
            .collect::<Vec<_>>();
        assert_eq!(
            select_namespace_replicas(&namespace, &one_domain, 512)
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn selection_is_capped_by_replication_factor() {
        let cid = Cid::new(CODEC_RAW, b"hello");
        let nodes = vec![
            PlacementNode {
                node_id: "a".to_string(),
                addresses: vec![],
                is_local: false,
                failure_domain: None,
                placement_labels: BTreeMap::new(),
                storage_capacity_bytes: None,
                storage_available_bytes: None,
            },
            PlacementNode {
                node_id: "b".to_string(),
                addresses: vec![],
                is_local: false,
                failure_domain: None,
                placement_labels: BTreeMap::new(),
                storage_capacity_bytes: None,
                storage_available_bytes: None,
            },
        ];
        assert_eq!(select_replicas(&cid, &nodes, 3).len(), 2);
        assert_eq!(select_replicas(&cid, &nodes, 1).len(), 1);
    }
}
