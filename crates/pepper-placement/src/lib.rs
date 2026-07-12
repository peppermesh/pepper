// SPDX-License-Identifier: Apache-2.0

use pepper_types::Cid;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

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
    #[error("exactly three capable namespace replicas are unavailable")]
    InsufficientCapableNodes,
    #[error("three distinct failure domains are unavailable")]
    InsufficientFailureDomains,
}

pub fn select_namespace_replicas(
    namespace_id: &Cid,
    nodes: &[ConsensusPlacementNode],
    required_log_bytes: u64,
) -> Result<[ConsensusPlacementNode; 3], ConsensusPlacementError> {
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
    if candidates.len() < 3 {
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
        if selected.len() == 3 {
            break;
        }
    }
    if selected.len() < 3 {
        for (_, node) in candidates {
            if !selected
                .iter()
                .any(|selected| selected.node_id == node.node_id)
            {
                selected.push(node);
            }
            if selected.len() == 3 {
                break;
            }
        }
    }
    selected
        .try_into()
        .map_err(|_| ConsensusPlacementError::InsufficientCapableNodes)
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
    use pepper_types::CODEC_RAW;

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
