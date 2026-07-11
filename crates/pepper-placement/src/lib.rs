// SPDX-License-Identifier: Apache-2.0

use pepper_types::Cid;
use std::collections::BTreeMap;

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
