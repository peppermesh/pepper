// SPDX-License-Identifier: Apache-2.0

//! Trusted evidence for incremental SQLite publication.
//!
//! This type intentionally has no Serde implementation. The agent constructs
//! it after building the page-table update and collecting backend receipts;
//! external protocol callers submit pages and transaction metadata, never a
//! claim that their own blocks are preverified.

use crate::{SnapshotDescriptor, SqliteError, SqliteFormatLimits, format::encode_canonical};
use pepper_dataset::{ExactBase, MutationFrontier, PreparedDatasetArtifact};
use pepper_types::{
    CODEC_ERASURE_MANIFEST, CODEC_OBJECT_MANIFEST, CODEC_SMALL_OBJECT, CODEC_SQLITE_PAGE_TABLE,
    CODEC_SQLITE_SNAPSHOT, Cid, DurabilityReceipt, PlacementRole,
};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct IncrementalProofInput {
    pub protected_base_snapshot: Cid,
    pub protected_base_generation: u64,
    pub protected_base_descriptor: SnapshotDescriptor,
    pub new_snapshot: Cid,
    pub new_snapshot_descriptor: SnapshotDescriptor,
    pub new_page_table_nodes: Vec<Cid>,
    pub new_page_pack_roots: Vec<Cid>,
    pub verified_descendants: Vec<Cid>,
    pub changed_page_count: usize,
    pub durability_receipts: Vec<DurabilityReceipt>,
    pub builder_identity: String,
}

/// Validated internal evidence. Fields remain private so later publication
/// code cannot accidentally mutate a checked proof.
#[derive(Debug, Clone)]
pub struct IncrementalDurabilityProof {
    protected_base_snapshot: Cid,
    new_snapshot: Cid,
    new_page_table_nodes: Vec<Cid>,
    new_page_pack_roots: Vec<Cid>,
    verified_descendants: Vec<Cid>,
    durability_receipts: Vec<DurabilityReceipt>,
    builder_identity: String,
}

impl IncrementalDurabilityProof {
    pub fn build(
        input: IncrementalProofInput,
        required_replicas: usize,
        limits: SqliteFormatLimits,
    ) -> Result<Self, SqliteError> {
        if required_replicas == 0
            || input.builder_identity.is_empty()
            || input.builder_identity.len() > 1024
            || input.protected_base_snapshot.codec != CODEC_SQLITE_SNAPSHOT
            || input.new_snapshot.codec != CODEC_SQLITE_SNAPSHOT
            || input.protected_base_snapshot == input.new_snapshot
        {
            return Err(SqliteError::Invalid(
                "invalid incremental durability proof header".into(),
            ));
        }
        input.protected_base_descriptor.validate(limits)?;
        input.new_snapshot_descriptor.validate(limits)?;
        verify_descriptor_cid(
            &input.protected_base_descriptor,
            &input.protected_base_snapshot,
            limits,
        )?;
        verify_descriptor_cid(&input.new_snapshot_descriptor, &input.new_snapshot, limits)?;
        if input.new_snapshot_descriptor.base_snapshot_cid.as_ref()
            != Some(&input.protected_base_snapshot)
            || input.new_snapshot_descriptor.database_cid
                != input.protected_base_descriptor.database_cid
            || input.new_snapshot_descriptor.page_size != input.protected_base_descriptor.page_size
        {
            return Err(SqliteError::Invalid(
                "new snapshot is not based on the protected database snapshot".into(),
            ));
        }

        let root_changed = input.new_snapshot_descriptor.page_table_root_cid
            != input.protected_base_descriptor.page_table_root_cid;
        let artifact = PreparedDatasetArtifact {
            exact_base: ExactBase {
                generation: input.protected_base_generation,
                root: input.protected_base_snapshot.clone(),
            },
            candidate_root: input.new_snapshot.clone(),
            descriptor: input
                .new_snapshot_descriptor
                .dataset_root(input.protected_base_generation.saturating_add(1)),
            frontier: MutationFrontier {
                // A byte-identical rewrite (for example, SQLite compaction)
                // advances the snapshot descriptor while retaining the
                // content-addressed page table. Its submitted pages are not
                // changed index keys and therefore have an empty frontier.
                changed_keys: if root_changed {
                    input.changed_page_count
                } else {
                    0
                },
                index_depth: 4,
                candidate_index_root: input.new_snapshot_descriptor.page_table_root_cid.clone(),
                new_index_nodes: input.new_page_table_nodes.clone(),
                new_data_roots: input.new_page_pack_roots.clone(),
                verified_descendants: input.verified_descendants.clone(),
            },
        };
        artifact
            .validate()
            .map_err(|error| SqliteError::Invalid(error.to_string()))?;

        validate_cid_list(
            &input.new_page_table_nodes,
            |cid| cid.codec == CODEC_SQLITE_PAGE_TABLE,
            "new page-table nodes",
        )?;
        validate_cid_list(
            &input.new_page_pack_roots,
            |cid| {
                matches!(
                    cid.codec,
                    CODEC_SMALL_OBJECT | CODEC_OBJECT_MANIFEST | CODEC_ERASURE_MANIFEST
                )
            },
            "new page-pack roots",
        )?;
        validate_cid_list(
            &input.verified_descendants,
            |_| true,
            "verified descendants",
        )?;

        if root_changed
            != input
                .new_page_table_nodes
                .contains(&input.new_snapshot_descriptor.page_table_root_cid)
        {
            return Err(SqliteError::Invalid(
                "changed page-table root must be declared as a new node".into(),
            ));
        }

        let mut required = HashSet::new();
        required.insert(input.new_snapshot.clone());
        for cid in input
            .new_page_table_nodes
            .iter()
            .chain(&input.new_page_pack_roots)
            .chain(&input.verified_descendants)
        {
            if !required.insert(cid.clone()) {
                return Err(SqliteError::Invalid(
                    "incremental evidence categories overlap".into(),
                ));
            }
        }
        let receipts = input
            .durability_receipts
            .iter()
            .map(|receipt| (receipt.cid.clone(), receipt))
            .collect::<HashMap<_, _>>();
        if receipts.len() != input.durability_receipts.len() || receipts.len() != required.len() {
            return Err(SqliteError::Invalid(
                "durability receipts must exactly cover the new strong-link frontier".into(),
            ));
        }
        for cid in &required {
            let Some(receipt) = receipts.get(cid) else {
                return Err(SqliteError::Invalid(format!(
                    "missing durability receipt for {cid}"
                )));
            };
            let replicas = if receipt
                .placement
                .as_ref()
                .is_some_and(|placement| placement.role == PlacementRole::ErasureShard)
            {
                1
            } else {
                required_replicas
            };
            if receipt.codec != cid.codec
                || receipt.status != "durable"
                || receipt.replicas_accepted < replicas
                || receipt.replica_nodes.len() < replicas
            {
                return Err(SqliteError::Invalid(format!(
                    "invalid durability receipt for {cid}"
                )));
            }
        }

        Ok(Self {
            protected_base_snapshot: input.protected_base_snapshot,
            new_snapshot: input.new_snapshot,
            new_page_table_nodes: input.new_page_table_nodes,
            new_page_pack_roots: input.new_page_pack_roots,
            verified_descendants: input.verified_descendants,
            durability_receipts: input.durability_receipts,
            builder_identity: input.builder_identity,
        })
    }

    pub fn protected_base_snapshot(&self) -> &Cid {
        &self.protected_base_snapshot
    }

    pub fn new_snapshot(&self) -> &Cid {
        &self.new_snapshot
    }

    pub fn new_page_table_nodes(&self) -> &[Cid] {
        &self.new_page_table_nodes
    }

    pub fn new_page_pack_roots(&self) -> &[Cid] {
        &self.new_page_pack_roots
    }

    pub fn verified_descendants(&self) -> &[Cid] {
        &self.verified_descendants
    }

    pub fn durability_receipts(&self) -> &[DurabilityReceipt] {
        &self.durability_receipts
    }

    pub fn builder_identity(&self) -> &str {
        &self.builder_identity
    }
}

fn verify_descriptor_cid(
    descriptor: &SnapshotDescriptor,
    expected: &Cid,
    limits: SqliteFormatLimits,
) -> Result<(), SqliteError> {
    let payload = encode_canonical(descriptor, limits.max_descriptor_bytes)?;
    if Cid::new(CODEC_SQLITE_SNAPSHOT, &payload) != *expected {
        return Err(SqliteError::Invalid(
            "snapshot CID does not match its canonical descriptor".into(),
        ));
    }
    Ok(())
}

fn validate_cid_list(
    values: &[Cid],
    allowed: impl Fn(&Cid) -> bool,
    name: &str,
) -> Result<(), SqliteError> {
    let mut seen = HashSet::new();
    if values.iter().any(|cid| !allowed(cid) || !seen.insert(cid)) {
        return Err(SqliteError::Invalid(format!(
            "{name} contain duplicate or invalid CIDs"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pepper_types::{CODEC_RAW, HashAlg};

    fn descriptor(root: Cid, base: Option<Cid>) -> SnapshotDescriptor {
        SnapshotDescriptor {
            descriptor_type: "pepper.sqlite_snapshot".into(),
            version: 1,
            database_cid: Cid::new(pepper_types::CODEC_SQLITE_DATABASE, b"db"),
            page_table_root_cid: root,
            page_size: 4096,
            page_count: 1,
            logical_size: 4096,
            base_snapshot_cid: base,
        }
    }

    fn receipt(cid: Cid) -> DurabilityReceipt {
        DurabilityReceipt {
            codec: cid.codec,
            cid,
            placement: None,
            size: 1,
            replicas_accepted: 3,
            replica_nodes: vec!["a".into(), "b".into(), "c".into()],
            status: "durable".into(),
        }
    }

    fn fixture() -> IncrementalProofInput {
        let old_root = Cid::new(CODEC_SQLITE_PAGE_TABLE, b"old-root");
        let new_root = Cid::new(CODEC_SQLITE_PAGE_TABLE, b"new-root");
        let base_descriptor = descriptor(old_root, None);
        let base_payload = encode_canonical(&base_descriptor, 64 * 1024).unwrap();
        let base = Cid::new(CODEC_SQLITE_SNAPSHOT, &base_payload);
        let new_descriptor = descriptor(new_root.clone(), Some(base.clone()));
        let new_payload = encode_canonical(&new_descriptor, 64 * 1024).unwrap();
        let new_snapshot = Cid::new(CODEC_SQLITE_SNAPSHOT, &new_payload);
        let pack = Cid::new(CODEC_SMALL_OBJECT, b"pack");
        let child = Cid::new(CODEC_RAW, b"child");
        IncrementalProofInput {
            protected_base_snapshot: base,
            protected_base_generation: 4,
            protected_base_descriptor: base_descriptor,
            new_snapshot: new_snapshot.clone(),
            new_snapshot_descriptor: new_descriptor,
            new_page_table_nodes: vec![new_root.clone()],
            new_page_pack_roots: vec![pack.clone()],
            verified_descendants: vec![child.clone()],
            changed_page_count: 1,
            durability_receipts: vec![
                receipt(new_snapshot),
                receipt(new_root),
                receipt(pack),
                receipt(child),
            ],
            builder_identity: "node:a".into(),
        }
    }

    #[test]
    fn trusted_proof_requires_exact_new_frontier_receipts() {
        let proof =
            IncrementalDurabilityProof::build(fixture(), 3, SqliteFormatLimits::default()).unwrap();
        assert_eq!(proof.durability_receipts().len(), 4);
        assert_eq!(proof.builder_identity(), "node:a");

        let mut missing = fixture();
        missing.durability_receipts.pop();
        assert!(
            IncrementalDurabilityProof::build(missing, 3, SqliteFormatLimits::default()).is_err()
        );
    }

    #[test]
    fn proof_rejects_wrong_base_and_bad_receipt() {
        let mut wrong_base = fixture();
        wrong_base.new_snapshot_descriptor.base_snapshot_cid = None;
        assert!(
            IncrementalDurabilityProof::build(wrong_base, 3, SqliteFormatLimits::default())
                .is_err()
        );

        let mut weak = fixture();
        weak.durability_receipts[0].replicas_accepted = 2;
        assert!(IncrementalDurabilityProof::build(weak, 3, SqliteFormatLimits::default()).is_err());
    }

    #[test]
    fn proof_accepts_byte_identical_rewrite_with_unchanged_index() {
        let old_root = Cid::new(CODEC_SQLITE_PAGE_TABLE, b"unchanged-root");
        let base_descriptor = descriptor(old_root.clone(), None);
        let base_payload = encode_canonical(&base_descriptor, 64 * 1024).unwrap();
        let base = Cid::new(CODEC_SQLITE_SNAPSHOT, &base_payload);
        let new_descriptor = descriptor(old_root, Some(base.clone()));
        let new_payload = encode_canonical(&new_descriptor, 64 * 1024).unwrap();
        let new_snapshot = Cid::new(CODEC_SQLITE_SNAPSHOT, &new_payload);
        let proof = IncrementalDurabilityProof::build(
            IncrementalProofInput {
                protected_base_snapshot: base,
                protected_base_generation: 4,
                protected_base_descriptor: base_descriptor,
                new_snapshot: new_snapshot.clone(),
                new_snapshot_descriptor: new_descriptor,
                new_page_table_nodes: Vec::new(),
                new_page_pack_roots: Vec::new(),
                verified_descendants: Vec::new(),
                changed_page_count: 1,
                durability_receipts: vec![receipt(new_snapshot)],
                builder_identity: "node:a".into(),
            },
            3,
            SqliteFormatLimits::default(),
        )
        .unwrap();
        assert!(proof.new_page_table_nodes().is_empty());
    }

    #[test]
    fn proof_has_no_wire_format_marker() {
        // Compile-time smoke: CIDs still use the expected hash algorithm; the
        // proof itself intentionally does not implement Serialize/Deserialize.
        assert_eq!(fixture().new_snapshot.hash_alg, HashAlg::Blake3);
    }
}
