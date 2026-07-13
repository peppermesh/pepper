// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use std::{fs, path::PathBuf};

#[test]
fn version_one_schemas_accept_valid_and_reject_invalid_fixtures() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for name in [
        "run",
        "topology",
        "event",
        "observation",
        "artifact-manifest",
    ] {
        let schema: Value = serde_json::from_slice(
            &fs::read(root.join("schemas/v1").join(format!("{name}.schema.json"))).unwrap(),
        )
        .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let valid: Value = serde_json::from_slice(
            &fs::read(
                root.join("tests/fixtures")
                    .join(format!("{name}.valid.json")),
            )
            .unwrap(),
        )
        .unwrap();
        if let Err(error) = validator.validate(&valid) {
            panic!("{name} valid fixture was rejected: {error}");
        }
        let invalid: Value = serde_json::from_slice(
            &fs::read(
                root.join("tests/fixtures")
                    .join(format!("{name}.invalid.json")),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            validator.validate(&invalid).is_err(),
            "{name} invalid fixture was accepted"
        );
    }
}

#[test]
fn all_packaged_schemas_are_draft_2020_12() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schemas/v1");
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let schema: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        jsonschema::validator_for(&schema).unwrap();
    }
}
