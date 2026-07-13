// SPDX-License-Identifier: Apache-2.0

use pepper_system_tests::scenario_names;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
struct GateFile {
    version: u8,
    required_successful_runs: usize,
    required_distinct_days: usize,
    tests: Vec<GateEntry>,
}

#[derive(Deserialize)]
struct GateEntry {
    legacy_test: String,
    replacement_scenarios: Vec<String>,
    replacement_complete: bool,
    decision: String,
    evidence_source: String,
    owner: String,
}

#[test]
fn removal_gate_is_conservative_and_matches_registry() {
    let gate: GateFile = serde_json::from_str(include_str!("../ci/removal-gates.json")).unwrap();
    assert_eq!(gate.version, 1);
    assert!(gate.required_successful_runs >= 20);
    assert!(gate.required_distinct_days >= 7);
    let registry = scenario_names()
        .iter()
        .map(|(id, _)| *id)
        .collect::<BTreeSet<_>>();
    let mut legacy = BTreeSet::new();
    for entry in gate.tests {
        assert!(
            legacy.insert(entry.legacy_test.clone()),
            "duplicate legacy test {}",
            entry.legacy_test
        );
        assert!(!entry.replacement_scenarios.is_empty());
        assert!(!entry.owner.is_empty() && !entry.evidence_source.is_empty());
        assert!(matches!(
            entry.decision.as_str(),
            "remove-after-historical-gate"
                | "retain-until-soak-qualification"
                | "retain-focused-protocol-smoke"
        ));
        let all_implemented = entry
            .replacement_scenarios
            .iter()
            .all(|scenario| registry.contains(scenario.as_str()));
        assert_eq!(
            entry.replacement_complete, all_implemented,
            "replacement completeness is stale for {}",
            entry.legacy_test
        );
    }
}

#[test]
fn ci_tiers_only_reference_registered_scenarios_and_bound_parallelism() {
    let registry = scenario_names()
        .iter()
        .map(|(id, _)| *id)
        .collect::<BTreeSet<_>>();
    let workflows = [
        include_str!("../../.github/workflows/system-smoke.yml"),
        include_str!("../../.github/workflows/system-nightly.yml"),
        include_str!("../../.github/workflows/system-chaos.yml"),
    ];
    let mut declared = BTreeSet::new();
    for workflow in workflows {
        assert!(workflow.contains("max-parallel:"));
        assert!(workflow.contains("retention-days:"));
        for line in workflow.lines().map(str::trim) {
            if let Some(rest) = line.strip_prefix("- { scenario: ") {
                declared.insert(rest.split(',').next().unwrap().trim());
            } else if let Some(values) = line
                .strip_prefix("scenario: [")
                .and_then(|rest| rest.strip_suffix(']'))
            {
                declared.extend(values.split(',').map(str::trim));
            }
        }
    }
    assert!(!declared.is_empty());
    for scenario in declared {
        assert!(
            registry.contains(scenario),
            "CI references unknown scenario {scenario}"
        );
    }
}
