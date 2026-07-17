// SPDX-License-Identifier: Apache-2.0

use pepper_system_tests::scenario_names;
use std::collections::BTreeSet;

#[test]
fn qualification_policy_references_registered_scenarios_and_all_release_tiers() {
    let policy: serde_json::Value =
        serde_json::from_str(include_str!("../ci/qualification-policy.json")).unwrap();
    assert_eq!(policy["schema_version"], 1);
    assert_eq!(policy["release"], "0.2.0");
    let registry = scenario_names()
        .iter()
        .map(|(id, _)| *id)
        .collect::<BTreeSet<_>>();
    let tiers = policy["tiers"].as_array().unwrap();
    let tier_names = tiers
        .iter()
        .map(|tier| tier["name"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        tier_names,
        BTreeSet::from(["smoke", "functional", "chaos", "soak"])
    );
    let mut requirements = BTreeSet::new();
    for requirement in tiers
        .iter()
        .flat_map(|tier| tier["requirements"].as_array().unwrap())
    {
        let scenario = requirement["scenario"].as_str().unwrap();
        let backend = requirement["backend"].as_str().unwrap();
        assert!(
            registry.contains(scenario),
            "unknown qualification scenario {scenario}"
        );
        assert!(matches!(backend, "process" | "docker"));
        assert!(requirement["minimum_passes"].as_u64().unwrap() >= 1);
        requirements.insert((scenario, backend));
    }
    assert!(requirements.contains(&("SOAK-001", "docker")));
    assert!(!requirements.contains(&("WAN-001", "wan")));
    assert!(!requirements.contains(&("KVM-001", "kvm")));
}

#[test]
fn release_gate_is_hosted_and_specialized_scenarios_are_optional() {
    let soak = include_str!("../../.github/workflows/system-soak.yml");
    let wan = include_str!("../../.github/workflows/system-wan.yml");
    let kvm = include_str!("../../.github/workflows/firecracker-host-gated.yml");
    let qualification = include_str!("../../.github/workflows/release-qualification.yml");
    assert!(
        soak.contains("SOAK-001")
            && soak.contains("runs-on: ubuntu-latest")
            && !soak.contains("self-hosted")
            && soak.contains("retention-days: 60")
    );
    assert!(
        wan.contains("WAN-001")
            && wan.contains("name: system-wan-optional")
            && !wan.contains("schedule:")
            && wan.contains("tailscale")
            && wan.contains("direct")
            && wan.contains("retention-days: 60")
    );
    assert!(
        kvm.contains("KVM-001")
            && kvm.contains("name: firecracker-host-gated-optional")
            && kvm.contains("/dev/kvm")
            && kvm.contains("retention-days: 60")
    );
    assert!(
        qualification.contains("qualification-policy.json")
            && qualification.contains("retention-days: 90")
            && !qualification.contains("wan_run_id")
            && !qualification.contains("kvm_run_id")
    );
}
