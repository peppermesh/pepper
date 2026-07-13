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
        BTreeSet::from(["smoke", "functional", "chaos", "soak", "wan", "host-gated"])
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
        assert!(matches!(backend, "process" | "docker" | "wan" | "kvm"));
        assert!(requirement["minimum_passes"].as_u64().unwrap() >= 1);
        requirements.insert((scenario, backend));
    }
    assert!(requirements.contains(&("SOAK-001", "docker")));
    assert_eq!(
        policy["tiers"][4]["requirements"][0]["required_capability"],
        "tailscale"
    );
    assert_eq!(
        policy["tiers"][4]["requirements"][1]["required_capability"],
        "direct"
    );
    assert!(requirements.contains(&("WAN-001", "wan")));
    assert!(requirements.contains(&("KVM-001", "kvm")));
}

#[test]
fn phase_nine_workflows_archive_reports_and_are_host_isolated() {
    let soak = include_str!("../../.github/workflows/system-soak.yml");
    let wan = include_str!("../../.github/workflows/system-wan.yml");
    let kvm = include_str!("../../.github/workflows/firecracker-host-gated.yml");
    let qualification = include_str!("../../.github/workflows/release-qualification.yml");
    assert!(
        soak.contains("SOAK-001")
            && soak.contains("pepper-soak")
            && soak.contains("retention-days: 60")
    );
    assert!(
        wan.contains("WAN-001")
            && wan.contains("tailscale")
            && wan.contains("direct")
            && wan.contains("retention-days: 60")
    );
    assert!(
        kvm.contains("KVM-001") && kvm.contains("/dev/kvm") && kvm.contains("retention-days: 60")
    );
    assert!(
        qualification.contains("qualification-policy.json")
            && qualification.contains("retention-days: 90")
    );
}
