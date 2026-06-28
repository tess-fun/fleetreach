//! The static-reachability model (spec §7): the legacy-bool mapping, the wire
//! shape of the verdict, and the additive discipline (absent unless it ran).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fleetreach_core::{ReachVerdict, Reachability};
use serde_json::json;

fn reachability(verdict: ReachVerdict) -> Reachability {
    Reachability {
        verdict,
        config: "nightly-2026-06-01;default-features".into(),
        engine: "static-mir-rta@0.1".into(),
        targets: vec![],
        witness: None,
    }
}

#[test]
fn maps_onto_legacy_reachable_bool() {
    assert_eq!(
        reachability(ReachVerdict::Reachable {
            witness: vec!["main".into()]
        })
        .as_legacy_bool(),
        Some(true)
    );
    assert_eq!(
        reachability(ReachVerdict::NotReachable).as_legacy_bool(),
        Some(false)
    );
    assert_eq!(
        reachability(ReachVerdict::Unknown {
            reason: "opaque".into()
        })
        .as_legacy_bool(),
        None
    );
}

#[test]
fn verdict_wire_shape_is_internally_tagged() {
    let v = reachability(ReachVerdict::Reachable {
        witness: vec!["a".into(), "b".into()],
    });
    let value = serde_json::to_value(&v).unwrap();
    assert_eq!(
        value,
        json!({
            "verdict": {"kind": "reachable", "witness": ["a", "b"]},
            "config": "nightly-2026-06-01;default-features",
            "engine": "static-mir-rta@0.1"
        })
    );

    // Round-trips.
    let back: Reachability = serde_json::from_value(value).unwrap();
    assert_eq!(back, v);

    // NotReachable carries no payload but keeps the tag.
    assert_eq!(
        serde_json::to_value(reachability(ReachVerdict::NotReachable).verdict).unwrap(),
        json!({"kind": "not_reachable"})
    );
}

#[test]
fn reachability_is_additive_absent_when_not_run() {
    // A finding without the static engine must not emit `reachability` at all,
    // preserving schema_version 1.
    let finding = json!({
        "advisory_id": "RUSTSEC-2099-0001",
        "aliases": [],
        "title": "t",
        "severity": "high",
        "url": null,
        "occurrences": []
    });
    let parsed: fleetreach_core::VulnFinding = serde_json::from_value(finding).unwrap();
    assert!(parsed.reachability.is_none());

    let reserialized = serde_json::to_value(&parsed).unwrap();
    assert!(
        reserialized.get("reachability").is_none(),
        "absent reachability must be omitted from JSON"
    );
}
