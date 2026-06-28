//! Property tests for the only non-trivial owned logic (§13): grouping conserves
//! occurrences, lands every finding in exactly one group, sorts totally, keeps
//! the vuln/warning streams apart, and computes the per-occurrence verdict
//! correctly when versions diverge across the fleet.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fleetreach_core::semver::{Version, VersionReq};
use fleetreach_core::{
    DependencyKind, Occurrence, RepoId, Severity, VulnFinding, WarnFinding, WarnKind,
};
use fleetreach_correlate::correlate;
use proptest::prelude::*;

// ---- strategies ----

fn arb_severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Unknown),
        Just(Severity::Low),
        Just(Severity::Medium),
        Just(Severity::High),
        Just(Severity::Critical),
    ]
}

fn arb_version() -> impl Strategy<Value = Version> {
    (0u64..3, 0u64..3, 0u64..3).prop_map(|(a, b, c)| Version::new(a, b, c))
}

fn arb_repo() -> impl Strategy<Value = RepoId> {
    (0u32..4).prop_map(|n| RepoId(format!("repo-{n}")))
}

/// A single-occurrence vuln, as produced before correlation. The id space is
/// small so collisions (the interesting case) happen often.
fn arb_vuln() -> impl Strategy<Value = VulnFinding> {
    (
        (0u32..6).prop_map(|n| format!("RUSTSEC-2099-{n:04}")),
        arb_severity(),
        arb_repo(),
        arb_version(),
    )
        .prop_map(|(id, severity, repo, installed)| VulnFinding {
            aliases: vec![format!("CVE-{id}")],
            ecosystem: Default::default(),
            reachability: None,
            exploit: Default::default(),
            affected_functions: vec![],
            reachable: None,
            title: format!("title for {id}"),
            advisory_id: id,
            severity,
            cvss_score: None,
            url: None,
            occurrences: vec![Occurrence::InRepo {
                repo,
                package: "pkg".into(),
                installed,
                patched: vec![],
                dependency_kind: DependencyKind::Transitive,
                dependency_path: vec![],
                active: None,
                source: Default::default(),
            }],
        })
}

fn arb_warn() -> impl Strategy<Value = WarnFinding> {
    (
        prop_oneof![
            Just(WarnKind::Unmaintained),
            Just(WarnKind::Yanked),
            Just(WarnKind::Unsound),
            Just(WarnKind::Notice),
        ],
        prop_oneof![
            Just(None),
            (0u32..4).prop_map(|n| Some(format!("RUSTSEC-2098-{n:04}"))),
        ],
        arb_repo(),
        arb_version(),
    )
        .prop_map(|(kind, advisory_id, repo, installed)| WarnFinding {
            kind,
            advisory_id,
            title: "warn".into(),
            occurrences: vec![Occurrence::InRepo {
                repo,
                package: "pkg".into(),
                installed,
                patched: vec![],
                dependency_kind: DependencyKind::Transitive,
                dependency_path: vec![],
                active: None,
                source: Default::default(),
            }],
        })
}

proptest! {
    #[test]
    fn vulns_group_conserve_and_sort(inputs in prop::collection::vec(arb_vuln(), 0..40)) {
        let total_in: usize = inputs.iter().map(|v| v.occurrences.len()).sum();
        let distinct_ids: BTreeSet<String> =
            inputs.iter().map(|v| v.advisory_id.clone()).collect();

        let out = correlate(inputs, vec![]).vulnerabilities;

        // exactly one group per distinct id, and the id sets match
        prop_assert_eq!(out.len(), distinct_ids.len());
        let out_ids: BTreeSet<String> = out.iter().map(|v| v.advisory_id.clone()).collect();
        prop_assert_eq!(&out_ids, &distinct_ids);

        // occurrences are conserved as a set: dedup only removes exact
        // duplicates, never invents, so the total can only shrink...
        let total_out: usize = out.iter().map(|v| v.occurrences.len()).sum();
        prop_assert!(total_out <= total_in);
        // ...and within each finding there are no remaining duplicates.
        for v in &out {
            let mut occ = v.occurrences.clone();
            let before = occ.len();
            occ.dedup(); // already sorted, so equal ones would be adjacent
            prop_assert_eq!(occ.len(), before, "occurrences must be deduped");
        }

        // total, stable order: severity desc, then id asc (ids are unique)
        for pair in out.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            let ordered = a.severity > b.severity
                || (a.severity == b.severity && a.advisory_id < b.advisory_id);
            prop_assert!(ordered, "order violated near {}", a.advisory_id);
        }
    }

    #[test]
    fn warns_group_conserve_and_streams_never_cross(
        vulns in prop::collection::vec(arb_vuln(), 0..20),
        warns in prop::collection::vec(arb_warn(), 0..20),
    ) {
        let vuln_ids: BTreeSet<String> = vulns.iter().map(|v| v.advisory_id.clone()).collect();
        let warn_keys: BTreeSet<(WarnKind, Option<String>)> =
            warns.iter().map(|w| (w.kind, w.advisory_id.clone())).collect();
        let warn_occ_in: usize = warns.iter().map(|w| w.occurrences.len()).sum();

        let out = correlate(vulns, warns);

        // warnings: one group per (kind, id); occurrences deduped, never invented
        prop_assert_eq!(out.warnings.len(), warn_keys.len());
        let warn_occ_out: usize = out.warnings.iter().map(|w| w.occurrences.len()).sum();
        prop_assert!(warn_occ_out <= warn_occ_in);
        for w in &out.warnings {
            let mut occ = w.occurrences.clone();
            let before = occ.len();
            occ.dedup();
            prop_assert_eq!(occ.len(), before, "warning occurrences must be deduped");
        }

        // streams never cross: every output vuln id came from the vuln stream,
        // and the disjoint id namespaces never leak into each other
        for v in &out.vulnerabilities {
            prop_assert!(vuln_ids.contains(&v.advisory_id));
        }
        for w in &out.warnings {
            prop_assert!(warn_keys.contains(&(w.kind, w.advisory_id.clone())));
        }
    }
}

#[test]
fn version_divergent_occurrences_keep_independent_verdicts() {
    let patched = vec![VersionReq::parse(">=1.2.3").unwrap()];
    let at = |repo: &str, installed: Version| VulnFinding {
        advisory_id: "RUSTSEC-2099-0001".into(),
        aliases: vec![],
        ecosystem: Default::default(),
        reachability: None,
        exploit: Default::default(),
        affected_functions: vec![],
        reachable: None,
        title: "shared advisory".into(),
        severity: Severity::High,
        cvss_score: None,
        url: None,
        occurrences: vec![Occurrence::InRepo {
            repo: RepoId(repo.into()),
            package: "foo".into(),
            installed,
            patched: patched.clone(),
            dependency_kind: DependencyKind::Transitive,
            dependency_path: vec![],
            active: None,
            source: Default::default(),
        }],
    };

    let out = correlate(
        vec![
            at("repo-a", Version::new(1, 1, 9)), // vulnerable
            at("repo-b", Version::new(1, 2, 0)), // vulnerable (1.2.0 < 1.2.3)
            at("repo-c", Version::new(1, 2, 3)), // patched
        ],
        vec![],
    )
    .vulnerabilities;

    // one advisory, three occurrences, sorted by repo id (a, b, c)
    assert_eq!(out.len(), 1);
    let verdicts: Vec<bool> = out[0]
        .occurrences
        .iter()
        .map(|o| o.is_vulnerable())
        .collect();
    assert_eq!(
        verdicts,
        vec![true, true, false],
        "per-occurrence verdicts diverge"
    );
}

#[test]
fn identical_occurrences_are_deduplicated() {
    // The same package@version in the same repo, surfaced twice (e.g. two
    // lockfiles under one glob repo), collapses to a single occurrence.
    let dup = || VulnFinding {
        advisory_id: "RUSTSEC-2099-0001".into(),
        aliases: vec![],
        ecosystem: Default::default(),
        reachability: None,
        exploit: Default::default(),
        affected_functions: vec![],
        reachable: None,
        title: "t".into(),
        severity: Severity::High,
        cvss_score: None,
        url: None,
        occurrences: vec![Occurrence::InRepo {
            repo: RepoId("services".into()),
            package: "foo".into(),
            installed: Version::new(1, 0, 0),
            patched: vec![],
            dependency_kind: DependencyKind::Transitive,
            dependency_path: vec![],
            active: None,
            source: Default::default(),
        }],
    };

    let out = correlate(vec![dup(), dup()], vec![]).vulnerabilities;
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].occurrences.len(),
        1,
        "exact duplicates collapse to one"
    );
}
