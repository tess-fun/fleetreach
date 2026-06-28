//! Rendering contract: color is emitted only when asked, and a clean fleet
//! renders a friendly note rather than an empty table.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fleetreach_core::semver::Version;
use fleetreach_core::{
    DependencyKind, FleetReport, Occurrence, Provenance, ReachVerdict, Reachability, RepoId,
    Severity, Summary, VulnFinding,
};
use fleetreach_report::{to_table, HumanAssertion};

fn provenance() -> Provenance {
    Provenance {
        tool_version: "0.1.0".into(),
        rustsec_crate_version: "0.33.0".into(),
        db_commit: None,
        db_timestamp: None,
        host_os: "linux".into(),
        host_arch: "x86_64".into(),
        generated_at: "2026-06-24T00:00:00Z".into(),
    }
}

fn report(vulns: Vec<VulnFinding>) -> FleetReport {
    FleetReport {
        schema_version: 1,
        provenance: provenance(),
        summary: Summary {
            repos_scanned: 1,
            repos_errored: 0,
            vuln_count: vulns.len(),
            warn_count: 0,
            max_severity: Severity::Critical,
            stale_ignores: vec![],
        },
        vulnerabilities: vulns,
        warnings: vec![],
        outcomes: vec![],
    }
}

fn a_vuln() -> VulnFinding {
    VulnFinding {
        advisory_id: "RUSTSEC-2099-0001".into(),
        aliases: vec![],
        ecosystem: Default::default(),
        reachability: None,
        exploit: Default::default(),
        affected_functions: vec![],
        reachable: None,
        title: "boom".into(),
        severity: Severity::Critical,
        cvss_score: Some(9.8),
        url: None,
        occurrences: vec![Occurrence::InRepo {
            repo: RepoId("app".into()),
            package: "foo".into(),
            installed: Version::new(1, 0, 0),
            patched: vec![],
            dependency_kind: DependencyKind::Transitive,
            dependency_path: vec![],
            active: None,
            source: Default::default(),
        }],
    }
}

#[test]
fn table_emits_ansi_only_when_color_is_requested() {
    let r = report(vec![a_vuln()]);
    let plain = to_table(&r, false);
    let colored = to_table(&r, true);
    assert!(
        !plain.contains('\u{1b}'),
        "no-color output must be ANSI-free"
    );
    assert!(colored.contains('\u{1b}'), "color output must contain ANSI");
    // Content is identical once the escapes are stripped — color is cosmetic.
    assert!(plain.contains("RUSTSEC-2099-0001"));
    assert!(colored.contains("RUSTSEC-2099-0001"));
}

#[test]
fn impact_and_fix_first_sanitize_untrusted_cells() {
    // Advisory titles and repo names are untrusted; a terminal escape in either must
    // not survive into the impact / fix-first table views (M-4 regression).
    let mut v = a_vuln();
    v.title = "pwn\u{1b}[31mTITLE".into();
    v.occurrences = vec![Occurrence::InRepo {
        repo: RepoId("repo\u{1b}]0;evilREPO".into()),
        package: "foo".into(),
        installed: Version::new(1, 0, 0),
        patched: vec![],
        dependency_kind: DependencyKind::Transitive,
        dependency_path: vec![],
        active: None,
        source: Default::default(),
    }];
    let r = report(vec![v]);
    for out in [
        fleetreach_report::to_impact(&r, false),
        fleetreach_report::to_fix_first(&r, false),
    ] {
        assert!(
            !out.contains('\u{1b}'),
            "untrusted escape leaked into a table view: {out:?}"
        );
    }
}

#[test]
fn table_shows_cvss_score_next_to_severity() {
    let t = to_table(&report(vec![a_vuln()]), false);
    assert!(
        t.contains("critical 9.8"),
        "score should sit by severity:\n{t}"
    );
}

#[test]
fn clean_report_renders_a_friendly_note() {
    let r = report(vec![]);
    assert_eq!(to_table(&r, true), "No advisories found.");
}

#[test]
fn table_shows_dependency_provenance_hint() {
    let vuln = |kind, path: Vec<&str>| {
        let mut v = a_vuln();
        if let Occurrence::InRepo {
            dependency_kind,
            dependency_path,
            ..
        } = &mut v.occurrences[0]
        {
            *dependency_kind = kind;
            *dependency_path = path.into_iter().map(String::from).collect();
        }
        v
    };

    // Transitive: name the chain that drags it in.
    let t = to_table(
        &report(vec![vuln(
            DependencyKind::Transitive,
            vec!["app", "middle", "foo"],
        )]),
        false,
    );
    assert!(t.contains("(via middle)"), "table:\n{t}");

    // Direct: labelled so you know you can bump it yourself.
    let d = to_table(
        &report(vec![vuln(DependencyKind::Direct, vec!["app", "foo"])]),
        false,
    );
    assert!(d.contains("(direct)"), "table:\n{d}");
}

#[test]
fn sarif_is_valid_and_maps_severity() {
    let r = report(vec![a_vuln()]); // a_vuln is Critical
    let sarif = fleetreach_report::to_sarif(&r, &[]).unwrap();
    let v: serde_json::Value = serde_json::from_str(&sarif).unwrap();

    assert_eq!(v["version"], "2.1.0");
    let run = &v["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "fleetreach");
    assert_eq!(run["tool"]["driver"]["rules"][0]["id"], "RUSTSEC-2099-0001");
    // critical -> SARIF error + GitHub security-severity >= 9
    assert_eq!(run["results"][0]["level"], "error");
    // no reachability ran -> no VEX suppression on a plain finding.
    assert!(run["results"][0]["suppressions"].is_null());
    let sev: f64 = run["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(sev >= 9.0);
}

#[test]
fn sarif_result_carries_dependency_kind() {
    // Each result tags its direct/transitive kind so a SARIF consumer gets the same
    // fix-path signal as `-f blast` without parsing the message text.
    let mut direct = a_vuln(); // a_vuln's occurrence is Transitive by default
    direct.advisory_id = "RUSTSEC-DIRECT".into();
    if let Occurrence::InRepo {
        dependency_kind, ..
    } = &mut direct.occurrences[0]
    {
        *dependency_kind = DependencyKind::Direct;
    }
    let transitive = a_vuln(); // RUSTSEC-2099-0001, transitive

    let run = sarif_value(&report(vec![direct, transitive]), &[]);
    let results = run["runs"][0]["results"].as_array().unwrap();
    let kind_of = |id: &str| {
        results.iter().find(|r| r["ruleId"] == id).unwrap()["properties"]["dependencyKind"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(kind_of("RUSTSEC-DIRECT"), "direct");
    assert_eq!(kind_of("RUSTSEC-2099-0001"), "transitive");
}

fn sarif_value(r: &FleetReport, approved: &[HumanAssertion]) -> serde_json::Value {
    let s = fleetreach_report::to_sarif(r, approved).unwrap();
    serde_json::from_str(&s).unwrap()
}

/// §11: a machine-sound `not_affected` (static `NotReachable`) suppresses the result.
#[test]
fn sarif_suppresses_a_not_reachable_finding() {
    let mut v = a_vuln();
    v.reachability = Some(Reachability {
        verdict: ReachVerdict::NotReachable,
        config: "x86_64-unknown-linux-gnu".into(),
        engine: "static-mir-rta@0.1.0".into(),
        targets: vec!["x86_64-unknown-linux-gnu".into()],
        witness: Some("sha256:abc".into()),
    });
    let run = sarif_value(&report(vec![v]), &[]);
    let result = &run["runs"][0]["results"][0];
    let sup = &result["suppressions"][0];
    assert_eq!(sup["kind"], "external");
    assert!(sup["justification"]
        .as_str()
        .unwrap()
        .contains("vulnerable_code_not_in_execute_path"));
}

/// A phantom dependency (`active: Some(false)`) is also a machine `not_affected`.
#[test]
fn sarif_suppresses_a_phantom_dependency() {
    let mut v = a_vuln();
    if let Occurrence::InRepo { active, .. } = &mut v.occurrences[0] {
        *active = Some(false);
    }
    let run = sarif_value(&report(vec![v]), &[]);
    let sup = &run["runs"][0]["results"][0]["suppressions"][0];
    assert!(sup["justification"]
        .as_str()
        .unwrap()
        .contains("component_not_present"));
}

/// §11: an undecided/affected finding is never suppressed.
#[test]
fn sarif_does_not_suppress_reachable_or_undecided() {
    let mut reachable = a_vuln();
    reachable.advisory_id = "RUSTSEC-2099-0002".into();
    reachable.reachability = Some(Reachability {
        verdict: ReachVerdict::Reachable {
            witness: vec!["root".into(), "foo::bad".into()],
        },
        config: "x86_64".into(),
        engine: "e".into(),
        targets: vec![],
        witness: None,
    });
    let undecided = a_vuln(); // no reachability -> under_investigation
    let run = sarif_value(&report(vec![reachable, undecided]), &[]);
    for result in run["runs"][0]["results"].as_array().unwrap() {
        assert!(
            result["suppressions"].is_null(),
            "reachable/undecided must not be suppressed"
        );
    }
}

/// §11: only an approved human assertion is injected as a suppressed result.
#[test]
fn sarif_injects_only_approved_human_assertions() {
    let approved = HumanAssertion {
        advisory_id: "RUSTSEC-2020-0071".into(),
        aliases: vec![],
        product_id: "pkg:cargo/app@1.0.0".into(),
        package: "time".into(),
        version: "0.2.7".into(),
        justification: Some("component_not_present".into()),
        impact_statement: "dev only".into(),
        approved_by: Some("secteam".into()),
    };
    let unapproved = HumanAssertion {
        advisory_id: "RUSTSEC-2021-0003".into(),
        approved_by: None,
        ..approved.clone()
    };
    let run = sarif_value(&report(vec![]), &[approved, unapproved]);
    let results = run["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 1, "only the approved assertion is injected");
    let r = &results[0];
    assert_eq!(r["ruleId"], "RUSTSEC-2020-0071");
    assert!(r["suppressions"][0]["justification"]
        .as_str()
        .unwrap()
        .contains("approved_by secteam"));
}

#[test]
fn impact_ranks_by_repos_affected() {
    // A finding present in two repos vs. one present in a single repo.
    let mut wide = a_vuln(); // one occurrence in "app"
    wide.advisory_id = "RUSTSEC-WIDE".into();
    wide.occurrences.push(Occurrence::InRepo {
        repo: RepoId("services".into()),
        package: "foo".into(),
        installed: Version::new(1, 0, 0),
        patched: vec![],
        dependency_kind: DependencyKind::Transitive,
        dependency_path: vec![],
        active: None,
        source: Default::default(),
    });
    let mut narrow = a_vuln();
    narrow.advisory_id = "RUSTSEC-NARROW".into();

    let out = fleetreach_report::to_impact(&report(vec![narrow, wide]), false);
    // Both repos of the wide finding are named, and it sorts above the narrow one.
    assert!(out.contains("app") && out.contains("services"));
    let wide_pos = out.find("RUSTSEC-WIDE").unwrap();
    let narrow_pos = out.find("RUSTSEC-NARROW").unwrap();
    assert!(wide_pos < narrow_pos, "wider blast radius ranks first");
}

#[test]
fn blast_splits_direct_and_transitive_with_fix_hint() {
    fn occ(repo: &str, kind: DependencyKind) -> Occurrence {
        Occurrence::InRepo {
            repo: RepoId(repo.into()),
            package: "foo".into(),
            installed: Version::new(1, 0, 0),
            patched: vec![],
            dependency_kind: kind,
            dependency_path: vec![],
            active: None,
            source: Default::default(),
        }
    }
    fn vuln(id: &str, occs: Vec<Occurrence>) -> VulnFinding {
        let mut v = a_vuln();
        v.advisory_id = id.into();
        v.occurrences = occs;
        v
    }

    // mixed: 1 direct + 2 transitive repos -> total 3, Fix "mixed".
    let mixed = vuln(
        "RUSTSEC-MIXED",
        vec![
            occ("app", DependencyKind::Direct),
            occ("services", DependencyKind::Transitive),
            occ("web", DependencyKind::Transitive),
        ],
    );
    // manifest: every affected repo depends on it directly -> Fix "manifest".
    let manifest = vuln(
        "RUSTSEC-MANIFEST",
        vec![
            occ("m1", DependencyKind::Direct),
            occ("m2", DependencyKind::Direct),
        ],
    );
    // upstream: purely transitive -> Fix "upstream".
    let upstream = vuln(
        "RUSTSEC-UPSTREAM",
        vec![occ("u1", DependencyKind::Transitive)],
    );

    let out = fleetreach_report::to_blast(&report(vec![upstream, manifest, mixed]), false);

    // Ranked by total blast radius: mixed (3) > manifest (2) > upstream (1).
    let pos = |id: &str| out.find(id).unwrap();
    assert!(pos("RUSTSEC-MIXED") < pos("RUSTSEC-MANIFEST"));
    assert!(pos("RUSTSEC-MANIFEST") < pos("RUSTSEC-UPSTREAM"));
    // Each fix-path hint is rendered.
    assert!(out.contains("manifest"), "all-direct -> manifest hint");
    assert!(out.contains("upstream"), "all-transitive -> upstream hint");
    assert!(out.contains("mixed"), "direct+transitive -> mixed hint");
    // The header names the decomposition.
    assert!(out.contains("Direct") && out.contains("Transitive"));
}

#[test]
fn packages_roll_up_advisories_per_dependency() {
    fn occ(repo: &str, package: &str, kind: DependencyKind) -> Occurrence {
        Occurrence::InRepo {
            repo: RepoId(repo.into()),
            package: package.into(),
            installed: Version::new(1, 0, 0),
            patched: vec![],
            dependency_kind: kind,
            dependency_path: vec![],
            active: None,
            source: Default::default(),
        }
    }
    fn vuln(id: &str, occs: Vec<Occurrence>) -> VulnFinding {
        let mut v = a_vuln();
        v.advisory_id = id.into();
        v.occurrences = occs;
        v
    }

    // openssl: two advisories across repos {x, y} -> one row, advisories = 2, reach 2.
    let a = vuln(
        "RUSTSEC-A",
        vec![
            occ("x", "openssl", DependencyKind::Direct),
            occ("y", "openssl", DependencyKind::Transitive),
        ],
    );
    let b = vuln(
        "RUSTSEC-B",
        vec![occ("x", "openssl", DependencyKind::Direct)],
    );
    // smallvec: one advisory in one repo -> reach 1.
    let c = vuln(
        "RUSTSEC-C",
        vec![occ("z", "smallvec", DependencyKind::Direct)],
    );

    let rep = report(vec![a, b, c]);

    // Table: openssl (reach 2) ranks above smallvec (reach 1).
    let out = fleetreach_report::to_packages(&rep, false);
    assert!(out.find("openssl").unwrap() < out.find("smallvec").unwrap());

    // JSON rollup: openssl carries 2 advisories across 2 repos (1 direct, 1 transitive).
    let json: serde_json::Value =
        serde_json::from_str(&fleetreach_report::to_packages_json(&rep).unwrap()).unwrap();
    let rows = json.as_array().unwrap();
    let openssl = rows.iter().find(|r| r["package"] == "openssl").unwrap();
    assert_eq!(openssl["advisories"], 2);
    assert_eq!(openssl["repos"], 2);
    assert_eq!(openssl["direct"], 1);
    assert_eq!(openssl["transitive"], 1);
    assert_eq!(openssl["fix"], "mixed");
}

#[test]
fn fix_first_ranks_severity_over_blast_radius() {
    use fleetreach_core::{Exploitability, WarnFinding, WarnKind};

    let in_repos = |names: &[&str]| -> Vec<Occurrence> {
        names
            .iter()
            .map(|n| Occurrence::InRepo {
                repo: RepoId((*n).into()),
                package: "foo".into(),
                installed: Version::new(1, 0, 0),
                patched: vec![],
                dependency_kind: DependencyKind::Transitive,
                dependency_path: vec![],
                active: None,
                source: Default::default(),
            })
            .collect()
    };

    // A critical CVE in a single repo.
    let mut crit = a_vuln();
    crit.advisory_id = "RUSTSEC-CRIT".into();
    crit.severity = Severity::Critical;
    crit.cvss_score = Some(9.8);

    // A low-severity CVE spread across many repos.
    let mut low_wide = a_vuln();
    low_wide.advisory_id = "RUSTSEC-LOW-WIDE".into();
    low_wide.severity = Severity::Low;
    low_wide.cvss_score = Some(3.1);
    low_wide.occurrences = in_repos(&["a", "b", "c", "d", "e"]);

    // An actively-exploited high — must lead despite hitting a single repo.
    let mut kev = a_vuln();
    kev.advisory_id = "RUSTSEC-KEV".into();
    kev.severity = Severity::High;
    kev.cvss_score = Some(7.5);
    kev.exploit = Exploitability {
        kev: true,
        epss: Some(0.9),
    };

    let mut r = report(vec![low_wide, crit, kev]);
    // A warning hitting the most repos of all — the historical false-priority case.
    r.warnings.push(WarnFinding {
        kind: WarnKind::Unsound,
        advisory_id: Some("RUSTSEC-WARN".into()),
        title: "unsound but wide".into(),
        occurrences: in_repos(&["w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8"]),
    });

    let out = fleetreach_report::to_fix_first(&r, false);
    let pos = |id: &str| out.find(id).expect("id present in output");
    // KEV first, then critical, then the low CVE, and the warning dead last —
    // even though the warning and low CVE hit far more repos than KEV/crit.
    assert!(pos("RUSTSEC-KEV") < pos("RUSTSEC-CRIT"), "KEV leads");
    assert!(
        pos("RUSTSEC-CRIT") < pos("RUSTSEC-LOW-WIDE"),
        "severity beats blast radius"
    );
    assert!(
        pos("RUSTSEC-LOW-WIDE") < pos("RUSTSEC-WARN"),
        "real CVEs rank above warnings"
    );
    // The exploit column surfaces the KEV + EPSS signals.
    assert!(out.contains("KEV") && out.contains("EPSS"), "exploit shown");
}

/// A vulnerable occurrence with an explicit patched range, so remediation can
/// name an upgrade target (vs `a_vuln`, whose empty `patched` = no fix).
fn fixable(repo: &str, pkg: &str, installed: &str, fixed: &str) -> Occurrence {
    use fleetreach_core::semver::VersionReq;
    Occurrence::InRepo {
        repo: RepoId(repo.into()),
        package: pkg.into(),
        installed: Version::parse(installed).unwrap(),
        patched: vec![VersionReq::parse(fixed).unwrap()],
        dependency_kind: DependencyKind::Transitive,
        dependency_path: vec![],
        active: None,
        source: Default::default(),
    }
}

#[test]
fn remediation_batches_a_single_bump_and_orders_by_severity() {
    // Two advisories on `foo`, both cleared by >=1.5.0 -> one batched row.
    let mut a = a_vuln();
    a.advisory_id = "RUSTSEC-FOO-A".into();
    a.severity = Severity::Medium;
    a.cvss_score = Some(5.0);
    a.occurrences = vec![fixable("r1", "foo", "1.0.0", ">=1.2.0")];
    let mut b = a_vuln();
    b.advisory_id = "RUSTSEC-FOO-B".into();
    b.severity = Severity::High;
    b.cvss_score = Some(7.0);
    b.occurrences = vec![fixable("r2", "foo", "1.1.0", ">=1.5.0")];
    // A critical on a different package, must lead the queue.
    let mut c = a_vuln();
    c.advisory_id = "RUSTSEC-BAR".into();
    c.severity = Severity::Critical;
    c.cvss_score = Some(9.5);
    c.occurrences = vec![fixable("r1", "bar", "2.0.0", ">=2.1.0")];

    let out = fleetreach_report::to_remediation(&report(vec![a, b, c]), false);
    // One batched action names the minimal bump that clears both foo advisories.
    assert!(
        out.contains("bump foo 1.0.0 \u{2192} 1.5.0"),
        "batched bump:\n{out}"
    );
    assert!(out.contains("2 advisories"), "batch resolves two:\n{out}");
    // Critical bar leads foo (severity-dominant ordering).
    let pos = |s: &str| out.find(s).expect("present");
    assert!(pos("bar") < pos("bump foo"), "critical leads:\n{out}");
}

#[test]
fn remediation_promotes_reachable_within_a_severity_band() {
    // Same severity; the unknown-reach batch hits MORE repos. The confirmed-
    // reachable one must still lead, proving reachability outranks blast radius
    // within a band (the key signal when severity is uniform, e.g. Go findings).
    let mut reach = a_vuln();
    reach.advisory_id = "RUSTSEC-REACH".into();
    reach.severity = Severity::High;
    reach.cvss_score = Some(7.0);
    reach.occurrences = vec![fixable("r1", "alpha", "1.0.0", ">=1.2.0")];
    reach.reachability = Some(Reachability {
        verdict: ReachVerdict::Reachable { witness: vec![] },
        config: "c".into(),
        engine: "e".into(),
        targets: vec![],
        witness: None,
    });
    let mut wide_unknown = a_vuln();
    wide_unknown.advisory_id = "RUSTSEC-WIDE".into();
    wide_unknown.severity = Severity::High;
    wide_unknown.cvss_score = Some(7.0);
    wide_unknown.occurrences = vec![
        fixable("r1", "beta", "1.0.0", ">=1.2.0"),
        fixable("r2", "beta", "1.0.0", ">=1.2.0"),
        fixable("r3", "beta", "1.0.0", ">=1.2.0"),
    ];

    let out = fleetreach_report::to_remediation(&report(vec![wide_unknown, reach]), false);
    let pos = |s: &str| out.find(s).expect("present");
    assert!(
        pos("bump alpha") < pos("bump beta"),
        "confirmed-reachable (1 repo) must lead wider-but-unknown (3 repos):\n{out}"
    );
}

#[test]
fn remediation_gate_demotes_not_reachable() {
    let mut live = a_vuln();
    live.advisory_id = "RUSTSEC-LIVE".into();
    live.occurrences = vec![fixable("r1", "live", "1.0.0", ">=1.2.0")];
    live.reachability = Some(Reachability {
        verdict: ReachVerdict::Reachable { witness: vec![] },
        config: "cfg".into(),
        engine: "test".into(),
        targets: vec![],
        witness: None,
    });
    let mut dead = a_vuln();
    dead.advisory_id = "RUSTSEC-DEAD".into();
    dead.occurrences = vec![fixable("r2", "dead", "1.0.0", ">=1.2.0")];
    dead.reachability = Some(Reachability {
        verdict: ReachVerdict::NotReachable,
        config: "cfg".into(),
        engine: "test".into(),
        targets: vec![],
        witness: None,
    });

    let out = fleetreach_report::to_remediation(&report(vec![live, dead]), false);
    // The reachable one is queued above the informational tail; the dead one sits
    // below the "not reachable" heading.
    let heading = out
        .find("not reachable (shown")
        .expect("informational heading");
    assert!(
        out.find("bump live").expect("live") < heading,
        "live is queued:\n{out}"
    );
    assert!(
        out.find("bump dead").expect("dead") > heading,
        "dead is informational:\n{out}"
    );
}

#[test]
fn remediation_reports_no_fix_honestly() {
    // a_vuln has empty patched -> no published fix.
    let mut v = a_vuln();
    v.advisory_id = "RUSTSEC-NOFIX".into();
    let out = fleetreach_report::to_remediation(&report(vec![v]), false);
    assert!(out.contains("no fix: foo"), "honest no-fix:\n{out}");
}

#[test]
fn remediation_on_clean_report_is_friendly() {
    let out = fleetreach_report::to_remediation(&report(vec![]), false);
    assert!(out.contains("nothing to fix"), "friendly note:\n{out}");
}

#[test]
fn remediation_json_round_trips() {
    let mut v = a_vuln();
    v.occurrences = vec![fixable("r1", "foo", "1.0.0", ">=1.2.0")];
    let json = fleetreach_report::to_remediation_json(&report(vec![v])).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed[0]["package"], "foo");
    assert_eq!(parsed[0]["action"]["type"], "upgrade");
    assert_eq!(parsed[0]["action"]["to"], "1.2.0");
}
