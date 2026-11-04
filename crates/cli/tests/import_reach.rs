//! Import chains for RubyGems and the rest: a package reached from an import line and the
//! lockfile is `Reachable` with its chain and that line; anything else is left as it was, and
//! nothing is ever `NotReachable`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fleetreach_cli::config::Config;
use fleetreach_cli::import_reach;
use fleetreach_cli::{build_report, ScanData};
use fleetreach_core::semver::Version;
use fleetreach_core::{
    DependencyKind, Ecosystem, Exploitability, Occurrence, Provenance, ReachVerdict, RepoId,
    VulnFinding,
};

fn provenance() -> Provenance {
    Provenance {
        tool_version: "0".into(),
        rustsec_crate_version: "0".into(),
        db_commit: None,
        db_timestamp: None,
        db_snapshot: None,
        host_os: "x".into(),
        host_arch: "x".into(),
        generated_at: "2026-10-30T00:00:00Z".into(),
        osv: Vec::new(),
        sources: Vec::new(),
        images: Vec::new(),
    }
}

fn finding(id: &str, package: &str) -> VulnFinding {
    VulnFinding {
        advisory_id: id.into(),
        aliases: vec![],
        ecosystem: Ecosystem::RubyGems,
        affected_functions: vec![],
        reachable: None,
        reachability: None,
        exploit: Exploitability::default(),
        title: id.into(),
        severity: fleetreach_core::Severity::High,
        cvss_score: None,
        cvss_vector: None,
        url: None,
        occurrences: vec![Occurrence::InRepo {
            repo: RepoId("app".into()),
            package: package.into(),
            installed: Version::new(1, 0, 0),
            patched: vec![],
            dependency_kind: DependencyKind::Transitive,
            dependency_path: vec![],
            active: None,
            source: Default::default(),
            scope: Default::default(),
            layer: None,
        }],
    }
}

const LOCK: &str = "GEM
  remote: https://rubygems.org/
  specs:
    lonely (1.0.0)
    loofah (1.0.0)
      nokogiri (>= 1.0)
    nokogiri (1.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  lonely
  loofah
";

#[test]
fn a_chain_or_nothing_and_never_not_reachable() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Gemfile"), "gem 'loofah'\ngem 'lonely'\n").unwrap();
    std::fs::write(dir.path().join("Gemfile.lock"), LOCK).unwrap();
    std::fs::write(dir.path().join("app.rb"), "# app\nrequire 'loofah'\n").unwrap();
    let text = format!(
        "[[repo]]\nid = \"app\"\npath = {:?}\necosystem = \"rubygems\"\n",
        dir.path()
    );
    let config = Config::from_str(&text, dir.path(), "reach.toml").expect("valid config");
    let scan = ScanData {
        images: Vec::new(),
        pulled: Vec::new(),
        reused: 0,
        vulnerabilities: vec![finding("REACHED", "nokogiri"), finding("ALONE", "lonely")],
        warnings: vec![],
        outcomes: vec![],
        skipped_unparseable: 0,
        coverage: Vec::new(),
    };
    let mut report = build_report(scan, &[], None, provenance());
    import_reach::assess(&mut report, &config);

    let find = |id: &str| {
        report
            .vulnerabilities
            .iter()
            .find(|v| v.advisory_id == id)
            .unwrap()
    };
    let reached = find("REACHED");
    assert_eq!(reached.reachable, Some(true));
    let reach = reached.reachability.as_ref().unwrap();
    assert_eq!(
        reach.verdict,
        ReachVerdict::Reachable {
            witness: vec!["loofah".to_string(), "nokogiri".to_string()]
        }
    );
    let site = reach.import_site.as_ref().unwrap();
    assert_eq!((site.file.as_str(), site.line), ("app.rb", 2));

    let alone = find("ALONE");
    assert_eq!(alone.reachable, None);
    assert!(
        alone.reachability.is_none(),
        "an unreached finding keeps what it had"
    );
}
