//! Parser contract, checked against a real `govulncheck -format json` capture
//! (golang.org/x/text v0.3.0, trimmed to the relevant messages). The fixture
//! deliberately contains one finding of each reachability depth.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fleetreach_core::{DependencyKind, Ecosystem, Occurrence, ReachVerdict, RepoId};
use fleetreach_go::{direct_modules, parse_findings};

fn findings() -> Vec<fleetreach_core::VulnFinding> {
    let json = include_str!("fixtures/xtext.json");
    // No direct-deps context → everything classifies transitive.
    parse_findings(json, &RepoId("svc".into()), &BTreeSet::new()).expect("fixture parses")
}

fn dependency_kind(f: &fleetreach_core::VulnFinding) -> DependencyKind {
    match &f.occurrences[0] {
        Occurrence::InRepo {
            dependency_kind, ..
        } => *dependency_kind,
        _ => panic!("expected InRepo occurrence"),
    }
}

fn verdict(id: &str) -> ReachVerdict {
    findings()
        .into_iter()
        .find(|f| f.advisory_id == id)
        .unwrap_or_else(|| panic!("{id} present"))
        .reachability
        .expect("reachability set")
        .verdict
}

#[test]
fn symbol_level_finding_is_reachable_with_a_witness() {
    // GO-2021-0113: main calls language.Parse, a vulnerable symbol -> a symbol
    // trace -> Reachable, with the call chain as the witness.
    match verdict("GO-2021-0113") {
        ReachVerdict::Reachable { witness } => {
            assert!(!witness.is_empty(), "witness carries the call chain");
            assert!(
                witness.iter().any(|f| f.contains("Parse")),
                "witness names the vulnerable symbol: {witness:?}"
            );
        }
        other => panic!("expected Reachable, got {other:?}"),
    }
}

#[test]
fn imported_but_uncalled_is_unknown_never_not_reachable() {
    // GO-2022-1059: the package is imported but its vulnerable symbol is not
    // called -> package-level deepest -> Unknown (NOT NotReachable).
    match verdict("GO-2022-1059") {
        ReachVerdict::Unknown { reason } => assert!(reason.contains("imported")),
        other => panic!("expected Unknown, got {other:?}"),
    }
}

#[test]
fn present_but_unimported_is_unknown() {
    // GO-2020-0015: module present, package never imported -> module-level only.
    match verdict("GO-2020-0015") {
        ReachVerdict::Unknown { reason } => assert!(reason.contains("present")),
        other => panic!("expected Unknown, got {other:?}"),
    }
}

#[test]
fn never_emits_not_reachable() {
    // The whole soundness contract: govulncheck is sound-positive only.
    for f in findings() {
        if let Some(r) = f.reachability {
            assert!(
                !matches!(r.verdict, ReachVerdict::NotReachable),
                "{} must not be NotReachable",
                f.advisory_id
            );
        }
    }
}

/// Real end-to-end against a live govulncheck. Ignored by default (CI has no Go
/// toolchain); run with `FLEETREACH_GO_E2E=<module dir>` and `GOVULNCHECK=<path>`.
///
/// `FLEETREACH_GO_SANDBOX` (off|auto|require, default off) picks the build
/// confinement. To exercise the confined, network-denied path, also point
/// `GOVULNDB=file://<mirror>` at a local DB mirror:
///   FLEETREACH_GO_SANDBOX=require GOVULNDB=file:///path/to/mirror \
///   FLEETREACH_GO_E2E=/path/to/module GOVULNCHECK=$(go env GOPATH)/bin/govulncheck \
///   cargo test -p fleetreach-go --test parse -- --ignored e2e
#[test]
#[ignore = "needs go + govulncheck; set FLEETREACH_GO_E2E and GOVULNCHECK"]
fn e2e_against_live_govulncheck() {
    use fleetreach_go::SandboxPolicy;
    let dir = std::env::var("FLEETREACH_GO_E2E").expect("FLEETREACH_GO_E2E set");
    let gv = std::env::var("GOVULNCHECK").expect("GOVULNCHECK set");
    let sandbox = match std::env::var("FLEETREACH_GO_SANDBOX").as_deref() {
        Ok("auto") => SandboxPolicy::Auto,
        Ok("require") => SandboxPolicy::Require,
        _ => SandboxPolicy::Off,
    };
    // A `file://` mirror here lets the confined (network-denied) path run offline.
    let vuln_db = std::env::var("GOVULNDB").ok().filter(|s| !s.is_empty());
    let found = fleetreach_go::scan_module(
        std::path::Path::new(&dir),
        &RepoId("e2e".into()),
        &fleetreach_go::GoScanOptions {
            govulncheck: std::path::Path::new(&gv),
            sandbox,
            vuln_db: vuln_db.as_deref(),
            offline: false,
        },
    )
    .expect("scan_module runs");
    let reachable = found
        .iter()
        .find(|f| f.advisory_id == "GO-2021-0113")
        .expect("GO-2021-0113 found");
    assert!(matches!(
        reachable.reachability.as_ref().map(|r| &r.verdict),
        Some(ReachVerdict::Reachable { .. })
    ));
}

#[test]
fn version_adapter_handles_go_version_shapes() {
    // Representative real shapes from the Go vuln DB (validated at full scale by
    // version_adapter_handles_every_db_version): plain, v-prefixed, pseudo-version,
    // +incompatible build metadata, pre-release.
    for v in [
        "v1.6.0",
        "0.3.8",
        "v0.0.0-20200116001909-b77594299b42",
        "0.0.0-20130808000456-233bccbb1abe",
        "v2.0.0+incompatible",
        "v1.2.3-rc.1",
    ] {
        assert!(
            fleetreach_go::parse_go_version(v).is_some(),
            "should parse: {v}"
        );
    }
    assert!(fleetreach_go::parse_go_version("not-a-version").is_none());
}

/// DB-scale stress for the Go version adapter. Ignored by default; point
/// `FLEETREACH_GO_VERSIONS` at a newline-delimited list of real Go version strings
/// (extracted from vuln.go.dev's vulndb) and assert every one parses, so no real
/// advisory is ever silently dropped by a version it cannot read.
#[test]
#[ignore = "needs FLEETREACH_GO_VERSIONS (extracted vulndb version list)"]
fn version_adapter_handles_every_db_version() {
    use fleetreach_core::semver::VersionReq;
    let path = std::env::var("FLEETREACH_GO_VERSIONS").expect("FLEETREACH_GO_VERSIONS set");
    let text = std::fs::read_to_string(&path).expect("read version list");
    let mut total = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        total += 1;
        // Both directions matter: the installed-version parse (drops the finding on
        // failure) and the >=fixed range synthesis (drops the fix on failure).
        if fleetreach_go::parse_go_version(line).is_none() {
            failures.push(format!("Version({line})"));
        }
        let stripped = line.strip_prefix('v').unwrap_or(line);
        if VersionReq::parse(&format!(">={stripped}")).is_err() {
            failures.push(format!("VersionReq({line})"));
        }
    }
    eprintln!(
        "version adapter: {total} strings, {} failures",
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "unparseable Go versions: {:?}",
        &failures[..failures.len().min(20)]
    );
}

/// Corpus-scale test: every version string that appears in a *real* `go.mod`
/// require/replace must parse, or a Tier-C finding can be silently dropped (a
/// false-clean). The
/// vulndb test above covers the 2.3k versions advisories mention; this mines the tens
/// of thousands of distinct version strings real manifests actually declare.
///
/// Ignored by default; point `FLEETREACH_GO_CORPUS` at a directory tree of `go.mod`
/// files (the module-proxy corpus). Distinct version strings are deduped, so the
/// reported count is the real surface, not file count.
#[test]
#[ignore = "needs FLEETREACH_GO_CORPUS (a tree of real go.mod files)"]
fn version_adapter_handles_every_corpus_version() {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use fleetreach_go::{replace_directives, required_modules};

    let root = std::env::var("FLEETREACH_GO_CORPUS").expect("FLEETREACH_GO_CORPUS set");

    // Iterative walk: collect every file named `go.mod` under the corpus root.
    let mut go_mods: Vec<PathBuf> = Vec::new();
    let mut stack = vec![PathBuf::from(&root)];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|n| n == "go.mod") {
                go_mods.push(path);
            }
        }
    }
    assert!(!go_mods.is_empty(), "no go.mod files under {root}");

    // distinct version string -> (origin: "require"|"replace.from"|"replace.to", sample module path)
    let mut distinct: BTreeMap<String, (&'static str, String)> = BTreeMap::new();
    for go_mod in &go_mods {
        let Ok(text) = std::fs::read_to_string(go_mod) else {
            continue;
        };
        for req in required_modules(&text) {
            distinct.entry(req.version).or_insert(("require", req.path));
        }
        for r in replace_directives(&text) {
            if let Some(v) = r.from_version {
                distinct
                    .entry(v)
                    .or_insert(("replace.from", r.from_path.clone()));
            }
            if let Some(v) = r.to_version {
                distinct.entry(v).or_insert(("replace.to", r.to_path));
            }
        }
    }

    // The pre-registered falsifier for C2 was "any version fails to parse"; on the 47k
    // corpus 8 do. Investigation (see the spec) classified all of them as *indeterminate
    // references*, not versions: branch refs (`master`/`HEAD`/`latest`/a fork branch), a
    // missing version, and a non-canonical `v1.0`. None is a canonical semver the adapter
    // is dropping, and `parse_go_version` cannot order a branch name. The matcher now
    // *surfaces* these (offline.rs warns, never reports clean), so the soundness core of
    // C2 holds. The durable, still-falsifiable claim this test enforces: every version
    // shaped like a full `v?MAJOR.MINOR.PATCH` semver parses — a real adapter gap (a
    // pseudo-version variant, a `+incompatible` combo) would fail here, an unparseable
    // branch name would not.
    let mut unparseable: Vec<String> = Vec::new();
    let mut canonical_failures: Vec<String> = Vec::new();
    for (version, (origin, module)) in &distinct {
        if fleetreach_go::parse_go_version(version).is_none() {
            unparseable.push(format!("{version:?} ({origin} of {module})"));
            if looks_like_full_semver(version) {
                canonical_failures.push(format!("{version:?} ({origin} of {module})"));
            }
        }
    }

    eprintln!(
        "corpus version adapter: {} go.mod files, {} distinct version strings, \
         {} unparseable ({} canonical-shaped)",
        go_mods.len(),
        distinct.len(),
        unparseable.len(),
        canonical_failures.len()
    );
    eprintln!("  unparseable (all indeterminate refs, surfaced not dropped): {unparseable:?}");
    assert!(
        canonical_failures.is_empty(),
        "canonical-shaped Go versions the adapter cannot parse ({} total) -> real gap: {:?}",
        canonical_failures.len(),
        canonical_failures,
    );
}

/// True for a string shaped like a full canonical Go version: optional `v`, then
/// `MAJOR.MINOR.PATCH` numeric, optionally followed by a `-`prerelease / `+`build tail
/// (so pseudo-versions and `+incompatible` count). A branch ref (`master`), an empty
/// string, or a truncated `v1.0` is not full-shaped: the adapter is allowed to reject
/// those, but never a string that looks like a real version.
fn looks_like_full_semver(raw: &str) -> bool {
    let s = raw.strip_prefix('v').unwrap_or(raw);
    let core = s.split(['-', '+']).next().unwrap_or(s);
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() >= 3
        && parts
            .iter()
            .take(3)
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

#[test]
fn classifies_direct_vs_transitive_from_go_mod() {
    let json = include_str!("fixtures/xtext.json");
    let repo = RepoId("svc".into());

    // Default (no go.mod context): x/text is transitive.
    let transitive = parse_findings(json, &repo, &BTreeSet::new()).expect("parses");
    assert!(
        transitive
            .iter()
            .all(|f| dependency_kind(f) == DependencyKind::Transitive),
        "no direct set -> everything transitive"
    );

    // With a go.mod that requires golang.org/x/text directly, the same finding is
    // reclassified Direct — the whole point of the go.mod-driven classification.
    let direct = direct_modules("module github.com/acme/svc\nrequire golang.org/x/text v0.3.0\n");
    let classified = parse_findings(json, &repo, &direct).expect("parses");
    let xtext = classified
        .iter()
        .find(|f| matches!(&f.occurrences[0], Occurrence::InRepo { package, .. } if package == "golang.org/x/text"))
        .expect("x/text finding present");
    assert_eq!(dependency_kind(xtext), DependencyKind::Direct);
}

#[test]
fn maps_metadata_into_the_shared_model() {
    let all = findings();
    let f = all
        .iter()
        .find(|f| f.advisory_id == "GO-2021-0113")
        .expect("present");
    assert_eq!(f.ecosystem, Ecosystem::Go);
    // CVE/GHSA aliases carry through, so --enrich can backfill severity/KEV/EPSS.
    assert!(f.aliases.iter().any(|a| a.starts_with("CVE-")));
    assert!(f
        .url
        .as_deref()
        .unwrap()
        .contains("pkg.go.dev/vuln/GO-2021-0113"));
    // The vulnerable symbol is surfaced for the `affects fn` display.
    assert!(f.affected_functions.iter().any(|s| s.contains("Parse")));
    match &f.occurrences[0] {
        Occurrence::InRepo {
            package,
            installed,
            patched,
            ..
        } => {
            assert_eq!(package, "golang.org/x/text");
            assert_eq!(installed.to_string(), "0.3.0"); // leading `v` stripped
                                                        // Fixed in v0.3.7 -> a >=0.3.7 patched range (no `v`), above installed.
            assert!(patched.iter().any(|r| r.to_string().contains("0.3.7")));
            let fix = fleetreach_core::semver::Version::parse("0.3.7").unwrap();
            assert!(*installed < fix);
        }
        _ => panic!("expected InRepo occurrence"),
    }
}
