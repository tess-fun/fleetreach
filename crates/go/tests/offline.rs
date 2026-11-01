//! Tier-C offline matcher: scan a `go.mod` against an OSV DB mirror with no
//! toolchain. Checked against a tiny hand-built fixture DB.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fleetreach_core::{DependencyKind, Ecosystem, Occurrence, ReachVerdict, RepoId};
use fleetreach_go::{scan_offline, GoDb};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tierc")
}

fn db() -> GoDb {
    GoDb::load(&fixtures().join("db")).expect("load fixture GoDb")
}

fn run() -> Vec<fleetreach_core::VulnFinding> {
    scan_offline(&fixtures().join("repo"), &db(), &RepoId("app".into())).expect("scan_offline runs")
}

#[test]
fn matches_vulnerable_modules_and_skips_patched() {
    let found = run();
    let ids: Vec<&str> = found.iter().map(|f| f.advisory_id.as_str()).collect();
    // vuln@1.0.0 (< fixed 1.2.0) and indirectvuln@0.5.0 (< fixed 1.0.0) are affected;
    // safe@2.0.0 (>= fixed 1.0.0) is not. Sorted by id.
    assert_eq!(ids, vec!["GO-TEST-0001", "GO-TEST-0002"]);
}

#[test]
fn finding_is_module_level_unknown_never_reachable() {
    for f in run() {
        assert_eq!(f.ecosystem, Ecosystem::Go);
        let reach = f.reachability.as_ref().expect("reachability set");
        assert_eq!(reach.engine, "fleetreach-tier-c");
        assert!(
            matches!(reach.verdict, ReachVerdict::Unknown { .. }),
            "{} must be Unknown (module-level), never Reachable/NotReachable",
            f.advisory_id
        );
    }
}

#[test]
fn carries_metadata_patch_and_dependency_kind() {
    let found = run();
    let direct = found
        .iter()
        .find(|f| f.advisory_id == "GO-TEST-0001")
        .unwrap();
    // CVE/GHSA aliases carry through so --enrich can backfill severity/EPSS.
    assert!(direct.aliases.iter().any(|a| a.starts_with("CVE-")));
    assert!(direct
        .url
        .as_deref()
        .unwrap()
        .contains("pkg.go.dev/vuln/GO-TEST-0001"));
    // The vulnerable symbol from ecosystem_specific.imports is surfaced.
    assert!(direct.affected_functions.iter().any(|s| s.contains("Boom")));
    match &direct.occurrences[0] {
        Occurrence::InRepo {
            package,
            installed,
            patched,
            dependency_kind,
            ..
        } => {
            assert_eq!(package, "example.com/vuln");
            assert_eq!(installed.to_string(), "1.0.0");
            // A direct require (not `// indirect`) → Direct; patch is `>=1.2.0`.
            assert_eq!(*dependency_kind, DependencyKind::Direct);
            assert!(patched.iter().any(|r| r.to_string().contains("1.2.0")));
        }
        _ => panic!("expected InRepo occurrence"),
    }

    // The indirect require classifies Transitive.
    let indirect = found
        .iter()
        .find(|f| f.advisory_id == "GO-TEST-0002")
        .unwrap();
    match &indirect.occurrences[0] {
        Occurrence::InRepo {
            dependency_kind, ..
        } => assert_eq!(*dependency_kind, DependencyKind::Transitive),
        _ => panic!("expected InRepo occurrence"),
    }
}

fn scan_repo(sub: &str) -> Vec<fleetreach_core::VulnFinding> {
    scan_offline(&fixtures().join(sub), &db(), &RepoId("app".into())).expect("scan_offline runs")
}

#[test]
fn replace_to_a_fixed_version_is_not_a_false_positive() {
    // vuln@1.0.0 is vulnerable (GO-TEST-0001, fixed 1.2.0) but `replace`d up to the
    // fixed 1.2.0 — the corpus stress test caught Tier-C false-positiving here.
    let found = scan_repo("repo_replace_fixed");
    assert!(
        found.is_empty(),
        "replace to the fixed version must not false-positive: {:?}",
        found.iter().map(|f| &f.advisory_id).collect::<Vec<_>>()
    );
}

#[test]
fn replace_down_to_a_vulnerable_version_is_matched_at_the_replacement() {
    // safe@2.0.0 is clean, but `replace`d DOWN to the vulnerable 0.9.0 (GO-TEST-0003).
    let found = scan_repo("repo_replace_vuln");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].advisory_id, "GO-TEST-0003");
    match &found[0].occurrences[0] {
        Occurrence::InRepo { installed, .. } => assert_eq!(installed.to_string(), "0.9.0"),
        _ => panic!("expected InRepo"),
    }
}

#[test]
fn replace_to_a_local_path_is_unmatchable_and_skipped() {
    // A local-path replacement is no longer the published artifact — don't match it.
    assert!(scan_repo("repo_replace_local").is_empty());
}

#[test]
fn missing_db_is_an_honest_error_with_a_source_chain() {
    use fleetreach_go::{DbError, GoError};
    use std::error::Error;

    let f = fixtures();
    // The DB index is read once at load time, so a missing mirror errors there (before
    // any repo is scanned) — still an honest gap, never a clean scan.
    let err = GoDb::load(&f.join("nonexistent-db"))
        .expect_err("a missing DB index must error, not scan clean");

    // A+ error behavior: the variant carries the offending path AND preserves the
    // underlying I/O error as its source(), so callers can walk the chain.
    match &err {
        GoError::Db { path, source } => {
            assert!(path.ends_with("modules.json"));
            assert!(matches!(source, DbError::Read(_)));
        }
        other => panic!("expected GoError::Db, got {other:?}"),
    }
    assert!(
        err.source().is_some(),
        "GoError::Db must expose its underlying cause via source()"
    );
}

/// The osv.dev `Go` export (a folder of OSV records, or its `all.zip`) gives exactly what
/// the vuln.go.dev mirror gives: GHSA copies, withdrawn records and other ecosystems'
/// entries are ignored.
#[test]
fn the_osv_dev_export_matches_like_the_vuln_go_dev_mirror() {
    let export = std::env::temp_dir().join(format!("fleetreach-go-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&export);
    std::fs::create_dir_all(&export).unwrap();
    let mut records: Vec<(String, String)> = std::fs::read_dir(fixtures().join("db/ID"))
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    let ignored = |id: &str, extra: &str, eco: &str| {
        format!(
            r#"{{"id":"{id}",{extra}"affected":[{{"package":{{"name":"example.com/safe","ecosystem":"{eco}"}},
            "ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}}]}}]}}]}}"#
        )
    };
    records.push((
        "GHSA-test-0001.json".into(),
        ignored("GHSA-test-0001", "", "Go"),
    ));
    records.push((
        "GO-TEST-0009.json".into(),
        ignored(
            "GO-TEST-0009",
            r#""withdrawn":"2026-01-01T00:00:00Z","#,
            "Go",
        ),
    ));
    records.push((
        "GO-TEST-0010.json".into(),
        ignored("GO-TEST-0010", "", "npm"),
    ));
    records.sort();

    let dir = export.join("Go");
    std::fs::create_dir_all(&dir).unwrap();
    for (name, body) in &records {
        std::fs::write(dir.join(name), body).unwrap();
    }
    let zip_path = export.join("all.zip");
    {
        use std::io::Write;
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in &records {
            zip.start_file(name.as_str(), opts).unwrap();
            zip.write_all(body.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
    }

    let summary = |db: &GoDb| -> Vec<(String, String)> {
        scan_offline(&fixtures().join("repo"), db, &RepoId("app".into()))
            .unwrap()
            .iter()
            .map(|f| (f.advisory_id.clone(), format!("{:?}", f.occurrences)))
            .collect()
    };
    let expected = summary(&db());
    assert_eq!(expected.len(), 2);
    assert_eq!(
        summary(&GoDb::load(&dir).unwrap()),
        expected,
        "unzipped export"
    );
    assert_eq!(
        summary(&GoDb::load(&zip_path).unwrap()),
        expected,
        "all.zip"
    );

    // A corrupt record fails closed.
    std::fs::write(dir.join("GO-TEST-0011.json"), "{not json").unwrap();
    assert!(GoDb::load(&dir).is_err());
}

/// An export folder with no `GO-` record is a wrong path or a failed download: an error,
/// never an empty database that scans clean.
#[test]
fn an_empty_osv_export_is_an_error_not_a_clean_db() {
    let dir = std::env::temp_dir().join(format!("fleetreach-go-empty-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("GHSA-test-0001.json"), "{}").unwrap();
    assert!(GoDb::load(&dir).is_err());
}

/// Real-world regression found against osv-scanner on caddy 2.6: an advisory naming two
/// required modules reports both (GO-2024-2606 names pgx/v4 and pgproto3/v2). Also pinned:
/// a pseudo-version matches `introduced: 0`, and a pre-release of the introducing release is
/// flagged (the deliberate fail-loud bias; govulncheck does not flag it).
#[test]
fn every_named_module_is_reported() {
    let root = std::env::temp_dir().join(format!("fleetreach-go-multi-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let db_dir = root.join("Go");
    let repo = root.join("repo");
    std::fs::create_dir_all(&db_dir).unwrap();
    std::fs::create_dir_all(&repo).unwrap();
    let range = |name: &str, events: &str| {
        format!(
            r#"{{"package":{{"name":"{name}","ecosystem":"Go"}},"ranges":[{{"type":"SEMVER","events":{events}}}]}}"#
        )
    };
    std::fs::write(
        db_dir.join("GO-TEST-0100.json"),
        format!(
            r#"{{"id":"GO-TEST-0100","affected":[{},{}]}}"#,
            range(
                "example.com/pgproto3",
                r#"[{"introduced":"0"},{"fixed":"2.3.3"}]"#
            ),
            range(
                "example.com/pgx",
                r#"[{"introduced":"0"},{"fixed":"4.18.2"}]"#
            )
        ),
    )
    .unwrap();
    std::fs::write(
        db_dir.join("GO-TEST-0101.json"),
        format!(
            r#"{{"id":"GO-TEST-0101","affected":[{}]}}"#,
            range(
                "example.com/etcd",
                r#"[{"introduced":"3.5.0"},{"fixed":"3.5.30"}]"#
            )
        ),
    )
    .unwrap();
    std::fs::write(
        db_dir.join("GO-TEST-0102.json"),
        format!(
            r#"{{"id":"GO-TEST-0102","affected":[{}]}}"#,
            range(
                "example.com/pseudo",
                r#"[{"introduced":"0"},{"fixed":"0.1.0"}]"#
            )
        ),
    )
    .unwrap();
    std::fs::write(
        repo.join("go.mod"),
        "module example.com/app\n\ngo 1.21\n\nrequire (\n\texample.com/pgproto3 v2.2.0\n\
         \texample.com/pgx v4.14.0\n\texample.com/etcd v3.5.0-alpha.0\n\
         \texample.com/pseudo v0.0.0-20210101000000-abcdefabcdef\n)\n",
    )
    .unwrap();
    let db = GoDb::load(&db_dir).unwrap();
    let found: Vec<(String, String)> = scan_offline(&repo, &db, &RepoId("app".into()))
        .unwrap()
        .iter()
        .map(|f| match &f.occurrences[0] {
            Occurrence::InRepo { package, .. } => (f.advisory_id.clone(), package.clone()),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        found,
        [
            (
                "GO-TEST-0100".to_string(),
                "example.com/pgproto3".to_string()
            ),
            ("GO-TEST-0100".to_string(), "example.com/pgx".to_string()),
            ("GO-TEST-0101".to_string(), "example.com/etcd".to_string()),
            ("GO-TEST-0102".to_string(), "example.com/pseudo".to_string()),
        ]
    );
}

/// A record can list one module in several entries, one per release line (go-redis/v9 in
/// GO-2025-3540: 9.5.1-9.5.5, below 9.6.3, 9.7.0-beta.1-9.7.3). A version only a later entry
/// covers is affected, and its safe versions skip the other lines' vulnerable spans.
#[test]
fn every_entry_for_a_module_counts() {
    let root = std::env::temp_dir().join(format!("fleetreach-go-split-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let db_dir = root.join("Go");
    let repo = root.join("repo");
    std::fs::create_dir_all(&db_dir).unwrap();
    std::fs::create_dir_all(&repo).unwrap();
    let entry = |events: &str| {
        format!(
            r#"{{"package":{{"name":"example.com/redis/v9","ecosystem":"Go"}},"ranges":[{{"type":"SEMVER","events":{events}}}]}}"#
        )
    };
    std::fs::write(
        db_dir.join("GO-TEST-0200.json"),
        format!(
            r#"{{"id":"GO-TEST-0200","affected":[{},{},{}]}}"#,
            entry(r#"[{"introduced":"9.5.1"},{"fixed":"9.5.5"}]"#),
            entry(r#"[{"introduced":"0"},{"fixed":"9.6.3"}]"#),
            entry(r#"[{"introduced":"9.7.0-beta.1"},{"fixed":"9.7.3"}]"#)
        ),
    )
    .unwrap();
    std::fs::write(
        repo.join("go.mod"),
        "module example.com/app\n\ngo 1.21\n\nrequire example.com/redis/v9 v9.7.1\n",
    )
    .unwrap();
    let db = GoDb::load(&db_dir).unwrap();
    let found = scan_offline(&repo, &db, &RepoId("app".into())).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    let Occurrence::InRepo { patched, .. } = &found[0].occurrences[0] else {
        panic!("{found:?}");
    };
    let patched: Vec<String> = patched.iter().map(ToString::to_string).collect();
    assert_eq!(patched, [">=9.7.3"]);
}
