//! Black-box tests of the **compiled binary** — the contract users actually
//! depend on: exit codes (§8), stdout/stderr separation (§7), and each
//! subcommand flag. Library-level tests cover the pieces; these cover the
//! assembled whole. All offline (every run passes `--db`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Output;

use assert_cmd::Command;

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn db() -> String {
    manifest()
        .join("../scan/tests/fixtures/advisory-db")
        .to_string_lossy()
        .into_owned()
}

fn cfg(name: &str) -> String {
    manifest()
        .join("tests/fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

/// A `file://` URL for a fixtures subdirectory (the npm OSV mirror).
fn file_url(name: &str) -> String {
    format!(
        "file://{}",
        manifest().join("tests/fixtures").join(name).display()
    )
}

/// An empty, per-process cache root, so a developer's real `~/.cache/fleetreach/osv` can never
/// satisfy a test that expects a missing mirror.
fn empty_cache() -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("fleetreach-cli-test-cache-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run the binary hermetically: no OSV auto-sync, no inherited OSV directory, an empty cache.
fn run(args: &[&str]) -> Output {
    run_env(args, &[])
}

fn run_env(args: &[&str], env: &[(&str, &std::ffi::OsStr)]) -> Output {
    let mut cmd = Command::cargo_bin("fleetreach").unwrap();
    cmd.args(args)
        .env("FLEETREACH_OSV_SYNC", "off")
        .env("XDG_CACHE_HOME", empty_cache())
        .env_remove("FLEETREACH_OSV_DIR");
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.output().unwrap()
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ---- npm ecosystem (toolchain-free Tier-C) ----

#[test]
fn npm_repo_scans_against_osv_mirror() {
    // Auto-detected as npm from package-lock.json; lodash 4.17.20 is vulnerable.
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-npm.toml"),
        "--db",
        &db(),
        "--npm-vuln-db",
        &file_url("npm-osv"),
        "-f",
        "json",
        "-q",
    ]);
    assert_eq!(
        code(&out),
        1,
        "vuln found -> exit 1; stderr: {}",
        stderr(&out)
    );
    let value: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(value["summary"]["vuln_count"], 1);
    let vuln = &value["vulnerabilities"][0];
    assert_eq!(vuln["advisory_id"], "GHSA-p6mc-m468-83gw");
    assert_eq!(vuln["ecosystem"], "npm");
    assert_eq!(vuln["severity"], "high"); // mapped from the GHSA band
    assert_eq!(vuln["occurrences"][0]["package"], "lodash");
}

#[test]
fn bun_lock_is_read_like_any_npm_lockfile() {
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-bun.toml"),
        "--db",
        &db(),
        "--npm-vuln-db",
        &file_url("npm-osv"),
        "-f",
        "json",
        "-q",
    ]);
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
    let value: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(
        value["vulnerabilities"][0]["advisory_id"],
        "GHSA-p6mc-m468-83gw"
    );
    let occurrence = &value["vulnerabilities"][0]["occurrences"][0];
    assert_eq!(occurrence["package"], "lodash");
    assert_eq!(occurrence["dependency_kind"], "direct");
    assert!(
        value["coverage"].as_array().is_none_or(Vec::is_empty),
        "{}",
        value["coverage"]
    );
}

/// Lay out a temp OSV directory the way osv.dev's bucket does, with the npm fixture records
/// under `npm/`.
fn osv_dir_with_npm(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("fleetreach-osvdir-{tag}-{}", std::process::id()));
    let npm = root.join("npm");
    std::fs::create_dir_all(&npm).unwrap();
    for entry in std::fs::read_dir(manifest().join("tests/fixtures/npm-osv")).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), npm.join(entry.file_name())).unwrap();
    }
    root
}

#[test]
fn osv_dir_serves_the_npm_export_without_a_per_ecosystem_flag() {
    let dir = osv_dir_with_npm("flag");
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-npm.toml"),
        "--db",
        &db(),
        "--osv-dir",
        dir.to_str().unwrap(),
        "-f",
        "json",
        "-q",
    ]);
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
    let value: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(
        value["vulnerabilities"][0]["advisory_id"],
        "GHSA-p6mc-m468-83gw"
    );
    let osv = &value["provenance"]["osv"][0];
    assert_eq!(osv["ecosystem"], "npm");
    assert_eq!(osv["source"], "dir");
    assert_eq!(osv["age_basis"], "mtime");
}

#[test]
fn osv_dir_from_env_and_the_default_cache_are_used() {
    let dir = osv_dir_with_npm("env");
    let out = run_env(
        &["scan", "-c", &cfg("fleet-npm.toml"), "--db", &db(), "-q"],
        &[("FLEETREACH_OSV_DIR", dir.as_os_str())],
    );
    assert_eq!(code(&out), 1, "env dir: stderr: {}", stderr(&out));

    // The same layout as the default cache root (`$XDG_CACHE_HOME/fleetreach/osv`).
    let cache = std::env::temp_dir().join(format!("fleetreach-xdg-{}", std::process::id()));
    let osv = cache.join("fleetreach").join("osv");
    std::fs::create_dir_all(&osv).unwrap();
    let _ = std::fs::remove_dir_all(osv.join("npm"));
    std::fs::rename(dir.join("npm"), osv.join("npm")).unwrap();
    let out = run_env(
        &["scan", "-c", &cfg("fleet-npm.toml"), "--db", &db(), "-q"],
        &[("XDG_CACHE_HOME", cache.as_os_str())],
    );
    assert_eq!(code(&out), 1, "cache: stderr: {}", stderr(&out));
}

#[test]
fn missing_osv_export_names_the_fix() {
    let out = run(&["scan", "-c", &cfg("fleet-npm.toml"), "--db", &db()]);
    assert_eq!(code(&out), 2);
    assert!(
        stderr(&out).contains("fleetreach db sync"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn db_status_lists_every_osv_ecosystem() {
    let dir = osv_dir_with_npm("status");
    let out = run(&["db", "status", "--osv-dir", dir.to_str().unwrap()]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("npm") && text.contains("present"), "{text}");
    assert!(text.contains("PyPI") && text.contains("missing"), "{text}");
}

#[test]
fn npm_repo_without_a_mirror_is_an_honest_gap() {
    // No --npm-vuln-db: the npm repo errors (a gap), forcing exit 2 — never clean.
    let out = run(&["scan", "-c", &cfg("fleet-npm.toml"), "--db", &db()]);
    assert_eq!(
        code(&out),
        2,
        "a gap must not be reported clean; stderr: {}",
        stderr(&out)
    );
}

#[test]
fn polyglot_repo_scans_every_ecosystem_and_nested_lockfiles() {
    // `polyglot` has a root Cargo.lock and an npm lockfile in `web/`; `npm-nested` has its
    // only lockfile below the root (the vscode shape). Root-only, first-match detection
    // scanned just the Cargo.lock and called `npm-nested` a Rust repo with nothing in it.
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-polyglot.toml"),
        "--db",
        &db(),
        "--npm-vuln-db",
        &file_url("npm-osv"),
        "-f",
        "json",
        "-q",
    ]);
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
    let value: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(value["summary"]["repos_errored"], 0, "{value}");
    let hits: Vec<(String, String)> = value["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| {
            v["occurrences"].as_array().unwrap().iter().map(|o| {
                (
                    o["repo"].as_str().unwrap().to_string(),
                    o["package"].as_str().unwrap().to_string(),
                )
            })
        })
        .collect();
    assert!(
        hits.contains(&("polyglot".into(), "lodash".into())),
        "{hits:?}"
    );
    assert!(
        hits.contains(&("npm-nested".into(), "lodash".into())),
        "{hits:?}"
    );
    assert!(
        hits.iter().any(|(r, p)| r == "polyglot" && p != "lodash"),
        "the root Cargo.lock is still scanned: {hits:?}"
    );
    // `.flox/env/manifest.toml` (Flox, lowercase) is not a Julia `Manifest.toml`, even on a
    // case-insensitive filesystem; misdetecting it would error the repo (no Julia mirror).
    // yarn.lock is read now (spec 02); the binary bun.lockb is named, not silently skipped.
    let err = stderr(&out);
    assert!(err.contains("polyglot: legacy-bun/bun.lockb"), "{err}");
    assert!(!err.contains("yarn.lock"), "{err}");
}

#[test]
fn yarn_and_pnpm_repos_scan_without_package_lock() {
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-js.toml"),
        "--db",
        &db(),
        "--npm-vuln-db",
        &file_url("npm-osv"),
        "-f",
        "json",
        "-q",
    ]);
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
    let value: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(value["summary"]["repos_errored"], 0, "{value}");
    assert!(value.get("coverage").is_none(), "{value}");
    let occ: Vec<&serde_json::Value> = value["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| v["occurrences"].as_array().unwrap())
        .collect();
    let find = |repo: &str| {
        occ.iter()
            .find(|o| o["repo"] == repo && o["package"] == "lodash")
            .unwrap_or_else(|| panic!("no lodash hit in {repo}: {occ:?}"))
    };
    assert_eq!(find("yarn-app")["dependency_kind"], "direct");
    // In pnpm-app lodash is a devDependency: still found, and labelled dev.
    assert_eq!(find("pnpm-app")["scope"], "dev");
}

#[test]
fn requirements_and_pylock_repos_scan_with_coverage_labels() {
    let args = |extra: &[&'static str]| {
        let mut v = vec![
            "scan".to_string(),
            "-c".into(),
            cfg("fleet-py.toml"),
            "--db".into(),
            db(),
            "--pypi-vuln-db".into(),
            file_url("pypi-osv"),
            "-f".into(),
            "json".into(),
            "-q".into(),
        ];
        v.extend(extra.iter().map(|s| (*s).to_string()));
        v
    };
    let argv = args(&[]);
    let out = run(&argv.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
    let value: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(value["summary"]["repos_errored"], 0, "{value}");
    let occ: Vec<&serde_json::Value> = value["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| v["occurrences"].as_array().unwrap())
        .collect();
    let find = |repo: &str| {
        occ.iter()
            .find(|o| o["repo"] == repo && o["package"] == "jinja2")
            .unwrap_or_else(|| panic!("no jinja2 hit in {repo}: {occ:?}"))
    };
    // pip-compile's `# via` annotations give the introducer chain.
    let req = find("py-req");
    assert_eq!(req["dependency_kind"], "transitive");
    assert_eq!(
        req["dependency_path"],
        serde_json::json!(["(root)", "flask", "jinja2"])
    );
    assert_eq!(find("py-pylock")["installed"], "3.1.4");

    // The compiled requirements.txt and pylock.toml are full; the dev file's unpinned
    // `pytest` is named, and gates under --require-full-coverage.
    let coverage = value["coverage"].as_array().unwrap();
    assert_eq!(coverage.len(), 1, "{coverage:?}");
    assert_eq!(coverage[0]["source"], "requirements-dev.txt");
    assert_eq!(coverage[0]["level"], "direct-only");
    assert!(coverage[0]["reason"].as_str().unwrap().contains("pytest"));
    let argv = args(&["--require-full-coverage"]);
    let out = run(&argv.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
}

#[test]
fn dotnet_repos_without_a_lockfile_scan_with_coverage_labels() {
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-dotnet.toml"),
        "--db",
        &db(),
        "--nuget-vuln-db",
        &file_url("nuget-osv"),
        "-f",
        "json",
        "-q",
    ]);
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
    let value: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(value["summary"]["repos_errored"], 0, "{value}");
    let occ: Vec<&serde_json::Value> = value["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| v["occurrences"].as_array().unwrap())
        .collect();
    let find = |repo: &str| {
        occ.iter()
            .find(|o| o["repo"] == repo && o["package"] == "newtonsoft.json")
            .unwrap_or_else(|| panic!("no newtonsoft.json hit in {repo}: {occ:?}"))
    };
    // Central package management, with the version from a property.
    assert_eq!(find("dotnet-cpm")["installed"], "12.0.1");
    // Restore output: transitive, with its chain.
    let restored = find("dotnet-restored");
    assert_eq!(restored["dependency_kind"], "transitive");
    assert_eq!(
        restored["dependency_path"],
        serde_json::json!(["(root)", "contoso.wrapper", "newtonsoft.json"])
    );
    assert_eq!(find("dotnet-config")["installed"], "9.0.1");

    let coverage: Vec<(String, String, String)> = value["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["repo"].as_str().unwrap().to_string(),
                c["source"].as_str().unwrap().to_string(),
                c["level"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        coverage,
        vec![
            (
                "dotnet-cpm".into(),
                "App.csproj".into(),
                "direct-only".into()
            ),
            (
                "dotnet-restored".into(),
                "obj/project.assets.json".into(),
                "partial".into()
            ),
        ]
    );
    let reasons: String = value["coverage"].to_string();
    assert!(
        reasons.contains("serilog"),
        "the range-versioned package is named: {reasons}"
    );
    assert!(
        reasons.contains("added.later"),
        "the unrestored package is named: {reasons}"
    );
}

#[test]
fn sbom_writes_one_deterministic_cyclonedx_bom_per_repo() {
    let out_dir = std::env::temp_dir().join(format!("fleetreach-sbom-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out_dir);
    let sbom = || {
        run_env(
            &[
                "sbom",
                "-q",
                "-c",
                &cfg("fleet-dotnet.toml"),
                "-o",
                out_dir.to_str().unwrap(),
            ],
            &[("SOURCE_DATE_EPOCH", std::ffi::OsStr::new("1793404800"))],
        )
    };
    let out = sbom();
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let read =
        |repo: &str| std::fs::read_to_string(out_dir.join(format!("{repo}.cdx.json"))).unwrap();
    let first = read("dotnet-restored");
    let bom: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(bom["bomFormat"], "CycloneDX");
    assert_eq!(bom["specVersion"], "1.6");
    assert_eq!(bom["metadata"]["timestamp"], "2026-10-31T00:00:00Z");
    let purls: Vec<&str> = bom["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["purl"].as_str().unwrap())
        .collect();
    assert_eq!(
        purls,
        vec![
            "pkg:nuget/contoso.wrapper@1.0.0",
            "pkg:nuget/newtonsoft.json@12.0.1"
        ]
    );
    // The restore output is older than the project file, so the BOM says it is incomplete.
    assert_eq!(bom["compositions"][0]["aggregate"], "incomplete", "{bom}");
    let deps = bom["dependencies"].as_array().unwrap();
    let wrapper = deps
        .iter()
        .find(|d| d["ref"] == "pkg:nuget/contoso.wrapper@1.0.0")
        .unwrap();
    assert_eq!(
        wrapper["dependsOn"],
        serde_json::json!(["pkg:nuget/newtonsoft.json@12.0.1"])
    );
    // packages.config is a full inventory.
    let config: serde_json::Value = serde_json::from_str(&read("dotnet-config")).unwrap();
    assert_eq!(
        config["compositions"][0]["aggregate"], "complete",
        "{config}"
    );

    // Byte-identical on a second run.
    assert_eq!(code(&sbom()), 0);
    assert_eq!(read("dotnet-restored"), first);
}

#[test]
fn sbom_embeds_a_saved_scans_findings_in_both_formats() {
    let tmp = std::env::temp_dir().join(format!("fleetreach-sbom-vulns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let scan = run(&[
        "scan",
        "-q",
        "-c",
        &cfg("fleet-vuln.toml"),
        "--db",
        &db(),
        "-f",
        "json",
    ]);
    let mut report: serde_json::Value = serde_json::from_str(&stdout(&scan)).unwrap();
    let report_path = tmp.join("report.json");
    let sbom = |format: &str, report: &serde_json::Value| {
        std::fs::write(&report_path, report.to_string()).unwrap();
        let out = run(&[
            "sbom",
            "-q",
            "-c",
            &cfg("fleet-vuln.toml"),
            "-o",
            tmp.to_str().unwrap(),
            "-f",
            format,
            "--report",
            report_path.to_str().unwrap(),
        ]);
        assert_eq!(code(&out), 0, "{}", stderr(&out));
        let ext = if format == "spdx" { "spdx" } else { "cdx" };
        let text = std::fs::read_to_string(tmp.join(format!("app.{ext}.json"))).unwrap();
        serde_json::from_str::<serde_json::Value>(&text).unwrap()
    };

    let bom = sbom("cyclonedx", &report);
    let vuln = &bom["vulnerabilities"][0];
    assert_eq!(vuln["id"], "RUSTSEC-2099-0001");
    assert_eq!(vuln["affects"][0]["ref"], "pkg:cargo/fixturevuln@1.0.0");
    assert_eq!(vuln["ratings"][0]["score"], 9.8);
    assert_eq!(vuln["ratings"][0]["severity"], "critical");
    assert_eq!(vuln["analysis"]["state"], "in_triage");

    let spdx = sbom("spdx", &report);
    let package = spdx["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "fixturevuln")
        .unwrap();
    let advisory = package["externalRefs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["referenceType"] == "advisory")
        .unwrap();
    assert_eq!(advisory["referenceCategory"], "SECURITY");
    assert!(
        advisory["comment"]
            .as_str()
            .unwrap()
            .starts_with("RUSTSEC-2099-0001: in triage"),
        "{advisory}"
    );

    // A sound static verdict is the only way to `not_affected`.
    report["vulnerabilities"][0]["reachability"] = serde_json::json!({
        "verdict": { "kind": "not_reachable" },
        "config": "default",
        "engine": "test",
        "targets": [],
    });
    let bom = sbom("cyclonedx", &report);
    let analysis = &bom["vulnerabilities"][0]["analysis"];
    assert_eq!(analysis["state"], "not_affected");
    assert_eq!(analysis["justification"], "code_not_reachable");
}

#[test]
fn sbom_of_an_unreadable_source_exits_2() {
    let out_dir =
        std::env::temp_dir().join(format!("fleetreach-sbom-errored-{}", std::process::id()));
    let out = run(&[
        "sbom",
        "-q",
        "-c",
        &cfg("fleet-errored.toml"),
        "-o",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("could not be read in full"),
        "{}",
        stderr(&out)
    );
}

/// Run `git` in `dir` for the fix tests, with a fixed identity and no global config.
fn git_in(dir: &std::path::Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn fix_plans_applies_and_verifies_a_lock_bump_on_a_branch() {
    let root = std::env::temp_dir().join(format!("fleetreach-fix-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let repo = root.join("ci-repo");
    let workflows = repo.join(".github/workflows");
    std::fs::create_dir_all(&workflows).unwrap();
    let workflow = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      \
                    - uses: actions/checkout@v4\n      - uses: tj-actions/changed-files@v44\n";
    std::fs::write(workflows.join("ci.yml"), workflow).unwrap();
    git_in(&repo, &["init", "-q", "-b", "main"]);
    git_in(&repo, &["add", "-A"]);
    git_in(&repo, &["commit", "-q", "-m", "init"]);
    let fleet = root.join("fleet.toml");
    std::fs::write(
        &fleet,
        format!("[[repo]]\nid = \"ci-repo\"\npath = {:?}\n", repo),
    )
    .unwrap();
    let fleet = fleet.to_str().unwrap().to_string();
    let osv = file_url("ghactions-osv");
    let db = db();
    let env: Vec<(&str, &std::ffi::OsStr)> = vec![
        ("GIT_CONFIG_GLOBAL", std::ffi::OsStr::new("/dev/null")),
        ("GIT_AUTHOR_NAME", std::ffi::OsStr::new("t")),
        ("GIT_AUTHOR_EMAIL", std::ffi::OsStr::new("t@example.com")),
        ("GIT_COMMITTER_NAME", std::ffi::OsStr::new("t")),
        ("GIT_COMMITTER_EMAIL", std::ffi::OsStr::new("t@example.com")),
        ("XDG_CACHE_HOME", root.as_os_str()),
    ];

    // 1. Scan: the vulnerable tag is found.
    let out = run_env(
        &[
            "scan",
            "-q",
            "-c",
            &fleet,
            "--db",
            &db,
            "--ghactions-vuln-db",
            &osv,
            "-f",
            "json",
        ],
        &env,
    );
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
    let report = root.join("report.json");
    std::fs::write(&report, stdout(&out)).unwrap();

    // 2. Plan. v44 -> v46.0.1 is a major jump: blocked unless breaking bumps are allowed.
    let plan_with = |extra: &[&str]| {
        let mut argv = vec![
            "fix",
            "plan",
            "-c",
            &fleet,
            "--report",
            report.to_str().unwrap(),
        ];
        argv.extend_from_slice(extra);
        run_env(&argv, &env)
    };
    let out = plan_with(&[]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let plan: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(plan["edits"][0]["strategy"], "blocked", "{plan}");
    assert!(plan["edits"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("--allow-breaking"));
    let out = plan_with(&["--allow-breaking"]);
    let plan: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let edit = &plan["edits"][0];
    assert_eq!(edit["strategy"], "lock-bump", "{plan}");
    assert_eq!(edit["breaking"], true);
    assert_eq!(edit["package"], "tj-actions/changed-files");
    assert_eq!(edit["to"], "46.0.1");
    let plan_path = root.join("plan.json");
    std::fs::write(&plan_path, stdout(&out)).unwrap();

    // 3. Apply: verified by the re-scan, on its own branch.
    let out = run_env(
        &[
            "fix",
            "apply",
            "-q",
            "-c",
            &fleet,
            plan_path.to_str().unwrap(),
            "--",
            "--db",
            &db,
            "--ghactions-vuln-db",
            &osv,
        ],
        &env,
    );
    assert_eq!(
        code(&out),
        0,
        "stderr: {}\nstdout: {}",
        stderr(&out),
        stdout(&out)
    );
    let applied: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(applied[0]["outcome"], "verified", "{applied}");
    let branch = applied[0]["branch"].as_str().unwrap().to_string();
    assert!(
        branch.starts_with("fleetreach/") && branch.ends_with("/tj-actions-changed-files-46.0.1")
    );

    // The branch holds the fixed tag; the user's work tree and main are untouched.
    let fixed = git_in(
        &repo,
        &["show", &format!("{branch}:.github/workflows/ci.yml")],
    );
    assert!(
        fixed.contains("tj-actions/changed-files@v46.0.1"),
        "{fixed}"
    );
    assert!(fixed.contains("actions/checkout@v4"));
    assert_eq!(
        std::fs::read_to_string(workflows.join("ci.yml")).unwrap(),
        workflow
    );
    assert_eq!(
        git_in(&repo, &["rev-parse", "--abbrev-ref", "HEAD"]),
        "main"
    );
    assert!(git_in(&repo, &["status", "--porcelain"]).is_empty());
    let message = git_in(&repo, &["log", "-1", "--format=%B", &branch]);
    assert!(
        message.contains("Verified by a fleetreach re-scan"),
        "{message}"
    );
    assert!(!message.to_lowercase().contains("co-authored"), "{message}");

    // 4. GitLab: push to `origin` and open a merge request with `glab` (a fake one here that
    // records its arguments), then update it on a second run, and list it.
    let origin = root.join("origin.git");
    git_in(&root, &["init", "-q", "--bare", origin.to_str().unwrap()]);
    git_in(
        &repo,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let glab = bin.join("glab");
    std::fs::write(
        &glab,
        r#"#!/bin/sh
echo "$*" >> "$FAKE_GLAB_LOG"
case "$1 $2" in
  "mr list") cat "$FAKE_GLAB_STATE" 2>/dev/null || echo '[]' ;;
  "mr create")
    while [ $# -gt 0 ]; do [ "$1" = "--source-branch" ] && b="$2"; shift; done
    printf '[{"iid":7,"web_url":"https://gitlab.example/acme/ci-repo/-/merge_requests/7","source_branch":"%s","state":"opened","title":"t"}]' "$b" > "$FAKE_GLAB_STATE"
    echo "!7 created" ;;
esac
"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&glab, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let log = root.join("glab.log");
    let state = root.join("glab.json");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut gl_env = env.clone();
    gl_env.push(("PATH", std::ffi::OsStr::new(&path)));
    gl_env.push(("FAKE_GLAB_LOG", log.as_os_str()));
    gl_env.push(("FAKE_GLAB_STATE", state.as_os_str()));
    let open_mr = || {
        let out = run_env(
            &[
                "fix",
                "apply",
                "-q",
                "-c",
                &fleet,
                plan_path.to_str().unwrap(),
                "--open-pr",
                "--forge",
                "gitlab",
                "--",
                "--db",
                &db,
                "--ghactions-vuln-db",
                &osv,
            ],
            &gl_env,
        );
        assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
        let applied: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
        applied[0].clone()
    };
    let first = open_mr();
    assert!(
        first["detail"]
            .as_str()
            .unwrap()
            .ends_with("pushed; merge request opened"),
        "{first}"
    );
    assert_eq!(
        first["pull_request"],
        "https://gitlab.example/acme/ci-repo/-/merge_requests/7"
    );
    assert_eq!(
        git_in(&origin, &["rev-parse", &branch]),
        git_in(&repo, &["rev-parse", &branch])
    );
    let second = open_mr();
    assert!(
        second["detail"]
            .as_str()
            .unwrap()
            .ends_with("merge request updated"),
        "{second}"
    );
    let calls = std::fs::read_to_string(&log).unwrap();
    assert!(
        calls.contains(&format!("mr create --source-branch {branch} --title")),
        "{calls}"
    );
    assert!(calls.contains("mr update 7 --title"), "{calls}");
    assert!(calls.contains("--yes"), "{calls}");

    let out = run_env(
        &["fix", "status", "-c", &fleet, "--forge", "gitlab"],
        &gl_env,
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let rows: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(rows[0]["state"], "OPEN", "{rows}");
    assert_eq!(rows[0]["forge"], "gitlab");
    assert_eq!(rows[0]["branch"], branch.as_str());
}

#[test]
fn licenses_inventory_and_policy_violations() {
    let out = run(&["licenses", "-c", &cfg("fleet-licenses.toml"), "-f", "json"]);
    assert_eq!(code(&out), 1, "a denied license exits 1: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["policy"], true);
    let by_pkg = |pkg: &str| {
        v["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["package"] == pkg)
            .unwrap_or_else(|| panic!("no {pkg}"))
            .clone()
    };
    // From composer.lock and package-lock.json, with where each came from.
    assert_eq!(by_pkg("monolog/monolog")["license"], "MIT");
    assert_eq!(by_pkg("monolog/monolog")["source"], "composer.lock");
    assert_eq!(by_pkg("monolog/monolog")["verdict"], "allow");
    assert_eq!(by_pkg("left-pad")["source"], "package-lock.json");
    // `WTFPL OR MIT` passes through its MIT side; `AGPL OR MIT` (a composer list) too.
    assert_eq!(by_pkg("left-pad")["verdict"], "allow");
    assert_eq!(by_pkg("acme/dual")["license"], "AGPL-3.0-only OR MIT");
    assert_eq!(by_pkg("acme/dual")["verdict"], "allow");
    // Forbidden denied, restricted warned, unknown denied (fail closed).
    assert_eq!(by_pkg("acme/agpl-lib")["verdict"], "deny");
    assert_eq!(by_pkg("acme/agpl-lib")["category"], "forbidden");
    assert_eq!(by_pkg("acme/gpl-lib")["verdict"], "warn");
    assert_eq!(by_pkg("mystery")["verdict"], "deny");
    assert!(by_pkg("mystery")["reason"]
        .as_str()
        .unwrap()
        .contains("no license found"));
    // Dev-only packages are out of a runtime-scoped policy.
    assert_eq!(by_pkg("phpunit/phpunit")["dev"], true);
    assert_eq!(by_pkg("phpunit/phpunit")["verdict"], "allow");
    let mut denied: Vec<&str> = v["violations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["package"].as_str().unwrap())
        .collect();
    denied.sort_unstable();
    assert_eq!(denied, vec!["acme/agpl-lib", "mystery"]);

    // The SBOM carries the same licenses.
    let out_dir = std::env::temp_dir().join(format!("fleetreach-lic-sbom-{}", std::process::id()));
    let out = run(&[
        "sbom",
        "-q",
        "-c",
        &cfg("fleet-licenses.toml"),
        "-o",
        out_dir.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let bom: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out_dir.join("lic-app.cdx.json")).unwrap())
            .unwrap();
    let dual = bom["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "acme/dual")
        .unwrap();
    assert_eq!(dual["licenses"][0]["expression"], "AGPL-3.0-only OR MIT");
}

#[test]
fn license_policy_rejects_unknown_ids() {
    let path = temp_fleet(
        "lic-bad",
        "[[repo]]\nid = \"a\"\npath = \".\"\n[settings.licenses]\nallow = [\"MIT\", \"NotALicense\"]\n",
    );
    let out = run(&["licenses", "-c", path.to_str().unwrap()]);
    assert_eq!(code(&out), 2);
    assert!(
        stderr(&out).contains("`NotALicense` is not an SPDX license id"),
        "{}",
        stderr(&out)
    );
}

/// `(advisory, repo, package, version, path)` of every finding in a JSON report.
fn finding_keys(report: &serde_json::Value) -> Vec<(String, String, String, String, String)> {
    let mut keys: Vec<_> = report["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| {
            v["occurrences"].as_array().unwrap().iter().map(move |o| {
                (
                    v["advisory_id"].as_str().unwrap().to_string(),
                    o["repo"].as_str().unwrap().to_string(),
                    o["package"].as_str().unwrap().to_string(),
                    o["installed"].as_str().unwrap().to_string(),
                    o["dependency_path"].to_string(),
                )
            })
        })
        .collect();
    keys.sort();
    keys
}

#[test]
fn an_sbom_written_by_fleetreach_scans_back_to_the_same_findings() {
    for ((fleet, repo, flag, osv), (format, ext)) in [
        ("fleet-py.toml", "py-req", "--pypi-vuln-db", "pypi-osv"),
        (
            "fleet-dotnet.toml",
            "dotnet-restored",
            "--nuget-vuln-db",
            "nuget-osv",
        ),
    ]
    .into_iter()
    .flat_map(|case| [(case, ("cyclonedx", "cdx")), (case, ("spdx", "spdx"))])
    {
        let tmp = std::env::temp_dir().join(format!(
            "fleetreach-sbom-in-{repo}-{ext}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // 1. Scan the lockfiles directly, and write the SBOM.
        let direct = run(&[
            "scan",
            "-q",
            "-c",
            &cfg(fleet),
            "--db",
            &db(),
            flag,
            &file_url(osv),
            "-f",
            "json",
        ]);
        let direct: serde_json::Value = serde_json::from_str(&stdout(&direct)).unwrap();
        let out = run(&[
            "sbom",
            "-q",
            "-c",
            &cfg(fleet),
            "-o",
            tmp.to_str().unwrap(),
            "-f",
            format,
        ]);
        assert_eq!(code(&out), 0, "{}", stderr(&out));
        // 2. Scan the SBOM instead.
        let repo_path = manifest().join("tests/fixtures/repos").join(repo);
        let bom = tmp.join(format!("{repo}.{ext}.json"));
        let fleet_from_sbom = tmp.join("fleet.toml");
        std::fs::write(
            &fleet_from_sbom,
            format!("[[repo]]\nid = {repo:?}\npath = {repo_path:?}\nsbom = {bom:?}\n"),
        )
        .unwrap();
        let from_sbom = run(&[
            "scan",
            "-q",
            "-c",
            fleet_from_sbom.to_str().unwrap(),
            "--db",
            &db(),
            flag,
            &file_url(osv),
            "-f",
            "json",
        ]);
        let from_sbom: serde_json::Value = serde_json::from_str(&stdout(&from_sbom)).unwrap();
        let want: Vec<_> = finding_keys(&direct)
            .into_iter()
            .filter(|k| k.1 == repo)
            .collect();
        assert!(
            !want.is_empty(),
            "{repo}: the direct scan should find something"
        );
        assert_eq!(
            finding_keys(&from_sbom),
            want,
            "{repo}: {format} round trip"
        );
    }
}

#[test]
fn incomplete_coverage_is_reported_and_can_gate() {
    let args = |extra: &[&'static str]| {
        let mut v = vec![
            "scan".to_string(),
            "-c".into(),
            cfg("fleet-polyglot.toml"),
            "--db".into(),
            db(),
            "--npm-vuln-db".into(),
            file_url("npm-osv"),
            "-f".into(),
            "json".into(),
        ];
        v.extend(extra.iter().map(|s| s.to_string()));
        v
    };
    let plain = args(&[]);
    let out = run(&plain.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(
        code(&out),
        1,
        "a coverage gap alone does not gate by default"
    );
    let value: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let gap = value["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["source"] == "legacy-bun/bun.lockb")
        .unwrap_or_else(|| panic!("{}", value["coverage"]));
    assert_eq!(gap["repo"], "polyglot");
    assert_eq!(gap["level"], "partial");
    assert!(
        stderr(&out).contains("Incomplete coverage"),
        "{}",
        stderr(&out)
    );

    let gated = args(&["--require-full-coverage"]);
    let out = run(&gated.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
}

#[test]
fn dev_only_finding_is_marked_and_can_be_ignored() {
    let base = |extra: &[&str]| {
        let mut args = vec!["scan", "-c"];
        let c = cfg("fleet-npm-dev.toml");
        let d = db();
        let u = file_url("npm-osv");
        args.extend_from_slice(&[&c, "--db", &d, "--npm-vuln-db", &u]);
        args.extend_from_slice(extra);
        run(&args)
    };
    let out = base(&["-f", "json", "-q"]);
    assert_eq!(
        code(&out),
        1,
        "a dev finding still gates by default: {}",
        stderr(&out)
    );
    let value: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(
        value["vulnerabilities"][0]["occurrences"][0]["scope"],
        "dev"
    );

    let table = stdout(&base(&[]));
    assert!(table.contains("(dev only)"), "{table}");

    let out = base(&["--ignore-dev-deps"]);
    assert_eq!(code(&out), 0, "dropped -> clean; stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("dev/build-only"), "{}", stderr(&out));
}

#[test]
fn nested_lockfile_without_glob_is_an_honest_gap() {
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-npm-nested-noglob.toml"),
        "--db",
        &db(),
        "--npm-vuln-db",
        &file_url("npm-osv"),
    ]);
    assert_eq!(code(&out), 2, "never clean; stderr: {}", stderr(&out));
}

// ---- `diff` subcommand ----

#[test]
fn diff_gates_on_new_finding_and_reports_buckets() {
    // curr adds a new critical and clears one advisory -> exit 1, both buckets shown.
    let out = run(&["diff", &cfg("diff-base.json"), &cfg("diff-curr.json")]);
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
    let table = stdout(&out);
    assert!(table.contains("1 new, 1 fixed, 1 still open."), "{table}");
    assert!(
        table.contains("RUSTSEC-2026-9999"),
        "new advisory listed: {table}"
    );
    assert!(
        table.contains("RUSTSEC-2021-0001"),
        "fixed advisory listed: {table}"
    );
}

#[test]
fn diff_json_is_machine_readable() {
    let out = run(&[
        "diff",
        &cfg("diff-base.json"),
        &cfg("diff-curr.json"),
        "-f",
        "json",
    ]);
    let value: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(value["new"][0]["advisory_id"], "RUSTSEC-2026-9999");
    assert_eq!(value["fixed"][0]["advisory_id"], "RUSTSEC-2021-0001");
    assert_eq!(value["still_open"][0]["advisory_id"], "RUSTSEC-2021-0002");
    // The surviving advisory lost a repo since the baseline.
    assert_eq!(value["still_open"][0]["repos_removed"][0], "app-b");
}

#[test]
fn diff_fail_on_filters_below_floor() {
    // The only new finding is critical, so a `--fail-on high` floor still gates.
    let out = run(&[
        "diff",
        &cfg("diff-base.json"),
        &cfg("diff-curr.json"),
        "--fail-on",
        "high",
    ]);
    assert_eq!(code(&out), 1);
    // Same inputs, but report-only: never gate.
    let out = run(&[
        "diff",
        &cfg("diff-base.json"),
        &cfg("diff-curr.json"),
        "--exit-zero",
    ]);
    assert_eq!(code(&out), 0);
}

#[test]
fn diff_identical_reports_exit_zero() {
    let out = run(&["diff", &cfg("diff-base.json"), &cfg("diff-base.json")]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("No advisories appeared or cleared."));
}

#[test]
fn diff_unreadable_file_exits_two() {
    let out = run(&["diff", &cfg("does-not-exist.json"), &cfg("diff-base.json")]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("reading report"));
}

// ---- exit-code contract ----

#[test]
fn clean_fleet_exits_zero() {
    let out = run(&["scan", "-c", &cfg("fleet-clean.toml"), "--db", &db()]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
}

#[test]
fn vuln_exits_one() {
    let out = run(&["scan", "-c", &cfg("fleet-vuln.toml"), "--db", &db()]);
    assert_eq!(code(&out), 1);
}

#[test]
fn errored_repo_exits_two_even_with_a_finding() {
    let out = run(&["scan", "-c", &cfg("fleet-errored.toml"), "--db", &db()]);
    assert_eq!(
        code(&out),
        2,
        "a gap must never be reported as clean or merely failing"
    );
}

#[test]
fn missing_config_exits_two() {
    let out = run(&["scan", "-c", &cfg("does-not-exist.toml"), "--db", &db()]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("error"));
}

#[test]
fn usage_error_exits_three() {
    let out = run(&["scan", "--no-such-flag"]);
    assert_eq!(code(&out), 3);
}

#[test]
fn help_exits_zero() {
    let out = run(&["--help"]);
    assert_eq!(code(&out), 0);
}

// ---- stream routing (§7) ----

#[test]
fn json_payload_on_stdout_summary_on_stderr() {
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-vuln.toml"),
        "--db",
        &db(),
        "-f",
        "json",
    ]);
    // stdout is the machine payload — and only that, so `| jq` stays clean.
    let value: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("stdout must be valid JSON");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["summary"]["vuln_count"], 1);
    // human summary goes to stderr.
    assert!(stderr(&out).contains("Scanned"));
    // never color/escape codes in piped output.
    assert!(!stdout(&out).contains('\u{1b}'));
}

#[test]
fn piped_table_is_never_colored() {
    // stdout here is a pipe, not a TTY, so the table must be ANSI-free.
    let out = run(&["scan", "-c", &cfg("fleet-vuln.toml"), "--db", &db()]);
    assert!(!stdout(&out).contains('\u{1b}'));
}

#[test]
fn two_runs_are_byte_identical_modulo_the_clock() {
    // Determinism (§13): same lockfiles + same DB -> identical JSON, except the
    // one wall-clock field (generated_at), which we normalize away.
    let args = &[
        "scan",
        "-c",
        &cfg("fleet-vuln.toml"),
        "--db",
        &db(),
        "-f",
        "json",
        "-q",
    ];
    let mut a: serde_json::Value = serde_json::from_str(&stdout(&run(args))).unwrap();
    let mut b: serde_json::Value = serde_json::from_str(&stdout(&run(args))).unwrap();
    a["provenance"]["generated_at"] = serde_json::Value::Null;
    b["provenance"]["generated_at"] = serde_json::Value::Null;
    assert_eq!(a, b, "runs must be deterministic apart from the clock");
}

#[test]
fn quiet_suppresses_the_summary_line() {
    let out = run(&["scan", "-c", &cfg("fleet-clean.toml"), "--db", &db(), "-q"]);
    assert_eq!(code(&out), 0);
    assert!(stderr(&out).trim().is_empty(), "stderr: {:?}", stderr(&out));
}

// ---- inspection subcommands ----

#[test]
fn explain_prints_detail_and_exits_zero() {
    let out = run(&["scan", "--db", &db(), "--explain", "RUSTSEC-2099-0001"]);
    assert_eq!(code(&out), 0);
    let text = stdout(&out);
    assert!(text.contains("RUSTSEC-2099-0001"));
    assert!(text.contains("Fixture vulnerability in fixturevuln"));
}

#[test]
fn explain_unknown_advisory_exits_two() {
    let out = run(&["scan", "--db", &db(), "--explain", "RUSTSEC-2098-0001"]);
    assert_eq!(code(&out), 2);
}

// ---- baseline diff ----

#[test]
fn baseline_suppresses_known_findings() {
    // Capture the current report as a baseline...
    let baseline = run(&[
        "scan",
        "-c",
        &cfg("fleet-vuln.toml"),
        "--db",
        &db(),
        "-f",
        "json",
        "-q",
    ]);
    assert_eq!(code(&baseline), 1);
    let path = std::env::temp_dir().join("fleetreach_cli_baseline_test.json");
    std::fs::write(&path, baseline.stdout).unwrap();

    // ...then a re-run against it has nothing new -> exit 0.
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-vuln.toml"),
        "--db",
        &db(),
        "--baseline",
        path.to_str().unwrap(),
        "-f",
        "json",
    ]);
    assert_eq!(code(&out), 0, "known findings must be suppressed");
    let value: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(value["summary"]["vuln_count"], 0);

    let _ = std::fs::remove_file(&path);
}

// ---- exploit-risk enrichment ----

#[test]
fn kev_epss_enrichment_annotates_and_gates() {
    // The fixture advisory aliases CVE-2099-0001, which the KEV/EPSS fixtures
    // contain — so it lights up via the offline files.
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-vuln.toml"),
        "--db",
        &db(),
        "--kev-file",
        &cfg("kev.json"),
        "--epss-file",
        &cfg("epss.csv"),
        "-f",
        "json",
    ]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["vulnerabilities"][0]["kev"], true);
    assert!(v["vulnerabilities"][0]["epss"].as_f64().unwrap() > 0.9);

    // --fail-on-kev gates on the actively-exploited finding.
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-vuln.toml"),
        "--db",
        &db(),
        "--kev-file",
        &cfg("kev.json"),
        "--fail-on-kev",
        "-q",
    ]);
    assert_eq!(code(&out), 1);
}

// ---- OpenVEX output (-f vex) ----

/// Self-dogfood (§15): a default scan (no reachability) never emits `affected` —
/// it only arises from a sound static `Reachable` verdict.
#[test]
fn vex_never_emits_affected_without_reachability() {
    for fleet in ["fleet-vuln.toml", "fleet-clean.toml"] {
        let out = run(&[
            "scan",
            "-c",
            &cfg(fleet),
            "--db",
            &db(),
            "-f",
            "vex",
            "--vex-author",
            "ci@fleetreach",
            "--vex-timestamp",
            "2026-06-25T00:00:00Z",
        ]);
        let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid OpenVEX");
        let affected = v["statements"]
            .as_array()
            .map(|s| s.iter().filter(|st| st["status"] == "affected").count())
            .unwrap_or(0);
        assert_eq!(affected, 0, "{fleet} must emit zero `affected` statements");
    }
}

#[test]
fn vex_emits_valid_openvex_under_investigation_by_default() {
    // A default scan ran no reachability, so every live finding is the
    // conservative `under_investigation` — never `not_affected` (§2, §5).
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-vuln.toml"),
        "--db",
        &db(),
        "-f",
        "vex",
        "--vex-author",
        "secteam@acme.example",
        "--vex-timestamp",
        "2026-06-25T00:00:00Z",
    ]);
    assert_eq!(
        code(&out),
        1,
        "findings present -> gate trips; stderr: {}",
        stderr(&out)
    );
    let v: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("stdout must be valid OpenVEX JSON");
    assert_eq!(v["@context"], "https://openvex.dev/ns/v0.2.0");
    assert_eq!(v["author"], "secteam@acme.example");
    assert_eq!(v["version"], 1);
    let statements = v["statements"].as_array().expect("statements");
    assert!(!statements.is_empty(), "the fixture vuln must appear");
    for s in statements {
        assert_eq!(s["status"], "under_investigation");
        assert_ne!(s["status"], "not_affected");
        let sub = s["subcomponents"][0]["@id"].as_str().expect("subcomponent");
        assert!(
            sub.starts_with("pkg:cargo/"),
            "canonical cargo PURL, got {sub}"
        );
    }
    assert!(!stdout(&out).contains('\u{1b}'));
}

#[test]
fn vex_assertion_emits_approved_not_affected_and_clears_the_gate() {
    // A vex_assertion suppresses the gated finding and, under -f vex, becomes a
    // not_affected statement (§6).
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-vex-assertion.toml"),
        "--db",
        &db(),
        "-f",
        "vex",
        "--vex-timestamp",
        "2026-06-25T00:00:00Z",
    ]);
    assert_eq!(
        code(&out),
        0,
        "asserted finding clears the gate; stderr: {}",
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid OpenVEX");
    let statements = v["statements"].as_array().expect("statements");
    assert_eq!(statements.len(), 1);
    let s = &statements[0];
    assert_eq!(s["vulnerability"]["name"], "RUSTSEC-2099-0001");
    assert_eq!(s["status"], "not_affected");
    assert_eq!(s["justification"], "vulnerable_code_not_in_execute_path");
    assert!(s["status_notes"]
        .as_str()
        .unwrap()
        .contains("approved_by=secteam"));

    // The same config in JSON suppresses the finding entirely (gate view).
    let json = run(&[
        "scan",
        "-c",
        &cfg("fleet-vex-assertion.toml"),
        "--db",
        &db(),
        "-f",
        "json",
        "-q",
    ]);
    let jv: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(jv["summary"]["vuln_count"], 0);
}

#[test]
fn vex_only_sound_drops_the_human_assertion() {
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-vex-assertion.toml"),
        "--db",
        &db(),
        "-f",
        "vex",
        "--vex-timestamp",
        "2026-06-25T00:00:00Z",
        "--vex-only-sound",
    ]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid OpenVEX");
    assert!(
        v["statements"].as_array().expect("statements").is_empty(),
        "only-sound keeps no human assertion (and the finding was already suppressed)"
    );
}

#[test]
fn sarif_reflects_vex_suppression_in_the_same_run() {
    // The approved vex_assertion re-injects the finding into SARIF as a suppressed
    // result (§11).
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-vex-assertion.toml"),
        "--db",
        &db(),
        "-f",
        "sarif",
        "-q",
    ]);
    assert_eq!(code(&out), 0, "asserted finding clears the gate");
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid SARIF");
    let results = v["runs"][0]["results"].as_array().expect("results");
    let suppressed: Vec<&serde_json::Value> = results
        .iter()
        .filter(|r| r["ruleId"] == "RUSTSEC-2099-0001")
        .collect();
    assert_eq!(suppressed.len(), 1);
    let sup = &suppressed[0]["suppressions"][0];
    assert_eq!(sup["kind"], "external");
    assert!(sup["justification"]
        .as_str()
        .unwrap()
        .contains("approved_by"));
}

// ---- vex verify (witness re-derivation, §9.2) ----

#[test]
fn vex_verify_requires_consent_then_a_driver() {
    let path = std::env::temp_dir().join("fleetreach_vexverify_doc.json");
    std::fs::write(&path, r#"{"statements":[]}"#).unwrap();

    // No consent -> usage error (exit 3), never a silent build.
    let no_consent = run(&[
        "vex",
        "verify",
        path.to_str().unwrap(),
        "-c",
        &cfg("fleet-clean.toml"),
    ]);
    assert_eq!(code(&no_consent), 3);
    assert!(stderr(&no_consent).contains("--allow-untrusted-builds"));

    // Consent but no driver -> usage error (exit 3).
    let no_driver = run(&[
        "vex",
        "verify",
        path.to_str().unwrap(),
        "-c",
        &cfg("fleet-clean.toml"),
        "--allow-untrusted-builds",
    ]);
    assert_eq!(code(&no_driver), 3);
    assert!(stderr(&no_driver).contains("--reach-driver"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn vex_verify_no_machine_witnesses_is_a_noop() {
    // A document with only an under_investigation statement has no reachability
    // witness to re-derive, so verify short-circuits to 0 without building.
    let path = std::env::temp_dir().join("fleetreach_vexverify_nowitness.json");
    std::fs::write(
        &path,
        r#"{"statements":[{
            "vulnerability": { "name": "RUSTSEC-2099-0001" },
            "subcomponents": [{ "@id": "pkg:cargo/foo@1.0.0" }],
            "status": "under_investigation"
        }]}"#,
    )
    .unwrap();
    let out = run(&[
        "vex",
        "verify",
        path.to_str().unwrap(),
        "-c",
        &cfg("fleet-clean.toml"),
        "--allow-untrusted-builds",
        "--reach-driver",
        "/nonexistent/driver",
        "-q",
    ]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let _ = std::fs::remove_file(&path);
}

// ---- vex check (drift gate, §10) ----

#[test]
fn vex_check_passes_when_in_sync() {
    // Generate a committed document, then check the same config against it.
    let gen = run(&[
        "scan",
        "-c",
        &cfg("fleet-vex-assertion.toml"),
        "--db",
        &db(),
        "-f",
        "vex",
        "--vex-timestamp",
        "2026-06-25T00:00:00Z",
        "-q",
    ]);
    let path = std::env::temp_dir().join("fleetreach_vexcheck_insync.json");
    std::fs::write(&path, gen.stdout).unwrap();

    let out = run(&[
        "vex",
        "check",
        "-c",
        &cfg("fleet-vex-assertion.toml"),
        "--against",
        path.to_str().unwrap(),
        "--db",
        &db(),
        "-q",
    ]);
    assert_eq!(code(&out), 0, "in sync; stderr: {}", stderr(&out));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn vex_check_fails_on_an_untriaged_finding() {
    // A real finding checked against an empty committed document is un-triaged.
    let path = std::env::temp_dir().join("fleetreach_vexcheck_empty.json");
    std::fs::write(&path, r#"{"statements":[]}"#).unwrap();

    let out = run(&[
        "vex",
        "check",
        "-c",
        &cfg("fleet-vuln.toml"),
        "--against",
        path.to_str().unwrap(),
        "--db",
        &db(),
        "-q",
    ]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("untriaged"),
        "stderr: {}",
        stderr(&out)
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn vex_check_fails_on_a_stale_not_affected() {
    // A committed not_affected for a crate that is not in the (clean) fleet.
    let path = std::env::temp_dir().join("fleetreach_vexcheck_ghost.json");
    std::fs::write(
        &path,
        r#"{"statements":[{
            "vulnerability": { "name": "RUSTSEC-GHOST-0001" },
            "products": [{ "@id": "pkg:cargo/app@1.0.0" }],
            "subcomponents": [{ "@id": "pkg:cargo/ghost@9.9.9" }],
            "status": "not_affected"
        }]}"#,
    )
    .unwrap();

    let out = run(&[
        "vex",
        "check",
        "-c",
        &cfg("fleet-clean.toml"),
        "--against",
        path.to_str().unwrap(),
        "--db",
        &db(),
        "-q",
    ]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("stale not_affected"),
        "stderr: {}",
        stderr(&out)
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn vex_check_unreadable_document_is_could_not_scan() {
    let out = run(&[
        "vex",
        "check",
        "-c",
        &cfg("fleet-clean.toml"),
        "--against",
        &cfg("does-not-exist.openvex.json"),
        "--db",
        &db(),
        "-q",
    ]);
    assert_eq!(code(&out), 2);
}

#[test]
fn vex_without_an_author_is_a_usage_error() {
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-vuln.toml"),
        "--db",
        &db(),
        "-f",
        "vex",
        "--vex-timestamp",
        "2026-06-25T00:00:00Z",
    ]);
    assert_eq!(
        code(&out),
        3,
        "missing author must fail closed as a usage error"
    );
    assert!(stdout(&out).is_empty(), "no document is emitted on failure");
    assert!(stderr(&out).contains("author"));
}

// ---- gating flags ----

#[test]
fn fail_on_critical_still_trips_on_a_critical_vuln() {
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-vuln.toml"),
        "--db",
        &db(),
        "--fail-on",
        "critical",
    ]);
    assert_eq!(code(&out), 1, "the fixture vuln is CVSS critical");
}

#[test]
fn min_severity_at_the_threshold_keeps_the_finding() {
    // The fixture vuln is CVSS critical, so `--min-severity critical` keeps it
    // (critical >= critical) and it still gates.
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-vuln.toml"),
        "--db",
        &db(),
        "--min-severity",
        "critical",
        "-f",
        "json",
    ]);
    assert_eq!(code(&out), 1);
    let value: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(value["summary"]["vuln_count"], 1);
}

#[test]
fn static_reachability_requires_explicit_consent() {
    // --reachability=static COMPILES (and thus executes) the scanned repos. It
    // must refuse without explicit opt-in, naming the risk — no silent ACE.
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-clean.toml"),
        "--db",
        &db(),
        "--reachability=static",
    ]);
    assert_ne!(code(&out), 0, "must not proceed without consent");
    let err = stderr(&out).to_lowercase();
    assert!(
        err.contains("--allow-untrusted-builds"),
        "names the opt-in flag; stderr: {err}"
    );
    assert!(
        err.contains("build scripts") || err.contains("arbitrary code"),
        "names the risk; stderr: {err}"
    );
}

fn temp_fleet(tag: &str, toml: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fleetreach-src-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("fleet.toml");
    std::fs::write(&path, toml).unwrap();
    path
}

#[test]
fn unsynced_github_source_fails_closed_with_the_fix() {
    // Never listed: the fleet is unknown, so the scan must not run as if it were complete.
    let path = temp_fleet(
        "unsynced",
        "[[source]]\nkind = \"github\"\norg = \"acme\"\n",
    );
    let out = run(&["scan", "-c", path.to_str().unwrap(), "--db", &db()]);
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("fleetreach fleet sync"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn invalid_sources_are_config_errors() {
    for (toml, needle) in [
        (
            "[[source]]\nkind = \"bitbucket\"\norg = \"x\"\n",
            "kind `bitbucket` is not one of `github`, `gitlab`, `git`",
        ),
        (
            "[[source]]\nkind = \"gitlab\"\n",
            "kind `gitlab` needs `org`",
        ),
        ("[[source]]\nkind = \"github\"\n", "needs `org`"),
        ("[[source]]\nkind = \"git\"\n", "needs `urls`"),
        (
            "[[source]]\nkind = \"git\"\nurls = [\"git@github.com:a/b.git\"]\n",
            "must be https://",
        ),
        (
            "[[source]]\nkind = \"git\"\nurls = [\"https://x/a/b\"]\ncheckout = \"half\"\n",
            "checkout `half`",
        ),
    ] {
        let path = temp_fleet("invalid", toml);
        let out = run(&["scan", "-c", path.to_str().unwrap(), "--db", &db()]);
        assert_eq!(code(&out), 2, "{toml}");
        assert!(stderr(&out).contains(needle), "{toml}: {}", stderr(&out));
    }
}

// ---- fleet sources (spec 06), offline cases ----

fn write_fleet(tag: &str, body: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fleetreach-src-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("fleet.toml");
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn never_synced_source_repos_are_gaps_not_clean() {
    let path = write_fleet(
        "unsynced",
        "[[source]]\nkind = \"git\"\nurls = [\"https://example.com/acme/api.git\"]\n",
    );
    let out = run(&["fleet", "list", "-c", path.to_str().unwrap()]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("acme/api") && stdout(&out).contains("MISSING"));

    let out = run(&["scan", "-c", path.to_str().unwrap(), "--db", &db()]);
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("fleetreach fleet sync"),
        "{}",
        stderr(&out)
    );
}

// ---- exposure context and SSVC (spec 08) ----

fn ssvc_scan(extra: &[&str]) -> Output {
    let fleet = cfg("fleet-ssvc.toml");
    let db = db();
    let mut args = vec!["scan", "-c", &fleet, "--db", &db];
    args.extend_from_slice(extra);
    run(&args)
}

#[test]
fn ssvc_decides_per_repo_context() {
    let kev = cfg("kev.json");
    let out = ssvc_scan(&["--kev-file", &kev, "-f", "json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["ssvc"]["table"], "ssvc:DT_DP:1.0.0");
    let outcome = |repo: &str| {
        v["ssvc"]["decisions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["repo"] == repo)
            .map(|d| (d["outcome"].clone(), d["vector"].clone()))
            .unwrap()
    };
    // KEV + automatable vector: an open, mission-critical repo acts now, a small, low-impact
    // one schedules it, and a repo without context fails closed to the most urgent values.
    assert_eq!(
        outcome("payments"),
        ("immediate".into(), "E:A/X:O/A:Y/HI:VH".into())
    );
    assert_eq!(
        outcome("intranet"),
        ("scheduled".into(), "E:A/X:S/A:Y/HI:L".into())
    );
    assert_eq!(outcome("legacy").0, "immediate");
    let legacy = v["context"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["repo"] == "legacy")
        .unwrap();
    assert_eq!(legacy["fail_closed"], true);
    assert!(stderr(&out).contains("1 repo(s) have incomplete context"));
    assert_eq!(
        v["vulnerabilities"][0]["cvss_vector"],
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    );

    let table = stdout(&ssvc_scan(&["--kev-file", &kev, "-f", "ssvc"]));
    assert!(table.contains("E:A/X:S/A:Y/HI:L"), "{table}");
    assert!(table.contains("2 immediate, 0 out-of-cycle, 1 scheduled, 0 defer"));

    // SARIF carries the outcome and maps it to the level.
    let sarif: serde_json::Value =
        serde_json::from_str(&stdout(&ssvc_scan(&["--kev-file", &kev, "-f", "sarif"]))).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    let levels: std::collections::BTreeSet<(String, String)> = results
        .iter()
        .map(|r| {
            (
                r["properties"]["ssvc"].as_str().unwrap().to_string(),
                r["level"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(levels.contains(&("immediate".into(), "error".into())));
    assert!(levels.contains(&("scheduled".into(), "warning".into())));
}

#[test]
fn ssvc_without_exploitation_data_decides_nothing() {
    let out = ssvc_scan(&["-f", "json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["ssvc"]["decisions"].as_array().unwrap().len(), 0);
    assert!(v["ssvc"]["not_computed"]
        .as_str()
        .unwrap()
        .contains("--enrich"));

    // EPSS alone cannot say a finding is not actively exploited.
    let epss = cfg("epss.csv");
    let out = ssvc_scan(&["--epss-file", &epss, "-f", "ssvc"]);
    assert!(stdout(&out).starts_with("No SSVC decisions: no exploitation data"));

    // The gate fails closed rather than passing on missing data.
    let out = ssvc_scan(&["--epss-file", &epss, "--fail-on-ssvc", "immediate"]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("no SSVC decisions under --fail-on-ssvc"));
}

#[test]
fn fail_on_ssvc_replaces_the_default_severity_gate() {
    let kev = cfg("kev.json");
    // A repo decided `immediate` trips the gate...
    let out = ssvc_scan(&["--kev-file", &kev, "--fail-on-ssvc", "immediate", "-q"]);
    assert_eq!(code(&out), 1);
    // ...while a fleet whose only repo is decided `scheduled` passes `out-of-cycle` even
    // though the finding is critical: SSVC replaced the default `--fail-on low`.
    let fleet = cfg("fleet-ssvc-small.toml");
    let db = db();
    let gate = |extra: &[&str]| {
        let mut args = vec!["scan", "-c", &fleet, "--db", &db, "--kev-file", &kev, "-q"];
        args.extend_from_slice(extra);
        code(&run(&args))
    };
    assert_eq!(gate(&["--fail-on-ssvc", "out-of-cycle"]), 0);
    assert_eq!(gate(&["--fail-on-ssvc", "scheduled"]), 1);
    // An explicit --fail-on still applies alongside it.
    assert_eq!(
        gate(&["--fail-on-ssvc", "out-of-cycle", "--fail-on", "high"]),
        1
    );
}

#[test]
fn owners_view_splits_the_queue_by_owner() {
    let out = ssvc_scan(&["-f", "owners"]);
    let text = stdout(&out);
    let payments = text.find("team-payments (1 repo(s): payments)").unwrap();
    let tools = text.find("team-tools (1 repo(s): intranet)").unwrap();
    let unowned = text.find("(no owner) (1 repo(s): legacy)").unwrap();
    assert!(payments < tools && tools < unowned, "{text}");
}

#[test]
fn context_values_must_be_ssvc_names() {
    let dir = std::env::temp_dir().join("fleetreach_ssvc_bad_context");
    std::fs::create_dir_all(&dir).unwrap();
    let fleet = dir.join("fleet.toml");
    std::fs::write(
        &fleet,
        "[[repo]]\nid = \"a\"\npath = \".\"\nexposure = \"internet\"\n",
    )
    .unwrap();
    let out = run(&["scan", "-c", fleet.to_str().unwrap()]);
    assert_eq!(code(&out), 2);
    assert!(
        stderr(&out).contains("unknown variant `internet`"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn custom_ssvc_table_and_weights_are_used_and_recorded() {
    let fleet = cfg("fleet-ssvc-custom.toml");
    let (db, kev) = (db(), cfg("kev.json"));
    let out = run(&[
        "scan",
        "-c",
        &fleet,
        "--db",
        &db,
        "--kev-file",
        &kev,
        "-f",
        "json",
    ]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert!(v["ssvc"]["table"].as_str().unwrap().starts_with("custom:"));
    assert_eq!(v["ssvc"]["decisions"][0]["outcome"], "out-of-cycle");
    assert_eq!(v["ssvc"]["weights"]["out-of-cycle"], 5);
    let out = run(&[
        "scan",
        "-c",
        &fleet,
        "--db",
        &db,
        "--kev-file",
        &kev,
        "-f",
        "packages-json",
    ]);
    let p: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(p[0]["weighted_reach"], 5);
    assert_eq!(p[0]["max_outcome"], "out-of-cycle");
}

#[test]
fn fleet_views_weight_reach_by_outcome() {
    let kev = cfg("kev.json");
    // payments and legacy decide `immediate` (8 each), intranet `scheduled` (2).
    for view in ["impact", "blast", "packages"] {
        let text = stdout(&ssvc_scan(&["--kev-file", &kev, "-f", view, "-q"]));
        assert!(text.contains("Weighted"), "{view}: {text}");
        assert!(text.contains("┆ 18 "), "{view}: {text}");
    }
    // Without decisions the views are unchanged.
    let text = stdout(&ssvc_scan(&["-f", "impact", "-q"]));
    assert!(!text.contains("Weighted"));
}

#[test]
fn vulnrichment_dir_supplies_cisas_assessment() {
    let (kev, dir) = (cfg("kev-empty.json"), cfg("vulnrichment"));
    let out = ssvc_scan(&["--kev-file", &kev, "--vulnrichment-dir", &dir, "-f", "json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let payments = v["ssvc"]["decisions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["repo"] == "payments")
        .unwrap()
        .clone();
    // Not in KEV, but CISA says exploitation is active and the attack is not automatable.
    assert_eq!(payments["vector"], "E:A/X:O/A:N/HI:VH");
    assert_eq!(payments["outcome"], "immediate");
    assert!(payments["rationale"]
        .as_str()
        .unwrap()
        .contains("CISA Vulnrichment"));
    // Without it, the same scan decides from the empty KEV and the CVSS vector.
    let out = ssvc_scan(&["--kev-file", &kev, "-f", "json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let vector = v["ssvc"]["decisions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["repo"] == "payments")
        .unwrap()["vector"]
        .clone();
    assert_eq!(vector, "E:N/X:O/A:Y/HI:VH");
}

// ---- upgrade safety (spec 13) ----

fn evidence_scan(format: &str) -> String {
    let out = run(&[
        "scan",
        "-c",
        &cfg("fleet-evidence.toml"),
        "--db",
        &db(),
        "-f",
        format,
        "-q",
    ]);
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
    stdout(&out)
}

#[test]
fn the_report_records_which_versions_the_fleet_runs() {
    let value: serde_json::Value = serde_json::from_str(&evidence_scan("json")).unwrap();
    let versions = &value["package_versions"];
    assert_eq!(versions.as_array().unwrap().len(), 1, "{versions}");
    assert_eq!(versions[0]["package"], "fixturevuln");
    assert_eq!(versions[0]["versions"][0]["version"], "1.0.0");
    assert_eq!(versions[0]["versions"][0]["repos"][0], "app");
    assert_eq!(versions[0]["versions"][1]["version"], "1.0.1");
    assert_eq!(versions[0]["versions"][1]["repos"][0], "patched");
}

#[test]
fn remediation_rates_each_bump_against_the_fleet() {
    let value: serde_json::Value =
        serde_json::from_str(&evidence_scan("remediation-json")).unwrap();
    let item = &value[0];
    assert_eq!(item["risk"], "low");
    assert_eq!(item["evidence"]["repos"], 1);
    assert_eq!(item["evidence"]["newest"], "1.0.1");
    assert_eq!(item["risk_reasons"][1], "1 repo already runs 1.0.1+");

    let table = evidence_scan("remediation");
    assert!(table.contains("Bump risk"), "{table}");
    assert!(table.contains("low · 1 on 1.0.1"), "{table}");
}

// ---- scan history (spec 09) ----

#[test]
fn history_tracks_fixes_age_sla_and_never_trusts_a_gap_run() {
    let root = std::env::temp_dir().join(format!("fleetreach-history-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let vulnerable =
        std::fs::read_to_string(manifest().join("tests/fixtures/repos/repo-vuln/Cargo.lock"))
            .unwrap();
    let patched = vulnerable.replace("1.0.0", "1.0.1");
    let app = root.join("app");
    let api = root.join("api");
    for dir in [&app, &api] {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("Cargo.lock"), &vulnerable).unwrap();
    }
    let fleet = root.join("fleet.toml");
    let write_fleet = |sla: &str| {
        std::fs::write(
            &fleet,
            format!(
                "[[repo]]\nid = \"app\"\npath = {app:?}\nowner = \"team-a\"\n\n\
                 [[repo]]\nid = \"api\"\npath = {api:?}\nowner = \"team-b\"\n\n\
                 [settings.sla]\n{sla}\n"
            ),
        )
        .unwrap();
    };
    write_fleet("critical = \"30d\"");
    let history = root.join("history");
    let day = 86_400_i64;
    let t0 = 1_793_404_800_i64; // 2026-10-31T00:00:00Z
    let scan_at = |t: i64| {
        let out = run_env(
            &[
                "scan",
                "-q",
                "-c",
                fleet.to_str().unwrap(),
                "--db",
                &db(),
                "-f",
                "json",
                "--history-dir",
                history.to_str().unwrap(),
            ],
            &[("SOURCE_DATE_EPOCH", std::ffi::OsStr::new(&t.to_string()))],
        );
        code(&out)
    };
    // Day 0: both vulnerable. Day 10: app fixed. Day 20: api unreadable, the run is a gap.
    // Day 40: api read again, still vulnerable.
    assert_eq!(scan_at(t0), 1);
    std::fs::write(app.join("Cargo.lock"), &patched).unwrap();
    assert_eq!(scan_at(t0 + 10 * day), 1);
    std::fs::write(api.join("Cargo.lock"), "not a lockfile [[[").unwrap();
    assert_eq!(scan_at(t0 + 20 * day), 2);
    std::fs::write(api.join("Cargo.lock"), &vulnerable).unwrap();
    assert_eq!(scan_at(t0 + 40 * day), 1);

    let at = "2026-12-10T00:00:00Z"; // day 40
    let query = |args: &[&str]| {
        let mut argv = vec!["history"];
        argv.extend_from_slice(args);
        argv.extend_from_slice(&["--history-dir", history.to_str().unwrap(), "--at", at]);
        let out = run(&argv);
        (code(&out), stdout(&out), stderr(&out))
    };
    let json = |args: &[&str]| -> serde_json::Value {
        let mut argv = args.to_vec();
        argv.extend_from_slice(&["-f", "json"]);
        let (_, out, err) = query(&argv);
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out} {err}"))
    };

    let trend = json(&["trend"]);
    let open: Vec<u64> = trend
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["open"].as_u64().unwrap())
        .collect();
    assert_eq!(open, [2, 1, 0, 1], "{trend}");
    assert_eq!(trend[2]["gap"], true);

    // The gap run did not fix api's finding: it has been open since day 0.
    let age = json(&["age"]);
    assert_eq!(age.as_array().unwrap().len(), 1, "{age}");
    assert_eq!(age[0]["repo"], "api");
    assert_eq!(age[0]["age_days"], 40.0);
    assert_eq!(age[0]["owner"], "team-b");
    assert_eq!(age[0]["first_seen"], "2026-10-31T00:00:00Z");

    let mttr = json(&["mttr", "--by", "owner"]);
    let team_a = mttr
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["group"] == "team-a")
        .unwrap();
    assert_eq!(team_a["fixed"], 1);
    assert_eq!(team_a["mean_days"], 10.0);

    let config = fleet.to_str().unwrap();
    let (code_sla, out, _) = query(&["sla", "-c", config]);
    assert_eq!(
        code_sla, 1,
        "a 30-day critical SLA is 10 days overdue: {out}"
    );
    assert!(out.contains("api") && out.contains("10.0"), "{out}");
    write_fleet("critical = \"60d\"");
    assert_eq!(query(&["sla", "-c", config]).0, 0);
    write_fleet("");
    assert_eq!(
        query(&["sla", "-c", config]).0,
        2,
        "no policy is not a pass"
    );

    // The snapshots are the truth: a lost index is rebuilt to the same answer.
    std::fs::remove_file(history.join("index.json")).unwrap();
    assert_eq!(json(&["age"]), age);

    // Flags that drop findings would record them as fixed.
    let out = run(&[
        "scan",
        "-q",
        "-c",
        config,
        "--db",
        &db(),
        "--min-severity",
        "high",
        "--history-dir",
        history.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("--min-severity"), "{}", stderr(&out));

    // Retention drops old snapshots, but the index keeps when each finding was first seen.
    std::fs::write(
        &fleet,
        std::fs::read_to_string(&fleet).unwrap() + "\n[settings.history]\nkeep = \"15d\"\n",
    )
    .unwrap();
    assert_eq!(scan_at(t0 + 41 * day), 1);
    let left = std::fs::read_dir(&history)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .path()
                .to_string_lossy()
                .ends_with(".json.gz")
        })
        .count();
    assert_eq!(left, 2, "days 40 and 41 are kept");
    assert_eq!(json(&["age"])[0]["first_seen"], "2026-10-31T00:00:00Z");
}

#[test]
fn notify_reports_changes_by_owner_and_keeps_one_issue_per_owner() {
    let root = std::env::temp_dir().join(format!("fleetreach-notify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let vulnerable =
        std::fs::read_to_string(manifest().join("tests/fixtures/repos/repo-vuln/Cargo.lock"))
            .unwrap();
    let patched = vulnerable.replace("1.0.0", "1.0.1");
    let app = root.join("app");
    let api = root.join("api");
    for dir in [&app, &api] {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("Cargo.lock"), &vulnerable).unwrap();
    }
    let fleet = root.join("fleet.toml");
    std::fs::write(
        &fleet,
        format!(
            "[[repo]]\nid = \"app\"\npath = {app:?}\nowner = \"team-a\"\n\n\
             [[repo]]\nid = \"api\"\npath = {api:?}\nowner = \"team-b\"\n\n\
             [settings.sla]\ncritical = \"30d\"\n"
        ),
    )
    .unwrap();
    let config = fleet.to_str().unwrap();
    let history = root.join("history");
    let hist = history.to_str().unwrap();
    let day = 86_400_i64;
    let t0 = 1_793_404_800_i64; // 2026-10-31T00:00:00Z
    let epoch = |t: i64| t.to_string();
    let scan_at = |t: i64| {
        let e = epoch(t);
        let out = run_env(
            &[
                "scan",
                "-q",
                "-c",
                config,
                "--db",
                &db(),
                "-f",
                "json",
                "--history-dir",
                hist,
            ],
            &[("SOURCE_DATE_EPOCH", std::ffi::OsStr::new(&e))],
        );
        code(&out)
    };
    let notify = |t: i64, extra: &[&str], env: &[(&str, &std::ffi::OsStr)]| {
        let e = epoch(t);
        let mut argv = vec!["notify", "--history-dir", hist, "-c", config];
        argv.extend_from_slice(extra);
        let mut env = env.to_vec();
        env.push(("SOURCE_DATE_EPOCH", std::ffi::OsStr::new(&e)));
        let out = run_env(&argv, &env);
        (code(&out), stdout(&out), stderr(&out))
    };
    let payload = |t: i64| -> serde_json::Value {
        let (c, out, err) = notify(t, &[], &[]);
        assert_eq!(c, 0, "{err}");
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out} {err}"))
    };
    let owners = |p: &serde_json::Value| -> Vec<String> {
        p["owners"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["owner"].as_str().unwrap().to_string())
            .collect()
    };

    // Day 0: both new, one section per owner, the documented schema.
    assert_eq!(scan_at(t0), 1);
    let p = payload(t0);
    assert_eq!(p["schema"], "fleetreach-notify/1");
    assert_eq!(p["previous_run"], serde_json::Value::Null);
    assert_eq!(p["summary"]["new"], 2, "{p}");
    assert_eq!(owners(&p), ["team-a", "team-b"]);
    let item = &p["owners"][0]["new"][0];
    for field in [
        "advisory",
        "ecosystem",
        "repo",
        "package",
        "version",
        "severity",
        "first_seen",
        "url",
    ] {
        assert!(item.get(field).is_some(), "{field} missing: {item}");
    }
    assert_eq!(item["advisory"], "RUSTSEC-2099-0001");
    assert_eq!(item["severity"], "critical");
    assert_eq!(
        item["url"],
        "https://osv.dev/vulnerability/RUSTSEC-2099-0001"
    );

    // Day 10: app fixed, nothing new.
    std::fs::write(app.join("Cargo.lock"), &patched).unwrap();
    assert_eq!(scan_at(t0 + 10 * day), 1);
    let p = payload(t0 + 10 * day);
    assert_eq!(p["summary"]["new"], 0, "{p}");
    assert_eq!(p["summary"]["fixed"], 1, "{p}");
    assert_eq!(owners(&p), ["team-a"]);
    assert!(p["previous_run"].is_string());

    // Day 20, a gap run, then day 40: api read again. Its finding is neither fixed by the
    // gap nor new when it is read again; it is past its 30-day SLA.
    std::fs::write(api.join("Cargo.lock"), "not a lockfile [[[").unwrap();
    assert_eq!(scan_at(t0 + 20 * day), 2);
    let p = payload(t0 + 20 * day);
    assert_eq!(p["run"]["gap"], true);
    assert_eq!(
        (p["summary"]["new"].as_u64(), p["summary"]["fixed"].as_u64()),
        (Some(0), Some(0))
    );
    std::fs::write(api.join("Cargo.lock"), &vulnerable).unwrap();
    assert_eq!(scan_at(t0 + 40 * day), 1);
    let p = payload(t0 + 40 * day);
    assert_eq!(p["summary"]["new"], 0, "{p}");
    assert_eq!(p["summary"]["breaches"], 1, "{p}");
    assert_eq!(p["owners"][0]["owner"], "team-b");
    assert_eq!(p["owners"][0]["breaches"][0]["overdue_days"], 10.0);

    let (_, slack, _) = notify(t0 + 40 * day, &["-f", "slack"], &[]);
    let slack: serde_json::Value = serde_json::from_str(&slack).unwrap();
    assert_eq!(slack["blocks"][0]["type"], "header");
    assert!(
        slack["blocks"][2]["text"]["text"]
            .as_str()
            .unwrap()
            .contains("*Past SLA* (1)"),
        "{slack}"
    );

    // Webhooks: HTTPS only, and a POST of the payload.
    let (c, _, err) = notify(
        t0 + 40 * day,
        &["--webhook", "http://example.com/hook"],
        &[],
    );
    assert_eq!(c, 3, "{err}");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://127.0.0.1:{}/hook/secret",
        listener.local_addr().unwrap().port()
    );
    let server = std::thread::spawn(move || {
        use std::io::{BufRead, BufReader, Read, Write};
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line.trim().is_empty() {
                break;
            }
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = v.trim().parse().unwrap();
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
            .unwrap();
        String::from_utf8(body).unwrap()
    });
    let (c, _, err) = notify(t0 + 40 * day, &["--webhook", &url], &[]);
    if cfg!(feature = "network") {
        assert_eq!(c, 0, "{err}");
        assert!(!err.contains("secret"), "the URL's path is a secret: {err}");
        let got: serde_json::Value = serde_json::from_str(&server.join().unwrap()).unwrap();
        assert_eq!(got["schema"], "fleetreach-notify/1");
        assert_eq!(got["summary"]["breaches"], 1);
    } else {
        assert_eq!(c, 2, "{err}");
        assert!(err.contains("network"), "{err}");
    }

    // Issues: a fake gh that keeps each issue as files.
    let bin = root.join("bin");
    let state = root.join("issues");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&state).unwrap();
    let gh = bin.join("gh");
    std::fs::write(
        &gh,
        r#"#!/bin/sh
echo "$*" >> "$FAKE_GH_LOG"
S="$FAKE_GH_STATE"
case "$1 $2" in
  "issue list")
    printf '['; sep=''
    for f in "$S"/*.body; do
      [ -e "$f" ] || continue
      n=$(basename "$f" .body)
      printf '%s{"number":%s,"body":"%s","state":"%s"}' "$sep" "$n" "$(head -n1 "$f")" "$(cat "$S/$n.state")"
      sep=','
    done
    echo ']' ;;
  "issue create")
    n=$(( $(ls "$S" | grep -c '\.body$') + 1 ))
    cat > "$S/$n.body"; echo OPEN > "$S/$n.state"
    echo "https://github.com/acme/security/issues/$n" ;;
  "issue edit") cat > "$S/$3.body" ;;
  "issue close") echo CLOSED > "$S/$3.state" ;;
  "issue reopen") echo OPEN > "$S/$3.state" ;;
esac
"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let log = root.join("gh.log");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let gh_env: Vec<(&str, &std::ffi::OsStr)> = vec![
        ("PATH", std::ffi::OsStr::new(&path)),
        ("FAKE_GH_LOG", log.as_os_str()),
        ("FAKE_GH_STATE", state.as_os_str()),
    ];
    let issues = ["--github-issues", "--repo", "acme/security"];
    let read = |p: &str| std::fs::read_to_string(state.join(p)).unwrap();

    let (c, out, err) = notify(
        t0 + 40 * day,
        &[&issues[..], &["--dry-run"]].concat(),
        &gh_env,
    );
    assert_eq!(c, 0, "{err}");
    assert!(
        out.contains("fleetreach: 1 open finding(s) for team-b, 1 past SLA"),
        "{out}"
    );
    assert!(!log.exists(), "a dry run runs no gh");

    // Only team-b has an open finding, so only it gets an issue; running again rewrites it.
    for _ in 0..2 {
        let (c, _, err) = notify(t0 + 40 * day, &issues, &gh_env);
        assert_eq!(c, 0, "{err}");
    }
    assert!(
        !state.join("2.body").exists(),
        "one issue, updated in place"
    );
    let body = read("1.body");
    assert!(
        body.starts_with("<!-- fleetreach:campaign=fleetreach;owner=team-b -->"),
        "{body}"
    );
    assert!(
        body.contains("### Past SLA (1)") && body.contains("api"),
        "{body}"
    );
    let calls = std::fs::read_to_string(&log).unwrap();
    assert!(
        calls.contains("issue create --repo acme/security"),
        "{calls}"
    );
    assert!(
        calls.contains("issue edit 1 --repo acme/security"),
        "{calls}"
    );

    // api fixed: the issue says so and is closed; back again: reopened.
    std::fs::write(api.join("Cargo.lock"), &patched).unwrap();
    assert_eq!(scan_at(t0 + 41 * day), 0);
    assert_eq!(notify(t0 + 41 * day, &issues, &gh_env).0, 0);
    assert_eq!(read("1.state").trim(), "CLOSED");
    assert!(
        read("1.body").contains("### Fixed in this run (1)"),
        "{}",
        read("1.body")
    );
    std::fs::write(api.join("Cargo.lock"), &vulnerable).unwrap();
    assert_eq!(scan_at(t0 + 42 * day), 1);
    let p = payload(t0 + 42 * day);
    assert_eq!(
        p["summary"]["new"], 1,
        "a finding back after its fix is new: {p}"
    );
    assert_eq!(notify(t0 + 42 * day, &issues, &gh_env).0, 0);
    assert_eq!(read("1.state").trim(), "OPEN");
    assert!(!state.join("2.body").exists());
}
