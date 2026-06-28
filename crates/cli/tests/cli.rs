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

fn run(args: &[&str]) -> Output {
    Command::cargo_bin("fleetreach")
        .unwrap()
        .args(args)
        .output()
        .unwrap()
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
