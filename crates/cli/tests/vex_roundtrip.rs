//! Round-trip effectiveness (spec §15): emit fleetreach's OpenVEX and prove it
//! actually *suppresses* a finding in a pinned, real consumer — not merely that
//! the JSON parses. This is what makes the §4 identity guarantee real: the
//! statement's identifiers must byte-match what the consumer emits for the crate,
//! or suppression silently fails.
//!
//! **Validated behaviour (the matrix in `docs/vex-compatibility.md`):**
//! - **Trivy** (`fs` scan): honors fleetreach's real output. It matches the
//!   vulnerability by *alias* (the finding is `CVE-…`; our `name` is `RUSTSEC-…`
//!   with the CVE in `aliases`) and the package by the crate PURL that fleetreach
//!   now lists in `products`. → suppression works.
//! - **Grype** (`--vex`): only supports a **container image** source. A `dir:` or
//!   SBOM-of-directory scan errors with "source type not supported for VEX", so
//!   fleetreach's source-oriented VEX cannot suppress in grype today. The grype
//!   test is a canary that flags if that ever changes.
//!
//! Both tests are **skip-if-missing**: absent the tool, its network DB, or the
//! baseline finding, they return early rather than fail, so they are inert
//! locally. The `vex-roundtrip` CI job installs pinned versions and runs them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use fleetreach_report::{to_vex, HumanAssertion, VexParams, VexScope};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/roundtrip")
}

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// An empty report — the round-trip drives suppression through a human assertion,
/// so no scanned findings are needed; only the emitted statement shape matters.
fn empty_report() -> fleetreach_core::FleetReport {
    fleetreach_core::FleetReport {
        schema_version: 1,
        provenance: fleetreach_core::Provenance {
            tool_version: "0".into(),
            rustsec_crate_version: "0".into(),
            db_commit: None,
            db_timestamp: None,
            host_os: "linux".into(),
            host_arch: "x86_64".into(),
            generated_at: "t".into(),
        },
        summary: fleetreach_core::Summary {
            repos_scanned: 1,
            repos_errored: 0,
            vuln_count: 0,
            warn_count: 0,
            max_severity: fleetreach_core::Severity::Unknown,
            stale_ignores: vec![],
        },
        vulnerabilities: vec![],
        warnings: vec![],
        outcomes: vec![],
    }
}

/// Emit a fleetreach OpenVEX document marking `(vuln_id, pkg:cargo/<name>@<ver>)`
/// `not_affected`, in the serializer's **real** shape (the crate PURL appears in
/// both `products` — for package-centric consumers — and `subcomponents`).
/// `vuln_id` is whatever the consumer reported, so matching does not hinge on
/// which alias the consumer keys on.
fn vex_document(vuln_id: &str, name: &str, version: &str) -> String {
    let mut product_ids = BTreeMap::new();
    product_ids.insert("app".to_string(), "pkg:cargo/roundtrip@0.1.0".to_string());
    let params = VexParams {
        author: "ci@fleetreach".into(),
        role: Some("Document Creator".into()),
        scope: VexScope::Runtime,
        timestamp: "2026-06-25T00:00:00Z".into(),
        doc_id: None,
        product_id_base: Some("https://fleetreach.test/".into()),
        product_ids,
        assertions: vec![HumanAssertion {
            advisory_id: vuln_id.into(),
            aliases: vec![],
            product_id: "pkg:cargo/roundtrip@0.1.0".into(),
            package: name.into(),
            version: version.into(),
            justification: Some("vulnerable_code_not_in_execute_path".into()),
            impact_statement: "round-trip test".into(),
            approved_by: Some("ci".into()),
        }],
        only_sound: false,
        alias_rustbinary: false,
        include_fixed: false,
        version: 1,
        supersedes: None,
    };
    to_vex(&empty_report(), &params).expect("serialize VEX")
}

/// Trivy: `fs`-scan the fixture, then re-scan with our VEX and assert the finding
/// is gone (suppressed). This is the validated, load-bearing round-trip.
#[test]
fn trivy_honors_fleetreach_vex() {
    if !have("trivy") {
        eprintln!("skip: trivy not installed");
        return;
    }
    let dir = fixture_dir();

    let baseline = Command::new("trivy")
        .args(["fs", "--format", "json", "--quiet"])
        .arg(&dir)
        .output()
        .expect("run trivy");
    if !baseline.status.success() {
        eprintln!("skip: trivy baseline failed (offline DB?)");
        return;
    }
    let report: serde_json::Value = serde_json::from_slice(&baseline.stdout).expect("trivy json");
    let vuln_id = report["Results"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r["Vulnerabilities"].as_array())
        .flatten()
        .find(|v| v["PkgName"] == "time")
        .and_then(|v| v["VulnerabilityID"].as_str().map(str::to_string));
    let Some(vuln_id) = vuln_id else {
        eprintln!("skip: trivy did not flag time (DB variance)");
        return;
    };

    let doc = vex_document(&vuln_id, "time", "0.2.7");
    let doc_path = std::env::temp_dir().join("fleetreach_roundtrip_trivy.openvex.json");
    std::fs::write(&doc_path, doc).unwrap();

    let suppressed = Command::new("trivy")
        .args(["fs", "--format", "json", "--quiet", "--vex"])
        .arg(&doc_path)
        .arg(&dir)
        .output()
        .expect("run trivy --vex");
    let after: serde_json::Value = serde_json::from_slice(&suppressed.stdout).expect("trivy json");
    let still_present = after["Results"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r["Vulnerabilities"].as_array())
        .flatten()
        .any(|v| v["VulnerabilityID"] == vuln_id.as_str() && v["PkgName"] == "time");

    let _ = std::fs::remove_file(&doc_path);
    assert!(
        !still_present,
        "fleetreach VEX did not suppress {vuln_id} in trivy \
         (the crate PURL must appear in `products`, and the alias must match — \
          see docs/vex-compatibility.md)"
    );
}

/// Grype canary: grype's `--vex` only supports a container-image source, so a
/// `dir:` scan with `--vex` errors. This test confirms grype still flags the
/// fixture and that source-scan VEX remains unsupported; if a future grype gains
/// `dir`/SBOM VEX support, the assertion flips and the matrix needs updating.
#[test]
fn grype_source_scan_vex_is_unsupported_canary() {
    if !have("grype") {
        eprintln!("skip: grype not installed");
        return;
    }
    let target = format!("dir:{}", fixture_dir().display());

    let baseline = Command::new("grype")
        .args([&target, "-o", "json", "-q"])
        .env("GRYPE_DB_VALIDATE_AGE", "false") // pinned grype's newest DB can exceed its own age cap
        .output()
        .expect("run grype");
    if !baseline.status.success() {
        eprintln!("skip: grype baseline failed (offline DB?)");
        return;
    }
    let report: serde_json::Value = serde_json::from_slice(&baseline.stdout).expect("grype json");
    let flagged = report["matches"]
        .as_array()
        .map(|ms| ms.iter().any(|m| m["artifact"]["name"] == "time"))
        .unwrap_or(false);
    if !flagged {
        eprintln!("skip: grype did not flag time (DB variance)");
        return;
    }
    let id = report["matches"][0]["vulnerability"]["id"]
        .as_str()
        .unwrap_or("CVE-2020-26235");

    let doc = vex_document(id, "time", "0.2.7");
    let doc_path = std::env::temp_dir().join("fleetreach_roundtrip_grype.openvex.json");
    std::fs::write(&doc_path, doc).unwrap();

    let vexed = Command::new("grype")
        .args([
            &target,
            "-o",
            "json",
            "-q",
            "--vex",
            doc_path.to_str().unwrap(),
        ])
        .env("GRYPE_DB_VALIDATE_AGE", "false")
        .output()
        .expect("run grype --vex");
    let _ = std::fs::remove_file(&doc_path);

    // Documented limitation: grype rejects VEX for a non-image source. If this
    // ever succeeds, grype gained source-scan VEX support — update the matrix.
    assert!(
        !vexed.status.success(),
        "grype --vex unexpectedly succeeded on a dir source — it may now support \
         source-scan VEX; update docs/vex-compatibility.md"
    );
    let err = String::from_utf8_lossy(&vexed.stderr);
    assert!(
        err.contains("source type not supported") || err.contains("VEX"),
        "expected grype to reject source-scan VEX; stderr: {err}"
    );
}
