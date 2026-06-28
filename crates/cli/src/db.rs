//! Advisory-DB loading, freshness, provenance, and enrichment fetch — the
//! binary's I/O wiring, kept out of the command runners. Everything here is
//! `Args`-agnostic (it takes primitives), so `scan` and the `vex` subcommands
//! share it without coupling to a particular clap struct.

use std::path::Path;
use std::process::Command;

use fleetreach_core::semver::Version;
use fleetreach_core::{FleetReport, Provenance};
// `Severity` only appears in the network-only enrichment fetch.
#[cfg(feature = "network")]
use fleetreach_core::Severity;
use fleetreach_scan::{AdvisoryDb, DatabaseMeta, RUSTSEC_VERSION};

use crate::enrich::Enrichment;
use crate::orchestrate::Toolchain;

/// Load the advisory DB from explicit options, shared by `scan` and `vex check`.
pub(crate) fn load_db_from(
    db: Option<&Path>,
    db_rev: Option<&str>,
    offline: bool,
) -> Result<AdvisoryDb, String> {
    if let Some(path) = db {
        if let Some(rev) = db_rev {
            checkout_rev(path, rev)?;
        }
        return AdvisoryDb::open(path).map_err(|e| e.to_string());
    }
    if db_rev.is_some() {
        return Err("--db-rev requires --db <PATH> (a local advisory-db git clone)".to_string());
    }
    load_db_remote(offline)
}

/// Load the DB from the network (default cache when `offline`, else fetch). Only
/// exists in a `network` build; the pure-Rust build directs the user to `--db`.
#[cfg(feature = "network")]
fn load_db_remote(offline: bool) -> Result<AdvisoryDb, String> {
    if offline {
        AdvisoryDb::open_default_cache().map_err(|e| e.to_string())
    } else {
        AdvisoryDb::fetch().map_err(|e| e.to_string())
    }
}

/// Pure-Rust build: no git/network backend, so the advisory DB must be supplied
/// explicitly with `--db`.
#[cfg(not(feature = "network"))]
fn load_db_remote(_offline: bool) -> Result<AdvisoryDb, String> {
    Err(
        "this build has no network support: pass --db <PATH> to a local advisory-db \
         clone, or rebuild with --features network to fetch the DB"
            .to_string(),
    )
}

/// Compute the (deduped) CVE lists and fetch KEV/EPSS/NVD enrichment. Network
/// build only; the pure-Rust build directs the user to `--kev-file`/`--epss-file`.
#[cfg(feature = "network")]
pub(crate) fn fetch_enrichment(report: &FleetReport) -> Result<Enrichment, String> {
    use std::collections::BTreeSet;
    // Dedup so a CVE shared across advisories doesn't multiply rate-limited lookups.
    let cves: Vec<String> = report
        .vulnerabilities
        .iter()
        .flat_map(|v| v.aliases.iter().filter(|a| a.starts_with("CVE-")).cloned())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect();
    // NVD CVSS backfill only targets unknown-severity findings (the few that need it).
    let backfill_cves: Vec<String> = report
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == Severity::Unknown)
        .flat_map(|v| v.aliases.iter().filter(|a| a.starts_with("CVE-")).cloned())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect();
    Enrichment::fetch(&cves, &backfill_cves)
}

/// Pure-Rust build: enrichment fetch is unavailable; use the local `*_file` paths.
#[cfg(not(feature = "network"))]
pub(crate) fn fetch_enrichment(_report: &FleetReport) -> Result<Enrichment, String> {
    Err(
        "enrichment fetch needs the `network` feature; supply --kev-file / --epss-file, \
         or rebuild with --features network"
            .to_string(),
    )
}

fn checkout_rev(path: &Path, rev: &str) -> Result<(), String> {
    let status = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["checkout", "--quiet", rev])
        .status()
        .map_err(|e| format!("running git: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("git checkout {rev} failed in {}", path.display()))
    }
}

pub(crate) fn check_db_age(db: &AdvisoryDb, spec: &str) -> Result<(), String> {
    let limit = parse_duration_secs(spec)?;
    match db.age_seconds() {
        Some(age) if age <= limit => Ok(()),
        Some(age) => Err(format!(
            "advisory DB is {age}s old, older than --max-db-age {limit}s"
        )),
        None => Err("cannot determine advisory DB age; refusing under --max-db-age".to_string()),
    }
}

/// Parse a duration like `7d`, `24h`, `30m`, `90s`, or a bare seconds count.
fn parse_duration_secs(spec: &str) -> Result<i64, String> {
    let spec = spec.trim();
    let (digits, mult) = match spec.chars().last() {
        Some('d') => (&spec[..spec.len() - 1], 86_400),
        Some('h') => (&spec[..spec.len() - 1], 3_600),
        Some('m') => (&spec[..spec.len() - 1], 60),
        Some('s') => (&spec[..spec.len() - 1], 1),
        _ => (spec, 1),
    };
    digits
        .trim()
        .parse::<i64>()
        .map(|n| n * mult)
        .map_err(|_| format!("invalid duration `{spec}`"))
}

/// Best-effort toolchain detection via `rustc --version`. A missing or
/// unparseable rustc simply skips the toolchain scan (not an error).
pub(crate) fn detect_toolchain() -> Option<Toolchain> {
    let output = Command::new("rustc").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let token = text.split_whitespace().nth(1)?; // "rustc <token> (...)"
    let version = Version::parse(token).ok()?;
    Some(Toolchain {
        channel: format!("rustc {token}"),
        version,
    })
}

pub(crate) fn build_provenance(meta: &DatabaseMeta) -> Provenance {
    Provenance {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        rustsec_crate_version: RUSTSEC_VERSION.to_string(),
        db_commit: meta.commit.clone(),
        db_timestamp: meta.timestamp.clone(),
        host_os: std::env::consts::OS.to_string(),
        host_arch: std::env::consts::ARCH.to_string(),
        generated_at: now_rfc3339(),
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}
