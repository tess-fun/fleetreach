//! The `vex` subcommands: product/assertion resolution shared by `-f vex` and
//! SARIF, the pure cores of `vex check` (drift) and `vex verify` (witnesses), and
//! the `Check`/`Verify` argument structs + runners. The binary only parses and
//! dispatches into [`run_vex_check`]/[`run_vex_verify`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use clap::Parser;
use fleetreach_core::{FleetReport, Occurrence, Provenance, ReachVerdict, Severity, VulnFinding};
use fleetreach_go::SandboxPolicy;
use fleetreach_report as report;
use fleetreach_scan::AdvisoryDb;

use crate::assemble::{assemble, Assembled, SuppressedOccurrence, Suppression};
use crate::cli::{fail, usage_fail, BuildSandbox};
use crate::config::{Config, Repo};
use crate::db::{build_provenance, load_db_from};
use crate::orchestrate::{
    scan_fleet, GhActionsScan, GoScan, HexScan, JuliaScan, MavenScan, NpmScan, NuGetScan,
    PackagistScan, PyPiScan, RubyGemsScan, SwiftScan,
};
use crate::static_reach;

/// Resolve a product `@id` (§4.3) for every repo, keyed by repo id.
pub fn resolve_product_ids(config: &Config) -> BTreeMap<String, String> {
    let base = config.vex.product_id_base.as_deref();
    config
        .repos
        .iter()
        .map(|repo| (repo.id.0.clone(), resolve_product_id(repo, base)))
        .collect()
}

/// Resolve a repo's product `@id` (§4.3): explicit config, else the publishable-crate
/// PURL, else `product_id_base` + id, else a `urn:` fallback.
pub fn resolve_product_id(repo: &Repo, base: Option<&str>) -> String {
    if let Some(id) = &repo.vex_product_id {
        return id.clone();
    }
    if let Some(purl) = crate_purl(&repo.path) {
        return purl;
    }
    match base {
        Some(base) => format!("{base}{}", repo.id.0),
        None => format!("urn:fleetreach:product:{}", repo.id.0),
    }
}

/// The `pkg:cargo/<name>@<version>` PURL for a repo root that is itself a publishable
/// crate. `None` for a virtual/workspace manifest, an inherited version, or `publish = false`.
fn crate_purl(repo_path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(repo_path.join("Cargo.toml")).ok()?;
    let value: toml::Value = toml::from_str(&text).ok()?;
    let pkg = value.get("package")?.as_table()?;
    if pkg.get("publish").and_then(toml::Value::as_bool) == Some(false) {
        return None;
    }
    let name = pkg.get("name")?.as_str()?;
    // A workspace-inherited version is a table, not a string -> fall back.
    let version = pkg.get("version")?.as_str()?;
    Some(format!("pkg:cargo/{name}@{version}"))
}

/// Promote each suppressed occurrence (an ignore or `vex_assertion`) into a human
/// `not_affected` (§6), shared by the VEX and SARIF paths. `warn_free_text` nudges
/// once per advisory toward a machine `justification` label.
pub fn build_human_assertions(
    suppressed: &[SuppressedOccurrence],
    product_ids: &BTreeMap<String, String>,
    warn_free_text: bool,
) -> Vec<report::HumanAssertion> {
    let mut assertions = Vec::new();
    let mut nudged: BTreeSet<&str> = BTreeSet::new();
    for s in suppressed {
        let Occurrence::InRepo {
            repo,
            package,
            installed,
            ..
        } = &s.occurrence
        else {
            continue;
        };
        let Some(product_id) = product_ids.get(&repo.0) else {
            continue;
        };
        if warn_free_text && s.justification.is_none() && nudged.insert(&s.advisory_id) {
            eprintln!(
                "warning: vex suppression for {} uses a free-text reason; \
                 prefer a `justification` label for machine consumers",
                s.advisory_id
            );
        }
        assertions.push(report::HumanAssertion {
            advisory_id: s.advisory_id.clone(),
            aliases: s.aliases.clone(),
            product_id: product_id.clone(),
            package: package.clone(),
            version: installed.to_string(),
            justification: s.justification.clone(),
            impact_statement: s.impact_statement.clone(),
            approved_by: s.approved_by.clone(),
        });
    }
    assertions
}

/// Minimal [`report::VexParams`] for [`report::project`]; the envelope fields
/// (author/timestamp) are unused by projection.
pub fn projection_params(
    product_ids: BTreeMap<String, String>,
    assertions: Vec<report::HumanAssertion>,
) -> report::VexParams {
    report::VexParams {
        author: String::new(),
        role: None,
        scope: report::VexScope::Runtime,
        timestamp: String::new(),
        doc_id: None,
        product_id_base: None,
        product_ids,
        assertions,
        only_sound: false,
        alias_rustbinary: false,
        include_fixed: false,
        version: 1,
        supersedes: None,
    }
}

/// A plain fresh scan assembled with the config's ignores + vex_assertions, for
/// `vex check`/`verify` to compare against a committed document.
pub fn assemble_fresh(config: &Config, db: &AdvisoryDb, provenance: Provenance) -> Assembled {
    // No govulncheck binary or npm/PyPI mirror here, so Go/npm/PyPI repos surface as gaps
    // before any work — the sandbox policy + DB mirrors are moot; `None` is the neutral
    // choice.
    let scan = scan_fleet(
        db,
        config,
        None,
        None,
        &GoScan {
            govulncheck: None,
            sandbox: SandboxPolicy::Off,
            vuln_db: None,
            offline: false,
        },
        &NpmScan { vuln_db: None },
        &PyPiScan { vuln_db: None },
        &RubyGemsScan { vuln_db: None },
        &PackagistScan { vuln_db: None },
        &NuGetScan { vuln_db: None },
        &JuliaScan { vuln_db: None },
        &SwiftScan { vuln_db: None },
        &HexScan { vuln_db: None },
        &GhActionsScan { vuln_db: None },
        &MavenScan { vuln_db: None },
    );
    let mut suppressions: Vec<Suppression> = config
        .ignores
        .iter()
        .map(Suppression::from_ignore)
        .collect();
    suppressions.extend(
        config
            .vex_assertions
            .iter()
            .map(Suppression::from_assertion),
    );
    assemble(scan, &suppressions, None, provenance)
}

// ---- `vex check` drift (§10) ----

/// The drift between a fresh projection and a committed document (§10).
pub struct Drift {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// A committed VEX statement's identity, status, and authoring role, parsed from a
/// document for the drift gate.
pub struct CommittedStatement {
    pub vulnerability: String,
    pub product: String,
    pub subcomponent: String,
    pub status: String,
    /// `status_notes`, used to tell a human assertion (`role=Human Assertion`) from
    /// machine analysis (`role=Automated Analysis`). Only a human `not_affected` is
    /// status-checked here; a machine one can't be reproduced by a plain scan.
    pub status_notes: String,
}

impl CommittedStatement {
    /// Whether this is a human-authored assertion — the only `not_affected` kind a
    /// plain scan can re-derive (the assertion lives in config), so the only kind we
    /// status-check. A machine `not_affected` (reachability / phantom) is left to
    /// `vex verify`, which actually reproduces it.
    fn is_human(&self) -> bool {
        self.status_notes.contains("Human Assertion")
    }
}

/// Diff a fresh projection against committed statements (§10):
/// - a current statement absent from the document is **untriaged** (error);
/// - a committed `not_affected` whose key is gone is **stale** (error);
/// - a committed **human** `not_affected` whose key is still present but whose
///   current status is no longer `not_affected` is a **dropped suppression**
///   (error) — the assertion was removed or no longer applies. Only human
///   statements are status-checked: a plain scan can't reproduce a machine
///   `not_affected` (no `--reachability=static`), so checking its status would
///   false-flag every one; that case is `vex verify`'s job.
/// - a still-present gating-severity `under_investigation` is a **warning**.
pub fn check_drift(
    current: &[report::StatementView],
    committed: &[CommittedStatement],
    severity: &BTreeMap<String, Severity>,
) -> Drift {
    let key = |v: &str, p: &str, s: &str| (v.to_string(), p.to_string(), s.to_string());
    let current_keys: BTreeSet<(String, String, String)> = current
        .iter()
        .map(|s| key(&s.vulnerability, &s.product, &s.subcomponent))
        .collect();
    // The current status per key, so a committed human `not_affected` can be
    // compared against what the fresh scan now reports for the same statement.
    let current_status: BTreeMap<(String, String, String), &str> = current
        .iter()
        .map(|s| {
            (
                key(&s.vulnerability, &s.product, &s.subcomponent),
                s.status.as_str(),
            )
        })
        .collect();
    let committed_keys: BTreeSet<(String, String, String)> = committed
        .iter()
        .map(|c| key(&c.vulnerability, &c.product, &c.subcomponent))
        .collect();

    let mut errors = Vec::new();
    for s in current {
        if !current_in(
            &committed_keys,
            &s.vulnerability,
            &s.product,
            &s.subcomponent,
        ) {
            errors.push(format!(
                "untriaged: {} on {} has no statement in the committed document",
                s.vulnerability, s.subcomponent
            ));
        }
    }
    for c in committed {
        if c.status != "not_affected" {
            continue;
        }
        let k = key(&c.vulnerability, &c.product, &c.subcomponent);
        match current_status.get(&k) {
            // Key gone: the suppression pins a version that moved.
            None => errors.push(format!(
                "stale not_affected: {} on {} no longer appears in the fleet \
                 (the suppression pins a version that moved)",
                c.vulnerability, c.subcomponent
            )),
            // Key present but status downgraded — only checkable for human
            // assertions (a machine verdict isn't reproduced by a plain scan).
            Some(&now) if now != "not_affected" && c.is_human() => errors.push(format!(
                "dropped suppression: {} on {} is not_affected in the committed \
                 document (human assertion) but the current scan reports {now} — \
                 the assertion was removed or no longer applies",
                c.vulnerability, c.subcomponent
            )),
            Some(_) => {}
        }
    }
    let mut warnings: BTreeSet<String> = BTreeSet::new();
    for c in committed {
        if c.status == "under_investigation"
            && current_in(&current_keys, &c.vulnerability, &c.product, &c.subcomponent)
            && is_gating_severity(severity.get(&c.vulnerability).copied())
        {
            warnings.insert(format!(
                "{} is still under_investigation at gating severity; \
                 resolve with --reachability=static",
                c.vulnerability
            ));
        }
    }
    Drift {
        errors,
        warnings: warnings.into_iter().collect(),
    }
}

fn current_in(keys: &BTreeSet<(String, String, String)>, v: &str, p: &str, s: &str) -> bool {
    keys.contains(&(v.to_string(), p.to_string(), s.to_string()))
}

/// One [`CommittedStatement`] per statement in the document; missing fields default
/// to empty (surfaced as drift, never a panic).
pub fn parse_committed_statements(doc: &serde_json::Value) -> Vec<CommittedStatement> {
    let Some(stmts) = doc.get("statements").and_then(|s| s.as_array()) else {
        return Vec::new();
    };
    let field = |s: &serde_json::Value, ptr: &str| {
        s.pointer(ptr)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };
    stmts
        .iter()
        .map(|s| CommittedStatement {
            vulnerability: field(s, "/vulnerability/name"),
            product: field(s, "/products/0/@id"),
            subcomponent: field(s, "/subcomponents/0/@id"),
            status: field(s, "/status"),
            status_notes: field(s, "/status_notes"),
        })
        .collect()
}

/// A gating-severity advisory is one we cannot prove is low-risk: High, Critical,
/// or Unknown (fail-closed, consistent with the scan gate).
pub fn is_gating_severity(severity: Option<Severity>) -> bool {
    matches!(
        severity,
        Some(Severity::High) | Some(Severity::Critical) | Some(Severity::Unknown) | None
    )
}

// ---- `vex verify` witnesses (§9.2) ----

/// The reachability `not_affected` statements `(vulnerability, subcomponent)` that
/// `vex verify` re-derives. Phantom and human assertions are out of scope.
pub fn committed_reachability_witnesses(doc: &serde_json::Value) -> Vec<(String, String)> {
    fn str_at<'a>(s: &'a serde_json::Value, ptr: &str) -> &'a str {
        s.pointer(ptr).and_then(|v| v.as_str()).unwrap_or_default()
    }
    let Some(stmts) = doc.get("statements").and_then(|s| s.as_array()) else {
        return Vec::new();
    };
    stmts
        .iter()
        .filter(|s| {
            str_at(s, "/status") == "not_affected"
                && str_at(s, "/justification") == "vulnerable_code_not_in_execute_path"
                // Only machine witnesses are re-derivable; a human assertion using the
                // same label is trust-based.
                && str_at(s, "/status_notes").contains("Automated Analysis")
        })
        .map(|s| {
            (
                str_at(s, "/vulnerability/name").to_string(),
                str_at(s, "/subcomponents/0/@id").to_string(),
            )
        })
        .collect()
}

/// Witnesses that no longer hold against the fresh `report`: the advisory is still
/// present but no longer a definite `NotReachable`. A disappeared advisory holds
/// vacuously. Pure, so unit-tested without the reach-driver.
pub fn failed_reachability_witnesses(
    witnesses: &[(String, String)],
    report: &FleetReport,
) -> Vec<(String, String)> {
    let by_advisory: BTreeMap<&str, &VulnFinding> = report
        .vulnerabilities
        .iter()
        .map(|v| (v.advisory_id.as_str(), v))
        .collect();
    witnesses
        .iter()
        .filter(|(vuln, _)| match by_advisory.get(vuln.as_str()) {
            None => false,
            Some(finding) => !matches!(
                finding.reachability.as_ref().map(|r| &r.verdict),
                Some(ReachVerdict::NotReachable)
            ),
        })
        .cloned()
        .collect()
}

// ---- `vex` subcommand arguments + runners ----

#[derive(Parser)]
pub(crate) struct VexCheckArgs {
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,
    #[arg(
        long,
        value_name = "PATH",
        help = "the committed OpenVEX document to check against"
    )]
    against: PathBuf,

    // advisory DB control (mirrors `scan`)
    #[arg(long, help = "use a local advisory-db clone instead of fetching")]
    db: Option<PathBuf>,
    #[arg(long, help = "pin advisory DB to an exact commit (requires --db)")]
    db_rev: Option<String>,
    #[arg(long, help = "never fetch; require cache/--db")]
    offline: bool,

    #[arg(short, long, help = "suppress the summary line")]
    quiet: bool,
}

#[derive(Parser)]
pub(crate) struct VexVerifyArgs {
    /// The OpenVEX document whose machine witnesses to re-check.
    #[arg(value_name = "DOCUMENT")]
    document: PathBuf,
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,

    // advisory DB control (mirrors `scan`)
    #[arg(long, help = "use a local advisory-db clone instead of fetching")]
    db: Option<PathBuf>,
    #[arg(long, help = "pin advisory DB to an exact commit (requires --db)")]
    db_rev: Option<String>,
    #[arg(long, help = "never fetch; require cache/--db")]
    offline: bool,

    // static reachability (re-derivation COMPILES each repo — same gates as scan)
    #[arg(
        long,
        help = "REQUIRED: re-deriving witnesses compiles each repo, running its build scripts and proc-macros (arbitrary code). Only verify repos you trust."
    )]
    allow_untrusted_builds: bool,
    #[arg(
        long,
        value_name = "PATH",
        help = "path to the built fleetreach-reach-driver"
    )]
    reach_driver: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "auto", value_name = "MODE")]
    build_sandbox: BuildSandbox,
    #[arg(long, value_name = "FEATURES", value_delimiter = ',')]
    features: Vec<String>,
    #[arg(long)]
    all_features: bool,
    #[arg(long)]
    no_default_features: bool,

    #[arg(short, long, help = "suppress the summary line")]
    quiet: bool,
    #[arg(short, long, help = "per-repo progress to stderr")]
    verbose: bool,
}

/// `vex check` (§10): fail (exit 1) when a committed OpenVEX document has drifted
/// from a fresh scan — a stale `not_affected` (pinned version gone) or an untriaged
/// finding. A gating-severity `under_investigation` is a warning; exit 2 = can't-scan.
pub(crate) fn run_vex_check(args: VexCheckArgs) -> u8 {
    let config = match Config::load(&args.config) {
        Ok(config) => config,
        Err(e) => return fail(&e.to_string()),
    };
    let db = match load_db_from(args.db.as_deref(), args.db_rev.as_deref(), args.offline) {
        Ok(db) => db,
        Err(e) => return fail(&e),
    };
    let committed_text = match std::fs::read_to_string(&args.against) {
        Ok(text) => text,
        Err(e) => {
            return fail(&format!(
                "reading committed VEX `{}`: {e}",
                args.against.display()
            ))
        }
    };
    let committed: serde_json::Value = match serde_json::from_str(&committed_text) {
        Ok(value) => value,
        Err(e) => {
            return fail(&format!(
                "parsing committed VEX `{}`: {e}",
                args.against.display()
            ))
        }
    };

    let provenance = build_provenance(&db.meta());
    let Assembled { report, suppressed } = assemble_fresh(&config, &db, provenance);
    let product_ids = resolve_product_ids(&config);
    let assertions = build_human_assertions(&suppressed, &product_ids, false);
    let params = projection_params(product_ids, assertions);
    let current = report::project(&report, &params);

    let committed_stmts = parse_committed_statements(&committed);
    let severity: BTreeMap<String, Severity> = report
        .vulnerabilities
        .iter()
        .map(|v| (v.advisory_id.clone(), v.severity))
        .collect();
    let drift = check_drift(&current, &committed_stmts, &severity);

    for w in &drift.warnings {
        eprintln!("warning: {w}");
    }
    for e in &drift.errors {
        eprintln!("error: {e}");
    }
    if !args.quiet {
        eprintln!(
            "vex check: {} current statement(s), {} committed; {} drift error(s), {} warning(s).",
            current.len(),
            committed_stmts.len(),
            drift.errors.len(),
            drift.warnings.len()
        );
    }
    u8::from(!drift.errors.is_empty())
}

/// `vex verify` (§9.2): re-derive each reachability `not_affected` witness against
/// current source, failing (exit 1) if any no longer holds. COMPILES each repo, so
/// it needs the same consent + driver as `scan --reachability=static` (else exit 3).
pub(crate) fn run_vex_verify(args: VexVerifyArgs) -> u8 {
    if !args.allow_untrusted_builds {
        return usage_fail(
            "vex verify re-derives witnesses by COMPILING each repo (build scripts + \
             proc-macros run). Re-run with --allow-untrusted-builds only if you trust every repo.",
        );
    }
    let Some(driver) = args.reach_driver.as_deref() else {
        return usage_fail("vex verify requires --reach-driver <PATH>");
    };
    let config = match Config::load(&args.config) {
        Ok(config) => config,
        Err(e) => return fail(&e.to_string()),
    };
    let committed_text = match std::fs::read_to_string(&args.document) {
        Ok(text) => text,
        Err(e) => return fail(&format!("reading `{}`: {e}", args.document.display())),
    };
    let committed: serde_json::Value = match serde_json::from_str(&committed_text) {
        Ok(value) => value,
        Err(e) => return fail(&format!("parsing `{}`: {e}", args.document.display())),
    };

    let targets = committed_reachability_witnesses(&committed);
    if targets.is_empty() {
        if !args.quiet {
            eprintln!("vex verify: no reachability witnesses to re-derive.");
        }
        return 0;
    }

    let db = match load_db_from(args.db.as_deref(), args.db_rev.as_deref(), args.offline) {
        Ok(db) => db,
        Err(e) => return fail(&e),
    };
    let provenance = build_provenance(&db.meta());
    let Assembled {
        mut report,
        suppressed: _,
    } = assemble_fresh(&config, &db, provenance);

    let features = fleetreach_reach::FeatureSelection {
        all_features: args.all_features,
        no_default_features: args.no_default_features,
        features: args.features.clone(),
    };
    static_reach::assess(
        &mut report,
        &config,
        &static_reach::Options {
            driver,
            features,
            sandbox: args.build_sandbox.into(),
            verbose: args.verbose,
        },
    );

    let failed = failed_reachability_witnesses(&targets, &report);
    for (vuln, sub) in &failed {
        eprintln!("error: witness no longer holds: {vuln} on {sub} is now reachable or undecided");
    }
    if !args.quiet {
        eprintln!(
            "vex verify: {} witness(es) re-derived, {} failed.",
            targets.len(),
            failed.len()
        );
    }
    u8::from(!failed.is_empty())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fleetreach_core::semver::Version;
    use fleetreach_core::{DependencyKind, Provenance, Reachability, RepoId, Summary, VulnFinding};
    use fleetreach_report::StatementView;

    fn finding_with_reach(id: &str, reach: Option<ReachVerdict>) -> VulnFinding {
        VulnFinding {
            advisory_id: id.into(),
            aliases: vec![],
            ecosystem: Default::default(),
            title: "t".into(),
            severity: Severity::High,
            cvss_score: None,
            url: None,
            occurrences: vec![Occurrence::InRepo {
                repo: RepoId("app".into()),
                package: "foo".into(),
                installed: Version::new(1, 0, 0),
                patched: vec![],
                dependency_kind: DependencyKind::Direct,
                dependency_path: vec![],
                active: None,
                source: Default::default(),
            }],
            affected_functions: vec!["foo::bad".into()],
            reachable: None,
            reachability: reach.map(|verdict| Reachability {
                verdict,
                config: "nightly".into(),
                engine: "e".into(),
                targets: vec!["x86_64-unknown-linux-gnu".into()],
                witness: Some("sha256:abc".into()),
            }),
            exploit: Default::default(),
        }
    }

    fn report_of(vulns: Vec<VulnFinding>) -> FleetReport {
        FleetReport {
            schema_version: 1,
            provenance: Provenance {
                tool_version: "0".into(),
                rustsec_crate_version: "0".into(),
                db_commit: None,
                db_timestamp: None,
                host_os: "linux".into(),
                host_arch: "x86_64".into(),
                generated_at: "t".into(),
            },
            summary: Summary {
                repos_scanned: 1,
                repos_errored: 0,
                vuln_count: vulns.len(),
                warn_count: 0,
                max_severity: Severity::High,
                stale_ignores: vec![],
            },
            vulnerabilities: vulns,
            warnings: vec![],
            outcomes: vec![],
        }
    }

    fn view(v: &str, p: &str, s: &str, status: &str) -> StatementView {
        StatementView {
            vulnerability: v.into(),
            product: p.into(),
            subcomponent: s.into(),
            status: status.into(),
        }
    }

    fn committed(v: &str, p: &str, s: &str, status: &str, notes: &str) -> CommittedStatement {
        CommittedStatement {
            vulnerability: v.into(),
            product: p.into(),
            subcomponent: s.into(),
            status: status.into(),
            status_notes: notes.into(),
        }
    }

    #[test]
    fn drift_flags_untriaged_and_stale() {
        let current = vec![view(
            "RUSTSEC-NEW",
            "p",
            "pkg:cargo/foo@1",
            "under_investigation",
        )];
        let committed = vec![committed(
            "RUSTSEC-OLD",
            "p",
            "pkg:cargo/bar@1",
            "not_affected",
            "role=Automated Analysis",
        )];
        let drift = check_drift(&current, &committed, &BTreeMap::new());
        assert_eq!(drift.errors.len(), 2, "untriaged + stale");
        assert!(drift.warnings.is_empty());
    }

    #[test]
    fn drift_is_empty_when_in_sync() {
        let current = vec![view("RUSTSEC-A", "p", "s", "not_affected")];
        let committed = vec![committed(
            "RUSTSEC-A",
            "p",
            "s",
            "not_affected",
            "role=Human Assertion; approved_by=x",
        )];
        let drift = check_drift(&current, &committed, &BTreeMap::new());
        assert!(drift.errors.is_empty());
    }

    /// A human `not_affected` whose assertion was removed: the finding reappears as
    /// `under_investigation` in the plain scan (same key, new status) → drift.
    #[test]
    fn dropped_human_suppression_is_flagged() {
        let current = vec![view("RUSTSEC-A", "p", "s", "under_investigation")];
        let committed = vec![committed(
            "RUSTSEC-A",
            "p",
            "s",
            "not_affected",
            "role=Human Assertion; approved_by=x",
        )];
        let drift = check_drift(&current, &committed, &BTreeMap::new());
        assert_eq!(drift.errors.len(), 1, "dropped suppression");
        assert!(drift.errors[0].contains("dropped suppression"));
    }

    /// A machine `not_affected` reads as `under_investigation` in the plain scan
    /// (reachability didn't run) — status-checking it would false-flag, so it must
    /// NOT drift. (Re-deriving it is `vex verify`'s job.)
    #[test]
    fn machine_not_affected_is_not_status_checked() {
        let current = vec![view("RUSTSEC-A", "p", "s", "under_investigation")];
        let committed = vec![committed(
            "RUSTSEC-A",
            "p",
            "s",
            "not_affected",
            "role=Automated Analysis; static call-graph: no path",
        )];
        let drift = check_drift(&current, &committed, &BTreeMap::new());
        assert!(
            drift.errors.is_empty(),
            "machine not_affected must not be status-checked: {:?}",
            drift.errors
        );
    }

    /// Only machine reachability `not_affected` are witnesses; human assertions excluded.
    #[test]
    fn extracts_only_machine_reachability_witnesses() {
        let doc = serde_json::json!({ "statements": [
            { "vulnerability": { "name": "RUSTSEC-A" },
              "subcomponents": [{ "@id": "pkg:cargo/foo@1.0.0" }],
              "status": "not_affected",
              "justification": "vulnerable_code_not_in_execute_path",
              "status_notes": "role=Automated Analysis; static call-graph: no path" },
            { "vulnerability": { "name": "RUSTSEC-H" },
              "subcomponents": [{ "@id": "pkg:cargo/bar@2.0.0" }],
              "status": "not_affected",
              "justification": "vulnerable_code_not_in_execute_path",
              "status_notes": "role=Human Assertion; approved_by=x" },
            { "vulnerability": { "name": "RUSTSEC-U" },
              "subcomponents": [{ "@id": "pkg:cargo/baz@3.0.0" }],
              "status": "under_investigation" },
        ]});
        let w = committed_reachability_witnesses(&doc);
        assert_eq!(
            w,
            vec![("RUSTSEC-A".to_string(), "pkg:cargo/foo@1.0.0".to_string())]
        );
    }

    #[test]
    fn witness_holds_when_still_not_reachable() {
        let w = vec![("RUSTSEC-A".to_string(), "pkg:cargo/foo@1.0.0".to_string())];
        let report = report_of(vec![finding_with_reach(
            "RUSTSEC-A",
            Some(ReachVerdict::NotReachable),
        )]);
        assert!(failed_reachability_witnesses(&w, &report).is_empty());
    }

    #[test]
    fn witness_fails_when_now_reachable() {
        let w = vec![("RUSTSEC-A".to_string(), "pkg:cargo/foo@1.0.0".to_string())];
        let report = report_of(vec![finding_with_reach(
            "RUSTSEC-A",
            Some(ReachVerdict::Reachable {
                witness: vec!["main".into(), "foo::bad".into()],
            }),
        )]);
        assert_eq!(failed_reachability_witnesses(&w, &report).len(), 1);
    }

    #[test]
    fn witness_holds_vacuously_when_advisory_is_gone() {
        let w = vec![("RUSTSEC-A".to_string(), "pkg:cargo/foo@1.0.0".to_string())];
        assert!(failed_reachability_witnesses(&w, &report_of(vec![])).is_empty());
    }

    #[test]
    fn witness_fails_when_now_undecided() {
        let w = vec![("RUSTSEC-A".to_string(), "pkg:cargo/foo@1.0.0".to_string())];
        let report = report_of(vec![finding_with_reach("RUSTSEC-A", None)]);
        assert_eq!(failed_reachability_witnesses(&w, &report).len(), 1);
    }
}
