//! `fleetreach whatif`: what a set of bumps would do to a saved report, before any lockfile
//! moves (spec 16, row 2).
//!
//! A bump names a package and a target version, for the whole fleet or one repo. It comes
//! from `--bump`, from the first items of the remediation queue (`--top`), or from a
//! `fix plan` file (`--plan`). Every in-repo occurrence of the package below the target is
//! raised to it, and the target is matched again with the same OSV exports `fix plan` reads,
//! in the ecosystem's own version order. What comes out, per bump and per repo:
//!
//! - **cleared**: findings (an advisory in a repo) with no copy left that the advisory covers;
//! - **remaining**: findings on a bumped package the target does not clear, with whether some
//!   of their copies moved off;
//! - **new**: advisories that cover the target and covered none of the versions it replaces.
//!
//! Without an export for the ecosystem (and always for Go and GitHub Actions) the report's own
//! fixed ranges decide what clears, and new findings are not looked for; a warning says so.
//! Packages the target pulls in need the registry, and stay with the re-scan `fix apply` runs.
//! Image findings are left as they are: an image takes a bump at its next build.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use clap::{Args, ValueEnum};
use fleetreach_core::semver::Version;
use fleetreach_core::{remediations, Action, Ecosystem, FleetReport, Occurrence, Severity};
use serde::Serialize;

use crate::cli::fail;
use crate::config::Config;
use crate::fix::{Plan, Strategy};
use crate::fix_targets::{self, Hit, Lookup};
use crate::osvdb;

/// The schema of `whatif -f json`.
pub const SCHEMA: &str = "fleetreach-whatif/1";

#[derive(Args)]
pub struct WhatifArgs {
    /// The saved report (`fleetreach scan -f json > report.json`)
    #[arg(long)]
    report: PathBuf,
    /// A bump to try, `[ECOSYSTEM:]PACKAGE@VERSION` (repeatable); the ecosystem is needed only
    /// when the package name is in more than one
    #[arg(long, value_name = "BUMP")]
    bump: Vec<String>,
    /// Try the first N upgrades of the remediation queue
    #[arg(long, value_name = "N")]
    top: Option<usize>,
    /// Try every edit of a `fix plan` file that is not blocked, each in its own repo
    #[arg(long, value_name = "PLAN")]
    plan: Option<PathBuf>,
    /// Apply `--bump` and `--top` bumps to this repo only
    #[arg(long, value_name = "REPO")]
    repo: Option<String>,
    /// fleet.toml, for `[settings.osv]`; `./fleet.toml` is read when it exists
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Directory of OSV exports to match targets against
    #[arg(long, value_name = "DIR")]
    osv_dir: Option<PathBuf>,
    #[arg(short, long, value_enum, default_value_t = Format::Table)]
    format: Format,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Table,
    Json,
}

/// One bump to try.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Bump {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub to: String,
    /// Every repo with the package when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
}

/// A finding: one advisory in one repo.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Finding {
    pub repo: String,
    pub advisory: String,
    pub severity: Severity,
    pub package: String,
    /// The versions it was on.
    pub from: Vec<String>,
    /// For a remaining finding: whether this bump clears its own copies and other copies keep
    /// the finding open.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub partly: bool,
    /// For a new finding: the version that carries it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

/// What one bump does.
#[derive(Debug, Serialize)]
pub struct BumpOutcome {
    #[serde(flatten)]
    pub bump: Bump,
    /// The repos it moves.
    pub repos: Vec<String>,
    pub cleared: Vec<Finding>,
    pub remaining: Vec<Finding>,
    pub new: Vec<Finding>,
    /// Whether new findings were looked for (an export was read for the ecosystem).
    pub checked_new: bool,
}

/// Open findings by severity.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
    pub total: usize,
}

impl Counts {
    fn add(&mut self, severity: Severity, n: isize) {
        let slot = match severity {
            Severity::Critical => &mut self.critical,
            Severity::High => &mut self.high,
            Severity::Medium => &mut self.medium,
            Severity::Low => &mut self.low,
            Severity::Unknown => &mut self.unknown,
        };
        *slot = slot.saturating_add_signed(n);
        self.total = self.total.saturating_add_signed(n);
    }
}

#[derive(Debug, Serialize)]
pub struct RepoOutcome {
    pub repo: String,
    pub before: Counts,
    pub after: Counts,
    pub cleared: usize,
    pub new: usize,
}

#[derive(Debug, Serialize)]
pub struct WhatIf {
    pub schema: &'static str,
    pub bumps: Vec<BumpOutcome>,
    pub repos: Vec<RepoOutcome>,
    pub before: Counts,
    pub after: Counts,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Parses `[ECOSYSTEM:]PACKAGE@VERSION`. The ecosystem prefix is read only when the text
/// before the first `:` names one, since Maven coordinates hold a `:` of their own.
fn parse_bump(text: &str, report: &FleetReport, repo: Option<&str>) -> Result<Bump, String> {
    let (spec, to) = text
        .rsplit_once('@')
        .filter(|(p, v)| !p.is_empty() && !v.is_empty())
        .ok_or_else(|| format!("`{text}`: expected [ECOSYSTEM:]PACKAGE@VERSION"))?;
    let named = spec
        .split_once(':')
        .and_then(|(eco, rest)| Some((osvdb::parse_ecosystem(eco)?, rest)));
    let (ecosystem, package) = match named {
        Some((eco, package)) => (eco, package.to_string()),
        None => {
            let ecosystems: BTreeSet<Ecosystem> = report
                .vulnerabilities
                .iter()
                .filter(|v| v.occurrences.iter().any(|o| package_of(o) == Some(spec)))
                .map(|v| v.ecosystem)
                .collect();
            match ecosystems.len() {
                1 => (
                    ecosystems.into_iter().next().unwrap_or_default(),
                    spec.to_string(),
                ),
                0 => return Err(format!("`{text}`: no finding in the report is on `{spec}`")),
                _ => {
                    let names: Vec<String> = ecosystems.iter().map(|e| eco_name(*e)).collect();
                    return Err(format!(
                        "`{text}`: `{spec}` is in {}; name one, as `{}:{spec}@{to}`",
                        names.join(" and "),
                        names[0]
                    ));
                }
            }
        }
    };
    Ok(Bump {
        ecosystem,
        package,
        to: to.to_string(),
        repo: repo.map(str::to_string),
    })
}

fn eco_name(ecosystem: Ecosystem) -> String {
    serde_json::to_value(ecosystem)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn package_of(occ: &Occurrence) -> Option<&str> {
    match occ {
        Occurrence::InRepo {
            package,
            layer: None,
            ..
        } => Some(package),
        _ => None,
    }
}

/// The first `n` actionable upgrades of the remediation queue, in its fix-first order.
pub fn top_bumps(report: &FleetReport, n: usize, repo: Option<&str>) -> Vec<Bump> {
    let items = remediations(report);
    let mut active: Vec<&fleetreach_core::RemediationItem> =
        items.iter().filter(|i| i.reach.is_actionable()).collect();
    fleetreach_report::fix_first(report, &mut active);
    let upgrades = active.into_iter().filter_map(|i| match &i.action {
        Action::Upgrade { to, .. } => Some(Bump {
            ecosystem: i.ecosystem,
            package: i.package.clone(),
            to: to.to_string(),
            repo: repo.map(str::to_string),
        }),
        Action::NoFixAvailable => None,
    });
    upgrades.take(n).collect()
}

/// Every edit of a plan that is not blocked, in its own repo.
pub fn plan_bumps(plan: &Plan) -> Vec<Bump> {
    let edits = plan
        .edits
        .iter()
        .filter(|e| e.strategy != Strategy::Blocked);
    let bumps = edits.filter(|e| !e.to.is_empty()).map(|e| Bump {
        ecosystem: e.ecosystem,
        package: e.package.clone(),
        to: e.to.clone(),
        repo: Some(e.repo.clone()),
    });
    let mut out: Vec<Bump> = Vec::new();
    for bump in bumps {
        if !out.contains(&bump) {
            out.push(bump);
        }
    }
    out
}

/// Whether `installed` sits below `to`; a pair that does not parse is left alone.
fn below(ecosystem: Ecosystem, installed: &str, to: &str) -> bool {
    fix_targets::order(ecosystem, installed, to) == Some(Ordering::Less)
}

fn names(v: &fleetreach_core::VulnFinding) -> BTreeSet<&str> {
    let all = std::iter::once(&v.advisory_id).chain(&v.aliases);
    all.map(String::as_str).collect()
}

fn hit_names(hit: &Hit) -> impl Iterator<Item = &String> {
    std::iter::once(&hit.id).chain(&hit.aliases)
}

fn covers(hit: &Hit, ids: &BTreeSet<&str>) -> bool {
    ids.contains(hit.id.as_str()) || hit.aliases.iter().any(|a| ids.contains(a.as_str()))
}

/// The bump that applies to an occurrence: a repo's own bump wins over a fleet-wide one.
fn bump_for<'a>(
    bumps: &'a [Bump],
    ecosystem: Ecosystem,
    repo: &str,
    package: &str,
) -> Option<(usize, &'a Bump)> {
    let on = |b: &&Bump| b.ecosystem == ecosystem && b.package == package;
    let own = bumps
        .iter()
        .enumerate()
        .find(|(_, b)| on(b) && b.repo.as_deref() == Some(repo));
    own.or_else(|| {
        bumps
            .iter()
            .enumerate()
            .find(|(_, b)| on(b) && b.repo.is_none())
    })
}

/// Runs the bumps over the report. `lookups` holds the readers of the exports that loaded.
pub(crate) fn evaluate(
    report: &FleetReport,
    bumps: &[Bump],
    lookups: &BTreeMap<Ecosystem, Lookup>,
) -> WhatIf {
    let mut outcomes: Vec<BumpOutcome> = bumps
        .iter()
        .map(|b| BumpOutcome {
            bump: b.clone(),
            repos: Vec::new(),
            cleared: Vec::new(),
            remaining: Vec::new(),
            new: Vec::new(),
            checked_new: lookups.contains_key(&b.ecosystem),
        })
        .collect();
    let (mut before, mut after) = (Counts::default(), Counts::default());
    let mut per_repo: BTreeMap<String, RepoOutcome> = BTreeMap::new();
    let repo_entry = |per_repo: &mut BTreeMap<String, RepoOutcome>, repo: &str| {
        per_repo
            .entry(repo.to_string())
            .or_insert_with(|| RepoOutcome {
                repo: repo.to_string(),
                before: Counts::default(),
                after: Counts::default(),
                cleared: 0,
                new: 0,
            });
    };
    // (bump, repo) -> the versions it moved off, and the report's ids already in that repo.
    let mut moved: BTreeMap<(usize, String), BTreeSet<String>> = BTreeMap::new();
    let mut seen: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for v in &report.vulnerabilities {
        let ids = names(v);
        // repo (or toolchain channel) -> (open after?, any moved?, bump, package, versions)
        let mut units: BTreeMap<String, Unit> = BTreeMap::new();
        for occ in v.occurrences.iter().filter(|o| o.is_vulnerable()) {
            let (key, open) = match occ {
                Occurrence::InRepo {
                    repo,
                    package,
                    installed,
                    patched,
                    layer,
                    ..
                } => {
                    seen.entry(repo.0.clone())
                        .or_default()
                        .extend(ids.iter().map(|s| s.to_string()));
                    let installed = installed.to_string();
                    let bump = bump_for(bumps, v.ecosystem, &repo.0, package)
                        .filter(|_| layer.is_none())
                        .filter(|(_, b)| below(v.ecosystem, &installed, &b.to));
                    let open = match bump {
                        None => true,
                        Some((i, b)) => {
                            moved
                                .entry((i, repo.0.clone()))
                                .or_default()
                                .insert(installed.clone());
                            match lookups.get(&v.ecosystem).and_then(|l| l(package, &b.to)) {
                                Some(hits) => hits.iter().any(|h| covers(h, &ids)),
                                // No export: the report's fixed ranges decide.
                                None => !fixed_by(patched, &b.to),
                            }
                        }
                    };
                    if let Some((i, _)) = bump {
                        let unit = units.entry(repo.0.clone()).or_default();
                        let moved = unit.bumps.entry(i).or_default();
                        moved.from.insert(installed);
                        moved.open |= open;
                    }
                    (repo.0.clone(), open)
                }
                Occurrence::Toolchain { channel, .. } => (format!("toolchain {channel}"), true),
            };
            units.entry(key).or_default().open |= open;
        }
        for (repo, unit) in units {
            repo_entry(&mut per_repo, &repo);
            let row = per_repo.get_mut(&repo);
            before.add(v.severity, 1);
            if let Some(row) = row {
                row.before.add(v.severity, 1);
                if unit.open {
                    row.after.add(v.severity, 1);
                } else {
                    row.cleared += 1;
                }
            }
            if unit.open {
                after.add(v.severity, 1);
            }
            for (i, moved) in unit.bumps {
                let Some(out) = outcomes.get_mut(i) else {
                    continue;
                };
                let finding = Finding {
                    repo: repo.clone(),
                    advisory: v.advisory_id.clone(),
                    severity: v.severity,
                    package: out.bump.package.clone(),
                    from: moved.from.into_iter().collect(),
                    partly: unit.open && !moved.open,
                    at: None,
                };
                if unit.open {
                    out.remaining.push(finding);
                } else {
                    out.cleared.push(finding);
                }
            }
        }
    }

    // New findings: advisories on the target that covered none of the versions it replaces.
    for ((i, repo), from) in &moved {
        let Some(out) = outcomes.get_mut(*i) else {
            continue;
        };
        out.repos.push(repo.clone());
        let Some(lookup) = lookups.get(&out.bump.ecosystem) else {
            continue;
        };
        let Some(on_target) = lookup(&out.bump.package, &out.bump.to) else {
            continue;
        };
        let known = seen.get(repo);
        let old: Vec<Hit> = from
            .iter()
            .filter_map(|v| lookup(&out.bump.package, v))
            .flatten()
            .collect();
        // Records that alias each other (a GHSA and a RUSTSEC id for one issue) count once.
        let mut taken: BTreeSet<String> = BTreeSet::new();
        for hit in on_target {
            let before_too = old
                .iter()
                .any(|o| hit_names(&hit).any(|n| hit_names(o).any(|m| m == n)));
            let in_report = known.is_some_and(|k| hit_names(&hit).any(|n| k.contains(n)));
            let twice = hit_names(&hit).any(|n| taken.contains(n));
            if before_too || in_report || twice {
                continue;
            }
            taken.extend(hit_names(&hit).cloned());
            after.add(hit.severity, 1);
            if let Some(row) = per_repo.get_mut(repo) {
                row.after.add(hit.severity, 1);
                row.new += 1;
            }
            out.new.push(Finding {
                repo: repo.clone(),
                advisory: hit.id.clone(),
                severity: hit.severity,
                package: out.bump.package.clone(),
                from: from.iter().cloned().collect(),
                partly: false,
                at: Some(out.bump.to.clone()),
            });
        }
    }
    for out in &mut outcomes {
        out.cleared.sort();
        out.remaining.sort();
        out.new.sort();
        out.new.dedup();
    }
    let mut warnings = Vec::new();
    let unread: BTreeSet<Ecosystem> = bumps
        .iter()
        .map(|b| b.ecosystem)
        .filter(|e| !lookups.contains_key(e))
        .collect();
    for eco in unread {
        warnings.push(format!(
            "no advisory export read for {}: its bumps are judged by the report's fixed \
             ranges, and new findings on the targets were not looked for",
            eco_name(eco)
        ));
    }
    for out in &outcomes {
        if out.repos.is_empty() {
            let b = &out.bump;
            warnings.push(format!(
                "{} {}: no repo has it below {} in a finding",
                eco_name(b.ecosystem),
                b.package,
                b.to
            ));
        }
    }
    WhatIf {
        schema: SCHEMA,
        bumps: outcomes,
        repos: per_repo.into_values().collect(),
        before,
        after,
        warnings,
    }
}

#[derive(Default)]
struct Unit {
    open: bool,
    /// The bumps that move a copy, with the versions each moves off. One advisory can sit on
    /// several packages (`lodash`, `lodash-es`), each with its own bump.
    bumps: BTreeMap<usize, Moved>,
}

/// The copies one bump moves within a finding.
#[derive(Default)]
struct Moved {
    from: BTreeSet<String>,
    /// Whether any of them stays covered at the target.
    open: bool,
}

/// Whether the report's fixed ranges take in `to`.
fn fixed_by(patched: &[fleetreach_core::semver::VersionReq], to: &str) -> bool {
    let Ok(to) = Version::parse(to.strip_prefix('v').unwrap_or(to)) else {
        return false;
    };
    patched.iter().any(|req| req.matches(&to))
}

fn render_table(w: &WhatIf) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "what-if: {} bump(s)", w.bumps.len());
    for b in &w.bumps {
        let where_ = match &b.bump.repo {
            Some(repo) => repo.clone(),
            None if b.repos.len() == 1 => "1 repo".to_string(),
            None => format!("{} repos", b.repos.len()),
        };
        let new = if b.checked_new {
            b.new.len().to_string()
        } else {
            "not checked".to_string()
        };
        let _ = writeln!(
            s,
            "  {} {} -> {} ({}): clears {}, leaves {}, new {}",
            eco_name(b.bump.ecosystem),
            b.bump.package,
            b.bump.to,
            where_,
            b.cleared.len(),
            b.remaining.len(),
            new
        );
    }
    let row = |label: &str, c: &Counts| {
        format!(
            "  {label:<8} {:>8} {:>5} {:>6} {:>4} {:>7} {:>6}\n",
            c.critical, c.high, c.medium, c.low, c.unknown, c.total
        )
    };
    s.push_str("\nopen findings  critical  high medium  low unknown  total\n");
    s.push_str(&row("before", &w.before));
    s.push_str(&row("after", &w.after));
    let changed: Vec<&RepoOutcome> = w
        .repos
        .iter()
        .filter(|r| r.cleared > 0 || r.new > 0)
        .collect();
    if !changed.is_empty() {
        s.push_str("\nper repo\n");
        for r in changed {
            let _ = writeln!(
                s,
                "  {}: {} -> {} (cleared {}, new {})",
                r.repo, r.before.total, r.after.total, r.cleared, r.new
            );
        }
    }
    let remaining: Vec<&Finding> = w.bumps.iter().flat_map(|b| &b.remaining).collect();
    if !remaining.is_empty() {
        s.push_str("\nstill open on bumped packages\n");
        for f in remaining {
            let partly = if f.partly { " (some copies moved)" } else { "" };
            let _ = writeln!(
                s,
                "  {} {} {}: {} {}{partly}",
                f.repo,
                f.advisory,
                format!("{:?}", f.severity).to_lowercase(),
                f.package,
                f.from.join(", ")
            );
        }
    }
    let new: Vec<&Finding> = w.bumps.iter().flat_map(|b| &b.new).collect();
    if !new.is_empty() {
        s.push_str("\nnew on the targets\n");
        for f in new {
            let _ = writeln!(
                s,
                "  {} {} {}: {} {}",
                f.repo,
                f.advisory,
                format!("{:?}", f.severity).to_lowercase(),
                f.package,
                f.at.as_deref().unwrap_or_default()
            );
        }
    }
    s
}

fn load_lookups(
    bumps: &[Bump],
    args: &WhatifArgs,
    config: Option<&Config>,
) -> (BTreeMap<Ecosystem, Lookup>, Vec<String>) {
    let needed: Vec<Ecosystem> = bumps
        .iter()
        .map(|b| b.ecosystem)
        .filter(|e| fix_targets::readable(*e))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let osv = config.map(|c| &c.osv);
    let opts = osvdb::Options {
        dir: args
            .osv_dir
            .clone()
            .or_else(|| std::env::var_os(osvdb::DIR_ENV).map(PathBuf::from))
            .or_else(|| osv.and_then(|o| o.dir.clone())),
        cache: osvdb::default_cache_dir(),
        sync: false,
        refresh: osv
            .and_then(|o| o.refresh)
            .unwrap_or(osvdb::DEFAULT_REFRESH),
        quiet: true,
    };
    let (sources, mut warnings) = osvdb::resolve_all(&needed, &BTreeMap::new(), &opts);
    let overlay = osv.and_then(|o| o.advisories.as_deref());
    let mut lookups = BTreeMap::new();
    for (eco, source) in sources {
        let wanted = fix_targets::Wanted::of(
            bumps
                .iter()
                .filter(|b| b.ecosystem == eco)
                .map(|b| b.package.as_str()),
        );
        match fix_targets::lookup(eco, &source.path, overlay, &wanted) {
            Ok(Some(found)) => {
                lookups.insert(eco, found);
            }
            Ok(None) => {}
            Err(e) => warnings.push(format!("{} export could not be read: {e}", eco_name(eco))),
        }
    }
    (lookups, warnings)
}

pub fn run_whatif(args: &WhatifArgs) -> u8 {
    let report: FleetReport = match std::fs::read_to_string(&args.report)
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
    {
        Ok(report) => report,
        Err(e) => return fail(&format!("{}: {e}", args.report.display())),
    };
    let default = PathBuf::from("./fleet.toml");
    let path = args
        .config
        .as_ref()
        .or(default.is_file().then_some(&default));
    let config = match path {
        Some(path) => match Config::load(path) {
            Ok(config) => Some(config),
            Err(e) => return fail(&e.to_string()),
        },
        None => None,
    };
    let repo = args.repo.as_deref();
    let mut bumps = Vec::new();
    for text in &args.bump {
        match parse_bump(text, &report, repo) {
            Ok(bump) => bumps.push(bump),
            Err(e) => return fail(&e),
        }
    }
    if let Some(n) = args.top {
        bumps.extend(top_bumps(&report, n, repo));
    }
    if let Some(path) = &args.plan {
        let plan: Plan = match std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
        {
            Ok(plan) => plan,
            Err(e) => return fail(&format!("{}: {e}", path.display())),
        };
        bumps.extend(plan_bumps(&plan));
    }
    if bumps.is_empty() {
        return fail("nothing to try: pass --bump, --top or --plan");
    }
    let (lookups, load_warnings) = load_lookups(&bumps, args, config.as_ref());
    let mut out = evaluate(&report, &bumps, &lookups);
    out.warnings.splice(0..0, load_warnings);
    for w in &out.warnings {
        eprintln!("warning: {w}");
    }
    match args.format {
        Format::Table => print!("{}", render_table(&out)),
        Format::Json => match serde_json::to_string_pretty(&out) {
            Ok(text) => println!("{text}"),
            Err(e) => return fail(&e.to_string()),
        },
    }
    0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use fleetreach_core::semver::VersionReq;
    use fleetreach_core::{
        DependencyKind, Provenance, RepoId, Summary, VulnFinding, SCHEMA_VERSION,
    };

    fn occ(repo: &str, pkg: &str, installed: &str, patched: &[&str]) -> Occurrence {
        Occurrence::InRepo {
            repo: RepoId(repo.into()),
            package: pkg.into(),
            installed: Version::parse(installed).unwrap(),
            patched: patched
                .iter()
                .map(|p| VersionReq::parse(p).unwrap())
                .collect(),
            dependency_kind: DependencyKind::Transitive,
            dependency_path: vec![],
            active: None,
            source: Default::default(),
            scope: Default::default(),
            layer: None,
        }
    }

    fn vuln(
        id: &str,
        eco: Ecosystem,
        severity: Severity,
        occurrences: Vec<Occurrence>,
    ) -> VulnFinding {
        VulnFinding {
            advisory_id: id.into(),
            aliases: vec![],
            ecosystem: eco,
            title: id.into(),
            severity,
            cvss_score: None,
            cvss_vector: None,
            url: None,
            occurrences,
            affected_functions: vec![],
            reachable: None,
            reachability: None,
            exploit: Default::default(),
        }
    }

    fn report(vulnerabilities: Vec<VulnFinding>) -> FleetReport {
        FleetReport {
            schema_version: SCHEMA_VERSION,
            provenance: Provenance {
                tool_version: "t".into(),
                rustsec_crate_version: "t".into(),
                db_commit: None,
                db_timestamp: None,
                db_snapshot: None,
                host_os: "t".into(),
                host_arch: "t".into(),
                generated_at: "t".into(),
                osv: Vec::new(),
                sources: Vec::new(),
                images: Vec::new(),
            },
            summary: Summary {
                repos_scanned: 0,
                repos_errored: 0,
                vuln_count: vulnerabilities.len(),
                warn_count: 0,
                max_severity: Severity::Unknown,
                stale_ignores: vec![],
            },
            vulnerabilities,
            warnings: vec![],
            outcomes: vec![],
            coverage: Vec::new(),
            context: Vec::new(),
            ssvc: None,
            package_versions: Vec::new(),
            base_images: Vec::new(),
            set_aside: Vec::new(),
        }
    }

    fn bump(eco: Ecosystem, package: &str, to: &str, repo: Option<&str>) -> Bump {
        Bump {
            ecosystem: eco,
            package: package.into(),
            to: to.into(),
            repo: repo.map(Into::into),
        }
    }

    /// A lookup over a fixed table: (package, id, severity, versions it covers).
    fn table(
        rows: &'static [(
            &'static str,
            &'static str,
            Severity,
            &'static [&'static str],
        )],
    ) -> Lookup {
        Box::new(move |name, version| {
            let found = rows
                .iter()
                .filter(|(p, _, _, vs)| *p == name && vs.contains(&version));
            Some(
                found
                    .map(|(_, id, severity, _)| Hit {
                        id: (*id).into(),
                        aliases: vec![],
                        severity: *severity,
                    })
                    .collect(),
            )
        })
    }

    #[test]
    fn fixed_ranges_decide_without_an_export() {
        let r = report(vec![
            vuln(
                "A-1",
                Ecosystem::Go,
                Severity::High,
                vec![occ("api", "x", "1.0.0", &[">=1.2.0"])],
            ),
            vuln(
                "A-2",
                Ecosystem::Go,
                Severity::Low,
                vec![occ("api", "x", "1.0.0", &[">=2.0.0"])],
            ),
            vuln(
                "A-3",
                Ecosystem::Go,
                Severity::Low,
                vec![occ("web", "y", "1.0.0", &[">=1.1.0"])],
            ),
        ]);
        let out = evaluate(
            &r,
            &[bump(Ecosystem::Go, "x", "1.2.0", None)],
            &BTreeMap::new(),
        );
        let b = &out.bumps[0];
        assert_eq!(
            b.cleared
                .iter()
                .map(|f| f.advisory.as_str())
                .collect::<Vec<_>>(),
            ["A-1"]
        );
        assert_eq!(
            b.remaining
                .iter()
                .map(|f| f.advisory.as_str())
                .collect::<Vec<_>>(),
            ["A-2"]
        );
        assert!(!b.checked_new);
        assert_eq!(out.before.total, 3);
        assert_eq!(out.after.total, 2);
        assert_eq!(out.after.high, 0);
        assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
    }

    #[test]
    fn the_export_finds_advisories_new_on_the_target() {
        static ROWS: &[(&str, &str, Severity, &[&str])] = &[
            ("lodash", "OLD", Severity::High, &["4.17.15"]),
            ("lodash", "NEW", Severity::Medium, &["4.18.0"]),
            ("lodash", "BOTH", Severity::Low, &["4.17.15", "4.18.0"]),
        ];
        let r = report(vec![
            vuln(
                "OLD",
                Ecosystem::Npm,
                Severity::High,
                vec![occ("api", "lodash", "4.17.15", &[])],
            ),
            vuln(
                "BOTH",
                Ecosystem::Npm,
                Severity::Low,
                vec![occ("api", "lodash", "4.17.15", &[])],
            ),
        ]);
        let lookups = BTreeMap::from([(Ecosystem::Npm, table(ROWS))]);
        let out = evaluate(
            &r,
            &[bump(Ecosystem::Npm, "lodash", "4.18.0", None)],
            &lookups,
        );
        let b = &out.bumps[0];
        assert_eq!(b.cleared.len(), 1);
        assert_eq!(b.remaining[0].advisory, "BOTH");
        assert_eq!(b.new.len(), 1);
        assert_eq!(b.new[0].advisory, "NEW");
        assert_eq!(b.new[0].at.as_deref(), Some("4.18.0"));
        assert_eq!((out.before.total, out.after.total), (2, 2));
        assert_eq!((out.after.high, out.after.medium), (0, 1));
        assert_eq!(out.repos[0].new, 1);
    }

    #[test]
    fn a_copy_left_behind_keeps_the_finding_open() {
        // Two copies in one repo; the image copy does not take a bump.
        let mut image = occ("img", "x", "1.0.0", &[">=1.2.0"]);
        if let Occurrence::InRepo { layer, .. } = &mut image {
            *layer = Some(serde_json::from_str(r#"{"index":0}"#).unwrap());
        }
        let r = report(vec![vuln(
            "A-1",
            Ecosystem::Cargo,
            Severity::High,
            vec![
                occ("api", "x", "1.0.0", &[">=1.2.0"]),
                occ("api", "x", "1.3.0", &[">=1.4.0"]),
                image,
            ],
        )]);
        let out = evaluate(
            &r,
            &[bump(Ecosystem::Cargo, "x", "1.2.0", None)],
            &BTreeMap::new(),
        );
        let b = &out.bumps[0];
        // 1.0.0 moves to 1.2.0; 1.3.0 is above the target and stays affected.
        assert!(b.cleared.is_empty());
        assert_eq!(b.remaining.len(), 1);
        assert!(b.remaining[0].partly);
        assert_eq!(b.repos, ["api"]);
        assert_eq!(out.after.total, 2);
    }

    #[test]
    fn one_advisory_on_two_packages_needs_both_bumps() {
        let r = report(vec![vuln(
            "A-1",
            Ecosystem::Npm,
            Severity::High,
            vec![
                occ("api", "lodash", "4.17.21", &[">=4.18.0"]),
                occ("api", "lodash-es", "4.17.21", &[">=4.18.0"]),
            ],
        )]);
        let one = [bump(Ecosystem::Npm, "lodash", "4.18.0", None)];
        let out = evaluate(&r, &one, &BTreeMap::new());
        let f = &out.bumps[0].remaining[0];
        assert_eq!((f.package.as_str(), f.partly), ("lodash", true));
        let both = [
            bump(Ecosystem::Npm, "lodash", "4.18.0", None),
            bump(Ecosystem::Npm, "lodash-es", "4.18.0", None),
        ];
        let out = evaluate(&r, &both, &BTreeMap::new());
        assert_eq!(out.bumps[0].cleared[0].package, "lodash");
        assert_eq!(out.bumps[1].cleared[0].package, "lodash-es");
        assert_eq!(out.after.total, 0);
    }

    #[test]
    fn a_repo_bump_wins_over_a_fleet_bump() {
        let r = report(vec![vuln(
            "A-1",
            Ecosystem::Cargo,
            Severity::High,
            vec![
                occ("api", "x", "1.0.0", &[">=2.0.0"]),
                occ("web", "x", "1.0.0", &[">=2.0.0"]),
            ],
        )]);
        let bumps = [
            bump(Ecosystem::Cargo, "x", "2.0.0", None),
            bump(Ecosystem::Cargo, "x", "1.1.0", Some("api")),
        ];
        let out = evaluate(&r, &bumps, &BTreeMap::new());
        assert_eq!(out.bumps[0].cleared[0].repo, "web");
        assert_eq!(out.bumps[1].remaining[0].repo, "api");
    }

    #[test]
    fn bumps_parse_with_and_without_an_ecosystem() {
        let r = report(vec![
            vuln(
                "A",
                Ecosystem::Npm,
                Severity::Low,
                vec![occ("a", "@scope/pkg", "1.0.0", &[])],
            ),
            vuln(
                "B",
                Ecosystem::Npm,
                Severity::Low,
                vec![occ("a", "both", "1.0.0", &[])],
            ),
            vuln(
                "C",
                Ecosystem::Pypi,
                Severity::Low,
                vec![occ("a", "both", "1.0.0", &[])],
            ),
        ]);
        let b = parse_bump("@scope/pkg@1.2.3", &r, None).unwrap();
        assert_eq!(
            (b.ecosystem, b.package.as_str(), b.to.as_str()),
            (Ecosystem::Npm, "@scope/pkg", "1.2.3")
        );
        let m = parse_bump("maven:org.apache:commons@2.0", &r, Some("a")).unwrap();
        assert_eq!(
            (m.ecosystem, m.package.as_str()),
            (Ecosystem::Maven, "org.apache:commons")
        );
        assert_eq!(m.repo.as_deref(), Some("a"));
        assert!(parse_bump("both@2.0.0", &r, None)
            .unwrap_err()
            .contains("name one"));
        assert!(parse_bump("pypi:both@2.0.0", &r, None).is_ok());
        assert!(parse_bump("missing@1.0.0", &r, None).is_err());
        assert!(parse_bump("nover", &r, None).is_err());
    }

    #[test]
    fn versions_order_by_the_ecosystem() {
        assert!(below(Ecosystem::Pypi, "2.0.0rc1", "2.0.0"));
        assert!(below(Ecosystem::Maven, "1.9.0", "1.10"));
        assert!(!below(Ecosystem::Cargo, "1.2.0", "1.2.0"));
        assert!(below(Ecosystem::Go, "1.2.0", "v1.3.0"));
    }
}
