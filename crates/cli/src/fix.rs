//! `fleetreach fix`: turn the remediation queue into verified lockfile changes (spec 07,
//! phases 1 and 2).
//!
//! - `fix plan` reads a saved `scan -f json` report and writes one edit per repo per
//!   remediation item: a `lock-bump` when an ecosystem's lock-only update can apply it, a
//!   `manifest-bump` when the repo's own range leaves the target out, or `blocked` with the
//!   reason (no published fix, a semver-major jump without `--allow-breaking`, a range in a
//!   published package, an ecosystem `apply` does not handle yet). The ranges are read in
//!   [`crate::fix_constraints`].
//! - `fix apply` performs each `lock-bump` and `manifest-bump` in a git worktree on a `fleetreach/<campaign>/...`
//!   branch, never in the user's own work tree, with a lock-only command that runs no package
//!   code (`cargo update --precise`, `npm update --package-lock-only --ignore-scripts`, a
//!   text edit of a workflow `uses:` tag, `go get`, `uv lock --no-build`, and the updates in
//!   `crate::fix_managers`). It then **verifies** the change by running
//!   fleetreach's own scan on the work tree before and after: every targeted advisory must be
//!   gone, nothing new may appear, and the repo must still scan without errors or new
//!   coverage gaps. The commit stays on its branch either way, marked verified or not;
//!   nothing is pushed.
//!
//! A branch only ever moves to a verified commit. Work happens on a detached work tree, so a
//! failed rerun leaves the earlier verified branch as it was, an unverified result lands on a
//! `fleetreach-unverified/*` branch that is never pushed, and a branch already on the current
//! base is left alone, keeping its CI and reviews. With `--push` or `--open-pr` the base is the
//! remote's default branch, which is what rebases a stale request. `--close-obsolete` closes the
//! requests a newer plan no longer wants, and a branch someone else has pushed to is not touched.
//!
//! The scan runs as a subprocess of the same binary with the flags given after `--`, so a
//! verification sees exactly what `fleetreach scan` reports.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Args, Subcommand, ValueEnum};
use fleetreach_core::semver::Version;
use fleetreach_core::{
    line, remediations, upgrade_risk, Action, Ecosystem, FleetReport, Occurrence,
};
use serde::{Deserialize, Serialize};

use crate::cli::fail;
use crate::config::{Config, Repo};
use crate::fix_policy::{FixSettings, Group, RolloutGate};
use crate::{fix_constraints, fix_forges, fix_locks, fix_managers, fix_targets, osvdb, sources};

/// The plan file format.
const PLAN_SCHEMA: &str = "fleetreach-fix-plan/1";

#[derive(Subcommand)]
pub enum FixCommand {
    /// Write a fix plan (JSON, stdout) from a saved `scan -f json` report.
    Plan(FixPlanArgs),
    /// Apply a plan's lock and manifest bumps on local branches, each verified by a re-scan.
    Apply(FixApplyArgs),
    /// List each repo's fleetreach pull or merge requests and their state (via `gh` or
    /// `glab`).
    Status(FixStatusArgs),
}

#[derive(Args)]
pub struct FixStatusArgs {
    /// fleet.toml naming the repos
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,
    /// Where the repos are hosted; `auto` reads each repo's `origin` remote
    #[arg(long, value_enum, default_value_t = ForgeArg::Auto)]
    forge: ForgeArg,
    /// The forge's API base, when it cannot be read from `origin` (an ssh remote on another
    /// port, or a forge under a path), e.g. `https://git.example.com/api/v1`
    #[arg(long, value_name = "URL")]
    forge_api: Option<String>,
}

/// `--forge`: where the requests are opened and listed.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ForgeArg {
    /// From the `origin` host: GitLab when it names GitLab, Bitbucket Cloud for bitbucket.org,
    /// Azure DevOps for dev.azure.com, GitHub otherwise
    Auto,
    /// GitHub pull requests through `gh`
    Github,
    /// GitLab merge requests through `glab`
    Gitlab,
    /// Gitea pull requests through its API (`GITEA_TOKEN`)
    Gitea,
    /// Forgejo pull requests through its API (`FORGEJO_TOKEN`)
    Forgejo,
    /// Bitbucket Cloud pull requests through its API (`BITBUCKET_TOKEN`)
    Bitbucket,
    /// Bitbucket Data Center pull requests through its API (`BITBUCKET_SERVER_TOKEN`)
    BitbucketServer,
    /// Azure DevOps pull requests through its API (`AZURE_DEVOPS_TOKEN`)
    Azure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Forge {
    GitHub,
    GitLab,
    /// A forge reached through its REST API.
    Api(fix_forges::Target),
}

impl ForgeArg {
    /// The forge for the repo checked out at `dir`.
    fn resolve(self, dir: &Path, api: Option<&str>) -> Result<Forge, String> {
        let origin = || git(dir, &["remote", "get-url", "origin"]);
        let rest = |kind: fix_forges::Kind| -> Result<Forge, String> {
            let url = origin().map_err(|e| format!("no origin remote: {e}"))?;
            fix_forges::Target::from_remote(kind, &url, api).map(Forge::Api)
        };
        match self {
            ForgeArg::Github => Ok(Forge::GitHub),
            ForgeArg::Gitlab => Ok(Forge::GitLab),
            ForgeArg::Gitea => rest(fix_forges::Kind::Gitea),
            ForgeArg::Forgejo => rest(fix_forges::Kind::Forgejo),
            ForgeArg::Bitbucket => rest(fix_forges::Kind::Bitbucket),
            ForgeArg::BitbucketServer => rest(fix_forges::Kind::BitbucketServer),
            ForgeArg::Azure => rest(fix_forges::Kind::Azure),
            ForgeArg::Auto => {
                let host = origin().ok().and_then(|url| remote_host(&url));
                match host.as_deref() {
                    Some(h) if h.contains("gitlab") => Ok(Forge::GitLab),
                    Some("bitbucket.org") => rest(fix_forges::Kind::Bitbucket),
                    Some(h)
                        if h == "dev.azure.com"
                            || h == "ssh.dev.azure.com"
                            || h.ends_with(".visualstudio.com") =>
                    {
                        rest(fix_forges::Kind::Azure)
                    }
                    _ => Ok(Forge::GitHub),
                }
            }
        }
    }
}

impl Forge {
    fn name(&self) -> &'static str {
        match self {
            Forge::GitHub => "github",
            Forge::GitLab => "gitlab",
            Forge::Api(t) => t.kind.name(),
        }
    }
}

/// The host of a git remote: `https://gitlab.com/a/b.git` and `git@gitlab.com:a/b.git` both
/// give `gitlab.com`. `None` for a local path.
fn remote_host(url: &str) -> Option<String> {
    let authority = match url.split_once("://") {
        // `scheme://[user[:pass]@]host[:port]/path`
        Some((_, rest)) => rest
            .split('/')
            .next()?
            .rsplit('@')
            .next()?
            .split(':')
            .next()?,
        // scp-like `[user@]host:path`
        None if !url.starts_with('/') && url.contains(':') => {
            url.split(':').next()?.rsplit('@').next()?
        }
        None => return None,
    };
    (!authority.is_empty()).then(|| authority.to_ascii_lowercase())
}

#[derive(Args)]
pub struct FixPlanArgs {
    /// fleet.toml the report was scanned from
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,
    /// The saved report (`fleetreach scan -f json > report.json`)
    #[arg(long)]
    report: PathBuf,
    /// Plan semver-major (and 0.x minor) bumps too; they are blocked otherwise
    #[arg(long)]
    allow_breaking: bool,
    /// Directory of OSV exports, to keep targets clear of advisories of their own
    #[arg(long, value_name = "DIR")]
    osv_dir: Option<PathBuf>,
}

#[derive(Args)]
pub struct FixApplyArgs {
    /// fleet.toml naming the repos
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,
    /// The plan written by `fix plan`
    plan: PathBuf,
    /// Only these repo ids
    #[arg(long, value_delimiter = ',')]
    repos: Vec<String>,
    /// At most this many repos per run
    #[arg(long, default_value_t = 20)]
    max_repos: usize,
    /// Open at most this many new pull requests this run; open ones are still updated
    #[arg(long, value_name = "N")]
    max_prs: Option<usize>,
    /// Repos to try first; the rest of the run waits on every edit in them being verified
    #[arg(long, value_delimiter = ',', value_name = "REPOS")]
    canary: Vec<String>,
    /// Stop the run after this many edits that did not verify
    #[arg(long, value_name = "N")]
    stop_after_failures: Option<usize>,
    /// Close the open fleetreach requests this plan no longer wants, in repos it scanned
    #[arg(long)]
    close_obsolete: bool,
    /// Publish even outside the `[settings.fix] schedule` windows
    #[arg(long)]
    ignore_schedule: bool,
    #[arg(short, long, help = "no progress output")]
    quiet: bool,
    /// Push each verified branch to the repo's `origin` (only `fleetreach/*` branches;
    /// unverified ones are never pushed)
    #[arg(long)]
    push: bool,
    /// Open (or update) a pull request for each pushed branch with `gh`, or a GitLab merge
    /// request with `glab`; implies --push
    #[arg(long)]
    open_pr: bool,
    /// Open pull or merge requests as drafts
    #[arg(long)]
    draft: bool,
    /// Where the repos are hosted; `auto` reads each repo's `origin` remote
    #[arg(long, value_enum, default_value_t = ForgeArg::Auto)]
    forge: ForgeArg,
    /// The forge's API base, when it cannot be read from `origin`
    #[arg(long, value_name = "URL")]
    forge_api: Option<String>,
    /// Flags for the verifying scan, after `--` (e.g. `-- --db ./advisory-db --osv-dir ./osv`)
    #[arg(last = true)]
    scan_args: Vec<String>,
}

pub fn run_fix(command: FixCommand) -> u8 {
    match command {
        FixCommand::Plan(args) => run_plan(&args),
        FixCommand::Apply(args) => run_apply(&args),
        FixCommand::Status(args) => run_status(&args),
    }
}

// ---- plan ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Strategy {
    LockBump,
    /// A range in the repo's own manifest leaves the target out, so it is raised first.
    ManifestBump,
    Blocked,
}

/// One change to one repo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edit {
    /// Stable across runs for the same bump: `(ecosystem, package, to, advisories)`.
    pub campaign: String,
    pub repo: String,
    pub ecosystem: Ecosystem,
    pub package: String,
    /// The vulnerable versions present in this repo.
    pub from: Vec<String>,
    /// The version to move to (empty when no fix exists).
    pub to: String,
    pub advisories: Vec<String>,
    pub breaking: bool,
    pub strategy: Strategy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The upgrade's risk and why (spec 13), from the scan's fleet evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<fleetreach_core::Risk>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risk_reasons: Vec<String>,
    /// The most urgent SSVC outcome among the advisories in this repo, when the scan decided
    /// one; `[settings.fix] group = "ssvc"` splits requests by it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssvc: Option<fleetreach_core::ssvc::Outcome>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Plan {
    pub schema: String,
    pub edits: Vec<Edit>,
    /// The repos the report read in full. Only here can a request be called obsolete: a repo
    /// that errored says nothing about what it still needs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scanned: Vec<String>,
}

/// Ecosystems `fix apply` can bump without running package code.
fn applicable(ecosystem: Ecosystem) -> bool {
    matches!(
        ecosystem,
        Ecosystem::Cargo
            | Ecosystem::Npm
            | Ecosystem::GitHubActions
            | Ecosystem::Go
            | Ecosystem::Pypi
            | Ecosystem::Packagist
            | Ecosystem::RubyGems
            | Ecosystem::NuGet
            | Ecosystem::Maven
            | Ecosystem::Swift
            | Ecosystem::Hex
            | Ecosystem::Julia
    )
}

/// Build the plan from a report. Soundly unreachable items are left out (they are not work).
pub fn build_plan(report: &FleetReport, allow_breaking: bool) -> Plan {
    let mut edits = Vec::new();
    for item in remediations(report) {
        let report_has_fleet = report
            .package_versions
            .iter()
            .any(|p| p.ecosystem == item.ecosystem && p.package == item.package);
        if !item.reach.is_actionable() {
            continue;
        }
        let (to, breaking) = match &item.action {
            Action::Upgrade { to, breaking } => (to.to_string(), *breaking),
            Action::NoFixAvailable => (String::new(), false),
        };
        let campaign = campaign_id(item.ecosystem, &item.package, &to, &item.advisories);
        // Vulnerable versions per repo, from the findings this item groups.
        let mut per_repo: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for v in report
            .vulnerabilities
            .iter()
            .filter(|v| v.ecosystem == item.ecosystem && item.advisories.contains(&v.advisory_id))
        {
            for occ in &v.occurrences {
                if let Occurrence::InRepo {
                    repo,
                    package,
                    installed,
                    ..
                } = occ
                {
                    if *package == item.package {
                        per_repo
                            .entry(repo.0.clone())
                            .or_default()
                            .insert(installed.to_string());
                    }
                }
            }
        }
        let malware = item.advisories.iter().any(|a| a.starts_with("MAL-"));
        let strategy_for = |to: &str, breaking: bool| match &item.action {
            _ if malware => (
                Strategy::Blocked,
                Some(
                    "malicious package: remove it from the manifest and rotate credentials on \
                     machines that installed it; no version bump fixes malware"
                        .to_string(),
                ),
            ),
            Action::NoFixAvailable => (
                Strategy::Blocked,
                Some("no published fix; consider a VEX statement or a mitigation".to_string()),
            ),
            Action::Upgrade { .. } if breaking && !allow_breaking => (
                Strategy::Blocked,
                Some(format!(
                    "{to} is a breaking upgrade; pass --allow-breaking to plan it"
                )),
            ),
            Action::Upgrade { .. } if !applicable(item.ecosystem) => (
                Strategy::Blocked,
                Some(format!(
                    "fix apply does not handle {} yet",
                    ecosystem_name(item.ecosystem)
                )),
            ),
            Action::Upgrade { .. } => (Strategy::LockBump, None),
        };
        for (repo, from) in per_repo {
            let versions: Vec<Version> =
                from.iter().filter_map(|v| Version::parse(v).ok()).collect();
            let repo_line = versions.first().map(line);
            let on_one_line = versions.iter().all(|v| Some(line(v)) == repo_line);
            // A repo on an older line takes that line's fix when it clears everything there
            // (spec 13): a lock bump instead of a new major.
            let alternative = item.alternatives.iter().find(|a| {
                on_one_line && Some(line(&a.to)) == repo_line && a.leaves_open.is_empty()
            });
            let edit = match (alternative, &item.action) {
                (Some(alt), _) if !malware => {
                    let to = alt.to.to_string();
                    let (strategy, reason) = strategy_for(&to, false);
                    let (risk, mut risk_reasons) =
                        upgrade_risk(&alt.to, false, alt.evidence.as_ref(), report_has_fleet);
                    if let Action::Upgrade { to: main, .. } = &item.action {
                        risk_reasons.insert(1, format!("instead of {main}, a new major"));
                    }
                    Edit {
                        campaign: campaign_id(item.ecosystem, &item.package, &to, &alt.clears),
                        repo,
                        ecosystem: item.ecosystem,
                        package: item.package.clone(),
                        from: from.into_iter().collect(),
                        to,
                        advisories: alt.clears.clone(),
                        breaking: false,
                        strategy,
                        reason,
                        risk: Some(risk),
                        risk_reasons,
                        ssvc: None,
                    }
                }
                (_, action) => {
                    // The item's `breaking` is relative to the fleet's newest version; a repo
                    // on an older line crosses a major even when that newest one does not.
                    let (breaking, risk, risk_reasons) = match action {
                        Action::Upgrade {
                            to: target,
                            breaking: false,
                        } if versions.iter().any(|v| line(v) != line(target)) => {
                            let (risk, reasons) = upgrade_risk(
                                target,
                                true,
                                item.evidence.as_ref(),
                                report_has_fleet,
                            );
                            (true, Some(risk), reasons)
                        }
                        _ => (breaking, item.risk, item.risk_reasons.clone()),
                    };
                    let (strategy, reason) = strategy_for(&to, breaking);
                    Edit {
                        campaign: campaign.clone(),
                        repo,
                        ecosystem: item.ecosystem,
                        package: item.package.clone(),
                        from: from.into_iter().collect(),
                        to: to.clone(),
                        advisories: item.advisories.clone(),
                        breaking,
                        strategy,
                        reason,
                        risk,
                        risk_reasons,
                        ssvc: None,
                    }
                }
            };
            edits.push(edit);
        }
    }
    if let Some(ssvc) = &report.ssvc {
        for edit in &mut edits {
            edit.ssvc = ssvc
                .decisions
                .iter()
                .filter(|d| {
                    d.repo.0 == edit.repo
                        && d.package == edit.package
                        && edit.advisories.contains(&d.advisory_id)
                })
                .map(|d| d.outcome)
                .max();
        }
    }
    edits.sort_by(|a, b| (&a.repo, &a.campaign).cmp(&(&b.repo, &b.campaign)));
    let scanned = report
        .outcomes
        .iter()
        .filter(|o| matches!(o.status, fleetreach_core::ScanStatus::Scanned { .. }))
        .map(|o| o.repo.0.clone())
        .collect();
    Plan {
        schema: PLAN_SCHEMA.to_string(),
        edits,
        scanned,
    }
}

pub(crate) fn campaign_id(
    ecosystem: Ecosystem,
    package: &str,
    to: &str,
    advisories: &[String],
) -> String {
    use sha2::{Digest, Sha256};
    let key = format!(
        "{}\u{1f}{package}\u{1f}{to}\u{1f}{}",
        ecosystem_name(ecosystem),
        advisories.join(",")
    );
    Sha256::digest(key.as_bytes())
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn ecosystem_name(ecosystem: Ecosystem) -> String {
    serde_json::to_value(ecosystem)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Moves targets off advisories of their own, from the exports a scan would read. Never syncs:
/// `fix plan` stays offline, and a target left unchecked still meets the re-scan.
fn check_targets(plan: &mut Plan, args: &FixPlanArgs, config: &Config) -> usize {
    let opts = osvdb::Options {
        dir: args
            .osv_dir
            .clone()
            .or_else(|| std::env::var_os(osvdb::DIR_ENV).map(PathBuf::from))
            .or_else(|| config.osv.dir.clone()),
        cache: osvdb::default_cache_dir(),
        sync: false,
        refresh: config.osv.refresh.unwrap_or(osvdb::DEFAULT_REFRESH),
        quiet: true,
    };
    let needed = fix_targets::needed(&plan.edits);
    let (sources, mut warnings) = osvdb::resolve_all(&needed, &BTreeMap::new(), &opts);
    let exports = sources.into_iter().map(|(eco, s)| (eco, s.path)).collect();
    let overlay = config.osv.advisories.as_deref();
    let (moved, more) = fix_targets::check(&mut plan.edits, &exports, overlay, args.allow_breaking);
    warnings.extend(more);
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    moved
}

/// Checks each edit against the repo's manifests. A finding in an image or a repo no longer in
/// the fleet has no checkout to edit, so its edit is blocked instead of promised.
fn fit_to_checkouts(edits: &mut [Edit], repos: &[Repo]) {
    for edit in edits {
        match repos.iter().find(|r| r.id.0 == edit.repo) {
            Some(repo) => fix_constraints::constrain(edit, &repo.path),
            None if edit.strategy != Strategy::Blocked => {
                edit.strategy = Strategy::Blocked;
                edit.reason = Some(format!(
                    "`{}` has no checkout in fleet.toml; an image takes {} {} at its next build",
                    edit.repo, edit.package, edit.to
                ));
            }
            None => {}
        }
    }
}

fn run_plan(args: &FixPlanArgs) -> u8 {
    let config = match Config::load(&args.config) {
        Ok(config) => config,
        Err(e) => return fail(&e.to_string()),
    };
    let report: FleetReport = match std::fs::read_to_string(&args.report)
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
    {
        Ok(r) => r,
        Err(e) => return fail(&format!("report `{}`: {e}", args.report.display())),
    };
    let mut plan = build_plan(&report, args.allow_breaking);
    let moved = check_targets(&mut plan, args, &config);
    let mut repos = config.repos.clone();
    match sources::materialize(&config, false, true) {
        Ok(m) => repos.extend(m.repos),
        Err(e) => return fail(&e),
    }
    fit_to_checkouts(&mut plan.edits, &repos);
    match crate::cli::print_json(&plan) {
        Ok(()) => {
            let count = |strategy: Strategy| {
                let matching = plan.edits.iter().filter(|e| e.strategy == strategy);
                matching.count()
            };
            eprintln!(
                "{} edit(s): {} lock bump(s), {} manifest bump(s), {} blocked",
                plan.edits.len(),
                count(Strategy::LockBump),
                count(Strategy::ManifestBump),
                count(Strategy::Blocked)
            );
            if moved > 0 {
                eprintln!("{moved} target(s) moved or blocked for advisories of their own");
            }
            0
        }
        Err(e) => fail(&e),
    }
}

// ---- apply ----

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Outcome {
    /// Applied and verified: the targeted advisories are gone and nothing new appeared.
    Verified,
    /// Applied, but the re-scan did not confirm it; the branch is kept for inspection.
    Unverified,
    /// Not applied (tool missing or failed, nothing to change, not a git repo, ...).
    Blocked,
    /// Left out by the plan or the filters.
    Skipped,
    /// A request this plan no longer wants, closed by `--close-obsolete`.
    Closed,
}

#[derive(Debug, Serialize)]
struct Applied {
    repo: String,
    package: String,
    to: String,
    campaign: String,
    outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    branch: Option<String>,
    detail: String,
    /// The pull request opened or updated for the branch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pull_request: Option<String>,
    /// What the update ran and changed, for the pull request.
    #[serde(skip)]
    ran: String,
    /// A new request was opened, which `--max-prs` counts.
    #[serde(skip)]
    opened: bool,
}

impl Applied {
    fn new(edit: &Edit, outcome: Outcome, detail: &str) -> Applied {
        Applied {
            repo: edit.repo.clone(),
            package: edit.package.clone(),
            to: edit.to.clone(),
            campaign: edit.campaign.clone(),
            outcome,
            branch: None,
            detail: detail.to_string(),
            pull_request: None,
            ran: String::new(),
            opened: false,
        }
    }

    /// The edit landed nowhere it was meant to.
    fn failed(&self) -> bool {
        matches!(self.outcome, Outcome::Unverified | Outcome::Blocked)
    }
}

/// The fleetreach requests of each repo seen so far, by branch, as `(state, url)`.
/// A repo's requests by branch, as (state, url).
type RepoRequests = BTreeMap<String, (String, String)>;

#[derive(Default)]
struct Requests {
    by_repo: BTreeMap<String, Result<RepoRequests, String>>,
}

impl Requests {
    fn of(
        &mut self,
        repo: &Repo,
        forge: ForgeArg,
        api: Option<&str>,
    ) -> &Result<RepoRequests, String> {
        self.by_repo.entry(repo.id.0.clone()).or_insert_with(|| {
            let listed = list_requests(&forge.resolve(&repo.path, api)?, &repo.path)?;
            let text = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
            let mut out = RepoRequests::new();
            for request in listed {
                let state = text(&request["state"]);
                let branch = text(&request["branch"]);
                // A branch may have an old closed request and a newer open one.
                if state == "OPEN" || !out.contains_key(&branch) {
                    out.insert(branch, (state, text(&request["url"])));
                }
            }
            Ok(out)
        })
    }
}

/// Why an edit should not go ahead given the requests its branch already has.
fn settled(state: &str) -> Option<&'static str> {
    match state {
        "CLOSED" => Some("this request is closed, so it is not opened again"),
        "MERGED" => Some("this request is already merged; the plan is older than the merge"),
        _ => None,
    }
}

/// Edits that share one branch and one request (spec 16, row 5): a single bump with
/// `group = "package"`, or every bump of a repo (or of a repo and SSVC outcome) otherwise.
struct Unit<'a> {
    repo: String,
    branch: String,
    edits: Vec<&'a Edit>,
}

/// Split the edits into units, keeping the order they come in.
fn units<'a>(edits: &[&'a Edit], group: Group) -> Vec<Unit<'a>> {
    let mut out: Vec<Unit<'a>> = Vec::new();
    for edit in edits {
        let branch = unit_branch(edit, group);
        match out
            .iter_mut()
            .find(|u| u.repo == edit.repo && u.branch == branch)
        {
            Some(unit) => unit.edits.push(edit),
            None => out.push(Unit {
                repo: edit.repo.clone(),
                branch,
                edits: vec![edit],
            }),
        }
    }
    out
}

/// The branch an edit lands on under a grouping preset.
fn unit_branch(edit: &Edit, group: Group) -> String {
    match group {
        Group::Package => branch_name(edit),
        Group::Repo => "fleetreach/all".to_string(),
        Group::Ssvc => format!(
            "fleetreach/ssvc-{}",
            edit.ssvc.map_or("undecided", |o| o.label())
        ),
    }
}

/// How many of a campaign's requests, across the fleet, are merged, open and closed unmerged.
fn campaign_requests(
    campaign: &str,
    plan: &Plan,
    config: &Config,
    forge: ForgeArg,
    api: Option<&str>,
    requests: &mut Requests,
) -> Result<(usize, usize, usize), String> {
    let (mut merged, mut open, mut closed) = (0, 0, 0);
    for edit in plan.edits.iter().filter(|e| e.campaign == campaign) {
        let Some(repo) = config.repos.iter().find(|r| r.id.0 == edit.repo) else {
            continue;
        };
        let known = requests
            .of(repo, forge, api)
            .as_ref()
            .map_err(|e| format!("{}: {e}", edit.repo))?;
        match known
            .get(&branch_name(edit))
            .map(|(state, _)| state.as_str())
        {
            Some("MERGED") => merged += 1,
            Some("OPEN") => open += 1,
            Some("CLOSED") => closed += 1,
            _ => {}
        }
    }
    Ok((merged, open, closed))
}

fn run_apply(args: &FixApplyArgs) -> u8 {
    let mut config = match Config::load(&args.config) {
        Ok(c) => c,
        Err(e) => return fail(&e.to_string()),
    };
    match sources::materialize(&config, false, true) {
        Ok(m) => config.repos.extend(m.repos),
        Err(e) => return fail(&e),
    }
    let plan: Plan = match std::fs::read_to_string(&args.plan)
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
    {
        Ok(p) => p,
        Err(e) => return fail(&format!("plan `{}`: {e}", args.plan.display())),
    };
    if plan.schema != PLAN_SCHEMA {
        return fail(&format!(
            "plan `{}` is `{}`, expected `{PLAN_SCHEMA}`",
            args.plan.display(),
            plan.schema
        ));
    }
    let policy = config.fix.clone();
    let publishing = args.push || args.open_pr;
    if (publishing || args.close_obsolete) && !args.ignore_schedule {
        let now = jiff::Zoned::now();
        if !policy.open_at(&now) {
            let next = policy.next_open(&now).map_or_else(
                || "no window ahead".to_string(),
                |at| format!("it next opens {}", at.strftime("%a %Y-%m-%d %H:%M %Z")),
            );
            eprintln!(
                "outside [settings.fix] schedule ({}): nothing published; {next}, or pass \
                 --ignore-schedule",
                policy.timezone_name
            );
            println!("[]");
            return 0;
        }
    }
    let Some(work_root) = crate::osvdb::private_subdir("fix") else {
        return fail("no usable cache directory for fix work trees");
    };

    for canary in &args.canary {
        if !config.repos.iter().any(|r| &r.id.0 == canary) {
            return fail(&format!("--canary repo `{canary}` is not in fleet.toml"));
        }
    }
    let mut results: Vec<Applied> = Vec::new();
    // Canaries go first; sorting is stable, so the plan's order holds within each group.
    let is_canary = |repo: &str| args.canary.iter().any(|c| c == repo);
    let mut edits: Vec<&Edit> = Vec::new();
    for edit in &plan.edits {
        if edit.strategy == Strategy::Blocked {
            results.push(Applied::new(
                edit,
                Outcome::Skipped,
                edit.reason.as_deref().unwrap_or("blocked in the plan"),
            ));
        } else if args.repos.is_empty() || args.repos.contains(&edit.repo) {
            edits.push(edit);
        }
    }
    edits.sort_by_key(|e| !is_canary(&e.repo));

    let mut requests = Requests::default();
    let mut repos_touched: BTreeSet<String> = BTreeSet::new();
    let mut opened_by_campaign: BTreeMap<String, usize> = BTreeMap::new();
    let mut stopped: Option<String> = None;
    for unit in units(&edits, policy.group) {
        let skip_all = |results: &mut Vec<Applied>, outcome: Outcome, why: &str| {
            for edit in &unit.edits {
                results.push(Applied::new(edit, outcome.clone(), why));
            }
        };
        let failures = results.iter().filter(|r| r.failed()).count();
        if stopped.is_none() && args.stop_after_failures.is_some_and(|n| failures >= n) {
            stopped = Some(format!("stopped after {failures} failed edit(s)"));
        }
        let canary_failed = results.iter().any(|r| r.failed() && is_canary(&r.repo));
        if stopped.is_none() && canary_failed && !is_canary(&unit.repo) {
            stopped = Some("stopped: a canary repo did not verify".to_string());
        }
        if let Some(why) = &stopped {
            skip_all(&mut results, Outcome::Skipped, why);
            continue;
        }
        if !repos_touched.contains(&unit.repo) && repos_touched.len() >= args.max_repos {
            skip_all(
                &mut results,
                Outcome::Skipped,
                "over --max-repos for this run",
            );
            continue;
        }
        let Some(repo) = config.repos.iter().find(|r| r.id.0 == unit.repo) else {
            skip_all(&mut results, Outcome::Skipped, "repo not in fleet.toml");
            continue;
        };
        let mut has_open = false;
        if args.open_pr {
            match requests.of(repo, args.forge, args.forge_api.as_deref()) {
                Ok(known) => {
                    let state = known.get(&unit.branch).map(|(state, _)| state.as_str());
                    if let Some(why) = state.and_then(settled) {
                        skip_all(&mut results, Outcome::Skipped, why);
                        continue;
                    }
                    has_open = state == Some("OPEN");
                }
                // Unknown requests cannot be counted or respected.
                Err(e) => {
                    let detail = format!("could not list requests: {e}");
                    skip_all(&mut results, Outcome::Blocked, &detail);
                    continue;
                }
            }
        }
        // Gradual rollout: a campaign opens its next wave only once the last one merged.
        if args.open_pr && !has_open && !policy.rollout.is_empty() {
            let campaign = &unit.edits[0].campaign;
            let held = match campaign_requests(
                campaign,
                &plan,
                &config,
                args.forge,
                args.forge_api.as_deref(),
                &mut requests,
            ) {
                Err(e) => Some(format!("rollout: could not list requests: {e}")),
                Ok((merged, open, closed)) => {
                    let opened = opened_by_campaign.get(campaign).copied().unwrap_or(0);
                    match policy.rollout_allowance(merged, open, closed) {
                        RolloutGate::Stopped => Some(
                            "rollout stopped: a request of this campaign was closed without \
                             merging"
                                .to_string(),
                        ),
                        RolloutGate::Waiting if opened == 0 => Some(format!(
                            "rollout: waiting for this campaign's {open} open request(s) to merge"
                        )),
                        RolloutGate::Waiting => {
                            Some("rollout: this run already opened the current wave".to_string())
                        }
                        RolloutGate::Open(Some(n)) if opened >= n => Some(format!(
                            "rollout: this wave is {n} repo(s), already opened this run"
                        )),
                        RolloutGate::Open(_) => None,
                    }
                }
            };
            if let Some(why) = held {
                skip_all(&mut results, Outcome::Skipped, &why);
                continue;
            }
        }
        let opened = results.iter().filter(|r| r.opened).count();
        if !has_open && args.open_pr && args.max_prs.is_some_and(|n| opened >= n) {
            skip_all(
                &mut results,
                Outcome::Skipped,
                "over --max-prs for this run",
            );
            continue;
        }
        repos_touched.insert(unit.repo.clone());
        if !args.quiet {
            let what: Vec<String> = unit
                .edits
                .iter()
                .map(|e| format!("{} -> {}", e.package, e.to))
                .collect();
            eprintln!("{}: {} ...", unit.repo, what.join(", "));
        }
        let mut applied = if policy.group == Group::Package {
            vec![apply_one(
                unit.edits[0],
                repo,
                &work_root,
                &args.scan_args,
                publishing,
            )]
        } else {
            apply_group(
                &unit,
                policy.group,
                repo,
                &work_root,
                &args.scan_args,
                publishing,
            )
        };
        if publishing && applied.iter().any(|a| a.outcome == Outcome::Verified) {
            publish(
                &mut applied,
                &unit,
                policy.group,
                repo,
                &plan,
                args,
                &policy,
            );
        }
        for result in &applied {
            if result.opened {
                *opened_by_campaign
                    .entry(result.campaign.clone())
                    .or_default() += 1;
            }
            if !args.quiet {
                eprintln!(
                    "  {}: {:?}: {}",
                    result.package, result.outcome, result.detail
                );
            }
        }
        results.extend(applied);
    }
    if args.close_obsolete {
        close_obsolete(
            &plan,
            &config,
            args,
            policy.group,
            &mut requests,
            &mut results,
        );
    }

    if let Err(e) = crate::cli::print_json(&results) {
        return fail(&e);
    }
    let count = |o: Outcome| results.iter().filter(|r| r.outcome == o).count();
    eprintln!(
        "{} verified, {} unverified, {} blocked, {} skipped, {} closed{}",
        count(Outcome::Verified),
        count(Outcome::Unverified),
        count(Outcome::Blocked),
        count(Outcome::Skipped),
        count(Outcome::Closed),
        if publishing { "" } else { " (nothing pushed)" }
    );
    // Like scan: 0 when everything planned was verified, 1 when some edit did not land.
    u8::from(count(Outcome::Unverified) + count(Outcome::Blocked) > 0)
}

/// The commit a run builds on, and the branch's own head on the remote if it has one. When
/// publishing that is the remote's default branch, so a rerun rebases what went stale, and a
/// remote with no default branch yet falls back to `HEAD`.
fn base_and_remote(
    top: &Path,
    branch: &str,
    publishing: bool,
) -> Result<(String, Option<String>), String> {
    let head = git(top, &["rev-parse", "HEAD"])?;
    if !publishing {
        return Ok((head, None));
    }
    let tracking = |name: &str| format!("refs/remotes/origin/{name}");
    let fetch = |name: &str| {
        let spec = format!("+refs/heads/{name}:{}", tracking(name));
        git(top, &["fetch", "--quiet", "origin", &spec])
    };
    let symref = git(top, &["ls-remote", "--symref", "origin", "HEAD"])?;
    let default = symref
        .lines()
        .find_map(|l| l.strip_prefix("ref: refs/heads/"))
        .and_then(|l| l.split_whitespace().next())
        .map(str::to_string);
    let base = match default {
        Some(name) if fetch(&name).is_ok() => git(top, &["rev-parse", &tracking(&name)])?,
        _ => head,
    };
    let listed = git(
        top,
        &["ls-remote", "origin", &format!("refs/heads/{branch}")],
    )?;
    let remote = match listed.split_whitespace().next() {
        Some(sha) => {
            fetch(branch)?;
            Some(sha.to_string())
        }
        None => None,
    };
    Ok((base, remote))
}

/// Whether fleetreach made this commit for this campaign, and verified it.
fn ours(top: &Path, commit: &str, edit: &Edit) -> bool {
    git(top, &["log", "-1", "--format=%B", commit])
        .is_ok_and(|m| m.contains(&format!("campaign {}", edit.campaign)) && m.contains(VERIFIED))
}

const VERIFIED: &str = "Verified by a fleetreach re-scan";

fn apply_one(
    edit: &Edit,
    repo: &Repo,
    work_root: &Path,
    scan_args: &[String],
    publishing: bool,
) -> Applied {
    let mut out = Applied::new(edit, Outcome::Blocked, "");
    let top = match git(&repo.path, &["rev-parse", "--show-toplevel"]) {
        Ok(t) => PathBuf::from(t),
        Err(e) => {
            out.detail = format!("not a git work tree: {e}");
            return out;
        }
    };
    let rel = repo
        .path
        .canonicalize()
        .ok()
        .and_then(|p| {
            top.canonicalize()
                .ok()
                .and_then(|t| p.strip_prefix(t).ok().map(Path::to_path_buf))
        })
        .unwrap_or_default();
    let branch = branch_name(edit);
    let tree = work_root.join(format!("{}-{}", safe(&edit.repo), safe(&branch)));
    let (base, remote) = match base_and_remote(&top, &branch, publishing) {
        Ok(found) => found,
        Err(e) => {
            out.detail = format!("could not read the remote: {e}");
            return out;
        }
    };
    if let Some(sha) = &remote {
        if !ours(&top, sha, edit) {
            out.outcome = Outcome::Skipped;
            out.detail = "someone else has pushed to this branch; left alone".to_string();
            return out;
        }
    }
    let current = remote
        .clone()
        .or_else(|| git(&top, &["rev-parse", "--verify", "--quiet", &branch]).ok());
    if let Some(sha) = current {
        let parent = git(&top, &["rev-parse", &format!("{sha}^")]);
        if parent.as_deref() == Ok(base.as_str()) && ours(&top, &sha, edit) {
            // Nothing moved under it: a rewrite would only reset its CI and reviews.
            if let Err(e) = git(&top, &["branch", "--force", &branch, &sha]) {
                out.detail = format!("could not update {branch}: {e}");
                return out;
            }
            out.outcome = Outcome::Verified;
            out.branch = Some(branch);
            out.detail = "already verified on the current base".to_string();
            return out;
        }
    }
    let _ = git(&top, &["worktree", "remove", "--force", path_str(&tree)]);
    let _ = std::fs::remove_dir_all(&tree);
    let _ = git(&top, &["worktree", "prune"]);
    // Detached: no branch moves until there is a commit worth moving it to.
    if let Err(e) = git(
        &top,
        &[
            "worktree",
            "add",
            "--quiet",
            "--force",
            "--detach",
            path_str(&tree),
            &base,
        ],
    ) {
        out.detail = format!("could not create a work tree: {e}");
        return out;
    }
    let cleanup = || {
        let _ = git(&top, &["worktree", "remove", "--force", path_str(&tree)]);
    };
    let work = tree.join(&rel);

    let before = match scan(&work, repo, scan_args) {
        Ok(s) => s,
        Err(e) => {
            cleanup();
            out.detail = format!("baseline scan failed: {e}");
            return out;
        }
    };
    let changed = match apply_edit(&work, edit) {
        Ok(c) => c,
        Err(e) => {
            cleanup();
            out.detail = e;
            return out;
        }
    };
    if git(&tree, &["status", "--porcelain"]).is_ok_and(|s| s.is_empty()) {
        cleanup();
        out.detail = "the update changed nothing".to_string();
        return out;
    }
    let after = scan(&work, repo, scan_args);
    let verdict = match &after {
        Ok(after) => verify(edit, &before, after),
        Err(e) => Err(format!("re-scan failed: {e}")),
    };
    let (outcome, detail, title) = match verdict {
        Ok(()) => (
            Outcome::Verified,
            format!(
                "{changed}; re-scan: {} cleared, nothing new",
                edit.advisories.join(", ")
            ),
            format!("fix(deps): bump {} to {}", edit.package, edit.to),
        ),
        Err(why) => (
            Outcome::Unverified,
            format!("{changed}; re-scan did not verify: {why}"),
            format!(
                "fix(deps): bump {} to {} (unverified)",
                edit.package, edit.to
            ),
        ),
    };
    let message = format!(
        "{title}\n\nClears {} ({} campaign {}).\nUpdate: {changed}.\n{}\n",
        edit.advisories.join(", "),
        ecosystem_name(edit.ecosystem),
        edit.campaign,
        if outcome == Outcome::Verified {
            format!("{VERIFIED}: the advisories are gone and nothing new appeared.")
        } else {
            "Not verified by the fleetreach re-scan; review before using.".to_string()
        }
    );
    let committed =
        git(&tree, &["add", "-A"]).and_then(|_| git(&tree, &["commit", "--quiet", "-m", &message]));
    if let Err(e) = committed {
        cleanup();
        out.detail = format!("could not commit: {e}");
        return out;
    }
    let commit = git(&tree, &["rev-parse", "HEAD"]);
    cleanup();
    // An unverified commit takes a branch of its own, which is never pushed and never replaces
    // a verified one.
    let target = if outcome == Outcome::Verified {
        branch
    } else {
        branch.replacen("fleetreach/", "fleetreach-unverified/", 1)
    };
    let moved = commit.and_then(|sha| git(&top, &["branch", "--force", &target, &sha]));
    if let Err(e) = moved {
        out.detail = format!("could not update {target}: {e}");
        return out;
    }
    out.outcome = outcome;
    out.branch = Some(target);
    out.detail = detail;
    out.ran = changed;
    out
}

/// The marker a grouped commit carries, so a rerun can tell it is fleetreach's and which
/// campaigns it holds.
fn group_marker(campaigns: &[&str]) -> String {
    format!("Campaigns: {}", campaigns.join(", "))
}

/// Apply a unit of several bumps on one branch. Each bump is applied and re-scanned on top of
/// the ones before it; one that fails or does not verify is undone and left out, so the branch
/// only ever holds verified bumps, squashed into one commit.
fn apply_group(
    unit: &Unit,
    group: Group,
    repo: &Repo,
    work_root: &Path,
    scan_args: &[String],
    publishing: bool,
) -> Vec<Applied> {
    let all = |outcome: Outcome, detail: &str| -> Vec<Applied> {
        unit.edits
            .iter()
            .map(|e| Applied::new(e, outcome.clone(), detail))
            .collect()
    };
    let top = match git(&repo.path, &["rev-parse", "--show-toplevel"]) {
        Ok(t) => PathBuf::from(t),
        Err(e) => return all(Outcome::Blocked, &format!("not a git work tree: {e}")),
    };
    let rel = repo
        .path
        .canonicalize()
        .ok()
        .and_then(|p| {
            top.canonicalize()
                .ok()
                .and_then(|t| p.strip_prefix(t).ok().map(Path::to_path_buf))
        })
        .unwrap_or_default();
    let branch = unit.branch.clone();
    let tree = work_root.join(format!("{}-{}", safe(&unit.repo), safe(&branch)));
    let (base, remote) = match base_and_remote(&top, &branch, publishing) {
        Ok(found) => found,
        Err(e) => return all(Outcome::Blocked, &format!("could not read the remote: {e}")),
    };
    let grouped_ours = |sha: &str| {
        git(&top, &["log", "-1", "--format=%B", sha])
            .is_ok_and(|m| m.contains(VERIFIED) && m.contains("Campaigns: "))
    };
    if let Some(sha) = &remote {
        if !grouped_ours(sha) {
            return all(
                Outcome::Skipped,
                "someone else has pushed to this branch; left alone",
            );
        }
    }
    let mut wanted: Vec<&str> = unit.edits.iter().map(|e| e.campaign.as_str()).collect();
    wanted.sort_unstable();
    let current = remote
        .clone()
        .or_else(|| git(&top, &["rev-parse", "--verify", "--quiet", &branch]).ok());
    if let Some(sha) = current {
        let parent = git(&top, &["rev-parse", &format!("{sha}^")]);
        let same = git(&top, &["log", "-1", "--format=%B", &sha])
            .is_ok_and(|m| m.contains(VERIFIED) && m.contains(&group_marker(&wanted)));
        if parent.as_deref() == Ok(base.as_str()) && same {
            // Nothing moved under it: a rewrite would only reset its CI and reviews.
            if let Err(e) = git(&top, &["branch", "--force", &branch, &sha]) {
                return all(Outcome::Blocked, &format!("could not update {branch}: {e}"));
            }
            let mut out = all(Outcome::Verified, "already verified on the current base");
            for a in &mut out {
                a.branch = Some(branch.clone());
            }
            return out;
        }
    }
    let _ = git(&top, &["worktree", "remove", "--force", path_str(&tree)]);
    let _ = std::fs::remove_dir_all(&tree);
    let _ = git(&top, &["worktree", "prune"]);
    if let Err(e) = git(
        &top,
        &[
            "worktree",
            "add",
            "--quiet",
            "--force",
            "--detach",
            path_str(&tree),
            &base,
        ],
    ) {
        return all(
            Outcome::Blocked,
            &format!("could not create a work tree: {e}"),
        );
    }
    let cleanup = || {
        let _ = git(&top, &["worktree", "remove", "--force", path_str(&tree)]);
    };
    let work = tree.join(&rel);
    let mut before = match scan(&work, repo, scan_args) {
        Ok(s) => s,
        Err(e) => {
            cleanup();
            return all(Outcome::Blocked, &format!("baseline scan failed: {e}"));
        }
    };
    // Back to the last verified state after a bump that did not make it.
    let undo = || {
        git(&tree, &["reset", "--quiet", "--hard"])
            .and_then(|_| git(&tree, &["clean", "--quiet", "-fd"]))
    };
    let mut out: Vec<Applied> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    let mut kept: Vec<&Edit> = Vec::new();
    for edit in &unit.edits {
        let mut result = Applied::new(edit, Outcome::Blocked, "");
        match apply_edit(&work, edit) {
            Err(e) => result.detail = e,
            Ok(_) if git(&tree, &["status", "--porcelain"]).is_ok_and(|s| s.is_empty()) => {
                result.detail = "the update changed nothing".to_string();
            }
            Ok(changed) => match scan(&work, repo, scan_args) {
                Err(e) => result.detail = format!("{changed}; re-scan failed: {e}"),
                Ok(after) => match verify(edit, &before, &after) {
                    Err(why) => {
                        result.outcome = Outcome::Unverified;
                        result.detail = format!(
                            "{changed}; re-scan did not verify: {why}; left out of {branch}"
                        );
                    }
                    Ok(()) => {
                        let step = git(&tree, &["add", "-A"])
                            .and_then(|_| git(&tree, &["commit", "--quiet", "-m", &edit.campaign]));
                        match step {
                            Err(e) => result.detail = format!("could not commit: {e}"),
                            Ok(_) => {
                                result.outcome = Outcome::Verified;
                                result.detail = format!(
                                    "{changed}; re-scan: {} cleared, nothing new",
                                    edit.advisories.join(", ")
                                );
                                result.ran = changed.clone();
                                lines.push(format!(
                                    "- {} {} -> {}: {} ({} campaign {}). Update: {changed}.",
                                    edit.package,
                                    edit.from.join(", "),
                                    edit.to,
                                    edit.advisories.join(", "),
                                    ecosystem_name(edit.ecosystem),
                                    edit.campaign
                                ));
                                kept.push(edit);
                                before = after;
                            }
                        }
                    }
                },
            },
        }
        if result.outcome != Outcome::Verified {
            if let Err(e) = undo() {
                cleanup();
                out.push(result);
                for rest in unit.edits.iter().skip(out.len()) {
                    out.push(Applied::new(
                        rest,
                        Outcome::Blocked,
                        &format!("could not undo a failed bump: {e}"),
                    ));
                }
                return out;
            }
        }
        out.push(result);
    }
    if kept.is_empty() {
        cleanup();
        return out;
    }
    let mut campaigns: Vec<&str> = kept.iter().map(|e| e.campaign.as_str()).collect();
    campaigns.sort_unstable();
    let advisories: BTreeSet<&str> = kept
        .iter()
        .flat_map(|e| e.advisories.iter().map(String::as_str))
        .collect();
    let message = format!(
        "{}\n\nClears {}.\n{}\n\nGroup: {}\n{}\n{VERIFIED}: after each bump its advisories \
         are gone and nothing new appeared.\n",
        group_title(&kept, group),
        advisories.into_iter().collect::<Vec<_>>().join(", "),
        lines.join("\n"),
        unit.branch.trim_start_matches("fleetreach/"),
        group_marker(&campaigns),
    );
    let squashed = git(&tree, &["reset", "--quiet", "--soft", &base])
        .and_then(|_| git(&tree, &["commit", "--quiet", "-m", &message]))
        .and_then(|_| git(&tree, &["rev-parse", "HEAD"]));
    cleanup();
    let moved = squashed.and_then(|sha| git(&top, &["branch", "--force", &branch, &sha]));
    if let Err(e) = moved {
        for a in out.iter_mut().filter(|a| a.outcome == Outcome::Verified) {
            a.outcome = Outcome::Blocked;
            a.detail = format!("could not update {branch}: {e}");
        }
        return out;
    }
    for a in out.iter_mut().filter(|a| a.outcome == Outcome::Verified) {
        a.branch = Some(branch.clone());
    }
    out
}

// ---- publish ----

/// Push a unit's verified branch and, with `--open-pr`, open or update its request, then turn
/// on the forge's own auto-merge when `[settings.fix] automerge = "verified"` allows it.
fn publish(
    applied: &mut [Applied],
    unit: &Unit,
    group: Group,
    repo: &Repo,
    plan: &Plan,
    args: &FixApplyArgs,
    policy: &FixSettings,
) {
    let note = |applied: &mut [Applied], text: &str| {
        for a in applied
            .iter_mut()
            .filter(|a| a.outcome == Outcome::Verified)
        {
            a.detail.push_str(text);
        }
    };
    let Some(branch) = applied
        .iter()
        .find(|a| a.outcome == Outcome::Verified)
        .and_then(|a| a.branch.clone())
    else {
        return;
    };
    if !branch.starts_with("fleetreach/") {
        return; // never push anything but our own branches
    }
    let top = match git(&repo.path, &["rev-parse", "--show-toplevel"]) {
        Ok(t) => PathBuf::from(t),
        Err(e) => {
            note(applied, &format!("; push skipped: {e}"));
            return;
        }
    };
    // The branch is fleetreach's own, rebuilt on every run, so a force push pinned to the head
    // just read from the remote is what keeps it current without touching anyone else's work.
    let lease = match git(
        &top,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("refs/remotes/origin/{branch}"),
        ],
    ) {
        Ok(sha) => format!("--force-with-lease={branch}:{sha}"),
        Err(_) => format!("--force-with-lease={branch}:"),
    };
    if let Err(e) = git(
        &top,
        &[
            "push",
            "--quiet",
            &lease,
            "origin",
            &format!("{branch}:{branch}"),
        ],
    ) {
        note(applied, &format!("; push failed: {e}"));
        return;
    }
    note(applied, "; pushed");
    if !args.open_pr {
        return;
    }
    let verified: Vec<&Edit> = unit
        .edits
        .iter()
        .copied()
        .filter(|e| {
            applied
                .iter()
                .any(|a| a.outcome == Outcome::Verified && a.campaign == e.campaign)
        })
        .collect();
    let (title, body) = if group == Group::Package {
        let edit = unit.edits[0];
        let ran = applied.first().map(|a| a.ran.clone()).unwrap_or_default();
        (
            format!("fix(deps): bump {} to {}", edit.package, edit.to),
            pr_body(edit, plan, &ran),
        )
    } else {
        (
            group_title(&verified, group),
            group_body(&verified, applied, group),
        )
    };
    let forge = match args.forge.resolve(&top, args.forge_api.as_deref()) {
        Ok(f) => f,
        Err(e) => {
            note(applied, &format!("; no request opened: {e}"));
            return;
        }
    };
    let (noun, opened) = match &forge {
        Forge::GitHub => (
            "pull request",
            github_request(&top, &branch, &title, &body, args.draft),
        ),
        Forge::GitLab => (
            "merge request",
            gitlab_request(&top, &branch, &title, &body, args.draft),
        ),
        Forge::Api(target) => (
            "pull request",
            api_request(target, &top, &branch, &title, &body, args.draft),
        ),
    };
    let url = match opened {
        Ok((url, updated)) => {
            let verb = if updated { "updated" } else { "opened" };
            note(applied, &format!("; {noun} {verb}"));
            for a in applied
                .iter_mut()
                .filter(|a| a.outcome == Outcome::Verified)
            {
                a.pull_request = Some(url.clone());
            }
            // One new request, counted once for --max-prs and the rollout.
            if let Some(first) = applied.iter_mut().find(|a| a.outcome == Outcome::Verified) {
                first.opened = !updated;
            }
            url
        }
        Err(e) => {
            note(applied, &format!("; {noun} failed: {e}"));
            return;
        }
    };
    if !policy.automerge {
        return;
    }
    let why_not = if args.draft {
        Some("a draft")
    } else if verified.iter().any(|e| e.breaking) {
        Some("a breaking bump needs a review")
    } else {
        None
    };
    if let Some(why) = why_not {
        note(applied, &format!("; auto-merge left off: {why}"));
        return;
    }
    let head = match git(&top, &["rev-parse", &branch]) {
        Ok(sha) => sha,
        Err(e) => {
            note(applied, &format!("; auto-merge not enabled: {e}"));
            return;
        }
    };
    match enable_automerge(&forge, &top, &url, &head, policy.merge_method) {
        // With no required checks pending, `gh pr merge --auto` merges at once.
        Ok(()) if forge == Forge::GitHub && github_merged(&top, &url) => {
            note(applied, "; merged (no required checks were pending)");
        }
        Ok(()) => note(applied, "; auto-merge on"),
        Err(e) => note(applied, &format!("; auto-merge not enabled: {e}")),
    }
}

/// Ask the forge to merge the request once its own checks pass, and only at `head`, the commit
/// fleetreach verified: a later push to the branch cancels it.
fn enable_automerge(
    forge: &Forge,
    top: &Path,
    url: &str,
    head: &str,
    method: crate::fix_policy::MergeMethod,
) -> Result<(), String> {
    match forge {
        Forge::GitHub => run(Command::new("gh").current_dir(top).args([
            "pr",
            "merge",
            url,
            "--auto",
            method.flag(),
            "--match-head-commit",
            head,
        ]))
        .map(|_| ()),
        Forge::GitLab => {
            let iid = url.rsplit('/').next().unwrap_or_default();
            let mut cmd = Command::new("glab");
            cmd.current_dir(top)
                .args(["mr", "merge", iid, "--auto-merge", "--yes", "--sha", head]);
            match method {
                crate::fix_policy::MergeMethod::Squash => {
                    cmd.arg("--squash");
                }
                crate::fix_policy::MergeMethod::Rebase => {
                    cmd.arg("--rebase");
                }
                crate::fix_policy::MergeMethod::Merge => {}
            }
            run(&mut cmd).map(|_| ())
        }
        Forge::Api(target) => {
            let id = fix_forges::id_from_url(url).ok_or("no request id in its URL")?;
            let method = match method {
                crate::fix_policy::MergeMethod::Squash => "squash",
                crate::fix_policy::MergeMethod::Merge => "merge",
                crate::fix_policy::MergeMethod::Rebase => "rebase",
            };
            let mut send = fix_forges::http_send(target.kind)?;
            fix_forges::automerge(target, &id, head, method, &mut send)
        }
    }
}

/// Whether the pull request at `url` is merged.
fn github_merged(top: &Path, url: &str) -> bool {
    run(Command::new("gh")
        .current_dir(top)
        .args(["pr", "view", url, "--json", "state", "--jq", ".state"]))
    .is_ok_and(|state| state.trim() == "MERGED")
}

/// The remote's default branch, which a new request targets.
fn default_branch(top: &Path) -> Result<String, String> {
    let symref = git(top, &["ls-remote", "--symref", "origin", "HEAD"])?;
    symref
        .lines()
        .find_map(|l| l.strip_prefix("ref: refs/heads/"))
        .and_then(|l| l.split_whitespace().next())
        .map(str::to_string)
        .ok_or_else(|| "the remote names no default branch".to_string())
}

/// [`github_request`] for a forge reached through its API.
fn api_request(
    target: &fix_forges::Target,
    top: &Path,
    branch: &str,
    title: &str,
    body: &str,
    draft: bool,
) -> Result<(String, bool), String> {
    let base = default_branch(top)?;
    let mut send = fix_forges::http_send(target.kind)?;
    fix_forges::open_or_update(target, branch, &base, title, body, draft, &mut send)
        .map(|(url, updated, _)| (url, updated))
}

/// A grouped request's title.
fn group_title(edits: &[&Edit], group: Group) -> String {
    let what = match edits {
        [one] => format!("bump {} to {}", one.package, one.to),
        many => format!("bump {} packages", many.len()),
    };
    match (group, edits.first().and_then(|e| e.ssvc)) {
        (Group::Ssvc, Some(outcome)) => format!("fix(deps): {what} ({})", outcome.label()),
        _ => format!("fix(deps): {what}"),
    }
}

/// A grouped request's description: one line per bump, how it was checked, the campaigns.
fn group_body(edits: &[&Edit], applied: &[Applied], group: Group) -> String {
    let mut body = String::from("| Package | From | To | Fixes |\n|---|---|---|---|\n");
    for edit in edits {
        body.push_str(&format!(
            "| `{}` ({}) | {} | {} | {} |\n",
            edit.package,
            ecosystem_name(edit.ecosystem),
            edit.from.join(", "),
            edit.to,
            edit.advisories.join(", ")
        ));
    }
    body.push('\n');
    if let (Group::Ssvc, Some(outcome)) = (group, edits.first().and_then(|e| e.ssvc)) {
        body.push_str(&format!(
            "**SSVC:** every fix here is `{}` for this repo.\n\n",
            outcome.label()
        ));
    }
    let breaking: Vec<&str> = edits
        .iter()
        .filter(|e| e.breaking)
        .map(|e| e.package.as_str())
        .collect();
    if !breaking.is_empty() {
        let verb = if breaking.len() == 1 {
            "crosses"
        } else {
            "cross"
        };
        body.push_str(&format!(
            "**Breaking:** {} {verb} a major version; review the changelog.\n\n",
            breaking.join(", ")
        ));
    }
    let left_out: Vec<String> = applied
        .iter()
        .filter(|a| a.outcome != Outcome::Verified)
        .map(|a| format!("`{}` ({})", a.package, a.detail))
        .collect();
    if !left_out.is_empty() {
        body.push_str(&format!("**Left out:** {}.\n\n", left_out.join("; ")));
    }
    body.push_str(
        "**Verified:** a fleetreach re-scan after each bump finds its advisories gone and \
         nothing new. The updates ran no package code.\n\n",
    );
    let campaigns: Vec<&str> = edits.iter().map(|e| e.campaign.as_str()).collect();
    body.push_str(&format!("Campaigns: `{}`.", campaigns.join("`, `")));
    body.push_str("\n\n_Opened by `fleetreach fix apply --open-pr`._\n");
    body
}

/// Close each open fleetreach request the plan does not want, in repos the report read in
/// full, and delete its branch. What the plan blocks is still wanted, and a branch someone else
/// has pushed to stays open for them.
fn close_obsolete(
    plan: &Plan,
    config: &Config,
    args: &FixApplyArgs,
    group: Group,
    requests: &mut Requests,
    results: &mut Vec<Applied>,
) {
    let wanted: BTreeSet<(&str, String)> = plan
        .edits
        .iter()
        .map(|e| (e.repo.as_str(), unit_branch(e, group)))
        .collect();
    let in_scope = |id: &String| args.repos.is_empty() || args.repos.contains(id);
    for id in plan.scanned.iter().filter(|id| in_scope(id)) {
        let Some(repo) = config.repos.iter().find(|r| &r.id.0 == id) else {
            continue;
        };
        let open: Vec<(String, String)> =
            match requests.of(repo, args.forge, args.forge_api.as_deref()) {
                Ok(known) => known
                    .iter()
                    .filter(|(branch, (state, _))| {
                        state == "OPEN" && !wanted.contains(&(id.as_str(), (*branch).clone()))
                    })
                    .map(|(branch, (_, url))| (branch.clone(), url.clone()))
                    .collect(),
                Err(e) => {
                    eprintln!("error: {id}: could not list requests: {e}");
                    continue;
                }
            };
        for (branch, url) in open {
            results.push(close_one(
                repo,
                &branch,
                url,
                args.forge,
                args.forge_api.as_deref(),
            ));
        }
    }
}

fn close_one(
    repo: &Repo,
    branch: &str,
    url: String,
    forge: ForgeArg,
    api: Option<&str>,
) -> Applied {
    let mut out = Applied {
        repo: repo.id.0.clone(),
        package: String::new(),
        to: String::new(),
        campaign: branch.split('/').nth(1).unwrap_or_default().to_string(),
        outcome: Outcome::Blocked,
        branch: Some(branch.to_string()),
        detail: String::new(),
        pull_request: Some(url.clone()),
        ran: String::new(),
        opened: false,
    };
    let note = "The newest fleetreach plan no longer needs this change.";
    let closed = fetch_head(&repo.path, branch).and_then(|head| {
        let message = git(&repo.path, &["log", "-1", "--format=%B", &head])?;
        if !message.contains(VERIFIED) {
            return Err("someone else has pushed to this branch; left open".to_string());
        }
        match forge.resolve(&repo.path, api)? {
            Forge::GitHub => run(Command::new("gh").current_dir(&repo.path).args([
                "pr",
                "close",
                &url,
                "--comment",
                note,
            ])),
            Forge::GitLab => {
                let iid = url.rsplit('/').next().unwrap_or_default();
                run(Command::new("glab").current_dir(&repo.path).args([
                    "mr",
                    "note",
                    iid,
                    "--message",
                    note,
                ]))?;
                run(Command::new("glab")
                    .current_dir(&repo.path)
                    .args(["mr", "close", iid]))
            }
            Forge::Api(target) => {
                let id = fix_forges::id_from_url(&url).ok_or("no request id in its URL")?;
                let mut send = fix_forges::http_send(target.kind)?;
                fix_forges::close(&target, &id, note, &mut send).map(|()| String::new())
            }
        }?;
        git(
            &repo.path,
            &["push", "--quiet", "origin", "--delete", branch],
        )
    });
    match closed {
        Ok(_) => {
            out.outcome = Outcome::Closed;
            out.detail = "no longer in the plan: closed and its branch deleted".to_string();
        }
        Err(e) => out.detail = format!("not closed: {e}"),
    }
    out
}

/// The head of `branch` on the remote, fetched so it can be read.
fn fetch_head(dir: &Path, branch: &str) -> Result<String, String> {
    if !branch.starts_with("fleetreach/") {
        return Err("not a fleetreach branch".to_string());
    }
    let spec = format!("+refs/heads/{branch}:refs/remotes/origin/{branch}");
    git(dir, &["fetch", "--quiet", "origin", &spec])?;
    git(
        dir,
        &["rev-parse", &format!("refs/remotes/origin/{branch}")],
    )
}

/// Open the pull request for `branch`, or update the open one. The URL, and whether it
/// already existed.
fn github_request(
    top: &Path,
    branch: &str,
    title: &str,
    body: &str,
    draft: bool,
) -> Result<(String, bool), String> {
    let existing = run(Command::new("gh").current_dir(top).args([
        "pr", "list", "--head", branch, "--state", "open", "--json", "url", "--jq", ".[0].url",
    ]))
    .ok()
    .filter(|u| !u.is_empty());
    if let Some(url) = existing {
        run(Command::new("gh")
            .current_dir(top)
            .args(["pr", "edit", &url, "--title", title, "--body", body]))?;
        return Ok((url, true));
    }
    let mut cmd = Command::new("gh");
    cmd.current_dir(top).args([
        "pr", "create", "--head", branch, "--title", title, "--body", body,
    ]);
    if draft {
        cmd.arg("--draft");
    }
    let out = run(&mut cmd)?;
    Ok((out.lines().last().unwrap_or_default().to_string(), false))
}

/// The same with `glab`: the open merge request from `branch` is updated, or one is opened.
/// `glab mr create` does not promise its output format, so the URL is read back from the
/// list afterwards.
fn gitlab_request(
    top: &Path,
    branch: &str,
    title: &str,
    body: &str,
    draft: bool,
) -> Result<(String, bool), String> {
    let open_mr = || -> Option<(String, String)> {
        let listed = run(Command::new("glab").current_dir(top).args([
            "mr",
            "list",
            "--source-branch",
            branch,
            "--output",
            "json",
        ]))
        .ok()?;
        let mrs: serde_json::Value = serde_json::from_str(&listed).ok()?;
        let mr = mrs.as_array()?.first()?;
        Some((
            mr["iid"].as_u64()?.to_string(),
            mr["web_url"].as_str()?.to_string(),
        ))
    };
    if let Some((iid, url)) = open_mr() {
        run(Command::new("glab").current_dir(top).args([
            "mr",
            "update",
            &iid,
            "--title",
            title,
            "--description",
            body,
            "--yes",
        ]))?;
        return Ok((url, true));
    }
    let mut cmd = Command::new("glab");
    cmd.current_dir(top).args([
        "mr",
        "create",
        "--source-branch",
        branch,
        "--title",
        title,
        "--description",
        body,
        "--yes",
    ]);
    if draft {
        cmd.arg("--draft");
    }
    let out = run(&mut cmd)?;
    let url = open_mr().map(|(_, url)| url).or_else(|| {
        out.split_whitespace()
            .rfind(|w| w.starts_with("https://") || w.starts_with("http://"))
            .map(str::to_string)
    });
    Ok((url.unwrap_or_default(), false))
}

/// The pull request description: what it fixes, how it was checked, and the campaign.
fn pr_body(edit: &Edit, plan: &Plan, ran: &str) -> String {
    let siblings: Vec<&str> = plan
        .edits
        .iter()
        .filter(|e| e.campaign == edit.campaign && e.repo != edit.repo)
        .map(|e| e.repo.as_str())
        .collect();
    let mut body = format!(
        "Bumps `{}` from {} to {} ({}).\n\n**Fixes:** {}\n\n",
        edit.package,
        edit.from.join(", "),
        edit.to,
        ecosystem_name(edit.ecosystem),
        edit.advisories.join(", ")
    );
    if !ran.is_empty() {
        body.push_str(&format!("**Update:** {ran}.\n\n"));
    }
    if edit.breaking {
        body.push_str("**Breaking:** this crosses a major version; review the changelog.\n\n");
    }
    if let Some(risk) = edit.risk {
        body.push_str(&format!("**Risk:** {}", risk.label()));
        if !edit.risk_reasons.is_empty() {
            body.push_str(&format!(" ({})", edit.risk_reasons.join("; ")));
        }
        body.push_str(".\n\n");
    }
    body.push_str(
        "**Verified:** a fleetreach re-scan of this branch finds none of these advisories and \
         nothing new. The update ran no package code.\n\n",
    );
    if siblings.is_empty() {
        body.push_str(&format!("Campaign `{}`.", edit.campaign));
    } else {
        body.push_str(&format!(
            "Campaign `{}`: the same bump in {} other repo(s): {}.",
            edit.campaign,
            siblings.len(),
            siblings.join(", ")
        ));
    }
    body.push_str("\n\n_Opened by `fleetreach fix apply --open-pr`._\n");
    body
}

/// `fix status`: every `fleetreach/*` pull request of every repo, with its state.
fn run_status(args: &FixStatusArgs) -> u8 {
    let mut config = match Config::load(&args.config) {
        Ok(c) => c,
        Err(e) => return fail(&e.to_string()),
    };
    match sources::materialize(&config, false, true) {
        Ok(m) => config.repos.extend(m.repos),
        Err(e) => return fail(&e),
    }
    let mut rows = Vec::new();
    let mut failed = 0usize;
    for repo in &config.repos {
        let listed = args
            .forge
            .resolve(&repo.path, args.forge_api.as_deref())
            .and_then(|forge| list_requests(&forge, &repo.path));
        match listed {
            Ok(requests) => {
                for mut request in requests {
                    request["repo"] = serde_json::json!(repo.id.0);
                    rows.push(request);
                }
            }
            Err(e) => {
                failed += 1;
                eprintln!("error: {}: {e}", repo.id);
            }
        }
    }
    if let Err(e) = crate::cli::print_json(&rows) {
        return fail(&e);
    }
    u8::from(failed > 0) * 2
}

/// Every `fleetreach/*` pull or merge request of the repo at `dir`, in any state, as
/// `{branch, state, title, url}` (states as GitHub spells them: `OPEN`, `MERGED`, `CLOSED`).
fn list_requests(forge: &Forge, dir: &Path) -> Result<Vec<serde_json::Value>, String> {
    let (listed, branch_key, url_key) = match forge {
        Forge::Api(target) => {
            let mut send = fix_forges::http_send(target.kind)?;
            return Ok(fix_forges::list(target, &mut send)?
                .iter()
                .map(|r| r.to_json(target.kind))
                .collect());
        }
        Forge::GitHub => (
            run(Command::new("gh").current_dir(dir).args([
                "pr",
                "list",
                "--state",
                "all",
                "--limit",
                "200",
                "--json",
                "headRefName,state,url,title",
            ]))?,
            "headRefName",
            "url",
        ),
        Forge::GitLab => (
            run(Command::new("glab").current_dir(dir).args([
                "mr",
                "list",
                "--all",
                "--per-page",
                "100",
                "--output",
                "json",
            ]))?,
            "source_branch",
            "web_url",
        ),
    };
    let requests: serde_json::Value = serde_json::from_str(&listed).map_err(|e| e.to_string())?;
    Ok(requests
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| {
            let branch = r[branch_key].as_str()?;
            branch.starts_with("fleetreach/").then(|| {
                let state = match r["state"].as_str().unwrap_or_default() {
                    "opened" => "OPEN".to_string(),
                    other => other.to_ascii_uppercase(),
                };
                serde_json::json!({
                    "branch": branch, "state": state, "title": r["title"], "url": r[url_key],
                    "forge": forge.name(),
                })
            })
        })
        .collect())
}

fn branch_name(edit: &Edit) -> String {
    format!(
        "fleetreach/{}/{}-{}",
        edit.campaign,
        safe(&edit.package),
        safe(&edit.to)
    )
}

/// A string usable in a branch or directory name.
fn safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches(['-', '.'])
        .to_string()
}

fn path_str(path: &Path) -> &str {
    path.to_str().unwrap_or_default()
}

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    run(Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args))
}

pub(crate) fn run(cmd: &mut Command) -> Result<String, String> {
    let output = cmd.output().map_err(|e| format!("{e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        // The first few lines: tools such as uv wrap one error over several, framed with
        // box-drawing characters.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lines: Vec<&str> = stderr
            .lines()
            .map(|l| l.trim_start_matches(['×', '│', '╰', '─', '▶', ' ']).trim())
            .filter(|l| !l.is_empty())
            .take(3)
            .collect();
        Err(if lines.is_empty() {
            "failed".to_string()
        } else {
            lines.join(" ")
        })
    }
}

// ---- edits ----

/// Apply the lock-only update; returns a short description of what ran.
fn apply_edit(work: &Path, edit: &Edit) -> Result<String, String> {
    match edit.ecosystem {
        Ecosystem::Cargo => cargo_bump(work, edit),
        Ecosystem::Npm => node_bump(work, edit),
        Ecosystem::GitHubActions => actions_bump(work, edit),
        Ecosystem::Go => go_bump(work, edit),
        Ecosystem::Pypi => uv_bump(work, edit),
        Ecosystem::Packagist => fix_managers::composer_bump(work, edit),
        Ecosystem::RubyGems => fix_managers::bundler_bump(work, edit),
        Ecosystem::NuGet => fix_managers::nuget_bump(work, edit),
        Ecosystem::Maven => fix_managers::maven_bump(work, edit),
        Ecosystem::Swift => fix_locks::swift_bump(work, edit),
        Ecosystem::Hex => {
            let client = crate::health::registry_client();
            fix_locks::hex_bump(work, edit, client.as_deref())
        }
        Ecosystem::Julia => {
            let client = crate::health::registry_client();
            fix_locks::julia_bump(work, edit, client.as_deref())
        }
        other => Err(format!(
            "fix apply does not handle {} yet",
            ecosystem_name(other)
        )),
    }
}

/// The update for each lockfile a Node project may keep the package in.
fn node_bump(work: &Path, edit: &Edit) -> Result<String, String> {
    let mut ran: Vec<String> = Vec::new();
    if edit.strategy == Strategy::ManifestBump {
        ran.push(npm_manifest_bump(work, edit)?);
    } else {
        ran.extend(npm_bump(work, edit)?);
    }
    ran.extend(fix_managers::pnpm_bump(work, edit)?);
    ran.extend(fix_managers::yarn_bump(work, edit)?);
    if ran.is_empty() {
        return Err(format!(
            "no package-lock.json, pnpm-lock.yaml or yarn.lock holds {}",
            edit.package
        ));
    }
    Ok(ran.join("; "))
}

/// Raises the range in `package.json`, then `npm install --package-lock-only` to follow it.
fn npm_manifest_bump(work: &Path, edit: &Edit) -> Result<String, String> {
    let dirs = fix_constraints::raise_npm(work, edit)?;
    if dirs.is_empty() {
        return Err(format!(
            "no package.json range on {} to raise",
            edit.package
        ));
    }
    for dir in &dirs {
        run(Command::new("npm").current_dir(dir).args([
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ]))
        .map_err(|e| format!("npm install: {e}"))?;
    }
    Ok(format!(
        "raised {} to {} in {} dir(s), npm install --package-lock-only",
        edit.package,
        edit.to,
        dirs.len()
    ))
}

/// Directories under `root` (skipping VCS and dependency directories) holding `file`.
pub(crate) fn dirs_with(root: &Path, file: &str) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = walkdir::WalkDir::new(root)
        .max_depth(6)
        .into_iter()
        .filter_entry(|e| {
            !(e.file_type().is_dir()
                && matches!(
                    e.file_name().to_str(),
                    Some(".git" | "node_modules" | "target" | ".venv")
                ))
        })
        .flatten()
        .filter(|e| e.file_type().is_file() && e.file_name() == file)
        .filter_map(|e| e.path().parent().map(Path::to_path_buf))
        .collect();
    found.sort();
    found
}

/// `cargo update -p <pkg>@<from> --precise <to>` in every workspace whose `Cargo.lock`
/// holds a vulnerable version. Cargo resolves the registry index only; no build scripts run.
fn cargo_bump(work: &Path, edit: &Edit) -> Result<String, String> {
    let mut ran = Vec::new();
    if edit.strategy == Strategy::ManifestBump {
        let raised = fix_constraints::raise_cargo(work, edit)?;
        ran.push(format!("raised {} in {raised} Cargo.toml", edit.package));
    }
    for dir in dirs_with(work, "Cargo.lock") {
        let lock = std::fs::read_to_string(dir.join("Cargo.lock")).unwrap_or_default();
        for from in &edit.from {
            let entry = format!("name = \"{}\"\nversion = \"{from}\"", edit.package);
            if !lock.contains(&entry) {
                continue;
            }
            let spec = format!("{}@{from}", edit.package);
            run(Command::new("cargo").current_dir(&dir).args([
                "update",
                "--quiet",
                "-p",
                &spec,
                "--precise",
                &edit.to,
            ]))
            .map_err(|e| format!("cargo update {spec} --precise {}: {e}", edit.to))?;
            ran.push(format!("cargo update {spec} --precise {}", edit.to));
        }
    }
    if ran.is_empty() {
        return Err(format!(
            "no Cargo.lock holds {} at {}",
            edit.package,
            edit.from.join(", ")
        ));
    }
    Ok(ran.join("; "))
}

/// `npm update <pkg> --package-lock-only --ignore-scripts` where `package-lock.json` holds
/// the package: the newest version every declared range allows, with no install scripts.
fn npm_bump(work: &Path, edit: &Edit) -> Result<Option<String>, String> {
    let needle = format!("\"node_modules/{}\"", edit.package);
    let dirs: Vec<PathBuf> = dirs_with(work, "package-lock.json")
        .into_iter()
        .filter(|d| {
            std::fs::read_to_string(d.join("package-lock.json")).is_ok_and(|t| t.contains(&needle))
        })
        .collect();
    for dir in &dirs {
        run(Command::new("npm").current_dir(dir).args([
            "update",
            &edit.package,
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ]))
        .map_err(|e| format!("npm update {}: {e}", edit.package))?;
    }
    Ok((!dirs.is_empty()).then(|| {
        format!(
            "npm update {} --package-lock-only in {} dir(s)",
            edit.package,
            dirs.len()
        )
    }))
}

/// `go get <module>@v<to>` in every module whose `go.mod` requires the module, then
/// `go list` to record the checksums the build needs. Go resolves and downloads module
/// sources but never runs their code; `GOTOOLCHAIN=local` stops a
/// `toolchain` line from fetching another Go, and `GOWORK=off` keeps the edit to that module.
fn go_bump(work: &Path, edit: &Edit) -> Result<String, String> {
    let needle = format!("{} v", edit.package);
    let dirs: Vec<PathBuf> = dirs_with(work, "go.mod")
        .into_iter()
        .filter(|d| std::fs::read_to_string(d.join("go.mod")).is_ok_and(|t| t.contains(&needle)))
        .collect();
    if dirs.is_empty() {
        return Err(format!("no go.mod requires {}", edit.package));
    }
    let target = format!("{}@v{}", edit.package, edit.to);
    let mut raised = Vec::new();
    for dir in &dirs {
        let before = go_directive(&dir.join("go.mod"));
        run(Command::new("go")
            .current_dir(dir)
            .env("GOTOOLCHAIN", "local")
            .env("GOWORK", "off")
            .env("GOFLAGS", "-mod=mod")
            .args(["get", &target]))
        .map_err(|e| format!("go get {target}: {e}"))?;
        // `go get` records the module graph, not the checksums of packages the new versions
        // import: without them the branch fails to build ("missing go.sum entry"). Listing the
        // build's packages adds them; it compiles nothing.
        run(Command::new("go")
            .current_dir(dir)
            .env("GOTOOLCHAIN", "local")
            .env("GOWORK", "off")
            .env("GOFLAGS", "-mod=mod")
            .args(["list", "-deps", "-test", "./..."]))
        .map_err(|e| format!("go list after go get {target}: {e}"))?;
        // A newer module can require a newer Go, and `go get` raises the directive to match:
        // a real change for whoever builds the module, so it is named.
        let after = go_directive(&dir.join("go.mod"));
        if after != before {
            if let (Some(before), Some(after)) = (before, after) {
                raised.push(format!("raised the go directive from {before} to {after}"));
            }
        }
    }
    raised.dedup();
    let mut done = format!("go get {target} in {} module(s)", dirs.len());
    for r in raised {
        done.push_str("; ");
        done.push_str(&r);
    }
    Ok(done)
}

/// The `go` directive of a `go.mod`.
fn go_directive(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()?.lines().find_map(|l| {
        l.trim()
            .strip_prefix("go ")
            .map(|v| v.split_whitespace().next().unwrap_or_default().to_string())
    })
}

/// `uv lock --upgrade-package <pkg>==<to> --no-build` where `uv.lock` holds the package:
/// a re-resolution from the index's metadata, with source builds refused so no package code
/// runs. Other Python lockfiles are not handled: Poetry and Pipenv can build sdists to read
/// their metadata, which runs package code.
fn uv_bump(work: &Path, edit: &Edit) -> Result<String, String> {
    let needle = format!("name = \"{}\"", edit.package);
    let dirs: Vec<PathBuf> = dirs_with(work, "uv.lock")
        .into_iter()
        .filter(|d| std::fs::read_to_string(d.join("uv.lock")).is_ok_and(|t| t.contains(&needle)))
        .collect();
    if dirs.is_empty() {
        return Err(format!(
            "no uv.lock holds {} (poetry.lock, Pipfile.lock and requirements files are not \
             handled: their tools can run package code)",
            edit.package
        ));
    }
    let spec = format!("{}=={}", edit.package, edit.to);
    for dir in &dirs {
        run(Command::new("uv").current_dir(dir).args([
            "lock",
            "--quiet",
            "--no-build",
            "--upgrade-package",
            &spec,
        ]))
        .map_err(|e| {
            let hint = if e.contains("is disabled") {
                " (resolving needs a source build, such as a workspace member with dynamic \
                 metadata; fix apply never builds, since that runs package code)"
            } else {
                ""
            };
            format!("uv lock --upgrade-package {spec}: {e}{hint}")
        })?;
    }
    Ok(format!(
        "uv lock --upgrade-package {spec} in {} dir(s)",
        dirs.len()
    ))
}

/// Rewrite `uses: <action>@<ref>` tags whose version is vulnerable to the fixed release tag,
/// keeping a leading `v`. A text edit; nothing runs.
fn actions_bump(work: &Path, edit: &Edit) -> Result<String, String> {
    let from: BTreeSet<&str> = edit.from.iter().map(String::as_str).collect();
    let dir = work.join(".github").join("workflows");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map_err(|e| format!(".github/workflows: {e}"))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| matches!(e, "yml" | "yaml"))
        })
        .collect();
    files.sort();
    let mut changed = 0usize;
    for file in &files {
        let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
        let mut out = String::with_capacity(text.len());
        let mut file_changed = false;
        for line in text.split_inclusive('\n') {
            match rewrite_uses(line, &edit.package, &from, &edit.to) {
                Some(new) => {
                    out.push_str(&new);
                    file_changed = true;
                    changed += 1;
                }
                None => out.push_str(line),
            }
        }
        if file_changed {
            std::fs::write(file, out).map_err(|e| format!("{}: {e}", file.display()))?;
        }
    }
    if changed == 0 {
        return Err(format!(
            "no workflow uses {} at a vulnerable tag",
            edit.package
        ));
    }
    Ok(format!(
        "{changed} `uses: {}` reference(s) moved to {}",
        edit.package, edit.to
    ))
}

/// The line with its `<action>@<ref>` moved to `to` when `ref` is a vulnerable version.
fn rewrite_uses(line: &str, action: &str, from: &BTreeSet<&str>, to: &str) -> Option<String> {
    let idx = line.find("uses:")?;
    let rest = &line[idx + "uses:".len()..];
    let start = rest.find(|c: char| !c.is_whitespace() && c != '"' && c != '\'')?;
    let token_end = rest[start..]
        .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '#')
        .map_or(rest.len(), |e| start + e);
    let token = &rest[start..token_end];
    let (name, reference) = token.split_once('@')?;
    if !name.eq_ignore_ascii_case(action) {
        return None;
    }
    let version = fleetreach_ghactions::parse_gha_version(reference)?.to_string();
    if !from.contains(version.as_str()) {
        return None;
    }
    let new_ref = if reference.starts_with('v') {
        format!("v{to}")
    } else {
        to.to_string()
    };
    let absolute = idx + "uses:".len();
    Some(format!(
        "{}{name}@{new_ref}{}",
        &line[..absolute + start],
        &line[absolute + token_end..]
    ))
}

// ---- verification ----

/// What one scan of a work tree found, for one repo.
#[derive(Debug, Default, PartialEq, Eq)]
struct Scanned {
    /// `(advisory, package, version)` for every vulnerable occurrence.
    findings: BTreeSet<(String, String, String)>,
    errored: bool,
    coverage_gaps: usize,
}

/// Scan `work` as `repo` with the user's scan flags, through this same binary.
fn scan(work: &Path, repo: &Repo, scan_args: &[String]) -> Result<Scanned, String> {
    let dir = std::env::temp_dir().join(format!(
        "fleetreach-fix-{}-{}",
        std::process::id(),
        safe(&repo.id.0)
    ));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let fleet = dir.join("fleet.toml");
    let mut body = format!(
        "[[repo]]\nid = {}\npath = {}\nglob = {}\nglob_max_depth = {}\n",
        toml_str(&repo.id.0),
        toml_str(path_str(work)),
        repo.glob,
        repo.glob_max_depth
    );
    if let Some(eco) = repo.ecosystem {
        body.push_str(&format!("ecosystem = {}\n", toml_str(&ecosystem_name(eco))));
    }
    std::fs::write(&fleet, body).map_err(|e| e.to_string())?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let output = Command::new(exe)
        .args(["scan", "-q", "-f", "json", "-c", path_str(&fleet)])
        .args(scan_args)
        .output()
        .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&dir);
    let report: FleetReport = serde_json::from_slice(&output.stdout).map_err(|_| {
        let stderr = String::from_utf8_lossy(&output.stderr);
        stderr
            .lines()
            .find(|l| l.starts_with("error"))
            .unwrap_or("no JSON report")
            .to_string()
    })?;
    let mut scanned = Scanned {
        errored: report.outcomes.iter().any(|o| {
            o.repo == repo.id && matches!(o.status, fleetreach_core::ScanStatus::Errored { .. })
        }),
        coverage_gaps: report.coverage.iter().filter(|c| c.repo == repo.id).count(),
        ..Scanned::default()
    };
    for v in &report.vulnerabilities {
        for occ in &v.occurrences {
            if let Occurrence::InRepo {
                repo: r,
                package,
                installed,
                ..
            } = occ
            {
                if *r == repo.id {
                    scanned.findings.insert((
                        v.advisory_id.clone(),
                        package.clone(),
                        installed.to_string(),
                    ));
                }
            }
        }
    }
    Ok(scanned)
}

fn toml_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

/// Every targeted advisory gone for the package, nothing new, no new errors or gaps.
fn verify(edit: &Edit, before: &Scanned, after: &Scanned) -> Result<(), String> {
    let targeted =
        |f: &(String, String, String)| f.1 == edit.package && edit.advisories.contains(&f.0);
    if !before.findings.iter().any(targeted) {
        return Err("the baseline scan did not find the targeted advisories".to_string());
    }
    let left: Vec<String> = after
        .findings
        .iter()
        .filter(|f| targeted(f))
        .map(|f| format!("{} {}@{}", f.0, f.1, f.2))
        .collect();
    if !left.is_empty() {
        return Err(format!("still present: {}", left.join(", ")));
    }
    // New means an advisory the package did not have before. An open advisory on a package
    // whose version moved (a transitive bump with no fix yet) is the same finding.
    let had: BTreeSet<(&str, &str)> = before
        .findings
        .iter()
        .map(|f| (f.0.as_str(), f.1.as_str()))
        .collect();
    let new: Vec<String> = after
        .findings
        .iter()
        .filter(|f| !had.contains(&(f.0.as_str(), f.1.as_str())))
        .map(|f| format!("{} {}@{}", f.0, f.1, f.2))
        .collect();
    if !new.is_empty() {
        return Err(format!("new findings: {}", new.join(", ")));
    }
    if after.errored && !before.errored {
        return Err("the repo no longer scans cleanly".to_string());
    }
    if after.coverage_gaps > before.coverage_gaps {
        return Err("coverage dropped".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// One advisory fixed on 1.x and 2.x, in repos on both lines, plus a 2.x-only one.
    fn two_line_report() -> FleetReport {
        let occ = |repo: &str, installed: &str, patched: &[&str]| {
            serde_json::json!({"kind": "in_repo", "repo": repo, "package": "foo",
                "installed": installed, "patched": patched, "dependency_kind": "direct",
                "dependency_path": ["foo"]})
        };
        let both = [">=1.4.2, <2.0.0", ">=2.1.0"];
        let vuln = |id: &str, occurrences: Vec<serde_json::Value>| {
            serde_json::json!({"advisory_id": id, "aliases": [], "title": id, "severity": "high",
                "affected_functions": [],
                "occurrences": occurrences})
        };
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "provenance": {"tool_version": "t", "rustsec_crate_version": "t", "host_os": "t",
                "host_arch": "t", "generated_at": "t"},
            "summary": {"repos_scanned": 3, "repos_errored": 0, "vuln_count": 2,
                "warn_count": 0, "max_severity": "high", "stale_ignores": []},
            "vulnerabilities": [
                vuln("RUSTSEC-A", vec![occ("old", "1.4.0", &both), occ("mixed", "1.3.0", &both),
                    occ("mixed", "2.0.0", &both), occ("new", "2.0.0", &both)]),
                vuln("RUSTSEC-B", vec![occ("new", "2.0.0", &[">=2.0.3"])]),
            ],
            "warnings": [],
            "outcomes": [],
            "package_versions": [{"package": "foo", "versions": [
                {"version": "1.3.0", "repos": ["mixed"]},
                {"version": "1.4.0", "repos": ["old"]},
                {"version": "2.0.0", "repos": ["mixed", "new"]}]}],
        }))
        .unwrap()
    }

    #[test]
    fn a_repo_on_an_older_line_gets_its_own_lines_fix() {
        let plan = build_plan(&two_line_report(), false);
        let by_repo = |repo: &str| plan.edits.iter().find(|e| e.repo == repo).unwrap();

        let old = by_repo("old");
        assert_eq!((old.to.as_str(), old.breaking), ("1.4.2", false));
        assert_eq!(old.strategy, Strategy::LockBump);
        assert_eq!(old.advisories, ["RUSTSEC-A"]);
        assert_eq!(old.risk, Some(fleetreach_core::Risk::Low));
        assert_eq!(old.risk_reasons[1], "instead of 2.1.0, a new major");

        let new = by_repo("new");
        assert_eq!((new.to.as_str(), new.breaking), ("2.1.0", false));
        assert_eq!(new.strategy, Strategy::LockBump);
        assert_ne!(new.campaign, old.campaign);

        // Versions on both lines: the main target, which is breaking for its 1.x copy.
        let mixed = by_repo("mixed");
        assert_eq!((mixed.to.as_str(), mixed.breaking), ("2.1.0", true));
        assert_eq!(mixed.strategy, Strategy::Blocked);
        assert_eq!(mixed.risk, Some(fleetreach_core::Risk::High));
    }

    #[test]
    fn an_edit_with_no_checkout_is_blocked_with_its_target_kept() {
        let edit = |repo: &str, strategy, reason: Option<&str>| Edit {
            campaign: "c".into(),
            repo: repo.into(),
            ecosystem: Ecosystem::Npm,
            package: "lodash".into(),
            from: vec!["4.17.15".into()],
            to: "4.18.1".into(),
            advisories: vec!["GHSA-A".into()],
            breaking: false,
            strategy,
            reason: reason.map(String::from),
            risk: None,
            risk_reasons: Vec::new(),
            ssvc: None,
        };
        let mut edits = [
            edit("nginx", Strategy::LockBump, None),
            edit("nginx", Strategy::Blocked, Some("no published fix")),
        ];
        fit_to_checkouts(&mut edits, &[]);
        assert_eq!(edits[0].strategy, Strategy::Blocked);
        assert_eq!(edits[0].to, "4.18.1");
        assert!(edits[0].reason.as_deref().unwrap_or("").contains("`nginx`"));
        assert_eq!(edits[1].reason.as_deref(), Some("no published fix"));
    }

    fn set(items: &[&str]) -> BTreeSet<&'static str> {
        items
            .iter()
            .map(|s| &*Box::leak(s.to_string().into_boxed_str()))
            .collect()
    }

    #[test]
    fn rewrites_only_vulnerable_tags_of_the_action() {
        let from = set(&["44.0.0"]);
        assert_eq!(
            rewrite_uses(
                "      - uses: tj-actions/changed-files@v44\n",
                "tj-actions/changed-files",
                &from,
                "46.0.1"
            )
            .as_deref(),
            Some("      - uses: tj-actions/changed-files@v46.0.1\n")
        );
        assert_eq!(
            rewrite_uses(
                "      uses: 'TJ-Actions/changed-files@44' # pinned\n",
                "tj-actions/changed-files",
                &from,
                "46.0.1"
            )
            .as_deref(),
            Some("      uses: 'TJ-Actions/changed-files@46.0.1' # pinned\n")
        );
        // Another action, a fixed tag, or a SHA pin: untouched.
        assert!(rewrite_uses(
            "- uses: actions/checkout@v44\n",
            "tj-actions/changed-files",
            &from,
            "46.0.1"
        )
        .is_none());
        assert!(rewrite_uses(
            "- uses: tj-actions/changed-files@v46\n",
            "tj-actions/changed-files",
            &from,
            "46.0.1"
        )
        .is_none());
        assert!(rewrite_uses(
            "- uses: tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67\n",
            "tj-actions/changed-files",
            &from,
            "46.0.1"
        )
        .is_none());
    }

    #[test]
    fn remote_hosts_pick_the_forge() {
        let host = |u: &str| remote_host(u);
        assert_eq!(
            host("https://gitlab.com/acme/app.git").as_deref(),
            Some("gitlab.com")
        );
        assert_eq!(
            host("git@gitlab.acme.io:team/app.git").as_deref(),
            Some("gitlab.acme.io")
        );
        assert_eq!(
            host("ssh://git@GitHub.com:22/acme/app").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            host("https://user:tok@gitlab.com/a/b").as_deref(),
            Some("gitlab.com")
        );
        assert_eq!(host("/srv/git/app.git"), None);
    }

    fn edit() -> Edit {
        Edit {
            campaign: "c".into(),
            repo: "app".into(),
            ecosystem: Ecosystem::Cargo,
            package: "foo".into(),
            from: vec!["1.0.0".into()],
            to: "1.2.0".into(),
            advisories: vec!["RUSTSEC-1".into()],
            breaking: false,
            strategy: Strategy::LockBump,
            reason: None,
            risk: None,
            risk_reasons: Vec::new(),
            ssvc: None,
        }
    }

    #[test]
    fn units_follow_the_grouping_preset() {
        use fleetreach_core::ssvc::Outcome as Ssvc;
        let at = |repo: &str, campaign: &str, ssvc: Option<Ssvc>| Edit {
            repo: repo.into(),
            campaign: campaign.into(),
            package: campaign.into(),
            ssvc,
            ..edit()
        };
        let edits = [
            at("a", "c1", Some(Ssvc::Immediate)),
            at("b", "c1", Some(Ssvc::Immediate)),
            at("a", "c2", Some(Ssvc::Defer)),
            at("a", "c3", Some(Ssvc::Immediate)),
            at("a", "c4", None),
        ];
        let refs: Vec<&Edit> = edits.iter().collect();
        let shape = |group| -> Vec<(String, String, Vec<String>)> {
            units(&refs, group)
                .into_iter()
                .map(|u| {
                    let c = u.edits.iter().map(|e| e.campaign.clone()).collect();
                    (u.repo, u.branch, c)
                })
                .collect()
        };
        assert_eq!(shape(Group::Package).len(), 5);
        assert_eq!(
            shape(Group::Repo),
            [
                (
                    "a".into(),
                    "fleetreach/all".into(),
                    vec!["c1".into(), "c2".into(), "c3".into(), "c4".into()]
                ),
                ("b".into(), "fleetreach/all".into(), vec!["c1".into()]),
            ]
        );
        let ssvc = shape(Group::Ssvc);
        let branches: Vec<(&str, &str)> = ssvc
            .iter()
            .map(|(r, b, _)| (r.as_str(), b.as_str()))
            .collect();
        assert_eq!(
            branches,
            [
                ("a", "fleetreach/ssvc-immediate"),
                ("b", "fleetreach/ssvc-immediate"),
                ("a", "fleetreach/ssvc-defer"),
                ("a", "fleetreach/ssvc-undecided"),
            ]
        );
        assert_eq!(ssvc[0].2, ["c1", "c3"]);
        let both = [&edits[0], &edits[3]];
        assert_eq!(
            group_title(&both, Group::Ssvc),
            "fix(deps): bump 2 packages (immediate)"
        );
        assert_eq!(
            group_title(&both[..1], Group::Repo),
            "fix(deps): bump c1 to 1.2.0"
        );
    }

    #[test]
    fn the_pr_body_states_the_bump_risk() {
        let mut e = edit();
        let plain = pr_body(
            &e,
            &Plan {
                schema: PLAN_SCHEMA.into(),
                edits: vec![],
                scanned: vec![],
            },
            "",
        );
        assert!(!plain.contains("**Risk:**"), "{plain}");
        e.risk = Some(fleetreach_core::Risk::Medium);
        e.risk_reasons = vec![
            "breaking (new major)".into(),
            "4 repos already run 2.0.0+".into(),
        ];
        let body = pr_body(
            &e,
            &Plan {
                schema: PLAN_SCHEMA.into(),
                edits: vec![],
                scanned: vec![],
            },
            "",
        );
        assert!(
            body.contains("**Risk:** medium (breaking (new major); 4 repos already run 2.0.0+)."),
            "{body}"
        );
    }

    fn scanned(findings: &[(&str, &str, &str)]) -> Scanned {
        Scanned {
            findings: findings
                .iter()
                .map(|(a, p, v)| ((*a).to_string(), (*p).to_string(), (*v).to_string()))
                .collect(),
            ..Scanned::default()
        }
    }

    #[test]
    fn verification_needs_the_advisory_gone_and_nothing_new() {
        let before = scanned(&[("RUSTSEC-1", "foo", "1.0.0"), ("RUSTSEC-9", "bar", "2.0.0")]);
        assert!(verify(&edit(), &before, &scanned(&[("RUSTSEC-9", "bar", "2.0.0")])).is_ok());
        let still = verify(&edit(), &before, &before).unwrap_err();
        assert!(still.contains("still present"), "{still}");
        let new = verify(
            &edit(),
            &before,
            &scanned(&[("RUSTSEC-9", "bar", "2.0.0"), ("RUSTSEC-7", "foo", "1.2.0")]),
        )
        .unwrap_err();
        assert!(new.contains("new findings: RUSTSEC-7"), "{new}");
        // An unfixed advisory on a package whose version moved is not new.
        assert!(verify(&edit(), &before, &scanned(&[("RUSTSEC-9", "bar", "2.0.1")])).is_ok());
        let mut errored = scanned(&[]);
        errored.errored = true;
        assert!(verify(&edit(), &before, &errored).is_err());
        assert!(
            verify(&edit(), &scanned(&[]), &scanned(&[])).is_err(),
            "nothing to fix"
        );
    }

    #[test]
    fn names_are_safe_for_branches_and_paths() {
        assert_eq!(safe("@scope/pkg"), "scope-pkg");
        assert_eq!(safe("tj-actions/changed-files"), "tj-actions-changed-files");
        assert_eq!(safe("../x"), "x");
        assert_eq!(branch_name(&edit()), "fleetreach/c/foo-1.2.0");
    }
}
