//! `fleetreach fix`: turn the remediation queue into verified lockfile changes (spec 07,
//! phases 1 and 2).
//!
//! - `fix plan` reads a saved `scan -f json` report and writes one edit per repo per
//!   remediation item: a `lock-bump` when an ecosystem's lock-only update can apply it, or
//!   `blocked` with the reason (no published fix, a semver-major jump without
//!   `--allow-breaking`, an ecosystem `apply` does not handle yet).
//! - `fix apply` performs each `lock-bump` in a git worktree on a `fleetreach/<campaign>/...`
//!   branch, never in the user's own work tree, with a lock-only command that runs no package
//!   code (`cargo update --precise`, `npm update --package-lock-only --ignore-scripts`, a
//!   text edit of a workflow `uses:` tag). It then **verifies** the change by running
//!   fleetreach's own scan on the work tree before and after: every targeted advisory must be
//!   gone, nothing new may appear, and the repo must still scan without errors or new
//!   coverage gaps. The commit stays on its branch either way, marked verified or not;
//!   nothing is pushed.
//!
//! The scan runs as a subprocess of the same binary with the flags given after `--`, so a
//! verification sees exactly what `fleetreach scan` reports.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Args, Subcommand};
use fleetreach_core::{remediations, Action, Ecosystem, FleetReport, Occurrence};
use serde::{Deserialize, Serialize};

use crate::cli::fail;
use crate::config::{Config, Repo};
use crate::sources;

/// The plan file format.
const PLAN_SCHEMA: &str = "fleetreach-fix-plan/1";

#[derive(Subcommand)]
pub enum FixCommand {
    /// Write a fix plan (JSON, stdout) from a saved `scan -f json` report.
    Plan(FixPlanArgs),
    /// Apply a plan's lock bumps on local branches, each verified by a re-scan.
    Apply(FixApplyArgs),
    /// List each repo's fleetreach pull requests and their state (via `gh`).
    Status(FixStatusArgs),
}

#[derive(Args)]
pub struct FixStatusArgs {
    /// fleet.toml naming the repos
    #[arg(short, long, default_value = "./fleet.toml")]
    config: PathBuf,
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
    #[arg(short, long, help = "no progress output")]
    quiet: bool,
    /// Push each verified branch to the repo's `origin` (only `fleetreach/*` branches;
    /// unverified ones are never pushed)
    #[arg(long)]
    push: bool,
    /// Open (or update) a pull request for each pushed branch with `gh`; implies --push
    #[arg(long)]
    open_pr: bool,
    /// Open pull requests as drafts
    #[arg(long)]
    draft: bool,
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Plan {
    pub schema: String,
    pub edits: Vec<Edit>,
}

/// Ecosystems `fix apply` can bump without running package code.
fn applicable(ecosystem: Ecosystem) -> bool {
    matches!(
        ecosystem,
        Ecosystem::Cargo | Ecosystem::Npm | Ecosystem::GitHubActions
    )
}

/// Build the plan from a report. Soundly unreachable items are left out (they are not work).
pub fn build_plan(report: &FleetReport, allow_breaking: bool) -> Plan {
    let mut edits = Vec::new();
    for item in remediations(report) {
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
        let (strategy, reason) = match &item.action {
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
            edits.push(Edit {
                campaign: campaign.clone(),
                repo,
                ecosystem: item.ecosystem,
                package: item.package.clone(),
                from: from.into_iter().collect(),
                to: to.clone(),
                advisories: item.advisories.clone(),
                breaking,
                strategy: strategy.clone(),
                reason: reason.clone(),
            });
        }
    }
    edits.sort_by(|a, b| (&a.repo, &a.campaign).cmp(&(&b.repo, &b.campaign)));
    Plan {
        schema: PLAN_SCHEMA.to_string(),
        edits,
    }
}

fn campaign_id(ecosystem: Ecosystem, package: &str, to: &str, advisories: &[String]) -> String {
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

fn run_plan(args: &FixPlanArgs) -> u8 {
    // The config is loaded only to fail early on a bad one; the plan names repos by id.
    if let Err(e) = Config::load(&args.config) {
        return fail(&e.to_string());
    }
    let report: FleetReport = match std::fs::read_to_string(&args.report)
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
    {
        Ok(r) => r,
        Err(e) => return fail(&format!("report `{}`: {e}", args.report.display())),
    };
    let plan = build_plan(&report, args.allow_breaking);
    match serde_json::to_string_pretty(&plan) {
        Ok(json) => {
            println!("{json}");
            let bumps = plan
                .edits
                .iter()
                .filter(|e| e.strategy == Strategy::LockBump)
                .count();
            eprintln!(
                "{} edit(s): {bumps} lock bump(s), {} blocked",
                plan.edits.len(),
                plan.edits.len() - bumps
            );
            0
        }
        Err(e) => fail(&e.to_string()),
    }
}

// ---- apply ----

#[derive(Debug, Serialize, PartialEq, Eq)]
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
    let Some(work_root) = crate::osvdb::private_subdir("fix") else {
        return fail("no usable cache directory for fix work trees");
    };

    let mut results = Vec::new();
    let mut repos_touched: BTreeSet<String> = BTreeSet::new();
    for edit in &plan.edits {
        let skip = |why: &str| Applied {
            repo: edit.repo.clone(),
            package: edit.package.clone(),
            to: edit.to.clone(),
            campaign: edit.campaign.clone(),
            outcome: Outcome::Skipped,
            branch: None,
            detail: why.to_string(),
            pull_request: None,
        };
        if edit.strategy != Strategy::LockBump {
            results.push(skip(
                edit.reason.as_deref().unwrap_or("blocked in the plan"),
            ));
            continue;
        }
        if !args.repos.is_empty() && !args.repos.contains(&edit.repo) {
            continue;
        }
        if !repos_touched.contains(&edit.repo) && repos_touched.len() >= args.max_repos {
            results.push(skip("over --max-repos for this run"));
            continue;
        }
        let Some(repo) = config.repos.iter().find(|r| r.id.0 == edit.repo) else {
            results.push(skip("repo not in fleet.toml"));
            continue;
        };
        repos_touched.insert(edit.repo.clone());
        if !args.quiet {
            eprintln!("{}: {} -> {} ...", edit.repo, edit.package, edit.to);
        }
        let mut result = apply_one(edit, repo, &work_root, &args.scan_args);
        if result.outcome == Outcome::Verified && (args.push || args.open_pr) {
            publish(&mut result, edit, repo, &plan, args);
        }
        if !args.quiet {
            eprintln!("  {:?}: {}", result.outcome, result.detail);
        }
        results.push(result);
    }

    match serde_json::to_string_pretty(&results) {
        Ok(json) => println!("{json}"),
        Err(e) => return fail(&e.to_string()),
    }
    let count = |o: Outcome| results.iter().filter(|r| r.outcome == o).count();
    eprintln!(
        "{} verified, {} unverified, {} blocked, {} skipped{}",
        count(Outcome::Verified),
        count(Outcome::Unverified),
        count(Outcome::Blocked),
        count(Outcome::Skipped),
        if args.push || args.open_pr {
            ""
        } else {
            " (nothing pushed)"
        }
    );
    // Like scan: 0 when everything planned was verified, 1 when some edit did not land.
    u8::from(count(Outcome::Unverified) + count(Outcome::Blocked) > 0)
}

fn apply_one(edit: &Edit, repo: &Repo, work_root: &Path, scan_args: &[String]) -> Applied {
    let mut out = Applied {
        repo: edit.repo.clone(),
        package: edit.package.clone(),
        to: edit.to.clone(),
        campaign: edit.campaign.clone(),
        outcome: Outcome::Blocked,
        branch: None,
        detail: String::new(),
        pull_request: None,
    };
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
            "-B",
            &branch,
            path_str(&tree),
            "HEAD",
        ],
    ) {
        out.detail = format!("could not create a work tree: {e}");
        return out;
    }
    let cleanup = |keep_branch: bool| {
        let _ = git(&top, &["worktree", "remove", "--force", path_str(&tree)]);
        if !keep_branch {
            let _ = git(&top, &["branch", "-D", &branch]);
        }
    };
    let work = tree.join(&rel);

    let before = match scan(&work, repo, scan_args) {
        Ok(s) => s,
        Err(e) => {
            cleanup(false);
            out.detail = format!("baseline scan failed: {e}");
            return out;
        }
    };
    let changed = match apply_edit(&work, edit) {
        Ok(c) => c,
        Err(e) => {
            cleanup(false);
            out.detail = e;
            return out;
        }
    };
    if git(&tree, &["status", "--porcelain"]).is_ok_and(|s| s.is_empty()) {
        cleanup(false);
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
        "{title}\n\nClears {} ({} campaign {}).\n{}\n",
        edit.advisories.join(", "),
        ecosystem_name(edit.ecosystem),
        edit.campaign,
        if outcome == Outcome::Verified {
            "Verified by a fleetreach re-scan: the advisories are gone and nothing new appeared."
        } else {
            "Not verified by the fleetreach re-scan; review before using."
        }
    );
    let committed =
        git(&tree, &["add", "-A"]).and_then(|_| git(&tree, &["commit", "--quiet", "-m", &message]));
    if let Err(e) = committed {
        cleanup(false);
        out.detail = format!("could not commit: {e}");
        return out;
    }
    cleanup(true);
    out.outcome = outcome;
    out.branch = Some(branch);
    out.detail = detail;
    out
}

// ---- publish ----

/// Push a verified branch and, with `--open-pr`, open or update its pull request.
fn publish(result: &mut Applied, edit: &Edit, repo: &Repo, plan: &Plan, args: &FixApplyArgs) {
    let Some(branch) = result.branch.clone() else {
        return;
    };
    if !branch.starts_with("fleetreach/") {
        return; // never push anything but our own branches
    }
    let top = match git(&repo.path, &["rev-parse", "--show-toplevel"]) {
        Ok(t) => PathBuf::from(t),
        Err(e) => {
            result.detail.push_str(&format!("; push skipped: {e}"));
            return;
        }
    };
    // The branch is fleetreach's own, rebuilt from HEAD on every run, so a lease-protected
    // force push is what keeps it current without touching anyone else's work.
    if let Err(e) = git(
        &top,
        &[
            "push",
            "--quiet",
            "--force-with-lease",
            "origin",
            &format!("{branch}:{branch}"),
        ],
    ) {
        result.detail.push_str(&format!("; push failed: {e}"));
        return;
    }
    result.detail.push_str("; pushed");
    if !args.open_pr {
        return;
    }
    let title = format!("fix(deps): bump {} to {}", edit.package, edit.to);
    let body = pr_body(edit, plan);
    let existing = run(Command::new("gh").current_dir(&top).args([
        "pr", "list", "--head", &branch, "--state", "open", "--json", "url", "--jq", ".[0].url",
    ]))
    .ok()
    .filter(|u| !u.is_empty());
    let outcome = match &existing {
        Some(url) => run(Command::new("gh")
            .current_dir(&top)
            .args(["pr", "edit", url, "--title", &title, "--body", &body]))
        .map(|_| url.clone()),
        None => {
            let mut cmd = Command::new("gh");
            cmd.current_dir(&top).args([
                "pr", "create", "--head", &branch, "--title", &title, "--body", &body,
            ]);
            if args.draft {
                cmd.arg("--draft");
            }
            run(&mut cmd).map(|out| out.lines().last().unwrap_or_default().to_string())
        }
    };
    match outcome {
        Ok(url) => {
            result.detail.push_str(if existing.is_some() {
                "; pull request updated"
            } else {
                "; pull request opened"
            });
            result.pull_request = Some(url);
        }
        Err(e) => result
            .detail
            .push_str(&format!("; pull request failed: {e}")),
    }
}

/// The pull request description: what it fixes, how it was checked, and the campaign.
fn pr_body(edit: &Edit, plan: &Plan) -> String {
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
    if edit.breaking {
        body.push_str("**Breaking:** this crosses a major version; review the changelog.\n\n");
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
        let listed = run(Command::new("gh").current_dir(&repo.path).args([
            "pr",
            "list",
            "--state",
            "all",
            "--limit",
            "200",
            "--json",
            "headRefName,state,url,title",
        ]));
        match listed
            .and_then(|j| serde_json::from_str::<serde_json::Value>(&j).map_err(|e| e.to_string()))
        {
            Ok(prs) => {
                for pr in prs.as_array().into_iter().flatten() {
                    let head = pr["headRefName"].as_str().unwrap_or_default();
                    if head.starts_with("fleetreach/") {
                        rows.push(serde_json::json!({
                            "repo": repo.id.0, "branch": head, "state": pr["state"],
                            "title": pr["title"], "url": pr["url"],
                        }));
                    }
                }
            }
            Err(e) => {
                failed += 1;
                eprintln!("error: {}: {e}", repo.id);
            }
        }
    }
    match serde_json::to_string_pretty(&rows) {
        Ok(json) => println!("{json}"),
        Err(e) => return fail(&e.to_string()),
    }
    u8::from(failed > 0) * 2
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

fn run(cmd: &mut Command) -> Result<String, String> {
    let output = cmd.output().map_err(|e| format!("{e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(stderr
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("failed")
            .to_string())
    }
}

// ---- edits ----

/// Apply the lock-only update; returns a short description of what ran.
fn apply_edit(work: &Path, edit: &Edit) -> Result<String, String> {
    match edit.ecosystem {
        Ecosystem::Cargo => cargo_bump(work, edit),
        Ecosystem::Npm => npm_bump(work, edit),
        Ecosystem::GitHubActions => actions_bump(work, edit),
        other => Err(format!(
            "fix apply does not handle {} yet",
            ecosystem_name(other)
        )),
    }
}

/// Directories under `root` (skipping VCS and dependency directories) holding `file`.
fn dirs_with(root: &Path, file: &str) -> Vec<PathBuf> {
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
fn npm_bump(work: &Path, edit: &Edit) -> Result<String, String> {
    let needle = format!("\"node_modules/{}\"", edit.package);
    let dirs: Vec<PathBuf> = dirs_with(work, "package-lock.json")
        .into_iter()
        .filter(|d| {
            std::fs::read_to_string(d.join("package-lock.json")).is_ok_and(|t| t.contains(&needle))
        })
        .collect();
    if dirs.is_empty() {
        return Err(format!(
            "no package-lock.json holds {} (pnpm and yarn lockfiles are not handled yet)",
            edit.package
        ));
    }
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
    Ok(format!(
        "npm update {} --package-lock-only in {} dir(s)",
        edit.package,
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
    let new: Vec<String> = after
        .findings
        .difference(&before.findings)
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
        }
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
