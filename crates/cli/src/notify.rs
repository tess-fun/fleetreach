//! `fleetreach notify` (spec 09): what the newest `scan --history-dir` run changed (new and
//! fixed findings) and every finding past its SLA, grouped by owner. It is delivered as a
//! webhook POST (a stable generic JSON payload, or a Slack Block Kit message), kept as one
//! issue per owner on GitHub (`gh`) or GitLab (`glab`), or printed.
//!
//! A webhook gets nothing when nothing changed and nothing is past due, unless `--always`.
//! Issues are found again by a hidden marker in their body and rewritten in place: reopened
//! when findings come back, closed when an owner has none open.
//!
//! Exit `0` when delivered (or nothing to send), `2` when the history cannot be read or
//! delivery fails, `3` for a webhook URL that is not HTTPS.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use clap::{Args, ValueEnum};
use fleetreach_core::ssvc::Outcome;
use fleetreach_core::{Ecosystem, Severity};
use fleetreach_report::sanitize_cell;
use serde::Serialize;
use serde_json::{json, Value};

use crate::cli::{fail, usage_fail};
use crate::config::Config;
use crate::fix::run;
use crate::history::{self, Entry, History, Status};

/// The generic payload's schema id; bumped only for incompatible changes.
pub const NOTIFY_SCHEMA: &str = "fleetreach-notify/1";

/// Most findings listed per section of a Slack message or an issue.
const SLACK_ITEMS: usize = 10;
const ISSUE_ROWS: usize = 200;

#[derive(Clone, Copy, ValueEnum)]
pub enum NotifyFormat {
    Generic,
    Slack,
}

#[derive(Args)]
pub struct NotifyArgs {
    /// The directory `scan --history-dir` writes
    #[arg(long)]
    history_dir: PathBuf,
    /// fleet.toml whose `[settings.sla]` judges breaches (without it none are reported)
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// POST the payload to this HTTPS URL (needs a build with the `network` feature)
    #[arg(long, conflicts_with_all = ["github_issues", "gitlab_issues"])]
    webhook: Option<String>,
    /// Payload for the webhook or stdout
    #[arg(short, long, value_enum, default_value = "generic")]
    format: NotifyFormat,
    /// Keep one issue per owner in `--repo`, with `gh`
    #[arg(long, requires = "repo", conflicts_with = "gitlab_issues")]
    github_issues: bool,
    /// Keep one issue per owner in `--repo`, with `glab`
    #[arg(long, requires = "repo")]
    gitlab_issues: bool,
    /// The repo issues go to (`owner/name`, or a GitLab project path)
    #[arg(long)]
    repo: Option<String>,
    /// Names the set of issues, so separate programs keep separate issues
    #[arg(long, default_value = "fleetreach")]
    campaign: String,
    /// Print what would be sent or changed instead
    #[arg(long)]
    dry_run: bool,
    /// Send to the webhook even when nothing changed
    #[arg(long)]
    always: bool,
}

/// The generic payload (`fleetreach-notify/1`).
#[derive(Debug, Serialize)]
pub struct Payload {
    pub schema: &'static str,
    pub run: RunRef,
    pub previous_run: Option<String>,
    pub summary: Summary,
    /// Owners with something to report, named owners first; `owner` is null for findings
    /// in repos without one.
    pub owners: Vec<OwnerSection>,
}

#[derive(Debug, Serialize)]
pub struct RunRef {
    pub id: String,
    pub at: String,
    pub exit_code: u8,
    /// The run exited `2`: part of the fleet was not read, so nothing could be marked fixed
    /// there and the open count is a floor.
    pub gap: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub new: usize,
    pub fixed: usize,
    pub breaches: usize,
    pub open: usize,
}

#[derive(Debug, Serialize)]
pub struct OwnerSection {
    pub owner: Option<String>,
    pub open: usize,
    pub new: Vec<Item>,
    pub fixed: Vec<Item>,
    pub breaches: Vec<Item>,
}

/// One finding as notified.
#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub advisory: String,
    pub ecosystem: Ecosystem,
    pub repo: String,
    pub package: String,
    pub version: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssvc: Option<Outcome>,
    pub first_seen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overdue_days: Option<f64>,
    pub url: String,
}

impl Item {
    fn of(e: &Entry) -> Item {
        Item {
            advisory: e.key.advisory.clone(),
            ecosystem: e.key.ecosystem,
            repo: e.key.repo.clone(),
            package: e.key.package.clone(),
            version: e.key.version.clone(),
            severity: e.severity,
            ssvc: e.ssvc,
            first_seen: e.first_seen.clone(),
            fixed_at: e.fixed_at.clone(),
            due: None,
            overdue_days: None,
            url: format!("https://osv.dev/vulnerability/{}", e.key.advisory),
        }
    }
}

/// Everything one owner has: the payload's view plus every open finding, for issues.
#[derive(Default)]
struct OwnerState {
    new: Vec<Item>,
    fixed: Vec<Item>,
    breaches: Vec<Item>,
    open: Vec<(Item, bool)>,
}

impl OwnerState {
    fn has_news(&self) -> bool {
        !(self.new.is_empty() && self.fixed.is_empty() && self.breaches.is_empty())
    }
}

/// Named owners in order, then the unowned.
fn owner_order(a: &Option<String>, b: &Option<String>) -> std::cmp::Ordering {
    match (a, b) {
        (Some(a), Some(b)) => a.cmp(b),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

struct Built {
    payload: Payload,
    owners: Vec<(Option<String>, OwnerState)>,
}

fn build(
    h: &History,
    policy: Option<&history::SlaPolicy>,
    at: time::OffsetDateTime,
) -> Option<Built> {
    let changes = history::changes(h)?;
    let mut owners: BTreeMap<Option<String>, OwnerState> = BTreeMap::new();
    let new_keys: std::collections::BTreeSet<_> = changes.new.iter().map(|e| &e.key).collect();
    // Every owner the index knows, so an owner whose findings are all gone still gets its
    // issue closed.
    for e in &h.index.entries {
        let state = owners.entry(e.owner.clone()).or_default();
        if e.status == Status::Open {
            state.open.push((Item::of(e), new_keys.contains(&e.key)));
        }
    }
    for e in &changes.new {
        owners
            .entry(e.owner.clone())
            .or_default()
            .new
            .push(Item::of(e));
    }
    for e in &changes.fixed {
        owners
            .entry(e.owner.clone())
            .or_default()
            .fixed
            .push(Item::of(e));
    }
    let mut breaches = 0;
    if let Some(policy) = policy {
        for b in history::sla(h, policy, at) {
            let mut item = Item::of(b.entry);
            item.due = Some(b.due.clone());
            item.overdue_days = Some(b.overdue_days);
            owners
                .entry(b.entry.owner.clone())
                .or_default()
                .breaches
                .push(item);
            breaches += 1;
        }
    }
    let mut owners: Vec<(Option<String>, OwnerState)> = owners.into_iter().collect();
    owners.sort_by(|a, b| owner_order(&a.0, &b.0));
    let summary = Summary {
        new: changes.new.len(),
        fixed: changes.fixed.len(),
        breaches,
        open: owners.iter().map(|(_, s)| s.open.len()).sum(),
    };
    let sections = owners
        .iter()
        .filter(|(_, s)| s.has_news())
        .map(|(owner, s)| OwnerSection {
            owner: owner.clone(),
            open: s.open.len(),
            new: s.new.clone(),
            fixed: s.fixed.clone(),
            breaches: s.breaches.clone(),
        })
        .collect();
    Some(Built {
        payload: Payload {
            schema: NOTIFY_SCHEMA,
            run: RunRef {
                id: changes.run.id.clone(),
                at: changes.run.at.clone(),
                exit_code: changes.run.exit_code,
                gap: changes.run.exit_code == 2,
            },
            previous_run: changes.previous.map(|r| r.id.clone()),
            summary,
            owners: sections,
        },
        owners,
    })
}

pub fn run_notify(args: &NotifyArgs) -> u8 {
    if let Some(url) = &args.webhook {
        if !allowed_url(url) {
            return usage_fail("--webhook must be an https:// URL (http:// only for localhost)");
        }
    }
    let policy = match &args.config {
        Some(path) => match Config::load(path) {
            Ok(c) if c.sla.is_empty() => {
                eprintln!(
                    "note: no [settings.sla] in {}; SLA breaches are not reported",
                    path.display()
                );
                None
            }
            Ok(c) => Some(c.sla),
            Err(e) => return fail(&e.to_string()),
        },
        None => None,
    };
    let h = match history::load(&args.history_dir) {
        Ok(h) => h,
        Err(e) => return fail(&e),
    };
    for u in &h.unreadable {
        eprintln!("warning: unreadable snapshot skipped: {u}");
    }
    let Some(built) = build(&h, policy.as_ref(), history::now()) else {
        return fail(&format!(
            "no scan history in {}; record some with `fleetreach scan --history-dir`",
            args.history_dir.display()
        ));
    };
    if built.payload.run.gap {
        eprintln!("note: the newest run exited 2; part of the fleet was not read");
    }
    if args.github_issues || args.gitlab_issues {
        let tracker = if args.github_issues {
            Tracker::GitHub
        } else {
            Tracker::GitLab
        };
        let repo = args.repo.as_deref().unwrap_or_default();
        return sync_issues(tracker, repo, &args.campaign, &built, args.dry_run);
    }
    let body = match render(&built.payload, args.format) {
        Ok(b) => b,
        Err(e) => return fail(&e),
    };
    let Some(url) = &args.webhook else {
        println!("{body}");
        return 0;
    };
    let s = &built.payload.summary;
    if s.new + s.fixed + s.breaches == 0 && !args.always {
        eprintln!("nothing new, fixed or past due; nothing sent (--always sends anyway)");
        return 0;
    }
    if args.dry_run {
        println!("{body}");
        eprintln!("dry run: would POST to {}", host_of(url));
        return 0;
    }
    match post_json(url, &body) {
        Ok(()) => {
            eprintln!(
                "sent: {} new, {} fixed, {} past SLA to {}",
                s.new,
                s.fixed,
                s.breaches,
                host_of(url)
            );
            0
        }
        Err(e) => fail(&e),
    }
}

fn render(payload: &Payload, format: NotifyFormat) -> Result<String, String> {
    let value = match format {
        NotifyFormat::Generic => serde_json::to_value(payload).map_err(|e| e.to_string())?,
        NotifyFormat::Slack => slack(payload),
    };
    serde_json::to_string_pretty(&value).map_err(|e| e.to_string())
}

fn label<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn owner_name(owner: Option<&str>) -> &str {
    owner.unwrap_or("(no owner)")
}

fn headline(s: &Summary) -> String {
    format!(
        "fleetreach: {} new, {} fixed, {} past SLA ({} open)",
        s.new, s.fixed, s.breaches, s.open
    )
}

// ---- Slack ----

/// Slack mrkdwn treats `&`, `<` and `>` as control characters.
fn mrkdwn(s: &str) -> String {
    sanitize_cell(s)
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn slack_lines(title: &str, items: &[Item], out: &mut Vec<String>) {
    if items.is_empty() {
        return;
    }
    out.push(format!("*{title}* ({})", items.len()));
    for i in items.iter().take(SLACK_ITEMS) {
        let mut line = format!(
            "• <{}|{}> {}@{} in {} ({}",
            i.url,
            mrkdwn(&i.advisory),
            mrkdwn(&i.package),
            mrkdwn(&i.version),
            mrkdwn(&i.repo),
            label(&i.severity)
        );
        if let Some(o) = i.ssvc {
            line.push_str(&format!(", SSVC {o}"));
        }
        if let Some(d) = i.overdue_days {
            line.push_str(&format!(", {d:.1} days overdue"));
        }
        line.push(')');
        out.push(line);
    }
    if items.len() > SLACK_ITEMS {
        out.push(format!("…and {} more", items.len() - SLACK_ITEMS));
    }
}

/// A Block Kit message: a header, a context line and one section per owner (Slack allows
/// 50 blocks and 3,000 characters per section, so both are capped).
fn slack(p: &Payload) -> Value {
    let mut context = format!("run `{}`", p.run.id);
    if p.run.gap {
        context.push_str(" · part of the fleet was not read");
    }
    let mut blocks = vec![
        json!({"type": "header", "text": {"type": "plain_text", "text": headline(&p.summary)}}),
        json!({"type": "context", "elements": [{"type": "mrkdwn", "text": context}]}),
    ];
    for o in p.owners.iter().take(45) {
        let mut lines = vec![format!(
            "*{}* · {} open",
            mrkdwn(owner_name(o.owner.as_deref())),
            o.open
        )];
        slack_lines("Past SLA", &o.breaches, &mut lines);
        slack_lines("New", &o.new, &mut lines);
        slack_lines("Fixed", &o.fixed, &mut lines);
        let mut text = lines.join("\n");
        if text.len() > 2900 {
            let mut cut = 2900;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            text.truncate(cut);
            text.push('…');
        }
        blocks.push(json!({"type": "section", "text": {"type": "mrkdwn", "text": text}}));
    }
    if p.owners.len() > 45 {
        blocks.push(json!({"type": "context", "elements": [{"type": "mrkdwn",
            "text": format!("…and {} more owners", p.owners.len() - 45)}]}));
    }
    json!({"text": headline(&p.summary), "blocks": blocks})
}

// ---- webhook ----

fn allowed_url(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    url.strip_prefix("http://").is_some_and(|rest| {
        let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host = host.rsplit_once(':').map_or(host, |(h, _)| h);
        matches!(host, "localhost" | "127.0.0.1" | "[::1]")
    })
}

/// The URL's host, for messages: webhook URLs carry their secret in the path.
fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    authority
        .rsplit_once('@')
        .map_or(authority, |(_, h)| h)
        .to_string()
}

#[cfg(feature = "network")]
fn post_json(url: &str, body: &str) -> Result<(), String> {
    use std::time::Duration;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    let host = host_of(url);
    agent
        .post(url)
        .header("Content-Type", "application/json")
        .send(body)
        .map(|_| ())
        .map_err(|e| format!("POST to {host}: {}", e.to_string().replace(url, &host)))
}

#[cfg(not(feature = "network"))]
fn post_json(_url: &str, _body: &str) -> Result<(), String> {
    Err(
        "this build has no network support; rebuild with `--features network`, or print the \
         payload (no --webhook) and send it with curl"
            .to_string(),
    )
}

// ---- issues ----

#[derive(Clone, Copy)]
enum Tracker {
    GitHub,
    GitLab,
}

struct Issue {
    number: u64,
    body: String,
    open: bool,
}

/// The hidden line that finds an owner's issue again.
fn marker(campaign: &str, owner: Option<&str>) -> String {
    let clean = |s: &str| -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '@' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .replace("--", "_")
    };
    format!(
        "<!-- fleetreach:campaign={};owner={} -->",
        clean(campaign),
        clean(owner.unwrap_or(""))
    )
}

fn cell(s: &str) -> String {
    sanitize_cell(s).replace('|', "\\|").replace('`', "'")
}

fn issue_title(campaign: &str, owner: Option<&str>, s: &OwnerState) -> String {
    let owner = sanitize_cell(owner_name(owner));
    match (s.open.len(), s.breaches.len()) {
        (0, _) => format!("{campaign}: no open findings for {owner}"),
        (n, 0) => format!("{campaign}: {n} open finding(s) for {owner}"),
        (n, b) => format!("{campaign}: {n} open finding(s) for {owner}, {b} past SLA"),
    }
}

fn issue_body(campaign: &str, owner: Option<&str>, s: &OwnerState, run: &RunRef) -> String {
    let mut out = vec![marker(campaign, owner), String::new()];
    out.push(format!(
        "**{} open finding(s)** for **{}** as of run `{}` ({}).",
        s.open.len(),
        cell(owner_name(owner)),
        run.id,
        run.at
    ));
    if run.gap {
        out.push(String::new());
        out.push(
            "> Part of the fleet was not read in this run, so the list may be incomplete."
                .to_string(),
        );
    }
    let row = |i: &Item| {
        format!(
            "[{}]({}) | {}@{} | {} | {}{}",
            cell(&i.advisory),
            i.url,
            cell(&i.package),
            cell(&i.version),
            cell(&i.repo),
            label(&i.severity),
            i.ssvc.map(|o| format!(" / {o}")).unwrap_or_default()
        )
    };
    let mut table = |title: &str, header: &str, rows: Vec<String>| {
        if rows.is_empty() {
            return;
        }
        out.push(String::new());
        out.push(format!("### {title} ({})", rows.len()));
        out.push(String::new());
        out.push(format!(
            "| Advisory | Package | Repo | Severity | {header} |"
        ));
        out.push("|---|---|---|---|---|".to_string());
        let more = rows.len().saturating_sub(ISSUE_ROWS);
        out.extend(
            rows.into_iter()
                .take(ISSUE_ROWS)
                .map(|r| format!("| {r} |")),
        );
        if more > 0 {
            out.push(format!("\n…and {more} more"));
        }
    };
    table(
        "Past SLA",
        "Due (overdue days)",
        s.breaches
            .iter()
            .map(|i| {
                format!(
                    "{} | {} ({:.1})",
                    row(i),
                    i.due.as_deref().unwrap_or("-"),
                    i.overdue_days.unwrap_or(0.0)
                )
            })
            .collect(),
    );
    table(
        "Open",
        "First seen",
        s.open
            .iter()
            .map(|(i, new)| {
                format!(
                    "{} | {}{}",
                    row(i),
                    i.first_seen,
                    if *new { " (new)" } else { "" }
                )
            })
            .collect(),
    );
    table(
        "Fixed in this run",
        "First seen",
        s.fixed
            .iter()
            .map(|i| format!("{} | {}", row(i), i.first_seen))
            .collect(),
    );
    out.push(String::new());
    out.push(
        "_Kept up to date by `fleetreach notify`; edits to this issue are overwritten._"
            .to_string(),
    );
    out.join("\n")
}

fn run_input(cmd: &mut Command, input: &str) -> Result<String, String> {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
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

impl Tracker {
    fn tool(self) -> &'static str {
        match self {
            Tracker::GitHub => "gh",
            Tracker::GitLab => "glab",
        }
    }

    fn list(self, repo: &str) -> Result<Vec<Issue>, String> {
        let parse = |text: &str, number: &str, body: &str| -> Result<Vec<Issue>, String> {
            let rows: Vec<Value> = serde_json::from_str(text)
                .map_err(|e| format!("{} issue list: {e}", self.tool()))?;
            Ok(rows
                .iter()
                .filter_map(|r| {
                    Some(Issue {
                        number: r.get(number)?.as_u64()?,
                        body: r
                            .get(body)
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        open: r
                            .get("state")
                            .and_then(Value::as_str)
                            .is_some_and(|s| s.eq_ignore_ascii_case("open") || s == "opened"),
                    })
                })
                .collect())
        };
        match self {
            Tracker::GitHub => parse(
                &run(Command::new("gh").args([
                    "issue",
                    "list",
                    "--repo",
                    repo,
                    "--state",
                    "all",
                    "--limit",
                    "1000",
                    "--json",
                    "number,body,state",
                ]))?,
                "number",
                "body",
            ),
            Tracker::GitLab => {
                let mut all = Vec::new();
                for page in 1..=50 {
                    let page = page.to_string();
                    let text = run(Command::new("glab").args([
                        "issue",
                        "list",
                        "-R",
                        repo,
                        "--all",
                        "--output",
                        "json",
                        "--per-page",
                        "100",
                        "--page",
                        &page,
                    ]))?;
                    let rows = parse(&text, "iid", "description")?;
                    let done = rows.len() < 100;
                    all.extend(rows);
                    if done {
                        break;
                    }
                }
                Ok(all)
            }
        }
    }

    fn create(self, repo: &str, title: &str, body: &str) -> Result<String, String> {
        match self {
            Tracker::GitHub => run_input(
                Command::new("gh").args([
                    "issue",
                    "create",
                    "--repo",
                    repo,
                    "--title",
                    title,
                    "--body-file",
                    "-",
                ]),
                body,
            ),
            Tracker::GitLab => run(Command::new("glab").args([
                "issue",
                "create",
                "-R",
                repo,
                "--title",
                title,
                "--description",
                body,
                "--yes",
            ])),
        }
    }

    fn update(self, repo: &str, number: u64, title: &str, body: &str) -> Result<(), String> {
        let n = number.to_string();
        match self {
            Tracker::GitHub => run_input(
                Command::new("gh").args([
                    "issue",
                    "edit",
                    &n,
                    "--repo",
                    repo,
                    "--title",
                    title,
                    "--body-file",
                    "-",
                ]),
                body,
            ),
            Tracker::GitLab => run(Command::new("glab").args([
                "issue",
                "update",
                &n,
                "-R",
                repo,
                "--title",
                title,
                "--description",
                body,
            ])),
        }
        .map(|_| ())
    }

    fn set_open(self, repo: &str, number: u64, open: bool) -> Result<(), String> {
        let n = number.to_string();
        let verb = if open { "reopen" } else { "close" };
        let repo_flag = match self {
            Tracker::GitHub => "--repo",
            Tracker::GitLab => "-R",
        };
        run(Command::new(self.tool()).args(["issue", verb, &n, repo_flag, repo])).map(|_| ())
    }
}

/// Bring each owner's issue in line with the history: create or rewrite it while the owner
/// has open findings (reopening a closed one), close it once they have none.
fn sync_issues(tracker: Tracker, repo: &str, campaign: &str, built: &Built, dry_run: bool) -> u8 {
    let existing = if dry_run {
        Ok(Vec::new())
    } else {
        tracker.list(repo)
    };
    let existing = match existing {
        Ok(e) => e,
        Err(e) => return fail(&format!("{} issue list: {e}", tracker.tool())),
    };
    let mut failures = 0;
    for (owner, state) in &built.owners {
        let mark = marker(campaign, owner.as_deref());
        let found = existing
            .iter()
            .find(|i| i.body.lines().next().is_some_and(|l| l.trim() == mark));
        let title = issue_title(campaign, owner.as_deref(), state);
        let body = issue_body(campaign, owner.as_deref(), state, &built.payload.run);
        let wanted_open = !state.open.is_empty();
        if dry_run {
            if wanted_open {
                println!(
                    "--- issue for {}: {title}\n{body}\n",
                    owner_name(owner.as_deref())
                );
            }
            continue;
        }
        let result = match (found, wanted_open) {
            (None, false) => continue,
            (None, true) => tracker.create(repo, &title, &body).map(|url| {
                eprintln!("created: {}", if url.is_empty() { &title } else { &url });
            }),
            (Some(issue), _) => (|| {
                if wanted_open && !issue.open {
                    tracker.set_open(repo, issue.number, true)?;
                }
                if wanted_open || issue.open {
                    tracker.update(repo, issue.number, &title, &body)?;
                }
                if !wanted_open && issue.open {
                    tracker.set_open(repo, issue.number, false)?;
                    eprintln!("closed #{}: {}", issue.number, owner_name(owner.as_deref()));
                } else if wanted_open {
                    eprintln!("updated #{}: {title}", issue.number);
                }
                Ok(())
            })(),
        };
        if let Err(e) = result {
            eprintln!("error: issue for {}: {e}", owner_name(owner.as_deref()));
            failures += 1;
        }
    }
    if dry_run {
        eprintln!("dry run: no issues listed or changed in {repo}");
    }
    if failures > 0 {
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_urls_must_be_https_except_on_localhost() {
        assert!(allowed_url("https://hooks.slack.com/services/T/B/x"));
        assert!(allowed_url("http://localhost:8080/hook"));
        assert!(allowed_url("http://127.0.0.1/hook"));
        assert!(!allowed_url("http://example.com/hook"));
        assert!(!allowed_url("http://localhost.example.com/hook"));
        assert!(!allowed_url("ftp://localhost/hook"));
        assert_eq!(
            host_of("https://user:secret@hooks.slack.com/services/T/B/x"),
            "hooks.slack.com"
        );
    }

    #[test]
    fn markers_cannot_close_the_comment() {
        let m = marker("q4 --> push", Some("team<a>"));
        assert_eq!(m, "<!-- fleetreach:campaign=q4____push;owner=team_a_ -->");
        assert_eq!(m.matches("-->").count(), 1);
    }

    #[test]
    fn slack_text_escapes_control_characters() {
        assert_eq!(mrkdwn("<a&b>"), "&lt;a&amp;b&gt;");
    }
}
