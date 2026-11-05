//! Triage files (spec 16, row 6): one decision per finding key, kept in git beside the fleet.
//! `triage/<advisory>/<ecosystem>-<package>.toml` holds the state, assignee, expiry and an
//! append-only log, so two people triaging different findings never touch the same file and
//! the audit trail is the repo's history. `scan` reads them; `fleetreach triage set`, `list`
//! and `export` write, show and publish them.
//!
//! A decision sets a finding aside only in `accepted_risk`, `false_positive` or `not_affected`,
//! until it expires. An expired decision no longer hides its finding, and fails the scan.

use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use fleetreach_core::{DepSource, Ecosystem, FleetReport, RepoId};
use fleetreach_report as report;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::{Date, Month};

use crate::assemble::{matches_any, Suppression};
use crate::cli::fail;
use crate::config::{Config, Ignore, VEX_JUSTIFICATIONS};
use crate::history::{format_time, now};

/// What is known about a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub enum State {
    Affected,
    InTriage,
    AcceptedRisk,
    FalsePositive,
    NotAffected,
    Fixed,
}

impl State {
    /// Whether a decision in this state sets its finding aside.
    fn sets_aside(self) -> bool {
        matches!(
            self,
            State::AcceptedRisk | State::FalsePositive | State::NotAffected
        )
    }

    fn as_str(self) -> &'static str {
        match self {
            State::Affected => "affected",
            State::InTriage => "in_triage",
            State::AcceptedRisk => "accepted_risk",
            State::FalsePositive => "false_positive",
            State::NotAffected => "not_affected",
            State::Fixed => "fixed",
        }
    }
}

/// One entry of a decision's append-only log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogEntry {
    pub at: String,
    pub by: String,
    pub state: State,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The contents of one triage file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub advisory: String,
    /// The advisory's other ids, which `export` also writes statements for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub ecosystem: Ecosystem,
    pub package: String,
    pub state: State,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    /// The last day the decision holds, `YYYY-MM-DD`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// One of [`VEX_JUSTIFICATIONS`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Empty = every repo of the fleet.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<String>,
    #[serde(default)]
    pub log: Vec<LogEntry>,
}

pub(crate) fn parse_day(s: &str) -> Option<Date> {
    let mut parts = s.split('-');
    let (year, month, day) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || year.len() != 4 || month.len() != 2 || day.len() != 2 {
        return None;
    }
    let month = Month::try_from(month.parse::<u8>().ok()?).ok()?;
    Date::from_calendar_date(year.parse().ok()?, month, day.parse().ok()?).ok()
}

impl Decision {
    fn check(&self) -> Result<(), String> {
        if self.advisory.is_empty() || self.package.is_empty() {
            return Err("`advisory` and `package` must not be empty".to_string());
        }
        if let Some(day) = &self.expires {
            if parse_day(day).is_none() {
                return Err(format!("`expires` `{day}` is not a YYYY-MM-DD date"));
            }
        }
        if let Some(j) = &self.justification {
            if !VEX_JUSTIFICATIONS.contains(&j.as_str()) {
                return Err(format!(
                    "`justification` `{j}` is not one of {}",
                    VEX_JUSTIFICATIONS.join(", ")
                ));
            }
        }
        let reasonless = self.reason.as_deref().is_none_or(|r| r.trim().is_empty());
        if self.state.sets_aside() && reasonless {
            return Err(format!("`{}` needs a `reason`", self.state.as_str()));
        }
        Ok(())
    }

    fn expired(&self, today: Date) -> bool {
        let last = self.expires.as_deref().and_then(parse_day);
        self.state.sets_aside() && last.is_some_and(|day| today > day)
    }

    /// The suppressions this decision makes, one per repo it is scoped to.
    fn suppressions(&self) -> Vec<Suppression> {
        let one = |repo: Option<RepoId>| Suppression {
            id: self.advisory.clone(),
            repo,
            package: None,
            scope: Some((self.ecosystem, self.package.clone())),
            justification: self.justification.clone(),
            reason: self.reason.clone().unwrap_or_default(),
            approved_by: self.log.last().map(|entry| entry.by.clone()),
            accepted_risk: self.state == State::AcceptedRisk,
        };
        if self.repos.is_empty() {
            return vec![one(None)];
        }
        let repos = self.repos.iter().map(|r| Some(RepoId(r.clone())));
        repos.map(one).collect()
    }
}

/// A name as one path segment: anything but plain characters is percent-encoded, so a scoped
/// npm package or a Maven coordinate stays one file, and nothing climbs out of the directory.
fn segment(name: &str) -> String {
    let plain = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-');
    let mut out = String::with_capacity(name.len());
    for byte in name.bytes() {
        if plain(byte) && !(byte == b'.' && out.is_empty()) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn ecosystem_name(ecosystem: Ecosystem) -> String {
    serde_json::to_value(ecosystem)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Where the decision on this finding key lives, relative to the triage directory.
fn relative_path(advisory: &str, ecosystem: Ecosystem, package: &str) -> PathBuf {
    let file = format!("{}-{}.toml", ecosystem_name(ecosystem), segment(package));
    Path::new(&segment(advisory)).join(file)
}

fn toml_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if path.is_dir() {
            toml_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "toml") {
            out.push(path);
        }
    }
    Ok(())
}

fn read_decision(dir: &Path, path: &Path) -> Result<Decision, String> {
    let at = |e: String| format!("{}: {e}", path.display());
    let text = std::fs::read_to_string(path).map_err(|e| at(e.to_string()))?;
    let decision: Decision = toml::from_str(&text).map_err(|e| at(e.to_string()))?;
    decision.check().map_err(at)?;
    let expected = relative_path(&decision.advisory, decision.ecosystem, &decision.package);
    if path.strip_prefix(dir).ok() != Some(expected.as_path()) {
        return Err(at(format!(
            "this decision belongs at {}, so `set` would not find it",
            expected.display()
        )));
    }
    Ok(decision)
}

/// Every decision under `dir`, sorted by path. Any file that cannot be read stops the caller:
/// a decision silently skipped would put a finding back, or leave an expiry unnoticed.
pub fn read_all(dir: &Path) -> Result<Vec<Decision>, String> {
    let mut paths = Vec::new();
    toml_files(dir, &mut paths)?;
    paths.sort();
    paths.iter().map(|p| read_decision(dir, p)).collect()
}

/// [`read_all`] for the default `triage/`, which nobody chose and may hold someone else's files:
/// one that names no advisory is passed over with a warning. A decision that is broken still
/// stops the scan.
fn read_default(dir: &Path) -> Result<Vec<Decision>, String> {
    let mut paths = Vec::new();
    toml_files(dir, &mut paths)?;
    paths.sort();
    let (ours, others): (Vec<_>, Vec<_>) = paths.into_iter().partition(|path| {
        let text = std::fs::read_to_string(path);
        text.map_or(true, |text| text.contains("advisory"))
    });
    for path in others {
        eprintln!(
            "warning: {} is not a triage decision; set [settings.triage] dir if triage/ is \
             not for fleetreach",
            path.display()
        );
    }
    ours.iter().map(|p| read_decision(dir, p)).collect()
}

/// A fleet's decisions, split for a scan.
#[derive(Debug, Default)]
pub struct Triage {
    /// What sets findings aside today.
    pub suppressions: Vec<Suppression>,
    /// What set findings aside until it expired: how to name it, and its last day.
    expired: Vec<(Suppression, String, String)>,
}

fn ignore_expired(ignore: &Ignore, today: Date) -> bool {
    let last = ignore.expires.as_deref().and_then(parse_day);
    last.is_some_and(|day| today > day)
}

/// The `[[settings.ignore]]` entries that still hold today.
pub(crate) fn live_ignores(config: &Config) -> impl Iterator<Item = &Ignore> {
    let today = now().date();
    config
        .ignores
        .iter()
        .filter(move |i| !ignore_expired(i, today))
}

impl Triage {
    /// The decisions of `config`'s fleet, or `dir` over it. An absent default directory is a
    /// fleet that triages nothing; an absent one that was asked for is an error.
    pub fn load(config: &Config, dir: Option<&Path>) -> Result<Triage, String> {
        let chosen = dir.unwrap_or(&config.triage.dir);
        if !chosen.exists() {
            if dir.is_some() || config.triage.explicit {
                return Err(format!(
                    "triage directory {} does not exist",
                    chosen.display()
                ));
            }
            return Ok(Triage::of(&[], &config.ignores, now().date()));
        }
        let asked = dir.is_some() || config.triage.explicit;
        let read = if asked { read_all } else { read_default };
        let decisions = read(chosen).map_err(|e| format!("triage file {e}"))?;
        Ok(Triage::of(&decisions, &config.ignores, now().date()))
    }

    fn of(decisions: &[Decision], ignores: &[Ignore], today: Date) -> Triage {
        let mut triage = Triage::default();
        for ignore in ignores.iter().filter(|i| ignore_expired(i, today)) {
            let name = match &ignore.owner {
                Some(owner) => format!("ignore of {} (owner {owner})", ignore.id),
                None => format!("ignore of {}", ignore.id),
            };
            let day = ignore.expires.clone().unwrap_or_default();
            let suppression = Suppression::from_ignore(ignore);
            triage.expired.push((suppression, name, day));
        }
        for decision in decisions.iter().filter(|d| d.state.sets_aside()) {
            if decision.expired(today) {
                let day = decision.expires.clone().unwrap_or_default();
                let lapsed = decision.suppressions().into_iter().map(|s| {
                    let package = s.scope.as_ref().map_or("", |(_, p)| p.as_str());
                    let name = format!("triage decision on {} in {package}", s.id);
                    (s, name, day.clone())
                });
                triage.expired.extend(lapsed);
            } else {
                triage.suppressions.extend(decision.suppressions());
            }
        }
        triage
    }

    /// Say which open findings an expired decision used to set aside, and whether any do.
    pub fn report_expired(&self, report: &FleetReport) -> bool {
        let mut any = false;
        for (suppression, name, day) in &self.expired {
            if matches_any(report, std::slice::from_ref(suppression)) {
                any = true;
                eprintln!("error: {name} expired on {day}, and the finding is open");
            }
        }
        any
    }
}

// ---- `fleetreach triage` ----

/// The directory options every `triage` subcommand shares.
#[derive(Parser, Debug)]
pub struct Place {
    #[arg(short, long, help = "fleet.toml (default: ./fleet.toml, if there)")]
    config: Option<PathBuf>,
    #[arg(
        long,
        help = "the triage directory (default: `triage/` beside fleet.toml)"
    )]
    dir: Option<PathBuf>,
}

impl Place {
    /// The fleet's config: the one named, else `./fleet.toml` if there. One that cannot be read
    /// stops the command, where falling back would write decisions somewhere else.
    fn config(&self) -> Result<Option<Config>, String> {
        let default = Path::new("fleet.toml");
        let path = match &self.config {
            Some(path) => path.as_path(),
            None if default.exists() => default,
            None => return Ok(None),
        };
        Config::load(path).map(Some).map_err(|e| e.to_string())
    }

    fn resolve(&self) -> Result<PathBuf, String> {
        if let Some(dir) = &self.dir {
            return Ok(dir.clone());
        }
        let config = self.config()?;
        Ok(config.map_or_else(|| PathBuf::from("triage"), |c| c.triage.dir))
    }
}

#[derive(clap::Subcommand, Debug)]
pub enum TriageCommand {
    /// Record a decision on a finding, appending to its log.
    Set(SetArgs),
    /// Show the decisions.
    List(ListArgs),
    /// Publish the decisions as OpenVEX.
    Export(ExportArgs),
}

#[derive(Parser, Debug)]
pub struct SetArgs {
    /// The advisory id, as the scan reports it.
    advisory: String,
    #[arg(long, help = "the package the decision is about")]
    package: String,
    #[arg(long, value_parser = parse_ecosystem, help = "its ecosystem, as in the report (npm, pypi, cargo, ...)")]
    ecosystem: Ecosystem,
    #[arg(long, value_enum, help = "the state to record")]
    state: State,
    #[arg(long, help = "why (required to set a finding aside)")]
    reason: Option<String>,
    #[arg(long, help = "who owns the finding")]
    assignee: Option<String>,
    #[arg(
        long,
        value_name = "YYYY-MM-DD",
        help = "the last day the decision holds"
    )]
    expires: Option<String>,
    #[arg(long, help = "an OpenVEX justification label")]
    justification: Option<String>,
    #[arg(long, help = "another id of the advisory, for export (repeatable)")]
    alias: Vec<String>,
    #[arg(long, help = "only this repo (repeatable; default: the whole fleet)")]
    repo: Vec<String>,
    #[arg(long, help = "who decided (default: git's user.name, else $USER)")]
    by: Option<String>,
    #[command(flatten)]
    place: Place,
}

fn parse_ecosystem(s: &str) -> Result<Ecosystem, String> {
    serde_json::from_value(json!(s)).map_err(|_| format!("unknown ecosystem `{s}`"))
}

#[derive(Parser, Debug)]
pub struct ListArgs {
    #[arg(long, value_enum, help = "only this state")]
    state: Option<State>,
    #[arg(long, help = "only this assignee")]
    assignee: Option<String>,
    #[arg(long, help = "only decisions that have expired")]
    expired: bool,
    #[arg(long, help = "print JSON instead of a table")]
    json: bool,
    #[command(flatten)]
    place: Place,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ExportFormat {
    Openvex,
}

#[derive(Parser, Debug)]
pub struct ExportArgs {
    #[arg(
        short,
        long,
        value_enum,
        default_value = "openvex",
        help = "output format"
    )]
    format: ExportFormat,
    #[arg(long, help = "OpenVEX author (default: settings.vex.author)")]
    author: Option<String>,
    #[command(flatten)]
    place: Place,
}

pub(crate) fn run_triage(command: TriageCommand) -> u8 {
    let result = match command {
        TriageCommand::Set(args) => set(args),
        TriageCommand::List(args) => list(&args),
        TriageCommand::Export(args) => export(&args),
    };
    match result {
        Ok(()) => 0,
        Err(e) => fail(&e),
    }
}

fn who(explicit: Option<String>) -> Result<String, String> {
    let git = || {
        let out = std::process::Command::new("git")
            .args(["config", "user.name"])
            .output()
            .ok()?;
        let name = String::from_utf8(out.stdout).ok()?;
        Some(name.trim().to_string()).filter(|n| !n.is_empty())
    };
    explicit
        .or_else(git)
        .or_else(|| std::env::var("USER").ok().filter(|u| !u.is_empty()))
        .ok_or_else(|| "cannot tell who is deciding: pass --by".to_string())
}

fn set(args: SetArgs) -> Result<(), String> {
    let dir = args.place.resolve()?;
    let path = dir.join(relative_path(&args.advisory, args.ecosystem, &args.package));
    let mut decision = if path.exists() {
        read_decision(&dir, &path)?
    } else {
        Decision {
            advisory: args.advisory,
            aliases: Vec::new(),
            ecosystem: args.ecosystem,
            package: args.package,
            state: args.state,
            assignee: None,
            expires: None,
            justification: None,
            reason: None,
            repos: Vec::new(),
            log: Vec::new(),
        }
    };
    decision.state = args.state;
    // A new state starts from what was said, so an old expiry or reason cannot outlive the
    // decision it was given for; the log keeps them.
    decision.expires = args.expires;
    decision.justification = args.justification;
    decision.reason.clone_from(&args.reason);
    decision.assignee = args.assignee.or(decision.assignee);
    if !args.repo.is_empty() {
        decision.repos = args.repo;
    }
    for alias in args.alias {
        if !decision.aliases.contains(&alias) {
            decision.aliases.push(alias);
        }
    }
    decision.log.push(LogEntry {
        at: format_time(now()),
        by: who(args.by)?,
        state: args.state,
        note: args.reason,
    });
    decision.check()?;
    let text = toml::to_string_pretty(&decision).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    println!("{}", path.display());
    Ok(())
}

fn list(args: &ListArgs) -> Result<(), String> {
    let dir = args.place.resolve()?;
    if !dir.exists() {
        return Err(format!("no triage directory at {}", dir.display()));
    }
    let today = now().date();
    let mut decisions = read_all(&dir)?;
    decisions.retain(|d| {
        args.state.is_none_or(|s| s == d.state)
            && args
                .assignee
                .as_ref()
                .is_none_or(|a| d.assignee.as_ref() == Some(a))
            && (!args.expired || d.expired(today))
    });
    if args.json {
        let text = serde_json::to_string_pretty(&decisions).map_err(|e| e.to_string())?;
        println!("{text}");
        return Ok(());
    }
    println!(
        "{:<15} {:<11} {:<24} {:<34} ASSIGNEE",
        "STATE", "EXPIRES", "ADVISORY", "PACKAGE"
    );
    for d in &decisions {
        let lapsed = if d.expired(today) { " (expired)" } else { "" };
        let line = format!(
            "{:<15} {:<11} {:<24} {:<34} {}{lapsed}",
            d.state.as_str(),
            d.expires.as_deref().unwrap_or("-"),
            d.advisory,
            format!("{}/{}", ecosystem_name(d.ecosystem), d.package),
            d.assignee.as_deref().unwrap_or("-"),
        );
        println!("{}", report::sanitize_text(&line));
    }
    Ok(())
}

/// The OpenVEX fields for a decision. An accepted risk is `affected`: the package is
/// vulnerable, and only a person chose to live with it. A lapsed decision says nothing any more.
fn vex_status(d: &Decision, today: Date) -> serde_json::Value {
    let reason = d.reason.clone().unwrap_or_default();
    if d.expired(today) {
        return json!({"status": "under_investigation"});
    }
    match d.state {
        State::NotAffected | State::FalsePositive => match &d.justification {
            Some(label) => json!({
                "status": "not_affected", "justification": label, "status_notes": reason
            }),
            None => json!({"status": "not_affected", "impact_statement": reason}),
        },
        State::AcceptedRisk => {
            let until = d
                .expires
                .as_ref()
                .map(|day| format!(" Accepted until {day}."))
                .unwrap_or_default();
            json!({"status": "affected", "action_statement": format!("{reason}{until}")})
        }
        State::Affected => json!({
            "status": "affected",
            "action_statement": if reason.is_empty() { "To be fixed.".to_string() } else { reason }
        }),
        State::InTriage => json!({"status": "under_investigation"}),
        State::Fixed => json!({"status": "fixed"}),
    }
}

/// The package's purl with no version, so a statement covers the versions the decision does.
fn product(d: &Decision) -> String {
    let with_version = report::purl(d.ecosystem, &d.package, "", &DepSource::CratesIo);
    with_version.trim_end_matches('@').to_string()
}

fn export(args: &ExportArgs) -> Result<(), String> {
    let ExportFormat::Openvex = args.format;
    let dir = args.place.resolve()?;
    if !dir.exists() {
        return Err(format!("no triage directory at {}", dir.display()));
    }
    let author = match &args.author {
        Some(author) => Some(author.clone()),
        None => args.place.config()?.and_then(|c| c.vex.author),
    };
    let author =
        author.ok_or("OpenVEX needs an author: pass --author or set settings.vex.author")?;
    let today = now().date();
    let decisions = read_all(&dir)?;
    let mut statements = Vec::new();
    for d in &decisions {
        let at = d.log.last().map(|entry| entry.at.clone());
        for id in std::iter::once(&d.advisory).chain(&d.aliases) {
            let mut statement = json!({
                "vulnerability": {"name": id},
                "products": [{"@id": product(d)}],
            });
            if let (Some(fields), Some(out)) = (
                vex_status(d, today).as_object().cloned(),
                statement.as_object_mut(),
            ) {
                out.extend(fields);
                if let Some(at) = &at {
                    out.insert("timestamp".to_string(), json!(at));
                }
            }
            statements.push(statement);
        }
    }
    let body = serde_json::to_string(&statements).map_err(|e| e.to_string())?;
    let hash = Sha256::digest(body.as_bytes());
    let id: String = hash.iter().take(16).map(|b| format!("{b:02x}")).collect();
    let timestamp = decisions
        .iter()
        .flat_map(|d| d.log.last())
        .map(|entry| entry.at.clone())
        .max()
        .unwrap_or_else(|| format_time(now()));
    let doc = json!({
        "@context": report::OPENVEX_CONTEXT,
        "@id": format!("https://fleetreach.dev/vex/triage/{id}"),
        "author": author,
        "timestamp": timestamp,
        "version": 1,
        "statements": statements,
    });
    let text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    println!("{text}");
    Ok(())
}

/// [`Triage::load`] for `scan`: what cannot be read exits 2, as an unreadable repo does.
pub(crate) fn load_or_fail(config: &Config, dir: Option<&Path>) -> Result<Triage, u8> {
    Triage::load(config, dir).map_err(|e| fail(&e))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn decision(state: State, expires: Option<&str>) -> Decision {
        Decision {
            advisory: "GHSA-1".to_string(),
            aliases: vec!["CVE-1".to_string()],
            ecosystem: Ecosystem::Npm,
            package: "@babel/core".to_string(),
            state,
            assignee: None,
            expires: expires.map(str::to_string),
            justification: None,
            reason: Some("because".to_string()),
            repos: Vec::new(),
            log: Vec::new(),
        }
    }

    #[test]
    fn a_default_directory_may_hold_files_that_are_not_ours() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rota.toml"), "[[people]]\nname = \"a\"\n").unwrap();
        assert!(read_default(dir.path()).unwrap().is_empty());
        assert!(read_all(dir.path()).is_err());
        // A decision with a mistake in it is not somebody else's file.
        std::fs::write(dir.path().join("d.toml"), "advisory = \"X\"\n").unwrap();
        assert!(read_default(dir.path()).is_err());
    }

    #[test]
    fn paths_stay_one_file_inside_the_directory() {
        let path = relative_path("../x", Ecosystem::Npm, "@babel/core");
        assert_eq!(path, Path::new("%2E.%2Fx/npm-%40babel%2Fcore.toml"));
        assert_eq!(segment(".."), "%2E.");
    }

    #[test]
    fn only_the_three_states_set_aside_and_only_until_they_expire() {
        let today = parse_day("2026-11-04").unwrap();
        for (state, count) in [
            (State::AcceptedRisk, 1),
            (State::FalsePositive, 1),
            (State::NotAffected, 1),
            (State::Affected, 0),
            (State::InTriage, 0),
            (State::Fixed, 0),
        ] {
            let triage = Triage::of(&[decision(state, None)], &[], today);
            assert_eq!(triage.suppressions.len(), count, "{state:?}");
        }
        // The last day still holds.
        let holds = Triage::of(
            &[decision(State::AcceptedRisk, Some("2026-11-04"))],
            &[],
            today,
        );
        assert_eq!((holds.suppressions.len(), holds.expired.len()), (1, 0));
        let lapsed = Triage::of(
            &[decision(State::AcceptedRisk, Some("2026-11-03"))],
            &[],
            today,
        );
        assert_eq!((lapsed.suppressions.len(), lapsed.expired.len()), (0, 1));
    }

    #[test]
    fn setting_a_finding_aside_needs_a_reason_and_real_values() {
        let mut d = decision(State::NotAffected, None);
        d.reason = None;
        assert!(d.check().unwrap_err().contains("reason"));
        assert!(decision(State::Fixed, Some("soon")).check().is_err());
        let mut d = decision(State::NotAffected, None);
        d.justification = Some("trust me".to_string());
        assert!(d.check().is_err());
    }

    #[test]
    fn accepted_risk_is_never_not_affected() {
        let today = parse_day("2026-11-04").unwrap();
        let status = vex_status(&decision(State::AcceptedRisk, Some("2027-01-01")), today);
        assert_eq!(status["status"], "affected");
        let lapsed = vex_status(&decision(State::NotAffected, Some("2026-01-01")), today);
        assert_eq!(lapsed["status"], "under_investigation");
    }
}
