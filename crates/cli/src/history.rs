//! Scan history as plain files (spec 09): one gzipped snapshot per run, and an index of every
//! finding's first and last sighting, so trends, age, SLA breaches and time to fix need no
//! server. A git repo of the history directory is then the database and the audit trail.
//!
//! Fail-closed rules: a run that exited `2` never marks anything fixed, and neither does a
//! run in which the finding's repo errored or was read with less than full coverage. Fixed
//! means a later trustworthy scan of that repo no longer has the finding. An ignored finding
//! is recorded as ignored, not as fixed. The snapshots are the source of truth: an index that
//! is missing, unreadable or out of step with them is rebuilt, keeping the first sightings of
//! findings whose snapshots retention already removed.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fleetreach_core::ssvc::Outcome;
use fleetreach_core::{Ecosystem, FleetReport, Occurrence, ScanStatus, Severity};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::assemble::SuppressedOccurrence;

const SNAPSHOT_SCHEMA: &str = "fleetreach-history/1";
const INDEX_SCHEMA: &str = "fleetreach-history-index/1";
const INDEX_FILE: &str = "index.json";

/// One run as stored: the full report, the occurrences ignores suppressed, and the exit code.
#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema: String,
    pub run: Run,
    #[serde(default)]
    pub suppressed: Vec<Key>,
    pub report: FleetReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    /// The file stem: `<UTC time>-<short hash>`.
    pub id: String,
    /// RFC 3339.
    pub at: String,
    pub exit_code: u8,
}

/// A finding's identity across runs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Key {
    pub advisory: String,
    #[serde(default, skip_serializing_if = "Ecosystem::is_cargo")]
    pub ecosystem: Ecosystem,
    pub repo: String,
    pub package: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Open,
    Ignored,
    Fixed,
}

/// Everything the index knows about one finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    #[serde(flatten)]
    pub key: Key,
    pub status: Status,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssvc: Option<Outcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_at: Option<String>,
    /// How often it came back after being fixed.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub reopened: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Index {
    pub schema: String,
    /// Run ids folded in, oldest first (ids of pruned snapshots stay listed).
    pub runs: Vec<String>,
    pub entries: Vec<Entry>,
}

/// The history directory loaded: every readable snapshot (oldest first), the index brought
/// up to date with them, and the snapshots that could not be read.
pub struct History {
    pub snapshots: Vec<Snapshot>,
    pub index: Index,
    pub unreadable: Vec<String>,
    /// Why the index was rebuilt, when it was.
    pub rebuilt: Option<String>,
}

/// The time to stamp a run or measure against: `SOURCE_DATE_EPOCH` when set (reproducible
/// runs and tests), otherwise now.
pub fn now() -> OffsetDateTime {
    std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .and_then(|secs| OffsetDateTime::from_unix_timestamp(secs).ok())
        .unwrap_or_else(OffsetDateTime::now_utc)
}

pub fn format_time(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

pub fn parse_time(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}

/// The keys of every vulnerable in-repo occurrence of `report`.
fn present(report: &FleetReport) -> BTreeMap<Key, (Severity, Option<Outcome>)> {
    let mut ssvc: BTreeMap<(&str, &str, &str, String), Outcome> = BTreeMap::new();
    for d in report.ssvc.iter().flat_map(|s| &s.decisions) {
        let slot = ssvc
            .entry((
                d.advisory_id.as_str(),
                d.repo.0.as_str(),
                d.package.as_str(),
                d.installed.clone(),
            ))
            .or_insert(d.outcome);
        *slot = (*slot).max(d.outcome);
    }
    let mut out = BTreeMap::new();
    for v in &report.vulnerabilities {
        for occ in &v.occurrences {
            let Occurrence::InRepo {
                repo,
                package,
                installed,
                ..
            } = occ
            else {
                continue;
            };
            if !occ.is_vulnerable() {
                continue;
            }
            let version = installed.to_string();
            let outcome = ssvc
                .get(&(
                    v.advisory_id.as_str(),
                    repo.0.as_str(),
                    package.as_str(),
                    version.clone(),
                ))
                .copied();
            out.insert(
                Key {
                    advisory: v.advisory_id.clone(),
                    ecosystem: v.ecosystem,
                    repo: repo.0.clone(),
                    package: package.clone(),
                    version,
                },
                (v.severity, outcome),
            );
        }
    }
    out
}

/// The keys of the occurrences ignores suppressed in a run.
pub fn suppressed_keys(report: &FleetReport, suppressed: &[SuppressedOccurrence]) -> Vec<Key> {
    let ecosystem_of: BTreeMap<&str, Ecosystem> = report
        .vulnerabilities
        .iter()
        .map(|v| (v.advisory_id.as_str(), v.ecosystem))
        .collect();
    let mut keys: Vec<Key> = suppressed
        .iter()
        .filter_map(|s| match &s.occurrence {
            Occurrence::InRepo {
                repo,
                package,
                installed,
                ..
            } => Some(Key {
                advisory: s.advisory_id.clone(),
                ecosystem: ecosystem_of
                    .get(s.advisory_id.as_str())
                    .copied()
                    .unwrap_or_default(),
                repo: repo.0.clone(),
                package: package.clone(),
                version: installed.to_string(),
            }),
            Occurrence::Toolchain { .. } => None,
        })
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Repos a run can vouch for: scanned without error and read in full, in a run that did not
/// exit `2`.
fn trustworthy(snapshot: &Snapshot) -> BTreeSet<&str> {
    if snapshot.run.exit_code == 2 {
        return BTreeSet::new();
    }
    let partial: BTreeSet<&str> = snapshot
        .report
        .coverage
        .iter()
        .map(|g| g.repo.0.as_str())
        .collect();
    snapshot
        .report
        .outcomes
        .iter()
        .filter(|o| matches!(o.status, ScanStatus::Scanned { .. }))
        .map(|o| o.repo.0.as_str())
        .filter(|r| !partial.contains(r))
        .collect()
}

/// Fold one run into the index.
fn fold(index: &mut Index, snapshot: &Snapshot) {
    let at = &snapshot.run.at;
    let owners: BTreeMap<&str, &str> = snapshot
        .report
        .context
        .iter()
        .filter_map(|c| Some((c.repo.0.as_str(), c.owner.as_deref()?)))
        .collect();
    let mut by_key: BTreeMap<Key, Entry> = std::mem::take(&mut index.entries)
        .into_iter()
        .map(|e| (e.key.clone(), e))
        .collect();
    let seen = present(&snapshot.report);
    let ignored: BTreeSet<&Key> = snapshot.suppressed.iter().collect();
    let trusted = trustworthy(snapshot);

    let mut touch = |key: &Key, status: Status, severity: Option<Severity>, ssvc| {
        let owner = owners.get(key.repo.as_str()).map(|o| (*o).to_string());
        let entry = by_key.entry(key.clone()).or_insert_with(|| Entry {
            key: key.clone(),
            status,
            severity: severity.unwrap_or_default(),
            ssvc: None,
            owner: None,
            first_seen: at.clone(),
            last_seen: at.clone(),
            fixed_at: None,
            reopened: 0,
        });
        if entry.status == Status::Fixed {
            entry.reopened += 1;
            entry.fixed_at = None;
        }
        entry.status = status;
        entry.last_seen.clone_from(at);
        if let Some(severity) = severity {
            entry.severity = severity;
            entry.ssvc = ssvc;
        }
        if owner.is_some() {
            entry.owner = owner;
        }
    };
    for (key, (severity, ssvc)) in &seen {
        let status = if ignored.contains(key) {
            Status::Ignored
        } else {
            Status::Open
        };
        touch(key, status, Some(*severity), *ssvc);
    }
    for key in &ignored {
        if !seen.contains_key(*key) {
            touch(key, Status::Ignored, None, None);
        }
    }
    for entry in by_key.values_mut() {
        let gone = !seen.contains_key(&entry.key) && !ignored.contains(&entry.key);
        if gone && entry.status != Status::Fixed && trusted.contains(entry.key.repo.as_str()) {
            entry.status = Status::Fixed;
            entry.fixed_at = Some(at.clone());
        }
    }
    index.entries = by_key.into_values().collect();
    index.runs.push(snapshot.run.id.clone());
}

/// Rebuild the index from `snapshots`, keeping what `old` knew about findings whose
/// snapshots are gone (their first sighting, their fix).
fn rebuild(snapshots: &[Snapshot], old: Option<Index>) -> Index {
    let mut index = Index {
        schema: INDEX_SCHEMA.to_string(),
        ..Index::default()
    };
    for s in snapshots {
        fold(&mut index, s);
    }
    if let Some(old) = old {
        let mut by_key: BTreeMap<Key, Entry> = index
            .entries
            .into_iter()
            .map(|e| (e.key.clone(), e))
            .collect();
        for e in old.entries {
            match by_key.get_mut(&e.key) {
                Some(fresh) => {
                    if parse_time(&e.first_seen) < parse_time(&fresh.first_seen) {
                        fresh.first_seen = e.first_seen;
                    }
                    fresh.reopened = fresh.reopened.max(e.reopened);
                }
                None => {
                    by_key.insert(e.key.clone(), e);
                }
            }
        }
        index.entries = by_key.into_values().collect();
        let mut runs: Vec<String> = old.runs;
        for id in index.runs {
            if !runs.contains(&id) {
                runs.push(id);
            }
        }
        index.runs = runs;
    }
    index
}

fn read_snapshot(path: &Path) -> Result<Snapshot, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut text = String::new();
    flate2::read::GzDecoder::new(file)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    let snapshot: Snapshot = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    if snapshot.schema != SNAPSHOT_SCHEMA {
        return Err(format!("unknown schema `{}`", snapshot.schema));
    }
    Ok(snapshot)
}

/// Load `dir`: every snapshot, and the index caught up with them.
///
/// # Errors
///
/// When the directory cannot be listed.
pub fn load(dir: &Path) -> Result<History, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with(".json.gz"))
        .collect();
    paths.sort();
    let mut snapshots = Vec::new();
    let mut unreadable = Vec::new();
    for path in paths {
        match read_snapshot(&path) {
            Ok(s) => snapshots.push(s),
            Err(e) => unreadable.push(format!("{}: {e}", path.display())),
        }
    }
    snapshots.sort_by(|a, b| {
        (parse_time(&a.run.at), &a.run.id).cmp(&(parse_time(&b.run.at), &b.run.id))
    });

    let index_path = dir.join(INDEX_FILE);
    let old: Option<Index> = std::fs::read_to_string(&index_path)
        .ok()
        .and_then(|t| serde_json::from_str::<Index>(&t).ok())
        .filter(|i| i.schema == INDEX_SCHEMA);
    let (index, rebuilt) = match old {
        None if index_path.exists() => (
            rebuild(&snapshots, None),
            Some(format!("{} was unreadable", index_path.display())),
        ),
        None => (rebuild(&snapshots, None), None),
        Some(mut index) => {
            let known: BTreeSet<&str> = index.runs.iter().map(String::as_str).collect();
            // The newest run the index covers that is still on disk: anything new must come
            // after it, or the order is off and only a rebuild is right.
            let last_known = snapshots
                .iter()
                .rposition(|s| known.contains(s.run.id.as_str()));
            let first_new = snapshots
                .iter()
                .position(|s| !known.contains(s.run.id.as_str()));
            match (first_new, last_known) {
                (None, _) => (index, None),
                (Some(new), last) if last.is_none_or(|l| new > l) => {
                    for s in &snapshots[new..] {
                        fold(&mut index, s);
                    }
                    (index, None)
                }
                _ => (
                    rebuild(&snapshots, Some(index)),
                    Some("a snapshot older than the index's newest run appeared".to_string()),
                ),
            }
        }
    };
    Ok(History {
        snapshots,
        index,
        unreadable,
        rebuilt,
    })
}

/// Record a run: write its snapshot, bring the index up to date, and drop snapshots older
/// than `keep` seconds (the index keeps their findings). The newest snapshot is never
/// dropped. The run's path, and any problem worth a note.
///
/// # Errors
///
/// When the snapshot or index cannot be written.
pub fn record(
    dir: &Path,
    report: &FleetReport,
    suppressed: Vec<Key>,
    exit_code: u8,
    keep: Option<i64>,
) -> Result<(PathBuf, Vec<String>), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let at = now();
    let body = serde_json::to_vec(report).map_err(|e| e.to_string())?;
    let hash: String = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&body)[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    let stamp = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    );
    let id = format!("{stamp}-{hash}");
    let snapshot = Snapshot {
        schema: SNAPSHOT_SCHEMA.to_string(),
        run: Run {
            id: id.clone(),
            at: format_time(at),
            exit_code,
        },
        suppressed,
        report: report.clone(),
    };
    let path = dir.join(format!("{id}.json.gz"));
    let json = serde_json::to_vec(&snapshot).map_err(|e| e.to_string())?;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&json).map_err(|e| e.to_string())?;
    let bytes = gz.finish().map_err(|e| e.to_string())?;
    write_atomic(&path, &bytes)?;

    let history = load(dir)?;
    let mut notes: Vec<String> = history
        .unreadable
        .iter()
        .map(|u| format!("unreadable snapshot skipped: {u}"))
        .collect();
    if let Some(why) = &history.rebuilt {
        notes.push(format!("history index rebuilt: {why}"));
    }
    let index_json = serde_json::to_vec_pretty(&history.index).map_err(|e| e.to_string())?;
    write_atomic(&dir.join(INDEX_FILE), &index_json)?;

    if let Some(keep) = keep {
        let cutoff = at - time::Duration::seconds(keep);
        let newest = history.snapshots.last().map(|s| s.run.id.clone());
        for s in &history.snapshots {
            let old = parse_time(&s.run.at).is_some_and(|t| t < cutoff);
            if old && Some(&s.run.id) != newest.as_ref() {
                let file = dir.join(format!("{}.json.gz", s.run.id));
                if let Err(e) = std::fs::remove_file(&file) {
                    notes.push(format!("could not prune {}: {e}", file.display()));
                }
            }
        }
    }
    Ok((path, notes))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

// ---- queries ----

/// What `trend` and `mttr` group by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum GroupBy {
    Severity,
    Ssvc,
    Ecosystem,
    Owner,
}

impl GroupBy {
    fn of(
        self,
        severity: Severity,
        ssvc: Option<Outcome>,
        ecosystem: Ecosystem,
        owner: Option<&str>,
    ) -> String {
        match self {
            GroupBy::Severity => label(&severity),
            GroupBy::Ssvc => ssvc.map_or("(none)".to_string(), |o| o.label().to_string()),
            GroupBy::Ecosystem => label(&ecosystem),
            GroupBy::Owner => owner.unwrap_or("(no owner)").to_string(),
        }
    }
}

fn label<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// One run's open findings, grouped.
#[derive(Debug, Serialize)]
pub struct TrendPoint {
    pub run: String,
    pub at: String,
    /// The run exited `2`: some of the fleet was not read, so its counts are a floor.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub gap: bool,
    pub open: usize,
    pub groups: BTreeMap<String, usize>,
}

pub fn trend(history: &History, by: GroupBy, since: Option<OffsetDateTime>) -> Vec<TrendPoint> {
    history
        .snapshots
        .iter()
        .filter(|s| since.is_none_or(|t| parse_time(&s.run.at).is_some_and(|at| at >= t)))
        .map(|s| {
            let owners: BTreeMap<&str, &str> = s
                .report
                .context
                .iter()
                .filter_map(|c| Some((c.repo.0.as_str(), c.owner.as_deref()?)))
                .collect();
            let ignored: BTreeSet<&Key> = s.suppressed.iter().collect();
            let mut groups: BTreeMap<String, usize> = BTreeMap::new();
            let mut open = 0;
            for (key, (severity, ssvc)) in present(&s.report) {
                if ignored.contains(&key) {
                    continue;
                }
                open += 1;
                let owner = owners.get(key.repo.as_str()).copied();
                *groups
                    .entry(by.of(severity, ssvc, key.ecosystem, owner))
                    .or_default() += 1;
            }
            TrendPoint {
                run: s.run.id.clone(),
                at: s.run.at.clone(),
                gap: s.run.exit_code == 2,
                open,
                groups,
            }
        })
        .collect()
}

/// An open finding and how long it has been open.
#[derive(Debug, Serialize)]
pub struct Aged<'a> {
    #[serde(flatten)]
    pub entry: &'a Entry,
    pub age_days: f64,
}

fn days(seconds: i64) -> f64 {
    (seconds as f64 / 86_400.0 * 10.0).round() / 10.0
}

pub fn age(history: &History, at: OffsetDateTime, min_age: i64) -> Vec<Aged<'_>> {
    let mut out: Vec<Aged<'_>> = history
        .index
        .entries
        .iter()
        .filter(|e| e.status == Status::Open)
        .filter_map(|e| {
            let seconds = (at - parse_time(&e.first_seen)?).whole_seconds();
            (seconds >= min_age).then(|| Aged {
                entry: e,
                age_days: days(seconds),
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.age_days
            .total_cmp(&a.age_days)
            .then_with(|| a.entry.key.cmp(&b.entry.key))
    });
    out
}

/// `[settings.sla]`: how long a finding may stay open, by SSVC outcome or severity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlaPolicy {
    pub by_outcome: BTreeMap<Outcome, i64>,
    pub by_severity: BTreeMap<Severity, i64>,
}

impl SlaPolicy {
    pub fn is_empty(&self) -> bool {
        self.by_outcome.is_empty() && self.by_severity.is_empty()
    }

    /// The deadline for a finding, in seconds from its first sighting: its SSVC outcome's
    /// when the policy has one, else its severity's. An `unknown` severity without its own
    /// entry takes the shortest severity deadline, so not knowing never buys time.
    pub fn deadline(&self, severity: Severity, ssvc: Option<Outcome>) -> Option<i64> {
        if let Some(d) = ssvc.and_then(|o| self.by_outcome.get(&o)) {
            return Some(*d);
        }
        match self.by_severity.get(&severity) {
            Some(d) => Some(*d),
            None if severity == Severity::Unknown => self.by_severity.values().min().copied(),
            None => None,
        }
    }
}

/// A finding past its deadline.
#[derive(Debug, Serialize)]
pub struct Breach<'a> {
    #[serde(flatten)]
    pub entry: &'a Entry,
    pub due: String,
    pub overdue_days: f64,
}

pub fn sla<'a>(history: &'a History, policy: &SlaPolicy, at: OffsetDateTime) -> Vec<Breach<'a>> {
    let mut out: Vec<Breach<'a>> = history
        .index
        .entries
        .iter()
        .filter(|e| e.status == Status::Open)
        .filter_map(|e| {
            let deadline = policy.deadline(e.severity, e.ssvc)?;
            let due = parse_time(&e.first_seen)? + time::Duration::seconds(deadline);
            let overdue = (at - due).whole_seconds();
            (overdue > 0).then(|| Breach {
                entry: e,
                due: format_time(due),
                overdue_days: days(overdue),
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.overdue_days
            .total_cmp(&a.overdue_days)
            .then_with(|| a.entry.key.cmp(&b.entry.key))
    });
    out
}

/// Time to fix for one group.
#[derive(Debug, Serialize)]
pub struct Mttr {
    pub group: String,
    pub fixed: usize,
    pub mean_days: f64,
    pub median_days: f64,
    /// Still open in this group, for context.
    pub open: usize,
}

pub fn mttr(history: &History, by: GroupBy) -> Vec<Mttr> {
    let mut fixed: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    let mut open: BTreeMap<String, usize> = BTreeMap::new();
    for e in &history.index.entries {
        let group = by.of(e.severity, e.ssvc, e.key.ecosystem, e.owner.as_deref());
        match (e.status, &e.fixed_at) {
            (Status::Fixed, Some(fixed_at)) => {
                if let (Some(a), Some(b)) = (parse_time(&e.first_seen), parse_time(fixed_at)) {
                    fixed
                        .entry(group)
                        .or_default()
                        .push((b - a).whole_seconds());
                }
            }
            (Status::Open, _) => *open.entry(group).or_default() += 1,
            _ => {}
        }
    }
    let groups: BTreeSet<String> = fixed.keys().chain(open.keys()).cloned().collect();
    groups
        .into_iter()
        .map(|group| {
            let mut times = fixed.get(&group).cloned().unwrap_or_default();
            times.sort_unstable();
            let n = times.len();
            let mean = if n == 0 {
                0.0
            } else {
                days(times.iter().sum::<i64>() / n as i64)
            };
            let median = match n {
                0 => 0.0,
                n if n % 2 == 1 => days(times[n / 2]),
                n => days((times[n / 2 - 1] + times[n / 2]) / 2),
            };
            Mttr {
                open: open.get(&group).copied().unwrap_or(0),
                group,
                fixed: n,
                mean_days: mean,
                median_days: median,
            }
        })
        .collect()
}

/// Where to read each advisory: its own `https://` URL from the newest snapshot that gives
/// one, otherwise its osv.dev page.
pub struct AdvisoryLinks(BTreeMap<String, String>);

impl AdvisoryLinks {
    pub fn new(history: &History) -> AdvisoryLinks {
        let mut urls = BTreeMap::new();
        for s in &history.snapshots {
            for v in &s.report.vulnerabilities {
                if let Some(url) = v.url.as_deref().filter(|u| u.starts_with("https://")) {
                    urls.insert(v.advisory_id.clone(), url.to_string());
                }
            }
        }
        AdvisoryLinks(urls)
    }

    pub fn url(&self, advisory: &str) -> String {
        self.0
            .get(advisory)
            .cloned()
            .unwrap_or_else(|| format!("https://osv.dev/vulnerability/{advisory}"))
    }
}

/// What the newest run changed against the one before it.
pub struct Changes<'a> {
    pub run: &'a Run,
    pub previous: Option<&'a Run>,
    /// Open now and not open before: first seen, back after a fix, or no longer ignored.
    pub new: Vec<&'a Entry>,
    /// Marked fixed by the newest run.
    pub fixed: Vec<&'a Entry>,
}

/// The newest run's changes, judged from the index as it stood before that run (rebuilt
/// from the earlier snapshots), so a gap run in between never makes old findings look new.
/// `None` without snapshots.
pub fn changes(history: &History) -> Option<Changes<'_>> {
    let (latest, earlier) = history.snapshots.split_last()?;
    let before = rebuild(earlier, None);
    let status_before: BTreeMap<&Key, Status> =
        before.entries.iter().map(|e| (&e.key, e.status)).collect();
    let mut new = Vec::new();
    let mut fixed = Vec::new();
    for e in &history.index.entries {
        match e.status {
            Status::Open => {
                let is_new = match status_before.get(&e.key) {
                    Some(Status::Open) => false,
                    Some(Status::Fixed | Status::Ignored) => true,
                    // Unknown to the retained snapshots: new only if this run first saw it
                    // (otherwise its earlier sightings were pruned).
                    None => e.first_seen == latest.run.at,
                };
                if is_new {
                    new.push(e);
                }
            }
            Status::Fixed if e.fixed_at.as_deref() == Some(latest.run.at.as_str()) => {
                fixed.push(e);
            }
            _ => {}
        }
    }
    Some(Changes {
        run: &latest.run,
        previous: earlier.last().map(|s| &s.run),
        new,
        fixed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisories_without_their_own_page_link_to_osv() {
        let h = History {
            snapshots: Vec::new(),
            index: Index::default(),
            unreadable: Vec::new(),
            rebuilt: None,
        };
        assert_eq!(
            AdvisoryLinks::new(&h).url("GHSA-xxxx-yyyy-zzzz"),
            "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz"
        );
    }

    #[test]
    fn deadlines_prefer_ssvc_and_unknown_never_buys_time() {
        let policy = SlaPolicy {
            by_outcome: [(Outcome::Immediate, 2)].into_iter().collect(),
            by_severity: [(Severity::Critical, 7), (Severity::High, 30)]
                .into_iter()
                .collect(),
        };
        assert_eq!(
            policy.deadline(Severity::High, Some(Outcome::Immediate)),
            Some(2)
        );
        assert_eq!(
            policy.deadline(Severity::High, Some(Outcome::Scheduled)),
            Some(30)
        );
        assert_eq!(policy.deadline(Severity::Unknown, None), Some(7));
        assert_eq!(policy.deadline(Severity::Low, None), None);
    }
}
