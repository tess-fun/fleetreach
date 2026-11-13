//! Affected ranges re-derived from fix commits (spec 16, row 12 phase 2): `db ranges`.
//!
//! About half of the OSV records name the commit that fixed them, as a `GIT` range or a
//! reference such as `https://github.com/<owner>/<repo>/commit/<sha>`. Which release tags
//! contain that commit says where the fix shipped, independently of the version an advisory
//! author typed. Each published `fixed` bound is checked against that:
//!
//! - **confirmed**: the bound's tag contains the fix, and no earlier tag on its line does;
//! - **fixed-earlier**: an earlier tag on the same line already contains every fix commit
//!   the bound's tag holds, so versions in between are reported vulnerable but carry the fix;
//! - **fixed-later**: the bound's tag lacks the fix, and a later tag that descends from it
//!   holds it: versions in between are reported safe but are not (a false clean);
//! - **fix-missing**: a range has no end, but a tag at or after its start holds the fix;
//! - **unverified**: the fix is on another line (a backport with a commit the record does
//!   not name), or the tags in between disagree.
//!
//! A correction is written only when every tag between the two bounds agrees with it, and
//! the line is the same history (`git merge-base --is-ancestor`). Corrections are OSV
//! records with the upstream id, so they drop into `[settings.advisories] dir` as overlays;
//! each is marked `unreviewed` with its evidence until a person checks it.
//!
//! Repositories are cloned bare with `--filter=tree:0` (commits and tags, no files), under
//! the private cache, and never checked out: nothing in them is run.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Display;
use std::io::{Cursor, Read as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use fleetreach_core::osv::{Advisory, ParsedBound};
use fleetreach_core::Ecosystem;
use rayon::prelude::*;
use serde::Serialize;

use crate::osvdb;
use crate::osvrecords::{self, Record};

/// A clone checked less than this long ago is not fetched again.
const REFRESH: Duration = Duration::from_secs(24 * 60 * 60);
/// Clones at once: each is one `git` process mostly waiting on the network.
const CLONES_AT_ONCE: usize = 8;

/// What the check found for one published bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Confirmed,
    FixedEarlier,
    FixedLater,
    FixMissing,
    Unverified,
    /// No tag maps to the published bound, so there is nothing to compare.
    NoTag,
    /// The named commit is not in the repository (a fork, a rewritten history).
    NoCommit,
    /// The repository could not be cloned or fetched.
    NoRepo,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Confirmed => "confirmed",
            Verdict::FixedEarlier => "fixed-earlier",
            Verdict::FixedLater => "fixed-later",
            Verdict::FixMissing => "fix-missing",
            Verdict::Unverified => "unverified",
            Verdict::NoTag => "no-tag",
            Verdict::NoCommit => "no-commit",
            Verdict::NoRepo => "no-repo",
        }
    }

    /// Whether the verdict changes the record.
    pub fn corrects(self) -> bool {
        matches!(
            self,
            Verdict::FixedEarlier | Verdict::FixedLater | Verdict::FixMissing
        )
    }
}

/// One published bound checked against the tags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub ecosystem: String,
    pub id: String,
    pub package: String,
    pub repo: String,
    pub commits: Vec<String>,
    pub verdict: Verdict,
    /// The bound as published (`None` for an open range).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    /// The bound the tags give, when it differs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived: Option<String>,
    /// The tags behind the verdict: the published bound's, then the derived bound's.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub detail: String,
}

/// What `db ranges` takes.
#[derive(Debug, Clone)]
pub struct Options {
    pub dir: PathBuf,
    pub ecosystems: Vec<Ecosystem>,
    /// Only these advisory ids (all when empty).
    pub ids: BTreeSet<String>,
    /// At most this many records per ecosystem, in id order (all when `None`).
    pub limit: Option<usize>,
    /// Use only clones already in the cache.
    pub offline: bool,
    /// Where clones live.
    pub cache: PathBuf,
}

impl Options {
    /// Hold corrections to the registries' publish times (network builds, not offline).
    fn release_times(&self) -> Box<ReleaseTimes<'static>> {
        match (self.offline, crate::health::registry_client()) {
            (false, Some(client)) => {
                Box::new(move |eco, package| registry_times(client.as_ref(), eco, package))
            }
            _ => Box::new(|_, _| Ok(None)),
        }
    }
}

/// A record's fix commits, grouped by repository (`host/owner/repo`).
fn fix_commits(record: &Record) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for affected in &record.affected {
        for range in affected
            .ranges
            .iter()
            .filter(|r| r.kind.as_deref() == Some("GIT"))
        {
            let Some(repo) = range.repo.as_deref().and_then(osvrecords::repo_key) else {
                continue;
            };
            for sha in range.events.iter().filter_map(|e| e.fixed.as_deref()) {
                if is_sha(sha) {
                    out.entry(repo.clone())
                        .or_default()
                        .insert(sha.to_ascii_lowercase());
                }
            }
        }
    }
    for url in record.references.iter().filter_map(|r| r.url.as_deref()) {
        if let Some((repo, sha)) = commit_url(url) {
            out.entry(repo).or_default().insert(sha);
        }
    }
    out
}

fn is_sha(s: &str) -> bool {
    (7..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `(repo, sha)` from a commit link on GitHub, GitLab or Bitbucket, including a commit
/// inside a pull request (`/pull/<n>/commits/<sha>`).
fn commit_url(url: &str) -> Option<(String, String)> {
    let repo = osvrecords::repo_key(url)?;
    let path = url.split(['?', '#']).next()?;
    let mut parts = path.rsplit('/');
    let last = parts.next()?;
    let last = last
        .strip_suffix(".patch")
        .or_else(|| last.strip_suffix(".diff"))
        .unwrap_or(last);
    let marker = parts.next()?;
    (matches!(marker, "commit" | "commits") && is_sha(last))
        .then(|| (repo, last.to_ascii_lowercase()))
}

/// A bare, tree-less clone of one repository.
struct Repo {
    /// The repository's own name, the last part of `host/owner/repo`.
    name: String,
    dir: PathBuf,
    tags: Vec<String>,
    contains: Mutex<HashMap<String, Option<BTreeSet<String>>>>,
}

fn git(dir: Option<&Path>, args: &[&str]) -> Result<std::process::Output, String> {
    let mut cmd = Command::new("git");
    if let Some(dir) = dir {
        cmd.arg("-C").arg(dir);
    }
    cmd.args([
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "protocol.fd.allow=never",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "credential.helper=",
    ])
    .args(args)
    .env("GIT_TERMINAL_PROMPT", "0")
    .env("GIT_ASKPASS", "true")
    .stdin(std::process::Stdio::null());
    cmd.output().map_err(|e| format!("running git: {e}"))
}

fn git_ok(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = git(Some(dir), args)?;
    if !out.status.success() {
        return Err(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

impl Repo {
    /// Clone or refresh `key` (`host/owner/repo`) under `cache`.
    fn open(cache: &Path, key: &str, offline: bool) -> Result<Repo, String> {
        // `repo_key` keeps only lowercase `host/owner/repo` of three known hosts.
        if key.split('/').count() != 3 || key.split('/').any(|p| p.is_empty() || p.starts_with('.'))
        {
            return Err(format!("{key}: not a repository key"));
        }
        let dir = cache.join(format!("{key}.git"));
        let stamp = dir.join("fleetreach-fetched");
        if dir.is_dir() {
            let fresh = std::fs::metadata(&stamp)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .is_some_and(|age| age < REFRESH);
            if !offline && !fresh {
                git_ok(
                    &dir,
                    &["fetch", "--quiet", "--prune", "--tags", "--force", "origin"],
                )?;
                std::fs::write(&stamp, b"").map_err(|e| e.to_string())?;
            }
        } else {
            if offline {
                return Err(format!("{key}: not cloned yet (offline)"));
            }
            let parent = dir.parent().ok_or("no parent")?;
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            let partial = parent.join(format!(
                ".{}.partial-{}",
                key.rsplit('/').next().unwrap_or("repo"),
                std::process::id()
            ));
            let url = format!("https://{key}.git");
            let partial_s = partial.to_string_lossy().into_owned();
            let out = git(
                None,
                &[
                    "clone",
                    "--quiet",
                    "--bare",
                    "--filter=tree:0",
                    "--",
                    &url,
                    &partial_s,
                ],
            )?;
            if !out.status.success() {
                let _ = std::fs::remove_dir_all(&partial);
                return Err(format!(
                    "cloning {url}: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            std::fs::rename(&partial, &dir).map_err(|e| e.to_string())?;
            std::fs::write(&stamp, b"").map_err(|e| e.to_string())?;
        }
        let tags = git_ok(&dir, &["tag", "--list"])?
            .lines()
            .map(str::to_string)
            .collect();
        Ok(Repo {
            name: key.rsplit('/').next().unwrap_or_default().to_string(),
            dir,
            tags,
            contains: Mutex::new(HashMap::new()),
        })
    }

    /// The tags that contain `sha`, or `None` when the commit is not in the repository.
    fn tags_containing(&self, sha: &str) -> Result<Option<BTreeSet<String>>, String> {
        if let Some(hit) = self.contains.lock().map_err(|e| e.to_string())?.get(sha) {
            return Ok(hit.clone());
        }
        let spec = format!("{sha}^{{commit}}");
        let resolved = git(
            Some(&self.dir),
            &["rev-parse", "--verify", "--quiet", &spec],
        )?;
        let result = if resolved.status.success() {
            let full = String::from_utf8_lossy(&resolved.stdout).trim().to_string();
            Some(
                git_ok(&self.dir, &["tag", "--contains", &full])?
                    .lines()
                    .map(str::to_string)
                    .collect(),
            )
        } else {
            None
        };
        self.contains
            .lock()
            .map_err(|e| e.to_string())?
            .insert(sha.to_string(), result.clone());
        Ok(result)
    }

    /// The committer time of `sha`, in Unix seconds.
    fn commit_time(&self, sha: &str) -> Option<i64> {
        let out = git(Some(&self.dir), &["log", "-1", "--format=%ct", sha]).ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().parse().ok())
            .flatten()
    }

    /// Whether `older` is an ancestor of `newer` (both tag names).
    fn is_ancestor(&self, older: &str, newer: &str) -> Result<bool, String> {
        let a = format!("refs/tags/{older}^{{commit}}");
        let b = format!("refs/tags/{newer}^{{commit}}");
        let out = git(Some(&self.dir), &["merge-base", "--is-ancestor", &a, &b])?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(format!(
                "git merge-base {older} {newer}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )),
        }
    }
}

/// The version a tag names for `package`, if it names one: `1.2.3`, `v1.2.3`, `name-1.2.3`,
/// `name@1.2.3`, `release-1.2.3`, ... In a repository whose tags name packages, only the
/// tags naming this one count, so another package's `1.2.3` is not read as this one's.
fn tag_versions<V: Ord + Clone>(
    tags: &[String],
    package: &str,
    repo_name: &str,
    shared_versions: bool,
    parse: impl Fn(&str) -> Option<V>,
) -> BTreeMap<V, String> {
    let lower = package.to_ascii_lowercase();
    let short = lower
        .rsplit(['/', ':'])
        .next()
        .unwrap_or(&lower)
        .to_string();
    let named = |n: &str| -> Vec<String> {
        [
            format!("{n}-v"),
            format!("{n}-"),
            format!("{n}@v"),
            format!("{n}@"),
            format!("{n}_"),
        ]
        .to_vec()
    };
    // A repository's own releases: bare, or after its name (`sshd-2.12.0`, `rel/nifi-1.23.1`,
    // `REL42.2.28`).
    let repo = repo_name.to_ascii_lowercase();
    let mut generic: Vec<String> = [
        "v", "release-", "release/", "rel-", "rel/", "version-", "rel", "r", "",
    ]
    .map(String::from)
    .to_vec();
    if !repo.is_empty() {
        for base in ["", "rel/", "release/", "release-"] {
            generic.extend([
                format!("{base}{repo}-v"),
                format!("{base}{repo}-"),
                format!("{base}{repo}_"),
            ]);
        }
    }
    let read = |tag: &str, prefixes: &[String]| -> Option<V> {
        let low = tag.to_ascii_lowercase();
        prefixes.iter().find_map(|p| {
            let rest = low.strip_prefix(p.as_str())?;
            let rest = &tag[tag.len() - rest.len()..];
            rest.bytes().next().filter(u8::is_ascii_digit)?;
            parse(rest)
        })
    };
    // The most specific spelling any tag uses wins: the full name, the last segment
    // (an npm scope or Maven group dropped), then bare versions.
    let mut tiers = vec![named(&lower)];
    if short != lower {
        tiers.push(named(&short));
    }
    // A Maven group's last segment (`org.apache.sshd` tags `sshd-2.12.0`).
    if let Some(group) = lower
        .split_once(':')
        .and_then(|(g, _)| g.rsplit('.').next())
    {
        if group != short {
            tiers.push(named(group));
        }
    }
    // Bare `v1.2.3` tags are the repository's releases: they are this package's versions only
    // when the repository is this package's. In a monorepo (Backstage) they are the product's.
    // Maven's multi-module repositories release every module at one version, so there the
    // repository's tags are the package's.
    if shared_versions || names_match(package, repo_name) {
        tiers.push(generic);
    }
    for prefixes in tiers {
        let mut out: BTreeMap<V, String> = BTreeMap::new();
        for tag in tags {
            if let Some(v) = read(tag, &prefixes) {
                // Two tags for one version (`1.2` and `v1.2`): keep the first listed.
                out.entry(v).or_insert_with(|| tag.clone());
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    BTreeMap::new()
}

/// Whether a repository is named for the package: `deepHas` for `deephas`, `vxe-table`,
/// `spring-framework` for `org.springframework:spring-core` (a Maven group's last segment).
fn names_match(package: &str, repo_name: &str) -> bool {
    let norm = |s: &str| -> String {
        s.chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_lowercase())
            .collect()
    };
    let repo = norm(repo_name);
    let lower = package.to_ascii_lowercase();
    let mut names = vec![lower
        .rsplit(['/', ':'])
        .next()
        .unwrap_or(&lower)
        .to_string()];
    if let Some((group, _)) = lower.split_once(':') {
        names.extend(group.rsplit('.').next().map(str::to_string));
    }
    names.iter().map(|n| norm(n)).any(|n| {
        n.len() >= 3 && repo.len() >= 3 && (n == repo || n.contains(&repo) || repo.contains(&n))
    })
}

/// A pre-release (letters in the version, or with `dash_is_pre` a `-` suffix, as SemVer
/// reads `2026.3.23-2`), which never moves a release bound.
fn is_prerelease(version: &str, dash_is_pre: bool) -> bool {
    version.bytes().any(|b| b.is_ascii_alphabetic()) || (dash_is_pre && version.contains('-'))
}

/// One stretch of a range: from `introduced` (`None` = 0) to `fixed`, or open.
struct Span<V> {
    introduced: Option<V>,
    fixed: Option<V>,
    /// A `last_affected` end: not checked (nothing says where the fix shipped).
    last_affected: bool,
}

fn spans<V: Clone>(adv: &Advisory<V>) -> Vec<Span<V>> {
    let mut out = Vec::new();
    for range in adv.ranges.iter().filter(|r| r.matchable) {
        // `Some(None)`: open from 0; `None`: no open stretch. An unparseable start skips
        // its stretch: nothing about it can be checked.
        let mut open: Option<Option<V>> = None;
        let mut skip = false;
        for event in &range.events {
            match &event.introduced {
                Some(ParsedBound::Version(v)) => {
                    open = Some(Some(v.clone()));
                    skip = false;
                }
                Some(ParsedBound::Unparseable) => {
                    open = None;
                    skip = true;
                }
                None => {}
            }
            if event.fixed.is_some() || event.last_affected.is_some() {
                // A bound with no `introduced` before it is affected from 0.
                let introduced = open.take().unwrap_or(None);
                if !std::mem::take(&mut skip) {
                    out.push(Span {
                        introduced,
                        fixed: event.fixed.clone(),
                        last_affected: event.last_affected.is_some(),
                    });
                }
            }
        }
        if let (Some(introduced), false) = (open, skip) {
            out.push(Span {
                introduced,
                fixed: None,
                last_affected: false,
            });
        }
    }
    out
}

/// One verdict: the published bound, the derived one, the tags behind it and why.
type Found = (Verdict, Option<String>, Option<String>, Vec<String>, String);

/// Check one advisory's spans for `package` against the repository's tags.
fn check_spans<V: Ord + Clone + Display>(
    adv: &Advisory<V>,
    package: &str,
    repo: &Repo,
    commits: &BTreeSet<String>,
    parse: impl Fn(&str) -> Option<V>,
    dash_is_pre: bool,
) -> Result<Vec<Found>, String> {
    let mut containing: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for sha in commits {
        if let Some(tags) = repo.tags_containing(sha)? {
            containing.insert(sha, tags);
        }
    }
    if containing.is_empty() {
        return Ok(vec![(
            Verdict::NoCommit,
            None,
            None,
            Vec::new(),
            format!("none of {} commit(s) is in the repository", commits.len()),
        )]);
    }
    // Maven writes plain releases with a `-` (`2.9.10-1`) and releases modules together.
    let shared_versions = !dash_is_pre;
    let versions = tag_versions(&repo.tags, package, &repo.name, shared_versions, &parse);
    let tag_of = |v: &V| versions.get(v).cloned();
    let has_any = |tag: &str| containing.values().any(|t| t.contains(tag));
    let mut out = Vec::new();
    for span in spans(adv) {
        if span.last_affected {
            continue;
        }
        let releases = |lo: Option<&V>, hi: Option<&V>| -> Vec<(&V, &String)> {
            versions
                .iter()
                .filter(|(v, _)| lo.is_none_or(|lo| *v >= lo) && hi.is_none_or(|hi| *v < hi))
                .filter(|(v, _)| !is_prerelease(&v.to_string(), dash_is_pre))
                .collect()
        };
        // A commit already in the release where the range starts is not this range's fix
        // (a record linking the fix of an earlier, similar advisory).
        if let Some(intro_tag) = span.introduced.as_ref().and_then(tag_of) {
            if has_any(&intro_tag) {
                out.push((
                    Verdict::Unverified,
                    span.fixed.as_ref().map(ToString::to_string),
                    None,
                    vec![intro_tag.clone()],
                    format!(
                        "{intro_tag}, where the range starts, already holds the linked commit: \
                         it is not this range's fix"
                    ),
                ));
                continue;
            }
        }
        match &span.fixed {
            Some(fixed) => {
                let published = fixed.to_string();
                let Some(fixed_tag) = tag_of(fixed) else {
                    out.push((
                        Verdict::NoTag,
                        Some(published),
                        None,
                        Vec::new(),
                        format!("no tag names {fixed}"),
                    ));
                    continue;
                };
                // The commits this bound's tag holds: on a line with a backport only some.
                let held: Vec<&BTreeSet<String>> = containing
                    .values()
                    .filter(|t| t.contains(&fixed_tag))
                    .collect();
                if !held.is_empty() {
                    // The earliest release before the bound, on its line, that holds them all.
                    let mut earliest: Option<(&V, &String)> = None;
                    for (v, tag) in releases(span.introduced.as_ref(), Some(fixed)) {
                        if held.iter().all(|t| t.contains(tag))
                            && repo.is_ancestor(tag, &fixed_tag)?
                        {
                            earliest = Some((v, tag));
                            break;
                        }
                    }
                    match earliest {
                        None => out.push((
                            Verdict::Confirmed,
                            Some(published),
                            None,
                            vec![fixed_tag.clone()],
                            format!("{fixed_tag} is the first tag with the fix"),
                        )),
                        Some((v, tag)) => {
                            // Every release from there up to the bound must hold the fix.
                            let between = releases(Some(v), Some(fixed));
                            if between
                                .iter()
                                .all(|(_, t)| held.iter().all(|h| h.contains(*t)))
                            {
                                out.push((
                                    Verdict::FixedEarlier,
                                    Some(published),
                                    Some(v.to_string()),
                                    vec![fixed_tag.clone(), tag.clone()],
                                    format!(
                                        "{tag} already holds the fix: {} release(s) before {fixed} are not vulnerable",
                                        between.len()
                                    ),
                                ));
                            } else {
                                out.push((
                                    Verdict::Unverified,
                                    Some(published),
                                    Some(v.to_string()),
                                    vec![fixed_tag.clone(), tag.clone()],
                                    format!("{tag} holds the fix but a release between it and {fixed} does not"),
                                ));
                            }
                        }
                    }
                } else {
                    // The bound's tag lacks the fix: is there a later release on its line?
                    let mut later: Option<(&V, &String)> = None;
                    for (v, tag) in releases(Some(fixed), None) {
                        if v > fixed && has_any(tag) && repo.is_ancestor(&fixed_tag, tag)? {
                            later = Some((v, tag));
                            break;
                        }
                    }
                    match later {
                        Some((v, tag)) => {
                            let between = releases(Some(fixed), Some(v));
                            if between.iter().all(|(_, t)| !has_any(t)) {
                                out.push((
                                    Verdict::FixedLater,
                                    Some(published),
                                    Some(v.to_string()),
                                    vec![fixed_tag.clone(), tag.clone()],
                                    format!(
                                        "{fixed_tag} lacks the fix, {tag} is the first after it with it: {} release(s) are reported safe but vulnerable",
                                        between.len()
                                    ),
                                ));
                            } else {
                                out.push((
                                    Verdict::Unverified,
                                    Some(published),
                                    Some(v.to_string()),
                                    vec![fixed_tag.clone(), tag.clone()],
                                    "releases between the bounds disagree".to_string(),
                                ));
                            }
                        }
                        None => out.push((
                            Verdict::Unverified,
                            Some(published),
                            None,
                            vec![fixed_tag.clone()],
                            format!("{fixed_tag} lacks the named commit(s): a backport, or a fix the record does not link"),
                        )),
                    }
                }
            }
            None => {
                // An open range: the first release at or after its start that holds every
                // commit, provided every later release does too.
                let candidates = releases(span.introduced.as_ref(), None);
                let all = |tag: &str| containing.values().all(|t| t.contains(tag));
                let first = candidates.iter().position(|(_, t)| all(t));
                match first {
                    Some(i) if candidates[i..].iter().all(|(_, t)| all(t)) => {
                        let (v, tag) = candidates[i];
                        out.push((
                            Verdict::FixMissing,
                            None,
                            Some(v.to_string()),
                            vec![tag.clone()],
                            format!("the range has no fix, but {tag} and every release after it hold the fix"),
                        ));
                    }
                    Some(i) => {
                        let (v, tag) = candidates[i];
                        out.push((
                            Verdict::Unverified,
                            None,
                            Some(v.to_string()),
                            vec![tag.clone()],
                            format!("{tag} holds the fix but a later release does not"),
                        ));
                    }
                    None => {}
                }
            }
        }
    }
    Ok(out)
}

/// The records worth checking in one export: those that name fix commits, keyed by id.
fn candidates(
    opts: &Options,
    export: &str,
) -> Result<BTreeMap<String, BTreeMap<String, BTreeSet<String>>>, String> {
    let records = osvrecords::load_dir(&opts.dir, Some(&[export]))?;
    let mut out = BTreeMap::new();
    for (id, (_, record)) in records {
        if record.withdrawn.is_some() || (!opts.ids.is_empty() && !opts.ids.contains(&id)) {
            continue;
        }
        let commits = fix_commits(&record);
        if !commits.is_empty() {
            out.insert(id, commits);
        }
        if opts.limit.is_some_and(|n| out.len() >= n) {
            break;
        }
    }
    Ok(out)
}

/// When each version of a package was published, from its registry: `None` for an ecosystem
/// whose registry gives no times here (or offline).
pub(crate) type ReleaseTimes<'a> =
    dyn Fn(Ecosystem, &str) -> Result<Option<Vec<(String, i64)>>, String> + Sync + 'a;

fn timestamp(raw: &str) -> Option<i64> {
    raw.parse::<jiff::Timestamp>().ok().map(|t| t.as_second())
}

/// Publish times from npm, PyPI, crates.io, RubyGems, Hex and Maven Central.
///
/// # Errors
///
/// When the registry answers with something unreadable.
pub(crate) fn registry_times(
    fetch: &dyn crate::health::Fetch,
    eco: Ecosystem,
    package: &str,
) -> Result<Option<Vec<(String, i64)>>, String> {
    let enc = |s: &str| -> String {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'~' | b'@') {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    };
    let url = match eco {
        Ecosystem::Npm => format!("https://registry.npmjs.org/{}", enc(package)),
        Ecosystem::Pypi => format!("https://pypi.org/pypi/{}/json", enc(package)),
        Ecosystem::Cargo => format!("https://crates.io/api/v1/crates/{}", enc(package)),
        Ecosystem::RubyGems => {
            format!("https://rubygems.org/api/v1/versions/{}.json", enc(package))
        }
        Ecosystem::Hex => format!("https://hex.pm/api/packages/{}", enc(package)),
        Ecosystem::Maven => {
            let Some((group, artifact)) = package.split_once(':') else {
                return Ok(None);
            };
            format!(
                "https://search.maven.org/solrsearch/select?q=g:{}+AND+a:{}&core=gav&rows=1000&wt=json",
                enc(group),
                enc(artifact)
            )
        }
        _ => return Ok(None),
    };
    let Some(body) = fetch.get(&url)? else {
        return Ok(Some(Vec::new()));
    };
    let v: serde_json::Value = serde_json::from_slice(&body).map_err(|e| format!("{url}: {e}"))?;
    let text =
        |x: &serde_json::Value, k: &str| x.get(k).and_then(|s| s.as_str()).map(str::to_string);
    let when = |x: &serde_json::Value, k: &str| text(x, k).and_then(|t| timestamp(&t));
    let list =
        |x: Option<&serde_json::Value>| x.and_then(|r| r.as_array()).cloned().unwrap_or_default();
    let mut out = Vec::new();
    match eco {
        Ecosystem::Npm => {
            for (ver, at) in v
                .get("time")
                .and_then(|t| t.as_object())
                .into_iter()
                .flatten()
            {
                if let Some(t) = at.as_str().and_then(timestamp) {
                    out.push((ver.clone(), t));
                }
            }
        }
        Ecosystem::Pypi => {
            for (ver, files) in v
                .get("releases")
                .and_then(|r| r.as_object())
                .into_iter()
                .flatten()
            {
                let first = list(Some(files))
                    .iter()
                    .filter_map(|f| when(f, "upload_time_iso_8601"))
                    .min();
                if let Some(t) = first {
                    out.push((ver.clone(), t));
                }
            }
        }
        Ecosystem::Cargo | Ecosystem::RubyGems | Ecosystem::Hex => {
            let (items, num, at) = match eco {
                Ecosystem::Cargo => (list(v.get("versions")), "num", "created_at"),
                Ecosystem::RubyGems => (list(Some(&v)), "number", "created_at"),
                _ => (list(v.get("releases")), "version", "inserted_at"),
            };
            for item in &items {
                if let (Some(n), Some(t)) = (text(item, num), when(item, at)) {
                    out.push((n, t));
                }
            }
        }
        Ecosystem::Maven => {
            for doc in list(v.pointer("/response/docs")) {
                let ms = doc.get("timestamp").and_then(serde_json::Value::as_i64);
                if let (Some(n), Some(ms)) = (text(&doc, "v"), ms) {
                    out.push((n, ms / 1000));
                }
            }
        }
        _ => {}
    }
    Ok(Some(out))
}

/// Hold a correction to the registry: a derived bound must be a published version; a fix
/// shipped earlier must have been published after the fix was committed; a fix shipped later
/// needs the published bound released before the commit existed (else a backport the record
/// does not link may fix it). `None` when the correction stands, else why not.
fn release_guard<V: Ord>(
    verdict: Verdict,
    published: Option<&V>,
    derived: Option<&V>,
    times: &BTreeMap<V, i64>,
    commit_times: &[i64],
) -> Option<String> {
    let derived = derived?;
    let Some(&shipped) = times.get(derived) else {
        return Some("the derived version was never published to the registry".to_string());
    };
    let (Some(&first), Some(&last)) = (commit_times.iter().min(), commit_times.iter().max()) else {
        return Some("the fix commit has no date".to_string());
    };
    match verdict {
        _ if shipped < last => Some(
            "the derived version was published before the fix was committed (a tag made later)"
                .to_string(),
        ),
        Verdict::FixedLater => match published.and_then(|p| times.get(p)) {
            Some(&released) if released < first => None,
            Some(_) => Some(
                "the published version came out after the fix commit: a backport the record \
                 does not link may fix it"
                    .to_string(),
            ),
            None => Some("the published version is not on the registry".to_string()),
        },
        _ => None,
    }
}

/// Run the checks for one feeder's parsed advisories.
fn check_ecosystem<'a, V: Ord + Clone + Display + Send + Sync + 'a>(
    export: &str,
    advisories: impl Iterator<Item = (&'a str, &'a Advisory<V>)>,
    wanted: &BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    repos: &BTreeMap<String, Result<Repo, String>>,
    parse: impl Fn(&str) -> Option<V> + Sync,
    eco: Ecosystem,
    release_times: &ReleaseTimes<'_>,
) -> Vec<Check> {
    // Maven writes plain releases with a `-` (`2.9.10-1`); elsewhere it marks a pre-release.
    let dash_is_pre = eco != Ecosystem::Maven;
    type Times<V> = Result<Option<BTreeMap<V, i64>>, String>;
    let cache: Mutex<HashMap<String, Times<V>>> = Mutex::new(HashMap::new());
    let times_for = |package: &str| -> Times<V> {
        if let Some(hit) = cache.lock().map_err(|e| e.to_string())?.get(package) {
            return hit.clone();
        }
        let got = release_times(eco, package).map(|list| {
            list.map(|list| {
                list.into_iter()
                    .filter_map(|(raw, t)| parse(&raw).map(|v| (v, t)))
                    .collect::<BTreeMap<V, i64>>()
            })
        });
        cache
            .lock()
            .map_err(|e| e.to_string())?
            .insert(package.to_string(), got.clone());
        got
    };
    let jobs: Vec<(&str, &Advisory<V>)> = advisories
        .filter(|(_, adv)| wanted.contains_key(&adv.id))
        .collect();
    jobs.par_iter()
        .flat_map_iter(|(package, adv)| {
            let mut out = Vec::new();
            let by_repo = &wanted[&adv.id];
            for (key, commits) in by_repo {
                let base = |verdict, published, derived, tags, detail| Check {
                    ecosystem: export.to_string(),
                    id: adv.id.clone(),
                    package: (*package).to_string(),
                    repo: key.clone(),
                    commits: commits.iter().cloned().collect(),
                    verdict,
                    published,
                    derived,
                    tags,
                    detail,
                };
                match repos.get(key) {
                    Some(Ok(repo)) => {
                        match check_spans(adv, package, repo, commits, &parse, dash_is_pre) {
                            Ok(found) => {
                                // A repository whose tags never name the package is someone
                                // else's (a dependency's fix linked from this record).
                                let all_untagged = found.iter().all(|f| f.0 == Verdict::NoTag);
                                if all_untagged && by_repo.len() > 1 {
                                    continue;
                                }
                                for (mut verdict, p, d, t, mut detail) in found {
                                    if verdict.corrects() {
                                        let dates: Vec<i64> = commits
                                            .iter()
                                            .filter_map(|c| repo.commit_time(c))
                                            .collect();
                                        match times_for(package) {
                                            Ok(Some(registry)) => {
                                                let pv = p.as_deref().and_then(&parse);
                                                let dv = d.as_deref().and_then(&parse);
                                                if let Some(why) = release_guard(
                                                    verdict,
                                                    pv.as_ref(),
                                                    dv.as_ref(),
                                                    &registry,
                                                    &dates,
                                                ) {
                                                    verdict = Verdict::Unverified;
                                                    detail = format!("{detail}; but {why}");
                                                }
                                            }
                                            Ok(None) => {
                                                detail.push_str(" (publish times not checked)")
                                            }
                                            Err(e) => {
                                                verdict = Verdict::Unverified;
                                                detail = format!(
                                                    "{detail}; publish times unreadable: {e}"
                                                );
                                            }
                                        }
                                    }
                                    out.push(base(verdict, p, d, t, detail));
                                }
                            }
                            Err(e) => out.push(base(Verdict::NoRepo, None, None, Vec::new(), e)),
                        }
                    }
                    Some(Err(e)) => {
                        out.push(base(Verdict::NoRepo, None, None, Vec::new(), e.clone()))
                    }
                    None => {}
                }
            }
            out
        })
        .collect()
}

/// Run `db ranges`: every check, in ecosystem, id and package order.
///
/// # Errors
///
/// When an export cannot be read.
pub fn run(opts: &Options) -> Result<Vec<Check>, String> {
    let mut all = Vec::new();
    std::fs::create_dir_all(&opts.cache).map_err(|e| format!("{}: {e}", opts.cache.display()))?;
    for &eco in &opts.ecosystems {
        let Some(export) = osvdb::osv_name(eco) else {
            continue;
        };
        let root = opts.dir.join(export).join("all.zip");
        let root = if root.is_file() {
            root
        } else {
            opts.dir.join(export)
        };
        if !root.exists() {
            return Err(format!("no {export} export in {}", opts.dir.display()));
        }
        let wanted = candidates(opts, export)?;
        let keys: BTreeSet<&String> = wanted.values().flat_map(|r| r.keys()).collect();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(CLONES_AT_ONCE)
            .build()
            .map_err(|e| e.to_string())?;
        let repos: BTreeMap<String, Result<Repo, String>> = pool.install(|| {
            keys.par_iter()
                .map(|k| ((*k).clone(), Repo::open(&opts.cache, k, opts.offline)))
                .collect()
        });
        let err = |e: &dyn Display| format!("{export} export: {e}");
        let release_times = opts.release_times();
        macro_rules! check {
            ($db:ty, $parse:expr) => {{
                let db = <$db>::load_with_overlay(&root, None).map_err(|e| err(&e))?;
                let found = pool.install(|| {
                    check_ecosystem(
                        export,
                        db.iter(),
                        &wanted,
                        &repos,
                        $parse,
                        eco,
                        release_times.as_ref(),
                    )
                });
                all.extend(found);
            }};
        }
        match eco {
            Ecosystem::Npm => check!(fleetreach_npm::NpmDb, fleetreach_npm::parse_npm_version),
            Ecosystem::Pypi => check!(fleetreach_pypi::PyPiDb, fleetreach_pypi::parse_pypi_version),
            Ecosystem::RubyGems => {
                check!(
                    fleetreach_rubygems::RubyGemsDb,
                    fleetreach_rubygems::parse_rubygems_version
                )
            }
            Ecosystem::Packagist => {
                check!(
                    fleetreach_packagist::PackagistDb,
                    fleetreach_packagist::parse_composer_version
                )
            }
            Ecosystem::NuGet => check!(
                fleetreach_nuget::NuGetDb,
                fleetreach_nuget::parse_nuget_version
            ),
            Ecosystem::Maven => check!(
                fleetreach_maven::MavenDb,
                fleetreach_maven::parse_maven_version
            ),
            Ecosystem::Hex => check!(fleetreach_hex::HexDb, fleetreach_hex::parse_hex_version),
            Ecosystem::Swift => check!(
                fleetreach_swift::SwiftDb,
                fleetreach_swift::parse_swift_version
            ),
            Ecosystem::Cargo => check!(fleetreach_scan::CratesDb, |s: &str| {
                fleetreach_core::semver::Version::parse(s).ok()
            }),
            other => {
                return Err(format!(
                    "{other:?}: fix-commit ranges are not checked for it"
                ))
            }
        }
    }
    all.sort_by(|a, b| {
        (&a.ecosystem, &a.id, &a.package, &a.published).cmp(&(
            &b.ecosystem,
            &b.id,
            &b.package,
            &b.published,
        ))
    });
    Ok(all)
}

/// Every record a correction changes, as OSV JSON: the upstream record with each corrected
/// `fixed` bound moved (or added to an open range), `modified` set to `now`, and the evidence
/// under `database_specific.fleetreach_correction`, marked `unreviewed`.
///
/// # Errors
///
/// When an upstream record cannot be read again.
pub fn corrections(
    dir: &Path,
    checks: &[Check],
    now: &str,
) -> Result<BTreeMap<String, serde_json::Value>, String> {
    let mut by_id: BTreeMap<(&str, &str), Vec<&Check>> = BTreeMap::new();
    for check in checks.iter().filter(|c| c.verdict.corrects()) {
        by_id
            .entry((&check.ecosystem, &check.id))
            .or_default()
            .push(check);
    }
    let mut out = BTreeMap::new();
    for ((export, id), fixes) in by_id {
        let mut record = raw_record(dir, export, id)?;
        let upstream_modified = record.get("modified").cloned();
        let mut applied = Vec::new();
        for fix in &fixes {
            if move_bound(
                &mut record,
                &fix.package,
                fix.published.as_deref(),
                fix.derived.as_deref(),
            ) {
                applied.push(serde_json::json!({
                    "package": fix.package,
                    "kind": fix.verdict.as_str(),
                    "from": fix.published,
                    "to": fix.derived,
                    "repo": fix.repo,
                    "commits": fix.commits,
                    "tags": fix.tags,
                    "detail": fix.detail,
                }));
            }
        }
        if applied.is_empty() {
            continue;
        }
        record["modified"] = serde_json::Value::String(now.to_string());
        let db = record
            .as_object_mut()
            .ok_or("not an object")?
            .entry("database_specific")
            .or_insert_with(|| serde_json::json!({}));
        if !db.is_object() {
            *db = serde_json::json!({});
        }
        db["fleetreach_correction"] = serde_json::json!({
            "status": "unreviewed",
            "method": "fix-commit tags",
            "upstream_modified": upstream_modified,
            "changes": applied,
        });
        out.insert(id.to_string(), record);
    }
    Ok(out)
}

/// Move the `fixed` bound `from` to `to` in the record's non-GIT ranges for `package` (or,
/// with no `from`, close the first open range with `to`). Whether anything moved.
fn move_bound(
    record: &mut serde_json::Value,
    package: &str,
    from: Option<&str>,
    to: Option<&str>,
) -> bool {
    let Some(to) = to else { return false };
    let Some(affected) = record.get_mut("affected").and_then(|a| a.as_array_mut()) else {
        return false;
    };
    let mut moved = false;
    for entry in affected {
        let name = entry
            .pointer("/package/name")
            .and_then(|n| n.as_str())
            .unwrap_or_default();
        if !same_package(name, package) {
            continue;
        }
        let Some(ranges) = entry.get_mut("ranges").and_then(|r| r.as_array_mut()) else {
            continue;
        };
        for range in ranges {
            if range.get("type").and_then(|t| t.as_str()) == Some("GIT") {
                continue;
            }
            let Some(events) = range.get_mut("events").and_then(|e| e.as_array_mut()) else {
                continue;
            };
            match from {
                Some(from) => {
                    for event in events.iter_mut() {
                        if event.get("fixed").and_then(|f| f.as_str()) == Some(from) {
                            event["fixed"] = serde_json::Value::String(to.to_string());
                            moved = true;
                        }
                    }
                }
                None => {
                    let open = events.last().is_some_and(|e| e.get("introduced").is_some());
                    if open && !moved {
                        events.push(serde_json::json!({ "fixed": to }));
                        moved = true;
                    }
                }
            }
        }
    }
    moved
}

/// Package names compare the way the feeders normalize them: case and, for PyPI, `-_.`.
fn same_package(raw: &str, normalized: &str) -> bool {
    let norm = |s: &str| -> String {
        s.to_ascii_lowercase()
            .chars()
            .map(|c| if matches!(c, '_' | '.') { '-' } else { c })
            .collect()
    };
    norm(raw) == norm(normalized)
}

/// One record as published, read again from the export.
fn raw_record(dir: &Path, export: &str, id: &str) -> Result<serde_json::Value, String> {
    let file = format!("{id}.json");
    let zip = dir.join(export).join("all.zip");
    let body = if zip.is_file() {
        let bytes = std::fs::read(&zip).map_err(|e| format!("reading {}: {e}", zip.display()))?;
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
            .map_err(|e| format!("{}: {e}", zip.display()))?;
        let mut entry = archive
            .by_name(&file)
            .map_err(|e| format!("{}: {file}: {e}", zip.display()))?;
        let mut body = String::new();
        entry.read_to_string(&mut body).map_err(|e| e.to_string())?;
        body
    } else {
        let path = dir.join(export).join(&file);
        std::fs::read_to_string(&path).map_err(|e| format!("reading {}: {e}", path.display()))?
    };
    serde_json::from_str(&body).map_err(|e| format!("{export}/{file}: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn commit_links_are_read_from_three_forges() {
        let cases = [
            (
                "https://github.com/Owner/Repo/commit/0123456789abcdef0123456789abcdef01234567",
                Some("github.com/owner/repo"),
            ),
            (
                "https://github.com/o/r/pull/12/commits/abcdef1234567",
                Some("github.com/o/r"),
            ),
            (
                "https://gitlab.com/o/r/-/commit/abcdef1234567.patch",
                Some("gitlab.com/o/r"),
            ),
            (
                "https://bitbucket.org/o/r/commits/abcdef1234567#diff",
                Some("bitbucket.org/o/r"),
            ),
            ("https://github.com/o/r/releases/tag/v1.2.3", None),
            ("https://github.com/o/r/commit/not-a-sha", None),
            ("https://example.com/o/r/commit/abcdef1234567", None),
        ];
        for (url, repo) in cases {
            assert_eq!(
                commit_url(url).map(|(r, _)| r),
                repo.map(str::to_string),
                "{url}"
            );
        }
    }

    #[test]
    fn corrections_must_agree_with_the_registry() {
        let times = BTreeMap::from([(1, 100), (2, 200), (3, 300)]);
        let guard = |verdict, published: Option<i32>, derived: Option<i32>, commits: &[i64]| {
            release_guard(
                verdict,
                published.as_ref(),
                derived.as_ref(),
                &times,
                commits,
            )
        };
        assert_eq!(guard(Verdict::FixedEarlier, Some(3), Some(2), &[150]), None);
        // deephas: the derived release predates the commit, so a tag was made later.
        assert!(guard(Verdict::FixedEarlier, Some(3), Some(2), &[250]).is_some());
        // 9router: a tag never published.
        assert!(guard(Verdict::FixedEarlier, Some(3), Some(9), &[50]).is_some());
        // node-red-dashboard: the published bound came out before the fix existed.
        assert_eq!(guard(Verdict::FixedLater, Some(1), Some(2), &[150]), None);
        // better-auth: the derived release is on the registry before the commit's date.
        assert!(guard(Verdict::FixedLater, Some(1), Some(2), &[250]).is_some());
        // tauri: it came out after, so a backport may have fixed it.
        assert!(guard(Verdict::FixedLater, Some(2), Some(3), &[150]).is_some());
        assert!(
            guard(Verdict::FixMissing, None, Some(2), &[]).is_some(),
            "no commit date"
        );
    }

    #[test]
    fn bare_tags_count_only_in_the_package_s_own_repository() {
        assert!(names_match("deephas", "deepHas"));
        assert!(names_match("vxe-table", "vxe-table"));
        assert!(names_match(
            "org.springframework:spring-core",
            "spring-framework"
        ));
        assert!(names_match("Django", "django"));
        // A monorepo's product releases are not each package's versions.
        assert!(!names_match("@backstage/backend-common", "backstage"));
        assert!(!names_match("@oneuptime/model", "oneuptime"));
        let parse = |s: &str| fleetreach_core::semver::Version::parse(s).ok();
        let tags: Vec<String> = ["v0.21.1", "v1.24.0"].map(String::from).to_vec();
        assert!(tag_versions(
            &tags,
            "@backstage/backend-common",
            "backstage",
            false,
            parse
        )
        .is_empty());
        assert!(is_prerelease("2026.3.23-2", true));
        // Maven modules tagged after their group or repository.
        let cases: [(&str, &str, &[&str], usize); 3] = [
            (
                "org.apache.sshd:sshd-common",
                "mina-sshd",
                &["sshd-2.12.0"],
                1,
            ),
            (
                "org.apache.nifi:nifi-dbcp-base",
                "nifi",
                &["rel/nifi-1.23.1", "x-1.0.0"],
                1,
            ),
            ("org.postgresql:postgresql", "pgjdbc", &["REL42.2.28"], 1),
        ];
        for (package, repo, tags, want) in cases {
            let tags: Vec<String> = tags.iter().map(|t| t.to_string()).collect();
            let got = tag_versions(&tags, package, repo, true, parse);
            assert_eq!(got.len(), want, "{package}: {got:?}");
        }
        assert!(!is_prerelease("2.9.10-1", false));
    }

    #[test]
    fn tags_name_versions_and_package_tags_win() {
        let parse = |s: &str| fleetreach_core::semver::Version::parse(s).ok();
        let plain: Vec<String> = ["v1.0.0", "1.1.0", "release-1.2.0", "nightly", "v1.3.0-rc.1"]
            .map(String::from)
            .to_vec();
        let got: Vec<String> = tag_versions(&plain, "pkg", "pkg", false, parse)
            .into_values()
            .collect();
        assert_eq!(got, ["v1.0.0", "1.1.0", "release-1.2.0", "v1.3.0-rc.1"]);
        // A monorepo: only this package's tags, not its sibling's.
        let mono: Vec<String> = [
            "core-1.0.0",
            "core-1.1.0",
            "util-2.0.0",
            "@scope/core@1.2.0",
        ]
        .map(String::from)
        .to_vec();
        let got: Vec<String> = tag_versions(&mono, "core", "mono", false, parse)
            .into_values()
            .collect();
        assert_eq!(got, ["core-1.0.0", "core-1.1.0"]);
        let got: Vec<String> = tag_versions(&mono, "@scope/core", "mono", false, parse)
            .into_values()
            .collect();
        assert_eq!(got, ["@scope/core@1.2.0"]);
        // Maven: the artifact id after the colon.
        let maven: Vec<String> = ["jackson-databind-2.9.10", "jackson-core-2.9.10"]
            .map(String::from)
            .to_vec();
        let got: Vec<String> = tag_versions(
            &maven,
            "com.fasterxml.jackson.core:jackson-databind",
            "jackson-databind",
            true,
            parse,
        )
        .into_values()
        .collect();
        assert_eq!(got, ["jackson-databind-2.9.10"]);
    }

    /// A real git repository with two lines:
    ///
    /// ```text
    /// 1.0.0 - 1.0.1 - [fix] - 1.0.2 - 1.1.0 - 1.2.0
    ///    \
    ///     0.9.x branch: 0.9.5 (no fix)
    /// ```
    fn fixture(root: &Path) -> (Repo, String) {
        let src = root.join("src");
        std::fs::create_dir_all(&src).unwrap();
        let run = |args: &[&str]| {
            let out = Command::new("git")
                .arg("-C")
                .arg(&src)
                .args(args)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@example.com")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@example.com")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        run(&["init", "-q", "-b", "main"]);
        let commit = |msg: &str| run(&["commit", "-q", "--allow-empty", "-m", msg]);
        commit("one");
        run(&["tag", "v1.0.0"]);
        commit("two");
        run(&["tag", "v1.0.1"]);
        commit("fix");
        let fix = run(&["rev-parse", "HEAD"]);
        commit("three");
        run(&["tag", "v1.0.2"]);
        commit("four");
        run(&["tag", "v1.1.0"]);
        commit("five");
        run(&["tag", "v1.2.0"]);
        run(&["checkout", "-q", "-b", "maint", "v1.0.0"]);
        commit("maint");
        run(&["tag", "v0.9.5"]);
        // Tests read the source repository directly; `Repo::open` clones only https.
        let tags = git_ok(&src, &["tag", "--list"])
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        (
            Repo {
                name: "pkg".into(),
                dir: src,
                tags,
                contains: Mutex::new(HashMap::new()),
            },
            fix,
        )
    }

    fn advisory(events: &[(&str, &str)]) -> Advisory<fleetreach_core::semver::Version> {
        use fleetreach_core::osv::{ParsedEvent, ParsedRange};
        let v = |s: &str| fleetreach_core::semver::Version::parse(s).unwrap();
        let events = events
            .iter()
            .map(|(kind, ver)| ParsedEvent {
                introduced: (*kind == "introduced").then(|| ParsedBound::Version(v(ver))),
                fixed: (*kind == "fixed").then(|| v(ver)),
                last_affected: None,
            })
            .collect();
        Advisory {
            id: "GHSA-test".into(),
            aliases: vec![],
            summary: None,
            severity: fleetreach_core::Severity::High,
            cvss_score: None,
            cvss_vector: None,
            ranges: vec![ParsedRange {
                matchable: true,
                events,
            }],
            versions: vec![],
        }
    }

    fn verdicts(
        adv: &Advisory<fleetreach_core::semver::Version>,
        repo: &Repo,
        fix: &str,
    ) -> Vec<(Verdict, Option<String>)> {
        let parse = |s: &str| fleetreach_core::semver::Version::parse(s).ok();
        let commits = BTreeSet::from([fix.to_string()]);
        check_spans(adv, "pkg", repo, &commits, parse, true)
            .unwrap()
            .into_iter()
            .map(|(v, _, d, _, _)| (v, d))
            .collect()
    }

    #[test]
    fn bounds_are_checked_against_the_tags_that_hold_the_fix() {
        let tmp = tempfile::tempdir().unwrap();
        let (repo, fix) = fixture(tmp.path());
        let check = |events: &[(&str, &str)]| verdicts(&advisory(events), &repo, &fix);

        assert_eq!(
            check(&[("introduced", "0.0.0"), ("fixed", "1.0.2")]),
            [(Verdict::Confirmed, None)]
        );
        // Published too late: 1.0.2 and 1.1.0 already hold the fix.
        assert_eq!(
            check(&[("introduced", "0.0.0"), ("fixed", "1.2.0")]),
            [(Verdict::FixedEarlier, Some("1.0.2".into()))]
        );
        // Published too early: 1.0.1 lacks it, a false clean.
        assert_eq!(
            check(&[("introduced", "0.0.0"), ("fixed", "1.0.1")]),
            [(Verdict::FixedLater, Some("1.0.2".into()))]
        );
        // The 0.9.x line never got this commit: a backport the record does not link.
        assert_eq!(
            check(&[("introduced", "0.9.0"), ("fixed", "0.9.5")]),
            [(Verdict::Unverified, None)]
        );
        // An open range is fixed from 1.0.2 on, every later release holding the fix.
        assert_eq!(
            check(&[("introduced", "1.0.0")]),
            [(Verdict::FixMissing, Some("1.0.2".into()))]
        );
        // From 0.0.0 the 0.9.x line comes first and lacks it; the main line still decides.
        assert_eq!(
            check(&[("introduced", "0.0.0")]),
            [(Verdict::FixMissing, Some("1.0.2".into()))]
        );
        // The range starts at a release that already holds the commit: the record links
        // another advisory's fix.
        assert_eq!(
            check(&[("introduced", "1.1.0"), ("fixed", "1.2.0")]),
            [(Verdict::Unverified, None)]
        );
        // No tag for the bound.
        assert_eq!(
            check(&[("introduced", "0.0.0"), ("fixed", "1.0.3")]),
            [(Verdict::NoTag, None)]
        );
        // A commit the repository does not have.
        let missing = verdicts(
            &advisory(&[("introduced", "0.0.0"), ("fixed", "1.0.2")]),
            &repo,
            "0123456789abcdef0123456789abcdef01234567",
        );
        assert_eq!(missing, [(Verdict::NoCommit, None)]);
    }

    #[test]
    fn corrections_move_the_bound_and_carry_the_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::create_dir_all(dir.join("npm")).unwrap();
        std::fs::write(
            dir.join("npm/GHSA-test.json"),
            r#"{"id":"GHSA-test","modified":"2024-01-01T00:00:00Z","affected":[
                {"package":{"ecosystem":"npm","name":"Pkg"},"ranges":[
                  {"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]},
                  {"type":"GIT","repo":"https://github.com/o/r","events":[{"introduced":"0"},{"fixed":"abcdef1"}]}]},
                {"package":{"ecosystem":"npm","name":"other"},"ranges":[
                  {"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]}]}"#,
        )
        .unwrap();
        let check = Check {
            ecosystem: "npm".into(),
            id: "GHSA-test".into(),
            package: "pkg".into(),
            repo: "github.com/o/r".into(),
            commits: vec!["abcdef1".into()],
            verdict: Verdict::FixedEarlier,
            published: Some("1.2.0".into()),
            derived: Some("1.0.2".into()),
            tags: vec!["v1.2.0".into(), "v1.0.2".into()],
            detail: "d".into(),
        };
        let confirmed = Check {
            verdict: Verdict::Confirmed,
            derived: None,
            ..check.clone()
        };
        let out = corrections(dir, &[check, confirmed], "2026-11-12T00:00:00Z").unwrap();
        let record = &out["GHSA-test"];
        assert_eq!(record["modified"], "2026-11-12T00:00:00Z");
        assert_eq!(
            record["affected"][0]["ranges"][0]["events"][1]["fixed"],
            "1.0.2"
        );
        assert_eq!(
            record["affected"][0]["ranges"][1]["events"][1]["fixed"], "abcdef1",
            "GIT range untouched"
        );
        assert_eq!(
            record["affected"][1]["ranges"][0]["events"][1]["fixed"], "1.2.0",
            "another package untouched"
        );
        let note = &record["database_specific"]["fleetreach_correction"];
        assert_eq!(note["status"], "unreviewed");
        assert_eq!(note["upstream_modified"], "2024-01-01T00:00:00Z");
        assert_eq!(note["changes"].as_array().unwrap().len(), 1);
        // The correction is valid OSV for the overlay loader.
        let body = serde_json::to_string(record).unwrap();
        let parsed: Record = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.id, "GHSA-test");
    }
}
