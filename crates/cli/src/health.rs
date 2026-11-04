//! Registry health (spec 16, row 21): `scan --health` asks each public registry what it says
//! about the packages in use, and warns on what a lockfile cannot show.
//!
//! | Signal | Registry | Read from |
//! |--------|----------|-----------|
//! | `deprecated` | npm, NuGet, Go | the version's `deprecated`, `deprecation`, the `// Deprecated:` comment in the newest `go.mod` |
//! | `yanked` | PyPI, RubyGems, crates.io, NuGet | `info.yanked`, absent from the version list, the sparse index, `listed: false` |
//! | `abandoned` | Packagist | `abandoned`, with its replacement |
//! | `retracted` | Go | `retract` in the newest `go.mod` |
//! | `retired` | Hex | `retirements` |
//! | `relocated` | Maven | `distributionManagement/relocation` in the POM |
//! | `archived` | GitHub repos | the GitHub API, with `GITHUB_TOKEN` or `GH_TOKEN` |
//! | `low-scorecard` | any repo deps.dev knows | OpenSSF Scorecard, below `[settings.health] min_scorecard` |
//!
//! Each is a warning with the id `fleetreach:<signal>:<ecosystem>/<package>`, with `@<version>`
//! for what is said of one version, so `[[settings.ignore]]` can take one package out.
//!
//! Only packages from the public registry are sent: git, path and other-registry sources are
//! not. Answers are cached per package under the user cache for [`FRESH_SECS`]. A package with
//! no answer, offline or after a failure, is a coverage gap and never clean, and `--offline`
//! reads the cache however old it is. Julia's registry records none of this.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use fleetreach_core::{
    Coverage, CoverageGap, DepScope, DepSource, DependencyKind, Ecosystem, Occurrence, RepoId,
    WarnFinding, WarnKind,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::Repo;

/// How long an answer stands before it is asked again: a registry can change its mind.
const FRESH_SECS: i64 = 7 * 24 * 3600;
const LOOKUPS_AT_ONCE: usize = 32;
/// The longest message kept from a registry.
const MAX_DETAIL: usize = 200;

/// What a registry says of a package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Signal {
    Deprecated,
    Yanked,
    Abandoned,
    Retracted,
    Retired,
    Relocated,
    Archived,
    LowScorecard,
}

impl Signal {
    fn id(self) -> &'static str {
        match self {
            Signal::Deprecated => "deprecated",
            Signal::Yanked => "yanked",
            Signal::Abandoned => "abandoned",
            Signal::Retracted => "retracted",
            Signal::Retired => "retired",
            Signal::Relocated => "relocated",
            Signal::Archived => "archived",
            Signal::LowScorecard => "low-scorecard",
        }
    }

    fn kind(self) -> WarnKind {
        match self {
            Signal::Deprecated | Signal::Abandoned | Signal::Archived => WarnKind::Unmaintained,
            Signal::Yanked | Signal::Retracted | Signal::Retired => WarnKind::Yanked,
            Signal::Relocated | Signal::LowScorecard => WarnKind::Notice,
        }
    }

    /// Said of one version, not the package.
    fn per_version(self) -> bool {
        matches!(self, Signal::Yanked | Signal::Retracted | Signal::Retired)
    }
}

/// One thing a registry said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flag {
    pub signal: Signal,
    /// The registry's own words, cleaned.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// What the registry names instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
}

impl Flag {
    fn new(signal: Signal, detail: &str) -> Flag {
        Flag {
            signal,
            detail: clean(detail),
            replacement: None,
        }
    }

    fn instead(mut self, replacement: &str) -> Flag {
        self.replacement = Some(clean(replacement)).filter(|r| !r.is_empty());
        self
    }
}

/// Registry text is anyone's: one line, no control characters, bounded.
fn clean(text: &str) -> String {
    let words: Vec<&str> = text.split_whitespace().collect();
    let line: String = words
        .join(" ")
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    match line.char_indices().nth(MAX_DETAIL) {
        Some((end, _)) => format!("{}...", &line[..end]),
        None => line,
    }
}

/// A registry's answer for one package.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    #[serde(default)]
    fetched: i64,
    /// The versions asked about, with what was said of each.
    #[serde(default)]
    versions: BTreeMap<String, Vec<Flag>>,
    /// Versions the registry does not have, or every version of a package it does not have.
    #[serde(default)]
    unknown: BTreeSet<String>,
}

impl Answer {
    fn covers(&self, versions: &BTreeSet<String>) -> bool {
        versions
            .iter()
            .all(|v| self.versions.contains_key(v) || self.unknown.contains(v))
    }

    fn merge(&mut self, newer: Answer) {
        self.fetched = newer.fetched;
        for version in newer.versions.keys().chain(&newer.unknown) {
            self.versions.remove(version);
            self.unknown.remove(version);
        }
        self.versions.extend(newer.versions);
        self.unknown.extend(newer.unknown);
    }
}

/// What is known of a source repo.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Project {
    #[serde(default)]
    fetched: i64,
    /// deps.dev was asked: a run without `min_scorecard` does not.
    #[serde(default)]
    scored: bool,
    #[serde(default)]
    scorecard: Option<f64>,
    /// `None` until GitHub was asked.
    #[serde(default)]
    archived: Option<bool>,
}

/// Fetches a URL: its body, `None` for a 404.
pub trait Fetch: Sync {
    /// # Errors
    ///
    /// On anything but a body or a 404.
    fn get(&self, url: &str) -> Result<Option<Vec<u8>>, String>;
    /// [`Fetch::get`] with the login for GitHub's API.
    ///
    /// # Errors
    ///
    /// As [`Fetch::get`].
    fn github(&self, url: &str) -> Result<Option<Vec<u8>>, String>;
    fn has_github_token(&self) -> bool;
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'~' | b'@') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn json(body: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(body).map_err(|e| format!("reading the answer: {e}"))
}

/// Whether this ecosystem has a registry to ask.
fn has_registry(ecosystem: Ecosystem) -> bool {
    matches!(
        ecosystem,
        Ecosystem::Npm
            | Ecosystem::Pypi
            | Ecosystem::RubyGems
            | Ecosystem::Cargo
            | Ecosystem::NuGet
            | Ecosystem::Packagist
            | Ecosystem::Go
            | Ecosystem::Hex
            | Ecosystem::Maven
    )
}

fn slug(ecosystem: Ecosystem) -> String {
    let text = serde_json::to_value(ecosystem).ok();
    text.and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{ecosystem:?}").to_ascii_lowercase())
}

/// Ask one version at a time: `one` says what is flagged, `None` for an unknown version.
fn per_version(
    versions: &BTreeSet<String>,
    mut one: impl FnMut(&str) -> Result<Option<Vec<Flag>>, String>,
) -> Result<Answer, String> {
    let mut answer = Answer::default();
    for version in versions {
        match one(version)? {
            Some(flags) => {
                answer.versions.insert(version.clone(), flags);
            }
            None => {
                answer.unknown.insert(version.clone());
            }
        }
    }
    Ok(answer)
}

fn unknown(versions: &BTreeSet<String>) -> Answer {
    Answer {
        unknown: versions.clone(),
        ..Answer::default()
    }
}

fn npm(fetch: &dyn Fetch, name: &str, versions: &BTreeSet<String>) -> Result<Answer, String> {
    per_version(versions, |version| {
        let url = format!(
            "https://registry.npmjs.org/{}/{}",
            encode(name),
            encode(version)
        );
        let Some(body) = fetch.get(&url)? else {
            return Ok(None);
        };
        Ok(Some(npm_flags(&json(&body)?)))
    })
}

fn npm_flags(doc: &Value) -> Vec<Flag> {
    let message = doc.get("deprecated").and_then(Value::as_str);
    let message = message.filter(|m| !m.trim().is_empty());
    message
        .map(|m| Flag::new(Signal::Deprecated, m))
        .into_iter()
        .collect()
}

fn pypi(fetch: &dyn Fetch, name: &str, versions: &BTreeSet<String>) -> Result<Answer, String> {
    per_version(versions, |version| {
        let url = format!(
            "https://pypi.org/pypi/{}/{}/json",
            encode(name),
            encode(version)
        );
        let Some(body) = fetch.get(&url)? else {
            return Ok(None);
        };
        Ok(Some(pypi_flags(&json(&body)?)))
    })
}

fn pypi_flags(doc: &Value) -> Vec<Flag> {
    let Some(info) = doc.get("info") else {
        return Vec::new();
    };
    if info.get("yanked").and_then(Value::as_bool) != Some(true) {
        return Vec::new();
    }
    let reason = info.get("yanked_reason").and_then(Value::as_str);
    vec![Flag::new(Signal::Yanked, reason.unwrap_or(""))]
}

/// `/api/v1/versions` lists what is not yanked, under every platform.
fn rubygems(fetch: &dyn Fetch, name: &str, versions: &BTreeSet<String>) -> Result<Answer, String> {
    let url = format!("https://rubygems.org/api/v1/versions/{}.json", encode(name));
    let Some(body) = fetch.get(&url)? else {
        return Ok(unknown(versions));
    };
    let listed = json(&body)?;
    let listed: BTreeSet<&str> = listed
        .as_array()
        .ok_or("the version list is not a list")?
        .iter()
        .filter_map(|v| v.get("number").and_then(Value::as_str))
        .collect();
    per_version(versions, |version| {
        // A locked platform gem reads `1.16.0-x86_64-linux`.
        let number = version.split('-').next().unwrap_or(version);
        let flags = match listed.contains(number) {
            true => Vec::new(),
            false => vec![Flag::new(Signal::Yanked, "")],
        };
        Ok(Some(flags))
    })
}

fn sparse_path(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    match lower.len() {
        0..=2 => format!("{}/{lower}", lower.len()),
        3 => format!("3/{}/{lower}", &lower[..1]),
        _ => format!("{}/{}/{lower}", &lower[..2], &lower[2..4]),
    }
}

fn cargo(fetch: &dyn Fetch, name: &str, versions: &BTreeSet<String>) -> Result<Answer, String> {
    if !name.is_ascii() {
        return Ok(unknown(versions));
    }
    let url = format!("https://index.crates.io/{}", sparse_path(name));
    let Some(body) = fetch.get(&url)? else {
        return Ok(unknown(versions));
    };
    let text = String::from_utf8_lossy(&body);
    let mut yanked = BTreeMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let entry = json(line.as_bytes())?;
        let version = entry.get("vers").and_then(Value::as_str).unwrap_or("");
        let flag = entry
            .get("yanked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        yanked.insert(version.to_string(), flag);
    }
    per_version(versions, |version| {
        Ok(yanked.get(version).map(|yanked| match yanked {
            true => vec![Flag::new(Signal::Yanked, "")],
            false => Vec::new(),
        }))
    })
}

/// A registry leaf's flags.
fn nuget_flags(entry: &Value) -> Vec<Flag> {
    let mut flags = Vec::new();
    if let Some(deprecation) = entry.get("deprecation") {
        let message = deprecation.get("message").and_then(Value::as_str);
        let reasons: Vec<&str> = deprecation
            .get("reasons")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let joined = reasons.join(", ");
        let mut flag = Flag::new(Signal::Deprecated, message.unwrap_or(&joined));
        let alternate = deprecation.get("alternatePackage");
        if let Some(id) = alternate.and_then(|a| a.get("id")).and_then(Value::as_str) {
            flag = flag.instead(id);
        }
        flags.push(flag);
    }
    if entry.get("listed").and_then(Value::as_bool) == Some(false) {
        flags.push(Flag::new(Signal::Yanked, "unlisted"));
    }
    flags
}

/// NuGet's normalized form: lower case, no build metadata, three parts at least, no zero fourth.
fn nuget_version(version: &str) -> String {
    let lower = version.to_ascii_lowercase();
    let bare = lower.split('+').next().unwrap_or(&lower);
    let (release, label) = match bare.split_once('-') {
        Some((release, label)) => (release, Some(label)),
        None => (bare, None),
    };
    let mut parts: Vec<String> = release
        .split('.')
        .map(|p| p.parse::<u64>().map_or(p.to_string(), |n| n.to_string()))
        .collect();
    while parts.len() < 3 {
        parts.push("0".to_string());
    }
    if parts.len() == 4 && parts[3] == "0" {
        parts.pop();
    }
    let release = parts.join(".");
    label.map_or(release.clone(), |label| format!("{release}-{label}"))
}

/// The gzipped registration: the plain one leaves out SemVer 2 versions.
fn gunzip(body: Vec<u8>) -> Result<Vec<u8>, String> {
    use std::io::Read;
    if !body.starts_with(&[0x1f, 0x8b]) {
        return Ok(body);
    }
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(body.as_slice())
        .take(64 << 20)
        .read_to_end(&mut out)
        .map_err(|e| format!("unpacking the answer: {e}"))?;
    Ok(out)
}

fn nuget(fetch: &dyn Fetch, name: &str, versions: &BTreeSet<String>) -> Result<Answer, String> {
    const BASE: &str = "https://api.nuget.org/v3/registration5-gz-semver2/";
    let url = format!("{BASE}{}/index.json", encode(&name.to_ascii_lowercase()));
    let Some(body) = fetch.get(&url)? else {
        return Ok(unknown(versions));
    };
    let index = json(&gunzip(body)?)?;
    let mut leaves: BTreeMap<String, Vec<Flag>> = BTreeMap::new();
    let mut read_page = |page: &Value| {
        for leaf in page
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(entry) = leaf.get("catalogEntry") else {
                continue;
            };
            if let Some(version) = entry.get("version").and_then(Value::as_str) {
                leaves.insert(nuget_version(version), nuget_flags(entry));
            }
        }
    };
    for page in index
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if page.get("items").is_some() {
            read_page(page);
            continue;
        }
        let url = page.get("@id").and_then(Value::as_str).unwrap_or("");
        // The page's address comes from the answer: it may not lead anywhere else.
        if !url.starts_with(BASE) {
            return Err(format!(
                "a registration page outside the registry: {}",
                clean(url)
            ));
        }
        let body = fetch.get(url)?.ok_or("a registration page is missing")?;
        read_page(&json(&gunzip(body)?)?);
    }
    per_version(versions, |version| {
        Ok(leaves.get(&nuget_version(version)).cloned())
    })
}

fn packagist_flag(entry: &Value) -> Option<Flag> {
    match entry.get("abandoned")? {
        Value::Bool(true) => Some(Flag::new(Signal::Abandoned, "")),
        Value::String(instead) if !instead.is_empty() => {
            Some(Flag::new(Signal::Abandoned, "").instead(instead))
        }
        Value::String(_) => Some(Flag::new(Signal::Abandoned, "")),
        _ => None,
    }
}

fn packagist(fetch: &dyn Fetch, name: &str, versions: &BTreeSet<String>) -> Result<Answer, String> {
    let lower = name.to_ascii_lowercase();
    let path: Vec<String> = lower.split('/').map(encode).collect();
    let url = format!("https://repo.packagist.org/p2/{}.json", path.join("/"));
    let Some(body) = fetch.get(&url)? else {
        return Ok(unknown(versions));
    };
    let doc = json(&body)?;
    let entries = doc.get("packages").and_then(|p| p.get(&lower));
    // Metadata is minified: the first entry is the newest, and whole.
    let newest = entries.and_then(Value::as_array).and_then(|e| e.first());
    let flags: Vec<Flag> = newest.and_then(packagist_flag).into_iter().collect();
    per_version(versions, |_| Ok(Some(flags.clone())))
}

fn hex(fetch: &dyn Fetch, name: &str, versions: &BTreeSet<String>) -> Result<Answer, String> {
    let url = format!("https://hex.pm/api/packages/{}", encode(name));
    let Some(body) = fetch.get(&url)? else {
        return Ok(unknown(versions));
    };
    let doc = json(&body)?;
    let retirements = doc.get("retirements").cloned().unwrap_or(Value::Null);
    per_version(versions, |version| {
        let Some(retired) = retirements.get(version) else {
            return Ok(Some(Vec::new()));
        };
        let field = |key: &str| retired.get(key).and_then(Value::as_str).unwrap_or("");
        let detail = format!("{} {}", field("reason"), field("message"));
        Ok(Some(vec![Flag::new(Signal::Retired, &detail)]))
    })
}

/// The `Deprecated:` paragraph above the `module` line, or on it.
fn go_deprecation(text: &str) -> Option<String> {
    let mut above: Vec<&str> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(comment) = line.strip_prefix("//") {
            above.push(comment.trim());
            continue;
        }
        if line.starts_with("module") {
            let trailing = line.split_once("//").map(|(_, c)| c.trim());
            above.extend(trailing);
            break;
        }
        above.clear();
    }
    let start = above.iter().position(|l| l.starts_with("Deprecated:"))?;
    let rest = &above[start..];
    let end = rest.iter().position(|l| l.is_empty()).unwrap_or(rest.len());
    let text = rest[..end].join(" ");
    Some(text.trim_start_matches("Deprecated:").trim().to_string())
}

/// `retract` directives: (low, high, rationale).
fn go_retractions(text: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut block = false;
    for raw in text.lines() {
        let line = raw.trim();
        let entry = if block {
            if line.starts_with(')') {
                block = false;
                continue;
            }
            line
        } else if line == "retract (" || line == "retract(" {
            block = true;
            continue;
        } else if let Some(rest) = line.strip_prefix("retract ") {
            rest.trim()
        } else {
            continue;
        };
        let (spec, why) = entry.split_once("//").unwrap_or((entry, ""));
        let spec = spec.trim();
        let (low, high) = match spec.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            Some(range) => {
                let (low, high) = range.split_once(',').unwrap_or((range, range));
                (low.trim(), high.trim())
            }
            None => (spec, spec),
        };
        if !low.is_empty() {
            out.push((low.to_string(), high.to_string(), why.trim().to_string()));
        }
    }
    out
}

fn go(fetch: &dyn Fetch, name: &str, versions: &BTreeSet<String>) -> Result<Answer, String> {
    // `stdlib` and `toolchain` are not modules on the proxy.
    if !name.split('/').next().unwrap_or("").contains('.') {
        return Ok(Answer {
            versions: versions.iter().map(|v| (v.clone(), Vec::new())).collect(),
            ..Answer::default()
        });
    }
    let base = format!(
        "https://proxy.golang.org/{}/@",
        crate::scope::cache_escaped(name)
    );
    let Some(body) = fetch.get(&format!("{base}latest"))? else {
        return Ok(unknown(versions));
    };
    let latest = json(&body)?;
    let latest = latest
        .get("Version")
        .and_then(Value::as_str)
        .ok_or("no version")?;
    let url = format!("{base}v/{}.mod", crate::scope::cache_escaped(latest));
    let Some(body) = fetch.get(&url)? else {
        return Ok(unknown(versions));
    };
    let text = String::from_utf8_lossy(&body);
    let deprecated = go_deprecation(&text);
    let retractions = go_retractions(&text);
    let parse = |v: &str| fleetreach_go::parse_go_version(v);
    per_version(versions, |version| {
        let mut flags: Vec<Flag> = deprecated
            .iter()
            .map(|d| Flag::new(Signal::Deprecated, d))
            .collect();
        let Some(installed) = parse(version) else {
            return Ok(Some(flags));
        };
        let retracted = retractions.iter().find(|(low, high, _)| {
            matches!((parse(low), parse(high)), (Some(l), Some(h)) if l <= installed && installed <= h)
        });
        flags.extend(retracted.map(|(_, _, why)| Flag::new(Signal::Retracted, why)));
        Ok(Some(flags))
    })
}

fn maven_flags(pom: &str) -> Result<Vec<Flag>, String> {
    let doc = roxmltree::Document::parse(pom).map_err(|e| format!("reading the POM: {e}"))?;
    let root = doc.root_element();
    let child = |node: roxmltree::Node<'_, '_>, name: &str| {
        node.children()
            .find(|c| c.has_tag_name(name))
            .and_then(|c| {
                let text = c.text().map(str::trim).filter(|t| !t.is_empty());
                text.map(str::to_string)
            })
    };
    let manage = root
        .children()
        .find(|c| c.has_tag_name("distributionManagement"));
    let moved = manage.and_then(|m| m.children().find(|c| c.has_tag_name("relocation")));
    let Some(moved) = moved else {
        return Ok(Vec::new());
    };
    let own = |name: &str| {
        child(root, name).or_else(|| {
            let parent = root.children().find(|c| c.has_tag_name("parent"))?;
            child(parent, name)
        })
    };
    let group = child(moved, "groupId").or_else(|| own("groupId"));
    let artifact = child(moved, "artifactId").or_else(|| own("artifactId"));
    let target = format!(
        "{}:{}",
        group.unwrap_or_default(),
        artifact.unwrap_or_default()
    );
    let message = child(moved, "message").unwrap_or_default();
    Ok(vec![Flag::new(Signal::Relocated, &message).instead(&target)])
}

fn maven(fetch: &dyn Fetch, name: &str, versions: &BTreeSet<String>) -> Result<Answer, String> {
    let Some((group, artifact)) = name.split_once(':') else {
        return Ok(unknown(versions));
    };
    per_version(versions, |version| {
        let url = format!(
            "https://repo1.maven.org/maven2/{}/{artifact}/{version}/{artifact}-{version}.pom",
            group.replace('.', "/")
        );
        let Some(body) = fetch.get(&url)? else {
            return Ok(None);
        };
        maven_flags(&String::from_utf8_lossy(&body)).map(Some)
    })
}

/// Asks the registry of `ecosystem` about `versions` of `name`.
fn check(
    fetch: &dyn Fetch,
    ecosystem: Ecosystem,
    name: &str,
    versions: &BTreeSet<String>,
) -> Result<Answer, String> {
    match ecosystem {
        Ecosystem::Npm => npm(fetch, name, versions),
        Ecosystem::Pypi => pypi(fetch, name, versions),
        Ecosystem::RubyGems => rubygems(fetch, name, versions),
        Ecosystem::Cargo => cargo(fetch, name, versions),
        Ecosystem::NuGet => nuget(fetch, name, versions),
        Ecosystem::Packagist => packagist(fetch, name, versions),
        Ecosystem::Hex => hex(fetch, name, versions),
        Ecosystem::Go => go(fetch, name, versions),
        Ecosystem::Maven => maven(fetch, name, versions),
        _ => Ok(Answer::default()),
    }
}

/// `github.com/owner/repo` from a URL or a bare path, on a host deps.dev knows.
fn project_id(text: &str) -> Option<String> {
    let bare = text.split_once("://").map_or(text, |(_, rest)| rest);
    let bare = bare
        .strip_prefix("git@")
        .unwrap_or(bare)
        .replacen(':', "/", 1);
    let mut parts = bare.split('/').filter(|p| !p.is_empty());
    let (host, owner, repo) = (parts.next()?, parts.next()?, parts.next()?);
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    matches!(host, "github.com" | "gitlab.com" | "bitbucket.org")
        .then(|| format!("{host}/{owner}/{repo}"))
}

/// Where a package's source lives. deps.dev for what it covers; others say so themselves.
fn source_repo(
    fetch: &dyn Fetch,
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> Result<Option<String>, String> {
    match ecosystem {
        Ecosystem::GitHubActions => return Ok(project_id(&format!("github.com/{name}"))),
        Ecosystem::Swift => return Ok(project_id(name)),
        _ => {}
    }
    if ecosystem == Ecosystem::Packagist {
        let url = format!(
            "https://repo.packagist.org/p2/{}.json",
            name.to_ascii_lowercase()
        );
        let Some(body) = fetch.get(&url)? else {
            return Ok(None);
        };
        let doc = json(&body)?;
        let entries = doc
            .get("packages")
            .and_then(|p| p.get(name.to_ascii_lowercase()));
        let newest = entries.and_then(Value::as_array).and_then(|e| e.first());
        let source = newest
            .and_then(|e| e.get("source"))
            .and_then(|s| s.get("url"));
        return Ok(source.and_then(Value::as_str).and_then(project_id));
    }
    let Some(system) = crate::depsdev::system(ecosystem) else {
        return Ok(None);
    };
    let url = format!(
        "https://api.deps.dev/v3/systems/{system}/packages/{}/versions/{}",
        encode(name).replace('@', "%40"),
        encode(version)
    );
    let Some(body) = fetch.get(&url)? else {
        return Ok(None);
    };
    let doc = json(&body)?;
    let related = doc.get("relatedProjects").and_then(Value::as_array);
    let source = related
        .into_iter()
        .flatten()
        .find(|p| p.get("relationType").and_then(Value::as_str) == Some("SOURCE_REPO"));
    let id = source
        .and_then(|p| p.get("projectKey"))
        .and_then(|k| k.get("id"))
        .and_then(Value::as_str);
    Ok(id.and_then(project_id))
}

fn project(fetch: &dyn Fetch, id: &str, scorecard: bool) -> Result<Project, String> {
    let mut out = Project::default();
    if scorecard {
        out.scored = true;
        let url = format!("https://api.deps.dev/v3/projects/{}", encode(id));
        if let Some(body) = fetch.get(&url)? {
            let doc = json(&body)?;
            let card = doc.get("scorecard").and_then(|s| s.get("overallScore"));
            out.scorecard = card.and_then(Value::as_f64);
        }
    }
    if let (true, Some(path)) = (fetch.has_github_token(), id.strip_prefix("github.com/")) {
        let url = format!("https://api.github.com/repos/{path}");
        if let Some(body) = fetch.github(&url)? {
            out.archived = json(&body)?.get("archived").and_then(Value::as_bool);
        }
    }
    Ok(out)
}

/// The answers kept between runs.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Cache {
    #[serde(default)]
    packages: BTreeMap<String, Answer>,
    /// A package's source repo, or `None` when it names none.
    #[serde(default)]
    sources: BTreeMap<String, Option<String>>,
    #[serde(default)]
    projects: BTreeMap<String, Project>,
}

fn cache_path() -> Result<PathBuf, String> {
    let dir = crate::osvdb::private_subdir("health").ok_or("no usable cache directory")?;
    crate::osvdb::create_private_dir(&dir)
        .map_err(|e| format!("creating {}: {e}", dir.display()))?;
    Ok(dir.join("answers.json"))
}

fn load_cache(path: &std::path::Path) -> Cache {
    let text = std::fs::read_to_string(path).ok();
    text.and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_cache(path: &std::path::Path, cache: &Cache) {
    let scratch = path.with_extension("tmp");
    let written = serde_json::to_vec(cache)
        .map_err(|e| e.to_string())
        .and_then(|bytes| std::fs::write(&scratch, bytes).map_err(|e| e.to_string()))
        .and_then(|()| std::fs::rename(&scratch, path).map_err(|e| e.to_string()));
    if let Err(e) = written {
        eprintln!(
            "warning: could not save the health cache {}: {e}",
            path.display()
        );
    }
}

fn package_key(ecosystem: Ecosystem, name: &str) -> String {
    format!("{}\u{1f}{name}", slug(ecosystem))
}

/// What to ask about: every public-registry package of a repo.
#[derive(Debug, Clone)]
pub struct Used {
    pub repo: RepoId,
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub direct: bool,
    pub dev: bool,
    /// The file that listed it.
    pub source: String,
}

/// What `scan --health` adds.
#[derive(Debug, Default)]
pub struct Outcome {
    pub findings: Vec<WarnFinding>,
    pub gaps: Vec<CoverageGap>,
    /// Said once, on stderr.
    pub notes: Vec<String>,
}

/// How to run.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Flag repos scoring under this, when set.
    pub min_scorecard: Option<f64>,
    pub now: i64,
}

fn used_packages(repos: &[Repo], maven: Option<&crate::maven_repo::Remote>) -> Vec<Used> {
    let read = |repo: &Repo| {
        let inv = crate::inventory::repo_inventory_with(repo, maven);
        let mut out = Vec::new();
        for source in inv.sources {
            for p in source.packages {
                // A private package's name goes nowhere. Swift packages are all git repos.
                let public = !p.version.contains(':')
                    && (source.ecosystem == Ecosystem::Swift
                        || !matches!(
                            p.source,
                            DepSource::Git { .. }
                                | DepSource::Path
                                | DepSource::OtherRegistry { .. }
                        ));
                if public {
                    out.push(Used {
                        repo: inv.repo.clone(),
                        ecosystem: source.ecosystem,
                        name: p.name,
                        version: p.version,
                        direct: p.direct,
                        dev: p.dev,
                        source: source.source.clone(),
                    });
                }
            }
        }
        out
    };
    repos.par_iter().flat_map_iter(read).collect()
}

/// Fills `cache` from `fetch`, or leaves it when `fetch` is `None`. Returns the keys that
/// failed, with one reason.
fn refresh(
    cache: &mut Cache,
    wanted: &BTreeMap<(Ecosystem, String), BTreeSet<String>>,
    fetch: Option<&dyn Fetch>,
    options: Options,
) -> (BTreeSet<String>, Option<String>) {
    let Some(fetch) = fetch else {
        return (BTreeSet::new(), None);
    };
    let stale = |key: &str, versions: &BTreeSet<String>| match cache.packages.get(key) {
        Some(a) => !a.covers(versions) || options.now - a.fetched >= FRESH_SECS,
        None => true,
    };
    let todo: Vec<(&(Ecosystem, String), &BTreeSet<String>)> = wanted
        .iter()
        .filter(|((e, _), _)| has_registry(*e))
        .filter(|((e, n), v)| stale(&package_key(*e, n), v))
        .collect();
    let answers: Vec<(String, Result<Answer, String>)> = todo
        .par_iter()
        .map(|((ecosystem, name), versions)| {
            let answer = check(fetch, *ecosystem, name, versions);
            (package_key(*ecosystem, name), answer)
        })
        .collect();
    let mut failed = BTreeSet::new();
    let mut reason = None;
    for (key, answer) in answers {
        match answer {
            Ok(mut answer) => {
                answer.fetched = options.now;
                cache.packages.entry(key).or_default().merge(answer);
            }
            Err(e) => {
                reason.get_or_insert(e);
                failed.insert(key);
            }
        }
    }
    (failed, reason)
}

/// Looks up source repos and what is known of them.
fn refresh_projects(
    cache: &mut Cache,
    wanted: &BTreeMap<(Ecosystem, String), BTreeSet<String>>,
    fetch: &dyn Fetch,
    options: Options,
) -> Option<String> {
    let todo: Vec<_> = wanted
        .iter()
        .filter(|((e, n), _)| !cache.sources.contains_key(&package_key(*e, n)))
        .collect();
    let found: Vec<_> = todo
        .par_iter()
        .map(|((ecosystem, name), versions)| {
            let version = versions.iter().next_back().map_or("", String::as_str);
            let repo = source_repo(fetch, *ecosystem, name, version);
            (package_key(*ecosystem, name), repo)
        })
        .collect();
    let mut failure = None;
    for (key, repo) in found {
        match repo {
            Ok(repo) => {
                cache.sources.insert(key, repo);
            }
            Err(e) => {
                failure.get_or_insert(e);
            }
        }
    }
    let keys = wanted.keys().map(|(e, n)| package_key(*e, n));
    let ids: BTreeSet<&String> = keys
        .filter_map(|k| cache.sources.get(&k)?.as_ref())
        .collect();
    let scorecard = options.min_scorecard.is_some();
    let token = fetch.has_github_token();
    let stale = |id: &&&String| match cache.projects.get(id.as_str()) {
        Some(p) => {
            options.now - p.fetched >= FRESH_SECS
                || (scorecard && !p.scored)
                || (token && p.archived.is_none() && id.starts_with("github.com/"))
        }
        None => true,
    };
    let todo: Vec<&&String> = ids.iter().filter(|id| stale(id)).collect();
    let answers: Vec<(String, Result<Project, String>)> = todo
        .par_iter()
        .map(|id| (id.to_string(), project(fetch, id, scorecard)))
        .collect();
    for (id, answer) in answers {
        match answer {
            Ok(mut answer) => {
                answer.fetched = options.now;
                cache.projects.insert(id, answer);
            }
            Err(e) => {
                failure.get_or_insert(e);
            }
        }
    }
    failure
}

fn title(ecosystem: Ecosystem, name: &str, version: &str, flag: &Flag) -> String {
    let eco = slug(ecosystem);
    let head = match flag.signal {
        Signal::Deprecated => format!("{eco} package {name} is deprecated"),
        Signal::Yanked => format!("{eco} package {name} {version} was yanked"),
        Signal::Abandoned => format!("{eco} package {name} is abandoned"),
        Signal::Retracted => format!("{eco} module {name} {version} was retracted"),
        Signal::Retired => format!("{eco} package {name} {version} was retired"),
        Signal::Relocated => format!("{eco} package {name} moved"),
        Signal::Archived => format!("the source repo of {eco} package {name} is archived"),
        Signal::LowScorecard => format!("the source repo of {eco} package {name} scores low"),
    };
    let mut out = head;
    if !flag.detail.is_empty() {
        out.push_str(": ");
        out.push_str(&flag.detail);
    }
    if let Some(instead) = &flag.replacement {
        out.push_str(&format!(" (use {instead})"));
    }
    out
}

fn occurrence(used: &Used) -> Occurrence {
    Occurrence::InRepo {
        repo: used.repo.clone(),
        package: used.name.clone(),
        installed: crate::signals::lenient_version(&used.version),
        patched: Vec::new(),
        dependency_kind: if used.direct {
            DependencyKind::Direct
        } else {
            DependencyKind::Transitive
        },
        dependency_path: Vec::new(),
        active: None,
        source: Default::default(),
        scope: if used.dev {
            DepScope::Dev
        } else {
            DepScope::Runtime
        },
        layer: None,
    }
}

/// What `cache` says of each use, and the gaps it leaves.
fn report(
    used: &[Used],
    cache: &Cache,
    failed: &BTreeSet<String>,
    options: Options,
) -> (Vec<WarnFinding>, Vec<CoverageGap>) {
    let mut findings: BTreeMap<String, WarnFinding> = BTreeMap::new();
    let mut unanswered: BTreeMap<(RepoId, String, Ecosystem), usize> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for use_ in used {
        let key = package_key(use_.ecosystem, &use_.name);
        let identity = (use_.repo.clone(), key.clone(), use_.version.clone());
        if !seen.insert(identity) {
            continue;
        }
        let answer = cache.packages.get(&key);
        let said = answer.and_then(|a| a.versions.get(&use_.version));
        if has_registry(use_.ecosystem) && (said.is_none() || failed.contains(&key)) {
            let gap = (use_.repo.clone(), use_.source.clone(), use_.ecosystem);
            *unanswered.entry(gap).or_default() += 1;
        }
        let mut flags: Vec<Flag> = said.cloned().unwrap_or_default();
        let repo = cache.sources.get(&key).and_then(Option::as_ref);
        if let Some((id, project)) = repo.and_then(|id| Some((id, cache.projects.get(id)?))) {
            if project.archived == Some(true) {
                flags.push(Flag::new(Signal::Archived, id));
            }
            if let (Some(floor), Some(score)) = (options.min_scorecard, project.scorecard) {
                if score < floor {
                    let detail = format!("{id} has an OpenSSF Scorecard of {score:.1}");
                    flags.push(Flag::new(Signal::LowScorecard, &detail));
                }
            }
        }
        for flag in flags {
            let mut id = format!(
                "fleetreach:{}:{}/{}",
                flag.signal.id(),
                slug(use_.ecosystem),
                use_.name
            );
            if flag.signal.per_version() {
                id.push('@');
                id.push_str(&use_.version);
            }
            let finding = findings.entry(id.clone()).or_insert_with(|| WarnFinding {
                kind: flag.signal.kind(),
                advisory_id: Some(id),
                title: title(use_.ecosystem, &use_.name, &use_.version, &flag),
                occurrences: Vec::new(),
            });
            finding.occurrences.push(occurrence(use_));
        }
    }
    let gaps = unanswered
        .into_iter()
        .map(|((repo, source, ecosystem), count)| CoverageGap {
            repo,
            source,
            ecosystem,
            level: Coverage::Partial,
            reason: format!("registry health: no answer for {count} package(s)"),
        })
        .collect();
    (findings.into_values().collect(), gaps)
}

fn run(used: Vec<Used>, cache: &mut Cache, fetch: Option<&dyn Fetch>, options: Options) -> Outcome {
    let mut wanted: BTreeMap<(Ecosystem, String), BTreeSet<String>> = BTreeMap::new();
    for use_ in &used {
        let key = (use_.ecosystem, use_.name.clone());
        wanted.entry(key).or_default().insert(use_.version.clone());
    }
    let (failed, reason) = refresh(cache, &wanted, fetch, options);
    let mut notes: Vec<String> = reason
        .map(|e| {
            format!(
                "{} package(s) had no health answer, the first: {e}",
                failed.len()
            )
        })
        .into_iter()
        .collect();
    if let Some(fetch) = fetch {
        if options.min_scorecard.is_some() || fetch.has_github_token() {
            notes.extend(refresh_projects(cache, &wanted, fetch, options));
        }
        if !fetch.has_github_token() {
            let note = "archived repos not checked: set GITHUB_TOKEN or GH_TOKEN";
            notes.push(note.to_string());
        }
    }
    let (findings, gaps) = report(&used, cache, &failed, options);
    Outcome {
        findings,
        gaps,
        notes,
    }
}

/// Runs `scan --health` over `repos`. `offline` reads only the cache.
///
/// # Errors
///
/// When there is no usable cache directory.
pub fn scan(
    repos: &[Repo],
    maven: Option<&crate::maven_repo::Remote>,
    min_scorecard: Option<f64>,
    offline: bool,
) -> Result<Outcome, String> {
    let path = cache_path()?;
    let mut cache = load_cache(&path);
    let options = Options {
        min_scorecard,
        now: time::OffsetDateTime::now_utc().unix_timestamp(),
    };
    let client = (!offline).then(client::Http::new).flatten();
    let fetch = client.as_ref().map(|c| c as &dyn Fetch);
    // Lookups wait on the network, not the CPU.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(LOOKUPS_AT_ONCE)
        .build()
        .map_err(|e| e.to_string())?;
    let used = used_packages(repos, maven);
    let outcome = pool.install(|| run(used, &mut cache, fetch, options));
    if fetch.is_some() {
        save_cache(&path, &cache);
    }
    Ok(outcome)
}

#[cfg(feature = "network")]
mod client {
    use std::time::Duration;

    use super::Fetch;

    const MAX_BODY: u64 = 64 << 20;
    const MAX_TRIES: u32 = 6;
    const MAX_WAIT_SECONDS: u64 = 60;

    pub struct Http {
        agent: ureq::Agent,
        github_token: Option<String>,
    }

    impl Http {
        pub fn new() -> Option<Http> {
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .https_only(true)
                .http_status_as_error(false)
                .timeout_global(Some(Duration::from_secs(60)))
                .build()
                .into();
            let token = ["GITHUB_TOKEN", "GH_TOKEN"]
                .iter()
                .find_map(|name| std::env::var(name).ok().filter(|t| !t.is_empty()));
            Some(Http {
                agent,
                github_token: token,
            })
        }

        fn call(&self, url: &str, token: Option<&str>) -> Result<Option<Vec<u8>>, String> {
            for attempt in 1..=MAX_TRIES {
                let mut request = self.agent.get(url).header(
                    "User-Agent",
                    concat!("fleetreach/", env!("CARGO_PKG_VERSION")),
                );
                if let Some(token) = token {
                    request = request.header("Authorization", &format!("Bearer {token}"));
                }
                let mut response = request.call().map_err(|e| e.to_string())?;
                let status = response.status().as_u16();
                match status {
                    200 => {
                        let body = response
                            .body_mut()
                            .with_config()
                            .limit(MAX_BODY)
                            .read_to_vec();
                        return body.map(Some).map_err(|e| e.to_string());
                    }
                    404 | 410 => return Ok(None),
                    429 | 500 | 502 | 503 | 504 if attempt < MAX_TRIES => {
                        let asked = response
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok());
                        let wait = asked.unwrap_or(1 << attempt).min(MAX_WAIT_SECONDS);
                        std::thread::sleep(Duration::from_secs(wait));
                    }
                    other => return Err(format!("HTTP {other} from {url}")),
                }
            }
            Err(format!("no answer from {url}"))
        }
    }

    impl Fetch for Http {
        fn get(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
            self.call(url, None)
        }

        fn github(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
            self.call(url, self.github_token.as_deref())
        }

        fn has_github_token(&self) -> bool {
            self.github_token.is_some()
        }
    }
}

#[cfg(not(feature = "network"))]
mod client {
    use super::Fetch;

    pub struct Http;

    impl Http {
        pub fn new() -> Option<Http> {
            None
        }
    }

    impl Fetch for Http {
        fn get(&self, _: &str) -> Result<Option<Vec<u8>>, String> {
            Err("no network in this build".to_string())
        }

        fn github(&self, _: &str) -> Result<Option<Vec<u8>>, String> {
            Err("no network in this build".to_string())
        }

        fn has_github_token(&self) -> bool {
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Answers from a table; any other URL is a 404, and `failing` an error.
    #[derive(Default)]
    struct Fake {
        answers: BTreeMap<String, String>,
        failing: BTreeSet<String>,
        asked: Mutex<Vec<String>>,
        token: bool,
    }

    impl Fake {
        fn with(mut self, url: &str, body: &str) -> Fake {
            self.answers.insert(url.to_string(), body.to_string());
            self
        }
    }

    impl Fetch for Fake {
        fn get(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
            self.asked.lock().unwrap().push(url.to_string());
            if self.failing.contains(url) {
                return Err("HTTP 500".to_string());
            }
            Ok(self.answers.get(url).map(|b| b.clone().into_bytes()))
        }

        fn github(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
            self.get(url)
        }

        fn has_github_token(&self) -> bool {
            self.token
        }
    }

    fn versions(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|v| v.to_string()).collect()
    }

    fn signals(answer: &Answer, version: &str) -> Vec<Signal> {
        answer.versions[version].iter().map(|f| f.signal).collect()
    }

    #[test]
    fn npm_reads_deprecated_and_ignores_an_empty_one() {
        let fake = Fake::default()
            .with(
                "https://registry.npmjs.org/@a%2Fb/1.0.0",
                r#"{"deprecated":"use c"}"#,
            )
            .with(
                "https://registry.npmjs.org/@a%2Fb/2.0.0",
                r#"{"deprecated":""}"#,
            );
        let answer = npm(&fake, "@a/b", &versions(&["1.0.0", "2.0.0", "3.0.0"])).unwrap();
        assert_eq!(answer.versions["1.0.0"][0].detail, "use c");
        assert!(answer.versions["2.0.0"].is_empty());
        assert!(answer.unknown.contains("3.0.0"));
    }

    #[test]
    fn pypi_reads_yanked_with_its_reason() {
        let doc = r#"{"info":{"yanked":true,"yanked_reason":"broken"}}"#;
        let fake = Fake::default().with("https://pypi.org/pypi/x/1.0/json", doc);
        let answer = pypi(&fake, "x", &versions(&["1.0"])).unwrap();
        assert_eq!(answer.versions["1.0"][0].detail, "broken");
    }

    #[test]
    fn a_gem_missing_from_the_list_is_yanked_and_an_unknown_gem_is_not() {
        let list = r#"[{"number":"1.0.0"},{"number":"1.16.0","platform":"x86_64-linux"}]"#;
        let fake = Fake::default().with("https://rubygems.org/api/v1/versions/x.json", list);
        let answer = rubygems(
            &fake,
            "x",
            &versions(&["1.0.0", "0.9.0", "1.16.0-x86_64-linux"]),
        );
        let answer = answer.unwrap();
        assert_eq!(signals(&answer, "0.9.0"), vec![Signal::Yanked]);
        assert!(answer.versions["1.0.0"].is_empty());
        assert!(answer.versions["1.16.0-x86_64-linux"].is_empty());
        let answer = rubygems(&fake, "private", &versions(&["1.0.0"])).unwrap();
        assert!(answer.versions.is_empty());
        assert!(answer.unknown.contains("1.0.0"));
    }

    #[test]
    fn crates_read_the_sparse_index() {
        assert_eq!(sparse_path("a"), "1/a");
        assert_eq!(sparse_path("ab"), "2/ab");
        assert_eq!(sparse_path("abc"), "3/a/abc");
        assert_eq!(sparse_path("Serde"), "se/rd/serde");
        let lines = "{\"vers\":\"1.0.0\",\"yanked\":true}\n{\"vers\":\"1.0.1\",\"yanked\":false}\n";
        let fake = Fake::default().with("https://index.crates.io/se/rd/serde", lines);
        let answer = cargo(&fake, "serde", &versions(&["1.0.0", "1.0.1", "9.0.0"])).unwrap();
        assert_eq!(signals(&answer, "1.0.0"), vec![Signal::Yanked]);
        assert!(answer.versions["1.0.1"].is_empty());
        assert!(answer.unknown.contains("9.0.0"));
    }

    #[test]
    fn nuget_reads_inline_and_linked_pages() {
        const BASE: &str = "https://api.nuget.org/v3/registration5-gz-semver2/p/";
        let leaf = r#"{"catalogEntry":{"version":"2.0.0","listed":false,
            "deprecation":{"message":"old","reasons":["Legacy"],"alternatePackage":{"id":"Q"}}}}"#;
        let index = format!(r#"{{"items":[{{"items":[{leaf}]}},{{"@id":"{BASE}page/3.json"}}]}}"#);
        let page = r#"{"items":[{"catalogEntry":{"version":"3.0.0"}}]}"#;
        let fake = Fake::default()
            .with(&format!("{BASE}index.json"), &index)
            .with(&format!("{BASE}page/3.json"), page);
        let answer = nuget(&fake, "P", &versions(&["2.0", "3.0.0.0"])).unwrap();
        assert_eq!(
            signals(&answer, "2.0"),
            vec![Signal::Deprecated, Signal::Yanked]
        );
        assert_eq!(answer.versions["2.0"][0].replacement.as_deref(), Some("Q"));
        assert!(answer.versions["3.0.0.0"].is_empty());
    }

    #[test]
    fn a_nuget_page_off_the_registry_is_refused() {
        let url = "https://api.nuget.org/v3/registration5-gz-semver2/p/index.json";
        let index = r#"{"items":[{"@id":"https://evil.example/x.json"}]}"#;
        let fake = Fake::default().with(url, index);
        assert!(nuget(&fake, "p", &versions(&["1.0.0"])).is_err());
        assert_eq!(fake.asked.lock().unwrap().len(), 1);
    }

    #[test]
    fn packagist_names_the_replacement() {
        let url = "https://repo.packagist.org/p2/a/b.json";
        let doc = r#"{"packages":{"a/b":[{"version":"2.0","abandoned":"c/d"},{"version":"1.0"}]}}"#;
        let fake = Fake::default().with(url, doc);
        let answer = packagist(&fake, "A/b", &versions(&["1.0"])).unwrap();
        assert_eq!(
            answer.versions["1.0"][0].replacement.as_deref(),
            Some("c/d")
        );
        let doc = r#"{"packages":{"a/b":[{"version":"2.0","abandoned":false}]}}"#;
        let fake = Fake::default().with(url, doc);
        assert!(packagist(&fake, "a/b", &versions(&["1.0"]))
            .unwrap()
            .versions["1.0"]
            .is_empty());
    }

    #[test]
    fn hex_reads_retirements_per_version() {
        let doc = r#"{"retirements":{"1.0.0":{"reason":"security","message":"CVE"}}}"#;
        let fake = Fake::default().with("https://hex.pm/api/packages/x", doc);
        let answer = hex(&fake, "x", &versions(&["1.0.0", "1.1.0"])).unwrap();
        assert_eq!(answer.versions["1.0.0"][0].detail, "security CVE");
        assert!(answer.versions["1.1.0"].is_empty());
    }

    #[test]
    fn go_mod_comments_and_retractions() {
        let text = "// Deprecated: use y.\n// More.\n\nmodule x\n";
        assert_eq!(
            go_deprecation("// Deprecated: use y.\n// More.\nmodule x\n").unwrap(),
            "use y. More."
        );
        assert!(go_deprecation(text).is_none());
        assert_eq!(
            go_deprecation("module x // Deprecated: no.\n").unwrap(),
            "no."
        );
        let text = "module x\nretract v1.0.0 // bad\nretract (\n\t[v1.1.0, v1.2.0]\n)\n";
        let got = go_retractions(text);
        assert_eq!(
            got[0],
            (
                "v1.0.0".to_string(),
                "v1.0.0".to_string(),
                "bad".to_string()
            )
        );
        assert_eq!(got[1].1, "v1.2.0");
    }

    #[test]
    fn go_checks_versions_against_the_newest_go_mod() {
        let latest = r#"{"Version":"v1.3.0"}"#;
        let module = "module github.com/A/b\nretract [v1.1.0, v1.2.0] // oops\n";
        let fake = Fake::default()
            .with("https://proxy.golang.org/github.com/!a/b/@latest", latest)
            .with(
                "https://proxy.golang.org/github.com/!a/b/@v/v1.3.0.mod",
                module,
            );
        let answer = go(&fake, "github.com/A/b", &versions(&["v1.1.5", "v1.0.0"])).unwrap();
        assert_eq!(signals(&answer, "v1.1.5"), vec![Signal::Retracted]);
        assert!(answer.versions["v1.0.0"].is_empty());
        let answer = go(&fake, "stdlib", &versions(&["1.21.0"])).unwrap();
        assert!(answer.versions["1.21.0"].is_empty());
    }

    #[test]
    fn maven_reads_a_relocation_with_defaults_from_the_pom() {
        let pom = "<project><groupId>g</groupId><artifactId>a</artifactId><distributionManagement>\
            <relocation><groupId>h</groupId><message>moved</message></relocation>\
            </distributionManagement></project>";
        let got = maven_flags(pom).unwrap();
        assert_eq!(got[0].replacement.as_deref(), Some("h:a"));
        assert!(maven_flags("<project><groupId>g</groupId></project>")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn registry_text_cannot_reach_the_terminal_raw() {
        assert_eq!(clean("a\n\x1b[31mb\tc"), "a [31mb c");
        assert!(clean(&"x".repeat(500)).len() < 210);
    }

    #[test]
    fn project_ids_come_from_urls_and_ssh_remotes() {
        for text in [
            "https://github.com/a/b.git",
            "git+https://github.com/a/b/tree/main",
            "git@github.com:a/b.git",
            "github.com/a/b/sub",
        ] {
            assert_eq!(
                project_id(text).as_deref(),
                Some("github.com/a/b"),
                "{text}"
            );
        }
        assert_eq!(project_id("https://example.com/a/b"), None);
    }

    fn used(repo: &str, ecosystem: Ecosystem, name: &str, version: &str) -> Used {
        Used {
            repo: RepoId(repo.to_string()),
            ecosystem,
            name: name.to_string(),
            version: version.to_string(),
            direct: true,
            dev: false,
            source: "lock".to_string(),
        }
    }

    const REQUEST: &str = "https://registry.npmjs.org/request/2.88.2";

    #[test]
    fn one_finding_per_package_with_an_occurrence_per_repo() {
        let fake = Fake::default().with(REQUEST, r#"{"deprecated":"no"}"#);
        let list = vec![
            used("a", Ecosystem::Npm, "request", "2.88.2"),
            used("b", Ecosystem::Npm, "request", "2.88.2"),
        ];
        let out = run(list, &mut Cache::default(), Some(&fake), Options::default());
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].occurrences.len(), 2);
        let id = out.findings[0].advisory_id.as_deref().unwrap();
        assert_eq!(id, "fleetreach:deprecated:npm/request");
        assert!(out.gaps.is_empty());
        assert_eq!(
            fake.asked.lock().unwrap().len(),
            1,
            "asked once for two repos"
        );
    }

    #[test]
    fn no_answer_is_a_gap_never_clean() {
        let list = vec![used("a", Ecosystem::Npm, "request", "2.88.2")];
        let out = run(
            list.clone(),
            &mut Cache::default(),
            None,
            Options::default(),
        );
        assert!(out.findings.is_empty());
        assert_eq!(out.gaps.len(), 1);
        let mut failing = Fake::default();
        failing.failing.insert(REQUEST.to_string());
        let out = run(
            list.clone(),
            &mut Cache::default(),
            Some(&failing),
            Options::default(),
        );
        assert_eq!(out.gaps.len(), 1);
        assert!(out.notes[0].contains("HTTP 500"));
        let private = Fake::default();
        let out = run(
            list,
            &mut Cache::default(),
            Some(&private),
            Options::default(),
        );
        assert_eq!(out.gaps.len(), 1, "a package the registry does not know");
    }

    #[test]
    fn the_cache_answers_until_it_goes_stale_and_offline_after() {
        let list = vec![used("a", Ecosystem::Npm, "request", "2.88.2")];
        let fake = Fake::default().with(REQUEST, r#"{"deprecated":"no"}"#);
        let mut cache = Cache::default();
        let at = |now| Options {
            now,
            ..Options::default()
        };
        run(list.clone(), &mut cache, Some(&fake), at(1000));
        run(
            list.clone(),
            &mut cache,
            Some(&fake),
            at(1000 + FRESH_SECS - 1),
        );
        assert_eq!(fake.asked.lock().unwrap().len(), 1);
        run(list.clone(), &mut cache, Some(&fake), at(1000 + FRESH_SECS));
        assert_eq!(fake.asked.lock().unwrap().len(), 2);
        let out = run(list.clone(), &mut cache, None, at(1000 + 100 * FRESH_SECS));
        assert_eq!(out.findings.len(), 1);
        assert!(out.gaps.is_empty());
        // A failed refresh keeps the old finding and still reports the gap.
        let mut failing = Fake::default();
        failing.failing.insert(REQUEST.to_string());
        let out = run(
            list,
            &mut cache,
            Some(&failing),
            at(1000 + 100 * FRESH_SECS),
        );
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.gaps.len(), 1);
    }

    #[test]
    fn a_new_version_of_a_cached_package_is_asked_about() {
        let mut cache = Cache::default();
        let fake = Fake::default().with(REQUEST, r#"{}"#).with(
            "https://registry.npmjs.org/request/2.0.0",
            r#"{"deprecated":"x"}"#,
        );
        let first = vec![used("a", Ecosystem::Npm, "request", "2.88.2")];
        run(first, &mut cache, Some(&fake), Options::default());
        let second = vec![
            used("a", Ecosystem::Npm, "request", "2.88.2"),
            used("a", Ecosystem::Npm, "request", "2.0.0"),
        ];
        let out = run(second, &mut cache, Some(&fake), Options::default());
        assert_eq!(out.findings.len(), 1);
    }

    #[test]
    fn a_dev_package_keeps_its_scope_and_a_yank_its_version() {
        let mut one = used("a", Ecosystem::Pypi, "x", "1.0");
        one.dev = true;
        let doc = r#"{"info":{"yanked":true,"yanked_reason":null}}"#;
        let fake = Fake::default().with("https://pypi.org/pypi/x/1.0/json", doc);
        let out = run(
            vec![one],
            &mut Cache::default(),
            Some(&fake),
            Options::default(),
        );
        assert_eq!(out.findings[0].kind, WarnKind::Yanked);
        assert_eq!(
            out.findings[0].advisory_id.as_deref(),
            Some("fleetreach:yanked:pypi/x@1.0")
        );
        assert!(matches!(
            out.findings[0].occurrences[0],
            Occurrence::InRepo {
                scope: DepScope::Dev,
                ..
            }
        ));
    }

    #[test]
    fn repos_are_looked_up_for_archived_and_low_scorecard() {
        let version = r#"{"relatedProjects":[{"relationType":"ISSUE_TRACKER","projectKey":{"id":"github.com/z/z"}},
            {"relationType":"SOURCE_REPO","projectKey":{"id":"github.com/a/b"}}]}"#;
        let mut fake = Fake::default()
            .with(REQUEST, "{}")
            .with(
                "https://api.deps.dev/v3/systems/npm/packages/request/versions/2.88.2",
                version,
            )
            .with(
                "https://api.deps.dev/v3/projects/github.com%2Fa%2Fb",
                r#"{"scorecard":{"overallScore":2.5}}"#,
            )
            .with("https://api.github.com/repos/a/b", r#"{"archived":true}"#);
        fake.token = true;
        let options = Options {
            min_scorecard: Some(3.0),
            now: 0,
        };
        let list = vec![used("a", Ecosystem::Npm, "request", "2.88.2")];
        let out = run(list, &mut Cache::default(), Some(&fake), options);
        let ids: Vec<&str> = out
            .findings
            .iter()
            .filter_map(|f| f.advisory_id.as_deref())
            .collect();
        assert_eq!(
            ids,
            vec![
                "fleetreach:archived:npm/request",
                "fleetreach:low-scorecard:npm/request"
            ]
        );
    }

    #[test]
    fn julia_has_no_registry_to_ask_and_is_no_gap() {
        let list = vec![used("a", Ecosystem::Julia, "X", "1.0.0")];
        let fake = Fake::default();
        let out = run(list, &mut Cache::default(), Some(&fake), Options::default());
        assert!(out.gaps.is_empty());
        assert!(fake.asked.lock().unwrap().is_empty());
    }
}
