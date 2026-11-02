//! Whole OSV records as published, for the data-quality and cross-source checks (spec 16,
//! row 12). The feeders keep only what matching needs; these checks also need the dates,
//! references and raw range events, so they read the exports again with a wider schema.

use std::collections::BTreeMap;
use std::io::{Cursor, Read as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rayon::prelude::*;
use serde::Deserialize;

/// One OSV record with the fields the checks read.
#[derive(Debug, Clone, Deserialize)]
pub struct Record {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// The upstream ids a record derives from (OSV 1.7; Red Hat's records list their CVEs here).
    #[serde(default)]
    pub upstream: Vec<String>,
    pub published: Option<String>,
    pub modified: Option<String>,
    pub withdrawn: Option<String>,
    #[serde(default)]
    pub severity: Vec<Severity>,
    #[serde(default)]
    pub affected: Vec<Affected>,
    #[serde(default)]
    pub references: Vec<Reference>,
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Severity {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub score: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Affected {
    #[serde(default)]
    pub package: Package,
    #[serde(default)]
    pub ranges: Vec<Range>,
    #[serde(default)]
    pub versions: Vec<String>,
    pub database_specific: Option<serde_json::Value>,
    pub ecosystem_specific: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Package {
    pub ecosystem: Option<String>,
    pub name: Option<String>,
    pub purl: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Range {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub repo: Option<String>,
    #[serde(default)]
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
    pub limit: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Reference {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub url: Option<String>,
}

impl Record {
    /// Whether the record carries any severity: a `severity[]` vector or a GHSA band.
    #[must_use]
    pub fn has_severity(&self) -> bool {
        self.severity.iter().any(|s| s.score.is_some())
            || self
                .database_specific
                .as_ref()
                .and_then(|d| d.get("severity"))
                .and_then(|s| s.as_str())
                .is_some_and(|s| !s.is_empty())
    }

    /// The CVE ids among the record's id, aliases and upstream ids.
    pub fn cves(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.id.as_str())
            .chain(self.aliases.iter().map(String::as_str))
            .chain(self.upstream.iter().map(String::as_str))
            .filter(|a| a.starts_with("CVE-"))
    }

    /// Every `fixed` bound of the record's ranges for `(ecosystem, name)`.
    pub fn fixes_for<'a>(
        &'a self,
        ecosystem: &'a str,
        name: &'a str,
    ) -> impl Iterator<Item = &'a str> {
        self.affected
            .iter()
            .filter(move |a| {
                a.package.ecosystem.as_deref() == Some(ecosystem)
                    && a.package.name.as_deref() == Some(name)
            })
            .flat_map(|a| &a.ranges)
            .filter(|r| r.kind.as_deref() != Some("GIT"))
            .flat_map(|r| &r.events)
            .filter_map(|e| e.fixed.as_deref())
    }
}

/// Every record in an OSV directory laid out like the osv.dev bucket, keyed by id (an
/// advisory that names several ecosystems appears in each export, once here), plus the
/// export each was first read from. `exports` restricts which `<dir>/<Name>/` to read.
///
/// # Errors
///
/// An unreadable export or a record that is not valid JSON: the checks fail closed.
pub fn load_dir(
    dir: &Path,
    exports: Option<&[&str]>,
) -> Result<BTreeMap<String, (String, Record)>, String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| format!("reading {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.'))
        .filter(|n| exports.is_none_or(|x| x.contains(&n.as_str())))
        .collect();
    names.sort();
    let mut out: BTreeMap<String, (String, Record)> = BTreeMap::new();
    for name in names {
        let eco_dir = dir.join(&name);
        let zip = eco_dir.join("all.zip");
        let records = if zip.is_file() {
            load_zip(&zip)?
        } else {
            load_json_dir(&eco_dir)?
        };
        for record in records {
            out.entry(record.id.clone())
                .or_insert_with(|| (name.clone(), record));
        }
    }
    Ok(out)
}

fn load_zip(path: &Path) -> Result<Vec<Record>, String> {
    let bytes: Arc<[u8]> = std::fs::read(path)
        .map_err(|e| format!("reading {}: {e}", path.display()))?
        .into();
    let archive =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| format!("{}: {e}", path.display()))?;
    (0..archive.len())
        .into_par_iter()
        .map_init(
            || archive.clone(),
            |archive, i| {
                let mut entry = archive
                    .by_index(i)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                let name = entry.name().map_err(|e| e.to_string())?.to_string();
                if !name.ends_with(".json") {
                    return Ok(None);
                }
                let mut body = String::new();
                entry
                    .read_to_string(&mut body)
                    .map_err(|e| format!("{}: {name}: {e}", path.display()))?;
                serde_json::from_str(&body)
                    .map(Some)
                    .map_err(|e| format!("{}: {name}: {e}", path.display()))
            },
        )
        .filter_map(Result::transpose)
        .collect()
}

fn load_json_dir(dir: &Path) -> Result<Vec<Record>, String> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("reading {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
        .filter(|p| !p.to_string_lossy().ends_with(".meta.json"))
        .collect();
    paths.sort();
    paths
        .par_iter()
        .map(|p| {
            let body =
                std::fs::read_to_string(p).map_err(|e| format!("reading {}: {e}", p.display()))?;
            serde_json::from_str(&body).map_err(|e| format!("{}: {e}", p.display()))
        })
        .collect()
}

/// Normalize a repository URL for comparison: lowercase host and path, no scheme, no
/// trailing `.git` or `/`, `www.` dropped. Only `github.com`, `gitlab.com` and `bitbucket.org`
/// repository roots (`host/owner/repo`) are kept; anything else is `None`.
#[must_use]
pub fn repo_key(url: &str) -> Option<String> {
    let rest = url
        .trim()
        .strip_prefix("https://")
        .or_else(|| url.trim().strip_prefix("http://"))
        .or_else(|| url.trim().strip_prefix("git+https://"))
        .or_else(|| url.trim().strip_prefix("git://"))?;
    let rest = rest.strip_prefix("www.").unwrap_or(rest);
    let mut parts = rest.split(['/', '#', '?']).filter(|p| !p.is_empty());
    let host = parts.next()?.to_ascii_lowercase();
    if !matches!(host.as_str(), "github.com" | "gitlab.com" | "bitbucket.org") {
        return None;
    }
    let owner = parts.next()?.to_ascii_lowercase();
    let repo = parts.next()?.to_ascii_lowercase();
    let repo = repo.strip_suffix(".git").unwrap_or(&repo);
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(format!("{host}/{owner}/{repo}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn repo_keys_normalize() {
        assert_eq!(
            repo_key("https://github.com/Pallets/Flask.git").as_deref(),
            Some("github.com/pallets/flask")
        );
        assert_eq!(
            repo_key("https://github.com/pallets/flask/security/advisories/GHSA-x").as_deref(),
            Some("github.com/pallets/flask")
        );
        assert_eq!(repo_key("https://github.com/pallets"), None);
        assert_eq!(repo_key("https://example.com/a/b"), None);
    }

    #[test]
    fn severity_and_fixes() {
        let r: Record = serde_json::from_str(
            r#"{"id":"GHSA-1","aliases":["CVE-2024-1"],"database_specific":{"severity":"HIGH"},
            "affected":[{"package":{"ecosystem":"npm","name":"a"},"ranges":[{"type":"SEMVER",
            "events":[{"introduced":"0"},{"fixed":"1.2.3"}]},{"type":"GIT","repo":"x",
            "events":[{"introduced":"0"},{"fixed":"abc"}]}]}]}"#,
        )
        .unwrap();
        assert!(r.has_severity());
        assert_eq!(r.cves().collect::<Vec<_>>(), ["CVE-2024-1"]);
        assert_eq!(r.fixes_for("npm", "a").collect::<Vec<_>>(), ["1.2.3"]);
    }
}
