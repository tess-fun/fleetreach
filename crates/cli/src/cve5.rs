//! CVE 5.x records from the CVE Program's `cvelistV5` repository (spec 16, row 12).
//!
//! A CVE record carries what its CNA wrote within minutes of publication, often before OSV or
//! GHSA has reviewed it: the affected products with versions (`containers.cna.affected`), and
//! often a registry (`collectionURL` + `packageName`), a package URL or a repository. ADP
//! containers add enrichment later, CISA-ADP's CVSS and SSVC above all.
//!
//! Records are reduced to a compact [`CveSummary`] once, when they are synced or imported, and
//! the summaries are what the cross-source and quality checks read. A record's packages map
//! to an OSV ecosystem only from what the CNA wrote (a purl, or a registry URL and package
//! name); mapping through a repository URL needs the OSV records and is the cross-check's job.
//! Everything derived here is marked `unreviewed`: it is the CNA's claim, not a curated
//! advisory.

use std::collections::BTreeSet;
use std::io::{BufRead as _, Cursor, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One CVE, reduced to what the checks read.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CveSummary {
    pub id: String,
    /// `PUBLISHED` or `REJECTED`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigner: Option<String>,
    /// The CNA's best CVSS vector (v4.0, else v3.1, else v3.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cna_cvss: Option<String>,
    /// The first ADP container's CVSS vector, with that ADP's short name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adp_cvss: Option<(String, String)>,
    /// ADP providers that enriched the record (`CISA-ADP`, `CVE`, ...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub adp: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<CvePackage>,
}

/// One CNA `affected[]` entry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CvePackage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// The OSV ecosystem name (`PyPI`, `npm`, ...) when a purl or registry URL says so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    /// The package name in that ecosystem's spelling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The `repo` the CNA named, normalized (`github.com/owner/repo`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<CveRange>,
    /// Single affected versions (`= 1.2.3`, or a version with no range).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exact: Vec<String>,
}

/// One affected interval: `introduced` (absent = from the start) up to `fixed` (exclusive)
/// or `last_affected` (inclusive); neither = no fix known.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CveRange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduced: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_affected: Option<String>,
}

impl CvePackage {
    /// The `fixed` bounds of the CNA's ranges.
    pub fn fixes(&self) -> impl Iterator<Item = &str> {
        self.ranges.iter().filter_map(|r| r.fixed.as_deref())
    }
}

/// Reduce one CVE 5.x JSON record. `None` when it is not a CVE record at all.
#[must_use]
pub fn summarize(body: &str) -> Option<CveSummary> {
    let v: Value = serde_json::from_str(body).ok()?;
    let meta = v.get("cveMetadata")?;
    let id = meta.get("cveId")?.as_str()?.to_string();
    let text = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).map(str::to_string);
    let mut out = CveSummary {
        id,
        state: text(meta, "state").unwrap_or_default(),
        published: text(meta, "datePublished"),
        updated: text(meta, "dateUpdated"),
        assigner: text(meta, "assignerShortName"),
        ..CveSummary::default()
    };
    let Some(cna) = v.pointer("/containers/cna") else {
        return Some(out);
    };
    out.cna_cvss = best_cvss(cna);
    for adp in v
        .pointer("/containers/adp")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = adp
            .pointer("/providerMetadata/shortName")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        if out.adp_cvss.is_none() {
            out.adp_cvss = best_cvss(adp).map(|c| (name.clone(), c));
        }
        if !out.adp.contains(&name) {
            out.adp.push(name);
        }
    }
    let assigner_is_github = out.assigner.as_deref() == Some("GitHub_M");
    for affected in cna
        .get("affected")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        out.packages.push(package(affected, assigner_is_github));
    }
    Some(out)
}

fn best_cvss(container: &Value) -> Option<String> {
    let metrics = container.get("metrics")?.as_array()?;
    ["cvssV4_0", "cvssV3_1", "cvssV3_0"].iter().find_map(|key| {
        metrics.iter().find_map(|m| {
            m.get(*key)?
                .get("vectorString")?
                .as_str()
                .map(str::to_string)
        })
    })
}

fn package(affected: &Value, assigner_is_github: bool) -> CvePackage {
    let text = |key: &str| {
        affected
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty() && *s != "n/a")
            .map(str::to_string)
    };
    let mut pkg = CvePackage {
        vendor: text("vendor"),
        product: text("product"),
        ..CvePackage::default()
    };
    if let Some((eco, name)) = text("packageURL").as_deref().and_then(from_purl) {
        pkg.ecosystem = Some(eco.to_string());
        pkg.name = Some(name);
    } else if let Some(eco) = text("collectionURL").as_deref().and_then(registry) {
        let name = text("packageName").or_else(|| {
            text("collectionURL")
                .as_deref()
                .and_then(|u| name_from_registry_url(eco, u))
        });
        if let Some(name) = name {
            pkg.ecosystem = Some(eco.to_string());
            pkg.name = Some(normalize_name(eco, &name));
        }
    }
    pkg.repo = text("repo")
        .as_deref()
        .and_then(crate::osvrecords::repo_key)
        .or_else(|| {
            // GitHub's CNA writes the repository as vendor/product.
            assigner_is_github
                .then(|| {
                    Some(format!(
                        "github.com/{}/{}",
                        pkg.vendor.as_ref()?,
                        pkg.product.as_ref()?
                    ))
                })
                .flatten()
                .map(|r| r.to_ascii_lowercase())
        });
    let default_affected =
        affected.get("defaultStatus").and_then(Value::as_str) == Some("affected");
    for version in affected
        .get("versions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        add_version(&mut pkg, version, default_affected);
    }
    pkg
}

/// Words CNAs put where a version belongs.
fn placeholder(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "*" | "n/a" | "unspecified" | "unknown" | "all" | "-"
    )
}

fn add_version(pkg: &mut CvePackage, version: &Value, default_affected: bool) {
    let text = |key: &str| version.get(key).and_then(Value::as_str).map(str::trim);
    if matches!(text("versionType"), Some("git" | "original_commit_for_fix")) {
        return;
    }
    let Some(v) = text("version") else {
        return;
    };
    let status = text("status").unwrap_or("affected");
    // Some CNAs repeat the operator in the bound (`lessThan: "< 4.3.7"`).
    let bound = |key: &str| {
        text(key)
            .map(|s| s.trim_start_matches(['<', '=', ' ']))
            .filter(|s| !placeholder(s))
    };
    let less_than = bound("lessThan");
    let less_eq = bound("lessThanOrEqual");
    let introduced = (!placeholder(v)).then(|| v.to_string());
    match status {
        "affected" if less_than.is_some() || less_eq.is_some() => pkg.ranges.push(CveRange {
            introduced,
            fixed: less_than.map(str::to_string),
            last_affected: less_eq.map(str::to_string),
        }),
        "affected" if text("lessThan").is_some() || text("lessThanOrEqual").is_some() => {
            // `lessThan: "*"`: affected from `version` on, no fix known.
            pkg.ranges.push(CveRange {
                introduced,
                ..CveRange::default()
            });
        }
        "affected" => match parse_constraint(v) {
            Some(Constraint::Range(range)) => pkg.ranges.push(range),
            Some(Constraint::Exact(exact)) => pkg.exact.push(exact),
            None => {}
        },
        // `defaultStatus: affected` with an unaffected version and no range: fixed there.
        "unaffected" if default_affected && less_than.is_none() && less_eq.is_none() => {
            if let Some(fixed) = introduced {
                pkg.ranges.push(CveRange {
                    fixed: Some(fixed),
                    ..CveRange::default()
                });
            }
        }
        _ => {}
    }
}

enum Constraint {
    Range(CveRange),
    Exact(String),
}

/// GitHub's CNA writes constraints in the version string: `< 1.2.3`, `<= 1.2`, `>= 1.0, <
/// 1.2.3`, `= 1.2.3`. A bare version is one affected version.
fn parse_constraint(v: &str) -> Option<Constraint> {
    let v = v.trim();
    if placeholder(v) {
        return None;
    }
    if !v.starts_with(['<', '>', '=']) {
        return (!v.contains(' ')).then(|| Constraint::Exact(v.to_string()));
    }
    let mut range = CveRange::default();
    for part in v.split(',').map(str::trim) {
        let (op, ver) = part
            .find(|c: char| !matches!(c, '<' | '>' | '=' | ' '))
            .map(|i| (part[..i].trim(), part[i..].trim()))?;
        if ver.is_empty() || ver.contains(' ') {
            return None;
        }
        match op {
            "<" => range.fixed = Some(ver.to_string()),
            "<=" => range.last_affected = Some(ver.to_string()),
            ">=" => range.introduced = Some(ver.to_string()),
            "=" | "==" if !v.contains(',') => return Some(Constraint::Exact(ver.to_string())),
            _ => return None,
        }
    }
    Some(Constraint::Range(range))
}

/// The OSV ecosystem and name of a package URL.
#[must_use]
pub fn from_purl(purl: &str) -> Option<(&'static str, String)> {
    let rest = purl.strip_prefix("pkg:")?;
    let rest = rest.split(['@', '?', '#']).next()?;
    let (kind, path) = rest.split_once('/')?;
    let path = path.trim_matches('/');
    let eco = match kind.to_ascii_lowercase().as_str() {
        "npm" => "npm",
        "pypi" => "PyPI",
        "maven" => "Maven",
        "gem" => "RubyGems",
        "composer" => "Packagist",
        "nuget" => "NuGet",
        "golang" => "Go",
        "cargo" => "crates.io",
        "hex" => "Hex",
        "swift" => "SwiftURL",
        "pub" => "Pub",
        _ => return None,
    };
    let name = match eco {
        "Maven" => path.replacen('/', ":", 1),
        _ => path.replace("%40", "@"),
    };
    (!name.is_empty()).then(|| (eco, normalize_name(eco, &name)))
}

/// The OSV ecosystem of a package registry URL.
#[must_use]
pub fn registry(url: &str) -> Option<&'static str> {
    let host = url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()?
        .to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    Some(match host {
        "pypi.org" | "pypi.python.org" | "files.pythonhosted.org" => "PyPI",
        "npmjs.com" | "registry.npmjs.org" | "npmjs.org" => "npm",
        "repo.maven.apache.org"
        | "repo1.maven.org"
        | "central.sonatype.com"
        | "search.maven.org"
        | "mvnrepository.com" => "Maven",
        "packagist.org" | "repo.packagist.org" => "Packagist",
        "rubygems.org" => "RubyGems",
        "nuget.org" | "api.nuget.org" => "NuGet",
        "pkg.go.dev" | "proxy.golang.org" => "Go",
        "crates.io" => "crates.io",
        "hex.pm" => "Hex",
        _ => return None,
    })
}

/// A package name written into a registry URL (`pypi.org/project/Django/`).
fn name_from_registry_url(eco: &str, url: &str) -> Option<String> {
    let path: Vec<&str> = url
        .split("://")
        .nth(1)?
        .split('/')
        .skip(1)
        .filter(|s| !s.is_empty())
        .collect();
    let name = match (eco, path.as_slice()) {
        ("PyPI", ["project", name, ..]) => (*name).to_string(),
        ("npm", ["package", scope, name, ..]) if scope.starts_with('@') => {
            format!("{scope}/{name}")
        }
        ("npm", ["package", name, ..]) => (*name).to_string(),
        ("RubyGems", ["gems", name, ..]) => (*name).to_string(),
        ("NuGet", ["packages", name, ..]) => (*name).to_string(),
        ("Packagist", ["packages", vendor, name, ..]) => format!("{vendor}/{name}"),
        ("crates.io", ["crates", name, ..]) => (*name).to_string(),
        ("Hex", ["packages", name, ..]) => (*name).to_string(),
        _ => return None,
    };
    Some(name)
}

/// The spelling OSV uses for a package in `eco` (names compare in this form).
#[must_use]
pub fn normalize_name(eco: &str, name: &str) -> String {
    let name = name.trim();
    match eco {
        // PEP 503.
        "PyPI" => {
            let mut out = String::with_capacity(name.len());
            let mut sep = false;
            for c in name.chars() {
                if matches!(c, '-' | '_' | '.') {
                    sep = true;
                } else {
                    if sep && !out.is_empty() {
                        out.push('-');
                    }
                    sep = false;
                    out.push(c.to_ascii_lowercase());
                }
            }
            out
        }
        "Maven" if !name.contains(':') => name.replacen('/', ":", 1),
        "npm" | "Packagist" | "NuGet" | "RubyGems" | "crates.io" | "Hex" => {
            name.to_ascii_lowercase()
        }
        _ => name.to_string(),
    }
}

/// A version written the way CNAs and OSV differ least: no leading `v`, no Go
/// `+incompatible`, trailing `.0` components dropped (`v1.2.0` and `1.2` compare equal).
#[must_use]
pub fn normalize_version(v: &str) -> String {
    let v = v.trim();
    let v = v.strip_prefix(['v', 'V']).unwrap_or(v);
    // Go's marker for a pre-modules major version is not part of the release.
    let v = v.strip_suffix("+incompatible").unwrap_or(v);
    let mut parts: Vec<&str> = v.split('.').collect();
    while parts.len() > 1 && parts.last() == Some(&"0") {
        parts.pop();
    }
    parts.join(".")
}

// ---- Reading the repository and the compact index ----

/// Read every CVE record under `input`: a `cvelistV5` checkout (or its `cves/` directory), the
/// `cves.zip` inside a release, or the release's `*_all_CVEs_at_midnight.zip.zip` itself.
///
/// # Errors
///
/// An unreadable input or archive. A JSON file that is not a CVE record is counted in the
/// second value, never silently dropped.
pub fn read_all(input: &Path) -> Result<(Vec<CveSummary>, usize), String> {
    if input.is_dir() {
        let paths: Vec<PathBuf> = walkdir::WalkDir::new(input)
            .into_iter()
            .filter_entry(|e| e.depth() == 0 || !e.file_name().to_string_lossy().starts_with('.'))
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .map(walkdir::DirEntry::into_path)
            .filter(|p| is_record_name(&p.to_string_lossy()))
            .collect();
        let parsed: Vec<Option<CveSummary>> = paths
            .par_iter()
            .map(|p| {
                std::fs::read_to_string(p)
                    .map(|body| summarize(&body))
                    .map_err(|e| format!("reading {}: {e}", p.display()))
            })
            .collect::<Result<_, _>>()?;
        return Ok(split(parsed));
    }
    let bytes: Arc<[u8]> = std::fs::read(input)
        .map_err(|e| format!("reading {}: {e}", input.display()))?
        .into();
    let bytes = unwrap_nested(bytes).map_err(|e| format!("{}: {e}", input.display()))?;
    let archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| format!("{}: {e}", input.display()))?;
    let parsed: Vec<Option<CveSummary>> = (0..archive.len())
        .into_par_iter()
        .map_init(
            || archive.clone(),
            |archive, i| {
                let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
                let name = entry.name().map_err(|e| e.to_string())?.to_string();
                if !is_record_name(&name) {
                    return Ok(None);
                }
                let mut body = String::new();
                entry
                    .read_to_string(&mut body)
                    .map_err(|e| format!("{name}: {e}"))?;
                Ok(Some(summarize(&body)))
            },
        )
        .filter_map(Result::transpose)
        .collect::<Result<_, String>>()?;
    Ok(split(parsed))
}

fn is_record_name(name: &str) -> bool {
    let file = name.rsplit('/').next().unwrap_or(name);
    file.starts_with("CVE-") && file.ends_with(".json")
}

fn split(parsed: Vec<Option<CveSummary>>) -> (Vec<CveSummary>, usize) {
    let bad = parsed.iter().filter(|p| p.is_none()).count();
    let mut out: Vec<CveSummary> = parsed.into_iter().flatten().collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    (out, bad)
}

/// A release zip holds one entry, `cves.zip`: return that inner archive's bytes.
fn unwrap_nested(bytes: Arc<[u8]>) -> Result<Arc<[u8]>, String> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes.clone())).map_err(|e| e.to_string())?;
    if archive.len() != 1 {
        return Ok(bytes);
    }
    let mut entry = archive.by_index(0).map_err(|e| e.to_string())?;
    if !entry.name().map_err(|e| e.to_string())?.ends_with(".zip") {
        return Ok(bytes);
    }
    let mut inner = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
    entry.read_to_end(&mut inner).map_err(|e| e.to_string())?;
    Ok(inner.into())
}

/// The index file a sync or import writes (`<dir>/cvelistV5/index.jsonl.gz`).
#[must_use]
pub fn index_path(root: &Path) -> PathBuf {
    root.join(CVE_DIR).join("index.jsonl.gz")
}

/// The directory under an OSV directory that holds the CVE index.
pub const CVE_DIR: &str = "cvelistV5";

/// Write summaries as gzipped JSON lines, atomically (temp file, then rename).
///
/// # Errors
///
/// Any write failure; the previous index stays in place.
pub fn write_index(path: &Path, summaries: &[CveSummary]) -> Result<(), String> {
    write_jsonl_gz(path, summaries)
}

/// Read the compact index.
///
/// # Errors
///
/// A missing or corrupt index: fail closed.
pub fn read_index(path: &Path) -> Result<Vec<CveSummary>, String> {
    read_jsonl_gz(path)
}

pub(crate) fn write_jsonl_gz<T: Serialize>(path: &Path, items: &[T]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        crate::osvdb::create_private_dir(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let tmp = path.with_extension("partial");
    let result = (|| {
        let file = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        let mut gz = flate2::write::GzEncoder::new(
            std::io::BufWriter::new(file),
            flate2::Compression::default(),
        );
        for item in items {
            serde_json::to_writer(&mut gz, item).map_err(|e| e.to_string())?;
            gz.write_all(b"\n").map_err(|e| e.to_string())?;
        }
        let mut buf = gz.finish().map_err(|e| e.to_string())?;
        buf.flush().map_err(|e| e.to_string())?;
        buf.get_ref().sync_all().map_err(|e| e.to_string())
    })();
    match result {
        Ok(()) => {
            std::fs::rename(&tmp, path).map_err(|e| format!("installing {}: {e}", path.display()))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(format!("writing {}: {e}", tmp.display()))
        }
    }
}

/// Stream a gzipped JSON-lines index, one item at a time. The first error ends the stream and
/// is left in `error`.
pub(crate) fn stream_jsonl_gz<'a, T: for<'de> Deserialize<'de> + 'a>(
    path: &'a Path,
    error: &'a std::cell::RefCell<Option<String>>,
) -> Result<impl Iterator<Item = T> + 'a, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let reader = std::io::BufReader::new(flate2::read::GzDecoder::new(file));
    Ok(reader.lines().enumerate().map_while(move |(n, line)| {
        let item = line
            .map_err(|e| format!("{}: {e}", path.display()))
            .and_then(|l| {
                serde_json::from_str(&l).map_err(|e| format!("{}:{}: {e}", path.display(), n + 1))
            });
        match item {
            Ok(item) => Some(item),
            Err(e) => {
                *error.borrow_mut() = Some(e);
                None
            }
        }
    }))
}

pub(crate) fn read_jsonl_gz<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Vec<T>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let reader = std::io::BufReader::new(flate2::read::GzDecoder::new(file));
    reader
        .lines()
        .enumerate()
        .map(|(n, line)| {
            let line = line.map_err(|e| format!("{}: {e}", path.display()))?;
            serde_json::from_str(&line).map_err(|e| format!("{}:{}: {e}", path.display(), n + 1))
        })
        .collect()
}

/// The ecosystems the CNA data mapped, for reporting.
#[must_use]
pub fn mapped_ecosystems(summaries: &[CveSummary]) -> BTreeSet<String> {
    summaries
        .iter()
        .flat_map(|s| &s.packages)
        .filter_map(|p| p.ecosystem.clone())
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const GITHUB: &str = r#"{"dataType":"CVE_RECORD","cveMetadata":{"cveId":"CVE-2025-50181",
      "state":"PUBLISHED","assignerShortName":"GitHub_M","datePublished":"2025-06-19T01:02:03Z"},
      "containers":{"cna":{"affected":[{"vendor":"urllib3","product":"urllib3",
        "versions":[{"version":">= 2.2.0, < 2.5.0","status":"affected"},
                    {"version":"= 1.26.0","status":"affected"}]}],
        "metrics":[{"cvssV3_1":{"vectorString":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"}}]},
       "adp":[{"providerMetadata":{"shortName":"CISA-ADP"},"metrics":[{"other":{"type":"ssvc"}}]}]}}"#;

    #[test]
    fn github_cna_constraints_and_repo() {
        let s = summarize(GITHUB).unwrap();
        assert_eq!(s.id, "CVE-2025-50181");
        assert_eq!(s.adp, ["CISA-ADP"]);
        assert!(s.adp_cvss.is_none());
        assert!(s.cna_cvss.as_deref().unwrap().starts_with("CVSS:3.1"));
        let p = &s.packages[0];
        assert_eq!(p.repo.as_deref(), Some("github.com/urllib3/urllib3"));
        assert_eq!(p.ecosystem, None);
        assert_eq!(
            p.ranges,
            [CveRange {
                introduced: Some("2.2.0".into()),
                fixed: Some("2.5.0".into()),
                last_affected: None
            }]
        );
        assert_eq!(p.exact, ["1.26.0"]);
    }

    #[test]
    fn registry_and_purl_mapping() {
        let body = r#"{"cveMetadata":{"cveId":"CVE-2025-1","state":"PUBLISHED"},
          "containers":{"cna":{"affected":[
            {"vendor":"x","product":"Django","collectionURL":"https://pypi.org/project/Django/",
             "defaultStatus":"affected",
             "versions":[{"version":"5.0","lessThan":"5.0.14","status":"affected","versionType":"semver"},
                         {"version":"5.1.8","status":"unaffected"},
                         {"version":"abc123","status":"affected","versionType":"git","lessThan":"def"}]},
            {"vendor":"y","product":"z","packageURL":"pkg:maven/org.example/lib@1.0",
             "versions":[{"version":"0","lessThanOrEqual":"1.4","status":"affected"},
                         {"version":"2.0","lessThan":"*","status":"affected"},
                         {"version":"3.0","lessThan":"< 3.1","status":"affected"}]},
            {"vendor":"w","product":"w","collectionURL":"https://registry.npmjs.org",
             "packageName":"@Scope/Pkg","versions":[{"version":"n/a","status":"affected"}]}]}}}"#;
        let s = summarize(body).unwrap();
        let [django, lib, npm] = s.packages.as_slice() else {
            panic!("three packages")
        };
        assert_eq!(django.ecosystem.as_deref(), Some("PyPI"));
        assert_eq!(django.name.as_deref(), Some("django"));
        assert_eq!(django.fixes().collect::<Vec<_>>(), ["5.0.14", "5.1.8"]);
        assert_eq!(lib.ecosystem.as_deref(), Some("Maven"));
        assert_eq!(lib.name.as_deref(), Some("org.example:lib"));
        assert_eq!(lib.ranges[0].last_affected.as_deref(), Some("1.4"));
        assert_eq!(lib.ranges[0].introduced, None);
        assert_eq!(lib.ranges[1].introduced.as_deref(), Some("2.0"));
        assert_eq!(lib.ranges[1].fixed, None);
        assert_eq!(lib.ranges[2].fixed.as_deref(), Some("3.1"));
        assert_eq!(npm.name.as_deref(), Some("@scope/pkg"));
        assert!(npm.ranges.is_empty() && npm.exact.is_empty());
    }

    #[test]
    fn names_and_versions_normalize() {
        assert_eq!(normalize_name("PyPI", "Foo_Bar.baz"), "foo-bar-baz");
        assert_eq!(normalize_name("Maven", "org.a/b"), "org.a:b");
        assert_eq!(normalize_version("v1.2.0"), "1.2");
        assert_eq!(normalize_version("1.0"), "1");
        assert_eq!(normalize_version("0"), "0");
        assert_eq!(normalize_version("3.2.0+incompatible"), "3.2");
        assert_eq!(
            from_purl("pkg:npm/%40babel/core@7").unwrap(),
            ("npm", "@babel/core".into())
        );
        assert_eq!(
            registry("https://repo1.maven.org/maven2/org/bouncycastle"),
            Some("Maven")
        );
        assert_eq!(registry("https://wordpress.org/plugins"), None);
    }

    #[test]
    fn rejected_and_non_records() {
        let s = summarize(
            r#"{"cveMetadata":{"cveId":"CVE-2020-9","state":"REJECTED"},"containers":{}}"#,
        )
        .unwrap();
        assert_eq!(s.state, "REJECTED");
        assert!(summarize(r#"{"hello":1}"#).is_none());
        assert!(summarize("not json").is_none());
    }

    #[test]
    fn index_round_trips() {
        let dir = std::env::temp_dir().join(format!("fr-cve-index-{}", std::process::id()));
        let path = index_path(&dir);
        let s = vec![summarize(GITHUB).unwrap()];
        write_index(&path, &s).unwrap();
        assert_eq!(read_index(&path).unwrap(), s);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
