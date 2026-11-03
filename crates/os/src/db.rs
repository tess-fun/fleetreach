//! The distro advisory DB: osv.dev distro exports (`Debian:12/all.zip`, `Wolfi/all.zip`,
//! ...) loaded once and indexed by `(ecosystem, source package)`.
//!
//! One export holds records for many ecosystems (a `Debian:12` record also lists Debian 11
//! and 13), so only the affected entries of the ecosystems a fleet's images run are kept, and
//! only for the source packages those images install. The zip is read from disk entry by
//! entry rather than into memory, because the Chainguard export alone is 1.1 GB.
//!
//! Unfixed records are kept: a Debian or Ubuntu entry with no `fixed` event is "affected,
//! no fix yet" and becomes a finding, with its urgency (Debian) or priority (Ubuntu).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Event, ParsedRange, Range};
use fleetreach_core::Severity;
use rayon::prelude::*;
use serde::Deserialize;

use crate::apkver::ApkVersion;
use crate::distro::Family;
use crate::dpkgver::DebVersion;
use crate::error::OsError;
use crate::rpmver::RpmVersion;

/// One advisory's facts for one source package in one ecosystem.
#[derive(Debug, Clone)]
pub struct Advisory<V> {
    pub id: String,
    /// Other ids for the same issue; always includes the CVE id when the record names one,
    /// so KEV, EPSS and NVD enrichment work on distro records too.
    pub aliases: Vec<String>,
    pub title: String,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub cvss_vector: Option<String>,
    /// Debian's `urgency` or Ubuntu's `ubuntu_priority`, verbatim, or a vendor's status for
    /// an unfixed issue (`will not fix`).
    pub urgency: Option<String>,
    /// The module stream (`nodejs:18`) whose builds this is about; only packages from that
    /// stream match.
    pub module: Option<String>,
    /// The vendor's page for an advisory from a vendor feed (an ALAS or ELSA id has no
    /// osv.dev record to link to).
    pub url: Option<String>,
    pub ranges: Vec<ParsedRange<V>>,
    /// Enumerated affected versions, sorted.
    pub versions: Vec<V>,
}

impl<V> Advisory<V> {
    /// Whether the distro rates this as not worth fixing: Debian `unimportant`, Ubuntu
    /// `negligible`.
    pub fn unimportant(&self) -> bool {
        matches!(self.urgency.as_deref(), Some("unimportant" | "negligible"))
    }

    /// The ids this advisory is known by (its own and its aliases).
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.id.as_str()).chain(self.aliases.iter().map(String::as_str))
    }
}

type Index<V> = BTreeMap<(String, String), Vec<Advisory<V>>>;

/// The loaded distro advisories.
#[derive(Debug, Default)]
pub struct DistroDb {
    deb: Index<DebVersion>,
    apk: Index<ApkVersion>,
    rpm: Index<RpmVersion>,
    /// Affected entries seen per wanted ecosystem, before the package filter: zero means
    /// osv.dev knows no such release, which the scan reports as a coverage gap.
    records: BTreeMap<String, usize>,
}

impl DistroDb {
    /// The advisories for `package` (a source name) in Debian-family `ecosystem`.
    pub fn deb(&self, ecosystem: &str, package: &str) -> &[Advisory<DebVersion>] {
        self.deb
            .get(&(ecosystem.to_string(), package.to_string()))
            .map_or(&[], Vec::as_slice)
    }

    /// The advisories for `package` (an origin name) in apk-family `ecosystem`.
    pub fn apk(&self, ecosystem: &str, package: &str) -> &[Advisory<ApkVersion>] {
        self.apk
            .get(&(ecosystem.to_string(), package.to_string()))
            .map_or(&[], Vec::as_slice)
    }

    /// The advisories for `package` (a source or, for Red Hat and AlmaLinux, a binary name)
    /// in rpm-family `ecosystem`.
    pub fn rpm(&self, ecosystem: &str, package: &str) -> &[Advisory<RpmVersion>] {
        self.rpm
            .get(&(ecosystem.to_string(), package.to_string()))
            .map_or(&[], Vec::as_slice)
    }

    /// How many affected entries the exports hold for `ecosystem`.
    pub fn records(&self, ecosystem: &str) -> usize {
        self.records.get(ecosystem).copied().unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn insert_apk(&mut self, ecosystem: &str, package: &str, adv: Advisory<ApkVersion>) {
        *self.records.entry(ecosystem.to_string()).or_default() += 1;
        self.apk
            .entry((ecosystem.to_string(), package.to_string()))
            .or_default()
            .push(adv);
    }

    #[cfg(test)]
    pub(crate) fn insert_rpm(&mut self, ecosystem: &str, package: &str, adv: Advisory<RpmVersion>) {
        *self.records.entry(ecosystem.to_string()).or_default() += 1;
        self.rpm
            .entry((ecosystem.to_string(), package.to_string()))
            .or_default()
            .push(adv);
    }

    /// Total indexed advisory entries, for diagnostics.
    pub fn len(&self) -> usize {
        self.deb.values().map(Vec::len).sum::<usize>()
            + self.apk.values().map(Vec::len).sum::<usize>()
            + self.rpm.values().map(Vec::len).sum::<usize>()
    }

    /// Whether nothing was indexed.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---- Wire schema: what the distro records carry beyond the shared OSV fields ----

#[derive(Deserialize)]
struct Record {
    id: String,
    #[serde(default)]
    references: Vec<Reference>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    upstream: Vec<String>,
    #[serde(default)]
    related: Vec<String>,
    summary: Option<String>,
    details: Option<String>,
    withdrawn: Option<String>,
    #[serde(default)]
    affected: Vec<Affected>,
    #[serde(default)]
    severity: Vec<osv::SeverityEntry>,
    database_specific: Option<osv::DatabaseSpecific>,
}

#[derive(Deserialize)]
struct Affected {
    package: Option<Package>,
    #[serde(default)]
    ranges: Vec<osv::RawRange>,
    #[serde(default)]
    versions: Vec<String>,
    ecosystem_specific: Option<EcosystemSpecific>,
}

#[derive(Deserialize)]
struct Reference {
    #[serde(rename = "type")]
    kind: Option<String>,
    url: Option<String>,
}

#[derive(Deserialize)]
struct Package {
    name: Option<String>,
    ecosystem: Option<String>,
}

#[derive(Deserialize)]
struct EcosystemSpecific {
    urgency: Option<String>,
    ubuntu_priority: Option<String>,
    status: Option<String>,
    module: Option<String>,
}

/// Which ecosystems to keep, with their family, and (optionally) which source packages.
#[derive(Debug, Clone, Default)]
pub struct Wanted {
    pub ecosystems: BTreeMap<String, Family>,
    /// Source package names to keep; `None` keeps every package.
    pub packages: Option<BTreeSet<String>>,
}

fn title(r: &Record) -> String {
    if let Some(s) = r
        .summary
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return s.to_string();
    }
    if let Some(d) = r
        .details
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let first = d.lines().next().unwrap_or(d);
        let sentence = first.split(". ").next().unwrap_or(first);
        let mut out: String = sentence.chars().take(120).collect();
        if sentence.chars().count() > 120 {
            out.push('…');
        }
        return out;
    }
    r.id.clone()
}

fn aliases(r: &Record) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    out.extend(r.aliases.iter().cloned());
    out.extend(r.upstream.iter().cloned());
    out.extend(r.related.iter().filter(|a| a.starts_with("CVE-")).cloned());
    if r.id.starts_with("CVE-") {
        out.insert(r.id.clone());
    }
    // Ubuntu writes `UBUNTU-CVE-2024-1234` and Debian `DEBIAN-CVE-...`: the CVE is in the id.
    if let Some(cve) = r.id.find("CVE-").map(|i| &r.id[i..]) {
        out.insert(cve.to_string());
    }
    out.into_iter().collect()
}

/// The Debian/Ubuntu urgency as a severity band, for records with no CVSS of their own.
fn band_from_urgency(u: &str) -> Severity {
    match u {
        "low" | "unimportant" | "negligible" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Unknown,
    }
}

fn ranges_of<V>(a: &Affected, parse: fn(&str) -> Option<V>) -> Vec<ParsedRange<V>> {
    a.ranges
        .iter()
        .map(|r| {
            let range = Range {
                matchable: r.kind.as_deref() == Some("ECOSYSTEM"),
                events: r
                    .events
                    .iter()
                    .map(|e| Event {
                        introduced: e.introduced.clone(),
                        fixed: e.fixed.clone(),
                        last_affected: e.last_affected.clone(),
                    })
                    .collect(),
            };
            osv::parse_range(&range, parse)
        })
        .collect()
}

/// The advisories one record contributes, plus a count of affected entries per wanted
/// ecosystem.
enum Entry {
    Deb((String, String), Advisory<DebVersion>),
    Apk((String, String), Advisory<ApkVersion>),
    Rpm((String, String), Advisory<RpmVersion>),
}

fn entries_of(mut r: Record, wanted: &Wanted) -> (Vec<Entry>, BTreeMap<String, usize>) {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut out = Vec::new();
    if r.withdrawn.is_some() {
        return (out, counts);
    }
    let shared = osv::OsvRecord {
        id: r.id.clone(),
        aliases: None,
        summary: None,
        withdrawn: None,
        affected: Vec::new(),
        severity: std::mem::take(&mut r.severity),
        database_specific: r.database_specific.take(),
    };
    let (severity, cvss_score) = osv::default_severity(&shared);
    let cvss_vector = osv::cvss_vector_of(&shared);
    let title = title(&r);
    let aliases = aliases(&r);
    for a in &r.affected {
        let Some(pkg) = &a.package else { continue };
        let (Some(name), Some(eco)) = (pkg.name.as_deref(), pkg.ecosystem.as_deref()) else {
            continue;
        };
        let Some(&family) = wanted.ecosystems.get(eco) else {
            continue;
        };
        *counts.entry(eco.to_string()).or_default() += 1;
        if wanted.packages.as_ref().is_some_and(|p| !p.contains(name)) {
            continue;
        }
        let urgency = a.ecosystem_specific.as_ref().and_then(|e| {
            e.urgency
                .clone()
                .or_else(|| e.ubuntu_priority.clone())
                .or_else(|| e.status.clone())
        });
        let severity = if severity == Severity::Unknown {
            urgency
                .as_deref()
                .map_or(Severity::Unknown, band_from_urgency)
        } else {
            severity
        };
        let key = (eco.to_string(), name.to_string());
        macro_rules! advisory {
            ($parse:expr) => {{
                let mut versions: Vec<_> = a.versions.iter().filter_map(|v| $parse(v)).collect();
                versions.sort();
                versions.dedup();
                Advisory {
                    id: r.id.clone(),
                    aliases: aliases.clone(),
                    title: title.clone(),
                    severity,
                    cvss_score,
                    cvss_vector: cvss_vector.clone(),
                    urgency: urgency.clone(),
                    module: a.ecosystem_specific.as_ref().and_then(|e| e.module.clone()),
                    url: (crate::feeds::feed_for(eco).is_some() || crate::distro::is_vex(eco))
                        .then_some(&r.references)
                        .and_then(|refs| {
                            refs.iter().find(|x| x.kind.as_deref() == Some("ADVISORY"))
                        })
                        .and_then(|x| x.url.clone())
                        .filter(|u| u.starts_with("https://")),
                    ranges: ranges_of(a, $parse),
                    versions,
                }
            }};
        }
        out.push(match family {
            Family::Deb => Entry::Deb(key, advisory!(DebVersion::parse)),
            Family::Apk => Entry::Apk(key, advisory!(ApkVersion::parse)),
            Family::Rpm => Entry::Rpm(key, advisory!(RpmVersion::parse)),
        });
    }
    (out, counts)
}

/// Load the exports at `paths` (each an `all.zip` or a directory of records), keeping what
/// `wanted` selects.
///
/// # Errors
///
/// [`OsError::Db`] when an export cannot be read or holds a record that is not valid JSON:
/// a broken mirror fails closed.
pub fn load(paths: &[PathBuf], wanted: &Wanted) -> Result<DistroDb, OsError> {
    let mut db = DistroDb::default();
    for eco in wanted.ecosystems.keys() {
        db.records.insert(eco.clone(), 0);
    }
    for path in paths {
        let per_record = if path.is_dir() {
            load_dir(path, wanted)?
        } else {
            load_zip(path, wanted)?
        };
        for (entries, counts) in per_record {
            for (eco, n) in counts {
                *db.records.entry(eco).or_default() += n;
            }
            for e in entries {
                match e {
                    Entry::Deb(k, a) => db.deb.entry(k).or_default().push(a),
                    Entry::Apk(k, a) => db.apk.entry(k).or_default().push(a),
                    Entry::Rpm(k, a) => db.rpm.entry(k).or_default().push(a),
                }
            }
        }
    }
    Ok(db)
}

type PerRecord = Vec<(Vec<Entry>, BTreeMap<String, usize>)>;

fn parse_record(
    body: &[u8],
    wanted: &Wanted,
    path: &Path,
) -> Result<(Vec<Entry>, BTreeMap<String, usize>), OsError> {
    let r: Record = serde_json::from_slice(body).map_err(|e| OsError::db(path, e))?;
    Ok(entries_of(r, wanted))
}

fn load_dir(root: &Path, wanted: &Wanted) -> Result<PerRecord, OsError> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(root)
        .map_err(|e| OsError::db(root, e))?
        .map(|e| e.map(|e| e.path()).map_err(|e| OsError::db(root, e)))
        .collect::<Result<_, _>>()?;
    paths.retain(|p| {
        p.extension().and_then(|e| e.to_str()) == Some("json")
            && !p.to_string_lossy().ends_with(".meta.json")
    });
    paths.sort();
    paths
        .par_iter()
        .map(|p| {
            let body = std::fs::read(p).map_err(|e| OsError::db(p, e))?;
            parse_record(&body, wanted, p)
        })
        .collect()
}

fn load_zip(path: &Path, wanted: &Wanted) -> Result<PerRecord, OsError> {
    let open = || -> Result<zip::ZipArchive<std::io::BufReader<std::fs::File>>, OsError> {
        let f = std::fs::File::open(path).map_err(|e| OsError::db(path, e))?;
        zip::ZipArchive::new(std::io::BufReader::new(f)).map_err(|e| OsError::db(path, e))
    };
    let count = open()?.len();
    // One archive handle per worker, each reading its own entries from disk.
    let chunks: Vec<(usize, usize)> = {
        let size = 2048;
        (0..count.div_ceil(size))
            .map(|i| (i * size, ((i + 1) * size).min(count)))
            .collect()
    };
    let per_chunk: Vec<PerRecord> = chunks
        .par_iter()
        .map(|&(from, to)| {
            let mut archive = open()?;
            let mut out = Vec::with_capacity(to - from);
            let mut body = Vec::new();
            for i in from..to {
                let mut entry = archive.by_index(i).map_err(|e| OsError::db(path, e))?;
                if !entry
                    .name()
                    .map_err(|e| OsError::db(path, e))?
                    .ends_with(".json")
                {
                    continue;
                }
                body.clear();
                entry
                    .read_to_end(&mut body)
                    .map_err(|e| OsError::db(path, e))?;
                out.push(parse_record(&body, wanted, path)?);
            }
            Ok(out)
        })
        .collect::<Result<_, OsError>>()?;
    Ok(per_chunk.into_iter().flatten().collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn wanted() -> Wanted {
        let mut w = Wanted::default();
        w.ecosystems.insert("Debian:12".into(), Family::Deb);
        w.ecosystems.insert("Alpine:v3.20".into(), Family::Apk);
        w
    }

    #[test]
    fn debian_unfixed_record_keeps_urgency_and_cve() {
        let json = br#"{"id":"CVE-2002-1976","details":"ifconfig does not report promiscuous mode. More text.",
          "affected":[
            {"package":{"name":"net-tools","ecosystem":"Debian:11"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]},
            {"package":{"name":"net-tools","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}],
             "versions":["2.10-0.1"],"ecosystem_specific":{"urgency":"unimportant"}}]}"#;
        let (entries, counts) = parse_record(json, &wanted(), Path::new("x")).unwrap();
        assert_eq!(counts.get("Debian:12"), Some(&1));
        assert!(
            !counts.contains_key("Debian:11"),
            "unwanted ecosystems are not counted"
        );
        let [Entry::Deb(key, adv)] = entries.as_slice() else {
            unreachable!("one Debian 12 entry")
        };
        assert_eq!(key, &("Debian:12".to_string(), "net-tools".to_string()));
        assert!(adv.unimportant());
        assert_eq!(adv.severity, Severity::Low);
        assert_eq!(adv.aliases, vec!["CVE-2002-1976"]);
        assert_eq!(adv.title, "ifconfig does not report promiscuous mode");
        assert_eq!(adv.versions.len(), 1);
    }

    #[test]
    fn withdrawn_records_and_upstream_ids() {
        let w = br#"{"id":"CGA-x","withdrawn":"2024-01-01T00:00:00Z","affected":[{"package":{"name":"a","ecosystem":"Alpine:v3.20"}}]}"#;
        assert!(parse_record(w, &wanted(), Path::new("x"))
            .unwrap()
            .0
            .is_empty());
        let u = br#"{"id":"UBUNTU-CVE-2024-1","upstream":["GHSA-1"],"related":["USN-1","CVE-2024-1"],
          "affected":[{"package":{"name":"musl","ecosystem":"Alpine:v3.20"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.5-r1"}]}]}]}"#;
        let (entries, _) = parse_record(u, &wanted(), Path::new("x")).unwrap();
        let [Entry::Apk(_, adv)] = entries.as_slice() else {
            unreachable!("one Alpine entry")
        };
        assert_eq!(adv.aliases, vec!["CVE-2024-1", "GHSA-1"]);
    }
}
