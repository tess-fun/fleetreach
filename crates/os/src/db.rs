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

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use fleetreach_core::osv::{self, Event, ParsedBound, ParsedRange, Range};
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

    /// Whether any distribution's advisories name `package`, for telling what a distribution
    /// builds and patches from what a vendor's own package carries.
    pub fn mentions(&self, package: &str) -> bool {
        self.records.keys().any(|ecosystem| {
            let key = (ecosystem.clone(), package.to_string());
            self.deb.contains_key(&key)
                || self.apk.contains_key(&key)
                || self.rpm.contains_key(&key)
        })
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

    /// File one OSV record, as loading an export would.
    #[cfg(test)]
    pub(crate) fn absorb(&mut self, record: &[u8], wanted: &Wanted) {
        let (entries, _) = parse_record(record, wanted, Path::new("test")).unwrap_or_default();
        for e in entries {
            if let Entry::Deb(k, a) = e {
                self.deb.entry(k).or_default().push(a);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn insert_deb(&mut self, ecosystem: &str, package: &str, adv: Advisory<DebVersion>) {
        self.deb
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
    /// Exports read as a [`frozen`](crate::distro::frozen) ecosystem, by path. Their records
    /// name the plain release and, in Debian's, other releases too: only the release's own
    /// count, under the frozen name, so they stay apart from what the maintained export says.
    pub frozen: BTreeMap<PathBuf, String>,
    /// The frozen ecosystem the records being read are filed under.
    relabel: Option<String>,
}

impl Wanted {
    /// What to keep from the export at `path`.
    fn at(&self, path: &Path) -> Cow<'_, Wanted> {
        let frozen = self.frozen.get(path).and_then(|eco| {
            let export = crate::distro::frozen_export(eco)?;
            Some((eco, export, *self.ecosystems.get(eco)?))
        });
        let Some((eco, export, family)) = frozen else {
            return Cow::Borrowed(self);
        };
        Cow::Owned(Wanted {
            ecosystems: BTreeMap::from([(export.to_string(), family)]),
            packages: self.packages.clone(),
            frozen: BTreeMap::new(),
            relabel: Some(eco.clone()),
        })
    }
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

/// Drop a lower bound above the fix it opens: osv.dev's Alpine records take `introduced` from
/// upstream and `fixed` from the branch's backport (`introduced 3.4.0, fixed 3.3.7-r2` for
/// OpenSSL in `Alpine:v3.21`), which read literally match no version at all, when the
/// distribution has said the versions below the fix are affected.
fn open_inverted_range<V: Ord>(range: &mut ParsedRange<V>) {
    let mut opened: Option<usize> = None;
    for at in 0..range.events.len() {
        let inverted = match (opened, range.events.get(at).and_then(|e| e.fixed.as_ref())) {
            (Some(i), Some(fixed)) => {
                matches!(range.events.get(i).and_then(|e| e.introduced.as_ref()),
                    Some(ParsedBound::Version(introduced)) if introduced > fixed)
            }
            _ => false,
        };
        if let (true, Some(event)) = (inverted, opened.and_then(|i| range.events.get_mut(i))) {
            // An unreadable bound is what the matcher already treats as open.
            event.introduced = Some(ParsedBound::Unparseable);
        }
        if range.events.get(at).is_some_and(|e| e.introduced.is_some()) {
            opened = Some(at);
        }
    }
}

fn ranges_of<V: Ord>(a: &Affected, parse: fn(&str) -> Option<V>) -> Vec<ParsedRange<V>> {
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
            let mut parsed = osv::parse_range(&range, parse);
            open_inverted_range(&mut parsed);
            parsed
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

/// AlmaLinux's export carries its bug fix (`ALBA`) and enhancement (`ALEA`) advisories next
/// to the security ones (`ALSA`). One that names no CVE fixes no vulnerability: reporting it
/// (a coreutils bug fix, "fixed in" a later build) would be a false positive. One that names
/// a CVE is kept.
fn not_security(id: &str, aliases: &[String]) -> bool {
    (id.starts_with("ALBA-") || id.starts_with("ALEA-"))
        && !aliases.iter().any(|a| a.starts_with("CVE-"))
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
    for a in &mut r.affected {
        let root = a
            .package
            .as_ref()
            .and_then(|p| p.ecosystem.as_deref())
            .is_some_and(|e| e.starts_with("Root:"));
        if root {
            for v in &mut a.versions {
                *v = crate::distro::root_build(v);
            }
            let events = a.ranges.iter_mut().flat_map(|r| r.events.iter_mut());
            for fixed in events.filter_map(|e| e.fixed.as_mut()) {
                *fixed = crate::distro::root_build(fixed);
            }
        }
    }
    if not_security(&r.id, &aliases) {
        return (out, counts);
    }
    for a in &r.affected {
        let Some(pkg) = &a.package else { continue };
        let (Some(name), Some(eco)) = (pkg.name.as_deref(), pkg.ecosystem.as_deref()) else {
            continue;
        };
        let Some(&family) = wanted.ecosystems.get(eco) else {
            continue;
        };
        let eco = wanted.relabel.as_deref().unwrap_or(eco);
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
            ($parse:expr) => {
                advisory!($parse, $parse)
            };
            ($parse:expr, $parse_bound:expr) => {{
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
                    module: a
                        .ecosystem_specific
                        .as_ref()
                        .and_then(|e| e.module.clone())
                        .or_else(|| module_fix_streams(family, a, r.summary.as_deref())),
                    url: (crate::feeds::feed_for(eco).is_some() || crate::distro::is_vex(eco))
                        .then_some(&r.references)
                        .and_then(|refs| {
                            refs.iter().find(|x| x.kind.as_deref() == Some("ADVISORY"))
                        })
                        .and_then(|x| x.url.clone())
                        .filter(|u| u.starts_with("https://")),
                    ranges: ranges_of(a, $parse_bound),
                    versions,
                }
            }};
        }
        out.push(match family {
            Family::Deb => Entry::Deb(key, advisory!(DebVersion::parse)),
            Family::Apk => Entry::Apk(key, advisory!(ApkVersion::parse)),
            Family::Rpm => Entry::Rpm(key, advisory!(RpmVersion::parse, RpmVersion::parse_fix)),
        });
    }
    (out, counts)
}

/// The module streams an rpm entry is about, when its record does not say: osv.dev's Red
/// Hat, AlmaLinux and Rocky records carry no stream, but an entry whose fix is a module build
/// (`.module+el8`, `.module_el8`) comes from an advisory whose summary names the streams
/// (`php:7.4 security update`, `virt:rhel and virt-devel:rhel security update`). Returned
/// comma-separated; `None` when the fix is no module build or the summary names no stream,
/// which leaves the entry ungated as before.
fn module_fix_streams(family: Family, a: &Affected, summary: Option<&str>) -> Option<String> {
    let module_fix = a
        .ranges
        .iter()
        .flat_map(|r| &r.events)
        .filter_map(|e| e.fixed.as_deref())
        .any(|f| f.contains(".module"));
    if family != Family::Rpm || !module_fix {
        return None;
    }
    let streams = summary_streams(summary?);
    (!streams.is_empty()).then(|| streams.join(","))
}

/// The `name:stream` words of an advisory summary (`389-ds:1.4`, `perl-DBD-Pg:3.7`,
/// `container-tools:rhel8`), in order, without repeats. A severity prefix (`Moderate:`) has
/// nothing after its colon and is not one.
fn summary_streams(summary: &str) -> Vec<String> {
    let part = |s: &str| {
        !s.is_empty()
            && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.+-".contains(&b))
    };
    let mut out: Vec<String> = Vec::new();
    for word in summary.split_whitespace() {
        let word = word.trim_end_matches([',', ';', ')']);
        let Some((name, stream)) = word.split_once(':') else {
            continue;
        };
        if part(name) && part(stream) && !out.iter().any(|w| w == word) {
            out.push(word.to_string());
        }
    }
    out
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
        let here = wanted.at(path);
        let per_record = if path.is_dir() {
            load_dir(path, &here)?
        } else {
            load_zip(path, &here)?
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
    fn a_frozen_export_files_only_its_own_release_under_the_frozen_name() {
        let tmp = std::env::temp_dir().join(format!("fr-frozen-{}", std::process::id()));
        let (live, frozen) = (tmp.join("Debian"), tmp.join("Debian_11"));
        let record = |id: &str, ecos: &[&str]| {
            let affected: Vec<String> = ecos
                .iter()
                .map(|e| {
                    format!(
                        r#"{{"package":{{"name":"zlib","ecosystem":"{e}"}},
                        "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}}]}}]}}"#
                    )
                })
                .collect();
            format!(r#"{{"id":"{id}","affected":[{}]}}"#, affected.join(","))
        };
        for dir in [&live, &frozen] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(
            live.join("a.json"),
            record("DEBIAN-CVE-2026-1", &["Debian:11", "Debian:12"]),
        )
        .unwrap();
        std::fs::write(
            frozen.join("b.json"),
            record("CVE-2024-1", &["Debian:11", "Debian:12"]),
        )
        .unwrap();
        let mut w = Wanted::default();
        for eco in ["Debian:11", "Debian:11::frozen", "Debian:12"] {
            w.ecosystems.insert(eco.into(), Family::Deb);
        }
        w.frozen
            .insert(frozen.clone(), "Debian:11::frozen".to_string());
        let db = load(&[live, frozen], &w).unwrap();
        std::fs::remove_dir_all(&tmp).unwrap();
        let ids = |eco: &str| -> Vec<String> {
            db.deb(eco, "zlib").iter().map(|a| a.id.clone()).collect()
        };
        assert_eq!(ids("Debian:11"), ["DEBIAN-CVE-2026-1"]);
        assert_eq!(ids("Debian:12"), ["DEBIAN-CVE-2026-1"]);
        assert_eq!(ids("Debian:11::frozen"), ["CVE-2024-1"]);
        assert_eq!(db.records("Debian:11::frozen"), 1);
    }

    #[test]
    fn alma_bug_fix_advisories_without_a_cve_are_not_vulnerabilities() {
        let mut w = Wanted::default();
        w.ecosystems.insert("AlmaLinux:8".into(), Family::Rpm);
        let record = |id: &str, related: &str| {
            format!(
                r#"{{"id":"{id}","summary":"coreutils bug fix and enhancement update",
                "related":[{related}],
                "affected":[{{"package":{{"name":"coreutils","ecosystem":"AlmaLinux:8"}},
                "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"8.30-20.el8_10"}}]}}]}}]}}"#
            )
        };
        let entries = |id: &str, related: &str| {
            parse_record(record(id, related).as_bytes(), &w, Path::new("x"))
                .unwrap()
                .0
                .len()
        };
        assert_eq!(entries("ALBA-2026:47115", ""), 0);
        assert_eq!(entries("ALEA-2026:1", ""), 0);
        assert_eq!(entries("ALBA-2026:2", r#""CVE-2026-1""#), 1);
        assert_eq!(entries("ALSA-2026:3", ""), 1);
    }

    #[test]
    fn module_fixes_take_their_streams_from_the_summary() {
        let mut w = Wanted::default();
        w.ecosystems.insert("Rocky Linux:8".into(), Family::Rpm);
        let entry = |summary: &str, fixed: &str| {
            let record = format!(
                r#"{{"id":"RLSA-2026:1","summary":"{summary}","aliases":["CVE-2026-1"],
                "affected":[{{"package":{{"name":"php","ecosystem":"Rocky Linux:8"}},
                "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"{fixed}"}}]}}]}}]}}"#
            );
            match parse_record(record.as_bytes(), &w, Path::new("x"))
                .unwrap()
                .0
                .pop()
            {
                Some(Entry::Rpm(_, a)) => a,
                _ => panic!("no rpm entry"),
            }
        };
        let module_of = |summary: &str, fixed: &str| entry(summary, fixed).module;
        let module = "0:8.0.30-1.module+el8.8.0+1550+1a2b3c4d";
        assert_eq!(
            module_of("Important: php:8.0 security update", module).as_deref(),
            Some("php:8.0")
        );
        assert_eq!(
            module_of(
                "Moderate: virt:rhel and virt-devel:rhel security update",
                module
            )
            .as_deref(),
            Some("virt:rhel,virt-devel:rhel")
        );
        assert_eq!(
            module_of("Moderate: 389-ds:1.4 security update", module).as_deref(),
            Some("389-ds:1.4")
        );
        // No stream named, or no module build: ungated.
        assert_eq!(
            module_of("Important: varnish security update", module),
            None
        );
        assert_eq!(
            module_of("Important: php:8.0 security update", "0:7.2.24-1.el8"),
            None
        );
        // The fix compares as its version and release (a build of it for another module
        // context is not older), and still shows in full.
        let fixed = entry("Important: php:8.0 security update", module).ranges[0]
            .events
            .iter()
            .find_map(|e| e.fixed.clone())
            .unwrap();
        assert_eq!(fixed, RpmVersion::parse("0:8.0.30-1").unwrap());
        assert_eq!(fixed.to_string(), module);
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

    /// `ALPINE-CVE-2026-54875`: a lower bound above the fix must not hide the versions below it.
    #[test]
    fn a_lower_bound_above_its_fix_is_dropped() {
        let matched = |introduced: &str, installed: &str| {
            let record = format!(
                r#"{{"id":"ALPINE-CVE-1","affected":[{{"package":{{"name":"openssl","ecosystem":"Alpine:v3.20"}},
                "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"{introduced}"}},{{"fixed":"3.3.7-r2"}}]}}]}}]}}"#
            );
            let (entries, _) = parse_record(record.as_bytes(), &wanted(), Path::new("x")).unwrap();
            let [Entry::Apk(_, adv)] = entries.as_slice() else {
                unreachable!("one Alpine entry")
            };
            let installed = ApkVersion::parse(installed).unwrap();
            let matched = osv::affected_fixed_parsed(&installed, &adv.ranges, |v, b| v >= b);
            matches!(matched, osv::Match::Affected { .. })
        };
        assert!(matched("3.4.0", "3.3.3-r0"));
        assert!(!matched("3.4.0", "3.3.7-r2"));
        // A bound below its fix still means what it says.
        assert!(!matched("3.3.0", "3.2.0-r0"));
        assert!(matched("3.3.0", "3.3.3-r0"));
    }
}
