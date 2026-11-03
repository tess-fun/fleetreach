//! Vendor feeds for rpm distributions osv.dev does not cover, converted into OSV records so
//! the distro loader and matcher read them like any export:
//!
//! - **Amazon Linux 2 and 2023**: the `updateinfo.xml` of the distribution's core repository
//!   (what `yum updateinfo` reads), one record per ALAS advisory, each binary package fixed at
//!   the version the advisory ships.
//! - **Oracle Linux 7 to 10**: Oracle's per-release OVAL (`com.oracle.elsa-ol9.xml.bz2`), one
//!   record per ELSA. A definition's criteria are evaluated as OVAL would: a package is
//!   affected when it is earlier than any version an `OR` branch names (so the highest),
//!   branches for Ksplice and FIPS builds are left out (their own versions, not what a plain
//!   package is measured against), and branches that need a module stream carry it
//!   (`ecosystem_specific.module`), so only packages from that stream match. The file also
//!   holds definitions for other releases; only the feed's own are kept, and ELBA (bug fix)
//!   definitions are skipped.
//! - **Photon OS 3.0 to 5.0**: VMware's CVE metadata (`cve_data_photon5.0.json`), one record
//!   per CVE, `Not Affected` rows dropped.
//!
//! All three name binary packages. Conversion is strict: a feed whose shape is not the one
//! described here is an error, never a partial set of records.

use std::collections::BTreeMap;
use std::io::Read;

use serde::Deserialize;
use serde_json::{json, Value};

/// Which converter a feed needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A yum repository's `updateinfo.xml.gz`.
    AmazonUpdateinfo,
    /// An OVAL definitions file, bzip2-compressed.
    OracleOval,
    /// Photon's CVE metadata JSON.
    PhotonCves,
}

/// A vendor feed serving one ecosystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feed {
    /// The ecosystem the records are written for, also the export's name
    /// (`Amazon Linux:2023`, `Oracle Linux:9`, `Photon OS:5.0`).
    pub ecosystem: String,
    pub kind: Kind,
    /// Where to start: the repository mirror list for Amazon Linux (resolved with
    /// [`updateinfo_url`]), the file itself otherwise.
    pub url: String,
}

/// The vendor feed for `ecosystem`, if it is one fleetreach reads from its vendor.
pub fn feed_for(ecosystem: &str) -> Option<Feed> {
    let (base, release) = ecosystem.split_once(':')?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let (kind, url) = match (base, release) {
        ("Amazon Linux", "2") => (
            Kind::AmazonUpdateinfo,
            "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list".to_string(),
        ),
        ("Amazon Linux", "2023") => (
            Kind::AmazonUpdateinfo,
            "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list".to_string(),
        ),
        ("Oracle Linux", r) if digits(r) => (
            Kind::OracleOval,
            format!("https://linux.oracle.com/security/oval/com.oracle.elsa-ol{r}.xml.bz2"),
        ),
        ("Photon OS", r @ ("3.0" | "4.0" | "5.0")) => (
            Kind::PhotonCves,
            format!(
                "https://packages.broadcom.com/photon/photon_cve_metadata/cve_data_photon{r}.json"
            ),
        ),
        _ => return None,
    };
    Some(Feed {
        ecosystem: ecosystem.to_string(),
        kind,
        url,
    })
}

/// The `updateinfo.xml.gz` URL of a yum repository, from its mirror list (one base URL per
/// line) and that mirror's `repodata/repomd.xml`. `fetch` gets a URL's body.
///
/// # Errors
///
/// When a step fails or the repository lists no `updateinfo`.
pub fn updateinfo_url(
    mirror_list: &str,
    fetch: &mut dyn FnMut(&str) -> Result<Vec<u8>, String>,
) -> Result<String, String> {
    let base = mirror_list
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("https://"))
        .ok_or("the mirror list names no https mirror")?;
    let base = if base.ends_with('/') {
        base.to_string()
    } else {
        format!("{base}/")
    };
    let repomd = fetch(&format!("{base}repodata/repomd.xml"))?;
    let repomd = std::str::from_utf8(&repomd).map_err(|e| format!("repomd.xml: {e}"))?;
    let doc = roxmltree::Document::parse(repomd).map_err(|e| format!("repomd.xml: {e}"))?;
    let href = doc
        .descendants()
        .filter(|n| n.has_tag_name("data") && n.attribute("type") == Some("updateinfo"))
        .find_map(|n| n.children().find(|c| c.has_tag_name("location")))
        .and_then(|l| l.attribute("href"))
        .ok_or("repomd.xml lists no updateinfo")?;
    if href.contains("..") || href.starts_with('/') || href.contains("://") {
        return Err(format!("repomd.xml: unexpected updateinfo location {href}"));
    }
    Ok(format!("{base}{href}"))
}

/// Fixed versions by package: `(name, module stream) -> fixed EVR`.
type Fixed = BTreeMap<(String, Option<String>), String>;

/// One converted record: its id and OSV JSON.
#[derive(Debug, Clone)]
pub struct Record {
    pub id: String,
    pub json: Vec<u8>,
}

/// Feeds larger than this, decompressed, are refused (Oracle's largest is about 110 MB).
const MAX_FEED_BYTES: u64 = 1 << 30;

fn decompress(raw: &[u8], kind: Kind) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let read = match kind {
        Kind::AmazonUpdateinfo => flate2::read::GzDecoder::new(raw)
            .take(MAX_FEED_BYTES)
            .read_to_end(&mut out),
        Kind::OracleOval => bzip2_rs::DecoderReader::new(raw)
            .take(MAX_FEED_BYTES)
            .read_to_end(&mut out),
        Kind::PhotonCves => return Ok(raw.to_vec()),
    };
    read.map_err(|e| format!("decompressing the feed: {e}"))?;
    if out.len() as u64 >= MAX_FEED_BYTES {
        return Err("the feed is larger than any known one".into());
    }
    Ok(out)
}

/// Convert a feed as downloaded (gzip, bzip2 or plain JSON, per its kind) into OSV records,
/// sorted by id.
///
/// # Errors
///
/// When the feed does not have the shape its kind promises, or yields no records.
pub fn convert(feed: &Feed, raw: &[u8]) -> Result<Vec<Record>, String> {
    let body = decompress(raw, feed.kind)?;
    let records = match feed.kind {
        Kind::AmazonUpdateinfo => amazon(&feed.ecosystem, text(&body)?)?,
        Kind::OracleOval => oracle(&feed.ecosystem, text(&body)?)?,
        Kind::PhotonCves => photon(&feed.ecosystem, &body)?,
    };
    if records.is_empty() {
        return Err(format!("the {} feed holds no advisories", feed.ecosystem));
    }
    let mut out: Vec<Record> = records
        .into_iter()
        .map(|(id, v)| {
            serde_json::to_vec(&v)
                .map(|json| Record { id, json })
                .map_err(|e| e.to_string())
        })
        .collect::<Result<_, _>>()?;
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

fn text(body: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(body).map_err(|e| format!("the feed is not UTF-8: {e}"))
}

/// A vendor severity word as the OSV `database_specific.severity` band.
fn band(word: &str) -> Option<&'static str> {
    match word.trim().to_ascii_lowercase().as_str() {
        "critical" => Some("CRITICAL"),
        "important" | "high" => Some("HIGH"),
        "moderate" | "medium" => Some("MEDIUM"),
        "low" => Some("LOW"),
        _ => None,
    }
}

/// One OSV record with a fixed version per package (`(name, module) -> fixed`).
fn record(
    ecosystem: &str,
    id: &str,
    summary: &str,
    aliases: Vec<String>,
    severity: Option<&str>,
    source: &str,
    fixed: &Fixed,
) -> Value {
    let affected: Vec<Value> = fixed
        .iter()
        .map(|((name, module), evr)| {
            let mut a = json!({
                "package": {"ecosystem": ecosystem, "name": name},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": evr}]}],
            });
            if let Some(m) = module {
                a["ecosystem_specific"] = json!({ "module": m });
            }
            a
        })
        .collect();
    let mut r = json!({
        "id": id,
        "summary": summary,
        "aliases": aliases,
        "affected": affected,
        "database_specific": {"source": source},
    });
    if let Some(s) = severity {
        r["database_specific"]["severity"] = json!(s);
    }
    // The vendor's page for its own ids; a CVE's record on osv.dev says more than the
    // feed file a Photon CVE comes from.
    if !id.starts_with("CVE-") {
        r["references"] = json!([{"type": "ADVISORY", "url": source}]);
    }
    r
}

/// Keep the higher of two fixed versions for one package.
fn keep_max(fixed: &mut Fixed, key: (String, Option<String>), evr: String) -> Result<(), String> {
    let parsed =
        crate::RpmVersion::parse(&evr).ok_or_else(|| format!("unparseable version {evr}"))?;
    match fixed.get(&key) {
        Some(old) if crate::RpmVersion::parse(old).is_some_and(|o| o >= parsed) => {}
        _ => {
            fixed.insert(key, evr);
        }
    }
    Ok(())
}

fn amazon(ecosystem: &str, xml: &str) -> Result<Vec<(String, Value)>, String> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| format!("updateinfo.xml: {e}"))?;
    let root = doc.root_element();
    if !root.has_tag_name("updates") {
        return Err("updateinfo.xml: the root is not <updates>".into());
    }
    let child_text = |n: roxmltree::Node, tag: &str| {
        n.children()
            .find(|c| c.has_tag_name(tag))
            .and_then(|c| c.text())
            .map(str::trim)
            .map(str::to_string)
    };
    let mut out = Vec::new();
    for u in root.children().filter(|n| n.has_tag_name("update")) {
        let id = child_text(u, "id").ok_or("an update has no id")?;
        let aliases: Vec<String> = u
            .descendants()
            .filter(|n| n.has_tag_name("reference") && n.attribute("type") == Some("cve"))
            .filter_map(|n| n.attribute("id").map(str::to_string))
            .collect();
        let mut fixed = BTreeMap::new();
        for p in u.descendants().filter(|n| n.has_tag_name("package")) {
            let attr = |k: &str| {
                p.attribute(k)
                    .ok_or_else(|| format!("{id}: a package has no {k}"))
            };
            let (name, version, release) = (attr("name")?, attr("version")?, attr("release")?);
            let epoch = p.attribute("epoch").unwrap_or("0");
            keep_max(
                &mut fixed,
                (name.to_string(), None),
                format!("{epoch}:{version}-{release}"),
            )?;
        }
        if fixed.is_empty() {
            return Err(format!("{id}: no packages"));
        }
        let title = child_text(u, "title").unwrap_or_else(|| id.clone());
        let severity = child_text(u, "severity").and_then(|s| band(&s));
        let source = format!(
            "https://alas.aws.amazon.com/{}{id}.html",
            if id.starts_with("ALAS2023") {
                "AL2023/"
            } else if id.starts_with("ALAS2") {
                "AL2/"
            } else {
                ""
            }
        );
        out.push((
            id.clone(),
            record(ecosystem, &id, &title, aliases, severity, &source, &fixed),
        ));
    }
    Ok(out)
}

/// What the `AND` criteria above a package test say.
#[derive(Debug, Clone, Default)]
struct Context {
    release: Option<String>,
    module: Option<String>,
    /// A Ksplice or FIPS build, measured against its own versions.
    special_build: bool,
}

/// One OVAL definition's package tests: `(release, name, module) -> highest earlier-than`.
type Earlier = BTreeMap<(String, String, Option<String>), String>;

fn oracle(ecosystem: &str, xml: &str) -> Result<Vec<(String, Value)>, String> {
    let release = ecosystem.trim_start_matches("Oracle Linux:");
    let opts = roxmltree::ParsingOptions {
        allow_dtd: false,
        ..roxmltree::ParsingOptions::default()
    };
    let doc =
        roxmltree::Document::parse_with_options(xml, opts).map_err(|e| format!("OVAL: {e}"))?;
    let root = doc.root_element();
    let section = |tag: &str| root.children().find(|n| n.has_tag_name(tag));
    let by_id = |tag: &str| -> BTreeMap<&str, roxmltree::Node> {
        section(tag)
            .into_iter()
            .flat_map(|s| s.children().filter(roxmltree::Node::is_element))
            .filter_map(|n| n.attribute("id").map(|id| (id, n)))
            .collect()
    };
    let (tests, objects, states) = (by_id("tests"), by_id("objects"), by_id("states"));
    // A test that says "<name> is earlier than <evr>": its object's name and state's evr.
    let earlier = |test_ref: &str| -> Option<(String, String)> {
        let test = tests.get(test_ref)?;
        let child = |tag: &str, attr: &str| {
            test.children()
                .find(|c| c.has_tag_name(tag))
                .and_then(|c| c.attribute(attr))
        };
        let state = states.get(child("state", "state_ref")?)?;
        let evr = state
            .children()
            .find(|c| c.has_tag_name("evr") && c.attribute("operation") == Some("less than"))?
            .text()?;
        let object = objects.get(child("object", "object_ref")?)?;
        let name = object.children().find(|c| c.has_tag_name("name"))?.text()?;
        Some((name.trim().to_string(), evr.trim().to_string()))
    };

    let mut out = Vec::new();
    let definitions = section("definitions").ok_or("OVAL: no <definitions>")?;
    for def in definitions
        .children()
        .filter(|n| n.has_tag_name("definition"))
    {
        let meta = def
            .children()
            .find(|n| n.has_tag_name("metadata"))
            .ok_or("OVAL: a definition has no metadata")?;
        let refs: Vec<(&str, &str)> = meta
            .children()
            .filter(|n| n.has_tag_name("reference"))
            .filter_map(|n| Some((n.attribute("source")?, n.attribute("ref_id")?)))
            .collect();
        let Some(id) = refs.iter().find(|(s, _)| *s == "elsa").map(|(_, id)| *id) else {
            if refs.iter().any(|(s, _)| *s == "elba") {
                continue;
            }
            return Err(format!(
                "OVAL: definition {} names no ELSA",
                def.attribute("id").unwrap_or("?")
            ));
        };
        let aliases: Vec<String> = refs
            .iter()
            .filter(|(s, _)| *s == "CVE")
            .map(|(_, id)| id.to_string())
            .collect();
        let title = meta
            .children()
            .find(|n| n.has_tag_name("title"))
            .and_then(|n| n.text())
            .map(str::trim)
            .unwrap_or(id);
        let severity = meta
            .descendants()
            .find(|n| n.has_tag_name("severity"))
            .and_then(|n| n.text())
            .and_then(band);
        let criteria = def
            .children()
            .find(|n| n.has_tag_name("criteria"))
            .ok_or_else(|| format!("{id}: no criteria"))?;
        let mut found = Earlier::new();
        walk(criteria, &Context::default(), &earlier, &mut found)
            .map_err(|e| format!("{id}: {e}"))?;
        let fixed: Fixed = found
            .into_iter()
            .filter(|((r, _, _), _)| r == release)
            .map(|((_, name, module), evr)| ((name, module), evr))
            .collect();
        if fixed.is_empty() {
            // Another release's, or only special builds: nothing a plain package here matches.
            continue;
        }
        let source = format!("https://linux.oracle.com/errata/{id}.html");
        out.push((
            id.to_string(),
            record(ecosystem, id, title, aliases, severity, &source, &fixed),
        ));
    }
    Ok(out)
}

/// Collect the package tests under `node` (a `<criteria>`), with the context its `AND`
/// siblings give them.
fn walk(
    node: roxmltree::Node,
    ctx: &Context,
    earlier: &dyn Fn(&str) -> Option<(String, String)>,
    out: &mut Earlier,
) -> Result<(), String> {
    let and = node.attribute("operator").unwrap_or("AND") == "AND";
    if node.attribute("negate") == Some("true") {
        return Err("negated criteria are not read".into());
    }
    let criteria: Vec<roxmltree::Node> = node
        .children()
        .filter(|c| c.has_tag_name("criterion"))
        .collect();
    let mut ctx = ctx.clone();
    let mut tests = Vec::new();
    for c in &criteria {
        if c.attribute("negate") == Some("true") {
            return Err("negated criteria are not read".into());
        }
        let comment = c.attribute("comment").unwrap_or_default();
        let test_ref = c.attribute("test_ref").ok_or("a criterion has no test")?;
        if let Some(pkg) = earlier(test_ref) {
            tests.push(pkg);
            continue;
        }
        if let Some(r) = comment
            .strip_prefix("Oracle Linux ")
            .and_then(|r| r.strip_suffix(" is installed"))
        {
            ctx.release = Some(r.to_string());
        } else if let Some(m) = comment
            .strip_prefix("Module ")
            .and_then(|m| m.strip_suffix(" is enabled"))
        {
            ctx.module = Some(m.to_string());
        } else if comment.ends_with(" is ksplice-based") || comment.ends_with(" is fips patched") {
            ctx.special_build = true;
        } else if comment.starts_with("Oracle Linux arch is ")
            || comment.contains(" is signed with the Oracle Linux ")
        {
            // Every architecture is read (an OR across them keeps the highest fix), and the
            // signature only tells Oracle's builds from others'.
        } else {
            return Err(format!("criterion not understood: {comment:?}"));
        }
        if !and {
            return Err(format!("a condition under OR: {comment:?}"));
        }
    }
    if !ctx.special_build {
        for (name, evr) in tests {
            let release = ctx
                .release
                .clone()
                .ok_or_else(|| format!("{name}: no Oracle Linux release above it"))?;
            let parsed = crate::RpmVersion::parse(&evr)
                .ok_or_else(|| format!("{name}: unparseable version {evr}"))?;
            let key = (release, name, ctx.module.clone());
            match out.get(&key) {
                Some(old) if crate::RpmVersion::parse(old).is_some_and(|o| o >= parsed) => {}
                _ => {
                    out.insert(key, evr);
                }
            }
        }
    }
    for child in node.children().filter(|c| c.has_tag_name("criteria")) {
        walk(child, &ctx, earlier, out)?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PhotonRow {
    cve_id: String,
    pkg: String,
    cve_score: Option<f64>,
    aff_ver: String,
    res_ver: String,
    status: String,
}

fn photon(ecosystem: &str, body: &[u8]) -> Result<Vec<(String, Value)>, String> {
    let rows: Vec<PhotonRow> =
        serde_json::from_slice(body).map_err(|e| format!("Photon CVE metadata: {e}"))?;
    let mut by_cve: BTreeMap<String, (f64, Fixed)> = BTreeMap::new();
    for r in rows {
        match r.status.as_str() {
            "Not Affected" => continue,
            "Fixed" => {}
            other => return Err(format!("{} {}: status {other:?}", r.cve_id, r.pkg)),
        }
        if r.aff_ver != format!("all versions before {} are vulnerable", r.res_ver) {
            return Err(format!(
                "{} {}: affected versions {:?} do not end at the fix {:?}",
                r.cve_id, r.pkg, r.aff_ver, r.res_ver
            ));
        }
        let entry = by_cve.entry(r.cve_id.clone()).or_default();
        entry.0 = entry.0.max(r.cve_score.unwrap_or(0.0));
        keep_max(&mut entry.1, (r.pkg, None), r.res_ver)?;
    }
    let base = ecosystem.replace("Photon OS:", "");
    Ok(by_cve
        .into_iter()
        .map(|(id, (score, fixed))| {
            let severity = match score {
                s if s >= 9.0 => Some("CRITICAL"),
                s if s >= 7.0 => Some("HIGH"),
                s if s >= 4.0 => Some("MEDIUM"),
                s if s > 0.0 => Some("LOW"),
                _ => None,
            };
            let source = format!(
                "https://packages.broadcom.com/photon/photon_cve_metadata/cve_data_photon{base}.json"
            );
            let v = record(ecosystem, &id, &id, Vec::new(), severity, &source, &fixed);
            (id, v)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn parsed(records: &[Record]) -> Vec<Value> {
        records
            .iter()
            .map(|r| serde_json::from_slice(&r.json).unwrap())
            .collect()
    }

    #[test]
    fn feeds_by_ecosystem() {
        assert_eq!(
            feed_for("Amazon Linux:2023").unwrap().kind,
            Kind::AmazonUpdateinfo
        );
        assert!(feed_for("Oracle Linux:9")
            .unwrap()
            .url
            .ends_with("elsa-ol9.xml.bz2"));
        assert_eq!(feed_for("Photon OS:5.0").unwrap().kind, Kind::PhotonCves);
        assert!(feed_for("Amazon Linux:1").is_none());
        assert!(feed_for("Oracle Linux:x").is_none());
        assert!(feed_for("Debian:12").is_none());
    }

    #[test]
    fn updateinfo_location_from_repomd() {
        let repomd = br#"<repomd xmlns="http://linux.duke.edu/metadata/repo">
          <data type="primary"><location href="repodata/primary.xml.gz"/></data>
          <data type="updateinfo"><location href="repodata/updateinfo.xml.gz"/></data></repomd>"#;
        let mut fetch = |url: &str| {
            assert_eq!(url, "https://m.example/x/repodata/repomd.xml");
            Ok(repomd.to_vec())
        };
        assert_eq!(
            updateinfo_url("https://m.example/x\n", &mut fetch).unwrap(),
            "https://m.example/x/repodata/updateinfo.xml.gz"
        );
        assert!(updateinfo_url("http://insecure/\n", &mut fetch).is_err());
    }

    #[test]
    fn amazon_updateinfo() {
        let xml = r#"<?xml version="1.0" ?><updates>
          <update type="security"><id>ALAS2-2026-1</id><title>openssl update</title>
          <severity>important</severity>
          <references><reference type="cve" id="CVE-2026-1"/></references>
          <pkglist><collection>
            <package name="openssl" version="1.0.2k" release="24.amzn2.0.1" epoch="1" arch="x86_64"/>
            <package name="openssl" version="1.0.2k" release="24.amzn2.0.1" epoch="1" arch="aarch64"/>
            <package name="openssl-libs" version="1.0.2k" release="24.amzn2.0.1" epoch="1" arch="x86_64"/>
          </collection></pkglist></update></updates>"#;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, xml.as_bytes()).unwrap();
        let feed = feed_for("Amazon Linux:2").unwrap();
        let recs = parsed(&convert(&feed, &gz.finish().unwrap()).unwrap());
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r["aliases"], json!(["CVE-2026-1"]));
        assert_eq!(r["database_specific"]["severity"], "HIGH");
        assert_eq!(
            r["affected"].as_array().unwrap().len(),
            2,
            "one entry per package name"
        );
        assert_eq!(
            r["affected"][0]["ranges"][0]["events"][1]["fixed"],
            "1:1.0.2k-24.amzn2.0.1"
        );
        assert_eq!(r["affected"][0]["package"]["ecosystem"], "Amazon Linux:2");
    }

    const OVAL: &str = r#"<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
<definitions>
<definition id="oval:com.oracle.elsa:def:1" class="patch"><metadata>
<title>ELSA-2026-1: perl-DBI security update (IMPORTANT)</title>
<reference source="elsa" ref_id="ELSA-2026-1"/><reference source="CVE" ref_id="CVE-2026-9"/>
<advisory><severity>IMPORTANT</severity></advisory></metadata>
<criteria operator="AND">
 <criterion test_ref="t-ol8" comment="Oracle Linux 8 is installed"/>
 <criteria operator="OR">
  <criteria operator="AND">
   <criterion test_ref="t-x86" comment="Oracle Linux arch is x86_64"/>
   <criteria operator="AND">
    <criterion test_ref="t-mod" comment="Module perl-DBI:1.641 is enabled"/>
    <criteria operator="OR">
     <criteria operator="AND">
      <criterion test_ref="t-dbi-a" comment="perl-DBI is earlier than 0:1.641-4.module+el8"/>
      <criterion test_ref="t-sig" comment="perl-DBI is signed with the Oracle Linux 8 key"/>
     </criteria>
     <criteria operator="AND">
      <criterion test_ref="t-dbi-b" comment="perl-DBI is earlier than 0:1.641-5.module+el8"/>
     </criteria>
    </criteria>
   </criteria>
   <criteria operator="AND">
    <criterion test_ref="t-ssl" comment="openssl is earlier than 1:1.1.1k-12.el8_9"/>
   </criteria>
   <criteria operator="AND">
    <criterion test_ref="t-ssl-k" comment="openssl is earlier than 1:1.1.1k-12.ksplice1.el8_9"/>
    <criterion test_ref="t-kspl" comment="openssl is ksplice-based"/>
   </criteria>
  </criteria>
 </criteria>
</criteria></definition>
</definitions>
<tests>
 <rpminfo_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="t-dbi-a"><object object_ref="o-dbi"/><state state_ref="s-a"/></rpminfo_test>
 <rpminfo_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="t-dbi-b"><object object_ref="o-dbi"/><state state_ref="s-b"/></rpminfo_test>
 <rpminfo_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="t-ssl"><object object_ref="o-ssl"/><state state_ref="s-ssl"/></rpminfo_test>
 <rpminfo_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="t-ssl-k"><object object_ref="o-ssl"/><state state_ref="s-ssl-k"/></rpminfo_test>
 <rpminfo_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="t-ol8"><object object_ref="o-rel"/><state state_ref="s-ver"/></rpminfo_test>
</tests>
<objects>
 <rpminfo_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="o-dbi"><name>perl-DBI</name></rpminfo_object>
 <rpminfo_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="o-ssl"><name>openssl</name></rpminfo_object>
 <rpminfo_object xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="o-rel"><name>oraclelinux-release</name></rpminfo_object>
</objects>
<states>
 <rpminfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="s-a"><evr datatype="evr_string" operation="less than">0:1.641-4.module+el8</evr></rpminfo_state>
 <rpminfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="s-b"><evr datatype="evr_string" operation="less than">0:1.641-5.module+el8</evr></rpminfo_state>
 <rpminfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="s-ssl"><evr datatype="evr_string" operation="less than">1:1.1.1k-12.el8_9</evr></rpminfo_state>
 <rpminfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="s-ssl-k"><evr datatype="evr_string" operation="less than">1:1.1.1k-12.ksplice1.el8_9</evr></rpminfo_state>
 <rpminfo_state xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" id="s-ver"><version operation="pattern match">^8</version></rpminfo_state>
</states>
</oval_definitions>"#;

    /// `s` bzip2-compressed by the `bzip2` tool (this crate only decodes).
    fn bz2(s: &str) -> Vec<u8> {
        let mut child = std::process::Command::new("bzip2")
            .arg("-c")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let input = s.to_string();
        let writer =
            std::thread::spawn(move || std::io::Write::write_all(&mut stdin, input.as_bytes()));
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap().unwrap();
        assert!(out.status.success());
        out.stdout
    }

    #[test]
    fn oracle_oval_criteria() {
        let feed = feed_for("Oracle Linux:8").unwrap();
        let recs = parsed(&convert(&feed, &bz2(OVAL)).unwrap());
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r["id"], "ELSA-2026-1");
        assert_eq!(r["aliases"], json!(["CVE-2026-9"]));
        assert_eq!(r["database_specific"]["severity"], "HIGH");
        let affected = r["affected"].as_array().unwrap();
        assert_eq!(
            affected.len(),
            2,
            "the Ksplice branch is left out: {affected:?}"
        );
        let fixed = |i: usize| affected[i]["ranges"][0]["events"][1]["fixed"].clone();
        assert_eq!(affected[0]["package"]["name"], "openssl");
        assert_eq!(fixed(0), "1:1.1.1k-12.el8_9");
        assert!(affected[0].get("ecosystem_specific").is_none());
        assert_eq!(affected[1]["package"]["name"], "perl-DBI");
        assert_eq!(fixed(1), "0:1.641-5.module+el8", "OR keeps the highest");
        assert_eq!(
            affected[1]["ecosystem_specific"]["module"],
            "perl-DBI:1.641"
        );
        assert_eq!(affected[1]["package"]["ecosystem"], "Oracle Linux:8");
    }

    #[test]
    fn oracle_unknown_criterion_fails_closed() {
        let odd = OVAL.replace("Oracle Linux arch is x86_64", "Something else entirely");
        let feed = feed_for("Oracle Linux:8").unwrap();
        let err = convert(&feed, &bz2(&odd)).unwrap_err();
        assert!(err.contains("not understood"), "{err}");
    }

    #[test]
    fn photon_rows() {
        let json = br#"[
          {"cve_id":"CVE-2026-1","pkg":"krb5","cve_score":7.1,"aff_ver":"all versions before 1.17-15.ph4 are vulnerable","res_ver":"1.17-15.ph4","status":"Fixed"},
          {"cve_id":"CVE-2026-1","pkg":"krb5-devel","cve_score":7.1,"aff_ver":"all versions before 1.17-15.ph4 are vulnerable","res_ver":"1.17-15.ph4","status":"Fixed"},
          {"cve_id":"CVE-2026-2","pkg":"ntp","cve_score":5.0,"aff_ver":"NA","res_ver":"NA","status":"Not Affected"}]"#;
        let feed = feed_for("Photon OS:4.0").unwrap();
        let recs = parsed(&convert(&feed, json).unwrap());
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["affected"].as_array().unwrap().len(), 2);
        assert_eq!(recs[0]["database_specific"]["severity"], "HIGH");
        let bad = br#"[{"cve_id":"CVE-2026-3","pkg":"x","cve_score":5.0,"aff_ver":"only 1.0","res_ver":"1.1-1.ph4","status":"Fixed"}]"#;
        assert!(convert(&feed, bad).is_err());
        assert!(convert(&feed, b"[]").is_err(), "an empty feed is an error");
    }
}
