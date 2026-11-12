//! CSAF 2.0 VEX (spec 16, row 24): the OpenVEX statement set ([`crate::vex`]) as a
//! `csaf_vex` document, for consumers that read CSAF (Trivy, Dependency-Track, vendor
//! portals).
//!
//! The statements are the same ones `-f vex` writes, so the two documents never disagree.
//! Each repo is a product and each package a component; a component in a repo is the
//! relationship `default_component_of`, and that combined product is what the statuses name.
//! Packages carry their package URL as `product_identification_helper.purl`, which is how a
//! scanner matches a statement to what it found.
//!
//! The VEX profile asks more of a status than OpenVEX does: `known_not_affected` needs an
//! impact statement (a flag with the justification label, plus a `threats` entry of category
//! `impact`), and `known_affected` needs a remediation. A machine statement has both from its
//! notes and its action statement.

use std::collections::{BTreeMap, BTreeSet};

use fleetreach_core::FleetReport;
use serde_json::{json, Value};

use crate::vex::{build_statements, content_id, Statement, VexParams};

/// The namespace of the product ids `x_generic_uris` carries: fleetreach's VEX product ids.
const GENERIC_URI_NAMESPACE: &str = "https://github.com/tess-fun/fleetreach#vex-product-id";

/// CSAF publisher details `-f csaf-vex` needs beyond OpenVEX's author.
pub struct CsafParams {
    /// `document.publisher.namespace`: a URL naming the publisher (`https://acme.example`).
    pub namespace: String,
    /// `document.publisher.category`: `vendor`, `discoverer`, `coordinator`, `user`, `other`
    /// or `translator`. A fleet assessing its own services is `vendor` or `user`.
    pub category: String,
    /// Leave out advisories with no CVE id. CSAF names them by `ids`, which the standard
    /// allows, but Trivy 0.73 reads every entry's `cve` and stops on one without it.
    pub cve_only: bool,
}

/// The publisher namespace an author implies: the domain of an email address, as a URL.
#[must_use]
pub fn namespace_from_author(author: &str) -> Option<String> {
    if author.starts_with("https://") || author.starts_with("http://") {
        return Some(author.trim_end_matches('/').to_string());
    }
    let (_, domain) = author.trim().rsplit_once('@')?;
    let domain = domain.trim_end_matches('>');
    let valid = domain.contains('.')
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    valid.then(|| format!("https://{}", domain.to_ascii_lowercase()))
}

/// The CSAF identifier systems an advisory id names.
fn system_of(id: &str) -> &'static str {
    match id.split('-').next().unwrap_or("") {
        "GHSA" => "GitHub Security Advisory",
        "RUSTSEC" => "RustSec",
        "PYSEC" => "PyPA",
        "GO" => "Go Vulnerability Database",
        "OSV" => "OSV",
        "CVE" => "CVE",
        _ => "OSV",
    }
}

fn product_status_key(status: &str) -> &'static str {
    match status {
        "not_affected" => "known_not_affected",
        "affected" => "known_affected",
        "fixed" => "fixed",
        _ => "under_investigation",
    }
}

/// One advisory's statements, by the CSAF combined product id.
struct Vuln<'a> {
    /// Advisory id -> its title.
    titles: BTreeMap<&'a str, &'a str>,
    ids: BTreeSet<String>,
    status: BTreeMap<&'static str, BTreeSet<String>>,
    /// `(label, product)`
    flags: BTreeMap<String, BTreeSet<String>>,
    /// `(details, product)`
    impacts: BTreeMap<String, BTreeSet<String>>,
    /// `(category, details, product)`
    remediations: BTreeMap<(&'static str, String), BTreeSet<String>>,
}

/// Serialize a report to a CSAF 2.0 document of the VEX profile. Deterministic: equal
/// inputs give byte-identical output.
/// Returns the document and how many advisories `cve_only` left out.
pub fn to_csaf_vex(
    report: &FleetReport,
    params: &VexParams,
    csaf: &CsafParams,
) -> Result<(String, usize), serde_json::Error> {
    let mut statements = build_statements(report, params);
    let mut left_out = BTreeSet::new();
    if csaf.cve_only {
        statements.retain(|s| {
            let has = cve_of(s).is_some();
            if !has {
                left_out.insert(s.vulnerability.name.clone());
            }
            has
        });
    }
    let titles: BTreeMap<&str, &str> = report
        .vulnerabilities
        .iter()
        .map(|v| (v.advisory_id.as_str(), v.title.as_str()))
        .collect();

    // Product ids are stable: numbered in sorted order.
    let mut repos: BTreeSet<&str> = BTreeSet::new();
    let mut packages: BTreeSet<&str> = BTreeSet::new();
    for s in &statements {
        if let Some(p) = s.products.first() {
            repos.insert(&p.id);
        }
        packages.extend(s.subcomponents.iter().map(|c| c.id.as_str()));
    }
    let repo_ids: BTreeMap<&str, String> = repos
        .iter()
        .enumerate()
        .map(|(i, r)| (*r, format!("FR-PRODUCT-{}", i + 1)))
        .collect();
    let package_ids: BTreeMap<&str, String> = packages
        .iter()
        .enumerate()
        .map(|(i, p)| (*p, format!("FR-COMPONENT-{}", i + 1)))
        .collect();
    let mut relationships: BTreeMap<(String, String), (&str, &str)> = BTreeMap::new();

    let mut vulns: BTreeMap<String, Vuln> = BTreeMap::new();
    for s in &statements {
        let Some(repo) = s.products.first() else {
            continue;
        };
        // An OS statement names each binary package of one source package.
        for package in &s.subcomponents {
            let (Some(rid), Some(cid)) = (
                repo_ids.get(repo.id.as_str()),
                package_ids.get(package.id.as_str()),
            ) else {
                continue;
            };
            let combined = format!("{cid}:{rid}");
            relationships.insert((cid.clone(), rid.clone()), (&package.id, &repo.id));
            // One entry per CVE: consumers look a finding up by its CVE and take the first entry,
            // so two advisories for one CVE (a GHSA and its RUSTSEC) must share it.
            let name = s.vulnerability.name.as_str();
            let key = cve_of(s).unwrap_or(name).to_string();
            let v = vulns.entry(key).or_insert_with(|| Vuln {
                titles: BTreeMap::new(),
                ids: BTreeSet::new(),
                status: BTreeMap::new(),
                flags: BTreeMap::new(),
                impacts: BTreeMap::new(),
                remediations: BTreeMap::new(),
            });
            v.titles.entry(name).or_insert_with(|| {
                titles
                    .get(name)
                    .copied()
                    .filter(|t| !t.is_empty())
                    .unwrap_or(name)
            });
            v.ids.insert(name.to_string());
            v.ids.extend(s.vulnerability.aliases.iter().cloned());
            v.status
                .entry(product_status_key(s.status))
                .or_default()
                .insert(combined.clone());
            add_details(v, s, &combined);
        }
    }

    for v in vulns.values_mut() {
        add_bare_components(v);
    }
    let vulnerabilities: Vec<Value> = vulns
        .into_iter()
        .map(|(key, v)| vulnerability(&key, v))
        .collect();

    let mut full_product_names: Vec<Value> = repo_ids
        .iter()
        .map(|(repo, id)| {
            let mut p = json!({ "name": product_name(repo), "product_id": id });
            // The VEX product id, so a reader can tell which service this is.
            p["product_identification_helper"] = if repo.starts_with("pkg:") {
                json!({ "purl": repo })
            } else {
                json!({ "x_generic_uris": [{ "namespace": GENERIC_URI_NAMESPACE, "uri": repo }] })
            };
            p
        })
        .collect();
    full_product_names.extend(package_ids.iter().map(|(purl, id)| {
        json!({
            "name": component_name(purl),
            "product_id": id,
            "product_identification_helper": { "purl": purl },
        })
    }));
    let relationships: Vec<Value> = relationships
        .iter()
        .map(|((cid, rid), (purl, repo))| {
            json!({
                "category": "default_component_of",
                "full_product_name": {
                    "name": format!("{} in {}", component_name(purl), product_name(repo)),
                    "product_id": format!("{cid}:{rid}"),
                },
                "product_reference": cid,
                "relates_to_product_reference": rid,
            })
        })
        .collect();

    // The content hash is the last 64 characters of the OpenVEX `@id`.
    let tracking_id = params.doc_id.clone().unwrap_or_else(|| {
        let id = content_id(&statements, params);
        let hash = id.get(id.len().saturating_sub(64)..).unwrap_or(&id);
        format!("fleetreach-vex-{hash}")
    });
    let summary = match &params.supersedes {
        Some(prior) => format!("Generated from a fleet scan; supersedes {prior}."),
        None => "Generated from a fleet scan.".to_string(),
    };
    let version = params.version.max(1).to_string();
    let document = json!({
        "category": "csaf_vex",
        "csaf_version": "2.0",
        "publisher": {
            "category": csaf.category,
            "name": params.author,
            "namespace": csaf.namespace,
        },
        "title": "fleetreach VEX for the fleet's services",
        "notes": [{
            "category": "summary",
            "title": "How the statuses were decided",
            "text": "Generated by fleetreach from a fleet scan. not_affected comes from a sound \
                     signal (a dependency never compiled in, or no call path to the vulnerable \
                     code) or from a reviewed exception, named as such in each impact statement. \
                     Everything else is under_investigation or known_affected.",
        }],
        "tracking": {
            "current_release_date": params.timestamp,
            "generator": {
                "engine": { "name": "fleetreach", "version": env!("CARGO_PKG_VERSION") },
            },
            "id": tracking_id,
            "initial_release_date": params.timestamp,
            "revision_history": [{
                "date": params.timestamp,
                "number": version,
                "summary": summary,
            }],
            "status": "final",
            "version": version,
        },
    });
    let mut product_tree = json!({ "full_product_names": full_product_names });
    if !relationships.is_empty() {
        product_tree["relationships"] = Value::Array(relationships);
    }
    let doc = json!({
        "document": document,
        "product_tree": product_tree,
        "vulnerabilities": vulnerabilities,
    });
    Ok((serde_json::to_string_pretty(&doc)?, left_out.len()))
}

/// A statement's CVE: its own id or an alias.
fn cve_of(s: &Statement) -> Option<&str> {
    std::iter::once(&s.vulnerability.name)
        .chain(&s.vulnerability.aliases)
        .map(String::as_str)
        .find(|id| id.starts_with("CVE-"))
}

/// Name a component on its own (`FR-COMPONENT-5`, not only `FR-COMPONENT-5:FR-PRODUCT-6`)
/// where every repo the document has it in gives it the same status. A scanner looking at a
/// directory has no product to match a relationship against, only the package; where repos
/// disagree, the package alone has no one status and is named only inside each repo.
fn add_bare_components(v: &mut Vuln) {
    let mut by_component: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
    for (status, ids) in &v.status {
        for id in ids {
            if let Some((component, _)) = id.split_once(':') {
                by_component
                    .entry(component.to_string())
                    .or_default()
                    .insert(status);
            }
        }
    }
    let agreed: BTreeSet<String> = by_component
        .into_iter()
        .filter(|(_, statuses)| statuses.len() == 1)
        .map(|(component, _)| component)
        .collect();
    let widen = |ids: &mut BTreeSet<String>| {
        let bare: Vec<String> = ids
            .iter()
            .filter_map(|id| id.split_once(':').map(|(c, _)| c.to_string()))
            .filter(|c| agreed.contains(c))
            .collect();
        ids.extend(bare);
    };
    v.status.values_mut().for_each(&widen);
    v.flags.values_mut().for_each(&widen);
    v.impacts.values_mut().for_each(&widen);
    v.remediations.values_mut().for_each(&widen);
}

fn add_details(v: &mut Vuln, s: &Statement, combined: &str) {
    let notes = s.status_notes.as_deref().unwrap_or_default();
    match s.status {
        "not_affected" => {
            if let Some(label) = &s.justification {
                v.flags
                    .entry(label.clone())
                    .or_default()
                    .insert(combined.to_string());
            }
            let details = match (
                s.reason.as_ref().or(s.impact_statement.as_ref()),
                &s.justification,
            ) {
                (Some(text), _) => format!("{text} ({notes})"),
                (None, Some(label)) => format!("{label}: {notes}"),
                (None, None) => notes.to_string(),
            };
            v.impacts
                .entry(details)
                .or_default()
                .insert(combined.to_string());
        }
        "affected" => {
            let action = s
                .action_statement
                .clone()
                .unwrap_or_else(|| "Upgrade to a fixed version.".to_string());
            let category = if action.starts_with("Upgrade") {
                "vendor_fix"
            } else {
                "none_available"
            };
            v.remediations
                .entry((category, action))
                .or_default()
                .insert(combined.to_string());
        }
        _ => {}
    }
}

fn vulnerability(key: &str, v: Vuln) -> Value {
    let cve = std::iter::once(key.to_string())
        .chain(v.ids.iter().cloned())
        .find(|id| id.starts_with("CVE-"));
    let ids: Vec<Value> = v
        .ids
        .iter()
        .filter(|id| !id.starts_with("CVE-"))
        .map(|id| json!({ "system_name": system_of(id), "text": id }))
        .collect();
    let notes: Vec<Value> = v
        .titles
        .iter()
        .map(|(id, title)| json!({ "category": "description", "title": id, "text": title }))
        .collect();
    let mut out = json!({
        "notes": notes,
        "product_status": v.status,
    });
    if let Some(cve) = cve {
        out["cve"] = json!(cve);
    }
    if !ids.is_empty() {
        out["ids"] = Value::Array(ids);
    }
    if !v.flags.is_empty() {
        out["flags"] = v
            .flags
            .into_iter()
            .map(|(label, ids)| json!({ "label": label, "product_ids": ids }))
            .collect();
    }
    if !v.impacts.is_empty() {
        out["threats"] = v
            .impacts
            .into_iter()
            .map(|(details, ids)| {
                json!({ "category": "impact", "details": details, "product_ids": ids })
            })
            .collect();
    }
    if !v.remediations.is_empty() {
        out["remediations"] = v
            .remediations
            .into_iter()
            .map(|((category, details), ids)| {
                json!({ "category": category, "details": details, "product_ids": ids })
            })
            .collect();
    }
    out
}

/// `urn:fleetreach:product:ledger-svc` reads as `ledger-svc`.
fn product_name(id: &str) -> String {
    id.strip_prefix("urn:fleetreach:product:")
        .unwrap_or(id)
        .to_string()
}

/// `pkg:cargo/time@0.1.45` reads as `time 0.1.45`.
fn component_name(purl: &str) -> String {
    let path = purl.split(['?', '#']).next().unwrap_or(purl);
    let path = path.split_once('/').map_or(path, |(_, rest)| rest);
    match path.rsplit_once('@') {
        Some((name, version)) => format!("{name} {version}"),
        None => path.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_come_from_the_author() {
        assert_eq!(
            namespace_from_author("security@Acme.example").as_deref(),
            Some("https://acme.example")
        );
        assert_eq!(
            namespace_from_author("https://acme.example/").as_deref(),
            Some("https://acme.example")
        );
        assert_eq!(namespace_from_author("Acme Security"), None);
    }

    #[test]
    fn names_read_well() {
        assert_eq!(component_name("pkg:cargo/time@0.1.45"), "time 0.1.45");
        assert_eq!(
            component_name("pkg:npm/%40scope/x@1.0.0"),
            "%40scope/x 1.0.0"
        );
        assert_eq!(
            product_name("urn:fleetreach:product:ledger-svc"),
            "ledger-svc"
        );
    }

    use crate::vex::tests::{finding, occ, params, reach, report};
    use fleetreach_core::ReachVerdict;

    fn csaf(cve_only: bool) -> CsafParams {
        CsafParams {
            namespace: "https://acme.example".to_string(),
            category: "vendor".to_string(),
            cve_only,
        }
    }

    fn doc(r: &FleetReport, cve_only: bool) -> (Value, usize) {
        let (text, left_out) = to_csaf_vex(r, &params(), &csaf(cve_only)).unwrap();
        (serde_json::from_str(&text).unwrap(), left_out)
    }

    fn ids(v: &Value) -> Vec<&str> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect()
    }

    #[test]
    fn two_advisories_for_one_cve_share_an_entry() {
        let mut a = finding("RUSTSEC-2023-0001", vec![occ("app", "foo", "1.0.0", None)]);
        a.aliases = vec!["CVE-2023-0001".to_string()];
        let mut b = finding(
            "GHSA-aaaa-bbbb-cccc",
            vec![occ("svc", "foo", "1.0.0", None)],
        );
        b.aliases = vec!["CVE-2023-0001".to_string()];
        let (d, _) = doc(&report(vec![a, b]), false);
        let vulns = d["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["cve"], "CVE-2023-0001");
        let names: Vec<&str> = vulns[0]["ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["text"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["GHSA-aaaa-bbbb-cccc", "RUSTSEC-2023-0001"]);
        assert_eq!(d["document"]["category"], "csaf_vex");
        assert_eq!(
            d["document"]["publisher"]["namespace"],
            "https://acme.example"
        );
    }

    #[test]
    fn cve_only_leaves_out_advisories_without_one() {
        let mut v = finding("RUSTSEC-2023-0002", vec![occ("app", "foo", "1.0.0", None)]);
        v.aliases = vec![];
        let r = report(vec![v]);
        let (d, left_out) = doc(&r, true);
        assert_eq!(left_out, 1);
        assert!(d["vulnerabilities"].as_array().unwrap().is_empty());
        let (d, left_out) = doc(&r, false);
        assert_eq!(left_out, 0);
        let entry = &d["vulnerabilities"][0];
        assert!(entry.get("cve").is_none());
        assert_eq!(entry["ids"][0]["text"], "RUSTSEC-2023-0002");
        assert_eq!(entry["ids"][0]["system_name"], "RustSec");
    }

    /// A directory scan has no product to match a relationship against, so a package is
    /// also named alone, but only where every repo gives it the same status.
    #[test]
    fn a_component_is_named_alone_only_where_repos_agree() {
        let both = || {
            vec![
                occ("app", "foo", "1.0.0", None),
                occ("svc", "foo", "1.0.0", None),
            ]
        };
        let (d, _) = doc(&report(vec![finding("RUSTSEC-2023-0003", both())]), false);
        let status = &d["vulnerabilities"][0]["product_status"];
        assert_eq!(
            ids(&status["under_investigation"]),
            [
                "FR-COMPONENT-1",
                "FR-COMPONENT-1:FR-PRODUCT-1",
                "FR-COMPONENT-1:FR-PRODUCT-2"
            ]
        );
        assert_eq!(
            d["product_tree"]["relationships"].as_array().unwrap().len(),
            2
        );

        let mut v = finding("RUSTSEC-2023-0003", vec![occ("app", "foo", "1.0.0", None)]);
        v.reachability = Some(reach(ReachVerdict::NotReachable));
        let w = finding("RUSTSEC-2023-0003", vec![occ("svc", "foo", "1.0.0", None)]);
        let (d, _) = doc(&report(vec![v, w]), false);
        let entry = &d["vulnerabilities"][0];
        assert_eq!(
            ids(&entry["product_status"]["known_not_affected"]),
            ["FR-COMPONENT-1:FR-PRODUCT-1"]
        );
        assert_eq!(
            ids(&entry["product_status"]["under_investigation"]),
            ["FR-COMPONENT-1:FR-PRODUCT-2"]
        );
        // The VEX profile: known_not_affected carries a flag and an impact statement.
        assert_eq!(
            entry["flags"][0]["label"],
            "vulnerable_code_not_in_execute_path"
        );
        assert_eq!(entry["threats"][0]["category"], "impact");
    }
}
