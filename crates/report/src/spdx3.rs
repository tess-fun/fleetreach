//! SPDX 3.0.1 JSON-LD SBOM for one repo, from the same merged inventory as the CycloneDX BOM.
//!
//! One `SpdxDocument` holds a `software_Sbom` whose root is the repo, a `software_Package` per
//! resolved package (purl, version, lockfile hashes as `verifiedUsing`), and the lockfiles'
//! graph as `dependsOn` relationships. SPDX 3 says what 2.3 could not: a relationship carries
//! its `completeness`, so a package read from a source with less than full coverage has
//! `incomplete` edges, and a dev-only direct dependency is a `LifecycleScopedRelationship` with
//! the `development` scope. Declared licenses are `simplelicensing_LicenseExpression` elements.
//!
//! With a scan report each finding is a `security_Vulnerability` and its verdict a VEX
//! relationship to the packages it was found in: `affects` (a call graph reaches it, or a person
//! accepted the risk), `doesNotAffect` (not compiled, no static path, or set aside by a person,
//! with the reason), `underInvestigationFor` otherwise. CVSS 3 and 4 scores and the CISA KEV
//! catalog become their own assessment relationships.
//!
//! Deterministic like the other SBOMs: element ids hash what they name, and the document's
//! namespace is a UUID derived from the content without the creation time.

use std::collections::{BTreeMap, BTreeSet};

use fleetreach_core::inventory::RepoInventory;
use fleetreach_core::FleetReport;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::cyclonedx::{advisory_url, bom_vulns, merge, uuid_v8, BomVuln, VulnState};

/// The SPDX spec version written.
pub const SPDX3_VERSION: &str = "3.0.1";

/// The JSON-LD context every SPDX 3.0.1 document names.
pub const SPDX3_CONTEXT: &str = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld";

/// Stands for the document's namespace until the content is hashed; never in the output.
const BASE: &str = "urn:fleetreach:spdx3-namespace-placeholder#";

/// The one `CreationInfo` every element shares.
const CREATION: &str = "_:creationinfo";

/// Render `inventory` as an SPDX 3.0.1 JSON-LD document. `created` is the creation time
/// (RFC 3339; fractional seconds are dropped, as SPDX dates have none); `report`, when given,
/// adds this repo's findings as vulnerabilities with VEX relationships.
///
/// # Errors
///
/// Only if serialization fails, which a `Value` tree does not.
pub fn to_spdx3(
    inventory: &RepoInventory,
    report: Option<&FleetReport>,
    tool_version: &str,
    created: &str,
) -> Result<String, serde_json::Error> {
    let merged = merge(inventory);
    let id = |kind: &str, of: &str| format!("{BASE}{kind}-{}", short_hash(of));
    let repo_id = format!("{BASE}Repo");
    let package_ids: BTreeMap<&str, String> = merged
        .components
        .keys()
        .map(|purl| (purl.as_str(), id("Package", purl)))
        .collect();
    let id_of = |r: &str| {
        if r == merged.root_ref {
            Some(repo_id.clone())
        } else {
            package_ids.get(r).cloned()
        }
    };
    let element = |kind: &str, spdx_id: &str| json!({ "type": kind, "spdxId": spdx_id, "creationInfo": CREATION });

    let agent_id = format!("{BASE}Agent-fleetreach");
    let tool_id = format!("{BASE}Tool-fleetreach");
    let mut agent = element("SoftwareAgent", &agent_id);
    agent["name"] = json!("fleetreach");
    let mut tool = element("Tool", &tool_id);
    tool["name"] = json!(format!("fleetreach-{tool_version}"));

    let mut repo = element("software_Package", &repo_id);
    repo["name"] = json!(inventory.repo.0);
    repo["software_primaryPurpose"] = json!("application");
    if let Some(url) = &inventory.url {
        repo["software_downloadLocation"] = json!(match &inventory.commit {
            Some(commit) => format!("git+{url}@{commit}"),
            None => format!("git+{url}"),
        });
    }
    if let Some(commit) = &inventory.commit {
        repo["software_packageVersion"] = json!(commit);
    }
    let mut notes: Vec<String> = inventory
        .sources
        .iter()
        .map(|s| {
            format!(
                "source {} ({}, {})",
                s.source,
                fleetreach_core::wire_name(&s.ecosystem),
                s.coverage.label()
            )
        })
        .collect();
    notes.extend(inventory.sources.iter().flat_map(|s| {
        s.coverage_reasons
            .iter()
            .map(|r| format!("coverage gap: {r}"))
    }));
    notes.extend(inventory.errors.iter().map(|e| format!("unread: {e}")));
    if !notes.is_empty() {
        repo["comment"] = json!(notes.join("\n"));
    }

    let mut graph = vec![agent, tool, repo];
    let mut licenses: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (purl, c) in &merged.components {
        let mut package = element("software_Package", &package_ids[purl.as_str()]);
        package["name"] = json!(c.name);
        package["software_packageVersion"] = json!(c.version);
        package["software_packageUrl"] = json!(purl);
        // The same purl as an external identifier too: readers such as sbomqs look only there.
        package["externalIdentifier"] = json!([{
            "type": "ExternalIdentifier",
            "externalIdentifierType": "packageUrl",
            "identifier": purl,
        }]);
        package["software_primaryPurpose"] = json!("library");
        let hashes: Vec<Value> = c
            .checksums
            .iter()
            .filter_map(|h| {
                Some(json!({
                    "type": "Hash",
                    "algorithm": hash_algorithm(h.algorithm)?,
                    "hashValue": h.hex,
                }))
            })
            .collect();
        if !hashes.is_empty() {
            package["verifiedUsing"] = json!(hashes);
        }
        let license = c
            .license
            .as_deref()
            .filter(|l| spdx::Expression::parse_mode(l, spdx::ParseMode::STRICT).is_ok());
        if let Some(l) = license {
            licenses
                .entry(l.to_string())
                .or_default()
                .push(package_ids[purl.as_str()].clone());
        }
        package["comment"] = json!(c.spdx_comment(license));
        graph.push(package);
    }
    for (expression, holders) in &licenses {
        let license_id = id("License", expression);
        let mut license = element("simplelicensing_LicenseExpression", &license_id);
        license["simplelicensing_licenseExpression"] = json!(expression);
        graph.push(license);
        for holder in holders {
            let mut rel = element(
                "Relationship",
                &id("Relationship", &format!("{holder} hasDeclaredLicense")),
            );
            rel["from"] = json!(holder);
            rel["relationshipType"] = json!("hasDeclaredLicense");
            rel["to"] = json!([license_id]);
            graph.push(rel);
        }
    }

    for (from, on) in &merged.depends {
        let Some(from_id) = id_of(from) else { continue };
        let is_root = from == &merged.root_ref;
        let complete = if is_root {
            merged.repo_complete
        } else {
            merged.components.get(from).is_some_and(|c| c.complete)
        };
        let (mut runtime, mut dev) = (Vec::new(), Vec::new());
        for to in on {
            let Some(to_id) = id_of(to) else { continue };
            if is_root && merged.components[to].dev {
                dev.push(to_id);
            } else {
                runtime.push(to_id);
            }
        }
        for (targets, scope) in [(runtime, None), (dev, Some("development"))] {
            if targets.is_empty() {
                continue;
            }
            let key = format!("{from} dependsOn {}", scope.unwrap_or(""));
            let mut rel = match scope {
                Some(scope) => {
                    let mut rel = element("LifecycleScopedRelationship", &id("Relationship", &key));
                    rel["scope"] = json!(scope);
                    rel
                }
                None => element("Relationship", &id("Relationship", &key)),
            };
            rel["from"] = json!(from_id);
            rel["relationshipType"] = json!("dependsOn");
            rel["to"] = json!(targets);
            rel["completeness"] = json!(if complete { "complete" } else { "incomplete" });
            graph.push(rel);
        }
    }

    let mut profiles = vec!["core", "software", "simpleLicensing"];
    if let Some(report) = report {
        let vulns = bom_vulns(inventory, &merged, report);
        if !vulns.is_empty() {
            profiles.push("security");
        }
        let mut written: BTreeSet<String> = BTreeSet::new();
        for v in &vulns {
            let targets: Vec<String> = v.refs.iter().filter_map(|r| id_of(r)).collect();
            if targets.is_empty() {
                continue;
            }
            let f = v.finding;
            let vuln_id = format!("{BASE}Vulnerability-{}", iri_segment(&f.advisory_id));
            if written.insert(vuln_id.clone()) {
                graph.push(vulnerability(v, &vuln_id));
                graph.extend(scores(v, &vuln_id, &targets, &id));
            }
            graph.push(vex_relationship(v, &vuln_id, &targets, &id));
        }
    }

    let sbom_id = format!("{BASE}Sbom");
    // The root as a `describes` relationship as well as `rootElement`, as SPDX 2 readers and
    // sbomqs find the described package.
    let mut describes = element("Relationship", &id("Relationship", "sbom describes"));
    describes["from"] = json!(sbom_id);
    describes["relationshipType"] = json!("describes");
    describes["to"] = json!([repo_id]);
    graph.push(describes);
    let elements: Vec<Value> = graph.iter().map(|e| e["spdxId"].clone()).collect();
    let mut sbom = element("software_Sbom", &sbom_id);
    sbom["software_sbomType"] = json!(["source"]);
    sbom["rootElement"] = json!([repo_id]);
    sbom["element"] = json!(elements);
    sbom["profileConformance"] = json!(profiles);
    let mut document = element("SpdxDocument", &format!("{BASE}Document"));
    document["name"] = json!(format!("fleetreach SBOM for {}", inventory.repo.0));
    document["rootElement"] = json!([sbom_id]);
    document["element"] = json!(std::iter::once(json!(sbom_id))
        .chain(elements)
        .collect::<Vec<_>>());
    document["profileConformance"] = json!(profiles);
    document["dataLicense"] = json!(format!("{BASE}DataLicense"));
    if !merged.repo_complete {
        document["comment"] = json!(
            "Incomplete: at least one source was read with less than full coverage or could \
             not be read; see the repo package's comment and each relationship's completeness."
        );
    }
    let mut data_license = element(
        "simplelicensing_LicenseExpression",
        &format!("{BASE}DataLicense"),
    );
    data_license["simplelicensing_licenseExpression"] = json!("CC0-1.0");

    let mut nodes = vec![
        json!({
            "type": "CreationInfo",
            "@id": CREATION,
            "specVersion": SPDX3_VERSION,
            "createdBy": [agent_id],
            "createdUsing": [tool_id],
            "created": "",
        }),
        document,
        sbom,
        data_license,
    ];
    nodes.extend(graph);
    let doc = json!({ "@context": SPDX3_CONTEXT, "@graph": nodes });

    // The namespace hashes the content (not the creation time), so it is stable.
    let digest = Sha256::digest(serde_json::to_vec(&doc)?);
    let base = format!(
        "https://spdx.org/spdxdocs/fleetreach/{}-{}#",
        namespace_segment(&inventory.repo.0),
        uuid_v8(&digest)
    );
    let mut doc = doc;
    if let Some(info) = doc["@graph"].get_mut(0) {
        info["created"] = json!(whole_seconds(created));
    }
    Ok(serde_json::to_string_pretty(&doc)?.replace(BASE, &base))
}

/// The vulnerability itself: its id (a CVE as `cve`, others as `securityOther`), aliases, and
/// the advisory as a `securityAdvisory` reference.
fn vulnerability(v: &BomVuln<'_>, vuln_id: &str) -> Value {
    let f = v.finding;
    let identifiers: Vec<Value> = std::iter::once(&f.advisory_id)
        .chain(&f.aliases)
        .map(|a| {
            let (kind, locator) = if a.starts_with("CVE-") {
                ("cve", format!("https://www.cve.org/CVERecord?id={a}"))
            } else {
                (
                    "securityOther",
                    format!("https://osv.dev/vulnerability/{a}"),
                )
            };
            json!({
                "type": "ExternalIdentifier",
                "externalIdentifierType": kind,
                "identifier": a,
                "identifierLocator": [locator],
            })
        })
        .collect();
    let mut value = json!({
        "type": "security_Vulnerability",
        "spdxId": vuln_id,
        "creationInfo": CREATION,
        "name": f.advisory_id,
        "externalIdentifier": identifiers,
        "externalRef": [{
            "type": "ExternalRef",
            "externalRefType": "securityAdvisory",
            "locator": [advisory_url(f)],
        }],
    });
    if !f.title.is_empty() {
        value["summary"] = json!(f.title);
    }
    value
}

/// CVSS 3 or 4 from the advisory's vector, and the KEV catalog entry, for the packages it is in.
fn scores(
    v: &BomVuln<'_>,
    vuln_id: &str,
    targets: &[String],
    id: &dyn Fn(&str, &str) -> String,
) -> Vec<Value> {
    let f = v.finding;
    let mut out = Vec::new();
    if let (Some(vector), Some(score)) = (&f.cvss_vector, f.cvss_score) {
        let kind = if vector.starts_with("CVSS:3") {
            Some("security_CvssV3VulnAssessmentRelationship")
        } else if vector.starts_with("CVSS:4") {
            Some("security_CvssV4VulnAssessmentRelationship")
        } else {
            None
        };
        if let Some(kind) = kind {
            out.push(json!({
                "type": kind,
                "spdxId": id("Assessment", &format!("{vuln_id} cvss")),
                "creationInfo": CREATION,
                "from": vuln_id,
                "relationshipType": "hasAssessmentFor",
                "to": targets,
                // A string: JSON-LD turns a fractional JSON number into a double's lexical
                // form (`7.5E0`), which is not a valid xsd:decimal.
                "security_score": format!("{:.1}", (f64::from(score) * 10.0).round() / 10.0),
                "security_severity": cvss_severity(score),
                "security_vectorString": vector,
            }));
        }
    }
    if f.exploit.kev {
        let cve = std::iter::once(&f.advisory_id)
            .chain(&f.aliases)
            .find(|a| a.starts_with("CVE-"));
        if let Some(cve) = cve {
            out.push(json!({
                "type": "security_ExploitCatalogVulnAssessmentRelationship",
                "spdxId": id("Assessment", &format!("{vuln_id} kev")),
                "creationInfo": CREATION,
                "from": vuln_id,
                "relationshipType": "hasAssessmentFor",
                "to": targets,
                "security_catalogType": "kev",
                "security_exploited": true,
                "security_locator": format!(
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}"
                ),
            }));
        }
    }
    out
}

/// The VEX relationship for one verdict on one advisory.
fn vex_relationship(
    v: &BomVuln<'_>,
    vuln_id: &str,
    targets: &[String],
    id: &dyn Fn(&str, &str) -> String,
) -> Value {
    let (kind, relationship) = match v.state {
        VulnState::Exploitable | VulnState::AcceptedRisk => {
            ("security_VexAffectedVulnAssessmentRelationship", "affects")
        }
        VulnState::InTriage => (
            "security_VexUnderInvestigationVulnAssessmentRelationship",
            "underInvestigationFor",
        ),
        VulnState::NotPresent | VulnState::NotReachable | VulnState::Asserted => (
            "security_VexNotAffectedVulnAssessmentRelationship",
            "doesNotAffect",
        ),
    };
    let mut value = json!({
        "type": kind,
        "spdxId": id("Assessment", &format!("{vuln_id} {:?} {}", v.state, targets.join(" "))),
        "creationInfo": CREATION,
        "from": vuln_id,
        "relationshipType": relationship,
        "to": targets,
    });
    let decided = v.set_aside.map(|d| match &d.approved_by {
        Some(who) => format!("{} (approved by {who})", d.reason),
        None => d.reason.clone(),
    });
    match v.state {
        VulnState::Exploitable => {
            value["security_actionStatement"] =
                json!("Update to a version the advisory lists as fixed; a static call graph reaches the vulnerable code.");
        }
        VulnState::AcceptedRisk => {
            value["security_actionStatement"] = json!(format!(
                "None: the risk is accepted and will not be fixed. {}",
                decided.clone().unwrap_or_default()
            ));
        }
        VulnState::InTriage => {}
        VulnState::NotPresent => {
            value["security_justificationType"] = json!("componentNotPresent");
            value["security_impactStatement"] = json!("Not compiled into the build.");
        }
        VulnState::NotReachable => {
            value["security_justificationType"] = json!("vulnerableCodeNotInExecutePath");
            value["security_impactStatement"] =
                json!("No static call path reaches the vulnerable code.");
        }
        VulnState::Asserted => {
            if let Some(j) = v
                .set_aside
                .and_then(|d| d.justification.as_deref())
                .and_then(justification)
            {
                value["security_justificationType"] = json!(j);
            }
            value["security_impactStatement"] = json!(decided.unwrap_or_default());
        }
    }
    let mut notes = vec![format!("severity {}", v.finding.severity.as_str())];
    if v.finding.exploit.kev {
        notes.push("in CISA KEV".to_string());
    }
    if let Some(outcome) = v.ssvc {
        notes.push(format!("SSVC {outcome}"));
    }
    if v.state == VulnState::InTriage {
        notes.push("no sound reachability verdict".to_string());
    }
    value["security_statusNotes"] = json!(notes.join("; "));
    value
}

/// SPDX 3's justification for an OpenVEX label: the same five, in camel case.
fn justification(openvex: &str) -> Option<&'static str> {
    match openvex {
        "component_not_present" => Some("componentNotPresent"),
        "vulnerable_code_not_present" => Some("vulnerableCodeNotPresent"),
        "vulnerable_code_not_in_execute_path" => Some("vulnerableCodeNotInExecutePath"),
        "vulnerable_code_cannot_be_controlled_by_adversary" => {
            Some("vulnerableCodeCannotBeControlledByAdversary")
        }
        "inline_mitigations_already_exist" => Some("inlineMitigationsAlreadyExist"),
        _ => None,
    }
}

/// The CVSS severity band of a score (CVSS 3.1 and 4.0 use the same bands).
fn cvss_severity(score: f32) -> &'static str {
    match score {
        s if s >= 9.0 => "critical",
        s if s >= 7.0 => "high",
        s if s >= 4.0 => "medium",
        s if s > 0.0 => "low",
        _ => "none",
    }
}

/// SPDX 3's name for a lockfile hash algorithm.
fn hash_algorithm(algorithm: &str) -> Option<&'static str> {
    match algorithm {
        "SHA-1" => Some("sha1"),
        "SHA-256" => Some("sha256"),
        "SHA-384" => Some("sha384"),
        "SHA-512" => Some("sha512"),
        _ => None,
    }
}

/// SPDX 3 dates are `YYYY-MM-DDThh:mm:ssZ`: fractional seconds are not allowed.
fn whole_seconds(created: &str) -> String {
    match (created.find('.'), created.strip_suffix('Z')) {
        (Some(dot), Some(_))
            if created[dot + 1..created.len() - 1]
                .bytes()
                .all(|b| b.is_ascii_digit()) =>
        {
            format!("{}Z", &created[..dot])
        }
        _ => created.to_string(),
    }
}

/// 12 hex of the SHA-256 of `of`: stable across runs and package sets.
fn short_hash(of: &str) -> String {
    Sha256::digest(of.as_bytes())[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// An advisory id as an IRI fragment: letters, digits, `.`, `_` and `-` kept.
fn iri_segment(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// A repo id as one URI path segment.
fn namespace_segment(id: &str) -> String {
    iri_segment(id)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use fleetreach_core::inventory::{Checksum, Package, SourceInventory};
    use fleetreach_core::{Coverage, DepGraph, Ecosystem, RepoId};

    fn inventory() -> RepoInventory {
        let mut graph = DepGraph::new("app");
        graph.add_edges("app", ["express", "@types/node"]);
        graph.add_edges("express", ["qs"]);
        let mut express = Package::new("express", "4.18.2", true, false);
        express.license = Some("MIT".into());
        express.checksums = Checksum::new("SHA-512", &"ab".repeat(64))
            .into_iter()
            .collect();
        let npm = SourceInventory::new(
            Ecosystem::Npm,
            "package-lock.json",
            vec![
                express,
                Package::new("qs", "6.11.0", false, false),
                Package::new("@types/node", "20.0.0", true, true),
            ],
        )
        .with_graph(&graph);
        let maven = SourceInventory::new(
            Ecosystem::Maven,
            "pom.xml",
            vec![Package::new("org.slf4j:slf4j-api", "2.0.9", true, false)],
        )
        .with_gap(Coverage::DirectOnly, "pom.xml: direct only");
        let mut inv = RepoInventory::new(RepoId("acme/app".into()));
        inv.url = Some("https://github.com/acme/app".into());
        inv.commit = Some("abc123".into());
        inv.sources = vec![npm, maven];
        inv
    }

    fn doc(created: &str) -> Value {
        serde_json::from_str(&to_spdx3(&inventory(), None, "1.7.0", created).unwrap()).unwrap()
    }

    fn nodes<'a>(doc: &'a Value, kind: &str) -> Vec<&'a Value> {
        doc["@graph"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["type"] == kind)
            .collect()
    }

    fn package<'a>(doc: &'a Value, name: &str) -> &'a Value {
        nodes(doc, "software_Package")
            .into_iter()
            .find(|p| p["name"] == name)
            .unwrap()
    }

    #[test]
    fn document_sbom_and_creation_info() {
        let doc = doc("2026-11-12T04:46:38.175594Z");
        assert_eq!(doc["@context"], SPDX3_CONTEXT);
        let info = &nodes(&doc, "CreationInfo")[0];
        assert_eq!(info["created"], "2026-11-12T04:46:38Z");
        assert_eq!(info["specVersion"], "3.0.1");
        let sbom = &nodes(&doc, "software_Sbom")[0];
        assert_eq!(sbom["rootElement"][0], package(&doc, "acme/app")["spdxId"]);
        let document = &nodes(&doc, "SpdxDocument")[0];
        assert_eq!(document["rootElement"][0], sbom["spdxId"]);
        assert!(document["comment"]
            .as_str()
            .unwrap()
            .starts_with("Incomplete"));
        // Every element the SBOM lists is in the graph.
        let ids: BTreeSet<&str> = doc["@graph"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|n| n["spdxId"].as_str())
            .collect();
        assert!(sbom["element"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e.as_str().is_some_and(|e| ids.contains(e))));
        assert!(!serde_json::to_string(&doc).unwrap().contains("placeholder"));
    }

    #[test]
    fn packages_hashes_licenses_and_scoped_complete_edges() {
        let doc = doc("2026-11-12T00:00:00Z");
        let express = package(&doc, "express");
        assert_eq!(express["software_packageUrl"], "pkg:npm/express@4.18.2");
        assert_eq!(
            express["externalIdentifier"][0]["identifier"],
            "pkg:npm/express@4.18.2"
        );
        assert!(nodes(&doc, "Relationship")
            .iter()
            .any(|r| r["relationshipType"] == "describes"
                && r["to"][0] == package(&doc, "acme/app")["spdxId"]));
        assert_eq!(express["verifiedUsing"][0]["algorithm"], "sha512");
        let licensed = nodes(&doc, "Relationship")
            .into_iter()
            .find(|r| r["relationshipType"] == "hasDeclaredLicense")
            .unwrap();
        assert_eq!(licensed["from"], express["spdxId"]);
        let license = nodes(&doc, "simplelicensing_LicenseExpression")
            .into_iter()
            .find(|l| l["spdxId"] == licensed["to"][0])
            .unwrap();
        assert_eq!(license["simplelicensing_licenseExpression"], "MIT");

        let repo = package(&doc, "acme/app");
        let depends = |from: &Value| {
            nodes(&doc, "Relationship")
                .into_iter()
                .find(|r| r["relationshipType"] == "dependsOn" && r["from"] == from["spdxId"])
                .unwrap()
        };
        // The repo is incomplete (pom.xml is direct only); express's edges are from a full read.
        assert_eq!(depends(repo)["completeness"], "incomplete");
        assert_eq!(depends(express)["completeness"], "complete");
        assert_eq!(depends(express)["to"][0], package(&doc, "qs")["spdxId"]);
        let dev = &nodes(&doc, "LifecycleScopedRelationship")[0];
        assert_eq!(dev["scope"], "development");
        assert_eq!(dev["to"][0], package(&doc, "@types/node")["spdxId"]);
        assert!(!depends(repo)["to"]
            .as_array()
            .unwrap()
            .contains(&package(&doc, "@types/node")["spdxId"]));
    }

    #[test]
    fn deterministic_and_the_namespace_ignores_the_creation_time() {
        let a = doc("2026-10-31T00:00:00Z");
        let b = doc("2027-01-01T00:00:00Z");
        assert_eq!(a["@graph"][1], b["@graph"][1]);
        assert!(a["@graph"][1]["spdxId"]
            .as_str()
            .unwrap()
            .starts_with("https://spdx.org/spdxdocs/fleetreach/acme_app-"));
    }

    #[test]
    fn findings_become_vulnerabilities_with_vex_relationships() {
        use crate::vex::tests::{finding, occ, report};
        use fleetreach_core::Occurrence;
        let inv = inventory();
        let mut o = occ("acme/app", "express", "4.18.2", None);
        if let Occurrence::InRepo { patched, .. } = &mut o {
            patched.clear();
        }
        let mut f = finding("GHSA-xxxx-yyyy-zzzz", vec![o]);
        f.ecosystem = Ecosystem::Npm;
        f.aliases = vec!["CVE-2024-0001".into()];
        f.cvss_vector = Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".into());
        f.cvss_score = Some(7.5);
        let doc: Value = serde_json::from_str(
            &to_spdx3(
                &inv,
                Some(&report(vec![f])),
                "1.7.0",
                "2026-11-12T00:00:00Z",
            )
            .unwrap(),
        )
        .unwrap();
        let vuln = &nodes(&doc, "security_Vulnerability")[0];
        assert_eq!(
            vuln["externalIdentifier"][1]["externalIdentifierType"],
            "cve"
        );
        let cvss = &nodes(&doc, "security_CvssV3VulnAssessmentRelationship")[0];
        assert_eq!(cvss["security_score"], "7.5");
        assert_eq!(cvss["security_severity"], "high");
        let vex = nodes(
            &doc,
            "security_VexUnderInvestigationVulnAssessmentRelationship",
        );
        assert_eq!(vex[0]["from"], vuln["spdxId"]);
        assert_eq!(vex[0]["to"][0], package(&doc, "express")["spdxId"]);
        assert!(nodes(&doc, "SpdxDocument")[0]["profileConformance"]
            .as_array()
            .unwrap()
            .contains(&json!("security")));
    }
}
