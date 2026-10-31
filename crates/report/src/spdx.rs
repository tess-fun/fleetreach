//! SPDX 2.3 JSON SBOM for one repo, from the same merged inventory as the CycloneDX BOM.
//!
//! The repo is the described package (`DESCRIBES`), each resolved package an SPDX package
//! with its purl as a `PACKAGE-MANAGER` external reference, and the lockfiles' graph becomes
//! `DEPENDS_ON` relationships (`DEV_DEPENDENCY_OF` for a dev-only direct dependency). SPDX 2.3
//! has no composition model, so a source read with less than full coverage is named in the
//! document and package comments instead. With a scan report, each affected package gets a
//! `SECURITY` / `advisory` reference per finding, its state in the reference's comment.
//!
//! Deterministic like the CycloneDX output: package ids hash the purl, and the namespace is a
//! UUID derived from the content without the creation time.

use std::collections::BTreeMap;

use fleetreach_core::inventory::RepoInventory;
use fleetreach_core::FleetReport;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::cyclonedx::{advisory_url, bom_vulns, ecosystem_name, merge, uuid_v8, VulnState};

/// The SPDX spec version written.
pub const SPDX_VERSION: &str = "SPDX-2.3";

/// Render `inventory` as an SPDX 2.3 JSON document. `created` is the creation time
/// (RFC 3339, required by SPDX); `report`, when given, adds this repo's findings as security
/// references on the packages they affect.
///
/// # Errors
///
/// Only if serialization fails, which a `Value` tree does not.
pub fn to_spdx(
    inventory: &RepoInventory,
    report: Option<&FleetReport>,
    tool_version: &str,
    created: &str,
) -> Result<String, serde_json::Error> {
    let merged = merge(inventory);
    let root_id = "SPDXRef-Repo".to_string();
    let ids: BTreeMap<&str, String> = merged
        .components
        .keys()
        .map(|purl| (purl.as_str(), package_id(purl)))
        .collect();
    let id_of = |r: &str| {
        if r == merged.root_ref {
            Some(root_id.clone())
        } else {
            ids.get(r).cloned()
        }
    };

    let mut advisories: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    if let Some(report) = report {
        for v in bom_vulns(inventory, &merged, report) {
            let state = match v.state {
                VulnState::Exploitable => "exploitable (a static call graph reaches it)",
                VulnState::InTriage => "in triage (no sound reachability verdict)",
                VulnState::NotPresent => "not affected (not compiled into the build)",
                VulnState::NotReachable => "not affected (no static call path)",
            };
            let mut comment = format!("{}: {}; severity {}", v.finding.advisory_id, state, {
                serde_json::to_value(v.finding.severity)
                    .ok()
                    .and_then(|s| s.as_str().map(str::to_string))
                    .unwrap_or_default()
            });
            if v.finding.exploit.kev {
                comment.push_str("; in CISA KEV");
            }
            if let Some(outcome) = v.ssvc {
                comment.push_str(&format!("; SSVC {outcome}"));
            }
            for r in &v.refs {
                advisories.entry(r.clone()).or_default().push(json!({
                    "referenceCategory": "SECURITY",
                    "referenceType": "advisory",
                    "referenceLocator": advisory_url(v.finding),
                    "comment": comment,
                }));
            }
        }
    }

    let mut repo_package = json!({
        "SPDXID": root_id,
        "name": inventory.repo.0,
        "downloadLocation": match (&inventory.url, &inventory.commit) {
            (Some(url), Some(commit)) => format!("git+{url}@{commit}"),
            (Some(url), None) => format!("git+{url}"),
            _ => "NOASSERTION".to_string(),
        },
        "filesAnalyzed": false,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
    });
    if let Some(commit) = &inventory.commit {
        repo_package["versionInfo"] = json!(commit);
    }
    let mut notes: Vec<String> = inventory
        .sources
        .iter()
        .map(|s| {
            format!(
                "source {} ({}, {})",
                s.source,
                ecosystem_name(s.ecosystem),
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
        repo_package["comment"] = json!(notes.join("\n"));
    }

    let mut packages = vec![repo_package];
    for (purl, c) in &merged.components {
        let license = c
            .license
            .as_deref()
            .filter(|l| spdx::Expression::parse_mode(l, spdx::ParseMode::STRICT).is_ok());
        let mut refs = vec![json!({
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl,
        })];
        refs.extend(advisories.remove(purl.as_str()).unwrap_or_default());
        let mut package = json!({
            "SPDXID": ids[purl.as_str()],
            "name": c.name,
            "versionInfo": c.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": license.unwrap_or("NOASSERTION"),
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": refs,
        });
        let mut comment = vec![format!(
            "{}; {}{}; from {}",
            ecosystem_name(c.ecosystem),
            if c.direct { "direct" } else { "transitive" },
            if c.dev { ", dev only" } else { "" },
            c.sources.iter().cloned().collect::<Vec<_>>().join(", ")
        )];
        if !c.complete {
            comment.push("from a source read with less than full coverage".to_string());
        }
        if let (Some(l), None) = (&c.license, license) {
            comment.push(format!("license as found: {l}"));
        }
        package["comment"] = json!(comment.join("; "));
        packages.push(package);
    }

    let mut relationships = vec![json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_id,
    })];
    for (from, on) in &merged.depends {
        let Some(from_id) = id_of(from) else { continue };
        for to in on {
            let Some(to_id) = id_of(to) else { continue };
            let dev_direct = from == &merged.root_ref && merged.components[to].dev;
            relationships.push(if dev_direct {
                json!({
                    "spdxElementId": to_id,
                    "relationshipType": "DEV_DEPENDENCY_OF",
                    "relatedSpdxElement": from_id,
                })
            } else {
                json!({
                    "spdxElementId": from_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": to_id,
                })
            });
        }
    }

    let mut doc = json!({
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("fleetreach SBOM for {}", inventory.repo.0),
        "creationInfo": {
            "creators": [format!("Tool: fleetreach-{tool_version}")],
        },
        "packages": packages,
        "relationships": relationships,
    });
    if !merged.repo_complete {
        doc["comment"] = json!(
            "Incomplete: at least one source was read with less than full coverage or could \
             not be read; see the repo package's comment."
        );
    }
    // The namespace hashes the content (not the creation time), so it is stable.
    let digest = Sha256::digest(serde_json::to_vec(&doc)?);
    doc["documentNamespace"] = json!(format!(
        "https://spdx.org/spdxdocs/fleetreach/{}-{}",
        namespace_segment(&inventory.repo.0),
        uuid_v8(&digest)
    ));
    doc["creationInfo"]["created"] = json!(created);
    serde_json::to_string_pretty(&doc)
}

/// `SPDXRef-Package-<12 hex of the purl's SHA-256>`: stable across runs and package sets.
fn package_id(purl: &str) -> String {
    let digest = Sha256::digest(purl.as_bytes());
    let hex: String = digest[..6].iter().map(|b| format!("{b:02x}")).collect();
    format!("SPDXRef-Package-{hex}")
}

/// A repo id as one URI path segment.
fn namespace_segment(id: &str) -> String {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use fleetreach_core::inventory::{Package, SourceInventory};
    use fleetreach_core::{Coverage, DepGraph, Ecosystem, RepoId};

    fn inventory() -> RepoInventory {
        let mut graph = DepGraph::new("app");
        graph.add_edges("app", ["express", "@types/node"]);
        graph.add_edges("express", ["qs"]);
        let mut express = Package::new("express", "4.18.2", true, false);
        express.license = Some("MIT".into());
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
        serde_json::from_str(&to_spdx(&inventory(), None, "1.5.0", created).unwrap()).unwrap()
    }

    #[test]
    fn packages_carry_purls_and_the_graph_becomes_relationships() {
        let doc = doc("2026-10-31T00:00:00Z");
        assert_eq!(doc["spdxVersion"], "SPDX-2.3");
        let packages = doc["packages"].as_array().unwrap();
        assert_eq!(packages[0]["SPDXID"], "SPDXRef-Repo");
        assert_eq!(
            packages[0]["downloadLocation"],
            "git+https://github.com/acme/app@abc123"
        );
        let by_name = |n: &str| packages.iter().find(|p| p["name"] == n).unwrap();
        let express = by_name("express");
        assert_eq!(
            express["externalRefs"][0]["referenceLocator"],
            "pkg:npm/express@4.18.2"
        );
        assert_eq!(express["licenseDeclared"], "MIT");
        let rel = |kind: &str, a: &Value, b: &Value| {
            doc["relationships"].as_array().unwrap().iter().any(|r| {
                r["relationshipType"] == kind
                    && r["spdxElementId"] == a["SPDXID"]
                    && r["relatedSpdxElement"] == b["SPDXID"]
            })
        };
        assert!(rel("DEPENDS_ON", &packages[0], express));
        assert!(rel("DEPENDS_ON", express, by_name("qs")));
        assert!(rel(
            "DEV_DEPENDENCY_OF",
            by_name("@types/node"),
            &packages[0]
        ));
        assert!(by_name("org.slf4j:slf4j-api")["comment"]
            .as_str()
            .unwrap()
            .contains("less than full coverage"));
        assert!(doc["comment"].as_str().unwrap().starts_with("Incomplete"));
    }

    #[test]
    fn output_is_deterministic_and_the_namespace_ignores_the_creation_time() {
        let a = doc("2026-10-31T00:00:00Z");
        let b = doc("2027-01-01T00:00:00Z");
        assert_eq!(a["documentNamespace"], b["documentNamespace"]);
        assert_eq!(a["packages"], b["packages"]);
        assert!(a["documentNamespace"]
            .as_str()
            .unwrap()
            .starts_with("https://spdx.org/spdxdocs/fleetreach/acme_app-"));
    }
}
