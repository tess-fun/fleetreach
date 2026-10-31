//! CycloneDX 1.6 JSON SBOM for one repo, from its package inventory.
//!
//! One `library` component per resolved package (deduplicated by purl across the repo's
//! sources), the repo as `metadata.component`, `dependencies[]` from the lockfiles' graphs,
//! and `compositions[]` that say honestly which components come from a complete resolved
//! graph and which from a source read with less than full coverage (a `pom.xml`, unpinned
//! requirements, a project file without restore output).
//!
//! Deterministic: components and edges are sorted, and the `serialNumber` is a UUID derived
//! from the content, so two runs over the same lockfiles produce byte-identical BOMs and diff
//! cleanly. The timestamp is the caller's (pass `None` to omit it).

use std::collections::{BTreeMap, BTreeSet};

use fleetreach_core::inventory::{RepoInventory, ROOT};
use fleetreach_core::{Coverage, Ecosystem};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::vex::purl;

/// The CycloneDX spec version written.
pub const CYCLONEDX_SPEC_VERSION: &str = "1.6";

/// Render `inventory` as a CycloneDX 1.6 JSON BOM.
///
/// # Errors
///
/// Only if serialization fails, which a `Value` tree does not.
pub fn to_cyclonedx(
    inventory: &RepoInventory,
    tool_version: &str,
    timestamp: Option<&str>,
) -> Result<String, serde_json::Error> {
    let root_ref = format!("repo:{}", inventory.repo.0);

    // Components by purl, merged across sources: direct if any source says so, dev only if
    // every source does, and the sources listed.
    struct Merged {
        name: String,
        version: String,
        ecosystem: String,
        direct: bool,
        dev: bool,
        sources: BTreeSet<String>,
        complete: bool,
        license: Option<String>,
    }
    let mut components: BTreeMap<String, Merged> = BTreeMap::new();
    let mut depends: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    depends.entry(root_ref.clone()).or_default();
    for source in &inventory.sources {
        let complete = source.coverage == Coverage::Full;
        // Name -> every purl of that name in this source (a name can resolve at several
        // versions; an edge by name then points at each, an over-approximation).
        let mut by_name: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        for p in &source.packages {
            let id = purl(source.ecosystem, &p.name, &p.version, &p.source);
            by_name
                .entry(p.name.as_str())
                .or_default()
                .insert(id.clone());
            let entry = components.entry(id.clone()).or_insert_with(|| Merged {
                name: p.name.clone(),
                version: p.version.clone(),
                ecosystem: ecosystem_name(source.ecosystem),
                direct: false,
                dev: true,
                sources: BTreeSet::new(),
                complete: true,
                license: None,
            });
            if entry.license.is_none() {
                entry.license.clone_from(&p.license);
            }
            entry.direct |= p.direct;
            entry.dev &= p.dev;
            entry.complete &= complete;
            entry.sources.insert(source.source.clone());
            depends.entry(id.clone()).or_default();
            if p.direct {
                depends.entry(root_ref.clone()).or_default().insert(id);
            }
        }
        for (from, to) in &source.edges {
            let Some(targets) = by_name.get(to.as_str()) else {
                continue;
            };
            let froms: Vec<String> = if from == ROOT {
                vec![root_ref.clone()]
            } else {
                by_name
                    .get(from.as_str())
                    .map(|s| s.iter().cloned().collect())
                    .unwrap_or_default()
            };
            for f in froms {
                let set = depends.entry(f.clone()).or_default();
                set.extend(targets.iter().filter(|t| **t != f).cloned());
            }
        }
    }

    let component_values: Vec<Value> = components
        .iter()
        .map(|(id, c)| {
            let mut component = json!({
                "type": "library",
                "bom-ref": id,
                "name": c.name,
                "version": c.version,
                "purl": id,
                "scope": if c.dev { "excluded" } else { "required" },
                "properties": [
                    { "name": "fleetreach:ecosystem", "value": c.ecosystem },
                    { "name": "fleetreach:direct", "value": c.direct.to_string() },
                    { "name": "fleetreach:source",
                      "value": c.sources.iter().cloned().collect::<Vec<_>>().join(", ") },
                ],
            });
            if let Some(license) = &c.license {
                // An SPDX expression goes in `expression`; anything else is a license name.
                let entry =
                    if spdx::Expression::parse_mode(license, spdx::ParseMode::STRICT).is_ok() {
                        json!([{ "expression": license }])
                    } else {
                        json!([{ "license": { "name": license } }])
                    };
                component["licenses"] = entry;
            }
            component
        })
        .collect();

    let dependency_values: Vec<Value> = depends
        .iter()
        .map(|(r, on)| json!({ "ref": r, "dependsOn": on.iter().collect::<Vec<_>>() }))
        .collect();

    // Complete: every component whose sources are all full coverage, and the repo itself
    // when nothing was incomplete or unreadable.
    let (complete, incomplete): (Vec<&String>, Vec<&String>) = components
        .iter()
        .map(|(id, c)| (id, c.complete))
        .fold((Vec::new(), Vec::new()), |(mut yes, mut no), (id, ok)| {
            if ok {
                yes.push(id);
            } else {
                no.push(id);
            }
            (yes, no)
        });
    let repo_complete = inventory.errors.is_empty()
        && inventory
            .sources
            .iter()
            .all(|s| s.coverage == Coverage::Full);
    let mut compositions = Vec::new();
    let mut complete_refs: Vec<&String> = complete;
    let mut incomplete_refs: Vec<&String> = incomplete;
    if repo_complete {
        complete_refs.insert(0, &root_ref);
    } else {
        incomplete_refs.insert(0, &root_ref);
    }
    if !complete_refs.is_empty() {
        compositions.push(json!({ "aggregate": "complete", "assemblies": complete_refs, "dependencies": complete_refs }));
    }
    if !incomplete_refs.is_empty() {
        compositions.push(json!({ "aggregate": "incomplete", "assemblies": incomplete_refs, "dependencies": incomplete_refs }));
    }

    let mut repo_component = Map::new();
    repo_component.insert("type".into(), json!("application"));
    repo_component.insert("bom-ref".into(), json!(root_ref));
    repo_component.insert("name".into(), json!(inventory.repo.0));
    if let Some(commit) = &inventory.commit {
        repo_component.insert("version".into(), json!(commit));
    }
    if let Some(url) = &inventory.url {
        repo_component.insert(
            "externalReferences".into(),
            json!([{ "type": "vcs", "url": url }]),
        );
    }
    let mut properties: Vec<Value> = Vec::new();
    for source in &inventory.sources {
        properties.push(json!({ "name": "fleetreach:source", "value": format!("{} ({}, {})", source.source, ecosystem_name(source.ecosystem), source.coverage.label()) }));
        for reason in &source.coverage_reasons {
            properties.push(json!({ "name": "fleetreach:coverage-gap", "value": reason }));
        }
    }
    for error in &inventory.errors {
        properties.push(json!({ "name": "fleetreach:unread", "value": error }));
    }
    if !properties.is_empty() {
        repo_component.insert("properties".into(), Value::Array(properties));
    }

    let mut metadata = Map::new();
    if let Some(ts) = timestamp {
        metadata.insert("timestamp".into(), json!(ts));
    }
    metadata.insert(
        "tools".into(),
        json!({ "components": [{ "type": "application", "name": "fleetreach", "version": tool_version }] }),
    );
    metadata.insert("component".into(), Value::Object(repo_component));

    let mut bom = Map::new();
    bom.insert("bomFormat".into(), json!("CycloneDX"));
    bom.insert("specVersion".into(), json!(CYCLONEDX_SPEC_VERSION));
    bom.insert("version".into(), json!(1));
    bom.insert("metadata".into(), Value::Object(metadata));
    bom.insert("components".into(), Value::Array(component_values));
    bom.insert("dependencies".into(), Value::Array(dependency_values));
    bom.insert("compositions".into(), Value::Array(compositions));

    // The serial number hashes the content (not the timestamp), so it is stable.
    let mut hashed = bom.clone();
    if let Some(Value::Object(meta)) = hashed.get_mut("metadata") {
        meta.remove("timestamp");
    }
    let digest = Sha256::digest(serde_json::to_vec(&hashed)?);
    bom.insert(
        "serialNumber".into(),
        json!(format!("urn:uuid:{}", uuid_v8(&digest))),
    );
    serde_json::to_string_pretty(&Value::Object(bom))
}

/// The ecosystem's stable report name (`npm`, `pypi`, `github-actions`, ...).
fn ecosystem_name(ecosystem: Ecosystem) -> String {
    serde_json::to_value(ecosystem)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// An RFC 9562 version-8 (custom) UUID from the first 16 bytes of a hash.
fn uuid_v8(hash: &[u8]) -> String {
    let mut b = [0u8; 16];
    b.copy_from_slice(&hash[..16]);
    b[6] = (b[6] & 0x0f) | 0x80;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use fleetreach_core::inventory::{Package, SourceInventory};
    use fleetreach_core::{DepGraph, RepoId};

    fn inventory() -> RepoInventory {
        let mut graph = DepGraph::new("app");
        graph.add_edges("app", ["express"]);
        graph.add_edges("express", ["qs"]);
        let npm = SourceInventory::new(
            Ecosystem::Npm,
            "package-lock.json",
            vec![
                Package::new("express", "4.18.2", true, false),
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

    fn bom() -> Value {
        serde_json::from_str(
            &to_cyclonedx(&inventory(), "1.2.0", Some("2026-10-30T00:00:00Z")).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn components_carry_purls_scope_and_provenance() {
        let bom = bom();
        assert_eq!(bom["specVersion"], "1.6");
        let purls: Vec<&str> = bom["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["purl"].as_str().unwrap())
            .collect();
        assert_eq!(
            purls,
            vec![
                "pkg:maven/org.slf4j/slf4j-api@2.0.9",
                "pkg:npm/%40types/node@20.0.0",
                "pkg:npm/express@4.18.2",
                "pkg:npm/qs@6.11.0",
            ]
        );
        let types_node = &bom["components"][1];
        assert_eq!(types_node["scope"], "excluded");
        assert_eq!(bom["metadata"]["component"]["version"], "abc123");
        assert_eq!(
            bom["metadata"]["component"]["externalReferences"][0]["url"],
            "https://github.com/acme/app"
        );
    }

    #[test]
    fn dependencies_follow_the_graph_and_compositions_are_honest() {
        let bom = bom();
        let deps: BTreeMap<String, Vec<String>> = bom["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| {
                (
                    d["ref"].as_str().unwrap().to_string(),
                    d["dependsOn"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x.as_str().unwrap().to_string())
                        .collect(),
                )
            })
            .collect();
        assert_eq!(
            deps["repo:acme/app"],
            vec![
                "pkg:maven/org.slf4j/slf4j-api@2.0.9",
                "pkg:npm/%40types/node@20.0.0",
                "pkg:npm/express@4.18.2"
            ]
        );
        assert_eq!(deps["pkg:npm/express@4.18.2"], vec!["pkg:npm/qs@6.11.0"]);
        assert!(deps["pkg:npm/qs@6.11.0"].is_empty());

        let compositions = bom["compositions"].as_array().unwrap();
        let incomplete = compositions
            .iter()
            .find(|c| c["aggregate"] == "incomplete")
            .unwrap();
        let refs: Vec<&str> = incomplete["assemblies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect();
        assert_eq!(
            refs,
            vec!["repo:acme/app", "pkg:maven/org.slf4j/slf4j-api@2.0.9"]
        );
    }

    #[test]
    fn output_is_deterministic_and_the_serial_ignores_the_timestamp() {
        let a = to_cyclonedx(&inventory(), "1.2.0", Some("2026-10-30T00:00:00Z")).unwrap();
        let b = to_cyclonedx(&inventory(), "1.2.0", Some("2026-10-30T00:00:00Z")).unwrap();
        assert_eq!(a, b);
        let c: Value =
            serde_json::from_str(&to_cyclonedx(&inventory(), "1.2.0", None).unwrap()).unwrap();
        assert_eq!(c["serialNumber"], bom()["serialNumber"]);
        let serial = c["serialNumber"].as_str().unwrap();
        assert!(
            serial.starts_with("urn:uuid:") && serial.len() == 45,
            "{serial}"
        );
        assert_eq!(&serial[23..24], "8", "version-8 UUID: {serial}");
    }
}
