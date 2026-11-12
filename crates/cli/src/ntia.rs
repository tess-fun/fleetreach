//! `sbom --check-ntia`: the NTIA minimum elements (July 2021) checked on the SBOM as written.
//!
//! Each element is read from the document, the way a consumer would, not from the inventory
//! it was built from: author and timestamp once per document; supplier, name, version and a
//! unique identifier (a purl or CPE) for every component, the described one included; and
//! the described component's dependency relationships. A value of `NOASSERTION` or `NONE`
//! counts as absent.
//!
//! CycloneDX JSON, SPDX 2.3 JSON and SPDX 3 JSON-LD are read; CycloneDX XML is checked
//! through the JSON it is converted from, which has the same content.

use serde_json::Value;

/// How many of the components carry one element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Count {
    pub have: usize,
    pub of: usize,
}

impl Count {
    fn add(&mut self, present: bool) {
        self.of += 1;
        self.have += usize::from(present);
    }

    pub fn complete(self) -> bool {
        self.have == self.of
    }
}

/// The minimum elements of one document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Ntia {
    /// Who or what wrote the SBOM data, as the document names it.
    pub author: Option<String>,
    pub timestamp: bool,
    pub supplier: Count,
    pub name: Count,
    pub version: Count,
    pub identifier: Count,
    /// The described component has at least one dependency relationship.
    pub dependencies: bool,
}

impl Ntia {
    /// The elements missing, by their NTIA names; empty when the document meets them all.
    pub fn missing(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.author.is_none() {
            out.push("author of SBOM data".to_string());
        }
        if !self.timestamp {
            out.push("timestamp".to_string());
        }
        for (label, count) in [
            ("supplier name", self.supplier),
            ("component name", self.name),
            ("version", self.version),
            ("other unique identifiers", self.identifier),
        ] {
            if !count.complete() {
                out.push(format!(
                    "{label} ({} of {} components lack it)",
                    count.of - count.have,
                    count.of
                ));
            }
        }
        if !self.dependencies {
            out.push("dependency relationship".to_string());
        }
        out
    }
}

/// Check one SBOM document.
///
/// # Errors
///
/// When the text is not JSON or not a CycloneDX, SPDX 2 or SPDX 3 document.
pub(crate) fn check(text: &str) -> Result<Ntia, String> {
    let doc: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    if doc["bomFormat"] == "CycloneDX" {
        Ok(cyclonedx(&doc))
    } else if doc["spdxVersion"]
        .as_str()
        .is_some_and(|v| v.starts_with("SPDX-2"))
    {
        Ok(spdx2(&doc))
    } else if doc["@context"]
        .as_str()
        .is_some_and(|c| c.starts_with("https://spdx.org/rdf/3."))
    {
        Ok(spdx3(&doc))
    } else {
        Err("not a CycloneDX, SPDX 2 or SPDX 3 document".to_string())
    }
}

/// A value that says something: not empty, `NOASSERTION` or `NONE`.
fn asserted(value: &Value) -> Option<&str> {
    value.as_str().map(str::trim).filter(|s| {
        !s.is_empty() && !s.eq_ignore_ascii_case("NOASSERTION") && !s.eq_ignore_ascii_case("NONE")
    })
}

/// An RFC 3339 date-time, `YYYY-MM-DDThh:mm:ss` and a zone.
fn rfc3339(value: &Value) -> bool {
    let Some(s) = value.as_str() else {
        return false;
    };
    let b = s.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|d| d.iter().all(u8::is_ascii_digit));
    b.len() >= 20
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && matches!(b[10], b'T' | b't')
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19)
        && (s.ends_with('Z') || s.ends_with('z') || {
            let zone = &b[b.len() - 6..];
            matches!(zone[0], b'+' | b'-') && zone[3] == b':'
        })
}

fn arr(value: &Value) -> &[Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}

/// An organization or contact: its name, else an email, else a URL.
fn entity(value: &Value) -> Option<String> {
    asserted(&value["name"])
        .or_else(|| asserted(&value["email"]))
        .or_else(|| {
            arr(&value["contact"])
                .iter()
                .find_map(|c| asserted(&c["name"]).or_else(|| asserted(&c["email"])))
        })
        .or_else(|| arr(&value["url"]).iter().find_map(asserted))
        .map(str::to_string)
}

fn cyclonedx(doc: &Value) -> Ntia {
    let meta = &doc["metadata"];
    let tools = match &meta["tools"] {
        Value::Array(list) => list.clone(),
        tools => [&tools["components"], &tools["services"]]
            .into_iter()
            .flat_map(|v| arr(v).iter().cloned())
            .collect(),
    };
    let author = arr(&meta["authors"])
        .iter()
        .find_map(entity)
        .or_else(|| {
            tools.iter().find_map(|t| {
                asserted(&t["name"]).map(|n| match asserted(&t["version"]) {
                    Some(v) => format!("{n}-{v}"),
                    None => n.to_string(),
                })
            })
        })
        .or_else(|| entity(&meta["supplier"]))
        .or_else(|| entity(&meta["manufacturer"]))
        .or_else(|| entity(&meta["manufacture"]));

    let mut components = Vec::new();
    fn walk<'a>(list: &'a [Value], out: &mut Vec<&'a Value>) {
        for c in list {
            out.push(c);
            walk(arr(&c["components"]), out);
        }
    }
    if meta["component"].is_object() {
        components.push(&meta["component"]);
    }
    walk(arr(&doc["components"]), &mut components);
    let mut ntia = Ntia {
        author,
        timestamp: rfc3339(&meta["timestamp"]),
        ..Ntia::default()
    };
    for c in &components {
        ntia.supplier.add(
            entity(&c["supplier"])
                .or_else(|| entity(&c["manufacturer"]))
                .is_some(),
        );
        ntia.name.add(asserted(&c["name"]).is_some());
        ntia.version.add(asserted(&c["version"]).is_some());
        ntia.identifier
            .add(asserted(&c["purl"]).is_some() || asserted(&c["cpe"]).is_some());
    }
    ntia.dependencies = asserted(&meta["component"]["bom-ref"]).is_some_and(|root| {
        arr(&doc["dependencies"])
            .iter()
            .any(|d| d["ref"] == root && !arr(&d["dependsOn"]).is_empty())
    });
    ntia
}

fn spdx2(doc: &Value) -> Ntia {
    let info = &doc["creationInfo"];
    let author = arr(&info["creators"])
        .iter()
        .filter_map(asserted)
        .filter_map(|c| {
            c.split_once(':')
                .map(|(kind, who)| (kind.trim(), who.trim()))
        })
        .filter(|(_, who)| !who.is_empty())
        // A person or organization first, else the tool.
        .min_by_key(|(kind, _)| kind.eq_ignore_ascii_case("Tool"))
        .map(|(_, who)| who.to_string());
    let mut ntia = Ntia {
        author,
        timestamp: rfc3339(&info["created"]),
        ..Ntia::default()
    };
    for p in arr(&doc["packages"]) {
        let named = |field: &str| {
            asserted(&p[field])
                .and_then(|s| s.split_once(':').map(|(_, who)| who.trim().to_string()))
                .filter(|who| !who.is_empty() && !who.eq_ignore_ascii_case("NOASSERTION"))
        };
        ntia.supplier
            .add(named("supplier").or_else(|| named("originator")).is_some());
        ntia.name.add(asserted(&p["name"]).is_some());
        ntia.version.add(asserted(&p["versionInfo"]).is_some());
        ntia.identifier.add(arr(&p["externalRefs"]).iter().any(|r| {
            matches!(
                r["referenceType"].as_str(),
                Some("purl" | "cpe23Type" | "cpe22Type")
            ) && asserted(&r["referenceLocator"]).is_some()
        }));
    }
    let relationships = arr(&doc["relationships"]);
    let described: Vec<&Value> = relationships
        .iter()
        .filter_map(|r| match r["relationshipType"].as_str() {
            Some("DESCRIBES") if r["spdxElementId"] == "SPDXRef-DOCUMENT" => {
                Some(&r["relatedSpdxElement"])
            }
            Some("DESCRIBED_BY") if r["relatedSpdxElement"] == "SPDXRef-DOCUMENT" => {
                Some(&r["spdxElementId"])
            }
            _ => None,
        })
        .chain(arr(&doc["documentDescribes"]))
        .collect();
    ntia.dependencies = described.iter().any(|root| {
        relationships.iter().any(|r| {
            (r["relationshipType"] == "DEPENDS_ON" && &&r["spdxElementId"] == root)
                || (matches!(
                    r["relationshipType"].as_str(),
                    Some("DEPENDENCY_OF" | "DEV_DEPENDENCY_OF")
                ) && &&r["relatedSpdxElement"] == root)
        })
    });
    ntia
}

fn spdx3(doc: &Value) -> Ntia {
    let graph = arr(&doc["@graph"]);
    let by_id = |id: &Value| graph.iter().find(|n| n["spdxId"] == *id || n["@id"] == *id);
    let creation = graph.iter().find(|n| n["type"] == "CreationInfo");
    let agent_name = |id: &Value| {
        by_id(id)
            .and_then(|a| asserted(&a["name"]))
            .map(str::to_string)
    };
    let author = creation.and_then(|c| {
        arr(&c["createdBy"])
            .iter()
            .find_map(agent_name)
            .or_else(|| arr(&c["createdUsing"]).iter().find_map(agent_name))
    });
    let mut ntia = Ntia {
        author,
        timestamp: creation.is_some_and(|c| rfc3339(&c["created"])),
        ..Ntia::default()
    };
    for p in graph.iter().filter(|n| n["type"] == "software_Package") {
        let agent = |field: &str| {
            arr(&p[field])
                .iter()
                .find_map(agent_name)
                .or_else(|| agent_name(&p[field]))
        };
        ntia.supplier.add(
            agent("suppliedBy")
                .or_else(|| agent("originatedBy"))
                .is_some(),
        );
        ntia.name.add(asserted(&p["name"]).is_some());
        ntia.version
            .add(asserted(&p["software_packageVersion"]).is_some());
        ntia.identifier.add(
            asserted(&p["software_packageUrl"]).is_some()
                || arr(&p["externalIdentifier"]).iter().any(|e| {
                    matches!(
                        e["externalIdentifierType"].as_str(),
                        Some("packageUrl" | "cpe22" | "cpe23")
                    ) && asserted(&e["identifier"]).is_some()
                }),
        );
    }
    let roots: Vec<&Value> = graph
        .iter()
        .filter(|n| n["type"] == "software_Sbom")
        .flat_map(|s| arr(&s["rootElement"]))
        .collect();
    ntia.dependencies = roots.iter().any(|root| {
        graph.iter().any(|r| {
            r["relationshipType"] == "dependsOn" && &&r["from"] == root && !arr(&r["to"]).is_empty()
        })
    });
    ntia
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use serde_json::json;

    #[test]
    fn cyclonedx_counts_every_component_and_the_described_one() {
        let doc = json!({
            "bomFormat": "CycloneDX",
            "metadata": {
                "timestamp": "2026-11-12T00:00:00Z",
                "tools": { "components": [{ "name": "fleetreach", "version": "1.7.0" }] },
                "component": { "bom-ref": "repo:app", "name": "app", "supplier": { "name": "Acme" } }
            },
            "components": [
                { "bom-ref": "a", "name": "a", "version": "1", "purl": "pkg:npm/a@1",
                  "supplier": { "name": "A Inc" } },
                { "bom-ref": "b", "name": "b", "version": "2", "purl": "pkg:npm/b@2" }
            ],
            "dependencies": [{ "ref": "repo:app", "dependsOn": ["a"] }]
        });
        let n = check(&doc.to_string()).unwrap();
        assert_eq!(n.author.as_deref(), Some("fleetreach-1.7.0"));
        assert!(n.timestamp && n.dependencies);
        assert_eq!(n.supplier, Count { have: 2, of: 3 });
        assert_eq!(n.version, Count { have: 2, of: 3 });
        assert_eq!(n.identifier, Count { have: 2, of: 3 });
        let missing = n.missing();
        assert_eq!(missing.len(), 3);
        assert!(missing[0].starts_with("supplier name (1 of 3"));
    }

    #[test]
    fn spdx2_noassertion_is_absent_and_a_person_beats_the_tool() {
        let doc = json!({
            "spdxVersion": "SPDX-2.3",
            "creationInfo": { "created": "2026-11-12T00:00:00Z",
                              "creators": ["Tool: fleetreach-1.7.0", "Organization: Acme"] },
            "packages": [
                { "SPDXID": "SPDXRef-Repo", "name": "app", "versionInfo": "abc",
                  "supplier": "Organization: Acme",
                  "externalRefs": [{ "referenceType": "purl", "referenceLocator": "pkg:github/acme/app@abc" }] },
                { "SPDXID": "SPDXRef-a", "name": "a", "versionInfo": "1", "supplier": "NOASSERTION",
                  "originator": "Person: Ann",
                  "externalRefs": [{ "referenceType": "purl", "referenceLocator": "pkg:npm/a@1" }] },
                { "SPDXID": "SPDXRef-b", "name": "b", "versionInfo": "NOASSERTION", "supplier": "NOASSERTION" }
            ],
            "relationships": [
                { "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Repo" },
                { "spdxElementId": "SPDXRef-b", "relationshipType": "DEV_DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-Repo" }
            ]
        });
        let n = check(&doc.to_string()).unwrap();
        assert_eq!(n.author.as_deref(), Some("Acme"));
        assert_eq!(n.supplier, Count { have: 2, of: 3 });
        assert_eq!(n.version, Count { have: 2, of: 3 });
        assert_eq!(n.identifier, Count { have: 2, of: 3 });
        assert!(n.dependencies);
    }

    #[test]
    fn spdx3_reads_agents_and_root_relationships() {
        let doc = json!({
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [
                { "type": "CreationInfo", "@id": "_:c", "created": "2026-11-12T00:00:00Z",
                  "createdBy": ["x:agent"], "specVersion": "3.0.1" },
                { "type": "SoftwareAgent", "spdxId": "x:agent", "name": "fleetreach" },
                { "type": "software_Sbom", "spdxId": "x:sbom", "rootElement": ["x:repo"] },
                { "type": "software_Package", "spdxId": "x:repo", "name": "app" },
                { "type": "software_Package", "spdxId": "x:a", "name": "a",
                  "software_packageVersion": "1", "software_packageUrl": "pkg:npm/a@1",
                  "suppliedBy": "x:agent" },
                { "type": "Relationship", "spdxId": "x:r", "from": "x:repo",
                  "relationshipType": "dependsOn", "to": ["x:a"] }
            ]
        });
        let n = check(&doc.to_string()).unwrap();
        assert_eq!(n.author.as_deref(), Some("fleetreach"));
        assert!(n.timestamp && n.dependencies);
        assert_eq!(n.supplier, Count { have: 1, of: 2 });
        assert_eq!(n.version, Count { have: 1, of: 2 });
    }

    #[test]
    fn timestamps_must_be_rfc3339() {
        assert!(rfc3339(&json!("2026-11-12T00:00:00Z")));
        assert!(rfc3339(&json!("2026-11-12T00:00:00.5+01:00")));
        assert!(!rfc3339(&json!("2026-11-12")));
        assert!(!rfc3339(&json!("2026-11-12 00:00:00")));
        assert!(check("{}").is_err());
    }
}
