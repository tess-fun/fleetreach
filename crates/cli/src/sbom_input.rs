//! SBOMs as a scan input (spec 05, phase 2): `[[repo]] sbom = "build/bom.json"` scans the
//! packages a CycloneDX (1.4 to 1.6) or SPDX 2.3 JSON document lists, instead of the repo's
//! lockfiles. Useful where fleetreach cannot read the build (Gradle without locking, Bazel,
//! in-house tooling) but the build already writes an SBOM.
//!
//! Each component is routed by its package URL to the matcher of its ecosystem, in the name
//! form that matcher expects (`group:artifact` for Maven, `@scope/name` for npm, lowercase
//! for NuGet and Composer). Direct dependencies are the ones the document's root depends on;
//! without a dependency graph everything counts as transitive. Coverage is full only when a
//! CycloneDX document asserts its root is `complete`; SPDX has no such assertion, so an SPDX
//! input is always partial. Components without a purl, or of a type no matcher covers from an
//! SBOM (`cargo` and `golang` are read from their lockfiles; `githubactions`; container or OS
//! packages), are counted and named, never silently dropped.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fleetreach_core::{DepGraph, Ecosystem};

/// One routed package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomPackage {
    pub name: String,
    pub version: String,
    pub direct: bool,
    pub dev: bool,
}

/// Everything an SBOM yields for scanning.
#[derive(Debug, Default)]
pub struct SbomInput {
    pub packages: BTreeMap<Ecosystem, Vec<SbomPackage>>,
    pub graph: DepGraph,
    /// The document asserts it lists everything (CycloneDX `compositions`).
    pub complete: bool,
    /// Components that were not routed, e.g. `cargo (12)`, `no purl (3)`.
    pub unrouted: Vec<String>,
}

/// A parsed package URL: ecosystem and the matcher's name form, and the version.
fn route(purl: &str) -> Result<(Ecosystem, String, String), String> {
    let rest = purl.strip_prefix("pkg:").ok_or("not a purl")?;
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let (ty, path) = rest.split_once('/').ok_or("purl without a name")?;
    let (path, version) = path.rsplit_once('@').ok_or("purl without a version")?;
    let version = decode(version);
    let segments: Vec<String> = path.split('/').map(decode).collect();
    let joined = segments.join("/");
    let eco = match ty.to_ascii_lowercase().as_str() {
        "npm" => (Ecosystem::Npm, joined),
        "pypi" => (Ecosystem::Pypi, joined),
        "gem" => (Ecosystem::RubyGems, joined),
        "composer" => (Ecosystem::Packagist, joined.to_lowercase()),
        "nuget" => (Ecosystem::NuGet, joined.to_lowercase()),
        "maven" if segments.len() == 2 => {
            (Ecosystem::Maven, format!("{}:{}", segments[0], segments[1]))
        }
        "hex" => (Ecosystem::Hex, joined),
        "julia" => (Ecosystem::Julia, joined),
        "swift" => (Ecosystem::Swift, joined),
        other => return Err(other.to_string()),
    };
    Ok((eco.0, eco.1, version))
}

fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Read an SBOM file.
///
/// # Errors
///
/// When the file cannot be read, is not JSON, or is neither CycloneDX nor SPDX: failing
/// closed (the repo becomes an errored gap).
pub fn read(path: &Path) -> Result<SbomInput, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let doc: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: not JSON: {e}", path.display()))?;
    if doc.get("bomFormat").and_then(|v| v.as_str()) == Some("CycloneDX") {
        Ok(cyclonedx(&doc))
    } else if doc.get("spdxVersion").is_some() {
        Ok(spdx(&doc))
    } else {
        Err(format!(
            "{}: neither a CycloneDX nor an SPDX JSON document",
            path.display()
        ))
    }
}

/// Accumulates routed packages by reference.
#[derive(Default)]
struct Builder {
    /// ref -> (ecosystem, name, version, dev)
    by_ref: BTreeMap<String, (Ecosystem, String, String, bool)>,
    unrouted: BTreeMap<String, usize>,
}

impl Builder {
    fn add(&mut self, reference: String, purl: Option<&str>, dev: bool) {
        match purl.map(route) {
            Some(Ok((eco, name, version))) => {
                self.by_ref.insert(reference, (eco, name, version, dev));
            }
            Some(Err(ty)) => *self.unrouted.entry(ty).or_default() += 1,
            None => *self.unrouted.entry("no purl".into()).or_default() += 1,
        }
    }

    fn finish(
        self,
        root_deps: &BTreeSet<String>,
        edges: &[(String, String)],
        complete: bool,
    ) -> SbomInput {
        const ROOT: &str = "(root)";
        let mut graph = DepGraph::new(ROOT);
        let name_of = |r: &str| self.by_ref.get(r).map(|(_, n, _, _)| n.clone());
        // Root edges come in `root_deps`; the rest link two routed packages.
        for (from, to) in edges {
            if let (Some(from_name), Some(to_name)) = (name_of(from), name_of(to)) {
                graph.add_edges(&from_name, [to_name]);
            }
        }
        for r in root_deps {
            if let Some(n) = name_of(r) {
                graph.add_edges(ROOT, [n]);
            }
        }
        let mut packages: BTreeMap<Ecosystem, Vec<SbomPackage>> = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for (r, (eco, name, version, dev)) in &self.by_ref {
            if !seen.insert((*eco, name.clone(), version.clone())) {
                continue;
            }
            packages.entry(*eco).or_default().push(SbomPackage {
                name: name.clone(),
                version: version.clone(),
                direct: root_deps.contains(r),
                dev: *dev,
            });
        }
        SbomInput {
            packages,
            graph,
            complete,
            unrouted: self
                .unrouted
                .into_iter()
                .map(|(ty, n)| format!("{ty} ({n})"))
                .collect(),
        }
    }
}

fn cyclonedx(doc: &serde_json::Value) -> SbomInput {
    let mut b = Builder::default();
    fn walk(list: Option<&serde_json::Value>, b: &mut Builder) {
        for c in list.and_then(|v| v.as_array()).into_iter().flatten() {
            let purl = c.get("purl").and_then(|v| v.as_str());
            let reference = c
                .get("bom-ref")
                .and_then(|v| v.as_str())
                .or(purl)
                .unwrap_or_default()
                .to_string();
            let dev = c.get("scope").and_then(|v| v.as_str()) == Some("excluded");
            if c.get("type").and_then(|v| v.as_str()) != Some("application") || purl.is_some() {
                b.add(reference, purl, dev);
            }
            walk(c.get("components"), b);
        }
    }
    walk(doc.get("components"), &mut b);
    let root = doc
        .pointer("/metadata/component/bom-ref")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let mut edges = Vec::new();
    let mut root_deps = BTreeSet::new();
    for d in doc
        .get("dependencies")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let Some(from) = d.get("ref").and_then(|v| v.as_str()) else {
            continue;
        };
        for to in d
            .get("dependsOn")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let Some(to) = to.as_str() else { continue };
            if from == root {
                root_deps.insert(to.to_string());
            } else {
                edges.push((from.to_string(), to.to_string()));
            }
        }
    }
    let complete = doc
        .get("compositions")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .any(|c| {
            c.get("aggregate").and_then(|a| a.as_str()) == Some("complete")
                && c.get("assemblies")
                    .and_then(|a| a.as_array())
                    .is_some_and(|a| a.iter().any(|r| r.as_str() == Some(root.as_str())))
        });
    b.finish(&root_deps, &edges, complete && !root.is_empty())
}

fn spdx(doc: &serde_json::Value) -> SbomInput {
    let mut b = Builder::default();
    for p in doc
        .get("packages")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let id = p
            .get("SPDXID")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let purl = p
            .get("externalRefs")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .find(|r| r.get("referenceType").and_then(|t| t.as_str()) == Some("purl"))
            .and_then(|r| r.get("referenceLocator").and_then(|l| l.as_str()));
        // The described root package is the project, not a dependency.
        let described = doc
            .get("documentDescribes")
            .and_then(|v| v.as_array())
            .is_some_and(|d| d.iter().any(|x| x.as_str() == Some(id.as_str())));
        if !described {
            b.add(id, purl, false);
        }
    }
    let mut roots: BTreeSet<String> = doc
        .get("documentDescribes")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|x| x.as_str().map(str::to_string))
        .collect();
    let mut edges = Vec::new();
    for r in doc
        .get("relationships")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let (Some(a), Some(kind), Some(z)) = (
            r.get("spdxElementId").and_then(|v| v.as_str()),
            r.get("relationshipType").and_then(|v| v.as_str()),
            r.get("relatedSpdxElement").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        match kind {
            "DESCRIBES" => {
                roots.insert(z.to_string());
            }
            "DEPENDS_ON" => edges.push((a.to_string(), z.to_string())),
            "DEPENDENCY_OF" => edges.push((z.to_string(), a.to_string())),
            _ => {}
        }
    }
    let root_deps: BTreeSet<String> = edges
        .iter()
        .filter(|(from, _)| roots.contains(from))
        .map(|(_, to)| to.clone())
        .collect();
    let edges: Vec<(String, String)> = edges
        .into_iter()
        .filter(|(f, _)| !roots.contains(f))
        .collect();
    b.finish(&root_deps, &edges, false)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn purls_route_to_the_matchers_name_form() {
        assert_eq!(
            route("pkg:npm/%40types/node@20.0.0").unwrap(),
            (Ecosystem::Npm, "@types/node".into(), "20.0.0".into())
        );
        assert_eq!(
            route("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar").unwrap(),
            (
                Ecosystem::Maven,
                "org.apache.logging.log4j:log4j-core".into(),
                "2.14.1".into()
            )
        );
        assert_eq!(
            route("pkg:nuget/Newtonsoft.Json@12.0.1").unwrap().1,
            "newtonsoft.json"
        );
        assert_eq!(
            route("pkg:composer/Monolog/Monolog@3.5.0").unwrap().1,
            "monolog/monolog"
        );
        assert_eq!(route("pkg:cargo/serde@1.0.0").unwrap_err(), "cargo");
        assert!(route("pkg:npm/left-pad").is_err(), "no version");
    }

    #[test]
    fn cyclonedx_direct_dev_and_completeness() {
        let doc: serde_json::Value = serde_json::from_str(r#"{
          "bomFormat": "CycloneDX", "specVersion": "1.6",
          "metadata": { "component": { "type": "application", "bom-ref": "root", "name": "app" } },
          "components": [
            { "type": "library", "bom-ref": "a", "purl": "pkg:npm/express@4.17.1" },
            { "type": "library", "bom-ref": "b", "purl": "pkg:npm/qs@6.5.2" },
            { "type": "library", "bom-ref": "t", "purl": "pkg:npm/jest@29.0.0", "scope": "excluded" },
            { "type": "library", "bom-ref": "c", "purl": "pkg:cargo/serde@1.0.0" },
            { "type": "library", "bom-ref": "x", "name": "vendored" }
          ],
          "dependencies": [
            { "ref": "root", "dependsOn": ["a", "t"] },
            { "ref": "a", "dependsOn": ["b"] }
          ],
          "compositions": [ { "aggregate": "complete", "assemblies": ["root"] } ]
        }"#).unwrap();
        let input = cyclonedx(&doc);
        let npm = &input.packages[&Ecosystem::Npm];
        let get = |n: &str| npm.iter().find(|p| p.name == n).unwrap();
        assert!(get("express").direct && !get("express").dev);
        assert!(!get("qs").direct);
        assert!(get("jest").dev);
        assert!(input.complete);
        assert_eq!(input.unrouted, vec!["cargo (1)", "no purl (1)"]);
        assert_eq!(input.graph.chain_to("qs"), vec!["(root)", "express", "qs"]);
    }

    #[test]
    fn spdx_relationships_give_the_graph_and_coverage_is_partial() {
        let doc: serde_json::Value = serde_json::from_str(r#"{
          "spdxVersion": "SPDX-2.3",
          "documentDescribes": ["SPDXRef-root"],
          "packages": [
            { "SPDXID": "SPDXRef-root", "name": "app" },
            { "SPDXID": "SPDXRef-a", "name": "requests", "externalRefs": [ { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.19.0" } ] },
            { "SPDXID": "SPDXRef-b", "name": "urllib3", "externalRefs": [ { "referenceType": "purl", "referenceLocator": "pkg:pypi/urllib3@1.24.1" } ] }
          ],
          "relationships": [
            { "spdxElementId": "SPDXRef-root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-a" },
            { "spdxElementId": "SPDXRef-b", "relationshipType": "DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-a" }
          ]
        }"#).unwrap();
        let input = spdx(&doc);
        let pypi = &input.packages[&Ecosystem::Pypi];
        assert!(pypi.iter().find(|p| p.name == "requests").unwrap().direct);
        assert!(!pypi.iter().find(|p| p.name == "urllib3").unwrap().direct);
        assert!(!input.complete);
        assert_eq!(
            input.graph.chain_to("urllib3"),
            vec!["(root)", "requests", "urllib3"]
        );
    }
}
