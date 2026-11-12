//! SBOMs as a scan input (spec 05, phase 2): `[[repo]] sbom = "build/bom.json"` scans the
//! packages a CycloneDX (JSON or XML, 1.4 to 1.7), SPDX 2.x (JSON or tag-value) or SPDX 3.0
//! (JSON-LD) document lists, instead of the repo's lockfiles. Useful where fleetreach cannot read the build (Gradle without locking, Bazel,
//! in-house tooling) but the build already writes an SBOM.
//!
//! Each component is routed by its package URL to the matcher of its ecosystem, in the name
//! form that matcher expects (`group:artifact` for Maven, `@scope/name` for npm, lowercase
//! for NuGet and Composer). Direct dependencies are the ones the document's root depends on;
//! without a dependency graph everything counts as transitive. Coverage is full only when a
//! CycloneDX document asserts its root is `complete`, or an SPDX 3 document marks every
//! dependency relationship `complete`; SPDX 2 has no such assertion, so an SPDX 2 input is
//! always partial. Components without a purl, or of a type no matcher covers from an
//! SBOM (`githubactions`, containers), are counted and named, never silently dropped.
//!
//! `pkg:deb`, `pkg:apk` and `pkg:rpm` components go to the distro matchers, as an image's packages
//! do: [`fleetreach_os::purl`] reads the release and each package's source from what the
//! document says, and a document that does not say which release is a coverage gap.
//!
//! XML and tag-value are turned into the JSON shape and read by the same code, so a document
//! yields the same packages in every format. [`discover`] finds SBOMs in a repo with nothing
//! else to read, and [`stale`] says when one predates the lockfiles beside it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fleetreach_core::{DepGraph, Ecosystem};
use fleetreach_os::purl::{self, decode, Component, Hint, SourceHint};
use fleetreach_os::{Family, Inspection};

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
    /// Components that were not routed, e.g. `deb (12)`, `no purl (3)`.
    pub unrouted: Vec<String>,
    /// When the document says it was made, in Unix seconds.
    pub created: Option<i64>,
    /// The OS packages it lists, for the distro matchers.
    pub os: Vec<Component>,
    /// Its operating-system component, name and version.
    pub os_named: Option<(String, String)>,
}

impl SbomInput {
    /// The ecosystem of the OS packages listed, if any.
    pub fn os_ecosystem(&self) -> Option<Ecosystem> {
        self.os.first().map(|c| match c.family {
            Family::Deb => Ecosystem::Deb,
            Family::Apk => Ecosystem::Apk,
            Family::Rpm => Ecosystem::Rpm,
        })
    }

    /// The OS packages listed, as an image's inspection; `None` with none listed.
    pub fn os_inspection(&self) -> Option<Inspection> {
        (!self.os.is_empty()).then(|| purl::inspect(&self.os, self.os_named.as_ref()))
    }
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
        "golang" => (Ecosystem::Go, joined),
        "cargo" => (Ecosystem::Cargo, joined),
        other => return Err(other.to_string()),
    };
    Ok((eco.0, eco.1, version))
}

/// Read an SBOM file.
///
/// # Errors
///
/// When the file cannot be read or is in no format read here: failing closed (the repo
/// becomes an errored gap).
pub fn read(path: &Path) -> Result<SbomInput, String> {
    let text = fleetreach_core::repofile::read_to_string(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn parse(text: &str) -> Result<SbomInput, String> {
    let text = text.trim_start_matches('\u{feff}').trim_start();
    if text.starts_with('<') {
        return Ok(cyclonedx(&cyclonedx_xml(text)?));
    }
    if !text.starts_with('{') {
        return Ok(spdx(&spdx_tag_value(text)?));
    }
    let doc: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    // GitHub's dependency graph export wraps the document.
    let doc = doc.get("sbom").unwrap_or(&doc);
    if doc.get("bomFormat").and_then(|v| v.as_str()) == Some("CycloneDX") {
        Ok(cyclonedx(doc))
    } else if doc.get("spdxVersion").is_some() {
        Ok(spdx(doc))
    } else if is_spdx3(doc) {
        Ok(spdx3(doc))
    } else if doc.get("@context").is_some() {
        Err("a JSON-LD document that is not SPDX 3".to_string())
    } else {
        Err("neither a CycloneDX nor an SPDX JSON document".to_string())
    }
}

/// A CycloneDX XML document in the shape of the JSON one.
fn cyclonedx_xml(text: &str) -> Result<serde_json::Value, String> {
    use roxmltree::Node;
    use serde_json::{json, Value};

    fn child<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
        node.children().find(|c| c.has_tag_name(name))
    }
    fn text_of(node: Node<'_, '_>, name: &str) -> Value {
        let found = child(node, name).and_then(|c| c.text()).map(str::trim);
        found.map_or(Value::Null, Value::from)
    }
    fn elements<'a, 'i>(
        node: Node<'a, 'i>,
        list: &str,
        item: &'a str,
    ) -> impl Iterator<Item = Node<'a, 'i>> {
        child(node, list)
            .into_iter()
            .flat_map(|l| l.children())
            .filter(move |c| c.has_tag_name(item))
    }
    fn component(node: Node<'_, '_>) -> Value {
        let nested: Vec<Value> = elements(node, "components", "component")
            .map(component)
            .collect();
        let properties: Vec<Value> = elements(node, "properties", "property")
            .map(|p| json!({"name": p.attribute("name"), "value": p.text().map(str::trim)}))
            .collect();
        let mut out = json!({
            "type": node.attribute("type"),
            "name": text_of(node, "name"),
            "version": text_of(node, "version"),
            "purl": text_of(node, "purl"),
            "scope": text_of(node, "scope"),
            "properties": properties,
            "components": nested,
        });
        if let Some(reference) = node.attribute("bom-ref") {
            out["bom-ref"] = Value::from(reference);
        }
        out
    }

    let doc = roxmltree::Document::parse(text).map_err(|e| format!("not XML: {e}"))?;
    let root = doc.root_element();
    let namespace = root.tag_name().namespace().unwrap_or("");
    if !namespace.starts_with("http://cyclonedx.org/schema/bom/") {
        return Err(format!(
            "an XML document that is not CycloneDX (root `{}`)",
            root.tag_name().name()
        ));
    }
    let components: Vec<Value> = elements(root, "components", "component")
        .map(component)
        .collect();
    let dependencies: Vec<Value> = elements(root, "dependencies", "dependency")
        .map(|d| {
            let on: Vec<&str> = d
                .children()
                .filter(|c| c.has_tag_name("dependency"))
                .filter_map(|c| c.attribute("ref"))
                .collect();
            json!({"ref": d.attribute("ref"), "dependsOn": on})
        })
        .collect();
    let compositions: Vec<Value> = elements(root, "compositions", "composition")
        .map(|c| {
            let refs: Vec<&str> = elements(c, "assemblies", "assembly")
                .filter_map(|a| a.attribute("ref"))
                .collect();
            json!({"aggregate": text_of(c, "aggregate"), "assemblies": refs})
        })
        .collect();
    let metadata = child(root, "metadata");
    let timestamp = metadata.map_or(Value::Null, |m| text_of(m, "timestamp"));
    let subject = metadata.and_then(|m| child(m, "component"));
    let reference = subject.and_then(|c| c.attribute("bom-ref"));
    Ok(json!({
        "bomFormat": "CycloneDX",
        "metadata": {"timestamp": timestamp, "component": {"bom-ref": reference}},
        "components": components,
        "dependencies": dependencies,
        "compositions": compositions,
    }))
}

/// An SPDX 2.x tag-value document in the shape of the JSON one.
fn spdx_tag_value(text: &str) -> Result<serde_json::Value, String> {
    use serde_json::{json, Value};

    let mut version = None;
    let mut created = None;
    let mut packages: Vec<Value> = Vec::new();
    let mut relationships: Vec<Value> = Vec::new();
    let mut in_package = false;
    let mut in_text = false;
    for line in text.lines() {
        if in_text {
            in_text = !line.contains("</text>");
            continue;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((tag, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.contains("<text>") {
            in_text = !value.contains("</text>");
            continue;
        }
        match tag {
            "SPDXVersion" => version = Some(value.to_string()),
            "Created" => created = Some(value.to_string()),
            "PackageName" => {
                packages.push(json!({"name": value, "externalRefs": []}));
                in_package = true;
            }
            // Every other section opens with one of these, and has an SPDXID of its own.
            "FileName" | "SnippetSPDXID" | "LicenseID" | "Annotator" => in_package = false,
            "SPDXID" if in_package => {
                if let Some(package) = packages.last_mut() {
                    package["SPDXID"] = Value::from(value);
                }
            }
            "PrimaryPackagePurpose" if in_package => {
                if let Some(package) = packages.last_mut() {
                    package["primaryPackagePurpose"] = Value::from(value);
                }
            }
            "PackageVersion" | "PackageSourceInfo" if in_package => {
                let key = if tag == "PackageVersion" {
                    "versionInfo"
                } else {
                    "sourceInfo"
                };
                if let Some(package) = packages.last_mut() {
                    package[key] = Value::from(value);
                }
            }
            "ExternalRef" if in_package => {
                let words: Vec<&str> = value.split_whitespace().collect();
                if let ([_, kind, locator, ..], Some(package)) =
                    (words.as_slice(), packages.last_mut())
                {
                    let reference = json!({"referenceType": kind, "referenceLocator": locator});
                    if let Some(list) = package["externalRefs"].as_array_mut() {
                        list.push(reference);
                    }
                }
            }
            "Relationship" => {
                if let [from, kind, to, ..] = value.split_whitespace().collect::<Vec<_>>()[..] {
                    relationships.push(json!({
                        "spdxElementId": from,
                        "relationshipType": kind,
                        "relatedSpdxElement": to,
                    }));
                }
            }
            _ => {}
        }
    }
    let Some(version) = version else {
        return Err("neither JSON, XML nor SPDX tag-value".to_string());
    };
    Ok(json!({
        "spdxVersion": version,
        "creationInfo": {"created": created},
        "packages": packages,
        "relationships": relationships,
    }))
}

fn timestamp(text: Option<&str>) -> Option<i64> {
    let format = time::format_description::well_known::Rfc3339;
    let at = time::OffsetDateTime::parse(text?, &format).ok()?;
    Some(at.unix_timestamp())
}

/// Reads several SBOMs as one. It is complete only if each of them is.
///
/// # Errors
///
/// As [`read`], for the first that fails.
pub fn read_all(paths: &[std::path::PathBuf]) -> Result<SbomInput, String> {
    let mut merged: Option<SbomInput> = None;
    for path in paths {
        let input = read(path)?;
        merged = Some(match merged {
            Some(so_far) => so_far.merge(input),
            None => input,
        });
    }
    merged.ok_or_else(|| "no SBOM to read".to_string())
}

impl SbomInput {
    fn merge(mut self, other: SbomInput) -> SbomInput {
        for (ecosystem, packages) in other.packages {
            let list = self.packages.entry(ecosystem).or_default();
            for package in packages {
                let same =
                    |p: &&mut SbomPackage| p.name == package.name && p.version == package.version;
                match list.iter_mut().find(same) {
                    Some(known) => {
                        known.direct |= package.direct;
                        known.dev &= package.dev;
                    }
                    None => list.push(package),
                }
            }
        }
        for (from, to) in other.graph.edges() {
            self.graph.add_edges(from, [to]);
        }
        self.complete &= other.complete;
        self.unrouted.extend(other.unrouted);
        self.os.extend(other.os);
        self.os_named = self.os_named.or(other.os_named);
        self.created = match (self.created, other.created) {
            (Some(a), Some(b)) => Some(a.min(b)),
            _ => None,
        };
        self
    }
}

/// Whether a file's name says it is an SBOM.
pub fn looks_like_sbom(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let suffixes = [
        ".cdx.json",
        ".cdx.xml",
        ".spdx.json",
        ".spdx3.json",
        ".spdx",
        ".bom.json",
        ".bom.xml",
        ".sbom.json",
        ".sbom.xml",
        ".sbom",
    ];
    suffixes.iter().any(|s| lower.ends_with(s))
        || matches!(
            lower.as_str(),
            "bom.json" | "bom.xml" | "sbom.json" | "sbom.xml"
        )
}

/// Directories whose SBOMs describe something else, or nothing.
fn skipped_dir(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "node_modules"
            | "vendor"
            | "target"
            | "test"
            | "tests"
            | "testdata"
            | "fixtures"
            | "__fixtures__"
            | "examples"
            | "third_party"
    ) || (name.starts_with('.') && name != ASSET_DIR_PARENT)
}

const ASSET_DIR_PARENT: &str = ".fleetreach";
/// Where release assets land in a checkout, relative to it.
pub const ASSET_DIR: &str = ".fleetreach/sbom";
const MAX_DISCOVERED: usize = 200;
const MAX_DEPTH: usize = 6;

/// The SBOMs in the repo at `dir`, sorted.
pub fn discover(dir: &Path) -> Vec<std::path::PathBuf> {
    let walk = walkdir::WalkDir::new(dir)
        .max_depth(MAX_DEPTH)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| {
            e.depth() == 0
                || !e.file_type().is_dir()
                || !skipped_dir(&e.file_name().to_string_lossy())
        });
    walk.flatten()
        .filter(|e| e.file_type().is_file())
        .filter(|e| looks_like_sbom(&e.file_name().to_string_lossy()))
        .map(walkdir::DirEntry::into_path)
        .take(MAX_DISCOVERED)
        .collect()
}

const LOCKFILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "Gemfile.lock",
    "composer.lock",
    "go.sum",
    "packages.lock.json",
    "mix.lock",
    "Package.resolved",
    "Manifest.toml",
    "gradle.lockfile",
];

/// When the newest commit touching a lockfile was made. `None` outside git, and in a shallow
/// clone, where every file seems to change in the one commit there is.
fn newest_lockfile_commit(dir: &Path) -> Option<i64> {
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .current_dir(dir)
            .args(["-c", "core.fsmonitor=false"])
            .args(args)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    if git(&["rev-parse", "--is-shallow-repository"])? != "false" {
        return None;
    }
    let specs: Vec<String> = LOCKFILES
        .iter()
        .map(|name| format!(":(glob)**/{name}"))
        .collect();
    let mut args = vec!["log", "-1", "--format=%ct", "--"];
    args.extend(specs.iter().map(String::as_str));
    git(&args)?.parse().ok()
}

/// Why an SBOM made at `created` no longer describes the repo at `dir`, if it does not.
pub fn stale(dir: &Path, created: Option<i64>) -> Option<String> {
    let created = created?;
    let changed = newest_lockfile_commit(dir)?;
    (created < changed).then(|| {
        let date = |at: i64| {
            let at = time::OffsetDateTime::from_unix_timestamp(at).ok();
            at.map_or(String::new(), |t| t.date().to_string())
        };
        format!(
            "the SBOM was made on {}, before the last lockfile change on {}",
            date(created),
            date(changed)
        )
    })
}

/// Accumulates routed packages by reference.
#[derive(Default)]
struct Builder {
    /// ref -> (ecosystem, name, version, dev)
    by_ref: BTreeMap<String, (Ecosystem, String, String, bool)>,
    unrouted: BTreeMap<String, usize>,
    os: Vec<Component>,
    os_named: Option<(String, String)>,
}

/// What a CycloneDX component's properties say of an OS package: Trivy's source package, and
/// either tool's modularity label.
fn cyclonedx_hint(component: &serde_json::Value) -> Hint {
    let property = |name: &str| {
        let list = component.get("properties")?.as_array()?;
        let found = list
            .iter()
            .find(|p| p.get("name").and_then(|n| n.as_str()) == Some(name))?;
        found.get("value")?.as_str()
    };
    let version = property("aquasecurity:trivy:SrcVersion").map(|version| {
        let epoch = property("aquasecurity:trivy:SrcEpoch").filter(|e| *e != "0");
        let epoch = epoch.map(|e| format!("{e}:")).unwrap_or_default();
        match property("aquasecurity:trivy:SrcRelease") {
            Some(release) => format!("{epoch}{version}-{release}"),
            None => format!("{epoch}{version}"),
        }
    });
    Hint {
        source: property("aquasecurity:trivy:SrcName").map(|name| SourceHint {
            name: name.to_string(),
            version,
        }),
        module: property("aquasecurity:trivy:Modularitylabel")
            .or_else(|| property("syft:metadata:modularityLabel"))
            .map(str::to_string),
    }
}

/// The source package of an SPDX package, from Trivy's `built package from: openssl 1:3.0.7-1`.
fn spdx_source(package: &serde_json::Value) -> Option<SourceHint> {
    let info = package.get("sourceInfo")?.as_str()?;
    let built = info.strip_prefix("built package from:")?.trim();
    let (name, version) = built.split_once(' ').unwrap_or((built, ""));
    (!name.is_empty()).then(|| SourceHint {
        name: name.to_string(),
        version: (!version.is_empty()).then(|| version.trim().to_string()),
    })
}

impl Builder {
    fn add(&mut self, reference: String, purl: Option<&str>, dev: bool, hint: Hint) {
        if let Some(c) = purl.and_then(|p| purl::component(p, &hint)) {
            self.os.push(c);
            return;
        }
        match purl.map(route) {
            Some(Ok((eco, name, version))) => {
                self.by_ref.insert(reference, (eco, name, version, dev));
            }
            Some(Err(ty)) => *self.unrouted.entry(ty).or_default() += 1,
            None => *self.unrouted.entry("no purl".into()).or_default() += 1,
        }
    }

    /// What the root depends on, looking through what is no package: Trivy puts each lockfile
    /// under the root, and the project's own unversioned module under that, so the direct
    /// dependencies are below both.
    fn through_holders(
        &self,
        root_deps: &BTreeSet<String>,
        edges: &[(String, String)],
    ) -> BTreeSet<String> {
        let mut below: BTreeMap<&str, Vec<&String>> = BTreeMap::new();
        for (from, to) in edges {
            below.entry(from).or_default().push(to);
        }
        let mut out = root_deps.clone();
        let mut pending: Vec<String> = root_deps.iter().cloned().collect();
        while let Some(reference) = pending.pop() {
            if self.by_ref.contains_key(&reference) {
                continue;
            }
            for to in below.get(reference.as_str()).into_iter().flatten() {
                if out.insert((*to).clone()) {
                    pending.push((*to).clone());
                }
            }
        }
        out
    }

    fn finish(
        self,
        root_deps: &BTreeSet<String>,
        edges: &[(String, String)],
        complete: bool,
    ) -> SbomInput {
        const ROOT: &str = "(root)";
        let root_deps = self.through_holders(root_deps, edges);
        let root_deps = &root_deps;
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
            created: None,
            os: self.os,
            os_named: self.os_named,
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
            // Generators list the lockfile they read this way, which is no package.
            let kind = c.get("type").and_then(|v| v.as_str());
            let text = |key: &str| c.get(key).and_then(|v| v.as_str()).map(str::to_string);
            if kind == Some("operating-system") && purl.is_none() {
                b.os_named = b.os_named.take().or(text("name").zip(text("version")));
            } else if !matches!(kind, Some("application" | "file")) || purl.is_some() {
                b.add(reference, purl, dev, cyclonedx_hint(c));
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
    let mut input = b.finish(&root_deps, &edges, complete && !root.is_empty());
    input.created = timestamp(doc.pointer("/metadata/timestamp").and_then(|v| v.as_str()));
    input
}

fn spdx(doc: &serde_json::Value) -> SbomInput {
    let mut b = Builder::default();
    let relationships = || {
        let list = doc.get("relationships").and_then(|v| v.as_array());
        list.into_iter().flatten().filter_map(|r| {
            Some((
                r.get("spdxElementId")?.as_str()?,
                r.get("relationshipType")?.as_str()?,
                r.get("relatedSpdxElement")?.as_str()?,
            ))
        })
    };
    let mut roots: BTreeSet<String> = doc
        .get("documentDescribes")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|x| x.as_str().map(str::to_string))
        .collect();
    for (a, kind, z) in relationships() {
        match kind {
            "DESCRIBES" => {
                roots.insert(z.to_string());
            }
            "DESCRIBED_BY" => {
                roots.insert(a.to_string());
            }
            _ => {}
        }
    }
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
        // The described root package is the project, not a dependency, and generators list
        // the lockfile and directory they read as packages too.
        let purpose = p.get("primaryPackagePurpose").and_then(|v| v.as_str());
        let holder = purl.is_none() && matches!(purpose, Some("APPLICATION" | "FILE" | "SOURCE"));
        let text = |key: &str| p.get(key).and_then(|v| v.as_str()).map(str::to_string);
        if purl.is_none() && purpose == Some("OPERATING-SYSTEM") {
            b.os_named = b.os_named.take().or(text("name").zip(text("versionInfo")));
        } else if !roots.contains(&id) && !holder {
            let source = spdx_source(p);
            let hint = Hint {
                source,
                module: None,
            };
            b.add(id, purl, false, hint);
        }
    }
    let mut edges = Vec::new();
    for (a, kind, z) in relationships() {
        match kind {
            "DEPENDS_ON" => edges.push((a.to_string(), z.to_string())),
            "DEPENDENCY_OF" => edges.push((z.to_string(), a.to_string())),
            // How Trivy hangs a lockfile from the root and a project from the lockfile. Syft
            // has the root contain every package, which says nothing of what is direct.
            "CONTAINS" if !(roots.contains(a) && b.by_ref.contains_key(z)) => {
                edges.push((a.to_string(), z.to_string()));
            }
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
    let mut input = b.finish(&root_deps, &edges, false);
    input.created = timestamp(
        doc.pointer("/creationInfo/created")
            .and_then(|v| v.as_str()),
    );
    input
}

/// An SPDX 3 JSON-LD document: its context is SPDX's (3.0 or 3.0.1), named alone or first.
fn is_spdx3(doc: &serde_json::Value) -> bool {
    let spdx = |c: &serde_json::Value| {
        c.as_str()
            .is_some_and(|c| c.starts_with("https://spdx.org/rdf/3."))
    };
    match doc.get("@context") {
        Some(serde_json::Value::Array(list)) => list.iter().any(spdx),
        Some(c) => spdx(c),
        None => false,
    }
}

/// SPDX 3.0 JSON-LD: `software_Package` elements with their purls, the SBOM's root elements as
/// the project, `dependsOn` (and the link and optional-dependency kinds) as the graph, and a
/// `LifecycleScopedRelationship` scoped to development or test making its targets dev. The
/// document vouches for itself only when every dependency relationship says `complete`.
fn spdx3(doc: &serde_json::Value) -> SbomInput {
    let graph: Vec<&serde_json::Value> = match doc.get("@graph").and_then(|g| g.as_array()) {
        Some(list) => list.iter().collect(),
        None => vec![doc],
    };
    fn text<'a>(n: &'a serde_json::Value, key: &str) -> Option<&'a str> {
        n.get(key).and_then(|v| v.as_str())
    }
    fn id_of(n: &serde_json::Value) -> Option<&str> {
        text(n, "spdxId").or_else(|| text(n, "@id"))
    }
    fn kind(n: &serde_json::Value) -> Option<&str> {
        text(n, "type").or_else(|| text(n, "@type"))
    }
    fn ids(n: &serde_json::Value, key: &str) -> Vec<String> {
        match n.get(key) {
            Some(serde_json::Value::Array(list)) => list
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            Some(serde_json::Value::String(one)) => vec![one.clone()],
            _ => Vec::new(),
        }
    }

    let mut roots: BTreeSet<String> = BTreeSet::new();
    for n in &graph {
        if kind(n) == Some("software_Sbom") {
            roots.extend(ids(n, "rootElement"));
        }
    }
    const DEPENDENCY: [&str; 5] = [
        "dependsOn",
        "hasStaticLink",
        "hasDynamicLink",
        "hasOptionalDependency",
        "hasProvidedDependency",
    ];
    let relationships: Vec<(&serde_json::Value, &str, String, Vec<String>)> = graph
        .iter()
        .filter(|n| kind(n).is_some_and(|k| k.ends_with("Relationship")))
        .filter_map(|n| {
            Some((
                *n,
                text(n, "relationshipType")?,
                text(n, "from")?.to_string(),
                ids(n, "to"),
            ))
        })
        .collect();
    for (_, rel, _, to) in &relationships {
        if *rel == "describes" {
            roots.extend(to.iter().cloned());
        }
    }
    // A package every scoped edge to it calls development or test, and no plain edge reaches.
    let (mut scoped_dev, mut runtime) = (BTreeSet::new(), BTreeSet::new());
    for (n, rel, _, to) in &relationships {
        if !DEPENDENCY.contains(rel) {
            continue;
        }
        let dev = kind(n) == Some("LifecycleScopedRelationship")
            && matches!(text(n, "scope"), Some("development" | "test"));
        for t in to {
            if dev {
                scoped_dev.insert(t.clone());
            } else {
                runtime.insert(t.clone());
            }
        }
    }

    let mut b = Builder::default();
    for p in graph.iter().filter(|n| kind(n) == Some("software_Package")) {
        let Some(id) = id_of(p) else { continue };
        let purl = text(p, "software_packageUrl").or_else(|| {
            p.get("externalIdentifier")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .find(|e| text(e, "externalIdentifierType") == Some("packageUrl"))
                .and_then(|e| text(e, "identifier"))
        });
        let purpose = text(p, "software_primaryPurpose");
        let holder = purl.is_none() && matches!(purpose, Some("application" | "file" | "source"));
        if purl.is_none() && purpose == Some("operatingSystem") {
            let named = text(p, "name")
                .zip(text(p, "software_packageVersion"))
                .map(|(n, v)| (n.to_string(), v.to_string()));
            b.os_named = b.os_named.take().or(named);
        } else if !roots.contains(id) && !holder {
            let source = text(p, "software_sourceInfo")
                .and_then(|info| spdx_source(&serde_json::json!({ "sourceInfo": info })));
            let dev = scoped_dev.contains(id) && !runtime.contains(id);
            b.add(
                id.to_string(),
                purl,
                dev,
                Hint {
                    source,
                    module: None,
                },
            );
        }
    }

    let mut edges = Vec::new();
    let mut said = (0usize, 0usize);
    for (n, rel, from, to) in &relationships {
        let dependency = DEPENDENCY.contains(rel);
        // Like SPDX 2's CONTAINS: a lockfile under the root, but not the root holding every package.
        let contains = *rel == "contains" && !roots.contains(from);
        if !(dependency || contains) {
            continue;
        }
        if dependency {
            said.0 += 1;
            said.1 += usize::from(text(n, "completeness") == Some("complete"));
        }
        edges.extend(to.iter().map(|t| (from.clone(), t.clone())));
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
    let complete = !roots.is_empty() && !root_deps.is_empty() && said.0 > 0 && said.0 == said.1;
    let mut input = b.finish(&root_deps, &edges, complete);
    input.created = timestamp(
        graph
            .iter()
            .find(|n| kind(n) == Some("CreationInfo"))
            .and_then(|c| text(c, "created")),
    );
    input
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <metadata><timestamp>2026-01-02T03:04:05Z</timestamp>
    <component type="application" bom-ref="root"><name>app</name></component></metadata>
  <components>
    <component type="library" bom-ref="a"><name>a</name><purl>pkg:npm/a@1.0.0</purl>
      <components><component type="library" bom-ref="n"><purl>pkg:npm/n@1.0.0</purl></component></components>
    </component>
    <component type="library" bom-ref="b"><scope>excluded</scope><purl>pkg:npm/b@2.0.0</purl></component>
    <component type="library" bom-ref="c"><name>no purl</name></component>
    <component type="file"><name>/composer.lock</name></component>
  </components>
  <dependencies>
    <dependency ref="root"><dependency ref="a"/></dependency>
    <dependency ref="a"><dependency ref="b"/></dependency>
  </dependencies>
  <compositions><composition><aggregate>complete</aggregate>
    <assemblies><assembly ref="root"/></assemblies></composition></compositions>
</bom>"#;

    const JSON: &str = r#"{"bomFormat":"CycloneDX","metadata":{"timestamp":"2026-01-02T03:04:05Z",
      "component":{"type":"application","bom-ref":"root"}},
      "components":[{"type":"library","bom-ref":"a","purl":"pkg:npm/a@1.0.0",
        "components":[{"type":"library","bom-ref":"n","purl":"pkg:npm/n@1.0.0"}]},
        {"type":"library","bom-ref":"b","scope":"excluded","purl":"pkg:npm/b@2.0.0"},
        {"type":"library","bom-ref":"c"},{"type":"file","name":"/composer.lock"}],
      "dependencies":[{"ref":"root","dependsOn":["a"]},{"ref":"a","dependsOn":["b"]}],
      "compositions":[{"aggregate":"complete","assemblies":["root"]}]}"#;

    fn same(a: &SbomInput, b: &SbomInput) {
        assert_eq!(a.packages, b.packages);
        assert_eq!(a.unrouted, b.unrouted);
        assert_eq!(a.complete, b.complete);
        assert_eq!(a.created, b.created);
        let edges = |i: &SbomInput| {
            let list = i.graph.edges().map(|(f, t)| (f.to_string(), t.to_string()));
            list.collect::<Vec<_>>()
        };
        assert_eq!(edges(a), edges(b));
    }

    #[test]
    fn os_packages_read_alike_from_every_format() {
        let purl =
            "pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?arch=x86_64&amp;distro=rocky-9.3&amp;epoch=1";
        let xml = format!(
            r#"<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components>
            <component type="operating-system"><name>rocky</name><version>9.3</version></component>
            <component type="library" bom-ref="a"><purl>{purl}</purl><properties>
              <property name="aquasecurity:trivy:SrcName">openssl</property>
              <property name="aquasecurity:trivy:SrcEpoch">1</property>
              <property name="aquasecurity:trivy:SrcVersion">3.0.7</property>
              <property name="aquasecurity:trivy:SrcRelease">24.el9</property>
            </properties></component></components></bom>"#
        );
        let purl = purl.replace("&amp;", "&");
        let json = serde_json::json!({
            "bomFormat": "CycloneDX",
            "components": [
                {"type": "operating-system", "name": "rocky", "version": "9.3"},
                {"type": "library", "bom-ref": "a", "purl": purl, "properties": [
                    {"name": "aquasecurity:trivy:SrcName", "value": "openssl"},
                    {"name": "aquasecurity:trivy:SrcEpoch", "value": "1"},
                    {"name": "aquasecurity:trivy:SrcVersion", "value": "3.0.7"},
                    {"name": "aquasecurity:trivy:SrcRelease", "value": "24.el9"},
                ]},
            ],
        });
        let tag_value = format!(
            "SPDXVersion: SPDX-2.3\nPackageName: rocky\nSPDXID: SPDXRef-os\nPackageVersion: 9.3\n\
             PrimaryPackagePurpose: OPERATING-SYSTEM\nPackageName: openssl-libs\nSPDXID: SPDXRef-a\n\
             PackageVersion: 3.0.7-24.el9\n\
             PackageSourceInfo: built package from: openssl 1:3.0.7-24.el9\n\
             ExternalRef: PACKAGE-MANAGER purl {purl}\n"
        );
        for input in [
            parse(&xml).unwrap(),
            parse(&json.to_string()).unwrap(),
            parse(&tag_value).unwrap(),
        ] {
            assert!(input.unrouted.is_empty(), "{:?}", input.unrouted);
            assert_eq!(input.os_ecosystem(), Some(Ecosystem::Rpm));
            let named = ("rocky".to_string(), "9.3".to_string());
            assert_eq!(input.os_named, Some(named));
            let package = &input.os[0].package;
            assert_eq!(package.version, "1:3.0.7-24.el9");
            assert_eq!(package.source, "openssl");
            assert_eq!(package.source_version, "1:3.0.7-24.el9");
            let inspection = input.os_inspection().unwrap();
            assert_eq!(inspection.distro.unwrap().ecosystem, "Rocky Linux:9");
        }
    }

    #[test]
    fn cyclonedx_xml_reads_like_its_json() {
        let xml = parse(XML).unwrap();
        same(&xml, &parse(JSON).unwrap());
        assert!(xml.complete);
        assert_eq!(xml.packages[&Ecosystem::Npm].len(), 3);
        assert_eq!(xml.unrouted, vec!["no purl (1)"]);
        assert!(xml.created.is_some());
    }

    const TAG_VALUE: &str = "SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: x
Creator: Tool: t
Created: 2026-01-02T03:04:05Z
DocumentComment: <text>a comment
PackageName: not a package
</text>

##### Package
PackageName: app
SPDXID: SPDXRef-app

PackageName: a
SPDXID: SPDXRef-a
PackageVersion: 1.0.0
PackageComment: <text>ExternalRef: PACKAGE-MANAGER purl pkg:npm/fake@1</text>
ExternalRef: SECURITY cpe23Type cpe:2.3:a:a:a:1.0.0:*:*:*:*:*:*:*
ExternalRef: PACKAGE-MANAGER purl pkg:npm/a@1.0.0

FileName: ./index.js
SPDXID: SPDXRef-file
FileChecksum: SHA1: 85ed0817af83a24ad8da68c2b5094de69833983c

PackageName: b
SPDXID: SPDXRef-b
ExternalRef: PACKAGE-MANAGER purl pkg:npm/b@2.0.0

PackageName: composer.lock
SPDXID: SPDXRef-lock
PrimaryPackagePurpose: APPLICATION

Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-app
Relationship: SPDXRef-app DEPENDS_ON SPDXRef-a
Relationship: SPDXRef-b DEPENDENCY_OF SPDXRef-a
";

    const SPDX_JSON: &str = r#"{"spdxVersion":"SPDX-2.3","creationInfo":{"created":"2026-01-02T03:04:05Z"},
      "packages":[{"SPDXID":"SPDXRef-app"},
        {"SPDXID":"SPDXRef-a","externalRefs":[{"referenceType":"cpe23Type","referenceLocator":"x"},
          {"referenceType":"purl","referenceLocator":"pkg:npm/a@1.0.0"}]},
        {"SPDXID":"SPDXRef-b","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/b@2.0.0"}]},
        {"SPDXID":"SPDXRef-lock","primaryPackagePurpose":"APPLICATION"}],
      "relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-app"},
        {"spdxElementId":"SPDXRef-app","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-a"},
        {"spdxElementId":"SPDXRef-b","relationshipType":"DEPENDENCY_OF","relatedSpdxElement":"SPDXRef-a"}]}"#;

    #[test]
    fn tag_value_reads_like_its_json() {
        let got = parse(TAG_VALUE).unwrap();
        same(&got, &parse(SPDX_JSON).unwrap());
        let npm = &got.packages[&Ecosystem::Npm];
        let names: Vec<(&str, bool)> = npm.iter().map(|p| (p.name.as_str(), p.direct)).collect();
        assert_eq!(names, vec![("a", true), ("b", false)]);
        assert!(
            got.unrouted.is_empty(),
            "the described root is no component"
        );
    }

    #[test]
    fn the_wrapper_of_github_dependency_graph_is_opened() {
        let wrapped = format!(r#"{{"sbom":{SPDX_JSON}}}"#);
        same(&parse(&wrapped).unwrap(), &parse(SPDX_JSON).unwrap());
    }

    #[test]
    fn direct_dependencies_are_found_below_lockfiles_and_the_project() {
        let cyclonedx = r#"{"bomFormat":"CycloneDX","metadata":{"component":{"bom-ref":"root"}},
          "components":[{"type":"application","bom-ref":"lock","name":"go.mod"},
            {"type":"library","bom-ref":"main","purl":"pkg:golang/example.com/main"},
            {"type":"library","bom-ref":"a","purl":"pkg:golang/example.com/a@v1.0.0"},
            {"type":"library","bom-ref":"b","purl":"pkg:golang/example.com/b@v1.0.0"}],
          "dependencies":[{"ref":"root","dependsOn":["lock"]},{"ref":"lock","dependsOn":["main"]},
            {"ref":"main","dependsOn":["a"]},{"ref":"a","dependsOn":["b"]}]}"#;
        let spdx_json = r#"{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-root"},
            {"SPDXID":"SPDXRef-lock","primaryPackagePurpose":"APPLICATION"},
            {"SPDXID":"SPDXRef-main","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/example.com/main"}]},
            {"SPDXID":"SPDXRef-a","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/example.com/a@v1.0.0"}]},
            {"SPDXID":"SPDXRef-b","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/example.com/b@v1.0.0"}]}],
          "relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-root"},
            {"spdxElementId":"SPDXRef-root","relationshipType":"CONTAINS","relatedSpdxElement":"SPDXRef-lock"},
            {"spdxElementId":"SPDXRef-lock","relationshipType":"CONTAINS","relatedSpdxElement":"SPDXRef-main"},
            {"spdxElementId":"SPDXRef-main","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-a"},
            {"spdxElementId":"SPDXRef-a","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-b"}]}"#;
        for text in [cyclonedx, spdx_json] {
            let input = parse(text).unwrap();
            let go = &input.packages[&Ecosystem::Go];
            let direct: Vec<(&str, bool)> =
                go.iter().map(|p| (p.name.as_str(), p.direct)).collect();
            assert_eq!(
                direct,
                vec![("example.com/a", true), ("example.com/b", false)]
            );
            assert_eq!(
                input.graph.chain_to("example.com/b"),
                vec!["(root)", "example.com/a", "example.com/b"]
            );
        }
    }

    #[test]
    fn a_root_containing_every_package_makes_none_direct() {
        let text = r#"{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-root"},
            {"SPDXID":"SPDXRef-a","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/a@1.0.0"}]}],
          "relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-root"},
            {"spdxElementId":"SPDXRef-root","relationshipType":"CONTAINS","relatedSpdxElement":"SPDXRef-a"}]}"#;
        assert!(!parse(text).unwrap().packages[&Ecosystem::Npm][0].direct);
    }

    #[test]
    fn a_byte_order_mark_is_skipped() {
        same(
            &parse(&format!("\u{feff}{JSON}")).unwrap(),
            &parse(JSON).unwrap(),
        );
    }

    #[test]
    fn what_is_not_read_is_refused_and_named() {
        assert!(parse("<project/>").unwrap_err().contains("not CycloneDX"));
        assert!(parse(r#"{"@context":"x"}"#)
            .unwrap_err()
            .contains("not SPDX 3"));
        assert!(parse("hello: world").is_err());
        let entities = "<!DOCTYPE bom [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><bom/>";
        assert!(parse(entities).is_err());
    }

    #[test]
    fn several_sboms_read_as_one() {
        let (a, b) = (parse(JSON).unwrap(), parse(SPDX_JSON).unwrap());
        let merged = a.merge(b);
        assert_eq!(merged.packages[&Ecosystem::Npm].len(), 3);
        assert!(!merged.complete);
        let a = merged.packages[&Ecosystem::Npm]
            .iter()
            .find(|p| p.name == "a");
        assert!(a.unwrap().direct);
    }

    #[test]
    fn discovery_finds_sboms_and_leaves_test_data_alone() {
        let dir = tempfile::tempdir().unwrap();
        for path in [
            "bom.xml",
            "dist/app.cdx.json",
            "dist/app.spdx",
            "tests/bom.json",
            "node_modules/x/sbom.json",
            ".git/bom.json",
            ".fleetreach/sbom/release.spdx.json",
            "src/main.json",
        ] {
            let file = dir.path().join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, "{}").unwrap();
        }
        let found = discover(dir.path());
        let names: Vec<String> = found
            .iter()
            .map(|p| p.strip_prefix(dir.path()).unwrap().display().to_string())
            .collect();
        assert_eq!(
            names,
            vec![
                ".fleetreach/sbom/release.spdx.json",
                "bom.xml",
                "dist/app.cdx.json",
                "dist/app.spdx"
            ]
        );
    }

    #[test]
    fn an_sbom_older_than_the_last_lockfile_change_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .current_dir(dir.path())
                .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
                .args(args)
                .env("GIT_COMMITTER_DATE", "2026-06-01T00:00:00Z")
                .env("GIT_AUTHOR_DATE", "2026-06-01T00:00:00Z")
                .output()
                .unwrap();
            assert!(status.status.success());
        };
        git(&["init", "-q"]);
        std::fs::write(dir.path().join("README"), "x").unwrap();
        git(&["add", "."]);
        git(&["commit", "-qm", "readme"]);
        let may = timestamp(Some("2026-05-01T00:00:00Z"));
        let july = timestamp(Some("2026-07-01T00:00:00Z"));
        assert_eq!(stale(dir.path(), may), None, "no lockfile committed");
        std::fs::write(dir.path().join("Cargo.lock"), "x").unwrap();
        git(&["add", "."]);
        git(&["commit", "-qm", "lock"]);
        assert!(stale(dir.path(), may).unwrap().contains("2026-06-01"));
        assert_eq!(stale(dir.path(), july), None);
        assert_eq!(stale(dir.path(), None), None);
    }

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
        assert_eq!(
            route("pkg:cargo/serde@1.0.0").unwrap(),
            (Ecosystem::Cargo, "serde".to_string(), "1.0.0".to_string())
        );
        assert_eq!(
            route("pkg:golang/github.com/a/b/v2@v2.0.0%2Bincompatible#sub/dir").unwrap(),
            (
                Ecosystem::Go,
                "github.com/a/b/v2".to_string(),
                "v2.0.0+incompatible".to_string()
            )
        );
        assert_eq!(
            route("pkg:golang/github.com%2Fa%2Fb@v1.0.0").unwrap().1,
            "github.com/a/b"
        );
        assert_eq!(route("pkg:deb/debian/curl@8").unwrap_err(), "deb");
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
        assert_eq!(input.unrouted, vec!["no purl (1)"]);
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

    #[test]
    fn spdx3_reads_roots_scopes_and_completeness() {
        let doc = r#"{
          "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
          "@graph": [
            { "type": "CreationInfo", "@id": "_:c", "created": "2026-01-02T03:04:05Z" },
            { "type": "software_Sbom", "spdxId": "x:sbom", "rootElement": ["x:root"] },
            { "type": "software_Package", "spdxId": "x:root", "name": "app",
              "software_primaryPurpose": "application" },
            { "type": "software_Package", "spdxId": "x:a", "software_packageUrl": "pkg:pypi/requests@2.19.0" },
            { "type": "software_Package", "spdxId": "x:b",
              "externalIdentifier": [{ "type": "ExternalIdentifier",
                "externalIdentifierType": "packageUrl", "identifier": "pkg:pypi/urllib3@1.24.1" }] },
            { "type": "software_Package", "spdxId": "x:t", "software_packageUrl": "pkg:pypi/pytest@7.0.0" },
            { "type": "software_Package", "spdxId": "x:n", "name": "no purl" },
            { "type": "Relationship", "spdxId": "x:r1", "from": "x:root", "relationshipType": "dependsOn",
              "to": ["x:a"], "completeness": "complete" },
            { "type": "LifecycleScopedRelationship", "spdxId": "x:r2", "from": "x:root",
              "relationshipType": "dependsOn", "to": ["x:t"], "scope": "development",
              "completeness": "complete" },
            { "type": "Relationship", "spdxId": "x:r3", "from": "x:a", "relationshipType": "dependsOn",
              "to": ["x:b"], "completeness": "complete" }
          ]
        }"#;
        let input = parse(doc).unwrap();
        let pypi = &input.packages[&Ecosystem::Pypi];
        let get = |n: &str| pypi.iter().find(|p| p.name == n).unwrap();
        assert!(get("requests").direct && !get("requests").dev);
        assert!(!get("urllib3").direct);
        assert!(get("pytest").direct && get("pytest").dev);
        assert_eq!(pypi.len(), 3);
        assert_eq!(input.unrouted, vec!["no purl (1)".to_string()]);
        assert!(input.complete);
        assert_eq!(
            input.graph.chain_to("urllib3"),
            vec!["(root)", "requests", "urllib3"]
        );
        assert!(input.created.is_some());

        // One incomplete edge, and the document no longer vouches for itself.
        let partial = doc.replacen(
            r#""completeness": "complete" }"#,
            r#""completeness": "incomplete" }"#,
            1,
        );
        assert!(!parse(&partial).unwrap().complete);
        assert!(looks_like_sbom("app.spdx3.json"));
    }

    #[test]
    fn our_spdx3_reads_back_like_our_cyclonedx() {
        use fleetreach_core::inventory::{Package, RepoInventory, SourceInventory};
        use fleetreach_core::{DepGraph, RepoId};
        let mut graph = DepGraph::new("app");
        graph.add_edges("app", ["express", "@types/node"]);
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
        let mut inv = RepoInventory::new(RepoId("acme/app".into()));
        inv.sources = vec![npm];
        let t = "2026-11-12T00:00:00Z";
        let spdx3 = parse(&fleetreach_report::to_spdx3(&inv, None, "1.7.0", t).unwrap()).unwrap();
        let cdx = parse(
            &fleetreach_report::to_cyclonedx(
                &inv,
                "1.7.0",
                Some(t),
                fleetreach_report::CycloneDxVersion::V1_7,
            )
            .unwrap(),
        )
        .unwrap();
        same(&spdx3, &cdx);
        assert!(spdx3.complete);
    }
}
