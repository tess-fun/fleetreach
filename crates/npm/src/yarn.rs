//! Read `yarn.lock` (spec 02): the classic v1 text format and the yarn 2+ ("berry") YAML
//! format, told apart by berry's `__metadata` entry.
//!
//! Both key each entry by the descriptors (`name@range`) that resolved to it; dependencies
//! inside an entry are `name range` pairs, so the graph is rebuilt by looking the
//! descriptor up. Neither format records which entries the project asked for, so roots and
//! the dev/runtime split come from the `package.json` files ([`crate::manifest`]). Berry
//! also lists each workspace as an entry, whose dependencies are the direct set.

use std::collections::BTreeMap;
use std::path::Path;

use crate::manifest::{self, Declared};
use crate::resolved::{split_name_version, Node, Resolved};
use crate::yaml::{self, Node as Y};

/// Parse `yarn.lock` in `dir` (the directory also holding `package.json`).
pub(crate) fn parse(text: &str, dir: &Path) -> Result<Resolved, String> {
    let declared = manifest::declared(dir);
    if is_berry(text) {
        parse_berry(text, &declared)
    } else {
        parse_v1(text, &declared)
    }
}

fn is_berry(text: &str) -> bool {
    text.lines().any(|l| l.trim_start() == "__metadata:")
}

/// One parsed entry before the graph is linked: its descriptors, resolved name/version and
/// dependency descriptors.
struct Entry {
    descriptors: Vec<String>,
    name: String,
    version: String,
    deps: Vec<String>,
}

/// Link entries into a [`Resolved`] graph, taking roots from `declared` plus the
/// descriptors in `extra_prod` (berry's workspace entries), or, with neither, from entries
/// nothing depends on. A root the manifest marks dev stays dev.
fn link(
    entries: Vec<Entry>,
    declared: &Declared,
    extra_prod: &[String],
    normalize: fn(&str, &str) -> String,
) -> Resolved {
    let mut by_descriptor: BTreeMap<String, String> = BTreeMap::new();
    let mut resolved = Resolved {
        root_name: declared
            .name
            .clone()
            .unwrap_or_else(|| "(root)".to_string()),
        ..Resolved::default()
    };
    for entry in &entries {
        let id = format!("{}@{}", entry.name, entry.version);
        for d in &entry.descriptors {
            by_descriptor.insert(d.clone(), id.clone());
        }
    }
    for entry in entries {
        let id = format!("{}@{}", entry.name, entry.version);
        let deps: Vec<String> = entry
            .deps
            .iter()
            .filter_map(|d| by_descriptor.get(d).cloned())
            .collect();
        let node = resolved.nodes.entry(id).or_insert(Node {
            name: entry.name,
            version: entry.version,
            deps: Vec::new(),
        });
        node.deps.extend(deps);
    }
    let lookup = |name: &str, range: &str| by_descriptor.get(&normalize(name, range)).cloned();
    for (name, range) in &declared.prod {
        if let Some(id) = lookup(name, range) {
            resolved.prod_roots.insert(id);
        }
    }
    for (name, range) in &declared.dev {
        if let Some(id) = lookup(name, range) {
            resolved.dev_roots.insert(id);
        }
    }
    for id in extra_prod.iter().filter_map(|d| by_descriptor.get(d)) {
        if !resolved.dev_roots.contains(id) {
            resolved.prod_roots.insert(id.clone());
        }
    }
    if resolved.prod_roots.is_empty() && resolved.dev_roots.is_empty() {
        // No manifest: entries nothing else depends on are the project's own requests.
        let depended: std::collections::BTreeSet<&String> =
            resolved.nodes.values().flat_map(|n| &n.deps).collect();
        let roots: Vec<String> = resolved
            .nodes
            .keys()
            .filter(|id| !depended.contains(id))
            .cloned()
            .collect();
        resolved.prod_roots.extend(roots);
    }
    resolved
}

// ---- yarn v1 ----

fn parse_v1(text: &str, declared: &Declared) -> Result<Resolved, String> {
    let mut entries = Vec::new();
    let mut current: Option<(Vec<String>, Option<String>, Vec<String>)> = None;
    let mut in_deps = false;
    let finish = |cur: Option<(Vec<String>, Option<String>, Vec<String>)>,
                  entries: &mut Vec<Entry>|
     -> Result<(), String> {
        let Some((descriptors, version, deps)) = cur else {
            return Ok(());
        };
        let first = descriptors
            .first()
            .ok_or("yarn.lock entry with no descriptor")?;
        let version = version.ok_or_else(|| format!("yarn.lock entry `{first}` has no version"))?;
        let (name, range) = split_name_version(first)
            .ok_or_else(|| format!("yarn.lock descriptor `{first}` is not name@range"))?;
        entries.push(Entry {
            name: registry_name(name, range).to_string(),
            version,
            descriptors,
            deps,
        });
        Ok(())
    };

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim_end();
        if line.is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let body = line.trim_start();
        match indent {
            0 => {
                finish(current.take(), &mut entries)?;
                let header = body.strip_suffix(':').ok_or_else(|| {
                    format!("yarn.lock line {}: expected an entry header", lineno + 1)
                })?;
                let descriptors = header
                    .split(", ")
                    .map(|d| unquote(d.trim()).to_string())
                    .collect();
                current = Some((descriptors, None, Vec::new()));
                in_deps = false;
            }
            2 => {
                let Some(cur) = current.as_mut() else {
                    return Err(format!(
                        "yarn.lock line {}: field outside an entry",
                        lineno + 1
                    ));
                };
                in_deps = matches!(body, "dependencies:" | "optionalDependencies:");
                if let Some(v) = body.strip_prefix("version ") {
                    cur.1 = Some(unquote(v.trim()).to_string());
                }
            }
            _ if in_deps => {
                let Some(cur) = current.as_mut() else {
                    return Err(format!(
                        "yarn.lock line {}: dependency outside an entry",
                        lineno + 1
                    ));
                };
                let (name, range) = split_pair(body).ok_or_else(|| {
                    format!("yarn.lock line {}: expected `name range`", lineno + 1)
                })?;
                cur.2.push(format!("{name}@{range}"));
            }
            _ => {}
        }
    }
    finish(current.take(), &mut entries)?;
    Ok(link(entries, declared, &[], |name, range| {
        format!("{name}@{range}")
    }))
}

/// A `name range` dependency line, either part possibly quoted.
fn split_pair(body: &str) -> Option<(&str, &str)> {
    let (name, rest) = if let Some(stripped) = body.strip_prefix('"') {
        let end = stripped.find('"')?;
        (stripped.get(..end)?, stripped.get(end + 1..)?)
    } else {
        body.split_once(' ')?
    };
    Some((name, unquote(rest.trim())))
}

fn unquote(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}

/// The registry package behind a descriptor: an `npm:` alias names it explicitly
/// (`sw@npm:string-width@^4` is `string-width`).
fn registry_name<'a>(name: &'a str, range: &'a str) -> &'a str {
    range
        .strip_prefix("npm:")
        .and_then(|aliased| split_name_version(aliased).map(|(n, _)| n))
        .unwrap_or(name)
}

// ---- yarn berry (2+) ----

fn parse_berry(text: &str, declared: &Declared) -> Result<Resolved, String> {
    let docs = yaml::parse(text)?;
    let doc = docs.first().ok_or("empty yarn.lock")?;
    let mut entries = Vec::new();
    let mut workspace_deps: Vec<String> = Vec::new();
    for (key, entry) in doc.entries() {
        if key == "__metadata" {
            continue;
        }
        let descriptors: Vec<String> = key.split(", ").map(|d| d.trim().to_string()).collect();
        let resolution = entry
            .str_at("resolution")
            .ok_or_else(|| format!("yarn.lock entry `{key}` has no resolution"))?;
        let deps: Vec<String> = ["dependencies", "optionalDependencies"]
            .iter()
            .flat_map(|s| entry.get(s).map(Y::entries).unwrap_or_default())
            .filter_map(|(name, range)| range.as_str().map(|r| berry_descriptor(name, r)))
            .collect();
        match berry_package(resolution) {
            Some((name, _)) => {
                let version = entry
                    .str_at("version")
                    .ok_or_else(|| format!("yarn.lock entry `{key}` has no version"))?;
                entries.push(Entry {
                    descriptors,
                    name: name.to_string(),
                    version: version.to_string(),
                    deps,
                });
            }
            // A workspace (`name@workspace:path`): its dependencies are the project's own.
            None if resolution.contains("@workspace:") => workspace_deps.extend(deps),
            // git, file, link, portal, exec: no registry package to match.
            None => {}
        }
    }
    Ok(link(entries, declared, &workspace_deps, berry_descriptor))
}

/// The descriptor a berry dependency refers to. Berry writes ranges with their protocol
/// (`npm:^1.0.0`); a bare range means `npm:`.
fn berry_descriptor(name: &str, range: &str) -> String {
    if range.contains(':') {
        format!("{name}@{range}")
    } else {
        format!("{name}@npm:{range}")
    }
}

/// `(name, version)` of a registry resolution: `lodash@npm:4.17.21`, or a patched one
/// (`resolve@patch:resolve@npm%3A1.22.8#...`, which is still that registry package).
fn berry_package(resolution: &str) -> Option<(&str, &str)> {
    if let Some(at) = resolution.get(1..).and_then(|r| r.find("@npm:")) {
        let (name, rest) = resolution.split_at(at + 1);
        return Some((name, rest.strip_prefix("@npm:")?));
    }
    let at = resolution.get(1..)?.find("@patch:")? + 1;
    let inner = resolution.get(at + "@patch:".len()..)?;
    let inner = inner.split('#').next()?;
    let (name, rest) = inner.split_at(inner.get(1..)?.find("@npm%3A")? + 1);
    Some((name, rest.strip_prefix("@npm%3A")?))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn tempdir(tag: &str, package_json: Option<&str>) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fr-yarn-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let _ = std::fs::remove_file(dir.join("package.json"));
        if let Some(pj) = package_json {
            std::fs::write(dir.join("package.json"), pj).unwrap();
        }
        dir
    }

    const V1: &str = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz"
  integrity sha512-x
  dependencies:
    "@babel/highlight" "^7.12.13"

"@babel/highlight@^7.12.13":
  version "7.13.10"

lodash@^4.17.20:
  version "4.17.20"

sw@npm:string-width@^4.2.0:
  version "4.2.3"

jest@^29.0.0:
  version "29.7.0"
  dependencies:
    lodash "^4.17.20"
"#;

    #[test]
    fn reads_v1_with_manifest_roots() {
        let dir = tempdir(
            "v1",
            Some(
                r#"{"name":"app","dependencies":{"lodash":"^4.17.20","@babel/code-frame":"^7.10.4",
                "sw":"npm:string-width@^4.2.0"},"devDependencies":{"jest":"^29.0.0"}}"#,
            ),
        );
        let (installed, graph) = parse(V1, &dir).unwrap().into_parts();
        let get = |n: &str| {
            installed
                .iter()
                .find(|p| p.name == n)
                .unwrap_or_else(|| panic!("{n}: {installed:?}"))
        };
        assert_eq!(get("lodash").version, "4.17.20");
        assert!(
            get("lodash").direct && !get("lodash").dev,
            "runtime wins over dev"
        );
        assert!(!get("@babel/highlight").direct);
        assert!(
            get("string-width").direct,
            "npm: alias names the registry package"
        );
        assert!(get("jest").dev);
        assert_eq!(
            graph.chain_to("@babel/highlight"),
            vec!["app", "@babel/code-frame", "@babel/highlight"]
        );
    }

    #[test]
    fn v1_without_manifest_treats_unrequired_entries_as_roots() {
        let dir = tempdir("v1-bare", None);
        let (installed, _) = parse(V1, &dir).unwrap().into_parts();
        let get = |n: &str| installed.iter().find(|p| p.name == n).unwrap();
        assert!(get("jest").direct);
        assert!(!get("lodash").direct, "jest depends on it");
        assert!(installed.iter().all(|p| !p.dev));
    }

    #[test]
    fn v1_malformed_fails_closed() {
        let dir = tempdir("v1-bad", None);
        assert!(
            parse("lodash@^4:\n  resolved \"x\"\n", &dir).is_err(),
            "no version"
        );
        assert!(
            parse("  version \"1\"\n", &dir).is_err(),
            "field outside entry"
        );
    }

    const BERRY: &str = r#"# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 8
  cacheKey: 10c0

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  dependencies:
    lodash: "npm:^4.17.20"
    resolve: "patch:resolve@npm%3A^1.22.0#~builtin<compat/resolve>"
    vitest: "npm:^1.0.0"
  languageName: unknown
  linkType: soft

"lodash@npm:^4.17.20":
  version: 4.17.20
  resolution: "lodash@npm:4.17.20"
  checksum: 10c0/abc
  languageName: node
  linkType: hard

"resolve@patch:resolve@npm%3A^1.22.0#~builtin<compat/resolve>":
  version: 1.22.8
  resolution: "resolve@patch:resolve@npm%3A1.22.8#~builtin<compat/resolve>::version=1.22.8&hash=c3c19d"
  languageName: node
  linkType: hard

"vitest@npm:^1.0.0":
  version: 1.6.0
  resolution: "vitest@npm:1.6.0"
  dependencies:
    tinyspy: "npm:^2.2.0"
  languageName: node
  linkType: hard

"tinyspy@npm:^2.2.0":
  version: 2.2.1
  resolution: "tinyspy@npm:2.2.1"
  languageName: node
  linkType: hard

"local-thing@file:./vendor/thing::locator=app%40workspace%3A.":
  version: 1.0.0
  resolution: "local-thing@file:./vendor/thing#./vendor/thing::hash=1"
  languageName: node
  linkType: hard
"#;

    #[test]
    fn reads_berry_with_patches_workspaces_and_dev() {
        let dir = tempdir(
            "berry",
            Some(
                r#"{"name":"app","dependencies":{"lodash":"^4.17.20"},
                "devDependencies":{"vitest":"^1.0.0"}}"#,
            ),
        );
        let (installed, graph) = parse(BERRY, &dir).unwrap().into_parts();
        let get = |n: &str| {
            installed
                .iter()
                .find(|p| p.name == n)
                .unwrap_or_else(|| panic!("{n}: {installed:?}"))
        };
        assert!(get("lodash").direct && !get("lodash").dev);
        assert_eq!(get("resolve").version, "1.22.8", "patched registry package");
        assert!(get("resolve").direct, "listed by the workspace entry");
        assert!(get("vitest").dev && get("tinyspy").dev);
        assert!(installed
            .iter()
            .all(|p| p.name != "local-thing" && p.name != "app"));
        assert_eq!(graph.chain_to("tinyspy"), vec!["app", "vitest", "tinyspy"]);
    }
}
