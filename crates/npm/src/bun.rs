//! Read `bun.lock`, bun's text lockfile (bun 1.2 and later; `lockfileVersion` 0 and 1).
//!
//! The file is JSONC (comments and trailing commas allowed). `workspaces` maps each
//! workspace path (`""` for the root) to its declared `dependencies`, `devDependencies` and
//! `optionalDependencies`, which are the roots. `packages` holds every installed instance
//! under its install path, the way `node_modules` nests it: `undici` is hoisted to the top,
//! `@actions/http-client/undici` is a second copy only `@actions/http-client` sees. Each value
//! is an array whose first element is the resolution, `name@version` for a registry package,
//! or a `name@<protocol>:...` (`workspace:`, `github:`, `git+`, `file:`, `link:`, a tarball
//! URL) that names no registry version.
//!
//! A dependency is resolved the way Node finds it: from the dependent's own path up through
//! each parent to the top level. The binary `bun.lockb` is not read.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::resolved::{split_name_version, Node, Resolved};

/// Parse a `bun.lock` body.
pub(crate) fn parse(text: &str) -> Result<Resolved, String> {
    let doc: Value = serde_json::from_str(&to_json(text))
        .map_err(|e| format!("bun.lock is not valid JSON: {e}"))?;
    match doc.get("lockfileVersion").and_then(Value::as_u64) {
        Some(0 | 1) => {}
        Some(v) => {
            return Err(format!(
                "bun.lock lockfileVersion {v} is not supported (0 and 1 are)"
            ))
        }
        None => return Err("bun.lock has no lockfileVersion".to_string()),
    }
    let packages = doc
        .get("packages")
        .and_then(Value::as_object)
        .ok_or("bun.lock has no packages")?;

    // Every install path, registry or not, with its resolution and dependency names.
    let mut entries: BTreeMap<&str, Entry> = BTreeMap::new();
    for (path, value) in packages {
        let resolution = value
            .get(0)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("bun.lock package `{path}` has no resolution"))?;
        let meta = value
            .as_array()
            .into_iter()
            .flatten()
            .find(|v| v.is_object());
        let names = |section: &str| -> Vec<String> {
            meta.and_then(|m| m.get(section))
                .and_then(Value::as_object)
                .map(|deps| deps.keys().cloned().collect())
                .unwrap_or_default()
        };
        entries.insert(
            path.as_str(),
            Entry {
                registry: registry(resolution),
                required: names("dependencies"),
                optional: [names("optionalDependencies"), names("peerDependencies")].concat(),
            },
        );
    }

    let mut resolved = Resolved {
        root_name: "(root)".to_string(),
        ..Resolved::default()
    };
    for (path, entry) in &entries {
        let Some((name, version)) = &entry.registry else {
            continue;
        };
        let mut deps = BTreeSet::new();
        let mut seen = BTreeSet::new();
        children(&entries, path, entry, &mut deps, &mut seen)?;
        resolved.nodes.insert(
            (*path).to_string(),
            Node {
                name: name.clone(),
                version: version.clone(),
                deps: deps.into_iter().collect(),
            },
        );
    }

    let workspaces = doc
        .get("workspaces")
        .and_then(Value::as_object)
        .ok_or("bun.lock has no workspaces")?;
    for (dir, workspace) in workspaces {
        let member = workspace.get("name").and_then(Value::as_str);
        if dir.is_empty() {
            if let Some(name) = member {
                resolved.root_name = name.to_string();
            }
        }
        // A member's own copies nest under its package name; the root's are top-level.
        let from = if dir.is_empty() { None } else { member };
        for (section, dev) in [
            ("dependencies", false),
            ("optionalDependencies", false),
            ("devDependencies", true),
        ] {
            let Some(deps) = workspace.get(section).and_then(Value::as_object) else {
                continue;
            };
            for dep in deps.keys() {
                let Some(path) = lookup(&entries, from.unwrap_or(""), dep) else {
                    if section == "optionalDependencies" {
                        continue;
                    }
                    return Err(format!(
                        "bun.lock workspace `{dir}` depends on `{dep}` but has no entry for it"
                    ));
                };
                let mut roots = BTreeSet::new();
                let mut seen = BTreeSet::new();
                registry_or_children(&entries, path, &mut roots, &mut seen)?;
                let target = if dev {
                    &mut resolved.dev_roots
                } else {
                    &mut resolved.prod_roots
                };
                target.extend(roots);
            }
        }
    }
    Ok(resolved)
}

struct Entry {
    /// `(name, version)` for a registry package, `None` for a workspace, git, file, link or
    /// tarball dependency.
    registry: Option<(String, String)>,
    required: Vec<String>,
    /// Optional and peer dependencies: an install may legitimately leave these out.
    optional: Vec<String>,
}

/// `name@1.2.3` as a registry package; anything with a protocol is not one.
fn registry(resolution: &str) -> Option<(String, String)> {
    let (name, version) = split_name_version(resolution)?;
    (!version.contains(':')).then(|| (name.to_string(), version.to_string()))
}

/// The registry install paths `path` depends on. A non-registry dependency (a git or file
/// package) is looked through to its own dependencies, so what only it pulls in keeps its
/// runtime scope instead of looking dev-only.
fn children<'a>(
    entries: &'a BTreeMap<&'a str, Entry>,
    path: &'a str,
    entry: &'a Entry,
    out: &mut BTreeSet<String>,
    seen: &mut BTreeSet<&'a str>,
) -> Result<(), String> {
    let deps = entry
        .required
        .iter()
        .map(|d| (d, true))
        .chain(entry.optional.iter().map(|d| (d, false)));
    for (dep, required) in deps {
        match lookup(entries, path, dep) {
            Some(child) => registry_or_children(entries, child, out, seen)?,
            None if required => {
                return Err(format!(
                    "bun.lock package `{path}` depends on `{dep}` but has no entry for it"
                ))
            }
            None => {}
        }
    }
    Ok(())
}

fn registry_or_children<'a>(
    entries: &'a BTreeMap<&'a str, Entry>,
    path: &'a str,
    out: &mut BTreeSet<String>,
    seen: &mut BTreeSet<&'a str>,
) -> Result<(), String> {
    let Some(entry) = entries.get(path) else {
        return Ok(());
    };
    if entry.registry.is_some() {
        out.insert(path.to_string());
        Ok(())
    } else if seen.insert(path) {
        children(entries, path, entry, out, seen)
    } else {
        Ok(())
    }
}

/// The install path Node would load `dep` from when required by the package at `from`:
/// `from/dep`, then each parent's `…/dep`, then the top-level `dep`.
fn lookup<'a>(entries: &'a BTreeMap<&'a str, Entry>, from: &str, dep: &str) -> Option<&'a str> {
    let segments = package_segments(from);
    (0..=segments.len()).rev().find_map(|n| {
        let candidate = segments[..n]
            .iter()
            .copied()
            .chain(std::iter::once(dep))
            .collect::<Vec<_>>()
            .join("/");
        entries.get_key_value(candidate.as_str()).map(|(k, _)| *k)
    })
}

/// An install path split into package names: `@a/b/c/@d/e` is `["@a/b", "c", "@d/e"]`.
fn package_segments(path: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = path;
    while !rest.is_empty() {
        let mut end = rest.find('/').unwrap_or(rest.len());
        if rest.starts_with('@') && end < rest.len() {
            end += 1 + rest[end + 1..].find('/').unwrap_or(rest.len() - end - 1);
        }
        out.push(&rest[..end]);
        rest = rest.get(end + 1..).unwrap_or_default();
    }
    out
}

/// Turn bun's JSONC into JSON: drop `//` and `/* */` comments and the commas left before a
/// closing `}` or `]`, all outside strings.
fn to_json(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut pending_comma: Option<usize> = None;
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                pending_comma = None;
                out.push(c);
                let mut escaped = false;
                for c in chars.by_ref() {
                    out.push(c);
                    match c {
                        _ if escaped => escaped = false,
                        '\\' => escaped = true,
                        '"' => break,
                        _ => {}
                    }
                }
            }
            '/' if chars.peek() == Some(&'/') => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push(c);
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut star = false;
                for c in chars.by_ref() {
                    if star && c == '/' {
                        break;
                    }
                    star = c == '*';
                }
                out.push(' ');
            }
            ',' => {
                pending_comma = Some(out.len());
                out.push(c);
            }
            '}' | ']' => {
                if let Some(at) = pending_comma.take() {
                    out.remove(at);
                }
                out.push(c);
            }
            c if c.is_whitespace() => out.push(c),
            _ => {
                pending_comma = None;
                out.push(c);
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const LOCK: &str = r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "app",
      "dependencies": {
        "@actions/http-client": "^4.0.0",
        "vendored": "github:acme/vendored",
        "member": "workspace:*",
      },
      "devDependencies": {
        "typescript": "^5",
      },
    },
    "packages/member": {
      "name": "member",
      "dependencies": {
        "undici": "^7",
      },
    },
  },
  "packages": {
    "@actions/http-client": ["@actions/http-client@4.0.1", "", { "dependencies": { "tunnel": "^0.0.6", "undici": "^6.23.0" } }, "sha512-a"],
    "@actions/http-client/undici": ["undici@6.26.0", "", {}, "sha512-b"],
    "member": ["member@workspace:packages/member"],
    "member/undici": ["undici@7.1.0", "", {}, "sha512-c"],
    "tunnel": ["tunnel@0.0.6", "", {}, "sha512-d"],
    "typescript": ["typescript@5.6.2", "", { "optionalDependencies": { "fsevents": "*" } }, "sha512-e"],
    "undici": ["undici@5.0.0", "", {}, "sha512-f"],
    "vendored": ["vendored@github:acme/vendored#abc123", { "dependencies": { "left-pad": "^1" } }, "acme-vendored-abc123"],
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-g"],
  }
}"#;

    #[test]
    fn jsonc_becomes_json_outside_strings() {
        assert_eq!(
            to_json(r#"{"a": [1, 2,], "b": "x,} // y",}"#),
            r#"{"a": [1, 2], "b": "x,} // y"}"#
        );
        let text = "{\n  // a comment\n  \"a\": 1, /* b */\n}";
        let value: Value = serde_json::from_str(&to_json(text)).unwrap();
        assert_eq!(value["a"], 1);
    }

    #[test]
    fn splits_install_paths_into_package_names() {
        assert_eq!(package_segments("@a/b/c/@d/e"), ["@a/b", "c", "@d/e"]);
        assert_eq!(package_segments("undici"), ["undici"]);
        assert!(package_segments("").is_empty());
    }

    #[test]
    fn reads_nested_copies_workspaces_and_dev_scope() {
        let (installed, graph) = parse(LOCK).unwrap().into_parts();
        let get = |n: &str, v: &str| {
            installed
                .iter()
                .find(|p| p.name == n && p.version == v)
                .unwrap_or_else(|| panic!("{n}@{v} in {installed:?}"))
        };
        // The nested copy is the one http-client loads; the member's own copy is direct.
        assert!(!get("undici", "6.26.0").direct && !get("undici", "6.26.0").dev);
        assert!(get("undici", "7.1.0").direct);
        // Hoisted but nothing depends on it: neither a root nor runtime.
        assert!(get("undici", "5.0.0").dev);
        assert!(get("@actions/http-client", "4.0.1").direct);
        assert!(get("typescript", "5.6.2").direct && get("typescript", "5.6.2").dev);
        // Only the git dependency pulls left-pad in, so it stays runtime.
        assert!(!get("left-pad", "1.3.0").dev);
        assert!(!installed
            .iter()
            .any(|p| p.name == "vendored" || p.name == "member"));
        assert_eq!(
            graph.chain_to("tunnel"),
            vec!["app", "@actions/http-client", "tunnel"]
        );
    }

    #[test]
    fn fails_closed_on_a_missing_or_unknown_entry() {
        let missing = LOCK.replace(r#""tunnel": ["tunnel@0.0.6", "", {}, "sha512-d"],"#, "");
        assert!(parse(&missing).unwrap_err().contains("`tunnel`"));
        let future = LOCK.replace(r#""lockfileVersion": 1"#, r#""lockfileVersion": 7"#);
        assert!(parse(&future).unwrap_err().contains("lockfileVersion 7"));
        assert!(parse("{not json").is_err());
    }
}
