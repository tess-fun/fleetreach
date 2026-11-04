//! Read `pnpm-lock.yaml` (spec 02): lockfile versions 5.x, 6.x and 9.x.
//!
//! - **v9**: `importers.<path>.{dependencies,devDependencies,optionalDependencies}` name the
//!   project's roots; `snapshots` holds every installed instance keyed by
//!   `name@version(peer suffix)`, with its own dependency maps.
//! - **v6**: the same, but instances live in `packages` under keys with a leading `/`, and a
//!   single-project lockfile puts the root maps at the top level instead of in `importers`.
//! - **v5**: as v6, but keys are paths (`/name/1.2.3_peer@1`, `/@scope/name/1.2.3`) and a
//!   dependency value is `1.2.3_peer@1`, or `/other/1.2.3` for an alias. Paths are rewritten
//!   to the `name@version(peers)` ids the other versions use.
//!
//! Dependency values are a version (`4.17.21`, maybe with a peer suffix), an alias
//! (`string-width@4.2.3`, or `/string-width@4.2.3` in v6), or a local spec (`link:`,
//! `file:`) that names no registry package. Catalogs need no step of their own: importers
//! record the version a `catalog:` specifier resolved to. Older formats fail closed with the
//! version named rather than being half-read.

use crate::resolved::{split_name_version, Node, Resolved};
use crate::yaml::{self, Node as Y};

/// Parse a `pnpm-lock.yaml` body.
pub(crate) fn parse(text: &str) -> Result<Resolved, String> {
    let docs = yaml::parse(text)?;
    // A lockfile may hold several documents; the project graph is the last one.
    let doc = docs.last().ok_or("empty pnpm-lock.yaml")?;
    let version = doc
        .str_at("lockfileVersion")
        .ok_or("pnpm-lock.yaml has no lockfileVersion")?;
    let major = version
        .trim_matches('\'')
        .split('.')
        .next()
        .unwrap_or_default();
    let format = match major {
        "9" => Format::V9,
        "6" | "7" => Format::V6,
        "5" => Format::V5,
        other => {
            return Err(format!(
            "pnpm lockfileVersion {version} is not supported (5.x, 6.x and 9.x are; major {other})"
        ))
        }
    };

    let mut resolved = Resolved {
        root_name: "(root)".to_string(),
        ..Resolved::default()
    };

    // Instances.
    let instances = if format == Format::V9 {
        doc.get("snapshots")
    } else {
        doc.get("packages")
    };
    for (key, entry) in instances.map(Y::entries).unwrap_or_default() {
        let Some(id) = instance_id(key, format) else {
            continue;
        };
        let Some((name, version)) = split_name_version(strip_peers(&id)) else {
            continue;
        };
        let mut deps = Vec::new();
        for section in ["dependencies", "optionalDependencies"] {
            for (dep, spec) in entry.get(section).map(Y::entries).unwrap_or_default() {
                if let Some(child) = spec.as_str().and_then(|s| target_id(dep, s, format)) {
                    deps.push(child);
                }
            }
        }
        resolved.nodes.insert(
            id.clone(),
            Node {
                name: name.to_string(),
                version: version.to_string(),
                deps,
            },
        );
    }

    // Roots: every importer (workspace member), or the top level of a v6 single project.
    let importers: Vec<&Y> = match doc.get("importers") {
        Some(map) => map.entries().iter().map(|(_, v)| v).collect(),
        None => vec![doc],
    };
    for importer in importers {
        for (section, dev) in [
            ("dependencies", false),
            ("optionalDependencies", false),
            ("devDependencies", true),
        ] {
            for (dep, spec) in importer.get(section).map(Y::entries).unwrap_or_default() {
                // v9 and v6 importers store `{specifier, version}`; very old v6 files store
                // the version directly.
                let version = spec.str_at("version").or_else(|| spec.as_str());
                let Some(version) = version else { continue };
                match target_id(dep, version, format) {
                    Some(id) if dev => {
                        resolved.dev_roots.insert(id);
                    }
                    Some(id) => {
                        resolved.prod_roots.insert(id);
                    }
                    // A workspace link or local path: not a registry package.
                    None => {}
                }
            }
        }
    }
    // A root id with no instance (a malformed or truncated file) would silently drop a
    // package; fail closed instead.
    if let Some(missing) = resolved
        .prod_roots
        .iter()
        .chain(&resolved.dev_roots)
        .find(|id| !resolved.nodes.contains_key(*id))
    {
        return Err(format!(
            "pnpm-lock.yaml lists `{missing}` as a dependency but has no entry for it"
        ));
    }
    Ok(resolved)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    V5,
    V6,
    V9,
}

/// The `name@version(peers)` id of a `packages` or `snapshots` key. `None` for a v5 key that
/// is no registry path, such as `github.com/owner/repo/<commit>`.
pub(crate) fn instance_id(key: &str, format: Format) -> Option<String> {
    match format {
        Format::V5 => v5_id(key.strip_prefix('/')?),
        _ => Some(key.strip_prefix('/').unwrap_or(key).to_string()),
    }
}

/// `name/1.2.3_peers` or `@scope/name/1.2.3_peers` as `name@1.2.3(peers)`. Lockfiles before
/// 5.2 put the peers in a further path segment.
fn v5_id(path: &str) -> Option<String> {
    let segments = if path.starts_with('@') { 2 } else { 1 };
    let mut parts = path.splitn(segments + 2, '/');
    let name: Vec<&str> = parts.by_ref().take(segments).collect();
    let version = parts.next()?;
    let (version, peers) = match (version.split_once('_'), parts.next()) {
        (Some((version, peers)), _) => (version, Some(peers)),
        (None, peers) => (version, peers),
    };
    let name = name.join("/");
    Some(match peers {
        Some(peers) => format!("{name}@{version}({peers})"),
        None => format!("{name}@{version}"),
    })
}

/// The instance id a dependency value points at, or `None` for a local spec.
fn target_id(dep: &str, spec: &str, format: Format) -> Option<String> {
    if ["link:", "file:", "workspace:", "portal:"]
        .iter()
        .any(|p| spec.starts_with(p))
    {
        return None;
    }
    if format == Format::V5 {
        return match spec.strip_prefix('/') {
            Some(path) => v5_id(path),
            // A git or tarball dependency is written as a host path.
            None if spec.contains('/') => None,
            None => v5_id(&format!("{dep}/{spec}")),
        };
    }
    let spec = spec.strip_prefix('/').unwrap_or(spec);
    // An alias names the real package itself (`string-width@4.2.3`); a plain version needs
    // the dependency name prefixed.
    if split_name_version(strip_peers(spec)).is_some() {
        Some(spec.to_string())
    } else {
        Some(format!("{dep}@{spec}"))
    }
}

/// Drop a pnpm peer suffix: `react-dom@18.2.0(react@18.2.0)` -> `react-dom@18.2.0`.
pub(crate) fn strip_peers(id: &str) -> &str {
    id.split('(').next().unwrap_or(id)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const V9: &str = r"lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      lodash:
        specifier: ^4.17.20
        version: 4.17.20
      react-dom:
        specifier: ^18.2.0
        version: 18.2.0(react@18.2.0)
      sw:
        specifier: npm:string-width@^4.2.0
        version: string-width@4.2.3
    devDependencies:
      vitest:
        specifier: ^1.0.0
        version: 1.6.0

  packages/lib:
    dependencies:
      app-core:
        specifier: workspace:*
        version: link:../core
      '@babel/core':
        specifier: ^7.24.0
        version: 7.24.0

packages:

  lodash@4.17.20:
    resolution: {integrity: sha512-a}

snapshots:

  '@babel/core@7.24.0':
    dependencies:
      debug: 4.3.4

  debug@4.3.4: {}

  lodash@4.17.20: {}

  loose-envify@1.4.0: {}

  react-dom@18.2.0(react@18.2.0):
    dependencies:
      loose-envify: 1.4.0
      react: 18.2.0

  react@18.2.0:
    dependencies:
      loose-envify: 1.4.0

  string-width@4.2.3: {}

  vitest@1.6.0:
    dependencies:
      tinyspy: 2.2.1

  tinyspy@2.2.1: {}
";

    #[test]
    fn reads_v9_roots_instances_aliases_and_dev() {
        let (installed, graph) = parse(V9).unwrap().into_parts();
        let get = |n: &str| {
            installed
                .iter()
                .find(|p| p.name == n)
                .unwrap_or_else(|| panic!("{n} missing: {installed:?}"))
        };
        assert_eq!(get("lodash").version, "4.17.20");
        assert!(get("lodash").direct && !get("lodash").dev);
        assert_eq!(get("react-dom").version, "18.2.0", "peer suffix stripped");
        assert!(
            get("string-width").direct,
            "alias resolves to the real package"
        );
        assert!(
            get("@babel/core").direct,
            "workspace member roots are direct"
        );
        assert!(!get("debug").direct && !get("debug").dev);
        assert!(get("vitest").dev && get("tinyspy").dev);
        assert!(!get("react").dev);
        assert!(
            installed.iter().all(|p| p.name != "app-core"),
            "link: is local"
        );
        assert_eq!(
            graph.chain_to("tinyspy"),
            vec!["(root)", "vitest", "tinyspy"]
        );
    }

    #[test]
    fn reads_v6_single_project() {
        let v6 = r"lockfileVersion: '6.0'

dependencies:
  lodash:
    specifier: ^4.17.20
    version: 4.17.20

devDependencies:
  sw:
    specifier: npm:string-width@4.2.3
    version: /string-width@4.2.3

packages:

  /lodash@4.17.20:
    resolution: {integrity: sha512-a}
    dev: false

  /string-width@4.2.3:
    resolution: {integrity: sha512-b}
    dependencies:
      strip-ansi: 6.0.1
    dev: true

  /strip-ansi@6.0.1:
    dev: true
";
        let (installed, _) = parse(v6).unwrap().into_parts();
        let names: Vec<(&str, &str, bool, bool)> = installed
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str(), p.direct, p.dev))
            .collect();
        assert_eq!(
            names,
            vec![
                ("lodash", "4.17.20", true, false),
                ("string-width", "4.2.3", true, true),
                ("strip-ansi", "6.0.1", false, true),
            ]
        );
    }

    #[test]
    fn reads_v5_paths_peers_aliases_and_git() {
        let r = parse(
            "lockfileVersion: 5.4

specifiers:
  tsup: ^5.0.0
  sw: npm:string-width@4
  mine: github:o/r
  local: link:../local

dependencies:
  sw: /string-width/4.2.3
  mine: github.com/o/r/abc123
  local: link:../local

devDependencies:
  tsup: 5.12.9_typescript@4.8.4

packages:

  /@s/a/1.0.0:
    resolution: {integrity: sha512-a}

  /string-width/4.2.3:
    resolution: {integrity: sha512-b}
    dependencies:
      '@s/a': 1.0.0

  /tsup/5.12.9_typescript@4.8.4:
    resolution: {integrity: sha512-c}
    dependencies:
      typescript: 4.8.4

  /typescript/4.8.4:
    resolution: {integrity: sha512-d}

  github.com/o/r/abc123:
    resolution: {tarball: https://codeload.github.com/o/r/tar.gz/abc123}
    name: mine
    version: 1.0.0
",
        )
        .unwrap();
        let ids: Vec<&str> = r.nodes.keys().map(String::as_str).collect();
        assert_eq!(
            ids,
            [
                "@s/a@1.0.0",
                "string-width@4.2.3",
                "tsup@5.12.9(typescript@4.8.4)",
                "typescript@4.8.4"
            ]
        );
        assert_eq!(r.nodes["tsup@5.12.9(typescript@4.8.4)"].version, "5.12.9");
        assert_eq!(r.nodes["string-width@4.2.3"].deps, ["@s/a@1.0.0"]);
        assert!(r.prod_roots.contains("string-width@4.2.3"));
        assert!(r.dev_roots.contains("tsup@5.12.9(typescript@4.8.4)"));
    }

    #[test]
    fn a_file_dependency_is_followed_but_not_listed() {
        let r = parse(
            "lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      sdk:
        specifier: file:../sdk
        version: file:../sdk

packages:

  a@1.0.0:
    resolution: {integrity: sha512-a}

  sdk@file:../sdk:
    resolution: {directory: ../sdk, type: directory}

snapshots:

  a@1.0.0: {}

  sdk@file:../sdk:
    dependencies:
      a: 1.0.0
",
        )
        .unwrap();
        let (installed, _) = r.into_parts();
        let names: Vec<&str> = installed.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["a"]);
    }

    #[test]
    fn v5_paths_become_ids() {
        for (path, id) in [
            ("a/1.0.0", "a@1.0.0"),
            ("@s/a/1.0.0-rc.1", "@s/a@1.0.0-rc.1"),
            ("a/1.0.0_b@2.0.0+c@3.0.0", "a@1.0.0(b@2.0.0+c@3.0.0)"),
            ("a/1.0.0/b@2.0.0", "a@1.0.0(b@2.0.0)"),
        ] {
            assert_eq!(v5_id(path).as_deref(), Some(id));
        }
        assert_eq!(v5_id("a"), None);
    }

    #[test]
    fn a_catalog_specifier_reads_the_version_it_resolved_to() {
        let r = parse(
            "lockfileVersion: '9.0'

catalogs:
  default:
    a:
      specifier: ^1.0.0
      version: 1.2.0

importers:

  .:
    dependencies:
      a:
        specifier: 'catalog:'
        version: 1.2.0

packages:

  a@1.2.0:
    resolution: {integrity: sha512-a}

snapshots:

  a@1.2.0: {}
",
        )
        .unwrap();
        assert!(r.prod_roots.contains("a@1.2.0"));
    }

    #[test]
    fn old_and_broken_files_fail_closed() {
        let err = parse("lockfileVersion: 3.9\n").unwrap_err();
        assert!(err.contains("3.9"), "{err}");
        let missing = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: ^1\n        version: 1.0.0\nsnapshots: {}\n";
        assert!(parse(missing).unwrap_err().contains("a@1.0.0"));
        assert!(parse(": : :\n  - [").is_err());
    }
}
