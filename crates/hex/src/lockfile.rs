//! Parse an Elixir `mix.lock` into a flat, deduplicated set of installed Hex packages — the
//! input the OSV matcher scans. Read straight from the lockfile, so it needs **no Elixir/mix
//! toolchain and no network**: `mix.lock` already pins every dependency to an exact version.
//!
//! `mix.lock` is an Elixir map literal (not JSON/TOML), so this is a small hand-rolled scan.
//! Each Hex dependency is a tuple whose first element is `:hex`:
//!
//! ```text
//! %{
//!   "phoenix": {:hex, :phoenix, "1.6.2", "<hash>", [:mix], [ ... ], "hexpm", "<hash>"},
//!   "my_git_dep": {:git, "https://github.com/x/y.git", "<ref>", []},
//! }
//! ```
//!
//! The matcher reads the `:hex` tuples: the **second** element is the canonical Hex package
//! name (lowercase) and the **third** is the exact version. `{:git, ...}` / `{:path, ...}`
//! dependencies have no Hex registry release and are skipped.
//!
//! `mix.lock` does not carry the project's own `mix.exs` deps list, but it *does* record, in
//! each tuple's **sixth** element, that package's own direct dependencies:
//!
//! ```text
//! {:hex, :phoenix, "1.6.2", "<hash>", [:mix], [{:plug, "~> 1.10"}], "hexpm", "<hash>"}
//! //                                          ^^^^^^^^^^^^^^^^^^^^^^ deps of :phoenix
//! ```
//!
//! That lets the tree be inferred from the lockfile alone: build a name-level [`DepGraph`]
//! (`pkg -> each listed dep`), then treat a package as **direct/top-level** iff no other
//! package lists it as a dependency. A synthetic `(root)` node gains an edge to every such
//! top-level package, so `chain_to` yields `[(root), …, target]` provenance without a
//! toolchain or `mix.exs`.

use std::collections::{BTreeMap, BTreeSet};

use fleetreach_core::DepGraph;

/// The synthetic graph root, since `mix.lock` has no node for the scanned project itself.
const ROOT: &str = "(root)";

/// One resolved package from `mix.lock`: its Hex name (verbatim, lowercase), exact installed
/// version, and whether it is a direct dependency — inferred as "nothing else depends on it".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub direct: bool,
}

/// One raw Hex tuple as scanned: name, version, and the names this package directly requires.
struct RawEntry {
    name: String,
    version: String,
    deps: Vec<String>,
}

/// Scan every `:hex` tuple out of `mix.lock`, capturing name, version, and the sixth-element
/// deps list. Non-`:hex` (git/path) dependencies have no Hex release and are skipped.
fn raw_entries(mix_lock: &str) -> Vec<RawEntry> {
    let mut out = Vec::new();
    let mut rest = mix_lock;
    // Each Hex entry begins with the `{:hex,` tag; everything else (git/path deps, the map
    // key, comments) is skipped by scanning to the next tag.
    while let Some(pos) = rest.find("{:hex,") {
        rest = &rest[pos + "{:hex,".len()..];
        // The second tuple element is the package name atom `:name`.
        let trimmed = rest.trim_start();
        let Some(atom) = trimmed.strip_prefix(':') else {
            rest = trimmed;
            continue;
        };
        let name_end = atom
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(atom.len());
        let name = atom[..name_end].to_string();
        // The third element is the version, the next double-quoted string.
        let tail = &atom[name_end..];
        let Some(q1) = tail.find('"') else { break };
        let vtail = &tail[q1 + 1..];
        let Some(q2) = vtail.find('"') else { break };
        let version = vtail[..q2].to_string();
        // After the version comes the outer hash, the build-tools list (`[:mix]`-style), the
        // **deps** list (whose own `{:dep}` tuples contain `}`), then `, "hexpm"`. Bound the
        // deps scan at the start of the NEXT `:hex` entry so it covers this whole tuple
        // (including multi-element deps lists) without ever reading into the next package.
        let after_version = &vtail[q2 + 1..];
        let tuple_end = after_version.find("{:hex,").unwrap_or(after_version.len());
        let deps = parse_deps_list(&after_version[..tuple_end]);
        if !name.is_empty() && !version.is_empty() {
            out.push(RawEntry {
                name,
                version,
                deps,
            });
        }
        rest = &after_version[tuple_end..];
    }
    out
}

/// Extract the dependency atom names from the part of a Hex tuple that follows the version
/// (i.e. `, "<outer-hash>", [:mix], [{:plug, "~> 1.10"}, ...], "hexpm", "<inner-hash>"`,
/// truncated at the tuple's `}`). The deps list is the bracketed group that precedes the
/// `"hexpm"` registry string; each `{:atom,` inside it names one direct dependency. Robust to
/// an empty list `[]` and to the build-tools list (`[:mix, :rebar3]`), which holds bare atoms
/// but no `{` tuples and so contributes no names.
fn parse_deps_list(tuple_tail: &str) -> Vec<String> {
    // The deps list sits between the build-tools list and the `"hexpm"` registry string, and
    // is the LAST `[...]` group before that registry string. The quoted strings around it are
    // the outer hash (before the lists) and `"hexpm"`/inner-hash (after). To stay clear of the
    // trailing `"hexpm", "<hash>"` strings, bound the scan at the last `[` .. matching `]`.
    let Some(open) = tuple_tail.rfind('[') else {
        return Vec::new();
    };
    let after_open = &tuple_tail[open..];
    let close = after_open.find(']').unwrap_or(after_open.len());
    let region = &after_open[..close];
    // Within the deps list, each direct dep is introduced by `{:`. The build-tools list is a
    // separate (earlier) `[...]` group and is never reached, so its bare atoms are ignored.
    let mut deps = Vec::new();
    let mut scan = region;
    while let Some(p) = scan.find("{:") {
        let atom = &scan[p + 2..];
        let end = atom
            .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
            .unwrap_or(atom.len());
        let name = &atom[..end];
        if !name.is_empty() {
            deps.push(name.to_string());
        }
        scan = &atom[end..];
    }
    deps
}

/// Parse `mix.lock` text into a deduplicated, sorted set of installed Hex packages **and** the
/// inferred name-level dependency graph. A malformed-but-present line never aborts the scan
/// (mix writes this file, so it is reliable); non-`:hex` dependencies are skipped. Infallible —
/// the caller only reaches here once the file has been read.
///
/// The `direct` flag is inferred from the lockfile's own dependency lists: a package is direct
/// iff no other package depends on it. The returned [`DepGraph`] is rooted at `(root)`, with an
/// edge to each inferred top-level package, so `chain_to(name)` gives full provenance.
pub fn installed_packages(mix_lock: &str) -> (Vec<InstalledPackage>, DepGraph) {
    let entries = raw_entries(mix_lock);

    // Every package that appears as someone else's dependency is, by definition, not top-level.
    let mut depended_on: BTreeSet<String> = BTreeSet::new();
    for e in &entries {
        for d in &e.deps {
            depended_on.insert(d.clone());
        }
    }

    let mut graph = DepGraph::new(ROOT);
    for e in &entries {
        graph.add_edges(&e.name, e.deps.iter().cloned());
        // Inferred top-level: nothing in the lockfile lists this package as a dependency.
        if !depended_on.contains(&e.name) {
            graph.add_edges(ROOT, [e.name.clone()]);
        }
    }

    let packages = entries
        .into_iter()
        .map(|e| {
            let direct = !depended_on.contains(&e.name);
            InstalledPackage {
                name: e.name,
                version: e.version,
                direct,
            }
        })
        .collect();

    (dedupe(packages), graph)
}

/// Collapse duplicate `(name, version)` rows into one and sort for deterministic output.
fn dedupe(packages: Vec<InstalledPackage>) -> Vec<InstalledPackage> {
    let mut by_key: BTreeMap<(String, String), bool> = BTreeMap::new();
    for p in packages {
        let e = by_key.entry((p.name, p.version)).or_insert(false);
        *e = *e || p.direct;
    }
    by_key
        .into_iter()
        .map(|((name, version), direct)| InstalledPackage {
            name,
            version,
            direct,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn rows(pkgs: &[InstalledPackage]) -> Vec<(&str, &str)> {
        pkgs.iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect()
    }

    const LOCK: &str = r#"%{
  "phoenix": {:hex, :phoenix, "1.6.2", "abc", [:mix], [{:plug, "~> 1.10"}], "hexpm", "def"},
  "plug": {:hex, :plug, "1.12.1", "ghi", [:mix], [], "hexpm", "jkl"},
  "my_git_dep": {:git, "https://github.com/x/y.git", "deadbeef", []},
  "decimal": {:hex, :decimal, "2.0.0", "mno", [:mix], [], "hexpm", "pqr"},
}
"#;

    #[test]
    fn parses_hex_entries_skips_git() {
        let (pkgs, _graph) = installed_packages(LOCK);
        assert_eq!(
            rows(&pkgs),
            vec![
                ("decimal", "2.0.0"),
                ("phoenix", "1.6.2"),
                ("plug", "1.12.1"),
            ]
        );
        // The git dependency has no Hex release → skipped.
        assert!(pkgs.iter().all(|p| p.name != "my_git_dep" && p.name != "y"));
    }

    #[test]
    fn handles_prerelease_versions() {
        let lock = r#"%{ "ash": {:hex, :ash, "3.0.0-rc.1", "h", [:mix], [], "hexpm", "h2"} }"#;
        let (pkgs, _g) = installed_packages(lock);
        assert_eq!(rows(&pkgs), vec![("ash", "3.0.0-rc.1")]);
    }

    #[test]
    fn empty_and_non_hex_lockfiles() {
        assert!(installed_packages("%{}").0.is_empty());
        assert!(installed_packages("").0.is_empty());
        // A lockfile with only git deps is matchable-empty.
        assert!(installed_packages(r#"%{ "g": {:git, "u", "r", []} }"#)
            .0
            .is_empty());
    }

    #[test]
    fn infers_direct_flag_from_deps_lists() {
        // In LOCK, phoenix depends on plug → plug is transitive; phoenix and decimal are
        // listed by no one → direct.
        let (pkgs, _g) = installed_packages(LOCK);
        let direct: BTreeMap<&str, bool> =
            pkgs.iter().map(|p| (p.name.as_str(), p.direct)).collect();
        assert!(direct["phoenix"]);
        assert!(direct["decimal"]);
        assert!(!direct["plug"]);
    }

    #[test]
    fn graph_yields_direct_and_transitive_chains() {
        let (_pkgs, graph) = installed_packages(LOCK);
        // Transitive: (root) -> phoenix -> plug.
        assert_eq!(graph.chain_to("plug"), vec!["(root)", "phoenix", "plug"]);
        // Direct: (root) -> phoenix.
        assert_eq!(graph.chain_to("phoenix"), vec!["(root)", "phoenix"]);
        assert_eq!(graph.chain_to("decimal"), vec!["(root)", "decimal"]);
    }

    #[test]
    fn ignores_build_tools_list_and_hashes() {
        // The build-tools list `[:mix, :rebar3]` holds bare atoms (no `{:` tuples) and must
        // not be read as dependencies; only the sixth-element `{:dep}` tuples count.
        let lock = r#"%{
  "a": {:hex, :a, "1.0.0", "h1", [:mix, :rebar3], [{:b, "~> 1.0"}], "hexpm", "h2"},
  "b": {:hex, :b, "2.0.0", "h3", [:mix], [], "hexpm", "h4"},
}"#;
        let (pkgs, _g) = installed_packages(lock);
        let direct: BTreeMap<&str, bool> =
            pkgs.iter().map(|p| (p.name.as_str(), p.direct)).collect();
        // `a` requires `b`; `:mix`/`:rebar3` are not deps.
        assert!(direct["a"]);
        assert!(!direct["b"]);
    }
}
