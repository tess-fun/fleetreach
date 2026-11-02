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
    /// The subset of `deps` marked `optional: true`.
    optional: Vec<String>,
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
        let listed = parse_deps_list(&after_version[..tuple_end]);
        let optional = listed.iter().filter(|d| d.1).map(|d| d.0.clone()).collect();
        let deps = listed.into_iter().map(|d| d.0).collect();
        if !name.is_empty() && !version.is_empty() {
            out.push(RawEntry {
                name,
                version,
                deps,
                optional,
            });
        }
        rest = &after_version[tuple_end..];
    }
    out
}

/// Extract the dependency atom names from the part of a Hex tuple that follows the version:
///
/// ```text
/// , "<inner-hash>", [:mix], [{:plug, "~> 1.14", [hex: :plug, repo: "hexpm", optional: false]}], "hexpm", "<outer-hash>"}
/// ```
///
/// The deps list is the **second** top-level `[...]` group (the first is the build tools).
/// mix writes each dependency as `{:name, "<requirement>", [<options>]}`, so the list holds
/// nested `[...]` options of its own: brackets are matched by depth, skipping quoted strings,
/// and only a `{:atom` directly inside the deps list names a dependency. Each comes back with
/// whether its options say `optional: true`.
fn parse_deps_list(tuple_tail: &str) -> Vec<(String, bool)> {
    let mut deps = Vec::new();
    let (mut depth, mut group, mut quoted) = (0usize, 0usize, false);
    let mut chars = tuple_tail.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => quoted = !quoted,
            '\\' if quoted => {
                chars.next();
            }
            _ if quoted => {}
            '[' => {
                if depth == 0 {
                    group += 1;
                }
                depth += 1;
            }
            ']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 && group == 2 {
                    break;
                }
            }
            '{' if depth == 1 && group == 2 => {
                let atom = tuple_tail[i + 1..].strip_prefix(':').unwrap_or_default();
                let end = atom
                    .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
                    .unwrap_or(atom.len());
                if end > 0 {
                    // A dependency tuple holds no `}` of its own before its end.
                    let tuple = &atom[..atom.find('}').unwrap_or(atom.len())];
                    deps.push((atom[..end].to_string(), tuple.contains("optional: true")));
                }
            }
            // The tuple closes before a deps list was seen (an older 6-element entry).
            '}' if depth == 0 => break,
            _ => {}
        }
    }
    deps
}

/// Parse `mix.lock` text into a deduplicated, sorted set of installed Hex packages **and** the
/// inferred name-level dependency graph. A malformed-but-present line never aborts the scan
/// (mix writes this file, so it is reliable); non-`:hex` dependencies are skipped. Infallible —
/// the caller only reaches here once the file has been read.
///
/// The `direct` flag is inferred from the lockfile's own dependency lists: a package is direct
/// iff no other package requires it. An optional dependency does not count: mix installs one
/// only when something requires it, so if no package does, the project itself must. The returned [`DepGraph`] is rooted at `(root)`, with an
/// edge to each inferred top-level package, so `chain_to(name)` gives full provenance.
pub fn installed_packages(mix_lock: &str) -> (Vec<InstalledPackage>, DepGraph) {
    let entries = raw_entries(mix_lock);

    // Every package another one requires (not just optionally) is not top-level.
    let mut depended_on: BTreeSet<String> = BTreeSet::new();
    for e in &entries {
        for d in e.deps.iter().filter(|d| !e.optional.contains(d)) {
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
    fn reads_deps_lists_as_mix_writes_them() {
        // mix writes each dependency with its own options list. The last `[` in the tuple is
        // then an options list, not the deps list, which once left every package "direct".
        let lock = r#"%{
  "cowboy": {:hex, :cowboy, "2.10.0", "ff9ffeff91dae4ae270dd975642997afe2a1179d94b1887863e43f681a203e26", [:make, :rebar3], [{:cowlib, "2.12.1", [hex: :cowlib, repo: "hexpm", optional: false]}, {:ranch, "1.8.0", [hex: :ranch, repo: "hexpm", optional: false]}], "hexpm", "3afdccb7183cc6f143cb14d3cf51fa00e53db9ec80cdcd525482f5e99bc41d6b"},
  "cowlib": {:hex, :cowlib, "2.12.1", "a9fa9a625f1d2025fe6b462cb865881329b5caff8f1854d1cbc9f9533f00e1e1", [:make, :rebar3], [], "hexpm", "163b73f6367a7341b33c794c4e88e7dbfe6498ac42dcd69ef44c5bc5507c8db0"},
  "phoenix": {:hex, :phoenix, "1.7.10", "02189140a61b2ce85bb633a9b6fd02dff705a5f1596869547aeb2b2b95edd729", [:mix], [{:jason, "~> 1.0", [hex: :jason, repo: "hexpm", optional: true]}, {:plug, "~> 1.14", [hex: :plug, repo: "hexpm", optional: false]}, {:plug_cowboy, "~> 2.6", [hex: :plug_cowboy, repo: "hexpm", optional: true]}], "hexpm", "cf784932e010fd736d656d7fead6a584a4498efefe5b8227e9f383bf15bb79d0"},
  "plug": {:hex, :plug, "1.15.2", "94cf1fa375526f30ff8770837cb804798e0045fd97185f0bb9e5fcd858c792a3", [:mix], [], "hexpm", "02731fa0c2dcb03d8d21a1d941bdbbe99c2946c0db098eee31008e04c6283615"},
  "plug_cowboy": {:hex, :plug_cowboy, "2.6.1", "9a3bbfceeb65eff5f39dab529e5cd79137ac36e913c02067dba3963a26efe9b2", [:mix], [{:cowboy, "~> 2.7", [hex: :cowboy, repo: "hexpm", optional: false]}, {:plug, "~> 1.14", [hex: :plug, repo: "hexpm", optional: false]}], "hexpm", "de36e1a21f451a18b790f37765db198075c25875c64834bcc82d90b309eb6613"},
  "ranch": {:hex, :ranch, "1.8.0", "8c7a100a139fd57f17327b6413e4167ac559fbc04ca7448e9be9057311597a1d", [:make, :rebar3], [], "hexpm", "49fbcfd3682fab1f5d109351b61257676da1a2fdbe295904176d5e521a2ddfe5"},
}"#;
        let (pkgs, graph) = installed_packages(lock);
        let direct: Vec<&str> = pkgs
            .iter()
            .filter(|p| p.direct)
            .map(|p| p.name.as_str())
            .collect();
        // plug_cowboy is only an optional dependency of phoenix, so the project requires it.
        assert_eq!(direct, vec!["phoenix", "plug_cowboy"]);
        assert_eq!(
            graph.chain_to("ranch"),
            vec!["(root)", "plug_cowboy", "cowboy", "ranch"]
        );
        assert_eq!(graph.chain_to("plug"), vec!["(root)", "phoenix", "plug"]);
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
