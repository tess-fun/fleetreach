//! Parse a `Gemfile.lock` into a flat, deduplicated set of installed gems — the input the
//! OSV matcher scans. Read straight from the lockfile, so it needs **no Ruby toolchain and
//! no network**: Bundler already pins every gem to one exact version across the full
//! transitive tree.
//!
//! `Gemfile.lock` is Bundler's own indented text format, not TOML/JSON, so this is a small
//! hand-rolled parser. Its shape:
//!
//! ```text
//! GEM
//!   remote: https://rubygems.org/
//!   specs:
//!     rack (2.2.8)             <- 4-space: a resolved gem (name + exact version)
//!     rails (7.0.4)
//!       actioncable (= 7.0.4)  <- 6-space: a dependency edge (a requirement, skipped)
//! GIT / PATH                   <- non-rubygems.org sources: not registry-matchable
//!   ...
//! DEPENDENCIES
//!   rails (~> 7.0)             <- the direct set (with optional `!` / constraint)
//! ```
//!
//! Only gems under a `GEM` section whose `remote:` is rubygems.org are
//! registry-matchable; `GIT`/`PATH` sections and private `GEM` remotes have no OSV
//! `RubyGems` advisory to match and are skipped (the same stance as the npm/PyPI feeders'
//! non-registry pins). Gem names are matched **verbatim** — RubyGems names are
//! case-sensitive and not normalized, unlike PyPI.

use std::collections::BTreeSet;

use fleetreach_core::DepGraph;

/// One resolved gem from `Gemfile.lock`: its name (verbatim), exact installed version, and
/// whether the project depends on it **directly** (it appears in the `DEPENDENCIES`
/// section) rather than transitively.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstalledGem {
    pub name: String,
    pub version: String,
    pub direct: bool,
}

/// Which top-level section the parser is currently inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    /// A `GEM` source; `matchable` is true only for the rubygems.org registry.
    Gem { matchable: bool },
    /// A `GIT` or `PATH` source — not registry-matchable.
    NonRegistry,
    /// The `DEPENDENCIES` block — the direct set.
    Dependencies,
    /// Any other block (`PLATFORMS`, `CHECKSUMS`, `BUNDLED WITH`, ...).
    Other,
}

/// Parse `Gemfile.lock` text into a deduplicated, sorted set of installed gems. Only
/// rubygems.org `GEM` specs are returned; the `DEPENDENCIES` section marks the `direct`
/// flag. A malformed-but-present line never aborts the parse — Bundler writes this file, so
/// the structure is reliable — but an empty result for a non-empty lockfile is impossible
/// to confuse with "no lockfile" because the caller only reaches here once the file is read.
pub fn installed_gems(lock_text: &str) -> Vec<InstalledGem> {
    let direct = direct_set(lock_text);

    let mut section = Section::Other;
    let mut in_specs = false;
    let mut gems: Vec<InstalledGem> = Vec::new();

    for line in lock_text.lines() {
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // A non-indented, non-empty line is a section header.
        if indent == 0 {
            section = match trimmed {
                "GEM" => Section::Gem { matchable: false },
                "GIT" | "PATH" => Section::NonRegistry,
                "DEPENDENCIES" => Section::Dependencies,
                _ => Section::Other,
            };
            in_specs = false;
            continue;
        }

        match section {
            Section::Gem { .. } | Section::NonRegistry => {
                // `  remote:` flips a GEM source matchable iff it is rubygems.org.
                if indent == 2 {
                    if let Some(remote) = trimmed.strip_prefix("remote:") {
                        if let Section::Gem { matchable } = &mut section {
                            *matchable = is_rubygems_org(remote.trim());
                        }
                    }
                    in_specs = trimmed == "specs:";
                    continue;
                }
                // A 4-space line within `specs:` is a resolved gem; deeper lines (6-space)
                // are that gem's dependency edges (requirements, not resolved versions).
                if in_specs && indent == 4 {
                    if let Section::Gem { matchable: true } = section {
                        if let Some((name, version)) = parse_spec(trimmed) {
                            gems.push(InstalledGem {
                                name: name.clone(),
                                version,
                                direct: direct.contains(&name),
                            });
                        }
                    }
                }
            }
            Section::Dependencies | Section::Other => {}
        }
    }

    dedupe(gems)
}

/// Build the `dependency_path` provenance graph from `Gemfile.lock`. Nodes are verbatim gem
/// names; the synthetic root is `"(root)"`. Edges come from two places:
///
/// * `"(root)" -> name` for each name in the `DEPENDENCIES` section (the direct set).
/// * `gem -> requirement` for each 6-space dependency-edge line under a 4-space resolved gem
///   inside a `GEM ... specs:` block (regardless of which `GEM` remote it is — the tree shape
///   is independent of registry-matchability).
///
/// `chain_to(&gem.name)` then yields `[(root), …, gem]`, matching the occurrence's verbatim
/// `package`. A lockfile with no `specs:` edges produces an edgeless graph, so `chain_to`
/// honestly returns an empty chain (unknown provenance) rather than a wrong one.
pub fn dependency_graph(lock_text: &str) -> DepGraph {
    let mut graph = DepGraph::new("(root)");

    for name in direct_set(lock_text) {
        graph.add_edges("(root)", [name]);
    }

    let mut in_specs = false;
    let mut in_gem = false;
    let mut current: Option<String> = None;
    for line in lock_text.lines() {
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if indent == 0 {
            in_gem = trimmed == "GEM";
            in_specs = false;
            current = None;
            continue;
        }
        if !in_gem {
            continue;
        }
        if indent == 2 {
            in_specs = trimmed == "specs:";
            current = None;
            continue;
        }
        if !in_specs {
            continue;
        }
        // A 4-space line is a resolved gem (the edge source); a 6-space line under it is one
        // of that gem's dependency edges (the requirement name = token before ` ` or `(`).
        if indent == 4 {
            current = parse_spec(trimmed).map(|(name, _)| name);
        } else if indent == 6 {
            if let Some(from) = &current {
                let req = trimmed
                    .split([' ', '('])
                    .next()
                    .unwrap_or(trimmed)
                    .trim_end_matches('!');
                if !req.is_empty() {
                    graph.add_edges(from, [req.to_string()]);
                }
            }
        }
    }
    graph
}

/// The direct-dependency names: the `DEPENDENCIES` section lists each direct gem at
/// 2-space indent as `name`, `name (~> 1.2)`, or `name!` (a source-pinned dep). Strip the
/// trailing `!` and any version constraint.
fn direct_set(lock_text: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let mut in_dependencies = false;
    for line in lock_text.lines() {
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if indent == 0 {
            in_dependencies = trimmed == "DEPENDENCIES";
            continue;
        }
        if in_dependencies && indent == 2 {
            // Take the leading token up to a space or `(`, then drop a trailing `!`.
            let name = trimmed
                .split([' ', '('])
                .next()
                .unwrap_or(trimmed)
                .trim_end_matches('!');
            if !name.is_empty() {
                set.insert(name.to_string());
            }
        }
    }
    set
}

/// Parse a `specs:` line `name (version)` into `(name, version)`. The version may carry a
/// platform suffix (`1.13.10-x86_64-linux`) — left intact here and stripped at version
/// parse time. Returns `None` for a line without the `name (version)` shape.
fn parse_spec(line: &str) -> Option<(String, String)> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    if close <= open {
        return None;
    }
    let name = line[..open].trim();
    let version = line[open + 1..close].trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// Whether a `remote:` URL points at the public rubygems.org registry (the only source for
/// which OSV `RubyGems` advisories apply). A private gem server is not matchable.
fn is_rubygems_org(remote: &str) -> bool {
    let host = remote
        .trim_end_matches('/')
        .strip_prefix("https://")
        .or_else(|| remote.trim_end_matches('/').strip_prefix("http://"))
        .unwrap_or(remote);
    host == "rubygems.org" || host == "www.rubygems.org"
}

/// Collapse duplicate `(name, version)` rows into one, with `direct` winning if any
/// occurrence was direct, and sort for deterministic output.
fn dedupe(gems: Vec<InstalledGem>) -> Vec<InstalledGem> {
    let mut by_key: std::collections::BTreeMap<(String, String), bool> =
        std::collections::BTreeMap::new();
    for g in gems {
        let e = by_key.entry((g.name, g.version)).or_insert(false);
        *e = *e || g.direct;
    }
    by_key
        .into_iter()
        .map(|((name, version), direct)| InstalledGem {
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

    fn rows(gems: &[InstalledGem]) -> Vec<(&str, &str, bool)> {
        gems.iter()
            .map(|g| (g.name.as_str(), g.version.as_str(), g.direct))
            .collect()
    }

    const LOCK: &str = r#"GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.8)
    rails (7.0.4)
      actioncable (= 7.0.4)
      activesupport (= 7.0.4)
    nokogiri (1.13.10-x86_64-linux)
      racc (~> 1.4)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  rails (~> 7.0)
  rack

BUNDLED WITH
   2.4.1
"#;

    #[test]
    fn parses_specs_with_direct_set_and_platform() {
        let gems = installed_gems(LOCK);
        assert_eq!(
            rows(&gems),
            vec![
                // nokogiri's platform suffix is kept verbatim here; version parsing strips it.
                ("nokogiri", "1.13.10-x86_64-linux", false),
                ("rack", "2.2.8", true),
                ("rails", "7.0.4", true),
            ]
        );
    }

    #[test]
    fn skips_dependency_edges_under_specs() {
        // actioncable/activesupport/racc are 6-space dependency edges, not resolved gems.
        let gems = installed_gems(LOCK);
        assert!(gems.iter().all(|g| g.name != "actioncable"));
        assert!(gems.iter().all(|g| g.name != "racc"));
    }

    #[test]
    fn skips_git_and_path_and_private_sources() {
        let lock = r#"GIT
  remote: https://github.com/ruby/irb
  revision: 9bb6562d
  specs:
    irb (1.2.4)

PATH
  remote: ./vendor/mygem
  specs:
    mygem (0.1.0)

GEM
  remote: https://gems.example.com/
  specs:
    private_gem (3.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.8)

DEPENDENCIES
  irb!
  mygem!
  rack
"#;
        let gems = installed_gems(lock);
        // Only the rubygems.org gem is matchable; git/path/private are skipped.
        assert_eq!(rows(&gems), vec![("rack", "2.2.8", true)]);
    }

    #[test]
    fn dependencies_section_strips_bang_and_constraint() {
        let set =
            direct_set("DEPENDENCIES\n  rails (~> 7.0)\n  rack\n  mygem!\n  pg (>= 1.1, < 2.0)\n");
        assert!(set.contains("rails"));
        assert!(set.contains("rack"));
        assert!(set.contains("mygem"));
        assert!(set.contains("pg"));
    }

    #[test]
    fn empty_lockfile_yields_no_gems() {
        assert!(installed_gems("").is_empty());
        // A lockfile with only non-registry sources is matchable-empty (not an error).
        assert!(installed_gems("GIT\n  remote: x\n  specs:\n    g (1.0)\n").is_empty());
    }

    #[test]
    fn dependency_graph_chains_transitive_and_direct() {
        let g = dependency_graph(LOCK);
        // rack is a direct dependency: a 2-name chain from the root.
        assert_eq!(g.chain_to("rack"), vec!["(root)", "rack"]);
        // actioncable is reached transitively via rails (a 6-space edge under it).
        assert_eq!(
            g.chain_to("actioncable"),
            vec!["(root)", "rails", "actioncable"]
        );
        // nokogiri is not in DEPENDENCIES in this fixture, so racc (reached only via
        // nokogiri) is unreachable from the root -> honest empty chain.
        assert!(g.chain_to("racc").is_empty());
    }

    #[test]
    fn dependency_graph_empty_without_any_edges() {
        // No DEPENDENCIES and no GEM/specs edges -> edgeless graph -> honest empty chain.
        assert!(dependency_graph("PLATFORMS\n  ruby\n")
            .chain_to("rack")
            .is_empty());
    }

    #[test]
    fn dedupes_same_name_version_direct_wins() {
        let gems = dedupe(vec![
            InstalledGem {
                name: "x".into(),
                version: "1.0".into(),
                direct: false,
            },
            InstalledGem {
                name: "x".into(),
                version: "1.0".into(),
                direct: true,
            },
        ]);
        assert_eq!(rows(&gems), vec![("x", "1.0", true)]);
    }
}
