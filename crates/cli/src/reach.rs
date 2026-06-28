//! `--reachability`: a **heuristic** source-presence check — NOT static call-graph
//! reachability analysis.
//!
//! Two complementary signals, both build-free greps of the repo's *own* source:
//!
//! - **Cargo (symbol-presence):** for findings whose advisory names functions, grep the
//!   affected repos' `.rs` source for those names ("do I call any affected function in my
//!   code?"). Sets `Some(true)`/`Some(false)`.
//! - **Tier-C feeders (import-presence):** grep the repo's source for use of a **direct**
//!   dependency. For npm / Julia / RubyGems the lockfile coordinate is the import name (exact);
//!   for PyPI / NuGet / Maven / Packagist / Swift / Hex the coordinate differs from the import
//!   name, so the predicate derives import-name *candidates* from the coordinate (a per-ecosystem
//!   heuristic — e.g. Hex `foo_bar` → `FooBar` module). For GitHub Actions a `uses:` reference is
//!   an active CI step, a sound-positive signal. Either way this only ever raises a finding to
//!   `Some(true)` on a positive match;
//!   it **never** emits `Some(false)`, because a grep can miss an import (dynamic `require`,
//!   re-export, an irregular dist→module name) and a false `Some(false)` would let
//!   `--reachable-only` drop a real vulnerability. So the worst a Tier-C miss can do is leave
//!   `reachable = None` (unknown) — never a false-clean; and a heuristic over-match only
//!   over-reports reachability (safe).
//!
//! Verdict meaning:
//! - `Some(true)`  — a name/import appears in your source (possibly reachable).
//! - `Some(false)` — Cargo only: no affected name appears in your source (could *still* be
//!   reached via a dependency — this only scans your code).
//! - `None`        — not checked, advisory names no functions, or a Tier-C dep not found
//!   imported (unknown, never auto-suppressed).
//!
//! A `false` never proves the vuln is unreachable, so it never auto-suppresses by default —
//! `--reachable-only` is a separate, explicit opt-in.

use std::path::Path;

use fleetreach_core::{DependencyKind, Ecosystem, FleetReport, Occurrence};
use walkdir::WalkDir;

use crate::config::Config;

/// Annotate each vulnerability's `reachable` from the source-presence heuristic.
pub fn assess(report: &mut FleetReport, config: &Config) {
    for finding in &mut report.vulnerabilities {
        if finding.ecosystem.is_cargo() {
            assess_cargo_symbols(finding, config);
        } else if let Some(scan) = import_scanner(finding.ecosystem) {
            assess_tier_c_imports(finding, config, scan);
        }
        // Go has its own (govulncheck) engine and is handled in the scan path, not here.
    }
}

// --- Cargo symbol-presence (the original heuristic, unchanged) ---

fn assess_cargo_symbols(finding: &mut fleetreach_core::VulnFinding, config: &Config) {
    if finding.affected_functions.is_empty() {
        return; // nothing to look for -> leave None (unknown)
    }
    // The function/type short names to search for.
    let names: Vec<&str> = finding
        .affected_functions
        .iter()
        .map(|p| p.rsplit("::").next().unwrap_or(p.as_str()))
        .collect();
    // The repos in which this finding appears.
    let repos: std::collections::BTreeSet<&str> = finding
        .occurrences
        .iter()
        .filter_map(|o| match o {
            Occurrence::InRepo { repo, .. } => Some(repo.0.as_str()),
            Occurrence::Toolchain { .. } => None,
        })
        .collect();

    let found = repos.iter().any(|repo_id| {
        config
            .repos
            .iter()
            .find(|r| r.id.0 == *repo_id)
            .is_some_and(|r| source_mentions_symbol(&r.path, &names))
    });
    finding.reachable = Some(found);
}

/// Does any `.rs` file under `dir` (excluding `target/`) mention any of `names`?
fn source_mentions_symbol(dir: &Path, names: &[&str]) -> bool {
    scan_source(dir, &["rs"], &[], |text| {
        names.iter().any(|n| mentions(text, n))
    })
}

/// A crude call/path test: the name used as a call `name(`, a method `.name`, or
/// a path `::name`. Reduces (does not eliminate) coincidental matches.
fn mentions(text: &str, name: &str) -> bool {
    text.contains(&format!("{name}("))
        || text.contains(&format!(".{name}"))
        || text.contains(&format!("::{name}"))
}

// --- Tier-C import-presence ---

/// A pure per-file-text predicate: does this source text import `package`?
type ImportPredicate = fn(text: &str, package: &str) -> bool;

/// The source globs + import predicate for each Tier-C ecosystem. For npm/Julia/RubyGems the
/// lockfile coordinate IS the source import name (exact). For PyPI/NuGet/Maven/Packagist/Swift/Hex
/// the coordinate ≠ the import name, so the predicate derives import-name *candidates* from the
/// coordinate (a heuristic) — but because this only ever raises a finding to `Some(true)` and
/// never to `Some(false)`, a heuristic miss is harmless (the finding stays `None`, never a
/// false-clean) and a coincidental hit only over-reports reachability. GitHub Actions is exact
/// (a `uses:` reference). Only Go is `None` here (it has its own govulncheck engine).
fn import_scanner(eco: Ecosystem) -> Option<(&'static [&'static str], ImportPredicate)> {
    match eco {
        // Coordinate == import name (exact).
        Ecosystem::Npm => Some((&["js", "mjs", "cjs", "ts", "tsx", "jsx"], npm_imports_text)),
        Ecosystem::Julia => Some((&["jl"], julia_imports_text)),
        Ecosystem::RubyGems => Some((&["rb", "rake"], rubygems_imports_text)),
        // Coordinate → import-name candidates (heuristic, fail-open-to-unknown).
        Ecosystem::Pypi => Some((&["py"], pypi_imports_text)),
        Ecosystem::NuGet => Some((&["cs", "fs", "vb"], nuget_imports_text)),
        Ecosystem::Maven => Some((&["java", "kt", "scala", "groovy"], maven_imports_text)),
        Ecosystem::Packagist => Some((&["php"], packagist_imports_text)),
        Ecosystem::Swift => Some((&["swift"], swift_imports_text)),
        Ecosystem::Hex => Some((&["ex", "exs"], hex_module_used_text)),
        // A referenced action actively runs in CI (sound-positive, not a heuristic).
        Ecosystem::GitHubActions => Some((&["yml", "yaml"], ghactions_uses_text)),
        _ => None,
    }
}

/// Raise a Tier-C finding to `Some(true)` if a **direct** dependency it names is imported in
/// any affected repo's own source. Never sets `Some(false)` — see the module docs.
fn assess_tier_c_imports(
    finding: &mut fleetreach_core::VulnFinding,
    config: &Config,
    (exts, pred): (&'static [&'static str], ImportPredicate),
) {
    let imported = finding.occurrences.iter().any(|o| match o {
        Occurrence::InRepo {
            repo,
            package,
            dependency_kind: DependencyKind::Direct,
            ..
        } => config
            .repos
            .iter()
            .find(|r| r.id.0 == repo.0)
            .is_some_and(|r| scan_source(&r.path, exts, &[], |text| pred(text, package))),
        // Transitive deps are expected to be absent from your source (a dependency uses
        // them, not you), so they carry no import signal — leave them unknown.
        _ => false,
    });
    if imported {
        finding.reachable = Some(true);
    }
}

/// npm: a `require`/`import`/dynamic-`import()` whose module specifier is `pkg` or a `pkg/…`
/// subpath. Scoped names (`@scope/name`) work verbatim. The import keyword must be on the
/// same line to keep coincidental string literals from matching.
fn npm_imports_text(text: &str, pkg: &str) -> bool {
    let specifiers = [
        format!("'{pkg}'"),
        format!("\"{pkg}\""),
        format!("'{pkg}/"),
        format!("\"{pkg}/"),
    ];
    text.lines().any(|line| {
        (line.contains("require") || line.contains("import") || line.contains("from"))
            && specifiers.iter().any(|s| line.contains(s.as_str()))
    })
}

/// Julia: a `using`/`import` statement that names the package as a whole word
/// (`using Foo`, `import Foo, Bar`, `import Foo: x`, `using Foo.Sub`).
fn julia_imports_text(text: &str, pkg: &str) -> bool {
    text.lines().any(|line| {
        let t = line.trim_start();
        (t.starts_with("using ") || t.starts_with("import ")) && word_present(line, pkg)
    })
}

/// RubyGems: a `require 'gem'` / `require "gem"` (or a `gem/…` subpath). Some gems require a
/// path that differs from the gem name (e.g. `activesupport` → `require 'active_support'`);
/// those simply stay unknown (`None`) rather than risk a false `Some(false)`.
fn rubygems_imports_text(text: &str, pkg: &str) -> bool {
    let needles = [
        format!("'{pkg}'"),
        format!("\"{pkg}\""),
        format!("'{pkg}/"),
        format!("\"{pkg}/"),
    ];
    text.lines()
        .any(|line| line.contains("require") && needles.iter().any(|n| line.contains(n.as_str())))
}

/// PyPI: `import mod` / `from mod import …`. The PyPI **dist** name usually maps to a module by
/// lowercasing and turning `-`/`.` into `_` (`Flask`→`flask`, `python-dateutil`→`python_dateutil`).
/// Irregular maps (`PyYAML`→`yaml`, `beautifulsoup4`→`bs4`) simply miss → stay unknown.
fn pypi_imports_text(text: &str, pkg: &str) -> bool {
    let module = pkg.to_ascii_lowercase().replace(['-', '.'], "_");
    let candidates = [module, pkg.to_ascii_lowercase()];
    text.lines().any(|line| {
        let t = line.trim_start();
        (t.starts_with("import ") || t.starts_with("from "))
            && candidates
                .iter()
                .any(|c| !c.is_empty() && word_present(line, c))
    })
}

/// NuGet: a `using Some.Namespace;`. The root .NET namespace is usually the package id
/// (`Newtonsoft.Json` → `using Newtonsoft.Json;` / `using Newtonsoft.Json.Linq;`).
fn nuget_imports_text(text: &str, pkg: &str) -> bool {
    text.lines().any(|line| {
        let t = line.trim_start();
        t.strip_prefix("using ")
            .or_else(|| t.strip_prefix("global using "))
            .map(str::trim_start)
            .is_some_and(|rest| namespace_starts_with(rest, pkg))
    })
}

/// Maven: a Java/Kotlin `import group.subpkg.Class;`. The Java package is not the
/// `group:artifact` coordinate, but it almost always starts with the **group** (the org's
/// reverse-DNS), so match the group as the import prefix.
fn maven_imports_text(text: &str, pkg: &str) -> bool {
    let Some((group, _artifact)) = pkg.split_once(':') else {
        return false;
    };
    if group.is_empty() {
        return false;
    }
    text.lines().any(|line| {
        let t = line.trim_start();
        t.strip_prefix("import ")
            .map(|r| r.strip_prefix("static ").unwrap_or(r))
            .map(str::trim_start)
            .is_some_and(|rest| namespace_starts_with(rest, group))
    })
}

/// Packagist: a PHP `use Vendor\Pkg\…;`. The PSR-4 namespace is not in the lockfile, but it is
/// usually a PascalCase of the `vendor`/`name` segments (`monolog/monolog` → `Monolog\`,
/// `symfony/http-kernel` → `…\HttpKernel\`). Match a `use` statement whose namespace contains the
/// PascalCased package segment.
fn packagist_imports_text(text: &str, pkg: &str) -> bool {
    let candidates: Vec<String> = pkg
        .split('/')
        .map(pascal_case)
        .filter(|c| !c.is_empty())
        .collect();
    if candidates.is_empty() {
        return false;
    }
    text.lines().any(|line| {
        let t = line.trim_start();
        t.starts_with("use ") && candidates.iter().any(|c| namespace_segment_present(t, c))
    })
}

/// Swift: an `import Module`. The module name is not the `owner/repo` identity, but it is often
/// the repo name with a leading `swift-` stripped (`swift-nio` → `NIO`, matched case-insensitively).
/// Weak by nature — many modules diverge — but a hit only adds a (true) signal, never suppresses.
fn swift_imports_text(text: &str, pkg: &str) -> bool {
    let id = pkg.rsplit('/').next().unwrap_or(pkg);
    let stripped = id
        .strip_prefix("swift-")
        .or_else(|| id.strip_prefix("Swift"))
        .unwrap_or(id);
    let candidates = [id.to_string(), stripped.replace('-', "")];
    text.lines().any(|line| {
        let t = line.trim_start();
        t.strip_prefix("import ").map(str::trim).is_some_and(|m| {
            candidates
                .iter()
                .any(|c| !c.is_empty() && m.eq_ignore_ascii_case(c))
        })
    })
}

/// Hex (Elixir): a package `foo_bar` exposes a `FooBar` module, referenced as a qualified call
/// (`FooBar.run`, `Plug.Conn`) or named in an `alias`/`import`/`use`/`require` directive. Irregular
/// module names (`ecto_sql` → `Ecto.SQL`, `gen_stage` → `GenStage`) may miss, which is safe — a
/// miss only leaves the finding `None`.
fn hex_module_used_text(text: &str, pkg: &str) -> bool {
    let module = pascal_case(pkg);
    if module.is_empty() {
        return false;
    }
    text.lines().any(|line| {
        let t = line.trim_start();
        let directive = (t.starts_with("alias ")
            || t.starts_with("import ")
            || t.starts_with("use ")
            || t.starts_with("require "))
            && word_present(t, &module);
        directive || module_qualified(line, &module)
    })
}

/// Whether `module` appears as a qualified-call head (`Module.`) at a segment boundary — the
/// char before is neither an identifier char nor `.` (so a submodule `MyApp.Plug.` is not a
/// match for `Plug`).
fn module_qualified(line: &str, module: &str) -> bool {
    let needle = format!("{module}.");
    line.match_indices(&needle).any(|(i, _)| {
        line[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !is_ident_char(c) && c != '.')
    })
}

/// GitHub Actions: a `uses: owner/repo[/subpath]@ref` step. The package id is the lowercased
/// `owner/repo[/subpath]`; a workflow that `uses:` it is actively invoking it in CI, so a match
/// is effectively sound-positive (the finding came from such a line in the first place).
fn ghactions_uses_text(text: &str, pkg: &str) -> bool {
    let needle = format!("{pkg}@");
    text.lines().any(|line| {
        let low = line.to_ascii_lowercase();
        low.contains("uses:") && low.contains(&needle)
    })
}

/// Whether a dotted namespace path (`Newtonsoft.Json.Linq;`) starts with `prefix` at a segment
/// boundary (so `prefix` is followed by `.`, `;`, whitespace, or end — not more identifier).
fn namespace_starts_with(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.chars().next().is_none_or(|c| !is_ident_char(c)))
}

/// Whether a PHP `use` line names `segment` as a whole `\`-delimited namespace segment.
fn namespace_segment_present(line: &str, segment: &str) -> bool {
    line.match_indices(segment).any(|(i, _)| {
        let before = line[..i].chars().next_back();
        let after = line[i + segment.len()..].chars().next();
        before.is_none_or(|c| c == '\\' || c == ' ') && after.is_none_or(|c| !is_ident_char(c))
    })
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// PascalCase a `-`/`_`-separated identifier (`http-kernel` → `HttpKernel`).
fn pascal_case(s: &str) -> String {
    s.split(['-', '_'])
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// Whether `word` appears in `hay` bounded by non-identifier characters (so `Foo` does not
/// match inside `FooBar`). Package names here are ASCII, so byte boundaries are safe.
fn word_present(hay: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let bytes = hay.as_bytes();
    let mut from = 0;
    while let Some(rel) = hay[from..].find(word) {
        let start = from + rel;
        let end = start + word.len();
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_ident_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Walk `dir` for files with one of `exts` (or an exact name in `names`), skipping vendored
/// directories, and return true as soon as `pred` matches a file's text.
fn scan_source(dir: &Path, exts: &[&str], names: &[&str], pred: impl Fn(&str) -> bool) -> bool {
    const SKIP: &[&str] = &["target", "node_modules", "vendor", ".git", "dist", "build"];
    WalkDir::new(dir)
        .into_iter()
        .filter_entry(|e| !SKIP.contains(&e.file_name().to_str().unwrap_or("")))
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            let p = e.path();
            let ext_ok = p
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| exts.contains(&x));
            let name_ok = p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| names.contains(&n));
            ext_ok || name_ok
        })
        .any(|e| {
            std::fs::read_to_string(e.path())
                .map(|text| pred(&text))
                .unwrap_or(false)
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn npm_detects_require_and_import_forms() {
        assert!(npm_imports_text("const _ = require('lodash')", "lodash"));
        assert!(npm_imports_text("import x from \"lodash\"", "lodash"));
        assert!(npm_imports_text("import { a } from 'lodash/fp'", "lodash"));
        assert!(npm_imports_text("await import('lodash')", "lodash"));
        assert!(npm_imports_text("import x from '@scope/pkg'", "@scope/pkg"));
        // a bare string literal is not an import, and a different package is not a match
        assert!(!npm_imports_text("const s = 'lodash'", "lodash"));
        assert!(!npm_imports_text("require('lodash-es')", "lodash"));
        assert!(!npm_imports_text("import x from 'react'", "lodash"));
    }

    #[test]
    fn julia_detects_using_and_import_whole_word() {
        assert!(julia_imports_text("using HTTP", "HTTP"));
        assert!(julia_imports_text("  import HTTP", "HTTP"));
        assert!(julia_imports_text("using HTTP, JSON", "JSON"));
        assert!(julia_imports_text("import HTTP: get", "HTTP"));
        assert!(julia_imports_text("using HTTP.Sub", "HTTP"));
        // whole-word: HTTP must not match inside HTTPClient
        assert!(!julia_imports_text("using HTTPClient", "HTTP"));
        // not an import line
        assert!(!julia_imports_text("x = HTTP", "HTTP"));
    }

    #[test]
    fn rubygems_detects_require_forms() {
        assert!(rubygems_imports_text("require 'rack'", "rack"));
        assert!(rubygems_imports_text("require \"rack\"", "rack"));
        assert!(rubygems_imports_text("require 'rack/utils'", "rack"));
        // a require for a different gem, and a non-require mention, do not match
        assert!(!rubygems_imports_text("require 'rackup'", "rack"));
        assert!(!rubygems_imports_text("rack = 1", "rack"));
    }

    #[test]
    fn word_present_respects_boundaries() {
        assert!(word_present("using Foo, Bar", "Foo"));
        assert!(word_present("a Foo b", "Foo"));
        assert!(!word_present("Foobar", "Foo"));
        assert!(!word_present("myFoo", "Foo"));
    }

    #[test]
    fn pypi_maps_dist_name_to_module() {
        assert!(pypi_imports_text("import requests", "requests"));
        assert!(pypi_imports_text("from flask import Flask", "Flask")); // case-fold
        assert!(pypi_imports_text(
            "import python_dateutil",
            "python-dateutil"
        )); // - -> _
        assert!(pypi_imports_text("import requests.sessions", "requests"));
        // not an import line, and an irregular map (PyYAML->yaml) misses (stays unknown)
        assert!(!pypi_imports_text("x = requests", "requests"));
        assert!(!pypi_imports_text("import yaml", "PyYAML"));
    }

    #[test]
    fn nuget_matches_using_namespace() {
        assert!(nuget_imports_text(
            "using Newtonsoft.Json;",
            "Newtonsoft.Json"
        ));
        assert!(nuget_imports_text(
            "using Newtonsoft.Json.Linq;",
            "Newtonsoft.Json"
        ));
        assert!(nuget_imports_text("global using Serilog;", "Serilog"));
        // a different package and a non-using line do not match
        assert!(!nuget_imports_text(
            "using Newtonsoft.JsonNet;",
            "Newtonsoft.Json"
        ));
        assert!(!nuget_imports_text("var x = Serilog;", "Serilog"));
    }

    #[test]
    fn maven_matches_group_import_prefix() {
        let coord = "org.apache.logging.log4j:log4j-core";
        assert!(maven_imports_text(
            "import org.apache.logging.log4j.Logger;",
            coord
        ));
        assert!(maven_imports_text(
            "import static org.apache.logging.log4j.Level.INFO;",
            coord
        ));
        // a different group does not match
        assert!(!maven_imports_text("import org.slf4j.Logger;", coord));
    }

    #[test]
    fn packagist_matches_pascal_cased_namespace() {
        assert!(packagist_imports_text(
            "use Monolog\\Logger;",
            "monolog/monolog"
        ));
        assert!(packagist_imports_text(
            "use Symfony\\Component\\HttpKernel\\Kernel;",
            "symfony/http-kernel"
        ));
        // not a use line
        assert!(!packagist_imports_text(
            "$x = new Monolog();",
            "monolog/monolog"
        ));
    }

    #[test]
    fn swift_strips_prefix_and_matches_module() {
        assert!(swift_imports_text("import NIO", "swift-nio"));
        assert!(swift_imports_text("import Vapor", "vapor/vapor"));
        // a non-import line does not match
        assert!(!swift_imports_text("let nio = 1", "swift-nio"));
    }

    #[test]
    fn pascal_case_splits_separators() {
        assert_eq!(pascal_case("http-kernel"), "HttpKernel");
        assert_eq!(pascal_case("monolog"), "Monolog");
        assert_eq!(pascal_case("php_unit"), "PhpUnit");
    }

    #[test]
    fn hex_matches_pascal_module_usage() {
        // qualified call, and alias/import/use/require directives
        assert!(hex_module_used_text(
            "    Plug.Conn.send_resp(conn)",
            "plug"
        ));
        assert!(hex_module_used_text(
            "  alias Phoenix.Controller",
            "phoenix"
        ));
        assert!(hex_module_used_text("  use Phoenix.Router", "phoenix"));
        assert!(hex_module_used_text("import FooBar", "foo_bar")); // foo_bar -> FooBar
                                                                   // a submodule of another app is NOT a match for the bare module
        assert!(!hex_module_used_text("MyApp.Plug.call()", "plug"));
        // a non-usage mention does not match
        assert!(!hex_module_used_text("# plug is great", "plug"));
    }

    #[test]
    fn ghactions_matches_uses_reference() {
        assert!(ghactions_uses_text(
            "      - uses: actions/checkout@v4",
            "actions/checkout"
        ));
        // case-insensitive (GitHub treats owner/repo case-insensitively)
        assert!(ghactions_uses_text(
            "      - uses: Actions/Checkout@v4",
            "actions/checkout"
        ));
        // subpath action id (the coordinate includes the subpath)
        assert!(ghactions_uses_text(
            "      - uses: github/codeql-action/analyze@v3",
            "github/codeql-action/analyze"
        ));
        // a different action, and a non-uses line, do not match
        assert!(!ghactions_uses_text(
            "      - uses: actions/setup-node@v4",
            "actions/checkout"
        ));
        assert!(!ghactions_uses_text(
            "  name: actions/checkout",
            "actions/checkout"
        ));
    }
}
