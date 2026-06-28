//! Go ecosystem feeder for fleetreach: turn `govulncheck` output into the shared
//! `VulnFinding` model so the existing correlate / report / remediation pipeline
//! works on Go modules unchanged.
//!
//! The interesting part is the reachability mapping, and it is the mirror image of
//! the Rust engine. `govulncheck` is **sound-positive**: a symbol-level call trace
//! is strong evidence the vulnerable code is actually called. But the *absence* of
//! a symbol-level finding is only "not observed", not proven unreachable (calls via
//! `reflect`/`unsafe` are invisible to the analysis). So this feeder may emit
//! `Reachable` (with the trace as the witness) but **never** `NotReachable`;
//! everything present-but-not-confirmed-called maps to `Unknown`, which the
//! remediation gate keeps in the active queue. The Rust engine suppresses
//! provably-dead findings; this confirms provably-live ones, into the same queue
//! from the opposite end.
//!
//! # Minimum supported Rust version
//!
//! 1.89. An MSRV increase is treated as a minor-version bump.

mod error;
mod offline;
mod run;

use std::collections::{BTreeMap, BTreeSet};

use fleetreach_core::{
    DependencyKind, Ecosystem, Occurrence, ReachVerdict, Reachability, RepoId, Severity,
    VulnFinding,
};
use serde::Deserialize;

pub use error::{DbError, GoError};
/// Re-exported so callers can drive [`scan_module`]'s build confinement without a
/// direct dependency on `fleetreach-reach`.
pub use fleetreach_reach::SandboxPolicy;
pub use offline::{offline_db_path, scan_offline, GoDb};
pub use run::{scan_module, GoScanOptions};

/// Parse a `govulncheck -format json` stream into Go-tagged [`VulnFinding`]s,
/// attributed to `repo`.
///
/// govulncheck emits a stream of whitespace-separated JSON `Message` objects, each
/// with exactly one field set. A single vulnerability yields several findings at
/// increasing depth (module, then package, then symbol); we group by advisory id
/// and keep the **deepest** trace, which decides the reachability verdict. Output
/// is sorted by advisory id for determinism.
///
/// `direct` is the set of direct module paths (from [`direct_modules`]); a vulnerable
/// module in it is reported as a [`Direct`](DependencyKind::Direct) dependency, anything
/// else as [`Transitive`](DependencyKind::Transitive). Pass an empty set when the
/// `go.mod` is unavailable, which conservatively classifies everything transitive.
///
/// # Errors
///
/// Returns [`GoError::Parse`] if `json` is not a valid govulncheck `Message` stream.
pub fn parse_findings(
    json: &str,
    repo: &RepoId,
    direct: &BTreeSet<String>,
) -> Result<Vec<VulnFinding>, GoError> {
    let mut osvs: BTreeMap<String, OsvEntry> = BTreeMap::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut modules: BTreeMap<String, String> = BTreeMap::new();
    let mut scope = String::from("source/symbol");
    let mut engine = String::from("govulncheck");

    for message in serde_json::Deserializer::from_str(json).into_iter::<Message>() {
        let message = message?;
        if let Some(config) = message.config {
            scope = format!(
                "{}/{}",
                config.scan_mode.as_deref().unwrap_or("source"),
                config.scan_level.as_deref().unwrap_or("symbol")
            );
            if let Some(version) = config.scanner_version {
                engine = format!("govulncheck@{version}");
            }
        }
        if let Some(sbom) = message.sbom {
            for module in sbom.modules {
                if let Some(version) = module.version {
                    modules.insert(module.path, version);
                }
            }
        }
        if let Some(osv) = message.osv {
            osvs.insert(osv.id.clone(), osv);
        }
        if let Some(finding) = message.finding {
            findings.push(finding);
        }
    }

    // Group findings by advisory id; a vuln is reported once per depth level.
    let mut by_id: BTreeMap<String, Vec<Finding>> = BTreeMap::new();
    for finding in findings {
        if let Some(id) = finding.osv.clone() {
            by_id.entry(id).or_default().push(finding);
        }
    }

    let mut out: Vec<VulnFinding> = Vec::new();
    for (id, group) in by_id {
        if let Some(vuln) =
            build_finding(&id, &group, &osvs, &modules, repo, &scope, &engine, direct)
        {
            out.push(vuln);
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn build_finding(
    id: &str,
    group: &[Finding],
    osvs: &BTreeMap<String, OsvEntry>,
    modules: &BTreeMap<String, String>,
    repo: &RepoId,
    scope: &str,
    engine: &str,
    direct: &BTreeSet<String>,
) -> Option<VulnFinding> {
    // The vulnerable module is the first frame of any finding's trace (frames run
    // from the vulnerable symbol outward to the entry point).
    let vuln_module = group
        .iter()
        .filter_map(|f| f.trace.first())
        .find_map(|frame| frame.module.clone())?;

    // The deepest finding decides reachability; its trace (if symbol level) is the
    // witness.
    let deepest = group.iter().max_by_key(|f| depth(f))?;
    let verdict = match depth(deepest) {
        Depth::Symbol => ReachVerdict::Reachable {
            witness: witness(deepest),
        },
        // Imported or merely present: sound-positive analysis did not confirm a
        // call, but reflect/unsafe mean we cannot call it unreachable. Never
        // NotReachable.
        Depth::Package => ReachVerdict::Unknown {
            reason: "imported, not confirmed called".into(),
        },
        Depth::Module => ReachVerdict::Unknown {
            reason: "present, not imported".into(),
        },
    };

    let installed_raw = modules.get(&vuln_module).map(String::as_str).or_else(|| {
        group
            .iter()
            .filter_map(|f| f.trace.first())
            .find_map(|x| x.version.as_deref())
    });
    // govulncheck gave no version at all — nothing to reason about, drop quietly.
    let installed_raw = installed_raw?;
    // A version we can't parse means we can't reason about the finding; drop it rather
    // than emit a bogus occurrence. The DB-stress test (all 2288 real vuln.go.dev
    // versions parse) keeps this from triggering in practice, but if it ever does, a
    // govulncheck-*reported* advisory must not vanish silently — surface it.
    let Some(installed_version) = parse_go_version(installed_raw) else {
        eprintln!(
            "warning: dropping Go advisory {id}: govulncheck reported an unparseable \
             installed version {installed_raw:?} for {vuln_module}"
        );
        return None;
    };

    // A `>=fixed` requirement is the safe range; empty when no fix is published, so
    // the remediation layer reports it as no-fix-available, same as Rust.
    let patched: Vec<fleetreach_core::semver::VersionReq> = group
        .iter()
        .find_map(|f| f.fixed_version.as_deref())
        .filter(|v| !strip_v(v).is_empty())
        .and_then(|v| fleetreach_core::semver::VersionReq::parse(&format!(">={}", strip_v(v))).ok())
        .into_iter()
        .collect();

    let osv = osvs.get(id);

    // Computed before the move of `vuln_module` into `package`.
    let dependency_kind = dep_kind(direct, &vuln_module);

    Some(VulnFinding {
        advisory_id: id.to_string(),
        aliases: osv.and_then(|o| o.aliases.clone()).unwrap_or_default(),
        ecosystem: Ecosystem::Go,
        title: osv
            .and_then(|o| o.summary.clone())
            .unwrap_or_else(|| id.to_string()),
        severity: Severity::Unknown,
        cvss_score: None,
        url: Some(go_vuln_url(id)),
        occurrences: vec![Occurrence::InRepo {
            repo: repo.clone(),
            package: vuln_module,
            installed: installed_version,
            patched,
            dependency_kind,
            dependency_path: Vec::new(),
            active: None,
            source: Default::default(),
        }],
        affected_functions: osv.map(affected_symbols).unwrap_or_default(),
        reachable: None,
        reachability: Some(Reachability {
            verdict,
            config: scope.to_string(),
            engine: engine.to_string(),
            targets: Vec::new(),
            witness: None,
        }),
        exploit: Default::default(),
    })
}

/// Reachability depth of a single finding, read off its first trace frame.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Depth {
    Module,
    Package,
    Symbol,
}

fn depth(finding: &Finding) -> Depth {
    match finding.trace.first() {
        Some(frame) if frame.function.is_some() => Depth::Symbol,
        Some(frame) if frame.package.is_some() => Depth::Package,
        _ => Depth::Module,
    }
}

/// The call chain as a witness, ordered entry-point first to vulnerable symbol
/// last (govulncheck emits it sink-first, so we reverse).
fn witness(finding: &Finding) -> Vec<String> {
    let mut frames: Vec<String> = finding.trace.iter().map(frame_label).collect();
    frames.reverse();
    frames
}

fn frame_label(frame: &Frame) -> String {
    let loc = frame
        .package
        .as_deref()
        .or(frame.module.as_deref())
        .unwrap_or("?");
    match (&frame.receiver, &frame.function) {
        (Some(recv), Some(func)) => format!("{loc}.{recv}.{func}"),
        (None, Some(func)) => format!("{loc}.{func}"),
        _ => loc.to_string(),
    }
}

/// Every vulnerable symbol named by the advisory, for the `affects fn` display.
fn affected_symbols(osv: &OsvEntry) -> Vec<String> {
    render_symbols(
        osv.affected
            .iter()
            .flatten()
            .filter_map(|a| a.ecosystem_specific.as_ref())
            .filter_map(|e| e.imports.as_ref())
            .flatten()
            .map(|i| (i.path.as_str(), i.symbols.as_deref().unwrap_or_default())),
    )
}

/// Go module versions are SemVer with a leading `v` (`v0.3.0`); OSV ranges drop
/// it. Strip the prefix for `semver` parsing.
pub(crate) fn strip_v(version: &str) -> &str {
    version.strip_prefix('v').unwrap_or(version)
}

/// Parse a Go module version into a [`semver::Version`](fleetreach_core::semver::Version).
/// Handles the leading `v` (`v1.2.3`), pseudo-versions
/// (`v0.0.0-20210101000000-abcdef`, a SemVer pre-release), and `+incompatible`
/// (SemVer build metadata). Returns `None` for anything `semver` rejects.
///
/// # Examples
///
/// ```
/// use fleetreach_go::parse_go_version;
///
/// assert_eq!(parse_go_version("v1.2.3").unwrap().to_string(), "1.2.3");
/// assert!(parse_go_version("v0.0.0-20210101000000-abcdef").is_some()); // pseudo-version
/// assert!(parse_go_version("not-a-version").is_none());
/// ```
pub fn parse_go_version(raw: &str) -> Option<fleetreach_core::semver::Version> {
    fleetreach_core::semver::Version::parse(strip_v(raw)).ok()
}

/// One `require` entry from a `go.mod`: module path, declared version, and whether
/// it is annotated `// indirect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredModule {
    pub path: String,
    pub version: String,
    pub indirect: bool,
}

/// Every `require` entry in a `go.mod`, from both the single-line `require x v1`
/// and the block `require ( ... )` forms. Read straight from the manifest so it is
/// deterministic and needs **no toolchain** (the same reason the Rust path reads
/// `Cargo.lock` rather than invoking cargo). This is the module set the Tier-C
/// offline matcher scans when no govulncheck/toolchain is available. `replace`/
/// `exclude`/`retract` directives are ignored (they do not add requires here).
///
/// Note: for go 1.17+ the manifest lists the full pruned graph (direct + `// indirect`)
/// with selected versions, so this is complete; an older `go.mod` may omit indirect
/// deps, in which case Tier-C only sees the direct ones.
///
/// # Examples
///
/// ```
/// use fleetreach_go::required_modules;
///
/// let go_mod = "\
/// module example.com/app
/// require (
/// \tgolang.org/x/text v0.3.0
/// \tgithub.com/dep/indirect v0.1.0 // indirect
/// )
/// ";
/// let reqs = required_modules(go_mod);
/// assert_eq!(reqs.len(), 2);
/// assert_eq!(reqs[0].path, "golang.org/x/text");
/// assert_eq!(reqs[0].version, "v0.3.0");
/// assert!(!reqs[0].indirect);
/// assert!(reqs[1].indirect);
/// ```
pub fn required_modules(go_mod: &str) -> Vec<RequiredModule> {
    let mut out = Vec::new();
    let mut in_require_block = false;
    for raw in go_mod.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if in_require_block {
            if line.starts_with(')') {
                in_require_block = false;
            } else if let Some(m) = parse_require(line) {
                out.push(m);
            }
            continue;
        }
        if line.starts_with("require (") {
            in_require_block = true;
        } else if let Some(rest) = line.strip_prefix("require ") {
            if let Some(m) = parse_require(rest.trim()) {
                out.push(m);
            }
        }
    }
    out
}

/// The main module path declared by the `module` directive, if present.
pub fn main_module(go_mod: &str) -> Option<String> {
    go_mod.lines().find_map(|raw| {
        raw.trim()
            .strip_prefix("module ")
            .and_then(|rest| rest.split_whitespace().next())
            .map(str::to_string)
    })
}

/// A `go.mod` `replace` directive: `from[ from_version] => to[ to_version]`. A `to`
/// with **no** version is a local filesystem path (`../local`), meaning the module is
/// no longer the published artifact, so it cannot be matched against the OSV DB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replace {
    /// The replaced module path.
    pub from_path: String,
    /// The specific version replaced, or `None` to replace every version of `from_path`.
    pub from_version: Option<String>,
    /// The replacement module path (or local path).
    pub to_path: String,
    /// The replacement version; `None` for a local-path replacement.
    pub to_version: Option<String>,
}

/// All `replace` directives in a `go.mod` (single-line and block forms). A `replace`
/// overrides which module/version a dependency actually resolves to, so the Tier-C
/// matcher must honor it or it false-positives on a require that was replaced with a
/// fixed version (and `replace` appears in a large fraction of real manifests).
pub fn replace_directives(go_mod: &str) -> Vec<Replace> {
    let mut out = Vec::new();
    let mut in_block = false;
    for raw in go_mod.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if in_block {
            if line.starts_with(')') {
                in_block = false;
            } else if let Some(r) = parse_replace(line) {
                out.push(r);
            }
            continue;
        }
        if line.starts_with("replace (") {
            in_block = true;
        } else if let Some(rest) = line.strip_prefix("replace ") {
            if let Some(r) = parse_replace(rest) {
                out.push(r);
            }
        }
    }
    out
}

/// Parse one `replace` entry: `from [from_version] => to [to_version]`.
fn parse_replace(entry: &str) -> Option<Replace> {
    let code = entry.split("//").next().unwrap_or(entry);
    let (lhs, rhs) = code.split_once("=>")?;
    let mut l = lhs.split_whitespace();
    let from_path = l.next()?.to_string();
    let from_version = l.next().map(str::to_string);
    let mut r = rhs.split_whitespace();
    let to_path = r.next()?.to_string();
    let to_version = r.next().map(str::to_string);
    Some(Replace {
        from_path,
        from_version,
        to_path,
        to_version,
    })
}

/// Parse one `require` entry (`<module> <version> [// indirect]`).
fn parse_require(entry: &str) -> Option<RequiredModule> {
    let indirect = entry.contains("// indirect");
    let code = entry.split("//").next().unwrap_or(entry);
    let mut parts = code.split_whitespace();
    let path = parts.next()?.to_string();
    if path.is_empty() {
        return None;
    }
    let version = parts.next().unwrap_or_default().to_string();
    Some(RequiredModule {
        path,
        version,
        indirect,
    })
}

/// The set of *direct* module paths declared by a `go.mod`: the main module itself
/// plus every `require` not annotated `// indirect`. This is Go's own direct/indirect
/// distinction (the one `go mod tidy` records). A module govulncheck reports that is
/// in this set is a direct dependency; anything else (an indirect require, or a deeper
/// transitive not pinned in `go.mod`) is transitive.
///
/// # Examples
///
/// ```
/// use fleetreach_go::direct_modules;
///
/// let go_mod = "module example.com/app\nrequire golang.org/x/text v0.3.0\n";
/// let direct = direct_modules(go_mod);
/// assert!(direct.contains("example.com/app")); // the main module is direct
/// assert!(direct.contains("golang.org/x/text"));
/// ```
pub fn direct_modules(go_mod: &str) -> BTreeSet<String> {
    direct_set(&required_modules(go_mod), go_mod)
}

/// [`direct_modules`] from an already-parsed require list, so a caller that needs both
/// the full module set and the direct set (the Tier-C matcher) parses `go.mod` once.
pub(crate) fn direct_set(required: &[RequiredModule], go_mod: &str) -> BTreeSet<String> {
    let mut direct: BTreeSet<String> = required
        .iter()
        .filter(|m| !m.indirect)
        .map(|m| m.path.clone())
        .collect();
    // The main module is your own code: classify a vuln in it as direct.
    if let Some(main) = main_module(go_mod) {
        direct.insert(main);
    }
    direct
}

/// Direct vs. transitive for `module`, given the repo's [`direct_set`].
pub(crate) fn dep_kind(direct: &BTreeSet<String>, module: &str) -> DependencyKind {
    if direct.contains(module) {
        DependencyKind::Direct
    } else {
        DependencyKind::Transitive
    }
}

/// The canonical advisory URL on pkg.go.dev.
pub(crate) fn go_vuln_url(id: &str) -> String {
    format!("https://pkg.go.dev/vuln/{id}")
}

/// Render `(import-path, symbols)` pairs into sorted, deduped `path.Symbol` strings
/// for the `affects fn` display. Shared by the govulncheck and Tier-C paths, which
/// read different OSV schemas but format symbols identically.
pub(crate) fn render_symbols<'a>(
    imports: impl Iterator<Item = (&'a str, &'a [String])>,
) -> Vec<String> {
    let mut out: Vec<String> = imports
        .flat_map(|(path, symbols)| symbols.iter().map(move |s| format!("{path}.{s}")))
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_directives_parse_all_forms() {
        let go_mod = "\
module example.com/app

replace golang.org/x/text => golang.org/x/text v0.3.8

replace (
\tgithub.com/old/pkg v1.0.0 => github.com/fork/pkg v1.2.0
\texample.com/local => ../local
)
";
        let r = replace_directives(go_mod);
        assert_eq!(r.len(), 3);
        // version-agnostic module replacement
        assert_eq!(r[0].from_path, "golang.org/x/text");
        assert_eq!(r[0].from_version, None);
        assert_eq!(r[0].to_version.as_deref(), Some("v0.3.8"));
        // version-specific replacement
        assert_eq!(r[1].from_version.as_deref(), Some("v1.0.0"));
        assert_eq!(r[1].to_path, "github.com/fork/pkg");
        // local-path replacement: no `to` version
        assert_eq!(r[2].to_path, "../local");
        assert_eq!(r[2].to_version, None);
    }

    #[test]
    fn direct_modules_reads_block_single_and_indirect() {
        let go_mod = "\
module github.com/acme/svc

go 1.21

require github.com/direct/single v1.0.0

require (
\tgithub.com/direct/block v1.2.0
\tgolang.org/x/text v0.3.0 // indirect
\tgithub.com/indirect/dep v0.1.0 // indirect
)
";
        let direct = direct_modules(go_mod);
        // main module + the two un-annotated requires are direct.
        assert!(direct.contains("github.com/acme/svc"));
        assert!(direct.contains("github.com/direct/single"));
        assert!(direct.contains("github.com/direct/block"));
        // `// indirect` requires are excluded.
        assert!(!direct.contains("golang.org/x/text"));
        assert!(!direct.contains("github.com/indirect/dep"));
        assert_eq!(direct.len(), 3);
    }

    #[test]
    fn direct_modules_empty_when_no_manifest() {
        assert!(direct_modules("").is_empty());
    }
}

// --- govulncheck JSON Message schema (protocol v1.0.0), the subset we read. ---

#[derive(Deserialize)]
struct Message {
    config: Option<Config>,
    #[serde(rename = "SBOM")]
    sbom: Option<Sbom>,
    osv: Option<OsvEntry>,
    finding: Option<Finding>,
}

#[derive(Deserialize)]
struct Config {
    scan_level: Option<String>,
    scan_mode: Option<String>,
    scanner_version: Option<String>,
}

#[derive(Deserialize)]
struct Sbom {
    #[serde(default)]
    modules: Vec<SbomModule>,
}

#[derive(Deserialize)]
struct SbomModule {
    path: String,
    version: Option<String>,
}

#[derive(Deserialize)]
struct Finding {
    osv: Option<String>,
    fixed_version: Option<String>,
    #[serde(default)]
    trace: Vec<Frame>,
}

#[derive(Deserialize)]
struct Frame {
    module: Option<String>,
    version: Option<String>,
    package: Option<String>,
    function: Option<String>,
    receiver: Option<String>,
}

#[derive(Deserialize)]
struct OsvEntry {
    id: String,
    aliases: Option<Vec<String>>,
    summary: Option<String>,
    affected: Option<Vec<Affected>>,
}

#[derive(Deserialize)]
struct Affected {
    ecosystem_specific: Option<EcoSpecific>,
}

#[derive(Deserialize)]
struct EcoSpecific {
    imports: Option<Vec<Import>>,
}

#[derive(Deserialize)]
struct Import {
    path: String,
    symbols: Option<Vec<String>>,
}
