//! OpenVEX 0.2.0 serializer (§1, §5, §14): a projection of a [`FleetReport`],
//! sibling to the SARIF serializer.
//!
//! Invariant (§2): `not_affected` is emitted only from a sound signal — a static
//! [`ReachVerdict::NotReachable`] or a phantom dependency (`active == Some(false)`).
//! The grep heuristic ([`VulnFinding::reachable`]) is never consulted; without
//! static data a finding stays `under_investigation`.

use std::collections::BTreeMap;

use fleetreach_core::{DepSource, Ecosystem, FleetReport, Occurrence, ReachVerdict, VulnFinding};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The OpenVEX 0.2.0 JSON-LD context.
pub const OPENVEX_CONTEXT: &str = "https://openvex.dev/ns/v0.2.0";

/// Product scope (§7 edge 4): a dev/build-only dependency is `component_not_present`
/// for a `runtime` product but in scope for a `build` one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VexScope {
    Runtime,
    Build,
}

impl VexScope {
    pub fn as_str(self) -> &'static str {
        match self {
            VexScope::Runtime => "runtime",
            VexScope::Build => "build",
        }
    }

    /// Parse the `runtime` / `build` spelling used in `fleet.toml` and `--vex-scope`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "runtime" => Some(VexScope::Runtime),
            "build" => Some(VexScope::Build),
            _ => None,
        }
    }
}

/// Emission parameters, fully resolved by the CLI before [`to_vex`] (which never
/// fails on missing config — the CLI fails closed first, §7.3 edge 8).
pub struct VexParams {
    /// OpenVEX-mandatory author.
    pub author: String,
    /// Document-level author role; omitted when `None`.
    pub role: Option<String>,
    pub scope: VexScope,
    /// RFC3339 timestamp; the advisory-DB commit time by default so re-emits are
    /// byte-stable (§9.1).
    pub timestamp: String,
    /// Explicit `@id` (`--vex-id`); a content hash when `None`.
    pub doc_id: Option<String>,
    /// Base IRI for the generated content-addressed `@id`.
    pub product_id_base: Option<String>,
    /// Resolved product `@id` per repo id (§4.3).
    pub product_ids: BTreeMap<String, String>,
    /// Human assertions (§6), disjoint from machine statements (their findings were
    /// removed from the gated report).
    pub assertions: Vec<HumanAssertion>,
    /// Drop human assertions, keeping only machine-derived statements (§7.1).
    pub only_sound: bool,
    /// Also emit `pkg:rustbinary` subcomponents for binary-scanning consumers (§4.2).
    pub alias_rustbinary: bool,
    /// Emit `fixed` statements for already-patched occurrences.
    pub include_fixed: bool,
    /// Monotonic document version (§9.3).
    pub version: u64,
    /// Prior document `@id` this supersedes (§9.3).
    pub supersedes: Option<String>,
}

/// A human-asserted `not_affected` (§6, §7.1) resolved from an `ignore` or a
/// `vex_assertion`. Disjoint from machine statements.
#[derive(Clone)]
pub struct HumanAssertion {
    pub advisory_id: String,
    pub aliases: Vec<String>,
    pub product_id: String,
    pub package: String,
    pub version: String,
    /// A VEX WG label, or `None` to fall back to `impact_statement`.
    pub justification: Option<String>,
    pub impact_statement: String,
    /// `None` for a legacy `ignore` (no approver).
    pub approved_by: Option<String>,
}

// ---- OpenVEX wire structs ----

#[derive(Serialize)]
struct Document<'a> {
    #[serde(rename = "@context")]
    context: &'a str,
    #[serde(rename = "@id")]
    id: String,
    author: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'a str>,
    timestamp: &'a str,
    version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    supersedes: Option<&'a str>,
    statements: Vec<Statement>,
}

/// A statement's identity `(vulnerability, product, subcomponent)` + status, for
/// the drift gate (§9.3, §10). The subcomponent is the canonical `pkg:cargo` PURL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementView {
    pub vulnerability: String,
    pub product: String,
    pub subcomponent: String,
    pub status: String,
}

#[derive(Serialize, PartialEq, Eq)]
struct Statement {
    vulnerability: Vulnerability,
    products: Vec<Component>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subcomponents: Vec<Component>,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    justification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_statement: Option<String>,
    /// Free-text `not_affected` rationale when there's no `justification` label (§7.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    impact_statement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_notes: Option<String>,
}

#[derive(Serialize, PartialEq, Eq)]
struct Vulnerability {
    name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    aliases: Vec<String>,
}

#[derive(Serialize, PartialEq, Eq, Clone)]
struct Component {
    #[serde(rename = "@id")]
    id: String,
}

/// Statement products: the repo first (the drift-gate key), then the crate PURL(s).
/// Package-centric consumers (e.g. Trivy) match on the crate PURL; the repo product
/// is often an opaque IRI no scanner recognizes (§4, §15).
fn products_for(product_id: &str, subcomponents: &[Component]) -> Vec<Component> {
    let mut products = Vec::with_capacity(1 + subcomponents.len());
    products.push(Component {
        id: product_id.to_string(),
    });
    products.extend(subcomponents.iter().cloned());
    products
}

/// The sorted, deduped statement set (machine verdicts + human assertions), shared
/// by [`to_vex`] and [`project`] so the document and the drift gate agree.
fn build_statements(report: &FleetReport, params: &VexParams) -> Vec<Statement> {
    let mut statements: Vec<Statement> = Vec::new();
    for v in &report.vulnerabilities {
        for occ in &v.occurrences {
            if let Some(stmt) = statement_for(v, occ, params) {
                statements.push(stmt);
            }
        }
    }
    // Human assertions (§6), unless `--vex-only-sound` (§7.1).
    if !params.only_sound {
        for assertion in &params.assertions {
            statements.push(human_statement(assertion, params));
        }
    }

    statements.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    // Collapse exact duplicates so the document and its `@id` stay canonical.
    statements.dedup();
    statements
}

/// Serialize a [`FleetReport`] to an OpenVEX 0.2.0 document. Deterministic: equal
/// inputs give byte-identical output and a stable content `@id` (§14).
pub fn to_vex(report: &FleetReport, params: &VexParams) -> Result<String, serde_json::Error> {
    let statements = build_statements(report, params);

    let id = params
        .doc_id
        .clone()
        .unwrap_or_else(|| content_id(&statements, params));

    let doc = Document {
        context: OPENVEX_CONTEXT,
        id,
        author: &params.author,
        role: params.role.as_deref(),
        timestamp: &params.timestamp,
        version: params.version,
        supersedes: params.supersedes.as_deref(),
        statements,
    };
    serde_json::to_string_pretty(&doc)
}

/// Statement identities a fresh scan would emit, for the drift gate to diff against
/// a committed document (§10).
pub fn project(report: &FleetReport, params: &VexParams) -> Vec<StatementView> {
    build_statements(report, params)
        .iter()
        .map(|s| StatementView {
            vulnerability: s.vulnerability.name.clone(),
            product: s.products.first().map(|c| c.id.clone()).unwrap_or_default(),
            subcomponent: s
                .subcomponents
                .first()
                .map(|c| c.id.clone())
                .unwrap_or_default(),
            status: s.status.to_string(),
        })
        .collect()
}

/// One statement per `(advisory, occurrence)`, or `None` when out of VEX scope: a
/// toolchain advisory, an already-fixed occurrence (unless `--vex-include-fixed`),
/// or a repo with no resolved product id.
fn statement_for(v: &VulnFinding, occ: &Occurrence, params: &VexParams) -> Option<Statement> {
    let Occurrence::InRepo {
        repo,
        package,
        installed,
        patched,
        source,
        ..
    } = occ
    else {
        // Toolchain advisories carry no dependency subcomponent.
        return None;
    };

    let product_id = params.product_ids.get(&repo.0)?;
    let subcomponents = subcomponents(
        v.ecosystem,
        package,
        &installed.to_string(),
        source,
        params.alias_rustbinary,
    );
    let products = products_for(product_id, &subcomponents);
    let vulnerability = Vulnerability {
        name: v.advisory_id.clone(),
        aliases: v.aliases.clone(),
    };

    let (status, justification, action_statement, status_notes) = match machine_status(v, occ) {
        // Already patched: opt-in only (§5).
        MachineStatus::Fixed => {
            if !params.include_fixed {
                return None;
            }
            ("fixed", None, None, None)
        }
        MachineStatus::NotAffected { justification } => {
            let notes = if justification == "component_not_present" {
                format!(
                    "role=Automated Analysis; component_not_present: in Cargo.lock but not \
                     compiled into the analyzed build (feature-resolved); scope={}",
                    params.scope.as_str()
                )
            } else {
                reach_note(v, "no path to the vulnerable function")
            };
            (
                "not_affected",
                Some(justification.to_string()),
                None,
                Some(notes),
            )
        }
        MachineStatus::Affected => (
            "affected",
            None,
            Some(upgrade_action(package, patched)),
            Some(reach_note(v, "a path to the vulnerable function exists")),
        ),
        MachineStatus::UnderInvestigation { reason } => {
            let notes = match reason {
                Some(reason) => format!(
                    "reachability undecided ({reason}); re-run --reachability=static to resolve"
                ),
                None => "no reachability data; run --reachability=static to classify".to_string(),
            };
            ("under_investigation", None, None, Some(notes))
        }
    };

    Some(Statement {
        vulnerability,
        products,
        subcomponents,
        status,
        justification,
        action_statement,
        impact_statement: None,
        status_notes,
    })
}

/// `status_notes` for a reachability verdict: config, engine, targets (§7), and the
/// witness hash (§9.2) when present.
fn reach_note(v: &VulnFinding, what: &str) -> String {
    let Some(r) = &v.reachability else {
        return format!("role=Automated Analysis; {what}");
    };
    let mut note = format!(
        "role=Automated Analysis; static call-graph: {what}; config={}; engine={}",
        r.config, r.engine
    );
    if !r.targets.is_empty() {
        note.push_str(&format!("; targets=[{}]", r.targets.join(",")));
    }
    if let Some(witness) = &r.witness {
        note.push_str(&format!("; witness={witness}"));
    }
    note
}

/// A human-asserted `not_affected` (§6, §7.1): records the approver, and uses the
/// machine `justification` label or the free-text `impact_statement`.
fn human_statement(assertion: &HumanAssertion, params: &VexParams) -> Statement {
    let approver_note = match &assertion.approved_by {
        Some(who) => format!("approved_by={who}"),
        None => "source=ignore (no approver)".to_string(),
    };
    // OpenVEX needs a justification or an impact_statement; use the reason as the
    // latter only when there's no label.
    let impact_statement = assertion
        .justification
        .is_none()
        .then(|| assertion.impact_statement.clone());
    // A config-authored assertion has no lockfile source or ecosystem; treat it as the bare
    // crates.io PURL (its identity is the package name, as authored). Per-ecosystem human
    // assertions would need an ecosystem field on the config assertion (follow-up).
    let subcomponents = subcomponents(
        Ecosystem::Cargo,
        &assertion.package,
        &assertion.version,
        &DepSource::CratesIo,
        params.alias_rustbinary,
    );
    Statement {
        vulnerability: Vulnerability {
            name: assertion.advisory_id.clone(),
            aliases: assertion.aliases.clone(),
        },
        products: products_for(&assertion.product_id, &subcomponents),
        subcomponents,
        status: "not_affected",
        justification: assertion.justification.clone(),
        action_statement: None,
        impact_statement,
        status_notes: Some(format!("role=Human Assertion; {approver_note}")),
    }
}

/// The machine-derived §5 verdict for one occurrence, shared by the VEX serializer
/// and the SARIF suppression hook (§11) so they never disagree.
pub(crate) enum MachineStatus {
    /// Sound `not_affected` with its justification label.
    NotAffected {
        justification: &'static str,
    },
    Affected,
    /// Conservative default; `reason` from an `Unknown` verdict.
    UnderInvestigation {
        reason: Option<String>,
    },
    /// Installed version is already patched.
    Fixed,
}

/// Classify one occurrence per §5. Phantom (`active == Some(false)`) takes
/// precedence over reachability; the grep heuristic is never consulted (§2).
pub(crate) fn machine_status(v: &VulnFinding, occ: &Occurrence) -> MachineStatus {
    if !occ.is_vulnerable() {
        return MachineStatus::Fixed;
    }
    let active = match occ {
        Occurrence::InRepo { active, .. } => *active,
        Occurrence::Toolchain { .. } => None,
    };
    if active == Some(false) {
        return MachineStatus::NotAffected {
            justification: "component_not_present",
        };
    }
    match v.reachability.as_ref().map(|r| &r.verdict) {
        Some(ReachVerdict::NotReachable) => MachineStatus::NotAffected {
            justification: "vulnerable_code_not_in_execute_path",
        },
        Some(ReachVerdict::Reachable { .. }) => MachineStatus::Affected,
        Some(ReachVerdict::Unknown { reason }) => MachineStatus::UnderInvestigation {
            reason: Some(reason.clone()),
        },
        None => MachineStatus::UnderInvestigation { reason: None },
    }
}

/// Canonical cargo PURL `pkg:cargo/<name>@<version>` (§4.1), plus a `pkg:rustbinary`
/// alias under `--vex-alias-rustbinary` for binary-scanning consumers (§4.2). The
/// name/version come from an untrusted Cargo.lock; they are percent-encoded per the
/// purl spec so a crafted character can't smuggle extra path/qualifier segments
/// into a PURL a downstream scanner parses (defense-in-depth; serde already escapes
/// the surrounding JSON).
fn subcomponents(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    source: &DepSource,
    alias_rustbinary: bool,
) -> Vec<Component> {
    let path = purl_path(ecosystem, name);
    let version = purl_encode(version);
    // §4.1: a non-crates.io dep is a *different artifact* than the registry crate of
    // the same name@version, so qualify its PURL with the source. crates.io (and a
    // local path, which has no canonical remote) stay the bare PURL — byte-identical to
    // before — so the Docker-validated registry suppression path is untouched. Tier-C
    // feeders carry no source, so they stay bare. Qualifier-matching by consumers is not
    // yet validated (see the module note); this only adds precision for the rare
    // git/alt-registry case.
    let qualifier = purl_qualifier(source).unwrap_or_default();
    let mut out = vec![Component {
        id: format!("pkg:{}/{path}@{version}{qualifier}", purl_type(ecosystem)),
    }];
    // The `pkg:rustbinary` alias is for Rust binary scanners only.
    if alias_rustbinary && ecosystem.is_cargo() {
        out.push(Component {
            id: format!("pkg:rustbinary/{path}@{version}"),
        });
    }
    out
}

/// The PURL `type` for an ecosystem (the segment after `pkg:`), per the purl-spec / OSV
/// conventions: `pkg:npm/…`, `pkg:pypi/…`, `pkg:gem/…`, `pkg:composer/…`, `pkg:maven/…`, etc.
fn purl_type(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Cargo => "cargo",
        Ecosystem::Go => "golang",
        Ecosystem::Npm => "npm",
        Ecosystem::Pypi => "pypi",
        Ecosystem::RubyGems => "gem",
        Ecosystem::Packagist => "composer",
        Ecosystem::NuGet => "nuget",
        Ecosystem::Julia => "julia",
        Ecosystem::Swift => "swift",
        Ecosystem::Hex => "hex",
        Ecosystem::Maven => "maven",
        Ecosystem::GitHubActions => "githubactions",
    }
}

/// The PURL name path for a package coordinate, percent-encoding each `/`-separated segment
/// (so an npm scope `@scope/pkg` becomes `%40scope/pkg` and a Composer `vendor/pkg` stays a
/// two-segment path). Maven `group:artifact` is split into the `group/artifact` PURL path.
fn purl_path(ecosystem: Ecosystem, name: &str) -> String {
    let coordinate = if ecosystem == Ecosystem::Maven {
        name.replacen(':', "/", 1)
    } else {
        name.to_string()
    };
    coordinate
        .split('/')
        .map(purl_encode)
        .collect::<Vec<_>>()
        .join("/")
}

/// The PURL qualifier suffix (`?key=value`) for a dependency source, or `None` for
/// crates.io / path deps (which stay a bare `pkg:cargo` PURL). A git dep carries its
/// `vcs_url` (`git+<url>[@<rev>]`); an alternate registry its `repository_url`. Values
/// are percent-encoded per the PURL spec.
fn purl_qualifier(source: &DepSource) -> Option<String> {
    match source {
        DepSource::CratesIo | DepSource::Path => None,
        DepSource::Git { url, rev } => {
            let mut value = format!("git+{url}");
            if let Some(rev) = rev {
                value.push('@');
                value.push_str(rev);
            }
            Some(format!("?vcs_url={}", purl_encode(&value)))
        }
        DepSource::OtherRegistry { url } => Some(format!("?repository_url={}", purl_encode(url))),
    }
}

/// Percent-encode a PURL name/version component, leaving the unreserved set
/// (`A-Za-z0-9` plus `.`, `_`, `-`) untouched — a superset of cargo's crate-name
/// charset, so well-formed names pass through unchanged.
fn purl_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The `affected` action: the concrete upgrade target, or a generic note when no
/// fix is published.
fn upgrade_action(package: &str, patched: &[fleetreach_core::semver::VersionReq]) -> String {
    match crate::fix_target(patched) {
        Some(target) => format!("Upgrade {package} to >= {target}."),
        None => format!("No fixed version of {package} is published; remove or replace it."),
    }
}

/// A total, deterministic ordering key for statements (§14).
fn sort_key(s: &Statement) -> (&str, &str, &str, &'static str) {
    (
        s.vulnerability.name.as_str(),
        s.products.first().map(|c| c.id.as_str()).unwrap_or(""),
        s.subcomponents.first().map(|c| c.id.as_str()).unwrap_or(""),
        s.status,
    )
}

/// Content-addressed `@id` (§9.1): SHA-256 over the statement set only (not
/// provenance), so it's stable across a DB refresh. Falls back to a `urn:` IRI.
fn content_id(statements: &[Statement], params: &VexParams) -> String {
    let bytes = serde_json::to_vec(statements).unwrap_or_default();
    let digest = Sha256::digest(&bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    match &params.product_id_base {
        Some(base) => format!("{base}vex-{hex}"),
        None => format!("urn:fleetreach:vex:{hex}"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fleetreach_core::semver::{Version, VersionReq};
    use fleetreach_core::{
        DependencyKind, Provenance, Reachability, RepoId, Severity, Summary, VulnFinding,
    };
    use serde_json::Value;

    fn params() -> VexParams {
        let mut product_ids = BTreeMap::new();
        product_ids.insert("app".to_string(), "pkg:cargo/app@1.0.0".to_string());
        product_ids.insert("svc".to_string(), "pkg:cargo/svc@2.0.0".to_string());
        VexParams {
            author: "secteam@acme.example".to_string(),
            role: Some("Document Creator".to_string()),
            scope: VexScope::Runtime,
            timestamp: "2026-06-25T00:00:00Z".to_string(),
            doc_id: None,
            product_id_base: Some("https://acme.example/fleet/".to_string()),
            product_ids,
            assertions: vec![],
            only_sound: false,
            alias_rustbinary: false,
            include_fixed: false,
            version: 1,
            supersedes: None,
        }
    }

    fn occ(repo: &str, package: &str, version: &str, active: Option<bool>) -> Occurrence {
        Occurrence::InRepo {
            repo: RepoId(repo.to_string()),
            package: package.to_string(),
            installed: Version::parse(version).expect("version"),
            patched: vec![VersionReq::parse(">=2.0.0").expect("req")],
            dependency_kind: DependencyKind::Transitive,
            dependency_path: vec![],
            active,
            source: Default::default(),
        }
    }

    fn reach(verdict: ReachVerdict) -> Reachability {
        Reachability {
            verdict,
            config: "x86_64-unknown-linux-gnu;default-features".to_string(),
            engine: "static-mir-rta@0.1.0".to_string(),
            targets: vec!["x86_64-unknown-linux-gnu".to_string()],
            witness: Some("sha256:deadbeef".to_string()),
        }
    }

    fn finding(id: &str, occs: Vec<Occurrence>) -> VulnFinding {
        VulnFinding {
            advisory_id: id.to_string(),
            aliases: vec![format!("CVE-{id}")],
            ecosystem: Default::default(),
            title: "a vuln".to_string(),
            severity: Severity::High,
            cvss_score: None,
            url: None,
            occurrences: occs,
            affected_functions: vec!["some_crate::bad".to_string()],
            reachable: None,
            reachability: None,
            exploit: Default::default(),
        }
    }

    fn report(vulns: Vec<VulnFinding>) -> FleetReport {
        FleetReport {
            schema_version: fleetreach_core::SCHEMA_VERSION,
            provenance: Provenance {
                tool_version: "0.1.0".to_string(),
                rustsec_crate_version: "0.33.0".to_string(),
                db_commit: Some("abc123".to_string()),
                db_timestamp: Some("2026-06-25T00:00:00Z".to_string()),
                host_os: "linux".to_string(),
                host_arch: "x86_64".to_string(),
                generated_at: "2026-06-25T12:00:00Z".to_string(),
            },
            summary: Summary {
                repos_scanned: 1,
                repos_errored: 0,
                vuln_count: vulns.len(),
                warn_count: 0,
                max_severity: Severity::High,
                stale_ignores: vec![],
            },
            vulnerabilities: vulns,
            warnings: vec![],
            outcomes: vec![],
        }
    }

    fn parse(doc: &str) -> Value {
        serde_json::from_str(doc).expect("valid json")
    }

    fn statements(doc: &Value) -> &Vec<Value> {
        doc["statements"].as_array().expect("statements array")
    }

    #[test]
    fn document_envelope_is_well_formed() {
        let r = report(vec![finding(
            "RUSTSEC-2023-0001",
            vec![occ("app", "foo", "1.0.0", None)],
        )]);
        let doc = parse(&to_vex(&r, &params()).expect("vex"));
        assert_eq!(doc["@context"], OPENVEX_CONTEXT);
        assert_eq!(doc["author"], "secteam@acme.example");
        assert_eq!(doc["role"], "Document Creator");
        assert_eq!(doc["timestamp"], "2026-06-25T00:00:00Z");
        assert_eq!(doc["version"], 1);
        assert!(doc["@id"]
            .as_str()
            .expect("@id")
            .starts_with("https://acme.example/fleet/vex-"));
    }

    /// §2: the grep heuristic alone never reaches `not_affected`.
    #[test]
    fn heuristic_only_never_emits_not_affected() {
        let mut v = finding("RUSTSEC-2023-0002", vec![occ("app", "foo", "1.0.0", None)]);
        v.reachable = Some(false); // grep found nothing — still not a proof
        let doc = parse(&to_vex(&report(vec![v]), &params()).expect("vex"));
        let s = &statements(&doc)[0];
        assert_eq!(s["status"], "under_investigation");
        assert!(statements(&doc)
            .iter()
            .all(|s| s["status"] != "not_affected"));
    }

    #[test]
    fn static_not_reachable_is_not_affected() {
        let mut v = finding("RUSTSEC-2023-0003", vec![occ("app", "foo", "1.0.0", None)]);
        v.reachability = Some(reach(ReachVerdict::NotReachable));
        let doc = parse(&to_vex(&report(vec![v]), &params()).expect("vex"));
        let s = &statements(&doc)[0];
        assert_eq!(s["status"], "not_affected");
        assert_eq!(s["justification"], "vulnerable_code_not_in_execute_path");
        let notes = s["status_notes"].as_str().expect("notes");
        assert!(notes.contains("Automated Analysis"));
        // The checkable witness (§9.2) and analyzed targets (§7 edge 3) are recorded.
        assert!(notes.contains("witness=sha256:deadbeef"), "notes: {notes}");
        assert!(
            notes.contains("targets=[x86_64-unknown-linux-gnu]"),
            "notes: {notes}"
        );
    }

    #[test]
    fn non_crates_io_sources_qualify_the_subcomponent_purl() {
        // crates.io and local path stay the bare PURL — byte-identical to before, so
        // the validated registry-suppression path is untouched.
        assert_eq!(
            subcomponents(
                Ecosystem::Cargo,
                "foo",
                "1.0.0",
                &DepSource::CratesIo,
                false
            )[0]
            .id,
            "pkg:cargo/foo@1.0.0"
        );
        assert_eq!(
            subcomponents(Ecosystem::Cargo, "foo", "1.0.0", &DepSource::Path, false)[0].id,
            "pkg:cargo/foo@1.0.0"
        );
        // A git dep carries its vcs_url (git+url@rev), percent-encoded.
        let git = subcomponents(
            Ecosystem::Cargo,
            "foo",
            "1.0.0",
            &DepSource::Git {
                url: "https://github.com/x/y".into(),
                rev: Some("abc123".into()),
            },
            false,
        )[0]
        .id
        .clone();
        assert!(git.starts_with("pkg:cargo/foo@1.0.0?vcs_url="), "{git}");
        assert!(git.contains("git%2Bhttps"), "{git}");
        assert!(git.contains("abc123"), "{git}");
        // An alternate registry carries its repository_url.
        let reg = subcomponents(
            Ecosystem::Cargo,
            "foo",
            "1.0.0",
            &DepSource::OtherRegistry {
                url: "https://my.reg/index".into(),
            },
            false,
        )[0]
        .id
        .clone();
        assert!(
            reg.starts_with("pkg:cargo/foo@1.0.0?repository_url="),
            "{reg}"
        );
    }

    #[test]
    fn purl_type_is_per_ecosystem() {
        let id = |eco, name: &str| {
            subcomponents(eco, name, "1.0.0", &DepSource::CratesIo, false)[0]
                .id
                .clone()
        };
        assert_eq!(id(Ecosystem::Pypi, "urllib3"), "pkg:pypi/urllib3@1.0.0");
        assert_eq!(id(Ecosystem::Npm, "lodash"), "pkg:npm/lodash@1.0.0");
        // npm scope: the `@` is percent-encoded, the `/` stays a path separator.
        assert_eq!(
            id(Ecosystem::Npm, "@scope/pkg"),
            "pkg:npm/%40scope/pkg@1.0.0"
        );
        assert_eq!(id(Ecosystem::RubyGems, "rack"), "pkg:gem/rack@1.0.0");
        assert_eq!(
            id(Ecosystem::Packagist, "monolog/monolog"),
            "pkg:composer/monolog/monolog@1.0.0"
        );
        assert_eq!(
            id(Ecosystem::NuGet, "Newtonsoft.Json"),
            "pkg:nuget/Newtonsoft.Json@1.0.0"
        );
        // Maven `group:artifact` splits into the `group/artifact` PURL path.
        assert_eq!(
            id(Ecosystem::Maven, "org.apache.logging.log4j:log4j-core"),
            "pkg:maven/org.apache.logging.log4j/log4j-core@1.0.0"
        );
        assert_eq!(
            id(Ecosystem::Go, "golang.org/x/net"),
            "pkg:golang/golang.org/x/net@1.0.0"
        );
    }

    #[test]
    fn rustbinary_alias_is_cargo_only() {
        // A non-Cargo finding never gets the Rust-binary alias even with the flag on.
        let subs = subcomponents(
            Ecosystem::Pypi,
            "urllib3",
            "1.0.0",
            &DepSource::CratesIo,
            true,
        );
        assert_eq!(
            subs.len(),
            1,
            "no rustbinary alias for a non-Cargo ecosystem"
        );
        assert_eq!(subs[0].id, "pkg:pypi/urllib3@1.0.0");
    }

    #[test]
    fn phantom_dep_is_component_not_present() {
        let mut v = finding(
            "RUSTSEC-2023-0004",
            vec![occ("app", "foo", "1.0.0", Some(false))],
        );
        // Even a reachable verdict can't override "not compiled in".
        v.reachability = Some(reach(ReachVerdict::Reachable {
            witness: vec!["root".into(), "some_crate::bad".into()],
        }));
        let doc = parse(&to_vex(&report(vec![v]), &params()).expect("vex"));
        let s = &statements(&doc)[0];
        assert_eq!(s["status"], "not_affected");
        assert_eq!(s["justification"], "component_not_present");
    }

    #[test]
    fn static_reachable_is_affected_with_action() {
        let mut v = finding("RUSTSEC-2023-0005", vec![occ("app", "foo", "1.0.0", None)]);
        v.reachability = Some(reach(ReachVerdict::Reachable {
            witness: vec!["root".into(), "some_crate::bad".into()],
        }));
        let doc = parse(&to_vex(&report(vec![v]), &params()).expect("vex"));
        let s = &statements(&doc)[0];
        assert_eq!(s["status"], "affected");
        assert_eq!(s["action_statement"], "Upgrade foo to >= 2.0.0.");
        assert!(s["justification"].is_null());
    }

    #[test]
    fn unknown_and_default_are_under_investigation() {
        let mut undecided = finding("RUSTSEC-2023-0006", vec![occ("app", "foo", "1.0.0", None)]);
        undecided.reachability = Some(reach(ReachVerdict::Unknown {
            reason: "build failed".to_string(),
        }));
        let plain = finding("RUSTSEC-2023-0007", vec![occ("svc", "bar", "1.0.0", None)]);
        let doc = parse(&to_vex(&report(vec![undecided, plain]), &params()).expect("vex"));
        for s in statements(&doc) {
            assert_eq!(s["status"], "under_investigation");
            assert!(s["justification"].is_null());
        }
    }

    /// §7.7: unknown severity proven unreachable is still soundly `not_affected`.
    #[test]
    fn unknown_severity_unreachable_is_not_affected() {
        let mut v = finding("RUSTSEC-2023-0008", vec![occ("app", "foo", "1.0.0", None)]);
        v.severity = Severity::Unknown;
        v.reachability = Some(reach(ReachVerdict::NotReachable));
        let doc = parse(&to_vex(&report(vec![v]), &params()).expect("vex"));
        assert_eq!(statements(&doc)[0]["status"], "not_affected");
    }

    /// §7 edge 6: distinct versions are distinct subcomponents, never merged.
    #[test]
    fn duplicate_versions_stay_distinct() {
        let mut v = finding(
            "RUSTSEC-2023-0009",
            vec![
                occ("app", "foo", "1.0.0", Some(false)), // phantom -> not_affected
                occ("svc", "foo", "1.5.0", None),        // live -> under_investigation
            ],
        );
        // Reachability is per-finding; leave it absent so the live one is honest.
        v.reachability = None;
        let doc = parse(&to_vex(&report(vec![v]), &params()).expect("vex"));
        let by_sub: BTreeMap<&str, &str> = statements(&doc)
            .iter()
            .map(|s| {
                (
                    s["subcomponents"][0]["@id"].as_str().expect("sub"),
                    s["status"].as_str().expect("status"),
                )
            })
            .collect();
        assert_eq!(by_sub["pkg:cargo/foo@1.0.0"], "not_affected");
        assert_eq!(by_sub["pkg:cargo/foo@1.5.0"], "under_investigation");
    }

    /// §15: the crate PURL is also a product (so Trivy fs matches); repo first.
    #[test]
    fn crate_purl_is_also_a_product() {
        let mut v = finding("RUSTSEC-2023-0060", vec![occ("app", "foo", "1.0.0", None)]);
        v.reachability = Some(reach(ReachVerdict::NotReachable));
        let doc = parse(&to_vex(&report(vec![v]), &params()).expect("vex"));
        let products: Vec<&str> = statements(&doc)[0]["products"]
            .as_array()
            .expect("products")
            .iter()
            .map(|p| p["@id"].as_str().expect("id"))
            .collect();
        assert_eq!(products[0], "pkg:cargo/app@1.0.0", "repo product is first");
        assert!(
            products.contains(&"pkg:cargo/foo@1.0.0"),
            "crate PURL must also be a product: {products:?}"
        );
    }

    #[test]
    fn cargo_purl_has_no_namespace_and_exact_version() {
        let r = report(vec![finding(
            "RUSTSEC-2023-0010",
            vec![occ("app", "MixedCase", "1.2.3-pre.1", None)],
        )]);
        let doc = parse(&to_vex(&r, &params()).expect("vex"));
        let sub = statements(&doc)[0]["subcomponents"][0]["@id"]
            .as_str()
            .expect("sub");
        assert_eq!(sub, "pkg:cargo/MixedCase@1.2.3-pre.1");
        assert!(!sub.contains("//")); // no namespace segment
    }

    #[test]
    fn rustbinary_alias_emits_both_subcomponents() {
        let mut p = params();
        p.alias_rustbinary = true;
        let r = report(vec![finding(
            "RUSTSEC-2023-0011",
            vec![occ("app", "foo", "1.0.0", None)],
        )]);
        let doc = parse(&to_vex(&r, &p).expect("vex"));
        let subs = statements(&doc)[0]["subcomponents"]
            .as_array()
            .expect("subs");
        let ids: Vec<&str> = subs
            .iter()
            .map(|c| c["@id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, vec!["pkg:cargo/foo@1.0.0", "pkg:rustbinary/foo@1.0.0"]);
    }

    #[test]
    fn fixed_is_gated_behind_include_fixed() {
        // installed 3.0.0 is >= patched >=2.0.0 -> already fixed, not a finding.
        let v = finding("RUSTSEC-2023-0012", vec![occ("app", "foo", "3.0.0", None)]);
        let off = parse(&to_vex(&report(vec![v.clone()]), &params()).expect("vex"));
        assert!(statements(&off).is_empty());

        let mut p = params();
        p.include_fixed = true;
        let on = parse(&to_vex(&report(vec![v]), &p).expect("vex"));
        assert_eq!(statements(&on)[0]["status"], "fixed");
    }

    #[test]
    fn toolchain_occurrences_are_skipped() {
        let mut v = finding("RUSTSEC-2023-0013", vec![]);
        v.occurrences = vec![Occurrence::Toolchain {
            channel: "stable 1.96".to_string(),
            installed: Some(Version::parse("1.96.0").expect("v")),
            patched: vec![],
        }];
        let doc = parse(&to_vex(&report(vec![v]), &params()).expect("vex"));
        assert!(statements(&doc).is_empty());
    }

    fn assertion(id: &str, justification: Option<&str>, approver: Option<&str>) -> HumanAssertion {
        HumanAssertion {
            advisory_id: id.to_string(),
            aliases: vec![],
            product_id: "pkg:cargo/app@1.0.0".to_string(),
            package: "foo".to_string(),
            version: "1.0.0".to_string(),
            justification: justification.map(str::to_string),
            impact_statement: "dev-dependency only, not in any shipped path".to_string(),
            approved_by: approver.map(str::to_string),
        }
    }

    /// §6/§7.1: a labelled `vex_assertion` emits `not_affected` + Human Assertion + approver.
    #[test]
    fn human_assertion_with_label_is_not_affected() {
        let mut p = params();
        p.assertions = vec![assertion(
            "RUSTSEC-2020-0071",
            Some("component_not_present"),
            Some("secteam"),
        )];
        let doc = parse(&to_vex(&report(vec![]), &p).expect("vex"));
        let s = &statements(&doc)[0];
        assert_eq!(s["status"], "not_affected");
        assert_eq!(s["justification"], "component_not_present");
        assert!(
            s["impact_statement"].is_null(),
            "label present -> no free text"
        );
        let notes = s["status_notes"].as_str().expect("notes");
        assert!(notes.contains("Human Assertion"));
        assert!(notes.contains("approved_by=secteam"));
    }

    /// A promoted `ignore` (no label/approver) falls back to `impact_statement`.
    #[test]
    fn human_assertion_without_label_uses_impact_statement() {
        let mut p = params();
        p.assertions = vec![assertion("RUSTSEC-2020-0071", None, None)];
        let doc = parse(&to_vex(&report(vec![]), &p).expect("vex"));
        let s = &statements(&doc)[0];
        assert_eq!(s["status"], "not_affected");
        assert!(s["justification"].is_null());
        assert_eq!(
            s["impact_statement"],
            "dev-dependency only, not in any shipped path"
        );
        assert!(s["status_notes"]
            .as_str()
            .expect("notes")
            .contains("no approver"));
    }

    /// §7.1: `--vex-only-sound` drops every human assertion, keeping machine ones.
    #[test]
    fn only_sound_drops_human_assertions() {
        let mut p = params();
        p.only_sound = true;
        p.assertions = vec![assertion(
            "RUSTSEC-2020-0071",
            Some("component_not_present"),
            Some("secteam"),
        )];
        let machine = finding("RUSTSEC-2023-0099", vec![occ("app", "bar", "1.0.0", None)]);
        let doc = parse(&to_vex(&report(vec![machine]), &p).expect("vex"));
        let sts = statements(&doc);
        assert_eq!(sts.len(), 1, "only the machine statement remains");
        assert_eq!(sts[0]["vulnerability"]["name"], "RUSTSEC-2023-0099");
        assert!(sts.iter().all(|s| !s["status_notes"]
            .as_str()
            .unwrap_or_default()
            .contains("Human Assertion")));
    }

    /// §9.3: a monotonic `version` and an optional `supersedes` chain.
    #[test]
    fn version_and_supersedes_are_emitted() {
        let mut p = params();
        p.version = 4;
        p.supersedes = Some("https://acme.example/fleet/vex-prior".to_string());
        let r = report(vec![finding(
            "RUSTSEC-2023-0050",
            vec![occ("app", "foo", "1.0.0", None)],
        )]);
        let doc = parse(&to_vex(&r, &p).expect("vex"));
        assert_eq!(doc["version"], 4);
        assert_eq!(doc["supersedes"], "https://acme.example/fleet/vex-prior");
    }

    #[test]
    fn supersedes_is_omitted_when_absent() {
        let doc = parse(&to_vex(&report(vec![]), &params()).expect("vex"));
        assert!(doc.get("supersedes").is_none());
        assert_eq!(doc["version"], 1);
    }

    /// §10: `project` exposes the statement identities the document carries.
    #[test]
    fn project_exposes_statement_identities() {
        let mut v = finding("RUSTSEC-2023-0051", vec![occ("app", "foo", "1.0.0", None)]);
        v.reachability = Some(reach(ReachVerdict::NotReachable));
        let views = project(&report(vec![v]), &params());
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].vulnerability, "RUSTSEC-2023-0051");
        assert_eq!(views[0].product, "pkg:cargo/app@1.0.0");
        assert_eq!(views[0].subcomponent, "pkg:cargo/foo@1.0.0");
        assert_eq!(views[0].status, "not_affected");
    }

    /// Determinism: byte-identical output; `@id` stable across a DB refresh (§9.1).
    #[test]
    fn deterministic_and_db_stable_id() {
        let make = || {
            report(vec![
                finding("RUSTSEC-2023-0015", vec![occ("svc", "bar", "1.0.0", None)]),
                finding("RUSTSEC-2023-0014", vec![occ("app", "foo", "1.0.0", None)]),
            ])
        };
        let a = to_vex(&make(), &params()).expect("vex");
        let b = to_vex(&make(), &params()).expect("vex");
        assert_eq!(a, b, "identical inputs must be byte-identical");

        // A DB refresh changes provenance but not the statement set -> same @id.
        let mut refreshed = make();
        refreshed.provenance.db_commit = Some("def456".to_string());
        let id_a = parse(&a)["@id"].as_str().expect("id").to_string();
        let id_b = parse(&to_vex(&refreshed, &params()).expect("vex"))["@id"]
            .as_str()
            .expect("id")
            .to_string();
        assert_eq!(id_a, id_b, "@id must not churn on a DB-only change");
    }
}
