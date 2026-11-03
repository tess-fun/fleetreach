//! Vendor CSAF 2.0 VEX (spec 16, row 12; consumed by containers phase 2 for unfixed OS
//! package statuses). Red Hat first: it publishes one VEX document per CVE, covering every
//! product and component it ships, with statuses OSV's Red Hat export does not carry
//! (affected with no fix yet, will not fix, fix deferred, out of support, under
//! investigation, not affected).
//!
//! A document is reduced to [`VexRecord`]s, one per (document, CVE), each holding one
//! [`VexEntry`] per (platform product, component, status, version): architecture variants of
//! one build collapse into one entry. Red Hat's archive is 24 GB of JSON uncompressed, so the
//! records are built once when the archive is synced or imported, and the checks read the
//! compact index.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A CSAF 2.0 `product_status` category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductStatus {
    FirstAffected,
    FirstFixed,
    Fixed,
    KnownAffected,
    KnownNotAffected,
    LastAffected,
    Recommended,
    UnderInvestigation,
}

impl ProductStatus {
    const ALL: [(&'static str, ProductStatus); 8] = [
        ("first_affected", ProductStatus::FirstAffected),
        ("first_fixed", ProductStatus::FirstFixed),
        ("fixed", ProductStatus::Fixed),
        ("known_affected", ProductStatus::KnownAffected),
        ("known_not_affected", ProductStatus::KnownNotAffected),
        ("last_affected", ProductStatus::LastAffected),
        ("recommended", ProductStatus::Recommended),
        ("under_investigation", ProductStatus::UnderInvestigation),
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(_, s)| *s == self)
            .map_or("", |(name, _)| name)
    }
}

/// A CSAF remediation `category` (2.0, plus 2.1's `fix_planned` and `optional_patch`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationCategory {
    Mitigation,
    NoFixPlanned,
    NoneAvailable,
    VendorFix,
    Workaround,
    FixPlanned,
    OptionalPatch,
}

impl RemediationCategory {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "mitigation" => Self::Mitigation,
            "no_fix_planned" => Self::NoFixPlanned,
            "none_available" => Self::NoneAvailable,
            "vendor_fix" => Self::VendorFix,
            "workaround" => Self::Workaround,
            "fix_planned" => Self::FixPlanned,
            "optional_patch" => Self::OptionalPatch,
            _ => return None,
        })
    }

    /// Whether the category says something about a fix (workarounds and mitigations do not).
    fn about_fix(self) -> bool {
        !matches!(self, Self::Mitigation | Self::Workaround)
    }
}

/// What a vendor's status and remediation mean for a scanner, the way Red Hat uses them
/// (and Trivy reads them): a `known_affected` product is plain affected, will-not-fix, fix
/// deferred or out of support depending on the remediation's category and details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VendorState {
    Fixed,
    /// Affected; no fix released yet and no decision against one.
    Affected,
    /// The vendor will not fix it (`no_fix_planned`, "Will not fix").
    WillNotFix,
    /// A fix is deferred to a later release (`none_available`, "Deferred" / "Fix deferred").
    FixDeferred,
    /// The product is outside its support scope (`no_fix_planned`, "Out of support scope").
    OutOfSupport,
    UnderInvestigation,
    NotAffected,
}

impl VendorState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::Affected => "affected",
            Self::WillNotFix => "will_not_fix",
            Self::FixDeferred => "fix_deferred",
            Self::OutOfSupport => "out_of_support",
            Self::UnderInvestigation => "under_investigation",
            Self::NotAffected => "not_affected",
        }
    }

    /// Derive the state from a product's status and its remediation. `None` for `recommended`,
    /// which names a version to use rather than a vulnerability status.
    #[must_use]
    pub fn derive(
        status: ProductStatus,
        remediation: Option<RemediationCategory>,
        details: Option<&str>,
    ) -> Option<VendorState> {
        let details = details.unwrap_or("").to_ascii_lowercase();
        Some(match status {
            ProductStatus::Fixed | ProductStatus::FirstFixed => Self::Fixed,
            ProductStatus::KnownNotAffected => Self::NotAffected,
            ProductStatus::UnderInvestigation => Self::UnderInvestigation,
            ProductStatus::Recommended => return None,
            ProductStatus::KnownAffected
            | ProductStatus::FirstAffected
            | ProductStatus::LastAffected => match remediation {
                Some(RemediationCategory::NoFixPlanned) if details.contains("out of support") => {
                    Self::OutOfSupport
                }
                Some(RemediationCategory::NoFixPlanned) => Self::WillNotFix,
                Some(RemediationCategory::NoneAvailable | RemediationCategory::FixPlanned)
                    if details.contains("defer") =>
                {
                    Self::FixDeferred
                }
                _ => Self::Affected,
            },
        })
    }
}

/// One (document, vulnerability) pair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VexRecord {
    /// The CVE id (or the vulnerability's first `ids[]` text when it has no CVE).
    pub cve: String,
    /// The document's `tracking.id`.
    pub document: String,
    /// `document.publisher.namespace`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    /// `tracking.current_release_date`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    /// `document.aggregate_severity.text`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Platform product id to its CPE, for the platforms the entries name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub platforms: BTreeMap<String, String>,
    pub entries: Vec<VexEntry>,
}

/// One component's status on one platform.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VexEntry {
    /// The platform product id (`red_hat_enterprise_linux_8`, `AppStream-8.10.0.Z.MAIN.EUS`);
    /// empty when the product is not a component of another.
    pub platform: String,
    /// The component name (from its purl, else its product id).
    pub component: String,
    /// The component's purl without version or qualifiers (`pkg:rpm/redhat/python3-idna`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// The version (an rpm `epoch:version-release`) when the product names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The module stream of a modular rpm (`php:7.3`, from the purl's `rpmmod`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    pub status: ProductStatus,
    pub state: VendorState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<RemediationCategory>,
    /// The remediation's details, when it is about a fix and short (`Will not fix`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// A `flags[].label` justification (`vulnerable_code_not_present`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
}

/// The facts the product tree gives about one product id.
#[derive(Debug, Default, Clone)]
struct Product {
    name: Option<String>,
    purl: Option<String>,
    cpe: Option<String>,
}

fn walk_branches(branch: &Value, out: &mut BTreeMap<String, Product>) {
    if let Some(product) = branch.get("product") {
        add_product(product, out);
    }
    for child in branch
        .get("branches")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        walk_branches(child, out);
    }
}

fn add_product(product: &Value, out: &mut BTreeMap<String, Product>) {
    let Some(id) = product.get("product_id").and_then(Value::as_str) else {
        return;
    };
    let helper = product.get("product_identification_helper");
    let field = |v: Option<&Value>, key: &str| {
        v.and_then(|v| v.get(key))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    out.insert(
        id.to_string(),
        Product {
            name: field(Some(product), "name"),
            purl: field(helper, "purl"),
            cpe: field(helper, "cpe"),
        },
    );
}

/// Reduce one CSAF document. `None` when it is not a CSAF document.
#[must_use]
pub fn summarize(body: &str) -> Option<Vec<VexRecord>> {
    let doc: Value = serde_json::from_str(body).ok()?;
    let document = doc.get("document")?;
    let text = |v: &Value, ptr: &str| v.pointer(ptr).and_then(Value::as_str).map(str::to_string);
    let tracking_id = text(document, "/tracking/id")?;
    let publisher = text(document, "/publisher/namespace");
    let modified = text(document, "/tracking/current_release_date");
    let severity = text(document, "/aggregate_severity/text");

    let mut products: BTreeMap<String, Product> = BTreeMap::new();
    let tree = doc.get("product_tree");
    for branch in tree
        .and_then(|t| t.get("branches"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        walk_branches(branch, &mut products);
    }
    for product in tree
        .and_then(|t| t.get("full_product_names"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        add_product(product, &mut products);
    }
    // Composite product id -> (component reference, platform reference).
    let mut relations: BTreeMap<String, (String, String)> = BTreeMap::new();
    for rel in tree
        .and_then(|t| t.get("relationships"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let (Some(id), Some(component), Some(platform)) = (
            text(rel, "/full_product_name/product_id"),
            text(rel, "/product_reference"),
            text(rel, "/relates_to_product_reference"),
        ) else {
            continue;
        };
        relations.insert(id, (component, platform));
    }

    let mut out = Vec::new();
    for vuln in doc
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let cve = text(vuln, "/cve")
            .or_else(|| text(vuln, "/ids/0/text"))
            .unwrap_or_else(|| tracking_id.clone());
        // Product id -> the remediation that speaks about a fix (vendor_fix, no_fix_planned,
        // none_available, ...), else any.
        let mut remediations: BTreeMap<&str, (RemediationCategory, Option<&str>)> = BTreeMap::new();
        for rem in vuln
            .get("remediations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(cat) = rem
                .get("category")
                .and_then(Value::as_str)
                .and_then(RemediationCategory::parse)
            else {
                continue;
            };
            let details = rem.get("details").and_then(Value::as_str);
            for pid in rem
                .get("product_ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                let slot = remediations.entry(pid).or_insert((cat, details));
                if !slot.0.about_fix() && cat.about_fix() {
                    *slot = (cat, details);
                }
            }
        }
        let mut flags: BTreeMap<&str, &str> = BTreeMap::new();
        for flag in vuln
            .get("flags")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(label) = flag.get("label").and_then(Value::as_str) else {
                continue;
            };
            for pid in flag
                .get("product_ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                flags.insert(pid, label);
            }
        }

        let mut entries: BTreeSet<VexEntry> = BTreeSet::new();
        let mut platforms: BTreeMap<String, String> = BTreeMap::new();
        for (key, status) in ProductStatus::ALL {
            for pid in vuln
                .pointer(&format!("/product_status/{key}"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                let (remediation, details) = remediations
                    .get(pid)
                    .map_or((None, None), |(c, d)| (Some(*c), *d));
                let Some(state) = VendorState::derive(status, remediation, details) else {
                    continue;
                };
                let (component_ref, platform) = relations
                    .get(pid)
                    .map_or((pid, ""), |(c, p)| (c.as_str(), p.as_str()));
                if let Some(cpe) = products.get(platform).and_then(|p| p.cpe.clone()) {
                    platforms.insert(platform.to_string(), cpe);
                }
                let product = products.get(component_ref);
                let product_purl = product.and_then(|p| p.purl.as_deref());
                let (component, purl, version) = component_identity(component_ref, product_purl);
                let module = product_purl.and_then(rpm_module);
                let component = if component.is_empty() {
                    product
                        .and_then(|p| p.name.clone())
                        .unwrap_or_else(|| component_ref.to_string())
                } else {
                    component
                };
                entries.insert(VexEntry {
                    platform: platform.to_string(),
                    component,
                    purl,
                    version,
                    module,
                    status,
                    state,
                    // A fixed or unaffected product's remediation adds nothing (and would
                    // keep architecture variants apart).
                    remediation: remediation.filter(|c| {
                        c.about_fix()
                            && !matches!(state, VendorState::Fixed | VendorState::NotAffected)
                    }),
                    details: details
                        .filter(|_| {
                            remediation.is_some_and(|c| {
                                c.about_fix() && c != RemediationCategory::VendorFix
                            })
                        })
                        .filter(|d| d.len() <= 80)
                        .map(str::to_string),
                    justification: flags.get(pid).map(|s| (*s).to_string()),
                });
            }
        }
        out.push(VexRecord {
            cve,
            document: tracking_id.clone(),
            publisher: publisher.clone(),
            modified: modified.clone(),
            severity: severity.clone(),
            platforms,
            entries: entries.into_iter().collect(),
        });
    }
    Some(out)
}

/// A component's name, versionless purl and version, from its purl when it has one, else
/// from an rpm-style product id (`python-idna-0:2.4-2.el7_9.noarch`, `name::module:stream`).
fn component_identity(
    component_ref: &str,
    purl: Option<&str>,
) -> (String, Option<String>, Option<String>) {
    if let Some(purl) = purl {
        let (base, qualifiers) = purl.split_once('?').unwrap_or((purl, ""));
        let (path, version) = match base.rsplit_once('@') {
            Some((p, v)) if p.contains('/') => (p, Some(v.to_string())),
            _ => (base, None),
        };
        let name = percent_decode(path.rsplit('/').next().unwrap_or(path));
        let epoch = qualifiers
            .split('&')
            .find_map(|q| q.strip_prefix("epoch="))
            .filter(|e| !e.is_empty());
        // rpm versions read as rpm writes them (`module+el8`), others as the purl has them.
        let rpm = path.starts_with("pkg:rpm/");
        let version = version.map(|v| if rpm { percent_decode(&v) } else { v });
        let version = match (version, epoch) {
            (Some(v), Some(e)) => Some(format!("{e}:{v}")),
            (Some(v), None) if rpm => Some(format!("0:{v}")),
            (v, _) => v,
        };
        return (name, Some(path.to_string()), version);
    }
    let base = component_ref.split("::").next().unwrap_or(component_ref);
    if let Some((name, evr)) = split_nevra(base) {
        return (name, None, Some(evr));
    }
    (String::new(), None, None)
}

/// A purl component with its `%XX` escapes decoded (`gcc-c%2B%2B` is `gcc-c++`). An escape
/// that is not valid hex, or bytes that are not UTF-8, leave the text as written.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match (
            b[i],
            b.get(i + 1).copied().and_then(hex),
            b.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(h), Some(l)) => {
                out.push(u8::try_from(h * 16 + l).unwrap_or(b'?'));
                i += 3;
            }
            (c, _, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// The `name:stream` of a modular rpm's purl (`rpmmod=php:7.3`, or with version and context
/// after the stream on a built package).
fn rpm_module(purl: &str) -> Option<String> {
    let query = purl.split_once('?')?.1;
    let value = query.split('&').find_map(|q| q.strip_prefix("rpmmod="))?;
    let mut parts = value.split(':');
    match (parts.next(), parts.next()) {
        (Some(n), Some(s)) if !n.is_empty() && !s.is_empty() => Some(format!("{n}:{s}")),
        _ => None,
    }
}

/// `name-epoch:version-release.arch` into `(name, epoch:version-release)`.
fn split_nevra(s: &str) -> Option<(String, String)> {
    let colon = s.find(':')?;
    let dash = s[..colon].rfind('-')?;
    let epoch = &s[dash + 1..colon];
    if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let name = &s[..dash];
    let evr = &s[dash + 1..];
    let evr = match evr.rsplit_once('.') {
        Some((head, arch)) if KNOWN_ARCHES.contains(&arch) => head,
        _ => evr,
    };
    Some((name.to_string(), evr.to_string()))
}

const KNOWN_ARCHES: &[&str] = &[
    "noarch", "src", "x86_64", "aarch64", "ppc64le", "s390x", "i686", "i386", "ppc64", "s390",
    "ppc",
];

// ---- Reading archives and the compact index ----

/// What a read produced: the records, plus how many files were not CSAF documents.
#[derive(Debug, Default)]
pub struct ReadResult {
    pub records: Vec<VexRecord>,
    pub documents: usize,
    pub not_csaf: usize,
}

/// Read every CSAF document under `input`: a directory of `*.json` documents (searched
/// recursively), or a `.tar.zst` archive like Red Hat's `csaf_vex_<date>.tar.zst`.
///
/// # Errors
///
/// An unreadable input, or a corrupt archive.
pub fn read_all(input: &Path) -> Result<ReadResult, String> {
    let mut result = ReadResult::default();
    if input.is_dir() {
        let paths: Vec<PathBuf> = walkdir::WalkDir::new(input)
            .into_iter()
            .filter_entry(|e| e.depth() == 0 || !e.file_name().to_string_lossy().starts_with('.'))
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .map(walkdir::DirEntry::into_path)
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
            .collect();
        let parsed: Vec<Option<Vec<VexRecord>>> = paths
            .par_iter()
            .map(|p| {
                std::fs::read_to_string(p)
                    .map(|b| summarize(&b))
                    .map_err(|e| format!("reading {}: {e}", p.display()))
            })
            .collect::<Result<_, _>>()?;
        absorb(&mut result, parsed);
    } else {
        let file =
            std::fs::File::open(input).map_err(|e| format!("reading {}: {e}", input.display()))?;
        let decoder = ruzstd::decoding::StreamingDecoder::new(std::io::BufReader::new(file))
            .map_err(|e| format!("{}: not a zstd stream: {e}", input.display()))?;
        let mut archive = tar::Archive::new(decoder);
        // Parse in batches so a 24 GB archive never sits in memory, while JSON parsing (the
        // slow half) runs on every core.
        const BATCH_BYTES: usize = 512 << 20;
        let mut batch: Vec<String> = Vec::new();
        let mut batch_bytes = 0usize;
        let entries = archive
            .entries()
            .map_err(|e| format!("{}: {e}", input.display()))?;
        for entry in entries {
            let mut entry = entry.map_err(|e| format!("{}: {e}", input.display()))?;
            let path = entry
                .path()
                .map_err(|e| format!("{}: {e}", input.display()))?
                .to_string_lossy()
                .into_owned();
            if !entry.header().entry_type().is_file() || !path.ends_with(".json") {
                continue;
            }
            let mut body = String::new();
            entry
                .read_to_string(&mut body)
                .map_err(|e| format!("{}: {path}: {e}", input.display()))?;
            batch_bytes += body.len();
            batch.push(body);
            if batch_bytes >= BATCH_BYTES {
                let parsed = std::mem::take(&mut batch)
                    .par_iter()
                    .map(|b| summarize(b))
                    .collect();
                absorb(&mut result, parsed);
                batch_bytes = 0;
            }
        }
        let parsed = batch.par_iter().map(|b| summarize(b)).collect();
        absorb(&mut result, parsed);
    }
    result
        .records
        .sort_by(|a, b| a.cve.cmp(&b.cve).then_with(|| a.document.cmp(&b.document)));
    Ok(result)
}

fn absorb(result: &mut ReadResult, parsed: Vec<Option<Vec<VexRecord>>>) {
    for doc in parsed {
        match doc {
            Some(records) => {
                result.documents += 1;
                result.records.extend(records);
            }
            None => result.not_csaf += 1,
        }
    }
}

/// Call `f` on each record of a compact index, read as a stream (Red Hat's holds millions
/// of entries).
///
/// # Errors
///
/// A missing or corrupt index, or `f`'s error.
pub fn for_each_record(
    path: &Path,
    mut f: impl FnMut(VexRecord) -> Result<(), String>,
) -> Result<(), String> {
    use std::io::BufRead as _;
    let file = std::fs::File::open(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let reader = std::io::BufReader::new(flate2::read::GzDecoder::new(file));
    for (n, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("{}: {e}", path.display()))?;
        let record = serde_json::from_str(&line)
            .map_err(|e| format!("{}:{}: {e}", path.display(), n + 1))?;
        f(record)?;
    }
    Ok(())
}

/// The RHEL release a platform product names (`red_hat_enterprise_linux_9` is 9).
fn rhel_release(platform: &str) -> Option<&str> {
    platform
        .strip_prefix("red_hat_enterprise_linux_")
        .filter(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit()))
}

/// How a Red Hat state reads in a finding (`will not fix`), for the states that leave a
/// package exposed; `None` for fixed and not affected.
fn unfixed_status(state: VendorState) -> Option<&'static str> {
    match state {
        VendorState::Affected => Some("affected"),
        VendorState::WillNotFix => Some("will not fix"),
        VendorState::FixDeferred => Some("fix deferred"),
        VendorState::OutOfSupport => Some("out of support scope"),
        VendorState::UnderInvestigation => Some("under investigation"),
        VendorState::Fixed | VendorState::NotAffected => None,
    }
}

/// Red Hat's aggregate severity as an OSV `database_specific.severity` band.
fn severity_band(text: &str) -> Option<&'static str> {
    match text.to_ascii_lowercase().as_str() {
        "critical" => Some("CRITICAL"),
        "important" => Some("HIGH"),
        "moderate" => Some("MEDIUM"),
        "low" => Some("LOW"),
        _ => None,
    }
}

/// The RHEL release of a main-stream platform CPE (`cpe:/o:redhat:enterprise_linux:8::baseos`
/// is 8; EUS, AUS and the like have products of their own and are not read).
fn rhel_cpe_release(cpe: &str) -> Option<&str> {
    let mut parts = cpe.split(':');
    let (Some("cpe"), Some("/o" | "/a"), Some("redhat"), Some("enterprise_linux"), Some(r)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    (!r.is_empty() && r.bytes().all(|b| b.is_ascii_digit())).then_some(r)
}

/// What the VEX says about one RHEL package, strongest first: a fix outranks a statement
/// that the package is not affected, which outranks an open status.
enum Verdict {
    /// Fixed in this version (the highest a main-stream platform names).
    Fixed(String),
    /// Not affected (`vulnerable_code_not_present`): said so that the package is never
    /// matched through its source package's entry.
    NotAffected,
    /// Not fixed, with the status as it reads in a finding.
    Open(&'static str),
}

impl Verdict {
    fn rank(&self) -> u8 {
        match self {
            Verdict::Fixed(_) => 2,
            Verdict::NotAffected => 1,
            Verdict::Open(_) => 0,
        }
    }
}

/// The OSV records of one Red Hat record's RHEL rpm entries, by ecosystem
/// ([`fleetreach_os::distro::red_hat_vex`]): one record per release, its id the CVE, one
/// affected package per (component, module stream). A package fixed on a main-stream
/// platform (`cpe:/o:redhat:enterprise_linux:8::baseos`) gets its fix version; one Red Hat
/// lists as not fixed on the release gets no fix event and its status in
/// `ecosystem_specific.status`; one it lists as not affected gets an empty range.
#[must_use]
pub fn red_hat_vex(record: &VexRecord) -> Vec<(String, Value)> {
    type Key<'a> = (&'a str, Option<&'a str>);
    let mut by_release: BTreeMap<&str, BTreeMap<Key<'_>, Verdict>> = BTreeMap::new();
    for e in &record.entries {
        if !e
            .purl
            .as_deref()
            .is_some_and(|p| p.starts_with("pkg:rpm/redhat/"))
            || e.component.is_empty()
        {
            continue;
        }
        let key = (e.component.as_str(), e.module.as_deref());
        if e.state == VendorState::Fixed {
            let (Some(release), Some(version)) = (
                record
                    .platforms
                    .get(&e.platform)
                    .and_then(|c| rhel_cpe_release(c)),
                e.version.as_deref(),
            ) else {
                continue;
            };
            // Indexes written before versions were decoded hold `module%2Bel8...`.
            let version = percent_decode(version);
            let Some(parsed) = fleetreach_os::RpmVersion::parse(&version) else {
                continue;
            };
            let slot = by_release.entry(release).or_default();
            match slot.get(&key) {
                Some(Verdict::Fixed(old))
                    if fleetreach_os::RpmVersion::parse(old).is_some_and(|o| o >= parsed) => {}
                _ => {
                    slot.insert(key, Verdict::Fixed(version));
                }
            }
        } else {
            let release = rhel_release(&e.platform).or_else(|| {
                record
                    .platforms
                    .get(&e.platform)
                    .and_then(|c| rhel_cpe_release(c))
            });
            let verdict = match (e.state, unfixed_status(e.state)) {
                (VendorState::NotAffected, _) => Verdict::NotAffected,
                (_, Some(status)) if rhel_release(&e.platform).is_some() => Verdict::Open(status),
                _ => continue,
            };
            let Some(release) = release else { continue };
            let slot = by_release.entry(release).or_default();
            if slot.get(&key).is_none_or(|old| old.rank() < verdict.rank()) {
                slot.insert(key, verdict);
            }
        }
    }
    by_release
        .into_iter()
        .map(|(release, components)| {
            let ecosystem = fleetreach_os::distro::red_hat_vex(release);
            let affected: Vec<Value> = components
                .into_iter()
                .map(|((name, module), verdict)| {
                    let range = |events: Value| serde_json::json!([{"type": "ECOSYSTEM", "events": events}]);
                    let (ranges, mut specific) = match verdict {
                        Verdict::Fixed(v) => (
                            range(serde_json::json!([{"introduced": "0"}, {"fixed": v}])),
                            serde_json::json!({}),
                        ),
                        Verdict::Open(status) => (
                            range(serde_json::json!([{"introduced": "0"}])),
                            serde_json::json!({ "status": status }),
                        ),
                        // No range and no versions: no version is affected.
                        Verdict::NotAffected => (
                            serde_json::json!([]),
                            serde_json::json!({ "status": "not affected" }),
                        ),
                    };
                    if let Some(m) = module {
                        specific["module"] = Value::from(m);
                    }
                    serde_json::json!({
                        "package": {"ecosystem": ecosystem, "name": name},
                        "ranges": ranges,
                        "ecosystem_specific": specific,
                    })
                })
                .collect();
            let mut osv = serde_json::json!({
                "id": record.cve,
                "summary": record.cve,
                "modified": record.modified,
                "affected": affected,
                "references": [{
                    "type": "ADVISORY",
                    "url": format!("https://access.redhat.com/security/cve/{}", record.cve),
                }],
                "database_specific": {"source": "Red Hat CSAF VEX", "document": record.document},
            });
            if let Some(band) = record.severity.as_deref().and_then(severity_band) {
                osv["database_specific"]["severity"] = Value::from(band);
            }
            (ecosystem, osv)
        })
        .collect()
}

/// The directory under an OSV directory holding a provider's CSAF index.
#[must_use]
pub fn provider_dir(root: &Path, provider: &str) -> PathBuf {
    root.join("csaf").join(provider)
}

/// The compact index of a provider (`<dir>/csaf/<provider>/index.jsonl.gz`).
#[must_use]
pub fn index_path(root: &Path, provider: &str) -> PathBuf {
    provider_dir(root, provider).join("index.jsonl.gz")
}

/// Write records as gzipped JSON lines, atomically.
///
/// # Errors
///
/// Any write failure; the previous index stays in place.
pub fn write_index(path: &Path, records: &[VexRecord]) -> Result<(), String> {
    crate::cve5::write_jsonl_gz(path, records)
}

/// Read a provider's compact index.
///
/// # Errors
///
/// A missing or corrupt index: fail closed.
pub fn read_index(path: &Path) -> Result<Vec<VexRecord>, String> {
    crate::cve5::read_jsonl_gz(path)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The shape of Red Hat's documents (trimmed from cve-2024-3651.json).
    const DOC: &str = r#"{
      "document": {"category":"csaf_vex","csaf_version":"2.0",
        "aggregate_severity":{"text":"Moderate"},
        "publisher":{"namespace":"https://www.redhat.com","name":"Red Hat Product Security"},
        "tracking":{"id":"CVE-2024-3651","current_release_date":"2026-07-03T01:52:13+00:00"}},
      "product_tree": {
        "branches":[{"category":"vendor","name":"Red Hat","branches":[
          {"category":"product_family","name":"RHEL","branches":[
            {"category":"product_name","name":"Red Hat Enterprise Linux 8","product":{
              "name":"Red Hat Enterprise Linux 8","product_id":"red_hat_enterprise_linux_8",
              "product_identification_helper":{"cpe":"cpe:/o:redhat:enterprise_linux:8"}}},
            {"category":"product_name","name":"RHEL 7 ELS","product":{
              "name":"RHEL 7 ELS","product_id":"7Server-ELS",
              "product_identification_helper":{"cpe":"cpe:/o:redhat:rhel_els:7"}}}]},
          {"category":"product_version","name":"python3-idna","product":{
              "name":"python3-idna","product_id":"python3-idna",
              "product_identification_helper":{"purl":"pkg:rpm/redhat/python3-idna"}}},
          {"category":"product_version","name":"python-idna-0:2.4-2.el7_9.noarch","product":{
              "name":"python-idna-0:2.4-2.el7_9.noarch","product_id":"python-idna-0:2.4-2.el7_9.noarch",
              "product_identification_helper":{"purl":"pkg:rpm/redhat/python-idna@2.4-2.el7_9?arch=noarch"}}},
          {"category":"product_version","name":"python-idna-0:2.4-2.el7_9.src","product":{
              "name":"python-idna-0:2.4-2.el7_9.src","product_id":"python-idna-0:2.4-2.el7_9.src",
              "product_identification_helper":{"purl":"pkg:rpm/redhat/python-idna@2.4-2.el7_9?arch=src"}}}
        ]}],
        "relationships":[
          {"category":"default_component_of","product_reference":"python3-idna",
           "relates_to_product_reference":"red_hat_enterprise_linux_8",
           "full_product_name":{"name":"x","product_id":"red_hat_enterprise_linux_8:python3-idna"}},
          {"category":"default_component_of","product_reference":"python-idna-0:2.4-2.el7_9.noarch",
           "relates_to_product_reference":"7Server-ELS",
           "full_product_name":{"name":"x","product_id":"7Server-ELS:python-idna-0:2.4-2.el7_9.noarch"}},
          {"category":"default_component_of","product_reference":"python-idna-0:2.4-2.el7_9.src",
           "relates_to_product_reference":"7Server-ELS",
           "full_product_name":{"name":"x","product_id":"7Server-ELS:python-idna-0:2.4-2.el7_9.src"}}]},
      "vulnerabilities":[{"cve":"CVE-2024-3651",
        "product_status":{
          "fixed":["7Server-ELS:python-idna-0:2.4-2.el7_9.noarch","7Server-ELS:python-idna-0:2.4-2.el7_9.src"],
          "known_affected":["red_hat_enterprise_linux_8:python3-idna"]},
        "remediations":[
          {"category":"vendor_fix","details":"long text","product_ids":["7Server-ELS:python-idna-0:2.4-2.el7_9.noarch"]},
          {"category":"workaround","details":"Mitigation is not available","product_ids":["red_hat_enterprise_linux_8:python3-idna"]},
          {"category":"no_fix_planned","details":"Will not fix","product_ids":["red_hat_enterprise_linux_8:python3-idna"]}]}]
    }"#;

    #[test]
    fn red_hat_document_reduces_to_entries() {
        let records = summarize(DOC).unwrap();
        let [record] = records.as_slice() else {
            panic!("one vulnerability")
        };
        assert_eq!(record.cve, "CVE-2024-3651");
        assert_eq!(record.severity.as_deref(), Some("Moderate"));
        assert_eq!(record.platforms.len(), 2);
        // The noarch and src builds collapse into one fixed entry.
        let fixed: Vec<&VexEntry> = record
            .entries
            .iter()
            .filter(|e| e.state == VendorState::Fixed)
            .collect();
        assert_eq!(fixed.len(), 1);
        assert_eq!(fixed[0].component, "python-idna");
        assert_eq!(fixed[0].version.as_deref(), Some("0:2.4-2.el7_9"));
        assert_eq!(fixed[0].purl.as_deref(), Some("pkg:rpm/redhat/python-idna"));
        assert_eq!(fixed[0].platform, "7Server-ELS");
        let wontfix = record
            .entries
            .iter()
            .find(|e| e.platform == "red_hat_enterprise_linux_8")
            .unwrap();
        assert_eq!(wontfix.status, ProductStatus::KnownAffected);
        assert_eq!(wontfix.state, VendorState::WillNotFix);
        assert_eq!(wontfix.remediation, Some(RemediationCategory::NoFixPlanned));
        assert_eq!(wontfix.details.as_deref(), Some("Will not fix"));
        assert_eq!(wontfix.version, None);
    }

    #[test]
    fn vendor_states_follow_red_hat_semantics() {
        use ProductStatus as S;
        use RemediationCategory as R;
        let d = VendorState::derive;
        assert_eq!(d(S::KnownAffected, None, None), Some(VendorState::Affected));
        assert_eq!(
            d(S::KnownAffected, Some(R::NoneAvailable), Some("Affected")),
            Some(VendorState::Affected)
        );
        assert_eq!(
            d(S::KnownAffected, Some(R::NoneAvailable), Some("Deferred")),
            Some(VendorState::FixDeferred)
        );
        assert_eq!(
            d(
                S::KnownAffected,
                Some(R::NoFixPlanned),
                Some("Out of support scope")
            ),
            Some(VendorState::OutOfSupport)
        );
        assert_eq!(
            d(
                S::KnownAffected,
                Some(R::NoFixPlanned),
                Some("Will not fix")
            ),
            Some(VendorState::WillNotFix)
        );
        assert_eq!(
            d(S::UnderInvestigation, None, None),
            Some(VendorState::UnderInvestigation)
        );
        assert_eq!(
            d(S::KnownNotAffected, None, None),
            Some(VendorState::NotAffected)
        );
        assert_eq!(
            d(S::Fixed, Some(R::VendorFix), None),
            Some(VendorState::Fixed)
        );
        assert_eq!(d(S::Recommended, None, None), None);
    }

    #[test]
    fn nevra_and_purl_identities() {
        assert_eq!(
            split_nevra("python3x-idna-0:3.7-1.el8ap.src"),
            Some(("python3x-idna".into(), "0:3.7-1.el8ap".into()))
        );
        assert_eq!(
            split_nevra("PyYAML-0:5.4.1-1.module+el8.9.0+19644+d68f775d.src"),
            Some((
                "PyYAML".into(),
                "0:5.4.1-1.module+el8.9.0+19644+d68f775d".into()
            ))
        );
        assert_eq!(split_nevra("python3-idna"), None);
        let (name, purl, version) = component_identity(
            "x",
            Some("pkg:rpm/redhat/kernel@5.14.0-1.el9?arch=x86_64&epoch=1"),
        );
        assert_eq!(name, "kernel");
        assert_eq!(purl.as_deref(), Some("pkg:rpm/redhat/kernel"));
        assert_eq!(version.as_deref(), Some("1:5.14.0-1.el9"));
        let (name, _, version) = component_identity(
            "x",
            Some("pkg:oci/ose-cli@sha256%3Aabc?repository_url=registry.redhat.io"),
        );
        assert_eq!(name, "ose-cli");
        assert_eq!(version.as_deref(), Some("sha256%3Aabc"));
        let (name, _, _) = component_identity("x", Some("pkg:rpm/redhat/gcc-c%2B%2B?arch=src"));
        assert_eq!(name, "gcc-c++");
        let (_, _, version) = component_identity(
            "x",
            Some("pkg:rpm/redhat/libzip@1.6.1-1.module%2Bel8.3.0?arch=x86_64&epoch=1"),
        );
        assert_eq!(version.as_deref(), Some("1:1.6.1-1.module+el8.3.0"));
        assert_eq!(percent_decode("bad%zz%4"), "bad%zz%4");
    }

    /// The index line for CVE-2026-28417 on RHEL 8, trimmed: vim fixed on the main stream
    /// (and on an EUS stream, which is ignored), vim-minimal not affected, a modular php
    /// package left open, and an EUS-only fix that says nothing about the main stream.
    #[test]
    fn red_hat_records_per_release() {
        let line = r#"{"cve":"CVE-2026-28417","document":"CVE-2026-28417","modified":"2026-10-01",
          "severity":"Moderate",
          "platforms":{"BaseOS-8.10.0.Z.MAIN.EUS":"cpe:/o:redhat:enterprise_linux:8::baseos",
            "BaseOS-8.6.0.Z.AUS":"cpe:/o:redhat:rhel_aus:8.6::baseos",
            "red_hat_enterprise_linux_8":"cpe:/o:redhat:enterprise_linux:8"},
          "entries":[
            {"platform":"BaseOS-8.10.0.Z.MAIN.EUS","component":"vim","purl":"pkg:rpm/redhat/vim",
             "version":"2:8.0.1763-22.el8_10.1","status":"fixed","state":"fixed"},
            {"platform":"BaseOS-8.10.0.Z.MAIN.EUS","component":"vim","purl":"pkg:rpm/redhat/vim",
             "version":"2:8.0.1763-21.el8","status":"fixed","state":"fixed"},
            {"platform":"BaseOS-8.6.0.Z.AUS","component":"vim","purl":"pkg:rpm/redhat/vim",
             "version":"2:8.0.1763-99.el8_6","status":"fixed","state":"fixed"},
            {"platform":"BaseOS-8.6.0.Z.AUS","component":"gvim","purl":"pkg:rpm/redhat/gvim",
             "version":"2:8.0.1763-99.el8_6","status":"fixed","state":"fixed"},
            {"platform":"BaseOS-8.10.0.Z.MAIN.EUS","component":"vim-minimal","purl":"pkg:rpm/redhat/vim-minimal",
             "status":"known_not_affected","state":"not_affected"},
            {"platform":"red_hat_enterprise_linux_8","component":"vim","purl":"pkg:rpm/redhat/vim",
             "status":"known_affected","state":"affected"},
            {"platform":"red_hat_enterprise_linux_8","component":"php-cli","purl":"pkg:rpm/redhat/php-cli?rpmmod=php:7.3",
             "module":"php:7.3","status":"known_affected","state":"will_not_fix"}]}"#;
        let record: VexRecord = serde_json::from_str(line).unwrap();
        let out = red_hat_vex(&record);
        assert_eq!(out.len(), 1);
        let (eco, osv) = &out[0];
        assert_eq!(eco, "Red Hat:enterprise_linux:8::vex");
        assert_eq!(osv["id"], "CVE-2026-28417");
        assert_eq!(
            osv["references"][0]["url"],
            "https://access.redhat.com/security/cve/CVE-2026-28417"
        );
        let by_name: BTreeMap<&str, &Value> = osv["affected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| (a["package"]["name"].as_str().unwrap(), a))
            .collect();
        // The highest main-stream fix, and it outranks the release's open status.
        assert_eq!(
            by_name["vim"]["ranges"][0]["events"],
            serde_json::json!([{"introduced": "0"}, {"fixed": "2:8.0.1763-22.el8_10.1"}])
        );
        assert_eq!(by_name["vim-minimal"]["ranges"], serde_json::json!([]));
        assert_eq!(
            by_name["vim-minimal"]["ecosystem_specific"]["status"],
            "not affected"
        );
        assert_eq!(
            by_name["php-cli"]["ecosystem_specific"],
            serde_json::json!({"status": "will not fix", "module": "php:7.3"})
        );
        assert!(
            !by_name.contains_key("gvim"),
            "an AUS-only fix is not the release's"
        );
    }

    #[test]
    fn module_streams_from_rpmmod() {
        assert_eq!(
            rpm_module("pkg:rpm/redhat/php-cli?rpmmod=php:7.3").as_deref(),
            Some("php:7.3")
        );
        assert_eq!(
            rpm_module(
                "pkg:rpm/redhat/libzip@1.6.1-1.module%2Bel8.3.0?arch=x86_64&rpmmod=php:7.4:8080020230118140634:cc342424"
            )
            .as_deref(),
            Some("php:7.4")
        );
        assert_eq!(rpm_module("pkg:rpm/redhat/tar?arch=src"), None);
    }

    #[test]
    fn reads_a_directory_and_counts_non_csaf() {
        let dir = std::env::temp_dir().join(format!("fr-csaf-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("2024")).unwrap();
        std::fs::write(dir.join("2024/cve-2024-3651.json"), DOC).unwrap();
        std::fs::write(dir.join("other.json"), "{}").unwrap();
        let result = read_all(&dir).unwrap();
        assert_eq!(result.documents, 1);
        assert_eq!(result.not_csaf, 1);
        let path = index_path(&dir, "redhat");
        write_index(&path, &result.records).unwrap();
        assert_eq!(read_index(&path).unwrap(), result.records);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
