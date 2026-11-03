//! OpenVEX attached to images in registries (`--vex-oci`): what a publisher says about its own
//! image, read from the attestations [`crate::registry::attachments`] finds.
//!
//! An attachment is outside the image's digest, so anyone who can push to the repository can
//! add one, to a digest pinned long ago. A document therefore sets findings aside only when it
//! is signed with a key the user named (`--vex-oci-key`, cosign's ECDSA P-256 keys) or the user
//! accepted unsigned documents (`--vex-oci-unsigned`). Others are listed and change nothing.
//! Keyless signatures are not checked: they count as unsigned.
//!
//! A document must name this image in its in-toto subject, so one copied from another image
//! is refused whatever signs it. Statements are read as OpenVEX says: for one vulnerability
//! and product the latest wins, so a later `affected` undoes an earlier `not_affected`. On a
//! tie the finding stays. An advisory covering several CVEs goes only when each is covered,
//! and a source package only when each of its binaries is.

use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine;
use fleetreach_core::semver::Version;
use fleetreach_core::{Ecosystem, Occurrence, RepoId, VulnFinding};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::assemble::Suppression;
use crate::config::VEX_JUSTIFICATIONS;
use crate::registry::Attachment;

const DSSE_IN_TOTO: &str = "application/vnd.in-toto+json";
const OPENVEX: &str = "https://openvex.dev/ns";
/// Purl qualifiers that describe a build this image holds, or nothing about the package.
const IGNORED_QUALIFIERS: [&str; 6] = [
    "arch",
    "distro",
    "epoch",
    "repository_url",
    "type",
    "upstream",
];

/// Which documents may set findings aside.
#[derive(Debug, Clone, Default)]
pub(crate) struct Policy {
    /// The keys to accept, each with the file it came from.
    keys: Vec<(String, VerifyingKey)>,
    unsigned: bool,
}

impl Policy {
    pub(crate) fn load(keys: &[PathBuf], unsigned: bool) -> Result<Self, String> {
        let keys = keys
            .iter()
            .map(|path| {
                let pem = std::fs::read_to_string(path)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                let key = VerifyingKey::from_public_key_pem(&pem).map_err(|e| {
                    format!("{}: not an ECDSA P-256 public key: {e}", path.display())
                })?;
                Ok((path.display().to_string(), key))
            })
            .collect::<Result<_, String>>()?;
        Ok(Policy { keys, unsigned })
    }

    /// The file of the key that signed `envelope`.
    fn signer(&self, envelope: &Envelope, payload: &[u8]) -> Option<&str> {
        let signed = encapsulate(&envelope.payload_type, payload);
        envelope.signatures.iter().find_map(|s| {
            let bytes = decode_base64(&s.sig)?;
            let signature = DerSignature::try_from(bytes.as_slice()).ok()?;
            self.keys
                .iter()
                .find(|(_, key)| key.verify(&signed, &signature).is_ok())
                .map(|(file, _)| file.as_str())
        })
    }
}

/// DSSE's pre-authentication encoding, what a signature covers.
fn encapsulate(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "DSSEv1 {} {payload_type} {} ",
        payload_type.len(),
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(payload);
    out
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(text)
        .or_else(|_| URL_SAFE.decode(text))
        .ok()
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "payloadType")]
    payload_type: String,
    payload: String,
    #[serde(default)]
    signatures: Vec<EnvelopeSignature>,
}

#[derive(Deserialize)]
struct EnvelopeSignature {
    sig: String,
}

#[derive(Deserialize)]
struct Bundle {
    #[serde(rename = "dsseEnvelope")]
    envelope: Envelope,
}

#[derive(Deserialize)]
struct InToto {
    #[serde(rename = "predicateType")]
    predicate_type: String,
    #[serde(default)]
    subject: Vec<Subject>,
    #[serde(default)]
    predicate: serde_json::Value,
}

#[derive(Deserialize)]
struct Subject {
    #[serde(default)]
    digest: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct RawDocument {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    statements: Vec<RawStatement>,
}

#[derive(Deserialize)]
struct RawStatement {
    vulnerability: RawVulnerability,
    #[serde(default)]
    products: Vec<RawComponent>,
    status: String,
    #[serde(default)]
    justification: Option<String>,
    #[serde(default)]
    impact_statement: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
}

/// Early OpenVEX wrote a bare string where 0.2.0 has an object.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawVulnerability {
    Name(String),
    Full {
        #[serde(default)]
        name: Option<String>,
        #[serde(rename = "@id", default)]
        id: Option<String>,
        #[serde(default)]
        aliases: Vec<String>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawComponent {
    Id(String),
    Full {
        #[serde(rename = "@id", default)]
        id: Option<String>,
        #[serde(default)]
        identifiers: BTreeMap<String, String>,
        #[serde(default)]
        hashes: BTreeMap<String, String>,
        #[serde(default)]
        subcomponents: Vec<RawComponent>,
    },
}

impl RawComponent {
    fn purl(&self) -> Option<Purl> {
        match self {
            RawComponent::Id(id) => Purl::parse(id),
            RawComponent::Full {
                id, identifiers, ..
            } => identifiers
                .get("purl")
                .or(id.as_ref())
                .and_then(|p| Purl::parse(p)),
        }
    }

    /// The sha256 digests this component names, as hex.
    fn hashes(&self) -> Vec<&str> {
        let (id, hashes) = match self {
            RawComponent::Id(id) => (Some(id), None),
            RawComponent::Full { id, hashes, .. } => (id.as_ref(), Some(hashes)),
        };
        let named = hashes
            .into_iter()
            .flatten()
            .filter(|(kind, _)| matches!(kind.as_str(), "sha-256" | "sha256"))
            .map(|(_, hex)| hex.as_str());
        id.and_then(|i| i.rsplit_once("sha256:").map(|(_, hex)| hex))
            .into_iter()
            .chain(named)
            .collect()
    }

    fn subcomponents(&self) -> &[RawComponent] {
        match self {
            RawComponent::Id(_) => &[],
            RawComponent::Full { subcomponents, .. } => subcomponents,
        }
    }
}

/// A package URL, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Purl {
    kind: String,
    path: String,
    version: Option<String>,
    qualifiers: Vec<String>,
}

impl Purl {
    fn parse(text: &str) -> Option<Purl> {
        let rest = text.strip_prefix("pkg:")?.trim_start_matches('/');
        // A subpath names part of a package, which no finding does.
        if rest.contains('#') {
            return None;
        }
        let (rest, qualifiers) = rest.split_once('?').unwrap_or((rest, ""));
        let (kind, rest) = rest.split_once('/')?;
        let (dir, last) = rest.rsplit_once('/').map_or(("", rest), |(d, l)| (d, l));
        let (name, version) = match last.rsplit_once('@') {
            Some((name, version)) if !name.is_empty() => (name, Some(unescape(version)?)),
            _ => (last, None),
        };
        let path = if dir.is_empty() {
            unescape(name)?
        } else {
            format!("{}/{}", unescape(dir)?, unescape(name)?)
        };
        let kind = kind.to_ascii_lowercase();
        let path = if kind == "pypi" {
            path.to_ascii_lowercase().replace('_', "-")
        } else {
            path
        };
        Some(Purl {
            kind,
            path,
            version,
            qualifiers: qualifiers
                .split('&')
                .filter(|q| !q.is_empty())
                .map(|q| q.split('=').next().unwrap_or(q).to_ascii_lowercase())
                .collect(),
        })
    }

    /// Whether this purl, from a statement, names `package` at `installed`. A version must be
    /// the installed one; none means every version.
    fn names(&self, package: &Purl, installed: &Version) -> bool {
        self.kind == package.kind
            && self.path == package.path
            && self
                .qualifiers
                .iter()
                .all(|q| IGNORED_QUALIFIERS.contains(&q.as_str()))
            && self
                .version
                .as_deref()
                .is_none_or(|v| fleetreach_os::scan::to_semver(v) == *installed)
    }
}

fn unescape(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// What one product of a statement covers.
#[derive(Debug)]
struct Product {
    /// This image; otherwise `package`.
    image: bool,
    package: Option<Purl>,
    /// Empty when the statement names no subcomponents.
    subcomponents: Vec<Option<Purl>>,
}

impl Product {
    fn covers(&self, unit: &[Purl], installed: &Version) -> bool {
        let names = |p: &Purl| unit.iter().any(|u| p.names(u, installed));
        if self.image {
            self.subcomponents.is_empty() || self.subcomponents.iter().flatten().any(names)
        } else {
            // Within a package, a subcomponent says nothing of the package itself.
            self.subcomponents.is_empty() && self.package.as_ref().is_some_and(names)
        }
    }
}

#[derive(Debug)]
struct Statement {
    ids: Vec<String>,
    products: Vec<Product>,
    sets_aside: bool,
    justification: Option<String>,
    reason: String,
    at: Option<OffsetDateTime>,
    /// The attachment it came from.
    document: String,
}

/// One OpenVEX document attached to an image.
#[derive(Debug)]
pub(crate) struct Document {
    pub(crate) digest: String,
    /// The key file that verified it.
    pub(crate) signed_by: Option<String>,
    /// Why it sets nothing aside, when it does not.
    pub(crate) refused: Option<String>,
    pub(crate) statements: usize,
    trusted: Vec<Statement>,
}

impl Document {
    fn refused(digest: &str, why: impl Into<String>) -> Self {
        Document {
            digest: digest.to_string(),
            signed_by: None,
            refused: Some(why.into()),
            statements: 0,
            trusted: Vec::new(),
        }
    }
}

/// The VEX attached to one image.
#[derive(Debug)]
pub(crate) struct Attested {
    pub(crate) repo: RepoId,
    pub(crate) documents: Vec<Document>,
}

fn parse_time(text: Option<&str>) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text?, &Rfc3339).ok()
}

/// The statement of `raw` as this image reads it, or why it cannot be used.
fn statement(
    raw: RawStatement,
    fallback: Option<OffsetDateTime>,
    digest: &str,
    subjects: &[&str],
    name: &str,
) -> Result<Statement, String> {
    let ids = match raw.vulnerability {
        RawVulnerability::Name(name) => vec![name],
        RawVulnerability::Full {
            name,
            id,
            mut aliases,
        } => {
            aliases.extend(name);
            aliases.extend(id);
            aliases
        }
    };
    let sets_aside = matches!(raw.status.as_str(), "not_affected" | "fixed");
    let justification = raw
        .justification
        .filter(|j| VEX_JUSTIFICATIONS.contains(&j.as_str()));
    let impact = raw.impact_statement.filter(|i| !i.trim().is_empty());
    if raw.status == "not_affected" && justification.is_none() && impact.is_none() {
        return Err("a not_affected statement gives no justification".to_string());
    }
    let is_image = |c: &RawComponent| {
        c.hashes().iter().any(|h| subjects.contains(h))
            || c.purl().is_some_and(|p| {
                p.kind == "oci"
                    && p.version.as_deref().map_or(p.path == name, |v| {
                        v.strip_prefix("sha256:")
                            .is_some_and(|h| subjects.contains(&h))
                    })
            })
    };
    let products = raw
        .products
        .iter()
        .map(|c| Product {
            image: is_image(c),
            package: c.purl().filter(|p| p.kind != "oci"),
            subcomponents: c.subcomponents().iter().map(RawComponent::purl).collect(),
        })
        .collect();
    Ok(Statement {
        ids,
        products,
        sets_aside,
        justification,
        reason: impact.unwrap_or_else(|| format!("VEX attestation {digest}")),
        at: parse_time(raw.timestamp.as_deref()).or(fallback),
        document: digest.to_string(),
    })
}

/// Read one attachment. `None` for a well-formed attestation of something else, such as an
/// SBOM. `subjects` are the image's digests.
fn decode(
    attachment: &Attachment,
    subjects: &[String],
    name: &str,
    policy: &Policy,
) -> Option<Document> {
    let digest = attachment.digest.as_str();
    let value: serde_json::Value = match serde_json::from_slice(&attachment.bytes) {
        Ok(value) => value,
        Err(e) => return Some(Document::refused(digest, format!("unreadable: {e}"))),
    };
    let envelope: Option<Envelope> = if value.get("dsseEnvelope").is_some() {
        serde_json::from_value::<Bundle>(value.clone())
            .ok()
            .map(|b| b.envelope)
    } else if value.get("payloadType").is_some() {
        serde_json::from_value(value.clone()).ok()
    } else {
        None
    };
    let (payload, signer) = match &envelope {
        Some(envelope) => {
            let Some(payload) = decode_base64(&envelope.payload) else {
                return Some(Document::refused(digest, "its payload is not base64"));
            };
            if envelope.payload_type != DSSE_IN_TOTO {
                return None;
            }
            let signer = policy.signer(envelope, &payload).map(str::to_string);
            (payload, signer)
        }
        None => (attachment.bytes.clone(), None),
    };
    let intoto: InToto = match serde_json::from_slice(&payload) {
        Ok(intoto) => intoto,
        Err(e) => return Some(Document::refused(digest, format!("unreadable: {e}"))),
    };
    let is_vex = intoto.predicate_type == OPENVEX
        || intoto
            .predicate_type
            .strip_prefix(OPENVEX)
            .is_some_and(|rest| rest.starts_with('/'));
    if !is_vex {
        return None;
    }
    let hexes: Vec<&str> = subjects
        .iter()
        .filter_map(|s| s.strip_prefix("sha256:"))
        .collect();
    let about_this_image = intoto
        .subject
        .iter()
        .filter_map(|s| s.digest.get("sha256"))
        .any(|h| hexes.contains(&h.as_str()));
    if !about_this_image {
        return Some(Document::refused(digest, "its subject is another image"));
    }
    let raw: RawDocument = match serde_json::from_value(intoto.predicate) {
        Ok(raw) => raw,
        Err(e) => return Some(Document::refused(digest, format!("unreadable: {e}"))),
    };
    let fallback = parse_time(raw.timestamp.as_deref());
    let count = raw.statements.len();
    let statements: Result<Vec<Statement>, String> = raw
        .statements
        .into_iter()
        .map(|s| statement(s, fallback, digest, &hexes, name))
        .collect();
    let statements = match statements {
        Ok(statements) => statements,
        Err(why) => return Some(Document::refused(digest, why)),
    };
    let refused = (signer.is_none() && !policy.unsigned).then(|| {
        if policy.keys.is_empty() {
            "no key was named, and --vex-oci-unsigned was not given".to_string()
        } else {
            "no named key signed it".to_string()
        }
    });
    Some(Document {
        digest: digest.to_string(),
        signed_by: signer,
        statements: count,
        trusted: if refused.is_none() {
            statements
        } else {
            Vec::new()
        },
        refused,
    })
}

/// Read what is attached to an image. `reference` is its name, `subjects` its digests.
pub(crate) fn read(
    repo: &RepoId,
    reference: &str,
    subjects: &[String],
    attachments: &[Attachment],
    policy: &Policy,
) -> Attested {
    let path = reference
        .split(['@'])
        .next()
        .unwrap_or(reference)
        .rsplit('/')
        .next()
        .unwrap_or(reference);
    let name = path.split(':').next().unwrap_or(path);
    Attested {
        repo: repo.clone(),
        documents: attachments
            .iter()
            .filter_map(|a| decode(a, subjects, name, policy))
            .collect(),
    }
}

/// The packages an occurrence stands for, each with the names that identify it: a source
/// package's binaries, or the one package. A binary also answers to its source's name, unless
/// one binary has that name: `pkg:apk/alpine/busybox` then means that binary alone, as it does
/// to Trivy, not `ssl_client` beside it.
fn units(ecosystem: Ecosystem, package: &str, path: &[String]) -> Vec<Vec<Purl>> {
    let purl = |name: &str| {
        let text = fleetreach_report::purl(ecosystem, name, "0", &Default::default());
        Purl::parse(&text).map(|mut p| {
            p.version = None;
            p
        })
    };
    if !matches!(ecosystem, Ecosystem::Deb | Ecosystem::Apk | Ecosystem::Rpm) {
        return vec![purl(package).into_iter().collect()];
    }
    let Some(namespace) = package.split('/').next() else {
        return Vec::new();
    };
    let binaries: Vec<&str> = path
        .get(2)
        .map_or("", String::as_str)
        .split(", ")
        .filter(|b| !b.is_empty())
        .collect();
    let source = package.split_once('/').map_or(package, |(_, name)| name);
    let by_source = !binaries.contains(&source);
    binaries
        .iter()
        .map(|binary| {
            purl(&format!("{namespace}/{binary}"))
                .into_iter()
                .chain(purl(package).filter(|_| by_source))
                .collect()
        })
        .collect()
}

/// The ids statements must answer for: each CVE of an advisory that covers several, or else
/// any of its names.
fn groups(v: &VulnFinding) -> Vec<Vec<&str>> {
    let cves: Vec<&str> = std::iter::once(&v.advisory_id)
        .chain(&v.aliases)
        .map(String::as_str)
        .filter(|id| id.starts_with("CVE-"))
        .collect();
    if cves.len() > 1 {
        // A statement on the advisory itself answers for all of them.
        cves.into_iter()
            .map(|cve| vec![cve, v.advisory_id.as_str()])
            .collect()
    } else {
        vec![std::iter::once(&v.advisory_id)
            .chain(&v.aliases)
            .map(String::as_str)
            .collect()]
    }
}

impl Attested {
    /// The statement deciding `ids` for `unit`, the latest; a tie goes to the finding.
    fn latest(&self, ids: &[&str], unit: &[Purl], installed: &Version) -> Option<&Statement> {
        self.documents
            .iter()
            .flat_map(|d| &d.trusted)
            .filter(|s| s.ids.iter().any(|id| ids.contains(&id.as_str())))
            .filter(|s| s.products.iter().any(|p| p.covers(unit, installed)))
            .max_by_key(|s| (s.at, !s.sets_aside))
    }

    /// The statement that sets this occurrence aside, when every part of it is covered.
    fn decide(
        &self,
        v: &VulnFinding,
        package: &str,
        path: &[String],
        installed: &Version,
    ) -> Option<&Statement> {
        let units = units(v.ecosystem, package, path);
        if units.is_empty() {
            return None;
        }
        let mut decided = None;
        for ids in groups(v) {
            for unit in &units {
                let statement = self.latest(&ids, unit, installed)?;
                if !statement.sets_aside {
                    return None;
                }
                decided = Some(statement);
            }
        }
        decided
    }
}

/// The findings the images' trusted statements set aside, as suppressions of those exact
/// occurrences, and how many each document accounts for.
pub(crate) fn suppressions(
    attested: &[Attested],
    findings: &[VulnFinding],
) -> (Vec<Suppression>, BTreeMap<String, usize>) {
    let by_repo: BTreeMap<&RepoId, &Attested> = attested.iter().map(|a| (&a.repo, a)).collect();
    let mut out = Vec::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for v in findings {
        for occurrence in &v.occurrences {
            let Occurrence::InRepo {
                repo,
                package,
                installed,
                dependency_path,
                ..
            } = occurrence
            else {
                continue;
            };
            let Some(image) = by_repo.get(repo) else {
                continue;
            };
            if let Some(s) = image.decide(v, package, dependency_path, installed) {
                *counts.entry(s.document.clone()).or_default() += 1;
                out.push(Suppression {
                    id: v.advisory_id.clone(),
                    repo: Some(repo.clone()),
                    package: Some((package.clone(), installed.clone())),
                    justification: s.justification.clone(),
                    reason: s.reason.clone(),
                    approved_by: Some(format!("VEX attestation {}", s.document)),
                });
            }
        }
    }
    (out, counts)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fleetreach_core::{DependencyKind, Severity};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use serde_json::json;

    const HEX: &str = "aaaa000000000000000000000000000000000000000000000000000000000000";

    fn subjects() -> Vec<String> {
        vec![format!("sha256:{HEX}")]
    }

    fn intoto(subject: &str, statements: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://openvex.dev/ns/v0.2.0",
            "subject": [{"name": "app", "digest": {"sha256": subject}}],
            "predicate": {"timestamp": "2026-01-01T00:00:00Z", "statements": statements},
        }))
        .unwrap()
    }

    fn envelope(payload: &[u8], key: Option<&SigningKey>) -> Vec<u8> {
        let signatures: Vec<serde_json::Value> = key
            .iter()
            .map(|k| {
                let s: Signature = k.sign(&encapsulate(DSSE_IN_TOTO, payload));
                json!({"sig": STANDARD.encode(s.to_der().as_bytes())})
            })
            .collect();
        serde_json::to_vec(&json!({
            "payloadType": DSSE_IN_TOTO,
            "payload": STANDARD.encode(payload),
            "signatures": signatures,
        }))
        .unwrap()
    }

    fn attachment(bytes: Vec<u8>) -> Attachment {
        Attachment {
            digest: "sha256:doc".to_string(),
            bytes,
        }
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn trusting(key: &SigningKey) -> Policy {
        Policy {
            keys: vec![("cosign.pub".to_string(), *key.verifying_key())],
            unsigned: false,
        }
    }

    fn unsigned() -> Policy {
        Policy {
            keys: Vec::new(),
            unsigned: true,
        }
    }

    fn finding(id: &str, aliases: &[&str], ecosystem: Ecosystem, occ: Occurrence) -> VulnFinding {
        serde_json::from_value(json!({
            "advisory_id": id,
            "aliases": aliases,
            "ecosystem": ecosystem,
            "title": "",
            "severity": Severity::High,
            "url": null,
            "occurrences": [occ],
        }))
        .unwrap()
    }

    fn occurrence(package: &str, version: &str, path: &[&str]) -> Occurrence {
        Occurrence::InRepo {
            repo: RepoId("app".into()),
            package: package.to_string(),
            installed: fleetreach_os::scan::to_semver(version),
            patched: Vec::new(),
            dependency_kind: DependencyKind::Direct,
            dependency_path: path.iter().map(ToString::to_string).collect(),
            active: None,
            source: Default::default(),
            scope: Default::default(),
            layer: None,
        }
    }

    fn deb() -> VulnFinding {
        finding(
            "DEBIAN-CVE-2024-1",
            &["CVE-2024-1"],
            Ecosystem::Deb,
            occurrence(
                "debian/openssl",
                "3.0.11-1~deb12u2",
                &["debian:12", "openssl 3.0.11-1~deb12u2", "libssl3, openssl"],
            ),
        )
    }

    /// A source package none of whose binaries shares its name.
    fn one_binary() -> VulnFinding {
        finding(
            "DEBIAN-CVE-2024-1",
            &["CVE-2024-1"],
            Ecosystem::Deb,
            occurrence(
                "debian/openssl",
                "3.0.11-1~deb12u2",
                &["debian:12", "openssl 3.0.11-1~deb12u2", "libssl3"],
            ),
        )
    }

    fn npm() -> VulnFinding {
        finding(
            "GHSA-aaaa",
            &["CVE-2024-2"],
            Ecosystem::Npm,
            occurrence("@scope/lib", "1.2.3", &[]),
        )
    }

    fn image_says(status: &str, sub: &str) -> serde_json::Value {
        json!({
            "vulnerability": {"name": "CVE-2024-1"},
            "products": [{"@id": format!("pkg:oci/app@sha256:{HEX}"),
                          "subcomponents": [{"@id": sub}]}],
            "status": status,
            "justification": "vulnerable_code_not_in_execute_path",
        })
    }

    fn outcome(bytes: Vec<u8>, policy: &Policy, v: &VulnFinding) -> usize {
        let image = read(
            &RepoId("app".into()),
            "ghcr.io/o/app:1",
            &subjects(),
            &[attachment(bytes)],
            policy,
        );
        suppressions(&[image], std::slice::from_ref(v)).0.len()
    }

    #[test]
    fn only_a_named_key_or_a_stated_choice_sets_a_finding_aside() {
        let good = signing_key(1);
        let other = signing_key(2);
        let payload = intoto(
            HEX,
            json!([image_says("not_affected", "pkg:deb/debian/openssl")]),
        );
        assert_eq!(
            outcome(
                envelope(&payload, Some(&good)),
                &trusting(&good),
                &one_binary()
            ),
            1
        );
        // Signed by a key nobody named, unsigned, or tampered with: nothing changes.
        assert_eq!(
            outcome(
                envelope(&payload, Some(&other)),
                &trusting(&good),
                &one_binary()
            ),
            0
        );
        assert_eq!(
            outcome(envelope(&payload, None), &trusting(&good), &one_binary()),
            0
        );
        let mut tampered: serde_json::Value =
            serde_json::from_slice(&envelope(&payload, Some(&good))).unwrap();
        let swapped = intoto(HEX, json!([image_says("fixed", "pkg:deb/debian/openssl")]));
        tampered["payload"] = json!(STANDARD.encode(swapped));
        assert_eq!(
            outcome(
                serde_json::to_vec(&tampered).unwrap(),
                &trusting(&good),
                &one_binary()
            ),
            0
        );
        assert_eq!(
            outcome(payload.clone(), &Policy::default(), &one_binary()),
            0
        );
        // The user can choose Trivy's behaviour.
        assert_eq!(outcome(payload, &unsigned(), &one_binary()), 1);
    }

    #[test]
    fn a_document_about_another_image_is_refused_even_when_signed() {
        let key = signing_key(1);
        let other = "b".repeat(64);
        let payload = intoto(
            &other,
            json!([image_says("not_affected", "pkg:deb/debian/openssl")]),
        );
        let bytes = envelope(&payload, Some(&key));
        assert_eq!(outcome(bytes.clone(), &trusting(&key), &one_binary()), 0);
        assert_eq!(outcome(bytes, &unsigned(), &one_binary()), 0);
    }

    #[test]
    fn a_sigstore_bundle_is_read_and_other_attestations_are_skipped() {
        let key = signing_key(1);
        let payload = intoto(
            HEX,
            json!([image_says("not_affected", "pkg:deb/debian/openssl")]),
        );
        let inner: serde_json::Value =
            serde_json::from_slice(&envelope(&payload, Some(&key))).unwrap();
        let bundle = serde_json::to_vec(&json!({"dsseEnvelope": inner})).unwrap();
        assert_eq!(outcome(bundle, &trusting(&key), &one_binary()), 1);

        let sbom = serde_json::to_vec(&json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://spdx.dev/Document",
            "subject": [],
            "predicate": {},
        }))
        .unwrap();
        let image = read(
            &RepoId("app".into()),
            "app",
            &subjects(),
            &[attachment(sbom)],
            &unsigned(),
        );
        assert!(image.documents.is_empty());
        // What cannot be read is listed, never an error, and sets nothing aside.
        let image = read(
            &RepoId("app".into()),
            "app",
            &subjects(),
            &[attachment(b"\xff not json".to_vec())],
            &unsigned(),
        );
        assert!(image.documents[0].refused.is_some());
    }

    #[test]
    fn products_match_the_image_or_the_package() {
        let says = |statement| outcome(intoto(HEX, json!([statement])), &unsigned(), &one_binary());
        let vuln = json!({"name": "CVE-2024-1"});
        let status = |products: serde_json::Value| json!({"vulnerability": vuln, "products": products, "status": "fixed"});
        // The image with no subcomponents: everything in it.
        assert_eq!(
            says(status(
                json!([{"@id": format!("pkg:oci/app@sha256:{HEX}")}])
            )),
            1
        );
        assert_eq!(says(status(json!([{"@id": "pkg:oci/app"}]))), 1);
        assert_eq!(says(status(json!([{"hashes": {"sha-256": HEX}}]))), 1);
        // Another image, by digest or by name.
        let wrong = format!("pkg:oci/app@sha256:{}", "b".repeat(64));
        assert_eq!(says(status(json!([{"@id": wrong}]))), 0);
        assert_eq!(says(status(json!([{"@id": "pkg:oci/other"}]))), 0);
        // The package itself, as Trivy reads it, at the installed version or any: each binary.
        let package = |purl: &str| status(json!([{"@id": purl}]));
        assert_eq!(says(package("pkg:deb/debian/openssl")), 1);
        assert_eq!(says(package("pkg:deb/debian/libssl3")), 1);
        let exact = "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12.4";
        assert_eq!(says(status(json!([{"identifiers": {"purl": exact}}]))), 1);
        assert_eq!(
            says(status(json!([{"@id": "pkg:deb/debian/openssl@3.0.12-1"}]))),
            0
        );
        assert_eq!(says(status(json!([{"@id": "pkg:deb/ubuntu/openssl"}]))), 0);
        assert_eq!(
            says(status(json!([{"@id": "pkg:deb/debian/openssl?foo=bar"}]))),
            0
        );
        // A subcomponent of some package says nothing about this one.
        let inside = json!([{"@id": "pkg:deb/debian/openssl",
                             "subcomponents": [{"@id": "pkg:deb/debian/libssl3"}]}]);
        assert_eq!(says(status(inside)), 0);
        // A subcomponent that cannot be read does not widen to the whole image.
        let unread = json!([{"@id": "pkg:oci/app", "subcomponents": [{"@id": "nonsense"}]}]);
        assert_eq!(says(status(unread)), 0);
        // No product at all.
        assert_eq!(says(status(json!([]))), 0);
    }

    #[test]
    fn a_source_package_goes_only_when_every_binary_is_covered() {
        let says = |list| outcome(intoto(HEX, list), &unsigned(), &deb());
        let libssl = image_says("not_affected", "pkg:deb/debian/libssl3");
        // `openssl` is a binary too, so it means that binary, not the source.
        let openssl = image_says("not_affected", "pkg:deb/debian/openssl");
        assert_eq!(says(json!([libssl.clone()])), 0);
        assert_eq!(says(json!([openssl.clone()])), 0);
        assert_eq!(says(json!([libssl, openssl])), 1);
    }

    #[test]
    fn an_advisory_of_several_cves_goes_only_when_each_is_covered() {
        let mut v = one_binary();
        v.advisory_id = "DSA-1".to_string();
        v.aliases = vec!["CVE-2024-1".to_string(), "CVE-2024-9".to_string()];
        let first = image_says("fixed", "pkg:deb/debian/openssl");
        assert_eq!(
            outcome(intoto(HEX, json!([first.clone()])), &unsigned(), &v),
            0
        );
        let mut second = first.clone();
        second["vulnerability"]["name"] = json!("CVE-2024-9");
        assert_eq!(
            outcome(intoto(HEX, json!([first, second])), &unsigned(), &v),
            1
        );
        let mut whole = image_says("fixed", "pkg:deb/debian/openssl");
        whole["vulnerability"]["name"] = json!("DSA-1");
        assert_eq!(outcome(intoto(HEX, json!([whole])), &unsigned(), &v), 1);
    }

    #[test]
    fn the_latest_statement_wins_and_a_tie_keeps_the_finding() {
        let pkg = "pkg:deb/debian/openssl";
        let at = |status: &str, time: &str| {
            let mut s = image_says(status, pkg);
            s["timestamp"] = json!(time);
            s
        };
        let says = |list| outcome(intoto(HEX, list), &unsigned(), &one_binary());
        let (early, late) = ("2026-02-01T00:00:00Z", "2026-03-01T00:00:00Z");
        assert_eq!(
            says(json!([at("not_affected", early), at("affected", late)])),
            0
        );
        assert_eq!(
            says(json!([at("affected", late), at("not_affected", early)])),
            0
        );
        assert_eq!(
            says(json!([at("affected", early), at("not_affected", late)])),
            1
        );
        assert_eq!(says(json!([at("affected", late), at("fixed", late)])), 0);
        assert_eq!(says(json!([at("under_investigation", late)])), 0);
    }

    #[test]
    fn not_affected_needs_a_reason_and_aliases_and_language_packages_match() {
        let bare = json!({"vulnerability": {"name": "CVE-2024-1"},
                          "products": [{"@id": "pkg:oci/app"}], "status": "not_affected"});
        assert_eq!(
            outcome(
                intoto(HEX, json!([bare.clone()])),
                &unsigned(),
                &one_binary()
            ),
            0
        );
        let mut made_up = bare.clone();
        made_up["justification"] = json!("trust_me");
        assert_eq!(
            outcome(intoto(HEX, json!([made_up])), &unsigned(), &one_binary()),
            0
        );
        let mut explained = bare;
        explained["impact_statement"] = json!("not built");
        assert_eq!(
            outcome(intoto(HEX, json!([explained])), &unsigned(), &one_binary()),
            1
        );

        let by_alias = json!({"vulnerability": {"name": "X-1", "aliases": ["CVE-2024-2"]},
                              "products": [{"@id": "pkg:npm/%40scope/lib@1.2.3"}],
                              "status": "fixed"});
        assert_eq!(
            outcome(intoto(HEX, json!([by_alias])), &unsigned(), &npm()),
            1
        );
        let older = json!({"vulnerability": "CVE-2024-2",
                           "products": ["pkg:npm/%40scope/lib"], "status": "fixed"});
        assert_eq!(outcome(intoto(HEX, json!([older])), &unsigned(), &npm()), 1);
    }

    #[test]
    fn hostile_purls_are_refused_not_panicked_on() {
        for text in [
            "",
            "pkg:",
            "pkg:a",
            "pkg:/",
            "pkg:a/%",
            "pkg:a/%zz",
            "pkg:a/é%",
            "pkg:a/b#c",
        ] {
            assert_eq!(Purl::parse(text), None, "{text}");
        }
        let p = Purl::parse("pkg:npm/@scope/x@1?a=b").unwrap();
        assert_eq!(
            (p.path.as_str(), p.version.as_deref()),
            ("@scope/x", Some("1"))
        );
    }
}
