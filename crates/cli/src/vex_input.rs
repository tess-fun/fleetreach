//! VEX documents given as files (`scan --vex FILE`, `[settings.vex] files`): OpenVEX,
//! CycloneDX VEX and CSAF VEX, read into the statements image attestations become
//! ([`crate::oci_vex`]), so one rule decides both.
//!
//! Naming a file is the user's opt-in, so an unsigned file applies, unless keys were named
//! (`--vex-key`): then each file needs a `cosign sign-blob` signature by one of them beside it
//! (`FILE.sig`, or a bundle `FILE.sigstore.json` or `FILE.bundle`), and an unsigned one sets
//! nothing aside. A document that is none of the three formats, or whose `not_affected`
//! statement gives no justification and no impact statement, sets nothing aside either.
//!
//! Scope: a statement whose product names one of the fleet's repos (its VEX product id,
//! `urn:fleetreach:product:<id>`, or the SBOM's `repo:<id>`) applies to that repo only, and the
//! packages it names are that repo's. A statement that names no repo of the fleet applies to the
//! packages it names, in every repo; one that names another product (a vendor's platform) has
//! no package of ours in it and applies nowhere.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fleetreach_core::{RepoId, VulnFinding};
use serde_json::Value;

use crate::assemble::Suppression;
use crate::oci_vex::{self, Attested, FileProduct, Policy};

/// A product as a file names it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SaidProduct {
    /// The identifiers that may name a repo of the fleet: an `@id`, a purl, a bom-ref, a URI.
    names: Vec<String>,
    /// The package it is, when it is one.
    purl: Option<String>,
    /// The packages within it the statement is about.
    subcomponents: Vec<String>,
}

/// A statement as a file says it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Said {
    ids: Vec<String>,
    sets_aside: bool,
    /// `not_affected` (not `fixed`): it needs a justification or an impact statement.
    not_affected: bool,
    justification: Option<String>,
    impact: Option<String>,
    at: Option<String>,
    products: Vec<SaidProduct>,
}

/// One VEX file, read.
#[derive(Debug)]
pub(crate) struct VexFile {
    pub(crate) path: String,
    pub(crate) format: &'static str,
    /// The key file that verified its signature.
    pub(crate) signed_by: Option<String>,
    /// Why it sets nothing aside, when it does not.
    pub(crate) refused: Option<String>,
    said: Vec<Said>,
}

impl VexFile {
    pub(crate) fn statements(&self) -> usize {
        self.said.len()
    }

    fn refused(path: &str, format: &'static str, why: impl Into<String>) -> Self {
        VexFile {
            path: path.to_string(),
            format,
            signed_by: None,
            refused: Some(why.into()),
            said: Vec::new(),
        }
    }
}

/// Read one file. With keys in `policy`, it needs a signature by one of them.
pub(crate) fn load(path: &Path, policy: &Policy) -> VexFile {
    let shown = path.display().to_string();
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => return VexFile::refused(&shown, "unknown", format!("unreadable: {e}")),
    };
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(e) => return VexFile::refused(&shown, "unknown", format!("not JSON: {e}")),
    };
    let (format, said) = match parse(&value) {
        Ok(parsed) => parsed,
        Err((format, why)) => return VexFile::refused(&shown, format, why),
    };
    let mut signed_by = None;
    if policy.has_keys() {
        let signatures = signatures_beside(path);
        signed_by = policy
            .blob_signer(&bytes, signatures.iter().map(String::as_str))
            .map(str::to_string);
        if signed_by.is_none() {
            let why = if signatures.is_empty() {
                format!("no signature beside it ({shown}.sig, .sigstore.json or .bundle)")
            } else {
                "no named key signed it".to_string()
            };
            return VexFile::refused(&shown, format, why);
        }
    }
    VexFile {
        path: shown,
        format,
        signed_by,
        refused: None,
        said,
    }
}

/// The base64 signatures `cosign sign-blob` may have left beside `path`: a bare `.sig`, or a
/// bundle (v2's `base64Signature`, v3's `messageSignature.signature`).
fn signatures_beside(path: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let with = |suffix: &str| {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        std::path::PathBuf::from(name)
    };
    if let Ok(text) = std::fs::read_to_string(with(".sig")) {
        out.push(text.trim().to_string());
    }
    for suffix in [".sigstore.json", ".bundle"] {
        let Ok(text) = std::fs::read_to_string(with(suffix)) else {
            continue;
        };
        let Ok(bundle) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        for pointer in ["/messageSignature/signature", "/base64Signature"] {
            if let Some(sig) = bundle.pointer(pointer).and_then(Value::as_str) {
                out.push(sig.to_string());
            }
        }
    }
    out
}

type Parsed = Result<(&'static str, Vec<Said>), (&'static str, String)>;

/// The format and statements of a document.
fn parse(value: &Value) -> Parsed {
    let said = if value.get("statements").is_some()
        && str_at(value, "/@context").is_some_and(|c| c.contains("openvex"))
    {
        ("OpenVEX", openvex(value))
    } else if str_at(value, "/bomFormat") == Some("CycloneDX") {
        ("CycloneDX", Ok(cyclonedx(value)))
    } else if value.pointer("/document/category").is_some()
        && value.get("vulnerabilities").is_some()
    {
        ("CSAF", Ok(csaf(value)))
    } else {
        return Err((
            "unknown",
            "not an OpenVEX, CycloneDX or CSAF document".to_string(),
        ));
    };
    let (format, said) = said;
    let said = said.map_err(|why| (format, why))?;
    if let Some(s) = said
        .iter()
        .find(|s| s.not_affected && s.justification.is_none() && s.impact.is_none())
    {
        let id = s.ids.first().map_or("", String::as_str);
        return Err((
            format,
            format!(
                "its not_affected statement on {id} gives no justification or impact statement"
            ),
        ));
    }
    Ok((format, said))
}

fn str_at<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

fn strings(value: Option<&Value>) -> impl Iterator<Item = &str> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

/// A text that says something, trimmed.
fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
}

/// An OpenVEX component: a bare id, or `{"@id", "identifiers": {"purl"}, "subcomponents"}`.
fn openvex_component(c: &Value) -> SaidProduct {
    if let Some(id) = c.as_str() {
        return SaidProduct {
            names: vec![id.to_string()],
            purl: id.starts_with("pkg:").then(|| id.to_string()),
            subcomponents: Vec::new(),
        };
    }
    let id = str_at(c, "/@id");
    let purl = str_at(c, "/identifiers/purl").or(id.filter(|i| i.starts_with("pkg:")));
    SaidProduct {
        names: id.into_iter().chain(purl).map(str::to_string).collect(),
        purl: purl.map(str::to_string),
        subcomponents: (c
            .get("subcomponents")
            .and_then(Value::as_array)
            .into_iter()
            .flatten())
        .filter_map(|s| openvex_component(s).purl)
        .collect(),
    }
}

fn openvex(doc: &Value) -> Result<Vec<Said>, String> {
    let fallback = text(doc.get("timestamp"));
    let statements = doc
        .get("statements")
        .and_then(Value::as_array)
        .ok_or("its statements are not a list")?;
    let mut out = Vec::new();
    for s in statements {
        let vulnerability = s.get("vulnerability");
        let mut ids: Vec<String> = match vulnerability {
            Some(Value::String(name)) => vec![name.clone()],
            Some(v) => (str_at(v, "/name").into_iter().chain(str_at(v, "/@id")))
                .chain(strings(v.get("aliases")))
                .map(str::to_string)
                .collect(),
            None => Vec::new(),
        };
        ids.dedup();
        let status = str_at(s, "/status").unwrap_or_default();
        // Early OpenVEX put subcomponents beside the products; they belong to each of them.
        let shared: Vec<String> = (s.get("subcomponents").and_then(Value::as_array).into_iter())
            .flatten()
            .filter_map(|c| openvex_component(c).purl)
            .collect();
        let products = (s
            .get("products")
            .and_then(Value::as_array)
            .into_iter()
            .flatten())
        .map(|p| {
            let mut p = openvex_component(p);
            p.subcomponents.extend(shared.iter().cloned());
            p
        })
        .collect();
        out.push(Said {
            ids,
            sets_aside: matches!(status, "not_affected" | "fixed"),
            not_affected: status == "not_affected",
            justification: text(s.get("justification")),
            impact: text(s.get("impact_statement")),
            at: text(s.get("timestamp")).or_else(|| fallback.clone()),
            products,
        });
    }
    Ok(out)
}

/// The OpenVEX label a CycloneDX justification means, where one does.
fn openvex_justification(cyclonedx: &str) -> Option<&'static str> {
    match cyclonedx {
        "code_not_present" => Some("vulnerable_code_not_present"),
        "code_not_reachable" => Some("vulnerable_code_not_in_execute_path"),
        "requires_configuration" | "requires_dependency" | "requires_environment" => {
            Some("vulnerable_code_cannot_be_controlled_by_adversary")
        }
        "protected_by_compiler"
        | "protected_at_runtime"
        | "protected_at_perimeter"
        | "protected_by_mitigating_control" => Some("inline_mitigations_already_exist"),
        _ => None,
    }
}

fn cyclonedx_components(list: Option<&Value>, out: &mut BTreeMap<String, String>) {
    for c in list.and_then(Value::as_array).into_iter().flatten() {
        if let (Some(r), Some(p)) = (str_at(c, "/bom-ref"), str_at(c, "/purl")) {
            out.insert(r.to_string(), p.to_string());
        }
        cyclonedx_components(c.get("components"), out);
    }
}

fn cyclonedx(bom: &Value) -> Vec<Said> {
    let mut purls = BTreeMap::new();
    cyclonedx_components(bom.get("components"), &mut purls);
    let root = bom.pointer("/metadata/component");
    let root_names: Vec<String> = root
        .into_iter()
        .flat_map(|c| [str_at(c, "/bom-ref"), str_at(c, "/purl")])
        .flatten()
        .map(str::to_string)
        .collect();
    let mut out = Vec::new();
    for v in bom
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let ids: Vec<String> = str_at(v, "/id")
            .into_iter()
            .chain(
                (v.get("references")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten())
                .filter_map(|r| str_at(r, "/id")),
            )
            .map(str::to_string)
            .collect();
        let state = str_at(v, "/analysis/state").unwrap_or_default();
        // A BOM-Link names a component of another BOM by its bom-ref, after the `#`.
        let affected: Vec<String> = (v.get("affects").and_then(Value::as_array).into_iter())
            .flatten()
            .filter_map(|a| str_at(a, "/ref"))
            .filter_map(|r| {
                let r = if r.starts_with("urn:cdx:") {
                    r.rsplit_once('#')?.1
                } else {
                    r
                };
                purls
                    .get(r)
                    .cloned()
                    .or_else(|| r.starts_with("pkg:").then(|| r.to_string()))
            })
            .collect();
        let mut products: Vec<SaidProduct> = affected
            .iter()
            .map(|p| SaidProduct {
                names: Vec::new(),
                purl: Some(p.clone()),
                subcomponents: Vec::new(),
            })
            .collect();
        if !root_names.is_empty() {
            products.push(SaidProduct {
                names: root_names.clone(),
                purl: None,
                subcomponents: affected,
            });
        }
        let at = ["/analysis/lastUpdated", "/updated", "/published"]
            .iter()
            .find_map(|p| text(v.pointer(p)));
        out.push(Said {
            ids,
            sets_aside: matches!(
                state,
                "not_affected" | "false_positive" | "resolved" | "resolved_with_pedigree"
            ),
            not_affected: matches!(state, "not_affected" | "false_positive"),
            justification: str_at(v, "/analysis/justification")
                .and_then(openvex_justification)
                .map(str::to_string),
            impact: text(v.pointer("/analysis/detail")),
            at,
            products,
        });
    }
    out
}

/// What a CSAF product tree says of each product id: the names that may be a repo, its purl.
fn csaf_products(doc: &Value) -> BTreeMap<String, (Vec<String>, Option<String>)> {
    fn add(p: &Value, out: &mut BTreeMap<String, (Vec<String>, Option<String>)>) {
        let Some(id) = str_at(p, "/product_id") else {
            return;
        };
        let helper = p.get("product_identification_helper");
        let purl = helper.and_then(|h| str_at(h, "/purl")).map(str::to_string);
        let uris = (helper
            .and_then(|h| h.get("x_generic_uris"))
            .and_then(Value::as_array))
        .into_iter()
        .flatten()
        .filter_map(|u| str_at(u, "/uri"))
        .map(str::to_string);
        let names = purl.iter().cloned().chain(uris).collect();
        out.insert(id.to_string(), (names, purl));
    }
    fn walk(branch: &Value, out: &mut BTreeMap<String, (Vec<String>, Option<String>)>) {
        if let Some(p) = branch.get("product") {
            add(p, out);
        }
        for b in branch
            .get("branches")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            walk(b, out);
        }
    }
    let mut out = BTreeMap::new();
    let tree = doc.get("product_tree");
    for p in tree
        .and_then(|t| t.get("full_product_names"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        add(p, &mut out);
    }
    if let Some(tree) = tree {
        walk(tree, &mut out);
    }
    out
}

fn csaf(doc: &Value) -> Vec<Said> {
    let products = csaf_products(doc);
    // A relationship's product: (component, product it is in).
    let mut combined: BTreeMap<String, (String, String)> = BTreeMap::new();
    for r in doc
        .pointer("/product_tree/relationships")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let (Some(id), Some(c), Some(p)) = (
            str_at(r, "/full_product_name/product_id"),
            str_at(r, "/product_reference"),
            str_at(r, "/relates_to_product_reference"),
        ) {
            combined.insert(id.to_string(), (c.to_string(), p.to_string()));
        }
    }
    let product = |id: &str| -> SaidProduct {
        if let Some((component, within)) = combined.get(id) {
            let (names, _) = products.get(within).cloned().unwrap_or_default();
            let purl = products.get(component).and_then(|(_, p)| p.clone());
            return SaidProduct {
                names,
                purl: None,
                subcomponents: purl.into_iter().collect(),
            };
        }
        let (names, purl) = products.get(id).cloned().unwrap_or_default();
        SaidProduct {
            names,
            purl,
            subcomponents: Vec::new(),
        }
    };
    let at = text(doc.pointer("/document/tracking/current_release_date"));
    let mut out = Vec::new();
    for v in doc
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let ids: Vec<String> = str_at(v, "/cve")
            .into_iter()
            .chain(
                (v.get("ids").and_then(Value::as_array).into_iter().flatten())
                    .filter_map(|i| str_at(i, "/text")),
            )
            .map(str::to_string)
            .collect();
        // The label and the impact each product id has.
        let mut labels: BTreeMap<&str, &str> = BTreeMap::new();
        for f in v
            .get("flags")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(label) = str_at(f, "/label") {
                for id in strings(f.get("product_ids")) {
                    labels.insert(id, label);
                }
            }
        }
        let mut impacts: BTreeMap<&str, &str> = BTreeMap::new();
        for t in v
            .get("threats")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if str_at(t, "/category") != Some("impact") {
                continue;
            }
            if let Some(details) = str_at(t, "/details") {
                for id in strings(t.get("product_ids")) {
                    impacts.insert(id, details);
                }
            }
        }
        let Some(status) = v.get("product_status").and_then(Value::as_object) else {
            continue;
        };
        for (category, ids_in) in status {
            let not_affected = category == "known_not_affected";
            let sets_aside = not_affected || matches!(category.as_str(), "fixed" | "first_fixed");
            for pid in strings(Some(ids_in)) {
                out.push(Said {
                    ids: ids.clone(),
                    sets_aside,
                    not_affected,
                    justification: labels.get(pid).map(|l| (*l).to_string()),
                    impact: impacts.get(pid).map(|d| (*d).to_string()),
                    at: at.clone(),
                    products: vec![product(pid)],
                });
            }
        }
    }
    out
}

/// The names each repo's product goes by in a VEX document.
pub(crate) fn repo_names(
    product_ids: &BTreeMap<String, String>,
) -> BTreeMap<RepoId, BTreeSet<String>> {
    product_ids
        .iter()
        .map(|(repo, id)| {
            let names = [
                id.clone(),
                format!("urn:fleetreach:product:{repo}"),
                format!("repo:{repo}"),
            ];
            (RepoId(repo.clone()), names.into_iter().collect())
        })
        .collect()
}

/// The findings the files' statements set aside, and how many each file accounts for.
pub(crate) fn suppressions(
    files: &[VexFile],
    names: &BTreeMap<RepoId, BTreeSet<String>>,
    findings: &[VulnFinding],
) -> (Vec<Suppression>, BTreeMap<String, usize>) {
    let any_repo: BTreeSet<&str> = names.values().flatten().map(String::as_str).collect();
    let applied: Vec<&VexFile> = files.iter().filter(|f| f.refused.is_none()).collect();
    // Only statements on an advisory some finding has can decide anything; a supplier's
    // document may hold thousands of others.
    let found: BTreeSet<&str> = findings
        .iter()
        .flat_map(|v| std::iter::once(&v.advisory_id).chain(&v.aliases))
        .map(String::as_str)
        .collect();
    let relevant = |s: &&Said| s.ids.iter().any(|id| found.contains(id.as_str()));
    let statement = |s: &Said, products: &[FileProduct<'_>], file: &VexFile| {
        let reason = s
            .impact
            .clone()
            .unwrap_or_else(|| format!("VEX file {}", file.path));
        oci_vex::file_statement(
            s.ids.clone(),
            s.sets_aside,
            s.justification.clone(),
            reason,
            s.at.as_deref(),
            products,
            &file.path,
        )
    };
    // Statements that name no repo of the fleet: about packages, wherever they are.
    let fleet_wide: Vec<(String, Vec<oci_vex::Statement>)> = applied
        .iter()
        .map(|file| {
            let statements = file
                .said
                .iter()
                .filter(relevant)
                .filter(|s| {
                    !s.products
                        .iter()
                        .any(|p| p.names.iter().any(|n| any_repo.contains(n.as_str())))
                })
                .map(|s| {
                    let products: Vec<FileProduct<'_>> = s
                        .products
                        .iter()
                        .filter(|p| p.subcomponents.is_empty())
                        .filter_map(|p| p.purl.as_deref())
                        .map(|purl| FileProduct {
                            this_repo: false,
                            package: Some(purl),
                            subcomponents: Vec::new(),
                        })
                        .collect();
                    statement(s, &products, file)
                })
                .collect();
            (file.path.clone(), statements)
        })
        .collect();
    // Each repo's own statements, per file, found by the names the statement gives.
    let owner: BTreeMap<&str, &RepoId> = names
        .iter()
        .flat_map(|(repo, own)| own.iter().map(move |n| (n.as_str(), repo)))
        .collect();
    let mut own: BTreeMap<&RepoId, BTreeMap<&str, Vec<oci_vex::Statement>>> = BTreeMap::new();
    for file in &applied {
        for s in file.said.iter().filter(relevant) {
            let repos: BTreeSet<&RepoId> = (s.products.iter())
                .flat_map(|p| {
                    p.names
                        .iter()
                        .filter_map(|n| owner.get(n.as_str()).copied())
                })
                .collect();
            if repos.is_empty() {
                continue;
            }
            // The repo is the product; every package the statement names is one of its.
            let subcomponents: Vec<&str> = s
                .products
                .iter()
                .flat_map(|p| {
                    let package = p
                        .purl
                        .as_deref()
                        .filter(|_| !p.names.iter().any(|n| any_repo.contains(n.as_str())));
                    p.subcomponents.iter().map(String::as_str).chain(package)
                })
                .collect();
            let product = FileProduct {
                this_repo: true,
                package: None,
                subcomponents,
            };
            for repo in repos {
                (own.entry(repo)
                    .or_default()
                    .entry(file.path.as_str())
                    .or_default())
                .push(statement(s, std::slice::from_ref(&product), file));
            }
        }
    }
    let attested: Vec<Attested> = own
        .into_iter()
        .map(|(repo, files)| {
            let documents = files
                .into_iter()
                .map(|(path, statements)| (path.to_string(), statements))
                .collect();
            oci_vex::file_attested(repo.clone(), documents)
        })
        .collect();
    let wide = oci_vex::file_attested(RepoId(String::new()), fleet_wide);
    oci_vex::suppressions_with(&attested, Some(&wide), findings)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn formats_are_told_apart() {
        let openvex = json!({"@context": "https://openvex.dev/ns/v0.2.0", "statements": []});
        assert_eq!(parse(&openvex).unwrap().0, "OpenVEX");
        let cdx = json!({"bomFormat": "CycloneDX", "vulnerabilities": []});
        assert_eq!(parse(&cdx).unwrap().0, "CycloneDX");
        let csaf = json!({"document": {"category": "csaf_vex"}, "vulnerabilities": []});
        assert_eq!(parse(&csaf).unwrap().0, "CSAF");
        assert!(parse(&json!({"spdxVersion": "SPDX-2.3"})).is_err());
    }

    #[test]
    fn not_affected_without_a_reason_refuses_the_document() {
        let doc = json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [{"vulnerability": {"name": "CVE-1"}, "products": ["pkg:npm/a@1.0.0"],
                            "status": "not_affected"}]
        });
        let (_, why) = parse(&doc).unwrap_err();
        assert!(why.contains("CVE-1"), "{why}");
    }

    #[test]
    fn cyclonedx_reads_bom_links_and_the_root() {
        let bom = json!({
            "bomFormat": "CycloneDX",
            "metadata": {"component": {"bom-ref": "repo:svc", "name": "svc"}},
            "vulnerabilities": [{
                "id": "CVE-2020-26235",
                "references": [{"id": "RUSTSEC-2020-0071"}],
                "analysis": {"state": "not_affected", "justification": "code_not_reachable",
                             "detail": "UTC only"},
                "affects": [{"ref": "urn:cdx:abc/1#pkg:cargo/time@0.2.7"}]
            }]
        });
        let said = cyclonedx(&bom);
        assert_eq!(said[0].ids, ["CVE-2020-26235", "RUSTSEC-2020-0071"]);
        assert!(said[0].sets_aside);
        assert_eq!(
            said[0].justification.as_deref(),
            Some("vulnerable_code_not_in_execute_path")
        );
        assert_eq!(
            said[0].products[0].purl.as_deref(),
            Some("pkg:cargo/time@0.2.7")
        );
        assert_eq!(said[0].products[1].names, ["repo:svc"]);
        assert_eq!(said[0].products[1].subcomponents, ["pkg:cargo/time@0.2.7"]);
    }

    #[test]
    fn csaf_reads_relationships_and_bare_components() {
        let doc = json!({
            "document": {"category": "csaf_vex", "tracking": {"current_release_date": "2026-11-01T00:00:00Z"}},
            "product_tree": {
                "full_product_names": [
                    {"product_id": "P", "name": "svc",
                     "product_identification_helper": {"x_generic_uris": [{"namespace": "urn:fleetreach:product", "uri": "urn:fleetreach:product:svc"}]}},
                    {"product_id": "C", "name": "time 0.2.7",
                     "product_identification_helper": {"purl": "pkg:cargo/time@0.2.7"}}
                ],
                "relationships": [{"category": "default_component_of",
                    "full_product_name": {"product_id": "C:P", "name": "time in svc"},
                    "product_reference": "C", "relates_to_product_reference": "P"}]
            },
            "vulnerabilities": [{
                "cve": "CVE-2020-26235",
                "product_status": {"known_not_affected": ["C", "C:P"]},
                "flags": [{"label": "vulnerable_code_not_in_execute_path", "product_ids": ["C", "C:P"]}]
            }]
        });
        let said = csaf(&doc);
        assert_eq!(said.len(), 2);
        let bare = said.iter().find(|s| s.products[0].purl.is_some()).unwrap();
        assert_eq!(
            bare.products[0].purl.as_deref(),
            Some("pkg:cargo/time@0.2.7")
        );
        let within = said.iter().find(|s| s.products[0].purl.is_none()).unwrap();
        assert_eq!(within.products[0].names, ["urn:fleetreach:product:svc"]);
        assert_eq!(within.products[0].subcomponents, ["pkg:cargo/time@0.2.7"]);
        assert_eq!(within.at.as_deref(), Some("2026-11-01T00:00:00Z"));
    }

    fn npm_finding() -> VulnFinding {
        let occ = |repo: &str| {
            json!({"kind": "in_repo", "repo": repo, "package": "foo", "installed": "1.0.0",
                   "patched": [], "dependency_kind": "direct", "dependency_path": [repo, "foo"]})
        };
        serde_json::from_value(json!({
            "advisory_id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2024-1"], "ecosystem": "npm",
            "title": "", "severity": "high", "url": null,
            "occurrences": [occ("a"), occ("b")],
        }))
        .unwrap()
    }

    fn file(doc: Value) -> VexFile {
        let (format, said) = parse(&doc).unwrap();
        VexFile {
            path: "test.json".to_string(),
            format,
            signed_by: None,
            refused: None,
            said,
        }
    }

    fn set_aside_in(doc: Value) -> Vec<String> {
        let ids: BTreeMap<String, String> =
            [("a", "urn:fleetreach:product:a"), ("b", "pkg:npm/b@2.0.0")]
                .iter()
                .map(|(r, id)| (r.to_string(), id.to_string()))
                .collect();
        let (out, _) = suppressions(&[file(doc)], &repo_names(&ids), &[npm_finding()]);
        let mut repos: Vec<String> = out
            .into_iter()
            .filter_map(|s| s.repo.map(|r| r.0))
            .collect();
        repos.sort();
        repos
    }

    fn openvex(statements: Value) -> Value {
        json!({"@context": "https://openvex.dev/ns/v0.2.0", "statements": statements})
    }

    #[test]
    fn a_statement_naming_a_repo_applies_to_that_repo_only() {
        // As fleetreach writes it: the repo, then the package also as a product.
        let doc = openvex(json!([{
            "vulnerability": {"name": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2024-1"]},
            "products": [{"@id": "urn:fleetreach:product:a"}, {"@id": "pkg:npm/foo@1.0.0"}],
            "subcomponents": [{"@id": "pkg:npm/foo@1.0.0"}],
            "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"
        }]));
        assert_eq!(set_aside_in(doc), ["a"]);
        // A repo's product id may be its own purl.
        let doc = openvex(json!([{
            "vulnerability": "CVE-2024-1",
            "products": [{"@id": "pkg:npm/b@2.0.0", "subcomponents": [{"@id": "pkg:npm/foo@1.0.0"}]}],
            "status": "not_affected", "impact_statement": "never called"
        }]));
        assert_eq!(set_aside_in(doc), ["b"]);
    }

    #[test]
    fn a_statement_on_a_package_applies_wherever_it_is() {
        let doc = openvex(json!([{
            "vulnerability": "CVE-2024-1", "products": ["pkg:npm/foo@1.0.0"],
            "status": "not_affected", "justification": "vulnerable_code_not_present"
        }]));
        assert_eq!(set_aside_in(doc), ["a", "b"]);
        // Another version is another package.
        let doc = openvex(json!([{
            "vulnerability": "CVE-2024-1", "products": ["pkg:npm/foo@1.0.1"],
            "status": "not_affected", "justification": "vulnerable_code_not_present"
        }]));
        assert!(set_aside_in(doc).is_empty());
    }

    #[test]
    fn a_later_affected_statement_wins() {
        let doc = openvex(json!([
            {"vulnerability": "CVE-2024-1", "products": ["pkg:npm/foo@1.0.0"],
             "status": "not_affected", "justification": "vulnerable_code_not_present",
             "timestamp": "2026-01-01T00:00:00Z"},
            {"vulnerability": "CVE-2024-1",
             "products": [{"@id": "urn:fleetreach:product:a"}],
             "subcomponents": [{"@id": "pkg:npm/foo@1.0.0"}],
             "status": "affected", "action_statement": "upgrade",
             "timestamp": "2026-02-01T00:00:00Z"}
        ]));
        assert_eq!(set_aside_in(doc), ["b"]);
    }

    #[test]
    fn a_vendor_platform_holds_no_package_of_ours() {
        let doc = json!({
            "document": {"category": "csaf_vex"},
            "product_tree": {
                "full_product_names": [
                    {"product_id": "RHEL", "name": "Red Hat Enterprise Linux 9",
                     "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9"}},
                    {"product_id": "FOO", "name": "foo",
                     "product_identification_helper": {"purl": "pkg:npm/foo@1.0.0"}}
                ],
                "relationships": [{"category": "default_component_of",
                    "full_product_name": {"product_id": "FOO:RHEL", "name": "foo in RHEL"},
                    "product_reference": "FOO", "relates_to_product_reference": "RHEL"}]
            },
            "vulnerabilities": [{"cve": "CVE-2024-1",
                "product_status": {"known_not_affected": ["FOO:RHEL"]},
                "flags": [{"label": "vulnerable_code_not_present", "product_ids": ["FOO:RHEL"]}]}]
        });
        assert!(set_aside_in(doc).is_empty());
    }

    /// Signed as `cosign sign-blob` signs: ECDSA P-256 over the file's bytes, DER, base64.
    #[test]
    fn a_named_key_must_have_signed_the_file() {
        use base64::Engine;
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{DerSignature, SigningKey};

        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        // SubjectPublicKeyInfo for P-256: a fixed header, then the uncompressed point.
        let mut der = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        der.extend_from_slice(key.verifying_key().to_sec1_point(false).as_bytes());
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let lines: Vec<&str> = (0..b64.len())
            .step_by(64)
            .map(|i| &b64[i..b64.len().min(i + 64)])
            .collect();
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            lines.join("\n")
        );
        let pub_path = dir.path().join("cosign.pub");
        std::fs::write(&pub_path, pem).unwrap();
        let policy = Policy::load(&[pub_path], false).unwrap();
        let body = serde_json::to_vec(&openvex(json!([]))).unwrap();
        let sign = |bytes: &[u8]| {
            let sig: DerSignature = key.sign(bytes);
            base64::engine::general_purpose::STANDARD.encode(sig.as_bytes())
        };

        let signed = dir.path().join("signed.json");
        std::fs::write(&signed, &body).unwrap();
        std::fs::write(dir.path().join("signed.json.sig"), sign(&body)).unwrap();
        let read = load(&signed, &policy);
        assert_eq!(read.refused, None);
        assert!(read.signed_by.unwrap().ends_with("cosign.pub"));

        // cosign v3 writes a bundle instead.
        let bundled = dir.path().join("bundled.json");
        std::fs::write(&bundled, &body).unwrap();
        let bundle = json!({"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                            "messageSignature": {"signature": sign(&body)}});
        std::fs::write(
            dir.path().join("bundled.json.sigstore.json"),
            bundle.to_string(),
        )
        .unwrap();
        assert_eq!(load(&bundled, &policy).refused, None);

        // A signature of other bytes, or none, sets nothing aside.
        let changed = dir.path().join("changed.json");
        std::fs::write(&changed, [&body[..], b" "].concat()).unwrap();
        std::fs::write(dir.path().join("changed.json.sig"), sign(&body)).unwrap();
        assert_eq!(
            load(&changed, &policy).refused.as_deref(),
            Some("no named key signed it")
        );
        let bare = dir.path().join("bare.json");
        std::fs::write(&bare, &body).unwrap();
        assert!(load(&bare, &policy)
            .refused
            .unwrap()
            .starts_with("no signature beside it"));
        // Without keys, naming the file is enough.
        assert_eq!(load(&bare, &Policy::default()).refused, None);
    }
}
