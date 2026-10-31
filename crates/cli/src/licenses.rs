//! License inventory and policy (spec 11, phases 1 and 2).
//!
//! Every package in a repo's inventory gets a license from the best local source, recorded
//! with where it came from. Nothing is fetched from the network:
//!
//! | Ecosystem | Sources, in order |
//! |-----------|-------------------|
//! | npm | the `license` field of `package-lock.json`, else `node_modules/<pkg>/package.json` |
//! | Packagist | `composer.lock` (`license`, a list meaning any one of them) |
//! | Cargo | the crate's `Cargo.toml` in the local registry cache (`$CARGO_HOME/registry/src`) |
//! | PyPI | `License-Expression` (PEP 639), else `License`, else license classifiers, from a repo virtualenv's `.dist-info/METADATA` |
//! | NuGet | the `.nuspec` in the global packages folder (`$NUGET_PACKAGES` or `~/.nuget/packages`) |
//!
//! A license string is normalized to an SPDX expression with the `spdx` crate in its lax mode
//! (`MIT/Apache-2.0`, `Apache 2.0` are accepted); anything it cannot parse stays as written
//! and counts as unknown for policy. Each license id gets a category from a bundled table
//! modelled on Google's license classification: forbidden, restricted, reciprocal, notice,
//! unencumbered, or unknown.
//!
//! A `[settings.licenses]` policy turns the inventory into violations. `allow` and `deny`
//! name SPDX ids; categories map to `allow`, `warn` or `deny` (forbidden is denied and
//! restricted warned by default); a package with no known license follows `unknown`, which
//! defaults to `deny` (fail closed). An expression passes when it can be satisfied: `A OR B`
//! needs either, `A AND B` both. `scope = "runtime"` leaves dev-only packages out, and an
//! `[[settings.licenses.exception]]` allows named licenses for one package, with a reason.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fleetreach_core::inventory::{Package, RepoInventory};
use fleetreach_core::Ecosystem;
use serde::Serialize;
use spdx::{Expression, LicenseItem, LicenseReq, ParseMode};

// ---- categories ----

/// Google-style license categories, from most to least restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Forbidden,
    Restricted,
    Reciprocal,
    Notice,
    Unencumbered,
    Unknown,
}

impl Category {
    pub fn parse(s: &str) -> Option<Category> {
        Some(match s {
            "forbidden" => Category::Forbidden,
            "restricted" => Category::Restricted,
            "reciprocal" => Category::Reciprocal,
            "notice" => Category::Notice,
            "unencumbered" => Category::Unencumbered,
            "unknown" => Category::Unknown,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            Category::Forbidden => "forbidden",
            Category::Restricted => "restricted",
            Category::Reciprocal => "reciprocal",
            Category::Notice => "notice",
            Category::Unencumbered => "unencumbered",
            Category::Unknown => "unknown",
        }
    }
}

/// The category of one SPDX license id. Ids are matched on their family prefix, so every
/// GPL version and suffix (`-only`, `-or-later`) lands in the same place.
pub fn category(id: &str) -> Category {
    const FORBIDDEN: &[&str] = &[
        "AGPL-",
        "SSPL-",
        "CPAL-",
        "CC-BY-NC",
        "Commons-Clause",
        "WTFPL",
        "BUSL-",
        "Elastic-2.0",
    ];
    const RESTRICTED: &[&str] = &[
        "GPL-",
        "LGPL-",
        "CC-BY-SA",
        "CC-BY-ND",
        "OSL-",
        "EUPL-",
        "QPL-",
        "Sleepycat",
        "SISSL",
        "NPL-",
        "BCL",
        "CECILL-1",
        "CECILL-2",
    ];
    const RECIPROCAL: &[&str] = &[
        "MPL-", "EPL-", "CDDL-", "APSL-", "CPL-", "IPL-", "Ruby", "MS-RL", "ErlPL-", "CECILL-C",
        "LPPL-",
    ];
    const UNENCUMBERED: &[&str] = &["CC0-", "Unlicense", "0BSD", "MIT-0", "WTFNMFPL"];
    const NOTICE: &[&str] = &[
        "MIT",
        "Apache-",
        "BSD-",
        "ISC",
        "Zlib",
        "BSL-1.0",
        "Python-",
        "PSF-",
        "Unicode-",
        "OpenSSL",
        "X11",
        "BlueOak-",
        "PostgreSQL",
        "NCSA",
        "CC-BY-",
        "MS-PL",
        "Artistic-",
        "W3C",
        "AFL-",
        "Beerware",
        "bzip2-",
        "curl",
        "FTL",
        "HPND",
        "ICU",
        "IJG",
        "JSON",
        "libpng",
        "Libpng",
        "NTP",
        "OFL-",
        "PHP-",
        "UPL-",
        "Vim",
        "Zend-",
        "ZPL-",
        "BSD-Source",
        "Info-ZIP",
        "PIL",
        "TCL",
        "Xnet",
        "MulanPSL-",
        "ImageMagick",
        "CNRI-",
        "Spencer-",
        "CDLA-Permissive-",
        "Unicode-TOU",
        "Apache-1.1",
    ];
    let has = |list: &[&str]| list.iter().any(|p| id.starts_with(p));
    // Order matters: `LGPL-` before `GPL-` is not needed (prefix), but `CC-BY-NC`, `-SA`
    // and `-ND` must win over plain `CC-BY-`, and `MIT-0` over `MIT`.
    if has(FORBIDDEN) {
        Category::Forbidden
    } else if has(RESTRICTED) {
        Category::Restricted
    } else if has(RECIPROCAL) {
        Category::Reciprocal
    } else if has(UNENCUMBERED) {
        Category::Unencumbered
    } else if has(NOTICE) {
        Category::Notice
    } else {
        Category::Unknown
    }
}

// ---- normalization ----

/// A license as found and as understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct License {
    /// The string from the source, verbatim.
    pub raw: String,
    /// The canonical SPDX expression, when it parses.
    pub expression: Option<String>,
}

/// Normalize a license string. Several strings (a list, or legacy `licenses[]`) mean any
/// one of them, so they join with `OR`.
pub fn normalize(parts: &[String]) -> Option<License> {
    let parts: Vec<&str> = parts
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() {
        return None;
    }
    let raw = parts.join(" OR ");
    let joined = if parts.len() > 1 {
        parts
            .iter()
            .map(|p| {
                if p.contains(' ') {
                    format!("({p})")
                } else {
                    (*p).to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(" OR ")
    } else {
        raw.clone()
    };
    // Lax parsing guesses a version for a bare family name; which BSD or GPL is meant is not
    // said, so those stay unknown rather than become a specific license.
    let ambiguous = parts.iter().any(|p| {
        matches!(
            p.trim_matches(|c| c == '(' || c == ')')
                .to_ascii_uppercase()
                .as_str(),
            "BSD" | "BSD LICENSE" | "GPL" | "LGPL" | "AGPL" | "GNU GPL" | "GNU LGPL"
        )
    });
    let expression = (!ambiguous)
        .then(|| Expression::parse_mode(&joined, ParseMode::LAX).ok())
        .flatten()
        .map(|_| {
            let canonical = Expression::canonicalize(&joined)
                .ok()
                .flatten()
                .unwrap_or_else(|| joined.clone());
            strip_outer_parens(canonical.trim()).to_string()
        });
    Some(License { raw, expression })
}

/// `(A OR B)` -> `A OR B` when the parentheses wrap the whole expression.
fn strip_outer_parens(s: &str) -> &str {
    let Some(inner) = s.strip_prefix('(').and_then(|r| r.strip_suffix(')')) else {
        return s;
    };
    let mut depth = 0i32;
    for c in inner.chars() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return s; // `(A) OR (B)`: the first ')' closes the opening '('
                }
            }
            _ => {}
        }
    }
    if depth == 0 {
        inner.trim()
    } else {
        s
    }
}

/// Every license id an expression names (`LicenseRef-*` as written).
fn ids(expression: &str) -> Vec<String> {
    Expression::parse_mode(expression, ParseMode::LAX)
        .map(|e| e.requirements().map(|r| req_id(&r.req)).collect())
        .unwrap_or_default()
}

fn req_id(req: &LicenseReq) -> String {
    match &req.license {
        LicenseItem::Spdx { id, .. } => id.name.to_string(),
        LicenseItem::Other(r) => r.to_string(),
    }
}

// ---- policy ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Warn,
    Deny,
}

impl Verdict {
    pub fn parse(s: &str) -> Option<Verdict> {
        Some(match s {
            "allow" => Verdict::Allow,
            "warn" => Verdict::Warn,
            "deny" => Verdict::Deny,
            _ => return None,
        })
    }
}

/// A validated `[settings.licenses]` block.
#[derive(Debug, Clone)]
pub struct Policy {
    pub allow: BTreeSet<String>,
    pub deny: BTreeSet<String>,
    pub categories: BTreeMap<Category, Verdict>,
    pub unknown: Verdict,
    pub runtime_only: bool,
    /// Package name -> license ids allowed for it, with the reason.
    pub exceptions: BTreeMap<String, (BTreeSet<String>, String)>,
}

impl Policy {
    /// The defaults a bare `[settings.licenses]` gets: forbidden denied, restricted warned,
    /// unknown denied.
    pub fn default_categories() -> BTreeMap<Category, Verdict> {
        BTreeMap::from([
            (Category::Forbidden, Verdict::Deny),
            (Category::Restricted, Verdict::Warn),
        ])
    }

    /// The verdict for one license id, for `package`.
    fn id_verdict(&self, id: &str, package: &str) -> Verdict {
        if self
            .exceptions
            .get(package)
            .is_some_and(|(ids, _)| ids.contains(id))
        {
            return Verdict::Allow;
        }
        if self.deny.contains(id) {
            return Verdict::Deny;
        }
        if self.allow.contains(id) {
            return Verdict::Allow;
        }
        let from_category = self
            .categories
            .get(&category(id))
            .copied()
            .unwrap_or(Verdict::Allow);
        // With an allow list, anything not on it is at least a warning.
        if self.allow.is_empty() {
            from_category
        } else {
            from_category.max(Verdict::Warn)
        }
    }

    /// The verdict for a package's license: the best way to satisfy its expression.
    pub fn evaluate(&self, package: &str, license: Option<&License>) -> (Verdict, String) {
        let Some(expr) = license.and_then(|l| l.expression.as_deref()) else {
            let why = match license {
                Some(l) => format!("license `{}` is not an SPDX expression", l.raw),
                None => "no license found".to_string(),
            };
            return (self.unknown, why);
        };
        let Ok(parsed) = Expression::parse_mode(expr, ParseMode::LAX) else {
            return (self.unknown, format!("license `{expr}` does not parse"));
        };
        let at_most =
            |limit: Verdict| parsed.evaluate(|req| self.id_verdict(&req_id(req), package) <= limit);
        if at_most(Verdict::Allow) {
            return (Verdict::Allow, String::new());
        }
        let culprits: Vec<String> = parsed
            .requirements()
            .map(|r| req_id(&r.req))
            .filter(|id| self.id_verdict(id, package) != Verdict::Allow)
            .map(|id| format!("{id} ({})", category(&id).label()))
            .collect();
        let culprits = culprits.join(", ");
        if at_most(Verdict::Warn) {
            (Verdict::Warn, format!("{expr}: {culprits}"))
        } else {
            (Verdict::Deny, format!("{expr}: {culprits}"))
        }
    }
}

// ---- lookup ----

/// The license of every package in `inv` that a local source knows, keyed by the package's
/// position in `inv.sources[i].packages[j]`, with the source name.
pub fn annotate(inv: &mut RepoInventory, repo_root: &Path) {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| home().map(|h| h.join(".cargo")));
    let nuget_root = std::env::var_os("NUGET_PACKAGES")
        .map(PathBuf::from)
        .or_else(|| home().map(|h| h.join(".nuget").join("packages")));
    let mut cargo_index: Option<Vec<PathBuf>> = None;
    for source in &mut inv.sources {
        let dir = source_dir(repo_root, &source.source);
        match source.ecosystem {
            Ecosystem::Npm => {
                let lock = npm_lock_licenses(&dir);
                for p in &mut source.packages {
                    let found = lock
                        .get(&(p.name.clone(), p.version.clone()))
                        .cloned()
                        .map(|l| (l, "package-lock.json"))
                        .or_else(|| {
                            node_modules_license(&dir, &p.name, &p.version)
                                .map(|l| (l, "node_modules"))
                        });
                    set(p, found);
                }
            }
            Ecosystem::Packagist => {
                let lock = composer_licenses(&dir);
                for p in &mut source.packages {
                    let found = lock.get(&p.name).cloned().map(|l| (l, "composer.lock"));
                    set(p, found);
                }
            }
            Ecosystem::Cargo => {
                let roots =
                    cargo_index.get_or_insert_with(|| cargo_registry_roots(cargo_home.as_deref()));
                for p in &mut source.packages {
                    let found = roots
                        .iter()
                        .find_map(|r| cargo_license(&r.join(format!("{}-{}", p.name, p.version))));
                    set(p, found.map(|l| (l, "cargo registry")));
                }
            }
            Ecosystem::Pypi => {
                let dists = python_dists(repo_root, &dir);
                for p in &mut source.packages {
                    let key = (pep503(&p.name), p.version.clone());
                    set(p, dists.get(&key).cloned().map(|l| (l, "site-packages")));
                }
            }
            Ecosystem::NuGet => {
                for p in &mut source.packages {
                    let found = nuget_root.as_deref().and_then(|root| {
                        nuspec_license(
                            &root
                                .join(p.name.to_lowercase())
                                .join(p.version.to_lowercase()),
                        )
                    });
                    set(p, found.map(|l| (l, "nuget packages")));
                }
            }
            _ => {}
        }
    }
}

fn set(p: &mut Package, found: Option<(License, &'static str)>) {
    if let Some((license, source)) = found {
        p.license = Some(license.expression.unwrap_or(license.raw));
        p.license_source = Some(source.to_string());
    }
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// The directory of a source: the parent of its first file (`sub/package-lock.json, ...`).
fn source_dir(repo_root: &Path, source: &str) -> PathBuf {
    let first = source.split(", ").next().unwrap_or(source);
    let path = repo_root.join(first);
    if path.is_dir() {
        return path;
    }
    path.parent()
        .map_or_else(|| repo_root.to_path_buf(), Path::to_path_buf)
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// `license` (a string or `{ type }`), else legacy `licenses: [{ type }]`.
fn json_license(v: &serde_json::Value) -> Option<License> {
    let mut parts = Vec::new();
    match v.get("license") {
        Some(serde_json::Value::String(s)) => parts.push(s.clone()),
        Some(serde_json::Value::Object(o)) => {
            if let Some(s) = o.get("type").and_then(|t| t.as_str()) {
                parts.push(s.to_string());
            }
        }
        _ => {}
    }
    if parts.is_empty() {
        for l in v
            .get("licenses")
            .and_then(|l| l.as_array())
            .into_iter()
            .flatten()
        {
            if let Some(s) = l
                .as_str()
                .or_else(|| l.get("type").and_then(|t| t.as_str()))
            {
                parts.push(s.to_string());
            }
        }
    }
    normalize(&parts)
}

/// `(name, version) -> license` from a `package-lock.json` v2/v3 `packages` map.
fn npm_lock_licenses(dir: &Path) -> BTreeMap<(String, String), License> {
    let mut out = BTreeMap::new();
    let Some(lock) = read_json(&dir.join("package-lock.json")) else {
        return out;
    };
    for (key, entry) in lock
        .get("packages")
        .and_then(|p| p.as_object())
        .into_iter()
        .flatten()
    {
        let Some(name) = key
            .rsplit("node_modules/")
            .next()
            .filter(|_| !key.is_empty())
        else {
            continue;
        };
        let (Some(version), Some(license)) = (
            entry.get("version").and_then(|v| v.as_str()),
            json_license(entry),
        ) else {
            continue;
        };
        out.entry((name.to_string(), version.to_string()))
            .or_insert(license);
    }
    out
}

fn node_modules_license(dir: &Path, name: &str, version: &str) -> Option<License> {
    let manifest = read_json(&dir.join("node_modules").join(name).join("package.json"))?;
    (manifest.get("version").and_then(|v| v.as_str()) == Some(version))
        .then(|| json_license(&manifest))
        .flatten()
}

/// `name -> license` from `composer.lock` (`packages` and `packages-dev`).
fn composer_licenses(dir: &Path) -> BTreeMap<String, License> {
    let mut out = BTreeMap::new();
    let Some(lock) = read_json(&dir.join("composer.lock")) else {
        return out;
    };
    for key in ["packages", "packages-dev"] {
        for p in lock
            .get(key)
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let Some(name) = p.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let parts: Vec<String> = p
                .get("license")
                .and_then(|l| l.as_array())
                .into_iter()
                .flatten()
                .filter_map(|l| l.as_str().map(str::to_string))
                .collect();
            if let Some(license) = normalize(&parts) {
                out.insert(name.to_lowercase(), license);
            }
        }
    }
    out
}

/// The unpacked-crate directories of every registry in `$CARGO_HOME/registry/src`.
fn cargo_registry_roots(cargo_home: Option<&Path>) -> Vec<PathBuf> {
    let Some(src) = cargo_home.map(|h| h.join("registry").join("src")) else {
        return Vec::new();
    };
    std::fs::read_dir(src)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect()
}

/// `[package] license` of an unpacked crate (a `license-file` alone gives none).
fn cargo_license(crate_dir: &Path) -> Option<License> {
    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(crate_dir.join("Cargo.toml")).ok()?).ok()?;
    let license = manifest.get("package")?.get("license")?.as_str()?;
    normalize(&[license.to_string()])
}

fn pep503(name: &str) -> String {
    let mut out = String::new();
    let mut sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            sep = true;
        } else {
            if sep && !out.is_empty() {
                out.push('-');
            }
            sep = false;
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// `(normalized name, version) -> license` from the `.dist-info/METADATA` of every
/// virtualenv in the repo root or the source directory (`.venv`, `venv`, `env`).
fn python_dists(repo_root: &Path, dir: &Path) -> BTreeMap<(String, String), License> {
    let mut out = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for base in [dir, repo_root] {
        for venv in [".venv", "venv", "env"] {
            let lib = base.join(venv).join("lib");
            let Ok(pythons) = std::fs::read_dir(&lib) else {
                continue;
            };
            for py in pythons.flatten() {
                let site = py.path().join("site-packages");
                if !seen.insert(site.clone()) {
                    continue;
                }
                for entry in std::fs::read_dir(&site).into_iter().flatten().flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if !name.ends_with(".dist-info") {
                        continue;
                    }
                    let Ok(meta) = std::fs::read_to_string(entry.path().join("METADATA")) else {
                        continue;
                    };
                    if let Some((dist, version, license)) = metadata_license(&meta) {
                        out.entry((pep503(&dist), version)).or_insert(license);
                    }
                }
            }
        }
    }
    out
}

/// `Name`, `Version` and the license of a core-metadata file: `License-Expression` (PEP 639),
/// else a short `License` field, else the `License ::` classifiers.
fn metadata_license(meta: &str) -> Option<(String, String, License)> {
    let headers = meta.split("\n\n").next().unwrap_or(meta);
    let field = |key: &str| {
        headers
            .lines()
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
    };
    let name = field("Name:")?;
    let version = field("Version:")?;
    let license = field("License-Expression:")
        .and_then(|e| normalize(&[e]))
        .or_else(|| {
            field("License:")
                .filter(|l| l.len() < 60 && !l.contains('\n') && !l.eq_ignore_ascii_case("UNKNOWN"))
                .and_then(|l| normalize(&[l]))
                .filter(|l| l.expression.is_some())
        })
        .or_else(|| {
            let ids: Vec<String> = headers
                .lines()
                .filter_map(|l| l.strip_prefix("Classifier: License :: "))
                .filter_map(classifier_id)
                .map(str::to_string)
                .collect();
            normalize(&ids)
        });
    Some((name, version, license?))
}

/// The SPDX id of a trove license classifier, for the common ones.
fn classifier_id(classifier: &str) -> Option<&'static str> {
    let last = classifier.rsplit(" :: ").next()?;
    Some(match last {
        "MIT License" => "MIT",
        "MIT No Attribution License (MIT-0)" => "MIT-0",
        "Apache Software License" => "Apache-2.0",
        "BSD License" => return None, // which BSD is not said
        "ISC License (ISCL)" => "ISC",
        "Mozilla Public License 2.0 (MPL 2.0)" => "MPL-2.0",
        "GNU General Public License v2 (GPLv2)" => "GPL-2.0-only",
        "GNU General Public License v2 or later (GPLv2+)" => "GPL-2.0-or-later",
        "GNU General Public License v3 (GPLv3)" => "GPL-3.0-only",
        "GNU General Public License v3 or later (GPLv3+)" => "GPL-3.0-or-later",
        "GNU Lesser General Public License v2 (LGPLv2)" => "LGPL-2.0-only",
        "GNU Lesser General Public License v2 or later (LGPLv2+)" => "LGPL-2.0-or-later",
        "GNU Lesser General Public License v3 (LGPLv3)" => "LGPL-3.0-only",
        "GNU Lesser General Public License v3 or later (LGPLv3+)" => "LGPL-3.0-or-later",
        "GNU Affero General Public License v3" => "AGPL-3.0-only",
        "GNU Affero General Public License v3 or later (AGPLv3+)" => "AGPL-3.0-or-later",
        "Python Software Foundation License" => "PSF-2.0",
        "The Unlicense (Unlicense)" => "Unlicense",
        "CC0 1.0 Universal (CC0 1.0) Public Domain Dedication" => "CC0-1.0",
        "Eclipse Public License 2.0 (EPL-2.0)" => "EPL-2.0",
        "Zope Public License" => "ZPL-2.1",
        "zlib/libpng License" => "Zlib",
        "Boost Software License 1.0 (BSL-1.0)" => "BSL-1.0",
        _ => return None,
    })
}

/// `<license type="expression">` of a `.nuspec`, else a known `licenseUrl`.
fn nuspec_license(version_dir: &Path) -> Option<License> {
    let nuspec = std::fs::read_dir(version_dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "nuspec"))?;
    let text = std::fs::read_to_string(nuspec).ok()?;
    let doc = roxmltree::Document::parse(text.trim_start_matches('\u{feff}')).ok()?;
    if let Some(node) = doc.descendants().find(|n| n.has_tag_name("license")) {
        if node.attribute("type") == Some("expression") {
            return normalize(&[node.text()?.to_string()]);
        }
    }
    let url = doc
        .descendants()
        .find(|n| n.has_tag_name("licenseUrl"))?
        .text()?
        .trim()
        .to_lowercase();
    let id = [
        ("licenses.nuget.org/", ""),
        ("opensource.org/licenses/mit", "MIT"),
        ("apache.org/licenses/license-2.0", "Apache-2.0"),
        ("opensource.org/licenses/apache-2.0", "Apache-2.0"),
        ("opensource.org/licenses/bsd-3-clause", "BSD-3-Clause"),
    ]
    .iter()
    .find(|(needle, _)| url.contains(needle))
    .map(|(needle, id)| {
        if id.is_empty() {
            url.rsplit(needle).next().unwrap_or_default().to_string()
        } else {
            (*id).to_string()
        }
    })?;
    normalize(&[id])
}

// ---- deps.dev ----

/// Look up, on deps.dev, every package whose license no local source knew (see
/// [`crate::depsdev`]: opt-in, cached). Returns `(found, looked up, failed)`.
///
/// # Errors
///
/// When no cache directory is usable, or (without the `network` feature) always.
pub fn fetch_missing(inventories: &mut [RepoInventory]) -> Result<(usize, usize, usize), String> {
    use crate::depsdev::{infos, system};
    let mut wanted = BTreeSet::new();
    for inv in inventories.iter() {
        for source in &inv.sources {
            let Some(sys) = system(source.ecosystem) else {
                continue;
            };
            for p in source.packages.iter().filter(|p| p.license.is_none()) {
                wanted.insert((sys.to_string(), p.name.clone(), p.version.clone()));
            }
        }
    }
    let (answers, failed) = infos(&wanted)?;
    // deps.dev lists each license expression; several mean any one of them.
    let license_of = |k: &crate::depsdev::Key| -> Option<License> {
        let info = answers.get(k)?.as_ref()?;
        let usable: Vec<String> = info
            .licenses
            .iter()
            .filter(|l| !l.eq_ignore_ascii_case("non-standard"))
            .map(|l| {
                if l.contains(' ') && info.licenses.len() > 1 {
                    format!("({l})")
                } else {
                    l.clone()
                }
            })
            .collect();
        normalize(&[usable.join(" OR ")]).filter(|_| !usable.is_empty())
    };
    let found = wanted.iter().filter(|k| license_of(k).is_some()).count();
    for inv in inventories.iter_mut() {
        for source in &mut inv.sources {
            let Some(sys) = system(source.ecosystem) else {
                continue;
            };
            for p in source.packages.iter_mut().filter(|p| p.license.is_none()) {
                let k = (sys.to_string(), p.name.clone(), p.version.clone());
                set(p, license_of(&k).map(|l| (l, "deps.dev")));
            }
        }
    }
    Ok((found, wanted.len(), failed))
}

// ---- rollup ----

/// One package's license decision.
#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub repo: String,
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub license: Option<String>,
    pub source: Option<String>,
    pub category: Category,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    pub dev: bool,
}

/// Decide every package of every inventory. Without a policy everything is allowed (an
/// inventory only).
pub fn decide(inventories: &[RepoInventory], policy: Option<&Policy>) -> Vec<Decision> {
    let mut out = Vec::new();
    for inv in inventories {
        for source in &inv.sources {
            let ecosystem = serde_json::to_value(source.ecosystem)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            for p in &source.packages {
                let license = p.license.as_deref().map(|l| {
                    normalize(&[l.to_string()]).unwrap_or(License {
                        raw: l.to_string(),
                        expression: None,
                    })
                });
                let category = license
                    .as_ref()
                    .and_then(|l| l.expression.as_deref())
                    .map_or(Category::Unknown, |e| {
                        ids(e)
                            .iter()
                            .map(|id| category(id))
                            .min()
                            .unwrap_or(Category::Unknown)
                    });
                let (verdict, reason) = match policy {
                    Some(policy) if !(policy.runtime_only && p.dev) => {
                        policy.evaluate(&p.name, license.as_ref())
                    }
                    _ => (Verdict::Allow, String::new()),
                };
                out.push(Decision {
                    repo: inv.repo.0.clone(),
                    ecosystem: ecosystem.clone(),
                    package: p.name.clone(),
                    version: p.version.clone(),
                    license: p.license.clone(),
                    source: p.license_source.clone(),
                    category,
                    verdict,
                    reason,
                    dev: p.dev,
                });
            }
        }
    }
    out.sort_by(|a, b| {
        (&a.repo, &a.ecosystem, &a.package, &a.version).cmp(&(
            &b.repo,
            &b.ecosystem,
            &b.package,
            &b.version,
        ))
    });
    out.dedup_by(|a, b| {
        a.repo == b.repo
            && a.ecosystem == b.ecosystem
            && a.package == b.package
            && a.version == b.version
    });
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn lic(s: &str) -> License {
        normalize(&[s.to_string()]).unwrap()
    }

    #[test]
    fn normalizes_common_spellings() {
        assert_eq!(lic("MIT").expression.as_deref(), Some("MIT"));
        assert_eq!(
            lic("MIT/Apache-2.0").expression.as_deref(),
            Some("MIT OR Apache-2.0")
        );
        assert_eq!(lic("Apache 2.0").expression.as_deref(), Some("Apache-2.0"));
        assert_eq!(
            lic("(MIT OR CC0-1.0)").expression.as_deref(),
            Some("MIT OR CC0-1.0")
        );
        assert!(lic("BSD").expression.is_none(), "which BSD is unknown");
        assert!(lic("GPL").expression.is_none(), "which GPL is unknown");
        assert_eq!(
            lic("(MIT) OR (Apache-2.0)").expression.as_deref(),
            Some("(MIT) OR (Apache-2.0)")
        );
        assert!(lic("SEE LICENSE IN LICENSE.md").expression.is_none());
        let both = normalize(&["MIT".into(), "GPL-3.0-or-later".into()]).unwrap();
        assert_eq!(both.expression.as_deref(), Some("MIT OR GPL-3.0-or-later"));
    }

    #[test]
    fn categories_follow_the_license_family() {
        assert_eq!(category("AGPL-3.0-only"), Category::Forbidden);
        assert_eq!(category("GPL-2.0-or-later"), Category::Restricted);
        assert_eq!(category("LGPL-2.1-only"), Category::Restricted);
        assert_eq!(category("MPL-2.0"), Category::Reciprocal);
        assert_eq!(category("MIT"), Category::Notice);
        assert_eq!(category("MIT-0"), Category::Unencumbered);
        assert_eq!(category("CC-BY-4.0"), Category::Notice);
        assert_eq!(category("CC-BY-SA-4.0"), Category::Restricted);
        assert_eq!(category("CC-BY-NC-4.0"), Category::Forbidden);
        assert_eq!(category("LicenseRef-Proprietary"), Category::Unknown);
    }

    fn policy() -> Policy {
        Policy {
            allow: BTreeSet::new(),
            deny: BTreeSet::from(["SSPL-1.0".to_string()]),
            categories: Policy::default_categories(),
            unknown: Verdict::Deny,
            runtime_only: true,
            exceptions: BTreeMap::from([(
                "ring".to_string(),
                (BTreeSet::from(["OpenSSL".to_string()]), "legal".to_string()),
            )]),
        }
    }

    #[test]
    fn expressions_pass_when_they_can_be_satisfied() {
        let p = policy();
        assert_eq!(p.evaluate("a", Some(&lic("MIT"))).0, Verdict::Allow);
        // An OR with an allowed side is allowed; an AND needs both.
        assert_eq!(
            p.evaluate("a", Some(&lic("MIT OR AGPL-3.0-only"))).0,
            Verdict::Allow
        );
        assert_eq!(
            p.evaluate("a", Some(&lic("MIT AND AGPL-3.0-only"))).0,
            Verdict::Deny
        );
        // Restricted warns by default; forbidden denies; the deny list wins.
        let (v, why) = p.evaluate("a", Some(&lic("GPL-3.0-only")));
        assert_eq!(v, Verdict::Warn);
        assert!(why.contains("GPL-3.0-only (restricted)"), "{why}");
        assert_eq!(p.evaluate("a", Some(&lic("SSPL-1.0"))).0, Verdict::Deny);
        // Unknown fails closed.
        assert_eq!(p.evaluate("a", None).0, Verdict::Deny);
        assert_eq!(p.evaluate("a", Some(&lic("BSD"))).0, Verdict::Deny);
    }

    #[test]
    fn allow_lists_and_exceptions() {
        let mut p = policy();
        p.allow = BTreeSet::from(["MIT".to_string(), "Apache-2.0".to_string()]);
        assert_eq!(p.evaluate("a", Some(&lic("MIT"))).0, Verdict::Allow);
        assert_eq!(
            p.evaluate("a", Some(&lic("ISC"))).0,
            Verdict::Warn,
            "not on the allow list"
        );
        assert_eq!(
            p.evaluate("ring", Some(&lic("ISC AND OpenSSL"))).0,
            Verdict::Warn
        );
        p.allow.insert("ISC".to_string());
        assert_eq!(
            p.evaluate("ring", Some(&lic("ISC AND OpenSSL"))).0,
            Verdict::Allow
        );
        assert_eq!(
            p.evaluate("other", Some(&lic("ISC AND OpenSSL"))).0,
            Verdict::Warn
        );
    }

    #[test]
    fn python_metadata_prefers_the_expression_then_classifiers() {
        let pep639 = "Metadata-Version: 2.4\nName: Foo_Bar\nVersion: 1.0\nLicense-Expression: MIT OR Apache-2.0\nLicense: whatever\n\nbody";
        let (name, version, l) = metadata_license(pep639).unwrap();
        assert_eq!((name.as_str(), version.as_str()), ("Foo_Bar", "1.0"));
        assert_eq!(l.expression.as_deref(), Some("MIT OR Apache-2.0"));
        let classifiers = "Name: x\nVersion: 2\nLicense: UNKNOWN\nClassifier: License :: OSI Approved :: BSD License\nClassifier: License :: OSI Approved :: MIT License\n";
        assert_eq!(
            metadata_license(classifiers)
                .unwrap()
                .2
                .expression
                .as_deref(),
            Some("MIT")
        );
        let none = "Name: x\nVersion: 2\nLicense: Copyright (c) 2019 Someone, all rights reserved and more text\n";
        assert!(metadata_license(none).is_none());
        assert_eq!(pep503("Foo_Bar.baz"), "foo-bar-baz");
    }
}
