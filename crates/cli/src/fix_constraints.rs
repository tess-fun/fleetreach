//! What a repo's own ranges allow, read before `fix plan` proposes a target (spec 16, row 3).
//!
//! A lock bump only moves a package inside the ranges that ask for it. So for npm's
//! `package-lock.json` and for Cargo the plan reads each range that reaches a vulnerable copy:
//!
//! | The target is left out by | Plan |
//! |---------------------------|------|
//! | nothing | lock bump |
//! | a range in the repo's own manifest | manifest bump: raise that range, then update the lock |
//! | a range or peer range in a published package | blocked, naming the package to update first |
//!
//! A range that cannot be read as a version range (a git url, a tag, `workspace:`) says nothing,
//! and neither does a Cargo dependency whose manifest is not in the local registry. Those stay
//! lock bumps: `fix apply` runs the package manager and re-scans, so this check can only spare
//! a failed attempt, never pass a bad one. pnpm and yarn locks do not keep these ranges.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fleetreach_core::semver::{Prerelease, Version, VersionReq};
use fleetreach_core::Ecosystem;
use serde_json::Value;

use crate::fix::{dirs_with, Edit, Strategy};

/// A range that leaves the target out.
#[derive(Debug, PartialEq, Eq)]
struct Excluding {
    /// `package.json`, a member's `Cargo.toml`, or the published package asking.
    holder: String,
    range: String,
    /// The repo's own manifest, rather than a published package's.
    own: bool,
}

/// Sets `edit`'s strategy from the ranges in the checkout at `root`.
pub fn constrain(edit: &mut Edit, root: &Path) {
    if edit.strategy != Strategy::LockBump {
        return;
    }
    let Ok(to) = Version::parse(&edit.to) else {
        return;
    };
    let found = match edit.ecosystem {
        Ecosystem::Npm => npm_excluding(root, edit, &to),
        Ecosystem::Cargo => cargo_excluding(root, edit, &to),
        _ => return,
    };
    if let Some(blocker) = found.iter().find(|e| !e.own) {
        edit.strategy = Strategy::Blocked;
        edit.reason = Some(format!(
            "{} asks for {} {}, which leaves out {}: update {} first",
            blocker.holder, edit.package, blocker.range, edit.to, blocker.holder
        ));
    } else if let Some(first) = found.first() {
        edit.strategy = Strategy::ManifestBump;
        edit.reason = Some(format!(
            "{} asks for {} {}, which leaves out {}",
            first.holder, edit.package, first.range, edit.to
        ));
    }
}

/// Where `dependency` resolves from the lock entry `holder`: node's walk up `node_modules`.
fn resolved<'a>(packages: &'a Value, holder: &str, dependency: &str) -> Option<&'a Value> {
    let mut base = holder;
    loop {
        let candidate = if base.is_empty() {
            format!("node_modules/{dependency}")
        } else {
            format!("{base}/node_modules/{dependency}")
        };
        if let Some(entry) = packages.get(&candidate) {
            return Some(entry);
        }
        if base.is_empty() {
            return None;
        }
        base = base
            .rfind("node_modules/")
            .map_or("", |at| base[..at].trim_end_matches('/'));
    }
}

fn is_local(key: &str) -> bool {
    !key.contains("node_modules/")
}

/// Every range in a `package-lock.json` that reaches a vulnerable copy of the package and
/// leaves out `to`.
fn npm_excluding(root: &Path, edit: &Edit, to: &Version) -> Vec<Excluding> {
    let mut out = Vec::new();
    for dir in dirs_with(root, "package-lock.json") {
        let Some(lock) = read_json(&dir.join("package-lock.json")) else {
            continue;
        };
        let Some(packages) = lock.get("packages") else {
            continue;
        };
        for (key, entry) in packages.as_object().into_iter().flatten() {
            let own = is_local(key);
            let sections: &[&str] = if own {
                &[
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                    "peerDependencies",
                ]
            } else {
                &["dependencies", "optionalDependencies", "peerDependencies"]
            };
            for section in sections {
                let Some(range) = entry[*section][&edit.package].as_str() else {
                    continue;
                };
                let copy = resolved(packages, key, &edit.package);
                let version = copy.and_then(|c| c["version"].as_str()).unwrap_or("");
                if edit.from.iter().any(|f| f == version) && npm_satisfies(range, to) == Some(false)
                {
                    let holder = match key.rsplit_once("node_modules/") {
                        Some((_, name)) => name.to_string(),
                        None => manifest_label(root, &dir, key),
                    };
                    let range = range.to_string();
                    out.push(Excluding { holder, range, own });
                }
            }
        }
    }
    out
}

fn manifest_label(root: &Path, dir: &Path, key: &str) -> String {
    let path = dir.join(key).join("package.json");
    let path = path.strip_prefix(root).unwrap_or(&path);
    path.to_string_lossy().replace('\\', "/")
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&fleetreach_core::repofile::read(path).ok()?).ok()
}

/// One comparator of an npm range.
type Comparator = (Op, Version);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
}

/// A possibly partial version: `1`, `1.2`, `1.x`, `1.2.3-rc.1`.
#[derive(Clone, Debug)]
struct Partial {
    numbers: [Option<u64>; 3],
    pre: String,
}

impl Partial {
    fn parse(text: &str) -> Option<Partial> {
        let text = text.trim().trim_start_matches(['v', '=']);
        let text = text.split('+').next().unwrap_or(text);
        let (core, pre) = text.split_once('-').unwrap_or((text, ""));
        let parts: Vec<&str> = core.split('.').collect();
        if parts.len() > 3 {
            return None;
        }
        let mut numbers = [None; 3];
        let mut wild = false;
        for (slot, part) in numbers.iter_mut().zip(&parts) {
            if matches!(*part, "x" | "X" | "*") {
                wild = true;
            } else if part.len() > 1 && part.starts_with('0') {
                return None;
            } else {
                let number = part.parse().ok()?;
                *slot = (!wild).then_some(number);
            }
        }
        Some(Partial {
            numbers,
            pre: pre.to_string(),
        })
    }

    /// Filled with zeros, keeping the prerelease only when the version was whole.
    fn floor(&self) -> Option<Version> {
        let [a, b, c] = self.numbers;
        let pre = if c.is_some() && !self.pre.is_empty() {
            format!("-{}", self.pre)
        } else {
            String::new()
        };
        let text = format!(
            "{}.{}.{}{pre}",
            a.unwrap_or(0),
            b.unwrap_or(0),
            c.unwrap_or(0)
        );
        Version::parse(&text).ok()
    }

    /// The first version past what the given parts name, below every prerelease of it.
    fn after(&self, kept: usize) -> Option<Version> {
        let [a, b, c] = self.numbers;
        let (a, b, c) = (a.unwrap_or(0), b.unwrap_or(0), c.unwrap_or(0));
        let text = match kept {
            1 => format!("{}.0.0-0", a + 1),
            2 => format!("{a}.{}.0-0", b + 1),
            _ => format!("{a}.{b}.{}-0", c + 1),
        };
        Version::parse(&text).ok()
    }

    fn known(&self) -> usize {
        self.numbers.iter().flatten().count()
    }
}

/// `^`, `~`, a bare version or a comparison, as plain comparators.
fn comparators(token: &str) -> Option<Vec<Comparator>> {
    let (op, rest) = ["<=", ">=", "<", ">", "=", "^", "~>", "~"]
        .iter()
        .find_map(|op| Some((*op, token.strip_prefix(op)?)))
        .unwrap_or(("", token));
    let partial = Partial::parse(rest)?;
    let known = partial.known();
    let floor = partial.floor()?;
    let between = |top: Version| vec![(Op::Ge, floor.clone()), (Op::Lt, top)];
    Some(match op {
        _ if known == 0 && matches!(op, "" | "=" | "^" | "~" | "~>" | ">=" | "<=") => Vec::new(),
        // `>*` and `<*` match nothing.
        ">" | "<" if known == 0 => vec![(Op::Lt, Version::parse("0.0.0-0").ok()?)],
        "" | "=" if known == 3 => vec![(Op::Eq, floor)],
        "" | "=" => between(partial.after(known)?),
        "^" => {
            let [a, b, c] = partial.numbers;
            let kept = match (a.unwrap_or(0), b, c) {
                (0, None, _) => 1,
                (0, Some(0), None) => 2,
                (0, Some(0), Some(0)) if known == 3 => 3,
                (0, Some(0), Some(_)) => 3,
                (0, Some(_), _) => 2,
                _ => 1,
            };
            between(partial.after(kept)?)
        }
        "~" | "~>" => between(partial.after(known.min(2))?),
        ">=" => vec![(Op::Ge, floor)],
        ">" if known == 3 => vec![(Op::Gt, floor)],
        ">" => {
            let mut next = partial.after(known)?;
            next.pre = Prerelease::EMPTY;
            vec![(Op::Ge, next)]
        }
        "<" => vec![(Op::Lt, floor)],
        "<=" if known == 3 => vec![(Op::Le, floor)],
        "<=" => vec![(Op::Lt, partial.after(known)?)],
        _ => return None,
    })
}

/// One `||` part of a range.
fn comparator_set(text: &str) -> Option<Vec<Comparator>> {
    if let Some((low, high)) = text.split_once(" - ") {
        let (low, high) = (Partial::parse(low)?, Partial::parse(high)?);
        let mut out = vec![(Op::Ge, low.floor()?)];
        match high.known() {
            0 => {}
            3 => out.push((Op::Le, high.floor()?)),
            known => out.push((Op::Lt, high.after(known)?)),
        }
        return Some(out);
    }
    // `>= 1.2.3` may keep its operator apart.
    let mut tokens: Vec<String> = Vec::new();
    let mut pending = String::new();
    for word in text.split_whitespace() {
        if word.chars().all(|c| "<>=^~".contains(c)) {
            pending.push_str(word);
        } else {
            tokens.push(format!("{pending}{word}"));
            pending.clear();
        }
    }
    let mut out = Vec::new();
    for token in tokens {
        out.extend(comparators(&token)?);
    }
    Some(out)
}

fn holds(comparator: &Comparator, version: &Version) -> bool {
    let (op, bound) = comparator;
    match op {
        Op::Lt => version < bound,
        Op::Le => version <= bound,
        Op::Gt => version > bound,
        Op::Ge => version >= bound,
        Op::Eq => version == bound,
    }
}

/// Whether `version` is in the npm `range`, as node-semver decides. `None` when the text is not
/// a version range: a url, a tag, an alias.
pub fn npm_satisfies(range: &str, version: &Version) -> Option<bool> {
    let mut matched = false;
    for part in range.split("||") {
        let set = comparator_set(part.trim())?;
        let mut fits = set.iter().all(|c| holds(c, version));
        // A prerelease counts only against a comparator on the same version that has one.
        if fits && !version.pre.is_empty() {
            fits = set.iter().any(|(_, bound)| {
                !bound.pre.is_empty()
                    && (bound.major, bound.minor, bound.patch)
                        == (version.major, version.minor, version.patch)
            });
        }
        matched |= fits;
    }
    Some(matched)
}

/// A dependency of a Cargo manifest: the name it goes by, and its requirement.
fn cargo_requirements(manifest: &toml::Value, package: &str, dev: bool) -> Vec<String> {
    let mut tables: Vec<&toml::Value> = vec![manifest];
    let targets = manifest.get("target").and_then(toml::Value::as_table);
    tables.extend(targets.into_iter().flat_map(|t| t.values()));
    let sections: &[&str] = if dev {
        &["dependencies", "dev-dependencies", "build-dependencies"]
    } else {
        &["dependencies", "build-dependencies"]
    };
    let mut out = Vec::new();
    for table in tables {
        for section in sections {
            let deps = table.get(*section).and_then(toml::Value::as_table);
            for (key, value) in deps.into_iter().flatten() {
                let renamed = value.get("package").and_then(toml::Value::as_str);
                if renamed.unwrap_or(key) != package {
                    continue;
                }
                let req = value
                    .as_str()
                    .or(value.get("version").and_then(toml::Value::as_str));
                out.extend(req.map(str::to_string));
            }
        }
    }
    out
}

fn read_toml(path: &Path) -> Option<toml::Value> {
    toml::from_str(&fleetreach_core::repofile::read_to_string(path).ok()?).ok()
}

/// The manifests under `dir`, by package name, and the workspace's own requirement.
fn members(dir: &Path) -> (BTreeMap<String, PathBuf>, Vec<PathBuf>) {
    let mut by_name = BTreeMap::new();
    let all = dirs_with(dir, "Cargo.toml");
    for member in &all {
        let path = member.join("Cargo.toml");
        let manifest = read_toml(&path);
        let name = manifest
            .as_ref()
            .and_then(|m| m.get("package")?.get("name")?.as_str().map(str::to_string));
        if let Some(name) = name {
            by_name.insert(name, path);
        }
    }
    (
        by_name,
        all.into_iter().map(|d| d.join("Cargo.toml")).collect(),
    )
}

fn registry_manifest(name: &str, version: &str) -> Option<PathBuf> {
    let home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| Some(PathBuf::from(std::env::var_os("HOME")?).join(".cargo")))?;
    let indexes = std::fs::read_dir(home.join("registry").join("src")).ok()?;
    let candidates = indexes.flatten().map(|index| {
        index
            .path()
            .join(format!("{name}-{version}"))
            .join("Cargo.toml")
    });
    candidates.into_iter().find(|path| path.is_file())
}

/// Every requirement in a repo's manifests, or a cached published manifest, on a vulnerable
/// copy of the package that leaves out `to`.
fn cargo_excluding(root: &Path, edit: &Edit, to: &Version) -> Vec<Excluding> {
    let parsed = edit.from.iter().map(|f| Version::parse(f));
    let from: Vec<Version> = parsed.filter_map(Result::ok).collect();
    let mut out = Vec::new();
    for dir in dirs_with(root, "Cargo.lock") {
        let Some(lock) = read_toml(&dir.join("Cargo.lock")) else {
            continue;
        };
        let (own, all) = members(&dir);
        let listed = lock.get("package").and_then(toml::Value::as_array);
        let packages: &[toml::Value] = listed.map_or(&[], Vec::as_slice);
        let versions: BTreeSet<&str> = packages
            .iter()
            .filter(|p| p.get("name").and_then(toml::Value::as_str) == Some(edit.package.as_str()))
            .filter_map(|p| p.get("version")?.as_str())
            .collect();
        for package in packages {
            let Some(name) = package.get("name").and_then(toml::Value::as_str) else {
                continue;
            };
            let version = package
                .get("version")
                .and_then(toml::Value::as_str)
                .unwrap_or("");
            let deps = package.get("dependencies").and_then(toml::Value::as_array);
            let wanted = deps
                .into_iter()
                .flatten()
                .filter_map(toml::Value::as_str)
                .any(|dep| {
                    let (dep_name, at) = dep.split_once(' ').unwrap_or((dep, ""));
                    let at = at.split_whitespace().next().unwrap_or("");
                    let vulnerable = |v: &&str| edit.from.iter().any(|f| f == v);
                    dep_name == edit.package
                        && if at.is_empty() {
                            versions.iter().any(&vulnerable)
                        } else {
                            vulnerable(&at)
                        }
                });
            if !wanted {
                continue;
            }
            let local = package.get("source").is_none();
            let path = match local {
                true => own.get(name).cloned(),
                false => registry_manifest(name, version),
            };
            let Some(manifest) = path.as_deref().and_then(read_toml) else {
                continue;
            };
            let mut requirements = cargo_requirements(&manifest, &edit.package, local);
            if local {
                requirements.extend(workspace_requirement(&all, &edit.package));
            }
            for range in requirements {
                let excludes = VersionReq::parse(&range).is_ok_and(|req| {
                    let on_a_copy = from.iter().any(|version| req.matches(version));
                    on_a_copy && !req.matches(to)
                });
                if excludes {
                    let holder = match local {
                        true => format!("{name}'s Cargo.toml"),
                        false => name.to_string(),
                    };
                    out.push(Excluding {
                        holder,
                        range,
                        own: local,
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| (a.own, &a.holder).cmp(&(b.own, &b.holder)));
    out
}

fn workspace_requirement(manifests: &[PathBuf], package: &str) -> Vec<String> {
    let mut out = Vec::new();
    for path in manifests {
        let Some(manifest) = read_toml(path) else {
            continue;
        };
        if let Some(workspace) = manifest.get("workspace") {
            out.extend(cargo_requirements(workspace, package, false));
        }
    }
    out
}

/// `old` raised to take `to`, in the same spirit: an exact pin stays exact, a tilde stays one.
fn raised_npm(old: &str, to: &str) -> String {
    let old = old.trim();
    if old.starts_with('~') {
        format!("~{to}")
    } else if old.starts_with(|c: char| c.is_ascii_digit() || c == '=') && !old.contains(' ') {
        to.to_string()
    } else {
        format!("^{to}")
    }
}

fn raised_cargo(old: &str, to: &str) -> String {
    match old.trim().chars().next() {
        Some('=') => format!("={to}"),
        Some('~') => format!("~{to}"),
        _ => to.to_string(),
    }
}

/// The text of a `package.json` with `package`'s range `old` changed to `new`, every section.
fn with_npm_range(text: &str, package: &str, old: &str, new: &str) -> String {
    let key = format!("\"{package}\"");
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(&key) {
        let end = at + key.len();
        out.push_str(&rest[..end]);
        rest = &rest[end..];
        let after_colon = rest.trim_start().strip_prefix(':').map(str::trim_start);
        if let Some(value) = after_colon.and_then(|v| v.strip_prefix(&format!("\"{old}\""))) {
            let gap = rest.len() - value.len() - old.len() - 2;
            out.push_str(&rest[..gap]);
            out.push('"');
            out.push_str(new);
            out.push('"');
            rest = value;
        }
    }
    out.push_str(rest);
    out
}

/// Raises every range in the repo's own `package.json` files that leaves out the target.
///
/// # Errors
///
/// When a manifest cannot be written.
pub fn raise_npm(work: &Path, edit: &Edit) -> Result<Vec<PathBuf>, String> {
    let to = Version::parse(&edit.to).map_err(|e| e.to_string())?;
    let mut lock_dirs = Vec::new();
    for dir in dirs_with(work, "package-lock.json") {
        let Some(lock) = read_json(&dir.join("package-lock.json")) else {
            continue;
        };
        let entries = lock["packages"].as_object().into_iter().flatten();
        let local = entries.filter(|(key, _)| is_local(key));
        let mut changed = false;
        for (key, entry) in local {
            let path = dir.join(key).join("package.json");
            let Ok(mut text) = fleetreach_core::repofile::read_to_string(&path) else {
                continue;
            };
            let before = text.clone();
            for section in [
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ] {
                let Some(old) = entry[section][&edit.package].as_str() else {
                    continue;
                };
                let copy = resolved(&lock["packages"], key, &edit.package);
                let version = copy.and_then(|c| c["version"].as_str()).unwrap_or("");
                let vulnerable = edit.from.iter().any(|f| f == version);
                if vulnerable && npm_satisfies(old, &to) == Some(false) {
                    let new = raised_npm(old, &edit.to);
                    text = with_npm_range(&text, &edit.package, old, &new);
                }
            }
            if text != before {
                std::fs::write(&path, text).map_err(|e| e.to_string())?;
                changed = true;
            }
        }
        if changed {
            lock_dirs.push(dir);
        }
    }
    Ok(lock_dirs)
}

/// What a Cargo requirement is raised from and to.
struct Raise<'a> {
    package: &'a str,
    text: &'a str,
    to: Version,
    from: Vec<Version>,
}

impl Raise<'_> {
    /// A requirement on a vulnerable copy that leaves the target out. One on another line of
    /// the package, which the plan is not fixing, stays as it is.
    fn wants(&self, requirement: &str) -> bool {
        VersionReq::parse(requirement).is_ok_and(|req| {
            !req.matches(&self.to) && self.from.iter().any(|from| req.matches(from))
        })
    }

    /// Raises the package in one `[dependencies]`-like table.
    fn section(&self, table: &mut dyn toml_edit::TableLike, section: &str) -> bool {
        let Some(deps) = table.get_mut(section).and_then(|d| d.as_table_like_mut()) else {
            return false;
        };
        let mut touched = false;
        for (key, item) in deps.iter_mut() {
            let renamed = item.get("package").and_then(|p| p.as_str());
            if renamed.unwrap_or(key.get()) != self.package {
                continue;
            }
            let slot = if item.is_str() {
                Some(item)
            } else {
                item.get_mut("version")
            };
            let Some(slot) = slot else {
                continue;
            };
            let Some(old) = slot.as_str().map(str::to_string) else {
                continue;
            };
            if self.wants(&old) {
                let decor = slot.as_value().map(|v| v.decor().clone());
                *slot = toml_edit::value(raised_cargo(&old, self.text));
                if let (Some(decor), Some(value)) = (decor, slot.as_value_mut()) {
                    *value.decor_mut() = decor;
                }
                touched = true;
            }
        }
        touched
    }

    /// Raises the package in every dependency table of a table: a manifest, or a target.
    fn sections(&self, table: &mut dyn toml_edit::TableLike) -> bool {
        let names = ["dependencies", "dev-dependencies", "build-dependencies"];
        let touched = names.map(|name| self.section(table, name));
        touched.contains(&true)
    }

    fn manifest(&self, doc: &mut toml_edit::DocumentMut) -> bool {
        let root = doc.as_table_mut();
        let mut touched = self.sections(root);
        if let Some(workspace) = root
            .get_mut("workspace")
            .and_then(|w| w.as_table_like_mut())
        {
            touched |= self.section(workspace, "dependencies");
        }
        if let Some(targets) = root.get_mut("target").and_then(|t| t.as_table_like_mut()) {
            for (_, target) in targets.iter_mut() {
                if let Some(target) = target.as_table_like_mut() {
                    touched |= self.sections(target);
                }
            }
        }
        touched
    }
}

/// Raises every requirement in the repo's `Cargo.toml` files that holds a vulnerable copy back
/// from the target, keeping their layout and comments.
///
/// # Errors
///
/// When a manifest cannot be parsed or written.
pub fn raise_cargo(work: &Path, edit: &Edit) -> Result<usize, String> {
    let raise = Raise {
        package: &edit.package,
        text: &edit.to,
        to: Version::parse(&edit.to).map_err(|e| e.to_string())?,
        from: edit
            .from
            .iter()
            .filter_map(|f| Version::parse(f).ok())
            .collect(),
    };
    let mut changed = 0;
    for dir in dirs_with(work, "Cargo.toml") {
        let path = dir.join("Cargo.toml");
        let text = fleetreach_core::repofile::read_to_string(&path).map_err(|e| e.to_string())?;
        let mut doc: toml_edit::DocumentMut = text
            .parse()
            .map_err(|e: toml_edit::TomlError| e.to_string())?;
        if raise.manifest(&mut doc) {
            std::fs::write(&path, doc.to_string()).map_err(|e| e.to_string())?;
            changed += 1;
        }
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn version(v: &str) -> Version {
        Version::parse(v).unwrap()
    }

    fn edit(ecosystem: Ecosystem, package: &str, from: &str, to: &str) -> Edit {
        Edit {
            campaign: "c".to_string(),
            repo: "r".to_string(),
            ecosystem,
            package: package.to_string(),
            from: vec![from.to_string()],
            to: to.to_string(),
            advisories: vec![],
            breaking: false,
            strategy: Strategy::LockBump,
            reason: None,
            risk: None,
            risk_reasons: vec![],
        }
    }

    fn write(root: &Path, file: &str, text: &str) {
        let path = root.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn npm_ranges_read_as_node_semver_does() {
        let yes = [
            ("^1.2.3", "1.9.0"),
            ("~1.2.3", "1.2.9"),
            ("1.x", "1.5.0"),
            ("1.2 - 2.3", "2.3.9"),
            (">= 1.0.0 < 2", "1.5.0"),
            ("*", "9.0.0"),
            ("", "9.0.0"),
            ("^0.2.3", "0.2.9"),
            ("^1.0.0 || ^2.0.0", "2.1.0"),
            (">=1.0.0-rc.1", "1.0.0"),
            ("1.2.3-rc.1", "1.2.3-rc.1"),
        ];
        for (range, v) in yes {
            assert_eq!(npm_satisfies(range, &version(v)), Some(true), "{range} {v}");
        }
        let no = [
            ("^1.2.3", "2.0.0"),
            ("~1.2.3", "1.3.0"),
            ("^0.2.3", "0.3.0"),
            ("^0.0.3", "0.0.4"),
            ("1.2.3", "1.2.4"),
            ("<2", "2.0.0"),
            ("^1.0.0", "2.0.0-rc.1"),
            ("^1.0.0", "1.5.0-rc.1"),
            (">1", "2.0.0-0"),
        ];
        for (range, v) in no {
            assert_eq!(
                npm_satisfies(range, &version(v)),
                Some(false),
                "{range} {v}"
            );
        }
        for odd in [
            "latest",
            "git+https://x/y.git",
            "npm:other@1",
            "workspace:*",
            "file:../a",
        ] {
            assert_eq!(npm_satisfies(odd, &version("1.0.0")), None, "{odd}");
        }
    }

    const LOCK: &str = r#"{"packages":{
        "":{"dependencies":{"direct":"^1.0.0","parent":"^1.0.0"}},
        "node_modules/direct":{"version":"1.0.0"},
        "node_modules/parent":{"version":"1.0.0","dependencies":{"deep":"~1.0.0"}},
        "node_modules/deep":{"version":"1.0.0"},
        "node_modules/other":{"version":"1.0.0","dependencies":{"deep":"^3.0.0"}},
        "node_modules/other/node_modules/deep":{"version":"3.0.0"}
    }}"#;

    #[test]
    fn npm_fits_raises_or_blocks() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "package-lock.json", LOCK);

        let mut fits = edit(Ecosystem::Npm, "direct", "1.0.0", "1.5.0");
        constrain(&mut fits, root.path());
        assert_eq!(fits.strategy, Strategy::LockBump);

        let mut manifest = edit(Ecosystem::Npm, "direct", "1.0.0", "2.0.0");
        constrain(&mut manifest, root.path());
        assert_eq!(manifest.strategy, Strategy::ManifestBump);

        let mut held = edit(Ecosystem::Npm, "deep", "1.0.0", "1.1.0");
        constrain(&mut held, root.path());
        assert_eq!(held.strategy, Strategy::Blocked);
        let reason = held.reason.unwrap();
        assert!(reason.contains("parent asks for deep ~1.0.0"), "{reason}");
        assert!(
            !reason.contains("other"),
            "another copy's range is not this copy's"
        );
    }

    #[test]
    fn a_range_on_a_safe_copy_says_nothing() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "package-lock.json", LOCK);
        // `other` asks for deep ^3 and has its own copy, which is not the vulnerable one.
        let mut wanted = edit(Ecosystem::Npm, "deep", "3.0.0", "3.1.0");
        constrain(&mut wanted, root.path());
        assert_eq!(wanted.strategy, Strategy::LockBump);
    }

    #[test]
    fn a_package_json_keeps_its_layout_when_raised() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "package-lock.json", LOCK);
        let text = "{\n  \"dependencies\": {\n    \"direct\":   \"^1.0.0\",\n    \"parent\": \"^1.0.0\"\n  }\n}\n";
        write(root.path(), "package.json", text);
        let dirs = raise_npm(
            root.path(),
            &edit(Ecosystem::Npm, "direct", "1.0.0", "2.0.0"),
        )
        .unwrap();
        assert_eq!(dirs.len(), 1);
        let after = std::fs::read_to_string(root.path().join("package.json")).unwrap();
        assert_eq!(after, text.replace("\"^1.0.0\",", "\"^2.0.0\","));
    }

    #[test]
    fn a_raised_range_keeps_its_kind() {
        assert_eq!(raised_npm("^1.0.0", "2.0.0"), "^2.0.0");
        assert_eq!(raised_npm("~1.0.0", "1.1.0"), "~1.1.0");
        assert_eq!(raised_npm("1.0.0", "1.1.0"), "1.1.0");
        assert_eq!(raised_npm(">=1 <2", "2.0.0"), "^2.0.0");
        assert_eq!(raised_cargo("=1.0.0", "1.1.0"), "=1.1.0");
        assert_eq!(raised_cargo("~1.0", "1.1.0"), "~1.1.0");
        assert_eq!(raised_cargo("1", "2.0.0"), "2.0.0");
    }

    const CARGO_LOCK: &str = r#"
version = 4
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["left", "right 1.0.0"]
[[package]]
name = "left"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "right"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "right"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

    #[test]
    fn cargo_reads_member_requirements() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "Cargo.lock", CARGO_LOCK);
        let manifest = "[package]\nname = \"app\"\n[dependencies]\nleft = \"=1.0.0\" # pinned\n\
            right = { version = \"1\", features = [\"x\"] }\n";
        write(root.path(), "Cargo.toml", manifest);

        let mut pinned = edit(Ecosystem::Cargo, "left", "1.0.0", "1.2.0");
        constrain(&mut pinned, root.path());
        assert_eq!(pinned.strategy, Strategy::ManifestBump);

        let mut fits = edit(Ecosystem::Cargo, "right", "1.0.0", "1.2.0");
        constrain(&mut fits, root.path());
        assert_eq!(fits.strategy, Strategy::LockBump);

        assert_eq!(raise_cargo(root.path(), &pinned).unwrap(), 1);
        let after = std::fs::read_to_string(root.path().join("Cargo.toml")).unwrap();
        assert!(after.contains("left = \"=1.2.0\" # pinned"), "{after}");
        assert!(
            after.contains("right = { version = \"1\", features = [\"x\"] }"),
            "{after}"
        );
    }

    #[test]
    fn a_requirement_on_another_line_of_a_renamed_crate_says_nothing() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "Cargo.lock", CARGO_LOCK);
        let manifest = "[package]\nname = \"app\"\n[dependencies]\nright = \"1.0\"\n\
            right-old = { package = \"right\", version = \"=0.2.0\" }\n\
            left = \"1\"\n";
        write(root.path(), "Cargo.toml", manifest);
        let mut fits = edit(Ecosystem::Cargo, "right", "1.0.0", "1.2.0");
        constrain(&mut fits, root.path());
        assert_eq!(fits.strategy, Strategy::LockBump);
    }

    #[test]
    fn a_range_on_another_line_is_not_raised() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "a/Cargo.lock", CARGO_LOCK);
        let vulnerable = "[package]\nname = \"app\"\n[dependencies]\nleft = \"=1.0.0\"\n";
        write(root.path(), "a/Cargo.toml", vulnerable);
        let newer = "[package]\nname = \"other\"\n[dependencies]\nleft = \"3\"\n";
        write(root.path(), "b/Cargo.toml", newer);
        let left = edit(Ecosystem::Cargo, "left", "1.0.0", "1.2.0");
        assert_eq!(raise_cargo(root.path(), &left).unwrap(), 1);
        let after = std::fs::read_to_string(root.path().join("b/Cargo.toml")).unwrap();
        assert_eq!(after, newer);

        let other = tempfile::tempdir().unwrap();
        write(other.path(), "package-lock.json", LOCK);
        let manifest = "{\"dependencies\":{\"direct\":\"^1.0.0\"}}";
        write(other.path(), "package.json", manifest);
        let safe = edit(Ecosystem::Npm, "direct", "0.9.0", "2.0.0");
        assert!(raise_npm(other.path(), &safe).unwrap().is_empty());
    }

    #[test]
    fn a_blocked_edit_stays_as_it_was() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "package-lock.json", LOCK);
        let mut blocked = edit(Ecosystem::Npm, "direct", "1.0.0", "2.0.0");
        blocked.strategy = Strategy::Blocked;
        blocked.reason = Some("breaking".to_string());
        constrain(&mut blocked, root.path());
        assert_eq!(blocked.reason.as_deref(), Some("breaking"));
    }
}
