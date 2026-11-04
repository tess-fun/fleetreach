//! The integrity value each npm lockfile records for a package, for SBOM hashes. Read apart
//! from the scan, which needs none of it. Yarn berry's `checksum` is left out: it hashes
//! yarn's own zip of the package, not the tarball the registry serves.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use crate::pnpm::{instance_id, strip_peers, Format};
use crate::resolved::split_name_version;
use crate::yaml::{self, Node as Y};

/// `(name, version)` to the integrity string as written (`sha512-<base64>`).
pub type Integrity = BTreeMap<(String, String), String>;

/// Every integrity value in the lockfiles in `dir`. A lockfile that cannot be read adds
/// nothing: the scan reports it, and a package with no hash claims nothing.
#[must_use]
pub fn lock_integrity(dir: &Path) -> Integrity {
    let mut out = Integrity::new();
    for file in crate::LOCKFILES {
        let Ok(text) = std::fs::read_to_string(dir.join(file)) else {
            continue;
        };
        match file {
            "pnpm-lock.yaml" => pnpm(&text, &mut out),
            "yarn.lock" => yarn(&text, &mut out),
            "bun.lock" => bun(&text, &mut out),
            _ => package_lock(&text, &mut out),
        }
    }
    out
}

fn add(out: &mut Integrity, name: &str, version: &str, integrity: &str) {
    out.entry((name.to_string(), version.to_string()))
        .or_insert_with(|| integrity.to_string());
}

/// `packages` by install path in lockfile v2 and v3; the nested `dependencies` tree in v1.
fn package_lock(text: &str, out: &mut Integrity) {
    let Ok(doc) = serde_json::from_str::<Value>(text) else {
        return;
    };
    if let Some(packages) = doc.get("packages").and_then(Value::as_object) {
        for (path, entry) in packages {
            let Some((_, tail)) = path.rsplit_once("node_modules/") else {
                continue;
            };
            let name = entry.get("name").and_then(Value::as_str).unwrap_or(tail);
            let version = entry.get("version").and_then(Value::as_str);
            let integrity = entry.get("integrity").and_then(Value::as_str);
            if let (Some(version), Some(integrity)) = (version, integrity) {
                add(out, name, version, integrity);
            }
        }
    } else {
        v1_tree(&doc, out);
    }
}

fn v1_tree(node: &Value, out: &mut Integrity) {
    let Some(dependencies) = node.get("dependencies").and_then(Value::as_object) else {
        return;
    };
    for (name, entry) in dependencies {
        let version = entry.get("version").and_then(Value::as_str);
        let integrity = entry.get("integrity").and_then(Value::as_str);
        if let (Some(version), Some(integrity)) = (version, integrity) {
            add(out, name, version, integrity);
        }
        v1_tree(entry, out);
    }
}

/// `packages` holds the resolution in every format; only the key's spelling differs.
fn pnpm(text: &str, out: &mut Integrity) {
    let Ok(docs) = yaml::parse(text) else {
        return;
    };
    let Some(doc) = docs.last() else {
        return;
    };
    let v5 = doc
        .str_at("lockfileVersion")
        .is_some_and(|v| v.trim_matches('\'').starts_with("5."));
    let format = if v5 { Format::V5 } else { Format::V6 };
    for (key, entry) in doc.get("packages").map(Y::entries).unwrap_or_default() {
        let Some(id) = instance_id(key, format) else {
            continue;
        };
        let integrity = entry.get("resolution").and_then(|r| r.str_at("integrity"));
        if let (Some((name, version)), Some(integrity)) =
            (split_name_version(strip_peers(&id)), integrity)
        {
            add(out, name, version, integrity);
        }
    }
}

/// Yarn v1 blocks: a `"name@range", ...:` header, then `  version` and `  integrity` lines.
fn yarn(text: &str, out: &mut Integrity) {
    if crate::yarn::is_berry(text) {
        return;
    }
    let mut name = None;
    let mut version = None;
    for line in text.lines() {
        if !line.starts_with(' ') {
            let first = line.trim_end_matches(':').split(", ").next();
            name = first
                .map(crate::yarn::unquote)
                .and_then(split_name_version)
                .map(|(n, range)| crate::yarn::registry_name(n, range));
            version = None;
        } else if let Some(v) = line.strip_prefix("  version ") {
            version = Some(crate::yarn::unquote(v.trim()));
        } else if let Some(integrity) = line.strip_prefix("  integrity ") {
            if let (Some(name), Some(version)) = (name, version) {
                add(out, name, version, integrity.trim());
            }
        }
    }
}

/// Each `packages` value is `[resolution, registry, metadata, integrity]`.
fn bun(text: &str, out: &mut Integrity) {
    let Ok(doc) = serde_json::from_str::<Value>(&crate::bun::to_json(text)) else {
        return;
    };
    let packages = doc.get("packages").and_then(Value::as_object);
    for value in packages.into_iter().flat_map(|p| p.values()) {
        let resolution = value.get(0).and_then(Value::as_str).unwrap_or_default();
        let integrity = value.get(3).and_then(Value::as_str);
        if let (Some((name, version)), Some(integrity)) =
            (crate::bun::registry(resolution), integrity)
        {
            add(out, &name, &version, integrity);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn key(name: &str, version: &str) -> (String, String) {
        (name.to_string(), version.to_string())
    }

    #[test]
    fn reads_package_lock_v3_and_v1() {
        let mut out = Integrity::new();
        package_lock(
            r#"{"packages":{
                "":{"name":"me","version":"1.0.0"},
                "node_modules/a":{"version":"1.0.0","integrity":"sha512-a"},
                "node_modules/a/node_modules/@s/b":{"version":"2.0.0","integrity":"sha512-b"},
                "node_modules/alias":{"name":"c","version":"3.0.0","integrity":"sha512-c"},
                "packages/local":{"version":"1.0.0","integrity":"sha512-x"}}}"#,
            &mut out,
        );
        assert_eq!(out.len(), 3);
        assert_eq!(out[&key("@s/b", "2.0.0")], "sha512-b");
        assert_eq!(out[&key("c", "3.0.0")], "sha512-c");

        let mut out = Integrity::new();
        package_lock(
            r#"{"dependencies":{"a":{"version":"1.0.0","integrity":"sha1-a",
                "dependencies":{"b":{"version":"2.0.0","integrity":"sha512-b"}}}}}"#,
            &mut out,
        );
        assert_eq!(out[&key("a", "1.0.0")], "sha1-a");
        assert_eq!(out[&key("b", "2.0.0")], "sha512-b");
    }

    #[test]
    fn reads_pnpm_keys_of_each_version() {
        let mut out = Integrity::new();
        pnpm(
            "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-a}\n  '@s/b@2.0.0':\n    resolution: {integrity: sha512-b}\n",
            &mut out,
        );
        assert_eq!(out[&key("a", "1.0.0")], "sha512-a");
        assert_eq!(out[&key("@s/b", "2.0.0")], "sha512-b");

        let mut out = Integrity::new();
        pnpm(
            "lockfileVersion: '6.0'\npackages:\n  /a@1.0.0(b@2.0.0):\n    resolution: {integrity: sha512-a}\n",
            &mut out,
        );
        assert_eq!(out[&key("a", "1.0.0")], "sha512-a");

        let mut out = Integrity::new();
        pnpm(
            "lockfileVersion: 5.4\npackages:\n  /@s/a/1.0.0_b@2.0.0:\n    resolution: {integrity: sha512-a}\n",
            &mut out,
        );
        assert_eq!(out[&key("@s/a", "1.0.0")], "sha512-a");
    }

    #[test]
    fn reads_yarn_v1_and_leaves_berry_out() {
        let mut out = Integrity::new();
        yarn(
            "# yarn lockfile v1\n\n\"@s/a@^1.0.0\", \"@s/a@^1.1.0\":\n  version \"1.2.0\"\n  resolved \"https://x\"\n  integrity sha512-a\n  dependencies:\n    b \"^2\"\n\nb@^2:\n  version \"2.0.0\"\n",
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[&key("@s/a", "1.2.0")], "sha512-a");

        let mut out = Integrity::new();
        yarn(
            "__metadata:\n  version: 8\n\n\"a@npm:^1\":\n  version: 1.0.0\n  checksum: 10c0/abc\n",
            &mut out,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn reads_bun_and_skips_workspaces() {
        let mut out = Integrity::new();
        bun(
            r#"{"lockfileVersion":1,"workspaces":{"":{}},"packages":{
                "a":["a@1.0.0","",{},"sha512-a"],
                "local":["local@workspace:packages/local"],}}"#,
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[&key("a", "1.0.0")], "sha512-a");
    }
}
