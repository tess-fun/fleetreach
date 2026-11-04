//! Component hashes for `fleetreach sbom`, from the fields lockfiles keep: Cargo's `checksum`,
//! npm-family `integrity`, Bundler's `CHECKSUMS`, Composer's `dist.shasum`, mix's outer
//! checksum and the source distribution's hash in Python locks. Each is the hash of the file
//! the registry serves. Three lockfile hashes are not and are left out: NuGet's `contentHash`
//! skips the package signature, `go.sum`'s `h1:` hashes a directory tree, and yarn berry's
//! `checksum` hashes yarn's own archive. A package with no such value has no hash; nothing
//! is computed or guessed.

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use fleetreach_core::inventory::{Checksum, RepoInventory};
use fleetreach_core::Ecosystem;

use crate::licenses::{pep503, source_dir};

type Table = BTreeMap<(String, String), Checksum>;

/// Add the hash of every package whose lockfile records one.
pub fn annotate(inv: &mut RepoInventory, repo_root: &Path) {
    for source in &mut inv.sources {
        let dir = source_dir(repo_root, &source.source);
        let read = |file: &str| std::fs::read_to_string(dir.join(file)).unwrap_or_default();
        let table = match source.ecosystem {
            Ecosystem::Cargo => cargo(&read("Cargo.lock")),
            Ecosystem::Npm => fleetreach_npm::lock_integrity(&dir)
                .into_iter()
                .filter_map(|(key, value)| Some((key, sri(&value)?)))
                .collect(),
            Ecosystem::RubyGems => gems(&read("Gemfile.lock")),
            Ecosystem::Packagist => composer(&read("composer.lock")),
            Ecosystem::Hex => mix(&read("mix.lock")),
            Ecosystem::Pypi => python(&read("uv.lock"), &read("poetry.lock"), &read("pylock.toml")),
            _ => continue,
        };
        for p in &mut source.packages {
            let name = match source.ecosystem {
                Ecosystem::Packagist => p.name.to_lowercase(),
                Ecosystem::Pypi => pep503(&p.name),
                _ => p.name.clone(),
            };
            if let Some(checksum) = table.get(&(name, p.version.clone())) {
                p.checksums = vec![checksum.clone()];
            }
        }
    }
}

/// `sha512-<base64>`, the strongest listed when there are several.
fn sri(value: &str) -> Option<Checksum> {
    value
        .split_whitespace()
        .filter_map(|one| {
            let (algorithm, encoded) = one.split_once('-')?;
            let algorithm = match algorithm {
                "sha512" => "SHA-512",
                "sha384" => "SHA-384",
                "sha256" => "SHA-256",
                "sha1" => "SHA-1",
                _ => return None,
            };
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .ok()?;
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            Checksum::new(algorithm, &hex)
        })
        .max_by_key(|c| c.hex.len())
}

fn cargo(text: &str) -> Table {
    let mut out = Table::new();
    let Ok(doc) = toml::from_str::<toml::Value>(text) else {
        return out;
    };
    for p in array(&doc, "package") {
        if let (Some(key), Some(sum)) = (name_version(p), string(p, "checksum")) {
            if let Some(checksum) = Checksum::new("SHA-256", sum) {
                out.insert(key, checksum);
            }
        }
    }
    out
}

/// `CHECKSUMS` lines: `  rack (3.0.8) sha256=<hex>`. A platform build keeps its own line, and
/// only matches a package listed at that same version.
fn gems(text: &str) -> Table {
    let mut out = Table::new();
    let Some((_, section)) = text.split_once("\nCHECKSUMS\n") else {
        return out;
    };
    for line in section.lines().take_while(|l| l.starts_with(' ')) {
        let mut words = line.split_whitespace();
        let (Some(name), Some(version), Some(sum)) = (words.next(), words.next(), words.next())
        else {
            continue;
        };
        let version = version.trim_matches(|c| c == '(' || c == ')');
        let checksum = sum
            .strip_prefix("sha256=")
            .and_then(|hex| Checksum::new("SHA-256", hex));
        if let Some(checksum) = checksum {
            out.insert((name.to_string(), version.to_string()), checksum);
        }
    }
    out
}

/// `dist.shasum`, which most packages leave empty: GitHub archives are not stable.
fn composer(text: &str) -> Table {
    let mut out = Table::new();
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(text) else {
        return out;
    };
    for section in ["packages", "packages-dev"] {
        let packages = doc.get(section).and_then(|p| p.as_array());
        for p in packages.into_iter().flatten() {
            let name = p.get("name").and_then(|v| v.as_str());
            let version = p.get("version").and_then(|v| v.as_str());
            let sum = p.pointer("/dist/shasum").and_then(|v| v.as_str());
            if let (Some(name), Some(version), Some(sum)) = (name, version, sum) {
                if let Some(checksum) = Checksum::new("SHA-1", sum) {
                    out.insert((name.to_lowercase(), version.to_string()), checksum);
                }
            }
        }
    }
    out
}

/// `"x": {:hex, :x, "1.0.0", "<inner>", [:mix], [...], "hexpm", "<outer>"}`. The outer checksum
/// is the SHA-256 of the tarball; the inner one, all that older locks have, is of its contents.
fn mix(text: &str) -> Table {
    let mut out = Table::new();
    for line in text.lines() {
        let Some((_, tuple)) = line.split_once("{:hex, :") else {
            continue;
        };
        let Some((name, rest)) = tuple.split_once(',') else {
            continue;
        };
        let strings: Vec<&str> = rest.split('"').skip(1).step_by(2).collect();
        let (Some(version), Some(outer)) = (strings.first(), strings.last()) else {
            continue;
        };
        if strings.len() < 4 {
            continue;
        }
        if let Some(checksum) = Checksum::new("SHA-256", outer) {
            out.insert((name.to_string(), (*version).to_string()), checksum);
        }
    }
    out
}

/// The source distribution's hash: one file per package, where wheels are many. A package
/// published as wheels only has none here.
fn python(uv: &str, poetry: &str, pylock: &str) -> Table {
    let mut out = Table::new();
    let sha256 = |value: &str| {
        value
            .strip_prefix("sha256:")
            .and_then(|hex| Checksum::new("SHA-256", hex))
    };
    if let Ok(doc) = toml::from_str::<toml::Value>(uv) {
        for p in array(&doc, "package") {
            let hash = p.get("sdist").and_then(|s| string(s, "hash"));
            if let (Some((name, version)), Some(checksum)) =
                (name_version(p), hash.and_then(sha256))
            {
                out.insert((pep503(&name), version), checksum);
            }
        }
    }
    if let Ok(doc) = toml::from_str::<toml::Value>(poetry) {
        let old = doc.get("metadata").and_then(|m| m.get("files"));
        for p in array(&doc, "package") {
            let Some((name, version)) = name_version(p) else {
                continue;
            };
            let files = p
                .get("files")
                .or_else(|| old.and_then(|o| o.get(name.as_str())));
            let sdist = files
                .and_then(|f| f.as_array())
                .into_iter()
                .flatten()
                .find(|f| string(f, "file").is_some_and(|n| n.ends_with(".tar.gz")));
            if let Some(checksum) = sdist.and_then(|f| string(f, "hash")).and_then(sha256) {
                out.insert((pep503(&name), version), checksum);
            }
        }
    }
    if let Ok(doc) = toml::from_str::<toml::Value>(pylock) {
        for p in array(&doc, "packages") {
            let hash = p
                .get("sdist")
                .and_then(|s| s.get("hashes"))
                .and_then(|h| string(h, "sha256"));
            if let (Some((name, version)), Some(hash)) = (name_version(p), hash) {
                if let Some(checksum) = Checksum::new("SHA-256", hash) {
                    out.insert((pep503(&name), version), checksum);
                }
            }
        }
    }
    out
}

fn array<'a>(doc: &'a toml::Value, key: &str) -> &'a [toml::Value] {
    doc.get(key)
        .and_then(toml::Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn string<'a>(value: &'a toml::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(toml::Value::as_str)
}

fn name_version(p: &toml::Value) -> Option<(String, String)> {
    Some((
        string(p, "name")?.to_string(),
        string(p, "version")?.to_string(),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const SHA256: &str = "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c";

    fn key(name: &str, version: &str) -> (String, String) {
        (name.to_string(), version.to_string())
    }

    #[test]
    fn sri_decodes_to_hex_and_prefers_the_stronger_hash() {
        let c = sri("sha1-qUqP5cyxm6YcTAhz05Hph5gvu9M=").unwrap();
        assert_eq!(c.algorithm, "SHA-1");
        assert_eq!(c.hex, "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
        let both = format!(
            "sha1-qUqP5cyxm6YcTAhz05Hph5gvu9M= sha512-{}",
            "A".repeat(86) + "=="
        );
        assert_eq!(sri(&both).unwrap().algorithm, "SHA-512");
        // A value of the wrong length is no hash at all.
        assert_eq!(sri("sha512-qUqP5cyxm6YcTAhz05Hph5gvu9M="), None);
        assert_eq!(sri("md5-qUqP5cyxm6YcTAhz05Hph5gvu9M="), None);
    }

    #[test]
    fn cargo_reads_checksums_and_skips_local_packages() {
        let lock = format!(
            "version = 3\n[[package]]\nname = \"me\"\nversion = \"0.1.0\"\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nchecksum = \"{SHA256}\"\n"
        );
        let table = cargo(&lock);
        assert_eq!(table.len(), 1);
        assert_eq!(table[&key("a", "1.0.0")].hex, SHA256);
    }

    #[test]
    fn gems_read_the_checksums_section() {
        let lock = format!(
            "GEM\n  specs:\n    rack (3.0.8)\n\nCHECKSUMS\n  rack (3.0.8) sha256={SHA256}\n  nosum (1.0.0)\n\nBUNDLED WITH\n   2.5.0\n"
        );
        let table = gems(&lock);
        assert_eq!(table.len(), 1);
        assert_eq!(table[&key("rack", "3.0.8")].hex, SHA256);
    }

    #[test]
    fn composer_skips_empty_shasums() {
        let sum = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
        let lock = format!(
            r#"{{"packages":[{{"name":"A/b","version":"1.0.0","dist":{{"shasum":"{sum}"}}}},{{"name":"c/d","version":"1.0.0","dist":{{"shasum":""}}}}]}}"#
        );
        let table = composer(&lock);
        assert_eq!(table.len(), 1);
        assert_eq!(table[&key("a/b", "1.0.0")].algorithm, "SHA-1");
    }

    #[test]
    fn mix_takes_the_outer_checksum_only() {
        let inner = "1".repeat(64);
        let lock = format!(
            "%{{\n  \"a\": {{:hex, :a, \"1.0.0\", \"{inner}\", [:mix], [{{:b, \"~> 1.0\", [hex: :b, repo: \"hexpm\", optional: false]}}], \"hexpm\", \"{SHA256}\"}},\n  \"old\": {{:hex, :old, \"1.0.0\", \"{inner}\", [:mix], [], \"hexpm\"}},\n}}\n"
        );
        let table = mix(&lock);
        assert_eq!(table.len(), 1);
        assert_eq!(table[&key("a", "1.0.0")].hex, SHA256);
    }

    #[test]
    fn python_takes_the_source_distribution() {
        let uv = format!(
            "version = 1\n[[package]]\nname = \"a-b\"\nversion = \"1.0.0\"\nsdist = {{ url = \"u\", hash = \"sha256:{SHA256}\" }}\nwheels = [{{ url = \"w\", hash = \"sha256:{}\" }}]\n[[package]]\nname = \"wheel-only\"\nversion = \"1.0.0\"\nwheels = [{{ url = \"w\", hash = \"sha256:{SHA256}\" }}]\n",
            "1".repeat(64)
        );
        let table = python(&uv, "", "");
        assert_eq!(table.len(), 1);
        assert_eq!(table[&key("a-b", "1.0.0")].hex, SHA256);

        let poetry = format!(
            "[[package]]\nname = \"A_B\"\nversion = \"1.0.0\"\nfiles = [\n  {{file = \"a_b-1.0.0-py3-none-any.whl\", hash = \"sha256:{}\"}},\n  {{file = \"a_b-1.0.0.tar.gz\", hash = \"sha256:{SHA256}\"}},\n]\n",
            "1".repeat(64)
        );
        assert_eq!(python("", &poetry, "")[&key("a-b", "1.0.0")].hex, SHA256);

        let old = format!(
            "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n[metadata.files]\na = [{{file = \"a-1.0.0.tar.gz\", hash = \"sha256:{SHA256}\"}}]\n"
        );
        assert_eq!(python("", &old, "")[&key("a", "1.0.0")].hex, SHA256);

        let pylock = format!(
            "lock-version = \"1.0\"\n[[packages]]\nname = \"a\"\nversion = \"1.0.0\"\n[packages.sdist]\nname = \"a-1.0.0.tar.gz\"\nhashes = {{ sha256 = \"{SHA256}\" }}\n"
        );
        assert_eq!(python("", "", &pylock)[&key("a", "1.0.0")].hex, SHA256);
    }
}
