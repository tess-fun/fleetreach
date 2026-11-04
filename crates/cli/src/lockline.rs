//! The line a package's entry starts on, for SARIF `region`s. One reader per file a package can
//! be read from. A format it does not know, or an entry it cannot find, gives no line: the
//! result then points at the file, never at a guess.

use std::path::Path;

fn pep503(name: &str) -> String {
    name.to_ascii_lowercase().replace(['_', '.'], "-")
}

/// The 1-based line of the first of `lines` that `is_entry` accepts and whose next few lines
/// hold `version`, else of the first accepted at all.
fn pick(
    text: &str,
    version: &str,
    is_entry: impl Fn(&str) -> bool,
    version_line: impl Fn(&str, &str) -> bool,
) -> Option<u32> {
    let lines: Vec<&str> = text.lines().collect();
    let entries = || (0..lines.len()).filter(|i| is_entry(lines[*i]));
    let versioned = entries().find(|i| {
        let near = &lines[*i..lines.len().min(i + 4)];
        !version.is_empty() && near.iter().any(|l| version_line(l, version))
    });
    let line = versioned.or_else(|| entries().next())?;
    u32::try_from(line + 1).ok()
}

/// `package` at `version` (empty when not known) in `file`, whose contents are `text`.
#[must_use]
pub fn entry_line(file: &str, text: &str, package: &str, version: &str) -> Option<u32> {
    let name = Path::new(file).file_name()?.to_str()?;
    let quoted = |l: &str, v: &str| l.contains(&format!("\"{v}\""));
    let any = |_: &str, _: &str| false;
    match name {
        "Cargo.lock" => {
            let key = format!("name = \"{package}\"");
            pick(text, version, |l| l == key, quoted)
        }
        "uv.lock" | "poetry.lock" => {
            let wanted = pep503(package);
            let entry = |l: &str| {
                let value = l
                    .strip_prefix("name = \"")
                    .and_then(|r| r.strip_suffix('"'));
                value.is_some_and(|n| pep503(n) == wanted)
            };
            pick(text, version, entry, quoted)
        }
        "package-lock.json" | "npm-shrinkwrap.json" => {
            let key = format!("node_modules/{package}\": {{");
            pick(text, version, |l| l.trim_end().ends_with(&key), quoted)
        }
        "yarn.lock" => {
            let entry = |l: &str| {
                !l.starts_with(' ')
                    && l.split(", ").any(|spec| {
                        let spec = spec.trim_matches(['"', ':']);
                        spec.strip_prefix(package)
                            .is_some_and(|r| r.starts_with('@'))
                    })
            };
            let held = |l: &str, v: &str| l.trim().trim_end_matches('"').ends_with(v);
            pick(text, version, entry, |l, v| {
                l.trim_start().starts_with("version") && held(l, v)
            })
        }
        "pnpm-lock.yaml" => {
            let key = format!("{package}@{version}");
            pick(
                text,
                version,
                |l| {
                    l.trim_start()
                        .trim_start_matches(['\'', '"', '/'])
                        .starts_with(&key)
                },
                any,
            )
        }
        "Gemfile.lock" => {
            let key = format!("    {package} (");
            let exact = format!("{key}{version})");
            let entry = |l: &str| {
                if version.is_empty() {
                    l.starts_with(&key)
                } else {
                    l == exact
                }
            };
            pick(text, version, entry, any)
        }
        "composer.lock" => {
            let key = format!("\"name\": \"{package}\"");
            let wanted = key.to_ascii_lowercase();
            pick(
                text,
                version,
                |l| l.trim().trim_end_matches(',').to_ascii_lowercase() == wanted,
                |l, v| l.contains("\"version\"") && l.contains(v),
            )
        }
        "go.mod" => {
            let entry = |l: &str| {
                let l = l.trim_start().trim_start_matches("require ");
                l.strip_prefix(package).is_some_and(|r| r.starts_with(' '))
            };
            pick(text, version, entry, any)
        }
        "packages.lock.json" | "Pipfile.lock" | "bun.lock" => {
            let key = format!("\"{}\":", package.to_ascii_lowercase());
            pick(
                text,
                version,
                |l| l.trim_start().to_ascii_lowercase().starts_with(&key),
                any,
            )
        }
        "requirements.txt" => {
            let wanted = pep503(package);
            let entry = |l: &str| {
                let end = l.find(|c: char| !(c.is_alphanumeric() || "-_.".contains(c)));
                pep503(&l[..end.unwrap_or(l.len())]) == wanted
            };
            pick(text, version, entry, any)
        }
        "pom.xml" => {
            let artifact = package.rsplit(':').next()?;
            let key = format!("<artifactId>{artifact}</artifactId>");
            pick(text, version, |l| l.contains(&key), any)
        }
        "mix.lock" => {
            let key = format!("\"{package}\":");
            pick(text, version, |l| l.trim_start().starts_with(&key), any)
        }
        "Manifest.toml" => {
            let key = format!("[[deps.{package}]]");
            pick(text, version, |l| l.trim() == key, any)
        }
        "Package.resolved" => {
            let wanted = package.rsplit('/').next()?.to_ascii_lowercase();
            let keys = [
                format!("\"identity\" : \"{wanted}\""),
                format!("\"package\": \"{wanted}\""),
            ];
            pick(
                text,
                version,
                |l| {
                    let l = l.to_ascii_lowercase();
                    keys.iter().any(|k| l.contains(k))
                },
                any,
            )
        }
        _ if name.ends_with(".yml") || name.ends_with(".yaml") => {
            let key = format!("uses: {package}@");
            pick(text, version, |l| l.contains(&key), any)
        }
        _ if name.ends_with("proj") || name.ends_with(".props") => {
            let key = format!("include=\"{}\"", package.to_ascii_lowercase());
            pick(
                text,
                version,
                |l| l.to_ascii_lowercase().contains(&key),
                any,
            )
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::entry_line;

    #[test]
    fn each_format_finds_the_entry_at_its_version() {
        let cargo = "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"a\"\nversion = \"2.0.0\"\n";
        assert_eq!(entry_line("Cargo.lock", cargo, "a", "2.0.0"), Some(6));
        assert_eq!(entry_line("x/Cargo.lock", cargo, "a", ""), Some(2));
        assert_eq!(entry_line("Cargo.lock", cargo, "b", "1.0.0"), None);

        let npm = "{\n  \"packages\": {\n    \"node_modules/b/node_modules/a\": {\n      \"version\": \"1.0.0\"\n    },\n    \"node_modules/a\": {\n      \"version\": \"2.0.0\"\n    }\n  }\n}\n";
        assert_eq!(entry_line("package-lock.json", npm, "a", "2.0.0"), Some(6));
        assert_eq!(entry_line("package-lock.json", npm, "a", "1.0.0"), Some(3));

        let yarn =
            "\"@x/a@^1.0.0\":\n  version \"1.0.0\"\n\na@^1.0.0, a@^1.1.0:\n  version \"1.2.0\"\n";
        assert_eq!(entry_line("yarn.lock", yarn, "a", "1.2.0"), Some(4));
        assert_eq!(entry_line("yarn.lock", yarn, "@x/a", "1.0.0"), Some(1));

        let pnpm = "packages:\n\n  a@1.0.0:\n    resolution: {}\n  '@x/b@2.0.0':\n";
        assert_eq!(entry_line("pnpm-lock.yaml", pnpm, "a", "1.0.0"), Some(3));
        assert_eq!(entry_line("pnpm-lock.yaml", pnpm, "@x/b", "2.0.0"), Some(5));

        let gems = "GEM\n  specs:\n    rack (2.0.1)\n      x (>= 1)\n    rack-test (1.0)\n";
        assert_eq!(entry_line("Gemfile.lock", gems, "rack", "2.0.1"), Some(3));
        assert_eq!(entry_line("Gemfile.lock", gems, "rack", ""), Some(3));
        assert_eq!(entry_line("Gemfile.lock", gems, "x", ""), None);

        let go = "module m\n\nrequire a.io/b v1.0.0\nrequire (\n\ta.io/c v1.0.0 // indirect\n)\n";
        assert_eq!(entry_line("go.mod", go, "a.io/c", "1.0.0"), Some(5));
        assert_eq!(entry_line("go.mod", go, "a.io/b", "1.0.0"), Some(3));
    }

    #[test]
    fn names_compare_as_their_registry_does() {
        let uv = "[[package]]\nname = \"zope-interface\"\nversion = \"5.0\"\n";
        assert_eq!(entry_line("uv.lock", uv, "Zope_Interface", "5.0"), Some(2));
        let reqs = "# a comment\nFlask[async]==2.0\nflask-cors>=3\n";
        assert_eq!(entry_line("requirements.txt", reqs, "flask", ""), Some(2));
        let nuget = "{\n  \"Newtonsoft.Json\": {\n";
        let hit = entry_line("packages.lock.json", nuget, "newtonsoft.json", "");
        assert_eq!(hit, Some(2));
    }

    #[test]
    fn an_unknown_file_gives_no_line() {
        assert_eq!(entry_line("var/lib/dpkg/status", "a\n", "a", "1"), None);
    }
}
