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

/// Whether `version` stands alone in `line`: `1.2.3` is not in `11.2.3`, `1.2.3-beta` or the
/// range `^1.2.3`.
fn holds(line: &str, version: &str) -> bool {
    let bytes = line.as_bytes();
    let at = |i: usize, back: usize| i.checked_sub(back).and_then(|p| bytes.get(p)).copied();
    let name_char = |b: Option<u8>| b.is_some_and(|b| b.is_ascii_alphanumeric());
    line.match_indices(version).any(|(i, _)| {
        let (before, prior) = (at(i, 1), at(i, 2));
        let clean_before = match before {
            None => true,
            Some(b'v') => !name_char(prior),
            // `<version>1.2` is a value; `>1.2` and `>=1.2` are ranges.
            Some(b'>') => name_char(prior),
            Some(b'=') => !prior.is_some_and(|b| b"<>~!".contains(&b)),
            Some(b) => !b.is_ascii_alphanumeric() && !b".-+^~<".contains(&b),
        };
        let after = bytes.get(i + version.len()).copied();
        clean_before && !name_char(after) && !after.is_some_and(|b| b".-+".contains(&b))
    })
}

/// The line of `package`'s entry when that entry is at exactly `version`. Unlike
/// [`entry_line`] this never settles for the package at another version.
#[must_use]
pub fn exact_line(file: &str, text: &str, package: &str, version: &str) -> Option<u32> {
    if version.is_empty() {
        return None;
    }
    let line = entry_line(file, text, package, version)?;
    let name = Path::new(file).file_name()?.to_str()?;
    // Hashes or metadata can stand between these entries and their version.
    let reach = match name {
        "Pipfile.lock" | "Manifest.toml" | "Package.resolved" => 64,
        _ => 4,
    };
    let start = usize::try_from(line).ok()?.checked_sub(1)?;
    // A workflow says `@v4` where the finding has the padded `4.0.0`.
    let tag = version.trim_end_matches(".0");
    let short = (name.ends_with(".yml") || name.ends_with(".yaml")).then_some(tag);
    for (i, l) in text.lines().skip(start).take(reach).enumerate() {
        if holds(l, version) || short.is_some_and(|tag| holds(l, tag)) {
            return Some(line);
        }
        if i > 0 && (l.trim().is_empty() || l.contains("version")) {
            return None;
        }
    }
    None
}

/// Whether [`entry_line`] can read `file`.
#[must_use]
pub fn reads(file: &str) -> bool {
    let Some(name) = Path::new(file).file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    matches!(
        name,
        "Cargo.lock"
            | "uv.lock"
            | "poetry.lock"
            | "pylock.toml"
            | "package-lock.json"
            | "npm-shrinkwrap.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "Gemfile.lock"
            | "composer.lock"
            | "go.mod"
            | "packages.lock.json"
            | "packages.config"
            | "Pipfile.lock"
            | "bun.lock"
            | "pom.xml"
            | "gradle.lockfile"
            | "mix.lock"
            | "Manifest.toml"
            | "Package.resolved"
    ) || is_requirements(name)
        || name.ends_with("proj")
        || name.ends_with(".props")
        || file.contains(".github/workflows/")
            && (name.ends_with(".yml") || name.ends_with(".yaml"))
}

fn is_requirements(name: &str) -> bool {
    name.ends_with(".txt") && (name.contains("requirements") || name.starts_with("constraints"))
}

/// Whether `file` declares dependencies by hand, so a changed line in it is a cause.
#[must_use]
pub fn is_manifest(file: &str) -> bool {
    let Some(name) = Path::new(file).file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    matches!(
        name,
        "Cargo.toml"
            | "package.json"
            | "pyproject.toml"
            | "Pipfile"
            | "go.mod"
            | "Gemfile"
            | "composer.json"
            | "pom.xml"
            | "build.gradle"
            | "build.gradle.kts"
            | "libs.versions.toml"
            | "mix.exs"
            | "Project.toml"
            | "Package.swift"
    ) || is_requirements(name)
        || name.ends_with(".gemspec")
        || name.ends_with("proj")
        || name.ends_with(".props")
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
        "uv.lock" | "poetry.lock" | "pylock.toml" => {
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
            // A bun package entry is an array; a string under that key is a workspace's range.
            let bun = name == "bun.lock";
            let entry = |l: &str| {
                l.trim_start().to_ascii_lowercase().starts_with(&key) && (!bun || l.contains('['))
            };
            pick(text, version, entry, holds)
        }
        "gradle.lockfile" => {
            let key = format!("{package}:");
            pick(text, version, |l| l.starts_with(&key), any)
        }
        "packages.config" => {
            let key = format!("id=\"{}\"", package.to_ascii_lowercase());
            pick(
                text,
                version,
                |l| l.to_ascii_lowercase().contains(&key),
                any,
            )
        }
        _ if is_requirements(name) => {
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
            let tag = version.trim_end_matches(".0");
            pick(
                text,
                version,
                |l| l.contains(&key),
                |l, _| holds(l, tag) || holds(l, version),
            )
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
    use super::{entry_line, exact_line};

    #[test]
    fn an_exact_line_is_the_package_at_that_version_or_nothing() {
        let cargo = "[[package]]\nname = \"time\"\nversion = \"0.1.43\"\n";
        assert_eq!(exact_line("Cargo.lock", cargo, "time", "0.1.43"), Some(2));
        assert_eq!(exact_line("Cargo.lock", cargo, "time", "0.1.4"), None);
        assert_eq!(exact_line("Cargo.lock", cargo, "time", "1.43"), None);
        let bun = "    \"vite\": \"^8.3.1\",\n\n    \"vite\": [\"vite@8.3.1\", \"\"],\n";
        assert_eq!(exact_line("bun.lock", bun, "vite", "8.3.1"), Some(3));
        let range = "    \"vite\": \"^8.3.1\",\n";
        assert_eq!(exact_line("bun.lock", range, "vite", "8.3.1"), None);
        let pipfile = "\"rack\": {\n\"hashes\": [\n\"a\",\n\"b\",\n\"c\",\n\"d\"\n],\n\"version\": \"==2.0\"\n}";
        assert_eq!(exact_line("Pipfile.lock", pipfile, "rack", "2.0"), Some(1));
        let pom = "<artifactId>a</artifactId>\n<version>1.2</version>\n";
        assert_eq!(exact_line("pom.xml", pom, "g:a", "1.2"), Some(1));
        assert_eq!(
            exact_line("requirements.txt", "rack>=2.0\n", "rack", "2.0"),
            None
        );
        assert_eq!(
            exact_line("requirements.txt", "rack==2.0\n", "rack", "2.0"),
            Some(1)
        );
        let flow = "      - uses: a/b@v4\n";
        assert_eq!(
            exact_line(".github/workflows/c.yml", flow, "a/b", "4.0.0"),
            Some(1)
        );
        assert_eq!(
            exact_line(".github/workflows/c.yml", flow, "a/b", "4.1.0"),
            None
        );
        let go = "require golang.org/x/text v0.3.0\n";
        assert_eq!(
            exact_line("go.mod", go, "golang.org/x/text", "0.3.0"),
            Some(1)
        );
        let gradle = "org.a:b:1.2=compileClasspath\n";
        assert_eq!(
            exact_line("gradle.lockfile", gradle, "org.a:b", "1.2"),
            Some(1)
        );
        let config = "  <package id=\"Foo\" version=\"1.0.0\" />\n";
        assert_eq!(
            exact_line("packages.config", config, "foo", "1.0.0"),
            Some(1)
        );
    }

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
