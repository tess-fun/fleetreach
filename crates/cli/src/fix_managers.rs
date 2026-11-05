//! The lock-only updates for pnpm, yarn, Composer, Bundler, NuGet and Maven (spec 16, row 5).
//! As in [`crate::fix`], none of them runs a package's code. The pnpm, yarn, Composer and
//! Bundler updates ask the package manager for a new lockfile with scripts and plugins off;
//! NuGet and Maven change the version where the project declares it. Which version lands is
//! the package manager's call within the declared ranges, so the re-scan decides whether the
//! update did the job.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::fix::{dirs_with, run, Edit};

/// The directories whose `lockfile` passes `holds`.
fn dirs_holding(work: &Path, lockfile: &str, holds: impl Fn(&str) -> bool) -> Vec<PathBuf> {
    dirs_with(work, lockfile)
        .into_iter()
        .filter(|d| {
            fleetreach_core::repofile::read_to_string(d.join(lockfile)).is_ok_and(|t| holds(&t))
        })
        .collect()
}

/// `pnpm update <pkg> --lockfile-only`, which writes the lockfile and installs nothing. A
/// workspace needs `--recursive` to reach its packages; outside one, `--recursive` leaves a
/// transitive dependency where it was and pnpm still reports success.
fn pnpm_update(dir: &Path, package: &str) -> Command {
    let mut pnpm = Command::new("pnpm");
    pnpm.current_dir(dir).args([
        "update",
        package,
        "--lockfile-only",
        "--ignore-scripts",
        "--depth",
        "Infinity",
    ]);
    if dir.join("pnpm-workspace.yaml").is_file() {
        pnpm.arg("--recursive");
    }
    pnpm
}

pub(crate) fn pnpm_bump(work: &Path, edit: &Edit) -> Result<Option<String>, String> {
    let needle = format!("{}@", edit.package);
    let dirs = dirs_holding(work, "pnpm-lock.yaml", |t| t.contains(&needle));
    for dir in &dirs {
        run(&mut pnpm_update(dir, &edit.package))
            .map_err(|e| format!("pnpm update {}: {e}", edit.package))?;
    }
    Ok((!dirs.is_empty()).then(|| {
        format!(
            "pnpm update {} --lockfile-only in {} dir(s)",
            edit.package,
            dirs.len()
        )
    }))
}

/// `yarn.lock` without the entries for `package`, so an install resolves them afresh. An entry
/// is a key line (`foo@^1.0.0, "foo@~1.2":`) and the indented lines after it.
fn without_yarn_entries(lock: &str, package: &str) -> String {
    let names = |key: &str| {
        key.trim_end_matches(':').split(", ").any(|spec| {
            let spec = spec.trim_matches('"');
            spec.strip_prefix(package)
                .is_some_and(|rest| rest.starts_with('@'))
        })
    };
    let mut out = String::with_capacity(lock.len());
    let mut dropping = false;
    for line in lock.split_inclusive('\n') {
        let indented = line.starts_with(' ');
        let key = !indented && !line.starts_with('#') && !line.trim().is_empty();
        if key {
            dropping = names(line.trim_end());
        } else if !indented {
            dropping = false;
        }
        if !dropping {
            out.push_str(line);
        }
    }
    out
}

/// Berry updates the lockfile alone. Classic cannot, so the package's entries are dropped and
/// an install with scripts off puts them back, into a folder outside the tree.
pub(crate) fn yarn_bump(work: &Path, edit: &Edit) -> Result<Option<String>, String> {
    let needle = format!("{}@", edit.package);
    let dirs = dirs_holding(work, "yarn.lock", |t| t.contains(&needle));
    for dir in &dirs {
        let path = dir.join("yarn.lock");
        let lock = fleetreach_core::repofile::read_to_string(&path).map_err(|e| e.to_string())?;
        if lock.contains("__metadata:") {
            // Yarn rewrites its install state even when no version moved. In a repo that
            // tracks it, that alone would read as a change.
            let state = dir.join(".yarn/install-state.gz");
            let kept = fleetreach_core::repofile::read(&state).ok();
            run(Command::new("yarn")
                .current_dir(dir)
                .env("YARN_ENABLE_SCRIPTS", "0")
                .env("YARN_ENABLE_IMMUTABLE_INSTALLS", "0")
                .env("YARN_ENABLE_TELEMETRY", "0")
                .args(["up", "-R", &edit.package, "--mode=update-lockfile"]))
            .map_err(|e| format!("yarn up -R {}: {e}", edit.package))?;
            match kept {
                Some(bytes) => std::fs::write(&state, bytes).map_err(|e| e.to_string())?,
                None => {
                    let _ = std::fs::remove_file(&state);
                }
            }
        } else {
            let modules = tempfile_dir(&edit.package)?;
            std::fs::write(&path, without_yarn_entries(&lock, &edit.package))
                .map_err(|e| e.to_string())?;
            let installed = run(Command::new("yarn").current_dir(dir).args([
                "install",
                "--ignore-scripts",
                "--non-interactive",
                "--no-bin-links",
                "--ignore-engines",
                "--modules-folder",
                modules.to_str().unwrap_or_default(),
            ]));
            let _ = std::fs::remove_dir_all(&modules);
            installed.map_err(|e| format!("yarn install: {e}"))?;
        }
    }
    Ok((!dirs.is_empty()).then(|| {
        format!(
            "yarn.lock updated for {} in {} dir(s)",
            edit.package,
            dirs.len()
        )
    }))
}

fn tempfile_dir(tag: &str) -> Result<PathBuf, String> {
    let name: String = tag
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let dir = std::env::temp_dir().join(format!("fleetreach-fix-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

/// `composer update <pkg> --no-scripts --no-plugins --no-install`: `composer.lock` only.
pub(crate) fn composer_bump(work: &Path, edit: &Edit) -> Result<String, String> {
    let needle = format!("\"name\": \"{}\"", edit.package);
    let dirs = dirs_holding(work, "composer.lock", |t| t.contains(&needle));
    if dirs.is_empty() {
        return Err(format!("no composer.lock holds {}", edit.package));
    }
    for dir in &dirs {
        run(Command::new("composer").current_dir(dir).args([
            "update",
            &edit.package,
            "--with-dependencies",
            "--no-scripts",
            "--no-plugins",
            "--no-install",
            "--no-audit",
            "--no-interaction",
            "--no-progress",
        ]))
        .map_err(|e| format!("composer update {}: {e}", edit.package))?;
    }
    Ok(format!(
        "composer update {} --no-install in {} dir(s)",
        edit.package,
        dirs.len()
    ))
}

/// `bundle lock --update <gem> --conservative`: `Gemfile.lock` only, nothing installed. Bundler
/// evaluates the repo's own Gemfile to do it, as every Bundler command does.
pub(crate) fn bundler_bump(work: &Path, edit: &Edit) -> Result<String, String> {
    let needle = format!("    {} (", edit.package);
    let dirs = dirs_holding(work, "Gemfile.lock", |t| t.contains(&needle));
    if dirs.is_empty() {
        return Err(format!("no Gemfile.lock holds {}", edit.package));
    }
    for dir in &dirs {
        run(Command::new("bundle").current_dir(dir).args([
            "lock",
            "--update",
            &edit.package,
            "--conservative",
        ]))
        .map_err(|e| format!("bundle lock --update {}: {e}", edit.package))?;
    }
    Ok(format!(
        "bundle lock --update {} --conservative in {} dir(s)",
        edit.package,
        dirs.len()
    ))
}

/// Files under `work` whose name passes `wanted`.
fn files_where(work: &Path, wanted: impl Fn(&str) -> bool) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = walkdir::WalkDir::new(work)
        .max_depth(8)
        .into_iter()
        .filter_entry(|e| {
            !(e.file_type().is_dir()
                && matches!(
                    e.file_name().to_str(),
                    Some(".git" | "node_modules" | "target" | "bin" | "obj")
                ))
        })
        .flatten()
        .filter(|e| e.file_type().is_file() && e.file_name().to_str().is_some_and(&wanted))
        .map(walkdir::DirEntry::into_path)
        .collect();
    found.sort();
    found
}

/// `text` with each range replaced by `to`. Ranges come from one parse and do not overlap.
fn replaced(text: &str, mut ranges: Vec<std::ops::Range<usize>>, to: &str) -> String {
    ranges.sort_by_key(|r| std::cmp::Reverse(r.start));
    let mut out = text.to_string();
    for range in ranges {
        out.replace_range(range, to);
    }
    out
}

/// Whether `declared` is one of `from`, which come from a report: NuGet and Maven both read
/// `1.9` and `1.9.0` as one version, and the report shows the normalized form.
fn version_is(declared: &str, from: &[String]) -> bool {
    fn parts(version: &str) -> (&str, &str) {
        let end = version.find(['-', '+']).unwrap_or(version.len());
        let (mut core, suffix) = version.split_at(end);
        while let Some(shorter) = core.strip_suffix(".0") {
            core = shorter;
        }
        (core, suffix)
    }
    let declared = parts(declared);
    from.iter().any(|f| parts(f) == declared)
}

/// Whether a declared NuGet version is one of `from`: `1.2.3`, or pinned as `[1.2.3]`.
fn nuget_version_is(declared: &str, from: &[String]) -> bool {
    let bare = declared
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    version_is(bare, from)
}

/// Where `package` is declared at one of `from` in an MSBuild project: the `Version` attribute
/// or child of `PackageReference` and `PackageVersion` items, as ranges of `text`.
fn msbuild_versions(
    text: &str,
    package: &str,
    from: &[String],
) -> Result<Vec<std::ops::Range<usize>>, String> {
    let doc = roxmltree::Document::parse(text).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let items = doc.descendants().filter(|n| {
        matches!(n.tag_name().name(), "PackageReference" | "PackageVersion")
            && ["Include", "Update"].iter().any(|a| {
                n.attribute(*a)
                    .is_some_and(|v| v.eq_ignore_ascii_case(package))
            })
    });
    for item in items {
        let attribute = item
            .attributes()
            .find(|a| a.name() == "Version" && nuget_version_is(a.value(), from));
        let child = item
            .children()
            .find(|c| c.has_tag_name("Version"))
            .and_then(|c| c.first_child())
            .filter(|t| t.text().is_some_and(|v| nuget_version_is(v, from)));
        out.extend(attribute.map(|a| a.range_value()));
        out.extend(child.map(|t| t.range()));
    }
    Ok(out)
}

/// The version in the project files where the package is declared, then `dotnet restore
/// --force-evaluate` where a `packages.lock.json` records it. A transitive package has no
/// declaration to change.
pub(crate) fn nuget_bump(work: &Path, edit: &Edit) -> Result<String, String> {
    let projects = files_where(work, |name| {
        name.ends_with(".csproj")
            || name.ends_with(".fsproj")
            || name.ends_with(".vbproj")
            || name.ends_with(".props")
    });
    let mut changed = 0;
    for path in &projects {
        let text = fleetreach_core::repofile::read_to_string(path).map_err(|e| e.to_string())?;
        let ranges = msbuild_versions(&text, &edit.package, &edit.from)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if !ranges.is_empty() {
            let new = replaced(&text, ranges, &edit.to);
            std::fs::write(path, new).map_err(|e| e.to_string())?;
            changed += 1;
        }
    }
    if changed == 0 {
        return Err(format!(
            "no project file declares {} at {}: a transitive package needs a direct reference, \
             which fix apply does not add",
            edit.package,
            edit.from.join(", ")
        ));
    }
    let locks = dirs_with(work, "packages.lock.json");
    for dir in &locks {
        run(Command::new("dotnet").current_dir(dir).args([
            "restore",
            "--force-evaluate",
            "--nologo",
            "--verbosity",
            "quiet",
        ]))
        .map_err(|e| format!("dotnet restore: {e}"))?;
    }
    Ok(format!(
        "{} set to {} in {changed} project file(s), {} lockfile(s) restored",
        edit.package,
        edit.to,
        locks.len()
    ))
}

/// What a `pom.xml` says about one dependency.
enum PomVersion {
    Literal(std::ops::Range<usize>),
    Property(String),
}

fn child_text<'a>(node: roxmltree::Node<'a, 'a>, name: &str) -> Option<&'a str> {
    let child = node.children().find(|c| c.tag_name().name() == name)?;
    child.text().map(str::trim)
}

/// Where `group:artifact` is declared at one of `from` in a `pom.xml`.
fn pom_versions(text: &str, package: &str, from: &[String]) -> Result<Vec<PomVersion>, String> {
    let doc = roxmltree::Document::parse(text).map_err(|e| e.to_string())?;
    let Some((group, artifact)) = package.split_once(':') else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    let dependencies = doc.descendants().filter(|n| {
        n.tag_name().name() == "dependency"
            && child_text(*n, "groupId") == Some(group)
            && child_text(*n, "artifactId") == Some(artifact)
    });
    for dependency in dependencies {
        let Some(version) = dependency
            .children()
            .find(|c| c.tag_name().name() == "version")
            .and_then(|v| v.first_child())
        else {
            continue; // Managed elsewhere: dependencyManagement or a parent says it.
        };
        let value = version.text().unwrap_or_default().trim();
        if let Some(property) = value.strip_prefix("${").and_then(|v| v.strip_suffix('}')) {
            out.push(PomVersion::Property(property.to_string()));
        } else if version_is(value, from) {
            out.push(PomVersion::Literal(version.range()));
        }
    }
    Ok(out)
}

/// Where a `pom.xml`'s `<properties>` sets `property` to one of `from`.
fn pom_property(
    text: &str,
    property: &str,
    from: &[String],
) -> Result<Option<std::ops::Range<usize>>, String> {
    let doc = roxmltree::Document::parse(text).map_err(|e| e.to_string())?;
    let found = doc
        .descendants()
        .filter(|n| n.tag_name().name() == "properties")
        .flat_map(|n| n.children())
        .find(|n| n.tag_name().name() == property)
        .and_then(|n| n.first_child())
        .filter(|t| t.text().is_some_and(|v| version_is(v.trim(), from)));
    Ok(found.map(|t| t.range()))
}

/// The version in each `pom.xml` that declares the dependency, or the property it reads, which
/// may live in another module's pom. A property moves every dependency that shares it, as it
/// would by hand. Nothing runs; a transitive dependency has no declaration to change.
pub(crate) fn maven_bump(work: &Path, edit: &Edit) -> Result<String, String> {
    let poms = files_where(work, |name| name == "pom.xml");
    let mut texts = Vec::with_capacity(poms.len());
    for path in &poms {
        texts.push(fleetreach_core::repofile::read_to_string(path).map_err(|e| e.to_string())?);
    }
    let at = |path: &Path, e: String| format!("{}: {e}", path.display());
    let mut properties = Vec::new();
    let mut edits: Vec<Vec<std::ops::Range<usize>>> = vec![Vec::new(); poms.len()];
    for (index, text) in texts.iter().enumerate() {
        let declared =
            pom_versions(text, &edit.package, &edit.from).map_err(|e| at(&poms[index], e))?;
        for version in declared {
            match version {
                PomVersion::Literal(range) => edits[index].push(range),
                PomVersion::Property(name) => properties.push(name),
            }
        }
    }
    properties.sort();
    properties.dedup();
    for property in &properties {
        for (index, text) in texts.iter().enumerate() {
            let range =
                pom_property(text, property, &edit.from).map_err(|e| at(&poms[index], e))?;
            edits[index].extend(range);
        }
    }
    let mut changed = 0;
    for ((path, text), ranges) in poms.iter().zip(&texts).zip(edits) {
        if !ranges.is_empty() {
            std::fs::write(path, replaced(text, ranges, &edit.to)).map_err(|e| e.to_string())?;
            changed += 1;
        }
    }
    if changed == 0 {
        return Err(format!(
            "no pom.xml sets {} to {}: a transitive or parent-managed version has no line here \
             to change",
            edit.package,
            edit.from.join(", ")
        ));
    }
    Ok(format!(
        "{} set to {} in {changed} pom.xml file(s)",
        edit.package, edit.to
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn from(v: &str) -> Vec<String> {
        vec![v.to_string()]
    }

    #[test]
    fn yarn_entries_go_whole_and_only_the_named_package() {
        let lock = r#"# yarn lockfile v1


"@babel/core@^7.0.0":
  version "7.0.0"

lodash-es@^4.0.0:
  version "4.17.0"

lodash@^4.0.0, lodash@~4.17.0:
  version "4.17.20"
  resolved "https://example.test/lodash"
  dependencies:
    a "1"

zlib@1:
  version "1.0.0"
"#;
        let out = without_yarn_entries(lock, "lodash");
        assert!(
            !out.contains("4.17.20") && !out.contains("resolved"),
            "{out}"
        );
        assert!(
            out.contains("lodash-es@") && out.contains("zlib@1:"),
            "{out}"
        );
        let scoped = without_yarn_entries(lock, "@babel/core");
        assert!(
            !scoped.contains("7.0.0") && scoped.contains("lodash@"),
            "{scoped}"
        );
    }

    #[test]
    fn pnpm_goes_recursive_only_in_a_workspace() {
        let recursive = |dir: &Path| {
            pnpm_update(dir, "lodash")
                .get_args()
                .any(|a| a == "--recursive")
        };
        let dir = tempfile_dir("pnpm-workspace-test").unwrap();
        assert!(!recursive(&dir));
        std::fs::write(dir.join("pnpm-workspace.yaml"), "packages: []\n").unwrap();
        assert!(recursive(&dir));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_version_matches_its_normalized_form() {
        let from = ["1.9.0".to_string(), "27.0.0-jre".to_string()];
        assert!(version_is("1.9", &from));
        assert!(version_is("1.9.0.0", &from));
        assert!(version_is("27.0-jre", &from));
        assert!(!version_is("1.9.1", &from));
        assert!(!version_is("1", &from));
        assert!(!version_is("27.0-android", &from));
    }

    #[test]
    fn msbuild_versions_are_found_as_attribute_child_and_pin() {
        let text = r#"<Project>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="newtonsoft.json"><Version>12.0.1</Version></PackageReference>
    <PackageVersion Include="Newtonsoft.Json" Version="[12.0.1]" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.0" />
    <PackageReference Include="Other" Version="12.0.1" />
  </ItemGroup>
</Project>"#;
        let ranges = msbuild_versions(text, "Newtonsoft.Json", &from("12.0.1")).unwrap();
        assert_eq!(ranges.len(), 3);
        let out = replaced(text, ranges, "13.0.3");
        assert_eq!(out.matches("13.0.3").count(), 3, "{out}");
        assert!(out.contains(r#"Include="Other" Version="12.0.1""#), "{out}");
        assert!(out.contains(r#"Version="13.0.0""#), "{out}");
    }

    #[test]
    fn a_pom_changes_the_literal_or_the_property_and_nothing_else() {
        let text = r#"<project>
  <properties><jackson.version>2.9.8</jackson.version><other>2.9.8</other></properties>
  <dependencies>
    <dependency><groupId>a</groupId><artifactId>b</artifactId><version>1.0</version></dependency>
    <dependency><groupId>a</groupId><artifactId>c</artifactId><version>1.0</version></dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
  </dependencies>
</project>"#;
        let literal = pom_versions(text, "a:b", &from("1.0")).unwrap();
        let [PomVersion::Literal(range)] = literal.as_slice() else {
            panic!("expected one literal");
        };
        let out = replaced(text, vec![range.clone()], "1.1");
        assert!(
            out.contains("<artifactId>b</artifactId><version>1.1<"),
            "{out}"
        );
        assert!(
            out.contains("<artifactId>c</artifactId><version>1.0<"),
            "{out}"
        );

        let package = "com.fasterxml.jackson.core:jackson-databind";
        let property = pom_versions(text, package, &from("2.9.8")).unwrap();
        let [PomVersion::Property(name)] = property.as_slice() else {
            panic!("expected one property");
        };
        let range = pom_property(text, name, &from("2.9.8")).unwrap().unwrap();
        let out = replaced(text, vec![range], "2.9.10");
        assert!(out.contains("<jackson.version>2.9.10<"), "{out}");
        assert!(out.contains("<other>2.9.8<"), "{out}");
        // A property already past the vulnerable version is not moved.
        assert!(pom_property(text, name, &from("2.9.9")).unwrap().is_none());
    }
}
