//! Read NuGet dependencies straight from MSBuild files, for .NET projects that never enabled
//! `packages.lock.json`:
//!
//! - legacy `packages.config` (non-SDK projects): every installed package, transitive ones
//!   included, so full coverage;
//! - `*.csproj` / `*.fsproj` / `*.vbproj` `PackageReference` items, with central package
//!   management (`Directory.Packages.props` `PackageVersion`, `GlobalPackageReference`,
//!   `VersionOverride`) and simple `$(Property)` substitution from the project and the nearest
//!   `Directory.Build.props`: declared dependencies only, so direct-only coverage.
//!
//! No MSBuild evaluation beyond that: conditions are ignored (every item is read, which can
//! only add a finding, never hide one), and an `<Import>` of another file is named as a
//! coverage gap rather than followed. A version that is a range or floating (`[1,2)`, `1.*`),
//! or a property that cannot be resolved, is never guessed: the package is listed as
//! unresolved. A bare version (`1.2.3`) is NuGet's minimum, which restore resolves to that
//! exact release when it exists, so it is matched as installed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use roxmltree::{Document, Node};

use crate::lockfile::InstalledPackage;
use crate::version::parse_nuget_version;

/// MSBuild project files the feeder reads.
const PROJECT_EXTENSIONS: &[&str] = &["csproj", "fsproj", "vbproj"];

/// The project files directly in `dir`, sorted.
pub(crate) fn project_files(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| PROJECT_EXTENSIONS.iter().any(|x| e.eq_ignore_ascii_case(x)))
        })
        .collect();
    found.sort();
    found
}

/// A file that does not parse as XML, or another reason a file could not be used.
#[derive(Debug)]
pub(crate) struct XmlError(pub String);

impl std::fmt::Display for XmlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<XmlError> for std::io::Error {
    fn from(e: XmlError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.0)
    }
}

fn parse_xml(text: &str) -> Result<Document<'_>, XmlError> {
    // MSBuild files are often written with a UTF-8 byte-order mark.
    Document::parse(text.trim_start_matches('\u{feff}')).map_err(|e| XmlError(e.to_string()))
}

/// `packages.config`: `<package id="X" version="1.2.3" />` for every installed package.
///
/// # Errors
///
/// [`XmlError`] if the file is not XML: failing closed.
pub(crate) fn parse_packages_config(text: &str) -> Result<Vec<InstalledPackage>, XmlError> {
    let doc = parse_xml(text)?;
    Ok(doc
        .descendants()
        .filter(|n| n.has_tag_name("package"))
        .filter_map(|n| {
            Some(InstalledPackage {
                name: n.attribute("id")?.trim().to_ascii_lowercase(),
                version: n.attribute("version")?.trim().to_string(),
                // Every package is listed (and upgraded) here explicitly.
                direct: true,
            })
        })
        .collect())
}

/// What a project file declares.
#[derive(Debug, Default)]
pub(crate) struct Declared {
    /// Packages whose version resolved to one release (lowercase name, version).
    pub packages: Vec<InstalledPackage>,
    /// Packages whose version is a range, floating, missing or an unresolved property.
    pub unresolved: Vec<String>,
    /// `<Import Project="…">` targets that were not followed.
    pub imports: Vec<String>,
    /// Every declared name (lowercase) with its version text when it is a literal one, for
    /// comparing against `project.assets.json`.
    pub declared: BTreeMap<String, Option<String>>,
}

/// The MSBuild context around a project: properties and centrally managed versions from the
/// nearest `Directory.Build.props` and `Directory.Packages.props` at or above it.
#[derive(Default)]
struct Context {
    properties: BTreeMap<String, String>,
    central: BTreeMap<String, String>,
    /// `PackageReference` items from `Directory.Build.props`, applying to every project below.
    inherited: Vec<Item>,
    /// `GlobalPackageReference` items, applying to every project that uses central versions.
    global: Vec<Item>,
    imports: Vec<String>,
}

#[derive(Debug, Clone)]
struct Item {
    name: String,
    version: Option<String>,
    version_override: Option<String>,
}

/// Read a project file and its `Directory.*.props` context.
///
/// # Errors
///
/// [`XmlError`] if the project file or a props file it depends on is not XML: failing
/// closed, as `dotnet restore` would.
pub(crate) fn read_project(path: &Path) -> Result<Declared, XmlError> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut ctx = Context::default();
    if let Some(props) = nearest_upward(dir, "Directory.Build.props") {
        let text = read(&props)?;
        let doc = parse_xml(&text)?;
        collect_properties(&doc, &mut ctx.properties);
        ctx.inherited.extend(items(&doc, "PackageReference"));
        ctx.imports.extend(imports(&doc, &props));
    }
    if let Some(props) = nearest_upward(dir, "Directory.Packages.props") {
        let text = read(&props)?;
        let doc = parse_xml(&text)?;
        collect_properties(&doc, &mut ctx.properties);
        for item in items(&doc, "PackageVersion") {
            if let Some(version) = item.version {
                ctx.central.insert(item.name, version);
            }
        }
        ctx.global.extend(items(&doc, "GlobalPackageReference"));
        ctx.imports.extend(imports(&doc, &props));
    }
    let text = read(path)?;
    let doc = parse_xml(&text)?;
    collect_properties(&doc, &mut ctx.properties);
    // A project can opt out of central versions (`ManagePackageVersionsCentrally` false, the
    // last definition winning as in MSBuild); it then pins its own and gets no global items.
    let central = ctx
        .properties
        .get("managepackageversionscentrally")
        .is_none_or(|v| !v.eq_ignore_ascii_case("false"));
    if !central {
        ctx.central.clear();
        ctx.global.clear();
    }
    let mut all = ctx.inherited.clone();
    all.extend(ctx.global.iter().cloned());
    all.extend(items(&doc, "PackageReference"));
    // `Update` items change the version of an item declared elsewhere.
    for update in updates(&doc) {
        if let Some(item) = all.iter_mut().find(|i| i.name == update.name) {
            item.version = update.version.or(item.version.take());
        }
    }

    let mut out = Declared {
        imports: ctx.imports.clone(),
        ..Declared::default()
    };
    out.imports.extend(imports(&doc, path));
    for item in all {
        let raw = item
            .version_override
            .clone()
            .or(item.version.clone())
            .or_else(|| ctx.central.get(&item.name).cloned());
        let version = raw.as_deref().and_then(|v| expand(v, &ctx.properties));
        let pinned = version.as_deref().and_then(single_version);
        out.declared.insert(item.name.clone(), pinned.clone());
        match pinned {
            Some(version) => out.packages.push(InstalledPackage {
                name: item.name,
                version,
                direct: true,
            }),
            None => out.unresolved.push(item.name),
        }
    }
    out.unresolved.sort();
    out.unresolved.dedup();
    Ok(out)
}

fn read(path: &Path) -> Result<String, XmlError> {
    std::fs::read_to_string(path).map_err(|e| XmlError(format!("{}: {e}", path.display())))
}

/// The nearest `name` in `dir` or an ancestor, stopping at the repository root (the first
/// directory holding `.git`), as MSBuild finds `Directory.*.props` without leaving the repo.
fn nearest_upward(dir: &Path, name: &str) -> Option<PathBuf> {
    for ancestor in dir.ancestors() {
        let candidate = ancestor.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
        if ancestor.join(".git").exists() {
            break;
        }
    }
    None
}

/// `<PropertyGroup><Name>value</Name></PropertyGroup>`, later definitions winning.
fn collect_properties(doc: &Document<'_>, into: &mut BTreeMap<String, String>) {
    for group in doc
        .descendants()
        .filter(|n| n.has_tag_name("PropertyGroup"))
    {
        for prop in group.children().filter(Node::is_element) {
            let value = prop.text().unwrap_or("").trim().to_string();
            into.insert(prop.tag_name().name().to_ascii_lowercase(), value);
        }
    }
}

/// Items `<tag Include="Name" Version="…" />` (version as an attribute or child element).
fn items(doc: &Document<'_>, tag: &str) -> Vec<Item> {
    doc.descendants()
        .filter(|n| n.has_tag_name(tag))
        .filter_map(|n| {
            let name = n.attribute("Include")?.trim();
            // `Include="A;B"` declares several items.
            Some(
                name.split(';')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|name| Item {
                        name: name.to_ascii_lowercase(),
                        version: value(n, "Version"),
                        version_override: value(n, "VersionOverride"),
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .flatten()
        .collect()
}

/// `<PackageReference Update="Name" Version="…" />` items.
fn updates(doc: &Document<'_>) -> Vec<Item> {
    doc.descendants()
        .filter(|n| n.has_tag_name("PackageReference"))
        .filter_map(|n| {
            Some(Item {
                name: n.attribute("Update")?.trim().to_ascii_lowercase(),
                version: value(n, "Version"),
                version_override: None,
            })
        })
        .collect()
}

/// An attribute, else a child element of that name.
fn value(node: Node<'_, '_>, name: &str) -> Option<String> {
    node.attribute(name)
        .map(str::to_string)
        .or_else(|| {
            node.children()
                .find(|c| c.has_tag_name(name))
                .and_then(|c| c.text())
                .map(str::to_string)
        })
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// `<Import Project="…" />` other than SDK imports, named relative to their file.
fn imports(doc: &Document<'_>, file: &Path) -> Vec<String> {
    let base = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    doc.descendants()
        .filter(|n| n.has_tag_name("Import"))
        .filter(|n| n.attribute("Sdk").is_none())
        .filter_map(|n| n.attribute("Project"))
        .map(|p| format!("{p} (imported by {base})"))
        .collect()
}

/// Substitute `$(Name)` properties (case-insensitive, as MSBuild); `None` if any stays
/// unresolved.
fn expand(text: &str, properties: &BTreeMap<String, String>) -> Option<String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("$(") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find(')')?;
        let value = properties.get(&after[..end].trim().to_ascii_lowercase())?;
        if value.contains("$(") {
            return None; // nested properties are not evaluated
        }
        out.push_str(value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out.trim().to_string())
}

/// The one release a version text resolves to: a bare version (`1.2.3`, NuGet's minimum,
/// which restore picks) or an exact range (`[1.2.3]`). Ranges and floating versions resolve
/// to whatever is newest at restore time, so they are not one release.
fn single_version(text: &str) -> Option<String> {
    let text = text.trim();
    let exact = text
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .filter(|t| !t.contains(','));
    let candidate = exact.unwrap_or(text).trim();
    if candidate.contains(['*', ',', '(', ')', '[', ']', ' ']) {
        return None;
    }
    parse_nuget_version(candidate).map(|_| candidate.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fr-msbuild-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        dir
    }

    fn rows(d: &Declared) -> Vec<(&str, &str)> {
        let mut rows: Vec<_> = d
            .packages
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        rows.sort_unstable();
        rows
    }

    #[test]
    fn plain_project_with_literal_versions() {
        let dir = scratch("plain");
        let csproj = dir.join("App.csproj");
        std::fs::write(
            &csproj,
            "\u{feff}<Project Sdk=\"Microsoft.NET.Sdk\">\n<ItemGroup>\n\
             <PackageReference Include=\"Newtonsoft.Json\" Version=\"12.0.1\" />\n\
             <PackageReference Include=\"Serilog\"><Version>2.10.0</Version></PackageReference>\n\
             <PackageReference Include=\"Polly\" Version=\"7.*\" />\n\
             <PackageReference Include=\"Dapper\" Version=\"[2.0.0, 3.0.0)\" />\n\
             <PackageReference Include=\"Exact\" Version=\"[1.0.0]\" />\n\
             </ItemGroup>\n</Project>\n",
        )
        .unwrap();
        let d = read_project(&csproj).unwrap();
        assert_eq!(
            rows(&d),
            vec![
                ("exact", "1.0.0"),
                ("newtonsoft.json", "12.0.1"),
                ("serilog", "2.10.0")
            ]
        );
        assert_eq!(d.unresolved, vec!["dapper", "polly"]);
        assert!(d.imports.is_empty());
    }

    #[test]
    fn central_package_management_with_properties() {
        let dir = scratch("cpm");
        std::fs::create_dir_all(dir.join("src/App")).unwrap();
        std::fs::write(
            dir.join("Directory.Packages.props"),
            "<Project><PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>\
             <ItemGroup>\
             <PackageVersion Include=\"Newtonsoft.Json\" Version=\"12.0.1\" />\
             <PackageVersion Include=\"Microsoft.Data.SqlClient\" Version=\"$(SqlVersion)\" />\
             <PackageVersion Include=\"Missing.Prop\" Version=\"$(Nope)\" />\
             <GlobalPackageReference Include=\"StyleCop.Analyzers\" Version=\"1.1.118\" />\
             </ItemGroup></Project>",
        )
        .unwrap();
        std::fs::write(
            dir.join("Directory.Build.props"),
            "<Project><PropertyGroup><SqlVersion>5.1.0</SqlVersion></PropertyGroup>\
             <Import Project=\"build/common.props\" /></Project>",
        )
        .unwrap();
        let csproj = dir.join("src/App/App.csproj");
        std::fs::write(
            &csproj,
            "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup>\
             <PackageReference Include=\"Newtonsoft.Json\" VersionOverride=\"13.0.1\" />\
             <PackageReference Include=\"Microsoft.Data.SqlClient\" />\
             <PackageReference Include=\"Missing.Prop\" />\
             <PackageReference Include=\"Not.Managed\" />\
             </ItemGroup></Project>",
        )
        .unwrap();
        let d = read_project(&csproj).unwrap();
        assert_eq!(
            rows(&d),
            vec![
                ("microsoft.data.sqlclient", "5.1.0"),
                ("newtonsoft.json", "13.0.1"),
                ("stylecop.analyzers", "1.1.118"),
            ]
        );
        assert_eq!(d.unresolved, vec!["missing.prop", "not.managed"]);
        assert_eq!(
            d.imports,
            vec!["build/common.props (imported by Directory.Build.props)"]
        );
    }

    #[test]
    fn a_project_can_opt_out_of_central_versions() {
        let dir = scratch("optout");
        std::fs::write(
            dir.join("Directory.Packages.props"),
            "<Project><PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>\
             <ItemGroup><PackageVersion Include=\"A\" Version=\"2.0.0\" />\
             <GlobalPackageReference Include=\"G\" Version=\"1.0.0\" /></ItemGroup></Project>",
        )
        .unwrap();
        let csproj = dir.join("App.csproj");
        std::fs::write(
            &csproj,
            "<Project><PropertyGroup><ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally></PropertyGroup>\
             <ItemGroup><PackageReference Include=\"A\" Version=\"1.5.0\" />\
             <PackageReference Include=\"B\" /></ItemGroup></Project>",
        )
        .unwrap();
        let d = read_project(&csproj).unwrap();
        assert_eq!(rows(&d), vec![("a", "1.5.0")]);
        assert_eq!(d.unresolved, vec!["b"]);
    }

    #[test]
    fn props_lookup_stops_at_the_repo_root() {
        let dir = scratch("bound");
        let inner = dir.join("repo");
        std::fs::create_dir_all(inner.join(".git")).unwrap();
        std::fs::write(
            dir.join("Directory.Packages.props"),
            "<Project><ItemGroup><PackageVersion Include=\"A\" Version=\"1.0.0\" /></ItemGroup></Project>",
        )
        .unwrap();
        let csproj = inner.join("App.csproj");
        std::fs::write(
            &csproj,
            "<Project><ItemGroup><PackageReference Include=\"A\" /></ItemGroup></Project>",
        )
        .unwrap();
        let d = read_project(&csproj).unwrap();
        assert!(d.packages.is_empty());
        assert_eq!(d.unresolved, vec!["a"]);
    }

    #[test]
    fn packages_config_lists_every_package() {
        let pkgs = parse_packages_config(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<packages>\n\
             <package id=\"Newtonsoft.Json\" version=\"9.0.1\" targetFramework=\"net45\" />\n\
             <package id=\"jQuery\" version=\"1.7.1\" developmentDependency=\"true\" />\n\
             </packages>",
        )
        .unwrap();
        let rows: Vec<(&str, &str)> = pkgs
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        assert_eq!(
            rows,
            vec![("newtonsoft.json", "9.0.1"), ("jquery", "1.7.1")]
        );
        assert!(parse_packages_config("<packages><package").is_err());
    }

    #[test]
    fn malformed_project_fails_closed() {
        let dir = scratch("bad");
        let csproj = dir.join("Bad.csproj");
        std::fs::write(&csproj, "<Project><ItemGroup>").unwrap();
        assert!(read_project(&csproj).is_err());
    }
}
