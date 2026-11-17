//! Read a Gradle build without running it: `gradle/libs.versions.toml` and the literal
//! declarations in `*.gradle` and `*.gradle.kts`, resolved through the POM resolver with
//! Gradle's rule that the highest requested version wins. Build scripts are programs, so
//! anything that is not a literal (a helper call, an undefined variable, `latest.release`) is
//! named in [`Resolution::missing`]; a range or a prefix version (`3.19+`) is settled from the
//! version listing. Each build file is resolved alone, since two subprojects can pin
//! different versions.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use crate::resolve::{
    resolve_gradle_module, Enforced, PomSource, Resolution, ResolvedDep, RuleCondition, VersionRule,
};

const SKIPPED_DIRS: &[&str] = &[".git", ".gradle", "build", "node_modules", "target", "out"];
const MAX_FILES: usize = 2000;
const MAX_FILE_BYTES: u64 = 4 << 20;

/// Whether `dir` is the root of a Gradle build.
#[must_use]
pub fn has_gradle_build(dir: &Path) -> bool {
    [
        "settings.gradle",
        "settings.gradle.kts",
        "build.gradle",
        "build.gradle.kts",
    ]
    .iter()
    .any(|f| dir.join(f).is_file())
}

/// Resolve every build file under `dir`, and catalog entries no build file names. An unused
/// entry still counts, as development only, since a convention plugin can reach it in ways not
/// read here.
#[must_use]
pub fn resolve_gradle(dir: &Path, source: &dyn PomSource) -> Resolution {
    let mut missing = BTreeSet::new();
    let mut scripts = build_scripts(dir, &mut missing);
    applied_scripts(&mut scripts);
    project_blocks(dir, &mut scripts);
    project_accessors(dir, &mut scripts);
    spring_boot_boms(dir, &mut scripts);
    // spring-boot's docs project depends on every published Java project, through a
    // `gradle.projectsEvaluated { rootProject.subprojects.findAll { } .each { } }` hook.
    projects_evaluated(dir, &mut scripts, &mut missing);
    let named = named_catalogs(dir);
    for (name, _) in &named {
        for (_, text) in &mut scripts {
            *text = catalog_accessors(text, name);
        }
    }
    let mut vars = properties(&dir.join("gradle.properties"));
    // The wrapper decides which Gradle runs the build: axion picks its Spock by
    // `GradleVersion.current().version.startsWith("9.")`.
    if let Some(version) = wrapper_version(dir) {
        vars.insert(GRADLE_VERSION.to_string(), version);
    }
    // Read once branch-blind, then again with each `if` decided from what the last read
    // settled, until nothing changes: kafka's `versions["scala"]` is set in an `if` on
    // gradle.properties, and `versions["baseScala"]` in an `if` on `versions.scala`.
    let base = vars.clone();
    let constants = build_constants(dir);
    let (mut vars, mut later) = script_vars(&scripts, &constants, base.clone(), None);
    for _ in 0..4 {
        let (next, next_later) = script_vars(&scripts, &constants, base.clone(), Some(&vars));
        let settled = next == vars;
        (vars, later) = (next, next_later);
        if settled {
            break;
        }
    }
    let catalog_file = catalog_file(dir, &scripts);
    let mut doc = match fleetreach_core::repofile::read_to_string(dir.join(&catalog_file)) {
        Ok(text) => toml::from_str::<toml::Table>(&text).unwrap_or_else(|e| {
            missing.insert(format!("{catalog_file}: {e}"));
            toml::Table::new()
        }),
        Err(_) => toml::Table::new(),
    };
    // A catalog can also be declared in the settings script; its entries join the file's.
    for name in ["settings.gradle", "settings.gradle.kts"] {
        if let Ok(text) = fleetreach_core::repofile::read_to_string(dir.join(name)) {
            for (section, entries) in settings_catalog(&text) {
                let slot = doc
                    .entry(section)
                    .or_insert_with(|| toml::Value::Table(toml::Table::new()));
                if let Some(table) = slot.as_table_mut() {
                    for (key, entry) in entries {
                        table.entry(key).or_insert(entry);
                    }
                }
            }
        }
    }
    // Another named catalog (spotless's `pinnedLibs`) joins `libs` with its name before
    // each alias, as `catalog_accessors` spells its accessors.
    for (name, file) in &named {
        match fleetreach_core::repofile::read_to_string(dir.join(file))
            .map_err(|e| e.to_string())
            .and_then(|t| toml::from_str::<toml::Table>(&t).map_err(|e| e.to_string()))
        {
            Ok(other) => {
                for (section, entries) in prefixed_catalog(other, name) {
                    let slot = doc
                        .entry(section)
                        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
                    if let Some(table) = slot.as_table_mut() {
                        for (key, entry) in entries {
                            table.entry(key).or_insert(entry);
                        }
                    }
                }
            }
            Err(e) => {
                missing.insert(format!("{file}: {e}"));
            }
        }
    }
    let line_boms = line_scripts_boms(dir, &doc);
    let catalog = Catalog::from_doc(&toml::Value::Table(doc));
    for (alias, version) in &catalog.versions {
        vars.entry(format!("libs.versions.{alias}"))
            .or_insert_with(|| version.clone());
    }
    // A library's own version, for `eachDependency` rules that name it (PlotSquared's
    // `useVersion(checkNotNull(libs.paper.orNull?.version))`).
    for (alias, c) in &catalog.libraries {
        if let Some(version) = &c.version {
            vars.entry(format!("{LIBRARY_VERSION}{}", accessor(alias)))
                .or_insert_with(|| version.clone());
        }
    }
    // `val kotlinVersion = libs.versions.kotlin.get()`, once the catalog is read.
    for (name, key) in later {
        if let Some(value) = vars.get(&key).cloned() {
            vars.entry(name).or_insert(value);
        }
    }
    let mut plugins = catalog.plugins.clone();
    // A convention plugin often applies Kotlin, with its version set on the plugin's library.
    if let Some(c) = catalog
        .libraries
        .values()
        .find(|c| c.artifact == "kotlin-gradle-plugin")
    {
        if let Some(version) = &c.version {
            plugins.insert(KOTLIN_JVM.to_string(), version.clone());
        }
    }
    // Some script applies the Spring dependency-management plugin, by id or through a catalog
    // alias (interview-guide's `alias(libs.plugins.spring.dependency.management)`).
    let mut spring_dm = scripts.iter().any(|(_, t)| t.contains(SPRING_DM));
    for (file, text) in &scripts {
        // What buildSrc or build-logic depends on is on the build's classpath too
        // (spring-framework's buildSrc `implementation` of kotlin-gradle-plugin).
        let build_logic = file.starts_with("buildSrc/") || file.starts_with("build-logic/");
        for line in text.lines() {
            let line = line.trim();
            if build_logic {
                let rest = ["implementation", "api", "compileOnly", "runtimeOnly"]
                    .iter()
                    .find_map(|c| line.strip_prefix(c))
                    .filter(|r| r.starts_with([' ', '(']));
                if let Some((id, version)) =
                    rest.and_then(|r| classpath_plugin(&format!("classpath{r}"), &vars))
                {
                    plugins.entry(id.to_string()).or_insert(version);
                }
            }
            if let Some((id, version)) = plugin_line(line, &catalog, &vars) {
                spring_dm |= id == SPRING_DM;
                if let Some(version) = version {
                    plugins.entry(id).or_insert(version);
                }
            }
            // `buildscript { dependencies { classpath "g:a:v" } }` puts a plugin on the
            // build's classpath at that version; `apply plugin:` then applies it.
            if let Some((id, version)) = classpath_plugin(line, &vars) {
                plugins.entry(id.to_string()).or_insert(version);
            }
        }
    }
    // `pluginManagement { plugins { kotlin("jvm") version "1.8.0" } }` in the settings sets
    // the version a build file's bare `kotlin("jvm")` applies (Charlatano).
    for name in ["settings.gradle", "settings.gradle.kts"] {
        let Ok(text) = fleetreach_core::repofile::read_to_string(dir.join(name)) else {
            continue;
        };
        for line in strip_comments(&text).lines() {
            if let Some((id, Some(version))) = plugin_line(line.trim(), &catalog, &vars) {
                plugins.entry(id).or_insert(version);
            }
        }
    }
    let mut extended_by = BTreeMap::new();
    for (_, text) in &scripts {
        for line in text.lines() {
            extends_from(line.trim(), &mut extended_by);
        }
    }
    let lombok = scripts.iter().find_map(|(_, t)| lombok_extension(t, &vars));
    let local_configurations = local_configurations(dir);
    let mut lists: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut lists_twice = BTreeSet::new();
    for (_, text) in &scripts {
        for (name, items) in list_variables(text) {
            match lists.get(&name) {
                Some(known) if *known != items => {
                    lists_twice.insert(name);
                }
                _ => {
                    lists.insert(name, items);
                }
            }
        }
    }
    for name in lists_twice {
        lists.remove(&name);
    }
    let mut context = Context {
        lists,
        vars,
        catalog,
        lombok,
        plugins,
        used: BTreeSet::new(),
        exported: true,
        extended_by,
        spring_dm,

        processor: false,
        runtime_only: false,
        local: false,
        local_configurations,
        custom: false,
        dependency_set: None,
    };
    // The kordamp enforcer's `ForceDependencies` rule in the settings forces its versions on
    // every configuration of every project (jreleaser).
    let settings_forced: Vec<(Coordinate, bool)> = ["settings.gradle", "settings.gradle.kts"]
        .iter()
        .filter_map(|f| fleetreach_core::repofile::read_to_string(dir.join(f)).ok())
        .flat_map(|t| forced_versions(&t, &context.vars, &mut missing))
        .collect();
    // Precompiled script plugins (convention plugins) by plugin id, and the build logic's
    // own plugin classes, as the declarations they add.
    let binary = binary_plugins(dir, &scripts);
    let mut conventions: BTreeMap<String, usize> = scripts
        .iter()
        .enumerate()
        .filter_map(|(i, (file, text))| convention_id(file, text).map(|id| (id, i)))
        .collect();
    for (id, file, text) in binary {
        if let std::collections::btree_map::Entry::Vacant(slot) = conventions.entry(id) {
            slot.insert(scripts.len());
            scripts.push((file, text));
        }
    }
    // LINE's gradle-scripts put every `[boms]` entry of the catalog in the platform project
    // all configurations of every project extend (armeria).
    if !line_boms.is_empty() {
        if let Some((_, text)) = scripts
            .iter_mut()
            .find(|(f, _)| f == "build.gradle" || f == "build.gradle.kts")
        {
            text.push_str("\nallprojects {\n    dependencies {\n");
            for bom in &line_boms {
                text.push_str(&format!("        implementation platform('{bom}')\n"));
            }
            text.push_str("    }\n}\n");
        }
    }
    // LINE's gradle-scripts: `configure(projectsWithFlags('java')) { ... }` configures each
    // project the settings script includes with those flags (`includeWithFlags ':p', 'java'`),
    // so the root's block is read in each of them (armeria's `:ai:mcp`, flagged `java17`).
    line_flag_blocks(dir, &mut scripts);
    // Each file's own Java toolchain (caffeine's `java.toolchain { languageVersion =
    // javaVersion() }`, 11 by default), the project's toolchain version as `TOOLCHAIN` in
    // conditions, decided per project once its conventions apply, and `${libs.x.get().module}`
    // as the module it names.
    let toolchains: Vec<Option<Option<u32>>> = scripts
        .iter()
        .map(|(file, text)| script_toolchain(dir, file, text, &context.vars))
        .collect();
    for (_, text) in &mut scripts {
        *text = text.replace("java.toolchain.languageVersion.get().asInt()", TOOLCHAIN);
        *text = catalog_modules(text, &context.catalog);
    }
    let mut modules: Vec<Module> = Vec::new();
    for (i, (file, text)) in scripts.iter().enumerate() {
        let mut module = read_script(text, &mut context);
        module.toolchain = toolchains.get(i).copied().flatten();
        let (forced, forced_when) = forced_versions_when(text, &context.vars, &mut missing);
        module.forced = forced;
        module.forced_when = forced_when;
        module.forced.extend(settings_forced.iter().cloned());
        for (rule, test_only, shared) in version_rules(text, &context.vars) {
            if shared {
                module.shared.rules.push((rule, test_only));
            } else {
                module.rules.push((rule, test_only));
            }
        }
        for (ex, test_only, shared) in configuration_exclusions(text) {
            // As with shared declarations, the root file keeps its own copy.
            if shared {
                module.shared.excluded.push((ex.clone(), test_only));
            }
            module.excluded.push((ex, test_only));
        }
        // Build logic runs at build time and never ships; a convention plugin's own
        // declarations belong to the projects that apply it.
        let convention = conventions.values().any(|&c| c == i);
        if (file.starts_with("buildSrc/") || file.starts_with("build-logic/")) && !convention {
            module.deps.iter_mut().for_each(|d| d.scope = "test");
        }
        gretty_apis(text, &context, &mut module);
        for line in std::mem::take(&mut module.unread) {
            missing.insert(format!("{file}: {line}"));
        }
        modules.push(module);
    }
    // The root build's `subprojects { }` and `allprojects { }` apply to every other build file
    // (BOM imports and versions there are how most multi-project builds manage versions).
    if let Some(root) = scripts
        .iter()
        .position(|(f, _)| f == "build.gradle" || f == "build.gradle.kts")
    {
        let shared = std::mem::take(&mut modules[root].shared);
        for (i, (file, _)) in scripts.iter().enumerate() {
            if i == root || file.starts_with("buildSrc/") || file.starts_with("build-logic/") {
                continue;
            }
            let module = &mut modules[i];
            module.shared_from = Some(module.platforms.len());
            module.platforms.extend_from_slice(&shared.platforms);
            module.constraints.extend_from_slice(&shared.constraints);
            module.deps.extend_from_slice(&shared.deps);
            module.dm |= shared.dm;
            module.rules.extend_from_slice(&shared.rules);
            module.excluded.extend_from_slice(&shared.excluded);
            module
                .project_platforms
                .extend_from_slice(&shared.project_platforms);
        }
    }
    apply_conventions(&conventions, &mut modules);
    // What holds only for some toolchain versions, decided for each project's own; a project
    // whose toolchain is not read takes none of it.
    for m in &mut modules {
        let version = m.toolchain.flatten();
        let holds = |t: &Toolchain| version.is_some_and(|v| toolchain_holds(*t, v));
        m.rules
            .retain(|(r, _)| r.toolchain.is_none_or(|t| holds(&t)));
        for (c, test_only, t) in std::mem::take(&mut m.forced_when) {
            if holds(&t) {
                m.forced.push((c, test_only));
            }
        }
    }
    // The Kotlin plugin adds the `kotlin-test` variant for the framework the tests run on
    // next to a `kotlin-test` dependency: JUnit 5 with `useJUnitPlatform()`, TestNG with
    // `useTestNG()`, else JUnit 4 (grpc-spring's kotlin-test-junit5, moshi's kotlin-test-junit).
    let framework = |text: &str| {
        if text.contains("useJUnitPlatform") {
            Some("junit5")
        } else if text.contains("useTestNG") {
            Some("testng")
        } else if text.contains("useJUnit") {
            Some("junit")
        } else {
            None
        }
    };
    let root_framework = scripts
        .iter()
        .find(|(f, _)| f == "build.gradle" || f == "build.gradle.kts")
        .and_then(|(_, t)| framework(t));
    for (module, (_, text)) in modules.iter_mut().zip(&scripts) {
        if !module
            .applied
            .iter()
            .any(|id| id == KOTLIN_JVM || id == "kotlin")
        {
            continue;
        }
        // The Kotlin plugin gives a Kotlin library declared with no version its own version
        // (spring-integration-samples' `org.jetbrains.kotlin:kotlin-reflect`, under the
        // dependency-management plugin too).
        if let Some(kotlin) = context.plugins.get(KOTLIN_JVM) {
            for d in &mut module.deps {
                if d.coordinate.group == "org.jetbrains.kotlin" && d.coordinate.version.is_none() {
                    d.coordinate.version = Some(kotlin.clone());
                }
            }
        }
        let variant = framework(text).or(root_framework).unwrap_or("junit");
        let added: Vec<Declared> = module
            .deps
            .iter()
            .filter(|d| {
                d.coordinate.group == "org.jetbrains.kotlin"
                    && d.coordinate.artifact == "kotlin-test"
            })
            .map(|d| Declared {
                coordinate: Coordinate {
                    artifact: format!("kotlin-test-{variant}"),
                    ..d.coordinate.clone()
                },
                ..d.clone()
            })
            .collect();
        module.deps.extend(added);
    }
    // `platform(project(":p"))` takes the platform project's versions, by its path: the
    // directory's by default, or what the settings script names it (conductor renames every
    // child `conductor-*`, pulsar moves projects to other directories).
    let settings = ["settings.gradle", "settings.gradle.kts"]
        .iter()
        .find_map(|f| fleetreach_core::repofile::read_to_string(dir.join(f)).ok())
        .map(|t| settings_paths(&strip_comments(&t)))
        .unwrap_or_default();
    let mut by_path: BTreeMap<String, usize> = BTreeMap::new();
    for (i, (file, _)) in scripts.iter().enumerate() {
        let Some(dir) = Path::new(file).parent().and_then(Path::to_str) else {
            continue;
        };
        by_path.insert(format!(":{}", dir.replace('/', ":")), i);
    }
    for (i, (file, _)) in scripts.iter().enumerate() {
        let Some(dir) = Path::new(file).parent().and_then(Path::to_str) else {
            continue;
        };
        for (path, _) in settings.iter().filter(|(_, d)| d == dir) {
            by_path.insert(path.clone(), i);
        }
    }
    // A settings script that sets `buildFileName` names projects after their build files
    // (spring-security includes `:spring-security-core` for core/spring-security-core.gradle).
    let named_files = ["settings.gradle", "settings.gradle.kts"]
        .iter()
        .filter_map(|f| fleetreach_core::repofile::read_to_string(dir.join(f)).ok())
        .any(|t| strip_comments(&t).contains("buildFileName"));
    if named_files {
        for (i, (file, _)) in scripts.iter().enumerate() {
            let name = Path::new(file)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            let stem = name
                .strip_suffix(".gradle.kts")
                .or_else(|| name.strip_suffix(".gradle"))
                .filter(|s| *s != "build" && !s.is_empty());
            if let Some(stem) = stem {
                by_path.entry(format!(":{stem}")).or_insert(i);
            }
        }
    }
    let managed: Vec<(Vec<Coordinate>, Vec<Coordinate>, Vec<Declared>)> = modules
        .iter()
        .map(|m| {
            let (mut platforms, mut constraints) = (Vec::new(), Vec::new());
            // The platform project's own platforms are nodes of this graph too, so a BOM a
            // library's `.module` names meets the version they nest (kestra's
            // micronaut-core-bom: 5.2.3 from micronaut-validation, 5.2.22 from
            // micronaut-platform) and only the winner is listed.
            let mut nodes = Vec::new();
            // A platform project's own project platforms count too, in turn (spring-boot's
            // internal platform takes `enforcedPlatform(project(":platform:spring-boot-
            // dependencies"))`); an enforced one forces everything it reaches.
            let mut stack: Vec<(String, bool)> =
                m.project_platforms.iter().rev().cloned().collect();
            // A platform met again as an enforced one is read again, enforced: spring-boot's
            // docs project names spring-boot-dependencies as a plain platform before the
            // internal enforced one that nests it.
            let mut seen: BTreeMap<String, bool> = BTreeMap::new();
            while let Some((path, strict)) = stack.pop() {
                if seen.get(&path).is_some_and(|&was| was || !strict) {
                    continue;
                }
                seen.insert(path.clone(), strict);
                if let Some(&i) = by_path.get(&path) {
                    // `enforcedPlatform(project(...))` forces what the platform project sets.
                    let mark = |c: &Coordinate| Coordinate {
                        strict: c.strict || strict,
                        ..c.clone()
                    };
                    platforms.extend(modules[i].platforms.iter().map(mark));
                    constraints.extend(modules[i].constraints.iter().map(mark));
                    nodes.extend(modules[i].deps.iter().filter(|d| d.pom).cloned());
                    for (inner, inner_strict) in modules[i].project_platforms.iter().rev() {
                        stack.push((inner.clone(), strict || *inner_strict));
                    }
                } else {
                    missing.insert(format!(
                        "platform project `{path}` is not a build file here"
                    ));
                }
            }
            (platforms, constraints, nodes)
        })
        .collect();
    for (module, (platforms, constraints, nodes)) in modules.iter_mut().zip(managed) {
        module.platforms.extend(platforms);
        module.constraints.extend(constraints);
        module.deps.extend(nodes);
    }
    // `implementation project(":p")` puts p's own dependencies on this file's classpaths, with
    // p's platforms and constraints (Gradle publishes them with the project), through p's own
    // project dependencies too. p's `compileOnly` and test dependencies stay in p.
    let via: Vec<(Vec<Declared>, Vec<Coordinate>, Vec<Coordinate>)> = (0..modules.len())
        .map(|start| {
            let (mut deps, mut platforms, mut constraints) = (Vec::new(), Vec::new(), Vec::new());
            // A project met again through another of its configurations is read again for
            // it (spring-boot's docs: `implementation(project(p))`, then p's `optional`).
            let mut seen = BTreeSet::new();
            let mut queue: VecDeque<QueuedProject> = modules[start]
                .project_deps
                .iter()
                .filter_map(|(path, scope, _, cut, named)| match by_path.get(path) {
                    Some(&i) => Some((i, *scope, cut.clone(), false, *named)),
                    None => {
                        missing.insert(format!("project `{path}` is not a build file here"));
                        None
                    }
                })
                .collect();
            while let Some((i, scope, cut, behind, named)) = queue.pop_front() {
                if i == start || !seen.insert((i, named)) {
                    continue;
                }
                let whole = named == Named::Whole;
                let local = named == Named::Local;
                let m = &modules[i];
                // What p declares in `implementation` is on this file's runtime classpath
                // only; its `api` reaches the compile classpath too.
                // `compileOnly(project(":p"))` compiles against p's `api` only (reposilite's
                // plugins against the backend).
                let through = |own: &'static str, exported: bool| match (scope, own) {
                    (_, "test" | "provided") => None,
                    ("provided", "compile") if exported => Some(scope),
                    ("provided", _) => None,
                    ("test", _) => Some(scope),
                    ("runtime", _) | (_, "runtime") => Some("runtime"),
                    _ if !exported => Some("runtime"),
                    _ => Some("compile"),
                };
                let excluded = |c: &Coordinate| {
                    cut.iter()
                        .any(|(g, a)| (g == "*" || *g == c.group) && (a == "*" || *a == c.artifact))
                };
                for d in m
                    .deps
                    .iter()
                    .filter(|d| d.local == local && !excluded(&d.coordinate))
                {
                    if let Some(scope) = through(d.scope, d.exported || local) {
                        let mut exclusions = d.exclusions.clone();
                        exclusions.extend(cut.iter().cloned());
                        // On a test path, what p does not export (or what lies behind a
                        // project p does not export) is on the test runtime classpath only:
                        // Talaiot's tests compile against testcontainers' JNA 5.13, not the
                        // 5.19 their test-utils project puts in `implementation`.
                        let hidden = scope == "test"
                            && !whole
                            && (behind || !d.exported || d.scope == "runtime");
                        deps.push(Declared {
                            scope,
                            exclusions,
                            runtime_only: d.runtime_only || hidden,
                            ..d.clone()
                        });
                    }
                }
                let own = m.shared_from.unwrap_or(m.platforms.len());
                platforms.extend(
                    m.platforms[..own]
                        .iter()
                        .filter(|c| !c.enforced && !c.test)
                        .cloned(),
                );
                constraints.extend(
                    m.constraints
                        .iter()
                        .filter(|c| !c.enforced && !c.test)
                        .cloned(),
                );
                for (path, own, exported, more, next_named) in &m.project_deps {
                    if local {
                        break;
                    }
                    if let (Some(&j), Some(next)) = (by_path.get(path), through(own, *exported)) {
                        let mut cut = cut.clone();
                        cut.extend(more.iter().cloned());
                        let hidden =
                            next == "test" && !whole && (behind || !*exported || *own == "runtime");
                        queue.push_back((j, next, cut, hidden, *next_named));
                    }
                }
            }
            (deps, platforms, constraints)
        })
        .collect();
    for (module, (deps, platforms, constraints)) in modules.iter_mut().zip(via) {
        module.via_projects = deps;
        module.platforms.extend(platforms);
        module.constraints.extend(constraints);
    }
    let unused: Vec<Declared> = context
        .catalog
        .libraries
        .iter()
        .filter(|(alias, _)| !context.used.contains(*alias))
        .map(|(_, coordinate)| Declared {
            coordinate: coordinate.clone(),
            scope: "test",
            exclusions: Vec::new(),
            pom: false,
            exported: false,
            runtime_only: false,
            local: false,
            soft: false,
        })
        .collect();
    if !unused.is_empty() {
        modules.push(Module {
            deps: unused,
            ..Module::default()
        });
    }
    for line in std::mem::take(&mut context.catalog.unread) {
        missing.insert(format!("gradle/libs.versions.toml: {line}"));
    }

    // The Spring dependency-management plugin lets a project property override the
    // same-named property of a BOM it imports; Gradle's own `platform(...)` reads none. Only
    // the files that apply it: when none does in a way read here (a convention plugin in
    // buildSrc applies it), every file is taken to.
    if context.spring_dm && !modules.iter().any(|m| m.dm) {
        for m in &mut modules {
            m.dm = true;
        }
    }
    let no_overrides = BTreeMap::new();
    let mut graph = fleetreach_core::DepGraph::new("(root)");
    let mut packages: BTreeMap<(String, String), ResolvedDep> = BTreeMap::new();
    for module in &modules {
        if module.deps.is_empty() && module.via_projects.is_empty() {
            continue;
        }
        // Gradle resolves each configuration on its own, so a test dependency cannot raise a
        // version on the main classpath, nor a runtime one on the compile classpath. Resolve
        // the main classpath first; what only the compile classpath (without runtime
        // dependencies) or the full (test) resolution adds is off the runtime classpath.
        // What projects bring counts too (a project of only `testImplementation project(...)`).
        let every = || module.deps.iter().chain(&module.via_projects);
        let has_test = every().any(|d| d.scope == "test");
        let has_main = every().any(|d| d.scope != "test");
        let mut main = BTreeSet::new();
        let mut passes: Vec<Pass> = Vec::new();
        // A force on test configurations only leaves the main classpath to itself.
        let test_force = module.forced.iter().any(|(_, test_only)| *test_only)
            || module.rules.iter().any(|(_, test_only)| *test_only);
        // The compile classpaths differ from the runtime ones whenever a path to an artifact
        // is runtime-scoped, which a POM down the tree can decide (JavaPackager's redline
        // compiles against xz 1.4, plexus-archiver's runtime xz 1.9 is on the runtime
        // classpath only), so each is resolved on its own. With no test dependencies, the
        // test classpaths are the main ones.
        let test_managed = module
            .platforms
            .iter()
            .chain(&module.constraints)
            .any(|c| c.test);
        if has_main {
            passes.push(Pass::Main);
            passes.push(Pass::Compile);
        }
        if has_test {
            passes.push(Pass::TestCompile);
        }
        if has_test || test_force || test_managed || !has_main {
            passes.push(Pass::Full);
        }
        let split = passes.len() > 1;
        // With Kotlin applied, the Spring Boot plugin sets `kotlin.version` to the Kotlin
        // plugin's version unless the build does, so the Boot BOM's Kotlin follows it
        // (mmorpg's game-server: 2.2.0 over Boot 3.0.4's 1.7.22; its root, without Boot, 1.7.22).
        let applies = |id: &str| module.applied.iter().any(|a| a == id);
        let boot_kotlin = (applies(SPRING_BOOT)
            && applies(KOTLIN_JVM)
            && !context.vars.contains_key("kotlin.version"))
        .then(|| context.plugins.get(KOTLIN_JVM))
        .flatten()
        .map(|kotlin| {
            let mut vars = context.vars.clone();
            vars.insert("kotlin.version".to_string(), kotlin.clone());
            vars
        });
        let dm_overrides = boot_kotlin.as_ref().unwrap_or(&context.vars);
        for &pass in &passes {
            match resolve_gradle_module(
                &module.to_pom(pass),
                source,
                if module.dm {
                    dm_overrides
                } else {
                    &no_overrides
                },
                &module.enforced(pass),
                matches!(pass, Pass::Compile | Pass::TestCompile),
            ) {
                Ok(one) => {
                    missing.extend(one.missing);
                    for (from, to) in one.graph.edges() {
                        graph.add_edges(from, [to.to_string()]);
                    }
                    for mut p in one.packages {
                        let key = (p.name.clone(), p.version.clone());
                        if pass == Pass::Main {
                            main.insert(key.clone());
                        } else if split && !main.contains(&key) {
                            p.dev = true;
                        }
                        packages
                            .entry(key)
                            .and_modify(|seen| {
                                seen.direct |= p.direct;
                                seen.dev &= p.dev;
                            })
                            .or_insert(p);
                    }
                }
                Err(e) => {
                    missing.insert(e);
                }
            }
        }
    }
    Resolution {
        packages: packages.into_values().collect(),
        graph,
        missing: missing.into_iter().collect(),
    }
}

fn build_scripts(dir: &Path, missing: &mut BTreeSet<String>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                // Under `src/`, only `src/main` holds build logic (precompiled script plugins);
                // `src/test/resources` and the like hold fixture builds Gradle never runs.
                let fixtures = current.file_name().is_some_and(|p| p == "src") && name != "main";
                if !SKIPPED_DIRS.contains(&name.as_str()) && !fixtures {
                    stack.push(entry.path());
                }
                continue;
            }
            let script = name.ends_with(".gradle") || name.ends_with(".gradle.kts");
            if !kind.is_file() || !script || name.starts_with("settings.gradle") {
                continue;
            }
            let path = entry.path();
            let shown = path
                .strip_prefix(dir)
                .unwrap_or(&path)
                .display()
                .to_string();
            if out.len() >= MAX_FILES || entry.metadata().map_or(true, |m| m.len() > MAX_FILE_BYTES)
            {
                missing.insert(format!("{shown}: too large or too many to read"));
                continue;
            }
            match fleetreach_core::repofile::read_to_string(&path) {
                Ok(text) => out.push((shown, strip_comments(&text))),
                Err(e) => {
                    missing.insert(format!("{shown}: {e}"));
                }
            }
        }
    }
    out.sort();
    out
}

/// The TOML file of the `libs` catalog: `gradle/libs.versions.toml`, Gradle's default, or
/// the one a script creating `libs` names, by `from(files("x.toml"))` or as the file its own
/// code reads (armeria's `dependencies.toml`).
fn catalog_file(dir: &Path, scripts: &[(String, String)]) -> String {
    const DEFAULT: &str = "gradle/libs.versions.toml";
    if dir.join(DEFAULT).is_file() {
        return DEFAULT.to_string();
    }
    let settings = ["settings.gradle", "settings.gradle.kts"]
        .iter()
        .filter_map(|f| fleetreach_core::repofile::read_to_string(dir.join(f)).ok())
        .map(|t| strip_comments(&t))
        .collect::<Vec<_>>();
    let texts = settings
        .iter()
        .map(String::as_str)
        .chain(scripts.iter().map(|(_, t)| t.as_str()));
    for text in texts {
        let creates = [
            "create(\"libs\")",
            "create('libs')",
            "register(\"libs\")",
            "register('libs')",
        ]
        .iter()
        .any(|c| text.contains(c));
        if !creates {
            continue;
        }
        let named: Vec<String> = strings(text)
            .into_iter()
            .filter(|s| s.ends_with(".toml"))
            .map(|s| {
                let mut s = s.as_str();
                for p in [
                    "${rootProject.projectDir}/",
                    "${rootDir}/",
                    "$rootDir/",
                    "${projectDir}/",
                ] {
                    s = s.strip_prefix(p).unwrap_or(s);
                }
                s.to_string()
            })
            .collect();
        if let [one] = named.as_slice() {
            if !one.contains('$') && dir.join(one).is_file() {
                return one.clone();
            }
        }
    }
    DEFAULT.to_string()
}

/// The `[boms]` of a catalog read by LINE's gradle-scripts (`gradle/scripts/lib/
/// common-dependencies.gradle` applying `dependenciesTomlBoms`), as `g:a:v`: its own section,
/// beside `[libraries]`, each entry a BOM every project's classpaths take. A BOM whose version
/// is not literal or a `version.ref` is left out, as the scripts skip it.
/// The build-logic plugins buildSrc registers: (id, the class's simple name, its source).
fn plugin_classes(dir: &Path, scripts: &[(String, String)]) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for (file, text) in scripts {
        if !file.starts_with("buildSrc/") || !text.contains("implementationClass") {
            continue;
        }
        let base = Path::new(file).parent().unwrap_or(Path::new(""));
        let mut id = None;
        for line in text.lines().map(str::trim) {
            let value = |key: &str| {
                let rest = line.strip_prefix(key)?.trim_start();
                let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
                quoted(rest).map(|(v, _)| v.to_string())
            };
            if let Some(v) = value("id") {
                id = Some(v);
            } else if let Some(class) = value("implementationClass") {
                let (Some(id), Some((_, source))) = (id.take(), plugin_class(dir, base, &class))
                else {
                    continue;
                };
                let simple = class.rsplit('.').next().unwrap_or(&class).to_string();
                out.push((id, simple, source));
            }
        }
    }
    out
}

/// The plugin ids that give a project plugin class `class` (`JavaPlugin`, or a build-logic
/// class such as `OptionalDependenciesPlugin`): Gradle's own ids for it, and each build-logic
/// id whose class is it or applies it (`project.getPlugins().apply(MavenPublishPlugin.class)`),
/// in turn. `None` for a class neither Gradle's table here nor build logic knows.
fn ids_giving(class: &str, classes: &[(String, String, String)]) -> Option<BTreeSet<String>> {
    let (gradle_ids, mut wanted): (&[&str], BTreeSet<&str>) = match class {
        "JavaPlugin" => (
            &[
                "java",
                "java-library",
                "war",
                "groovy",
                "java-gradle-plugin",
                "org.jetbrains.kotlin.jvm",
            ],
            BTreeSet::from([
                "JavaPlugin",
                "JavaLibraryPlugin",
                "WarPlugin",
                "GroovyPlugin",
            ]),
        ),
        "JavaLibraryPlugin" => (&["java-library"], BTreeSet::from(["JavaLibraryPlugin"])),
        "MavenPublishPlugin" => (&["maven-publish"], BTreeSet::from(["MavenPublishPlugin"])),
        _ if classes.iter().any(|(_, name, _)| name == class) => (&[], BTreeSet::from([class])),
        _ => return None,
    };
    let mut ids: BTreeSet<String> = gradle_ids.iter().map(|id| (*id).to_string()).collect();
    loop {
        let before = ids.len();
        for (id, name, source) in classes {
            let applies = wanted.contains(name.as_str())
                || wanted
                    .iter()
                    .any(|w| source.contains(&format!(".apply({w}.class)")));
            if applies {
                ids.insert(id.clone());
                wanted.insert(name.as_str());
            }
        }
        if ids.len() == before {
            return Some(ids);
        }
    }
}

/// The plugin ids a build script applies by id: `id "x"` / `id("x")` in `plugins { }`,
/// `` `java-library` `` and `apply plugin: 'x'`.
fn applied_ids(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in text.lines().map(str::trim) {
        let id = if let Some(rest) = line.strip_prefix("id") {
            let rest = rest.trim_start();
            quoted(rest.strip_prefix('(').unwrap_or(rest)).map(|(v, _)| v)
        } else if let Some(rest) = line.strip_prefix("apply plugin:") {
            quoted(rest.trim_start()).map(|(v, _)| v)
        } else {
            line.strip_prefix('`').and_then(|r| r.strip_suffix('`'))
        };
        if let Some(id) = id {
            out.insert(id.to_string());
        }
    }
    out
}

/// A subproject as a `projectsEvaluated` filter sees it.
struct Candidate<'a> {
    path: &'a str,
    name: &'a str,
    ids: &'a BTreeSet<String>,
}

/// Whether `it` passes `.findAll { cond }`: `it != project`, `it.plugins.hasPlugin(C)`,
/// `[!]it.path.contains("s")`, `[!]it.name.startsWith("s")`, joined by `&&`. `None` for
/// anything else.
fn hook_filter(
    cond: &str,
    it: &Candidate<'_>,
    own: &str,
    classes: &[(String, String, String)],
) -> Option<bool> {
    let mut all = true;
    for atom in cond.split("&&").map(str::trim) {
        let (negated, atom) = match atom.strip_prefix('!') {
            Some(rest) => (true, rest.trim_start()),
            None => (false, atom),
        };
        let call = |prefix: &str| atom.strip_prefix(prefix).and_then(|r| r.strip_suffix(')'));
        let text_arg = |prefix: &str| match quoted(call(prefix)?.trim()) {
            Some((s, "")) => Some(s),
            _ => None,
        };
        let holds = if atom == "it != project" && !negated {
            it.path != own
        } else if let Some(class) = call("it.plugins.hasPlugin(") {
            !ids_giving(class.trim(), classes)?.is_disjoint(it.ids)
        } else if atom.starts_with("it.path.contains(") {
            it.path.contains(text_arg("it.path.contains(")?)
        } else {
            it.name.starts_with(text_arg("it.name.startsWith(")?)
        };
        all &= holds != negated;
    }
    Some(all)
}

/// The body of a hook's `.each { p -> body }` for one project: `project(p.path)` and
/// `path: p.path` as its path, and `if (p.plugins.hasPlugin(C)) { }` decided. `None` when `p`
/// is used any other way.
fn hook_body(
    body: &[&str],
    var: &str,
    it: &Candidate<'_>,
    classes: &[(String, String, String)],
) -> Option<String> {
    let mut out = String::new();
    let mut skip: Vec<(bool, i32)> = Vec::new();
    let has = format!("if ({var}.plugins.hasPlugin(");
    let mut depth = 0i32;
    for line in body {
        let trimmed = line.trim();
        if let Some(class) = trimmed
            .strip_prefix(&has)
            .and_then(|r| r.strip_suffix(")) {"))
        {
            let holds = !ids_giving(class.trim(), classes)?.is_disjoint(it.ids);
            skip.push((!holds, depth));
            depth += 1;
            continue;
        }
        let opens = code_only(line).matches('{').count() as i32;
        let closes = code_only(line).matches('}').count() as i32;
        if trimmed == "}" && skip.last().is_some_and(|(_, d)| *d == depth - 1) {
            skip.pop();
            depth -= 1;
            continue;
        }
        depth += opens - closes;
        if skip.iter().any(|(s, _)| *s) {
            continue;
        }
        let quoted_path = format!("\"{}\"", it.path);
        let line = line
            .replace(
                &format!("project({var}.path)"),
                &format!("project({quoted_path})"),
            )
            .replace(
                &format!("path: {var}.path"),
                &format!("path: {quoted_path}"),
            );
        let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
        let left = line.match_indices(var).any(|(at, _)| {
            !line[..at].ends_with(word) && !line[at + var.len()..].starts_with(word)
        });
        if left {
            return None;
        }
        out.push_str(&line);
        out.push('\n');
    }
    skip.is_empty().then_some(out)
}

/// `gradle.projectsEvaluated { rootProject.subprojects .findAll { } ... .each { p -> } }` in a
/// project's build file, written out as the body once per subproject the filters keep
/// (spring-boot's docs project: `implementation(project(p.path))` for every published Java
/// project, its `optional` configuration too). A hook not read in full is reported.
fn projects_evaluated(
    dir: &Path,
    scripts: &mut [(String, String)],
    missing: &mut BTreeSet<String>,
) {
    if !scripts
        .iter()
        .any(|(_, t)| t.contains("gradle.projectsEvaluated {"))
    {
        return;
    }
    let settings = ["settings.gradle", "settings.gradle.kts"]
        .iter()
        .find_map(|f| fleetreach_core::repofile::read_to_string(dir.join(f)).ok())
        .map(|t| settings_paths(&strip_comments(&t)))
        .unwrap_or_default();
    let classes = plugin_classes(dir, scripts);
    let ids_of = |dir: &str| {
        scripts
            .iter()
            .find(|(f, _)| {
                *f == format!("{dir}/build.gradle") || *f == format!("{dir}/build.gradle.kts")
            })
            .map(|(_, t)| applied_ids(t))
            .unwrap_or_default()
    };
    let projects: Vec<(String, String, BTreeSet<String>)> = settings
        .iter()
        .map(|(path, d)| {
            let name = path.rsplit(':').next().unwrap_or(path).to_string();
            (path.clone(), name, ids_of(d))
        })
        .collect();
    for (file, text) in scripts.iter_mut() {
        let Some(own) = settings
            .iter()
            .find(|(_, d)| {
                *file == format!("{d}/build.gradle") || *file == format!("{d}/build.gradle.kts")
            })
            .map(|(p, _)| p.clone())
        else {
            continue;
        };
        if !text.contains("gradle.projectsEvaluated {") {
            continue;
        }
        let lines: Vec<&str> = text.lines().collect();
        let Some(start) = lines.iter().position(|l| {
            let t = l.trim();
            t.ends_with("gradle.projectsEvaluated {")
                && [
                    "gradle.",
                    "rootProject.gradle.",
                    "project.rootProject.gradle.",
                ]
                .iter()
                .any(|p| t == format!("{p}projectsEvaluated {{"))
        }) else {
            continue;
        };
        let written = (|| {
            let mut i = start + 1;
            if lines.get(i)?.trim() != "rootProject.subprojects" {
                return None;
            }
            i += 1;
            let mut filters = Vec::new();
            while let Some(cond) = lines
                .get(i)?
                .trim()
                .strip_prefix(".findAll {")
                .and_then(|r| r.strip_suffix('}'))
            {
                filters.push(cond.trim());
                i += 1;
            }
            let var = lines
                .get(i)?
                .trim()
                .strip_prefix(".each {")?
                .strip_suffix("->")?
                .trim();
            if var.is_empty() || !var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return None;
            }
            let mut depth = 1i32;
            let mut end = None;
            for (j, line) in lines.iter().enumerate().skip(i + 1) {
                let code = code_only(line);
                depth += code.matches('{').count() as i32 - code.matches('}').count() as i32;
                if depth == 0 {
                    end = Some(j);
                    break;
                }
            }
            let end = end.filter(|&e| lines[e].trim() == "}")?;
            if lines.get(end + 1)?.trim() != "}" {
                return None;
            }
            let mut body = String::new();
            for (path, name, ids) in &projects {
                let it = Candidate { path, name, ids };
                let mut keep = true;
                for cond in &filters {
                    keep &= hook_filter(cond, &it, &own, &classes)?;
                }
                if keep {
                    body.push_str(&hook_body(&lines[i + 1..end], var, &it, &classes)?);
                }
            }
            Some((body, end + 1))
        })();
        let Some((body, last)) = written else {
            missing.insert(format!(
                "{file}: a gradle.projectsEvaluated hook is not read in full"
            ));
            continue;
        };
        let mut rewritten: String = lines[..start].iter().map(|l| format!("{l}\n")).collect();
        rewritten.push_str(&body);
        for l in &lines[last + 1..] {
            rewritten.push_str(l);
            rewritten.push('\n');
        }
        *text = rewritten;
    }
}

/// The flags LINE's gradle-scripts give each project: what `includeWithFlags ':p', 'a', ...`
/// names, with the implications its `settings-flags.gradle` adds (`javaNN` and `kotlin` imply
/// `java`, `kotlinN.N` implies `kotlin`, `shade` implies `relocate`, `bom` and
/// `version-catalog` imply `publish`).
fn line_flags(settings: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut out = BTreeMap::new();
    for line in settings.lines() {
        let Some(rest) = line.trim().strip_prefix("includeWithFlags") else {
            continue;
        };
        let mut items = strings(rest).into_iter();
        let Some(path) = items.next().filter(|p| p.starts_with(':')) else {
            continue;
        };
        let mut flags: BTreeSet<String> = items.collect();
        let numbered = |prefix: &str, flags: &BTreeSet<String>| {
            flags.iter().any(|f| {
                f.strip_prefix(prefix).is_some_and(|n| {
                    !n.is_empty() && n.chars().all(|c| c.is_ascii_digit() || c == '.')
                })
            })
        };
        if flags.contains("shade") {
            flags.insert("relocate".to_string());
        }
        if flags.contains("bom") || flags.contains("version-catalog") {
            flags.insert("publish".to_string());
        }
        if numbered("java", &flags) {
            flags.insert("java".to_string());
        }
        if numbered("kotlin", &flags) {
            flags.insert("kotlin".to_string());
        }
        if flags.contains("kotlin") {
            flags.insert("java".to_string());
        }
        out.insert(path, flags);
    }
    out
}

/// Moves each `configure(projectsWithFlags('a', ...)) { body }` of the root build script into
/// the build file of every project flagged with all of those flags, `project.path` there as
/// that project's path. Only when the build uses LINE's settings flags.
fn line_flag_blocks(dir: &Path, scripts: &mut [(String, String)]) {
    let marker =
        fleetreach_core::repofile::read_to_string(dir.join("gradle/scripts/settings-flags.gradle"))
            .is_ok_and(|t| t.contains("includeWithFlags") && t.contains("projectsWithFlags"));
    let settings = fleetreach_core::repofile::read_to_string(dir.join("settings.gradle"));
    let (true, Ok(settings)) = (marker, settings) else {
        return;
    };
    let settings = strip_comments(&settings);
    let flags = line_flags(&settings);
    let moved: BTreeMap<String, String> = settings_paths(&settings).into_iter().collect();
    let Some(root) = scripts.iter().position(|(f, _)| f == "build.gradle") else {
        return;
    };
    let text = scripts[root].1.clone();
    let lines: Vec<&str> = text.lines().collect();
    let mut kept = String::with_capacity(text.len());
    let mut blocks: Vec<(BTreeSet<String>, String)> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        let head = trimmed
            .strip_prefix("configure(projectsWithFlags(")
            .and_then(|r| r.strip_suffix('{'))
            .and_then(|r| r.trim_end().strip_suffix("))"));
        let Some(args) = head else {
            kept.push_str(lines[i]);
            kept.push('\n');
            i += 1;
            continue;
        };
        let wanted: BTreeSet<String> = strings(args).into_iter().collect();
        let mut depth = 1i32;
        let mut end = None;
        for (j, line) in lines.iter().enumerate().skip(i + 1) {
            for c in code_only(line).chars() {
                match c {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            if depth == 0 {
                end = Some(j);
                break;
            }
        }
        let Some(end) = end.filter(|&e| lines[e].trim() == "}" && !wanted.is_empty()) else {
            kept.push_str(lines[i]);
            kept.push('\n');
            i += 1;
            continue;
        };
        blocks.push((wanted, lines[i + 1..end].join("\n")));
        i = end + 1;
    }
    if blocks.is_empty() {
        return;
    }
    scripts[root].1 = kept;
    for (path, own) in &flags {
        let project_dir = moved
            .get(path)
            .cloned()
            .unwrap_or_else(|| path.trim_start_matches(':').replace(':', "/"));
        let file = format!("{project_dir}/build.gradle");
        let Some(at) = scripts.iter().position(|(f, _)| *f == file) else {
            continue;
        };
        for (wanted, body) in &blocks {
            if wanted.is_subset(own) {
                let body = project_paths_named(&body.replace("project.path", &format!("'{path}'")));
                scripts[at].1.push_str(&format!("\n{body}\n"));
            }
        }
    }
}

/// `project(':x').path` as `':x'`.
fn project_paths_named(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("project(") {
        out.push_str(&rest[..at]);
        let after = &rest[at + "project(".len()..];
        let named = quoted(after).and_then(|(p, tail)| Some((p, tail.strip_prefix(").path")?)));
        match named {
            Some((p, tail)) if p.starts_with(':') => {
                out.push_str(&format!("'{p}'"));
                rest = tail;
            }
            _ => {
                out.push_str("project(");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn line_scripts_boms(dir: &Path, doc: &toml::Table) -> Vec<String> {
    let marker = fleetreach_core::repofile::read_to_string(
        dir.join("gradle/scripts/lib/common-dependencies.gradle"),
    )
    .is_ok_and(|t| t.contains("dependenciesTomlBoms") && t.contains("platform(library)"));
    let Some(boms) = doc
        .get("boms")
        .and_then(toml::Value::as_table)
        .filter(|_| marker)
    else {
        return Vec::new();
    };
    let versions = doc.get("versions");
    boms.values()
        .filter_map(|entry| {
            let module = entry.get("module").and_then(toml::Value::as_str)?;
            let version = catalog_version(entry.get("version")?, versions).ok()?;
            module.contains(':').then(|| format!("{module}:{version}"))
        })
        .collect()
}

/// Spring Boot's own build (spring-boot itself): its buildSrc `org.springframework.boot.bom`
/// plugin turns `bom { library("AssertJ", "${assertjVersion}") { group("org.assertj") {
/// modules = [...]; bom("x") } } }` into a `java-platform` whose `api` constraints are the
/// modules at the library's version and whose `api platform(...)` dependencies are the BOMs,
/// and its JavaConventions put `enforcedPlatform(project(":platform:spring-boot-internal-
/// dependencies"))` on every classpath of every Java project. Read only where buildSrc holds
/// that plugin and those conventions.
fn spring_boot_boms(dir: &Path, scripts: &mut [(String, String)]) {
    const BUILD: &str = "buildSrc/src/main/java/org/springframework/boot/build/";
    const INTERNAL: &str = ":platform:spring-boot-internal-dependencies";
    let read = |f: &str| fleetreach_core::repofile::read_to_string(dir.join(BUILD).join(f));
    let bom_plugin = read("bom/BomExtension.java").is_ok_and(|t| t.contains("getConstraints()"));
    let conventions = read("JavaConventions.java")
        .is_ok_and(|t| t.contains("enforcedPlatform") && t.contains(INTERNAL));
    if !bom_plugin {
        return;
    }
    let mut platform_files = Vec::new();
    for (file, text) in scripts.iter_mut() {
        if !text.contains("id \"org.springframework.boot.bom\"") {
            continue;
        }
        if let Some(rewritten) = spring_boot_bom(text) {
            *text = rewritten;
            platform_files.push(file.clone());
        }
    }
    let internal = format!(
        "{}/build.gradle",
        INTERNAL.trim_start_matches(':').replace(':', "/")
    );
    if !conventions || !platform_files.contains(&internal) {
        return;
    }
    // Java projects: the core plugins that apply Java, and buildSrc's own plugins whose class
    // applies it (the `org.springframework.boot.starter` every starter uses).
    let mut java_ids: Vec<String> = [
        "java",
        "java-library",
        "war",
        "java-gradle-plugin",
        "org.jetbrains.kotlin.jvm",
    ]
    .iter()
    .map(|id| (*id).to_string())
    .collect();
    java_ids.extend(java_plugin_ids(dir, scripts));
    for (file, text) in scripts.iter_mut() {
        let project = file.ends_with("build.gradle") || file.ends_with("build.gradle.kts");
        let java = java_ids.iter().any(|id| {
            text.contains(&format!("id \"{id}\"")) || text.contains(&format!("id '{id}'"))
        });
        if project && java && !platform_files.contains(file) && !file.starts_with("buildSrc/") {
            text.push_str(&format!(
                "\ndependencies {{\n    implementation enforcedPlatform(project(\"{INTERNAL}\"))\n}}\n"
            ));
        }
    }
}

/// One `org.springframework.boot.bom` script with its `bom { }` block as the `java-platform`
/// dependencies it stands for (see `spring_boot_boms`); `None` when it has no such block.
fn spring_boot_bom(text: &str) -> Option<String> {
    let mut out = String::from("apply plugin: 'java-platform'\n");
    let (mut constraints, mut boms) = (Vec::new(), Vec::new());
    let mut depth = 0usize;
    let mut bom_depth = None;
    let mut library: Option<(String, usize)> = None;
    let mut group: Option<(String, usize)> = None;
    let mut in_modules = false;
    for line in text.lines() {
        let trimmed = line.trim();
        let code = code_only(line);
        let before = depth;
        let opens = code.matches('{').count();
        let closes = code.matches('}').count();
        if bom_depth != Some(0) {
            if bom_depth.is_none() && before == 0 && trimmed.starts_with("bom {") {
                bom_depth = Some(0);
            } else {
                out.push_str(line);
                out.push('\n');
            }
            depth = (depth + opens).saturating_sub(closes);
            continue;
        }
        let version = library.as_ref().map(|(v, _)| v.clone());
        let group_id = group
            .as_ref()
            .filter(|(_, d)| *d + 1 == before)
            .map(|(g, _)| g.clone());
        if in_modules {
            if let (Some((name, _)), Some(g), Some(v)) = (quoted(trimmed), &group_id, &version) {
                constraints.push(format!("{g}:{name}:{v}"));
            }
            if trimmed.starts_with(']') {
                in_modules = false;
            }
        } else if let Some(rest) = trimmed.strip_prefix("library(") {
            let (_, tail) = quoted(rest.trim())?;
            let tail = tail.trim_start().strip_prefix(',')?.trim_start();
            let (v, _) = quoted(tail)?;
            library = Some((v.to_string(), before));
            group = None;
        } else if let Some(rest) = trimmed.strip_prefix("group(") {
            if library.as_ref().is_some_and(|(_, d)| *d + 1 == before) {
                group = quoted(rest.trim()).map(|(g, _)| (g.to_string(), before));
            }
        } else if let (Some(g), Some(v)) = (&group_id, &version) {
            if trimmed.starts_with("modules") && trimmed.contains('[') {
                in_modules = !trimmed.contains(']');
                for name in strings(trimmed.split_once('[').map_or("", |(_, r)| r)) {
                    constraints.push(format!("{g}:{name}:{v}"));
                }
            } else if let Some(rest) = trimmed.strip_prefix("module(") {
                if let Some((name, _)) = quoted(rest.trim()) {
                    constraints.push(format!("{g}:{name}:{v}"));
                }
            } else if let Some(rest) = trimmed.strip_prefix("bom(") {
                if let Some((name, _)) = quoted(rest.trim()) {
                    boms.push(format!("{g}:{name}:{v}"));
                }
            }
        }
        depth = (depth + opens).saturating_sub(closes);
        if library.as_ref().is_some_and(|(_, d)| depth <= *d) {
            library = None;
        }
        if group.as_ref().is_some_and(|(_, d)| depth <= *d) {
            group = None;
        }
        if depth == 0 {
            // Past the block: what follows is read as written.
            bom_depth = Some(usize::MAX);
        }
    }
    if constraints.is_empty() && boms.is_empty() {
        return None;
    }
    out.push_str("dependencies {\n    constraints {\n");
    for c in &constraints {
        out.push_str(&format!("        api \"{c}\"\n"));
    }
    out.push_str("    }\n");
    for b in &boms {
        out.push_str(&format!("    api platform(\"{b}\")\n"));
    }
    out.push_str("}\n");
    Some(out)
}

/// The catalogs other than `libs` a settings script creates from one TOML file:
/// `versionCatalogs { create("pinnedLibs") { from(files("gradle/pinned-libs.versions.toml")) } }`,
/// as (name, file). One built any other way is not read.
fn named_catalogs(dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for f in ["settings.gradle", "settings.gradle.kts"] {
        let Ok(text) = fleetreach_core::repofile::read_to_string(dir.join(f)) else {
            continue;
        };
        let text = strip_comments(&text);
        let mut rest = text.as_str();
        while let Some(at) = ["create(", "register("]
            .iter()
            .filter_map(|c| rest.find(c).map(|i| (i, c.len())))
            .min()
        {
            let after = &rest[at.0 + at.1..];
            rest = after;
            let Some((name, tail)) = quoted(after) else {
                continue;
            };
            let valid = !name.is_empty()
                && name != "libs"
                && name.chars().all(|c| c.is_ascii_alphanumeric())
                && name.starts_with(|c: char| c.is_ascii_lowercase());
            // Its block, up to the next catalog it creates.
            let block = tail
                .find("create(")
                .into_iter()
                .chain(tail.find("register("))
                .min()
                .map_or(tail, |end| &tail[..end]);
            let files: Vec<String> = strings(block)
                .into_iter()
                .filter(|s| s.ends_with(".toml"))
                .collect();
            if let ([file], true) = (files.as_slice(), valid) {
                if block.contains("from(") && !file.contains('$') && dir.join(file).is_file() {
                    out.push((name.to_string(), file.clone()));
                }
            }
        }
    }
    out
}

/// `pinnedLibs.maven.core` as `libs.pinnedLibs.maven.core`, `pinnedLibs.versions.x` as
/// `libs.versions.pinnedLibs.x` (and so on for `bundles` and `plugins`): the accessors of a
/// named catalog's entries once they join `libs` under the catalog's name.
fn catalog_accessors(text: &str, name: &str) -> String {
    let lead = format!("{name}.");
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(&lead) {
        let before = rest[..at].chars().last().or_else(|| out.chars().last());
        out.push_str(&rest[..at]);
        let after = &rest[at + lead.len()..];
        if before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '$') {
            out.push_str(&lead);
        } else if let Some(section) = ["versions.", "bundles.", "plugins."]
            .iter()
            .find(|s| after.starts_with(**s))
        {
            out.push_str(&format!("libs.{section}{lead}"));
            rest = &after[section.len()..];
            continue;
        } else {
            out.push_str(&format!("libs.{lead}"));
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// A named catalog's TOML with every alias (and each `version.ref` and bundle member, which
/// name aliases of the same catalog) led by `name-`.
fn prefixed_catalog(doc: toml::Table, name: &str) -> Vec<(String, toml::Table)> {
    let lead = |alias: &str| format!("{name}-{alias}");
    let fix_ref = |entry: &mut toml::Value| {
        if let Some(version) = entry.get_mut("version") {
            if let Some(r) = version.get_mut("ref") {
                if let Some(text) = r.as_str() {
                    *r = toml::Value::String(lead(text));
                }
            }
        }
    };
    let mut out = Vec::new();
    for (section, value) in doc {
        let Some(table) = value.as_table() else {
            continue;
        };
        let mut entries = toml::Table::new();
        for (alias, entry) in table {
            let mut entry = entry.clone();
            match section.as_str() {
                "libraries" | "plugins" => fix_ref(&mut entry),
                "bundles" => {
                    if let Some(members) = entry.as_array_mut() {
                        for m in members {
                            if let Some(text) = m.as_str() {
                                *m = toml::Value::String(lead(text));
                            }
                        }
                    }
                }
                _ => {}
            }
            entries.insert(lead(alias), entry);
        }
        out.push((section, entries));
    }
    out
}

/// `apply from: "$rootDir/gradle/x.gradle"` (or `apply(from = ...)`, `rootProject.file(...)`,
/// a path relative to the project) runs that script in the project that applies it: its text
/// takes the place of the line, a script applying others in turn, and a script some project
/// applies is no longer read on its own (xpipe's `gradle_scripts/javafx.gradle`).
fn applied_scripts(scripts: &mut Vec<(String, String)>) {
    const DEPTH: usize = 4;
    let is_project_file = |file: &str| {
        let name = Path::new(file)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        name == "build.gradle" || name == "build.gradle.kts"
    };
    let texts: BTreeMap<String, String> = scripts
        .iter()
        .filter(|(f, _)| !is_project_file(f))
        .cloned()
        .collect();
    if texts.is_empty() {
        return;
    }
    fn inline(
        text: &str,
        project_dir: &str,
        texts: &BTreeMap<String, String>,
        applied: &mut BTreeSet<String>,
        stack: &mut Vec<String>,
    ) -> String {
        let mut out = String::with_capacity(text.len());
        for line in text.split_inclusive('\n') {
            let target = applied_path(line.trim(), project_dir)
                .filter(|t| texts.contains_key(t) && !stack.contains(t) && stack.len() < DEPTH);
            match target {
                Some(t) => {
                    applied.insert(t.clone());
                    stack.push(t.clone());
                    let body = inline(&texts[&t], project_dir, texts, applied, stack);
                    stack.pop();
                    out.push_str(&body);
                    if !body.ends_with('\n') {
                        out.push('\n');
                    }
                }
                None => out.push_str(line),
            }
        }
        out
    }
    let mut applied = BTreeSet::new();
    for (file, text) in scripts.iter_mut() {
        if !is_project_file(file) || !text.contains("apply") {
            continue;
        }
        let project_dir = Path::new(file.as_str())
            .parent()
            .and_then(Path::to_str)
            .unwrap_or_default()
            .to_string();
        *text = inline(text, &project_dir, &texts, &mut applied, &mut Vec::new());
    }
    scripts.retain(|(f, _)| !applied.contains(f));
}

/// The root-relative script an `apply from:` line names, from a project in `project_dir`.
fn applied_path(line: &str, project_dir: &str) -> Option<String> {
    let rest = line
        .strip_prefix("apply from:")
        .or_else(|| line.strip_prefix("apply(from ="))
        .or_else(|| line.strip_prefix("apply from ="))?
        .trim();
    let (rooted, rest) = match rest.strip_prefix("rootProject.file(") {
        Some(r) => (true, r),
        None => (
            false,
            rest.strip_prefix("project.file(")
                .or_else(|| rest.strip_prefix("file("))
                .unwrap_or(rest),
        ),
    };
    let (path, _) = quoted(rest.trim_start())?;
    let (rooted, path) = [
        "$rootDir/",
        "${rootDir}/",
        "${rootProject.projectDir}/",
        "$rootProject.projectDir/",
        "${project.rootDir}/",
    ]
    .iter()
    .find_map(|p| path.strip_prefix(p))
    .map_or((rooted, path), |p| (true, p));
    if path.contains('$') || path.contains("://") || path.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = if rooted || project_dir.is_empty() {
        Vec::new()
    } else {
        project_dir.split('/').collect()
    };
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

/// Type-safe project accessors: `projects.plotsquaredCore` is `project(":plotsquared-core")`,
/// `projects.a.bC` is `project(":a:b-c")`. Each path a settings script gives (after its
/// renames) or a build file's directory implies is spelled the way Gradle names its accessor;
/// one that names no known project is left as it is.
fn project_accessors(dir: &Path, scripts: &mut [(String, String)]) {
    if !scripts.iter().any(|(_, t)| t.contains("projects.")) {
        return;
    }
    let mut paths: Vec<String> = ["settings.gradle", "settings.gradle.kts"]
        .iter()
        .find_map(|f| fleetreach_core::repofile::read_to_string(dir.join(f)).ok())
        .map(|t| settings_paths(&strip_comments(&t)))
        .unwrap_or_default()
        .into_iter()
        .map(|(path, _)| path)
        .collect();
    for (file, _) in scripts.iter() {
        if let Some(d) = Path::new(file)
            .parent()
            .and_then(Path::to_str)
            .filter(|d| !d.is_empty())
        {
            paths.push(format!(":{}", d.replace('/', ":")));
        }
    }
    let accessors: BTreeMap<String, String> = paths
        .into_iter()
        .filter_map(|path| {
            let segments: Vec<String> = path
                .trim_start_matches(':')
                .split(':')
                .map(project_accessor)
                .collect();
            (!segments.iter().any(String::is_empty)).then(|| (segments.join("."), path))
        })
        .collect();
    for (_, text) in scripts.iter_mut() {
        if !text.contains("projects.") {
            continue;
        }
        let mut out = String::with_capacity(text.len());
        let mut rest = text.as_str();
        while let Some(at) = rest.find("projects.") {
            let before = rest[..at].chars().next_back();
            let tail = &rest[at + "projects.".len()..];
            let chain_len = tail
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                .unwrap_or(tail.len());
            let chain = tail[..chain_len].trim_end_matches('.');
            // The longest prefix of the chain that names a project.
            let found = (before
                .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '.')))
            .then(|| {
                let mut ends: Vec<usize> = chain.match_indices('.').map(|(i, _)| i).collect();
                ends.push(chain.len());
                ends.into_iter()
                    .rev()
                    .find_map(|end| accessors.get(&chain[..end]).map(|p| (end, p)))
            })
            .flatten();
            match found {
                Some((end, path)) => {
                    out.push_str(&rest[..at]);
                    out.push_str(&format!("project(\"{path}\")"));
                    rest = &tail[end..];
                }
                None => {
                    out.push_str(&rest[..at + "projects.".len()]);
                    rest = tail;
                }
            }
        }
        out.push_str(rest);
        *text = out;
    }
}

/// Gradle's accessor for one project name: `plotsquared-core`, `plotsquared_core` and
/// `plotsquared.core` are all `plotsquaredCore`, and `Core` is `core`.
fn project_accessor(name: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.' | ' ') {
            upper = !out.is_empty();
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else if out.is_empty() {
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The root build's top-level `project(':p') { ... }` blocks configure project `:p`: each
/// body moves to that project's build file, or stands as one at the project's directory when
/// it has none (kafka declares every project's dependencies in its root build.gradle).
fn project_blocks(dir: &Path, scripts: &mut Vec<(String, String)>) {
    let Some(root) = scripts
        .iter()
        .position(|(f, _)| f == "build.gradle" || f == "build.gradle.kts")
    else {
        return;
    };
    let settings = ["settings.gradle", "settings.gradle.kts"]
        .iter()
        .find_map(|f| fleetreach_core::repofile::read_to_string(dir.join(f)).ok())
        .map(|t| settings_paths(&strip_comments(&t)))
        .unwrap_or_default();
    let kotlin = scripts[root].0.ends_with(".kts");
    let text = std::mem::take(&mut scripts[root].1);
    let mut kept = String::new();
    let mut bodies: Vec<(String, String)> = Vec::new();
    let mut rest = text.as_str();
    while !rest.is_empty() {
        let end = rest.find('\n').map_or(rest.len(), |i| i + 1);
        let line = &rest[..end];
        let path = line
            .strip_prefix("project(")
            .and_then(|r| quoted(r))
            .and_then(|(p, tail)| {
                let tail = tail.trim_start().strip_prefix(')')?.trim();
                (tail == "{" && p.starts_with(':')).then_some(p)
            });
        let open = path.and_then(|_| line.find('{'));
        match (
            path,
            open.and_then(|o| balanced(&rest[o..], '{', '}').map(|b| (o, b))),
        ) {
            (Some(path), Some((o, body))) => {
                bodies.push((path.to_string(), body.to_string()));
                rest = &rest[o + body.len() + 2..];
            }
            _ => {
                kept.push_str(line);
                rest = &rest[end..];
            }
        }
    }
    scripts[root].1 = kept;
    for (path, body) in bodies {
        let project_dir = settings
            .iter()
            .find(|(p, _)| *p == path)
            .map_or_else(|| path[1..].replace(':', "/"), |(_, d)| d.clone());
        let in_dir = |f: &str| {
            Path::new(f)
                .parent()
                .and_then(Path::to_str)
                .is_some_and(|d| d == project_dir)
        };
        if let Some(i) = scripts.iter().position(|(f, _)| in_dir(f)) {
            scripts[i].1.push('\n');
            scripts[i].1.push_str(&body);
        } else {
            let name = if kotlin {
                "build.gradle.kts"
            } else {
                "build.gradle"
            };
            scripts.push((format!("{project_dir}/{name}"), body));
        }
    }
}

fn properties(path: &Path) -> BTreeMap<String, String> {
    let text = fleetreach_core::repofile::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter(|l| !l.trim_start().starts_with(['#', '!']))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Remove `//` and `/* */` comments, leaving strings (a URL's `//`) alone.
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut quote = None;
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                out.push(c);
                if c == '\\' {
                    out.extend(chars.next());
                } else if c == q || c == '\n' {
                    quote = None;
                }
            }
            None if c == '/' && chars.peek() == Some(&'/') => {
                while chars.peek().is_some_and(|n| *n != '\n') {
                    chars.next();
                }
            }
            None if c == '/' && chars.peek() == Some(&'*') => {
                chars.next();
                let mut last = ' ';
                for n in chars.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                    }
                    if last == '*' && n == '/' {
                        break;
                    }
                    last = n;
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                }
                out.push(c);
            }
        }
    }
    out
}

/// The variables the build scripts set, from `vars` (gradle.properties and the wrapper): see
/// `script_variables`. With `decided`, each script's `if` chains are first settled from those
/// variables. Also the aliases of catalog versions, known once the catalog is read.
type Later = Vec<(String, String)>;

fn script_vars(
    scripts: &[(String, String)],
    constants: &[(PathBuf, String)],
    mut vars: BTreeMap<String, String>,
    decided: Option<&BTreeMap<String, String>>,
) -> (BTreeMap<String, String>, Later) {
    let mut seen_twice = BTreeSet::new();
    let mut aliases = Vec::new();
    for (_, text) in constants {
        kotlin_constants(text, &mut vars, &mut seen_twice);
    }
    let mut entries = Vec::new();
    for (_, text) in scripts {
        let settled = decided.map(|known| settle_ifs(text, known));
        let text = settled.as_deref().unwrap_or(text);
        script_variables(text, &mut vars, &mut seen_twice, &mut aliases);
        map_entries(text, &mut entries);
        set_calls(text, &mut entries);
    }
    // A name given two values is unknown before anything is built from it: an alias or a
    // `lib = [ ... ]` entry naming it is not read either.
    for name in &seen_twice {
        vars.remove(name);
    }
    // `val v = extra["k"] as String` and `extra["k"] = Versions.K` name another variable,
    // known once every literal is read.
    let mut later = Vec::new();
    for (name, key) in aliases {
        if key.starts_with("libs.versions.") {
            later.push((name, key));
        } else if seen_twice.contains(&name) {
            continue;
        } else if let Some(value) = alias_value(&key, &vars) {
            match vars.get(&name) {
                Some(known) if *known != value => {
                    vars.remove(&name);
                    seen_twice.insert(name);
                }
                _ => {
                    vars.insert(name, value);
                }
            }
        }
    }
    // `lib = [ "k": "g:a:${v}" ]` entries, as `lib.k`, once the versions they name are known.
    for (name, template) in entries {
        if seen_twice.contains(&name) {
            continue;
        }
        let Ok(value) = expand(&template, &vars) else {
            continue;
        };
        match vars.get(&name) {
            Some(known) if *known != value => {
                vars.remove(&name);
                seen_twice.insert(name);
            }
            _ => {
                vars.insert(name, value);
            }
        }
    }
    for name in seen_twice {
        vars.remove(&name);
    }
    (vars, later)
}

/// An alias's value: the variable it names, or `a.substring(0, a.lastIndexOf("."))` (and
/// `indexOf`) of one.
fn alias_value(key: &str, vars: &BTreeMap<String, String>) -> Option<String> {
    if let Some(v) = vars.get(key) {
        return Some(v.clone());
    }
    let (base, rest) = key.split_once(".substring(0,")?;
    let rest = rest.trim().strip_suffix(')')?.trim();
    let (last, arg) = if let Some(a) = rest.strip_prefix(&format!("{base}.lastIndexOf(")) {
        (true, a)
    } else {
        (false, rest.strip_prefix(&format!("{base}.indexOf("))?)
    };
    let (sep, tail) = quoted(arg.trim())?;
    if tail.trim() != ")" || sep.is_empty() {
        return None;
    }
    let v = vars.get(base)?;
    let at = if last { v.rfind(sep)? } else { v.find(sep)? };
    Some(v[..at].to_string())
}

/// `if (c) { a } else if (d) { b } else { e }` chains whose conditions `condition` decides
/// (`.contains("x")` too), as the branch a default build takes; an undecided chain is kept.
fn settle_ifs(text: &str, vars: &BTreeMap<String, String>) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < lines.len() {
        match settle_chain(&lines, i, vars) {
            Some((kept, next)) => {
                out.push_str(&settle_ifs(&kept, vars));
                i = next;
            }
            None => {
                out.push_str(lines[i]);
                out.push('\n');
                i += 1;
            }
        }
    }
    out
}

/// The chain starting at `lines[start]`: the lines of the branch taken, and the index after it.
fn settle_chain(
    lines: &[&str],
    start: usize,
    vars: &BTreeMap<String, String>,
) -> Option<(String, usize)> {
    let mut cond = Some(if_condition(lines[start].trim())?);
    let mut at = start;
    let mut taken: Option<String> = None;
    loop {
        // The branch body runs to the line that closes its brace.
        let mut depth = 1i32;
        let mut end = None;
        for (j, line) in lines.iter().enumerate().skip(at + 1) {
            for c in code_only(line).chars() {
                match c {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    break;
                }
            }
            if depth == 0 {
                end = Some(j);
                break;
            }
        }
        let end = end?;
        let holds = match cond {
            Some(c) => variable_condition(c, vars)?,
            None => true,
        };
        if holds && taken.is_none() {
            let body: String = lines[at + 1..end]
                .iter()
                .map(|l| format!("{l}\n"))
                .collect();
            taken = Some(body);
        }
        let closing = lines[end].trim();
        if closing == "}" {
            return Some((taken.unwrap_or_default(), end + 1));
        }
        let rest = closing
            .strip_prefix('}')?
            .trim_start()
            .strip_prefix("else")?
            .trim_start();
        if rest == "{" {
            cond = None;
        } else {
            cond = Some(if_condition(rest)?);
        }
        at = end;
        // Once a branch is taken, a later condition need not be decided; its body is skipped.
        if taken.is_some() {
            cond = cond.map(|_| "false");
        }
    }
}

/// `condition`, and `NAME.contains("x")`.
fn variable_condition(cond: &str, vars: &BTreeMap<String, String>) -> Option<bool> {
    let c = cond.trim();
    if c == "false" {
        return Some(false);
    }
    let (negated, inner) = match c.strip_prefix('!') {
        Some(rest) if !rest.starts_with('=') => (true, rest.trim()),
        _ => (false, c),
    };
    if let Some((left, right)) = inner.split_once(".contains(") {
        let (needle, tail) = quoted(right.trim())?;
        if tail.trim() != ")" {
            return None;
        }
        return Some(vars.get(left.trim())?.contains(needle) != negated);
    }
    condition(c, vars)
}

/// `val x = "1"`, `def x = '1'`, `ext.x = '1'`, `x = '1'` and `extra["x"] = "1"`. A name given
/// two values is dropped, so a declaration using it is reported instead of guessed. A value
/// naming another variable (`extra["k"] as String`, `property("k")`, `Versions.K`) goes to
/// `aliases`, resolved once every literal is known.
fn script_variables(
    text: &str,
    vars: &mut BTreeMap<String, String>,
    twice: &mut BTreeSet<String>,
    aliases: &mut Vec<(String, String)>,
) {
    for line in text.lines() {
        let mut l = line.trim();
        for prefix in [
            "final ", "const ", "val ", "var ", "def ", "String ", "project.", "ext.",
        ] {
            l = l.strip_prefix(prefix).unwrap_or(l).trim_start();
        }
        let Some((name, value)) = l.split_once('=') else {
            continue;
        };
        // `versions["scala"] = ...` (kafka): the map entry `versions.scala`. A value not read
        // here leaves the entry unknown rather than whatever another line gives it.
        let indexed = indexed_name(name.trim());
        if let Some(name) = &indexed {
            if value.trim_start().starts_with('=') {
                continue;
            }
            let value = value.trim();
            match quoted(value) {
                Some((v, tail)) if tail.trim().is_empty() && !v.contains('$') => {
                    match vars.get(name) {
                        Some(known) if known != v => {
                            twice.insert(name.clone());
                        }
                        _ => {
                            vars.insert(name.clone(), v.to_string());
                        }
                    }
                }
                _ => match variable_reference(value) {
                    Some(key) => aliases.push((name.clone(), key)),
                    None if value.contains(".substring(0,") => {
                        aliases.push((name.clone(), value.to_string()));
                    }
                    None => {
                        twice.insert(name.clone());
                    }
                },
            }
            continue;
        }
        let name = name
            .trim()
            .trim_start_matches("extra[")
            .trim_start_matches("ext[")
            .trim_end_matches(']')
            .trim_matches(['"', '\''])
            .split(':')
            .next()
            .unwrap_or_default()
            .trim();
        let plain = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-');
        if plain {
            if let Some(v) = property_default(value, vars) {
                match vars.get(name) {
                    Some(known) if *known != v => {
                        twice.insert(name.to_string());
                    }
                    _ => {
                        vars.insert(name.to_string(), v);
                    }
                }
                continue;
            }
        }
        let Some((value, tail)) = quoted(value.trim()) else {
            if plain {
                if let Some(key) = variable_reference(value) {
                    aliases.push((name.to_string(), key));
                }
            }
            continue;
        };
        // A lone trailing comma is an entry of a Groovy list: `libraries = [ v = '1.0', ... ]`.
        let tail = tail.trim();
        if !plain || !(tail.is_empty() || tail == ",") || value.contains('$') {
            continue;
        }
        match vars.get(name) {
            Some(known) if known != value => {
                twice.insert(name.to_string());
            }
            _ => {
                vars.insert(name.to_string(), value.to_string());
            }
        }
    }
}

/// `map["k"]` (or `map['k']`) as `map.k`, for a plain map name other than `extra` and `ext`.
fn indexed_name(name: &str) -> Option<String> {
    let (map, rest) = name.split_once('[')?;
    let (key, tail) = quoted(rest)?;
    let plain = |t: &str| {
        !t.is_empty()
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    };
    (tail == "]" && plain(map) && plain(key) && !matches!(map, "extra" | "ext"))
        .then(|| format!("{map}.{key}"))
}

/// `set('k', "v")`, `ext.set("k", "v")` or `extra.set("k", "v")` in an `ext` block: the
/// spelling for a property name with dots or dashes, as a BOM override (`grpc-java.version`).
fn set_calls(text: &str, out: &mut Vec<(String, String)>) {
    for line in text.lines() {
        let l = line.trim();
        let Some(rest) = ["set(", "ext.set(", "extra.set(", "project.ext.set("]
            .iter()
            .find_map(|p| l.strip_prefix(p))
        else {
            continue;
        };
        let Some((name, tail)) = quoted(rest.trim_start()) else {
            continue;
        };
        let Some(tail) = tail.trim_start().strip_prefix(',') else {
            continue;
        };
        let Some((value, end)) = quoted(tail.trim_start()) else {
            continue;
        };
        if end.trim() == ")" {
            out.push((name.to_string(), value.to_string()));
        }
    }
}

/// The entries of Groovy map literals, `name = [ "key": "value", ... ]` over several lines (as
/// `ext.libraries = [...]` builds keep coordinates), as `name.key` and the value as written.
fn map_entries(text: &str, out: &mut Vec<(String, String)>) {
    let mut current: Option<String> = None;
    for line in text.lines() {
        let mut l = line.trim();
        if let Some(name) = &current {
            if l.starts_with(']') {
                current = None;
                continue;
            }
            let l = l.trim_end_matches(',').trim();
            let (key, value) = if let Some((key, tail)) = quoted(l) {
                let Some(value) = tail.trim_start().strip_prefix(':') else {
                    continue;
                };
                (key, value.trim())
            } else {
                let Some((key, value)) = l.split_once(':') else {
                    continue;
                };
                let key = key.trim();
                if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    continue;
                }
                (key, value.trim())
            };
            if let Some((value, tail)) = quoted(value) {
                if tail.trim().is_empty() {
                    out.push((format!("{name}.{key}"), value.to_string()));
                }
            }
            continue;
        }
        for prefix in ["project.ext.", "ext.", "def ", "final "] {
            l = l.strip_prefix(prefix).unwrap_or(l).trim_start();
        }
        let Some((name, open)) = l.split_once('=') else {
            continue;
        };
        // kafka's `libs += [ ... ]` adds to an `ext { libs = [:] }` map.
        let name = name.trim().trim_end_matches('+').trim_end();
        let plain = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if plain && open.trim() == "[" {
            current = Some(name.to_string());
        }
    }
}

/// `lib["k"]` or `lib['k']` as the variable `lib.k`.
fn map_reference(text: &str) -> Option<String> {
    let plain =
        |map: &str| !map.is_empty() && map.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    // Groovy also reads a map entry as `NAME."k"` or `NAME.'k'`.
    if let Some(at) = text.find(".\"").or_else(|| text.find(".'")) {
        let (map, key) = (&text[..at], &text[at + 1..]);
        let (key, tail) = quoted(key)?;
        return (plain(map) && tail.trim().is_empty()).then(|| format!("{map}.{key}"));
    }
    let (map, key) = text.split_once('[')?;
    let (key, tail) = quoted(key.trim())?;
    (plain(map) && tail.trim() == "]").then(|| format!("{map}.{key}"))
}

/// The variable an unquoted value names: `extra["k"]`, `ext["k"]`, `ext.k`, `property("k")`,
/// `findProperty("k")` (each with an optional `as String`, `!!` or `.toString()`), or a plain
/// dotted name such as `Versions.KOTLIN`.
fn variable_reference(value: &str) -> Option<String> {
    let mut v = value.trim();
    // `System.getenv("MOSHI_KOTLIN_VERSION") ?: libs.versions.kotlin.get()`: the environment
    // is not read, so its fallback.
    if v.starts_with("System.getenv(") {
        return variable_reference(v.split_once("?:")?.1);
    }
    for suffix in [" as String?", " as String", "!!", ".toString()", ".get()"] {
        v = v.strip_suffix(suffix).unwrap_or(v).trim_end();
    }
    for prefix in ["rootProject.", "project."] {
        v = v.strip_prefix(prefix).unwrap_or(v);
    }
    for call in ["extra[", "ext[", "property(", "findProperty("] {
        if let Some(inner) = v.strip_prefix(call) {
            let (key, tail) = quoted(inner.trim())?;
            return matches!(tail.trim(), "]" | ")").then(|| key.to_string());
        }
    }
    let v = v.strip_prefix("ext.").unwrap_or(v);
    let plain = !v.is_empty()
        && v.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
    plain.then(|| v.to_string())
}

/// Kotlin files of `buildSrc` and `build-logic`, where builds keep version constants.
fn build_constants(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = ["buildSrc", "build-logic"]
        .iter()
        .map(|d| dir.join(d))
        .collect();
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().to_string();
            if kind.is_dir() {
                if !SKIPPED_DIRS.contains(&name.as_str()) {
                    stack.push(entry.path());
                }
            } else if kind.is_file()
                && name.ends_with(".kt")
                && out.len() < MAX_FILES
                && entry.metadata().is_ok_and(|m| m.len() <= MAX_FILE_BYTES)
            {
                if let Ok(text) = fleetreach_core::repofile::read_to_string(entry.path()) {
                    out.push((entry.path(), strip_comments(&text)));
                }
            }
        }
    }
    out.sort();
    out
}

/// The configurations build logic adds to every source set's compile and runtime classpaths
/// and hands no consumer: a plugin under `buildSrc` or `build-logic` that creates one by name
/// (`Configuration optional = project.getConfigurations().create("optional")`, or through a
/// string constant) and has `getCompileClasspathConfigurationName()` and
/// `getRuntimeClasspathConfigurationName()` extend it (Spring Framework's and Spring Boot's
/// `OptionalDependenciesPlugin`). A plugin that also adds it to what consumers see
/// (`apiElements`, `runtimeElements`) is left out.
fn local_configurations(dir: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut stack: Vec<PathBuf> = ["buildSrc", "build-logic"]
        .iter()
        .map(|d| dir.join(d))
        .collect();
    let mut read = 0usize;
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().to_string();
            if kind.is_dir() {
                // Under `src/`, `build` is a package (`org.springframework.build`), not output.
                let in_src = current.components().any(|c| c.as_os_str() == "src");
                if in_src || !SKIPPED_DIRS.contains(&name.as_str()) {
                    stack.push(entry.path());
                }
                continue;
            }
            let source = [".java", ".kt", ".groovy"]
                .iter()
                .any(|e| name.ends_with(e));
            if !kind.is_file()
                || !source
                || read >= MAX_FILES
                || entry.metadata().map_or(true, |m| m.len() > MAX_FILE_BYTES)
            {
                continue;
            }
            read += 1;
            let Ok(text) = fleetreach_core::repofile::read_to_string(entry.path()) else {
                continue;
            };
            out.extend(local_configuration(&strip_comments(&text)));
        }
    }
    out
}

/// The configuration one build-logic source creates and puts on every source set's compile
/// and runtime classpaths only (see `local_configurations`).
fn local_configuration(text: &str) -> Option<String> {
    let classpaths = [
        "CompileClasspathConfigurationName",
        "RuntimeClasspathConfigurationName",
    ];
    if !classpaths.iter().all(|c| text.contains(c))
        || text.contains("apiElements")
        || text.contains("runtimeElements")
        || text.contains("ApiElements")
        || text.contains("RuntimeElements")
    {
        return None;
    }
    for (at, _) in text.match_indices(".create(") {
        // `Configuration optional = ...create(` (Java) or `val optional = ...create(`.
        let line_start = text[..at].rfind('\n').map_or(0, |i| i + 1);
        let head = text[line_start..at].trim();
        let Some((left, _)) = head.split_once('=') else {
            continue;
        };
        let variable = left.split_whitespace().last()?.trim_end_matches(':');
        if variable.is_empty()
            || !variable
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        let arg = text[at + ".create(".len()..].split(')').next()?.trim();
        let name = match quoted(arg) {
            Some((n, _)) => n.to_string(),
            None => string_constant(text, arg)?,
        };
        let extends = format!(".extendsFrom({variable})");
        if text.matches(extends.as_str()).count() >= 2 && !name.is_empty() {
            return Some(name);
        }
    }
    None
}

/// The value of `NAME = "value"` in a source (a Java `static final String` or Kotlin `const`).
fn string_constant(text: &str, name: &str) -> Option<String> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    text.lines().find_map(|l| {
        let (left, right) = l.split_once('=')?;
        (left.split_whitespace().last() == Some(name))
            .then(|| quoted(right.trim()).map(|(v, _)| v.to_string()))
            .flatten()
    })
}

/// `const val K = "1"` inside `object Versions { }`, as `Versions.K`.
fn kotlin_constants(text: &str, vars: &mut BTreeMap<String, String>, twice: &mut BTreeSet<String>) {
    let mut objects: Vec<(String, usize)> = Vec::new();
    let mut depth = 0usize;
    for line in text.lines() {
        let t = line.trim();
        let word = |p: &str| -> Option<String> {
            let rest = t.strip_prefix(p)?.trim_start();
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            (!name.is_empty()).then_some(name)
        };
        if let Some(name) = word("object ").or_else(|| word("internal object ")) {
            objects.push((name, depth));
        }
        if let Some(rest) = t
            .strip_prefix("const val ")
            .or_else(|| t.strip_prefix("internal const val "))
        {
            if let (Some((name, value)), Some((object, _))) = (rest.split_once('='), objects.last())
            {
                let name = name.split(':').next().unwrap_or_default().trim();
                if let Some((value, tail)) = quoted(value.trim()) {
                    if tail.trim().is_empty() && !value.contains('$') {
                        let key = format!("{object}.{name}");
                        match vars.get(&key) {
                            Some(known) if known != value => {
                                twice.insert(key);
                            }
                            _ => {
                                vars.insert(key, value.to_string());
                            }
                        }
                    }
                }
            }
        }
        for c in code_only(line).chars() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth = depth.saturating_sub(1);
                    while objects.last().is_some_and(|(_, d)| *d >= depth) {
                        objects.pop();
                    }
                }
                _ => {}
            }
        }
    }
}

/// The string at the start of `text` and what follows it.
/// The project paths a settings script gives, with each project's directory relative to the
/// root: its `include`s, `project(":p").projectDir = file("d")`, `project(":p").name = "n"`
/// and `rootProject.children.each { it.name = "x-${it.name}" }`, applied in order.
fn settings_paths(text: &str) -> Vec<(String, String)> {
    fn rename(projects: &mut [(String, String)], from: &str, to: &str) {
        let below = format!("{from}:");
        for (path, _) in projects.iter_mut() {
            if path == from {
                *path = to.to_string();
            } else if let Some(rest) = path.strip_prefix(&below) {
                *path = format!("{to}:{rest}");
            }
        }
    }
    let mut projects: Vec<(String, String)> = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        i += 1;
        if let Some(rest) = line
            .strip_prefix("include")
            .filter(|r| r.starts_with([' ', '(', '\'', '"']))
        {
            // `include 'a',` / `include(` / a trailing `\` go on to the next lines.
            let mut statement = rest.to_string();
            while i < lines.len() {
                let t = statement.trim_end();
                let open = statement.matches('(').count() > statement.matches(')').count();
                if !(open || t.ends_with(',') || t.ends_with('\\')) {
                    break;
                }
                statement.push(' ');
                statement.push_str(lines[i].trim());
                i += 1;
            }
            for name in strings(&statement) {
                let segments: Vec<&str> = name.trim_start_matches(':').split(':').collect();
                for n in 1..=segments.len() {
                    let path = format!(":{}", segments[..n].join(":"));
                    if !projects.iter().any(|(p, _)| *p == path) {
                        projects.push((path, segments[..n].join("/")));
                    }
                }
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("project(") {
            let Some((path, tail)) = quoted(rest.trim_start()) else {
                continue;
            };
            let path = format!(":{}", path.trim_start_matches(':'));
            let tail = tail.trim_start().trim_start_matches(')').trim_start();
            if let Some(value) = tail.strip_prefix(".projectDir").map(str::trim_start) {
                let Some(value) = value.strip_prefix('=') else {
                    continue;
                };
                let Some(dir) = strings(value).pop() else {
                    continue;
                };
                let dir = [
                    "${rootDir}/",
                    "$rootDir/",
                    "${settingsDir}/",
                    "$settingsDir/",
                    "./",
                ]
                .iter()
                .fold(dir.as_str(), |d, p| d.strip_prefix(p).unwrap_or(d))
                .trim_end_matches('/')
                .to_string();
                if dir.contains('$') || dir.starts_with(['/', '.']) {
                    continue;
                }
                match projects.iter_mut().find(|(p, _)| *p == path) {
                    Some(project) => project.1 = dir,
                    None => projects.push((path, dir)),
                }
            } else if let Some(value) = tail.strip_prefix(".name").map(str::trim_start) {
                let Some(name) = value.strip_prefix('=').and_then(|v| strings(v).pop()) else {
                    continue;
                };
                if name.contains('$') {
                    continue;
                }
                let parent = path.rsplit_once(':').map_or("", |(p, _)| p);
                rename(&mut projects, &path, &format!("{parent}:{name}"));
            }
            continue;
        }
        // `rootProject.children.each { it.name = "conductor-${it.name}" }`, the block on one
        // line or a few.
        if line.starts_with("rootProject.children.each")
            || line.starts_with("rootProject.children.forEach")
        {
            let mut block = line.to_string();
            while i < lines.len() && block.matches('{').count() > block.matches('}').count() {
                block.push(' ');
                block.push_str(lines[i].trim());
                i += 1;
            }
            let var = block
                .split_once('{')
                .and_then(|(_, b)| b.split_once("->"))
                .map_or("it", |(v, _)| v.trim())
                .to_string();
            let own = format!("${{{var}.name}}");
            let Some(template) = block
                .split_once(&format!("{var}.name"))
                .and_then(|(_, t)| t.trim_start().strip_prefix('='))
                .and_then(|t| strings(t).into_iter().next())
                .filter(|t| t.contains(&own))
            else {
                continue;
            };
            let children: Vec<String> = projects
                .iter()
                .map(|(p, _)| p.clone())
                .filter(|p| p.matches(':').count() == 1)
                .collect();
            for child in children {
                let named = template.replace(&own, &child[1..]);
                if !named.contains('$') {
                    rename(&mut projects, &child, &format!(":{named}"));
                }
            }
        }
    }
    projects
}

fn quoted(text: &str) -> Option<(&str, &str)> {
    let q = text.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    // A Groovy `${...}` may hold quotes of its own (`"${lib["x"]}"`): skip over it.
    let bytes = text.as_bytes();
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'$' if q == '"' && bytes.get(i + 1) == Some(&b'{') => {
                i += text[i..].find('}')? + 1;
            }
            b if b == q as u8 => return Some((&text[1..i], &text[i + 1..])),
            _ => i += 1,
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Coordinate {
    group: String,
    artifact: String,
    version: Option<String>,
    /// Managed by the Spring dependency-management plugin (`mavenBom`, `dependency`, Spring
    /// Boot's BOM): its versions win over conflict resolution, as `eachDependency` sets them.
    enforced: bool,
    /// From an `enforcedPlatform(...)`: its versions win over every request, a version the
    /// build declares itself included.
    strict: bool,
    /// From a test configuration (`testImplementation(platform(...))`): it manages the test
    /// classpaths only, and the project does not publish it.
    test: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Declared {
    coordinate: Coordinate,
    scope: &'static str,
    /// `exclude(group = "g", module = "a")` in the declaration's block; `*` for a part left out.
    exclusions: Vec<(String, String)>,
    /// A `platform(...)`: Gradle lists the BOM itself as a module of the configuration.
    pom: bool,
    /// Declared in `api` (or another configuration a consumer compiles against): on the
    /// compile classpath of a project that depends on this one. `implementation` is not.
    exported: bool,
    /// `testRuntimeOnly`: on the test runtime classpath, not the test compile one.
    runtime_only: bool,
    /// On this project's own classpaths only, never on a consumer's (Spring's `optional`).
    local: bool,
    /// A version a plugin adds (the Kotlin plugin's standard library at its own version): the
    /// Spring dependency-management plugin still manages it, as it would an unversioned one.
    soft: bool,
}

/// One of the classpaths a build file is resolved for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pass {
    /// `runtimeClasspath`: what the main code ships with, without test dependencies or the
    /// `compileOnly` and processor ones (gradle-versions-plugin's compile-only kotlin-stdlib
    /// 2.4.10 leaves okio's 1.9.21 at runtime).
    Main,
    /// `compileClasspath`: what the main sources compile against.
    Compile,
    /// `testCompileClasspath`: the tests' compile classpath, without runtime-only
    /// dependencies or the main `compileOnly` ones (komga's JUnit 5.12.2, raised to 5.14.4 on
    /// the test runtime classpath by the launcher Spring Boot adds there).
    TestCompile,
    /// Everything, tests included.
    Full,
}

#[derive(Debug, Default)]
struct Module {
    deps: Vec<Declared>,
    platforms: Vec<Coordinate>,
    constraints: Vec<Coordinate>,
    unread: Vec<String>,
    /// What a `subprojects { }`, `allprojects { }` or `configure(subprojects...) { }` block
    /// declares: the root build applies it to every other build file.
    shared: Shared,
    /// `platform(project(":p"))`: another build file's constraints and platforms manage this
    /// one (a `java-platform` project), by Gradle project path.
    project_platforms: Vec<(String, bool)>,
    /// Where the root's shared platforms start in `platforms`: they are applied before this
    /// file's own, so a later import here overrides them.
    shared_from: Option<usize>,
    /// `implementation project(":p")`: by Gradle project path, with this file's scope and
    /// whether it is exported (`api project(":p")`), and the exclusions its block sets
    /// (`{ exclude module: "x" }`, cutting only the path through p).
    project_deps: Vec<ProjectDep>,
    /// What those projects put on this file's classpaths: their own dependencies, never this
    /// file's declarations (the Spring plugin keeps only a file's own declared versions).
    via_projects: Vec<Declared>,
    /// `resolutionStrategy.force("g:a:v")`: versions forced over conflict resolution, the
    /// flag set when only test configurations are forced.
    forced: Vec<(Coordinate, bool)>,
    /// Forces inside an `if` on the project's toolchain version.
    forced_when: Vec<(Coordinate, bool, Toolchain)>,
    /// The file's Java toolchain version: `None` when it sets none, `Some(None)` when it
    /// sets one not read here.
    toolchain: Option<Option<u32>>,
    /// `resolutionStrategy.eachDependency` rules, the flag set when only test
    /// configurations take them.
    rules: Vec<(VersionRule, bool)>,
    /// The plugin ids the file applies, for convention plugins of the build's own.
    applied: Vec<String>,
    /// The file applies the Spring dependency-management plugin, whose `mavenBom` imports
    /// read project properties (halo's `thymeleaf.version` in `:application`, not in `:api`).
    dm: bool,
    /// `configurations.all { exclude ... }`: excluded on every configuration, direct
    /// declarations too, the flag set when only test configurations exclude it.
    excluded: Vec<((String, String), bool)>,
}

#[derive(Debug, Default)]
struct Shared {
    dm: bool,
    /// `eachDependency` rules in the root's `allprojects { }` or `subprojects { }`.
    rules: Vec<(VersionRule, bool)>,
    excluded: Vec<((String, String), bool)>,
    deps: Vec<Declared>,
    platforms: Vec<Coordinate>,
    constraints: Vec<Coordinate>,
    project_platforms: Vec<(String, bool)>,
}

impl Module {
    /// The module as a POM, so BOM imports and versions go through the resolver.
    /// What the Spring dependency-management plugin sets for this build file.
    fn enforced(&self, pass: Pass) -> Enforced {
        let triple = |c: &Coordinate| {
            c.version
                .clone()
                .map(|v| (c.group.clone(), c.artifact.clone(), v))
        };
        // The Spring plugin's later imports override earlier ones: the root's shared block
        // runs before this file.
        let from = self.shared_from.unwrap_or(self.platforms.len());
        let (own, shared) = self.platforms.split_at(from);
        Enforced {
            boms: shared
                .iter()
                .chain(own)
                .filter(|c| c.enforced)
                .filter_map(triple)
                .collect(),
            versions: self
                .constraints
                .iter()
                .filter(|c| c.enforced)
                .filter_map(triple)
                .collect(),
            keep: self
                .deps
                .iter()
                .filter(|d| d.coordinate.version.is_some() && !d.soft)
                .map(|d| (d.coordinate.group.clone(), d.coordinate.artifact.clone()))
                .collect(),
            strict_boms: shared
                .iter()
                .chain(own)
                .filter(|c| c.strict)
                .filter_map(triple)
                .collect(),
            strict_versions: self
                .constraints
                .iter()
                .filter(|c| c.strict)
                .chain(
                    self.forced
                        .iter()
                        .filter(|(_, test_only)| {
                            !test_only || matches!(pass, Pass::TestCompile | Pass::Full)
                        })
                        .map(|(c, _)| c),
                )
                .filter_map(triple)
                .collect(),
            declared_manage: self.dm,
            rules: self
                .rules
                .iter()
                .filter(|(_, test_only)| {
                    !test_only || matches!(pass, Pass::TestCompile | Pass::Full)
                })
                .map(|(r, _)| r.clone())
                .collect(),
        }
    }

    /// The build file as a POM, with the dependencies of one resolution `pass`.
    fn to_pom(&self, pass: Pass) -> String {
        let xml = |text: &str| {
            text.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        };
        let dep = |c: &Coordinate, extra: &str| {
            let version = c
                .version
                .as_ref()
                .map(|v| format!("<version>{}</version>", xml(v)))
                .unwrap_or_default();
            format!(
                "<dependency><groupId>{}</groupId><artifactId>{}</artifactId>{version}{extra}</dependency>",
                xml(&c.group),
                xml(&c.artifact)
            )
        };
        let mut managed = String::new();
        let applies = |c: &&Coordinate| matches!(pass, Pass::TestCompile | Pass::Full) || !c.test;
        for p in self.platforms.iter().filter(applies) {
            managed.push_str(&dep(p, "<type>pom</type><scope>import</scope>"));
        }
        for c in self.constraints.iter().filter(applies) {
            managed.push_str(&dep(c, ""));
        }
        let mut deps = String::new();
        let kept: Vec<&Declared> = self
            .deps
            .iter()
            .chain(&self.via_projects)
            .filter(|d| match pass {
                Pass::Main => !matches!(d.scope, "test" | "provided"),
                Pass::Compile => !matches!(d.scope, "test" | "runtime"),
                // `compileOnlyApi` (provided and exported) is on the test compile classpath, a
                // plain `compileOnly` is not, and neither is on the test runtime one
                // (PlotSquared's checker-qual: 4.4.0 to compile its tests, worldedit's 3.48.3
                // to run them).
                Pass::TestCompile => {
                    (matches!(d.scope, "compile" | "test") || (d.scope == "provided" && d.exported))
                        && !d.runtime_only
                }
                Pass::Full => d.scope != "provided",
            })
            .collect();
        // Under the Spring plugin, a declaration this pass leaves out still versions one of
        // the same module the pass keeps without a version (LogNet's `compileOnly
        // grpc-netty:${v}` its `testImplementation grpc-netty`), never one with its own.
        if self.dm {
            let unversioned = |d: &Declared| {
                kept.iter().any(|k| {
                    k.coordinate.version.is_none()
                        && k.coordinate.group == d.coordinate.group
                        && k.coordinate.artifact == d.coordinate.artifact
                })
            };
            for d in self
                .deps
                .iter()
                .filter(|d| !d.pom && d.coordinate.version.is_some())
            {
                if !kept.iter().any(|k| std::ptr::eq(*k, d)) && unversioned(d) {
                    managed.push_str(&dep(&d.coordinate, ""));
                }
            }
        }
        let excluded: Vec<&(String, String)> = self
            .excluded
            .iter()
            .filter(|(_, test_only)| !test_only || matches!(pass, Pass::TestCompile | Pass::Full))
            .map(|(ex, _)| ex)
            .collect();
        let matches = |c: &Coordinate| {
            excluded
                .iter()
                .any(|(g, a)| (g == "*" || *g == c.group) && (a == "*" || *a == c.artifact))
        };
        let kept: Vec<&Declared> = kept
            .into_iter()
            .filter(|d| !matches(&d.coordinate))
            .collect();
        // Gradle drops a module's dependency only when every edge to it excludes it, so an
        // artifact declared twice keeps just the exclusions all its declarations share.
        let mut shared_exclusions: BTreeMap<(&str, &str), Vec<(String, String)>> = BTreeMap::new();
        for d in &kept {
            let key = (d.coordinate.group.as_str(), d.coordinate.artifact.as_str());
            shared_exclusions
                .entry(key)
                .and_modify(|common| common.retain(|e| d.exclusions.contains(e)))
                .or_insert_with(|| d.exclusions.clone());
        }
        for d in kept {
            let mut extra = format!("<scope>{}</scope>", d.scope);
            if d.pom {
                // A platform's own dependencies are constraints to Gradle, never followed.
                extra.push_str(
                    "<type>pom</type><exclusions><exclusion><groupId>*</groupId>\
                     <artifactId>*</artifactId></exclusion></exclusions>",
                );
            }
            let mut exclusions = shared_exclusions
                .get(&(d.coordinate.group.as_str(), d.coordinate.artifact.as_str()))
                .map_or(&d.exclusions, |e| e)
                .clone();
            exclusions.extend(excluded.iter().map(|&e| e.clone()));
            if !exclusions.is_empty() {
                extra.push_str("<exclusions>");
                for (g, a) in &exclusions {
                    extra.push_str(&format!(
                        "<exclusion><groupId>{}</groupId><artifactId>{}</artifactId></exclusion>",
                        xml(g),
                        xml(a)
                    ));
                }
                extra.push_str("</exclusions>");
            }
            deps.push_str(&dep(&d.coordinate, &extra));
        }
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>gradle</groupId>\
             <artifactId>build</artifactId><version>0</version>\
             <dependencyManagement><dependencies>{managed}</dependencies></dependencyManagement>\
             <dependencies>{deps}</dependencies></project>"
        )
    }
}

#[derive(Debug, Default)]
struct Catalog {
    /// `a-b.c` as written, to its coordinate.
    libraries: BTreeMap<String, Coordinate>,
    bundles: BTreeMap<String, Vec<String>>,
    /// Plugin id to version.
    plugins: BTreeMap<String, String>,
    /// Plugin alias to id.
    plugin_aliases: BTreeMap<String, String>,
    /// `[versions]` by accessor, as scripts name them: `libs.versions.<accessor>`.
    versions: BTreeMap<String, String>,
    unread: Vec<String>,
}

fn accessor(alias: &str) -> String {
    alias.replace(['-', '_'], ".")
}

impl Catalog {
    #[cfg(test)]
    fn parse(text: &str) -> Result<Catalog, String> {
        let doc: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
        Ok(Catalog::from_doc(&doc))
    }

    fn from_doc(doc: &toml::Value) -> Catalog {
        let mut catalog = Catalog::default();
        let versions = doc.get("versions");
        let table = |key: &str| doc.get(key).and_then(toml::Value::as_table);
        for (alias, entry) in table("versions").into_iter().flatten() {
            if let Ok(version) = catalog_version(entry, None) {
                catalog.versions.insert(accessor(alias), version);
            }
        }
        for (alias, entry) in table("libraries").into_iter().flatten() {
            match library(entry, versions) {
                Ok(coordinate) => {
                    catalog.libraries.insert(alias.clone(), coordinate);
                }
                Err(e) => catalog.unread.push(format!("library `{alias}`: {e}")),
            }
        }
        for (alias, members) in table("bundles").into_iter().flatten() {
            let members = members.as_array().into_iter().flatten();
            let members = members.filter_map(toml::Value::as_str).map(str::to_string);
            catalog.bundles.insert(alias.clone(), members.collect());
        }
        for (alias, entry) in table("plugins").into_iter().flatten() {
            let (id, version) = match entry.as_str() {
                Some(text) => match text.split_once(':') {
                    Some((id, version)) => (id.to_string(), Some(version.to_string())),
                    None => (text.to_string(), None),
                },
                None => {
                    let id = entry.get("id").and_then(toml::Value::as_str);
                    let version = entry.get("version");
                    let version = version.and_then(|v| catalog_version(v, versions).ok());
                    (id.unwrap_or_default().to_string(), version)
                }
            };
            catalog.plugin_aliases.insert(accessor(alias), id.clone());
            if let Some(version) = version {
                catalog.plugins.insert(id, version);
            }
        }
        catalog
    }
}

/// The `libs` catalog a settings script declares (`versionCatalogs { create("libs") { ... } }`,
/// or `.register('libs')`), as `libs.versions.toml` sections: `version`, `library` (with
/// `version` or `versionRef`, or a `g:a:v` string), `bundle` and `plugin`, in Groovy or Kotlin.
fn settings_catalog(text: &str) -> Vec<(&'static str, toml::Table)> {
    let mut versions = toml::Table::new();
    let mut libraries = toml::Table::new();
    let mut bundles = toml::Table::new();
    let mut plugins = toml::Table::new();
    let mut inside = false;
    let s = |v: &str| toml::Value::String(v.to_string());
    for line in text.lines() {
        let line = line.trim();
        if line.contains("versionCatalogs") || line.contains("create(\"libs\")") {
            inside = true;
        }
        if !inside {
            continue;
        }
        let words = strings(line);
        let reference = line.contains("versionRef");
        let keyword: String = line.chars().take_while(char::is_ascii_alphabetic).collect();
        let version = |at: usize| -> Option<toml::Value> {
            let v = words.get(at)?;
            Some(if reference {
                let mut t = toml::Table::new();
                t.insert("ref".to_string(), s(v));
                toml::Value::Table(t)
            } else {
                s(v)
            })
        };
        match (keyword.as_str(), words.len()) {
            ("version", 2..) => {
                versions.insert(words[0].clone(), s(&words[1]));
            }
            ("library", 2) => {
                libraries.insert(words[0].clone(), s(&words[1]));
            }
            ("library", 3..) => {
                let mut t = toml::Table::new();
                t.insert(
                    "module".to_string(),
                    s(&format!("{}:{}", words[1], words[2])),
                );
                if let Some(v) = version(3) {
                    t.insert("version".to_string(), v);
                }
                libraries.insert(words[0].clone(), toml::Value::Table(t));
            }
            ("bundle", 2..) => {
                let members = words[1..].iter().map(|m| s(m)).collect();
                bundles.insert(words[0].clone(), toml::Value::Array(members));
            }
            ("plugin", 2..) => {
                let mut t = toml::Table::new();
                t.insert("id".to_string(), s(&words[1]));
                if let Some(v) = version(2) {
                    t.insert("version".to_string(), v);
                }
                plugins.insert(words[0].clone(), toml::Value::Table(t));
            }
            _ => {}
        }
    }
    vec![
        ("versions", versions),
        ("libraries", libraries),
        ("bundles", bundles),
        ("plugins", plugins),
    ]
}

/// The versions a script forces: `resolutionStrategy.force("g:a:v", ...)`, `force 'g:a:v'`,
/// and the coordinates of a kordamp enforcer `ForceDependencies` rule. Each is flagged when it
/// sits in a `configurations.matching { ... 'test' ... }` block, which forces test
/// classpaths only (conductor's http-task).
fn forced_versions(
    text: &str,
    vars: &BTreeMap<String, String>,
    missing: &mut BTreeSet<String>,
) -> Vec<(Coordinate, bool)> {
    forced_versions_when(text, vars, missing).0
}

/// `forced_versions`, with the forces inside an `if` on the project's toolchain version
/// apart, each with that condition (caffeine's eclipse-collections 12.0.0 below Java 17).
#[allow(clippy::type_complexity)]
fn forced_versions_when(
    text: &str,
    vars: &BTreeMap<String, String>,
    missing: &mut BTreeSet<String>,
) -> (Vec<(Coordinate, bool)>, Vec<(Coordinate, bool, Toolchain)>) {
    let text = strip_comments(text);
    let mut out = Vec::new();
    let mut when = Vec::new();
    // Per open brace: the toolchain condition of the `if` that opened it.
    let mut toolchain_blocks: Vec<Option<Toolchain>> = Vec::new();
    // Per open brace: whether it opened a test-only configurations block.
    let mut test_blocks: Vec<bool> = Vec::new();
    // Per open brace: whether an `if` the default build decides false opened it.
    let mut false_blocks: Vec<bool> = Vec::new();
    // Inside `force(` still open, or a kordamp rule at this depth.
    let mut open_call = false;
    let mut kordamp: Option<usize> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        let test_only = test_blocks.iter().any(|t| *t);
        let force_at = ["force(", "force '", "force \""].iter().find_map(|p| {
            trimmed.find(p).filter(|&i| {
                !trimmed[..i].ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
            })
        });
        if trimmed.contains("ForceDependencies") {
            kordamp = Some(test_blocks.len());
        }
        let off = false_blocks.iter().any(|f| *f);
        let collect = !off && (open_call || force_at.is_some() || kordamp.is_some());
        if collect {
            let from = force_at.map_or(trimmed, |i| &trimmed[i..]);
            for value in strings(from) {
                if value.matches(':').count() < 2 {
                    continue;
                }
                let on = toolchain_blocks.iter().rev().find_map(|t| *t);
                match coordinate(&value, vars) {
                    Ok(c) if c.version.is_some() => match on {
                        Some(t) => when.push((c, test_only, t)),
                        None => out.push((c, test_only)),
                    },
                    Ok(_) => {}
                    Err(e) => {
                        missing.insert(format!("forced version: {e}"));
                    }
                }
            }
        }
        if let Some(i) = force_at.filter(|_| trimmed.contains("force(")) {
            open_call = !trimmed[i..].contains(')');
        } else if open_call && trimmed.contains(')') {
            open_call = false;
        }
        let opens_test = trimmed.starts_with("configurations")
            && (trimmed.contains("'test") || trimmed.contains("\"test"));
        let opens_false = if_condition(trimmed).and_then(|c| condition(c, vars)) == Some(false);
        let opens_toolchain = if_condition(trimmed).and_then(toolchain_test);
        for c in code_only(line).chars() {
            match c {
                '{' => {
                    test_blocks.push(opens_test);
                    false_blocks.push(opens_false);
                    toolchain_blocks.push(opens_toolchain);
                }
                '}' => {
                    test_blocks.pop();
                    false_blocks.pop();
                    toolchain_blocks.pop();
                    if kordamp.is_some_and(|d| test_blocks.len() <= d) {
                        kordamp = None;
                    }
                }
                _ => {}
            }
        }
    }
    (out, when)
}

/// `resolutionStrategy.eachDependency { ... }` rules: each `useVersion(v)` with the
/// `requested.group` / `requested.name` conditions around it (`==`, `!=`, `startsWith`,
/// `&&`, nested `if` and `else`). A branch on anything else is not read; a rule on one named
/// configuration other than the classpaths, or on the buildscript, sets nothing read here.
/// Each comes with whether only test configurations take it and whether the root's
/// `allprojects { }` / `subprojects { }` gives it to every project.
fn version_rules(text: &str, vars: &BTreeMap<String, String>) -> Vec<(VersionRule, bool, bool)> {
    let text = strip_comments(text);
    // `val groups = setOf("a", "b")`, for a `when` branch `in groups -> ...`.
    let sets: BTreeMap<String, Vec<String>> = text
        .lines()
        .filter_map(|l| {
            let (name, value) = l.trim().strip_prefix("val ")?.split_once('=')?;
            let items = value.trim().strip_prefix("setOf(")?.strip_suffix(')')?;
            let items: Option<Vec<String>> = items
                .split(',')
                .map(|i| match quoted(i.trim()) {
                    Some((v, "")) => Some(v.to_string()),
                    _ => None,
                })
                .collect();
            Some((name.trim().to_string(), items?))
        })
        .collect();
    let mut out = Vec::new();
    let mut openers: Vec<String> = Vec::new();
    let mut at = 0;
    while let Some(found) = text[at..].find("eachDependency") {
        let start = at + found;
        // The blocks open around it, and what its own line says before it.
        for line in text[at..start].split_inclusive('\n') {
            // Each block is known by its whole line, quotes kept: `configurations.matching
            // { it.name.startsWith('test') }.configureEach {` is a test one.
            for c in code_only(line).chars() {
                match c {
                    '{' => openers.push(line.trim().to_string()),
                    '}' => {
                        openers.pop();
                    }
                    _ => {}
                }
            }
        }
        let line_start = text[..start].rfind('\n').map_or(0, |i| i + 1);
        let own = text[line_start..start].to_string();
        let Some(open) = text[start..].find('{').map(|i| start + i) else {
            break;
        };
        let Some(body) = balanced(&text[open..], '{', '}') else {
            break;
        };
        at = open + body.len() + 2;
        // `body` was taken out of the text: the scan for braces resumes after it.
        let context: Vec<&str> = openers
            .iter()
            .map(String::as_str)
            .chain([own.trim()])
            .filter(|o| !o.is_empty())
            .collect();
        if context.iter().any(|o| o.starts_with("buildscript")) {
            continue;
        }
        let shared = context
            .iter()
            .any(|o| o.starts_with("allprojects") || o.starts_with("subprojects"));
        // The innermost block that names configurations.
        let scope = context.iter().rev().find(|o| {
            o.contains("configurations")
                || *o == &"all"
                || o.starts_with("all ")
                || o.contains("configureEach")
        });
        let Some(scope) = scope else {
            continue;
        };
        let test_only = scope.contains("\"test") || scope.contains("'test");
        let every = scope.contains("configureEach")
            || scope.contains(".all")
            || scope.starts_with("all")
            || scope.trim_end_matches(['{', ' ']) == "configurations";
        if !(test_only || every) {
            continue;
        }
        let mut rules = Vec::new();
        rule_statements(body, &[], None, (vars, &sets), &mut rules);
        out.extend(rules.into_iter().map(|r| (r, test_only, shared)));
    }
    out
}

/// `exclude group: 'g', module: 'a'` set on every configuration: in `configurations.all { }`,
/// `configurations { all { } }` or `configurations.configureEach { }`, or on the test ones
/// only (`matching { it.name.startsWith('test') }`), with whether a root's
/// `allprojects { }` or `subprojects { }` shares it (conductor drops Logback everywhere).
fn configuration_exclusions(text: &str) -> Vec<((String, String), bool, bool)> {
    let text = strip_comments(text);
    let mut out = Vec::new();
    let mut openers: Vec<String> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("exclude") {
            if let (Some(ex), Some(inner)) = (exclusion(trimmed), openers.last()) {
                let in_configurations = inner == "all {"
                    && openers
                        .iter()
                        .rev()
                        .nth(1)
                        .is_some_and(|o| o == "configurations {");
                let every = in_configurations
                    || inner.starts_with("configurations.all")
                    || inner.starts_with("configurations.configureEach");
                let test_only = inner.starts_with("configurations.matching")
                    && (inner.contains("\"test") || inner.contains("'test"))
                    && inner.contains("configureEach");
                if (every || test_only) && !openers.iter().any(|o| o.starts_with("buildscript")) {
                    let shared = openers
                        .iter()
                        .any(|o| o.starts_with("allprojects") || o.starts_with("subprojects"));
                    out.push((ex, test_only, shared));
                }
            }
        }
        for c in code_only(line).chars() {
            match c {
                '{' => openers.push(trimmed.to_string()),
                '}' => {
                    openers.pop();
                }
                _ => {}
            }
        }
    }
    out
}

/// What is between an opening `open` at the start of `text` and its match.
fn balanced(text: &str, open: char, close: char) -> Option<&str> {
    let mut depth = 0usize;
    for (i, c) in text.char_indices() {
        if c == open {
            depth += 1;
        } else if c == close {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(&text[open.len_utf8()..i]);
            }
        }
    }
    None
}

type RuleNames<'a> = (
    &'a BTreeMap<String, String>,
    &'a BTreeMap<String, Vec<String>>,
);

fn rule_statements(
    body: &str,
    conditions: &[RuleCondition],
    toolchain: Option<Toolchain>,
    names: RuleNames<'_>,
    out: &mut Vec<VersionRule>,
) {
    let vars = names.0;
    let mut rest = body;
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == ';');
        if rest.is_empty() {
            return;
        }
        if let Some(after) = rest
            .strip_prefix("if")
            .filter(|a| a.trim_start().starts_with('('))
        {
            let after = after.trim_start();
            let Some(cond) = balanced(after, '(', ')') else {
                return;
            };
            let (then, tail) = branch(&after[cond.len() + 2..]);
            let parsed = rule_conditions(cond);
            // A condition the default build decides, or one on the project's toolchain
            // version (caffeine's JUnit 5 below Java 17), decided per project.
            let decided = parsed.is_none().then(|| condition(cond, vars)).flatten();
            let on = if toolchain.is_none() {
                toolchain_test(cond)
            } else {
                None
            };
            if let Some(parsed) = &parsed {
                let mut inner = conditions.to_vec();
                inner.extend(parsed.iter().cloned());
                rule_statements(then, &inner, toolchain, names, out);
            } else if decided == Some(true) {
                rule_statements(then, conditions, toolchain, names, out);
            } else if on.is_some() {
                rule_statements(then, conditions, on, names, out);
            }
            rest = tail;
            let trimmed = rest.trim_start();
            if let Some(other) = trimmed.strip_prefix("else") {
                let (otherwise, tail) = branch(other);
                if decided == Some(false) {
                    rule_statements(otherwise, conditions, toolchain, names, out);
                } else if let Some(t) = on {
                    rule_statements(
                        otherwise,
                        conditions,
                        Some(toolchain_negated(t)),
                        names,
                        out,
                    );
                }
                // `else` negates a single condition; of several, it is not read.
                if let Some([one]) = parsed.as_deref() {
                    let mut inner = conditions.to_vec();
                    inner.push(RuleCondition {
                        negated: !one.negated,
                        ..one.clone()
                    });
                    rule_statements(otherwise, &inner, toolchain, names, out);
                }
                rest = tail;
            }
            continue;
        }
        let call = ["details.useVersion", "it.useVersion", "useVersion"]
            .iter()
            .find_map(|p| rest.strip_prefix(p));
        if let Some(arg) = call {
            let arg = arg.trim_start();
            let (value, tail) = match arg.strip_prefix('(') {
                Some(_) => match balanced(arg, '(', ')') {
                    Some(inner) => (inner, &arg[inner.len() + 2..]),
                    None => return,
                },
                None => {
                    let end = arg.find(['\n', ';', '}']).unwrap_or(arg.len());
                    (&arg[..end], &arg[end..])
                }
            };
            if let Some(version) = rule_version(value.trim(), vars) {
                if !conditions.is_empty() {
                    out.push(VersionRule {
                        conditions: conditions.to_vec(),
                        version,
                        toolchain,
                    });
                }
            }
            rest = tail;
            continue;
        }
        // `when (requested.group) { in groups -> useVersion("v"); "g" -> useVersion("v") }`.
        let subject = ["when (requested.group)", "when (requested.name)"]
            .iter()
            .position(|w| rest.starts_with(w));
        if let Some(on_name) = subject.map(|i| i == 1) {
            let open = rest.find('{').unwrap_or(rest.len());
            let Some(inner) = balanced(&rest[open..], '{', '}') else {
                return;
            };
            for arm in inner.lines().map(str::trim).filter(|l| !l.is_empty()) {
                let Some((test, action)) = arm.split_once("->") else {
                    continue;
                };
                let test = test.trim();
                let values: Vec<String> = match test.strip_prefix("in ") {
                    Some(set) => names.1.get(set.trim()).cloned().unwrap_or_default(),
                    None => match quoted(test) {
                        Some((v, tail)) if tail.trim().is_empty() => vec![v.to_string()],
                        _ => Vec::new(),
                    },
                };
                for value in values {
                    let mut inner = conditions.to_vec();
                    inner.push(RuleCondition {
                        on_name,
                        prefix: false,
                        value,
                        negated: false,
                    });
                    rule_statements(action.trim(), &inner, toolchain, names, out);
                }
            }
            rest = &rest[open + inner.len() + 2..];
            continue;
        }
        // Anything else (`because`, assignments): to the end of its line, or of the block it
        // opens.
        let end = rest.find('\n').unwrap_or(rest.len());
        let line = &rest[..end];
        match line.find('{') {
            Some(i) => match balanced(&rest[i..], '{', '}') {
                Some(inner) => rest = &rest[i + inner.len() + 2..],
                None => return,
            },
            None => rest = &rest[end..],
        }
    }
}

/// An `if`'s body: a `{ }` block or the one statement on its line, and what follows.
fn branch(text: &str) -> (&str, &str) {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        if let Some(inner) = balanced(trimmed, '{', '}') {
            return (inner, &trimmed[inner.len() + 2..]);
        }
        return ("", "");
    }
    let end = trimmed.find('\n').unwrap_or(trimmed.len());
    // `if (c) useVersion("a") else useVersion("b")` on one line.
    let end = trimmed[..end].find(" else ").map_or(end, |i| i + 1);
    (&trimmed[..end], &trimmed[end..])
}

fn rule_conditions(cond: &str) -> Option<Vec<RuleCondition>> {
    if cond.contains("||") {
        return None;
    }
    cond.split("&&")
        .map(|atom| {
            let mut atom = atom.trim();
            let mut negated = false;
            if let Some(inner) = atom.strip_prefix('!') {
                negated = true;
                atom = inner.trim();
            }
            while atom.starts_with('(') && atom.ends_with(')') {
                atom = atom[1..atom.len() - 1].trim();
            }
            let atom = atom
                .strip_prefix("details.")
                .or_else(|| atom.strip_prefix("it."))
                .unwrap_or(atom);
            let rest = atom.strip_prefix("requested.")?;
            let (on_name, rest) = if let Some(r) = rest.strip_prefix("group") {
                (false, r)
            } else {
                (true, rest.strip_prefix("name")?)
            };
            let rest = rest.trim_start();
            let (prefix, rest) = if let Some(r) = rest.strip_prefix(".startsWith(") {
                (true, r.trim_end().strip_suffix(')')?)
            } else if let Some(r) = rest.strip_prefix("==") {
                (false, r)
            } else {
                let r = rest.strip_prefix("!=")?;
                negated = !negated;
                (false, r)
            };
            let rest = rest.trim();
            let (value, tail) = quoted(rest)?;
            if !tail.trim().is_empty() || value.contains('$') {
                return None;
            }
            Some(RuleCondition {
                on_name,
                prefix,
                value: value.to_string(),
                negated,
            })
        })
        .collect()
}

/// `"1.2"`, `libs.versions.x.get()`, `catalog.findVersion("x").get().requiredVersion` or a
/// variable the build defines.
fn rule_version(value: &str, vars: &BTreeMap<String, String>) -> Option<String> {
    if value.starts_with(['"', '\'']) {
        let (text, tail) = quoted(value)?;
        if !tail.trim().is_empty() {
            return None;
        }
        return expand(text, vars).ok().filter(|v| !v.is_empty());
    }
    let catalog = |alias: &str| {
        vars.get(&format!("libs.versions.{alias}"))
            .or_else(|| vars.get(&format!("libs.versions.{}", accessor(alias))))
            .cloned()
    };
    if let Some(at) = value.find("findVersion(") {
        let (alias, _) = quoted(value[at + "findVersion(".len()..].trim_start())?;
        return catalog(alias);
    }
    // `libs.paper.get().version` or `checkNotNull(libs.paper.orNull?.version)`.
    let unwrapped = value
        .strip_prefix("checkNotNull(")
        .or_else(|| value.strip_prefix("requireNotNull("))
        .and_then(|v| v.strip_suffix(')'))
        .unwrap_or(value)
        .trim();
    if let Some(path) = unwrapped
        .strip_prefix("libs.")
        .filter(|p| !p.starts_with("versions."))
    {
        let path = [
            ".version",
            "?.version",
            ".get()",
            ".orNull",
            "?",
            ".asProvider()",
        ]
        .iter()
        .fold(path, |p, s| p.strip_suffix(s).unwrap_or(p));
        let path = path.strip_suffix(".orNull").unwrap_or(path);
        let path = path.strip_suffix(".get()").unwrap_or(path);
        if unwrapped.ends_with("version") {
            return vars.get(&format!("{LIBRARY_VERSION}{path}")).cloned();
        }
    }
    if let Some(path) = value.strip_prefix("libs.versions.") {
        let path = [".requiredVersion", ".get()", ".asProvider()"]
            .iter()
            .fold(path, |p, s| p.strip_suffix(s).unwrap_or(p));
        let path = path.strip_suffix(".get()").unwrap_or(path);
        let path = path.strip_suffix(".asProvider()").unwrap_or(path);
        return catalog(path);
    }
    vars.get(value).cloned()
}

const GRADLE_VERSION: &str = "GradleVersion.current().version";

/// The variable prefix a catalog library's own version is kept under, by accessor.
const LIBRARY_VERSION: &str = "libs.library-version.";

/// The Gradle version the wrapper downloads (`gradle-9.8.2-bin.zip`).
fn wrapper_version(dir: &Path) -> Option<String> {
    let props = properties(&dir.join("gradle/wrapper/gradle-wrapper.properties"));
    let url = props.get("distributionUrl")?;
    let file = url.rsplit('/').next()?;
    let version = file
        .strip_prefix("gradle-")?
        .strip_suffix(".zip")?
        .trim_end_matches("-all")
        .trim_end_matches("-bin");
    (!version.is_empty()).then(|| version.to_string())
}

/// The quoted strings of a line, up to a `//` comment.
fn strings(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    loop {
        let quote = rest.find(['"', '\'']);
        let comment = rest.find("//");
        match (quote, comment) {
            (Some(q), c) if c.is_none_or(|c| q < c) => match quoted(&rest[q..]) {
                Some((value, tail)) => {
                    out.push(value.to_string());
                    rest = tail;
                }
                None => break,
            },
            _ => break,
        }
    }
    out
}

const SPRING_BOOT: &str = "org.springframework.boot";

/// The plugin id and version a buildscript `classpath` line brings, for the plugins whose
/// dependencies the reader adds.
fn classpath_plugin(line: &str, vars: &BTreeMap<String, String>) -> Option<(&'static str, String)> {
    let rest = line.strip_prefix("classpath")?;
    let rest = rest.trim_start().trim_start_matches('(').trim_start();
    // `classpath(kotlin("gradle-plugin", version = kotlinVersion))` (moshi).
    if let Some(inner) = rest.strip_prefix("kotlin(") {
        let (module, tail) = quoted(inner.trim_start())?;
        if module != "gradle-plugin" {
            return None;
        }
        let tail = tail.trim_start().strip_prefix(',')?.trim_start();
        let tail = tail
            .strip_prefix("version")
            .and_then(|t| t.trim_start().strip_prefix('='))
            .unwrap_or(tail)
            .trim();
        let value = tail.trim_end_matches(')').trim();
        let version = match quoted(value) {
            Some((v, _)) => expand(v, vars).ok()?,
            None => vars.get(value)?.clone(),
        };
        return Some((KOTLIN_JVM, version));
    }
    let (text, _) = quoted(rest)?;
    let c = coordinate(text, vars).ok()?;
    let id = match (c.group.as_str(), c.artifact.as_str()) {
        ("org.springframework.boot", "spring-boot-gradle-plugin") => SPRING_BOOT,
        ("org.jetbrains.kotlin", "kotlin-gradle-plugin") => KOTLIN_JVM,
        ("io.freefair.gradle", "lombok-plugin") => FREEFAIR_LOMBOK,
        ("io.franzbecker", "gradle-lombok") => FRANZBECKER_LOMBOK,
        ("org.gretty", "gretty") => GRETTY,
        _ => return None,
    };
    Some((id, c.version?))
}
const KOTLIN_JVM: &str = "org.jetbrains.kotlin.jvm";
const FREEFAIR_LOMBOK: &str = "io.freefair.lombok";
/// The older franzbecker Lombok plugin: the same extension, Lombok on `compileOnly` and
/// `testCompileOnly` (LogNet's gRPC starter).
const FRANZBECKER_LOMBOK: &str = "io.franzbecker.gradle-lombok";
const GRETTY: &str = "org.gretty";

/// Plugin major version, container, and the two APIs as group, artifact and version.
type GrettyApis = (
    &'static str,
    Option<&'static str>,
    [(&'static str, &'static str, &'static str); 2],
);

/// The servlet and websocket APIs Gretty adds to every classpath of a project that applies it,
/// by plugin major version and `servletContainer` (`None`: the default): only what real
/// Gradle showed (Hystrix on 3.0.5 with `jetty9`, spring-integration-samples on 4.1.10).
/// Another pairing is reported, never guessed.
const GRETTY_APIS: &[GrettyApis] = &[
    (
        "3",
        Some("jetty9"),
        [
            ("javax.servlet", "javax.servlet-api", "3.1.0"),
            ("javax.websocket", "javax.websocket-api", "1.0"),
        ],
    ),
    (
        "4",
        None,
        [
            ("jakarta.servlet", "jakarta.servlet-api", "5.0.0"),
            ("jakarta.websocket", "jakarta.websocket-api", "2.0.0"),
        ],
    ),
];

/// What Gretty adds to a build file that applies it, from its `gretty { servletContainer }`.
/// `useJUnitJupiter("v")` or `useJUnitJupiter(libs.versions.x)` in a test suite: Gradle adds
/// `org.junit.jupiter:junit-jupiter:v` to the suite's implementation and the JUnit Platform
/// launcher to its runtime only, at the platform release that ships with v (1.x.y for
/// Jupiter 5.x.y, the same number from JUnit 6). With no version, Gradle's own default is not
/// known here and it is reported.
fn jupiter_suite(line: &str, context: &Context, module: &mut Module) {
    let Some(arg) = line
        .strip_prefix("useJUnitJupiter(")
        .and_then(|a| a.trim_end().strip_suffix(')'))
        .map(str::trim)
    else {
        return;
    };
    let version = match quoted(arg) {
        Some((v, tail)) if tail.trim().is_empty() && !v.contains('$') => Some(v.to_string()),
        _ => arg
            .strip_prefix("libs.versions.")
            .and_then(|a| context.catalog.versions.get(a))
            .cloned(),
    };
    let Some(version) = version else {
        module
            .unread
            .push(format!("`{line}`: the JUnit Jupiter version is not read"));
        return;
    };
    let launcher = match version.split_once('.') {
        Some(("5", rest)) => format!("1.{rest}"),
        _ => version.clone(),
    };
    for (group, artifact, v, runtime_only) in [
        ("org.junit.jupiter", "junit-jupiter", version, false),
        (
            "org.junit.platform",
            "junit-platform-launcher",
            launcher,
            true,
        ),
    ] {
        module.deps.push(Declared {
            coordinate: Coordinate {
                group: group.to_string(),
                artifact: artifact.to_string(),
                version: Some(v),
                enforced: false,
                strict: false,
                test: false,
            },
            scope: "test",
            exclusions: Vec::new(),
            pom: false,
            exported: false,
            runtime_only,
            local: false,
            soft: false,
        });
    }
}

fn gretty_apis(text: &str, context: &Context, module: &mut Module) {
    if !module.applied.iter().any(|id| id == GRETTY) {
        return;
    }
    let Some(version) = context.plugins.get(GRETTY) else {
        module
            .unread
            .push("org.gretty: the plugin version is not known".to_string());
        return;
    };
    let container = text.lines().find_map(|l| {
        let rest = l
            .trim()
            .strip_prefix("gretty.")
            .unwrap_or(l.trim())
            .strip_prefix("servletContainer")?;
        let rest = rest.trim_start().strip_prefix('=')?.trim_start();
        quoted(rest).map(|(v, _)| v.to_string())
    });
    let major = version.split('.').next().unwrap_or_default();
    let Some((_, _, apis)) = GRETTY_APIS
        .iter()
        .find(|(m, c, _)| *m == major && c.map(str::to_string) == container)
    else {
        module.unread.push(format!(
            "org.gretty {version} ({}): the servlet APIs it adds are not known",
            container.as_deref().unwrap_or("default container")
        ));
        return;
    };
    for (group, artifact, v) in apis {
        module.deps.push(Declared {
            coordinate: Coordinate {
                group: (*group).to_string(),
                artifact: (*artifact).to_string(),
                version: Some((*v).to_string()),
                enforced: false,
                strict: false,
                test: false,
            },
            // `grettyProvidedCompile`, through the war plugin's `providedCompile`: on the
            // compile and runtime classpaths and the test ones, not passed to consumers.
            scope: "compile",
            exclusions: Vec::new(),
            pom: false,
            exported: false,
            runtime_only: false,
            local: true,
            soft: false,
        });
    }
}

/// The Lombok version the freefair plugin adds when the build sets none, by plugin version:
/// only what real Gradle showed (grpc-spring on 8.6, halo on 9.8.0). Another release's is
/// not known here and is reported, never guessed.
const FREEFAIR_LOMBOK_DEFAULTS: &[(&str, &str)] = &[("8.6", "1.18.30"), ("9.8.0", "1.18.48")];

/// `lombok { version = "1.18.48" }` (or `version.set(...)`, or `lombok.version = ...`): the
/// freefair plugin's extension, setting the Lombok it adds.
fn lombok_extension(text: &str, vars: &BTreeMap<String, String>) -> Option<String> {
    let mut inside = false;
    for line in text.lines() {
        let trimmed = line.trim();
        let setting = if let Some(rest) = trimmed.strip_prefix("lombok.version") {
            Some(rest)
        } else if inside {
            trimmed.strip_prefix("version")
        } else {
            None
        };
        if let Some(rest) = setting {
            let rest = rest.trim_start();
            let value = rest
                .strip_prefix('=')
                .or_else(|| {
                    rest.strip_prefix(".set(")
                        .and_then(|r| r.trim_end().strip_suffix(')'))
                })
                .map(str::trim);
            if let Some(version) = value.and_then(|v| rule_version(v, vars)) {
                return Some(version);
            }
        }
        let word = trimmed.trim_end_matches(['{', ' ']);
        if word == "lombok" && trimmed.ends_with('{') {
            inside = true;
        } else if inside && trimmed.starts_with('}') {
            inside = false;
        }
    }
    None
}
const SPRING_DM: &str = "io.spring.dependency-management";

/// The plugin a line applies, with its version when the line gives one: `id 'x' version '1'`,
/// `id("x") version "1"`, `kotlin("jvm") version "1"` or `alias(libs.plugins.x)`.
fn plugin_line(
    line: &str,
    catalog: &Catalog,
    vars: &BTreeMap<String, String>,
) -> Option<(String, Option<String>)> {
    if let Some(alias) = line.strip_prefix("alias(libs.plugins.") {
        let alias = alias.split(')').next()?;
        return Some((catalog.plugin_aliases.get(alias)?.clone(), None));
    }
    // `apply plugin: 'x'` or `apply(plugin = "x")`, which never carry a version.
    if let Some(rest) = line
        .strip_prefix("apply plugin:")
        .or_else(|| line.strip_prefix("apply(plugin ="))
        .or_else(|| line.strip_prefix("apply(plugin:"))
        // `apply { plugin("x") }` (dgs) and `pluginManager.apply("x")`.
        .or_else(|| line.strip_prefix("plugin("))
        .or_else(|| line.strip_prefix("pluginManager.apply("))
    {
        let (id, _) = quoted(rest.trim())?;
        let id = if id == "kotlin" { KOTLIN_JVM } else { id };
        return Some((id.to_string(), None));
    }
    let (id, rest) = if let Some(rest) = line.strip_prefix("kotlin(") {
        let (short, tail) = quoted(rest.trim())?;
        (format!("org.jetbrains.kotlin.{short}"), tail)
    } else {
        let rest = line.strip_prefix("id")?;
        let rest = rest.trim_start().trim_start_matches('(').trim_start();
        let (id, tail) = quoted(rest)?;
        (id.to_string(), tail)
    };
    let rest = rest.trim_start().trim_start_matches(')').trim_start();
    let version = rest.strip_prefix("version").and_then(|v| {
        let v = v.trim_start().trim_start_matches('(').trim_start();
        match quoted(v) {
            Some((v, _)) => Some(v.to_string()),
            // `version libs.versions.x.get()`
            None => {
                let name = v.trim_end();
                let name = name
                    .strip_suffix(".get())")
                    .or_else(|| name.strip_suffix(".get()"));
                let name = name.unwrap_or(v).trim_end_matches(')').trim_end();
                match name.strip_prefix("libs.versions.") {
                    Some(name) => catalog.versions.get(name).cloned(),
                    // `version kotlinVersion`, a variable the script sets.
                    None => vars.get(name).cloned(),
                }
            }
        }
    });
    Some((id, version))
}

/// `"g:a:v"`, `{ module = "g:a", version = ... }` or `{ group, name, version }`, where a version
/// is a string, `{ ref = "x" }`, `version.ref = "x"` or rich (`strictly`, `require`, `prefer`).
fn library(entry: &toml::Value, versions: Option<&toml::Value>) -> Result<Coordinate, String> {
    if let Some(text) = entry.as_str() {
        return coordinate(text, &BTreeMap::new());
    }
    let text = |key: &str| entry.get(key).and_then(toml::Value::as_str);
    let (group, artifact) = match (text("module"), text("group"), text("name")) {
        (Some(module), _, _) => module
            .split_once(':')
            .ok_or_else(|| format!("module `{module}` is not group:name"))?,
        (None, Some(group), Some(name)) => (group, name),
        _ => return Err("names no module".to_string()),
    };
    let version = match entry.get("version") {
        None => None,
        Some(v) => Some(catalog_version(v, versions)?),
    };
    Ok(Coordinate {
        group: group.to_string(),
        artifact: artifact.to_string(),
        version: version.map(|v| version_text(&v)).transpose()?,
        enforced: false,
        strict: false,
        test: false,
    })
}

fn catalog_version(value: &toml::Value, versions: Option<&toml::Value>) -> Result<String, String> {
    if let Some(version) = value.as_str() {
        return Ok(version.to_string());
    }
    if let Some(name) = value.get("ref").and_then(toml::Value::as_str) {
        let target = versions
            .and_then(|v| v.get(name))
            .ok_or_else(|| format!("version.ref `{name}` is not defined"))?;
        return catalog_version(target, None);
    }
    ["strictly", "require", "prefer"]
        .iter()
        .find_map(|k| value.get(*k).and_then(toml::Value::as_str))
        .map(str::to_string)
        .ok_or_else(|| "has no usable version".to_string())
}

/// A version as the resolver spells it. A prefix version (`3.19+`) is settled from the
/// listing like a range; `latest.release` depends on each version's status, which a Maven
/// repository does not record, so it is reported rather than picked.
fn version_text(version: &str) -> Result<String, String> {
    let v = version.trim();
    if v.starts_with("latest.") {
        return Err(format!("dynamic version `{v}`"));
    }
    // Gradle writes an excluded bound with the bracket reversed: `[1.0,2.0[`.
    let mut out = v.to_string();
    if out.starts_with(']') {
        out.replace_range(0..1, "(");
    }
    if out.starts_with(['[', '(']) && out.ends_with('[') {
        out.pop();
        out.push(')');
    }
    Ok(out)
}

fn coordinate(text: &str, vars: &BTreeMap<String, String>) -> Result<Coordinate, String> {
    // A classifier picks one of the artifact's files, never the package or its version: one
    // computed from the host (xpipe's JavaFX `:${platform}`, `win`, `mac` or `linux`) leaves
    // `group:name:version` as read.
    let expanded = expand(text, vars).or_else(|err| {
        let segments: Vec<&str> = text.split(':').collect();
        match segments.as_slice() {
            [g, a, v, _classifier] => expand(&format!("{g}:{a}:{v}"), vars).map_err(|_| err),
            _ => Err(err),
        }
    })?;
    let plain = expanded.split('@').next().unwrap_or_default();
    let mut parts = plain.split(':');
    let (Some(group), Some(artifact)) = (parts.next(), parts.next()) else {
        return Err(format!("`{text}` is not group:name:version"));
    };
    if group.is_empty() || artifact.is_empty() {
        return Err(format!("`{text}` is not group:name:version"));
    }
    // `1.0!!` is Gradle's shorthand for `strictly("1.0")`, read as a `strictly` block is.
    let version = parts
        .next()
        .map(|v| v.strip_suffix("!!").unwrap_or(v))
        .filter(|v| !v.is_empty());
    Ok(Coordinate {
        group: group.to_string(),
        artifact: artifact.to_string(),
        version: version.map(version_text).transpose()?,
        enforced: false,
        strict: false,
        test: false,
    })
}

/// Replace `$name` and `${name}`, or fail naming the text.
fn expand(text: &str, vars: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let (name, tail) = if let Some(inner) = after.strip_prefix('{') {
            let end = inner.find('}').ok_or(format!("`{text}` is computed"))?;
            (&inner[..end], &inner[end + 1..])
        } else {
            let end = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                .unwrap_or(after.len());
            (&after[..end], &after[end..])
        };
        let name = name.trim();
        let name = name.strip_suffix(".get()").unwrap_or(name);
        let keyed = map_reference(name);
        let name = keyed.as_deref().unwrap_or(name);
        let short = [
            "rootProject.ext.",
            "project.ext.",
            "rootProject.",
            "project.",
            "ext.",
        ]
        .iter()
        .find_map(|p| name.strip_prefix(p))
        .unwrap_or(name);
        let value = vars
            .get(name)
            .or_else(|| vars.get(short))
            .ok_or_else(|| format!("`{text}` is computed"))?;
        out.push_str(value);
        rest = tail;
    }
    out.push_str(rest);
    Ok(out)
}

struct Context {
    vars: BTreeMap<String, String>,
    catalog: Catalog,
    /// The Lombok version a freefair `lombok { }` extension sets.
    lombok: Option<String>,
    /// Plugin id to the version any script or the catalog gives it.
    plugins: BTreeMap<String, String>,
    /// Catalog aliases some build file names.
    used: BTreeSet<String>,
    /// Whether the declaration being read is exported (see `exported_by`).
    exported: bool,
    /// Whether it is runtime-only (see `Declared::runtime_only`).
    runtime_only: bool,
    /// Whether it is on this project's classpaths only (see `Declared::local`).
    local: bool,
    /// Configurations build logic puts on every source set's compile and runtime classpaths
    /// and on no consumer's (see `local_configurations`).
    local_configurations: BTreeSet<String>,
    /// Whether its configuration is a tool's own (`checkstyle`), which no classpath read here
    /// extends: its constraints manage nothing read.
    custom: bool,
    /// `testImplementation.extendsFrom testShadow`: a custom configuration to the standard one
    /// that takes it in, so it gets that one's scope.
    extended_by: BTreeMap<String, String>,
    /// Some script applies the Spring dependency-management plugin.
    spring_dm: bool,
    /// The declaration being read is on an annotation processor's path (`kapt`, `ksp`,
    /// `annotationProcessor`), which no classpath read here extends.
    processor: bool,
    /// `name = [ libs.a, "g:b:1", ... ]`: lists a declaration names whole
    /// (kafka's `testRuntimeOnly runtimeTestLibs`).
    lists: BTreeMap<String, Vec<String>>,
    /// The Spring plugin's open `dependencySet(group: g, version: v) {`: its group, version
    /// and the block depth its `entry` lines sit at.
    dependency_set: Option<(String, String, usize)>,
}

impl Context {
    /// The aliases a `libs.a.b` accessor names: one library, or a bundle's members.
    fn aliases(&self, path: &str) -> Vec<String> {
        if let Some(bundle) = path.strip_prefix("bundles.") {
            let found = self
                .catalog
                .bundles
                .iter()
                .find(|(a, _)| accessor(a) == bundle);
            return found
                .map(|(_, members)| members.clone())
                .unwrap_or_default();
        }
        self.catalog
            .libraries
            .keys()
            .filter(|a| accessor(a) == path)
            .cloned()
            .collect()
    }
}

fn scope_of(configuration: &str) -> &'static str {
    // Source sets of their own (`jmhImplementation`, `benchmarkImplementation`) are on no
    // main classpath, and never reach a project that depends on this one.
    const OWN_SOURCE_SETS: &[&str] = &[
        "jmh",
        "benchmark",
        "jcstress",
        "perf",
        "e2e",
        "integration",
        "sample",
        "example",
        "docs",
    ];
    let lower = configuration.to_ascii_lowercase();
    if lower.contains("test") || OWN_SOURCE_SETS.iter().any(|p| lower.starts_with(p)) {
        "test"
    } else if lower.contains("compileonly")
        || lower.contains("annotationprocessor")
        || lower.starts_with("kapt")
        || lower.starts_with("ksp")
    {
        "provided"
    } else if lower.contains("runtimeonly") || lower == "runtime" {
        "runtime"
    } else {
        "compile"
    }
}

/// Fold a rich version block into its declaration, so `api("g:a") { version { require("1.0") } }`
/// over several lines reads as `api("g:a:1.0")`: `strictly` first, then `require`, then
/// `prefer`. A declaration that already has a version, or a block naming none, is left alone.
fn fold_rich_versions(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let folded = (|| {
            let code = line.trim();
            let open = code.strip_suffix('{')?.trim_end();
            let (head, call) = open.split_once('(')?;
            let call = call.strip_suffix(')')?;
            if head.is_empty() || !head.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return None;
            }
            let (coord, tail) = quoted(call.trim())?;
            if !tail.trim().is_empty() || coord.matches(':').count() != 1 {
                return None;
            }
            // The block's lines, by brace depth.
            let mut depth = 0i32;
            let mut end = i;
            for (j, l) in lines.iter().enumerate().skip(i) {
                let code = code_only(l);
                depth += code.matches('{').count() as i32 - code.matches('}').count() as i32;
                if depth <= 0 {
                    end = j;
                    break;
                }
            }
            if end == i || end - i > 40 {
                return None;
            }
            let body = &lines[i + 1..end];
            let version = ["strictly(", "require(", "prefer("].iter().find_map(|k| {
                body.iter().find_map(|l| {
                    let at = l.find(k)? + k.len();
                    quoted(l[at..].trim()).map(|(v, _)| v.to_string())
                })
            })?;
            let indent = &line[..line.len() - line.trim_start().len()];
            Some((format!("{indent}{head}(\"{coord}:{version}\")"), end))
        })();
        match folded {
            Some((joined, end)) => {
                out.push_str(&joined);
                out.push('\n');
                // Keep the line count, so nothing else shifts.
                for _ in i + 1..=end {
                    out.push('\n');
                }
                i = end + 1;
            }
            None => {
                out.push_str(line);
                out.push('\n');
                i += 1;
            }
        }
    }
    out
}

/// `a.extendsFrom b, c`, `a.extendsFrom(b)` or `configurations.a.extendsFrom(b)`: each custom
/// configuration named, to the standard one `a` that takes it in.
fn extends_from(line: &str, out: &mut BTreeMap<String, String>) {
    let line = line.strip_prefix("configurations.").unwrap_or(line);
    let Some((target, sources)) = line.split_once(".extendsFrom") else {
        return;
    };
    let target = target.trim().trim_end_matches(".get()");
    if !is_configuration(target) {
        return;
    }
    let sources = sources.trim().trim_start_matches('(');
    let sources = sources.split(')').next().unwrap_or_default();
    for source in sources.split(',') {
        let source = source.trim();
        let source = source.strip_prefix("configurations.").unwrap_or(source);
        let plain = !source.is_empty()
            && source
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        if plain && !is_configuration(source) {
            out.insert(source.to_string(), target.to_string());
        }
    }
}

fn is_configuration(name: &str) -> bool {
    const NAMES: &[&str] = &["api", "implementation", "compile", "runtime", "kapt", "ksp"];
    const ENDINGS: &[&str] = &[
        "Api",
        "Implementation",
        "Compile",
        "Runtime",
        "CompileOnly",
        "CompileOnlyApi",
        "RuntimeOnly",
        "AnnotationProcessor",
    ];
    NAMES.contains(&name)
        || name == "compileOnly"
        || name == "compileOnlyApi"
        || name == "runtimeOnly"
        || name == "annotationProcessor"
        || name.starts_with("kapt")
        || name.starts_with("ksp")
        || ENDINGS.iter().any(|e| name.ends_with(e))
}

/// `implementation(project(":p")) { exclude ... }`: p's path, the scope, whether exported, the
/// block's exclusions, and which of p's configurations it names.
type ProjectDep = (String, &'static str, bool, Exclusions, Named);

/// The configuration of p a project dependency names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Named {
    /// None: what p exports.
    Exported,
    /// One of p's own (`configuration: 'tests'`): all p holds is handed over.
    Whole,
    /// A configuration build logic keeps to p (`configuration: 'optional'`, see
    /// `local_configurations`): what it holds, on both classpaths.
    Local,
}

/// `configuration: 'x'` (or `configuration = "x"`) in a project dependency: x.
fn configuration_named(text: &str) -> Option<&str> {
    let at = text.find("configuration")? + "configuration".len();
    let rest = text[at..]
        .trim_start()
        .strip_prefix([':', '='])?
        .trim_start();
    quoted(rest).map(|(v, _)| v)
}

/// Exclusions by (group, module), `*` for either part left out.
type Exclusions = Vec<(String, String)>;

/// A project reached through project dependencies: its index, the scope, the exclusions on the
/// way, whether it lies behind a project that does not export it (on a test path), and whether
/// a named configuration of it was asked for.
type QueuedProject = (usize, &'static str, Exclusions, bool, Named);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Block {
    Dependencies,
    Constraints,
    /// The Spring plugin's `dependencyManagement { }`: `imports { mavenBom ... }` and
    /// `dependencies { dependency ... }` manage versions.
    Management,
    ManagedVersions,
    /// `subprojects { }`, `allprojects { }`, `configure(subprojects...) { }`.
    Shared,
    /// `testing { suites { } }` or `testing.suites { }`: JVM test suites, whose
    /// `dependencies { implementation(...) }` are test dependencies.
    Suites,
    /// An `if`/`else` branch a default build takes (no `-D` or `-P` flags): read as the
    /// block around it.
    Taken,
    Other,
}

/// `read_project_script`, with each `a.extendsFrom(b)` the script itself writes taking
/// precedence: xpipe's app puts its `javafx` configuration in `implementation`, its
/// extensions in `compileOnly`.
fn read_script(text: &str, context: &mut Context) -> Module {
    let mut own = BTreeMap::new();
    for line in text.lines() {
        extends_from(line.trim(), &mut own);
    }
    if own.is_empty() {
        return read_project_script(text, context);
    }
    let saved = context.extended_by.clone();
    context.extended_by.extend(own);
    let module = read_project_script(text, context);
    context.extended_by = saved;
    module
}

fn read_project_script(text: &str, context: &mut Context) -> Module {
    let mut module = Module::default();
    let mut blocks: Vec<Block> = Vec::new();
    let mut text = null_branches(&catalog_lookups(text, &context.catalog), &context.vars);
    match catalog_platform(&text, &context.catalog, &context.vars) {
        Ok(Some(written)) => text.push_str(&written),
        Ok(None) => {}
        Err(e) => module.unread.push(e),
    }
    let text = expand_lists(&text, &context.lists);
    let text = expand_loops(&text);
    let text = fold_rich_versions(&text);
    let mut open_deps: Option<OpenDeps> = None;
    // Open branches the default build decides: (block depth inside, taken), and the last
    // one closed, for an `else` on the next line.
    let mut branches: Vec<(usize, bool)> = Vec::new();
    let mut closed_branch: Option<bool> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        let current = blocks.iter().rev().find(|b| **b != Block::Taken).copied();
        let in_deps = matches!(current, Some(Block::Dependencies | Block::Constraints));
        let is_else = trimmed
            .trim_start_matches('}')
            .trim_start()
            .strip_prefix("else")
            .is_some_and(|r| r.trim_start().starts_with('{'));
        let decided = if is_else {
            let closing = if trimmed.starts_with('}') {
                branches
                    .last()
                    .filter(|(d, _)| *d == blocks.len())
                    .map(|b| b.1)
            } else {
                closed_branch
            };
            closing.map(|taken| !taken)
        } else {
            // Outside a `dependencies { }` block only a branch the default build skips is
            // decided (logstash's `if (rootProject.fedrampHighMode) { dependencies { } }`).
            if_condition(trimmed)
                .and_then(|c| condition(c, &context.vars))
                .filter(|taken| in_deps || !taken)
        };
        closed_branch = None;
        // Inside a branch the default build skips, nothing is read, nested blocks included.
        let skipping = branches.iter().any(|&(_, taken)| !taken);
        let shared = blocks.contains(&Block::Shared);
        let before = (
            module.deps.len(),
            module.platforms.len(),
            module.constraints.len(),
            module.project_platforms.len(),
        );
        let projects_before = module.project_deps.len();
        // Whether this line applies the dependency-management plugin, for a shared block.
        let dm_before = std::mem::take(&mut module.dm);
        if decided.is_none() && !skipping {
            read_line(trimmed, current, &blocks, context, &mut module);
        }
        if shared && module.dm {
            module.shared.dm = true;
        }
        module.dm |= dm_before;
        // A suite's `useJUnitJupiter("v")` adds junit-jupiter v and the JUnit Platform
        // launcher to run it (caffeine's simulator).
        if blocks.contains(&Block::Suites) && decided.is_none() && !skipping {
            jupiter_suite(trimmed, context, &mut module);
        }
        // caffeine's `testing.suites { named<JvmTestSuite>("test") { dependencies {
        // implementation(libs.jazzer) } } }` is its test classpath.
        if blocks.contains(&Block::Suites) {
            for d in &mut module.deps[before.0..] {
                d.scope = "test";
            }
            for p in &mut module.project_deps[projects_before..] {
                p.1 = "test";
            }
        }
        // `implementation("g:a:1") { exclude(...) }`: the block's excludes belong to the
        // declarations its opening line made, here and in the shared copy.
        if let Some(open) = &open_deps {
            if blocks.len() >= open.depth {
                if let Some(ex) = exclusion(trimmed) {
                    for i in open.deps.clone() {
                        module.deps[i].exclusions.push(ex.clone());
                    }
                    for i in open.projects.clone() {
                        module.project_deps[i].3.push(ex.clone());
                    }
                    for i in open.shared.clone() {
                        module.shared.deps[i].exclusions.push(ex.clone());
                    }
                }
            } else {
                open_deps = None;
            }
        }
        let shared_before = module.shared.deps.len();
        if shared {
            module
                .shared
                .deps
                .extend_from_slice(&module.deps[before.0..]);
            module
                .shared
                .platforms
                .extend_from_slice(&module.platforms[before.1..]);
            module
                .shared
                .constraints
                .extend_from_slice(&module.constraints[before.2..]);
            module
                .shared
                .project_platforms
                .extend_from_slice(&module.project_platforms[before.3..]);
        }
        let word: String = trimmed
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let after_word = trimmed[word.len()..].trim_start();
        let new_block = if word == "dependencies"
            && after_word.starts_with('{')
            && blocks.contains(&Block::Management)
        {
            Some(Block::ManagedVersions)
        } else if word == "dependencies" && after_word.starts_with('{') {
            Some(Block::Dependencies)
        } else if word == "constraints"
            && after_word.starts_with('{')
            && current == Some(Block::Dependencies)
        {
            Some(Block::Constraints)
        } else {
            None
        };
        if let Some(block) = new_block.filter(|_| !skipping) {
            // A one-liner: `dependencies { implementation 'g:a:1' }`.
            let inner = after_word[1..].trim();
            if inner.strip_suffix('}').is_some() {
                continue;
            }
            blocks.push(block);
            continue;
        }
        let marks = if word == "dependencyManagement" {
            Some(Block::Management)
        } else if matches!(word.as_str(), "subprojects" | "allprojects")
            || (word == "configure"
                && (after_word.starts_with("(subprojects")
                    || after_word.starts_with("(allprojects")))
        {
            Some(Block::Shared)
        } else if word == "testing" {
            Some(Block::Suites)
        } else {
            None
        };
        let depth = blocks.len();
        let code = code_only(line);
        for c in code.chars() {
            match c {
                '{' => blocks.push(Block::Other),
                '}' => {
                    blocks.pop();
                }
                _ => {}
            }
        }
        if let Some(taken) = decided {
            if is_else && trimmed.starts_with('}') {
                branches.pop();
            }
            if blocks.len() > depth || (is_else && trimmed.starts_with('}')) {
                if let Some(last) = blocks.last_mut() {
                    *last = if taken { Block::Taken } else { Block::Other };
                }
                branches.push((blocks.len(), taken));
            }
        }
        while let Some(&(d, taken)) = branches.last() {
            if blocks.len() >= d {
                break;
            }
            branches.pop();
            closed_branch = Some(taken);
        }
        if module.deps.len() > before.0 || module.project_deps.len() > projects_before {
            let added = before.0..module.deps.len();
            let projects = projects_before..module.project_deps.len();
            let shared_added = shared_before..module.shared.deps.len();
            // A one-line block: `implementation('g:a:1') { exclude group: 'x' }`.
            if let Some((_, inner)) = trimmed.split_once('{') {
                for part in inner.split([';', '}']) {
                    if let Some(ex) = exclusion(part.trim()) {
                        for i in added.clone() {
                            module.deps[i].exclusions.push(ex.clone());
                        }
                        for i in projects.clone() {
                            module.project_deps[i].3.push(ex.clone());
                        }
                        for i in shared_added.clone() {
                            module.shared.deps[i].exclusions.push(ex.clone());
                        }
                    }
                }
            }
            open_deps = (blocks.len() > depth).then_some(OpenDeps {
                deps: added,
                projects,
                shared: shared_added,
                depth: blocks.len(),
            });
        }
        if let Some(mark) = marks {
            if blocks.len() > depth {
                if let Some(last) = blocks.last_mut() {
                    *last = mark;
                }
            }
        }
    }
    module
}

/// The condition of `if (cond) {`.
fn if_condition(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("if")?.trim_start().strip_prefix('(')?;
    let body = rest
        .trim_end()
        .strip_suffix('{')?
        .trim_end()
        .strip_suffix(')')?;
    Some(body.trim())
}

/// A condition a default build decides from what is read: `NAME == 'x'`, `NAME != 'x'`,
/// `NAME.equals('x')`, `hasProperty('k')` and `!` of these. `None` for anything else.
fn condition(cond: &str, vars: &BTreeMap<String, String>) -> Option<bool> {
    let c = cond.trim();
    if c.contains("&&") || c.contains("||") {
        return None;
    }
    if let Some(inner) = c.strip_prefix('!') {
        if !inner.starts_with('=') {
            return condition(inner, vars).map(|b| !b);
        }
    }
    if let Some(inner) = c.strip_prefix('(').and_then(|i| i.strip_suffix(')')) {
        return condition(inner, vars);
    }
    let value = |side: &str| -> Option<String> {
        let side = side.trim();
        if let Some((v, tail)) = quoted(side) {
            return tail.trim().is_empty().then(|| v.to_string());
        }
        vars.get(side).cloned()
    };
    for (op, equal) in [("==", true), ("!=", false)] {
        if let Some((left, right)) = c.split_once(op) {
            return Some((value(left)? == value(right)?) == equal);
        }
    }
    if let Some((left, right)) = c.split_once(".equals(") {
        let right = right.strip_suffix(')')?;
        return Some(value(left)? == value(right)?);
    }
    if let Some((left, right)) = c.split_once(".startsWith(") {
        let right = right.strip_suffix(')')?;
        return Some(value(left)?.starts_with(&value(right)?));
    }
    let name = c
        .strip_prefix("rootProject.")
        .or_else(|| c.strip_prefix("project."))
        .unwrap_or(c);
    if let Some(v) = vars.get(name) {
        return match v.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        };
    }
    for call in ["project.hasProperty(", "hasProperty("] {
        if let Some(inner) = c.strip_prefix(call) {
            let (key, tail) = quoted(inner)?;
            return (tail.trim() == ")").then(|| vars.contains_key(key));
        }
    }
    java_compatible(c)
}

/// `JavaVersion.current().isJava9Compatible()` and the like: the JDK that runs Gradle, taken
/// to be 17 or later (Gradle 9 needs it; grpc-spring's `@Generated` workaround is on under
/// real Gradle). A check for a later release is not decided.
fn java_compatible(c: &str) -> Option<bool> {
    let rest = c.strip_prefix("JavaVersion.current()")?;
    let release = if let Some(r) = rest.strip_prefix(".isCompatibleWith(JavaVersion.VERSION_") {
        r.strip_suffix(')')?.trim_start_matches("1_")
    } else {
        let r = rest
            .strip_prefix(".isJava")
            .or_else(|| rest.strip_prefix(".java"))?;
        r.strip_suffix("Compatible()")
            .or_else(|| r.strip_suffix("Compatible"))?
    };
    let release: u32 = release.parse().ok()?;
    (release <= 17).then_some(true)
}

/// `System.properties['k'] ?: 'd'`, `System.getProperty('k', 'd')` or
/// `findProperty('k') ?: 'd'`: the value a default build sees (no `-D` flags; a `-P` property
/// only from what is read).
fn property_default(value: &str, vars: &BTreeMap<String, String>) -> Option<String> {
    let v = value.trim();
    let v = v
        .strip_prefix('(')
        .and_then(|i| i.strip_suffix(')'))
        .unwrap_or(v)
        .trim();
    // `findProperty("k")?.toString() != "false"`: with k unset, a default build compares null.
    for (op, equal) in [(" != ", false), (" == ", true)] {
        if let Some((left, right)) = v.split_once(op) {
            let (literal, tail) = quoted(right.trim())?;
            if !tail.trim().is_empty() {
                return None;
            }
            let left = left.trim();
            let left = left
                .strip_suffix("?.toString()")
                .or_else(|| left.strip_suffix(".toString()"))
                .unwrap_or(left);
            let left = left
                .strip_prefix("project.")
                .or_else(|| left.strip_prefix("rootProject."))
                .unwrap_or(left);
            let (key, end) = quoted(left.strip_prefix("findProperty(")?)?;
            if end.trim() != ")" {
                return None;
            }
            let same = vars.get(key).map(String::as_str) == Some(literal);
            return Some((same == equal).to_string());
        }
    }
    if let Some(inner) = v.strip_prefix("System.getProperty(") {
        let (_, tail) = quoted(inner.trim_start())?;
        let tail = tail.trim_start().strip_prefix(',')?;
        let (default, end) = quoted(tail.trim_start())?;
        return (end.trim() == ")").then(|| default.to_string());
    }
    // `Objects.requireNonNullElse(project.findProperty('k'), false).toBoolean()` (logstash's
    // `fedrampHighMode`): the property when read, else the default.
    if let Some(inner) = v.strip_prefix("Objects.requireNonNullElse(") {
        let inner = inner
            .strip_suffix(".toBoolean()")
            .unwrap_or(inner)
            .strip_suffix(')')?;
        let (call, default) = inner.rsplit_once(',')?;
        let call = call.trim();
        let call = call.strip_prefix("project.").unwrap_or(call);
        let (key, tail) = quoted(call.strip_prefix("findProperty(")?)?;
        if tail.trim() != ")" {
            return None;
        }
        let default = default.trim();
        let default = match quoted(default) {
            Some((d, tail)) if tail.trim().is_empty() => d,
            _ if matches!(default, "true" | "false") => default,
            _ => return None,
        };
        return Some(vars.get(key).map_or(default, String::as_str).to_string());
    }
    // `providers.gradleProperty("k").map { ... }.getOrElse(false)`: the default when unset.
    for (prefix, settable) in [
        ("providers.gradleProperty(", true),
        ("providers.systemProperty(", false),
    ] {
        if let Some(inner) = v.strip_prefix(prefix) {
            let (key, _) = quoted(inner)?;
            if settable && vars.contains_key(key) {
                return None;
            }
            let default = v.rsplit_once(".getOrElse(")?.1.strip_suffix(')')?.trim();
            return match quoted(default) {
                Some((d, tail)) if tail.trim().is_empty() => Some(d.to_string()),
                _ => matches!(default, "true" | "false").then(|| default.to_string()),
            };
        }
    }
    let (call, default) = v.split_once("?:")?;
    let (default, tail) = quoted(default.trim())?;
    if !tail.trim().is_empty() {
        return None;
    }
    let call = call.trim();
    for prefix in ["System.properties[", "System.getProperty("] {
        if let Some(inner) = call.strip_prefix(prefix) {
            let (_, tail) = quoted(inner)?;
            return matches!(tail.trim(), "]" | ")").then(|| default.to_string());
        }
    }
    for prefix in ["project.findProperty(", "findProperty("] {
        if let Some(inner) = call.strip_prefix(prefix) {
            let (key, tail) = quoted(inner)?;
            if tail.trim() != ")" {
                return None;
            }
            return Some(
                vars.get(key)
                    .cloned()
                    .unwrap_or_else(|| default.to_string()),
            );
        }
    }
    None
}

/// Declarations whose block is still open, and the block depth inside it.
struct OpenDeps {
    deps: std::ops::Range<usize>,
    projects: std::ops::Range<usize>,
    shared: std::ops::Range<usize>,
    depth: usize,
}

/// `exclude group: 'g', module: 'a'`, `exclude(group = "g")` or `exclude(module: "a")`, with
/// `*` for the part left out. `transitive = false` (`isTransitive = false`) excludes everything.
fn exclusion(line: &str) -> Option<(String, String)> {
    let flag: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    if matches!(
        flag.as_str(),
        "transitive=false" | "isTransitive=false" | "transitivefalse"
    ) {
        return Some(("*".to_string(), "*".to_string()));
    }
    let rest = line.strip_prefix("exclude")?;
    if !rest.starts_with([' ', '(']) {
        return None;
    }
    let value = |key: &str| {
        let at = rest.find(key)?;
        let tail = rest[at + key.len()..].trim_start();
        let tail = tail.strip_prefix([':', '='])?;
        quoted(tail.trim_start()).map(|(v, _)| v.to_string())
    };
    let (mut group, mut module) = (value("group"), value("module"));
    if group.is_none() && module.is_none() {
        // The Kotlin DSL's positional `exclude("org.codehaus.groovy", "groovy")` (axion).
        if rest.contains("mapOf") || rest.contains(" to ") {
            return None;
        }
        let args = strings(rest);
        group = args.first().cloned();
        module = args.get(1).cloned();
        group.as_ref()?;
    }
    Some((
        group.unwrap_or_else(|| "*".to_string()),
        module.unwrap_or_else(|| "*".to_string()),
    ))
}

/// The group and version of a `dependencySet(...)` (its arguments, `rest`): a version that
/// is an expression is kept as `${...}` for the entries to expand.
fn dependency_set(rest: &str) -> Option<(String, String)> {
    let args = rest.trim().strip_prefix('(')?;
    let args = &args[..args.rfind(')')?];
    let named = |key: &str| -> Option<String> {
        let at = args.find(key)?;
        let value = args[at + key.len()..]
            .trim_start()
            .strip_prefix([':', '='])?
            .trim_start();
        if let Some((q, _)) = quoted(value) {
            return Some(q.to_string());
        }
        let end = value.find(',').unwrap_or(value.len());
        let expr = value[..end].trim();
        (!expr.is_empty() && !expr.contains(['(', ' ', '"', '\''])).then(|| format!("${{{expr}}}"))
    };
    if args.contains("group") {
        let group = named("group")?;
        let version = named("version")?;
        return (!group.contains('$')).then_some((group, version));
    }
    let (text, _) = quoted(args.trim())?;
    let (group, version) = text.split_once(':')?;
    Some((group.to_string(), version.to_string()))
}

/// One line of a build script, read by the block it sits in.
fn read_line(
    trimmed: &str,
    current: Option<Block>,
    blocks: &[Block],
    context: &mut Context,
    module: &mut Module,
) {
    if let Some((group, version, depth)) = context.dependency_set.clone() {
        if blocks.len() < depth {
            context.dependency_set = None;
        } else {
            if blocks.len() == depth {
                if let Some(rest) = trimmed.strip_prefix("entry") {
                    if let Some((artifact, _)) = quoted(rest.trim().trim_start_matches('(')) {
                        let before = module.constraints.len();
                        let line = format!("\"{group}:{artifact}:{version}\"");
                        read_values(&line, "compile", Block::Constraints, context, module);
                        for c in &mut module.constraints[before..] {
                            c.enforced = true;
                        }
                    }
                }
            }
            return;
        }
    }
    match current {
        Some(block @ (Block::Dependencies | Block::Constraints)) => {
            // `constraints {` opens a block; only what follows its brace is an entry.
            if let Some(after) = trimmed.strip_prefix("constraints") {
                if let Some(inner) = after.trim_start().strip_prefix('{') {
                    let inner = inner.trim();
                    let body = inner.strip_suffix('}').unwrap_or(inner);
                    read_entry(body.trim(), Block::Constraints, context, module);
                    return;
                }
            }
            if trimmed.contains('{') || !trimmed.starts_with('}') {
                read_entry(trimmed, block, context, module);
            }
            return;
        }
        Some(Block::ManagedVersions) => {
            // `dependency 'g:a:1'` or `dependency("g:a:1")`, and `dependencySet(group: 'g',
            // version: v) { entry 'a' }` (mmorpg's jforgame) or `dependencySet("g:v") { ... }`.
            if let Some(rest) = trimmed.strip_prefix("dependencySet") {
                if trimmed.contains('{') && !trimmed.contains('}') {
                    context.dependency_set =
                        dependency_set(rest).map(|(g, v)| (g, v, blocks.len() + 1));
                }
                return;
            }
            if let Some(rest) = trimmed.strip_prefix("dependency") {
                if rest.starts_with([' ', '(']) {
                    let before = module.constraints.len();
                    read_values(rest, "compile", Block::Constraints, context, module);
                    for c in &mut module.constraints[before..] {
                        c.enforced = true;
                    }
                }
            }
            return;
        }
        _ => {}
    }
    apply_plugin(trimmed, context, module);
    if blocks.contains(&Block::Management) {
        if let Some(rest) = trimmed.strip_prefix("mavenBom") {
            let inner = rest.trim().trim_start_matches('(');
            let inner = inner.trim_end().trim_end_matches(')');
            let before = module.platforms.len();
            let listed = module.deps.len();
            read_values(
                &format!("platform({inner})"),
                "compile",
                Block::Dependencies,
                context,
                module,
            );
            // The plugin manages versions with it; it is not a dependency.
            module.deps.truncate(listed);
            for c in &mut module.platforms[before..] {
                c.enforced = true;
            }
        }
    }
    // `dependencies { implementation 'g:a:1' }` on one line.
    let word: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    let after_word = trimmed[word.len()..].trim_start();
    if word == "dependencies" && !blocks.contains(&Block::Management) {
        if let Some(inner) = after_word.strip_prefix('{') {
            let inner = inner.trim();
            let body = inner.strip_suffix('}').unwrap_or(inner);
            read_entry(body.trim(), Block::Dependencies, context, module);
        }
    }
}

/// The dependencies a plugin brings: Spring Boot's BOM and Kotlin's standard library.
fn apply_plugin(line: &str, context: &Context, module: &mut Module) {
    if line == "`kotlin-dsl`" || line.starts_with("id(\"org.gradle.kotlin.kotlin-dsl\")") {
        kotlin_dsl(context, module);
        return;
    }
    let Some((id, _)) = plugin_line(line, &context.catalog, &context.vars) else {
        return;
    };
    if !line.trim_end().ends_with("apply false") {
        module.applied.push(id.clone());
    }
    if id == SPRING_DM && !line.trim_end().ends_with("apply false") {
        module.dm = true;
    }
    let Some(version) = context.plugins.get(&id) else {
        return;
    };
    // `id 'x' version "${xVersion}"` with the variable set in `buildscript { ext { } }`.
    let version = &expand(version, &context.vars).unwrap_or_else(|_| version.clone());
    if id == SPRING_BOOT {
        // From 3.5 the plugin adds the JUnit Platform launcher to `testRuntimeOnly` (komga,
        // petclinic, Timefold's spring-boot-integration list it without declaring it).
        let launcher = {
            let mut parts = version.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
            (parts.next().unwrap_or(0), parts.next().unwrap_or(0)) >= (3, 5)
        };
        if launcher && !line.trim_end().ends_with("apply false") {
            module.deps.push(Declared {
                coordinate: Coordinate {
                    group: "org.junit.platform".to_string(),
                    artifact: "junit-platform-launcher".to_string(),
                    version: None,
                    enforced: false,
                    strict: false,
                    test: false,
                },
                scope: "test",
                exclusions: Vec::new(),
                pom: false,
                exported: false,
                runtime_only: true,
                local: false,
                soft: false,
            });
        }
        // Spring Boot applies its BOM through the dependency-management plugin, and only
        // when the build applies that plugin somewhere (armeria applies Boot alone, and
        // Gradle keeps its caffeine 2.9.3 under Boot 3.5.16's 3.2.4).
        if context.spring_dm {
            module.platforms.push(Coordinate {
                group: "org.springframework.boot".to_string(),
                artifact: "spring-boot-dependencies".to_string(),
                version: Some(version.clone()),
                enforced: true,
                strict: false,
                test: false,
            });
        }
    } else if (id == FREEFAIR_LOMBOK || id == FRANZBECKER_LOMBOK)
        && !line.trim_end().ends_with("apply false")
    {
        // The plugin adds Lombok to `compileOnly` and `annotationProcessor`, and to their test
        // counterparts.
        let default = FREEFAIR_LOMBOK_DEFAULTS
            .iter()
            .filter(|_| id == FREEFAIR_LOMBOK)
            .find(|(plugin, _)| plugin == version)
            .map(|(_, lombok)| (*lombok).to_string());
        let Some(lombok) = context.lombok.clone().or(default) else {
            module.unread.push(format!(
                "{id} {version}: the Lombok version it adds is not known"
            ));
            return;
        };
        for scope in ["provided", "test"] {
            module.deps.push(Declared {
                coordinate: Coordinate {
                    group: "org.projectlombok".to_string(),
                    artifact: "lombok".to_string(),
                    version: Some(lombok.clone()),
                    enforced: false,
                    strict: false,
                    test: false,
                },
                scope,
                exclusions: Vec::new(),
                pom: false,
                exported: false,
                runtime_only: false,
                local: false,
                soft: false,
            });
        }
    } else if id == KOTLIN_JVM
        // `kotlin.stdlib.default.dependency=false` turns the added library off (reposilite).
        && context.vars.get("kotlin.stdlib.default.dependency").map(String::as_str) != Some("false")
    {
        let Some(stdlib) = kotlin_default_stdlib(version) else {
            module.unread.push(format!(
                "org.jetbrains.kotlin.jvm {version}: the standard library it adds is not known"
            ));
            return;
        };
        module.deps.push(Declared {
            coordinate: Coordinate {
                group: "org.jetbrains.kotlin".to_string(),
                artifact: stdlib.to_string(),
                version: Some(version.clone()),
                enforced: false,
                strict: false,
                test: false,
            },
            scope: "compile",
            exclusions: Vec::new(),
            pom: false,
            // The Kotlin plugin adds the standard library to `api`.
            exported: true,
            runtime_only: false,
            local: false,
            // A BOM the Spring plugin imports manages it (mmorpg's Boot 3.0.4: 1.7.22).
            soft: true,
        });
    }
}

/// The standard library the Kotlin plugin adds, by plugin version: `kotlin-stdlib` from 1.9.23
/// (grpc-spring), `kotlin-stdlib-jdk8` on 1.8.0 (Charlatano), as real Gradle showed. A release
/// in between, or older, is not known here and is reported, never guessed.
fn kotlin_default_stdlib(version: &str) -> Option<&'static str> {
    if version == "1.8.0" {
        return Some("kotlin-stdlib-jdk8");
    }
    (crate::version::gradle_cmp(version, "1.9.23") != std::cmp::Ordering::Less)
        .then_some("kotlin-stdlib")
}

/// The Kotlin each Gradle release embeds, from its minimum Gradle version (Gradle's
/// compatibility page, read at 9.9.1).
const EMBEDDED_KOTLIN: &[(&str, &str)] = &[
    ("5.0", "1.3.10"),
    ("5.1", "1.3.11"),
    ("5.2", "1.3.20"),
    ("5.3", "1.3.21"),
    ("5.5", "1.3.31"),
    ("5.6", "1.3.41"),
    ("6.0", "1.3.50"),
    ("6.1", "1.3.61"),
    ("6.3", "1.3.70"),
    ("6.4", "1.3.71"),
    ("6.5", "1.3.72"),
    ("6.8", "1.4.20"),
    ("7.0", "1.4.31"),
    ("7.2", "1.5.21"),
    ("7.3", "1.5.31"),
    ("7.5", "1.6.21"),
    ("7.6", "1.7.10"),
    ("8.0", "1.8.10"),
    ("8.2", "1.8.20"),
    ("8.3", "1.9.0"),
    ("8.4", "1.9.10"),
    ("8.5", "1.9.20"),
    ("8.7", "1.9.22"),
    ("8.9", "1.9.23"),
    ("8.10", "1.9.24"),
    ("8.11", "2.0.20"),
    ("8.12", "2.0.21"),
    ("9.0", "2.2.0"),
    ("9.2", "2.2.20"),
    ("9.3", "2.2.21"),
    ("9.4", "2.3.0"),
    ("9.5", "2.3.20"),
    ("9.6", "2.3.21"),
    ("9.7", "2.4.0"),
    ("9.8", "2.4.10"),
    ("9.9", "2.4.21"),
];

/// `9.8.2` as numbers, to compare release lines.
fn gradle_release(version: &str) -> Vec<u32> {
    version
        .split(['.', '-'])
        .map_while(|p| p.parse().ok())
        .collect()
}

/// The `kotlin-dsl` plugin compiles against the Kotlin the running Gradle embeds: its
/// standard library and reflection, on the compile and test classpaths but not the runtime
/// one (axion on Gradle 9.8, Kotlin 2.4.10). Before Gradle 8 the library is
/// `kotlin-stdlib-jdk8` (node-gradle on 7.6); in 8.x, unconfirmed, only the parts both forms
/// bring. No wrapper, or a Gradle newer than the table, adds nothing.
fn kotlin_dsl(context: &Context, module: &mut Module) {
    let Some(running) = context.vars.get(GRADLE_VERSION).map(|v| gradle_release(v)) else {
        return;
    };
    let Some(last) = EMBEDDED_KOTLIN.last() else {
        return;
    };
    // A release past the table's last line may embed a newer Kotlin.
    if running[..running.len().min(2)] > gradle_release(last.0)[..] {
        return;
    }
    let Some((_, kotlin)) = EMBEDDED_KOTLIN
        .iter()
        .rev()
        .find(|(min, _)| gradle_release(min) <= running)
    else {
        return;
    };
    let stdlib = if running < vec![8] {
        "kotlin-stdlib-jdk8"
    } else {
        "kotlin-stdlib"
    };
    for (artifact, scope) in [
        (stdlib, "provided"),
        ("kotlin-reflect", "provided"),
        (stdlib, "test"),
        ("kotlin-reflect", "test"),
    ] {
        module.deps.push(Declared {
            coordinate: Coordinate {
                group: "org.jetbrains.kotlin".to_string(),
                artifact: artifact.to_string(),
                version: Some((*kotlin).to_string()),
                enforced: false,
                strict: false,
                test: false,
            },
            scope,
            exclusions: Vec::new(),
            pom: false,
            exported: false,
            runtime_only: false,
            local: false,
            soft: false,
        });
    }
}

/// The plugin id of a precompiled script plugin: `cosid.java` for
/// `build-logic/src/main/kotlin/cosid.java.gradle.kts`, under its `package` when it has one.
/// Scripts under `src/main/kotlin` or `src/main/groovy` only.
fn convention_id(file: &str, text: &str) -> Option<String> {
    let at = file
        .find("src/main/kotlin/")
        .or_else(|| file.find("src/main/groovy/"))?;
    if at > 0 && !file[..at].ends_with('/') {
        return None;
    }
    let name = file.rsplit('/').next()?;
    let stem = name
        .strip_suffix(".gradle.kts")
        .or_else(|| name.strip_suffix(".gradle"))?;
    if stem.is_empty() || stem == "build" {
        return None;
    }
    let package = name
        .ends_with(".kts")
        .then(|| {
            text.lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .and_then(|l| l.strip_prefix("package "))
                .map(|p| p.trim().trim_end_matches(';').to_string())
        })
        .flatten();
    Some(match package {
        Some(p) if !p.is_empty() => format!("{p}.{stem}"),
        _ => stem.to_string(),
    })
}

/// The plugins build logic registers as classes (`gradlePlugin { plugins { register("x") {
/// id = "kotlinLib"; implementationClass = "a.b.LibPlugin" } } }` in buildSrc or
/// build-logic), each as (id, the class's file, a script of what its `apply` adds for sure):
/// the literal `add("testImplementation", "g:a:1")` calls in a `dependencies { }` block and
/// `plugins.apply("kotlin")`, outside any `if`, `when`, loop or callback (Talaiot's `kotlinLib`
/// adds kotlintest and mockito-kotlin to every library's tests).
/// The project's toolchain version in a condition, as the scripts are read.
const TOOLCHAIN: &str = "TOOLCHAIN_VERSION";

/// `TOOLCHAIN op n`: a condition on the project's Java toolchain version.
type Toolchain = (&'static str, i64);

/// `TOOLCHAIN_VERSION < 17` (`<`, `<=`, `>`, `>=`), as a condition to decide per project.
fn toolchain_test(cond: &str) -> Option<Toolchain> {
    let rest = cond.trim().strip_prefix(TOOLCHAIN)?.trim_start();
    for op in ["<=", ">=", "<", ">"] {
        if let Some(n) = rest.strip_prefix(op) {
            return Some((op, n.trim().parse().ok()?));
        }
    }
    None
}

fn toolchain_negated((op, n): Toolchain) -> Toolchain {
    let op = match op {
        "<" => ">=",
        "<=" => ">",
        ">" => "<=",
        _ => "<",
    };
    (op, n)
}

fn toolchain_holds((op, n): Toolchain, version: u32) -> bool {
    let v = i64::from(version);
    match op {
        "<" => v < n,
        "<=" => v <= n,
        ">" => v > n,
        _ => v >= n,
    }
}

/// The Java toolchain version a file's `java.toolchain { languageVersion = ... }` (or
/// `java { toolchain { ... } }`, or `java.toolchain.languageVersion = ...`) sets:
/// `JavaLanguageVersion.of(N)`, or a build-logic helper `fun Project.f():
/// Provider<JavaLanguageVersion> = providers.gradleProperty("k")[.orElse(providers
/// .environmentVariable("E"))].map { it.toIntOrNull() }.orElse(N).map(JavaLanguageVersion::of)`
/// with k unset (a default build sets no environment variable). `None` when the file sets
/// none, `Some(None)` when it sets one not read here or two that differ.
fn script_toolchain(
    dir: &Path,
    file: &str,
    text: &str,
    vars: &BTreeMap<String, String>,
) -> Option<Option<u32>> {
    let mut found: BTreeSet<Option<u32>> = BTreeSet::new();
    let mut blocks: Vec<String> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let inside = blocks.last().is_some_and(|b| {
            b == "java.toolchain {"
                || (b == "toolchain {" && blocks.iter().rev().nth(1).is_some_and(|p| p == "java {"))
        });
        let value = trimmed
            .strip_prefix("languageVersion")
            .map(str::trim_start)
            .and_then(|r| {
                r.strip_prefix('=').or_else(|| {
                    r.strip_prefix(".set(")
                        .and_then(|v| v.trim_end().strip_suffix(')'))
                })
            })
            .map(str::trim);
        let value = match value {
            Some(v) if inside => Some(v),
            _ => trimmed
                .strip_prefix("java.toolchain.languageVersion")
                .map(str::trim_start)
                .and_then(|r| r.strip_prefix('='))
                .map(str::trim),
        };
        if let Some(v) = value {
            found.insert(toolchain_value(dir, file, v, vars));
        }
        for c in code_only(line).chars() {
            match c {
                '{' => blocks.push(trimmed.to_string()),
                '}' => {
                    blocks.pop();
                }
                _ => {}
            }
        }
    }
    match found.into_iter().collect::<Vec<_>>().as_slice() {
        [] => None,
        [one] => Some(*one),
        _ => Some(None),
    }
}

fn toolchain_value(
    dir: &Path,
    file: &str,
    value: &str,
    vars: &BTreeMap<String, String>,
) -> Option<u32> {
    if let Some(n) = value
        .strip_prefix("JavaLanguageVersion.of(")
        .and_then(|v| v.strip_suffix(')'))
    {
        return n.trim().parse().ok();
    }
    let name = value.strip_suffix("()")?;
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    // The helper sits in a Kotlin file of the same build logic: up from the script to the
    // `kotlin` source root.
    let mut base = Path::new(file).parent();
    while let Some(b) = base {
        if b.file_name().is_some_and(|n| n == "kotlin") {
            break;
        }
        base = b.parent();
    }
    let root = dir.join(base?);
    let header = format!("fun Project.{name}(): Provider<JavaLanguageVersion> =");
    let mut bodies = Vec::new();
    for entry in std::fs::read_dir(&root).ok()?.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "kt") {
            continue;
        }
        let Ok(text) = fleetreach_core::repofile::read_to_string(&path) else {
            continue;
        };
        if let Some((_, rest)) = text.split_once(&header) {
            let end = rest.find("\nfun ").unwrap_or(rest.len());
            bodies.push(
                rest[..end]
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>(),
            );
        }
    }
    let [body] = bodies.as_slice() else {
        return None;
    };
    let rest = body.strip_prefix("providers.gradleProperty(\"")?;
    let (key, rest) = rest.split_once("\")")?;
    let rest = match rest.strip_prefix(".orElse(providers.environmentVariable(\"") {
        Some(r) => r.split_once("\"))")?.1,
        None => rest,
    };
    let rest = rest.strip_prefix(".map{it.toIntOrNull()}.orElse(")?;
    let (default, rest) = rest.split_once(')')?;
    if rest != ".map(JavaLanguageVersion::of)" {
        return None;
    }
    match vars.get(key) {
        Some(v) => v.trim().parse().ok(),
        None => default.parse().ok(),
    }
}

/// `${libs.a.b.get().module}` (and `${libs.a.b.get().module.group}`-free forms only): the
/// `group:artifact` of that catalog library, as caffeine's forces name it.
fn catalog_modules(text: &str, catalog: &Catalog) -> String {
    if !text.contains(".get().module}") {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("${libs.") {
        out.push_str(&rest[..at]);
        let after = &rest[at + "${libs.".len()..];
        let found = after.split_once(".get().module}").and_then(|(path, tail)| {
            let ok = path
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_');
            let c = catalog
                .libraries
                .iter()
                .find(|(a, _)| accessor(a) == path)
                .map(|(_, c)| c)
                .filter(|_| ok)?;
            Some((format!("{}:{}", c.group, c.artifact), tail))
        });
        match found {
            Some((module, tail)) => {
                out.push_str(&module);
                rest = tail;
            }
            None => {
                out.push_str("${libs.");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn binary_plugins(dir: &Path, scripts: &[(String, String)]) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for (file, text) in scripts {
        if !(file.starts_with("buildSrc/") || file.starts_with("build-logic/"))
            || !text.contains("implementationClass")
        {
            continue;
        }
        let base = Path::new(file).parent().unwrap_or(Path::new(""));
        let mut id = None;
        for line in text.lines().map(str::trim) {
            let value = |key: &str| {
                let rest = line.strip_prefix(key)?.trim_start();
                let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
                let rest = rest.strip_prefix('(').unwrap_or(rest);
                quoted(rest).map(|(v, _)| v.to_string())
            };
            if let Some(v) = value("id") {
                id = Some(v);
            } else if let Some(class) = value("implementationClass") {
                let Some(id) = id.take() else {
                    continue;
                };
                let Some((shown, source)) = plugin_class(dir, base, &class) else {
                    continue;
                };
                if let Some(script) = plugin_script(&source) {
                    out.push((id, shown, script));
                }
            }
        }
    }
    out
}

/// The ids of the plugins buildSrc registers whose class applies the Java or Java Library
/// plugin itself (`plugins.apply(JavaLibraryPlugin.class)`).
fn java_plugin_ids(dir: &Path, scripts: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (file, text) in scripts {
        if !file.starts_with("buildSrc/") || !text.contains("implementationClass") {
            continue;
        }
        let base = Path::new(file).parent().unwrap_or(Path::new(""));
        let mut id = None;
        for line in text.lines().map(str::trim) {
            let value = |key: &str| {
                let rest = line.strip_prefix(key)?.trim_start();
                let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
                quoted(rest).map(|(v, _)| v.to_string())
            };
            if let Some(v) = value("id") {
                id = Some(v);
            } else if let Some(class) = value("implementationClass") {
                let (Some(id), Some((_, source))) = (id.take(), plugin_class(dir, base, &class))
                else {
                    continue;
                };
                let applies = ["JavaPlugin", "JavaLibraryPlugin", "WarPlugin"]
                    .iter()
                    .any(|p| source.contains(&format!(".apply({p}.class)")));
                if applies {
                    out.push(id);
                }
            }
        }
    }
    out
}

/// The source of build-logic class `class` (`a.b.C`): `src/main/{kotlin,java,groovy}/a/b/C.*`
/// under the build-logic project `base`.
fn plugin_class(dir: &Path, base: &Path, class: &str) -> Option<(String, String)> {
    let path = class.replace('.', "/");
    for lang in ["kotlin", "java", "groovy"] {
        for ext in ["kt", "java", "groovy"] {
            let shown = base.join(format!("src/main/{lang}/{path}.{ext}"));
            if let Ok(text) = fleetreach_core::repofile::read_to_string(dir.join(&shown)) {
                return Some((shown.display().to_string(), strip_comments(&text)));
            }
        }
    }
    None
}

/// What a plugin class's `apply` adds for sure, as a build script (see `binary_plugins`).
fn plugin_script(source: &str) -> Option<String> {
    #[derive(PartialEq)]
    enum Kind {
        Apply,
        Deps,
        Cond,
        Plain,
    }
    let mut stack: Vec<Kind> = Vec::new();
    let (mut deps, mut plugins) = (Vec::new(), Vec::new());
    for line in source.lines().map(str::trim) {
        let sure = stack.contains(&Kind::Apply) && !stack.contains(&Kind::Cond);
        if sure {
            let call = line
                .strip_prefix("target.")
                .or_else(|| line.strip_prefix("project."))
                .unwrap_or(line);
            if let Some(rest) = call
                .strip_prefix("plugins.apply(")
                .or_else(|| call.strip_prefix("pluginManager.apply("))
            {
                if let Some((id, tail)) = quoted(rest.trim()) {
                    if tail.trim() == ")" {
                        plugins.push(id.to_string());
                    }
                }
            }
            if stack.last() == Some(&Kind::Deps) {
                if let Some(rest) = line.strip_prefix("add(") {
                    if let Some((conf, tail)) = quoted(rest.trim()) {
                        let tail = tail.trim().strip_prefix(',').unwrap_or("").trim();
                        if let Some((coord, end)) = quoted(tail) {
                            let literal = !coord.contains('$') && coord.split(':').count() >= 3;
                            if end.trim() == ")" && literal && !conf.contains('$') {
                                deps.push(format!("    {conf}(\"{coord}\")"));
                            }
                        }
                    }
                }
            }
        }
        let code = code_only(line);
        let opens = code.matches('{').count();
        let closes = code.matches('}').count();
        for _ in 0..closes.saturating_sub(opens) {
            stack.pop();
        }
        if opens > closes {
            let word = |w: &str| {
                code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .any(|t| t == w)
            };
            let kind = if code.contains("fun apply(") || code.contains("void apply(") {
                Kind::Apply
            } else if [
                "if",
                "when",
                "for",
                "while",
                "else",
                "forEach",
                "let",
                "also",
                "run",
                "afterEvaluate",
                "withPlugin",
                "all",
                "configureEach",
                "matching",
                "whenPluginAdded",
                "withType",
                "catch",
                "try",
            ]
            .iter()
            .any(|w| word(w))
            {
                Kind::Cond
            } else if code
                .trim_end()
                .trim_end_matches('{')
                .trim_end()
                .ends_with("dependencies")
            {
                Kind::Deps
            } else {
                Kind::Plain
            };
            stack.push(kind);
            for _ in 1..opens - closes {
                stack.push(Kind::Plain);
            }
        }
    }
    if deps.is_empty() && plugins.is_empty() {
        return None;
    }
    let mut script = String::new();
    for id in plugins {
        script.push_str(&format!("apply plugin: '{id}'\n"));
    }
    script.push_str("dependencies {\n");
    for d in deps {
        script.push_str(&d);
        script.push('\n');
    }
    script.push_str("}\n");
    Some(script)
}

/// A project that applies one of the build's convention plugins (`id("cosid.library")`) takes
/// its declarations, and those of the conventions it applies in turn, as if written in the
/// project's own file, before the file's own. A convention no project applies stays build
/// logic: development only.
fn apply_conventions(conventions: &BTreeMap<String, usize>, modules: &mut [Module]) {
    if conventions.is_empty() {
        return;
    }
    let is_convention: BTreeSet<usize> = conventions.values().copied().collect();
    let mut used = BTreeSet::new();
    for i in 0..modules.len() {
        if is_convention.contains(&i) {
            continue;
        }
        // The conventions reached, depth first, each once.
        let mut order = Vec::new();
        let mut stack: Vec<String> = modules[i].applied.iter().rev().cloned().collect();
        while let Some(id) = stack.pop() {
            let Some(&c) = conventions.get(&id) else {
                continue;
            };
            if order.contains(&c) {
                continue;
            }
            order.push(c);
            stack.extend(modules[c].applied.iter().rev().cloned());
        }
        if order.is_empty() {
            continue;
        }
        let mut deps = Vec::new();
        let mut platforms = Vec::new();
        let mut constraints = Vec::new();
        let mut project_platforms = Vec::new();
        let mut project_deps = Vec::new();
        let mut forced = Vec::new();
        let mut forced_when = Vec::new();
        let mut toolchain = None;
        let mut rules = Vec::new();
        let mut dm = false;
        for &c in &order {
            used.insert(c);
            let from = &modules[c];
            deps.extend(from.deps.iter().cloned());
            platforms.extend(from.platforms.iter().cloned());
            constraints.extend(from.constraints.iter().cloned());
            project_platforms.extend(from.project_platforms.iter().cloned());
            project_deps.extend(from.project_deps.iter().cloned());
            forced.extend(from.forced.iter().cloned());
            forced_when.extend(from.forced_when.iter().cloned());
            toolchain = toolchain.or(from.toolchain);
            rules.extend(from.rules.iter().cloned());
            dm |= from.dm;
        }
        let module = &mut modules[i];
        let added = platforms.len();
        platforms.append(&mut module.platforms);
        module.platforms = platforms;
        module.shared_from = module.shared_from.map(|at| at + added);
        deps.append(&mut module.deps);
        module.deps = deps;
        constraints.append(&mut module.constraints);
        module.constraints = constraints;
        module.project_platforms.extend(project_platforms);
        module.project_deps.extend(project_deps);
        module.forced.extend(forced);
        module.forced_when.extend(forced_when);
        // A toolchain the file sets itself wins over its conventions'.
        module.toolchain = module.toolchain.or(toolchain);
        rules.append(&mut module.rules);
        module.rules = rules;
        module.dm |= dm;
    }
    for &c in conventions.values() {
        let module = &mut modules[c];
        if used.contains(&c) {
            // Resolved where it is applied, not on its own.
            module.deps.clear();
        } else {
            module.deps.iter_mut().for_each(|d| d.scope = "test");
        }
    }
}

/// The catalog's API as a convention plugin calls it, rewritten to what the reader reads:
/// `libs.findLibrary("a-b").get()` to `libs.a.b`, and `libs.findVersion("v").get()` (with
/// `.requiredVersion` or `.toString()`) to the version, inside a string or as one. A one-line
/// helper over either (CosId's `fun library(name: String) = libs.findLibrary(name).get()`) is
/// read the same way.
/// Multi-line list literals, `name = [` then one item a line and `]`, as in kafka's
/// `runtimeTestLibs = [ libs.slf4jLog4j2, ... ]`. A line `key: value` makes it a map, left out.
fn list_variables(text: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;
    for line in text.lines() {
        let l = line.trim();
        if let Some((_, items)) = current.as_mut() {
            if l.starts_with(']') {
                if let Some(done) = current.take().filter(|(_, items)| !items.is_empty()) {
                    out.push(done);
                }
                continue;
            }
            let item = l.trim_end_matches(',').trim();
            let map_key = item.split_once(':').is_some_and(|(k, _)| {
                !k.is_empty()
                    && k.trim()
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_')
            });
            if item.is_empty() || item.contains('[') || map_key {
                current = None;
                continue;
            }
            items.push(item.to_string());
            continue;
        }
        let mut l = l;
        for prefix in ["project.ext.", "ext.", "def "] {
            l = l.strip_prefix(prefix).unwrap_or(l).trim_start();
        }
        if let Some((name, open)) = l.split_once('=') {
            let name = name.trim();
            if open.trim() == "["
                && !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                current = Some((name.to_string(), Vec::new()));
            }
        }
    }
    out
}

/// `testImplementation testLog4j2Libs` or `testImplementation(testLog4j2Libs)` with a known
/// list: one declaration line per item.
/// A loop over a literal list, `['a', 'b'].each { v -> ... }` or `listOf("a", "b").forEach
/// { v -> ... }`, written out once per item with `v` as that item (armeria's netty native
/// transports, one per OS and CPU). `variantOf(libs.x) { classifier(...) }` is `libs.x`: the
/// classifier picks a file of the same module.
fn expand_loops(text: &str) -> String {
    let mut text = text.to_string();
    for _ in 0..4 {
        let (next, changed) = expand_loops_once(&text);
        text = next;
        if !changed {
            break;
        }
    }
    variants(&text)
}

fn expand_loops_once(text: &str) -> (String, bool) {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    let mut i = 0;
    while i < lines.len() {
        let Some((items, name)) = loop_head(lines[i].trim()) else {
            out.push_str(lines[i]);
            out.push('\n');
            i += 1;
            continue;
        };
        // The body runs to the brace that closes the loop's own.
        let mut depth = 1i32;
        let mut end = None;
        for (j, line) in lines.iter().enumerate().skip(i + 1) {
            for c in code_only(line).chars() {
                match c {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            if depth == 0 {
                end = Some(j);
                break;
            }
        }
        let Some(end) = end.filter(|&e| lines[e].trim() == "}") else {
            out.push_str(lines[i]);
            out.push('\n');
            i += 1;
            continue;
        };
        for item in &items {
            for line in &lines[i + 1..end] {
                out.push_str(&substitute(line, &name, item));
                out.push('\n');
            }
        }
        changed = true;
        i = end + 1;
    }
    (out, changed)
}

/// `['a', 'b'].each { v ->` or `listOf("a", "b").forEach { v ->`: the items and the name.
fn loop_head(line: &str) -> Option<(Vec<String>, String)> {
    let (list, rest) = if let Some(r) = line.strip_prefix('[') {
        r.split_once(']')?
    } else {
        let r = line.strip_prefix("listOf(")?;
        r.split_once(')')?
    };
    let rest = rest
        .strip_prefix(".each")
        .or_else(|| rest.strip_prefix(".forEach"))?
        .trim_start()
        .strip_prefix('{')?;
    let (name, tail) = rest.split_once("->")?;
    let name = name.trim();
    if !tail.trim().is_empty()
        || name.is_empty()
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    let items: Option<Vec<String>> = list
        .split(',')
        .map(|i| match quoted(i.trim()) {
            Some((v, "")) if !v.contains('$') => Some(v.to_string()),
            _ => None,
        })
        .collect();
    let items = items.filter(|i| !i.is_empty())?;
    Some((items, name.to_string()))
}

/// The loop variable `name` as `item`: `${name}` and `$name` in a string, a bare `name` as a
/// quoted string.
fn substitute(line: &str, name: &str, item: &str) -> String {
    let line = line.replace(&format!("${{{name}}}"), item);
    let mut out = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while i < line.len() {
        let at_word = line[i..].starts_with(name)
            && (i == 0 || !word(bytes[i - 1]))
            && bytes.get(i + name.len()).is_none_or(|c| !word(*c));
        if at_word {
            if i > 0 && bytes[i - 1] == b'$' {
                out.pop();
                out.push_str(item);
            } else {
                out.push('"');
                out.push_str(item);
                out.push('"');
            }
            i += name.len();
        } else {
            let c = line[i..].chars().next().unwrap_or(' ');
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

/// `variantOf(libs.x) { classifier("c") }` (and `variantOf(libs.x) { artifactType(...) }`) as
/// `libs.x`.
fn variants(text: &str) -> String {
    if !text.contains("variantOf(") {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("variantOf(") {
        out.push_str(&rest[..at]);
        let after = &rest[at + "variantOf(".len()..];
        let parsed = after.split_once(')').and_then(|(inner, tail)| {
            let inner = inner.trim();
            let tail = tail.trim_start();
            let block = tail.strip_prefix('{')?;
            let (body, tail) = block.split_once('}')?;
            let body = body.trim();
            let plain = inner.starts_with("libs.")
                && inner
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_');
            let known = body.starts_with("classifier(") || body.starts_with("artifactType(");
            (plain && known && !body.contains('\n')).then_some((inner, tail))
        });
        match parsed {
            Some((inner, tail)) => {
                out.push_str(inner);
                rest = tail;
            }
            None => {
                out.push_str("variantOf(");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn expand_lists(text: &str, lists: &BTreeMap<String, Vec<String>>) -> String {
    if lists.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let trimmed = line.trim();
        let indent = &line[..line.len() - line.trim_start().len()];
        let split = trimmed
            .split_once(' ')
            .map(|(c, n)| (c, n.trim()))
            .or_else(|| {
                let (c, rest) = trimmed.split_once('(')?;
                Some((c, rest.strip_suffix(')')?.trim()))
            });
        if let Some((config, name)) = split {
            let config = config.trim_matches(['"', '\'']);
            if let Some(items) = lists.get(name).filter(|_| is_configuration(config)) {
                for item in items {
                    out.push_str(&format!("{indent}{config} {item}\n"));
                }
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// `val v = findProperty("k")?.toString()` with k unset is null in a default build, so a
/// declaration `cfg(if (v == null) A else B)` declares A (and `v != null` declares B), as
/// CosId's `managedVersions(if (springBootVersion == null) platform(...) else ...)` does.
/// Any other shape is left as written, and reported where it is read.
fn null_branches(text: &str, vars: &BTreeMap<String, String>) -> String {
    let mut null: BTreeSet<&str> = BTreeSet::new();
    for line in text.lines() {
        let l = line.trim();
        let Some(rest) = l.strip_prefix("val ").or_else(|| l.strip_prefix("var ")) else {
            continue;
        };
        let Some((name, value)) = rest.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_suffix("?.toString()")
            .or_else(|| value.strip_suffix(" as String?"))
            .unwrap_or(value);
        let value = value.strip_prefix("project.").unwrap_or(value);
        let Some((key, tail)) = value.strip_prefix("findProperty(").and_then(quoted) else {
            continue;
        };
        if tail.trim() == ")" && !vars.contains_key(key) {
            null.insert(name.trim());
        }
    }
    if null.is_empty() || !text.contains("(if (") {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        out.push_str(&null_branch(line, &null).unwrap_or_else(|| line.to_string()));
        out.push('\n');
    }
    out
}

fn null_branch(line: &str, null: &BTreeSet<&str>) -> Option<String> {
    let (call, rest) = line.split_once("(if (")?;
    let (test, rest) = rest.split_once(") ")?;
    let (name, is_null) = if let Some(n) = test.strip_suffix(" == null") {
        (n.trim(), true)
    } else {
        (test.strip_suffix(" != null")?.trim(), false)
    };
    if !null.contains(name) {
        return None;
    }
    // `A else B)`: A runs to the ` else ` at paren depth 0.
    let mut depth = 0i32;
    let mut split = None;
    for (i, c) in rest.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ if depth == 0 && rest[i..].starts_with(" else ") => {
                split = Some(i);
                break;
            }
            _ => {}
        }
    }
    let at = split?;
    let (yes, no) = (&rest[..at], rest[at + " else ".len()..].strip_suffix(')')?);
    let taken = if is_null { yes } else { no };
    Some(format!("{call}({})", taken.trim()))
}

/// A platform project built from the whole catalog (pulsar's `pulsar-dependencies`):
/// `catalog.libraryAliases.filterNot { it...startsWith("p") }.forEach { alias -> ... }`, where
/// a module whose name looks like a BOM is `api(platform(provider))` and every other one
/// `constraints.api(provider)`. Written out as the declarations it makes, one per alias, or
/// `Err` with what is not read when any condition is beyond the plain ones read here.
fn catalog_platform(
    text: &str,
    catalog: &Catalog,
    vars: &BTreeMap<String, String>,
) -> Result<Option<String>, String> {
    let shape = [
        ".libraryAliases",
        "findLibrary(alias)",
        "api(platform(provider))",
        "constraints.api(provider)",
    ];
    if !shape.iter().all(|s| text.contains(s)) {
        return Ok(None);
    }
    let unread = |why: &str| Err(format!("the catalog-wide platform: {why}"));
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let Some(head) = lines.iter().find(|l| l.contains(".libraryAliases")) else {
        return Ok(None);
    };
    // The aliases left out: `filterNot { <accessor of it>.startsWith("tooling.") }`.
    let mut skipped: Vec<String> = Vec::new();
    if let Some((_, filter)) = head.split_once(".filterNot") {
        let normalized =
            filter.contains(".replace('-', '.')") && filter.contains(".replace('_', '.')");
        match filter
            .split_once(".startsWith(")
            .and_then(|(_, t)| quoted(t))
        {
            Some((prefix, tail)) if normalized && tail.trim_start().starts_with(')') => {
                skipped.push(prefix.to_string());
            }
            _ => return unread("its alias filter"),
        }
    }
    if head.contains(".filter {") || head.contains(".filter{") {
        return unread("its alias filter");
    }
    // A branch on a Gradle property that is set (pulsar's `protobufVersion`) is not read.
    for line in &lines {
        if let Some((_, inner)) = line.split_once("providers.gradleProperty(") {
            match quoted(inner) {
                Some((key, _)) if !vars.contains_key(key) => {}
                _ => return unread("a Gradle property it branches on is set"),
            }
        }
    }
    // The BOM test, `if (module.name.endsWith("-bom") || module.name == "bom" || ...) {`,
    // over as many lines as it takes.
    // The branch whose body is `api(platform(provider))`: its `if` is the nearest above.
    let body = lines
        .iter()
        .position(|l| l.contains("api(platform(provider))"))
        .unwrap_or(0);
    let Some(at) = lines[..body].iter().rposition(|l| l.contains("if (")) else {
        return unread("its BOM test");
    };
    let mut condition = String::new();
    for line in &lines[at..] {
        condition.push_str(line);
        condition.push(' ');
        if line.ends_with('{') {
            break;
        }
    }
    let mut rest = condition
        .split_once("if (")
        .map_or("", |(_, r)| r)
        .trim_end()
        .trim_end_matches('{')
        .trim_end()
        .strip_suffix(')')
        .unwrap_or("");
    let mut tests: Vec<(&str, String)> = Vec::new();
    while !rest.trim().is_empty() {
        let Some(after) = rest.trim_start().strip_prefix("module.name") else {
            return unread("its BOM test");
        };
        let (kind, arg) = if let Some(a) = after.strip_prefix(".endsWith(") {
            ("ends", a)
        } else if let Some(a) = after.strip_prefix(".contains(") {
            ("contains", a)
        } else if let Some(a) = after.trim_start().strip_prefix("==") {
            ("eq", a.trim_start())
        } else {
            return unread("its BOM test");
        };
        let Some((value, tail)) = quoted(arg) else {
            return unread("its BOM test");
        };
        let tail = if kind == "eq" {
            Some(tail)
        } else {
            tail.trim_start().strip_prefix(')')
        };
        let Some(tail) = tail.map(str::trim_start) else {
            return unread("its BOM test");
        };
        tests.push((kind, value.to_string()));
        rest = match tail.strip_prefix("||") {
            Some(more) => more,
            None if tail.is_empty() => "",
            None => return unread("its BOM test"),
        };
    }
    if tests.is_empty() {
        return unread("its BOM test");
    }
    let is_bom = |name: &str| {
        tests.iter().any(|(kind, v)| match *kind {
            "ends" => name.ends_with(v.as_str()),
            "contains" => name.contains(v.as_str()),
            _ => name == v,
        })
    };
    let (mut platforms, mut constraints) = (String::new(), String::new());
    for (alias, c) in &catalog.libraries {
        let name = accessor(alias);
        if skipped.iter().any(|p| name.starts_with(p.as_str())) {
            continue;
        }
        // Written as coordinates, not `libs.` accessors: an alias only this loop names is
        // still unused, and listed as unused ones are.
        let Some(version) = &c.version else {
            continue;
        };
        let coordinate = format!("\"{}:{}:{version}\"", c.group, c.artifact);
        if is_bom(&c.artifact) {
            platforms.push_str(&format!("    api(platform({coordinate}))\n"));
        } else {
            constraints.push_str(&format!("        api({coordinate})\n"));
        }
    }
    let out =
        format!("\ndependencies {{\n{platforms}    constraints {{\n{constraints}    }}\n}}\n");
    Ok(Some(out))
}

fn catalog_lookups(text: &str, catalog: &Catalog) -> String {
    if !text.contains(".findLibrary(") && !text.contains(".findVersion(") {
        return text.to_string();
    }
    // Helpers: name to whether it finds a library (else a version).
    let mut helpers: Vec<(String, bool)> = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("fun ") else {
            continue;
        };
        let Some((name, body)) = rest.split_once('(') else {
            continue;
        };
        let Some((_, value)) = body.split_once(" = ") else {
            continue;
        };
        let value = value.trim();
        let lookup = value
            .strip_prefix("libs.")
            .or_else(|| value.strip_prefix("versionCatalogs.named(\"libs\")."));
        if let Some(lookup) = lookup {
            if lookup.starts_with("findLibrary(") {
                helpers.push((name.trim().to_string(), true));
            } else if lookup.starts_with("findVersion(") {
                helpers.push((name.trim().to_string(), false));
            }
        }
    }
    let mut calls: Vec<(String, bool)> = vec![
        (
            "versionCatalogs.named(\"libs\").findLibrary".to_string(),
            true,
        ),
        (
            "versionCatalogs.named(\"libs\").findVersion".to_string(),
            false,
        ),
        ("libs.findLibrary".to_string(), true),
        ("libs.findVersion".to_string(), false),
    ];
    calls.extend(helpers);
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        if line.trim().starts_with("fun ") {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let mut line = line.to_string();
        for (call, library) in &calls {
            let open = format!("{call}(\"");
            let mut from = 0;
            while let Some(at) = line[from..].find(&open).map(|i| i + from) {
                // A helper's name must not be the tail of a longer name (`libs.findLibrary`).
                let before = line[..at].chars().next_back();
                if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                    && !call.contains('.')
                {
                    from = at + open.len();
                    continue;
                }
                let name_at = at + open.len();
                let Some(len) = line[name_at..].find("\")") else {
                    break;
                };
                let name = line[name_at..name_at + len].to_string();
                let mut end = name_at + len + 2;
                for tail in [".get()", ".requiredVersion", ".toString()"] {
                    if line[end..].starts_with(tail) {
                        end += tail.len();
                    }
                }
                let replacement = if *library {
                    catalog
                        .libraries
                        .contains_key(&name)
                        .then(|| format!("libs.{}", accessor(&name)))
                } else {
                    catalog.versions.get(&accessor(&name)).map(|v| {
                        // Inside `${...}` the version stands alone; elsewhere it is a string.
                        let wrapped = line[..at].ends_with("${") && line[end..].starts_with('}');
                        if wrapped {
                            v.clone()
                        } else {
                            format!("\"{v}\"")
                        }
                    })
                };
                let Some(replacement) = replacement else {
                    from = end;
                    continue;
                };
                let (start, stop) =
                    if !*library && line[..at].ends_with("${") && line[end..].starts_with('}') {
                        (at - 2, end + 1)
                    } else {
                        (at, end)
                    };
                line.replace_range(start..stop, &replacement);
                from = start + replacement.len();
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// `line` without its strings, so a brace in one does not count.
fn code_only(line: &str) -> String {
    let mut out = String::new();
    let mut quote = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) if c == '\\' => {
                chars.next();
                let _: char = q;
            }
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None => out.push(c),
        }
    }
    out
}

/// One statement of a `dependencies` or `constraints` block.
fn read_entry(line: &str, block: Block, context: &mut Context, module: &mut Module) {
    if line.is_empty() || line == "{" {
        return;
    }
    let unquoted = line.trim_start_matches(['"', '\'']);
    let name: String = unquoted
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name == "classpath" || name == "exclude" || name == "because" {
        return;
    }
    let rest = unquoted[name.len()..]
        .trim_start_matches(['"', '\''])
        .trim();
    // A custom configuration (`checkstyle`, `developmentOnly`) is off the runtime classpath.
    // `testImplementation lib.h2` or `api(lib['x'])`: a map entry or variable holding a
    // coordinate, read as that string.
    let bare = rest.trim_start_matches('(').trim_end_matches(')').trim();
    let resolved = (!bare.starts_with("libs.") && !bare.is_empty())
        .then(|| map_reference(bare).unwrap_or_else(|| bare.to_string()))
        .and_then(|key| context.vars.get(&key))
        .filter(|v| v.contains(':'))
        .map(|v| format!("\"{v}\""));
    let rest = resolved.as_deref().unwrap_or(rest);
    let declared = rest.trim_start_matches('(').trim_start();
    // A platform manages versions whichever configuration carries it (Spring Framework's
    // `dependencyManagement(enforcedPlatform(...))`).
    let a_platform = declared.starts_with("platform(") || declared.starts_with("enforcedPlatform(");
    let local = context.local_configurations.contains(&name);
    let scope = if local {
        "compile"
    } else if is_configuration(&name) {
        scope_of(&name)
    } else if let Some(target) = context.extended_by.get(&name) {
        scope_of(target)
    } else if a_platform
        || declared.starts_with(['"', '\''])
        || declared.starts_with("group:")
        || declared.starts_with("group =")
        || rest.contains("libs.")
    {
        "test"
    } else {
        module
            .unread
            .push(format!("`{line}` is not a plain declaration"));
        return;
    };
    let configuration = context
        .extended_by
        .get(&name)
        .map_or(name.as_str(), String::as_str);
    context.exported = exported_by(configuration);
    context.processor = is_processor(configuration);
    context.runtime_only = configuration.to_ascii_lowercase().contains("runtimeonly");
    context.custom = !local && !is_configuration(&name) && !context.extended_by.contains_key(&name);
    if local {
        context.exported = false;
        context.local = true;
    }
    let before = (module.platforms.len(), module.constraints.len());
    read_values(rest, scope, block, context, module);
    // Only a named test configuration keeps its platform to the tests: Spring Framework's
    // custom `dependencyManagement` reads as test, yet every configuration extends it.
    if scope == "test" && (is_configuration(&name) || context.extended_by.contains_key(&name)) {
        for c in module.platforms[before.0..]
            .iter_mut()
            .chain(&mut module.constraints[before.1..])
        {
            c.test = true;
        }
    }
    context.exported = true;
    context.processor = false;
    context.runtime_only = false;
    context.local = false;
    context.custom = false;
}

/// Whether a configuration's dependencies reach the compile classpath of a project that
/// depends on this one: `api`, the old `compile`, and the variants ending so
/// (`commonMainApi`). `implementation` and `runtimeOnly` do not.
fn exported_by(configuration: &str) -> bool {
    configuration == "api"
        || configuration == "compile"
        || configuration.ends_with("Api")
        || (configuration.ends_with("Compile") && !configuration.ends_with("TestCompile"))
}

/// Whether a configuration is an annotation processor's path: reposilite's
/// `kapt(platform(jackson-bom))` manages the processors' Jackson, not the backend's.
fn is_processor(configuration: &str) -> bool {
    let lower = configuration.to_ascii_lowercase();
    lower.starts_with("kapt") || lower.starts_with("ksp") || lower.contains("annotationprocessor")
}

/// `read_declaration`, with what an `enforcedPlatform(...)` adds marked strict.
/// The path of `project(":p")`, `project(path: ":p")` or `dependencies.project(path = ":p")`.
fn project_path(rest: &str) -> Option<&str> {
    let project = rest.strip_prefix("dependencies.").unwrap_or(rest);
    project
        .strip_prefix("project(")
        .or_else(|| project.strip_prefix("project "))
        .map(|p| {
            let p = p.trim_start();
            p.strip_prefix("path").map_or(p, |q| {
                q.trim_start().trim_start_matches([':', '=']).trim_start()
            })
        })
        .and_then(|p| quoted(p))
        .map(|(p, _)| p)
}

fn read_values(
    text: &str,
    scope: &'static str,
    block: Block,
    context: &mut Context,
    module: &mut Module,
) {
    let before = module.platforms.len();
    read_declaration(text, scope, block, context, module);
    if text
        .trim()
        .trim_start_matches('(')
        .trim_start()
        .starts_with("enforcedPlatform(")
    {
        for c in &mut module.platforms[before..] {
            c.strict = true;
        }
    }
}

fn read_declaration(
    text: &str,
    scope: &'static str,
    block: Block,
    context: &mut Context,
    module: &mut Module,
) {
    // `cond ? "g:a:1" : "g:a:2"`, when a default build decides `cond`.
    if let Some((cond, branches)) = text.trim().trim_start_matches('(').split_once(" ? ") {
        if let Some((yes, no)) = branches.split_once(" : ") {
            let no = no.trim().trim_end_matches(')').trim();
            if let Some(taken) = condition(cond, &context.vars) {
                let pick = if taken { yes.trim() } else { no };
                if quoted(pick).is_some_and(|(_, tail)| tail.trim().is_empty()) {
                    read_values(pick, scope, block, context, module);
                    return;
                }
            }
        }
    }
    let mut rest = text.trim().trim_start_matches('(').trim();
    let whole = text.trim();
    let exported = context.exported;
    let processor = context.processor;
    let runtime_only = context.runtime_only;
    let local = context.local;
    let custom = context.custom;
    let add = |module: &mut Module, c: Coordinate, platform: bool| {
        if platform && processor {
            // A processor's platform manages that path only; it lists nothing either.
        } else if platform {
            if c.version.is_some() && block == Block::Dependencies {
                module.deps.push(Declared {
                    coordinate: c.clone(),
                    scope,
                    exclusions: Vec::new(),
                    pom: true,
                    exported,
                    runtime_only,
                    local,
                    soft: false,
                });
            }
            module.platforms.push(c);
        } else if block == Block::Constraints {
            // A constraint without a version (a `because` only) manages nothing.
            if c.version.is_some() && !custom {
                module.constraints.push(c);
            }
        } else {
            module.deps.push(Declared {
                coordinate: c,
                scope,
                exclusions: Vec::new(),
                pom: false,
                exported,
                runtime_only,
                local,
                soft: false,
            });
        }
    };
    // ForgeGradle's `fg.deobf("g:a:v")` remaps the jar; the coordinate is the dependency.
    if let Some(inner) = rest.strip_prefix("fg.deobf(") {
        rest = inner.trim();
    }
    let mut platform = false;
    let mut strict = false;
    for prefix in ["enforcedPlatform(", "platform(", "testFixtures("] {
        if let Some(inner) = rest.strip_prefix(prefix) {
            platform = prefix != "testFixtures(";
            strict = prefix == "enforcedPlatform(";
            rest = inner.trim();
            break;
        }
    }
    // `platform(dependencyStrings.JACKSON_BOM)`: a map entry or variable holding the
    // coordinate (jib's `ext.dependencyStrings`).
    let named = rest.trim_end_matches(')').trim();
    let held = (platform && !named.starts_with(['"', '\'']) && !named.starts_with("libs."))
        .then(|| map_reference(named).unwrap_or_else(|| named.to_string()))
        .and_then(|key| context.vars.get(&key))
        .filter(|v| v.contains(':'))
        .map(|v| format!("\"{v}\")"));
    if let Some(held) = &held {
        rest = held;
    }
    if platform {
        if let Some(path) = project_path(rest) {
            module.project_platforms.push((path.to_string(), strict));
            return;
        }
        // The Spring Boot plugin's BOM, at the version the plugin is declared with (even one
        // declared `apply false`).
        // Imported or written out in full (isolating-the-domain).
        let bom = rest
            .strip_prefix("org.springframework.boot.gradle.plugin.")
            .unwrap_or(rest);
        if bom.starts_with("SpringBootPlugin.BOM_COORDINATES") {
            if let Some(version) = context.plugins.get(SPRING_BOOT) {
                let c = Coordinate {
                    group: "org.springframework.boot".to_string(),
                    artifact: "spring-boot-dependencies".to_string(),
                    version: Some(version.clone()),
                    enforced: false,
                    strict: false,
                    test: false,
                };
                if block == Block::Dependencies {
                    module.deps.push(Declared {
                        coordinate: c.clone(),
                        scope,
                        exclusions: Vec::new(),
                        pom: true,
                        exported,
                        runtime_only,
                        local,
                        soft: false,
                    });
                }
                module.platforms.push(c);
                return;
            }
        }
    }
    let local = [
        "project(",
        "project ",
        "files(",
        "files ",
        "fileTree(",
        "gradleApi(",
        "gradleTestKit(",
        "localGroovy(",
        "sourceSets",
        "dependencies.",
    ];
    if local.iter().any(|p| rest.starts_with(p)) {
        if block == Block::Dependencies {
            if let Some(path) = project_path(rest) {
                // A named configuration (`project(path: ':core', configuration: 'tests')`,
                // `project(':core').configurations.implementation.dependencies`) hands over all
                // it holds, not only what the project exports.
                let named = match configuration_named(rest) {
                    Some(c) if context.local_configurations.contains(c) => Named::Local,
                    Some(_) => Named::Whole,
                    None if rest.contains("configuration") => Named::Whole,
                    None => Named::Exported,
                };
                module.project_deps.push((
                    path.to_string(),
                    scope,
                    exported || named != Named::Exported,
                    Vec::new(),
                    named,
                ));
            }
        }
        return;
    }
    if rest.starts_with("group") {
        let field = |key: &str| {
            let at = rest.find(key)? + key.len();
            let tail = rest[at..]
                .trim_start()
                .strip_prefix([':', '='])?
                .trim_start();
            quoted(tail).map(|(value, _)| value)
        };
        if let (Some(g), Some(a)) = (field("group"), field("name")) {
            let literal = format!("{g}:{a}:{}", field("version").unwrap_or_default());
            match coordinate(&literal, &context.vars) {
                Ok(c) => add(module, c, platform),
                Err(e) => module.unread.push(e),
            }
            return;
        }
    }
    if let Some(path) = rest.strip_prefix("libs.") {
        let end = path
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
            .unwrap_or(path.len());
        let path = path[..end]
            .trim_end_matches(".get")
            .trim_end_matches(".asProvider");
        let aliases = context.aliases(path);
        if aliases.is_empty() {
            // No catalog entry: a Groovy map named `libs` (kafka's `libs += [ k: "g:a:v" ]`).
            if let Some(literal) = context.vars.get(&format!("libs.{path}")).cloned() {
                match coordinate(&literal, &context.vars) {
                    Ok(c) => add(module, c, platform),
                    Err(e) => module.unread.push(e),
                }
                return;
            }
            module
                .unread
                .push(format!("`libs.{path}` is not in the catalog"));
        }
        for alias in aliases {
            match context.catalog.libraries.get(&alias).cloned() {
                Some(c) => add(module, c, platform),
                None => module
                    .unread
                    .push(format!("`{alias}` is not in the catalog")),
            }
            context.used.insert(alias);
        }
        return;
    }
    if let Some(inner) = rest.strip_prefix("kotlin(") {
        let Some((short, tail)) = quoted(inner.trim()) else {
            module.unread.push(format!("`{whole}` is computed"));
            return;
        };
        let version = tail
            .trim_start()
            .strip_prefix(',')
            .and_then(|t| quoted(t.trim()))
            .map(|(v, _)| v)
            .or(context.plugins.get(KOTLIN_JVM).map(String::as_str));
        match version {
            Some(v) => add(
                module,
                Coordinate {
                    group: "org.jetbrains.kotlin".to_string(),
                    artifact: format!("kotlin-{short}"),
                    version: Some(v.to_string()),
                    enforced: false,
                    strict: false,
                    test: false,
                },
                platform,
            ),
            None => module.unread.push(format!(
                "`{whole}` takes its version from the Kotlin plugin"
            )),
        }
        return;
    }
    // One or more literals: `implementation 'g:a:1', 'g:b:2'`.
    let mut any = false;
    while let Some((value, tail)) = quoted(rest) {
        any = true;
        match coordinate(value, &context.vars) {
            Ok(c) => add(module, c, platform),
            Err(e) => module.unread.push(e),
        }
        match tail.trim_start().strip_prefix(',') {
            Some(next) => rest = next.trim_start(),
            None => break,
        }
    }
    if !any {
        module.unread.push(format!("`{whole}` is computed"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn context(toml: &str, vars: &[(&str, &str)]) -> Context {
        Context {
            vars: vars
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            catalog: Catalog::parse(toml).unwrap(),
            lombok: None,
            plugins: BTreeMap::new(),
            used: BTreeSet::new(),
            exported: true,
            extended_by: BTreeMap::new(),
            spring_dm: false,
            processor: false,
            runtime_only: false,
            local: false,
            local_configurations: BTreeSet::new(),
            custom: false,
            lists: BTreeMap::new(),
            dependency_set: None,
        }
    }

    fn rows(m: &Module) -> Vec<(String, &'static str)> {
        m.deps
            .iter()
            .map(|d| {
                let c = &d.coordinate;
                let v = c.version.as_deref().unwrap_or("-");
                (format!("{}:{}:{v}", c.group, c.artifact), d.scope)
            })
            .collect()
    }

    #[test]
    fn reads_groovy_and_kotlin_declarations() {
        let script = strip_comments(
            r#"
buildscript { dependencies { classpath 'g:plugin:1' } }
dependencies {
    implementation 'g:a:1.0'            // a comment
    api("g:b:2.0") { exclude group: 'x', module: 'y' }
    /* implementation 'g:gone:1' */
    testImplementation "g:c:$cVersion"
    runtimeOnly group: 'g', name: 'd', version: '4.0'
    compileOnly(group = "g", name = "e", version = "5.0")
    implementation project(':sibling')
    implementation(files("libs/x.jar"))
    implementation platform('g:bom:1.0')
    implementation 'g:managed'
    "implementation"("g:f:6.0")
    kapt 'g:h:7.0', 'g:i:8.0'
    implementation "g:j:${unknown}"
    implementation 'g:k:1.+'
    implementation someHelper('x')
    helper()
    checkstyle 'g:tool:1.0'
    constraints {
        implementation('g:pinned:9.0') { because 'CVE' }
    }
}
"#,
        );
        let mut c = context("", &[("cVersion", "3.0")]);
        let m = read_script(&script, &mut c);
        assert_eq!(
            rows(&m),
            [
                ("g:a:1.0".to_string(), "compile"),
                ("g:b:2.0".to_string(), "compile"),
                ("g:c:3.0".to_string(), "test"),
                ("g:d:4.0".to_string(), "runtime"),
                ("g:e:5.0".to_string(), "provided"),
                ("g:bom:1.0".to_string(), "compile"),
                ("g:managed:-".to_string(), "compile"),
                ("g:f:6.0".to_string(), "compile"),
                ("g:h:7.0".to_string(), "provided"),
                ("g:i:8.0".to_string(), "provided"),
                ("g:k:1.+".to_string(), "compile"),
                ("g:tool:1.0".to_string(), "test"),
            ]
        );
        assert_eq!(m.platforms.len(), 1);
        assert_eq!(m.constraints[0].artifact, "pinned");
        assert_eq!(m.unread.len(), 3, "{:?}", m.unread);
    }

    #[test]
    fn reads_every_catalog_form() {
        let toml = r#"
[versions]
x = "1.0"
rich = { strictly = "2.0" }
[libraries]
plain = "g:plain:0.1"
a-b = { module = "g:ab", version.ref = "x" }
c_d = { group = "g", name = "cd", version = { ref = "rich" } }
e = { module = "g:e", version = "3.0" }
nov = { module = "g:nov" }
[bundles]
set = ["a-b", "e"]
"#;
        let mut c = context(toml, &[]);
        let script = "dependencies {\n  implementation(libs.a.b)\n  testImplementation libs.c.d\n  api(libs.bundles.set)\n  implementation(platform(libs.plain))\n  implementation(libs.missing)\n}\n";
        let m = read_script(script, &mut c);
        assert_eq!(
            rows(&m),
            [
                ("g:ab:1.0".to_string(), "compile"),
                ("g:cd:2.0".to_string(), "test"),
                ("g:ab:1.0".to_string(), "compile"),
                ("g:e:3.0".to_string(), "compile"),
                ("g:plain:0.1".to_string(), "compile"),
            ]
        );
        assert_eq!(m.platforms[0].artifact, "plain");
        assert_eq!(m.unread, ["`libs.missing` is not in the catalog"]);
        assert!(!c.used.contains("nov"));
    }

    #[test]
    fn buildscript_classpath_versions_plugins_applied_by_name() {
        let mut vars = BTreeMap::new();
        vars.insert("bootVersion".to_string(), "4.0.0".to_string());
        assert_eq!(
            classpath_plugin(
                "classpath \"org.springframework.boot:spring-boot-gradle-plugin:$bootVersion\"",
                &vars
            ),
            Some((SPRING_BOOT, "4.0.0".to_string()))
        );
        assert_eq!(
            classpath_plugin(
                "classpath(\"org.jetbrains.kotlin:kotlin-gradle-plugin:2.1.0\")",
                &vars
            ),
            Some((KOTLIN_JVM, "2.1.0".to_string()))
        );
        assert_eq!(
            classpath_plugin("classpath 'org.gretty:gretty:4.1.10'", &vars),
            Some((GRETTY, "4.1.10".to_string()))
        );
        assert_eq!(
            classpath_plugin(
                "classpath 'com.diffplug.spotless:spotless-plugin-gradle:6.0.0'",
                &vars
            ),
            None
        );
        let catalog = Catalog::default();
        for (line, id) in [
            ("apply plugin: 'org.springframework.boot'", SPRING_BOOT),
            ("apply(plugin = \"org.springframework.boot\")", SPRING_BOOT),
            ("apply plugin: 'kotlin'", KOTLIN_JVM),
        ] {
            assert_eq!(
                plugin_line(line, &catalog, &BTreeMap::new()),
                Some((id.to_string(), None))
            );
        }
        let mut c = context("", &[]);
        c.plugins
            .insert(SPRING_BOOT.to_string(), "4.0.0".to_string());
        // Boot alone imports no BOM (armeria); the dependency-management plugin does.
        let m = read_script("apply plugin: 'org.springframework.boot'\n", &mut c);
        assert!(m.platforms.is_empty(), "{:?}", m.platforms);
        c.spring_dm = true;
        let m = read_script("apply plugin: 'org.springframework.boot'\n", &mut c);
        assert_eq!(m.platforms[0].artifact, "spring-boot-dependencies");
        assert_eq!(m.platforms[0].version.as_deref(), Some("4.0.0"));
    }

    #[test]
    fn plugins_bring_their_boms_and_libraries() {
        let toml = "[plugins]\nboot = { id = \"org.springframework.boot\", version = \"3.2.0\" }\n";
        let catalog = Catalog::parse(toml).unwrap();
        assert_eq!(
            plugin_line("alias(libs.plugins.boot)", &catalog, &BTreeMap::new()),
            Some(("org.springframework.boot".to_string(), None))
        );
        let catalog = Catalog::parse(&format!("{toml}[versions]\nmy-x = \"1.0\"\n")).unwrap();
        for line in [
            "id 'g.x' version '1.0'",
            "id(\"g.x\") version \"1.0\"",
            "id(\"g.x\") version libs.versions.my.x.get()",
            "id(\"g.x\") version(libs.versions.my.x.get())",
        ] {
            assert_eq!(
                plugin_line(line, &catalog, &BTreeMap::new()),
                Some(("g.x".to_string(), Some("1.0".to_string())))
            );
        }
        assert_eq!(
            plugin_line(
                "kotlin(\"jvm\") version \"2.0.0\"",
                &catalog,
                &BTreeMap::new()
            )
            .unwrap()
            .0,
            KOTLIN_JVM
        );
        // komga: `val kotlinVersion = "2.4.10"` then `kotlin("jvm") version kotlinVersion`.
        let vars = BTreeMap::from([("kotlinVersion".to_string(), "2.4.10".to_string())]);
        assert_eq!(
            plugin_line("kotlin(\"jvm\") version kotlinVersion", &catalog, &vars),
            Some((KOTLIN_JVM.to_string(), Some("2.4.10".to_string())))
        );

        let mut c = context(toml, &[]);
        c.spring_dm = true;
        c.plugins = c.catalog.plugins.clone();
        c.plugins
            .insert(KOTLIN_JVM.to_string(), "2.0.0".to_string());
        let m = read_script(
            "plugins {\n  alias(libs.plugins.boot)\n  kotlin(\"jvm\")\n}\ndependencies {\n  testImplementation(kotlin(\"test\"))\n}\n",
            &mut c,
        );
        assert_eq!(m.platforms[0].version.as_deref(), Some("3.2.0"));
        assert_eq!(
            rows(&m),
            [
                (
                    "org.jetbrains.kotlin:kotlin-stdlib:2.0.0".to_string(),
                    "compile"
                ),
                ("org.jetbrains.kotlin:kotlin-test:2.0.0".to_string(), "test"),
            ]
        );
    }

    #[test]
    fn variables_with_two_values_are_not_guessed() {
        let mut vars = BTreeMap::new();
        let mut twice = BTreeSet::new();
        script_variables(
            "val a = \"1\"\next.b = '2'\ndef c = '3'\nc = '4'\nd = compute()\n",
            &mut vars,
            &mut twice,
            &mut Vec::new(),
        );
        assert_eq!(vars["a"], "1");
        assert_eq!(vars["b"], "2");
        assert!(twice.contains("c"));
        assert!(!vars.contains_key("d"));
    }

    #[test]
    fn groovy_list_entries_are_variables() {
        let mut vars = BTreeMap::new();
        script_variables(
            "libraries = [\n    springVersion = '5.3.39',\n    pair = '1', '2'\n]\n",
            &mut vars,
            &mut BTreeSet::new(),
            &mut Vec::new(),
        );
        assert_eq!(vars["springVersion"], "5.3.39");
        assert!(!vars.contains_key("pair"));
    }

    #[test]
    fn gradle_ranges_become_maven_ranges() {
        assert_eq!(version_text("[1.0,2.0[").unwrap(), "[1.0,2.0)");
        assert_eq!(version_text("]1.0,2.0]").unwrap(), "(1.0,2.0]");
        assert_eq!(version_text("1.+").unwrap(), "1.+");
        assert!(version_text("latest.release").is_err());
    }

    /// POMs in memory, keyed `g:a:v`.
    struct Mem(BTreeMap<String, String>);

    impl PomSource for Mem {
        fn pom(&self, g: &str, a: &str, v: &str) -> Option<String> {
            self.0.get(&format!("{g}:{a}:{v}")).cloned()
        }
        fn metadata(&self, _: &str, _: &str) -> Option<String> {
            None
        }
        fn module(&self, g: &str, a: &str, v: &str) -> Option<String> {
            self.0.get(&format!("{g}:{a}:{v}.module")).cloned()
        }
    }

    fn pom(a: &str, v: &str, deps: &[(&str, &str)]) -> (String, String) {
        let deps: String = deps
            .iter()
            .map(|(a, v)| {
                format!("<dependency><groupId>g</groupId><artifactId>{a}</artifactId><version>{v}</version></dependency>")
            })
            .collect();
        (
            format!("g:{a}:{v}"),
            format!("<project><groupId>g</groupId><artifactId>{a}</artifactId><version>{v}</version><dependencies>{deps}</dependencies></project>"),
        )
    }

    fn tree(tag: &str, files: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fr-gradle-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (file, text) in files {
            let path = dir.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        dir
    }

    fn versions(r: &Resolution, name: &str) -> Vec<String> {
        r.packages
            .iter()
            .filter(|p| p.name == name)
            .map(|p| p.version.clone())
            .collect()
    }

    #[test]
    fn exclusions_in_a_declaration_block_prune_its_tree() {
        assert_eq!(
            exclusion("exclude group: 'g', module: 'x'"),
            Some(("g".to_string(), "x".to_string()))
        );
        assert_eq!(
            exclusion("exclude(module = \"x\")"),
            Some(("*".to_string(), "x".to_string()))
        );
        assert_eq!(exclusion("excludeRules()"), None);
        for line in [
            "isTransitive = false",
            "transitive = false",
            "transitive false",
        ] {
            assert_eq!(exclusion(line), Some(("*".to_string(), "*".to_string())));
        }
        assert_eq!(exclusion("isTransitive = true"), None);
        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[("x", "1"), ("y", "1")]),
            pom("b", "1", &[("x", "1"), ("y", "1")]),
            pom("x", "1", &[]),
            pom("y", "1", &[]),
        ]));
        let dir = tree(
            "exclusions",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "dependencies {\n    api(\"g:a:1\") {\n        exclude(group = \"g\", module = \"x\")\n    }\n}\n",
                ),
                (
                    "sub/build.gradle",
                    "dependencies {\n    implementation('g:b:1') { exclude group: 'g', module: 'y' }\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let mut names: Vec<_> = r.packages.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        // `x` comes only through `b` and `y` only through `a`.
        assert_eq!(names, ["g:a", "g:b", "g:x", "g:y"], "{:?}", r.missing);
        let dir = tree(
            "exclusions-one",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "dependencies {\n    api(\"g:a:1\") {\n        exclude(group = \"g\", module = \"x\")\n    }\n    api 'g:y:1'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(versions(&r, "g:x").is_empty(), "{:?}", r.packages);
        // Declared again without the block, `a` keeps its dependencies.
        let dir = tree(
            "exclusions-twice",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "dependencies {\n    testImplementation 'g:a:1'\n    agent('g:a:1') { transitive = false }\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:x"), ["1"], "{:?}", r.packages);
    }

    #[test]
    fn gradle_keeps_a_relocation_pom_and_adds_its_target() {
        let repo = Mem(BTreeMap::from([
            (
                "old:a:1".to_string(),
                "<project><groupId>old</groupId><artifactId>a</artifactId><version>1</version>\
                 <distributionManagement><relocation><groupId>g</groupId></relocation>\
                 </distributionManagement></project>"
                    .to_string(),
            ),
            pom("a", "1", &[]),
            pom("a", "2", &[]),
            pom("b", "1", &[("a", "2")]),
        ]));
        let dir = tree(
            "relocation",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "dependencies {\n    implementation 'old:a:1'\n    implementation 'g:b:1'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "old:a"), ["1"], "{:?}", r.missing);
        // The target competes with other requests: the highest wins.
        assert_eq!(versions(&r, "g:a"), ["2"], "{:?}", r.missing);
    }

    #[test]
    fn a_test_dependency_does_not_raise_the_main_classpath() {
        // Gradle resolves `compileClasspath` without test dependencies: `x` stays 1 there,
        // and 2 is on the test classpath only.
        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[("x", "1")]),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
        ]));
        let dir = tree(
            "main-vs-test",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "dependencies {\n    implementation 'g:a:1'\n    testImplementation 'g:x:2'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let x: Vec<_> = r
            .packages
            .iter()
            .filter(|p| p.name == "g:x")
            .map(|p| (p.version.as_str(), p.dev))
            .collect();
        assert_eq!(x, [("1", false), ("2", true)], "{:?}", r.missing);
    }

    #[test]
    fn the_highest_version_wins_where_maven_would_take_the_nearest() {
        // Maven keeps `c` at 1.0, nearest. Gradle takes 2.0, which then brings `d`.
        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[("b", "1")]),
            pom("b", "1", &[("c", "2.0")]),
            pom("c", "1.0", &[]),
            pom("c", "2.0", &[("d", "1")]),
            pom("d", "1", &[]),
        ]));
        let dir = tree(
            "highest",
            &[(
                "build.gradle",
                "dependencies {\n  implementation 'g:c:1.0'\n  implementation 'g:a:1'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:c"), ["2.0"]);
        assert_eq!(versions(&r, "g:d"), ["1"]);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
    }

    #[test]
    fn module_metadata_redirects_and_constrains() {
        let marker = "<!-- do_not_remove: published-with-gradle-metadata -->";
        let gradle_pom = |a: &str, v: &str| {
            (
                format!("g:{a}:{v}"),
                format!("<project>{marker}<groupId>g</groupId><artifactId>{a}</artifactId><version>{v}</version></project>"),
            )
        };
        let module = |a: &str, v: &str, body: &str| {
            (
                format!("g:{a}:{v}.module"),
                format!(r#"{{"formatVersion":"1.1","variants":[{body}]}}"#),
            )
        };
        let runtime = r#""attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"library","org.jetbrains.kotlin.platform.type":"jvm"}"#;
        let repo = Mem(BTreeMap::from([
            gradle_pom("kmp", "1.0"),
            module(
                "kmp",
                "1.0",
                &format!(
                    r#"{{"name":"jvmRuntimeElements",{runtime},"available-at":{{"group":"g","module":"kmp-jvm","version":"1.0"}}}}"#
                ),
            ),
            gradle_pom("kmp-jvm", "1.0"),
            module(
                "kmp-jvm",
                "1.0",
                &format!(
                    r#"{{"name":"jvmRuntimeElements",{runtime},"dependencies":[
                {{"group":"g","module":"dep","version":{{"requires":"1.0"}}}},
                {{"group":"g","module":"bom","version":{{"requires":"1.0"}},"attributes":{{"org.gradle.category":"platform"}}}}]}}"#
                ),
            ),
            gradle_pom("bom", "1.0"),
            module(
                "bom",
                "1.0",
                r#"{"name":"platformRuntimeElements","attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"platform"},
                "dependencyConstraints":[{"group":"g","module":"dep","version":{"requires":"2.0"}}]}"#,
            ),
            pom("dep", "1.0", &[]),
            pom("dep", "2.0", &[]),
            // A BOM with only module metadata, imported by the build: its constraints manage.
            gradle_pom("bom2", "1.0"),
            module(
                "bom2",
                "1.0",
                r#"{"name":"platformRuntimeElements","attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"platform"},
                "dependencyConstraints":[{"group":"g","module":"unversioned","version":{"requires":"3.0"}}]}"#,
            ),
            pom("unversioned", "3.0", &[]),
            // Published with metadata, but the file is not there: the POM is read.
            gradle_pom("nomod", "1.0"),
        ]));
        let dir = tree(
            "module-metadata",
            &[(
                "build.gradle",
                "dependencies {\n  implementation 'g:kmp:1.0'\n  implementation 'g:nomod:1.0'\n  implementation platform('g:bom2:1.0')\n  implementation 'g:unversioned'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:kmp-jvm"), ["1.0"]);
        assert_eq!(versions(&r, "g:bom"), ["1.0"]);
        assert_eq!(versions(&r, "g:dep"), ["2.0"]);
        assert_eq!(versions(&r, "g:nomod"), ["1.0"]);
        assert_eq!(versions(&r, "g:unversioned"), ["3.0"]);
        assert_eq!(
            r.missing,
            ["g:nomod:1.0: Gradle module metadata not available, read the POM instead"]
        );
    }

    #[test]
    fn a_runtime_variant_constraint_stays_off_the_compile_classpath() {
        // wiremock-jre8's runtimeElements pins json-smart 2.4.8 by a dependency constraint its
        // apiElements does not have: the compile classpath keeps json-path's 2.4.7.
        let marker = "<!-- do_not_remove: published-with-gradle-metadata -->";
        let dep = r#"{"group":"g","module":"path","version":{"requires":"1"}}"#;
        let json = format!(
            r#"{{"formatVersion":"1.1","variants":[
            {{"name":"apiElements","attributes":{{"org.gradle.usage":"java-api","org.gradle.category":"library"}},
              "dependencies":[{dep}]}},
            {{"name":"runtimeElements","attributes":{{"org.gradle.usage":"java-runtime","org.gradle.category":"library"}},
              "dependencies":[{dep}],
              "dependencyConstraints":[{{"group":"g","module":"smart","version":{{"requires":"2"}}}}]}}]}}"#
        );
        let repo = Mem(BTreeMap::from([
            (
                "g:wm:1".to_string(),
                format!("<project>{marker}<groupId>g</groupId><artifactId>wm</artifactId><version>1</version></project>"),
            ),
            ("g:wm:1.module".to_string(), json),
            pom("path", "1", &[("smart", "1")]),
            pom("smart", "1", &[]),
            pom("smart", "2", &[]),
        ]));
        let dir = tree(
            "runtime-constraint",
            &[(
                "build.gradle",
                "dependencies {\n  testImplementation 'g:wm:1'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:smart"), ["1", "2"]);
        assert_eq!(versions(&r, "g:path"), ["1"]);
    }

    #[test]
    fn a_non_transitive_dependency_brings_no_constraints() {
        // PlotSquared: `compileOnly(libs.faweBukkit) { isTransitive = false }`, whose `.module`
        // constrains Gson to 2.11.0: Gradle keeps the build's own 2.10.
        let marker = "<!-- do_not_remove: published-with-gradle-metadata -->";
        let json = r#"{"formatVersion":"1.1","variants":[
            {"name":"apiElements","attributes":{"org.gradle.usage":"java-api","org.gradle.category":"library"},
              "dependencyConstraints":[{"group":"g","module":"gson","version":{"requires":"2"}}]}]}"#;
        let repo = Mem(BTreeMap::from([
            (
                "g:fawe:1".to_string(),
                format!("<project>{marker}<groupId>g</groupId><artifactId>fawe</artifactId><version>1</version></project>"),
            ),
            ("g:fawe:1.module".to_string(), json.to_string()),
            pom("gson", "1", &[]),
            pom("gson", "2", &[]),
        ]));
        let dir = tree(
            "non-transitive-constraints",
            &[(
                "build.gradle.kts",
                "dependencies {\n    compileOnly(\"g:gson:1\")\n\
                 \x20   compileOnly(\"g:fawe:1\") { isTransitive = false }\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:gson"), ["1"], "{:?}", r.missing);
    }

    #[test]
    fn a_type_safe_project_accessor_names_its_project() {
        // PlotSquared: `api(projects.plotsquaredCore)`, the project the settings rename
        // `plotsquared-core`.
        let repo = Mem(BTreeMap::from([pom("b", "1", &[]), pom("b", "2", &[])]));
        let dir = tree(
            "project-accessors",
            &[
                (
                    "settings.gradle.kts",
                    "include(\"Core\", \"Bukkit\")\nproject(\":Core\").name = \"plotsquared-core\"\n",
                ),
                ("Core/build.gradle.kts", "dependencies {\n    api(\"g:b:2\")\n}\n"),
                (
                    "Bukkit/build.gradle.kts",
                    "dependencies {\n    api(projects.plotsquaredCore)\n    implementation(\"g:b:1\")\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        // Core's 2 wins on Bukkit's classpaths too.
        assert_eq!(versions(&r, "g:b"), ["2"], "{:?}", r.missing);
        assert_eq!(project_accessor("plotsquared-core"), "plotsquaredCore");
        assert_eq!(project_accessor("Core"), "core");
        assert_eq!(project_accessor("a_b.c"), "aBC");
        let mut scripts = vec![(
            "Bukkit/build.gradle.kts".to_string(),
            "api(projects.plotsquaredCore)\nsubprojects.forEach { }\nprojects.unknown\n"
                .to_string(),
        )];
        project_accessors(&dir, &mut scripts);
        assert_eq!(
            scripts[0].1,
            "api(project(\":plotsquared-core\"))\nsubprojects.forEach { }\nprojects.unknown\n"
        );
    }

    #[test]
    fn an_applied_script_declares_in_the_project_that_applies_it() {
        // xpipe: `apply from: "$rootDir/gradle/gradle_scripts/javafx.gradle"` declares JavaFX in
        // a `javafx` configuration, with a classifier computed from the host OS. The app puts
        // it in `implementation`, an extension in `compileOnly`; JavaFX 27 then wins on the
        // app's classpaths over the 22 a library asks for.
        let repo = Mem(BTreeMap::from([
            pom("fx", "22", &[]),
            pom("fx", "27", &[]),
            pom("lib", "1", &[("fx", "22")]),
        ]));
        let dir = tree(
            "applied-script",
            &[
                ("settings.gradle", "include 'app', 'ext'\n"),
                ("build.gradle", "ext {\n    fxVersion = '27'\n}\n"),
                (
                    "gradle/scripts/fx.gradle",
                    "def platform = null\nif (os) {\n    platform = 'win'\n} else {\n    platform = 'linux'\n}\n\
                     configurations {\n    javafx\n}\n\
                     dependencies {\n    javafx \"g:fx:${fxVersion}:${platform}\"\n}\n",
                ),
                (
                    "app/build.gradle",
                    "apply from: \"$rootDir/gradle/scripts/fx.gradle\"\n\
                     configurations {\n    implementation.extendsFrom(javafx)\n}\n\
                     dependencies {\n    implementation 'g:lib:1'\n}\n",
                ),
                (
                    "ext/build.gradle",
                    "apply from: \"${rootDir}/gradle/scripts/fx.gradle\"\n\
                     configurations {\n    compileOnly.extendsFrom(javafx)\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        let of = |name: &str| -> Vec<(String, bool)> {
            r.packages
                .iter()
                .filter(|p| p.name == name)
                .map(|p| (p.version.clone(), p.dev))
                .collect()
        };
        assert_eq!(of("g:fx"), [("27".to_string(), false)], "{:?}", r.packages);
        assert_eq!(
            applied_path("apply from: rootProject.file('a/b.gradle')", "x"),
            Some("a/b.gradle".to_string())
        );
        assert_eq!(
            applied_path("apply(from = \"../common.gradle.kts\")", "x/y"),
            Some("x/common.gradle.kts".to_string())
        );
        assert_eq!(applied_path("apply from: \"https://h/x.gradle\"", ""), None);
    }

    #[test]
    fn a_settings_build_file_name_names_projects_after_their_files() {
        // spring-security: the settings make every `x.gradle` project `:x`, its directory the
        // file's (`project.buildFileName = buildFile.name`).
        let repo = Mem(BTreeMap::from([pom("b", "1", &[]), pom("b", "2", &[])]));
        let dir = tree(
            "build-file-name",
            &[
                (
                    "settings.gradle",
                    "buildFiles.each { File buildFile ->\n    configureProject(buildFile)\n}\n\
                     def configureProject(File buildFile) {\n    project.buildFileName = buildFile.name\n}\n",
                ),
                ("core/spring-security-core.gradle", "dependencies {\n    api 'g:b:2'\n}\n"),
                (
                    "web/spring-security-web.gradle",
                    "dependencies {\n    api project(':spring-security-core')\n    implementation 'g:b:1'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:b"), ["2"], "{:?}", r.packages);
    }

    #[test]
    fn a_platform_lists_and_applies_the_platforms_it_depends_on() {
        // kestra: an `enforcedPlatform(project(":platform"))` whose platform project imports
        // micronaut-platform, a `.module` platform that depends on 73 nested BOMs, and pins
        // jetty-bom with `enforcedPlatform`. Gradle lists each nested BOM, applies what they
        // manage, and still holds jetty at the enforced BOM's version, the BOM itself too.
        let marker = "<!-- do_not_remove: published-with-gradle-metadata -->";
        let gradle_pom = |a: &str, v: &str| {
            (
                format!("g:{a}:{v}"),
                format!("<project>{marker}<groupId>g</groupId><artifactId>{a}</artifactId><version>{v}</version><packaging>pom</packaging></project>"),
            )
        };
        let module = |a: &str, body: &str| {
            (
                format!("g:{a}:1.module"),
                format!(
                    r#"{{"formatVersion":"1.1","variants":[{{"name":"apiElements","attributes":{{"org.gradle.usage":"java-api","org.gradle.category":"platform"}},{body}}},{{"name":"runtimeElements","attributes":{{"org.gradle.usage":"java-runtime","org.gradle.category":"platform"}},{body}}}]}}"#
                ),
            )
        };
        let bom = |v: &str, managed: &str| {
            (
                format!("g:pin:{v}"),
                format!(
                    "<project><groupId>g</groupId><artifactId>pin</artifactId><version>{v}</version>\
                     <packaging>pom</packaging><dependencyManagement><dependencies><dependency>\
                     <groupId>g</groupId><artifactId>x</artifactId><version>{managed}</version>\
                     </dependency></dependencies></dependencyManagement></project>"
                ),
            )
        };
        let repo = Mem(BTreeMap::from([
            gradle_pom("outer", "1"),
            module(
                "outer",
                r#""dependencyConstraints":[{"group":"g","module":"a","version":{"requires":"2"}}],
                "dependencies":[{"group":"g","module":"inner","version":{"requires":"1"},"attributes":{"org.gradle.category":"platform"}}]"#,
            ),
            gradle_pom("inner", "1"),
            module(
                "inner",
                r#""dependencyConstraints":[{"group":"g","module":"b","version":{"requires":"2"}},{"group":"g","module":"x","version":{"requires":"2"}}],
                "dependencies":[{"group":"g","module":"pin","version":{"requires":"2"},"attributes":{"org.gradle.category":"platform"}}]"#,
            ),
            bom("1", "1"),
            bom("2", "2"),
            pom("a", "2", &[]),
            pom("b", "2", &[]),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
        ]));
        let dir = tree(
            "nested-platforms",
            &[
                ("settings.gradle", "include 'platform', 'app'\n"),
                (
                    "platform/build.gradle",
                    "plugins {\n    id 'java-platform'\n}\njavaPlatform {\n    allowDependencies()\n}\n\
                     dependencies {\n    api enforcedPlatform(\"g:pin:1\")\n    api platform(\"g:outer:1\")\n}\n",
                ),
                (
                    "app/build.gradle",
                    "plugins {\n    id 'java'\n}\ndependencies {\n    implementation enforcedPlatform(project(\":platform\"))\n\
                     \x20   implementation \"g:a\"\n    implementation \"g:b\"\n    implementation \"g:x\"\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:inner"), ["1"], "{:?}", r.packages);
        assert_eq!(versions(&r, "g:a"), ["2"]);
        assert_eq!(versions(&r, "g:b"), ["2"]);
        assert_eq!(versions(&r, "g:x"), ["1"]);
        assert_eq!(versions(&r, "g:pin"), ["1"]);
    }

    #[test]
    fn a_libraries_lower_bom_takes_the_platforms_nested_one() {
        // kestra: micronaut-validation's `.module` names micronaut-core-bom 5.2.3, which the
        // micronaut-platform the build's platform imports nests at 5.2.22. Gradle has one
        // micronaut-core-bom node, at 5.2.22; it is never listed at both.
        let marker = "<!-- do_not_remove: published-with-gradle-metadata -->";
        let gradle_pom = |a: &str, v: &str| {
            (
                format!("g:{a}:{v}"),
                format!("<project>{marker}<groupId>g</groupId><artifactId>{a}</artifactId><version>{v}</version></project>"),
            )
        };
        let module = |a: &str, v: &str, category: &str, body: &str| {
            (
                format!("g:{a}:{v}.module"),
                format!(
                    r#"{{"formatVersion":"1.1","variants":[{{"name":"apiElements","attributes":{{"org.gradle.usage":"java-api","org.gradle.category":"{category}"}},{body}}},{{"name":"runtimeElements","attributes":{{"org.gradle.usage":"java-runtime","org.gradle.category":"{category}"}},{body}}}]}}"#
                ),
            )
        };
        let inner = |v: &str| {
            r#""dependencies":[{"group":"g","module":"inner","version":{"requires":"V"},"attributes":{"org.gradle.category":"platform"}}]"#.replace('V', v)
        };
        let repo = Mem(BTreeMap::from([
            gradle_pom("outer", "1"),
            module("outer", "1", "platform", &inner("2")),
            gradle_pom("inner", "1"),
            module("inner", "1", "platform", r#""dependencies":[]"#),
            gradle_pom("inner", "2"),
            module("inner", "2", "platform", r#""dependencies":[]"#),
            gradle_pom("lib", "1"),
            module("lib", "1", "library", &inner("1")),
        ]));
        let dir = tree(
            "library-lower-bom",
            &[
                ("settings.gradle", "include 'platform', 'app'\n"),
                (
                    "platform/build.gradle",
                    "plugins {\n    id 'java-platform'\n}\njavaPlatform {\n    allowDependencies()\n}\n\
                     dependencies {\n    api platform(\"g:outer:1\")\n}\n",
                ),
                (
                    "app/build.gradle",
                    "plugins {\n    id 'java'\n}\ndependencies {\n    implementation enforcedPlatform(project(\":platform\"))\n\
                     \x20   implementation \"g:lib:1\"\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:inner"), ["2"], "{:?}", r.packages);
        assert_eq!(versions(&r, "g:lib"), ["1"]);
    }

    #[test]
    fn the_spring_bom_manages_the_kotlin_plugins_standard_library() {
        // mmorpg: under the dependency-management plugin, Boot 3.0.4's BOM manages the
        // standard library the Kotlin plugin adds (the root: 1.7.22, not the plugin's 2.2.0);
        // in a project that also applies Boot, Boot sets `kotlin.version` to the plugin's.
        let kotlin = |v: &str| {
            (
                format!("org.jetbrains.kotlin:kotlin-stdlib:{v}"),
                format!("<project><groupId>org.jetbrains.kotlin</groupId><artifactId>kotlin-stdlib</artifactId><version>{v}</version></project>"),
            )
        };
        let repo = Mem(BTreeMap::from([
            kotlin("1.7.22"),
            kotlin("2.0.0"),
            (
                "org.springframework.boot:spring-boot-dependencies:3.0.4".to_string(),
                "<project><groupId>org.springframework.boot</groupId><artifactId>spring-boot-dependencies</artifactId>\
                 <version>3.0.4</version><packaging>pom</packaging><properties><kotlin.version>1.7.22</kotlin.version></properties>\
                 <dependencyManagement><dependencies><dependency><groupId>org.jetbrains.kotlin</groupId>\
                 <artifactId>kotlin-stdlib</artifactId><version>${kotlin.version}</version></dependency>\
                 </dependencies></dependencyManagement></project>"
                    .to_string(),
            ),
        ]));
        let root = "buildscript {\n    dependencies {\n\
             \x20       classpath(\"org.springframework.boot:spring-boot-gradle-plugin:3.0.4\")\n\
             \x20       classpath 'io.spring.gradle:dependency-management-plugin:1.1.4'\n\
             \x20       classpath \"org.jetbrains.kotlin:kotlin-gradle-plugin:2.0.0\"\n    }\n}\n\
             apply plugin: 'kotlin'\napply plugin: 'io.spring.dependency-management'\n\
             dependencyManagement {\n    imports {\n\
             \x20       mavenBom \"org.springframework.boot:spring-boot-dependencies:3.0.4\"\n    }\n}\n";
        let app = "apply plugin: 'org.springframework.boot'\napply plugin: 'kotlin'\n\
                   apply plugin: 'io.spring.dependency-management'\n";
        let dir = tree(
            "kotlin-under-spring",
            &[
                ("settings.gradle", "include 'app'\n"),
                ("build.gradle", root),
                ("app/build.gradle", app),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(
            versions(&r, "org.jetbrains.kotlin:kotlin-stdlib"),
            ["1.7.22", "2.0.0"],
            "{:?}",
            r.packages
        );
    }

    #[test]
    fn a_map_entry_set_in_a_decided_branch_is_read() {
        // kafka: `versions["scala"]` takes `scalaVersion` from gradle.properties (not the
        // default, the property is set and is not "2.13"), and `versions["baseScala"]` is its
        // `substring(0, lastIndexOf("."))` in the branch `!versions.scala.contains('-')` takes.
        let repo = Mem(BTreeMap::from([pom("lib_2.12", "2.12.20", &[])]));
        let script = "ext {\n  versions = [:]\n  libs = [:]\n}\n\
             def defaultScala213Version = '2.13.18'\n\
             if (hasProperty('scalaVersion')) {\n  if (scalaVersion == '2.13') {\n\
             \x20   versions[\"scala\"] = defaultScala213Version\n  }  else {\n\
             \x20   versions[\"scala\"] = scalaVersion\n  }\n} else {\n\
             \x20 versions[\"scala\"] = defaultScala213Version\n}\n\
             if ( !versions.scala.contains('-') ) {\n\
             \x20 versions[\"baseScala\"] = versions.scala.substring(0, versions.scala.lastIndexOf(\".\"))\n\
             } else {\n  versions[\"baseScala\"] = versions.scala\n}\n\
             libs += [\n  lib: \"g:lib_$versions.baseScala:$versions.scala\",\n]\n\
             apply plugin: 'java'\ndependencies {\n  implementation libs.lib\n}\n";
        let dir = tree(
            "map-entry-branches",
            &[
                ("gradle.properties", "scalaVersion=2.12.20\n"),
                ("build.gradle", script),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:lib_2.12"), ["2.12.20"], "{:?}", r.packages);
        // An entry set again to something not read is unknown, so its declaration is reported
        // (Gradle takes the later value).
        let unread = script.replace(
            "if ( !versions.scala",
            "versions[\"scala\"] = pickScala()\nif ( !versions.scala",
        );
        let dir = tree(
            "map-entry-unread",
            &[
                ("gradle.properties", "scalaVersion=2.12.20\n"),
                ("build.gradle", &unread),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(versions(&r, "g:lib_2.12").is_empty(), "{:?}", r.packages);
        assert!(!r.missing.is_empty());
        // Nor does a library entry take the first of a variable's two values.
        let repo = Mem(BTreeMap::from([pom("o", "1", &[]), pom("o", "2", &[])]));
        let dir = tree(
            "map-entry-twice",
            &[(
                "build.gradle",
                "def v = '1'\nv = '2'\next {\n  libs = [:]\n}\nlibs += [\n  o: \"g:o:$v\",\n]\n\
                 apply plugin: 'java'\ndependencies {\n  implementation libs.o\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(versions(&r, "g:o").is_empty(), "{:?}", r.packages);
        assert!(!r.missing.is_empty());
    }

    #[test]
    fn a_projects_evaluated_hook_depends_on_the_projects_it_keeps() {
        // spring-boot's docs: every subproject with the Java and Maven Publish plugins (here
        // through a buildSrc plugin that applies it), but no starter, and each one's
        // `optional` configuration. lib's optional x 2 beats the x 1 its y brings on docs
        // too; starter and tool are left out, so docs keeps its own v 1 and u 1.
        let optional = "public class OptionalDependenciesPlugin {\n\
             \tpublic void apply(Project project) {\n\
             \t\tConfiguration optional = project.getConfigurations().create(\"optional\");\n\
             \t\tsourceSets.all((s) -> {\n\
             \t\t\tproject.getConfigurations().getByName(s.getCompileClasspathConfigurationName()).extendsFrom(optional);\n\
             \t\t\tproject.getConfigurations().getByName(s.getRuntimeClasspathConfigurationName()).extendsFrom(optional);\n\
             \t\t});\n\t}\n}\n";
        let deployed = "public class DeployedPlugin implements Plugin<Project> {\n\
             \tpublic void apply(Project project) {\n\
             \t\tproject.getPlugins().apply(MavenPublishPlugin.class);\n\t}\n}\n";
        let repo = Mem(BTreeMap::from([
            pom("y", "1", &[("x", "1")]),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
            pom("v", "1", &[]),
            pom("v", "2", &[]),
            pom("u", "1", &[]),
            pom("u", "2", &[]),
        ]));
        let published = "plugins {\n\tid \"java-library\"\n\tid \"org.example.deployed\"\n\
                         \tid \"org.example.optional-dependencies\"\n}\n";
        let lib =
            format!("{published}dependencies {{\n\tapi(\"g:y:1\")\n\toptional(\"g:x:2\")\n}}\n");
        let starter = format!("{published}dependencies {{\n\tapi(\"g:v:2\")\n}}\n");
        let docs = "plugins {\n\tid \"java\"\n}\ndependencies {\n\timplementation(\"g:v:1\")\n\
                    \timplementation(\"g:u:1\")\n}\n\
                    project.rootProject.gradle.projectsEvaluated {\n\trootProject.subprojects\n\
                    \t\t.findAll { it != project }\n\
                    \t\t.findAll { it.plugins.hasPlugin(JavaPlugin) && it.plugins.hasPlugin(MavenPublishPlugin) }\n\
                    \t\t.findAll { !it.name.startsWith('starter') }\n\
                    \t\t.findAll { !it.path.contains(\":cli:\") }\n\
                    \t\t.each { javadocProject ->\n\t\t\tdependencies {\n\
                    \t\t\t\timplementation(project(javadocProject.path))\n\
                    \t\t\t\tif (javadocProject.plugins.hasPlugin(OptionalDependenciesPlugin)) {\n\
                    \t\t\t\t\timplementation(project(path: javadocProject.path, configuration: 'optional'))\n\
                    \t\t\t\t}\n\t\t\t}\n\t\t}\n}\n";
        let dir = tree(
            "projects-evaluated",
            &[
                ("settings.gradle", "include \"lib\"\ninclude \"starter-x\"\ninclude \"tool\"\ninclude \"docs\"\n"),
                (
                    "buildSrc/build.gradle",
                    "gradlePlugin {\n\tplugins {\n\t\tdeployed {\n\t\t\tid = \"org.example.deployed\"\n\
                     \t\t\timplementationClass = \"org.example.build.DeployedPlugin\"\n\t\t}\n\
                     \t\toptional {\n\t\t\tid = \"org.example.optional-dependencies\"\n\
                     \t\t\timplementationClass = \"org.example.build.optional.OptionalDependenciesPlugin\"\n\
                     \t\t}\n\t}\n}\n",
                ),
                ("buildSrc/src/main/java/org/example/build/DeployedPlugin.java", deployed),
                (
                    "buildSrc/src/main/java/org/example/build/optional/OptionalDependenciesPlugin.java",
                    optional,
                ),
                ("lib/build.gradle", &lib),
                ("starter-x/build.gradle", &starter),
                (
                    "tool/build.gradle",
                    "plugins {\n\tid \"java-library\"\n}\ndependencies {\n\tapi(\"g:u:2\")\n}\n",
                ),
                ("docs/build.gradle", docs),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:x"), ["2"], "{:?}", r.packages);
        assert_eq!(versions(&r, "g:y"), ["1"]);
        assert_eq!(versions(&r, "g:v"), ["1", "2"]);
        assert_eq!(versions(&r, "g:u"), ["1", "2"]);
        // A filter not read here leaves the hook reported.
        let unread = docs.replace("!it.path.contains(\":cli:\")", "it.version != null");
        let dir = tree(
            "projects-evaluated-unread",
            &[
                ("settings.gradle", "include \"lib\"\ninclude \"docs\"\n"),
                ("lib/build.gradle", &lib),
                ("docs/build.gradle", &unread),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(
            r.missing.iter().any(|m| m.contains("projectsEvaluated")),
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn a_platform_met_again_as_an_enforced_one_forces() {
        // spring-boot's docs: `platform(project(":deps"))`, then the internal enforced
        // platform that nests :deps. Everything :deps sets is forced (x stays 1 under y's 2).
        let repo = Mem(BTreeMap::from([
            pom("y", "1", &[("x", "2")]),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
        ]));
        let dir = tree(
            "enforced-again",
            &[
                ("settings.gradle", "include 'deps', 'internal', 'app'\n"),
                (
                    "deps/build.gradle",
                    "plugins {\n    id 'java-platform'\n}\ndependencies {\n    constraints {\n\
                     \x20       api 'g:x:1'\n    }\n}\n",
                ),
                (
                    "internal/build.gradle",
                    "plugins {\n    id 'java-platform'\n}\ndependencies {\n\
                     \x20   api enforcedPlatform(project(':deps'))\n}\n",
                ),
                (
                    "app/build.gradle",
                    "plugins {\n    id 'java'\n}\ndependencies {\n    implementation platform(project(':deps'))\n\
                     \x20   implementation enforcedPlatform(project(':internal'))\n    implementation 'g:y:1'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:x"), ["1"], "{:?}", r.packages);
    }

    #[test]
    fn a_version_a_rule_moves_asks_for_nothing() {
        // spring-boot's docs: an eachDependency rule moves opensaml 5.2.3 to 4.0.1, and
        // Gradle follows only 4.0.1's edges: its xmlsec 2.1.4, not 5.2.3's 3.0.6.
        let h = |v: &str, x: &str| {
            (
                format!("h:a:{v}"),
                format!(
                    "<project><groupId>h</groupId><artifactId>a</artifactId><version>{v}</version>\
                     <dependencies><dependency><groupId>g</groupId><artifactId>x</artifactId>\
                     <version>{x}</version></dependency></dependencies></project>"
                ),
            )
        };
        let repo = Mem(BTreeMap::from([
            h("1", "1"),
            h("2", "2"),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
        ]));
        let dir = tree(
            "rule-moves",
            &[(
                "build.gradle",
                "plugins {\n\tid \"java\"\n}\ndependencies {\n\timplementation(\"h:a:2\")\n}\n\
                 configurations {\n\tconfigureEach {\n\t\tresolutionStrategy {\n\t\t\teachDependency {\n\
                 \t\t\t\tif (it.requested.group == 'h') {\n\t\t\t\t\tit.useVersion '1'\n\t\t\t\t}\n\
                 \t\t\t}\n\t\t}\n\t}\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "h:a"), ["1"], "{:?}", r.packages);
        assert_eq!(versions(&r, "g:x"), ["1"]);
    }

    #[test]
    fn a_declared_platform_that_rises_manages_at_its_new_version() {
        // armeria: the build's junit-bom 5.14.4 rises to 6.0.2 through mcp-test's `.module`,
        // and Gradle takes the engine the build declares at 5.14.4 to 6.0.2 with it.
        let marker = "<!-- do_not_remove: published-with-gradle-metadata -->";
        let bom = |v: &str| {
            (
                format!("g:bom:{v}"),
                format!(
                    "<project><groupId>g</groupId><artifactId>bom</artifactId><version>{v}</version>\
                     <packaging>pom</packaging><dependencyManagement><dependencies><dependency>\
                     <groupId>g</groupId><artifactId>x</artifactId><version>{v}</version>\
                     </dependency></dependencies></dependencyManagement></project>"
                ),
            )
        };
        let body = r#""dependencies":[{"group":"g","module":"bom","version":{"requires":"2"},"attributes":{"org.gradle.category":"platform"}}]"#;
        let repo = Mem(BTreeMap::from([
            bom("1"),
            bom("2"),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
            (
                "g:lib:1".to_string(),
                format!("<project>{marker}<groupId>g</groupId><artifactId>lib</artifactId><version>1</version></project>"),
            ),
            (
                "g:lib:1.module".to_string(),
                format!(
                    r#"{{"formatVersion":"1.1","variants":[{{"name":"apiElements","attributes":{{"org.gradle.usage":"java-api","org.gradle.category":"library"}},{body}}},{{"name":"runtimeElements","attributes":{{"org.gradle.usage":"java-runtime","org.gradle.category":"library"}},{body}}}]}}"#
                ),
            ),
        ]));
        let dir = tree(
            "declared-platform-rises",
            &[(
                "build.gradle",
                "plugins {\n    id 'java'\n}\ndependencies {\n    implementation platform('g:bom:1')\n\
                 \x20   implementation 'g:x:1'\n    implementation 'g:lib:1'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:bom"), ["2"], "{:?}", r.packages);
        assert_eq!(versions(&r, "g:x"), ["2"]);
    }

    #[test]
    fn a_loop_over_a_literal_list_declares_each_item() {
        // armeria: netty's native transports, one declaration per OS in a `.each` loop, and
        // `variantOf(libs.x) { classifier(...) }` naming a file of libs.x.
        let repo = Mem(BTreeMap::from([
            pom("native-linux", "1", &[]),
            pom("native-osx", "1", &[]),
            pom("io-linux", "1", &[]),
            pom("io-osx", "1", &[]),
            pom("x", "1", &[]),
        ]));
        let dir = tree(
            "literal-loops",
            &[
                ("settings.gradle", "include 'groovy', 'kts'\n"),
                ("gradle/libs.versions.toml", "[libraries]\nx = \"g:x:1\"\n"),
                (
                    "groovy/build.gradle",
                    "plugins {\n    id 'java'\n}\ndependencies {\n    ['linux', 'osx'].each { os ->\n\
                     \x20       runtimeOnly \"g:native-${os}:1\"\n    }\n}\n",
                ),
                (
                    "kts/build.gradle.kts",
                    "plugins {\n    java\n}\ndependencies {\n    listOf(\"linux\", \"osx\").forEach { os ->\n\
                     \x20       runtimeOnly(\"g:io-$os:1\")\n    }\n\
                     \x20   implementation(variantOf(libs.x) { classifier(\"linux-x86_64\") })\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        for name in [
            "g:native-linux",
            "g:native-osx",
            "g:io-linux",
            "g:io-osx",
            "g:x",
        ] {
            assert_eq!(versions(&r, name), ["1"], "{name}: {:?}", r.packages);
        }
    }

    #[test]
    fn a_root_block_for_flagged_projects_reaches_each_one() {
        // armeria: LINE's gradle-scripts read `configure(projectsWithFlags('java')) { }` in
        // every project `includeWithFlags` flags with java (`java17` implies it), with
        // `project.path` as that project's path; an unflagged project takes none of it.
        let repo = Mem(BTreeMap::from([
            pom("x", "1", &[]),
            pom("y", "1", &[]),
            pom("z", "1", &[]),
        ]));
        let dir = tree(
            "line-flags",
            &[
                (
                    "gradle/scripts/settings-flags.gradle",
                    "// includeWithFlags and projectsWithFlags are defined here.\n",
                ),
                (
                    "settings.gradle",
                    "apply from: \"${rootDir}/gradle/scripts/settings-flags.gradle\"\n\
                     includeWithFlags ':app', 'java17'\nincludeWithFlags ':docs'\n",
                ),
                (
                    "build.gradle",
                    "configure(projectsWithFlags('java')) {\n    dependencies {\n\
                     \x20       if (project.path != project(':app').path) {\n            implementation 'g:x:1'\n        }\n\
                     \x20       implementation 'g:y:1'\n    }\n}\n\
                     configure(projectsWithFlags('java', 'publish')) {\n    dependencies {\n\
                     \x20       implementation 'g:z:1'\n    }\n}\n",
                ),
                ("app/build.gradle", "dependencies {\n}\n"),
                ("docs/build.gradle", "dependencies {\n}\n"),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:y"), ["1"], "{:?}", r.packages);
        assert!(versions(&r, "g:x").is_empty(), "{:?}", r.packages);
        assert!(versions(&r, "g:z").is_empty(), "{:?}", r.packages);
    }

    #[test]
    fn toolchain_conditions_are_decided_per_project() {
        // caffeine: below Java 17, an eachDependency `when (requested.group)` rule moves JUnit
        // to 5.x (its BOM too) and a force pins eclipse-collections; a project on 21 keeps
        // its own versions.
        let bom = |v: &str| {
            (
                format!("g:bom:{v}"),
                format!(
                    "<project><groupId>g</groupId><artifactId>bom</artifactId><version>{v}</version>\
                     <packaging>pom</packaging></project>"
                ),
            )
        };
        let repo = Mem(BTreeMap::from([
            bom("1"),
            bom("3"),
            pom("x", "1", &[]),
            pom("x", "3", &[]),
            ("h:y:1".to_string(), "<project><groupId>h</groupId><artifactId>y</artifactId><version>1</version></project>".to_string()),
            ("h:y:3".to_string(), "<project><groupId>h</groupId><artifactId>y</artifactId><version>3</version></project>".to_string()),
        ]));
        let script = |jdk: u32| {
            format!(
                "plugins {{\n    `java-library`\n}}\njava.toolchain {{\n    languageVersion = JavaLanguageVersion.of({jdk})\n}}\n\
                 dependencies {{\n    implementation(platform(\"g:bom:3\"))\n    implementation(\"g:x:3\")\n    implementation(libs.y)\n}}\n\
                 configurations.configureEach {{\n    val groups = setOf(\"g\")\n    resolutionStrategy.eachDependency {{\n\
                 \x20       if (java.toolchain.languageVersion.get().asInt() < 17) {{\n            when (requested.group) {{\n\
                 \x20               in groups -> useVersion(\"1\")\n            }}\n        }}\n    }}\n\
                 \x20   resolutionStrategy {{\n        if (java.toolchain.languageVersion.get().asInt() < 17) {{\n\
                 \x20           force(\"${{libs.y.get().module}}:1\")\n        }}\n    }}\n}}\n"
            )
        };
        let (old, new) = (script(11), script(21));
        let dir = tree(
            "toolchain-conditions",
            &[
                ("settings.gradle.kts", "include(\"old\", \"new\")\n"),
                ("gradle/libs.versions.toml", "[libraries]\ny = \"h:y:3\"\n"),
                ("old/build.gradle.kts", &old),
                ("new/build.gradle.kts", &new),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:x"), ["1", "3"], "{:?}", r.packages);
        assert_eq!(versions(&r, "g:bom"), ["1", "3"]);
        assert_eq!(versions(&r, "h:y"), ["1", "3"]);
    }

    #[test]
    fn a_force_in_a_branch_the_build_skips_forces_nothing() {
        let text =
            "configurations.all {\n    resolutionStrategy {\n        if (hasProperty('old')) {\n\
                    \x20           force 'g:a:1'\n        }\n        force 'g:b:2'\n    }\n}\n";
        let mut missing = BTreeSet::new();
        let forced = forced_versions(text, &BTreeMap::new(), &mut missing);
        let names: Vec<&str> = forced.iter().map(|(c, _)| c.artifact.as_str()).collect();
        assert_eq!(names, ["b"]);
    }

    #[test]
    fn a_toolchain_from_a_build_logic_helper_is_its_default() {
        let helper = "fun Project.javaVersion(): Provider<JavaLanguageVersion> =\n\
                      \x20 providers.gradleProperty(\"javaVersion\")\n\
                      \x20   .orElse(providers.environmentVariable(\"JAVA_VERSION\"))\n\
                      \x20   .map { it.toIntOrNull() }.orElse(11).map(JavaLanguageVersion::of)\n\
                      fun Project.other() = 1\n";
        let dir = tree(
            "toolchain-helper",
            &[("logic/src/main/kotlin/ProjectExtensions.kt", helper)],
        );
        let file = "logic/src/main/kotlin/lifecycle/java.gradle.kts";
        let text = "java.toolchain {\n  languageVersion = javaVersion()\n}\n";
        let mut vars = BTreeMap::new();
        assert_eq!(script_toolchain(&dir, file, text, &vars), Some(Some(11)));
        vars.insert("javaVersion".to_string(), "21".to_string());
        assert_eq!(script_toolchain(&dir, file, text, &vars), Some(Some(21)));
        assert_eq!(
            script_toolchain(
                &dir,
                file,
                "java.toolchain {\n  languageVersion = mine()\n}\n",
                &vars
            ),
            Some(None)
        );
        assert_eq!(script_toolchain(&dir, file, "plugins {\n}\n", &vars), None);
    }

    #[test]
    fn a_suite_using_junit_jupiter_takes_it_and_its_launcher() {
        let repo = Mem(BTreeMap::from([
            (
                "org.junit.jupiter:junit-jupiter:5.10.2".to_string(),
                "<project><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId><version>5.10.2</version></project>".to_string(),
            ),
            (
                "org.junit.platform:junit-platform-launcher:1.10.2".to_string(),
                "<project><groupId>org.junit.platform</groupId><artifactId>junit-platform-launcher</artifactId><version>1.10.2</version></project>".to_string(),
            ),
        ]));
        let dir = tree(
            "jupiter-suite",
            &[(
                "build.gradle.kts",
                "plugins {\n    java\n}\ntesting.suites {\n    named<JvmTestSuite>(\"test\") {\n\
                 \x20       useJUnitJupiter(\"5.10.2\")\n    }\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "org.junit.jupiter:junit-jupiter"), ["5.10.2"]);
        assert_eq!(
            versions(&r, "org.junit.platform:junit-platform-launcher"),
            ["1.10.2"]
        );
    }

    #[test]
    fn an_inline_if_on_an_unset_property_takes_its_null_branch() {
        // CosId: `managedVersions(if (springBootVersion == null) platform(...) else
        // enforcedPlatform(...))`, springBootVersion being `findProperty(...)?.toString()`.
        let bom = |v: &str| {
            (
                format!("g:bom:{v}"),
                format!(
                    "<project><groupId>g</groupId><artifactId>bom</artifactId><version>{v}</version>\
                     <packaging>pom</packaging><dependencyManagement><dependencies><dependency>\
                     <groupId>g</groupId><artifactId>x</artifactId><version>{v}</version>\
                     </dependency></dependencies></dependencyManagement></project>"
                ),
            )
        };
        let repo = Mem(BTreeMap::from([
            bom("1"),
            bom("2"),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
        ]));
        for (test, want) in [("== null", "1"), ("!= null", "2")] {
            let dir = tree(
                &format!("null-branch-{}", &test[..1]),
                &[(
                    "build.gradle.kts",
                    &format!(
                        "plugins {{\n    java\n}}\nval boot = findProperty(\"boot\")?.toString()\n\
                         dependencies {{\n    implementation(if (boot {test}) platform(\"g:bom:1\") else platform(\"g:bom:2\"))\n\
                         \x20   implementation(\"g:x\")\n}}\n"
                    ),
                )],
            );
            let r = resolve_gradle(&dir, &repo);
            assert!(r.missing.is_empty(), "{:?}", r.missing);
            assert_eq!(versions(&r, "g:x"), [want], "{test}: {:?}", r.packages);
        }
    }

    #[test]
    fn a_platform_built_from_the_whole_catalog_is_read() {
        // pulsar's pulsar-dependencies: every catalog alias but the tooling ones, a BOM-named
        // module as a platform and every other as a constraint.
        let bom = (
            "g:x-bom:2".to_string(),
            "<project><groupId>g</groupId><artifactId>x-bom</artifactId><version>2</version>\
             <packaging>pom</packaging><dependencyManagement><dependencies><dependency>\
             <groupId>g</groupId><artifactId>x</artifactId><version>2</version>\
             </dependency></dependencies></dependencyManagement></project>"
                .to_string(),
        );
        let repo = Mem(BTreeMap::from([
            bom,
            pom("a", "1", &[]),
            pom("a", "2", &[]),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
            pom("tool", "1", &[]),
            pom("tool", "3", &[]),
            pom("lib", "1", &[("a", "1"), ("x", "1"), ("tool", "1")]),
        ]));
        let platform = "plugins {\n    `java-platform`\n}\njavaPlatform {\n    allowDependencies()\n}\n\
            dependencies {\n\
            \x20   val catalog = project.extensions.getByType<VersionCatalogsExtension>().named(\"libs\")\n\
            \x20   val protobufVersion = providers.gradleProperty(\"protobufVersion\").orNull\n\
            \x20   catalog.libraryAliases.filterNot { it.replace('-', '.').replace('_', '.').startsWith(\"tooling.\") }.forEach { alias ->\n\
            \x20       catalog.findLibrary(alias).ifPresent { provider ->\n\
            \x20           val module = provider.get().module\n\
            \x20           if (module.group == \"com.google.protobuf\" && protobufVersion != null) {\n\
            \x20               if (module.name == \"protobuf-bom\") {\n\
            \x20                   api(platform(\"$module:$protobufVersion\"))\n\
            \x20               }\n\
            \x20           } else if (module.name.endsWith(\"-bom\") || module.name == \"bom\"\n\
            \x20                   || module.name.contains(\"-bom-\")) {\n\
            \x20               api(platform(provider))\n\
            \x20           } else {\n\
            \x20               constraints.api(provider)\n\
            \x20           }\n\
            \x20       }\n\
            \x20   }\n}\n";
        let dir = tree(
            "catalog-platform",
            &[
                ("settings.gradle.kts", "include(\"platform\", \"app\")\n"),
                (
                    "gradle/libs.versions.toml",
                    "[libraries]\nx-bom = \"g:x-bom:2\"\na = \"g:a:2\"\ntooling-tool = \"g:tool:3\"\nlib = \"g:lib:1\"\n",
                ),
                ("platform/build.gradle.kts", platform),
                (
                    "app/build.gradle.kts",
                    "plugins {\n    java\n}\ndependencies {\n    implementation(enforcedPlatform(project(\":platform\")))\n\
                     \x20   implementation(libs.lib)\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        // The loop's own lines stay reported; the loop itself is read.
        assert!(
            r.missing.iter().all(|m| !m.contains("catalog-wide")),
            "{:?}",
            r.missing
        );
        assert_eq!(versions(&r, "g:a"), ["2"], "{:?}", r.packages);
        assert_eq!(versions(&r, "g:x"), ["2"]);
        // The tooling alias is left out of the platform: only the unused-alias listing has 3.
        assert_eq!(versions(&r, "g:tool"), ["1", "3"]);
    }

    #[test]
    fn a_named_catalog_from_a_file_joins_libs() {
        // spotless: `create("pinnedLibs") { from(files("gradle/pinned-libs.versions.toml")) }`,
        // used as `pinnedLibs.maven.core`; its version refs and bundles name its own entries.
        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[]),
            pom("b", "2", &[]),
            pom("d", "2", &[]),
        ]));
        let dir = tree(
            "named-catalog",
            &[
                (
                    "settings.gradle.kts",
                    "dependencyResolutionManagement {\n  versionCatalogs {\n    create(\"pinnedLibs\") {\n\
                     \x20     from(files(\"gradle/pinned-libs.versions.toml\"))\n    }\n  }\n}\n",
                ),
                (
                    "gradle/pinned-libs.versions.toml",
                    "[versions]\nb = \"2\"\n[libraries]\nmaven-core = \"g:a:1\"\nb = { module = \"g:b\", version.ref = \"b\" }\n\
                     [bundles]\nboth = [\"maven-core\", \"b\"]\n",
                ),
                (
                    "build.gradle.kts",
                    "plugins {\n  java\n}\ndependencies {\n  compileOnly(pinnedLibs.maven.core)\n\
                     \x20 implementation(pinnedLibs.bundles.both)\n  implementation(\"g:d:${pinnedLibs.versions.b.get()}\")\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:a"), ["1"], "{:?}", r.packages);
        assert_eq!(versions(&r, "g:b"), ["2"]);
        assert_eq!(versions(&r, "g:d"), ["2"]);
        assert_eq!(
            catalog_accessors("x(myPinnedLibs.a, pinnedLibs.plugins.p)", "pinnedLibs"),
            "x(myPinnedLibs.a, libs.plugins.pinnedLibs.p)"
        );
    }

    #[test]
    fn a_dependency_set_manages_each_entry() {
        // mmorpg: `dependencySet(group: 'io.github.jforgame', version:
        // rootProject.ext.versions.jforgameVersion) { entry 'jforgame-commons' ... }`.
        let repo = Mem(BTreeMap::from([pom("a", "3", &[]), pom("b", "2", &[])]));
        let dir = tree(
            "dependency-set",
            &[(
                "build.gradle",
                "ext {\n    versions = [\n        aVersion: \"3\",\n    ]\n}\n\
                 apply plugin: 'java'\napply plugin: 'io.spring.dependency-management'\n\
                 dependencyManagement {\n    dependencies {\n\
                 \x20       dependencySet(group: 'g', version: rootProject.ext.versions.aVersion) {\n\
                 \x20           entry 'a'\n        }\n        dependencySet('g:2') {\n            entry 'b'\n        }\n\
                 \x20   }\n}\ndependencies {\n    implementation 'g:a'\n    implementation 'g:b'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:a"), ["3"], "{:?}", r.packages);
        assert_eq!(versions(&r, "g:b"), ["2"]);
    }

    #[test]
    fn a_build_logic_plugin_class_adds_what_its_apply_adds_for_sure() {
        // Talaiot: buildSrc registers `kotlinLib` as a class whose `apply` adds kotlintest to
        // every library's tests; an add inside an `if` is not sure, and stays unread.
        let repo = Mem(BTreeMap::from([pom("t", "1", &[]), pom("c", "1", &[])]));
        let dir = tree(
            "binary-plugin",
            &[
                ("settings.gradle.kts", "include(\":lib\")\n"),
                (
                    "buildSrc/build.gradle.kts",
                    "plugins {\n    `kotlin-dsl`\n}\ngradlePlugin {\n    plugins {\n        register(\"Lib\") {\n\
                     \x20           id = \"kotlinLib\"\n            implementationClass = \"a.b.LibPlugin\"\n\
                     \x20       }\n    }\n}\n",
                ),
                (
                    "buildSrc/src/main/kotlin/a/b/LibPlugin.kt",
                    "package a.b\n\nclass LibPlugin : Plugin<Project> {\n    override fun apply(target: Project) {\n\
                     \x20       target.plugins.apply(\"java-library\")\n        target.dependencies {\n\
                     \x20           add(\"testImplementation\", \"g:t:1\")\n        }\n\
                     \x20       if (target.hasProperty(\"x\")) {\n            target.dependencies {\n\
                     \x20               add(\"implementation\", \"g:c:1\")\n            }\n        }\n    }\n}\n",
                ),
                ("lib/build.gradle.kts", "plugins {\n    id(\"kotlinLib\")\n}\n"),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:t"), ["1"], "{:?}", r.packages);
        assert!(r
            .packages
            .iter()
            .find(|p| p.name == "g:t")
            .is_some_and(|p| p.dev));
        assert!(versions(&r, "g:c").is_empty(), "{:?}", r.packages);
    }

    #[test]
    fn the_franzbecker_plugin_adds_the_lombok_its_extension_sets() {
        // LogNet's gRPC starter: `classpath "io.franzbecker:gradle-lombok:4.0.0"`,
        // `apply plugin: 'io.franzbecker.gradle-lombok'`, `lombok { version = "${lombokVersion}" }`.
        // Without a version set, it is reported: the plugin's own default is not known here.
        let repo = Mem(BTreeMap::from([(
            "org.projectlombok:lombok:1.18.24".to_string(),
            "<project><groupId>org.projectlombok</groupId><artifactId>lombok</artifactId><version>1.18.24</version></project>".to_string(),
        )]));
        let build = |extension: &str| {
            format!(
                "buildscript {{\n    dependencies {{\n        classpath \"io.franzbecker:gradle-lombok:4.0.0\"\n    }}\n}}\n\
                 apply plugin: 'java'\napply plugin: 'io.franzbecker.gradle-lombok'\n{extension}"
            )
        };
        let set = build("lombok {\n    version = \"${lombokVersion}\"\n}\n");
        let dir = tree(
            "franzbecker",
            &[
                ("build.gradle", &set),
                ("gradle.properties", "lombokVersion=1.18.24\n"),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "org.projectlombok:lombok"), ["1.18.24"]);
        let unset = build("");
        let r = resolve_gradle(
            &tree("franzbecker-unset", &[("build.gradle", &unset)]),
            &repo,
        );
        assert!(versions(&r, "org.projectlombok:lombok").is_empty());
        assert_eq!(
            r.missing,
            ["build.gradle: io.franzbecker.gradle-lombok 4.0.0: the Lombok version it adds is not known"]
        );
    }

    #[test]
    fn line_gradle_scripts_boms_manage_every_project() {
        // armeria: LINE's gradle-scripts turn each `[boms]` entry of `dependencies.toml` into
        // `api platform(...)` of the platform project every configuration extends. Without
        // that script, a `[boms]` section is nothing Gradle reads.
        let bom = "<project><groupId>g</groupId><artifactId>bom</artifactId><version>4</version>\
                   <packaging>pom</packaging><dependencyManagement><dependencies><dependency>\
                   <groupId>g</groupId><artifactId>a</artifactId><version>4</version></dependency>\
                   </dependencies></dependencyManagement></project>";
        let repo = Mem(BTreeMap::from([
            ("g:bom:4".to_string(), bom.to_string()),
            pom("a", "4", &[]),
        ]));
        let files = |marker: &str| {
            vec![
                ("settings.gradle".to_string(), "include 'core'\n".to_string()),
                (
                    "dependencies.toml".to_string(),
                    "[versions]\nb = \"4\"\n[boms]\nb = { module = \"g:bom\", version.ref = \"b\" }\n\
                     [libraries.a]\nmodule = \"g:a\"\n"
                        .to_string(),
                ),
                (
                    "settings.gradle".to_string(),
                    "dependencyResolutionManagement {\n  versionCatalogs {\n    create(\"libs\") {\n\
                     \x20     from(files(\"dependencies.toml\"))\n    }\n  }\n}\ninclude 'core'\n"
                        .to_string(),
                ),
                (
                    "gradle/scripts/lib/common-dependencies.gradle".to_string(),
                    format!("dependencies {{\n    rootProject.ext.dependenciesTomlBoms.each {{ alias ->\n\
                             \x20       def library = rootProject.ext.findLibrary(alias)\n{marker}\n    }}\n}}\n"),
                ),
                ("build.gradle".to_string(), "allprojects {\n    apply plugin: 'java'\n}\n".to_string()),
                ("core/build.gradle".to_string(), "dependencies {\n    implementation libs.a\n}\n".to_string()),
            ]
        };
        let read = |name: &str, marker: &str| {
            let owned = files(marker);
            let refs: Vec<(&str, &str)> = owned
                .iter()
                .map(|(a, b)| (a.as_str(), b.as_str()))
                .collect();
            resolve_gradle(&tree(name, &refs), &repo)
        };
        let r = read("line-boms", "        api platform(library)");
        let own: Vec<&String> = r
            .missing
            .iter()
            .filter(|m| !m.starts_with("gradle/scripts/"))
            .collect();
        assert!(own.is_empty(), "{own:?}");
        assert_eq!(versions(&r, "g:a"), ["4"], "{:?}", r.packages);
        assert_eq!(versions(&r, "g:bom"), ["4"]);
        let r = read("line-boms-unused", "");
        assert!(versions(&r, "g:bom").is_empty(), "{:?}", r.packages);
    }

    #[test]
    fn compile_only_declarations_stay_off_the_test_runtime_classpath() {
        // PlotSquared: `compileOnlyApi(checker-qual 4.4.0)` compiles main and tests, and
        // worldedit's checker-qual 3.48.3 is what the tests run with.
        let repo = Mem(BTreeMap::from([
            pom("t", "1", &[("a", "1")]),
            pom("a", "1", &[]),
            pom("a", "2", &[]),
            pom("n", "1", &[]),
        ]));
        let dir = tree(
            "compile-only-test-runtime",
            &[(
                "build.gradle",
                "plugins { id 'java-library' }\ndependencies {\n    compileOnlyApi 'g:a:2'\n    testImplementation 'g:t:1'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:a"), ["1", "2"], "{:?}", r.packages);
        // Under the Spring plugin, LogNet's `compileOnly grpc-netty:${v}` still versions its
        // unversioned `testImplementation grpc-netty`.
        let dir = tree(
            "compile-only-spring-versions",
            &[(
                "build.gradle",
                "apply plugin: 'java'\napply plugin: 'io.spring.dependency-management'\ndependencies {\n    compileOnly 'g:n:1'\n    testImplementation 'g:n'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:n"), ["1"]);
    }

    #[test]
    fn a_test_compile_classpath_skips_what_a_project_does_not_export() {
        // Talaiot: `testImplementation(project(":test-utils"))`, whose `api` testcontainers
        // brings JNA 1 and whose `implementation` JNA is 2. The test compile classpath takes 1,
        // the test runtime one 2. A named configuration (jib's `configuration: 'tests'`)
        // hands over all it holds.
        let repo = Mem(BTreeMap::from([
            pom("tc", "1", &[("jna", "1")]),
            pom("jna", "1", &[]),
            pom("jna", "2", &[]),
        ]));
        let utils = "plugins { id 'java-library' }\ndependencies {\n    api 'g:tc:1'\n    implementation 'g:jna:2'\n}\n";
        let run = |consumer: &str| {
            let dir = tree(
                &format!("test-compile-exports-{}", consumer.len()),
                &[
                    ("settings.gradle", "include ':utils'\ninclude ':core'\n"),
                    ("utils/build.gradle", utils),
                    (
                        "core/build.gradle",
                        &format!("plugins {{ id 'java' }}\ndependencies {{\n    {consumer}\n}}\n"),
                    ),
                ],
            );
            let r = resolve_gradle(&dir, &repo);
            assert!(r.missing.is_empty(), "{:?}", r.missing);
            versions(&r, "g:jna")
        };
        assert_eq!(run("testImplementation project(':utils')"), ["1", "2"]);
        assert_eq!(
            run("testImplementation project(path: ':utils', configuration: 'tests')"),
            ["2"]
        );
    }

    #[test]
    fn a_strict_shorthand_version_is_its_version() {
        // kestra's platform: `api 'io.kestra:kotlp:0.1.6!!'`, Gradle's `strictly` shorthand.
        let repo = Mem(BTreeMap::from([pom("a", "1", &[])]));
        let dir = tree(
            "strict-shorthand",
            &[(
                "build.gradle",
                "plugins { id 'java' }\ndependencies {\n    implementation 'g:a:1!!'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:a"), ["1"], "{:?}", r.packages);
    }

    #[test]
    fn a_pom_profile_on_by_a_missing_property_counts_for_gradle() {
        // resteasy-core's parent imports resteasy-dependencies in a profile switched on by
        // `!resteasy.dependencies.eap`; Gradle reads it, and then not the default profile.
        let profile = |activation: &str, managed: &str| {
            format!(
                "<profile><activation>{activation}</activation><dependencyManagement><dependencies>\
                 {managed}</dependencies></dependencyManagement></profile>"
            )
        };
        let parent = format!(
            "<project><groupId>g</groupId><artifactId>par</artifactId><version>1</version>\
             <packaging>pom</packaging><profiles>{}{}</profiles></project>",
            profile(
                "<property><name>!eap</name></property>",
                "<dependency><groupId>g</groupId><artifactId>deps</artifactId><version>1</version>\
                 <type>pom</type><scope>import</scope></dependency>"
            ),
            profile(
                "<activeByDefault>true</activeByDefault>",
                "<dependency><groupId>g</groupId><artifactId>t</artifactId><version>9</version></dependency>"
            ),
        );
        let deps = "<project><groupId>g</groupId><artifactId>deps</artifactId><version>1</version>\
                    <packaging>pom</packaging><dependencyManagement><dependencies><dependency>\
                    <groupId>g</groupId><artifactId>t</artifactId><version>3</version></dependency>\
                    </dependencies></dependencyManagement></project>";
        let core = "<project><parent><groupId>g</groupId><artifactId>par</artifactId><version>1</version>\
                    </parent><artifactId>core</artifactId><dependencies><dependency><groupId>g</groupId>\
                    <artifactId>t</artifactId></dependency></dependencies></project>";
        let repo = Mem(BTreeMap::from([
            ("g:par:1".to_string(), parent),
            ("g:deps:1".to_string(), deps.to_string()),
            ("g:core:1".to_string(), core.to_string()),
            pom("t", "3", &[]),
            pom("t", "9", &[]),
        ]));
        let dir = tree(
            "absent-property-profile",
            &[(
                "build.gradle",
                "plugins { id 'java' }\ndependencies {\n    implementation 'g:core:1'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:t"), ["3"], "{:?}", r.packages);
    }

    #[test]
    fn a_project_dependency_exclusion_keeps_the_projects_own_declaration() {
        // armeria's :jetty9.3 tests against Jetty 9.3 while depending on :jetty9 (Jetty 9.4)
        // without its jetty-server: the exclusion cuts only the path through :jetty9.
        let repo = Mem(BTreeMap::from([
            pom("s", "1", &[("h", "1")]),
            pom("s", "2", &[("h", "2")]),
            pom("h", "1", &[]),
            pom("h", "2", &[]),
        ]));
        let dir = tree(
            "project-exclusion",
            &[
                ("settings.gradle", "include ':b'\ninclude ':old'\n"),
                ("b/build.gradle", "plugins { id 'java-library' }\ndependencies {\n    api 'g:s:2'\n}\n"),
                (
                    "old/build.gradle",
                    "plugins { id 'java' }\ndependencies {\n    testImplementation(project(':b')) {\n        exclude group: 'g', module: 's'\n    }\n    testImplementation 'g:s:1'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:s"), ["1", "2"], "{:?}", r.packages);
        assert_eq!(versions(&r, "g:h"), ["1", "2"]);
    }

    #[test]
    fn spring_boot_own_bom_dsl_manages_its_projects() {
        // spring-boot: buildSrc's `org.springframework.boot.bom` plugin reads `bom { library(...)
        // { group(...) { modules = [...]; module(...) { }; bom(...) } } }` into a java-platform,
        // and JavaConventions put the internal platform, which enforces the public one, on
        // every Java project. `links { module(...) }` only documents.
        let bom = "<project><groupId>g</groupId><artifactId>b-bom</artifactId><version>5</version>\
                   <packaging>pom</packaging><dependencyManagement><dependencies><dependency>\
                   <groupId>g</groupId><artifactId>b</artifactId><version>5</version></dependency>\
                   </dependencies></dependencyManagement></project>";
        let repo = Mem(BTreeMap::from([
            ("g:b-bom:5".to_string(), bom.to_string()),
            pom("a", "2", &[]),
            pom("m", "2", &[]),
            pom("b", "5", &[]),
            pom("i", "7", &[]),
            pom("c", "1", &[]),
            pom("s", "7", &[]),
            pom("w", "7", &[]),
        ]));
        let public = "plugins {\n\tid \"org.springframework.boot.bom\"\n}\n\nbom {\n\
                      \tlibrary(\"A\", \"${aVersion}\") {\n\t\tgroup(\"g\") {\n\t\t\tmodules = [\n\
                      \t\t\t\t\"a\",\n\t\t\t\t\"c-ignored\" {\n\t\t\t\t\tclassifier = \"test\"\n\t\t\t\t}\n\t\t\t]\n\
                      \t\t\tmodule(\"m\") {\n\t\t\t\tjavadoc(\"x\")\n\t\t\t}\n\t\t}\n\
                      \t\tlinks {\n\t\t\tmodule(\"c\") {\n\t\t\t\tjavadoc(\"y\")\n\t\t\t}\n\t\t}\n\t}\n\
                      \tlibrary(\"B\", \"5\") {\n\t\tgroup(\"g\") {\n\t\t\tbom(\"b-bom\")\n\t\t}\n\t}\n}\n";
        let internal = "plugins {\n\tid \"org.springframework.boot.bom\"\n}\n\nbom {\n\
                        \tlibrary(\"I\", \"7\") {\n\t\tgroup(\"g\") {\n\t\t\tmodules = [\"i\", \"s\", \"w\"]\n\t\t}\n\t}\n}\n\n\
                        dependencies {\n\tapi(enforcedPlatform(project(\":platform:spring-boot-dependencies\")))\n}\n";
        let dir = tree(
            "spring-boot-bom",
            &[
                (
                    "settings.gradle",
                    "include \"platform:spring-boot-dependencies\"\ninclude \"platform:spring-boot-internal-dependencies\"\ninclude \"core\"\ninclude \"starter\"\ninclude \"web\"\n",
                ),
                ("gradle.properties", "aVersion=2\n"),
                (
                    "buildSrc/src/main/java/org/springframework/boot/build/bom/BomExtension.java",
                    "dependencies.getConstraints().add(JavaPlatformPlugin.API_CONFIGURATION_NAME, constraint);\n",
                ),
                (
                    "buildSrc/src/main/java/org/springframework/boot/build/JavaConventions.java",
                    "project.getDependencies().enforcedPlatform(project.getDependencies()\n\
                     \t.project(Collections.singletonMap(\"path\", \":platform:spring-boot-internal-dependencies\")));\n",
                ),
                (
                    "buildSrc/build.gradle",
                    "gradlePlugin {\n\tplugins {\n\t\tstarterPlugin {\n\t\t\tid = \"org.springframework.boot.starter\"\n\
                     \t\t\timplementationClass = \"org.springframework.boot.build.starters.StarterPlugin\"\n\t\t}\n\t}\n}\n",
                ),
                (
                    "buildSrc/src/main/java/org/springframework/boot/build/starters/StarterPlugin.java",
                    "public void apply(Project project) {\n\tPluginContainer plugins = project.getPlugins();\n\
                     \tplugins.apply(JavaLibraryPlugin.class);\n}\n",
                ),
                (
                    "starter/build.gradle",
                    "plugins {\n\tid \"org.springframework.boot.starter\"\n}\n\ndependencies {\n\tapi(\"g:s\")\n}\n",
                ),
                (
                    "web/build.gradle",
                    "plugins {\n\tid \"war\"\n}\n\ndependencies {\n\tprovidedRuntime(\"g:w\")\n}\n",
                ),
                ("platform/spring-boot-dependencies/build.gradle", public),
                ("platform/spring-boot-internal-dependencies/build.gradle", internal),
                (
                    "core/build.gradle",
                    "plugins {\n\tid \"java-library\"\n}\n\ndependencies {\n\tapi(\"g:a\")\n\tapi(\"g:m\")\n\
                     \tapi(\"g:b\")\n\ttestImplementation(\"g:i\")\n\tapi(\"g:c:1\")\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
        assert_eq!(versions(&r, "g:a"), ["2"], "{:?}", r.packages);
        assert_eq!(versions(&r, "g:m"), ["2"]);
        assert_eq!(versions(&r, "g:b"), ["5"]);
        assert_eq!(versions(&r, "g:i"), ["7"]);
        assert_eq!(versions(&r, "g:c"), ["1"]);
        // A starter (buildSrc's plugin applies java-library) and a war project are Java ones.
        assert_eq!(versions(&r, "g:s"), ["7"]);
        assert_eq!(versions(&r, "g:w"), ["7"]);
    }

    #[test]
    fn a_branch_the_default_build_skips_adds_nothing() {
        // logstash: `if (rootProject.fedrampHighMode) { dependencies { runtimeOnly ... } }`,
        // with the flag `Objects.requireNonNullElse(project.findProperty(...), false)`.
        let repo = Mem(BTreeMap::from([pom("a", "1", &[]), pom("fips", "1", &[])]));
        let dir = tree(
            "skipped-branch",
            &[(
                "build.gradle",
                "ext {\n    fips = Objects.requireNonNullElse(project.findProperty('fips'), false).toBoolean()\n}\n\
                 dependencies {\n    implementation 'g:a:1'\n}\n\
                 afterEvaluate {\n    if (rootProject.fips) {\n        dependencies {\n            runtimeOnly 'g:fips:1'\n        }\n    }\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:a"), ["1"]);
        assert!(versions(&r, "g:fips").is_empty(), "{:?}", r.packages);
    }

    #[test]
    fn a_configuration_wide_exclude_drops_direct_declarations_too() {
        // conductor: the root's `subprojects { configurations { all { exclude group:
        // 'ch.qos.logback', ... } } }` drops Logback a module declares itself.
        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[("log", "1")]),
            pom("log", "1", &[]),
        ]));
        let dir = tree(
            "configuration-exclude",
            &[
                ("settings.gradle", "include 'app'\n"),
                (
                    "build.gradle",
                    "subprojects {\n    configurations {\n        all {\n\
                     \x20           exclude group: 'g', module: 'log'\n        }\n    }\n}\n",
                ),
                (
                    "app/build.gradle",
                    "dependencies {\n    implementation 'g:a:1'\n    runtimeOnly 'g:log:1'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:a"), ["1"]);
        assert!(versions(&r, "g:log").is_empty(), "{:?}", r.packages);
    }

    #[test]
    fn a_root_project_block_configures_that_project() {
        // kafka: the root build.gradle's `project(':clients') { dependencies { ... } }` blocks
        // are each project's build; the projects have no build file of their own.
        let repo = Mem(BTreeMap::from([pom("a", "1", &[]), pom("a", "2", &[])]));
        let dir = tree(
            "project-blocks",
            &[
                ("settings.gradle", "include 'lib', 'app'\n"),
                (
                    "build.gradle",
                    "subprojects {\n    apply plugin: 'java'\n}\n\
                     project(':lib') {\n    dependencies {\n        implementation 'g:a:1'\n    }\n}\n\
                     project(':app') {\n    dependencies {\n        implementation 'g:a:2'\n    }\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:a"), ["1", "2"], "{:?}", r.missing);
    }

    #[test]
    fn a_libs_map_added_to_names_coordinates() {
        // kafka's gradle/dependencies.gradle: `versions += [ k: "v" ]`, `libs += [ k:
        // "g:a:$versions.k" ]`, named as `libs.k` with no version catalog.
        let repo = Mem(BTreeMap::from([pom("a", "1", &[])]));
        let dir = tree(
            "libs-map",
            &[
                (
                    "gradle/dependencies.gradle",
                    "ext {\n  versions = [:]\n  libs = [:]\n}\n\
                     versions += [\n  a: \"1\",\n]\n\
                     libs += [\n  a: \"g:a:$versions.a\",\n]\n",
                ),
                (
                    "build.gradle",
                    "apply from: \"$rootDir/gradle/dependencies.gradle\"\n\
                     dependencies {\n    implementation libs.a\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:a"), ["1"], "{:?}", r.missing);
    }

    #[test]
    fn the_libs_catalog_can_live_in_another_toml_file() {
        // armeria: the settings apply a script that creates `libs` from the root's
        // `dependencies.toml`, read by its own code.
        let repo = Mem(BTreeMap::from([pom("a", "1", &[])]));
        let dir = tree(
            "catalog-file",
            &[
                ("settings.gradle", "apply from: \"${rootDir}/gradle/catalog.gradle\"\n"),
                (
                    "gradle/catalog.gradle",
                    "def file = new File(\"${rootProject.projectDir}/dependencies.toml\")\n\
                     dependencyResolutionManagement {\n    versionCatalogs {\n        create(\"libs\") { libs ->\n        }\n    }\n}\n",
                ),
                (
                    "dependencies.toml",
                    "[versions]\na = \"1\"\n\n[libraries.a]\nmodule = \"g:a\"\nversion.ref = \"a\"\n",
                ),
                ("build.gradle", "dependencies {\n    implementation libs.a\n}\n"),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:a"), ["1"], "{:?}", r.missing);
    }

    #[test]
    fn a_list_variable_declares_each_of_its_items() {
        // kafka: `testLog4j2Libs = [ libs.a, ... ]` in the root's `ext { }`, declared whole as
        // `testImplementation testLog4j2Libs`.
        let repo = Mem(BTreeMap::from([pom("a", "1", &[]), pom("b", "2", &[])]));
        let dir = tree(
            "list-variable",
            &[(
                "build.gradle",
                "ext {\n  testLibs = [\n    'g:a:1',\n    \"g:b:2\"\n  ]\n}\n\
                 dependencies {\n    testImplementation testLibs\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:a"), ["1"], "{:?}", r.missing);
        assert_eq!(versions(&r, "g:b"), ["2"], "{:?}", r.missing);
        assert!(r.missing.is_empty(), "{:?}", r.missing);
    }

    #[test]
    fn an_each_dependency_rule_can_take_a_catalog_library_version() {
        // PlotSquared: `useVersion(checkNotNull(libs.paper.orNull?.version))` pins paper-api
        // to the catalog's own version over the 2 a dependency asks for.
        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[("paper", "2")]),
            pom("paper", "1", &[]),
            pom("paper", "2", &[]),
        ]));
        let dir = tree(
            "catalog-library-version",
            &[
                (
                    "gradle/libs.versions.toml",
                    "[versions]\npaper = \"1\"\n[libraries]\n\
                     paper = { group = \"g\", name = \"paper\", version.ref = \"paper\" }\n",
                ),
                (
                    "build.gradle.kts",
                    "configurations.all {\n    resolutionStrategy.eachDependency {\n\
                     \x20       if (requested.group == \"g\" && requested.name == \"paper\") {\n\
                     \x20           useVersion(checkNotNull(libs.paper.orNull?.version))\n\
                     \x20       }\n    }\n}\n\
                     dependencies {\n    implementation(\"g:a:1\")\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:paper"), ["1"], "{:?}", r.missing);
    }

    #[test]
    fn a_compile_only_version_stays_off_the_runtime_classpath() {
        // gradle-versions-plugin: `compileOnly(libs.kotlin.stdlib)` 2.4.10 is on the compile
        // classpath only; the runtime classpath keeps okio's 1.9.21.
        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[("lib", "1")]),
            pom("lib", "1", &[]),
            pom("lib", "2", &[]),
        ]));
        let dir = tree(
            "compile-only-runtime",
            &[(
                "build.gradle",
                "dependencies {\n  implementation 'g:a:1'\n  compileOnly 'g:lib:2'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:lib"), ["1", "2"]);
    }

    #[test]
    fn an_api_variant_only_dependency_stays_off_the_runtime_classpath() {
        // zaproxy: log4j-api's apiElements alone lists bnd's annotations 7.1.0, which the
        // build's `compileOnly` 7.4.0 raises; the runtime classpath has neither.
        let marker = "<!-- do_not_remove: published-with-gradle-metadata -->";
        let json = r#"{"formatVersion":"1.1","variants":[
            {"name":"apiElements","attributes":{"org.gradle.usage":"java-api","org.gradle.category":"library"},
              "dependencies":[{"group":"g","module":"bnd","version":{"requires":"1"}}]},
            {"name":"runtimeElements","attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"library"}}]}"#;
        let repo = Mem(BTreeMap::from([
            (
                "g:log:1".to_string(),
                format!("<project>{marker}<groupId>g</groupId><artifactId>log</artifactId><version>1</version></project>"),
            ),
            ("g:log:1.module".to_string(), json.to_string()),
            pom("bnd", "1", &[]),
            pom("bnd", "2", &[]),
        ]));
        let dir = tree(
            "api-only-runtime",
            &[(
                "build.gradle",
                "dependencies {\n  implementation 'g:log:1'\n  compileOnly 'g:bnd:2'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:bnd"), ["2"]);
    }

    #[test]
    fn a_root_blocks_boms_and_versions_reach_every_subproject() {
        // A BOM managing g:a, imported in the root's `configure(subprojects...)` through the
        // Spring plugin with its version in `extra`, a managed version for g:b, and Kotlin's
        // version as a buildSrc constant.
        let bom = (
            "g:bom:4.1.1".to_string(),
            "<project><groupId>g</groupId><artifactId>bom</artifactId><version>4.1.1</version>\
             <packaging>pom</packaging><dependencyManagement><dependencies>\
             <dependency><groupId>g</groupId><artifactId>a</artifactId><version>3.0</version></dependency>\
             </dependencies></dependencyManagement></project>"
                .to_string(),
        );
        let repo = Mem(BTreeMap::from([
            bom,
            pom("a", "3.0", &[]),
            pom("b", "2.0", &[]),
            pom("k", "2.2.20", &[]),
        ]));
        let dir = tree(
            "shared-blocks",
            &[
                ("settings.gradle.kts", ""),
                (
                    "build.gradle.kts",
                    "allprojects {\n    extra[\"sb.version\"] = \"4.1.1\"\n}\n\
                     configure(subprojects.filterNot { it in skipped }) {\n\
                     \x20   val sbVersion = extra[\"sb.version\"] as String\n\
                     \x20   dependencyManagement {\n\
                     \x20       imports {\n\
                     \x20           mavenBom(\"g:bom:$sbVersion\")\n\
                     \x20       }\n\
                     \x20       dependencies {\n\
                     \x20           dependency(\"g:b:2.0\")\n\
                     \x20       }\n\
                     \x20   }\n\
                     \x20   dependencies {\n\
                     \x20       implementation(\"g:k:${Versions.KOTLIN}\")\n\
                     \x20   }\n\
                     }\n",
                ),
                (
                    "buildSrc/src/main/kotlin/Versions.kt",
                    "object Versions {\n    const val KOTLIN = \"2.2.20\"\n}\n",
                ),
                (
                    "lib/build.gradle.kts",
                    "dependencies {\n    api(\"g:a\")\n    implementation(\"g:b\")\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:a"), ["3.0"], "{:?}", r.missing);
        assert_eq!(versions(&r, "g:b"), ["2.0"], "{:?}", r.missing);
        assert_eq!(versions(&r, "g:k"), ["2.2.20"], "{:?}", r.missing);
    }

    #[test]
    fn a_platform_project_manages_the_projects_that_import_it() {
        // halo's shape: a `java-platform` project imports the Spring Boot plugin's BOM (the
        // plugin declared `apply false` with its version in the catalog) and constrains g:c;
        // another project takes both through `platform(project(...))`.
        let bom = (
            "org.springframework.boot:spring-boot-dependencies:3.5.0".to_string(),
            "<project><groupId>org.springframework.boot</groupId>\
             <artifactId>spring-boot-dependencies</artifactId><version>3.5.0</version>\
             <packaging>pom</packaging><dependencyManagement><dependencies>\
             <dependency><groupId>g</groupId><artifactId>a</artifactId><version>3.0</version></dependency>\
             </dependencies></dependencyManagement></project>"
                .to_string(),
        );
        let repo = Mem(BTreeMap::from([
            bom,
            pom("a", "3.0", &[]),
            pom("c", "1.5", &[]),
        ]));
        let dir = tree(
            "platform-project",
            &[
                ("settings.gradle", "include 'platform:app', 'api'\n"),
                (
                    "gradle/libs.versions.toml",
                    "[plugins]\nspring-boot = { id = \"org.springframework.boot\", version = \"3.5.0\" }\n",
                ),
                (
                    "platform/app/build.gradle",
                    "plugins {\n    id 'java-platform'\n    alias(libs.plugins.spring.boot) apply false\n}\n\
                     dependencies {\n    api platform(SpringBootPlugin.BOM_COORDINATES)\n\
                     \x20   constraints {\n        api 'g:c:1.5'\n    }\n}\n",
                ),
                (
                    "api/build.gradle",
                    "dependencies {\n    api platform(project(':platform:app'))\n\
                     \x20   api 'g:a'\n    api 'g:c'\n}\n",
                ),
                (
                    "build.gradle",
                    "configure(allprojects - project(':platform:app')) {\n\
                     \x20   dependencies {\n\
                     \x20       dependencyManagement(enforcedPlatform(dependencies.project(path: \":platform:app\")))\n\
                     \x20   }\n}\n",
                ),
                ("web/build.gradle", "dependencies {\n    api 'g:c'\n}\n"),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:a"), ["3.0"], "{:?}", r.missing);
        assert_eq!(versions(&r, "g:c"), ["1.5"], "{:?}", r.missing);
        assert!(
            !r.missing.iter().any(|m| m.contains("not managed")),
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn groovy_map_entries_name_coordinates() {
        let repo = Mem(BTreeMap::from([
            pom("a", "3.5.19", &[]),
            pom("b", "2.0", &[]),
            pom("c", "1.4", &[]),
            pom("d", "6.1", &[]),
        ]));
        let dir = tree(
            "groovy-maps",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "buildscript {\n    ext {\n        libraries = [\n            aVersion = '3.5.19',\n        ]\n\
                     \x20       lib = [\n            \"a\"      : \"g:a:${aVersion}\",\n\
                     \x20           'b-x'    : 'g:b:2.0',\n            c: \"g:c:1.4\",\n\
                     \x20           \"junit\": \"g:d:6.1\",\n        ]\n    }\n}\n\
                     dependencies {\n    implementation lib.a\n    api(lib['b-x'])\n\
                     \x20   testImplementation \"${lib.'c'}\"\n    testImplementation \"${lib[\"junit\"]}\"\n\
                     \x20   implementation \"${lib.\"b-x\"}\"\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        for (name, want) in [
            ("g:a", "3.5.19"),
            ("g:b", "2.0"),
            ("g:c", "1.4"),
            ("g:d", "6.1"),
        ] {
            assert_eq!(versions(&r, name), [want], "{name} {:?}", r.missing);
        }
    }

    #[test]
    fn forge_deobf_wraps_a_plain_coordinate() {
        let mut context = context("", &[("project.blockUI_version", "1.0.9"), ("v", "2.1")]);
        let module = read_script(
            "dependencies {\n    implementation(fg.deobf(\"com.ldtteam:blockui:${project.blockUI_version}\")){\n\
             \x20       transitive = false\n    }\n    compileOnly fg.deobf(\"g:x:$v:universal\")\n}\n",
            &mut context,
        );
        let got: Vec<String> = module
            .deps
            .iter()
            .map(|d| {
                format!(
                    "{}:{}",
                    d.coordinate.artifact,
                    d.coordinate.version.as_deref().unwrap_or("-")
                )
            })
            .collect();
        assert_eq!(got, ["blockui:1.0.9", "x:2.1"], "{:?}", module.unread);
    }

    #[test]
    fn rich_version_blocks_fold_into_their_declaration() {
        let text = "constraints {\n    api(\"g:a\") {\n        version {\n            require(\"3.8.0\")\n\
                    \x20           reject(\"[3.2.1]\")\n        }\n    }\n\
                    \x20   api(\"g:b\") {\n        version { strictly(\"3.0.0\") }\n    }\n\
                    \x20   api(\"g:c:2.26.1\") {\n        because(\"CVE\")\n    }\n\
                    \x20   api(\"g:d\") {\n        because(\"no version\")\n    }\n}\n";
        let folded = fold_rich_versions(text);
        assert_eq!(folded.lines().count(), text.lines().count());
        assert!(folded.contains("api(\"g:a:3.8.0\")"), "{folded}");
        assert!(folded.contains("api(\"g:b:3.0.0\")"), "{folded}");
        assert!(folded.contains("api(\"g:c:2.26.1\") {"), "{folded}");
        assert!(folded.contains("api(\"g:d\") {"), "{folded}");
        let mut context = context("", &[]);
        let module = read_script(&format!("dependencies {{\n{text}}}\n"), &mut context);
        let mut got: Vec<String> = module
            .constraints
            .iter()
            .map(|c| format!("{}:{}", c.artifact, c.version.as_deref().unwrap_or("-")))
            .collect();
        got.sort();
        assert_eq!(got, ["a:3.8.0", "b:3.0.0", "c:2.26.1"]);
    }

    #[test]
    fn custom_configurations_take_the_scope_that_extends_them() {
        let mut map = BTreeMap::new();
        for line in [
            "testImplementation.extendsFrom testShadow",
            "implementation.extendsFrom(shade, bundled)",
            "configurations.compileOnly.get().extendsFrom(configurations.provided)",
            "foo.extendsFrom bar",
        ] {
            extends_from(line, &mut map);
        }
        assert_eq!(map["testShadow"], "testImplementation");
        assert_eq!(map["shade"], "implementation");
        assert_eq!(map["bundled"], "implementation");
        assert_eq!(map["provided"], "compileOnly");
        assert!(!map.contains_key("bar"));

        let repo = Mem(BTreeMap::from([
            pom("j", "4.13", &[]),
            pom("s", "3.2", &[]),
        ]));
        let dir = tree(
            "custom-configurations",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "configurations {\n    implementation.extendsFrom shade\n}\n\
                     dependencies {\n    shade group: 'g', name: 's', version: '3.2'\n\
                     \x20   testShadow group: 'g', name: 'j', version: '4.13'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:s"), ["3.2"], "{:?}", r.missing);
        assert_eq!(versions(&r, "g:j"), ["4.13"], "{:?}", r.missing);
        let s = r.packages.iter().find(|p| p.name == "g:s").unwrap();
        assert!(!s.dev);
    }

    #[test]
    fn a_catalog_in_the_settings_script_is_read() {
        let repo = Mem(BTreeMap::from([
            pom("a", "3.4.9", &[]),
            pom("b", "0.4.1", &[]),
            pom("c", "1.2", &[]),
            pom("k", "2.0", &[]),
        ]));
        let dir = tree(
            "settings-catalog",
            &[
                (
                    "settings.gradle",
                    "rootProject.name = 'x'\n\
                     dependencyResolutionManagement.versionCatalogs.register('libs') {\n\
                     \x20   version 'av', '3.4.9'\n\
                     \x20   library 'a-lib', 'g', 'a' versionRef 'av' // a comment 'quoted'\n\
                     \x20   library 'b', 'g', 'b' version '0.4.1'\n\
                     \x20   library 'c', 'g:c:1.2'\n\
                     \x20   bundle 'utils', ['b', 'c']\n}\n",
                ),
                (
                    "build.gradle.kts",
                    "dependencies {\n    implementation(libs.a.lib)\n    implementation(libs.bundles.utils)\n}\n",
                ),
                (
                    "other/settings.gradle.kts",
                    "dependencyResolutionManagement {\n  versionCatalogs {\n    create(\"libs\") {\n\
                     \x20     library(\"k\", \"g\", \"k\").version(\"2.0\")\n    }\n  }\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:a"), ["3.4.9"], "{:?}", r.missing);
        assert_eq!(versions(&r, "g:b"), ["0.4.1"], "{:?}", r.missing);
        assert_eq!(versions(&r, "g:c"), ["1.2"], "{:?}", r.missing);
        let kotlin = settings_catalog(
            "versionCatalogs {\n create(\"libs\") {\n  library(\"k\", \"g\", \"k\").version(\"2.0\")\n\
             \x20 plugin(\"p\", \"g.p\").versionRef(\"pv\")\n }\n}\n",
        );
        assert_eq!(kotlin[1].1["k"]["module"].as_str(), Some("g:k"));
        assert_eq!(kotlin[1].1["k"]["version"].as_str(), Some("2.0"));
        assert_eq!(kotlin[3].1["p"]["version"]["ref"].as_str(), Some("pv"));
    }

    #[test]
    fn a_declared_platform_is_listed_without_its_dependencies() {
        let repo = Mem(BTreeMap::from([
            pom("chain", "1", &[("x", "1")]),
            pom("x", "1", &[]),
        ]));
        let dir = tree(
            "platform-listed",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "dependencies {\n    implementation platform('g:chain:1')\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let names: Vec<_> = r.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["g:chain"], "{:?}", r.missing);
    }

    #[test]
    fn spring_managed_versions_beat_conflict_resolution() {
        let bom = |name: &str, x: &str| {
            (
                format!("g:{name}:1"),
                format!(
                    "<project><groupId>g</groupId><artifactId>{name}</artifactId><version>1</version>\
                     <dependencyManagement><dependencies><dependency><groupId>g</groupId>\
                     <artifactId>x</artifactId><version>{x}</version></dependency></dependencies>\
                     </dependencyManagement></project>"
                ),
            )
        };
        let repo = Mem(BTreeMap::from([
            bom("bom", "1"),
            bom("later", "3"),
            pom("a", "1", &[("x", "2")]),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
            pom("x", "3", &[]),
            pom("y", "1", &[("x", "2")]),
        ]));
        let script = |imports: &str, deps: &str| {
            format!(
                "plugins {{ id 'io.spring.dependency-management' version '1.1.7' }}\n\
                 dependencyManagement {{\n    imports {{\n{imports}    }}\n}}\n\
                 dependencies {{\n{deps}}}\n"
            )
        };
        let one = |tag: &str, text: &str| {
            let dir = tree(tag, &[("settings.gradle", ""), ("build.gradle", text)]);
            versions(&resolve_gradle(&dir, &repo), "g:x")
        };
        // `a` asks for x 2; the BOM's 1 wins, as the plugin sets it.
        assert_eq!(
            one(
                "spring-enforced",
                &script(
                    "        mavenBom 'g:bom:1'\n",
                    "    implementation 'g:a:1'\n"
                )
            ),
            ["1"]
        );
        // A later import overrides an earlier one.
        assert_eq!(
            one(
                "spring-later",
                &script(
                    "        mavenBom 'g:bom:1'\n        mavenBom 'g:later:1'\n",
                    "    implementation 'g:a:1'\n"
                )
            ),
            ["3"]
        );
        // A version the build declares itself is kept.
        assert_eq!(
            one(
                "spring-own",
                &script(
                    "        mavenBom 'g:bom:1'\n",
                    "    implementation 'g:a:1'\n    implementation 'g:x:2'\n"
                )
            ),
            ["2"]
        );
        // The declared version is the managed one for every path: `a` asking for 2 does not
        // raise a declared 1 the BOM would set to 3 (conductor's grpc 1.75.0 under Boot).
        assert_eq!(
            one(
                "spring-own-lower",
                &script(
                    "        mavenBom 'g:later:1'\n",
                    "    implementation 'g:a:1'\n    implementation 'g:x:1'\n"
                )
            ),
            ["1"]
        );
        // `enforcedPlatform` forces its version, over one the build declares too.
        assert_eq!(
            one(
                "enforced-platform",
                "dependencies {\n    implementation enforcedPlatform('g:bom:1')\n    implementation 'g:a:1'\n\
                 \x20   implementation 'g:x:2'\n}\n"
            ),
            ["1"]
        );
        // A plain platform only requests: the highest wins.
        assert_eq!(
            one(
                "platform-highest",
                "dependencies {\n    implementation platform('g:bom:1')\n    implementation 'g:a:1'\n}\n"
            ),
            ["2"]
        );
    }

    #[test]
    fn a_project_dependency_brings_its_dependencies_and_the_highest_wins() {
        // ethereum-lists: processor declares moshi 1.15.2 and depends on `:model`, which
        // declares 1.14.0; Gradle gives processor 1.15.2 and model 1.14.0. A version only `:lib`
        // asks for reaches `:app` too, raising `:app`'s own lower one.
        let repo = Mem(BTreeMap::from([
            pom("x", "1", &[]),
            pom("x", "2", &[]),
            pom("y", "1", &[]),
            pom("y", "2", &[]),
        ]));
        let dir = tree(
            "project-deps",
            &[
                ("settings.gradle", "include 'lib', 'app'\n"),
                (
                    "lib/build.gradle",
                    "dependencies {\n    implementation 'g:x:1'\n    implementation 'g:y:2'\n}\n",
                ),
                (
                    "app/build.gradle",
                    "dependencies {\n    implementation project(':lib')\n    implementation 'g:x:2'\n\
                     \x20   implementation 'g:y:1'\n    implementation project(':gone')\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let set = |name: &str| versions(&r, name).into_iter().collect::<BTreeSet<_>>();
        // lib keeps its x 1; app takes x 2 (its own, the higher) and, at run time, y 2 (lib's,
        // the higher). lib's `implementation` stays off app's compile classpath, so app
        // compiles against its own y 1.
        let both = BTreeSet::from(["1".to_string(), "2".to_string()]);
        assert_eq!(set("g:x"), both);
        assert_eq!(set("g:y"), both);
        assert!(
            r.missing.iter().any(|m| m.contains("project `:gone`")),
            "{:?}",
            r.missing
        );
        // Source sets of their own never reach a main classpath.
        assert_eq!(scope_of("jmhImplementation"), "test");
        assert_eq!(scope_of("benchmarkImplementation"), "test");
        assert_eq!(scope_of("modImplementation"), "compile");
    }

    #[test]
    fn project_paths_follow_the_settings_script() {
        // conductor names every child `conductor-*` and moves some to other directories;
        // Hystrix and kafka rename single projects. `project(":conductor-lib")` is lib/.
        let paths = settings_paths(
            "include 'lib', 'app', \\\n  'contrib/tool', 'storage:api'\n\
             rootProject.children.each {it.name=\"conductor-${it.name}\"}\n\
             project(':conductor-sched').projectDir = file('scheduler/core')\n\
             project(':conductor-contrib/tool').name = 'tool'\n\
             project(':conductor-storage:api').name = 'storage-api'\n\
             project(':x').projectDir = new File(rootDir, 'tools/x')\n",
        );
        let path_of = |dir: &str| {
            paths
                .iter()
                .filter(|(_, d)| d == dir)
                .map(|(p, _)| p.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(path_of("lib"), [":conductor-lib"]);
        assert_eq!(path_of("scheduler/core"), [":conductor-sched"]);
        assert_eq!(path_of("contrib/tool"), [":tool"]);
        assert_eq!(path_of("storage/api"), [":conductor-storage:storage-api"]);
        assert_eq!(path_of("tools/x"), [":x"]);

        let repo = Mem(BTreeMap::from([pom("x", "1", &[])]));
        let dir = tree(
            "settings-paths",
            &[
                (
                    "settings.gradle.kts",
                    "include(\n    \"lib\",\n    \"app\"\n)\n\
                     project(\":lib\").projectDir = file(\"modules/lib\")\n",
                ),
                (
                    "modules/lib/build.gradle",
                    "dependencies {\n    api 'g:x:1'\n}\n",
                ),
                (
                    "app/build.gradle",
                    "dependencies {\n    implementation project(':lib')\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert!(
            r.missing.iter().all(|m| !m.contains("project `:lib`")),
            "{:?}",
            r.missing
        );
        assert_eq!(versions(&r, "g:x"), ["1"]);
    }

    #[test]
    fn a_siblings_implementation_stays_off_the_compile_classpath() {
        // mybatis-plus's generator compiles against springfox's spring 5.2.0: the 5.3.39 its
        // sibling declares in `implementation` is on its runtime classpath only. With `api`, the
        // sibling's version reaches the compile classpath too.
        let repo = Mem(BTreeMap::from([
            pom("fox", "1", &[("spring", "1")]),
            pom("spring", "1", &[]),
            pom("spring", "2", &[]),
        ]));
        for (configuration, expected) in [("implementation", vec!["1", "2"]), ("api", vec!["2"])] {
            let dir = tree(
                &format!("sibling-{configuration}"),
                &[
                    ("settings.gradle", "include 'lib', 'app'\n"),
                    (
                        "lib/build.gradle",
                        &format!("dependencies {{\n    {configuration} 'g:spring:2'\n}}\n"),
                    ),
                    (
                        "app/build.gradle",
                        "dependencies {\n    implementation project(':lib')\n\
                         \x20   implementation 'g:fox:1'\n}\n",
                    ),
                ],
            );
            let r = resolve_gradle(&dir, &repo);
            let spring: Vec<_> = r
                .packages
                .iter()
                .filter(|p| p.name == "g:spring")
                .map(|p| (p.version.as_str(), p.dev))
                .collect();
            let want: Vec<_> = expected.iter().map(|v| (*v, *v == "1")).collect();
            assert_eq!(spring, want, "{configuration}: {:?}", r.missing);
        }
    }

    #[test]
    fn test_and_processor_platforms_manage_their_own_paths() {
        // reposilite: a root `testImplementation(platform(jackson-bom))` and the backend's
        // `kapt(platform(...))` leave the main classpath's Jackson to conflict resolution.
        let bom = (
            "g:bom:1".to_string(),
            "<project><groupId>g</groupId><artifactId>bom</artifactId><version>1</version>\
             <packaging>pom</packaging><dependencyManagement><dependencies>\
             <dependency><groupId>g</groupId><artifactId>a</artifactId><version>2</version></dependency>\
             </dependencies></dependencyManagement></project>"
                .to_string(),
        );
        let repo = Mem(BTreeMap::from([
            bom,
            pom("a", "1", &[]),
            pom("a", "2", &[]),
        ]));
        for (configuration, expected) in [
            ("testImplementation", vec![("1", false), ("2", true)]),
            ("kapt", vec![("1", false)]),
            ("implementation", vec![("2", false)]),
        ] {
            let dir = tree(
                &format!("platform-{configuration}"),
                &[(
                    "build.gradle",
                    &format!(
                        "dependencies {{\n    implementation 'g:a:1'\n\
                         \x20   {configuration} platform('g:bom:1')\n}}\n"
                    ),
                )],
            );
            let r = resolve_gradle(&dir, &repo);
            let a: Vec<_> = r
                .packages
                .iter()
                .filter(|p| p.name == "g:a")
                .map(|p| (p.version.as_str(), p.dev))
                .collect();
            assert_eq!(a, expected, "{configuration}: {:?}", r.missing);
        }
    }

    #[test]
    fn compile_only_on_a_project_takes_its_api_only() {
        // reposilite's plugins compile against `compileOnly(project(":reposilite-backend"))`:
        // the backend's `implementation` dependencies are on no plugin classpath.
        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[]),
            pom("a", "2", &[]),
            pom("b", "1", &[]),
        ]));
        let dir = tree(
            "compile-only-project",
            &[
                ("settings.gradle", "include 'lib', 'app'\n"),
                (
                    "lib/build.gradle",
                    "dependencies {\n    implementation 'g:a:2'\n    api 'g:b:1'\n}\n",
                ),
                (
                    "app/build.gradle",
                    "dependencies {\n    compileOnly project(':lib')\n\
                     \x20   implementation 'g:a:1'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:a"), ["1", "2"], "{:?}", r.missing);
        assert_eq!(versions(&r, "g:b"), ["1"]);
    }

    #[test]
    fn the_stdlib_property_turns_kotlins_library_off() {
        let repo = Mem(BTreeMap::new());
        for (flag, listed) in [("false", false), ("true", true)] {
            let dir = tree(
                &format!("stdlib-{flag}"),
                &[
                    (
                        "gradle.properties",
                        &format!("kotlin.stdlib.default.dependency={flag}\n"),
                    ),
                    (
                        "build.gradle.kts",
                        "plugins {\n    kotlin(\"jvm\") version \"2.0.0\"\n}\n\
                         dependencies {\n    implementation(\"g:a:1\")\n}\n",
                    ),
                ],
            );
            let r = resolve_gradle(&dir, &repo);
            let stdlib = r
                .missing
                .iter()
                .chain(r.packages.iter().map(|p| &p.name))
                .any(|m| m.contains("kotlin-stdlib"));
            assert_eq!(stdlib, listed, "{flag}: {:?}", r.missing);
        }
    }

    #[test]
    fn spring_property_overrides_need_the_dependency_management_plugin() {
        // halo's `thymeleaf.version` in gradle.properties moves the BOM's version in
        // `:application`, which applies the plugin, and not in `:api`, which imports the BOM
        // with Gradle's own `platform(...)`. dgs applies the plugin as `apply { plugin(...) }`;
        // jib names its BOM through an `ext` map.
        let bom = (
            "g:bom:1".to_string(),
            "<project><groupId>g</groupId><artifactId>bom</artifactId><version>1</version>\
             <packaging>pom</packaging><properties><a.version>2</a.version></properties>\
             <dependencyManagement><dependencies>\
             <dependency><groupId>g</groupId><artifactId>a</artifactId><version>${a.version}</version></dependency>\
             </dependencies></dependencyManagement></project>"
                .to_string(),
        );
        let repo = Mem(BTreeMap::from([
            bom,
            pom("a", "2", &[]),
            pom("a", "3", &[]),
        ]));
        let dm = "dependencyManagement {\n    imports {\n        mavenBom 'g:bom:1'\n    }\n}\n\
                  dependencies {\n    implementation 'g:a'\n}\n";
        let native = "dependencies {\n    implementation(platform(dependencyStrings.BOM))\n\
                      \x20   implementation 'g:a'\n}\n";
        for (file, text, expected) in [
            (
                "build.gradle",
                format!("plugins {{\n    id 'io.spring.dependency-management'\n}}\n{dm}"),
                "3",
            ),
            (
                "build.gradle",
                format!("apply {{\n    plugin(\"io.spring.dependency-management\")\n}}\n{dm}"),
                "3",
            ),
            ("build.gradle", native.to_string(), "2"),
        ] {
            let dir = tree(
                &format!("dm-overrides-{expected}-{}", text.len()),
                &[
                    ("gradle.properties", "a.version=3\n"),
                    ("settings.gradle", "include 'app', 'other'\n"),
                    (
                        "build.gradle",
                        "plugins {\n    id 'io.spring.dependency-management' version '1' apply false\n}\n\
                         project.ext.dependencyStrings = [\n  BOM: 'g:bom:1',\n]\n",
                    ),
                    (
                        "other/build.gradle",
                        "plugins {\n    id 'io.spring.dependency-management'\n}\n",
                    ),
                    (&format!("app/{file}"), &text),
                ],
            );
            let r = resolve_gradle(&dir, &repo);
            assert_eq!(versions(&r, "g:a"), [expected], "{text}: {:?}", r.missing);
        }
    }

    fn raw(g: &str, a: &str, v: &str, managed: &str) -> (String, String) {
        (
            format!("{g}:{a}:{v}"),
            format!(
                "<project><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version>\
                 <dependencyManagement><dependencies>{managed}</dependencies></dependencyManagement>\
                 </project>"
            ),
        )
    }

    #[test]
    fn a_catalog_aliased_dependency_management_plugin_and_boots_launcher() {
        // interview-guide applies the plugin as `alias(libs.plugins...)`, so the build's own
        // jakarta.annotation-api 2.1.1 wins over Boot's 3.0.0; Boot 3.5+ adds the JUnit
        // Platform launcher to the tests (komga, petclinic).
        let managed = "<dependency><groupId>g</groupId><artifactId>a</artifactId><version>3</version></dependency>\
                       <dependency><groupId>org.junit.platform</groupId><artifactId>junit-platform-launcher</artifactId><version>1.12.0</version></dependency>";
        let repo = Mem(BTreeMap::from([
            raw(
                "org.springframework.boot",
                "spring-boot-dependencies",
                "3.5.0",
                managed,
            ),
            raw(
                "org.junit.platform",
                "junit-platform-launcher",
                "1.12.0",
                "",
            ),
            pom("a", "2", &[]),
            pom("a", "3", &[]),
        ]));
        let dir = tree(
            "dm-alias",
            &[
                (
                    "gradle/libs.versions.toml",
                    "[plugins]\nboot = { id = \"org.springframework.boot\", version = \"3.5.0\" }\n\
                     dm = { id = \"io.spring.dependency-management\", version = \"1.1.7\" }\n",
                ),
                (
                    "build.gradle",
                    "plugins {\n    alias(libs.plugins.boot)\n    alias(libs.plugins.dm)\n}\n\
                     dependencies {\n    implementation 'g:a:2'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:a"), ["2"], "{:?}", r.missing);
        assert_eq!(
            versions(&r, "org.junit.platform:junit-platform-launcher"),
            ["1.12.0"]
        );
    }

    #[test]
    fn kotlin_dsl_brings_the_running_gradles_kotlin() {
        let repo = Mem(BTreeMap::from([
            raw("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.10", ""),
            raw("org.jetbrains.kotlin", "kotlin-reflect", "2.4.10", ""),
            raw("org.jetbrains.kotlin", "kotlin-stdlib-jdk8", "1.7.10", ""),
            raw("org.jetbrains.kotlin", "kotlin-reflect", "1.7.10", ""),
        ]));
        for (gradle, expected) in [
            (
                "9.8.2",
                vec![
                    "org.jetbrains.kotlin:kotlin-reflect@2.4.10",
                    "org.jetbrains.kotlin:kotlin-stdlib@2.4.10",
                ],
            ),
            (
                "7.6.3",
                vec![
                    "org.jetbrains.kotlin:kotlin-reflect@1.7.10",
                    "org.jetbrains.kotlin:kotlin-stdlib-jdk8@1.7.10",
                ],
            ),
            ("10.1", vec![]),
        ] {
            let dir = tree(
                &format!("kotlin-dsl-{gradle}"),
                &[
                    (
                        "gradle/wrapper/gradle-wrapper.properties",
                        &format!("distributionUrl=https\\://services.gradle.org/distributions/gradle-{gradle}-bin.zip\n"),
                    ),
                    ("build.gradle.kts", "plugins {\n    `kotlin-dsl`\n}\n"),
                ],
            );
            let r = resolve_gradle(&dir, &repo);
            let got: Vec<String> = r
                .packages
                .iter()
                .map(|p| format!("{}@{}", p.name, p.version))
                .collect();
            assert_eq!(got, expected, "{gradle}: {:?}", r.missing);
        }
    }

    #[test]
    fn the_kotlin_plugin_versions_its_own_unversioned_libraries() {
        // spring-integration-samples: `api "org.jetbrains.kotlin:kotlin-reflect"` with no
        // version, under the dependency-management plugin, takes the Kotlin plugin's 2.4.21.
        let kotlin = |a: &str| {
            (
                format!("org.jetbrains.kotlin:{a}:2.4.21"),
                format!("<project><groupId>org.jetbrains.kotlin</groupId><artifactId>{a}</artifactId><version>2.4.21</version></project>"),
            )
        };
        let repo = Mem(BTreeMap::from([
            kotlin("kotlin-stdlib"),
            kotlin("kotlin-reflect"),
        ]));
        let dir = tree(
            "kotlin-unversioned",
            &[
                ("settings.gradle", "include 'app'\n"),
                (
                    "build.gradle",
                    "buildscript {\n  ext {\n    kotlinVersion = '2.4.21'\n  }\n  dependencies {\n\
                     \x20   classpath \"org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlinVersion\"\n  }\n}\n\
                     subprojects {\n  apply plugin: 'java-library'\n  apply plugin: 'io.spring.dependency-management'\n}\n",
                ),
                (
                    "app/build.gradle",
                    "apply plugin: 'kotlin'\n\
                     dependencies {\n  api \"org.jetbrains.kotlin:kotlin-reflect\"\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(
            versions(&r, "org.jetbrains.kotlin:kotlin-reflect"),
            ["2.4.21"],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn the_settings_plugin_management_versions_a_bare_plugin() {
        // Charlatano: settings.gradle.kts' `pluginManagement { plugins { kotlin("jvm") version
        // "1.8.0" } }` versions the bare `kotlin("jvm")` a build applies, and Kotlin 1.8.0 adds
        // `kotlin-stdlib-jdk8` as its standard library, as real Gradle showed.
        let kotlin = |a: &str| {
            (
                format!("org.jetbrains.kotlin:{a}:1.8.0"),
                format!("<project><groupId>org.jetbrains.kotlin</groupId><artifactId>{a}</artifactId><version>1.8.0</version></project>"),
            )
        };
        let repo = Mem(BTreeMap::from([
            kotlin("kotlin-stdlib-jdk8"),
            kotlin("kotlin-reflect"),
        ]));
        let dir = tree(
            "kotlin-settings-plugins",
            &[
                (
                    "settings.gradle.kts",
                    "pluginManagement {\n  plugins {\n    kotlin(\"jvm\") version \"1.8.0\"\n  }\n}\n",
                ),
                (
                    "build.gradle.kts",
                    "plugins {\n  kotlin(\"jvm\")\n}\n\
                     dependencies {\n  implementation(kotlin(\"reflect\"))\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        for name in ["kotlin-reflect", "kotlin-stdlib-jdk8"] {
            assert_eq!(
                versions(&r, &format!("org.jetbrains.kotlin:{name}")),
                ["1.8.0"],
                "{name} {:?}",
                r.missing
            );
        }
    }

    #[test]
    fn an_untested_kotlin_plugin_version_reports_its_standard_library() {
        // Between 1.8.0 and 1.9.23 real Gradle was never seen, so which library the plugin adds
        // is reported rather than guessed.
        let mut c = context("", &[]);
        c.plugins
            .insert(KOTLIN_JVM.to_string(), "1.8.20".to_string());
        let m = read_script("plugins {\n  kotlin(\"jvm\")\n}\n", &mut c);
        assert!(
            m.unread.iter().any(|u| u.contains("standard library")),
            "{:?}",
            m.unread
        );
        assert!(m
            .deps
            .iter()
            .all(|d| d.coordinate.artifact != "kotlin-stdlib"));
    }

    #[test]
    fn build_logics_dependencies_version_the_plugins_it_applies() {
        // spring-framework: buildSrc's `implementation "...kotlin-gradle-plugin:${kotlinVersion}"`
        // puts Kotlin 2.4.21 on the build's classpath; `apply plugin: "kotlin"` then gives the
        // unversioned `kotlin-reflect` that version.
        let repo = Mem(BTreeMap::from([(
            "org.jetbrains.kotlin:kotlin-reflect:2.4.21".to_string(),
            "<project><groupId>org.jetbrains.kotlin</groupId><artifactId>kotlin-reflect</artifactId><version>2.4.21</version></project>".to_string(),
        )]));
        let dir = tree(
            "build-logic-classpath",
            &[
                ("settings.gradle", "include 'core'\n"),
                ("gradle.properties", "kotlinVersion=2.4.21\nkotlin.stdlib.default.dependency=false\n"),
                (
                    "buildSrc/build.gradle",
                    "dependencies {\n    implementation \"org.jetbrains.kotlin:kotlin-gradle-plugin:${kotlinVersion}\"\n}\n",
                ),
                (
                    "core/build.gradle",
                    "apply plugin: \"kotlin\"\ndependencies {\n    api(\"org.jetbrains.kotlin:kotlin-reflect\")\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(
            versions(&r, "org.jetbrains.kotlin:kotlin-reflect"),
            ["2.4.21"],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn build_logic_names_its_local_configurations() {
        // Spring Framework's OptionalDependenciesPlugin, through a constant; Spring Boot's
        // creates "optional" by its literal name.
        let framework = r#"public class OptionalDependenciesPlugin implements Plugin<Project> {
	public static final String OPTIONAL_CONFIGURATION_NAME = "optional";
	public void apply(Project project) {
		Configuration optional = project.getConfigurations().create(OPTIONAL_CONFIGURATION_NAME);
		optional.setCanBeConsumed(false);
		sourceSets.all((sourceSet) -> {
			project.getConfigurations().getByName(sourceSet.getCompileClasspathConfigurationName()).extendsFrom(optional);
			project.getConfigurations().getByName(sourceSet.getRuntimeClasspathConfigurationName()).extendsFrom(optional);
		});
	}
}"#;
        assert_eq!(local_configuration(framework).as_deref(), Some("optional"));
        let boot = framework.replace(
            ".create(OPTIONAL_CONFIGURATION_NAME)",
            ".create(\"optional\")",
        );
        assert_eq!(local_configuration(&boot).as_deref(), Some("optional"));
        // Handed to consumers too, or on one classpath only: not local.
        let consumed = format!("{framework}\nconfigurations.apiElements.extendsFrom(optional)");
        assert_eq!(local_configuration(&consumed), None);
        let compile_only = framework.replace("getRuntimeClasspathConfigurationName", "x");
        assert_eq!(local_configuration(&compile_only), None);
    }

    #[test]
    fn a_local_configuration_stays_off_consumers() {
        // Spring Framework: `optional("g:x:2")` in :lib is on lib's main compile and runtime
        // classpaths (x 2 over the 1 lib's own dependency brings), and not on :app's.
        let plugin = "public class OptionalDependenciesPlugin {\n\
             \tpublic void apply(Project project) {\n\
             \t\tConfiguration optional = project.getConfigurations().create(\"optional\");\n\
             \t\tsourceSets.all((s) -> {\n\
             \t\t\tproject.getConfigurations().getByName(s.getCompileClasspathConfigurationName()).extendsFrom(optional);\n\
             \t\t\tproject.getConfigurations().getByName(s.getRuntimeClasspathConfigurationName()).extendsFrom(optional);\n\
             \t\t});\n\t}\n}\n";
        let repo = Mem(BTreeMap::from([
            pom("y", "1", &[("x", "1")]),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
            pom("w", "1", &[]),
        ]));
        let files = |optional: &str| {
            vec![
                ("settings.gradle", "include 'lib', 'app'\n".to_string()),
                (
                    "buildSrc/src/main/java/org/example/build/optional/OptionalDependenciesPlugin.java",
                    plugin.to_string(),
                ),
                (
                    "lib/build.gradle",
                    format!("dependencies {{\n    api 'g:y:1'\n    {optional}('g:x:2')\n}}\n"),
                ),
                (
                    "app/build.gradle",
                    "dependencies {\n    implementation project(':lib')\n    implementation 'g:w:1'\n}\n"
                        .to_string(),
                ),
            ]
        };
        let run = |tag: &str, optional: &str| {
            let owned = files(optional);
            let refs: Vec<(&str, &str)> = owned.iter().map(|(f, t)| (*f, t.as_str())).collect();
            let r = resolve_gradle(&tree(tag, &refs), &repo);
            let x: Vec<_> = r
                .packages
                .iter()
                .filter(|p| p.name == "g:x")
                .map(|p| (p.version.clone(), p.dev))
                .collect();
            (x, r.missing)
        };
        // lib's main classpaths hold x 2 (read as a test configuration, it would be dev only);
        // app's hold y's x 1.
        let (x, missing) = run("local-configuration", "optional");
        assert_eq!(
            x,
            [("1".to_string(), false), ("2".to_string(), false)],
            "{missing:?}"
        );
    }

    #[test]
    fn kotlin_test_brings_the_test_frameworks_variant() {
        // moshi: the Kotlin plugin on the buildscript classpath at
        // `System.getenv(...) ?: libs.versions.kotlin.get()`, JUnit 4 by default; grpc-spring's
        // root `useJUnitPlatform()` makes it JUnit 5.
        let kotlin = |a: &str| {
            (
                format!("org.jetbrains.kotlin:{a}:2.0.0"),
                format!("<project><groupId>org.jetbrains.kotlin</groupId><artifactId>{a}</artifactId><version>2.0.0</version></project>"),
            )
        };
        let repo = Mem(BTreeMap::from([
            kotlin("kotlin-stdlib"),
            kotlin("kotlin-test"),
            kotlin("kotlin-test-junit"),
            kotlin("kotlin-test-junit5"),
        ]));
        let variants = |root_extra: &str| {
            let root = format!(
                "buildscript {{\n  dependencies {{\n\
                 \x20   val kotlinVersion = System.getenv(\"K\") ?: libs.versions.kotlin.get()\n\
                 \x20   classpath(kotlin(\"gradle-plugin\", version = kotlinVersion))\n  }}\n}}\n{root_extra}"
            );
            let r = resolve_gradle(
                &tree(
                    "kotlin-test",
                    &[
                        ("settings.gradle.kts", "include(\":app\")\n"),
                        (
                            "gradle/libs.versions.toml",
                            "[versions]\nkotlin = \"2.0.0\"\n",
                        ),
                        ("build.gradle.kts", root.as_str()),
                        (
                            "app/build.gradle.kts",
                            "plugins {\n  kotlin(\"jvm\")\n}\n\
                             dependencies {\n  testImplementation(kotlin(\"test\"))\n}\n",
                        ),
                    ],
                ),
                &repo,
            );
            let found: BTreeSet<String> = r
                .packages
                .iter()
                .filter(|p| p.name.starts_with("org.jetbrains.kotlin:kotlin-test"))
                .map(|p| format!("{}:{}", p.name, p.version))
                .collect();
            (found, r.missing)
        };
        let (found, missing) = variants("");
        assert_eq!(
            found,
            BTreeSet::from([
                "org.jetbrains.kotlin:kotlin-test:2.0.0".to_string(),
                "org.jetbrains.kotlin:kotlin-test-junit:2.0.0".to_string(),
            ]),
            "{missing:?}"
        );
        let (found, missing) = variants("subprojects {\n  tasks.test { useJUnitPlatform() }\n}\n");
        assert_eq!(
            found,
            BTreeSet::from([
                "org.jetbrains.kotlin:kotlin-test:2.0.0".to_string(),
                "org.jetbrains.kotlin:kotlin-test-junit5:2.0.0".to_string(),
            ]),
            "{missing:?}"
        );
    }

    #[test]
    fn a_range_takes_the_versions_gradles_cache_holds() {
        // spring-integration-samples: smack-core asks for jxmpp `[1.0.0, 1.0.999]`; Gradle's
        // cache keeps no maven-metadata.xml, only a folder per version it holds.
        let pom = |a: &str, v: &str, deps: &str| {
            format!("<project><groupId>g</groupId><artifactId>{a}</artifactId><version>{v}</version><dependencies>{deps}</dependencies></project>")
        };
        let cache = tree(
            "gradle-cache-listing",
            &[
                (
                    "g/smack/1/h1/smack-1.pom",
                    &pom("smack", "1", "<dependency><groupId>g</groupId><artifactId>jxmpp</artifactId><version>[1.0.0, 1.0.999]</version></dependency>"),
                ),
                ("g/jxmpp/1.0.1/h2/jxmpp-1.0.1.pom", &pom("jxmpp", "1.0.1", "")),
                ("g/jxmpp/1.0.3/h3/jxmpp-1.0.3.pom", &pom("jxmpp", "1.0.3", "")),
                ("g/jxmpp/2.0.0/h4/jxmpp-2.0.0.pom", &pom("jxmpp", "2.0.0", "")),
                // A version folder with only a jar is not a version the cache can resolve.
                ("g/jxmpp/1.0.9/h5/jxmpp-1.0.9.jar", ""),
            ],
        );
        let source = crate::resolve::LocalRepositories {
            roots: Vec::new(),
            gradle_roots: vec![cache],
        };
        let listing = source.metadata("g", "jxmpp").unwrap_or_default();
        assert!(listing.contains("<version>1.0.3</version>"), "{listing}");
        assert!(!listing.contains("1.0.9"), "{listing}");
        let dir = tree(
            "gradle-range",
            &[(
                "build.gradle",
                "dependencies {\n    implementation 'g:smack:1'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &source);
        assert_eq!(versions(&r, "g:jxmpp"), ["1.0.3"], "{:?}", r.missing);
    }

    #[test]
    fn a_prefix_version_takes_the_highest_listed_match() {
        // Hystrix's `javassist:3.19+` is 3.19.0-GA: the highest listed version that starts
        // with `3.19`, not 3.20.0-GA.
        let pom = |v: &str| {
            format!("<project><groupId>g</groupId><artifactId>j</artifactId><version>{v}</version></project>")
        };
        let cache = tree(
            "gradle-cache-prefix",
            &[
                ("g/j/3.18.2-GA/h1/j-3.18.2-GA.pom", &pom("3.18.2-GA")),
                ("g/j/3.19.0-GA/h2/j-3.19.0-GA.pom", &pom("3.19.0-GA")),
                ("g/j/3.20.0-GA/h3/j-3.20.0-GA.pom", &pom("3.20.0-GA")),
            ],
        );
        let source = crate::resolve::LocalRepositories {
            roots: Vec::new(),
            gradle_roots: vec![cache],
        };
        for (declared, want) in [
            ("3.19+", "3.19.0-GA"),
            ("3.+", "3.20.0-GA"),
            ("+", "3.20.0-GA"),
        ] {
            let dir = tree(
                &format!("gradle-prefix-{}", declared.replace('+', "p")),
                &[(
                    "build.gradle",
                    &format!("dependencies {{\n    api 'g:j:{declared}'\n}}\n"),
                )],
            );
            let r = resolve_gradle(&dir, &source);
            assert_eq!(versions(&r, "g:j"), [want], "{declared}: {:?}", r.missing);
        }
        // pygradle: `junit:4.+` is settled before conflict resolution, so it beats the 3.18.2-GA a
        // dependency asks for.
        let spock = "<project><groupId>g</groupId><artifactId>s</artifactId><version>1</version>\
                     <dependencies><dependency><groupId>g</groupId><artifactId>j</artifactId>\
                     <version>3.18.2-GA</version></dependency></dependencies></project>";
        let with_spock = tree("gradle-cache-prefix-spock", &[("g/s/1/h4/s-1.pom", spock)]);
        let both = crate::resolve::LocalRepositories {
            roots: Vec::new(),
            gradle_roots: vec![source.gradle_roots[0].clone(), with_spock],
        };
        let dir = tree(
            "gradle-prefix-conflict",
            &[(
                "build.gradle",
                "dependencies {\n    api 'g:j:3.+'\n    api 'g:s:1'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &both);
        assert_eq!(versions(&r, "g:j"), ["3.20.0-GA"], "{:?}", r.missing);
        let dir = tree(
            "gradle-prefix-none",
            &[("build.gradle", "dependencies {\n    api 'g:j:4.+'\n}\n")],
        );
        let r = resolve_gradle(&dir, &source);
        assert!(versions(&r, "g:j").is_empty());
        assert!(
            r.missing
                .iter()
                .any(|m| m.contains("g:j: no published version matches 4.+")),
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn a_range_is_settled_in_gradles_version_order() {
        // ehcache 3.10.8 asks for jaxb-runtime `[2.2,3)`: Gradle orders 3.0.0-M5 above 3, so
        // it takes 2.4.0-b180830.0438, where Maven's order would let 3.0.0-M5 in.
        let pom = |v: &str| {
            format!("<project><groupId>g</groupId><artifactId>jaxb</artifactId><version>{v}</version></project>")
        };
        let cache = tree(
            "gradle-cache-order",
            &[
                (
                    "g/eh/1/h0/eh-1.pom",
                    "<project><groupId>g</groupId><artifactId>eh</artifactId><version>1</version><dependencies><dependency><groupId>g</groupId><artifactId>jaxb</artifactId><version>[2.2,3)</version></dependency></dependencies></project>",
                ),
                ("g/jaxb/2.3.9/h1/jaxb-2.3.9.pom", &pom("2.3.9")),
                (
                    "g/jaxb/2.4.0-b180830.0438/h2/jaxb-2.4.0-b180830.0438.pom",
                    &pom("2.4.0-b180830.0438"),
                ),
                ("g/jaxb/3.0.0-M5/h3/jaxb-3.0.0-M5.pom", &pom("3.0.0-M5")),
                ("g/jaxb/3.0.2/h4/jaxb-3.0.2.pom", &pom("3.0.2")),
            ],
        );
        let source = crate::resolve::LocalRepositories {
            roots: Vec::new(),
            gradle_roots: vec![cache],
        };
        let dir = tree(
            "gradle-order-range",
            &[(
                "build.gradle",
                "dependencies {\n    implementation 'g:eh:1'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &source);
        assert_eq!(
            versions(&r, "g:jaxb"),
            ["2.4.0-b180830.0438"],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn an_optional_dependency_leaves_an_inherited_one_alone() {
        // netty-common 4.1.3 lists javassist 3.20.0-GA as optional and inherits it from
        // netty-parent at test scope: neither is on a classpath, so powermock's 3.18.2-GA holds.
        let parent = (
            "g:parent:1".to_string(),
            "<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>\
             <packaging>pom</packaging><dependencies><dependency><groupId>g</groupId>\
             <artifactId>j</artifactId><version>3.20.0-GA</version><scope>test</scope>\
             </dependency></dependencies></project>"
                .to_string(),
        );
        let common = (
            "g:common:1".to_string(),
            "<project><parent><groupId>g</groupId><artifactId>parent</artifactId>\
             <version>1</version></parent><artifactId>common</artifactId><dependencies>\
             <dependency><groupId>g</groupId><artifactId>j</artifactId>\
             <version>3.20.0-GA</version><optional>true</optional></dependency>\
             </dependencies></project>"
                .to_string(),
        );
        let repo = Mem(BTreeMap::from([
            parent,
            common,
            pom("powermock", "1", &[("j", "3.18.2-GA")]),
            pom("j", "3.18.2-GA", &[]),
            pom("j", "3.20.0-GA", &[]),
        ]));
        let dir = tree(
            "optional-inherited",
            &[(
                "build.gradle",
                "dependencies {\n    implementation 'g:common:1'\n\
                 \x20   testImplementation 'g:powermock:1'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:j"), ["3.18.2-GA"], "{:?}", r.missing);
    }

    #[test]
    fn the_dependency_management_plugin_manages_declared_versions() {
        // conductor: no BOM manages jna, yet `testImplementation jna:5.7.0` wins over
        // Elasticsearch's 5.10.0 on the test classpaths, which hold the declaration; the main
        // classpath keeps 5.10.0. Without the plugin, Gradle takes the higher.
        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[("x", "2")]),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
        ]));
        let x = |plugins: &str| {
            let r = resolve_gradle(
                &tree(
                    "declared-managed",
                    &[(
                        "build.gradle",
                        format!(
                            "{plugins}dependencies {{\n    implementation 'g:a:1'\n\
                             \x20   testImplementation 'g:x:1'\n}}\n"
                        )
                        .as_str(),
                    )],
                ),
                &repo,
            );
            r.packages
                .iter()
                .filter(|p| p.name == "g:x")
                .map(|p| (p.version.clone(), p.dev))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            x("plugins {\n    id 'io.spring.dependency-management' version '1.1.6'\n}\n"),
            [("1".to_string(), true), ("2".to_string(), false)]
        );
        assert_eq!(x(""), [("2".to_string(), false)]);
    }

    #[test]
    fn a_dependency_stays_out_only_when_every_path_excludes_it() {
        // isolating-the-domain: thymeleaf-spring5 excludes ognl from thymeleaf,
        // thymeleaf-extras-java8time does not, and Gradle keeps ognl. Excluded on both
        // paths, y stays out.
        let with = |a: &str, deps: &str| {
            (
                format!("g:{a}:1"),
                format!("<project><groupId>g</groupId><artifactId>{a}</artifactId><version>1</version><dependencies>{deps}</dependencies></project>"),
            )
        };
        let common = "<dependency><groupId>g</groupId><artifactId>common</artifactId><version>1</version><exclusions>";
        let repo = Mem(BTreeMap::from([
            with(
                "spring",
                &format!("{common}<exclusion><groupId>g</groupId><artifactId>x</artifactId></exclusion><exclusion><groupId>g</groupId><artifactId>y</artifactId></exclusion></exclusions></dependency>"),
            ),
            with(
                "extras",
                &format!("{common}<exclusion><groupId>g</groupId><artifactId>y</artifactId></exclusion></exclusions></dependency>"),
            ),
            with(
                "common",
                "<dependency><groupId>g</groupId><artifactId>x</artifactId><version>1</version></dependency>\
                 <dependency><groupId>g</groupId><artifactId>y</artifactId><version>1</version></dependency>",
            ),
            pom("x", "1", &[]),
            pom("y", "1", &[]),
        ]));
        let dir = tree(
            "all-paths-exclusion",
            &[(
                "build.gradle",
                "dependencies {\n    implementation 'g:spring:1'\n    implementation 'g:extras:1'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:x"), ["1"], "{:?}", r.missing);
        assert!(versions(&r, "g:y").is_empty(), "{:?}", r.packages);
    }

    #[test]
    fn java_version_checks_take_a_modern_jdk() {
        let vars = BTreeMap::new();
        for (c, want) in [
            ("JavaVersion.current().isJava9Compatible()", Some(true)),
            ("JavaVersion.current().java8Compatible", Some(true)),
            (
                "JavaVersion.current().isCompatibleWith(JavaVersion.VERSION_1_9)",
                Some(true),
            ),
            (
                "JavaVersion.current().isCompatibleWith(JavaVersion.VERSION_17)",
                Some(true),
            ),
            (
                "JavaVersion.current().isCompatibleWith(JavaVersion.VERSION_21)",
                None,
            ),
            ("!JavaVersion.current().isJava11Compatible()", Some(false)),
            ("JavaVersion.current().isJava21Compatible()", None),
        ] {
            assert_eq!(condition(c, &vars), want, "{c}");
        }
        // grpc-spring's `@javax.annotation.Generated` workaround.
        let repo = Mem(BTreeMap::from([pom("a", "1", &[]), pom("b", "1", &[])]));
        let dir = tree(
            "java-version",
            &[(
                "build.gradle",
                "dependencies {\n    implementation 'g:b:1'\n\
                 \x20   if (JavaVersion.current().isJava9Compatible()) {\n\
                 \x20       compileOnly 'g:a:1'\n    }\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:a"), ["1"], "{:?}", r.missing);
    }

    #[test]
    fn gretty_adds_its_containers_servlet_apis() {
        // Hystrix: Gretty 3.0.5 with `servletContainer = 'jetty9'`; spring-integration-samples:
        // Gretty 4.1.10 on its default container. Another pairing is reported.
        let jar = |g: &str, a: &str, v: &str| {
            (
                format!("{g}:{a}:{v}"),
                format!("<project><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version></project>"),
            )
        };
        let repo = Mem(BTreeMap::from([
            jar("javax.servlet", "javax.servlet-api", "3.1.0"),
            jar("javax.websocket", "javax.websocket-api", "1.0"),
            jar("jakarta.servlet", "jakarta.servlet-api", "5.0.0"),
            jar("jakarta.websocket", "jakarta.websocket-api", "2.0.0"),
        ]));
        let gretty = |version: &str, block: &str| {
            let script = format!(
                "buildscript {{\n  dependencies {{\n    classpath 'org.gretty:gretty:{version}'\n  }}\n}}\n\
                 apply plugin: 'war'\napply plugin: 'org.gretty'\n{block}"
            );
            let r = resolve_gradle(
                &tree(
                    &format!("gretty-{version}"),
                    &[("build.gradle", script.as_str())],
                ),
                &repo,
            );
            let found: Vec<String> = r
                .packages
                .iter()
                .map(|p| format!("{}:{}", p.name, p.version))
                .collect();
            (found, r.missing)
        };
        let (found, missing) = gretty("3.0.5", "gretty {\n  servletContainer = 'jetty9'\n}\n");
        assert_eq!(
            found,
            [
                "javax.servlet:javax.servlet-api:3.1.0",
                "javax.websocket:javax.websocket-api:1.0"
            ],
            "{missing:?}"
        );
        let (found, missing) = gretty("4.1.10", "");
        assert_eq!(
            found,
            [
                "jakarta.servlet:jakarta.servlet-api:5.0.0",
                "jakarta.websocket:jakarta.websocket-api:2.0.0"
            ],
            "{missing:?}"
        );
        let (found, missing) = gretty("4.1.10", "gretty {\n  servletContainer = 'tomcat10'\n}\n");
        assert!(found.is_empty(), "{found:?}");
        assert!(
            missing.iter().any(|m| m
                .contains("org.gretty 4.1.10 (tomcat10): the servlet APIs it adds are not known")),
            "{missing:?}"
        );
    }

    #[test]
    fn the_freefair_plugin_adds_its_lombok() {
        // grpc-spring: plugin 8.6 through a buildscript `ext` variable, applied in
        // `allprojects`; mybatis-plus sets the version in the extension; a release whose
        // default is not known is reported, not guessed.
        let repo = Mem(BTreeMap::from([
            (
                "org.projectlombok:lombok:1.18.30".to_string(),
                "<project><groupId>org.projectlombok</groupId><artifactId>lombok</artifactId><version>1.18.30</version></project>".to_string(),
            ),
            (
                "org.projectlombok:lombok:1.18.48".to_string(),
                "<project><groupId>org.projectlombok</groupId><artifactId>lombok</artifactId><version>1.18.48</version></project>".to_string(),
            ),
            pom("a", "1", &[]),
        ]));
        let lombok = |files: &[(&str, &str)]| {
            let r = resolve_gradle(&tree("freefair", files), &repo);
            let versions: BTreeSet<(String, bool)> = r
                .packages
                .iter()
                .filter(|p| p.name == "org.projectlombok:lombok")
                .map(|p| (p.version.clone(), p.dev))
                .collect();
            (versions, r.missing)
        };
        let (found, missing) = lombok(&[
            ("settings.gradle", "include 'app'\n"),
            (
                "build.gradle",
                "buildscript {\n    ext {\n        lombokPluginVersion = '8.6'\n    }\n}\n\
                 plugins {\n    id 'io.freefair.lombok' version \"${lombokPluginVersion}\" apply false\n}\n\
                 allprojects {\n    apply plugin: 'io.freefair.lombok'\n}\n",
            ),
            ("app/build.gradle", "dependencies {\n    implementation 'g:a:1'\n}\n"),
        ]);
        assert_eq!(
            found,
            BTreeSet::from([("1.18.30".to_string(), true)]),
            "{missing:?}"
        );
        let (found, missing) = lombok(&[
            ("settings.gradle", ""),
            (
                "build.gradle",
                "buildscript {\n    dependencies {\n        classpath \"io.freefair.gradle:lombok-plugin:9.8.3\"\n    }\n}\n\
                 apply plugin: 'io.freefair.lombok'\nlombok {\n    version = \"1.18.48\"\n}\n\
                 dependencies {\n    implementation 'g:a:1'\n}\n",
            ),
        ]);
        assert_eq!(
            found,
            BTreeSet::from([("1.18.48".to_string(), true)]),
            "{missing:?}"
        );
        let (found, missing) = lombok(&[
            ("settings.gradle", ""),
            (
                "build.gradle",
                "plugins {\n    id 'io.freefair.lombok' version '6.6.1'\n}\n\
                 dependencies {\n    implementation 'g:a:1'\n}\n",
            ),
        ]);
        assert!(found.is_empty(), "{found:?}");
        assert!(
            missing
                .iter()
                .any(|m| m.contains("io.freefair.lombok 6.6.1")),
            "{missing:?}"
        );
    }

    #[test]
    fn a_runtime_path_down_the_tree_splits_the_compile_classpath() {
        // JavaPackager declares no runtime dependency: redline compiles against xz 1.4 and
        // plexus-archiver's `runtime` xz 1.9 raises it on the runtime classpath only.
        let runtime_child = (
            "g:a:1".to_string(),
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version><dependencies>\
             <dependency><groupId>g</groupId><artifactId>x</artifactId><version>2</version><scope>runtime</scope></dependency>\
             </dependencies></project>"
                .to_string(),
        );
        let repo = Mem(BTreeMap::from([
            runtime_child,
            pom("c", "1", &[("x", "1")]),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
        ]));
        let dir = tree(
            "runtime-down-the-tree",
            &[(
                "build.gradle",
                "dependencies {\n    implementation 'g:a:1'\n    implementation 'g:c:1'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        let of: Vec<(String, bool)> = r
            .packages
            .iter()
            .filter(|p| p.name == "g:x")
            .map(|p| (p.version.clone(), p.dev))
            .collect();
        assert_eq!(
            of,
            [("1".to_string(), true), ("2".to_string(), false)],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn the_test_compile_classpath_leaves_runtime_dependencies_out() {
        // komga: the launcher in `testRuntimeOnly` raises JUnit on the test runtime classpath
        // only; a POM's `runtime` dependency is on no compile classpath at any depth.
        let runtime_child = (
            "g:a:1".to_string(),
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version><dependencies>\
             <dependency><groupId>g</groupId><artifactId>b</artifactId><version>2</version><scope>runtime</scope></dependency>\
             </dependencies></project>"
                .to_string(),
        );
        let test_runtime_child = (
            "g:c:1".to_string(),
            "<project><groupId>g</groupId><artifactId>c</artifactId><version>1</version><dependencies>\
             <dependency><groupId>g</groupId><artifactId>t</artifactId><version>2</version><scope>runtime</scope></dependency>\
             </dependencies></project>"
                .to_string(),
        );
        let repo = Mem(BTreeMap::from([
            runtime_child,
            test_runtime_child,
            pom("b", "1", &[]),
            pom("b", "2", &[]),
            pom("t", "1", &[]),
            pom("t", "2", &[]),
            pom("r", "1", &[("t", "2")]),
            pom("z", "1", &[]),
        ]));
        let dir = tree(
            "test-compile",
            &[(
                "build.gradle",
                "dependencies {\n    implementation 'g:a:1'\n    implementation 'g:b:1'\n\
                 \x20   runtimeOnly 'g:z:1'\n    testImplementation 'g:t:1'\n\
                 \x20   testImplementation 'g:c:1'\n\
                 \x20   testRuntimeOnly 'g:r:1'\n}\n",
            )],
        );
        let r = resolve_gradle(&dir, &repo);
        let of = |name: &str| -> Vec<(String, bool)> {
            r.packages
                .iter()
                .filter(|p| p.name == name)
                .map(|p| (p.version.clone(), p.dev))
                .collect()
        };
        let want = |v: &[(&str, bool)]| -> Vec<(String, bool)> {
            v.iter().map(|(a, b)| ((*a).to_string(), *b)).collect()
        };
        assert_eq!(
            of("g:b"),
            want(&[("1", true), ("2", false)]),
            "{:?}",
            r.missing
        );
        assert_eq!(of("g:t"), want(&[("1", true), ("2", true)]));
    }

    #[test]
    fn convention_plugins_declare_for_the_projects_that_apply_them() {
        // CosId's `id("cosid.library")` applies `cosid.java`, whose dependencies come
        // from the catalog through a helper, inside `if (bootBom)` with the property unset; a
        // constraint on `checkstyle` manages nothing read. A convention nothing applies stays
        // build logic.
        let repo = Mem(BTreeMap::from([
            pom("j", "1", &[]),
            pom("h", "2", &[("a", "1")]),
            pom("a", "1", &[]),
            pom("a", "9", &[]),
            pom("u", "1", &[]),
        ]));
        let dir = tree(
            "conventions",
            &[
                (
                    "gradle/libs.versions.toml",
                    "[versions]\nh = \"2\"\n[libraries]\nj = { module = \"g:j\", version = \"1\" }\n",
                ),
                ("settings.gradle.kts", "include(\"core\")\n"),
                (
                    "build-logic/src/main/kotlin/my.library.gradle.kts",
                    "plugins {\n    id(\"my.java\")\n}\n",
                ),
                (
                    "build-logic/src/main/kotlin/my.java.gradle.kts",
                    "fun library(name: String) = libs.findLibrary(name).get()\n\
                     fun version(name: String) = libs.findVersion(name).get().requiredVersion\n\
                     val bootBom = findProperty(\"my.bootBom\")?.toString() != \"false\"\n\
                     dependencies {\n    if (bootBom) {\n        implementation(library(\"j\"))\n\
                     \x20       implementation(\"g:h:${version(\"h\")}\")\n    }\n\
                     \x20   constraints {\n        \"checkstyle\"(\"g:a:9\")\n    }\n}\n",
                ),
                (
                    "build-logic/src/main/kotlin/my.unused.gradle.kts",
                    "dependencies {\n    implementation(\"g:u:1\")\n}\n",
                ),
                (
                    "core/build.gradle.kts",
                    "plugins {\n    id(\"my.library\")\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let of = |name: &str| -> Vec<(String, bool)> {
            r.packages
                .iter()
                .filter(|p| p.name == name)
                .map(|p| (p.version.clone(), p.dev))
                .collect()
        };
        assert_eq!(of("g:j"), [("1".to_string(), false)], "{:?}", r.missing);
        assert_eq!(of("g:h"), [("2".to_string(), false)]);
        assert_eq!(of("g:a"), [("1".to_string(), false)]);
        assert_eq!(of("g:u"), [("1".to_string(), true)]);
    }

    #[test]
    fn forced_versions_win_conflict_resolution() {
        // pulsar's `resolutionStrategy { force(...) }`, conductor's test-only force, and the
        // kordamp enforcer's `ForceDependencies` rule in jreleaser's settings.
        let repo = Mem(BTreeMap::from([
            pom("a", "2", &[]),
            pom("a", "1", &[]),
            pom("t", "2", &[]),
            pom("t", "1", &[]),
            pom("k", "2", &[]),
            pom("k", "1", &[]),
        ]));
        let dir = tree(
            "forced",
            &[
                ("gradle.properties", "kVersion = 1\n"),
                (
                    "settings.gradle",
                    "enforce {\n    rule(enforcer.rules.ForceDependencies) { r ->\n\
                     \x20       r.dependencies.addAll \"g:k:$kVersion\",\n\
                     \x20           \"g:other:3\"\n    }\n}\n",
                ),
                (
                    "build.gradle",
                    "dependencies {\n    implementation 'g:a:2'\n    implementation 'g:t:2'\n\
                     \x20   implementation 'g:k:2'\n}\n\
                     configurations.all {\n    resolutionStrategy {\n        force('g:a:1')\n    }\n}\n\
                     configurations.matching { it.name.startsWith('test') }.configureEach {\n\
                     \x20   resolutionStrategy.force 'g:t:1'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let of = |name: &str| -> Vec<(String, bool)> {
            r.packages
                .iter()
                .filter(|p| p.name == name)
                .map(|p| (p.version.clone(), p.dev))
                .collect()
        };
        assert_eq!(of("g:a"), [("1".to_string(), false)], "{:?}", r.missing);
        assert_eq!(of("g:k"), [("1".to_string(), false)], "{:?}", r.missing);
        // Forced on the test classpaths only: 2 ships, 1 is what the tests run with.
        assert_eq!(
            of("g:t"),
            [("1".to_string(), true), ("2".to_string(), false)],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn each_dependency_rules_set_the_versions_they_match() {
        // conductor's root `allprojects { configurations { all { eachDependency } } }` pins
        // lz4 in every project; pulsar's convention sets every Jackson module but one to the
        // catalog's version, the one through a nested `if`/`else`.
        let rules = version_rules(
            "configurations.configureEach {\n\
             \x20   resolutionStrategy.eachDependency {\n\
             \x20       if (requested.group.startsWith(\"com.fasterxml.jackson\")) {\n\
             \x20           if (requested.name == \"jackson-annotations\") {\n\
             \x20               useVersion(catalog.findVersion(\"jackson-annotations\").get().requiredVersion)\n\
             \x20           } else {\n\
             \x20               useVersion(libs.versions.jackson.get())\n\
             \x20           }\n\
             \x20       }\n\
             \x20   }\n\
             }\n\
             buildscript {\n    configurations.all { resolutionStrategy.eachDependency {\n\
             \x20       if (requested.group == \"b\") { useVersion(\"9\") }\n    } }\n}\n\
             configurations.spotbugs {\n    resolutionStrategy.eachDependency {\n\
             \x20       if (requested.group == \"s\") { useVersion(\"9\") }\n    }\n}\n\
             configurations.all {\n    resolutionStrategy.eachDependency {\n\
             \x20       if (requested.group == \"v\" || requested.group == \"w\") { useVersion(\"9\") }\n\
             \x20       if (version(requested.version) < version(\"2\")) { useVersion(\"9\") }\n    }\n}\n",
            &BTreeMap::from([
                ("libs.versions.jackson".to_string(), "2.21.8".to_string()),
                ("libs.versions.jackson-annotations".to_string(), "2.21".to_string()),
            ]),
        );
        let read: Vec<(String, bool, bool, String)> = rules
            .iter()
            .map(|(r, test, shared)| {
                let cond = r
                    .conditions
                    .iter()
                    .map(|c| {
                        format!(
                            "{}{}{}{}",
                            if c.negated { "!" } else { "" },
                            if c.on_name { "name" } else { "group" },
                            if c.prefix { "^" } else { "=" },
                            c.value
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                (cond, *test, *shared, r.version.clone())
            })
            .collect();
        assert_eq!(
            read,
            [
                (
                    "group^com.fasterxml.jackson name=jackson-annotations".to_string(),
                    false,
                    false,
                    "2.21".to_string()
                ),
                (
                    "group^com.fasterxml.jackson !name=jackson-annotations".to_string(),
                    false,
                    false,
                    "2.21.8".to_string()
                ),
            ]
        );

        let repo = Mem(BTreeMap::from([
            pom("lib", "1", &[("x", "2"), ("y", "2")]),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
            pom("y", "1", &[]),
            pom("y", "2", &[]),
        ]));
        let dir = tree(
            "each-dependency",
            &[
                ("settings.gradle", "include 'app'\n"),
                ("gradle/libs.versions.toml", "[versions]\nyv = \"1\"\n"),
                (
                    "build.gradle",
                    "allprojects {\n    configurations {\n        all {\n\
                     \x20           resolutionStrategy.eachDependency { details ->\n\
                     \x20               if (details.requested.group == 'g' && details.requested.name == 'x') {\n\
                     \x20                   details.useVersion '1'\n\
                     \x20               }\n            }\n        }\n    }\n}\n",
                ),
                (
                    "app/build.gradle",
                    "dependencies {\n    implementation 'g:lib:1'\n}\n\
                     configurations.matching { it.name.startsWith('test') }.configureEach {\n\
                     \x20   resolutionStrategy.eachDependency {\n\
                     \x20       if (requested.name != 'x' && requested.name.startsWith('y')) useVersion(libs.versions.yv.get())\n\
                     \x20   }\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let of = |name: &str| -> Vec<(String, bool)> {
            r.packages
                .iter()
                .filter(|p| p.name == name)
                .map(|p| (p.version.clone(), p.dev))
                .collect()
        };
        assert_eq!(of("g:x"), [("1".to_string(), false)], "{:?}", r.missing);
        assert_eq!(of("g:lib"), [("1".to_string(), false)], "{:?}", r.missing);
        // Set on the test classpaths only: 2 ships, 1 is what the tests run with.
        assert_eq!(
            of("g:y"),
            [("1".to_string(), true), ("2".to_string(), false)],
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn the_wrapper_decides_gradle_version_conditions() {
        // axion: `if (GradleVersion.current().version.startsWith("9.")) { spock for groovy 4 }`,
        // with a positional Kotlin `exclude(group, module)` in the taken branch.
        let repo = Mem(BTreeMap::from([
            pom("spock4", "1", &[]),
            pom("spock3", "1", &[]),
            pom("grgit", "1", &[("groovy", "3")]),
            pom("groovy", "3", &[]),
        ]));
        let dir = tree(
            "wrapper",
            &[
                ("settings.gradle.kts", ""),
                (
                    "gradle/wrapper/gradle-wrapper.properties",
                    "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.8.2-bin.zip\n",
                ),
                (
                    "build.gradle.kts",
                    "dependencies {\n    if (GradleVersion.current().version.startsWith(\"9.\")) {\n\
                     \x20       implementation(\"g:spock4:1\")\n\
                     \x20       implementation(\"g:grgit:1\") {\n\
                     \x20           exclude(\"g\", \"groovy\")\n        }\n    } else {\n\
                     \x20       implementation(\"g:spock3:1\")\n    }\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let mut names: Vec<_> = r.packages.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["g:grgit", "g:spock4"], "{:?}", r.missing);
    }

    #[test]
    fn test_suite_dependencies_are_test_dependencies() {
        // caffeine declares jazzer and lincheck in `testing.suites { named<JvmTestSuite>("test")
        // { dependencies { implementation(...) } } }`: its test classpath, not the main one.
        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[("x", "1")]),
            pom("x", "1", &[]),
            pom("x", "2", &[]),
        ]));
        let dir = tree(
            "test-suites",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle.kts",
                    "dependencies {\n    implementation(\"g:a:1\")\n}\n\
                     testing.suites {\n    named<JvmTestSuite>(\"test\") {\n\
                     \x20       dependencies {\n            implementation(\"g:x:2\")\n\
                     \x20       }\n    }\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let x: Vec<_> = r
            .packages
            .iter()
            .filter(|p| p.name == "g:x")
            .map(|p| (p.version.as_str(), p.dev))
            .collect();
        assert_eq!(x, [("1", false), ("2", true)], "{:?}", r.missing);
    }

    #[test]
    fn fixture_builds_under_src_are_not_read() {
        // spring-boot's plugin tests keep builds in src/test/resources; one sets
        // `def kotlinVersion = ... ?: 'none'`, which must not clash with gradle.properties.
        let repo = Mem(BTreeMap::from([
            pom("x", "2.4", &[]),
            pom("fixture", "1", &[]),
        ]));
        let dir = tree(
            "src-fixtures",
            &[
                ("settings.gradle", ""),
                ("gradle.properties", "kotlinVersion=2.4\n"),
                (
                    "build.gradle",
                    "dependencies {\n    implementation \"g:x:$kotlinVersion\"\n}\n",
                ),
                (
                    "src/test/resources/fixture.gradle",
                    "def kotlinVersion = project.findProperty('kotlin.version') ?: 'none'\n\
                     dependencies {\n    implementation 'g:fixture:1'\n}\n",
                ),
                (
                    "build-logic/src/main/groovy/conv.gradle",
                    "dependencies {\n    implementation 'g:x:2.4'\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        assert_eq!(versions(&r, "g:x"), ["2.4"]);
        assert!(versions(&r, "g:fixture").is_empty(), "{:?}", r.packages);
    }

    #[test]
    fn default_build_branches_are_read() {
        let mut vars = BTreeMap::new();
        vars.insert("fromProps".to_string(), "yes".to_string());
        assert_eq!(
            property_default("System.properties['e'] ?: ''", &vars).as_deref(),
            Some("")
        );
        assert_eq!(
            property_default("System.getProperty(\"e\", \"x\")", &vars).as_deref(),
            Some("x")
        );
        assert_eq!(
            property_default("findProperty('fromProps') ?: 'no'", &vars).as_deref(),
            Some("yes")
        );
        assert_eq!(
            property_default("(findProperty('k') ?: 'no')", &vars).as_deref(),
            Some("no")
        );
        assert_eq!(property_default("System.getenv('E') ?: 'x'", &vars), None);
        assert_eq!(
            property_default(
                "providers.gradleProperty(\"toolchainVersion\").map { (it as int) < 21 }.getOrElse(false)",
                &vars
            )
            .as_deref(),
            Some("false")
        );
        assert_eq!(
            property_default(
                "providers.gradleProperty('fromProps').getOrElse('x')",
                &vars
            ),
            None
        );
        vars.insert("old".to_string(), "false".to_string());
        assert_eq!(condition("old", &vars), Some(false));
        let mut c = context("", &[("old", "false")]);
        let m = read_script(
            "dependencies {\n    api(old ? \"g:j:9\" : \"g:j:10\")\n}\n",
            &mut c,
        );
        assert_eq!(rows(&m), [("g:j:10".to_string(), "compile")]);
        vars.insert("e".to_string(), String::new());
        assert_eq!(condition("e == 'true'", &vars), Some(false));
        assert_eq!(condition("!(e != 'true')", &vars), Some(false));
        assert_eq!(condition("hasProperty(\"fromProps\")", &vars), Some(true));
        assert_eq!(condition("project.hasProperty('nope')", &vars), Some(false));
        assert_eq!(condition("e == 'true' && x", &vars), None);
        assert_eq!(
            condition("JavaVersion.current().isJava21Compatible()", &vars),
            None
        );

        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[]),
            pom("b", "1", &[]),
            pom("c", "1", &[]),
            pom("d", "1", &[]),
        ]));
        let dir = tree(
            "branches",
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "def enterprise = System.properties['enterprise'] ?: ''\n\
                     dependencies {\n    if (enterprise == 'true') {\n        implementation 'g:a:1'\n\
                     \x20   } else {\n        implementation 'g:b:1'\n    }\n\
                     \x20   if (hasProperty('nope')) {\n        implementation 'g:c:1'\n    }\n\
                     \x20   else {\n        implementation 'g:d:1'\n    }\n}\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let mut names: Vec<_> = r.packages.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["g:b", "g:d"], "{:?}", r.missing);
        assert!(
            r.missing.iter().all(|m| !m.contains("plain declaration")),
            "{:?}",
            r.missing
        );
    }

    #[test]
    fn set_calls_name_dotted_properties() {
        let mut out = Vec::new();
        set_calls(
            "ext {\n  set('grpc-java.version', \"$grpcVersion\")\n  extra.set(\"a-b\", \"1\")\n  set(x)\n}\n",
            &mut out,
        );
        assert_eq!(
            out,
            [
                ("grpc-java.version".to_string(), "$grpcVersion".to_string()),
                ("a-b".to_string(), "1".to_string())
            ]
        );
    }

    #[test]
    fn a_project_property_overrides_the_bom_property_of_that_name() {
        let bom = |name: &str| {
            (
                format!("g:{name}:1"),
                format!(
                    "<project><groupId>g</groupId><artifactId>{name}</artifactId><version>1</version>\
                     <packaging>pom</packaging><properties><a.version>1.0</a.version></properties>\
                     <dependencyManagement><dependencies>\
                     <dependency><groupId>g</groupId><artifactId>a</artifactId><version>${{a.version}}</version></dependency>\
                     </dependencies></dependencyManagement></project>"
                ),
            )
        };
        let repo = Mem(BTreeMap::from([
            bom("bom"),
            pom("a", "1.0", &[]),
            pom("a", "2.0", &[]),
        ]));
        let script = |plugin: &str| {
            format!(
                "plugins {{\n    id '{plugin}' version '1.1.7'\n}}\next['a.version'] = '2.0'\n\
                 dependencyManagement {{\n    imports {{\n        mavenBom 'g:bom:1'\n    }}\n}}\n\
                 dependencies {{\n    implementation 'g:a'\n}}\n"
            )
        };
        for (plugin, want) in [
            ("io.spring.dependency-management", "2.0"),
            ("other.plugin", "1.0"),
        ] {
            let dir = tree(
                &format!("bom-override-{want}"),
                &[("settings.gradle", ""), ("build.gradle", &script(plugin))],
            );
            let r = resolve_gradle(&dir, &repo);
            assert_eq!(versions(&r, "g:a"), [want], "{plugin} {:?}", r.missing);
        }
    }

    #[test]
    fn variable_references_name_another_variable() {
        for (value, key) in [
            ("extra[\"sb.version\"] as String", Some("sb.version")),
            ("rootProject.ext['v']", Some("v")),
            ("property(\"kotlinVersion\")!!", Some("kotlinVersion")),
            ("Versions.KOTLIN", Some("Versions.KOTLIN")),
            ("compute()", None),
            ("\"1.0\"", None),
        ] {
            assert_eq!(variable_reference(value).as_deref(), key, "{value}");
        }
    }

    #[test]
    fn subprojects_resolve_alone_so_a_lower_version_stays_visible() {
        let repo = Mem(BTreeMap::from([pom("c", "1.0", &[]), pom("c", "2.0", &[])]));
        let dir = tree(
            "subprojects",
            &[
                ("settings.gradle", ""),
                (
                    "one/build.gradle",
                    "dependencies { implementation 'g:c:1.0' }\n",
                ),
                (
                    "two/build.gradle",
                    "dependencies { implementation 'g:c:2.0' }\n",
                ),
            ],
        );
        assert_eq!(
            versions(&resolve_gradle(&dir, &repo), "g:c"),
            ["1.0", "2.0"]
        );
    }

    #[test]
    fn unused_catalog_entries_and_build_logic_are_development_only() {
        let repo = Mem(BTreeMap::from([
            pom("a", "1", &[]),
            pom("b", "1", &[]),
            pom("c", "1", &[]),
        ]));
        let dir = tree(
            "dev",
            &[
                (
                    "gradle/libs.versions.toml",
                    "[libraries]\na = \"g:a:1\"\nb = \"g:b:1\"\n",
                ),
                ("build.gradle", "dependencies { implementation(libs.a) }\n"),
                (
                    "buildSrc/build.gradle",
                    "dependencies { implementation 'g:c:1' }\n",
                ),
            ],
        );
        let r = resolve_gradle(&dir, &repo);
        let dev = |name: &str| r.packages.iter().find(|p| p.name == name).unwrap().dev;
        assert!(!dev("g:a"));
        assert!(dev("g:b"));
        assert!(dev("g:c"));
    }

    #[test]
    fn a_comment_marker_in_a_string_is_not_a_comment() {
        let out = strip_comments("url = \"https://x\" // gone\n/* a\nb */ c\n");
        assert_eq!(out, "url = \"https://x\" \n\n c\n");
    }
}
