//! Gradle module metadata (`.module` files, format 1.1), read for Gradle builds in place of
//! the POM when the POM says the library was published with it (spec 16, row 9).
//!
//! A `.module` file lists variants, each a set of attributes with its own dependencies. A
//! JVM build's runtime classpath takes the variant whose `org.gradle.usage` is `java-runtime`
//! (else `java-api`), of category `library` (else `platform`, for a BOM), preferring a
//! Kotlin `jvm` platform and a `standard-jvm` environment over Android. A variant may live in
//! another module (`available-at`: Kotlin Multiplatform's `foo` points at `foo-jvm`), which
//! then becomes the one dependency. Each dependency's version is `strictly`, else `requires`,
//! else `prefers`; a dependency of category `platform` brings its constraints, and
//! `dependencyConstraints` raise versions of artifacts present elsewhere in the graph.

use serde_json::Value;

/// One dependency or constraint of the chosen variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleDep {
    pub group: String,
    pub module: String,
    /// `None` when the entry gives no version (it is then managed by a platform).
    pub version: Option<String>,
    pub excludes: Vec<(String, String)>,
    /// A `platform` or `enforced-platform` dependency (a BOM).
    pub platform: bool,
}

/// What the chosen variant says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Variant {
    pub name: String,
    pub dependencies: Vec<ModuleDep>,
    pub constraints: Vec<ModuleDep>,
    /// What the matching `java-api` variant adds (`compileOnlyApi`: JUnit's apiguardian, the
    /// OSGi annotations): on compile classpaths only, never at runtime.
    pub api_only: Vec<ModuleDep>,
}

/// The runtime variant of a `.module` file. `Err` when the file does not parse or has no
/// variant a JVM runtime classpath would take.
pub(crate) fn runtime_variant(json: &str) -> Result<Variant, String> {
    let doc: Value = serde_json::from_str(json).map_err(|e| format!("module metadata: {e}"))?;
    let variants = doc
        .get("variants")
        .and_then(Value::as_array)
        .ok_or("module metadata has no variants")?;
    // A variant that declares capabilities without the component's own is a feature variant
    // (kotlin-test's JUnit and TestNG flavours): only taken when asked for by capability.
    let component = |k: &str| {
        doc.get("component")
            .and_then(|c| c.get(k))
            .and_then(Value::as_str)
    };
    let (own_group, own_module) = (component("group"), component("module"));
    let default_capability = |v: &Value| -> bool {
        let Some(caps) = v.get("capabilities").and_then(Value::as_array) else {
            return true;
        };
        caps.is_empty()
            || caps.iter().any(|c| {
                c.get("group").and_then(Value::as_str) == own_group
                    && c.get("name").and_then(Value::as_str) == own_module
            })
    };
    let attr = |v: &Value, name: &str| -> Option<String> {
        v.get("attributes")?.get(name)?.as_str().map(str::to_string)
    };
    let rank = |v: &Value| -> Option<(u8, u8, u8, u8, u8)> {
        let usage = match attr(v, "org.gradle.usage").as_deref() {
            Some("java-runtime") => 2,
            Some("java-api") => 1,
            _ => return None,
        };
        let category = match attr(v, "org.gradle.category").as_deref() {
            Some("library") | None => 2,
            Some("platform") | Some("enforced-platform") => 1,
            _ => return None,
        };
        let platform = match attr(v, "org.jetbrains.kotlin.platform.type").as_deref() {
            Some("jvm") | None => 2,
            Some("androidJvm") => 1,
            _ => return None,
        };
        let environment = match attr(v, "org.gradle.jvm.environment").as_deref() {
            Some("standard-jvm") | None => 2,
            Some("android") => 1,
            _ => 0,
        };
        // The runtime classpath asks for `external`: a shadowed jar's dependencies are inside
        // it, so its variant lists none.
        let bundling = match attr(v, "org.gradle.dependency.bundling").as_deref() {
            Some("external") | None => 2,
            Some("embedded") => 1,
            _ => 0,
        };
        Some((category, platform, environment, bundling, usage))
    };
    let best = variants
        .iter()
        .filter(|v| default_capability(v))
        .filter_map(|v| Some((rank(v)?, v)))
        // On a tie the first variant listed, not the last.
        .rev()
        .max_by_key(|(r, _)| *r)
        .map(|(_, v)| v)
        .ok_or("module metadata has no JVM runtime variant")?;
    let name = best
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if let Some(at) = best.get("available-at") {
        let text = |k: &str| at.get(k).and_then(Value::as_str).map(str::to_string);
        let (Some(group), Some(module)) = (text("group"), text("module")) else {
            return Err(format!("variant {name}: available-at without a module"));
        };
        return Ok(Variant {
            name,
            dependencies: vec![ModuleDep {
                group,
                module,
                version: text("version"),
                excludes: Vec::new(),
                platform: false,
            }],
            constraints: Vec::new(),
            api_only: Vec::new(),
        });
    }
    let list = |v: &Value, key: &str| -> Vec<ModuleDep> {
        v.get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(entry)
            .collect()
    };
    let dependencies = list(best, "dependencies");
    // The `java-api` variant ranked the same way: a compile classpath takes it.
    let best_rank = rank(best);
    let api = variants
        .iter()
        .filter(|v| default_capability(v) && v.get("available-at").is_none())
        .filter(|v| attr(v, "org.gradle.usage").as_deref() == Some("java-api"))
        .find(|v| rank(v).map(|r| (r.0, r.1, r.2, r.3)) == best_rank.map(|r| (r.0, r.1, r.2, r.3)));
    let api_only = match api {
        Some(api) if best_rank.is_some_and(|r| r.4 == 2) => list(api, "dependencies")
            .into_iter()
            .filter(|d| {
                !dependencies
                    .iter()
                    .any(|r| r.group == d.group && r.module == d.module)
            })
            .collect(),
        _ => Vec::new(),
    };
    Ok(Variant {
        name,
        dependencies,
        constraints: list(best, "dependencyConstraints"),
        api_only,
    })
}

fn entry(v: &Value) -> Option<ModuleDep> {
    let group = v.get("group")?.as_str()?.to_string();
    let module = v.get("module")?.as_str()?.to_string();
    let version = v.get("version").and_then(|ver| {
        ["strictly", "requires", "prefers"]
            .into_iter()
            .find_map(|k| ver.get(k)?.as_str())
            .map(str::to_string)
    });
    let excludes = v
        .get("excludes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|e| {
            let part = |k: &str| e.get(k).and_then(Value::as_str).unwrap_or("*").to_string();
            (part("group"), part("module"))
        })
        .collect();
    let category = v
        .get("attributes")
        .and_then(|a| a.get("org.gradle.category"))
        .and_then(Value::as_str);
    Some(ModuleDep {
        group,
        module,
        version,
        excludes,
        platform: matches!(category, Some("platform") | Some("enforced-platform")),
    })
}

/// Whether a POM says a `.module` file was published next to it.
pub(crate) fn pom_points_to_module(pom: &str) -> bool {
    pom.contains("published-with-gradle-metadata")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn multiplatform_points_at_the_jvm_module() {
        let json = r#"{"formatVersion":"1.1","variants":[
          {"name":"metadataApiElements","attributes":{"org.gradle.usage":"kotlin-metadata","org.jetbrains.kotlin.platform.type":"common"}},
          {"name":"jsRuntimeElements","attributes":{"org.gradle.usage":"kotlin-runtime","org.jetbrains.kotlin.platform.type":"js"},
           "available-at":{"url":"../../x-js/1.0/x-js-1.0.module","group":"org.x","module":"x-js","version":"1.0"}},
          {"name":"jvmApiElements-published","attributes":{"org.gradle.usage":"java-api","org.gradle.category":"library","org.jetbrains.kotlin.platform.type":"jvm"},
           "available-at":{"url":"../../x-jvm/1.0/x-jvm-1.0.module","group":"org.x","module":"x-jvm","version":"1.0"}},
          {"name":"jvmRuntimeElements-published","attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"library","org.jetbrains.kotlin.platform.type":"jvm"},
           "available-at":{"url":"../../x-jvm/1.0/x-jvm-1.0.module","group":"org.x","module":"x-jvm","version":"1.0"}}
        ]}"#;
        let v = runtime_variant(json).unwrap();
        assert_eq!(v.name, "jvmRuntimeElements-published");
        assert_eq!(v.dependencies[0].module, "x-jvm");
        assert_eq!(v.dependencies[0].version.as_deref(), Some("1.0"));
    }

    #[test]
    fn standard_jvm_beats_android_and_versions_follow_gradle() {
        let json = r#"{"formatVersion":"1.1","variants":[
          {"name":"androidRuntimeElements","attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"library","org.gradle.jvm.environment":"android"},
           "dependencies":[{"group":"a","module":"android-only","version":{"requires":"1"}}]},
          {"name":"jreRuntimeElements","attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"library","org.gradle.jvm.environment":"standard-jvm"},
           "dependencies":[
             {"group":"g","module":"strict","version":{"strictly":"[1.0,2.0)","prefers":"1.5"}},
             {"group":"g","module":"req","version":{"requires":"2.1"},"excludes":[{"group":"x","module":"y"}]},
             {"group":"g","module":"bom","version":{"requires":"3.0"},"attributes":{"org.gradle.category":"platform"}},
             {"group":"g","module":"managed"}],
           "dependencyConstraints":[{"group":"g","module":"c","version":{"requires":"4.0"}}]},
          {"name":"jreApiElements","attributes":{"org.gradle.usage":"java-api","org.gradle.category":"library","org.gradle.jvm.environment":"standard-jvm"}},
          {"name":"sourcesElements","attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"documentation"}}
        ]}"#;
        let v = runtime_variant(json).unwrap();
        assert_eq!(v.name, "jreRuntimeElements");
        let versions: Vec<_> = v
            .dependencies
            .iter()
            .map(|d| d.version.as_deref())
            .collect();
        assert_eq!(
            versions,
            [Some("[1.0,2.0)"), Some("2.1"), Some("3.0"), None]
        );
        assert_eq!(
            v.dependencies[1].excludes,
            [("x".to_string(), "y".to_string())]
        );
        assert!(v.dependencies[2].platform);
        assert_eq!(v.constraints[0].module, "c");
    }

    #[test]
    fn the_api_variant_adds_compile_only_dependencies() {
        // junit-jupiter-api: apiguardian-api and opentest4j in apiElements, only opentest4j at
        // runtime, so apiguardian is on compile classpaths only.
        let json = r#"{"component":{"group":"org.junit.jupiter","module":"junit-jupiter-api"},"variants":[
          {"name":"apiElements","attributes":{"org.gradle.usage":"java-api","org.gradle.category":"library"},
           "dependencies":[{"group":"org.apiguardian","module":"apiguardian-api","version":{"requires":"1.1.2"}},
                           {"group":"org.opentest4j","module":"opentest4j","version":{"requires":"1.3.0"}}]},
          {"name":"runtimeElements","attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"library"},
           "dependencies":[{"group":"org.opentest4j","module":"opentest4j","version":{"requires":"1.3.0"}}]}
        ]}"#;
        let v = runtime_variant(json).unwrap();
        assert_eq!(v.name, "runtimeElements");
        let api_only: Vec<_> = v.api_only.iter().map(|d| d.module.as_str()).collect();
        assert_eq!(api_only, ["apiguardian-api"]);
        // With only an API variant there is nothing extra to add.
        let json = r#"{"variants":[{"name":"apiElements","attributes":{"org.gradle.usage":"java-api"},
           "dependencies":[{"group":"g","module":"a","version":{"requires":"1"}}]}]}"#;
        assert!(runtime_variant(json).unwrap().api_only.is_empty());
    }

    #[test]
    fn the_shadowed_jar_is_not_the_runtime_variant() {
        let json = r#"{"formatVersion":"1.1","variants":[
          {"name":"runtimeElements","attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"library","org.gradle.dependency.bundling":"external"},
           "dependencies":[{"group":"g","module":"a","version":{"requires":"1"}}]},
          {"name":"shadowRuntimeElements","attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"library","org.gradle.dependency.bundling":"shadowed"}}]}"#;
        assert_eq!(runtime_variant(json).unwrap().name, "runtimeElements");
    }

    #[test]
    fn feature_variants_need_their_capability_asked_for() {
        let json = r#"{"formatVersion":"1.1","component":{"group":"k","module":"kotlin-test","version":"2"},"variants":[
          {"name":"jvmRuntimeElements","attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"library","org.jetbrains.kotlin.platform.type":"jvm"},
           "dependencies":[{"group":"k","module":"stdlib","version":{"requires":"2"}}]},
          {"name":"jvmTestNGRuntimeElements","attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"library","org.jetbrains.kotlin.platform.type":"jvm"},
           "capabilities":[{"group":"k","name":"kotlin-test-framework-testng","version":"2"}],
           "dependencies":[{"group":"t","module":"testng","version":{"requires":"7"}}]}]}"#;
        let v = runtime_variant(json).unwrap();
        assert_eq!(v.name, "jvmRuntimeElements");
        assert_eq!(v.dependencies[0].module, "stdlib");
    }

    #[test]
    fn a_bom_takes_its_platform_variant() {
        let json = r#"{"formatVersion":"1.1","variants":[
          {"name":"platformRuntimeElements","attributes":{"org.gradle.usage":"java-runtime","org.gradle.category":"platform"},
           "dependencyConstraints":[{"group":"g","module":"a","version":{"requires":"1.2"}}]}]}"#;
        let v = runtime_variant(json).unwrap();
        assert!(v.dependencies.is_empty());
        assert_eq!(v.constraints.len(), 1);
        assert!(runtime_variant("{}").is_err());
        assert!(runtime_variant(
            r#"{"variants":[{"attributes":{"org.gradle.usage":"kotlin-metadata"}}]}"#
        )
        .is_err());
    }
}
