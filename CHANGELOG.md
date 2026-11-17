# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`scan --reachability=dotnet` builds a call graph over each image's .NET assemblies.**
  Every `.dll` a service ships (not the runtime's shared frameworks) is read as data by a new
  in-house ECMA-335 reader, nothing is loaded or run, and one graph is walked from the code of
  each folder holding a `*.deps.json`. NuGet findings with a curated sink record are judged as
  JVM ones are: reachable with a chain, not reachable only from a reviewed record, unknown
  with the reason otherwise. The graph follows what reflection makes (`typeof`, generic
  arguments such as dependency injection and serializers, type names in strings, attributes
  and `appsettings.json`), and what the runtime calls on its own (`ToString`, `Dispose`, async
  state machines, ASP.NET Core interfaces). Checked against the runtime: on 11 apps built from
  real NuGet packages, every one of the 6,727 methods the JIT compiled in their assemblies is
  in the graph. 97 reviewed NuGet sink records ship, each narrowed by hand
  from its fix commit and the IL of the releases either side of it, with its sinks checked
  across every affected release line. A record's sinks count only in the assemblies its
  packages ship, as the image's deps files list them. On 11 public .NET app images (Jellyfin,
  Sonarr, Radarr, Lidarr, Prowlarr, Jackett, Squidex, Duplicati, Kavita, EventStore) 20 of 34
  NuGet findings had a record: 10 reached with a chain, 6 not reached (OpenTelemetry's
  propagators in EventStore, Pkcs signature checks in four *arr images where only MimeKit's
  Windows S/MIME context calls them, and Kavita's old WebSocket package that nothing calls), 4
  unknown with the reason.

- **Signed webhooks.** `fleetreach notify --webhook-secret-env VAR` signs each post as
  Standard Webhooks specifies (`webhook-id`, `webhook-timestamp`, `webhook-signature`: HMAC-SHA256
  of `id.timestamp.body`), with the secret read from that environment variable, so any of the
  spec's libraries can verify that a post came from your scan. Checked against the spec's
  test vector and an independent verifier.
- **`fleetreach ecosystems` prints the coverage matrix.** Per ecosystem: the files read and
  the coverage each gives, where advisories come from, the version rules, what they were
  checked against and the result (table, `-f markdown` or `-f json`). The website's ecosystem
  overview is generated from it and CI fails when the page is out of date; a test runs every
  listed file through the scan's own detection.
- **Gradle module metadata is read.** For a Gradle build without a lockfile, a library
  published with a `.module` file is resolved from it instead of its POM, as Gradle does: the
  JVM runtime variant (Kotlin multiplatform `-jvm` artifacts, standard-JVM over Android, never
  a shadowed jar or a test-framework feature variant), its dependencies, and constraints that
  raise versions or manage an imported BOM. On three Kotlin builds this adds 27 to 36 packages
  the POMs did not name. `.module` files are fetched with `--maven-fetch` like POMs.
- **The Gradle reader is measured against real Gradle, and reads much more.** On 62 real
  Gradle builds resolved by Gradle 8.14 in containers (four classpaths per project), fleetreach
  now lists 87.2% of the 11,816 modules at Gradle's version and 91.2% by name (the 56 first
  builds alone went from 59.7% and 70.0% to 88.1% and 91.4%); 96.1% and 98.7% on the 56 builds
  whose dependencies no build plugin adds. The main classpath is resolved without the test dependencies, as Gradle resolves each
  configuration on its own, so a test library no longer raises a version the shipped code
  uses. The compile classpath is resolved on its own too: a sibling project's
  `implementation` dependencies are only on the runtime classpath of a project that depends
  on it, so mybatis-plus's generator compiles against springfox's Spring 5.2.0, as Gradle
  shows (20 modules). Dependencies declared in JVM test suites (`testing.suites { ... }`) are
  test dependencies (caffeine's jazzer and lincheck). Forced versions are read:
  `resolutionStrategy.force(...)`, test-only when it sits in a `configurations.matching`
  block for tests (conductor), and the kordamp enforcer's `ForceDependencies` rule in the
  settings (jreleaser, all 17 misses and 64 extras gone). The wrapper's Gradle version
  decides `GradleVersion.current().version.startsWith(...)` branches (axion's Spock), and the
  Kotlin DSL's positional `exclude("group", "module")` is read. A platform in a test
  configuration (`testImplementation(platform(...))`) manages the test classpaths only, one
  on an annotation processor's path (`kapt`, `ksp`, `annotationProcessor`) manages none of
  the classpaths read, `compileOnly(project(':p'))` brings only p's `api` dependencies, and
  `kotlin.stdlib.default.dependency=false` drops the standard library the Kotlin plugin adds
  (reposilite 95.0% to 97.7%). A project property overrides a BOM's property only in the
  build files that apply the Spring dependency-management plugin (also written
  `apply { plugin(...) }`), never through Gradle's own `platform(...)`: halo's
  `thymeleaf.version` moves `:application` and not `:api`, as Gradle shows (97.1% to
  99.6%). A `platform(...)` naming its BOM through an `ext` map is read (jib 93.5% to 99.2%).
  The dependency-management plugin is also recognised through a catalog alias, so a version
  the build declares wins over Spring Boot's (interview-guide 98.1% to 100%); Spring Boot 3.5+
  adds the JUnit Platform launcher to the tests; and `kotlin-dsl` brings the Kotlin the
  wrapper's Gradle embeds, from Gradle's compatibility table (axion 94.0% to 98.5%,
  node-gradle 93.9% to 98.5%). The tests' compile classpath is resolved on its own as well,
  without `testRuntimeOnly` and main `compileOnly` dependencies, and no compile classpath
  takes a runtime dependency at any depth: a POM's `runtime` scope and what a `.module`
  file's runtime variant adds over its API variant (komga's JUnit 5.12.2, raised to 5.14.4 at
  test runtime only; komga 95.4% to 96.9%, conductor 98.2% to 99.0%). The build's own
  convention plugins (precompiled scripts under `src/main/kotlin` or `src/main/groovy` of
  `build-logic`, `buildSrc` or an included build) now declare for the projects that apply
  them, through the conventions they apply in turn; one nothing applies stays build logic.
  Inside them the catalog API is read (`libs.findLibrary("x").get()`,
  `libs.findVersion("x").get()`, and one-line helpers over either), as is
  `findProperty("k")?.toString() != "false"` with the property unset. A constraint on a
  tool's own configuration (`checkstyle`) manages none of the classpaths (caffeine 86.3% to
  87.4% and 23 fewer packages Gradle does not list, gradle-versions-plugin 27 fewer). Project paths follow the settings script:
  `project(':p').projectDir = file('d')`, `project(':p').name = 'n'` and
  `rootProject.children.each { it.name = "x-${it.name}" }`, so a dependency on a renamed or
  moved project brings its dependencies (conductor names every child `conductor-*`: its
  dependents now take Spring Boot's bson 5.8.1 while `:conductor-ai` keeps the 4.11.0 it
  declares; 99.0% to 99.6% and 27 fewer packages Gradle does not list). `resolutionStrategy.eachDependency` rules
  are read where their conditions are on `requested.group` and `requested.name` (`==`, `!=`,
  `startsWith`, `&&`, nested `if` and `else`) and the version is a literal, a variable, a catalog library's own version (`libs.paper.orNull?.version`) or the
  catalog's: every request a rule matches takes its version, in the root's `allprojects` or
  `subprojects` for every project, in a convention plugin for the projects that apply it, and
  in a test `configurations.matching` block for the tests only (pulsar's Jackson rule 97.4% to
  98.5% and 33 fewer packages Gradle does not list; conductor's lz4 floors, 99.9%). The
  compile classpaths are now resolved on their own for every project with main or test
  dependencies, not only for one that declares a runtime dependency: a POM's `runtime` scope
  down the tree splits them too (JavaPackager compiles against redline's xz 1.4, while
  plexus-archiver's runtime xz 1.9 is on the runtime classpath only). The freefair Lombok
  plugin's Lombok is added to the compile and test-compile classpaths: the version its
  `lombok { version = ... }` extension sets, else the plugin's default where real Gradle
  showed it (8.6 adds 1.18.30, 9.8.0 adds 1.18.48); another release's default is reported,
  not guessed (grpc-spring, halo, mybatis-plus). A plugin version written as a variable of
  `buildscript { ext { } }` is expanded. Next to a `kotlin-test` dependency the Kotlin plugin's
  variant for the test framework is added: `kotlin-test-junit5` with `useJUnitPlatform()`,
  `-testng` with `useTestNG()`, else `-junit` (grpc-spring, moshi, ideavim). The Kotlin
  plugin's version is also read from `classpath(kotlin("gradle-plugin", version = v))`,
  and a variable set to `System.getenv("X") ?: libs.versions.k.get()` takes the catalog's
  version, as with the variable unset (moshi 92.2% to 96.1%). `JavaVersion.current()` checks for Java 17 or
  earlier (`isJava9Compatible()`, `java8Compatible`, `isCompatibleWith(VERSION_1_9)`) are
  taken as true, the JDK that runs Gradle being 17 or later (Gradle 9 requires it), so
  grpc-spring's `@Generated` workaround dependencies are listed; a check for a later
  release stays undecided. A dependency an exclusion removes stays out only when every path to its
  parent excludes it, as in Gradle: thymeleaf-spring5 excludes ognl from thymeleaf,
  thymeleaf-extras-java8time does not, so ognl and javassist are listed
  (isolating-the-domain 98.8% to 100%; Hystrix, Timefold, grpc-spring and moshi gain too).
  `platform(org.springframework.boot.gradle.plugin.SpringBootPlugin.BOM_COORDINATES)`,
  written out in full, is read like the imported name. Under the dependency-management plugin, every version a
  project declares is managed on the classpaths holding the declaration, even for an
  artifact no BOM manages: conductor's `testImplementation jna:5.7.0` wins over
  Elasticsearch's 5.10.0 on the test classpaths only (conductor 100%). A version range
  with no `maven-metadata.xml` to choose from takes its candidates from the versions Gradle's
  download cache holds a POM or `.module` of, as Gradle settles a range offline
  (spring-integration-samples' jxmpp and minidns through smack-core's `[1.0.0, 1.0.999]`). A dependency
  constraint that a module's Gradle metadata puts in its runtime variant alone holds on runtime
  classpaths only (gradle-download-task compiles against json-path's json-smart 2.4.7 and runs
  with the 2.4.8 wiremock-jre8 pins). A Kotlin library declared with no version takes the Kotlin
  plugin's version, as the plugin sets it (spring-integration-samples' `kotlin-reflect` 2.4.21). Gretty
  adds its container's servlet and websocket APIs to every classpath of a project that applies
  it, for the pairings real Gradle showed (3.x with `jetty9`, 4.x's default); another is
  reported, never guessed (Hystrix's webapp, spring-integration-samples' web samples). A
  prefix version (`3.19+`) now settles to the highest listed version that starts with it, as
  Gradle reads one, instead of being reported (Hystrix's javassist 3.19.0-GA, dgs-framework's
  mockk); `latest.release` is still reported. In a POM, an optional dependency no longer
  widens the test-scoped one it inherits under the same name onto the classpath (netty-common
  4.1.3's javassist, which raised powermock's 3.18.2-GA to 3.20.0-GA). A plugin that buildSrc or
  build-logic depends on (`implementation "...kotlin-gradle-plugin:${kotlinVersion}"`) sets the
  version of that plugin where a build file applies it (spring-framework's Kotlin 2.4.21). A
  configuration a buildSrc or build-logic plugin creates by name and adds to every source
  set's compile and runtime classpaths, and to nothing consumers see, holds on the project's
  own main and test classpaths only (Spring's `optional`: spring-framework's spring-messaging
  keeps kotlinx's kotlin-stdlib 2.3.20 on its main classpath). Gradle builds now
  compare versions in Gradle's own order, not Maven's, for ranges, prefix versions and
  conflict resolution: an extra numeric part is higher, so `[2.2,3)` leaves out 3.0.0-M5
  (ehcache 3.10.8's jaxb-runtime is 2.4.0-b180830.0438), and `rc`, `ga`, `sp` and the like
  take Gradle's places. The order agreed with Gradle 8.14.3's `DefaultVersionComparator` on
  all of 306,536 pairs (`docs/differential/gradle/vercmp`); spring-framework 100%. Plugin
  versions set in settings' `pluginManagement { plugins { } }` version the plugins a build
  applies bare, and Kotlin 1.8.0 adds `kotlin-stdlib-jdk8` as its standard library, as
  Gradle shows; a Kotlin plugin version real Gradle was not seen with (between 1.8.0 and
  1.9.23, or older) is reported rather than given a guessed library (Charlatano 36 to 52
  of 52). The runtime classpath leaves out `compileOnly` and annotation-processor
  dependencies, and what a `.module` lists in its API variant alone, as Gradle's
  `runtimeClasspath` does: a compile-only version no longer raises what ships
  (gradle-versions-plugin's kotlin-stdlib stays at okio's 1.9.21 at runtime, 100%), and 17
  fewer packages Gradle never lists across the corpus (zaproxy's log4j bnd annotations). An `if`
  around a `dependencies { }` block that a default build leaves false is skipped, nested
  blocks included (logstash's FIPS libraries need `-PfedrampHighMode=true`), and
  `configurations.all { exclude ... }`, `configurations { all { exclude ... } }` and
  `configureEach` excludes drop a module on every classpath, direct declarations too
  (conductor's Logback). A root build's top-level `project(':p') { ... }` blocks configure
  those projects, a `libs += [ k: "g:a:$versions.k" ]` map names coordinates when there is no
  version catalog, and the `libs` catalog is read from the TOML file the script creating it
  names (armeria's `dependencies.toml`): kafka 1 to 409 of 421, armeria 5 to 1,129 of 1,324. A multi-line list variable
  (`testLog4j2Libs = [ libs.a, ... ]`) declared whole (`testImplementation testLog4j2Libs`)
  declares each item (kafka 414). Dependency `exclude` rules and `transitive = false` are applied (an artifact declared
  twice keeps only the exclusions both declarations share), which drops about 180 packages
  Gradle never puts on a classpath. Versions the Spring dependency-management plugin manages
  (its `mavenBom` imports, its `dependency` entries, Spring Boot's BOM) now win over
  conflict resolution, a later import overriding an earlier one, as the plugin sets them;
  a version the build declares itself is the managed one for every path to that artifact
  (conductor's grpc 1.75.0 under Spring Boot's 1.83.1). An `enforcedPlatform(...)` forces its versions
  even over ones the build declares. A `project(':p')` dependency brings p's own
  dependencies, platforms and constraints onto the depending project's classpaths, and
  when an artifact is declared more than once the highest version wins, as in Gradle
  (mybatis-plus's Boot 3 and 4 starters, ethereum-lists' moshi). `jmh`, `benchmark` and
  similar source sets of their own are off the main classpath. A library's compile-only API
  dependencies (from its `.module` file's `java-api` variant) are on compile classpaths only.
  Build fixtures under `src/` (spring-boot's plugin test projects) are no longer read as part
  of the build. A declared `platform(...)` is listed as a
  module, as Gradle lists it, without its own dependencies. `if`/`else` branches a default
  build decides (`System.properties['k'] ?: ''`, `findProperty`, `hasProperty`,
  `providers.gradleProperty(...).getOrElse(...)`, a `cond ? 'a' : 'b'` coordinate) are read.
  Newly read: the root's `subprojects`/`allprojects`/`configure` blocks, Spring
  `dependencyManagement` (BOM imports, managed versions, and project properties that override
  a BOM's properties), `platform(project(...))` from `java-platform` projects, the Spring Boot
  plugin's `BOM_COORDINATES`, catalog versions as `libs.versions.x`, catalogs declared in the
  settings script, Groovy dependency maps (`lib = [ "k": "g:a:v" ]`), rich version blocks
  (`strictly`, `require`, `prefer`), custom configurations that a standard one `extendsFrom`,
  map notation on custom configurations, ForgeGradle's `fg.deobf`, plugin versions from a
  `buildscript` `classpath` line with `apply plugin:`, Groovy map entries as `lib."k"`,
  `set('grpc-java.version', ...)` properties, and variables that name other variables. The
  harness is in `docs/differential/gradle`.
- **POM relocations are followed.** A POM with `<distributionManagement><relocation>` resolves
  the way each tool does: Maven resolves the artifact as its new coordinate, and Gradle keeps
  the relocation POM and adds the target (Artemis moved from `org.apache.activemq` to
  `org.apache.artemis`, so findings for the new group were missed).
- **A property a POM sets now decides the versions its parents manage**, as Maven merges a
  POM's parents before interpolating (a project's `<jackson.version>` under a Spring Boot
  parent, artemis-jakarta-client's `jakarta.jms-api.version`). A version left naming an
  undefined property (its parent POM out of reach) is reported instead of listed as
  `${...}`.
- **POM profiles switch on as Maven switches them.** A profile activated by the JDK
  (`<jdk>[9,)</jdk>`, assumed a current JDK 21) or by an unset property (`!name`) now applies
  in Maven builds, and an `activeByDefault` profile then stays off, as Maven decides
  (xmlunit-core adds jakarta.xml.bind-api this way, so its findings were missed). Gradle builds
  keep reading only `activeByDefault`, as Gradle does. Profiles that name an OS or a file
  stay off. Against real Maven 3.9.9, offline in a container, every project now matches
  exactly, every scope: 271 of 271 one-dependency projects built from published artifacts
  with parents (1,875 packages; before: 265, 4 misses, 20 extras) and 109 of 109
  six-dependency projects (3,478 packages; before: 96, 11 misses, 55 extras). The harness is
  in `docs/differential/maven`.
- **Maven reactors resolve as Maven builds them.** Each module is mediated on its own, so
  every version a module ships is listed (pooled, arthas's starter hid the junit-jupiter
  5.10.0 the other modules get). A BOM or parent that is a module of the same build is read
  from the build, as Maven's reactor does, so dubbo's and ruoyi-vue-pro's own dependency BOMs
  now manage their versions (dubbo: 128 dependencies were dropped as unmanaged; ruoyi-vue-pro
  went from 2 packages to 139). A profile's `<modules>` join the reactor. The build's own
  modules are walked through, never listed as packages.
- **Checked against real Maven on 14 real multi-module repos: all 3,555 packages match.**
  Real Maven 3.9.9 resolved 657 modules of dubbo, nacos, netty, ruoyi-vue-pro and ten others,
  and 13 of the 14 repos are now identical. It found seven rules: a parent's BOM import beats
  its grandparent's (dubbo's Spring Boot 1 modules, 97 packages); a managed entry's
  exclusions apply at every depth, merged with a dependency's own (Spring Cloud keeps
  archaius-core out of eureka-client); a module is taken from the build only at its own
  version (easyexcel manages its support module at the published 3.3.4); `<optional>` can name
  a property (the Kubernetes client's optional cloud clients); a one-version range such as
  `[1.53.0]` needs no metadata (grpc-core); a direct dependency sits above a sibling
  module's (nacos's slf4j-api 1.7.26); and `<jdk>` ranges are read as Maven reads them,
  including `[17,` with no closing bracket. The one difference left is netty's
  OS-activated profile, which depends on the machine that builds.
- **Checked again on 30 more real repos, module by module: 1,999 of 2,136 modules
  identical, and every other one differs only by a machine-dependent profile.** Real Maven's tree for each module of flink, keycloak, skywalking, seatunnel,
  dolphinscheduler, hbase and 24 others was compared with fleetreach's per module. Another
  137 modules differ only by profiles that follow the building machine's OS or CPU (brotli4j
  and netty natives, hadoop's aarch64 leveldbjni). The fixes: a POM that starts with a plain `<!DOCTYPE project>` is read (oshi-core 6.1.1; its
  jna was missing from 112 dolphinscheduler modules); a module named with a property
  (`flink-table-planner_${scala.binary.version}`) is found as a sibling; a nearer version
  outside a range in the same conflict gives way to the nearest one that fits (zipkin's
  bcprov 1.81.1); a relocation applies on every path, not only the first (linkis's
  slf4j-log4j12); a module reached both as a `pom` and as a jar is walked for each (keycloak's
  integration tests, 82 packages); the build's own module holds its place in mediation
  (guava-testlib's guava); a profile's `<file>` activation is checked in the checkout
  (seata's distribution module); a winner whose scope widens keeps its own path's exclusions
  and depth (keycloak's guava, excluded down to nothing, then reached at compile by grpc);
  a version range stops at its first version that relocates, as Maven's collector does
  (system-rules' `junit-dep [4.9,)`); a range's winner is the nearest occurrence that asks
  for the fitting version itself, with its own subtree (seatunnel's grpc-core 1.33.0 under
  vitess, not firestore's copy, which excludes grpc-api); a range also reads the version
  listing of each repository the build declares, from the local repository only (flink
  declares Red Hat's, so `lang-tag [1.4.3,)` is 1.7.0.redhat-00003); a module's own dependencies come before inherited ones; a
  managed `provided` or `test` scope holds on every path; and element names XML forbids but
  Maven reads (`<Xlint:-unchecked/>`) no longer fail the POM.
- **And on a third batch of 30 real repos: 1,697 of 1,767 modules identical, the other 70
  differing only by OS- or CPU-activated profiles.** Real Maven's per-module tree for
  shardingsphere, inlong, cxf, tika, hudi, streampipes and 23 others (kylin left out: its
  build needs a private repository). The fixes: a `test-jar` dependency is the `tests` jar
  for mediation and management (hudi-io); `.mvn/maven.config` profiles and `-D` properties
  apply (spring-cloud-gateway); an exclusion can name a property (drill's
  `${calcite.groupId}`); a scope Maven does not know, such as `optional`, still takes part in
  mediation (kudu-client's audience-annotations in hive); `RELEASE` and `LATEST` versions
  come from the newest repository metadata (COLA's junit-jupiter); and a published POM
  whose `system` dependency has no absolute path is read with no dependencies, as Maven
  does (druid 1.2.6 in inlong).
- **gradle-consistent-versions' `versions.lock` is read as a full lockfile** (beside its
  `versions.props`), checked so a damaged file is refused.
- **POMs are read from Gradle's download cache** (`$GRADLE_USER_HOME` or `~/.gradle`,
  `caches/modules-2/files-2.1`), so a machine that has built the project resolves it offline.
- **Poetry projects without a lock, and `-e .`, are read.** A `pyproject.toml` with only
  `[tool.poetry.dependencies]` and no `poetry.lock` was an errored gap; its constraints are
  now written as PEP 440 (`^`, `~`, wildcards, exact versions, `python` and `markers`) and read
  direct-only, or resolved with `--resolve-python`. A requirements line that installs a
  project from the repo (`-e .`, `./pkg[dev]`) is replaced by that project's declared
  dependencies and extras when resolving. On the 185-repo resolution corpus no finding
  changed; one repo with `-e .` now resolves and one Poetry-only repo is read.
- **`fleetreach whatif` shows what bumps would do before any lockfile moves.** From a saved
  report, it takes bumps from `--bump [ECOSYSTEM:]PACKAGE@VERSION`, the first N items of the
  fix-first queue (`--top N`) or a `fix plan` file (`--plan`). It raises each copy below the
  target and matches the target again against the same OSV exports `fix plan` reads, in each
  ecosystem's own version order. Output: findings cleared, findings left open (and whether
  only some copies moved), advisories new on the target, and open findings by severity before
  and after, per bump and per repo (table or `-f json`). Records that alias each other count
  once. Go and GitHub Actions bumps use the report's fixed ranges, with no search for new
  advisories. Checked against a real `fix apply` and re-scan of 22 repos (cargo, npm, yarn,
  pnpm, uv, Pipfile, Actions): 104 verified edits, 360 findings on the bumped packages, 357
  predicted exactly, and none predicted cleared that stayed open. The two misses were
  copies moved by another bump's dependencies, which needs the registry. Its new findings on
  the queue targets match the 11 advisories `fix plan` steps around.
- **Function-level witnesses for npm and PyPI findings.** `scan --reachability` now follows
  calls, not only imports, from your JavaScript/TypeScript or Python source into installed
  dependency source, and a finding whose sink is reached shows the chain of calls with file
  and line. Calls resolve by name through imports, exports, classes, assigned locals and
  factory return values. It is positive-only: no chain changes nothing. Sinks come from 573
  proposed PyPI and npm records now bundled. On 40 real repos with dependencies installed it
  found 33 chains, 139 of 140 hops on a real call line, in 0.1 to 3 seconds per repo.
- **Sink proposals for Python and npm advisories.** The `sinkpropose` example takes
  `--ecosystem PyPI|npm` and proposes the functions a fix commit changed, read from Python
  (a hand-written reader) and JavaScript/TypeScript (`oxc_parser`) source. Sink records now
  validate PyPI and npm names. On fix commits for 600 advisories, a fresh hand-labelled sample
  was right for 9 of 10 PyPI and 5 of 10 npm records.
- **`scan --resolve-python` resolves unlocked Python dependency sets with uv.** A
  requirements file with unpinned names, or a `pyproject.toml` with no lockfile, is compiled
  with `uv pip compile --no-build --universal`, so transitive packages are matched too. uv
  gets the set on standard input in an empty directory and opens no file of the repo:
  fleetreach expands includes inside the repo and leaves out local paths, URLs and other
  options, naming them. Nothing is built. Resolved files are labelled partial, and a file uv
  cannot resolve keeps its label with uv's reason. On 185 real repos uv resolved 90 of 143
  sets (44 failures need a package with no wheel), and the scan found 355 more PyPI findings
  in 14 repos, matching an independent reading of uv's output.
- **`pyproject.toml`-only Python repos are scanned.** Their PEP 621 dependencies are read as
  direct-only instead of the repo being an errored gap.
- **Exploit maturity from Metasploit, nuclei and Exploit-DB.** `db sync --source exploits`
  reads which CVEs have public code in the three collections into one index (29,764 CVEs,
  2,570 with a Metasploit exploit module). Enriched findings then carry `exploit_maturity`
  (`attacked` for KEV, `mature`, `proof-of-concept`, `no-known-exploit`) and
  `exploit_sources`. Tables show `exploit` or `PoC` beside `KEV`, `fix-first` breaks ties on
  it, CycloneDX VEX carries it as properties, and SSVC counts public code as a public PoC.
  `scan --exploits-file` and `db import --exploits` take the index or the collections' own
  files. Without the index nothing is called `no-known-exploit`. The index matched an
  independent reading of the three files on all 29,764 CVEs.
- **`db ranges` checks published fixed versions against the fix commits.** For records that
  link a fix commit, it clones the repository (commits and tags only, never checked out) and
  asks which release tags contain the fix. Each `fixed` bound is `confirmed`,
  `fixed-earlier`, `fixed-later` (a false clean), `fix-missing` or `unverified`. `--out`
  writes corrected records as OSV overlays, marked `unreviewed`, with the evidence. A
  proposal must also agree with the registry's publish times. On 300 records each from npm,
  PyPI and Maven (1,523 bounds), 816 were confirmed and 14 corrections proposed. In the
  published archives, 10 of those were shown right and none wrong; 4 could not be decided
  (bundled builds). Two were real false cleans upstream: node-red-dashboard 2.26.2 and
  loguru 0.5.3 lack their fixes.
- **`scan --capabilities` reads what npm and PyPI package code can do.** It looks for network,
  shell, filesystem, env, eval, obfuscation, high-entropy strings, native binaries and install
  scripts. It warns on what a version adds over the previous release, such as `adds network
  access to install-time code (1.0.0 had none): install.js`. Install-time code, `setup.py`
  and obfuscation also warn on their own. Archives are checked against their hashes and read
  in memory: never unpacked, never run. Profiles are cached by hash. On the top 1,000 npm and
  PyPI packages, 6 and 13 in 1,000 warn.
- **`fix apply` updates Swift, Hex and Julia lockfiles** without running package code. It
  moves the `Package.resolved` pin to the tag's commit (`git ls-remote`). It rewrites the
  `mix.lock` entry with checksums and requirements from `repo.hex.pm`. It sets the
  `Manifest.toml` entry's version and tree hash from the General registry. An edit is
  refused, with the reason, when the target leaves a visible constraint unmet. Those are the
  range in `Package.swift`, `mix.exs` or `Project.toml`, a dependent's requirement, a locked
  dependency's version, or a changed dependency list. Transitive Swift pins are left alone.
- **`fix apply --open-pr` and `fix status` work on Gitea, Forgejo, Bitbucket Cloud and Data
  Center, and Azure DevOps**, through their APIs with the same tokens as the forge sources
  (`--forge gitea|forgejo|bitbucket|bitbucket-server|azure`, `--forge-api` for an unusual API
  base). Requests are opened, updated in place, and closed with a comment by
  `--close-obsolete`. Auto-merge stays off on these forges: none can hold it to the verified
  commit, and Forgejo 11 merged a commit pushed after it was turned on. Proven against a real
  Forgejo 11; Bitbucket and Azure against their documented API shapes only.
- **`[settings.fix]` sets when and how `fix apply` publishes.** `schedule` windows (with an
  IANA `timezone`) keep `--push` and `--open-pr` to working hours; outside them a run publishes
  nothing and says when the next window opens. `group = "repo"` or `"ssvc"` puts a repo's bumps
  on one branch and request, each applied and re-scanned on top of the last, with any that do
  not verify undone and left out. `automerge = "verified"` turns on GitHub's or GitLab's own
  auto-merge for the verified commit, except for drafts and breaking bumps; on GitHub a repo
  with no required checks pending is merged at once, and the summary says so. `rollout = [1, 5]`
  spreads a campaign in waves: the next wave opens once the last one merged, and a request
  closed unmerged stops it.
- **`fleetreach serve` shows the history report and records triage decisions in a browser.**
  It reads the `scan --history-dir` directory and the triage files on every request, lists the
  newest run's findings with their decisions, and writes a decision from a form as the same file
  and log entry `triage set` writes; it never runs git. By default it listens on loopback only and
  records decisions as `--by`, git's `user.name` or `$USER`. Behind a reverse proxy that signs
  people in (`--trust-proxy`), it serves only that proxy and takes the reviewer from its identity
  header. Forms carry a per-process token and cross-site posts are refused; the one script
  allowed to run is the report's own, by hash. Release binaries include it; with cargo, build
  with `--features serve` (pure Rust).
- **`sbom -f spdx3` writes SPDX 3.0.1 JSON-LD.** The same packages, hashes, licenses and graph
  as the other formats, and two things SPDX 2.3 cannot say: each dependency relationship carries
  its `completeness`, and a development-only dependency has the `development` scope. With
  `--report`, findings are vulnerabilities with VEX relationships (`affects`, `doesNotAffect`
  with the justification or a person's reason, `underInvestigationFor`), CVSS scores and KEV
  entries. Every document of the demo fleet, and of two real repos with 870 packages, passes
  `spdx3-validate` (the SPDX 3.0.1 JSON schema and SHACL model).
- **`sbom --check-ntia` checks each SBOM for the NTIA minimum elements** (2021), as written, in
  every format: author, timestamp, and a supplier, name, version and purl or CPE for every
  component, and the repo's dependencies. It exits 1 when one is missing, and says which and
  how many components lack it, agreeing with sbomqs's NTIA 2021 profile on all 44 documents
  compared. Lockfiles name no supplier, so that element is reported missing, never filled in.
- **SPDX 3.0 SBOMs are read as scan input**, and found by `discover` as `.spdx3.json`. Roots,
  dependency relationships, development and test scopes and completeness come from the
  document's own graph; it is complete only when every dependency relationship says so.
- **`scan --reachability=jvm` sets aside Java findings no code path reaches.** fleetreach reads
  every Java archive in each image as data, never running it, and builds one call graph from the
  service's entry points. Those are the classes in the image's `jvm_app` packages
  (`--jvm-app org.example` for `--image`), or a Spring Boot fat jar's or a war's own classes. A
  Maven finding is judged against the reviewed sink records built into fleetreach. It is
  reachable, with the chain from an entry point to a method the fix changes; not reachable,
  when no image it occurs in reaches one, which makes it `not_affected` in VEX and SARIF; or
  unknown, with the reason. Records whose sinks are loaded by name (JDBC drivers, JCA providers)
  never say "not reachable", and neither do unreviewed ones. On 63 public Java service images
  this sets aside 12.9% of Maven findings (13.9% of high and critical). On 79 CVE reproducers, 86
  of the 87 vulnerable methods that ran were in the graph; the one missed is loaded by a name
  built at run time.
- **`licenses` finds copyleft that conflicts with the repo using it.** Give a repo
  `license = "proprietary"` (or an SPDX expression) in `fleet.toml` and a runtime dependency is a
  conflict when its license requires GPL, AGPL, SSPL, OSL or EUPL in proprietary or permissive
  code, AGPL or SSPL in a repo whose exposure is `open`, or Apache-2.0 or a v3 GNU license in a
  `GPL-2.0-only` repo. `MIT OR GPL-3.0-only` requires neither and never conflicts.
  `[settings.licenses] conflicts` is `warn` by default; `deny` makes the run exit 1.
- **`licenses --notice DIR` writes one attribution file per repo**: the license texts its
  runtime packages ship, grouped where identical, their `NOTICE` files, the license files of
  code they bundle in subdirectories, and a list of the packages whose files are not on the
  machine. Checked against license-checker and cargo-about. The download cache now keeps `NOTICE` files;
  an entry written by 1.6.0 is fetched again by `--download`.
- **`-f csaf-vex` writes the VEX statements as a CSAF 2.0 document**, of the VEX profile, for
  tools and portals that read CSAF. Repos are products, packages are components with their
  purls, and advisories that share a CVE share one entry. `--csaf-namespace` (or
  `[settings.vex] namespace`, or the domain of an email author) names the publisher. Trivy
  0.73 applies it to images and directories. Grype matches CSAF only by its own exact package
  URLs, so use OpenVEX with Grype. `--csaf-cve-only` leaves out advisories with no CVE, which
  Trivy 0.73 cannot read.
- **`sbom --report R --separate-vex` writes a CycloneDX VEX beside each CycloneDX SBOM**, its
  findings pointing at the SBOM's components by BOM-Link and named by CVE where there is one,
  so `trivy sbom --vex` applies it.
- **`scan --vex FILE` sets findings aside on VEX documents others wrote**: OpenVEX, CycloneDX
  VEX and CSAF VEX, repeatable, or `[settings.vex] files` for every run. A statement about one
  of your repos applies to that repo only; one about a package and no repo applies to that
  package wherever it is; one about another product, such as a vendor's platform, applies
  nowhere. The latest statement wins, and a `not_affected` with no justification or impact
  statement makes the document unusable. fleetreach's own documents in all three formats read
  back to exactly what their assertions set aside.
- **`--vex-key` requires each VEX file to be signed** with `cosign sign-blob` by a named key:
  a `.sig` beside the file (cosign 2) or a bundle (cosign 3), checked offline. A file no named
  key signed is refused with a warning, and its findings stand.
- **A saved JSON report keeps what a person set aside**, under `set_aside`: each advisory's
  occurrences with the reason, the label and the approver. A CycloneDX or SPDX SBOM made from
  the report shows them as not affected (an accepted risk as `exploitable`, `will_not_fix`),
  where before they were left out.

### Changed

- **`--reachability` runs about 4x faster on npm and PyPI repos.** The npm and PyPI import
  graphs analyzed one repo at a time, reading every installed file serially; repos, installed
  packages and first-party files are now read in parallel. On 40 real npm and PyPI repos a
  scan with `--reachability` went from 36 s to 9.5 s with identical output.
- **SARIF output runs about 2.5x faster.** Every advisory of one package searched the
  lockfile for the same line; each search is now done once. On the same 40 repos, 2.6 s to
  1.0 s, byte-identical. The lockfile lines SARIF points at are now also found in parallel,
  each lockfile split into lines once: on 10,471 repos SARIF output takes 4.9 s instead of
  9.9 s, byte-identical.
- **`fleetreach serve` pages load about 20x faster.** Every page read the whole history again,
  inflating and parsing every snapshot; the history is now read once and again only when one
  of its files changes, so a new scan shows on the next page without a restart. The overview
  also works out each run's open findings, and what was open before the newest run, once per
  history read and reuses them. On a 12-run history
  of 10,471 repos the overview takes 45 ms instead of 0.8 to 1.3 s, the triage list 14 ms, and
  the server holds 1.0 GB instead of 2.2 GB, with the same pages.
- **Scans read only the npm, PyPI and crates.io advisories they need.** Loading the
  advisories of a few packages used to inflate every record of the export to see its package
  names; the names of each record are now saved next to the export (`all.zip.names.json`, tied
  to the export's central directory, so any other export or a damaged file is passed over and
  the records are read as before). One npm repo scans in 0.15 s instead of 0.43 s, using
  0.15 CPU-seconds instead of 5.2; 40 npm and PyPI repos in 0.24 s instead of 0.57 s;
  `whatif` takes 0.06 s instead of 0.37 s and `fix plan` 0.40 s instead of 0.74 s. Reports,
  SARIF, plans and whatif output are byte-identical.
- **Reading the history takes half the time.** Snapshots are read in parallel and parsed as
  they inflate, and what was open before the newest run is worked out in one pass. On the same
  history `notify` takes 0.63 s instead of 1.34 s at slightly lower peak memory, and recording
  a run with `scan --history-dir` saves about 0.7 s. `notify`, `report html`, every
  `history` command and the recorded index are byte-identical.
- **Faster .NET and JVM graphs.** An image's .NET assemblies are parsed on all cores (graphs
  still run one at a time, to bound memory), and both call graphs hash with foldhash, seeded per
  process so names in a crafted image cannot pile into one bucket, instead of SipHash. On the 11
  .NET app images `scan --reachability=dotnet` takes 9.2 s instead of 16.5 s at the same peak
  memory; a 216-jar JVM graph 2.6 s instead of 3.0 s. Output is byte-identical.
- **Less memory reading OSV exports.** The `all.zip` exports are now read member by member
  from disk with an in-house ZIP reader (ZIP64 included, every member checked against its size
  and CRC-32), instead of holding the whole archive and an index of every member name in
  memory. A scan of one npm repo peaks at 453 MB instead of 832 MB, a PyPI repo at 323 MB
  instead of 392 MB, with the same speed and byte-identical reports; distro exports for images
  no longer re-read the central directory per chunk.
- **Scans load only the npm and PyPI advisories the fleet needs.** The package names each npm
  and PyPI source declares are read first, and only their records are loaded from the two
  largest exports. A lookup of any other name is noticed, and the repos are then scanned
  again with the whole exports, so a missed name costs time, never a finding. On 10,471 repos
  the scan peaks at 436 MB instead of 1,266 MB (22 polyglot repos: 155 MB instead of
  1,020 MB) at the same speed, with byte-identical reports. Image scans, SBOM inputs and
  `--incremental` load the whole exports as before.
- **Faster image scans.** A distro record is first read for its package names only, and in full
  only when it names a package installed in the images: one Debian image scans in 1.6 s and
  350 MB instead of 2.6 s and 588 MB; 25 mixed images peak at 1.9 GB instead of 2.6 GB, with
  byte-identical reports.
- **`vex verify` leaves JVM witnesses out and says how many.** It re-derives the Rust engine's
  `not_affected` statements by building the repos. A JVM statement comes from scanning images,
  so `scan --reachability=jvm` derives it again; counted as re-derived, it would pass without
  being checked.
- **`whatif` and `fix plan` read only the advisories of the packages they ask about.** Each
  OSV record is first read just far enough to see its package names, and only records naming a
  bumped package are parsed in full. Peak memory on a 30-repo fleet went from about 1 GB to
  about 600 MB for `whatif` and from 836 MB to 607 MB for `fix plan`, with byte-identical output.

### Fixed

- **A busy or rate-limited POM repository no longer reads as missing POMs without a word.**
  A 429 or 5xx is retried three times (waiting as `Retry-After` asks, at most 10 s); if the
  repository still refuses, fleetreach stops asking it for the rest of the run and says so
  once, naming the host, and coverage stays partial.
- **SARIF output hung on a workflow linked to a device, and `fix apply` wrote through
  linked workflows.** To name the workflow that uses an action, SARIF read the repo's
  workflow files with no guard, so one linked to `/dev/zero` never finished. The Actions bump
  in `fix apply` read and rewrote workflow files through links, so a linked workflow or
  workflows directory sent the edit to wherever it pointed. SARIF now reads through the same
  guard as every other repo file, `fix apply` refuses a linked workflow or directory and keeps
  every read inside its work tree, and the static-reachability cache key no longer reads a
  device. A few other repo reads (a crate's own `Cargo.toml` for VEX, triage files, the
  lockfiles `fix apply` checks) moved to the guard too.
- **`-f csaf-vex` without a publisher namespace failed only after the scan.** It is now
  reported before any repo is read, like a missing author.
- **A damaged lockfile could scan as a smaller, clean project.** The `Gemfile.lock`,
  `mix.lock`, `go.mod`, `gradle.lockfile` and yarn berry readers skipped what they did not
  know, so a stray line at the left margin ended a `Gemfile.lock` `GEM` section early (14 of
  41 findings lost on one real file), and a file cut short read as a clean project. Each is
  now checked for the shape its tool writes: Bundler's section headers and `DEPENDENCIES`,
  a closed `%{...}` map, closed `require (` blocks, Gradle's closing `empty=` line, and an
  entry for every package a berry entry depends on. A damaged file is an errored repo. Every
  real file in the test corpus passes: 37 `Gemfile.lock`, 40 `mix.lock`, 5,656 `go.mod`, 40
  `yarn.lock`. `go.mod` blocks written `require(` are also read now.
- **A `resolutions` override in a berry `yarn.lock` made the forced package dev.** The
  lockfile keys the entry by the forced range, while the packages that depend on it keep the
  range they asked for, so the edge pointed nowhere and a runtime package (lodash in
  spectral) read as dev, which does not gate by default. A dependency no entry lists now
  links to the entries under its name.
- **Block YAML nested a few thousand deep aborted the scan.** The YAML reader limits only
  flow nesting (`[[[`), so a `pnpm-lock.yaml` or berry `yarn.lock` nesting blocks deeply
  overflowed the stack. A file nesting past 256 levels is now refused; real lockfiles nest
  about 30.
- **A long dependency chain took quadratic time.** npm, Hex, Julia and Maven scans built the
  introducer chain for every package; a 100,000-package chain in a `package-lock.json` ran
  past a minute. The chain is now built only for a package with an advisory, which takes
  about a second.
- **An errored repo said why only in the JSON.** The table and the other text formats now
  print each errored repo's reason to stderr.
- **A crafted JavaScript or Python file could abort or stall a `--reachability` scan.** The
  call graphs read every installed package's source. Deep nesting inside the 2 MiB file cap
  (`((((...`, `a=a=a=...`, nested arrow functions) overflowed the parser's stack, which ends
  the process where no error handling can catch it, and long call or attribute chains, or
  nested calls in Python, took quadratic time and memory (53 GB on one file). Each file is
  now parsed on its own thread with a stack sized from a bound on what the file can need,
  chains keep at most 64 links, and Python matches brackets once per line. 43 crafted shapes
  read in 200 ms at most, 48,000 mutated real files in 2.5 ms at most, and the call graphs on
  40 real repos are unchanged.
- **A crafted Java class could crash a JVM scan.** `cafebabe` 0.9 panics on a name entry that
  is not valid modified UTF-8; such a class is now unread, a gap in the read like any other
  class it rejects. 1.1 million mutated real class files read with no panic, the slowest in
  3 ms.
- **A Java archive could inflate without bound.** Entries that share one compressed stream,
  or jars nested in a fat jar, could make a few megabytes inflate terabytes: a 3 MB jar held a
  JVM scan for minutes. One archive now inflates to at most 64 MiB plus 32 times its size,
  nested jars included, and the rest is one gap. 13,498 real jars inflate to at most 7 times
  their size, and their graphs are unchanged.
- **JVM witness chains changed from run to run.** Which caller a chain named depended on the
  hash seed; the graph now resolves calls in the order it saw them, so the same image gives
  the same chain.
- **`-f vex` and `-f csaf-vex` without an author failed only after the scan.** The missing
  author (`--vex-author` or `settings.vex.author`) is now reported before any repo is read,
  with the same usage error.
- **Unread .NET and Composer files in images were filed under RubyGems.** A `.deps.json` or
  Composer `installed.json` an image holds but that does not parse is a coverage gap; it now
  names NuGet or Packagist instead of RubyGems.
- **NuGet packages that put no code into an image were reported.** A `.deps.json` lists every
  package the build resolved, also those whose assemblies it dropped because the runtime pack
  ships a newer copy (`System.Private.Uri/4.3.0` beside .NET 6, `System.Text.Encodings.Web`
  4.7.0 in a plugin of an 8.0 host) and build-only tools (`Microsoft.Build.Tasks.Git`). A
  package with no `runtime`, `runtimeTargets` or `native` assets in the runtime target is now
  left out, as Trivy does; one the target does not describe is kept. On 11 .NET app images, 22
  of 82 NuGet findings went, 8 advisories entirely, and nothing else changed.
- **.NET graphs reached a method the runtime could not call.** A new virtual method on a type
  implementing any interface from outside the graph counted as the runtime's way in, so
  ImageSharp's `Image<T>.Accept` was reached as soon as an image was made (`Image` is
  `IDisposable`), with a chain that skipped real calls. The graph now reads the interfaces of
  the image's shared frameworks (metadata only) and keeps such a method only under a name one
  of them declares; an interface it cannot read may still declare anything. The JIT check
  still misses nothing.
- **.NET graphs mixed up copies of one type in different assemblies.** A package can carry
  its own internal copy of a type the runtime defines too (`ManagedWebSocket` in
  `System.Net.WebSockets.WebSocketProtocol` and in `System.Net.WebSockets`), and compilers
  embed the same helper types in every assembly. A call, type token, field or base type
  resolved by name to every copy, so Kavita's WebSocket code reached the old package's
  `ReceiveAsyncPrivate` through the runtime's own copy, and a base type could resolve to the
  wrong assembly's copy and lose its overrides. A reference now means the referring assembly's
  own type when it defines one, and a record's sinks count only in its packages' assemblies.
  The JIT check still misses nothing; reached methods fell (33,373 to 32,761 on the SqlClient
  app) and rose where the right base type was found (2,598 to 2,610).

- **JVM witnesses named a temporary file.** A chain that started at a resource (a
  `META-INF/services` file, `web.xml`) named the scan's temporary copy of its archive, a path
  that changed on every run; it now names the archive's path in the image.

- **`licenses --detect` reads npm packages installed below another package.** A second version
  sits at `node_modules/a/node_modules/b`, and only the top-level copy was looked at, so the
  others kept their declared license unchecked. pnpm's `.pnpm` store is read the same way.
- **VEX for images had no statements, and OS packages were named wrongly.** Images had no
  product id, so `-f vex` said nothing about them. OS packages carried the SemVer form of their
  version (`1.2.3-r.3`) and only the source package's name. Statements now name each binary
  package at its installed version, an epoch as the `epoch` qualifier (and, for Debian, in the
  version as Grype writes it), under every namespace Trivy and Grype use for the distribution
  (`rocky` for Rocky Linux, `ol` and `oracle`, `sles` and `suse`). Checked with
  `docs/differential/vex_consumers.py` on Alpine, Debian and Rocky Linux images: Trivy and
  Grype set aside every asserted finding they report.

## [1.6.0] - 2026-11-05

### Added

- **SBOM input matches OS packages.** `pkg:deb`, `pkg:apk` and `pkg:rpm` components go to the same
  distro matchers as an image, so a Syft or Trivy image SBOM scans in full. The release comes from
  the `distro` qualifier or the operating-system component, and each package's source from what
  the tool wrote. A document that names no release, or several, is a coverage gap, and so is one
  that names no source packages. SPDX has no module stream labels, so on a Red Hat module build
  the scan says it may differ from the image.
- **`fix plan` reads each repo's ranges before it proposes a target**, for npm's
  `package-lock.json` and for Cargo. A target your own manifest leaves out is a new
  `manifest-bump` edit: `fix apply` raises the range, an exact pin included, then updates the
  lock. A target a published package leaves out, peer ranges included, is blocked and names the
  package to update first, rather than failing in `fix apply`.
- **`fix plan` keeps targets clear of advisories of their own.** The queue only knows the
  advisories some repo already has, so a target could carry one that starts above every installed
  version, and the re-scan then refused the bump. The plan now reads the OSV exports (`--osv-dir`,
  or wherever a scan finds them) and moves the target to the lowest fix that adds nothing. This
  also restores Maven's four-part fixes such as `3.41.2.2`, which the plan had cut to a version
  that does not exist.
- **`scan --reachability` builds witness chains for Ruby, PHP, .NET, Java and Kotlin, Elixir and
  Swift.** A chain starts at the import line in your source and follows the lockfile, for example
  `imported at app/models/user.rb:3 via loofah → nokogiri`. Positive-only, like Python's. JSON
  reports the line as `reachability.import_site`.
- **SARIF `codeFlows` follow import chains**, for npm and Python too, and start at the import line
  where it is known.
- **`licenses --detect` reads the license files packages ship**, with the `spdx` crate's own
  matcher over the SPDX texts, in pure Rust, on this machine. A package nothing declared takes
  the license its files say, unless one of them could not be recognized. A package whose files
  name a license its declaration does not account for is a mismatch, with its verdict in
  `[settings.licenses] mismatch`.
- **`licenses --detect --download` reads packages that are not on this machine.** It fetches each
  public package's archive for npm, Cargo, PyPI, RubyGems, Hex and Go, checks it against the
  lockfile's hash (the tree hash in `go.sum` for Go), and keeps only its license files in a cache
  keyed by that hash, which `--detect` then reads offline.
- **SBOM input takes CycloneDX XML, SPDX tag-value and GitHub's dependency graph export**, and
  finds SBOMs by itself. `[settings.sbom] discover` scans the SBOMs in a repo with nothing else
  to read, `[[repo]] sbom_discover` sets that per repo, and `[[source]] sbom_assets` fetches
  those on the latest release on `fleet sync` (GitHub, Gitea, Forgejo). An SBOM older than the
  newest lockfile commit is a coverage gap.
- **`pkg:golang` and `pkg:cargo` in an SBOM are now matched**, with RustSec and the crates.io
  export for Rust. Go names compare without case where a purl lost it, as Trivy's do. Direct
  dependencies are found below the lockfile and project nodes Trivy puts under the root, in
  every ecosystem.
- **`scan --health` asks registries what a lockfile cannot show**: npm and NuGet deprecations,
  PyPI, RubyGems, crates.io and NuGet yanks, Packagist `abandoned` with the replacement, Go
  deprecations and retractions, Hex retirements and Maven relocations, plus archived GitHub
  repos with a token and low OpenSSF Scorecards with `[settings.health] min_scorecard`. Only
  public packages are sent, and answers are cached for a week. A package with no answer is a
  coverage gap, never clean.
- **Scope for Cargo, Bundler, Hex, NuGet and Go, and a gate per scope.** A package only dev
  dependencies lead to is now `scope: dev` in these five too, so `--ignore-dev-deps`, SBOM
  `scope: excluded` and license `scope = "runtime"` cover them. `--fail-on-dev` and
  `[settings.gate.scope] dev` give dev packages their own floor, or `never`; `diff --base` takes
  the flag. Known malware keeps the runtime floor. Whatever cannot be read stays runtime: against
  `cargo tree`, `go list`, Bundler and `mix deps` on real repos, no package those tools ship was
  called dev. Go needs the dependency source, so run `go mod download` first. See "Gate on what
  ships".
- **`diff --base <ref>` says what a change brought in.** New findings are compared per
  occurrence and placed by git: brought in, with the lockfile line and the manifest line that
  caused it; already at the merge base, so the advisory is what changed, which no longer
  gates; or not placed, which still gates. Fixture PRs from real lockfiles passed on all twelve
  ecosystems.
- SARIF regions now also cover `gradle.lockfile`, `packages.config`, `pylock.toml` and
  requirements files under other names.
- **Five more `[[source]]` kinds**: `gitea`, `forgejo`, `bitbucket` (Cloud), `bitbucket-server`
  (Data Center) and `azure` (Azure DevOps). `topics` on a forge without topics is a config
  error. Listings refuse a `next` link off the API, a pager that repeats, and Azure's redirect
  to sign-in. A sync without a token now says that only public repos were listed.
- **`fleet sync` and `scan --sync` report the repos added, removed and renamed** since the last
  listing, by the forge's own repo id, and `--history-dir` appends them to `inventory.jsonl`.
- **`SSL_CERT_FILE` sets the trusted roots for forge listings**, for a forge behind a private CA.
- A repo with nothing fleetreach reads now says "no recognized lockfile or manifest", not "no
  Cargo.lock found".
- **`scan --incremental` reuses a repo's findings** while the binary, the advisory data for its
  ecosystems and the files a scan reads are unchanged, and skips loading the advisory data of any
  ecosystem with nothing to re-scan. On 10,471 repos a warm run took about half the time and a
  third of the memory, with byte-identical output. A fleet of a few large monorepos gains
  nothing; see the new scale benchmark page. Maven, Gradle, SBOM inputs and govulncheck are
  never reused.
- **`db sync` updates an export record by record.** It reads the ecosystem's `modified_id.csv`,
  fetches only the changed records and rewrites `all.zip`, instead of downloading the whole zip
  again. A cache five days old took 8 seconds, against 300 MB before. Every one of 329,822
  records then matched a fresh download byte for byte, and a 121-repo scan came out identical.
  Anything doubtful falls back to the whole export; `--force` always downloads it. Releases
  like `Debian:12` have no listing on osv.dev and stay whole downloads.
- **`db snapshot` and `--db-snapshot` pin a run.** The manifest hashes every source; a pinned
  scan is offline and exits 2 unless the directory holds exactly those files.
- **`db bundle` and `db import --bundle` carry all the advisory data in one tar**: OSV and
  distro exports, RustSec, KEV, EPSS, CVE and CSAF indexes, and the NVD and Vulnrichment caches.
  `db sync --source` gains `rustsec`, `kev`, `epss`, `nvd` and `vulnrichment`. An imported
  scan with `--enrich` matched the online one on 1,182 findings, run with network access denied,
  and 44 images matched on 19,286 findings.
- `scan --offline --enrich` reads KEV, EPSS, NVD scores and Vulnrichment from the data directory.
- `--db` on a RustSec clone reports its commit, so `--max-db-age` works there. It used to be
  unknown.
- **`fix apply` handles pnpm, yarn, Composer, Bundler, NuGet and Maven.** Lockfile managers
  update with scripts and plugins off; NuGet and Maven change the declared version, or the
  property it reads. Checked on 30 throwaway repos across all twelve update paths: 28 edits
  verified, and every changed lockfile passed the package manager's frozen install.
- **`fix apply` keeps its pull requests current.** A re-run leaves a branch verified on the
  current base alone, rebuilds a stale one, and skips closed or merged requests and branches
  someone else pushed to. `--close-obsolete` closes requests the plan no longer wants, only
  in repos it scanned.
- `fix apply --max-prs`, `--canary` and `--stop-after-failures` limit a rollout.
- **Gradle builds without a lockfile are scanned.** They were skipped before. Version catalogs
  and literal declarations resolve through the POM resolver, with the highest version winning,
  and the result is always marked partial. Against real Gradle, 163 of 173 packages matched on
  Spring PetClinic, 17 of 18 on Aeron and 71 of 109 on the Airflow Java SDK.
- Releases add static musl builds for Linux x86-64 and ARM64, and a Windows ARM64 build. The
  install script picks musl on Alpine.
- `pnpm-lock.yaml` version 5 is read, and a `catalog:` dependency is proven to use the version
  its importer records. Across 39 real lockfiles, the package sets match `pnpm list`, `yarn list`,
  `yarn info` and `bun pm ls` on 35; the other four are explained in
  `docs/specs/16-a-plus.md`.
- SBOM components carry hashes from the lockfile: Cargo, npm, pnpm, yarn v1, bun, Bundler, mix,
  uv, Poetry, pylock and Composer. Sampled against registry downloads: 442 hashes across ten
  lockfile formats, all matching. NuGet's `contentHash` is left out, since it skips the package
  signature and matched none of 25 downloads.
- **`sbom` writes CycloneDX 1.7 by default,** with `--cyclonedx-version 1.6` on request, and XML
  with `-f cyclonedx-xml`. All 121 test BOMs pass the official schemas in both versions, the XML
  holds the same content as the JSON, and Grype and Trivy read them.
- CI runs the whole test suite in a network namespace with no route out, so a test or feature
  that needs the network fails the build.
- `ci/fleetreach.gitlab-ci.yml`, a template a GitLab pipeline can include to scan a repo and keep
  the SARIF.
- SARIF results point at the package's line in its lockfile, and carry the dependency chain as
  `codeFlows`. A package whose line cannot be found keeps a file-level location. Checked on 30
  repos and 600 real lockfiles: the output passes the SARIF 2.1.0 schema, and every line named
  holds its package.
- `history epss` flags open advisories whose EPSS rose by 0.1 or entered the top 5%, and exits 1
  on any. Findings now carry `epss_percentile`. Checked by replaying 31 days of real EPSS files
  against a frozen fleet.
- `scan --why --all-paths` lists every path into a package, shortest first and capped by
  `--max-paths`. `scan --versions <pkg>` lists each version across the fleet with its repos.
  Both, and plain `--why`, take `-f json`.
- `[[settings.ignore]]` takes `expires` and `owner`. After its last day an ignore stops
  hiding its finding, and the scan fails while the finding is open, as for triage decisions.
- `[[settings.context.tag_rules]]` sets SSVC exposure and impact from repo tags and forge
  topics. The report's `context[].set_by` names the rule behind each value.
- **Triage files** (spec 16, row 6). One decision per finding, in
  `triage/<advisory>/<ecosystem>-<package>.toml` beside `fleet.toml`: state (`affected`,
  `in_triage`, `accepted_risk`, `false_positive`, `not_affected`, `fixed`), assignee, expiry,
  justification, repos and an append-only log. Two people triaging different findings never
  touch the same file, so branches merge clean, and git is the audit trail. `fleetreach triage
  set` and `list` write and show them, and `scan` reads them: `accepted_risk`, `false_positive`
  and `not_affected` set a finding aside until they expire.
  An expired decision puts the finding back and fails the run. A file that cannot be read exits
  2. `triage export -f openvex` publishes the decisions, and Trivy and Grype honor them: an
  accepted risk is `affected`, never `not_affected`, so other tools keep reporting it.
- Rust binaries in images are read: the crates `cargo auditable` lists in the binary are matched
  against RustSec, as Go binaries are against the Go database. A Rust binary with no such list
  is a coverage gap.
- `fleetreach scan` without a `fleet.toml` scans the git work tree around the current
  directory as a one-repo fleet (a note on stderr says so); `scan --repo <DIR>` does the same
  for any directory. An explicit `-c` that does not exist is still an error.
- **Container images** (spec 16, row 10, phase 1). `[[image]]` in `fleet.toml` (`id`, `path`,
  optional `platform` and `distro`, and the repo context fields) and `scan --image <path>`
  (repeatable; no `fleet.toml` needed) scan a `docker save` or OCI-layout tarball, an
  OCI-layout directory, or a root filesystem. Layers merge with OCI whiteouts, and layers
  named by digest are verified. Nothing in the image runs. The distribution comes from
  `/etc/os-release`: Debian, Ubuntu (with Ubuntu Pro for `+esm` packages), Alpine, Wolfi,
  Chainguard, MinimOS, Alpaquita, Echo, CleanStart, and Root's patched packages. dpkg
  `status`, distroless `status.d` and apk `installed` are read, each binary package matched
  under its source package against the osv.dev distro export, with dpkg's and apk-tools'
  version orderings. Unfixed Debian and Ubuntu advisories are findings marked `no fix yet`
  with their urgency; `--distro-ignore-unimportant` drops the `unimportant` and `negligible`
  ones. Lockfiles and installed Python and npm packages in the image go through the
  language matchers, skipping files an OS package owns. Fail-closed: an unreadable image or a
  missing distro export is an errored target, and an unknown distribution or release or an
  unreadable package database is a coverage gap. New crate `fleetreach-os`.
- **Registry pull** (spec 16, row 10, phase 3; network build). `--image docker://<reference>`
  and `ref = "..."` in `[[image]]` pull from any OCI registry, with logins from Docker's config
  and credential helpers. The manifest, config and every layer are checked against their
  digests, a tag's digest is computed here and recorded in the report's provenance, and blobs
  are cached by digest, so a digest pulled before also scans with `--offline`. Logins go only
  to the registry and a token service on its domain, over TLS.
- **VEX attached to images** (spec 16, row 10, phase 3). `--vex-oci` reads OpenVEX attestations
  on images pulled from registries: OCI 1.1 referrers, the referrers tag, and cosign's `.att`
  tag, on the image and its index. A document sets findings aside only when `--vex-oci-key`
  verifies its signature, or with `--vex-oci-unsigned`; others are listed in the report and
  change nothing. A document naming another image is refused. The latest statement decides,
  and a source package or a many-CVE advisory goes only when every binary and CVE is covered.
- **Go binaries, Composer and .NET in images** (spec 16, row 10). Go binaries are read for their
  build info and matched as Go modules and `stdlib`. Composer's `installed.json`, .NET's
  `.deps.json`, any `package.json` and bare `.egg-info` files are read as installed packages.
- **Image differential** (spec 16, row 10, phase 3). 217 public images against Trivy 0.73.0 and
  Grype v0.121.1, every difference in findings classified, in `docs/differential`.
- **Image layers and base images** (spec 16, row 10, phase 3). Every finding in an image names
  the layer that put the package there, with its digest and build step, and whether it belongs
  to the base image. Where several images share a base, the report's `base_images` and the
  table's closing section say how many findings its layers hold and how many a rebuild can
  clear. Layers match Trivy 0.73.0 on Debian, Alpine and Rocky images.
- **Java archives and gems inside images** (spec 16, row 10). `.jar`, `.war`, `.ear`, `.par`,
  `.kar`, `.jpi` and `.hpi` files are read through, nested archives included, and matched as
  Maven packages; installed gems (`specifications/*.gemspec`) are matched as RubyGems. An
  archive is identified by its `pom.properties`, by its file name with the group settled from
  its OSGi bundle name and class packages, or by its OSGi manifest. Nothing in an archive is
  run. An archive that cannot be placed is a coverage gap, never a guess. On Tomcat, Jenkins,
  Elasticsearch, Spring and Ruby images, every package Trivy 0.73.0 reports as vulnerable is
  reported, and fleetreach also reaches jars inside Jenkins plugins that Trivy does not.
- **rpm-based container images** (spec 16, row 10, phase 2). Red Hat Enterprise Linux (UBI),
  AlmaLinux, Rocky Linux, openSUSE Leap and Tumbleweed, SUSE Linux Enterprise 15 and SLE
  Micro, Azure Linux and CBL-Mariner 2, Mageia and openEuler images are matched against their
  osv.dev exports. The rpm database is read in pure Rust in all three formats rpm has used
  (SQLite with its write-ahead log, Berkeley DB, NDB), with no `rpm` and no database library;
  an empty stray database beside the real one (Oracle Linux 9 ships one) is skipped, and two
  that disagree are a coverage gap. Versions compare with rpm's ordering (epoch, `~`, `^`).
  Red Hat and AlmaLinux advisories name binary packages, so there each binary is matched on
  its own; elsewhere binaries fold into their source rpm. AlmaLinux's bug fix and
  enhancement advisories (ALBA, ALEA) that name no CVE are not reported as vulnerabilities.
  Package names are `<distro>/<package>` (`rocky-linux/openssl`, `redhat/openssl-libs`),
  ecosystem `rpm`.
- **Vendor feeds for rpm distributions osv.dev lacks** (spec 16, row 10, phase 2). Amazon
  Linux 2 and 2023 (the core repository's `updateinfo.xml`, the ALAS advisories `yum
  updateinfo` reads), Oracle Linux 7 to 10 (Oracle's OVAL, the ELSA advisories) and Photon OS
  3.0 to 5.0 (VMware's CVE metadata) are fetched from the vendor, converted to OSV records and
  cached like an osv.dev export, so their images are matched instead of being gaps. Findings
  link the vendor's advisory page. Oracle's advisories for a module stream match only
  packages from that stream (from the package's modularity label, or for an older build
  without one, the stream `/etc/dnf/modules.d` enables). Conversion is strict: a feed whose
  shape is not understood fails the sync rather than load partly. Validated against the
  distributions' own tools: equal to `yum updateinfo list security` on Amazon Linux 2 (261
  advisory and package pairs) and `dnf updateinfo list --security` on Amazon Linux 2023
  (260) and Oracle Linux 8 with module streams enabled (371 of 374; the other 3 are one ELSA
  Oracle's OVAL omits, a reissue whose CVEs a later ELSA in the feed covers), and to the raw
  Photon feed evaluated with rpm's comparator (252).
- **Bottlerocket** (spec 16, row 10, phase 2). A Bottlerocket root filesystem is matched against
  Bottlerocket's own advisory feed (`updateinfo.xml.gz`, BRSA and GHSA advisories for every
  variant and version; `db sync --distros Bottlerocket`), with its packages read from
  `/usr/share/bottlerocket/application-inventory.json`, as Bottlerocket ships no rpm database.
  Both the `bottlerocket-` prefixed and the short package names in an advisory are matched, and
  epochs are kept, which Bottlerocket's switch from OS-release to upstream versions relies on.
  Findings link the advisory's page. Validated on 1.66.0 and 1.68.1: equal to the feed evaluated
  with rpm's comparator, and a superset of Trivy 0.73.0 (its 200 findings plus 130 kernel
  advisories its data does not carry yet).
- **Red Hat's unfixed CVEs in RHEL and UBI images** (spec 16, row 10, phase 2). The CSAF VEX
  index (`db sync --source csaf:redhat` or `db import --csaf`) is turned into a per-release
  export on the first scan that needs it (about 20 seconds, then cached until the index
  changes) and consulted where the release's osv.dev records do not name a CVE for a package:
  CVEs Red Hat lists as affected, will not fix, fix deferred, out of support scope or under
  investigation become findings marked `no fix yet` with that status, and fixes on the
  release's main stream that osv.dev has not imported yet are reported with their version.
  Red Hat lists open CVEs by source package, so a binary package also matches its source
  package's open statuses, unless Red Hat says something about the binary itself (a binary
  it lists as not affected stays clean). Module streams (`php:7.3`) gate their entries as
  for Oracle. Findings link Red Hat's CVE page. A RHEL image scanned without the index is a
  coverage gap naming the command; a plain `db sync` leaves the derived exports to the scan
  instead of asking osv.dev for them. Validated against Trivy 0.73.0 on UBI 8.8 and UBI 9:
  every one of Trivy's 947 and 538 findings is reported with the same status; the 19 and 2
  more are Red Hat's open statuses for the binary's source package, which Trivy matches by
  binary name only.
- **Module streams on RHEL, AlmaLinux and Rocky Linux images** (spec 16, row 10, phase 2).
  osv.dev's records for these distributions carry no module stream, so an advisory for
  `php:8.0` matched an installed `php:7.4` build as "fixed in 8.0.x". An advisory whose fix
  is a module build now takes its streams from its title (`php:8.0 security update`,
  `virt:rhel and virt-devel:rhel ...`) and matches only packages from those streams; a
  non-module fix no longer applies to a module build, and a fix built once per module
  context compares by its version and release. Another stream's advisory no longer hides
  Red Hat's open status for the installed stream. Also fixed: an rpm subpackage with an
  epoch of its own (`perl-base` `0:2.27`) gave its source rpm that epoch, so perl's source
  looked older than `4:5.32.1` fixes. Checked against `dnf updateinfo` in Rocky Linux 8 and
  9 and AlmaLinux 8 images with module streams: 46 and 100 cross-stream false positives gone,
  AlmaLinux 8 equal to dnf; on a UBI 8 image with php, nodejs, ruby and perl streams, 171
  other-stream pairs gone, 27 open statuses for the installed streams back, and every one of
  Grype v0.121.1's 751 pairs reported.
- **CBL-Mariner 2.0 from Microsoft's OVAL** (spec 16, row 10, phase 2). osv.dev's Mariner 2
  records stopped in April 2026, while Microsoft's OVAL ran on to May: 269 CVE and package pairs
  missing and 153 fixes still listed as open. The OVAL is now read over osv.dev's records
  (`db sync --distros "Azure Linux:2::oval"`); where it names a CVE for a package, including
  "Not Applicable", it wins. On a 2023 image every pair Grype v0.121.1 reports is reported with
  the same status, and every pair the raw OVAL finds affected.
- **CentOS Linux 6, 7 and 8** (spec 16, row 10, phase 2). Matched against Red Hat's records
  for the release each rebuilt, with Red Hat's open statuses. A Red Hat fix counts as fixed
  only when CentOS shipped it, from a bundled list of each release's final builds
  (`crates/os/data/centos.tsv`, vault.centos.org); otherwise it is fixed only in another line
  (all of RHEL 8's fixes since CentOS 8 ended). Rebranded builds (`.el7.centos`) compare as
  the Red Hat build they rebuilt. CentOS Stream remains a coverage gap. Equal to Grype v0.121.1
  on CentOS 7 (12,619 pairs, no status differs) and CentOS 8 (1,286 pairs; 557 Red Hat fixes
  CentOS 8 never shipped are fixed only in another line where Grype calls them fixed).
- **Fedora** (spec 16, row 10, phase 2). Fedora 41 and later are matched against the updates
  repository's `updateinfo.xml.zst` (`db sync --distros Fedora`; from the Fedora archive once
  a release leaves the mirrors), its security updates only, with CVEs from the Bugzilla bugs
  each update closes. Findings link the Bodhi update. Equal to `dnf updateinfo list
  --security` on a Fedora 43 image (26 advisories, 51 advisory and package pairs). Fedora 40
  and older are a coverage gap.
- **End-of-life warnings for images** (spec 16, row 10, phase 2). An image whose release is
  past the end of its standard support (CentOS 7, Debian 10, Amazon Linux 2, Fedora 41, ...)
  gets an `unmaintained` warning, `EOL-<product>-<release>`, grouped across the fleet, with
  the date and, where the vendor sells it, when paid extended support ends. The dates come
  from a snapshot of endoflife.date bundled in `fleetreach-os` (refreshed at release time
  by `scripts/update-eol.py`), so scans stay offline; the scan date honors
  `SOURCE_DATE_EPOCH`. On the 24 rpm test images it flags the six releases past their date;
  Grype v0.121.1 flags Amazon Linux 2 and Fedora 41 but not CentOS 7 or openSUSE Leap 15.5.
- **Red Hat's unfixed CVEs in AlmaLinux and Rocky Linux images** (spec 16, row 10, phase 2).
  AlmaLinux and Rocky rebuild Red Hat Enterprise Linux from the same sources, so a CVE Red
  Hat has not fixed in RHEL 8 or 9 is not fixed in the rebuild either. Their scans take Red
  Hat's CSAF VEX open statuses and "not affected" for the matching RHEL release, where the
  rebuild's own records do not name the CVE for the package, titled `no fix yet; Red Hat
  status ...`. Red Hat's fix versions are Red Hat's builds and are not borrowed. An AlmaLinux
  or Rocky image scanned without the Red Hat index is now a coverage gap naming the command.
  Against Grype v0.121.1 on six AlmaLinux and Rocky images, the 582 to 611 open statuses per
  image Grype reported and fleetreach did not are now all reported, with no status
  disagreements; the 4 to 18 more per image are Red Hat statuses newer than Grype's data.
- **SUSE's unfixed CVEs in openSUSE, SLES and SLE Micro images** (spec 16, row 10, phase 2).
  `db sync --source csaf:suse` or `db import --csaf csaf-vex.tar.bz2 --provider suse`
  indexes SUSE's CSAF VEX (a 526 MB `.tar.bz2`, read in pure Rust), which scans of openSUSE
  Leap, Leap Micro and Tumbleweed, SUSE Linux Enterprise Server 15, SLE Micro and SUSE Linux
  Micro images consult as Red Hat's is consulted: open statuses become findings marked `no
  fix yet`, and fixes osv.dev lacks are reported with their version. SUSE names binary
  packages, each looked up by its own name and compared with its own version. A SUSE status
  outranks SUSE's `recommended` build, and a SUSE open status stands unless the release's
  records find the package affected (SUSE's update advisories also name CVEs they did not
  fix). Leap 15.x takes the fixes of the SLE 15 service pack it is built from, as `fixed
  only in another line`. Findings link SUSE's CVE page. A SUSE image scanned without the
  index is a coverage gap naming the command. Validated against OpenSCAP evaluating SUSE's
  OVAL: all 238 CVEs on SLES BCI 15.6.
- SLES images are now matched against every SLE 15 module's osv.dev records (Containers,
  Python 3, Public Cloud and the rest) and against LTSS, which carries the service pack's
  later fixes.
- `db sync --distros Debian:12,Wolfi` fetches distro exports one distribution at a time (the
  per-release export where osv.dev has one, else the whole distribution's), and a plain
  `db sync` fetches what the fleet's images need. `db status` lists the distro exports present.

- **Local advisory overlays** (spec 16, row 12). `[settings.advisories] dir` points at a
  directory of OSV JSON records layered over every OSV feeder's export (npm, PyPI, RubyGems,
  Packagist, NuGet, Julia, Swift, Hex, GitHub Actions, Maven): a record with an upstream id
  replaces it, a new id adds an advisory, and `withdrawn` retracts one. Fail-closed: a
  missing directory, invalid JSON or a duplicate id stops the scan with exit 2. Records for Go
  or Rust are not applied and say so. The report's `provenance.osv` gains an `overlay` entry
  with a sha256 over the records.
- **CVE 5.x and Red Hat CSAF VEX indexes**. `db sync --source osv,cve,csaf:redhat` (network
  build) and `db import --cve <dir|zip>` / `db import --csaf <dir|tar.zst> --provider redhat`
  reduce cvelistV5 (CNA affected data, ADP enrichment) and Red Hat's CSAF VEX archive (every
  product status plus will-not-fix, fix-deferred, out-of-support and similar remediations) to
  compact indexes next to the OSV exports, with sha256 and dates in `db status`. Scans of
  RHEL images match against the Red Hat index (above).
- **`db quality`**: data-quality checks on the advisory data as the matchers see it
  (unmatchable entries, versions outside ranges, events out of order, unparseable bounds,
  alias conflicts, live records aliasing rejected CVEs, missing severity, withdrawn records,
  overlay records not applied, stale or reviving). Exit 1 on an error-level issue.
- **`db crosscheck`**: JSON counts, with examples, of what the CVE and CSAF indexes add to or
  contradict in the OSV data.
- Additive APIs: `load_with_overlay` and `iter` on every OSV feeder database, and
  `osv::load_with_overlay` / `osv::read_overlay` in `fleetreach_core`. `OsvSettings` gains an
  `advisories` field.

### Fixed

- **A hostile repo can no longer hang a scan or read outside itself.** A manifest or lockfile that
  was a symlink to `/dev/zero`, or to a file beyond the repos in the fleet, was followed. Manifests,
  lockfiles and source files now go through one reader: it refuses what is not a regular
  file, anything that resolves outside the repo, and files over 512 MiB.
- **`licenses --detect` could hang.** Building the license matcher could deadlock on a busy thread
  pool, about one run in three.
- A file in the default `triage/` directory that names no advisory is skipped with a warning
  instead of failing the scan. A directory you name with `--triage-dir` stays strict.
- `fix plan` on a report with images listed lock bumps nothing could apply. An edit with no
  checkout in `fleet.toml` is now `blocked`, and says the image takes the fix at its next build.
- **Go findings have severities.** They all read `unknown` and so failed every `--fail-on`
  floor. The offline matcher now reads GitHub's records in the osv.dev export, and a `GO-` record
  takes the worst band of the records sharing an id with it. A Go finding under the floor no
  longer fails it. What nothing rates stays `unknown` and still fails, as do all findings from
  govulncheck or a vuln.go.dev mirror, which carry no severity.
- A repo scanned from `sbom =` with no lockfile of the same ecosystem errored, because the
  advisory data for what the SBOM held was never loaded.

- Dependency paths for RubyGems now go through gems from `GIT` and `PATH` sources.
- A pnpm `file:` or tarball dependency no longer appears as a package with a path for a version.
- **`fix apply` could destroy a verified branch.** A re-run that failed its baseline scan
  deleted the branch. Branches now move only after a commit, and an unverified result goes
  on `fleetreach-unverified/*`, never over a verified branch.
- Human VEX statements (`[[settings.ignore]]`, `[[settings.vex_assertion]]`) named every package
  as `pkg:cargo`, so a statement on an npm or PyPI package matched nothing in other tools.
- **Rust scans missed the advisories only GitHub carries.** RustSec has no record of about 650
  live crates.io advisories (`rustix`, `deno`, `surrealdb` among them), so `Cargo.lock` files
  and Rust binaries read clean of them. The osv.dev crates.io export is now synced and matched
  beside RustSec, and `--crates-vuln-db` points at a copy. A package RustSec already reported
  an advisory for keeps RustSec's finding, so nothing is reported twice; where GitHub's range
  or crate list is wider than RustSec's the package is reported, and what RustSec withdrew
  stays withdrawn. Checked on 600 real lockfiles: every row added is one Trivy and Grype both
  report, and an independent evaluation of the records agrees row for row.

- **Debian, Ubuntu and Alpine advisories were two years old.** Sync preferred osv.dev's
  per-release exports (`Debian:12/all.zip`), which still download but stopped changing in
  October 2024, so every later CVE was missed. Sync now fetches the whole distribution's
  export, and a scan warns when an export has not changed for a year. Found by the Trivy and
  Grype differential.
- Debian 7 to 11 lost the CVEs they left open when they left the security tracker. Their
  frozen osv.dev exports are now read too, wherever the maintained export says nothing about a
  CVE; `db sync --distros Debian:11` fetches both, `--max-db-age` does not apply to a frozen
  export, and the image's coverage gap says the data stops in October 2024.
- **Root's patched images could read as clean when they were not.** Root numbers its builds
  on one counter under two spellings, `.root.io.N` and `.aikido.N`, and dpkg sorts `aikido`
  below `root`, so a package at `root.io.2` counted as past a fix at `root.io.3`. Versions now
  compare by the counter. Packages Root renames (`rootio-coreutils`) now get Debian's and
  Alpine's records, records filed under either name are found, Root's apk builds
  (`-r00072`) are recognized, and Root's fix is shown for packages it has not rebuilt. Found
  on Root's public images: every Root row Trivy reports is now reported too.
- A registry that rate limits a pull (429) is now waited for and tried again.
- Files of third-party OS packages in images (`docker-ce-cli`, `mongodb-database-tools`) were
  skipped as if a distribution's advisories covered them. They are skipped now only when a
  distribution's records know the package, on dpkg, rpm and apk images.
- Ubuntu Pro's records were read only for `+esm` images; on any LTS they now speak about CVEs
  the release's own records never mention.
- CentOS 6 images have no `os-release` and were not matched; they are now read from
  `/etc/centos-release`, and RHEL's from `/etc/redhat-release`. CentOS stays affected by a Red
  Hat fix made after it stopped.
- Red Hat's Extended Life Support records are read for RHEL 6 and 7, and RHEL 10's records,
  which go by minor release, are read at all. A Red Hat record naming only the source package
  now applies to binaries it does not list.
- A Ubuntu or Debian notice no longer joins the CVEs it covers into one finding that takes the
  first one's status. A finding's title no longer names another release's status, and one
  GitHub record naming packages in two ecosystems stays two findings.
- Alpine ranges whose lower bound is above their fix hid open CVEs; the bound is dropped.
- Go records from GitHub in osv.dev's Go export were dropped, and `+incompatible` versions missed
  `last_affected` bounds.
- A `package.json` marked `"private": true` is not matched as a registry package.
- A retired Debian release now reports a coverage gap, where its CVEs went silently unreported.

### Compatibility

- `fleetreach_report::HumanAssertion` gains an `ecosystem` field, `fleetreach_cli::Suppression`
  gains `scope` and `accepted_risk`, and `fleetreach_cli::config::Config` gains `triage`.
- `fleetreach_scan::scan_lockfile` takes the new `Option<&CratesDb>` as its second argument;
  `None` keeps the RustSec-only behavior.
- A Rust repo or image scanned without the crates.io export now gets a partial coverage gap,
  as a repo with workflows does without the GitHub Actions export. RustSec's findings are
  unchanged. Network builds fetch the export on their own; offline ones need it from
  `fleetreach db sync` or `--osv-dir`.

- `fleetreach_core::Ecosystem` gains the `Deb` and `Apk` variants (JSON `deb`, `apk`). The
  enum is not `#[non_exhaustive]`, so an exhaustive `match` on it in code that depends on
  `fleetreach-core` needs a new arm. No existing variant or JSON value changes.
- `fleetreach_cli::config::Config` gains a public `images` field (as 1.5.0 added `sboms` and
  `context`); code building a `Config` literal adds `images: Vec::new()`.

## [1.5.0] - 2026-11-01

### Added

- **Repo context and SSVC decisions** (spec 08). `[[repo]]` takes `exposure`,
  `mission_impact`, `safety_impact`, `owner` and `tags`, with `[settings.context.defaults]`
  for the rest. Each vulnerable occurrence then gets a CISA SSVC deployer decision
  (`immediate`, `out-of-cycle`, `scheduled`, `defer`) from KEV exploitation, the advisory's
  CVSS vector (Automatable) and the repo's exposure and impact, through the published
  `ssvc:DT_DP:1.0.0` table, tested row by row against CERT/CC's data. `-f ssvc` lists the
  decisions with their vector and reason; `fix-first` and `remediation` sort by them; SARIF
  results carry the outcome and take their level from it; `-f owners` splits the fix queue by
  owner. `--fail-on-ssvc <outcome>` gates on them and, given alone, replaces the default
  severity gate. Fail-closed throughout: without KEV data nothing is decided (and the gate
  exits 2), missing context takes the most urgent values, and only a sound `NotReachable` or a
  phantom dependency lowers a decision to `defer`. `[settings.ssvc] poc_epss` optionally
  counts a high EPSS as a public proof of concept.
- Findings carry the advisory's `cvss_vector` (additive JSON field).
- **SSVC, continued** (spec 08). CISA Vulnrichment supplies CISA's own Exploitation and
  Automatable per CVE where it has assessed one (fetched under `--enrich`, cached a day, or
  read from a clone with `--vulnrichment-dir`); it only ever raises Exploitation.
  `[settings.ssvc] table` loads your own decision table in CERT/CC's CSV layout, validated to
  cover all 72 combinations and recorded as `custom:<sha256>`. `impact`, `blast` and
  `packages` (and `packages-json`) show the most urgent outcome and a reach weighted by it
  (`[settings.ssvc] weights`, default 8/4/2/0), and rank by it. `[[source]]` takes the same
  context fields for every repo it discovers.
- **Upgrade risk from fleet evidence** (spec 13, phase 1). Each remediation upgrade is rated
  `low` (within the current major), `medium` (breaking, but at least 3 repos already run the
  target or newer in its major) or `high`, with the reasons and the evidence (`repos`,
  `newest`). `-f remediation` shows a **Bump risk** column, `remediation-json` the `risk`,
  `risk_reasons` and `evidence` fields, and `fix plan` edits and pull request descriptions
  carry the risk. The JSON report gains `package_versions`: the versions of each vulnerable
  package that the fleet's lockfiles hold, and in which repos.
- **`bun.lock` is read in full** (bun 1.2+, lockfile versions 0 and 1): workspaces, nested
  copies resolved the way Node loads them, dev scope and dependency paths. Checked against
  osv-scanner on opencode, midday, elysia and bun's own lockfile: the same 4,829 registry
  packages. The binary `bun.lockb` is still reported as partial coverage.
- **SPDX output and vulnerabilities in the SBOM** (spec 05). `fleetreach sbom -f spdx` writes
  SPDX 2.3 JSON (purls, `DEPENDS_ON` and `DEV_DEPENDENCY_OF` relationships, coverage in
  comments, a content-derived namespace). `--report report.json` embeds a saved scan's
  findings: CycloneDX `vulnerabilities[]` with ratings, `affects`, KEV, EPSS and SSVC
  properties and an `analysis` that is `not_affected` only for a sound verdict (static
  `NotReachable`: `code_not_reachable`; phantom: `requires_dependency`), or SPDX `SECURITY`
  advisory references. Both formats pass their official schemas, and an SPDX document scans
  back to the same findings.
- **Scan history, trends and SLAs** (spec 09, phases 1 and 2). `scan --history-dir DIR`
  records each run as a gzipped snapshot plus an index of every finding's first and last
  sighting and fix. `fleetreach history trend|age|sla|mttr` reads it: open findings per run
  by severity, SSVC, ecosystem or owner; the oldest open findings; breaches of a
  `[settings.sla]` policy keyed by SSVC outcome or severity (`history sla` exits 1 on a
  breach, 2 without a policy); and time to fix. Fail-closed: a run that exited 2, an errored
  repo or a partly-read source never marks a finding fixed, ignored findings are recorded as
  ignored, and `--history-dir` refuses the flags that drop findings. `[settings.history]
  keep` prunes old snapshots while the index keeps first-seen dates; a lost or stale index is
  rebuilt from the snapshots.
- **Notifications** (spec 09, phase 3). `fleetreach notify --history-dir DIR` reports what
  the newest run changed (new findings, fixed findings) and every breach of `[settings.sla]`
  (with `-c`), grouped by owner. It prints, or POSTs to `--webhook` (HTTPS; network builds),
  a stable `fleetreach-notify/1` JSON payload or, with `-f slack`, a Slack Block Kit message;
  a webhook gets nothing when nothing changed unless `--always`. `--github-issues` (`gh`) or
  `--gitlab-issues` (`glab`) with `--repo` keeps one issue per owner, found again by a hidden
  marker, rewritten each run, closed when the owner has nothing open and reopened when a
  finding comes back. A gap run never makes old findings look new.
- **Static HTML report** (spec 09, phase 4). `fleetreach report html --history-dir DIR -o
  fleet-report.html` writes one self-contained page (no external resources) to host
  anywhere: summary tiles, open findings per run by severity with gap runs marked, SLA
  breaches, a queue per owner, fix campaigns from a saved `fix status` (`--fix-status`) and
  time to fix by severity. Light and dark, usable at phone width, deterministic for a given
  history.
- **GitLab merge requests** for `fix apply --open-pr` and `fix status`, through `glab`:
  the open merge request from a `fleetreach/*` branch is updated, otherwise one is created.
  The forge is read from each repo's `origin` host, or set with `--forge gitlab|github`.
  `fix status` rows gain a `forge` field and GitLab states are reported as `OPEN`, `MERGED`
  and `CLOSED`, like GitHub's.
- **Fleet novelty signal** (spec 10, phase 4). With `--signals` and `--history-dir`,
  `fleetreach:new-to-fleet` flags packages whose name no earlier recorded run of the fleet
  has read, the cheap early sign of a planted dependency (strongest next to a typosquat or a
  recent release). Each history snapshot now records the package names it read, and the
  index keeps them past retention. The first run that records names is the baseline and
  flags nothing.
- **Maven mirrors from `settings.xml`** (spec 04). `--maven-fetch` fetches POMs through
  the mirror of Maven Central that `~/.m2/settings.xml` (or `--maven-settings FILE`) names,
  chosen with Maven's `mirrorOf` rules, with credentials from the matching `<server>` and
  `${env.NAME}` expansion. A configured mirror that cannot be used (plain HTTP, encrypted
  password, unset variable) stops the scan instead of falling back to Maven Central.
  `sbom` and `licenses` take `--maven-fetch` and `--maven-settings` too.
- **Fixes on an older line** (spec 13). Remediation items list `alternatives`: for repos
  still on an older major (or `0.x` minor) than the target, the smallest version on their
  own line that clears their advisories, with what it leaves open and the fleet evidence.
  `-f remediation` shows them under the action (`or 1.4.2 on 1.x (3 repos)`), and `fix plan`
  gives those repos a low-risk lock bump to it instead of a blocked breaking upgrade. Plan
  edits are now marked breaking per repo: a repo on an older line crossing a major is
  breaking even when the fleet's newest version is not.
- **`fix apply` for Go and uv** (spec 07). Go modules are bumped with `go get
  <module>@v<to>`, then `go list -deps -test ./...` records the checksums the build needs
  (both with `GOTOOLCHAIN=local` and `GOWORK=off`), and `uv.lock` with `uv lock
  --upgrade-package <pkg>==<to> --no-build`, so neither runs package code; both are
  verified by the re-scan like Cargo and npm. A raised `go` directive is named in the result,
  the commit and the pull request, which now also say what the update ran.
- **Go from the osv.dev export** (spec 01, phase 3). Without govulncheck, the module-level
  Go scan reads `Go/all.zip` from `--osv-dir` or the default cache like every other
  toolchain-free ecosystem, so `fleetreach db sync` now covers Go and no separate
  vuln.go.dev mirror is needed. `--go-vuln-db=file://` still takes a mirror (or an unzipped
  export). Only `GO-` records are used, so GHSA copies are not double-counted; an export
  with no `GO-` record is an error, not a clean database.
- **A new website** (spec 15): docs, guides, integrations, use cases, dated comparisons and
  examples in one Astro Starlight site, replacing the mdBook docs. Every example is real
  output from a frozen demo fleet (`website/demo`), regenerated by `npm run examples` and
  checked in CI, as is the CLI reference generated from `--help`. Each page has a Markdown
  copy, and the site publishes `llms.txt`, `llms-full.txt`, a sitemap and JSON-LD. Old
  `/docs/*.html` addresses redirect. The README is shorter and points to the site.

### Changed

- **Faster on large lockfiles and large fleets**, with byte-identical output (checked on a
  10,471-repo fleet and 13 large open-source monorepos):
  - Dependency chains are built from one walk of each lockfile's graph instead of one walk per
    package. npm, Hex and Julia asked for a chain for every package, so a big lockfile was
    quadratic: the 13-monorepo scan went from 9.2s to 2.7s.
  - `sbom` builds each repo's inventory and BOM in parallel, and reads each crate's or NuGet
    package's license once per run instead of once per repo: 37s to 4.3s on the 10k fleet.
    With `--fetch-licenses`, deps.dev is asked once per package for the whole fleet, not once
    per repo. `licenses` reads repos in parallel too.
  - `--signals` reads repos in parallel: 16s to 5.2s on the 10k fleet.
  - The OSV databases a fleet needs load at the same time instead of one after another.

### Fixed

Found by checking each feature against real repos (gitea, caddy, hugo, spring-petclinic,
elysia, a FastAPI template, pydantic-ai) and independent tools: govulncheck, osv-scanner,
the osv.dev API, pyspdxtools, and CISA's and CERT/CC's own SSVC data.

- **Go without govulncheck read only a module's first `affected` entry.** 35 Go records list
  a module once per release line (go-redis/v9 in GO-2025-3540), so a version only a later
  entry covered was reported clean. Every entry now counts. An advisory naming several
  modules (GO-2024-2606: pgx/v4 and pgproto3/v2) now reports each of them, not only the
  first.
- **Safe versions stop where the bug comes back.** The `patched` versions of a finding, in
  every OSV ecosystem and Go, ended at the first fix, so a fix that a later release branch
  re-breaks, or that only covers one of the record's release lines, counted as safe: `fix
  plan` bumped grpc to 1.83.1, inside GO-2026-6443's re-introduced range, and could batch
  js-yaml on 4.1.1, which GHSA-2883 still affects. Safe versions now account for every range
  and every `affected` entry for the package, and a batched bump moves up to the first
  version safe for all its advisories (grpc 1.83.2, clearing six).
- **An advisory naming several packages** (`@babel/helpers` and `@babel/runtime`) gets a
  remediation item for each; one of them used to disappear from the queue.
- **PyPI bounds with NVD-style suffixes** (`2.6.0-NA`, `2.6.0-cu124`) read as their release,
  instead of leaving the range open (9 false positives on torch).
- **SBOM vulnerabilities on four-part versions** (PyPI `1.2.0.0`, NuGet `1.2.3.4`) now point
  at their component. CycloneDX referenced a component that was not in the BOM, and SPDX
  left the finding out.
- **`sbom`, `licenses` and `--signals` read a `pom.xml` the way `scan` does**, resolving
  parents, BOMs and transitive dependencies, instead of only the declared dependencies:
  spring-petclinic's SBOM listed 0 packages next to a scan that matched 171.
- **Workflows in a repo with packages were never scanned.** GitHub Actions workflows were
  read only when a repo had no package ecosystem, so a vulnerable action beside a lockfile
  was missed: a false clean. They are now scanned in every repo that has
  `.github/workflows`; without GitHub Actions advisory data, the repo gets a partial
  coverage gap naming the workflows instead of an error.
- **`--why` only searched Rust dependencies.** It now finds a package in every ecosystem,
  with its version, ecosystem, direct or transitive, and the chain that pulls it in.
- **Go findings made tables hundreds of columns wide.** Affected function names are shown
  without their package path, and the list is cut at 60 characters.
- **History runs were not reproducible under `SOURCE_DATE_EPOCH`.** The report's
  `generated_at` used the clock, and a run's id hashes the report, so the same scan recorded
  twice got different ids. It now follows `SOURCE_DATE_EPOCH` like every other timestamp.
- **`history mttr` showed 0.0 days for a group with nothing fixed**, which read as fixed at
  once. The table shows `-`; JSON is unchanged.
- **SARIF results all pointed at `Cargo.lock`**, a file most non-Rust repos do not have, so
  code scanning annotated nothing useful. Each result now names the file its package was read
  from: the repo's lockfile in the order its reader tries them (`bun.lock`, `uv.lock`,
  `requirements.txt` and so on), and for a GitHub Action the workflow that uses it.
- **The upgrade target could be a downgrade.** The `→` hint in tables, the SARIF message and
  the VEX action took the first patched range, so `smallvec 1.6.0` (patched in `>= 0.6.14,
  < 1.0.0` and `>= 1.6.1`) was told to move to 0.6.14. It is now the nearest fix above the
  installed version. The fix queue already did this.
- **Hex: every package in a real `mix.lock` was direct.** mix writes each dependency with an
  options list, `{:plug, "~> 1.14", [hex: :plug, ...]}`, and the reader took the options list
  for the dependency list, so it found none, and provenance chains were lost. Optional
  dependencies also no longer make a package transitive: mix installs one only when something
  requires it.
- **Advisory titles kept stray spaces from osv.dev** (` cowlib cow_http_te module: ...`),
  which showed in tables. Whitespace in titles is now collapsed.

## [1.4.0] - 2026-10-31

### Added

- **SBOMs as a scan input.** `[[repo]] sbom = "build/bom.json"` scans a CycloneDX (1.4 to
  1.6) or SPDX 2.3 JSON document instead of the repo's lockfiles, for builds fleetreach cannot
  read. Components are routed by purl to the ecosystem matchers (each feeder gained a public
  `scan_installed`), with direct dependencies and paths from the document's graph. Coverage is
  full only when CycloneDX asserts completeness; unscannable components are named. An SBOM
  from `fleetreach sbom` scans back to identical findings.

- **Fix pull requests.** `fix apply --push` pushes each verified `fleetreach/*` branch, and
  `--open-pr [--draft]` opens a pull request for it with `gh`, or updates the open one on a
  re-run. The description lists the advisories, flags breaking jumps, states the
  verification and names the campaign's other repos. Unverified branches are never pushed.
  `fix status` lists the pull requests of every repo. Tested against a real private repo.

- **Typosquat signal.** `scan --signals` also flags npm, PyPI and Cargo dependencies one edit
  from a popular package they are not, against bundled lists (17,338 npm, 15,000 PyPI and
  5,000 crate names, refreshed by `scripts/update-popular.py`). Registry-equivalent spellings,
  siblings in one npm scope and version-digit forks are not flagged. Measured at 1.6 flags per
  1,000 distinct names on real projects, all legitimate, so it stays opt-in.

- **Release-age signal (`scan --release-age 72h`).** Warns on dependency versions published
  less than the given time ago, the question that matters during a worm outbreak. Publish
  times come from deps.dev (opt-in: it sends names and versions; cached), and a version
  deps.dev cannot date is listed separately, never treated as old. `licenses --fetch` and
  this signal share one deps.dev client and cache.

- **Maven transitive resolution.** A `pom.xml` is resolved into the dependency tree Maven
  would build, in pure Rust and without running Maven: parent chains, properties,
  `dependencyManagement` and imported BOMs, default profiles, nearest-wins mediation with
  scope widening, exclusions, optional dependencies, version ranges and multi-module
  reactors. POMs come from `~/.m2/repository` and a local cache; `scan --maven-fetch` also
  fetches missing ones from Maven Central (opt-in: it sends coordinates). Unresolvable items
  are named as partial coverage. Matched `mvn dependency:list` on test projects (25 of 25, and
  85 of 85 artifacts and versions for a Spring Boot project, with one scope label differing).

- **Supply-chain signals (`scan --signals`).** Lockfile hygiene as warnings, read from files
  already parsed and with no network: install scripts (npm `hasInstallScript`), git, URL or
  path sources, registries outside the public ones or `[settings.signals] registries`
  (matched on the whole host, so lookalike hosts are caught), registry packages without a
  checksum, and third-party GitHub Actions pinned to a movable tag instead of a commit SHA.
  Opt-in, so existing reports and `--fail-on-warnings` gates do not change.
- **Known malware is first-class.** OSV `MAL-` findings are always critical, are never
  hidden by `--min-severity`, and the remediation queue and `fix plan` say to remove the
  package and rotate credentials instead of suggesting a version.

- **License inventory and policy.** `fleetreach licenses` gives every dependency's license
  (SPDX, with where it came from: `composer.lock`, `package-lock.json`, `node_modules`, the
  Cargo registry cache, virtualenv metadata, the NuGet cache) and a category (forbidden,
  restricted, reciprocal, notice, unencumbered). `--fetch` looks unknown ones up on deps.dev,
  opt-in because it sends package names, with a permanent local cache. A
  `[settings.licenses]` policy (allow/deny lists, per-category verdicts, `unknown = "deny"`
  by default, runtime scope, per-package exceptions with a reason) turns them into
  violations: exit 1 on a denied license. `fleetreach sbom` fills CycloneDX `licenses` from
  the same data. Cargo licenses agree with cargo-deny's on this repository.

- **`fleetreach fix`: verified fix branches.** `fix plan` turns a saved report's
  remediation queue into per-repo edits (lock bumps, or blocked with the reason: no fix, a
  breaking jump without `--allow-breaking`, an unsupported ecosystem). `fix apply` performs
  each lock bump in a git worktree on a `fleetreach/<campaign>/...` branch with a lock-only
  command that runs no package code (`cargo update --precise`, `npm update
  --package-lock-only --ignore-scripts`, or a GitHub Actions tag rewrite), then re-scans:
  the commit is marked verified only when the targeted advisories are gone and nothing new
  appeared. Your work tree is never touched and nothing is pushed.

- **GitLab fleet sources.** `[[source]] kind = "gitlab"` lists a GitLab group with all its
  subgroups (or a user namespace) on gitlab.com or a self-managed instance (`api_url`), with
  the same include/exclude globs, topics, archived and fork filters and sparse checkouts as
  GitHub. `GITLAB_TOKEN` (or `token_env`) authenticates private groups.

- **Stable SARIF fingerprints.** Every result carries `partialFingerprints` keyed on the
  advisory, ecosystem, repo and package (not the version), so GitHub code scanning keeps one
  alert per finding with its history across scans and through bumps that do not fix it.
  Before, every result pointed at the same lockfile location, so code scanning could merge
  the same advisory across repos or packages into one alert.

### Changed

- Repo ids from fleet sources keep the full namespace path of nested URLs
  (`group/sub/name`, previously `sub/name`), so same-named projects in different subgroups
  no longer collide. A `git` source with a nested URL gets a new id, so a saved baseline
  or a `[[repo]]` override written against the old id needs updating.

## [1.3.0] - 2026-10-30

### Added

- **`fleetreach sbom`: CycloneDX 1.6 SBOMs.** One BOM per repo from the same sources `scan`
  reads, in all 12 ecosystems: a component per package with its purl (git dependencies keep
  their remote and revision), dev-only packages as `scope: excluded`, the lockfiles'
  dependency graph, and `compositions` that mark components from partly-read sources
  `incomplete`. Deterministic (content-derived serial number, `SOURCE_DATE_EPOCH`); exit 2
  if any source could not be read. Validated against the official CycloneDX 1.6 schema on
  21 real repos (up to 13,291 packages), and against osv-scanner's package lists.

- **Python without a lockfile.** The PyPI feeder now reads `pylock.toml` (PEP 751) and, when
  a repo has no Python lockfile at all, its requirements files (`requirements*.txt`,
  `*requirements.txt`, `requirements/*.txt`) with `-r` includes, `-c` constraints, hashes and
  markers. pip-compile and uv output is full coverage with dependency paths from `# via`
  annotations; pinned files with no sign of a resolver are labelled partial, and unpinned
  requirements direct-only with their names listed, never guessed. Checked against pip's own
  parser on warehouse, NetBox and Home Assistant (1,603 of 1,603 pinned packages). Fleet
  sources now check out these files too.
- **.NET without `packages.lock.json`.** The NuGet feeder reads `obj/project.assets.json`
  (the full graph from `dotnet restore`, with dependency paths; partial when older than the
  project file), legacy `packages.config`, and otherwise the project files' `PackageReference`
  items with central package management, `VersionOverride`, global references and simple
  `$(Property)` values, labelled direct-only. Range and floating versions are named, never
  guessed. Checked statically on eShop, both CleanArchitecture templates and nopCommerce:
  every one of 236 package references read with its central version.

## [1.2.0] - 2026-10-30

### Added

- **Prebuilt binaries, Homebrew and a container image.** Each tagged release now builds
  `fleetreach` (with the `network` feature) for Linux x86-64/ARM64, macOS Apple silicon/Intel
  and Windows x86-64, attaches the archives with `SHA256SUMS` and signed build provenance,
  publishes `ghcr.io/tess-fun/fleetreach` for linux/amd64 and linux/arm64, and renders a
  Homebrew formula. `scripts/install.sh` installs the right archive after checking its
  SHA-256. The GitHub Action installs the prebuilt binary (seconds) instead of compiling from
  source, with a new `version` input; it still builds with cargo where no binary exists.
- **OSV exports without per-ecosystem flags.** Network builds fetch exactly the osv.dev
  exports a fleet needs into `~/.cache/fleetreach/osv/` and keep them fresh (conditional
  requests, atomic install, never replacing a good copy with a failed download). One
  `--osv-dir` (or `FLEETREACH_OSV_DIR`, `[settings.osv] dir`) laid out like the osv.dev
  bucket serves every ecosystem for air-gapped use. New `fleetreach db sync` and
  `fleetreach db status`. Each export's source, age and hash is recorded in
  `provenance.osv`.
- **pnpm and yarn lockfiles.** The npm feeder reads `pnpm-lock.yaml` (v6, v9) and `yarn.lock`
  (v1 and berry, including aliases, patches and workspaces) with direct/transitive, dev scope
  and dependency paths, validated on 19 real lockfiles. Several npm-family lockfiles in one
  directory are all read.
- **Coverage labels.** Sources read with less than a full resolved graph (`pom.xml` without
  `gradle.lockfile`, `bun.lock`/`bun.lockb`) are listed in a JSON `coverage` array, on
  stderr and in the summary line. `--require-full-coverage` makes them exit 2.
- **Fleet sources.** `[[source]]` entries discover repos from a GitHub organization or user
  (with include/exclude globs, topics, archived and fork filters, GitHub Enterprise via
  `api_url`) or a list of https URLs. `fleetreach fleet sync` / `scan --sync` keep shallow,
  blob-less, sparse checkouts holding only lockfiles and manifests; the commit scanned is
  recorded in `provenance.sources`. A failed listing stops the run; a failed clone is an
  errored gap. `git` runs without hooks, submodules or the `file://` transport, and the token
  never appears on the command line.

### Changed

- `--max-db-age` now also checks every OSV export used (upstream `Last-Modified` from a sync,
  else file mtime; unknown age refuses).
- NVD severity backfill caches answers per CVE (7 days for a score, 1 day for none), waits
  only between real requests, and says how long an unkeyed lookup will take. `NVD_API_KEY`
  is now documented.

### Fixed

- `--npm-prune-unreachable` could mark packages `NotReachable` in a pnpm `node_modules`
  layout, whose transitive packages the import graph does not walk. It no longer prunes
  there.
- **`--npm-prune-unreachable` pruned tools the project runs.** The npm import graph only started
  from imports, so a package run as a command (vitest, jest, stylelint, eslint from a
  `package.json` script or a CI workflow step) and everything it loads came out `NotReachable`;
  on matomo all 18 npm findings were, including a critical Vitest advisory. Executables named in
  `scripts` and `.github/workflows` are now resolved through each installed package's `bin` and
  treated as entry points, with witness chains such as `vitest → vite → esbuild`.

## [1.1.0] - 2026-10-30

### Added

- **Python reachability with witness chains.** `--reachability` now builds a package import
  graph for PyPI over the repo's virtualenv(s), resolving module names through each
  distribution's `RECORD` and following plugin entry points. A reached package is
  `Reachable` with the chain that loads it (e.g. `fastapi → starlette → python-multipart`);
  an unreached one stays `Unknown` (never `NotReachable`).
- **Witness chains in the table.** The Reach column shows how a package is reached
  (`imported via a → b → c`) for the npm and Python import graphs and the static engine.
- **Dev/build-only scope.** Findings record `"scope": "dev"` when the lockfile installs the
  package only for development (npm `dev`, uv dependency groups, poetry groups/category,
  Pipfile `develop`, composer `packages-dev`); the table marks them `(dev only)` and
  `--ignore-dev-deps` drops them.

### Fixed

- uv.lock dependency groups and extras were not read, so packages pulled in only by them had
  no dependency path and were never marked direct.

- **Polyglot and monorepo repos were only partly scanned, silently.** A repo was scanned as
  the first ecosystem found at its root, and `glob` only discovered `Cargo.lock`s, so a
  `package-lock.json` beside a `Cargo.lock`, or any lockfile in a subdirectory, was never
  read. A repo with no root lockfile (e.g. vscode, whose 14 npm lockfiles are all nested)
  was reported clean. fleetreach now scans every ecosystem at the root and, with
  `glob = true`, every lockfile below it. On 13 large open-source repos this surfaced 394
  missed findings (13 critical). Discovered lockfiles whose ecosystem has no OSV mirror now
  make the repo an errored gap; set `ecosystem` to scope a repo to one ecosystem.
  `yarn.lock`/`pnpm-lock.yaml`/`bun.lock` files, which no feeder reads, are now listed in a
  note instead of being ignored.
- **Withdrawn OSV advisories were reported.** Only the Rust path honoured `withdrawn`; all
  OSV feeders (and the Go offline matcher) now drop retracted advisories.
- **A second vulnerable version of a package was dropped.** The OSV feeders deduplicated
  findings on (advisory, package), so when a lockfile held two vulnerable versions (npm nests
  a conflicting copy) only one was reported and its fix left the other in place. The
  installed version is now part of the key.
- **One vulnerability reported under several ids.** osv.dev publishes, e.g., both a `PYSEC-`
  and a `GHSA-` record for most PyPI vulnerabilities; both were reported, inflating counts by
  about 28% on real fleets. Findings on the same package version whose ids or aliases overlap
  are now one finding: the GHSA id is kept, the others become aliases, and it takes the worst
  severity. Ignores and VEX assertions now also match an advisory's aliases, so an ignore
  naming the absorbed id keeps working.

## [1.0.3] - 2026-10-30

### Security

- `Cargo.lock` refreshed: `webpki-roots` and `webpki-root-certs` 1.0.9 -> 1.0.11 and
  `rustls-webpki` 0.103.15 -> 0.103.16, clearing RUSTSEC-2026-0381, RUSTSEC-2026-0383 and
  RUSTSEC-2026-0382 (bundled roots and path validation still trusted the distrusted emSign
  intermediates). All fixes were semver-compatible; no manifest changes.

### Changed

- Dependency majors: `comfy-table` 8, `sha2` 0.11, `toml` 1, `cvss` 3, and `ureq` 3 (the opt-in
  `network` feature). No output change: SHA-256 digests are hex-encoded byte by byte, and the
  CVSS v3 base score and severity band were checked identical between `cvss` 2 and 3 over all
  5,184 CVSS 3.0/3.1 base vectors. HTTP timeouts map onto ureq 3's per-phase timeouts with the
  same 60s overall cap; the 10 MiB response-body limit is unchanged.
- The per-ecosystem comparator harness examples are renamed `<ecosystem>_vercmp` (e.g.
  `cargo run -p fleetreach-nuget --example nuget_vercmp`), fixing cargo's output-filename
  collision across six crates.

### Fixed

- CHANGELOG: merged the two `## [1.0.0]` sections into one.

## [1.0.2] - 2026-10-16

### Security

- `Cargo.lock` refreshed: clears 11 advisories in transitive deps (rustls, quinn-proto, h2,
  crossbeam-epoch) and the anyhow/faster-hex unsound and proc-macro-error2 unmaintained warnings.
  All fixes were semver-compatible; no manifest changes.

### Changed

- Workspace toolchain pin bumped from stable 1.96.0 to 1.99.1 (MSRV stays 1.89).
- `reach-driver`: bumped the pinned nightly to `2026-10-15` and migrated to rustc's current API
  (`compiler_entrypoint`, `rustc_structures::CrateType`, `explicit_super_clauses_of`, and `FnDef`
  args now wrapped in a `Binder`, whose late-bound regions are erased before resolution).

- CI also runs weekly (Mondays 06:17 UTC) and on manual dispatch. On the scheduled run the
  reach-driver churn canary and VEX round-trip are blocking, so upstream drift fails the run and
  notifies instead of passing silently.

### Fixed

- **`cargo install fleetreach-cli` failed to resolve**: every `zip` 2.x release has been yanked
  from crates.io, so a fresh resolve of `zip = "^2"` (used by `fleetreach-core` to read the OSV
  `all.zip`) had no candidate. Moved to `zip` 9 with only the pure-Rust `flate2`/`zlib-rs`
  inflate backend. A malformed entry name in the archive now fails closed as a load error.
- `deny.toml`: dropped the RUSTSEC-2026-0173 ignore, whose crate left the tree with the lockfile
  refresh (cargo-deny rejects stale ignores).
- Website footer showed `1.0.0` instead of the released `1.0.1`. `scripts/release.sh` now bumps
  the footer and the reach-driver lockfile itself.

## [1.0.1] - 2026-06-28

### Changed

- Crate `homepage` now points at the project website
  (<https://tess-fun.github.io/fleetreach/>) instead of the repository.

### Fixed

- `reach-driver`: migrated to rustc's current `EarlyBinder::bind(cx, value)` API and bumped the
  pinned nightly to `2026-06-27` (the churn canary flagged the `rustc_private` drift).
- CI: resolved first-run failures — a Linux-only sandbox compile error, cargo-deny license/wildcard
  policy, the reach-driver toolchain-component install, the cargo-rdme intra-doc-link toolchain, and
  the VEX round-trip consumer install (pinned release binaries; trivy bumped to a fetchable version).

### Added

- Project website: a hand-built landing page and an mdBook documentation site, deployed to GitHub
  Pages (<https://tess-fun.github.io/fleetreach/>).
- `scripts/release.sh` — one-command version bump, test, tag, and publish of all crates.

## [1.0.0] - 2026-06-27

First stable release. Fleet-wide, reachability-aware dependency advisory auditing across
twelve ecosystems (Cargo, Go, npm, PyPI, RubyGems, Packagist, NuGet, Julia, Swift, Hex,
GitHub Actions, Maven) through one agnostic core, with a fail-closed spine (an unreadable
repo is an honest gap, never a clean scan) and ten output views plus a `diff` subcommand
for tracking drift.

### Added

- **Maven (Java) ecosystem support** (`fleetreach-maven`) — a twelfth ecosystem through the
  shared finding model. A Java repo is scanned **toolchain-free** from a **`gradle.lockfile`**
  (Gradle dependency locking — the full resolved transitive closure) or, failing that, a
  **`pom.xml`** (best-effort: direct dependencies with a literal `<version>`; a `${property}`
  or version range cannot be resolved without running Maven and is skipped). Dependencies are
  matched against an OSV mirror passed as `--maven-vuln-db=file://<path>` — either the osv.dev
  Maven export `all.zip` read directly or a directory of OSV JSON records (also via the
  `MAVENVULNDB` env var); overridable with `ecosystem = "maven"`/`"gradle"`/`"java"`.
  Coordinates `group:artifact` are matched verbatim. Versions follow Apache Maven's
  `ComparableVersion`, **not** SemVer (qualifiers order `alpha < beta < milestone < rc <
  snapshot < <release> < sp`; `ga`/`final`/`release` alias the release; integers compare as
  arbitrary precision so Jenkins-style `2646.v…` build numbers order numerically; `.X` is
  treated like `-X`), so the matcher uses a faithful `ComparableVersion` port. It runs no
  `mvn`/`gradle`, so like the other Tier-C feeders it is safe by construction and needs no
  `--allow-untrusted-builds`; without a mirror a Maven repo is an honest errored gap. The
  comparator was validated **differentially against Apache Maven's own `ComparableVersion`**:
  **710,000+ version-pair comparisons agree 100%** (the corpus surfaced and fixed the Maven 3.9
  "treat `.X` as `-X`" parsing behavior). Validated end-to-end on real `gradle.lockfile`
  (DataDog dd-trace-java) and `pom.xml` (commons-lang, guava, dubbo) files, flagging
  jackson-databind / log4j-core / commons-text advisories with zero parse errors.

- **GitHub Actions ecosystem support** (`fleetreach-ghactions`) — an eleventh ecosystem
  through the shared finding model. A repo's `.github/workflows/*.yml` (and a root
  `action.yml`) are scanned **toolchain-free**: `fleetreach` extracts every
  `uses: owner/repo@ref` reference and matches the version-tag pins against an OSV mirror
  passed as `--ghactions-vuln-db=file://<path>` — either the osv.dev GitHub Actions export
  `all.zip` read directly or a directory of OSV JSON records (also via the `GHACTIONSVULNDB`
  env var). Action identity is `owner/repo[/subpath]` (case-insensitive); a partial tag is
  padded (`v4` → `4.0.0`, as the OSV ranges treat it), while a branch (`@main`) or commit-SHA
  pin has no semantic version and is skipped as an honest gap. This catches pins to
  known-compromised actions such as the `tj-actions/changed-files` supply-chain advisory
  (everything below `46.0.1`). Auto-detected only for a workflow-only repo (a package repo is
  scanned for its package ecosystem); set `ecosystem = "githubactions"`/`"actions"`/`"gha"` to
  scan a package repo's workflows too. Validated end-to-end on real workflow files from major
  projects (rust-lang/rust, tokio, next.js, react, home-assistant, …) with zero parse errors,
  correctly flagging the tj-actions advisory and skipping SHA/branch pins.

- **Hex (Elixir/Erlang) ecosystem support** (`fleetreach-hex`) — a tenth ecosystem through
  the shared finding model. A repo with a `mix.lock` (auto-detected, or overridable with
  `ecosystem = "hex"`/`"elixir"`) is scanned **toolchain-free**: `fleetreach` reads the
  lockfile's pinned dependencies and matches each against an OSV mirror passed as
  `--hex-vuln-db=file://<path>` — either the osv.dev Hex export `all.zip` read directly or a
  directory of OSV JSON records (also via the `HEXVULNDB` env var). Hex versions are plain
  SemVer, so the shared comparator is reused; the Hex-specific part is the lockfile —
  `mix.lock` is an Elixir map literal (not JSON/TOML), so a small hand-rolled scan reads the
  `{:hex, :name, "version", …}` tuples and skips `{:git, …}`/`{:path, …}` dependencies.
  Package names are lowercase, matched verbatim. Severity comes from the GHSA band or a
  CVSS_V3 vector. It runs no `mix`/Elixir and no build, so like the other Tier-C feeders it
  is safe by construction and needs no `--allow-untrusted-builds`; without a mirror a Hex
  repo is an honest errored gap. The lockfile parser was validated against real `mix.lock`
  files from 12 well-known Elixir projects (phoenix, ecto, plug, absinthe, oban, broadway,
  …) with zero parse errors. A mixed multi-ecosystem fleet folds into one unified
  remediation queue.

- **Swift ecosystem support** (`fleetreach-swift`) — a ninth ecosystem through the shared
  finding model. A repo with a `Package.resolved` (auto-detected, or overridable with
  `ecosystem = "swift"`) is scanned **toolchain-free**: `fleetreach` reads the lockfile's
  pinned dependency graph (both the v1 and v2/v3 formats) and matches each package against an
  OSV mirror passed as `--swift-vuln-db=file://<path>` — either the osv.dev SwiftURL export
  `all.zip` read directly or a directory of OSV JSON records (also via the `SWIFTVULNDB` env
  var); the sibling `Package.swift`'s `.package(url:)` declarations mark the direct set. Swift
  versions are plain SemVer, so the shared comparator is reused; the Swift-specific part is
  **package identity by source URL** — the OSV `SwiftURL` ecosystem keys advisories on a
  normalized URL (`github.com/apple/swift-nio`), so the full clone URL from `Package.resolved`
  is normalized (scheme/`git@`/`.git`/trailing-slash stripped, lowercased) before matching.
  Severity comes from the GHSA band or a CVSS_V3 vector. It runs no `swift`/SwiftPM and no
  build, so like the other Tier-C feeders it is safe by construction and needs no
  `--allow-untrusted-builds`; without a mirror a Swift repo is an honest errored gap.
  Validated end-to-end against the SwiftPackageIndex master list: all **11,188 real package
  URLs** normalize and scan without panic, and the OSV-affected packages correctly match
  their real clone URLs. A mixed multi-ecosystem fleet folds into one unified remediation
  queue.

- **Julia ecosystem support** (`fleetreach-julia`) — an eighth ecosystem through the shared
  finding model. A repo with a `Manifest.toml` (auto-detected, or overridable with
  `ecosystem = "julia"`) is scanned **toolchain-free**: `fleetreach` reads the manifest's
  pinned dependency tree (both the v1 and v2 manifest formats) and matches each package
  against an OSV mirror passed as `--julia-vuln-db=file://<path>` — either the osv.dev Julia
  export `all.zip` read directly or a directory of OSV JSON records (also via the
  `JULIAVULNDB` env var); the sibling `Project.toml`'s `[deps]` keys mark the direct set.
  Julia's `VersionNumber` looks like SemVer but **build metadata is significant for
  ordering** (binary `_jll` packages carry a build counter such as `8.15.0+0`, and the
  majority of Julia advisory bounds key on it), which strict SemVer ignores — so the matcher
  uses a faithful `VersionNumber` comparator. Package names are case-sensitive. Severity
  comes from the GHSA band or a CVSS_V3 vector. It runs no `julia`/`Pkg` and no build, so
  like the other Tier-C feeders it is safe by construction and needs no
  `--allow-untrusted-builds`; without a mirror a Julia repo is an honest errored gap. The
  comparator was validated **differentially against Julia's own `VersionNumber`**: all
  sampled version strings parse identically and **69,483 version-pair comparisons agree
  100%**, including the JLL build-counter cases. A mixed multi-ecosystem fleet folds into one
  unified remediation queue.

- **NuGet (.NET) ecosystem support** (`fleetreach-nuget`) — a seventh ecosystem through the
  shared finding model. A repo with a `packages.lock.json` (auto-detected, or overridable
  with `ecosystem = "nuget"`/`"dotnet"`) is scanned **toolchain-free**: `fleetreach` reads
  the lockfile's pinned transitive tree (which records each package's `Direct`/`Transitive`
  type) and matches each package against an OSV mirror passed as `--nuget-vuln-db=file://<path>`
  — either the osv.dev NuGet export `all.zip` read directly or a directory of OSV JSON
  records (also via the `NUGETVULNDB` env var). Versions follow NuGet's scheme: SemVer 2.0
  with a **four-component** numeric core (`Major.Minor.Patch.Revision`) and **case-insensitive**
  prerelease labels, which the stock three-component `semver` crate cannot represent. Package
  ids are matched case-insensitively. Severity comes from the GHSA band or, when absent, a
  CVSS_V3 vector. It runs no `dotnet`/`nuget` and no build, so like the other Tier-C feeders
  it is safe by construction and needs no `--allow-untrusted-builds`; without a mirror a
  NuGet repo is an honest errored gap. The comparator was validated **differentially against
  .NET's own `NuGet.Versioning` library**: 21,537/21,537 version strings parse identically
  and **167,539 version-pair comparisons agree 100%**, drawn from the OSV NuGet data plus the
  top-600 packages on nuget.org. A mixed Rust + Go + npm + PyPI + RubyGems + Packagist +
  NuGet fleet folds into one unified remediation queue.

- **Packagist (Composer/PHP) ecosystem support** (`fleetreach-packagist`) — a sixth
  ecosystem through the shared finding model. A repo with a `composer.lock` (auto-detected,
  and overridable with `ecosystem = "packagist"`/`"composer"`/`"php"`) is scanned
  **toolchain-free**: `fleetreach` reads the lockfile's pinned transitive tree (the sibling
  `composer.json`'s `require`/`require-dev` mark which deps are direct) and matches each
  package against an OSV mirror passed as `--packagist-vuln-db=file://<path>` — either the
  osv.dev Packagist export `all.zip` read directly or a directory of OSV JSON records (also
  via the `PACKAGISTVULNDB` env var). Versions are compared with PHP's `version_compare`
  semantics, **not** SemVer: the stability ladder is `dev < alpha < beta < RC < <stable> <
  patch`, so `alpha`/`beta`/`RC` prereleases sort below their release but a `patch` level
  (`2.4.5-p1`, Magento's scheme) sorts **above** it — a SemVer comparator would mis-order
  every `-pN` version. Package names are Composer's case-insensitive `vendor/name`.
  Severity comes from the GHSA band or, when absent, a CVSS_V3 vector (which also yields a
  base score). It runs no `composer`/`php` and no build, so like the Go/npm/PyPI/RubyGems
  Tier-C modes it is safe by construction and needs no `--allow-untrusted-builds`; without a
  mirror a Packagist repo is an honest errored gap. The comparator was validated
  **differentially against the real `composer/semver` library** on 185,537 version pairs
  drawn from the 3,000 most-installed packages (**100% agreement**, after the corpus
  surfaced and fixed three faithfulness gaps: `+build` metadata is ignored, the numeric core
  is normalized to four components before the stability tail, and a bare `>=X` bound includes
  the prereleases of `X` — Composer's `-dev` floor, which a plain `>=` would false-clean for
  a prerelease pinned at an `introduced` boundary). End-to-end it scanned a 2,996-repo
  corpus of generated `composer.lock` files with **100% recall and 100% precision** against
  `composer/semver` (0 false-cleans, 0 false-positives, 0 panics), including the Magento
  `2.4.8-p1` patch-level case correctly flagged in the `[2.4.8-beta1, 2.4.8-p2)` window. A
  mixed Rust + Go + npm + PyPI + RubyGems + Packagist fleet folds into one unified
  remediation queue.

- **RubyGems (Ruby) ecosystem support** (`fleetreach-rubygems`) — a fifth ecosystem through
  the shared finding model. A repo with a `Gemfile.lock` (auto-detected, and overridable with
  `ecosystem = "rubygems"`/`"ruby"`) is read for its pinned transitive tree and matched against
  an OSV mirror passed as `--rubygems-vuln-db=file://<path>` — either the osv.dev RubyGems
  export `all.zip` read directly or a directory of OSV JSON records (also via the
  `RUBYGEMSVULNDB` env var). Versions are compared as `Gem::Version`, **not** SemVer: any
  letter segment is a prerelease, segments are arbitrary-length, and trailing zeros are
  insignificant (a faithful port of modern RubyGems' `canonical_segments`). Gem names are
  matched verbatim (case-sensitive, unnormalized), and only rubygems.org sources are matched
  (`GIT`/`PATH` and private-registry pins are skipped). Because RubyGems advisories often
  enumerate affected versions instead of a range, the matcher consults both. Severity comes
  from the GHSA band or a CVSS_V3 vector (which also yields a base score). It runs no
  `bundler`/`gem` and no build, so like the Go/npm/PyPI Tier-C modes it is safe by
  construction and needs no `--allow-untrusted-builds`; without a mirror a RubyGems repo is an
  honest errored gap. Validated against the osv.dev RubyGems export with **100% recall and
  100% precision** (2,775 sampled advisories) and differentially against real Ruby's
  `Gem::Version` (405,924 version pairs, zero disagreements with the modern canonical
  algorithm).

- **PyPI (Python) ecosystem support** (`fleetreach-pypi`) — a fourth ecosystem through
  the shared finding model. A repo with a `uv.lock`, `poetry.lock`, or `Pipfile.lock`
  (auto-detected in that order, and overridable with `ecosystem = "pypi"`/`"python"`) is
  scanned **toolchain-free**: `fleetreach` reads the lockfile's pinned transitive tree and
  matches each package against an OSV mirror passed as `--pypi-vuln-db=file://<path>` —
  either the osv.dev PyPI export `all.zip` read directly or a directory of OSV JSON
  records (also via the `PYPIVULNDB` env var). Versions are compared as **PEP 440**
  (epochs, `.post`/`.dev`, pre-releases) and names matched after **PEP 503**
  normalization. Because PyPI advisories frequently enumerate affected versions instead
  of a range (notably the `MAL-` malware records), the matcher consults both the
  `ECOSYSTEM` ranges and the explicit `versions` list. Severity comes from the GHSA band
  or, when absent, a CVSS_V3 vector (which also yields a base score). It runs no
  `pip`/`poetry`/`uv` and no build, so like the Go/npm Tier-C modes it is safe by
  construction and needs no `--allow-untrusted-builds`; without a mirror a PyPI repo is an
  honest errored gap. Validated against the OSV PyPI export with **100% recall / zero
  false-cleans** on 3,000 sampled advisories and 100% precision at the fix boundary, and
  end-to-end against real `uv`/`poetry`/`pipenv` lockfiles. A mixed Rust + Go + npm + PyPI
  fleet folds into one unified remediation queue.

- **npm ecosystem support** (`fleetreach-npm`) — a third ecosystem through the shared
  finding model. A repo with a `package-lock.json` (and no `Cargo.lock`/`go.mod`) is
  scanned **toolchain-free**: `fleetreach` reads the lockfile (the full transitive tree,
  already pinned to exact versions) and matches each package against an OSV mirror passed
  as `--npm-vuln-db=file://<path>` — either the osv.dev npm export `all.zip` read
  directly (one file, ~3x faster than the unzipped directory and no unzip step) or a
  directory of OSV JSON records. It runs no `npm` and no install scripts, so like the Go
  Tier-C mode it is safe by construction and needs no `--allow-untrusted-builds`. Supports
  lockfileVersion 1/2/3; findings carry the GitHub Advisory Database severity band (so
  they rank and gate like Rust ones) at `unknown` reachability, with direct/transitive
  from the lockfile. Without a mirror an npm repo is an honest errored gap, never
  silently skipped. A mixed Rust + Go + npm fleet folds into one unified remediation
  queue. Falls back to the `NPMVULNDB` env var.
- **`fleetreach diff <baseline.json> <current.json>`** — a first-class subcommand
  that compares two saved JSON reports and splits findings into **new**, **fixed**,
  and **still-open**, with each surviving advisory's blast-radius drift (`±repos`).
  Answers "did this branch make the fleet better or worse?" — a question a single
  scan can't. Pure (no scanning, DB, or network), so it's a cheap CI gate: exit `1`
  when a *new* finding trips `--fail-on <severity>` (default `low`; Unknown fails
  closed), `--fail-on-warnings` to also gate new warnings, `--exit-zero` for
  report-only. `-f json` emits the structured diff (`new`/`fixed`/`still_open` with
  `repos_added`/`repos_removed`). Generalizes the scan `--baseline` flag, which only
  keeps new findings from a live scan and never reports what was fixed.
- **`-f blast`** — a blast-radius view that splits each advisory's affected-repo
  count into **direct** vs **transitive** reach and prints a fix-path hint
  (`manifest` if every affected repo depends on it directly, `upstream` if every
  exposure is transitive, else `mixed`). Same ranking as `-f impact`; the split tells
  you *how* to fix, not just how wide. Motivated by a corpus study: across a real
  ecosystem the large majority of vulnerable-dependency exposures are transitive,
  which a plain affected count hides.
- **`-f packages`** — a package-impact rollup: vulnerable *dependencies* ranked by
  fleet reach, each row carrying its direct/transitive split and the number of
  advisories one bump would resolve. Answers "which dependency is my biggest
  liability?" (e.g. a single `openssl` bump clearing seven advisories shows as one
  row). Also available programmatically as `to_packages_json`.
- **`-f packages-json` / `-f remediation-json`** — the package-impact rollup and the
  remediation fix queue as JSON, so automation can consume those views from the binary
  (previously library-only). The full `-f json` payload is unchanged.
- **SARIF `dependencyKind`** — each SARIF result now carries a `properties.dependencyKind`
  (`direct`/`transitive`), giving CI security tooling the same fix-path signal as
  `-f blast` without parsing message text (`-f json` already exposes it per occurrence).
- **Affected functions** — when an advisory scopes itself to specific
  functions/types (vulnerable *at the installed version*), they are surfaced:
  `affected_functions` in JSON, an `affects fn:` line in the table, and a
  `functions:` line in `--explain`. Turns "crate X has a bug" into "...in *these*
  functions — do you call any?".
- **`--reachability`** (heuristic, opt-in) — greps your repos' source for those
  function names: `in source` / `not found` (a `Reach` column + `reachable` in
  JSON). It only scans *your* code, so a `not found` never proves the vuln is
  unreachable — it's a hint. `--reachable-only` drops the not-found ones
  (fail-closed: unknown is always kept). Not static call-graph analysis.
- **Fleet impact view (`-f impact`)** — the cross-repo angle only a fleet tool
  can show: advisories ranked by how many repos they hit (`RUSTSEC-X — 12 repos`),
  so you can see which fix clears the most repos. KEV is flagged inline.
- **Fix-first view (`-f fix-first`)** — the remediation queue: a severity-dominant
  ranking (KEV, then severity band, then blast radius) so real CVEs stay above
  high-spread informational warnings. The `#` column is the fix order; the
  `Exploit` column surfaces KEV/EPSS. The complement to `-f impact`.
- **Go ecosystem scanning (mixed fleets)**: a `fleet.toml` repo with a `go.mod`
  (and no `Cargo.lock`) is scanned by `govulncheck`, and its findings flow through
  the *same* correlate / rank / remediation pipeline as Rust crates, so a mixed
  Rust+Go fleet produces one unified, reachability-aware fix queue. Ecosystem is
  auto-detected (Rust-first: a `Cargo.lock` wins) or set explicitly with
  `ecosystem = "go"` per `[[repo]]`. Reachability is the mirror of the Rust engine:
  govulncheck is sound-positive, so a confirmed call is `Reachable` (the queue can
  trust it), but present-but-uncalled is `Unknown`, never a false "not reachable".
  Go scanning runs `govulncheck` (which compiles the module), so it requires
  `--allow-untrusted-builds` and a `govulncheck` binary (`--govulncheck`, or found
  on `PATH`/`$GOPATH/bin`); without them a Go repo is an honest errored gap, never
  silently skipped. Go advisories carry CVE/GHSA aliases, so `--enrich` backfills
  their severity / KEV / EPSS too.
- **Go toolchain-free scanning (Tier-C)**: when no `govulncheck` is available (no
  `--allow-untrusted-builds`, or no binary), a Go repo is still scanned by matching
  its `go.mod` module versions against an OSV DB mirror (`--go-vuln-db=file://<mirror>`)
  directly. This compiles nothing, so it needs **no untrusted-build consent** — it
  reads files and compares versions. Module-level only (`Unknown` reachability, engine
  `fleetreach-tier-c`), and it feeds the same pipeline + `--enrich`. Direct/transitive
  is read from `go.mod`. Without a mirror, no-toolchain stays an honest errored gap.
- **Go direct vs. transitive** dependency classification, read deterministically from
  `go.mod` (`require` without `// indirect` is direct), so Go findings distinguish
  direct from transitive the way Cargo ones do.
- **Source-aware VEX subcomponent PURLs**: a non-crates.io dependency (a git or
  alternate-registry source) is a different artifact than the registry crate of the
  same `name@version`, so its `-f vex` subcomponent PURL now carries the source as a
  qualifier (`?vcs_url=git+<url>@<rev>` / `?repository_url=<index>`). crates.io and
  local-path deps keep the bare `pkg:cargo/name@version` PURL, byte-identical to before,
  so the validated registry-suppression path is unchanged. (Consumer matching on the
  qualifiers is not yet validated against Grype/Trivy; it only adds precision for the
  rare non-registry case.)
- **Remediation view (`-f remediation`)**: the actionable fix queue. Where
  `fix-first` ranks *which advisory*, this prints *what to do*: the concrete
  dependency bump, **batched** so one row (`bump tokio 1.0 → 1.38`) clears every
  advisory that single upgrade resolves across every repo. Breaking (semver-major)
  jumps are flagged; the upgrade target never recommends a downgrade even when the
  advisory's safe set spans an older line; no-fix advisories are called out
  honestly. Ordering is severity-dominant, and within a severity band a
  *confirmed-reachable* batch leads before blast radius breaks the tie (decisive
  for Go, whose advisories carry no CVSS). When `--reachability=static` has run,
  *soundly* unreachable advisories drop to an informational tail (shown, never
  queued). The same data is available as JSON via
  `fleetreach_report::to_remediation_json`.
- **SARIF output + GitHub Action** — `-f sarif` emits SARIF 2.1.0 (rule per
  advisory, result per occurrence, `security-severity` for GitHub's badge, fix
  hint in the message). A composite `action.yml` installs fleetreach, scans, and
  uploads to GitHub code scanning, so findings land in the Security tab and on
  PRs. See `.github/workflows/audit-example.yml`.
- **Fix targets & `--why`** — each finding's location now shows the upgrade
  target inline (`foo@1.1.9 → 1.2.3`), the lower bound of the patched range — the
  exact `cargo update -p foo --precise 1.2.3`. `fleetreach scan --why <pkg>`
  prints how a package (any package, not just an advisory'd one) enters each
  repo's dependency tree, then exits.
- **Exploit-risk enrichment (`--enrich`)** — annotate findings with CISA KEV
  (actively exploited in the wild) and FIRST EPSS (exploit probability), matched
  by CVE alias. Findings re-rank into an action queue (KEV first, then EPSS), the
  table gains a `Risk` column (`KEV epss 87%`), and the JSON adds inline `kev` /
  `epss`. New gates: `--fail-on-kev` and `--min-epss <P>`. Offline via
  `--kev-file` / `--epss-file`. Opt-in; default scans stay offline-capable.

- **Dependency provenance** — each in-repo finding now records the chain from a
  root crate down to the flagged package (`dependency_path` in JSON), and an
  accurate `direct`/`transitive` classification. The table shows a triage hint
  (`(direct)` or `(via … → parent)`) so you can see *who pulls a package in*
  without reaching for `cargo tree -i`. The field is additive and omitted when
  empty, so `schema_version: 1` consumers are unaffected.
- **`--resolve-features`** (opt-in) — for repos with buildable source, marks each
  finding as actually built or a phantom `Cargo.lock`-only optional dependency
  (off-by-default feature, never compiled), via a feature-aware `cargo tree`. The
  table flags phantoms with `⚠ not in default build`; the JSON adds
  `occurrences[].active`. Default scans stay lockfile-only and portable.
- **`--ignore-phantom`** (opt-in, implies `--resolve-features`) — suppresses
  findings whose packages are never compiled, so CI doesn't gate on optional deps
  that aren't in the build. The count suppressed is reported on stderr;
  unknown-build-status findings are always kept (fail-closed).

### Changed

- The shared OSV range matcher (`fleetreach_core::osv`) is now generic over the version
  type, so the Go/npm SemVer feeders and the new PyPI PEP 440 feeder share one
  event-walking skeleton (the place where a missed case is a false-clean). Behavior for
  Go and npm is unchanged.

## [0.1.0] - 2026-06-24

Initial release. Fleet-wide Rust dependency advisory audit built on `rustsec`.

### Added

- **Fleet scanning** — `fleetreach scan` reads a `fleet.toml`, scans each repo's
  `Cargo.lock` (with bounded-depth `glob` discovery for monorepos), and reports
  vulnerabilities and supply-chain warnings as separate streams.
- **Cross-repo correlation** — findings are deduplicated across the fleet by
  canonical RUSTSEC id, with a per-occurrence verdict (the same advisory can be
  patched in one repo and not another).
- **Toolchain advisories** — `rustsec`'s `rust` collection is matched against the
  installed toolchain.
- **Output** — human table (default, with severity color on a TTY) and machine
  JSON (`-f json`, `schema_version: 1`), with payload on stdout and the summary
  on stderr. Color is never emitted in JSON or piped output.
- **CI contract** — exit codes `0`/`1`/`2`/`3` with a fail-closed precedence: any
  un-scannable repo, stale DB, or invalid config exits `2`, never `0`.
- **Determinism** — `--db`/`--offline`/`--max-db-age`; byte-identical JSON across
  runs (the clock is injected via provenance).
- **Inspection & diffing** — `--explain <ID>` dumps one advisory; `--baseline`
  surfaces only findings new since a prior report.
- **Provenance** — every report records tool/rustsec versions, DB commit and
  timestamp, host OS/arch, and generation time.

### Security / engineering

- `#![forbid(unsafe_code)]` and a denied `unwrap`/`expect`/`panic` family on
  externally-derived values, workspace-wide.
- `proptest` over the correlation engine and the assemble pipeline; `cargo-fuzz`
  targets on the two untrusted-byte surfaces (`fleet.toml`, lockfile content);
  black-box tests over the compiled binary's exit-code and stream contract.

[Unreleased]: https://github.com/tess-fun/fleetreach/compare/v1.6.0...HEAD
[1.6.0]: https://github.com/tess-fun/fleetreach/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/tess-fun/fleetreach/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/tess-fun/fleetreach/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/tess-fun/fleetreach/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/tess-fun/fleetreach/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/tess-fun/fleetreach/compare/v1.0.3...v1.1.0
[1.0.3]: https://github.com/tess-fun/fleetreach/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/tess-fun/fleetreach/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/tess-fun/fleetreach/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/tess-fun/fleetreach/releases/tag/v1.0.0
[0.1.0]: https://github.com/tess-fun/fleetreach/releases/tag/v0.1.0
