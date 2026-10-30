# Spec 04: Maven transitive resolution

Status: draft · Gap: #2 (coverage) · CTEM stage: discovery · Effort: L

## Problem

`pom.xml` is read for declared dependencies only (`crates/maven/src/lockfile.rs`: "It does
not see the transitive closure"). Gradle is covered only when dependency locking is on
(`gradle.lockfile`). Most JVM vulnerabilities sit in transitive dependencies (Log4Shell
reached most victims transitively), so a Maven repo today is a large blind spot that still
prints as scanned.

## What competitors do

- **OSV-Scanner** resolves `pom.xml` transitively by default (disable with `--no-resolve`),
  using deps.dev for version and dependency data, or Maven Central directly with a "native"
  data source; test dependencies are excluded from the graph.
  ([supported files](https://google.github.io/osv-scanner/supported-languages-and-lockfiles))
- **Snyk, Mend, Sonatype, JFrog** run Maven or Gradle (or have their own resolvers) in CI.
- **Semgrep** resolves Java/Kotlin without lockfiles (beta) by running the build tool.

## Goals

1. A pure-Rust Maven resolver that turns a `pom.xml` (single or multi-module) into the same
   dependency tree `mvn dependency:tree` would show, without running Maven or any plugin.
2. Coverage `full` when resolution completes; `partial` with named reasons when it cannot.
3. Validated differentially against real Maven, at the same bar as the `ComparableVersion`
   port (which agrees with Maven over 710k pairs).

Non-goals: Gradle script evaluation (Groovy/Kotlin code; use `gradle.lockfile` or an SBOM
from Spec 05), SNAPSHOT resolution, plugin dependencies, non-default profiles.

## Design

### Effective model (per module)

1. **Parent chain**: `<parent>` via `relativePath` (default `../pom.xml`) when the local
   file's GAV matches, else fetched from a repository.
2. **Property interpolation**: `${project.*}`, `${parent.*}`, `<properties>`, `${env.*}`
   left unresolved (→ `partial`), recursion depth bounded.
3. **dependencyManagement** merge, including `<scope>import</scope>` BOMs (fetched,
   recursively, cycle-checked).
4. **Profiles**: only `<activeByDefault>true</activeByDefault>`. Others listed in the
   coverage note when they add dependencies.

### Graph resolution

- BFS from the module's dependencies with Maven's **nearest-wins** mediation (shallowest
  depth wins, first declaration breaks ties), `dependencyManagement` overriding versions
  and scopes for transitives, `<exclusions>` (including `*` wildcards), `<optional>` not
  propagated.
- Scope propagation per Maven's table; `test` and `provided` become dev scope (findings
  kept, marked dev, same rule as the 1.1.0 dev scope).
- Version ranges (`[1.0,2.0)`): read `maven-metadata.xml`, pick the highest matching
  version with the existing `ComparableVersion` port.
- Multi-module reactors: `<modules>` resolved locally; inter-module dependencies use the
  local POMs, not the repository.

### Repositories and cache

- Default: Maven Central (`repo.maven.apache.org/maven2`). Plus `<repositories>` declared in
  POMs (HTTPS only) and, opt-in, mirrors from `--maven-settings ~/.m2/settings.xml`.
- Credentials from settings.xml `<servers>` are used only for that server's URL, never
  logged, never written to the report.
- Read-through to `~/.m2/repository` first (no network if the developer or CI already
  built), then fetch to `~/.cache/fleetreach/maven/` (release POMs are immutable, so cache
  forever; metadata files refresh like Spec 01).
- `--offline`: local caches only; any missing POM makes resolution `partial`.
- Fetches are POMs and metadata only (small XML), never jars.

### Alternative data source

`--maven-resolver deps.dev`: use the deps.dev API for published-package dependency graphs
(faster, one call per direct dependency, discloses names to Google). Off by default.
Shared plumbing with Spec 03's optional Python resolution.

## Fail-closed rules

- Any unresolved parent, BOM, property or range → `partial` coverage with the exact items
  named; findings for what did resolve are still reported.
- Declared-only scanning (today's behaviour) remains the fallback and is labelled
  `direct-only`.
- `--require-coverage full` gates on both.

## Testing and validation

1. **Differential vs Maven**: ~1,000 open-source Maven projects (from the existing corpus
   tooling); run `mvn dependency:tree -DoutputType=json` (in a container, network to Central
   only) and compare GAV + scope sets with ours. Target: ≥99% exact project agreement, every
   disagreement triaged to a rule.
2. Differential vs OSV-Scanner on the same projects (findings superset).
3. Unit fixtures per rule: nearest-wins ties, BOM import order, exclusion wildcards,
   property in parent, range selection.
4. Fuzz the POM parser.

## Phasing

1. Single-module resolution (parent, properties, dependencyManagement, BOMs, nearest-wins)
   with `~/.m2` read-through and Central: L.
2. Multi-module reactors, ranges, settings.xml mirrors: M.
3. deps.dev data source: S (after Spec 03 phase 4).

## Open questions

- Is a full resolver worth it vs requiring an SBOM (Spec 05) or `mvn dependency:tree` output
  ingestion? Proposal: build it. Maven repos without either are the common case, and the
  differential-validation culture makes this a credible differentiator ("resolver validated
  against Maven on N projects").
- Maven 4 POM model changes (consumer POMs, `<subprojects>`): track, not phase 1.
