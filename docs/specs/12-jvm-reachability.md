# Spec 12: JVM function-level reachability (research spec)

Status: draft, research-gated · Gap: #9 · CTEM stage: validation · Effort: L (experiment first: M)

## Problem

Function-level reachability exists for Rust (sound MIR engine) and Go (govulncheck). npm and
Python have package-level import graphs that give witness chains but almost never suppress:
the 2026-10-30 feasibility study found build-free "not reachable" for Python sets aside only
~3% of findings. JVM is the remaining large ecosystem where competitors sell function-level
reachability, and where it is known to matter (huge transitive trees, many advisories in
rarely used corners of libraries).

## What competitors do

- **Snyk**: reachability GA for Maven and Gradle (Java was its first), via its CLI/SCM
  integrations. ([Snyk reachability](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/reachability))
- **Endor Labs**: function-level reachability for Java, Kotlin, Scala (and others), plus
  upgrade impact on the same call graph. ([language support](https://docs.endorlabs.com/scan-with-endorlabs/language-scanning/))
- **Semgrep Supply Chain**: reachability rules for Java/Kotlin/Scala, written per advisory by
  Semgrep's research team.
- **Eclipse Steady** (open source, from SAP): derives vulnerable "constructs" from fix
  commits and checks reachability with static and dynamic analysis. The proven academic
  approach to the hard part.

The hard part is not the call graph. It is **sink data**: which methods are vulnerable.
OSV records for Maven almost never carry symbols (the same study found ~0 symbol data
outside Rust and Go). Competitors fill that with paid research teams or proprietary
databases.

## Research questions (answer before building)

1. **Sink availability**: for Maven advisories in OSV, what fraction link a fix commit
   (references typed `FIX`, or GHSA patch links) from which changed methods can be extracted?
2. **Sink precision**: on a hand-labelled sample of 100 advisories, how often are the
   methods changed in the fix commit the actual vulnerable entry points (vs refactors, tests,
   unrelated changes)?
3. **Suppression yield**: on ~50 real Java services from the corpus, what fraction of
   findings are soundly `NotReachable` with a CHA/RTA call graph over app + dependency
   bytecode? (This is the number that decided Python.)
4. **Soundness gaps**: reflection, `ServiceLoader`, Spring/DI wiring, serialization
   gadgets. How much over-approximation is needed to stay sound, and does it erase the yield?

Go/no-go: proceed only if (1) × (2) gives usable sinks for ≥ 50% of high/critical Maven
advisories **and** (3) is ≥ 20% after soundness handling. Otherwise record the result
(as for Python) and keep JVM at witness-chain level.

## Candidate design (if go)

- **Inputs**: dependency jars by GAV (from Spec 04 resolution, fetched from Maven Central or
  `~/.m2`; jars are data, never executed) and the app's compiled classes from existing build
  output (`target/classes`, `build/classes`). No build is run by fleetreach; a repo with no
  build output gets `Unknown`, never `NotReachable`.
- **Bytecode parsing**: pure-Rust class-file reader (the format is simple and stable; a small
  in-house parser, fuzzed, avoids C dependencies).
- **Call graph**: CHA first, RTA (instantiated types) as the refinement, mirroring the Rust
  engine's coercion-tracked RTA. Roots: `main` methods, servlet/Spring entry points
  (annotations), public API for libraries (treated as reachable, as for Rust lib roots).
- **Soundness spine** (same as the Rust engine): reflection, `ServiceLoader`,
  `invokedynamic` bootstrap methods we cannot resolve, and native methods widen the graph or
  force `Unknown`. A false `NotReachable` is a security defect.
- **Sinks**: extracted from fix commits (method-level diff of the fixed version vs the
  last affected version), cached per advisory, published as a data file so the community can
  correct them. Advisories without extracted sinks stay package-level.
- **Output**: same `Reachability { verdict, engine, witness }` model, VEX/SARIF suppression
  for sound `NotReachable`, witness chains in the table.

## Experiment plan

| Step | Output | Effort |
|------|--------|--------|
| E1 | Script: OSV Maven advisories → fix-commit coverage (question 1) | S |
| E2 | Method-diff extractor + labelled sample of 100 (question 2) | M |
| E3 | Prototype CHA over jars + classes for 50 services (questions 3, 4) | M |
| Decision | Write results to `docs/` and memory, like the Python study | S |

## Dependencies

Spec 04 (resolved GAVs) for jar retrieval. Shares data plumbing with Spec 13 (fix-commit
diffs also inform upgrade safety).
