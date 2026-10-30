# Spec 05: SBOM output and input

Status: draft · Gap: #5 (interop/compliance) · CTEM stage: discovery, interop · Effort: M

## Problem

fleetreach neither writes nor reads CycloneDX or SPDX. That blocks three things:

1. Compliance asks (US EO 14028 attestations, EU Cyber Resilience Act) that want an SBOM per
   product.
2. Feeding CTEM / ASPM aggregators and Dependency-Track, which ingest SBOMs.
3. Coverage for builds fleetreach cannot read natively (Gradle without locking, Bazel,
   exotic tooling) where the build can already emit an SBOM.

## What competitors do

- **OSV-Scanner, Trivy, Grype/Syft** emit CycloneDX and SPDX and scan SBOMs as input.
  Trivy also consumes CycloneDX VEX and checks licenses from SBOM input.
- **Dependency-Track** is SBOM-native: projects are fed CycloneDX, findings triaged
  against them.
- **GitHub** exports an SPDX SBOM per repo. All commercial platforms export SBOMs.

## Goals

1. `fleetreach sbom` writes one CycloneDX 1.6 JSON BOM per repo (and SPDX 2.3 JSON on
   request) from the same parsed dependency graphs the scan uses.
2. SBOM files as a scan input for any ecosystem, routed by purl into the existing matchers.
3. Optional embedded vulnerabilities and VEX analysis (CycloneDX `vulnerabilities[]`) so a
   single file carries findings plus fleetreach's sound `not_affected` verdicts.

Non-goals: generating SBOMs for container images, file-level SBOMs, signing (users can sign
with cosign/sigstore).

## Design

### Output

```
fleetreach sbom -c fleet.toml --out-dir boms/ [--format cyclonedx|spdx] [--with-vulns]
```

- File per repo: `boms/<repo-id>.cdx.json` (repo id slashes become `__`).
- `metadata.component` = the repo (type `application`, `bom-ref` = repo id, VCS URL and
  commit SHA when known from Spec 06).
- One component per resolved package: `purl` (pkg:cargo, pkg:npm, pkg:pypi, pkg:gem,
  pkg:composer, pkg:nuget, pkg:julia, pkg:swift, pkg:hex, pkg:maven, pkg:github,
  pkg:golang), `version`, `scope` (`required`, or `excluded` for dev-only), `hashes` when
  the lockfile has them (npm `integrity`, Cargo checksum, uv/Pipfile hashes, composer
  `dist.shasum`), licenses when Spec 11 lands.
- `dependencies[]` from the dependency graph (we already build paths for `--why`).
- `compositions[]`: `aggregate: complete` for `full` coverage, `incomplete` with the
  affected refs for `direct-only`/`partial` (Spec 00, C1). Honest about what it is.
- Deterministic: `serialNumber` = `urn:uuid` derived from a content hash, components sorted,
  timestamp = advisory DB time (same trick as the OpenVEX `@id`), so BOMs diff cleanly.
- `--with-vulns`: CycloneDX `vulnerabilities[]` with `ratings` (CVSS, EPSS like Grype does),
  `affects[].ref`, and `analysis.state` = `not_affected` + `justification`
  (`code_not_reachable`, `requires_dependency` for phantom deps) only for machine-sound
  verdicts, mirroring `--vex-only-sound`.
- SPDX 2.3 JSON: packages with `externalRefs` purl, `DEPENDS_ON` relationships.

### Input

```toml
[[repo]]
id   = "android-app"
path = "../android-app"
sbom = "build/reports/bom.json"   # explicit
# or: sbom_discover = true         # finds *.cdx.json, bom.json, *.spdx.json
```

- CycloneDX 1.4–1.6 JSON and SPDX 2.3 JSON. (XML formats: later, if asked.)
- Each component with a purl routes to the matcher for its type; unknown purl types and
  components without purl are `non_registry`.
- Direct vs transitive from `dependencies[]` (refs reachable in one step from the root);
  without a graph, everything is transitive (conservative, as with `gradle.lockfile`).
- Coverage: `compositions` `complete` → `full`; `incomplete`/`unknown`/absent → `partial`
  ("SBOM does not assert completeness").
- An SBOM next to a lockfile fleetreach reads natively: the lockfile wins; the SBOM is used
  only when `sbom` is set explicitly (then it replaces native discovery for that repo).

### Interop recipes (docs, no code)

- Gradle: `cyclonedx-gradle-plugin` in CI → `sbom = "build/reports/bom.json"`.
- Dependency-Track: `fleetreach sbom` + `curl` PUT `/api/v1/bom` per repo.

## Fail-closed rules

- A declared `sbom` path that is missing or unparsable: errored gap.
- An SBOM older than the repo's lockfiles (mtime or embedded timestamp): warn as `partial`.

## Testing

- Round trip: scan → `sbom` → scan with `sbom =` must yield identical findings for every
  fixture repo in every ecosystem.
- Validate outputs against the official CycloneDX 1.6 and SPDX 2.3 JSON schemas in CI.
- Ingest BOMs produced by Syft, cdxgen, cyclonedx-gradle-plugin and GitHub's SPDX export.
- Dependency-Track import smoke test in the Docker validation job used for VEX.

## Phasing

1. CycloneDX output (no vulns): S/M.
2. CycloneDX input with purl routing: M.
3. `--with-vulns`, SPDX output: S each.
