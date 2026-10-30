# Capability excellence: what A+ means for each capability

Status: draft for prioritization · 2026-10-30

The competitive matrix (https://claude.ai/artifact/WFVHTdpXcT7mYoSWZnRo5w) grades fleetreach
and 16 other tools on 28 capabilities. This document defines, for each capability, the **best
possible outcome**: what a best-in-class implementation does, written as concrete, checkable
criteria. It then states who sets the bar today, where fleetreach stands, and what is missing
for A+. It is the input for a later prioritization pass; it does not order the work.

Grades: "1.1.0" is the released version; "Wave 1" is the uncommitted work on `main`
(OSV auto-sync, coverage labels, pnpm/yarn, fleet sources, NVD cache).

## Principles that apply to every capability

A capability is only A+ if it also meets these. They are what makes fleetreach's A+ different
from a competitor's A+.

1. **Fail-closed.** Anything it cannot read, resolve, fetch or prove is a visible gap or an
   exit 2, never silence. No default may lower priority on missing data.
2. **Fleet-native.** Every answer exists per repo *and* rolled up across the fleet, ranked by
   how much one action clears.
3. **Offline-capable.** Every network input has a file or cache equivalent, and `--offline`
   provably makes no request.
4. **Validated against the real thing.** Each parser, comparator or resolver is
   differentially tested against the native tool on a real corpus, with the result
   published (as for the Maven comparator, 710k pairs).
5. **Explainable.** Every verdict carries its evidence: the dependency path, the witness
   chain, the data source and its age.
6. **Deterministic and reproducible.** The same inputs give byte-identical output, and the
   report records every input (DB revisions, commits scanned).
7. **Machine-first output.** Every view has a stable JSON form; additive schema changes only.
8. **Safe by construction.** No third-party code runs without explicit consent and a
   sandbox; secrets never reach argv, logs or reports.

## Summary

| # | Capability | 1.1.0 | Wave 1 | Distance to A+ | Spec |
|---|------------|-------|--------|----------------|------|
| 1 | Many repos, one deduplicated report | A | A | small | new |
| 2 | Rank by fleet blast radius | A+ | A+ | small | 08 |
| 3 | Batched cross-repo fix queue | A | A | medium | 07, 13 |
| 4 | Repo discovery | F | B | medium | 06 |
| 5 | Automated fix PRs | F | F | large | 07 |
| 6 | Dashboard, triage, tickets | F | F | large | 09 |
| 7 | Ecosystems for app dependencies | B | B | medium | new |
| 8 | yarn / pnpm / bun lockfiles | F | A- | small | 02 |
| 9 | Manifest-only resolution | D | D+ (labelled) | large | 03, 04 |
| 10 | Container / OS packages | – | – | medium (by integration) | 05, 14 |
| 11 | Advisory DB fetched automatically | D | A- | small | 01 |
| 12 | Curated vulnerability data | C | C | medium | new |
| 13 | Function-level reachability | B | B | large | 12 |
| 14 | Import-graph witness chains | A- | A- | medium | new |
| 15 | KEV + EPSS ranking | A | A | small | 08 |
| 16 | Dev / build-only scoping | B+ | B+ | medium | new |
| 17 | Fleet-wide dependency provenance | A | A | small | new |
| 18 | Malware / typosquat detection | D | D | medium | 10 |
| 19 | License compliance | F | F | medium | 11 |
| 20 | Unmaintained / unsound warnings | A | A | medium | new |
| 21 | SARIF + exit-code gating | A+ | A+ | small | new |
| 22 | Gate only on new findings | A | A | small | new |
| 23 | VEX | A+ | A+ | small | new |
| 24 | SBOM output | F | F | medium | 05 |
| 25 | SBOM input | F | F | medium | 05 |
| 26 | No server or account needed | A+ | A+ | small | new |
| 27 | Air-gapped / offline | A+ | A+ | small | 01 |
| 28 | Cost | A+ | A+ | none | n/a |

"new" means no spec covers the A+ delta yet; the delta is described below.

---

## Fleet scale

### 1. Many repos, one deduplicated report

**A+ looks like**
- Scans 10,000 repos in one run with bounded memory, and publishes the measured time and
  memory per repo per ecosystem.
- Deduplicates across repos by advisory (including aliases), package and version, while
  keeping every occurrence.
- Re-scans incrementally: unchanged lockfiles (by content hash) reuse cached results.
- Isolates failures: one bad repo never stops or contaminates the rest, and is named.
- Gives per-repo, per-owner and fleet-wide rollups from the same data.

**Bar today:** GitHub security overview, Dependency-Track and the commercial platforms hold
org-scale inventories, but as hosted services.

**fleetreach:** A. Has cross-repo dedup, parallel scanning, failure isolation and a perf
profile. Missing for A+: incremental re-scan cache, per-owner rollups (needs owners from
spec 08), and a published scale benchmark.

### 2. Rank by fleet blast radius

**A+ looks like**
- Ranks advisories and packages by repos affected, split direct vs transitive with a fix-path
  hint.
- Weights each repo by business context (exposure, criticality), not just a count.
- Answers "what if": given a set of bumps, which advisories and repos clear, and what remains.
- Shows the ranking's reason on every row.

**Bar today:** nobody else ranks this way; commercial tools offer "where used" inventories.

**fleetreach:** A+ for the unweighted version. Missing for A+ in full: context weighting
(spec 08) and a what-if simulation over the remediation queue.

### 3. Batched cross-repo fix queue

**A+ looks like**
- For each package, the minimal-churn target that clears every grouped advisory in every repo,
  checked against each repo's own constraints (ranges, peer dependencies).
- Picks a strategy per repo: in-range lock bump, manifest bump, override, or parent bump.
- Flags breaking upgrades with evidence (API changes actually used), not only semver.
- Routes advisories with no fix to VEX or mitigation, never a fake upgrade.
- Groups by owner and tracks each batch as a campaign until it is done.

**Bar today:** OSV-Scanner guided remediation (one project, strategies), Endor upgrade impact
(one project, API-change evidence), Dependabot grouping (per repo).

**fleetreach:** A. Has fleet-wide batching, semver-major flags and honest no-fix rows. Missing
for A+: per-repo constraint checking, strategies, API-change evidence (spec 13), campaigns and
owners (specs 07, 08).

### 4. Repo discovery from forges

**A+ looks like**
- Lists every major forge: GitHub (cloud and Enterprise Server), GitLab (cloud and
  self-managed), Bitbucket (Cloud and Data Center), Azure DevOps, Gitea/Forgejo.
- Filters by topic, name glob, visibility, language, archived and fork status.
- Fetches only what the scan needs (sparse, shallow, blob-less).
- Reports inventory changes between syncs (new, removed, renamed repos) and repos with no
  recognized manifest at all, so blind spots are visible.
- Documents the least-privilege token for each forge; never stores or logs tokens.

**Bar today:** Renovate autodiscover (many forges, filters), GitHub security overview.

**fleetreach:** F in 1.1.0, B with Wave 1 (GitHub incl. GHES and plain git URLs, sparse
checkouts, fail-closed). Missing for A+: GitLab, Bitbucket, Azure DevOps, Gitea; inventory
diff; no-manifest report; token guidance.

### 5. Automated fix PRs

**A+ looks like**
- Every PR is verified before it opens: re-scanned, targeted advisories gone, nothing new
  introduced, coverage not lower.
- Edits use lockfile-only operations; no package scripts run without consent and a sandbox.
- PRs are idempotent: updated in place, closed when obsolete, rebased when stale.
- Respects branch protection, CODEOWNERS and repo conventions (commit style, labels).
- Rolls out gradually: canary repos first, a cap per run, stop on failures.
- The PR body explains why: advisories, severity, exploit signals, reachability, risk.

**Bar today:** Renovate (A+), Dependabot (A), Snyk, Mend.

**fleetreach:** F. Spec 07 covers plan, apply, verify and publish. Missing for A+: all of it,
plus PR lifecycle (close/rebase) and gradual rollout, which spec 07 should add.

### 6. Dashboard, triage and tickets

**A+ looks like**
- History: first seen, fixed at, mean time to remediate, trend per severity, owner and SSVC
  outcome.
- SLA clocks per risk level, with breaches as a gate.
- Triage states with an audit trail (who decided, when, why), expressible as VEX.
- Notifications and tickets routed by owner, updated in place, closed when fixed.
- A dashboard that needs no server to operate.

**Bar today:** Dependency-Track (history, audit trail, notifications), GitHub security
overview and campaigns, all commercial platforms.

**fleetreach:** F. Spec 09 covers history files, SLAs, notifications and a static HTML report.
Missing for A+: all of it.

## Coverage

### 7. Ecosystems for application dependencies

**A+ looks like**
- Covers every ecosystem with meaningful advisory volume or user demand, including C/C++
  (Conan, vcpkg), CocoaPods, Pub, CRAN and Hackage where the data justifies it.
- Each ecosystem has a faithful version comparator validated against the native library.
- A published coverage matrix states, per ecosystem, the files read, the coverage level and
  the validation result.

**Bar today:** Renovate (90+ managers, for updates), OSV-Scanner, Trivy and Grype (20+).

**fleetreach:** B (12). Earlier research found Pub too small to justify (about 13 advisories).
Missing for A+: a data-driven decision per remaining ecosystem (advisory counts in OSV vs
effort), C/C++ the most likely candidate, and the published coverage matrix.

### 8. yarn, pnpm and bun lockfiles

**A+ looks like**
- Every format version of each lockfile, including workspaces, aliases, patches, peer
  suffixes and pnpm catalogs.
- `bun.lock` (text) and `bun.lockb` (binary).
- Direct/transitive, dev scope and dependency paths at parity with `package-lock.json`.
- Validated against each package manager's own package listing on a real corpus.

**Bar today:** OSV-Scanner, Trivy, Snyk, Dependabot (all formats).

**fleetreach:** F in 1.1.0, A- with Wave 1 (pnpm v6/v9, yarn v1/berry, 19 real lockfiles
match exactly). Missing for A+: `bun.lock`/`bun.lockb`, pnpm v5, pnpm catalogs, and
validation against the package managers themselves (blocked on installing them).

### 9. Manifest-only resolution

**A+ looks like**
- Resolves the full graph without running build code: Maven (parents, BOMs, properties,
  ranges, nearest-wins), NuGet (restore output, central package management), pip
  (pinned requirements, PEP 751 `pylock.toml`), Gradle via lockfile or SBOM.
- Unpinned inputs resolve only with explicit consent (a resolver or network service), and
  are otherwise labelled direct-only, never guessed.
- Each resolver is validated against the native tool (`mvn dependency:tree`, `dotnet
  restore`).

**Bar today:** OSV-Scanner (Maven and requirements.txt via deps.dev), Snyk and Endor (run the
build tools).

**fleetreach:** D, D+ with Wave 1 (the `pom.xml` gap is labelled, not fixed). Specs 03 and 04
cover it. Missing for A+: all resolvers.

### 10. Container and OS packages

**A+ looks like (for fleetreach, by integration)**
- Container scanning stays out of scope; the A+ outcome is that image findings still land in
  the same fleet views.
- Ingests image SBOMs (Syft, Trivy) through SBOM input, so base-image packages rank in the
  same blast-radius and remediation views.
- Emits VEX that Trivy and Grype honor (already true), and documents the pairing.

**Bar today (as a scanner):** Trivy (layer-aware, distro backports, VEX), Grype.

**fleetreach:** "–" by design. Missing for A+ by integration: SBOM input (spec 05) and the
pairing recipe (spec 14).

### 11. Advisory DB fetched automatically

**A+ looks like**
- Zero configuration: fetches exactly the data the fleet needs.
- Incremental updates (only changed records), not full re-downloads.
- Integrity verified (hash at minimum, signature where the source signs).
- Freshness gates on every source, with ages in the report.
- Reproducible: a run can be pinned to a dated snapshot of every source, not only RustSec.
- One portable bundle for air-gapped hosts.

**Bar today:** Trivy, Grype, OSV-Scanner (automatic fetch, offline DB).

**fleetreach:** D in 1.1.0, A- with Wave 1 (auto-sync, conditional requests, hashes, age
gates, provenance). Missing for A+: incremental record updates, snapshot pinning for OSV,
and a single bundle covering OSV, RustSec, KEV, EPSS and the NVD cache (see 27).

### 12. Curated vulnerability data

**A+ looks like**
- Merges every public source (OSV, GHSA, RustSec, Go, distro and vendor feeds, NVD) with
  alias deduplication and the best severity per advisory.
- Lets an organization add its own advisories and corrections in OSV format, versioned with
  its config.
- Flags data quality problems (missing ranges, missing severity, withdrawn records) instead of
  hiding them.
- Feeds corrections back upstream.

**Bar today:** Snyk, Sonatype, JFrog (proprietary research teams).

**fleetreach:** C by design (no proprietary feed). A realistic A+ is "best merging of public
data": missing are local advisory overlays, data-quality reporting and an upstream
contribution workflow.

## Prioritization

### 13. Function-level reachability

**A+ looks like**
- Sound reachability (no false "not reachable") for every major language, with witness
  chains from real entry points.
- Vulnerable symbols for most advisories, from the advisory or derived from fix commits.
- Build-free where possible; sandboxed and consented where a build is needed.
- Cached, fast enough for CI, with published precision and suppression yield.

**Bar today:** Endor Labs and Snyk (many languages), govulncheck (Go, sound).

**fleetreach:** B (Rust sound MIR engine, Go via govulncheck). Spec 12 gates JVM on an
experiment; Python build-free suppression was measured at about 3%. Missing for A+: JVM (if
the experiment says go), symbol extraction from fix commits, published precision numbers.

### 14. Import-graph witness chains

**A+ looks like**
- For every ecosystem, a build-free chain from first-party code (and scripts, CI steps,
  entry points) to the vulnerable package.
- Shown in every output, including SARIF `codeFlows`, not only the table.
- Positive-only unless soundness is proven for that ecosystem.

**Bar today:** Endor, Snyk, Semgrep (package-level reachability in several languages).

**fleetreach:** A- (npm, PyPI; Rust and Go have stronger engines). Missing for A+: Ruby, PHP,
.NET, Java import graphs, and SARIF `codeFlows`.

### 15. KEV and EPSS ranking

**A+ looks like**
- KEV, EPSS (probability and percentile), public exploit evidence and CISA Vulnrichment
  decision points, all with source dates.
- Combined into an action with business context (SSVC outcome), not a single score.
- EPSS movement over time surfaced ("rising").
- Every feed works offline from files.

**Bar today:** Grype (risk score), Endor, Snyk, Mend.

**fleetreach:** A. Missing for A+: SSVC decisions with context (spec 08), Vulnrichment, EPSS
trend (needs history, spec 09).

### 16. Dev and build-only scoping

**A+ looks like**
- Precise scope for every ecosystem: runtime, dev, test, build, optional, peer, and
  platform-specific dependencies.
- Computed by reachability from runtime roots, not by name.
- Policy per scope (for example dev findings gate at a lower severity), while remembering
  that CI tools run with credentials.

**Bar today:** GitHub (scope on alerts), Snyk, Endor.

**fleetreach:** B+ (npm, uv, poetry, Pipfile, composer, pnpm, yarn). Missing for A+: Maven test
and provided scope, Gradle configurations, Bundler groups, Cargo dev and build dependencies,
and per-scope gating policy.

### 17. Fleet-wide dependency provenance

**A+ looks like**
- "Why is X here" for any package and version across the fleet: shortest path, all paths,
  and reverse dependents.
- Version distribution across the fleet ("which repos still run log4j 2.14").
- Machine-readable output for every query.

**Bar today:** commercial "where used" inventories, per project dependency paths.

**fleetreach:** A (`--why` across the fleet, Cargo only). Missing for A+: every ecosystem (the
data now exists for all of them), all-paths mode, version distribution view, JSON output.

## Supply chain beyond CVEs

### 18. Malware and typosquat detection

**A+ looks like**
- Known malware always gates, with "remove and rotate credentials" advice.
- Behavioral analysis of new versions shortly after publication.
- Install-time blocking.
- Typosquat, dependency confusion, release-age cooldown and maintainer-change signals.

**Bar today:** Socket (A+), Sonatype Firewall, JFrog Curation, Aikido.

**fleetreach:** D (OSV `MAL-` records). Behavioral analysis and install-time blocking are out
of scope. A realistic A+ for fleetreach is "every signal derivable from lockfiles and public
metadata, at fleet scale": spec 10 (malware first-class, lockfile hygiene, typosquats,
release age, fleet novelty).

### 19. License compliance

**A+ looks like**
- An SPDX license expression for every package, with its source recorded.
- Policy with allow and deny lists, categories, SPDX expression logic and exceptions.
- Obligations handled: attribution notices generated, copyleft conflicts flagged.
- Fleet rollup and SBOM licenses.

**Bar today:** Sonatype (A+), Mend, Snyk, Dependency-Track, cargo-deny for Rust.

**fleetreach:** F. Spec 11 covers inventory, policy and rollup. Missing for A+: spec 11 plus
notice generation and conflict detection.

### 20. Unmaintained and unsound warnings

**A+ looks like**
- For every ecosystem: deprecated packages (npm deprecation, PyPI yanked releases), archived
  source repos, unmaintained notices, last-release age, maintainer count, OpenSSF Scorecard.
- Each warning suggests an alternative where one is known.

**Bar today:** Socket and Endor (package health scores), Sonatype.

**fleetreach:** A for Rust (RustSec unmaintained and unsound, fleet-wide). Missing for A+: the
same signals for the other 11 ecosystems, which need registry metadata (opt-in network).

## CI and interop

### 21. SARIF and exit-code gating

**A+ looks like**
- SARIF with stable fingerprints so code-scanning alerts persist across runs.
- Locations on the exact manifest or lockfile line.
- Witness chains as `codeFlows`; machine-sound verdicts as suppressions.
- A documented exit-code contract and gates on severity, KEV, EPSS, SSVC outcome and
  coverage.
- Ready-made CI templates for GitHub Actions and GitLab CI.

**Bar today:** Semgrep, Snyk, GitHub native.

**fleetreach:** A+ on the contract (fail-closed exit 2). Missing for A+ (checked in the code):
SARIF results carry a file location but no `partialFingerprints`, no line `region` and no
`codeFlows`; there is no GitLab CI template; no SSVC gate yet (spec 08).

### 22. Gate only on new findings

**A+ looks like**
- A PR mode that compares the change against its base and reports only what the change
  introduced, attributed to the manifest edit that did it.
- Baselines per repo and branch.
- Exceptions with an expiry date and an owner, which turn into failures when they lapse.

**Bar today:** GitHub dependency review, Snyk, Semgrep (diff-aware).

**fleetreach:** A (`diff`, `--baseline`). Missing for A+: native PR mode with attribution,
expiring ignores.

### 23. VEX

**A+ looks like**
- Emits and consumes OpenVEX, CycloneDX VEX and CSAF VEX.
- Machine-sound justifications with verifiable evidence, kept separate from human
  assertions.
- Drift checks and re-verification of evidence.
- Signed documents (Sigstore), published per product.

**Bar today:** fleetreach leads (OpenVEX both ways, sound justifications, drift checks).

**fleetreach:** A+ for OpenVEX. Missing for A+ in full: CycloneDX VEX (with spec 05), CSAF VEX,
signing.

### 24. SBOM output

**A+ looks like**
- CycloneDX 1.6 and SPDX 2.3/3.0, validated against the official schemas.
- Complete graph, purls, hashes, licenses, and honest completeness (`compositions`).
- Deterministic output, NTIA minimum elements, optionally signed or attested.

**Bar today:** Trivy, Syft, OSV-Scanner, all commercial platforms.

**fleetreach:** F. Spec 05 covers it. Missing for A+: spec 05 plus SPDX 3.0, signing and an
NTIA check.

### 25. SBOM input

**A+ looks like**
- Ingests CycloneDX and SPDX in JSON and XML from any generator.
- Routes components by purl to the right matcher; honors declared completeness; flags stale
  SBOMs.

**Bar today:** Dependency-Track (A+), Trivy, Grype, Sonatype, JFrog.

**fleetreach:** F. Spec 05 covers JSON; XML would be the remaining delta.

## Operating model

### 26. No server or account needed

**A+ looks like**
- A single binary for Linux, macOS and Windows on x86-64 and ARM, installable by `cargo`,
  Homebrew, prebuilt releases and a container image.
- No telemetry; all configuration as code.

**Bar today:** OSV-Scanner, Trivy, Grype.

**fleetreach:** A+ on the model. Release binaries, Homebrew formula, install script and
container image are implemented (ICE item O1, uncommitted; first live run is the next
tag). Remaining for A+: Windows ARM64 and Linux musl (static) builds, a slimmer image.

### 27. Air-gapped and offline

**A+ looks like**
- One command builds a dated, hashed bundle of every data source (RustSec, OSV, KEV, EPSS,
  NVD cache); one command imports it on the air-gapped host.
- `--offline` is tested to make no network request at all.
- Every report records the bundle it used.

**Bar today:** Trivy and Grype (offline DB bundles), Dependency-Track (mirrors).

**fleetreach:** A+ for the pure-Rust offline build. Missing for A+ in full: the all-sources
bundle (`db sync` covers OSV only) and a test that proves `--offline` makes no request.

### 28. Cost

**A+ looks like:** free, permissively licensed, no paid tier gating features.

**fleetreach:** A+ (MIT or Apache-2.0). Nothing to do.

---

## New work this document surfaces (not in any spec yet)

Collected from the "Missing for A+" lines above that no existing spec covers. Each is a
candidate for the prioritization session.

- Incremental re-scan cache and a published 10k-repo benchmark (1).
- What-if simulation over the remediation queue (2).
- Forge coverage beyond GitHub, inventory diff and no-manifest report (4, extends spec 06).
- PR lifecycle and gradual rollout (5, extends spec 07).
- Data-driven ecosystem expansion and a published coverage matrix (7).
- `bun.lock`/`bun.lockb`, pnpm v5 and catalogs (8, finishes spec 02).
- OSV snapshot pinning, incremental record updates, all-sources offline bundle (11, 27).
- Local advisory overlays and data-quality reporting (12).
- Witness chains for Ruby, PHP, .NET, Java and SARIF `codeFlows` (14, 21).
- Scope for Maven, Gradle, Bundler and Cargo; per-scope gating (16).
- `--why` for every ecosystem, all-paths and version distribution (17).
- Package-health signals for the 11 non-Rust ecosystems (20).
- SARIF fingerprints, line locations and a GitLab CI template (21).
- PR-native diff mode and expiring ignores (22).
- CycloneDX and CSAF VEX, signed documents (23).
- Release binaries, Homebrew and a container image (26).
- An `--offline` no-network test (27).
