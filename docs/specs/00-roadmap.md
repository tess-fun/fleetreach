# fleetreach gap roadmap

Status: draft for prioritization · 2026-10-30

This index ties together the technical specs written after the competitive analysis
(https://claude.ai/artifact/WFVHTdpXcT7mYoSWZnRo5w) and the CTEM notes
([`../ctem-notes.md`](../ctem-notes.md)). Each gap has its own spec; this page holds the
shared contracts, the dependency graph and a proposed order to discuss.

## The specs

| # | Spec | Gap it closes | CTEM stage | Effort | Impact for a fleet owner |
|---|------|---------------|------------|--------|--------------------------|
| 01 | [OSV database sync](01-osv-db-sync.md) | 10 manual DB flags; no OSV freshness check | discovery | S/M | very high |
| 02 | [yarn, pnpm, bun lockfiles](02-js-lockfiles.md) | JS repos unreadable | discovery | M | very high |
| 03 | [Python and .NET without native lockfile](03-python-nuget-coverage.md) | requirements.txt, pylock.toml, csproj | discovery | M | high |
| 04 | [Maven transitive resolution](04-maven-resolution.md) | pom.xml direct-only | discovery | L | high |
| 05 | [SBOM output and input](05-sbom.md) | no CycloneDX/SPDX | discovery, interop | M | medium/high |
| 06 | [Fleet sources](06-fleet-sources.md) | repos listed by hand as local clones | scoping, discovery | M | very high |
| 07 | [Fix plans, verified patches, PRs](07-fix-plans-and-prs.md) | queue stops at advice | validation, mobilization | L | very high |
| 08 | [Exposure context and SSVC](08-exposure-context-ssvc.md) | every repo weighs the same | scoping, prioritization | M | high |
| 09 | [History, SLAs, notifications](09-history-and-triage.md) | no trend or triage workflow | mobilization | M | medium |
| 10 | [Supply-chain signals](10-supply-chain-signals.md) | malware only via OSV `MAL-` | discovery, prioritization | M | medium/high |
| 11 | [Licenses](11-licenses.md) | no license data | discovery | M | medium |
| 12 | [JVM reachability (research)](12-jvm-reachability.md) | no function-level reach beyond Rust/Go | validation | M then L | medium, uncertain |
| 13 | [Upgrade safety](13-upgrade-safety.md) | no "will this bump break me" | mobilization | S to L | medium |
| 14 | [Decisions on the rest](14-out-of-scope.md) | containers, proprietary intel, NVD speed | n/a | S | low |

The A+ bar for each of the 28 capabilities in the competitive matrix, and the work that no
spec covers yet, is in [capability-excellence.md](capability-excellence.md).

Effort: S ≈ days, M ≈ 1–2 weeks, L ≈ 3+ weeks of focused work.

## How the specs map to CTEM

| Stage | Today | After the roadmap |
|-------|-------|-------------------|
| Scoping | hand-written repo list | org/group sources (06), per-repo exposure, impact and owner (08) |
| Discovery | 12 ecosystems, format holes, manual DBs | auto DBs (01), all common lockfiles (02, 03, 04), SBOM in (05), signals (10), licenses (11) |
| Prioritization | blast radius, KEV/EPSS | SSVC outcomes and outcome-weighted blast radius (08) |
| Validation | reachability (Rust sound, Go, npm/Python witnesses) | re-scan verification of every patch (07), JVM if research says go (12) |
| Mobilization | remediation queue | verified PR campaigns (07), owners (08), SLAs and notifications (09), upgrade risk (13) |

Positioning that follows: "the dependency-surface engine of a CTEM program, from one
binary". Not a CTEM platform (cross-domain, out of scope).

## Cross-cutting contracts

Every spec follows these. They are written once here.

### C1. Coverage model

Each scanned source (lockfile, manifest, SBOM) records a coverage level:

- `full`: the resolved transitive closure with exact versions.
- `direct-only`: declared dependencies only (today's `pom.xml`, Spec 03 csproj and unpinned
  requirements).
- `partial`: some of the graph could not be resolved; the unresolved items are named.

Plus counts of `non_registry` packages (git, path, URL) that are never matchable. Reported
in JSON (`repos[].sources[]`), in the summary line ("3 repos with direct-only coverage") and
as SARIF run properties. `--require-full-coverage` turns anything less into exit 2 (as built; the draft said `--require-coverage full`). Default
stays permissive in 1.x (today `pom.xml` passes as scanned); proposal: make `full` the
default in 2.0.

C1 ships first, with Spec 02 or 03, because it relabels an existing silent weakness
(`pom.xml`).

### C2. Network and privacy

- All network access stays behind the `network` feature and is listed in one place
  (endpoint, purpose, what is sent).
- Downloads of whole public datasets (OSV exports, POMs, KEV, EPSS) are fine by default.
- Anything that **sends the fleet's package names** to a third party (deps.dev resolution,
  registry license lookups) needs an explicit flag per run or setting, named in `--help`.
- `--offline` always works from caches, and a missing cache is a gap, never a clean result.

### C3. Fail-closed

Every new reader, resolver and fetcher fails into an errored gap (exit 2) or a labelled
coverage downgrade, never into silence. Every new signal is additive: its absence is never
presented as safety.

### C4. Schema stability

New report data is additive under `schema_version: 1`. New views are new `-f` values.
Anything that changes existing semantics waits for 2.0.

### C5. External tools and untrusted code

External tools (`git`, `gh`, `glab`, package managers, `cargo-semver-checks`) are invoked as
subprocesses, found on `PATH`, and their absence is a reported gap for that step. Anything
that can execute third-party code goes through `--allow-untrusted-builds` and
`--build-sandbox`, as the static reachability and govulncheck paths already do. The pure-Rust
rule applies to linked dependencies, not to these tools.

## Dependency graph

```
01 OSV sync ──────────────┐
C1 coverage ─┬─ 02 JS     │
             ├─ 03 Py/.NET├──► every scan
             ├─ 04 Maven ─┼──► 12 JVM reach (jars by GAV)
             └─ 05 SBOM   │
06 sources ──┬────────────┴──► 07 fix PRs (full checkouts, base commits)
08 context ──┼───────────────► 07 (owners as reviewers), 09 (owner routing, SLA by outcome)
09 history ──┴───────────────► 10 fleet novelty
13 phase 1 ──────────────────► 07 (risk in PR bodies, lock-bump choice)
```

## Proposed order (to discuss)

Ordering principle: the fleet thesis only holds if the whole fleet is readable on the first
run, so onboarding and coverage come before new kinds of output.

**Wave 1: the first run works on a real fleet** (shipped in 1.2.0, 2026-10-30; open: bun.lock, GitLab sources)
1. 01 OSV sync, phases 1–2.
2. C1 coverage model.
3. 06 fleet sources, phases 1–2 (git + GitHub).
4. 02 JS lockfiles, phase 1 (pnpm v9, yarn v1).
5. 14 NVD quick fix (any patch release).

**Wave 2: see everything, rank by what matters**
6. 03 Python and .NET, phases 1–3.
7. 08 context and SSVC, phases 1–2.
8. 10 supply-chain signals, phase 1 (malware first-class, lockfile hygiene).
9. 05 SBOM output, phase 1.
10. 02 phases 2–3.

**Wave 3: act on it**
11. 13 upgrade safety, phase 1 (fleet evidence).
12. 07 fix plans and PRs, phases 1–3.
13. 09 history and SLAs, phases 1–2.

**Wave 4: breadth and depth**
14. 04 Maven resolver.
15. 11 licenses.
16. 05 input, 09 notify/HTML, 10 typosquats and release age, 08 phases 3–4.

**Research track (parallel, small)**
- 12 JVM reachability experiment E1 (fix-commit coverage) can run anytime; it decides
  whether 12 exists at all.

## Questions for the prioritization session

1. Who is the first real user fleet (size, ecosystems, GitHub vs GitLab)? Its mix should
   reorder Wave 1 (for example, a JVM-heavy fleet pulls Spec 04 forward).
2. Is opening PRs (07) in scope for the product's identity, or should it stop at verified
   local patches plus a plan file that Renovate/Dependabot users can act on?
3. Default for missing exposure context (Spec 08 open question).
4. Release framing: Wave 1 as 1.2, Waves 2–3 as 1.3/1.4, the coverage default flip as 2.0?
