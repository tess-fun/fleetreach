# ICE scoring of the open work

Status: ranked with weights I×5, C×2, E×3 · 2026-10-30

Every open piece of work from the specs and from
[capability-excellence.md](capability-excellence.md), scored on Impact, Confidence and Ease.
Wave 1 (OSV sync, coverage labels, pnpm/yarn, GitHub sources, NVD cache) is done and not
listed. Items are grouped by area, not ranked: the ranking waits for the weights.

## Scales

**Impact** (value to someone securing many repos), forced into a bell curve: few 1s and 5s,
some 2s and 4s, most items 3.

| Score | Meaning |
|-------|---------|
| 5 | Changes whether the target user can adopt or act on fleetreach at all |
| 4 | Closes a gap a typical fleet hits in the first weeks |
| 3 | Clearly useful to many fleets, but they can work around it |
| 2 | Useful to some fleets or some situations |
| 1 | Nice to have, or matters to very few |

**Confidence** (how sure we are that the impact is real and the approach works):

| Score | Meaning |
|-------|---------|
| 5 | Proven: measured on our data, or the same thing shipped by competitors with a clear design here |
| 4 | Strong evidence, small open questions |
| 3 | Reasonable belief; one significant unknown |
| 2 | Speculative; depends on an assumption we have not tested |
| 1 | Unknown; needs an experiment first |

**Ease** (inverse of effort, focused working days):

| Score | Effort |
|-------|--------|
| 5 | 2 days or less |
| 4 | 3 to 5 days |
| 3 | 1 to 2 weeks |
| 2 | 2 to 4 weeks |
| 1 | more than 4 weeks |

Impact distribution below: two **5**, six **4**, sixteen **3**, seven **2**, three **1**
(34 items).

## Scores

| ID | Item | Source | I | C | E | Effort | Why these scores |
|----|------|--------|---|---|---|--------|------------------|
| **Coverage and data** |||||||
| C1 | `bun.lock` (text), pnpm v5, pnpm catalogs; `bun.lockb` stays a labelled gap | spec 02, cap 8 | 2 | 4 | 4 | 4 d | bun is a small share of JS repos; formats are documented; binary `bun.lockb` excluded (text is bun's default since 1.2) |
| C2 | Python: `pylock.toml` + fully pinned requirements files | spec 03, cap 9 | 4 | 4 | 4 | 4 d | requirements files are everywhere in Python fleets; pinned files are a full lock; OSV-Scanner shows demand |
| C3 | .NET: restore output, `packages.config`, csproj direct-only | spec 03, cap 9 | 3 | 4 | 3 | 1.5 wk | most .NET repos lack `packages.lock.json`; restore output only exists after a build, which limits it |
| C4 | Maven transitive resolver, validated against `mvn` | spec 04, cap 9 | 4 | 3 | 1 | 5 wk | Java fleets are large and transitive is where JVM vulns live; resolver fidelity is the risk |
| C5 | New ecosystems by data (C/C++ first) + public coverage matrix | cap 7 | 2 | 2 | 2 | 3 wk | OSV data for C/C++ is thin and unmeasured here; needs a data check before building |
| C6 | Local advisory overlays + data-quality report | cap 12 | 3 | 3 | 4 | 4 d | orgs track internal advisories; data-quality flags make "clean" more honest; demand unproven |
| C7 | All-sources offline bundle, OSV snapshot pinning, incremental OSV updates | caps 11, 27 | 3 | 4 | 3 | 1.5 wk | strengthens the air-gap differentiator; regulated users ask for it; OSV publishes per-record modification data |
| **Fleet scale and discovery** |||||||
| F1 | Incremental re-scan cache + published 10k-repo benchmark | cap 1 | 2 | 3 | 3 | 1.5 wk | perf profile is already healthy, so the gain is speed at very large scale and a credible number |
| F2 | GitLab sources (cloud and self-managed) | spec 06, cap 4 | 4 | 4 | 4 | 4 d | many companies run GitLab; same design as GitHub, different API |
| F3 | Blind-spot report: repos with no readable manifest + inventory diff between syncs | cap 4 | 3 | 4 | 4 | 3 d | fail-closed at the fleet level ("what are we not seeing"); cheap once sources exist |
| F4 | Bitbucket, Azure DevOps, Gitea sources | cap 4 | 2 | 4 | 3 | 1.5 wk | real but smaller user bases; known APIs |
| **Prioritization** |||||||
| P1 | Exposure context, owners, SSVC decisions and gate | spec 08, cap 15 | 4 | 3 | 3 | 2 wk | the CTEM piece: ranks by what matters; risk is that users must fill in context |
| P2 | What-if simulation over the remediation queue | cap 2 | 2 | 3 | 4 | 4 d | nice planning aid; the queue already answers most of it |
| P3 | Dev scope for Maven, Gradle, Bundler, Cargo + per-scope gating | cap 16 | 3 | 4 | 3 | 1.5 wk | cuts noise in four more ecosystems; data is in the lockfiles |
| P4 | `--why` for every ecosystem + version distribution + JSON | cap 17 | 3 | 4 | 4 | 4 d | the graphs exist now; "who still runs log4j 2.14" is a classic fleet question |
| P5 | Import-graph witness chains for Ruby, PHP, .NET, Java | cap 14 | 2 | 2 | 2 | 4 wk | positive-only chains; the Python study found little suppression value |
| P6 | JVM reachability experiment (E1 to E3) | spec 12, cap 13 | 2 | 1 | 3 | 2 wk | an experiment: its value is the go/no-go answer; sink data is the unknown |
| **Mobilization** |||||||
| M1 | Fix plan + lock-only apply + re-scan verification | spec 07, caps 3, 5 | 5 | 4 | 2 | 3 wk | turns the queue into work done; competitors prove demand; verification reuses `diff` |
| M2 | Pull requests via `gh`/`glab`, PR lifecycle, gradual rollout | spec 07, cap 5 | 4 | 3 | 2 | 3 wk | the last mile after M1; lifecycle (rebase, close) is the hard part |
| M3 | Upgrade safety: fleet evidence, alternatives, risk level | spec 13, cap 3 | 3 | 4 | 4 | 4 d | unique fleet signal ("7 repos already run it"); all data is in the scan |
| M4 | Rust API impact via `cargo-semver-checks` + call graph | spec 13, cap 3 | 1 | 2 | 2 | 3 wk | Rust only, needs the static engine; precision unproven |
| M5 | History, MTTR, SLA clocks and gate | spec 09, cap 6 | 3 | 4 | 3 | 2 wk | gives a program its metrics without a server; plain files |
| M6 | Notifications, GitHub issues, static HTML dashboard | spec 09, cap 6 | 3 | 3 | 3 | 2 wk | routing by owner; unknown how many users want this from a CLI vs their own tooling |
| **Supply chain** |||||||
| S1 | Malware first-class + lockfile hygiene signals | spec 10, cap 18 | 3 | 4 | 4 | 4 d | worm waves make this timely; `MAL-` records are already matched, so the gain is gating and hygiene |
| S2 | Typosquats, release-age cooldown, fleet novelty | spec 10, cap 18 | 3 | 3 | 3 | 2 wk | strong signals during outbreaks; false-positive rate is the unknown |
| S3 | License inventory, policy and gate | spec 11, cap 19 | 3 | 4 | 3 | 2 wk | legal asks alongside security; data sources are known |
| S4 | Package health for non-Rust: deprecated, yanked, archived | cap 20 | 3 | 3 | 3 | 1.5 wk | extends a Rust strength fleet-wide; needs registry metadata (opt-in network) |
| **Interop and CI** |||||||
| I1 | SBOM output: CycloneDX 1.6 + SPDX | spec 05, cap 24 | 4 | 5 | 4 | 5 d | compliance and Dependency-Track interop; every competitor has it; data already in hand |
| I2 | SBOM input (purl routing) | spec 05, caps 10, 25 | 3 | 4 | 3 | 1.5 wk | covers Gradle without locking and image SBOMs; depends on users having SBOMs |
| I3 | SARIF fingerprints, line regions, `codeFlows`, GitLab CI template | cap 21 | 3 | 5 | 4 | 4 d | alerts persist across runs in GitHub; known SARIF fields |
| I4 | PR-native diff mode + expiring ignores | cap 22 | 3 | 4 | 4 | 4 d | the PR gate teams expect; ignores that lapse stop silent rot |
| I5 | CycloneDX and CSAF VEX, signed documents | cap 23 | 1 | 3 | 3 | 1.5 wk | OpenVEX already leads; few consumers need the other formats |
| **Operating model** |||||||
| O1 | Release binaries for every platform, Homebrew, container image | cap 26 | 5 | 5 | 5 | 2 d | today install needs a Rust toolchain, a real barrier for security teams; standard tooling exists |
| O2 | Test that `--offline` makes no network request | cap 27 | 1 | 5 | 5 | 1 d | protects a promise already kept; low user-visible value |

## Ranking (weights I×5, C×2, E×3)

Score = 5 × Impact + 2 × Confidence + 3 × Ease (maximum 50). Ties are broken by Impact, then
Ease.

| Rank | ID | Item | I | C | E | Effort | Score |
|------|----|------|---|---|---|--------|-------|
| 1 | O1 | Release binaries for every platform, Homebrew, container image (**implemented, uncommitted**) | 5 | 5 | 5 | 2 d | **50** |
| 2 | I1 | SBOM output: CycloneDX 1.6 + SPDX | 4 | 5 | 4 | 5 d | **42** |
| 3 | C2 | Python: `pylock.toml` + fully pinned requirements files | 4 | 4 | 4 | 4 d | **40** |
| 4 | F2 | GitLab sources (cloud and self-managed) | 4 | 4 | 4 | 4 d | **40** |
| 5 | M1 | Fix plan + lock-only apply + re-scan verification | 5 | 4 | 2 | 3 wk | **39** |
| 6 | I3 | SARIF fingerprints, line regions, `codeFlows`, GitLab CI template | 3 | 5 | 4 | 4 d | **37** |
| 7 | P1 | Exposure context, owners, SSVC decisions and gate | 4 | 3 | 3 | 2 wk | **35** |
| 8 | F3 | Blind-spot report: repos with no readable manifest + inventory diff between syncs | 3 | 4 | 4 | 3 d | **35** |
| 9 | I4 | PR-native diff mode + expiring ignores | 3 | 4 | 4 | 4 d | **35** |
| 10 | M3 | Upgrade safety: fleet evidence, alternatives, risk level | 3 | 4 | 4 | 4 d | **35** |
| 11 | P4 | `--why` for every ecosystem + version distribution + JSON | 3 | 4 | 4 | 4 d | **35** |
| 12 | S1 | Malware first-class + lockfile hygiene signals | 3 | 4 | 4 | 4 d | **35** |
| 13 | C6 | Local advisory overlays + data-quality report | 3 | 3 | 4 | 4 d | **33** |
| 14 | M2 | Pull requests via `gh`/`glab`, PR lifecycle, gradual rollout | 4 | 3 | 2 | 3 wk | **32** |
| 15 | C3 | .NET: restore output, `packages.config`, csproj direct-only | 3 | 4 | 3 | 1.5 wk | **32** |
| 16 | C7 | All-sources offline bundle, OSV snapshot pinning, incremental OSV updates | 3 | 4 | 3 | 1.5 wk | **32** |
| 17 | I2 | SBOM input (purl routing) | 3 | 4 | 3 | 1.5 wk | **32** |
| 18 | M5 | History, MTTR, SLA clocks and gate | 3 | 4 | 3 | 2 wk | **32** |
| 19 | P3 | Dev scope for Maven, Gradle, Bundler, Cargo + per-scope gating | 3 | 4 | 3 | 1.5 wk | **32** |
| 20 | S3 | License inventory, policy and gate | 3 | 4 | 3 | 2 wk | **32** |
| 21 | M6 | Notifications, GitHub issues, static HTML dashboard | 3 | 3 | 3 | 2 wk | **30** |
| 22 | S2 | Typosquats, release-age cooldown, fleet novelty | 3 | 3 | 3 | 2 wk | **30** |
| 23 | S4 | Package health for non-Rust: deprecated, yanked, archived | 3 | 3 | 3 | 1.5 wk | **30** |
| 24 | C1 | `bun.lock` (text), pnpm v5, pnpm catalogs; `bun.lockb` stays a labelled gap | 2 | 4 | 4 | 4 d | **30** |
| 25 | O2 | Test that `--offline` makes no network request | 1 | 5 | 5 | 1 d | **30** |
| 26 | C4 | Maven transitive resolver, validated against `mvn` | 4 | 3 | 1 | 5 wk | **29** |
| 27 | P2 | What-if simulation over the remediation queue | 2 | 3 | 4 | 4 d | **28** |
| 28 | F4 | Bitbucket, Azure DevOps, Gitea sources | 2 | 4 | 3 | 1.5 wk | **27** |
| 29 | F1 | Incremental re-scan cache + published 10k-repo benchmark | 2 | 3 | 3 | 1.5 wk | **25** |
| 30 | P6 | JVM reachability experiment (E1 to E3) | 2 | 1 | 3 | 2 wk | **21** |
| 31 | C5 | New ecosystems by data (C/C++ first) + public coverage matrix | 2 | 2 | 2 | 3 wk | **20** |
| 32 | P5 | Import-graph witness chains for Ruby, PHP, .NET, Java | 2 | 2 | 2 | 4 wk | **20** |
| 33 | I5 | CycloneDX and CSAF VEX, signed documents | 1 | 3 | 3 | 1.5 wk | **20** |
| 34 | M4 | Rust API impact via `cargo-semver-checks` + call graph | 1 | 2 | 2 | 3 wk | **15** |
