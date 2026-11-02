# Spec 16: A+ on every matrix row by 1.8.0

Status: plan, not started · Written 2026-11-02 after the 1.5.0 release, revised the same day
(three releases instead of two; a path to A+ researched for every row) · Supersedes the
"out of scope" parts of [spec 14](14-out-of-scope.md) for containers, curated research,
hosted triage and malware analysis (user decisions of 2026-11-02, not re-argued here)

This spec turns the A+ criteria in [capability-excellence.md](capability-excellence.md) into
a plan. For each of the 29 graded rows of the competitive matrix
(https://claude.ai/artifact/WFVHTdpXcT7mYoSWZnRo5w), it gives the gap at 1.5.0, the work, its
effort and dependencies, the release, and how A+ will be proven. The bar on each row is the
best-scoring competitor today, and A+ means matching it and then beating it on something it
cannot do. The eight principles in capability-excellence.md (fail-closed, fleet-native,
offline, validated against the real thing, explainable, deterministic, machine-first, safe by
construction) apply to every item and are not repeated per row.

Effort: S = days, M = 1 to 2 weeks, L = 3 to 5 weeks, XL = more than 5 weeks of focused work.

## Summary

| Row | 1.5.0 | Best other (Nov 2026) | Path to A+ | Effort | Releases | Proof |
|---|---|---|---|---|---|---|
| Many repos, one report | A | A- | incremental cache, published 10k benchmark | M | 1.6 | warm = cold output, benchmark script |
| Rank by blast radius | A+ | C+ | keep; what-if | S | 1.8 | what-if = real fix + re-scan |
| Batched fix queue | A+ | B- | keep; per-repo constraints | S | 1.6 | package managers accept target |
| Repo discovery | A- | A | 5 more forges, inventory diff | M | 1.6 | live listing per forge |
| Automated fix PRs | A- | A+ Renovate | lifecycle, every manager, schedules, automerge, rollout | L | 1.6, 1.7 | 30-repo PR corpus |
| Dashboard, triage, tickets | B- | A | triage files, `serve`, Jira | L | 1.6, 1.7, 1.8 | merge tests, VEX round trip |
| Ecosystems | B | A+ Renovate (updates) / A OSV-Scanner, Trivy | about 30 matchable ecosystems via distros | XL (with containers) | 1.6, 1.7 | per-ecosystem oracle |
| yarn / pnpm / bun | A | A | pnpm v5, catalogs, bun.lockb, PM oracle | S | 1.6 | package managers' listings |
| Manifest-only resolution | B+ | A- | Gradle catalogs, consented resolution | L | 1.6, 1.7 | `gradle`, `uv`, `mvn` |
| Container / OS packages | - | A+ Trivy | Trivy's distro list plus more, unfixed statuses, layers, base-image rollup | XL | 1.6, 1.7, 1.8 | `dpkg`/`apk`/`rpm` + Trivy/Grype diff |
| Advisory DB auto-fetch | A- | A | incremental sync, snapshots, one bundle | M | 1.6 | sync = full download |
| Curated vuln research | C | A Snyk, Sonatype | automatic curation, published as an open feed | XL | 1.6, 1.7, 1.8 | coverage and lead time vs Snyk's public DB |
| Function-level reachability | B | A Endor | own sink data from jar diffs + fix commits; JVM, then JS/TS, Python, .NET | XL | 1.6, 1.7, 1.8 | labelled sinks, soundness corpus, yield |
| Import-graph witness chains | A- | B+ | six more ecosystems, SARIF codeFlows | M | 1.6 | chains point at real imports |
| KEV + EPSS | A | A | EPSS trend, exploit maturity | S | 1.6, 1.7 | history replay |
| Repo context / SSVC | A | C+ | `tag_rules` | S | 1.6 | unit tests |
| Dev / build-only scoping | B+ | A- | every ecosystem, per-scope gate | M | 1.6 | `cargo tree`, `mvn` scopes |
| Fleet-wide provenance | A | B+ | all paths, version distribution | S | 1.6 | vs `npm ls`, `cargo tree -i` |
| Malware / typosquat | B- | A+ Socket | **light touch by user choice**: static capability diff | M | 1.7 | benign-corpus alert rates |
| License compliance | B | A+ Sonatype | text detection, NOTICE, conflicts | L | 1.6, 1.7 | vs ScanCode |
| Unmaintained / unsound | A | A- | registry health for 11 ecosystems | M | 1.6 | registry spot checks |
| SARIF + exit gating | A+ | A | keep; regions, codeFlows, GitLab template | S | 1.6 | code scanning upload |
| Gate on new findings | A | A | PR attribution, expiring exceptions | M | 1.6 | PR fixtures |
| VEX | A+ | A- | keep; CycloneDX VEX, CSAF VEX, signing | M | 1.7 | schemas, Trivy/Grype consume |
| SBOM output | A- | A | hashes, CycloneDX 1.7, SPDX 3, NTIA | M | 1.6, 1.7 | official schemas |
| SBOM input | B | A+ Dependency-Track | XML, tag-value, SPDX 3, discovery, OS purls | M | 1.6, 1.7 | multi-generator corpus |
| No server needed | A+ | A | keep; musl, Windows ARM | S | 1.6 | release artifacts |
| Air-gapped | A+ | A | keep; all-sources bundle, no-network test | S | 1.6 | CI job without network |
| Cost | A+ | A+ | nothing | none | n/a | n/a |

Every row has a path to A+ except **malware**, which the user chose to keep light
(2026-11-02: no live malware samples, no registry-watch service, no AI review). Its target is A
on the static signals, and the matrix will say so. Three paths are **research-gated**: each
has a measurable bar written into its row and a decision point in 1.6.0 or 1.7.0, so a miss
is found early and published, not hidden. They are function-level reachability (sink
precision and suppression yield), curated research (coverage and lead time against Snyk's
public database) and containers (zero unexplained differences against Trivy).

## Research findings (2026-11-02)

### OSV data volume per ecosystem

Counted from the zip directories of every osv.dev export (`<eco>/all.zip`, 47 ecosystems) on
2026-11-02. Script: session scratchpad `osv/cd2.py`; raw numbers in `osv/eco-counts.json`, a
copy of the summary in the shared side-session notes.

| Group | Ecosystem: records |
|---|---|
| Already covered | npm 231,006 (222,933 MAL), PyPI 26,778 (11,975 MAL), Go 9,815, Packagist 7,397, Maven 7,224, RubyGems 5,472, crates.io 3,028, NuGet 1,967, Julia 1,717, Hex 420, SwiftURL 64, GitHub Actions 57 |
| Distros, deb family | Debian 73,078 (61,634 DEBIAN-CVE tracker records, incl. unfixed), Ubuntu 72,992 (806 MB zip) |
| Distros, apk family | Alpine 4,845, Wolfi 368,020 (309 MB), Chainguard 1,356,742 (1.1 GB) |
| Distros, rpm family | Red Hat 24,010 (RHSA only), SUSE 24,134, openSUSE 15,151, Azure Linux 20,062, openEuler 9,328, AlmaLinux 6,343, Mageia 6,340, Rocky 4,664 |
| Hardened images | MinimOS 185,310, CleanStart 21,266, Root 20,820, TuxCare 22,177, Alpaquita 17,452, Echo 12,423, Bitnami 10,074, BellSoft 931 |
| Small language feeds | opam 35, Hackage 33, Pub 14, CRAN 14, GHC 3 |
| Not package-matchable | GIT 119,626 (commit ranges), Linux 33,366 (kernel), OSS-Fuzz 4,275, Android 3,700 |

- **No new language ecosystem has real volume.** Pub, CRAN, Hackage and opam hold 96 records
  together; CocoaPods, Conan, vcpkg and Conda have no OSV or GHSA ecosystem at all. This
  confirms the Pub lesson.
- **The volume is in distros and hardened images.** With the deb, apk and rpm families,
  fleetreach matches about 30 osv.dev ecosystems, more than any other open-source scanner.
  That is the Ecosystems row's path: vulnerability-matchable ecosystems, which is what
  OSV-Scanner, Trivy and Grype are graded on (Renovate's 120 managers are update managers).
- **Record shapes** (sampled): Alpine ranges always carry a fix (secdb lists fixed issues
  only). Debian has 2,247 no-fix ranges in 20k records (unfixed, with an `urgency` such as
  `unimportant` or `end-of-life`). Red Hat records are RHSA only, so RHEL's unfixed and "will
  not fix" CVEs must come from Red Hat's CSAF VEX feed. Wolfi/Chainguard carry
  `ecosystem_specific.components` and many withdrawn records (1,560 of 20k).
- **Size**: Chainguard (1.1 GB) and Ubuntu (806 MB) cannot be fetched by default. Sync must
  fetch only the distros the fleet's images contain.

### Fix-commit and symbol coverage per ecosystem

Live, non-malware records in each osv.dev export (scratchpad `osv/`, 2026-11-02):

| Ecosystem | Records | Link a commit or PR | Symbol data |
|---|---|---|---|
| Maven | 7,102 | 52% | 0% |
| PyPI | 14,199 | 65% | 0% |
| npm | 7,663 | 59% | 0% |
| Packagist | 7,241 | 51% | 0% |
| RubyGems | 1,097 | 66% | 0% |
| NuGet | 1,144 | 50% | 0% |
| Go | 9,612 | 64% | 11% |
| crates.io | 2,883 | 49% | 47% |

Endor Labs' patents describe exactly this pipeline (advisory, then fix commits, then changed
functions), and its own 2024 research says about half of advisories reference fix commits.
So fleetreach starts from the same base as the leader. SAP's Prospector (Apache-2.0) finds a
missing fix commit in the top 10 candidates for 84% of advisories and in first place for 65%,
which closes much of the other half.

### Jar diff experiment (JVM sinks without fix commits), run 2026-11-02

Spec 12's E1 (52% of Maven records link a commit) looked like a no-go. A different source of
sink data does not need commits: every Maven advisory with a `fixed` version has both the
last affected and the fixed jar on Maven Central, and the difference between the two is a
superset of the fix. Over 40 random high/critical advisories (5,821 candidate fixed events),
script `osv/jardiff.py`:

- Both jars were found for 40 of 40 sampled.
- Classes whose bytes changed, plus added and removed: median **12**; 15 of 40 at 5 or fewer;
  23 of 40 at 20 or fewer.
- Outliers come from rebuild noise (groovy 808 changed, postgresql 383), which a method-level
  comparison that ignores line tables and constant-pool order removes. Two of 40 showed no
  class change (fix outside bytecode, or the advisory is on a sibling artifact), and those
  get no sink.

Narrowing the diff to the vulnerable methods uses evidence that is all open and offline:

1. **Normalized method diff**: compare method bodies, not class bytes.
2. **Twin intersection**: most fixes ship on several lines at once (Tomcat 9.0.x, 10.1.x and
   11.0.x for one CVE). Methods changed in every line's fix release are almost always the
   fix itself.
3. **Fix commit diff** where one is linked (52%) or found by Prospector-style search.
4. **Advisory text**: class and method names named in the description.
5. **Test code in the fix commit**: the public API the regression test calls is the entry
   point to the sink.

This makes JVM sink data plausible for most advisories, not half. It must still pass E2
(precision on a labelled sample). The same diff works for npm, PyPI, NuGet and RubyGems
packages, which ship code in the artifact.

### Competitors, as of Nov 2026

- **Trivy v0.76.1** (2026-10-21). 2026: pylock.toml (0.70.0), CycloneDX 1.7 and Ubuntu 26.04
  (0.71.0), Bottlerocket (0.72.0), VEX discovered from OCI artifacts (0.73.0), Echo
  Maven/npm (0.76.0). OS coverage: Alpine, Wolfi, Chainguard, MinimOS, RHEL 6 to 9, CentOS,
  Alma, Rocky, Oracle, Azure Linux, Amazon Linux, SUSE/openSUSE/SLE Micro, Photon, Debian,
  Ubuntu, Bottlerocket, distroless, Bitnami. Unfixed reported; Red Hat statuses Affected, Will
  Not Fix, Fix Deferred, End of Life; Debian Fixed, Affected, Fix Deferred, End of Life.
  Sources beyond OSV: Amazon Linux Security Center (ALAS), Oracle OVAL, Photon advisories.
  https://github.com/aquasecurity/trivy/releases, https://trivy.dev/latest/docs/coverage/os/,
  https://trivy.dev/latest/docs/scanner/vulnerability/
- **Grype v0.121.0** (2026-10-19): Ubuntu ESM and lightweight Go reachability (v0.116.0),
  distro-dropped matches with `--show-suppressed` (v0.119.0), NVD SSVC stored (v0.120.0), OS
  end-of-life warnings (v0.121.0). https://github.com/anchore/grype/releases
- **OSV-Scanner v2.x**: image scanning for Debian, Ubuntu, Alpine with layer attribution;
  guided remediation still experimental. https://google.github.io/osv-scanner/
- **Renovate 44.199.2** (2026-11-01): 120 managers; schedules, `groupName` and presets,
  `automerge` + `platformAutomerge`, `minimumReleaseAge`, `rebaseWhen`, dependency dashboard,
  `vulnerabilityAlerts` and `osvVulnerabilityAlerts`, `lockFileMaintenance`,
  `prConcurrentLimit` 10, `prHourlyLimit` 2; GitHub, GitLab, Bitbucket, Azure DevOps, Gitea,
  Forgejo, SCM-Manager. https://docs.renovatebot.com/modules/manager/,
  https://docs.renovatebot.com/configuration-options/
- **Dependency-Track 5.2.1** (2026-10-25; Hyades archived into 5.x in May 2026): service
  accounts with key expiry, HMAC-signed webhooks (5.2.0), initial KEV support (5.1.0),
  Jira and DefectDojo integrations; sources NVD, GHSA, OSV, Snyk, Trivy, VulnDB, OSS Index,
  JVN, VulnCheck KEV. https://github.com/DependencyTrack/dependency-track/releases
- **GitHub security overview**: Overview/Risk/Coverage views, campaigns with owners and
  goals, no per-alert SLA or assignment, paid products only.
  https://docs.github.com/en/code-security/security-overview/about-security-overview
- **Socket**: 47 alert types (supply chain 29, quality 4, maintenance 2, license 8,
  vulnerability 4), a registry firewall (proxy for npm, PyPI, Maven, Cargo, RubyGems, NuGet,
  Go), and SocketAI (static pre-screen, then LLM review; 99% precision on a 5,115-package
  benchmark). https://docs.socket.dev/docs/issues-list,
  https://docs.socket.dev/docs/socket-firewall-registry-mode, https://arxiv.org/abs/2403.12196
- **Endor Labs**: function-level reachability needs a successful build; without one it falls
  back to dependency-level or "pre-computed" reachability. Function data from fix commits.
  https://docs.api.endorlabs.com/scan/sca/reachability-analysis,
  https://patents.google.com/patent/US12189788
- **Semgrep Supply Chain**: Java reachability through per-advisory rules (version match plus
  code-pattern match), written by its research team.
  https://semgrep.dev/docs/supported-languages
- **Snyk**: claims disclosure ahead of NVD for most open-source advisories (third-party
  figures of 92% for JavaScript and 47 days are not traceable to a primary source). NVD moved
  to risk-based triage in 2026. Snyk's advisory pages are public (security.snyk.io), so
  coverage and lead time can be measured from outside.
  https://snyk.io/blog/nvd-multi-source-vulnerability-intelligence/
- **GHSA unreviewed** advisories are NVD records with no package mapping (about 265k of 288k,
  https://arxiv.org/html/2602.06009v1): CVE text, not matchable data.
- **Prospector** (SAP, Apache-2.0): ranks candidate fix commits for an advisory; top-10 hit
  84%, top-1 65% on 1,248 advisories. https://github.com/SAP/project-kb

### Building blocks in pure Rust

- **OCI images**: tar plus gzip or zstd layers. `tar` and `flate2` (zlib-rs, already used)
  are pure Rust; zstd through `ruzstd` (pure-Rust decoder), not `zstd` (C). Whiteouts are a
  small in-house layer merge.
- **dpkg** status and `status.d/*` (distroless) are RFC 822 text, with `Source:` mapping
  binary to source packages. **apk** `/lib/apk/db/installed` is line-based, with `o:` as the
  origin.
- **rpm** has three databases with no mature pure-Rust reader: SQLite (`rpmdb.sqlite`, RHEL
  9+), Berkeley DB hash (`Packages`, RHEL 7/8, Amazon Linux 2), NDB (`Packages.db`, SUSE). A
  read-only SQLite B-tree reader is a few hundred lines (crates like `sqlite_wasm_reader`
  show the shape); BDB hash and NDB are smaller. All fuzzed.
- **Bytecode**: Java class files are a stable, simple format; an in-house reader (as spec 12
  planned) is S/M. .NET CIL metadata (ECMA-335 tables) is the same kind of work.
- **Source parsers**: JavaScript/TypeScript through `oxc_parser` (pure Rust, MIT, production
  ready per its authors). Python through `rustpython-parser` on crates.io (to verify its
  maintenance; `ruff_python_parser` is not published on crates.io).
- **`serve`**: `axum` on `hyper`/`tokio`, no vendored C, plain HTTP behind a reverse proxy,
  in its own `serve` cargo feature.
- **License text**: `askalono` is pure Rust apart from an optional zstd cache feature; build
  without it.

## Release split

The principle: start every long bet in 1.6.0 so later releases finish rather than start them;
ship each independent S/M item as early as it fits; put dependent work after what it depends
on; keep each release about 8 weeks.

**1.6.0: foundations, quick wins, and every long bet's first phase**

- Containers phase 1: deb and apk families from image tarballs and rootfs dirs (Debian,
  Ubuntu, Alpine, Wolfi, Chainguard, MinimOS, Alpaquita, distroless), comparators validated.
- Sink pipeline phase 1 and the JVM experiments: jar and package diffs, method
  normalization, twin intersection, fix-commit diffs; E2 (precision on a labelled 100) and
  E3 (suppression yield on 50 services). Decision recorded.
- Curated research phase 1: CVE 5.x records, vendor CSAF (Red Hat first), local advisory
  overlays, `db quality`.
- Triage files and `fleetreach triage`.
- Fix PRs phase A: lifecycle, caps and canaries, pnpm, yarn, Composer, Bundler, NuGet and
  Maven edits.
- Quick wins: incremental re-scan cache and benchmark, three more forges, incremental OSV
  sync with snapshots and one offline bundle, no-network test, SARIF regions and codeFlows,
  GitLab CI template, PR attribution and expiring exceptions, scopes for every ecosystem with
  per-scope gating, registry health signals, EPSS trend, `tag_rules`, all-paths and version
  distribution, pnpm v5/catalogs/bun.lockb, Gradle version catalogs, SBOM hashes, CycloneDX
  1.7, SBOM input XML and tag-value with discovery, license text detection, witness chains
  for six more ecosystems, musl and Windows ARM builds.

**1.7.0: the second phases**

- Containers phase 2: rpm family (SQLite, BDB, NDB readers), Red Hat and SUSE CSAF VEX for
  unfixed statuses, direct feeds for Amazon Linux, Oracle, Photon, Bottlerocket, OS
  end-of-life.
- JVM function-level reachability (if E2/E3 pass), and the sink data published as an open
  feed.
- `fleetreach serve` (UI over history and triage files).
- Curated research phase 2: published corrections feed, fix-commit-derived ranges,
  exploit maturity.
- Fix PRs phase B: schedules, grouping presets, automerge on verified PRs, gradual rollout,
  PRs on the new forges.
- Malware, light touch: static capability diff for npm and PyPI.
- License obligations; VEX in full; SPDX 3 output and input; consented Python resolution.

**1.8.0: the A+ finish**

- Containers phase 3: registry pull, layer attribution, base-image rollup across the fleet,
  published differential against Trivy and Grype.
- Function-level reachability for JavaScript/TypeScript, Python and .NET (if their own
  yield bars pass).
- Curated research phase 3: silent-fix detection for the fleet's dependencies, the
  auto-curated advisory feed, the published coverage and lead-time measurement against Snyk.
- `serve` tickets (Jira) and SSO header hardening; what-if over the fix queue.

Dependency graph:

```
containers ph1 (deb/apk) ──► ph2 (rpm, CSAF statuses, direct feeds) ──► ph3 (registry, layers, Trivy diff)
                                ▲
vendor CSAF (curated ph1) ──────┘
sink pipeline + E2/E3 (1.6) ──► JVM reach + sinks feed (1.7) ──► JS/TS, Python, .NET reach (1.8)
                            └─► curated ph2 ranges (1.7) ──► auto-curated feed (1.8)
triage files (1.6) ──► serve (1.7) ──► tickets, SSO (1.8)
                   └─► VEX from triage decisions (1.7)
fix PR lifecycle (1.6) ──► schedules, automerge, rollout (1.7)
forges (1.6) ──► PRs on those forges (1.7)
incremental cache (1.6) ──► serve refresh (1.7), what-if (1.8)
tarball cache (license text, 1.6) ──► malware capability diff (1.7)
```

---

## Per row

Each row: A+ criteria (short form; the full list is in capability-excellence.md), gap at
1.5.0, work, effort, dependencies, release, proof.

### Fleet scale

#### 1. Many repos, one deduplicated report (A to A+)

- **A+**: 10k repos per run with bounded memory and published numbers; alias-aware dedup;
  incremental re-scan; failure isolation; per-repo, per-owner and fleet rollups.
- **Gap**: no incremental cache; no published scale benchmark. Per-owner rollups exist
  (`-f owners`).
- **Work**: content-hash cache of parsed sources (lockfile bytes plus parser version as the
  key), match results reused while the advisory snapshot hash is unchanged. A benchmark page
  from a native arm64 run over `~/fa-testbed` (10k repos): time, RSS, per ecosystem.
- **Effort**: M. **Release**: 1.6.0. **Depends on**: nothing.
- **Proof**: warm run byte-identical to cold run on both testbeds (refactor-verification
  harness); benchmark reproducible from a script in the repo.

#### 2. Rank by fleet blast radius (A+, keep)

- **Beyond the bar**: what-if over the remediation queue ("if these 3 bumps land, what
  clears, what remains").
- **Work**: `fleetreach whatif --bump pkg@ver ...` re-matching an in-memory graph.
- **Effort**: S. **Release**: 1.8.0 (uses the incremental cache). **Proof**: what-if equals a
  real `fix apply` plus re-scan on the demo fleet.

#### 3. Batched cross-repo fix queue (A+, keep)

- **Beyond the bar**: per-repo constraint checks (manifest ranges, peer dependencies) before a
  target is proposed, choosing lock bump or manifest bump accordingly.
- **Effort**: S. **Release**: 1.6.0. **Proof**: the proposed strategy is what `npm install
  --package-lock-only` and `cargo update -p` accept on the fix-test corpus.

#### 4. Repo discovery (A- to A+)

- **A+**: GitHub (+GHES), GitLab (+self-managed), Bitbucket Cloud and Data Center, Azure
  DevOps, Gitea/Forgejo; filters; sparse fetch; inventory diff; repos with no recognized
  manifest reported; least-privilege token docs. Renovate's platform list is the bar.
- **Gap**: Bitbucket, Azure DevOps, Gitea/Forgejo; inventory diff; no-manifest report.
- **Work**: three `[[source]] kind`s over their REST APIs; `fleet sync` reports added,
  removed and renamed repos and writes them to history; repos with zero sources are a
  coverage gap.
- **Effort**: M. **Release**: 1.6.0.
- **Proof**: live listings on test orgs (Gitea and Forgejo in Docker; Bitbucket and Azure
  free tiers) checked against the forge's own count, as was done for GitLab.

#### 5. Automated fix PRs (A- to A+)

- **A+**: Renovate is the bar. For security fixes fleetreach must match its mechanics
  (managers for every scanned ecosystem, schedules, grouping, automerge, rate limits, every
  forge) and beat it on what Renovate does not do: verification by re-scan before a PR opens,
  lock-only edits that run no package code, fleet-wide batching, and a PR body with SSVC,
  reachability and fleet bump risk.
- **Gap**: managers today are Cargo, npm, GitHub Actions, Go, uv.lock; no lifecycle beyond
  create and update; no schedules, automerge or rollout control. Known bug: a rerun whose
  baseline scan fails deletes the earlier verified branch.
- **Work**:
  - Phase A (1.6.0): lifecycle (close obsolete PRs, rebase stale ones, never delete a
    verified branch on a failed baseline); `--max-prs`, `--canary` repos, stop after N
    failures; lock bumps for pnpm (`pnpm update --lockfile-only`), yarn
    (`--mode=update-lockfile`), Composer (`update --no-scripts --no-plugins --no-install`),
    Bundler (`bundle lock --update`), NuGet (lock regeneration), Maven (pom version or
    property edit).
  - Phase B (1.7.0): `schedule` windows in `[settings.fix]`, grouping presets (by package,
    owner, SSVC outcome), `automerge = "verified"` through the platform's native auto-merge,
    PRs on Bitbucket, Azure DevOps and Gitea/Forgejo, Swift/Hex/Julia manifest edits.
    Poetry and Pipenv stay excluded unless their lock commands can be proven not to build
    sdists.
- **Effort**: L. **Release**: 1.6.0 + 1.7.0. **Depends on**: forges (row 4) for phase B.
- **Proof**: a 30-repo PR corpus across all managers on throwaway repos: every PR re-scanned
  clean, nothing new introduced, lockfile accepted by the package manager's frozen install.

#### 6. Hosted dashboard, triage, tickets (B- to A+, self-hosted)

- **A+**: Dependency-Track is the bar: history, trends, audit trail of triage decisions,
  notifications, ticket integrations, SSO. Beat it on: no server needed for the same data
  (files in git), triage expressed as VEX, SSVC and SLA clocks built in.
- **Gap**: no triage states, assignment, audit trail or UI; tickets only as GitHub/GitLab
  issues.
- **Work**:
  - 1.6.0, **triage files**: one file per finding key under `triage/`
    (`triage/<advisory>/<ecosystem>-<package>.toml`) with state (`affected`, `in_triage`,
    `accepted_risk`, `false_positive`, `not_affected`, `fixed`), assignee, `expires`,
    justification, and an append-only `[[log]]`. One file per finding means parallel triage
    never conflicts in git. `fleetreach triage set|list|export`; scan reads them; an expired
    acceptance is a failure; `triage export -f openvex` turns decisions into VEX.
  - 1.7.0, **`fleetreach serve`** (feature `serve`, axum): views over the history dir
    (trends, SLA, owner queues, campaigns) and actions that edit triage files. Auth: none on
    localhost; behind a reverse proxy it trusts a configured identity header only from
    configured proxy addresses and records that identity in the log. No database.
  - 1.8.0: Jira tickets (create, update, close with the finding) next to the existing
    GitHub/GitLab issues; signed webhooks.
- **Effort**: L. **Release**: 1.6.0, 1.7.0, 1.8.0. **Depends on**: incremental cache.
- **Proof**: merge tests (two branches triaging different findings merge clean); triage to
  VEX consumed by Trivy and Grype; HTTP-level tests of every `serve` action; Jira against a
  free cloud instance.

### Coverage

#### 7. Ecosystems (B to A+)

- **A+**: every ecosystem with meaningful advisory volume matched with a validated
  comparator, and a published coverage matrix. Measured against OSV-Scanner, Trivy and Grype,
  fleetreach then leads (about 30 matchable ecosystems).
- **Gap**: 12 language ecosystems, which already include every osv.dev language ecosystem
  with more than 50 records.
- **Work**: comes from row 10. Plus a coverage matrix page generated from code (files read,
  coverage level, comparator, validation result). Pub, CRAN, Hackage and opam are not planned
  (96 records together); the decision is recorded and revisited if osv.dev volume changes.
- **Effort**: S on its own, XL with row 10. **Release**: 1.6.0 (deb, apk) and 1.7.0 (rpm).
- **Proof**: per-ecosystem comparator oracle (row 10).

#### 8. yarn / pnpm / bun (A to A+)

- **Gap**: pnpm v5, pnpm catalogs, `bun.lockb`, and validation against the package managers
  themselves.
- **Work**: pnpm v5 reader, catalog resolution, `bun.lockb` decoder (or a partial-coverage
  label if its format is unstable), an oracle script over `pnpm list --json --depth
  Infinity`, `yarn info --all --json`, `bun pm ls --all`.
- **Effort**: S. **Release**: 1.6.0.
- **Proof**: identical package sets to each tool on 100 real lockfiles from `~/fa-testbed`.

#### 9. Manifest-only resolution (B+ to A+)

- **Gap**: Gradle without locking, Python sdists and unpinned requirements (direct-only), one
  Maven scope edge on Spring Boot.
- **Work**: Gradle version catalogs (`libs.versions.toml`) and literal declarations in
  `build.gradle(.kts)` resolved through the Maven resolver, computed ones named partial
  (1.6.0). Python: `--resolve` with consent through a pinned `uv pip compile --no-build`
  subprocess (1.7.0). Fix the Spring Boot scope edge.
- **Effort**: L. **Release**: 1.6.0 + 1.7.0.
- **Proof**: `gradle dependencies` and `uv pip compile` vs fleetreach on 50 repos each;
  `mvn dependency:list` across the 13 OSS monorepos.

#### 10. Container / OS packages (- to A+)

- **A+**: Trivy is the bar: distro breadth, unfixed vulnerabilities with vendor statuses,
  layer attribution, language packages inside images, VEX. Beat it on: comparators
  validated and published, fail-closed coverage of unknown distros, fleet-wide base-image
  rollup ("14 services on debian:12-slim; one rebuild clears 31 findings"), and SSVC and
  owners on image findings.
- **Gap**: everything.
- **Work**:
  - **Phase 1 (1.6.0)**: `[[image]]` in fleet.toml (tarball or rootfs dir) and `scan
    --image`; OCI and docker-save layer merge with whiteouts; OS detection from
    `/etc/os-release`; dpkg (+ `status.d`) and apk readers with binary-to-source mapping;
    dpkg and apk comparators; matching for Debian, Ubuntu (incl. ESM/Pro records where the
    export carries them), Alpine, Wolfi, Chainguard, MinimOS, Alpaquita/BellSoft, Echo,
    CleanStart, Root; per-distro sync. Unfixed Debian/Ubuntu records are findings with `fix:
    none` and their urgency or priority, never silently dropped (`--distro-ignore-unimportant`
    as an opt-in, Trivy's default). An unknown distro or release is a coverage gap. Language
    packages inside the image go through the existing feeders; files owned by an OS package
    are not reported twice (Trivy's rule).
    **Status: implemented, unreleased** (crate `fleetreach-os`). Comparators: 0 differences
    over 619,997 dpkg and 619,999 apk pairs from the exports (apk validity agrees on all
    42,587 distinct versions). Installed sets equal `dpkg-query -W` / `apk info -v` on 8 real
    images, and findings equal an independent real-tool evaluation of the exports on 11.
    Still open: fuzzing the layer merge, Java archives and gems inside images (reported as
    coverage gaps), and the language records some hardened-image exports carry
    (`Echo:PyPI`, `Root:npm`).
  - **Phase 2 (1.7.0)**: rpm family: read-only SQLite, BDB and NDB readers, RPM header
    parsing, `rpmvercmp` comparator; Red Hat, Alma, Rocky, CentOS, SUSE, openSUSE, SLE
    Micro, Azure Linux, openEuler, Mageia, TuxCare. Unfixed statuses (affected, will not fix,
    fix deferred, under investigation, end of life) from Red Hat's and SUSE's CSAF VEX feeds,
    since the OSV Red Hat export holds only fixes. Direct feeds for distros osv.dev lacks:
    Amazon Linux (ALAS), Oracle Linux (OVAL), Photon (CVE metadata), Bottlerocket. OS
    end-of-life warnings from endoflife.date data, bundled for offline use.
  - **Phase 3 (1.8.0)**: pull by digest from an OCI registry (behind `network`, docker
    config credentials); per-layer attribution and base-image detection from image history;
    base-image rollup and rebuild advice across the fleet; VEX discovered from OCI
    referrers (Trivy 0.73.0 parity); the published differential.
- **Effort**: XL. **Release**: 1.6.0, 1.7.0, 1.8.0. **Depends on**: per-distro sync (row 11),
  vendor CSAF (row 12).
- **Proof**: comparators vs `dpkg --compare-versions`, `apk version -t` and `rpmdev-vercmp`
  in Docker over 500k+ version pairs drawn from the exports; installed sets vs `dpkg-query
  -W`, `apk info -v`, `rpm -qa` in the same images; findings vs Trivy and Grype on 200 public
  images with every difference explained (data source, status policy, or a bug fixed). Fuzz
  the three rpm readers and the layer merge. **Bar for A+: zero unexplained differences.**

#### 11. Advisory DB fetched automatically (A- to A+)

- **Gap**: whole-zip re-downloads, no snapshot pinning, no bundle across all sources.
- **Work**: incremental OSV sync via each ecosystem's `modified_id.csv`; `db snapshot`
  writes a dated, hashed manifest of every source and `--db-snapshot` pins a run to it; `db
  bundle` and `db import` cover OSV, RustSec, KEV, EPSS, Vulnrichment, NVD cache, CSAF and
  distro feeds; distro exports fetched by fleet need.
- **Effort**: M. **Release**: 1.6.0.
- **Proof**: a week of daily incremental syncs byte-identical to full downloads; bundle
  import plus `--offline` scan identical to the online scan.

#### 12. Curated vuln research (C to A+)

- **A+**: Snyk and Sonatype are the bar: advisories early, accurate ranges, function-level
  data, exploit maturity, coverage of issues never filed as CVEs. Their edge is a research
  team. fleetreach's path is **automatic curation from open data, published as an open
  feed**, so its quality is checkable by anyone, which no proprietary database offers.
- **Gap**: OSV and RustSec only.
- **Work**:
  - **Phase 1 (1.6.0), more sources, earlier**: CVE 5.x records from the CVE Program's
    `cvelistV5` repository, which carry CNA-supplied package names, repos and versions
    minutes after publication and before OSV or GHSA review; map them to purls by repo URL
    and package name, marked `unreviewed`. Vendor CSAF VEX (Red Hat, SUSE, Cisco, Siemens,
    through CSAF provider metadata). Local advisories and corrections in OSV format under
    `[settings.advisories] dir`. `db quality` (records with no ranges or severity, withdrawn,
    conflicting aliases).
  - **Phase 2 (1.7.0), better records**: ranges re-derived from fix commits (which tags
    contain the fix) and from the sink pipeline, compared with the published ranges, and
    differences published as corrections in a public `fleetreach-advisories` repository and
    submitted upstream; exploit maturity from open exploit sources (Metasploit modules,
    nuclei templates, Exploit-DB, KEV), shown like Snyk's; function-level data from row 13.
  - **Phase 3 (1.8.0), issues nobody filed**: silent-fix detection for the fleet's
    dependencies: watch their repositories' commits and releases (only the fleet's
    dependencies, so the scale is the fleet's), score commits with Prospector-style rules
    (security keywords, files touched, test additions, sink-pipeline diff shape), and
    publish candidates as `unconfirmed` records that never gate by default. A scheduled job
    in the public repository publishes the whole feed daily; `db sync` fetches it like any
    OSV export.
- **Effort**: XL. **Release**: 1.6.0, 1.7.0, 1.8.0.
- **Proof**: the A+ bar is measured against Snyk's public advisory pages each month on a
  sample of 500 recent open-source advisories: share also present in fleetreach's merged data,
  and median lead time against Snyk's publication date. Target: at least 95% coverage and a
  median lead time no worse than Snyk's. Corrections: the share accepted upstream. Published
  with each release.
- **Research gate**: if the 1.7.0 measurement misses the bar, the gap is published with the
  number, and 1.8.0 work shifts to whatever the misses have in common.

### Prioritization

#### 13. Function-level reachability (B to A+)

- **A+**: Endor Labs is the bar: function-level reachability for Java, Python, JavaScript,
  Go, Rust and .NET, from its own vulnerable-function data, needing a build. Beat it on:
  sound verdicts where provable (Rust today, JVM by design), an open, correctable sink
  dataset, and working without a build where the data allows it.
- **Gap**: Rust (sound MIR) and Go (govulncheck) only; no sink data outside them.
- **Work**:
  - **Sink pipeline (1.6.0)**, for every ecosystem that ships code in its artifacts: for each
    advisory with a fixed version, diff the last affected and the first fixed artifact (jar,
    wheel/sdist, npm tarball, nupkg, gem) at the method level after normalization; intersect
    across the fix lines (twins); intersect with the fix commit's diff (OSV link, or
    Prospector-style search); rank with advisory text and the fix's regression test. Output:
    OSV `affected_functions`-shaped records with a confidence and the evidence that produced
    them. E2: precision on 100 advisories labelled by hand from project-kb's curated fix
    commits. E3: suppression yield of a CHA call graph on 50 real Java services.
  - **JVM (1.7.0)**: pure-Rust class-file reader; CHA then RTA over app classes and
    dependency jars (from Maven resolution; jars are data, never run); roots from `main`,
    servlet and Spring annotations, `META-INF/services`; the soundness spine of the Rust
    engine (reflection, `ServiceLoader`, unresolved `invokedynamic` and native methods widen
    the graph or give `Unknown`). App bytecode from existing build output, from the service's
    own jar inside its container image (row 10 makes this build-free for any service that
    ships as an image), or from the org's own published artifacts by GAV; otherwise a
    consented, sandboxed `mvn -o compile` through the existing `--allow-untrusted-builds`
    path. Sound `NotReachable` feeds VEX and SARIF suppressions. Without app bytecode, a
    library-only pass still answers the transitive case: if no other dependency's bytecode and
    no app import reaches the vulnerable methods, that is reported as "not reached from the
    dependency graph", with its limits stated, never as `NotReachable`.
  - **JavaScript/TypeScript, Python, .NET (1.8.0)**: call graphs from source through
    `oxc_parser` and `rustpython-parser`, and from IL for .NET (in-house ECMA-335 reader).
    JS and Python are positive-only (witnesses, never suppression) unless a soundness argument
    holds for a given package; .NET follows the JVM design.
  - The sink data is published in the open feed (row 12) for correction by anyone.
- **Effort**: XL. **Release**: 1.6.0 (pipeline, experiments), 1.7.0 (JVM), 1.8.0 (rest).
  **Depends on**: Maven resolution (done), containers (app jars from images), row 14.
- **Proof**: sink precision on the labelled 100 (bar: 80% of high/critical Maven advisories
  with a sink whose precision is at least 90%); zero false `NotReachable` on a soundness
  corpus of known-reachable CVE reproducers (vul4j-style); suppression yield published per
  ecosystem (Endor claims up to 97% noise reduction; fleetreach publishes its measured
  number, whatever it is).
- **Research gate**: E2 decides whether the sink data is good enough (1.6.0); E3 decides
  whether JVM suppression is worth shipping or JVM ships witnesses only. A miss is
  published with its number, as for Python's 3%.

#### 14. Import-graph witness chains (A- to A+)

- **Gap**: npm and PyPI only; no SARIF `codeFlows`.
- **Work**: import extractors for Ruby, PHP (composer autoload), .NET (`using` plus
  project.assets.json), Java/Kotlin (imports to packages through jar class indexes), Elixir,
  Swift; SARIF `codeFlows` from chains.
- **Effort**: M. **Release**: 1.6.0.
- **Proof**: on 20 real repos per ecosystem, every chain's first hop points at a real import
  line (checked by script); positive-only asserted in tests.

#### 15. KEV + EPSS (A to A+)

- **Gap**: no EPSS trend; no exploit maturity beyond KEV.
- **Work**: EPSS per finding in history, flagged when it jumps (default +0.1 or into the top
  5%) (1.6.0); exploit maturity from row 12 phase 2 (1.7.0).
- **Effort**: S. **Release**: 1.6.0 + 1.7.0.
- **Proof**: replay of 30 days of EPSS files against a frozen fleet, checked by script.

#### 16. Repo context / SSVC (A to A+)

- **Gap**: `[settings.context.tag_rules]` (forge topics and tags to exposure and impact).
- **Work**: ordered rules, first match wins, applied to sources too; the report names the
  rule that set each value.
- **Effort**: S. **Release**: 1.6.0. **Proof**: unit tests per rule shape; demo fleet.

#### 17. Dev / build-only scoping (B+ to A+)

- **Gap**: Cargo dev/build, Maven test/provided, Gradle configurations, Bundler groups,
  NuGet `PrivateAssets`, Hex `only:`, Go test-only; no per-scope gate.
- **Work**: scope by closure from runtime roots per ecosystem; `[settings.gate.scope]`
  thresholds; CI tools stay in scope by default.
- **Effort**: M. **Release**: 1.6.0.
- **Proof**: `cargo tree -e normal` vs `-e dev,build`; `mvn dependency:list` scopes; `bundle
  list --without`.

#### 18. Fleet-wide provenance (A to A+)

- **Gap**: shortest path only; no version distribution view.
- **Work**: `--why --all-paths` (capped, deterministic), `-f versions <pkg>`, JSON for both.
- **Effort**: S. **Release**: 1.6.0. **Proof**: vs `npm ls --all` and `cargo tree -i`.

### Supply chain beyond CVEs

#### 19. Malware / typosquat (B- to A, light touch by user choice)

- **User decision (2026-11-02)**: keep this row light. Nothing in it ever executes package
  code, malicious or not: no sandbox, no dynamic analysis, no install scripts run. No known
  malware samples are downloaded or kept for testing. No registry-watch service, no AI
  review, no install-time proxy. Leveraging open data is fine (OSV `MAL-` records from
  OpenSSF malicious-packages, already used). This is the one row planned below A+, on
  purpose.
- **Gap**: MAL- records, typosquats, release age, new-to-fleet and lockfile signals exist; no
  look inside package contents.
- **Work (1.7.0)**: reuse the tarball cache from license detection (row 20); for npm and
  PyPI, a static capability scan (network, child process/subprocess, filesystem, env, eval,
  install-time code, obfuscation and high-entropy payloads, bundled binaries) and, the main
  signal, the **difference from the previous version** ("1.4.2 adds network access in
  postinstall"). Alert names follow Socket's where they overlap. Opt-in under `--signals`.
  The scan reads tarball bytes as text only; the tarballs are the fleet's own dependencies,
  already in its lockfiles, and are never unpacked into a place where anything could run them.
- **Effort**: M. **Release**: 1.7.0. **Depends on**: tarball cache (row 20).
- **Proof**: alerts per 1,000 benign packages per alert type, measured on the top 5,000 npm
  and PyPI packages and `~/fa-testbed` (as the typosquat signal's 1.6 per 1,000). Recall
  from synthetic fixtures modelled on public reports, not live samples.
- **If the user later wants A+ here**, the researched paths are: a registry proxy that blocks
  at install time (Socket Firewall's model), a scheduled job that scans new versions of the
  fleet's dependencies, and an optional LLM review of pre-screened files (SocketAI's model).
  None is planned.

#### 20. License compliance (B to A+)

- **A+**: Sonatype is the bar: detected (not just declared) licenses, policy, obligations,
  attribution notices, conflicts.
- **Gap**: metadata licenses only; no text detection, NOTICE output or conflict detection.
- **Work**: (1.6.0) fetch package tarballs by lockfile integrity hash into a shared cache
  (offline from the cache); detect LICENSE/COPYING texts with a pure-Rust SPDX matcher;
  declared vs detected mismatches as findings. (1.7.0) `fleetreach licenses notice`
  attribution files; copyleft conflicts using repo context (AGPL in an internet-exposed
  service, GPL in a repo declared proprietary).
- **Effort**: L. **Release**: 1.6.0 + 1.7.0.
- **Proof**: detected licenses vs ScanCode Toolkit on 2,000 packages; Cargo vs cargo-deny;
  NOTICE files vs `cargo about` and `license-checker`.

#### 21. Unmaintained / unsound (A to A+)

- **Gap**: RustSec only.
- **Work**: opt-in `--health` (sends package names, named in `--help`): npm deprecated, PyPI
  and RubyGems and crates.io yanked, NuGet deprecation, Packagist `abandoned` with its
  replacement, Go retractions, archived repos and Scorecard via deps.dev; alternatives where
  the registry names one; cached per package.
- **Effort**: M. **Release**: 1.6.0.
- **Proof**: 200 flagged packages checked against the registries; offline without cache is a
  gap, never clean.

### CI and interop

#### 22. SARIF + exit gating (A+, keep)

- **Beyond the bar**: line `region`s on lockfile entries, `codeFlows`, a GitLab CI template.
- **Effort**: S. **Release**: 1.6.0. **Proof**: SARIF 2.1.0 schema; upload to GitHub code
  scanning lands on the right line.

#### 23. Gate only on new findings (A to A+)

- **Gap**: no PR attribution; ignores have no expiry or owner.
- **Work**: `diff --base <ref>` attributes each new finding to the changed lockfile or
  manifest lines; ignores gain `expires` and `owner` (shared with triage files); expired
  means failure.
- **Effort**: M. **Release**: 1.6.0. **Proof**: fixture PRs per ecosystem.

#### 24. VEX (A+, keep)

- **Beyond the bar**: CycloneDX VEX and CSAF 2.0 VEX in and out (CSAF in also feeds row 12),
  signing through `cosign` as an external tool, VEX from triage decisions.
- **Effort**: M. **Release**: 1.7.0. **Proof**: schemas; Trivy and Grype honour both formats
  (Docker test, as for OpenVEX).

#### 25. SBOM output (A- to A+)

- **Gap**: no component hashes, CycloneDX 1.7, SPDX 3.0, NTIA check or XML.
- **Work**: hashes from lockfile integrity fields; CycloneDX 1.7 default (1.6 on request) and
  XML (1.6.0); SPDX 3.0 JSON-LD and `--check-ntia` (1.7.0).
- **Effort**: M. **Release**: 1.6.0 + 1.7.0.
- **Proof**: official schemas; NTIA check vs `sbomqs`; hashes checked against registry
  downloads.

#### 26. SBOM input (B to A+)

- **A+**: Dependency-Track is the bar.
- **Gap**: JSON only; no XML, tag-value, SPDX 3, CycloneDX 1.7; no discovery; OS purls
  unrouted.
- **Work**: missing formats (quick-xml is pure Rust); `sbom_discover` in repos and release
  assets; staleness against the newest lockfile commit (1.6.0); SPDX 3 (1.7.0); `pkg:deb`,
  `pkg:apk`, `pkg:rpm` routed to the distro matchers as row 10 lands, so Syft and Trivy image
  SBOMs scan fully.
- **Effort**: M. **Release**: 1.6.0 + 1.7.0.
- **Proof**: SBOMs from Syft, Trivy, cdxgen, Microsoft sbom-tool, GitHub dependency graph
  and spdx-tools in every format: identical component sets across formats of one run.

### Operating model

#### 27. No server needed (A+, keep)

Linux musl and Windows ARM64 builds, slimmer image; `serve` stays optional. S, 1.6.0, proven
by the release artifacts running on each target.

#### 28. Air-gapped (A+, keep)

The all-sources bundle (row 11) and a CI job running the offline suite in a network
namespace without a route. S, 1.6.0.

#### 29. Cost (A+)

Nothing to do. `serve` and every new capability stay in the one free binary; the published
feeds (advisories, corrections, sinks) are open data.

## Biggest risks

1. **Sink precision** (row 13): the jar diff makes sink data available for most advisories,
   but precision is unmeasured until E2. Mitigation: E2 is the first task of 1.6.0, on
   project-kb's hand-checked fixes.
2. **RPM databases in pure Rust** (row 10): three formats, no mature reader. Mitigation: a
   SQLite reader spike in 1.6.0, fuzzing from day one, partial coverage per format if one
   slips.
3. **Lead time against Snyk** (row 12): CVE 5.x records and silent-fix detection are the
   bets; the bar may not be met for advisories Snyk's researchers find themselves.
   Mitigation: measure in 1.7.0, publish the number, aim 1.8.0 at the misses.
4. **Distro data size** (Chainguard 1.1 GB, Ubuntu 806 MB): per-distro fetch and incremental
   sync are prerequisites, not polish.
5. **Scope**: three releases of about 8 weeks each. If a release slips, cut order: what-if,
   SPDX 3, pnpm v5, Jira; never a long bet's phase that a later release depends on.
6. **Matrix honesty**: until each research gate passes, the matrix shows the measured grade,
   not the target.

## Open questions for the user

1. If a research gate misses its bar (sink precision, lead time against Snyk, Trivy diff), is
   publishing the measured grade with the reason acceptable for that release, while the work
   continues?
2. Should `serve` commit triage edits to git itself, or only write files and leave commits to
   the user?
3. Answered 2026-11-02: no malware is ever executed and no known samples are collected;
   benign packages and synthetic fixtures only, plus open data such as OSV `MAL-` records.
