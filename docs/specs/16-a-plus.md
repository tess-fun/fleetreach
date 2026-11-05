# Spec 16: A+ on every matrix row by 1.8.0

Status: in progress (1.6.0: E2 jar-diff and commit-first runs done, both gates missed; 1.7.0: rpm images implemented) · Written 2026-11-02 after the 1.5.0 release, revised the same day
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

### E2 result: jar-diff sink precision, run 2026-11-02 (gate MISSED)

Setup (scripts and data in `~/fa-testbed/e2/`, differ in `crates/sinks`):

- **Labels**: 100 high/critical Maven advisories, seeded sample (seed 16) of the 390 that
  join SAP project-kb fix commits with the OSV Maven export. Label = every non-test Java
  method whose body changes in the fix commit(s), from a comment- and string-aware source
  parser (`label.py`). 100 of 102 tried got labels; median 4 methods; 46 have 3 or fewer,
  78 have 10 or fewer, 4 have more than 40. A hand check of 10 found the small sets right
  (Netty `readHeaders`, RESTEasy `isValid`, Jackson `SubTypeValidator.<clinit>`) and the
  large ones padded with refactoring, so labels are a slight overestimate of the true sinks.
- **Differ**: `fleetreach-sinks` (`cafebabe` 0.9, pure Rust): methods fingerprinted from
  opcodes with constant-pool references resolved, debug attributes ignored, lambdas folded
  into their declaring method, bridges and other synthetic methods skipped. Last affected
  version = the newest below the fixed one by the validated `ComparableVersion` port.
- **Strategies**: S1 smallest single diff; S2 twin intersection across fix lines, else S1;
  S3 S2 narrowed to classes or methods named in the advisory text.

| | S1 | S2 twins | S3 + text |
|---|---|---|---|
| Advisories with a candidate set | 80 | 80 | 80 |
| Median set size | 11.5 | 7 | 4.5 |
| Set contains a true sink | 60 | 56 | 49 |
| **Set at least 90% precise (bar: 80)** | **10** | **12** | **14** |
| Same, abstaining above 5 methods | 7 | 9 | 12 |

Why it misses:

- **Releases carry more than the fix.** Where the true sink is in the diff (63 of 100), it
  sits among a median of 11 other changed methods. Twin intersection applies to 44 and
  helps little; a majority vote over lines (at least 2) does no better (3 of 15 precise).
- **The named artifact is often not where the fix is** (16): OSV lists `netty-handler`
  for a fix in `netty-codec-http`, `micronaut-http-client` for `micronaut-http`. Diffing
  every sibling artifact in the groupId lifts full recall from 46 to 51 but triples the
  candidate set (median 43 to 117 methods).
- **No diffable pair** (20): the fixed jar is not on Central (11, often a qualifier OSV
  dropped that a `.RELEASE`/`.Final` mapping only partly recovers), no earlier version
  under that coordinate (6), or no bytecode change (3).
- **Deny-list fixes** (Jackson and similar): the changed method is a static initializer;
  the reachable sink is the deserialization entry point, which no diff shows.

Recall, which matters for sound suppression, is not good enough either: the release diff
covers every labelled method for only 46 of the 80 diffable advisories.

**Decision (autonomous, for the user to confirm)**: jar diffs alone do not produce sink data
good enough to suppress on, and do not meet the bar. They stay useful as a cross-check and
as a mapping step (commit methods to the shipped artifact and its descriptors). The sink
pipeline becomes **commit-first**: OSV/project-kb fix commits, then Prospector-style search
for the rest, restricted to methods the release diff confirms. Its precision cannot be
measured on these labels (they come from the same commits), so the next experiment needs
independently hand-labelled sinks. Until a commit-first E2 passes, JVM function-level
reachability is planned as **witnesses only** in 1.7.0, and the matrix keeps row 13 at its
measured grade. The user confirmed the commit-first pivot on 2026-11-02.

### E2b result: commit-first sink precision, pilot run 2026-11-02 (gate MISSED)

Setup (`~/fa-testbed/e2/cf/`, scripts `commits.py`, `sheet.py`, `cfscore.py`):

- **Candidates**: for each of the 100 advisories, every non-test Java method the
  project-kb fix commit(s) touch, with its change kind (added, modified, removed) and its
  old and new source.
- **Labels, independent of the strategies**: a seeded pilot of 40 (seed 1602), labelled by
  hand from the advisory text and the full fix diff before any strategy was scored. A sink
  is a method that exists in the vulnerable version, holds the flawed behaviour, and is
  reached only when the vulnerable feature is used. Plumbing (threading a new flag through
  callers), refactors, logging, cosmetic edits and generic init or registration code are
  not sinks. 6 of 40 have no such method in the fix commits: 4 Jackson deny-list updates,
  Cassandra (the flaw is in a shell script), commons-text (the dangerous lookups are not in
  the diff). Labels are in `cf/hand_labels.py` with the reason for each `None`.
- **Strategies**: C0 every changed method; C1 drop methods the fix added (they do not exist
  in the vulnerable version); C2 drop methods whose only changes are logging, comments or
  braces; C3 narrow to classes or methods named in the advisory text when any are; C4 also
  drop plumbing (no added or removed guard, check or security call, and no more added than
  removed lines).

| 40-advisory pilot | C0 | C1 | C2 | C3 + text | C4 − plumbing |
|---|---|---|---|---|---|
| Median set size | 4.5 | 2 | 2 | 2 | 1.5 |
| Mean precision | 0.45 | 0.52 | 0.52 | 0.55 | 0.59 |
| Mean recall (sinkable) | 1.00 | 1.00 | 1.00 | 0.96 | 0.89 |
| **Set at least 90% precise (bar: 80%)** | **30%** | **35%** | **35%** | **38%** | **45%** |

Commit-first is about three times better than jar diffs (14%), and still far from the bar.
18 of 40 gives a 95% interval of roughly 30% to 60%, so the remaining 60 were not labelled:
no outcome there brings it near 80%. C4 was tuned on these same 40, so 45% is optimistic.
Recall of 1.00 for C0 to C2 is partly circular (sinks were chosen from the fix diff), but a
sink outside the diff was marked `None`, not counted as missed.

Why it misses:

- **No sink in the fix** (6 of 40, 15%): this caps any diff-based method at 85%. Deny-list
  fixes need a different model: gadget class on the classpath plus polymorphic typing
  enabled, a rule, not a sink.
- **Plumbing and refactoring around the fix** (most of the rest): callers that pass a new
  argument (Beam's four `createClient`s, Tomcat's `connectToServerRecursive`), helpers moved
  in the same commit (Spark, ActiveMQ), one commit fixing three CVEs (Jetty), and mass
  log-guard edits (MINA: 50 methods changed, 1 sink). Text and plumbing filters help, and
  start costing recall.
- **Wrong or partial commits**: Infinispan's project-kb commit is a data-format refactor
  with the vulnerable transcoders merely moved.

**Decision (confirmed by the user on 2026-11-02)**: no automatic method gets JVM sinks to
90% precision for 80% of advisories, so automatic sinks never drive suppression. But C1 is
an excellent candidate generator: median 2 methods, nothing the fix added, and every true
sink inside it. A reviewer confirms a 2-method set in about a minute. So:

1. Sinks become **curated data**: the pipeline proposes C1 sets with evidence (commit,
   diff, advisory text match, plumbing flag), a person accepts or edits them, and the
   accepted record goes into the open feed (row 12's auto-curation flow). Reviewed sinks
   are precise by construction; the measured number becomes coverage (share of
   high/critical Maven advisories with a reviewed sink), not precision.
2. **Unreviewed automatic sinks are witnesses only**: they can say "reached", never "not
   reached".
3. **Deny-list advisories** get a rule type (gadget class present plus a polymorphic
   typing entry point reached) instead of a sink.
4. **E3** (CHA suppression yield on 50 services) runs on reviewed sinks only. The pilot's
   34 sinkable labels are the first 34 reviewed records.

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
- **License text**: the `spdx` crate's own `detection` and `text` features, which are pure Rust
  (only `detection-cache` pulls zstd). `askalono` is out: it needs `zstd` on every native target.

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

    **Status: implemented 2026-11-04, unreleased** (`crates/cli/src/scancache.rs`,
    `scripts/benchmark.py`, opt-in `scan --incremental`). Differs from the work above in two
    ways. It caches a repo's matched results only, not parsed sources: reparsing is not where
    the time goes once advisory data is reused. And the key is the binary, the advisory data per
    ecosystem and the bytes of every file a feeder can read. Stating every file instead cost as
    much as the scan (760,000 files, 3.3 s). The input list is checked under strace by
    `docs/differential/scan_inputs.py`: 186 reads across the demo fleets, the test fixtures and
    118 real repos, none outside it. Warm output byte-identical on both testbeds. See the scale
    benchmark page: the 10k fleet halves, but the 13 monorepos gain nothing, since one Maven repo
    keeps the advisory data loading; reuse per unit rather than per repo would fix that.
    Images are not reused.

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

  **Status: implemented 2026-11-04, unreleased** (`crates/cli/src/fix_constraints.rs`, new
  `manifest-bump` strategy). Over real locks and published versions, 531 npm and 600 Cargo
  edits: the strategy agreed with `npm update`, `npm install --package-lock-only` and `cargo
  update --precise` on all but 28, each explained and none a wrong call by the ranges
  (`docs/differential/fix_constraints.py`). The npm range evaluator matches npm's `semver` on
  32,303 pairs. Eight fixture repos through `fix plan` and `fix apply` all pass `npm ci` or
  `cargo metadata --locked`, and a restored range fails both. Not read: `overrides`, pnpm and
  yarn locks, and a target's own requirements.

  A target can itself carry an advisory that begins after the installed version, so `fix plan`
  moves it past those from the OSV exports (`crates/cli/src/fix_targets.rs`). That took the
  fixtures from 4 verified of 8 to 7; the last is `express`, whose target brings in a vulnerable
  `qs`, which needs the registry. Over two real fleets 41 edits moved, 25 of 26 distinct targets
  are published, and the other is a `fixed` bound (`tinymce` 7.9.4) that npm never had.

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

  **Status: implemented 2026-11-04, unreleased** (`crates/cli/src/forges.rs`, kinds `gitea`,
  `forgejo`, `bitbucket`, `bitbucket-server`, `azure`; `fleet sync` inventory diff, recorded
  in `inventory.jsonl`; `SSL_CERT_FILE`). Gitea 1.24 and Forgejo 11 in Docker behind a private
  CA: 120 of 120 repos with a read-scoped token, private repos cloned, 80 without a token, one
  rename, removal and addition each reported. Public listings, cloned too, against each
  forge's own count: Codeberg 17 of 20 and gitea.com 59 of 60 (the rest empty), Bitbucket
  Cloud 406 of 406, Azure DevOps and Data Center 1 of 1. **Not yet proven**: tokens on
  Bitbucket Cloud, Data Center and Azure DevOps, which need accounts. Those listings ran
  anonymously, and the Data Center and Azure lists held one repo, so Data Center paging is
  covered by unit tests only. A rename leaves finding history under the old id.

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
- **Result (1.6.0)**: `~/fa-testbed` holds 39 such lockfiles, not 100. 37 were compared with the
  tools, plus pnpm 5.3 and 5.4 lockfiles generated for the test, and 35 of the 39 comparisons are
  identical. The four others: entries a stale `yarn.lock` still holds (we list them, yarn does
  not install them); a repo with two lockfiles, both read; a tarball dependency, which is no
  registry package; and one workspace where `pnpm list` shows only the root, where our 196
  packages equal the lockfile's own `packages` keys. Two could not be compared: a `bun.lock`
  that fails bun's frozen check, and a real pnpm v5 lockfile out of step with its manifest, whose
  110 packages equal its keys. `bun.lockb` stays a labelled gap: Bun has replaced it with
  `bun.lock`, and the binary layout changes between versions.

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
- **Result (1.6.0, Gradle)**: three real Java builds so far, not 50, resolved by Gradle with an
  init script over the four classpaths: PetClinic 163 of 173, Aeron 17 of 18, Airflow Java SDK
  71 of 109. Misses are Gradle module metadata (`-jvm` artifacts, BOM nodes) and a Kotlin version
  set by a convention plugin. Android builds need the Android SDK and Google's repository and
  are untested. Reading `.module` files is the next step.

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
    Root's OS records checked 2026-11-04 on 6 public `rootpublic/*` images against Trivy
    0.73.0: every Root row Trivy reports is reported, after fixing the `.aikido.N` build order
    (a false clean), `rootio-*` renames, records under either name and apk `-r00072` builds.
    Still open: the language records some hardened-image exports carry (`Echo:PyPI`,
    `Root:npm`). None of those images holds a patched language package, and Trivy matched
    theirs against GHSA and the Go database, so there is nothing yet to validate a rule
    against. A renamed one (`rootio-requests`, `@rootio/undici`) matches no upstream record
    today.
    **Fuzzing done 2026-11-03**: cargo-fuzz targets `rpmdb` (SQLite with its log, Berkeley
    DB, NDB, seeded with the test databases), `image_layers` (a program of colliding paths,
    link cycles and whiteouts over several layers, plus raw tar bytes), `jar` and
    `os_packages`, ten minutes each in a Linux container: 26.4 million runs, no panic, hang
    or memory blow-up. All four run in CI's short fuzz job. They do not build on this Mac
    (no C++ headers in the Command Line Tools for libFuzzer), so run them in `rust:1.90`.
    **Java archives and gems in images: implemented 2026-11-03, unreleased**
    (`fleetreach_os::jar`). Evidence in order: `pom.properties`, file name with the group
    settled against the advisory data, OSGi manifest; anything else is a coverage gap. On
    five images (Tomcat 9.0.50, Jenkins 2.346.1, Elasticsearch 7.10.1, Spring PetClinic,
    Ruby 3.1.2), all 90 packages Trivy 0.73.0 reports as vulnerable are reported, with no
    advisory missing except two from ruby-advisory-db that osv.dev lacks. Trivy names some
    jars from its Maven Central checksum index, which fleetreach does not have: those stay
    coverage gaps (38 on Tomcat, none vulnerable there).
  - **Phase 2 (1.7.0)**: rpm family: read-only SQLite, BDB and NDB readers, RPM header
    parsing, `rpmvercmp` comparator; Red Hat, Alma, Rocky, CentOS, SUSE, openSUSE, SLE
    Micro, Azure Linux, openEuler, Mageia, TuxCare. Unfixed statuses (affected, will not fix,
    fix deferred, under investigation, end of life) from Red Hat's and SUSE's CSAF VEX feeds,
    since the OSV Red Hat export holds only fixes. Direct feeds for distros osv.dev lacks:
    Amazon Linux (ALAS), Oracle Linux (OVAL), Photon (CVE metadata), Bottlerocket. OS
    end-of-life warnings from endoflife.date data, bundled for offline use.
    **Status: rpm images implemented 2026-11-02, unreleased** (`fleetreach_os::rpmdb`,
    `RpmVersion`, wired into `scan --image`). Pure-Rust readers for all three databases, no
    new dependency: SQLite is a read-only b-tree walker (overflow chains, interior pages, the
    write-ahead log applied up to its last valid commit frame); Berkeley DB reads only pages
    a hash bucket reaches, so headers of erased packages left on free pages are never
    reported; NDB verifies each blob's adler32. Installed sets equal `rpm -qa` (name, epoch,
    version, release, arch, source rpm, modularity label) on 18 real images, 0 differences,
    from CentOS 7 to Fedora 41 in all three formats. The comparator agrees with rpm 4.20's
    `rpm.vercmp` on 538,780 pairs from the eight rpm exports and the installed versions.
    Findings equal an independent evaluation of the exports with rpm deciding every
    comparison on 12 images: 1,130 findings, 0 missing, 0 extra (AlmaLinux 8.8, 9.2, 9;
    Rocky 8, 9.2, 9; UBI 8.8, 9; Azure Linux 3; CBL-Mariner 2; Leap 15.5, 15.6). Distros
    matched: Red Hat (BaseOS, AppStream, CRB; binary names), AlmaLinux (binary names),
    Rocky, openSUSE, SLES 15 (Basesystem, Server Applications), SLE Micro, Azure Linux,
    Mageia, openEuler. **Found**: Oracle Linux 9 ships an empty stray
    `/usr/lib/sysimage/rpm/rpmdb.sqlite` while its real database is `/var/lib/rpm`; both
    locations are read, the empty one gives way, and two that disagree are a gap (simpler and
    as safe as evaluating the `%_dbpath` macro).
    **Status: direct feeds implemented 2026-11-03, unreleased** (`fleetreach_os::feeds`,
    fetched by distro sync). Amazon Linux 2 and 2023 (`updateinfo.xml` from the core
    repository's mirror list and `repomd.xml`), Oracle Linux 7 to 10 (OVAL, decoded by
    `bzip2-rs`, pure Rust and MIT/Apache; the `bzip2` crate's pure-Rust backend carries the
    bzip2-1.0.6 license, which `deny.toml` does not allow) and Photon OS 3.0 to 5.0 (CVE
    metadata) converted to OSV records with
    binary names. Oracle's criteria are read structurally (test, object, `evr` state "less
    than"); Ksplice and FIPS branches are left out (their own epoch-10 or `ksplice` builds);
    each file's definitions for other releases and its ELBA (bug fix) definitions are
    skipped; an unrecognized criterion fails the conversion. Module streams: the record
    carries `ecosystem_specific.module` and matches only its stream, from the modularity
    label or `/etc/dnf/modules.d` for unlabelled module builds (an unknown stream still
    matches). Validated against the distributions' own tools: Amazon Linux 2 old image 261
    of 261 (`yum updateinfo list security`), Amazon Linux 2023 old image 260 of 260 (`dnf
    updateinfo list --security --releasever=latest`), Oracle Linux 8.7 with `nodejs:18` and
    `php:7.4` installed 371 of 374, Oracle Linux 9 3 of 3, current Amazon images 0 and 0;
    Photon 4.0 252 of 252 against the raw feed evaluated with rpm's `rpm.vercmp`. **Found**:
    (1) Oracle's OVAL omits some reissued ELSAs (ELSA-2024-0606, whose CVEs ELSA-2024-12164
    carries): the 3 misses, no CVE lost. (2) An older module build carries no modularity
    label (php 7.4.6 for el8.3): gating on the label alone was a false clean on 26 pairs,
    fixed by the `modules.d` fallback. (3) Photon's `cve_id` is sometimes a Black Duck id
    (BDSA), which has no public page; those link the feed file. **Still open in phase 2**:
    CentOS and Fedora are gaps; RHEL module streams in the OSV data are not told apart (the
    OSV Red Hat records carry no stream); the rpm comparison against Grype. (Module streams
    and the Grype comparison since done, below.)
    **Status: RHEL module streams implemented 2026-11-03, unreleased.** osv.dev's Red Hat,
    AlmaLinux and Rocky records carry no stream (82,869 of Red Hat's 638,319 affected
    entries have module-build fixes); the stream comes from the summary's `name:stream` words
    when the entry's fix is a module build (1 word on 71%, several on 26%, none on 3%, which
    stay ungated). Rules, all from dnf's modular filtering: another stream's advisory neither
    matches nor counts as the release having spoken (else it hid Red Hat's open status for
    the installed stream, a false negative found on UBI 8); a non-module fix never applies to
    a module build (RHEL 8 `perl:5.24` vs perl 5.26's fix); a module-build fix compares by
    version-release (`RpmVersion::parse_fix`), as an advisory lists one build per module
    context. **Found**: a subpackage's own epoch became its source rpm's (`perl-base`
    `0:2.27` made perl's source `0:5.32.1`); the source now takes the epoch of the binary
    at its own version. Validated with `dnf updateinfo list --security` in images with php,
    nodejs, ruby, perl and postgresql streams: Rocky 8 46 cross-stream extras to 1 (a
    lagging updateinfo), AlmaLinux 8 100 to 0 and equal to dnf, Rocky 9 every in-stream row;
    the remaining dnf-only rows are dnf listing a newer stream's advisory (php:8.3 for php:8.2)
    that `dnf upgrade` would not install (checked with `check-update`), Rocky's republished
    records and alias-merged ids. UBI 8 (no updateinfo): 171 other-stream pairs gone, 27 Red
    Hat open statuses back, Grype v0.121.1 751 of 751. The 22-image Grype set is unchanged.
    **Status: OS end-of-life warnings implemented 2026-11-03, unreleased**
    (`fleetreach_os::eol`). A bundled endoflife.date snapshot (`crates/os/data/eol.tsv`, 250
    releases of 16 products, MIT data, refreshed by `scripts/update-eol.py`); os-release maps
    to a product (CentOS 8 Stream told apart by its name) and release (exact `VERSION_ID`,
    then major.minor, then major). A release past `eol` is an `unmaintained` warning
    `EOL-<product>-<cycle>` naming the extended-support end where there is one. Checked on
    the 24 rpm images: flagged Amazon Linux 2 (both), CentOS 7, Fedora 41, Leap 15.5 and
    15.6, SLES 15.6 (LTSS until 2028-12-31); Grype v0.121.1 flags only Amazon Linux 2 and
    Fedora 41. Not covered by endoflife.date: Azure Linux, openEuler, Bottlerocket.
    **Status: CBL-Mariner 2.0 OVAL implemented 2026-11-03, unreleased.** Microsoft's OSV for
    Mariner 2 stopped in April 2026 (every record `modified` 2026-04), its OVAL on 2026-05-06;
    both look final. Against the OVAL, osv.dev lacks 269 pairs and lists 153 fixes as open, and
    has 1,485 pairs the OVAL does not, so the OVAL is an overlay (`Azure Linux:2::oval`, one
    record per CVE) that supersedes per CVE and package, not a replacement. Definitions: `true`
    with "less than" (and optional "greater than") is a fixed range, `false` with "less than or
    equal" is open to `last_affected`, `Not Applicable` is `ranges: []`, "not affected". A
    package can have several version lines (golang 1.18 and 1.22). **Found**: lower bounds
    carry the release tag (`0:1.19.0.cm2`), which rpm orders above `1.19.0-1.cm2`, so those
    builds would fall in neither line; the tag is dropped. Validated on 2.0.20230126: Grype
    v0.121.1 134 of 134 with no status difference, raw OVAL evaluated with rpm's ordering 111 of
    111; 70 extras are 55 OVAL pairs (Grype lacks `openssl` CVE-2022-4304, which the OVAL lists
    below `-21`, and subpackages of hits) and 15 from Microsoft's OSV records. Current image:
    the 2 pairs osv.dev missed now match. Azure Linux 3 needs no overlay: its OSV is daily.
    **Status: Fedora implemented 2026-11-03, unreleased.** Fedora publishes nothing to osv.dev;
    the vendor feed is the updates repository's `updateinfo.xml.zst` (Bodhi's FEDORA ids),
    `type="security"` only, CVEs from the Bugzilla reference titles, falling back to
    `archives.fedoraproject.org` on a 404. Releases 41 and later (older ones ship xz, and are
    past their end of life), so Fedora 40 and older stay a gap. Validated on a Fedora 43 GA
    image: 26 of 26 advisories and 51 of 51 advisory and package pairs equal to `dnf
    updateinfo list --security`; a current Fedora 41 image 0 and 0.
    **Status: CentOS Linux implemented 2026-11-03, unreleased.** CentOS 6, 7 and 8 match Red
    Hat's records for the release they rebuilt (6 and 7 `server`, 8 BaseOS, AppStream, CRB)
    plus Red Hat's VEX opens (as the rebuilds borrow them), binaries by name, namespace
    `centos`. osv.dev's Red Hat records have no issue date (`published` is the import date),
    so a cut-off date cannot tell which fixes CentOS got; instead `crates/os/data/centos.tsv`
    (21,359 rows, 840 KB, from the final vault.centos.org repositories by
    `scripts/update-centos.py`, which checks its rpm comparator against the 800 golden pairs
    first) gives the highest build per package and module stream, and a fix above it is
    "fixed only in another line" (`fleetreach_os::centos`). **Found**: CentOS rebranded some
    builds (`dhcp 4.2.5-83.el7.centos.2` for `83.el7_9.2`, firefox, grub2, about 500 binaries),
    which rpm orders below Red Hat's fix: a false positive on each, fixed by comparing such a
    build against Red Hat's fix rewritten as `.el<N>.centos`. Validated against Grype
    v0.121.1: CentOS 7 (2020 image) 12,619 common pairs, 0 status differences; Grype-only are
    a 4.18 `kernel-core` Grype matches to other kernels' opens and Red Hat's vim-minimal "not
    affected" (as on UBI 8); extras are newer VEX opens. CentOS 8 (8.4) 1,286 common, 557
    status differences, all Red Hat fixes after CentOS 8's end that CentOS never built (Grype
    calls them fixed). Every fixed status on both images checked independently against the
    Red Hat fix versions and the snapshot (296 of 296). CentOS Stream stays a gap (built
    ahead of RHEL).
    **Status: Bottlerocket implemented 2026-11-03, unreleased.** Feed
    `advisories.bottlerocket.aws/updateinfo.xml.gz` (1,841 advisories, 190 KB) converted by the
    updateinfo converter into one `Bottlerocket` ecosystem; packages from
    `usr/share/bottlerocket/application-inventory.json` (no rpm database). **Found**: (1) the
    real files are under `<arch>-bottlerocket-linux-gnu/sys-root/` with `/usr` a symlink, and
    the image reader selects files before symlinks resolve, so the selector strips that prefix.
    (2) Release images are EROFS, not ext4, despite the `root.ext4.lz4` name. (3) Old GHSA
    advisories give the OS release as the package version at epoch 0 (`runc 0:1.19.0`); the
    packages took epoch 1 with upstream versions, so the epoch is load-bearing. (4) Advisories
    since the `bottlerocket-` rename list both names; the inventory has the short one (except
    true `bottlerocket-*` packages), so prefixed names are recorded under both. Validated on
    aws-k8s-1.33 1.66.0 and 1.68.1 (root images from the TUF repository, sha256-checked):
    equal to the feed evaluated with `rpm.labelCompare` (330 and 0); Trivy 0.73.0 200 of 200
    reported, 130 extra = kernel BRSAs of 2026-10-26 missing from Trivy's vuln-list.
    **Status: Red Hat CSAF statuses implemented 2026-11-03, unreleased.** The CSAF index
    (`csaf:redhat`, 415 MB archive, about 7 minutes and 6.8 GB RSS to index, so never
    started by a scan) is derived on first use into `Red Hat:enterprise_linux:N::vex`
    exports (about 20 s, cached under the index's size and mtime). It is a distro
    *fallback*: consulted for a package only for CVEs the release's own records do not name
    for it. One OSV record per CVE and release: a component fixed on a main-stream CPE
    (`cpe:/o:redhat:enterprise_linux:8::baseos`; EUS, AUS, E4S and TUS CPEs are ignored)
    gets the highest fix; one not affected there gets no range (an explicit clean); one
    listed against `red_hat_enterprise_linux_N` as affected, will not fix, fix deferred, out
    of support or under investigation gets an open range and the status. Order: fix, then
    not affected, then status. Matching takes the binary's entries first, then the source
    package's open entries for CVEs the binary has none for. Module streams come from the
    purl's `rpmmod`. Validated against Trivy 0.73.0 (Docker): UBI 8.8 947 of 947 and UBI 9
    538 of 538 with the same status, 0 missed; 19 and 2 extra, all source-package open
    statuses (CVE-2021-28861 on python3-requests and friends, whose sources Red Hat lists as
    affected), kept on purpose. **Found**: (1) osv.dev's Red Hat export lags the VEX (21
    fixed findings Trivy had, missing even after a fresh sync), hence the main-stream fixes.
    (2) A source package's fix applied to its binaries was a false positive on 20 pairs:
    Red Hat lists vim fixed and vim-minimal not affected for one CVE. Hence not-affected
    entries and no source fixes for binaries. (3) Purl versions are percent-encoded
    (`module%2Bel8`), and rpm's order treats `%` as a separator: decoded on index and on
    derive.
    **Status: SUSE CSAF statuses implemented 2026-11-03, unreleased.** `csaf:suse` (526 MB
    `.tar.bz2`, 19 GB of JSON over 73,700 documents; about 14 minutes and 10.4 GB RSS to
    index into 61,548 records, 207 MB) derives into `<osv ecosystem>::vex` exports per
    product (`openSUSE:Leap 15.6::vex`, `SUSE:Linux Enterprise Server 15 SP6-LTSS::vex`);
    products are matched by name, modules and other products are dropped. SUSE's entries
    name binaries with a `pkg:rpm/suse/` purl. **Found**: (1) SLES matched only the
    Basesystem and Server Applications modules and not LTSS, a false clean on SLES BCI
    15.6 (15 of 238 CVEs): osv.dev's Basesystem SP6 records stop at 2026-01-05 and later
    fixes are only under `Server 15 SP6-LTSS`, and packages of other modules (Containers,
    Python 3, Public Cloud, ...) are in their own ecosystems. Now all are matched, as
    optional ecosystems (absent is no gap). (2) Binary-named entries were dropped at load
    (the wanted set held source names only). (3) SUSE's `recommended` names the build to
    use, also for a package it lists `known_affected` (214,371 such pairs, CVE-2025-1372
    on libdw1): an explicit status outranks it, unlike Red Hat where a fix outranks. (4) A
    SUSE update advisory names CVEs it did not fix (SUSE-SU-2025:4092-1 lists
    CVE-2025-1372), so a SUSE open status is suppressed only by a release record that
    matches as affected; Red Hat keeps the release-first rule (its open entries can be about
    another stream). (5) A binary at a version of its own (`libreadline7` 7.0 from `bash`
    4.4) was compared with the source version, a false positive: binary entries now compare
    with the binary's version. (6) Borrowing SLE's open statuses for Leap gave about 190
    extras SUSE's Leap OVAL does not list; Leap borrows SLE SPx fixes only, reported as
    fixed only in another line. (7) SUSE's published `.sha256` matches neither the archive
    nor the tar. Validated against OpenSCAP 1.3.6 evaluating SUSE's OVAL (fixed and
    `-affected` files): SLES BCI 15.6 238 of 238, 0 missed, 1 extra (a gcc15 CVE the VEX
    lists open, newer than the OVAL); Tumbleweed 2 of 2; Leap 15.6 11 of 13 (CVE-2026-40226
    is only an SLE open status, not borrowed; CVE-2026-6732 is in no VEX entry), with the
    extras being borrowed SLE fixes the frozen post-end-of-life Leap OVAL does not track;
    Leap 15.5 2 of 2 (frozen OVAL). Tumbleweed's 2014 bash CVEs come from an osv.dev record
    (openSUSE-SU-2024:10106-1, "fixed in 7.0-92.1" for bash) and are left as osv.dev says.
    **Status: Grype diff done 2026-11-03.** Grype v0.121.1 (DB built 2026-11-03) vs
    fleetreach on the 22 rpm images, compared on (CVE, binary rpm) pairs with fixed/open
    status: 5,951 pairs in common, **0 status disagreements**; Amazon Linux 2 and 2023
    (old images) equal (540 and 562). Grype-only pairs, by cause: (1) AlmaLinux and Rocky:
    Grype applies Red Hat's data to the rebuilds, 582 to 611 unfixed statuses per image plus
    5 to 120 RHEL fixes the rebuild's own records do not name. **Decided and done**: the
    rebuilds now borrow Red Hat's open statuses and "not affected" for their RHEL release
    (`Distro::borrowed_opens`), not its fix versions (Red Hat's builds); rescanned, all of
    Grype's open statuses on the six images are reported, 0 status disagreements, and the
    remaining Grype-only pairs are the unborrowed RHEL fixes (5, 11, 0, 15, 120, 68). (2) Oracle
    8.7 and 9: Grype applies Oracle's FIPS epoch-10 builds (`10:3.7.6-...fips`) to plain
    gnutls and libgcrypt, 5 and 87 false positives. (3) Amazon Linux 2: Grype's
    `ALAS2MOCK2-2026-002` applies a separate rpm 4.14 stream; Amazon's ALAS2-2026-3984 fixes
    the installed build. (4) UBI 8.8 vim-minimal (20): Red Hat lists it not affected where
    vim is fixed; fleetreach follows Red Hat. (5) CBL-Mariner 2 (2): osv.dev's Azure Linux
    export lacks the Mariner 2 records Grype reads from Microsoft's OVAL, a data gap.
    fleetreach-only pairs: openSUSE (Grype reports nothing for Leap or Tumbleweed), SUSE and
    Red Hat VEX open statuses newer than or outside Grype's data, Photon BDSA ids, SUSE
    security updates with no CVE, Oracle's bind-export-libs (in the ELSA's OVAL), and a
    Rocky record republished with a later fix. **Found and fixed**: (a) AlmaLinux's ALBA
    and ALEA records were reported as vulnerabilities (a coreutils bug fix); records with no
    CVE are now skipped (970 ALBA, 218 ALEA). (b) A plain `db sync` asked osv.dev for the
    derived `::vex` ecosystems (404s, a failed sync); they are now left to the scan.
  - **Phase 3 (1.8.0)**: pull by digest from an OCI registry (behind `network`, docker
    config credentials); per-layer attribution and base-image detection from image history;
    base-image rollup and rebuild advice across the fleet; VEX discovered from OCI
    referrers (Trivy 0.73.0 parity); the published differential.
    **Status: layers and base images implemented 2026-11-03, unreleased.** The image reader
    re-reads the package database after each layer that changes it, so a package's layer is
    the first with that name and version unbroken to the top, with nothing held back per
    layer. Language packages take the layer that wrote their file. `Occurrence::InRepo.layer`
    carries index, `diff_id`, build step and `base`; a source finding takes the highest layer
    of its binaries, so `base` never claims a rebuild clears what a later layer also installed.
    Base: the last `CMD` below the image's last layer (Trivy's rule), name from
    `org.opencontainers.image.base.name`. `base_images` groups images by a digest of the base's
    `diff_id`s and counts distinct advisory and package pairs, `fixable` being those with a
    fix. Validated against each package's `Layer.DiffID` in Trivy 0.73.0: Ruby 3.1.2 1,427 of
    1,427, Tomcat 123 of 123, nginx Alpine 23 of 23, Rocky 9 123 of 123, Jenkins 298 of 327
    (the other 29 are jars inside `.hpi` plugins in layer 5 that Trivy does not read; it lists
    the same names from `jenkins-plugin-manager.jar` in layer 7). Two BuildKit images on
    `tomcat:9.0.50-jdk11` rolled up as one base of 10 layers, 123 findings counted once.
    **Status: registry pull implemented 2026-11-03, unreleased** (`crates/cli/src/registry.rs`,
    `--image docker://<ref>`, `ref` in `[[image]]`). Pulls into a content-addressed cache
    (`~/.cache/fleetreach/images`, layouts as hard links) read by the existing OCI layout code,
    so a pulled image and a saved one take one path. A tag's digest is computed from the
    manifest bytes, never taken from the header, and recorded in `provenance.images`. Layers
    must be tar media types, so a Helm chart or other artifact is an error, not an empty
    image. Logins: `credHelpers`, `auths`, `credsStore`, helpers run with no shell and a checked
    name. A login goes only to the registry and a token realm on its domain, over TLS; redirects
    are followed by hand, dropping `Authorization` off the registry's host and refusing
    plain HTTP (localhost excepted). Tested on Docker Hub, gcr.io, ghcr.io, quay.io and
    mcr.microsoft.com anonymously and a local `registry:2` with a Basic login; the same image
    pulled and `docker save`d gives 23 of 23 identical findings with identical layers.
    **VEX from OCI referrers implemented 2026-11-03, unreleased.** `--vex-oci` reads OCI 1.1
    referrers, the referrers tag, and cosign's `.att` tag, on the platform manifest and the
    index. Trivy applies the first document with no signature check; fleetreach reads all of
    them, applies one only when `--vex-oci-key` verifies it (or `--vex-oci-unsigned` is given),
    and refuses a subject naming another image. Validated with real cosign 2.6.1 (`.att` on
    `registry:2`) and 3.0.2 (a Sigstore bundle referrer on zot, on a tag and on a 14-platform
    index) against Trivy 0.73.0: on nginx 1.25.3-alpine and seven statements, Trivy removes 8
    of 74 per-binary findings and fleetreach the same ones rolled up to 4 of 23 source findings,
    keeping `CVE-2023-42363` where one of three binaries is still open. The diff found one bug
    (a binary's name read as its source's). Keyless signatures are not checked: they count as
    unsigned. The published differential is done: 217 public images against Trivy 0.73.0 and
    Grype v0.121.1, 0 unexplained differences, in `docs/differential` and on the website's
    image differential page. It added Go binaries, .NET, Composer, the vendor package rule,
    Ubuntu Pro as a supplement, CentOS 6, RHEL ELS and RHEL 10's records. Debian 7 to 11 read
    osv.dev's frozen export as a supplement. Known limits: CVEs after that October 2024 freeze
    on Debian 10 and 11 (a coverage gap). Rust binaries are read from their `cargo auditable` list
    (checked 2026-11-04 on `bat`, `fd`, `rg` and a built binary: crate lists equal Trivy's), and a
    binary without one is a coverage gap (8 of the 217 images).
    A base with no declared name shows its distribution and fingerprint, as a config does not
    say which tag it came from.
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

    **Status: implemented 2026-11-04, unreleased** (`crates/cli/src/osvdelta.rs`, `snapshot.rs`).
    Measured on the bucket: all 14 exports' listings match their zips on ids and `modified`,
    and a `<id>.json` is byte-identical to its zip entry. The local state is read from the zip,
    not saved from a listing, because a listing newer than the zip would hide a change for good.
    A cache five days old updated in 8 seconds (339 changed records in 8 exports) and all
    329,822 records then matched whole downloads byte for byte, in the same order; a 121-repo
    scan was identical. **Not yet proven: the spec's week of daily syncs.** That needs a real
    week; `docs/differential/osv_sync_compare.py` is the daily check. Per-release exports
    (`Debian:12`, `Ubuntu:22.04:LTS`) have no listing and stay whole downloads.
    Bundle: online `scan --enrich` against import into an empty home with
    `sandbox-exec` denying network: every report section identical on 1,182 findings (3 KEV,
    1,105 EPSS). 44 images on 80 sources: 19,286 findings identical. Live CSAF and CVE indexes
    were not in those runs; the bundle treats them as files like the rest, and a unit test
    covers them.

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
- **Proof**: coverage of reviewed records (bar: 80% of high/critical Maven advisories have
  a reviewed sink, a deny-list rule, or a reviewed "no method-level sink" marker); unreviewed
  automatic sinks only ever produce witnesses; zero false `NotReachable` on a soundness
  corpus of known-reachable CVE reproducers (vul4j-style); suppression yield published per
  ecosystem (Endor claims up to 97% noise reduction; fleetreach publishes its measured
  number, whatever it is).
- **Research gate**: E2 decides whether the sink data is good enough (1.6.0); E3 decides
  whether JVM suppression is worth shipping or JVM ships witnesses only. A miss is
  published with its number, as for Python's 3%.
- **E2 outcome (2026-11-02)**: jar diffs alone MISSED (14 of 100 at 90% precision against a
  bar of 80); see "E2 result" under Research findings. Commit-first (E2b, 40 hand-labelled)
  MISSED too: 45% at best, with 15% of advisories having no sink in the fix at all. Decided (user,
  2026-11-02): sinks become reviewed, curated records (pipeline proposes, a person accepts);
  unreviewed sinks are witnesses only; the proof is coverage of reviewed records. See "E2b
  result".
- **Curated sink records (built 2026-11-02, unreleased)**: `crates/sinks` holds the record
  format (`fleetreach-sinks/1`, fail-closed loader), a Java source reader, and `sinkpropose`
  (fix commits to a `proposed` record, from a local clone or fetched files). On the pilot the
  Rust proposer is right for 24 of 40 (sinks at least 90% precise, or no sinks where none
  exist), including all 4 Jackson deny lists, which it proposes as gadget rules. Seed data:
  100 `proposed` Maven records in `crates/sinks/data/` (40 with E2b labels, 60 straight from
  the proposer), none reviewed yet; `data/README.md` has the review steps.

#### 14. Import-graph witness chains (A- to A+)

- **Gap**: npm and PyPI only; no SARIF `codeFlows`.
- **Work**: import extractors for Ruby, PHP (composer autoload), .NET (`using` plus
  project.assets.json), Java/Kotlin (imports to packages through jar class indexes), Elixir,
  Swift; SARIF `codeFlows` from chains.
- **Effort**: M. **Release**: 1.6.0.
- **Proof**: on 20 real repos per ecosystem, every chain's first hop points at a real import
  line (checked by script); positive-only asserted in tests.

  **Status: implemented 2026-11-04, unreleased** (`crates/cli/src/import_reach.rs`,
  `reachability.import_site`, SARIF `codeFlows`). `docs/differential/import_chains.py`, with
  patterns of its own: 7,561 chains over 132 repos (20 to 24 with chains per ecosystem) and every
  first hop is an import line. On a scan of 119 of those repos 509 of 709 findings in these ecosystems
  got a chain, none `NotReachable`. Differences from the plan: hops after the first are lockfile
  edges, not imports read from installed code, so an optional dependency counts; jars are read
  only if already in `~/.m2` or the Gradle cache, and without one the coordinates must decide;
  a package sharing a namespace prefix can take a class of its neighbour (`laravel/ui` for
  `Illuminate\Foundation\Auth\User`); npm and Python witnesses gained code flows but no
  import line.

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

  **Status: implemented 2026-11-04, unreleased** (`crates/cli/src/scope.rs`,
  `fleetreach_nuget::build_only`, `--fail-on-dev`, `[settings.gate.scope] dev`, guide "Gate on
  what ships"). `docs/differential/scope_oracle.py`, no package the tool ships called dev
  anywhere: `cargo tree` on 39 repos, 975 of 1,243 dev-only packages caught, the rest build
  dependencies of third-party crates that `Cargo.lock` cannot separate; `go list` on 14 repos, 15
  of 16; Bundler's own Gemfile evaluation on Mastodon 65 of 65 and Discourse 63 of 66; `mix
  deps` under `MIX_ENV=prod` on Realtime and Plausible, 16 of 29 because both ship git deps, so
  only declared dev deps count. `bundle list` with groups excluded and `mvn dependency:list
  -DincludeScope=runtime` matched exactly on fixtures, and `dotnet publish` left out every
  NuGet package called dev. Two false devs were found this way and fixed: Go needs the import
  closure through dependency source (gitea's `klauspost/compress`), and Bundler needed edges
  from `PATH` gems (Discourse's `unicode-display_width`). Go therefore needs `vendor/` or a
  warm module cache, and stays runtime without. Swift and Julia stay runtime, their lockfiles
  do not mark test dependencies. GitHub Actions stay in scope by default.

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

  **Status: 1.6.0 part implemented 2026-11-04, unreleased** (`crates/cli/src/licensetext.rs`,
  `licensefetch.rs`, `licenses --detect --download`, `[settings.licenses] mismatch`). Against
  ScanCode 32.5.0: 1,964 of 2,000 packages from local caches and 1,435 of 1,500 from downloads
  agreed exactly, 2 disagreed, neither a real difference. Against cargo-deny 2,013 of 2,015
  crates. Fetched with local caches hidden, 4,149 packages read the same as from local files,
  and 9,164 archives matched their lockfile hashes, Go's tree hash included. Differences from
  the plan: only license files are kept, not tarballs, which is about 7 KB a package; NuGet,
  Packagist, Maven and wheel-only Python are not fetched, having no hash of the served file;
  a sentence naming a license in prose and source headers are not read. NOTICE files and
  conflicts stay 1.7.0.

#### 21. Unmaintained / unsound (A to A+)

- **Gap**: RustSec only.
- **Work**: opt-in `--health` (sends package names, named in `--help`): npm deprecated, PyPI
  and RubyGems and crates.io yanked, NuGet deprecation, Packagist `abandoned` with its
  replacement, Go retractions, archived repos and Scorecard via deps.dev; alternatives where
  the registry names one; cached per package.
- **Effort**: M. **Release**: 1.6.0.
- **Proof**: 200 flagged packages checked against the registries; offline without cache is a
  gap, never clean.

  **Status: implemented 2026-11-04, unreleased** (`crates/cli/src/health.rs`, `scan --health`,
  `[settings.health] min_scorecard`). `docs/differential/health_oracle.py`, by another route
  than the code reads: 220 of 220 flagged packages and 183 of 183 clean ones agreed, across all
  nine registries. Archived matched `gh api` on 76 of 76 repos. Differences from the plan:
  deps.dev does not report archived repos, so that check reads GitHub and needs a token, and is
  a note without one; Scorecard is opt-in, because 3.0 flags about one package in ten; Hex
  retirements and Maven relocations were added; PyPI project status (PEP 792) is not read, it
  sits only in the full simple-API listing; Julia's registry has nothing to read.

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

  **Status: implemented 2026-11-04, unreleased** (`crates/cli/src/attribute.rs`, exact-version
  check in `lockline.rs`; expiry shipped earlier). `docs/differential/pr_attribution.py` makes
  17 fixture PRs across all 12 ecosystems and each lockfile format, 11 from real repos and 6
  (Cargo, Go, Maven, Swift, Actions, Julia) from small written fixtures. Each names the
  right file and entry, and the same report with no git change does not gate, except Maven: a
  transitive package with no lockfile is in no file, so it stays not placed and gates. A
  rewound fixture only changes a lockfile, so manifest causes are proven by unit test.

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
- **Status: XML, tag-value, discovery, release assets and staleness implemented 2026-11-04,
  unreleased** (`crates/cli/src/sbom_input.rs`, `release_sboms` in `sources.rs`).
  `docs/differential/sbom_formats.py` over six repos (Rust, Go, npm, PHP, Python, Ruby) and three
  GitHub exports: 75 documents from Syft, Trivy, cdxgen, sbom-tool and GitHub, with spdx-tools
  and cyclonedx-cli conversions, 0 format differences, 0 purls lost against a separate read of
  the JSON, and direct flags differing only in Syft's two forms of one Cargo repo, whose graphs
  differ. `pkg:golang` and `pkg:cargo` route to the matchers: `docs/differential/sbom_vs_lockfile.py`
  over gitea, caddy, meilisearch, deno, zed and calcit, 547 findings shared with the lockfile scan
  across Syft and Trivy, 0 extra, 9 missing, all packages Trivy did not list. Release assets fetched from GitHub (cosign, Trivy) and a private repo on Gitea 1.24
  in Docker. OS purls implemented 2026-11-05, unreleased (`crates/os/src/purl.rs`):
  `docs/differential/sbom_os.py` over 27 images, Syft and Trivy, CycloneDX and SPDX, 108 documents:
  OS findings identical to the image's own scan in 104; the 4 others are SPDX documents of images
  with module builds, which carry no stream label and say so in a coverage gap. **Left**: SPDX 3
  (1.7.0); SPDX as YAML, RDF or XML is refused; GitLab release
  assets are links and are not fetched; staleness says nothing in a shallow clone.

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
