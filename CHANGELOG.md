# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

### Fixed

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

### Added

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

[Unreleased]: https://github.com/tess-fun/fleetreach/compare/v1.5.0...HEAD
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
