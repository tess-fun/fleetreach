---
title: Generate SBOMs
description: Write a CycloneDX 1.7, SPDX 2.3 or SPDX 3.0.1 SBOM per repository from the same lockfiles fleetreach scans, with the dependency graph, coverage and optional vulnerabilities, and check it for the NTIA minimum elements.
sidebar:
  order: 9
---

`fleetreach sbom` writes one SBOM per repo, CycloneDX 1.7, SPDX 2.3 or SPDX 3.0.1, from the same
lockfiles and manifests `scan` reads, in every ecosystem. It needs no advisory data and no
network.

<!-- run: fleetreach sbom -o boms/ 2>&1 -->
```console
$ fleetreach sbom -o boms/ 2>&1
payments-api: 27 package(s) from 1 source(s) -> boms/payments-api.cdx.json
ledger-svc: 25 package(s) from 1 source(s) -> boms/ledger-svc.cdx.json
checkout-web: 8 package(s) from 2 source(s) -> boms/checkout-web.cdx.json
admin-dashboard: 67 package(s) from 1 source(s) -> boms/admin-dashboard.cdx.json
ml-service: 11 package(s) from 1 source(s) -> boms/ml-service.cdx.json
data-pipeline: 6 package(s) from 1 source(s), 1 source(s) with incomplete coverage -> boms/data-pipeline.cdx.json
inventory-svc: 7 package(s) from 1 source(s) -> boms/inventory-svc.cdx.json
billing: 4 package(s) from 1 source(s) -> boms/billing.cdx.json
partner-api: 5 package(s) from 1 source(s) -> boms/partner-api.cdx.json
```
<!-- /run -->

```sh
fleetreach sbom -o boms/ -f spdx              # boms/<repo-id>.spdx.json
fleetreach sbom -o boms/ -f spdx3             # boms/<repo-id>.spdx3.json (JSON-LD)
fleetreach sbom -o boms/ -f cyclonedx-xml     # boms/<repo-id>.cdx.xml
fleetreach sbom -o boms/ --cyclonedx-version 1.6
```

CycloneDX JSON and XML hold the same content. Every format passes its official schema: SPDX
2.3 validates with the SPDX tools, and SPDX 3 with `spdx3-validate`, which checks the SPDX 3.0.1
JSON schema and the SHACL model.

## What each BOM holds

- **The repo** as the root component, with its git remote and commit when it came from a
  fleet source, and each dependency source it read with its coverage.
- **One component per resolved package**, identified by its package URL (`pkg:npm`,
  `pkg:pypi`, `pkg:maven`, `pkg:golang`, `pkg:githubactions` and so on). Development-only
  packages are marked `excluded`.
- **Hashes** of the file the registry serves, where the lockfile records one. See below.
- **The dependency graph** from the lockfiles.
- **Compositions** that say which parts are complete and which came from a source read only
  in part, so an incomplete inventory is never presented as complete. SPDX 3 says the same on
  each relationship (`completeness`), and gives a development-only dependency the
  `development` scope; SPDX 2.3 can only say it in comments.

BOMs are deterministic: set `SOURCE_DATE_EPOCH` and two runs over the same lockfiles write
byte-identical files.

## Component hashes

Hashes come from the lockfile and are never computed or guessed, so a package with no
recorded value has none.

| Lockfile | Hash | Of |
|----------|------|----|
| `Cargo.lock` | SHA-256 | the `.crate` file |
| `package-lock.json`, `pnpm-lock.yaml`, `bun.lock`, yarn v1 `yarn.lock` | as recorded, usually SHA-512 | the tarball |
| `Gemfile.lock` with `CHECKSUMS` | SHA-256 | the `.gem` file |
| `mix.lock` | SHA-256 | the tarball, from the outer checksum |
| `uv.lock`, `poetry.lock`, `pylock.toml` | SHA-256 | the source distribution |
| `composer.lock` | SHA-1 | the dist archive, when `dist.shasum` is set |

Three lockfile hashes are left out because none is the hash of the published file: NuGet's
`contentHash` skips the package signature, `go.sum` hashes a directory tree, and yarn
berry's `checksum` hashes yarn's own archive. A Python package published only as wheels has no
hash either, since a lock lists many wheels and an install uses one.

## Add the vulnerabilities

```sh
fleetreach scan -f json > report.json
fleetreach sbom -o boms/ --report report.json
```

CycloneDX gets a `vulnerabilities[]` entry per finding, with ratings, KEV, EPSS and the SSVC
outcome, and an `analysis.state`: `not_affected` only for the sound signals (a proven
unreachable function, a dependency that is never compiled), `in_triage` otherwise. SPDX 3 has
the same model: each finding is a `security_Vulnerability`, and its verdict a VEX relationship
to the packages it is in (`affects`, `doesNotAffect` with the justification, or
`underInvestigationFor`), with CVSS scores and the CISA KEV entry as assessments. A finding a
person set aside is `doesNotAffect` with their reason and approver. SPDX 2.3 has no
vulnerability model, so each affected package gets an advisory reference.

## Scan an SBOM instead of lockfiles

Where fleetreach cannot read a build (Gradle without locking, Bazel) but the build writes an
SBOM, point the repo at it:

```toml
[[repo]]
id   = "android-app"
path = "../android-app"
sbom = "build/reports/bom.json"
```

fleetreach reads CycloneDX as JSON or XML, SPDX 2 as JSON or tag-value, SPDX 3.0 as JSON-LD, and
the JSON GitHub's dependency graph export returns. Anything else that is not an SBOM is refused
by name. A scan reads the same packages from any format of one generator's run, checked on Syft,
Trivy, cdxgen, Microsoft sbom-tool and GitHub. Go and Rust repos scanned from Syft's or Trivy's
SBOM gave the findings their lockfiles give, except where the SBOM left a package out.

An SPDX 3 document is read from its own graph: the SBOM's root elements are the project,
`dependsOn` (and the link and optional-dependency kinds) are the edges, and a dependency scoped to
development or test is dev. It counts as complete only when every dependency relationship says
`complete`; SPDX 2 has no way to say so, and is always partial. fleetreach's own SPDX 3 reads
back as its CycloneDX does: over the demo fleet, the same 254 findings.

Direct and transitive come from the SBOM's own graph, so they are only as good as the generator's.
Syft's CycloneDX has no edges from the root, so everything reads as transitive; Trivy hangs every Go module
from the project, and all of them read as direct.

A coverage gap says what the SBOM could not vouch for: it does not assert it is complete, it is
older than the newest commit to a lockfile, or it lists components no matcher takes. No age is claimed in a shallow clone, which has no history to compare with, and fleet
checkouts are shallow.

### Scan an image's SBOM

`pkg:deb`, `pkg:apk` and `pkg:rpm` components go to the same distro matchers as an
[image](/fleetreach/docs/ecosystems/container-images/), so a Syft or Trivy SBOM of an image scans
in full without the image. On 27 images, 108 documents gave the OS findings the image itself
gives, apart from four SPDX documents covered below. The distro data is fetched the same way:
`fleetreach db sync --distros <ecosystem>`, or `--osv-dir`.

Three things are read from the document, and a gap says when one is missing:

- **The release**, from each URL's `distro` qualifier or the operating-system component. A document
  that names none, or lists two distributions, has its OS packages left unmatched.
- **The source package**, which most advisories name. A document that names no source for any
  package is matched by binary name, and will miss findings.
- **The module stream** of a Red Hat module build. CycloneDX from Syft and Trivy carries it; SPDX
  does not, so prefer CycloneDX for images with module builds.

### Find SBOMs by themselves

```toml
[settings.sbom]
discover = true

[[source]]
kind        = "github"
org         = "acme"
sbom_assets = true
```

With `discover`, a repo with no lockfile or manifest is scanned from the SBOMs it holds, by name:
`bom.json`, `bom.xml`, `sbom.json`, `sbom.xml`, and `.cdx.json`, `.cdx.xml`, `.spdx.json`,
`.spdx3.json`, `.spdx`, `.bom.json`, `.bom.xml`, `.sbom.json`, `.sbom.xml` or `.sbom` endings. Several are read
as one, complete only if all are. A file with such a name that is not an SBOM errors the repo
rather than leaving it unscanned, and `sbom_discover = false` on the `[[repo]]` turns it off.

`sbom_assets` also brings in what a release carries: `fleet sync` keeps up to 20 SBOM files of
64 MB from each repo's latest release in the checkout, for GitHub, Gitea and Forgejo. A release
that cannot be read is a note, and the files of the last good sync stay. GitLab releases only
link to their files, so they are not fetched.

## Check the NTIA minimum elements

`--check-ntia` reads each SBOM as written and checks the
[NTIA minimum elements](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom)
of 2021: the author of the SBOM data and a timestamp, a supplier, name, version and unique
identifier (a purl or CPE) for every component, the repo included, and the repo's dependency
relationships. It works on every format, and exits 1 when an element is missing.

<!-- run: fleetreach sbom -o boms/ --check-ntia -q 2>&1 | head -n 3 -->
```console
$ fleetreach sbom -o boms/ --check-ntia -q 2>&1 | head -n 3
ntia: payments-api: missing supplier name (28 of 28 components lack it); version (1 of 28 components lack it); other unique identifiers (1 of 28 components lack it)
ntia: ledger-svc: missing supplier name (26 of 26 components lack it); version (1 of 26 components lack it); other unique identifiers (1 of 26 components lack it)
ntia: checkout-web: missing supplier name (9 of 9 components lack it); version (1 of 9 components lack it); other unique identifiers (1 of 9 components lack it)
```
<!-- /run -->

Lockfiles do not name who supplied a package, so no component has a supplier, and the check
says so rather than filling one in. `NOASSERTION` and `NONE` count as absent. The repo itself
has a version (its commit) only when it came from a fleet source, and no package URL, since it
is not a published package; that is the one component the version and identifier counts above
are missing.

## Next

Send the BOMs to [Dependency-Track](/fleetreach/docs/integrations/dependency-track/).
