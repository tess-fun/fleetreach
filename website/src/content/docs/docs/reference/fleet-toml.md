---
title: fleet.toml
description: "Every table and key in fleetreach's fleet.toml configuration file: repos, images, sources, ignores, OSV data, repo context and SSVC, SLAs, history, signals, licenses and VEX."
sidebar:
  order: 1
---

`fleet.toml` lists the repos to scan and optional settings. Commands read `./fleet.toml`, or
the file given with `-c`. Unknown keys are rejected, so a typo is an error, never a setting
silently ignored. Relative paths are relative to the file.

## `[[repo]]`

```toml
[[repo]]
id             = "payments-api"
path           = "../payments-api"
glob           = true                # also scan lockfiles below the root
glob_max_depth = 4                   # default 3
# ecosystem    = "cargo"             # scan exactly one ecosystem at the root
# sbom         = "build/bom.json"    # scan this SBOM instead of lockfiles
exposure       = "open"
mission_impact = "mission-failure"
safety_impact  = "negligible"
owner          = "team-payments"
tags           = ["pci", "tier-1"]
```

| Key | Meaning |
|-----|---------|
| `id` | Stable name used in reports, history and fix branches. |
| `path` | Repo root. |
| `glob`, `glob_max_depth` | Also scan lockfiles in subdirectories, to this depth (default 3). `node_modules` and `.git` are never searched. |
| `ecosystem` | `cargo` (or `rust`), `go`, `npm`, `pypi` (or `python`), `rubygems` (or `ruby`), `packagist` (or `composer`, `php`), `nuget`, `julia`, `swift`, `hex`, `maven`, `githubactions`. Without it every ecosystem found is scanned. |
| `sbom` | A CycloneDX or SPDX JSON file to scan instead of the lockfiles. |
| `exposure` | `small`, `controlled` or `open`. |
| `mission_impact` | `degraded`, `mef-support-crippled`, `mef-failure` or `mission-failure`. |
| `safety_impact` | `negligible`, `marginal`, `critical` or `catastrophic`. |
| `owner`, `tags` | Who owns it, and free labels. |
| `vex_product_id` | The product id used in VEX statements for this repo. |

**Auto-detection.** Without `ecosystem`, every ecosystem at the root (and below it, with
`glob`) is scanned, so a polyglot repo is read in full. GitHub Actions workflows are scanned
in every repo that has `.github/workflows`, alongside its packages. A nested `pom.xml` is a
module of the root build. Every lockfile found must be scannable: one whose ecosystem has no
advisory data makes the repo an errored gap.

## `[[image]]`

A container image, scanned for its OS packages and the language packages inside it. See
[Container images](/fleetreach/docs/ecosystems/container-images/).

```toml
[[image]]
id       = "api"
path     = "images/api.tar"   # docker save, OCI layout (tarball or directory), or a rootfs
platform = "linux/arm64"      # which image of a multi-platform OCI index
distro   = "Debian:12"        # instead of the image's /etc/os-release
owner    = "team-api"
```

| Key | Meaning |
|-----|---------|
| `id` | Stable name used in reports, like a repo id (the two share one namespace). |
| `path` | The image: a `docker save` or OCI-layout tarball (gzip or zstd layers), an OCI-layout directory, or a root filesystem directory or tarball. |
| `platform` | `os/arch`, to pick one image from a multi-platform index. Required when an index holds several. |
| `distro` | An osv.dev distro ecosystem (`Debian:12`, `Ubuntu:24.04:LTS`, `Alpine:v3.20`, `Wolfi`, ...), to match against instead of the detected one. |
| `exposure`, `mission_impact`, `safety_impact`, `owner`, `tags` | As for `[[repo]]`. |

`scan --image <path>` adds an image without a `fleet.toml` entry; its id is the file name.

## `[[source]]`

Discovers repos from a forge. See
[Scan a GitHub or GitLab org](/fleetreach/docs/guides/scan-a-github-or-gitlab-org/).

| Key | Meaning |
|-----|---------|
| `kind` | `github`, `gitlab` or `git` |
| `org` | GitHub org or user, GitLab group (with subgroups) or user |
| `urls` | for `kind = "git"`: clone URLs |
| `include`, `exclude` | globs on the repo name |
| `topics` | topics that must all be present |
| `archived`, `forks` | include archived repos or forks (default `false`) |
| `checkout` | `lockfiles` (sparse, default) or `full` |
| `glob`, `glob_max_depth` | as on `[[repo]]` (default `glob = true`) |
| `api_url` | GitHub Enterprise or self-managed GitLab API |
| `token_env` | the variable holding the token |
| `exposure`, `mission_impact`, `safety_impact`, `owner`, `tags` | context for every repo it finds |

## `[[settings.ignore]]`

```toml
[[settings.ignore]]
id     = "RUSTSEC-2020-0071"
reason = "dev-dependency only"     # required
```

A stale ignore, one that matches nothing, is reported.

## `[[settings.vex_assertion]]`

A reviewed `not_affected` statement with an approver, written into VEX output.

```toml
[[settings.vex_assertion]]
id            = "GHSA-xxxx-xxxx-xxxx"
repo          = "payments-api"                 # omit for fleet-wide
justification = "vulnerable_code_not_in_execute_path"
reason        = "the parser is only used on our own config"
approved_by   = "security@acme.example"
```

## `[settings.vex]`

`author`, `role`, `scope` and `product_id_base` for VEX documents; flags (`--vex-author`) win.

## `[settings.osv]`

| Key | Meaning |
|-----|---------|
| `dir` | a directory of osv.dev exports, `<dir>/<Ecosystem>/all.zip` |
| `refresh` | how stale the default cache may get before a re-check (default `6h`) |

## `[settings.context.defaults]`

`exposure`, `mission_impact`, `safety_impact`, `owner` and `tags` for every repo that does
not set them. Its presence turns on SSVC decisions. A repo with a value unset and no default
is decided with the most urgent value.

## `[settings.ssvc]`

| Key | Meaning |
|-----|---------|
| `poc_epss` | count an EPSS at least this high as a public proof of concept (off by default) |
| `table` | your own decision table, CERT/CC CSV layout, covering all 72 combinations |
| `weights` | reach weights per outcome, default `{ immediate = 8, out-of-cycle = 4, scheduled = 2, defer = 0 }` |

## `[settings.sla]`

Deadlines by SSVC outcome or severity, from first seen:

```toml
[settings.sla]
immediate      = "2d"
"out-of-cycle" = "7d"
scheduled      = "30d"
critical       = "7d"
high           = "30d"
```

## `[settings.history]`

`keep = "180d"` drops older snapshots; the index keeps first-seen dates.

## `[settings.signals]`

`registries = ["npm.example.com"]`: registry hosts allowed besides the public ones.

## `[settings.licenses]`

```toml
[settings.licenses]
allow      = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]
deny       = ["SSPL-1.0"]
categories = { restricted = "deny", reciprocal = "warn" }
unknown    = "deny"
scope      = "runtime"

[[settings.licenses.exception]]
package = "ring"
allow   = ["OpenSSL"]
reason  = "reviewed by legal 2026-09"
```

See [Enforce a license policy](/fleetreach/docs/guides/enforce-a-license-policy/).
