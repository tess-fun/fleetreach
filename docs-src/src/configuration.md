# Configuration

## `fleet.toml`

A list of repos to scan, plus optional settings. Pass it with `-c`.

```toml
[[repo]]
id   = "core-lib"
path = "../core-lib"            # repo root; the lockfile is located within

[[repo]]
id             = "services"
path           = "../services"
glob           = true           # also scan lockfiles below the root
glob_max_depth = 4              # bounded; default 3

[[repo]]
id        = "billing-api"
path      = "../billing-api"    # a go.mod repo; scanned via govulncheck
ecosystem = "go"                # optional; auto-detected from the manifests

[[repo]]
id        = "ml-service"
path      = "../ml-service"     # a uv.lock/poetry.lock/pylock.toml/requirements repo
ecosystem = "pypi"

[[settings.ignore]]
id     = "RUSTSEC-2020-0071"
reason = "dev-dependency only, not in any shipped path"   # REQUIRED, non-empty
```

### Repo fields

| Field | Meaning |
|-------|---------|
| `id` | Stable identifier used in the report. |
| `path` | Repo root (the lockfile is located within). |
| `glob` | Also scan lockfiles below the repo root (every ecosystem). |
| `glob_max_depth` | How deep `glob` descends (default 3). |
| `ecosystem` | Override auto-detection (`cargo`, `go`, `npm`, `pypi`, `rubygems`, `packagist`, `nuget`, `julia`, `swift`, `hex`, `maven`, `githubactions`). |

### Ignoring an advisory

Each `[[settings.ignore]]` requires a non-empty `reason` — an ignore without a
justification is rejected. A stale ignore (one that no longer matches anything)
is surfaced, so the ignore list cannot rot silently.

## Auto-detection

When `ecosystem` is omitted, fleetreach scans **every** ecosystem it finds, so a
polyglot repo (say a `Cargo.lock` beside a `package-lock.json` and a
`composer.lock`) is scanned in full. Without `glob` it looks only at the repo
root; with `glob = true` it also scans each lockfile below the root, within
`glob_max_depth`, which covers monorepos whose lockfiles live in subdirectories.
`node_modules` and `.git` are never searched. A nested `pom.xml` is treated as a
module of the root build and not scanned on its own, and GitHub Actions workflows
are scanned only when the repo has no package ecosystem.

Every discovered lockfile must be scannable: one whose ecosystem has no OSV
export (or, for Go, no govulncheck) makes the repo an errored gap, as it would
for a single-ecosystem repo. When several npm-family lockfiles sit together
(`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`), all are read.

## Coverage

A source that was read but not as a full resolved graph is reported with a
coverage level: `direct-only` (a `pom.xml` without `gradle.lockfile`, which lists
declared dependencies only) or `partial` (a `bun.lock`/`bun.lockb`, which no
feeder reads yet). The repo still counts as scanned, the gaps are listed on
stderr and in the JSON `coverage` array, and the summary line counts them.
`--require-full-coverage` turns any of them into exit 2.

Set `ecosystem` to scan exactly one ecosystem at the repo root, which is also
how to opt a repo out of the multi-ecosystem scan.

## Fleet sources

A `[[source]]` discovers repos instead of listing local paths:

```toml
[[source]]
kind     = "github"        # or "git", with urls = ["https://host/owner/repo.git"]
org      = "acme"          # an organization or a user
include  = ["svc-*"]       # globs on the repo name (default: all)
exclude  = ["*-sandbox"]
topics   = ["production"]  # all must be present
archived = false           # default: skip archived repos
forks    = false           # default: skip forks
checkout = "lockfiles"     # sparse clone of lockfiles/manifests; "full" for reachability
glob     = true            # default for discovered repos
# api_url = "https://ghe.example.com/api/v3"
# token_env = "GHE_TOKEN"  # default: GITHUB_TOKEN or GH_TOKEN
```

`fleetreach fleet sync` lists each source and clones or refreshes its repos under
`~/.cache/fleetreach/checkouts/`; `scan --sync` does the same before scanning, and a
plain `scan` uses what is already there. `fleetreach fleet list` prints the resolved
fleet. A discovered repo's id is `owner/name`; a `[[repo]]` with the same id wins.
The commit scanned is recorded in the report's `provenance.sources`.

Fail-closed: a source that cannot be listed (or was never synced) stops the run with
exit 2, and a repo that cannot be cloned is an errored gap.

## OSV exports

```toml
[settings.osv]
dir     = "../osv"   # a directory laid out as <dir>/<Ecosystem>/all.zip
refresh = "6h"       # how stale the default cache may get before a re-check
```

See [Ecosystems](./ecosystems.md) for the resolution order.

## Key flags

| Flag | Effect |
|------|--------|
| `-f <view>` | Output format / view (see [Report views](./views.md)). |
| `--db <PATH>` | Use a local advisory-db clone (required without `--features network`). |
| `--offline` | Never touch the network. |
| `--osv-dir <DIR>` | One directory of osv.dev exports for every toolchain-free ecosystem. |
| `--sync` | List `[[source]]` entries afresh and clone/refresh checkouts first. |
| `--require-full-coverage` | Exit 2 if any source was read as `direct-only` or `partial`. |
| `--max-db-age 7d` | Refuse a DB older than this (refuses when age is unknown). |
| `--min-severity high` | Filter below a severity (Unknown always survives). |
| `--fail-on <severity>` | Gate threshold for a new vulnerability. |
| `--enrich` | Add CISA KEV + FIRST EPSS, re-rank by real-world risk. |
| `--why <pkg>` | Show how a package gets into the tree, fleet-wide. |
| `--resolve-features` | Mark phantom (never-built) optional dependencies. |
| `--ignore-dev-deps` | Drop findings on dev/build-only packages (marked `(dev only)` in the table). |
| `--reachability[=heuristic\|static]` | Reachability analysis (see [Reachability](./reachability.md)). |

Run `fleetreach scan --help` for the complete list.

## Design decisions (fail-closed)

fleetreach errs toward noise over silence — when it cannot *prove* something is
safe, it surfaces it:

- **Unknown-severity vulnerabilities always gate.** An advisory with no CVSS
  score still trips `--fail-on` and survives `--min-severity` filtering — it
  cannot be proven below the threshold, so it is never silently dropped.
- **`--max-db-age` refuses when age is unknown.** If the DB carries no commit
  timestamp, freshness cannot be verified, so the run exits `2`.
