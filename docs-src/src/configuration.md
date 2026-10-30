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
path      = "../ml-service"     # a uv.lock/poetry.lock/Pipfile.lock repo
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
mirror (or, for Go, no govulncheck) makes the repo an errored gap, as it would
for a single-ecosystem repo. Lockfiles in formats fleetreach cannot read
(`yarn.lock`, `pnpm-lock.yaml`, `bun.lock`) are listed in a note on stderr.

Set `ecosystem` to scan exactly one ecosystem at the repo root, which is also
how to opt a repo out of the multi-ecosystem scan.

## Key flags

| Flag | Effect |
|------|--------|
| `-f <view>` | Output format / view (see [Report views](./views.md)). |
| `--db <PATH>` | Use a local advisory-db clone (required without `--features network`). |
| `--offline` | Never touch the network. |
| `--max-db-age 7d` | Refuse a DB older than this (refuses when age is unknown). |
| `--min-severity high` | Filter below a severity (Unknown always survives). |
| `--fail-on <severity>` | Gate threshold for a new vulnerability. |
| `--enrich` | Add CISA KEV + FIRST EPSS, re-rank by real-world risk. |
| `--why <pkg>` | Show how a package gets into the tree, fleet-wide. |
| `--resolve-features` | Mark phantom (never-built) optional dependencies. |
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
