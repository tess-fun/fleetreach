# Spec 06: Fleet sources (repo discovery and checkouts)

Status: implemented: git + GitHub incl. GHES (1.2.0), GitLab groups with subgroups · Gap: #3 (onboarding) · CTEM stage: scoping, discovery · Effort: M

## Problem

`fleet.toml` lists local paths. The target user has hundreds of repos that appear, move and
get archived; they have to clone everything, keep clones current, and keep the list in sync
by hand. A repo missing from the list is the worst kind of gap: nobody knows it exists.

## What competitors do

- **Renovate** (self-hosted): `autodiscover` runs on every repo the bot token can see, with
  `autodiscoverFilter` (globs or regex), `autodiscoverTopics` and `autodiscoverNamespaces`
  (more efficient, filters on the platform side). Supports GitHub, GitLab, Bitbucket,
  Azure DevOps, Gitea/Forgejo.
  ([self-hosted config](https://github.com/renovatebot/renovate/blob/main/docs/usage/self-hosted-configuration.md))
- **GitHub security overview**, **Snyk**, **Socket**, **Endor**, **Semgrep**, **Aikido**:
  import an organization through an SCM integration and keep it in sync.
- **Dependency-Track**: no discovery; repos push SBOMs.

## Goals

1. Declare a fleet as "these orgs/groups, minus these" and get every matching repo scanned.
2. Cheap: fetch only the files fleetreach reads, not whole repos.
3. Reproducible: the report records exactly which repos and which commit SHAs were scanned.
4. Fail-closed: if listing fails, the run cannot claim the fleet is clean.

Non-goals: webhooks or a daemon, scanning every branch, Bitbucket/Azure DevOps in phase 1.

## Design

### Config

```toml
[[source]]
kind     = "github"              # "github" | "gitlab" | "git"
org      = "acme"                # github: org or user; gitlab: group (subgroups included)
api_url  = "https://github.example.com/api/v3"   # optional: GHES / self-managed GitLab
include  = ["*"]                 # globs on repo name
exclude  = ["*-sandbox", "legacy-*"]
topics   = ["production"]        # all must match (GitHub topics / GitLab topics)
archived = false
forks    = false
checkout = "lockfiles"           # "lockfiles" (sparse) | "full" (needed for reachability, fix)
glob     = true                  # defaults applied to every discovered repo
[source.context]                 # Spec 08 defaults for these repos
exposure = "controlled"

[[source]]
kind = "git"                     # explicit URLs, no API listing
urls = ["https://git.example.com/infra/billing.git"]
```

Explicit `[[repo]]` entries keep working. A `[[repo]]` whose `id` equals a discovered
`<owner>/<name>` overrides the discovered entry (to attach context, a different path,
`ecosystem`, or to pin `checkout = "full"`).

### Listing

- GitHub: `GET /orgs/{org}/repos?type=all&per_page=100` (falls back to `/users/{u}/repos`),
  paginated by `Link` header; topics, `archived`, `fork`, `default_branch` come in the same
  response.
- GitLab: `GET /groups/:id/projects?include_subgroups=true&archived=false&per_page=100`.
- Tokens from `GITHUB_TOKEN`/`GH_TOKEN` and `GITLAB_TOKEN` (or `token_env = "NAME"` per
  source). Never written to disk or the report.
- Rate limits: honour `Retry-After` / `X-RateLimit-Reset`, bounded retries.
- Listing is cached for `[settings.sources] list_ttl = "1h"` so repeated runs are cheap.

### Checkouts

Materialized under `~/.cache/fleetreach/checkouts/<host>/<owner>/<repo>` (0700), using the
`git` CLI:

```
git clone --filter=blob:none --no-checkout --depth 1 --single-branch <url> <dir>
git -C <dir> sparse-checkout set --no-cone <patterns>
git -C <dir> checkout
```

- `<patterns>` are generated from the feeders' own lockfile/manifest registry (one source of
  truth, so a new feeder automatically extends sparse checkouts), plus
  `.github/workflows/*`. With `glob`, patterns are `**/<name>`.
- Refresh: `git fetch --depth 1 origin <default>` + `git reset --hard FETCH_HEAD`
  (only ever inside the cache).
- `checkout = "full"`: a normal shallow clone (needed by reachability, `--resolve-features`
  and Spec 07).
- Hardened invocation: `-c core.hooksPath=/dev/null`, `-c protocol.file.allow=never`,
  `-c submodule.recurse=false`, `GIT_TERMINAL_PROMPT=0`, token passed via
  `GIT_CONFIG_COUNT`/`http.extraHeader` env vars, never argv.
- Bounded parallelism (`[settings.sources] jobs = 8`).

Why the `git` CLI and not `gix`: partial clone plus sparse checkout is what makes this cheap
for hundreds of repos, and the CLI does both reliably today. fleetreach already shells out to
`cargo` and `govulncheck`; the pure-Rust rule covers linked dependencies, not external tools.
Revisit when `gix` sparse/partial support matures.

### Commands

```
fleetreach fleet sync [-c fleet.toml]   # list + clone/refresh, prints a table
fleetreach fleet list                   # resolved fleet without fetching
fleetreach scan -c fleet.toml --sync    # sync then scan (CI one-liner)
```

### Report

Additive `repos[].source`: `{kind, url, default_branch, commit}`. The commit SHA makes a
report reproducible and is the base for Spec 07 PRs. `provenance.sources[]` records each
source's listing result (count, filters, time).

## Fail-closed rules

- Listing a source fails (auth, 5xx, rate limit exhausted): exit 2. A partial org listing
  is never treated as the fleet.
- A repo fails to clone or refresh: that repo is an errored gap (exit 2), with the git error.
- A stale checkout (refresh failed but an old one exists): not used silently; gap unless
  `--allow-stale-checkouts` (then flagged in coverage).
- Empty listing after filters: exit 2 (zero repos scanned rule already exists).

## Testing

- Mock GitHub/GitLab API server: pagination, topics, archived/fork filters, 401, 403 rate
  limit with reset, 500.
- Local bare repos for checkout tests (sparse patterns, refresh, hooks never run: a fixture
  repo with a `post-checkout` hook that would create a file).
- End to end against a real public org (e.g. a small known org) in an ignored test.

## Phasing

1. `kind = "git"` + checkouts + `fleet sync`: S/M.
2. GitHub listing (incl. GHES): S.
3. GitLab listing: S.
4. Bitbucket / Azure DevOps / Gitea: on demand.
