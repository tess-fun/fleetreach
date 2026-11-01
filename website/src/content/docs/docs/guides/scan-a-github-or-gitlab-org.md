---
title: Scan a GitHub or GitLab org
description: Discover every repository in a GitHub organisation or GitLab group, clone only their lockfiles, and scan them as one fleet, with include, exclude and topic filters.
sidebar:
  order: 11
---

A `[[source]]` in `fleet.toml` discovers repos instead of listing local paths. fleetreach
lists the org or group through its API, makes a sparse clone of each repo's lockfiles and
manifests, and scans them as one fleet.

```toml title="fleet.toml"
[[source]]
kind     = "github"        # or "gitlab", or "git" with urls = [...]
org      = "acme"          # GitHub org or user; GitLab group (subgroups included) or user
include  = ["svc-*"]       # globs on the repo name (default: all)
exclude  = ["*-sandbox"]
topics   = ["production"]  # all must be present
archived = false           # default: skip archived repos
forks    = false           # default: skip forks
checkout = "lockfiles"     # sparse clone; "full" for reachability
```

```sh
fleetreach scan --sync     # list, clone or refresh, then scan
fleetreach fleet list      # print the resolved fleet
```

`fleetreach fleet sync` clones or refreshes under `~/.cache/fleetreach/checkouts/`, and a
plain `scan` uses what is already there. The commit scanned is recorded in the report's
`provenance.sources`.

## Tokens

| Forge | Token | Scopes |
|-------|-------|--------|
| GitHub | `GITHUB_TOKEN` or `GH_TOKEN` (or `token_env`) | read access to the repos |
| GitLab | `GITLAB_TOKEN` | `read_api` to list, `read_repository` to clone |

Public orgs and groups need no token. For GitHub Enterprise or self-managed GitLab, set
`api_url` (`https://ghe.example.com/api/v3`, `https://gitlab.example.com/api/v4`).

## Ids and overrides

A discovered repo's id is `owner/name` (GitLab keeps the full path, `acme/platform/api`, so
subgroups never collide). A `[[repo]]` with the same id wins, and context fields
(`exposure`, `owner`, `tags`) on a `[[source]]` apply to every repo it discovers.

## Failing closed

A source that cannot be listed, or was never synced, stops the run with exit 2. A repo that
cannot be cloned is an errored gap. Empty repositories are skipped.
