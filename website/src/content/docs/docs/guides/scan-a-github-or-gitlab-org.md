---
title: Scan a forge org
description: Discover every repository in a GitHub, GitLab, Gitea, Forgejo, Bitbucket or Azure DevOps organisation, clone only their lockfiles, and scan them as one fleet.
sidebar:
  order: 11
---

A `[[source]]` in `fleet.toml` discovers repos instead of listing local paths. fleetreach
lists the org or group through its API, makes a sparse clone of each repo's lockfiles and
manifests, and scans them as one fleet.

```toml title="fleet.toml"
[[source]]
kind     = "github"        # see the table below, or "git" with urls = [...]
org      = "acme"
include  = ["svc-*"]       # globs on the repo name (default: all)
exclude  = ["*-sandbox"]
topics   = ["production"]  # all must be present
archived = false           # default: skip archived repos
forks    = false           # default: skip forks
checkout = "lockfiles"     # sparse clone; "full" for reachability
```

| `kind` | Forge | `org` | `api_url` |
|--------|-------|-------|-----------|
| `github` | GitHub, GitHub Enterprise | org or user | `https://ghe.example.com/api/v3` when self-hosted |
| `gitlab` | GitLab, self-managed | group (subgroups included) or user | `https://gitlab.example.com/api/v4` when self-managed |
| `gitea`, `forgejo` | Gitea, Forgejo, Codeberg | org or user | required: `https://git.example.com/api/v1` |
| `bitbucket` | Bitbucket Cloud | workspace | not needed |
| `bitbucket-server` | Bitbucket Data Center | project key, or `~user` | required: `https://bitbucket.example.com/rest/api/latest` |
| `azure` | Azure DevOps | organization, or `organization/project` | `https://tfs.example.com/tfs` for Azure DevOps Server |

Bitbucket and Azure DevOps have no repo topics, so `topics` on those kinds is a config error
rather than a filter that matches nothing. Bitbucket Cloud has no archived flag; a disabled
Azure DevOps repo counts as archived.

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
| Gitea | `GITEA_TOKEN` | `read:organization` and `read:repository` |
| Forgejo | `FORGEJO_TOKEN` | `read:organization` and `read:repository` |
| Bitbucket Cloud | `BITBUCKET_TOKEN` | an access token, or an API token with `BITBUCKET_USER` set to its account email; repository read |
| Bitbucket Data Center | `BITBUCKET_SERVER_TOKEN` | an HTTP access token with project read |
| Azure DevOps | `AZURE_DEVOPS_TOKEN` or `AZURE_DEVOPS_EXT_PAT` | a personal access token with Code (Read) |

Any kind can name another variable with `token_env`. Public orgs need no token, but a sync
without one says so, because only public repos are listed. Azure DevOps asks for sign-in on
an organization-wide listing without a token, so name a public project as `org/project`.

A forge behind a private CA: set `SSL_CERT_FILE` to the CA bundle for the listing, and
`GIT_SSL_CAINFO` to the same file if `git` does not already trust it.

## Ids and overrides

A discovered repo's id is `owner/name`. GitLab keeps the full path, `acme/platform/api`, so
subgroups never collide, Bitbucket Data Center uses `PROJECT/slug`, and Azure DevOps uses
`organization/project/repo` with spaces and punctuation replaced by `-`. A `[[repo]]` with the same id wins, and context fields
(`exposure`, `owner`, `tags`) on a `[[source]]` apply to every repo it discovers.

## What changed since the last sync

`fleet sync` and `scan --sync` compare each fresh listing with the one before it and print
the repos added, removed and renamed. A rename is the forge's own repo id under a new name.
With `--history-dir` the changes are appended to `inventory.jsonl` in that directory, one
JSON object a line. Finding history stays under a repo's old id after a rename.

## Failing closed

A source that cannot be listed, or was never synced, stops the run with exit 2. A repo that
cannot be cloned is an errored gap, and so is a repo with no recognized lockfile or manifest.
Empty repositories are skipped, except on Bitbucket Data Center, whose listing does not say
which are empty, so they are errored gaps too.
