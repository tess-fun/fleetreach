---
title: Environment variables
description: "Environment variables fleetreach reads: OSV data location and sync, forge tokens, NVD API key, Maven and Go settings, cache location and reproducible output."
sidebar:
  order: 4
---

| Variable | Effect |
|----------|--------|
| `FLEETREACH_OSV_DIR` | directory of osv.dev exports, as `--osv-dir` |
| `FLEETREACH_OSV_SYNC=off` | never refresh the OSV cache automatically |
| `FLEETREACH_GO_TIMEOUT_SECS` | time limit for one `govulncheck` run |
| `XDG_CACHE_HOME` | cache root (default `~/.cache`); fleetreach uses `fleetreach/` inside it |
| `GITHUB_TOKEN`, `GH_TOKEN` | GitHub API and clone access for `[[source]] kind = "github"` |
| `GITLAB_TOKEN` | GitLab API and clone access for `kind = "gitlab"` |
| `GITEA_TOKEN`, `FORGEJO_TOKEN` | API and clone access for `kind = "gitea"` and `"forgejo"` |
| `BITBUCKET_TOKEN` | Bitbucket Cloud API and clone access for `kind = "bitbucket"` |
| `BITBUCKET_USER` | the account email of an Atlassian API token in `BITBUCKET_TOKEN`; unset for an access token |
| `BITBUCKET_SERVER_TOKEN` | Data Center API and clone access for `kind = "bitbucket-server"` |
| `AZURE_DEVOPS_TOKEN`, `AZURE_DEVOPS_EXT_PAT` | Azure DevOps API and clone access for `kind = "azure"` |
| `SSL_CERT_FILE` | the CA bundle trusted for forge listings, for a forge behind a private CA |
| `NVD_API_KEY` | faster NVD lookups for findings without a severity (about 8 times) |
| `MAVEN_REPO_LOCAL` | the local Maven repository, instead of `~/.m2/repository` |
| `NUGET_PACKAGES` | the NuGet global packages folder, for license lookups |
| `GOVULNDB` | vulnerability database for `govulncheck`, as `--go-vuln-db` |
| `SOURCE_DATE_EPOCH` | fixed timestamps in SBOMs, VEX, HTML reports, JSON reports and recorded history runs, for reproducible output |

A `[[source]]` can name another variable with `token_env`. Tokens reach `git` as an HTTP header in its environment, scoped to the forge host,
never on the command line or in a remote URL.
