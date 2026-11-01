---
title: fleet.toml recipes
description: Ready-to-copy fleet.toml configurations for local checkouts, a GitHub org, a GitLab group, monorepos, SBOM-only builds, SSVC context, SLAs and license policy.
sidebar:
  order: 2
---

## Local checkouts

```toml
[[repo]]
id   = "api"
path = "../api"

[[repo]]
id   = "web"
path = "../web"
```

## A whole GitHub org, production repos only

```toml
[[source]]
kind    = "github"
org     = "acme"
topics  = ["production"]
exclude = ["*-sandbox", "*-archive"]
```

## A self-managed GitLab group

```toml
[[source]]
kind      = "gitlab"
org       = "platform"
api_url   = "https://gitlab.example.com/api/v4"
token_env = "GITLAB_READ_TOKEN"
```

## Plain git URLs

```toml
[[source]]
kind = "git"
urls = ["https://git.example.com/team/service-a.git", "https://git.example.com/team/service-b.git"]
```

## A monorepo with lockfiles in subdirectories

```toml
[[repo]]
id             = "monorepo"
path           = "../monorepo"
glob           = true
glob_max_depth = 5
```

## A build fleetreach cannot read, through its SBOM

```toml
[[repo]]
id   = "android-app"
path = "../android-app"
sbom = "build/reports/bom.json"
```

## Context for SSVC decisions

```toml
[settings.context.defaults]
exposure       = "controlled"
mission_impact = "mef-support-crippled"
safety_impact  = "negligible"

[[repo]]
id             = "payments-api"
path           = "../payments-api"
exposure       = "open"
mission_impact = "mission-failure"
owner          = "team-payments"
tags           = ["pci"]
```

## SLAs and history retention

```toml
[settings.sla]
immediate      = "2d"
"out-of-cycle" = "7d"
scheduled      = "30d"
critical       = "7d"
high           = "30d"
medium         = "90d"

[settings.history]
keep = "365d"
```

## License policy

```toml
[settings.licenses]
allow   = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-3.0"]
deny    = ["AGPL-3.0-only", "SSPL-1.0"]
unknown = "deny"
scope   = "runtime"
```

## An air-gapped mirror and a company registry

```toml
[settings.osv]
dir = "/mnt/advisories/osv"

[settings.signals]
registries = ["npm.internal.example.com", "pypi.internal.example.com"]
```

## Reviewed exceptions

```toml
[[settings.ignore]]
id     = "RUSTSEC-2023-0071"
reason = "rsa timing: we only verify signatures, never decrypt (reviewed 2026-10)"
```

Every key is described in the [fleet.toml reference](/fleetreach/docs/reference/fleet-toml/).
