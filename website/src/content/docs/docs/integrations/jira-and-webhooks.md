---
title: Jira, ServiceNow and webhooks
description: Send fleetreach's stable JSON notification payload to Jira automation, ServiceNow, PagerDuty or your own service, or keep one GitHub or GitLab issue per owning team.
sidebar:
  order: 7
---

`fleetreach notify --webhook` POSTs a stable JSON payload, `fleetreach-notify/1`, with new,
fixed and overdue findings grouped by owner:

```sh
fleetreach notify --history-dir history/ -c fleet.toml --webhook "$HOOK_URL"
```

Its fields only grow within the schema id; a breaking change gets a new id. The full payload
is in [Send notifications](/fleetreach/docs/guides/send-notifications/).

## Jira

There is no Jira client, so fleetreach holds no Jira credentials. Create a Jira automation
rule with an incoming webhook trigger, point `--webhook` at it, and create or update issues
from `{{webhookData.owners}}`.

## Issues in GitHub or GitLab

```sh
fleetreach notify --history-dir history/ -c fleet.toml --github-issues --repo acme/security
fleetreach notify --history-dir history/ -c fleet.toml --gitlab-issues --repo acme/security
```

One issue per owner, rewritten in place on each run, closed when the owner has nothing open
and reopened when something comes back.
