---
title: Send notifications
description: Tell each owner what the newest scan found, fixed and left overdue, through a webhook, Slack, or one GitHub or GitLab issue per team.
sidebar:
  order: 7
---

`fleetreach notify` reads the scan history and reports, grouped by owner, what the newest
run changed and what is past its SLA. It prints a payload, POSTs it to a webhook or Slack,
or keeps one issue per team up to date.

```sh
fleetreach notify --history-dir history/ -c fleet.toml                         # print it
fleetreach notify --history-dir history/ -c fleet.toml --webhook "$HOOK_URL"   # generic JSON
fleetreach notify --history-dir history/ -c fleet.toml -f slack --webhook "$SLACK_WEBHOOK"
fleetreach notify --history-dir history/ -c fleet.toml --github-issues --repo acme/security
fleetreach notify --history-dir history/ -c fleet.toml --gitlab-issues --repo acme/security
```

Run it right after `scan --history-dir`, in the same job.

## What it reports

- **new**: open in the newest run and not open before it (first seen, back after a fix, or
  no longer ignored);
- **fixed**: marked fixed by the newest run;
- **breaches**: every open finding past its `[settings.sla]` deadline (with `-c`), repeated
  on every run until it is fixed.

A gap run in between never makes old findings look new when their repo is read again.

## Webhooks and Slack

`--webhook` must be `https://` (or `http://` to localhost). Messages name only the URL's
host, because webhook URLs carry their secret in the path. Nothing is sent when nothing is
new, fixed or overdue, unless `--always`. `--dry-run` prints the payload instead.

The default `generic` payload has a stable schema, `fleetreach-notify/1`, whose fields only
grow; use it for Jira automation, ServiceNow, PagerDuty or your own script. `-f slack` sends
a Block Kit message with one section per owner. See
[Jira and webhooks](/fleetreach/docs/integrations/jira-and-webhooks/) and
[Slack](/fleetreach/docs/integrations/slack/).

## One issue per team

`--github-issues` (through `gh`) or `--gitlab-issues` (through `glab`) keeps one issue per
owner in `--repo`. Each lists the owner's breaches, every open finding (new ones marked) and
those just fixed. A hidden marker finds the issue again, so it is rewritten in place,
closed when the owner has nothing open and reopened when something comes back. Lists stop
at 200 findings, or fewer to stay under GitHub's size limit, and count the rest.
`--campaign` keeps a separate set of issues, for example per quarter.
