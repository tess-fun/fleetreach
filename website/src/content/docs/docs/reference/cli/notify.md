---
title: fleetreach notify
description: "fleetreach notify: Send what the newest history run changed, and SLA breaches, to a webhook or issues. Every flag, from the binary's help."
sidebar:
  order: 10
---

Send what the newest history run changed, and SLA breaches, to a webhook or issues

```text
Send what the newest history run changed, and SLA breaches, to a webhook or issues

Usage: fleetreach notify [OPTIONS] --history-dir <HISTORY_DIR>

Options:
      --history-dir <HISTORY_DIR>  The directory `scan --history-dir` writes
  -c, --config <CONFIG>            fleet.toml whose `[settings.sla]` judges breaches (without it none are reported)
      --webhook <WEBHOOK>          POST the payload to this HTTPS URL (needs a build with the `network` feature)
  -f, --format <FORMAT>            Payload for the webhook or stdout [default: generic] [possible values: generic, slack]
      --github-issues              Keep one issue per owner in `--repo`, with `gh`
      --gitlab-issues              Keep one issue per owner in `--repo`, with `glab`
      --repo <REPO>                The repo issues go to (`owner/name`, or a GitLab project path)
      --campaign <CAMPAIGN>        Names the set of issues, so separate programs keep separate issues [default: fleetreach]
      --dry-run                    Print what would be sent or changed instead
      --always                     Send to the webhook even when nothing changed
  -h, --help                       Print help
```
