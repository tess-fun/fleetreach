---
title: Slack
description: Post new, fixed and overdue findings to Slack after each fleet scan, grouped by owning team, with fleetreach notify and an incoming webhook.
sidebar:
  order: 6
---

```sh
fleetreach scan --history-dir history/ > /dev/null
fleetreach notify --history-dir history/ -c fleet.toml -f slack --webhook "$SLACK_WEBHOOK"
```

The message has a summary header, then one section per owner listing new findings, fixed
ones and those past their SLA deadline. Nothing is sent when nothing changed, unless
`--always`. Use `--dry-run` to see the payload first.

Create an [incoming webhook](https://api.slack.com/messaging/webhooks) for the channel and
keep its URL in a CI secret: the URL is the credential. fleetreach logs only its host.

See [Send notifications](/fleetreach/docs/guides/send-notifications/) for owners, SLAs and the
payload.
