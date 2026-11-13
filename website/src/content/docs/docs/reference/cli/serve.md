---
title: fleetreach serve
description: "fleetreach serve: Browse the history report and record triage decisions in a browser (plain HTTP). Every flag, from the binary's help."
sidebar:
  order: 13
---

Browse the history report and record triage decisions in a browser (plain HTTP)

```text
Browse the history report and record triage decisions in a browser (plain HTTP)

Usage: fleetreach serve [OPTIONS] --history-dir <HISTORY_DIR>

Options:
      --history-dir <HISTORY_DIR>
          The directory `scan --history-dir` writes
  -c, --config <CONFIG>
          fleet.toml: its `[settings.sla]` sets deadlines, and decisions go to its triage directory [default: ./fleet.toml]
      --listen <LISTEN>
          The address to listen on; anything but a loopback address needs --trust-proxy [default: 127.0.0.1:8484]
      --trust-proxy <IP>
          A reverse proxy's address (repeatable): only requests from these are served, and the reviewer is the identity header they send
      --identity-header <IDENTITY_HEADER>
          The header in which a trusted proxy names the signed-in user [default: X-Forwarded-User]
      --by <BY>
          Who records decisions when there is no proxy (default: git's user.name, else $USER)
      --title <TITLE>
          The overview page's title [default: "Fleet security report"]
  -h, --help
          Print help
```
