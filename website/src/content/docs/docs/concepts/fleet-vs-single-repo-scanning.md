---
title: Fleet vs single-repo scanning
description: "Why scanning many repositories together answers questions a per-repo scanner cannot: which fix clears the most repos, who owns what, and what changed across the whole organisation."
sidebar:
  order: 1
---

A per-repo scanner answers "is this repo vulnerable?" and produces one report per repo. With
fifty repos you get fifty reports, and the question you actually have, *what do we fix
first?*, is left to a spreadsheet.

fleetreach reads every repo in one run and correlates the findings. That gives answers that
only exist at fleet scale:

- **Which one fix clears the most repos.** The same advisory in twelve repos is one
  decision, not twelve. See [Blast radius](/fleetreach/docs/concepts/blast-radius/).
- **Which version to move to.** The fleet already runs some versions; a target three teams
  already use is a low-risk bump. See
  [Safe versions and batch targets](/fleetreach/docs/concepts/safe-versions-and-batch-targets/).
- **Who owns it.** With `owner` on each repo, the queue splits per team and notifications
  go to the right place.
- **What changed.** History across runs gives new and fixed findings, SLA breaches and time
  to fix for the whole organisation.
- **Where a package is.** `--why lodash` lists every repo that has it and the chain that
  pulls it in, in one command, during an incident.

The cost of fleet scope is coverage: a fleet has every lockfile format there is, and a
tool that silently skips the ones it cannot read reports clean when it is not. fleetreach
[fails closed](/fleetreach/docs/concepts/coverage-and-fail-closed/) instead.
