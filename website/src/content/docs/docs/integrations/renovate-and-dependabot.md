---
title: Renovate and Dependabot
description: "Use fleetreach alongside Renovate or Dependabot: they keep each repo current, fleetreach says which fix matters most across the fleet and opens verified, lock-only fix branches."
sidebar:
  order: 5
---

Renovate and Dependabot work one repository at a time and open a pull request per update.
fleetreach works across the fleet and answers a different question: of everything open,
which bump clears the most repos, and which findings are past their deadline.

They fit together:

- Keep Renovate or Dependabot for routine updates.
- Run fleetreach nightly to see what is still vulnerable, where, and who owns it, and to
  catch repos those bots do not cover (a missing config, an unsupported ecosystem, a
  workflow pinned to a moved tag).
- When a fix is urgent, `fleetreach fix plan` groups the same bump across every affected
  repo into one campaign, and `fix apply --open-pr` opens a verified, lock-only pull request
  in each. Bot pull requests that already fix the advisory are fine: the next scan sees
  the advisory gone.

`fix apply` branches are named `fleetreach/<campaign>/<package>-<version>`, so they never
collide with `renovate/*` or `dependabot/*` branches.

See [fleetreach vs Dependabot and Renovate](/fleetreach/compare/dependabot-and-renovate/).
