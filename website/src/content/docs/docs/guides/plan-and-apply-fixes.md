---
title: Plan and apply fixes
description: Turn the remediation queue into lockfile bumps on branches, each verified by a re-scan, and open pull or merge requests with fleetreach fix plan and fix apply.
sidebar:
  order: 4
---

`fleetreach fix` turns the remediation queue into lockfile changes you can review. Each
change is made on its own branch, re-scanned, and kept as **verified** only when the
targeted advisories are gone and nothing new appeared.

```sh
fleetreach scan -f json > report.json
fleetreach fix plan --report report.json > plan.json
fleetreach fix apply plan.json
```

## 1. Plan

`fix plan` reads a saved report and writes one edit per repo per remediation item, with the
same batching as `-f remediation`:

<!-- run: fleetreach fix plan --report report.json | head -n 52 -->
```console
$ fleetreach fix plan --report report.json | head -n 52
{
  "schema": "fleetreach-fix-plan/1",
  "edits": [
    {
      "campaign": "0145dfcd",
      "repo": "admin-dashboard",
      "ecosystem": "npm",
      "package": "axios",
      "from": [
        "0.21.0"
      ],
      "to": "0.33.0",
      "advisories": [
        "GHSA-3g43-6gmg-66jw",
        "GHSA-3p68-rc4w-qgx5",
        "GHSA-43fc-jf86-j433",
        "GHSA-4w2v-q235-vp99",
        "GHSA-5c9x-8gcm-mpgx",
        "GHSA-62hf-57xw-28j9",
        "GHSA-6chq-wfr3-2hj9",
        "GHSA-7q8q-rj6j-mhjq",
        "GHSA-898c-q2cr-xwhg",
        "GHSA-cph5-m8f7-6c5x",
        "GHSA-fvcv-3m26-pcqx",
        "GHSA-hfxv-24rg-xrqf",
        "GHSA-j5f8-grm9-p9fc",
        "GHSA-jr5f-v2jv-69x6",
        "GHSA-m7pr-hjqh-92cm",
        "GHSA-mmx7-hfxf-jppx",
        "GHSA-p92q-9vqr-4j8v",
        "GHSA-pf86-5x62-jrwf",
        "GHSA-pjwm-pj3p-43mv",
        "GHSA-pmwg-cvhr-8vh7",
        "GHSA-vf2m-468p-8v99",
        "GHSA-w9j2-pvgh-6h63",
        "GHSA-wf5p-g6vw-rhxx",
        "GHSA-xhjh-pmcv-23jw",
        "GHSA-xx6v-rp6x-q39c"
      ],
      "breaking": true,
      "strategy": "blocked",
      "reason": "0.33.0 is a breaking upgrade; pass --allow-breaking to plan it",
      "risk": "high",
      "risk_reasons": [
        "breaking (new major)",
        "no repo in the fleet runs it yet"
      ]
    },
    {
      "campaign": "1f397432",
      "repo": "admin-dashboard",
      "ecosystem": "npm",
```
<!-- /run -->

Each edit is a `lock-bump` or `blocked` with the reason: no published fix, a semver-major
jump without `--allow-breaking`, or an ecosystem `apply` does not handle yet. When an older
line has its own complete fix, those repos get a low-risk bump on their line instead of a
blocked breaking one. Every edit carries a campaign id that is the same across repos and
runs, so one fix rolled out to ten repos is one campaign.

## 2. Apply

`fix apply` never touches your work tree. For each lock bump it creates a git worktree on
`fleetreach/<campaign>/<package>-<version>` from the repo's `HEAD` and runs an update that
executes no package code:

| Ecosystem | Update |
|-----------|--------|
| Cargo | `cargo update -p <pkg>@<from> --precise <to>` |
| npm | `npm update <pkg> --package-lock-only --ignore-scripts` |
| Go | `go get <module>@v<to>`, then `go list -deps -test ./...`, with `GOTOOLCHAIN=local` and `GOWORK=off` |
| PyPI (`uv.lock`) | `uv lock --upgrade-package <pkg>==<to> --no-build` |
| GitHub Actions | the `uses:` tag rewritten to the fixed release |

Poetry, Pipenv and requirements files are not updated, because their tools may build source
distributions (which runs package code). pnpm, yarn, Composer, Bundler, Maven and NuGet are
not handled yet.

## 3. Verify

Before and after the update, `fix apply` scans the work tree with the flags you pass after
`--` (for example `-- --osv-dir ./osv`). The change is verified only when:

- every targeted advisory is gone for that package;
- no new finding appeared;
- the repo scans with no new errors or coverage gaps.

The commit stays on its branch either way, with a message that says whether it was
verified. `fix apply` prints a JSON summary and exits `0` only when everything planned was
verified.

## 4. Open pull requests

```sh
fleetreach fix apply plan.json --open-pr --draft
fleetreach fix status
```

`--push` pushes each verified branch, and `--open-pr` opens a pull request with `gh` (or a
merge request with `glab` on GitLab), or updates the open one so re-running never
duplicates it. Unverified branches are never pushed, and only `fleetreach/*` branches are
ever pushed. The description lists the advisories, flags a breaking jump, states the
verification and names the other repos in the campaign. Nothing is merged for you.

`fix status` lists every repo's `fleetreach/*` requests with their state.

## Limits

`--repos a,b` limits a run to some repos and `--max-repos` (default 20) caps it. See
[Renovate and Dependabot](/fleetreach/docs/integrations/renovate-and-dependabot/) for how
this sits next to a dependency bot.
