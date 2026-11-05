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

Each edit is a `lock-bump`, a `manifest-bump`, or `blocked` with the reason: no published
fix, a semver-major jump without `--allow-breaking`, a range in a published package, or an
ecosystem `apply` does not handle yet. When an older line has its own complete fix, those
repos get a low-risk bump on their line instead of a blocked breaking one. Every edit carries
a campaign id that is the same across repos and runs, so one fix rolled out to ten repos is
one campaign.

### What each repo's ranges allow

For npm's `package-lock.json` and for Cargo, the plan reads the checkouts in `fleet.toml` and
looks at every range that reaches a vulnerable copy of the package, peer ranges included:

| The target is left out by | Strategy |
|---------------------------|----------|
| nothing | `lock-bump` |
| a range in your own `package.json` or `Cargo.toml`, an exact pin included | `manifest-bump` |
| a range in a published package | `blocked`, naming the package to update first |

A manifest bump raises the range and keeps its kind: `^1.2.3` becomes `^2.0.0`, `~1.2.3`
becomes `~1.3.0`, and an exact pin stays exact. It also covers `[workspace.dependencies]`.
A range on another line of the package is left alone.

Some ranges say nothing, and those edits stay lock bumps: a git url or a tag, a Cargo
dependency whose manifest is not in the local registry, and any pnpm or yarn lock, which do
not keep these ranges. `overrides` are not read either. `fix apply` still runs the package
manager and re-scans, so the worst case is an edit that does not verify.

## 2. Apply

`fix apply` never touches your work tree. For each bump it creates a git worktree from
the repo's `HEAD`, or from the remote's default branch with `--push` or `--open-pr`, and runs
an update that executes no package code:

| Ecosystem | Update |
|-----------|--------|
| Cargo | `cargo update -p <pkg>@<from> --precise <to>` |
| npm | `npm update <pkg> --package-lock-only --ignore-scripts` |
| pnpm | `pnpm update <pkg> --lockfile-only --ignore-scripts --depth Infinity`, with `--recursive` in a workspace |
| yarn 2+ | `yarn up -R <pkg> --mode=update-lockfile` with scripts off |
| yarn 1 | the package's `yarn.lock` entries dropped, then `yarn install --ignore-scripts` into a folder outside the tree |
| Composer | `composer update <pkg> --with-dependencies --no-install --no-scripts --no-plugins` |
| Bundler | `bundle lock --update <gem> --conservative` |
| NuGet | the `Version` in the project or `Directory.Packages.props` edited, then `dotnet restore --force-evaluate` where a `packages.lock.json` exists |
| Maven | the version in each `pom.xml` edited, or the property it reads |
| Go | `go get <module>@v<to>`, then `go list -deps -test ./...`, with `GOTOOLCHAIN=local` and `GOWORK=off` |
| PyPI (`uv.lock`) | `uv lock --upgrade-package <pkg>==<to> --no-build` |
| GitHub Actions | the `uses:` tag rewritten to the fixed release |

Poetry, Pipenv and requirements files are not updated, because their tools may build source
distributions (which runs package code).

The lockfile updates stay inside the ranges your manifests declare. A version pinned exactly
in `package.json` does not move, and the edit reports `the update changed nothing`. A range
that excludes the fix ends as unverified. Maven and NuGet change a declared version, so a
transitive dependency with no declaration in the repo is reported as blocked.

## 3. Verify

Before and after the update, `fix apply` scans the work tree with the flags you pass after
`--` (for example `-- --osv-dir ./osv`). The change is verified only when:

- every targeted advisory is gone for that package;
- no new finding appeared;
- the repo scans with no new errors or coverage gaps.

A verified commit goes on `fleetreach/<campaign>/<package>-<version>`. One that did not verify
goes on `fleetreach-unverified/<campaign>/<package>-<version>` with a message that says so, and
never replaces a verified branch. A failed baseline scan moves no branch at all. `fix apply`
prints a JSON summary and exits `0` only when everything planned was verified.

## 4. Open pull requests

```sh
fleetreach fix apply plan.json --open-pr --draft
fleetreach fix status
```

`--push` pushes each verified branch, and `--open-pr` opens a pull request with `gh` (or a
merge request with `glab` on GitLab), or updates the open one so re-running never
duplicates it. Unverified branches are never pushed, and only `fleetreach/*` branches are
ever pushed. A push leases on the commit fleetreach last saw, so it does not overwrite work
someone else pushed. The description lists the advisories, flags a breaking jump, states the
verification and names the other repos in the campaign. Nothing is merged for you.

`fix status` lists every repo's `fleetreach/*` requests with their state.

## 5. Re-run

Run `fix apply` on a fresh plan as often as you like:

- A branch already verified on the current base is left alone.
- A branch behind the base is rebuilt on it and verified again.
- A branch someone else has pushed to is skipped, and so is a closed or merged request.
- `--close-obsolete` closes the open `fleetreach/*` requests the plan no longer wants, in the
  repos the plan's report scanned. A repo that failed to scan keeps its requests.

## Limits

`--repos a,b` limits a run to some repos and `--max-repos` (default 20) caps it. Three more
flags keep a large rollout small:

| Flag | Effect |
|------|--------|
| `--max-prs <n>` | Opens at most `n` new requests; open ones are still updated. |
| `--canary a,b` | Runs these repos first; the rest wait on every edit in them being verified. |
| `--stop-after-failures <n>` | Stops the run after `n` edits that did not verify. |

See
[Renovate and Dependabot](/fleetreach/docs/integrations/renovate-and-dependabot/) for how
this sits next to a dependency bot.
