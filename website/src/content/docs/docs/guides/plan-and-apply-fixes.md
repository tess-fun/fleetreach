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
      ],
      "ssvc": "scheduled"
    },
    {
      "campaign": "1f397432",
      "repo": "admin-dashboard",
```
<!-- /run -->

Each edit is a `lock-bump`, a `manifest-bump`, or `blocked` with the reason: no published
fix, a semver-major jump without `--allow-breaking`, a range in a published package, an
ecosystem `apply` does not handle yet, or a finding in an image, which has no checkout to edit. When an older line has its own complete fix, those
repos get a low-risk bump on their line instead of a blocked breaking one. Every edit carries
a campaign id that is the same across repos and runs, so one fix rolled out to ten repos is
one campaign.

### Targets with advisories of their own

The queue picks a target from the findings in your report, so it only knows the advisories some
repo already has. A target can carry one that starts above everything you run: `lodash` 4.17.15
is clear of GHSA-f23m-r3pf-42rh, while the target 4.18.0 is not. `fix plan` reads the same OSV
exports a scan does (`--osv-dir`, `FLEETREACH_OSV_DIR`, `[settings.osv] dir`, or the default
cache, never syncing) and moves the target to the lowest fix that clears the edit's advisories
and adds none:

- The move is listed in `risk_reasons`, as `4.18.0 has GHSA-f23m-r3pf-42rh`.
- A move to a new major needs `--allow-breaking`, like any other.
- With no clear version published, the edit is `blocked`.

This covers npm, Cargo, PyPI, RubyGems, Packagist, NuGet and Maven, and only the package
itself. What a target brings in with it, and Go and GitHub Actions targets, stay with the
re-scan in `fix apply`. So does a `fixed` version the registry never published. Without an
export, `fix plan` warns and the target stands.

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
| Swift | the `Package.resolved` pin moved to the tag's commit, from `git ls-remote` |
| Hex | the `mix.lock` entry rewritten with the checksums and requirements from `repo.hex.pm` |
| Julia | the `Manifest.toml` entry's `version` and `git-tree-sha1` set from the General registry |

`Package.swift` and `mix.exs` are code, and Julia needs a resolver run, so for these three
fleetreach rewrites the lockfile entry itself. It reads only metadata, never a package archive.
It refuses with a reason when it cannot see that the result is consistent:

- **Swift:** a target outside the range in `Package.swift`, or a pin that comes in only
  through another package (its range is in that package's manifest).
- **Hex and Julia:** a new version whose dependency list differs, a locked dependency the new
  version's requirements leave out, or a requirement from `mix.exs`, `Project.toml`'s
  `[compat]` or a dependent package that leaves the target out.
- **All three:** a pin from git, a path or another registry.

Hex and Julia need a build with the `network` feature.

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
duplicates it. On Gitea, Forgejo, Bitbucket Cloud and Data Center, and Azure DevOps, it calls
their APIs with the token the matching [source](/fleetreach/docs/guides/scan-a-github-or-gitlab-org/)
reads (`GITEA_TOKEN`, `FORGEJO_TOKEN`, `BITBUCKET_TOKEN`, `BITBUCKET_SERVER_TOKEN`,
`AZURE_DEVOPS_TOKEN`), which needs pull request write scope; these need a network build.
`--forge auto` picks GitLab, bitbucket.org and dev.azure.com from the `origin` host and GitHub
otherwise; name a self-hosted forge with `--forge gitea`, `forgejo` or `bitbucket-server`,
and pass `--forge-api https://host/api/v1` when `origin` is an ssh remote on another port or
the forge runs under a path. Unverified branches are never pushed, and only `fleetreach/*` branches are
ever pushed. A push leases on the commit fleetreach last saw, so it does not overwrite work
someone else pushed. The description lists the advisories, flags a breaking jump, states the
verification and names the other repos in the campaign. Nothing is merged for you unless
`[settings.fix] automerge` says so.

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

## Schedules, grouping, automerge and rollout

`[settings.fix]` in fleet.toml sets how a fleet takes its fixes:

```toml
[settings.fix]
schedule = ["mon-thu 09:00-16:00"]   # when --push and --open-pr may publish
timezone = "Europe/Paris"            # IANA name; UTC by default
group = "repo"                       # "package" (default), "repo" or "ssvc"
automerge = "verified"               # "off" (default) or "verified"
merge_method = "squash"              # "squash" (default), "merge" or "rebase"
```

**Schedule.** Outside every window, a run with `--push`, `--open-pr` or `--close-obsolete`
publishes nothing, says when the next window opens, and exits 0. A window is
`[days] HH:MM-HH:MM`, where days are `mon` to `sun`, ranges (`mon-fri`) or lists
(`sat,sun`), and no days means every day. One that ends before it starts runs past midnight
(`fri 22:00-06:00`). Applying without publishing ignores the schedule, and so does
`--ignore-schedule`.

**Grouping.** `package` opens one request per bump. `repo` puts every bump of a repo on
`fleetreach/all`, and `ssvc` puts them on `fleetreach/ssvc-<outcome>`, so an `immediate` fix
never waits on a `defer` one (the plan takes each edit's most urgent SSVC outcome from a
scan run with SSVC decisions). In a group, each bump is applied and re-scanned on top of the
ones before it. One that fails or does not verify is undone and left out, and the request
lists it, so the branch only ever holds verified bumps, squashed into one commit.

**Automerge.** With `automerge = "verified"`, each request fleetreach opens or updates on GitHub
or GitLab turns on the forge's own auto-merge (`gh pr merge --auto --match-head-commit`,
`glab mr merge --auto-merge --sha`), naming the commit fleetreach verified, and the forge's
required checks and reviews still apply. On GitHub, a repo with no required checks pending is
merged at once, and the summary says `merged`; a repo that does not allow auto-merge (a
private repo on the free plan) says so and stays open. A draft, or a request with a breaking
bump, is left for a person. On Gitea, Forgejo, Bitbucket and Azure DevOps, auto-merge stays
off: their auto-merge cannot be held to the verified commit (Forgejo 11 merged a commit pushed
after auto-merge was turned on), so a later push by anyone would merge unverified.

**Rollout.** `rollout = [1, 5]` spreads each campaign in waves: one repo first, five more once
that request has merged, then the rest once those five have. While a wave's requests are open,
the campaign opens nothing new; one closed without merging stops the campaign. Rollout needs
`group = "package"`, since a grouped request mixes campaigns. It works with `--open-pr`, which
reads every repo's request states.

See
[Renovate and Dependabot](/fleetreach/docs/integrations/renovate-and-dependabot/) for how
this sits next to a dependency bot.
