# Fixing: plan and apply

`fleetreach fix` turns the remediation queue into lockfile changes you can review, each
one checked by a re-scan before you see it.

```sh
fleetreach scan -c fleet.toml -f json > report.json
fleetreach fix plan -c fleet.toml --report report.json > plan.json
fleetreach fix apply -c fleet.toml plan.json -- --db ./advisory-db --osv-dir ./osv
```

## Plan

`fix plan` reads a saved report and writes one edit per repo per remediation item (the
same batching as `-f remediation`). Each edit is a `lock-bump`, or `blocked` with the
reason:

- no published fix (consider a VEX statement or a mitigation);
- a semver-major (or `0.x` minor) jump, unless you pass `--allow-breaking`;
- an ecosystem `apply` does not handle yet.

Findings that are soundly not reachable are not planned. Every edit carries a campaign id,
a short hash of the ecosystem, package, target version and advisories, which is the same
across repos and across runs.

## Bump risk

Every upgrade in the queue is rated from evidence no single-repo tool has: the repos in your
own fleet that already run the target version, or a newer one with the same major (the same
minor for `0.x`). A repo that is already on it and still ships is the best sign the bump is
survivable.

| Upgrade | Risk |
|---------|------|
| within the current major | `low` |
| breaking, at least 3 repos already on the new version | `medium` |
| breaking, fewer | `high` |

`-f remediation` shows it in the **Bump risk** column (`medium · 4 on 2.1.0`),
`remediation-json` as `risk`, `risk_reasons` and `evidence` (`repos`, `newest`), and the
plan and pull request description carry it too. The versions come from the same lockfiles
the scan reads, with no network, and the JSON report saves them as `package_versions`, so a
plan made from a saved report sees the same evidence.

The rating does not yet look at API changes or CI results.

### Fixes on an older line

The queue proposes the smallest version that clears every advisory for the newest version
the fleet runs. Repos still on an older line (1.x when the target is 2.1.0; 0.3.x under a
0.4 target) often have a fix on their own line too, so each item also lists, per older
line, the smallest version on that line at or above what those repos run that clears the
advisories they have:

```text
bump foo 1.4.0 → 2.1.0
  or 1.4.2 on 1.x (3 repos)
```

`remediation-json` carries them as `alternatives` (`to`, `repos`, `clears`, `leaves_open`,
`evidence`). When an alternative clears everything on its line, `fix plan` gives each repo
whose vulnerable versions are all on that line its own edit to it: a low-risk lock bump,
in its own campaign, instead of a breaking upgrade that would be blocked without
`--allow-breaking`. An advisory with no fix on the line is listed in `leaves_open`, and
those repos keep the main target. A repo that is on the newest line but also holds an
older copy keeps the main target, marked breaking.

## Apply

`fix apply` never touches your work tree. For each lock bump it creates a git worktree on
the branch `fleetreach/<campaign>/<package>-<version>` from the repo's `HEAD` and runs a
lock-only update that runs no package code:

| Ecosystem | Update |
|-----------|--------|
| Cargo | `cargo update -p <pkg>@<from> --precise <to>` in each workspace that locks it |
| npm | `npm update <pkg> --package-lock-only --ignore-scripts` (the newest version the declared ranges allow) |
| GitHub Actions | the `uses: <action>@<tag>` reference rewritten to the fixed release tag |
| Go | `go get <module>@v<to>` in each module whose `go.mod` requires it, with `GOTOOLCHAIN=local` and `GOWORK=off` (Go downloads module sources but never runs them) |
| PyPI (`uv.lock`) | `uv lock --upgrade-package <pkg>==<to> --no-build` (source builds refused, so no package code runs) |

If the declared version range does not allow the target, the tool refuses and the edit is
reported `blocked`.

When a Go update raises the module's `go` directive (a newer module can require a newer Go),
the result, the commit message and the pull request say so. `poetry.lock`, `Pipfile.lock` and
requirements files are not updated: Poetry and Pipenv may build source distributions to read
their metadata, which runs package code. pnpm, yarn, Composer, Bundler, Maven and NuGet are
not handled yet. The tool must be on `PATH`; a missing one leaves the edit `blocked` with the
reason.

## Verify

Before and after the update, `fix apply` runs `fleetreach scan` on the work tree with the
flags given after `--`. The change is **verified** only when every targeted advisory is gone
for that package, no new finding appeared, and the repo scans without new errors or
coverage gaps. The commit stays on its branch either way, with a message that says whether
it was verified; an unverified one is for inspection, not for merging.

`fix apply` prints a JSON summary (one entry per edit: `verified`, `unverified`, `blocked`
or `skipped`, with the branch and what ran) and exits `0` only when everything planned was
verified. `--repos a,b` limits it to some repos and `--max-repos` (default 20) caps a run.
By default nothing is pushed.

## Pull requests

```sh
fleetreach fix apply -c fleet.toml plan.json --open-pr [--draft] -- --db ./advisory-db
fleetreach fix status -c fleet.toml
```

`--push` pushes each **verified** branch to the repo's `origin`; `--open-pr` also opens a
pull request with the GitHub CLI (`gh`, using your existing login), or updates the open one
when the branch already has a PR, so re-running a campaign never duplicates it. Unverified
branches are never pushed, and only `fleetreach/*` branches are ever pushed (with
`--force-with-lease`, since each run rebuilds them from `HEAD`). The description lists the
advisories, flags a breaking jump, states the verification, and names the other repos in the
same campaign. Nothing is merged for you.

On GitLab the same flags open **merge requests** with the GitLab CLI (`glab`, using your
existing login, gitlab.com or self-managed): an open merge request from the branch is
updated, otherwise one is created. The forge is picked per repo from the host of its
`origin` remote (a host containing `gitlab` means GitLab, anything else GitHub); pass
`--forge gitlab` or `--forge github` when the host does not say, such as a self-managed
GitLab at `code.example.com`.

`fix status` lists every repo's `fleetreach/*` pull or merge requests with their state
(`OPEN`, `MERGED`, `CLOSED`, for both forges), title, link and forge. It takes the same
`--forge`.
