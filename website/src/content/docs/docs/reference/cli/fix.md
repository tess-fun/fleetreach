---
title: fleetreach fix
description: "fleetreach fix: Plan and apply verified dependency fixes from the remediation queue. Every flag, from the binary's help."
sidebar:
  order: 8
---

Plan and apply verified dependency fixes from the remediation queue

```text
Plan and apply verified dependency fixes from the remediation queue

Usage: fleetreach fix <COMMAND>

Commands:
  plan    Write a fix plan (JSON, stdout) from a saved `scan -f json` report
  apply   Apply a plan's lock bumps on local branches, each verified by a re-scan
  status  List each repo's fleetreach pull or merge requests and their state (via `gh` or `glab`)
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## fleetreach fix plan

Write a fix plan (JSON, stdout) from a saved `scan -f json` report

```text
Write a fix plan (JSON, stdout) from a saved `scan -f json` report

Usage: fleetreach fix plan [OPTIONS] --report <REPORT>

Options:
  -c, --config <CONFIG>  fleet.toml the report was scanned from [default: ./fleet.toml]
      --report <REPORT>  The saved report (`fleetreach scan -f json > report.json`)
      --allow-breaking   Plan semver-major (and 0.x minor) bumps too; they are blocked otherwise
  -h, --help             Print help
```

## fleetreach fix apply

Apply a plan's lock bumps on local branches, each verified by a re-scan

```text
Apply a plan's lock bumps on local branches, each verified by a re-scan

Usage: fleetreach fix apply [OPTIONS] <PLAN> [-- <SCAN_ARGS>...]

Arguments:
  <PLAN>
          The plan written by `fix plan`

  [SCAN_ARGS]...
          Flags for the verifying scan, after `--` (e.g. `-- --db ./advisory-db --osv-dir ./osv`)

Options:
  -c, --config <CONFIG>
          fleet.toml naming the repos
          
          [default: ./fleet.toml]

      --repos <REPOS>
          Only these repo ids

      --max-repos <MAX_REPOS>
          At most this many repos per run
          
          [default: 20]

      --max-prs <N>
          Open at most this many new pull requests this run; open ones are still updated

      --canary <REPOS>
          Repos to try first; the rest of the run waits on every edit in them being verified

      --stop-after-failures <N>
          Stop the run after this many edits that did not verify

      --close-obsolete
          Close the open fleetreach requests this plan no longer wants, in repos it scanned

  -q, --quiet
          no progress output

      --push
          Push each verified branch to the repo's `origin` (only `fleetreach/*` branches; unverified ones are never pushed)

      --open-pr
          Open (or update) a pull request for each pushed branch with `gh`, or a GitLab merge request with `glab`; implies --push

      --draft
          Open pull or merge requests as drafts

      --forge <FORGE>
          Where the repos are hosted; `auto` reads each repo's `origin` remote

          Possible values:
          - auto:   GitLab when the `origin` host names GitLab, GitHub otherwise
          - github: GitHub pull requests through `gh`
          - gitlab: GitLab merge requests through `glab`
          
          [default: auto]

  -h, --help
          Print help (see a summary with '-h')
```

## fleetreach fix status

List each repo's fleetreach pull or merge requests and their state (via `gh` or `glab`)

```text
List each repo's fleetreach pull or merge requests and their state (via `gh` or `glab`)

Usage: fleetreach fix status [OPTIONS]

Options:
  -c, --config <CONFIG>
          fleet.toml naming the repos
          
          [default: ./fleet.toml]

      --forge <FORGE>
          Where the repos are hosted; `auto` reads each repo's `origin` remote

          Possible values:
          - auto:   GitLab when the `origin` host names GitLab, GitHub otherwise
          - github: GitHub pull requests through `gh`
          - gitlab: GitLab merge requests through `glab`
          
          [default: auto]

  -h, --help
          Print help (see a summary with '-h')
```
