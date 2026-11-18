---
title: Maintain open source
description: Audit every repository you maintain, across a GitHub account and its orgs, in one free run. See which dependency bump fixes the most of them, and catch risky dependencies before your users do.
sidebar:
  order: 8
---

**The problem.** You maintain a dozen crates, a couple of npm packages and a Python tool,
spread across your account and an org. Dependabot alerts arrive one repo at a time, some
repos have no alerts set up at all, and a compromised dependency would reach your users
before any advisory exists.

**With fleetreach**, list the accounts once and scan everything:

```toml title="fleet.toml"
[[source]]
kind = "github"
org  = "your-name"      # a user works as well as an org

[[source]]
kind = "github"
org  = "your-project-org"
```

```sh
fleetreach scan --sync -f packages     # which dependency bump clears the most repos
fleetreach scan --sync --signals       # install scripts, git deps, tag-pinned actions, typosquats
```

## One bump, many repos

The same package in several repos is one decision, ranked by how many repos it clears:

<!-- run: fleetreach scan -f packages | head -n 9 -->
```console
$ fleetreach scan -f packages | head -n 9
┌───────┬────────┬────────────┬────────────┬──────────┬──────────┬─────────┬─────────────────────────────────────────────────────┐
│ Repos ┆ Direct ┆ Transitive ┆ Advisories ┆ Severity ┆ Fix      ┆ Exploit ┆ Package                                             │
╞═══════╪════════╪════════════╪════════════╪══════════╪══════════╪═════════╪═════════════════════════════════════════════════════╡
│ 2     ┆ 2      ┆ 0          ┆ 25         ┆ high     ┆ manifest ┆ -       ┆ axios (npm)                                         │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ 10         ┆ high     ┆ manifest ┆ -       ┆ urllib3 (pypi)                                      │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 2     ┆ 2      ┆ 0          ┆ 6          ┆ high     ┆ manifest ┆ -       ┆ lodash (npm)                                        │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
```
<!-- /run -->

Public repos need no token. The GitHub Action adds the same checks to each repo's CI, with
results in the Security tab, and RustSec's unmaintained and unsound notices show up as
warnings for your Rust crates. Publishing a VEX document with your release
(`scan -f vex`) tells your users which advisories in your dependencies do not affect them.

Free and open source, MIT or Apache-2.0.
