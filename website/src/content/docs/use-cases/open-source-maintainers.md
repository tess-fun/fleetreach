---
title: For open-source maintainers
description: Audit every repository you maintain, including a GitHub org or user account, in one free run, and see which dependency bump fixes the most of them.
sidebar:
  order: 4
---

**The problem.** You maintain a dozen crates, a couple of npm packages and a Python tool,
spread across your account and an org. Dependabot alerts arrive one repo at a time, and some
repos have no alerts set up at all.

**With fleetreach**, list the account once and scan everything:

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

Public repos need no token. The GitHub Action adds the same checks to each repo's CI, with
results in the Security tab, and RustSec's unmaintained and unsound notices show up as
warnings for your Rust crates.

Free and open source, MIT or Apache-2.0.
