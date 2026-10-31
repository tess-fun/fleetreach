# Licenses

`fleetreach licenses` lists the license of every dependency across the fleet and, with a
policy, the ones that break it:

```sh
fleetreach licenses -c fleet.toml              # rollup table, then violations and warnings
fleetreach licenses -c fleet.toml -f json      # every package with its license and verdict
fleetreach licenses -c fleet.toml --fetch      # also look up unknown licenses on deps.dev
```

It reads the same lockfiles and manifests as `scan`, needs no advisory database, and by
default no network. `fleetreach sbom` fills the CycloneDX `licenses` field from the same data
(`--fetch-licenses` there).

## Where licenses come from

Each package's license is taken from the first source that knows it, and the report says
which:

| Ecosystem | Local sources |
|-----------|---------------|
| npm | the `license` field in `package-lock.json`, else `node_modules/<pkg>/package.json` |
| Composer | `composer.lock` |
| Cargo | the crate's `Cargo.toml` in your local registry cache (`$CARGO_HOME/registry/src`) |
| Python | `License-Expression`, `License` or license classifiers in a repo virtualenv's metadata |
| NuGet | the `.nuspec` in the global packages folder |

Lockfiles rarely carry licenses (Composer always does, npm sometimes), and local caches only
hold what was installed on this machine, so many packages start unknown. `--fetch` looks
those up on [deps.dev](https://deps.dev) (npm, PyPI, Cargo, Go, Maven, NuGet, RubyGems; not
Hex, Julia, Swift or GitHub Actions). That
sends each such package's ecosystem, name and version to deps.dev, which is Google's, so it
only happens when you pass the flag. Answers are cached under your user cache for good,
since a published version's license does not change.

License strings become SPDX expressions (`MIT/Apache-2.0` → `MIT OR Apache-2.0`). A bare
`BSD` or `GPL` stays unknown, because which one is meant is not said.

## Categories

Every license id gets a category, modelled on Google's license classification:

| Category | Examples |
|----------|----------|
| forbidden | AGPL, SSPL, BUSL, CC-BY-NC, WTFPL |
| restricted | GPL, LGPL, CC-BY-SA, EUPL |
| reciprocal | MPL, EPL, CDDL |
| notice | MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib |
| unencumbered | CC0, Unlicense, 0BSD, MIT-0 |
| unknown | no license found, or not an SPDX expression |

## Policy

```toml
[settings.licenses]
allow   = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]   # optional
deny    = ["SSPL-1.0"]                                     # always denied
categories = { restricted = "deny", reciprocal = "warn" }  # allow | warn | deny
unknown = "deny"          # default: a package with no known license is a violation
scope   = "runtime"       # leave dev-only packages out ("all" is the default)

[[settings.licenses.exception]]
package = "ring"
allow   = ["OpenSSL"]
reason  = "reviewed by legal 2026-09"
```

Without `categories`, forbidden licenses are denied and restricted ones warned. With an
`allow` list, a license not on it is at least a warning. An expression passes if it can be
satisfied: `A OR B` needs either side, `A AND B` both, so `AGPL-3.0-only OR MIT` is fine
under a policy that allows MIT.

Exit codes: `0` when nothing is denied, `1` when a license is denied, `2` when a source could
not be read. Warnings never fail the run.
