# SBOM output

`fleetreach sbom` writes one [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/) or
[SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/) JSON SBOM per repo, from the same
lockfiles and manifests `scan` reads, in every ecosystem:

```sh
fleetreach sbom -c fleet.toml -o boms/            # boms/<repo-id>.cdx.json
fleetreach sbom -c fleet.toml -o boms/ -f spdx    # boms/<repo-id>.spdx.json
fleetreach sbom -c fleet.toml -o boms/ --sync     # refresh [[source]] checkouts first
```

It needs no advisory database and no network (unless `--sync` refreshes fleet sources).
A repo id `owner/name` becomes the file `owner__name.cdx.json`. Both formats pass their
official JSON schemas.

## What each BOM holds

- **`metadata.component`**: the repo, with its git remote and the commit read when it
  came from a `[[source]]`, and one property per dependency source read (file, ecosystem,
  coverage).
- **`components`**: one `library` per resolved package, identified by its
  [package URL](https://github.com/package-url/purl-spec) (`pkg:cargo`, `pkg:npm`,
  `pkg:pypi`, `pkg:gem`, `pkg:composer`, `pkg:nuget`, `pkg:julia`, `pkg:swift`, `pkg:hex`,
  `pkg:maven`, `pkg:golang`, `pkg:githubactions`). A git dependency carries its remote and
  revision as a `vcs_url` qualifier. Development-only packages have `scope: excluded`.
  Workspace members and other path dependencies are the project itself and are not listed.
- **`dependencies`**: the "requires" graph from the lockfiles, rooted at the repo.
- **`compositions`**: which components come from a complete resolved graph (`complete`)
  and which from a source read with less than full coverage (`incomplete`: a `pom.xml`, a
  `.csproj` without restore output, unpinned requirements, a lockfile format fleetreach
  cannot read). The repo itself is `complete` only when every source was.

BOMs are deterministic: components and edges are sorted, and the `serialNumber` is a
UUID derived from the content. Set `SOURCE_DATE_EPOCH` and two runs over the same
lockfiles write byte-identical files.

## SPDX

`-f spdx` writes the same inventory as an SPDX 2.3 document: the repo is the package the
document `DESCRIBES` (its `downloadLocation` the git remote at the commit read), each
resolved package an SPDX package with its purl as a `PACKAGE-MANAGER` reference and its
license when it is a valid SPDX expression, and the graph as `DEPENDS_ON` relationships, with
`DEV_DEPENDENCY_OF` for a development-only direct dependency. SPDX 2.3 has no way to mark a
document incomplete, so the coverage of each source, and any source read with less than full
coverage, is written in the repo package's `comment` and the document's. The
`documentNamespace` is derived from the content, so it is as stable as the CycloneDX serial
number.

## Vulnerabilities in the BOM

```sh
fleetreach scan -c fleet.toml -f json > report.json
fleetreach sbom -c fleet.toml -o boms/ --report report.json
```

`--report` embeds a saved scan's findings for each repo. In CycloneDX they are
`vulnerabilities[]`: the advisory id and link, aliases as references, a rating with the
severity, the CVSS score and vector, `affects` pointing at the component, KEV, EPSS and the
SSVC outcome as properties, and an `analysis`:

| Scan result | `analysis.state` | `justification` |
|-------------|------------------|-----------------|
| static reachability found a path | `exploitable` | |
| no sound verdict (most findings) | `in_triage` | |
| static reachability proved no path | `not_affected` | `code_not_reachable` |
| a phantom dependency, never compiled | `not_affected` | `requires_dependency` |

Only the sound signals reach `not_affected`, the same rule the [OpenVEX](./views.md) output
follows; human-asserted ignores are not included. Already-patched occurrences are left out.
In SPDX, which has no vulnerability model before 3.0, each affected package gets a
`SECURITY` / `advisory` external reference per finding, with the state, severity, KEV and
SSVC outcome in its comment.

## Exit codes

`0` when every repo was read; `2` when a source exists but could not be read (its BOM is
still written and marked incomplete) or the run failed. A partial inventory is never
presented as a complete one.

## Feeding Dependency-Track

```sh
for bom in boms/*.cdx.json; do
  name=$(basename "$bom" .cdx.json)
  curl -sf -X POST "$DT_URL/api/v1/bom" -H "X-Api-Key: $DT_API_KEY" \
    -F "projectName=$name" -F autoCreate=true -F "bom=@$bom"
done
```

## SBOMs as input

Where fleetreach cannot read a build (Gradle without dependency locking, Bazel, in-house
tooling) but the build writes an SBOM, point the repo at it:

```toml
[[repo]]
id   = "android-app"
path = "../android-app"
sbom = "build/reports/bom.json"   # CycloneDX 1.4-1.6 or SPDX 2.3 JSON, relative to fleet.toml
```

The SBOM replaces lockfile discovery for that repo. Each component is routed by its package
URL to the matcher of its ecosystem (npm, PyPI, RubyGems, Composer, NuGet, Maven, Hex, Julia,
Swift); direct dependencies are the ones the document's root depends on, and the dependency
graph gives the usual paths. Coverage is full only when a CycloneDX document asserts its root
is `complete`; an SPDX document cannot say so and is always partial. Components without a
purl, or of a type read from its lockfile instead (`cargo`, `golang`), are named in the
coverage note, never silently dropped. An SBOM written by `fleetreach sbom` scans back to the
same findings as the lockfiles it came from.

An SPDX document scans back to the same findings too, but as partial coverage.
