# Package manager oracle

`osv_sync_compare.py` compares exports updated by `db sync` with whole downloads, record by
record, for the daily sync check in spec 16 row 11.

`scan_inputs.py` traces a scan's file reads with strace and checks that every file read is one
`scan --incremental` hashes for its key. `scripts/benchmark.py` produces the numbers on the scale
benchmark page.

`sbom_formats.py` reads one generator run in every format that generator writes, or that
spdx-tools and cyclonedx-cli convert it to, and compares the component sets. It also reads each
JSON document's purls itself, so a package every format lost would show. Needs Docker, `gh` and
`dotnet tool install --global microsoft.sbom.dotnettool`; build the reader with
`cargo build --release -p fleetreach-cli --example sbom_components`.

`sbom_vs_lockfile.py` scans Go and Rust repos from their lockfiles and from Syft's and Trivy's
SBOMs of them, and names any finding the lockfiles give that an SBOM's listed packages do not.

`go_severity.py` works each Go finding's severity out again from the export, and compares it
with what Trivy and Grype say of the same module, version and CVE.

`health_oracle.py` checks `scan --health` warnings and clean answers against each registry by
another route than fleetreach reads: `npm view`, `go list -m -u -retracted`, PyPI's simple API,
RubyGems v2, the crates.io API, the Packagist package page, Hex's release endpoint, Maven
Central's other host and deps.dev.

`scope_oracle.py` compares the dev scope in SBOMs with `cargo tree`, `go list`, Bundler's own
Gemfile evaluation and `mix deps` under `MIX_ENV=prod`, the last two in Docker. A package the
tool builds and fleetreach calls dev is a false dev, and must stay at zero.

`pr_attribution.py` makes a fixture PR per ecosystem from real lockfiles and real scans, and
checks that `diff --base` names the entry, and that a finding git does not explain stays out
of the gate.

`pm_oracle.py` asks pnpm, yarn and bun what each lockfile holds, in a container with scripts
off; `pm_compare.py` compares that with the package set in fleetreach's SBOMs. `targets.json`
lists each lockfile's id, directory and tool (`pnpm`, `pnpm5`, `pnpm6`, `yarn1`, `berry`, `bun`).
pnpm 9 lockfiles are read with `pnpm list --lockfile-only`; older ones and the other managers
list what they installed.

# Image differential

fleetreach against Trivy 0.73.0 and Grype v0.121.1 on 217 public images pinned by digest, with
every difference given a reason. The results and what they mean are on the website:
`website/src/content/docs/docs/concepts/image-differential.md`.

| File | What it is |
|------|------------|
| `pinned.toml` | The 217 images, by digest, as a fleetreach config |
| `scan_others.py` | Runs Trivy and Grype on the OCI layouts fleetreach pulled, so all three read the same bytes |
| `compare.py` | Reduces the three reports to (class, package, version, vulnerability) rows |
| `explain.py` | Gives each differing row a reason from upstream data; a row no rule claims is `UNEXPLAINED` |
| `owned.tsv` | Which OS package owns each language file, printed once from `Inventory::owners` |
| `results.json` | The count of rows for each reason in the published run (none unexplained) |

To run it, in one directory holding these files, with the same day's data for all three tools:

1. `fleetreach db sync`, then copy or link the exports to `osv/`, and download the Debian
   tracker's `https://security-tracker.debian.org/tracker/data/json` to `tracker.json`.
2. `fleetreach scan -c pinned.toml --offline --db <advisory-db> --osv-dir osv -f json > report3.json`
3. `python3 scan_others.py report3.json` (Docker; several hours, and tens of GB of layers)
4. `python3 compare.py report3.json rows.json`
5. `python3 explain.py rows.json`

`fleetreach db sync --distros Debian:10,Debian:11` fetches osv.dev's frozen exports of the
retired releases as `Debian_10` and `Debian_11`. Keep them in `osv/`, where the scan reads them,
and in `stale/`, where `explain.py` reads them to show what those releases last had.

## License detection

`license_text.py` compares what `licenses --detect` reads with ScanCode Toolkit 32.5.0, the
release tarball in a linux/amd64 image, on a sample of package directories:

```bash
cargo build --release -p fleetreach-cli --example license_text
python3 -B license_text.py <work> <example binary> 2000 <dirs of packages>...
```

It keeps the sample and ScanCode's answers in `<work>`, so a rerun only compares. On 2,000
packages from the Cargo, Go, npm and NuGet caches, 1,964 agreed exactly and none disagreed. On
1,500 packages from the download cache, with PyPI, RubyGems and Hex among them, 1,435 agreed and
2 disagreed: ScanCode's own id for the protobuf BSD text, and a compound Python file. The rest
are subsets, nearly all ScanCode reading a sentence that mentions a license, which is not read
here, or the LLVM exception.

`license_download.py <local.json> <downloaded.json>` compares `licenses --detect` from local
files with the same run from `--download`: 4,149 packages over Cargo, npm and Go read both ways
and all said the same.

`license_cargo.py <fleetreach> <repo>...` compares every crate of a Cargo repo with
`cargo deny list`: 2,013 of 2,015 crates over fleetreach, Deno and Meilisearch had the same ids.
The two others are `LGPL-2.0` read as `LGPL-2.0-only`, and a crate cargo-deny left empty.

## Import chains

`import_chains.py` checks the first hop of every chain the import engine finds, whether or not a
finding needs it, with patterns of its own rather than the engine's parser:

```bash
cargo build --release -p fleetreach-cli --example import_chains
target/release/examples/import_chains <repo>... > chains.jsonl
python3 -B import_chains.py chains.jsonl
```

It reports lines that are not imports, and imports sharing no word with their package to read by
hand, which is how `laravel/pint`'s `App\` and `com.fasterxml:classmate` were found. Over 132
public repos, 7,561 chains and no line that was not an import.

