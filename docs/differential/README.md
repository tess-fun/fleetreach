# Package manager oracle

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
