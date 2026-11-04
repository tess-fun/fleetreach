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

`explain.py` also reads `stale/Debian_10` and `stale/Debian_11`, osv.dev's frozen per-release
exports, which show what the retired Debian releases last had.
