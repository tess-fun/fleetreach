Data bundled into `fleetreach-os`.

- `eol.tsv`: distribution release end-of-life dates from endoflife.date (MIT-licensed data):
  product, release, end of standard support, end of paid extended support.
  Regenerate with `python3 scripts/update-eol.py` (at release time).
- `centos.tsv`: the highest build of each binary package (per module stream) in the final
  repositories of CentOS Linux 6, 7 and 8 on vault.centos.org: release, package, module stream
  (`-` for none), epoch:version-release. Written by `python3 scripts/update-centos.py`; those
  repositories no longer change.
