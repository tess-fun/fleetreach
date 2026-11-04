#!/usr/bin/env python3
"""Compare OSV exports updated by `db sync` with whole downloads, record by record.
usage: osv_sync_compare.py <synced dir> <dir of fresh all.zip downloads>
Exit 1 on any missing, extra or differing record. Run it after each day's sync; download the
whole zips right after the sync, since a record osv.dev changed in between differs honestly."""
import os, sys, zipfile


def main():
    synced, fresh = sys.argv[1:3]
    total = bad = 0
    for name in sorted(os.listdir(fresh)):
        a, b = f"{synced}/{name}/all.zip", f"{fresh}/{name}/all.zip"
        if not (os.path.exists(a) and os.path.exists(b)):
            continue
        za, zb = zipfile.ZipFile(a), zipfile.ZipFile(b)
        na, nb = set(za.namelist()), set(zb.namelist())
        differ = [n for n in na & nb if za.read(n) != zb.read(n)]
        total += len(nb)
        if differ or na != nb:
            bad += 1
            print(f"{name}: missing {len(nb - na)}, extra {len(na - nb)}, differ {len(differ)}")
    print(f"{total} records, {bad} export(s) differ")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
