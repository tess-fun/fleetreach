import collections, json, zipfile


def osv_index(path):
    """id or alias -> ecosystem -> list of (package, ranges, ecosystem_specific)."""
    out = collections.defaultdict(lambda: collections.defaultdict(list))
    z = zipfile.ZipFile(path)
    for n in z.namelist():
        d = json.loads(z.read(n))
        ids = {d["id"], *(d.get("aliases") or []), *(d.get("upstream") or [])}
        for a in d.get("affected", []):
            p = a.get("package") or {}
            e = p.get("ecosystem", "")
            for i in ids:
                out[i][e].append((p.get("name"), a.get("ranges"), a.get("ecosystem_specific")))
    return out
