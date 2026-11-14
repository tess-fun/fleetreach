"""Score fleetreach SBOMs (CycloneDX) against real Maven dependency:tree output, per project.

    python3 -I score.py TREE_DIR SBOM_DIR [OTHER_SBOM_DIR ...]

Give fleetreach the same POMs Maven had: HOME and XDG_CACHE_HOME at an empty folder,
MAVEN_REPO_LOCAL at the POM folder, so neither ~/.m2 nor its own POM cache is read.
"""
import glob, json, os, re, sys, collections

out, sides = sys.argv[1], sys.argv[2:]


def maven(path):
    rows = {}
    for line in open(path).read().splitlines()[1:]:
        p = re.sub(r'^[|+\\\- ]+', '', line).split(':')
        if len(p) < 5:
            continue
        rows[f'{p[0]}:{p[1]}:{p[-2]}'] = p[-1]
    return rows


def ours(path):
    d = json.load(open(path))
    return {c['name'] + ':' + c['version']: c.get('scope') for c in d.get('components', [])}


diffs = collections.defaultdict(list)
totals = {s: [0, 0, 0] for s in sides}  # exact projects, maven pkgs matched, extra
n = pkgs = 0
for tree in sorted(glob.glob(f'{out}/*.txt')):
    name = os.path.basename(tree)[:-4]
    mv = maven(tree)
    mv.pop(f't:{name}:1', None)
    n += 1
    pkgs += len(mv)
    for s in sides:
        fr = ours(f'{s}/{name}.cdx.json')
        hit = set(mv) & set(fr)
        totals[s][1] += len(hit)
        totals[s][2] += len(set(fr) - set(mv))
        if set(mv) == set(fr):
            totals[s][0] += 1
        elif s == sides[0]:
            diffs[name] = (sorted(set(mv) - set(fr)), sorted(set(fr) - set(mv)))
print(f'{n} projects resolved by Maven, {pkgs} packages')
for s in sides:
    e, h, x = totals[s]
    print(f'{s}: {e} projects identical, {h}/{pkgs} packages ({100*h/pkgs:.1f}%), {x} extra')
for k, (a, b) in list(diffs.items())[:40]:
    print(k, 'maven-only', a[:4], 'ours-only', b[:4])
