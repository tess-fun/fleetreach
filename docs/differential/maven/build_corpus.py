"""Build a corpus of one-dependency Maven projects from a Maven-layout POM folder.

    python3 -I build_corpus.py POMS ORACLE_OUT_DIR CORPUS_DIR [COUNT]

Picks published artifacts that have a parent POM (where inheritance and property rules
matter) from the coordinates a Gradle oracle run listed (`ORACLE_OUT_DIR/*.out`, `FA` rows),
and writes CORPUS_DIR/projects/pNNN/pom.xml plus CORPUS_DIR/fleet.toml for fleetreach.
"""
import glob, os, random, sys

poms, oracle, corpus = sys.argv[1], sys.argv[2], sys.argv[3]
count = int(sys.argv[4]) if len(sys.argv) > 4 else 300
seen = set()
for f in glob.glob(f'{oracle}/*.out'):
    for line in open(f, errors='replace'):
        p = line.split()
        if len(p) == 4 and p[0] == 'FA' and p[2] == 'runtimeClasspath':
            seen.add(p[3])
cands = []
for c in sorted(seen):
    parts = c.split(':')
    if len(parts) != 3:
        continue
    g, a, v = parts
    pom = f"{poms}/{g.replace('.', '/')}/{a}/{v}/{a}-{v}.pom"
    if os.path.exists(pom):
        t = open(pom, errors='replace').read()
        if '<parent>' in t and '<packaging>pom</packaging>' not in t and 'relocation' not in t:
            cands.append(c)
random.seed(7)
pick = sorted(random.sample(cands, min(count, len(cands))))
os.makedirs(f'{corpus}/projects', exist_ok=True)
with open(f'{corpus}/fleet.toml', 'w') as fleet:
    fleet.write('[fleet]\n')
    for i, c in enumerate(pick):
        g, a, v = c.split(':')
        d = f'{corpus}/projects/p{i:03d}'
        os.makedirs(d, exist_ok=True)
        with open(f'{d}/pom.xml', 'w') as out:
            out.write(
                '<project><modelVersion>4.0.0</modelVersion><groupId>t</groupId>'
                f'<artifactId>p{i:03d}</artifactId><version>1</version><dependencies>'
                f'<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId>'
                f'<version>{v}</version></dependency></dependencies></project>\n'
            )
        fleet.write(f'\n[[repo]]\nid = "p{i:03d}"\npath = "{os.path.abspath(d)}"\n')
print(f'{len(cands)} candidates, {len(pick)} projects')
