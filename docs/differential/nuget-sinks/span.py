# Do the sinks of each reviewed NuGet record exist across its affected range?
#
# python3 -I span.py DATA_DIR OSV_NUGET_ZIP WORK CLRDUMP [STATUS]
#
# STATUS is the review status to check, `reviewed` by default (`proposed` before a review).
#
# DATA_DIR is the folder of NuGet records itself (crates/sinks/data/nuget). On macOS with a
# python.org Python, set SSL_CERT_FILE=/etc/ssl/cert.pem or every fetch fails.
#
# For every ECOSYSTEM range, checks the earliest stable affected release and the last
# release of each major line in range, by method list (clrdump `M` lines). A record whose
# sinks are all absent from a release is judged unknown there (SinkAbsent), which is safe;
# one with only some present needs a look: the present ones must still sit on the path.
# Packages are read as data and never loaded or run.
import json, sys, os, re, zipfile, glob, subprocess, urllib.request
DATA, OSVZIP, WORK, DUMP = sys.argv[1:5]
STATUS = sys.argv[5] if len(sys.argv) > 5 else 'reviewed'
z = zipfile.ZipFile(OSVZIP)
def key(v):
    core, _, pre = v.partition('-'); nums=[int(x) if x.isdigit() else 0 for x in re.split(r'[.]', core)]
    return (nums + [0]*(4-len(nums)), pre == '', pre)
def versions(pkg):
    with urllib.request.urlopen(f'https://api.nuget.org/v3-flatcontainer/{pkg.lower()}/index.json') as r:
        return json.load(r)['versions']
def in_range(v, ev):
    lo, hi = None, None; ok=False
    intro=[e['introduced'] for e in ev if 'introduced' in e]; fix=[e['fixed'] for e in ev if 'fixed' in e]; last=[e['last_affected'] for e in ev if 'last_affected' in e]
    lo = intro[0] if intro else '0'
    if lo != '0' and key(v) < key(lo): return False
    if fix and key(v) >= key(fix[0]): return False
    if last and key(v) > key(last[0]): return False
    return True
def methods(pkg, v):
    d = os.path.join(WORK, f'{pkg.lower()}.{v}')
    if not os.path.isdir(d):
        os.makedirs(d); n=os.path.join(d,'p.nupkg')
        urllib.request.urlretrieve(f'https://api.nuget.org/v3-flatcontainer/{pkg.lower()}/{v}/{pkg.lower()}.{v}.nupkg', n)
        with zipfile.ZipFile(n) as nz:
            for m in nz.namelist():
                if m.startswith('lib/') and m.lower().endswith('.dll'):
                    parts=m.split('/')
                    if len(parts)==2: parts=['lib','any',parts[1]]  # old packages: lib/x.dll
                    if len(parts)!=3: continue
                    out=os.path.join(d, parts[1]+'__'+os.path.basename(parts[2]))
                    with open(out,'wb') as f: f.write(nz.read(m))
        # Split libraries keep the code in sibling packages (HotChocolate.Language.Utf8), and a
        # meta-package can point at another one (Umbraco.Cms -> Umbraco.Cms.Targets -> ...).
        def deps(path):
            with zipfile.ZipFile(path) as nz:
                spec=next((m for m in nz.namelist() if m.endswith('.nuspec') and '/' not in m),None)
                text=nz.read(spec).decode('utf-8','replace') if spec else ''
            return sorted(set((a, b) for a, b in re.findall(r'<dependency id="([^"]+)" version="\[?([0-9A-Za-z.+-]+)', text)
                              if a.lower().startswith(pkg.lower()+'.')))
        queue, seen = deps(n), set()
        while queue and len(seen) < 64:
            dep, ver = queue.pop(0)
            if dep.lower() in seen: continue
            seen.add(dep.lower())
            dn=os.path.join(d,f'sib-{len(seen)}.nupkg')
            urllib.request.urlretrieve(f'https://api.nuget.org/v3-flatcontainer/{dep.lower()}/{ver.lower()}/{dep.lower()}.{ver.lower()}.nupkg', dn)
            queue += deps(dn)
            with zipfile.ZipFile(dn) as sz:
                for m in sz.namelist():
                    parts=m.split('/')
                    if m.startswith('lib/') and m.lower().endswith('.dll') and len(parts)==3:
                        with open(os.path.join(d, parts[1]+'__'+os.path.basename(parts[2])),'wb') as f: f.write(sz.read(m))
    dlls=[p for p in glob.glob(os.path.join(d,'*.dll'))]
    ms=set()
    for p in dlls:
        o=subprocess.run([DUMP,p],capture_output=True,text=True).stdout
        for line in o.splitlines():
            if line.startswith('M '):
                ms.add(line.split()[1])
    return ms, len(dlls)
for f in sorted(glob.glob(os.path.join(DATA,'*.json'))):
    r=json.load(open(f))
    if r['status']!=STATUS or r.get('verdict')!='sinks': continue
    a=json.loads(z.read(r['id']+'.json'))
    for aff in a['affected']:
        pkg=aff['package']['name']
        if pkg not in r['packages']: continue
        try: allv=versions(pkg)
        except Exception as e: print(r['id'],pkg,'versions error',e); continue
        for rg in aff.get('ranges',[]):
            if rg['type']!='ECOSYSTEM': continue
            vs=sorted([v for v in allv if in_range(v,rg['events'])],key=key)
            stable=[v for v in vs if '-' not in v] or vs
            if not stable: continue
            pick={stable[0]}
            majors={}
            for v in stable: majors[v.split('.')[0]]=v
            pick|=set(majors.values())
            for v in sorted(pick,key=key):
                try: ms,n=methods(pkg,v)
                except Exception as e: print(r['id'],pkg,v,'fetch error',e); continue
                if n==0: print(r['id'],pkg,v,'no lib dlls'); continue
                miss=[s['class']+'::'+s['method'] for s in r['sinks'] if s['class']+'::'+s['method'] not in ms]
                hit=len(r['sinks'])-len(miss)
                print(r['id'],pkg,v,f'{hit}/{len(r["sinks"])}', ('MISSING '+', '.join(miss)) if miss else 'ok')
