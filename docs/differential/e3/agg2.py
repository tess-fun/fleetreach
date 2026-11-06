import json,glob,os,collections,re
H=os.path.expanduser('~/fa-testbed/e3')
tot=collections.Counter(); hc=collections.Counter(); per=[]; pk0=collections.Counter(); pkr=collections.Counter()
frac=[]
for p in sorted(glob.glob(H+'/out2/*.json')):
    m=json.load(open(p)); n=os.path.basename(p)[:-5]
    if 'jars' not in m: print('skip',n,m.get('error','')[:80]); continue
    try: d=json.load(open(f'{H}/out/{n}.scan'))
    except Exception: print('noscan',n); continue
    jars=m['jars']; c=collections.Counter()
    for v in d['vulnerabilities']:
        if v.get('ecosystem','').lower()!='maven': continue
        seen=set()
        for o in v['occurrences']:
            path=(o.get('dependency_path') or [''])[-1]; base=re.split(r'[/!]',path)[-1]
            k=(o.get('package'),base)
            if k in seen: continue
            seen.add(k)
            j=jars.get(base)
            if j is None or j[0]==0: b='jar-unmapped'
            elif j[1]==0: b='jar-untouched'; pk0[o['package']]+=1
            else: b='jar-touched'; pkr[o['package']]+=1
            c[b]+=1; tot[b]+=1
            if v.get('severity') in('high','critical'): hc[b]+=1
    t=c['jar-untouched']+c['jar-touched']
    if t: per.append((c['jar-untouched']/t,t,n))
print(dict(tot),sum(tot.values())); print(dict(hc),sum(hc.values()))
per.sort(); print('median per service',per[len(per)//2][0]); print(per[:4]); print(per[-6:])
print(pk0.most_common(12)); print(pkr.most_common(8))
L=[]
for p in glob.glob(H+'/out2/*.json'):
    m=json.load(open(p))
    for l in m.get('lookup',[]): L.append((os.path.basename(p)[:20],l[:150]))
for x in L[:14]: print(x)
