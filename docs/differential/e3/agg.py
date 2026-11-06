#!/usr/bin/env python3
import json,glob,os,collections,sys
H=os.path.expanduser('~/fa-testbed/e3/out')
rec={}
for f in glob.glob('./crates/sinks/data/maven/*.json'):
    r=json.load(open(f)); rec[r['id']]=r
    for a in r.get('aliases',[]): rec.setdefault(a,r)
tot=collections.Counter(); hc=collections.Counter(); rows=[]; byrec=collections.defaultdict(collections.Counter); ok=0; roots=collections.Counter()
for p in sorted(glob.glob(H+'/*.json')):
    m=json.load(open(p)); n=os.path.basename(p)[:-5]
    if m.get('error') or not os.path.exists(f'{H}/{n}.e3') or not os.path.exists(f'{H}/{n}.scan'):
        rows.append((n,'FAILED',(m.get('error') or m.get('jr_err') or 'no e3')[:70])); continue
    try: d=json.load(open(f'{H}/{n}.scan'))
    except Exception as e: rows.append((n,'BADSCAN',str(e)[:60])); continue
    ver={}
    for l in open(f'{H}/{n}.e3').read().split('\n'):
        if l:
            a=l.split('\t'); ver[a[0]]=a
    ok+=1; c=collections.Counter()
    for v in d['vulnerabilities']:
        if v.get('ecosystem','').lower()!='maven': continue
        ids=[v['advisory_id']]+v.get('aliases',[])
        r=next((rec[i] for i in ids if i in rec),None)
        pk={o.get('package') for o in v.get('occurrences',[])}
        for _ in pk:
            if r is None: b='no-record'
            elif r['status']!='reviewed': b='proposed-record'
            elif r['verdict']!='sinks': b='reviewed-'+r['verdict']
            else:
                a=ver.get(r['id'],[r['id'],'?','?',''])
                b=a[1]; 
                if a[1]=='unknown-RecordCannotSay': b='by-name:'+a[2]
                if a[2]=='reached' and a[3]: roots[a[3].split('(')[0]]+=1
                byrec[r['id']][b]+=1
            c[b]+=1; tot[b]+=1
            if v.get('severity') in('high','critical'): hc[b]+=1
    rows.append((n,sum(c.values()),dict(c)))
for r in rows: print(r[0][:44].ljust(45),r[1],str(r[2])[:150])
print('services',ok); print('all',sum(tot.values()),dict(tot.most_common())); print('high/critical',sum(hc.values()),dict(hc.most_common()))
print(roots.most_common())
for k,v in sorted(byrec.items()): print(k,dict(v), rec[k]['packages'][:1] if isinstance(rec[k]['packages'],list) else '')
