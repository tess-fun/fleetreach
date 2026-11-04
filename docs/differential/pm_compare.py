import json,os,urllib.parse,collections,sys
ts=json.load(open('targets.json'))
tot=collections.Counter(); rows=[]
import copy
for t in ts:
    o=f"out/{t['id']}.json"
    if not os.path.exists(o): tot[t['tool']+' none']+=1; continue
    d=json.load(open(o))
    if d['packages'] is None:
        tot[t['tool']+' tool-failed']+=1; rows.append((t['id'],t['tool'],'TOOL',d['error'][-110:].replace('\n',' '))); continue
    b=json.load(open(f"ours/{t['id']}.cdx.json"))
    mine=set()
    for c in b['components']:
        p=c['purl']
        if p.startswith('pkg:npm/'):
            mine.add(c['name']+'@'+c['version'])
    theirs=set(d['packages'])
    a=sorted(mine-theirs); z=sorted(theirs-mine)
    tot[t['tool']+' compared']+=1; tot[t['tool']+' pkgs']+=len(theirs)
    if not a and not z: tot[t['tool']+' identical']+=1
    else: rows.append((t['id'],t['tool'],len(mine),len(theirs),'ours-only',len(a),a[:3],'theirs-only',len(z),z[:3],t['dir'][-30:]))
print(sorted(tot.items()))
for r in rows: print(str(r)[:260])
