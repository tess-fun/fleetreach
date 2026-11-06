#!/usr/bin/env python3
"""E3: per image, pull it, scan it, judge the sink records over its jars, then delete it."""
import json,os,subprocess,sys,tarfile,shutil,gzip,time
from concurrent.futures import ThreadPoolExecutor
S=os.environ['FLEETREACH_TARGET_PARENT']
H=os.path.expanduser('~/fa-testbed/e3'); W=H+'/work'; O=H+'/out'
FR=S+'/base-target/release/fleetreach'; JR=S+'/base-target/release/examples/jvmreach'
REC='./crates/sinks/data'; OSV=os.path.expanduser('~/fa-testbed/java/osv')
def sh(cmd,**k): return subprocess.run(cmd,capture_output=True,text=True,**k)
def extract(tar,dest):
    os.makedirs(dest,exist_ok=True); n=0
    with tarfile.open(tar) as t:
        man=json.load(t.extractfile('manifest.json'))[0]
        for li,l in enumerate(man['Layers']):
            f=t.extractfile(l)
            with tarfile.open(fileobj=f,mode='r|*') as lt:
                for m in lt:
                    if m.isfile() and m.name.lower().endswith(('.jar','.war','.hpi','.ear')) and m.size<1<<30:
                        p=dest+'/'+m.name.replace('/','__').lstrip('.')
                        with open(p,'wb') as o: shutil.copyfileobj(lt.extractfile(m),o)
                        n+=1
    return n
import zipfile,io
def classes(z):
    return [n[:-6].replace('/','.') for n in z.namelist() if n.endswith('.class') and not n.startswith('META-INF/')]
def strip(c):
    for p in ('BOOT-INF.classes.','WEB-INF.classes.'):
        if c.startswith(p): return c[len(p):]
    return c
def jarmap(jars,reached):
    out={}
    def add(base,cs):
        a=out.setdefault(base,[0,0]); a[0]+=len(cs); a[1]+=sum(1 for c in cs if strip(c) in reached)
    for j in jars:
        base=j.split('__')[-1]
        try:
            z=zipfile.ZipFile(j)
            add(base,classes(z))
            for n in z.namelist():
                if n.endswith('.jar') and n.startswith(('BOOT-INF/lib/','WEB-INF/lib/')):
                    try: add(n.split('/')[-1],classes(zipfile.ZipFile(io.BytesIO(z.read(n)))))
                    except Exception: pass
        except Exception: pass
    return out
def one(line):
    ref,app=line.split(); n=ref.replace('/','_').replace(':','_'); res=f'{H}/out2/{n}.json'
    if os.path.exists(res): return
    d=f'{W}/{n}'; os.makedirs(d,exist_ok=True); tar=f'{d}/i.tar'; r={'ref':ref}; t0=time.time()
    try:
        p=sh(['docker','run','--rm','-v',f'{d}:/d','gcr.io/go-containerregistry/crane','pull','--platform','linux/amd64','--format','tarball',ref,'/d/i.tar'],timeout=1500)
        if p.returncode: r['error']='pull: '+p.stderr[-200:]; return
        extract(tar,d+'/j'); os.remove(tar)
        jars=[d+'/j/'+x for x in sorted(os.listdir(d+'/j'))]
        env=dict(os.environ,JVMREACH_APP=app,JVMREACH_DUMP=d+'/dump',JVMREACH_CALLERS='lookup')
        if jars:
            p=sh([JR,REC]+jars,env=env,timeout=900)
            r['stat']=p.stdout.split('\n')[:2]
            r['lookup']=[l for l in p.stdout.split('\n') if 'commons/text' in l and 'lookup' in l][:40]
            reached={l for l in open(d+'/dump').read().split('\n') if l[:2] not in('# ','= ')}
            r['jars']=jarmap(jars,reached)
    except Exception as e:
        r['error']=repr(e)[:300]
    finally:
        r['secs']=int(time.time()-t0)
        json.dump(r,open(res,'w')); shutil.rmtree(d,ignore_errors=True); print(n,r.get('error',''),len(r.get('jars',{})),r['secs'],flush=True)
os.makedirs(H+'/out2',exist_ok=True)
L=[l.strip() for l in open(H+'/corpus.txt') if l.strip()]
with ThreadPoolExecutor(3) as ex: list(ex.map(one,L))
print('E3_DONE')
