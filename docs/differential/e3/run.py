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
def one(line):
    ref,app=line.split(); n=ref.replace('/','_').replace(':','_'); res=f'{O}/{n}.json'
    if os.path.exists(res): return
    d=f'{W}/{n}'; os.makedirs(d,exist_ok=True); tar=f'{d}/i.tar'; r={'ref':ref,'app':app}; t0=time.time()
    try:
        p=sh(['docker','run','--rm','-v',f'{d}:/d','gcr.io/go-containerregistry/crane','pull','--platform','linux/amd64','--format','tarball',ref,'/d/i.tar'],timeout=1500)
        if p.returncode: r['error']='pull: '+p.stderr[-200:]; return
        r['bytes']=os.path.getsize(tar)
        with open(f'{O}/{n}.scan','w') as out:
            p=subprocess.run([FR,'scan','--image',tar,'--offline','--db',os.path.expanduser('~/.cargo/advisory-db'),'--osv-dir',OSV,'-f','json'],stdout=out,stderr=subprocess.PIPE,text=True,timeout=900)
        r['scan_exit']=p.returncode; r['scan_err']=p.stderr[-300:]
        r['jars']=extract(tar,d+'/j'); os.remove(tar)
        jars=[d+'/j/'+x for x in sorted(os.listdir(d+'/j'))]
        env=dict(os.environ,JVMREACH_APP=app,JVMREACH_E3=f'{O}/{n}.e3')
        if jars:
            p=sh([JR,REC]+jars,env=env,timeout=900)
            r['stat']=p.stdout.split('\n')[:2]; r['jr_exit']=p.returncode; r['jr_err']=p.stderr[-300:]
    except Exception as e:
        r['error']=repr(e)[:300]
    finally:
        r['secs']=int(time.time()-t0)
        json.dump(r,open(res,'w')); shutil.rmtree(d,ignore_errors=True); print(n,r.get('error',''),r.get('stat',''),r['secs'],flush=True)
L=[l.strip() for l in open(H+'/corpus.txt') if l.strip()]
with ThreadPoolExecutor(3) as ex: list(ex.map(one,L))
print('E3_DONE')
