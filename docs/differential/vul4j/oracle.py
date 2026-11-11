# Runs inside vul4j:oracle. Checks out one entry at its vulnerable commit, builds it, runs its
# PoV tests under the JaCoCo agent, and writes to /out/ID: the class path the graph needs, the
# methods the human patch changes (sinks.txt), and the methods the PoV run executed (covered.txt).
import glob, json, os, re, shutil, subprocess, sys, zipfile
from report import report
from sinks import map_sinks

vid = sys.argv[1]
W, O = f'/w/{vid}', f'/out/{vid}'
shutil.rmtree(O, ignore_errors=True)
os.makedirs(O)
log = open(f'{O}/oracle.log', 'w')

def sh(cmd, env=None, check=True, cwd=None):
    log.write(f'$ {cmd}\n'); log.flush()
    r = subprocess.run(cmd, shell=True, stdout=log, stderr=subprocess.STDOUT, env=env, cwd=cwd)
    if check and r.returncode:
        for f in glob.glob(f'{W}/VUL4J/*.log'):
            shutil.copy(f, O)
        raise SystemExit(f'{vid}: failed: {cmd}')
    return r.returncode

def status(**kw):
    json.dump(kw, open(f'{O}/status.json', 'w'), indent=1)

sh(f'vul4j checkout -i {vid} -d {W}')
info = json.load(open(f'{W}/VUL4J/vulnerability_info.json'))
level = int(info['compliance_level'])
jhome = {7: '/opt/jdks/jdk7', 8: '/opt/jdks/jdk8', 11: '/opt/jdks/jdk11'}.get(level, '/opt/jdks/jdk16')
# As vul4j's get_java_home_env: Java 7 builds use Maven 3.3.9.
mvn = os.environ['MAVEN33_HOME'] if level <= 7 else os.environ['MAVEN_HOME']
env = dict(os.environ, JAVA_HOME=jhome, PATH=f'{mvn}/bin:{jhome}/bin:' + os.environ['PATH'])
mod = info['failing_module']
M = W if mod in ('root', '') else f'{W}/{mod}'
if info['build_system'] != 'Maven':
    status(stage='skip', why='gradle')
    raise SystemExit(0)
sh(f'vul4j compile -d {W}')
pl = '' if M == W else f'-pl {mod}'
cpcmd = f"dependency:build-classpath -Dmdep.outputFile={O}/classpath.info {info['cmd_options']}"
if sh(f'mvn {cpcmd} {pl}', env, check=not pl, cwd=W):
    # A module whose sibling SNAPSHOTs were never installed resolves them from the reactor; the
    # target module builds last, so its class path is the one left in the file.
    sh(f'mvn test-compile {cpcmd} {pl} -am', env, cwd=W)

# PoV run under the agent, in surefire's forked JVM only (jvm/bin/java): JAVA_TOOL_OPTIONS
# would reach Maven's own JVM too, whose plugins and annotation processors (querydsl's apt) can
# load the project's own dependency jars.
# A first run without the agent compiles the tests.
sh(f'vul4j test -d {W} -b povs', check=False)
# A build's own JaCoCo agent (the commons parent adds one) cannot run beside this one; vul4j
# sets MAVEN_OPTS from its MVN_ARGS. The commons parent also sets surefire's jvm from its own
# property. Surefire 2.21+ wants the path to end in bin/java.
sh(f'vul4j test -d {W} -b povs', dict(os.environ, ORACLE_DEST=f'{O}/jacoco.exec',
   MVN_ARGS='-Djacoco.skip=true -Djvm=/h/jvm/bin/java -Dcommons.surefire.java=/h/jvm/bin/java'), check=False)
results = json.load(open(f'{W}/VUL4J/testing_results.json'))
for f in glob.glob(f'{W}/VUL4J/*.log'):
    shutil.copy(f, O)

def build_dir(expr, default):
    # Where Maven put the classes; some builds (OpenRefine) leave target/ for elsewhere.
    r = subprocess.run(f"mvn -q help:evaluate -Dexpression={expr} -DforceStdout {pl} {info['cmd_options']}",
                       shell=True, cwd=W, env=env, capture_output=True, text=True)
    out = r.stdout.strip().splitlines()[-1:] if r.returncode == 0 else []
    return out[0] if out and os.path.isdir(out[0]) else default

entries = [build_dir('project.build.testOutputDirectory', f'{M}/target/test-classes'),
           build_dir('project.build.outputDirectory', f'{M}/target/classes')]
entries += [p for p in open(f'{O}/classpath.info').read().strip().split(':') if p]
def case_clash(d):
    seen = set()
    for f in glob.glob(f'{d}/**/*', recursive=True):
        if f.lower() in seen:
            return True
        seen.add(f.lower())
    return False

os.makedirs(f'{O}/cp')
kept = []
for i, e in enumerate(entries):
    if not os.path.exists(e):
        continue
    base = ('test-classes', 'classes')[i] if i < 2 else os.path.basename(e.rstrip('/'))
    dst = f'{O}/cp/{i:03d}-{base}'
    if os.path.isdir(e) and case_clash(e):
        # /out is a macOS mount, which cannot hold Queue.class beside queue/ (Jenkins): a jar can.
        with zipfile.ZipFile(f'{dst}.jar', 'w') as z:
            for f in glob.glob(f'{e}/**/*', recursive=True):
                if os.path.isfile(f):
                    z.write(f, os.path.relpath(f, e))
        dst += '.jar'
    elif os.path.isdir(e):
        shutil.copytree(e, dst)
    else:
        shutil.copy(e, dst)
    kept.append(dst)

covered = report(O, kept)

# Methods the human patch changes, on the vulnerable side: lines removed or changed, and the
# lines either side of a pure insertion, mapped to methods by the LineNumberTable.
tip = subprocess.run('git log --all --format=%H -n1', shell=True, cwd=W, capture_output=True, text=True).stdout.strip()
diff = subprocess.run(f"git diff -U0 HEAD {tip} -- '*.java'", shell=True, cwd=W, capture_output=True, text=True).stdout
open(f'{O}/patch.diff', 'w').write(diff)
sinks, unmapped = map_sinks(O, kept, jhome)
status(stage='done', tests=info['failing_tests'], results=results['tests']['overall_metrics'],
       failures=[f["test_class"] + '#' + f["test_method"] for f in results['tests']['failures']],
       sinks=len(sinks), covered=len(covered), unmapped=unmapped)
