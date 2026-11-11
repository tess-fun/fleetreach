# Judges one oracle output: the graph is rooted at the PoV test classes alone, and every
# method the PoV run executed must be reached. Prints one JSON line per entry.
import glob, json, os, subprocess, sys, tempfile, zipfile

JVMREACH = os.environ['JVMREACH']
TEST_LIBS = ('junit/', 'org/junit/', 'org/hamcrest/', 'org/mockito/', 'org/testng/',
             'org/apache/maven/', 'org/easymock/', 'net/bytebuddy/', 'org/objenesis/',
             'org/powermock/', 'org/jmock/', 'org/assertj/', 'com/beust/')

def lines(p):
    return {l for l in open(p).read().splitlines() if l} if os.path.exists(p) else set()

def judge(d):
    if not os.path.exists(f'{d}/status.json'):
        return {'id': os.path.basename(d), 'stage': 'build-failed', 'why': 'see oracle.log'}
    st = json.load(open(f'{d}/status.json'))
    if st.get('stage') != 'done':
        return {'id': os.path.basename(d), 'stage': st.get('stage'), 'why': st.get('why')}
    tests = sorted({t.split('#')[0].strip() for x in (st['tests'] if isinstance(st['tests'], list) else [st['tests']]) for t in x.split(',') if t.strip()})
    cp = sorted(glob.glob(f'{d}/cp/*'))
    covered, sinks = lines(f'{d}/covered.txt'), lines(f'{d}/sinks.txt')
    # The test classes are a directory, or a jar when the directory did not fit a macOS mount.
    tdir, tjar = f'{d}/cp/000-test-classes', f'{d}/cp/000-test-classes.jar'
    if os.path.exists(tjar):
        names = zipfile.ZipFile(tjar).namelist()
    else:
        names = [os.path.relpath(f, tdir) for f in glob.glob(f'{tdir}/**/*.class', recursive=True)]
    test_classes = {n[:-6] for n in names if n.endswith('.class')}
    missing = [t for t in tests if t.replace('.', '/') not in test_classes]
    if missing:
        return {'id': os.path.basename(d), 'stage': 'no-root', 'why': missing}
    # The roots are the PoV classes and any other test class the run executed: a TestNG suite
    # (VUL4J-77) runs the whole suite for one PoV method.
    ran = {m.split('.')[0] for m in covered} & test_classes
    # Surefire calls the JUnit runner (`@RunWith`), and ApacheDS's FrameworkRunner starts the
    # server the PoV talks to (VUL4J-62): every runner that ran is an entry too.
    ran |= {m.split('.')[0] for m in covered
            if m.split('.', 1)[1] == 'run:(Lorg/junit/runner/notification/RunNotifier;)V'}
    roots = sorted({t.replace('.', '/') for t in tests} | ran)
    empty = tempfile.mkdtemp()
    dump = f'{d}/graph'
    env = dict(os.environ, JVMREACH_APP=','.join(r + '=' for r in roots), JVMREACH_DUMP=dump)
    out = subprocess.run([JVMREACH, empty, *cp], env=env, capture_output=True, text=True)
    open(f'{d}/graph.out', 'w').write(out.stdout + out.stderr)
    listed = lines(f'{dump}.methods')
    reached = {l for l in listed if not l.startswith(('# ', '= '))}
    # Every method on the class path, so a run that loaded its own copy of a class (Jenkins' war
    # brings a newer slf4j) is not taken for a graph miss.
    known = reached | {l[2:] for l in listed if l.startswith(('# ', '= '))}
    def lib(m):
        c = m.split('.')[0]
        return c in test_classes or c.startswith(TEST_LIBS)
    code = {m for m in covered if not lib(m)}
    ran_sinks = sinks & covered
    return {
        'id': os.path.basename(d), 'stage': 'done', 'tests': tests,
        'pov_failed': len(st['failures']), 'sinks': len(sinks), 'ran_sinks': len(ran_sinks),
        'missed_sinks': sorted(ran_sinks - reached), 'covered': len(code),
        'missed': sorted((code & known) - reached), 'elsewhere': sorted(code - known),
        'reached': len(reached), 'unmapped': st['unmapped'],
    }

for d in sys.argv[1:]:
    print(json.dumps(judge(d.rstrip('/'))), flush=True)
