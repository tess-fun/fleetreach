# Methods the PoV run executed, from jacoco.exec: one JaCoCo report per class path entry (two
# entries may hold a class of the same name, which one report refuses). Reports are kept in
# O/jac so the parse can be rerun.
import glob, os, re, subprocess, sys

CLASS = re.compile(r'<class name="([^"]+)"[^>]*?(/?)>')
METHOD = re.compile(r'<method name="([^"]+)" desc="([^"]+)"[^>]*>(.*?)</method>', re.S)
COVERED = re.compile(r'<counter type="METHOD" missed="\d+" covered="(\d+)"')

def parse(xml):
    out = set()
    for c in CLASS.finditer(xml):
        if c.group(2):
            continue
        body = xml[c.end():xml.index('</class>', c.end())]
        for m in METHOD.finditer(body):
            n = COVERED.search(m.group(3))
            if n and n.group(1) != '0':
                name = m.group(1).replace('&lt;', '<').replace('&gt;', '>')
                out.add(f'{c.group(1)}.{name}:{m.group(2)}')
    return out

def report(O, kept):
    os.makedirs(f'{O}/jac', exist_ok=True)
    covered = set()
    if os.path.exists(f'{O}/jacoco.exec'):
        for i, e in enumerate(kept):
            x = f'{O}/jac/{i:03d}.xml'
            subprocess.run(f'/opt/jdks/jdk11/bin/java -jar /opt/jacoco/cli.jar report {O}/jacoco.exec '
                           f'--classfiles {e} --xml {x} --quiet', shell=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if os.path.exists(x):
                covered |= parse(open(x).read())
    open(f'{O}/covered.txt', 'w').write('\n'.join(sorted(covered)) + '\n')
    return covered

if __name__ == '__main__':
    O = sys.argv[1]
    report(O, sorted(glob.glob(f'{O}/cp/*')))
