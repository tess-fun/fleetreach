# Methods the human patch changes, on the vulnerable side: lines removed or changed, and the
# lines either side of a pure insertion, mapped to methods by the LineNumberTable. JDK 7's
# javap prints the descriptor as "Signature:".
import glob, os, re, subprocess, sys, zipfile

def map_sinks(O, kept, jhome):
    diff = open(f'{O}/patch.diff').read()
    changed = {}
    cur = None
    for line in diff.splitlines():
        if line.startswith('--- '):
            cur = line[6:] if line.startswith('--- a/') else None
        m = re.match(r'@@ -(\d+)(?:,(\d+))? \+', line)
        if m and cur and '/test/' not in cur:
            start, n = int(m.group(1)), int(m.group(2) or 1)
            lines = set(range(start, start + n)) if n else {start, start + 1}
            changed.setdefault(cur, set()).update(lines)

    def classes_for(src):
        # src/main/java/a/b/C.java -> a/b/C and its nested classes, from any kept entry.
        m = re.search(r'(?:src/main/java|src/java|src|java)/(.+)\.java$', src)
        if not m:
            return []
        rel = m.group(1)
        out = []
        for e in kept:
            if os.path.isdir(e):
                for f in glob.glob(f'{e}/{rel}.class') + glob.glob(f'{e}/{rel}$*.class'):
                    out.append(f)
            elif e.endswith('.jar'):
                with zipfile.ZipFile(e) as z:
                    for n in z.namelist():
                        if n == f'{rel}.class' or (n.startswith(f'{rel}$') and n.endswith('.class')):
                            d = f'/tmp/x/{os.path.basename(e)}'
                            z.extract(n, d)
                            out.append(f'{d}/{n}')
        return out

    sinks = set()
    unmapped = []
    for src, lines in changed.items():
        # (method, its line numbers) for every method of the file's classes.
        methods = []
        for cf in classes_for(src):
            out = subprocess.run(f"{jhome}/bin/javap -p -l -s '{cf}'", shell=True, capture_output=True, text=True).stdout
            cls = re.search(r'(?:class|interface|enum) ([\w.$]+)', out)
            if not cls:
                continue
            cname = cls.group(1).replace('.', '/')
            for block in re.split(r'\n(?=  \S)', out):
                head = block.strip().splitlines()[0] if block.strip() else ''
                d = re.search(r'(?:descriptor|Signature): (\S+)', block)
                nums = {int(n) for n in re.findall(r'line (\d+): \d+', block)}
                if head.startswith('static {}'):
                    head = '<clinit>('
                if not d or not nums or '(' not in head:
                    continue
                name = head.split('(')[0].split()[-1]
                name = '<init>' if name.replace('.', '/') == cname else name
                methods.append((f'{cname}.{name}:{d.group(1)}', nums))
        hit = {m for m, nums in methods if nums & lines}
        # No instruction on a changed line (array elements, an insertion after a blank line):
        # the methods whose line range holds the change, the innermost ones.
        if not hit:
            around = [(max(n) - min(n), m) for m, n in methods if any(min(n) <= l <= max(n) for l in lines)]
            if around:
                least = min(w for w, _ in around)
                hit = {m for w, m in around if w == least}
        sinks |= hit
        if not hit:
            unmapped.append(src)
    open(f'{O}/sinks.txt', 'w').write('\n'.join(sorted(sinks)) + '\n')
    return sinks, unmapped

if __name__ == '__main__':
    import json
    O, jhome = sys.argv[1], sys.argv[2]
    sinks, unmapped = map_sinks(O, sorted(glob.glob(f'{O}/cp/*')), jhome)
    st = json.load(open(f'{O}/status.json'))
    st.update(sinks=len(sinks), unmapped=unmapped)
    json.dump(st, open(f'{O}/status.json', 'w'), indent=1)
