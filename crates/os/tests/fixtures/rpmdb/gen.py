# Regenerate the rpmdb.sqlite fixtures (needs the sqlite3 CLI): fake but well-formed RPM
# headers in rpm's Packages table, on 1 KiB pages so rows overflow and the b-tree has
# interior pages; plus a copy whose last changes sit uncheckpointed in a WAL.
#   python3 -I gen.py
import os, shutil, struct, subprocess

def header(name, epoch, version, release, arch, pad):
    tags = [(1000, 6, name), (1001, 6, version), (1002, 6, release), (1022, 6, arch),
            (1044, 6, f'{name}-{version}-{release}.src.rpm'), (1016, 6, 'x' * pad)]
    data, index = b'', b''
    if epoch is not None:
        index += struct.pack('>iIiI', 1003, 4, 0, 1); data += struct.pack('>I', epoch)
    for tag, kind, s in tags:
        index += struct.pack('>iIiI', tag, kind, len(data), 1); data += s.encode() + b'\0'
    return struct.pack('>II', len(index) // 16, len(data)) + index + data

def pkgs(n):
    return [(f'pkg{i:03d}', (i % 3) or None, f'1.{i}', f'{i}.fc41', 'x86_64', 50 + 37 * i) for i in range(n)]

def sql(rows):
    out = ["PRAGMA page_size=1024;",
           "CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT,blob BLOB NOT NULL);",
           "CREATE TABLE 'Name' (key TEXT NOT NULL, hnum INTEGER NOT NULL, idx INTEGER NOT NULL, PRIMARY KEY(key, hnum, idx)) WITHOUT ROWID;"]
    out += [f"INSERT INTO Packages(blob) VALUES (x'{header(*r).hex()}');" for r in rows]
    return '\n'.join(out)

for d in ('db-plain', 'db-wal'):
    shutil.rmtree(d, ignore_errors=True)
os.makedirs('db-plain'); os.makedirs('db-wal')
subprocess.run(['sqlite3', 'db-plain/rpmdb.sqlite'], input=sql(pkgs(60)), text=True, check=True)
# WAL: the same 60 rows checkpointed, then a delete and an insert left in the log.
subprocess.run(['sqlite3', 'db-wal/rpmdb.sqlite'], input=sql(pkgs(60)) + "\nPRAGMA journal_mode=WAL;", text=True, check=True)
tail = (".dbconfig no_ckpt_on_close on\nPRAGMA wal_autocheckpoint=0;\n"
        "DELETE FROM Packages WHERE hnum = 5;\n"
        f"INSERT INTO Packages(blob) VALUES (x'{header('walpkg', 7, '9.9', '1.fc41', 'noarch', 3000).hex()}');\n")
subprocess.run(['sqlite3', 'db-wal/rpmdb.sqlite'], input=tail, text=True, check=True)
for d in ('db-plain', 'db-wal'):
    print(d, {f: os.path.getsize(os.path.join(d, f)) for f in sorted(os.listdir(d))})
