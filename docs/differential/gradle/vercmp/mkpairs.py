# Pairs for the Gradle version-order differential: every pair of a fixed set of edge cases,
# 200k random pairs of the given versions, and pairs sharing a leading part.
# usage: mkpairs.py VERSIONS_FILE PAIRS_FILE
import random,sys
vs=[l.strip() for l in open(sys.argv[1]) if l.strip() and '\t' not in l]
extra="1 1.0 1.0.0 1.0.1 1.0-alpha 1.0-ALPHA 1.0-dev 1.0-rc 1.0-RC1 1.0-snapshot 1.0-SNAPSHOT 1.0-final 1.0-ga 1.0-GA 1.0-release 1.0-sp 1.0-sp1 1.0-zeta 1.a 1.1 1_0 1+0 1.0a1 1.0.a 3 3.0 3.0.0-M5 3.0.0 2.4.0-b180830.0438 2.2 2.3.9 1.0-beta 1.0-b 1.0.Final 1.0.RELEASE 1.0-jre 1.0-android 10 9 1.01 1.001 0.9 1.0-1 1.0.0.0 01 1.0-SP2 1.0-ea 1.0-M1 1.0-cr1 2.0.0-RC2 2.0.0-rc2 1.0-pre 1.0--1 1..0 v1 1.0-alpha1 1.0-alpha10 1.0-alpha2".split()
vs=sorted(set(vs+extra))
random.seed(7)
out=open(sys.argv[2],'w')
n=0
for a in extra:
    for b in extra:
        out.write(f"{a}\t{b}\n"); n+=1
for _ in range(200000):
    a,b=random.choice(vs),random.choice(vs); out.write(f"{a}\t{b}\n"); n+=1
# same-artifact neighbours are the interesting ones: pairs sharing a prefix
by={}
for v in vs: by.setdefault(v.split('.')[0],[]).append(v)
for k,l in by.items():
    for _ in range(min(200,len(l)*3)):
        a,b=random.choice(l),random.choice(l); out.write(f"{a}\t{b}\n"); n+=1
print(n)
