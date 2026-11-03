#!/bin/sh
# Regenerate the Berkeley DB and NDB fixtures with rpm itself (needs Docker and network):
# real small packages registered with --justdb, then one erased, so the Berkeley DB file
# still holds the erased header's bytes on a free page.
#   sh gen-bdb-ndb.sh
set -eu
cd "$(dirname "$0")"
rm -rf db-bdb db-ndb
docker run --rm -v "$PWD:/out" rockylinux:8 sh -c '
dnf -q -y install --downloadonly --downloaddir=/tmp/r libpng which bc >/dev/null
dnf -q -y reinstall --downloadonly --downloaddir=/tmp/r basesystem >/dev/null
rpm --dbpath /tmp/db --initdb
rpm --dbpath /tmp/db --justdb --nodeps --noscripts --nosignature -i /tmp/r/*.rpm
rpm --dbpath /tmp/db --justdb --nodeps --noscripts -e bc
mkdir -p /out/db-bdb && cp /tmp/db/Packages /out/db-bdb/'
docker run --rm -v "$PWD:/out" opensuse/leap:15.6 sh -c '
zypper -q --pkg-cache-dir /tmp/c download libpng16-16 which bc >/dev/null
rpm --dbpath /tmp/db --initdb
rpm --dbpath /tmp/db --justdb --nodeps --noscripts --nosignature -i $(find /tmp/c -name "*.rpm")
rpm --dbpath /tmp/db --justdb --nodeps --noscripts -e bc
mkdir -p /out/db-ndb && cp /tmp/db/Packages.db /out/db-ndb/'
