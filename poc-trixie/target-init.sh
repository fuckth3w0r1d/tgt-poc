#!/bin/sh
set -e

/usr/sbin/tgtd -f --iscsi portal=0.0.0.0:3260 &
sleep 1

/usr/sbin/tgtadm --lld iscsi --op new --mode target --tid 1 -T iqn.2026-11.test:disk
/usr/sbin/tgtadm --lld iscsi --op new --mode logicalunit --tid 1 --lun 1 -b /srv/tgt/disk1
/usr/sbin/tgtadm --lld iscsi --op bind --mode target --tid 1 -I ALL

echo "tgtd ready on 3260, target iqn.2026-11.test:disk, lun 1"
exec sleep infinity
