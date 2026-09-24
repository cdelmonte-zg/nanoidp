#!/usr/bin/env bash
# Start a NanoIDP for this CI job and wait until it answers.
set -euo pipefail

# Refuse a port another process holds: the readiness check below would
# otherwise be answered by that process instead of this job's IdP. Only
# "connection refused" (curl exit code 7) means the port is free; anything
# else, a listener that accepts and never answers included, means it is not.
probe=0
curl -s -o /dev/null --max-time 2 http://localhost:8000/ || probe=$?
if [ "$probe" -ne 7 ]; then
  echo "port 8000 is already in use" >&2
  exit 1
fi

python -m nanoidp init ./idp-config
python -m nanoidp --config ./idp-config > nanoidp.log 2>&1 &
echo $! > nanoidp.pid

# Ready when /api/health answers; give up if the process exits or after 30 s
timeout 30 sh -c 'until curl -fsS --max-time 2 http://localhost:8000/api/health; do
  kill -0 "$(cat nanoidp.pid)" || exit 1; sleep 1; done' \
  || { cat nanoidp.log; exit 1; }
