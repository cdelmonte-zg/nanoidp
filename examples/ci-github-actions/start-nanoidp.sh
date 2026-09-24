#!/usr/bin/env bash
# Start a NanoIDP for this CI job and wait until it answers.
set -euo pipefail

# Fail if something already answers on the port: the readiness check below
# would otherwise be answered by that process instead of this job's IdP
if curl -s -o /dev/null http://localhost:8000/; then
  echo "port 8000 is already in use" >&2
  exit 1
fi

python -m nanoidp init ./idp-config
python -m nanoidp --config ./idp-config > nanoidp.log 2>&1 &
echo $! > nanoidp.pid

# Ready when /api/health answers; give up if the process exits or after 30 s
timeout 30 sh -c 'until curl -fsS http://localhost:8000/api/health; do
  kill -0 "$(cat nanoidp.pid)" || exit 1; sleep 1; done' \
  || { cat nanoidp.log; exit 1; }
