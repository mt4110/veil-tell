#!/bin/bash
set -euo pipefail
for _ in {1..960}; do
  if [[ -f receiver.stop ]]; then exit 1; fi
  if [[ -f receiver.start ]]; then break; fi
  sleep 0.25
done
test -f receiver.start
sudo ifconfig lo0 inet 192.0.1.2 netmask 255.255.255.255 alias
route -n get 192.0.1.2 | grep -E 'interface: lo0$'
sudo "$(command -v python3)" -u "$PWD/tests/release-smoke.py" receive &
receiver_pid=$!
for _ in {1..40}; do
  if grep -qx ready "$RUNNER_TEMP/receiver.log"; then break; fi
  kill -0 "$receiver_pid"
  sleep 0.25
done
grep -qx ready "$RUNNER_TEMP/receiver.log"
touch receiver.ready
wait "$receiver_pid"
