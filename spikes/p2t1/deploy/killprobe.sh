#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Compare `systemctl kill --kill-whom=main` and `--kill-whom=all` on the spike
# plugin units and check what is left in the cgroup. Temporary diagnostic.
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

bash "$HERE/install.sh" >/dev/null || exit 1
systemctl stop 'qwq-spike-plugin@alpha.service' 'qwq-spike-plugin@beta.service' \
  'qwq-spike-plugin@alpha.socket' 'qwq-spike-plugin@beta.socket' 2>/dev/null
systemctl restart qwq-spike-agent.service
for _ in $(seq 1 100); do
  [[ -s /run/qwq-spike/state/alpha.json && -s /run/qwq-spike/state/beta.json ]] && break
  sleep 0.2
done
sleep 1

for id in alpha beta; do
  unit="qwq-spike-plugin@$id.service"
  cg=$(systemctl show -p ControlGroup --value "$unit")
  echo "=== $id before: $(systemctl show -p MainPID --value "$unit") cgroup=$cg ==="
  systemctl stop "qwq-spike-plugin@$id.socket"
  if [[ $id == alpha ]]; then
    echo '--- systemctl kill --kill-whom=main -s SIGKILL ---'
    systemctl kill --kill-whom=main -s SIGKILL "$unit"
    echo "rc=$?"
  else
    echo '--- systemctl kill --kill-whom=all -s SIGKILL ---'
    systemctl kill --kill-whom=all -s SIGKILL "$unit"
    echo "rc=$?"
  fi
  sleep 1
  echo "after: MainPID=$(systemctl show -p MainPID --value "$unit") ActiveState=$(systemctl show -p ActiveState --value "$unit") SubState=$(systemctl show -p SubState --value "$unit")"
  if [[ -e /sys/fs/cgroup$cg/cgroup.procs ]]; then
    echo "cgroup.procs: [$(cat "/sys/fs/cgroup$cg/cgroup.procs" | tr '\n' ' ')]"
  else
    echo 'cgroup removed'
  fi
done
echo '=== leftover plugin processes ==='
pgrep -a -f '/opt/qwq-spike/spike-plugin' || echo none
bash "$HERE/uninstall.sh" >/dev/null 2>&1
echo done
