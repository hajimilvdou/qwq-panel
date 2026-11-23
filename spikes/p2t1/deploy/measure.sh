#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Second install/uninstall cycle: dump the plugin's cgroup memory.stat to explain
# the difference between memory.current and VmRSS, and repeat the credential
# properties. Also proves install.sh and uninstall.sh are re-entrant.
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

bash "$HERE/install.sh" >/dev/null || exit 1
systemctl stop 'qwq-spike-plugin@alpha.service' 'qwq-spike-plugin@beta.service' \
  'qwq-spike-plugin@alpha.socket' 'qwq-spike-plugin@beta.socket' 2>/dev/null
systemctl restart qwq-spike-agent.service
for _ in $(seq 1 150); do
  [[ -s /run/qwq-spike/state/alpha.json ]] && break
  sleep 0.2
done
sleep 2
unit=qwq-spike-plugin@alpha.service
pid=$(systemctl show -p MainPID --value "$unit")
cg=$(systemctl show -p ControlGroup --value "$unit")
echo "=== $unit main_pid=$pid cgroup=$cg ==="
echo '--- cgroup memory.stat ---'
grep -E '^(anon|file|kernel|kernel_stack|pagetables|slab|sock|shmem|file_mapped|inactive_file|active_file) ' "/sys/fs/cgroup$cg/memory.stat"
echo '--- cgroup memory.current / peak / max / swap ---'
for f in memory.current memory.peak memory.max memory.swap.current; do
  printf '%s=%s\n' "$f" "$(cat "/sys/fs/cgroup$cg/$f")"
done
echo '--- process status ---'
grep -E 'VmRSS|VmHWM|VmSize|Threads|RssAnon|RssFile' "/proc/$pid/status"
echo '--- unit properties ---'
systemctl show -p DynamicUser -p SupplementaryGroups -p UMask -p Environment -p LoadCredential \
  -p MemoryMax -p MemoryHigh -p OOMScoreAdjust -p TasksMax -p LimitNOFILE "$unit"
echo '--- agent ---'
apid=$(systemctl show -p MainPID --value qwq-spike-agent.service)
acg=$(systemctl show -p ControlGroup --value qwq-spike-agent.service)
grep -E '^(anon|file) ' "/sys/fs/cgroup$acg/memory.stat"
printf 'agent memory.current=%s\n' "$(cat "/sys/fs/cgroup$acg/memory.current")"
grep -E 'VmRSS|VmHWM' "/proc/$apid/status"

bash "$HERE/uninstall.sh"
