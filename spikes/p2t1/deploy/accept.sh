#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Drive the P2-T1 acceptance checks on the test machine and write the raw
# evidence to $ROOT/evidence.txt. Run as root.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
EVID=$ROOT/evidence.txt
: >"$EVID"
PASS=0
FAIL=0

say() { echo "$*" | tee -a "$EVID"; }
hdr() { echo | tee -a "$EVID"; echo "===== $* =====" | tee -a "$EVID"; }
run() {
  echo "\$ $*" | tee -a "$EVID"
  "$@" 2>&1 | tee -a "$EVID"
  return "${PIPESTATUS[0]}"
}
ok() { PASS=$((PASS + 1)); echo "PASS: $*" | tee -a "$EVID"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $*" | tee -a "$EVID"; }
check() { # check <description> <command...>
  local desc=$1
  shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}
st() { jq -r "$2" "/run/qwq-spike/state/$1.json" 2>/dev/null; }
wait_attach() { # wait_attach <old timestamp> <plugin...>
  local old=$1
  shift
  for _ in $(seq 1 150); do
    local done=1
    for id in "$@"; do
      local now
      now=$(st "$id" '.attached_at // ""')
      [[ -n $now && $now != "$old" ]] || done=0
    done
    [[ $done == 1 ]] && return 0
    sleep 0.2
  done
  return 1
}
wait_probes() {
  for _ in $(seq 1 100); do
    local done=1
    for id in "$@"; do
      [[ $(st "$id" '.probes | length') -ge 3 ]] || done=0
    done
    [[ $done == 1 ]] && return 0
    sleep 0.2
  done
  return 1
}

# ---------------------------------------------------------------------------
hdr "S0 install and first start (cold start)"
run bash "$HERE/install.sh"
systemctl stop 'qwq-spike-plugin@alpha.service' 'qwq-spike-plugin@beta.service' \
  'qwq-spike-plugin@alpha.socket' 'qwq-spike-plugin@beta.socket' 2>/dev/null
systemctl reset-failed 'qwq-spike-plugin@alpha.service' 'qwq-spike-plugin@beta.service' 2>/dev/null
run systemctl restart qwq-spike-agent.service
sleep 1
wait_attach "" alpha beta || say "agent did not attach in time"
wait_probes alpha beta || true
run systemctl --no-pager --full status qwq-spike-agent.service
run journalctl -u qwq-spike-agent -n 40 --no-pager
run journalctl -u 'qwq-spike-plugin@alpha' -n 20 --no-pager

# ---------------------------------------------------------------------------
hdr "S1 acceptance 1: a plugin cannot reach another plugin's sockets"
for id in alpha beta; do
  say "--- plugin $id probes (executed inside its own sandbox) ---"
  jq -r '.probes[]? | [.name, .path, ("want_dial=" + (.want_dial | tostring)),
         ("dial_ok=" + (.dial_ok | tostring)), ("pass=" + (.pass | tostring)),
         (.dial_err // ""), (.stat_err // "")] | @tsv' \
    "/run/qwq-spike/state/$id.json" 2>/dev/null | tee -a "$EVID"
done
for id in alpha beta; do
  n=$(st "$id" '[.probes[]? | select(.pass == true)] | length')
  t=$(st "$id" '.probes | length')
  [[ ${n:-0} -ge 3 && $n == "$t" ]] && ok "all $t probes of $id match expectation" || bad "probe mismatch for $id ($n/$t)"
  own=$(st "$id" '.probes[]? | select(.name == "own-host-bind-mount") | .dial_ok')
  [[ $own == true ]] && ok "$id can connect its own host socket through the bind mount" || bad "$id cannot reach its own host socket"
  for other in alpha beta; do
    [[ $other == "$id" ]] && continue
    v=$(st "$id" ".probes[]? | select(.name == \"other-plugin-socket:$other\") | .dial_ok")
    [[ $v == false ]] && ok "$id cannot connect plugin socket of $other" || bad "$id could connect plugin socket of $other"
    v=$(st "$id" ".probes[]? | select(.name == \"other-host-socket:$other\") | .dial_ok")
    [[ $v == false ]] && ok "$id cannot connect host socket of $other" || bad "$id could connect host socket of $other"
  done
done

# ---------------------------------------------------------------------------
hdr "S2 acceptance 2: bidirectional SO_PEERCRED"
for id in alpha beta; do
  say "--- agent-side state for $id ---"
  jq '{plugin_id, unit, main_pid, plugin_uid, plugin_cgroup, plugin_start_time, generation,
       plugin_socket_peer_is_systemd, peer_pid, peer_uid, peer_pidfd, main_pid_match,
       host_verified, host_peer_pid, host_peer_uid, host_peer_unit, host_main_pid_match, host_generation,
       unit_match, reattach_pid, go_plugin_peer_pid, go_plugin_peer_uid, go_plugin_peer_unit,
       agent_peer_verified, agent_peer_unit_visible,
       echo: {peer_pid: .echo.peer_pid, peer_uid: .echo.peer_uid, peer_unit: .echo.peer_unit,
              peer_unit_err: .echo.peer_unit_err, expected_agent_uid: .echo.expected_agent_uid,
              peer_pidfd: .echo.peer_pidfd_supported, host_report_ok: .echo.host_report_ok,
              host_generation: .echo.host_generation, credential_sha256: .echo.credential_sha256}}' \
    "/run/qwq-spike/state/$id.json" | tee -a "$EVID"
  say "--- plugin-side host report state for $id ---"
  jq '{plugin_id, accepted, reason, count, agent_pid, peer_pid, peer_uid, peer_unit, peer_pidfd, unit, main_pid, generation}' \
    "/run/qwq-spike/state/$id.host.json" | tee -a "$EVID"
  [[ $(st "$id" '.host_main_pid_match') == true ]] && ok "$id host-channel peer pid equals systemd MainPID" || bad "$id host-channel pid != MainPID"
  [[ $(st "$id" '.host_peer_unit') == "$(st "$id" '.unit')" ]] && ok "$id host-channel peer cgroup unit matches" || bad "$id host-channel unit mismatch"
  [[ $(st "$id" '.host_verified') == true ]] && ok "$id plugin identity attested by the kernel on the host channel" || bad "$id host channel not verified"
  [[ $(st "$id" '.plugin_socket_peer_is_systemd') == true ]] && ok "$id plugin-socket peer is systemd (socket activation), documented" || bad "$id unexpected plugin-socket peer"
  [[ $(st "$id" '.peer_pidfd') == true ]] && ok "$id SO_PEERPIDFD available on the plugin socket" || bad "$id no SO_PEERPIDFD"
  [[ $(st "$id" '.agent_peer_verified') == true ]] && ok "$id verified the agent uid over its own connection" || bad "$id agent uid check failed"
  [[ $(jq -r '.accepted' "/run/qwq-spike/state/$id.host.json") == true ]] && ok "$id host report accepted by the agent" || bad "$id host report rejected"
  [[ $(jq -r '.generation' "/run/qwq-spike/state/$id.host.json") == $(st "$id" '.generation') ]] &&
    ok "$id host generation equals agent generation" || bad "$id generation mismatch"
done
say '--- socket ownership and modes ---'
say "plugin-side view of the agent: peer_unit='$(st alpha '.echo.peer_unit')' \
visible=$(st alpha '.agent_peer_unit_visible') err='$(st alpha '.echo.peer_unit_err')' \
(ProtectProc=invisible hides other users' /proc entries from the plugin)"ls -ld /run/qwq-spike/plugin/alpha /run/qwq-spike/host/alpha
ls -l /run/qwq-spike/plugin/alpha/plugin.sock /run/qwq-spike/host/alpha/host.sock
run id qwq-spike-agent
run systemctl show -p MainPID -p ControlGroup -p DynamicUser qwq-spike-plugin@alpha.service

# ---------------------------------------------------------------------------
hdr "S3 polkit: the agent may only control qwq-spike-plugin@*"
say '$ runuser -u qwq-spike-agent -- systemctl start qwq-spike-agent.service'
runuser -u qwq-spike-agent -- systemctl start qwq-spike-agent.service 2>&1 | tee -a "$EVID"
[[ ${PIPESTATUS[0]} -ne 0 ]] && ok "agent cannot start its own (non plugin) unit" || bad "agent started a non plugin unit"
say '$ runuser -u qwq-spike-agent -- systemctl stop ssh.service'
runuser -u qwq-spike-agent -- systemctl stop ssh.service 2>&1 | tee -a "$EVID"
[[ ${PIPESTATUS[0]} -ne 0 ]] && ok "agent cannot stop ssh.service" || bad "agent stopped ssh.service"

say '$ runuser -u qwq-spike-agent -- systemctl start qwq-spike-plugin@beta.service'
runuser -u qwq-spike-agent -- systemctl start qwq-spike-plugin@beta.service 2>&1 | tee -a "$EVID"
[[ ${PIPESTATUS[0]} -eq 0 ]] && ok "agent may start a plugin service" || bad "agent denied for plugin service start"
sleep 1
say '--- journal: a direct service start inherits fd 3 from the active socket unit ---'
journalctl -u 'qwq-spike-plugin@beta' -n 3 --no-pager | tee -a "$EVID"
journalctl -u 'qwq-spike-plugin@beta' --since -20s --no-pager | grep -q 'serving on inherited listener' &&
  ok "direct service start got LISTEN_FDS from the socket unit" || bad "direct service start did not get the socket"

say '$ runuser -u qwq-spike-agent -- systemctl stop qwq-spike-plugin@beta.service'
runuser -u qwq-spike-agent -- systemctl stop qwq-spike-plugin@beta.service 2>&1 | tee -a "$EVID"
[[ ${PIPESTATUS[0]} -eq 0 ]] && ok "agent may stop a plugin service" || bad "agent denied for plugin service stop"

say '--- socket unit restart while its service runs is refused (expected) ---'
runuser -u qwq-spike-agent -- systemctl start qwq-spike-plugin@beta.service 2>&1 | tee -a "$EVID"
runuser -u qwq-spike-agent -- systemctl stop qwq-spike-plugin@beta.socket 2>&1 | tee -a "$EVID"
runuser -u qwq-spike-agent -- systemctl start qwq-spike-plugin@beta.socket 2>&1 | tee -a "$EVID"
[[ ${PIPESTATUS[0]} -ne 0 ]] && ok "socket unit cannot restart while the service runs" || bad "socket unit restarted unexpectedly"
say '--- recovery order: stop service, stop/start socket, start service ---'
systemctl stop qwq-spike-plugin@beta.service 2>/dev/null
systemctl start qwq-spike-plugin@beta.socket 2>&1 | tee -a "$EVID"
runuser -u qwq-spike-agent -- systemctl start qwq-spike-plugin@beta.service 2>&1 | tee -a "$EVID"
[[ ${PIPESTATUS[0]} -eq 0 ]] && ok "agent restarts the plugin after the socket is back" || bad "recovery start failed"
sleep 1
journalctl -u 'qwq-spike-plugin@beta' -n 4 --no-pager | tee -a "$EVID"

# ---------------------------------------------------------------------------
hdr "S4 credentials: LoadCredential instead of Environment="
run systemctl show -p Environment -p LoadCredential qwq-spike-plugin@alpha.service
token=$(cat /run/qwq-spike/creds/alpha.token)
envshow=$(systemctl show -p Environment --value qwq-spike-plugin@alpha.service)
if [[ $envshow == *"$token"* ]]; then bad "token visible in Environment"; else ok "token is not in Environment="; fi
sha_env=$(printf %s "$token" | sha256sum | cut -c1-16)
sha_state=$(st alpha '.echo.credential_sha256')
say "token sha256[0:16]=$sha_env plugin-reported=$sha_state len=${#token}"
[[ $sha_env == "$sha_state" ]] && ok "plugin read the same token from the credential store" || bad "credential mismatch"
run ls -l /run/qwq-spike/creds
pid=$(systemctl show -p MainPID --value qwq-spike-plugin@alpha.service)
say "--- plugin process environment variable names ---"
tr '\0' '\n' <"/proc/$pid/environ" | cut -d= -f1 | sort | tee -a "$EVID"
if tr '\0' '\n' <"/proc/$pid/environ" | grep -qF -- "$token"; then
  bad "token visible in /proc/<pid>/environ"
else
  ok "token not present in /proc/<pid>/environ"
fi

# ---------------------------------------------------------------------------
hdr "S5 acceptance 5: systemd-analyze security"
systemd-analyze security qwq-spike-plugin@alpha.service >"$ROOT/security.txt" 2>&1
run tail -8 "$ROOT/security.txt"

# ---------------------------------------------------------------------------
hdr "S6 resource use"
pid=$(systemctl show -p MainPID --value qwq-spike-plugin@alpha.service)
apid=$(systemctl show -p MainPID --value qwq-spike-agent.service)
pcg=$(systemctl show -p ControlGroup --value qwq-spike-plugin@alpha.service)
acg=$(systemctl show -p ControlGroup --value qwq-spike-agent.service)
say "plugin MainPID=$pid cgroup=$pcg"
say "agent  MainPID=$apid cgroup=$acg"
run cat "/sys/fs/cgroup$pcg/memory.current"
run cat "/sys/fs/cgroup$pcg/memory.peak"
run cat "/sys/fs/cgroup$pcg/memory.max"
run cat "/sys/fs/cgroup$pcg/pids.current"
run grep -E 'VmRSS|VmHWM|Threads' /proc/"$pid"/status
run cat "/sys/fs/cgroup$acg/memory.current"
run grep -E 'VmRSS|VmHWM|Threads' /proc/"$apid"/status
run systemctl show -p MemoryMax -p MemoryHigh -p TasksMax -p OOMScoreAdjust qwq-spike-plugin@alpha.service

# ---------------------------------------------------------------------------
hdr "S7 acceptance 3: agent restart reattaches to the running plugin"
gen_before=$(st alpha '.generation')
start_before=$(st alpha '.plugin_start_time')
say "before: generation=$gen_before main_pid=$(st alpha '.main_pid') starttime=$start_before"
run systemctl restart qwq-spike-agent.service
wait_attach "$(st alpha '.attached_at')" alpha beta || say "reattach wait timed out"
wait_probes alpha beta || true
gen_after=$(st alpha '.generation')
say "after:  generation=$gen_after main_pid=$(st alpha '.main_pid') starttime=$(st alpha '.plugin_start_time') agent_pid=$(st alpha '.agent_pid')"
[[ $gen_before == "$gen_after" && -n $gen_before ]] && ok "generation unchanged across agent restart ($gen_after)" || bad "generation changed ($gen_before -> $gen_after)"
[[ $(st alpha '.plugin_start_time') == "$start_before" ]] && ok "plugin process start time unchanged (no restart)" || bad "plugin restarted"
[[ $(st alpha '.host_main_pid_match') == true && $(st alpha '.generation') == "$gen_after" ]] &&
  ok "new agent re-derived the same identity and generation" || bad "reattach identity mismatch"
for _ in $(seq 1 100); do
  [[ $(jq -r '.agent_pid' /run/qwq-spike/state/alpha.host.json 2>/dev/null) == "$(st alpha '.agent_pid')" ]] && break
  sleep 0.2
done
say "host report after restart:"
jq '{count, agent_pid, peer_pid, peer_unit, accepted, generation}' /run/qwq-spike/state/alpha.host.json | tee -a "$EVID"
[[ $(jq -r '.agent_pid' /run/qwq-spike/state/alpha.host.json) == "$(st alpha '.agent_pid')" ]] &&
  ok "plugin re-reported to the new agent process" || bad "plugin did not report to the new agent"
run journalctl -u 'qwq-spike-plugin@alpha' -n 12 --no-pager

# ---------------------------------------------------------------------------
hdr "S8 acceptance 4: systemctl kill leaves no process in the cgroup"
pid=$(systemctl show -p MainPID --value qwq-spike-plugin@alpha.service)
cg=$(systemctl show -p ControlGroup --value qwq-spike-plugin@alpha.service)
run systemctl stop qwq-spike-plugin@alpha.socket
run systemctl kill --kill-whom=main -s SIGKILL qwq-spike-plugin@alpha.service
sleep 1
run systemctl show -p MainPID -p ActiveState -p SubState qwq-spike-plugin@alpha.service
run cat "/sys/fs/cgroup$cg/cgroup.procs"
run pgrep -a -f '/opt/qwq-spike/spike-plugin'
[[ $(systemctl show -p MainPID --value qwq-spike-plugin@alpha.service) == 0 ]] &&
  ok "MainPID is 0 after kill" || bad "MainPID not cleared"
left=$(cat "/sys/fs/cgroup$cg/cgroup.procs" 2>/dev/null)
[[ -z $left ]] && ok "plugin cgroup has no processes left" || bad "cgroup still has pids: $left"
pgrep -f '/opt/qwq-spike/spike-plugin -id alpha' >/dev/null && bad "plugin process survived" || ok "no plugin process survived"
run systemctl show -p MainPID -p ActiveState qwq-spike-agent.service

# ---------------------------------------------------------------------------
hdr "S9 uninstall and verification"
run bash "$HERE/uninstall.sh"
run systemctl list-units 'qwq-spike*' --all --no-pager
run pgrep -a -f '/opt/qwq-spike/spike-'

echo | tee -a "$EVID"
echo "SUMMARY: PASS=$PASS FAIL=$FAIL" | tee -a "$EVID"
