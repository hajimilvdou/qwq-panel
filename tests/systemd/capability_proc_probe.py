#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

"""使用自有非 dumpable 监听进程核验能力助手的真实 /proc 沙箱权限。"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import uuid


# ======================== 只读取冻结单元；全部进程与单元都由本次探针创建 ========================

UNIT = Path("deployments/systemd/qwq-capability.service")
PREFIX = "qwq-proc-probe-"
TOOLS = {}
LISTENER = r'''
import ctypes, json, os, socket, sys
os.setgroups([])
os.setgid(1)
os.setuid(1)
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(4, 0, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "PR_SET_DUMPABLE failed")
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    print(json.dumps({"pid": os.getpid(), "port": listener.getsockname()[1]}), flush=True)
    sys.stdin.buffer.read(1)
'''
INSPECT = r'''
import json, os, re, subprocess, sys
pid, port = int(sys.argv[1]), int(sys.argv[2])
result = subprocess.run([sys.argv[3], "-H", "-ltnp", "sport = :" + str(port)],
                        capture_output=True, text=True, timeout=10)
if result.returncode:
    raise RuntimeError("controlled socket inspection failed")
visible = re.search(r"\bpid=" + str(pid) + r"\b", result.stdout) is not None
print(json.dumps({"visible": visible, "euid": os.geteuid()}), flush=True)
'''


def read_properties(expected_sha):
    raw = UNIT.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise RuntimeError("frozen capability unit checksum mismatch")
    properties = {}
    section = ""
    required = ("ProtectProc", "ProcSubset", "CapabilityBoundingSet", "NoNewPrivileges", "ProtectHome", "ProtectSystem")
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line
        elif section == "[Service]" and "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            if key in required:
                if key in properties:
                    raise RuntimeError("duplicate inspected unit property")
                properties[key] = value
    if set(properties) != set(required) or not re.fullmatch(r"CAP_[A-Z_]+(?: CAP_[A-Z_]+)*", properties["CapabilityBoundingSet"]):
        raise RuntimeError("capability unit properties are not usable")
    return properties


def start_listener():
    child = subprocess.Popen([TOOLS["python3"], "-c", LISTENER], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             env={"PATH": "/usr/bin:/bin"})
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            if not ready.select(10):
                raise RuntimeError("controlled listener did not become ready")
        info = json.loads(child.stdout.readline())
        if info.get("pid") != child.pid or not isinstance(info.get("port"), int) or not 0 < info["port"] <= 65535:
            raise RuntimeError("controlled listener identity is invalid")
        return child, info
    except BaseException:
        stop_listener(child)
        raise


def stop_listener(child):
    if child.stdin and not child.stdin.closed:
        child.stdin.close()
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=10)
    if child.stdout:
        child.stdout.close()
    if child.stderr:
        child.stderr.close()
    if child.returncode:
        raise RuntimeError("controlled listener did not exit normally")


def inspect(properties, listener):
    name = PREFIX + uuid.uuid4().hex + ".service"
    if not re.fullmatch(PREFIX + r"[0-9a-f]{32}\.service", name):
        raise RuntimeError("owned transient unit name rejected")
    command = [TOOLS["systemd-run"], "--quiet", "--wait", "--pipe", "--collect", "--unit=" + name]
    limits = {"MemoryMax": "48M", "TasksMax": "24", "RuntimeMaxSec": "20s", "TimeoutStopSec": "5s"}
    for key, value in dict(properties, **limits).items():
        command.extend(["--property", key + "=" + value])
    command.extend(["--", TOOLS["python3"], "-c", INSPECT, str(listener["pid"]), str(listener["port"]), TOOLS["ss"]])
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError("owned sandbox probe could not execute; exit=" + str(result.returncode) + "; " + result.stderr.strip()[:2048])
        output = json.loads(result.stdout)
        if output.get("euid") != 0 or not isinstance(output.get("visible"), bool):
            raise RuntimeError("owned sandbox probe result is invalid")
        return output["visible"]
    finally:
        # 只停止本次完整随机名称，既不修改正式单元，也不全局清除失败记录。
        subprocess.run([TOOLS["systemctl"], "stop", name], capture_output=True, timeout=10)
        state = subprocess.run([TOOLS["systemctl"], "show", name, "--property=LoadState", "--property=ActiveState"],
                               capture_output=True, text=True, timeout=10)
        if state.returncode or "LoadState=not-found" not in state.stdout:
            raise RuntimeError("owned sandbox probe unit was not collected")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit-sha", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{64}", args.unit_sha) or os.geteuid() != 0:
        raise RuntimeError("an explicit unit checksum and root Linux probe are required")
    for name in ("systemd-run", "systemctl", "ss", "python3"):
        found = shutil.which(name)
        if not found:
            raise RuntimeError("required existing probe tool is unavailable")
        tool = Path(found).resolve(strict=True)
        info = tool.stat()
        if not tool.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("existing probe tool is not a trusted root executable")
        TOOLS[name] = str(tool)
    version = subprocess.run([TOOLS["systemctl"], "--version"], capture_output=True, text=True, timeout=10)
    match = re.match(r"systemd ([0-9]+)\b", version.stdout)
    if version.returncode or not match or int(match.group(1)) < 249:
        raise RuntimeError("the proc sandbox probe requires supported systemd >= 249")
    properties = read_properties(args.unit_sha)
    child, listener = start_listener()
    try:
        control = dict(properties, ProtectProc="default", CapabilityBoundingSet=properties["CapabilityBoundingSet"] + " CAP_SYS_PTRACE")
        if not inspect(control, listener):
            raise RuntimeError("positive control cannot prove listener ownership")
        visible = inspect(properties, listener)
        print("capability_proc_owner_visible=" + str(visible).lower() + "; positive_control=true", flush=True)
        if not visible:
            raise RuntimeError("configured helper sandbox hides the non-dumpable listener owner")
    finally:
        stop_listener(child)
        print("owned_proc_probe_cleanup=pass", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("capability proc probe: " + str(error), file=sys.stderr)
        sys.exit(1)
