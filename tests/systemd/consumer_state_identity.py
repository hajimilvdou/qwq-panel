#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

"""在自有 DynamicUser 单元中验证 StateDirectory 的宿主属主与 0600 读取。"""

import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import uuid


# ======================== 固定随机自有资源；内层只读本次无秘密哨兵 ========================

PREFIX = "qwq-consumer-state-probe-"
FILES = ("inner-sentinel", "root-unreadable", "host-inherited", "host-inherited.tmp")
INNER = r'''
import json, os, stat, sys, time
from pathlib import Path
state = Path(os.environ["STATE_DIRECTORY"])
if str(state) != "/var/lib/" + sys.argv[1] or os.geteuid() == 0:
    raise RuntimeError("controlled dynamic state identity differs")
with open(state / "inner-sentinel", "xb") as output:
    output.write(b"owned-inner")
os.chmod(state / "inner-sentinel", 0o600)
print(json.dumps({"phase":"ready", "uid":os.geteuid(), "gid":os.getegid(),
                  "state_uid":state.stat().st_uid, "sentinel_uid":(state / "inner-sentinel").stat().st_uid}), flush=True)
deadline = time.monotonic() + 15
while not (state / "host-inherited").exists():
    if time.monotonic() >= deadline:
        raise RuntimeError("host-owned publication did not arrive")
    time.sleep(0.02)
if (state / "host-inherited").read_bytes() != b"owned-host":
    raise RuntimeError("host material sentinel differs")
try:
    (state / "root-unreadable").read_bytes()
except PermissionError:
    blocked = True
else:
    blocked = False
print(json.dumps({"phase":"result", "inherited_readable":True, "root_blocked":blocked,
                  "file_uid":(state / "host-inherited").stat().st_uid,
                  "file_mode":stat.S_IMODE((state / "host-inherited").stat().st_mode)}), flush=True)
if not blocked:
    raise RuntimeError("root-owned negative sentinel was readable")
'''


def command(arguments):
    return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=10)


def state_of(tools, unit):
    result = command([tools["systemctl"], "show", unit, "--property=LoadState", "--property=ActiveState", "--property=Description"])
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def frame(stream):
    with selectors.DefaultSelector() as ready:
        ready.register(stream, selectors.EVENT_READ)
        if not ready.select(10):
            raise RuntimeError("controlled unit output deadline exceeded")
    raw = stream.readline(8193)
    if not raw.endswith("\n") or len(raw) > 8192:
        raise RuntimeError("controlled unit frame is missing or unbounded")
    return json.loads(raw)


def private_link(public, private):
    target = os.readlink(public)
    if not os.path.isabs(target):
        target = os.path.join(str(public.parent), target)
    return os.path.normpath(target) == str(private)


def main():
    if os.geteuid() != 0 or sys.platform != "linux":
        raise RuntimeError("native Linux root verification is required")
    tools = {}
    for name in ("systemctl", "systemd-run", "python3"):
        executable = Path(shutil.which(name) or "").resolve(strict=True)
        info = executable.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("trusted existing tool is unavailable")
        tools[name] = str(executable)
    token = uuid.uuid4().hex
    name = PREFIX + token
    unit = name + ".service"
    description = "owned-consumer-state:" + token
    if not re.fullmatch(PREFIX + "[0-9a-f]{32}", name):
        raise RuntimeError("owned state name rejected")
    public, private = Path("/var/lib") / name, Path("/var/lib/private") / name
    if os.path.lexists(public) or os.path.lexists(private):
        raise RuntimeError("owned state paths already exist")
    print("native_owned_state=" + json.dumps({"unit":unit, "public":str(public), "private":str(private)}), flush=True)
    client = None
    state_fd = None
    primary = None
    cleanup_errors = []
    unit_collected = False
    client_collected = True
    try:
        arguments = [tools["systemd-run"], "--quiet", "--wait", "--pipe", "--collect", "--unit=" + unit]
        properties = {"Description":description, "DynamicUser":"yes", "StateDirectory":name, "StateDirectoryMode":"0700",
                      "MemoryMax":"32M", "TasksMax":"8", "RuntimeMaxSec":"25s", "TimeoutStopSec":"5s",
                      "NoNewPrivileges":"yes", "PrivateNetwork":"yes", "ProtectHome":"yes", "UMask":"0077"}
        for key, value in properties.items():
            arguments.extend(["--property", key + "=" + value])
        arguments.extend(["--", tools["python3"], "-c", INNER, name])
        client = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                  env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C"})
        client_collected = False
        ready = frame(client.stdout)
        if ready.get("phase") != "ready" or not isinstance(ready.get("uid"), int) or ready["uid"] <= 0 or ready.get("state_uid") != ready["uid"]:
            raise RuntimeError("actual dynamic identity did not match its state directory")
        if state_of(tools, unit).get("Description") != description:
            raise RuntimeError("owned active unit identity differs")
        location = public
        if public.is_symlink():
            if not private_link(public, private):
                raise RuntimeError("systemd state link points outside the owned private path")
            location = private
        state_fd = os.open(location, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        backing = os.fstat(state_fd)
        if stat.S_IMODE(backing.st_mode) != 0o700:
            raise RuntimeError("actual state directory mode differs")
        for leaf, content, inherit in (("root-unreadable", b"owned-root", False), ("host-inherited", b"owned-host", True)):
            destination = leaf + ".tmp" if inherit else leaf
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=state_fd)
            try:
                if os.write(fd, content) != len(content):
                    raise RuntimeError("controlled sentinel write was incomplete")
                if inherit:
                    os.fchown(fd, backing.st_uid, backing.st_gid)
                os.fsync(fd)
            finally:
                os.close(fd)
            if inherit:
                os.rename(destination, leaf, src_dir_fd=state_fd, dst_dir_fd=state_fd)
                os.fsync(state_fd)
        outcome = frame(client.stdout)
        if outcome.get("phase") != "result" or outcome.get("inherited_readable") is not True or outcome.get("root_blocked") is not True or outcome.get("file_mode") != 0o600 or outcome.get("file_uid") != ready["uid"]:
            raise RuntimeError("actual namespace read did not prove inherited 0600 ownership")
        remaining, errors = client.communicate(timeout=10)
        client_collected = True
        if client.returncode != 0 or remaining.strip():
            raise RuntimeError("controlled dynamic unit did not exit cleanly")
        print(json.dumps({"state_identity":"pass", "dynamic_uid":ready["uid"], "backing_uid":backing.st_uid,
                          "backing_gid":backing.st_gid, "mapped":backing.st_uid != ready["uid"], "read":outcome}), flush=True)
    except BaseException as error:
        primary = error
    finally:
        try:
            state = state_of(tools, unit)
            if state.get("LoadState") != "not-found":
                if state.get("Description") != description:
                    raise RuntimeError("refusing to stop an unowned transient unit")
                command([tools["systemctl"], "stop", unit])
                if state_of(tools, unit).get("LoadState") != "not-found":
                    raise RuntimeError("owned unit was not collected")
            unit_collected = True
        except BaseException as error:
            cleanup_errors.append(str(error))
        if client is not None:
            try:
                client.communicate(timeout=10)
                client_collected = True
            except subprocess.TimeoutExpired:
                try:
                    client.kill()
                    client.communicate(timeout=5)
                    client_collected = True
                except BaseException as error:
                    cleanup_errors.append(str(error))
            except BaseException as error:
                cleanup_errors.append(str(error))
        if unit_collected and client_collected and state_fd is None:
            try:
                if public.is_symlink():
                    if not private_link(public, private):
                        raise RuntimeError("owned state link changed before cleanup")
                    location = private
                else:
                    location = public
                if location.exists():
                    state_fd = os.open(location, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            except BaseException as error:
                cleanup_errors.append(str(error))
        if state_fd is not None and unit_collected and client_collected:
            try:
                names = os.listdir(state_fd)
                if set(names) - set(FILES):
                    raise RuntimeError("owned state contains unexpected entries; retained")
                for leaf in names:
                    info = os.stat(leaf, dir_fd=state_fd, follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise RuntimeError("owned cleanup entry is not a single regular file")
                    os.unlink(leaf, dir_fd=state_fd)
                os.fsync(state_fd)
            except BaseException as error:
                cleanup_errors.append(str(error))
            finally:
                os.close(state_fd)
                state_fd = None
        elif state_fd is not None:
            os.close(state_fd)
            state_fd = None
        try:
            if not unit_collected or not client_collected:
                raise RuntimeError("owned processes are not confirmed stopped; state retained")
            if private.exists():
                os.rmdir(private)
            if public.is_symlink():
                if not private_link(public, private):
                    raise RuntimeError("owned public link changed before cleanup")
                public.unlink()
            elif public.exists():
                os.rmdir(public)
        except BaseException as error:
            cleanup_errors.append(str(error))
        if cleanup_errors:
            raise RuntimeError("owned cleanup failed: " + "; ".join(cleanup_errors)) from primary
    if primary is not None:
        raise primary
    print("native_owned_state_cleanup=pass", flush=True)


if __name__ == "__main__":
    def cancelled(_number, _frame):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise InterruptedError("controlled identity probe cancelled")
    signal.signal(signal.SIGTERM, cancelled)
    main()
