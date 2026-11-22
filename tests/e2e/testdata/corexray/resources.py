#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""只读采样本轮 Xray 单元和显式客户端；不读 argv/environ，不修改系统计数器。"""

import argparse
import json
import os
import pathlib
import signal
import subprocess
import time


ROLES = ("driver", "server", "unit_prepare", "client_test_only")
PRODUCT_ROLES = ROLES[:-1]
PHASES = {"startup", "apply", "idle", "traffic", "update", "update_recovery", "rollback", "uninstall"}


def is_within(path, root):
    """兼容构建机 Python 3.8；调用方先规范化路径。"""
    try:
        pathlib.Path(path).relative_to(root)
        return True
    except ValueError:
        return False


def product_role(executable):
    """区分驱动、核心及单元摘要预检；未知进程不能被静默忽略。"""
    deleted_suffix = " (deleted)"
    if executable.endswith(deleted_suffix):
        executable = executable[:-len(deleted_suffix)]
    if str(pathlib.PurePosixPath(executable)) != executable:
        raise ValueError("unexpected product executable")
    if executable == "/usr/lib/systemd/systemd-executor":
        return "unit_prepare"
    for prefix, roles in (("/var/lib/qwq-plugins/core.xray/", {"plugin": "driver", "xray": "server"}),
                          ("/opt/qwq/releases/", {"qwq": "unit_prepare"})):
        if not executable.startswith(prefix):
            continue
        parts = executable[len(prefix):].split("/")
        if len(parts) == 3 and parts[0] not in ("", ".", "..") and parts[1] == "bin" and parts[2] in roles:
            return roles[parts[2]]
    raise ValueError("unexpected product executable: " + pathlib.PurePosixPath(executable).name[:80])


def process_sample(proc_root, pid):
    """用 starttime 识别 PID 换代；进程消失返回缺失，不伪造零值。"""
    base = pathlib.Path(proc_root) / str(pid)
    try:
        raw = (base / "stat").read_text(encoding="utf-8")
        close = raw.rfind(")")
        fields = raw[close + 1:].split()
        if close < 0 or len(fields) < 22:
            raise ValueError("invalid proc stat")
        status = {}
        for line in (base / "status").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition(":")
            if separator:
                status[key] = value.strip().split()
        if fields[0] == "Z":
            return None
        return {"pid": pid, "start_ticks": int(fields[19]), "cpu_ticks": int(fields[11]) + int(fields[12]),
                "rss_bytes": int(status["VmRSS"][0]) * 1024, "threads": int(status["Threads"][0]),
                "fds": len(list((base / "fd").iterdir()))}
    except FileNotFoundError:
        return None


def mem_available(proc_root):
    fields = {}
    for line in (pathlib.Path(proc_root) / "meminfo").read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition(":")
        fields[key] = value.strip().split()
    return {name: int(fields[name][0]) * 1024 for name in ("MemAvailable", "MemTotal")}


def key_values(path):
    output = {}
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        key, value = line.split()
        output[key] = int(value)
    return output


class Peaks:
    """保存观测峰值与同进程 CPU 差值，角色和阶段独立；不跨 PID 换代减法。"""

    def __init__(self, hz):
        if hz <= 0:
            raise ValueError("invalid clock ticks")
        self.hz = hz
        self.rows = {}
        self.previous = {}

    def add(self, phase, role, samples):
        if phase not in PHASES or role not in ROLES:
            raise ValueError("unknown resource phase/role")
        samples = [sample for sample in samples if sample is not None]
        if not samples:
            return
        key = phase + "/" + role
        row = self.rows.setdefault(key, {"observations": 0, "rss_observed_peak_bytes": 0,
                                       "fds_observed_peak": 0, "threads_observed_peak": 0,
                                       "pids_observed_peak": 0, "cpu_observed_seconds": 0.0})
        row["observations"] += 1
        for field, source in (("rss_observed_peak_bytes", "rss_bytes"), ("fds_observed_peak", "fds"),
                              ("threads_observed_peak", "threads")):
            row[field] = max(row[field], sum(sample[source] for sample in samples))
        row["pids_observed_peak"] = max(row["pids_observed_peak"], len(samples))
        for sample in samples:
            identity = (role, sample["pid"], sample["start_ticks"])
            previous = self.previous.get(identity)
            if previous is not None:
                if sample["cpu_ticks"] < previous:
                    raise ValueError("same process cpu counter decreased")
                row["cpu_observed_seconds"] += (sample["cpu_ticks"] - previous) / self.hz
            self.previous[identity] = sample["cpu_ticks"]


class KernelTotals:
    """cgroup 重新创建后独立累计，不能用最大值冒充跨代 CPU/OOM 总量。"""

    def __init__(self):
        self.previous = {}
        self.cpu_usage_usec = 0
        self.oom_kill = 0

    def add(self, identity, cpu, oom):
        previous_cpu, previous_oom = self.previous.get(identity, (0, 0))
        if cpu < previous_cpu or oom < previous_oom:
            raise ValueError("same cgroup kernel counter decreased")
        self.cpu_usage_usec += cpu - previous_cpu
        self.oom_kill += oom - previous_oom
        self.previous[identity] = (cpu, oom)


def marker(path):
    if path is None:
        return "idle", []
    try:
        raw = pathlib.Path(path).read_bytes()
    except FileNotFoundError:
        return "startup", []
    if len(raw) > 2048:
        raise ValueError("resource marker too large")
    data = json.loads(raw)
    phase = data["phase"]
    clients = data.get("client_pids", [])
    if phase not in PHASES or not isinstance(clients, list) or len(clients) > 8 or any(type(pid) is not int or pid <= 0 for pid in clients):
        raise ValueError("invalid resource marker")
    return phase, clients


def collect(duration, interval, marker_path, stopped=lambda: False):
    if os.name != "posix" or not pathlib.Path("/proc/self/stat").exists():
        raise ValueError("resource sampling requires the Linux test host")
    peaks = Peaks(os.sysconf("SC_CLK_TCK"))
    start = time.monotonic()
    min_available = None
    kernel_memory_peak = 0
    observations = 0
    errors = 0
    kernel = KernelTotals()
    memory = mem_available("/proc")
    while time.monotonic() - start < duration and not stopped():
        phase, clients = marker(marker_path)
        memory = mem_available("/proc")
        min_available = memory["MemAvailable"] if min_available is None else min(min_available, memory["MemAvailable"])
        command = subprocess.run(["systemctl", "show", "qwq-plugin@core.xray.service", "--value", "-p", "ControlGroup"],
                                 timeout=2, check=True, capture_output=True, text=True)
        group = command.stdout.strip()
        product = {role: [] for role in PRODUCT_ROLES}
        if group:
            cgroup_root = pathlib.Path("/sys/fs/cgroup").resolve()
            directory = (cgroup_root / group.lstrip("/")).resolve()
            if not is_within(directory, cgroup_root) or not directory.name.startswith("qwq-plugin@core.xray.service"):
                raise ValueError("untrusted product cgroup")
            try:
                for text in (directory / "cgroup.procs").read_text(encoding="utf-8").split():
                    pid = int(text)
                    try:
                        executable = os.readlink("/proc/" + text + "/exe")
                    except FileNotFoundError:
                        continue
                    role = product_role(executable)
                    sample = process_sample("/proc", pid)
                    if sample is not None:
                        product[role].append(sample)
                kernel_memory_peak = max(kernel_memory_peak, int((directory / "memory.peak").read_text(encoding="utf-8")))
                identity = directory.stat()
                identity = (identity.st_dev, identity.st_ino)
                current_cpu = key_values(directory / "cpu.stat").get("usage_usec", 0)
                current_oom = key_values(directory / "memory.events").get("oom_kill", 0)
                kernel.add(identity, current_cpu, current_oom)
            except FileNotFoundError:
                errors += 1  # 单元换代已移除 cgroup；保留采样缺口，不制造零值。
        for role in PRODUCT_ROLES:
            peaks.add(phase, role, product[role])
        peaks.add(phase, "client_test_only", [process_sample("/proc", pid) for pid in clients])
        observations += 1
        time.sleep(interval)
    return {"schema_version": "1", "duration_seconds": time.monotonic() - start,
            "observations": observations, "cgroup_gaps": errors, "clock_ticks_per_second": peaks.hz,
            "host_memory_total_bytes": memory["MemTotal"], "host_memory_available_min_bytes": min_available,
            "test_process_available_cpus": len(os.sched_getaffinity(0)),
            "product_cgroup_memory_peak_bytes": kernel_memory_peak, "product_cgroup_cpu_usage_usec": kernel.cpu_usage_usec,
            "product_cgroup_oom_kill": kernel.oom_kill, "phases": peaks.rows,
            "limits": "RSS/FD/threads are sampled peaks; short processes and between-sample peaks may be missed. Client rows are test-only; unit_prepare is the host entrypoint verifier/systemd executor, separate from the persistent driver/core."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, default=300)
    parser.add_argument("--interval", type=float, default=0.1)
    parser.add_argument("--marker")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not 1 <= args.duration <= 900 or not 0.05 <= args.interval <= 1:
        parser.error("duration/interval exceeds the bounded test budget")
    output = pathlib.Path(args.output).resolve()
    if not is_within(output, pathlib.Path.cwd().resolve()):
        parser.error("output must remain inside the dedicated test workspace")
    if args.marker and not is_within(pathlib.Path(args.marker).resolve(), pathlib.Path.cwd().resolve()):
        parser.error("marker must remain inside the dedicated test workspace")
    stopping = [False]
    def request_stop(_number, _frame):
        stopping[0] = True
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        result = collect(args.duration, args.interval, args.marker, lambda: stopping[0])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        detail = type(error).__name__
        if isinstance(error, ValueError):
            detail += ": " + str(error)[:160]
        raise SystemExit("resource probe failed: " + detail)


if __name__ == "__main__":
    main()
