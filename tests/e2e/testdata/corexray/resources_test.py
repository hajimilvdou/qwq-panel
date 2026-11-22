#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""用有界 proc/cgroup 夹具验证采样语义；不表示真实 VPS 已测量。"""

import json
import pathlib
import tempfile
import unittest

import resources


class ResourceProbeTests(unittest.TestCase):
    def setUp(self):
        root = pathlib.Path(__file__).resolve().parents[4]
        parent = root / ".cache" / "core-xray" / "resource-unit"
        parent.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=parent)
        self.root = pathlib.Path(self.directory.name).resolve()
        if not resources.is_within(self.root, parent.resolve()):
            raise ValueError("fixture escaped the project workspace")

    def tearDown(self):
        self.directory.cleanup()

    def proc(self, pid, state="R"):
        base = self.root / str(pid)
        (base / "fd").mkdir(parents=True)
        (base / "fd" / "0").write_text("", encoding="utf-8")
        (base / "fd" / "1").write_text("", encoding="utf-8")
        fields = [state] + ["0"] * 21
        fields[11], fields[12], fields[19] = "12", "8", "123"
        (base / "stat").write_text(str(pid) + " (xray (worker)) " + " ".join(fields), encoding="utf-8")
        (base / "status").write_text("VmRSS:\t10 kB\nThreads:\t2\n", encoding="utf-8")
        return base

    def test_proc_comm_parentheses_and_cpu_fields(self):
        self.proc(100)
        sample = resources.process_sample(self.root, 100)
        self.assertEqual((sample["cpu_ticks"], sample["start_ticks"], sample["rss_bytes"], sample["threads"], sample["fds"]),
                         (20, 123, 10240, 2, 2))

    def test_missing_process_remains_missing(self):
        self.assertIsNone(resources.process_sample(self.root, 999))

    def test_zombie_without_rss_does_not_create_zero_sample(self):
        base = self.proc(100, "Z")
        (base / "status").write_text("State:\tZ (zombie)\n", encoding="utf-8")
        self.assertIsNone(resources.process_sample(self.root, 100))

    def test_malformed_proc_stat_is_rejected(self):
        base = self.proc(100)
        (base / "stat").write_text("100 invalid", encoding="utf-8")
        with self.assertRaises(ValueError):
            resources.process_sample(self.root, 100)

    def test_pid_reuse_does_not_subtract_previous_process(self):
        peaks = resources.Peaks(100)
        first = {"pid": 100, "start_ticks": 123, "cpu_ticks": 100, "rss_bytes": 1000, "threads": 2, "fds": 3}
        peaks.add("apply", "server", [first])
        peaks.add("apply", "server", [dict(first, cpu_ticks=150)])
        peaks.add("apply", "server", [dict(first, start_ticks=200, cpu_ticks=5)])
        self.assertEqual(peaks.rows["apply/server"]["cpu_observed_seconds"], 0.5)

    def test_client_and_product_roles_and_phases_are_separate(self):
        sample = {"pid": 100, "start_ticks": 123, "cpu_ticks": 10, "rss_bytes": 1000, "threads": 2, "fds": 3}
        peaks = resources.Peaks(100)
        peaks.add("apply", "driver", [sample])
        peaks.add("traffic", "client_test_only", [dict(sample, pid=200, rss_bytes=9000)])
        self.assertEqual(peaks.rows["apply/driver"]["rss_observed_peak_bytes"], 1000)
        self.assertEqual(peaks.rows["traffic/client_test_only"]["rss_observed_peak_bytes"], 9000)
        self.assertNotIn("traffic/server", peaks.rows)

    def test_unit_prepare_and_binary_roles_are_distinct(self):
        self.assertEqual(resources.product_role("/opt/qwq/releases/e2e-xray/bin/qwq"), "unit_prepare")
        self.assertEqual(resources.product_role("/usr/lib/systemd/systemd-executor"), "unit_prepare")
        self.assertEqual(resources.product_role("/var/lib/qwq-plugins/core.xray/0.1.1/bin/plugin"), "driver")
        self.assertEqual(resources.product_role("/var/lib/qwq-plugins/core.xray/0.1.1/bin/xray (deleted)"), "server")
        for path in ("/usr/bin/sleep", "/var/lib/qwq-plugins/other/0.1.1/bin/plugin",
                     "/opt/qwq/releases/e2e-xray/bin/unexpected", "/var/lib/qwq-plugins/core.xray/../bin/plugin"):
            with self.assertRaises(ValueError):
                resources.product_role(path)

    def test_containment_preserves_python_38_boundary(self):
        self.assertTrue(resources.is_within(self.root / "out", self.root))
        self.assertTrue(resources.is_within(self.root, self.root))
        self.assertFalse(resources.is_within(self.root.parent / "outside", self.root))

    def test_cgroup_generations_sum_cpu_and_oom(self):
        totals = resources.KernelTotals()
        totals.add((1, 100), 10, 0)
        totals.add((1, 100), 20, 1)
        totals.add((1, 200), 5, 1)
        self.assertEqual((totals.cpu_usage_usec, totals.oom_kill), (25, 2))
        with self.assertRaises(ValueError):
            totals.add((1, 200), 3, 1)

    def test_boolean_pid_and_unbounded_marker_are_rejected(self):
        path = self.root / "marker.json"
        path.write_text(json.dumps({"phase": "traffic", "client_pids": [True]}), encoding="utf-8")
        with self.assertRaises(ValueError):
            resources.marker(path)
        path.write_text("x" * 2049, encoding="utf-8")
        with self.assertRaises(ValueError):
            resources.marker(path)


if __name__ == "__main__":
    unittest.main()
