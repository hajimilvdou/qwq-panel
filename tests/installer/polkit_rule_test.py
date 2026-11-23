# SPDX-License-Identifier: AGPL-3.0-only

"""运行实际安装脚本的规则安装段，所有目标改到自有临时目录。"""

from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile
import unittest


def _to_bash_path(path: Path) -> str:
    raw = str(path)
    if os.name == "nt":
        m = re.match(r"^([A-Za-z]):[\\/](.*)$", raw)
        if m:
            drive = m.group(1).lower()
            rest = m.group(2).replace("\\", "/")
            return f"/{drive}/{rest}"
        return raw.replace("\\", "/")
    return raw


def _find_bash() -> str:
    if os.name == "nt":
        for candidate in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"):
            if Path(candidate).is_file():
                return candidate
    return "bash"


# =============================================================================
# 只隔离绝对目标根，保留原条件/put/安装命令，不模拟生产判定。
# =============================================================================

class PolkitRuleInstallationTest(unittest.TestCase):
    def test_rule_is_installed_when_polkit_directory_is_absent(self):
        source = Path("scripts/install.sh").read_text(encoding="utf-8")
        put = re.search(r"(?m)^put\(\) \{.*?^\}", source, re.S)
        block = re.search(r"(?m)^if \[\[ -f \$R/share/polkit/qwq-plugin.rules.*?^fi", source, re.S)
        self.assertIsNotNone(put, "the existing idempotent installer helper is missing")
        self.assertIsNotNone(block, "the actual polkit installation block is missing")
        bash = _find_bash()
        with tempfile.TemporaryDirectory(prefix="qwq-polkit-install-") as temporary:
            root = Path(temporary)
            release = root / "release"
            policy = release / "share/polkit/qwq-plugin.rules"
            policy.parent.mkdir(parents=True)
            policy.write_text(Path("deployments/polkit/qwq-plugin.rules").read_text(encoding="utf-8"), encoding="utf-8")
            destination = root / "etc/polkit-1"
            self.assertFalse(destination.exists())
            dest_posix = _to_bash_path(destination)
            rel_posix = _to_bash_path(release)
            rewritten = block.group(0).replace("/etc/polkit-1", dest_posix)
            script = "set -euo pipefail\nchanged=0\nR=" + shlex.quote(rel_posix) + "\n"
            script += put.group(0) + "\n" + rewritten + "\n"
            result = subprocess.run([bash, "--noprofile", "--norc", "-c", script], cwd=temporary, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            installed = destination / "rules.d/60-qwq-plugin.rules"
            self.assertTrue(installed.is_file(), "the script skipped the deployment rule on a host without /etc/polkit-1")
            self.assertEqual(installed.read_bytes(), policy.read_bytes())
            if os.name != "nt":
                self.assertEqual(installed.stat().st_mode & 0o777, 0o644)
            first_mtime = installed.stat().st_mtime_ns
            again = subprocess.run([bash, "--noprofile", "--norc", "-c", script], cwd=temporary, capture_output=True, text=True, timeout=15)
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertEqual(installed.stat().st_mtime_ns, first_mtime, "an identical reinstall rewrote the rule")


if __name__ == "__main__":
    unittest.main()
