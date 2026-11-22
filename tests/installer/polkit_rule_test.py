# SPDX-License-Identifier: AGPL-3.0-only

"""运行实际安装脚本的规则安装段，所有目标改到自有临时目录。"""

from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


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
        with tempfile.TemporaryDirectory(prefix="qwq-polkit-install-") as temporary:
            root = Path(temporary)
            release = root / "release"
            policy = release / "share/polkit/qwq-plugin.rules"
            policy.parent.mkdir(parents=True)
            policy.write_text(Path("deployments/polkit/qwq-plugin.rules").read_text(encoding="utf-8"), encoding="utf-8")
            destination = root / "etc/polkit-1"
            self.assertFalse(destination.exists())
            script = "set -euo pipefail\nchanged=0\nR=" + shlex.quote(str(release)) + "\n"
            script += put.group(0) + "\n" + block.group(0).replace("/etc/polkit-1", str(destination)) + "\n"
            result = subprocess.run(["bash", "--noprofile", "--norc", "-c", script], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            installed = destination / "rules.d/60-qwq-plugin.rules"
            self.assertTrue(installed.is_file(), "the script skipped the deployment rule on a host without /etc/polkit-1")
            self.assertEqual(installed.read_bytes(), policy.read_bytes())
            self.assertEqual(installed.stat().st_mode & 0o777, 0o644)
            first_mtime = installed.stat().st_mtime_ns
            again = subprocess.run(["bash", "--noprofile", "--norc", "-c", script], capture_output=True, text=True, timeout=15)
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertEqual(installed.stat().st_mtime_ns, first_mtime, "an identical reinstall rewrote the rule")


if __name__ == "__main__":
    unittest.main()
