#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""仓库级检查（scripts/check.sh 调用；标准库实现，兼容 Python 3.8）。

    python3 tools/repo_lint.py

检查项：
  spdx      源文件前 5 行带 SPDX-License-Identifier，且与目录的许可证分区一致（ADR-0005、NOTICE）
  boundary  sdk/ 模块中的 Go 文件不导入宿主模块（只允许 github.com/qwq-panel/qwq/sdk/...）
  secrets   不跟踪私钥、构建机连接参数等敏感文件
  versions  protoc-gen-go 与 SDK 运行时的 protobuf 版本一致；go.mod 的 toolchain 与 scripts/tools.lock 一致
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

APACHE = 'Apache-2.0'
AGPL = 'AGPL-3.0-only'
# 目录分区：先匹配先得，其余为 AGPL
APACHE_PREFIXES = ('api/', 'sdk/', 'web/kit/', 'ui-design/prototype/kit/')
APACHE_FILES = {'ui-design/tokens.css', 'plugins/builtin/monitor/ui/tokens.css'}
# 仅锁定的第三方统计 wire 子集沿用 MPL；外围实现仍按原目录要求 AGPL。
MPL_FILES = {
    'internal/xraycore/xrayapi/wire/stats.proto',
    'internal/xraycore/xrayapi/wire/stats.pb.go',
    'internal/xraycore/xrayapi/wire/stats_grpc.pb.go',
}

SOURCE_EXT = {'.go', '.proto', '.py', '.sh', '.js', '.mjs', '.ts', '.tsx', '.css', '.html', '.svelte', '.vue'}
# api/ 下的 YAML 是公共契约（OpenAPI 等），也要带头
YAML_EXT = {'.yaml', '.yml'}
EXEMPT_PREFIXES = ('archive/',)
SPDX_RE = re.compile(r'SPDX-License-Identifier:\s*([A-Za-z0-9.+-]+)')

SECRET_PATH_RE = re.compile(r'(^|/)(服务器/|scripts/remote\.env$|id_(rsa|ed25519|ecdsa)(\.pub)?$|[^/]*_id_(rsa|ed25519)$|[^/]*\.(key|pem|p12|pfx)$)')
SECRET_TEXT_RE = re.compile(r'-----BEGIN ((OPENSSH|RSA|EC|DSA|ENCRYPTED) )?PRIVATE KEY-----')
SECRET_TEXT_ALLOW = {'tools/repo_lint.py'}

GO_IMPORT_RE = re.compile(r'^\s*(?:import\s+)?(?:[\w.]+\s+)?"(github\.com/qwq-panel/qwq(?:/[^"]*)?)"', re.M)


def tracked_files():
    out = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                         cwd=str(ROOT), check=True, stdout=subprocess.PIPE).stdout
    return sorted(p for p in out.decode('utf-8').split('\0') if p and (ROOT / p).is_file())


def expected_license(path):
    if path in MPL_FILES:
        return 'MPL-2.0'
    if path in APACHE_FILES or path.startswith(APACHE_PREFIXES):
        return APACHE
    return AGPL


def needs_spdx(path):
    if path.startswith(EXEMPT_PREFIXES):
        return False
    ext = pathlib.PurePosixPath(path).suffix
    if ext in SOURCE_EXT:
        return True
    return ext in YAML_EXT and path.startswith('api/')


def check_spdx(files):
    errs = []
    for f in files:
        if not needs_spdx(f):
            continue
        head = (ROOT / f).read_text(encoding='utf-8', errors='replace').splitlines()[:5]
        m = next((SPDX_RE.search(l) for l in head if SPDX_RE.search(l)), None)
        want = expected_license(f)
        if not m:
            errs.append(f'{f}: missing SPDX-License-Identifier (want {want})')
        elif m.group(1) != want:
            errs.append(f'{f}: SPDX {m.group(1)}, directory requires {want}')
    return errs


def check_boundary(files):
    errs = []
    for f in files:
        if not (f.startswith('sdk/') and f.endswith('.go')):
            continue
        for imp in GO_IMPORT_RE.findall((ROOT / f).read_text(encoding='utf-8', errors='replace')):
            if not (imp == 'github.com/qwq-panel/qwq/sdk' or imp.startswith('github.com/qwq-panel/qwq/sdk/')):
                errs.append(f'{f}: SDK module imports host package {imp}')
    return errs


def check_secrets(files):
    errs = []
    for f in files:
        if SECRET_PATH_RE.search(f):
            errs.append(f'{f}: sensitive path must not be tracked')
            continue
        if f in SECRET_TEXT_ALLOW:
            continue
        p = ROOT / f
        if p.stat().st_size > 2 * 1024 * 1024:
            continue
        if SECRET_TEXT_RE.search(p.read_text(encoding='utf-8', errors='replace')):
            errs.append(f'{f}: contains a private key block')
    return errs


def mod_require(gomod, module):
    m = re.search(r'^\s*' + re.escape(module) + r'\s+(v\S+)', (ROOT / gomod).read_text(encoding='utf-8'), re.M)
    return m.group(1) if m else None


def check_versions():
    errs = []
    tools_pb = mod_require('tools/go.mod', 'google.golang.org/protobuf')
    sdk_pb = mod_require('sdk/go.mod', 'google.golang.org/protobuf')
    if tools_pb and sdk_pb and tools_pb != sdk_pb:
        errs.append(f'protobuf: protoc-gen-go uses {tools_pb} (tools/go.mod) but SDK runtime requires {sdk_pb} (sdk/go.mod)')
    lock = dict(l.split('=', 1) for l in (ROOT / 'scripts/tools.lock').read_text(encoding='utf-8').splitlines()
                if '=' in l and not l.lstrip().startswith('#'))
    want = 'go' + lock.get('GO_VERSION', '?')
    for f in ('go.mod', 'go.work'):
        m = re.search(r'^toolchain\s+(\S+)', (ROOT / f).read_text(encoding='utf-8'), re.M)
        if not m or m.group(1) != want:
            errs.append(f'{f}: toolchain {m.group(1) if m else "missing"}, scripts/tools.lock pins {want}')
    return errs


def main():
    files = tracked_files()
    results = [('spdx', check_spdx(files)), ('boundary', check_boundary(files)),
               ('secrets', check_secrets(files)), ('versions', check_versions())]
    failed = 0
    for name, errs in results:
        print(('ok   ' if not errs else 'FAIL ') + name)
        for e in errs:
            print('     ', e)
        failed += bool(errs)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
