# 安装、沙箱门禁与静态入口

P1-RT-09：有效发布包始终安装 root 控制的插件单元 polkit 规则，不能因为 Debian 最小安装缺少 `/etc/polkit-1` 而跳过。规则源缺失在改动系统之前拒绝；原 `put` 保持重复安装的内容、权限和 mtime 幂等。

doctor 把缺失或无法读取的 polkit daemon、缺失/不安全的规则文件、无法理解的 polkit 版本及隔离分数超限标记为 Fail，复用原 `sandboxPreflight` 的失败门禁。保留受支持版本、正常 D-Bus 按需启动及 root 开发模式的原行为。`--preinstall` 只做原平台/端口检查，不检查尚未安装的规则，避免首次安装死锁。

日志 NextCursor 是实际扫描到的最后一条记录，过滤不影响推进；额外的 lookahead 记录只决定 Truncated，不跳过下一页。静态 resolver 在读取真实版本状态后拦截 QUARANTINED/REJECTED，保留安全的 STOPPED/ROLLED_BACK 版本资源。

验证执行原安装段与 `put`（只把绝对目标换到自有临时根）、真实 SQLite 状态与 HTTP 静态 handler、原 journald JSON 解析及 doctor/安装门禁。所有 Go、shell/Python 验证在 Linux，不在测试机改正式服务。
