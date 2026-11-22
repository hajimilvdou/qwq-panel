# 防火墙能力与恢复

qwq 仅管理 `inet qwq` 的 `input` 链，其他表及同表封禁链/集合保留。操作前从宿主配置、标准 SSH 单元和实际监听核验管理端口；插件只能扩大保留集合。lo、已建立连接和保留 TCP 端口的保护规则始终在用户规则之前。

首期接受 TCP/UDP 目标端口、IPv4/IPv6 来源、accept/drop 及 input 默认策略。配置最多 256 KiB、256 条用户规则、128 个保留端口；任意命令、其他表/链、跳转、NAT、mark、未知表达式和重复 JSON 键均拒绝。已安装的其他管理者默认只读，接管须走独立流程。

写入持有 `/run/qwq/capability.lock` 跨进程锁，revision 依据实时 input 策略与已保存策略。顺序为白名单校验、nft 原生 check、再次核验版本和管理端口、原子替换 input 链、写后核验、原子保存、再次核验。仅连接尚未成功时可重试，已发送的写入不自动重发。

保存文件 `/etc/nftables.d/qwq.nft` 是 qwq 管理的规范化 JSON 策略，权限 root:root 0644。`qwq-firewall-restore.service` 是无特权的开机客户端，经 socket 激活 helper 恢复；不编辑发行版 nftables 主配置。Root helper 空闲时仍退出。

实时与已保存策略不同会显示 `persistence_pending`；重启可能恢复旧策略，不能将此状态显示成已保存。失败时恢复本次候选，发现其他并发修改不会覆盖它；恢复无法确认返回 `RECOVERY_REQUIRED`，应读取实时状态再预演修复。

节点需安装 nftables、OpenSSH、systemd、iproute2 的 ss 工具。缺少工具、无法确认标准 SSH 单元监听、不可读取可信配置或无法获得资源锁都会明确失败。真机 netns、沙箱及开机恢复验收仍需记录实际版本和结果，单测不能替代。
