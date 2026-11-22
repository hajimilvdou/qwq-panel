# 运行时内存预检修复

状态：已验收，2026-11-20；P1-RT-02，基线 e736977。

## 真实问题与最小接线

修复前，`HostMemory.Current` 只读取 `system.slice/<unit>/memory.current`，遗漏官方模板单元的 `system-qwq\x2dplugin.slice` 中间层。旧回归也只构造 flat 布局，不能发现实际嵌套路径。

修复前，`planMemory` 在 Current 读取失败时立即返回 restart，连 Available 和候选＋reserve 硬预算都未检查。Current 未知不能作为预算充足的证据。

仅改两份生产文件：HostMemory 优先读取官方模板 slice，保留旧 flat 布局；只在路径不存在时回退，非法字节值仍报错。继续复用 ValidateID、UnitName 和字节解析，不增加 systemctl 查询、缓存或路径搜索。planMemory 遇 Current 错误只设置 Current=0、强制 restart，继续 Available、addBytes 溢出检查及候选＋reserve 门禁；低预算在写 unit、建 saga 或版本记录前拒绝。

## 既有策略

ARCHITECTURE §6.3 要求按可用内存与 cgroup 实测预检，禁止为了零中断触发 OOM。updater.Options.Memory 的现有注释明确允许 Available 读取错误时保守 restart，memory.go 也有这条分支；本次不暗中修改该既有策略。若要将完全未知可用内存改为拒绝，需在对应设计中显式收紧并增加独立回归。

## 回归与验证

复用真实临时 cgroup 文件证明模板 slice 可读取；复用现有真实 updater/SQLite fixture，证明 Current 错误＋低 Available 必须拒绝且无 unit/saga/version/运行态副作用，足够预算则只能 restart。

Root 的 Linux RED（native 95409）已完整结束：controller 因模板 slice 路径缺失失败，updater 的 low 用例因 Current 错误旁路预算并产生副作用失败；两包 go test 均为预期 exit 1，日志保留。随后实施两份生产修复，继续复用既有旧平铺布局回归；不增加路径搜索、进程或缓存，不修改 Platform ABI。

GREEN 8120 已完整 exit 0：两个新回归、controller/updater/supervisor/sandbox/cmd/qwq 五包普通与 race、vet、staticcheck、仓库 lint 及宿主构建全部通过。4Go 格式归档的 SHA、成员、类型、父路径和 token 受检后恢复；Root 独立 P0/P1/P2 复核未见本范围新增阻断项。1C1G 长时资源验收仍属于整个项目终验。
