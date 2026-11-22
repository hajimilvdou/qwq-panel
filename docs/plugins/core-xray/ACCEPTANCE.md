# Xray 真实流量与故障验收状态

状态：签名包/包完整性与 X11 六项独立真实流量/故障测试终态已通过；原生命周期五次失败停止记录保持，版本更新/回滚及完整阶段资源仍未完成。最新证据见 [E2E-REPORT.md](E2E-REPORT.md) 的2026-11-17节。

现有源码入口：

| 测试 | 实际覆盖计划 | 当前执行状态 |
|---|---|---|
| TestXrayPackageArtifacts | 三个签名版本、版本/摘要/权限/来源、合法容器内字节篡改 | 已通过三个版本及三种篡改子测试 |
| TestXrayPluginLifecycle | 正式安装、真人审批/Plan/Apply、真实核心/统计、私有目录、版本更新/失败恢复/回滚、免 reveal、清理 | 五次失败；最新首次 Apply 为 SECRET_UNAVAILABLE，purge/clean_host 通过，同序列停止 |
| TestXrayRealTraffic | 锁定真实客户端 SOCKS → VLESS/Vision/REALITY/RAW → 固定摘要公开HTTPS响应；入站/用户双向增长；错误 UUID/密钥拒绝 | 新增授权第1/1次PASS；21.27s、卸载/清理通过，原5次保留 |
| TestXrayRecoveryTraffic | 同 revision 重放、核心/驱动 SIGKILL、controller 重启后重新转发；epoch 分离与计数 | 第2次完整PASS；23.71s，首次卸载fields夹具错误保留 |
| TestXrayCandidateFailureTraffic | desired 未应用、认证材料无效、候选端口占用与旧代理恢复 | 首次PASS；21.62s，卸载/清理通过 |
| TestXrayCancelTraffic | 真实宿主 RUNNING/驱动分发阻塞阶段取消，旧核心独立保持流量 | 首次PASS；19.29s，卸载/清理通过 |
| TestXrayDeadlineTraffic | 声明 job deadline 与默认三次幂等尝试，最终 TIMEOUT 后旧配置可用 | 测试保存终态0/PASS378.26s；外层脚本1，已独立只读核验，不重跑 |
| TestXrayAPIOutageTraffic | 暂停真实核心/API，Observe 明确 unavailable，恢复同 epoch 流量 | 首次PASS；23.37s，卸载/清理通过 |

所有新入口带 `e2e && linux` 标签和 `QWQ_XRAY_E2E=1` 独立开关。普通测试不启动 Xray/systemd。真实客户端仍是 X0 锁定二进制，配置只写本轮私有临时目录，进程使用最小环境、明确 SIGTERM/强杀/Wait 清理；不能继承宿主凭据。

客户端复用既有 `golang.org/x/net/proxy`，版本保持 v0.60.0；只将 go.mod 声明改为直接依赖，与 DNC-1 同内容变更一致。没有新版本或全局工具安装。

流量目标正文为每次随机生成的已知数据；只有 HTTP 成功且完整字节一致才算转发成功，REALITY fallback 页面不能通过。字节比较只在同 epoch；缺失方向依然公开为缺失。测试针对未存在用户系列使用初始基线 0，随后必须看到真实系列 present，不把缺失状态写成零值成功。无符号差值前检查单调性，避免下溢伪装成增长。

## 仍待补齐与外部执行

- 已补宿主分发阻塞阶段的取消、job deadline 和独立 API 故障源码；这些场景尚未运行，不能冒充原生事务每个阶段的取消证据。X8 的逐阶段模型仍保留，必要的更深真实注入另列。
- 资源探针 resources.py 按启动/Apply/更新/恢复/回滚/卸载阶段采样，客户端单独计入 test-only。十项本地解析/角色测试通过；第五轮 Linux/1C1G 实测 16.185s/67 次、探针退出0、OOM0，仅有启动执行器及核心启动前的驱动数据。完整核心/流量/更新/回滚阶段仍缺失，采样间隙与短进程漏采明确记录。
- 双 VPS 交换角色的 PROTO-S0–S8，以及 Hysteria2/SS2022/simple-obfs、DNS/CA staging 是后续独立门禁，当前 v1 测试不证明它们完成。
- MPL/上游依赖 notices 的最终分类、完整 gate/race、清理逐项报告和候选汇总归 X12。

可执行步骤与清理要求见 [EXTERNAL-VERIFICATION.md](EXTERNAL-VERIFICATION.md)，五次真实结果及公开证据摘要见 [E2E-REPORT.md](E2E-REPORT.md)。传输和清理已经实际完成；同一生命周期不再重跑，未执行的 X11 场景继续保持“未执行”。

版本交付自审修复：能力响应 driver_version 原硬编码 0.1.0，现从同一嵌入 manifest 身份读取，版本 schema 复用 manifest 的 SemVer 规则，摘要同步。三个正式包的版本 overlay 探针已实际检查 descriptor 与真实 SDK 能力响应并通过。
