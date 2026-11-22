# 初始化链接的真实有效期

`qwq setup-token` 的帮助和控制台提示均为 30 分钟，但离线身份服务原来沿用 24 小时默认值，导致链接在提示期限到达后仍可完成初始化。

离线 `openLocalDatabase` 复用现有 `identity.Options.SetupTokenTTL` 显式设置 30 分钟。root 限制、按属主降权、既有数据库/密钥检查与 NoMigrate 流程保持，未增加接口或迁移。controller 仍使用其原默认设置；兑换以令牌已持久化的 `expires_at` 为准。

已有令牌的存储期限不会被构造选项改写。按原流程成功重发会在同一事务撤销此前尚未使用的初始化链接，新链接使用修正后的 30 分钟期限。

## Linux 验证与复核

- RED `setup-token-expiry-red-20261121` 完整 exit 1：三个独立安装均存储 24 小时期限，30 分钟及之后仍接受初始化。
- 测试复用真实 CLI 签发、SQLite 时间记录和重开 Controller，注入与 DB/身份共享的 FakeClock；按 `created_at + 30m` 验边界，未使用 sleep。
- GREEN `setup-token-expiry-green-20261121` 完整 exit 0：初始化前/等/后边界、重发撤销、已初始化拒绝、root/数据库约束和管理员恢复回归通过；cmd/identity 两包普通、相关 CLI race、两包 vet/staticcheck、仓库 lint 和 CLI 构建通过。
- 再补精确后置断言：期限前 1ms 成功并完成初始化，到期和之后返回 `UNAUTHENTICATED` 且仍为空安装。`setup-token-expiry-postcondition-20261121` 完整 exit 0，三个边界普通和 race 均通过（race 4.672s）；生产文件保持上一轮已验证内容。
- 最终两 Go 源冻结清单 `cfede964ca0cd0313c3b7c4ed3b633d093ff88f369d6ece8c7fb2234d9b4be26`；10240 bytes 格式归档 `c6b978adb0dc2e1b89d53973b9435e8428906a4affb7fea242338ff11464445f` 已受检恢复，成员/token/父路径/非 reparse 守卫通过。
- Root 和唯一工程代理分别只读复核，未发现本范围 P0/P1/P2 阻断。原密码/秘密/会话与管理员恢复链保持，实际存储和消费边界均被验证。

全部工具链仅 Linux；原失败和各轮源/格式/日志保留在 `wt-host-core/.cache/setup-token-expiry-*`。未运行开发服务器或安装依赖，所有自有临时目录已清理。整体项目和双 VPS/长时验收仍按执行表继续。
