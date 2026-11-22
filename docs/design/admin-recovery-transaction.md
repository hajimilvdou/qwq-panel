# 管理员本地恢复的事务边界

`qwq recover` 必须真正恢复禁用管理员的登录能力，并且只处理写入时仍为管理员的原 user ID。原实现只在哈希前检查角色，成功重置后也没有清除禁用标志。

## 实现与调用关系

哈希前的廉价预检和写事务内重读后的核验共用 `checkAdminRecoveryRole`。角色变为 operator/viewer 时沿用 `STATE_CONFLICT`，在口令、MFA、会话或审计写入前返回。原 user ID 不变，删除后重建同名用户不会让恢复转向另一记录。

`disabled = 0` 与原口令替换、第二因素秘密回收、会话/挑战撤销、revision、事件和审计在同一 SQLite 事务内提交。任一步失败全部回滚；失败修复后可以用原输入重试。没有新增迁移、修改接口或绕过现有秘密存储。

root 限制仍在 `openLocalDatabase`，打开既有库前按目录属主降权；恢复完成后仍由原 CLI 按同一 user ID 撤销委托并传播失败。旧 enroll 链接仍受兑换前与事务内的当前密码状态检查，不能覆盖已恢复的口令；本批没有扩大链接清理范围。

## 验证

- `admin-recovery-boundary-red-20261121` 完整 exit 1：三个真实回归分别证明恢复后仍禁用、哈希期间降级仍被改写、账户启用失败未触发原写入。
- 角色竞争复用真实 Hasher 的 `runAtHashBoundary`，在哈希返回前经原 `UpdateUser` 提交降级，没有 sleep 或替代密码实现。
- 故障回归由 SQLite `BEFORE UPDATE OF disabled` trigger 拒绝启用，检查原口令摘要、MFA 秘密、禁用状态与 revision 保持，成功审计未写；移除故障后重试登录成功。
- `admin-recovery-boundary-green-20261121` 完整 exit 0：新旧六项 `ResetAdmin` 回归全通过；identity/authz/api/cmd 四包普通通过；identity race **86.230s**；四包 vet/staticcheck、仓库 lint 和 CLI 构建通过。
- 全部工具链仅在 Linux；两 Go 源归档 `85104a815c0b201b6506bc990995fce046c9a838fe29031569d724d1115967ed`（20480 bytes）已严格恢复，成员、token、父路径和非 reparse 守卫通过。

源冻结清单 `1502dcc98962418473ad54b0219eec9250105ddf4db83945b53c7aed32b77bc5`，日志和两轮格式归档保留在 `wt-host-core/.cache/admin-recovery-boundary-*`。测试只使用临时 SQLite 与夹具身份，未启动服务；所有 rrun/下载临时目录已清理。

## Root 自检

P0/P1/P2：本批未发现遗留阻断。角色在持有写事务后再次核验；启用与原凭据/秘密/会话回收原子提交，失败错误可追踪，原 root 入口与委托撤销调用保持。原有普通管理员恢复、非管理员/未知用户拒绝、弱口令拒绝、MFA 秘密回收和 CLI 恢复回归均通过。完整双 VPS、1C1G 长时与其他项目轨道继续单列验收，本批不标记总体完成。
