# SSH 能力：配置与恢复

- 只管理 `/etc/ssh/sshd_config.d/00-qwq.conf`；自有文件使用固定 qwq 标记，只接受 Port、PasswordAuthentication、KbdInteractiveAuthentication、PermitRootLogin。其他配置只读。
- 有效配置由真实 OpenSSH `-T` 确认，完整 Include 展开必须与原配置语义一致；匹配块来源由原生诊断确认。配置与活动监听不一致时拒绝普通写入，先检查配置来源和既有变更。
- `SetPort` 明确使用 ADD_NEW、COMMIT_NEW、ROLLBACK。新增前检查占用、管理端口及最终单端口能否在自有范围生效；Port 为累加项，不能删除其他文件声明的端口。提交在宿主锁内重新验证新端口，写后实际监听集合必须与候选完全一致。
- 所有写入先原生预检、再次核验版本，再保存持久事务、提交文件和重载标准 SSH 管理单元。socket 激活执行 daemon-reload/restart socket，传统标准服务仅 reload；已有配置或恢复无法确认时返回明确失败，不报告成功。
- 事务在 `/var/lib/qwq-capability`（root 0700）保存，文件 0600；只保存本能力原始快照、身份与内容版本。跨 helper 退出和主机重启保留，普通卸载保留，purge 删除。
- `GetDropIn` 显示 pending；事务引用、原 operation、阶段与端口仅对同一插件/实例返回。原操作中断后使用新的已授权 `RecoverDropIn` operation，只能恢复已保存快照；原入口验证成功后才撤候选端口。不能提交任意文件内容或路径，也不能覆盖第三方修改。
- 收紧登录方式必须提供 recovery_user。宿主读取操作者全部有效人类会话地址，逐个验证可用公钥路径；关闭口令同时关闭 keyboard-interactive，root keys-only 使用 prohibit-password。账户读取执行器未就绪时失败关闭。

当前源码及原生无监听预检已验证；真实 systemd 重载、两 VPS 远端可达性和账户沙箱属于独立真机验收。回环横幅不能证明云安全组或公网路径已放行。
