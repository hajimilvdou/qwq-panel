# P6 实施补充：保护调用链与明确阶段

- 日期：2026-11-14。
- 依据：已批准的 ADR-0019/0020/0021 与 P6 任务拆解。
- 性质：修正实施中发现的契约缺口，不扩大插件能力或改变 Platform ABI v1。

## SSH 双端口契约

原 `SetPort(new_port, expected_revision)` 无法区分加入新端口和验证后摘旧端口。能力 proto 采用 append-only 追加阶段：`ADD_NEW` 保留全部现有监听端口，`COMMIT_NEW` 仅保留已验证的新端口，`ROLLBACK` 恢复本次变更前的 qwq drop-in。未指定阶段拒绝执行。

`ADD_NEW` 返回宿主生成的事务引用；提交和回滚同时校验该引用、派发 operation 身份及资源 revision。引用不包含路径，插件不能提供原文件内容。提交在 helper 锁内重新验证新端口；失败保留双端口，不能以先前的插件验证结果作为摘旧端口依据。每次写入先校验候选配置，重载失败尝试恢复旧配置并报告恢复结果。

2026-11-14 CAP-06 实施补充：OpenSSH 的 Port 是累加项，先以完整候选证明最终单端口可在自有范围生效；其他文件声明的旧端口不得擅自删除。Include 展开与真实主配置的原生有效值逐项核对；Match 来源通过原生诊断确认，不静态猜测。

所有 SSH 写入在 `/var/lib/qwq-capability`（root 0700）保存 0600 事务记录，再写自有 drop-in；跨 helper 退出、主机重启保留原始快照与内容版本。GetDropIn 公开 pending，事务详情仅返回原插件/实例。新增独立 RecoverDropIn 写 RPC，必须经过当前已授权 operation，限同一插件/实例、事务引用和当前版本，只能恢复宿主保存的原始快照。它用于原操作中断后无法继续的恢复，不放宽正常 SetPort 的原 operation 绑定。恢复同样先双端口验证原入口，再摘掉候选入口。

SetLoginPolicy/RemoveDropIn 追加 recovery_user；收紧策略前使用宿主读取的操作者全部有效会话地址逐一验证目标用户的公钥登录路径。关闭口令同时关闭 keyboard-interactive，root 策略追加 keys-only 枚举，以表达 prohibit-password。账户读取执行器未就绪时失败关闭，不能把“已有钥匙文本”当作可用登录路径。

## 宿主事实与持久化

保留端口取自宿主有效 SSH 配置及面板配置；管理会话地址、白名单、接管授权取自宿主确认的上下文。不能从插件请求中推导这些事实。事实缺失时写操作失败关闭。helper 再次校验保留端口与排除地址，精确控制文件及 nft 对象。

能力资源 CAS 不能依赖宿主进程内计数器：socket 激活 helper 在请求间退出。revision 依据资源实际内容，写入用跨进程锁；持久化与执行的部分失败必须对账或回滚，不能返回成功。防火墙输入只接受首期能够证明安全的 nft JSON 子集，未知表达式拒绝，原生检查通过并不替代白名单检查。

## operation 秘密入口

`plugin.operation` 秘密必须在 operation、plan、幂等记录和审计持久化之前提取；只在 dispatch 前替换不满足保密要求。HTTP、人类及代理调用共享执行器入口，复用 `secrets.ExtractSecrets` 的 schema 与 owner 规则。既有 `plugin.config` 揭示路径保持原用途；账户密码由独立能力 forwarder 按 owner、purpose 与当前 operation 的引用范围揭示。

## 验收边界

## 一次性私钥交付

普通 operation result 和幂等响应会持久化，服务器 fallback 不得直接返回 PEM。SEC-EXPORT 用通用安全交付元数据绑定原人类会话、producer/action/node/instance/purpose/subject；生成仍通过已授权 operation。宿主加密保存材料后再导入公钥，中断后复用；正常响应仅返回 export_id 与公钥。独立人类 POST consume 在审计、认领和加密值删除的同一事务后交付一次；5 分钟 TTL、每 owner 16 项、已有 Sweep 单批 128 过期清理。session/user 删除级联回收，X3 跨 owner reveal 不放宽。

fake executor 测试覆盖 CAS、取消、失败回滚及自锁保护。隔离 sshd/netns 和真实 systemd 验收分别记录；未完成真机门禁的项保留 pending。域名/证书和三协议仍按已批准设计一起交付，不把纯渲染或 mock 成功当作真实互通证据。
