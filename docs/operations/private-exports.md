# 会话绑定的私密交付

服务器生成 SSH 密钥的 fallback 先在面板创建短时交付 grant，再通过已授权的生成 operation 完成。grant 精确绑定人类会话、owner、动作、producer、instance、node、purpose 和 subject；它不会授予新的生成权限。

宿主先以现有 AES-GCM 秘密存储加密保存私钥材料，再导入对应公钥。中断后复用原公钥和材料，不能重试生成第二把。插件 RPC、operation、幂等记录与普通 JSON 只收到公开信息和 export_id；内部 secret ref 和 PEM 不公开。

原人类会话通过独立 POST consume 下载一次。权限和会话仍有效、交付 READY 且未过期才可消费；审计、认领、删除加密值同事务提交。响应为 no-store 二进制附件。短写或断连不重新发行私钥，已导入公钥需另行管理。

grant 有效期 5 分钟，每 owner 最多 16 个活跃项。取消、过期、session/user 删除均回收加密值；过期清理复用现有 operations Sweep，单批最多 128 项，不新增常驻循环。主密钥轮换复用原秘密存储，不另造加密格式。

公开路径：POST `/api/v1/private-exports` 准备；POST `/api/v1/private-exports/{export_id}/consume` 交付；DELETE `/api/v1/private-exports/{export_id}` 取消。三个路径仅接受人类会话和 CSRF，不进入 AI 动作目录；每步审计，生成行为仍由原 operation 控制。

当前为 CAP-07 的必要宿主前置；账户 GenerateKey、浏览器 WebCrypto、面板按钮及真实账户隔离接线继续实施。本功能不能据此标记 SSH 私钥生成已经整体可用。
