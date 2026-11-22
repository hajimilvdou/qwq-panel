# 插件彻底卸载的数据边界

P1-RT-08：普通卸载继续保留插件配置、凭据、启停位和持久数据；`purge_data=true` 才清理本插件的完整数据。现有秘密 owner 与引用索引回收复用 `secrets.DeleteOwner`。

## 调用与失败顺序

1. 在原插件锁内确认没有其他进行中的 saga 或绑定生命周期操作。
2. 停止并释放各版本实例，复用 `RemoveUnit` 删除单元与版本树。
3. 独立 `Installer.PurgeData(ctx, pluginID)` 清理持久数据和宿主 KV 状态；没有版本行的重试也执行此步。
4. 原短事务同步删除版本、配置、凭据、启停位及精确秘密 owner，最后发删除事件。
5. 清缓存并重发路由。

文件系统和 SQLite 无法共用提交。清理文件失败时停止在删行事务之前，保留记录供重试；事务失败时文件已清理，重试把缺失目录视为已经完成。默认卸载、更新和回滚补偿不调用 PurgeData。

启停写入也在原事务内读取真实活动版本，复用 `loadActiveVersionTx`；不能凭卸载提交后尚未更新的内存缓存重新插入 `plugin_states`。真实提交后日志提供可重现的交错点，验证完整 `SetEnabled` 与 purge 的并发边界。

## 固定删除范围

- `PluginInstaller.StateDir` 由 controller 的 `<DataDir>/plugin-state` 装配，只删除 `<StateDir>/<pluginID>`；清理前关闭本插件的驻留 host channel，防止旧 store 再写回。
- root helper 的 `HelperRequest.PurgeData` 只携带插件 ID 和布尔开关。持久根来自 root 配置，删除 `<logical-data-root>/<pluginID>` 及 `<private-data-root>/<pluginID>`，不接受请求提供的数据绝对路径。
- 生产根为 `/var/lib/qwq-plugin-data` 与 `/var/lib/private/qwq-plugin-data`。DynamicUser 的受控逻辑链接只删除链接本身，真实私有树按固定私有根清理；任意子树链接不跟随。
- 复用 `sandbox.TrustPolicy.Open` 与 `RemoveAllIn` 的固定句柄；拒绝不可信根、根链接、路径穿越和运行中实例。目录不存在属于幂等成功，其他读取或删除错误必须返回。

进行中的五写生命周期引用守卫与本次卸载 operationID 放行边界在 CORE 接受段串行接入；外部 DTO 不增加内部 operationID。

## 验证范围

真实 SQLite 验证 purge 与默认保留、精确插件边界、文件失败保留记录及重启重试；真实 Unix helper wire 验证新字段；临时可信根验证 logical/private 布局、链接逃逸、未知/运行状态及幂等清理。Linux 执行受影响包普通、race、静态检查、仓库 lint 与构建，再复核 P0/P1/P2。
