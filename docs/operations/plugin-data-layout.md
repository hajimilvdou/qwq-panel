# 插件持久数据目录

宿主数据库、主密钥和 staging 保持在 qwq 拥有的 `/var/lib/qwq`（0700）。声明 `state.backup_paths` 的插件使用 `/var/lib/qwq-plugin-data/<id>/default`；root 父目录为 0711，systemd 管理动态 UID 的 0700 叶目录与 DynamicUser 私有映射。未声明持久状态的插件不获得目录。

安装器和恢复路径共同使用 `sandbox.DefaultPluginDataRoot`，helper 仅接受与当前插件 ID 精确匹配的目录。更改面板 `data_dir` 不会扩大插件对宿主数据树的访问。

## 旧布局迁移

新版本安装器在写入前检测 `/var/lib/qwq/plugin-data`；发现旧数据或符号链接时停止，保留原数据。当前 core.xray 尚未完成真实运行验收，不能假定旧目录为空，也不能自动跟随旧符号链接搬移数据。

已有状态的主机须先盘点各插件、原单元的 `StateDirectory` 和 systemd 私有映射，备份后停止相关插件与 Controller。逐插件将实际数据复制到新专用目录，保持文件权限与内容；不得把整个 qwq 数据根改为可遍历，也不得递归 chown 主数据库树。重渲染单元并启动后核对动态 UID、Initialize 的 DataDir、数据摘要及恢复行为。迁移验证失败须恢复原单元和备份；完成并确认备份可用后，才移除旧入口并运行安装器。

真实迁移及动态 UID 映射作为 X10 门禁记录，当前未在两台 VPS 执行。默认卸载保留插件状态；用户显式选择 `--purge` 时同时清理新入口及 systemd 的对应私有状态树。
