# X6 原生预检与私有统计验证

2026-11-15；Xray v26.11.9 / 676eaf66，二进制 SHA-256 `e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d`。复用 X0 已核验材料，没有新增 Xray Go 核心依赖。

## 结果

| 子项 | 证据与结果 |
|---|---|
| X6A 原生渲染 | 生产 Render 的 VLESS/RAW/Vision/REALITY 配置通过真实预检；纯渲染与黄金测试通过 |
| X6B 二进制与预检 | 临时包 root 属主、只读、固定 bin/xray 和摘要；生产 Locate/Preflight 路径通过；预检前、中、后监听集合不变，未创建 API socket |
| X6C 私有 UDS | 动态 UID，目录 0700、api.sock 0600；同 UID 的 Xray CLI 与最小客户端可查询；其他 UID 真实连接返回 PermissionError；无额外 TCP 管理端口 |
| X6D 最小客户端 | 仅 QueryStats，固定前缀及精确 counter 名，reset=false；真实两次启动均读到两个零值入站 counter，缺失用户 counter 为空/ErrMissing；连接、进程、socket、端口均清理 |
| X6E mark 扩展 | 尚未施工或验证，不广告 per_user_mark/下行整形能力 |

握手前用户系列数量为 0。没有伪造流量；真实客户端握手、counter 增长和带流量重启的 reset epoch 属于 X11，仍未执行。上述证据不把首版代理标为正式可用。

## 执行与清理

构建机：`bash spikes/corexray/build.sh` 只编译带 x6spike 标签的测试二进制，复用生产渲染、核验与预检函数。控制脚本 `spikes/corexray/run.sh` 在测试机启动唯一 transient unit，使用私有网络、动态 UID、只读包挂载与有界运行时间。

测试代码通过 exec.Cmd 持有子进程身份、发送 SIGTERM 并 Wait，必要时受 context 取消；停止后验证 /proc/PID 不存在与监听集合恢复。socket 与锁文件仅在进程回收后清理。根夹具停止精确单元并确认 RuntimeDirectory 消失，未使用模糊进程匹配。

第一次入口检查在私有挂载建立前失败，未启动 Xray；改用固定 env 入口及空继承环境后通过。该失败不是 UDS/原生配置兼容失败。

真机退出码 0：`x6-native-live-fixed-entry.log`、`x6-minimal-client-live.log`。最小客户端的 fake Unix/gRPC 边界测试与 core.xray 全包 race/vet、生成漂移、repo_lint 通过，见 `x6-minimal-client-build.log`。完整仓库门禁另见 `g19-core-xray-private-stats.log`。

## 来源与自检

wire 子集保留原 proto package、QueryStats RPC 与字段号，源自锁定上游 command.proto；MPL-2.0 许可证与生成说明随源码保留，外围客户端为 AGPL。NOTICE/repo_lint 精确登记三个第三方源文件，漂移检查加入现有生成门禁。最终插件分发包的第三方源文件与许可证收集仍随 X12 验收。

按 HANDOFF §11.4 自检：P0/P1/P2 无新增发现。客户端拒绝共享目录、宽权限 socket、symlink、任意 counter pattern、超大/重复/负值响应；每次 RPC 有总 deadline，无采样后台、reset、HandlerService 或环境代理。真实进程与临时运行目录已回收。
