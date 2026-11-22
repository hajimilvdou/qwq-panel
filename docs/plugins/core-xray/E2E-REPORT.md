# X10/X11 正式包、流量与故障验收

状态：签名包、包完整性与 X11 六项独立真实流量/故障测试终态均已通过；原 X10 生命周期五次失败记录保持，更新/失败更新/版本回滚及完整阶段资源仍待验收。

## 2026-11-17 X11 六项真实终态

正式包和宿主来源保持干净提交 `3e9a8541d2e084e87ae02d9337340b5a6cd21309`；测试夹具来源为 `dc4150ca004b23d235f75607a8de54f317cae6c6`。夹具归档 SHA256 为 `6806f39b115e6a394164ad1e718a1a5d0c334b7358633a459c4b8e3c5e129f2c`，9,079,769 字节，展开23,035,146字节；两端三成员、六场景枚举与两份内层文件摘要均通过。

| 场景 | 实际覆盖与结果 | 耗时 | 公开证据目录 |
|---|---|---|---|
| RealTraffic | 三次完整转发各22,041字节；入站/用户双向统计增长，错误UUID/密钥拒绝，公共卸载通过 | 21.27s | `out/TestXrayRealTraffic.E0nSMe` |
| RecoveryTraffic | 同revision重放不重启；核心/驱动SIGKILL和controller重启后再次真实转发，epoch与计数断代、卸载通过 | 23.71s | `out/TestXrayRecoveryTraffic.XjdnaR` |
| CandidateFailureTraffic | 未Apply期望态保留旧代理；无效认证、候选端口占用后旧配置健康和转发保持，卸载通过 | 21.62s | `out/TestXrayCandidateFailureTraffic.NyMAJQ` |
| CancelTraffic | 真实RUNNING/驱动派发阻塞阶段取消，旧核心继续转发，运行摘要/epoch保持，卸载通过 | 19.29s | `out/TestXrayCancelTraffic.4cEwPp` |
| APIOutageTraffic | 暂停真实核心/API后Observe明确不可用，恢复同epoch并再次转发，卸载通过 | 23.37s | `out/TestXrayAPIOutageTraffic.cpvLeH` |
| DeadlineTraffic | 既定120秒job deadline和默认最多三次尝试后TIMEOUT，旧运行配置与转发保持，卸载通过 | 378.26s | `out/TestXrayDeadlineTraffic.oazcmC` |

六项远端保存的 `test.exit` 均为0，资源探针退出0、日志为空，每轮最终 `clean_host=true`。RealTraffic保留原5次记录，使用用户单独授权的新增1次成功；Recovery首次三故障通过而卸载因错误fields参数失败，修复为RFC6901 `/revision` 后第二次完整成功。其他四个独立故障场景均首次运行。

Deadline的Go测试实际PASS，但外层Bash随后退出1：Root在它运行时增补本机证据读取分支，脚本文件尾部继续读取位置发生偏移，报 `digest: unbound variable`。此外层失败原样保留；随后只读核验原测试终态、资源摘要及清理，证据检查退出0，没有重跑378秒的测试。后续运行入口先加载完整脚本文本交给 `bash -c`，或等待运行结束后再修改runner。

真实流量使用锁定摘要和大小的公开HTTPS响应，安装前检查TLS、禁止代理和重定向；生产原生Render与默认私网拒绝规则保持。回环TLS只作为REALITY握手目标，不把fallback页面当转发成功。REALITY公网伪装候选继续排除Cloudflare代理保护站点。

### 1C1G资源记录

[完整六场景资源证据](evidence/x11-2026-11-17.json)包含阶段/角色RSS、FD、线程、进程和CPU观测，以及内核cgroup峰值；文件SHA256为 `bbc42030f855d955ad81c6cc1ce16e895ac863047daf801fea917e050af4dde9`。实际主机1 CPU、961MiB内存，六场景均无cgroup采样缺口及OOM kill；共3,485次观测。最大产品cgroup memory.peak为44,339,200字节（约42.3MiB），主机最低可用547,110,912字节（约521.8MiB）。

客户进程为test-only，启动执行器与常驻驱动/核心分开。RSS、FD和线程是采样峰值，不能替代内核峰值，也不能把各阶段/角色峰值相加当作同一时刻占用。短进程和采样间峰值可能漏采；当前证据覆盖启动/Apply/流量/故障/卸载，更新、失败更新、版本回滚和完整长期预算仍缺失。X10原五次停止与后续三协议/双VPS互通门禁不因本节成功而恢复或完成。

## 2026-11-16 干净源码候选（最新）

固定来源3e9a8541d2e084e87ae02d9337340b5a6cd21309，GOWORK=off，实际三包嵌入版本/RPC descriptor、pack/sign/verify和包完整性7/7全部通过，每包source_modified=false。每包51组件、46实际外部身份、58来源原文摘要和63许可相关文件，NOASSERTION=0；实际生产x/net v0.60.0属于47身份的已审目录。

| 当前干净候选 | SHA256 |
|---|---|
| core.xray-0.1.1.qwq | 8c69a3ef97b2e4d2db851245bcb814a3beeb0063eec9b56d9a20f6cf8f2393b9 |
| core.xray-0.1.2.qwq | 134a40ee045f604b2fae9cd36b4e91052fcc99e5c9a973b8cfeeea36aa6b7999 |
| core.xray-0.1.3.qwq（仅故障验收） | f739bf967f9ec1f2e7f28fae11ce34d41c421f188edcb1dd3abad28ba9761641 |

新公开归档85046967字节，SHA25698dab78bd030f40f6653fe24af65fac1ff6bb5bb3a6579d7301b86b3cb9abf01，展开98957415字节/9成员。Root已独立受检取回新收据与归档，本机再次核验来源、实际pass名称（含tamper_manifest.json）、归档摘要/成员和七文件SHA256SUMS全部通过。旧归档与以下历史证据保留，不能用旧包替代本候选。

独立X11和完整资源验收仍在执行准备中，原X10五次停止保持。DNC稳定阶段后续已合主线且整批18/18/race通过，此处测试包的来源仍固定在3e9a854，不把后续主线源码与本次产物混为同一版本。

## 2026-11-16 主会话接续：许可候选已核验

当前Root源码完整门禁g25为18/18与两个模块race通过。新0.1.1、0.1.2及仅故障验收的0.1.3均实际构建、嵌入身份核验与pack/sign/verify通过，包读取/篡改7项实际pass事件已核验。新包每份51组件、46个精确依赖与58份来源原文摘要一致，63份许可相关文件，许可NOASSERTION为0；Go1.27.3与Go1.27.4标准库分别记录。

| 新候选 | SHA256 |
|---|---|
| core.xray-0.1.1.qwq | 9f5f45a539f4d9a84eeaf891fc19c59891915c0d0817f5fe772802d928439e5b |
| core.xray-0.1.2.qwq | fc32703b9e62f6a81e19984b9fd4ce31e4cdfee738854c2e4604772c40f8fa6a |
| core.xray-0.1.3.qwq（专用故障包） | 1072f9285029578de1509af3bb1572a2ee1d627f1c112cb025ef3224ccd9695f |

本机公开许可收据为.cache/core-xray/out/x12-license-verification.json；旧84,873,684字节传输包仍保留，摘要与历史记录一致。源原文的Git换行转换问题已修复为内容地址目录binary属性，独立提交19127da已合main，main干净。新候选来源仍如实记录modified=true；没有将新候选安装到测试VPS，没有重跑五次已停止生命周期序列，也没有将X11或完整资源验收标为通过。

## 2026-11-16 五次真实生命周期结果

第五轮宿主候选为 `434cf404d661fcddd487652890791cb5077c7404`，包含 DynamicUser 私有目录和所属插件配置快照修复。随后两修复与JSON映射修复87885be经过完整18/18/race后快进合入main；主线87885be干净，新签名包及新真机结果尚未产生。每轮使用正式签名包、公共 API 和真实 systemd，结束后既有 purge 与 `clean_host=true` 均通过。

| 次数 | 耗时 | 实际失败及处理 | 资源探针退出码 |
|---|---|---|---|
| 1 | 19.50s | 逻辑 DataDir 为链接，激活失败；真实目录诊断后提交 X10-DIR | 1 |
| 2 | 20.22s | 安装/激活通过，Plan 为 CONFIG_REVISION_CONFLICT；提交 X10-CFG | 0 |
| 3 | 27.27s | 保存 desired 和 Plan 通过，夹具错误要求 high/write 必须 MFA；按 ADR-0004 修正，并识别 systemd 启动执行器 | 1 |
| 4 | 20.05s | RequiresMFA=false，却仍传 TOTP，触发公共审批夹具守卫；删除不必要的审批参数 | 0 |
| 5 | 16.09s | 安装、desired、Plan 和真人审批通过，首次 Apply 为 SECRET_UNAVAILABLE；停止同一生命周期序列，转入配置秘密格式的定向诊断 | 0 |

第五轮传输归档 SHA256 为 `8c564ff11b3f19e7f7d6a836b9383ff4f99b2bb49af1b6dff94c14888aa9e7d1`，9,037,512 字节；两端摘要、受限三成员和解包 SHA256SUMS 均通过。公开终态证据归档 SHA256 为 `478e93bfbcf36ca506fa9c11f0934bdade779a63a84e1a65c71da16b78a45474`，2,514 字节。原三签名包摘要仍保持下表数值。

第五轮资源实测为 1 CPU、1,008,189,440 字节物理内存，采样 16.185s/67 次，cgroup 缺口0、OOM kill0、内核 memory.peak 28,557,312 字节、CPU 305,512µs；主机最小可用内存 512,053,248 字节。Apply 前驱动观测 RSS 峰值 19,304,448 字节、FD10、线程6；启动执行器单独记录。失败发生在原生核心启动之前，不能将未观测的核心/流量/更新/回滚阶段写成零占用或完整 X12 资源证明。

真实SQLite/加密存储测试证明API ExtractSecrets保存JSON值，宿主Reveal保持该字节契约。原映射器JSON字符串/转义回归实际RED；修复87885be有界解码内容、复用原生材料校验并清零缓冲区，新三顶层3/3及相关ordinary/race/vet/staticcheck通过，完整门禁18/18及两模块race262s通过。修复和真机结果分别记录，不能以单元通过替代尚缺的生命周期验收。禁止第六次重复本序列；X11六项流量/故障与后续协议门禁仍未执行。

2026-11-15 已恢复此前审批阻断项：正确克隆代理下的公开 Web 上传完成，四个关键摘要一致、163 个声明/预压缩文件存在，真实嵌入页面 smoke 通过。构建机正式 pack/sign/verify 三版本与实际嵌入 manifest/RPC/capabilities 身份验证通过；TestXrayPackageArtifacts 的三个版本与三个合法容器内篡改子测试通过。

| 产物 | 实际 SHA256 |
|---|---|
| core.xray-0.1.1.qwq | f7474648fd67e8e9afd2c347565efaa98f96b0017776d3a26f762ada6e54ac5f |
| core.xray-0.1.2.qwq | 5fbf5aad1b1e3b3ac76bc177f73bdb571020ac63e3bfa737ade7c2a6f308a5a9 |
| core.xray-0.1.3.qwq（故障验收） | 3f82238d5be3d767b6fd443cb8e801a054e588086906c24f3448bc223a149749 |
| xray-e2e-transfer.tar.gz | a00a1cf9e7b9212b3835dd73f4e0883d871a8426ee0e8e60371be05199bea2ac |

传输包 84,873,684 字节，清单仅公开信任根、release、签名包、已编译测试与资源探针，逐项 SHA256SUMS 通过。测试 VPS x86_64/systemd255，运行前确认无已加载 qwq 单元且自有安装路径不存在；实际生命周期、流量、资源和清理将另回填。

候选构建入口为 `plugins/builtin/core.xray/build.go`，使用显式既有签名材料、固定 Xray 摘要、Go overlay 版本、实际 RPC descriptor 核验和正式 pack/sign/verify。SBOM 来源是编译后驱动的真实链接依赖；保留依赖许可证原文和修改后的 MPL wire 源文件。故障版本 0.1.3 明确标记仅供失败更新验收。

新增测试：

- `TestXrayPackageArtifacts`：签名/版本/构建摘要、权限、来源材料完整性，以及保持合法容器的 manifest/驱动/核心字节篡改拒绝。
- `TestXrayPluginLifecycle`：正式安装、UNCONFIGURED、desired 与 running 分离、高风险 write 的真人审批、可选 TOTP、审批后的 Apply、真实 Xray/Observe、双进程 UID/cgroup/资源、私有文件与其他 UID 拒绝、停止与重启免 reveal、更新/失败恢复/回滚、公共卸载进程回收与最终 purge。

普通测试不启用 Xray；以下显式开关和路径全部必需：

```bash
export QWQ_XRAY_E2E=1
export QWQ_E2E_TRUST_PUB='<构建产物 key.pub>'
export QWQ_E2E_XRAY_PKG_V1='<core.xray-0.1.1.qwq>'
export QWQ_E2E_XRAY_PKG_V2='<core.xray-0.1.2.qwq>'
export QWQ_E2E_XRAY_PKG_BAD='<仅故障测试 core.xray-0.1.3.qwq>'
export QWQ_E2E_RELEASE_TAR='<按现有 release-layout 打包的宿主 tar>'
# QWQ_E2E_PASSWORD 在执行时生成，经 stdin/环境传递，禁止写入报告。
./e2e.test -test.v -test.run '^TestXray(PackageArtifacts|PluginLifecycle)$' -test.timeout 14m
```

测试机只接收公开信任根、宿主 tar、签名包与已编译测试二进制。没有签名私钥传输。测试只绑定回环非特权动态端口，并使用当次生成的 UUID、REALITY 材料和临时 TLS 目标；不连接公网，不改宝塔、SSH 或防火墙。默认插件卸载按现有架构保留用户数据，最终宿主 `uninstall.sh --purge` 由既有夹具执行，新增核验确认消费者 DataDir 清除。

现有公共卸载已经实现：`internal/api/plugins.go:uninstallPlugin` 排队 updater operation，`internal/pluginhost/updater/remove.go` 执行实例停止、helper 清理与状态删除。任务卡历史“公共卸载未实现”描述已过时；本轮按当前真实路径验收。

历史审批连接/解密失败的请求保持未执行；用户权限切换后实际环境为全访问/网络启用/never，恢复执行不再传审批参数。真实客户端流量、故障注入和 1C1G 峰值仍归 X11；第三方许可证最终分类及候选汇总仍归 X12。此次正式包结果不证明真实进程生命周期已通过。

2026-11-16 契约复核：core.apply 有效风险为 high，默认策略等待真人批准；ADR-0004 指定 destructive 才强制 MFA。旧夹具已按既有契约修正，产品风险和审批规则保持原契约。第五轮资源探针已识别 systemd 启动执行器且正常退出，完整资源验收仍有缺口。
