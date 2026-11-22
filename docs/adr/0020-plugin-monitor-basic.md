# ADR-0020：基础监控插件 `monitor.basic`

- 状态：Accepted（2026-11-13 用户批准全部待批准项;由 p6-mon 轨道实施）
- 日期：2026-11-13
- 关联：ADR-0009（首版范围：单机 CPU/内存/磁盘/网络/负载实时值 + 短期历史）、ADR-0019（Host Capability 传输与能力门）、ADR-0018（manifest 1.3 `ui.widgets`，p2-b 轨道）、ADR-0007（ABI 冻结）、ADR-0003（插件沙箱）；ARCH §5.4、§5.5、§5.6、§10.3、§13
- 编号：0020（0019 能力服务、0021 防护插件;0022 已预留 core.xray，额外 ADR 从 0023 起）

## 背景

`monitor.basic` 是首版两个业务插件之一，`placement=node`、内置（`publisher.id=qwq-builtin`），不进宿主（ADR-0009"业务全插件"）。范围：单机 CPU、内存、磁盘、网络、负载的**实时值 + 短期历史**。原型（`ui-design/prototype/plugins/monitor/`）已定 UI 形态：CPU/内存/磁盘三个液位仪表 + 网络吞吐（入/出）与负载（CPU/内存）两张 60 点流动图，采样间隔 1 秒、本地环形缓冲 60 点。

关键约束——**插件沙箱挡死了直接采集**：

- `PrivateNetwork=yes`：插件在私有 netns，`/proc/net/dev` 与 `/sys/class/net` 只反映私有 netns（仅 `lo`），**读不到宿主真实网卡统计**。
- `ProcSubset=pid` + `ProtectProc=invisible`：`/proc` 只暴露进程目录，`/proc/stat`、`/proc/meminfo`、`/proc/loadavg`、`/proc/diskstats` 等系统级文件被隐藏。
- `ProtectSystem=strict`、空 `CapabilityBoundingSet`：插件无特权，但上述指标本就世界可读，问题不在权限而在**命名空间隔离**。

因此"插件直接读 `/proc`"在默认沙箱下不可行;放宽 `PrivateNetwork=no` 会让一个低风险指标插件获得宿主 netns（可嗅探/连接），与 `metrics.read:self` 的 RiskLow 定级不相称。本 ADR 选定**宿主代读**：采集源仍是 `/proc`、`/sys`，但由宿主（agent）在宿主 netns 与完整 `/proc` 下读取，经一个低风险能力服务返回结构化指标;插件保持完整沙箱，只维护内存环形缓冲与渲染数据。

## 决策 1：采集形态——宿主 metrics 能力服务（选定）

### 候选评估

| 候选 | 说明 | 结论 |
|---|---|---|
| A. 宿主 metrics 能力服务，agent 代读 `/proc`、`/sys` | 插件经 `metrics.read:self` 调 `ReadMetrics`，agent 在宿主 netns 读真实指标 | **选定** |
| B. 放宽插件沙箱直读（`ProcSubset=all` + `PrivateNetwork=no`） | 插件自己读 `/proc` | 拒绝：`PrivateNetwork=no` 给低风险插件宿主 netns，隔离损失与定级不相称;`ProcSubset=all` 暴露更多 `/proc` |
| C. bind-mount 宿主 `/proc` 文件进插件 ns | 只读绑定 `/proc/stat` 等 | 拒绝：`/proc/net/dev` 是 per-netns，绑定无法得到宿主网卡统计;虚拟文件绑定脆弱 |
| D. 宿主采集后经事件推送 | 宿主定时 publish 指标事件 | 拒绝：推送模型重，指标会刷爆 journal;小组件本就是拉模型 |

选 A 的理由：

1. **插件零沙箱放宽**：`monitor.basic` 用与 noop 相同的默认沙箱（`PrivateNetwork=yes`、`ProcSubset=pid`），不请求任何放宽项，攻击面最小。
2. **准确**：agent 在宿主 netns 与完整 `/proc` 下读，网络/磁盘/CPU 都是宿主真实值。
3. **无需 root**：`/proc/stat`、`/proc/meminfo`、`/proc/loadavg`、`/proc/diskstats`、`/proc/net/dev`、`/sys/class/net/*/statistics` 均世界可读，`statfs` 无需特权。metrics 转发器**在 agent 进程内本地实现**，不经 `qwq-capability` root helper（区别于 ADR-0019 的四个高敏能力）。
4. **可复用**：第三方监控插件可用同一 `metrics.read:self` 能力做替代品（ADR-0009 目标）。
5. **复用 ADR-0019 传输**：能力服务挂在每插件 host UDS，经同一 `prepareCall`（`SO_PEERCRED`+token）与能力门;只是 forwarder 是 agent 本地读，无 root 往返。

### 能力服务 `qwq.capability.metrics.v1.MetricsService`

- 文件：`api/qwq/capability/metrics/v1/metrics.proto`，package `qwq.capability.metrics.v1`，生成 `sdk/gen/qwq/capability/metrics/v1/`（ADR-0019 同一布局/版本规则，不进 ABI）。
- capability：`metrics.read:self`（scope `self` = 当前节点自身指标，ARCH §10.3）。`operations.capabilityFloor` 对 `metrics.read` 返回 `RiskLow`，读操作保持 low。
- 这是 ADR-0019 四能力之外的**第五个能力 package**，由本 ADR 引入;传输/能力门/SDK 复用 ADR-0019，forwarder 为 agent 本地（无 `qwq-capability`）。

| RPC | 请求 | 返回 | effect/风险 |
|---|---|---|---|
| `ReadMetrics` | `{}` | `MetricsSnapshot`（见下） | read/low |

`ReadMetrics` 是**瞬时采样**：agent 每次读取当前计数器原值与时间戳，**速率/百分比由插件按相邻两次采样差分计算**（agent 无状态，不为每插件维护上一次采样）。这样 agent 侧无每插件状态，插件重启后只需两次采样即可恢复速率。

```proto
message MetricsSnapshot {
  int64  collected_at_unix_ms = 1;   // agent 采样时刻
  Cpu    cpu    = 2;
  Memory memory = 3;
  repeated Disk   disks   = 4;       // 每挂载点/设备
  repeated NetIf  nets    = 5;       // 每接口（含宿主真实网卡）
  Load   load   = 6;
  uint64 uptime_seconds = 7;
}
message Cpu {
  // /proc/stat 聚合 cpu 行的累计 jiffies（差分算使用率）
  uint64 user=1; uint64 nice=2; uint64 system=3; uint64 idle=4;
  uint64 iowait=5; uint64 irq=6; uint64 softirq=7; uint64 steal=8;
  uint32 core_count=9;
}
message Memory {
  uint64 total_bytes=1; uint64 available_bytes=2; uint64 buffers_bytes=3;
  uint64 cached_bytes=4; uint64 swap_total_bytes=5; uint64 swap_free_bytes=6;
}
message Disk {
  string device=1; string mount=2;
  uint64 total_bytes=3; uint64 used_bytes=4;   // statfs
  uint64 read_sectors=5; uint64 write_sectors=6; uint64 io_ticks_ms=7; // /proc/diskstats 累计
}
message NetIf {
  string name=1;
  uint64 rx_bytes=2; uint64 tx_bytes=3; uint64 rx_packets=4; uint64 tx_packets=5; // /proc/net/dev 累计
}
message Load { double load1=1; double load5=2; double load15=3; } // /proc/loadavg
```

- 采集源（agent 侧，全部只读、无 root）：
  - CPU `/proc/stat`;内存 `/proc/meminfo`;负载 `/proc/loadavg`; uptime `/proc/uptime`。
  - 磁盘容量 `statfs(mount)`（默认 `/`，可配）;磁盘吞吐 `/proc/diskstats`（sector=512B）。
  - 网络 `/proc/net/dev`（宿主 netns，真实网卡）;可选 `/sys/class/net/<if>/statistics` 交叉校验。
- agent 读取失败（某文件缺失/接口消失）→ 该字段缺省，`ReadMetrics` 仍返回其余指标;整体不可用 → `UNAVAILABLE`。
- 能力门：`metrics.read:self` 在 `GrantedCapabilities` 中即可;读操作不需 operation_id（ADR-0019 决策 4）。限频：每实例 `ReadMetrics` 令牌桶默认每秒 ≤ 2 次（配合 1s 采样，留余量），超限 `RESOURCE_EXHAUSTED`。

## 决策 2：历史存储——插件内存环形缓冲（选定）

### 候选评估

| 候选 | 说明 | 结论 |
|---|---|---|
| A. 插件内存环形缓冲 | 定长环，实时值 + 短期历史，重启即重建 | **选定** |
| B. hostsvc State（KV） | 每秒写历史进 KV | 拒绝：State 是带 revision/配额的持久 KV，每秒写造成磁盘 churn 与配额压力;`kv_max_kb` 默认 4 MiB、单值 1 MiB，时序数据挤占配置/状态配额;1C1G 下磁盘 I/O 与内存都不划算 |
| C. 插件私有 SQLite | 时序落盘 | 拒绝：短期历史无需持久化，SQLite 增加磁盘/内存/迁移负担，违背 1C1G 预算 |

选 A 的理由：短期历史**本就是易失的**（实时仪表只关心最近几分钟到一小时），重启后实时值立即恢复、历史从零重建是可接受的;内存环形缓冲零磁盘 I/O、内存占用可精确封顶、实现简单。State 仅用于少量配置/游标（`kv_max_kb=64`），不存时序。

### 缓冲规格与保留期

- **细环**：1s 分辨率，`fine_points=300`（5 分钟），供实时流动图与小组件 series（小组件取最近 60 点，与原型一致）。
- **粗环**：10s 分辨率，`coarse_points=360`（1 小时），供详情页短期历史。粗环由细环每 10s 降采样（取均值）写入。
- 每点字段：`cpu_pct, mem_pct, disk_pct, net_rx_bps, net_tx_bps, load1, disk_read_bps, disk_write_bps`（8 个 float64）。
- 内存量级：`(300+360) × 8 × 8B ≈ 42 KiB` 原始数据，加 Go 切片/对象开销封顶 < 1 MiB。相对 `GOMEMLIMIT≈20MiB` 可忽略。
- 保留期：细 5 分钟、粗 1 小时，超出即被环形覆盖;均可经 config 调整（上限受内存预算约束，`fine_points≤600`、`coarse_points≤720`）。
- 重启语义：`Activate` 启动采样定时器，环为空;两次采样后速率恢复，历史随时间填满。`Deactivate` 停定时器。蓝绿更新时历史短暂重置（监控可接受，见决策 5）。

### 速率计算（插件侧）

- CPU% = `1 - (idle_delta + iowait_delta) / total_delta`（相邻两次 `Cpu` 差分，clamp 0-100）。
- 内存% = `(total - available) / total × 100`。
- 磁盘% = `used / total × 100`（每挂载点，小组件取根挂载）。
- 网络 bps = `(rx_bytes_delta × 8) / dt`（每接口求和，排除 `lo`，可配接口白名单）;原型以 Mbps 显示 = `bps / 1e6`。
- 磁盘吞吐 bps = `sector_delta × 512 / dt`。
- 负载直接取 `load1/5/15`。
- 首次采样（无上一次）只存原值，速率字段为 0/缺省，不报错;计数器回绕（重启/溢出）→ 该次速率置缺省。

## 决策 3：operation 与小组件（manifest 1.3）

所有 operation `effect=read`、`mode=invoke`、`risk=low`、`permission=monitor.basic:read`（资源段=插件 id，ADR-0014）；读路径**不写 operations 表**（引用 p2-b 步骤 10"小组件数据调用约定"的读豁免）。需要采样的 operation 声明 `capabilities:[{name: metrics.read, scope: self}]`。小组件 operation 的 request schema 必须接受空 payload `{}`（ADR-0018 规则 3）。

### 小组件（`ui.widgets[]`，Shell 原生渲染，空 payload 轮询）

| id | kind | operation | refresh_seconds | size | 数据 |
|---|---|---|---|---|---|
| `cpu` | stat | `monitor.stat.cpu` | 2 | s | CPU 使用率 |
| `mem` | stat | `monitor.stat.mem` | 2 | s | 内存使用率 |
| `disk` | stat | `monitor.stat.disk` | 5 | s | 根盘使用率 |
| `net` | series | `monitor.series.net` | 2 | m | 入/出吞吐最近 60 点 |
| `load` | series | `monitor.series.load` | 2 | m | CPU/内存最近 60 点 |

- `refresh_seconds≥2`（schema 下限）;宿主另按"用户 + 小组件"限流，不信任客户端节奏（ADR-0018）。小组件轮询触发插件从内存环取最近数据（必要时补一次 `ReadMetrics`），**不**每秒打 agent。
- 结果形状（**待批准**：须与 p2-b 步骤 10 的小组件数据约定 / Web Shell 渲染器对齐;ADR-0018 只固定 kind 不固定 JSON，下列为本 ADR 提案）：
  - `stat`：`{value: number, unit: string, max?: number, warn?: number, crit?: number, label?: string}`。例 CPU `{value:25.3, unit:"%", max:100, warn:70, crit:90, label:"1 vCPU"}`。
  - `series`：`{series:[{name: string, unit: string}], points:[{t: number, values: number[]}], max?: number}`。例 net `{series:[{name:"入",unit:"Mbps"},{name:"出",unit:"Mbps"}], points:[{t:1731…, values:[40.1,12.3]}, …60], max:100}`。
  - `checks`/`list`：本插件首版不用;形状留待防护插件（0021）与 Shell 约定统一。
- 非法结果只让该卡片报错（ADR-0018），不影响其他卡片。

2026-11-15 实施对齐：当前 Shell `web/shell/src/lib/widgets/index.ts` 已采用 stat 的 `value/unit/sub/percent/spark/level`，series 的 `unit/max/series[{name,color,points:[[t,value]]}]`。monitor.basic 复用该实际契约；不引入第二套小组件格式。采样缺失/重置保留 null 或受控 unavailable，不显示虚构零值。详情页沿用既有令牌；随包副本保持 Apache-2.0 与许可证说明。

### 详情页 operation（插件 UI 页，经 MessagePort 调宿主代理的本插件 operation）

| operation | 请求 | 返回 |
|---|---|---|
| `monitor.snapshot` | `{}` | 当前全部实时值 + 细环最近 300 点（详情页仪表与流动图） |
| `monitor.history` | `{range: "5m"|"1h", metric?: string}` | 粗环短期历史（默认 1h） |

- `monitor.snapshot`/`monitor.history` 同样 read/invoke/low，request schema 接受 `{}`（`history` 的 `range` 可选、默认 `1h`）。
- 详情页 UI 走 `ui/` 沙箱 iframe（ADR-0018/ARCH §5.5），经 MessagePort 只代理本插件 operation 命名空间;`ui.entry=ui/index.html`，`sandbox=true`，`connect_sources=[]`（无外部连接）。

### manifest 要点（1.3）

```jsonc
{
  "schema_version": "1.3",
  "id": "monitor.basic", "placement": "node",
  "publisher": { "id": "qwq-builtin", "key_id": "ed25519:…" },
  "abi": { "major": 1, "minimum_minor": 0 },
  "lifecycle": { "startup": "eager", "background": true, "update_strategy": "auto" },
  "capabilities": [ { "name": "metrics.read", "scope": "self", "reason": "读取本节点 CPU/内存/磁盘/网络/负载" } ],
  "operations": [ /* 上述 7 个 read/invoke/low，permission monitor.basic:read */ ],
  "ui": {
    "entry": "ui/index.html", "sandbox": true, "connect_sources": [],
    "routes": [ { "path": "/monitor", "title": "监控", "nav": true, "permission": "monitor.basic:read" } ],
    "widgets": [ /* 上表 5 个 */ ]
  },
  "config": { "schema": "schemas/config.schema.json", "hot_apply": true },
  "state": { "schema_version": "1", "minimum_rollback_version": "0.1.0", "backup_paths": [] },
  "resources": { "memory_max_mb": 24, "cpu_quota_percent": 5, "pids_max": 8, "fds_max": 64, "disk_max_mb": 16, "kv_max_kb": 64 }
}
```

- `state.backup_paths=[]`：不请求宿主 DataDir（区别于 core.xray，见边界登记），保持 noop 式 `DataDir=""` 单元行为;历史易失，无需持久目录。
- `background=true`：采样定时器在 `Activate` 后启动（ADR-0007，两代不双跑后台）。

## 决策 4：config schema（hot_apply）

```jsonc
{
  "sample_interval_ms": 1000,      // 细采样，[500, 5000]
  "coarse_interval_ms": 10000,     // 粗采样，[5000, 60000]
  "fine_points": 300,              // [60, 600]
  "coarse_points": 360,            // [60, 720]
  "disk_mounts": ["/"],            // 监控挂载点，默认根
  "net_interfaces": [],            // 空=全部非 lo;否则白名单
  "thresholds": { "cpu": {warn:70,crit:90}, "mem": {warn:75,crit:90}, "disk": {warn:80,crit:92} }
}
```

- `ValidateConfig` 校验范围;`ApplyConfig` 热调整采样间隔/环长/阈值（环长变更时重建环，历史清空，提示用户）。
- 阈值只影响小组件 stat 的 warn/crit 着色，不产生告警 operation（告警策略属后续安全插件，ADR-0009）。

## 决策 5：1C1G 资源预算与生命周期

- `memory_max_mb=24` → `GOMEMLIMIT≈20MiB`、`MemoryHigh≈21M`（ARCH §13）;环 < 1 MiB，Go 运行时 + gRPC 缓冲余量充足。
- `cpu_quota_percent=5`：插件大部分时间睡眠，每秒一次差分 + 渲染数据，5% 足够。
- `pids_max=8`、`fds_max=64`：单进程 + host conn + 少量定时器。
- `disk_max_mb=16`、`kv_max_kb=64`：只存配置/游标，不存时序。
- agent 侧 `ReadMetrics` 是读几个 `/proc` 文件 + `statfs`，无每插件状态、无 root、无磁盘写;每实例每秒 ≤ 2 次限频。
- 更新：`update_strategy=auto`，`overlap_safe=true`（蓝绿短暂双跑 2×24M，preflight 通过）;历史在 `Activate` 时重置，监控可接受短暂空窗。若内存紧张，updater 自动降级受控重启（ARCH §6.3）。

## 测试纪律（ADR-0009）

- **构建机单测**：fake `MetricsService`（注入固定/序列 `MetricsSnapshot`）测差分速率、计数器回绕、环覆盖/降采样、小组件形状、config 校验/热apply;能力门用 fake `OperationResolver`/`GrantedCapabilities`。全部不碰真实系统。
- **agent 采集器单测**：用录制的 `/proc/stat`、`/proc/meminfo`、`/proc/net/dev`、`/proc/diskstats`、`/proc/loadavg` 样本（testdata）测解析;`statfs` 用 fake。
- **集成（只读，低风险）**：在测试机读真实 `/proc` 校验数值合理性——标注"**测试机执行，届时先经用户确认**";监控只读，不改系统，但仍遵守不在设计里安排碰测试机的纪律。
- 小组件形状契约测试：与 p2-b 步骤 10 / Web Shell 渲染器对齐后，加形状夹具（stat/series）。

## 已批准项（2026-11-13 用户批准）

1. **宿主 metrics 能力服务**（`qwq.capability.metrics.v1`，agent 代读 `/proc`、`/sys`，`metrics.read:self`）而非放宽插件沙箱直读。
2. **内存环形缓冲**（细 5 分钟 / 粗 1 小时，重启重建）而非 State/SQLite 持久化。
3. **小组件结果形状**（stat/series JSON）须与 p2-b 步骤 10 小组件数据约定 / Web Shell 渲染器对齐（本 ADR 提案待确认）。
4. 第五个能力 package `metrics`（低风险、agent 本地 forwarder，复用 ADR-0019 传输）。

## 边界登记（core.xray，只读参考）

- core.xray 的持久 **DataDir** 供给（`InitializeRequest.data_dir` + `state.backup_paths` 非空信号 + `StateDirectory=`）：`monitor.basic` **不**使用（`backup_paths=[]`、`DataDir=""`），历史易失。若未来需要持久历史，复用 core.xray 的 DataDir 机制，不另造。
- core.xray 的 `network.proxy:direct` 是精确 `(name,scope)` 网络放宽，与本插件 `metrics.read:self` 无交集;monitor 不请求任何网络放宽。

## 代价

- 新增第五个能力 package（metrics）与 agent 本地采集器;插件侧差分/环/渲染逻辑。
- 历史易失：重启/更新后短期历史从零重建（监控语义可接受）。
- 小组件形状需与 Shell 渲染器对齐，存在跨轨道协调成本。
