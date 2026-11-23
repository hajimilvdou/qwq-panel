# `qwq` 探针前台主题制作规范

> 适用插件：`server.probe`（ABI `v1`，主题契约 `api_version: "1"`）  
> 目标受众：希望为 `qwq` 服务器探针编写个性化公开展示页的社区主题作者与二次开发者。

---

## 1. 架构隔离原则（不透明源沙箱 + 后台防崩盘）

`qwq` 服务器探针采用**前后台物理路由隔离 + 第三方主题不透明源（Opaque Origin）沙箱隔离**设计：

| 路由前缀 | 归属 | 主题能否接管 | 说明 |
| --- | --- | --- | --- |
| `/` 与 SPA 回退路径 | 官方内置沙箱宿主 `theme-sandbox.html` | **由官方宿主承载** | 当激活第三方主题时，`/` 仅输出官方沙箱页，通过 `<iframe sandbox="allow-scripts" src="./theme-frame/<entry>">` 承载第三方主题 |
| `/theme-frame/*` | 当前激活的第三方主题 | **完全接管（不透明源沙箱）** | 所有响应强制附带 `X-QWQ-Theme-Sandbox: 1`，宿主网关自动下发严格沙箱 CSP（`sandbox allow-scripts; default-src 'none'; img-src 'self' data: blob: https:; connect-src 'none';`），零权限访问宿主 `Cookie`、`sessionStorage`、`/api/v1/*` 与 `/api/admin/*` |
| `/theme-frame/__qwq_bridge.js` | 官方注入桥接脚本 | **自动注入** | 服务端在第三方主题 `.html` 的 `<head>` 起始位置自动注入 `<script src="./__qwq_bridge.js"></script>`，通过 `postMessage` 透明代理 `./api/public/snapshot`、`./api/public/unlock`、`./api/public/bg`（仅限公开只读/解锁接口）与 `./admin` 跳转链接 |
| `/admin`、`/admin/*`、`/admin.css`、`/admin.js` | 官方内置管理后台 | **永久禁止接管** | 始终由插件内置 `portal_ui/admin.*` 提供，即使第三方主题代码报错或白屏，管理员随时访问 `/admin` 即可一键切回官方风格 |
| `/api/public/*`、`/api/admin/*`、`/api/ai/v1/*`、`/api/probe/v1/*` | 插件后端网关 | **永久禁止接管** | 统一提供脱敏公开数据快照、壁纸流、访客解锁与管理接口 |

> [!IMPORTANT]
> 第三方主题包运行在浏览器不透明源（`null` origin）`<iframe sandbox="allow-scripts">` 内，且即使包含 `admin.html` 或 `admin/index.html` 也绝无法劫持 `/admin` 或读取同源敏感凭据。同时，如果激活的自定义主题目录意外缺失或入口文件损坏，网关会自动无缝回退至官方内置前台页面。

---

## 2. `.qwqtheme.zip` 目录规范与安全限制

### 2.1 标准目录结构

推荐将主题打包为标准 `.zip`（习惯后缀 `.qwqtheme.zip`）。支持根目录平铺，也支持**自动解包单层顶层文件夹**（如 `my-cyber-theme/theme.json`）：

```text
my-cyber-theme.qwqtheme.zip
├── theme.json          # 必填：主题清单与可视化配置 Schema
├── index.html          # 必填（由 entry 指定）：前台入口 HTML
├── style.css           # 样式文件
├── app.js              # 前端逻辑（消费 /api/public/snapshot）
└── assets/             # 可选：图标、字体、装饰图片
    └── logo.svg
```

### 2.2 体积与静态文件白名单

上传或通过 HTTPS URL 拉取安装时，服务端会执行以下强校验（任一项不满足即拒绝安装）：

- **总压缩包 / 解压总大小上限**：`16 MiB`
  - **独立 `/admin` 后台原始二进制直传**（`Content-Type: application/zip`）与 **HTTPS URL 远程拉取**：支持完整 `16 MiB`；
  - **`qwq` 主面板内嵌页直接上传**（经 `postMessage` JSON/Base64 桥接，上限 4 MiB）：支持最大约 `2.9 MiB` 压缩包（3–16 MiB 主题包请使用 `/admin` 后台直传或 HTTPS URL 安装）。
- **单文件解压大小上限**：`4 MiB`
- **最多文件数量**：`256` 个
- **严禁路径穿越与符号链接**：拒绝包含 `..`、绝对路径、Windows 盘符、控制字符及任意 symlink / 特殊设备文件
- **允许的静态文件扩展名白名单**：
  - 网页与脚本：`.html`, `.css`, `.js`, `.mjs`, `.json`, `.txt`, `.map`
  - 图片与图标：`.svg`, `.png`, `.jpg`, `.jpeg`, `.webp`, `.gif`, `.ico`
  - 字体：`.woff`, `.woff2`, `.ttf`, `.otf`
  - 其余扩展名（如 `.sh`, `.php`, `.exe`, `.so`, `.wasm` 等）一律拦截拒绝。

### 2.3 沙箱 CSP、自动桥接与相对路径纪律

第三方自定义主题运行在严格的**不透明源沙箱 CSP**下（`sandbox allow-scripts; default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; font-src 'self' data:; connect-src 'none';`），并由官方自动注入 `./__qwq_bridge.js`：

1. **禁止内联 `<script>` 与 `on*=` 事件属性**：所有 JS 必须放在外部 `.js` 文件中通过 `<script src="app.js" defer></script>` 引入。
2. **直接使用相对路径调用公开接口即可**：`./__qwq_bridge.js` 会自动拦截 `fetch('./api/public/snapshot')`、`fetch('./api/public/unlock', ...)` 与 `fetch('./api/public/bg')`，经由 `postMessage` 向官方父窗口安全代理，主题作者无需编写任何额外桥接代码；同时 `img-src` 允许 `'self' data: blob: https:`，外链 HTTPS 壁纸与本地 `./api/public/bg` 均可直接渲染。
3. **禁止尝试直连 `/api/admin/*`、`/api/v1/*` 或外部网络**：沙箱 CSP 已设置 `connect-src 'none'`，任何非公开接口请求都会被浏览器拦截。
4. **对节点名、分组、公告等动态文本务必做 HTML 转义**，防止 XSS。

---

## 3. `theme.json` 清单规范

```json
{
  "id": "my-cyber-theme",
  "name": "Cyberpunk Glass",
  "version": "1.0.0",
  "author": "alice",
  "description": "赛博霓虹透明水玻璃探针展示主题，支持自定义强调色与紧凑布局。",
  "api_version": "1",
  "entry": "index.html",
  "settings_schema": [
    {
      "key": "accent",
      "label": "品牌强调色",
      "type": "color",
      "default": "#38bdf8",
      "description": "用于按钮、高亮边框与实时状态徽章"
    },
    {
      "key": "show_subtitle",
      "label": "显示站点副标题",
      "type": "boolean",
      "default": true
    },
    {
      "key": "card_density",
      "label": "卡片密度",
      "type": "select",
      "options": ["comfortable", "compact"],
      "default": "comfortable"
    }
  ]
}
```

### 字段校验规则

| 字段 | 必填 | 约束说明 |
| --- | --- | --- |
| `id` | 是 | 匹配 `^[a-z0-9][a-z0-9._-]{1,47}$`，不得以 `builtin:` 开头，不得包含 `..` |
| `name` | 是 | 展示名称，最长 80 字符 |
| `version` | 是 | 语义化版本号（如 `1.0.0`），最长 32 字符 |
| `author` | 否 | 作者名或主页标识，最长 64 字符 |
| `description` | 否 | 主题简介，最长 240 字符 |
| `api_version` | 否 | 固定 `"1"`（留空默认 `"1"`） |
| `entry` | 是 | 相对路径 `.html` 文件（默认 `"index.html"`），必须真实存在于压缩包内 |
| `settings_schema` | 否 | 最多 32 项。每项含 `key`（`^[a-zA-Z0-9_-]{1,48}$`）、`label`、`type`（`text` \| `color` \| `number` \| `boolean` \| `select`）、`default`、`options`（`select` 时填写）。用户在 `/admin` 或 `qwq` 面板中保存后，值会直接透传到 `/api/public/snapshot` 的 `theme_settings` 字段。 |

---

## 4. 公开数据契约详解

### 4.1 `GET ./api/public/snapshot`

核心实时快照接口（建议每 3 秒轮询一次，并在 `document.hidden === true` 时暂停轮询以省电省流）。

当探针开启了**私有访客口令保护**且未携带有效令牌时，接口返回 `HTTP 423 Locked`：

```json
{
  "locked": true,
  "site_title": "qwq Probe · 全球服务器实时探针",
  "message": "当前探针已启用私有访问保护，请输入访客查看口令"
}
```

正常返回 `HTTP 200 OK`：

```json
{
  "server_time_unix": 1795400000,
  "site_title": "qwq Probe · 全球服务器实时探针",
  "site_subtitle": "单向零入站安全遥测 · 90 天 SLA 在线率与三网延迟实时大盘",
  "default_view": "orb-cards",
  "default_palette": "oat-berry",
  "allow_theme": true,
  "banner_level": "ok",
  "banner_text": "所有监控节点与拨测链路运行正常",
  "active_theme": "my-cyber-theme",
  "admin_path": "./admin",
  "bg_url": "./api/public/bg?v=r5",
  "appearance": {
    "glass_opacity": 0.26,
    "glass_blur_px": 20,
    "glass_tint": "auto",
    "veil_opacity": 0.22,
    "motion_enabled": true,
    "accent_color": "#38bdf8",
    "custom_css": "",
    "background": {
      "mode": "local",
      "local_file": "bg.webp",
      "external_url": "",
      "lqip_data_url": "data:image/jpeg;base64,/9j/4AAQ...",
      "focal_x": 50,
      "focal_y": 0,
      "luminance": 172,
      "dominant_rgb": "188,210,235"
    }
  },
  "theme_settings": {
    "accent": "#38bdf8",
    "show_subtitle": true,
    "card_density": "comfortable"
  },
  "nodes": [
    {
      "id": "hk-01",
      "name": "香港 CN2 GIA · 01",
      "region_code": "HK",
      "group_name": "亚太主力",
      "tags": ["CN2 GIA", "1Gbps"],
      "is_local": false,
      "online": true,
      "os_name": "Debian 12",
      "arch": "amd64",
      "virt_type": "kvm",
      "cpu_cores": 2,
      "mem_total_bytes": 2147483648,
      "swap_total_bytes": 1073741824,
      "disk_total_bytes": 42949672960,
      "has_ipv4": true,
      "has_ipv6": true,
      "quota_bytes": 1099511627776,
      "quota_used_bytes": 128849018880,
      "quota_mode": "max",
      "reset_day": 15,
      "provider_name": "DMIT",
      "billing_badge": "$36.90/年",
      "expires_in_days": 142,
      "uptime_90d_pct": 99.98,
      "sla_ribbon": [
        {
          "day": "2026-11-23",
          "total_checks": 43200,
          "up_checks": 43198,
          "uptime_pct": 99.99,
          "downtime_sec": 4,
          "avg_latency_ms": 34
        }
      ],
      "live": {
        "sampled_at": 1795399999,
        "cpu_pct": 18.4,
        "mem_used_bytes": 734003200,
        "swap_used_bytes": 0,
        "disk_used_bytes": 9663676416,
        "net_rx_bps": 12400000,
        "net_tx_bps": 28600000,
        "load1": 0.24,
        "load5": 0.19,
        "load15": 0.15,
        "tcp_conns": 84,
        "udp_conns": 12,
        "process_count": 116,
        "uptime_seconds": 1843200,
        "carrier_ping_ms": { "ct": 31, "cu": 38, "cm": 44 }
      }
    }
  ],
  "service_monitors": []
}
```

### 4.2 `POST ./api/public/unlock`

当快照返回 `423 Locked` 时，提交访客口令换取短期 `X-Probe-Visitor-Token`：

- 请求：`{ "password": "visitor-secret" }`
- 响应 `200 OK`：`{ "visitor_token": "prb_vis_..." }`
- 后续请求 `GET ./api/public/snapshot` 时在请求头附加 `X-Probe-Visitor-Token: prb_vis_...` 即可。

### 4.3 `GET ./api/public/bg`

当管理员上传了本地壁纸（经浏览器 Canvas 压缩为 WebP/JPEG/PNG，≤ 2 MiB）时，由该端点直接输出二进制图片，响应头自动附带：

- 精确 `Content-Type`（`image/webp` / `image/jpeg` / `image/png`）
- `X-Content-Type-Options: nosniff`
- `Cache-Control: public, max-age=3600` 与 `ETag`
- 请直接使用快照中自带版本参数的 `bg_url`（如 `./api/public/bg?v=r5`）以实现换图即刻刷新缓存。

---

## 5. 复用 `appearance` 水玻璃参数、LQIP 与 9 宫格焦点最佳实践

强烈建议第三方主题复用后台已经配置好的 `appearance` 光学参数，这样用户在后台调节滑块和上传壁纸时，你的主题无需额外配置即可自动响应：

1. **零闪烁渐进壁纸加载（LQIP → HD Crossfade）**：
   - 先用 `appearance.background.lqip_data_url` 立即渲染底层模糊预览图（`filter: blur(22px); transform: scale(1.08)`）；
   - 同时加载高清 `bg_url`，在 `img.decode()` 完成后将高清图 `opacity` 从 `0` 过渡到 `1`；
   - 监听 `onerror`，外链或壁纸加载失败时无缝回退至渐变背景。
2. **尊重 9 宫格构图焦点**：
   - 将壁纸 `<img>` 设置 `object-fit: cover`，并用 `appearance.background.focal_x` / `focal_y` 驱动 `object-position: ${focal_x}% ${focal_y}%`，确保人像/竖图不裁切主体。
3. **自动浅冰/深曜玻璃色调与可读性保障**：
   - 当 `appearance.glass_tint === "auto"` 时，参考 `appearance.background.luminance`：`> 145` 使用浅冰玻璃深色字，`<= 145` 使用深曜玻璃浅色字；
   - 叠加护眼遮罩层 `rgba(..., appearance.veil_opacity)`，并在卡片内给关键数字套上高对比半透明 Chip，确保任何亮暗壁纸下文字都清晰锐利。
4. **尊重减弱动效偏好**：
   - 当 `appearance.motion_enabled === false` 或用户系统开启 `prefers-reduced-motion: reduce` 时，停止背景漂移与指针高光动画。
5. **保留后台入口**：
   - 在页头或页脚放置 `<a href="./admin">管理后台</a>`（或读取 `snapshot.admin_path`），方便站长一键进入官方隔离后台。

---

## 6. 从零制作、打包与安装完整流程

### 步骤 1：一键获取官方起步模板

- **在独立后台 `/admin`**：进入「主题中心」→ 点击「下载官方主题模板 `.zip`」（调用 `GET /api/admin/themes/starter.zip`）。
- **在 `qwq` 主面板内嵌页**：进入「服务器探针」→ 切换到「主题与水玻璃」→ 点击「下载官方主题模板 `.zip`」。

### 步骤 2：修改与打包

解压模板后，修改 `theme.json` 中的 `id`、`name`、`version` 以及 `index.html` / `style.css` / `app.js`，然后重新打包：

```bash
cd my-cyber-theme
zip -r ../my-cyber-theme.qwqtheme.zip theme.json index.html style.css app.js assets/
```

### 步骤 3：安装与启用（任选一种）

1. **拖拽上传**：在 `/admin` 或面板内嵌「主题中心」直接将 `.qwqtheme.zip` 拖入上传区；
2. **HTTPS URL 一键远程安装**：将压缩包托管至 GitHub Releases 或任意公网 HTTPS CDN，粘贴链接点击「拉取并安装主题」即可（服务端内置防 SSRF / DNS Rebinding 校验，仅允许公网 HTTPS）；
3. **一键切换与调参**：点击主题卡片上的「启用」，并在下方自动生成的主题专属配置表单与水玻璃滑块中微调参数，即时生效。
