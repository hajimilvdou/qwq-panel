// SPDX-License-Identifier: AGPL-3.0-only
/* ==========================================================================
 * 官方插件大白话介绍指南（应用中心点击弹窗 & 引擎插件工作台共用）
 * --------------------------------------------------------------------------
 * 全面杜绝空洞技术黑话与内部开发术语，用所有人一眼能看懂的语言说明：
 *   - 它是干什么用的
 *   - 支持哪些核心功能/协议
 *   - 默认资源占用建议
 * ========================================================================== */

export interface PluginHumanGuide {
  title: string;
  tagline: string;
  whatItDoes: string;
  highlights: readonly string[];
  defaults: {
    memory_max_mb: number;
    cpu_quota_percent: number;
    pids_max: number;
    fds_max: number;
    disk_max_mb: number;
  };
  tip?: string;
}

export const PLUGIN_GUIDES: Record<string, PluginHumanGuide> = {
  'security.basic': {
    title: '基础安全',
    tagline: '防火墙端口管理 · 安全改 SSH 端口 · 密钥与密码 · 防暴力破解',
    whatItDoes:
      '服务器必备安全管理台：可视化开关服务器防火墙端口、不断线安全修改 SSH 端口、管理登录密码和 SSH 公钥、自动封禁恶意爆破 SSH 的 IP，还支持一键备份并接管已有的 ufw / firewalld / fail2ban（随时可一键还原）。',
    highlights: [
      '一键放行/关闭 TCP & UDP 端口，自动锁定保留 SSH 与面板端口防失联',
      '双端口零断连 SSH 改端口向导，超时未确认自动回滚',
      '浏览器本地生成 SSH Ed25519 密钥对、导入公钥与修改系统用户密码',
      '自动检测 ufw / firewalld / fail2ban，支持备份原配置一键接管或随时还原',
    ],
    defaults: { memory_max_mb: 32, cpu_quota_percent: 20, pids_max: 16, fds_max: 128, disk_max_mb: 16 },
  },
  'monitor.basic': {
    title: '历史监控曲线',
    tagline: '更长时间段的 CPU / 内存 / 磁盘 / 网络趋势图表',
    whatItDoes:
      '面板主页本身已经自带实时资源监控（CPU、内存、磁盘、网络速率）。如果你希望在独立监控页里查看更长时间窗口的详细历史曲线和磁盘读写变化，可以选装本插件。',
    highlights: [
      '提供 5 分钟 / 15 分钟 / 更长窗口的连续趋势折线图',
      '轻量驻留内存，不影响低配 VPS 运行',
    ],
    defaults: { memory_max_mb: 24, cpu_quota_percent: 5, pids_max: 8, fds_max: 64, disk_max_mb: 16 },
  },
  'web.ingress': {
    title: '反向代理与建站',
    tagline: '域名反代本机服务 · 静态网站托管 · 自动 HTTPS · 限流保护',
    whatItDoes:
      '用来把你的域名指向本机运行的网站、应用端口或 Docker 容器，自动配好 HTTPS 加密访问，也支持直接托管静态网页、设置网站密码保护与单 IP 限流。',
    highlights: [
      '内置轻量反向代理引擎，无需手写复杂 Nginx 配置即可把域名绑定到任意端口',
      '支持 WebSocket、HTTPS 自动跳转、网站访问密码与防刷限流',
      '每次修改自动留存快照，配错随时一键回滚',
    ],
    defaults: { memory_max_mb: 32, cpu_quota_percent: 15, pids_max: 24, fds_max: 512, disk_max_mb: 128 },
  },
  'tls.certificates': {
    title: 'SSL / TLS 证书',
    tagline: '免费申请和自动续期 HTTPS 网站证书（支持泛域名）',
    whatItDoes:
      '自动为你的域名向 Let’s Encrypt 等机构免费申请 HTTPS/SSL 证书，到期前自动续期，免去手动上传续期的麻烦；也支持直接导入你已有的第三方证书。',
    highlights: [
      '支持单域名与 *.example.com 泛域名免费证书自动申请',
      '证书快到期时自动后台续期，并同步更新给反向代理、代理节点与探针',
      '私钥加密保存在宿主本地，不暴露明文',
    ],
    defaults: { memory_max_mb: 32, cpu_quota_percent: 10, pids_max: 16, fds_max: 128, disk_max_mb: 16 },
  },
  'domain.dns': {
    title: '域名 DNS 解析',
    tagline: '在面板里直接管理 Cloudflare、阿里云等域名解析记录',
    whatItDoes:
      '绑定 Cloudflare、阿里云等域名服务商 API 后，直接在面板里添加、修改、删除 A / AAAA / CNAME / TXT 解析记录，还能配合「SSL/TLS 证书」插件自动申请泛域名证书。',
    highlights: [
      '支持主流 DNS 服务商统一管理，无需反复登录域名商后台',
      '可视化增删改查解析记录并检验生效情况',
      '搭配证书插件可实现全自动泛域名 HTTPS 证书签发与续期',
    ],
    defaults: { memory_max_mb: 32, cpu_quota_percent: 10, pids_max: 16, fds_max: 128, disk_max_mb: 16 },
  },
  'containers.docker': {
    title: 'Docker 容器管理',
    tagline: '容器启停 · 日志查看 · 端口映射 · 镜像清理 · Compose 部署',
    whatItDoes:
      '在网页上直接管理服务器里的 Docker 容器和 Docker Compose 项目，轻松查看日志与资源占用、修改端口和内存限制、清理废弃镜像，还能一键给容器绑定反代域名。',
    highlights: [
      '直观展示容器状态、CPU/内存占用与实时滚动日志',
      '支持在线调整容器端口映射、环境变量与内存/CPU 限额',
      '支持 Docker Compose 编排文件在线部署与一键反代绑定域名',
    ],
    defaults: { memory_max_mb: 32, cpu_quota_percent: 15, pids_max: 24, fds_max: 256, disk_max_mb: 128 },
  },
  'server.probe': {
    title: '多机服务器探针',
    tagline: '多台 VPS 实时监控 · 90 天在线率 · 三网延迟测速 · 公开状态页',
    whatItDoes:
      '把你的多台 VPS 服务器汇总到一个美观的状态大屏上，实时查看每台机器的负载、流量、90 天在线率和电信/联通/移动三网延迟曲线，可对外分享状态页并更换自定义主题。',
    highlights: [
      '被控机器单向上报，无需开放额外入站端口更安全',
      '支持电信/联通/移动三网延迟测速曲线与 90 天历史在线率',
      '内置双套精美状态页风格，支持绑定公开域名和安装自定义主题包',
    ],
    defaults: { memory_max_mb: 32, cpu_quota_percent: 10, pids_max: 16, fds_max: 256, disk_max_mb: 128 },
  },
  'core.xray': {
    title: 'Xray 代理核心',
    tagline: '用于科学上网与加密代理转发的底层核心引擎（支持 VLESS / VMess / Trojan / SS2022 / Hysteria2 / AnyTLS）',
    whatItDoes:
      '负责实际跑代理转发流量的核心引擎，用于搭建科学上网 / 加密代理节点，支持 VLESS (Reality / Vision)、VMess、Trojan、Shadowsocks 2022、Hysteria2、AnyTLS、WireGuard / WARP 分流等主流协议，可导出节点分享链接与 Clash / sing-box 客户端配置。',
    highlights: [
      '支持协议：VLESS (Reality / Vision / WS / gRPC)、VMess、Trojan、Shadowsocks 2022、Hysteria2、AnyTLS',
      '支持 Cloudflare WARP 出站分流与 Reality 伪装域名测速',
      '支持导出单节点链接与 Clash / sing-box 配置文件',
    ],
    tip: '这是底层代理运行核心；如果你需要可视化图形界面来快速搭建节点、分配多用户流量配额和生成订阅链接，建议一并安装「高级代理与订阅中心」。',
    defaults: { memory_max_mb: 256, cpu_quota_percent: 100, pids_max: 64, fds_max: 4096, disk_max_mb: 64 },
  },
  'proxy.advanced': {
    title: '高级代理与订阅中心',
    tagline: '科学上网图形化建节点 · 多用户流量限速 · Clash / sing-box / Base64 订阅',
    whatItDoes:
      '科学上网与代理的完整可视化管理工作台：一键创建 VLESS Reality / Trojan / Hysteria2 / Shadowsocks 2022 / AnyTLS 节点，给不同用户设置流量限额、过期时间与网速限制，并自动生成 Clash / sing-box / Base64 客户端订阅地址。',
    highlights: [
      '新手向导一键搭建 Reality / Hysteria2 / VMess / Trojan / SS2022 / AnyTLS 节点',
      '多用户账号管理、流量配额、到期自动停用、连接数与带宽限速',
      '支持链式代理中转落地与网络加速参数调优',
      '自动生成 Base64 / Clash / sing-box 订阅链接，扫码即用（安装时自动连带安装 Xray 核心）',
    ],
    defaults: { memory_max_mb: 64, cpu_quota_percent: 25, pids_max: 16, fds_max: 4096, disk_max_mb: 32 },
  },
  'ai.relay': {
    title: 'AI API 中转站',
    tagline: '聚合 OpenAI / Claude / Gemini 密钥与订阅 · 协议互转 · 分发令牌计费',
    whatItDoes:
      '自建 AI 大模型接口中转站：把多个 OpenAI、Claude、Gemini 等 API Key 或订阅账号整合在一起，自动在不同协议间转换，支持多渠道轮询容灾，还能给朋友或团队分发子 Key 并限制额度。',
    highlights: [
      '统一聚合 OpenAI / Anthropic (Claude) / Gemini 多家接口与订阅池',
      '支持流式输出协议自动互转与多渠道负载均衡、失败自动切线路',
      '支持创建子 API Key、设置额度配额与独立自助查询页',
    ],
    defaults: { memory_max_mb: 64, cpu_quota_percent: 50, pids_max: 64, fds_max: 512, disk_max_mb: 256 },
  },
  'notify.hub': {
    title: '告警与消息通知',
    tagline: '把服务器告警实时推送到 Telegram、飞书、钉钉、企业微信、Discord 或邮箱',
    whatItDoes:
      '统一消息推送中心：配置一次机器人或邮箱，就能在服务器资源告警、SSH 暴力破解封禁、证书即将到期或面板重要变更时第一时间收到消息通知，并自动合并重复告警防刷屏。',
    highlights: [
      '支持 Telegram、飞书、钉钉、企业微信、Discord、邮箱 SMTP、自定义 Webhook',
      '可按告警级别和来源设置不同接收群组，支持冷却去重防刷屏',
      '所有推送密钥与 Token 均在宿主加密存储',
    ],
    defaults: { memory_max_mb: 24, cpu_quota_percent: 10, pids_max: 16, fds_max: 128, disk_max_mb: 64 },
  },
};

export function guideForPlugin(pluginId: string): PluginHumanGuide | undefined {
  return PLUGIN_GUIDES[pluginId];
}
