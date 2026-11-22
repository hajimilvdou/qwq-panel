# ADR-0027：双端 IPv4/IPv6 多地址选择与 MIT 洁净中国分流规则引擎

- 状态：Accepted
- 日期：2026-11-21
- 关联：Track 05（`IP-1 ~ IP-6`、`RULE-1 ~ RULE-5`）、Track 03（`core.xray` v2 出站 `domainStrategy`/`sendThrough`）、Track 04（`proxy.advanced` 客户端订阅生成）

## 1. 两跳网络解耦原则

1. **第一跳（Client → VPS 入站候选策略）**：
   - 支持配置多个入站候选（域名、多个公网 IPv4、多个公网 IPv6、备选端口）与独立地址族策略（`ipv4_only` / `ipv6_only` / `prefer_ipv4` / `prefer_ipv6`）；
   - 单栈模式严禁越界回退；双栈首选模式遵循 RFC 8305 有界抢跑（`250ms`）与失败候选指数退避冷却（`30s -> 5m`），全冷却时保留最早到期候选探测恢复。
2. **第二跳（VPS → 目标站出站策略）**：
   - 与第一跳完全解耦，通过 Xray `freedom` 出站 `domainStrategy`（`UseIPv4` / `UseIPv6` / `UseIPv4v6` / `UseIPv6v4`）与可选多源 IP `sendThrough` 及按域名后缀覆盖规则实现；
   - 宿主通过无特权内核接口（`net.Interfaces()` + `/proc/net/route` + `/proc/net/ipv6_route`）实时采集网卡与默认路由事实，缺失 IPv6 默认路由时拒绝保存必败的 `ipv6_only` 出站配置。

## 2. 规则数据源许可证洁净约束

- 禁用 GPL-3.0 传染性规则集污染 `sdk/` 或未来 Apache-2.0 客户端核心；
- 统一采用 MIT 洁净上游源（`v2fly/domain-list-community` 与 APNIC/MIT 中国 CIDR），编译为紧凑规则包并由 SHA-256 校验与临时文件原子替换（保留 `.prev` 回退副本），内置离线最小基线确保离线环境可用。
- 客户端匹配坚持「域名优先、零公网 DNS 预解析」五级优先级（内网保护 → 用户自定义 → 广告拦截 → 域名规则 → IP CIDR 与默认兜底），配合防 DNS 污染双上游策略（国内直连域名与 VPS 自身入口域名走国内纯净 DoH，海外走代理远端 DoH）。
