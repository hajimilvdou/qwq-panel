# 与宝塔共存

> 适用：已经装了宝塔的机器（DEP-06）；1Panel、手工 nginx 等占着 80/443 的环境做法相同。
> 配置文件 `/etc/qwq/qwq.json`，各变体见 `deployments/config/qwq.json.example.md`
> （装机后在 `/opt/qwq/current/share/config/`）。改完配置先 `sudo qwq doctor`，再
> `sudo systemctl restart qwq-controller`。

## qwq 碰什么、不碰什么

安装脚本和面板都**不改** nginx、宝塔站点、ufw / firewalld 规则；默认只监听
`127.0.0.1:8443`，装完对外不可达。下面两种方案里涉及宝塔的每一步都由你在宝塔里操作。

`qwq doctor` 只读，相关的三行：

| 行 | 含义 |
|---|---|
| `coexistence` | 发现了哪些面板与防火墙管理器（宝塔、1Panel、ufw、firewalld、fail2ban） |
| `port` | `http.listen` 的端口是否被别的进程占用，并列出 80 / 443 / 888 / 8888 上已有的监听 |
| `listen` | 监听地址不是回环时，提醒放行端口并给出命令 |

## 选哪种

| 情况 | 方案 | `http.tls.mode` |
|---|---|---|
| 有域名，想要浏览器信任的证书 | 方案 1：宝塔 nginx 反代 | `proxy` |
| 没有域名 | 方案 2：自签名 + 高位端口 | `self_signed` |
| 只是偶尔上去看看 | 保持默认，`ssh -L 8443:127.0.0.1:8443 root@<服务器>` | `self_signed` |

### 为什么这里不能用 `acme`

`acme` 模式由面板自己向 Let's Encrypt 申请证书，面板只应答 TLS-ALPN-01 挑战，而 CA
固定连接域名的 **443 端口**做验证（RFC 8737）。宝塔的 nginx 已经占着 80 和 443：

- `http.listen` 不是 443 端口：证书永远签不出来，所以配置校验直接拒绝，
  `qwq serve-controller` 不启动，`qwq doctor` 的 `config` 行报
  `http.listen: mode "acme" requires port 443, got 8443: …`。
- `http.listen` 写成 443：端口被 nginx 占用，启动报 `bind: address already in use`，
  `qwq doctor` 的 `port` 行会指回本文。**不要为此停掉 nginx**，你的网站都在上面。

所以证书交给宝塔去申请，面板走方案 1。`acme` 只适合 443 空闲的机器（`listen` 写
`0.0.0.0:443`）。

## 方案 1：宝塔 nginx 反代（有域名时推荐）

TLS 在 nginx 终止，面板只在回环地址上提供**明文 HTTP**。

**1. 面板配置**

```json
{
  "http": {
    "listen": "127.0.0.1:8443",
    "tls": { "mode": "proxy" },
    "public_origins": ["https://panel.example.com"],
    "trusted_proxies": ["127.0.0.1/32"]
  }
}
```

- `listen` 必须是回环地址，否则拒绝启动。
- `public_origins` 写浏览器地址栏里的 origin：`https`、不带路径；标准端口**不要**写
  `:443`。写错时请求会被 403 `CSRF_FAILED` 拒绝。
- `trusted_proxies` 只写 nginx 的来源地址；面板只信任它带来的 `X-Forwarded-For`。

**2. 宝塔里建站点**

网站 → 添加站点（域名 `panel.example.com`，纯静态，不建数据库和 FTP）→ SSL 里申请证书并开启
强制 HTTPS → 反向代理 → 添加反向代理，目标 URL 填 `http://127.0.0.1:8443`，发送域名填 `$host`，
不要开启宝塔反代的缓存选项。证书的申请与续签都由宝塔负责，qwq 不参与。

保存后打开这条反代的「配置文件」，把 `location` 块改成：

```nginx
location ^~ / {
    proxy_pass http://127.0.0.1:8443;   # 明文回环，不要写 https://
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_http_version 1.1;
    proxy_set_header Connection "";

    proxy_buffering off;                # 事件流（SSE）逐条下发
    proxy_cache off;
    proxy_read_timeout 1h;              # 长连接与耗时请求不被默认的 60 秒切断
    client_max_body_size 64m;           # 插件包上传上限 64 MiB
}
```

- 保留宝塔生成的 `^~`：否则站点模板里按后缀匹配的静态文件规则（`.js`、`.css`、图片）会先于反代
  命中，这些请求到不了面板。
- 宝塔自动生成的缓存相关行（`proxy_cache`、按后缀设 `expires` 的 `if` 块）删掉即可。
- 站点的 HTTPS 不在 443 端口时，把 `Host` 改成 `$host:$server_port`，`public_origins`
  也带上同一个端口。

**3. 验证**

```sh
curl -sI https://panel.example.com/healthz   # 应为 200
sudo qwq setup-token                         # 链接以 public_origins 第一项开头
```

| 现象 | 原因与处理 |
|---|---|
| 502 Bad Gateway | controller 没起来（`systemctl status qwq-controller`），或 `proxy_pass` 写成了 `https://` |
| 请求返回 403 `CSRF_FAILED` | `public_origins` 与浏览器地址栏的 origin 不一致（协议、域名、端口都要相同） |
| 事件流 `/api/v1/events` 迟迟收不到心跳，界面不实时刷新 | 响应被缓冲：确认 `proxy_buffering off`，域名前面有 CDN 时关闭其缓存 |
| 上传插件包返回 413 | `client_max_body_size` 小于 64m（nginx 默认 1m） |
| 以 `.js`、`.css`、图片后缀结尾的请求返回 404 | `location` 少了 `^~`，被站点的静态文件规则截走 |
| 审计与限流里的来源全是 127.0.0.1 | nginx 没有带 `X-Forwarded-For`，或 `trusted_proxies` 里没有 nginx 的来源地址（127.0.0.1） |

## 方案 2：自签名 + 高位端口（没有域名）

**1. 面板配置**：先用 `sudo ss -ltn` 挑一个空闲端口，避开 80 / 443 和宝塔的 888 / 8888。

```json
{
  "http": {
    "listen": "0.0.0.0:8443",
    "tls": { "mode": "self_signed" },
    "public_origins": ["https://203.0.113.10:8443"]
  }
}
```

`public_origins` 写你实际在浏览器里输入的地址：自签名证书会覆盖它（云主机的公网 IP
往往不在网卡上，不写证书里就没有这个 IP），`qwq setup-token` 打印的链接也用它。写了以后，
只有列出的地址能登录和提交，其它地址返回 403 `CSRF_FAILED`；还想走 SSH 隧道的话，把
`https://127.0.0.1:8443` 也加进这个列表。

**2. 放行端口**：见下一节。`sudo qwq doctor` 的 `listen` 行会给出对应端口的命令。

**3. 首次访问核对证书指纹**

```sh
sudo qwq setup-token
# 初始化链接（30 分钟内有效，只能使用一次）：…
# 证书指纹（自签名模式请核对）：SHA256:AB:CD:…
```

浏览器会提示证书不受信任：点开证书详情，SHA-256 指纹与上面打印的**完全一致**再继续；
不一致说明连到的不是你的服务器，不要输入任何内容。初始化之后要再次核对，用

```sh
sudo openssl x509 -in /var/lib/qwq/tls/self_signed.crt -noout -fingerprint -sha256
```

指纹在重启后不变；证书临近到期，或 `public_origins`、监听地址变化使它不再覆盖访问地址时，
会自动重新生成，指纹随之改变。

## 放行端口

只有方案 2（监听地址不是回环）需要。方案 1 用的是宝塔已经开放的 443，回环上的 8443
**不要**对外放行。

- **有宝塔**：宝塔面板 → 安全 → 添加端口规则（TCP）。宝塔自己记录它管理的规则并同步到系统
  防火墙，所以不要手工编辑 `/etc/ufw/user.rules`、`/etc/ufw/user6.rules` 或 firewalld 的
  zone 文件；直接执行下面的命令虽然也生效，但宝塔的列表里可能看不到，日后容易遗漏。
- **没有宝塔**：

  ```sh
  sudo ufw allow 8443/tcp                                                           # Debian / Ubuntu
  sudo firewall-cmd --permanent --add-port=8443/tcp && sudo firewall-cmd --reload   # Rocky / Alma
  ```

- 云厂商的安全组（或轻量服务器的防火墙页）也要放行同一个端口。

验证：服务器上 `sudo ss -ltnp 'sport = :8443'` 能看到 `qwq`；外部执行
`curl -kI https://<公网 IP>:8443/healthz` 返回 200。

## 回退

把 `http` 改回默认（`127.0.0.1:8443` + `self_signed`）并重启 controller 即可。宝塔里的反代站点和
端口规则由你自己删除；`uninstall.sh` 同样不会碰它们。
