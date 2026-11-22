<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# /etc/qwq/qwq.json

On a fresh install, `install.sh` generates `/etc/qwq/qwq.json` (`root:qwq 0640`)
with a **random free high port** (`20000–59999`), a **random 10-character secret
entry path** (`entry_path`), and `disguise: "drop"` (TCP reset / zero response on
wrong-path probes). It never overwrites an existing `/etc/qwq/qwq.json`.

The decoder is strict (unknown fields and comments are errors), so the variants
are documented here. Most access settings (`port`, `entry_path`, `disguise`,
`disguise_html`, `panel_domain`, `auto_disable_on_domain`) can also be changed
live in the panel under **设置 → 系统 → 面板入口与安全伪装** (persisted in SQLite,
with zero-reinstall hot port rebind). After manually editing `/etc/qwq/qwq.json`,
run `qwq doctor` and `systemctl restart qwq-controller`.

On a host that already runs BaoTa or another web server on ports 80/443, use
variant 1, 2 or 3; the step-by-step guide (nginx block, firewall, certificate
fingerprint) is `docs/operations/coexistence-baota.md`.

## 1. Loopback only + random high port + secret entry path (default)

The panel is not reachable from the network. Connect with
`ssh -L <port>:127.0.0.1:<port> root@<server>` and open the setup/entry link
printed by `install.sh` (or `sudo qwq setup-token`), e.g.
`https://127.0.0.1:<port>/<entry_path>/`.

When `entry_path` is active and a request hits the port without the secret path
(or its HttpOnly gate cookie), the outermost stealth middleware handles it before
any panel header or cookie is ever written:

- `"drop"` (default): immediately aborts/resets the connection (0 bytes, 0 headers,
  0 status code — indistinguishable from an unserved port in browsers and F12 DevTools).
- `"nginx_404"` / `"nginx_403"` / `"blank_404"` / `"custom_html"`: clean decoy
  responses with all panel fingerprint headers stripped.

```json
{
  "http": {
    "listen": "127.0.0.1:38421",
    "entry_path": "jsnsjx8k2m",
    "disguise": "drop",
    "auto_disable_on_domain": true,
    "tls": { "mode": "self_signed" }
  }
}
```

## 2. All interfaces + self-signed certificate

Open the port in the firewall yourself (BaoTa "Security" page, ufw or
firewalld — the installer never touches them; `qwq doctor` prints the
commands) and compare the certificate fingerprint printed by
`sudo qwq setup-token` with the browser's.

```json
{
  "http": {
    "listen": "0.0.0.0:38421",
    "entry_path": "jsnsjx8k2m",
    "disguise": "drop",
    "tls": { "mode": "self_signed" },
    "public_origins": ["https://203.0.113.10:38421"]
  }
}
```

## 3. Behind the BaoTa / nginx reverse proxy (secret entry path auto-disabled)

TLS terminates at nginx; qwq must listen on loopback, where it speaks plain
HTTP, and trust the proxy's `X-Forwarded-For`. Proxy
`https://panel.example.com` to `http://127.0.0.1:<port>` with `Host` forwarded,
response buffering off (the event stream is SSE) and a 64 MiB upload limit.
`public_origins` is the origin in the browser's address bar, without `:443`.

When `tls.mode` is `"proxy"`, `panel_domain` is set, or `public_origins` contains
a DNS domain (with `auto_disable_on_domain` enabled, the default), the secret entry
path and disguise are **automatically disabled** so visiting
`https://panel.example.com` goes straight to the panel.

```json
{
  "http": {
    "listen": "127.0.0.1:38421",
    "panel_domain": "panel.example.com",
    "auto_disable_on_domain": true,
    "tls": { "mode": "proxy" },
    "public_origins": ["https://panel.example.com"],
    "trusted_proxies": ["127.0.0.1/32"]
  }
}
```

## 4. ACME (Let's Encrypt) on a host whose port 443 is free

The panel answers the TLS-ALPN-01 challenge on its own listener, and the
certificate authority validates it on port 443 only, so `http.listen` must use
port 443: any other port is rejected at startup. Port 443 has to be reachable
from the internet and the domain must resolve to this host. Where another web
server owns 443, use variant 3 instead and let that server obtain the
certificate.

```json
{
  "http": {
    "listen": "0.0.0.0:443",
    "tls": { "mode": "acme", "domains": ["panel.example.com"], "email": "ops@example.com" },
    "public_origins": ["https://panel.example.com"]
  }
}
```
