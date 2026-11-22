<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# /etc/qwq/qwq.json

The installer writes `qwq.json.example` as `/etc/qwq/qwq.json` (root:qwq 0640)
only when the file does not exist. The decoder is strict (unknown fields and
comments are errors), so the variants are documented here. After editing, run
`qwq doctor` and `systemctl restart qwq-controller`.

On a host that already runs BaoTa or another web server on ports 80/443, use
variant 1, 2 or 3; the step-by-step guide (nginx block, firewall, certificate
fingerprint) is `docs/operations/coexistence-baota.md`.

## 1. Loopback only + SSH tunnel (default)

The panel is not reachable from the network. Connect with
`ssh -L 8443:127.0.0.1:8443 root@<server>` and open `https://127.0.0.1:8443`.

```json
{ "http": { "listen": "127.0.0.1:8443", "tls": { "mode": "self_signed" } } }
```

## 2. All interfaces + self-signed certificate

Open the port in the firewall yourself (BaoTa "Security" page, ufw or
firewalld — the installer never touches them; `qwq doctor` prints the
commands) and compare the certificate fingerprint printed by
`sudo qwq setup-token` with the browser's.

```json
{
  "http": {
    "listen": "0.0.0.0:8443",
    "tls": { "mode": "self_signed" },
    "public_origins": ["https://203.0.113.10:8443"]
  }
}
```

## 3. Behind the BaoTa / nginx reverse proxy

TLS terminates at nginx; qwq must listen on loopback, where it speaks plain
HTTP, and trust the proxy's `X-Forwarded-For`. Proxy
`https://panel.example.com` to `http://127.0.0.1:8443` with `Host` forwarded,
response buffering off (the event stream is SSE) and a 64 MiB upload limit.
`public_origins` is the origin in the browser's address bar, without `:443`.

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
