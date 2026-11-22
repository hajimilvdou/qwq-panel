# Deployment

This directory holds the files `scripts/install.sh` copies onto a host.
`scripts/package.sh` assembles them with the binaries into the release
tarball (layout in the header of `install.sh`).

## Install

```sh
sudo bash install.sh --offline qwq-vX.Y.Z-linux-amd64.tar.gz   # or: --version vX.Y.Z
sudo qwq setup-token        # prints the one-time setup link again if needed
```

The script is idempotent: running it twice with the same tarball changes
nothing and does not restart the controller. It creates the `qwq` user
(`sysusers/qwq.conf`), the directory skeleton (`tmpfiles/qwq.conf`), the
units, the polkit rule (when polkit is present), `/etc/qwq/qwq.json` from
`config/qwq.json.example` (only if missing; variants in
`config/qwq.json.example.md`) and `/etc/qwq/trust/`, switches
`/opt/qwq/current`, starts `qwq-privileged.socket` and `qwq-controller`, and
prints the setup link. An older layout with `/var/lib/qwq/plugins` is moved to
`/var/lib/qwq-plugins` while the services are stopped.

The panel listens on `127.0.0.1:8443` only. The installer never touches nginx,
ufw, firewalld or a BaoTa panel; reach the panel over
`ssh -L 8443:127.0.0.1:8443 root@<server>` or change `http.listen` and open the
port yourself. Running next to BaoTa (reverse proxy or self-signed on a high
port, firewall commands, why `acme` does not work there) is covered in
`docs/operations/coexistence-baota.md`.

## Uninstall

```sh
sudo bash /opt/qwq/current/uninstall.sh            # keeps /var/lib/qwq, /etc/qwq and the qwq user
sudo bash /opt/qwq/current/uninstall.sh --purge    # also deletes them (asks for a confirmation word)
```

It stops the controller, the plugin units and the helper (in that order),
removes every `qwq*` unit, the plugin tmpfiles snippets, the polkit rule, the
`qwq-p-*` groups, `/opt/qwq`, `/usr/local/bin/qwq`, `/var/lib/qwq-plugins`,
`/var/lib/qwq-privileged` and `/run/qwq`. Nothing outside qwq is touched.

## Filesystem (layout)

| Path | Owner / mode | Purpose |
|---|---|---|
| `/opt/qwq/releases/<version>/` | root:root, 0755 | Immutable release tree (binary, licenses, default units) |
| `/opt/qwq/current` | root:root, symlink | Active release; rollback is a link switch plus restart |
| `/etc/qwq/qwq.json` | root:qwq, 0640 | Bootstrap configuration (read-only for the service) |
| `/etc/qwq/trust/` | root:root, 0755 | Plugin publisher public keys, one PEM per key |
| `/var/lib/qwq/` | qwq:qwq, 0700 | SQLite database, master key, TLS/ACME cache |
| `/var/lib/qwq/staging/` | qwq:qwq, 0700 | Verified plugin staging tree, read by the helper during publish |
| `/var/lib/qwq/keys/master.key` | qwq:qwq, 0600 | Secret master key (created atomically on first start) |
| `/var/lib/qwq/backups/` | qwq:qwq, 0700 | `qwq backup` archives and pre-migration snapshots (`docs/operations/backup-restore.md`) |
| `/var/lib/qwq-plugins/<id>/<version>/` | root:root, 0555/0444 | Installed plugin package, immutable |
| `/var/lib/qwq-privileged/creds/` | root:root, 0700 | Plugin credentials (written by the helper only) |
| `/run/qwq/` | root:root, 0711 | Root-managed runtime tree; the helper refuses a qwq-writable ancestry |
| `/run/qwq/plugin/`, `/run/qwq/link/` | root:root, 0711 | Plugin sockets and bind targets |
| `/run/qwq/host/` | qwq:qwq, 0750 | The only runtime directory the controller writes (host reverse channel) |
| `/run/qwq/privileged.sock` | root:qwq, 0660 | Root helper listener (systemd socket unit) |

`deployments/tmpfiles/qwq.conf` creates the directory skeleton at boot. Logs
go to journald only; there is no `/var/log/qwq`. `qwq-controller.service` has
no `RuntimeDirectory=`, so stopping or restarting it never touches `/run/qwq`.

## Privileged plugin installation

`serve-controller` runs as `qwq`. It cannot write `/etc/systemd/system`,
`/etc/tmpfiles.d` or `/var/lib/qwq-plugins`, so plugin installation is split
across the privileged helper:

1. The controller verifies the package (`internal/pluginhost/install`) and
   unpacks it into `/var/lib/qwq/staging` as `qwq`.
2. It sends the staged directory and the target version path to
   `qwq-privileged` over `/run/qwq/privileged.sock`; the helper copies the tree
   into `/var/lib/qwq-plugins/<id>/<version>` with root ownership and
   0555/0444 modes, then the controller discards the staging tree.
3. It sends the rendered `UnitSpec` and a fresh plugin token to the helper,
   which writes the unit, the resource drop-in, the tmpfiles snippet, the
   0600 credential and the runtime directories, runs `systemctl daemon-reload`
   and enables `qwq-plugin@<id>.socket`.

`qwq-privileged` is **socket activated and serves one request per activation**:
`qwq-privileged.socket` stays active, the service is started by systemd for a
connection, answers, and exits. An idle host runs no root helper process.
`systemctl is-active qwq-privileged.service` is `inactive` between requests;
`systemctl status qwq-privileged.socket` shows the listener.

The request schema, the path allowlist and the systemctl/group allowlist are
documented in `cmd/qwq-privileged/REPORT.md`. The helper accepts only:

| Operation | Fields | Effect |
|---|---|---|
| `publish` | `staged_dir`, `version_dir`, `plugin_id`, `version` | validates and copies the staged tree into the immutable version directory (root, 0555/0444, executable bit preserved); an existing identical version is idempotent |
| `install` | `spec`, `credential_base64` | writes the unit artifacts and the 0600 credential, `daemon-reload`, `enable --now qwq-plugin@<id>.socket` (enable failure is a warning) |
| `remove` | `id`, `version`, `paths`, `keep_unit` | refuses a running unit, removes the unit artifacts and the version directory, `daemon-reload` |
| `reload` | — | `systemctl daemon-reload` |
| `ping` | — | reports the helper version and uid |

The socket is `0660 root:qwq`: the controller may connect, a plugin
(`DynamicUser`) and any other local user may not. The helper never takes a
command from a request, never opens a network socket and never logs a token.

The service runs with `ProtectSystem=strict`; `ReadWritePaths` is
`/etc /run/qwq /var/lib/qwq-plugins` and `/var/lib/qwq/staging` is mounted
read-only. `/etc` as a whole (not just the two systemd directories) is writable
because `groupadd`/`groupdel` rewrite `/etc/group` and `/etc/gshadow` through a
lock file and an atomic replace. The service has `MemoryMax=32M`, `TasksMax=16`,
no network namespace, and only `CAP_CHOWN CAP_DAC_OVERRIDE`.

The helper's `--plugins-root` (default `/var/lib/qwq-plugins`),
`--staging-root` (default `/var/lib/qwq/staging`) and the controller's
`--plugins-dir` must agree: both sides only accept paths below their own roots,
so a mismatch rejects every install instead of writing a unit that points
somewhere else. The two roots must not overlap; the staging root is writable by
`qwq`, the plugins root is not.

## Units

- `qwq-controller.service` — the standalone/controller host process. It runs as
  `qwq`, reads `/etc/qwq/qwq.json`, and drops all capabilities except
  `CAP_NET_BIND_SERVICE`.
- `qwq-privileged.socket` / `qwq-privileged.service` — the root half of plugin
  installation described above. Socket activated, one request per activation.
- `qwq-backup.service` / `qwq-backup.timer` — daily `qwq backup --keep 7` into
  `/var/lib/qwq/backups`, same sandbox as the controller, no network.
- `qwq-plugin@.service` / `qwq-plugin@.socket` — the plugin templates; the
  helper renders and installs a concrete `qwq-plugin@<id>.{service,socket}` per
  installed plugin. Plugin processes run under a dynamic user and cannot reach
  the privileged socket.

`serve-controller` uses `/run/qwq/privileged.sock` by default; pass
`--privileged-socket <path>` to point it elsewhere and `--privileged-socket ""`
to disable the helper (installs then run in-process, which requires the
controller itself to be root and is only meant for development; a non-root
controller refuses to start without a socket). A non-root controller never
falls back to in-process installs: until the helper socket is up, plugin
installs report UNAVAILABLE. Its
`--staging-dir` (default `/var/lib/qwq/staging`) must match the helper's
`--staging-root`.

Verify the helper without installing anything:

```sh
systemctl start qwq-privileged.socket
printf '{"op":"ping"}\n' | socat - UNIX-CONNECT:/run/qwq/privileged.sock
# or: qwq-privileged --socket /run/qwq/privileged.sock   (debug, foreground)
```

After the controller has started once, `sudo qwq setup-token` prints the
one-time setup link (token in the URL fragment, valid 30 minutes; each call
invalidates the previous one) and the self-signed certificate fingerprint. The
token is never written to the journal; there is no default password
(ARCH §4.1.1). Once initialized the command exits 3 — use `sudo qwq recover`.
