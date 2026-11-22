# 备份与恢复

> 适用：`qwq backup` / `qwq restore`（DEP-04）。数据目录默认 `/var/lib/qwq`，配置 `/etc/qwq/qwq.json`。

## 备份里有什么

`qwq backup` 生成一个 0600 的 `qwq-<UTC 时间>.tar.gz`：

| 归档内路径 | 来源 | 说明 |
|---|---|---|
| `data/qwq.db` | `VACUUM INTO` 快照 | 一致性快照，controller 不必停；**不要**自己拷贝在线的 `qwq.db`（会漏掉 WAL，得到不一致的库） |
| `data/keys/` | `/var/lib/qwq/keys/` | **主密钥 `master.key`**，见下文 |
| `data/tls/`、`data/acme/` | 同名目录 | 自签名证书、ACME 账户与证书缓存 |
| `data/plugin-state/` | 同名目录 | 插件 KV 状态 |
| `config/qwq.json` | `/etc/qwq/qwq.json` | 引导配置 |
| `manifest.json` | — | 格式版本、schema 版本、构建信息、时间、每个文件的 sha256 |

## master.key 必须和数据库一起保管

数据库里的 secret（ACME 账户密钥、插件凭据等）由 `keys/master.key` 加密。
**只有数据库没有主密钥，全部 secret 永久不可解**；反过来，拿到归档就拿到了全部
secret。因此：

- 备份归档就是敏感数据：离机保存时请再加密一次（例如 `age -r <公钥>` 或
  `gpg --symmetric`），并限制访问。
- 不要把数据库和主密钥分开备份或只备其一。

## 自动备份

安装脚本默认启用 `qwq-backup.timer`：每天一次（随机延迟至多 1 小时，关机错过会补跑），
以 `qwq` 用户执行

```sh
/opt/qwq/current/bin/qwq backup --out /var/lib/qwq/backups --keep 7
```

只保留最近 7 份。查看与手动触发：

```sh
systemctl list-timers qwq-backup.timer
sudo systemctl start qwq-backup.service && journalctl -u qwq-backup -n 20
ls -l /var/lib/qwq/backups/
```

备份留在本机只能防误操作，防不了磁盘损坏或机器丢失：请定期把最新一份拷走，例如
`scp root@服务器:/var/lib/qwq/backups/qwq-*.tar.gz ./`。

## 手动备份

```sh
sudo qwq backup                                   # 写到 /var/lib/qwq/backups
sudo qwq backup --out /srv/qwq-backups --keep 30  # 目录须对 qwq 用户可写
```

以 root 运行时命令会先降权为数据目录属主（`qwq`）再读库，避免留下 root 属主的 WAL 文件。

## 升级前的自动快照

controller 启动时若发现需要执行数据库迁移，会先把当前库快照到
`/var/lib/qwq/backups/pre-migrate-<旧版本>-<新版本>-<时间>.db`（0600，保留最近 3 份），
再迁移。迁移后的库会拒绝旧版本二进制启动；要回滚到旧版本：

```sh
sudo systemctl stop qwq-controller
sudo ln -sfn /opt/qwq/releases/<旧版本> /opt/qwq/current
sudo -u qwq cp /var/lib/qwq/backups/pre-migrate-<…>.db /var/lib/qwq/qwq.db.new
sudo -u qwq rm -f /var/lib/qwq/qwq.db-wal /var/lib/qwq/qwq.db-shm
sudo -u qwq mv /var/lib/qwq/qwq.db.new /var/lib/qwq/qwq.db
sudo systemctl start qwq-controller
```

快照之后在新版本上产生的数据会丢失。

## 恢复

`qwq restore` 要求 root 且 controller 已停止。它先把归档完整解到
`/var/lib/qwq/.restore-tmp`，核对每个文件的 sha256、数据库 `quick_check`、
schema 版本不高于当前二进制、主密钥存在、归档里的 `data_dir` 与当前配置一致；
全部通过后才逐项替换 `qwq.db`、`keys/`、`tls/`、`acme/`、`plugin-state/` 与
`/etc/qwq/qwq.json`，删除旧库的 `-wal/-shm`，并把属主恢复为数据目录属主。
替换过程中出错时，被替换下来的旧文件保留在 `/var/lib/qwq/.restore-old/`。

```sh
sudo systemctl stop qwq-controller
sudo qwq restore /path/to/qwq-20261110T020304.000Z.tar.gz
sudo systemctl start qwq-controller
```

### 换机或重装后恢复

```sh
sudo bash install.sh --offline qwq-vX.Y.Z-linux-amd64.tar.gz   # 版本不低于备份时的版本
sudo systemctl stop qwq-controller
sudo qwq restore qwq-<时间>.tar.gz
sudo systemctl start qwq-controller
```

恢复后用原账号登录，原有 secret 可直接使用。若提示
`backup schema version N is newer than this binary`，说明备份来自更新的版本，
请先安装该版本（提示里带有备份时的构建信息）。

`backups/` 与 `staging/` 不在备份范围内。插件程序文件（`/var/lib/qwq-plugins`）
也不在备份内：换机或 `--purge` 重装后需要重新安装插件包，插件的 KV 状态已随备份恢复。
