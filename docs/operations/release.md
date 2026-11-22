# 发布

> 适用：`scripts/release.sh`、`.github/workflows/release.yml`（DEP-03）。

## 产物

全部扁平输出至 `dist/`，直接上传为 GitHub Release 附件：

| 文件 | 内容 |
|---|---|
| `qwq-vX.Y.Z-linux-{amd64,arm64}.tar.gz` | 极简必装主包（宿主二进制、内嵌 Web Shell、必装 `security.basic.qwqpkg`、`share/`、`install.sh`、`uninstall.sh`、许可证） |
| `qwq-compat-polkit-vX.Y.Z-linux-{amd64,arm64}.tar.gz` | 旧版 polkit 兼容补丁（仅 Ubuntu 22.04 / Debian 11 等缺少 `polkit >= 0.106` 的系统由 `install.sh` 按需自动下载验签安装；原生支持系统不会下载或安装） |
| `install.sh` | 独立在线安装脚本（已内嵌 `deployments/release.pub` 公钥与仓库 Release 下载地址，支持交互或 `--plugins` 自选官方插件，旧版系统自动匹配兼容补丁） |
| `<plugin_id>-vX.Y.Z-linux-{amd64,arm64}.qwqpkg` | 10 款独立可选官方插件包（按需下载安装） |
| `plugins-index.json` | 官方可选插件元数据、依赖与校验和索引 |
| `sbom.cdx.json` | CycloneDX SBOM（`cmd/qwq`，linux/amd64） |
| `SHA256SUMS` | 以上全部产物的 sha256 |
| `SHA256SUMS.sig` | 发布私钥对 `SHA256SUMS` 的 Ed25519 签名（仅流水线产出） |

版本只注入 `internal/buildinfo.Version` 一处（`scripts/lib/ldflags.sh`）；`qwq version`、
`qwqctl version` 与 helper 的 ping 报同一个版本，提交号来自 Go 嵌入的 VCS 信息。

## 可复现

`release.sh` 要求工作区干净，归档时间取最后一次提交时间（`SOURCE_DATE_EPOCH`），
tar 固定顺序与属主、gzip `-n`，Go 以 `-trimpath`、`CGO_ENABLED=0` 构建。同一提交、
同一工具链（`scripts/tools.lock`、`tools/release/go.mod`）构建两次，`SHA256SUMS`
逐字节一致；流水线每次都构建两遍并 `diff`。

## 发布密钥与插件签名密钥

签名均使用 Ed25519 + PKCS#8/PKIX PEM：目标系统自带 OpenSSL 3 与宿主信任根即可验签，不依赖国内访问不稳定的 Sigstore。
**私钥由项目发起人离线保管，永不进仓库；只提交公钥 `.pub` 文件。**

```sh
# 1. 发布清单签名密钥（签 SHA256SUMS）
openssl genpkey -algorithm ed25519 -out qwq-release.key      # 离线保存
openssl pkey -in qwq-release.key -pubout -out deployments/release.pub

# 2. 官方插件包签名密钥（签 security.basic 与 10 款可选 .qwqpkg）
openssl genpkey -algorithm ed25519 -out qwq-plugin-signing.key  # 离线保存
openssl pkey -in qwq-plugin-signing.key -pubout -out deployments/plugin-trust.pub
```

- 提交 `deployments/release.pub` 与 `deployments/plugin-trust.pub`；`release.sh` 会将前者嵌入 `install.sh` 供在线安装验签，将后者装入宿主 `/etc/qwq/trust/` 信任官方插件。
- 在 GitHub 仓库建 environment `release`（Required reviewers 设为发起人），添加两个 secrets：
  - `QWQ_RELEASE_SIGNING_KEY` = `qwq-release.key` 的 PEM 全文
  - `QWQ_PLUGIN_SIGNING_KEY` = `qwq-plugin-signing.key` 的 PEM 全文

## 发布一个版本

```sh
git tag -s vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z
```

`release.yml` 等待 `release` environment 批准后：bootstrap → `check.sh` → 构建并嵌入 Web Shell → 构建两次比对 →
签名并用 `deployments/release.pub` 验签 → `gh release create --verify-tag`。

用户在线安装（含交互自选可选插件）：

```sh
curl -fsSL https://github.com/<owner>/<repo>/releases/download/vX.Y.Z/install.sh -o install.sh
sudo bash install.sh --version vX.Y.Z
```

本地或构建机试构建（不签名）：

```sh
source scripts/dev-env.sh && bash scripts/bootstrap-tools.sh
bash scripts/release.sh v0.0.0-test /tmp/qwq-dist
```

## 用户验签

```sh
openssl pkeyutl -verify -pubin -inkey release.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum --ignore-missing -c SHA256SUMS
```

deb/rpm（nfpm）是可选的后续工作，首版只发 tar + install.sh。
