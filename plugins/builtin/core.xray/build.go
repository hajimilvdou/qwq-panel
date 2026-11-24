// SPDX-License-Identifier: AGPL-3.0-only

//go:build ignore

// 本工具只在 Linux 构建机项目目录生成候选包，不安装服务或生成签名私钥。
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/packageinfo"
	"github.com/qwq-panel/qwq/sdk/manifest"
	"github.com/qwq-panel/qwq/sdk/pkgfile"
)

const (
	pluginDirectory = "plugins/builtin/core.xray"
	coreDigest      = "e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d"
	coreVersion     = "26.11.9"
)

type buildOptions struct {
	version    string
	xray       string
	signingKey string
	publicKey  string
	rejectCore bool
}

func main() {
	options := buildOptions{}
	flag.StringVar(&options.version, "version", "", "明确的候选插件版本")
	flag.StringVar(&options.xray, "xray", ".cache/core-xray/v26.11.9/unpacked/xray", "已核验的固定 Xray 二进制")
	flag.StringVar(&options.signingKey, "key", os.Getenv("QWQ_XRAY_SIGNING_KEY"), "显式提供的既有签名私钥路径")
	flag.StringVar(&options.publicKey, "trust", os.Getenv("QWQ_XRAY_TRUST_PUB"), "与签名私钥匹配的公钥路径")
	flag.BoolVar(&options.rejectCore, "e2e-reject-core", false, "仅 E2E：制造固定核心摘要不符的失败更新包")
	flag.Parse()
	if err := buildPackage(options); err != nil {
		fmt.Fprintln(os.Stderr, "core.xray package:", err)
		os.Exit(1)
	}
}

// ======================== 显式输入与工作区 ========================
// 整个打包流程只有公钥、签名包和公开构建信息进入产物目录。
func buildPackage(options buildOptions) (result error) {
	if runtime.GOOS != "linux" || options.version == "" || options.signingKey == "" || options.publicKey == "" || flag.NArg() != 0 {
		return errors.New("必须在 Linux 仓库根目录明确指定 version、既有 key 和 trust")
	}
	if options.rejectCore && options.version != "0.1.3" {
		return errors.New("故障核心只允许生成明确的 0.1.3 E2E 包")
	}
	root, err := filepath.Abs(".")
	if err != nil {
		return err
	}
	publicBytes, err := readRegular(options.publicKey, 8<<10)
	if err != nil {
		return errors.New("公开信任根不可读")
	}
	publicKey, err := pkgfile.ParsePublicKeyPEM(publicBytes)
	if err != nil {
		return errors.New("公开信任根格式无效")
	}
	keyInfo, err := os.Lstat(options.signingKey)
	if err != nil || !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm() != 0o600 {
		return errors.New("签名私钥必须是权限 0600 的普通文件")
	}
	if digest, err := fileDigest(options.xray); err != nil || digest != coreDigest {
		return errors.New("Xray 二进制与锁定摘要不一致")
	}
	out := filepath.Join(root, ".cache", "core-xray", "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	work, err := os.MkdirTemp(out, ".build-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(work)) }()
	stage := filepath.Join(work, "package")
	if err := copyPackageSources(root, stage); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(stage, "bin"), 0o755); err != nil {
		return err
	}
	if err := copyFile(options.xray, filepath.Join(stage, "bin", "xray"), 0o755); err != nil {
		return err
	}
	xrayDir := filepath.Dir(options.xray)
	for _, asset := range []string{"geoip.dat", "geosite.dat"} {
		srcAsset := filepath.Join(xrayDir, asset)
		if info, statErr := os.Stat(srcAsset); statErr == nil && !info.IsDir() && info.Size() > 0 {
			if err := copyFile(srcAsset, filepath.Join(stage, "bin", asset), 0o644); err != nil {
				return err
			}
		}
	}
	rawManifest, err := os.ReadFile(filepath.Join(root, pluginDirectory, "manifest.json"))
	if err != nil {
		return err
	}
	if _, err := manifest.Parse(rawManifest); err != nil {
		return fmt.Errorf("源码 manifest 校验失败: %w", err)
	}
	var document map[string]any
	if err := json.Unmarshal(rawManifest, &document); err != nil {
		return err
	}
	document["version"] = options.version
	publisher, ok := document["publisher"].(map[string]any)
	if !ok {
		return errors.New("源码 manifest 缺少发布者")
	}
	publisher["key_id"] = manifest.KeyID(publicKey)
	stamped := filepath.Join(work, "embedded-manifest.json")
	if err := writeJSON(stamped, document); err != nil {
		return err
	}
	stampedBytes, err := os.ReadFile(stamped)
	if err != nil {
		return err
	}
	if _, err := manifest.Parse(stampedBytes); err != nil {
		return fmt.Errorf("候选 manifest 校验失败: %w", err)
	}
	overlay := filepath.Join(work, "overlay.json")
	if err := writeJSON(overlay, map[string]any{"Replace": map[string]string{
		filepath.Join(root, pluginDirectory, "manifest.json"):            stamped,
		filepath.Join(root, pluginDirectory, "package_identity_test.go"): filepath.Join(root, "tests/e2e/testdata/corexray/package_identity.go.txt"),
	}}); err != nil {
		return err
	}
	environment := []string{"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "QWQ_XRAY_BUILD_EXPECT_VERSION=" + options.version}
	if err := verifyEmbeddedIdentity(root, environment, overlay); err != nil {
		return err
	}
	plugin := filepath.Join(stage, "bin", "plugin")
	if err := runCommand(root, environment, "go", "build", "-overlay", overlay, "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", plugin, "./"+pluginDirectory); err != nil {
		return err
	}
	if options.rejectCore {
		if err := corruptCore(filepath.Join(stage, "bin", "xray")); err != nil {
			return err
		}
	}
	if err := writeBuildInventory(root, stage, options); err != nil {
		return err
	}
	provenance, ok := document["provenance"].(map[string]any)
	if !ok {
		provenance = map[string]any{}
		document["provenance"] = provenance
	}
	provenance["build"] = "attestations/build.json"
	if err := writeJSON(filepath.Join(stage, "manifest.json"), document); err != nil {
		return err
	}
	packer := filepath.Join(work, "qwqctl")
	if err := runCommand(root, []string{"CGO_ENABLED=0"}, "go", "build", "-trimpath", "-buildvcs=false", "-o", packer, "./cmd/qwqctl"); err != nil {
		return err
	}
	unsigned, signed := filepath.Join(work, "unsigned.qwq"), filepath.Join(out, "core.xray-"+options.version+".qwq")
	if err := runCommand(root, nil, packer, "pack", "-src", stage, "-out", unsigned); err != nil {
		return err
	}
	if err := runCommand(root, nil, packer, "sign", "-key", options.signingKey, "-out", signed, unsigned); err != nil {
		return err
	}
	if err := runCommand(root, nil, packer, "verify", "-trust", options.publicKey, signed); err != nil {
		_ = os.Remove(signed)
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "key.pub"), publicBytes, 0o644); err != nil {
		return err
	}
	digest, err := fileDigest(signed)
	if err != nil {
		return err
	}
	if err := os.WriteFile(signed+".sha256", []byte(digest+"  "+filepath.Base(signed)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("已核验候选包 %s sha256:%s\n", filepath.Base(signed), digest)
	return nil
}

// ======================== 可审计的源码与许可证 ========================
func copyPackageSources(root, stage string) error {
	for _, directory := range []string{"schemas", "attestations", "LICENSES"} {
		base := filepath.Join(root, pluginDirectory, directory)
		if err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(base, path)
			if err != nil {
				return err
			}
			destination := filepath.Join(stage, directory, relative)
			if entry.IsDir() {
				return os.MkdirAll(destination, 0o755)
			}
			return copyFile(path, destination, 0o644)
		}); err != nil {
			return err
		}
	}
	wire := filepath.Join(root, pluginDirectory, "internal", "xrayapi", "wire")
	for _, name := range []string{"stats.proto", "stats.pb.go", "stats_grpc.pb.go", "README.md", "buf.yaml"} {
		destination := filepath.Join(stage, "sources", "stats-wire", name)
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return err
		}
		if err := copyFile(filepath.Join(wire, name), destination, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func writeBuildInventory(root, stage string, options buildOptions) error {
	binary := filepath.Join(stage, "bin", "plugin")
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		return err
	}
	licenses, err := packageinfo.Load(os.DirFS(stage))
	if err != nil {
		return err
	}
	if licenses.CoreDigest() != coreDigest {
		return errors.New("许可清单不属于锁定核心")
	}
	packages := []map[string]any{}
	packageIDs := map[string]bool{}
	relationships := []map[string]string{}
	add := func(name, version, license, digest, source, download string) string {
		idHash := sha256.Sum256([]byte(name + "@" + version))
		id := "SPDXRef-" + hex.EncodeToString(idHash[:8])
		if packageIDs[id] {
			return id
		}
		item := map[string]any{"name": name, "SPDXID": id, "versionInfo": version, "downloadLocation": download, "filesAnalyzed": false, "licenseConcluded": license, "licenseDeclared": license, "copyrightText": "NOASSERTION", "sourceInfo": source}
		if digest != "" {
			item["checksums"] = []map[string]string{{"algorithm": "SHA256", "checksumValue": digest}}
		}
		packages = append(packages, item)
		packageIDs[id] = true
		return id
	}
	driverDigest, err := fileDigest(binary)
	if err != nil {
		return err
	}
	coreBinaryDigest, err := fileDigest(filepath.Join(stage, "bin", "xray"))
	if err != nil {
		return err
	}
	revisionBytes, err := commandOutput(root, nil, "git", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	revision := strings.TrimSpace(string(revisionBytes))
	statusBytes, err := commandOutput(root, nil, "git", "status", "--porcelain")
	if err != nil {
		return err
	}
	modified := len(bytes.TrimSpace(statusBytes)) != 0
	driverID := add("core.xray", options.version, "AGPL-3.0-only", driverDigest, fmt.Sprintf("qwq source revision %s; modified=%t", revision, modified), "NOASSERTION")
	coreID := add("Xray-core", coreVersion, "MPL-2.0", coreBinaryDigest, "tag v26.11.9; commit 676eaf66f8f05d4d558ee7a74b4736623d3feeb9; https://github.com/XTLS/Xray-core/tree/v26.11.9", "https://github.com/XTLS/Xray-core/archive/676eaf66f8f05d4d558ee7a74b4736623d3feeb9.tar.gz")
	relationships = append(relationships, map[string]string{"spdxElementId": driverID, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": coreID})
	if err := copyFile(filepath.Join(runtime.GOROOT(), "LICENSE"), filepath.Join(stage, "LICENSES", "go-standard-library.txt"), 0o644); err != nil {
		return err
	}
	standardID := add("Go standard library", info.GoVersion, "BSD-3-Clause", "", "retained LICENSES/go-standard-library.txt", "https://go.dev/dl/"+info.GoVersion+".src.tar.gz")
	relationships = append(relationships, map[string]string{"spdxElementId": driverID, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": standardID})
	// 驱动与核心使用同一精确匹配，避免上游依赖跳过许可核验。
	addDependency := func(parent string, dependency *debug.Module) error {
		name, version, sum, source := linkedModuleIdentity(dependency)
		license, location := "", "NOASSERTION"
		paths := []string{}
		if name == "github.com/qwq-panel/qwq/sdk" {
			// 本仓 SDK 没有发布版本；必须实际来自当前工作区，不能替外部副本断言许可。
			output, err := commandOutput(root, nil, "go", "list", "-m", "-json", name)
			if err != nil {
				return err
			}
			var sdkSource struct {
				Path, Dir string
				Replace   *struct{ Dir string }
			}
			if json.Unmarshal(output, &sdkSource) != nil {
				return errors.New("SDK 来源元数据无效")
			}
			directory := sdkSource.Dir
			if sdkSource.Replace != nil {
				directory = sdkSource.Replace.Dir
			}
			if sdkSource.Path != name || filepath.Clean(directory) != filepath.Join(root, "sdk") || version != "(devel)" || sum != "" {
				return errors.New("SDK 许可只能来自本次工作区的本地模块")
			}
			license = "Apache-2.0"
			paths, err = copyModuleNotices(filepath.Join(root, "sdk"), stage, name)
			if err != nil {
				return err
			}
		} else {
			module, err := licenses.Module(name, version, sum)
			if err != nil {
				return fmt.Errorf("未审查依赖 %s@%s: %w", name, version, err)
			}
			license, location = module.License, module.SourceURL
			for _, notice := range module.Notices {
				paths = append(paths, notice.Path)
			}
		}
		id := add(name, version, license, "", source+"; retained license files: "+strings.Join(paths, ", "), location)
		relationships = append(relationships, map[string]string{"spdxElementId": parent, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": id})
		return nil
	}
	for _, dependency := range info.Deps {
		if err := addDependency(driverID, dependency); err != nil {
			return err
		}
	}
	coreInfo, err := buildinfo.ReadFile(filepath.Join(stage, "bin", "xray"))
	if options.rejectCore {
		// 故障副本损坏 ELF 头；来源清单仍从已经摘要核验的原始输入读取。
		coreInfo, err = buildinfo.ReadFile(options.xray)
	}
	if err != nil {
		return err
	}
	coreStandard, err := licenses.StandardLibrary(coreInfo.GoVersion)
	if err != nil {
		return fmt.Errorf("上游核心 Go 许可未审查: %w", err)
	}
	coreStandardID := add("Go standard library", coreInfo.GoVersion, coreStandard.License, "", "retained "+coreStandard.Path+"; source "+coreStandard.SourceURL, "https://go.dev/dl/"+coreInfo.GoVersion+".src.tar.gz")
	relationships = append(relationships, map[string]string{"spdxElementId": coreID, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": coreStandardID})
	for _, dependency := range coreInfo.Deps {
		if err := addDependency(coreID, dependency); err != nil {
			return err
		}
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	sbom := map[string]any{"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "core.xray-" + options.version, "documentNamespace": "https://qwq.invalid/spdx/core.xray-" + options.version + "-" + driverDigest, "creationInfo": map[string]any{"created": stamp, "creators": []string{"Tool: qwq-core-xray-package"}}, "documentDescribes": []string{driverID, coreID}, "packages": packages, "relationships": relationships}
	if err := writeJSON(filepath.Join(stage, "attestations", "sbom.spdx.json"), sbom); err != nil {
		return err
	}
	provenance := map[string]any{"schema_version": "1", "plugin_version": options.version, "source_revision": revision, "source_modified": modified, "go_version": info.GoVersion, "target": "linux/amd64", "cgo_enabled": false, "plugin_sha256": driverDigest, "xray_version": coreVersion, "xray_sha256": coreBinaryDigest, "created_at": stamp, "fault_injection": options.rejectCore}
	return writeJSON(filepath.Join(stage, "attestations", "build.json"), provenance)
}

func linkedModuleIdentity(module *debug.Module) (name, version, sum, source string) {
	actual := module
	name = module.Path
	source = "module " + module.Path + "@" + module.Version
	if module.Replace != nil {
		actual = module.Replace
		if !strings.HasPrefix(actual.Path, ".") {
			name = actual.Path
		}
		source += "; replacement " + actual.Path + "@" + actual.Version
	}
	version = actual.Version
	if version == "" {
		version = "(devel)"
	}
	sum = actual.Sum
	source += "; checksum " + sum
	return name, version, sum, source
}

func copyModuleNotices(directory, stage, module string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	id := sha256.Sum256([]byte(module))
	paths := []string{}
	for _, entry := range entries {
		name := strings.ToUpper(entry.Name())
		if entry.IsDir() || !(strings.HasPrefix(name, "LICENSE") || strings.HasPrefix(name, "COPYING") || name == "NOTICE" || name == "NOTICE.TXT" || name == "PATENTS" || name == "COPYRIGHT") {
			continue
		}
		relative := filepath.Join("LICENSES", "dependencies", hex.EncodeToString(id[:8]), entry.Name())
		destination := filepath.Join(stage, relative)
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return nil, err
		}
		if err := copyFile(filepath.Join(directory, entry.Name()), destination, 0o644); err != nil {
			return nil, err
		}
		paths = append(paths, filepath.ToSlash(relative))
	}
	if len(paths) == 0 {
		return nil, errors.New("构建依赖没有可保留的许可证文件")
	}
	sort.Strings(paths)
	return paths, nil
}

// ======================== 固定命令与有界文件操作 ========================
func verifyEmbeddedIdentity(root string, environment []string, overlay string) error {
	output, err := commandOutput(root, environment, "go", "test", "-json", "-overlay", overlay, "-run", "^TestXrayPackageIdentity$", "./"+pluginDirectory)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	passed := false
	for {
		var event struct {
			Action string
			Test   string
		}
		if err := decoder.Decode(&event); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return errors.New("版本探针没有返回有效测试事件")
		}
		if event.Action == "pass" && event.Test == "TestXrayPackageIdentity" {
			passed = true
		}
	}
	if !passed {
		return errors.New("实际嵌入版本与 RPC descriptor 探针未执行或未通过")
	}
	fmt.Println("实际嵌入版本与 RPC descriptor 已核验")
	return nil
}

func commandOutput(root string, environment []string, executable string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Dir, command.Env = root, append(os.Environ(), environment...)
	var output bytes.Buffer
	var diagnostic bytes.Buffer
	command.Stdout, command.Stderr = &output, &diagnostic
	if err := command.Run(); err != nil {
		message := diagnostic.String()
		if len(message) > 8192 {
			message = message[:8192]
		}
		return nil, fmt.Errorf("%s 执行失败: %w\n%s", filepath.Base(executable), err, message)
	}
	return output.Bytes(), nil
}

func runCommand(root string, environment []string, executable string, arguments ...string) error {
	output, err := commandOutput(root, environment, executable, arguments...)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(output)
	return err
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("文件不是有界普通文件")
	}
	return os.ReadFile(path)
}

func fileDigest(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("摘要输入不是普通文件")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func copyFile(source, destination string, mode fs.FileMode) error {
	data, err := readRegular(source, 256<<20)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, data, mode)
}

func corruptCore(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteAt([]byte{0}, 0); err != nil {
		return err
	}
	return file.Sync()
}
