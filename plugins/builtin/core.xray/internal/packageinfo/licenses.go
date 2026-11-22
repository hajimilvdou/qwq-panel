// SPDX-License-Identifier: AGPL-3.0-only

// Package packageinfo 校验候选包的已审查许可输入，不参与代理运行时。
package packageinfo

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"slices"
	"strings"
)

const (
	LockPath       = "attestations/dependencies.lock.json"
	maxLockBytes   = 512 << 10
	maxNoticeBytes = 1 << 20
)

var (
	ErrUnreviewed = errors.New("packageinfo: dependency identity has not been reviewed")
	ErrIntegrity  = errors.New("packageinfo: reviewed license input is inconsistent")
)

// Notice 关联原文件名称与保留的原字节；相同内容只分发一次。
type Notice struct {
	Path       string `json:"path"`
	SourcePath string `json:"source_path"`
	SHA256     string `json:"sha256"`
}

// Module 用实际链接的模块路径、版本和 h1 同时定位许可，拒绝名称相同的新版本。
type Module struct {
	Path      string   `json:"path"`
	Version   string   `json:"version"`
	Sum       string   `json:"sum"`
	License   string   `json:"license"`
	SourceURL string   `json:"source_url"`
	Notices   []Notice `json:"notices"`
}

// StandardLibrary 为上游核心的真实 Go 版本保留已核验许可。
type StandardLibrary struct {
	Version   string `json:"version"`
	License   string `json:"license"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SourceURL string `json:"source_url"`
}

type document struct {
	SchemaVersion              string            `json:"schema_version"`
	CoreSHA256                 string            `json:"core_sha256"`
	SourceSBOMSHA256           string            `json:"source_sbom_sha256"`
	SourceNoticesArchiveSHA256 string            `json:"source_notices_archive_sha256"`
	Modules                    []Module          `json:"modules"`
	StandardLibraries          []StandardLibrary `json:"standard_libraries"`
	SupplementalNotices        []Notice          `json:"supplemental_notices"`
}

// Catalog 在加载时核验全部材料；查询返回独立副本，不能改写后续匹配结果。
type Catalog struct {
	coreDigest string
	modules    map[string]Module
	standard   map[string]StandardLibrary
}

// ============================ 已审输入加载 ============================
// 调用方先把源码普通文件复制到专用 staging；这里仅做有界读取和一致性验证。
func Load(fsys fs.FS) (*Catalog, error) {
	if fsys == nil {
		return nil, ErrIntegrity
	}
	raw, err := readRegular(fsys, LockPath, maxLockBytes)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var doc document
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: invalid lock JSON", ErrIntegrity)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || doc.SchemaVersion != "1" ||
		!validSHA(doc.CoreSHA256) || !validSHA(doc.SourceSBOMSHA256) || !validSHA(doc.SourceNoticesArchiveSHA256) ||
		len(doc.Modules) == 0 || len(doc.Modules) > 64 || len(doc.StandardLibraries) == 0 || len(doc.StandardLibraries) > 8 || len(doc.SupplementalNotices) > 16 {
		return nil, fmt.Errorf("%w: invalid lock boundary", ErrIntegrity)
	}
	catalog := &Catalog{coreDigest: doc.CoreSHA256, modules: make(map[string]Module), standard: make(map[string]StandardLibrary)}
	checked := make(map[string]string)
	verify := func(notice Notice) error {
		if !fs.ValidPath(notice.Path) || !strings.HasPrefix(notice.Path, "LICENSES/") || strings.ContainsAny(notice.Path, "\\:") ||
			!fs.ValidPath(notice.SourcePath) || strings.ContainsAny(notice.SourcePath, "\\:") || !validSHA(notice.SHA256) {
			return fmt.Errorf("%w: invalid notice path or checksum", ErrIntegrity)
		}
		if previous, ok := checked[notice.Path]; ok {
			if previous != notice.SHA256 {
				return fmt.Errorf("%w: conflicting notice checksum", ErrIntegrity)
			}
			return nil
		}
		content, err := readRegular(fsys, notice.Path, maxNoticeBytes)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != notice.SHA256 {
			return fmt.Errorf("%w: notice bytes changed", ErrIntegrity)
		}
		checked[notice.Path] = notice.SHA256
		return nil
	}
	for _, module := range doc.Modules {
		key := module.Path + "@" + module.Version
		if _, duplicate := catalog.modules[key]; duplicate || !validModule(module) {
			return nil, fmt.Errorf("%w: invalid or duplicate module", ErrIntegrity)
		}
		paths := make(map[string]bool)
		for _, notice := range module.Notices {
			if paths[notice.SourcePath] || notice.Path != "LICENSES/dependencies/"+notice.SHA256+".txt" {
				return nil, fmt.Errorf("%w: invalid module notice identity", ErrIntegrity)
			}
			paths[notice.SourcePath] = true
			if err := verify(notice); err != nil {
				return nil, err
			}
		}
		catalog.modules[key] = module
	}
	for _, library := range doc.StandardLibraries {
		if _, duplicate := catalog.standard[library.Version]; duplicate || !strings.HasPrefix(library.Version, "go1.") ||
			strings.ContainsAny(library.Version, " \r\n\t/\\:") || len(library.Version) > 32 || library.License != "BSD-3-Clause" || !validSourceURL(library.SourceURL) {
			return nil, fmt.Errorf("%w: invalid standard library", ErrIntegrity)
		}
		if err := verify(Notice{Path: library.Path, SourcePath: "LICENSE", SHA256: library.SHA256}); err != nil {
			return nil, err
		}
		catalog.standard[library.Version] = library
	}
	for _, notice := range doc.SupplementalNotices {
		if err := verify(notice); err != nil {
			return nil, err
		}
	}
	return catalog, nil
}

// Module 返回本次 ELF 的精确许可；缺少身份或 h1 不符都不能继承旧许可结论。
func (c *Catalog) Module(path, version, sum string) (Module, error) {
	if c == nil {
		return Module{}, ErrUnreviewed
	}
	module, ok := c.modules[path+"@"+version]
	if !ok || module.Sum != sum {
		return Module{}, ErrUnreviewed
	}
	module.Notices = slices.Clone(module.Notices)
	return module, nil
}

// StandardLibrary 返回核心工具链对应的已审许可；未知版本不能沿用旧结论。
func (c *Catalog) StandardLibrary(version string) (StandardLibrary, error) {
	if c == nil {
		return StandardLibrary{}, ErrUnreviewed
	}
	library, ok := c.standard[version]
	if !ok {
		return StandardLibrary{}, ErrUnreviewed
	}
	return library, nil
}

// CoreDigest 返回此许可清单绑定的上游核心摘要。
func (c *Catalog) CoreDigest() string {
	if c == nil {
		return ""
	}
	return c.coreDigest
}

// ModuleCount 返回已审查的精确模块身份数量。
func (c *Catalog) ModuleCount() int {
	if c == nil {
		return 0
	}
	return len(c.modules)
}

// ============================ 纯格式与文件边界 ============================
func validModule(module Module) bool {
	if module.Path == "" || !fs.ValidPath(module.Path) || strings.ContainsAny(module.Path, "@\\: \r\n\t") ||
		!strings.HasPrefix(module.Version, "v") || strings.ContainsAny(module.Version, "@/\\: \r\n\t") || len(module.Version) > 128 ||
		!approvedExpression(module.License) || len(module.Notices) == 0 || len(module.Notices) > 128 ||
		module.SourceURL != "https://proxy.golang.org/"+module.Path+"/@v/"+module.Version+".zip" {
		return false
	}
	if !strings.HasPrefix(module.Sum, "h1:") {
		return false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(module.Sum, "h1:"))
	return err == nil && len(decoded) == sha256.Size
}

func approvedExpression(expression string) bool {
	switch expression {
	case "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "MIT", "MPL-2.0",
		"LGPL-3.0-only WITH LGPL-3.0-linking-exception", "Apache-2.0 AND BSD-3-Clause AND MIT",
		"Apache-2.0 AND MIT", "BSD-3-Clause AND MIT", "BSD-3-Clause AND MPL-2.0":
		return true
	default:
		return false
	}
}

func validSHA(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func validSourceURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func readRegular(fsys fs.FS, path string, limit int64) ([]byte, error) {
	file, err := fsys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: notice input unavailable", ErrIntegrity)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("%w: input is not a bounded regular file", ErrIntegrity)
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, fmt.Errorf("%w: input read failed", ErrIntegrity)
	}
	return raw, nil
}
