// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

const maxConfigFiles = 64
const maxConfigBytes = 512 << 10
const ownedDropIn = "sshd_config.d/00-qwq.conf"

var externalIncludeRoots = []string{"/etc/crypto-policies/back-ends"}
var externalSymlinkTargetRoots = []string{"/usr/share/crypto-policies", "/etc/crypto-policies"}

func isAllowedExternalInclude(p string) bool {
	if !filepath.IsAbs(p) || strings.ContainsAny(p, "\x00\\") {
		return false
	}
	clean := filepath.Clean(p)
	for _, root := range externalIncludeRoots {
		rel, err := filepath.Rel(root, clean)
		if err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			return true
		}
	}
	return false
}

func isAllowedExternalSymlinkTarget(p string) bool {
	if !filepath.IsAbs(p) || strings.ContainsAny(p, "\x00\\") {
		return false
	}
	clean := filepath.Clean(p)
	for _, root := range externalSymlinkTargetRoots {
		rel, err := filepath.Rel(root, clean)
		if err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			return true
		}
	}
	return false
}

type origin struct {
	File string
	Line int
}
type configGraph struct {
	files   map[string][]byte
	flat    strings.Builder
	lines   []origin
	covered bool
	global  bool
	bytes   int
	visits  int
}

func (r FileRepository) graph(replacement []byte, replace bool) (*configGraph, error) {
	graph := &configGraph{files: make(map[string][]byte), global: true}
	if replace && replacement != nil {
		graph.files[ownedDropIn] = slices.Clone(replacement)
	}
	if err := r.expand(graph, "sshd_config", replacement, replace, make(map[string]bool)); err != nil {
		return nil, err
	}
	if replace && replacement == nil {
		delete(graph.files, ownedDropIn)
	}
	return graph, nil
}

func (r FileRepository) expand(graph *configGraph, relative string, replacement []byte, replace bool, stack map[string]bool) error {
	graph.visits++
	if graph.visits > maxConfigFiles || len(stack) >= 8 || stack[relative] {
		return errors.New("sshd: Include graph exceeds limits or contains a cycle")
	}
	stack[relative] = true
	defer delete(stack, relative)
	var raw []byte
	var err error
	if relative == ownedDropIn && replace {
		raw = slices.Clone(replacement)
	} else {
		raw, err = r.readConfig(relative)
	}
	if err != nil {
		return err
	}
	if raw == nil {
		if relative == "sshd_config" {
			return errors.New("sshd: main config is missing")
		}
		return nil
	}
	graph.bytes += len(raw)
	if graph.bytes > maxConfigBytes {
		return errors.New("sshd: Include content exceeds limit")
	}
	graph.files[relative] = slices.Clone(raw)
	for index, line := range strings.Split(string(raw), "\n") {
		fields, err := configFields(line)
		if err != nil {
			return err
		}
		if len(fields) > 0 && strings.EqualFold(fields[0], "Include") {
			if len(fields) < 2 {
				return errors.New("sshd: empty Include")
			}
			for _, pattern := range fields[1:] {
				paths, covers, err := r.includePaths(pattern, replacement, replace)
				if err != nil {
					return err
				}
				if covers && graph.global {
					graph.covered = true
				}
				for _, path := range paths {
					if err := r.expand(graph, path, replacement, replace, stack); err != nil {
						return err
					}
				}
			}
			continue
		}
		if len(fields) > 0 && strings.EqualFold(fields[0], "Match") {
			graph.global = false
		}
		graph.flat.WriteString(line)
		graph.flat.WriteByte('\n')
		originFile := relative
		if !filepath.IsAbs(originFile) {
			originFile = filepath.Join(r.ConfigDir, originFile)
		}
		graph.lines = append(graph.lines, origin{File: originFile, Line: index + 1})
	}
	return nil
}

func (r FileRepository) readConfig(relative string) ([]byte, error) {
	ext := filepath.Ext(relative)
	if relative != "sshd_config" && ext != ".conf" && ext != ".config" {
		return nil, errors.New("sshd: Include target is not a configuration file")
	}
	if r.cached != nil {
		return slices.Clone(r.cached[relative]), nil
	}
	isExternal := filepath.IsAbs(relative)
	var parent string
	if isExternal {
		if !isAllowedExternalInclude(relative) {
			return nil, errors.New("sshd: Include escapes config root")
		}
		parent = filepath.Dir(relative)
	} else {
		parent = filepath.Join(r.ConfigDir, filepath.Dir(relative))
	}
	root, err := r.Trust.Open(parent)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Base(relative)
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err == nil && isExternal && info.Mode()&os.ModeSymlink != 0 {
		resolved, rerr := filepath.EvalSymlinks(relative)
		if rerr != nil || !isAllowedExternalSymlinkTarget(resolved) {
			return nil, errors.New("sshd: untrusted config symlink target")
		}
		resolvedRoot, oerr := r.Trust.Open(filepath.Dir(resolved))
		if oerr != nil {
			return nil, oerr
		}
		defer resolvedRoot.Close()
		root = resolvedRoot
		name = filepath.Base(resolved)
		info, err = root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("sshd: untrusted config file")
	}
	uid, ok := sandbox.FileOwner(info)
	if !ok || uid != r.Trust.UID || info.Size() > maxConfigBytes {
		return nil, errors.New("sshd: untrusted config owner or size")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("sshd: config changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil || len(raw) > maxConfigBytes {
		return nil, errors.New("sshd: config read failed")
	}
	return raw, nil
}

// Include 只允许可信 /etc/ssh 内的配置以及受控系统只读目录 /etc/crypto-policies/back-ends/；
// 不读取用户文件、私钥或任意 glob 根。
func (r FileRepository) includePaths(pattern string, replacement []byte, replace bool) ([]string, bool, error) {
	absolute := pattern
	if !filepath.IsAbs(absolute) {
		absolute = filepath.Join(r.ConfigDir, absolute)
	}
	if filepath.IsAbs(pattern) && isAllowedExternalInclude(pattern) {
		return r.externalIncludePaths(filepath.Clean(pattern))
	}
	relative, err := filepath.Rel(r.ConfigDir, absolute)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") || strings.ContainsAny(relative, "\x00\\") {
		return nil, false, errors.New("sshd: Include escapes config root")
	}
	parent := filepath.Dir(relative)
	if strings.ContainsAny(parent, "*?[") {
		return nil, false, errors.New("sshd: glob directory is unsupported")
	}
	if r.cached != nil {
		var paths []string
		for path := range r.cached {
			matched, matchErr := filepath.Match(relative, path)
			if matchErr != nil {
				return nil, false, matchErr
			}
			if matched && !(replace && path == ownedDropIn && replacement == nil) {
				paths = append(paths, path)
			}
		}
		covers, matchErr := filepath.Match(relative, ownedDropIn)
		if matchErr != nil {
			return nil, false, matchErr
		}
		if covers && replace && replacement != nil && !slices.Contains(paths, ownedDropIn) {
			paths = append(paths, ownedDropIn)
		}
		slices.Sort(paths)
		return paths, covers, nil
	}
	root, err := r.Trust.Open(filepath.Join(r.ConfigDir, parent))
	if err != nil {
		return nil, false, err
	}
	defer root.Close()
	entries, err := root.FS().Open(".")
	if err != nil {
		return nil, false, err
	}
	defer entries.Close()
	directory, ok := entries.(interface {
		ReadDir(int) ([]os.DirEntry, error)
	})
	if !ok {
		return nil, false, errors.New("sshd: Include directory cannot be enumerated")
	}
	items, err := directory.ReadDir(maxConfigFiles + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	if len(items) > maxConfigFiles {
		return nil, false, errors.New("sshd: Include directory exceeds limit")
	}
	var paths []string
	for _, item := range items {
		path := filepath.Join(parent, item.Name())
		matched, err := filepath.Match(relative, path)
		if err != nil {
			return nil, false, err
		}
		if matched && !(replace && path == ownedDropIn && replacement == nil) {
			paths = append(paths, path)
		}
	}
	covers, err := filepath.Match(relative, ownedDropIn)
	if err != nil {
		return nil, false, err
	}
	if covers && replace && replacement != nil && !slices.Contains(paths, ownedDropIn) {
		paths = append(paths, ownedDropIn)
	}
	slices.Sort(paths)
	return paths, covers, nil
}

func (r FileRepository) externalIncludePaths(cleanPattern string) ([]string, bool, error) {
	parent := filepath.Dir(cleanPattern)
	if strings.ContainsAny(parent, "*?[") {
		return nil, false, errors.New("sshd: glob directory is unsupported")
	}
	if r.cached != nil {
		var paths []string
		for p := range r.cached {
			if !filepath.IsAbs(p) {
				continue
			}
			matched, err := filepath.Match(cleanPattern, p)
			if err != nil {
				return nil, false, err
			}
			if matched {
				paths = append(paths, p)
			}
		}
		slices.Sort(paths)
		return paths, false, nil
	}
	root, err := r.Trust.Open(parent)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer root.Close()
	entries, err := root.FS().Open(".")
	if err != nil {
		return nil, false, err
	}
	defer entries.Close()
	directory, ok := entries.(interface {
		ReadDir(int) ([]os.DirEntry, error)
	})
	if !ok {
		return nil, false, errors.New("sshd: Include directory cannot be enumerated")
	}
	items, err := directory.ReadDir(maxConfigFiles + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	if len(items) > maxConfigFiles {
		return nil, false, errors.New("sshd: Include directory exceeds limit")
	}
	var paths []string
	for _, item := range items {
		candidate := filepath.Join(parent, item.Name())
		matched, err := filepath.Match(cleanPattern, candidate)
		if err != nil {
			return nil, false, err
		}
		if matched {
			paths = append(paths, candidate)
		}
	}
	slices.Sort(paths)
	return paths, false, nil
}

// configFields 保留 OpenSSH 的引用与注释语义；不支持的转义明确拒绝。
func configFields(line string) ([]string, error) {
	var fields []string
	var token strings.Builder
	quoted := false
	started := false
	flush := func() {
		if started {
			fields = append(fields, token.String())
			token.Reset()
			started = false
		}
	}
	for _, c := range line {
		switch {
		case c == '\\':
			return nil, errors.New("sshd: escaped config syntax is unsupported")
		case c == '"':
			quoted = !quoted
			started = true
		case c == '#' && !quoted:
			flush()
			return fields, nil
		case (c == ' ' || c == '\t' || c == '\r') && !quoted:
			flush()
		case c < 32 || c == 127:
			return nil, errors.New("sshd: invalid config character")
		default:
			token.WriteRune(c)
			started = true
		}
	}
	if quoted {
		return nil, errors.New("sshd: unterminated config quote")
	}
	flush()
	return fields, nil
}

func (g *configGraph) revision(external bool) string {
	paths := make([]string, 0, len(g.files))
	for path := range g.files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	digest := sha256.New()
	for _, path := range paths {
		if external && path == ownedDropIn {
			continue
		}
		fmt.Fprintf(digest, "%d:%s:%d:", len(path), path, len(g.files[path]))
		digest.Write(g.files[path])
	}
	return hex.EncodeToString(digest.Sum(nil))
}
