// SPDX-License-Identifier: AGPL-3.0-only

package install

import (
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/qwq-panel/qwq/sdk/manifest"
)

// PolicyError reports a package that is authentic and intact but violates a
// host policy that is not expressible in the manifest schema. The updater maps
// it to VALIDATION_FAILED so the caller sees a fixable rejection instead of
// INTERNAL.
type PolicyError struct {
	// Path is the package-relative file involved ("" for the package itself).
	Path string
	// Code is a stable machine-readable identifier.
	Code string
	// Message is for humans; it never echoes file content.
	Message string
}

func (e *PolicyError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("install: %s: %s", e.Path, e.Message)
	}
	return "install: " + e.Message
}

// uiScriptExtensions are the asset types that can reference a script at run
// time. Everything else in ui/ is binary and skipped.
var uiScriptExtensions = map[string]bool{
	".html": true, ".htm": true, ".js": true, ".mjs": true, ".cjs": true,
	".css": true, ".svg": true,
}

// uiScriptPatterns match runtime remote-script references in a ui/ asset
// (ARCH §5.1: the ui/ tree carries no runtime remote scripts). The sandbox CSP
// blocks them at run time anyway; refusing the package keeps the served tree
// within what the contract promises — classic scripts and same-package assets.
var uiScriptPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']?\s*(?:https?:)?//`),
	regexp.MustCompile(`(?i)\bimportScripts\s*\(\s*["']\s*(?:https?:)?//`),
	regexp.MustCompile(`(?i)\bimport\s*\(\s*["']\s*(?:https?:)?//`),
	regexp.MustCompile(`(?i)\bfrom\s*["']\s*(?:https?:)?//`),
	regexp.MustCompile(`(?i)\bnew\s+Worker\s*\(\s*["']\s*(?:https?:)?//`),
}

// checkUIAssets rejects a staged package whose ui/ tree references remote
// scripts. Only the files the signed manifest lists are read, exactly the set
// that is ever served.
func checkUIAssets(root *os.Root, m *manifest.Manifest) error {
	if m == nil || m.UI == nil {
		return nil
	}
	paths := make([]string, 0, 8)
	for p := range m.Files {
		if strings.HasPrefix(p, "ui/") {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		if !uiScriptExtensions[strings.ToLower(path.Ext(p))] {
			continue
		}
		raw, err := readPackageFile(root, p)
		if err != nil {
			return err
		}
		for _, re := range uiScriptPatterns {
			if re.Match(raw) {
				return &PolicyError{
					Path: p, Code: "UI_REMOTE_SCRIPT",
					Message: "ui/ assets must not reference remote scripts at run time",
				}
			}
		}
	}
	return nil
}

// readPackageFile reads one staged file through the confinement root.
func readPackageFile(root *os.Root, p string) ([]byte, error) {
	f, err := root.Open(p)
	if err != nil {
		return nil, fmt.Errorf("install: reading %s: %w", p, err)
	}
	defer f.Close() //nolint:errcheck // read only
	return io.ReadAll(f)
}
