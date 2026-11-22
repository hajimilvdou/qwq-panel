// SPDX-License-Identifier: AGPL-3.0-only

package main

// =============================================================================
//  qwq support-bundle —— 收集排障信息（DEP-05）
// -----------------------------------------------------------------------------
//  内容：doctor.json、最近 1 小时 qwq* 日志、qwq unit 文件、脱敏后的
//  qwq.json、buildinfo。日志与配置按 logging 的敏感键表脱敏；归档 0600。
// =============================================================================

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/buildinfo"
	"github.com/qwq-panel/qwq/internal/doctor"
	"github.com/qwq-panel/qwq/internal/platform/config"
	"github.com/qwq-panel/qwq/internal/platform/logging"
)

const redactedValue = "[REDACTED]"

// bundleSources are what a bundle collects; tests replace them.
type bundleSources struct {
	Doctor     func(ctx context.Context) []doctor.Result
	Journal    func(ctx context.Context) (string, error)
	ConfigPath string
	// UnitGlobs list the unit files and drop-ins to include.
	UnitGlobs []string
}

func runSupportBundle(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("support-bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "output file (.tar.gz, created 0600; must not exist)")
	configPath := fs.String("config", config.DefaultPath, "bootstrap configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(stderr, "qwq support-bundle: --out is required")
		return 2
	}
	if geteuid() != 0 {
		fmt.Fprintln(stderr, "qwq support-bundle: must run as root (use sudo)")
		return 1
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "qwq support-bundle: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	src := bundleSources{
		Doctor: func(ctx context.Context) []doctor.Result {
			return collectDoctor(ctx, doctor.System(), doctorOptions{ConfigPath: *configPath, Sandbox: true})
		},
		Journal: func(ctx context.Context) (string, error) {
			out, err := exec.CommandContext(ctx, "journalctl", "-u", "qwq*", "--since", "-1h", "--no-pager", "-o", "short-iso").Output()
			return string(out), err
		},
		ConfigPath: *configPath,
		UnitGlobs: []string{
			"/etc/systemd/system/qwq-*.service", "/etc/systemd/system/qwq-*.socket",
			"/etc/systemd/system/qwq-*.service.d/*.conf", "/etc/tmpfiles.d/qwq-plugin-*.conf",
		},
	}
	werr := writeSupportBundle(ctx, f, src)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(*out)
		fmt.Fprintf(stderr, "qwq support-bundle: %v\n", werr)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s\n", *out)
	return 0
}

// writeSupportBundle writes the gzip-compressed tar to w. A source that fails
// is recorded in errors.txt instead of aborting the bundle.
func writeSupportBundle(ctx context.Context, w io.Writer, src bundleSources) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	now := time.Now()
	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: now}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	var problems []string

	rs, err := json.MarshalIndent(src.Doctor(ctx), "", "  ")
	if err != nil {
		return err
	}
	if err := add("doctor.json", rs); err != nil {
		return err
	}
	journal, err := src.Journal(ctx)
	if err != nil {
		problems = append(problems, "journal: "+err.Error())
	}
	if err := add("journal.txt", []byte(redactLog(journal))); err != nil {
		return err
	}
	if raw, err := os.ReadFile(src.ConfigPath); err != nil {
		problems = append(problems, "config: "+err.Error())
	} else if err := add("qwq.json", redactJSONDocument(raw)); err != nil {
		return err
	}
	for _, pattern := range src.UnitGlobs {
		files, _ := filepath.Glob(pattern)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				problems = append(problems, f+": "+err.Error())
				continue
			}
			if err := add("units/"+strings.TrimPrefix(f, "/"), b); err != nil {
				return err
			}
		}
	}
	if err := add("buildinfo.txt", []byte(buildinfo.Read().String()+"\n")); err != nil {
		return err
	}
	if len(problems) > 0 {
		if err := add("errors.txt", []byte(strings.Join(problems, "\n")+"\n")); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// sensitiveField also treats contact data as sensitive: a bundle is shared
// with third parties.
func sensitiveField(key string) bool {
	return logging.IsSensitiveKey(key) || strings.EqualFold(key, "email")
}

// redactJSON replaces the values of sensitive keys at any depth.
func redactJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if sensitiveField(k) {
				t[k] = redactedValue
			} else {
				t[k] = redactJSON(val)
			}
		}
	case []any:
		for i := range t {
			t[i] = redactJSON(t[i])
		}
	}
	return v
}

// redactJSONDocument redacts a JSON document; anything unparsable is
// withheld rather than copied verbatim.
func redactJSONDocument(raw []byte) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []byte("[unparsable; withheld]\n")
	}
	out, err := json.MarshalIndent(redactJSON(v), "", "  ")
	if err != nil {
		return []byte("[unencodable; withheld]\n")
	}
	return append(out, '\n')
}

// kvPair matches key=value and "key": "value" pairs in text log lines.
var kvPair = regexp.MustCompile(`("?)([A-Za-z0-9_.-]+)("?\s*[=:]\s*)("[^"]*"|[^\s,}&#]+)`)

// redactLog redacts every line: the JSON object of a structured log line, or
// key=value pairs in any other line.
func redactLog(s string) string {
	var b bytes.Buffer
	for _, line := range strings.SplitAfter(s, "\n") {
		if i := strings.IndexByte(line, '{'); i >= 0 {
			body := strings.TrimRight(line[i:], "\n")
			var v map[string]any
			if json.Unmarshal([]byte(body), &v) == nil {
				out, _ := json.Marshal(redactJSON(v))
				b.WriteString(line[:i])
				b.Write(out)
				if strings.HasSuffix(line, "\n") {
					b.WriteByte('\n')
				}
				continue
			}
		}
		b.WriteString(kvPair.ReplaceAllStringFunc(line, func(m string) string {
			p := kvPair.FindStringSubmatch(m)
			if !sensitiveField(p[2]) {
				return m
			}
			return p[1] + p[2] + p[3] + redactedValue
		}))
	}
	return b.String()
}
