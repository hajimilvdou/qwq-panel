// SPDX-License-Identifier: AGPL-3.0-only

package sshd

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"

	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
)

var settingTrace = regexp.MustCompile(`^debug3: (.+):([0-9]+) setting ([^ ]+) (.*)$`)

type tracedSetting struct {
	key, value, file string
	matched          bool
}

func canonicalSetting(key, value string) (string, string) {
	key = strings.ToLower(key)
	value = strings.Join(strings.Fields(value), " ")
	if key == "challengeresponseauthentication" {
		key = "kbdinteractiveauthentication"
	}
	if key == "permitrootlogin" && value == "without-password" {
		value = "prohibit-password"
	}
	return key, value
}

// 来源由同一完整配置的原生 -ddd 诊断与展开行映射确认，不用静态首值猜测 Match。
func annotatedSettings(output, diagnostics []byte, candidatePath string, origins []origin) ([]*sshdv1.Setting, error) {
	var trace []tracedSetting
	for _, line := range strings.Split(string(diagnostics), "\n") {
		match := settingTrace.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		if match[1] != candidatePath && match[1] != "reprocess config" {
			return nil, errors.New("sshd: unexpected diagnostic source")
		}
		index, err := strconv.Atoi(match[2])
		if err != nil || index < 1 || index > len(origins) {
			return nil, errors.New("sshd: diagnostic line is outside candidate")
		}
		key, value := canonicalSetting(match[3], match[4])
		trace = append(trace, tracedSetting{key: key, value: value, file: origins[index-1].File, matched: match[1] == "reprocess config"})
	}
	var settings []*sshdv1.Setting
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, " ")
		if !ok || key == "" {
			return nil, errors.New("sshd: invalid effective setting")
		}
		key, value = canonicalSetting(key, value)
		setting := &sshdv1.Setting{Key: key, Value: value, SourceFile: "<OpenSSH default>"}
		var winner *tracedSetting
		// 匹配块重处理覆盖全局默认；块内仍由 OpenSSH 取首个适用值。
		for _, matched := range []bool{true, false} {
			for index := range trace {
				entry := &trace[index]
				if entry.matched == matched && entry.key == key && entry.value == value {
					winner = entry
					break
				}
			}
			if winner != nil {
				break
			}
		}
		var declared, shadowed []string
		for _, entry := range trace {
			if entry.key == key {
				declared = append(declared, entry.file)
			}
		}
		if winner != nil {
			setting.SourceFile = winner.file
			for _, file := range declared {
				if file != winner.file {
					shadowed = append(shadowed, file)
				}
			}
			slices.Sort(shadowed)
			setting.OverriddenBy = strings.Join(slices.Compact(shadowed), ", ")
		} else if len(declared) != 0 {
			// OpenSSH 规范化某些复合值。未确认具体来源时明确标注，禁止伪造路径。
			setting.SourceFile = "<OpenSSH effective; source unconfirmed>"
		}
		settings = append(settings, setting)
	}
	if len(settings) == 0 {
		return nil, errors.New("sshd: empty native effective config")
	}
	return settings, nil
}
