// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"strconv"
	"strings"
)

// ======================== 只读实际 Manager.Version 与 loaded 属性，禁止客户端版本替代 ========================

var generationLoadedProperties = []string{"MainPID", "ControlGroup", "Type", "DynamicUser", "KillMode", "RemainAfterExit", "SendSIGKILL", "InvocationID"}

// ReadGenerationProfile 核两份 loaded 元组及两侧实际 manager 版本；所有查询共用 Pin 预算。
func (systemctl *ExecSystemctl) ReadGenerationProfile(ctx context.Context, pluginID string) (LoadedGenerationProfile, error) {
	unit, _, err := UnitNames(pluginID)
	if err != nil || systemctl == nil {
		return LoadedGenerationProfile{}, ErrGenerationProfile
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, DefaultGenerationPinTimeout)
	defer cancel()
	version, major, err := systemctl.readGenerationManagerVersion(ctx)
	if err != nil {
		return LoadedGenerationProfile{}, err
	}
	args := generationLoadedArguments(unit, major)
	first, err := systemctl.readGenerationLoadedProfile(ctx, pluginID, major, args)
	if err != nil {
		return LoadedGenerationProfile{}, err
	}
	second, err := systemctl.readGenerationLoadedProfile(ctx, pluginID, major, args)
	if err != nil {
		return LoadedGenerationProfile{}, err
	}
	currentVersion, currentMajor, err := systemctl.readGenerationManagerVersion(ctx)
	if err != nil {
		return LoadedGenerationProfile{}, err
	}
	if version != currentVersion || major != currentMajor || first != second {
		return LoadedGenerationProfile{}, ErrGenerationProfile
	}
	if err := ctx.Err(); err != nil {
		return LoadedGenerationProfile{}, err
	}
	return first, nil
}

func generationLoadedArguments(unit string, major uint32) []string {
	args := []string{"show", "--no-pager"}
	for _, property := range generationLoadedProperties {
		args = append(args, "--property="+property)
	}
	if major >= 250 {
		args = append(args, "--property=ExitType")
	}
	return append(args, unit)
}

func (systemctl *ExecSystemctl) readGenerationLoadedProfile(ctx context.Context, pluginID string, major uint32, args []string) (LoadedGenerationProfile, error) {
	output, err := systemctl.run(ctx, args...)
	if err != nil {
		return LoadedGenerationProfile{}, err
	}
	if len(output) == 0 || len(output) > MaxGenerationMessage {
		return LoadedGenerationProfile{}, ErrGenerationProfile
	}
	allowed := make(map[string]bool, len(generationLoadedProperties)+1)
	for _, property := range generationLoadedProperties {
		allowed[property] = true
	}
	if major >= 250 {
		allowed["ExitType"] = true
	}
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		key, _, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
		if !ok || !allowed[key] {
			return LoadedGenerationProfile{}, ErrGenerationProfile
		}
	}
	return ParseGenerationProfile(pluginID, major, output)
}

func (systemctl *ExecSystemctl) readGenerationManagerVersion(ctx context.Context) (string, uint32, error) {
	output, err := systemctl.run(ctx, "show", "--no-pager", "--property=Version")
	if err != nil {
		return "", 0, err
	}
	return parseGenerationManagerVersion(output)
}

func parseGenerationManagerVersion(output string) (string, uint32, error) {
	if len(output) == 0 || len(output) > 256 {
		return "", 0, ErrGenerationProfile
	}
	var version string
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
		if !ok || key != "Version" || version != "" || value == "" {
			return "", 0, ErrGenerationProfile
		}
		version = value
	}
	if version == "" || version[0] < '1' || version[0] > '9' {
		return "", 0, ErrGenerationProfile
	}
	end := 0
	for end < len(version) && version[end] >= '0' && version[end] <= '9' {
		end++
	}
	major, err := strconv.ParseUint(version[:end], 10, 32)
	if err != nil || major < 247 || end < len(version) && !strings.ContainsRune(".-+~", rune(version[end])) {
		return "", 0, ErrGenerationProfile
	}
	if end < len(version) && (end+1 == len(version) || strings.ContainsRune(".-+~", rune(version[end+1])) || strings.ContainsRune(".-+~", rune(version[len(version)-1]))) {
		return "", 0, ErrGenerationProfile
	}
	for _, character := range version[end:] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || strings.ContainsRune(".-+~", character)) {
			return "", 0, ErrGenerationProfile
		}
	}
	return version, uint32(major), nil
}

var _ GenerationProfileReader = (*ExecSystemctl)(nil)
