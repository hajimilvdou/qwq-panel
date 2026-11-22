// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const (
	// DefaultCompatUnitctlSocket is the Unix socket opened by the optional
	// qwq-compat-polkit patch (qwq-compat-unitctl.socket) on legacy-polkit
	// distributions such as Ubuntu 22.04 and Debian 11. Native hosts with
	// polkit >= 0.106 never install this patch or create this socket.
	DefaultCompatUnitctlSocket = "/run/qwq/compat-unitctl.sock"

	// DefaultCompatPolkitMarker is the root-owned marker written by the
	// optional qwq-compat-polkit patch installer.
	DefaultCompatPolkitMarker = "/etc/qwq/compat/polkit-compat.json"

	CompatUnitctlOpPing  = "ping"
	CompatUnitctlOpStart = "start"
	CompatUnitctlOpStop  = "stop"
	CompatUnitctlOpKill  = "kill"
)

// compatPluginUnitPattern mirrors deployments/polkit/qwq-plugin.rules exactly:
// only qwq-plugin@<valid-plugin-id>.(service|socket) may be controlled.
var compatPluginUnitPattern = regexp.MustCompile(`^qwq-plugin@[a-z][a-z0-9]*([.-][a-z0-9]+)*\.(service|socket)$`)

// CheckCompatPluginUnit enforces the exact same unit allowlist as
// deployments/polkit/qwq-plugin.rules.
func CheckCompatPluginUnit(unit string) error {
	if !compatPluginUnitPattern.MatchString(unit) {
		return fmt.Errorf("sandbox: compat unitctl refuses unit %q (only qwq-plugin@<id>.service|socket is allowed)", unit)
	}
	return nil
}

// CompatUnitctlActionAllowed reports whether action is in the strict allowlist.
func CompatUnitctlActionAllowed(action string) bool {
	switch action {
	case CompatUnitctlOpPing, CompatUnitctlOpStart, CompatUnitctlOpStop, CompatUnitctlOpKill:
		return true
	default:
		return false
	}
}

// CompatUnitctlRequest is the single JSON frame sent to qwq-compat-unitctl.
type CompatUnitctlRequest struct {
	Action string `json:"action"`
	Unit   string `json:"unit,omitempty"`
}

// CompatUnitctlResponse is the single JSON frame returned by qwq-compat-unitctl.
type CompatUnitctlResponse struct {
	OK      bool   `json:"ok"`
	Code    string `json:"code,omitempty"`
	Error   string `json:"error,omitempty"`
	Version string `json:"version,omitempty"`
	UID     int    `json:"uid"`
}

// CompatUnitctlClient implements Systemctl for legacy-polkit hosts that have
// explicitly installed the qwq-compat-polkit patch. Start, Stop and Kill are
// dispatched over the root:qwq 0660 compat socket (strictly allowlisted to
// qwq-plugin@* units), while Show stays direct unprivileged `systemctl show`.
type CompatUnitctlClient struct {
	Socket  string
	Runner  Runner
	Timeout time.Duration
}

// NewCompatUnitctlClient builds a Systemctl backed by socket for mutations and
// r for read-only Show queries.
func NewCompatUnitctlClient(socket string, r Runner) *CompatUnitctlClient {
	return &CompatUnitctlClient{Socket: socket, Runner: r}
}

// Start starts one qwq-plugin@* unit through qwq-compat-unitctl.
func (c *CompatUnitctlClient) Start(ctx context.Context, unit string) error {
	return c.unitAction(ctx, CompatUnitctlOpStart, unit)
}

// Stop stops one qwq-plugin@* unit through qwq-compat-unitctl.
func (c *CompatUnitctlClient) Stop(ctx context.Context, unit string) error {
	return c.unitAction(ctx, CompatUnitctlOpStop, unit)
}

// Kill sends SIGKILL to the main process of one qwq-plugin@* unit.
func (c *CompatUnitctlClient) Kill(ctx context.Context, unit string) error {
	return c.unitAction(ctx, CompatUnitctlOpKill, unit)
}

// Show delegates read-only unit inspection to ExecSystemctl (no polkit needed).
func (c *CompatUnitctlClient) Show(ctx context.Context, unit string) (UnitStatus, error) {
	return (&ExecSystemctl{Runner: c.Runner, Timeout: c.Timeout}).Show(ctx, unit)
}

// Ping checks that qwq-compat-unitctl is reachable and running as root.
func (c *CompatUnitctlClient) Ping(ctx context.Context) (HelperPing, error) {
	var resp CompatUnitctlResponse
	if err := c.client().exchange(ctx, CompatUnitctlRequest{Action: CompatUnitctlOpPing}, &resp); err != nil {
		return HelperPing{}, err
	}
	if !resp.OK {
		return HelperPing{}, fmt.Errorf("compat-unitctl ping: %s", resp.Error)
	}
	return HelperPing{Version: resp.Version, UID: resp.UID}, nil
}

func (c *CompatUnitctlClient) unitAction(ctx context.Context, action, unit string) error {
	if err := CheckCompatPluginUnit(unit); err != nil {
		return err
	}
	var resp CompatUnitctlResponse
	if err := c.client().exchange(ctx, CompatUnitctlRequest{Action: action, Unit: unit}, &resp); err != nil {
		return fmt.Errorf("compat-unitctl %s %s: %w", action, unit, err)
	}
	if !resp.OK {
		if resp.Error != "" {
			return fmt.Errorf("compat-unitctl %s %s: %s", action, unit, resp.Error)
		}
		return fmt.Errorf("compat-unitctl %s %s failed (%s)", action, unit, resp.Code)
	}
	return nil
}

func (c *CompatUnitctlClient) client() *HelperClient {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultSystemctlTimeout
	}
	return &HelperClient{
		Socket:  c.Socket,
		Timeout: timeout,
	}
}

// CompatPolkitInstalled reports whether the optional qwq-compat-polkit patch is
// installed and active on this host. Native systems (polkit >= 0.106) never
// create either file and always return false.
func CompatPolkitInstalled(markerPath, socketPath string) bool {
	if markerPath == "" {
		markerPath = DefaultCompatPolkitMarker
	}
	if socketPath == "" {
		socketPath = DefaultCompatUnitctlSocket
	}
	if !filepath.IsAbs(markerPath) || !filepath.IsAbs(socketPath) {
		return false
	}
	markerInfo, err := os.Stat(markerPath)
	if err != nil || !markerInfo.Mode().IsRegular() || markerInfo.Mode().Perm()&0o022 != 0 {
		return false
	}
	sockInfo, err := os.Stat(socketPath)
	if err != nil || sockInfo.Mode()&os.ModeSocket == 0 {
		return false
	}
	return true
}

// NewSystemctl selects the native ExecSystemctl on all standard hosts, and
// switches to CompatUnitctlClient only when the optional qwq-compat-polkit
// patch has been installed on a legacy-polkit host.
func NewSystemctl(r Runner) Systemctl {
	if CompatPolkitInstalled(DefaultCompatPolkitMarker, DefaultCompatUnitctlSocket) {
		return NewCompatUnitctlClient(DefaultCompatUnitctlSocket, r)
	}
	return NewExecSystemctl(r)
}
