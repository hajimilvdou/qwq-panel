// SPDX-License-Identifier: AGPL-3.0-only

package supervisor

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// State is the lifecycle state of a plugin instance.
type State string

const (
	// StateRunning means the supervisor is attached and serving the host channel.
	StateRunning State = "running"
	// StateDegraded means the last Ensure exhausted its attempts. The plugin is
	// not polled until RetryAt (ARCH §6.4: no restart storm, no busy polling).
	StateDegraded State = "degraded"
)

// Status is a snapshot of one plugin instance for the host's node status.
type Status struct {
	PluginID     string    `json:"plugin_id"`
	Unit         string    `json:"unit"`
	Generation   string    `json:"generation,omitempty"`
	Owner        string    `json:"owner,omitempty"`
	MainPID      int       `json:"main_pid,omitempty"`
	ActiveState  string    `json:"active_state,omitempty"`
	SubState     string    `json:"sub_state,omitempty"`
	ControlGroup string    `json:"control_group,omitempty"`
	State        State     `json:"state"`
	VersionDir   string    `json:"version_dir,omitempty"`
	HostServing  bool      `json:"host_serving"`
	Attempts     int       `json:"attempts,omitempty"`
	Since        time.Time `json:"since"`
	LastError    string    `json:"last_error,omitempty"`
	RetryAt      time.Time `json:"retry_at,omitempty"`
}

// Instance is one attached plugin process generation. Its identity fields are
// immutable; the connection and host channel can be shut down concurrently.
type Instance struct {
	sup *Supervisor

	pluginID   string
	unit       string
	generation string
	owner      string
	mainPID    int
	unitState  UnitState
	versionDir string
	limits     Limits
	since      time.Time
	client     *Client

	mu          sync.Mutex
	closed      bool
	broken      bool
	brokenCause error
	grpc        *grpc.ClientConn
	service     platformv1.PluginServiceClient
	hostStop    func()
	hostCancel  func()
	hostServing bool
}

// newInstance records the identity of a generation. attach installs the
// connection and the host channel once they are ready.
func newInstance(sup *Supervisor, pluginID, gen string, state UnitState, versionDir string, limits Limits) *Instance {
	inst := &Instance{
		sup:        sup,
		pluginID:   pluginID,
		unit:       UnitName(pluginID),
		generation: gen,
		owner:      Owner(pluginID, gen),
		mainPID:    state.MainPID,
		unitState:  state,
		versionDir: versionDir,
		limits:     limits,
		since:      sup.clock.Now(),
	}
	inst.client = newClient(sup, inst)
	return inst
}

// attach 安装原生连接和宿主通道清理句柄。
func (i *Instance) attach(grpcClient *grpc.ClientConn, stop func(), hostCancel func()) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.grpc = grpcClient
	i.service = platformv1.NewPluginServiceClient(grpcClient)
	i.hostStop = stop
	i.hostCancel = hostCancel
	i.hostServing = true
}

// PluginID returns the plugin id.
func (i *Instance) PluginID() string { return i.pluginID }

// Unit returns the systemd unit name.
func (i *Instance) Unit() string { return i.unit }

// Generation returns sha256(unit|MainPID|starttime)[:16] of this generation.
func (i *Instance) Generation() string { return i.generation }

// Owner returns the host-side owner string of this generation (ARCH §5.7).
func (i *Instance) Owner() string { return i.owner }

// MainPID returns the MainPID systemd reported when the instance was attached.
func (i *Instance) MainPID() int { return i.mainPID }

// VersionDir returns the installed version directory of the plugin.
func (i *Instance) VersionDir() string { return i.versionDir }

// Limits returns the resource expectations validated for this instance.
func (i *Instance) Limits() Limits { return i.limits }

// Since returns when the instance was attached.
func (i *Instance) Since() time.Time { return i.since }

// HostServing reports whether the host channel is being served.
func (i *Instance) HostServing() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.hostServing
}

// Client returns the RPC wrapper of the instance, nil after it was shut down.
func (i *Instance) Client() *Client {
	if !i.usable() {
		return nil
	}
	return i.client
}

// Status returns a snapshot for Instances.
func (i *Instance) status() Status {
	i.mu.Lock()
	serving := i.hostServing
	broken := i.broken
	cause := i.brokenCause
	i.mu.Unlock()
	st := Status{
		PluginID:     i.pluginID,
		Unit:         i.unit,
		Generation:   i.generation,
		Owner:        i.owner,
		MainPID:      i.mainPID,
		ActiveState:  i.unitState.ActiveState,
		SubState:     i.unitState.SubState,
		ControlGroup: i.unitState.ControlGroup,
		State:        StateRunning,
		VersionDir:   i.versionDir,
		HostServing:  serving,
		Since:        i.since,
	}
	if broken && cause != nil {
		st.LastError = "the plugin connection broke: " + cause.Error()
	}
	return st
}

func (i *Instance) usable() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return !i.closed && i.grpc != nil
}

// brokenConnection reports whether an RPC failed at the transport level, so the
// supervisor reattaches instead of reusing a dead connection.
func (i *Instance) brokenConnection() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.broken
}

// markTransportFailure records that an RPC failed at the transport level. The
// next Ensure drops the instance and attaches again instead of retrying a dead
// connection until the process happens to restart.
func (i *Instance) markTransportFailure(err error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return
	}
	i.broken = true
	i.brokenCause = err
}

// pluginService returns the generated client, nil after shutdown.
func (i *Instance) pluginService() platformv1.PluginServiceClient {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.service
}

// shutdown stops the host channel and closes the connection exactly once. It
// never signals the plugin process; systemd owns it.
func (i *Instance) shutdown(reason string) {
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return
	}
	i.closed = true
	stop, cancel, grpcClient := i.hostStop, i.hostCancel, i.grpc
	i.hostStop, i.hostCancel, i.grpc, i.service = nil, nil, nil, nil
	i.hostServing = false
	i.mu.Unlock()

	// Cancel first so a host server waiting on the context returns, then wait for
	// it through the stop function.
	if cancel != nil {
		cancel()
	}
	if stop != nil {
		stop()
	}
	closePluginClient(grpcClient)
	i.sup.logger.Info("plugin detached",
		"plugin_id", i.pluginID, "unit", i.unit, "generation", i.generation,
		"owner", i.owner, "main_pid", i.mainPID, "reason", reason)
}

// generation is sha256(unit|MainPID|starttime)[:16]. Every input comes from
// systemd or the kernel; the plugin never contributes to its own identity.
func generation(unit string, mainPID int, start time.Time) string {
	sum := sha256.New()
	_, _ = sum.Write([]byte(unit))
	_, _ = sum.Write([]byte{'|'})
	_, _ = sum.Write([]byte(strconv.Itoa(mainPID)))
	_, _ = sum.Write([]byte{'|'})
	_, _ = sum.Write([]byte(strconv.FormatInt(start.UnixNano(), 10)))
	return hex.EncodeToString(sum.Sum(nil))[:16]
}
