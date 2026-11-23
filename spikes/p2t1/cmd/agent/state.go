// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/qwq-panel/qwq/spikes/p2t1/internal/echopb"
)

// PluginState is the agent-side record for one plugin. Every field that matters
// for identity is derived from systemd or the kernel, not from plugin messages.
type PluginState struct {
	PluginID   string `json:"plugin_id"`
	Unit       string `json:"unit"`
	Socket     string `json:"socket"`
	HostSocket string `json:"host_socket"`
	LinkPath   string `json:"link_path"`
	AgentPID   int    `json:"agent_pid"`
	AgentUID   int    `json:"agent_uid"`
	AgentUnit  string `json:"agent_unit"`
	AttachedAt string `json:"attached_at"`

	Error string `json:"error,omitempty"`

	SocketUnitStartedMS int64 `json:"socket_unit_started_ms"`
	ColdStartMS         int64 `json:"cold_start_ms"`
	FirstRPCMs          int64 `json:"first_rpc_ms"`
	EchoCallMS          int64 `json:"echo_call_ms"`
	HealthAttempts      int   `json:"health_attempts"`

	MainPID         int    `json:"main_pid"`
	PluginUID       uint32 `json:"plugin_uid"`
	PluginCgroup    string `json:"plugin_cgroup"`
	PluginUnit      string `json:"plugin_unit"`
	PluginStartTime uint64 `json:"plugin_start_time"`
	Generation      string `json:"generation"`

	PeerPID      int32  `json:"peer_pid"`
	PeerUID      uint32 `json:"peer_uid"`
	Pidfd        bool   `json:"peer_pidfd"`
	PidfdErr     string `json:"peer_pidfd_err,omitempty"`
	PidfdAlive   bool   `json:"peer_pidfd_alive"`
	MainPIDMatch bool   `json:"main_pid_match"`
	UnitMatch    bool   `json:"unit_match"`
	// PluginSocketPeerIsSystemd records the socket-activation consequence: the
	// client side of SO_PEERCRED sees the listening socket owner (systemd), not
	// the plugin process.
	PluginSocketPeerIsSystemd bool `json:"plugin_socket_peer_is_systemd"`

	// The plugin's real identity is attested on the host channel, where the
	// plugin is the client and the kernel reports its pid/uid to the agent.
	HostVerified     bool   `json:"host_verified"`
	HostPeerPID      int32  `json:"host_peer_pid"`
	HostPeerUID      uint32 `json:"host_peer_uid"`
	HostPeerUnit     string `json:"host_peer_unit"`
	HostPeerCgroup   string `json:"host_peer_cgroup"`
	HostMainPIDMatch bool   `json:"host_main_pid_match"`
	HostGeneration   string `json:"host_generation"`
	HostReportCount  int    `json:"host_report_count"`

	ReattachPid      int    `json:"reattach_pid"`
	GoPluginPeerPID  int32  `json:"go_plugin_peer_pid"`
	GoPluginPeerUID  uint32 `json:"go_plugin_peer_uid"`
	GoPluginPeerUnit string `json:"go_plugin_peer_unit"`

	AgentPeerVerified    bool                 `json:"agent_peer_verified"`
	AgentPeerUnitVisible bool                 `json:"agent_peer_unit_visible"`
	Echo                 *echopb.EchoResponse `json:"echo,omitempty"`
	EchoErr              string               `json:"echo_err,omitempty"`

	Environment    string `json:"environment"`
	LoadCredential string `json:"load_credential"`

	Probes []ProbeResult `json:"probes,omitempty"`
}

// ProbeResult is one sandbox probe executed by a plugin.
type ProbeResult struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	WantDial bool   `json:"want_dial"`
	StatErr  string `json:"stat_err,omitempty"`
	IsSocket bool   `json:"is_socket"`
	DialOK   bool   `json:"dial_ok"`
	DialErr  string `json:"dial_err,omitempty"`
	RPCErr   string `json:"rpc_err,omitempty"`
	Pass     bool   `json:"pass"`
}

// HostState is the agent-side record of the last host report from a plugin.
type HostState struct {
	PluginID   string                    `json:"plugin_id"`
	Accepted   bool                      `json:"accepted"`
	Reason     string                    `json:"reason,omitempty"`
	Count      int                       `json:"count"`
	At         string                    `json:"at"`
	AgentPID   int                       `json:"agent_pid"`
	PeerPID    int32                     `json:"peer_pid"`
	PeerUID    uint32                    `json:"peer_uid"`
	PeerUnit   string                    `json:"peer_unit"`
	PeerCgroup string                    `json:"peer_cgroup"`
	Pidfd      bool                      `json:"peer_pidfd"`
	Unit       string                    `json:"unit"`
	MainPID    int                       `json:"main_pid"`
	Generation string                    `json:"generation"`
	Request    *echopb.HostReportRequest `json:"request"`
}

func statePath(dir, id string) string     { return filepath.Join(dir, id+".json") }
func hostStatePath(dir, id string) string { return filepath.Join(dir, id+".host.json") }

func writeState(dir, id string, st *PluginState) error {
	return writeJSON(statePath(dir, id), st)
}

func writeHostState(dir, id string, st *HostState) error {
	return writeJSON(hostStatePath(dir, id), st)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readState(dir, id string) (*PluginState, error) {
	b, err := os.ReadFile(statePath(dir, id))
	if err != nil {
		return nil, err
	}
	st := new(PluginState)
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", statePath(dir, id), err)
	}
	return st, nil
}

func readHostState(dir, id string) (*HostState, error) {
	b, err := os.ReadFile(hostStatePath(dir, id))
	if err != nil {
		return nil, err
	}
	hs := new(HostState)
	if err := json.Unmarshal(b, hs); err != nil {
		return nil, fmt.Errorf("parse host state %s: %w", hostStatePath(dir, id), err)
	}
	return hs, nil
}
