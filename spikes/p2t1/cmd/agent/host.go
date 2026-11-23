// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/qwq-panel/qwq/spikes/p2t1/internal/echopb"
	"github.com/qwq-panel/qwq/spikes/p2t1/internal/peercred"
)

// hostServer serves the host API for exactly one plugin. Every call is
// authenticated from the kernel-provided peer credentials; request fields are
// only used as a cross-check.
type hostServer struct {
	agent    *agent
	pluginID string

	mu    sync.Mutex
	count int
}

// Report implements echopb.HostServer.
func (h *hostServer) Report(ctx context.Context, req *echopb.HostReportRequest) (*echopb.HostReportResponse, error) {
	resp := &echopb.HostReportResponse{AgentPID: int32(os.Getpid())}
	expectedUnit := h.agent.unit(h.pluginID)

	cred, ok := peercred.FromContext(ctx)
	if !ok {
		resp.Reason = "connection carries no peer credentials"
		h.record(resp, peercred.ProcInfo{}, "", "", 0, req)
		return resp, nil
	}
	resp.PeerPID, resp.PeerUID, resp.PIDFDSeen = cred.PID, cred.UID, cred.PidfdOK

	proc, err := peercred.ReadProc(int(cred.PID))
	if err != nil {
		resp.Reason = fmt.Sprintf("cannot read /proc/%d: %v", cred.PID, err)
		h.record(resp, proc, "", "", 0, req)
		return resp, nil
	}
	resp.PeerUnit = proc.Unit

	mainPID, err := h.agent.currentMainPID(h.pluginID)
	if err != nil || mainPID <= 0 {
		resp.Reason = fmt.Sprintf("no main pid for %s: %v", expectedUnit, err)
		h.record(resp, proc, "", "", 0, req)
		return resp, nil
	}

	reason := ""
	switch {
	case proc.Unit != expectedUnit:
		reason = fmt.Sprintf("peer unit %q is not %q", proc.Unit, expectedUnit)
	case int(cred.PID) != mainPID:
		reason = fmt.Sprintf("peer pid %d is not the unit main pid %d", cred.PID, mainPID)
	case req.PluginPID != mainPID:
		reason = fmt.Sprintf("reported pid %d is not the unit main pid %d", req.PluginPID, mainPID)
	case req.PluginUID != proc.UID:
		reason = fmt.Sprintf("reported uid %d is not the kernel uid %d", req.PluginUID, proc.UID)
	case req.PluginID != h.pluginID:
		reason = fmt.Sprintf("reported plugin id %q is not %q", req.PluginID, h.pluginID)
	}
	if reason != "" {
		resp.Reason = reason
		h.record(resp, proc, expectedUnit, "", mainPID, req)
		return resp, nil
	}

	gen, err := generation(expectedUnit, mainPID, proc.StartTime)
	if err != nil {
		resp.Reason = err.Error()
		h.record(resp, proc, expectedUnit, "", mainPID, req)
		return resp, nil
	}
	resp.Accepted = true
	resp.Unit = expectedUnit
	resp.MainPID = mainPID
	resp.Generation = gen
	h.record(resp, proc, expectedUnit, gen, mainPID, req)
	h.agent.log.Info("host report accepted",
		"plugin", h.pluginID, "peer_pid", cred.PID, "peer_uid", cred.UID,
		"peer_unit", proc.Unit, "generation", gen, "pidfd", cred.PidfdOK)
	return resp, nil
}

func (h *hostServer) record(resp *echopb.HostReportResponse, proc peercred.ProcInfo, unit, gen string, mainPID int, req *echopb.HostReportRequest) {
	h.mu.Lock()
	h.count++
	count := h.count
	h.mu.Unlock()

	st := &HostState{
		PluginID:   h.pluginID,
		Accepted:   resp.Accepted,
		Reason:     resp.Reason,
		Count:      count,
		At:         time.Now().UTC().Format(time.RFC3339Nano),
		AgentPID:   os.Getpid(),
		PeerPID:    resp.PeerPID,
		PeerUID:    resp.PeerUID,
		PeerUnit:   proc.Unit,
		PeerCgroup: proc.Cgroup,
		Pidfd:      resp.PIDFDSeen,
		Unit:       unit,
		MainPID:    mainPID,
		Generation: gen,
		Request:    req,
	}
	if err := writeHostState(h.agent.stateDir, h.pluginID, st); err != nil {
		h.agent.log.Warn("write host state", "plugin", h.pluginID, "err", err)
	}
	if !resp.Accepted {
		h.agent.log.Warn("host report rejected",
			"plugin", h.pluginID, "reason", resp.Reason,
			"peer_pid", resp.PeerPID, "peer_uid", resp.PeerUID, "peer_unit", proc.Unit)
	}
}
