// SPDX-License-Identifier: AGPL-3.0-only

package abi_test

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// Each service value is bound to one plugin's socket (p), which is how the host knows the caller.

type stateService struct {
	pb.UnimplementedHostStateServiceServer // DeleteState and ListState are not needed by the trial
	h                                      *fakeHost
	p                                      *hostPlugin
}

var kvKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,256}$`)

// kvKey namespaces a key to the calling instance (platform.proto, Host: state).
func kvKey(inst *hostInstance, key string) string { return inst.key() + "\x00" + key }

func (h *fakeHost) kvGet(inst *hostInstance, key string) (kvEntry, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.kv[kvKey(inst, key)]
	return e, ok
}

func (s *stateService) GetState(_ context.Context, req *pb.GetStateRequest) (*pb.GetStateResponse, error) {
	inst, err := s.h.caller(s.p, req.GetContext())
	if err != nil {
		return nil, err
	}
	if err := s.h.authorize(inst, req.GetContext(), false, kvCap("read"), "state.kv.read"); err != nil {
		return nil, err
	}
	if !kvKeyPattern.MatchString(req.GetKey()) {
		return nil, status.Error(codes.InvalidArgument, "invalid key")
	}
	e, ok := s.h.kvGet(inst, req.GetKey())
	return &pb.GetStateResponse{ValueJson: e.value, Found: ok, Revision: e.revision}, nil
}

// PutState: a failed must_not_exist / expected_revision guard is a gRPC ABORTED status. Host
// services have no ErrorDetail in their responses, so a status code is the only option without a
// proto change; ABORTED is gRPC's code for a failed compare-and-swap (see report).
func (s *stateService) PutState(_ context.Context, req *pb.PutStateRequest) (*pb.PutStateResponse, error) {
	inst, err := s.h.caller(s.p, req.GetContext())
	if err != nil {
		return nil, err
	}
	if err := s.h.authorize(inst, req.GetContext(), true, kvCap("write"), "state.kv.write"); err != nil {
		return nil, err
	}
	if !kvKeyPattern.MatchString(req.GetKey()) || !json.Valid(req.GetValueJson()) {
		return nil, status.Error(codes.InvalidArgument, "invalid key or value")
	}
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	k := kvKey(inst, req.GetKey())
	cur, exists := s.h.kv[k]
	switch pre := req.GetPrecondition().(type) {
	case *pb.PutStateRequest_MustNotExist:
		if pre.MustNotExist && exists {
			return nil, status.Errorf(codes.Aborted, "key %q exists at revision %s", req.GetKey(), cur.revision)
		}
	case *pb.PutStateRequest_ExpectedRevision:
		if !exists || cur.revision != pre.ExpectedRevision {
			return nil, status.Errorf(codes.Aborted, "key %q is at revision %q, not %q", req.GetKey(), cur.revision, pre.ExpectedRevision)
		}
	}
	s.h.seq++
	rev := strconv.FormatUint(s.h.seq, 10)
	s.h.kv[k] = kvEntry{value: append([]byte(nil), req.GetValueJson()...), revision: rev}
	return &pb.PutStateResponse{Revision: rev}, nil
}

type eventsService struct {
	pb.UnimplementedHostEventsServiceServer
	h *fakeHost
	p *hostPlugin
}

// ReportChanges validates every subject before emitting anything. The ABI does not say whose actor
// such events carry; the trial attributes them to the plugin as a SERVICE actor (see report).
func (s *eventsService) ReportChanges(_ context.Context, req *pb.ReportChangesRequest) (*pb.ReportChangesResponse, error) {
	inst, err := s.h.caller(s.p, req.GetContext())
	if err != nil {
		return nil, err
	}
	subjects := make([]string, len(req.GetChanges()))
	for i, c := range req.GetChanges() {
		if subjects[i], err = fullSubject(inst, c.GetSubject()); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	actor := &pb.Actor{Kind: pb.ActorKind_ACTOR_KIND_SERVICE, Id: "plugin:" + s.p.desc.GetPluginId()}
	for i, c := range req.GetChanges() {
		s.h.appendChange(subjects[i], c, actor, "", req.GetContext().GetTraceId(), s.p.node)
	}
	return &pb.ReportChangesResponse{}, nil
}

type configService struct {
	pb.UnimplementedHostConfigServiceServer
	h *fakeHost
	p *hostPlugin
}

func (s *configService) GetConfig(_ context.Context, req *pb.GetConfigRequest) (*pb.GetConfigResponse, error) {
	inst, err := s.h.caller(s.p, req.GetContext())
	if err != nil {
		return nil, err
	}
	if r := req.GetRevision(); r != "" && r != inst.configRev {
		return nil, status.Errorf(codes.NotFound, "config revision %s", r)
	}
	return &pb.GetConfigResponse{ConfigJson: inst.config, Revision: inst.configRev}, nil
}

// activeInstance resolves an InvokePlugin target to an ACTIVE instance.
func (h *fakeHost) activeInstance(node, pluginID, instanceID string) *hostInstance {
	h.mu.Lock()
	defer h.mu.Unlock()
	hp := h.plugins[node+"/"+pluginID]
	if hp == nil {
		return nil
	}
	if inst := hp.insts[instanceID]; inst != nil && inst.active {
		return inst
	}
	return nil
}
