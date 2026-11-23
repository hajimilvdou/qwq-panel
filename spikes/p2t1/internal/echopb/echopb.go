// SPDX-License-Identifier: AGPL-3.0-only

// Package echopb defines the two minimal gRPC services used by the P2-T1
// spike. Payloads are JSON encoded through a codec registered as "json" so the
// spike does not need generated protobuf code. The service and method names
// follow the production naming style so the wire shape is realistic.
package echopb

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
)

// JSONSubtype is the gRPC content subtype used for all spike messages.
const JSONSubtype = "json"

func init() {
	encoding.RegisterCodec(jsonCodec{})
}

type jsonCodec struct{}

func (jsonCodec) Name() string { return JSONSubtype }

func (jsonCodec) Marshal(v any) ([]byte, error) { return json.Marshal(v) }

func (jsonCodec) Unmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

// Service names. The agent dials /qwq.spike.v1.Echo, the plugin dials
// /qwq.spike.v1.Host.
const (
	EchoServiceName = "qwq.spike.v1.Echo"
	HostServiceName = "qwq.spike.v1.Host"
)

// EchoRequest is sent by the agent to the plugin.
type EchoRequest struct {
	Message string `json:"message"`
	// Nonce is opaque to the plugin and echoed back; the agent uses it to bind
	// the answer to the call it made.
	Nonce string `json:"nonce"`
}

// EchoResponse reports what the plugin saw, including the kernel-provided peer
// credentials the plugin observed for the agent connection.
type EchoResponse struct {
	Message   string `json:"message"`
	Nonce     string `json:"nonce"`
	PluginID  string `json:"plugin_id"`
	Pid       int    `json:"pid"`
	UID       uint32 `json:"uid"`
	StartedAt int64  `json:"started_at_unix_nano"`

	PeerPID  int32  `json:"peer_pid"`
	PeerUID  uint32 `json:"peer_uid"`
	PeerUnit string `json:"peer_unit"`
	PIDFD    bool   `json:"peer_pidfd_supported"`
	// AgentUID is the agent uid the plugin expects; it is taken from the owner
	// of the host socket, which only the agent can create.
	AgentUID uint32 `json:"expected_agent_uid"`
	// PeerUnitErr is set when the plugin cannot read the agent's cgroup, which
	// is the normal case under ProtectProc=invisible.
	PeerUnitErr string `json:"peer_unit_err,omitempty"`

	CredentialSHA256 string `json:"credential_sha256"`
	CredentialBytes  int    `json:"credential_bytes"`

	HostReportOK     bool   `json:"host_report_ok"`
	HostReportReason string `json:"host_report_reason"`
	HostGeneration   string `json:"host_generation"`
	HostAgentPID     int32  `json:"host_agent_pid"`
}

// ProbeRequest asks the plugin to exercise a filesystem path from inside its
// own sandbox (stat + connect). This is a spike-only test hook; a production
// ABI must never expose arbitrary path access.
type ProbeRequest struct {
	Path string `json:"path"`
}

// ProbeResponse reports the result of ProbeRequest.
type ProbeResponse struct {
	Path     string `json:"path"`
	StatErr  string `json:"stat_err"`
	IsSocket bool   `json:"is_socket"`
	DialOK   bool   `json:"dial_ok"`
	DialErr  string `json:"dial_err"`
}

// HostReportRequest is sent by the plugin to the agent over the per-plugin
// host socket.
type HostReportRequest struct {
	PluginID  string `json:"plugin_id"`
	PluginPID int    `json:"plugin_pid"`
	PluginUID uint32 `json:"plugin_uid"`
	StartedAt int64  `json:"started_at_unix_nano"`
	Attempt   int    `json:"attempt"`
}

// HostReportResponse is the agent's answer. The agent derives Unit, MainPID
// and Generation from systemd and from the kernel-provided peer credentials,
// never from the request fields.
type HostReportResponse struct {
	Accepted   bool   `json:"accepted"`
	Reason     string `json:"reason"`
	Unit       string `json:"unit"`
	MainPID    int    `json:"main_pid"`
	Generation string `json:"generation"`

	AgentPID  int32  `json:"agent_pid"`
	PeerPID   int32  `json:"peer_pid"`
	PeerUID   uint32 `json:"peer_uid"`
	PeerUnit  string `json:"peer_unit"`
	PIDFDSeen bool   `json:"peer_pidfd_supported"`
}

// EchoServer is implemented by the plugin.
type EchoServer interface {
	Echo(context.Context, *EchoRequest) (*EchoResponse, error)
	Probe(context.Context, *ProbeRequest) (*ProbeResponse, error)
}

// HostServer is implemented by the agent.
type HostServer interface {
	Report(context.Context, *HostReportRequest) (*HostReportResponse, error)
}

// RegisterEchoServer registers the echo service on a gRPC server.
func RegisterEchoServer(s *grpc.Server, srv EchoServer) {
	s.RegisterService(&EchoServiceDesc, srv)
}

// RegisterHostServer registers the host service on a gRPC server.
func RegisterHostServer(s *grpc.Server, srv HostServer) {
	s.RegisterService(&HostServiceDesc, srv)
}

// EchoServiceDesc is the service descriptor for the plugin-side service.
var EchoServiceDesc = grpc.ServiceDesc{
	ServiceName: EchoServiceName,
	HandlerType: (*EchoServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Echo", Handler: echoHandler},
		{MethodName: "Probe", Handler: probeHandler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "spikes/p2t1/echo.json",
}

// HostServiceDesc is the service descriptor for the agent-side service.
var HostServiceDesc = grpc.ServiceDesc{
	ServiceName: HostServiceName,
	HandlerType: (*HostServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Report", Handler: reportHandler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "spikes/p2t1/host.json",
}

func echoHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(EchoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EchoServer).Echo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + EchoServiceName + "/Echo"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(EchoServer).Echo(ctx, req.(*EchoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func probeHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(ProbeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EchoServer).Probe(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + EchoServiceName + "/Probe"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(EchoServer).Probe(ctx, req.(*ProbeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func reportHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(HostReportRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HostServer).Report(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + HostServiceName + "/Report"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(HostServer).Report(ctx, req.(*HostReportRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// EchoClient is a JSON-codec client for the plugin-side service.
type EchoClient struct{ cc *grpc.ClientConn }

// NewEchoClient returns a client bound to cc.
func NewEchoClient(cc *grpc.ClientConn) *EchoClient { return &EchoClient{cc: cc} }

// Echo performs the Echo RPC.
func (c *EchoClient) Echo(ctx context.Context, in *EchoRequest) (*EchoResponse, error) {
	out := new(EchoResponse)
	err := c.cc.Invoke(ctx, "/"+EchoServiceName+"/Echo", in, out, grpc.CallContentSubtype(JSONSubtype))
	return out, err
}

// Probe performs the Probe RPC.
func (c *EchoClient) Probe(ctx context.Context, in *ProbeRequest) (*ProbeResponse, error) {
	out := new(ProbeResponse)
	err := c.cc.Invoke(ctx, "/"+EchoServiceName+"/Probe", in, out, grpc.CallContentSubtype(JSONSubtype))
	return out, err
}

// HostClient is a JSON-codec client for the agent-side service.
type HostClient struct{ cc *grpc.ClientConn }

// NewHostClient returns a client bound to cc.
func NewHostClient(cc *grpc.ClientConn) *HostClient { return &HostClient{cc: cc} }

// Report performs the Report RPC.
func (c *HostClient) Report(ctx context.Context, in *HostReportRequest) (*HostReportResponse, error) {
	out := new(HostReportResponse)
	err := c.cc.Invoke(ctx, "/"+HostServiceName+"/Report", in, out, grpc.CallContentSubtype(JSONSubtype))
	return out, err
}
