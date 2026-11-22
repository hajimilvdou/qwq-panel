// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

const capabilityRequestTimeout = 30 * time.Second

type capabilityServer struct {
	runner         sandbox.CapabilityRunner
	logger         *slog.Logger
	version        string
	lookupAgentUID func(string) (int, error)
}

func newCapabilityServer(runner sandbox.CapabilityRunner, logger *slog.Logger, version string) *capabilityServer {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &capabilityServer{runner: runner, logger: logger, version: version}
}

func (s *capabilityServer) agentUID() (int, error) {
	if s.lookupAgentUID != nil {
		return s.lookupAgentUID(sandbox.DefaultAgentUser)
	}
	account, err := user.Lookup(sandbox.DefaultAgentUser)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(account.Uid)
}

func (s *capabilityServer) serve(ctx context.Context, listener net.Listener, oneShot bool) error {
	return sandbox.ServeHelperConnections(ctx, listener, oneShot, 4, s.serveConn)
}

func (s *capabilityServer) serveConn(ctx context.Context, connection net.Conn) {
	uid, err := sandbox.HelperPeerUID(connection)
	if err != nil {
		return
	}
	if uid != 0 {
		agentUID, lookupErr := s.agentUID()
		if lookupErr != nil || uid != agentUID {
			return
		}
	}
	requestCtx, cancel := context.WithTimeout(ctx, capabilityRequestTimeout)
	defer cancel()
	if deadline, ok := requestCtx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return
		}
	}
	var request sandbox.CapabilityRequest
	defer request.Clear()
	if err := sandbox.ReadHelperJSON(connection, &request); err != nil {
		s.logger.Warn("capability request rejected", "code", "INVALID_JSON")
		_ = sandbox.WriteHelperJSON(connection, sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: "能力请求格式无效"})
		return
	}
	executionCtx, finish := sandbox.WatchHelperDisconnect(requestCtx, connection)
	response := s.handle(executionCtx, request)
	finish()
	if err := sandbox.WriteHelperJSON(connection, response); err != nil {
		s.logger.Warn("capability response could not be sent", "code", "TRANSPORT_FAILURE")
	}
	clear(response.ResultJSON)
}

func (s *capabilityServer) handle(ctx context.Context, request sandbox.CapabilityRequest) (response sandbox.CapabilityResponse) {
	defer func() {
		if recover() != nil {
			response = sandbox.CapabilityResponse{Code: "INTERNAL", Error: "能力执行器发生内部错误"}
		}
		// 只记录经过白名单验证的 verb 和结果码，不写参数、秘密或 panic 值。
		if sandbox.CapabilityVerbAllowed(request.Op) {
			s.logger.Info("capability request", "op", request.Op, "ok", response.OK, "code", response.Code)
		}
	}()
	if err := sandbox.ValidateCapabilityRequest(request); err != nil {
		return sandbox.CapabilityResponse{Code: "VALIDATION_FAILED", Error: "能力请求无效"}
	}
	if err := ctx.Err(); err != nil {
		return sandbox.CapabilityResponse{Code: "CANCELED", Error: "能力请求已取消"}
	}
	if request.Op == "ping" {
		return sandbox.CapabilityResponse{OK: true, Version: s.version, UID: os.Geteuid()}
	}
	if s.runner == nil {
		return sandbox.CapabilityResponse{Code: "UNIMPLEMENTED", Error: "该能力执行器尚未接入"}
	}
	result, err := s.runner.Run(ctx, request)
	if err != nil {
		return sandbox.CapabilityResponse{Code: "INTERNAL", Error: "能力执行失败"}
	}
	return result
}
