// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/sandbox"
)

const (
	compatRequestTimeout   = 30 * time.Second
	defaultCredentialsRoot = "/run/credentials"
)

type compatServer struct {
	systemctl      sandbox.Systemctl
	agentUser      string
	version        string
	logger         *slog.Logger
	credentialsDir string
	lookupAgentUID func(string) (int, error)
}

func newCompatServer(sc sandbox.Systemctl, agentUser, version string, logger *slog.Logger) *compatServer {
	if agentUser == "" {
		agentUser = sandbox.DefaultAgentUser
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &compatServer{
		systemctl:      sc,
		agentUser:      agentUser,
		version:        version,
		logger:         logger,
		credentialsDir: defaultCredentialsRoot,
	}
}

func (s *compatServer) resolveAgentUID() (int, error) {
	if s.lookupAgentUID != nil {
		return s.lookupAgentUID(s.agentUser)
	}
	acc, err := user.Lookup(s.agentUser)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(acc.Uid)
}

func (s *compatServer) serve(ctx context.Context, listener net.Listener, oneShot bool) error {
	return sandbox.ServeHelperConnections(ctx, listener, oneShot, 4, s.serveConn)
}

func (s *compatServer) serveConn(ctx context.Context, conn net.Conn) {
	uid, err := sandbox.HelperPeerUID(conn)
	if err != nil {
		return
	}
	if uid != 0 {
		agentUID, lookupErr := s.resolveAgentUID()
		if lookupErr != nil || uid != agentUID {
			s.logger.Warn("compat unitctl rejected unauthorized peer", "peer_uid", uid)
			return
		}
	}
	reqCtx, cancel := context.WithTimeout(ctx, compatRequestTimeout)
	defer cancel()
	if deadline, ok := reqCtx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return
		}
	}
	var req sandbox.CompatUnitctlRequest
	if err := sandbox.ReadHelperJSON(conn, &req); err != nil {
		s.logger.Warn("compat unitctl rejected invalid json")
		_ = sandbox.WriteHelperJSON(conn, sandbox.CompatUnitctlResponse{
			Code:  "VALIDATION_FAILED",
			Error: "invalid compat unitctl request JSON",
		})
		return
	}
	execCtx, finish := sandbox.WatchHelperDisconnect(reqCtx, conn)
	resp := s.handle(execCtx, req)
	finish()
	if err := sandbox.WriteHelperJSON(conn, resp); err != nil {
		s.logger.Warn("compat unitctl could not send response", "error", err)
	}
}

func (s *compatServer) handle(ctx context.Context, req sandbox.CompatUnitctlRequest) (resp sandbox.CompatUnitctlResponse) {
	defer func() {
		if recover() != nil {
			resp = sandbox.CompatUnitctlResponse{Code: "INTERNAL", Error: "internal compat unitctl error"}
		}
		if sandbox.CompatUnitctlActionAllowed(req.Action) {
			s.logger.Info("compat unitctl request", "action", req.Action, "unit", req.Unit, "ok", resp.OK, "code", resp.Code)
		}
	}()

	if !sandbox.CompatUnitctlActionAllowed(req.Action) {
		return sandbox.CompatUnitctlResponse{Code: "VALIDATION_FAILED", Error: "action is not allowed"}
	}
	if req.Action == sandbox.CompatUnitctlOpPing {
		return sandbox.CompatUnitctlResponse{OK: true, Version: s.version, UID: os.Geteuid()}
	}
	if err := sandbox.CheckCompatPluginUnit(req.Unit); err != nil {
		return sandbox.CompatUnitctlResponse{Code: "FORBIDDEN", Error: err.Error()}
	}
	if err := ctx.Err(); err != nil {
		return sandbox.CompatUnitctlResponse{Code: "CANCELED", Error: err.Error()}
	}
	if s.systemctl == nil {
		return sandbox.CompatUnitctlResponse{Code: "UNAVAILABLE", Error: "systemctl backend not configured"}
	}
	var err error
	switch req.Action {
	case sandbox.CompatUnitctlOpStart:
		// systemd 247 (Debian 11) fails ExecStartPre=+ with 226/NAMESPACE when
		// /run/credentials/<unit> does not yet exist before setup_namespace().
		// req.Unit is already validated against qwq-plugin@<id>.(service|socket).
		if strings.HasSuffix(req.Unit, ".service") && s.credentialsDir != "" {
			if st, serr := os.Stat(s.credentialsDir); serr == nil && st.IsDir() {
				if merr := os.Mkdir(filepath.Join(s.credentialsDir, req.Unit), 0o755); merr != nil && !os.IsExist(merr) {
					s.logger.Warn("compat unitctl could not prepare credentials dir", "dir", s.credentialsDir, "unit", req.Unit, "error", merr)
				}
			}
		}
		err = s.systemctl.Start(ctx, req.Unit)
	case sandbox.CompatUnitctlOpStop:
		err = s.systemctl.Stop(ctx, req.Unit)
	case sandbox.CompatUnitctlOpKill:
		err = s.systemctl.Kill(ctx, req.Unit)
	}
	if err != nil {
		return sandbox.CompatUnitctlResponse{Code: "INTERNAL", Error: err.Error()}
	}
	return sandbox.CompatUnitctlResponse{OK: true, UID: os.Geteuid()}
}
