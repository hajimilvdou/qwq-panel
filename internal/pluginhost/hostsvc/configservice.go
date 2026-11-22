// SPDX-License-Identifier: AGPL-3.0-only

package hostsvc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
)

// configService implements HostConfigService: a read-only view of the config
// snapshot the instance currently runs with.
type configService struct {
	platformv1.UnimplementedHostConfigServiceServer
	s *Server
}

// GetConfig returns the applied revision and its JSON snapshot. A non-empty
// requested revision that is not the applied one is NOT_FOUND: this host keeps
// only the current snapshot, and a plugin must not read stale configuration.
func (x *configService) GetConfig(ctx context.Context, req *platformv1.GetConfigRequest) (*platformv1.GetConfigResponse, error) {
	if x.s.cfg.Config == nil {
		return nil, unavailable("configuration")
	}
	revision, snapshot, err := x.s.cfg.Config.Current(ctx)
	if err != nil {
		return nil, x.s.sinkError("read config", err)
	}
	if len(snapshot) == 0 || !jsonValid(snapshot) {
		x.s.log.Error("config source returned an invalid snapshot", "revision", revision)
		return nil, status.Error(codes.Internal, "the host returned an invalid config snapshot")
	}
	if requested := req.GetRevision(); requested != "" && requested != revision {
		return nil, status.Errorf(codes.NotFound, "config revision %q is not the applied revision", clipString(requested, 64))
	}
	return &platformv1.GetConfigResponse{
		ConfigJson: append([]byte(nil), snapshot...),
		Revision:   revision,
	}, nil
}
