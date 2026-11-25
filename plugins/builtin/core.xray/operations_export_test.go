// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/xraycore/state"
	"github.com/qwq-panel/qwq/internal/xraycore/xrayconfig"
	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/apply"
	pb "github.com/qwq-panel/qwq/sdk/gen/qwq/platform/v1"
	"google.golang.org/grpc"
)

// ======================== core.export_client 与 ObfsManager 事务闭环测试 ========================

type exportTestObfsManager struct {
	mu          sync.Mutex
	plans       []xrayconfig.ObfsPlan
	startCalls  int
	stopCalls   int
	failNext    error
	healthy     bool
	degradedErr string
}

func (m *exportTestObfsManager) StartAll(_ context.Context, plans []xrayconfig.ObfsPlan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalls++
	if m.failNext != nil {
		err := m.failNext
		m.failNext = nil
		return err
	}
	m.plans = append([]xrayconfig.ObfsPlan(nil), plans...)
	m.healthy = true
	m.degradedErr = ""
	return nil
}

func (m *exportTestObfsManager) StopAll(_ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopCalls++
	m.plans = nil
}

func (m *exportTestObfsManager) Status() (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.healthy && m.degradedErr != "" {
		return false, m.degradedErr
	}
	return true, ""
}

func (m *exportTestObfsManager) OwnedPIDs() []int {
	return nil
}

type exportFakeHost struct {
	*v2TestHost
}

func (h *exportFakeHost) RevealSecret(_ context.Context, reference, purpose string) ([]byte, error) {
	if purpose != "core.xray.apply" && purpose != "core.export_client" {
		return nil, errors.New("unexpected purpose")
	}
	val, ok := h.secrets[reference]
	if !ok {
		return nil, errors.New("secret not found")
	}
	cp := append([]byte(nil), val...)
	h.revealed = append(h.revealed, cp)
	return cp, nil
}

func quoteSecretJSON(s string) []byte {
	raw, _ := json.Marshal(s)
	return raw
}

func TestCoreExportClientV2RunningSnapshotAndObfsApply(t *testing.T) {
	now := time.Date(2026, 11, 21, 14, 0, 0, 0, time.UTC)
	dataDir, err := os.MkdirTemp("", "core-xray-export-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dataDir) })
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// 准备 VLESS REALITY X25519 私钥、Hysteria2 绑定材料与 SS2022 密钥
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privB64 := base64.RawURLEncoding.EncodeToString(privKey.Bytes())
	wantPubKey := base64.RawURLEncoding.EncodeToString(privKey.PublicKey().Bytes())

	ssServerKey := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	ssUserKey := base64.StdEncoding.EncodeToString([]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})

	vlessPort := reserveFreeTCPPort(t)
	hyPort := reserveFreeUDPPort(t)
	ssPort := reserveFreeTCPPort(t)

	binding := certificates.HostBinding{
		ID:             "bind-exp-01",
		CertificateID:  "cert-exp-01",
		Generation:     1,
		PolicyRevision: "rev-exp-1",
		Consumer: certificates.Consumer{
			PluginID:  "core.xray",
			ProfileID: "hy2-main",
			NodeID:    "local",
			SNI:       "hy2.export.test",
			Purpose:   "proxy.hysteria2",
		},
	}
	_, leafFP := stageAndActivateConsumerCert(t, dataDir, now, binding)

	refPriv := "sec_00000000000000000000000031"
	refUUID := "sec_00000000000000000000000032"
	refAuth := "sec_00000000000000000000000033"
	refSrv := "sec_00000000000000000000000034"
	refPSK := "sec_00000000000000000000000035"

	v2Cfg, err := json.Marshal(map[string]any{
		"schema_version": "2",
		"enabled":        true,
		"profiles": []any{
			map[string]any{
				"id":       "vless-main",
				"enabled":  true,
				"listen":   "127.0.0.1",
				"port":     vlessPort,
				"protocol": "vless",
				"users": []any{
					map[string]any{"id": "alice", "uuid": map[string]string{"$secret": refUUID}, "traffic_mark": 0x5101},
				},
				"vless": map[string]any{
					"transport": "raw",
					"flow":      "xtls-rprx-vision",
					"security": map[string]any{
						"mode":         "reality",
						"target":       "www.example.com:443",
						"server_names": []string{"www.example.com"},
						"private_key":  map[string]string{"$secret": refPriv},
						"short_ids":    []string{"aabbccdd"},
					},
				},
			},
			map[string]any{
				"id":       "hy2-main",
				"enabled":  true,
				"listen":   "127.0.0.1",
				"port":     hyPort,
				"protocol": "hysteria2",
				"users": []any{
					map[string]any{"id": "bob", "auth": map[string]string{"$secret": refAuth}},
				},
				"hysteria2": map[string]any{
					"tls": map[string]any{"binding_ref": binding.ID, "server_name": binding.Consumer.SNI},
				},
			},
			map[string]any{
				"id":       "ss-main",
				"enabled":  true,
				"listen":   "127.0.0.1",
				"port":     ssPort,
				"protocol": "shadowsocks2022",
				"users": []any{
					map[string]any{"id": "carol", "psk": map[string]string{"$secret": refPSK}},
				},
				"shadowsocks2022": map[string]any{
					"method":     "2022-blake3-aes-128-gcm",
					"server_key": map[string]string{"$secret": refSrv},
					"obfs":       map[string]any{"mode": "tls", "host": "cdn.example.com"},
				},
			},
		},
		"outbound": map[string]any{"type": "direct"},
	})
	if err != nil {
		t.Fatal(err)
	}

	host := &exportFakeHost{
		v2TestHost: &v2TestHost{
			fakeApplyHost: &fakeApplyHost{config: v2Cfg, revision: "1"},
			secrets: map[string][]byte{
				refPriv: quoteSecretJSON(privB64),
				refUUID: quoteSecretJSON("11111111-2222-3333-4444-555555555555"),
				refAuth: quoteSecretJSON("hy2-password-super-secret-01"),
				refSrv:  quoteSecretJSON(ssServerKey),
				refPSK:  quoteSecretJSON(ssUserKey),
			},
		},
	}

	obfsMgr := &exportTestObfsManager{healthy: true}
	fakeProc := &fakeApplyProcess{}
	store := state.NewStore(dataDir)
	eng, err := apply.New(apply.Options{
		Store:                  store,
		Process:                fakeProc,
		Binary:                 &v2TestBinary{},
		Obfs:                   obfsMgr,
		Socket:                 filepath.Join(dataDir, "runtime", "api.sock"),
		DataDir:                dataDir,
		PermitTestCertificates: true,
		Now:                    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	plugin := &Plugin{
		driverFactory: func(_ *instance) (*driverRuntime, error) {
			return &driverRuntime{
				store:       store,
				process:     fakeProc,
				obfs:        obfsMgr,
				controller:  eng,
				coreVersion: state.CoreVersion,
				trusted:     true,
			}, nil
		},
	}
	srv, _ := newPluginServer(t, plugin, v2Cfg, &exportFakeConn{host: host}, dataDir)
	ctx := t.Context()

	// 1. 未运行前导出必须被拒绝
	preResp, err := srv.Invoke(ctx, &pb.InvokeRequest{
		Context:     testContext(),
		Operation:   "core.export_client",
		ApiVersion:  "v2",
		PayloadJson: []byte(`{"host":"edge.example.com"}`),
		Attempt:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if preResp.GetError() == nil || preResp.GetError().GetCode() != "CORE_NOT_RUNNING" {
		t.Fatalf("expected CORE_NOT_RUNNING before apply, got %+v", preResp.GetError())
	}

	// 2. Apply v2（应同时拉起 ObfsManager）
	term := runSDKApply(t, srv, "1")
	if term.GetError() != nil {
		t.Fatalf("v2 apply failed: %s", term.GetError().GetCode())
	}
	if obfsMgr.startCalls != 1 || len(obfsMgr.plans) != 1 || obfsMgr.plans[0].External.Port != ssPort {
		t.Fatalf("expected ObfsManager to start 1 plan for ss port %d, got calls=%d plans=%+v", ssPort, obfsMgr.startCalls, obfsMgr.plans)
	}

	// 3. 运行中导出三协议标准客户端配置
	expResp, err := srv.Invoke(ctx, &pb.InvokeRequest{
		Context:     testContext(),
		Operation:   "core.export_client",
		ApiVersion:  "v2",
		PayloadJson: []byte(`{"host":"edge.example.com","label_prefix":"jp"}`),
		Attempt:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if expResp.GetError() != nil {
		t.Fatalf("export failed: %+v", expResp.GetError())
	}
	assertResponseSchema(t, "core.export_client", expResp.GetPayloadJson())

	var out exportClientResponse
	if err := json.Unmarshal(expResp.GetPayloadJson(), &out); err != nil {
		t.Fatal(err)
	}
	if out.RunningRevision != "1" || out.APIVersion != "v2" || len(out.Items) != 3 {
		t.Fatalf("unexpected export output: rev=%s ver=%s items=%d", out.RunningRevision, out.APIVersion, len(out.Items))
	}

	var sawVLESS, sawHy2, sawSS bool
	for _, item := range out.Items {
		switch item.ProfileID {
		case "vless-main":
			sawVLESS = true
			if !strings.Contains(item.ShareURI, "pbk="+url.QueryEscape(wantPubKey)) {
				t.Fatalf("vless URI missing derived pbk %s: %s", wantPubKey, item.ShareURI)
			}
		case "hy2-main":
			sawHy2 = true
			if !strings.Contains(item.ShareURI, "pinSHA256="+url.QueryEscape(leafFP)) {
				t.Fatalf("hy2 test cert URI missing pinSHA256 %s: %s", leafFP, item.ShareURI)
			}
		case "ss-main":
			sawSS = true
			if strings.Contains(item.ShareURI, ":30000") || !strings.Contains(item.ShareURI, "obfs%3Dtls") {
				t.Fatalf("ss2022 URI leaked internal port or missed obfs: %s", item.ShareURI)
			}
		}
	}
	if !sawVLESS || !sawHy2 || !sawSS {
		t.Fatalf("missing exported protocol items: vless=%v hy2=%v ss=%v", sawVLESS, sawHy2, sawSS)
	}

	// 4. 修改 desired 草稿但未 Apply 时必须拒绝导出
	if _, err := srv.ApplyConfig(ctx, &pb.ApplyConfigRequest{
		Context:          testContext(),
		ConfigJson:       v2Cfg,
		ProposedRevision: "2",
	}); err != nil {
		t.Fatal(err)
	}
	draftResp, err := srv.Invoke(ctx, &pb.InvokeRequest{
		Context:     testContext(),
		Operation:   "core.export_client",
		ApiVersion:  "v2",
		PayloadJson: []byte(`{"host":"edge.example.com"}`),
		Attempt:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if draftResp.GetError() == nil || draftResp.GetError().GetCode() != "PENDING_APPLY_EXPORT_DENIED" {
		t.Fatalf("expected PENDING_APPLY_EXPORT_DENIED for unapplied draft, got %+v", draftResp.GetError())
	}

	// 5. URI 注入型 host 必须被 ResolveExportHostStrict 严格拦截
	for _, badHost := range []string{
		"evil.com?allowInsecure=1#",
		"evil.com#frag",
		"user@evil.com",
		"evil.com/path",
		"0.0.0.0",
		"not a host",
	} {
		if _, err := ResolveExportHostStrict(badHost, "127.0.0.1"); err == nil {
			t.Fatalf("expected ResolveExportHostStrict to reject %q", badHost)
		}
	}
	if got, err := ResolveExportHostStrict("Edge.Example.COM", "0.0.0.0"); err != nil || got != "edge.example.com" {
		t.Fatalf("expected canonical host, got %q err=%v", got, err)
	}
	if got, err := ResolveExportHostStrict("[2001:db8::1]", "0.0.0.0"); err != nil || got != "2001:db8::1" {
		t.Fatalf("expected valid IPv6 host, got %q err=%v", got, err)
	}
}

type exportFakeConn struct{ host *exportFakeHost }

func (c *exportFakeConn) Invoke(ctx context.Context, method string, input, output any, opts ...grpc.CallOption) error {
	if method == pb.HostSecretsService_RevealSecret_FullMethodName {
		req := input.(*pb.RevealSecretRequest)
		val, err := c.host.RevealSecret(ctx, req.GetSecretRef(), req.GetPurpose())
		output.(*pb.RevealSecretResponse).Value = val
		return err
	}
	return (&v2FakeConn{host: c.host.v2TestHost}).Invoke(ctx, method, input, output, opts...)
}

func (*exportFakeConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("no stream")
}

func reserveFreeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	if port < 1024 {
		t.Skip("ephemeral port below 1024")
	}
	return port
}
