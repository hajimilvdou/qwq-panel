// SPDX-License-Identifier: AGPL-3.0-only

package xrayconfig

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/prerequisites/testsupport"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
	corev2 "github.com/qwq-panel/qwq/sdk/coreapi/v2"
)

func pickFreeLocalPort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		_ = pc.Close()
		return port
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// TestLiveXrayV26AllProtocolsAndForwarding 使用真实 Xray v26.11.9 二进制端到端验证：
// 1. 全量 8 大 Xray 原生协议（12 种组合：VLESS RAW/XHTTP/gRPC/WS/ENC、VMess、Trojan、SS AEAD、SS2022、Hysteria2+obfs、SOCKS5、HTTP）+ WARP 出站配置预检（xray run -test）；
// 2. 真实启动 Xray 进程并穿透 SOCKS5 与 HTTP 鉴权代理完成回环 HTTP 转发验收；
// 3. 真实外网 Reality SNI TLS 1.3 握手延迟探测。
// 仅在显式设置 QWQ_LIVE_XRAY_BIN 时运行，不影响离线 CI。
func TestLiveXrayV26AllProtocolsAndForwarding(t *testing.T) {
	xrayBin := strings.TrimSpace(os.Getenv("QWQ_LIVE_XRAY_BIN"))
	if xrayBin == "" {
		t.Skip("set QWQ_LIVE_XRAY_BIN to run live Xray v26.11.9 end-to-end verification")
	}

	tmpDir := t.TempDir()
	now := time.Now().UTC()
	cert, err := testsupport.SignedCertificate(now, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cert.Clear)

	makeTLSMat := func() TLSMaterials {
		m, err := tlsmgr.NewMaterial(cert.Chain, cert.Key)
		if err != nil {
			t.Fatal(err)
		}
		return TLSMaterials{
			BindingRef:     "certbind_live_1",
			Generation:     1,
			PolicyRevision: "pol-v1",
			SANs:           []string{"proxy.example.com"},
			Material:       m,
			Purpose:        tlsmgr.ServerTLS,
			Trust:          tlsmgr.PublicTrust,
			Roots:          cert.Roots,
		}
	}

	// 生成真实 X25519 私钥（用于 REALITY 与 WARP）
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	realityPriv := []byte(base64.RawURLEncoding.EncodeToString(xPriv.Bytes()))
	warpPriv := []byte(base64.StdEncoding.EncodeToString(xPriv.Bytes()))
	warpPeerPub := base64.StdEncoding.EncodeToString(xPriv.PublicKey().Bytes())

	// 调用真实 xray vlessenc 生成合法的 VLESS Encryption decryption 字符串
	vlessDecryption := ""
	if out, err := exec.Command(xrayBin, "vlessenc").CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, `"decryption":`) {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					vlessDecryption = strings.Trim(strings.TrimSpace(parts[1]), `",`)
					break
				}
			}
		}
	}
	t.Logf("xray vlessenc decryption generated=%v", vlessDecryption != "")

	pVlessRaw := pickFreeLocalPort(t, "tcp")
	pVlessXhttp := pickFreeLocalPort(t, "tcp")
	pVlessGrpc := pickFreeLocalPort(t, "tcp")
	pVlessWs := pickFreeLocalPort(t, "tcp")
	pVlessEnc := pickFreeLocalPort(t, "tcp")
	pVmessWs := pickFreeLocalPort(t, "tcp")
	pTrojanGrpc := pickFreeLocalPort(t, "tcp")
	pSS := pickFreeLocalPort(t, "tcp")
	pSS2022 := pickFreeLocalPort(t, "tcp")
	pHy2 := pickFreeLocalPort(t, "udp")
	pSocks5 := pickFreeLocalPort(t, "tcp")
	pHTTP := pickFreeLocalPort(t, "tcp")

	enabled := true
	sniffOn := true
	ref := func(i int) *corev2.SecretRef { return &corev2.SecretRef{ID: fmt.Sprintf("sec_%026d", i)} }
	tlsBind := &corev2.TLSBinding{BindingRef: "certbind_live_1", ServerName: "proxy.example.com"}
	reality := &corev2.Reality{
		Mode:        "reality",
		Target:      "www.microsoft.com:443",
		ServerNames: []string{"www.microsoft.com"},
		PrivateKey:  *ref(90),
		ShortIDs:    []string{"", "aabbccdd"},
	}

	profiles := []corev2.Profile{
		{
			ID: "p-vless-raw", Enabled: &enabled, Listen: "127.0.0.1", Port: pVlessRaw, Protocol: corev2.ProtocolVLESS,
			Users: []corev2.User{{ID: "u-vless-raw", UUID: ref(1)}},
			VLESS: &corev2.VLESS{Transport: "raw", Flow: "xtls-rprx-vision", Security: reality, Sniffing: &sniffOn},
		},
		{
			ID: "p-vless-xhttp", Enabled: &enabled, Listen: "127.0.0.1", Port: pVlessXhttp, Protocol: corev2.ProtocolVLESS,
			Users: []corev2.User{{ID: "u-vless-xh", UUID: ref(2)}},
			VLESS: &corev2.VLESS{Transport: "xhttp", SecurityMode: "reality", Security: reality, Path: "/xhttp", XHTTPMode: "auto", Sniffing: &sniffOn},
		},
		{
			ID: "p-vless-grpc", Enabled: &enabled, Listen: "127.0.0.1", Port: pVlessGrpc, Protocol: corev2.ProtocolVLESS,
			Users: []corev2.User{{ID: "u-vless-grpc", UUID: ref(3)}},
			VLESS: &corev2.VLESS{Transport: "grpc", SecurityMode: "tls", TLS: tlsBind, ServiceName: "vless-grpc"},
		},
		{
			ID: "p-vless-ws", Enabled: &enabled, Listen: "127.0.0.1", Port: pVlessWs, Protocol: corev2.ProtocolVLESS,
			Users: []corev2.User{{ID: "u-vless-ws", UUID: ref(4)}},
			VLESS: &corev2.VLESS{Transport: "ws", SecurityMode: "tls", TLS: tlsBind, Path: "/vws", Host: "proxy.example.com"},
		},
		{
			ID: "p-vmess-ws", Enabled: &enabled, Listen: "127.0.0.1", Port: pVmessWs, Protocol: corev2.ProtocolVMess,
			Users: []corev2.User{{ID: "u-vmess", UUID: ref(5)}},
			VMess: &corev2.VMess{Transport: "ws", SecurityMode: "tls", TLS: tlsBind, Path: "/vmess", Host: "proxy.example.com"},
		},
		{
			ID: "p-trojan-grpc", Enabled: &enabled, Listen: "127.0.0.1", Port: pTrojanGrpc, Protocol: corev2.ProtocolTrojan,
			Users:  []corev2.User{{ID: "u-trojan", Auth: ref(6)}},
			Trojan: &corev2.Trojan{Transport: "grpc", SecurityMode: "reality", Reality: reality, ServiceName: "tr-grpc"},
		},
		{
			ID: "p-ss-aead", Enabled: &enabled, Listen: "127.0.0.1", Port: pSS, Protocol: corev2.ProtocolShadowsocks,
			Users:       []corev2.User{{ID: "u-ss", Auth: ref(7)}},
			Shadowsocks: &corev2.Shadowsocks{Method: corev2.MethodAEADAES256GCM, UDP: true},
		},
		{
			ID: "p-ss2022", Enabled: &enabled, Listen: "127.0.0.1", Port: pSS2022, Protocol: corev2.ProtocolShadowsocks2022,
			Users: []corev2.User{{ID: "u-ss22", PSK: ref(8)}},
			Shadowsocks2022: &corev2.Shadowsocks2022{
				Method:    corev2.MethodAES128,
				ServerKey: *ref(92),
				Obfs:      &corev2.Obfs{Mode: corev2.ObfsNone},
				UDP:       true,
			},
		},
		{
			ID: "p-hy2", Enabled: &enabled, Listen: "127.0.0.1", Port: pHy2, Protocol: corev2.ProtocolHysteria2,
			Users:     []corev2.User{{ID: "u-hy2", Auth: ref(9)}},
			Hysteria2: &corev2.Hysteria2{TLS: tlsBind, ObfsPassword: ref(93)},
		},
		{
			ID: "p-socks5", Enabled: &enabled, Listen: "127.0.0.1", Port: pSocks5, Protocol: corev2.ProtocolSOCKS5,
			Users:  []corev2.User{{ID: "u-socks", Username: "suser", Auth: ref(10)}},
			SOCKS5: &corev2.SOCKS5{UDP: true},
		},
		{
			ID: "p-http", Enabled: &enabled, Listen: "127.0.0.1", Port: pHTTP, Protocol: corev2.ProtocolHTTP,
			Users: []corev2.User{{ID: "u-http", Username: "huser", Auth: ref(11)}},
			HTTP:  &corev2.HTTP{},
		},
	}

	vlessGrpcTLS := makeTLSMat()
	vlessWsTLS := makeTLSMat()
	vmessTLS := makeTLSMat()
	profileMats := map[string]ProfileMaterials{
		"p-vless-raw": {
			VLESS: &Secrets{PrivateKey: append([]byte(nil), realityPriv...), UUIDs: map[string][]byte{"u-vless-raw": []byte("10000000-0000-4000-8000-000000000001")}},
		},
		"p-vless-xhttp": {
			VLESS: &Secrets{PrivateKey: append([]byte(nil), realityPriv...), UUIDs: map[string][]byte{"u-vless-xh": []byte("10000000-0000-4000-8000-000000000002")}},
		},
		"p-vless-grpc": {
			VLESS:    &Secrets{UUIDs: map[string][]byte{"u-vless-grpc": []byte("10000000-0000-4000-8000-000000000003")}},
			VLESSTLS: &vlessGrpcTLS,
		},
		"p-vless-ws": {
			VLESS:    &Secrets{UUIDs: map[string][]byte{"u-vless-ws": []byte("10000000-0000-4000-8000-000000000004")}},
			VLESSTLS: &vlessWsTLS,
		},
		"p-vmess-ws": {
			VMess: &VMessMaterials{UUIDs: map[string][]byte{"u-vmess": []byte("10000000-0000-4000-8000-000000000005")}, TLS: &vmessTLS},
		},
		"p-trojan-grpc": {
			Trojan: &TrojanMaterials{Auth: map[string][]byte{"u-trojan": []byte("tr-live-pass-123")}, PrivateKey: append([]byte(nil), realityPriv...)},
		},
		"p-ss-aead": {
			Shadowsocks: &ShadowsocksMaterials{Auth: map[string][]byte{"u-ss": []byte("ss-live-pass-123")}},
		},
		"p-ss2022": {
			Shadowsocks2022: &SS2022Materials{ServerKey: testPSK(1, 16), PSKs: map[string][]byte{"u-ss22": testPSK(2, 16)}},
		},
		"p-hy2": {
			Hysteria2: &HysteriaMaterials{Auth: map[string][]byte{"u-hy2": []byte("hy2-live-pass-123")}, TLS: makeTLSMat(), ObfsPassword: []byte("hy2-obfs-pass")},
		},
		"p-socks5": {
			SOCKS5: &AccountMaterials{Auth: map[string][]byte{"u-socks": []byte("socks-live-pass")}},
		},
		"p-http": {
			HTTP: &AccountMaterials{Auth: map[string][]byte{"u-http": []byte("http-live-pass")}},
		},
	}

	if vlessDecryption != "" {
		profiles = append(profiles, corev2.Profile{
			ID: "p-vless-enc", Enabled: &enabled, Listen: "127.0.0.1", Port: pVlessEnc, Protocol: corev2.ProtocolVLESS,
			Users: []corev2.User{{ID: "u-vless-enc", UUID: ref(12)}},
			VLESS: &corev2.VLESS{Transport: "raw", SecurityMode: "none", Decryption: ref(94)},
		})
		profileMats["p-vless-enc"] = ProfileMaterials{
			VLESS:           &Secrets{UUIDs: map[string][]byte{"u-vless-enc": []byte("10000000-0000-4000-8000-000000000012")}},
			VLESSDecryption: []byte(vlessDecryption),
		}
	}

	intent := &corev2.Intent{
		SchemaVersion: "2",
		Enabled:       &enabled,
		Outbound:      &corev2.Outbound{Type: "direct"},
		Profiles:      profiles,
		WARP: &corev2.WARPOutbound{
			Enabled:       true,
			PrivateKey:    *ref(95),
			PeerPublicKey: warpPeerPub,
			Endpoint:      "engage.cloudflareclient.com:2408",
			AddressV4:     "172.16.0.2/32",
			MTU:           1280,
			RoutingMode:   corev2.WARPRoutingDomains,
			Domains:       []string{"openai.com", "netflix.com"},
		},
	}

	rendered, err := RenderV2(intent, V2Materials{
		Profiles: profileMats,
		WARP:     &WARPMaterials{PrivateKey: warpPriv},
	}, V2Options{
		Options: Options{APISocket: filepath.Join(tmpDir, "api.sock")},
		Now:     now,
	})
	if err != nil {
		t.Fatalf("RenderV2 failed: %v", err)
	}

	cfgPath := filepath.Join(tmpDir, "xray-live.json")
	if err := os.WriteFile(cfgPath, rendered, 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. 真实 Xray v26.11.9 静态预检（xray run -test）
	testOut, err := exec.Command(xrayBin, "run", "-test", "-c", cfgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("xray run -test failed: %v\noutput:\n%s\nconfig:\n%s", err, string(testOut), string(rendered))
	}
	t.Logf("xray run -test PASSED (%d profiles + WARP):\n%s", len(profiles), strings.TrimSpace(string(testOut)))

	// 2. 启动真实 Xray 进程并穿透 SOCKS5 与 HTTP 鉴权代理完成回环转发
	echoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("qwq-live-proxy-ok:" + r.URL.Path))
	}))
	defer echoSrv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, xrayBin, "run", "-c", cfgPath)
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start xray failed: %v", err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
	}()

	waitTCP := func(port int) {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
			if err == nil {
				_ = c.Close()
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("inbound %s did not start listening; stderr=%s", addr, stderrBuf.String())
	}
	for _, p := range []int{pVlessRaw, pVlessXhttp, pVlessGrpc, pVlessWs, pVmessWs, pTrojanGrpc, pSS, pSS2022, pSocks5, pHTTP} {
		waitTCP(p)
	}
	t.Logf("All 10 TCP Xray inbounds are actively listening!")

	// 2a. 实测 HTTP 代理鉴权转发
	proxyURL, _ := url.Parse(fmt.Sprintf("http://huser:http-live-pass@127.0.0.1:%d", pHTTP))
	httpClient := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := httpClient.Get(echoSrv.URL + "/via-http")
	if err != nil {
		t.Fatalf("HTTP proxy forward failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "qwq-live-proxy-ok:/via-http" {
		t.Fatalf("HTTP proxy unexpected response: status=%d body=%q", resp.StatusCode, string(body))
	}
	t.Logf("LIVE HTTP Proxy forwarding PASSED: %q", string(body))

	// 2b. 实测 SOCKS5 用户名/密码鉴权转发
	echoURL, _ := url.Parse(echoSrv.URL)
	echoHost, echoPortStr, _ := net.SplitHostPort(echoURL.Host)
	var echoPort int
	_, _ = fmt.Sscanf(echoPortStr, "%d", &echoPort)
	sConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pSocks5), 3*time.Second)
	if err != nil {
		t.Fatalf("dial socks5 failed: %v", err)
	}
	defer func() { _ = sConn.Close() }()
	_ = sConn.SetDeadline(time.Now().Add(5 * time.Second))
	// greeting: VER=5, NMETHODS=1, METHOD=0x02 (user/pass)
	_, _ = sConn.Write([]byte{0x05, 0x01, 0x02})
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(sConn, greetResp); err != nil || greetResp[0] != 0x05 || greetResp[1] != 0x02 {
		t.Fatalf("socks5 greeting failed: %v %x", err, greetResp)
	}
	// RFC1929 auth
	user, pass := "suser", "socks-live-pass"
	authPkt := append([]byte{0x01, byte(len(user))}, []byte(user)...)
	authPkt = append(authPkt, byte(len(pass)))
	authPkt = append(authPkt, []byte(pass)...)
	_, _ = sConn.Write(authPkt)
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(sConn, authResp); err != nil || authResp[1] != 0x00 {
		t.Fatalf("socks5 auth failed: %v %x", err, authResp)
	}
	// CONNECT 127.0.0.1:echoPort
	ip4 := net.ParseIP(echoHost).To4()
	reqPkt := []byte{0x05, 0x01, 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], 0, 0}
	binary.BigEndian.PutUint16(reqPkt[8:10], uint16(echoPort))
	_, _ = sConn.Write(reqPkt)
	connResp := make([]byte, 10)
	if _, err := io.ReadFull(sConn, connResp); err != nil || connResp[1] != 0x00 {
		t.Fatalf("socks5 connect failed: %v %x", err, connResp)
	}
	_, _ = fmt.Fprintf(sConn, "GET /via-socks5 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", echoURL.Host)
	httpResp, err := http.ReadResponse(bufio.NewReader(sConn), nil)
	if err != nil {
		t.Fatalf("socks5 http read failed: %v", err)
	}
	sBody, _ := io.ReadAll(httpResp.Body)
	_ = httpResp.Body.Close()
	if httpResp.StatusCode != 200 || string(sBody) != "qwq-live-proxy-ok:/via-socks5" {
		t.Fatalf("SOCKS5 proxy unexpected response: status=%d body=%q", httpResp.StatusCode, string(sBody))
	}
	t.Logf("LIVE SOCKS5 Proxy forwarding PASSED: %q", string(sBody))

	// 3. 实测外网 Reality SNI TLS 1.3 延迟探测
	for _, domain := range []string{"www.microsoft.com", "www.apple.com", "dl.google.com"} {
		start := time.Now()
		d := &net.Dialer{Timeout: 3 * time.Second}
		tc, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(domain, "443"), &tls.Config{
			ServerName: domain,
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{"h2", "http/1.1"},
		})
		if err != nil {
			t.Logf("SNI probe %s: err=%v", domain, err)
			continue
		}
		cs := tc.ConnectionState()
		_ = tc.Close()
		t.Logf("SNI probe %s: OK %dms tls=0x%x alpn=%s", domain, time.Since(start).Milliseconds(), cs.Version, cs.NegotiatedProtocol)
	}
}
