// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestL4SNIMuxSplitsPassthroughAndLocalHTTPSOnSinglePort(t *testing.T) {
	// 1. 模拟内网 core.xray TLS/Reality 上游监听器（不同证书与独立响应）
	proxyCertPEM, proxyKeyPEM := generateSelfSignedCertPEM(t, "reality.example.com")
	proxyPair, err := tls.X509KeyPair(proxyCertPEM, proxyKeyPEM)
	if err != nil {
		t.Fatalf("proxy keypair: %v", err)
	}
	upRaw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upRaw.Close()
	upTLS := tls.NewListener(upRaw, &tls.Config{Certificates: []tls.Certificate{proxyPair}})
	go func() {
		for {
			c, aerr := upTLS.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("XRAY_L4_PASSTHROUGH_OK"))
			}(c)
		}
	}()

	// 2. 启动单端口 L4SNIMuxListener + 本地 HTTPS Server
	webCertPEM, webKeyPEM := generateSelfSignedCertPEM(t, "blog.example.com")
	sniStore := NewSNICertStore(t.TempDir())
	if err := sniStore.UpsertCert("blog.example.com", webCertPEM, webKeyPEM); err != nil {
		t.Fatalf("UpsertCert: %v", err)
	}
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 443 sim: %v", err)
	}
	mux := NewL4SNIMuxListener(rawLn)
	defer mux.Close()
	mux.SetRoutes(map[string]L4PassthroughTarget{
		"reality.example.com": {UpstreamAddr: upRaw.Addr().String()},
	})

	httpsSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("LOCAL_WEB_HTTPS_OK"))
		}),
	}
	defer httpsSrv.Close()
	go func() { _ = httpsSrv.Serve(tls.NewListener(mux, sniStore.TLSConfig())) }()

	// 3. 验证命中透传 SNI -> 零解密直达内网模拟 Xray 进程（证书 CN 为 reality.example.com）
	c1, err := tls.Dial("tcp", rawLn.Addr().String(), &tls.Config{
		ServerName:         "reality.example.com",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial passthrough SNI: %v", err)
	}
	defer c1.Close()
	if gotCN := c1.ConnectionState().PeerCertificates[0].Subject.CommonName; gotCN != "reality.example.com" {
		t.Fatalf("expected passthrough cert CN=reality.example.com, got %q", gotCN)
	}
	gotBytes, _ := io.ReadAll(c1)
	if string(gotBytes) != "XRAY_L4_PASSTHROUGH_OK" {
		t.Fatalf("unexpected passthrough payload: %q", string(gotBytes))
	}

	// 4. 验证未命中透传 SNI -> 同一端口直达本地 HTTPS Server（证书 CN 为 blog.example.com）
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "blog.example.com",
				InsecureSkipVerify: true,
			},
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+rawLn.Addr().String()+"/", nil)
	req.Host = "blog.example.com"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("local https over mux failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "LOCAL_WEB_HTTPS_OK" {
		t.Fatalf("unexpected local https body: %q", string(body))
	}
	if resp.TLS == nil || resp.TLS.PeerCertificates[0].Subject.CommonName != "blog.example.com" {
		t.Fatalf("unexpected local https peer cert: %+v", resp.TLS)
	}
}

func TestValidateSNIPassthroughRejectsNonLoopbackUpstream(t *testing.T) {
	if _, err := validateSNIPassthroughUpstream("169.254.169.254:443"); err == nil {
		t.Fatal("expected metadata IP to be rejected")
	}
	if _, err := validateSNIPassthroughUpstream("8.8.8.8:443"); err == nil {
		t.Fatal("expected external IP to be rejected")
	}
	got, err := validateSNIPassthroughUpstream("127.0.0.1:24443")
	if err != nil || got != "127.0.0.1:24443" {
		t.Fatalf("expected valid loopback upstream, got %q err=%v", got, err)
	}
}

func TestLoadConsumerBindingKeypairReadsCurrentJSONGenerationsAndCanonical64Hex(t *testing.T) {
	dataDir := t.TempDir()
	bindingRef := "certbind_gen2"
	certPEM, keyPEM := generateSelfSignedCertPEM(t, "auto.example.com")

	genDir := filepath.Join(dataDir, "tls", "bindings", bindingRef, "generations", "g2")
	if err := os.MkdirAll(genDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(genDir, "fullchain.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(genDir, "privkey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	ptr := map[string]any{
		"version": 1,
		"active": map[string]any{
			"binding": map[string]any{
				"id":              bindingRef,
				"generation":      2,
				"policy_revision": "pol_rev_2",
				"consumer":        map[string]any{"sni": "auto.example.com"},
			},
			"fullchain_sha256":   sha256Hex(certPEM),
			"private_key_sha256": sha256Hex(keyPEM),
		},
	}
	ptrBytes, _ := json.Marshal(ptr)
	if err := os.WriteFile(filepath.Join(dataDir, "tls", "bindings", bindingRef, "current.json"), ptrBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	fullPath, keyPath := MaterializedCertPaths(dataDir, bindingRef)
	if !filepath.IsAbs(fullPath) || filepath.Base(fullPath) != "fullchain.pem" || filepath.Base(keyPath) != "privkey.pem" {
		t.Fatalf("expected MaterializedCertPaths to resolve generations/g2/{fullchain,privkey}.pem, got %q %q", fullPath, keyPath)
	}

	sni := NewSNICertStore(dataDir)
	sni.SetHTTPSListenerActive(true)
	obs, err := sni.LoadBinding(bindingRef, 2, "pol_rev_2", sha256Hex(certPEM), sha256Hex(keyPEM), "auto.example.com", "127.0.0.1:443")
	if err != nil {
		t.Fatalf("LoadBinding with current.json/generations/g2 failed: %v", err)
	}
	if len(obs.LeafFingerprint) != 64 {
		t.Fatalf("expected 64-char lowercase hex LeafFingerprint without prefix, got %q (len=%d)", obs.LeafFingerprint, len(obs.LeafFingerprint))
	}
	if obs.FullchainSHA256 != sha256Hex(certPEM) {
		t.Fatalf("unexpected fullchain_sha256: %s", obs.FullchainSHA256)
	}

	// 验证 ReloadFromBindings 不会清空已通过 ingress.tls.reload 加载的 s.bindings 证书
	if _, err := sni.ReloadFromBindings(map[string]string{}); err != nil {
		t.Fatalf("ReloadFromBindings empty: %v", err)
	}
	if !sni.HasCertForDomain("auto.example.com") {
		t.Fatal("expected ReloadFromBindings to preserve active LoadBinding certificate")
	}

	// 验证 cert_id == "" 时 syncSiteBindingsToSNI 自动扫描匹配到 auto.example.com
	syncSiteBindingsToSNI(sni, []SiteRecord{{
		ID:          "ing_auto",
		Domain:      "auto.example.com",
		Enabled:     true,
		TLSMode:     "managed",
		CertID:      "",
		UpstreamURL: "http://127.0.0.1:3000",
	}})
	if !sni.HasCertForDomain("auto.example.com") {
		t.Fatal("expected syncSiteBindingsToSNI to auto-match binding when cert_id is empty")
	}
}
