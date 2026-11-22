// SPDX-License-Identifier: AGPL-3.0-only

//go:build e2e && linux

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/qwq-panel/qwq/internal/pluginhost/install"
	"golang.org/x/net/proxy"
)

// ======================== 锁定真实客户端与已知目标 ========================
const (
	xrayPayloadURL    = "https://raw.githubusercontent.com/XTLS/Xray-core/676eaf66f8f05d4d558ee7a74b4736623d3feeb9/proxy/vless/inbound/inbound.go"
	xrayPayloadSHA256 = "bca095d17af679ba7e6c0793fe624ac71dff0a36a316a436170bc643f13a392b"
	xrayPayloadSize   = 22041
)

type xrayTestClient struct {
	http      *http.Client
	command   *exec.Cmd
	done      chan struct{}
	stop      context.CancelFunc
	address   string
	waitError error
}

func newXrayTestClient(t *testing.T, fixture *xrayFixture, uuid, publicKey string) *xrayTestClient {
	t.Helper()
	binary := filepath.Join(install.VersionDir(pluginsRoot, xrayID, "0.1.1"), "bin", "xray")
	file, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || hex.EncodeToString(hash.Sum(nil)) != xraySHA256 {
		t.Fatal("真实客户端不是锁定 Xray 二进制")
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	port := reservation.Addr().(*net.TCPAddr).Port
	configuration := map[string]any{"log": map[string]string{"loglevel": "none"},
		"inbounds": []map[string]any{{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}},
		"outbounds": []map[string]any{{"protocol": "vless", "settings": map[string]any{"vnext": []map[string]any{{"address": "127.0.0.1", "port": fixture.port, "users": []map[string]string{{"id": uuid, "encryption": "none", "flow": "xtls-rprx-vision"}}}}},
			"streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]string{"fingerprint": "chrome", "serverName": xrayServerName, "password": publicKey, "shortId": fixture.shortID}}}}}
	data, err := json.Marshal(configuration)
	if err != nil {
		_ = reservation.Close()
		t.Fatal(err)
	}
	defer clear(data)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = reservation.Close()
		t.Fatal(err)
	}
	path := filepath.Join(directory, "client.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		_ = reservation.Close()
		t.Fatal(err)
	}
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Minute)
	command := exec.CommandContext(ctx, binary, "run", "-c", path)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "TZ=UTC"}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.WaitDelay = 3 * time.Second
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal("锁定 Xray 客户端启动失败")
	}
	client := &xrayTestClient{command: command, done: make(chan struct{}), stop: cancel, address: address}
	go func() { client.waitError = command.Wait(); close(client.done) }()
	t.Cleanup(func() {
		if client.http != nil {
			client.http.CloseIdleConnections()
		}
		client.stop()
		select {
		case <-client.done:
		case <-time.After(5 * time.Second):
			_ = client.command.Process.Kill()
			select {
			case <-client.done:
			case <-time.After(3 * time.Second):
				t.Error("真实客户端未回收")
			}
		}
		requirePIDsGone(t, client.command.Process.Pid)
		listener, err := net.Listen("tcp", client.address)
		if err != nil {
			t.Error("真实客户端停止后仍有原 SOCKS 监听")
		} else if err := listener.Close(); err != nil {
			t.Errorf("客户端监听清理核验失败: %v", err)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		select {
		case <-client.done:
			t.Fatalf("真实客户端在就绪前退出: %v", client.waitError)
		default:
		}
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("真实客户端 SOCKS 端口未就绪")
	}
	dialer, err := proxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		t.Fatal("SOCKS 客户端不支持有界上下文")
	}
	transport := &http.Transport{DialContext: contextDialer.DialContext, DisableKeepAlives: true, DisableCompression: true, ResponseHeaderTimeout: 5 * time.Second}
	client.http = &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client
}

func newXrayHTTPPayload(t *testing.T) (string, []byte) {
	t.Helper()
	// 默认 finalrule 拒绝 VLESS 访问私网；验证锁定的公开 HTTPS 内容，
	// 保留该安全边界。安装前先核验来源/大小/摘要，单列网络前置故障。
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableKeepAlives:     true,
		DisableCompression:    true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, xrayPayloadURL, nil)
	if err != nil {
		t.Fatal("固定公开响应预检请求无效")
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("固定公开响应预检不可用")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, xrayPayloadSize+1))
	digest := sha256.Sum256(body)
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" || len(body) != xrayPayloadSize || hex.EncodeToString(digest[:]) != xrayPayloadSHA256 {
		t.Fatalf("固定公开响应预检失败（HTTP %d，%d bytes）", response.StatusCode, len(body))
	}
	return xrayPayloadURL, body
}

func (client *xrayTestClient) transfers(url string, expected []byte) bool {
	// 应用正文与核心计量使用相同的不压缩字节口径；正文摘要仍完整校验。
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.http.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(len(expected)+1)))
	return err == nil && response.StatusCode == http.StatusOK && response.Header.Get("Content-Encoding") == "" && bytes.Equal(data, expected)
}

type xrayCounter struct {
	Kind            string  `json:"kind"`
	ID              string  `json:"id"`
	Present         bool    `json:"present"`
	UplinkPresent   bool    `json:"uplink_present"`
	DownlinkPresent bool    `json:"downlink_present"`
	Uplink          *string `json:"uplink_bytes"`
	Downlink        *string `json:"downlink_bytes"`
	Epoch           string  `json:"reset_epoch"`
	Source          string  `json:"source"`
}

func xrayCounters(p *panel) map[string]xrayCounter {
	p.t.Helper()
	data, err := json.Marshal(p.invoke("core.observe", map[string]any{}))
	if err != nil {
		p.t.Fatal(err)
	}
	var result struct {
		Epoch  string        `json:"reset_epoch"`
		Source string        `json:"source"`
		Series []xrayCounter `json:"series"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		p.t.Fatal(err)
	}
	if result.Source != "xray" || result.Epoch == "" {
		p.t.Fatal("真实统计来源或代次缺失")
	}
	counters := map[string]xrayCounter{}
	for _, counter := range result.Series {
		if counter.Source != "xray" || counter.Epoch != result.Epoch || counter.Present != (counter.UplinkPresent && counter.DownlinkPresent) || counter.UplinkPresent != (counter.Uplink != nil) || counter.DownlinkPresent != (counter.Downlink != nil) {
			p.t.Fatal("真实计数器的代次或缺失语义错误")
		}
		counters[counter.Kind+"/"+counter.ID] = counter
	}
	return counters
}

func counterBytes(t *testing.T, value *string) uint64 {
	t.Helper()
	if value == nil {
		return 0
	}
	number, err := strconv.ParseUint(*value, 10, 63)
	if err != nil || strconv.FormatUint(number, 10) != *value {
		t.Fatal("真实字节计数不是规范 int64 十进制字符串")
	}
	return number
}
