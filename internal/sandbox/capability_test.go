// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCapabilityClientUsesBoundedHelperWire(t *testing.T) {
	client := NewCapabilityClient("/run/qwq/capability.sock")
	var received CapabilityRequest
	done := make(chan error, 1)
	client.dial = func(context.Context, string, string) (net.Conn, error) {
		local, remote := net.Pipe()
		go func() {
			defer remote.Close()
			if err := ReadHelperJSON(remote, &received); err != nil {
				done <- err
				return
			}
			done <- WriteHelperJSON(remote, CapabilityResponse{OK: true, ResultJSON: []byte(`{"revision":"2"}`)})
		}()
		return local, nil
	}
	response, err := client.Call(t.Context(), CapabilityRequest{Op: "firewall.get", ID: "security.basic", ParamsJSON: []byte(`{}`)})
	if err != nil || !response.OK || received.Op != "firewall.get" || string(response.ResultJSON) != `{"revision":"2"}` {
		t.Fatalf("能力 wire 错误：%v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCapabilityClientRejectsUnsafeEnvelope(t *testing.T) {
	client := NewCapabilityClient("/run/qwq/capability.sock")
	var calls atomic.Int32
	client.dial = func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("must not dial")
	}
	for _, request := range []CapabilityRequest{
		{Op: "exec", ID: "security.basic", ParamsJSON: []byte(`{}`)},
		{Op: "firewall.get", ID: "../outside", ParamsJSON: []byte(`{}`)},
		{Op: "firewall.get", ID: "security.basic", ParamsJSON: []byte(`[]`)},
		{Op: "firewall.get", ID: "security.basic", ParamsJSON: []byte(`{}`), Secret: []byte("FAKE_SECRET")},
	} {
		if _, err := client.Call(t.Context(), request); err == nil {
			t.Fatal("非法 envelope 被发送")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("输入校验晚于连接")
	}
}

func TestCapabilityClientDoesNotRetryAfterSending(t *testing.T) {
	client := NewCapabilityClient("/run/qwq/capability.sock")
	var calls atomic.Int32
	client.dial = func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		local, remote := net.Pipe()
		go func() { defer remote.Close(); var req CapabilityRequest; _ = ReadHelperJSON(remote, &req) }()
		return local, nil
	}
	if _, err := client.Call(t.Context(), CapabilityRequest{Op: "account.set-password", ID: "security.basic", ParamsJSON: []byte(`{"user":"alice"}`), Secret: []byte("FAKE_SECRET")}); err == nil {
		t.Fatal("缺响应未报错")
	}
	if calls.Load() != 1 {
		t.Fatal("已发送的写请求被重发")
	}
}

func TestCapabilityClientCancellationInterruptsRead(t *testing.T) {
	client := NewCapabilityClient("/run/qwq/capability.sock")
	client.Timeout = time.Minute
	started := make(chan struct{})
	client.dial = func(context.Context, string, string) (net.Conn, error) {
		local, remote := net.Pipe()
		go func() {
			defer remote.Close()
			var req CapabilityRequest
			_ = ReadHelperJSON(remote, &req)
			close(started)
			_, _ = io.Copy(io.Discard, remote)
		}()
		return local, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := client.Call(ctx, CapabilityRequest{Op: "firewall.get", ID: "security.basic", ParamsJSON: []byte(`{}`)})
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("取消后未报错")
		}
	case <-time.After(time.Second):
		t.Fatal("取消未中断响应读取")
	}
}

func TestCapabilityJSONRejectsDuplicateKeysAndShortWrites(t *testing.T) {
	for _, body := range []string{`{"op":"ping","op":"exec"}`, `{"op":"firewall.get","id":"security.basic","params_json":{"user":"a","user":"b"}}`} {
		var req CapabilityRequest
		if err := ReadHelperJSON(strings.NewReader(body), &req); err == nil {
			t.Fatal("helper 接受了重复键")
		}
	}
	if err := WriteHelperJSON(shortHelperWriter{}, CapabilityResponse{OK: true}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("没有检查短写")
	}
}

type shortHelperWriter struct{}

func (shortHelperWriter) Write(data []byte) (int, error) { return len(data) - 1, nil }

func TestCapabilityMessagesRedact(t *testing.T) {
	request := CapabilityRequest{Op: "account.set-password", Secret: []byte("CANARY_SECRET")}
	if strings.Contains(request.String(), "CANARY_SECRET") {
		t.Fatal("格式化泄漏秘密")
	}
}
