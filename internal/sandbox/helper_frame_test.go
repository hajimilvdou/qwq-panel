// SPDX-License-Identifier: AGPL-3.0-only

package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// ======================== 共用分帧/传输：第二帧不丢失、拒绝peer不写正文、监听有界退出 ========================

func TestHelperRawFramePreservesPrefetchedSecondFrame(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader("{\"op\":\"ping\"}\n{\"op\":\"reload\"}\n"), 64<<10)
	var first HelperRequest
	if err := ReadHelperJSON(reader, &first); err != nil || first.Op != HelperOpPing || reader.Buffered() == 0 {
		t.Fatalf("正式reader丢失预读第二帧：%+v buffered=%d %v", first, reader.Buffered(), err)
	}
	second, err := ReadHelperDocument(reader)
	if err != nil || string(second) != `{"op":"reload"}` {
		t.Fatalf("预读第二帧不可见：%q %v", second, err)
	}
}

func TestHelperRawFrameFragmentsAndBound(t *testing.T) {
	for _, suffix := range []string{"\n", "\r\n", ""} {
		reader := bufio.NewReaderSize(strings.NewReader(`{"op":"ping"}`+suffix), 16)
		raw, err := ReadHelperDocument(reader)
		if err != nil || string(raw) != `{"op":"ping"}` {
			t.Fatalf("旧frame delimiter/EOF兼容损坏：%q %v", raw, err)
		}
	}
	reader := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", MaxHelperMessage+3)), 32)
	if _, err := ReadHelperDocument(reader); err == nil {
		t.Fatal("碎片frame超过1MiB未失败")
	}
}

func TestHelperReaderDisconnectConsumesPrefetchedBytes(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	execution, finish := WatchHelperReaderDisconnect(generationTestContext(t), server, bufio.NewReader(bytes.NewReader([]byte("second frame"))))
	defer finish()
	select {
	case <-execution.Done():
	case <-time.After(time.Second):
		t.Fatal("预读额外内容绕过原请求取消")
	}
}

func TestHelperReaderDisconnectCancellationWaitsForBlockedReader(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	ctx, cancel := context.WithCancel(generationTestContext(t))
	execution, finish := WatchHelperReaderDisconnect(ctx, server, bufio.NewReader(server))
	cancel()
	done := make(chan struct{})
	go func() {
		finish()
		close(done)
	}()
	select {
	case <-done:
		if !errors.Is(execution.Err(), context.Canceled) {
			t.Fatal(execution.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("finish没有等待/唤醒被阻塞的reader")
	}
}

func TestHelperCheckedExchangeRejectsPeerBeforeAnyBody(t *testing.T) {
	server, connection := net.Pipe()
	defer server.Close()
	if err := server.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	type received struct {
		count int
		err   error
	}
	done := make(chan received, 1)
	go func() {
		var body [1]byte
		n, err := server.Read(body[:])
		done <- received{n, err}
	}()
	client := NewHelperClient("/run/qwq/test.sock")
	client.dial = func(context.Context, string, string) (net.Conn, error) { return connection, nil }
	denied := errors.New("test peer denied")
	if err := client.exchangeChecked(generationTestContext(t), HelperRequest{Op: HelperOpPing}, &HelperResponse{}, func(net.Conn) error { return denied }); !errors.Is(err, denied) {
		t.Fatalf("peer拒绝未返回：%v", err)
	}
	select {
	case result := <-done:
		if result.count != 0 || !errors.Is(result.err, io.EOF) {
			t.Fatalf("peer拒绝前发送了正文：%+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("peer拒绝后连接未关闭")
	}
}
