// SPDX-License-Identifier: AGPL-3.0-only

package anytls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func generateTestCertPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "anytls.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"anytls.local"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func writeTestFrame(t *testing.T, w io.Writer, cmd byte, streamID uint32, payload []byte) {
	t.Helper()
	var hdr [7]byte
	hdr[0] = cmd
	binary.BigEndian.PutUint32(hdr[1:5], streamID)
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
}

func readTestFrame(t *testing.T, r io.Reader) (byte, uint32, []byte) {
	t.Helper()
	var hdr [7]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatal(err)
	}
	cmd := hdr[0]
	sid := binary.BigEndian.Uint32(hdr[1:5])
	n := binary.BigEndian.Uint16(hdr[5:7])
	data := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, data); err != nil {
			t.Fatal(err)
		}
	}
	return cmd, sid, data
}

func TestAnyTLSV2EndToEndEchoAndCounters(t *testing.T) {
	// 1. 启动本地 TCP Echo 服务器作为代理目标
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(nc net.Conn) {
				defer nc.Close()
				_, _ = io.Copy(nc, nc)
			}(c)
		}
	}()
	echoAddr := echoLn.Addr().(*net.TCPAddr)

	// 2. 启动纯 Go AnyTLS v2 服务端
	certPEM, keyPEM := generateTestCertPEM(t)
	password := "anytls-super-secret-password-2026"
	srv, err := NewServer(ProfileSpec{
		ProfileID:          "anytls-main",
		BindingRef:         "bind-anytls-1",
		ServerName:         "anytls.local",
		Listen:             "127.0.0.1",
		Port:               1, // 测试中用自由端口覆盖 listenAddr
		CertPEM:            certPEM,
		KeyPEM:             keyPEM,
		Users:              map[string][]byte{"alice": []byte(password)},
		AllowPrivateTarget: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.listenAddr = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop(2 * time.Second)

	// 3. 发起真实 TLS 连接并执行 AnyTLS v2 握手
	conn, err := tls.Dial("tcp", srv.Addr().String(), &tls.Config{
		ServerName:         "anytls.local",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 发送认证头：sha256(password) + uint16(padLen=4) + 4字节pad0
	pwHash := sha256.Sum256([]byte(password))
	var authBuf bytes.Buffer
	authBuf.Write(pwHash[:])
	_ = binary.Write(&authBuf, binary.BigEndian, uint16(4))
	authBuf.Write([]byte{0xAA, 0xBB, 0xCC, 0xDD})
	if _, err := conn.Write(authBuf.Bytes()); err != nil {
		t.Fatal(err)
	}

	// 发送 cmdSettings (v=2, 故意传入不匹配的 padding-md5 触发服务端下发 paddingScheme)
	writeTestFrame(t, conn, cmdSettings, 0, []byte("v=2\nclient=qwq-test\npadding-md5=deadbeef\n"))

	// 读取服务端响应：cmdServerSettings (10) 与 cmdUpdatePaddingScheme (6)
	cmd1, _, data1 := readTestFrame(t, conn)
	if cmd1 != cmdServerSettings || !strings.Contains(string(data1), "v=2") {
		t.Fatalf("期望 cmdServerSettings v=2，实际 cmd=%d data=%q", cmd1, string(data1))
	}
	cmd2, _, data2 := readTestFrame(t, conn)
	if cmd2 != cmdUpdatePaddingScheme || !strings.Contains(string(data2), "stop=8") {
		t.Fatalf("期望 cmdUpdatePaddingScheme stop=8，实际 cmd=%d data=%q", cmd2, string(data2))
	}

	// 发送心跳测试
	writeTestFrame(t, conn, cmdHeartRequest, 0, nil)
	hbCmd, _, _ := readTestFrame(t, conn)
	if hbCmd != cmdHeartResponse {
		t.Fatalf("期望 cmdHeartResponse (9)，实际 %d", hbCmd)
	}

	// 发送 cmdSYN (streamID=1) + 分片发送 SOCKS5 IPv4 目标地址与业务载荷
	writeTestFrame(t, conn, cmdSYN, 1, nil)
	var socksAddr bytes.Buffer
	socksAddr.WriteByte(1) // IPv4
	socksAddr.Write(echoAddr.IP.To4())
	_ = binary.Write(&socksAddr, binary.BigEndian, uint16(echoAddr.Port))
	// 故意拆成两帧测试分片地址解析
	addrBytes := socksAddr.Bytes()
	writeTestFrame(t, conn, cmdPSH, 1, addrBytes[:3])
	payload := []byte("hello-anytls-v2-world!")
	writeTestFrame(t, conn, cmdPSH, 1, append(addrBytes[3:], payload...))

	// 等待 cmdSYNACK (len=0 表示建连成功)
	ackCmd, ackSID, ackData := readTestFrame(t, conn)
	if ackCmd != cmdSYNACK || ackSID != 1 || len(ackData) != 0 {
		t.Fatalf("期望成功 cmdSYNACK，实际 cmd=%d sid=%d data=%q", ackCmd, ackSID, string(ackData))
	}

	// 读取 Echo 返回载荷
	var echoed bytes.Buffer
	for echoed.Len() < len(payload) {
		c, sid, d := readTestFrame(t, conn)
		if c == cmdWaste {
			continue
		}
		if c != cmdPSH || sid != 1 {
			t.Fatalf("期望 cmdPSH sid=1，实际 cmd=%d sid=%d", c, sid)
		}
		echoed.Write(d)
	}
	if !bytes.Equal(echoed.Bytes(), payload) {
		t.Fatalf("Echo 载荷不匹配: got %q want %q", echoed.String(), string(payload))
	}

	// 发送 cmdFIN 优雅关闭流
	writeTestFrame(t, conn, cmdFIN, 1, nil)

	// 验证入站与用户流量计数器 > 0
	counters := make(map[string]int64)
	srv.AddCounters(counters)
	inUp := counters["inbound>>>qwq-in-anytls-main>>>traffic>>>uplink"]
	inDown := counters["inbound>>>qwq-in-anytls-main>>>traffic>>>downlink"]
	uUp := counters["user>>>qwq-user-alice>>>traffic>>>uplink"]
	uDown := counters["user>>>qwq-user-alice>>>traffic>>>downlink"]
	if inUp < int64(len(payload)) || inDown < int64(len(payload)) || uUp < int64(len(payload)) || uDown < int64(len(payload)) {
		t.Fatalf("流量计数器未正确累加: %+v", counters)
	}

	// 测试证书零中断热更新
	certPEM2, keyPEM2 := generateTestCertPEM(t)
	if err := srv.UpdateCertificate(certPEM2, keyPEM2); err != nil {
		t.Fatalf("UpdateCertificate 失败: %v", err)
	}
}

func TestAnyTLSPipelined0RTTOrderingAndPromptStop(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(nc net.Conn) {
				defer nc.Close()
				_, _ = io.Copy(nc, nc)
			}(c)
		}
	}()
	echoAddr := echoLn.Addr().(*net.TCPAddr)

	certPEM, keyPEM := generateTestCertPEM(t)
	password := "anytls-pipelined-0rtt-secret"
	srv, err := NewServer(ProfileSpec{
		ProfileID:   "anytls-0rtt",
		BindingRef:  "bind-anytls-0rtt",
		ServerName:  "anytls.local",
		Listen:      "127.0.0.1",
		Port:        1,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		UserDigests: map[string][32]byte{"bob": sha256.Sum256([]byte(password))},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.listenAddr = "127.0.0.1:0"
	// 注入建连延迟，确保客户端在 dial 完成前就已推送多帧 0-RTT 数据，覆盖 pending 排空竞态。
	srv.dialTarget = func(ctx context.Context, network, addr string) (net.Conn, error) {
		time.Sleep(40 * time.Millisecond)
		return (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, network, addr)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}

	conn, err := tls.Dial("tcp", srv.Addr().String(), &tls.Config{
		ServerName:         "anytls.local",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	pwHash := sha256.Sum256([]byte(password))
	var authBuf bytes.Buffer
	authBuf.Write(pwHash[:])
	_ = binary.Write(&authBuf, binary.BigEndian, uint16(0))
	if _, err := conn.Write(authBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	writeTestFrame(t, conn, cmdSettings, 0, []byte("v=2\n"))
	_, _, _ = readTestFrame(t, conn) // cmdServerSettings
	_, _, _ = readTestFrame(t, conn) // cmdUpdatePaddingScheme

	var socksAddr bytes.Buffer
	socksAddr.WriteByte(1)
	socksAddr.Write(echoAddr.IP.To4())
	_ = binary.Write(&socksAddr, binary.BigEndian, uint16(echoAddr.Port))

	var expected bytes.Buffer
	firstChunk := []byte("SEQ-0000|")
	expected.Write(firstChunk)
	writeTestFrame(t, conn, cmdSYN, 7, append(socksAddr.Bytes(), firstChunk...))
	// 不等待 cmdSYNACK，连续流水线发送 64 个带序号块，验证严格 FIFO 字节序
	for i := 1; i <= 64; i++ {
		chunk := []byte{
			'C', byte('0' + (i/10)%10), byte('0' + i%10), '-',
			byte(i), byte(i ^ 0x5A), '|',
		}
		expected.Write(chunk)
		writeTestFrame(t, conn, cmdPSH, 7, chunk)
		if i == 32 {
			time.Sleep(35 * time.Millisecond) // 跨 dialAndRelay 排空窗口并发写入
		}
	}

	ackCmd, ackSID, ackData := readTestFrame(t, conn)
	if ackCmd != cmdSYNACK || ackSID != 7 || len(ackData) != 0 {
		t.Fatalf("期望 cmdSYNACK sid=7 成功，实际 cmd=%d sid=%d data=%q", ackCmd, ackSID, string(ackData))
	}

	var echoed bytes.Buffer
	for echoed.Len() < expected.Len() {
		c, sid, d := readTestFrame(t, conn)
		if c == cmdWaste {
			continue
		}
		if c != cmdPSH || sid != 7 {
			t.Fatalf("期望 cmdPSH sid=7，实际 cmd=%d sid=%d", c, sid)
		}
		echoed.Write(d)
	}
	if !bytes.Equal(echoed.Bytes(), expected.Bytes()) {
		t.Fatalf("0-RTT 流水线字节序损坏: gotLen=%d wantLen=%d", echoed.Len(), expected.Len())
	}

	// 客户端保持空闲不关闭，验证 Stop() 立即关闭活跃连接并在远小于超时时间内退出
	stopStart := time.Now()
	srv.Stop(3 * time.Second)
	if elapsed := time.Since(stopStart); elapsed > 800*time.Millisecond {
		t.Fatalf("存在空闲活跃客户端时 Stop() 未立即回收连接，耗时 %v", elapsed)
	}
}

func TestAnyTLSRejectsSSRFAndUnknownSNI(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	echoAddr := echoLn.Addr().(*net.TCPAddr)

	certPEM, keyPEM := generateTestCertPEM(t)
	password := "anytls-ssrf-guard-secret"
	srv, err := NewServer(ProfileSpec{
		ProfileID:  "anytls-guard",
		BindingRef: "bind-guard",
		ServerName: "anytls.local",
		Listen:     "127.0.0.1",
		Port:       1,
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		Users:      map[string][]byte{"alice": []byte(password)},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.listenAddr = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop(2 * time.Second)

	// 1. 未知 SNI 必须在 TLS 握手层直接拒止
	if badConn, err := tls.Dial("tcp", srv.Addr().String(), &tls.Config{
		ServerName:         "evil.example.test",
		InsecureSkipVerify: true,
	}); err == nil {
		_ = badConn.Close()
		t.Fatal("未知 SNI 未在 TLS 握手层被拒绝")
	}

	// 2. 合法 SNI 鉴权后，请求回环地址 127.0.0.1 必须被 SafeOutboundDialer 阻断
	conn, err := tls.Dial("tcp", srv.Addr().String(), &tls.Config{
		ServerName:         "anytls.local",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	pwHash := sha256.Sum256([]byte(password))
	var authBuf bytes.Buffer
	authBuf.Write(pwHash[:])
	_ = binary.Write(&authBuf, binary.BigEndian, uint16(0))
	if _, err := conn.Write(authBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	writeTestFrame(t, conn, cmdSettings, 0, []byte("v=2\n"))
	_, _, _ = readTestFrame(t, conn)
	_, _, _ = readTestFrame(t, conn)

	var socksAddr bytes.Buffer
	socksAddr.WriteByte(1)
	socksAddr.Write(echoAddr.IP.To4())
	_ = binary.Write(&socksAddr, binary.BigEndian, uint16(echoAddr.Port))
	writeTestFrame(t, conn, cmdSYN, 3, socksAddr.Bytes())

	ackCmd, ackSID, ackData := readTestFrame(t, conn)
	if ackCmd != cmdSYNACK || ackSID != 3 || len(ackData) == 0 {
		t.Fatalf("期望 SSRF 拦截返回带错误的 cmdSYNACK，实际 cmd=%d sid=%d data=%q", ackCmd, ackSID, string(ackData))
	}
}

func TestAnyTLSV2UoTUDPEcho(t *testing.T) {
	udpSrv, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpSrv.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, rerr := udpSrv.ReadFrom(buf)
			if rerr != nil {
				return
			}
			_, _ = udpSrv.WriteTo(buf[:n], addr)
		}
	}()
	udpAddr := udpSrv.LocalAddr().(*net.UDPAddr)

	certPEM, keyPEM := generateTestCertPEM(t)
	password := "anytls-uot-v2-secret"
	srv, err := NewServer(ProfileSpec{
		ProfileID:          "anytls-uot",
		BindingRef:         "bind-uot",
		ServerName:         "anytls.local",
		Listen:             "127.0.0.1",
		Port:               1,
		CertPEM:            certPEM,
		KeyPEM:             keyPEM,
		Users:              map[string][]byte{"alice": []byte(password)},
		AllowPrivateTarget: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.listenAddr = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop(2 * time.Second)

	conn, err := tls.Dial("tcp", srv.Addr().String(), &tls.Config{
		ServerName:         "anytls.local",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	pwHash := sha256.Sum256([]byte(password))
	var authBuf bytes.Buffer
	authBuf.Write(pwHash[:])
	_ = binary.Write(&authBuf, binary.BigEndian, uint16(0))
	if _, err := conn.Write(authBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	writeTestFrame(t, conn, cmdSettings, 0, []byte("v=2\n"))
	_, _, _ = readTestFrame(t, conn)
	_, _, _ = readTestFrame(t, conn)

	// 发送 UoT v2 魔法域名 sp.v2.udp-over-tcp.arpa:53 + connect flag(1) + target UDP addr + 2B len + payload
	var uotInit bytes.Buffer
	uotInit.WriteByte(3)
	uotInit.WriteByte(byte(len(uotMagicHostV2)))
	uotInit.WriteString(uotMagicHostV2)
	_ = binary.Write(&uotInit, binary.BigEndian, uint16(53))
	uotInit.WriteByte(1) // isConnect=1
	uotInit.WriteByte(1) // IPv4
	uotInit.Write(udpAddr.IP.To4())
	_ = binary.Write(&uotInit, binary.BigEndian, uint16(udpAddr.Port))
	payload := []byte("hello-anytls-uot-v2-udp")
	_ = binary.Write(&uotInit, binary.BigEndian, uint16(len(payload)))
	uotInit.Write(payload)

	writeTestFrame(t, conn, cmdSYN, 9, uotInit.Bytes())
	ackCmd, ackSID, ackData := readTestFrame(t, conn)
	if ackCmd != cmdSYNACK || ackSID != 9 || len(ackData) != 0 {
		t.Fatalf("期望 UoT cmdSYNACK 成功，实际 cmd=%d sid=%d data=%q", ackCmd, ackSID, string(ackData))
	}
	cmd, sid, respFrame := readTestFrame(t, conn)
	if cmd != cmdPSH || sid != 9 || len(respFrame) < 2 {
		t.Fatalf("期望 UoT 回包 cmdPSH sid=9，实际 cmd=%d sid=%d len=%d", cmd, sid, len(respFrame))
	}
	gotLen := int(binary.BigEndian.Uint16(respFrame[0:2]))
	if gotLen != len(payload) || !bytes.Equal(respFrame[2:2+gotLen], payload) {
		t.Fatalf("UoT UDP 回包不匹配: got %q want %q", string(respFrame[2:]), string(payload))
	}
	writeTestFrame(t, conn, cmdFIN, 9, nil)
}
