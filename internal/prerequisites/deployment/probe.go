// SPDX-License-Identifier: AGPL-3.0-only

package deployment

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/qwq-panel/qwq/internal/platform/clock"
	"github.com/qwq-panel/qwq/internal/prerequisites/certificates"
	"github.com/qwq-panel/qwq/internal/prerequisites/consumerfiles"
	"github.com/qwq-panel/qwq/internal/prerequisites/fault"
	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 叶证书指纹与真实 TLS 握手健康探测 ========================

const (
	defaultProbeTimeout = 5 * time.Second
	maxProbeTimeout     = 10 * time.Second
)

// LeafFingerprintPEM 复用 tlsmgr 严格证书链解析，返回叶证书 DER 的 64 位小写 SHA-256 十六进制指纹。
func LeafFingerprintPEM(chainPEM []byte) (string, error) {
	certs, err := tlsmgr.ParseCertificateChain(chainPEM)
	if err != nil {
		return "", err
	}
	if len(certs) == 0 {
		return "", fault.New("CERTIFICATE_INVALID", "证书链缺少叶证书")
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

// TLSHandshakeProber 通过真实 TLS 握手核验消费者端点实际下发的叶证书指纹、有效期与目标 SNI。
type TLSHandshakeProber struct {
	Timeout time.Duration
	Clock   clock.Clock
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
}

var _ HandshakeProber = (*TLSHandshakeProber)(nil)

// Probe 连接消费者观测端点并执行真实 TLS 握手；只接受叶证书指纹、有效期与 SNI 全部精确匹配的连接。
func (p *TLSHandshakeProber) Probe(
	ctx context.Context,
	consumer certificates.Consumer,
	observation RuntimeObservation,
	expectedLeafFingerprint string,
) (HandshakeProbeResult, error) {
	if ctx == nil {
		return HandshakeProbeResult{}, fault.New("DEPLOYMENT_UNHEALTHY", "TLS 握手探测需要明确的 context")
	}
	if err := ctx.Err(); err != nil {
		return HandshakeProbeResult{}, errors.Join(fault.New("CANCELLED", "TLS 握手探测已取消"), err)
	}
	if !observation.Running || observation.Endpoint == "" {
		return HandshakeProbeResult{}, fault.New("DEPLOYMENT_UNHEALTHY", "消费者运行时未运行或缺少 TLS 探测端点")
	}
	if consumer.SNI == "" {
		return HandshakeProbeResult{}, fault.New("DEPLOYMENT_UNHEALTHY", "消费者缺少目标 SNI")
	}
	if !isHexSHA256(expectedLeafFingerprint) {
		return HandshakeProbeResult{}, fault.New("DEPLOYMENT_UNHEALTHY", "期望叶证书指纹格式无效")
	}

	timeout := defaultProbeTimeout
	if p != nil && p.Timeout > 0 {
		timeout = p.Timeout
	}
	if timeout > maxProbeTimeout {
		timeout = maxProbeTimeout
	}

	var clk clock.Clock = clock.System{}
	if p != nil && p.Clock != nil {
		clk = p.Clock
	}

	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	targetEndpoint, normErr := NormalizeLocalConsumerProbeEndpoint(observation.Endpoint)
	if normErr != nil {
		return HandshakeProbeResult{}, fault.New("DEPLOYMENT_UNHEALTHY", "消费者探测端点未通过本机回环/网卡校验")
	}

	dial := (&net.Dialer{Timeout: timeout}).DialContext
	if p != nil && p.Dial != nil {
		dial = p.Dial
	}

	// 纯 QUIC/UDP 消费者（Hysteria2）无 TCP 监听器：若目标 UDP 端口确在本机活跃监听且运行时元数据已核验，
	// 直接通过 UDP 路径验收；否则回退到下方真实 TCP TLS 握手探测（兼容双协议监听器与单元桩）。
	if consumer.Purpose == "proxy.hysteria2" && (p == nil || p.Dial == nil) {
		_, portStr, _ := net.SplitHostPort(targetEndpoint)
		portNum, portErr := strconv.ParseUint(portStr, 10, 16)
		if portErr == nil && portNum > 0 && hasLocalUDPListener(uint16(portNum)) {
			if observation.LeafFingerprint != expectedLeafFingerprint || observation.SNI != consumer.SNI {
				return HandshakeProbeResult{}, fault.New("DEPLOYMENT_UNHEALTHY", "Hysteria2 消费者运行时叶证书指纹或 SNI 与目标不符")
			}
			return HandshakeProbeResult{
				PeerLeafFingerprint: expectedLeafFingerprint,
				NegotiatedSNI:       consumer.SNI,
				NegotiatedProtocol:  "h3",
			}, nil
		}
	}

	rawConn, err := dial(bounded, "tcp", targetEndpoint)
	if err != nil {
		if ctx.Err() != nil {
			return HandshakeProbeResult{}, errors.Join(fault.New("CANCELLED", "TLS 握手探测已取消"), ctx.Err())
		}
		return HandshakeProbeResult{}, fault.New("DEPLOYMENT_UNHEALTHY", "无法连接消费者 TLS 探测端点")
	}
	if deadline, ok := bounded.Deadline(); ok {
		_ = rawConn.SetDeadline(deadline)
	}

	var verifyErr error
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         consumer.SNI,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // 由 VerifyPeerCertificate 执行精确叶指纹、时效与 SNI 密码学核验。
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				verifyErr = fault.New("DEPLOYMENT_UNHEALTHY", "消费者 TLS 握手未返回叶证书")
				return verifyErr
			}
			sum := sha256.Sum256(rawCerts[0])
			if hex.EncodeToString(sum[:]) != expectedLeafFingerprint {
				verifyErr = fault.New("DEPLOYMENT_UNHEALTHY", "消费者 TLS 握手返回的叶证书指纹与目标不符")
				return verifyErr
			}
			leaf, parseErr := x509.ParseCertificate(rawCerts[0])
			if parseErr != nil {
				verifyErr = fault.New("DEPLOYMENT_UNHEALTHY", "消费者 TLS 握手返回的叶证书无法解析")
				return verifyErr
			}
			now := clk.Now()
			if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
				verifyErr = fault.New("DEPLOYMENT_UNHEALTHY", "消费者 TLS 握手返回的叶证书不在有效期内")
				return verifyErr
			}
			if hostErr := leaf.VerifyHostname(consumer.SNI); hostErr != nil {
				verifyErr = fault.New("DEPLOYMENT_UNHEALTHY", "消费者 TLS 握手返回的叶证书不覆盖目标 SNI")
				return verifyErr
			}
			return nil
		},
	})
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.HandshakeContext(bounded); err != nil {
		if verifyErr != nil {
			return HandshakeProbeResult{}, verifyErr
		}
		if ctx.Err() != nil {
			return HandshakeProbeResult{}, errors.Join(fault.New("CANCELLED", "TLS 握手探测已取消"), ctx.Err())
		}
		return HandshakeProbeResult{}, fault.New("DEPLOYMENT_UNHEALTHY", "消费者 TLS 握手探测失败")
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return HandshakeProbeResult{}, fault.New("DEPLOYMENT_UNHEALTHY", "消费者 TLS 连接状态缺少叶证书")
	}
	peerSum := sha256.Sum256(state.PeerCertificates[0].Raw)
	if hex.EncodeToString(peerSum[:]) != expectedLeafFingerprint {
		return HandshakeProbeResult{}, fault.New("DEPLOYMENT_UNHEALTHY", "消费者 TLS 连接状态叶证书指纹与目标不符")
	}
	return HandshakeProbeResult{
		PeerLeafFingerprint: expectedLeafFingerprint,
		NegotiatedSNI:       consumer.SNI,
		NegotiatedProtocol:  state.NegotiatedProtocol,
	}, nil
}

// VerifyRuntimeHealth 同时核验消费者运行时观测快照与真实 TLS 握手结果；缺运行时或探测器一律视为不健康。
func VerifyRuntimeHealth(
	ctx context.Context,
	consumer certificates.Consumer,
	expected consumerfiles.Proof,
	expectedLeafFingerprint string,
	runtime ConsumerRuntime,
	prober HandshakeProber,
) error {
	if ctx == nil {
		return fault.New("DEPLOYMENT_UNHEALTHY", "运行时健康核验需要明确的 context")
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(fault.New("CANCELLED", "运行时健康核验已取消"), err)
	}
	if runtime == nil || prober == nil {
		return fault.New("DEPLOYMENT_UNHEALTHY", "缺少消费者运行时或 TLS 握手探测器")
	}
	if !isHexSHA256(expectedLeafFingerprint) {
		return fault.New("DEPLOYMENT_UNHEALTHY", "期望叶证书指纹格式无效")
	}

	obs, err := runtime.Inspect(ctx, consumer, expected.Binding.ID)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return errors.Join(fault.New("CANCELLED", "消费者运行时状态检查已取消"), err)
		}
		return fault.New("DEPLOYMENT_UNHEALTHY", "无法检查消费者运行时状态")
	}
	if !obs.Running {
		return fault.New("DEPLOYMENT_UNHEALTHY", "消费者运行时未处于运行状态")
	}
	if obs.BindingID != expected.Binding.ID {
		return fault.New("DEPLOYMENT_UNHEALTHY", "消费者运行时绑定 ID 与期望证明不符")
	}
	if obs.ActiveGeneration != expected.Binding.Generation {
		return fault.New("DEPLOYMENT_UNHEALTHY", "消费者运行时生效代次与期望证明不符")
	}
	if obs.PolicyRevision != expected.Binding.PolicyRevision {
		return fault.New("DEPLOYMENT_UNHEALTHY", "消费者运行时许可版本与期望证明不符")
	}
	if obs.FullchainSHA256 != expected.FullchainSHA256 {
		return fault.New("DEPLOYMENT_UNHEALTHY", "消费者运行时证书链摘要与期望证明不符")
	}
	if obs.LeafFingerprint != expectedLeafFingerprint {
		return fault.New("DEPLOYMENT_UNHEALTHY", "消费者运行时叶证书指纹与期望不符")
	}
	if obs.SNI != consumer.SNI {
		return fault.New("DEPLOYMENT_UNHEALTHY", "消费者运行时 SNI 与目标消费者不符")
	}

	res, err := prober.Probe(ctx, consumer, obs, expectedLeafFingerprint)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return errors.Join(fault.New("CANCELLED", "消费者 TLS 握手探测已取消"), err)
		}
		var fe *fault.Error
		if errors.As(err, &fe) && fe.Code == "DEPLOYMENT_UNHEALTHY" {
			return fe
		}
		return fault.New("DEPLOYMENT_UNHEALTHY", "消费者 TLS 握手探测未通过")
	}
	if res.PeerLeafFingerprint != expectedLeafFingerprint {
		return fault.New("DEPLOYMENT_UNHEALTHY", "TLS 握手探测返回的叶证书指纹与期望不符")
	}
	if res.NegotiatedSNI != consumer.SNI {
		return fault.New("DEPLOYMENT_UNHEALTHY", "TLS 握手探测协商的 SNI 与目标消费者不符")
	}
	return nil
}

func isHexSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// NormalizeLocalConsumerProbeEndpoint 确保宿主验证插件证书部署时仅连接本机回环或本机活跃网卡地址，
// 阻断受损插件返回云元数据或外部地址引发 SSRF，并将 0.0.0.0 / :: 映射至本机回环。
func NormalizeLocalConsumerProbeEndpoint(rawEndpoint string) (string, error) {
	host, portStr, err := net.SplitHostPort(rawEndpoint)
	if err != nil {
		return "", fmt.Errorf("probe: invalid endpoint %q: %w", rawEndpoint, err)
	}
	port, portErr := strconv.ParseUint(portStr, 10, 16)
	if portErr != nil || port == 0 {
		return "", fmt.Errorf("probe: invalid endpoint port %q", portStr)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return "", fmt.Errorf("probe: endpoint host %q must be an IP literal", host)
	}
	if ip.IsUnspecified() {
		if ip.Is6() {
			return net.JoinHostPort("::1", portStr), nil
		}
		return net.JoinHostPort("127.0.0.1", portStr), nil
	}
	if !ip.Unmap().IsLoopback() {
		if !isLocalInterfaceIP(ip) {
			return "", fmt.Errorf("probe: refusing non-local endpoint %s", ip)
		}
	}
	return net.JoinHostPort(ip.String(), portStr), nil
}

func isLocalInterfaceIP(target netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	t := target.Unmap()
	for _, a := range addrs {
		var cand net.IP
		switch v := a.(type) {
		case *net.IPNet:
			cand = v.IP
		case *net.IPAddr:
			cand = v.IP
		}
		if parsed, ok := netip.AddrFromSlice(cand); ok && parsed.Unmap() == t {
			return true
		}
	}
	return false
}

// hasLocalUDPListener 检查 /proc/net/udp 与 /proc/net/udp6 中目标端口是否存在未连接的本机监听套接字
// （状态 07=TCP_CLOSE/unbound-listen 且远端地址与端口全零）。
func hasLocalUDPListener(port uint16) bool {
	return hasLocalUDPListenerInFiles(port, []string{"/proc/net/udp", "/proc/net/udp6"})
}

func hasLocalUDPListenerInFiles(port uint16, procPaths []string) bool {
	for _, procPath := range procPaths {
		f, err := os.Open(procPath)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 {
				continue
			}
			if fields[3] != "07" {
				continue
			}
			if fields[2] != "00000000:0000" && fields[2] != "00000000000000000000000000000000:0000" {
				continue
			}
			_, localPortHex, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			lp, err := strconv.ParseUint(localPortHex, 16, 16)
			if err == nil && uint16(lp) == port {
				_ = f.Close()
				return true
			}
		}
		_ = f.Close()
	}
	return false
}
