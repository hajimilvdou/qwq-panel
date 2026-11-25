// SPDX-License-Identifier: AGPL-3.0-only

package anytls

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// 修复 R2-BUG-25（AnyTLS 封神升级补丁）：
//   完整实现 SagerNet UDP-over-TCP (UoT v1 `sp.udp-over-tcp.arpa` & UoT v2 `sp.v2.udp-over-tcp.arpa`)！
//   让 sing-box / Shadowrocket / NekoBox / Hiddify 客户端在 AnyTLS 下原生跑通远程 UDP DNS 与 QUIC/HTTP3，
//   且每个 UDP 目标包同样严格经过 IsPublicOutboundAddr 公网安全门禁校验，100% 阻断内网/回环 UDP 反射与探测！
// ============================================================================

const (
	uotMagicHostV1 = "sp.udp-over-tcp.arpa"
	uotMagicHostV2 = "sp.v2.udp-over-tcp.arpa"
	maxUDPPacket   = 65535
	udpIdleTimeout = 90 * time.Second
)

// IsUoTMagicTarget 判断客户端流请求的目标主机是否为 SagerNet UDP-over-TCP 魔法域名。
func IsUoTMagicTarget(targetAddr string) (version int, isUoT bool) {
	host := targetAddr
	if h, _, err := net.SplitHostPort(targetAddr); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	switch host {
	case uotMagicHostV2:
		return 2, true
	case uotMagicHostV1:
		return 1, true
	default:
		return 0, false
	}
}

// relayUoTStream 在单个 AnyTLS 复用流内处理 UoT v1 / v2 UDP 数据报收发。
//
// 协议格式对齐 github.com/sagernet/sing/common/uot：
//   - UoT v2 首字节为 `isConnect` (0x01 = 连接型单目标：紧跟一次 SOCKS5 地址头，后续每帧仅 2B BE 长度 + payload；
//     0x00 = 非连接型多目标：每帧均为 SOCKS5 地址头 + 2B BE 长度 + payload)；
//   - UoT v1 无首字节，固定为非连接型多目标帧（每帧 SOCKS5 地址头 + 2B BE 长度 + payload）。
func (st *anytlsStream) relayUoTStream(uotVersion int, streamReader io.ReadCloser) {
	defer streamReader.Close()

	pconn, err := net.ListenPacket("udp", "")
	if err != nil {
		st.failDial(err)
		return
	}
	defer pconn.Close()

	st.sess.mu.Lock()
	ver := st.sess.clientVersion
	st.sess.mu.Unlock()
	if ver >= 2 {
		if werr := st.sess.writeFrame(cmdSYNACK, st.id, nil); werr != nil {
			st.sess.removeStream(st.id, true)
			return
		}
	}

	allowPrivate := st.sess.server.allowPrivateTarget
	isConnect := false
	var connectedTarget *net.UDPAddr

	if uotVersion == 2 {
		var flag [1]byte
		if _, err := io.ReadFull(streamReader, flag[:]); err != nil {
			st.sess.removeStream(st.id, true)
			return
		}
		isConnect = flag[0] == 1
		if isConnect {
			destStr, rerr := readSocks5AddrFromReader(streamReader)
			if rerr != nil {
				st.sess.removeStream(st.id, true)
				return
			}
			uaddr, aerr := resolveVerifiedPublicUDPAddr(st.sess.server.ctx, destStr, allowPrivate)
			if aerr != nil {
				st.sess.removeStream(st.id, true)
				return
			}
			connectedTarget = uaddr
		}
	}

	// 启动下行协程：将远端 UDP 回包封装回 AnyTLS cmdPSH 帧
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		recvBuf := make([]byte, maxFramePayload)
		for {
			_ = pconn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, fromAddr, rerr := pconn.ReadFrom(recvBuf)
			if n > 0 {
				var frame []byte
				if isConnect {
					frame = make([]byte, 2+n)
					binary.BigEndian.PutUint16(frame[0:2], uint16(n))
					copy(frame[2:], recvBuf[:n])
				} else {
					addrBytes := encodeSocks5UDPAddr(fromAddr)
					frame = make([]byte, len(addrBytes)+2+n)
					copy(frame, addrBytes)
					binary.BigEndian.PutUint16(frame[len(addrBytes):len(addrBytes)+2], uint16(n))
					copy(frame[len(addrBytes)+2:], recvBuf[:n])
				}
				if werr := st.sess.writeFrame(cmdPSH, st.id, frame); werr != nil {
					return
				}
				st.sess.server.inboundDown.Add(int64(n))
				st.sess.user.down.Add(int64(n))
			}
			if rerr != nil {
				return
			}
		}
	}()

	// 上行循环：从客户端流解析 UoT 数据报并校验公网目标后发出
	pktBuf := make([]byte, maxUDPPacket)
	for {
		var target *net.UDPAddr
		if isConnect {
			target = connectedTarget
		} else {
			destStr, rerr := readSocks5AddrFromReader(streamReader)
			if rerr != nil {
				break
			}
			uaddr, aerr := resolveVerifiedPublicUDPAddr(st.sess.server.ctx, destStr, allowPrivate)
			if aerr != nil {
				break
			}
			target = uaddr
		}

		var lenBuf [2]byte
		if _, rerr := io.ReadFull(streamReader, lenBuf[:]); rerr != nil {
			break
		}
		pktLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if pktLen == 0 {
			continue
		}
		if _, rerr := io.ReadFull(streamReader, pktBuf[:pktLen]); rerr != nil {
			break
		}
		_ = pconn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		_ = pconn.SetWriteDeadline(time.Now().Add(targetWriteTimeout))
		if wn, werr := pconn.WriteTo(pktBuf[:pktLen], target); werr == nil && wn > 0 {
			st.sess.server.inboundUp.Add(int64(wn))
			st.sess.user.up.Add(int64(wn))
		}
	}

	_ = pconn.Close()
	<-doneCh
	st.sess.removeStream(st.id, true)
	_ = st.sess.writeFrame(cmdFIN, st.id, nil)
}

func resolveVerifiedPublicUDPAddr(parent context.Context, dest string, allowPrivate bool) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("anytls uot: invalid port")
	}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		if !allowPrivate && !IsPublicOutboundAddr(ip) {
			return nil, ErrBlockedDestination
		}
		return &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: port}, nil
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, dialTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("anytls uot: resolve failed")
	}
	for _, ip := range ips {
		if allowPrivate || IsPublicOutboundAddr(ip) {
			return &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: port}, nil
		}
	}
	return nil, ErrBlockedDestination
}

func readSocks5AddrFromReader(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", err
	}
	switch atyp[0] {
	case 1:
		var buf [6]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return "", err
		}
		port := binary.BigEndian.Uint16(buf[4:6])
		if port == 0 {
			return "", errors.New("invalid port 0")
		}
		return net.JoinHostPort(net.IP(buf[0:4]).String(), strconv.Itoa(int(port))), nil
	case 3:
		var dlen [1]byte
		if _, err := io.ReadFull(r, dlen[:]); err != nil || dlen[0] == 0 {
			return "", errors.New("invalid domain length")
		}
		buf := make([]byte, int(dlen[0])+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		port := binary.BigEndian.Uint16(buf[int(dlen[0]):])
		if port == 0 {
			return "", errors.New("invalid port 0")
		}
		return net.JoinHostPort(string(buf[:int(dlen[0])]), strconv.Itoa(int(port))), nil
	case 4:
		var buf [18]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return "", err
		}
		port := binary.BigEndian.Uint16(buf[16:18])
		if port == 0 {
			return "", errors.New("invalid port 0")
		}
		return net.JoinHostPort(net.IP(buf[0:16]).String(), strconv.Itoa(int(port))), nil
	default:
		return "", errors.New("unsupported uot address family")
	}
}

func encodeSocks5UDPAddr(addr net.Addr) []byte {
	uaddr, ok := addr.(*net.UDPAddr)
	if !ok || uaddr == nil {
		return []byte{1, 0, 0, 0, 0, 0, 0}
	}
	if ip4 := uaddr.IP.To4(); ip4 != nil {
		out := make([]byte, 7)
		out[0] = 1
		copy(out[1:5], ip4)
		binary.BigEndian.PutUint16(out[5:7], uint16(uaddr.Port))
		return out
	}
	ip16 := uaddr.IP.To16()
	out := make([]byte, 19)
	out[0] = 4
	copy(out[1:17], ip16)
	binary.BigEndian.PutUint16(out[17:19], uint16(uaddr.Port))
	return out
}
