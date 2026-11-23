// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/smtp"
	"strings"
	"time"
)

// RelaySMTPConfig 描述门户 SMTP 发信服务器参数。
type RelaySMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	UseTLS   bool // 465 隐式 TLS 或 587 STARTTLS
}

var (
	smtpBlockedPrefixes = []netip.Prefix{
		netip.MustParsePrefix("169.254.0.0/16"),    // AWS/GCP/Azure/OpenStack IMDS & Link-Local
		netip.MustParsePrefix("100.64.0.0/10"),     // 阿里云 100.100.100.200 元数据 & CGNAT
		netip.MustParsePrefix("0.0.0.0/8"),         // 本网络保留段
		netip.MustParsePrefix("fe80::/10"),         // IPv6 Link-Local
		netip.MustParsePrefix("fd00:ec2::254/128"), // AWS IPv6 IMDS
		netip.MustParsePrefix("64:ff9b::/96"),      // NAT64 well-known
		netip.MustParsePrefix("64:ff9b:1::/48"),    // NAT64 local
		netip.MustParsePrefix("2002::/16"),         // 6to4
		netip.MustParsePrefix("2001::/32"),         // Teredo
	}
)

func isMetadataIP(addr netip.Addr) bool {
	a := addr.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return true
	}
	for _, p := range smtpBlockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func validateSMTPHostNotMetadata(ctx context.Context, host string) (string, error) {
	clean := strings.Trim(strings.TrimSpace(host), "[]")
	if clean == "" {
		return "", errors.New("SMTP_NOT_CONFIGURED: 管理员尚未完成门户 SMTP 发信服务器配置")
	}
	if strings.EqualFold(clean, "metadata.google.internal") || strings.EqualFold(clean, "metadata.goog") {
		return "", errors.New("SSRF_BLOCKED: 禁止连接云元数据主机作为 SMTP 服务器")
	}
	if ip, err := netip.ParseAddr(clean); err == nil {
		if isMetadataIP(ip) {
			return "", fmt.Errorf("SSRF_BLOCKED: 禁止连接云元数据地址 %s 作为 SMTP 服务器", ip.String())
		}
		return ip.Unmap().String(), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", clean)
	if err != nil {
		return "", fmt.Errorf("resolve smtp host: %w", err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolve smtp host %s: no ip", clean)
	}
	for _, ip := range ips {
		if isMetadataIP(ip) {
			return "", fmt.Errorf("SSRF_BLOCKED: SMTP 域名 %s 解析到云元数据地址 %s", clean, ip.String())
		}
	}
	return ips[0].Unmap().String(), nil
}

// SendVerificationEmailBounded 在 SendEmailOTP 落库后真实调用，内置 12s 全链路硬超时（conn.SetDeadline）、
// 元数据 IP 硬拦截（即使允许内网也绝不放行云元数据）与 RFC 2047 UTF-8 Base64 标题编码。
func SendVerificationEmailBounded(ctx context.Context, cfg RelaySMTPConfig, toEmail, siteTitle, otpCode string) error {
	if strings.TrimSpace(cfg.Host) == "" || cfg.Port <= 0 || strings.TrimSpace(cfg.From) == "" {
		return errors.New("SMTP_NOT_CONFIGURED: 管理员尚未完成门户 SMTP 发信服务器配置")
	}
	if strings.ContainsAny(toEmail+cfg.From+cfg.Host, "\r\n\x00") {
		return errors.New("INVALID_EMAIL_HEADER")
	}
	if siteTitle == "" {
		siteTitle = "qwq AI Relay"
	}

	deadline := time.Now().Add(12 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	resolvedIP, err := validateSMTPHostNotMetadata(ctx, cfg.Host)
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(resolvedIP, fmt.Sprintf("%d", cfg.Port))
	dialer := &net.Dialer{Deadline: deadline}

	var conn net.Conn
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	if cfg.Port == 465 {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect smtp server: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return err
	}
	defer client.Close()

	if cfg.Port != 465 && cfg.UseTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("smtp starttls: %w", err)
			}
		}
	}
	if strings.TrimSpace(cfg.Username) != "" {
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		if err := client.Auth(auth); err != nil {
			return errors.New("SMTP_AUTH_FAILED: 发信服务器认证失败")
		}
	}
	if err := client.Mail(cfg.From); err != nil {
		return err
	}
	if err := client.Rcpt(toEmail); err != nil {
		return err
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}

	subjectRaw := fmt.Sprintf("[%s] 邮箱验证码：%s", siteTitle, otpCode)
	encodedSubject := "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(subjectRaw)) + "?="
	msg := strings.Join([]string{
		"From: " + cfg.From,
		"To: " + toEmail,
		"Subject: " + encodedSubject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		fmt.Sprintf("您好！\n\n您正在 %s 进行邮箱验证，本次一次性验证码为：%s\n有效期 10 分钟，请勿泄露给他人。\n", siteTitle, otpCode),
	}, "\r\n")

	if _, err := io.WriteString(wc, msg); err != nil {
		_ = wc.Close()
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return client.Quit()
}
