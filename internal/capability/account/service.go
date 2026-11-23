// SPDX-License-Identifier: AGPL-3.0-only

// Package account 提供受限的 Linux 账户 SSH 公钥与口令管理能力及 SSHD 恢复守卫。
package account

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/qwq-panel/qwq/internal/capability/bridge"
	"github.com/qwq-panel/qwq/internal/capability/sshd"
	"github.com/qwq-panel/qwq/internal/sandbox"
	accountv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/account/v1"
	"golang.org/x/crypto/ssh"
)

// ======================== 账户校验、密钥强度与防穿越常量 ========================

const (
	maxAuthorizedKeysBytes = 256 << 10
	maxAuthorizedKeysLines = 512
	minPasswordLen         = 12
	maxPasswordLen         = 128
)

var validUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

type passwdEntry struct {
	Username string
	UID      int
	GID      int
	HomeDir  string
	Shell    string
}

// SSHDReader 供防自锁检查查询目标用户的有效 SSHD 配置。
type SSHDReader interface {
	Read(ctx context.Context, match sshd.Match) (sshd.Snapshot, error)
}

// PasswordSetter 封装 chpasswd 执行，默认通过 stdin 喂入 /usr/sbin/chpasswd -c SHA512。
type PasswordSetter func(ctx context.Context, username string, password []byte) error

// Service 运行在特权 capability helper 中，处理 5 个 account.* verb。
type Service struct {
	PasswdPath   string
	ChpasswdPath string
	SSHD         SSHDReader
	SetPass      PasswordSetter
	mu           sync.Mutex
}

// NewService 构造默认账户能力服务。
func NewService(sshdReader SSHDReader) *Service {
	return &Service{
		PasswdPath:   "/etc/passwd",
		ChpasswdPath: "/usr/sbin/chpasswd",
		SSHD:         sshdReader,
	}
}

// ======================== Capability Helper 请求路由 ========================

type userQuery struct {
	User string `json:"user"`
}

type importKeyParams struct {
	User             string `json:"user"`
	PublicKey        string `json:"public_key"`
	ExpectedRevision string `json:"expected_revision"`
}

type removeKeyParams struct {
	User             string `json:"user"`
	Fingerprint      string `json:"fingerprint_sha256"`
	ExpectedRevision string `json:"expected_revision"`
}

type generateKeyParams struct {
	User             string `json:"user"`
	Type             string `json:"type"`
	ExpectedRevision string `json:"expected_revision"`
}

type setPasswordParams struct {
	User             string `json:"user"`
	ExpectedRevision string `json:"expected_revision"`
}

// Run 路由 account.* 五个受控动词，未知动词或非法请求立即失败关闭。
func (s *Service) Run(ctx context.Context, request sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	defer clear(request.Secret)
	if sandbox.ValidateCapabilityRequest(request) != nil || request.Cursor != "" {
		return bridge.Failure("VALIDATION_FAILED", "账户能力请求无效"), nil
	}
	if request.Op != "account.set-password" && len(request.Secret) != 0 {
		return bridge.Failure("VALIDATION_FAILED", "非口令修改请求不允许携带秘密"), nil
	}
	params := request.ParamsJSON
	if len(params) == 0 {
		params = []byte("{}")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch request.Op {
	case "account.list-keys":
		var q userQuery
		if sandbox.DecodeHelperDocument(params, &q) != nil {
			return bridge.Failure("VALIDATION_FAILED", "查询参数无效"), nil
		}
		return s.listKeys(q.User), nil
	case "account.import-key":
		var p importKeyParams
		if sandbox.DecodeHelperDocument(params, &p) != nil {
			return bridge.Failure("VALIDATION_FAILED", "导入公钥参数无效"), nil
		}
		return s.importKey(p), nil
	case "account.remove-key":
		var p removeKeyParams
		if sandbox.DecodeHelperDocument(params, &p) != nil {
			return bridge.Failure("VALIDATION_FAILED", "删除公钥参数无效"), nil
		}
		return s.removeKey(ctx, p), nil
	case "account.generate-key":
		var p generateKeyParams
		if sandbox.DecodeHelperDocument(params, &p) != nil {
			return bridge.Failure("VALIDATION_FAILED", "生成密钥参数无效"), nil
		}
		return s.generateKey(p), nil
	case "account.set-password":
		var p setPasswordParams
		if sandbox.DecodeHelperDocument(params, &p) != nil {
			return bridge.Failure("VALIDATION_FAILED", "修改口令参数无效"), nil
		}
		return s.setPassword(ctx, p, request.Secret), nil
	default:
		return bridge.Failure("UNIMPLEMENTED", "不支持的账户能力动词"), nil
	}
}

// ======================== /etc/passwd 解析与 authorized_keys 安全读写 ========================

func (s *Service) lookupInteractiveUser(username string) (passwdEntry, string) {
	if !validUserPattern.MatchString(username) {
		return passwdEntry{}, "VALIDATION_FAILED"
	}
	pPath := s.PasswdPath
	if pPath == "" {
		pPath = "/etc/passwd"
	}
	f, err := os.Open(pPath)
	if err != nil {
		return passwdEntry{}, "UNAVAILABLE"
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 || parts[0] != username {
			continue
		}
		uid, err1 := strconv.Atoi(parts[2])
		gid, err2 := strconv.Atoi(parts[3])
		home := filepath.Clean(parts[5])
		shell := strings.TrimSpace(parts[6])
		if err1 != nil || err2 != nil || !filepath.IsAbs(home) || home == "/" {
			return passwdEntry{}, "VALIDATION_FAILED"
		}
		if uid != 0 && uid < 1000 {
			return passwdEntry{}, "PERMISSION_DENIED"
		}
		if strings.HasSuffix(shell, "/nologin") || strings.HasSuffix(shell, "/false") {
			return passwdEntry{}, "PRECONDITION_FAILED"
		}
		return passwdEntry{Username: username, UID: uid, GID: gid, HomeDir: home, Shell: shell}, ""
	}
	return passwdEntry{}, "VALIDATION_FAILED"
}

type parsedKeyLine struct {
	RawLine     string
	Type        string
	Bits        uint32
	Fingerprint string
	Comment     string
	Options     []string
	LineIndex   uint32
}

func keyBitsAndStrengthOK(pub ssh.PublicKey) (string, uint32, bool) {
	switch pub.Type() {
	case "ssh-dss":
		return "dsa", 1024, false
	case ssh.KeyAlgoED25519:
		return "ed25519", 256, true
	case ssh.KeyAlgoECDSA256:
		return "ecdsa", 256, true
	case ssh.KeyAlgoECDSA384:
		return "ecdsa", 384, true
	case ssh.KeyAlgoECDSA521:
		return "ecdsa", 521, true
	case ssh.KeyAlgoRSA:
		if cryptoPub, ok := pub.(ssh.CryptoPublicKey); ok {
			if rsaPub, ok := cryptoPub.CryptoPublicKey().(*rsa.PublicKey); ok {
				bits := uint32(rsaPub.N.BitLen())
				return "rsa", bits, bits >= 3072
			}
		}
		return "rsa", 0, false
	default:
		return pub.Type(), 0, false
	}
}

func authorizedKeysRevision(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func readAuthorizedKeys(entry passwdEntry) ([]byte, []parsedKeyLine, []string, string) {
	root, err := os.OpenRoot(entry.HomeDir)
	if err != nil {
		return nil, nil, nil, "UNAVAILABLE"
	}
	defer root.Close()

	f, err := root.Open(".ssh/authorized_keys")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil, ""
		}
		return nil, nil, nil, "UNAVAILABLE"
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxAuthorizedKeysBytes {
		return nil, nil, nil, "CONFLICT"
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxAuthorizedKeysBytes+1))
	if err != nil || len(raw) > maxAuthorizedKeysBytes {
		return nil, nil, nil, "UNAVAILABLE"
	}

	var keys []parsedKeyLine
	var allLines []string
	sc := bufio.NewScanner(bytes.NewReader(raw))
	var idx uint32
	for sc.Scan() {
		idx++
		line := sc.Text()
		allLines = append(allLines, line)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		pub, comment, opts, _, perr := ssh.ParseAuthorizedKey([]byte(trimmed))
		if perr != nil {
			continue
		}
		kt, bits, _ := keyBitsAndStrengthOK(pub)
		keys = append(keys, parsedKeyLine{
			RawLine:     line,
			Type:        kt,
			Bits:        bits,
			Fingerprint: ssh.FingerprintSHA256(pub),
			Comment:     comment,
			Options:     opts,
			LineIndex:   idx,
		})
	}
	return raw, keys, allLines, ""
}

func writeAuthorizedKeys(entry passwdEntry, lines []string) ([]byte, string) {
	root, err := os.OpenRoot(entry.HomeDir)
	if err != nil {
		return nil, "UNAVAILABLE"
	}
	defer root.Close()

	if err := root.Mkdir(".ssh", 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, "UNAVAILABLE"
	}
	sshDir, err := openSSHDirNoFollow(root)
	if err != nil {
		return nil, "CONFLICT"
	}
	defer sshDir.Close()
	if sshInfo, err := sshDir.Stat(); err != nil || !sshInfo.IsDir() {
		return nil, "CONFLICT"
	}
	if os.Geteuid() == 0 {
		if err := sshDir.Chown(entry.UID, entry.GID); err != nil {
			return nil, "UNAVAILABLE"
		}
	}
	if err := sshDir.Chmod(0o700); err != nil {
		return nil, "UNAVAILABLE"
	}

	var buf bytes.Buffer
	for _, line := range lines {
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	content := buf.Bytes()
	if len(content) > maxAuthorizedKeysBytes {
		return nil, "RESOURCE_EXHAUSTED"
	}

	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, "INTERNAL"
	}
	tmpRel := ".ssh/.authorized_keys.tmp." + hex.EncodeToString(nonce[:])
	tmpFile, err := root.OpenFile(tmpRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, "UNAVAILABLE"
	}
	writeErr := func() error {
		defer tmpFile.Close()
		if _, err := tmpFile.Write(content); err != nil {
			return err
		}
		if err := tmpFile.Chmod(0o600); err != nil {
			return err
		}
		if os.Geteuid() == 0 {
			if err := tmpFile.Chown(entry.UID, entry.GID); err != nil {
				return err
			}
		}
		return tmpFile.Sync()
	}()
	if writeErr != nil {
		_ = root.Remove(tmpRel)
		return nil, "UNAVAILABLE"
	}
	if err := root.Rename(tmpRel, ".ssh/authorized_keys"); err != nil {
		_ = root.Remove(tmpRel)
		return nil, "UNAVAILABLE"
	}
	if _, err := os.Stat("/sbin/restorecon"); err == nil {
		_ = exec.Command("/sbin/restorecon", "-RF", filepath.Join(entry.HomeDir, ".ssh")).Run()
	}
	return content, ""
}

// ======================== 五大 Account RPC 业务实现 ========================

func (s *Service) listKeys(user string) sandbox.CapabilityResponse {
	entry, code := s.lookupInteractiveUser(user)
	if code != "" {
		return bridge.Failure(code, "目标系统用户无效或不可登录")
	}
	raw, keys, _, rcode := readAuthorizedKeys(entry)
	if rcode != "" {
		return bridge.Failure(rcode, "无法安全读取 authorized_keys")
	}
	out := make([]*accountv1.Key, 0, len(keys))
	for _, k := range keys {
		out = append(out, &accountv1.Key{
			Type:              k.Type,
			Bits:              k.Bits,
			FingerprintSha256: k.Fingerprint,
			Comment:           k.Comment,
			LineIndex:         k.LineIndex,
		})
	}
	return bridge.Pack(&accountv1.ListKeysResponse{
		Keys:     out,
		Revision: authorizedKeysRevision(raw),
	})
}

func (s *Service) importKey(p importKeyParams) sandbox.CapabilityResponse {
	entry, code := s.lookupInteractiveUser(p.User)
	if code != "" {
		return bridge.Failure(code, "目标系统用户无效或不可登录")
	}
	trimmed := strings.TrimSpace(p.PublicKey)
	if trimmed == "" || strings.ContainsAny(trimmed, "\r\n\x00") || len(trimmed) > 8192 {
		return bridge.Failure("VALIDATION_FAILED", "公钥必须是单行合法 authorized_keys 记录")
	}
	pub, comment, opts, _, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil || len(opts) > 0 {
		return bridge.Failure("VALIDATION_FAILED", "公钥格式无效或包含禁止的 authorized_keys 选项")
	}
	kt, bits, ok := keyBitsAndStrengthOK(pub)
	if !ok {
		return bridge.Failure("VALIDATION_FAILED", "公钥算法或长度不符合安全基线（禁止 DSA 或 RSA<3072）")
	}
	fp := ssh.FingerprintSHA256(pub)

	raw, keys, lines, rcode := readAuthorizedKeys(entry)
	if rcode != "" {
		return bridge.Failure(rcode, "无法安全读取 authorized_keys")
	}
	curRev := authorizedKeysRevision(raw)
	if p.ExpectedRevision != "" && p.ExpectedRevision != curRev {
		return bridge.Failure("PRECONDITION_FAILED", "authorized_keys 版本已变化")
	}
	for _, existing := range keys {
		if existing.Fingerprint == fp {
			return bridge.Pack(&accountv1.ImportKeyResponse{
				FingerprintSha256: fp,
				Type:              existing.Type,
				Bits:              existing.Bits,
				Comment:           existing.Comment,
				Revision:          curRev,
			})
		}
	}
	if len(lines) >= maxAuthorizedKeysLines {
		return bridge.Failure("RESOURCE_EXHAUSTED", "authorized_keys 数量已达上限")
	}

	canonicalLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if comment != "" && !strings.ContainsAny(comment, "\r\n\x00") {
		canonicalLine += " " + comment
	}
	lines = append(lines, canonicalLine)
	written, wcode := writeAuthorizedKeys(entry, lines)
	if wcode != "" {
		return bridge.Failure(wcode, "写入 authorized_keys 失败")
	}
	return bridge.Pack(&accountv1.ImportKeyResponse{
		FingerprintSha256: fp,
		Type:              kt,
		Bits:              bits,
		Comment:           comment,
		Revision:          authorizedKeysRevision(written),
	})
}

func (s *Service) removeKey(ctx context.Context, p removeKeyParams) sandbox.CapabilityResponse {
	entry, code := s.lookupInteractiveUser(p.User)
	if code != "" {
		return bridge.Failure(code, "目标系统用户无效或不可登录")
	}
	if p.Fingerprint == "" || !strings.HasPrefix(p.Fingerprint, "SHA256:") || len(p.Fingerprint) > 128 {
		return bridge.Failure("VALIDATION_FAILED", "公钥指纹格式无效")
	}
	raw, keys, lines, rcode := readAuthorizedKeys(entry)
	if rcode != "" {
		return bridge.Failure(rcode, "无法安全读取 authorized_keys")
	}
	curRev := authorizedKeysRevision(raw)
	if p.ExpectedRevision != "" && p.ExpectedRevision != curRev {
		return bridge.Failure("PRECONDITION_FAILED", "authorized_keys 版本已变化")
	}

	removeIdx := make(map[uint32]bool)
	remainingStrong := 0
	for _, k := range keys {
		if k.Fingerprint == p.Fingerprint {
			removeIdx[k.LineIndex] = true
			continue
		}
		if k.Type == "ed25519" || k.Type == "ecdsa" || (k.Type == "rsa" && k.Bits >= 3072) {
			remainingStrong++
		}
	}
	if len(removeIdx) == 0 {
		return bridge.Pack(&accountv1.RemoveKeyResponse{Revision: curRev})
	}
	// 防自锁检查：删除后无剩余强公钥且密码登录不可用时拒绝删除最后一把钥匙。
	if remainingStrong == 0 && !s.passwordLoginAvailable(ctx, p.User) {
		return bridge.Failure("PRECONDITION_FAILED", "密码登录已禁用，禁止删除最后一把有效 SSH 公钥")
	}

	kept := make([]string, 0, len(lines))
	for i, line := range lines {
		if removeIdx[uint32(i+1)] {
			continue
		}
		kept = append(kept, line)
	}
	written, wcode := writeAuthorizedKeys(entry, kept)
	if wcode != "" {
		return bridge.Failure(wcode, "写入 authorized_keys 失败")
	}
	return bridge.Pack(&accountv1.RemoveKeyResponse{
		Revision: authorizedKeysRevision(written),
	})
}

func (s *Service) passwordLoginAvailable(ctx context.Context, user string) bool {
	if s.SSHD == nil {
		return false
	}
	snap, err := s.SSHD.Read(ctx, sshd.Match{User: user})
	if err != nil {
		return false
	}
	var passAuth, rootLogin string
	for _, setting := range snap.Settings {
		switch strings.ToLower(setting.GetKey()) {
		case "passwordauthentication":
			passAuth = strings.ToLower(setting.GetValue())
		case "permitrootlogin":
			rootLogin = strings.ToLower(setting.GetValue())
		}
	}
	if passAuth != "yes" {
		return false
	}
	if user == "root" && rootLogin != "yes" {
		return false
	}
	return true
}

func (s *Service) generateKey(p generateKeyParams) sandbox.CapabilityResponse {
	entry, code := s.lookupInteractiveUser(p.User)
	if code != "" {
		return bridge.Failure(code, "目标系统用户无效或不可登录")
	}
	keyType := p.Type
	if keyType == "" {
		keyType = "ed25519"
	}
	var pub ssh.PublicKey
	var pemBytes []byte
	var err error
	switch keyType {
	case "ed25519":
		pubRaw, privRaw, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return bridge.Failure("INTERNAL", "生成 Ed25519 密钥失败")
		}
		defer clear(privRaw)
		pub, err = ssh.NewPublicKey(pubRaw)
		if err == nil {
			var block *pem.Block
			block, err = ssh.MarshalPrivateKey(privRaw, "qwq-"+p.User)
			if err == nil {
				pemBytes = pem.EncodeToMemory(block)
				clear(block.Bytes)
			}
		}
	case "rsa":
		privRaw, gerr := rsa.GenerateKey(rand.Reader, 4096)
		if gerr != nil {
			return bridge.Failure("INTERNAL", "生成 RSA-4096 密钥失败")
		}
		pub, err = ssh.NewPublicKey(&privRaw.PublicKey)
		if err == nil {
			var block *pem.Block
			block, err = ssh.MarshalPrivateKey(privRaw, "qwq-"+p.User)
			if err == nil {
				pemBytes = pem.EncodeToMemory(block)
				clear(block.Bytes)
			}
		}
	default:
		return bridge.Failure("VALIDATION_FAILED", "不支持的密钥类型，仅允许 ed25519 或 rsa")
	}
	if err != nil {
		clear(pemBytes)
		return bridge.Failure("INTERNAL", "编码 SSH 密钥失败")
	}
	defer clear(pemBytes)

	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " qwq-generated"
	fp := ssh.FingerprintSHA256(pub)

	raw, _, lines, rcode := readAuthorizedKeys(entry)
	if rcode != "" {
		return bridge.Failure(rcode, "无法安全读取 authorized_keys")
	}
	curRev := authorizedKeysRevision(raw)
	if p.ExpectedRevision != "" && p.ExpectedRevision != curRev {
		return bridge.Failure("PRECONDITION_FAILED", "authorized_keys 版本已变化")
	}
	if len(lines) >= maxAuthorizedKeysLines {
		return bridge.Failure("RESOURCE_EXHAUSTED", "authorized_keys 数量已达上限")
	}
	lines = append(lines, pubLine)
	written, wcode := writeAuthorizedKeys(entry, lines)
	if wcode != "" {
		return bridge.Failure(wcode, "写入 authorized_keys 失败")
	}
	return bridge.Pack(&accountv1.GenerateKeyResponse{
		PublicKey:         pubLine,
		FingerprintSha256: fp,
		PrivateKeyPem:     append([]byte(nil), pemBytes...),
		Revision:          authorizedKeysRevision(written),
	})
}

func validPassword(secret []byte) bool {
	if len(secret) < minPasswordLen || len(secret) > maxPasswordLen {
		return false
	}
	for _, b := range secret {
		if b == 0 || b == '\n' || b == '\r' || b == ':' || b < 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}

func (s *Service) setPassword(ctx context.Context, p setPasswordParams, secret []byte) sandbox.CapabilityResponse {
	entry, code := s.lookupInteractiveUser(p.User)
	if code != "" {
		return bridge.Failure(code, "目标系统用户无效或不可登录")
	}
	if !validPassword(secret) {
		return bridge.Failure("VALIDATION_FAILED", "口令长度须在 12..128 字节之间且不含控制字符或冒号")
	}
	if s.SetPass != nil {
		if err := s.SetPass(ctx, entry.Username, secret); err != nil {
			return bridge.Failure("UNAVAILABLE", "系统口令更新失败")
		}
	} else {
		chpasswd := s.ChpasswdPath
		if chpasswd == "" {
			chpasswd = "/usr/sbin/chpasswd"
		}
		payload := make([]byte, 0, len(entry.Username)+1+len(secret)+1)
		payload = append(payload, entry.Username...)
		payload = append(payload, ':')
		payload = append(payload, secret...)
		payload = append(payload, '\n')
		defer clear(payload)

		cmd := exec.CommandContext(ctx, chpasswd, "-c", "SHA512")
		cmd.Stdin = bytes.NewReader(payload)
		if err := cmd.Run(); err != nil {
			return bridge.Failure("UNAVAILABLE", "chpasswd 执行失败")
		}
	}
	// 用用户与当前时间戳无关的静态摘要格式返回新 revision 标记（不泄露口令摘要）。
	revBytes := make([]byte, 16)
	_, _ = rand.Read(revBytes)
	return bridge.Pack(&accountv1.SetPasswordResponse{
		Revision: hex.EncodeToString(revBytes),
	})
}
