// SPDX-License-Identifier: AGPL-3.0-only

package account

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/capability/sshd"
	"github.com/qwq-panel/qwq/internal/pluginhost/hostsvc"
	"github.com/qwq-panel/qwq/internal/sandbox"
	accountv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/account/v1"
	sshdv1 "github.com/qwq-panel/qwq/sdk/gen/qwq/capability/sshd/v1"
	"golang.org/x/crypto/ssh"
)

// ======================== 账户能力与 SSHD 恢复守卫单元测试 ========================

type fakeSSHDReader struct {
	passwordAuth string
	rootLogin    string
}

func (f fakeSSHDReader) Read(context.Context, sshd.Match) (sshd.Snapshot, error) {
	return sshd.Snapshot{
		Settings: []*sshdv1.Setting{
			{Key: "passwordauthentication", Value: f.passwordAuth},
			{Key: "permitrootlogin", Value: f.rootLogin},
		},
	}, nil
}

type helperAdapter struct{ svc *Service }

func (a helperAdapter) Call(ctx context.Context, req sandbox.CapabilityRequest) (sandbox.CapabilityResponse, error) {
	return a.svc.Run(ctx, req)
}

func makeTestAccountEnv(t *testing.T, passAuth string) (*Service, string, string) {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "alice")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	passwd := filepath.Join(dir, "passwd")
	content := "alice:x:1001:1001:Alice:" + home + ":/bin/bash\n" +
		"daemonuser:x:999:999:Sys:/var/empty:/usr/sbin/nologin\n"
	if err := os.WriteFile(passwd, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := NewService(fakeSSHDReader{passwordAuth: passAuth, rootLogin: "prohibit-password"})
	svc.PasswdPath = passwd
	return svc, "alice", home
}

func makeEd25519AuthorizedLine(t *testing.T, comment string) (string, string) {
	t.Helper()
	pubRaw, privRaw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clear(privRaw)
	pub, err := ssh.NewPublicKey(pubRaw)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + comment, ssh.FingerprintSHA256(pub)
}

func makeRSA2048AuthorizedLine(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

func TestAccountKeysStrengthAntiLockoutAndRecoveryGuard(t *testing.T) {
	svc, user, home := makeTestAccountEnv(t, "no")
	fwd := Forwarder{Helper: helperAdapter{svc: svc}}

	// 1. 初始无密钥时 RecoveryGuard 必须拒绝。
	if err := svc.RecoveryGuard().Check(t.Context(), user, "127.0.0.1", sshd.Snapshot{}); err == nil {
		t.Fatal("缺少 authorized_keys 时 RecoveryGuard 应拒绝")
	}

	// 2. 拒绝弱 RSA-2048 公钥。
	weakRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "account", Method: "ImportKey", PluginID: "security.basic",
		Request: &accountv1.ImportKeyRequest{User: user, PublicKey: makeRSA2048AuthorizedLine(t)},
	})
	if err != nil || weakRes.Error == nil || weakRes.Error.Code != "VALIDATION_FAILED" {
		t.Fatalf("RSA-2048 应被拒绝：res=%+v err=%v", weakRes, err)
	}

	// 3. 拒绝低 UID 系统伪账号。
	sysRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "account", Method: "ListKeys", PluginID: "security.basic",
		Request: &accountv1.ListKeysRequest{User: "daemonuser"},
	})
	if err != nil || sysRes.Error == nil || sysRes.Error.Code != "PERMISSION_DENIED" {
		t.Fatalf("低 UID 伪账号应被拒绝：res=%+v err=%v", sysRes, err)
	}

	// 4. 导入 Ed25519 公钥并验证幂等重复导入与 RecoveryGuard 放行。
	line1, fp1 := makeEd25519AuthorizedLine(t, "admin@laptop")
	imp1, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "account", Method: "ImportKey", PluginID: "security.basic",
		Request: &accountv1.ImportKeyRequest{User: user, PublicKey: line1},
	})
	if err != nil || imp1.Error != nil {
		t.Fatalf("导入 Ed25519 失败：res=%+v err=%v", imp1, err)
	}
	rev1 := imp1.Response.(*accountv1.ImportKeyResponse).GetRevision()
	if rev1 == "" || imp1.Response.(*accountv1.ImportKeyResponse).GetFingerprintSha256() != fp1 {
		t.Fatalf("导入返回不符：%+v", imp1.Response)
	}
	if err := svc.RecoveryGuard().Check(t.Context(), user, "127.0.0.1", sshd.Snapshot{}); err != nil {
		t.Fatalf("有效 Ed25519 存在时 RecoveryGuard 应放行：%v", err)
	}

	// 幂等重复导入同一公钥保持 revision 不变。
	impDup, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "account", Method: "ImportKey", PluginID: "security.basic",
		Request: &accountv1.ImportKeyRequest{User: user, PublicKey: line1, ExpectedRevision: rev1},
	})
	if err != nil || impDup.Error != nil || impDup.Response.(*accountv1.ImportKeyResponse).GetRevision() != rev1 {
		t.Fatalf("重复导入应幂等返回同 revision：res=%+v err=%v", impDup, err)
	}

	// 5. 密码登录关闭时删除最后一把公钥必须返回 PRECONDITION_FAILED 防自锁。
	remBlocked, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "account", Method: "RemoveKey", PluginID: "security.basic",
		Request: &accountv1.RemoveKeyRequest{User: user, FingerprintSha256: fp1, ExpectedRevision: rev1},
	})
	if err != nil || remBlocked.Error == nil || remBlocked.Error.Code != "PRECONDITION_FAILED" {
		t.Fatalf("删除最后一把钥匙应触发防自锁：res=%+v err=%v", remBlocked, err)
	}

	// 6. GenerateKey 生成第二把钥匙后再删除第一把应成功。
	genRes, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "account", Method: "GenerateKey", PluginID: "security.basic",
		Request: &accountv1.GenerateKeyRequest{User: user, Type: "ed25519", ExpectedRevision: rev1},
	})
	if err != nil || genRes.Error != nil {
		t.Fatalf("GenerateKey 失败：res=%+v err=%v", genRes, err)
	}
	genResp := genRes.Response.(*accountv1.GenerateKeyResponse)
	if len(genResp.GetPrivateKeyPem()) == 0 || !strings.HasPrefix(genResp.GetFingerprintSha256(), "SHA256:") || genResp.GetRevision() == rev1 {
		t.Fatalf("GenerateKey 返回不完整：fp=%s rev=%s pemLen=%d", genResp.GetFingerprintSha256(), genResp.GetRevision(), len(genResp.GetPrivateKeyPem()))
	}

	remOK, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "account", Method: "RemoveKey", PluginID: "security.basic",
		Request: &accountv1.RemoveKeyRequest{User: user, FingerprintSha256: fp1, ExpectedRevision: genResp.GetRevision()},
	})
	if err != nil || remOK.Error != nil {
		t.Fatalf("保留另一把钥匙时删除第一把应成功：res=%+v err=%v", remOK, err)
	}

	// 7. 若 authorized_keys 权限被篡改为组可写（0620），RecoveryGuard 必须拒绝。
	if err := os.Chmod(filepath.Join(home, ".ssh", "authorized_keys"), 0o620); err != nil {
		t.Fatal(err)
	}
	if err := svc.RecoveryGuard().Check(t.Context(), user, "127.0.0.1", sshd.Snapshot{}); err == nil {
		t.Fatal("组可写 authorized_keys 时 RecoveryGuard 必须拒绝")
	}
}

func TestAccountSetPasswordStdinAndSecretZeroing(t *testing.T) {
	svc, user, _ := makeTestAccountEnv(t, "yes")
	var capturedUser string
	var capturedPass []byte
	svc.SetPass = func(_ context.Context, username string, password []byte) error {
		capturedUser = username
		capturedPass = append([]byte(nil), password...)
		return nil
	}

	wantPass := "VeryStrongPassword!2026"
	encoded, _ := json.Marshal(wantPass)
	fwd := Forwarder{
		Helper: helperAdapter{svc: svc},
		RevealSecret: func(_ context.Context, _ hostsvc.CapabilityCall, ref string) ([]byte, error) {
			if ref != "sec_00000000000000000000000099" {
				return nil, os.ErrNotExist
			}
			return append([]byte(nil), encoded...), nil
		},
	}

	res, err := fwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "account", Method: "SetPassword", PluginID: "security.basic",
		Request: &accountv1.SetPasswordRequest{User: user, SecretRef: "sec_00000000000000000000000099"},
	})
	if err != nil || res.Error != nil {
		t.Fatalf("SetPassword 失败：res=%+v err=%v", res, err)
	}
	if capturedUser != user || !bytes.Equal(capturedPass, []byte(wantPass)) {
		t.Fatalf("SetPassword 未通过受控通道传递正确口令：user=%q", capturedUser)
	}

	// 过短口令必须被宿主直接拦截。
	shortFwd := Forwarder{
		Helper: helperAdapter{svc: svc},
		RevealSecret: func(context.Context, hostsvc.CapabilityCall, string) ([]byte, error) {
			return []byte(`"short"`), nil
		},
	}
	badRes, err := shortFwd.Forward(t.Context(), hostsvc.CapabilityCall{
		Service: "account", Method: "SetPassword", PluginID: "security.basic",
		Request: &accountv1.SetPasswordRequest{User: user, SecretRef: "sec_00000000000000000000000099"},
	})
	if err != nil || badRes.Error == nil || badRes.Error.Code != "VALIDATION_FAILED" {
		t.Fatalf("弱口令应返回 VALIDATION_FAILED：res=%+v err=%v", badRes, err)
	}
}
