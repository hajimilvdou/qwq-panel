// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/plugins/builtin/core.xray/internal/secretmap"
	"github.com/qwq-panel/qwq/sdk/coreapi"
)

type fakeSecretRevealer struct {
	key, uuid []byte
	calls     int
	fail      int
}

func (f *fakeSecretRevealer) RevealSecret(_ context.Context, _ string, purpose string) ([]byte, error) {
	f.calls++
	if purpose != "core.xray.apply" {
		return nil, errors.New("fake purpose mismatch")
	}
	value := f.uuid
	if f.calls == 1 {
		value = f.key
	}
	if f.calls == f.fail {
		return value, errors.New("sensitive fake diagnostic")
	}
	return value, nil
}

func fakeNativeMaterials() *fakeSecretRevealer {
	return &fakeSecretRevealer{
		key:  []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))),
		uuid: []byte("00000000-0000-4000-8000-000000000001"),
	}
}

func fakeSecretMaterials(t *testing.T) *fakeSecretRevealer {
	t.Helper()
	plain := fakeNativeMaterials()
	defer clear(plain.key)
	defer clear(plain.uuid)
	return &fakeSecretRevealer{key: testConfigSecretJSON(t, plain.key), uuid: testConfigSecretJSON(t, plain.uuid)}
}

func testConfigSecretJSON(t *testing.T, value []byte) []byte {
	t.Helper()
	encoded, err := json.Marshal(string(value))
	if err != nil {
		t.Fatal("test config secret encoding failed")
	}
	return encoded
}

// TestSecretMapDecodesHostConfigJSONString 固定真实 ExtractSecrets 的 JSON 字符串契约。
// RPC 只替换传输；Load、材料校验与缓冲区清零均调用生产实现。
func TestSecretMapDecodesHostConfigJSONString(t *testing.T) {
	for _, escaped := range []bool{false, true} {
		t.Run(fmt.Sprintf("escaped=%t", escaped), func(t *testing.T) {
			plain := fakeNativeMaterials()
			defer clear(plain.key)
			defer clear(plain.uuid)
			revealer := fakeSecretMaterials(t)
			key, uuid := revealer.key, revealer.uuid
			if escaped {
				clear(key)
				key = []byte(fmt.Sprintf("\"\\u%04x%s\"", plain.key[0], plain.key[1:]))
				revealer.key = key
			}
			intent := secretIntent(t)
			materials, err := secretmap.Load(t.Context(), intent, revealer)
			if err != nil || revealer.calls != 2 || !bytes.Equal(materials.PrivateKey, plain.key) || !bytes.Equal(materials.UUIDs[intent.Inbound.Users[0].ID], plain.uuid) {
				t.Fatal("host config JSON strings were not decoded into native materials")
			}
			if !allZero(key) || !allZero(uuid) {
				t.Fatal("decoded JSON transport buffers remained in memory")
			}
			ownedKey, ownedUUID := materials.PrivateKey, materials.UUIDs[intent.Inbound.Users[0].ID]
			materials.Clear()
			if !allZero(ownedKey) || !allZero(ownedUUID) {
				t.Fatal("caller cleanup did not clear decoded materials")
			}
		})
	}
}

// TestSecretMapRejectsNonStringConfigSecrets 拒绝错误类型、裸文本和额外 JSON 值。
func TestSecretMapRejectsNonStringConfigSecrets(t *testing.T) {
	for name, input := range map[string][]byte{
		"raw text": []byte("not-json"), "null": []byte("null"), "number": []byte("42"),
		"boolean": []byte("true"), "array": []byte("[]"), "object": []byte("{}"),
		"empty string": []byte(`""`), "trailing value": []byte(`"invalid" true`),
		"oversized": bytes.Repeat([]byte("a"), 1024), "invalid material": []byte(`"not-a-private-key"`),
		"raw valid private key": fakeNativeMaterials().key,
	} {
		t.Run(name, func(t *testing.T) {
			revealer := fakeSecretMaterials(t)
			clear(revealer.key)
			revealer.key = input
			materials, err := secretmap.Load(t.Context(), secretIntent(t), revealer)
			if !errors.Is(err, secretmap.ErrUnavailable) || revealer.calls != 1 || materials.PrivateKey != nil || len(materials.UUIDs) != 0 || !allZero(input) {
				t.Fatal("invalid config secret was accepted or retained")
			}
		})
	}
}

func secretIntent(t *testing.T) *coreapi.Intent {
	t.Helper()
	intent, err := coreapi.Decode(testIntent(t))
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func TestFakeSecretMapPartialFailureClearsAllReceivedBuffers(t *testing.T) {
	revealer := fakeSecretMaterials(t)
	revealer.fail = 2
	materials, err := secretmap.Load(t.Context(), secretIntent(t), revealer)
	if !errors.Is(err, secretmap.ErrUnavailable) || materials.PrivateKey != nil || len(materials.UUIDs) != 0 {
		t.Fatal("partial reveal did not fail closed")
	}
	if !allZero(revealer.key) || !allZero(revealer.uuid) {
		t.Fatal("failure retained a received secret buffer")
	}
	if strings.Contains(fmt.Sprint(err), "sensitive") {
		t.Fatal("secret lookup exposed an upstream diagnostic")
	}
}

func TestFakeSecretMapRejectsMalformedMaterialBeforeMoreReveals(t *testing.T) {
	revealer := fakeSecretMaterials(t)
	clear(revealer.key)
	revealer.key = testConfigSecretJSON(t, []byte("not-a-private-key"))
	if _, err := secretmap.Load(t.Context(), secretIntent(t), revealer); !errors.Is(err, secretmap.ErrUnavailable) || revealer.calls != 1 || !allZero(revealer.key) {
		t.Fatal("invalid key caused further reveal or remained in memory")
	}
	revealer = fakeSecretMaterials(t)
	clear(revealer.uuid)
	revealer.uuid = testConfigSecretJSON(t, []byte("not-a-uuid"))
	if _, err := secretmap.Load(t.Context(), secretIntent(t), revealer); !errors.Is(err, secretmap.ErrUnavailable) || !allZero(revealer.key) || !allZero(revealer.uuid) {
		t.Fatal("invalid UUID was accepted or retained")
	}
}

func TestFakeSecretMapCancellationAndCallerCleanup(t *testing.T) {
	revealer := fakeSecretMaterials(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := secretmap.Load(ctx, secretIntent(t), revealer); !errors.Is(err, context.Canceled) || revealer.calls != 0 {
		t.Fatal("cancelled load revealed a secret")
	}
	materials, err := secretmap.Load(t.Context(), secretIntent(t), revealer)
	if err != nil || revealer.calls != 2 || len(materials.UUIDs) != 1 {
		t.Fatal("valid material mapping failed")
	}
	materials.Clear()
	if !allZero(revealer.key) || !allZero(revealer.uuid) {
		t.Fatal("caller cleanup did not clear owned buffers")
	}
}

func allZero(value []byte) bool {
	for _, character := range value {
		if character != 0 {
			return false
		}
	}
	return true
}
