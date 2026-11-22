// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package consumerfiles

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/qwq-panel/qwq/internal/tlsmgr"
)

// ======================== 严格 PEM 边界必须先于任何目录或材料写入 ========================

func TestStageRejectsNoncanonicalPrivatePEM(t *testing.T) {
	original := testMaterial(t)
	key := original.PrivateKeyPEM()
	defer clear(key)
	block, rest := pem.Decode(key)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("真实私钥夹具不完整")
	}
	defer clear(block.Bytes)
	damagedPrefix := []byte("-----BEGIN " + block.Type + "-----\ninvalid-base64\n-----END " + block.Type + "-----\n")
	variants := map[string][]byte{
		"prefix":              append([]byte("unexpected-prefix\n"), key...),
		"suffix":              append(bytes.Clone(key), []byte("\nunexpected-suffix")...),
		"second_block":        append(bytes.Clone(key), key...),
		"damaged_first_block": append(damagedPrefix, key...),
		"headers":             pem.EncodeToMemory(&pem.Block{Type: block.Type, Headers: map[string]string{"X-Source": "untrusted"}, Bytes: block.Bytes}),
	}
	defer func() {
		for _, raw := range variants {
			clear(raw)
		}
	}()
	for name, raw := range variants {
		t.Run(name, func(t *testing.T) {
			store, root, _ := testStore(t)
			material, err := tlsmgr.NewMaterial(original.CertificatePEM(), raw)
			if err != nil {
				t.Fatal(err)
			}
			defer material.Clear()
			_, err = store.Stage(context.Background(), testBinding(1), material)
			requireCode(t, err, "PRIVATE_KEY_INVALID")
			if _, err := root.Stat("tls"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("不完整私钥触发了目录或材料写入")
			}
		})
	}
}

func TestStageAcceptsWhitespaceWrappedPrivatePEM(t *testing.T) {
	store, _, _ := testStore(t)
	original := testMaterial(t)
	key := original.PrivateKeyPEM()
	defer clear(key)
	wrapped := append([]byte("\t\n"), key...)
	wrapped = append(wrapped, '\n', ' ', '\t')
	defer clear(wrapped)
	material, err := tlsmgr.NewMaterial(original.CertificatePEM(), wrapped)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Clear()
	proof := stage(t, store, testBinding(1), material)
	requireLoaded(t, store, proof)
}

func TestStageRejectsCertificateOutsideConsumerSNI(t *testing.T) {
	store, root, _ := testStore(t)
	binding := testBinding(1)
	binding.Consumer.SNI = "uncovered.example"
	_, err := store.Stage(context.Background(), binding, testMaterial(t))
	requireCode(t, err, "SAN_MISMATCH")
	if _, err := root.Stat("tls"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("不覆盖消费者域名的证书触发了材料写入")
	}
}

// ======================== 可信证明只在私有账本序列化；常见日志表示均脱敏 ========================

func TestProofLogRepresentationsRedactMaterialDigests(t *testing.T) {
	store, _, _ := testStore(t)
	proof := stage(t, store, testBinding(1), testMaterial(t))
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	logger.Info("受控证明", "proof", proof)
	for _, representation := range []string{fmt.Sprint(proof), fmt.Sprintf("%#v", proof), output.String()} {
		if strings.Contains(representation, proof.PrivateKeySHA256) || strings.Contains(representation, proof.FullchainSHA256) ||
			strings.Contains(representation, proof.Binding.CertificateID) || !strings.Contains(representation, "REDACTED") {
			t.Fatal("证明的日志表示泄漏内部身份或材料摘要")
		}
	}
}
