package server

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	keyFile = "1111111111111111111111111111111111111111111111111111111111111111"
	keyEnv  = "2222222222222222222222222222222222222222222222222222222222222222"
	keyYAML = "3333333333333333333333333333333333333333333333333333333333333333"
	keyYF   = "4444444444444444444444444444444444444444444444444444444444444444"
	orderN  = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
)

func writeKey(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestResolveHNKey(t *testing.T) {
	fEnv := writeKey(t, keyFile+"\n", 0o400)
	fYAML := writeKey(t, "  "+keyYF+" \r\n", 0o400)
	tests := []struct {
		name       string
		env        map[string]string
		yamlVal    string
		yamlFile   string
		validate   func([]byte) error
		wantHex    string
		wantSrc    string
		wantErrSub string
	}{
		{"disabled", nil, "", "", nil, "", "", ""},
		{"yaml only", nil, keyYAML, "", nil, keyYAML, "yaml", ""},
		{"env over yaml", map[string]string{"K": keyEnv}, keyYAML, "", nil, keyEnv, "env", ""},
		{"yaml file over env", map[string]string{"K": keyEnv}, keyYAML, fYAML, nil, keyYF, "file:" + fYAML, ""},
		{"env file over yaml file", map[string]string{"K_FILE": fEnv}, keyYAML, fYAML, nil, keyFile, "file:" + fEnv, ""},
		{"trim newline and spaces", nil, "", fYAML, nil, keyYF, "file:" + fYAML, ""},
		{"trim env value", map[string]string{"K": " " + keyEnv + "\n"}, "", "", nil, keyEnv, "env", ""},
		{"short", map[string]string{"K": "0102"}, "", "", nil, "", "", "must be 32 bytes"},
		{"bad hex", map[string]string{"K": strings.Repeat("zz", 32)}, "", "", nil, "", "", "invalid hex"},
		{"p256 zero", map[string]string{"K": strings.Repeat("00", 32)}, "", "", validateP256Scalar, "", "", "P-256 scalar"},
		{"p256 n", map[string]string{"K": orderN}, "", "", validateP256Scalar, "", "", "P-256 scalar"},
		{"missing file", nil, "", "/nonexistent/hn.key", nil, "", "", "file:/nonexistent/hn.key"},
		{"missing env file", map[string]string{"K_FILE": "/nonexistent/x"}, keyYAML, "", nil, "", "", "file:/nonexistent/x"},
		{"bad content in file names source", nil, "", writeKey(t, "nothex\n", 0o400), nil, "", "", "invalid hex"},
		{"empty file", nil, keyYAML, writeKey(t, "\n", 0o400), nil, "", "", "empty"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, src, err := ResolveHNKey(envMap(tc.env), "hn_key", tc.yamlVal, tc.yamlFile, "K", tc.validate, nil)
			if tc.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) || !strings.Contains(err.Error(), "hn_key") {
					t.Fatalf("err = %v, want containing %q and key name", err, tc.wantErrSub)
				}
				if strings.Contains(err.Error(), keyYAML) {
					t.Fatalf("error leaks key material: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.wantHex || src != tc.wantSrc {
				t.Fatalf("got (%q,%q), want (%q,%q)", got, src, tc.wantHex, tc.wantSrc)
			}
		})
	}
}

// TestDevYAML_ProfileB loads the real dev.yaml through LoadHNKeys and drives the
// SBI handler with the TS 33.501 Annex C.4.4.1 vector and a fresh SUCI.
func TestDevYAML_ProfileB(t *testing.T) {
	raw, err := os.ReadFile("../../config/dev.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		X25519 string `yaml:"hn_private_key_x25519"`
		P256   string `yaml:"hn_private_key_p256"`
		IDA    uint8  `yaml:"hn_key_id_x25519"`
		IDB    uint8  `yaml:"hn_key_id_p256"`
	}
	if err := yaml.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	newSrv := func(udr UDRClient) *Server {
		s, err := New("127.0.0.1:0", "5G:mnc001.mcc001.3gppnetwork.org", TLSConfig{}, udr, discardLogger())
		if err != nil {
			t.Fatal(err)
		}
		if err := s.LoadHNKeys(envMap(nil), HNKeyConfig{X25519: c.X25519, P256: c.P256, KeyIDX25519: c.IDA, KeyIDP256: c.IDB}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if c.IDB != 2 {
		t.Fatalf("hn_key_id_p256 = %d, want 2", c.IDB)
	}
	priv, err := hex.DecodeString(c.P256)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ecdh.P256().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	raw65 := pk.PublicKey().Bytes()
	comp := hex.EncodeToString(append([]byte{0x02 | raw65[64]&1}, raw65[1:33]...))
	if comp != "0272da71976234ce833a6907425867b82e074d44ef907dfb4b3e21c1c2256ebcd1" {
		t.Fatalf("compressed public key = %s", comp)
	}

	const vec = "039aab8376597021e855679a9778ea0b67396e68c66df32c0f41e9acca2da9b9d146a33fc2716ac7dae96aa30a4d"
	t.Run("annex C.4.4.1 vector", func(t *testing.T) {
		udr := &recUDR{goldenUDR: goldenUDR{method: "5G_AKA"}}
		code, body := postSUCI(t, newSrv(udr), "suci-0-274-012-0000-2-2-"+vec)
		if code != 200 || udr.supi != "imsi-274012001002086" {
			t.Fatalf("status=%d supi=%q body=%s", code, udr.supi, body)
		}
	})
	t.Run("fresh profile B SUCI", func(t *testing.T) {
		udr := &recUDR{goldenUDR: goldenUDR{method: "5G_AKA"}}
		out := encryptProfileB(t, "0000000301", pk.PublicKey())
		code, body := postSUCI(t, newSrv(udr), "suci-0-001-01-0000-2-2-"+out)
		if code != 200 || udr.supi != "imsi-001010000000301" {
			t.Fatalf("status=%d supi=%q body=%s", code, udr.supi, body)
		}
	})
	t.Run("wrong key id", func(t *testing.T) {
		udr := &recUDR{goldenUDR: goldenUDR{method: "5G_AKA"}}
		code, body := postSUCI(t, newSrv(udr), "suci-0-274-012-0000-2-1-"+vec)
		if code != 403 || !strings.Contains(body, "INVALID_HN_PUBLIC_KEY_IDENTIFIER") {
			t.Fatalf("status=%d body=%s", code, body)
		}
	})
}

func capLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, nil)), &buf
}

func assertNoKeys(t *testing.T, out string, err error) {
	t.Helper()
	for _, k := range []string{keyFile, keyEnv, keyYAML, keyYF, annexCX25519Priv, annexCP256Priv} {
		if strings.Contains(out, k) || (err != nil && strings.Contains(err.Error(), k)) {
			t.Fatalf("key material leaked (%s...)", k[:4])
		}
	}
}

func TestResolveHNKey_WorldReadableWarn(t *testing.T) {
	p := writeKey(t, keyFile+"\n", 0o644)
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	lg, buf := capLogger()
	if _, _, err := ResolveHNKey(envMap(nil), "hn_key", "", p, "K", nil, lg); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "group/world accessible") || !strings.Contains(out, `"procedure":"SuciDeconcealment"`) {
		t.Fatalf("warn missing: %s", out)
	}
	assertNoKeys(t, out, nil)
	if _, _, err := ResolveHNKey(envMap(nil), "hn_key", "", writeKey(t, keyFile, 0o400), "K", nil, lg); err != nil {
		t.Fatal(err)
	}
}

func TestResolveHNKey_BadHexNoEcho(t *testing.T) {
	_, _, err := ResolveHNKey(envMap(map[string]string{"K": strings.Repeat("qz", 32)}), "hn_key", "", "", "K", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid hex encoding") {
		t.Fatalf("err = %v", err)
	}
	if strings.ContainsAny(err.Error(), "qz") || strings.Contains(err.Error(), "U+") {
		t.Fatalf("error echoes input: %v", err)
	}
}

func newKeySrv(t *testing.T, lg *slog.Logger) *Server {
	t.Helper()
	s, err := New("127.0.0.1:0", "5G:mnc001.mcc001.3gppnetwork.org", TLSConfig{}, nil, lg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLoadHNKeys_AnnexCVectorWarn(t *testing.T) {
	lg, buf := capLogger()
	s := newKeySrv(t, lg)
	err := s.LoadHNKeys(envMap(nil), HNKeyConfig{X25519: annexCX25519Priv, P256: annexCP256Priv, KeyIDX25519: 1, KeyIDP256: 2})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Count(out, "published test vector") != 2 {
		t.Fatalf("want 2 vector warns: %s", out)
	}
	assertNoKeys(t, out, nil)

	lg2, buf2 := capLogger()
	if err := newKeySrv(t, lg2).LoadHNKeys(envMap(nil), HNKeyConfig{X25519: keyYAML, P256: keyYF}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf2.String(), "published test vector") {
		t.Fatalf("unexpected warn: %s", buf2.String())
	}
	assertNoKeys(t, buf2.String(), nil)
}

func TestLoadHNKeys_X25519AllZero(t *testing.T) {
	lg, buf := capLogger()
	err := newKeySrv(t, lg).LoadHNKeys(envMap(nil), HNKeyConfig{X25519: strings.Repeat("00", 32)})
	if err == nil || !strings.Contains(err.Error(), "X25519") {
		t.Fatalf("err = %v", err)
	}
	assertNoKeys(t, buf.String(), err)
}
