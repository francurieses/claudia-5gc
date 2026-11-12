package server

// hnkey.go - Home Network private key resolution for SUCI Profile A / B
// (file > env > yaml). Ref: TS 33.501 §6.12.2, Annex C.3.4.

import (
	"crypto/ecdh"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// hnKeyFileMax bounds how many bytes are read from a key file.
const hnKeyFileMax = 4096

// hnLogProcedure is the canonical procedure name of the key-load log lines.
const hnLogProcedure = "SuciDeconcealment"

// Published TS 33.501 Annex C test-vector private keys (dev only, no privacy).
const (
	annexCX25519Priv = "c80949d0c3e4d73a54f8b49fbee7793c5c1de649d7e26ef8b05e0a1e0c8c12e9"
	annexCP256Priv   = "f1ab1074477ebcc7f554ea1c5fc368b1616730155e0041ac447d6301975fecda"
)

// hnKeyLen is the length in bytes of an X25519 / secp256r1 private key.
// Ref: TS 33.501 Annex C.3.
const hnKeyLen = 32

// groupWorldReadable is the permission mask flagged on a mounted key file.
const groupWorldReadable os.FileMode = 0o077

// HNKeyConfig carries the YAML-side home network key settings.
type HNKeyConfig struct {
	X25519, X25519File string // hn_private_key_x25519, hn_private_key_x25519_file
	P256, P256File     string // hn_private_key_p256, hn_private_key_p256_file
	KeyIDX25519        uint8
	KeyIDP256          uint8
}

// ResolveHNKey picks the hex private key by precedence: file named by env
// <envName>_FILE, then yamlFile, then env <envName>, then yamlValue. Returns the
// trimmed hex, the source ("file:<path>", "env", "yaml"; "" when nothing is
// configured) and a validated-format error naming keyName and source. validate
// checks the decoded 32-byte key (nil = length only). Key material is never
// included in errors. A group/world-readable file only triggers a Warn on log.
func ResolveHNKey(getenv func(string) string, keyName, yamlValue, yamlFile, envName string,
	validate func([]byte) error, log *slog.Logger) (hexKey, source string, err error) {
	path := getenv(envName + "_FILE")
	if path == "" {
		path = yamlFile
	}
	switch {
	case path != "":
		source = "file:" + path
		f, oerr := os.Open(path)
		if oerr != nil {
			return "", "", fmt.Errorf("udm: %s from %s: %w", keyName, source, oerr)
		}
		defer f.Close()
		st, serr := f.Stat()
		if serr != nil {
			return "", "", fmt.Errorf("udm: %s from %s: %w", keyName, source, serr)
		}
		raw, rerr := io.ReadAll(io.LimitReader(f, hnKeyFileMax))
		if rerr != nil {
			return "", "", fmt.Errorf("udm: %s from %s: %w", keyName, source, rerr)
		}
		hexKey = strings.TrimSpace(string(raw))
		if hexKey == "" {
			return "", "", fmt.Errorf("udm: %s from %s: file is empty", keyName, source)
		}
		if st.Mode().Perm()&groupWorldReadable != 0 {
			if log == nil {
				log = slog.Default()
			}
			log.Warn("UDM: home network key file is group/world accessible; use mode 0400",
				"nf", "UDM", "procedure", hnLogProcedure, "interface", "N/A", "direction", "IN",
				"key", keyName, "source", source, "mode", st.Mode().Perm().String(),
				"spec_ref", "TS 33.501 §6.12.2")
		}
	case getenv(envName) != "":
		source, hexKey = "env", strings.TrimSpace(getenv(envName))
	case yamlValue != "":
		source, hexKey = "yaml", strings.TrimSpace(yamlValue)
	default:
		return "", "", nil
	}
	b, derr := hex.DecodeString(hexKey)
	if derr != nil {
		return "", "", fmt.Errorf("udm: %s from %s: invalid hex encoding", keyName, source)
	}
	if len(b) != hnKeyLen {
		return "", "", fmt.Errorf("udm: %s from %s: must be %d bytes, got %d", keyName, source, hnKeyLen, len(b))
	}
	if validate != nil {
		if verr := validate(b); verr != nil {
			return "", "", fmt.Errorf("udm: %s from %s: %w", keyName, source, verr)
		}
	}
	return hexKey, source, nil
}

// validateP256Scalar rejects a zero scalar or one >= the curve order n.
func validateP256Scalar(b []byte) error {
	if _, err := ecdh.P256().NewPrivateKey(b); err != nil {
		return fmt.Errorf("not a valid P-256 scalar: %w", err)
	}
	return nil
}

// validateX25519Key rejects an all-zero key.
func validateX25519Key(b []byte) error {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	if acc == 0 {
		return errors.New("X25519 key must not be all zero")
	}
	return nil
}

// isAnnexCVector reports whether hexKey equals the published test-vector key.
func isAnnexCVector(hexKey, vector string) bool {
	a, err1 := hex.DecodeString(hexKey)
	b, err2 := hex.DecodeString(vector)
	return err1 == nil && err2 == nil && subtle.ConstantTimeCompare(a, b) == 1
}

// LoadHNKeys resolves and installs both home network private keys and the key
// identifiers. It is what cmd/udm calls at startup. Only the key id and the
// source are logged, never key material.
func (s *Server) LoadHNKeys(getenv func(string) string, c HNKeyConfig) error {
	a, srcA, err := ResolveHNKey(getenv, "hn_private_key_x25519", c.X25519, c.X25519File,
		"HN_PRIVATE_KEY_X25519", validateX25519Key, s.logger)
	if err != nil {
		return err
	}
	if err := s.WithHomeNetPrivKeyA(a); err != nil {
		return err
	}
	b, srcB, err := ResolveHNKey(getenv, "hn_private_key_p256", c.P256, c.P256File,
		"HN_PRIVATE_KEY_P256", validateP256Scalar, s.logger)
	if err != nil {
		return err
	}
	if err := s.WithHomeNetPrivKeyB(b); err != nil {
		return err
	}
	s.WithHNKeyIDs(c.KeyIDX25519, c.KeyIDP256)
	for _, k := range []struct{ hexKey, vec string }{{a, annexCX25519Priv}, {b, annexCP256Priv}} {
		if k.hexKey != "" && isAnnexCVector(k.hexKey, k.vec) {
			s.logger.Warn("UDM: SUCI Profile A/B key is the TS 33.501 Annex C published test vector - dev only, no SUPI privacy",
				"nf", "UDM", "procedure", hnLogProcedure, "interface", "N/A", "direction", "IN",
				"spec_ref", "TS 33.501 Annex C.4")
		}
	}
	if srcA != "" {
		s.logger.Info("UDM: SUCI Profile A key source", "nf", "UDM", "procedure", hnLogProcedure,
			"interface", "N/A", "direction", "IN", "source", srcA, "hn_key_id", c.KeyIDX25519,
			"spec_ref", "TS 33.501 Annex C.1")
	}
	if srcB != "" {
		s.logger.Info("UDM: SUCI Profile B key source", "nf", "UDM", "procedure", hnLogProcedure,
			"interface", "N/A", "direction", "IN", "source", srcB, "hn_key_id", c.KeyIDP256,
			"spec_ref", "TS 33.501 Annex C.1")
	}
	return nil
}
