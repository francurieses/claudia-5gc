package procedures

import (
	"fmt"
	"os"
	"strings"
)

// EnvCipheringOrder overrides nas_security.ciphering_order (comma separated).
const EnvCipheringOrder = "AMF_NAS_CIPHERING_ORDER"

// DefaultCipheringOrder is the default operator priority list: NEA2 > NEA1 >
// NEA3 > NEA0. It reproduces the pre-SEC-006 selection for every UE that
// supports NEA2. Ref: TS 33.501 §6.7.1.1
const DefaultCipheringOrder = "NEA2, NEA1, NEA3, NEA0"

// ParseCipheringOrder parses an ordered list of NAS ciphering algorithm names
// (NEA0..NEA3, case-insensitive, comma separated) into algorithm identifiers,
// highest priority first. An empty list, an unknown name (including NEA4-7) or
// a duplicate is an error. Ref: TS 33.501 §5.11.1.1, §6.7.1.1
func ParseCipheringOrder(s string) ([]byte, error) {
	var out []byte
	seen := map[byte]bool{}
	for _, tok := range strings.Split(s, ",") {
		tok = strings.ToUpper(strings.TrimSpace(tok))
		if tok == "" {
			continue
		}
		var id byte
		switch tok {
		case "NEA0":
			id = 0
		case "NEA1":
			id = 1
		case "NEA2":
			id = 2
		case "NEA3":
			id = 3
		default:
			return nil, fmt.Errorf("amf: nas_security.ciphering_order: unknown algorithm %q (want NEA0..NEA3)", tok)
		}
		if seen[id] {
			return nil, fmt.Errorf("amf: nas_security.ciphering_order: duplicate algorithm %s", tok)
		}
		seen[id] = true
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("amf: nas_security.ciphering_order: empty list")
	}
	return out, nil
}

// ResolveCipheringOrder applies the AMF_NAS_CIPHERING_ORDER override to the
// YAML value (empty = default) and validates the result.
func ResolveCipheringOrder(yamlValue string) ([]byte, error) {
	if v := os.Getenv(EnvCipheringOrder); strings.TrimSpace(v) != "" {
		yamlValue = v
	}
	if strings.TrimSpace(yamlValue) == "" {
		yamlValue = DefaultCipheringOrder
	}
	return ParseCipheringOrder(yamlValue)
}

// WithCipheringOrder sets the operator-ordered ciphering list (identifiers,
// highest priority first). A nil/empty slice keeps the default.
// Ref: TS 33.501 §6.7.1.1
func (h *RegistrationHandler) WithCipheringOrder(order []byte) {
	if len(order) > 0 {
		h.cipheringOrder = append([]byte(nil), order...)
	}
}

// defaultCipheringOrderIDs is DefaultCipheringOrder parsed once at start-up.
// The constant is valid, so a parse failure is a programming error: the zero
// value (nil) then makes every selection fail closed (registration rejected).
var defaultCipheringOrderIDs = func() []byte {
	o, err := ParseCipheringOrder(DefaultCipheringOrder)
	if err != nil {
		return nil
	}
	return o
}()

// effectiveCipheringOrder returns the configured list or the default.
func (h *RegistrationHandler) effectiveCipheringOrder() []byte {
	if len(h.cipheringOrder) > 0 {
		return h.cipheringOrder
	}
	return defaultCipheringOrderIDs
}

// CipheringOrderNames renders algorithm identifiers as "NEA2,NEA1,NEA3,NEA0".
func CipheringOrderNames(order []byte) string {
	names := make([]string, len(order))
	for i, id := range order {
		names[i] = fmt.Sprintf("NEA%d", id)
	}
	return strings.Join(names, ",")
}

// CipheringOrderWarning returns a non-empty operator warning when NEA0 (null
// ciphering) precedes every real algorithm or is the only entry: UEs supporting
// a real cipher would then be served without confidentiality. Allowed for lab
// use. Ref: TS 33.501 §6.7.1.1
func CipheringOrderWarning(order []byte) string {
	if len(order) > 0 && order[0] == 0 {
		return "NEA0 listed before any real ciphering algorithm: NAS ciphering disabled for UEs that support NEA0"
	}
	return ""
}

// selectCipheringAlgorithm returns the first algorithm of order that the UE
// supports (ea indexed by NEA id). ok is false when none matches.
// Ref: TS 33.501 §6.7.1.1, §6.7.2
func selectCipheringAlgorithm(order []byte, ea [8]bool) (alg byte, ok bool) {
	for _, id := range order {
		if int(id) < len(ea) && ea[id] {
			return id, true
		}
	}
	return 0, false
}
