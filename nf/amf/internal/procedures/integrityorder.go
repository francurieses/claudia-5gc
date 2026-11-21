package procedures

import (
	"fmt"
	"os"
	"strings"
)

// EnvIntegrityOrder overrides nas_security.integrity_order (comma separated).
const EnvIntegrityOrder = "AMF_NAS_INTEGRITY_ORDER"

// DefaultIntegrityOrder is the default operator priority list: NIA2 > NIA1 >
// NIA3. It reproduces the pre-SEC-007 selection (NIA2, else NIA1) and adds
// NIA3 last. NIA0 is never listed: null integrity is only for unauthenticated
// emergency sessions, which the AMF does not support. Ref: TS 33.501 §5.5.2,
// §6.7.1.1
const DefaultIntegrityOrder = "NIA2, NIA1, NIA3"

// ParseIntegrityOrder parses an ordered list of NAS integrity algorithm names
// (NIA1..NIA3, case-insensitive, comma separated) into algorithm identifiers,
// highest priority first. An empty list, NIA0, an unknown name (NIA4-7) or a
// duplicate is an error. Ref: TS 33.501 §5.11.1.2, §6.7.1.1
func ParseIntegrityOrder(s string) ([]byte, error) {
	var out []byte
	seen := map[byte]bool{}
	for _, tok := range strings.Split(s, ",") {
		tok = strings.ToUpper(strings.TrimSpace(tok))
		if tok == "" {
			continue
		}
		var id byte
		switch tok {
		case "NIA1":
			id = 1
		case "NIA2":
			id = 2
		case "NIA3":
			id = 3
		case "NIA0":
			return nil, fmt.Errorf("amf: nas_security.integrity_order: NIA0 is not allowed (emergency only, TS 33.501 §5.5.2)")
		default:
			return nil, fmt.Errorf("amf: nas_security.integrity_order: unknown algorithm %q (want NIA1..NIA3)", tok)
		}
		if seen[id] {
			return nil, fmt.Errorf("amf: nas_security.integrity_order: duplicate algorithm %s", tok)
		}
		seen[id] = true
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("amf: nas_security.integrity_order: empty list")
	}
	return out, nil
}

// ResolveIntegrityOrder applies the AMF_NAS_INTEGRITY_ORDER override to the
// YAML value (empty = default) and validates the result.
func ResolveIntegrityOrder(yamlValue string) ([]byte, error) {
	if v := os.Getenv(EnvIntegrityOrder); strings.TrimSpace(v) != "" {
		yamlValue = v
	}
	if strings.TrimSpace(yamlValue) == "" {
		yamlValue = DefaultIntegrityOrder
	}
	return ParseIntegrityOrder(yamlValue)
}

// WithIntegrityOrder sets the operator-ordered integrity list (identifiers,
// highest priority first). A nil/empty slice keeps the default.
// Ref: TS 33.501 §6.7.1.1
func (h *RegistrationHandler) WithIntegrityOrder(order []byte) {
	if len(order) > 0 {
		h.integrityOrder = append([]byte(nil), order...)
	}
}

// defaultIntegrityOrderIDs is DefaultIntegrityOrder parsed once at start-up.
// The constant is valid, so a parse failure is a programming error: the zero
// value (nil) then makes every selection fail closed (registration rejected).
var defaultIntegrityOrderIDs = func() []byte {
	o, err := ParseIntegrityOrder(DefaultIntegrityOrder)
	if err != nil {
		return nil
	}
	return o
}()

// effectiveIntegrityOrder returns the configured list or the default.
func (h *RegistrationHandler) effectiveIntegrityOrder() []byte {
	if len(h.integrityOrder) > 0 {
		return h.integrityOrder
	}
	return defaultIntegrityOrderIDs
}

// IntegrityOrderNames renders algorithm identifiers as "NIA2,NIA1,NIA3".
func IntegrityOrderNames(order []byte) string {
	names := make([]string, len(order))
	for i, id := range order {
		names[i] = fmt.Sprintf("NIA%d", id)
	}
	return strings.Join(names, ",")
}

// selectIntegrityAlgorithm returns the first algorithm of order that the UE
// supports (ia indexed by NIA id). ok is false when none matches: the caller
// rejects with 5GMM #23, never falls back to NIA0.
// Ref: TS 33.501 §6.7.1.1, §6.7.2
func selectIntegrityAlgorithm(order []byte, ia [8]bool) (alg byte, ok bool) {
	for _, id := range order {
		if id != 0 && int(id) < len(ia) && ia[id] {
			return id, true
		}
	}
	return 0, false
}
