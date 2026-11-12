// Package features implements the SBI "supportedFeatures" bitmask of
// TS 29.571 §5.2.2 and the negotiation helpers of TS 29.500 §6.6.2.
//
// The wire form is a hex string (pattern '^[A-Fa-f0-9]*$'): feature n
// (1-based) is bit (n-1)%4 of the hex character found (n-1)/4 positions from
// the right, so features 1-4 live in the LAST character and the most
// significant character comes first. Leading zeros are optional on input.
//
// Canonical output form (stable, relied on by golden tests): lowercase hex,
// leading zeros trimmed, and the empty set rendered as "0". Rendering "0"
// rather than "" keeps the attribute non-empty on the wire. TS 29.500 §6.6.2
// makes the attribute mandatory in both directions of a negotiation, so the
// Rel-19 profile always sends a value, "0" when nothing is supported; the
// Rel-17 profile omits it instead (Request and Answer return "" there, see
// SpecLiteral and decisions D1/D2 in dev/REL19_PROGRAM.md §2).
//
// An absent attribute or the empty string carries no characters and so, per
// TS 29.571 §5.2.2 ("all features that would be represented by characters
// that are not present in the string are not supported"), means no feature
// is supported: Parse("") is the empty set.
//
// The package depends on shared/capability (never the reverse): a Catalog
// maps per-API feature numbers to capability feature IDs so a negotiated Set
// can be turned into a capability.PeerNF predicate.
package features

import (
	"errors"
	"fmt"
	"math/bits"
	"strings"
)

// MaxHexChars bounds the accepted supportedFeatures string length. 256 hex
// characters carry 1024 features, far above any real SBI API (a handful of
// bits), and keep Parse allocation bounded for hostile input.
const MaxHexChars = 256

// MaxFeatures is the highest feature number representable in a Set.
const MaxFeatures = MaxHexChars * 4

// ErrInvalid is wrapped by every Parse error.
var ErrInvalid = errors.New("invalid supportedFeatures")

// Set is an immutable-by-convention set of feature numbers (1-based). The
// zero value is the empty set. Internally the set is normalised (no trailing
// zero words), so Equal is a plain word comparison.
type Set struct {
	w []uint64 // little-endian: bit i of the stream is feature i+1
}

// Parse decodes a TS 29.571 §5.2.2 hex string. The empty string is the empty
// set. Input is case-insensitive; non-hex characters and strings longer than
// MaxHexChars are rejected with an error wrapping ErrInvalid.
func Parse(s string) (Set, error) {
	if len(s) > MaxHexChars {
		return Set{}, fmt.Errorf("features: parse: %w: length %d exceeds %d", ErrInvalid, len(s), MaxHexChars)
	}
	var out Set
	if s == "" {
		return out, nil
	}
	w := make([]uint64, (len(s)+15)/16)
	for i := 0; i < len(s); i++ {
		var v uint64
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			v = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			v = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v = uint64(c-'A') + 10
		default:
			return Set{}, fmt.Errorf("features: parse: %w: non-hex character %q at offset %d", ErrInvalid, c, i)
		}
		k := len(s) - 1 - i // nibble index from the right
		w[k/16] |= v << (uint(k%16) * 4)
	}
	out.w = w
	out.trim()
	return out, nil
}

// Validate checks s against the TS 29.571 §5.2.2 SupportedFeatures schema
// (pattern '^[A-Fa-f0-9]*$'; the empty string is valid). Unlike Parse it
// applies no length bound: an over-long string is schema-valid. A producer
// that receives a non-compliant value should reject the request with
// "400 Bad Request" (INVALID_MSG_FORMAT) per TS 29.500 §5.2.7.2; Validate
// lets the handler make that decision, since Answer alone fails closed.
func Validate(s string) error {
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return fmt.Errorf("features: validate: %w: non-hex character %q at offset %d", ErrInvalid, s[i], i)
		}
	}
	return nil
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func (s *Set) trim() {
	n := len(s.w)
	for n > 0 && s.w[n-1] == 0 {
		n--
	}
	s.w = s.w[:n]
	if n == 0 {
		s.w = nil
	}
}

// String returns the canonical form: lowercase hex, no leading zeros, "0"
// for the empty set.
func (s Set) String() string {
	if len(s.w) == 0 {
		return "0"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%x", s.w[len(s.w)-1])
	for i := len(s.w) - 2; i >= 0; i-- {
		fmt.Fprintf(&b, "%016x", s.w[i])
	}
	return b.String()
}

// Has reports whether feature n (1-based) is in the set. Out-of-range n is
// false.
func (s Set) Has(n int) bool {
	if n < 1 || n > MaxFeatures {
		return false
	}
	i := n - 1
	return i/64 < len(s.w) && s.w[i/64]&(1<<uint(i%64)) != 0
}

// With returns a copy of s that also contains feature n. Out-of-range n
// (outside 1..MaxFeatures) returns s unchanged.
func (s Set) With(n int) Set {
	if n < 1 || n > MaxFeatures {
		return s
	}
	i := n - 1
	size := len(s.w)
	if i/64 >= size {
		size = i/64 + 1
	}
	w := make([]uint64, size)
	copy(w, s.w)
	w[i/64] |= 1 << uint(i%64)
	return Set{w: w}
}

// IsEmpty reports whether the set has no features.
func (s Set) IsEmpty() bool { return len(s.w) == 0 }

// Len returns the number of features in the set.
func (s Set) Len() int {
	n := 0
	for _, x := range s.w {
		n += bits.OnesCount64(x)
	}
	return n
}

// Equal reports whether both sets contain the same features.
func (s Set) Equal(o Set) bool {
	if len(s.w) != len(o.w) {
		return false
	}
	for i := range s.w {
		if s.w[i] != o.w[i] {
			return false
		}
	}
	return true
}

// Intersect returns the features present in both a and b. Sets of different
// lengths are handled (missing high words are zero).
func Intersect(a, b Set) Set {
	n := min(len(a.w), len(b.w))
	out := Set{w: make([]uint64, n)}
	for i := 0; i < n; i++ {
		out.w[i] = a.w[i] & b.w[i]
	}
	out.trim()
	return out
}

// Intersect is the method form of the package-level Intersect.
func (s Set) Intersect(o Set) Set { return Intersect(s, o) }
