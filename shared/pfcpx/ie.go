package pfcpx

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/wmnsk/go-pfcp/ie"
)

// ErrInvalidType is returned when a parser is given an IE of another type.
var ErrInvalidType = errors.New("pfcpx: unexpected IE type")

// ErrInvalidLength is returned when an IE payload is too short for its type.
var ErrInvalidLength = errors.New("pfcpx: invalid IE length")

// lastKnownByGoPFCP is the highest IE type go-pfcp v0.0.14 defines.
const lastKnownByGoPFCP uint16 = 271

// Name returns the TS 29.244 Table 8.1.2-1 name of an IE type above 271, or
// "" if the type is unassigned or above the table (see lastSpecType).
func Name(t uint16) string { return ieNames[t] }

// KnownByGoPFCP reports whether go-pfcp itself defines IE type t.
func KnownByGoPFCP(t uint16) bool { return t <= lastKnownByGoPFCP }

// IsGrouped reports whether extension IE type t is a grouped IE per
// TS 29.244 Table 8.1.2-1 (groupedTypes in types.go).
func IsGrouped(t uint16) bool { _, ok := groupedTypes[t]; return ok }

// NewRaw builds an IE of any type from its payload (ie.New).
func NewRaw(t uint16, payload []byte) *ie.IE { return ie.New(t, payload) }

// NewGrouped builds a grouped IE of type t. For types go-pfcp knows it uses
// ie.NewGroupedIE; for the others it serialises the children into the payload
// because go-pfcp only marshals ChildIEs for types in its own grouped map.
// Children are kept in the given order (spec order matters to peers).
func NewGrouped(t uint16, children ...*ie.IE) (*ie.IE, error) {
	if KnownByGoPFCP(t) {
		return ie.NewGroupedIE(t, children...), nil
	}
	var payload []byte
	for _, c := range children {
		b, err := c.Marshal()
		if err != nil {
			return nil, fmt.Errorf("pfcpx: marshal child %d of %d: %w", c.Type, t, err)
		}
		payload = append(payload, b...)
	}
	g := ie.New(t, payload)
	g.ChildIEs = children
	return g, nil
}

// ParseGrouped parses the payload of a grouped IE into its child IEs. It works
// for any type, including those go-pfcp does not know, and rejects truncated
// children.
func ParseGrouped(i *ie.IE) ([]*ie.IE, error) {
	if i == nil {
		return nil, fmt.Errorf("pfcpx: parse grouped: %w", ErrInvalidLength)
	}
	kids, err := ie.ParseMultiIEs(i.Payload)
	if err != nil {
		return nil, fmt.Errorf("pfcpx: parse grouped type %d: %w", i.Type, err)
	}
	return kids, nil
}

// FindChild returns the first child of type t in a grouped IE, or nil.
func FindChild(i *ie.IE, t uint16) (*ie.IE, error) {
	kids, err := ParseGrouped(i)
	if err != nil {
		return nil, err
	}
	for _, k := range kids {
		if k.Type == t {
			return k, nil
		}
	}
	return nil, nil
}

func check(i *ie.IE, t uint16, min int) error {
	if i == nil || i.Type != t {
		return fmt.Errorf("pfcpx: type %d: %w", t, ErrInvalidType)
	}
	if len(i.Payload) < min {
		return fmt.Errorf("pfcpx: type %d len %d: %w", t, len(i.Payload), ErrInvalidLength)
	}
	return nil
}

// NewRATType builds a RAT Type IE (TS 29.244 §8.2.186): one octet holding a
// Table 8.2.186-1 value (e.g. 10 = NR). The IE is extendable, so the parser
// reads octet 5 and ignores any trailing octets.
func NewRATType(v uint8) *ie.IE { return ie.New(RATType, []byte{v}) }

// RATTypeValue parses a RAT Type IE.
func RATTypeValue(i *ie.IE) (uint8, error) {
	if err := check(i, RATType, 1); err != nil {
		return 0, err
	}
	return i.Payload[0], nil
}

// NewMaximumReceiveUnit builds a Maximum Receive Unit IE (TS 29.244 §8.2.195):
// fixed length 2, the link MTU as a two-octet binary integer.
func NewMaximumReceiveUnit(v uint16) *ie.IE {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return ie.New(MaximumReceiveUnit, b)
}

// MaximumReceiveUnitValue parses a Maximum Receive Unit IE.
func MaximumReceiveUnitValue(i *ie.IE) (uint16, error) {
	if err := check(i, MaximumReceiveUnit, 2); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(i.Payload), nil
}

// NewGroupID builds a Group Id IE (TS 29.244 §8.2.198): a variable-length
// octet string, a globally unique group identifier (may use the TS 29.571
// NfInstanceId encoding).
func NewGroupID(id []byte) *ie.IE { return ie.New(GroupID, append([]byte(nil), id...)) }

// GroupIDValue parses a Group ID IE.
func GroupIDValue(i *ie.IE) ([]byte, error) {
	if err := check(i, GroupID, 1); err != nil {
		return nil, err
	}
	return append([]byte(nil), i.Payload...), nil
}

// NewURI builds a URI IE (TS 29.244 §8.2.244): a variable-length octet string
// holding an RFC 3986 URI.
func NewURI(s string) *ie.IE { return ie.New(URI, []byte(s)) }

// URIValue parses a URI IE.
func URIValue(i *ie.IE) (string, error) {
	if err := check(i, URI, 1); err != nil {
		return "", err
	}
	return string(i.Payload), nil
}
