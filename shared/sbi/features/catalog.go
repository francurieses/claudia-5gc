// Catalog of per-API supportedFeatures bits and the TS 29.500 §6.6.2
// negotiation helpers built on it.

package features

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// Entry describes one feature bit of one SBI API (the "Supported Features"
// table of the owning TS 29.5xx API clause).
type Entry struct {
	Number    int                // 1-based feature number
	Name      string             // feature name as in the spec table
	Release   capability.Release // release that introduced the feature
	FeatureID string             // optional capability feature ID gating the bit

	// Mandatory records "M" in the M/O column of the spec table: mandatory to
	// implement for an implementation of that API version. It is informational;
	// the bit is still negotiated like any other.
	Mandatory bool

	// Implemented says this NF actually implements the behaviour behind the
	// bit. Supported offers an entry only if Implemented is true, so
	// transcribing a spec table never advertises behaviour we lack. The zero
	// value (false) fails closed.
	Implemented bool
}

// Catalog is the immutable feature table of one SBI API.
type Catalog struct {
	entries []Entry // sorted by Number
	byNum   map[int]Entry
	byID    map[string]Entry
}

// NewCatalog validates and builds a Catalog. Numbers must lie in
// 1..MaxFeatures and be unique, names non-empty, releases non-zero, and a
// non-empty FeatureID may appear only once.
func NewCatalog(entries ...Entry) (*Catalog, error) {
	c := &Catalog{
		byNum: make(map[int]Entry, len(entries)),
		byID:  make(map[string]Entry),
	}
	for _, e := range entries {
		switch {
		case e.Number < 1 || e.Number > MaxFeatures:
			return nil, fmt.Errorf("features: new catalog: feature number %d out of range 1..%d", e.Number, MaxFeatures)
		case e.Name == "":
			return nil, fmt.Errorf("features: new catalog: feature %d has no name", e.Number)
		case e.Release <= 0:
			return nil, fmt.Errorf("features: new catalog: feature %d (%s) has no release", e.Number, e.Name)
		}
		if _, dup := c.byNum[e.Number]; dup {
			return nil, fmt.Errorf("features: new catalog: duplicate feature number %d", e.Number)
		}
		if e.FeatureID != "" {
			if _, dup := c.byID[e.FeatureID]; dup {
				return nil, fmt.Errorf("features: new catalog: duplicate feature ID %q", e.FeatureID)
			}
			c.byID[e.FeatureID] = e
		}
		c.byNum[e.Number] = e
		c.entries = append(c.entries, e)
	}
	sort.Slice(c.entries, func(i, j int) bool { return c.entries[i].Number < c.entries[j].Number })
	return c, nil
}

// MustCatalog is NewCatalog that panics on error; for package initialisers.
func MustCatalog(entries ...Entry) *Catalog {
	c, err := NewCatalog(entries...)
	if err != nil {
		panic(err)
	}
	return c
}

// Entries returns a copy of the entries sorted by Number. A nil Catalog has
// none.
func (c *Catalog) Entries() []Entry {
	if c == nil {
		return nil
	}
	return append([]Entry(nil), c.entries...)
}

// Lookup returns the entry for feature number n.
func (c *Catalog) Lookup(n int) (Entry, bool) {
	if c == nil {
		return Entry{}, false
	}
	e, ok := c.byNum[n]
	return e, ok
}

// baselineRelease is the release a nil *capability.Profile ("no profile
// loaded") behaves as: the frozen Rel-17 baseline.
const baselineRelease = capability.Rel17

// SpecLiteral reports whether p selects the spec-literal TS 29.500 §6.6.2
// behaviour: true iff p is non-nil and its release is Rel-19 or later. It is
// the single D1/D2 switch of the decision log (dev/REL19_PROGRAM.md §2).
//
// Rationale: TS 29.500 §6.6.2 makes supportedFeatures mandatory in both
// directions of a negotiation (consumer "shall include", producer "shall
// include"), so the Rel-19 profile always sends it ("0" when empty). The
// Rel-17 profile is the frozen baseline and must stay byte-identical on the
// wire to the pre-negotiation behaviour, so it omits the attribute when there
// is nothing to say. A nil profile behaves as Rel-17.
func SpecLiteral(p *capability.Profile) bool {
	return p != nil && p.Release() >= capability.Rel19
}

func profileRelease(p *capability.Profile) capability.Release {
	if p == nil {
		return baselineRelease
	}
	return p.Release()
}

// Supported returns the set of catalog features this NF offers under p.
//
// An entry is offered when Implemented is true, its Release is <= the profile
// release and, if it has a FeatureID, p.Gate(FeatureID) passes (feature
// registered, enabled and within the profile release). Entries without a
// FeatureID are baseline features offered whenever the release allows. A nil
// profile behaves as Rel-17 (and gates every FeatureID off); a nil catalog
// offers nothing.
func (c *Catalog) Supported(p *capability.Profile) Set {
	var out Set
	if c == nil {
		return out
	}
	rel := profileRelease(p)
	for _, e := range c.entries {
		if !e.Implemented || e.Release > rel {
			continue
		}
		if e.FeatureID != "" && !p.Gate(e.FeatureID) {
			continue
		}
		out = out.With(e.Number)
	}
	return out
}

// Request is the consumer side: the supportedFeatures value to put in a
// request or to advertise per NFService in the NF profile (TS 29.500 §6.6.2;
// decision D2, dev/REL19_PROGRAM.md §2).
//
// Under the Rel-19 profile (SpecLiteral) it returns Supported(p).String(),
// "0" when nothing is offered, never "": the consumer "shall include" the
// attribute in the HTTP PUT or POST creating the resource. Under the Rel-17
// profile or a nil profile it returns "" and the caller omits the attribute
// (an omitempty string field), keeping the legacy wire form byte-identical.
// For an HTTP GET the "supported-features" query parameter is optional ("may
// include") and the caller may skip it under either profile.
func Request(c *Catalog, p *capability.Profile) string {
	if !SpecLiteral(p) {
		return ""
	}
	return c.Supported(p).String()
}

// Answer is the producer side: given the consumer's supportedFeatures string
// it returns the value to put in the response and the negotiated Set.
//
// TS 29.500 §6.6.2: "The HTTP server shall determine the supported features
// for the corresponding resource by comparing the supported features
// indicated by the client with the supported features the HTTP server
// supports. Features that are supported both by the client and the server are
// supported for that resource. The HTTP server shall include the attribute
// ... indicating those features in the representation of the resource it
// returns". The result is the intersection; an empty one is "0" (schema-valid
// per TS 29.571 §5.2.2).
//
// Decision D1 (dev/REL19_PROGRAM.md §2): when peer is "" the answer depends
// on the profile. Go omitempty string fields cannot tell an absent attribute
// from an empty string, so both are treated alike. Under the Rel-17 profile
// or a nil profile the answer is "" and the caller omits supportedFeatures
// (legacy wire behaviour); under the Rel-19 profile (SpecLiteral) it is "0".
// A non-empty peer value, including "0", is answered with the intersection
// under both profiles.
//
// Bits we do not offer, including bits unknown to the catalog, drop out of
// the intersection ("Unknown attributes and values shall be ignored",
// §6.6.2). A schema-valid but over-long string (more than MaxHexChars) is
// still honoured: only its rightmost MaxHexChars characters can intersect a
// catalog. A non-hex value violates the schema; TS 29.500 §5.2.7.2 says the
// producer "should reject the request ... 400 Bad Request
// (INVALID_MSG_FORMAT)", which is the handler's call (use Validate). Answer
// itself fails closed and negotiates nothing.
func Answer(c *Catalog, p *capability.Profile, peer string) (string, Set) {
	if peer == "" && !SpecLiteral(p) {
		return "", Set{}
	}
	neg := Intersect(c.Supported(p), parsePeer(peer))
	return neg.String(), neg
}

// Accept is the consumer side of the response: it computes the features
// negotiated for a resource from what this NF offered and what the producer
// answered (TS 29.500 §6.6.2).
//
//   - R11: bits never offered are ignored (result is offer ∩ answer).
//   - R12: an absent/empty answer negotiates nothing, without error.
//   - R13: a non-hex answer fails closed: Set{} and an error wrapping
//     ErrInvalid, so the caller logs result=FAILURE without failing the
//     procedure.
//   - R14: a consumer that sent nothing (empty offer) negotiates nothing
//     whatever the answer.
//
// offer is our own value (as returned by Request) and is parsed strictly; an
// over-long valid answer is tolerated like a peer value in Answer.
func Accept(offer, answer string) (Set, error) {
	off, err := Parse(offer)
	if err != nil {
		return Set{}, fmt.Errorf("features: accept: offer: %w", err)
	}
	if off.IsEmpty() {
		return Set{}, nil
	}
	if err := Validate(answer); err != nil {
		return Set{}, fmt.Errorf("features: accept: answer: %w", err)
	}
	return Intersect(off, parsePeer(answer)), nil
}

// AcceptAnswer is Accept plus the validation Accept skips when the offer is
// empty (R14 skips the negotiation, not the check): a malformed non-empty
// answer is always reported, even when the consumer offered "0" or nothing, so
// the caller logs result=FAILURE. A valid answer to an empty offer negotiates
// nothing. Accept itself is unchanged.
func AcceptAnswer(offer, answer string) (Set, error) {
	neg, err := Accept(offer, answer)
	if err != nil {
		return Set{}, err
	}
	if answer != "" {
		if verr := Validate(answer); verr != nil {
			return Set{}, fmt.Errorf("features: accept: answer: %w", verr)
		}
	}
	return neg, nil
}

// parsePeer decodes a peer supportedFeatures value for negotiation: invalid
// input is the empty set, over-long valid input keeps its low MaxHexChars
// characters (higher features cannot exist in any Catalog).
func parsePeer(s string) Set {
	if Validate(s) != nil {
		return Set{}
	}
	if len(s) > MaxHexChars {
		s = s[len(s)-MaxHexChars:]
	}
	ps, err := Parse(s)
	if err != nil {
		return Set{}
	}
	return ps
}

// PeerNF returns a capability.PeerNF whose Negotiated(f) is true iff the
// catalog maps f.ID to a feature number present in negotiated. A nil
// catalog negotiates nothing.
func PeerNF(c *Catalog, negotiated Set) capability.PeerNF {
	return capability.PeerNF{Negotiated: func(f capability.Feature) bool {
		if c == nil || f.ID == "" {
			return false
		}
		e, ok := c.byID[f.ID]
		return ok && negotiated.Has(e.Number)
	}}
}

// RawString extracts the string value of a supportedFeatures-typed attribute
// received as raw JSON, so that a peer answer of the wrong JSON type is a
// negotiation error (R13, result=FAILURE) instead of failing the decode of the
// whole response. Absent or null -> "" and no error; a non-string value (number,
// array, object, bool) -> error wrapping ErrInvalid. Ref: TS 29.571 §5.2.2
// (SupportedFeatures is a string), TS 29.500 §6.6.2.
func RawString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("features: supportedFeatures is not a string: %w", ErrInvalid)
	}
	return s, nil
}
