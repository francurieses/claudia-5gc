package features

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/francurieses/claudia-5gc/shared/logging"
)

// TestLogNegotiationKeysOnce: slog's JSON handler does not de-duplicate keys,
// so every canonical key must appear exactly once in the raw line, with the
// correlation id taken from ctx and the base logger's nf kept.
func TestLogNegotiationKeysOnce(t *testing.T) {
	set1 := Set{}.With(1)
	var buf bytes.Buffer
	base := slog.New(slog.NewJSONHandler(&buf, nil)).With("nf", "AUSF", "nf_instance_id", "x")
	ctx := logging.WithCorrelationID(context.Background(), "01CORR")
	for _, n := range []Negotiation{
		{Interface: "Nausf", Direction: "IN", PeerNF: "AMF", SpecRef: SpecRef, Result: "OK",
			Local: set1, Peer: "3", PeerPresent: true, Negotiated: set1},
		{Interface: "Nausf", Direction: "IN", PeerNF: "AMF", SpecRef: SpecRefInvalid, Result: "REJECT",
			Cause: CauseInvalidMsgFormat, Peer: "zz", PeerPresent: true},
		{Interface: "Nudm", Direction: "OUT", PeerNF: "UDM", SpecRef: SpecRef, Result: "FAILURE"},
	} {
		LogNegotiation(ctx, base, n, "supi", "imsi-001010000000001")
	}
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("lines=%d want 3: %s", len(lines), buf.String())
	}
	keys := []string{"nf", "nf_instance_id", "procedure", "correlation_id", "interface", "direction", "spec_ref",
		"peer_nf_type", "features_local", "features_peer", "features_negotiated", "result", "supi"}
	for _, line := range lines {
		for _, k := range keys {
			if c := bytes.Count(line, []byte(`"`+k+`":`)); c != 1 {
				t.Errorf("key %q appears %d times in %s", k, c, line)
			}
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("invalid JSON %s: %v", line, err)
		}
		if rec["procedure"] != ProcedureName || rec["correlation_id"] != "01CORR" {
			t.Errorf("record %v", rec)
		}
	}
	if !bytes.Contains(lines[0], []byte(`"level":"INFO"`)) || !bytes.Contains(lines[1], []byte(`"level":"WARN"`)) ||
		!bytes.Contains(lines[1], []byte(`"cause":"INVALID_MSG_FORMAT"`)) ||
		!bytes.Contains(lines[1], []byte(`"features_peer":"zz"`)) || !bytes.Contains(lines[2], []byte(`"features_peer":"absent"`)) {
		t.Errorf("levels/fields wrong:\n%s", buf.String())
	}
}

func TestLogNegotiationNilBase(t *testing.T) {
	LogNegotiation(context.Background(), nil, Negotiation{Result: "OK"}) // must not panic
}

func TestIsTypeError(t *testing.T) {
	var v struct {
		SF   string `json:"supportedFeatures"`
		Name string `json:"name"`
	}
	tests := []struct {
		body string
		want bool
	}{
		{`{"supportedFeatures":3}`, true},
		{`{"supportedFeatures":["a"]}`, true},
		{`{"name":3}`, false},
		{`{"supportedFeatures":"ab"}`, false},
		{`{bad`, false},
	}
	for _, tc := range tests {
		err := json.NewDecoder(strings.NewReader(tc.body)).Decode(&v)
		if got := IsTypeError(err); got != tc.want {
			t.Errorf("IsTypeError(%s)=%v want %v (err=%v)", tc.body, got, tc.want, err)
		}
	}
	if IsTypeError(errors.New("x")) || IsTypeError(nil) {
		t.Error("non-JSON errors must be false")
	}
}

func TestIsTypeErrorOn(t *testing.T) {
	var v struct {
		SF   string `json:"suppFeat"`
		Name string `json:"name"`
	}
	tests := []struct {
		body string
		want bool
	}{
		{`{"suppFeat":3}`, true},
		{`{"suppFeat":{"a":1}}`, true},
		{`{"name":3}`, false},
		{`{"suppFeat":"ab"}`, false},
	}
	for _, tc := range tests {
		err := json.NewDecoder(strings.NewReader(tc.body)).Decode(&v)
		if got := IsTypeErrorOn(err, "suppFeat"); got != tc.want {
			t.Errorf("IsTypeErrorOn(%s)=%v want %v (err=%v)", tc.body, got, tc.want, err)
		}
		if IsTypeError(err) {
			t.Errorf("IsTypeError must only match supportedFeatures: %s", tc.body)
		}
	}
}

// TestIsTypeErrorEmbedded: a request struct that embeds the schema type must
// still be recognised whichever path form encoding/json reports for the
// promoted field (Go 1.26: "Base.supportedFeatures", Go 1.27: bare name).
func TestIsTypeErrorEmbedded(t *testing.T) {
	type base struct {
		SF string `json:"supportedFeatures"`
	}
	var v struct {
		base
		Name string `json:"name"`
	}
	for body, want := range map[string]bool{
		`{"supportedFeatures":7}`:     true,
		`{"supportedFeatures":["1"]}`: true,
		`{"name":3}`:                  false,
		`{"supportedFeatures":"ab"}`:  false,
	} {
		err := json.NewDecoder(strings.NewReader(body)).Decode(&v)
		if got := IsTypeError(err); got != want {
			t.Errorf("IsTypeError(%s)=%v want %v (err=%v)", body, got, want, err)
		}
	}
}

// TestLogAttrsTruncatesPeer: an attacker-controlled peer value is cut to
// MaxLoggedPeerChars with a "..." suffix; short values and "absent" are intact.
func TestLogAttrsTruncatesPeer(t *testing.T) {
	long := strings.Repeat("a", 5000)
	peerOf := func(peer string, present bool) string {
		attrs := LogAttrs(Set{}, peer, present, Set{})
		for i := 0; i+1 < len(attrs); i += 2 {
			if attrs[i] == "features_peer" {
				return attrs[i+1].(string)
			}
		}
		t.Fatal("no features_peer")
		return ""
	}
	if got := peerOf(long, true); got != strings.Repeat("a", MaxLoggedPeerChars)+"..." {
		t.Errorf("long peer logged as %d chars", len(got))
	}
	exact := strings.Repeat("b", MaxLoggedPeerChars)
	if got := peerOf(exact, true); got != exact {
		t.Errorf("boundary value altered: %q", got)
	}
	if peerOf("zz", true) != "zz" || peerOf(long, false) != PeerAbsent {
		t.Error("short/absent values must be unchanged")
	}
}

func TestPeerNFTypeFromUserAgent(t *testing.T) {
	tests := []struct{ ua, want string }{
		{"AMF-3f2c1a", "AMF"},
		{"SMF-a-b-c", "SMF"},
		{"", "FB"},
		{"curl/8.0", "FB"},
		{"amf-1", "FB"},
		{"A-1", "FB"},
		{"ABCDEFGHIJKLMNOPQ-1", "FB"},
		{"ABCDEFGHIJKLMNOP-1", "ABCDEFGHIJKLMNOP"},
		{"AMF", "AMF"},
		{"AM F-1", "FB"},
	}
	for _, tt := range tests {
		if got := PeerNFTypeFromUserAgent(tt.ua, "FB"); got != tt.want {
			t.Errorf("PeerNFTypeFromUserAgent(%q) = %q, want %q", tt.ua, got, tt.want)
		}
	}
}

func TestLogAttrsTruncatesOnRuneBoundary(t *testing.T) {
	// 63 ASCII bytes then a 3-byte rune straddling the 64-byte limit.
	peer := strings.Repeat("a", MaxLoggedPeerChars-1) + "€€"
	attrs := LogAttrs(Set{}, peer, true, Set{})
	got := attrs[3].(string)
	want := strings.Repeat("a", MaxLoggedPeerChars-1) + "..."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if strings.ContainsRune(got, '�') || !utf8.ValidString(got) {
		t.Errorf("invalid UTF-8: %q", got)
	}
}
