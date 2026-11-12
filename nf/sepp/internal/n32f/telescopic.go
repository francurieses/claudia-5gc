// Package n32f implements the SEPP N32-f message forwarding in TLS security
// mode: a net/http + golang.org/x/net/http2 reverse-proxy path that forwards
// HTTP/2 messages between a local NF and the peer SEPP without reformatting
// (the body is only touched when telescopic-FQDN topology hiding is enabled).
//
// Spec basis (resolved against the TS text, see docs/procedures/n32-roaming-interconnect.md):
//   - TS 29.573 §5.3.3.1: with TLS the messages are forwarded per TS 29.500 §6.1.4.3.4.
//   - TS 29.500 §6.1.4.3.1-§6.1.4.3.4: routing across PLMN (header model or telescopic FQDN).
//   - TS 23.003 §28.5.2: telescopic FQDN = <label>.<FQDN of the SEPP in the request initiating PLMN>.
//   - TS 33.501 §13.1.1.1 / §13.1.1.2: NF-SEPP TLS protection, telescopic FQDN rules a-c.
//   - TS 33.501 §13.1.2: TLS on N32-f, N32-c context correlation.
//   - TS 23.501 §6.2.17: SEPP functionality.
package n32f

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const (
	// maxDNSLabel is the maximum DNS label length. Ref: RFC 1035 §2.3.4. TS 33.501
	// §13.1.1.1 requires a single first label, so longer encodings fall back to
	// the mapping table.
	maxDNSLabel = 63
	// hashLabelPrefix marks a table-backed label (never produced by the
	// reversible encoding, whose output for a dotted FQDN contains '-').
	hashLabelPrefix = "hx"
	// hashLabelHexLen is the number of SHA-256 hex digits in a table label.
	hashLabelHexLen = 32
	// MaxMappings bounds the long-FQDN mapping table (implementation limit).
	MaxMappings = 4096
)

// ErrUnknownLabel is returned when a table-backed label has no mapping.
var ErrUnknownLabel = errors.New("n32f: telescopic: unknown label")

// Telescopic builds and resolves telescopic FQDNs for one SEPP domain.
//
// Label construction is implementation specific (TS 23.003 §28.5.2 NOTE 1):
// '-' is doubled and '.' becomes '-', which is reversible for valid FQDNs
// (a DNS label never starts or ends with '-'). TS 33.501 §13.1.1.1 step 3
// ("replacing the unique delimiter in the label with the period character and
// removing its own suffix part") is the inverse. FQDNs whose label would exceed
// 63 octets get a hash label resolved through a bounded in-memory table.
type Telescopic struct {
	domain string

	mu    sync.Mutex
	table map[string]string
	order []string
}

// NewTelescopic returns a Telescopic for the FQDN of this SEPP (the trailing
// part of every telescopic FQDN it forms, TS 23.003 §28.5.2).
func NewTelescopic(seppFQDN string) *Telescopic {
	return &Telescopic{domain: strings.ToLower(strings.TrimSuffix(seppFQDN, ".")), table: map[string]string{}}
}

// Domain returns the SEPP domain used as suffix.
func (t *Telescopic) Domain() string { return t.domain }

// Is reports whether host (no port) is a telescopic FQDN of this SEPP: a
// single label followed by the SEPP domain.
func (t *Telescopic) Is(host string) bool {
	_, ok := t.label(host)
	return ok
}

func (t *Telescopic) label(host string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	suffix := "." + t.domain
	if !strings.HasSuffix(host, suffix) {
		return "", false
	}
	l := strings.TrimSuffix(host, suffix)
	if l == "" || strings.Contains(l, ".") {
		return "", false
	}
	return l, true
}

// Encode returns the telescopic FQDN of a foreign FQDN. An already telescopic
// host is returned unchanged.
func (t *Telescopic) Encode(foreign string) (string, error) {
	foreign = strings.ToLower(strings.TrimSuffix(foreign, "."))
	if foreign == "" {
		return "", errors.New("n32f: telescopic: empty fqdn")
	}
	if t.Is(foreign) {
		return foreign, nil
	}
	l := strings.ReplaceAll(strings.ReplaceAll(foreign, "-", "--"), ".", "-")
	if len(l) > maxDNSLabel {
		sum := sha256.Sum256([]byte(foreign))
		l = hashLabelPrefix + hex.EncodeToString(sum[:])[:hashLabelHexLen]
		t.put(l, foreign)
	}
	return l + "." + t.domain, nil
}

func (t *Telescopic) put(label, fqdn string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.table[label]; ok {
		return
	}
	if len(t.order) >= MaxMappings {
		delete(t.table, t.order[0])
		t.order = t.order[1:]
	}
	t.table[label] = fqdn
	t.order = append(t.order, label)
}

// Decode returns the original FQDN of a telescopic FQDN of this SEPP
// (TS 33.501 §13.1.1.1 step 3).
func (t *Telescopic) Decode(host string) (string, error) {
	l, ok := t.label(host)
	if !ok {
		return "", fmt.Errorf("n32f: telescopic: %q is not a telescopic fqdn of %s", host, t.domain)
	}
	t.mu.Lock()
	orig, ok := t.table[l]
	t.mu.Unlock()
	if ok {
		return orig, nil
	}
	if strings.HasPrefix(l, hashLabelPrefix) && len(l) == len(hashLabelPrefix)+hashLabelHexLen && !strings.Contains(l, "-") {
		return "", ErrUnknownLabel
	}
	var b strings.Builder
	for i := 0; i < len(l); i++ {
		if l[i] != '-' {
			b.WriteByte(l[i])
			continue
		}
		if i+1 < len(l) && l[i+1] == '-' {
			b.WriteByte('-')
			i++
			continue
		}
		b.WriteByte('.')
	}
	return b.String(), nil
}
