package n32f

import (
	"bytes"
	"encoding/json"
	"net"
	"net/url"
	"strings"
)

// jsonFQDNKey is the NFProfile/NFService attribute carrying an FQDN
// (TS 29.510 §6.1.6.2.2); it is rewritten like a URI authority.
const jsonFQDNKey = "fqdn"

// hostMapper rewrites a host (no port).
type hostMapper func(host string) (string, error)

// splitHostPort splits an authority into host and ":port" suffix (IPv6 safe).
func splitHostPort(authority string) (host, port string) {
	if h, p, err := net.SplitHostPort(authority); err == nil {
		return h, ":" + p
	}
	return strings.Trim(authority, "[]"), ""
}

// rewriteURI rewrites the authority of an absolute http(s) URI. A relative
// reference, an IP literal or a non-URI is returned unchanged with ok=false.
// Ref: TS 29.500 §6.1.4.3.2 (callback URI / link relation URI),
// TS 33.501 §13.1.1.1 cases a-c.
func rewriteURI(s string, m hostMapper) (string, bool, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return s, false, nil
	}
	host, port := splitHostPort(u.Host)
	if net.ParseIP(host) != nil {
		return s, false, nil
	}
	nh, err := m(host)
	if err != nil {
		return s, false, err
	}
	if nh == host {
		return s, false, nil
	}
	u.Host = nh + port
	return u.String(), true, nil
}

// rewriteJSON walks a JSON document and rewrites every absolute http(s) URI
// string and every "fqdn" attribute with m. Numbers are preserved verbatim.
// It returns the (re-encoded) body and whether anything changed; when nothing
// changed the original bytes are returned untouched.
func rewriteJSON(body []byte, m hostMapper) ([]byte, bool, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return body, false, err
	}
	changed, err := walk(&doc, m)
	if err != nil || !changed {
		return body, false, err
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return body, false, err
	}
	return bytes.TrimRight(out.Bytes(), "\n"), true, nil
}

func walk(v *any, m hostMapper) (bool, error) {
	changed := false
	switch x := (*v).(type) {
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok {
				if k == jsonFQDNKey {
					nh, err := m(s)
					if err != nil {
						return false, err
					}
					if nh != s {
						x[k], changed = nh, true
					}
					continue
				}
				ns, c, err := rewriteURI(s, m)
				if err != nil {
					return false, err
				}
				if c {
					x[k], changed = ns, true
				}
				continue
			}
			c, err := walk(&e, m)
			if err != nil {
				return false, err
			}
			if c {
				x[k], changed = e, true
			}
		}
	case []any:
		for i := range x {
			if s, ok := x[i].(string); ok {
				ns, c, err := rewriteURI(s, m)
				if err != nil {
					return false, err
				}
				if c {
					x[i], changed = ns, true
				}
				continue
			}
			c, err := walk(&x[i], m)
			if err != nil {
				return false, err
			}
			changed = changed || c
		}
	}
	return changed, nil
}

// isJSON reports whether a Content-Type is JSON (application/json or +json).
func isJSON(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	return ct == "application/json" || strings.HasSuffix(ct, "+json")
}
