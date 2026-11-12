// Package sbi: Location header helpers.
package sbi

import (
	"net/url"
	"strings"
)

// ResourceIDFromLocationUnder returns the resource identifier of an SBI 201
// Location header value, but only when the URI path is exactly
// collectionPath + "/" + one non-empty segment. It accepts both the absolute
// form mandated by TS 29.501 §4.4.1 ("{apiRoot}/<collection>/<id>") and the
// legacy relative form, tolerates one trailing slash, and ignores query and
// fragment. It returns "" for an empty or unparsable value, a different
// collection, a missing id or additional path segments, so a Location that
// points somewhere unexpected is never mistaken for the created resource.
func ResourceIDFromLocationUnder(loc, collectionPath string) string {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	prefix := strings.TrimRight(collectionPath, "/") + "/"
	rest, ok := strings.CutPrefix(strings.TrimSuffix(u.Path, "/"), prefix)
	if !ok || rest == "" || strings.Contains(rest, "/") {
		return ""
	}
	return rest
}
