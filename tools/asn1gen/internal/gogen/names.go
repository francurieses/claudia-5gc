package gogen

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// goName converts an ASN.1 identifier to an exported Go identifier the way free5gc
// ngapType does: split at hyphens, upper-case the first rune of every part, keep the
// rest verbatim, drop the hyphens ("iE-Extensions" -> "IEExtensions", "S-NSSAI" ->
// "SNSSAI", "release-due-to-5gc-generated-reason" -> "ReleaseDueTo5gcGeneratedReason").
func goName(asn string) string {
	var b strings.Builder
	for _, part := range strings.Split(asn, "-") {
		if part == "" {
			continue
		}
		r, n := utf8.DecodeRuneInString(part)
		b.WriteRune(unicode.ToUpper(r))
		b.WriteString(part[n:])
	}
	return b.String()
}

// idName strips the conventional "id-" prefix of an identifier value ("id-AMFName" -> "AMFName").
func idName(v string) string { return strings.TrimPrefix(v, "id-") }
