package drift

import (
	"fmt"
	"regexp"

	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/tools/openapi-drift/internal/oapi"
)

var uriMajor = regexp.MustCompile(`/(v[0-9]+)(?:/|$)`)

// CheckVersions compares each apiversion entry with the YAML info.version
// (apiFullVersion) and the major version in the servers URL
// (apiVersionInUri) of the spec directory loaded by l. profile selects the
// table column (apiversion.ProfileRel17 / ProfileRel19).
func CheckVersions(l *oapi.Loader, entries []apiversion.Entry, profile string) []Finding {
	var out []Finding
	for _, e := range entries {
		name := e.YAML + ".yaml"
		path := l.Dir + "/" + name
		doc, err := l.File(name)
		if err != nil {
			out = append(out, Finding{Category: CatMissingYAML, File: path, Type: string(e.Service),
				Message: fmt.Sprintf("%s not found or unreadable in spec dir", name)})
			continue
		}
		want := e.Version(profile)
		m, _ := doc.(map[string]any)
		info, _ := m["info"].(map[string]any)
		got := ""
		if v, ok := info["version"]; ok {
			got = fmt.Sprint(v)
		}
		if got != want.Full {
			out = append(out, Finding{Category: CatVersionDrift, File: path, Type: string(e.Service), Field: "apiFullVersion",
				Message: fmt.Sprintf("apiversion table (%s) has %q, YAML info.version is %q", profile, want.Full, got)})
		}
		servers, _ := m["servers"].([]any)
		gotURI := ""
		for _, sv := range servers {
			sm, _ := sv.(map[string]any)
			u, _ := sm["url"].(string)
			if mm := uriMajor.FindStringSubmatch(u); mm != nil {
				gotURI = mm[1]
				break
			}
		}
		if gotURI != want.InURI {
			out = append(out, Finding{Category: CatVersionDrift, File: path, Type: string(e.Service), Field: "apiVersionInUri",
				Message: fmt.Sprintf("apiversion table has %q, YAML servers URL has %q", want.InURI, gotURI)})
		}
	}
	SortFindings(out)
	return out
}
