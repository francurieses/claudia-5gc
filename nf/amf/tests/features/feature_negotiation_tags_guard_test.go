//go:build functional

// feature_negotiation_tags_guard_test.go - tag-drop guard for
// feature_negotiation.feature (REL19-2.8). The catch-all TestFeatures is not
// strict and excludes @nsmf-consumer / @namf-producer, so a scenario that lost
// (or mistyped) its runner tag would silently never run. This test fails when
// any Scenario / Scenario Outline does not carry exactly one of the two tags.
package features_test

import (
	"os"
	"strings"
	"testing"
)

func TestFeatureNegotiationScenariosAreTagged(t *testing.T) {
	raw, err := os.ReadFile("feature_negotiation.feature")
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	counts := map[string]int{}
	for i, line := range strings.Split(string(raw), "\n") {
		l := strings.TrimSpace(line)
		switch {
		case l == "" || strings.HasPrefix(l, "#"):
		case strings.HasPrefix(l, "@"):
			tags = append(tags, strings.Fields(l)...)
		case strings.HasPrefix(l, "Scenario:") || strings.HasPrefix(l, "Scenario Outline:"):
			n := 0
			for _, tg := range tags {
				if tg == "@nsmf-consumer" || tg == "@namf-producer" {
					n++
					counts[tg]++
				}
			}
			if n != 1 {
				t.Errorf("line %d: %q carries %d of {@nsmf-consumer, @namf-producer} (tags %v), want exactly 1", i+1, l, n, tags)
			}
			tags = nil
		default:
			tags = nil
		}
	}
	for _, tg := range []string{"@nsmf-consumer", "@namf-producer"} {
		if counts[tg] == 0 {
			t.Errorf("no scenario tagged %s", tg)
		}
	}
}
