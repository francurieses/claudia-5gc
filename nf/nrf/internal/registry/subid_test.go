package registry

import (
	"regexp"
	"testing"
)

// TestNewHyphenlessIDPattern asserts the TS 29.510 §6.1.6.2.16 subscriptionId pattern.
func TestNewHyphenlessIDPattern(t *testing.T) {
	re := regexp.MustCompile(`^([0-9]{5,6}-(x3Lf57A:nid=[A-Fa-f0-9]{11}:)?)?[^-]+$`)
	for i := 0; i < 50; i++ {
		if id := NewHyphenlessID(); !re.MatchString(id) {
			t.Fatalf("id %q violates pattern", id)
		}
	}
}
