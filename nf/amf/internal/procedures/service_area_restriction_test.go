package procedures

// service_area_restriction_test.go — Unit tests for isAllowedTA.
// Ref: TS 23.501 §5.3.4, TS 29.507 §6.1.1.2.5

import (
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// newTestHandler returns a minimal RegistrationHandler for unit testing SAR.
func newTestHandler() *RegistrationHandler {
	return &RegistrationHandler{}
}

func TestRFSPSource_PCF(t *testing.T) {
	if got := rfspSource(3, 1); got != "PCF" {
		t.Fatalf("expected PCF, got %s", got)
	}
}

func TestRFSPSource_Default(t *testing.T) {
	if got := rfspSource(0, 1); got != "OPERATOR_DEFAULT" {
		t.Fatalf("expected OPERATOR_DEFAULT, got %s", got)
	}
}

func TestRFSPSource_None(t *testing.T) {
	if got := rfspSource(0, 0); got != "NONE" {
		t.Fatalf("expected NONE, got %s", got)
	}
}

func TestIsAllowedTA_AllowedAreas_Allowed(t *testing.T) {
	h := newTestHandler()
	sar := &amfctx.ServiceAreaRestriction{
		RestrictionType: "ALLOWED_AREAS",
		AllowedTACs:     []string{"000001", "000002"},
	}
	if !h.isAllowedTA(0x000001, sar) {
		t.Fatal("TAC 0x000001 should be allowed")
	}
}

func TestIsAllowedTA_AllowedAreas_Rejected(t *testing.T) {
	h := newTestHandler()
	sar := &amfctx.ServiceAreaRestriction{
		RestrictionType: "ALLOWED_AREAS",
		AllowedTACs:     []string{"000001"},
	}
	if h.isAllowedTA(0x000002, sar) {
		t.Fatal("TAC 0x000002 should be rejected (not in allowed list)")
	}
}

func TestIsAllowedTA_AllowedAreas_EmptyListUnrestricted(t *testing.T) {
	h := newTestHandler()
	sar := &amfctx.ServiceAreaRestriction{
		RestrictionType: "ALLOWED_AREAS",
		AllowedTACs:     nil,
	}
	if !h.isAllowedTA(0xFFFFFF, sar) {
		t.Fatal("empty allowed list should be treated as unrestricted")
	}
}

func TestIsAllowedTA_NotAllowedAreas_Blocked(t *testing.T) {
	h := newTestHandler()
	sar := &amfctx.ServiceAreaRestriction{
		RestrictionType: "NOT_ALLOWED_AREAS",
		NotAllowedTACs:  []string{"000002"},
	}
	if h.isAllowedTA(0x000002, sar) {
		t.Fatal("TAC 0x000002 should be blocked by NOT_ALLOWED_AREAS")
	}
}

func TestIsAllowedTA_NotAllowedAreas_Allowed(t *testing.T) {
	h := newTestHandler()
	sar := &amfctx.ServiceAreaRestriction{
		RestrictionType: "NOT_ALLOWED_AREAS",
		NotAllowedTACs:  []string{"000002"},
	}
	if !h.isAllowedTA(0x000001, sar) {
		t.Fatal("TAC 0x000001 should be allowed (not in not-allowed list)")
	}
}

func TestIsAllowedTA_CaseInsensitive(t *testing.T) {
	h := newTestHandler()
	sar := &amfctx.ServiceAreaRestriction{
		RestrictionType: "ALLOWED_AREAS",
		AllowedTACs:     []string{"ABCDEF"}, // uppercase
	}
	// TAC 0xABCDEF — isAllowedTA formats as lowercase hex
	if !h.isAllowedTA(0xABCDEF, sar) {
		t.Fatal("case-insensitive match should succeed")
	}
}

func TestIsAllowedTA_UnknownRestrictionTypePermissive(t *testing.T) {
	h := newTestHandler()
	sar := &amfctx.ServiceAreaRestriction{
		RestrictionType: "UNKNOWN_TYPE",
	}
	if !h.isAllowedTA(0x000001, sar) {
		t.Fatal("unknown restriction type should be treated as unrestricted")
	}
}
