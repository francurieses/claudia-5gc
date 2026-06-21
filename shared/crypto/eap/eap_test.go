package eap

import "testing"

func TestIdentityRoundTrip(t *testing.T) {
	req := BuildIdentityRequest(7)
	if err := Validate(req); err != nil {
		t.Fatal(err)
	}
	if c, _ := Code(req); c != CodeRequest {
		t.Fatalf("code = %d, want Request", c)
	}
	if ty, _ := Type(req); ty != TypeIdentity {
		t.Fatalf("type = %d, want Identity", ty)
	}

	resp := BuildIdentityResponse(7, "alice@nssaa.example.com")
	if err := Validate(resp); err != nil {
		t.Fatal(err)
	}
	id, err := Identity(resp)
	if err != nil {
		t.Fatal(err)
	}
	if id != "alice@nssaa.example.com" {
		t.Fatalf("identity = %q", id)
	}
	if got, _ := Identifier(resp); got != 7 {
		t.Fatalf("identifier = %d", got)
	}
}

func TestSuccessFailure(t *testing.T) {
	s := BuildSuccess(9)
	if c, _ := Code(s); c != CodeSuccess {
		t.Fatalf("success code = %d", c)
	}
	if err := Validate(s); err != nil {
		t.Fatal(err)
	}
	f := BuildFailure(9)
	if c, _ := Code(f); c != CodeFailure {
		t.Fatalf("failure code = %d", c)
	}
	// Success/Failure have no type field.
	if _, err := Type(s); err == nil {
		t.Fatal("expected error reading type from Success")
	}
}

func TestValidateRejectsBadLength(t *testing.T) {
	if err := Validate([]byte{CodeSuccess, 1, 0, 8}); err == nil {
		t.Fatal("expected length mismatch error")
	}
}
