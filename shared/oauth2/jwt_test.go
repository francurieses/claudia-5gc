package oauth2_test

import (
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/shared/oauth2"
)

func TestIssueAndValidateToken(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-enough!")
	claims := &oauth2.Claims{
		Issuer:    "nrf-001",
		Subject:   "amf-001",
		Audience:  []string{"SMF"},
		Scope:     "nsmf-pdusession",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}
	token, err := oauth2.IssueToken(secret, claims)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	got, err := oauth2.ValidateToken(secret, token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if got.Subject != "amf-001" {
		t.Errorf("Subject: got %q, want %q", got.Subject, "amf-001")
	}
	if got.Scope != "nsmf-pdusession" {
		t.Errorf("Scope: got %q, want %q", got.Scope, "nsmf-pdusession")
	}
}

func TestValidateToken_WrongSecret(t *testing.T) {
	secret1 := []byte("secret-one")
	secret2 := []byte("secret-two")
	c := &oauth2.Claims{
		Issuer: "nrf", Subject: "smf",
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	token, _ := oauth2.IssueToken(secret1, c)
	if _, err := oauth2.ValidateToken(secret2, token); err == nil {
		t.Error("expected error for wrong secret")
	} else if !oauth2.IsInvalidSignature(err) {
		t.Errorf("expected invalid-signature error, got: %v", err)
	}
}

func TestValidateToken_Expired(t *testing.T) {
	secret := []byte("s3cr3t")
	c := &oauth2.Claims{
		Issuer: "nrf", Subject: "udm",
		IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
	}
	token, _ := oauth2.IssueToken(secret, c)
	if _, err := oauth2.ValidateToken(secret, token); err == nil {
		t.Error("expected error for expired token")
	} else if !oauth2.IsExpired(err) {
		t.Errorf("expected expired error, got: %v", err)
	}
}

func TestValidateToken_Malformed(t *testing.T) {
	secret := []byte("s3cr3t")
	if _, err := oauth2.ValidateToken(secret, "not.a.valid.jwt.here"); err == nil {
		t.Error("expected error for malformed token with extra dot")
	}
	if _, err := oauth2.ValidateToken(secret, "onlytwoparts.here"); err == nil {
		t.Error("expected error for malformed token")
	}
}
