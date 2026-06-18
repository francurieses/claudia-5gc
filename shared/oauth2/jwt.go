// Package oauth2 provides JWT helpers for the 5GC SBA OAuth2 flow.
//
// Ref: 3GPP TS 33.501 §13.4.1 — OAuth 2.0 client_credentials grant for SBA.
//
// Token format: JWT signed with HMAC-SHA256 (HS256).
// The signing secret is shared between the NRF (issuer) and all NFs (validators)
// via configuration. In production this should be replaced with RS256 using
// the NRF PKI key pair so NFs can validate without the secret.
package oauth2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Claims holds the JWT payload for a 5GC SBA access token.
// Ref: TS 33.501 §13.4.1, RFC 9068 (JWT Profile for Access Tokens)
type Claims struct {
	Issuer    string   `json:"iss"`           // NRF instance ID
	Subject   string   `json:"sub"`           // requesting NF instance ID
	Audience  []string `json:"aud,omitempty"` // target NF type(s)
	Scope     string   `json:"scope"`         // authorized NF services
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

var errTokenExpired = errors.New("oauth2: token expired")
var errInvalidSignature = errors.New("oauth2: invalid signature")
var errMalformedToken = errors.New("oauth2: malformed token")

// IssueToken creates a signed JWT access token.
func IssueToken(secret []byte, claims *Claims) (string, error) {
	hdr, err := json.Marshal(jwtHeader{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	h := b64url(hdr) + "." + b64url(payload)
	sig := sign(secret, h)
	return h + "." + sig, nil
}

// ValidateToken parses and verifies a JWT access token.
// Returns Claims on success; error if expired, invalid signature, or malformed.
func ValidateToken(secret []byte, tokenStr string) (*Claims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errMalformedToken
	}
	h := parts[0] + "." + parts[1]
	if sign(secret, h) != parts[2] {
		return nil, errInvalidSignature
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errMalformedToken, err)
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("%w: %v", errMalformedToken, err)
	}
	if time.Now().Unix() > c.ExpiresAt {
		return nil, errTokenExpired
	}
	return &c, nil
}

// IsExpired returns true if the error indicates an expired token.
func IsExpired(err error) bool { return errors.Is(err, errTokenExpired) }

// IsInvalidSignature returns true if the error is a signature mismatch.
func IsInvalidSignature(err error) bool { return errors.Is(err, errInvalidSignature) }

func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func sign(secret []byte, data string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
