package server

// jwt.go — minimal JWT HS256 implementation for the NRF token endpoint.
// No external dependencies. Only used server-side for token issuance.
// Ref: TS 33.501 §13.4.1 — OAuth2 access tokens for SBA.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud,omitempty"`
	Scope     string   `json:"scope"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

const tokenTTL = 3600 * time.Second

func issueJWT(secret []byte, issuer, subject, scope string) (string, error) {
	hdrJSON, err := json.Marshal(jwtHeader{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	payload, err := json.Marshal(jwtClaims{
		Issuer:    issuer,
		Subject:   subject,
		Scope:     scope,
		IssuedAt:  now,
		ExpiresAt: now + int64(tokenTTL.Seconds()),
	})
	if err != nil {
		return "", err
	}
	unsigned := jwtB64(hdrJSON) + "." + jwtB64(payload)
	sig := jwtSign(secret, unsigned)
	return unsigned + "." + sig, nil
}

// validateBearerToken verifies HMAC signature and expiry.
// Returns the subject NF instance ID on success.
func validateBearerToken(secret []byte, tokenStr string) (subject string, err error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT")
	}
	unsigned := parts[0] + "." + parts[1]
	if jwtSign(secret, unsigned) != parts[2] {
		return "", fmt.Errorf("invalid JWT signature")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode JWT payload: %w", err)
	}
	var c jwtClaims
	if err := json.Unmarshal(payloadBytes, &c); err != nil {
		return "", fmt.Errorf("unmarshal JWT claims: %w", err)
	}
	if time.Now().Unix() > c.ExpiresAt {
		return "", fmt.Errorf("JWT expired")
	}
	return c.Subject, nil
}

func jwtB64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func jwtSign(secret []byte, data string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
