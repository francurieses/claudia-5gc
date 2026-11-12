package server

// udm_client_decode_test.go - decodeLcsPrivacy must not succeed silently on a
// body without usable privacy data (TS 29.500 §6.6.2 tolerant reader, but no
// empty result is cached as a policy).

import "testing"

func TestDecodeLcsPrivacy_EmptyIsError(t *testing.T) {
	for name, body := range map[string]string{
		"empty object": `{}`,
		"null":         `null`,
	} {
		if dp, err := decodeLcsPrivacy([]byte(body)); err == nil {
			t.Errorf("%s: want error, got %+v", name, dp)
		}
	}
	for name, tc := range map[string]struct{ body, want string }{
		"legacy":   {`{"locationPrivacy":"BLOCK_ALL"}`, "BLOCK_ALL"},
		"spec":     {`{"lpi":{"locationPrivacyInd":"LOCATION_ALLOWED"}}`, "ALLOW_ALL"},
		"disallow": {`{"lpi":{"locationPrivacyInd":"LOCATION_DISALLOWED"}}`, "BLOCK_ALL"},
	} {
		dp, err := decodeLcsPrivacy([]byte(tc.body))
		if err != nil || dp.LocationPrivacy != tc.want {
			t.Errorf("%s: %+v err=%v", name, dp, err)
		}
	}
}
