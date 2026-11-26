package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

func TestParseSMContextCreateError(t *testing.T) {
	rej := nas.WrapPDUSessionEstablishmentRejectBody(5, 1, 26, nil)
	b64 := base64.StdEncoding.EncodeToString(rej)
	multipartBody := "--B\r\nContent-Type: application/json\r\n\r\n" +
		`{"error":{"status":403,"cause":"DNN_DENIED"},"n1SmMsg":{"contentId":"n1"}}` +
		"\r\n--B\r\nContent-Type: application/vnd.3gpp.5gnas\r\nContent-Id: n1\r\n\r\n" + string(rej) + "\r\n--B--\r\n"

	tests := []struct {
		name, ct, body string
		wantTyped      bool
		wantCause      string
		wantReason     string
	}{
		{"json base64 n1SmMsg", "application/json", `{"error":{"status":500,"cause":"SYSTEM_FAILURE"},"n1SmMsg":"` + b64 + `"}`, true, "SYSTEM_FAILURE", ""},
		{"multipart n1SmMsg contentId", `multipart/related; boundary=B`, multipartBody, true, "DNN_DENIED", ""},
		{"json without n1SmMsg", "application/json", `{"error":{"status":500,"cause":"X"}}`, false, "X", "no n1SmMsg"},
		{"garbage", "application/json", `<<not json`, false, "", "not a JSON"},
		{"multipart garbage", `multipart/related; boundary=B`, "junk", false, "", "without a JSON part"},
		{"n1SmMsg not a reject", "application/json", `{"n1SmMsg":"` + base64.StdEncoding.EncodeToString([]byte{0x2E, 5, 1, 0xC2, 0}) + `"}`, false, "", "not a 5GSM"},
		{"dangling contentId", "multipart/related; boundary=B", "--B\r\nContent-Type: application/json\r\n\r\n{\"n1SmMsg\":{\"contentId\":\"zz\"}}\r\n--B--\r\n", false, "", "not a 5GSM"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := parseSMContextCreateError(500, tc.ct, []byte(tc.body))
			var ce *nasmsg.SMContextCreateError
			got := errors.As(err, &ce)
			if got != tc.wantTyped {
				t.Fatalf("typed = %v, want %v (err %v)", got, tc.wantTyped, err)
			}
			if !tc.wantTyped {
				if err == nil || !strings.HasPrefix(err.Error(), "smf: status 500 (") {
					t.Fatalf("plain error = %v", err)
				}
				if tc.wantReason != "" && !strings.Contains(err.Error(), tc.wantReason) {
					t.Fatalf("plain error %q lacks reason %q", err, tc.wantReason)
				}
				if tc.wantCause != "" && !strings.Contains(err.Error(), tc.wantCause) {
					t.Fatalf("plain error %q lacks cause %q", err, tc.wantCause)
				}
				return
			}
			if ce.Cause != tc.wantCause || string(ce.N1SmMsg) != string(rej) || ce.Cause5GSM() != 26 {
				t.Errorf("got %+v", ce)
			}
		})
	}
}

// TestParseSMContextCreateError_InvalidBase64Logged: a corrupt base64 n1SmMsg
// still yields the plain error, and a WARN names the decode error so the
// "not a 5GSM reject" reason is not misleading.
func TestParseSMContextCreateError_InvalidBase64Logged(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(old)

	err := parseSMContextCreateError(500, "application/json", []byte(`{"n1SmMsg":"!!not-base64!!"}`))
	var ce *nasmsg.SMContextCreateError
	if err == nil || errors.As(err, &ce) {
		t.Fatalf("want plain error, got %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "SMF n1SmMsg is not valid base64") || !strings.Contains(out, "illegal base64 data") {
		t.Fatalf("decode error not logged: %s", out)
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			t.Fatalf("log line not JSON: %s", line)
		}
		if strings.Contains(line, "valid base64") && (m["level"] != "WARN" || m["interface"] != "Nsmf" || m["direction"] != "IN") {
			t.Errorf("wrong level/interface/direction: %s", line)
		}
	}
}
