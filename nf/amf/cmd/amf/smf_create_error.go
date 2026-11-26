package main

// smf_create_error.go - parsing of the SmContextCreateError answer of
// Nsmf_PDUSession_CreateSMContext. Ref: TS 29.502 §5.2.2.2.1, §6.1.6.2.4,
// §6.1.5 (multipart/related); TS 29.571 §5.2.4.1 (RefToBinaryData).

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"strings"

	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// maxSMContextCreateErrorBody bounds the error body read by the AMF.
const maxSMContextCreateErrorBody = 1 << 20

// maxLoggedErrorBody bounds the SMF error body echoed in logs / error text.
const maxLoggedErrorBody = 256

// plainSMFError is the fallback error of parseSMContextCreateError. It keeps
// the "smf: status N" prefix and carries the reason the answer could not be
// parsed as a relayable SmContextCreateError, the ProblemDetails cause/detail
// when decodable and a truncated body, so a malformed reject stays
// distinguishable. It is also logged. Ref: TS 29.502 §5.2.2.2.1, TS 29.571 §5.2.4.1
func plainSMFError(status int, reason, cause, detail string, body []byte) error {
	b := body
	if len(b) > maxLoggedErrorBody {
		b = b[:maxLoggedErrorBody]
	}
	slog.Warn("SMF CreateSMContext error answer not relayable - plain error",
		"nf", "AMF", "procedure", "PduSessionEstablishment", "interface", "Nsmf", "direction", "IN",
		"result", "FAILURE", "http_status", status, "reason", reason,
		"cause", cause, "detail", detail, "body", string(b),
		"spec_ref", "TS 29.502 §5.2.2.2.1")
	return fmt.Errorf("smf: status %d (%s; cause=%q detail=%q body=%q)", status, reason, cause, detail, string(b))
}

// parseSMContextCreateError turns a non-201 CreateSMContext answer into an
// error. When the body is an SmContextCreateError carrying a well-formed 5GSM
// message in n1SmMsg (base64 string, this repo's SMF binding, or a
// RefToBinaryData contentId resolved in a multipart/related body) it returns
// *nasmsg.SMContextCreateError; in every other case (no n1SmMsg, garbage,
// not a 5GSM message) it returns the plain "smf: status N" error.
func parseSMContextCreateError(status int, contentType string, body []byte) error {
	jsonPart := body
	parts := map[string][]byte{}
	if mt, params, err := mime.ParseMediaType(contentType); err == nil && strings.EqualFold(mt, "multipart/related") {
		mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		jsonPart = nil
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			data, err := io.ReadAll(io.LimitReader(p, maxSMContextCreateErrorBody))
			if err != nil {
				return plainSMFError(status, "multipart part read: "+err.Error(), "", "", body)
			}
			if id := strings.Trim(p.Header.Get("Content-Id"), "<> "); id != "" {
				parts[id] = data
			}
			if jsonPart == nil {
				pt, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
				if pt == "" || strings.EqualFold(pt, "application/json") {
					jsonPart = data
				}
			}
		}
		if jsonPart == nil {
			return plainSMFError(status, "multipart body without a JSON part", "", "", body)
		}
	}

	var e struct {
		Error struct {
			Status int    `json:"status"`
			Cause  string `json:"cause"`
			Detail string `json:"detail"`
		} `json:"error"`
		N1SmMsg json.RawMessage `json:"n1SmMsg"`
	}
	if err := json.Unmarshal(jsonPart, &e); err != nil {
		return plainSMFError(status, "body is not a JSON SmContextCreateError: "+err.Error(), "", "", body)
	}
	if len(e.N1SmMsg) == 0 {
		return plainSMFError(status, "no n1SmMsg", e.Error.Cause, e.Error.Detail, body)
	}

	var n1 []byte
	var s string
	var ref struct {
		ContentID string `json:"contentId"`
	}
	switch {
	case json.Unmarshal(e.N1SmMsg, &s) == nil:
		var derr error
		n1, derr = base64.StdEncoding.DecodeString(s)
		if derr != nil {
			// Behaviour unchanged: n1 (possibly partial) falls through to the
			// too-short / not-a-reject check below; the log names the real cause.
			slog.Warn("SMF n1SmMsg is not valid base64",
				"nf", "AMF", "procedure", "PduSessionEstablishment", "interface", "Nsmf", "direction", "IN",
				"result", "FAILURE", "http_status", status, "error", derr,
				"spec_ref", "TS 29.502 §5.2.2.2.1; TS 29.571 §5.2.2")
		}
	case json.Unmarshal(e.N1SmMsg, &ref) == nil && ref.ContentID != "":
		n1 = parts[strings.Trim(ref.ContentID, "<> ")]
	}
	// EPD | PSI | PTI | MT | cause at minimum (TS 24.501 §8.3.9).
	if len(n1) < 5 || n1[0] != nas.PDGroupSessionManagement || n1[3] != byte(nas.MsgTypePDUSessionEstablishmentReject) {
		return plainSMFError(status, fmt.Sprintf("n1SmMsg is not a 5GSM PDU SESSION ESTABLISHMENT REJECT (%d bytes)", len(n1)),
			e.Error.Cause, e.Error.Detail, body)
	}
	return &nasmsg.SMContextCreateError{Status: status, Cause: e.Error.Cause, Detail: e.Error.Detail, N1SmMsg: n1}
}
