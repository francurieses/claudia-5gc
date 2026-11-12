package sbi

// multipart.go - minimal multipart/related (RFC 2387) encode/decode for SBI
// messages that carry a JSON root part plus binary parts referenced by
// RefToBinaryData.contentId. Stdlib only (mime/multipart).
// Ref: TS 29.500 §5.4 (multipart/related messages), TS 29.571 §5.2.2 RefToBinaryData.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
)

// MaxRelatedParts is the maximum number of body parts DecodeRelated accepts.
// SBI multipart messages carry one JSON root part plus a handful of binary
// parts (TS 29.500 §5.4); the bound stops part-count amplification.
const MaxRelatedParts = 8

// MaxRelatedPartBytes is the maximum size of one body part accepted by
// DecodeRelated. The caller must still bound the whole reader (e.g.
// http.MaxBytesReader); this limit is per part.
const MaxRelatedPartBytes = 1 << 20

// Sentinel errors returned (wrapped) by DecodeRelated.
var (
	// ErrRelatedTooManyParts: more than MaxRelatedParts parts.
	ErrRelatedTooManyParts = errors.New("sbi: multipart: too many parts")
	// ErrRelatedPartTooLarge: a part exceeds MaxRelatedPartBytes.
	ErrRelatedPartTooLarge = errors.New("sbi: multipart: part too large")
	// ErrRelatedTransferEncoding: a part has a non-identity Content-Transfer-Encoding.
	ErrRelatedTransferEncoding = errors.New("sbi: multipart: unsupported content-transfer-encoding")
	// ErrRelatedDuplicateContentID: two parts share a Content-Id.
	ErrRelatedDuplicateContentID = errors.New("sbi: multipart: duplicate content-id")
	// ErrRelatedStartNotFound: the "start" parameter names no part.
	ErrRelatedStartNotFound = errors.New("sbi: multipart: start part not found")
)

// RelatedPart is one body part of a multipart/related message.
type RelatedPart struct {
	// ContentType is the part media type (e.g. application/json).
	ContentType string
	// ContentID is the Content-Id header value without angle brackets; empty
	// for the root part.
	ContentID string
	// Body is the raw part content.
	Body []byte
}

// EncodeRelated builds a multipart/related body. The first part is the root
// part; boundary may be empty to generate a random one. It returns the
// Content-Type header value (type parameter = root part media type) and body.
// Content-Id is written bare (e.g. "smsPayload", no angle brackets), the form
// used by 3GPP examples (TS 29.500 §5.4); DecodeRelated accepts both forms.
// Ref: TS 29.500 §5.4, RFC 2387
func EncodeRelated(boundary string, parts []RelatedPart) (contentType string, body []byte, err error) {
	if len(parts) == 0 {
		return "", nil, errors.New("sbi: multipart: no parts")
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if boundary != "" {
		if err := w.SetBoundary(boundary); err != nil {
			return "", nil, fmt.Errorf("sbi: multipart: set boundary: %w", err)
		}
	}
	for _, p := range parts {
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", p.ContentType)
		if p.ContentID != "" {
			h.Set("Content-Id", p.ContentID)
		}
		pw, err := w.CreatePart(h)
		if err != nil {
			return "", nil, fmt.Errorf("sbi: multipart: create part: %w", err)
		}
		if _, err := pw.Write(p.Body); err != nil {
			return "", nil, fmt.Errorf("sbi: multipart: write part: %w", err)
		}
	}
	if err := w.Close(); err != nil {
		return "", nil, fmt.Errorf("sbi: multipart: close: %w", err)
	}
	ct := mime.FormatMediaType("multipart/related", map[string]string{
		"boundary": w.Boundary(),
		"type":     parts[0].ContentType,
	})
	return ct, buf.Bytes(), nil
}

// trimContentID strips one pair of angle brackets from a Content-Id value.
func trimContentID(id string) string {
	id = strings.TrimSpace(id)
	if n := len(id); n >= 2 && id[0] == '<' && id[n-1] == '>' {
		return id[1 : n-1]
	}
	return id
}

// IsRelated reports whether the Content-Type header value is multipart/related.
func IsRelated(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && mt == "multipart/related"
}

// DecodeRelated parses a multipart/related body into its parts. The root part
// is returned first: the part named by the "start" parameter when present
// (RFC 2387 §3.2), else the first part; the other parts keep their order.
// Limits: at most MaxRelatedParts parts of at most MaxRelatedPartBytes each;
// non-identity Content-Transfer-Encoding and duplicate Content-Id are rejected
// (raw parts are read, so quoted-printable is never silently decoded).
// The caller must bound r (e.g. http.MaxBytesReader); read errors, including
// *http.MaxBytesError, are returned wrapped so errors.As works.
// Ref: TS 29.500 §5.4, RFC 2387
func DecodeRelated(contentType string, r io.Reader) ([]RelatedPart, error) {
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("sbi: multipart: content-type: %w", err)
	}
	if mt != "multipart/related" || params["boundary"] == "" {
		return nil, errors.New("sbi: multipart: not multipart/related with boundary")
	}
	mr := multipart.NewReader(r, params["boundary"])
	var out []RelatedPart
	seen := map[string]bool{}
	for {
		p, err := mr.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("sbi: multipart: next part: %w", err)
		}
		if len(out) >= MaxRelatedParts {
			return nil, fmt.Errorf("%w (max %d)", ErrRelatedTooManyParts, MaxRelatedParts)
		}
		switch strings.ToLower(strings.TrimSpace(p.Header.Get("Content-Transfer-Encoding"))) {
		case "", "7bit", "8bit", "binary":
		default:
			return nil, fmt.Errorf("%w: %q", ErrRelatedTransferEncoding, p.Header.Get("Content-Transfer-Encoding"))
		}
		b, err := io.ReadAll(io.LimitReader(p, MaxRelatedPartBytes+1))
		if err != nil {
			return nil, fmt.Errorf("sbi: multipart: read part: %w", err)
		}
		if len(b) > MaxRelatedPartBytes {
			return nil, fmt.Errorf("%w (max %d bytes)", ErrRelatedPartTooLarge, MaxRelatedPartBytes)
		}
		id := trimContentID(p.Header.Get("Content-Id"))
		if id != "" {
			if seen[id] {
				return nil, fmt.Errorf("%w: %q", ErrRelatedDuplicateContentID, id)
			}
			seen[id] = true
		}
		out = append(out, RelatedPart{ContentType: p.Header.Get("Content-Type"), ContentID: id, Body: b})
	}
	if start := trimContentID(params["start"]); start != "" {
		for i := range out {
			if out[i].ContentID == start {
				root := out[i]
				copy(out[1:i+1], out[:i])
				out[0] = root
				return out, nil
			}
		}
		return nil, fmt.Errorf("%w: %q", ErrRelatedStartNotFound, start)
	}
	return out, nil
}
