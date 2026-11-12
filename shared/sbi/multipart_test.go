package sbi

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMultipartRoundTrip(t *testing.T) {
	in := []RelatedPart{
		{ContentType: "application/json", Body: []byte(`{"a":1}`)},
		{ContentType: "application/vnd.3gpp.sms", ContentID: "smsPayload", Body: []byte{0, 1, 2, 0xff}},
	}
	ct, body, err := EncodeRelated("BOUND", in)
	if err != nil {
		t.Fatal(err)
	}
	if !IsRelated(ct) || !strings.Contains(ct, "boundary=BOUND") {
		t.Fatalf("ct = %q", ct)
	}
	out, err := DecodeRelated(ct, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[1].ContentID != "smsPayload" || !bytes.Equal(out[1].Body, in[1].Body) || string(out[0].Body) != `{"a":1}` {
		t.Fatalf("out = %+v", out)
	}
}

func TestDecodeRelatedErrors(t *testing.T) {
	for name, ct := range map[string]string{"json": "application/json", "noboundary": "multipart/related", "garbage": ";;"} {
		if _, err := DecodeRelated(ct, strings.NewReader("")); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, err := DecodeRelated("multipart/related; boundary=X", strings.NewReader("--X\r\nbroken")); err == nil {
		t.Error("truncated part: want error")
	}
	if _, _, err := EncodeRelated("", nil); err == nil {
		t.Error("no parts: want error")
	}
}

func raw(parts ...string) string {
	var sb strings.Builder
	for _, p := range parts {
		sb.WriteString("--B\r\n" + p + "\r\n")
	}
	sb.WriteString("--B--\r\n")
	return sb.String()
}

const relCT = "multipart/related; boundary=B"

func TestDecodeRelatedLimits(t *testing.T) {
	var many []string
	for i := 0; i <= MaxRelatedParts; i++ {
		many = append(many, fmt.Sprintf("Content-Id: p%d\r\n\r\nx", i))
	}
	big := "Content-Id: big\r\n\r\n" + strings.Repeat("a", MaxRelatedPartBytes+1)
	atLimit := "Content-Id: ok\r\n\r\n" + strings.Repeat("a", MaxRelatedPartBytes)

	cases := []struct {
		name string
		body string
		want error
	}{
		{"max parts ok", raw(many[:MaxRelatedParts]...), nil},
		{"too many parts", raw(many...), ErrRelatedTooManyParts},
		{"part at limit", raw(atLimit), nil},
		{"part too large", raw(big), ErrRelatedPartTooLarge},
		{"quoted-printable rejected", raw("Content-Transfer-Encoding: quoted-printable\r\n\r\nA=42"), ErrRelatedTransferEncoding},
		{"base64 rejected", raw("Content-Transfer-Encoding: base64\r\n\r\nQQ=="), ErrRelatedTransferEncoding},
		{"binary accepted", raw("Content-Transfer-Encoding: binary\r\n\r\nQQ"), nil},
		{"duplicate content-id", raw("Content-Id: a\r\n\r\n1", "Content-Id: <a>\r\n\r\n2"), ErrRelatedDuplicateContentID},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodeRelated(relCT, strings.NewReader(c.body))
			if !errors.Is(err, c.want) || (c.want == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestDecodeRelatedQuotedPrintableNotDecoded(t *testing.T) {
	// Without the CTE check Go would silently decode "=42" to "B".
	if _, err := DecodeRelated(relCT, strings.NewReader(raw("Content-Transfer-Encoding: Quoted-Printable\r\n\r\nA=42"))); err == nil {
		t.Fatal("want error")
	}
}

func TestDecodeRelatedContentIDAngleBrackets(t *testing.T) {
	out, err := DecodeRelated(relCT, strings.NewReader(raw("Content-Type: application/json\r\n\r\n{}", "Content-Id: <sms1>\r\n\r\nx")))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[1].ContentID != "sms1" {
		t.Fatalf("out = %+v", out)
	}
}

func TestDecodeRelatedStart(t *testing.T) {
	body := raw("Content-Id: <a>\r\n\r\nA", "Content-Id: <root>\r\n\r\nR", "Content-Id: c\r\n\r\nC")
	for _, start := range []string{`"<root>"`, `root`} {
		out, err := DecodeRelated(relCT+"; start="+start, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 3 || out[0].ContentID != "root" || out[1].ContentID != "a" || out[2].ContentID != "c" {
			t.Fatalf("start=%s out = %+v", start, out)
		}
	}
	out, err := DecodeRelated(relCT, strings.NewReader(body))
	if err != nil || out[0].ContentID != "a" {
		t.Fatalf("no start: out=%+v err=%v", out, err)
	}
	if _, err := DecodeRelated(relCT+`; start="<zzz>"`, strings.NewReader(body)); !errors.Is(err, ErrRelatedStartNotFound) {
		t.Fatalf("err = %v, want ErrRelatedStartNotFound", err)
	}
}

func TestDecodeRelatedMaxBytesErrorPassThrough(t *testing.T) {
	body := raw("Content-Id: a\r\n\r\n" + strings.Repeat("a", 4096))
	w := httpRecorderLike{}
	r := http.MaxBytesReader(w, io.NopCloser(strings.NewReader(body)), 256)
	_, err := DecodeRelated(relCT, r)
	var mbe *http.MaxBytesError
	if !errors.As(err, &mbe) {
		t.Fatalf("err = %v, want *http.MaxBytesError via errors.As", err)
	}
}

// httpRecorderLike is the minimal http.ResponseWriter http.MaxBytesReader needs.
type httpRecorderLike struct{}

func (httpRecorderLike) Header() http.Header         { return http.Header{} }
func (httpRecorderLike) Write(b []byte) (int, error) { return len(b), nil }
func (httpRecorderLike) WriteHeader(int)             {}
