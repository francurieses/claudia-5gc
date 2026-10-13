package clients

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeTokens struct {
	tok string
	err error
}

func (f fakeTokens) Token(context.Context) (string, error) { return f.tok, f.err }

func TestNEFCreateSubscription(t *testing.T) {
	var method, path, auth, ctype, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		method, path, auth, ctype, body = r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), string(b)
		w.Header().Set("Location", "https://nef/3gpp-as-session-with-qos/v1/as-1/subscriptions/sub-1")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"subscriptionId":"sub-1"}`))
	}))
	defer srv.Close()
	c := NewNEF(srv.URL+"/", srv.Client(), fakeTokens{tok: "tok-abc"})
	status, raw, loc, err := c.CreateSubscription(context.Background(), "as-1", map[string]string{"qosReference": "q"})
	if err != nil || status != 201 {
		t.Fatalf("create: %d %v", status, err)
	}
	if method != "POST" || path != "/3gpp-as-session-with-qos/v1/as-1/subscriptions" {
		t.Errorf("request: %s %s", method, path)
	}
	if auth != "Bearer tok-abc" || ctype != "application/json" || body != `{"qosReference":"q"}` {
		t.Errorf("headers/body: %q %q %q", auth, ctype, body)
	}
	if loc == "" || string(raw) != `{"subscriptionId":"sub-1"}` {
		t.Errorf("loc/raw: %q %s", loc, raw)
	}
}

func TestNEFGetDeleteAndStatus(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := NewNEF(srv.URL, srv.Client(), nil)
	if s, _, err := c.GetSubscription(context.Background(), "as-1", "sub-1"); err != nil || s != 404 {
		t.Errorf("get: %d %v", s, err)
	}
	if s, _, err := c.DeleteSubscription(context.Background(), "as-1", "sub-1"); err != nil || s != 204 {
		t.Errorf("delete: %d %v", s, err)
	}
	want := []string{"GET /3gpp-as-session-with-qos/v1/as-1/subscriptions/sub-1", "DELETE /3gpp-as-session-with-qos/v1/as-1/subscriptions/sub-1"}
	if len(calls) != 2 || calls[0] != want[0] || calls[1] != want[1] {
		t.Errorf("calls: %v", calls)
	}
}

func TestNEFTokenFailureStillSendsWithoutBearer(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := NewNEF(srv.URL, srv.Client(), fakeTokens{err: io.ErrUnexpectedEOF})
	s, _, err := c.GetSubscription(context.Background(), "as-1", "sub-1")
	if err != nil || s != 401 || auth != "" {
		t.Errorf("got %d %v auth=%q", s, err, auth)
	}
}
