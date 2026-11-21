package sentinel_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dannyleb/network-sentinel-mcp/internal/fixture"
	"github.com/dannyleb/network-sentinel-mcp/internal/sentinel"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef"

func newClient(t *testing.T, url string, opts ...func(*sentinel.Options)) *sentinel.Client {
	t.Helper()
	o := sentinel.Options{URL: url, Token: testToken}
	for _, f := range opts {
		f(&o)
	}
	c, err := sentinel.New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestSnapshotIsAnAuthenticatedGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/snapshot" {
			t.Errorf("path = %s, want /api/snapshot", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("Authorization = %q", got)
		}
		// Network Sentinel blocks requests that look browser-originated.
		for _, h := range []string{"Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode"} {
			if r.Header.Get(h) != "" {
				t.Errorf("unexpected %s header", h)
			}
		}
		w.Write(fixture.LiveJSON)
	}))
	defer srv.Close()

	s, err := newClient(t, srv.URL).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Mode != "live" || len(s.Flows) != 9 || len(s.Alerts) != 11 || len(s.DNS) != 7 {
		t.Fatalf("decoded mode=%s flows=%d alerts=%d dns=%d", s.Mode, len(s.Flows), len(s.Alerts), len(s.DNS))
	}
	if want := time.Date(2026, 1, 15, 15, 0, 0, 0, time.UTC); !s.Clock().Equal(want) {
		t.Errorf("Clock() = %v, want %v", s.Clock(), want)
	}
}

func TestSnapshotDropsFieldsItDoesNotUse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture.LiveJSON)
	}))
	defer srv.Close()

	s, err := newClient(t, srv.URL).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	for _, leak := range []string{"192.168.1.20", "2001:db8:1::20", "ghp_", "/Users/alex"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("decoded snapshot still contains %q", leak)
		}
	}
}

func TestSnapshotUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"locked"}`))
	}))
	defer srv.Close()

	_, err := newClient(t, srv.URL).Snapshot(context.Background())
	if !errors.Is(err, sentinel.ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if !strings.Contains(err.Error(), "--token-file") {
		t.Errorf("error should say how to fix it: %v", err)
	}
}

func TestSnapshotNotRunning(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	_, err := newClient(t, url).Snapshot(context.Background())
	if !errors.Is(err, sentinel.ErrNotRunning) {
		t.Fatalf("err = %v, want ErrNotRunning", err)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Error("error message leaks the token")
	}
}

func TestSnapshotDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write(fixture.LiveJSON)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/snapshot", http.StatusFound)
	}))
	defer redirector.Close()

	if _, err := newClient(t, redirector.URL).Snapshot(context.Background()); err == nil {
		t.Fatal("expected an error for a redirect")
	}
	if hits.Load() != 0 {
		t.Error("client followed the redirect")
	}
}

func TestSnapshotRejectsOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture.LiveJSON)
	}))
	defer srv.Close()

	c := newClient(t, srv.URL, func(o *sentinel.Options) { o.MaxBytes = 1024 })
	_, err := c.Snapshot(context.Background())
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v, want size error", err)
	}
}

func TestSnapshotRejectsMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>not a snapshot</html>"))
	}))
	defer srv.Close()

	if _, err := newClient(t, srv.URL).Snapshot(context.Background()); err == nil {
		t.Fatal("expected a decode error")
	}
}

func TestSnapshotHonoursContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := newClient(t, srv.URL).Snapshot(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
}

func TestParseURLAllowsOnlyThisMachine(t *testing.T) {
	ok := []string{
		"http://127.0.0.1:8787",
		"http://127.0.0.1:8787/",
		"http://localhost:8787",
		"http://LOCALHOST:8787",
		"http://[::1]:8787",
		"https://127.0.0.2:9000",
	}
	for _, u := range ok {
		if _, err := sentinel.ParseURL(u); err != nil {
			t.Errorf("ParseURL(%q) = %v, want ok", u, err)
		}
	}
	bad := []string{
		"http://example.com:8787",
		"http://localhost.evil.test:8787",
		"http://10.0.0.5:8787",
		"http://192.168.1.20:8787",
		"http://0.0.0.0:8787",
		"http://[2001:db8::1]:8787",
		"http://user:pw@127.0.0.1:8787",
		"ftp://127.0.0.1:8787",
		"http://127.0.0.1:8787/api/snapshot",
		"http://127.0.0.1:8787/?x=1",
		"127.0.0.1:8787",
		"",
	}
	for _, u := range bad {
		if _, err := sentinel.ParseURL(u); err == nil {
			t.Errorf("ParseURL(%q) accepted, want error", u)
		}
	}
}

func TestNewRejectsMalformedToken(t *testing.T) {
	for _, tok := range []string{"short", strings.Repeat("a", 31), "abc def" + strings.Repeat("a", 40), "a\r\nX-Evil: 1" + strings.Repeat("a", 40)} {
		if _, err := sentinel.New(sentinel.Options{Token: tok}); err == nil {
			t.Errorf("New accepted token %q", tok)
		}
	}
}
