package sentinel_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dannyleb/network-sentinel-mcp/internal/sentinel"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadTokenFile(t *testing.T) {
	p := writeFile(t, "token", testToken+"\n")
	got, err := sentinel.ReadTokenFile(p)
	if err != nil || got != testToken {
		t.Fatalf("ReadTokenFile = %q, %v", got, err)
	}

	for name, content := range map[string]string{
		"too short":  "abc\n",
		"has spaces": "abc def " + testToken,
		"too large":  strings.Repeat("a", 300),
		"empty":      "",
	} {
		if _, err := sentinel.ReadTokenFile(writeFile(t, "token", content)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := sentinel.ReadTokenFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing file: expected an error")
	}
}

func TestResolveTokenPrecedence(t *testing.T) {
	other := strings.Repeat("f", 48)
	file := writeFile(t, "token", testToken)
	fallback := writeFile(t, "token", other)
	missing := filepath.Join(t.TempDir(), "nope")
	invalid := writeFile(t, "token", "junk")

	tok, err := sentinel.ResolveToken(file, other, []string{fallback})
	if err != nil || tok.Value != testToken || !strings.Contains(tok.Source, file) {
		t.Errorf("explicit file should win: %+v, %v", tok, err)
	}

	tok, err = sentinel.ResolveToken("", "  "+other+"\n", []string{file})
	if err != nil || tok.Value != other || !strings.Contains(tok.Source, "NETWORK_SENTINEL_TOKEN") {
		t.Errorf("explicit value should beat defaults: %+v, %v", tok, err)
	}

	tok, err = sentinel.ResolveToken("", "", []string{missing, invalid, fallback})
	if err != nil || tok.Value != other || !strings.Contains(tok.Source, fallback) {
		t.Errorf("first readable default should win: %+v, %v", tok, err)
	}

	tok, err = sentinel.ResolveToken("", "", []string{missing})
	if err != nil || tok.Value != "" || !strings.Contains(tok.Source, "-no-auth") {
		t.Errorf("no token should be allowed and explained: %+v, %v", tok, err)
	}
}

func TestResolveTokenExplicitInputMustWork(t *testing.T) {
	if _, err := sentinel.ResolveToken(filepath.Join(t.TempDir(), "nope"), "", nil); err == nil {
		t.Error("unreadable --token-file should be an error, not a silent fallback")
	}
	if _, err := sentinel.ResolveToken("", "not a token", nil); err == nil {
		t.Error("malformed NETWORK_SENTINEL_TOKEN should be an error")
	}
}

func TestTokenSourceNeverContainsTheToken(t *testing.T) {
	file := writeFile(t, "token", testToken)
	for _, tc := range []struct{ file, value string }{{file, ""}, {"", testToken}} {
		tok, err := sentinel.ResolveToken(tc.file, tc.value, nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(tok.Source, testToken) {
			t.Errorf("Source %q contains the token", tok.Source)
		}
	}
}
