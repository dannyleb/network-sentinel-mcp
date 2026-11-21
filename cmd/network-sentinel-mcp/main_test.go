package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dannyleb/network-sentinel-mcp/internal/fixture"
	"github.com/dannyleb/network-sentinel-mcp/internal/tools"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef"

// fakeSentinel serves the live fixture, but only to requests carrying the token.
func fakeSentinel(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write(fixture.LiveJSON)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func tokenFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func noEnv(string) string { return "" }

// start runs the whole program, as main would, against an in-memory MCP client.
func start(t *testing.T, args []string, getenv func(string) string) (*mcp.ClientSession, *bytes.Buffer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	serverT, clientT := mcp.NewInMemoryTransports()
	var logs bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, env{args: args, getenv: getenv, transport: serverT, stdout: &bytes.Buffer{}, stderr: &logs})
	}()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		cancel()
		t.Fatalf("connect: %v (server: %v)", err, <-done)
	}
	t.Cleanup(func() {
		cs.Close()
		cancel()
		<-done
	})
	return cs, &logs
}

func TestRunServesMCP(t *testing.T) {
	sentinel := fakeSentinel(t)
	cs, logs := start(t, []string{"-url", sentinel.URL, "-token-file", tokenFile(t)}, noEnv)

	if got := cs.InitializeResult().ServerInfo.Name; got != tools.ServerName {
		t.Errorf("server name = %q", got)
	}
	if strings.Contains(logs.String(), testToken) {
		t.Error("logs contain the token")
	}
	if !strings.Contains(logs.String(), "token: file ") {
		t.Errorf("logs should say where the token came from: %q", logs.String())
	}

	// A tool call goes all the way through: MCP -> tool -> HTTP with token -> fake sentinel.
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_recent_connections", Arguments: map[string]any{"host": "example-ai"}})
	if err != nil || res.IsError {
		t.Fatalf("get_recent_connections: %v %+v", err, res)
	}
	if text := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(text, `"ip":"203.0.113.10"`) {
		t.Errorf("unexpected result: %s", text)
	}
}

func TestRunReportsAMissingToken(t *testing.T) {
	sentinel := fakeSentinel(t)
	cs, _ := start(t, []string{"-url", sentinel.URL}, noEnv)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_recent_connections"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "--token-file") {
		t.Errorf("want an actionable token error, got %+v", res.Content)
	}
}

func TestRunReadsSettingsFromEnvironment(t *testing.T) {
	sentinel := fakeSentinel(t)
	file := tokenFile(t)
	getenv := func(k string) string {
		return map[string]string{"NETWORK_SENTINEL_URL": sentinel.URL, "NETWORK_SENTINEL_TOKEN_FILE": file}[k]
	}
	_, logs := start(t, nil, getenv)
	if !strings.Contains(logs.String(), sentinel.URL) || !strings.Contains(logs.String(), file) {
		t.Errorf("env settings not used: %q", logs.String())
	}
}

func TestRunRefusesRemoteSentinel(t *testing.T) {
	var logs bytes.Buffer
	err := run(context.Background(), env{args: []string{"-url", "http://203.0.113.5:8787"}, getenv: noEnv, stderr: &logs})
	if err == nil || !strings.Contains(err.Error(), "not on this machine") {
		t.Fatalf("err = %v, want refusal", err)
	}
}

func TestRunRejectsUnreadableTokenFile(t *testing.T) {
	err := run(context.Background(), env{args: []string{"-token-file", filepath.Join(t.TempDir(), "missing")}, getenv: noEnv, stderr: &bytes.Buffer{}})
	if err == nil {
		t.Fatal("expected an error for a missing token file")
	}
}

func TestRunVersionAndHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run(context.Background(), env{args: []string{"-version"}, getenv: noEnv, stdout: &out, stderr: &errOut}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) == "" {
		t.Error("-version printed nothing")
	}
	out.Reset()
	if err := run(context.Background(), env{args: []string{"-h"}, getenv: noEnv, stdout: &out, stderr: &errOut}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.String(), "-token-file") {
		t.Error("-h should list the flags")
	}
	if out.Len() != 0 {
		t.Error("-h must not write to stdout, which belongs to MCP")
	}
}

func TestRunRejectsStrayArguments(t *testing.T) {
	if err := run(context.Background(), env{args: []string{"oops"}, getenv: noEnv, stderr: &bytes.Buffer{}}); err == nil {
		t.Fatal("expected an error for a stray argument")
	}
}
