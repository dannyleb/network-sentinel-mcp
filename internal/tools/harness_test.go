package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dannyleb/network-sentinel-mcp/internal/fixture"
	"github.com/dannyleb/network-sentinel-mcp/internal/sentinel"
)

// stubSource serves a fixed snapshot (or error) and counts calls.
type stubSource struct {
	snap  *sentinel.Snapshot
	err   error
	calls int
}

func (s *stubSource) Snapshot(context.Context) (*sentinel.Snapshot, error) {
	s.calls++
	return s.snap, s.err
}

func liveSource() *stubSource   { return &stubSource{snap: fixture.Live()} }
func replaySource() *stubSource { return &stubSource{snap: fixture.Replay()} }

var testInfo = Info{Version: "test", SentinelURL: "http://127.0.0.1:8787", TokenSource: "file /tmp/token"}

// connect runs the server and a client over in-memory transports, so tests go
// through the same JSON-RPC, schema validation and output encoding as a real
// MCP client.
func connect(t *testing.T, src Source) *mcp.ClientSession {
	t.Helper()
	return connectServer(t, NewServer(src, testInfo))
}

func connectServer(t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverT, clientT := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// call invokes a tool. On success it decodes the structured output into out.
// Every result, success or error, is checked for leaks.
func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any, out any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	if !res.IsError && out != nil {
		b, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("decoding %s output: %v\n%s", name, err, b)
		}
	}
	assertNoLeaks(t, res)
	return res
}

// errorText returns the message of a failed tool call.
func errorText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if !res.IsError || len(res.Content) == 0 {
		t.Fatalf("expected an error result, got %+v", res)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("error content is %T", res.Content[0])
	}
	return tc.Text
}

// assertNoLeaks fails if v carries anything that must never reach a model:
// terminal control characters from the fixture's booby-trapped hostname, this
// machine's own addresses, or AI secret findings.
func assertNoLeaks(t *testing.T, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"\x1b", `\u001b`, "\a", `\u0007`, "192.168.1.20", "2001:db8:1::20", "ghp_", "/Users/alex"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("result contains %q:\n%s", bad, b)
		}
	}
}

// rejects asserts that a call with these arguments fails validation without
// ever asking Network Sentinel for data.
func rejects(t *testing.T, tool string, args map[string]any) {
	t.Helper()
	src := liveSource()
	res := call(t, connect(t, src), tool, args, nil)
	if !res.IsError {
		t.Errorf("%s accepted %v", tool, args)
	}
	if src.calls != 0 {
		t.Errorf("%s fetched a snapshot for invalid input %v", tool, args)
	}
}
