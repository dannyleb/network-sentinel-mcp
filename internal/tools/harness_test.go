package tools

import (
	"context"
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

func liveSource() *stubSource { return &stubSource{snap: fixture.Live()} }

var testInfo = Info{Version: "test", SentinelURL: "http://127.0.0.1:8787", TokenSource: "file /tmp/token"}

// connect runs the server and a client over in-memory transports, so tests go
// through the same JSON-RPC, schema validation and output encoding as a real
// MCP client.
func connect(t *testing.T, src Source) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverT, clientT := mcp.NewInMemoryTransports()
	ss, err := NewServer(src, testInfo).Connect(ctx, serverT, nil)
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
