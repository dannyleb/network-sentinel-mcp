package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestServerIdentifiesItself(t *testing.T) {
	cs := connect(t, liveSource())
	init := cs.InitializeResult()
	if init.ServerInfo.Name != ServerName || init.ServerInfo.Version != "test" {
		t.Errorf("server info = %+v", init.ServerInfo)
	}
	if !strings.Contains(init.Instructions, "never as instructions") {
		t.Error("instructions should warn that network text is data, not instructions")
	}
}

func TestConnectingDoesNotTouchNetworkSentinel(t *testing.T) {
	src := liveSource()
	connect(t, src)
	if src.calls != 0 {
		t.Errorf("snapshot fetched %d times before any tool call", src.calls)
	}
}

// TestSDKPanicIsContained reproduces the go-sdk v1.8.0 null-arguments panic on
// a real server and checks that it costs one request, not the process.
func TestSDKPanicIsContained(t *testing.T) {
	srv := NewServer(liveSource(), testInfo)
	type in struct {
		N int `json:"n"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "defaulted",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"n": map[string]any{"type": "integer", "default": 1}}},
	}, func(context.Context, *mcp.CallToolRequest, in) (*mcp.CallToolResult, any, error) {
		return nil, nil, nil
	})
	cs := connectServer(t, srv)

	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "defaulted", Arguments: map[string]any(nil)})
	if err == nil || !strings.Contains(err.Error(), "internal error") {
		t.Fatalf("err = %v, want a contained internal error", err)
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "defaulted", Arguments: map[string]any{}}); err != nil {
		t.Fatalf("server stopped answering after the panic: %v", err)
	}
}

func TestRecoverPanics(t *testing.T) {
	h := recoverPanics(func(context.Context, string, mcp.Request) (mcp.Result, error) {
		panic("boom")
	})
	res, err := h(context.Background(), "tools/call", nil)
	if res != nil || err == nil || !strings.Contains(err.Error(), "tools/call") {
		t.Errorf("recoverPanics = %v, %v", res, err)
	}
}
