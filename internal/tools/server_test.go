package tools

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// toolInputs maps every tool to its input struct. Adding a tool without an
// entry here fails TestEveryToolIsReadOnlyAndBounded.
var toolInputs = map[string]any{
	"get_recent_connections": RecentConnectionsInput{},
	"get_alerts":             AlertsInput{},
}

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

// TestEveryToolIsReadOnlyAndBounded enforces the project's two hard rules on
// every registered tool: it is declared read-only and closed-world, and every
// input it accepts has an explicit bound.
func TestEveryToolIsReadOnlyAndBounded(t *testing.T) {
	res, err := connect(t, liveSource()).ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
		a := tool.Annotations
		if a == nil || !a.ReadOnlyHint || !a.IdempotentHint || a.OpenWorldHint == nil || *a.OpenWorldHint {
			t.Errorf("%s: annotations must be read-only, idempotent and closed-world: %+v", tool.Name, a)
		}
		if len(tool.Description) < 80 {
			t.Errorf("%s: description is too thin for a model to act on", tool.Name)
		}

		in, ok := toolInputs[tool.Name]
		if !ok {
			t.Errorf("%s: no input struct listed in toolInputs", tool.Name)
			continue
		}
		s := tool.InputSchema.(map[string]any)
		if s["additionalProperties"] != false {
			t.Errorf("%s: unknown arguments must be rejected", tool.Name)
		}
		props := s["properties"].(map[string]any)
		if got, want := sortedKeys(props), jsonFields(in); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: schema properties %v don't match input struct fields %v", tool.Name, got, want)
		}
		for name, p := range props {
			p := p.(map[string]any)
			if p["description"] == "" || p["description"] == nil {
				t.Errorf("%s.%s: no description", tool.Name, name)
			}
			switch p["type"] {
			case "integer":
				if p["minimum"] == nil || p["maximum"] == nil {
					t.Errorf("%s.%s: integer without minimum and maximum", tool.Name, name)
				}
			case "string":
				if p["maxLength"] == nil && p["enum"] == nil {
					t.Errorf("%s.%s: string without maxLength or enum", tool.Name, name)
				}
			default:
				t.Errorf("%s.%s: unexpected type %v", tool.Name, name, p["type"])
			}
		}
	}
	sort.Strings(names)
	if want := sortedKeys(toolInputs); !reflect.DeepEqual(names, want) {
		t.Errorf("tools = %v, want %v", names, want)
	}
}

// TestNullArgumentsAreSafe is a regression test: go-sdk v1.8.0 panics on
// "arguments": null when a schema declares defaults. A typed nil map is sent
// over the wire as null.
func TestNullArgumentsAreSafe(t *testing.T) {
	cs := connect(t, liveSource())
	for name := range toolInputs {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: map[string]any(nil)})
		if err != nil {
			t.Fatalf("%s with null arguments: %v", name, err)
		}
		if res.IsError && name != "explain_alert" { // explain_alert requires alert_id
			t.Errorf("%s with null arguments failed: %v", name, res.Content)
		}
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
		InputSchema: schema{"type": "object", "properties": schema{"n": schema{"type": "integer", "default": 1}}},
	}, func(context.Context, *mcp.CallToolRequest, in) (*mcp.CallToolResult, any, error) {
		return nil, nil, nil
	})
	cs := connectServer(t, srv)

	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "defaulted", Arguments: map[string]any(nil)})
	if err == nil || !strings.Contains(err.Error(), "internal error") {
		t.Fatalf("err = %v, want a contained internal error", err)
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_recent_connections"}); err != nil {
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

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func jsonFields(v any) []string {
	var names []string
	rt := reflect.TypeOf(v)
	for i := 0; i < rt.NumField(); i++ {
		name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
