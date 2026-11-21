package tools

import (
	"strings"
	"testing"
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
