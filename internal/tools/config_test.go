package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func readConfig(t *testing.T, src Source) ConfigView {
	t.Helper()
	res, err := connect(t, src).ReadResource(context.Background(), &mcp.ReadResourceParams{URI: ConfigURI})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Contents) != 1 || res.Contents[0].MIMEType != "application/json" {
		t.Fatalf("contents = %+v", res.Contents)
	}
	assertNoLeaks(t, res)
	var v ConfigView
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestConfigIsListed(t *testing.T) {
	res, err := connect(t, liveSource()).ListResources(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resources) != 1 || res.Resources[0].URI != ConfigURI || res.Resources[0].MIMEType != "application/json" {
		t.Errorf("resources = %+v", res.Resources)
	}
}

func TestConfigDescribesSentinelAndServer(t *testing.T) {
	v := readConfig(t, liveSource())

	s := v.Server
	if s.Name != ServerName || !s.ReadOnly || s.SentinelURL != testInfo.SentinelURL || s.TokenSource != testInfo.TokenSource {
		t.Errorf("server = %+v", s)
	}

	n := v.Sentinel
	if !n.Reachable || n.Mode != "live" || n.Capturing != "en0, utun4" || n.TrackedConnections != 12 || n.ActiveConnections != 4 {
		t.Errorf("network_sentinel = %+v", n)
	}
	if !n.Started.Equal(time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)) || !n.Clock.Equal(time.Date(2026, 1, 15, 15, 0, 0, 0, time.UTC)) {
		t.Errorf("started=%v clock=%v", n.Started, n.Clock)
	}
	if fmt.Sprint(n.AlertCounts) != "map[high:3 info:40 low:2 medium:4]" || n.AIGateway != "http://localhost:8789" || n.AILogStatus != "watching 3 session logs" {
		t.Errorf("counts=%v gateway=%q log=%q", n.AlertCounts, n.AIGateway, n.AILogStatus)
	}
}

func TestConfigListsRulesAndLimits(t *testing.T) {
	v := readConfig(t, liveSource())
	if len(v.Rules) != len(rules) || v.Rules[0].ID == "" || v.Rules[0].Detects == "" {
		t.Errorf("rules = %+v", v.Rules)
	}
	for key, want := range map[string]string{
		"get_recent_connections.minutes": "1 to 1440, default 15",
		"get_alerts.limit":               "1 to 300, default 50",
		"get_alerts.since":               "at most 30 days back",
		"get_top_destinations.limit":     "1 to 100, default 10",
		"network_sentinel.timeout":       "5s",
		"network_sentinel.max_response":  "16.0 MB",
	} {
		if !strings.Contains(v.Limits[key], want) {
			t.Errorf("limit %s = %q, want %q", key, v.Limits[key], want)
		}
	}
	if len(v.NotExposed) == 0 {
		t.Error("should say which settings the API doesn't report")
	}
}

func TestConfigStillUsefulWhenSentinelIsDown(t *testing.T) {
	v := readConfig(t, &stubSource{err: errors.New("can't reach Network Sentinel at http://127.0.0.1:8787")})
	if v.Sentinel.Reachable || !strings.Contains(v.Sentinel.Error, "can't reach") || v.Sentinel.Started != nil {
		t.Errorf("network_sentinel = %+v", v.Sentinel)
	}
	if len(v.Rules) != len(rules) || len(v.Limits) == 0 {
		t.Error("rules and limits should be there even when Network Sentinel is down")
	}
}
