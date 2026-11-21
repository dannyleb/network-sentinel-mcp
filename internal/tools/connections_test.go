package tools

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dannyleb/network-sentinel-mcp/internal/sentinel"
)

func ips(cs []Connection) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.IP
	}
	return out
}

func TestRecentConnectionsDefaultWindow(t *testing.T) {
	var out RecentConnectionsOutput
	call(t, connect(t, liveSource()), "get_recent_connections", nil, &out)

	// Default is 15 minutes back from the fixture clock (15:00:00), newest first.
	want := []string{"198.51.100.20", "203.0.113.10", "203.0.113.11", "203.0.113.50", "2001:db8::5", "198.51.100.30", "192.0.2.66"}
	if got := ips(out.Connections); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("connections = %v\nwant          %v", got, want)
	}
	if !out.From.Equal(time.Date(2026, 1, 15, 14, 45, 0, 0, time.UTC)) || !out.To.Equal(time.Date(2026, 1, 15, 15, 0, 0, 0, time.UTC)) {
		t.Errorf("window = %v to %v", out.From, out.To)
	}
	if out.Matched != 7 || out.Truncated || out.Mode != "live" {
		t.Errorf("matched=%d truncated=%v mode=%s", out.Matched, out.Truncated, out.Mode)
	}
}

func TestRecentConnectionsFields(t *testing.T) {
	var out RecentConnectionsOutput
	call(t, connect(t, liveSource()), "get_recent_connections", map[string]any{"host": "203.0.113.10"}, &out)
	if len(out.Connections) != 1 {
		t.Fatalf("got %d connections", len(out.Connections))
	}
	c := out.Connections[0]
	want := Connection{
		Host: "api.example-ai.test", HostSource: "sni", IP: "203.0.113.10", Port: 443, Protocol: "TCP", Service: "HTTPS",
		BytesOut: 52428800, BytesIn: 1048576, Upload: "50.0 MB", Download: "1.0 MB", PacketsOut: 36000, PacketsIn: 900,
		FirstSeen: time.Date(2026, 1, 15, 14, 20, 0, 0, time.UTC), LastSeen: time.Date(2026, 1, 15, 14, 59, 58, 0, time.UTC), Alerts: 2,
	}
	if fmt.Sprintf("%+v", c) != fmt.Sprintf("%+v", want) {
		t.Errorf("connection =\n%+v\nwant\n%+v", c, want)
	}
}

func TestRecentConnectionsHostFilter(t *testing.T) {
	cs := connect(t, liveSource())
	for _, tc := range []struct {
		args map[string]any
		want []string
	}{
		{map[string]any{"host": "example-ai"}, []string{"203.0.113.10", "203.0.113.11"}},
		{map[string]any{"host": "EXAMPLE-AI"}, []string{"203.0.113.10", "203.0.113.11"}},
		{map[string]any{"host": "198.51.100.", "minutes": 60}, []string{"198.51.100.20", "198.51.100.30", "198.51.100.40"}},
		{map[string]any{"host": "2001:db8"}, []string{"2001:db8::5"}},
	} {
		var out RecentConnectionsOutput
		call(t, cs, "get_recent_connections", tc.args, &out)
		if got := ips(out.Connections); fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%v: got %v, want %v", tc.args, got, tc.want)
		}
	}
}

func TestRecentConnectionsNoMatchExplains(t *testing.T) {
	var out RecentConnectionsOutput
	call(t, connect(t, liveSource()), "get_recent_connections", map[string]any{"host": "nothing-here"}, &out)
	if len(out.Connections) != 0 || !strings.Contains(strings.Join(out.Notes, " "), "nothing-here") {
		t.Errorf("connections=%v notes=%v", out.Connections, out.Notes)
	}
	if out.Connections == nil {
		t.Error("connections should be an empty list, not null")
	}
}

func TestRecentConnectionsLimit(t *testing.T) {
	var out RecentConnectionsOutput
	call(t, connect(t, liveSource()), "get_recent_connections", map[string]any{"limit": 3}, &out)
	if len(out.Connections) != 3 || out.Matched != 7 || !out.Truncated {
		t.Errorf("returned=%d matched=%d truncated=%v", len(out.Connections), out.Matched, out.Truncated)
	}
}

func TestRecentConnectionsSaysWhenSnapshotIsPartial(t *testing.T) {
	var out RecentConnectionsOutput
	call(t, connect(t, liveSource()), "get_recent_connections", nil, &out)
	if !strings.Contains(strings.Join(out.Notes, " "), "tracking 12 connections but shares only the 9") {
		t.Errorf("notes = %v", out.Notes)
	}
}

func TestRecentConnectionsReplayUsesCaptureClock(t *testing.T) {
	// The capture is from 2025; the snapshot was taken in 2026. Measuring the
	// window from the wall clock would find nothing.
	var out RecentConnectionsOutput
	call(t, connect(t, replaySource()), "get_recent_connections", map[string]any{"minutes": 15}, &out)
	if got := ips(out.Connections); fmt.Sprint(got) != "[203.0.113.70 198.51.100.71]" {
		t.Errorf("connections = %v", got)
	}
	if !out.To.Equal(time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)) || out.Mode != "file" {
		t.Errorf("to=%v mode=%s", out.To, out.Mode)
	}
	if !strings.Contains(strings.Join(out.Notes, " "), "capture file") {
		t.Errorf("notes should explain replay timing: %v", out.Notes)
	}
}

func TestRecentConnectionsSanitizesHostNames(t *testing.T) {
	var out RecentConnectionsOutput
	call(t, connect(t, liveSource()), "get_recent_connections", map[string]any{"host": "203.0.113.50"}, &out)
	if len(out.Connections) != 1 || out.Connections[0].Host != "ignore-previous-instructions?[2J.example.test" {
		t.Errorf("connections = %+v", out.Connections)
	}
}

func TestRecentConnectionsRejectsBadInput(t *testing.T) {
	for _, args := range []map[string]any{
		{"minutes": 0},
		{"minutes": -5},
		{"minutes": recentMinutesMax + 1},
		{"minutes": "15"},
		{"minutes": 1.5},
		{"limit": 0},
		{"limit": recentLimitMax + 1},
		{"host": "has space"},
		{"host": "x;rm -rf"},
		{"host": "evil\x1b[2J"},
		{"host": strings.Repeat("a", maxHostLen+1)},
		{"process": "chrome"}, // Network Sentinel has no process data; unknown arguments are refused
	} {
		rejects(t, "get_recent_connections", args)
	}
}

func TestRecentConnectionsReportsSentinelErrors(t *testing.T) {
	src := &stubSource{err: fmt.Errorf("%w at http://127.0.0.1:8787", sentinel.ErrNotRunning)}
	res := call(t, connect(t, src), "get_recent_connections", nil, nil)
	if msg := errorText(t, res); !strings.Contains(msg, "can't reach Network Sentinel") {
		t.Errorf("error = %q", msg)
	}
}

func TestRecentConnectionsNormalize(t *testing.T) {
	in := RecentConnectionsInput{Host: "  github  "}
	if err := in.normalize(); err != nil {
		t.Fatal(err)
	}
	if in.Minutes != recentMinutesDefault || in.Limit != recentLimitDefault || in.Host != "github" {
		t.Errorf("normalize = %+v", in)
	}
	for _, bad := range []RecentConnectionsInput{{Minutes: -1}, {Minutes: recentMinutesMax + 1}, {Limit: -1}, {Limit: recentLimitMax + 1}, {Host: "a/b"}} {
		if err := bad.normalize(); err == nil {
			t.Errorf("normalize accepted %+v", bad)
		}
	}
}
