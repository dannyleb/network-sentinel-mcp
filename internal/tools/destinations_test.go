package tools

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func getTop(t *testing.T, src Source, args map[string]any) TopDestinationsOutput {
	t.Helper()
	var out TopDestinationsOutput
	res := call(t, connect(t, src), "get_top_destinations", args, &out)
	if res.IsError {
		t.Fatalf("get_top_destinations(%v): %s", args, errorText(t, res))
	}
	return out
}

func labels(ds []Destination) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.Host
		if d.Host == "" {
			out[i] = strings.Join(d.IPs, ",")
		}
	}
	return out
}

func TestTopDestinationsRanking(t *testing.T) {
	out := getTop(t, liveSource(), nil)
	want := []string{
		"api.example-ai.test", "video.example.com", "cdn.example.net", "legacy.example.org",
		"192.0.2.66", "tracker.bad-example.test", "router-admin.example.org", "ignore-previous-instructions?[2J.example.test",
	}
	if got := labels(out.Destinations); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("ranking = %v\nwant      %v", got, want)
	}
	if out.Total != 8 || out.Truncated || out.RankedBy != "bytes_out" {
		t.Errorf("total=%d truncated=%v ranked_by=%s", out.Total, out.Truncated, out.RankedBy)
	}
	for i, d := range out.Destinations {
		if d.Rank != i+1 {
			t.Errorf("destination %d has rank %d", i, d.Rank)
		}
	}
	if !out.CountingSince.Equal(time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("counting_since = %v", out.CountingSince)
	}
}

func TestTopDestinationsGroupsByHost(t *testing.T) {
	d := getTop(t, liveSource(), map[string]any{"limit": 1}).Destinations[0]
	want := Destination{
		Rank: 1, Host: "api.example-ai.test", IPs: []string{"203.0.113.10", "203.0.113.11"}, Ports: []int{443},
		Services: []string{"HTTPS"}, Connections: 2, BytesOut: 62914560, BytesIn: 1572864, Upload: "60.0 MB", Download: "1.5 MB",
		UploadShare: 95.9, FirstSeen: time.Date(2026, 1, 15, 14, 20, 0, 0, time.UTC), LastSeen: time.Date(2026, 1, 15, 14, 59, 58, 0, time.UTC),
		Alerts: 3,
	}
	if fmt.Sprintf("%+v", d) != fmt.Sprintf("%+v", want) {
		t.Errorf("destination =\n%+v\nwant\n%+v", d, want)
	}
}

func TestTopDestinationsWithoutAHostName(t *testing.T) {
	for _, d := range getTop(t, liveSource(), nil).Destinations {
		if d.Host == "" {
			if fmt.Sprint(d.IPs) != "[192.0.2.66]" || fmt.Sprint(d.Ports) != "[4444]" || len(d.Services) != 0 || d.Services == nil {
				t.Errorf("unnamed destination = %+v", d)
			}
			return
		}
	}
	t.Error("expected one destination without a host name")
}

func TestTopDestinationsLimit(t *testing.T) {
	out := getTop(t, liveSource(), map[string]any{"limit": 3})
	if len(out.Destinations) != 3 || out.Total != 8 || !out.Truncated {
		t.Errorf("returned=%d total=%d truncated=%v", len(out.Destinations), out.Total, out.Truncated)
	}
}

func TestTopDestinationsNotes(t *testing.T) {
	out := getTop(t, liveSource(), nil)
	if !strings.Contains(strings.Join(out.Notes, " "), "shares only the 9") {
		t.Errorf("notes = %v", out.Notes)
	}
	replay := getTop(t, replaySource(), nil)
	if fmt.Sprint(labels(replay.Destinations)) != "[backup.example.com files.example.org status.example.net]" {
		t.Errorf("replay ranking = %v", labels(replay.Destinations))
	}
	if !strings.Contains(strings.Join(replay.Notes, " "), "capture file") {
		t.Errorf("replay notes = %v", replay.Notes)
	}
}

func TestTopDestinationsRejectsBadInput(t *testing.T) {
	for _, args := range []map[string]any{
		{"limit": 0},
		{"limit": -1},
		{"limit": topLimitMax + 1},
		{"limit": "10"},
		{"sort_by": "bytes_in"},
	} {
		rejects(t, "get_top_destinations", args)
	}
}
