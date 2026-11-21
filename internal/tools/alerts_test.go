package tools

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func alertIDs(as []AlertView) []int {
	out := make([]int, len(as))
	for i, a := range as {
		out[i] = a.ID
	}
	return out
}

func getAlerts(t *testing.T, src Source, args map[string]any) AlertsOutput {
	t.Helper()
	var out AlertsOutput
	res := call(t, connect(t, src), "get_alerts", args, &out)
	if res.IsError {
		t.Fatalf("get_alerts(%v): %s", args, errorText(t, res))
	}
	return out
}

func TestAlertsDefaults(t *testing.T) {
	out := getAlerts(t, liveSource(), nil)
	// Last 24 hours, every severity, most recently seen first.
	if got, want := fmt.Sprint(alertIDs(out.Alerts)), "[1 10 11 8 9 7 6 5 4 3 2]"; got != want {
		t.Errorf("ids = %s, want %s", got, want)
	}
	if !out.From.Equal(time.Date(2026, 1, 14, 15, 0, 0, 0, time.UTC)) || out.MinSeverity != "" || out.Truncated {
		t.Errorf("from=%v min=%q truncated=%v", out.From, out.MinSeverity, out.Truncated)
	}
	if got := fmt.Sprint(out.CountsBySeverity); got != "map[high:3 info:2 low:2 medium:4]" {
		t.Errorf("counts = %s", got)
	}
}

func TestAlertsFields(t *testing.T) {
	out := getAlerts(t, liveSource(), map[string]any{"severity": "high", "limit": 1})
	want := AlertView{
		ID: 9, Severity: "high", Rule: "cleartext-credentials", Title: "Password sent in cleartext",
		Detail: `HTTP Basic auth (user "admin", password hidden) sent unencrypted to legacy.example.org:80`,
		IP:     "198.51.100.30", Host: "legacy.example.org", Port: 80, Protocol: "TCP",
		FirstSeen: time.Date(2026, 1, 15, 14, 50, 10, 0, time.UTC), LastSeen: time.Date(2026, 1, 15, 14, 50, 40, 0, time.UTC), Count: 3,
	}
	if len(out.Alerts) != 1 || fmt.Sprintf("%+v", out.Alerts[0]) != fmt.Sprintf("%+v", want) {
		t.Errorf("alert =\n%+v\nwant\n%+v", out.Alerts, want)
	}
}

func TestAlertsSeverityIsAMinimum(t *testing.T) {
	for sev, want := range map[string]string{
		"high":   "[9 6 2]",
		"medium": "[10 9 7 6 5 3 2]",
		"low":    "[10 11 8 9 7 6 5 3 2]",
		"info":   "[1 10 11 8 9 7 6 5 4 3 2]",
	} {
		out := getAlerts(t, liveSource(), map[string]any{"severity": sev})
		if got := fmt.Sprint(alertIDs(out.Alerts)); got != want {
			t.Errorf("severity %s: ids = %s, want %s", sev, got, want)
		}
		if out.MinSeverity != sev {
			t.Errorf("min_severity = %q", out.MinSeverity)
		}
	}
}

func TestAlertsSince(t *testing.T) {
	for since, want := range map[string]string{
		"1h":                        "[1 10 11 8 9 7 6 5 4]",
		"90m":                       "[1 10 11 8 9 7 6 5 4 3]",
		"1d":                        "[1 10 11 8 9 7 6 5 4 3 2]",
		"2026-01-15T14:45:00Z":      "[1 10 11 8 9 7]", // inclusive
		"2026-01-15T09:45:00-05:00": "[1 10 11 8 9 7]", // same instant, another zone
	} {
		out := getAlerts(t, liveSource(), map[string]any{"since": since})
		if got := fmt.Sprint(alertIDs(out.Alerts)); got != want {
			t.Errorf("since %s: ids = %s, want %s", since, got, want)
		}
	}
}

func TestAlertsLimit(t *testing.T) {
	out := getAlerts(t, liveSource(), map[string]any{"limit": 2})
	if fmt.Sprint(alertIDs(out.Alerts)) != "[1 10]" || out.Matched != 11 || !out.Truncated {
		t.Errorf("ids=%v matched=%d truncated=%v", alertIDs(out.Alerts), out.Matched, out.Truncated)
	}
	if out.CountsBySeverity["high"] != 3 {
		t.Error("counts should cover every match, not just the returned page")
	}
}

func TestAlertsSaysWhenOlderAlertsAreMissing(t *testing.T) {
	out := getAlerts(t, liveSource(), nil)
	if !strings.Contains(strings.Join(out.Notes, " "), "holds 49 alerts but shares only the 11 newest") {
		t.Errorf("notes = %v", out.Notes)
	}
}

func TestAlertsSanitizesNetworkText(t *testing.T) {
	out := getAlerts(t, liveSource(), map[string]any{"limit": 3})
	a := out.Alerts[2] // id 11, the booby-trapped one
	if a.ID != 11 || a.Detail != "Click?]8;;http://evil.test? here" || a.Host != "ignore-previous-instructions?[2J.example.test" {
		t.Errorf("alert 11 = %+v", a)
	}
}

func TestAlertsReplayUsesCaptureClock(t *testing.T) {
	out := getAlerts(t, replaySource(), map[string]any{"since": "1h"})
	if fmt.Sprint(alertIDs(out.Alerts)) != "[1 2]" || !strings.Contains(strings.Join(out.Notes, " "), "capture file") {
		t.Errorf("ids=%v notes=%v", alertIDs(out.Alerts), out.Notes)
	}
}

func TestAlertsRejectsBadInput(t *testing.T) {
	for _, args := range []map[string]any{
		{"severity": "critical"},
		{"severity": "HIGH"},
		{"since": "yesterday"},
		{"since": "-1h"},
		{"since": "0s"},
		{"since": "31d"},
		{"since": "721h"},
		{"since": "1 h"},
		{"since": "9999999999d"},
		{"since": strings.Repeat("1", sinceMaxLen+1)},
		{"limit": 0},
		{"limit": alertsLimitMax + 1},
		{"rule": "dns-tunnel"},
	} {
		rejects(t, "get_alerts", args)
	}
}

func TestAlertsRejectsTimesOutsideTheWindow(t *testing.T) {
	cs := connect(t, liveSource())
	for since, want := range map[string]string{
		"2025-12-01T00:00:00Z": "at most 30 days",
		"2026-02-01T00:00:00Z": "later than Network Sentinel's current time",
	} {
		res := call(t, cs, "get_alerts", map[string]any{"since": since}, nil)
		if msg := errorText(t, res); !strings.Contains(msg, want) {
			t.Errorf("since %s: error %q, want %q", since, msg, want)
		}
	}
}
