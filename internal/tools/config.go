package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dannyleb/network-sentinel-mcp/internal/sentinel"
)

// ConfigURI is the address of the configuration resource.
const ConfigURI = "sentinel://config"

// ConfigView is the content of the sentinel://config resource.
type ConfigView struct {
	Server     ServerView        `json:"server"`
	Sentinel   SentinelView      `json:"network_sentinel"`
	Rules      []RuleSummary     `json:"rules"`
	Limits     map[string]string `json:"input_limits"`
	NotExposed []string          `json:"not_exposed"`
}

// ServerView describes this MCP server.
type ServerView struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	ReadOnly    bool   `json:"read_only"`
	SentinelURL string `json:"network_sentinel_url"`
	TokenSource string `json:"token_source"`
}

// SentinelView is what Network Sentinel reports about itself right now.
type SentinelView struct {
	Reachable          bool           `json:"reachable"`
	Error              string         `json:"error,omitempty"`
	Mode               string         `json:"mode,omitempty"`
	Capturing          string         `json:"capturing,omitempty"`
	Started            *time.Time     `json:"started,omitempty"`
	Clock              *time.Time     `json:"clock,omitempty"`
	TrackedConnections int            `json:"tracked_connections"`
	ActiveConnections  int            `json:"active_connections"`
	AlertCounts        map[string]int `json:"alert_counts,omitempty"`
	AIGateway          string         `json:"ai_gateway,omitempty"`
	AILogStatus        string         `json:"ai_log_status,omitempty"`
}

// RuleSummary is one line of the rule catalog. explain_alert has the full entry.
type RuleSummary struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Detects  string `json:"detects"`
}

func addConfigResource(s *mcp.Server, src Source, info Info) {
	s.AddResource(&mcp.Resource{
		URI:   ConfigURI,
		Name:  "config",
		Title: "Network Sentinel status and rules",
		Description: "What Network Sentinel is monitoring right now (interfaces or capture file, start time, AI gateway), " +
			"every alert rule it can raise and what each detects, and this server's input limits.",
		MIMEType: "application/json",
	}, func(ctx context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		b, err := json.MarshalIndent(buildConfig(ctx, src, info), "", "  ")
		if err != nil {
			return nil, err
		}
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{
			{URI: ConfigURI, MIMEType: "application/json", Text: string(b)},
		}}, nil
	})
}

// buildConfig always succeeds: if Network Sentinel is down, the rules and
// limits are still useful, and the error says why the status is missing.
func buildConfig(ctx context.Context, src Source, info Info) ConfigView {
	v := ConfigView{
		Server: ServerView{
			Name:        ServerName,
			Version:     info.Version,
			ReadOnly:    true,
			SentinelURL: info.SentinelURL,
			TokenSource: info.TokenSource,
		},
		Rules:  make([]RuleSummary, 0, len(rules)),
		Limits: inputLimits(),
		NotExposed: []string{
			"the large-upload threshold (netsentinel -upload-mb)",
			"which blocklists are loaded",
			"whether metadata-only mode is on",
		},
	}
	for _, r := range rules {
		v.Rules = append(v.Rules, RuleSummary{ID: r.ID, Severity: r.Severity, Detects: r.Detects})
	}

	snap, err := src.Snapshot(ctx)
	if err != nil {
		v.Sentinel = SentinelView{Error: err.Error()}
		return v
	}
	started, clock := stamp(snap.Started), stamp(snap.Clock())
	v.Sentinel = SentinelView{
		Reachable:          true,
		Mode:               clean(snap.Mode, maxShortLen),
		Capturing:          clean(snap.Iface, maxTitleLen),
		Started:            &started,
		Clock:              &clock,
		TrackedConnections: snap.TotalDest,
		ActiveConnections:  snap.ActiveDest,
		AlertCounts:        map[string]int{},
		AIGateway:          clean(snap.AI.Gateway, maxShortLen),
		AILogStatus:        clean(snap.AI.LogStatus, maxTitleLen),
	}
	for sev, n := range snap.AlertCounts {
		v.Sentinel.AlertCounts[clean(sev, maxShortLen)] = n
	}
	return v
}

// inputLimits is generated from the same constants the tools enforce.
func inputLimits() map[string]string {
	span := func(hi, def int) string { return fmt.Sprintf("1 to %d, default %d", hi, def) }
	return map[string]string{
		"get_recent_connections.minutes": span(recentMinutesMax, recentMinutesDefault),
		"get_recent_connections.limit":   span(recentLimitMax, recentLimitDefault),
		"get_recent_connections.host":    fmt.Sprintf("up to %d characters: letters, digits, '.', '-', '_' and ':'", maxHostLen),
		"get_alerts.severity":            "high, medium, low or info (a minimum)",
		"get_alerts.since":               fmt.Sprintf("a duration or an RFC 3339 time, at most %d days back, default 24h", int(alertsSinceMax/(24*time.Hour))),
		"get_alerts.limit":               span(alertsLimitMax, alertsLimitDefault),
		"get_top_destinations.limit":     span(topLimitMax, topLimitDefault),
		"explain_alert.alert_id":         fmt.Sprintf("1 to %d, required", alertIDMax),
		"network_sentinel.timeout":       sentinel.DefaultTimeout.String(),
		"network_sentinel.max_response":  humanBytes(sentinel.DefaultMaxBytes),
	}
}
