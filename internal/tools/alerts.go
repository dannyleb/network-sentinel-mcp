package tools

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dannyleb/network-sentinel-mcp/internal/sentinel"
)

const (
	alertsLimitDefault = 50
	alertsLimitMax     = 300 // Network Sentinel shares at most its 300 newest alerts
	alertsSinceDefault = 24 * time.Hour
	alertsSinceMax     = 30 * 24 * time.Hour
	sinceMaxLen        = 40
	sincePattern       = `^[0-9A-Za-z:.+-]*$`
)

// severities from most to least serious.
var severities = []string{"high", "medium", "low", "info"}

var severityRank = map[string]int{"high": 3, "medium": 2, "low": 1, "info": 0}

var errSinceFormat = errors.New(`since must be a duration such as "30m", "2h" or "7d", or an RFC 3339 time such as "2026-01-15T09:00:00Z"`)

// AlertsInput is the input to get_alerts.
type AlertsInput struct {
	Severity string `json:"severity,omitempty"`
	Since    string `json:"since,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

func (in *AlertsInput) normalize() error {
	if in.Limit == 0 {
		in.Limit = alertsLimitDefault
	}
	if in.Limit < 1 || in.Limit > alertsLimitMax {
		return fmt.Errorf("limit must be between 1 and %d", alertsLimitMax)
	}
	if _, ok := severityRank[in.Severity]; in.Severity != "" && !ok {
		return fmt.Errorf("severity must be one of %s", strings.Join(severities, ", "))
	}
	in.Since = strings.TrimSpace(in.Since)
	if len(in.Since) > sinceMaxLen {
		return errSinceFormat
	}
	if d, ok := parseDuration(in.Since); ok {
		return checkLookback(d)
	}
	if in.Since != "" {
		if _, err := time.Parse(time.RFC3339, in.Since); err != nil {
			return errSinceFormat
		}
	}
	return nil
}

// sinceTime resolves Since against Network Sentinel's clock.
func (in *AlertsInput) sinceTime(clock time.Time) (time.Time, error) {
	if in.Since == "" {
		return clock.Add(-alertsSinceDefault), nil
	}
	if d, ok := parseDuration(in.Since); ok {
		if err := checkLookback(d); err != nil {
			return time.Time{}, err
		}
		return clock.Add(-d), nil
	}
	t, err := time.Parse(time.RFC3339, in.Since)
	if err != nil {
		return time.Time{}, errSinceFormat
	}
	if t.After(clock) {
		return time.Time{}, fmt.Errorf("since is later than Network Sentinel's current time (%s)", clock.Format(time.RFC3339))
	}
	if err := checkLookback(clock.Sub(t)); err != nil {
		return time.Time{}, err
	}
	return t, nil
}

func checkLookback(d time.Duration) error {
	if d <= 0 {
		return errors.New("since must be a positive duration")
	}
	if d > alertsSinceMax {
		return errors.New("since can reach back at most 30 days")
	}
	return nil
}

// parseDuration accepts Go durations ("90m", "2h30m") plus whole days ("7d").
func parseDuration(s string) (time.Duration, bool) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil {
			return 0, false
		}
		if n > 365 { // avoid overflow; anything this large is rejected anyway
			n = 365
		}
		return time.Duration(n) * 24 * time.Hour, true
	}
	d, err := time.ParseDuration(s)
	return d, err == nil
}

// AlertsOutput is the result of get_alerts.
type AlertsOutput struct {
	From             time.Time      `json:"from" jsonschema:"only alerts last seen at or after this time"`
	To               time.Time      `json:"to" jsonschema:"Network Sentinel's clock"`
	MinSeverity      string         `json:"min_severity,omitempty" jsonschema:"the severity filter, if any"`
	Matched          int            `json:"matched" jsonschema:"alerts that matched before the limit was applied"`
	Truncated        bool           `json:"truncated" jsonschema:"true when more alerts matched than the limit allowed"`
	CountsBySeverity map[string]int `json:"counts_by_severity" jsonschema:"matching alerts per severity, before the limit"`
	Alerts           []AlertView    `json:"alerts" jsonschema:"most recently seen first"`
	Notes            []string       `json:"notes,omitempty" jsonschema:"caveats about completeness"`
}

// AlertView is one alert as shown to a model.
type AlertView struct {
	ID        int       `json:"id" jsonschema:"pass to explain_alert; IDs restart from 1 whenever Network Sentinel restarts"`
	Severity  string    `json:"severity" jsonschema:"high, medium, low or info"`
	Rule      string    `json:"rule" jsonschema:"detection rule; sentinel://config describes each one"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail" jsonschema:"what was seen; quotes observed network data, with secrets already redacted by Network Sentinel"`
	IP        string    `json:"ip,omitempty" jsonschema:"remote IP address involved, if any"`
	Host      string    `json:"host,omitempty" jsonschema:"host name involved, if any"`
	Port      int       `json:"port,omitempty"`
	Protocol  string    `json:"protocol,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count" jsonschema:"times seen; repeats within 10 minutes are merged into one alert"`
}

func toAlertView(a sentinel.Alert) AlertView {
	return AlertView{
		ID:        a.ID,
		Severity:  clean(a.Severity, maxShortLen),
		Rule:      clean(a.Rule, maxShortLen),
		Title:     clean(a.Title, maxTitleLen),
		Detail:    clean(a.Detail, maxDetailLen),
		IP:        clean(a.Remote, maxShortLen),
		Host:      clean(a.Host, maxHostLen),
		Port:      int(a.Port),
		Protocol:  clean(a.Proto, maxShortLen),
		FirstSeen: stamp(a.First),
		LastSeen:  stamp(a.Last),
		Count:     a.Count,
	}
}

func addAlerts(s *mcp.Server, src Source) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "get_alerts",
		Description: "List Network Sentinel's alerts, most recently seen first: passwords or personal data sent unencrypted, " +
			"connections to blocklisted or suspicious destinations, unencrypted protocols, data hidden in DNS lookups, large uploads, " +
			"secrets sent to AI services, and more. Each alert has a severity, the rule that raised it, what was seen, and how often. " +
			"Filter by minimum severity and by time. Pass an alert's id to explain_alert for what it means and what to check next.",
		InputSchema: object(schema{
			"severity": oneOf(`Minimum severity to include: "high" returns only high, "medium" returns medium and high, and so on. Omit for all.`, severities...),
			"since": text(`Only alerts last seen within this period or after this time: a duration such as "30m", "2h" or "7d", `+
				`or an RFC 3339 time such as "2026-01-15T09:00:00Z". At most 30 days back; default "24h".`, sinceMaxLen, sincePattern),
			"limit": integer("Most alerts to return: 1 to 300, default 50.", 1, alertsLimitMax),
		}),
		Annotations: readOnlyTool("Alerts"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in AlertsInput) (*mcp.CallToolResult, AlertsOutput, error) {
		if err := in.normalize(); err != nil {
			return nil, AlertsOutput{}, err
		}
		snap, err := src.Snapshot(ctx)
		if err != nil {
			return nil, AlertsOutput{}, err
		}
		out, err := alerts(snap, in)
		return nil, out, err
	})
}

func alerts(snap *sentinel.Snapshot, in AlertsInput) (AlertsOutput, error) {
	to := snap.Clock()
	from, err := in.sinceTime(to)
	if err != nil {
		return AlertsOutput{}, err
	}
	minRank := -1
	if in.Severity != "" {
		minRank = severityRank[in.Severity]
	}

	out := AlertsOutput{
		From:             stamp(from),
		To:               stamp(to),
		MinSeverity:      in.Severity,
		CountsBySeverity: map[string]int{},
		Alerts:           []AlertView{},
	}
	for _, s := range severities {
		out.CountsBySeverity[s] = 0
	}

	var matches []sentinel.Alert
	for _, a := range snap.Alerts {
		rank, known := severityRank[a.Severity]
		if a.Last.Before(from) || (minRank >= 0 && (!known || rank < minRank)) {
			continue
		}
		matches = append(matches, a)
		out.CountsBySeverity[clean(a.Severity, maxShortLen)]++
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if !matches[i].Last.Equal(matches[j].Last) {
			return matches[i].Last.After(matches[j].Last)
		}
		return matches[i].ID > matches[j].ID
	})
	out.Matched = len(matches)
	for _, a := range matches {
		if len(out.Alerts) == in.Limit {
			out.Truncated = true
			break
		}
		out.Alerts = append(out.Alerts, toAlertView(a))
	}
	out.Notes = alertNotes(snap)
	return out, nil
}

// alertNotes explains the limits of a snapshot's alert list.
func alertNotes(snap *sentinel.Snapshot) []string {
	var notes []string
	if snap.Mode == "file" {
		notes = append(notes, "Network Sentinel is replaying a capture file, so times are from the capture, not the current time.")
	}
	total := 0
	for _, n := range snap.AlertCounts {
		total += n
	}
	if total > len(snap.Alerts) {
		notes = append(notes, fmt.Sprintf("Network Sentinel holds %d alerts but shares only the %d newest, so older ones aren't included.", total, len(snap.Alerts)))
	}
	return notes
}
