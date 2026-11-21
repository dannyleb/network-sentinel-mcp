package tools

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dannyleb/network-sentinel-mcp/internal/sentinel"
)

const (
	alertIDMax = math.MaxInt32
	relatedMax = 10
)

// ExplainAlertInput is the input to explain_alert.
type ExplainAlertInput struct {
	AlertID int `json:"alert_id"`
}

func (in *ExplainAlertInput) normalize() error {
	if in.AlertID < 1 || in.AlertID > alertIDMax {
		return fmt.Errorf("alert_id must be between 1 and %d; get it from get_alerts", alertIDMax)
	}
	return nil
}

// ExplainAlertOutput is the result of explain_alert.
type ExplainAlertOutput struct {
	Alert              AlertView    `json:"alert"`
	Rule               Rule         `json:"rule" jsonschema:"what the rule detects, why it matters, common harmless causes, and what to check next"`
	RelatedConnections []Connection `json:"related_connections" jsonschema:"connections to the alert's IP or host, most recent first (at most 10)"`
	RelatedDNS         []DNSLookup  `json:"related_dns" jsonschema:"DNS lookups of the alert's host or answering with its IP, newest first (at most 10)"`
	RelatedAlerts      []AlertView  `json:"related_alerts" jsonschema:"other alerts about the same IP or host, most recent first (at most 10)"`
	Notes              []string     `json:"notes,omitempty"`
}

// DNSLookup is one DNS query seen by Network Sentinel.
type DNSLookup struct {
	Time     time.Time `json:"time"`
	Name     string    `json:"name" jsonschema:"name looked up; observed network data"`
	Type     string    `json:"type" jsonschema:"record type, such as A, AAAA or TXT"`
	Resolver string    `json:"resolver" jsonschema:"DNS server the query went to"`
	Answers  []string  `json:"answers" jsonschema:"addresses in the reply, if one was seen"`
}

func addExplainAlert(s *mcp.Server, src Source) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "explain_alert",
		Description: "Explain one alert in depth: the rule behind it (what it detects, why it matters, common harmless causes, what to check next), " +
			"plus the connections, DNS lookups and other alerts involving the same IP or host. Takes an id from get_alerts. " +
			"Works only from data already on this machine; it never looks anything up online.",
		InputSchema: object(schema{
			"alert_id": integer("The alert's id, from get_alerts. IDs restart from 1 whenever Network Sentinel restarts.", 1, alertIDMax),
		}, "alert_id"),
		Annotations: readOnlyTool("Explain alert"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ExplainAlertInput) (*mcp.CallToolResult, ExplainAlertOutput, error) {
		if err := in.normalize(); err != nil {
			return nil, ExplainAlertOutput{}, err
		}
		snap, err := src.Snapshot(ctx)
		if err != nil {
			return nil, ExplainAlertOutput{}, err
		}
		out, err := explainAlert(snap, in.AlertID)
		return nil, out, err
	})
}

func explainAlert(snap *sentinel.Snapshot, id int) (ExplainAlertOutput, error) {
	idx := slices.IndexFunc(snap.Alerts, func(a sentinel.Alert) bool { return a.ID == id })
	if idx < 0 {
		return ExplainAlertOutput{}, fmt.Errorf("alert %d isn't in Network Sentinel's current snapshot. It shares only its %d newest alerts, "+
			"and alert IDs restart from 1 whenever it restarts. Call get_alerts for current IDs", id, len(snap.Alerts))
	}
	alert := snap.Alerts[idx]
	ip := alert.Remote
	host := strings.ToLower(alert.Host)

	rule, known := ruleByID(alert.Rule, alert.Severity)
	out := ExplainAlertOutput{
		Alert:              toAlertView(alert),
		Rule:               rule,
		RelatedConnections: []Connection{},
		RelatedDNS:         []DNSLookup{},
		RelatedAlerts:      []AlertView{},
	}
	if !known {
		out.Notes = append(out.Notes, fmt.Sprintf("network-sentinel-mcp doesn't know the rule %q.", out.Rule.ID))
	}

	var flows []sentinel.Flow
	for _, f := range snap.Flows {
		if (ip != "" && f.Remote == ip) || sameOrSubdomain(f.Host, host) {
			flows = append(flows, f)
		}
	}
	sort.SliceStable(flows, func(i, j int) bool { return flows[i].Last.After(flows[j].Last) })
	for _, f := range flows[:min(len(flows), relatedMax)] {
		out.RelatedConnections = append(out.RelatedConnections, toConnection(f))
	}

	for _, d := range snap.DNS { // already newest first
		if len(out.RelatedDNS) == relatedMax {
			break
		}
		if sameOrSubdomain(d.Name, host) || (ip != "" && slices.Contains(d.Answers, ip)) {
			out.RelatedDNS = append(out.RelatedDNS, DNSLookup{
				Time:     stamp(d.Time),
				Name:     clean(d.Name, maxHostLen),
				Type:     clean(d.Type, maxShortLen),
				Resolver: clean(d.Resolver, maxShortLen),
				Answers:  cleanList(d.Answers, maxShortLen),
			})
		}
	}

	var others []sentinel.Alert
	for _, a := range snap.Alerts {
		if a.ID != id && ((ip != "" && a.Remote == ip) || sameOrSubdomain(a.Host, host)) {
			others = append(others, a)
		}
	}
	sort.SliceStable(others, func(i, j int) bool { return others[i].Last.After(others[j].Last) })
	for _, a := range others[:min(len(others), relatedMax)] {
		out.RelatedAlerts = append(out.RelatedAlerts, toAlertView(a))
	}

	if ip != "" && len(flows) == 0 {
		out.Notes = append(out.Notes, "No connection to this IP is in Network Sentinel's snapshot. It may be on the local network, "+
			"or no longer among the connections Network Sentinel shares.")
	}
	return out, nil
}

// sameOrSubdomain reports whether name is host or a subdomain of it, ignoring case.
func sameOrSubdomain(name, host string) bool {
	if host == "" || name == "" {
		return false
	}
	name = strings.ToLower(name)
	return name == host || strings.HasSuffix(name, "."+host)
}
