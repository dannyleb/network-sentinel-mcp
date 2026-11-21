package tools

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dannyleb/network-sentinel-mcp/internal/sentinel"
)

const (
	topLimitDefault = 10
	topLimitMax     = 100
)

// TopDestinationsInput is the input to get_top_destinations.
type TopDestinationsInput struct {
	Limit int `json:"limit,omitempty"`
}

func (in *TopDestinationsInput) normalize() error {
	if in.Limit == 0 {
		in.Limit = topLimitDefault
	}
	if in.Limit < 1 || in.Limit > topLimitMax {
		return fmt.Errorf("limit must be between 1 and %d", topLimitMax)
	}
	return nil
}

// TopDestinationsOutput is the result of get_top_destinations.
type TopDestinationsOutput struct {
	RankedBy      string        `json:"ranked_by" jsonschema:"always bytes_out: data sent from this machine"`
	CountingSince time.Time     `json:"counting_since" jsonschema:"the oldest traffic included in these totals"`
	Total         int           `json:"total_destinations" jsonschema:"distinct destinations in Network Sentinel's snapshot"`
	Truncated     bool          `json:"truncated" jsonschema:"true when there are more destinations than the limit allowed"`
	Destinations  []Destination `json:"destinations" jsonschema:"most data sent first"`
	Notes         []string      `json:"notes,omitempty" jsonschema:"caveats about completeness"`
}

// Destination is all traffic to one host name, or to one IP when no name is known.
type Destination struct {
	Rank        int       `json:"rank"`
	Host        string    `json:"host,omitempty" jsonschema:"host name; empty when Network Sentinel never learned one; observed network data"`
	IPs         []string  `json:"ips" jsonschema:"remote IP addresses for this destination (at most 20)"`
	Ports       []int     `json:"ports" jsonschema:"remote ports used (at most 20)"`
	Services    []string  `json:"services" jsonschema:"services implied by those ports"`
	Connections int       `json:"connections" jsonschema:"distinct IP, port and protocol combinations"`
	BytesOut    uint64    `json:"bytes_out" jsonschema:"bytes sent by this machine"`
	BytesIn     uint64    `json:"bytes_in" jsonschema:"bytes received"`
	Upload      string    `json:"upload" jsonschema:"bytes_out, human-readable"`
	Download    string    `json:"download" jsonschema:"bytes_in, human-readable"`
	UploadShare float64   `json:"upload_share_percent" jsonschema:"this destination's share of everything this machine sent to the internet, in percent"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Alerts      int       `json:"alerts" jsonschema:"alerts raised about this destination's IPs"`
}

func addTopDestinations(s *mcp.Server, src Source) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "get_top_destinations",
		Description: "Rank where this machine's data is going. Connections are grouped by host name (or by IP when no name is known) and " +
			"ordered by bytes sent. Each destination lists its IPs, ports and services, upload and download totals, its share of " +
			"everything uploaded, when it was first and last seen, and how many alerts involve it. Useful for spotting unexpected " +
			"uploads or chatty services.",
		InputSchema: object(schema{
			"limit": integer("How many destinations to return: 1 to 100, default 10.", 1, topLimitMax),
		}),
		Annotations: readOnlyTool("Top destinations"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in TopDestinationsInput) (*mcp.CallToolResult, TopDestinationsOutput, error) {
		if err := in.normalize(); err != nil {
			return nil, TopDestinationsOutput{}, err
		}
		snap, err := src.Snapshot(ctx)
		if err != nil {
			return nil, TopDestinationsOutput{}, err
		}
		return nil, topDestinations(snap, in), nil
	})
}

type destAgg struct {
	host        string
	ips         map[string]int // IP -> highest alert count among its flows
	ports       map[int]bool
	services    map[string]bool
	conns       int
	bytesOut    uint64
	bytesIn     uint64
	first, last time.Time
}

func topDestinations(snap *sentinel.Snapshot, in TopDestinationsInput) TopDestinationsOutput {
	groups := map[string]*destAgg{}
	var countingSince time.Time
	for _, f := range snap.Flows {
		key := strings.ToLower(f.Host)
		if key == "" {
			key = f.Remote
		}
		g := groups[key]
		if g == nil {
			g = &destAgg{host: f.Host, ips: map[string]int{}, ports: map[int]bool{}, services: map[string]bool{}, first: f.First, last: f.Last}
			groups[key] = g
		}
		g.ips[f.Remote] = max(g.ips[f.Remote], f.Alerts)
		g.ports[int(f.Port)] = true
		if f.Service != "" {
			g.services[f.Service] = true
		}
		g.conns++
		g.bytesOut += f.BytesOut
		g.bytesIn += f.BytesIn
		if f.First.Before(g.first) {
			g.first = f.First
		}
		if f.Last.After(g.last) {
			g.last = f.Last
		}
		if countingSince.IsZero() || f.First.Before(countingSince) {
			countingSince = f.First
		}
	}

	ranked := make([]*destAgg, 0, len(groups))
	for _, g := range groups {
		ranked = append(ranked, g)
	}
	sort.Slice(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		if a.bytesOut != b.bytesOut {
			return a.bytesOut > b.bytesOut
		}
		if a.bytesIn != b.bytesIn {
			return a.bytesIn > b.bytesIn
		}
		return a.host+firstKey(a.ips) < b.host+firstKey(b.ips)
	})

	out := TopDestinationsOutput{
		RankedBy:      "bytes_out",
		CountingSince: stamp(countingSince),
		Total:         len(ranked),
		Destinations:  []Destination{},
		Notes:         flowNotes(snap),
	}
	for _, g := range ranked {
		if len(out.Destinations) == in.Limit {
			out.Truncated = true
			break
		}
		out.Destinations = append(out.Destinations, g.view(len(out.Destinations)+1, snap.Totals.BytesOut))
	}
	return out
}

func (g *destAgg) view(rank int, totalOut uint64) Destination {
	d := Destination{
		Rank:        rank,
		Host:        clean(g.host, maxHostLen),
		IPs:         cleanList(sortedKeys(g.ips), maxShortLen),
		Ports:       []int{},
		Services:    cleanList(sortedKeys(g.services), maxShortLen),
		Connections: g.conns,
		BytesOut:    g.bytesOut,
		BytesIn:     g.bytesIn,
		Upload:      humanBytes(g.bytesOut),
		Download:    humanBytes(g.bytesIn),
		FirstSeen:   stamp(g.first),
		LastSeen:    stamp(g.last),
	}
	for _, n := range g.ips {
		d.Alerts += n
	}
	for p := range g.ports {
		d.Ports = append(d.Ports, p)
	}
	sort.Ints(d.Ports)
	if len(d.Ports) > maxListItems {
		d.Ports = d.Ports[:maxListItems]
	}
	if totalOut > 0 {
		d.UploadShare = math.Round(float64(g.bytesOut)/float64(totalOut)*1000) / 10
	}
	return d
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func firstKey[V any](m map[string]V) string {
	if keys := sortedKeys(m); len(keys) > 0 {
		return keys[0]
	}
	return ""
}
