package tools

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dannyleb/network-sentinel-mcp/internal/sentinel"
)

const (
	recentMinutesDefault = 15
	recentMinutesMax     = 24 * 60
	recentLimitDefault   = 50
	recentLimitMax       = 200

	// A host filter is a fragment of a DNS name or an IPv4/IPv6 address.
	hostFilterPattern = `^[A-Za-z0-9._:-]*$`
)

var hostFilterRE = regexp.MustCompile(hostFilterPattern)

// RecentConnectionsInput is the input to get_recent_connections.
type RecentConnectionsInput struct {
	Minutes int    `json:"minutes,omitempty"`
	Host    string `json:"host,omitempty"`
	Limit   int    `json:"limit,omitempty"`
}

func (in *RecentConnectionsInput) normalize() error {
	if in.Minutes == 0 {
		in.Minutes = recentMinutesDefault
	}
	if in.Limit == 0 {
		in.Limit = recentLimitDefault
	}
	if in.Minutes < 1 || in.Minutes > recentMinutesMax {
		return fmt.Errorf("minutes must be between 1 and %d", recentMinutesMax)
	}
	if in.Limit < 1 || in.Limit > recentLimitMax {
		return fmt.Errorf("limit must be between 1 and %d", recentLimitMax)
	}
	return checkHostFilter(&in.Host)
}

func checkHostFilter(h *string) error {
	*h = strings.TrimSpace(*h)
	if len(*h) > maxHostLen || !hostFilterRE.MatchString(*h) {
		return fmt.Errorf(`host may contain only letters, digits, ".", "-", "_" and ":" (at most %d characters)`, maxHostLen)
	}
	return nil
}

// RecentConnectionsOutput is the result of get_recent_connections.
type RecentConnectionsOutput struct {
	From        time.Time    `json:"from" jsonschema:"start of the window"`
	To          time.Time    `json:"to" jsonschema:"end of the window: Network Sentinel's clock, which is the last packet's time when it replays a capture file"`
	Mode        string       `json:"mode" jsonschema:"live (capturing now) or file (replaying a capture)"`
	Matched     int          `json:"matched" jsonschema:"connections that matched before the limit was applied"`
	Truncated   bool         `json:"truncated" jsonschema:"true when more connections matched than the limit allowed"`
	Connections []Connection `json:"connections" jsonschema:"most recently active first"`
	Notes       []string     `json:"notes,omitempty" jsonschema:"caveats about completeness"`
}

// Connection is what Network Sentinel knows about traffic between this machine
// and one remote IP, port and protocol.
type Connection struct {
	Host       string    `json:"host,omitempty" jsonschema:"name learned from DNS, the TLS server name or the HTTP Host header; observed network data"`
	HostSource string    `json:"host_source,omitempty" jsonschema:"where the name came from: dns, sni or http"`
	IP         string    `json:"ip" jsonschema:"remote IP address"`
	Port       int       `json:"port" jsonschema:"remote port"`
	Protocol   string    `json:"protocol" jsonschema:"TCP or UDP"`
	Service    string    `json:"service,omitempty" jsonschema:"service implied by the port, such as HTTPS or QUIC/HTTP3"`
	BytesOut   uint64    `json:"bytes_out" jsonschema:"bytes sent by this machine"`
	BytesIn    uint64    `json:"bytes_in" jsonschema:"bytes received"`
	Upload     string    `json:"upload" jsonschema:"bytes_out, human-readable"`
	Download   string    `json:"download" jsonschema:"bytes_in, human-readable"`
	PacketsOut uint64    `json:"packets_out"`
	PacketsIn  uint64    `json:"packets_in"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Alerts     int       `json:"alerts" jsonschema:"alerts raised about this remote IP while the connection was tracked"`
}

func toConnection(f sentinel.Flow) Connection {
	return Connection{
		Host:       clean(f.Host, maxHostLen),
		HostSource: clean(f.HostSrc, maxShortLen),
		IP:         clean(f.Remote, maxShortLen),
		Port:       int(f.Port),
		Protocol:   clean(f.Proto, maxShortLen),
		Service:    clean(f.Service, maxShortLen),
		BytesOut:   f.BytesOut,
		BytesIn:    f.BytesIn,
		Upload:     humanBytes(f.BytesOut),
		Download:   humanBytes(f.BytesIn),
		PacketsOut: f.PktsOut,
		PacketsIn:  f.PktsIn,
		FirstSeen:  stamp(f.First),
		LastSeen:   stamp(f.Last),
		Alerts:     f.Alerts,
	}
}

func addRecentConnections(s *mcp.Server, src Source) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "get_recent_connections",
		Description: "List this machine's network connections that were active in the last N minutes, most recent first. " +
			"Each entry is one remote IP, port and protocol, with the host name Network Sentinel learned for it, bytes and packets in each direction, " +
			"when it was first and last seen, and how many alerts involve it. Use `host` to narrow to a site or address. " +
			"Network Sentinel can't see which app or process opened a connection.",
		InputSchema: object(schema{
			"minutes": integer("How far back to look, in minutes: 1 to 1440, default 15.", 1, recentMinutesMax),
			"host": text(`Only connections whose host name or IP contains this text, ignoring case, e.g. "github" or "203.0.113.". `+
				`Letters, digits, ".", "-", "_" and ":" only.`, maxHostLen, hostFilterPattern),
			"limit": integer("Most connections to return: 1 to 200, default 50.", 1, recentLimitMax),
		}),
		Annotations: readOnlyTool("Recent connections"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in RecentConnectionsInput) (*mcp.CallToolResult, RecentConnectionsOutput, error) {
		if err := in.normalize(); err != nil {
			return nil, RecentConnectionsOutput{}, err
		}
		snap, err := src.Snapshot(ctx)
		if err != nil {
			return nil, RecentConnectionsOutput{}, err
		}
		return nil, recentConnections(snap, in), nil
	})
}

func recentConnections(snap *sentinel.Snapshot, in RecentConnectionsInput) RecentConnectionsOutput {
	to := snap.Clock()
	from := to.Add(-time.Duration(in.Minutes) * time.Minute)
	needle := strings.ToLower(in.Host)

	var matches []sentinel.Flow
	for _, f := range snap.Flows {
		if f.Last.Before(from) {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(f.Host), needle) && !strings.Contains(strings.ToLower(f.Remote), needle) {
			continue
		}
		matches = append(matches, f)
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if !matches[i].Last.Equal(matches[j].Last) {
			return matches[i].Last.After(matches[j].Last)
		}
		return matches[i].BytesOut > matches[j].BytesOut
	})

	out := RecentConnectionsOutput{
		From:        stamp(from),
		To:          stamp(to),
		Mode:        clean(snap.Mode, maxShortLen),
		Matched:     len(matches),
		Connections: []Connection{},
	}
	for _, f := range matches {
		if len(out.Connections) == in.Limit {
			out.Truncated = true
			break
		}
		out.Connections = append(out.Connections, toConnection(f))
	}
	out.Notes = flowNotes(snap)
	if len(matches) == 0 && in.Host != "" {
		out.Notes = append(out.Notes, fmt.Sprintf("No connection in this window has a host name or IP containing %q. Try more minutes or a shorter search.", in.Host))
	}
	return out
}

// flowNotes explains the limits of a snapshot's flow list.
func flowNotes(snap *sentinel.Snapshot) []string {
	var notes []string
	if snap.Mode == "file" {
		notes = append(notes, "Network Sentinel is replaying a capture file, so times are from the capture and the window ends at its last packet, not at the current time.")
	}
	if snap.TotalDest > len(snap.Flows) {
		notes = append(notes, fmt.Sprintf("Network Sentinel is tracking %d connections but shares only the %d that sent the most data, so quieter connections may be missing.", snap.TotalDest, len(snap.Flows)))
	}
	return notes
}
