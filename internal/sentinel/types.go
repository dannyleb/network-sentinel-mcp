// Package sentinel is a read-only client for Network Sentinel's local dashboard API.
//
// The types mirror the JSON that GET /api/snapshot returns. They deliberately
// decode only the fields this server uses: anything else (this machine's own
// LAN address, AI request bodies, secret findings) is never even parsed.
package sentinel

import "time"

// Snapshot is one point-in-time view of Network Sentinel's in-memory state.
type Snapshot struct {
	Now         time.Time      `json:"now"`
	Started     time.Time      `json:"started"`
	Iface       string         `json:"iface"`
	Mode        string         `json:"mode"` // "live" or "file" (replaying a pcap)
	Totals      Totals         `json:"totals"`
	ActiveDest  int            `json:"activeDestinations"`
	TotalDest   int            `json:"totalDestinations"`
	Series      []Sample       `json:"series"`
	Flows       []Flow         `json:"flows"`  // top destinations by bytes sent (Network Sentinel caps this at 500)
	Alerts      []Alert        `json:"alerts"` // newest first (capped at 300)
	AlertCounts map[string]int `json:"alertCounts"`
	DNS         []DNSEntry     `json:"dns"` // newest first (capped at 150)
	AI          AIStatus       `json:"ai"`
}

// Totals are byte and packet counters since Network Sentinel started.
type Totals struct {
	PktsOut  uint64 `json:"pktsOut"`
	PktsIn   uint64 `json:"pktsIn"`
	BytesOut uint64 `json:"bytesOut"`
	BytesIn  uint64 `json:"bytesIn"`
	PktsLAN  uint64 `json:"pktsLan"`
	BytesLAN uint64 `json:"bytesLan"`
}

// Sample is one second of throughput. Only the timestamp is used here.
type Sample struct {
	T int64 `json:"t"`
}

// Flow is all traffic between this machine and one remote IP, port and protocol.
type Flow struct {
	Remote   string    `json:"remote"`
	Port     uint16    `json:"port"`
	Proto    string    `json:"proto"`
	Host     string    `json:"host"`
	HostSrc  string    `json:"hostSource"` // dns, sni or http
	BytesOut uint64    `json:"bytesOut"`
	BytesIn  uint64    `json:"bytesIn"`
	PktsOut  uint64    `json:"pktsOut"`
	PktsIn   uint64    `json:"pktsIn"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Service  string    `json:"service"`
	Alerts   int       `json:"alerts"`
}

// Alert is one finding. Repeats within 10 minutes are merged into Count.
type Alert struct {
	ID       int       `json:"id"`
	Severity string    `json:"severity"` // high, medium, low, info
	Rule     string    `json:"rule"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
	Remote   string    `json:"remote"`
	Host     string    `json:"host"`
	Port     uint16    `json:"port"`
	Proto    string    `json:"proto"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Count    int       `json:"count"`
}

// DNSEntry is one lookup and, when seen, its answers.
type DNSEntry struct {
	Time     time.Time `json:"time"`
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Resolver string    `json:"resolver"`
	Answers  []string  `json:"answers"`
}

// AIStatus is the status part of Network Sentinel's AI monitoring. Requests,
// findings and file access records are intentionally not decoded.
type AIStatus struct {
	Gateway   string `json:"gateway"`
	LogStatus string `json:"logStatus"`
}

// Clock is Network Sentinel's own notion of "now": the newest second of its
// throughput series. In live mode that tracks the wall clock; when replaying a
// pcap it is the time of the last packet, so "the last 15 minutes" still means
// something.
func (s *Snapshot) Clock() time.Time {
	if n := len(s.Series); n > 0 && s.Series[n-1].T > 0 {
		return time.Unix(s.Series[n-1].T, 0).UTC()
	}
	return s.Now.UTC()
}
