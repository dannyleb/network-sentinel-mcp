// Package fixture holds recorded-shape Network Sentinel snapshots for tests, so
// every test runs without live traffic, root, or a running Network Sentinel.
//
// All addresses come from documentation ranges (RFC 5737, RFC 3849) and all
// names use reserved TLDs (.test, .example, example.com/org/net).
package fixture

import (
	_ "embed"
	"encoding/json"

	"github.com/dannyleb/network-sentinel-mcp/internal/sentinel"
)

// LiveJSON is a live-capture snapshot whose clock reads 2026-01-15T15:00:00Z.
// It includes traps: a hostname with a terminal escape, an alert from a rule
// this server doesn't know, the machine's own LAN address in every flow, and an
// AI secret finding. None of those may reach a tool's output unchanged.
//
//go:embed live.json
var LiveJSON []byte

// ReplayJSON is a snapshot from replaying a pcap captured on 2025-06-01, read
// much later: its wall clock and its capture clock disagree.
//
//go:embed replay.json
var ReplayJSON []byte

// Live decodes LiveJSON.
func Live() *sentinel.Snapshot { return decode(LiveJSON) }

// Replay decodes ReplayJSON.
func Replay() *sentinel.Snapshot { return decode(ReplayJSON) }

func decode(b []byte) *sentinel.Snapshot {
	var s sentinel.Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		panic("fixture: " + err.Error())
	}
	return &s
}
