# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`network-sentinel-mcp` is a read-only [MCP](https://modelcontextprotocol.io) server, written in Go, that lets AI clients query
[Network Sentinel](https://github.com/dannyleb/network-sentinel), a local outbound-traffic monitor. It is a
portfolio project: clarity of code, tests, commits and docs matters as much as function.

## Rules (non-negotiable)

1. **Strictly read-only.** No tool or resource may change Network Sentinel's data or configuration, or write
   anything to disk. The only request this server ever makes is `GET /api/snapshot`. Every tool is annotated
   `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false`, and
   `TestEveryToolIsReadOnlyAndBounded` enforces it.
2. **Validate and bound every input.** Each input has an explicit range, length, pattern or enum in its
   hand-written JSON schema (`internal/tools/schema.go` helpers), `additionalProperties: false`, and a matching
   `normalize()` check in the handler. Time windows are capped (24 h for connections, 30 days for alerts).
   Invalid input must be rejected *before* fetching a snapshot (`rejects()` in tests checks this).
3. **No data leaves the machine. No telemetry.** The HTTP client only dials loopback addresses (checked
   after DNS resolution by a dialer `Control` hook), ignores proxy env vars, and never follows redirects.
   Don't add any other network call, update check or analytics.
4. **Small, focused commits**, one tool or concern at a time, with messages that explain *why*. Every commit
   must pass `make check`.
5. **Ask before adding any dependency** beyond the MCP SDK and the standard library (`testing` is the test
   framework). Dev tools run through `go run`/`npx` at pinned versions in the Makefile and are not module
   dependencies. Input schemas are plain maps so `github.com/google/jsonschema-go` stays an indirect dependency.

## Architecture

```
MCP client (Claude Desktop, Claude Code, Inspector)
        │  JSON-RPC over stdio
        ▼
cmd/network-sentinel-mcp      flags/env → token → sentinel.Client → tools.NewServer → Run(stdio)
        │
internal/tools                one file per tool + config resource; Source interface
        │  Snapshot(ctx)
internal/sentinel             read-only HTTP client, token discovery, API types
        │  GET /api/snapshot, Authorization: Bearer <token>, 127.0.0.1 only
        ▼
Network Sentinel (separate repo, ../network-sentinel)
```

- **One snapshot per call.** Each tool fetches `/api/snapshot`, filters it and returns structured output
  (`structuredContent` plus the same JSON as text). Nothing is cached between calls.
- **Network Sentinel's clock, not the wall clock.** `Snapshot.Clock()` is the newest second of its throughput
  series, so time windows work when it replays an old pcap.
- **Snapshot caps.** Network Sentinel shares its top 500 flows by bytes sent, its 300 newest alerts and its 150
  newest DNS lookups. Tools add a `notes` entry when an answer may be incomplete because of these caps.
- **Untrusted text.** Host names, DNS names and alert details come off the network. Every string from a
  snapshot goes through `clean()` (no control/bidi/zero-width characters, bounded length) before output.
- **Minimal decoding.** `internal/sentinel/types.go` only decodes fields the tools use. The machine's own LAN
  address (`local`), AI request bodies and secret findings are never parsed.
- **No process data.** Network Sentinel works from packets and can't say which app made a connection. Don't
  promise process filtering; suggest `lsof -nP -i @<ip>` to the user instead (see `rules.go`).
- **Rule catalog.** `internal/tools/rules.go` explains all 17 Network Sentinel rules, written from its
  `detect.go`, `secrets.go`, `ai.go` and README. When Network Sentinel adds a rule, add it here and to
  `TestRuleCatalogCoversNetworkSentinel`.

## Layout

| Path | Contents |
|---|---|
| `cmd/network-sentinel-mcp/` | `main` (thin) and `run(ctx, env)`, which tests drive end to end |
| `internal/sentinel/` | `Client` (loopback-only GET), `ParseURL`, token discovery, API types |
| `internal/tools/` | `server.go` (wiring, panic recovery), `connections.go`, `alerts.go`, `destinations.go`, `explain.go`, `rules.go`, `config.go`, `schema.go`, `sanitize.go` |
| `internal/fixture/` | `live.json` and `replay.json` snapshots used by every test |

## Commands

```bash
make build      # bin/network-sentinel-mcp
make test       # go vet + go test -race
make lint       # gofmt check + staticcheck
make vuln       # govulncheck
make check      # all of the above, as CI runs it
make inspector  # MCP Inspector against a local build (Node 22+; Network Sentinel must be running)
```

Without live traffic: in `../network-sentinel` run `make demo` (replays a synthetic pcap on 127.0.0.1:8787),
then `NETWORK_SENTINEL_TOKEN_FILE=../network-sentinel/testdata/demo-data/token make inspector`.

If `make vuln` reports standard-library vulnerabilities locally, the local Go toolchain is behind: CI uses
the latest patch release. `GOTOOLCHAIN=go1.X.Y make vuln` checks with a newer one.

## Adding a tool

1. New file in `internal/tools/` with an `XInput` (json tags, `omitempty` for optional fields), a
   `normalize()` that applies defaults and re-checks bounds, an `XOutput` with `jsonschema` descriptions,
   and `addX(s, src)` using `object()/integer()/text()/oneOf()` and `readOnlyTool()`.
2. Register it in `NewServer` and in `toolInputs` (`server_test.go`).
3. Tests: behavior against both fixtures, a `rejects()` table for invalid input, sanitization, notes.
4. Describe it in the README's tool table and, if it has limits, in `inputLimits()` (`config.go`).

## Gotchas

- **Don't put `default` in input schemas.** go-sdk v1.8.0 panics when a client sends `"arguments": null` to a
  tool whose schema declares defaults. Put the default in the description and apply it in `normalize()`.
  `recoverPanics` middleware contains any panic to one request (`TestSDKPanicIsContained`).
- **Output maps must be non-nil.** The SDK validates output against the inferred schema, and a nil map is `null`.
  Return empty slices, not nil, so clients see `[]`.
- **Error strings start lowercase** (staticcheck ST1005), so they say "can't reach Network Sentinel", not
  "Network Sentinel is unreachable".
- **stdout belongs to MCP.** Log to stderr only; `-help` and `-version` are the only stdout writers, and only
  because they exit before the server starts.
- **Fixtures use documentation IP ranges and reserved names** (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, `2001:db8::/32`, `.test`, `.example`, `example.com`). Keep real data out of the repo.
- **Commit identity.** This repo uses the GitHub noreply address, set in `.git/config`.
