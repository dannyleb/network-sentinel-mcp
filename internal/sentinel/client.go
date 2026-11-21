package sentinel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Defaults for talking to Network Sentinel.
const (
	DefaultURL      = "http://127.0.0.1:8787"
	DefaultTimeout  = 5 * time.Second
	DefaultMaxBytes = 16 << 20 // a full snapshot is typically well under 1 MB

	snapshotPath = "/api/snapshot"
)

var (
	// ErrNotLoopback means a URL or connection pointed somewhere other than this machine.
	ErrNotLoopback = errors.New("only loopback addresses (127.0.0.1, ::1, localhost) are allowed")
	// ErrNotRunning means nothing answered at the configured address.
	ErrNotRunning = errors.New("can't reach Network Sentinel")
	// ErrUnauthorized means Network Sentinel rejected (or needed) the login token.
	ErrUnauthorized = errors.New("login token rejected by Network Sentinel")
)

// Options configures a Client. Zero values pick the defaults.
type Options struct {
	URL      string        // base URL of the dashboard, e.g. http://127.0.0.1:8787
	Token    string        // dashboard login token; empty if Network Sentinel runs with -no-auth
	Timeout  time.Duration // per request
	MaxBytes int64         // largest response body accepted
}

// Client reads snapshots from Network Sentinel. It can only issue GET requests
// to a loopback address, and it never follows redirects.
type Client struct {
	base     *url.URL
	token    string
	maxBytes int64
	http     *http.Client
}

// New validates the options and builds a Client.
func New(opts Options) (*Client, error) {
	if opts.URL == "" {
		opts.URL = DefaultURL
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	base, err := ParseURL(opts.URL)
	if err != nil {
		return nil, err
	}
	if opts.Token != "" && !ValidToken(opts.Token) {
		return nil, errors.New("the login token has unexpected characters or length")
	}
	dialer := &net.Dialer{Timeout: opts.Timeout, Control: loopbackOnly}
	transport := &http.Transport{
		Proxy:                 nil, // never route through HTTP_PROXY: traffic stays on this machine
		DialContext:           dialer.DialContext,
		ResponseHeaderTimeout: opts.Timeout,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
	}
	return &Client{
		base:     base,
		token:    opts.Token,
		maxBytes: opts.MaxBytes,
		http: &http.Client{
			Transport: transport,
			Timeout:   opts.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// BaseURL is the dashboard address this client reads from.
func (c *Client) BaseURL() string { return c.base.String() }

// Snapshot fetches GET /api/snapshot.
func (c *Client) Snapshot(ctx context.Context) (*Snapshot, error) {
	u := *c.base
	u.Path = snapshotPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "network-sentinel-mcp")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotLoopback):
			return nil, err
		case ctx.Err() != nil:
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w at %s. Start it with `sudo netsentinel`, or replay a capture with `netsentinel -r file.pcap`", ErrNotRunning, c.base)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("%w. Set --token-file (or NETWORK_SENTINEL_TOKEN_FILE) to the `token` file in Network Sentinel's data folder", ErrUnauthorized)
	default:
		return nil, fmt.Errorf("unexpected HTTP %d from Network Sentinel's %s", resp.StatusCode, snapshotPath)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading snapshot: %w", err)
	}
	if int64(len(body)) > c.maxBytes {
		return nil, fmt.Errorf("snapshot is larger than %d bytes; refusing to read it", c.maxBytes)
	}
	var s Snapshot
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, fmt.Errorf("decoding snapshot: %w", err)
	}
	return &s, nil
}

// ParseURL accepts only http(s)://<loopback host>[:port], with no credentials,
// path, query or fragment.
func ParseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid Network Sentinel URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("the Network Sentinel URL must start with http:// or https://, got %q", raw)
	}
	if u.User != nil {
		return nil, errors.New("the Network Sentinel URL must not contain credentials")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("the Network Sentinel URL must be just scheme://host:port, got %q", raw)
	}
	if !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("the Network Sentinel URL %q is not on this machine: %w", raw, ErrNotLoopback)
	}
	u.Path = ""
	return u, nil
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.Unmap().IsLoopback()
}

// loopbackOnly runs just before each socket connects, after name resolution,
// so no hosts-file entry or redirect can point this client at another machine.
func loopbackOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Unmap().IsLoopback() {
		return fmt.Errorf("refusing to connect to %s: %w", address, ErrNotLoopback)
	}
	return nil
}
