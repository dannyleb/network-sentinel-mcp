// Command network-sentinel-mcp is a read-only MCP server that lets AI clients
// such as Claude query Network Sentinel, a local outbound-traffic monitor.
//
// It speaks MCP over stdio and reads Network Sentinel's dashboard API on this
// machine. It never writes anything and makes no other network connections.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dannyleb/network-sentinel-mcp/internal/sentinel"
	"github.com/dannyleb/network-sentinel-mcp/internal/tools"
)

// version is set at build time by the Makefile (-X main.version=...).
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := run(ctx, env{
		args:       os.Args[1:],
		getenv:     os.Getenv,
		tokenPaths: sentinel.DefaultTokenPaths(),
		transport:  &mcp.StdioTransport{},
		stdout:     os.Stdout,
		stderr:     os.Stderr,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "network-sentinel-mcp:", err)
		os.Exit(1)
	}
}

// env is everything run needs from the outside world, so tests can supply
// their own.
type env struct {
	args       []string
	getenv     func(string) string
	tokenPaths []string
	transport  mcp.Transport
	stdout     io.Writer // only for -version and -help; MCP owns the real stdout
	stderr     io.Writer // logs
}

func run(ctx context.Context, e env) error {
	fs := flag.NewFlagSet("network-sentinel-mcp", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	url := fs.String("url", or(e.getenv("NETWORK_SENTINEL_URL"), sentinel.DefaultURL),
		"Network Sentinel dashboard address; must be on this machine (env NETWORK_SENTINEL_URL)")
	tokenFile := fs.String("token-file", e.getenv("NETWORK_SENTINEL_TOKEN_FILE"),
		"file holding the dashboard login token (env NETWORK_SENTINEL_TOKEN_FILE; default: Network Sentinel's data folder)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "network-sentinel-mcp %s: read-only MCP server for Network Sentinel\n\n", buildVersion())
		fmt.Fprintf(fs.Output(), "Run it from an MCP client (Claude Desktop, Claude Code, MCP Inspector); it speaks MCP over stdio.\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), "\nThe token can also be passed directly in NETWORK_SENTINEL_TOKEN.\n")
	}
	if err := fs.Parse(e.args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if *showVersion {
		fmt.Fprintln(e.stdout, buildVersion())
		return nil
	}

	token, err := sentinel.ResolveToken(*tokenFile, e.getenv("NETWORK_SENTINEL_TOKEN"), e.tokenPaths)
	if err != nil {
		return err
	}
	client, err := sentinel.New(sentinel.Options{URL: *url, Token: token.Value})
	if err != nil {
		return err
	}

	logger := log.New(e.stderr, "network-sentinel-mcp: ", 0)
	logger.Printf("%s reading %s (token: %s)", buildVersion(), client.BaseURL(), token.Source)

	server := tools.NewServer(client, tools.Info{
		Version:     buildVersion(),
		SentinelURL: client.BaseURL(),
		TokenSource: token.Source,
	})
	return server.Run(ctx, e.transport)
}

// buildVersion is the Makefile's version, else the module version recorded by
// `go install ...@vX.Y.Z`, else "dev".
func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

func or(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}
