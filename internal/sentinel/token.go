package sentinel

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const maxTokenFileBytes = 256

// Token is the dashboard login token and a description of where it came from.
// Source is safe to show; Value never is.
type Token struct {
	Value  string
	Source string
}

// ValidToken reports whether s looks like a Network Sentinel token: 32 to 128
// printable ASCII characters with no spaces (it generates 48 hex characters).
// The check also keeps anything odd out of the Authorization header.
func ValidToken(s string) bool {
	if len(s) < 32 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// ReadTokenFile reads a token file. It only ever opens the file read-only.
func ReadTokenFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("can't read token file: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxTokenFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("can't read token file %s: %w", path, err)
	}
	if len(b) > maxTokenFileBytes {
		return "", fmt.Errorf("%s is too large to be a Network Sentinel token file", path)
	}
	t := strings.TrimSpace(string(b))
	if !ValidToken(t) {
		return "", fmt.Errorf("%s doesn't contain a Network Sentinel token", path)
	}
	return t, nil
}

// DefaultTokenPaths lists where Network Sentinel keeps its token, most likely first:
// the system data folder its macOS service and `sudo` runs use, then the
// per-user config folder.
func DefaultTokenPaths() []string {
	var paths []string
	if runtime.GOOS == "darwin" {
		paths = append(paths, "/Library/Application Support/NetworkSentinel/token")
	}
	if d, err := os.UserConfigDir(); err == nil {
		paths = append(paths, filepath.Join(d, "network-sentinel", "token"))
	}
	return paths
}

// ResolveToken picks the token in order: an explicit file, an explicit value,
// then the first readable default path. Finding no token is not an error,
// because Network Sentinel can run with -no-auth; an explicit file or value
// that is unusable is.
func ResolveToken(file, value string, defaults []string) (Token, error) {
	if file != "" {
		t, err := ReadTokenFile(file)
		if err != nil {
			return Token{}, err
		}
		return Token{Value: t, Source: "file " + file}, nil
	}
	if value != "" {
		v := strings.TrimSpace(value)
		if !ValidToken(v) {
			return Token{}, errors.New("NETWORK_SENTINEL_TOKEN doesn't look like a Network Sentinel token")
		}
		return Token{Value: v, Source: "environment variable NETWORK_SENTINEL_TOKEN"}, nil
	}
	for _, p := range defaults {
		if t, err := ReadTokenFile(p); err == nil {
			return Token{Value: t, Source: "file " + p}, nil
		}
	}
	return Token{Source: "none found (works only if Network Sentinel runs with -no-auth)"}, nil
}
