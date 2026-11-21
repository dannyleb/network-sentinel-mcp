package tools

import (
	"fmt"
	"time"
)

// humanBytes formats a byte count the way Network Sentinel's dashboard does.
func humanBytes(b uint64) string {
	const k = 1024
	switch {
	case b >= k*k*k:
		return fmt.Sprintf("%.1f GB", float64(b)/(k*k*k))
	case b >= k*k:
		return fmt.Sprintf("%.1f MB", float64(b)/(k*k))
	case b >= k:
		return fmt.Sprintf("%.1f KB", float64(b)/k)
	}
	return fmt.Sprintf("%d B", b)
}

// stamp normalizes a timestamp for output: UTC, whole seconds.
func stamp(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }
