package tools

import (
	"strings"
	"unicode/utf8"
)

// Length limits for text that came off the network.
const (
	maxHostLen   = 253 // the longest valid DNS name
	maxShortLen  = 64
	maxTitleLen  = 200
	maxDetailLen = 500
	maxListItems = 20
)

// clean makes observed network text inert before it reaches a model or a
// terminal. DNS names, TLS server names, HTTP Host headers and the alert
// details that quote them are all chosen by whoever runs the remote end, so
// the result is valid UTF-8, has no control characters (which could carry
// terminal escape sequences), has no invisible or direction-changing
// characters (which can hide text from a human reviewer), and is at most limit
// characters long.
func clean(s string, limit int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == limit {
			b.WriteString("…")
			break
		}
		if unsafeRune(r) {
			r = '?'
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// cleanList applies clean to each item and keeps at most maxListItems.
func cleanList(items []string, limit int) []string {
	out := make([]string, 0, min(len(items), maxListItems))
	for _, s := range items {
		if len(out) == maxListItems {
			break
		}
		out = append(out, clean(s, limit))
	}
	return out
}

func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f: // C0 controls, DEL
		return true
	case r >= 0x80 && r <= 0x9f: // C1 controls
		return true
	case r >= 0x200b && r <= 0x200f: // zero-width characters, LRM, RLM
		return true
	case r >= 0x202a && r <= 0x202e: // bidi embeddings and overrides
		return true
	case r >= 0x2066 && r <= 0x2069: // bidi isolates
		return true
	case r == 0x2028, r == 0x2029, r == 0xfeff: // line/paragraph separators, BOM
		return true
	}
	return false
}
