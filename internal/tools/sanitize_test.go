package tools

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestClean(t *testing.T) {
	cases := []struct{ in, want string }{
		{"api.example.com", "api.example.com"},
		{"evil\x1b[2J.example.test", "evil?[2J.example.test"},        // terminal escape
		{"link\x1b]8;;http://x.test\x07", "link?]8;;http://x.test?"}, // OSC hyperlink
		{"a\nb\rc\td", "a?b?c?d"},                                    // line breaks can't fake new fields
		{"C1\u009bcontrol", "C1?control"},                            // 8-bit CSI
		{"pay\u202eloc.exe", "pay?loc.exe"},                          // right-to-left override
		{"zero\u200bwidth\ufeff", "zero?width?"},                     // invisible characters
		{"bad\xffutf8", "bad\ufffdutf8"},                             // invalid UTF-8
		{"münchen.example", "münchen.example"},                       // legitimate non-ASCII survives
		{"", ""},
	}
	for _, c := range cases {
		if got := clean(c.in, 100); got != c.want {
			t.Errorf("clean(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCleanBoundsLength(t *testing.T) {
	got := clean(strings.Repeat("é", 1000), 10)
	if utf8.RuneCountInString(got) != 11 || !strings.HasSuffix(got, "…") {
		t.Errorf("clean truncated to %q", got)
	}
	if got := clean("exactly10!", 10); got != "exactly10!" {
		t.Errorf("clean cut a string that fit: %q", got)
	}
}

func TestCleanList(t *testing.T) {
	in := make([]string, 50)
	for i := range in {
		in[i] = "1.2.3.4\x00"
	}
	got := cleanList(in, maxShortLen)
	if len(got) != maxListItems || got[0] != "1.2.3.4?" {
		t.Errorf("cleanList = %d items, first %q", len(got), got[0])
	}
	if got := cleanList(nil, 10); got == nil || len(got) != 0 {
		t.Error("cleanList(nil) should be an empty, non-nil slice")
	}
}

func TestStamp(t *testing.T) {
	in := time.Date(2026, 1, 15, 10, 0, 0, 999_000_000, time.FixedZone("EST", -5*3600))
	if got, want := stamp(in), time.Date(2026, 1, 15, 15, 0, 0, 0, time.UTC); !got.Equal(want) || got.Location() != time.UTC {
		t.Errorf("stamp = %v, want %v", got, want)
	}
}

func TestHumanBytes(t *testing.T) {
	for in, want := range map[uint64]string{
		0:                      "0 B",
		1023:                   "1023 B",
		1024:                   "1.0 KB",
		52428800:               "50.0 MB",
		3 * 1024 * 1024 * 1024: "3.0 GB",
	} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
