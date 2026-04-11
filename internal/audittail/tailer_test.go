package audittail

import "testing"

func TestSplitCompleteLines(t *testing.T) {
	complete, rem := splitCompleteLines([]byte("a\nb\nc\n"))
	if len(complete) != 3 || string(complete[0]) != "a" || string(rem) != "" {
		t.Fatalf("got complete=%v rem=%q", complete, rem)
	}
	complete, rem = splitCompleteLines([]byte("partial"))
	if len(complete) != 0 || string(rem) != "partial" {
		t.Fatalf("got complete=%v rem=%q", complete, rem)
	}
	complete, rem = splitCompleteLines([]byte("ok\nincomplete"))
	if len(complete) != 1 || string(complete[0]) != "ok" || string(rem) != "incomplete" {
		t.Fatalf("got complete=%v rem=%q", complete, rem)
	}
	c, r := splitCompleteLines([]byte{})
	if c != nil || r != nil {
		t.Fatalf("empty buf: complete=%v rem=%v", c, r)
	}
}
