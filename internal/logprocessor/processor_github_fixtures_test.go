package logprocessor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProcessor_GitHubAuditSamplesJSONL(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	path := filepath.Join(root, "testdata", "rulesets", "github_audit", "samples.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	p := New()
	ctx := context.Background()
	out, errs := p.Process(ctx, bytes.NewReader(data))

	var n int
	for pe := range out {
		if pe.LogType != "GitHub.Audit" {
			t.Errorf("line %d: LogType=%q", n+1, pe.LogType)
		}
		if pe.Event.EventSource != "github.com" {
			t.Errorf("line %d: EventSource=%q", n+1, pe.Event.EventSource)
		}
		n++
	}
	for err := range errs {
		t.Fatalf("process error: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 events, got %d", n)
	}
}

func TestProcessor_GitHubWebhookSamplesJSONL(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	path := filepath.Join(root, "testdata", "rulesets", "github_webhook", "samples.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	p := New()
	ctx := context.Background()
	out, errs := p.Process(ctx, bytes.NewReader(data))

	var n int
	for pe := range out {
		if pe.LogType != "GitHub.Webhook" {
			t.Errorf("line %d: LogType=%q", n+1, pe.LogType)
		}
		if pe.Event.EventSource != "github.com.webhook" {
			t.Errorf("line %d: EventSource=%q", n+1, pe.Event.EventSource)
		}
		n++
	}
	for err := range errs {
		t.Fatalf("process error: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 events, got %d", n)
	}
}
