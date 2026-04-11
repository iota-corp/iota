package logprocessor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProcessor_SlackAuditSamplesJSONL(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	path := filepath.Join(root, "testdata", "rulesets", "slack_audit", "samples.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	p := New()
	ctx := context.Background()
	out, errs := p.Process(ctx, bytes.NewReader(data))

	var n int
	for pe := range out {
		if pe.LogType != "Slack.AuditLogs" {
			t.Errorf("LogType=%q", pe.LogType)
		}
		if pe.Event.EventSource != "slack.com" {
			t.Errorf("EventSource=%q", pe.Event.EventSource)
		}
		n++
	}
	for err := range errs {
		t.Fatalf("process error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 event, got %d", n)
	}
}

func TestProcessor_CloudflareFirewallSamplesJSONL(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	path := filepath.Join(root, "testdata", "rulesets", "cloudflare_firewall", "samples.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	p := New()
	ctx := context.Background()
	out, errs := p.Process(ctx, bytes.NewReader(data))

	var n int
	for pe := range out {
		if pe.LogType != "Cloudflare.Firewall" {
			t.Errorf("LogType=%q", pe.LogType)
		}
		if pe.Event.EventSource != "cloudflare.com.firewall" {
			t.Errorf("EventSource=%q", pe.Event.EventSource)
		}
		n++
	}
	for err := range errs {
		t.Fatalf("process error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 event, got %d", n)
	}
}

func TestProcessor_CloudflareHTTPSamplesJSONL(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	path := filepath.Join(root, "testdata", "rulesets", "cloudflare_http", "samples.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	p := New()
	ctx := context.Background()
	out, errs := p.Process(ctx, bytes.NewReader(data))

	var n int
	for pe := range out {
		if pe.LogType != "Cloudflare.HttpRequest" {
			t.Errorf("LogType=%q", pe.LogType)
		}
		if pe.Event.EventSource != "cloudflare.com.http_request" {
			t.Errorf("EventSource=%q", pe.Event.EventSource)
		}
		n++
	}
	for err := range errs {
		t.Fatalf("process error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 event, got %d", n)
	}
}
