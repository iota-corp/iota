package logprocessor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProcessor_GCPAuditLogSamplesJSONL(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	path := filepath.Join(root, "testdata", "rulesets", "gcp_auditlog", "samples.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	p := New()
	ctx := context.Background()
	out, errs := p.Process(ctx, bytes.NewReader(data))

	var n int
	for pe := range out {
		if pe.LogType != "GCP.AuditLog" {
			t.Errorf("line %d: LogType=%q", n+1, pe.LogType)
		}
		if pe.Event.EventSource != "cloudaudit.googleapis.com" {
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

func TestProcessor_GCPHTTPLoadBalancerSamplesJSONL(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	path := filepath.Join(root, "testdata", "rulesets", "gcp_httploadbalancer", "samples.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	p := New()
	ctx := context.Background()
	out, errs := p.Process(ctx, bytes.NewReader(data))

	var n int
	for pe := range out {
		if pe.LogType != "GCP.HTTPLoadBalancer" {
			t.Errorf("line %d: LogType=%q", n+1, pe.LogType)
		}
		if pe.Event.EventSource != "loadbalancing.googleapis.com" {
			t.Errorf("line %d: EventSource=%q", n+1, pe.Event.EventSource)
		}
		n++
	}
	for err := range errs {
		t.Fatalf("process error: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 events, got %d", n)
	}
}
