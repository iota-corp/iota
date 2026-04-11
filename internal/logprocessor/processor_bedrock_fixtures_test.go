package logprocessor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProcessor_BedrockSamplesJSONL(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	path := filepath.Join(root, "testdata", "rulesets", "aws_bedrockmodelinvocation", "samples.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	p := New()
	ctx := context.Background()
	out, errs := p.Process(ctx, bytes.NewReader(data))

	var n int
	for pe := range out {
		if pe.LogType != "AWS.BedrockModelInvocation" {
			t.Errorf("line %d: LogType=%q", n+1, pe.LogType)
		}
		if pe.Event.EventSource != "aws.bedrock.modelinvocation" {
			t.Errorf("line %d: EventSource=%q", n+1, pe.Event.EventSource)
		}
		n++
	}
	for err := range errs {
		t.Fatalf("process error: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 events, got %d", n)
	}
}

func TestProcessor_BedrockSamplesRecords(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	path := filepath.Join(root, "testdata", "rulesets", "aws_bedrockmodelinvocation", "samples.records.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	p := New()
	ctx := context.Background()
	out, errs := p.Process(ctx, bytes.NewReader(data))

	var n int
	for range out {
		n++
	}
	for err := range errs {
		t.Fatalf("process error: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 events from Records, got %d", n)
	}
}
