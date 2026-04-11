package parsers

import (
	"strings"
	"testing"
)

func TestGCPHTTPLoadBalancerParser_ParseLog(t *testing.T) {
	p := NewGCPHTTPLoadBalancerParser()
	raw := `{"httpRequest":{"remoteIp":"1.2.3.4","requestUrl":"https://ex/a"},"insertId":"lb-x","resource":{"type":"http_load_balancer","labels":{"project_id":"p1"}},"timestamp":"2025-01-01T12:00:00Z"}`

	events, err := p.ParseLog(raw)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.EventSource != "loadbalancing.googleapis.com" {
		t.Errorf("EventSource = %q", ev.EventSource)
	}
	if ev.EventID != "lb-x" {
		t.Errorf("EventID = %q", ev.EventID)
	}
}

func TestGCPHTTPLoadBalancerParser_RejectsAuditOnly(t *testing.T) {
	p := NewGCPHTTPLoadBalancerParser()
	_, err := p.ParseLog(`{"protoPayload":{"methodName":"x","serviceName":"y"}}`)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "http lb") {
		t.Fatalf("unexpected err: %v", err)
	}
}
