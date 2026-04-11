package parsers

import (
	"strings"
	"testing"
)

func TestGCPAuditLogParser_ParseLog(t *testing.T) {
	p := NewGCPAuditLogParser()
	raw := `{"logName":"projects/p/cloudaudit.googleapis.com%2Factivity","protoPayload":{"methodName":"v1.compute.firewalls.patch","serviceName":"compute.googleapis.com","authenticationInfo":{"principalEmail":"a@b.com"}},"timestamp":"2023-05-23T19:19:40.353","insertId":"x1"}`

	events, err := p.ParseLog(raw)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.EventSource != "cloudaudit.googleapis.com" {
		t.Errorf("EventSource = %q", ev.EventSource)
	}
	if ev.EventName != "v1.compute.firewalls.patch" {
		t.Errorf("EventName = %q", ev.EventName)
	}
	if ev.UserIdentity.UserName != "a@b.com" {
		t.Errorf("UserName = %q", ev.UserIdentity.UserName)
	}
}

func TestGCPAuditLogParser_MinimalMethodName(t *testing.T) {
	p := NewGCPAuditLogParser()
	events, err := p.ParseLog(`{"methodName":"v1.compute.firewalls.insert"}`)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if len(events) != 1 || events[0].EventName != "v1.compute.firewalls.insert" {
		t.Fatalf("unexpected: %+v", events)
	}
}

func TestGCPAuditLogParser_RejectsHTTPLB(t *testing.T) {
	p := NewGCPAuditLogParser()
	_, err := p.ParseLog(`{"httpRequest":{},"resource":{"type":"http_load_balancer"},"insertId":"1"}`)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "audit") {
		t.Fatalf("unexpected err: %v", err)
	}
}
