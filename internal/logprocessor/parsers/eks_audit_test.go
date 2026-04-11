package parsers

import (
	"testing"
)

func TestEKSAuditParser_ParseLog(t *testing.T) {
	p := NewEKSAuditParser()
	raw := `{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"a1","verb":"create","objectRef":{"resource":"pods","subresource":"exec","namespace":"ns","name":"p"},"user":{"username":"u@x.com"},"userAgent":"kubectl/v1.30","sourceIPs":["10.0.1.2"],"requestReceivedTimestamp":"2024-01-01T12:00:00.000Z"}`

	events, err := p.ParseLog(raw)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.EventSource != "eks.amazonaws.com" {
		t.Errorf("EventSource = %q", ev.EventSource)
	}
	if ev.EventID != "a1" {
		t.Errorf("EventID = %q", ev.EventID)
	}
	if ev.UserIdentity.UserName != "u@x.com" {
		t.Errorf("UserName = %q", ev.UserIdentity.UserName)
	}
	if ev.SourceIPAddress != "10.0.1.2" {
		t.Errorf("SourceIPAddress = %q", ev.SourceIPAddress)
	}
	if ev.UserAgent != "kubectl/v1.30" {
		t.Errorf("UserAgent = %q", ev.UserAgent)
	}
}
