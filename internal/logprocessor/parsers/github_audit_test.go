package parsers

import (
	"strings"
	"testing"
)

func TestGitHubAuditParser_ParseLog(t *testing.T) {
	p := NewGitHubAuditParser()
	raw := `{"p_log_type":"GitHub.Audit","action":"repo.create","actor":"alice","created_at":1710000000000,"id":"evt-audit-1"}`

	events, err := p.ParseLog(raw)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.EventSource != "github.com" {
		t.Errorf("EventSource = %q", ev.EventSource)
	}
	if ev.EventName != "repo.create" {
		t.Errorf("EventName = %q", ev.EventName)
	}
	if ev.EventID != "evt-audit-1" {
		t.Errorf("EventID = %q", ev.EventID)
	}
	if ev.RequestParameters == nil {
		t.Fatal("RequestParameters nil")
	}
	if ev.RequestParameters["actor"] != "alice" {
		t.Errorf("actor mismatch")
	}
}

func TestGitHubAuditParser_HeuristicShape(t *testing.T) {
	p := NewGitHubAuditParser()
	raw := `{"action":"org.update_member_role","actor":"admin","created_at":1710000001000}`

	events, err := p.ParseLog(raw)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if len(events) != 1 || events[0].EventName != "org.update_member_role" {
		t.Fatalf("unexpected parse: %+v", events)
	}
}

func TestGitHubAuditParser_RejectsWebhookLike(t *testing.T) {
	p := NewGitHubAuditParser()
	_, err := p.ParseLog(`{"action":"opened","repository":{"full_name":"o/r"},"sender":{"login":"x"},"created_at":1}`)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "audit") {
		t.Fatalf("unexpected err: %v", err)
	}
}
