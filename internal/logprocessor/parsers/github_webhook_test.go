package parsers

import (
	"strings"
	"testing"
)

func TestGitHubWebhookParser_ParseLog(t *testing.T) {
	p := NewGitHubWebhookParser()
	raw := `{"p_log_type":"GitHub.Webhook","action":"opened","repository":{"full_name":"org/repo"},"sender":{"login":"bob"},"pull_request":{"id":1,"created_at":"2025-01-01T00:00:00Z"}}`

	events, err := p.ParseLog(raw)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.EventSource != "github.com.webhook" {
		t.Errorf("EventSource = %q", ev.EventSource)
	}
	if ev.EventName != "opened" {
		t.Errorf("EventName = %q", ev.EventName)
	}
	if ev.RequestParameters == nil {
		t.Fatal("RequestParameters nil")
	}
	if ev.UserIdentity.UserName != "bob" {
		t.Errorf("UserName = %q", ev.UserIdentity.UserName)
	}
}

func TestGitHubWebhookParser_PusherShape(t *testing.T) {
	p := NewGitHubWebhookParser()
	raw := `{"action":"push","repository":{"full_name":"org/r"},"pusher":{"name":"u","email":"u@e.com"}}`

	events, err := p.ParseLog(raw)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if len(events) != 1 || events[0].EventName != "push" {
		t.Fatalf("unexpected: %+v", events)
	}
}

func TestGitHubWebhookParser_RejectsAuditOnly(t *testing.T) {
	p := NewGitHubWebhookParser()
	_, err := p.ParseLog(`{"action":"repo.create","actor":"a","created_at":1710000000000}`)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "webhook") {
		t.Fatalf("unexpected err: %v", err)
	}
}
