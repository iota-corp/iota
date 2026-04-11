package parsers

import (
	"testing"
)

func TestSlackAuditLogsParser_ParseLog(t *testing.T) {
	p := NewSlackAuditLogsParser()
	raw := `{"action":"app_installed","actor":{"type":"user","user":{"email":"u@e.com","name":"n"}},"context":{"ip_address":"1.1.1.1"},"date_create":"2021-06-08 22:16:15","entity":{"type":"app"}}`

	events, err := p.ParseLog(raw)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if len(events) != 1 || events[0].EventSource != "slack.com" || events[0].EventName != "app_installed" {
		t.Fatalf("unexpected: %+v", events[0])
	}
}
