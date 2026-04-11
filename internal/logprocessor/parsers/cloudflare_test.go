package parsers

import (
	"testing"
)

func TestCloudflareFirewallParser_ParseLog(t *testing.T) {
	p := NewCloudflareFirewallParser()
	raw := `{"Kind":"firewall","Action":"block","ClientIP":"9.9.9.9","Datetime":"2025-01-01 12:00:00","RayID":"r1"}`

	events, err := p.ParseLog(raw)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if len(events) != 1 || events[0].EventSource != "cloudflare.com.firewall" {
		t.Fatalf("unexpected: %+v", events[0])
	}
}

func TestCloudflareHTTPRequestParser_ParseLog(t *testing.T) {
	p := NewCloudflareHTTPRequestParser()
	raw := `{"BotScore":10,"ClientIP":"1.2.3.4","EdgeStartTimestamp":"2022-05-07 18:53:12","RayID":"x"}`

	events, err := p.ParseLog(raw)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if len(events) != 1 || events[0].EventSource != "cloudflare.com.http_request" {
		t.Fatalf("unexpected: %+v", events[0])
	}
}
