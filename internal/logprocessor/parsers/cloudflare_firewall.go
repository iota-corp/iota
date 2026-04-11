package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bilals12/iota/pkg/cloudtrail"
)

type CloudflareFirewallParser struct{}

func NewCloudflareFirewallParser() *CloudflareFirewallParser {
	return &CloudflareFirewallParser{}
}

func (p *CloudflareFirewallParser) LogType() string {
	return "Cloudflare.Firewall"
}

func (p *CloudflareFirewallParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(log), &raw); err != nil {
		return nil, fmt.Errorf("cloudflare firewall: %w", err)
	}
	if !isCloudflareFirewallShape(raw) {
		return nil, fmt.Errorf("cloudflare firewall: not a firewall event shape")
	}

	eventTime, err := cloudflareEventTime(raw)
	if err != nil {
		eventTime = time.Unix(0, 0).UTC()
	}

	eventID := cloudflareRayID(raw)
	action, _ := raw["Action"].(string)
	src, _ := raw["Source"].(string)
	eventName := "firewall"
	if action != "" {
		eventName = strings.ToLower(action) + "." + strings.ToLower(src)
	}

	clientIP, _ := raw["ClientIP"].(string)

	ct := &cloudtrail.Event{
		EventVersion:      "1.0",
		EventSource:       "cloudflare.com.firewall",
		EventName:         eventName,
		EventTime:         eventTime,
		SourceIPAddress:   clientIP,
		RequestID:         eventID,
		EventID:           eventID,
		EventType:         "Cloudflare.Firewall",
		RequestParameters: raw,
	}
	if clientIP != "" {
		ct.UserIdentity = cloudtrail.UserIdentity{
			Type:        "IPAddress",
			PrincipalID: clientIP,
		}
	}

	return []*cloudtrail.Event{ct}, nil
}

func isCloudflareFirewallShape(m map[string]interface{}) bool {
	if pt, ok := m["p_log_type"].(string); ok && pt == "Cloudflare.Firewall" {
		return true
	}
	k, ok := m["Kind"].(string)
	return ok && strings.EqualFold(k, "firewall")
}

func cloudflareRayID(m map[string]interface{}) string {
	if id, ok := m["RayID"].(string); ok && id != "" {
		return id
	}
	return "cf-fw"
}

func cloudflareEventTime(m map[string]interface{}) (time.Time, error) {
	if s, ok := m["Datetime"].(string); ok && s != "" {
		return parseCloudflareTime(s)
	}
	return time.Time{}, fmt.Errorf("missing Datetime")
}

func parseCloudflareTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	layouts := []string{
		"2006-01-02 15:04:05",
		time.RFC3339,
		time.RFC3339Nano,
	}
	var last error
	for _, layout := range layouts {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t.UTC(), nil
		}
		last = err
	}
	return time.Time{}, last
}

var _ ParserInterface = (*CloudflareFirewallParser)(nil)
