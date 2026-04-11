package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bilals12/iota/pkg/cloudtrail"
)

type CloudflareHTTPRequestParser struct{}

func NewCloudflareHTTPRequestParser() *CloudflareHTTPRequestParser {
	return &CloudflareHTTPRequestParser{}
}

func (p *CloudflareHTTPRequestParser) LogType() string {
	return "Cloudflare.HttpRequest"
}

func (p *CloudflareHTTPRequestParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(log), &raw); err != nil {
		return nil, fmt.Errorf("cloudflare http: %w", err)
	}
	if !isCloudflareHTTPRequestShape(raw) {
		return nil, fmt.Errorf("cloudflare http: not an HTTP request log shape")
	}
	if isCloudflareFirewallShape(raw) {
		return nil, fmt.Errorf("cloudflare http: firewall shape")
	}

	eventTime, err := cloudflareHTTPRequestEventTime(raw)
	if err != nil {
		eventTime = time.Unix(0, 0).UTC()
	}

	eventID := cloudflareHTTPRequestEventID(raw)
	host, _ := raw["ClientRequestHost"].(string)
	method, _ := raw["ClientRequestMethod"].(string)
	eventName := "http"
	if method != "" && host != "" {
		eventName = strings.ToLower(method) + "." + host
	}

	clientIP, _ := raw["ClientIP"].(string)

	ct := &cloudtrail.Event{
		EventVersion:      "1.0",
		EventSource:       "cloudflare.com.http_request",
		EventName:         eventName,
		EventTime:         eventTime,
		SourceIPAddress:   clientIP,
		RequestID:         eventID,
		EventID:           eventID,
		EventType:         "Cloudflare.HttpRequest",
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

func isCloudflareHTTPRequestShape(m map[string]interface{}) bool {
	if k, ok := m["Kind"].(string); ok && strings.EqualFold(k, "firewall") {
		return false
	}
	if pt, ok := m["p_log_type"].(string); ok && pt == "Cloudflare.HttpRequest" {
		return true
	}
	if _, ok := m["EdgeStartTimestamp"]; ok {
		return true
	}
	if _, ok := m["BotScore"]; ok {
		return true
	}
	return false
}

func cloudflareHTTPRequestEventTime(m map[string]interface{}) (time.Time, error) {
	if s, ok := m["EdgeStartTimestamp"].(string); ok && s != "" {
		return parseCloudflareTime(s)
	}
	if s, ok := m["Datetime"].(string); ok && s != "" {
		return parseCloudflareTime(s)
	}
	return time.Time{}, fmt.Errorf("missing time")
}

func cloudflareHTTPRequestEventID(m map[string]interface{}) string {
	if id, ok := m["RayID"].(string); ok && id != "" {
		return id
	}
	return "cf-http"
}

var _ ParserInterface = (*CloudflareHTTPRequestParser)(nil)
