package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bilals12/iota/pkg/cloudtrail"
)

type GCPHTTPLoadBalancerParser struct{}

func NewGCPHTTPLoadBalancerParser() *GCPHTTPLoadBalancerParser {
	return &GCPHTTPLoadBalancerParser{}
}

func (p *GCPHTTPLoadBalancerParser) LogType() string {
	return "GCP.HTTPLoadBalancer"
}

func (p *GCPHTTPLoadBalancerParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(log), &raw); err != nil {
		return nil, fmt.Errorf("gcp http lb: %w", err)
	}
	normalizeGCPHTTPLBKeys(raw)
	if !isGCPHTTPLoadBalancerShape(raw) {
		return nil, fmt.Errorf("gcp http lb: not an HTTP(S) load balancer log shape")
	}

	eventTime, err := gcpParseTimestamp(raw["timestamp"])
	if err != nil {
		eventTime = time.Unix(0, 0).UTC()
	}

	eventID := gcpHTTPLBEventID(raw)
	projectID := ""
	if res, ok := raw["resource"].(map[string]interface{}); ok {
		if labels, ok := res["labels"].(map[string]interface{}); ok {
			if s, ok := labels["project_id"].(string); ok {
				projectID = s
			}
		}
	}

	remoteIP := ""
	if hr, ok := raw["httpRequest"].(map[string]interface{}); ok {
		if s, ok := hr["remoteIp"].(string); ok {
			remoteIP = s
		}
	}

	ct := &cloudtrail.Event{
		EventVersion:       "1.0",
		EventSource:        "loadbalancing.googleapis.com",
		EventName:          "httpRequest",
		EventTime:          eventTime,
		SourceIPAddress:    remoteIP,
		RequestID:          eventID,
		EventID:            eventID,
		EventType:          "GCP.HTTPLoadBalancer",
		RequestParameters:  raw,
		RecipientAccountID: projectID,
	}
	if remoteIP != "" {
		ct.UserIdentity = cloudtrail.UserIdentity{
			Type:        "IPAddress",
			PrincipalID: remoteIP,
		}
	}

	return []*cloudtrail.Event{ct}, nil
}

func normalizeGCPHTTPLBKeys(m map[string]interface{}) {
	mergeKey(m, "insertid", "insertId")
	mergeKey(m, "logname", "logName")
}

func isGCPHTTPLoadBalancerShape(m map[string]interface{}) bool {
	if pt, ok := m["p_log_type"].(string); ok && pt == "GCP.HTTPLoadBalancer" {
		return true
	}
	if _, ok := m["httpRequest"].(map[string]interface{}); !ok {
		return false
	}
	if res, ok := m["resource"].(map[string]interface{}); ok {
		if t, ok := res["type"].(string); ok && t == "http_load_balancer" {
			return true
		}
	}
	if ln, ok := stringField(m, "logName"); ok {
		ln = strings.ToLower(ln)
		if strings.Contains(ln, "/logs/requests") {
			return true
		}
	}
	return false
}

func gcpHTTPLBEventID(m map[string]interface{}) string {
	if s, ok := stringField(m, "insertId"); ok && s != "" {
		return s
	}
	if hr, ok := m["httpRequest"].(map[string]interface{}); ok {
		if u, ok := hr["requestUrl"].(string); ok && u != "" {
			return u
		}
	}
	return "gcp-http-lb"
}

var _ ParserInterface = (*GCPHTTPLoadBalancerParser)(nil)
