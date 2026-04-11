package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bilals12/iota/pkg/cloudtrail"
)

type EKSAuditParser struct{}

func NewEKSAuditParser() *EKSAuditParser {
	return &EKSAuditParser{}
}

func (p *EKSAuditParser) LogType() string {
	return "Amazon.EKS.Audit"
}

func (p *EKSAuditParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(log), &raw); err != nil {
		return nil, fmt.Errorf("eks audit: %w", err)
	}
	if !isEKSAuditShape(raw) {
		return nil, fmt.Errorf("eks audit: not an EKS / Kubernetes audit Event shape")
	}

	auditID := eksAuditID(raw)
	eventTime, err := eksAuditEventTime(raw)
	if err != nil {
		eventTime = time.Unix(0, 0).UTC()
	}

	verb, _ := raw["verb"].(string)
	eventName := verb
	if or, ok := raw["objectRef"].(map[string]interface{}); ok {
		if res, ok := or["resource"].(string); ok && res != "" {
			eventName = verb + "." + res
			if sub, ok := or["subresource"].(string); ok && sub != "" {
				eventName += "." + sub
			}
		}
	}
	if eventName == "" {
		eventName = "audit"
	}

	username := ""
	if u, ok := raw["user"].(map[string]interface{}); ok {
		username, _ = u["username"].(string)
	}

	userAgent, _ := raw["userAgent"].(string)
	ct := &cloudtrail.Event{
		EventVersion:      "1.0",
		EventSource:       "eks.amazonaws.com",
		EventName:         eventName,
		EventTime:         eventTime,
		RequestID:         auditID,
		EventID:           auditID,
		EventType:         "Amazon.EKS.Audit",
		UserAgent:         userAgent,
		SourceIPAddress:   eksAuditFirstSourceIP(raw),
		RequestParameters: raw,
	}
	// AWS account and region are CloudTrail concepts; raw Kubernetes audit does not include them.
	if username != "" {
		ct.UserIdentity = cloudtrail.UserIdentity{
			Type:        "K8sUser",
			PrincipalID: username,
			UserName:    username,
		}
	}

	return []*cloudtrail.Event{ct}, nil
}

func isEKSAuditShape(m map[string]interface{}) bool {
	if pt, ok := m["p_log_type"].(string); ok && pt == "Amazon.EKS.Audit" {
		return true
	}
	kind, _ := m["kind"].(string)
	av, _ := m["apiVersion"].(string)
	if kind != "Event" {
		return false
	}
	// Prefix match only (avoid substring matches like "evilaudit.k8s.io/v1")
	return av == "audit.k8s.io/v1" || strings.HasPrefix(av, "audit.k8s.io/")
}

func eksAuditID(m map[string]interface{}) string {
	if id, ok := m["auditID"].(string); ok && id != "" {
		return id
	}
	v, _ := m["verb"].(string)
	ts := ""
	switch t := m["requestReceivedTimestamp"].(type) {
	case string:
		ts = t
	default:
		ts = "0"
	}
	return fmt.Sprintf("%s-%s", v, ts)
}

func eksAuditFirstSourceIP(m map[string]interface{}) string {
	v, ok := m["sourceIPs"]
	if !ok || v == nil {
		return ""
	}
	switch xs := v.(type) {
	case []interface{}:
		for _, x := range xs {
			if s, ok := x.(string); ok && s != "" {
				return s
			}
		}
	case []string:
		if len(xs) > 0 {
			return xs[0]
		}
	}
	return ""
}

func eksAuditEventTime(m map[string]interface{}) (time.Time, error) {
	for _, key := range []string{"requestReceivedTimestamp", "stageTimestamp"} {
		switch v := m[key].(type) {
		case string:
			if v == "" {
				continue
			}
			if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
				return t.UTC(), nil
			}
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				return t.UTC(), nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("eks audit: missing timestamp")
}

var _ ParserInterface = (*EKSAuditParser)(nil)
