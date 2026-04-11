package parsers

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bilals12/iota/pkg/cloudtrail"
)

type GCPAuditLogParser struct{}

func NewGCPAuditLogParser() *GCPAuditLogParser {
	return &GCPAuditLogParser{}
}

func (p *GCPAuditLogParser) LogType() string {
	return "GCP.AuditLog"
}

func (p *GCPAuditLogParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(log), &raw); err != nil {
		return nil, fmt.Errorf("gcp audit: %w", err)
	}
	normalizeGCPAuditKeys(raw)
	if !isGCPAuditLogShape(raw) {
		return nil, fmt.Errorf("gcp audit: not a GCP audit log shape")
	}

	methodName := gcpProtoString(raw, "methodName")
	serviceName := gcpProtoString(raw, "serviceName")
	eventName := methodName
	if eventName == "" {
		eventName = serviceName
	}
	if eventName == "" {
		return nil, fmt.Errorf("gcp audit: missing methodName/serviceName")
	}

	eventTime, err := gcpParseTimestamp(raw["timestamp"])
	if err != nil {
		eventTime = time.Unix(0, 0).UTC()
	}

	eventID := gcpInsertID(raw)
	principal := gcpPrincipalEmail(raw)
	projectID := ""
	if res, ok := raw["resource"].(map[string]interface{}); ok {
		if labels, ok := res["labels"].(map[string]interface{}); ok {
			if s, ok := labels["project_id"].(string); ok {
				projectID = s
			}
		}
	}

	ct := &cloudtrail.Event{
		EventVersion:       "1.0",
		EventSource:        "cloudaudit.googleapis.com",
		EventName:          eventName,
		EventTime:          eventTime,
		RequestID:          eventID,
		EventID:            eventID,
		EventType:          "GCP.AuditLog",
		RequestParameters:  raw,
		RecipientAccountID: projectID,
	}
	if principal != "" {
		ct.UserIdentity = cloudtrail.UserIdentity{
			Type:        "GCPUser",
			PrincipalID: principal,
			UserName:    principal,
		}
	}

	return []*cloudtrail.Event{ct}, nil
}

func normalizeGCPAuditKeys(m map[string]interface{}) {
	mergeKey(m, "insertid", "insertId")
	mergeKey(m, "logname", "logName")
	mergeKey(m, "receivetimestamp", "receiveTimestamp")
	mergeKey(m, "protopayload", "protoPayload")
	if pp, ok := m["protoPayload"].(map[string]interface{}); ok {
		mergeKey(pp, "servicename", "serviceName")
		mergeKey(pp, "methodname", "methodName")
		mergeKey(pp, "resourcename", "resourceName")
	}
}

func mergeKey(m map[string]interface{}, lower, canon string) {
	if v, ok := m[lower]; ok {
		if _, has := m[canon]; !has {
			m[canon] = v
		}
	}
}

func isGCPAuditLogShape(m map[string]interface{}) bool {
	if pt, ok := m["p_log_type"].(string); ok && pt == "GCP.AuditLog" {
		return true
	}
	if isGCPHTTPLoadBalancerShape(m) {
		return false
	}
	if ln, ok := stringField(m, "logName"); ok {
		if strings.Contains(ln, "cloudaudit.googleapis.com") {
			return true
		}
	}
	pp, ok := m["protoPayload"].(map[string]interface{})
	if !ok {
		pp, ok = m["protopayload"].(map[string]interface{})
	}
	if ok {
		if _, ok := pp["methodName"].(string); ok {
			return true
		}
		if _, ok := pp["serviceName"].(string); ok {
			return true
		}
	}
	if _, ok := m["methodName"].(string); ok {
		return true
	}
	return false
}

func protoPayloadMap(m map[string]interface{}) map[string]interface{} {
	if pp, ok := m["protoPayload"].(map[string]interface{}); ok {
		return pp
	}
	if pp, ok := m["protopayload"].(map[string]interface{}); ok {
		return pp
	}
	return nil
}

func gcpProtoString(m map[string]interface{}, field string) string {
	if pp := protoPayloadMap(m); pp != nil {
		if v, ok := pp[field].(string); ok && v != "" {
			return v
		}
		if v, ok := pp[strings.ToLower(field)].(string); ok && v != "" {
			return v
		}
	}
	if field == "methodName" {
		if s, ok := m["methodName"].(string); ok {
			return s
		}
	}
	return ""
}

func gcpPrincipalEmail(m map[string]interface{}) string {
	pp := protoPayloadMap(m)
	if pp == nil {
		return ""
	}
	auth, ok := pp["authenticationInfo"].(map[string]interface{})
	if !ok {
		auth, ok = pp["authenticationinfo"].(map[string]interface{})
	}
	if !ok {
		return ""
	}
	if s, ok := auth["principalEmail"].(string); ok {
		return s
	}
	if s, ok := auth["principalemail"].(string); ok {
		return s
	}
	return ""
}

func gcpInsertID(m map[string]interface{}) string {
	if s, ok := stringField(m, "insertId"); ok && s != "" {
		return s
	}
	method := gcpProtoString(m, "methodName")
	if method == "" {
		method = "audit"
	}
	ts := ""
	switch v := m["timestamp"].(type) {
	case string:
		ts = v
	case float64:
		ts = strconv.FormatInt(int64(v), 10)
	}
	return fmt.Sprintf("%s-%s", method, ts)
}

func stringField(m map[string]interface{}, canon string) (string, bool) {
	if s, ok := m[canon].(string); ok && s != "" {
		return s, true
	}
	low := strings.ToLower(canon)
	if s, ok := m[low].(string); ok && s != "" {
		return s, true
	}
	return "", false
}

func gcpParseTimestamp(v interface{}) (time.Time, error) {
	if v == nil {
		return time.Time{}, fmt.Errorf("missing timestamp")
	}
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return time.Time{}, fmt.Errorf("empty timestamp")
		}
		layouts := []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05.000000000",
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05.000000000",
			"2006-01-02 15:04:05.000",
			"2006-01-02 15:04:05",
		}
		var lastErr error
		for _, layout := range layouts {
			parsed, err := time.Parse(layout, s)
			if err == nil {
				return parsed.UTC(), nil
			}
			lastErr = err
		}
		return time.Time{}, fmt.Errorf("parse %q: %w", s, lastErr)
	case float64:
		sec := int64(t)
		nsec := int64((t - float64(sec)) * 1e9)
		return time.Unix(sec, nsec).UTC(), nil
	default:
		return time.Time{}, fmt.Errorf("unsupported timestamp type")
	}
}

var _ ParserInterface = (*GCPAuditLogParser)(nil)
