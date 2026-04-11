package parsers

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/bilals12/iota/pkg/cloudtrail"
)

type GitHubAuditParser struct{}

func NewGitHubAuditParser() *GitHubAuditParser {
	return &GitHubAuditParser{}
}

func (p *GitHubAuditParser) LogType() string {
	return "GitHub.Audit"
}

func (p *GitHubAuditParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(log), &raw); err != nil {
		return nil, fmt.Errorf("github audit: %w", err)
	}
	if !isGitHubAuditShape(raw) {
		return nil, fmt.Errorf("github audit: not an audit log shape")
	}

	action, _ := raw["action"].(string)
	if action == "" {
		return nil, fmt.Errorf("github audit: missing action")
	}

	eventTime, err := githubAuditEventTime(raw)
	if err != nil {
		return nil, err
	}

	eventID := githubAuditEventID(raw)
	actor, _ := raw["actor"].(string)

	ct := &cloudtrail.Event{
		EventVersion:       "1.0",
		EventSource:        "github.com",
		EventName:          action,
		EventTime:          eventTime,
		RequestID:          eventID,
		EventID:            eventID,
		EventType:          "GitHub.Audit",
		RequestParameters:  raw,
		RecipientAccountID: "",
	}
	if actor != "" {
		ct.UserIdentity = cloudtrail.UserIdentity{
			Type:        "GitHubUser",
			PrincipalID: actor,
			UserName:    actor,
		}
	}

	return []*cloudtrail.Event{ct}, nil
}

func isGitHubAuditShape(m map[string]interface{}) bool {
	if pt, ok := m["p_log_type"].(string); ok && pt == "GitHub.Audit" {
		return true
	}
	if _, ok := m["action"].(string); !ok {
		return false
	}
	if _, ok := m["repository"].(map[string]interface{}); ok {
		return false
	}
	switch v := m["created_at"].(type) {
	case float64:
		return v > 0
	}
	return false
}

func githubAuditEventTime(m map[string]interface{}) (time.Time, error) {
	switch v := m["created_at"].(type) {
	case float64:
		ms := int64(v)
		if ms > 1e12 {
			return time.UnixMilli(ms).UTC(), nil
		}
		return time.Unix(ms, 0).UTC(), nil
	case string:
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.UTC(), nil
		}
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t.UTC(), nil
		}
		return time.Time{}, fmt.Errorf("github audit: parse created_at string")
	case nil:
		if pt, ok := m["p_log_type"].(string); ok && pt == "GitHub.Audit" {
			return time.Unix(0, 0).UTC(), nil
		}
		return time.Time{}, fmt.Errorf("github audit: missing created_at")
	default:
		return time.Time{}, fmt.Errorf("github audit: unsupported created_at type")
	}
}

func githubAuditEventID(m map[string]interface{}) string {
	if id, ok := m["id"].(string); ok && id != "" {
		return id
	}
	if id, ok := m["id"].(float64); ok {
		return strconv.FormatInt(int64(id), 10)
	}
	actor, _ := m["actor"].(string)
	action, _ := m["action"].(string)
	var ts string
	switch v := m["created_at"].(type) {
	case float64:
		ts = strconv.FormatInt(int64(v), 10)
	case string:
		ts = v
	default:
		ts = "0"
	}
	return fmt.Sprintf("%s-%s-%s", actor, action, ts)
}

var _ ParserInterface = (*GitHubAuditParser)(nil)
