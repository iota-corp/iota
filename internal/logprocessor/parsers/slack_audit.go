package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bilals12/iota/pkg/cloudtrail"
)

type SlackAuditLogsParser struct{}

func NewSlackAuditLogsParser() *SlackAuditLogsParser {
	return &SlackAuditLogsParser{}
}

func (p *SlackAuditLogsParser) LogType() string {
	return "Slack.AuditLogs"
}

func (p *SlackAuditLogsParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(log), &raw); err != nil {
		return nil, fmt.Errorf("slack audit: %w", err)
	}
	if !isSlackAuditLogsShape(raw) {
		return nil, fmt.Errorf("slack audit: not a Slack audit log shape")
	}

	action, _ := raw["action"].(string)
	if action == "" {
		return nil, fmt.Errorf("slack audit: missing action")
	}

	eventTime, err := slackAuditEventTime(raw)
	if err != nil {
		eventTime = time.Unix(0, 0).UTC()
	}

	eventID := slackAuditEventID(raw)
	email := ""
	if actor, ok := raw["actor"].(map[string]interface{}); ok {
		if u, ok := actor["user"].(map[string]interface{}); ok {
			if s, ok := u["email"].(string); ok {
				email = s
			}
		}
	}

	ct := &cloudtrail.Event{
		EventVersion:      "1.0",
		EventSource:       "slack.com",
		EventName:         action,
		EventTime:         eventTime,
		RequestID:         eventID,
		EventID:           eventID,
		EventType:         "Slack.AuditLogs",
		RequestParameters: raw,
	}
	if email != "" {
		ct.UserIdentity = cloudtrail.UserIdentity{
			Type:        "SlackUser",
			PrincipalID: email,
			UserName:    email,
		}
	}

	return []*cloudtrail.Event{ct}, nil
}

func isSlackAuditLogsShape(m map[string]interface{}) bool {
	if pt, ok := m["p_log_type"].(string); ok && strings.Contains(pt, "Slack.Audit") {
		return true
	}
	_, hasAction := m["action"].(string)
	_, hasActor := m["actor"].(map[string]interface{})
	_, hasDate := m["date_create"].(string)
	return hasAction && hasActor && hasDate
}

func slackAuditEventTime(m map[string]interface{}) (time.Time, error) {
	switch v := m["date_create"].(type) {
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return time.Time{}, fmt.Errorf("empty date_create")
		}
		layouts := []string{
			"2006-01-02 15:04:05",
			time.RFC3339,
			time.RFC3339Nano,
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, s); err == nil {
				return t.UTC(), nil
			}
		}
		return time.Time{}, fmt.Errorf("parse date_create")
	default:
		return time.Time{}, fmt.Errorf("date_create type")
	}
}

func slackAuditEventID(m map[string]interface{}) string {
	if id, ok := m["p_row_id"].(string); ok && id != "" {
		return id
	}
	action, _ := m["action"].(string)
	dc, _ := m["date_create"].(string)
	return fmt.Sprintf("%s-%s", action, dc)
}

var _ ParserInterface = (*SlackAuditLogsParser)(nil)
