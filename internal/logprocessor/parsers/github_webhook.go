package parsers

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/bilals12/iota/pkg/cloudtrail"
)

type GitHubWebhookParser struct{}

func NewGitHubWebhookParser() *GitHubWebhookParser {
	return &GitHubWebhookParser{}
}

func (p *GitHubWebhookParser) LogType() string {
	return "GitHub.Webhook"
}

func (p *GitHubWebhookParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(log), &raw); err != nil {
		return nil, fmt.Errorf("github webhook: %w", err)
	}
	if !isGitHubWebhookShape(raw) {
		return nil, fmt.Errorf("github webhook: not a webhook payload shape")
	}

	action, _ := raw["action"].(string)
	if action == "" {
		return nil, fmt.Errorf("github webhook: missing action")
	}

	eventTime, err := githubWebhookEventTime(raw)
	if err != nil {
		eventTime = time.Now().UTC()
	}

	eventID := githubWebhookEventID(raw)

	ct := &cloudtrail.Event{
		EventVersion:       "1.0",
		EventSource:        "github.com.webhook",
		EventName:          action,
		EventTime:          eventTime,
		RequestID:          eventID,
		EventID:            eventID,
		EventType:          "GitHub.Webhook",
		RequestParameters:  raw,
		RecipientAccountID: "",
	}

	if sender, ok := raw["sender"].(map[string]interface{}); ok {
		if login, ok := sender["login"].(string); ok && login != "" {
			ct.UserIdentity = cloudtrail.UserIdentity{
				Type:        "GitHubUser",
				PrincipalID: login,
				UserName:    login,
			}
		}
	}

	return []*cloudtrail.Event{ct}, nil
}

func isGitHubWebhookShape(m map[string]interface{}) bool {
	if pt, ok := m["p_log_type"].(string); ok && pt == "GitHub.Webhook" {
		if _, ok := m["repository"].(map[string]interface{}); ok {
			return true
		}
	}
	if _, ok := m["repository"].(map[string]interface{}); !ok {
		return false
	}
	if _, ok := m["sender"].(map[string]interface{}); ok {
		return true
	}
	if _, ok := m["pusher"].(map[string]interface{}); ok {
		return true
	}
	if _, ok := m["workflow_run"].(map[string]interface{}); ok {
		return true
	}
	if _, ok := m["pull_request"].(map[string]interface{}); ok {
		return true
	}
	return false
}

func githubWebhookEventTime(m map[string]interface{}) (time.Time, error) {
	if wr, ok := m["workflow_run"].(map[string]interface{}); ok {
		if s, ok := wr["updated_at"].(string); ok {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t.UTC(), nil
			}
		}
		if s, ok := wr["created_at"].(string); ok {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t.UTC(), nil
			}
		}
	}
	if pr, ok := m["pull_request"].(map[string]interface{}); ok {
		if s, ok := pr["updated_at"].(string); ok {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t.UTC(), nil
			}
		}
		if s, ok := pr["created_at"].(string); ok {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t.UTC(), nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("no webhook timestamp")
}

func githubWebhookEventID(m map[string]interface{}) string {
	if wr, ok := m["workflow_run"].(map[string]interface{}); ok {
		if id, ok := wr["id"].(float64); ok {
			return fmt.Sprintf("wr-%d", int64(id))
		}
	}
	if pr, ok := m["pull_request"].(map[string]interface{}); ok {
		if id, ok := pr["id"].(float64); ok {
			return fmt.Sprintf("pr-%d", int64(id))
		}
	}
	action, _ := m["action"].(string)
	repo := ""
	if r, ok := m["repository"].(map[string]interface{}); ok {
		repo, _ = r["full_name"].(string)
	}
	return fmt.Sprintf("%s-%s", action, repo)
}

var _ ParserInterface = (*GitHubWebhookParser)(nil)
