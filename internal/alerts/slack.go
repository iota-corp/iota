package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bilals12/iota/internal/engine"
)

type SlackClient struct {
	webhookURL string
	client     *http.Client
}

type slackMessage struct {
	Text        string            `json:"text,omitempty"`
	Blocks      []slackBlock      `json:"blocks,omitempty"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

type slackBlock struct {
	Type string         `json:"type"`
	Text *slackTextNode `json:"text,omitempty"`
}

type slackTextNode struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackAttachment struct {
	Color  string       `json:"color"`
	Blocks []slackBlock `json:"blocks,omitempty"`
	// Do not set legacy Fields on the same attachment as Blocks — Slack returns 400.
}

func NewSlackClient(webhookURL string) *SlackClient {
	return &SlackClient{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (s *SlackClient) SendAlert(match engine.Match) error {
	msg := s.formatMessage(match)

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	resp, err := s.client.Post(s.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("post to slack: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("slack returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	return nil
}

// slackHeaderPlainMax is Slack's max length for header block plain_text.
const slackHeaderPlainMax = 150

func truncateSlackHeaderPlain(s string) string {
	if utf8.RuneCountInString(s) <= slackHeaderPlainMax {
		return s
	}
	r := []rune(s)
	return string(r[:slackHeaderPlainMax-1]) + "…"
}

func (s *SlackClient) formatMessage(match engine.Match) slackMessage {
	color := getSeverityColor(match.Severity)

	summary := fmt.Sprintf("*severity:* %s\n*rule:* %s\n*dedup:* %s",
		slackMrkdwnLite(match.Severity),
		slackMrkdwnLite(match.RuleID),
		slackMrkdwnLite(match.Dedup))

	var eventLines []string
	if match.Event != nil {
		ev := match.Event
		uidType := ""
		if ev.UserIdentity.Type != "" {
			uidType = ev.UserIdentity.Type
		}
		eksAudit := ev.EventSource == "eks.amazonaws.com"
		srcIP := ev.SourceIPAddress
		if srcIP == "" && eksAudit {
			srcIP = "N/A (not present on this audit record)"
		}
		region := ev.AWSRegion
		if region == "" && eksAudit {
			region = "N/A (Kubernetes audit has no AWS region)"
		}
		acct := ev.RecipientAccountID
		if acct == "" && eksAudit {
			acct = "N/A (Kubernetes audit has no AWS account)"
		}
		eventLines = append(eventLines,
			fmt.Sprintf("*event name:* %s", slackMrkdwnLite(ev.EventName)),
			fmt.Sprintf("*event source:* %s", slackMrkdwnLite(ev.EventSource)),
			fmt.Sprintf("*source ip:* %s", slackMrkdwnLite(srcIP)),
			fmt.Sprintf("*user agent:* %s", slackMrkdwnLite(ev.UserAgent)),
			fmt.Sprintf("*region:* %s", slackMrkdwnLite(region)),
			fmt.Sprintf("*user identity type:* %s", slackMrkdwnLite(uidType)),
			fmt.Sprintf("*account id:* %s", slackMrkdwnLite(acct)),
		)
	} else {
		eventLines = []string{"_no event payload_"}
	}
	eventSection := strings.Join(eventLines, "\n")

	return slackMessage{
		Attachments: []slackAttachment{
			{
				Color: color,
				Blocks: []slackBlock{
					{
						Type: "header",
						Text: &slackTextNode{
							Type: "plain_text",
							Text: truncateSlackHeaderPlain(match.Title),
						},
					},
					{
						Type: "section",
						Text: &slackTextNode{
							Type: "mrkdwn",
							Text: summary,
						},
					},
					{
						Type: "section",
						Text: &slackTextNode{
							Type: "mrkdwn",
							Text: eventSection,
						},
					},
				},
			},
		},
	}
}

// slackMrkdwnLite escapes characters that break mrkdwn or annoy Slack in simple labels.
func slackMrkdwnLite(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func getSeverityColor(severity string) string {
	switch severity {
	case "CRITICAL":
		return "#d32f2f"
	case "HIGH":
		return "#f57c00"
	case "MEDIUM":
		return "#fbc02d"
	case "LOW":
		return "#689f38"
	case "INFO":
		return "#1976d2"
	case "DEFAULT":
		return "#fbc02d"
	default:
		return "#757575"
	}
}
