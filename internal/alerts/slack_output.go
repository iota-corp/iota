package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bilals12/iota/internal/alertforwarder"
	"github.com/bilals12/iota/internal/metrics"
)

type SlackOutput struct {
	webhookURL string
	client     *http.Client
}

func NewSlackOutput(webhookURL string) *SlackOutput {
	return &SlackOutput{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (s *SlackOutput) SendAlert(ctx context.Context, alert *alertforwarder.Alert) error {
	msg := s.formatMessage(alert)

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		metrics.RecordAlertForwarded("slack", "failure")
		return fmt.Errorf("post to slack: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		metrics.RecordAlertForwarded("slack", "failure")
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}

	metrics.RecordAlertForwarded("slack", "success")
	return nil
}

func (s *SlackOutput) formatMessage(alert *alertforwarder.Alert) slackMessage {
	color := getSeverityColor(alert.Severity)

	fields := []slackAttachField{
		{
			Title: "rule id",
			Value: alert.RuleID,
			Short: true,
		},
		{
			Title: "severity",
			Value: alert.Severity,
			Short: true,
		},
		{
			Title: "alert id",
			Value: alert.AlertID,
			Short: true,
		},
		{
			Title: "dedup key",
			Value: alert.DedupKey,
			Short: true,
		},
	}

	if alert.Event != nil {
		fields = append(fields,
			slackAttachField{
				Title: "event name",
				Value: alert.Event.EventName,
				Short: true,
			},
			slackAttachField{
				Title: "event source",
				Value: alert.Event.EventSource,
				Short: true,
			},
			slackAttachField{
				Title: "source ip",
				Value: alert.Event.SourceIPAddress,
				Short: true,
			},
			slackAttachField{
				Title: "region",
				Value: alert.Event.AWSRegion,
				Short: true,
			},
			slackAttachField{
				Title: "account id",
				Value: alert.Event.RecipientAccountID,
				Short: true,
			},
		)
	}

	return slackMessage{
		Attachments: []slackAttachment{
			{
				Color: color,
				Blocks: []slackBlock{
					{
						Type: "header",
						Text: &slackTextNode{
							Type: "plain_text",
							Text: alert.Title,
						},
					},
					{
						Type: "section",
						Text: &slackTextNode{
							Type: "mrkdwn",
							Text: fmt.Sprintf("*created:* %s\n*updated:* %s",
								alert.AlertCreationTime, alert.AlertUpdateTime),
						},
					},
				},
				Fields: fields,
			},
		},
	}
}
