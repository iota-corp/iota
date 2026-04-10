package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("slack returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	metrics.RecordAlertForwarded("slack", "success")
	return nil
}

func (s *SlackOutput) formatMessage(alert *alertforwarder.Alert) slackMessage {
	color := getSeverityColor(alert.Severity)

	meta := fmt.Sprintf("*rule id:* %s\n*severity:* %s\n*alert id:* %s\n*dedup key:* %s\n*created:* %s\n*updated:* %s",
		slackMrkdwnLite(alert.RuleID),
		slackMrkdwnLite(alert.Severity),
		slackMrkdwnLite(alert.AlertID),
		slackMrkdwnLite(alert.DedupKey),
		slackMrkdwnLite(alert.AlertCreationTime),
		slackMrkdwnLite(alert.AlertUpdateTime),
	)

	var eventSection string
	if alert.Event != nil {
		ev := alert.Event
		eventSection = strings.Join([]string{
			fmt.Sprintf("*event name:* %s", slackMrkdwnLite(ev.EventName)),
			fmt.Sprintf("*event source:* %s", slackMrkdwnLite(ev.EventSource)),
			fmt.Sprintf("*source ip:* %s", slackMrkdwnLite(ev.SourceIPAddress)),
			fmt.Sprintf("*region:* %s", slackMrkdwnLite(ev.AWSRegion)),
			fmt.Sprintf("*account id:* %s", slackMrkdwnLite(ev.RecipientAccountID)),
		}, "\n")
	} else {
		eventSection = "_no event payload_"
	}

	blocks := []slackBlock{
		{
			Type: "header",
			Text: &slackTextNode{
				Type: "plain_text",
				Text: truncateSlackHeaderPlain(alert.Title),
			},
		},
		{
			Type: "section",
			Text: &slackTextNode{
				Type: "mrkdwn",
				Text: meta,
			},
		},
		{
			Type: "section",
			Text: &slackTextNode{
				Type: "mrkdwn",
				Text: eventSection,
			},
		},
	}

	return slackMessage{
		Attachments: []slackAttachment{
			{
				Color:  color,
				Blocks: blocks,
			},
		},
	}
}
