package transform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bilals12/iota/pkg/config"
	"github.com/bilals12/iota/pkg/message"
)

type sendSlackConfig struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
	Username   string `json:"username"`
}

type sendSlack struct {
	webhookURL string
	channel    string
	username   string
	client     *http.Client
}

func newSendSlack(ctx context.Context, cfg config.Config) (*sendSlack, error) {
	var conf sendSlackConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform send_slack: %v", err)
	}
	if conf.WebhookURL == "" {
		return nil, fmt.Errorf("transform send_slack: webhook_url is required")
	}
	return &sendSlack{
		webhookURL: conf.WebhookURL,
		channel:    conf.Channel,
		username:   conf.Username,
		client:     &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (t *sendSlack) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return []*message.Message{msg}, nil
	}

	payload := map[string]interface{}{
		"text": msg.String(),
	}
	if t.channel != "" {
		payload["channel"] = t.channel
	}
	if t.username != "" {
		payload["username"] = t.username
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("transform send_slack: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.webhookURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("transform send_slack: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("transform send_slack: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("transform send_slack: status %d: %s", resp.StatusCode, string(respBody))
	}

	return []*message.Message{msg}, nil
}

type sendHTTPPostConfig struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Timeout string            `json:"timeout"`
}

type sendHTTPPost struct {
	url     string
	headers map[string]string
	client  *http.Client
}

func newSendHTTPPost(ctx context.Context, cfg config.Config) (*sendHTTPPost, error) {
	var conf sendHTTPPostConfig
	if err := config.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("transform send_http_post: %v", err)
	}
	if conf.URL == "" {
		return nil, fmt.Errorf("transform send_http_post: url is required")
	}

	timeout := 10 * time.Second
	if conf.Timeout != "" {
		d, err := time.ParseDuration(conf.Timeout)
		if err == nil {
			timeout = d
		}
	}

	return &sendHTTPPost{
		url:     conf.URL,
		headers: conf.Headers,
		client:  &http.Client{Timeout: timeout},
	}, nil
}

func (t *sendHTTPPost) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return []*message.Message{msg}, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(msg.Data()))
	if err != nil {
		return nil, fmt.Errorf("transform send_http_post: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("transform send_http_post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("transform send_http_post: status %d: %s", resp.StatusCode, string(respBody))
	}

	return []*message.Message{msg}, nil
}
