package logprocessor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/bilals12/iota/internal/bloom"
	"github.com/bilals12/iota/internal/logprocessor/parsers"
	"github.com/bilals12/iota/pkg/cloudtrail"
)

type Processor struct {
	adaptiveClassifier *AdaptiveClassifier
	bloomFilter        *bloom.Filter
}

type ProcessedEvent struct {
	Event     *cloudtrail.Event
	LogType   string
	EventTime time.Time
	ParseTime time.Time
	RowID     string
}

func New() *Processor {
	parserMap := getParsers()
	return &Processor{
		adaptiveClassifier: NewAdaptiveClassifier(parserMap),
	}
}

func NewWithBloomFilter(bloomFilter *bloom.Filter) *Processor {
	parserMap := getParsers()
	return &Processor{
		adaptiveClassifier: NewAdaptiveClassifier(parserMap),
		bloomFilter:        bloomFilter,
	}
}

func getParsers() map[string]parsers.ParserInterface {
	return map[string]parsers.ParserInterface{
		"Cloudflare.Firewall":        parsers.NewCloudflareFirewallParser(),
		"Cloudflare.HttpRequest":     parsers.NewCloudflareHTTPRequestParser(),
		"Slack.AuditLogs":            parsers.NewSlackAuditLogsParser(),
		"GCP.HTTPLoadBalancer":       parsers.NewGCPHTTPLoadBalancerParser(),
		"GCP.AuditLog":               parsers.NewGCPAuditLogParser(),
		"Amazon.EKS.Audit":          parsers.NewEKSAuditParser(),
		"AWS.BedrockModelInvocation": parsers.NewBedrockModelInvocationParser(),
		"GitHub.Audit":               parsers.NewGitHubAuditParser(),
		"GitHub.Webhook":             parsers.NewGitHubWebhookParser(),
		"AWS.CloudTrail":             parsers.NewCloudTrailParser(),
		"AWS.S3ServerAccess":         parsers.NewS3ServerAccessParser(),
		"AWS.VPCFlow":               parsers.NewVPCFlowParser(),
		"AWS.ALB":                   parsers.NewALBParser(),
		"AWS.AuroraMySQLAudit":      parsers.NewAuroraMySQLAuditParser(),
		"Okta.SystemLog":            parsers.NewOktaParser(),
		"GSuite.Reports":            parsers.NewGSuiteParser(),
		"OnePassword.SignInAttempt": parsers.NewOnePasswordParser(),
	}
}

func (p *Processor) Process(ctx context.Context, reader io.Reader) (<-chan *ProcessedEvent, <-chan error) {
	events := make(chan *ProcessedEvent, 100)
	errs := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errs)

		if err := p.processReader(ctx, reader, events); err != nil {
			select {
			case errs <- err:
			case <-ctx.Done():
			}
		}
	}()

	return events, errs
}

func (p *Processor) processReader(ctx context.Context, reader io.Reader, events chan<- *ProcessedEvent) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("read data: %w", err)
	}

	var cloudTrailFile struct {
		Records []json.RawMessage `json:"Records"`
	}

	if err := json.Unmarshal(data, &cloudTrailFile); err == nil && len(cloudTrailFile.Records) > 0 {
		return p.processCloudTrailRecords(ctx, cloudTrailFile.Records, events)
	}

	var jsonArray []json.RawMessage
	if err := json.Unmarshal(data, &jsonArray); err == nil && len(jsonArray) > 0 {
		return p.processCloudTrailRecords(ctx, jsonArray, events)
	}

	return p.processLineByLine(ctx, data, events)
}

func (p *Processor) processCloudTrailRecords(ctx context.Context, records []json.RawMessage, events chan<- *ProcessedEvent) error {
	for _, recordBytes := range records {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		result, err := p.adaptiveClassifier.Classify(string(recordBytes))
		if err != nil {
			continue
		}

		for _, event := range result.Events {
			if p.bloomFilter != nil {
				if p.bloomFilter.Test([]byte(event.EventID)) {
					continue
				}
				p.bloomFilter.Add([]byte(event.EventID))
			}

			now := time.Now()
			processed := &ProcessedEvent{
				Event:     event,
				LogType:   result.LogType,
				EventTime: event.EventTime,
				ParseTime: now,
				RowID:     generateRowID(event),
			}

			select {
			case events <- processed:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}

func (p *Processor) processLineByLine(ctx context.Context, data []byte, events chan<- *ProcessedEvent) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		result, err := p.adaptiveClassifier.Classify(line)
		if err != nil {
			continue
		}

		for _, event := range result.Events {
			if p.bloomFilter != nil {
				if p.bloomFilter.Test([]byte(event.EventID)) {
					continue
				}
				p.bloomFilter.Add([]byte(event.EventID))
			}

			now := time.Now()
			processed := &ProcessedEvent{
				Event:     event,
				LogType:   result.LogType,
				EventTime: event.EventTime,
				ParseTime: now,
				RowID:     generateRowID(event),
			}

			select {
			case events <- processed:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return scanner.Err()
}

func generateRowID(event *cloudtrail.Event) string {
	return fmt.Sprintf("%s-%s", event.EventID, event.EventTime.Format("20060102150405"))
}

func (p *Processor) ProcessEvent(ctx context.Context, eventJSON []byte, logTypeHint string) ([]*ProcessedEvent, error) {
	line := string(eventJSON)

	if logTypeHint != "" {
		result, err := p.adaptiveClassifier.ClassifyWithHint(line, logTypeHint)
		if err == nil && len(result.Events) > 0 {
			return p.processClassifyResult(ctx, result)
		}
	}

	result, err := p.adaptiveClassifier.Classify(line)
	if err != nil {
		return nil, fmt.Errorf("classify event: %w", err)
	}

	return p.processClassifyResult(ctx, result)
}

// ProcessLineBestEffort parses one newline-delimited log line. It returns (nil, nil) when no parser
// matches (e.g. non-JSON or unrelated log types), which is normal for mixed audit backends.
func (p *Processor) ProcessLineBestEffort(ctx context.Context, line []byte) ([]*ProcessedEvent, error) {
	if len(bytes.TrimSpace(line)) == 0 {
		return nil, nil
	}
	result, err := p.adaptiveClassifier.Classify(string(line))
	if err != nil {
		return nil, nil
	}
	if !result.Matched || len(result.Events) == 0 {
		return nil, nil
	}
	return p.processClassifyResult(ctx, result)
}

func (p *Processor) processClassifyResult(ctx context.Context, result *ClassifierResult) ([]*ProcessedEvent, error) {
	var processed []*ProcessedEvent

	for _, event := range result.Events {
		select {
		case <-ctx.Done():
			return processed, ctx.Err()
		default:
		}

		if p.bloomFilter != nil {
			if p.bloomFilter.Test([]byte(event.EventID)) {
				continue
			}
			p.bloomFilter.Add([]byte(event.EventID))
		}

		now := time.Now()
		pe := &ProcessedEvent{
			Event:     event,
			LogType:   result.LogType,
			EventTime: event.EventTime,
			ParseTime: now,
			RowID:     generateRowID(event),
		}

		processed = append(processed, pe)
	}

	return processed, nil
}
