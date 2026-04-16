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
	"golang.org/x/sync/errgroup"
)

// maxScanTokenSize is the maximum line length for bufio.Scanner in line-delimited mode.
// Default bufio.MaxScanTokenSize is 64 KiB; long JSON lines (e.g. embedded blobs) can exceed it.
const maxScanTokenSize = 10 * 1024 * 1024

type Processor struct {
	adaptiveClassifier *AdaptiveClassifier
	bloomFilter        *bloom.Filter
	// classifyWorkers is the number of parallel classifiers for batched JSON (Records / arrays).
	// Each worker uses its own AdaptiveClassifier; bloom filter stays shared (mutex-safe).
	// Line-delimited parsing stays sequential so adaptive parser priorities stay consistent.
	// 0 means unset (treated as 1).
	classifyWorkers int
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

// SetClassifyWorkers sets parallel record classifiers for S3 JSON batches (root arrays and
// CloudTrail Records). Values below 1 are treated as 1; above 32 are capped at 32.
// Does not apply to line-delimited or single-line JSONL parsing (adaptive state is sequential there).
func (p *Processor) SetClassifyWorkers(n int) {
	if n < 1 {
		p.classifyWorkers = 1
		return
	}
	if n > 32 {
		n = 32
	}
	p.classifyWorkers = n
}

func (p *Processor) workerCount() int {
	if p.classifyWorkers < 1 {
		return 1
	}
	return p.classifyWorkers
}

func newProcessorForParallelClassify(bloom *bloom.Filter) *Processor {
	parserMap := getParsers()
	return &Processor{
		adaptiveClassifier: NewAdaptiveClassifier(parserMap),
		bloomFilter:        bloom,
	}
}

func getParsers() map[string]parsers.ParserInterface {
	return map[string]parsers.ParserInterface{
		"Cloudflare.Firewall":        parsers.NewCloudflareFirewallParser(),
		"Cloudflare.HttpRequest":     parsers.NewCloudflareHTTPRequestParser(),
		"Slack.AuditLogs":            parsers.NewSlackAuditLogsParser(),
		"GCP.HTTPLoadBalancer":       parsers.NewGCPHTTPLoadBalancerParser(),
		"GCP.AuditLog":               parsers.NewGCPAuditLogParser(),
		"Amazon.EKS.Audit":           parsers.NewEKSAuditParser(),
		"AWS.BedrockModelInvocation": parsers.NewBedrockModelInvocationParser(),
		"GitHub.Audit":               parsers.NewGitHubAuditParser(),
		"GitHub.Webhook":             parsers.NewGitHubWebhookParser(),
		"AWS.CloudTrail":             parsers.NewCloudTrailParser(),
		"AWS.S3ServerAccess":         parsers.NewS3ServerAccessParser(),
		"AWS.VPCFlow":                parsers.NewVPCFlowParser(),
		"AWS.ALB":                    parsers.NewALBParser(),
		"AWS.AuroraMySQLAudit":       parsers.NewAuroraMySQLAuditParser(),
		"Okta.SystemLog":             parsers.NewOktaParser(),
		"GSuite.Reports":             parsers.NewGSuiteParser(),
		"OnePassword.SignInAttempt":  parsers.NewOnePasswordParser(),
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
	br := bufio.NewReaderSize(reader, 256*1024)
	head, err := br.Peek(8192)
	if err != nil && err != io.EOF {
		return fmt.Errorf("peek: %w", err)
	}
	if len(head) == 0 && err == io.EOF {
		return nil
	}
	trim := bytes.TrimSpace(head)
	if len(trim) == 0 {
		data, rerr := io.ReadAll(br)
		if rerr != nil {
			return fmt.Errorf("read data: %w", rerr)
		}
		return p.processLineByLine(ctx, data, events)
	}
	if trim[0] == '[' {
		return p.processJSONArrayStream(ctx, br, events)
	}
	if trim[0] == '{' {
		lim := min(1024, len(trim))
		if bytes.Contains(trim[:lim], []byte(`"Records":[`)) || bytes.Contains(trim[:lim], []byte(`"Records": [`)) {
			return p.processRecordsObjectStream(ctx, br, events)
		}
	}
	data, err := io.ReadAll(br)
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

func (p *Processor) processJSONArrayStream(ctx context.Context, r io.Reader, events chan<- *ProcessedEvent) error {
	w := p.workerCount()
	if w <= 1 {
		return p.processJSONArrayStreamSequential(ctx, r, events)
	}
	return p.processJSONArrayStreamParallel(ctx, r, events, w)
}

func (p *Processor) processJSONArrayStreamSequential(ctx context.Context, r io.Reader, events chan<- *ProcessedEvent) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("json: %w", err)
	}
	d, ok := tok.(json.Delim)
	if !ok || d != '[' {
		return fmt.Errorf("expected JSON array")
	}
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return fmt.Errorf("decode array element: %w", err)
		}
		if err := p.processCloudTrailRecord(ctx, raw, events); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("json: %w", err)
	}
	return nil
}

func (p *Processor) processJSONArrayStreamParallel(ctx context.Context, r io.Reader, events chan<- *ProcessedEvent, workers int) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("json: %w", err)
	}
	d, ok := tok.(json.Delim)
	if !ok || d != '[' {
		return fmt.Errorf("expected JSON array")
	}
	if err := p.processJSONArrayBodyFromDecoderParallel(ctx, dec, events, workers); err != nil {
		return err
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("json: %w", err)
	}
	return nil
}

// processJSONArrayBodyFromDecoderParallel decodes the remainder of a JSON array using parallel
// classifiers. The decoder must be positioned after the opening '['.
func (p *Processor) processJSONArrayBodyFromDecoderParallel(ctx context.Context, dec *json.Decoder, events chan<- *ProcessedEvent, workers int) error {
	jobs := make(chan json.RawMessage, workers*4)
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		defer close(jobs)
		for dec.More() {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return fmt.Errorf("decode array element: %w", err)
			}
			select {
			case jobs <- raw:
			case <-gctx.Done():
				return gctx.Err()
			}
		}
		return nil
	})
	for range workers {
		g.Go(func() error {
			sub := newProcessorForParallelClassify(p.bloomFilter)
			for raw := range jobs {
				if err := sub.processCloudTrailRecord(gctx, raw, events); err != nil {
					return err
				}
			}
			return nil
		})
	}
	return g.Wait()
}

func (p *Processor) processRecordsObjectStream(ctx context.Context, r io.Reader, events chan<- *ProcessedEvent) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("json: %w", err)
	}
	d, ok := tok.(json.Delim)
	if !ok || d != '{' {
		return fmt.Errorf("expected JSON object")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return fmt.Errorf("json: %w", err)
		}
		key, ok := t.(string)
		if !ok {
			return fmt.Errorf("expected object key")
		}
		if key == "Records" {
			t2, err := dec.Token()
			if err != nil {
				return fmt.Errorf("json: %w", err)
			}
			d2, ok := t2.(json.Delim)
			if !ok || d2 != '[' {
				return fmt.Errorf("records must be a JSON array")
			}
			w := p.workerCount()
			if w <= 1 {
				for dec.More() {
					var raw json.RawMessage
					if err := dec.Decode(&raw); err != nil {
						return fmt.Errorf("decode Records element: %w", err)
					}
					if err := p.processCloudTrailRecord(ctx, raw, events); err != nil {
						return err
					}
				}
			} else {
				if err := p.processJSONArrayBodyFromDecoderParallel(ctx, dec, events, w); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return fmt.Errorf("json: %w", err)
			}
			for dec.More() {
				if _, err := dec.Token(); err != nil {
					return fmt.Errorf("json: %w", err)
				}
				var discard json.RawMessage
				if err := dec.Decode(&discard); err != nil {
					return fmt.Errorf("json: %w", err)
				}
			}
			if _, err := dec.Token(); err != nil {
				return fmt.Errorf("json: %w", err)
			}
			return nil
		}
		var discard json.RawMessage
		if err := dec.Decode(&discard); err != nil {
			return fmt.Errorf("json: %w", err)
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("json: %w", err)
	}
	return nil
}

func (p *Processor) processCloudTrailRecords(ctx context.Context, records []json.RawMessage, events chan<- *ProcessedEvent) error {
	w := p.workerCount()
	if w <= 1 || len(records) < w*2 {
		for _, recordBytes := range records {
			if err := p.processCloudTrailRecord(ctx, recordBytes, events); err != nil {
				return err
			}
		}
		return nil
	}

	jobs := make(chan json.RawMessage, w*2)
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		defer close(jobs)
		for _, r := range records {
			select {
			case jobs <- r:
			case <-gctx.Done():
				return gctx.Err()
			}
		}
		return nil
	})
	for range w {
		g.Go(func() error {
			sub := newProcessorForParallelClassify(p.bloomFilter)
			for raw := range jobs {
				if err := sub.processCloudTrailRecord(gctx, raw, events); err != nil {
					return err
				}
			}
			return nil
		})
	}
	return g.Wait()
}

func (p *Processor) processCloudTrailRecord(ctx context.Context, recordBytes json.RawMessage, events chan<- *ProcessedEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	result, err := p.adaptiveClassifier.Classify(string(recordBytes))
	if err != nil {
		return nil
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
	return nil
}

func (p *Processor) processLineByLine(ctx context.Context, data []byte, events chan<- *ProcessedEvent) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	buf := make([]byte, 0, bufio.MaxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)
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
	// EventBridge delivers one API call in detail; S3 log files use {"Records":[...]}. Accept the
	// batched wrapper when we already know the payload is CloudTrail-class.
	if logTypeHint == "AWS.CloudTrail" {
		var wrapped struct {
			Records []json.RawMessage `json:"Records"`
		}
		if err := json.Unmarshal(eventJSON, &wrapped); err == nil && len(wrapped.Records) > 0 {
			var out []*ProcessedEvent
			for _, rec := range wrapped.Records {
				part, err := p.ProcessEvent(ctx, rec, logTypeHint)
				if err != nil {
					return nil, err
				}
				out = append(out, part...)
			}
			return out, nil
		}
	}

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
