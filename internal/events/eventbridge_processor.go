package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

type EventHandler func(ctx context.Context, eventJSON []byte, logType string, envelope *EventBridgeEnvelope) error

type EventBridgeProcessor struct {
	client             *sqs.Client
	queueURL           string
	handler            EventHandler
	maxMessages        int32
	waitTime           int32
	processConcurrency int
}

type EventBridgeConfig struct {
	QueueURL    string
	Handler     EventHandler
	MaxMessages int32
	WaitTime    int32
	// ProcessConcurrency is SQS messages processed in parallel per receive (default 1).
	ProcessConcurrency int
}

func NewEventBridgeProcessor(client *sqs.Client, cfg EventBridgeConfig) *EventBridgeProcessor {
	maxMessages := cfg.MaxMessages
	if maxMessages == 0 {
		maxMessages = 10
	}
	waitTime := cfg.WaitTime
	if waitTime == 0 {
		waitTime = 20
	}

	procConc := cfg.ProcessConcurrency
	if procConc <= 0 {
		procConc = 1
	}

	return &EventBridgeProcessor{
		client:             client,
		queueURL:           cfg.QueueURL,
		handler:            cfg.Handler,
		maxMessages:        maxMessages,
		waitTime:           waitTime,
		processConcurrency: procConc,
	}
}

func (p *EventBridgeProcessor) Process(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		result, err := p.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
			QueueUrl:            aws.String(p.queueURL),
			MaxNumberOfMessages: p.maxMessages,
			WaitTimeSeconds:     p.waitTime,
			VisibilityTimeout:   int32(300),
		})
		if err != nil {
			return fmt.Errorf("receive message: %w", err)
		}

		msgs := result.Messages
		if len(msgs) == 0 {
			continue
		}

		if p.processConcurrency <= 1 {
			for _, message := range msgs {
				if err := p.processMessage(ctx, message); err != nil {
					log.Printf("error processing message: %v", err)
					continue
				}
				if _, err := p.client.DeleteMessage(ctx, &sqs.DeleteMessageInput{
					QueueUrl:        aws.String(p.queueURL),
					ReceiptHandle: message.ReceiptHandle,
				}); err != nil {
					log.Printf("error deleting message: %v", err)
				}
			}
			continue
		}

		errs := make([]error, len(msgs))
		var wg sync.WaitGroup
		sem := make(chan struct{}, p.processConcurrency)
		for i := range msgs {
			i, message := i, msgs[i]
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				errs[i] = p.processMessage(ctx, message)
			}()
		}
		wg.Wait()

		for i, message := range msgs {
			if errs[i] != nil {
				log.Printf("eventbridge sqs: skip delete after process error: %v", errs[i])
				continue
			}
			if _, err := p.client.DeleteMessage(ctx, &sqs.DeleteMessageInput{
				QueueUrl:        aws.String(p.queueURL),
				ReceiptHandle: message.ReceiptHandle,
			}); err != nil {
				log.Printf("error deleting message: %v", err)
			}
		}
	}
}

func (p *EventBridgeProcessor) processMessage(ctx context.Context, message types.Message) error {
	if message.Body == nil {
		return nil
	}

	body := []byte(*message.Body)

	detail, envelope, err := UnwrapEventBridgeEvent(body)
	if err != nil {
		return fmt.Errorf("unwrap eventbridge event: %w", err)
	}

	logType := ""
	if envelope != nil {
		logType = DetectEventSource(envelope)
	}

	if envelope == nil {
		detail = body
	}

	return p.handler(ctx, detail, logType, envelope)
}

type BatchedEvent struct {
	Events []json.RawMessage `json:"events"`
}

func ProcessBatchedEvents(data []byte) ([][]byte, error) {
	var events []json.RawMessage
	if err := json.Unmarshal(data, &events); err == nil && len(events) > 0 {
		result := make([][]byte, len(events))
		for i, e := range events {
			result[i] = e
		}
		return result, nil
	}

	var batched BatchedEvent
	if err := json.Unmarshal(data, &batched); err == nil && len(batched.Events) > 0 {
		result := make([][]byte, len(batched.Events))
		for i, e := range batched.Events {
			result[i] = e
		}
		return result, nil
	}

	return [][]byte{data}, nil
}

type EventBridgeMetrics struct {
	EventsReceived  int64
	EventsProcessed int64
	EventsFailed    int64
	LastEventTime   time.Time
}
