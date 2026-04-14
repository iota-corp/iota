package events

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/bilals12/iota/internal/metrics"
)

type SQSProcessor struct {
	client      *sqs.Client
	queueURL    string
	handler     func(ctx context.Context, s3Bucket, s3Key string, sqsMeta MessageMetadata) error
	maxMessages int32
	waitTime    int32
}

type Config struct {
	QueueURL    string
	Handler     func(ctx context.Context, s3Bucket, s3Key string, sqsMeta MessageMetadata) error
	MaxMessages int32
	WaitTime    int32
}

func NewSQSProcessor(client *sqs.Client, cfg Config) *SQSProcessor {
	maxMessages := cfg.MaxMessages
	if maxMessages == 0 {
		maxMessages = 10
	}
	waitTime := cfg.WaitTime
	if waitTime == 0 {
		waitTime = 20
	}

	return &SQSProcessor{
		client:      client,
		queueURL:    cfg.QueueURL,
		handler:     cfg.Handler,
		maxMessages: maxMessages,
		waitTime:    waitTime,
	}
}

func (p *SQSProcessor) Process(ctx context.Context) error {
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
			MessageSystemAttributeNames: []types.MessageSystemAttributeName{
				types.MessageSystemAttributeNameSentTimestamp,
				types.MessageSystemAttributeNameApproximateFirstReceiveTimestamp,
				types.MessageSystemAttributeNameApproximateReceiveCount,
			},
		})
		if err != nil {
			return fmt.Errorf("receive message: %w", err)
		}

		for _, message := range result.Messages {
			if err := p.processMessage(ctx, message); err != nil {
				continue
			}

			if _, err := p.client.DeleteMessage(ctx, &sqs.DeleteMessageInput{
				QueueUrl:      aws.String(p.queueURL),
				ReceiptHandle: message.ReceiptHandle,
			}); err != nil {
				return fmt.Errorf("delete message: %w", err)
			}
		}
	}
}

func (p *SQSProcessor) processMessage(ctx context.Context, message types.Message) (err error) {
	defer func() {
		if err == nil {
			metrics.RecordSQSMessageProcessed("success")
		} else {
			metrics.RecordSQSMessageProcessed("failure")
		}
	}()

	if message.Body == nil || *message.Body == "" {
		return fmt.Errorf("empty message body")
	}

	objects, err := ParseS3Notification(*message.Body)
	if err != nil {
		return err
	}

	meta := ParseMessageSystemAttributes(message)
	for _, obj := range objects {
		if err := p.handler(ctx, obj.Bucket, obj.Key, meta); err != nil {
			return fmt.Errorf("handle s3 object %s/%s: %w", obj.Bucket, obj.Key, err)
		}
	}

	return nil
}

// ParseS3Notification extracts S3 object refs from an SQS message body. AWS uses two shapes:
//   - S3 → SQS directly: top-level JSON with a "Records" array (S3 event notification).
//   - S3 → SNS → SQS: SNS envelope with Type "Notification" and string "Message" containing the same Records JSON.
//
// Previously only the SNS path worked; direct delivery returned nil objects and the message was deleted without processing.
func ParseS3Notification(body string) ([]S3Object, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &top); err != nil {
		return nil, fmt.Errorf("unmarshal notification json: %w", err)
	}

	if recRaw, ok := top["Records"]; ok && string(recRaw) != "null" {
		return objectsFromS3RecordsJSON(recRaw)
	}

	var snsOuter struct {
		Type    string `json:"Type"`
		Message string `json:"Message"`
	}
	if err := json.Unmarshal([]byte(body), &snsOuter); err != nil {
		return nil, fmt.Errorf("unmarshal sns envelope: %w", err)
	}
	if snsOuter.Type != "Notification" || snsOuter.Message == "" {
		return nil, nil
	}

	var inner map[string]json.RawMessage
	if err := json.Unmarshal([]byte(snsOuter.Message), &inner); err != nil {
		return nil, fmt.Errorf("unmarshal s3 notification: %w", err)
	}
	recRaw, ok := inner["Records"]
	if !ok || string(recRaw) == "null" {
		return nil, nil
	}
	return objectsFromS3RecordsJSON(recRaw)
}

func objectsFromS3RecordsJSON(recordsJSON json.RawMessage) ([]S3Object, error) {
	var records []struct {
		EventName string `json:"eventName"`
		S3        struct {
			Bucket struct {
				Name string `json:"name"`
			} `json:"bucket"`
			Object struct {
				Key string `json:"key"`
			} `json:"object"`
		} `json:"s3"`
	}
	if err := json.Unmarshal(recordsJSON, &records); err != nil {
		return nil, fmt.Errorf("unmarshal records: %w", err)
	}

	var objects []S3Object
	for _, record := range records {
		if record.EventName != "ObjectCreated:Put" && record.EventName != "ObjectCreated:CompleteMultipartUpload" {
			continue
		}

		objects = append(objects, S3Object{
			Bucket: record.S3.Bucket.Name,
			Key:    record.S3.Object.Key,
		})
	}

	return objects, nil
}

type S3Object struct {
	Bucket string
	Key    string
}
