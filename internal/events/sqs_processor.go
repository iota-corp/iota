package events

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

type SQSProcessor struct {
	client      *sqs.Client
	queueURL    string
	handler     func(ctx context.Context, s3Bucket, s3Key string) error
	maxMessages int32
	waitTime    int32
}

type Config struct {
	QueueURL    string
	Handler     func(ctx context.Context, s3Bucket, s3Key string) error
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

func (p *SQSProcessor) processMessage(ctx context.Context, message types.Message) error {
	if message.Body == nil || *message.Body == "" {
		return fmt.Errorf("empty message body")
	}

	objects, err := ParseS3Notification(*message.Body)
	if err != nil {
		return err
	}

	for _, obj := range objects {
		if err := p.handler(ctx, obj.Bucket, obj.Key); err != nil {
			return fmt.Errorf("handle s3 object %s/%s: %w", obj.Bucket, obj.Key, err)
		}
	}

	return nil
}

func ParseS3Notification(body string) ([]S3Object, error) {
	var snsMessage struct {
		Type    string `json:"Type"`
		Message string `json:"Message"`
	}

	if err := json.Unmarshal([]byte(body), &snsMessage); err != nil {
		return nil, fmt.Errorf("unmarshal sns message: %w", err)
	}

	if snsMessage.Type != "Notification" {
		return nil, nil
	}

	var s3Notification struct {
		Records []struct {
			EventName string `json:"eventName"`
			S3        struct {
				Bucket struct {
					Name string `json:"name"`
				} `json:"bucket"`
				Object struct {
					Key string `json:"key"`
				} `json:"object"`
			} `json:"s3"`
		} `json:"Records"`
	}

	if err := json.Unmarshal([]byte(snsMessage.Message), &s3Notification); err != nil {
		return nil, fmt.Errorf("unmarshal s3 notification: %w", err)
	}

	var objects []S3Object
	for _, record := range s3Notification.Records {
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
