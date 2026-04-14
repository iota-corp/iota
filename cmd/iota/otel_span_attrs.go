package main

import (
	"strings"

	"github.com/bilals12/iota/internal/events"
	"go.opentelemetry.io/otel/attribute"
)

// sqsQueueNameFromURL returns the queue name from a standard AWS SQS HTTPS URL (last path segment).
func sqsQueueNameFromURL(queueURL string) string {
	queueURL = strings.TrimSpace(queueURL)
	if queueURL == "" {
		return ""
	}
	if i := strings.LastIndex(queueURL, "/"); i >= 0 && i < len(queueURL)-1 {
		return queueURL[i+1:]
	}
	return queueURL
}

// spanAttrsSQSMessage adds OpenTelemetry messaging attributes for the SQS message that delivered
// work to iota (SigNoz APM metrics group by service + operation; these add filter dimensions).
func spanAttrsSQSMessage(queueURL string, meta events.MessageMetadata) []attribute.KeyValue {
	var attrs []attribute.KeyValue
	attrs = append(attrs, attribute.String("messaging.system", "aws_sqs"))
	if name := sqsQueueNameFromURL(queueURL); name != "" {
		attrs = append(attrs, attribute.String("messaging.destination.name", name))
	}
	if meta.MessageID != "" {
		attrs = append(attrs, attribute.String("messaging.message.id", meta.MessageID))
	}
	if meta.ApproximateReceiveCount > 0 {
		attrs = append(attrs, attribute.Int("iota.sqs.approximate_receive_count", meta.ApproximateReceiveCount))
	}
	return attrs
}
