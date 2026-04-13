package events

import (
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

// MessageMetadata holds SQS system attributes for latency profiling (S3 → SNS → SQS → iota).
// Zero value means unknown / not requested.
type MessageMetadata struct {
	MessageID                        string
	SentTimestamp                    *time.Time // when the message was sent to SQS (epoch ms)
	ApproximateFirstReceiveTimestamp *time.Time // first receive (epoch ms)
	ApproximateReceiveCount          int
}

// ParseMessageSystemAttributes extracts profiling fields from ReceiveMessage output.
// Request SentTimestamp, ApproximateFirstReceiveTimestamp, ApproximateReceiveCount on ReceiveMessage.
func ParseMessageSystemAttributes(m types.Message) MessageMetadata {
	var meta MessageMetadata
	if m.MessageId != nil {
		meta.MessageID = *m.MessageId
	}
	if m.Attributes == nil {
		return meta
	}
	attr := m.Attributes
	if v := attr["SentTimestamp"]; v != "" {
		meta.SentTimestamp = parseSQSEpochMillis(v)
	}
	if v := attr["ApproximateFirstReceiveTimestamp"]; v != "" {
		meta.ApproximateFirstReceiveTimestamp = parseSQSEpochMillis(v)
	}
	if v := attr["ApproximateReceiveCount"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			meta.ApproximateReceiveCount = n
		}
	}
	return meta
}

func parseSQSEpochMillis(s string) *time.Time {
	ms, err := strconv.ParseInt(s, 10, 64)
	if err != nil || ms <= 0 {
		return nil
	}
	t := time.UnixMilli(ms).UTC()
	return &t
}
