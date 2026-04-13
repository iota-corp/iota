package events

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func TestParseMessageSystemAttributes(t *testing.T) {
	t.Parallel()

	mid := "msg-123"
	sentMs := int64(1_700_000_000_123)
	firstMs := int64(1_700_000_010_456)

	m := types.Message{
		MessageId: aws.String(mid),
		Attributes: map[string]string{
			"SentTimestamp":                    "1700000000123",
			"ApproximateFirstReceiveTimestamp": "1700000010456",
			"ApproximateReceiveCount":          "2",
		},
	}

	got := ParseMessageSystemAttributes(m)
	if got.MessageID != mid {
		t.Errorf("MessageID = %q, want %q", got.MessageID, mid)
	}
	if got.SentTimestamp == nil || got.SentTimestamp.UnixMilli() != sentMs {
		t.Errorf("SentTimestamp = %v, want %v", got.SentTimestamp, time.UnixMilli(sentMs).UTC())
	}
	if got.ApproximateFirstReceiveTimestamp == nil || got.ApproximateFirstReceiveTimestamp.UnixMilli() != firstMs {
		t.Errorf("ApproximateFirstReceiveTimestamp = %v", got.ApproximateFirstReceiveTimestamp)
	}
	if got.ApproximateReceiveCount != 2 {
		t.Errorf("ApproximateReceiveCount = %d, want 2", got.ApproximateReceiveCount)
	}
}

func TestParseMessageSystemAttributes_empty(t *testing.T) {
	t.Parallel()
	got := ParseMessageSystemAttributes(types.Message{})
	if got.MessageID != "" || got.SentTimestamp != nil || got.ApproximateReceiveCount != 0 {
		t.Fatalf("expected zero meta, got %+v", got)
	}
}
