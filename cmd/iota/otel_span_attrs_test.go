package main

import (
	"testing"

	"github.com/bilals12/iota/internal/events"
)

func TestSqsQueueNameFromURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"https://sqs.us-east-1.amazonaws.com/969779760014/iota-lab-iota-cloudtrail-test", "iota-lab-iota-cloudtrail-test"},
		{"", ""},
		{"nslashes", "nslashes"},
	}
	for _, tc := range cases {
		if got := sqsQueueNameFromURL(tc.in); got != tc.want {
			t.Errorf("sqsQueueNameFromURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSpanAttrsSQSMessage(t *testing.T) {
	t.Parallel()
	meta := events.MessageMetadata{
		MessageID:               "msg-abc",
		ApproximateReceiveCount: 2,
	}
	attrs := spanAttrsSQSMessage("https://sqs.us-east-1.amazonaws.com/123/queue-one", meta)
	var sys, dest, msgID string
	var recv int
	for _, a := range attrs {
		switch string(a.Key) {
		case "messaging.system":
			sys = a.Value.AsString()
		case "messaging.destination.name":
			dest = a.Value.AsString()
		case "messaging.message.id":
			msgID = a.Value.AsString()
		case "iota.sqs.approximate_receive_count":
			recv = int(a.Value.AsInt64())
		}
	}
	if sys != "aws_sqs" || dest != "queue-one" || msgID != "msg-abc" || recv != 2 {
		t.Errorf("attrs mismatch: system=%q dest=%q msgID=%q recv=%d", sys, dest, msgID, recv)
	}
}
