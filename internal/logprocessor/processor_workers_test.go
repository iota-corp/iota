package logprocessor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func evJSON(id string) json.RawMessage {
	return json.RawMessage(`{"eventVersion":"1.08","userIdentity":{"type":"IAMUser"},"eventTime":"2024-01-15T12:00:00Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeInstances","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.1","userAgent":"aws-cli","requestID":"req-` + id + `","eventID":"ev-` + id + `","eventType":"AwsApiCall","recipientAccountId":"123456789012"}`)
}

func TestProcessCloudTrailRecordsParallel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := New()
	p.SetClassifyWorkers(4)

	rec := []json.RawMessage{
		evJSON("1"), evJSON("2"), evJSON("3"), evJSON("4"),
		evJSON("5"), evJSON("6"), evJSON("7"), evJSON("8"),
	}

	events := make(chan *ProcessedEvent, 20)
	errs := make(chan error, 1)
	go func() {
		errs <- p.processCloudTrailRecords(ctx, rec, events)
		close(events)
	}()

	var got int
	for range events {
		got++
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if got != 8 {
		t.Fatalf("events: got %d want 8", got)
	}
}

func TestProcessJSONArrayStreamParallel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := New()
	p.SetClassifyWorkers(2)

	payload := "[" + string(evJSON("a")) + "," + string(evJSON("b")) + "," + string(evJSON("c")) + "," + string(evJSON("d")) + "]"

	events := make(chan *ProcessedEvent, 10)
	errs := make(chan error, 1)
	go func() {
		errs <- p.processJSONArrayStream(ctx, strings.NewReader(payload), events)
		close(events)
	}()

	var got int
	for range events {
		got++
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if got != 4 {
		t.Fatalf("events: got %d want 4", got)
	}
}
