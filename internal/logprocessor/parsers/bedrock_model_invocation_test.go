package parsers

import (
	"strings"
	"testing"
)

func TestBedrockModelInvocationParser_ParseLog(t *testing.T) {
	p := NewBedrockModelInvocationParser()
	raw := `{
  "accountId": "111111111111",
  "identity": {"arn": "arn:aws:sts::111111111111:assumed-role/role_details/suspicious.user"},
  "modelId": "anthropic.claude-3-haiku-20240307-v1:0",
  "operation": "Converse",
  "output": {
    "outputBodyJson": {
      "usage": {"inputTokens": 0, "outputTokens": 0, "totalTokens": 5000}
    }
  },
  "region": "us-west-2",
  "requestId": "bb98d9a8-bd9a-47ca-976b-f165ef1f8b67",
  "schemaType": "ModelInvocationLog",
  "schemaVersion": "1.0",
  "timestamp": "2025-05-15 14:17:22.000000000"
}`

	events, err := p.ParseLog(raw)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.EventSource != "aws.bedrock.modelinvocation" {
		t.Errorf("EventSource = %q", ev.EventSource)
	}
	if ev.EventName != "Converse" {
		t.Errorf("EventName = %q", ev.EventName)
	}
	if ev.EventID != "bb98d9a8-bd9a-47ca-976b-f165ef1f8b67" {
		t.Errorf("EventID = %q", ev.EventID)
	}
	if ev.RequestParameters == nil {
		t.Fatal("RequestParameters nil")
	}
	if ev.RequestParameters["operation"] != "Converse" {
		t.Errorf("requestParameters.operation mismatch")
	}
}

func TestBedrockModelInvocationParser_RejectsNonBedrock(t *testing.T) {
	p := NewBedrockModelInvocationParser()
	_, err := p.ParseLog(`{"eventID":"x","eventSource":"s3.amazonaws.com"}`)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "ModelInvocationLog") {
		t.Fatalf("unexpected err: %v", err)
	}
}
