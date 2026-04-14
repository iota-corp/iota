package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDetectEventSource_CloudTrail(t *testing.T) {
	t.Parallel()

	t.Run("fixture_envelope_AWS_API_Call_via_CloudTrail", func(t *testing.T) {
		var env EventBridgeEnvelope
		if err := json.Unmarshal([]byte(mustReadEventBridgeFixture(t, "envelope_cloudtrail_api_call.json")), &env); err != nil {
			t.Fatal(err)
		}
		if got := DetectEventSource(&env); got != "AWS.CloudTrail" {
			t.Fatalf("DetectEventSource = %q, want AWS.CloudTrail", got)
		}
	})

	tests := []struct {
		name   string
		source string
		detail string
		want   string
	}{
		{
			name:   "source_aws_cloudtrail_detail_type_insight",
			source: "aws.cloudtrail",
			detail: "AWS Insight via CloudTrail",
			want:   "AWS.CloudTrail",
		},
		{
			name:   "source_aws_cloudtrail_console_signin",
			source: "aws.cloudtrail",
			detail: "AWS Console Sign In via CloudTrail",
			want:   "AWS.CloudTrail",
		},
		{
			name:   "via_CloudTrail_prefix_aws_service",
			source: "aws.cloudtrail",
			detail: "AWS Service Event via CloudTrail",
			want:   "AWS.CloudTrail",
		},
		{
			name:   "fallback_detail_type_not_aws_source",
			source: "aws.s3",
			detail: "Object Created",
			want:   "",
		},
		{
			name:   "okta_unchanged",
			source: "aws.partner/okta.com",
			detail: "Okta Log Event",
			want:   "Okta.SystemLog",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := &EventBridgeEnvelope{
				Source:     tt.source,
				DetailType: tt.detail,
			}
			if got := DetectEventSource(env); got != tt.want {
				t.Fatalf("DetectEventSource() = %q, want %q", got, tt.want)
			}
		})
	}
}

func mustReadEventBridgeFixture(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	path := filepath.Join(filepath.Dir(file), "testdata", "eventbridge", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
