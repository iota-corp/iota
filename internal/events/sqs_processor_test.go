package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseS3Notification(t *testing.T) {
	t.Parallel()

	t.Run("ObjectCreated_Put_realistic_fixture", func(t *testing.T) {
		body := mustReadTestdata(t, "sns_envelope_object_created_put.json")
		objs, err := ParseS3Notification(body)
		if err != nil {
			t.Fatalf("ParseS3Notification: %v", err)
		}
		if len(objs) != 1 {
			t.Fatalf("len(objects) = %d, want 1", len(objs))
		}
		if got, want := objs[0].Bucket, "iota-cloudtrail-test-us-east-1"; got != want {
			t.Errorf("Bucket = %q, want %q", got, want)
		}
		wantKey := "AWSLogs/111122223333/CloudTrail/us-east-1/2026/04/02/111122223333_CloudTrail_us-east-1_20260402T1935Z_smoke.json.gz"
		if got := objs[0].Key; got != wantKey {
			t.Errorf("Key = %q, want %q", got, wantKey)
		}
	})

	t.Run("ObjectCreated_CompleteMultipartUpload", func(t *testing.T) {
		body := mustBuildSNSEnvelope(t, []map[string]any{
			{
				"eventName": "ObjectCreated:CompleteMultipartUpload",
				"s3": map[string]any{
					"bucket": map[string]any{"name": "b"},
					"object": map[string]any{"key": "k"},
				},
			},
		})
		objs, err := ParseS3Notification(body)
		if err != nil {
			t.Fatal(err)
		}
		if len(objs) != 1 || objs[0].Bucket != "b" || objs[0].Key != "k" {
			t.Fatalf("got %+v", objs)
		}
	})

	t.Run("ignores_ObjectCreated_Post", func(t *testing.T) {
		body := mustBuildSNSEnvelope(t, []map[string]any{
			{
				"eventName": "ObjectCreated:Post",
				"s3": map[string]any{
					"bucket": map[string]any{"name": "b"},
					"object": map[string]any{"key": "k"},
				},
			},
		})
		objs, err := ParseS3Notification(body)
		if err != nil {
			t.Fatal(err)
		}
		if len(objs) != 0 {
			t.Fatalf("expected no objects, got %+v", objs)
		}
	})

	t.Run("s3_TestEvent_no_records", func(t *testing.T) {
		body := mustReadTestdata(t, "sns_envelope_s3_test_event.json")
		objs, err := ParseS3Notification(body)
		if err != nil {
			t.Fatal(err)
		}
		if len(objs) != 0 {
			t.Fatalf("expected no S3 objects for s3:TestEvent, got %+v", objs)
		}
	})

	t.Run("non_notification_returns_empty", func(t *testing.T) {
		raw := map[string]any{"Type": "SubscriptionConfirmation", "Message": "{}"}
		b, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		objs, err := ParseS3Notification(string(b))
		if err != nil {
			t.Fatal(err)
		}
		if len(objs) != 0 {
			t.Fatalf("want empty, got %+v", objs)
		}
	})

	t.Run("invalid_outer_json", func(t *testing.T) {
		_, err := ParseS3Notification("{")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func mustBuildSNSEnvelope(t *testing.T, records []map[string]any) string {
	t.Helper()
	inner, err := json.Marshal(map[string]any{"Records": records})
	if err != nil {
		t.Fatal(err)
	}
	outer, err := json.Marshal(map[string]any{
		"Type":    "Notification",
		"Message": string(inner),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(outer)
}

func mustReadTestdata(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	path := filepath.Join(filepath.Dir(file), "testdata", "sqs", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
