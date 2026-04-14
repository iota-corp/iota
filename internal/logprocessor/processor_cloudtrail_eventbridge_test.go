package logprocessor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProcessEvent_EventBridgeCloudTrailDetail(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := New()

	detail := mustReadLogprocessorFixture(t, "eventbridge/cloudtrail_detail_create_user.json")
	out, err := p.ProcessEvent(ctx, detail, "AWS.CloudTrail")
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(out))
	}
	if out[0].LogType != "AWS.CloudTrail" {
		t.Errorf("LogType = %q, want AWS.CloudTrail", out[0].LogType)
	}
	if out[0].Event.EventName != "CreateUser" {
		t.Errorf("EventName = %q, want CreateUser", out[0].Event.EventName)
	}
	if out[0].Event.EventID != "a1b2c3d4-1111-2222-3333-444455556666" {
		t.Errorf("EventID = %q", out[0].Event.EventID)
	}
}

func TestProcessEvent_CloudTrailRecordsWrapperWithHint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := New()

	body := mustReadLogprocessorFixture(t, "eventbridge/cloudtrail_records_wrapper.json")
	out, err := p.ProcessEvent(ctx, body, "AWS.CloudTrail")
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(out))
	}
	if out[0].Event.EventName != "DeleteUser" {
		t.Errorf("EventName = %q, want DeleteUser", out[0].Event.EventName)
	}
}

func mustReadLogprocessorFixture(t *testing.T, rel string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	path := filepath.Join(filepath.Dir(file), "testdata", rel)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}
