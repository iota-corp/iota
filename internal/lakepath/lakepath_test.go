package lakepath

import (
	"strings"
	"testing"
	"time"
)

func TestCanonicalLogType(t *testing.T) {
	t.Parallel()
	if got, want := CanonicalLogType("cloudtrail"), "AWS.CloudTrail"; got != want {
		t.Errorf("CanonicalLogType(cloudtrail) = %q, want %q", got, want)
	}
	if got, want := CanonicalLogType("AWS.CloudTrail"), "AWS.CloudTrail"; got != want {
		t.Errorf("CanonicalLogType(AWS.CloudTrail) = %q, want %q", got, want)
	}
}

func TestTableSlug(t *testing.T) {
	t.Parallel()
	if got, want := TableSlug("AWS.CloudTrail"), "aws_cloudtrail"; got != want {
		t.Errorf("TableSlug = %q, want %q", got, want)
	}
	if got, want := TableSlug("cloudtrail"), "aws_cloudtrail"; got != want {
		t.Errorf("TableSlug(cloudtrail) = %q, want %q", got, want)
	}
	if got, want := TableSlug("Okta.SystemLog"), "okta_systemlog"; got != want {
		t.Errorf("TableSlug(Okta.SystemLog) = %q, want %q", got, want)
	}
}

func TestHourPartitionPath(t *testing.T) {
	t.Parallel()
	h := time.Date(2024, 3, 15, 14, 0, 0, 0, time.UTC)
	got := HourPartitionPath("AWS.CloudTrail", h)
	want := "logs/aws_cloudtrail/year=2024/month=03/day=15/hour=14"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestS3JSONGlob(t *testing.T) {
	t.Parallel()
	h := time.Date(2024, 3, 15, 14, 0, 0, 0, time.UTC)
	got := S3JSONGlob("my-bucket", "cloudtrail", h)
	wantPrefix := "s3://my-bucket/logs/aws_cloudtrail/year=2024/month=03/day=15/hour=14/"
	if !strings.HasPrefix(got, wantPrefix) || !strings.HasSuffix(got, "*.json.gz") {
		t.Fatalf("S3JSONGlob = %q", got)
	}
}

func TestS3ObjectKey(t *testing.T) {
	t.Parallel()
	h := time.Date(2024, 3, 15, 14, 0, 0, 0, time.UTC)
	key := S3ObjectKey("AWS.CloudTrail", h, "20240315T140000Z-1.json.gz")
	want := "logs/aws_cloudtrail/year=2024/month=03/day=15/hour=14/20240315T140000Z-1.json.gz"
	if key != want {
		t.Errorf("S3ObjectKey = %q, want %q", key, want)
	}
}
