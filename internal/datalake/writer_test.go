package datalake

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGetTableName(t *testing.T) {
	t.Parallel()
	if got, want := getTableName("AWS.CloudTrail"), "aws_cloudtrail"; got != want {
		t.Errorf("getTableName(AWS.CloudTrail) = %q, want %q", got, want)
	}
	if got, want := getTableName("Okta.SystemLog"), "okta_systemlog"; got != want {
		t.Errorf("getTableName(Okta.SystemLog) = %q, want %q", got, want)
	}
}

func TestGenerateS3Key_PartitionLayout(t *testing.T) {
	t.Parallel()
	w := &Writer{}
	buf := &EventBuffer{
		logType: "AWS.CloudTrail",
		hour:    time.Date(2024, 3, 15, 14, 30, 45, 0, time.UTC),
	}
	key := w.generateS3Key(buf)

	// Hive-style partitions for Athena/Glue and DuckDB pruning.
	wantPrefix := "logs/aws_cloudtrail/year=2024/month=03/day=15/hour=14"
	if !strings.HasPrefix(key, wantPrefix) {
		t.Fatalf("key %q should start with %q", key, wantPrefix)
	}
	if !strings.Contains(key, ".json.gz") {
		t.Fatalf("key should be gzip jsonl: %q", key)
	}
	// S3 keys use forward slashes; filepath.Join on Unix preserves that.
	if strings.Contains(filepath.ToSlash(key), "//") {
		t.Fatalf("key should not contain empty segments: %q", key)
	}
}
