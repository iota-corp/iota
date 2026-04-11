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
	if got, want := CanonicalLogType("bedrock"), "AWS.BedrockModelInvocation"; got != want {
		t.Errorf("CanonicalLogType(bedrock) = %q, want %q", got, want)
	}
	if got, want := CanonicalLogType("github"), "GitHub.Audit"; got != want {
		t.Errorf("CanonicalLogType(github) = %q, want %q", got, want)
	}
	if got, want := CanonicalLogType("github.webhook"), "GitHub.Webhook"; got != want {
		t.Errorf("CanonicalLogType(github.webhook) = %q, want %q", got, want)
	}
	if got, want := CanonicalLogType("gcp"), "GCP.AuditLog"; got != want {
		t.Errorf("CanonicalLogType(gcp) = %q, want %q", got, want)
	}
	if got, want := CanonicalLogType("gcp.httplb"), "GCP.HTTPLoadBalancer"; got != want {
		t.Errorf("CanonicalLogType(gcp.httplb) = %q, want %q", got, want)
	}
	if got, want := CanonicalLogType("eks"), "Amazon.EKS.Audit"; got != want {
		t.Errorf("CanonicalLogType(eks) = %q, want %q", got, want)
	}
	if got, want := CanonicalLogType("slack"), "Slack.AuditLogs"; got != want {
		t.Errorf("CanonicalLogType(slack) = %q, want %q", got, want)
	}
	if got, want := CanonicalLogType("cloudflare.firewall"), "Cloudflare.Firewall"; got != want {
		t.Errorf("CanonicalLogType(cloudflare.firewall) = %q, want %q", got, want)
	}
	if got, want := CanonicalLogType("cfhttp"), "Cloudflare.HttpRequest"; got != want {
		t.Errorf("CanonicalLogType(cfhttp) = %q, want %q", got, want)
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
