// lakepath defines canonical S3 prefixes for the data lake so writers and query engines stay aligned
package lakepath

import (
	"fmt"
	"path"
	"strings"
	"time"
)

// CanonicalLogType: maps CLI + shorthand to log type strings in processing
func CanonicalLogType(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "cloudtrail":
		return "AWS.CloudTrail"
	case "bedrock", "bedrockmodelinvocation", "aws.bedrockmodelinvocation":
		return "AWS.BedrockModelInvocation"
	case "github", "github.audit", "githubaudit":
		return "GitHub.Audit"
	case "github.webhook", "githubwebhook":
		return "GitHub.Webhook"
	case "gcp", "gcp.audit", "gcpaudit", "gcpauditlog":
		return "GCP.AuditLog"
	case "gcp.httplb", "gcphttplb", "gcp_httploadbalancer", "httplb":
		return "GCP.HTTPLoadBalancer"
	case "eks", "eks.audit", "amazon.eks.audit", "eks_audit":
		return "Amazon.EKS.Audit"
	case "slack", "slack.audit", "slackauditlogs":
		return "Slack.AuditLogs"
	case "cloudflare", "cloudflare.firewall", "cffw":
		return "Cloudflare.Firewall"
	case "cloudflare.http", "cloudflare.httprequest", "cfhttp":
		return "Cloudflare.HttpRequest"
	default:
		return s
	}
}

// TableSlug: returns dir/table segment used under logs/
// applies CanonicalLogType first ("cloudtrail" and "AWS.CloudTrail" both become aws_cloudtrail)
func TableSlug(logType string) string {
	c := CanonicalLogType(logType)
	return strings.ToLower(strings.ReplaceAll(c, ".", "_"))
}

// HourPartitionPath: returns logs/<slug>/year=.../month=.../day=.../hour=...
func HourPartitionPath(logType string, hour time.Time) string {
	slug := TableSlug(logType)
	return fmt.Sprintf("logs/%s/year=%d/month=%02d/day=%02d/hour=%02d", slug, hour.Year(), int(hour.Month()), hour.Day(), hour.Hour())
}

// S3ObjectKey: returns full S3 obj key (no bucket) for a flushed object
func S3ObjectKey(logType string, hour time.Time, filename string) string {
	return path.Join(HourPartitionPath(logType, hour), filename)
}

// S3JSONGlob: returns glob pattern for gzip JSONL objects
func S3JSONGlob(bucket, logType string, hour time.Time) string {
	return fmt.Sprintf("s3://%s/%s/*.json.gz", bucket, HourPartitionPath(logType, hour))
}
