package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bilals12/iota/pkg/cloudtrail"
)

type BedrockModelInvocationParser struct{}

func NewBedrockModelInvocationParser() *BedrockModelInvocationParser {
	return &BedrockModelInvocationParser{}
}

func (p *BedrockModelInvocationParser) LogType() string {
	return "AWS.BedrockModelInvocation"
}

func (p *BedrockModelInvocationParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(log), &raw); err != nil {
		return nil, fmt.Errorf("bedrock model invocation: %w", err)
	}

	schemaType, _ := raw["schemaType"].(string)
	if schemaType != "ModelInvocationLog" {
		return nil, fmt.Errorf("bedrock model invocation: not ModelInvocationLog")
	}

	requestID, _ := raw["requestId"].(string)
	if requestID == "" {
		return nil, fmt.Errorf("bedrock model invocation: missing requestId")
	}

	operation, _ := raw["operation"].(string)
	if operation == "" {
		return nil, fmt.Errorf("bedrock model invocation: missing operation")
	}

	accountID, _ := raw["accountId"].(string)
	region, _ := raw["region"].(string)

	eventTime, err := parseBedrockTimestamp(raw["timestamp"])
	if err != nil {
		return nil, fmt.Errorf("bedrock model invocation: timestamp: %w", err)
	}

	ct := &cloudtrail.Event{
		EventVersion:       "1.0",
		EventSource:        "aws.bedrock.modelinvocation",
		EventName:          operation,
		EventTime:          eventTime,
		AWSRegion:          region,
		RequestID:          requestID,
		EventID:            requestID,
		EventType:          "AWS.BedrockModelInvocation",
		RecipientAccountID: accountID,
		RequestParameters:  raw,
	}

	if idmap, ok := raw["identity"].(map[string]interface{}); ok {
		if arn, ok := idmap["arn"].(string); ok && arn != "" {
			parts := strings.Split(arn, ":")
			acct := accountID
			if len(parts) >= 5 {
				acct = parts[4]
			}
			ct.UserIdentity = cloudtrail.UserIdentity{
				Type:        "BedrockCaller",
				ARN:         arn,
				AccountID:   acct,
				PrincipalID: arn,
			}
		}
	}

	return []*cloudtrail.Event{ct}, nil
}

func parseBedrockTimestamp(v interface{}) (time.Time, error) {
	if v == nil {
		return time.Time{}, fmt.Errorf("missing timestamp")
	}
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return time.Time{}, fmt.Errorf("empty timestamp")
		}
		layouts := []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05.000000000",
			"2006-01-02T15:04:05",
			"2006-01-02 15:04:05.000000000",
			"2006-01-02 15:04:05",
		}
		var lastErr error
		for _, layout := range layouts {
			parsed, err := time.Parse(layout, s)
			if err == nil {
				return parsed.UTC(), nil
			}
			lastErr = err
		}
		return time.Time{}, fmt.Errorf("parse %q: %w", s, lastErr)
	case float64:
		sec := int64(t)
		nsec := int64((t - float64(sec)) * 1e9)
		return time.Unix(sec, nsec).UTC(), nil
	default:
		return time.Time{}, fmt.Errorf("unsupported timestamp type")
	}
}

var _ ParserInterface = (*BedrockModelInvocationParser)(nil)
