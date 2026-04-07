package alertforwarder

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bilals12/iota/internal/deduplication"
	"github.com/bilals12/iota/internal/engine"
	"github.com/bilals12/iota/internal/metrics"
	"github.com/bilals12/iota/pkg/cloudtrail"
)

type Forwarder struct {
	deduplicator *deduplication.Deduplicator
	outputs      []Output
}

type Output interface {
	SendAlert(ctx context.Context, alert *Alert) error
}

type Alert struct {
	AlertID           string
	RuleID            string
	DedupKey          string
	Title             string
	Severity          string
	Event             *cloudtrail.Event
	AlertContext      map[string]interface{}
	AlertCreationTime string
	AlertUpdateTime   string
}

func New(deduplicator *deduplication.Deduplicator, outputs []Output) *Forwarder {
	return &Forwarder{
		deduplicator: deduplicator,
		outputs:      outputs,
	}
}

func (f *Forwarder) ProcessMatch(ctx context.Context, match engine.Match, dedupPeriodMinutes int) error {
	dedup := match.Dedup
	if dedup == "" {
		dedup = match.Title
	}

	alertInfo, err := f.deduplicator.UpdateAlertInfo(ctx, match.RuleID, dedup, match.Title, match.Severity, dedupPeriodMinutes)
	if err != nil {
		return fmt.Errorf("update alert info: %w", err)
	}

	alertContext := make(map[string]interface{})
	if match.Event != nil {
		alertContext["eventName"] = match.Event.EventName
		alertContext["eventSource"] = match.Event.EventSource
		alertContext["sourceIPAddress"] = match.Event.SourceIPAddress
		alertContext["recipientAccountId"] = match.Event.RecipientAccountID
		alertContext["awsRegion"] = match.Event.AWSRegion
	}

	alert := &Alert{
		AlertID:           alertInfo.AlertID,
		RuleID:            match.RuleID,
		DedupKey:          alertInfo.DedupKey,
		Title:             alertInfo.Title,
		Severity:          alertInfo.Severity,
		Event:             match.Event,
		AlertContext:      alertContext,
		AlertCreationTime: alertInfo.AlertCreationTime.Format("2006-01-02T15:04:05Z"),
		AlertUpdateTime:   alertInfo.AlertUpdateTime.Format("2006-01-02T15:04:05Z"),
	}

	metrics.RecordAlertGenerated(alert.Severity, alert.RuleID)

	for _, output := range f.outputs {
		if err := output.SendAlert(ctx, alert); err != nil {
			return fmt.Errorf("send alert: %w", err)
		}
	}

	return nil
}

func (a *Alert) ToJSON() ([]byte, error) {
	return json.Marshal(a)
}
