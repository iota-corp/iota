package main

import (
	"context"
	"fmt"
	"log"

	"github.com/bilals12/iota/internal/engine"
	"github.com/bilals12/iota/internal/telemetry"
)

// logDetectionMatches logs each rule match with identifiers (kubectl-friendly).
// When OpenTelemetry has a valid span in ctx (e.g. process_eventbridge_event), includes
// trace_id and span_id so log backends can correlate with traces; detection_ref is always
// rule_id + event id for uniqueness within the pipeline.
func logDetectionMatches(ctx context.Context, matches []engine.Match) {
	traceID, spanID := telemetry.TraceIDsForLog(ctx)
	for _, m := range matches {
		eventName := ""
		eventSource := ""
		eventID := ""
		if m.Event != nil {
			eventName = m.Event.EventName
			eventSource = m.Event.EventSource
			eventID = m.Event.EventID
		}
		if eventID == "" {
			eventID = "unknown"
		}
		detectionRef := fmt.Sprintf("%s:%s", m.RuleID, eventID)

		if traceID != "" {
			log.Printf(
				"detection: trace_id=%s span_id=%s detection_ref=%s rule_id=%s severity=%s eventSource=%s eventName=%s title=%q",
				traceID,
				spanID,
				detectionRef,
				m.RuleID,
				m.Severity,
				eventSource,
				eventName,
				truncateRunes(m.Title, 200),
			)
			continue
		}
		log.Printf(
			"detection: detection_ref=%s rule_id=%s severity=%s eventSource=%s eventName=%s title=%q",
			detectionRef,
			m.RuleID,
			m.Severity,
			eventSource,
			eventName,
			truncateRunes(m.Title, 200),
		)
	}
}

func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
