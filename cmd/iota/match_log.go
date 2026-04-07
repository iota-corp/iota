package main

import (
	"log"

	"github.com/bilals12/iota/internal/engine"
)

// logDetectionMatches logs each rule match with identifiers (kubectl-friendly).
func logDetectionMatches(matches []engine.Match) {
	for _, m := range matches {
		eventName := ""
		eventSource := ""
		if m.Event != nil {
			eventName = m.Event.EventName
			eventSource = m.Event.EventSource
		}
		log.Printf(
			"detection: rule_id=%s severity=%s eventSource=%s eventName=%s title=%q",
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
