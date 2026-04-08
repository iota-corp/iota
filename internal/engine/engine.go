package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/bilals12/iota/internal/metrics"
	"github.com/bilals12/iota/pkg/cloudtrail"
)

type Engine struct {
	pythonPath string
	enginePath string
	rulesDir   string
}

type Request struct {
	RulesDir string              `json:"rules_dir"`
	Events   []*cloudtrail.Event `json:"events"`
}

type Response struct {
	Matches           []Match           `json:"matches"`
	RuleEvaluations   []RuleEvalCount   `json:"rule_evaluations,omitempty"`
}

// RuleEvalCount is aggregated per Analyze() batch from the Python engine (match vs no_match per rule_id).
type RuleEvalCount struct {
	RuleID  string `json:"rule_id"`
	Match   int    `json:"match"`
	NoMatch int    `json:"no_match"`
}

type Match struct {
	RuleID   string            `json:"rule_id"`
	Title    string            `json:"title"`
	Severity string            `json:"severity"`
	Dedup    string            `json:"dedup"`
	Event    *cloudtrail.Event `json:"event"`
}

func New(pythonPath, enginePath, rulesDir string) *Engine {
	return &Engine{
		pythonPath: pythonPath,
		enginePath: enginePath,
		rulesDir:   rulesDir,
	}
}

func (e *Engine) Analyze(ctx context.Context, events []*cloudtrail.Event) ([]Match, error) {
	req := Request{
		RulesDir: e.rulesDir,
		Events:   events,
	}

	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	cmd := exec.CommandContext(ctx, e.pythonPath, e.enginePath)
	cmd.Stdin = bytes.NewReader(reqJSON)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("execute engine: %w, stderr: %s", err, stderr.String())
	}

	var resp Response
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	for _, ev := range resp.RuleEvaluations {
		metrics.RecordRuleEvaluatedCount(ev.RuleID, "match", float64(ev.Match))
		metrics.RecordRuleEvaluatedCount(ev.RuleID, "no_match", float64(ev.NoMatch))
	}

	return resp.Matches, nil
}
