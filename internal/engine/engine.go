package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/bilals12/iota/internal/metrics"
	"github.com/bilals12/iota/pkg/cloudtrail"
)

const maxFrameBytes = 512 << 20 // 512 MiB

type Engine struct {
	pythonPath string
	enginePath string
	rulesDir   string

	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

type Request struct {
	RulesDir string              `json:"rules_dir"`
	Events   []*cloudtrail.Event `json:"events"`
}

type Response struct {
	Matches         []Match         `json:"matches"`
	RuleEvaluations []RuleEvalCount `json:"rule_evaluations,omitempty"`
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

func oneshotMode() bool {
	return os.Getenv("IOTA_ENGINE_ONESHOT") == "1"
}

// Close releases the persistent Python worker subprocess. Safe to call multiple times.
func (e *Engine) Close() error {
	if oneshotMode() {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopWorkerLocked()
	return nil
}

func (e *Engine) stopWorkerLocked() {
	if e.cmd == nil {
		return
	}
	if e.stdin != nil {
		_ = e.stdin.Close()
	}
	if e.cmd.Process != nil {
		_ = e.cmd.Process.Kill()
	}
	_ = e.cmd.Wait()
	e.cmd = nil
	e.stdin = nil
	e.stdout = nil
}

func (e *Engine) startWorkerLocked() error {
	cmd := exec.Command(e.pythonPath, e.enginePath, "worker")
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start python worker: %w", err)
	}
	e.cmd = cmd
	e.stdin = stdin
	e.stdout = stdout
	return nil
}

func (e *Engine) ensureWorkerLocked() error {
	if e.cmd != nil && e.cmd.ProcessState == nil {
		return nil
	}
	e.stopWorkerLocked()
	return e.startWorkerLocked()
}

func (e *Engine) writeFrame(w io.Writer, data []byte) error {
	if len(data) > maxFrameBytes {
		return fmt.Errorf("request frame exceeds max size (%d)", maxFrameBytes)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func (e *Engine) readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if uint64(n) > uint64(maxFrameBytes) {
		return nil, fmt.Errorf("response frame exceeds max size (%d)", maxFrameBytes)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (e *Engine) analyzeOneshot(ctx context.Context, reqJSON []byte) ([]Match, error) {
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

func (e *Engine) Analyze(ctx context.Context, events []*cloudtrail.Event) ([]Match, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	req := Request{
		RulesDir: e.rulesDir,
		Events:   events,
	}

	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	if oneshotMode() {
		return e.analyzeOneshot(ctx, reqJSON)
	}

	type result struct {
		matches []Match
		err     error
	}
	ch := make(chan result, 1)

	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.ensureWorkerLocked(); err != nil {
		return nil, err
	}

	go func() {
		var resp Response
		if err := e.writeFrame(e.stdin, reqJSON); err != nil {
			ch <- result{err: fmt.Errorf("write request: %w", err)}
			return
		}
		body, err := e.readFrame(e.stdout)
		if err != nil {
			ch <- result{err: fmt.Errorf("read response: %w", err)}
			return
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			ch <- result{err: fmt.Errorf("unmarshal response: %w", err)}
			return
		}
		for _, ev := range resp.RuleEvaluations {
			metrics.RecordRuleEvaluatedCount(ev.RuleID, "match", float64(ev.Match))
			metrics.RecordRuleEvaluatedCount(ev.RuleID, "no_match", float64(ev.NoMatch))
		}
		ch <- result{matches: resp.Matches}
	}()

	select {
	case <-ctx.Done():
		e.stopWorkerLocked()
		<-ch
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			e.stopWorkerLocked()
			return nil, r.err
		}
		return r.matches, nil
	}
}
