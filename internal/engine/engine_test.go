package engine_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bilals12/iota/internal/engine"
	"github.com/bilals12/iota/pkg/cloudtrail"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestEngineWorkerAnalyze(t *testing.T) {
	t.Setenv("IOTA_ENGINE_ONESHOT", "")
	py := os.Getenv("PYTHON")
	if py == "" {
		py = "python3"
	}
	if _, err := exec.LookPath(py); err != nil {
		t.Skip("python not in PATH:", err)
	}
	root := repoRoot(t)
	enginePy := filepath.Join(root, "engines", "iota", "engine.py")
	rulesDir := filepath.Join(root, "testdata", "rules")
	if _, err := os.Stat(enginePy); err != nil {
		t.Skip("engine.py not found:", enginePy)
	}

	eng := engine.New(py, enginePy, rulesDir)
	defer func() { _ = eng.Close() }()

	ev := &cloudtrail.Event{
		EventTime:       time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC),
		EventSource:     "signin.amazonaws.com",
		EventName:       "ConsoleLogin",
		UserIdentity:    cloudtrail.UserIdentity{Type: "Root"},
		SourceIPAddress: "1.2.3.4",
		EventID:         "evt-test-1",
	}
	ctx := context.Background()
	matches, err := eng.Analyze(ctx, []*cloudtrail.Event{ev})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches: got %d want 1", len(matches))
	}
	if matches[0].RuleID != "root_login" {
		t.Fatalf("rule_id: %s", matches[0].RuleID)
	}

	matches2, err := eng.Analyze(ctx, []*cloudtrail.Event{})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches2) != 0 {
		t.Fatalf("empty batch: got %d matches", len(matches2))
	}
}

func TestEngineOneshotAnalyze(t *testing.T) {
	t.Setenv("IOTA_ENGINE_ONESHOT", "1")
	py := os.Getenv("PYTHON")
	if py == "" {
		py = "python3"
	}
	if _, err := exec.LookPath(py); err != nil {
		t.Skip("python not in PATH:", err)
	}
	root := repoRoot(t)
	enginePy := filepath.Join(root, "engines", "iota", "engine.py")
	rulesDir := filepath.Join(root, "testdata", "rules")
	if _, err := os.Stat(enginePy); err != nil {
		t.Skip("engine.py not found:", enginePy)
	}

	eng := engine.New(py, enginePy, rulesDir)
	defer func() { _ = eng.Close() }()

	ev := &cloudtrail.Event{
		EventTime:       time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC),
		EventSource:     "signin.amazonaws.com",
		EventName:       "ConsoleLogin",
		UserIdentity:    cloudtrail.UserIdentity{Type: "Root"},
		SourceIPAddress: "1.2.3.4",
		EventID:         "evt-test-oneshot",
	}
	matches, err := eng.Analyze(context.Background(), []*cloudtrail.Event{ev})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].RuleID != "root_login" {
		t.Fatalf("matches: %+v", matches)
	}
}
