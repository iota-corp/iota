package deduplication

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/bilals12/iota/internal/metrics"
	"github.com/bilals12/iota/internal/sqliteutil"
	_ "github.com/mattn/go-sqlite3"
)

var DedupNamespace = uuid.MustParse("a3bb189e-8bf9-3888-9912-ace4e6543002")

type Deduplicator struct {
	mu sync.RWMutex
	db *sql.DB
}

type AlertInfo struct {
	AlertID           string
	RuleID            string
	DedupKey          string
	AlertCreationTime time.Time
	AlertUpdateTime   time.Time
	ResolvedAt        *time.Time
	Title             string
	Severity          string
}

func New(stateFile string) (*Deduplicator, error) {
	db, err := sql.Open("sqlite3", sqliteutil.FileURI(stateFile))
	if err != nil {
		return nil, fmt.Errorf("open dedup db: %w", err)
	}

	if err := initDedupDB(db); err != nil {
		_ = db.Close()
		metrics.RecordStateDBOperation("dedup_init_schema", "error")
		return nil, fmt.Errorf("init dedup db: %w", err)
	}
	metrics.RecordStateDBOperation("dedup_init_schema", "success")

	sqliteutil.ConfigureConnectionPool(db)

	return &Deduplicator{db: db}, nil
}

func initDedupDB(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS alerts (
			alert_id TEXT PRIMARY KEY,
			rule_id TEXT NOT NULL,
			dedup_key TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			resolved_at TIMESTAMP,
			title TEXT,
			severity TEXT
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_unique_open
			ON alerts(rule_id, dedup_key, resolved_at);
		CREATE INDEX IF NOT EXISTS idx_alerts_rule_dedup
			ON alerts(rule_id, dedup_key) WHERE resolved_at IS NULL;
		CREATE INDEX IF NOT EXISTS idx_alerts_open_by_updated
			ON alerts(updated_at) WHERE resolved_at IS NULL;
	`)
	return err
}

func (d *Deduplicator) UpdateAlertInfo(ctx context.Context, ruleID, dedup, title, severity string, dedupPeriodMinutes int) (info *AlertInfo, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	start := time.Now()
	defer func() {
		st := "success"
		if err != nil {
			st = "error"
		}
		metrics.ObserveStateDBOperation("update_alert_info", time.Since(start))
		metrics.RecordStateDBOperation("update_alert_info", st)
	}()

	dedupKey := GenerateDedupKey(ruleID, dedup)
	now := time.Now()
	dedupThreshold := now.Add(-time.Duration(dedupPeriodMinutes) * time.Minute)

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var existing AlertInfo
	err = tx.QueryRowContext(ctx, `
		SELECT alert_id, rule_id, dedup_key, created_at, updated_at, title, severity
		FROM alerts
		WHERE rule_id = ? AND dedup_key = ? AND resolved_at IS NULL
	`, ruleID, dedupKey).Scan(
		&existing.AlertID, &existing.RuleID, &existing.DedupKey,
		&existing.AlertCreationTime, &existing.AlertUpdateTime,
		&existing.Title, &existing.Severity,
	)

	if err == sql.ErrNoRows {
		alertID := GenerateAlertID(ruleID, dedupKey, now)
		_, err = tx.ExecContext(ctx, `
			INSERT INTO alerts (alert_id, rule_id, dedup_key, created_at, updated_at, title, severity)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, alertID, ruleID, dedupKey, now, now, title, severity)
		if err != nil {
			return nil, fmt.Errorf("insert alert: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit: %w", err)
		}

		info = &AlertInfo{
			AlertID:           alertID,
			RuleID:            ruleID,
			DedupKey:          dedupKey,
			AlertCreationTime: now,
			AlertUpdateTime:   now,
			Title:             title,
			Severity:          severity,
		}
		return info, nil
	}

	if err != nil {
		return nil, fmt.Errorf("query alert: %w", err)
	}

	if existing.AlertCreationTime.Before(dedupThreshold) {
		_, err = tx.ExecContext(ctx, `
			UPDATE alerts SET resolved_at = ? WHERE alert_id = ?
		`, now, existing.AlertID)
		if err != nil {
			return nil, fmt.Errorf("resolve alert: %w", err)
		}

		alertID := GenerateAlertID(ruleID, dedupKey, now)
		_, err = tx.ExecContext(ctx, `
			INSERT INTO alerts (alert_id, rule_id, dedup_key, created_at, updated_at, title, severity)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, alertID, ruleID, dedupKey, now, now, title, severity)
		if err != nil {
			return nil, fmt.Errorf("insert new alert: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit: %w", err)
		}

		info = &AlertInfo{
			AlertID:           alertID,
			RuleID:            ruleID,
			DedupKey:          dedupKey,
			AlertCreationTime: now,
			AlertUpdateTime:   now,
			Title:             title,
			Severity:          severity,
		}
		return info, nil
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE alerts SET updated_at = ?, title = ?, severity = ? WHERE alert_id = ?
	`, now, title, severity, existing.AlertID)
	if err != nil {
		return nil, fmt.Errorf("update alert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	info = &AlertInfo{
		AlertID:           existing.AlertID,
		RuleID:            ruleID,
		DedupKey:          dedupKey,
		AlertCreationTime: existing.AlertCreationTime,
		AlertUpdateTime:   now,
		Title:             title,
		Severity:          severity,
	}
	return info, nil
}

func (d *Deduplicator) ResolveAlert(ctx context.Context, alertID string) (err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	start := time.Now()
	defer func() {
		st := "success"
		if err != nil {
			st = "error"
		}
		metrics.ObserveStateDBOperation("resolve_alert", time.Since(start))
		metrics.RecordStateDBOperation("resolve_alert", st)
	}()

	_, err = d.db.ExecContext(ctx, `
		UPDATE alerts SET resolved_at = ? WHERE alert_id = ? AND resolved_at IS NULL
	`, time.Now(), alertID)
	return err
}

func (d *Deduplicator) GetOpenAlerts(ctx context.Context, ruleID string) (alerts []AlertInfo, err error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	start := time.Now()
	defer func() {
		st := "success"
		if err != nil {
			st = "error"
		}
		metrics.ObserveStateDBOperation("get_open_alerts", time.Since(start))
		metrics.RecordStateDBOperation("get_open_alerts", st)
	}()

	rows, err := d.db.QueryContext(ctx, `
		SELECT alert_id, rule_id, dedup_key, created_at, updated_at, title, severity
		FROM alerts
		WHERE rule_id = ? AND resolved_at IS NULL
		ORDER BY created_at DESC
	`, ruleID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var a AlertInfo
		if err := rows.Scan(&a.AlertID, &a.RuleID, &a.DedupKey, &a.AlertCreationTime, &a.AlertUpdateTime, &a.Title, &a.Severity); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// ListOpenAlertsAll returns open alerts across all rules (newest activity first). For IR review and benchmarks.
func (d *Deduplicator) ListOpenAlertsAll(ctx context.Context, limit, offset int) (alerts []AlertInfo, err error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	start := time.Now()
	defer func() {
		st := "success"
		if err != nil {
			st = "error"
		}
		metrics.ObserveStateDBOperation("list_open_alerts_all", time.Since(start))
		metrics.RecordStateDBOperation("list_open_alerts_all", st)
	}()

	if limit <= 0 {
		limit = 100
	}
	if limit > 50000 {
		limit = 50000
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := d.db.QueryContext(ctx, `
		SELECT alert_id, rule_id, dedup_key, created_at, updated_at, title, severity
		FROM alerts
		WHERE resolved_at IS NULL
		ORDER BY updated_at DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var a AlertInfo
		if err := rows.Scan(&a.AlertID, &a.RuleID, &a.DedupKey, &a.AlertCreationTime, &a.AlertUpdateTime, &a.Title, &a.Severity); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

func GenerateDedupKey(ruleID, dedup string) string {
	return uuid.NewSHA1(DedupNamespace, []byte(ruleID+":"+dedup)).String()
}

func GenerateAlertID(ruleID, dedupKey string, ts time.Time) string {
	return uuid.NewSHA1(DedupNamespace, []byte(fmt.Sprintf("%s:%s:%d", ruleID, dedupKey, ts.UnixNano()))).String()
}

func (d *Deduplicator) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.db != nil {
		return d.db.Close()
	}
	return nil
}
