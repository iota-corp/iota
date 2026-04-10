package integration

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Integration struct {
	ID            string
	Type          string
	Label         string
	AWSAccountID  string
	S3Bucket      string
	S3Prefix      string
	RoleARN       string
	KMSKeyID      string
	Enabled       bool
	CreatedAt     time.Time
	LastEventTime *time.Time
	EventStatus   string
}

type Manager struct {
	db *sql.DB
}

func NewManager(stateFile string) (*Manager, error) {
	db, err := sql.Open("sqlite3", stateFile)
	if err != nil {
		return nil, fmt.Errorf("open integration db: %w", err)
	}

	if err := initIntegrationDB(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init integration db: %w", err)
	}

	return &Manager{db: db}, nil
}

func initIntegrationDB(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS integrations (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			label TEXT NOT NULL,
			aws_account_id TEXT,
			s3_bucket TEXT,
			s3_prefix TEXT,
			role_arn TEXT,
			kms_key_id TEXT,
			enabled INTEGER DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_event_time TIMESTAMP,
			event_status TEXT DEFAULT 'ACTIVE'
		)
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		ALTER TABLE integrations ADD COLUMN role_arn TEXT
	`)
	_ = err

	_, err = db.Exec(`
		ALTER TABLE integrations ADD COLUMN kms_key_id TEXT
	`)
	_ = err

	return nil
}

func (m *Manager) Create(ctx context.Context, integration *Integration) error {
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO integrations (id, type, label, aws_account_id, s3_bucket, s3_prefix, role_arn, kms_key_id, enabled, created_at, event_status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, integration.ID, integration.Type, integration.Label, integration.AWSAccountID,
		integration.S3Bucket, integration.S3Prefix, integration.RoleARN, integration.KMSKeyID,
		integration.Enabled, integration.CreatedAt, integration.EventStatus)
	return err
}

func (m *Manager) Get(ctx context.Context, id string) (*Integration, error) {
	var integration Integration
	err := m.db.QueryRowContext(ctx, `
		SELECT id, type, label, aws_account_id, s3_bucket, s3_prefix, role_arn, kms_key_id, enabled, created_at, last_event_time, event_status
		FROM integrations
		WHERE id = ?
	`, id).Scan(&integration.ID, &integration.Type, &integration.Label, &integration.AWSAccountID,
		&integration.S3Bucket, &integration.S3Prefix, &integration.RoleARN, &integration.KMSKeyID,
		&integration.Enabled, &integration.CreatedAt, &integration.LastEventTime, &integration.EventStatus)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("integration not found: %s", id)
	}
	if err != nil {
		return nil, err
	}
	return &integration, nil
}

func (m *Manager) List(ctx context.Context) ([]*Integration, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT id, type, label, aws_account_id, s3_bucket, s3_prefix, role_arn, kms_key_id, enabled, created_at, last_event_time, event_status
		FROM integrations
		WHERE enabled = 1
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var integrations []*Integration
	for rows.Next() {
		var integration Integration
		err := rows.Scan(&integration.ID, &integration.Type, &integration.Label, &integration.AWSAccountID,
			&integration.S3Bucket, &integration.S3Prefix, &integration.RoleARN, &integration.KMSKeyID,
			&integration.Enabled, &integration.CreatedAt, &integration.LastEventTime, &integration.EventStatus)
		if err != nil {
			return nil, err
		}
		integrations = append(integrations, &integration)
	}
	return integrations, rows.Err()
}

func (m *Manager) UpdateStatus(ctx context.Context, id string, lastEventTime time.Time) error {
	_, err := m.db.ExecContext(ctx, `
		UPDATE integrations
		SET last_event_time = ?, event_status = 'ACTIVE'
		WHERE id = ?
	`, lastEventTime, id)
	return err
}

func (m *Manager) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}
