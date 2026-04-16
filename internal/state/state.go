package state

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/bilals12/iota/internal/metrics"
	"github.com/bilals12/iota/internal/sqliteutil"
	_ "github.com/mattn/go-sqlite3"
)

const createTableSQL = `
CREATE TABLE IF NOT EXISTS state (
	bucket TEXT NOT NULL,
	account_id TEXT NOT NULL,
	region TEXT NOT NULL,
	last_processed_key TEXT,
	processed_count INTEGER DEFAULT 0,
	last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (bucket, account_id, region)
)`

type DB struct {
	mu sync.RWMutex
	db *sql.DB
}

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite3", sqliteutil.FileURI(path))
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	if _, err = db.Exec(createTableSQL); err != nil {
		_ = db.Close()
		metrics.RecordStateDBOperation("state_init_schema", "error")
		return nil, fmt.Errorf("create table: %w", err)
	}
	metrics.RecordStateDBOperation("state_init_schema", "success")

	sqliteutil.ConfigureConnectionPool(db)

	log.Printf("initialized state database: %s", path)

	return &DB{db: db}, nil
}

func (d *DB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.db.Close()
}

func (d *DB) GetLastProcessedKey(bucket, accountID, region string) (key string, err error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	start := time.Now()
	defer func() {
		st := "success"
		if err != nil {
			st = "error"
		}
		metrics.ObserveStateDBOperation("state_get_last_key", time.Since(start))
		metrics.RecordStateDBOperation("state_get_last_key", st)
	}()

	var lastKey sql.NullString
	err = d.db.QueryRow(
		"SELECT last_processed_key FROM state WHERE bucket = ? AND account_id = ? AND region = ?",
		bucket, accountID, region,
	).Scan(&lastKey)

	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("query last key: %w", err)
	}

	if lastKey.Valid {
		return lastKey.String, nil
	}
	return "", nil
}

func (d *DB) UpdateLastProcessedKey(bucket, accountID, region, key string) (err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	start := time.Now()
	defer func() {
		st := "success"
		if err != nil {
			st = "error"
		}
		metrics.ObserveStateDBOperation("state_update_last_key", time.Since(start))
		metrics.RecordStateDBOperation("state_update_last_key", st)
	}()

	_, err = d.db.Exec(`
		INSERT INTO state (bucket, account_id, region, last_processed_key, processed_count, last_updated)
		VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
		ON CONFLICT(bucket, account_id, region) DO UPDATE SET
			last_processed_key = excluded.last_processed_key,
			processed_count = processed_count + 1,
			last_updated = CURRENT_TIMESTAMP
	`, bucket, accountID, region, key)
	if err != nil {
		return fmt.Errorf("update state: %w", err)
	}

	return nil
}
