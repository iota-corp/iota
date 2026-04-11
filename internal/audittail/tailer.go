// Package audittail tails a newline-delimited file (e.g. Kubernetes API audit log)
// and invokes a callback for each complete line. It persists cursor state in SQLite
// so restarts resume without reprocessing completed lines.
package audittail

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// TailerConfig configures a single-file tail loop.
type TailerConfig struct {
	// Path is the path to the audit log file.
	Path string
	// StatePath is the SQLite database path (same file as iota --state is fine; uses its own table).
	StatePath string
	// FromStart when true and no cursor exists yet, begin at offset 0. When false, skip existing
	// bytes and only process lines appended after startup (same as seek-to-end).
	FromStart bool
	// PollInterval between reads when the file size is unchanged.
	PollInterval time.Duration
}

// Run tails Path until ctx is cancelled. For each complete non-empty line, calls onLine.
func Run(ctx context.Context, cfg TailerConfig, onLine func(line []byte) error) error {
	if cfg.Path == "" {
		return fmt.Errorf("audittail: path is required")
	}
	path, err := filepath.Abs(cfg.Path)
	if err != nil {
		return fmt.Errorf("audittail: abs path: %w", err)
	}
	cfg.Path = path

	if cfg.StatePath == "" {
		return fmt.Errorf("audittail: state path is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}

	db, err := sql.Open("sqlite3", cfg.StatePath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return fmt.Errorf("audittail: open state db: %w", err)
	}
	defer func() { _ = db.Close() }()

	if err := initSchema(db); err != nil {
		return err
	}

	off, pend, err := loadCursor(db, cfg.Path)
	if err != nil {
		return err
	}

	skippedToEOF := false
	if off == 0 && len(pend) == 0 && !cfg.FromStart {
		st, err := os.Stat(cfg.Path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("audittail: stat: %w", err)
		}
		if err == nil {
			off = st.Size()
			if err := saveCursor(db, cfg.Path, inodeOf(st), off, nil); err != nil {
				return err
			}
			log.Printf("audittail: no prior cursor; starting at EOF (offset=%d)", off)
			skippedToEOF = true
		}
	}

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	step := func() error {
		f, err := os.Open(cfg.Path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("open audit log: %w", err)
		}
		defer func() { _ = f.Close() }()

		st, err := f.Stat()
		if err != nil {
			return fmt.Errorf("stat: %w", err)
		}
		size := st.Size()
		curInode := inodeOf(st)

		if !skippedToEOF && !cfg.FromStart && off == 0 && len(pend) == 0 {
			off = size
			if err := saveCursor(db, cfg.Path, curInode, off, nil); err != nil {
				return err
			}
			skippedToEOF = true
			log.Printf("audittail: audit log appeared; starting at EOF (offset=%d)", off)
			return nil
		}

		savedInode, _, _, err := loadCursorRaw(db, cfg.Path)
		if err != nil {
			return err
		}
		if savedInode != 0 && curInode != 0 && savedInode != curInode {
			log.Printf("audittail: inode changed (%d -> %d), resetting cursor (log rotation)", savedInode, curInode)
			off, pend = 0, nil
		}
		if off > size {
			off, pend = 0, nil
		}

		chunkStart := off + int64(len(pend))
		var chunk []byte
		if chunkStart < size {
			chunk = make([]byte, size-chunkStart)
			if _, err := f.Seek(chunkStart, io.SeekStart); err != nil {
				return fmt.Errorf("seek: %w", err)
			}
			if _, err := io.ReadFull(f, chunk); err != nil {
				return fmt.Errorf("read: %w", err)
			}
		}
		buf := append(append([]byte{}, pend...), chunk...)

		complete, remainder := splitCompleteLines(buf)
		for _, line := range complete {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			if err := onLine(line); err != nil {
				return err
			}
		}

		newOff := size - int64(len(remainder))
		if err := saveCursor(db, cfg.Path, curInode, newOff, remainder); err != nil {
			return err
		}
		off, pend = newOff, remainder
		return nil
	}

	if err := step(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := step(); err != nil {
				return err
			}
		}
	}
}

func splitCompleteLines(buf []byte) (complete [][]byte, remainder []byte) {
	if len(buf) == 0 {
		return nil, nil
	}
	last := bytes.LastIndexByte(buf, '\n')
	if last < 0 {
		return nil, buf
	}
	raw := buf[:last+1]
	remainder = buf[last+1:]
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		if len(line) > 0 {
			complete = append(complete, line)
		}
	}
	return complete, remainder
}

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS audit_tail_cursor (
	path TEXT PRIMARY KEY,
	inode INTEGER NOT NULL DEFAULT 0,
	offset INTEGER NOT NULL DEFAULT 0,
	pending BLOB
);`)
	return err
}

func loadCursor(db *sql.DB, path string) (off int64, pend []byte, err error) {
	_, off, pend, err = loadCursorRaw(db, path)
	return off, pend, err
}

func loadCursorRaw(db *sql.DB, path string) (inode uint64, off int64, pend []byte, err error) {
	row := db.QueryRow(`SELECT inode, offset, pending FROM audit_tail_cursor WHERE path = ?`, path)
	var inode64 sql.NullInt64
	var off64 sql.NullInt64
	var pendBlob []byte
	switch err := row.Scan(&inode64, &off64, &pendBlob); err {
	case sql.ErrNoRows:
		return 0, 0, nil, nil
	case nil:
		break
	default:
		return 0, 0, nil, err
	}
	if inode64.Valid {
		inode = uint64(inode64.Int64)
	}
	if off64.Valid {
		off = off64.Int64
	}
	return inode, off, pendBlob, nil
}

func saveCursor(db *sql.DB, path string, inode uint64, off int64, pend []byte) error {
	_, err := db.Exec(`
INSERT INTO audit_tail_cursor (path, inode, offset, pending) VALUES (?, ?, ?, ?)
ON CONFLICT(path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset, pending=excluded.pending`,
		path, int64(inode), off, pend)
	return err
}
