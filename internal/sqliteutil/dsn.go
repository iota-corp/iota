package sqliteutil

import (
	"database/sql"
	"strings"
)

// FileURI returns a SQLite connection string with WAL journal and a busy timeout
// so concurrent handlers (e.g. parallel SQS message processing) see fewer
// "database is locked" errors. In-memory databases are returned unchanged.
func FileURI(path string) string {
	if path == "" || path == ":memory:" {
		return path
	}
	if strings.Contains(path, "?") {
		return path
	}
	return path + "?_journal_mode=WAL&_busy_timeout=5000"
}

// ConfigureConnectionPool sets SQLite-friendly pool limits for a file-backed DB.
// A single open connection avoids writer contention inside the pool when combined
// with application-level serialization (see deduplication and state packages).
func ConfigureConnectionPool(db *sql.DB) {
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
}
