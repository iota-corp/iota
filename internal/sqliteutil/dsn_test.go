package sqliteutil

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestFileURI(t *testing.T) {
	t.Parallel()
	if got, want := FileURI(""), ""; got != want {
		t.Errorf("empty: got %q want %q", got, want)
	}
	if got, want := FileURI(":memory:"), ":memory:"; got != want {
		t.Errorf(":memory:: got %q want %q", got, want)
	}
	if got := FileURI("/tmp/x.db"); got != "/tmp/x.db?_journal_mode=WAL&_busy_timeout=5000" {
		t.Errorf("file: got %q", got)
	}
	if got := FileURI("/tmp/x.db?mode=rwc"); got != "/tmp/x.db?mode=rwc" {
		t.Errorf("already has ?: got %q", got)
	}
}

func TestConfigureConnectionPool(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ConfigureConnectionPool(db)
}
