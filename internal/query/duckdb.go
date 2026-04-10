package query

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bilals12/iota/internal/lakepath"
	_ "github.com/marcboeker/go-duckdb"
)

type DuckDBClient struct {
	db          *sql.DB
	s3Region    string
	s3Bucket    string
	memoryLimit string
	threads     int
}

type DuckDBConfig struct {
	S3Region    string
	S3Bucket    string
	MemoryLimit string
	Threads     int
}

func NewDuckDB(cfg DuckDBConfig) (*DuckDBClient, error) {
	if cfg.MemoryLimit == "" {
		cfg.MemoryLimit = "4GB"
	}
	if cfg.Threads == 0 {
		cfg.Threads = 4
	}

	db, err := sql.Open("duckdb", "")
	if err != nil {
		return nil, fmt.Errorf("open duckdb: %w", err)
	}

	client := &DuckDBClient{
		db:          db,
		s3Region:    cfg.S3Region,
		s3Bucket:    cfg.S3Bucket,
		memoryLimit: cfg.MemoryLimit,
		threads:     cfg.Threads,
	}

	if err := client.initialize(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return client, nil
}

// duckdbLocalDir picks a writable base for extensions + spill files.
// Many k8s pods mount state under /data but leave /tmp read-only; prefer /data/duckdb then.
func duckdbLocalDir() string {
	if v := strings.TrimSpace(os.Getenv("IOTA_DUCKDB_DIR")); v != "" {
		return filepath.Clean(v)
	}
	if fi, err := os.Stat("/data"); err == nil && fi.IsDir() {
		return "/data/duckdb"
	}
	return filepath.Join(os.TempDir(), "iota-duckdb")
}

func sqlQuotedPath(p string) string {
	return strings.ReplaceAll(filepath.ToSlash(p), "'", "''")
}

func (c *DuckDBClient) initialize() error {
	base := duckdbLocalDir()
	extDir := filepath.Join(base, "extensions")
	tmpDir := filepath.Join(base, "tmp")
	for _, dir := range []string{extDir, tmpDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	// Default extension path is ~/.duckdb/; HOME may be "/" in containers. /tmp may be read-only in hardened pods.
	setup := []string{
		fmt.Sprintf("SET extension_directory='%s'", sqlQuotedPath(extDir)),
		"INSTALL httpfs",
		"LOAD httpfs",
		fmt.Sprintf("SET s3_region='%s'", c.s3Region),
		"SET s3_use_ssl=true",
		fmt.Sprintf("SET memory_limit='%s'", c.memoryLimit),
		fmt.Sprintf("SET threads=%d", c.threads),
		fmt.Sprintf("SET temp_directory='%s'", sqlQuotedPath(tmpDir)),
	}

	for _, stmt := range setup {
		if _, err := c.db.Exec(stmt); err != nil {
			return fmt.Errorf("setup %q: %w", stmt, err)
		}
	}

	return nil
}

type QueryResult struct {
	Columns []string
	Rows    [][]interface{}
	Elapsed time.Duration
}

func (c *DuckDBClient) Query(ctx context.Context, sql string) (*QueryResult, error) {
	start := time.Now()

	rows, err := c.db.QueryContext(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("columns: %w", err)
	}

	var results [][]interface{}
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}

		results = append(results, values)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}

	return &QueryResult{
		Columns: columns,
		Rows:    results,
		Elapsed: time.Since(start),
	}, nil
}

func (c *DuckDBClient) QueryS3(ctx context.Context, logType string, sqlTemplate string, tr TimeRange) (*QueryResult, error) {
	paths := c.buildS3Paths(logType, tr)
	if len(paths) == 0 {
		return &QueryResult{Columns: []string{}, Rows: [][]interface{}{}}, nil
	}

	tableSrc := c.buildTableSource(paths)
	sql := strings.Replace(sqlTemplate, "{TABLE}", tableSrc, 1)

	return c.Query(ctx, sql)
}

// buildS3Paths lists hour partition globs that may contain events in [tr.Start, tr.End).
// End is exclusive (same idea as --start/--end on the CLI). Using tr.End.Add(time.Hour)
// would include an extra empty hour and makes DuckDB fail when read_ndjson sees a glob with no files.
func (c *DuckDBClient) buildS3Paths(logType string, tr TimeRange) []string {
	if !tr.End.After(tr.Start) {
		return nil
	}
	var paths []string
	current := tr.Start.Truncate(time.Hour)
	lastHour := tr.End.Add(-time.Nanosecond).Truncate(time.Hour)
	for !current.After(lastHour) {
		paths = append(paths, lakepath.S3JSONGlob(c.s3Bucket, logType, current))
		current = current.Add(time.Hour)
	}
	return paths
}

// buildTableSource wraps paths for DuckDB read_ndjson; globs must match the data lake writer (*.json.gz under logs/<slug>/…).
func (c *DuckDBClient) buildTableSource(paths []string) string {
	if len(paths) == 1 {
		return fmt.Sprintf("read_ndjson('%s', hive_partitioning=true)", paths[0])
	}

	quoted := make([]string, len(paths))
	for i, p := range paths {
		quoted[i] = fmt.Sprintf("'%s'", p)
	}

	return fmt.Sprintf("read_ndjson([%s], hive_partitioning=true)", strings.Join(quoted, ", "))
}

func (c *DuckDBClient) Close() error {
	return c.db.Close()
}
