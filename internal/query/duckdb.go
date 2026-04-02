package query

import (
	"context"
	"database/sql"
	"fmt"
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
		db.Close()
		return nil, err
	}

	return client, nil
}

func (c *DuckDBClient) initialize() error {
	setup := []string{
		"INSTALL httpfs",
		"LOAD httpfs",
		fmt.Sprintf("SET s3_region='%s'", c.s3Region),
		"SET s3_use_ssl=true",
		fmt.Sprintf("SET memory_limit='%s'", c.memoryLimit),
		fmt.Sprintf("SET threads=%d", c.threads),
		"SET temp_directory='/tmp/duckdb'",
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
	defer rows.Close()

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

func (c *DuckDBClient) buildS3Paths(logType string, tr TimeRange) []string {
	var paths []string
	current := tr.Start.Truncate(time.Hour)
	end := tr.End.Add(time.Hour).Truncate(time.Hour)

	for current.Before(end) {
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
