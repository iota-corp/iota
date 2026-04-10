package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/bilals12/iota/internal/query"
)

type QueryConfig struct {
	SQL          string
	LogType      string
	Last         time.Duration
	StartTime    time.Time
	EndTime      time.Time
	OutputFormat string
	ForceAthena  bool
	ForceDuckDB  bool
	S3Region     string
	S3Bucket     string
	MemoryLimit  string
	Workgroup    string
	Database     string
	ResultBucket string
}

func runQuery(ctx context.Context, cfg QueryConfig) error {
	if cfg.SQL == "" {
		return fmt.Errorf("sql query is required")
	}
	if cfg.S3Bucket == "" {
		return fmt.Errorf("s3-bucket is required for queries")
	}

	var tr query.TimeRange
	if !cfg.StartTime.IsZero() && !cfg.EndTime.IsZero() {
		tr = query.TimeRange{Start: cfg.StartTime, End: cfg.EndTime}
	} else if cfg.Last > 0 {
		tr = query.TimeRange{Start: time.Now().Add(-cfg.Last), End: time.Now()}
	} else {
		tr = query.TimeRange{Start: time.Now().Add(-24 * time.Hour), End: time.Now()}
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.S3Region))
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}

	var athenaClient *athena.Client
	if cfg.Workgroup != "" && cfg.Database != "" && cfg.ResultBucket != "" {
		athenaClient = athena.NewFromConfig(awsCfg)
	}

	engine, err := query.NewEngine(query.EngineConfig{
		S3Region:     cfg.S3Region,
		S3Bucket:     cfg.S3Bucket,
		AthenaClient: athenaClient,
		Workgroup:    cfg.Workgroup,
		Database:     cfg.Database,
		ResultBucket: cfg.ResultBucket,
		MemoryLimit:  cfg.MemoryLimit,
	})
	if err != nil {
		return fmt.Errorf("create query engine: %w", err)
	}
	defer func() { _ = engine.Close() }()

	opts := query.QueryOptions{
		LogType:     cfg.LogType,
		ForceAthena: cfg.ForceAthena,
		ForceDuckDB: cfg.ForceDuckDB,
	}

	backend := "auto"
	if cfg.ForceAthena {
		backend = "athena"
	} else if cfg.ForceDuckDB {
		backend = "duckdb"
	}

	fmt.Fprintf(os.Stderr, "Executing query (backend=%s, range=%s to %s)...\n",
		backend, tr.Start.Format(time.RFC3339), tr.End.Format(time.RFC3339))

	result, err := engine.Query(ctx, cfg.SQL, tr, opts)
	if err != nil {
		return fmt.Errorf("query failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Query completed in %s, %d rows returned\n", result.Elapsed, len(result.Rows))

	switch cfg.OutputFormat {
	case "json":
		return outputJSON(result)
	case "csv":
		return outputCSV(result)
	default:
		return outputTable(result)
	}
}

func outputTable(result *query.QueryResult) error {
	if len(result.Columns) == 0 {
		fmt.Println("No results")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	_, _ = fmt.Fprintln(w, strings.Join(result.Columns, "\t"))
	_, _ = fmt.Fprintln(w, strings.Repeat("-", len(result.Columns)*15))

	for _, row := range result.Rows {
		values := make([]string, len(row))
		for i, v := range row {
			values[i] = fmt.Sprintf("%v", v)
		}
		_, _ = fmt.Fprintln(w, strings.Join(values, "\t"))
	}

	return w.Flush()
}

func outputJSON(result *query.QueryResult) error {
	output := make([]map[string]interface{}, len(result.Rows))
	for i, row := range result.Rows {
		obj := make(map[string]interface{})
		for j, col := range result.Columns {
			obj[col] = row[j]
		}
		output[i] = obj
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func outputCSV(result *query.QueryResult) error {
	w := csv.NewWriter(os.Stdout)

	if err := w.Write(result.Columns); err != nil {
		return err
	}

	for _, row := range result.Rows {
		values := make([]string, len(row))
		for i, v := range row {
			values[i] = fmt.Sprintf("%v", v)
		}
		if err := w.Write(values); err != nil {
			return err
		}
	}

	w.Flush()
	return w.Error()
}
