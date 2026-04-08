package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/bilals12/iota/internal/deduplication"
)

func runAlertsCmd() error {
	if len(os.Args) < 3 {
		return fmt.Errorf(`usage: iota alerts <command> [options]

Commands:
  list    List open (unresolved) alerts from the dedup SQLite DB (same file as --state)

Incident response: use this for fast, enriched rows (rule_id, severity, title, timestamps)
without going through the data lake. For historical raw events use: iota query (Athena/DuckDB).`)
	}
	switch os.Args[2] {
	case "list":
		return runAlertsList(os.Args[3:])
	default:
		return fmt.Errorf("unknown alerts subcommand %q (try: iota alerts list)", os.Args[2])
	}
}

func runAlertsList(args []string) error {
	fs := flag.NewFlagSet("alerts list", flag.ExitOnError)
	dbPath := fs.String("db", "iota.db", "path to SQLite DB (same as iota --state; holds `alerts` + `state` tables)")
	limit := fs.Int("limit", 100, "max rows (cap 50000)")
	offset := fs.Int("offset", 0, "pagination offset")
	asJSON := fs.Bool("json", false, "emit JSON instead of a table")
	timing := fs.Bool("timing", true, "print elapsed time to stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()
	d, err := deduplication.New(*dbPath)
	if err != nil {
		return fmt.Errorf("open dedup db: %w", err)
	}
	defer d.Close()

	start := time.Now()
	rows, err := d.ListOpenAlertsAll(ctx, *limit, *offset)
	elapsed := time.Since(start)
	if err != nil {
		return err
	}

	if *timing {
		fmt.Fprintf(os.Stderr, "alerts: rows=%d elapsed=%s\n", len(rows), elapsed.Round(time.Microsecond))
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "RULE_ID\tSEVERITY\tUPDATED\tTITLE")
	for _, r := range rows {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			r.RuleID, r.Severity, r.AlertUpdateTime.Format(time.RFC3339), r.Title)
	}
	return w.Flush()
}
