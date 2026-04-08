package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bilals12/iota/internal/alerts"
	"github.com/bilals12/iota/internal/api"
	"github.com/bilals12/iota/internal/engine"
	"github.com/bilals12/iota/internal/logprocessor"
	"github.com/bilals12/iota/internal/reader"
	"github.com/bilals12/iota/internal/s3poller"
	"github.com/bilals12/iota/internal/telemetry"
	"github.com/bilals12/iota/internal/watcher"
	"github.com/bilals12/iota/pkg/cloudtrail"
)

func main() {
	// Check if first arg is "query" subcommand
	if len(os.Args) > 1 && os.Args[0] != "-h" && os.Args[1] == "query" {
		if err := runQueryCmd(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "alerts" {
		if err := runAlertsCmd(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runQueryCmd() error {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	sql := fs.String("sql", "", "SQL query to execute (use {TABLE} as placeholder)")
	logType := fs.String("log-type", "cloudtrail", "Log type to query")
	last := fs.String("last", "24h", "Query last duration (e.g., 7d, 24h, 1h)")
	startTime := fs.String("start", "", "Start time (RFC3339 format)")
	endTime := fs.String("end", "", "End time (RFC3339 format)")
	output := fs.String("output", "table", "Output format: table, json, csv")
	forceAthena := fs.Bool("force-athena", false, "Force Athena backend")
	forceDuckDB := fs.Bool("force-duckdb", false, "Force DuckDB backend")
	s3Bucket := fs.String("s3-bucket", defaultQueryS3Bucket(), "S3 bucket for data lake JSON (env: IOTA_S3_BUCKET, IOTA_DATA_LAKE_BUCKET, DATA_LAKE_BUCKET)")
	s3Region := fs.String("aws-region", getEnvOrDefault("AWS_REGION", "us-east-1"), "AWS region")
	memoryLimit := fs.String("memory-limit", "4GB", "DuckDB memory limit")
	workgroup := fs.String("athena-workgroup", os.Getenv("IOTA_ATHENA_WORKGROUP"), "Athena workgroup")
	database := fs.String("athena-database", os.Getenv("IOTA_ATHENA_DATABASE"), "Athena/Glue database")
	resultBucket := fs.String("athena-result-bucket", os.Getenv("IOTA_ATHENA_RESULT_BUCKET"), "S3 bucket for Athena results")

	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}

	cfg := QueryConfig{
		SQL:          *sql,
		LogType:      *logType,
		OutputFormat: *output,
		ForceAthena:  *forceAthena,
		ForceDuckDB:  *forceDuckDB,
		S3Region:     *s3Region,
		S3Bucket:     *s3Bucket,
		MemoryLimit:  *memoryLimit,
		Workgroup:    *workgroup,
		Database:     *database,
		ResultBucket: *resultBucket,
	}

	// Parse time range
	if *startTime != "" && *endTime != "" {
		start, err := time.Parse(time.RFC3339, *startTime)
		if err != nil {
			return fmt.Errorf("invalid start time: %w", err)
		}
		end, err := time.Parse(time.RFC3339, *endTime)
		if err != nil {
			return fmt.Errorf("invalid end time: %w", err)
		}
		cfg.StartTime = start
		cfg.EndTime = end
	} else {
		duration, err := parseDuration(*last)
		if err != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}
		cfg.Last = duration
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	return runQuery(ctx, cfg)
}

func getEnvOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// defaultQueryS3Bucket resolves the lake bucket for `iota query` so kubectl exec
// picks up the same DATA_LAKE_BUCKET as the running deployment without passing flags.
func defaultQueryS3Bucket() string {
	for _, key := range []string{"IOTA_S3_BUCKET", "IOTA_DATA_LAKE_BUCKET", "DATA_LAKE_BUCKET"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return ""
}

func parseDuration(s string) (time.Duration, error) {
	// Support "7d" style durations
	if len(s) > 1 && s[len(s)-1] == 'd' {
		days, err := time.ParseDuration(s[:len(s)-1] + "h")
		if err != nil {
			return 0, err
		}
		return days * 24, nil
	}
	return time.ParseDuration(s)
}

func run() error {
	// Subcommands must run before flag.Parse(): the stdlib flag package stops at the first non-flag
	// argument, so `iota alerts list ...` would otherwise leave --rules unset and fail here.
	if len(os.Args) > 1 && os.Args[1] == "alerts" {
		return runAlertsCmd()
	}

	var (
		mode               = flag.String("mode", "sqs", "mode: once, watch, s3-poll, sqs, or eventbridge")
		jsonlFile          = flag.String("jsonl", "", "path to jsonl file (once mode)")
		eventsDir          = flag.String("events-dir", "", "path to events directory (watch mode)")
		s3Bucket           = flag.String("s3-bucket", "", "S3 bucket name (s3-poll or sqs mode)")
		s3Prefix           = flag.String("s3-prefix", "AWSLogs/", "S3 prefix (s3-poll mode)")
		sqsQueueURL        = flag.String("sqs-queue-url", "", "SQS queue URL (sqs or eventbridge mode)")
		pollInterval       = flag.String("poll-interval", "5m", "polling interval (s3-poll mode)")
		awsRegion          = flag.String("aws-region", "us-east-1", "AWS region")
		rulesDir           = flag.String("rules", "", "path to rules directory")
		python             = flag.String("python", "python3", "python executable path")
		enginePy           = flag.String("engine", "engines/iota/engine.py", "path to engine.py")
		stateFile          = flag.String("state", "iota.db", "path to state database")
		slackWebhook       = flag.String("slack-webhook", "", "slack webhook url for alerts")
		dataLakeBucket     = flag.String("data-lake-bucket", "", "S3 bucket for processed data lake (optional)")
		bloomFile          = flag.String("bloom-file", "", "path to bloom filter file for deduplication (optional)")
		bloomExpectedItems = flag.Uint64("bloom-expected-items", 10000000, "expected number of items for bloom filter")
		bloomFalsePositive = flag.Float64("bloom-false-positive", 0.001, "false positive rate for bloom filter (0.0-1.0)")
		downloadWorkers    = flag.Int("download-workers", 5, "number of parallel download workers")
		processWorkers     = flag.Int("process-workers", 10, "number of parallel process workers")
		glueDatabase       = flag.String("glue-database", "", "Glue database name for data catalog (optional)")
		athenaWorkgroup    = flag.String("athena-workgroup", "primary", "Athena workgroup for queries")
		athenaResultBucket = flag.String("athena-result-bucket", "", "S3 bucket for Athena query results (optional)")
	)
	flag.Parse()

	if *rulesDir == "" {
		return fmt.Errorf("rules flag is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("received shutdown signal")
		cancel()
	}()

	otelCfg := telemetry.ConfigFromEnv()
	shutdown, err := telemetry.Init(ctx, otelCfg)
	if err != nil {
		log.Printf("warning: failed to initialize telemetry: %v", err)
	} else {
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			if err := shutdown(shutdownCtx); err != nil {
				log.Printf("warning: failed to shutdown telemetry: %v", err)
			}
		}()
		if otelCfg.Enabled {
			log.Printf("telemetry enabled: endpoint=%s", otelCfg.Endpoint)
		}
	}

	var slackClient *alerts.SlackClient
	if *slackWebhook != "" {
		slackClient = alerts.NewSlackClient(*slackWebhook)
	}

	switch *mode {
	case "once":
		return runOnce(ctx, *jsonlFile, *rulesDir, *python, *enginePy, slackClient)
	case "watch":
		return runWatch(ctx, *eventsDir, *rulesDir, *python, *enginePy, *stateFile, slackClient)
	case "s3-poll":
		interval, err := time.ParseDuration(*pollInterval)
		if err != nil {
			return fmt.Errorf("invalid poll-interval: %w", err)
		}
		return runS3Poll(ctx, *s3Bucket, *s3Prefix, *awsRegion, interval, *rulesDir, *python, *enginePy, *stateFile, slackClient)
	case "sqs":
		if *sqsQueueURL == "" {
			return fmt.Errorf("sqs-queue-url flag is required in sqs mode")
		}
		healthPort := os.Getenv("HEALTH_PORT")
		if healthPort == "" {
			healthPort = "8080"
		}
		enableMetrics := os.Getenv("ENABLE_METRICS") == "true"
		healthServer := api.NewHealthServerWithReadiness(healthPort, nil, enableMetrics)
		go func() {
			if err := healthServer.Start(ctx); err != nil {
				log.Printf("health server error: %v", err)
			}
		}()
		return runSQS(ctx, *sqsQueueURL, *s3Bucket, *awsRegion, *rulesDir, *python, *enginePy, *stateFile, *dataLakeBucket, *bloomFile, *bloomExpectedItems, *bloomFalsePositive, *downloadWorkers, *processWorkers, *glueDatabase, *athenaWorkgroup, *athenaResultBucket, slackClient)
	case "eventbridge":
		if *sqsQueueURL == "" {
			return fmt.Errorf("sqs-queue-url flag is required in eventbridge mode")
		}
		healthPort := os.Getenv("HEALTH_PORT")
		if healthPort == "" {
			healthPort = "8080"
		}
		enableMetrics := os.Getenv("ENABLE_METRICS") == "true"
		healthServer := api.NewHealthServerWithReadiness(healthPort, nil, enableMetrics)
		go func() {
			if err := healthServer.Start(ctx); err != nil {
				log.Printf("health server error: %v", err)
			}
		}()
		return runEventBridge(ctx, *sqsQueueURL, *awsRegion, *rulesDir, *python, *enginePy, *stateFile, *dataLakeBucket, *bloomFile, *bloomExpectedItems, *bloomFalsePositive, *glueDatabase, *athenaWorkgroup, *athenaResultBucket, slackClient)
	default:
		return fmt.Errorf("invalid mode: %s (must be once, watch, s3-poll, sqs, or eventbridge)", *mode)
	}
}

func runOnce(ctx context.Context, jsonlFile, rulesDir, python, enginePy string, slackClient *alerts.SlackClient) error {
	if jsonlFile == "" {
		return fmt.Errorf("jsonl flag is required in once mode")
	}

	log.Printf("processing file: %s", jsonlFile)

	file, err := os.Open(jsonlFile)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	processor := logprocessor.New()
	processedEvents, errs := processor.Process(ctx, file)

	var batch []*cloudtrail.Event
	for event := range processedEvents {
		log.Printf("parsed event: logType=%s eventTime=%s eventID=%s",
			event.LogType, event.EventTime.Format(time.RFC3339), event.Event.EventID)
		batch = append(batch, event.Event)
	}

	if err := <-errs; err != nil {
		return fmt.Errorf("process events: %w", err)
	}

	log.Printf("processed %d events from file", len(batch))

	if len(batch) == 0 {
		log.Println("no events found in file")
		return nil
	}

	eng := engine.New(python, enginePy, rulesDir)
	matches, err := eng.Analyze(ctx, batch)
	if err != nil {
		return fmt.Errorf("analyze: %w", err)
	}

	log.Printf("found %d rule matches", len(matches))

	for _, match := range matches {
		if err := handleAlert(match, slackClient); err != nil {
			log.Printf("error handling alert: %v", err)
		}
	}

	return nil
}

func runWatch(ctx context.Context, eventsDir, rulesDir, python, enginePy, stateFile string, slackClient *alerts.SlackClient) error {
	if eventsDir == "" {
		return fmt.Errorf("events-dir flag is required in watch mode")
	}

	log.Printf("starting watcher on %s", eventsDir)

	eng := engine.New(python, enginePy, rulesDir)
	r := reader.New()

	handler := func(path string) error {
		log.Printf("processing file: %s", path)

		events, errs := r.ReadFile(ctx, path)

		var batch []*cloudtrail.Event
		for event := range events {
			batch = append(batch, event)
		}

		if err := <-errs; err != nil {
			return fmt.Errorf("read file: %w", err)
		}

		if len(batch) == 0 {
			return nil
		}

		matches, err := eng.Analyze(ctx, batch)
		if err != nil {
			return fmt.Errorf("analyze: %w", err)
		}

		for _, match := range matches {
			if err := handleAlert(match, slackClient); err != nil {
				log.Printf("error handling alert: %v", err)
			}
		}

		log.Printf("processed %d events, %d matches", len(batch), len(matches))
		return nil
	}

	w, err := watcher.New(eventsDir, stateFile, handler)
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}
	defer w.Close()

	log.Println("watcher started, press ctrl+c to stop")
	return w.Watch(ctx)
}

func runS3Poll(ctx context.Context, bucket, prefix, region string, interval time.Duration, rulesDir, python, enginePy, stateFile string, slackClient *alerts.SlackClient) error {
	if bucket == "" {
		return fmt.Errorf("s3-bucket flag is required in s3-poll mode")
	}

	log.Printf("starting S3 poller: bucket=%s prefix=%s interval=%v", bucket, prefix, interval)

	eng := engine.New(python, enginePy, rulesDir)
	r := reader.New()

	// Handler function that processes CloudTrail JSON from S3
	handler := func(ioReader io.Reader) error {
		events, errs := r.Read(ctx, ioReader)

		var batch []*cloudtrail.Event
		for event := range events {
			batch = append(batch, event)
		}

		if err := <-errs; err != nil {
			return fmt.Errorf("read events: %w", err)
		}

		if len(batch) == 0 {
			return nil
		}

		matches, err := eng.Analyze(ctx, batch)
		if err != nil {
			return fmt.Errorf("analyze: %w", err)
		}

		for _, match := range matches {
			if err := handleAlert(match, slackClient); err != nil {
				log.Printf("error handling alert: %v", err)
			}
		}

		log.Printf("processed %d events, %d matches", len(batch), len(matches))
		return nil
	}

	poller, err := s3poller.New(ctx, s3poller.Config{
		Bucket:    bucket,
		Prefix:    prefix,
		StateFile: stateFile,
		Handler:   handler,
		Interval:  interval,
		Region:    region,
	})
	if err != nil {
		return fmt.Errorf("create S3 poller: %w", err)
	}
	defer poller.Close()

	log.Println("S3 poller started, press ctrl+c to stop")
	return poller.Poll(ctx)
}

func handleAlert(match engine.Match, slackClient *alerts.SlackClient) error {
	output, err := json.MarshalIndent(match, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal alert: %w", err)
	}

	fmt.Println(string(output))

	if slackClient != nil {
		if err := slackClient.SendAlert(match); err != nil {
			return fmt.Errorf("send to slack: %w", err)
		}
		log.Printf("sent alert to slack: %s", match.Title)
	}

	return nil
}
