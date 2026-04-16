package main

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/bilals12/iota/internal/alertforwarder"
	"github.com/bilals12/iota/internal/alerts"
	"github.com/bilals12/iota/internal/bloom"
	"github.com/bilals12/iota/internal/datalake"
	"github.com/bilals12/iota/internal/deduplication"
	"github.com/bilals12/iota/internal/engine"
	"github.com/bilals12/iota/internal/events"
	gluecatalog "github.com/bilals12/iota/internal/glue"
	"github.com/bilals12/iota/internal/logprocessor"
	"github.com/bilals12/iota/internal/metrics"
	"github.com/bilals12/iota/internal/state"
	"github.com/bilals12/iota/internal/telemetry"
	"github.com/bilals12/iota/pkg/cloudtrail"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// openS3ObjectBody returns a reader for log parsing. Uses gzip when the key ends with .gz
// or S3 Content-Encoding is gzip (standard CloudTrail delivery).
func openS3ObjectBody(body io.ReadCloser, key string, contentEncoding *string) (io.Reader, func(), error) {
	if body == nil {
		return nil, nil, fmt.Errorf("nil body")
	}
	ce := ""
	if contentEncoding != nil {
		ce = strings.ToLower(strings.TrimSpace(*contentEncoding))
	}
	keyLower := strings.ToLower(key)
	if strings.HasSuffix(keyLower, ".gz") || ce == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			_ = body.Close()
			return nil, nil, fmt.Errorf("gzip reader: %w", err)
		}
		return gz, func() {
			_ = gz.Close()
			_ = body.Close()
		}, nil
	}
	return body, func() { _ = body.Close() }, nil
}

func sqsReceiveConfigFromEnv() (maxMessages, waitTime int32) {
	maxMessages = 10
	waitTime = 20
	if s := strings.TrimSpace(os.Getenv("IOTA_SQS_MAX_MESSAGES")); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= 10 {
			maxMessages = int32(n)
		}
	}
	if s := strings.TrimSpace(os.Getenv("IOTA_SQS_WAIT_SECONDS")); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 20 {
			waitTime = int32(n)
		}
	}
	return maxMessages, waitTime
}

// sqsProcessConcurrencyFromEnv returns how many SQS messages to process in parallel per receive
// (SQS and EventBridge ingestion paths). Default 1. Set IOTA_SQS_PROCESS_CONCURRENCY=2–8 after enabling
// SQLite WAL (state/dedup dbs) and load-testing; higher values increase SQLite lock risk.
func sqsProcessConcurrencyFromEnv() int {
	n := 1
	if s := strings.TrimSpace(os.Getenv("IOTA_SQS_PROCESS_CONCURRENCY")); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 1 && v <= 32 {
			n = v
		}
	}
	return n
}

func runSQS(ctx context.Context, queueURL, s3Bucket, region, rulesDir, python, enginePy, stateFile, dataLakeBucket, bloomFile string, bloomExpectedItems uint64, bloomFalsePositive float64, downloadWorkers, processWorkers int, glueDatabase, athenaWorkgroup, athenaResultBucket string, slackClient *alerts.SlackClient) error {
	log.Printf("starting SQS processor: queue=%s", queueURL)
	if latencyTraceEnabled() {
		log.Print("IOTA_LATENCY_TRACE is enabled: emitting latency_trace log lines (grep for 'latency_trace')")
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}

	sqsClient := sqs.NewFromConfig(awsCfg)
	s3Client := s3.NewFromConfig(awsCfg)

	stateDB, err := state.Open(stateFile)
	if err != nil {
		return fmt.Errorf("open state database: %w", err)
	}
	defer func() { _ = stateDB.Close() }()

	eng := engine.New(python, enginePy, rulesDir)
	defer func() { _ = eng.Close() }()

	var bloomFilter *bloom.Filter
	if bloomFile != "" {
		var err error
		bloomFilter, err = bloom.Load(bloomFile, uint(bloomExpectedItems), bloomFalsePositive)
		if err != nil {
			return fmt.Errorf("load bloom filter: %w", err)
		}
		defer func() {
			if err := bloomFilter.Save(); err != nil {
				log.Printf("warning: failed to save bloom filter: %v", err)
			}
		}()
	}

	var processor *logprocessor.Processor
	if bloomFilter != nil {
		processor = logprocessor.NewWithBloomFilter(bloomFilter)
	} else {
		processor = logprocessor.New()
	}
	processor.SetClassifyWorkers(processWorkers)

	dedup, err := deduplication.New(stateFile)
	if err != nil {
		return fmt.Errorf("create deduplicator: %w", err)
	}
	defer func() { _ = dedup.Close() }()

	var outputs []alertforwarder.Output
	if slackClient != nil {
		outputs = append(outputs, alerts.NewSlackOutput(slackClient.WebhookURL()))
	}

	forwarder := alertforwarder.New(dedup, outputs)

	var dataLakeWriter *datalake.Writer
	if dataLakeBucket != "" {
		if glueDatabase != "" {
			glueClient := gluecatalog.New(glue.NewFromConfig(awsCfg), glueDatabase, dataLakeBucket)
			if err := glueClient.EnsureDatabase(ctx); err != nil {
				log.Printf("warning: failed to ensure glue database: %v", err)
			}
			dataLakeWriter = datalake.NewWithGlue(s3Client, dataLakeBucket, 50*1024*1024, time.Minute, glueClient)
		} else {
			dataLakeWriter = datalake.New(s3Client, dataLakeBucket, 50*1024*1024, time.Minute)
		}
		defer func() { _ = dataLakeWriter.Flush(ctx) }()
	}

	handler := func(ctx context.Context, bucket, key string, sqsMeta events.MessageMetadata) error {
		handlerStart := time.Now().UTC()

		rootAttrs := []attribute.KeyValue{
			attribute.String("iota.pipeline.mode", "sqs"),
			attribute.String("s3.bucket", bucket),
			attribute.String("s3.key", key),
		}
		rootAttrs = append(rootAttrs, spanAttrsSQSMessage(queueURL, sqsMeta)...)
		op, ctx := telemetry.StartOperation(ctx, "process_s3_object", rootAttrs...)

		accountID, eventRegion, err := events.ExtractAccountRegionFromKey(key)
		if err != nil {
			log.Printf("warning: failed to parse s3 key, skipping state check: %v", err)
			accountID = "unknown"
			eventRegion = "unknown"
		}
		op.SetAttributes(
			attribute.String("aws.account_id", accountID),
			attribute.String("aws.region", eventRegion),
		)

		lastKey, err := stateDB.GetLastProcessedKey(bucket, accountID, eventRegion)
		if err != nil {
			log.Printf("warning: failed to get last processed key: %v", err)
		}

		if lastKey == key {
			log.Printf("skipping already processed s3 object: s3://%s/%s", bucket, key)
			metrics.RecordS3ObjectDownloaded("skipped", 0)
			op.SetAttributes(attribute.Bool("skipped", true))
			maybeLogLatencyTrace(bucket, key, sqsMeta, nil, handlerStart, nil, "skipped_duplicate")
			op.End(nil)
			return nil
		}

		log.Printf("processing s3 object: s3://%s/%s", bucket, key)

		downloadCtx, downloadSpan := telemetry.StartSpan(ctx, "s3.GetObject",
			trace.WithAttributes(
				attribute.String("s3.bucket", bucket),
				attribute.String("s3.key", key),
			),
		)
		result, err := s3Client.GetObject(downloadCtx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			telemetry.RecordError(downloadCtx, err)
			downloadSpan.End()
			metrics.RecordS3ObjectDownloaded("failure", 0)
			metrics.RecordProcessingError("s3", "get_object")
			op.End(err)
			return fmt.Errorf("get object: %w", err)
		}
		if result.ContentLength != nil {
			downloadSpan.SetAttributes(attribute.Int64("s3.object.size_bytes", *result.ContentLength))
		}
		downloadSpan.End()

		var s3LastModified *time.Time
		if result.LastModified != nil {
			t := result.LastModified.UTC()
			s3LastModified = &t
		}

		var downloadedBytes int64
		if result.ContentLength != nil {
			downloadedBytes = *result.ContentLength
		}
		metrics.RecordS3ObjectDownloaded("success", downloadedBytes)

		procReader, closeBody, err := openS3ObjectBody(result.Body, key, result.ContentEncoding)
		if err != nil {
			metrics.RecordProcessingError("s3", "open_body")
			op.End(err)
			return fmt.Errorf("open object body: %w", err)
		}
		defer closeBody()

		procStart := time.Now()
		processCtx, processSpan := telemetry.StartSpan(ctx, "logprocessor.Process",
			trace.WithAttributes(
				attribute.String("s3.bucket", bucket),
				attribute.String("s3.key", key),
			),
		)
		processedEvents, errs := processor.Process(processCtx, procReader)

		var batch []*cloudtrail.Event
		var procEvents []*logprocessor.ProcessedEvent
		for event := range processedEvents {
			if dataLakeWriter != nil {
				if err := dataLakeWriter.WriteEvent(ctx, event); err != nil {
					log.Printf("error writing to data lake: %v", err)
					metrics.RecordProcessingError("datalake", "write")
				}
			}

			procEvents = append(procEvents, event)
			batch = append(batch, event.Event)
		}

		if err := <-errs; err != nil {
			telemetry.RecordError(processCtx, err)
			processSpan.End()
			metrics.RecordProcessingError("logprocessor", "parse")
			op.End(err)
			return fmt.Errorf("process events: %w", err)
		}
		processSpan.SetAttributes(attribute.Int("events.count", len(batch)))
		processSpan.End()

		op.SetAttributes(attribute.Int("events.count", len(batch)))

		if len(batch) == 0 {
			if accountID != "unknown" && eventRegion != "unknown" {
				if err := stateDB.UpdateLastProcessedKey(bucket, accountID, eventRegion, key); err != nil {
					log.Printf("warning: failed to update state: %v", err)
				}
			}
			maybeLogLatencyTrace(bucket, key, sqsMeta, s3LastModified, handlerStart, batch, "parsed_empty")
			op.End(nil)
			return nil
		}

		logTypes := make([]string, 0, len(procEvents))
		for _, pe := range procEvents {
			logTypes = append(logTypes, pe.LogType)
		}

		analyzeCtx, analyzeSpan := telemetry.StartSpan(ctx, "engine.Analyze",
			trace.WithAttributes(
				attribute.String("s3.bucket", bucket),
				attribute.String("s3.key", key),
				attribute.Int("events.count", len(batch)),
			),
		)
		matches, err := eng.Analyze(analyzeCtx, batch, logTypes)
		if err != nil {
			telemetry.RecordError(analyzeCtx, err)
		}
		analyzeSpan.End()
		if err != nil {
			metrics.RecordProcessingError("engine", "analyze")
			op.End(err)
			return fmt.Errorf("analyze: %w", err)
		}

		logDetectionMatches(matches)

		pipelineDur := time.Since(procStart)
		perEvent := pipelineDur
		if len(procEvents) > 0 {
			perEvent = pipelineDur / time.Duration(len(procEvents))
		}
		for _, pe := range procEvents {
			metrics.RecordEventProcessed(pe.LogType, "ok", perEvent)
		}

		op.SetAttributes(attribute.Int("matches.count", len(matches)))

		for _, match := range matches {
			if err := forwarder.ProcessMatch(ctx, match, 60); err != nil {
				log.Printf("error processing match: %v", err)
			}
		}

		if accountID != "unknown" && eventRegion != "unknown" {
			if err := stateDB.UpdateLastProcessedKey(bucket, accountID, eventRegion, key); err != nil {
				log.Printf("warning: failed to update state: %v", err)
			}
		}

		log.Printf("processed %d events, %d matches", len(batch), len(matches))
		maybeLogLatencyTrace(bucket, key, sqsMeta, s3LastModified, handlerStart, batch, "ok")
		op.End(nil)
		return nil
	}

	maxMsgs, waitSec := sqsReceiveConfigFromEnv()
	procConc := sqsProcessConcurrencyFromEnv()
	sqsProcessor := events.NewSQSProcessor(sqsClient, events.Config{
		QueueURL:             queueURL,
		Handler:              handler,
		MaxMessages:          maxMsgs,
		WaitTime:             waitSec,
		ProcessConcurrency:   procConc,
		ObjectConcurrency:    downloadWorkers,
	})
	log.Printf("SQS processor: maxMessages=%d waitTimeSeconds=%d processConcurrency=%d objectConcurrency=%d (download-workers)", maxMsgs, waitSec, procConc, downloadWorkers)

	log.Println("SQS processor started, press ctrl+c to stop")
	return sqsProcessor.Process(ctx)
}

func latencyTraceEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("IOTA_LATENCY_TRACE")))
	return v == "1" || v == "true" || v == "yes"
}

func formatTimePtr(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// maybeLogLatencyTrace logs one line with S3 LastModified, SQS system attributes, and CloudTrail
// eventTime range when IOTA_LATENCY_TRACE is set. Used to split delay into AWS delivery vs iota work.
func maybeLogLatencyTrace(bucket, key string, sqsMeta events.MessageMetadata, s3LastModified *time.Time, handlerStart time.Time, batch []*cloudtrail.Event, stage string) {
	if !latencyTraceEnabled() {
		return
	}
	done := time.Now().UTC()
	evMin, evMax := "-", "-"
	if len(batch) > 0 {
		minT := batch[0].EventTime
		maxT := batch[0].EventTime
		for _, e := range batch[1:] {
			if e.EventTime.Before(minT) {
				minT = e.EventTime
			}
			if e.EventTime.After(maxT) {
				maxT = e.EventTime
			}
		}
		evMin = minT.UTC().Format(time.RFC3339Nano)
		evMax = maxT.UTC().Format(time.RFC3339Nano)
	}
	log.Printf(
		"latency_trace stage=%s s3_uri=s3://%s/%s s3_last_modified=%s sqs_message_id=%s sqs_sent_timestamp=%s sqs_approx_first_receive_timestamp=%s sqs_receive_count=%d event_time_min=%s event_time_max=%s iota_handler_start=%s iota_handler_done=%s iota_handler_seconds=%.3f",
		stage,
		bucket, key,
		formatTimePtr(s3LastModified),
		sqsMeta.MessageID,
		formatTimePtr(sqsMeta.SentTimestamp),
		formatTimePtr(sqsMeta.ApproximateFirstReceiveTimestamp),
		sqsMeta.ApproximateReceiveCount,
		evMin,
		evMax,
		handlerStart.Format(time.RFC3339Nano),
		done.Format(time.RFC3339Nano),
		done.Sub(handlerStart).Seconds(),
	)
}
