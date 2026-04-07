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
			body.Close()
			return nil, nil, fmt.Errorf("gzip reader: %w", err)
		}
		return gz, func() { gz.Close() }, nil
	}
	return body, func() { body.Close() }, nil
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

func runSQS(ctx context.Context, queueURL, s3Bucket, region, rulesDir, python, enginePy, stateFile, dataLakeBucket, bloomFile string, bloomExpectedItems uint64, bloomFalsePositive float64, downloadWorkers, processWorkers int, glueDatabase, athenaWorkgroup, athenaResultBucket string, slackClient *alerts.SlackClient) error {
	log.Printf("starting SQS processor: queue=%s", queueURL)

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
	defer stateDB.Close()

	eng := engine.New(python, enginePy, rulesDir)

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

	dedup, err := deduplication.New(stateFile)
	if err != nil {
		return fmt.Errorf("create deduplicator: %w", err)
	}
	defer dedup.Close()

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
		defer dataLakeWriter.Flush(ctx)
	}

	handler := func(ctx context.Context, bucket, key string) error {
		op, ctx := telemetry.StartOperation(ctx, "process_s3_object",
			attribute.String("s3.bucket", bucket),
			attribute.String("s3.key", key),
		)

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
			op.End(nil)
			return nil
		}

		log.Printf("processing s3 object: s3://%s/%s", bucket, key)

		downloadCtx, downloadSpan := telemetry.StartSpan(ctx, "s3.GetObject")
		result, err := s3Client.GetObject(downloadCtx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		downloadSpan.End()
		if err != nil {
			metrics.RecordS3ObjectDownloaded("failure", 0)
			metrics.RecordProcessingError("s3", "get_object")
			op.End(err)
			return fmt.Errorf("get object: %w", err)
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
		processCtx, processSpan := telemetry.StartSpan(ctx, "logprocessor.Process")
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
			processSpan.End()
			metrics.RecordProcessingError("logprocessor", "parse")
			op.End(err)
			return fmt.Errorf("process events: %w", err)
		}
		processSpan.End()

		op.SetAttributes(attribute.Int("events.count", len(batch)))

		if len(batch) == 0 {
			if accountID != "unknown" && eventRegion != "unknown" {
				if err := stateDB.UpdateLastProcessedKey(bucket, accountID, eventRegion, key); err != nil {
					log.Printf("warning: failed to update state: %v", err)
				}
			}
			op.End(nil)
			return nil
		}

		analyzeCtx, analyzeSpan := telemetry.StartSpan(ctx, "engine.Analyze")
		analyzeSpan.SetAttributes(attribute.Int("events.count", len(batch)))
		matches, err := eng.Analyze(analyzeCtx, batch)
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
		op.End(nil)
		return nil
	}

	maxMsgs, waitSec := sqsReceiveConfigFromEnv()
	sqsProcessor := events.NewSQSProcessor(sqsClient, events.Config{
		QueueURL:    queueURL,
		Handler:     handler,
		MaxMessages: maxMsgs,
		WaitTime:    waitSec,
	})
	log.Printf("SQS processor: maxMessages=%d waitTimeSeconds=%d", maxMsgs, waitSec)

	log.Println("SQS processor started, press ctrl+c to stop")
	return sqsProcessor.Process(ctx)
}
