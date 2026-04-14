package main

import (
	"context"
	"fmt"
	"log"
	"time"

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
	"github.com/bilals12/iota/internal/telemetry"
	"github.com/bilals12/iota/pkg/cloudtrail"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func runEventBridge(ctx context.Context, queueURL, region, rulesDir, python, enginePy, stateFile, dataLakeBucket, bloomFile string, bloomExpectedItems uint64, bloomFalsePositive float64, glueDatabase, athenaWorkgroup, athenaResultBucket string, slackClient *alerts.SlackClient) error {
	log.Printf("starting EventBridge processor: queue=%s", queueURL)

	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}

	sqsClient := sqs.NewFromConfig(awsCfg)
	s3Client := s3.NewFromConfig(awsCfg)

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

	handler := func(ctx context.Context, eventJSON []byte, logType string, envelope *events.EventBridgeEnvelope) error {
		spanAttrs := []attribute.KeyValue{
			attribute.String("iota.pipeline.mode", "eventbridge"),
			attribute.String("log_type", logType),
			attribute.Int("event_json_size", len(eventJSON)),
		}
		spanAttrs = append(spanAttrs, spanAttrsSQSMessage(queueURL, events.MessageMetadata{})...)
		if envelope != nil {
			spanAttrs = append(spanAttrs,
				attribute.String("eventbridge.source", envelope.Source),
				attribute.String("eventbridge.detail_type", envelope.DetailType),
			)
		}
		op, ctx := telemetry.StartOperation(ctx, "process_eventbridge_event", spanAttrs...)

		eventBatches, err := events.ProcessBatchedEvents(eventJSON)
		if err != nil {
			op.End(err)
			return fmt.Errorf("process batched events: %w", err)
		}

		var allEvents []*cloudtrail.Event

		for _, eventData := range eventBatches {
			processed, err := processor.ProcessEvent(ctx, eventData, logType)
			if err != nil {
				log.Printf("warning: failed to process event: %v", err)
				continue
			}

			for _, pe := range processed {
				if dataLakeWriter != nil {
					if err := dataLakeWriter.WriteEvent(ctx, pe); err != nil {
						log.Printf("error writing to data lake: %v", err)
					}
				}
				allEvents = append(allEvents, pe.Event)
			}
		}

		op.SetAttributes(attribute.Int("events.count", len(allEvents)))

		if len(allEvents) == 0 {
			op.End(nil)
			return nil
		}

		analyzeCtx, analyzeSpan := telemetry.StartSpan(ctx, "engine.Analyze",
			trace.WithAttributes(attribute.Int("events.count", len(allEvents))),
		)
		matches, err := eng.Analyze(analyzeCtx, allEvents)
		if err != nil {
			telemetry.RecordError(analyzeCtx, err)
		}
		analyzeSpan.End()
		if err != nil {
			op.End(err)
			return fmt.Errorf("analyze: %w", err)
		}

		logDetectionMatches(matches)

		op.SetAttributes(attribute.Int("matches.count", len(matches)))

		for _, match := range matches {
			if err := forwarder.ProcessMatch(ctx, match, 60); err != nil {
				log.Printf("error processing match: %v", err)
			}
		}

		log.Printf("processed %d events, %d matches (source: %s)", len(allEvents), len(matches), logType)
		op.End(nil)
		return nil
	}

	maxMsgs, waitSec := sqsReceiveConfigFromEnv()
	ebProcessor := events.NewEventBridgeProcessor(sqsClient, events.EventBridgeConfig{
		QueueURL:    queueURL,
		Handler:     handler,
		MaxMessages: maxMsgs,
		WaitTime:    waitSec,
	})
	log.Printf("EventBridge processor: maxMessages=%d waitTimeSeconds=%d", maxMsgs, waitSec)

	log.Println("EventBridge processor started, press ctrl+c to stop")
	return ebProcessor.Process(ctx)
}
