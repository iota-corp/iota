package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	EventsProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iota_events_processed_total",
			Help: "Total number of events processed",
		},
		[]string{"log_type", "status"},
	)

	EventsProcessedDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iota_events_processed_duration_seconds",
			Help:    "Time taken to process events",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
		},
		[]string{"log_type"},
	)

	RulesEvaluatedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iota_rules_evaluated_total",
			Help: "Total number of rules evaluated",
		},
		[]string{"rule_id", "result"},
	)

	AlertsGeneratedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iota_alerts_generated_total",
			Help: "Total number of alerts generated",
		},
		[]string{"severity", "rule_id"},
	)

	AlertsForwardedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iota_alerts_forwarded_total",
			Help: "Total number of alerts forwarded to outputs",
		},
		[]string{"output_type", "status"},
	)

	SQSMessagesProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iota_sqs_messages_processed_total",
			Help: "Total number of SQS messages processed",
		},
		[]string{"status"},
	)

	S3ObjectsDownloadedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iota_s3_objects_downloaded_total",
			Help: "Total number of S3 objects downloaded",
		},
		[]string{"status"},
	)

	S3ObjectsDownloadedBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iota_s3_objects_downloaded_bytes_total",
			Help: "Total bytes downloaded from S3",
		},
		[]string{"status"},
	)

	DataLakeWritesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iota_datalake_writes_total",
			Help: "Total number of data lake writes",
		},
		[]string{"log_type", "status"},
	)

	DataLakeWritesBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iota_datalake_writes_bytes_total",
			Help: "Total bytes written to data lake",
		},
		[]string{"log_type"},
	)

	ProcessingErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iota_processing_errors_total",
			Help: "Total number of processing errors",
		},
		[]string{"component", "error_type"},
	)

	StateDBOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iota_statedb_operations_total",
			Help: "Total number of state database operations",
		},
		[]string{"operation", "status"},
	)

	StateDBOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iota_statedb_operation_duration_seconds",
			Help:    "Latency of SQLite state/dedup operations",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 18),
		},
		[]string{"operation"},
	)
)

func RecordEventProcessed(logType, status string, duration time.Duration) {
	EventsProcessedTotal.WithLabelValues(logType, status).Inc()
	EventsProcessedDuration.WithLabelValues(logType).Observe(duration.Seconds())
}

func RecordRuleEvaluated(ruleID, result string) {
	RulesEvaluatedTotal.WithLabelValues(ruleID, result).Inc()
}

// RecordRuleEvaluatedCount increments rule evaluation counters by n (aggregated per engine batch).
func RecordRuleEvaluatedCount(ruleID, result string, n float64) {
	if n <= 0 {
		return
	}
	RulesEvaluatedTotal.WithLabelValues(ruleID, result).Add(n)
}

func RecordAlertGenerated(severity, ruleID string) {
	AlertsGeneratedTotal.WithLabelValues(severity, ruleID).Inc()
}

func RecordAlertForwarded(outputType, status string) {
	AlertsForwardedTotal.WithLabelValues(outputType, status).Inc()
}

func RecordSQSMessageProcessed(status string) {
	SQSMessagesProcessedTotal.WithLabelValues(status).Inc()
}

func RecordS3ObjectDownloaded(status string, bytes int64) {
	S3ObjectsDownloadedTotal.WithLabelValues(status).Inc()
	S3ObjectsDownloadedBytes.WithLabelValues(status).Add(float64(bytes))
}

func RecordDataLakeWrite(logType, status string, bytes int64) {
	DataLakeWritesTotal.WithLabelValues(logType, status).Inc()
	DataLakeWritesBytes.WithLabelValues(logType).Add(float64(bytes))
}

func RecordProcessingError(component, errorType string) {
	ProcessingErrorsTotal.WithLabelValues(component, errorType).Inc()
}

func RecordStateDBOperation(operation, status string) {
	StateDBOperationsTotal.WithLabelValues(operation, status).Inc()
}

// ObserveStateDBOperation records latency for a single state/dedup operation (e.g. update_alert_info).
func ObserveStateDBOperation(operation string, d time.Duration) {
	StateDBOperationDuration.WithLabelValues(operation).Observe(d.Seconds())
}

func Handler() http.Handler {
	return promhttp.Handler()
}
