package datalake

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/bilals12/iota/internal/logprocessor"
)

type Writer struct {
	s3Client    *s3.Client
	bucket      string
	buffer      *EventBuffer
	maxSize     int
	maxAge      time.Duration
	glueCatalog interface {
		EnsureDatabase(ctx context.Context) error
		CreateTable(ctx context.Context, logType string) error
		AddPartition(ctx context.Context, logType string, year, month, day, hour int) error
	}
	seenLogTypes map[string]bool
}

type EventBuffer struct {
	bytes     []byte
	events    int
	createdAt time.Time
	logType   string
	hour      time.Time
}

func New(s3Client *s3.Client, bucket string, maxSize int, maxAge time.Duration) *Writer {
	return &Writer{
		s3Client:     s3Client,
		bucket:       bucket,
		maxSize:      maxSize,
		maxAge:       maxAge,
		buffer:       nil,
		seenLogTypes: make(map[string]bool),
	}
}

func NewWithGlue(s3Client *s3.Client, bucket string, maxSize int, maxAge time.Duration, glueCatalog interface {
	EnsureDatabase(ctx context.Context) error
	CreateTable(ctx context.Context, logType string) error
	AddPartition(ctx context.Context, logType string, year, month, day, hour int) error
}) *Writer {
	return &Writer{
		s3Client:     s3Client,
		bucket:       bucket,
		maxSize:      maxSize,
		maxAge:       maxAge,
		buffer:       nil,
		glueCatalog:  glueCatalog,
		seenLogTypes: make(map[string]bool),
	}
}

func (w *Writer) WriteEvent(ctx context.Context, event *logprocessor.ProcessedEvent) error {
	if w.buffer == nil || w.buffer.logType != event.LogType || !sameHour(w.buffer.hour, event.EventTime) {
		if w.buffer != nil {
			if err := w.flushBuffer(ctx); err != nil {
				return fmt.Errorf("flush buffer: %w", err)
			}
		}

		if w.glueCatalog != nil && !w.seenLogTypes[event.LogType] {
			if err := w.glueCatalog.EnsureDatabase(ctx); err != nil {
				return fmt.Errorf("ensure database: %w", err)
			}
			if err := w.glueCatalog.CreateTable(ctx, event.LogType); err != nil {
				return fmt.Errorf("create table: %w", err)
			}
			w.seenLogTypes[event.LogType] = true
		}

		w.buffer = &EventBuffer{
			logType:   event.LogType,
			hour:      event.EventTime.Truncate(time.Hour),
			createdAt: time.Now(),
		}
	}

	eventJSON, err := json.Marshal(event.Event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	compressed, err := compressEvent(eventJSON)
	if err != nil {
		return fmt.Errorf("compress event: %w", err)
	}

	w.buffer.bytes = append(w.buffer.bytes, compressed...)
	w.buffer.events++

	if w.buffer.Size() > w.maxSize || time.Since(w.buffer.createdAt) > w.maxAge {
		return w.flushBuffer(ctx)
	}

	return nil
}

func (w *Writer) Flush(ctx context.Context) error {
	if w.buffer != nil {
		return w.flushBuffer(ctx)
	}
	return nil
}

func (w *Writer) flushBuffer(ctx context.Context) error {
	if w.buffer == nil || len(w.buffer.bytes) == 0 {
		return nil
	}

	key := w.generateS3Key(w.buffer)
	_, err := w.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(w.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(w.buffer.bytes),
		ContentType: aws.String("application/x-gzip"),
	})
	if err != nil {
		return fmt.Errorf("put object: %w", err)
	}

	if w.glueCatalog != nil {
		year := w.buffer.hour.Year()
		month := int(w.buffer.hour.Month())
		day := w.buffer.hour.Day()
		hour := w.buffer.hour.Hour()
		if err := w.glueCatalog.AddPartition(ctx, w.buffer.logType, year, month, day, hour); err != nil {
			return fmt.Errorf("add partition: %w", err)
		}
	}

	w.buffer = nil
	return nil
}

func (w *Writer) generateS3Key(buf *EventBuffer) string {
	table := getTableName(buf.logType)

	year := buf.hour.Year()
	month := int(buf.hour.Month())
	day := buf.hour.Day()
	hour := buf.hour.Hour()

	partitionPath := fmt.Sprintf("logs/%s/year=%d/month=%02d/day=%02d/hour=%02d", table, year, month, day, hour)
	filename := fmt.Sprintf("%s-%s.json.gz",
		buf.hour.Format("20060102T150405Z"),
		generateUUID(),
	)

	return filepath.Join(partitionPath, filename)
}

func (buf *EventBuffer) Size() int {
	return len(buf.bytes)
}

func compressEvent(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sameHour(t1, t2 time.Time) bool {
	return t1.Truncate(time.Hour).Equal(t2.Truncate(time.Hour))
}

func getTableName(logType string) string {
	return strings.ToLower(strings.ReplaceAll(logType, ".", "_"))
}

func generateUUID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
