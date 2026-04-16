package datalake

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/bilals12/iota/internal/lakepath"
	"github.com/bilals12/iota/internal/logprocessor"
	"github.com/bilals12/iota/internal/metrics"
)

type Writer struct {
	mu       sync.Mutex
	s3Client *s3.Client
	bucket   string
	buffer   *EventBuffer
	maxSize  int
	maxAge   time.Duration
	glueCatalog interface {
		EnsureDatabase(ctx context.Context) error
		CreateTable(ctx context.Context, logType string) error
		AddPartition(ctx context.Context, logType string, year, month, day, hour int) error
	}
	seenLogTypes map[string]bool

	async       bool
	flushCh     chan *EventBuffer
	flushWG     sync.WaitGroup
	flushClose  sync.Once
	flushClosed bool
}

type EventBuffer struct {
	bytes     []byte
	events    int
	createdAt time.Time
	logType   string
	hour      time.Time
}

func New(s3Client *s3.Client, bucket string, maxSize int, maxAge time.Duration) *Writer {
	w := &Writer{
		s3Client:     s3Client,
		bucket:       bucket,
		maxSize:      maxSize,
		maxAge:       maxAge,
		buffer:       nil,
		seenLogTypes: make(map[string]bool),
	}
	w.initAsyncFromEnv()
	return w
}

func NewWithGlue(s3Client *s3.Client, bucket string, maxSize int, maxAge time.Duration, glueCatalog interface {
	EnsureDatabase(ctx context.Context) error
	CreateTable(ctx context.Context, logType string) error
	AddPartition(ctx context.Context, logType string, year, month, day, hour int) error
}) *Writer {
	w := &Writer{
		s3Client:     s3Client,
		bucket:       bucket,
		maxSize:      maxSize,
		maxAge:       maxAge,
		buffer:       nil,
		glueCatalog:  glueCatalog,
		seenLogTypes: make(map[string]bool),
	}
	w.initAsyncFromEnv()
	return w
}

func (w *Writer) initAsyncFromEnv() {
	if os.Getenv("IOTA_DATALAKE_ASYNC_FLUSH") != "1" {
		return
	}
	depth := 4
	if s := os.Getenv("IOTA_DATALAKE_FLUSH_QUEUE_DEPTH"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= 64 {
			depth = n
		}
	}
	w.async = true
	w.flushCh = make(chan *EventBuffer, depth)
	w.flushWG.Add(1)
	go w.runFlushWorker()
}

func (w *Writer) runFlushWorker() {
	defer w.flushWG.Done()
	for buf := range w.flushCh {
		if buf == nil || len(buf.bytes) == 0 {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		err := w.putBuffer(ctx, buf)
		cancel()
		if err != nil {
			metrics.RecordProcessingError("datalake", "async_put")
		}
		metrics.SetDataLakeAsyncFlushQueueDepth(len(w.flushCh))
	}
}

func (w *Writer) WriteEvent(ctx context.Context, event *logprocessor.ProcessedEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.buffer == nil || w.buffer.logType != event.LogType || !sameHour(w.buffer.hour, event.EventTime) {
		if w.buffer != nil {
			if err := w.flushBufferLocked(ctx); err != nil {
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
		return w.flushBufferLocked(ctx)
	}

	return nil
}

func (w *Writer) Flush(ctx context.Context) error {
	w.mu.Lock()
	err := w.flushBufferLocked(ctx)
	async := w.async
	ch := w.flushCh
	w.mu.Unlock()

	if err != nil {
		return err
	}
	if async && ch != nil {
		w.drainAsyncFlush()
	}
	return nil
}

func (w *Writer) drainAsyncFlush() {
	w.flushClose.Do(func() {
		w.mu.Lock()
		ch := w.flushCh
		w.flushClosed = true
		w.mu.Unlock()
		if ch != nil {
			close(ch)
		}
	})
	w.flushWG.Wait()
}

func (w *Writer) flushBufferLocked(ctx context.Context) error {
	if w.buffer == nil || len(w.buffer.bytes) == 0 {
		return nil
	}
	buf := w.buffer
	w.buffer = nil

	if !w.async {
		return w.putBuffer(ctx, buf)
	}

	if w.flushClosed {
		return w.putBuffer(ctx, buf)
	}

	w.mu.Unlock()
	err := w.enqueueFlush(ctx, buf)
	w.mu.Lock()
	return err
}

func (w *Writer) enqueueFlush(ctx context.Context, buf *EventBuffer) error {
	select {
	case w.flushCh <- buf:
		metrics.SetDataLakeAsyncFlushQueueDepth(len(w.flushCh))
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *Writer) putBuffer(ctx context.Context, buf *EventBuffer) error {
	key := w.generateS3Key(buf)
	_, err := w.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(w.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(buf.bytes),
		ContentType: aws.String("application/x-gzip"),
	})
	if err != nil {
		metrics.RecordDataLakeWrite(buf.logType, "error", 0)
		return fmt.Errorf("put object: %w", err)
	}
	metrics.RecordDataLakeWrite(buf.logType, "success", int64(len(buf.bytes)))

	if w.glueCatalog != nil {
		year := buf.hour.Year()
		month := int(buf.hour.Month())
		day := buf.hour.Day()
		hour := buf.hour.Hour()
		if err := w.glueCatalog.AddPartition(ctx, buf.logType, year, month, day, hour); err != nil {
			metrics.RecordProcessingError("datalake", "glue_partition")
			return fmt.Errorf("add partition: %w", err)
		}
	}
	return nil
}

func (w *Writer) generateS3Key(buf *EventBuffer) string {
	filename := fmt.Sprintf("%s-%s.json.gz",
		buf.hour.Format("20060102T150405Z"),
		generateUUID(),
	)
	return lakepath.S3ObjectKey(buf.logType, buf.hour, filename)
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

func generateUUID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
