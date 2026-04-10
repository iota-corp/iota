package s3poller

import (
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	_ "github.com/mattn/go-sqlite3"
)

type S3Poller struct {
	client   *s3.Client
	bucket   string
	prefix   string
	db       *sql.DB
	handler  func(io.Reader) error
	interval time.Duration
	region   string
}

type Config struct {
	Bucket    string
	Prefix    string
	StateFile string
	Handler   func(io.Reader) error
	Interval  time.Duration
	Region    string
}

func New(ctx context.Context, cfg Config) (*S3Poller, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg)

	db, err := sql.Open("sqlite3", cfg.StateFile)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}

	if err := initDB(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init db: %w", err)
	}

	return &S3Poller{
		client:   client,
		bucket:   cfg.Bucket,
		prefix:   cfg.Prefix,
		db:       db,
		handler:  cfg.Handler,
		interval: cfg.Interval,
		region:   cfg.Region,
	}, nil
}

func initDB(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS processed_s3_objects (
			key TEXT PRIMARY KEY,
			etag TEXT,
			processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	return err
}

func (p *S3Poller) Poll(ctx context.Context) error {
	log.Printf("starting S3 poller: bucket=%s prefix=%s interval=%v", p.bucket, p.prefix, p.interval)

	if err := p.pollOnce(ctx); err != nil {
		log.Printf("error in initial poll: %v", err)
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := p.pollOnce(ctx); err != nil {
				log.Printf("error polling S3: %v", err)
			}
		}
	}
}

func (p *S3Poller) pollOnce(ctx context.Context) error {
	log.Printf("polling S3 bucket: %s/%s", p.bucket, p.prefix)

	var continuationToken *string
	objectCount := 0
	processedCount := 0

	for {
		input := &s3.ListObjectsV2Input{
			Bucket:            aws.String(p.bucket),
			Prefix:            aws.String(p.prefix),
			ContinuationToken: continuationToken,
			MaxKeys:           aws.Int32(1000),
		}

		result, err := p.client.ListObjectsV2(ctx, input)
		if err != nil {
			return fmt.Errorf("list objects: %w", err)
		}

		for _, obj := range result.Contents {
			objectCount++

			if !strings.HasSuffix(*obj.Key, ".json.gz") {
				continue
			}

			processed, err := p.isProcessed(*obj.Key, *obj.ETag)
			if err != nil {
				log.Printf("error checking if processed %s: %v", *obj.Key, err)
				continue
			}
			if processed {
				continue
			}

			if err := p.processObject(ctx, *obj.Key, *obj.ETag); err != nil {
				log.Printf("error processing %s: %v", *obj.Key, err)
				continue
			}

			processedCount++
		}

		if result.IsTruncated == nil || !*result.IsTruncated {
			break
		}
		continuationToken = result.NextContinuationToken
	}

	log.Printf("poll complete: checked %d objects, processed %d new files", objectCount, processedCount)
	return nil
}

func (p *S3Poller) processObject(ctx context.Context, key string, etag string) error {
	log.Printf("downloading and processing: %s", key)

	getInput := &s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(key),
	}

	result, err := p.client.GetObject(ctx, getInput)
	if err != nil {
		return fmt.Errorf("get object: %w", err)
	}
	defer func() { _ = result.Body.Close() }()

	gzReader, err := gzip.NewReader(result.Body)
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer func() { _ = gzReader.Close() }()

	if err := p.handler(gzReader); err != nil {
		return fmt.Errorf("handler: %w", err)
	}

	if err := p.markProcessed(key, etag); err != nil {
		return fmt.Errorf("mark processed: %w", err)
	}

	return nil
}

func (p *S3Poller) isProcessed(key string, etag string) (bool, error) {
	var storedEtag string
	err := p.db.QueryRow("SELECT etag FROM processed_s3_objects WHERE key = ?", key).Scan(&storedEtag)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return storedEtag == etag, nil
}

func (p *S3Poller) markProcessed(key string, etag string) error {
	_, err := p.db.Exec("INSERT OR REPLACE INTO processed_s3_objects (key, etag) VALUES (?, ?)", key, etag)
	return err
}

func (p *S3Poller) Close() error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}
