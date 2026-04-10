package reader

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/bilals12/iota/pkg/cloudtrail"
)

type Reader struct {
	maxLineSize int
}

func New() *Reader {
	return &Reader{
		maxLineSize: 1024 * 1024,
	}
}

func (r *Reader) ReadFile(ctx context.Context, path string) (<-chan *cloudtrail.Event, <-chan error) {
	events := make(chan *cloudtrail.Event, 100)
	errs := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errs)

		f, err := os.Open(path)
		if err != nil {
			errs <- fmt.Errorf("open file: %w", err)
			return
		}
		defer func() { _ = f.Close() }()

		if err := r.read(ctx, f, events); err != nil {
			errs <- err
		}
	}()

	return events, errs
}

func (r *Reader) Read(ctx context.Context, reader io.Reader) (<-chan *cloudtrail.Event, <-chan error) {
	events := make(chan *cloudtrail.Event, 100)
	errs := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errs)

		if err := r.read(ctx, reader, events); err != nil {
			errs <- err
		}
	}()

	return events, errs
}

func (r *Reader) read(ctx context.Context, reader io.Reader, events chan<- *cloudtrail.Event) error {
	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, r.maxLineSize)
	scanner.Buffer(buf, r.maxLineSize)

	lineNum := 0
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		lineNum++
		line := scanner.Bytes()

		if len(line) == 0 {
			continue
		}

		var event cloudtrail.Event
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}

		events <- &event
	}

	return scanner.Err()
}
