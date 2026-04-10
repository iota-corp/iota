package bloom

import (
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/bits-and-blooms/bloom/v3"
)

type Filter struct {
	mu     sync.RWMutex
	filter *bloom.BloomFilter
	path   string
}

func Load(path string, expectedItems uint, falsePositiveRate float64) (*Filter, error) {
	file, err := os.Open(path)
	if err == nil {
		defer func() { _ = file.Close() }()
		bf := bloom.NewWithEstimates(expectedItems, falsePositiveRate)
		if _, err := bf.ReadFrom(file); err != nil {
			log.Printf("failed to read bloom filter, creating new one: %v", err)
			return &Filter{
				filter: bloom.NewWithEstimates(expectedItems, falsePositiveRate),
				path:   path,
			}, nil
		}
		log.Printf("loaded bloom filter from disk: %s", path)
		return &Filter{
			filter: bf,
			path:   path,
		}, nil
	}

	log.Printf("creating new bloom filter: capacity=%d, false_positive_rate=%.2f%%", expectedItems, falsePositiveRate*100)

	return &Filter{
		filter: bloom.NewWithEstimates(expectedItems, falsePositiveRate),
		path:   path,
	}, nil
}

func (f *Filter) Test(data []byte) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.filter.Test(data)
}

func (f *Filter) Add(data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.filter.Add(data)
}

func (f *Filter) Save() error {
	tmpFile := f.path + ".tmp"
	file, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() { _ = file.Close() }()

	f.mu.RLock()
	_, err = f.filter.WriteTo(file)
	f.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("write bloom filter: %w", err)
	}

	if err := os.Rename(tmpFile, f.path); err != nil {
		return fmt.Errorf("rename bloom filter: %w", err)
	}

	return nil
}
