package watcher

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	_ "github.com/mattn/go-sqlite3"
)

type Watcher struct {
	dir      string
	db       *sql.DB
	handler  func(string) error
	watcher  *fsnotify.Watcher
	debounce time.Duration
}

func New(dir string, stateFile string, handler func(string) error) (*Watcher, error) {
	db, err := sql.Open("sqlite3", stateFile)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}

	if err := initDB(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init db: %w", err)
	}

	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create fsnotify watcher: %w", err)
	}

	return &Watcher{
		dir:      dir,
		db:       db,
		handler:  handler,
		watcher:  fsWatcher,
		debounce: 2 * time.Second,
	}, nil
}

func initDB(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS processed_files (
			path TEXT PRIMARY KEY,
			processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	return err
}

func (w *Watcher) Watch(ctx context.Context) error {
	if err := w.addWatches(w.dir); err != nil {
		return fmt.Errorf("add watches: %w", err)
	}

	if err := w.processExisting(ctx); err != nil {
		return fmt.Errorf("process existing: %w", err)
	}

	debounceTimer := make(map[string]*time.Timer)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case event, ok := <-w.watcher.Events:
			if !ok {
				return nil
			}

			if event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Write == fsnotify.Write {
				if !isJSONL(event.Name) {
					continue
				}

				if timer, exists := debounceTimer[event.Name]; exists {
					timer.Stop()
				}

				debounceTimer[event.Name] = time.AfterFunc(w.debounce, func() {
					if err := w.processFile(event.Name); err != nil {
						log.Printf("error processing %s: %v", event.Name, err)
					}
					delete(debounceTimer, event.Name)
				})
			}

			if event.Op&fsnotify.Create == fsnotify.Create {
				info, err := os.Stat(event.Name)
				if err == nil && info.IsDir() {
					if err := w.watcher.Add(event.Name); err != nil {
						log.Printf("error watching new directory %s: %v", event.Name, err)
					}
				}
			}

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return nil
			}
			log.Printf("watcher error: %v", err)
		}
	}
}

func (w *Watcher) addWatches(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return w.watcher.Add(path)
		}
		return nil
	})
}

func (w *Watcher) processExisting(ctx context.Context) error {
	return filepath.Walk(w.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if !info.IsDir() && isJSONL(path) {
			if err := w.processFile(path); err != nil {
				log.Printf("error processing existing file %s: %v", path, err)
			}
		}
		return nil
	})
}

func (w *Watcher) processFile(path string) error {
	processed, err := w.isProcessed(path)
	if err != nil {
		return fmt.Errorf("check processed: %w", err)
	}
	if processed {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}
	if info.Size() == 0 {
		return nil
	}

	log.Printf("processing file: %s", path)
	if err := w.handler(path); err != nil {
		return fmt.Errorf("handler: %w", err)
	}

	if err := w.markProcessed(path); err != nil {
		return fmt.Errorf("mark processed: %w", err)
	}

	return nil
}

func (w *Watcher) isProcessed(path string) (bool, error) {
	var count int
	err := w.db.QueryRow("SELECT COUNT(*) FROM processed_files WHERE path = ?", path).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (w *Watcher) markProcessed(path string) error {
	_, err := w.db.Exec("INSERT OR IGNORE INTO processed_files (path) VALUES (?)", path)
	return err
}

func (w *Watcher) Close() error {
	if w.watcher != nil {
		_ = w.watcher.Close()
	}
	if w.db != nil {
		return w.db.Close()
	}
	return nil
}

func isJSONL(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".jsonl" || ext == ".json"
}
