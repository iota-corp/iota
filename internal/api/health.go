package api

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/bilals12/iota/internal/metrics"
)

type HealthServer struct {
	server    *http.Server
	readiness ReadinessChecker
	metrics   bool
}

type ReadinessChecker interface {
	Check(ctx context.Context) error
}

type DBReadinessChecker struct {
	db *sql.DB
}

func NewDBReadinessChecker(db *sql.DB) *DBReadinessChecker {
	return &DBReadinessChecker{db: db}
}

func (c *DBReadinessChecker) Check(ctx context.Context) error {
	return c.db.PingContext(ctx)
}

func NewHealthServer(port string) *HealthServer {
	return NewHealthServerWithReadiness(port, nil, false)
}

func NewHealthServerWithReadiness(port string, readiness ReadinessChecker, enableMetrics bool) *HealthServer {
	mux := http.NewServeMux()
	server := &HealthServer{
		server: &http.Server{
			Addr:         ":" + port,
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		readiness: readiness,
		metrics:   enableMetrics,
	}

	mux.HandleFunc("/health", server.healthHandler)
	mux.HandleFunc("/ready", server.readyHandler)
	if enableMetrics {
		mux.Handle("/metrics", metrics.Handler())
	}

	return server
}

func (s *HealthServer) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
	}()

	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("health server: %w", err)
	}
	return nil
}

func (s *HealthServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func (s *HealthServer) readyHandler(w http.ResponseWriter, r *http.Request) {
	if s.readiness != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := s.readiness.Check(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, "NOT READY: %v", err)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("READY"))
}
