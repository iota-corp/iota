package telemetry

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	ServiceName    = "iota"
	ServiceVersion = "0.1.0"
)

var tracer trace.Tracer

type Config struct {
	Enabled     bool
	Endpoint    string
	ServiceName string
	Environment string
	SampleRate  float64
}

func ConfigFromEnv() Config {
	cfg := Config{
		Enabled:     os.Getenv("OTEL_ENABLED") == "true",
		Endpoint:    os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		ServiceName: os.Getenv("OTEL_SERVICE_NAME"),
		Environment: os.Getenv("OTEL_ENVIRONMENT"),
		SampleRate:  1.0,
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = ServiceName
	}
	if cfg.Environment == "" {
		cfg.Environment = "development"
	}
	cfg.SampleRate = parseTraceSampleRatio()
	return cfg
}

// parseTraceSampleRatio returns a ratio in [0,1] for trace sampling (default 1).
// Precedence: OTEL_TRACES_SAMPLER_ARG (OpenTelemetry standard, e.g. parentbased_traceidratio uses the arg),
// then IOTA_OTEL_TRACE_SAMPLE_RATIO.
func parseTraceSampleRatio() float64 {
	for _, key := range []string{"OTEL_TRACES_SAMPLER_ARG", "IOTA_OTEL_TRACE_SAMPLE_RATIO"} {
		v := strings.TrimSpace(os.Getenv(key))
		if v == "" {
			continue
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			continue
		}
		if f < 0 {
			return 0
		}
		if f > 1 {
			return 1
		}
		return f
	}
	return 1.0
}

func Init(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	if !cfg.Enabled {
		tracer = otel.Tracer(cfg.ServiceName)
		return func(context.Context) error { return nil }, nil
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(ServiceVersion),
			attribute.String("environment", cfg.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create resource: %w", err)
	}

	opts := []otlptracegrpc.Option{}
	if cfg.Endpoint != "" {
		opts = append(opts, otlptracegrpc.WithEndpoint(cfg.Endpoint))
	}
	if os.Getenv("OTEL_EXPORTER_OTLP_INSECURE") == "true" {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create exporter: %w", err)
	}

	var sampler sdktrace.Sampler
	switch {
	case cfg.SampleRate >= 1.0:
		sampler = sdktrace.AlwaysSample()
	case cfg.SampleRate <= 0:
		sampler = sdktrace.NeverSample()
	default:
		sampler = sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRate))
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer = tp.Tracer(cfg.ServiceName)

	return tp.Shutdown, nil
}

func Tracer() trace.Tracer {
	if tracer == nil {
		tracer = otel.Tracer(ServiceName)
	}
	return tracer
}

func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return Tracer().Start(ctx, name, opts...)
}

func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// TraceIDsForLog returns W3C trace and span IDs as hex strings for log correlation (e.g. SigNoz).
// Returns empty strings when the context has no valid span (OTEL disabled, not sampled, or no span).
func TraceIDsForLog(ctx context.Context) (traceID, spanID string) {
	sc := trace.SpanFromContext(ctx).SpanContext()
	if !sc.IsValid() {
		return "", ""
	}
	return sc.TraceID().String(), sc.SpanID().String()
}

func RecordError(ctx context.Context, err error) {
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.RecordError(err)
	}
}

func SetAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.SetAttributes(attrs...)
	}
}

func AddEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.AddEvent(name, trace.WithAttributes(attrs...))
	}
}

type TimedOperation struct {
	ctx       context.Context
	span      trace.Span
	startTime time.Time
}

func StartOperation(ctx context.Context, name string, attrs ...attribute.KeyValue) (*TimedOperation, context.Context) {
	ctx, span := StartSpan(ctx, name, trace.WithAttributes(attrs...))
	return &TimedOperation{
		ctx:       ctx,
		span:      span,
		startTime: time.Now(),
	}, ctx
}

func (t *TimedOperation) End(err error) {
	if err != nil {
		t.span.RecordError(err)
	}
	t.span.SetAttributes(
		attribute.Int64("duration_ms", time.Since(t.startTime).Milliseconds()),
	)
	t.span.End()
}

func (t *TimedOperation) SetAttributes(attrs ...attribute.KeyValue) {
	t.span.SetAttributes(attrs...)
}
