package telemetry

import (
	"testing"
)

func TestConfigFromEnvSampleRate(t *testing.T) {
	t.Setenv("OTEL_ENABLED", "false")
	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "")
	t.Setenv("IOTA_OTEL_TRACE_SAMPLE_RATIO", "")
	cfg := ConfigFromEnv()
	if cfg.SampleRate != 1.0 {
		t.Fatalf("default sample rate: got %v want 1", cfg.SampleRate)
	}

	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "0.25")
	cfg = ConfigFromEnv()
	if cfg.SampleRate != 0.25 {
		t.Fatalf("OTEL_TRACES_SAMPLER_ARG: got %v want 0.25", cfg.SampleRate)
	}

	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "")
	t.Setenv("IOTA_OTEL_TRACE_SAMPLE_RATIO", "0.5")
	cfg = ConfigFromEnv()
	if cfg.SampleRate != 0.5 {
		t.Fatalf("IOTA_OTEL_TRACE_SAMPLE_RATIO: got %v want 0.5", cfg.SampleRate)
	}

	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "0.1")
	t.Setenv("IOTA_OTEL_TRACE_SAMPLE_RATIO", "0.9")
	cfg = ConfigFromEnv()
	if cfg.SampleRate != 0.1 {
		t.Fatalf("OTEL_TRACES_SAMPLER_ARG should win: got %v want 0.1", cfg.SampleRate)
	}
}
