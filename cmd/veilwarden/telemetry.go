package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

const serviceName = "veilwarden"

type telemetryConfig struct {
	enabled bool
	logger  *slog.Logger
}

type telemetryShutdown func(context.Context) error

// initTelemetry initializes OpenTelemetry tracing and metrics
func initTelemetry(ctx context.Context, cfg telemetryConfig) (telemetryShutdown, error) {
	if !cfg.enabled {
		// Return no-op shutdown function
		return func(context.Context) error { return nil }, nil
	}

	var shutdownFuncs []func(context.Context) error

	// Create resource with service information
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion("0.1.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Initialize tracing
	tracerProvider, err := initTracer(res)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize tracer: %w", err)
	}
	shutdownFuncs = append(shutdownFuncs, tracerProvider.Shutdown)
	otel.SetTracerProvider(tracerProvider)

	// Initialize metrics
	meterProvider, err := initMeter(ctx, res)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize meter: %w", err)
	}
	shutdownFuncs = append(shutdownFuncs, meterProvider.Shutdown)
	otel.SetMeterProvider(meterProvider)

	cfg.logger.Info("OpenTelemetry initialized", "service", serviceName)

	// Return combined shutdown function
	return func(ctx context.Context) error {
		var err error
		for _, fn := range shutdownFuncs {
			if shutdownErr := fn(ctx); shutdownErr != nil {
				err = shutdownErr
			}
		}
		return err
	}, nil
}

func initTracer(res *resource.Resource) (*trace.TracerProvider, error) {
	// Use stdout exporter for development/debugging
	exporter, err := stdouttrace.New(
		stdouttrace.WithPrettyPrint(),
		stdouttrace.WithWriter(io.Discard), // Suppress trace output to avoid noise
	)
	if err != nil {
		return nil, err
	}

	traceProvider := trace.NewTracerProvider(
		trace.WithResource(res),
		trace.WithBatcher(exporter),
		trace.WithSampler(trace.AlwaysSample()),
	)

	return traceProvider, nil
}

func initMeter(ctx context.Context, res *resource.Resource) (*metric.MeterProvider, error) {
	// Use stdout exporter for development/debugging
	exporter, err := stdoutmetric.New(
		stdoutmetric.WithPrettyPrint(),
		stdoutmetric.WithWriter(io.Discard), // Suppress metric output to avoid noise
	)
	if err != nil {
		return nil, err
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(exporter)),
	)

	return meterProvider, nil
}
