// Package tracing initialises the OpenTelemetry tracer for 5GC NFs.
// Call Init at startup and Shutdown on exit. After Init, the global
// tracer is set and any code using otel.Tracer() will emit spans to Jaeger.
package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
	"go.opentelemetry.io/otel/trace"
)

// Provider wraps the SDK TracerProvider so callers can Shutdown cleanly.
type Provider struct {
	tp *sdktrace.TracerProvider
}

// Init creates and registers a global TracerProvider that exports spans to
// the OTLP HTTP endpoint at otlpEndpoint (e.g. "http://jaeger:4318").
// serviceName identifies this NF in Jaeger (e.g. "AMF", "AUSF").
// Returns a Provider whose Shutdown must be deferred by the caller.
func Init(ctx context.Context, serviceName, otlpEndpoint string) (*Provider, error) {
	exp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(otlpEndpoint+"/v1/traces"),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: create OTLP exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String("rel17"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: create resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &Provider{tp: tp}, nil
}

// Shutdown flushes pending spans and stops the exporter.
func (p *Provider) Shutdown(ctx context.Context) error {
	return p.tp.Shutdown(ctx)
}

// Tracer returns a named tracer from the global provider.
// nf should match the NF name (e.g. "AMF"). op is the instrumentation scope
// (e.g. "procedures", "nas", "ngap").
func Tracer(nf, op string) trace.Tracer {
	return otel.Tracer(fmt.Sprintf("5gc/%s/%s", nf, op))
}
