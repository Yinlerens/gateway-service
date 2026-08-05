package telemetry

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type traceLogHandler struct {
	slog.Handler
}

func NewJSONLogger(writer io.Writer) *slog.Logger {
	return slog.New(&traceLogHandler{Handler: slog.NewJSONHandler(writer, nil)})
}

func (h *traceLogHandler) Handle(ctx context.Context, record slog.Record) error {
	spanContext := trace.SpanContextFromContext(ctx)
	if spanContext.IsValid() && spanContext.IsSampled() {
		record.AddAttrs(
			slog.String("trace_id", spanContext.TraceID().String()),
			slog.String("span_id", spanContext.SpanID().String()),
		)
	}
	return h.Handler.Handle(ctx, record)
}

func (h *traceLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceLogHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *traceLogHandler) WithGroup(name string) slog.Handler {
	return &traceLogHandler{Handler: h.Handler.WithGroup(name)}
}

func Setup(ctx context.Context, defaultServiceName string) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if telemetryDisabled() {
		return func(context.Context) error { return nil }, nil
	}

	serviceName := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME"))
	if serviceName == "" {
		serviceName = defaultServiceName
	}

	res, err := resource.New(
		ctx,
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithProcess(),
		resource.WithHost(),
		resource.WithAttributes(attribute.String("service.name", serviceName)),
	)
	if err != nil {
		return nil, fmt.Errorf("create telemetry resource: %w", err)
	}

	exporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(configuredSampler()),
	)
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}

func HTTPHandler(next http.Handler) http.Handler {
	instrumented := otelhttp.NewHandler(
		next,
		"HTTP request",
		otelhttp.WithFilter(func(r *http.Request) bool {
			return r.URL.Path != "/health" && r.URL.Path != "/ready"
		}),
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/ready" {
			spanContext := trace.NewSpanContext(trace.SpanContextConfig{
				TraceID: trace.TraceID{1},
				SpanID:  trace.SpanID{1},
			})
			next.ServeHTTP(w, r.WithContext(trace.ContextWithSpanContext(r.Context(), spanContext)))
			return
		}
		instrumented.ServeHTTP(w, r)
	})
}

func HTTPTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return otelhttp.NewTransport(base)
}

func telemetryDisabled() bool {
	if disabled, err := strconv.ParseBool(strings.TrimSpace(os.Getenv("OTEL_SDK_DISABLED"))); err == nil && disabled {
		return true
	}
	return strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")) == "" &&
		strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")) == ""
}

func configuredSampler() sdktrace.Sampler {
	ratio := 1.0
	if raw := strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER_ARG")); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil && parsed >= 0 && parsed <= 1 {
			ratio = parsed
		}
	}

	ratioSampler := sdktrace.TraceIDRatioBased(ratio)
	switch strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER"))) {
	case "always_off":
		return sdktrace.NeverSample()
	case "always_on":
		return sdktrace.AlwaysSample()
	case "traceidratio":
		return ratioSampler
	default:
		return sdktrace.ParentBased(ratioSampler)
	}
}
