// Package interfaces contains all external interface definitions used by the go-user-management module.
// This file serves as a central location for interface contracts that the module depends on.
package interfaces

import (
	"context"
	"io"
	"time"
)

// Cache represents the caching interface used throughout the user management system.
// This interface is implemented by the go-cache module.
type Cache interface {
	// Basic operations
	Get(ctx context.Context, key string) (any, bool, error)
	Set(ctx context.Context, key string, value any, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Clear(ctx context.Context) error
	Has(ctx context.Context, key string) bool
	GetKeys(ctx context.Context) []string
	Close() error

	// Bulk operations
	GetMany(ctx context.Context, keys []string) (map[string]any, error)
	SetMany(ctx context.Context, items map[string]any, ttl time.Duration) error
	DeleteMany(ctx context.Context, keys []string) error

	// Metadata operations
	GetMetadata(ctx context.Context, key string) (*CacheEntryMetadata, error)
	GetManyMetadata(ctx context.Context, keys []string) (map[string]*CacheEntryMetadata, error)

	// Metrics
	GetMetrics() *CacheMetricsSnapshot
}

// CacheEntryMetadata represents metadata about a cache entry.
type CacheEntryMetadata struct {
	Key       string        `json:"key"`
	Size      int64         `json:"size"`
	CreatedAt time.Time     `json:"created_at"`
	ExpiresAt time.Time     `json:"expires_at"`
	TTL       time.Duration `json:"ttl"`
}

// CacheMetricsSnapshot represents a snapshot of cache metrics.
type CacheMetricsSnapshot struct {
	Hits       int64         `json:"hits"`
	Misses     int64         `json:"misses"`
	HitRate    float64       `json:"hit_rate"`
	Size       int64         `json:"size"`
	EntryCount int64         `json:"entry_count"`
	GetLatency time.Duration `json:"get_latency"`
	SetLatency time.Duration `json:"set_latency"`
}

// Config represents the configuration interface used by the user management system.
// This interface is implemented by the go-config module.
type Config interface {
	// Get retrieves a configuration value by key
	Get(key string) (any, bool)

	// GetString retrieves a string configuration value
	GetString(key string) (string, bool)

	// GetInt retrieves an integer configuration value
	GetInt(key string) (int, bool)

	// GetBool retrieves a boolean configuration value
	GetBool(key string) (bool, bool)

	// GetFloat retrieves a float configuration value
	GetFloat(key string) (float64, bool)

	// GetStringSlice retrieves a string slice configuration value
	GetStringSlice(key string) ([]string, bool)

	// Set sets a configuration value
	Set(key string, value any) error

	// Load loads configuration from a source
	Load(source Source) error

	// Validate validates the configuration
	Validate() error
}

// Source represents a configuration source.
type Source interface {
	// Load loads configuration from the source
	Load() (map[string]any, error)
}

// Encrypter represents the encryption interface used for PII protection.
// This interface is implemented by the go-encrypter module.
type Encrypter interface {
	Encrypt(data []byte) ([]byte, error)
	EncryptWithAAD(data, additionalData []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
	DecryptWithAAD(data, additionalData []byte) ([]byte, error)
	HashPassword(password []byte) ([]byte, error)
	VerifyPassword(hashedPassword, password []byte) (bool, error)
	HashLookupData(data []byte) []byte
}

// Logger represents the logging interface used throughout the user management system.
// This interface is implemented by the go-logger module.
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Fatal(msg string, fields ...Field)
	With(fields ...Field) Logger
	WithContext(ctx context.Context) Logger
}

// Field represents a key-value pair for structured logging.
type Field struct {
	Key   string
	Value any
}

// Metrics interfaces for observability throughout the user management system.
// These interfaces are implemented by the go-metrics module.

// Metric is the base interface that all metric types implement.
type Metric interface {
	// Name returns the unique identifier for the metric
	Name() string
	// Description provides additional information about what the metric measures
	Description() string
	// Type returns the metric type (counter, gauge, etc.)
	Type() Type
	// Tags returns the key-value pairs associated with this metric
	Tags() Tags
}

// Type represents the type of metric.
type Type string

// Tags represents key-value pairs for metric labeling.
type Tags map[string]string

// Counter represents a monotonically increasing value.
type Counter interface {
	Metric
	// Inc increments the counter by 1
	Inc()
	// Add increases the counter by the given value
	Add(value float64)
	// With returns a Counter with additional tags
	With(tags Tags) Counter
}

// Gauge represents a current point-in-time measurement.
type Gauge interface {
	Metric
	// Set sets the gauge to the given value
	Set(value float64)
	// Add adds the given value to the gauge (can be negative)
	Add(value float64)
	// Inc increments the gauge by 1
	Inc()
	// Dec decrements the gauge by 1
	Dec()
	// With returns a Gauge with additional tags
	With(tags Tags) Gauge
}

// Histogram represents a statistical distribution of values.
type Histogram interface {
	Metric
	// Observe records a value in the histogram
	Observe(value float64)
	// With returns a Histogram with additional tags
	With(tags Tags) Histogram
}

// Timer is a specialized metric for measuring durations.
type Timer interface {
	Metric
	// Record records a duration
	Record(d time.Duration)
	// RecordSince records the duration since the provided time
	RecordSince(t time.Time)
	// Time is a convenience method for timing a function
	Time(fn func()) time.Duration
	// With returns a Timer with additional tags
	With(tags Tags) Timer
}

// Options represents options for creating metrics.
type Options struct {
	Name        string
	Description string
	Tags        Tags
}

// Registry manages a collection of metrics.
type Registry interface {
	// Counter creates or retrieves a Counter
	Counter(opts Options) Counter
	// Gauge creates or retrieves a Gauge
	Gauge(opts Options) Gauge
	// Histogram creates or retrieves a Histogram
	Histogram(opts Options) Histogram
	// Timer creates or retrieves a Timer
	Timer(opts Options) Timer
	// Unregister removes a metric from the registry
	Unregister(name string)
	// Each iterates over all registered metrics
	Each(fn func(Metric))
}

// Reporter is the interface for reporting metrics to a backend system.
type Reporter interface {
	// Report sends metrics to a backend system
	Report(Registry) error
	// Flush ensures all buffered metrics are sent
	Flush() error
	// Close shuts down the reporter, flushing any remaining metrics
	Close() error
}

// Serializer represents the serialization interface for data persistence.
// This interface is implemented by the go-serializer module.
type Serializer interface {
	// Serialize converts a value to bytes
	Serialize(v any) ([]byte, error)

	// Deserialize converts bytes back to a value
	// v must be a pointer to the type you want to deserialize into
	Deserialize(data []byte, v any) error

	// SerializeTo writes a value to a writer
	SerializeTo(w io.Writer, v any) error

	// DeserializeFrom reads a value from a reader
	// v must be a pointer to the type you want to deserialize into
	DeserializeFrom(r io.Reader, v any) error

	// ContentType returns the MIME type for this serialization format
	ContentType() string
}
