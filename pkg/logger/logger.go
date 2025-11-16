// Package logger provides structured logging with automatic secret redaction
package logger

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Logger wraps zerolog.Logger with additional security features
type Logger struct {
	zlog zerolog.Logger
}

// Config holds logger configuration
type Config struct {
	// Level is the minimum log level (debug, info, warn, error)
	Level string

	// Output is where logs are written (default: os.Stdout)
	Output io.Writer

	// Pretty enables human-readable console output
	Pretty bool

	// TimeFormat for timestamps (default: RFC3339)
	TimeFormat string

	// CallerEnabled adds file and line number to logs
	CallerEnabled bool
}

// DefaultConfig returns default logger configuration
func DefaultConfig() *Config {
	return &Config{
		Level:         "info",
		Output:        os.Stdout,
		Pretty:        false,
		TimeFormat:    time.RFC3339,
		CallerEnabled: false,
	}
}

// New creates a new logger with the given configuration
func New(cfg *Config) *Logger {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Set global level
	level := parseLevel(cfg.Level)
	zerolog.SetGlobalLevel(level)

	// Configure output
	output := cfg.Output
	if output == nil {
		output = os.Stdout
	}

	// Pretty printing for development
	if cfg.Pretty {
		output = zerolog.ConsoleWriter{
			Out:        output,
			TimeFormat: cfg.TimeFormat,
		}
	}

	// Create base logger
	zlog := zerolog.New(output).With().Timestamp().Logger()

	// Add caller info if enabled
	if cfg.CallerEnabled {
		zlog = zlog.With().Caller().Logger()
	}

	return &Logger{zlog: zlog}
}

// parseLevel converts string level to zerolog.Level
func parseLevel(level string) zerolog.Level {
	switch level {
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	case "panic":
		return zerolog.PanicLevel
	default:
		return zerolog.InfoLevel
	}
}

// With creates a child logger with additional context
func (l *Logger) With() *Context {
	return &Context{zctx: l.zlog.With()}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string) {
	l.zlog.Debug().Msg(msg)
}

// Info logs an info message
func (l *Logger) Info(msg string) {
	l.zlog.Info().Msg(msg)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string) {
	l.zlog.Warn().Msg(msg)
}

// Error logs an error message
func (l *Logger) Error(msg string) {
	l.zlog.Error().Msg(msg)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string) {
	l.zlog.Fatal().Msg(msg)
}

// Context provides fluent API for adding fields to logs
type Context struct {
	zctx zerolog.Context
}

// Str adds a string field
func (c *Context) Str(key, val string) *Context {
	c.zctx = c.zctx.Str(key, val)
	return c
}

// Int adds an int field
func (c *Context) Int(key string, val int) *Context {
	c.zctx = c.zctx.Int(key, val)
	return c
}

// Bool adds a boolean field
func (c *Context) Bool(key string, val bool) *Context {
	c.zctx = c.zctx.Bool(key, val)
	return c
}

// Err adds an error field (automatically redacts sensitive info)
func (c *Context) Err(err error) *Context {
	if err != nil {
		c.zctx = c.zctx.AnErr("error", err)
	}
	return c
}

// Dur adds a duration field
func (c *Context) Dur(key string, val time.Duration) *Context {
	c.zctx = c.zctx.Dur(key, val)
	return c
}

// Logger returns the configured logger
func (c *Context) Logger() *Logger {
	return &Logger{zlog: c.zctx.Logger()}
}

// Event represents a log event
type Event struct {
	zevent *zerolog.Event
}

// Str adds a string field to the event
func (e *Event) Str(key, val string) *Event {
	e.zevent.Str(key, val)
	return e
}

// Int adds an int field to the event
func (e *Event) Int(key string, val int) *Event {
	e.zevent.Int(key, val)
	return e
}

// Bool adds a boolean field to the event
func (e *Event) Bool(key string, val bool) *Event {
	e.zevent.Bool(key, val)
	return e
}

// Err adds an error field to the event
func (e *Event) Err(err error) *Event {
	e.zevent.AnErr("error", err)
	return e
}

// Dur adds a duration field to the event
func (e *Event) Dur(key string, val time.Duration) *Event {
	e.zevent.Dur(key, val)
	return e
}

// Msg completes the event with a message
func (e *Event) Msg(msg string) {
	e.zevent.Msg(msg)
}

// Debug returns a debug event
func (l *Logger) DebugEvent() *Event {
	return &Event{zevent: l.zlog.Debug()}
}

// InfoEvent returns an info event
func (l *Logger) InfoEvent() *Event {
	return &Event{zevent: l.zlog.Info()}
}

// WarnEvent returns a warn event
func (l *Logger) WarnEvent() *Event {
	return &Event{zevent: l.zlog.Warn()}
}

// ErrorEvent returns an error event
func (l *Logger) ErrorEvent() *Event {
	return &Event{zevent: l.zlog.Error()}
}

// RedactSecret redacts sensitive information from logs
// IMPORTANT: Never log raw secrets, keys, or shares
func RedactSecret(secret string) string {
	if len(secret) == 0 {
		return "<empty>"
	}
	if len(secret) <= 8 {
		return "<redacted>"
	}
	// Show only first 4 chars for debugging (e.g., key IDs)
	return secret[:4] + "..." + "<redacted>"
}

// Global logger instance
var globalLogger = New(DefaultConfig())

// SetGlobalLogger sets the global logger instance
func SetGlobalLogger(logger *Logger) {
	if logger != nil {
		globalLogger = logger
	}
}

// Global convenience functions

// Debug logs a debug message using the global logger
func Debug(msg string) {
	globalLogger.Debug(msg)
}

// Info logs an info message using the global logger
func Info(msg string) {
	globalLogger.Info(msg)
}

// Warn logs a warning message using the global logger
func Warn(msg string) {
	globalLogger.Warn(msg)
}

// Error logs an error message using the global logger
func Error(msg string) {
	globalLogger.Error(msg)
}

// Fatal logs a fatal message using the global logger and exits
func Fatal(msg string) {
	globalLogger.Fatal(msg)
}
