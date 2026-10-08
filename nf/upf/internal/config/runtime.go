package config

import (
	"log/slog"
	"os"
	"strings"
)

// LogLevelFromEnv maps the LOG_LEVEL environment variable (debug|info|warn|error,
// case-insensitive) to a slog level. Unset or unrecognised values give info, the
// level the UPF always used before LOG_LEVEL was honoured.
func LogLevelFromEnv() slog.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LOG_LEVEL"))) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// PprofAddrFromEnv returns the optional net/http/pprof listen address
// (UPF_PPROF_ADDR, e.g. "0.0.0.0:6060"). Empty means profiling is off, the default.
func PprofAddrFromEnv() string {
	return strings.TrimSpace(os.Getenv("UPF_PPROF_ADDR"))
}
