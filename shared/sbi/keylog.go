package sbi

import (
	"io"
	"log/slog"
	"os"
)

// OpenKeyLogWriter opens the TLS session key log file pointed to by SSLKEYLOGFILE.
// Returns nil if the variable is unset or the file cannot be opened.
// Set tls.Config.KeyLogWriter to the result to write NSS key log entries that
// Wireshark can use to decrypt TLS 1.3 traffic (Edit → Preferences → TLS).
func OpenKeyLogWriter() io.Writer {
	path := os.Getenv("SSLKEYLOGFILE")
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		slog.Default().Warn("SSLKEYLOGFILE: cannot open file", "path", path, "error", err)
		return nil
	}
	return f
}
