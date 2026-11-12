//go:build !linux

// Package tun: non-Linux stub. The UPF data plane only runs on Linux; this stub
// lets the module build and unit-test on other hosts (e.g. macOS developer machines).
package tun

import (
	"errors"
	"fmt"
	"os"
	"runtime"
)

// errUnsupported is returned by Open on platforms without /dev/net/tun.
var errUnsupported = errors.New("unsupported")

// Open always fails on non-Linux platforms: TUN devices need the Linux /dev/net/tun clone device.
func Open(name string) (*os.File, error) {
	return nil, fmt.Errorf("tun: open %s: %w on %s", name, errUnsupported, runtime.GOOS)
}
