//go:build linux

// Package tun: Linux TUN device creation (TUNSETIFF ioctl). Other platforms use
// the stub in tun_other.go so the module builds and tests on macOS.
package tun

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const cloneDevicePath = "/dev/net/tun"

// Open creates a TUN device with the given name (layer 3, IFF_NO_PI).
// The returned *os.File is the read/write handle for IP packets.
func Open(name string) (*os.File, error) {
	fd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open %s: %w", cloneDevicePath, err)
	}

	// struct ifreq layout: ifr_name[IFNAMSIZ] + ifr_flags(uint16)
	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:unix.IFNAMSIZ], name)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = unix.IFF_TUN | unix.IFF_NO_PI

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: TUNSETIFF %s: %w", name, errno)
	}

	return os.NewFile(uintptr(fd), cloneDevicePath), nil
}
