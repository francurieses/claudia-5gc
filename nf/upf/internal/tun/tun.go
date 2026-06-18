// Package tun creates and configures a Linux TUN interface for N6 IP forwarding.
// Requires CAP_NET_ADMIN. Ref: Linux tun(4), TS 29.281 §5.
package tun

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
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

// Setup configures the TUN interface for N6 forwarding:
//   - enables IP forwarding in the network namespace
//   - brings the interface up and assigns tunAddr (CIDR, e.g. "10.60.0.254/16")
//   - allows all FORWARD traffic (Docker default policy is DROP)
//   - installs an iptables MASQUERADE rule so UE packets (ueSubnet) appear
//     to originate from the UPF's N6 IP when exiting any non-TUN interface
func Setup(name, tunAddr, ueSubnet string) error {
	// Enable IP forwarding if writable (docker-compose sysctls may have already set it).
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
	if err := run("ip", "link", "set", name, "up"); err != nil {
		return err
	}
	if err := runIdempotent("ip", "addr", "add", tunAddr, "dev", name); err != nil {
		return err
	}
	// Allow all forwarded traffic in this container's network namespace.
	// (Docker's default FORWARD policy is DROP; inside the container it's isolated.)
	if err := run("iptables", "-P", "FORWARD", "ACCEPT"); err != nil {
		return err
	}
	// MASQUERADE: replace UE source IP with UPF's outbound interface IP
	if !iptablesRuleExists("nat", "POSTROUTING", "-s", ueSubnet, "!", "-o", name, "-j", "MASQUERADE") {
		if err := run("iptables", "-t", "nat", "-A", "POSTROUTING",
			"-s", ueSubnet, "!", "-o", name, "-j", "MASQUERADE"); err != nil {
			return err
		}
	}
	return nil
}

func iptablesRuleExists(table, chain string, args ...string) bool {
	a := append([]string{"-t", table, "-C", chain}, args...)
	return exec.Command("iptables", a...).Run() == nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tun: %s %v: %s: %w", name, args, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// runIdempotent ignores "already exists" / "File exists" errors.
func runIdempotent(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		s := string(out)
		if strings.Contains(s, "File exists") ||
			strings.Contains(s, "already exists") ||
			strings.Contains(s, "Duplicate") {
			return nil
		}
		return fmt.Errorf("tun: %s %v: %s: %w", name, args, strings.TrimSpace(s), err)
	}
	return nil
}
