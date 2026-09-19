// Package tun creates and configures a Linux TUN interface for N6 IP forwarding.
// Requires CAP_NET_ADMIN. Ref: Linux tun(4), TS 29.281 §5.
package tun

import (
	"fmt"
	"net"
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

// Setup configures the TUN interface for N6 IPv4 forwarding:
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
	if !ipRuleExists("iptables", "nat", "POSTROUTING", "-s", ueSubnet, "!", "-o", name, "-j", "MASQUERADE") {
		if err := run("iptables", "-t", "nat", "-A", "POSTROUTING",
			"-s", ueSubnet, "!", "-o", name, "-j", "MASQUERADE"); err != nil {
			return err
		}
	}
	return nil
}

// SetupIPv6 configures the TUN interface for N6 IPv6 forwarding of a delegated
// prefix (TS 23.501 §5.8.2.2 / §5.6.5). It mirrors Setup for IPv4:
//   - enables IPv6 forwarding in the network namespace and on the TUN
//   - assigns the UPF's router address inside the delegated prefix so the
//     whole prefix is on-link via the TUN (return traffic routes back here)
//   - allows all FORWARD traffic (ip6tables)
//   - installs an ip6tables MASQUERADE rule so UE packets (ipv6Prefix) appear
//     to originate from the UPF's N6 IPv6 address when exiting a non-TUN interface
//
// ipv6Prefix is the DNN's delegated base prefix (CIDR, e.g. "2001:db8:60::/56").
// Egress to the actual internet additionally requires the N6 Docker network to
// have IPv6 enabled with a gateway (docker-compose.yml); without it, forwarding
// still works up to the N6 bridge but has no default route beyond it.
func SetupIPv6(name, ipv6Prefix string) error {
	tunAddr6, err := deriveTunV6Addr(ipv6Prefix)
	if err != nil {
		return fmt.Errorf("tun: derive IPv6 TUN address from %q: %w", ipv6Prefix, err)
	}

	// Enable IPv6 + forwarding in this netns and on the TUN. Best-effort writes:
	// docker-compose sysctls may already have set the namespace-wide knobs, and
	// a read-only /proc entry must not fail the whole setup.
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/all/disable_ipv6", []byte("0"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/disable_ipv6", []byte("0"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/forwarding", []byte("1"), 0644)

	// Assign the router address with the base prefix length so the whole
	// delegated pool (all per-session /64s) is a single connected route via the
	// TUN. nodad: a point-to-point TUN has no peer to answer Duplicate Address
	// Detection, so skip it to avoid the address lingering in "tentative".
	if err := runIdempotent("ip", "-6", "addr", "add", tunAddr6, "dev", name, "nodad"); err != nil {
		return err
	}
	if err := run("ip6tables", "-P", "FORWARD", "ACCEPT"); err != nil {
		return err
	}
	if !ipRuleExists("ip6tables", "nat", "POSTROUTING", "-s", ipv6Prefix, "!", "-o", name, "-j", "MASQUERADE") {
		if err := run("ip6tables", "-t", "nat", "-A", "POSTROUTING",
			"-s", ipv6Prefix, "!", "-o", name, "-j", "MASQUERADE"); err != nil {
			return err
		}
	}
	return nil
}

// deriveTunV6Addr returns the UPF's router address for a delegated IPv6 prefix:
// the prefix network address with the low byte set to 0xfe, keeping the base
// prefix length (e.g. "2001:db8:60::/56" → "2001:db8:60::fe/56"). 0xfe avoids
// the "::1" interface identifier the SMF assigns UEs, and keeping the /56 mask
// makes every delegated /64 on-link via the TUN.
func deriveTunV6Addr(ipv6Prefix string) (string, error) {
	_, ipnet, err := net.ParseCIDR(ipv6Prefix)
	if err != nil {
		return "", err
	}
	ones, _ := ipnet.Mask.Size()
	addr := make(net.IP, net.IPv6len)
	copy(addr, ipnet.IP.To16())
	addr[15] = 0xfe
	return fmt.Sprintf("%s/%d", addr.String(), ones), nil
}

func ipRuleExists(cmd, table, chain string, args ...string) bool {
	a := append([]string{"-t", table, "-C", chain}, args...)
	return exec.Command(cmd, a...).Run() == nil
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
