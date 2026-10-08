package gtpu

import (
	"net"

	"golang.org/x/sys/unix"
)

// setSocketBuffers sizes SO_RCVBUF/SO_SNDBUF of the GTP-U socket to n bytes. The portable
// SetReadBuffer is capped by net.core.rmem_max, which is not namespaced; the UPF holds
// CAP_NET_ADMIN so SO_RCVBUFFORCE/SO_SNDBUFFORCE lifts the cap. It returns the effective sizes.
func setSocketBuffers(c *net.UDPConn, n int) (rcv, snd int, err error) {
	if n <= 0 {
		return 0, 0, nil
	}
	_ = c.SetReadBuffer(n)
	_ = c.SetWriteBuffer(n)
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	_ = rc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, n)
		rcv, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		snd, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	})
	return rcv, snd, nil
}
