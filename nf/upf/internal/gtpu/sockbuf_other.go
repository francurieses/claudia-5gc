//go:build !linux

package gtpu

import "net"

// setSocketBuffers uses the portable setters off Linux (no force variant).
func setSocketBuffers(c *net.UDPConn, n int) (rcv, snd int, err error) {
	if n <= 0 {
		return 0, 0, nil
	}
	_ = c.SetReadBuffer(n)
	_ = c.SetWriteBuffer(n)
	return n, n, nil
}
