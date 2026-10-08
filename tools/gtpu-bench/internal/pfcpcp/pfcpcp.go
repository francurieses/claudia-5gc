// Package pfcpcp is gtpu-bench's minimal PFCP control plane: it plays a fake SMF toward the
// UPF over N4 (TS 29.244) using go-pfcp, installing synthetic sessions with the same IE set the
// real SMF sends (nf/smf sendPFCPSessionEstablishment / sendPFCPSessionModification), minus the
// URR so the UPF never sends Session Reports to the bench.
package pfcpcp

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

// Reserved identifier ranges: real SMF sessions never allocate here (docs: tools/gtpu-bench/CLAUDE.md).
const (
	SEIDBase = uint64(0xB000000000000000)
	TEIDBase = uint32(0xB0000000)
	// QFI used for the synthetic default flow.
	QFI = 1
)

// Session describes one synthetic PDU session.
type Session struct {
	Index  int
	SEID   uint64
	ULTEID uint32
	DLTEID uint32
	UEIP   net.IP
}

// NewSession derives the reserved identifiers for session i with UE IP base+i.
func NewSession(i int, ueBase net.IP) Session {
	ip := make(net.IP, 4)
	copy(ip, ueBase.To4())
	ip[3] += byte(i)
	return Session{Index: i, SEID: SEIDBase + uint64(i) + 1, ULTEID: TEIDBase + uint32(i)*2 + 1, DLTEID: TEIDBase + uint32(i)*2 + 2, UEIP: ip}
}

// EstablishmentRequest builds the Session Establishment Request for s (UL tunnel on upfN3).
func EstablishmentRequest(seq uint32, s Session, upfN3 net.IP, dnn string) *pfcpmsg.SessionEstablishmentRequest {
	return pfcpmsg.NewSessionEstablishmentRequest(0, 0, 0, seq, 0,
		pfcpie.NewNodeID("", "", "gtpu-bench"),
		pfcpie.NewFSEID(s.SEID, net.ParseIP("0.0.0.0"), nil),
		pfcpie.NewCreatePDR(
			pfcpie.NewPDRID(1),
			pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(
				pfcpie.NewSourceInterface(pfcpie.SrcInterfaceAccess),
				pfcpie.NewFTEID(0x01, s.ULTEID, upfN3, nil, 0),
				pfcpie.NewUEIPAddress(0x02, s.UEIP.String(), "", 0, 0),
				pfcpie.NewNetworkInstance(dnn),
			),
			pfcpie.NewOuterHeaderRemoval(0, 0),
			pfcpie.NewFARID(1),
			pfcpie.NewQERID(1),
		),
		pfcpie.NewCreateFAR(pfcpie.NewFARID(1), pfcpie.NewApplyAction(0x02)),
		pfcpie.NewCreateQER(
			pfcpie.NewQERID(1),
			pfcpie.NewGateStatus(0, 0),
			pfcpie.NewMBR(0xFFFFFFFF, 0xFFFFFFFF),
			pfcpie.NewQFI(QFI),
		),
	)
}

// ModificationRequest builds the Session Modification Request installing the DL tunnel to gnb.
func ModificationRequest(seq uint32, s Session, gnb net.IP) *pfcpmsg.SessionModificationRequest {
	return pfcpmsg.NewSessionModificationRequest(0, 0, s.SEID, seq, 0,
		pfcpie.NewUpdateFAR(
			pfcpie.NewFARID(1),
			pfcpie.NewApplyAction(0x02),
			pfcpie.NewUpdateForwardingParameters(
				pfcpie.NewOuterHeaderCreation(0x0100, s.DLTEID, gnb.String(), "", 0, 0, 0),
			),
		),
	)
}

// DeletionRequest builds the Session Deletion Request for s.
func DeletionRequest(seq uint32, s Session) *pfcpmsg.SessionDeletionRequest {
	return pfcpmsg.NewSessionDeletionRequest(0, 0, s.SEID, seq, 0)
}

// Client sends PFCP requests to one UPF and waits for the response.
type Client struct {
	conn *net.UDPConn
	seq  atomic.Uint32
}

// Dial opens a PFCP socket toward upf ("host:8805") from the local address local ("" = any).
func Dial(ctx context.Context, upf string) (*Client, error) {
	raddr, err := net.ResolveUDPAddr("udp", upf)
	if err != nil {
		return nil, fmt.Errorf("gtpu-bench: resolve UPF %q: %w", upf, err)
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", raddr.String())
	if err != nil {
		return nil, fmt.Errorf("gtpu-bench: dial UPF: %w", err)
	}
	return &Client{conn: c.(*net.UDPConn)}, nil
}

// Seq returns the next PFCP sequence number.
func (c *Client) Seq() uint32 { return c.seq.Add(1) }

// Close closes the socket.
func (c *Client) Close() error { return c.conn.Close() }

// Do marshals req, sends it and returns the Cause of the response.
func (c *Client) Do(req interface {
	Marshal() ([]byte, error)
}) (uint8, error) {
	b, err := req.Marshal()
	if err != nil {
		return 0, fmt.Errorf("gtpu-bench: marshal: %w", err)
	}
	if _, err := c.conn.Write(b); err != nil {
		return 0, fmt.Errorf("gtpu-bench: send: %w", err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := c.conn.Read(buf)
	if err != nil {
		return 0, fmt.Errorf("gtpu-bench: await response: %w", err)
	}
	msg, err := pfcpmsg.Parse(buf[:n])
	if err != nil {
		return 0, fmt.Errorf("gtpu-bench: parse response: %w", err)
	}
	switch m := msg.(type) {
	case *pfcpmsg.SessionEstablishmentResponse:
		return causeOf(m.Cause)
	case *pfcpmsg.SessionModificationResponse:
		return causeOf(m.Cause)
	case *pfcpmsg.SessionDeletionResponse:
		return causeOf(m.Cause)
	}
	return 0, fmt.Errorf("gtpu-bench: unexpected response %s", msg.MessageTypeName())
}

func causeOf(ie *pfcpie.IE) (uint8, error) {
	if ie == nil {
		return 0, fmt.Errorf("gtpu-bench: response without Cause")
	}
	return ie.Cause()
}

// Establish installs s (UL + DL tunnel) and returns an error unless both are accepted.
func (c *Client) Establish(s Session, upfN3, gnb net.IP, dnn string) error {
	cause, err := c.Do(EstablishmentRequest(c.Seq(), s, upfN3, dnn))
	if err != nil {
		return err
	}
	if cause != pfcpie.CauseRequestAccepted {
		return fmt.Errorf("gtpu-bench: establishment SEID %#x rejected, cause %d", s.SEID, cause)
	}
	cause, err = c.Do(ModificationRequest(c.Seq(), s, gnb))
	if err != nil {
		return err
	}
	if cause != pfcpie.CauseRequestAccepted {
		return fmt.Errorf("gtpu-bench: modification SEID %#x rejected, cause %d", s.SEID, cause)
	}
	return nil
}

// Delete removes s from the UPF.
func (c *Client) Delete(s Session) error {
	cause, err := c.Do(DeletionRequest(c.Seq(), s))
	if err != nil {
		return err
	}
	if cause != pfcpie.CauseRequestAccepted {
		return fmt.Errorf("gtpu-bench: deletion SEID %#x rejected, cause %d", s.SEID, cause)
	}
	return nil
}
