// Package nas implements the 5GS Non-Access Stratum (NAS) protocol codec.
//
// Reference: 3GPP TS 24.501 v17.x.x
//
// Architecture:
//
//	nas/               — this package: types, PDU header, encode/decode dispatcher
//	nas/mm/            — 5GMM (Mobility Management) messages
//	nas/sm/            — 5GSM (Session Management) messages
//	nas/ie/            — Information Elements shared between MM and SM
//
// Every public function in this package that encodes or decodes returns an
// error if the input is malformed or the output would violate mandatory IE
// constraints per the spec.
package nas

import (
	"errors"
	"fmt"
	"io"
)

// ---- Protocol Discriminators (TS 24.501 §9.2) ----------------------------

const (
	// PDGroupSessionManagement is EPD for 5GS session management messages (0x2E).
	PDGroupSessionManagement byte = 0x2E
	// PDMobilityManagement is EPD for 5GS mobility management messages (0x7E).
	PDMobilityManagement byte = 0x7E
)

// ---- Security Header Types (TS 24.501 §9.3) ------------------------------

type SecurityHeaderType byte

const (
	SecurityHeaderPlainNAS             SecurityHeaderType = 0x00
	SecurityHeaderIntegrityProtected   SecurityHeaderType = 0x01
	SecurityHeaderIntegrityProtectedAndCiphered SecurityHeaderType = 0x02
	SecurityHeaderIntegrityProtectedWithNewSC   SecurityHeaderType = 0x03
	SecurityHeaderIntegrityProtectedAndCipheredWithNewSC SecurityHeaderType = 0x04
)

// ---- 5GMM Message Types (TS 24.501 §9.7) ---------------------------------

type MessageType byte

const (
	// 5GS Mobility Management messages
	MsgTypeRegistrationRequest      MessageType = 0x41
	MsgTypeRegistrationAccept       MessageType = 0x42
	MsgTypeRegistrationComplete     MessageType = 0x43
	MsgTypeRegistrationReject       MessageType = 0x44
	MsgTypeDeregistrationRequestUE  MessageType = 0x45
	MsgTypeDeregistrationAcceptUE   MessageType = 0x46
	MsgTypeDeregistrationRequestNW  MessageType = 0x47
	MsgTypeDeregistrationAcceptNW   MessageType = 0x48
	MsgTypeServiceRequest           MessageType = 0x4C
	MsgTypeServiceReject            MessageType = 0x4D
	MsgTypeServiceAccept            MessageType = 0x4E
	MsgTypeControlPlaneServiceRequest MessageType = 0x4F
	MsgTypeNetworkSliceSpecificAuthCommand    MessageType = 0x50
	MsgTypeNetworkSliceSpecificAuthComplete   MessageType = 0x51
	MsgTypeNetworkSliceSpecificAuthResult     MessageType = 0x52
	MsgTypeConfigurationUpdateCommand  MessageType = 0x54
	MsgTypeConfigurationUpdateComplete MessageType = 0x55
	MsgTypeAuthenticationRequest    MessageType = 0x56
	MsgTypeAuthenticationResponse   MessageType = 0x57
	MsgTypeAuthenticationReject     MessageType = 0x58
	MsgTypeAuthenticationFailure    MessageType = 0x59
	MsgTypeAuthenticationResult     MessageType = 0x5A
	MsgTypeIdentityRequest          MessageType = 0x5B
	MsgTypeIdentityResponse         MessageType = 0x5C
	MsgTypeSecurityModeCommand      MessageType = 0x5D
	MsgTypeSecurityModeComplete     MessageType = 0x5E
	MsgTypeSecurityModeReject       MessageType = 0x5F
	MsgTypeStatus5GMM               MessageType = 0x64
	MsgTypeNotification             MessageType = 0x65
	MsgTypeNotificationResponse     MessageType = 0x66
	MsgTypeULNASTransport           MessageType = 0x67
	MsgTypeDLNASTransport           MessageType = 0x68

	// 5GS Session Management messages
	MsgTypePDUSessionEstablishmentRequest  MessageType = 0xC1
	MsgTypePDUSessionEstablishmentAccept   MessageType = 0xC2
	MsgTypePDUSessionEstablishmentReject   MessageType = 0xC3
	MsgTypePDUSessionAuthenticationCommand  MessageType = 0xC5
	MsgTypePDUSessionAuthenticationComplete MessageType = 0xC6
	MsgTypePDUSessionAuthenticationResult   MessageType = 0xC7
	MsgTypePDUSessionModificationRequest    MessageType = 0xC9
	MsgTypePDUSessionModificationReject     MessageType = 0xCA
	MsgTypePDUSessionModificationCommand    MessageType = 0xCB
	MsgTypePDUSessionModificationComplete   MessageType = 0xCC
	MsgTypePDUSessionModificationCommandReject MessageType = 0xCD
	MsgTypePDUSessionReleaseRequest         MessageType = 0xD1
	MsgTypePDUSessionReleaseReject          MessageType = 0xD2
	MsgTypePDUSessionReleaseCommand         MessageType = 0xD3
	MsgTypePDUSessionReleaseComplete        MessageType = 0xD4
	MsgTypeStatus5GSM                       MessageType = 0xD6
)

// ---- NAS PDU Header (TS 24.501 §9.1.1) -----------------------------------

// Header is the outer NAS-5GS PDU header (plain or security-protected).
type Header struct {
	ExtendedProtocolDiscriminator byte
	SecurityHeaderType            SecurityHeaderType
	// For non-plain messages: MAC (4 bytes) + SequenceNumber (1 byte)
	MessageAuthenticationCode [4]byte
	SequenceNumber            byte
	// Message type and body (after security header)
	MessageType MessageType
}

// Message is the decoded form of a complete NAS PDU.
type Message struct {
	Header Header
	// Body is the type-specific payload.
	Body interface{}
}

// Decode parses a raw NAS-5GS PDU from r.
// Returns a typed Message whose Body can be type-asserted.
// Ref: TS 24.501 §9.1.1
func Decode(data []byte) (*Message, error) {
	if len(data) < 3 {
		return nil, errors.New("nas: PDU too short")
	}
	msg := &Message{}
	epd := data[0]
	msg.Header.ExtendedProtocolDiscriminator = epd
	msg.Header.SecurityHeaderType = SecurityHeaderType(data[1] & 0x0F)

	switch msg.Header.SecurityHeaderType {
	case SecurityHeaderPlainNAS:
		// Plain: EPD | SHT | Message Type | ...
		if len(data) < 3 {
			return nil, errors.New("nas: plain PDU too short")
		}
		msg.Header.MessageType = MessageType(data[2])
		return decodeBody(msg, data[3:])
	default:
		// Security-protected: EPD | SHT | MAC (4) | SN (1) | inner EPD | SHT | MT | body
		if len(data) < 9 {
			return nil, errors.New("nas: security PDU too short")
		}
		copy(msg.Header.MessageAuthenticationCode[:], data[2:6])
		msg.Header.SequenceNumber = data[6]
		inner := data[7:]
		if len(inner) < 3 {
			return nil, errors.New("nas: inner PDU too short")
		}
		msg.Header.MessageType = MessageType(inner[2])
		return decodeBody(msg, inner[3:])
	}
}

// Encode serialises a plain NAS PDU.
func Encode(msg *Message) ([]byte, error) {
	body, err := encodeBody(msg)
	if err != nil {
		return nil, err
	}
	out := []byte{
		msg.Header.ExtendedProtocolDiscriminator,
		byte(msg.Header.SecurityHeaderType),
		byte(msg.Header.MessageType),
	}
	return append(out, body...), nil
}

// decodeBody dispatches to the message-specific decoder.
func decodeBody(msg *Message, b []byte) (*Message, error) {
	switch msg.Header.MessageType {
	case MsgTypeRegistrationRequest:
		body, err := DecodeRegistrationRequest(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeRegistrationAccept:
		body, err := DecodeRegistrationAccept(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeRegistrationComplete:
		msg.Body = &RegistrationComplete{}
	case MsgTypeAuthenticationRequest:
		body, err := DecodeAuthenticationRequest(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeAuthenticationResponse:
		body, err := DecodeAuthenticationResponse(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeAuthenticationFailure:
		body, err := DecodeAuthenticationFailure(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeSecurityModeCommand:
		body, err := DecodeSecurityModeCommand(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeSecurityModeComplete:
		body, err := DecodeSecurityModeComplete(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeSecurityModeReject:
		body, err := DecodeSecurityModeReject(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeIdentityRequest:
		body, err := DecodeIdentityRequest(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeIdentityResponse:
		body, err := DecodeIdentityResponse(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeULNASTransport:
		body, err := DecodeULNASTransport(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeDeregistrationRequestUE:
		body, err := DecodeDeregistrationRequest(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeDeregistrationAcceptUE:
		msg.Body = &DeregistrationAcceptUE{}
	case MsgTypeDeregistrationRequestNW:
		msg.Body = &RawBody{Data: b}
	case MsgTypeDeregistrationAcceptNW:
		msg.Body = &RawBody{Data: b}
	case MsgTypeServiceRequest:
		body, err := DecodeServiceRequest(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeServiceAccept:
		msg.Body = &ServiceAccept{}
	case MsgTypeConfigurationUpdateCommand:
		body, err := DecodeConfigurationUpdateCommand(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeConfigurationUpdateComplete:
		body, err := DecodeConfigurationUpdateComplete(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeNetworkSliceSpecificAuthCommand:
		body, err := DecodeNSSAAuthCommand(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeNetworkSliceSpecificAuthComplete:
		body, err := DecodeNSSAAuthComplete(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	case MsgTypeNetworkSliceSpecificAuthResult:
		body, err := DecodeNSSAAuthResult(b)
		if err != nil {
			return nil, err
		}
		msg.Body = body
	default:
		msg.Body = &RawBody{Data: b}
	}
	return msg, nil
}

func encodeBody(msg *Message) ([]byte, error) {
	switch msg.Header.MessageType {
	case MsgTypeAuthenticationRequest:
		b, ok := msg.Body.(*AuthenticationRequest)
		if !ok {
			return nil, fmt.Errorf("nas: body is not AuthenticationRequest")
		}
		return EncodeAuthenticationRequest(b)
	case MsgTypeSecurityModeCommand:
		b, ok := msg.Body.(*SecurityModeCommand)
		if !ok {
			return nil, fmt.Errorf("nas: body is not SecurityModeCommand")
		}
		return EncodeSecurityModeCommand(b)
	case MsgTypeRegistrationReject:
		b, ok := msg.Body.(*RegistrationReject)
		if !ok {
			return nil, fmt.Errorf("nas: body is not RegistrationReject")
		}
		return EncodeRegistrationReject(b)
	case MsgTypeRegistrationAccept:
		b, ok := msg.Body.(*RegistrationAccept)
		if !ok {
			return nil, fmt.Errorf("nas: body is not RegistrationAccept")
		}
		return EncodeRegistrationAccept(b)
	case MsgTypeIdentityRequest:
		b, ok := msg.Body.(*IdentityRequest)
		if !ok {
			return nil, fmt.Errorf("nas: body is not IdentityRequest")
		}
		return EncodeIdentityRequest(b)
	case MsgTypeDLNASTransport:
		b, ok := msg.Body.(*DLNASTransport)
		if !ok {
			return nil, fmt.Errorf("nas: body is not DLNASTransport")
		}
		return EncodeDLNASTransport(b)
	case MsgTypeULNASTransport:
		b, ok := msg.Body.(*ULNASTransport)
		if !ok {
			return nil, fmt.Errorf("nas: body is not ULNASTransport")
		}
		return EncodeULNASTransport(b)
	case MsgTypeDeregistrationAcceptUE:
		d, ok := msg.Body.(*DeregistrationAcceptUE)
		if !ok {
			return nil, fmt.Errorf("nas: body is not DeregistrationAcceptUE")
		}
		return EncodeDeregistrationAcceptUE(d)
	case MsgTypeDeregistrationRequestNW:
		d, ok := msg.Body.(*DeregistrationRequestNW)
		if !ok {
			return nil, fmt.Errorf("nas: body is not DeregistrationRequestNW")
		}
		return EncodeDeregistrationRequestNW(d)
	case MsgTypeServiceAccept:
		sa, ok := msg.Body.(*ServiceAccept)
		if !ok {
			return nil, fmt.Errorf("nas: body is not ServiceAccept")
		}
		return EncodeServiceAccept(sa)
	case MsgTypeServiceReject:
		r, ok := msg.Body.(*ServiceReject)
		if !ok {
			return nil, fmt.Errorf("nas: body is not ServiceReject")
		}
		return EncodeServiceReject(r)
	case MsgTypeConfigurationUpdateCommand:
		c, ok := msg.Body.(*ConfigurationUpdateCommand)
		if !ok {
			return nil, fmt.Errorf("nas: body is not ConfigurationUpdateCommand")
		}
		return EncodeConfigurationUpdateCommand(c)
	case MsgTypeConfigurationUpdateComplete:
		c, ok := msg.Body.(*ConfigurationUpdateComplete)
		if !ok {
			return nil, fmt.Errorf("nas: body is not ConfigurationUpdateComplete")
		}
		return EncodeConfigurationUpdateComplete(c)
	case MsgTypeNetworkSliceSpecificAuthCommand:
		c, ok := msg.Body.(*NSSAAuthCommand)
		if !ok {
			return nil, fmt.Errorf("nas: body is not NSSAAuthCommand")
		}
		return EncodeNSSAAuthCommand(c)
	case MsgTypeNetworkSliceSpecificAuthComplete:
		c, ok := msg.Body.(*NSSAAuthComplete)
		if !ok {
			return nil, fmt.Errorf("nas: body is not NSSAAuthComplete")
		}
		return EncodeNSSAAuthComplete(c)
	case MsgTypeNetworkSliceSpecificAuthResult:
		r, ok := msg.Body.(*NSSAAuthResult)
		if !ok {
			return nil, fmt.Errorf("nas: body is not NSSAAuthResult")
		}
		return EncodeNSSAAuthResult(r)
	default:
		if rb, ok := msg.Body.(*RawBody); ok {
			return rb.Data, nil
		}
		return nil, fmt.Errorf("nas: encode not implemented for %02x", msg.Header.MessageType)
	}
}

// RawBody is used when the specific body parser is not yet implemented.
type RawBody struct {
	Data []byte
}

// ---- Reader helper --------------------------------------------------------

// Reader wraps a byte slice with position tracking for sequential IE decoding.
type Reader struct {
	data []byte
	pos  int
}

func NewReader(data []byte) *Reader { return &Reader{data: data} }

func (r *Reader) Len() int { return len(r.data) - r.pos }

func (r *Reader) ReadByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	b := r.data[r.pos]
	r.pos++
	return b, nil
}

func (r *Reader) PeekByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	return r.data[r.pos], nil
}

func (r *Reader) ReadBytes(n int) ([]byte, error) {
	if r.pos+n > len(r.data) {
		return nil, fmt.Errorf("nas: need %d bytes, have %d", n, r.Len())
	}
	out := r.data[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *Reader) Remaining() []byte {
	return r.data[r.pos:]
}
