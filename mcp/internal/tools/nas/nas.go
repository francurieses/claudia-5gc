// Package nas implements MCP Group A tools: pure NAS-5GS codec helpers that wrap
// shared/nas. They perform no network I/O and never panic on malformed input —
// every failure is returned as a structured *mcperr.Error with a byte offset
// where applicable. Reference: 3GPP TS 24.501.
package nas

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

// All returns the four Group A tools ready for registration.
func All() []registry.Tool {
	return []registry.Tool{
		DecodeTool{}, EncodeTool{}, IEValidateTool{}, TLVInspectTool{},
	}
}

// ---- helpers --------------------------------------------------------------

// parseHex decodes a hex string, tolerating a leading "0x", whitespace and
// colon separators. A malformed string yields an *mcperr.Error (invalid params).
func parseHex(s string) ([]byte, *mcperr.Error) {
	t := strings.TrimSpace(s)
	t = strings.TrimPrefix(t, "0x")
	t = strings.TrimPrefix(t, "0X")
	t = strings.NewReplacer(" ", "", ":", "", "-", "", "\n", "", "\t", "").Replace(t)
	if t == "" {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "empty hex input", nil)
	}
	b, err := hex.DecodeString(t)
	if err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams,
			map[string]any{"input": s}, "invalid hex: %v", err)
	}
	return b, nil
}

// parseByte accepts a JSON number, a "0x"-prefixed hex string, or a decimal
// string and returns the byte value. Used for message_type / EPD / SHT fields.
func parseByte(v any, field string) (byte, *mcperr.Error) {
	switch x := v.(type) {
	case float64:
		if x < 0 || x > 255 {
			return 0, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{field: v},
				"%s out of byte range", field)
		}
		return byte(x), nil
	case string:
		s := strings.TrimSpace(x)
		base := 10
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			s, base = s[2:], 16
		}
		n, err := strconv.ParseUint(s, base, 8)
		if err != nil {
			return 0, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{field: v},
				"%s is not a valid byte: %v", field, err)
		}
		return byte(n), nil
	default:
		return 0, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{field: v},
			"%s must be a number or hex/decimal string", field)
	}
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

// ---- nas_decode -----------------------------------------------------------

// DecodeTool decodes a NAS-5GS PDU hex string into a structured representation.
type DecodeTool struct{}

func (DecodeTool) Name() string { return "nas_decode" }
func (DecodeTool) Description() string {
	return "Decode a 5GS NAS PDU (hex) into a structured message: protocol discriminator, " +
		"security header, message type (with name + TS 24.501 clause), the typed message body, " +
		"and the raw body bytes. Per 3GPP TS 24.501 §9.1.1."
}
func (DecodeTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"hex":{"type":"string","description":"NAS PDU as a hex string (optional 0x prefix)"}},"required":["hex"]}`)
}
func (DecodeTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"message_type":{"type":"integer"},"message_type_name":{"type":"string"},"spec_ref":{"type":"string"},"protocol_discriminator":{"type":"string"},"security_header_type":{"type":"integer"},"body":{"type":"object"},"raw_body_hex":{"type":"string"}}}`)
}

// DecodeResult is the structured nas_decode output.
type DecodeResult struct {
	ExtendedProtocolDiscriminator byte   `json:"extended_protocol_discriminator"`
	ProtocolDiscriminator         string `json:"protocol_discriminator"`
	SecurityHeaderType            byte   `json:"security_header_type"`
	SecurityHeaderName            string `json:"security_header_name"`
	MAC                           string `json:"mac,omitempty"`
	SequenceNumber                *byte  `json:"sequence_number,omitempty"`
	MessageType                   byte   `json:"message_type"`
	MessageTypeHex                string `json:"message_type_hex"`
	MessageTypeName               string `json:"message_type_name"`
	SpecRef                       string `json:"spec_ref"`
	Body                          any    `json:"body"`
	RawBodyHex                    string `json:"raw_body_hex"`
}

func (DecodeTool) Invoke(_ context.Context, in json.RawMessage) (any, error) {
	var args struct {
		Hex string `json:"hex"`
	}
	if err := json.Unmarshal(in, &args); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "decode args: %v", err)
	}
	data, perr := parseHex(args.Hex)
	if perr != nil {
		return nil, perr
	}
	if len(data) < 3 {
		return nil, mcperr.Newf(mcperr.CodeToolError,
			map[string]any{"offset": len(data), "length": len(data)},
			"NAS PDU too short: need ≥3 bytes, have %d", len(data))
	}

	msg, err := nas.Decode(data)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("nas: decode: %w", err),
			map[string]any{"length": len(data)})
	}

	res := DecodeResult{
		ExtendedProtocolDiscriminator: msg.Header.ExtendedProtocolDiscriminator,
		ProtocolDiscriminator:         epdName(msg.Header.ExtendedProtocolDiscriminator),
		SecurityHeaderType:            byte(msg.Header.SecurityHeaderType),
		SecurityHeaderName:            securityHeaderName(msg.Header.SecurityHeaderType),
		MessageType:                   byte(msg.Header.MessageType),
		MessageTypeHex:                fmt.Sprintf("0x%02x", byte(msg.Header.MessageType)),
		Body:                          msg.Body,
	}
	meta := metaFor(msg.Header.MessageType)
	res.MessageTypeName = meta.Name
	res.SpecRef = meta.SpecRef

	// Recover the raw body bytes (after the message-type byte) for round-tripping.
	if msg.Header.SecurityHeaderType == nas.SecurityHeaderPlainNAS {
		res.RawBodyHex = hex.EncodeToString(data[3:])
	} else if len(data) >= 10 {
		res.MAC = hex.EncodeToString(data[2:6])
		sn := data[6]
		res.SequenceNumber = &sn
		res.RawBodyHex = hex.EncodeToString(data[10:]) // skip MAC(4)+SN(1)+inner EPD/SHT/MT(3)
	}
	return res, nil
}

// ---- nas_encode -----------------------------------------------------------

// EncodeTool assembles a plain NAS-5GS PDU from a header and a raw body, then
// validates the result by re-parsing it. Round-trips nas_decode's raw_body_hex.
type EncodeTool struct{}

func (EncodeTool) Name() string { return "nas_encode" }
func (EncodeTool) Description() string {
	return "Assemble a plain 5GS NAS PDU from an extended protocol discriminator, security " +
		"header type, message type and raw body bytes (hex). Returns the encoded PDU hex and its " +
		"total length, after validating the result re-parses. Per 3GPP TS 24.501 §9.1.1."
}
func (EncodeTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"extended_protocol_discriminator":{"description":"EPD byte; default 0x7e (5GMM)"},"security_header_type":{"description":"Security header type byte; default 0 (plain)"},"message_type":{"description":"Message type byte, hex (0x41) or name"},"body_hex":{"type":"string","description":"Raw message body bytes after the message type"}},"required":["message_type"]}`)
}
func (EncodeTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"hex":{"type":"string"},"length":{"type":"integer"}}}`)
}

func (EncodeTool) Invoke(_ context.Context, in json.RawMessage) (any, error) {
	var args struct {
		EPD     any    `json:"extended_protocol_discriminator"`
		SHT     any    `json:"security_header_type"`
		MsgType any    `json:"message_type"`
		BodyHex string `json:"body_hex"`
	}
	if err := json.Unmarshal(in, &args); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "encode args: %v", err)
	}
	if args.MsgType == nil {
		return nil, mcperr.New(mcperr.CodeInvalidParams, "message_type is required", nil)
	}

	epd := nas.PDMobilityManagement
	if args.EPD != nil {
		b, perr := parseByte(args.EPD, "extended_protocol_discriminator")
		if perr != nil {
			return nil, perr
		}
		epd = b
	}
	var sht byte
	if args.SHT != nil {
		b, perr := parseByte(args.SHT, "security_header_type")
		if perr != nil {
			return nil, perr
		}
		sht = b
	}
	if sht != byte(nas.SecurityHeaderPlainNAS) {
		return nil, mcperr.New(mcperr.CodeInvalidParams,
			"nas_encode only assembles plain NAS (security_header_type must be 0)", nil)
	}
	mt, perr := parseMessageType(args.MsgType)
	if perr != nil {
		return nil, perr
	}

	var body []byte
	if args.BodyHex != "" {
		b, perr := parseHex(args.BodyHex)
		if perr != nil {
			return nil, perr
		}
		body = b
	}

	out := append([]byte{epd, sht, mt}, body...)
	// Validate the assembled PDU re-parses (catches structurally impossible bodies).
	if _, err := nas.Decode(out); err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("nas: encoded PDU does not re-parse: %w", err),
			map[string]any{"length": len(out)})
	}
	return map[string]any{
		"hex":    hex.EncodeToString(out),
		"length": len(out),
	}, nil
}

// parseMessageType accepts a byte (number/hex string) or a known message name.
func parseMessageType(v any) (byte, *mcperr.Error) {
	if s, ok := v.(string); ok {
		if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
			if _, err := strconv.Atoi(s); err != nil {
				// Treat as a message name.
				for mt, meta := range messageMeta {
					if strings.EqualFold(meta.Name, s) {
						return byte(mt), nil
					}
				}
				return 0, mcperr.Newf(mcperr.CodeInvalidParams,
					map[string]any{"message_type": v}, "unknown message type name %q", s)
			}
		}
	}
	return parseByte(v, "message_type")
}

// ---- ie_validate ----------------------------------------------------------

// IEValidateTool walks a TLV-encoded byte sequence and reports the first IE
// whose declared length exceeds the remaining bytes. Assumes the common 8-bit
// tag / 8-bit length (Type-4 TLV) optional-IE format of TS 24.007 §11.2.4.
type IEValidateTool struct{}

func (IEValidateTool) Name() string { return "ie_validate" }
func (IEValidateTool) Description() string {
	return "Validate the TLV length fields of an optional-IE byte sequence (hex). Walks " +
		"[IEI][length][value] entries and flags the first length field that overflows the " +
		"remaining bytes. Per 3GPP TS 24.501 §9 / TS 24.007 §11.2.4 (Type-4 TLV)."
}
func (IEValidateTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"hex":{"type":"string","description":"TLV-encoded optional-IE byte sequence"}},"required":["hex"]}`)
}
func (IEValidateTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"valid":{"type":"boolean"},"ie_count":{"type":"integer"},"errors":{"type":"array","items":{"type":"object"}}}}`)
}

func (IEValidateTool) Invoke(_ context.Context, in json.RawMessage) (any, error) {
	var args struct {
		Hex string `json:"hex"`
	}
	if err := json.Unmarshal(in, &args); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "ie_validate args: %v", err)
	}
	data, perr := parseHex(args.Hex)
	if perr != nil {
		return nil, perr
	}
	entries, validationErrs := walkTLV(data)
	return map[string]any{
		"valid":    len(validationErrs) == 0,
		"ie_count": len(entries),
		"errors":   validationErrs,
	}, nil
}

// ---- tlv_inspect ----------------------------------------------------------

// TLVInspectTool produces an annotated breakdown of a TLV byte sequence without
// semantic decoding. Tolerates malformed input, reporting where parsing breaks.
type TLVInspectTool struct{}

func (TLVInspectTool) Name() string { return "tlv_inspect" }
func (TLVInspectTool) Description() string {
	return "Break a TLV-encoded byte sequence (hex) into annotated entries: byte offset, IEI " +
		"tag, declared length, and value bytes. Stops at the first truncation, reporting the " +
		"offset. Per 3GPP TS 24.007 §11.2.4 (Type-4 TLV)."
}
func (TLVInspectTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"hex":{"type":"string","description":"TLV-encoded byte sequence"}},"required":["hex"]}`)
}
func (TLVInspectTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"entries":{"type":"array","items":{"type":"object"}},"truncated_at":{"type":"integer"}}}`)
}

func (TLVInspectTool) Invoke(_ context.Context, in json.RawMessage) (any, error) {
	var args struct {
		Hex string `json:"hex"`
	}
	if err := json.Unmarshal(in, &args); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "tlv_inspect args: %v", err)
	}
	data, perr := parseHex(args.Hex)
	if perr != nil {
		return nil, perr
	}
	entries, validationErrs := walkTLV(data)
	out := map[string]any{"entries": entries}
	if len(validationErrs) > 0 {
		out["truncated_at"] = validationErrs[0]["offset"]
	}
	return out, nil
}

// tlvEntry is one parsed [tag][length][value] entry.
type tlvEntry struct {
	Offset   int    `json:"offset"`
	IEI      byte   `json:"iei"`
	IEIHex   string `json:"iei_hex"`
	Length   int    `json:"length"`
	ValueHex string `json:"value_hex"`
}

// walkTLV parses data as a stream of 8-bit-tag, 8-bit-length TLV entries.
// It returns the successfully parsed entries and any structural errors (each a
// map carrying offset + message). Parsing stops at the first error.
func walkTLV(data []byte) ([]tlvEntry, []map[string]any) {
	var entries []tlvEntry
	var errs []map[string]any
	pos := 0
	for pos < len(data) {
		iei := data[pos]
		if pos+1 >= len(data) {
			errs = append(errs, map[string]any{
				"offset":  pos,
				"iei_hex": fmt.Sprintf("0x%02x", iei),
				"message": "truncated: tag present but length byte missing",
			})
			break
		}
		length := int(data[pos+1])
		valStart := pos + 2
		if valStart+length > len(data) {
			errs = append(errs, map[string]any{
				"offset":    pos,
				"iei_hex":   fmt.Sprintf("0x%02x", iei),
				"declared":  length,
				"available": len(data) - valStart,
				"message":   "length field overflows remaining bytes",
			})
			break
		}
		entries = append(entries, tlvEntry{
			Offset:   pos,
			IEI:      iei,
			IEIHex:   fmt.Sprintf("0x%02x", iei),
			Length:   length,
			ValueHex: hex.EncodeToString(data[valStart : valStart+length]),
		})
		pos = valStart + length
	}
	return entries, errs
}
