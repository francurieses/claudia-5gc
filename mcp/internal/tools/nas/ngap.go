package nas

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// ngap_decode decodes one NGAP PDU (N2, TS 38.413 §9) from hex. It is decode-only:
// nothing is encoded or sent. Output lists the procedure, the message and each IE
// in wire order, so a capture can be compared with what the spec or a RAN expects.
//
// The IE list is read by reflection over the free5gc ngapType structs, so the
// tool does not need a per-message table. That keeps it correct for every message.
type ngapDecodeTool struct{}

func (ngapDecodeTool) Name() string        { return "ngap_decode" }
func (ngapDecodeTool) Risk() registry.Risk { return registry.ReadOnly }
func (ngapDecodeTool) Description() string {
	return "Decode one NGAP PDU (N2, ASN.1 aligned PER, TS 38.413) from hex. Returns the PDU kind, " +
		"procedure code, criticality and the IEs in wire order with their ids and criticality. " +
		"Decode only: nothing is sent. Use it to inspect N2 messages from a capture. " +
		"Spec: TS 38.413 §9.2 (message structure), §9.3 (IEs)."
}
func (ngapDecodeTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"hex":{"type":"string","description":"NGAP PDU as hex, spaces allowed"}},"required":["hex"]}`)
}
func (ngapDecodeTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"pdu_type":{},"procedure_code":{},"criticality":{},"message":{},"ies":{}}}`)
}

// ngapIENames covers the IE ids of the messages this core handles. Other ids are
// reported as unknown rather than guessed.
var ngapIENames = map[int64]string{
	1:  "AMF-Name",
	10: "AMF-UE-NGAP-ID",
	15: "RelativeAMFCapacity",
	27: "Global-RAN-NodeID",
	38: "NAS-PDU",
	80: "PLMNSupportList",
	85: "RAN-UE-NGAP-ID",
	96: "ServedGUAMIList",
}

var ngapPDUKinds = map[int]string{1: "initiatingMessage", 2: "successfulOutcome", 3: "unsuccessfulOutcome"}

func (ngapDecodeTool) Invoke(_ context.Context, in json.RawMessage) (any, error) {
	var a struct {
		Hex string `json:"hex"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "ngap_decode args: %v", err)
	}
	raw, err := hex.DecodeString(strings.Join(strings.Fields(a.Hex), ""))
	if err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "hex: %v", err)
	}
	pdu, err := safeNGAPDecode(raw)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("ngap_decode: %w", err), nil)
	}
	return describeNGAP(pdu)
}

// safeNGAPDecode turns a decoder panic on hostile input into an error.
func safeNGAPDecode(raw []byte) (pdu *ngapType.NGAPPDU, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("malformed NGAP PDU: %v", r)
		}
	}()
	return libngap.Decoder(raw)
}

func describeNGAP(pdu *ngapType.NGAPPDU) (any, error) {
	kind := ngapPDUKinds[pdu.Present]
	var code, crit int64
	var body reflect.Value
	switch pdu.Present {
	case 1:
		code, crit = pdu.InitiatingMessage.ProcedureCode.Value, int64(pdu.InitiatingMessage.Criticality.Value)
		body = reflect.ValueOf(pdu.InitiatingMessage.Value)
	case 2:
		code, crit = pdu.SuccessfulOutcome.ProcedureCode.Value, int64(pdu.SuccessfulOutcome.Criticality.Value)
		body = reflect.ValueOf(pdu.SuccessfulOutcome.Value)
	case 3:
		code, crit = pdu.UnsuccessfulOutcome.ProcedureCode.Value, int64(pdu.UnsuccessfulOutcome.Criticality.Value)
		body = reflect.ValueOf(pdu.UnsuccessfulOutcome.Value)
	default:
		return nil, mcperr.Newf(mcperr.CodeToolError, map[string]any{"present": pdu.Present},
			"unknown NGAP PDU choice %d", pdu.Present)
	}

	msgName, list, ok := findProtocolIEs(body)
	out := map[string]any{
		"pdu_type":       kind,
		"procedure_code": code,
		"criticality":    crit,
		"message":        msgName,
		"ies":            []map[string]any{},
	}
	if !ok {
		return out, nil
	}
	ies := make([]map[string]any, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		el := deref(list.Index(i))
		id := intField(deref(el.FieldByName("Id")), "Value")
		c := intField(deref(el.FieldByName("Criticality")), "Value")
		name, known := ngapIENames[id]
		if !known {
			name = "unknown"
		}
		ies = append(ies, map[string]any{"id": id, "name": name, "criticality": c})
	}
	out["ies"] = ies
	out["ie_count"] = len(ies)
	return out, nil
}

// findProtocolIEs walks a *XxxValue choice struct to the one message that is set,
// then returns its name and the ProtocolIEs list.
func findProtocolIEs(body reflect.Value) (string, reflect.Value, bool) {
	v := deref(body)
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return "", reflect.Value{}, false
	}
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() != reflect.Pointer || f.IsNil() {
			continue
		}
		msg := deref(f)
		if msg.Kind() != reflect.Struct {
			continue
		}
		pie := deref(msg.FieldByName("ProtocolIEs"))
		if !pie.IsValid() {
			continue
		}
		list := pie.FieldByName("List")
		if list.Kind() != reflect.Slice {
			continue
		}
		return v.Type().Field(i).Name, list, true
	}
	return "", reflect.Value{}, false
}

func deref(v reflect.Value) reflect.Value {
	for v.IsValid() && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) {
		if v.IsNil() {
			return reflect.Value{}
		}
		v = v.Elem()
	}
	return v
}

// intField reads an integer field of a struct value, or 0 when absent.
func intField(v reflect.Value, name string) int64 {
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return 0
	}
	f := v.FieldByName(name)
	switch f.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return f.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int64(f.Uint())
	}
	return 0
}
