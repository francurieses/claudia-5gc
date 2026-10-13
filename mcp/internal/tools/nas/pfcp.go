package nas

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// pfcp_decode parses one PFCP message (N4, TS 29.244 §7) from hex and returns its
// header and the IE tree. It is decode-only.
type pfcpDecodeTool struct{}

func (pfcpDecodeTool) Name() string        { return "pfcp_decode" }
func (pfcpDecodeTool) Risk() registry.Risk { return registry.ReadOnly }
func (pfcpDecodeTool) Description() string {
	return "Decode one PFCP message (N4, TS 29.244) from hex. Returns the message type, SEID, sequence " +
		"and the IE tree (type number and length; grouped IEs nest their children). Decode only. " +
		"Spec: TS 29.244 §7.2 (message format), §8 (IEs)."
}
func (pfcpDecodeTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"hex":{"type":"string","description":"PFCP message as hex, spaces allowed"}},"required":["hex"]}`)
}
func (pfcpDecodeTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"message_type":{},"message_type_name":{},"seid":{},"sequence":{},"ies":{}}}`)
}

// maxIEDepth bounds the recursion over grouped IEs, so a crafted message cannot
// exhaust the stack.
const maxIEDepth = 8

func (pfcpDecodeTool) Invoke(_ context.Context, in json.RawMessage) (any, error) {
	var a struct {
		Hex string `json:"hex"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "pfcp_decode args: %v", err)
	}
	raw, err := hex.DecodeString(strings.Join(strings.Fields(a.Hex), ""))
	if err != nil {
		return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "hex: %v", err)
	}
	msg, err := safePFCPParse(raw)
	if err != nil {
		return nil, mcperr.ToolError(fmt.Errorf("pfcp_decode: %w", err), nil)
	}
	return map[string]any{
		"message_type":      msg.MessageType(),
		"message_type_name": msg.MessageTypeName(),
		"seid":              msg.SEID(),
		"sequence":          msg.Sequence(),
		"ies":               ieTree(msg, 0),
	}, nil
}

func safePFCPParse(raw []byte) (msg pfcpmsg.Message, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("malformed PFCP message: %v", r)
		}
	}()
	return pfcpmsg.Parse(raw)
}

type ieNode struct {
	Name     string   `json:"name"`
	Type     uint16   `json:"type"`
	Length   uint16   `json:"length"`
	Children []ieNode `json:"children,omitempty"`
}

var ieType = reflect.TypeOf(pfcpie.IE{})

// ieTree returns the IE tree of a parsed message. go-pfcp stores each known IE in
// a typed field (NodeID, CreatePDR []*ie.IE, …) in spec order, and unknown IEs in
// IEs. The walk covers every *ie.IE and []*ie.IE field, in struct order, and names
// each node after its field.
func ieTree(msg pfcpmsg.Message, depth int) []ieNode {
	v := deref(reflect.ValueOf(msg))
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return nil
	}
	var out []ieNode
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		name := t.Field(i).Name
		switch {
		case f.Type() == reflect.PointerTo(ieType):
			if e := ieOf(f); e != nil {
				out = append(out, nodeOf(name, *e, depth))
			}
		case f.Type() == reflect.SliceOf(reflect.PointerTo(ieType)):
			for j := 0; j < f.Len(); j++ {
				if e := ieOf(f.Index(j)); e != nil {
					out = append(out, nodeOf(name, *e, depth))
				}
			}
		}
	}
	return out
}

// ieOf returns the IE behind a *ie.IE value, or nil when it is unset.
func ieOf(v reflect.Value) *pfcpie.IE {
	v = deref(v)
	if !v.IsValid() {
		return nil
	}
	e, ok := v.Interface().(pfcpie.IE)
	if !ok {
		return nil
	}
	return &e
}

func nodeOf(name string, e pfcpie.IE, depth int) ieNode {
	n := ieNode{Name: name, Type: e.Type, Length: e.Length}
	if depth < maxIEDepth {
		for _, c := range e.ChildIEs {
			if c != nil {
				n.Children = append(n.Children, nodeOf("", *c, depth+1))
			}
		}
	}
	return n
}
