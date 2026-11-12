// Package pfcpx extends github.com/wmnsk/go-pfcp (v0.0.14, IE types <= 271)
// with the TS 29.244 V19.x information elements it does not know.
//
// go-pfcp keeps unknown IEs as opaque Type/Length/Payload triples, so this
// package is a thin layer: IE type constants above 271 (types.go), typed
// constructors and parsers built on ie.New / ie.NewGroupedIE (ie.go), a
// grouped-child parser for grouped types go-pfcp does not know (ie.go), and
// the UP/CP Function Features octets up to Rel-19 with bit names
// (features.go). Nothing here changes what go-pfcp emits for IEs it already
// supports; no NF imports this package yet.
//
// Type numbers, names and the grouped set follow TS 29.244 V19.6.0 Table
// 8.1.2-1 (types 272-403); feature bits follow Table 8.2.25-1 and Table
// 8.2.58-1. Where the Wireshark 4.6.9 dissector differs (e.g. 279 "Created
// L2TP Session", UMN6IP/UN6TU order, octet 11 bit 3 PSUPRM), the TS wins.
package pfcpx
