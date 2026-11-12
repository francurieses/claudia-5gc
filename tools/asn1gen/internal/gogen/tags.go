package gogen

import (
	"strings"
)

// tagSet is the content of an `aper:"..."` struct tag (github.com/free5gc/aper
// common.go parseFieldParameters). Only the keys NGAP needs are modelled.
type tagSet struct {
	openType     bool
	refName      string // referenceFieldName
	valueExt     bool
	refValue     string // referenceFieldValue
	vlb, vub     string
	sizeExt      bool
	slb, sub     string
	optional     bool
	defaultValue string
}

// String renders the tags in a canonical order, matching free5gc where it is consistent:
// openType, referenceFieldName, valueExt, referenceFieldValue, valueLB, valueUB, sizeExt,
// sizeLB, sizeUB, default, optional.
func (t tagSet) String() string {
	var p []string
	if t.openType {
		p = append(p, "openType")
	}
	if t.refName != "" {
		p = append(p, "referenceFieldName:"+t.refName)
	}
	if t.valueExt {
		p = append(p, "valueExt")
	}
	if t.refValue != "" {
		p = append(p, "referenceFieldValue:"+t.refValue)
	}
	if t.vlb != "" {
		p = append(p, "valueLB:"+t.vlb)
	}
	if t.vub != "" {
		p = append(p, "valueUB:"+t.vub)
	}
	if t.sizeExt {
		p = append(p, "sizeExt")
	}
	if t.slb != "" {
		p = append(p, "sizeLB:"+t.slb)
	}
	if t.sub != "" {
		p = append(p, "sizeUB:"+t.sub)
	}
	if t.defaultValue != "" {
		p = append(p, "default:"+t.defaultValue)
	}
	if t.optional {
		p = append(p, "optional")
	}
	return strings.Join(p, ",")
}

// tag renders a struct tag literal, or "" when there is nothing to say.
func (t tagSet) tag() string {
	if s := t.String(); s != "" {
		return " `aper:\"" + s + "\"`"
	}
	return ""
}
