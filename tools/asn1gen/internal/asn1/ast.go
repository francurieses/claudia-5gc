package asn1

// Kind is the ASN.1 type constructor of a Type node.
type Kind int

// Type kinds.
const (
	// KindRef is a reference to a named type, possibly with actual parameters.
	KindRef Kind = iota + 1
	// KindInteger is INTEGER.
	KindInteger
	// KindEnumerated is ENUMERATED.
	KindEnumerated
	// KindBitString is BIT STRING.
	KindBitString
	// KindOctetString is OCTET STRING.
	KindOctetString
	// KindCharString is a restricted character string (PrintableString, VisibleString, UTF8String, ...).
	KindCharString
	// KindOID is OBJECT IDENTIFIER.
	KindOID
	// KindNull is NULL.
	KindNull
	// KindBoolean is BOOLEAN.
	KindBoolean
	// KindSequence is SEQUENCE { ... }.
	KindSequence
	// KindSequenceOf is SEQUENCE [SIZE] OF Type.
	KindSequenceOf
	// KindChoice is CHOICE { ... }.
	KindChoice
	// KindClassField is CLASS.&field, optionally constrained by an object set (X.681 clause 9).
	KindClassField
)

// BoundKind says how a range bound is written.
type BoundKind int

// Bound kinds.
const (
	// BoundNone is an absent bound (used for open ranges).
	BoundNone BoundKind = iota
	// BoundNum is a literal number.
	BoundNum
	// BoundName is a reference to a value (constant or parameter).
	BoundName
	// BoundMin is MIN.
	BoundMin
	// BoundMax is MAX.
	BoundMax
)

// Bound is one end of a value or size range.
type Bound struct {
	Kind BoundKind
	// Num is the numeric value (math.MaxInt64 when the literal overflows int64).
	Num int64
	// Lit is the literal text of a BoundNum, kept for values above MaxInt64.
	Lit  string
	Name string
}

// Range is lo..hi (or a single value when Single is set). Ext reports a trailing ", ...".
type Range struct {
	Lo, Hi Bound
	Single bool
	Ext    bool
	// ExtAdditions are the ranges written after the extension marker; PER ignores them
	// (only the root range is a PER-visible bound), the parser records them for fidelity.
	ExtAdditions []*Range
}

// Constraint collects the subtype constraints of a type that matter for PER.
type Constraint struct {
	// Value is the value-range constraint of an INTEGER, if any.
	Value *Range
	// Size is the SIZE constraint, if any.
	Size *Range
	// Containing is the type named by (CONTAINING T), if any.
	Containing string
	// ObjectSets lists the object-set names of table constraints such as ({Set}{@id}).
	ObjectSets []string
}

// Value is a literal number or a value reference.
type Value struct {
	Num   int64
	Name  string // non-empty for a reference
	IsNum bool
}

// Arg is an actual parameter of a parameterised type reference.
type Arg struct {
	// ObjectSet is the set name for an actual parameter written {{Set}} or {Set}.
	ObjectSet string
	// Value is the parameter for a value argument (number or value reference).
	Value *Value
}

// Component is a SEQUENCE component or a CHOICE alternative.
type Component struct {
	Name     string
	Type     *Type
	Optional bool
	Default  *Value
	// ExtAddition is set for components written after the extension marker.
	ExtAddition bool
	Line        int
}

// Enumerator is one item of an ENUMERATED type.
type Enumerator struct {
	Name string
	// Value is the explicit number, or -1 when implicit.
	Value int64
	// ExtAddition is set for enumerators written after the extension marker.
	ExtAddition bool
}

// Type is a node of the type tree.
type Type struct {
	Kind Kind
	Line int

	Constraint Constraint

	// CharString is the name of the restricted string type (KindCharString).
	CharString string

	// Components holds SEQUENCE components or CHOICE alternatives.
	Components []Component
	// Extensible reports an extension marker "..." (SEQUENCE, CHOICE, ENUMERATED).
	Extensible bool

	Enums []Enumerator

	// Elem is the element type of a SEQUENCE OF.
	Elem *Type

	// Ref and Args describe a KindRef.
	Ref  string
	Args []Arg

	// ClassName and ClassField describe a KindClassField (CLASS.&field).
	ClassName  string
	ClassField string
}

// Param is a formal parameter of a parameterised type: "Governor : Name".
type Param struct {
	Governor string // class name, INTEGER, or a type name
	Name     string
}

// TypeAssign is "Name [{params}] ::= Type".
type TypeAssign struct {
	Name   string
	Params []Param
	Type   *Type
	Line   int
}

// ValueAssign is "name Type ::= value".
type ValueAssign struct {
	Name  string
	Type  string
	Value Value
	Line  int
}

// ClassField is one field of an information-object class (X.681 clause 9).
type ClassField struct {
	// Name is the field name without the leading '&'.
	Name string
	// IsType is true for type fields (&Value): no governing type, initial capital.
	IsType bool
	// Type is the governing type name of a fixed-type value field.
	Type     string
	Unique   bool
	Optional bool
	Default  string
}

// Class is "NAME ::= CLASS { &f ..., } WITH SYNTAX { ... }".
type Class struct {
	Name   string
	Fields []ClassField
	// Syntax maps a WITH SYNTAX keyword phrase (e.g. "INITIATING MESSAGE") to a field name.
	Syntax map[string]string
	Line   int
}

// ObjField is one "KEYWORD value" entry of an object, keyed by class field name.
type ObjField struct {
	Value *Value // value fields (ID, CRITICALITY, ...)
	Type  *Type  // type fields (TYPE, EXTENSION, INITIATING MESSAGE, ...)
}

// ObjElem is an element of an object set: a reference to another set/object, an inline
// object, or the extension marker.
type ObjElem struct {
	Ref      string
	Inline   map[string]ObjField
	InlineLn int
	Ellipsis bool
}

// Object is "name CLASS ::= { ... }": a single object (Fields set) or an object set (Elems).
type Object struct {
	Name   string
	Class  string
	Fields map[string]ObjField
	Elems  []ObjElem
	IsSet  bool
	Line   int
}

// Import is one "a, b FROM Module" group.
type Import struct {
	Module string
	Names  []string
}

// Module is one ASN.1 module.
type Module struct {
	Name    string
	File    string
	Imports []Import
	// Order lists the assignment names in source order, tagged by kind.
	Order   []Ref
	Types   map[string]*TypeAssign
	Values  map[string]*ValueAssign
	Classes map[string]*Class
	Objects map[string]*Object
}

// RefKind tags an entry of Module.Order.
type RefKind int

// Assignment kinds in Module.Order.
const (
	// RefType is a type assignment.
	RefType RefKind = iota + 1
	// RefValue is a value assignment.
	RefValue
	// RefClass is a class definition.
	RefClass
	// RefObject is an object or object-set assignment.
	RefObject
)

// Ref identifies an assignment in a module.
type Ref struct {
	Kind RefKind
	Name string
}
