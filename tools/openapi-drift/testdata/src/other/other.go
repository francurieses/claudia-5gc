// Package other is a fixture outside the default unannotated scope.
package other

// Thing has JSON tags and no annotation but is out of scope.
type Thing struct {
	A string `json:"a"`
}
