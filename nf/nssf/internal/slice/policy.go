// Package slice implements the NSSF slice selection policy.
// The MVP uses a static configuration table; future versions may query UDR.
//
// Ref: TS 23.501 §5.15.2, TS 29.531 §5.2.2.2
package slice

// SliceID identifies a network slice by SST and SD.
type SliceID struct {
	SST int
	SD  string
}

// Store holds the NSSF's static slice policy.
type Store struct {
	allowed []SliceID
}

// New creates a Store from a list of allowed slices.
func New(allowed []SliceID) *Store {
	return &Store{allowed: allowed}
}

// SelectForRegistration returns the intersection of requested and allowed slices.
// If requested is empty, all allowed slices are returned.
// Ref: TS 23.502 §4.2.9.1
func (s *Store) SelectForRegistration(requested []SliceID) []SliceID {
	if len(requested) == 0 {
		return append([]SliceID(nil), s.allowed...)
	}
	var result []SliceID
	for _, a := range s.allowed {
		for _, r := range requested {
			if r.SST != a.SST {
				continue
			}
			// SD=="" in requested is a wildcard: matches any SD with the same SST.
			if r.SD == "" || r.SD == a.SD {
				result = append(result, a)
				break
			}
		}
	}
	return result
}
