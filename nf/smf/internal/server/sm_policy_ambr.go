package server

// sessRuleAmbr returns the authorized Session-AMBR of a SessionRule JSON object.
// TS 29.512 §5.6.2.7 defines the attribute as authSessAmbr; the legacy
// non-standard "sessAmbr" is accepted as a fallback for older PCFs.
func sessRuleAmbr(rule map[string]interface{}) (map[string]interface{}, bool) {
	if a, ok := rule["authSessAmbr"].(map[string]interface{}); ok {
		return a, true
	}
	a, ok := rule["sessAmbr"].(map[string]interface{})
	return a, ok
}
