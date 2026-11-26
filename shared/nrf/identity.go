// Package nrf: identity.go adds the optional FQDN / ipEndPoints / plmnList
// identity an NF advertises when it is addressed by FQDN across PLMNs
// (roaming, TS 23.003 §28.5.1; resolver in nf/sepp/internal/n32f).
package nrf

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
)

// maxFQDNLen and maxLabelLen are the DNS limits (RFC 1035 §2.3.4).
const (
	maxFQDNLen  = 253
	maxLabelLen = 63
)

// ApplyFQDNIdentity stamps profile with fqdn, the SBI port of every service
// (ipEndPoints, so a SEPP can dial https://<fqdn>:<port>) and the plmnList
// attribute (TS 29.510 §6.1.6.2.2). With an empty fqdn it is a no-op, so the
// profile JSON stays byte-identical to the pre-change shape. With a non-empty
// fqdn every input is validated first and the profile is left untouched on
// error: fqdn must be a DNS name (no scheme/port), sbiAddr ("0.0.0.0:8003")
// must carry a numeric port 1-65535, mcc must be 3 digits and mnc 2-3 digits.
func ApplyFQDNIdentity(p *NFProfile, fqdn, sbiAddr, mcc, mnc string) error {
	if p == nil || fqdn == "" {
		return nil
	}
	if err := validateFQDN(fqdn); err != nil {
		return fmt.Errorf("nrf: apply fqdn identity: %w", err)
	}
	_, portStr, err := net.SplitHostPort(sbiAddr)
	if err != nil {
		return fmt.Errorf("nrf: apply fqdn identity: sbi address %q: %w", sbiAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("nrf: apply fqdn identity: sbi port %q not in 1-65535", portStr)
	}
	if !allDigits(mcc, 3, 3) || !allDigits(mnc, 2, 3) {
		return fmt.Errorf("nrf: apply fqdn identity: plmn mcc %q / mnc %q invalid (mcc 3 digits, mnc 2-3 digits)", mcc, mnc)
	}
	raw, err := json.Marshal([]map[string]string{{"mcc": mcc, "mnc": mnc}})
	if err != nil {
		return fmt.Errorf("nrf: apply fqdn identity: marshal plmnList: %w", err)
	}
	p.FQDN = fqdn
	for i := range p.NFServices {
		if len(p.NFServices[i].IPEndpoints) == 0 {
			p.NFServices[i].IPEndpoints = []IPEndpoint{{Port: port}}
		}
	}
	if p.Extra == nil {
		p.Extra = map[string]json.RawMessage{}
	}
	p.Extra["plmnList"] = raw
	return nil
}

// validateFQDN accepts a dot-separated DNS name: labels of 1-63 letters,
// digits or hyphens, not starting/ending with a hyphen; no scheme, port or path.
func validateFQDN(f string) error {
	if len(f) > maxFQDNLen {
		return fmt.Errorf("fqdn longer than %d bytes", maxFQDNLen)
	}
	start := 0
	for i := 0; i <= len(f); i++ {
		if i < len(f) && f[i] != '.' {
			c := f[i]
			ok := c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
			if !ok {
				return fmt.Errorf("fqdn %q: invalid character %q (scheme/port/path not allowed)", f, c)
			}
			continue
		}
		l := f[start:i]
		if l == "" || len(l) > maxLabelLen {
			return fmt.Errorf("fqdn %q: empty or over-long label", f)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("fqdn %q: label %q starts or ends with hyphen", f, l)
		}
		start = i + 1
	}
	return nil
}

func allDigits(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
