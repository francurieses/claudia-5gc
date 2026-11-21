package nasmsg

import "errors"

// 5GMM causes carried in the PDU session reactivation result error cause IE
// (IEI 0x72). Ref: TS 24.501 §5.6.1.4.1 a)-f), §9.11.3.43, §9.11.3.2.
const (
	// causeInsufficientUPResources is 5GMM cause #92 "insufficient user-plane
	// resources for the PDU session": the generic user-plane re-activation
	// failure (SMF error, UPF not responding, transport error, empty N2 SM info).
	causeInsufficientUPResources = uint8(92)
	// causeUnspecifiedProtocolError is 5GMM cause #111 "protocol error,
	// unspecified": the flagged PSI is unknown, has no SM context or was
	// released locally, so there is no user plane to re-establish.
	causeUnspecifiedProtocolError = uint8(111)
	// causeNotInLADNServiceArea is 5GMM cause #43 "LADN not available" (UE
	// outside the LADN service area).
	causeNotInLADNServiceArea = uint8(43)
	// causeInsufficientResourcesSlice is 5GMM cause #69 "insufficient resources
	// for specific slice" (S-NSSAI unavailable due to NSAC).
	causeInsufficientResourcesSlice = uint8(69)
)

// SMF application causes (TS 29.502 Table 5.2.7.3-1) that map to a dedicated
// 5GMM cause in the reactivation result error cause IE.
const (
	smfCauseUENonLADNServiceArea = "UE_IN_NON_LADN_SERVICE_AREA"
	smfCausePrioritizedServices  = "PRIORITIZED_SERVICES_ONLY"
	smfCauseNSACUnavailable      = "S-NSSAI_UNAVAILABLE_DUE_TO_NSAC"
)

// smfCauseError is implemented by SMF client errors that carry the
// ProblemDetails application cause of the failed UpdateSMContext.
type smfCauseError interface {
	SMFApplicationCause() string
}

// reactivationErrorCause maps an ActivateSMContext failure to the 5GMM cause of
// the PDU session reactivation result error cause IE: #43 / #28 / #69 for the
// matching SMF application cause, #92 for everything else (no body, transport
// error, empty n2SmInfo, UPF_NOT_RESPONDING, ...).
// Ref: TS 24.501 §5.6.1.4.1 a)-f)
func reactivationErrorCause(err error) uint8 {
	var ce smfCauseError
	if errors.As(err, &ce) {
		switch ce.SMFApplicationCause() {
		case smfCauseUENonLADNServiceArea:
			return causeNotInLADNServiceArea
		case smfCausePrioritizedServices:
			return causeRestrictedServiceArea
		case smfCauseNSACUnavailable:
			return causeInsufficientResourcesSlice
		}
	}
	return causeInsufficientUPResources
}
