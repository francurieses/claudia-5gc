package nas

import "github.com/francurieses/claudia-5gc/shared/nas"

// msgMeta carries the human-readable name and governing 3GPP clause for a NAS
// message type, surfaced in nas_decode output for traceability.
type msgMeta struct {
	Name    string
	SpecRef string
}

// messageMeta maps every NAS message type this codec recognises to its name and
// TS 24.501 §8 clause. Unknown types fall back to "Unknown" (see metaFor).
var messageMeta = map[nas.MessageType]msgMeta{
	nas.MsgTypeRegistrationRequest:         {"RegistrationRequest", "TS 24.501 §8.2.6"},
	nas.MsgTypeRegistrationAccept:          {"RegistrationAccept", "TS 24.501 §8.2.7"},
	nas.MsgTypeRegistrationComplete:        {"RegistrationComplete", "TS 24.501 §8.2.8"},
	nas.MsgTypeRegistrationReject:          {"RegistrationReject", "TS 24.501 §8.2.9"},
	nas.MsgTypeDeregistrationRequestUE:     {"DeregistrationRequestUEOriginating", "TS 24.501 §8.2.12"},
	nas.MsgTypeDeregistrationAcceptUE:      {"DeregistrationAcceptUEOriginating", "TS 24.501 §8.2.13"},
	nas.MsgTypeDeregistrationRequestNW:     {"DeregistrationRequestNWInitiated", "TS 24.501 §8.2.14"},
	nas.MsgTypeDeregistrationAcceptNW:      {"DeregistrationAcceptNWInitiated", "TS 24.501 §8.2.15"},
	nas.MsgTypeServiceRequest:              {"ServiceRequest", "TS 24.501 §8.2.16"},
	nas.MsgTypeServiceReject:               {"ServiceReject", "TS 24.501 §8.2.18"},
	nas.MsgTypeServiceAccept:               {"ServiceAccept", "TS 24.501 §8.2.17"},
	nas.MsgTypeConfigurationUpdateCommand:  {"ConfigurationUpdateCommand", "TS 24.501 §8.2.19"},
	nas.MsgTypeConfigurationUpdateComplete: {"ConfigurationUpdateComplete", "TS 24.501 §8.2.20"},
	nas.MsgTypeAuthenticationRequest:       {"AuthenticationRequest", "TS 24.501 §8.2.1"},
	nas.MsgTypeAuthenticationResponse:      {"AuthenticationResponse", "TS 24.501 §8.2.2"},
	nas.MsgTypeAuthenticationReject:        {"AuthenticationReject", "TS 24.501 §8.2.3"},
	nas.MsgTypeAuthenticationFailure:       {"AuthenticationFailure", "TS 24.501 §8.2.4"},
	nas.MsgTypeAuthenticationResult:        {"AuthenticationResult", "TS 24.501 §8.2.5"},
	nas.MsgTypeIdentityRequest:             {"IdentityRequest", "TS 24.501 §8.2.10"},
	nas.MsgTypeIdentityResponse:            {"IdentityResponse", "TS 24.501 §8.2.11"},
	nas.MsgTypeSecurityModeCommand:         {"SecurityModeCommand", "TS 24.501 §8.2.25"},
	nas.MsgTypeSecurityModeComplete:        {"SecurityModeComplete", "TS 24.501 §8.2.26"},
	nas.MsgTypeSecurityModeReject:          {"SecurityModeReject", "TS 24.501 §8.2.27"},
	nas.MsgTypeStatus5GMM:                  {"Status5GMM", "TS 24.501 §8.2.24"},
	nas.MsgTypeNotification:                {"Notification", "TS 24.501 §8.2.22"},
	nas.MsgTypeNotificationResponse:        {"NotificationResponse", "TS 24.501 §8.2.23"},
	nas.MsgTypeULNASTransport:              {"ULNASTransport", "TS 24.501 §8.2.10"},
	nas.MsgTypeDLNASTransport:              {"DLNASTransport", "TS 24.501 §8.2.11"},

	nas.MsgTypePDUSessionEstablishmentRequest: {"PDUSessionEstablishmentRequest", "TS 24.501 §8.3.1"},
	nas.MsgTypePDUSessionEstablishmentAccept:  {"PDUSessionEstablishmentAccept", "TS 24.501 §8.3.2"},
	nas.MsgTypePDUSessionEstablishmentReject:  {"PDUSessionEstablishmentReject", "TS 24.501 §8.3.3"},
	nas.MsgTypePDUSessionModificationRequest:  {"PDUSessionModificationRequest", "TS 24.501 §8.3.7"},
	nas.MsgTypePDUSessionModificationCommand:  {"PDUSessionModificationCommand", "TS 24.501 §8.3.9"},
	nas.MsgTypePDUSessionReleaseRequest:       {"PDUSessionReleaseRequest", "TS 24.501 §8.3.12"},
	nas.MsgTypePDUSessionReleaseCommand:       {"PDUSessionReleaseCommand", "TS 24.501 §8.3.14"},
	nas.MsgTypeStatus5GSM:                     {"Status5GSM", "TS 24.501 §8.3.16"},
}

// metaFor returns the metadata for a message type, or a generic fallback.
func metaFor(mt nas.MessageType) msgMeta {
	if m, ok := messageMeta[mt]; ok {
		return m
	}
	return msgMeta{Name: "Unknown", SpecRef: "TS 24.501 §9.7"}
}

// epdName maps an Extended Protocol Discriminator to its protocol group name.
func epdName(epd byte) string {
	switch epd {
	case nas.PDMobilityManagement:
		return "5GMM" // 5GS Mobility Management
	case nas.PDGroupSessionManagement:
		return "5GSM" // 5GS Session Management
	default:
		return "Unknown"
	}
}

// securityHeaderName maps a security header type to its TS 24.501 §9.3 label.
func securityHeaderName(sht nas.SecurityHeaderType) string {
	switch sht {
	case nas.SecurityHeaderPlainNAS:
		return "PlainNAS"
	case nas.SecurityHeaderIntegrityProtected:
		return "IntegrityProtected"
	case nas.SecurityHeaderIntegrityProtectedAndCiphered:
		return "IntegrityProtectedAndCiphered"
	case nas.SecurityHeaderIntegrityProtectedWithNewSC:
		return "IntegrityProtectedWithNewSecurityContext"
	case nas.SecurityHeaderIntegrityProtectedAndCipheredWithNewSC:
		return "IntegrityProtectedAndCipheredWithNewSecurityContext"
	default:
		return "Unknown"
	}
}
