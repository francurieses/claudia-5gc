// Package server implements the UDM HTTP/2 SBI server.
//
// Services implemented:
//
//	Nudm_UEAuthentication — GetAuthData (POST): generates 5G HE AV for AUSF
//	Nudm_SDM              — Get (GET): returns AM data / SM data to AMF
//	Nudm_SDM              — Subscribe/Notify: subscription CRUD + data-change callbacks
//	Nudm_UECM             — Registration (PUT): AMF registers serving network
//
// Ref: 3GPP TS 29.503 v17.x
package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	udmsbi "github.com/francurieses/claudia-5gc/nf/udm/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/aka"
	"github.com/francurieses/claudia-5gc/shared/capability"
	suciPkg "github.com/francurieses/claudia-5gc/shared/crypto/suci"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
	"github.com/francurieses/claudia-5gc/shared/sbi"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
	"github.com/francurieses/claudia-5gc/shared/types"
)

// SdmSubscription is the spec-literal body of Nudm_SDM_Subscribe (Rel-19
// profile response, and the normalised in-memory form of every subscription).
// Ref: TS 29.503 §6.1.6.2.3 (Type: SdmSubscription)
//
// oapi: TS29503_Nudm_SDM.yaml#/components/schemas/SdmSubscription
type SdmSubscription struct {
	NfInstanceID          string   `json:"nfInstanceId,omitempty"`
	CallbackRef           string   `json:"callbackReference"`
	MonitoredResourceURIs []string `json:"monitoredResourceUris,omitempty"`
	SubscriptionID        string   `json:"subscriptionId,omitempty"`
	ImplicitUnsub         bool     `json:"implicitUnsubscribe,omitempty"`
	// SupportedFeatures is the consumer's value on the request and the
	// negotiated answer on the response. Ref: TS 29.503 §6.1.6.2.3.
	SupportedFeatures string `json:"supportedFeatures,omitempty"`
	// negotiated is the Nudm_SDM feature set negotiated for this subscription
	// (TS 29.500 §6.6.2); kept on the resource context, never serialised.
	negotiated features.Set
}

// sdmSubscriptionRequest decodes the POST body in either shape: the schema's
// monitoredResourceUris array (embedded SdmSubscription) or the legacy
// singular monitoredResourceUri string sent by Rel-17-profile consumers.
//
// oapi: none decode-only superset of SdmSubscription that also accepts the legacy Rel-17-profile attribute monitoredResourceUri
type sdmSubscriptionRequest struct {
	SdmSubscription
	LegacyMonitoredResourceURI string `json:"monitoredResourceUri,omitempty"`
}

// sdmSubscriptionRel17 is the frozen Rel-17-profile subscription response
// (singular monitoredResourceUri). Field order is part of the baseline bytes.
//
// oapi: none legacy Rel-17-profile wire shape of SdmSubscription, see SdmSubscription
type sdmSubscriptionRel17 struct {
	NfInstanceID      string `json:"nfInstanceId,omitempty"`
	CallbackRef       string `json:"callbackReference"`
	MonitoredResURI   string `json:"monitoredResourceUri,omitempty"`
	SubscriptionID    string `json:"subscriptionId,omitempty"`
	ImplicitUnsub     bool   `json:"implicitUnsubscribe,omitempty"`
	SupportedFeatures string `json:"supportedFeatures,omitempty"`
}

// legacyView renders sub in the Rel-17-profile shape (first monitored URI).
func (sub *SdmSubscription) legacyView() sdmSubscriptionRel17 {
	v := sdmSubscriptionRel17{
		NfInstanceID:      sub.NfInstanceID,
		CallbackRef:       sub.CallbackRef,
		SubscriptionID:    sub.SubscriptionID,
		ImplicitUnsub:     sub.ImplicitUnsub,
		SupportedFeatures: sub.SupportedFeatures,
	}
	if len(sub.MonitoredResourceURIs) > 0 {
		v.MonitoredResURI = sub.MonitoredResourceURIs[0]
	}
	return v
}

// ModificationNotification is the spec-literal body POSTed to the callback URI
// under the Rel-19 profile. Ref: TS 29.503 §6.1.6.2.21 (Type: ModificationNotification)
//
// oapi: TS29503_Nudm_SDM.yaml#/components/schemas/ModificationNotification
type ModificationNotification struct {
	NotifyItems    []NotifyItem `json:"notifyItems"`
	SubscriptionID string       `json:"subscriptionId,omitempty"`
}

// NotifyItem indicates the changes on one resource; resourceId is the absolute
// URI of the changed resource. Ref: TS 29.571 §5.2.4.9 (Type NotifyItem)
//
// oapi: TS29571_CommonData.yaml#/components/schemas/NotifyItem
type NotifyItem struct {
	ResourceID string       `json:"resourceId"`
	Changes    []ChangeItem `json:"changes"`
}

// ChangeItem describes a single change. Ref: TS 29.571 §5.2.4.8 (Type ChangeItem)
//
// oapi: TS29571_CommonData.yaml#/components/schemas/ChangeItem
type ChangeItem struct {
	Op        string `json:"op"`             // ADD | MOVE | REMOVE | REPLACE
	Path      string `json:"path"`           // JSON Pointer (RFC 6901)
	From      string `json:"from,omitempty"` // source pointer, MOVE only
	OrigValue any    `json:"origValue,omitempty"`
	NewValue  any    `json:"newValue,omitempty"`
}

// changeNewValueRequired is true for the ops whose newValue "shall be present"
// (the null value being allowed). Ref: TS 29.571 §5.2.4.8.
func changeNewValueRequired(op string) bool { return op == opAdd || op == opReplace }

// MarshalJSON emits newValue as null when the op requires it but the value is
// not known to the UDM (e.g. the whole resource was replaced).
func (c ChangeItem) MarshalJSON() ([]byte, error) {
	type withNull struct {
		Op        string `json:"op"`
		Path      string `json:"path"`
		From      string `json:"from,omitempty"`
		OrigValue any    `json:"origValue,omitempty"`
		NewValue  any    `json:"newValue"`
	}
	type plain struct {
		Op        string `json:"op"`
		Path      string `json:"path"`
		From      string `json:"from,omitempty"`
		OrigValue any    `json:"origValue,omitempty"`
		NewValue  any    `json:"newValue,omitempty"`
	}
	if changeNewValueRequired(c.Op) {
		return json.Marshal(withNull(c))
	}
	return json.Marshal(plain(c))
}

// legacyModificationNotification is the frozen Rel-17-profile notification
// body (resourceChanges); not a schema of TS29503_Nudm_SDM.yaml.
//
// oapi: none legacy Rel-17-profile wire shape of ModificationNotification, see ModificationNotification
type legacyModificationNotification struct {
	ResourceChanges []legacyChangeItem `json:"resourceChanges"`
}

// legacyChangeItem is the Rel-17-profile change entry and also the accepted
// input element of the internal data-change trigger.
//
// oapi: none legacy Rel-17-profile wire shape of ChangeItem, see ChangeItem
type legacyChangeItem struct {
	ChangeType    string `json:"changeType"`              // ADD | REMOVE | REPLACE
	ResourcePath  string `json:"resourcePath"`            // JSON Pointer
	NewValue      any    `json:"newValue,omitempty"`      // value after change
	OriginalValue any    `json:"originalValue,omitempty"` // value before change
}

// triggerChange is one element of the internal data-change trigger body: the
// legacy change entry plus the optional MOVE source pointer, which only the
// Rel-19 conversion uses (the Rel-17 body forwards the legacy fields verbatim).
//
// oapi: none internal (non-3GPP) data-change trigger input, see ChangeItem
type triggerChange struct {
	legacyChangeItem
	From string `json:"from,omitempty"`
}

// ChangeItem op values. Ref: TS 29.571 §5.2.4.8 (ChangeType: ADD, MOVE, REMOVE, REPLACE).
const (
	opAdd     = "ADD"
	opMove    = "MOVE"
	opRemove  = "REMOVE"
	opReplace = "REPLACE"
)

// normaliseOp maps a trigger changeType to a TS 29.571 ChangeType value: the
// four op names (case-insensitive) and the legacy aliases CREATE, UPDATE and
// DELETE. ok is false for any other value.
func normaliseOp(changeType string) (op string, ok bool) {
	switch strings.ToUpper(changeType) {
	case opAdd, "CREATE":
		return opAdd, true
	case opMove:
		return opMove, true
	case opRemove, "DELETE":
		return opRemove, true
	case opReplace, "UPDATE":
		return opReplace, true
	}
	return "", false
}

// sdmResourcePrefix marks a trigger resourcePath whose path component is a
// Nudm_SDM resource URI (the trigger default) rather than a JSON pointer
// inside the resource.
const sdmResourcePrefix = "/nudm-sdm/"

// resourcePathComponent returns the URI path of s when s is an absolute URI,
// else s unchanged, with any trailing slash removed.
func resourcePathComponent(s string) string {
	if u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != "" {
		s = u.Path
	}
	if len(s) > 1 {
		s = strings.TrimSuffix(s, "/")
	}
	return s
}

// toNotifyItems converts trigger changes to the TS 29.571 NotifyItem shape for
// one subscription. A resourcePath whose path component is a Nudm_SDM resource
// URI (relative or absolute) names the changed resource and yields path "";
// any other value is a JSON pointer within the am-data resource of supi.
// resourceId is the absolute URI the subscriber monitors: the entry of
// sub.MonitoredResourceURIs whose path component equals the changed resource,
// else apiRoot + the resource path. Items sharing a resourceId are grouped in
// first-seen order. Ref: TS 29.571 §5.2.4.8-9, TS 29.503 §6.1.6.2.3.
func toNotifyItems(supi, apiRoot string, monitored []string, in []triggerChange) ([]NotifyItem, error) {
	var out []NotifyItem
	idx := map[string]int{}
	for _, c := range in {
		op, ok := normaliseOp(c.ChangeType)
		if !ok {
			return nil, fmt.Errorf("udm: unknown changeType %q", c.ChangeType)
		}
		if op == opMove && c.From == "" {
			return nil, fmt.Errorf("udm: changeType MOVE requires from")
		}
		resPath, path := "/nudm-sdm/v2/"+supi+"/am-data", c.ResourcePath
		if rp := resourcePathComponent(c.ResourcePath); strings.HasPrefix(rp, sdmResourcePrefix) {
			resPath, path = rp, ""
		}
		rid := apiRoot + resPath
		for _, m := range monitored {
			if resourcePathComponent(m) == resPath {
				rid = m
				break
			}
		}
		i, ok := idx[rid]
		if !ok {
			i = len(out)
			idx[rid] = i
			out = append(out, NotifyItem{ResourceID: rid})
		}
		out[i].Changes = append(out[i].Changes, ChangeItem{
			Op: op, Path: path, From: c.From, OrigValue: c.OriginalValue, NewValue: c.NewValue,
		})
	}
	return out, nil
}

// AuthType / AvType wire values. Ref: TS 29.503 §6.3.6.3.3 (Enumeration: AuthType),
// §6.3.6.3.4 (Enumeration: AvType).
const (
	authType5GAKA       = "5G_AKA"
	authTypeEAPAKAPrime = "EAP_AKA_PRIME"
	avType5GHEAKA       = "5G_HE_AKA"
	avTypeEAPAKAPrime   = "EAP_AKA_PRIME"
)

// AuthenticationInfoResult is the spec-literal generate-auth-data answer
// (Rel-19 profile). Ref: TS 29.503 §6.3.6.2.3 (Type: AuthenticationInfoResult)
//
// oapi: TS29503_Nudm_UEAU.yaml#/components/schemas/AuthenticationInfoResult
type AuthenticationInfoResult struct {
	AuthType             string                `json:"authType"`
	SupportedFeatures    string                `json:"supportedFeatures,omitempty"`
	AuthenticationVector *AuthenticationVector `json:"authenticationVector,omitempty"`
	Supi                 string                `json:"supi,omitempty"`
}

// AuthenticationVector carries either an Av5GHeAka (avType 5G_HE_AKA) or an
// AvEapAkaPrime (avType EAP_AKA_PRIME); the unused member attributes are
// omitted. Ref: TS 29.503 §6.3.6.2.4 (AvEapAkaPrime), §6.3.6.2.5 (Av5GHeAka); oneOf discriminated by avType.
//
// oapi: TS29503_Nudm_UEAU.yaml#/components/schemas/AuthenticationVector
type AuthenticationVector struct {
	AvType   string `json:"avType"`
	Rand     string `json:"rand"`
	Autn     string `json:"autn"`
	XresStar string `json:"xresStar,omitempty"` // 5G_HE_AKA
	Kausf    string `json:"kausf,omitempty"`    // 5G_HE_AKA
	Xres     string `json:"xres,omitempty"`     // EAP_AKA_PRIME
	CkPrime  string `json:"ckPrime,omitempty"`  // EAP_AKA_PRIME
	IkPrime  string `json:"ikPrime,omitempty"`  // EAP_AKA_PRIME
}

// UDRClient calls the UDR for subscription data.
type UDRClient interface {
	GetAuthSubscription(ctx context.Context, supi string) (*UDRAuthSub, error)
	UpdateSQN(ctx context.Context, supi, newSQN string) error
	GetAMData(ctx context.Context, supi string) (*UDRAMData, error)
	// GetSMData returns the raw SessionManagementSubscriptionData array
	// (TS 29.503 §6.1.6.2.7). Returns nil, nil when not provisioned.
	GetSMData(ctx context.Context, supi string) (json.RawMessage, error)
}

// UDRAuthSub mirrors the UDR authentication subscription structure.
type UDRAuthSub struct {
	AuthMethod string
	K          string // hex
	OPc        string // hex
	AMF        string // hex (2 bytes)
	SQN        string // hex (6 bytes)
	AlgID      string // "milenage"
}

// UDRAMData holds AM subscription data from the UDR.
//
// oapi: none internal normalised view of the Nudr am-data answer (not a wire body)
type UDRAMData struct {
	SNSSAIs                  []SNSSAIEntry
	AMBRUplink, AMBRDownlink uint64
	// GPSIs are the subscriber's Gpsi values decoded from the UDR answer
	// (AccessAndMobilitySubscriptionData.gpsis, TS 29.503 §6.1.6.2.4). Only
	// well-formed entries (TS 29.571 §5.3.2 pattern) are kept. The omitempty
	// keeps the marshalled form of a record without GPSIs unchanged.
	GPSIs []string `json:",omitempty"`
}

type SNSSAIEntry struct {
	SST int
	SD  string
	DNN string // portal-assigned preferred DNN (empty = no preference)
	// SubjectToNSSAA mirrors the subscription flag
	// subjectToNetworkSliceSpecificAuthenticationAndAuthorization (TS 23.501 §5.15.10).
	SubjectToNSSAA bool
}

// TLSConfig holds TLS configuration for the server.
type TLSConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// Server is the UDM SBI server.
type Server struct {
	udr     UDRClient
	logger  *slog.Logger
	httpSrv *http.Server
	addr    string
	// Serving network name (for KAUSF derivation)
	snName string
	// homeNetPrivKeyA is the Home Network X25519 private key for SUCI Profile A.
	// Zero value = Profile A not enabled; SUCI with protectionScheme=1 will be rejected.
	// Ref: TS 33.501 §6.12, Annex C.3
	homeNetPrivKeyA    [32]byte
	homeNetPrivKeyASet bool
	// homeNetPrivKeyB is the Home Network secp256r1 private scalar for SUCI
	// Profile B; nil = Profile B not enabled (501).
	// Ref: TS 33.501 §6.12, Annex C.3.4
	homeNetPrivKeyB []byte
	// hnKeyIDA / hnKeyIDB are the Home Network Public Key Identifiers of the
	// X25519 / P-256 key pairs; 0 = any identifier accepted.
	// Ref: TS 23.003 §2.2B, TS 33.501 Annex C.1
	hnKeyIDA, hnKeyIDB uint8

	// SDM subscription store — keyed by SUPI.
	// Value type: []*SdmSubscription.
	// Ref: TS 29.503 §5.3.2
	subscriptions   sync.Map
	subscriptionIdx sync.Map // subscriptionId → supi
	notifyClient    *http.Client

	// profile gates the supportedFeatures wire behaviour (decisions D1/D2,
	// dev/REL19_PROGRAM.md §2); nil behaves as rel17.
	profile *capability.Profile
	// ueauCat is the Nudm_UEAU producer catalog.
	ueauCat *features.Catalog
	// sdmCat / uecmCat are the Nudm_SDM and Nudm_UECM producer catalogs.
	sdmCat  *features.Catalog
	uecmCat *features.Catalog
}

// SetProfile wires the release profile used for supportedFeatures negotiation.
// Must be called before Start(). Ref: TS 29.500 §6.6.2.
func (s *Server) SetProfile(p *capability.Profile) { s.profile = p }

// SetUEAUCatalog replaces the Nudm_UEAU catalog (tests inject catalogs with
// Implemented entries); nil restores the default. Must be called before Start().
func (s *Server) SetUEAUCatalog(c *features.Catalog) {
	if c == nil {
		c = udmsbi.NudmUEAUCatalog()
	}
	s.ueauCat = c
}

// SetSDMCatalog replaces the Nudm_SDM catalog (tests inject catalogs with
// Implemented entries); nil restores the default. Must be called before Start().
func (s *Server) SetSDMCatalog(c *features.Catalog) {
	if c == nil {
		c = udmsbi.NudmSDMCatalog()
	}
	s.sdmCat = c
}

// SetUECMCatalog replaces the Nudm_UECM catalog (tests inject catalogs with
// Implemented entries); nil restores the default. Must be called before Start().
func (s *Server) SetUECMCatalog(c *features.Catalog) {
	if c == nil {
		c = udmsbi.NudmUECMCatalog()
	}
	s.uecmCat = c
}

func loadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("cert/key not configured")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
		KeyLogWriter: sbi.OpenKeyLogWriter(),
	}, nil
}

// New builds the UDM server.
func New(addr, snName string, tlsCfg TLSConfig, udr UDRClient, logger *slog.Logger) (*Server, error) {
	s := &Server{
		udr:          udr,
		logger:       logger.With("nf", "UDM"),
		addr:         addr,
		snName:       snName,
		notifyClient: &http.Client{Timeout: 5 * time.Second},
		ueauCat:      udmsbi.NudmUEAUCatalog(),
		sdmCat:       udmsbi.NudmSDMCatalog(),
		uecmCat:      udmsbi.NudmUECMCatalog(),
	}
	return newWithServer(s, tlsCfg)
}

// WithNotifyClient replaces the HTTP client used for SDM notification callbacks.
// Useful in tests to inject a plain-HTTP client when TLS is not available.
func (s *Server) WithNotifyClient(c *http.Client) *Server {
	s.notifyClient = c
	return s
}

// WithHomeNetPrivKeyA loads the Home Network X25519 private key (hex-encoded) for
// SUCI Profile A deconcealment. If not set, Profile A SUCI deconcealment returns 501.
// Ref: TS 33.501 §6.12, Annex C.3
func (s *Server) WithHomeNetPrivKeyA(hexKey string) error {
	if hexKey == "" {
		return nil
	}
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Errorf("udm: invalid hn_private_key_x25519: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("udm: hn_private_key_x25519 must be 32 bytes, got %d", len(b))
	}
	copy(s.homeNetPrivKeyA[:], b)
	s.homeNetPrivKeyASet = true
	s.logger.Info("UDM: SUCI Profile A (X25519) enabled",
		"spec_ref", "TS 33.501 §6.12 Annex C.3")
	return nil
}

// WithHomeNetPrivKeyB loads the Home Network secp256r1 private scalar
// (hex-encoded, 32 bytes) for SUCI Profile B de-concealment. Empty = disabled
// (Profile B SUCI is answered 501).
// Ref: TS 33.501 §6.12, Annex C.3.4
func (s *Server) WithHomeNetPrivKeyB(hexKey string) error {
	if hexKey == "" {
		return nil
	}
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Errorf("udm: invalid hn_private_key_p256: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("udm: hn_private_key_p256 must be 32 bytes, got %d", len(b))
	}
	// Reject a zero scalar or a scalar >= the curve order n at load time.
	if _, err := ecdh.P256().NewPrivateKey(b); err != nil {
		return fmt.Errorf("udm: hn_private_key_p256 is not a valid P-256 scalar: %w", err)
	}
	s.homeNetPrivKeyB = b
	s.logger.Info("UDM: SUCI Profile B (secp256r1) enabled",
		"spec_ref", "TS 33.501 §6.12 Annex C.3.4")
	return nil
}

// WithHNKeyIDs sets the Home Network Public Key Identifiers of the Profile A
// (X25519) and Profile B (P-256) key pairs. 0 accepts any identifier.
// Ref: TS 33.501 Annex C.1
func (s *Server) WithHNKeyIDs(x25519, p256 uint8) *Server {
	s.hnKeyIDA, s.hnKeyIDB = x25519, p256
	if s.homeNetPrivKeyASet && x25519 == 0 {
		s.logger.Warn("UDM: hn_private_key_x25519 set but hn_key_id_x25519 is 0; any SUCI key identifier is accepted",
			"spec_ref", "TS 23.003 §2.2B")
	}
	if s.homeNetPrivKeyB != nil && p256 == 0 {
		s.logger.Warn("UDM: hn_private_key_p256 set but hn_key_id_p256 is 0; any SUCI key identifier is accepted",
			"spec_ref", "TS 23.003 §2.2B")
	}
	return s
}

// ProblemDetails causes of the SIDF (SUCI de-concealment) failures.
// Ref: TS 29.503 §6.3.7.3 Table 6.3.7.3-1 (Nudm_UEAuthentication application
// errors), TS 29.500 §5.2.7.2 Table 5.2.7.2-1 (generic causes).
const (
	// causeMandatoryIEIncorrect: malformed SUCI path parameter (400).
	causeMandatoryIEIncorrect = "MANDATORY_IE_INCORRECT"
	// causeUnsupportedProtectionScheme: unknown or unconfigured protection
	// scheme (501, TS 29.503 Table 6.3.7.3-1).
	causeUnsupportedProtectionScheme = "UNSUPPORTED_PROTECTION_SCHEME"
	// causeInvalidHNPublicKeyID: unknown Home Network Public Key Identifier
	// (403, TS 29.503 Table 6.3.7.3-1).
	causeInvalidHNPublicKeyID = "INVALID_HN_PUBLIC_KEY_IDENTIFIER"
	// causeInvalidSchemeOutput: scheme output cannot be de-concealed (403,
	// TS 29.503 Table 6.3.7.3-1).
	causeInvalidSchemeOutput = "INVALID_SCHEME_OUTPUT"
	// causeUnsupportedSUPIType: SUCI of a SUPI type other than IMSI. TS 29.503
	// Table 6.3.7.3-1 defines no cause for it, so the 501 carries no "cause"
	// attribute (a project-invented cause string is not allowed).
	causeUnsupportedSUPIType = ""
)

// Fixed ProblemDetails details: never echo the SUCI or a crypto error.
const (
	detailInvalidSUCI         = "supiOrSuci is not a valid SUCI"
	detailInvalidSchemeOutput = "SUCI scheme output could not be de-concealed"
	detailUnsupportedSUPIType = "SUPI type of the SUCI is not supported"
	detailInvalidHNKeyID      = "unknown home network public key identifier"
	detailSchemeNotConfigured = "SUCI protection scheme not configured"
	detailSchemeUnsupported   = "SUCI protection scheme not supported"
)

// invalidParamSUCI is the invalidParams entry of a malformed SUCI: it is the
// URI path variable supiOrSuci of GenerateAuthData (TS 29.503 §6.3.3.2), so
// the plain variable name is the param (TS 29.500 §5.2.7.2 Table 5.2.7.2-1
// NOTE 1: invalidParams is mandatory for MANDATORY_IE_INCORRECT).
var invalidParamSUCI = []map[string]string{{"param": "supiOrSuci"}}

// maskSUCI renders a SUCI for logs: scheme output of Profile A/B is replaced
// (keeping the scheme, key id and routing indicator); the null scheme and
// unparsable input never reveal the MSIN either.
func maskSUCI(p types.SUCI) string {
	p.SchemeOutput = "<concealed>"
	return p.String()
}

// shownSupiOrSuci returns the identifier as it may appear in logs and spans:
// a SUPI unchanged, a parsable SUCI with the scheme output masked, an
// unparsable SUCI-prefixed value as a fixed placeholder.
func shownSupiOrSuci(id string) string {
	if !types.IsSUCI(id) {
		return id
	}
	p, err := types.ParseSUCI(id)
	if err != nil {
		return "suci-<malformed>"
	}
	return maskSUCI(p)
}

// sidfProblem writes a SIDF ProblemDetails. invalidParams is set only for 400.
func (s *Server) sidfProblem(w http.ResponseWriter, status int, cause, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	body := map[string]any{"status": status, "detail": detail}
	if cause != "" {
		body["cause"] = cause
	}
	if status == http.StatusBadRequest {
		body["invalidParams"] = invalidParamSUCI
	}
	_ = json.NewEncoder(w).Encode(body)
}

// deconceal resolves a standard-format SUCI (TS 29.571 §5.3.2) to a SUPI
// (SIDF, TS 33.501 §6.12). On failure it writes the ProblemDetails response
// and returns ok=false. Error causes follow TS 29.503 Table 6.3.7.3-1.
func (s *Server) deconceal(w http.ResponseWriter, log *slog.Logger, supi string) (string, bool) {
	parsed, err := types.ParseSUCI(supi)
	if err != nil {
		log.Error("SUCI parse failed", "error", err, "result", "REJECT")
		s.sidfProblem(w, http.StatusBadRequest, causeMandatoryIEIncorrect, detailInvalidSUCI)
		return "", false
	}
	masked := maskSUCI(parsed)
	log = log.With("scheme", parsed.ProtectionScheme, "hn_key_id", parsed.HNPublicKeyID,
		"routing_indicator", parsed.RoutingIndicator)
	if parsed.SUPIType != types.SUPITypeIMSI {
		log.Error("SUCI SUPI type not supported", "supi_type", parsed.SUPIType)
		s.sidfProblem(w, http.StatusNotImplemented, causeUnsupportedSUPIType, detailUnsupportedSUPIType)
		return "", false
	}

	switch parsed.ProtectionScheme {
	case types.SUCISchemeNull:
		actual, err := parsed.SUPI()
		if err != nil {
			return s.invalidOutput(w, log, err)
		}
		log.Info("SUCI deconcealed (null scheme)", "suci", masked, "supi", actual,
			"spec_ref", "TS 33.501 §6.12")
		return actual, true
	case types.SUCISchemeProfileA:
		if !s.homeNetPrivKeyASet {
			log.Error("SUCI Profile A received but hn_private_key_x25519 not configured")
			s.sidfProblem(w, http.StatusNotImplemented, causeUnsupportedProtectionScheme, detailSchemeNotConfigured)
			return "", false
		}
		if !s.checkHNKeyID(w, log, parsed, s.hnKeyIDA) {
			return "", false
		}
		ls, err := toLegacySUCI(parsed)
		if err != nil {
			return s.invalidOutput(w, log, err)
		}
		res, err := suciPkg.DeconceaProfileA(ls, s.homeNetPrivKeyA)
		if err != nil {
			return s.invalidOutput(w, log, err)
		}
		log.Info("SUCI deconcealed (Profile A / X25519)", "suci", masked, "supi", res.SUPI,
			"spec_ref", "TS 33.501 §6.12 Annex C.3")
		return res.SUPI, true
	case types.SUCISchemeProfileB:
		if s.homeNetPrivKeyB == nil {
			log.Error("SUCI Profile B received but hn_private_key_p256 not configured")
			s.sidfProblem(w, http.StatusNotImplemented, causeUnsupportedProtectionScheme, detailSchemeNotConfigured)
			return "", false
		}
		if !s.checkHNKeyID(w, log, parsed, s.hnKeyIDB) {
			return "", false
		}
		ls, err := toLegacySUCI(parsed)
		if err != nil {
			return s.invalidOutput(w, log, err)
		}
		res, err := suciPkg.DeconceaProfileB(ls, s.homeNetPrivKeyB)
		if err != nil {
			return s.invalidOutput(w, log, err)
		}
		log.Info("SUCI deconcealed (Profile B / secp256r1)", "suci", masked, "supi", res.SUPI,
			"spec_ref", "TS 33.501 §6.12 Annex C.3.4")
		return res.SUPI, true
	default:
		log.Error("SUCI protection scheme not supported")
		s.sidfProblem(w, http.StatusNotImplemented, causeUnsupportedProtectionScheme, detailSchemeUnsupported)
		return "", false
	}
}

// checkHNKeyID verifies the SUCI's Home Network Public Key Identifier against
// the configured one (0 = any accepted). It writes the 403 answer on mismatch.
func (s *Server) checkHNKeyID(w http.ResponseWriter, log *slog.Logger, p types.SUCI, want uint8) bool {
	if want != 0 && p.HNPublicKeyID != want {
		log.Error("SUCI home network public key id mismatch", "configured_key_id", want)
		s.sidfProblem(w, http.StatusForbidden, causeInvalidHNPublicKeyID, detailInvalidHNKeyID)
		return false
	}
	return true
}

// invalidOutput answers 403 INVALID_SCHEME_OUTPUT with a fixed detail; the
// real (crypto) error only goes to the log.
func (s *Server) invalidOutput(w http.ResponseWriter, log *slog.Logger, err error) (string, bool) {
	log.Error("SUCI de-concealment failed", "error", err, "result", "REJECT")
	s.sidfProblem(w, http.StatusForbidden, causeInvalidSchemeOutput, detailInvalidSchemeOutput)
	return "", false
}

// toLegacySUCI converts the parsed SUCI to the shared/crypto/suci input form.
func toLegacySUCI(p types.SUCI) (suciPkg.SUCI, error) {
	out, err := p.SchemeOutputBytes()
	if err != nil {
		return suciPkg.SUCI{}, err
	}
	return suciPkg.SUCI{
		SUPIFormat: 0, MCC: p.MCC, MNC: p.MNC,
		RoutingIndicator:       p.RoutingIndicator,
		ProtectionScheme:       suciPkg.Profile(p.ProtectionScheme),
		HomeNetworkPublicKeyID: p.HNPublicKeyID,
		SchemeOutput:           out,
	}, nil
}

func newWithServer(s *Server, tlsCfg TLSConfig) (*Server, error) {
	mux := http.NewServeMux()

	// Nudm_UEAuthentication
	mux.HandleFunc("POST /nudm-ueau/v1/{supi}/security-information/generate-auth-data",
		s.handleGenerateAuthData)

	// Nudm_SDM: AM data
	mux.HandleFunc("GET /nudm-sdm/v2/{supi}/am-data",
		s.handleGetAMData)

	// Nudm_SDM: SM data — session management subscription with subscribed
	// default QoS, consumed by the SMF over N10 (TS 29.503 §6.1.6.2.7)
	mux.HandleFunc("GET /nudm-sdm/v2/{supi}/sm-data",
		s.handleGetSMData)
	// Nudm_SDM: LCS location privacy data — allow-all stub for dev.
	// Consumed by LMF before disclosing a UE's location to an LCS client.
	// Ref: TS 29.503 §5.2.2, TS 23.273 §9.1.
	mux.HandleFunc("GET /nudm-sdm/v2/{supi}/lcs-privacy-data",
		s.handleGetLcsPrivacyData)

	// Nudm_SDM: Subscribe / Unsubscribe (TS 29.503 §5.3.2)
	mux.HandleFunc("POST /nudm-sdm/v2/{supi}/sdm-subscriptions",
		s.handleSDMSubscribe)
	mux.HandleFunc("DELETE /nudm-sdm/v2/{supi}/sdm-subscriptions/{subscriptionId}",
		s.handleSDMUnsubscribe)

	// Nudm_UECM: AMF registration / deregistration
	mux.HandleFunc("PUT /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access",
		s.handleAMFRegistration)
	mux.HandleFunc("DELETE /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access",
		s.handleAMFDeregistration)

	// Internal: data-change trigger — called by UDR or management tools to fan
	// out Nudm_SDM_Notify to all active subscribers for a SUPI.
	// Ref: TS 29.503 §5.3.3
	mux.HandleFunc("POST /nudm-mgmt/v1/{supi}/data-change",
		s.handleDataChangeTrigger)

	mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Load TLS config
	var tlsConfig *tls.Config
	if tlsCfg.CertFile != "" && tlsCfg.KeyFile != "" {
		var err error
		tlsConfig, err = loadTLSConfig(tlsCfg.CertFile, tlsCfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS config: %w", err)
		}
	} else {
		s.logger.Warn("TLS not configured, using H2C (DEV ONLY)", "cert_file", tlsCfg.CertFile)
	}

	s.httpSrv = &http.Server{
		Addr:              s.addr,
		Handler:           otelhttp.NewHandler(s.middleware(mux), "UDM"),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

// Start runs the server.
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("UDM SBI server listening", "addr", s.addr, "tls", s.httpSrv.TLSConfig != nil)
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutCtx)
	}()
	var err error
	if s.httpSrv.TLSConfig != nil {
		_ = http2.ConfigureServer(s.httpSrv, &http2.Server{})
		err = s.httpSrv.ListenAndServeTLS("", "")
	} else {
		s.httpSrv.Handler = h2c.NewHandler(s.httpSrv.Handler, &http2.Server{})
		err = s.httpSrv.ListenAndServe()
	}
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ---- Nudm_UEAuthentication (TS 29.503 §5.2.2.2) -------------------------
// POST /nudm-ueau/v1/{supiOrSuci}/security-information/generate-auth-data
func (s *Server) handleGenerateAuthData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi") // may be SUPI or SUCI (UDM resolves)

	spanCtx, span := tracing.Tracer("UDM", "procedures").Start(r.Context(), "Nudm_UEAuthentication_Get")
	shown := shownSupiOrSuci(supi)
	span.SetAttributes(attribute.String("supi_or_suci", shown))
	defer span.End()
	r = r.WithContext(spanCtx)

	log := s.logger.With(
		"procedure", "GenerateAuthData",
		"interface", "Nudm",
		"direction", "IN",
		"supi_or_suci", shown,
		"correlation_id", r.Header.Get("X-Correlation-Id"),
		"spec_ref", "TS 29.503 §5.2.2.2",
	)

	var req struct {
		ServingNetworkName    string `json:"servingNetworkName"`
		AUSFInstanceID        string `json:"ausfInstanceId,omitempty"`
		ResynchronizationInfo *struct {
			RAND string `json:"rand"`
			AUTS string `json:"auts"`
		} `json:"resynchronizationInfo,omitempty"`
		// SupportedFeatures: TS 29.503 §6.1.6.2.2 (AuthenticationInfoRequest).
		SupportedFeatures string `json:"supportedFeatures,omitempty"`
	}
	// The middleware sets the correlation id on the response header when the
	// request had none.
	corrID := r.Header.Get("X-Correlation-Id")
	if corrID == "" {
		corrID = w.Header().Get("X-Correlation-Id")
	}
	fctx := logging.WithCorrelationID(r.Context(), corrID)
	r.Body = http.MaxBytesReader(w, r.Body, features.MaxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if features.IsTypeError(err) {
			s.rejectSupportedFeatures(fctx, w, "AUSF", s.ueauCat, "<non-string>", err)
			return
		}
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			payloadTooLarge(w)
			return
		}
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", err.Error())
		return
	}
	// supportedFeatures must be schema-valid before any state is touched.
	// Ref: TS 29.500 §5.2.7.2, §6.6.2.
	if err := features.Validate(req.SupportedFeatures); err != nil {
		s.rejectSupportedFeatures(fctx, w, "AUSF", s.ueauCat, req.SupportedFeatures, err)
		return
	}
	// Producer side (decision D1): the intersection, absent under rel17 when
	// the request had none, "0" under rel19.
	sfAnswer, sfSet := features.Answer(s.ueauCat, s.profile, req.SupportedFeatures)
	features.LogNegotiation(fctx, s.logger, features.Negotiation{
		NF:        "UDM",
		Interface: "Nudm", Direction: "IN", PeerNF: "AUSF",
		SpecRef: features.SpecRef, Result: "OK",
		Local: s.ueauCat.Supported(s.profile), Peer: req.SupportedFeatures,
		PeerPresent: req.SupportedFeatures != "", Negotiated: sfSet,
	})
	log = log.With("serving_net", req.ServingNetworkName)
	if req.ResynchronizationInfo != nil {
		log.Info("GenerateAuthData re-sync request received",
			"spec_ref", "TS 33.501 §6.1.3.2 step 11")
	} else {
		log.Info("GenerateAuthData request received")
	}

	// SUCI deconcealment — TS 33.501 §6.12
	// The AMF passes the SUCI as received from the UE. UDM resolves it to a SUPI.
	actualSUPI := supi
	if types.IsSUCI(supi) {
		resolved, ok := s.deconceal(w, log, supi)
		if !ok {
			return
		}
		actualSUPI = resolved
	}

	span.SetAttributes(attribute.String("supi", actualSUPI))

	// Fetch authentication subscription from UDR
	authSub, err := s.udr.GetAuthSubscription(fctx, actualSUPI)
	if err != nil {
		log.Error("UDR auth subscription fetch failed", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "UDR fetch failed")
		s.problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND",
			fmt.Sprintf("subscriber not found: %v", err))
		return
	}

	// Parse credentials
	k, err := aka.ParseHexKey(authSub.K)
	if err != nil {
		log.Error("invalid K", "error", err)
		s.problem(w, http.StatusInternalServerError, "NF_FAILURE", "invalid K")
		return
	}
	opc, err := aka.ParseHexKey(authSub.OPc)
	if err != nil {
		log.Error("invalid OPc", "error", err)
		s.problem(w, http.StatusInternalServerError, "NF_FAILURE", "invalid OPc")
		return
	}
	sqn, err := aka.ParseHexSQN(authSub.SQN)
	if err != nil {
		log.Error("invalid SQN", "error", err)
		sqn = [6]byte{0, 0, 0, 0, 0, 1} // default
	}
	amf, err := aka.ParseHexAMF(authSub.AMF)
	if err != nil {
		log.Error("invalid AMF", "error", err)
		amf = [2]byte{0x80, 0x00}
	}

	// If resynchronizationInfo is present, recover SQN_MS from AUTS and use
	// SQN_MS+1 as the starting SQN for the new AV.
	// Ref: TS 33.501 §C.2, TS 33.501 §6.1.3.2 step 11
	if ri := req.ResynchronizationInfo; ri != nil {
		randHex, err := hex.DecodeString(ri.RAND)
		if err != nil || len(randHex) != 16 {
			s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "invalid resync RAND")
			return
		}
		autsHex, err := hex.DecodeString(ri.AUTS)
		if err != nil || len(autsHex) != 14 {
			s.problem(w, http.StatusBadRequest, "MANDATORY_IE_INCORRECT", "invalid AUTS length")
			return
		}
		sqnMS, err := aka.ResyncFromAUTS(k, opc, [16]byte(randHex), [14]byte(autsHex))
		if err != nil {
			log.Warn("AUTS verification failed", "error", err,
				"spec_ref", "TS 33.501 §C.2")
			s.problem(w, http.StatusForbidden, "AUTHENTICATION_REJECTED", err.Error())
			return
		}
		sqn = aka.IncrementSQN(sqnMS)
		log.Info("SQN recovered from AUTS and incremented",
			"sqn_ms", hex.EncodeToString(sqnMS[:]),
			"new_sqn", hex.EncodeToString(sqn[:]),
			"spec_ref", "TS 33.501 §C.2",
		)
	}

	// Generate 5G HE AV via Milenage + KDF
	snName := req.ServingNetworkName
	if snName == "" {
		snName = s.snName
	}

	// EAP-AKA' branch (TS 33.501 §6.1.3.1): when the subscriber's authentication
	// method is EAP_AKA_PRIME, the UDM/ARPF returns the transformed AV (CK'/IK')
	// and the AUSF runs the EAP method. Ref: TS 33.402 Annex A.2.
	if authSub.AuthMethod == "EAP_AKA_PRIME" {
		eapAV, err := aka.GenerateEAPAKAPrime(aka.HEAVInput{
			SUPI: actualSUPI, K: k, OPc: opc, AMF: amf, SQN: sqn,
		}, snName)
		if err != nil {
			log.Error("GenerateEAPAKAPrime failed", "error", err)
			s.problem(w, http.StatusInternalServerError, "NF_FAILURE", err.Error())
			return
		}
		newSQN := aka.IncrementSQN(sqn)
		if err := s.udr.UpdateSQN(r.Context(), actualSUPI, hex.EncodeToString(newSQN[:])); err != nil {
			log.Warn("SQN update failed (non-fatal)", "error", err)
		}
		span.SetStatus(codes.Ok, "")
		log.Info("EAP-AKA' transformed AV generated, returning to AUSF",
			"direction", "OUT", "supi", actualSUPI, "auth_type", "EAP_AKA_PRIME",
			"spec_ref", "TS 33.501 §6.1.3.1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if features.SpecLiteral(s.profile) {
			// Rel-19 profile: spec-literal AuthenticationInfoResult with the
			// nested AvEapAkaPrime. Ref: TS 29.503 §6.3.6.2.3, §6.3.6.2.4.
			err := json.NewEncoder(w).Encode(AuthenticationInfoResult{
				AuthType:          authTypeEAPAKAPrime,
				SupportedFeatures: sfAnswer,
				AuthenticationVector: &AuthenticationVector{
					AvType:  avTypeEAPAKAPrime,
					Rand:    hex.EncodeToString(eapAV.RAND[:]),
					Autn:    hex.EncodeToString(eapAV.AUTN[:]),
					Xres:    hex.EncodeToString(eapAV.XRES[:]),
					CkPrime: hex.EncodeToString(eapAV.CKPrime[:]),
					IkPrime: hex.EncodeToString(eapAV.IKPrime[:]),
				},
				Supi: actualSUPI,
			})
			if err != nil {
				log.Error("generate-auth-data: encode response", "error", err, "spec_ref", "TS 29.503 §6.3.6.2.3")
			}
			return
		}
		eapRsp := map[string]any{
			"authType": "EAP_AKA_PRIME",
			"rand":     hex.EncodeToString(eapAV.RAND[:]),
			"autn":     hex.EncodeToString(eapAV.AUTN[:]),
			"xres":     hex.EncodeToString(eapAV.XRES[:]),
			"ckPrime":  hex.EncodeToString(eapAV.CKPrime[:]),
			"ikPrime":  hex.EncodeToString(eapAV.IKPrime[:]),
			"supi":     actualSUPI,
		}
		if sfAnswer != "" {
			eapRsp["supportedFeatures"] = sfAnswer
		}
		_ = json.NewEncoder(w).Encode(eapRsp)
		return
	}

	heav, err := aka.GenerateFull(aka.HEAVInput{
		SUPI: actualSUPI,
		K:    k,
		OPc:  opc,
		AMF:  amf,
		SQN:  sqn,
	}, snName)
	if err != nil {
		log.Error("GenerateFull failed", "error", err)
		s.problem(w, http.StatusInternalServerError, "NF_FAILURE", err.Error())
		return
	}

	// Increment SQN and store (non-time-based scheme)
	newSQN := aka.IncrementSQN(sqn)
	newSQNHex := hex.EncodeToString(newSQN[:])
	if err := s.udr.UpdateSQN(r.Context(), actualSUPI, newSQNHex); err != nil {
		log.Warn("SQN update failed (non-fatal)", "error", err)
	}

	span.SetStatus(codes.Ok, "")
	log.Info("5G HE AV generated, returning to AUSF",
		"direction", "OUT",
		"supi", actualSUPI,
		"spec_ref", "TS 33.501 §6.1.3.2 step 3",
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if features.SpecLiteral(s.profile) {
		// Rel-19 profile: spec-literal AuthenticationInfoResult with the
		// nested Av5GHeAka. HXRES* is not a UDM output; the AUSF derives it
		// from RAND and XRES* (TS 33.501 Annex A.5). Ref: TS 29.503 §6.3.6.2.3.
		err := json.NewEncoder(w).Encode(AuthenticationInfoResult{
			AuthType:          authType5GAKA,
			SupportedFeatures: sfAnswer,
			AuthenticationVector: &AuthenticationVector{
				AvType:   avType5GHEAKA,
				Rand:     hex.EncodeToString(heav.RAND[:]),
				Autn:     hex.EncodeToString(heav.AUTN[:]),
				XresStar: hex.EncodeToString(heav.XRESStar),
				Kausf:    hex.EncodeToString(heav.KAUSF),
			},
			Supi: actualSUPI,
		})
		if err != nil {
			log.Error("generate-auth-data: encode response", "error", err, "spec_ref", "TS 29.503 §6.3.6.2.3")
		}
		return
	}
	rsp := map[string]any{
		"authType":  "5G_AKA",
		"rand":      hex.EncodeToString(heav.RAND[:]),
		"autn":      hex.EncodeToString(heav.AUTN[:]),
		"xresStar":  hex.EncodeToString(heav.XRESStar),
		"hxresStar": hex.EncodeToString(heav.HRESStar),
		"kausf":     hex.EncodeToString(heav.KAUSF),
		"supi":      actualSUPI,
	}
	if sfAnswer != "" {
		rsp["supportedFeatures"] = sfAnswer
	}
	_ = json.NewEncoder(w).Encode(rsp)
}

// rejectSupportedFeatures answers a schema-invalid supportedFeatures body
// attribute with 400 INVALID_MSG_FORMAT and invalidParams[{param:
// /supportedFeatures}] and logs the REJECT negotiation record for the API
// owning cat. Ref: TS 29.500 §5.2.7.2; TS 29.571 §5.2.4.6.
func (s *Server) rejectSupportedFeatures(ctx context.Context, w http.ResponseWriter, peerNF string,
	cat *features.Catalog, shown string, cause error) {
	features.LogNegotiation(ctx, s.logger, features.Negotiation{
		NF:        "UDM",
		Interface: "Nudm", Direction: "IN", PeerNF: peerNF,
		SpecRef: features.SpecRefInvalid, Result: "REJECT", Cause: features.CauseInvalidMsgFormat,
		Local: cat.Supported(s.profile), Peer: shown, PeerPresent: true,
	}, "error", cause)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": http.StatusBadRequest,
		"cause":  features.CauseInvalidMsgFormat,
		"detail": "supportedFeatures is not a valid hexadecimal string",
		"invalidParams": []map[string]string{
			{"param": features.ParamSupportedFeatures},
		},
	})
}

// querySupportedFeatures is the optional "supported-features" query parameter
// of the Nudm_SDM Get operations. Ref: TS 29.503 §6.1.3 (resource tables).
const querySupportedFeatures = "supported-features"

// correlationCtx returns a context carrying the request's correlation id; the
// middleware sets it on the response header when the request had none.
func correlationCtx(w http.ResponseWriter, r *http.Request) context.Context {
	corrID := r.Header.Get("X-Correlation-Id")
	if corrID == "" {
		corrID = w.Header().Get("X-Correlation-Id")
	}
	return logging.WithCorrelationID(r.Context(), corrID)
}

// negotiateQuery runs the producer side of TS 29.500 §6.6.2 for a Nudm_SDM Get
// whose consumer offers its features in the optional "supported-features"
// query parameter. A non-hex value is answered 400
// OPTIONAL_QUERY_PARAM_INCORRECT (TS 29.500 Table 5.2.7.2-1) and ok is false.
// answer is "" when the attribute must be omitted (decision D1).
func (s *Server) negotiateQuery(w http.ResponseWriter, r *http.Request, cat *features.Catalog) (answer string, ok bool) {
	ctx := correlationCtx(w, r)
	peerNF := features.PeerNFTypeFromUserAgent(r.UserAgent(), "UNKNOWN")
	q := r.URL.Query()
	peer := q.Get(querySupportedFeatures)
	if err := features.Validate(peer); err != nil {
		features.LogNegotiation(ctx, s.logger, features.Negotiation{
			NF:        "UDM",
			Interface: "Nudm", Direction: "IN", PeerNF: peerNF,
			SpecRef: features.SpecRefInvalid, Result: "REJECT", Cause: features.CauseOptionalQueryParamIncorrect,
			Local: cat.Supported(s.profile), Peer: peer, PeerPresent: true,
		}, "error", err)
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": http.StatusBadRequest,
			"cause":  features.CauseOptionalQueryParamIncorrect,
			"detail": "supported-features is not a valid hexadecimal string",
			"invalidParams": []map[string]string{
				{"param": features.ParamQuerySupportedFeatures},
			},
		})
		return "", false
	}
	answer, set := features.Answer(cat, s.profile, peer)
	features.LogNegotiation(ctx, s.logger, features.Negotiation{
		NF:        "UDM",
		Interface: "Nudm", Direction: "IN", PeerNF: peerNF,
		SpecRef: features.SpecRef, Result: "OK",
		Local: cat.Supported(s.profile), Peer: peer,
		PeerPresent: peer != "", Negotiated: set,
	})
	return answer, true
}

// ---- Nudm_SDM Get (TS 29.503 §5.2.2.2) ----------------------------------
func (s *Server) handleGetAMData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.logger.With("procedure", "GetAMData", "supi", supi)
	log.Info("GetAMData request", "direction", "IN")

	// Optional supported-features query (TS 29.500 §6.6.2); answered in
	// AccessAndMobilitySubscriptionData.supportedFeatures (TS 29.503 §6.1.6.2.4).
	sfAnswer, ok := s.negotiateQuery(w, r, s.sdmCat)
	if !ok {
		return
	}

	amData, err := s.udr.GetAMData(correlationCtx(w, r), supi)
	if err != nil {
		s.problem(w, http.StatusNotFound, "RESOURCE_URI_STRUCTURE_NOT_FOUND", err.Error())
		return
	}

	snssais := make([]map[string]any, 0)
	for _, s := range amData.SNSSAIs {
		entry := map[string]any{"sst": s.SST}
		if s.SD != "" {
			entry["sd"] = s.SD
		}
		if s.DNN != "" {
			entry["dnn"] = s.DNN
		}
		if s.SubjectToNSSAA {
			// TS 23.501 §5.15.10 — slice requires Network Slice-Specific Auth & Authz.
			entry["subjectToNetworkSliceSpecificAuthenticationAndAuthorization"] = true
		}
		snssais = append(snssais, entry)
	}
	w.Header().Set("Content-Type", "application/json")
	rsp := map[string]any{
		"nssai": map[string]any{
			"defaultSingleNssais": snssais,
		},
		"subscribedUeAmbr": map[string]any{
			"uplink":   fmt.Sprintf("%d Kbps", amData.AMBRUplink),
			"downlink": fmt.Sprintf("%d Kbps", amData.AMBRDownlink),
		},
	}
	// gpsis (TS 29.503 §6.1.6.2.4): spec-literal Rel-19 profile only (AMF-020);
	// the legacy profile never emits it, whatever the UDR answered.
	if features.SpecLiteral(s.profile) && len(amData.GPSIs) > 0 {
		rsp["gpsis"] = amData.GPSIs
	}
	if sfAnswer != "" {
		rsp["supportedFeatures"] = sfAnswer
	}
	_ = json.NewEncoder(w).Encode(rsp)
}

// handleGetSMData serves Nudm_SDM Get for sm-data: the per-slice session
// management subscription including the subscribed default QoS profile.
// Optional query parameters filter the result:
//
//	dnn           — keep only entries whose dnnConfigurations contain this DNN
//	single-nssai  — JSON {"sst":1,"sd":"000001"}; keep only the matching slice
//
// Ref: TS 29.503 §5.2.2.2 (GET sm-data), §6.1.6.2.7
func (s *Server) handleGetSMData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.logger.With("procedure", "GetSMData", "supi", supi, "interface", "Nudm")
	log.Info("GetSMData request", "direction", "IN")

	// Optional supported-features query (TS 29.500 §6.6.2); answered in
	// SessionManagementSubscriptionData.supportedFeatures of every returned
	// element (TS 29.503 §6.1.6.2.7).
	sfAnswer, ok := s.negotiateQuery(w, r, s.sdmCat)
	if !ok {
		return
	}

	raw, err := s.udr.GetSMData(correlationCtx(w, r), supi)
	if err != nil {
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}
	if raw == nil {
		s.problem(w, http.StatusNotFound, "DATA_NOT_FOUND", "no SM subscription for "+supi)
		return
	}

	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		s.problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", "malformed sm-data from UDR: "+err.Error())
		return
	}

	dnnFilter := r.URL.Query().Get("dnn")
	snssaiFilter := r.URL.Query().Get("single-nssai")
	var wantSNSSAI *struct {
		SST int    `json:"sst"`
		SD  string `json:"sd"`
	}
	if snssaiFilter != "" {
		wantSNSSAI = &struct {
			SST int    `json:"sst"`
			SD  string `json:"sd"`
		}{}
		if err := json.Unmarshal([]byte(snssaiFilter), wantSNSSAI); err != nil {
			s.problem(w, http.StatusBadRequest, "INVALID_QUERY_PARAM", "single-nssai: "+err.Error())
			return
		}
	}

	filtered := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		if wantSNSSAI != nil {
			sn, _ := e["singleNssai"].(map[string]any)
			sst, _ := sn["sst"].(float64)
			sd, _ := sn["sd"].(string)
			if int(sst) != wantSNSSAI.SST || (wantSNSSAI.SD != "" && sd != wantSNSSAI.SD) {
				continue
			}
		}
		if dnnFilter != "" {
			cfgs, _ := e["dnnConfigurations"].(map[string]any)
			if _, ok := cfgs[dnnFilter]; !ok {
				continue
			}
		}
		if sfAnswer != "" {
			e["supportedFeatures"] = sfAnswer
		}
		filtered = append(filtered, e)
	}

	log.Info("SM subscription returned",
		"direction", "OUT",
		"slice_count", len(filtered),
		"spec_ref", "TS 29.503 §6.1.6.2.7",
	)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(filtered)
}

// handleGetLcsPrivacyData serves Nudm_SDM Get for lcs-privacy-data.
// Returns an allow-all policy for all subscribers (dev stub).
// Real implementations would look up per-subscriber privacy exceptions from UDR.
// Ref: TS 29.503 §5.2.2, TS 23.273 §9.1, TS 29.571 §5.2.7.5.
func (s *Server) handleGetLcsPrivacyData(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	s.logger.Info("GetLcsPrivacyData request",
		"procedure", "GetLcsPrivacyData",
		"supi", supi,
		"nf", "UDM",
		"interface", "Nudm",
		"direction", "IN",
		"spec_ref", "TS 29.503 §5.2.2",
	)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"locationPrivacy": "ALLOW_ALL"})
}

// ---- Nudm_UECM AMF Registration / Deregistration --------------------------

func (s *Server) handleAMFRegistration(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")

	// Amf3GppAccessRegistration.supportedFeatures (TS 29.503 §6.2.6.2.2). The
	// handler has always accepted any body, so a body that does not parse as a
	// JSON object stays accepted (no supportedFeatures offered); only a
	// supportedFeatures that violates its schema is rejected (TS 29.500
	// §5.2.7.2).
	ctx := correlationCtx(w, r)
	peerNF := features.PeerNFTypeFromUserAgent(r.UserAgent(), "UNKNOWN")
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, features.MaxRequestBodyBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			payloadTooLarge(w)
			return
		}
		s.problem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT", "request body: "+err.Error())
		return
	}
	var reg struct {
		SupportedFeatures string `json:"supportedFeatures"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		if features.IsTypeError(err) {
			s.rejectSupportedFeatures(ctx, w, peerNF, s.uecmCat, "<non-string>", err)
			return
		}
		if features.Request(s.uecmCat, s.profile) != "" {
			// Rel-19 profile: the body is an Amf3GppAccessRegistration object
			// (TS 29.503 §5.3.2.2.2); anything else is malformed.
			// Ref: TS 29.500 §5.2.7.2.
			s.logger.Warn("AMF registration body is not a JSON object",
				"procedure", "UECMRegistration", "interface", "Nudm", "direction", "IN",
				"supi", supi, "result", "REJECT", "cause", "INVALID_MSG_FORMAT",
				"spec_ref", "TS 29.500 §5.2.7.2", "error", err)
			s.problem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT", "request body is not a JSON object")
			return
		}
		// Rel-17 profile: legacy behaviour, any body is accepted and no
		// supportedFeatures is offered. Leave a trace of the malformed body.
		s.logger.Warn("AMF registration body is not valid JSON; accepted (legacy)",
			"procedure", "UECMRegistration", "interface", "Nudm", "direction", "IN",
			"supi", supi, "result", "OK",
			"spec_ref", "TS 29.500 §5.2.7.2", "error", err)
		reg.SupportedFeatures = ""
	}
	if err := features.Validate(reg.SupportedFeatures); err != nil {
		s.rejectSupportedFeatures(ctx, w, peerNF, s.uecmCat, reg.SupportedFeatures, err)
		return
	}
	// Producer side (decision D1): the intersection, absent under rel17 when
	// the request had none, "0" under rel19. The UDM keeps no Nudm_UECM
	// registration resource context yet (the registration is only logged), so
	// the negotiated set has nowhere to be stored: a known gap.
	sfAnswer, sfSet := features.Answer(s.uecmCat, s.profile, reg.SupportedFeatures)
	features.LogNegotiation(ctx, s.logger, features.Negotiation{
		NF:        "UDM",
		Interface: "Nudm", Direction: "IN", PeerNF: peerNF,
		SpecRef: features.SpecRef, Result: "OK",
		Local: s.uecmCat.Supported(s.profile), Peer: reg.SupportedFeatures,
		PeerPresent: reg.SupportedFeatures != "", Negotiated: sfSet,
	}, "supi", supi)

	s.logger.Info("AMF registered at UDM",
		"procedure", "UECMRegistration",
		"direction", "IN",
		"supi", supi,
		"spec_ref", "TS 29.503 §5.3.2.2",
	)
	if sfAnswer == "" {
		// Legacy answer: 201 without a body.
		w.WriteHeader(http.StatusCreated)
		return
	}
	// 201 carries the Amf3GppAccessRegistration representation with the
	// negotiated supportedFeatures (TS 29.503 §5.3.2.2.2, TS 29.500 §6.6.2).
	rsp := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &rsp); err != nil || rsp == nil {
		rsp = map[string]json.RawMessage{}
	}
	sf, _ := json.Marshal(sfAnswer)
	rsp["supportedFeatures"] = sf
	w.Header().Set("Location", s.apiRoot(r)+"/nudm-uecm/v1/"+url.PathEscape(supi)+"/registrations/amf-3gpp-access")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(rsp)
}

// apiRoot returns the {apiRoot} of this UDM's SBI for absolute Location
// headers: "https://" + authority (SBA is always https). The UDM config has no
// fqdn, so the authority is, in order: the request Host (the peer is
// mTLS-authenticated: it is the name it used to reach this UDM); the TLS SNI
// server name (with the port of the listen address); the host of the listen
// address when it is a specified address; otherwise "" and the Location is the
// bare path. It never emits an unspecified host (0.0.0.0, ::, empty).
// Ref: TS 29.501 §4.4.1.
func (s *Server) apiRoot(r *http.Request) string {
	host, port, err := net.SplitHostPort(s.addr)
	if err != nil {
		host, port = s.addr, ""
	}
	authority := func(h string) string {
		if port == "" {
			return h
		}
		return net.JoinHostPort(h, port)
	}
	if r.Host != "" {
		return "https://" + r.Host
	}
	if r.TLS != nil && r.TLS.ServerName != "" {
		return "https://" + authority(r.TLS.ServerName)
	}
	if host != "" {
		if ip := net.ParseIP(host); ip == nil || !ip.IsUnspecified() {
			return "https://" + authority(host)
		}
	}
	return ""
}

// handleAMFDeregistration handles Nudm_UECM_Deregistration from the AMF.
// The AMF calls this after UE deregistration to clear its serving record.
// Ref: TS 29.503 §5.3.2.4
func (s *Server) handleAMFDeregistration(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	s.logger.Info("AMF deregistered at UDM",
		"procedure", "UECMDeregistration",
		"direction", "IN",
		"supi", supi,
		"spec_ref", "TS 29.503 §5.3.2.4",
	)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"UP"}`))
}

// ServeH2C binds to ln with cleartext HTTP/2 (H2C) — for in-process tests only.
func (s *Server) ServeH2C(ln net.Listener) error {
	s.httpSrv.Handler = h2c.NewHandler(s.httpSrv.Handler, &http2.Server{})
	err := s.httpSrv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ---- Nudm_SDM Subscribe / Notify (TS 29.503 §5.3.2 / §5.3.3) --------------

// handleSDMSubscribe processes POST /nudm-sdm/v2/{supi}/sdm-subscriptions.
// Ref: TS 29.503 §5.3.2.2
func (s *Server) handleSDMSubscribe(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	log := s.logger.With(
		"procedure", "SDMSubscribe",
		"interface", "Nudm",
		"direction", "IN",
		"supi", supi,
		"correlation_id", r.Header.Get("X-Correlation-Id"),
		"spec_ref", "TS 29.503 §5.3.2.2",
	)

	ctx := correlationCtx(w, r)
	peerNF := features.PeerNFTypeFromUserAgent(r.UserAgent(), "UNKNOWN")
	r.Body = http.MaxBytesReader(w, r.Body, features.MaxRequestBodyBytes)
	var subReq sdmSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&subReq); err != nil {
		if features.IsTypeError(err) {
			s.rejectSupportedFeatures(ctx, w, peerNF, s.sdmCat, "<non-string>", err)
			return
		}
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			payloadTooLarge(w)
			return
		}
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "request body: "+err.Error())
		return
	}
	// Both shapes are accepted whatever the profile (mixed-release
	// deployments): the legacy singular attribute is normalised into the
	// schema's monitoredResourceUris array.
	sub := subReq.SdmSubscription
	if len(sub.MonitoredResourceURIs) == 0 && subReq.LegacyMonitoredResourceURI != "" {
		sub.MonitoredResourceURIs = []string{subReq.LegacyMonitoredResourceURI}
	}
	// supportedFeatures must be schema-valid before any state is touched.
	// Ref: TS 29.500 §5.2.7.2, §6.6.2.
	peerSF := sub.SupportedFeatures
	if err := features.Validate(peerSF); err != nil {
		s.rejectSupportedFeatures(ctx, w, peerNF, s.sdmCat, peerSF, err)
		return
	}
	if sub.CallbackRef == "" {
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "callbackReference is mandatory")
		return
	}
	// Rel-19 profile: nfInstanceId and monitoredResourceUris are mandatory
	// (M, 1 / 1..N), and the 201 body must echo them. Rel-17 profile keeps
	// accepting their absence. Ref: TS 29.503 §6.1.6.2.3.
	if features.SpecLiteral(s.profile) {
		var missing []map[string]string
		if sub.NfInstanceID == "" {
			missing = append(missing, map[string]string{"param": "/nfInstanceId"})
		}
		if len(sub.MonitoredResourceURIs) == 0 {
			missing = append(missing, map[string]string{"param": "/monitoredResourceUris"})
		}
		if len(missing) > 0 {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": http.StatusBadRequest, "cause": "MANDATORY_IE_MISSING",
				"detail":        "nfInstanceId and monitoredResourceUris are mandatory",
				"invalidParams": missing,
			})
			return
		}
	}

	// Producer side (decision D1): SdmSubscription.supportedFeatures carries
	// the intersection (absent under rel17 when the request had none, "0"
	// under rel19) and the negotiated set is kept on the subscription.
	sfAnswer, sfSet := features.Answer(s.sdmCat, s.profile, peerSF)
	features.LogNegotiation(ctx, s.logger, features.Negotiation{
		NF:        "UDM",
		Interface: "Nudm", Direction: "IN", PeerNF: peerNF,
		SpecRef: features.SpecRef, Result: "OK",
		Local: s.sdmCat.Supported(s.profile), Peer: peerSF,
		PeerPresent: peerSF != "", Negotiated: sfSet,
	}, "supi", supi)
	sub.SupportedFeatures = sfAnswer
	sub.negotiated = sfSet

	sub.SubscriptionID = ulid.Make().String()
	log.Info("SDM subscription created",
		"subscription_id", sub.SubscriptionID,
		"callback_ref", sub.CallbackRef,
		"monitored_resources", sub.MonitoredResourceURIs,
		"wire_shape", sdmWireShape(features.SpecLiteral(s.profile)),
	)

	s.addSubscription(supi, &sub)
	s.subscriptionIdx.Store(sub.SubscriptionID, supi)

	location := fmt.Sprintf("/nudm-sdm/v2/%s/sdm-subscriptions/%s", supi, sub.SubscriptionID)
	w.Header().Set("Location", location)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	// Rel-17 profile (and no profile): frozen singular-attribute bytes.
	// Rel-19 profile: schema attribute names. Ref: TS 29.503 §6.1.6.2.3.
	if features.SpecLiteral(s.profile) {
		if err := json.NewEncoder(w).Encode(sub); err != nil {
			log.Error("SDM subscription: encode response", "error", err, "spec_ref", "TS 29.503 §6.1.6.2.3")
		}
		return
	}
	if len(sub.MonitoredResourceURIs) > 1 {
		log.Warn("SDM subscription: Rel-17 profile response carries only the first monitored resource URI",
			"monitored_resources", len(sub.MonitoredResourceURIs),
			"spec_ref", "TS 29.503 §6.1.6.2.3")
	}
	if err := json.NewEncoder(w).Encode(sub.legacyView()); err != nil {
		log.Error("SDM subscription: encode response", "error", err, "spec_ref", "TS 29.503 §6.1.6.2.3")
	}
}

// sdmWireShape names the body shape selected by the release profile, for logs.
func sdmWireShape(specLiteral bool) string {
	if specLiteral {
		return "spec"
	}
	return "legacy"
}

// handleSDMUnsubscribe processes DELETE /nudm-sdm/v2/{supi}/sdm-subscriptions/{subscriptionId}.
// Ref: TS 29.503 §5.3.2.7
func (s *Server) handleSDMUnsubscribe(w http.ResponseWriter, r *http.Request) {
	subscriptionID := r.PathValue("subscriptionId")
	log := s.logger.With(
		"procedure", "SDMUnsubscribe",
		"interface", "Nudm",
		"direction", "IN",
		"subscription_id", subscriptionID,
		"spec_ref", "TS 29.503 §5.3.2.7",
	)

	supiVal, ok := s.subscriptionIdx.LoadAndDelete(subscriptionID)
	if !ok {
		s.problem(w, http.StatusNotFound, "SUBSCRIPTION_NOT_FOUND",
			"subscription "+subscriptionID+" not found")
		return
	}
	supi := supiVal.(string)
	s.removeSubscription(supi, subscriptionID)
	log.Info("SDM subscription deleted", "supi", supi)
	w.WriteHeader(http.StatusNoContent)
}

// handleDataChangeTrigger processes POST /nudm-mgmt/v1/{supi}/data-change.
// Called internally (by UDR or management tools) to fan out SDM notifications.
// Ref: TS 29.503 §5.3.3
func (s *Server) handleDataChangeTrigger(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")

	var trig []triggerChange
	if err := json.NewDecoder(r.Body).Decode(&trig); err != nil || len(trig) == 0 {
		// default: generic AM data change
		trig = []triggerChange{{legacyChangeItem: legacyChangeItem{
			ChangeType:   "REPLACE",
			ResourcePath: "/nudm-sdm/v2/" + supi + "/am-data",
		}}}
	}
	changes := make([]legacyChangeItem, len(trig))
	for i, c := range trig {
		changes[i] = c.legacyChangeItem
	}

	specLiteral := features.SpecLiteral(s.profile)
	// Rel-19: reject an invalid trigger before any fan-out. Ref: TS 29.571 §5.2.4.8.
	if specLiteral {
		if _, err := toNotifyItems(supi, "", nil, trig); err != nil {
			s.logger.Warn("SDM notify: invalid data-change trigger",
				"procedure", "SDMNotify", "interface", "Nudm", "direction", "IN",
				"supi", supi, "result", "REJECT", "error", err,
				"spec_ref", "TS 29.571 §5.2.4.8")
			s.problem(w, http.StatusBadRequest, "INVALID_MSG_FORMAT", err.Error())
			return
		}
	}

	subs := s.listSubscriptions(supi)
	if len(subs) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Body shape follows the release profile: Rel-17 / no profile keeps the
	// frozen resourceChanges bytes; Rel-19 emits notifyItems.
	// Ref: TS 29.503 §6.1.6.2.21, TS 29.571 §5.2.4.8-9.
	var legacyBody []byte
	if !specLiteral {
		var err error
		legacyBody, err = json.Marshal(legacyModificationNotification{ResourceChanges: changes})
		if err != nil {
			s.logger.Error("SDM notify: marshal notification",
				"procedure", "SDMNotify", "interface", "Nudm", "direction", "OUT",
				"supi", supi, "result", "FAILURE", "error", err,
				"spec_ref", "TS 29.503 §5.2.2.5.2")
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	for _, sub := range subs {
		sub := sub
		body := legacyBody
		if specLiteral {
			items, err := toNotifyItems(supi, "https://"+s.addr, sub.MonitoredResourceURIs, trig)
			if err == nil {
				body, err = json.Marshal(ModificationNotification{NotifyItems: items, SubscriptionID: sub.SubscriptionID})
			}
			if err != nil {
				s.logger.Error("SDM notify: build notification, subscriber skipped",
					"procedure", "SDMNotify", "interface", "Nudm", "direction", "OUT",
					"supi", supi, "subscription_id", sub.SubscriptionID,
					"result", "FAILURE", "error", err,
					"spec_ref", "TS 29.503 §5.2.2.5.2")
				continue
			}
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "POST", sub.CallbackRef, bytes.NewReader(body))
			if err != nil {
				s.logger.Warn("SDM notify: bad callback URI",
					"subscription_id", sub.SubscriptionID,
					"callback_ref", sub.CallbackRef,
					"error", err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := s.notifyClient.Do(req)
			if err != nil {
				s.logger.Warn("SDM notify: callback failed",
					"subscription_id", sub.SubscriptionID,
					"error", err)
				return
			}
			resp.Body.Close()
			s.logger.Info("SDM notify: callback delivered",
				"procedure", "SDMNotify",
				"interface", "Nudm",
				"direction", "OUT",
				"supi", supi,
				"subscription_id", sub.SubscriptionID,
				"callback_status", resp.StatusCode,
				"spec_ref", "TS 29.503 §5.2.2.5.2",
			)
		}()
	}

	w.WriteHeader(http.StatusNoContent)
}

// subscriptionList is the per-SUPI subscription store (pointer → comparable for sync.Map).
type subscriptionList struct {
	mu   sync.Mutex
	subs []*SdmSubscription
}

func (s *Server) getOrCreateSubList(supi string) *subscriptionList {
	v, _ := s.subscriptions.LoadOrStore(supi, &subscriptionList{})
	return v.(*subscriptionList)
}

// addSubscription appends sub to the per-supi list (thread-safe).
func (s *Server) addSubscription(supi string, sub *SdmSubscription) {
	list := s.getOrCreateSubList(supi)
	list.mu.Lock()
	list.subs = append(list.subs, sub)
	list.mu.Unlock()
}

// removeSubscription deletes the entry with subscriptionId from the per-supi list.
func (s *Server) removeSubscription(supi, subscriptionID string) {
	v, ok := s.subscriptions.Load(supi)
	if !ok {
		return
	}
	list := v.(*subscriptionList)
	list.mu.Lock()
	newSubs := make([]*SdmSubscription, 0, len(list.subs))
	for _, sub := range list.subs {
		if sub.SubscriptionID != subscriptionID {
			newSubs = append(newSubs, sub)
		}
	}
	list.subs = newSubs
	list.mu.Unlock()
}

// listSubscriptions returns a copy of all subscriptions for supi (thread-safe).
func (s *Server) listSubscriptions(supi string) []*SdmSubscription {
	v, ok := s.subscriptions.Load(supi)
	if !ok {
		return nil
	}
	list := v.(*subscriptionList)
	list.mu.Lock()
	out := make([]*SdmSubscription, len(list.subs))
	copy(out, list.subs)
	list.mu.Unlock()
	return out
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		corr := r.Header.Get("X-Correlation-Id")
		if corr == "" {
			corr = ulid.Make().String()
		}
		w.Header().Set("X-Correlation-Id", corr)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) problem(w http.ResponseWriter, status int, cause, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "cause": cause, "detail": detail})
}

// ---- HTTP UDR client ----------------------------------------------------

// HTTPUDRClient calls the UDR over HTTP.
type HTTPUDRClient struct {
	address string
	client  *http.Client
	// profile gates supportedFeatures on the wire (decision D2): nil or rel17
	// sends none. cat overrides the default Nudr_DataRepository catalog and
	// logger is the base logger of the FeatureNegotiation record (nil =
	// slog.Default()). See udr_features.go.
	profile *capability.Profile
	cat     *features.Catalog
	logger  *slog.Logger
}

func NewHTTPUDRClient(address string, client *http.Client) *HTTPUDRClient {
	return &HTTPUDRClient{address: address, client: client}
}

func (c *HTTPUDRClient) GetAuthSubscription(ctx context.Context, supi string) (*UDRAuthSub, error) {
	url := fmt.Sprintf("https://%s/nudr-dr/v2/subscription-data/%s/authentication-data/authentication-subscription", c.address, supi)
	url, offer := c.withOffer(url)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("udr: get auth sub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("udr: subscriber not found: %s", supi)
	}
	var result struct {
		AuthMethod string `json:"authenticationMethod"`
		EncK       string `json:"encPermanentKey"`
		EncOPc     string `json:"encOpcKey"`
		AMF        string `json:"authenticationManagementField"`
		AlgID      string `json:"algorithmId"`
		SQN        struct {
			SQN string `json:"sqn"`
		} `json:"sequenceNumber"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxUDRResponseBytes)).Decode(&result); err != nil {
		return nil, fmt.Errorf("udr: decode auth sub: %w", err)
	}
	// AuthenticationSubscription has no supportedFeatures attribute: no answer.
	c.negotiate(ctx, supi, offer, nil)
	return &UDRAuthSub{
		AuthMethod: result.AuthMethod,
		K:          result.EncK,
		OPc:        result.EncOPc,
		AMF:        result.AMF,
		SQN:        result.SQN.SQN,
		AlgID:      result.AlgID,
	}, nil
}

func (c *HTTPUDRClient) UpdateSQN(ctx context.Context, supi, newSQN string) error {
	body, _ := json.Marshal(map[string]any{
		"sequenceNumber": map[string]string{"sqn": newSQN},
	})
	url := fmt.Sprintf("https://%s/nudr-dr/v2/subscription-data/%s/authentication-data/authentication-subscription", c.address, supi)
	url, _ = c.withOffer(url) // no answer to negotiate on a PATCH
	req, _ := http.NewRequestWithContext(ctx, "PATCH", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/merge-patch+json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (c *HTTPUDRClient) GetSMData(ctx context.Context, supi string) (json.RawMessage, error) {
	url := fmt.Sprintf("https://%s/nudr-dr/v2/subscription-data/%s/001/provisioned-data/sm-data", c.address, supi)
	url, offer := c.withOffer(url)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("udr: get sm data: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("udr: get sm data: status %d", resp.StatusCode)
	}
	var raw json.RawMessage
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxUDRResponseBytes)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("udr: decode sm data: %w", err)
	}
	// The sm-data body has no top-level supportedFeatures attribute: no answer.
	c.negotiate(ctx, supi, offer, nil)
	return raw, nil
}

func (c *HTTPUDRClient) GetAMData(ctx context.Context, supi string) (*UDRAMData, error) {
	url := fmt.Sprintf("https://%s/nudr-dr/v2/subscription-data/%s/001/provisioned-data/am-data", c.address, supi)
	url, offer := c.withOffer(url)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		// SupportedFeatures: AccessAndMobilitySubscriptionData.supportedFeatures
		// (TS 29.505), the UDR's answer to the supported-features query.
		// Read as raw JSON so a non-string answer is a negotiation failure
		// (R13) and not a decode failure of the whole response.
		SupportedFeatures json.RawMessage `json:"supportedFeatures"`
		// GPSIs: AccessAndMobilitySubscriptionData.gpsis (TS 29.503 §6.1.6.2.4).
		GPSIs []string `json:"gpsis"`
		NSSAI struct {
			DefaultSingleNssais []struct {
				SST            int    `json:"sst"`
				SD             string `json:"sd,omitempty"`
				DNN            string `json:"dnn,omitempty"` // portal-assigned preferred DNN
				SubjectToNSSAA bool   `json:"subjectToNetworkSliceSpecificAuthenticationAndAuthorization,omitempty"`
			} `json:"defaultSingleNssais"`
		} `json:"nssai"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxUDRResponseBytes)).Decode(&result); err != nil {
		return nil, fmt.Errorf("udr: decode am data: %w", err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.negotiate(ctx, supi, offer, result.SupportedFeatures)
	}
	amData := &UDRAMData{AMBRUplink: 100000, AMBRDownlink: 100000}
	// gpsis are only emitted under the spec-literal profile (AMF-020): filter
	// and log only then; the answer is decoded either way (raw under rel17,
	// where nothing is emitted).
	amData.GPSIs = result.GPSIs
	if features.SpecLiteral(c.profile) {
		var rejected []string
		amData.GPSIs, rejected = types.FilterGpsis(result.GPSIs)
		gl := c.logger
		if gl == nil {
			gl = slog.Default()
		}
		for _, g := range rejected {
			gl.Warn("UDR am-data gpsis entry does not match the Gpsi pattern, skipped",
				"nf", "UDM", "procedure", "GetAMData", "interface", "Nudr", "direction", "IN",
				"supi", supi, "result", "REJECT", "cause", "INVALID_GPSI", "gpsi", g,
				"spec_ref", "TS 29.571 §5.3.2")
		}
	}
	for _, s := range result.NSSAI.DefaultSingleNssais {
		amData.SNSSAIs = append(amData.SNSSAIs, SNSSAIEntry{SST: s.SST, SD: s.SD, DNN: s.DNN, SubjectToNSSAA: s.SubjectToNSSAA})
	}
	return amData, nil
}

// maxUDRResponseBytes bounds the UDR response bodies decoded by the Nudr
// client (same 1 MiB cap as features.MaxRequestBodyBytes).
const maxUDRResponseBytes = features.MaxRequestBodyBytes

// bitRateKbpsPattern is the TS 29.571 §5.5.2 BitRate regex (space mandatory).
const bitRateKbpsPattern = `^\d+(\.\d+)? (bps|Kbps|Mbps|Gbps|Tbps)$`

// payloadTooLarge answers a body over features.MaxRequestBodyBytes with 413 and
// a ProblemDetails without a cause (no 413 cause is defined).
// Ref: TS 29.500 §5.2.7.1; TS 29.571 §5.2.4.1.
func payloadTooLarge(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": http.StatusRequestEntityTooLarge,
		"detail": "request body too large",
	})
}
