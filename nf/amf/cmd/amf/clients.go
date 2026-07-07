package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
)

// ---- AUSF Client (Nausf_UEAuthentication) --------------------------------

// HTTPAUSFClient calls the AUSF over HTTP/2.
// Ref: TS 29.509
type HTTPAUSFClient struct {
	address string
	client  *http.Client
}

func (c *HTTPAUSFClient) InitiateAuth(ctx context.Context, supiOrSuci, servingNetName string) (*procedures.AUSFInitResponse, error) {
	body, _ := json.Marshal(map[string]any{
		"supiOrSuci":         supiOrSuci,
		"servingNetworkName": servingNetName,
	})
	req, _ := http.NewRequestWithContext(ctx, "POST",
		"https://"+c.address+"/nausf-auth/v1/ue-authentications",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ausf: initiate auth: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var prob map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&prob)
		return nil, fmt.Errorf("ausf: initiate auth: status %d cause=%v", resp.StatusCode, prob["cause"])
	}

	var result struct {
		RAND      string `json:"rand"`
		HXRESStar string `json:"hxresStar"`
		AUTN      string `json:"autn"`
		SUPI      string `json:"supi"`
		Links     struct {
			AKA struct {
				Href string `json:"href"`
			} `json:"5g-aka"`
		} `json:"_links"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ausf: decode response: %w", err)
	}

	randBytes, _ := hex.DecodeString(result.RAND)
	autnBytes, _ := hex.DecodeString(result.AUTN)
	hxres, _ := hex.DecodeString(result.HXRESStar)

	// Extract authCtxID from Location header
	loc := resp.Header.Get("Location")
	authCtxID := extractAuthCtxID(loc)

	return &procedures.AUSFInitResponse{
		AuthCtxID: authCtxID,
		RAND:      [16]byte(randBytes),
		AUTN:      [16]byte(autnBytes),
		HXRESStar: hxres,
		SUPI:      result.SUPI,
	}, nil
}

func (c *HTTPAUSFClient) ResyncAuth(ctx context.Context, supiOrSuci, servingNetName string, rand [16]byte, auts []byte) (*procedures.AUSFInitResponse, error) {
	body, _ := json.Marshal(map[string]any{
		"supiOrSuci":         supiOrSuci,
		"servingNetworkName": servingNetName,
		"resynchronizationInfo": map[string]string{
			"rand": hex.EncodeToString(rand[:]),
			"auts": hex.EncodeToString(auts),
		},
	})
	req, _ := http.NewRequestWithContext(ctx, "POST",
		"https://"+c.address+"/nausf-auth/v1/ue-authentications",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ausf: resync auth: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		var prob map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&prob)
		return nil, fmt.Errorf("ausf: resync auth: status %d cause=%v", resp.StatusCode, prob["cause"])
	}

	var result struct {
		RAND      string `json:"rand"`
		HXRESStar string `json:"hxresStar"`
		AUTN      string `json:"autn"`
		SUPI      string `json:"supi"`
		Links     struct {
			AKA struct {
				Href string `json:"href"`
			} `json:"5g-aka"`
		} `json:"_links"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ausf: resync decode: %w", err)
	}

	randBytes, _ := hex.DecodeString(result.RAND)
	autnBytes, _ := hex.DecodeString(result.AUTN)
	hxres, _ := hex.DecodeString(result.HXRESStar)
	loc := resp.Header.Get("Location")
	authCtxID := extractAuthCtxID(loc)

	return &procedures.AUSFInitResponse{
		AuthCtxID: authCtxID,
		RAND:      [16]byte(randBytes),
		AUTN:      [16]byte(autnBytes),
		HXRESStar: hxres,
		SUPI:      result.SUPI,
	}, nil
}

func (c *HTTPAUSFClient) ConfirmAuth(ctx context.Context, authCtxID, resStar string) (*procedures.AUSFConfirmResponse, error) {
	body, _ := json.Marshal(map[string]string{"resStar": resStar})
	url := "https://" + c.address + "/nausf-auth/v1/ue-authentications/" + authCtxID + "/5g-aka-confirmation"
	req, _ := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ausf: confirm auth: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		AuthResult string `json:"authResult"`
		KAUSF      string `json:"kausf"`
		SUPI       string `json:"supi"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ausf: confirm decode: %w", err)
	}
	if result.AuthResult != "AUTHENTICATION_SUCCESS" {
		return nil, fmt.Errorf("ausf: authentication rejected: %s", result.AuthResult)
	}

	kausf, _ := hex.DecodeString(result.KAUSF)
	return &procedures.AUSFConfirmResponse{SUPI: result.SUPI, KAUSF: kausf}, nil
}

// ---- NSSAA Client (Nausf_NSSAA EAP relay) --------------------------------

// HTTPNSSAAClient relays the UE's slice-auth EAP packets to the AAA-S via the AUSF.
// Ref: TS 23.502 §4.2.9.2, TS 29.526 (mapped onto the AUSF here).
type HTTPNSSAAClient struct {
	address string // AUSF SBI address
	client  *http.Client
}

func (c *HTTPNSSAAClient) Authenticate(
	ctx context.Context, supi, gpsi string, sst uint8, sd string, eapPayload []byte,
) (*procedures.NSSAAAuthResult, error) {
	body, _ := json.Marshal(map[string]any{
		"supi":       supi,
		"gpsi":       gpsi,
		"snssai":     map[string]any{"sst": sst, "sd": sd},
		"eapPayload": base64.StdEncoding.EncodeToString(eapPayload),
	})
	url := fmt.Sprintf("https://%s/nausf-nssaa/v1/%s/authenticate", c.address, supi)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ausf: nssaa authenticate: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ausf: nssaa authenticate: status %d", resp.StatusCode)
	}

	var result struct {
		AuthResult string `json:"authResult"`
		EAPPayload string `json:"eapPayload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ausf: nssaa decode: %w", err)
	}
	eapBytes, _ := base64.StdEncoding.DecodeString(result.EAPPayload)
	return &procedures.NSSAAAuthResult{AuthResult: result.AuthResult, EAPPayload: eapBytes}, nil
}

func extractAuthCtxID(location string) string {
	// Location: /nausf-auth/v1/ue-authentications/<authCtxId>
	for i := len(location) - 1; i >= 0; i-- {
		if location[i] == '/' {
			return location[i+1:]
		}
	}
	return location
}

// ---- UDM Client (Nudm_SDM + Nudm_UECM) ----------------------------------

// HTTPUDMClient calls the UDM over HTTP/2.
// Ref: TS 29.503
type HTTPUDMClient struct {
	address string
	client  *http.Client
}

func (c *HTTPUDMClient) RegisterAMF(ctx context.Context, supi, amfInstanceID, servingNetName string) error {
	body, _ := json.Marshal(map[string]string{
		"amfInstanceId":      amfInstanceID,
		"servingNetworkName": servingNetName,
	})
	url := fmt.Sprintf("https://%s/nudm-uecm/v1/%s/registrations/amf-3gpp-access", c.address, supi)
	req, _ := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("udm: register amf: %w", err)
	}
	resp.Body.Close()
	return nil
}

// DeregisterUECM deregisters the AMF from the UDM for this SUPI.
// Called after deregistration to clean up UDM state.
// Ref: TS 29.503 §5.3.2.4 (Nudm_UECM_Deregistration)
func (c *HTTPUDMClient) DeregisterUECM(ctx context.Context, supi string) error {
	url := fmt.Sprintf("https://%s/nudm-uecm/v1/%s/registrations/amf-3gpp-access", c.address, supi)
	req, _ := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("udm: deregister UE: %w", err)
	}
	resp.Body.Close()
	// 204 No Content = success; 404 = already deregistered (tolerate both)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK &&
		resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("udm: deregister UE: status %d", resp.StatusCode)
	}
	return nil
}

func (c *HTTPUDMClient) GetAMSubscriptionData(ctx context.Context, supi string) (*procedures.UDMAMSubscription, error) {
	url := fmt.Sprintf("https://%s/nudm-sdm/v2/%s/am-data", c.address, supi)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("udm: get AM data: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		NSSAI struct {
			DefaultSingleNssais []struct {
				SST            int    `json:"sst"`
				SD             string `json:"sd,omitempty"`
				DNN            string `json:"dnn,omitempty"` // portal-assigned preferred DNN
				SubjectToNSSAA bool   `json:"subjectToNetworkSliceSpecificAuthenticationAndAuthorization,omitempty"`
			} `json:"defaultSingleNssais"`
		} `json:"nssai"`
		SubscribedUEAMBR struct {
			Uplink   string `json:"uplink"`
			Downlink string `json:"downlink"`
		} `json:"subscribedUeAmbr"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("udm: decode AM data: %w", err)
	}

	sub := &procedures.UDMAMSubscription{}
	for _, s := range result.NSSAI.DefaultSingleNssais {
		sub.AllowedNSSAI = append(sub.AllowedNSSAI, amfctx.SNSSAISubscribed{
			SST:            uint8(s.SST),
			SD:             s.SD,
			DNN:            s.DNN,
			SubjectToNSSAA: s.SubjectToNSSAA,
		})
	}
	return sub, nil
}

// ---- SMF Client (Nsmf_PDUSession) ----------------------------------------

// SMFClient interface for PDU session management
type SMFClient interface {
	CreateSMContext(ctx context.Context, supi, dnn string, pduSessionID uint8, n1SmMsg []byte, snssai amfctx.SNSSAISubscribed) (smContextRef string, n1SmResp []byte, n2SmInfo []byte, err error)
	UpdateSMContext(ctx context.Context, smContextRef string, n2SmInfo []byte) error
	DeleteSMContext(ctx context.Context, smContextRef string) error
	// NotifyANRelease sends Nsmf_PDUSession_UpdateSMContext with upCnxState=DEACTIVATED
	// so the SMF can instruct the UPF to suspend DL forwarding.
	// Ref: TS 29.502 §5.2.2.3.2, TS 23.502 §4.2.6 step 5
	NotifyANRelease(ctx context.Context, smContextRef string) error
	// ModifySMContext sends Nsmf_PDUSession_UpdateSMContext with the 5GSM Modification
	// Request, triggering QoS recalculation at SMF+PCF and returning the Modification
	// Command + N2SM Modify Request Transfer. Ref: TS 23.502 §4.3.3.1
	ModifySMContext(ctx context.Context, smContextRef string, n1SmMsg []byte, pduSessionID uint8) (n1SmResp []byte, n2SmInfo []byte, err error)
	// ModifyQoSSMContext sends a NW-initiated policy-update trigger to the SMF with
	// new 5QI and AMBR parameters. The SMF responds with a 5GSM Modification Command
	// + N2SM Modify Request Transfer ready to forward to the gNB.
	// Ref: TS 23.502 §4.3.3.2, TS 29.512 §5.2.2.3 (PolicyUpdateNotification)
	ModifyQoSSMContext(ctx context.Context, smContextRef string, pduSessionID uint8, fiveQI, ambrDLMbps, ambrULMbps int) (n1SmResp []byte, n2SmInfo []byte, err error)
}

// HTTPSMFClient calls the SMF over HTTP/2
// Ref: TS 29.502
type HTTPSMFClient struct {
	address string
	client  *http.Client
}

func (c *HTTPSMFClient) CreateSMContext(ctx context.Context, supi, dnn string, pduSessionID uint8, n1SmMsg []byte, snssai amfctx.SNSSAISubscribed) (string, []byte, []byte, error) {
	body, _ := json.Marshal(map[string]any{
		"supi":         supi,
		"dnn":          dnn,
		"pduSessionId": pduSessionID,
		"anType":       "3GPP_ACCESS",
		"requestType":  "INITIAL_REQUEST",
		"servingNfId":  "amf-001",
		"n1SmMsg":      base64.StdEncoding.EncodeToString(n1SmMsg),
		"snssai":       map[string]any{"sst": int(snssai.SST), "sd": snssai.SD},
	})
	req, _ := http.NewRequestWithContext(ctx, "POST",
		"https://"+c.address+"/nsmf-pdusession/v1/sm-contexts",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", nil, nil, fmt.Errorf("smf: create sm context: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", nil, nil, fmt.Errorf("smf: status %d", resp.StatusCode)
	}

	var result struct {
		SMContextRef string `json:"smContextRef"`
		N1SmMsg      string `json:"n1SmMsg"`
		N2SmInfo     string `json:"n2SmInfo"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, nil, fmt.Errorf("smf: decode response: %w", err)
	}

	n1Resp, _ := base64.StdEncoding.DecodeString(result.N1SmMsg)
	n2Info, _ := base64.StdEncoding.DecodeString(result.N2SmInfo)

	return result.SMContextRef, n1Resp, n2Info, nil
}

func (c *HTTPSMFClient) UpdateSMContext(ctx context.Context, smContextRef string, n2SmInfo []byte) error {
	body, _ := json.Marshal(map[string]any{"n2SmInfo": base64.StdEncoding.EncodeToString(n2SmInfo)})
	url := "https://" + c.address + "/nsmf-pdusession/v1/sm-contexts/" + smContextRef + "/modify"
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("smf: update sm context: %w", err)
	}
	resp.Body.Close()
	return nil
}

// UpdatePathSwitch calls Nsmf_PDUSession_UpdateSMContext with the PathSwitchRequestTransfer.
// The SMF decodes the transfer to learn the target gNB's new DL GTP-U endpoint and
// updates the PFCP session accordingly.
// Ref: TS 29.502 §5.2.2.3.2, TS 23.502 §4.9.1.2 step 6
func (c *HTTPSMFClient) UpdatePathSwitch(ctx context.Context, smContextRef string, pathSwitchTransfer []byte) error {
	body, _ := json.Marshal(map[string]any{
		"n2SmInfo":     base64.StdEncoding.EncodeToString(pathSwitchTransfer),
		"n2SmInfoType": "PATH_SWITCH_REQ",
	})
	url := "https://" + c.address + "/nsmf-pdusession/v1/sm-contexts/" + smContextRef + "/modify"
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("smf: update path switch: %w", err)
	}
	resp.Body.Close()
	return nil
}

// NotifyANRelease calls Nsmf_PDUSession_UpdateSMContext with upCnxState=DEACTIVATED.
// This signals the SMF that the UE has gone CM-IDLE so DL traffic should be buffered/dropped.
// Ref: TS 29.502 §5.2.2.3.2
func (c *HTTPSMFClient) NotifyANRelease(ctx context.Context, smContextRef string) error {
	body, _ := json.Marshal(map[string]string{"upCnxState": "DEACTIVATED"})
	url := "https://" + c.address + "/nsmf-pdusession/v1/sm-contexts/" + smContextRef + "/modify"
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("smf: notify AN release: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("smf: notify AN release: status %d", resp.StatusCode)
	}
	return nil
}

// ActivateSMContext calls Nsmf_PDUSession_UpdateSMContext with upCnxState=ACTIVATING.
// The SMF rebuilds the PDUSessionResourceSetupRequestTransfer (UL TEID + QoS) for the
// session so the AMF can carry it as N2SM info in InitialContextSetupRequest during
// Service Request UP re-activation.
// Ref: TS 29.502 §5.2.2.3.2.2, TS 23.502 §4.2.3.2 step 12
func (c *HTTPSMFClient) ActivateSMContext(ctx context.Context, smContextRef string) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{"upCnxState": "ACTIVATING"})
	url := "https://" + c.address + "/nsmf-pdusession/v1/sm-contexts/" + smContextRef + "/modify"
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("smf: activate sm context: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("smf: activate sm context: status %d", resp.StatusCode)
	}

	var result struct {
		N2SmInfo string `json:"n2SmInfo"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("smf: activate sm context: decode response: %w", err)
	}
	n2SmInfo, err := base64.StdEncoding.DecodeString(result.N2SmInfo)
	if err != nil || len(n2SmInfo) == 0 {
		return nil, fmt.Errorf("smf: activate sm context: empty or invalid n2SmInfo")
	}
	return n2SmInfo, nil
}

// ModifySMContext sends Nsmf_PDUSession_UpdateSMContext with the 5GSM Modification Request.
// Returns the body of the 5GSM Modification Command and the N2SM Modify Request Transfer.
// Ref: TS 29.502 §5.2.2.3.2, TS 23.502 §4.3.3.1
func (c *HTTPSMFClient) ModifySMContext(ctx context.Context, smContextRef string, n1SmMsg []byte, pduSessionID uint8) ([]byte, []byte, error) {
	body, _ := json.Marshal(map[string]any{
		"n1SmMsg":      base64.StdEncoding.EncodeToString(n1SmMsg),
		"pduSessionId": pduSessionID,
	})
	url := "https://" + c.address + "/nsmf-pdusession/v1/sm-contexts/" + smContextRef + "/modify"
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("smf: modify sm context: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("smf: modify sm context: status %d", resp.StatusCode)
	}

	var result struct {
		N1SmMsg  string `json:"n1SmMsg"`
		N2SmInfo string `json:"n2SmInfo"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, fmt.Errorf("smf: modify sm context: decode response: %w", err)
	}
	n1SmResp, _ := base64.StdEncoding.DecodeString(result.N1SmMsg)
	n2SmInfo, _ := base64.StdEncoding.DecodeString(result.N2SmInfo)
	return n1SmResp, n2SmInfo, nil
}

// ModifyQoSSMContext sends a NW-initiated policy-update trigger to the SMF.
// The body carries policyUpdate=true plus the new 5QI and AMBR values.
// Ref: TS 23.502 §4.3.3.2
func (c *HTTPSMFClient) ModifyQoSSMContext(ctx context.Context, smContextRef string, pduSessionID uint8, fiveQI, ambrDLMbps, ambrULMbps int) ([]byte, []byte, error) {
	body, _ := json.Marshal(map[string]any{
		"policyUpdate": true,
		"pduSessionId": pduSessionID,
		"fiveQI":       fiveQI,
		"ambrDLMbps":   ambrDLMbps,
		"ambrULMbps":   ambrULMbps,
	})
	url := "https://" + c.address + "/nsmf-pdusession/v1/sm-contexts/" + smContextRef + "/modify"
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("smf: qos modify sm context: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("smf: qos modify sm context: status %d", resp.StatusCode)
	}

	var result struct {
		N1SmMsg  string `json:"n1SmMsg"`
		N2SmInfo string `json:"n2SmInfo"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, fmt.Errorf("smf: qos modify sm context: decode response: %w", err)
	}
	n1SmResp, _ := base64.StdEncoding.DecodeString(result.N1SmMsg)
	n2SmInfo, _ := base64.StdEncoding.DecodeString(result.N2SmInfo)
	return n1SmResp, n2SmInfo, nil
}

func (c *HTTPSMFClient) DeleteSMContext(ctx context.Context, smContextRef string) error {
	u := "https://" + c.address + "/nsmf-pdusession/v1/sm-contexts/" + smContextRef
	req, _ := http.NewRequestWithContext(ctx, "DELETE", u, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("smf: delete sm context: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("smf: delete sm context: status %d", resp.StatusCode)
	}
	return nil
}

// ---- NRF Client (Nnrf_NFDiscovery) ----------------------------------------

// HTTPNRFClient calls the NRF discovery API for slice-aware SMF selection.
// Ref: TS 29.510 §5.3.2.2.2
type HTTPNRFClient struct {
	address string
	client  *http.Client
	// cache maps "SST:SD" → SMF address to avoid repeated discovery calls
	mu    sync.Mutex
	cache map[string]string
}

// NewHTTPNRFClient creates a new NRF discovery client.
func NewHTTPNRFClient(address string, httpClient *http.Client) *HTTPNRFClient {
	return &HTTPNRFClient{
		address: address,
		client:  httpClient,
		cache:   make(map[string]string),
	}
}

// Discover queries NRF for NF instances of the given type, filtered by SNSSAIs.
// Returns the first (highest-priority) result.
func (c *HTTPNRFClient) Discover(ctx context.Context, targetNFType, requesterNFType string, snssais []amfctx.SNSSAISubscribed) ([]procedures.NFEndpoint, error) {
	params := url.Values{
		"target-nf-type":    {targetNFType},
		"requester-nf-type": {requesterNFType},
	}
	if len(snssais) > 0 {
		type snssaiQ struct {
			SST int    `json:"sst"`
			SD  string `json:"sd,omitempty"`
		}
		list := make([]snssaiQ, 0, len(snssais))
		for _, s := range snssais {
			list = append(list, snssaiQ{SST: int(s.SST), SD: s.SD})
		}
		b, _ := json.Marshal(list)
		params.Set("snssais", string(b))
	}
	reqURL := "https://" + c.address + "/nnrf-disc/v1/nf-instances?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("nrf: discover: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nrf: discover: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nrf: discover: status %d", resp.StatusCode)
	}
	var result struct {
		NFInstances []struct {
			NFInstanceID  string   `json:"nfInstanceId"`
			IPv4Addresses []string `json:"ipv4Addresses"`
			NFServices    []struct {
				IPEndpoints []struct {
					IPv4Address string `json:"ipv4Address"`
					Port        int    `json:"port"`
				} `json:"ipEndPoints"`
			} `json:"nfServices"`
		} `json:"nfInstances"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("nrf: discover: decode: %w", err)
	}
	var endpoints []procedures.NFEndpoint
	for _, inst := range result.NFInstances {
		addr := ""
		if len(inst.NFServices) > 0 && len(inst.NFServices[0].IPEndpoints) > 0 {
			ep := inst.NFServices[0].IPEndpoints[0]
			addr = fmt.Sprintf("%s:%d", ep.IPv4Address, ep.Port)
		} else if len(inst.IPv4Addresses) > 0 {
			addr = inst.IPv4Addresses[0]
		}
		if addr != "" {
			endpoints = append(endpoints, procedures.NFEndpoint{
				InstanceID: inst.NFInstanceID,
				Address:    addr,
			})
		}
	}
	return endpoints, nil
}

// DiscoverSMFAddress returns the address of an SMF serving the given slice.
// Uses a simple in-memory cache keyed by "SST:SD".
func (c *HTTPNRFClient) DiscoverSMFAddress(ctx context.Context, snssai amfctx.SNSSAISubscribed) (string, error) {
	key := fmt.Sprintf("%d:%s", snssai.SST, snssai.SD)
	c.mu.Lock()
	if addr, ok := c.cache[key]; ok {
		c.mu.Unlock()
		return addr, nil
	}
	c.mu.Unlock()

	endpoints, err := c.Discover(ctx, "SMF", "AMF", []amfctx.SNSSAISubscribed{snssai})
	if err != nil || len(endpoints) == 0 {
		return "", fmt.Errorf("nrf: no SMF found for slice SST=%d SD=%s: %w", snssai.SST, snssai.SD, err)
	}
	addr := endpoints[0].Address
	c.mu.Lock()
	c.cache[key] = addr
	c.mu.Unlock()
	return addr, nil
}

// ---- NSSF Client (Nnssf_NSSelection) ----------------------------------------

// HTTPNSSFClient calls the NSSF NSSelection API for slice-aware registration.
// Ref: TS 29.531 §5.2.2.2
type HTTPNSSFClient struct {
	address string
	client  *http.Client
}

// NSSelection calls NSSF to get the authorised NSSAI for a UE.
// Returns the intersection of requested slices and the NSSF-configured allowed list.
// Ref: TS 29.531 §5.2.2.2.3.1
func (c *HTTPNSSFClient) NSSelection(ctx context.Context, nfType, nfID string, requested []amfctx.SNSSAISubscribed) ([]amfctx.SNSSAISubscribed, error) {
	params := url.Values{
		"nf-type": {nfType},
		"nf-id":   {nfID},
	}
	if len(requested) > 0 {
		type snssaiQ struct {
			SST int    `json:"sst"`
			SD  string `json:"sd,omitempty"`
		}
		list := make([]snssaiQ, 0, len(requested))
		for _, s := range requested {
			list = append(list, snssaiQ{SST: int(s.SST), SD: s.SD})
		}
		b, _ := json.Marshal(list)
		params.Set("slice-info-request-for-registration.requestedNssai", string(b))
	}
	reqURL := "https://" + c.address + "/nnssf-nsselection/v2/network-slice-information?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("nssf: NSSelection: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nssf: NSSelection: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nssf: NSSelection: status %d", resp.StatusCode)
	}

	var result struct {
		AllowedNssaiList []struct {
			AllowedSnssaiList []struct {
				SST int    `json:"sst"`
				SD  string `json:"sd,omitempty"`
			} `json:"allowedSnssaiList"`
		} `json:"allowedNssaiList"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("nssf: NSSelection decode: %w", err)
	}

	var allowed []amfctx.SNSSAISubscribed
	for _, entry := range result.AllowedNssaiList {
		for _, s := range entry.AllowedSnssaiList {
			allowed = append(allowed, amfctx.SNSSAISubscribed{
				SST: uint8(s.SST),
				SD:  s.SD,
			})
		}
	}
	return allowed, nil
}

// ---- PCF Client (Npcf_UEPolicyControl / N15) ----------------------------

// HTTPPCFClient calls the PCF over HTTP/2 for UE policy association.
// Ref: TS 29.525 §4.2.2
type HTTPPCFClient struct {
	address string
	client  *http.Client
}

func (c *HTTPPCFClient) CreateUEPolicyAssociation(ctx context.Context, supi, servingPlmn string) (string, []byte, error) {
	body, _ := json.Marshal(map[string]any{
		"supi":        supi,
		"servingPlmn": servingPlmn,
	})
	req, _ := http.NewRequestWithContext(ctx, "POST",
		"https://"+c.address+"/npcf-ue-policy-control/v1/ue-policies",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("pcf: CreateUEPolicyAssociation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var prob map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&prob)
		return "", nil, fmt.Errorf("pcf: CreateUEPolicyAssociation: status %d cause=%v",
			resp.StatusCode, prob["cause"])
	}

	var result struct {
		PolAssoID        string `json:"polAssoId"`
		UEPolicySections map[string]struct {
			Content string `json:"uePolicySectionContent"`
		} `json:"uePolicySections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, fmt.Errorf("pcf: CreateUEPolicyAssociation: decode: %w", err)
	}

	// Decode the first section's content as the UE Policy Container bytes.
	var container []byte
	for _, section := range result.UEPolicySections {
		if section.Content != "" {
			container, err = base64.StdEncoding.DecodeString(section.Content)
			if err != nil {
				return result.PolAssoID, nil, fmt.Errorf("pcf: decode policy container: %w", err)
			}
			break
		}
	}
	return result.PolAssoID, container, nil
}

func (c *HTTPPCFClient) DeleteUEPolicyAssociation(ctx context.Context, polAssoID string) error {
	req, _ := http.NewRequestWithContext(ctx, "DELETE",
		"https://"+c.address+"/npcf-ue-policy-control/v1/ue-policies/"+polAssoID,
		nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("pcf: DeleteUEPolicyAssociation: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// ---- PCF AM Policy Client (Npcf_AMPolicyControl / N15) ----------------------

// HTTPAMPolicyClient calls the PCF over HTTP/2 for AM Policy Association.
// Ref: TS 29.507 §4.2.2
type HTTPAMPolicyClient struct {
	address string
	client  *http.Client
}

// CreateAMPolicyAssociation creates an AM Policy Association at registration.
// Returns the polAssoId, RFSP index, and optional service area restriction (nil = unrestricted).
// Non-fatal — caller should log and continue if it fails. Ref: TS 29.507 §4.2.2.2
func (c *HTTPAMPolicyClient) CreateAMPolicyAssociation(ctx context.Context, supi, accessType, mcc, mnc string) (
	polAssoID string, rfsp int, servAreaRes *amfctx.ServiceAreaRestriction, err error) {
	body, _ := json.Marshal(map[string]any{
		"supi":       supi,
		"accessType": accessType,
		"plmnId":     map[string]string{"mcc": mcc, "mnc": mnc},
	})
	req, _ := http.NewRequestWithContext(ctx, "POST",
		"https://"+c.address+"/npcf-ampolicycontrol/v1/policies",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", 0, nil, fmt.Errorf("pcf: CreateAMPolicyAssociation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var prob map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&prob)
		return "", 0, nil, fmt.Errorf("pcf: CreateAMPolicyAssociation: status %d cause=%v",
			resp.StatusCode, prob["cause"])
	}

	var result struct {
		PolAssoID   string  `json:"polAssoId"`
		RFSP        float64 `json:"rfsp"`
		ServAreaRes *struct {
			RestrictionType string `json:"restrictionType"`
			Areas           []struct {
				TACs []string `json:"tacs"`
			} `json:"areas"`
		} `json:"servAreaRes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, nil, fmt.Errorf("pcf: CreateAMPolicyAssociation: decode: %w", err)
	}

	var sar *amfctx.ServiceAreaRestriction
	if result.ServAreaRes != nil && result.ServAreaRes.RestrictionType != "" {
		sar = &amfctx.ServiceAreaRestriction{
			RestrictionType: result.ServAreaRes.RestrictionType,
		}
		for _, area := range result.ServAreaRes.Areas {
			if result.ServAreaRes.RestrictionType == "ALLOWED_AREAS" {
				sar.AllowedTACs = append(sar.AllowedTACs, area.TACs...)
			} else {
				sar.NotAllowedTACs = append(sar.NotAllowedTACs, area.TACs...)
			}
		}
	}
	return result.PolAssoID, int(result.RFSP), sar, nil
}

// DeleteAMPolicyAssociation releases the AM policy association at deregistration.
// Ref: TS 29.507 §4.2.2.4
func (c *HTTPAMPolicyClient) DeleteAMPolicyAssociation(ctx context.Context, polAssoID string) error {
	req, _ := http.NewRequestWithContext(ctx, "DELETE",
		"https://"+c.address+"/npcf-ampolicycontrol/v1/policies/"+polAssoID,
		nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("pcf: DeleteAMPolicyAssociation: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// ---- SMSF Client (Nsmsf_SMService) ---------------------------------------

// HTTPSMSFClient calls the SMSF over mTLS HTTP/2 to relay MO SMS.
// Implements nasmsg.SMSFClient.
// Ref: TS 29.540 §5.2.4 (Nsmsf_SMService_UplinkSMS)
type HTTPSMSFClient struct {
	address string
	client  *http.Client
}

// UplinkSMS forwards an MO SMS payload (base64 SM-CP/RP container from the NAS
// Payload Container, PCT=0x02) to the SMSF. The AMF is a transparent relay and
// does not parse the container. A 404 means the SMSF has no active SMS context.
// Ref: TS 29.540 §5.2.4
func (c *HTTPSMSFClient) UplinkSMS(ctx context.Context, supi, smsRecordID, smsPayloadBase64 string) error {
	body, _ := json.Marshal(map[string]string{
		"smsRecordId": smsRecordID,
		"smsPayload":  smsPayloadBase64,
	})
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://"+c.address+"/nsmsf-sms/v2/ue-contexts/"+url.PathEscape(supi)+"/sendsms",
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("smsf: uplink sms: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("smsf: uplink sms: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		var prob map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&prob)
		return fmt.Errorf("smsf: uplink sms: status %d cause=%v", resp.StatusCode, prob["cause"])
	}
	return nil
}
