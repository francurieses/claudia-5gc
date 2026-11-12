// Package server — notification client for Nlmf_Location EventSubscription.
//
// This file implements the NotificationClient interface used by the LMF to POST
// LocationNotification bodies to the LCS consumer's notificationUri.
//
// Delivery is best-effort: the LMF retries once on 5xx or transport error, then
// drops the notification (logged). The client is injected via the Server so tests
// can supply a mock sink without requiring a live mTLS stack.
//
// Ref: TS 29.572 §6.1.6.2.4 (LocationNotification body schema).
// Ref: TS 29.572 §5.2.3 (EventSubscription notification delivery).
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// EventNotifier is the optional NotificationClient capability that delivers a
// TS 29.572 EventNotify callback (EventNotifyData) to an hgmlcCallBackURI. It
// is a separate interface so the legacy NotificationClient (and the test
// doubles implementing it) stays unchanged.
//
// Ref: TS 29.572 §5.2.2.2 / TS29572_Nlmf_Location.yaml callback EventNotify.
type EventNotifier interface {
	// PostEventNotify sends n to uri; success is a 2xx answer (204 expected).
	PostEventNotify(ctx context.Context, uri string, n EventNotifyData) error
}

// NotificationItem is one entry in a LocationNotification.
// Ref: TS 29.572 §6.1.6.2.4.
//
// oapi: none project-specific LMF location notification envelope (3GPP equivalent: TS 29.572 DetermineLocation periodic/area event + EventNotifyData), no YAML path
type NotificationItem struct {
	// LocationData is the per-sample positioning result.
	LocationData LocationData `json:"locationData"`
	// AreaEventInfo is present only for AOI subscriptions, and only when a
	// boundary crossing triggered the notification.
	AreaEventInfo *AreaEventInfo `json:"areaEventInfo,omitempty"`
}

// AreaEventInfo carries the AOI crossing event type.
// Ref: TS 29.572 §6.1.6.2.4.
//
// oapi: none project-specific LMF location notification envelope (3GPP equivalent: TS 29.572 DetermineLocation periodic/area event + EventNotifyData), no YAML path
type AreaEventInfo struct {
	// Event is "AREA_ENTERING" or "AREA_LEAVING".
	Event string `json:"event"`
}

// LocationNotification is the body POSTed to the consumer's notificationUri.
// Ref: TS 29.572 §6.1.6.2.4.
//
// oapi: none project-specific LMF location notification envelope (3GPP equivalent: TS 29.572 DetermineLocation periodic/area event + EventNotifyData), no YAML path
type LocationNotification struct {
	// SubId correlates this notification to its subscription resource.
	SubId string `json:"subId"`
	// NotificationItems carries one or more per-sample results.
	// LMF-003 sends exactly one item per POST.
	NotificationItems []NotificationItem `json:"notificationItems"`
}

// NotificationClient posts LocationNotification bodies to caller-supplied URIs.
// Implementations must be safe for concurrent use.
type NotificationClient interface {
	// PostNotification sends n to uri and returns an error on transport failure
	// or a non-2xx response. The caller is responsible for retry logic.
	PostNotification(ctx context.Context, uri string, n LocationNotification) error
}

// HTTPNotificationClient is the production NotificationClient using the
// injected http.Client (typically the mTLS shared/sbi client).
type HTTPNotificationClient struct {
	// Client is an HTTP/2-capable (mTLS) *http.Client.
	Client *http.Client
}

// PostNotification implements NotificationClient.
// It serialises n to JSON and POSTs to uri. Any non-2xx response is an error.
//
// Ref: TS 29.572 §6.1.6.2.4; TS 29.500 §4.4.1 (mTLS HTTP/2).
func (c *HTTPNotificationClient) PostNotification(ctx context.Context, uri string, n LocationNotification) error {
	return c.postJSON(ctx, uri, n)
}

// PostEventNotify implements EventNotifier: it POSTs the EventNotifyData to the
// hgmlcCallBackURI over the same mTLS client; any non-2xx answer is an error.
//
// Ref: TS 29.572 callback EventNotify (204 expected); TS 29.500 §4.4.1.
func (c *HTTPNotificationClient) PostEventNotify(ctx context.Context, uri string, n EventNotifyData) error {
	return c.postJSON(ctx, uri, n)
}

// postJSON serialises v to JSON and POSTs it to uri, treating non-2xx as error.
func (c *HTTPNotificationClient) postJSON(ctx context.Context, uri string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("lmf: notification client: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("lmf: notification client: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("lmf: notification client: do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("lmf: notification client: server returned %d", resp.StatusCode)
	}
	return nil
}

// EventNotifyData is the body POSTed to the hgmlcCallBackURI of a deferred
// location session (the Event Notify callback; EventNotifyDataExt without
// addEventNotifyDatas is wire-identical).
//
// Ref: TS 29.572 §6.1.6.2 (EventNotifyData); TS29572_Nlmf_Location.yaml callback EventNotify.
//
// oapi: TS29572_Nlmf_Location.yaml#/components/schemas/EventNotifyData
type EventNotifyData struct {
	// ReportedEventType is mandatory (ReportedEventType enum).
	ReportedEventType string `json:"reportedEventType"`
	Supi              string `json:"supi,omitempty"`
	Gpsi              string `json:"gpsi,omitempty"`
	HgmlcCallBackURI  string `json:"hgmlcCallBackURI,omitempty"`
	// LdrReference is mandatory and correlates the report to the request.
	LdrReference                string          `json:"ldrReference"`
	LocationEstimate            *GeographicArea `json:"locationEstimate,omitempty"`
	AgeOfLocationEstimate       *int            `json:"ageOfLocationEstimate,omitempty"`
	TimestampOfLocationEstimate string          `json:"timestampOfLocationEstimate,omitempty"`
	TerminationCause            string          `json:"terminationCause,omitempty"`
}
