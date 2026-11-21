package main

// am_nssai_test.go - AMF-036: GetAMSubscriptionData decodes nssai.singleNssais
// as well as nssai.defaultSingleNssais (TS 29.503 Nssai).

import (
	"net/http"
	"testing"
)

func TestGetAMSubscriptionDataSingleNssais(t *testing.T) {
	const body = `{"nssai":{"defaultSingleNssais":[{"sst":1,"sd":"000001"},{"sst":1,"sd":"000003","subjectToNetworkSliceSpecificAuthenticationAndAuthorization":true}],` +
		`"singleNssais":[{"sst":1,"sd":"000001"},{"sst":2,"sd":"000002","dnn":"iot"}]}}`
	addr, _, hc := captureServer(t, http.StatusOK, body, "")
	c := newUDMClient(addr, hc, goldenModes(t)[0])
	sub, err := c.GetAMSubscriptionData(t.Context(), goldenSUPI)
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.DefaultNSSAI) != 2 || sub.DefaultNSSAI[0].SD != "000001" || !sub.DefaultNSSAI[1].SubjectToNSSAA {
		t.Fatalf("defaults = %+v", sub.DefaultNSSAI)
	}
	// default ∪ single, de-duplicated on SST+SD: 1-000001, 1-000003, 2-000002.
	if len(sub.AllowedNSSAI) != 3 || sub.AllowedNSSAI[2].SST != 2 || sub.AllowedNSSAI[2].DNN != "iot" {
		t.Fatalf("subscribed = %+v", sub.AllowedNSSAI)
	}
}
