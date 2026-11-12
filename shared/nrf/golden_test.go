package nrf

import (
	"encoding/json"
	"testing"
)

func TestLegacyProfileMarshalGolden(t *testing.T) {
	p := NFProfile{
		NFInstanceID: "id1", NFType: "SMF", NFStatus: "REGISTERED", HeartBeatTimer: 10,
		FQDN: "smf.local", IPv4Addresses: []string{"10.0.0.1"},
		NFServices: []NFService{{ServiceInstanceID: "s1", ServiceName: "nsmf-pdusession",
			Versions: []NFServiceVersion{{APIVersionInURI: "v1", APIFullVersion: "1.0.0"}},
			Scheme:   "https", NFServiceStatus: "REGISTERED",
			IPEndpoints: []IPEndpoint{{IPv4Address: "10.0.0.1", Port: 8000}}}},
		SNSSAIs: []SNSSAIEntry{{SST: 1, SD: "010203"}}, DNNList: []string{"internet"},
	}
	b, err := json.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}
	// Golden captured from the pre-REL19-2.4 types: legacy peers must get
	// byte-identical profiles (no supportedFeatures, no extra keys).
	const golden = `{"nfInstanceId":"id1","nfType":"SMF","nfStatus":"REGISTERED","heartBeatTimer":10,"fqdn":"smf.local","ipv4Addresses":["10.0.0.1"],"nfServices":[{"serviceInstanceId":"s1","serviceName":"nsmf-pdusession","versions":[{"apiVersionInUri":"v1","apiFullVersion":"1.0.0"}],"scheme":"https","nfServiceStatus":"REGISTERED","ipEndPoints":[{"ipv4Address":"10.0.0.1","port":8000}]}],"sNssais":[{"sst":1,"sd":"010203"}],"dnnList":["internet"]}`
	if string(b) != golden {
		t.Fatalf("got %s", b)
	}
}
