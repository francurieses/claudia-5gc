package suci

import (
	"encoding/hex"
	"testing"
)

// TestDeconceaProfileB_AnnexC44Vector verifies the TS 33.501 Annex C.4.4.1
// published Profile B test vector (IMSI-based SUPI, MCC/MNC 274/012,
// MSIN 001002086).
func TestDeconceaProfileB_AnnexC44Vector(t *testing.T) {
	priv, _ := hex.DecodeString("f1ab1074477ebcc7f554ea1c5fc368b1616730155e0041ac447d6301975fecda")
	out, _ := hex.DecodeString("039aab8376597021e855679a9778ea0b67396e68c66df32c0f41e9acca2da9b9d146a33fc2716ac7dae96aa30a4d")
	res, err := DeconceaProfileB(SUCI{
		MCC: "274", MNC: "012", RoutingIndicator: "0000",
		ProtectionScheme: ProfileB, HomeNetworkPublicKeyID: 2, SchemeOutput: out,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if res.MSIN != "001002086" {
		t.Fatalf("MSIN = %q, want 001002086", res.MSIN)
	}
	if res.SUPI != "imsi-274012001002086" {
		t.Fatalf("SUPI = %q, want imsi-274012001002086", res.SUPI)
	}
}
