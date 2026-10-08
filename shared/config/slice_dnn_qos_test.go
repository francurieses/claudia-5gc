package operatorcfg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOperator_SliceDNNQoS(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "operator.yaml")
	y := "plmn: {mcc: '001', mnc: '01'}\nslice_dnn_qos:\n  - sst: 1\n    sd: \"000001\"\n    dnn: internet\n    session_ambr: {uplink: \"20 Mbps\", downlink: \"30 Mbps\"}\n"
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	op, err := LoadOperator(p)
	if err != nil {
		t.Fatal(err)
	}
	l := op.SliceDNNQoSList()
	if len(l) != 1 || l[0].SST != 1 || l[0].SD != "000001" || l[0].DNN != "internet" || l[0].SessionAMBR.Downlink != "30 Mbps" {
		t.Errorf("got %+v", l)
	}
	var nilOp *OperatorConfig
	if nilOp.SliceDNNQoSList() != nil {
		t.Error("nil config must yield nil list")
	}
}
