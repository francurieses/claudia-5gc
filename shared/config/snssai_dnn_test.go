package operatorcfg

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSNSSAIEntryDNN(t *testing.T) {
	src := `snssais: [{sst: 1, sd: "000002", dnn: gaming}, {sst: 1, sd: "000001"}]`
	var op OperatorConfig
	if err := yaml.Unmarshal([]byte(src), &op); err != nil {
		t.Fatal(err)
	}
	if got := op.SNSSAIs[0].DNN; got != "gaming" {
		t.Errorf("DNN[0]=%q", got)
	}
	if got := op.SNSSAIs[1].DNN; got != "" {
		t.Errorf("DNN[1]=%q", got)
	}
}
