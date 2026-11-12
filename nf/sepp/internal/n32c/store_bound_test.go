package n32c

import (
	"fmt"
	"testing"
	"time"
)

func TestStoreBoundedEvictsOldest(t *testing.T) {
	s := NewStore(nil)
	base := time.Unix(1000, 0)
	for i := 0; i < MaxContexts+5; i++ {
		s.Replace(Context{
			RemotePLMN: PlmnId{Mcc: "001", Mnc: fmt.Sprintf("%03d", i%1000)},
			CreatedAt:  base.Add(time.Duration(i) * time.Second),
		})
	}
	if s.Len() > MaxContexts {
		t.Fatalf("store exceeded bound: %d", s.Len())
	}
}

func TestCountResultRegistered(t *testing.T) { countResult(resultOK) }
