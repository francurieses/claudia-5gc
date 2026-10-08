package context

import "testing"

func TestPagedPDUSessions(t *testing.T) {
	ue := &UEContext{}
	if got := ue.TakePagedPDUSessions(); got != nil {
		t.Fatalf("empty take = %v, want nil", got)
	}
	ue.AddPagedPDUSession(5)
	ue.AddPagedPDUSession(1)
	ue.AddPagedPDUSession(5)
	got := ue.PagedPDUSessions()
	if len(got) != 2 || got[0] != 1 || got[1] != 5 {
		t.Fatalf("PagedPDUSessions = %v, want [1 5]", got)
	}
	got = ue.TakePagedPDUSessions()
	if len(got) != 2 || got[0] != 1 || got[1] != 5 {
		t.Fatalf("Take = %v, want [1 5]", got)
	}
	if left := ue.PagedPDUSessions(); len(left) != 0 {
		t.Errorf("set not cleared: %v", left)
	}
}
