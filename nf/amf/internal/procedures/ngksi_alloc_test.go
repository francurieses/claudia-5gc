package procedures

// Tests for ngKSI allocation during authentication.
// A fresh ngKSI must differ from the one the UE holds for its existing native
// 5G security context, otherwise a spec-conformant UE rejects the Authentication
// Request with 5GMM cause #71 "ngKSI already in use".
// Ref: TS 24.501 §5.4.1.2.1, §5.4.1.3.2, §5.4.1.3.7.

import "testing"

func TestAllocateFreshNGKSI_DiffersFromCurrent(t *testing.T) {
	// For every ngKSI the UE could currently hold (0..6), the allocated value
	// must differ and stay in the valid 0..6 range (7 = "no key available").
	for cur := byte(0); cur <= 6; cur++ {
		got := allocateFreshNGKSI(cur)
		if got == cur {
			t.Errorf("allocateFreshNGKSI(%d) = %d; must differ from current ngKSI", cur, got)
		}
		if got > 6 {
			t.Errorf("allocateFreshNGKSI(%d) = %d; out of valid range 0..6", cur, got)
		}
	}
}

func TestAllocateFreshNGKSI_NoKeyAvailable(t *testing.T) {
	// ngKSI 7 means the UE has no key; any valid 0..6 value is acceptable.
	got := allocateFreshNGKSI(7)
	if got > 6 {
		t.Errorf("allocateFreshNGKSI(7) = %d; out of valid range 0..6", got)
	}
}

func TestAllocateFreshNGKSI_RepeatedRegistrationsRotate(t *testing.T) {
	// Simulate successive registrations where the UE presents the ngKSI it was
	// last assigned. Each round must yield a value different from the last, so a
	// real UE never sees a colliding ngKSI on re-registration.
	cur := byte(7) // first registration: UE has no key
	for i := 0; i < 10; i++ {
		next := allocateFreshNGKSI(cur)
		if next == cur {
			t.Fatalf("round %d: allocateFreshNGKSI(%d) reused the current ngKSI", i, cur)
		}
		cur = next // UE now holds `next`; it will present it on the next registration
	}
}
