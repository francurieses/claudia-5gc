package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLockEstablishmentSerialises checks that two establishments for the same
// SUPI+PSI never run their critical section concurrently, while a different PSI
// is independent.
func TestLockEstablishmentSerialises(t *testing.T) {
	s := &Server{}
	var inside, maxInside int32
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock := s.lockEstablishment("imsi-001010000000001", 1)
			defer unlock()
			n := atomic.AddInt32(&inside, 1)
			if n > atomic.LoadInt32(&maxInside) {
				atomic.StoreInt32(&maxInside, n)
			}
			time.Sleep(5 * time.Millisecond)
			atomic.AddInt32(&inside, -1)
		}()
	}
	wg.Wait()
	if maxInside != 1 {
		t.Fatalf("concurrent establishments for same SUPI/PSI: %d", maxInside)
	}
	u1 := s.lockEstablishment("imsi-001010000000001", 2)
	u2 := s.lockEstablishment("imsi-001010000000001", 1)
	u1()
	u2()
}
