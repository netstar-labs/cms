package cms

import (
	"sync"
	"testing"
	"time"
)

// TestConcurrentSignVerify exercises Sign, Verify, VerifyAsSigned and SigningTime from many
// goroutines against one shared root pool and the package-level OID values. cms keeps no mutable
// package state, so this must be clean under -race; it pins that property.
func TestConcurrentSignVerify(t *testing.T) {
	now := time.Now()
	fx := fixtures(t, now)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				x := fx[(g+i)%len(fx)]
				if _, err := Verify(x.content, x.sig, x.roots, now); err != nil {
					t.Errorf("%s: Verify: %v", x.name, err)
					return
				}
				if _, err := VerifyAsSigned(x.content, x.sig, x.roots); err != nil {
					t.Errorf("%s: VerifyAsSigned: %v", x.name, err)
					return
				}
				SigningTime(x.sig)
			}
		}(g)
	}
	wg.Wait()
}
