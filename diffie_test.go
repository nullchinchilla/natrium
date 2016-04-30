package natrium

import (
	"crypto/subtle"
	"testing"
)

func TestTripleECDH(t *testing.T) {
	for i := 0; i < 10; i++ {
		ai := ECDHGenerateKey()
		ae := ECDHGenerateKey()
		bi := ECDHGenerateKey()
		be := ECDHGenerateKey()
		if subtle.ConstantTimeCompare(TripleECDH(ai, bi.PublicKey(), ae, be.PublicKey()),
			TripleECDH(bi, ai.PublicKey(), be, ae.PublicKey())) != 1 {
			t.FailNow()
		}
	}
}
