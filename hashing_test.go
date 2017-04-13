package natrium

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestHashing(t *testing.T) {
	kee := make([]byte, 32)
	RandBytes(kee)
	hasher := SecureHasher(kee)
	buf := new(bytes.Buffer)
	for i := 0; i < 10; i++ {
		lol := make([]byte, rand.Int()%1000)
		RandBytes(lol)
		hasher.Write(lol)
		buf.Write(lol)
	}
	h1 := hasher.Sum(nil)
	h2 := SecureHash(buf.Bytes(), kee)
	if CTCompare(h1, h2) != 0 {
		t.Fail()
	}
}
