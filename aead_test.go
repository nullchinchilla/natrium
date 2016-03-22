package natrium

import (
	"crypto/cipher"
	"crypto/aes"
	"testing"
)

func Test_AEAD_Basic(t *testing.T) {
	tocrypt := []byte("Hello World")
	key := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	thingy := AEAD(key)
	crypted := thingy.Seal(make([]byte, 0), make([]byte, thingy.NonceSize()),
		tocrypt, nil)
	decrypted, err := thingy.Open(make([]byte, 0), make([]byte, thingy.NonceSize()),
		crypted, nil)
	if err != nil {
		t.FailNow()
	}
	for i := 0; i < len(decrypted); i++ {
		if tocrypt[i] != decrypted[i] {
			t.FailNow()
		}
	}
}

func Test_AEAD_NoData_Fail(t *testing.T) {
	tocrypt := []byte("Hello World")
	key := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	thingy := AEAD(key)
	crypted := thingy.Seal(make([]byte, 0), make([]byte, thingy.NonceSize()),
		tocrypt, nil)
	// Modify crypted
	crypted[3] = 100

	_, err := thingy.Open(make([]byte, 0), make([]byte, thingy.NonceSize()),
		crypted, nil)
	if err == nil {
		t.FailNow()
	}
}

func Test_AEAD_Data_Fail(t *testing.T) {
	tocrypt := []byte("Hello World")
	key := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	thingy := AEAD(key)
	dat := []byte("hello world")
	crypted := thingy.Seal(make([]byte, 0), make([]byte, thingy.NonceSize()),
		tocrypt, dat)
		
	dat[3] = 100

	_, err := thingy.Open(make([]byte, 0), make([]byte, thingy.NonceSize()),
		crypted, dat)
	if err == nil {
		t.FailNow()
	}
}

func BenchmarkAEAD(b *testing.B) {
	tocrypt := make([]byte, 1024)
	key := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	thingy := AEAD(key)
	nonce := make([]byte, thingy.NonceSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		thingy.Seal(make([]byte, 0), nonce, tocrypt, nil)
	}
}

func BenchmarkAEAD_AES(b *testing.B) {
	tocrypt := make([]byte, 1024)
	key := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	raw, _ := aes.NewCipher(key)
	thingy, _ := cipher.NewGCM(raw)
	nonce := make([]byte, thingy.NonceSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		thingy.Seal(make([]byte, 0), nonce, tocrypt, nil)
	}
}
