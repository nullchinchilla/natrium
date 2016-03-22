package natrium

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"fmt"
	"testing"
)

func TestStream(t *testing.T) {
	lol := Stream([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), make([]byte, 8))
	loll := Stream([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), make([]byte, 8))
	lele := make([]byte, 16)
	lol.XORKeyStream(lele, lele)
	loll.XORKeyStream(lele, lele)
	fmt.Printf("%v\n", lele)
}

func BenchmarkStream(b *testing.B) {
	lol := Stream([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), make([]byte, 8))
	b.ResetTimer()
	haha := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		lol.XORKeyStream(haha, haha)
	}
}

func BenchmarkStream_RC4(b *testing.B) {
	lol, _ := rc4.NewCipher([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	b.ResetTimer()
	haha := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		lol.XORKeyStream(haha, haha)
	}
}

func BenchmarkStream_AES(b *testing.B) {
	lolly, _ := aes.NewCipher([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	lol := cipher.NewCTR(lolly, make([]byte, 16))
	b.ResetTimer()
	haha := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		lol.XORKeyStream(haha, haha)
	}
}
