package natrium

import "testing"

func BenchmarkArgon(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pwd := make([]byte, 8)
		RandBytes(pwd)
		PasswordHash(pwd, 5, 64*1024*1024)
	}
}
