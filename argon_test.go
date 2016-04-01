package natrium

import "testing"

func BenchmarkArgon(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pwd := make([]byte, 8)
		FillRandom(pwd)
		salt := make([]byte, PasswordSaltLen)
		FillRandom(salt)
		PasswordHash(pwd, salt, 10, 64*1024*1024)
	}
}
