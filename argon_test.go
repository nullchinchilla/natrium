package natrium

import "testing"

func BenchmarkArgon(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pwd := make([]byte, 8)
		RandBytes(pwd)
		salt := make([]byte, PasswordSaltLen)
		RandBytes(salt)
		PasswordHash(pwd, salt, 5, 64*1024*1024)
	}
}
