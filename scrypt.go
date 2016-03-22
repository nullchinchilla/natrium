package natrium

// #cgo LDFLAGS: -Wl,-Bstatic -lsodium -Wl,-Bdynamic
// #include <stdio.h>
// #include <sodium.h>
import "C"

func Scrypt(pwd []byte, salt []byte, oplim uint64, memlim uint64) {
	if len(salt) != C.crypto_pwhash_scryptsalsa208sha256_SALTBYTES {
		panic("salt of wrong length")
	}

}
