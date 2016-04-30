package natrium

// #cgo LDFLAGS: -Wl,-Bstatic -lsodium -Wl,-Bdynamic
// #include <stdio.h>
// #include <sodium.h>
import "C"
import "unsafe"

var PasswordSaltLen int

func PasswordHash(pwd []byte, salt []byte, opslimit int, memlimit int) []byte {
	if len(salt) != PasswordSaltLen {
		panic("wrong salt length for crypto_pwhash")
	}
	toret := make([]byte, 32)
	retval := C.crypto_pwhash(g2cbt(toret), 32, (*C.char)(unsafe.Pointer(g2cbt(pwd))),
		C.ulonglong(len(pwd)), g2cbt(salt), C.ulonglong(opslimit),
		C.size_t(memlimit), nil)
	if retval != 0 {
		panic("crypto_pwhash returned non-zero!")
	}
	return toret
}

func init() {
	PasswordSaltLen = int(C.crypto_pwhash_SALTBYTES)
}
