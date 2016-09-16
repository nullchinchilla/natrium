package natrium

// #cgo darwin CFLAGS: -I/usr/local/include
// #cgo darwin LDFLAGS: /usr/local/lib/libsodium.a
// #cgo linux windows android LDFLAGS: -Wl,-Bstatic -lsodium -Wl,-Bdynamic
// #include <stdio.h>
// #include <sodium.h>
import "C"
import "unsafe"

var PasswordSaltLen int

func StretchKey(pwd []byte, salt []byte, opslimit int, memlimit int) []byte {
	if salt == nil {
		salt = make([]byte, PasswordSaltLen)
	}
	if len(salt) != PasswordSaltLen {
		panic("wrong salt length for crypto_pwhash")
	}
	toret := make([]byte, 32)
	retval := C.crypto_pwhash(g2cbt(toret), 32, (*C.char)(unsafe.Pointer(g2cbt(pwd))),
		C.ulonglong(len(pwd)), g2cbt(salt), C.ulonglong(opslimit),
		C.size_t(memlimit), C.crypto_pwhash_ALG_DEFAULT)
	if retval != 0 {
		panic("crypto_pwhash returned non-zero!")
	}
	return toret
}

func PasswordHash(pwd []byte, opslimit int, memlimit int) string {
	out := make([]byte, C.crypto_pwhash_STRBYTES)
	retval := C.crypto_pwhash_str(g2cst(out), g2cst(pwd), C.ulonglong(len(pwd)),
		C.ulonglong(opslimit), C.size_t(memlimit))
	if retval != 0 {
		panic("crypto_pwhash_str returned non-zero!")
	}
	return string(out[:len(out)-1])
}

func PasswordVerify(pwd []byte, hash string) bool {
	haha := []byte(hash)
	haha = append(haha, 0)
	return C.crypto_pwhash_str_verify(g2cst(haha), g2cst(pwd), C.ulonglong(len(pwd))) == 0
}

func init() {
	PasswordSaltLen = int(C.crypto_pwhash_SALTBYTES)
}
