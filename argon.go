package natrium

// #cgo darwin CFLAGS: -I/usr/local/include
// #cgo darwin LDFLAGS: /usr/local/lib/libsodium.a
// #cgo linux windows android LDFLAGS: -Wl,-Bstatic -lsodium -Wl,-Bdynamic
// #include <stdio.h>
// #include <sodium.h>
import "C"
import "unsafe"

// PasswordSaltLen gives the length of the salt parameter to StretchKey
var PasswordSaltLen int

// StretchKey uses the Argon2 algorithm to create a 256-bit key based upon a password and a salt. This function is deterministic given a certain opslimit and memlimit.
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

// PasswordHash uses the Argon2 algorithm to create an ASCII string which includes opslimit, memlimit, a random salt, and a memory-hard hash. It's designed to be stored in databases and directly used with PasswordVerify.
func PasswordHash(pwd []byte, opslimit int, memlimit int) string {
	out := make([]byte, C.crypto_pwhash_STRBYTES)
	retval := C.crypto_pwhash_str(g2cst(out), g2cst(pwd), C.ulonglong(len(pwd)),
		C.ulonglong(opslimit), C.size_t(memlimit))
	if retval != 0 {
		panic("crypto_pwhash_str returned non-zero!")
	}
	for i := range out {
		if out[i] == 0 {
			return string(out[:i])
		}
	}
	return string(out[:len(out)-1])
}

// PasswordVerify verifies that the given password corresponds to the given salted hash string (of the format returned by PasswordHash).
func PasswordVerify(pwd []byte, hash string) bool {
	haha := []byte(hash)
	haha = append(haha, 0)
	return C.crypto_pwhash_str_verify(g2cst(haha), g2cst(pwd), C.ulonglong(len(pwd))) == 0
}

func init() {
	PasswordSaltLen = int(C.crypto_pwhash_SALTBYTES)
}
