package natrium

// #cgo darwin CFLAGS: -I/usr/local/include
// #cgo darwin LDFLAGS: /usr/local/lib/libsodium.a
// #cgo linux windows android LDFLAGS: -Wl,-Bstatic -lsodium -Wl,-Bdynamic
// #include <stdio.h>
// #include <sodium.h>
import "C"

// SecureHash uses the Blake2b algorithm to generate a 256-bit (32-byte)
// hash of a message with an optional key. The key parameter can be nil if
// normal hashing, instead of authenticated hashing, is wanted.
func SecureHash(message []byte, key []byte) []byte {
	out := make([]byte, 32)
	var keyptr *C.uchar
	var msgptr *C.uchar
	var keylen C.size_t
	var msglen C.ulonglong
	if message == nil || len(message) == 0 {
		msgptr = nil
	} else {
		msgptr = (*C.uchar)(&message[0])
		msglen = C.ulonglong(len(message))
	}
	if key == nil || len(key) == 0 {
		keyptr = nil
	} else {
		keyptr = (*C.uchar)(&key[0])
		keylen = C.size_t(len(key))
	}
	C.crypto_generichash((*C.uchar)(&out[0]), 32,
		msgptr, msglen,
		keyptr, keylen)
	return out
}
