package natrium

// #cgo darwin CFLAGS: -I/usr/local/include
// #cgo darwin LDFLAGS: /usr/local/lib/libsodium.a
// #cgo linux windows android LDFLAGS: -Wl,-Bstatic -lsodium -Wl,-Bdynamic
// #include <stdio.h>
// #include <sodium.h>
import "C"
import (
	"hash"
	"unsafe"
)

type b2bHasher struct {
	state    [384]byte
	orgstate [384]byte
}

func (bh *b2bHasher) cstate() *C.struct_crypto_generichash_blake2b_state {
	return (*C.struct_crypto_generichash_blake2b_state)(unsafe.Pointer(&bh.state))
}

func (bh *b2bHasher) Sum(b []byte) []byte {
	out := make([]byte, 32)
	rv := C.crypto_generichash_final(bh.cstate(), (*C.uchar)(&out[0]), 32)
	if rv != 0 {
		panic("crypto_generichash_final returned non-zero")
	}
	return append(b, out...)
}

func (bh *b2bHasher) Write(b []byte) (int, error) {
	rv := C.crypto_generichash_update(bh.cstate(), (*C.uchar)(&b[0]), C.ulonglong(len(b)))
	if rv != 0 {
		panic("crypto_generichash_update returned non-zero")
	}
	return len(b), nil
}

func (bh *b2bHasher) Reset() {
	bh.state = bh.orgstate
}

func (bh *b2bHasher) Size() int {
	return 32
}

func (bh *b2bHasher) BlockSize() int {
	return 32
}

// SecureHasher creates a Blake2b stream hasher.
func SecureHasher(key []byte) hash.Hash {
	toret := new(b2bHasher)
	var keyptr *C.uchar
	var keylen C.size_t
	if key == nil || len(key) == 0 {
		keyptr = nil
	} else {
		keyptr = (*C.uchar)(&key[0])
		keylen = C.size_t(len(key))
	}
	rv := C.crypto_generichash_init(toret.cstate(), keyptr, keylen, 32)
	if rv != 0 {
		panic("crypto_generichash_init returned non-zero!")
	}
	toret.orgstate = toret.state
	return toret
}

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
