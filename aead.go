package natrium

// #cgo darwin CFLAGS: -I/usr/local/include
// #cgo darwin LDFLAGS: -l/usr/local/lib/libsodium.a
// #cgo linux windows android LDFLAGS: -Wl,-Bstatic -lsodium -Wl,-Bdynamic
// #include <stdio.h>
// #include <sodium.h>
import "C"
import (
	"crypto/cipher"
	"errors"
)

type natrAEAD struct {
	key *[32]byte
}

var _AEADKeyLength = 0
var _AEADNonceLength = 0
var _AEADOverheadBytes = 0

func (ctx *natrAEAD) Seal(dst, nonce, plaintext, data []byte) []byte {
	if nonce == nil {
		nonce = make([]byte, _AEADNonceLength)
	}
	out := make([]byte, len(plaintext)+_AEADOverheadBytes)
	rv := C.crypto_aead_chacha20poly1305_encrypt(g2cbt(out), nil,
		g2cbt(plaintext), C.ulonglong(len(plaintext)), g2cbt(data), C.ulonglong(len(data)),
		nil, g2cbt(nonce), g2cbt(ctx.key[:]))
	if rv != 0 {
		panic("crypto_secretbox_easy returned non-zero")
	}
	return append(dst, out...)
}

func (ctx *natrAEAD) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if nonce == nil {
		nonce = make([]byte, _AEADNonceLength)
	}
	out := make([]byte, len(ciphertext)-_AEADOverheadBytes)
	rv := C.crypto_aead_chacha20poly1305_decrypt(g2cbt(out), nil, nil,
		g2cbt(ciphertext), C.ulonglong(len(ciphertext)), g2cbt(data), C.ulonglong(len(data)),
		g2cbt(nonce), g2cbt(ctx.key[:]))
	if rv != 0 {
		return nil, errors.New("MAC error")
	}
	return append(dst, out...), nil
}

func (ctx *natrAEAD) NonceSize() int {
	return _AEADNonceLength
}

func (ctx *natrAEAD) Overhead() int {
	return _AEADOverheadBytes
}

// AEAD creates an object implementing the standard Go AEAD
// (Authenticated Encryption with Associated Data) interface. Keys must be 32
// bytes long, and the underlying algorithm uses the ChaCha20 stream cipher
// with the Poly1305 authentication function.
func AEAD(key []byte) cipher.AEAD {

	//PLACEHOLDER
	//lol, _ := aes.NewCipher(key)
	//toret, _ := cipher.NewGCM(lol)
	//return toret

	if len(key) != _AEADKeyLength {
		panic("AEAD key needs to be 32 bytes (256 bits) long")
	}
	arr := new([32]byte)
	copy(arr[:], key)
	return &natrAEAD{arr}
}

type dummyAEAD struct{}

func (ctx *dummyAEAD) Seal(dst, nonce, plaintext, data []byte) []byte {
	return append(dst, plaintext...)
}

func (ctx *dummyAEAD) Open(dst, nonce, plaintext, data []byte) ([]byte, error) {
	return append(dst, plaintext...), nil
}

func (ctx *dummyAEAD) NonceSize() int {
	return _AEADNonceLength
}

func (ctx *dummyAEAD) Overhead() int {
	return 0
}

func init() {
	C.sodium_init()
	_AEADKeyLength = int(C.crypto_aead_chacha20poly1305_keybytes())
	_AEADNonceLength = int(C.crypto_aead_chacha20poly1305_npubbytes())
	_AEADOverheadBytes = int(C.crypto_aead_chacha20poly1305_abytes())
}
