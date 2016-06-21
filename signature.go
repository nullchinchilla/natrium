package natrium

import (
	"encoding/json"
	"errors"
	"fmt"
)

// #cgo LDFLAGS: -Wl,-Bstatic -lsodium -Wl,-Bdynamic
// #include <stdio.h>
// #include <sodium.h>
import "C"

// EdDSA private key type
type EdDSAPrivate []byte

// EdDSA public key type
type EdDSAPublic []byte

func (k EdDSAPublic) String() string {
	return fmt.Sprintf("dsapub:%x", []byte(k))
}

func (k EdDSAPrivate) String() string {
	return fmt.Sprintf("dsaprv:%x", []byte(k))
}

var EdDSAPublicLength = 0
var EdDSAPrivateLength = 0
var EdDSASignatureLength = 0

// EdDSAGenerateKey generates an EdDSA private key. The public key
// can be derived from the private key, so there is no issue.
// Keys are represented by byte slices, and can be cast to and from them.
func EdDSAGenerateKey() EdDSAPrivate {
	priv := make([]byte, EdDSAPrivateLength)
	publ := make([]byte, EdDSAPublicLength)
	rv := C.crypto_sign_keypair((*C.uchar)(&publ[0]), (*C.uchar)(&priv[0]))
	if rv != 0 {
		panic("crypto_sign_keypair returned non-zero")
	}
	return priv
}

// EdDSADeriveKey derives an EdDSA private key from an arbitrary seed.
func EdDSADeriveKey(seed []byte) EdDSAPrivate {
	priv := make([]byte, EdDSAPrivateLength)
	publ := make([]byte, EdDSAPublicLength)
	seed = SecureHash(seed, nil)[:C.crypto_sign_SEEDBYTES]
	rv := C.crypto_sign_seed_keypair(g2cbt(publ), g2cbt(priv), g2cbt(seed))
	if rv != 0 {
		panic("crypto_sign_keypair returned non-zero")
	}
	return priv
}

// PublicKey obtains the public component of an EdDSA private key.
func (priv EdDSAPrivate) PublicKey() EdDSAPublic {
	toret := make([]byte, EdDSAPublicLength)
	rv := C.crypto_sign_ed25519_sk_to_pk((*C.uchar)(&toret[0]),
		(*C.uchar)(&priv[0]))
	if rv != 0 {
		panic("crypto_sign_ed25519_sk_to_pk returned non-zero")
	}
	return toret
}

// Sign signs a message using the given EdDSA private key, returning the signature.
func (priv EdDSAPrivate) Sign(message []byte) []byte {
	signature := make([]byte, EdDSASignatureLength)
	rv := C.crypto_sign_detached(
		(*C.uchar)(&signature[0]),
		nil,
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(&priv[0]))
	if rv != 0 {
		panic("crypto_sign_detached returned non-zero")
	}
	return signature
}

// ToECDH converts an EdDSA private key deterministically to a ECDH private key
func (priv EdDSAPrivate) ToECDH() ECDHPrivate {
	out := make([]byte, ECDHKeyLength)
	rv := C.crypto_sign_ed25519_sk_to_curve25519(g2cbt(out), g2cbt(priv))
	if rv != 0 {
		panic("crypto_sign_ed25519_sk_to_curve25519 returned non-zero")
	}
	return out
}

func (publ EdDSAPublic) MarshalJSON() ([]byte, error) {
	return json.Marshal([]byte(publ))
}

// Verify verifies a signature and a message using a public key. If there is
// a problem, then a non-nil value would be returned. A nil value means
// everything is fine.
func (publ EdDSAPublic) Verify(message []byte, signature []byte) error {
	if len(signature) != EdDSASignatureLength {
		panic(fmt.Sprintf("Signature passed has the wrong length (%v != %v)",
			len(signature), EdDSASignatureLength))
	}
	rv := C.crypto_sign_verify_detached(
		(*C.uchar)(&signature[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(&publ[0]))
	if rv != 0 {
		return errors.New("EdDSA signature is forged!")
	}
	return nil
}

// ToECDH converts an EdDSA public key deterministically to a ECDH public key
func (pub EdDSAPublic) ToECDH() ECDHPublic {
	out := make([]byte, ECDHKeyLength)
	rv := C.crypto_sign_ed25519_pk_to_curve25519(g2cbt(out), g2cbt(pub))
	if rv != 0 {
		panic("crypto_sign_ed25519_sk_to_curve25519 returned non-zero")
	}
	return out
}

func init() {
	C.sodium_init()
	EdDSAPrivateLength = C.crypto_sign_SECRETKEYBYTES
	EdDSAPublicLength = C.crypto_sign_PUBLICKEYBYTES
	EdDSASignatureLength = C.crypto_sign_BYTES
}
