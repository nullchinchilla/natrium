package natrium

import "crypto/rand"

// #cgo darwin CFLAGS: -I/usr/local/include
// #cgo darwin LDFLAGS: /usr/local/lib/libsodium.a
// #cgo linux windows android LDFLAGS: -Wl,-Bstatic -lsodium -Wl,-Bdynamic
// #include <stdio.h>
// #include <sodium.h>
import "C"

// ECDHPublic represents a X25519 public key.
type ECDHPublic []byte

// ECDHPrivate represents a X25519 private key.
type ECDHPrivate []byte

// ECDHKeyLength represents the length of an ECDH public or private key.
var ECDHKeyLength = C.crypto_scalarmult_BYTES

// ECDHGenerateKey generates an ECDH private key.
func ECDHGenerateKey() ECDHPrivate {
	toret := make([]byte, ECDHKeyLength)
	rand.Read(toret)
	return toret
}

// PublicKey derives the public key corresponding to the ECDH private key.
func (priv ECDHPrivate) PublicKey() ECDHPublic {
	toret := make([]byte, ECDHKeyLength)
	C.crypto_scalarmult_base((*C.uchar)(&toret[0]),
		(*C.uchar)(&priv[0]))
	return toret
}

// ECDHSecret computes the Diffie-Hellman shared-secret given our private key and their public key.
func ECDHSecret(ourPriv ECDHPrivate, theirPubl ECDHPublic) []byte {
	toret := make([]byte, ECDHKeyLength)
	C.crypto_scalarmult(
		(*C.uchar)(&toret[0]),
		(*C.uchar)(&ourPriv[0]),
		(*C.uchar)(&theirPubl[0]))
	return toret
}

// TripleECDH is a convenience function does a triple Diffie-Hellman authenticated key exchange; it derives a shared secret from both long term keys and ephemeral keys to provide both deniable and forward-secure session-key derivation.
func TripleECDH(ourAuth ECDHPrivate, theirAuth ECDHPublic, ourEph ECDHPrivate, theirEph ECDHPublic) []byte {
	gEA := ECDHSecret(ourEph, theirAuth)
	gAE := ECDHSecret(ourAuth, theirEph)
	gEE := ECDHSecret(ourEph, theirEph)
	if CTCompare(ourEph.PublicKey(), theirEph) == -1 {
		return SecureHash(append(append(gEA, gAE...), gEE...), nil)
	}
	return SecureHash(append(append(gAE, gEA...), gEE...), nil)
}
