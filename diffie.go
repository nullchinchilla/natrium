package natrium

import "crypto/rand"

// #cgo darwin CFLAGS: -I/usr/local/include
// #cgo darwin LDFLAGS: /usr/local/lib/libsodium.a
// #cgo linux windows android LDFLAGS: -Wl,-Bstatic -lsodium -Wl,-Bdynamic
// #include <stdio.h>
// #include <sodium.h>
import "C"

type ECDHPublic []byte
type ECDHPrivate []byte

var ECDHKeyLength = 0

func ECDHGenerateKey() ECDHPrivate {
	toret := make([]byte, ECDHKeyLength)
	rand.Read(toret)
	return toret
}

func (priv ECDHPrivate) PublicKey() ECDHPublic {
	toret := make([]byte, ECDHKeyLength)
	C.crypto_scalarmult_base((*C.uchar)(&toret[0]),
		(*C.uchar)(&priv[0]))
	return toret
}

func ECDHSecret(our_priv ECDHPrivate, their_publ ECDHPublic) []byte {
	toret := make([]byte, ECDHKeyLength)
	C.crypto_scalarmult(
		(*C.uchar)(&toret[0]),
		(*C.uchar)(&our_priv[0]),
		(*C.uchar)(&their_publ[0]))
	return toret
}

func TripleECDH(ourAuth ECDHPrivate, theirAuth ECDHPublic, ourEph ECDHPrivate, theirEph ECDHPublic) []byte {
	gEA := ECDHSecret(ourEph, theirAuth)
	gAE := ECDHSecret(ourAuth, theirEph)
	gEE := ECDHSecret(ourEph, theirEph)
	if CTCompare(ourEph.PublicKey(), theirEph) == -1 {
		return SecureHash(append(append(gEA, gAE...), gEE...), nil)
	} else {
		return SecureHash(append(append(gAE, gEA...), gEE...), nil)
	}
}

func init() {
	C.sodium_init()
	ECDHKeyLength = C.crypto_scalarmult_BYTES
}
