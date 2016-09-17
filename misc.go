package natrium

import (
	"encoding/hex"
	"unsafe"
)

// #cgo darwin CFLAGS: -I/usr/local/include
// #cgo darwin LDFLAGS: /usr/local/lib/libsodium.a
// #cgo linux windows android LDFLAGS: -Wl,-Bstatic -lsodium -Wl,-Bdynamic
// #include <stdio.h>
// #include <sodium.h>
import "C"

// TODO use the sodium encode and decode

// HexEncode encodes a byte array to a hexadecimal string.
func HexEncode(bts []byte) string {
	return hex.EncodeToString(bts)
}

// HexDecode decodes a hexadecimal string to a byte array.
func HexDecode(str string) ([]byte, error) {
	return hex.DecodeString(str)
}

// CTCompare returns 0 if the two byte strings are identical, -1 if a is less than b (little-endian), and 1 if a is larger than b. It runs in constant time given a particular length of a and b.
func CTCompare(a []byte, b []byte) int {
	if len(a) != len(b) {
		panic("unequal lengths passed to CTCompare")
	}
	return int(C.sodium_compare(g2cbt(a), g2cbt(b), C.size_t(len(a))))
}

func g2cbt(f []byte) *C.uchar {
	if len(f) > 0 {
		return (*C.uchar)(&f[0])
	}
	return nil
}

func g2cst(f []byte) *C.char {
	if len(f) > 0 {
		return (*C.char)(unsafe.Pointer(&f[0]))
	}
	return nil
}

func init() {
	C.sodium_init()
}
