package natrium

import (
	"encoding/hex"
	"unsafe"
)

// #cgo LDFLAGS: -Wl,-Bstatic -lsodium -Wl,-Bdynamic
// #include <stdio.h>
// #include <sodium.h>
import "C"

// TODO use the sodium encode and decode

func HexEncode(bts []byte) string {
	return hex.EncodeToString(bts)
}

func HexDecode(str string) ([]byte, error) {
	return hex.DecodeString(str)
}

// CTCompare returns 0 if the two byte strings are identical, -1 if a is
// less than b (little-endian), and 1 if a is larger than b.
func CTCompare(a []byte, b []byte) int {
	if len(a) != len(b) {
		panic("unequal lengths passed to CTCompare")
	}
	return int(C.sodium_compare(g2cbt(a), g2cbt(b), C.size_t(len(a))))
}

func g2cbt(f []byte) *C.uchar {
	if len(f) > 0 {
		return (*C.uchar)(&f[0])
	} else {
		return nil
	}
}

func g2cst(f []byte) *C.char {
	if len(f) > 0 {
		return (*C.char)(unsafe.Pointer(&f[0]))
	} else {
		return nil
	}
}
