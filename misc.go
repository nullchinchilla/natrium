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

func g2cbt(f []byte) *C.uchar {
	if len(f) > 0 {
		return (*C.uchar)(&f[0])
	} else {
		return nil
	}
}

func FillRandom(b []byte) {
	C.randombytes_buf(unsafe.Pointer(&b[0]), C.size_t(len(b)))
}
