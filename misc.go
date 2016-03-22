package natrium

import (
	"encoding/hex"
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
