package natrium

// #cgo darwin CFLAGS: -I/usr/local/include
// #cgo darwin LDFLAGS: -l/usr/local/lib/libsodium.a
// #cgo linux windows android LDFLAGS: -Wl,-Bstatic -lsodium -Wl,-Bdynamic
// #include <stdio.h>
// #include <sodium.h>
import "C"
import "unsafe"

// RandUint32 returns a random uint32.
func RandUint32() uint32 {
	return uint32(C.randombytes_random())
}

// RandUint32LT returns a random uint32 from 0 to lim, uniformly.
func RandUint32LT(lim uint32) uint32 {
	return uint32(C.randombytes_uniform(C.uint32_t(lim)))
}

// RandBytes fills the given byte slice with random values.
func RandBytes(b []byte) {
	C.randombytes_buf(unsafe.Pointer(g2cbt(b)), C.size_t(len(b)))
}
