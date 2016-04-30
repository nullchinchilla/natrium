package natrium

// #cgo LDFLAGS: -Wl,-Bstatic -lsodium -Wl,-Bdynamic
// #include <stdio.h>
// #include <sodium.h>
import "C"
import "crypto/cipher"

type natrStream struct {
	key      *[32]byte
	nonce    *[8]byte
	blockcnt uint64
	buffer   []byte
}

// Stream creates a raw ChaCha20 streamer based on the key and nonce.
func Stream(key []byte, nonce []byte) cipher.Stream {
	lol := new([32]byte)
	if len(key) != 32 {
		panic("key of the wrong length")
	}
	copy(lol[:], key)
	haha := new([8]byte)
	copy(haha[:], nonce)
	return &natrStream{lol, haha, 0, nil}
}

func (ctx *natrStream) XORKeyStream(dst, src []byte) {
	if len(ctx.buffer) != 0 {
		lol := make([]byte, len(dst))
		n := copy(lol, ctx.buffer)
		for i := 0; i < n; i++ {
			dst[i] = lol[i] ^ src[i]
		}
		ctx.buffer = ctx.buffer[n:]
		if n == len(src) {
			return
		}
		ctx.XORKeyStream(dst[n:], src[n:])
		return
	}
	ctx.buffer = make([]byte, 16384)
	buffhand := (*C.uchar)(&ctx.buffer[0])
	C.crypto_stream_chacha20_xor_ic(buffhand, buffhand,
		C.ulonglong(16384), (*C.uchar)(&ctx.nonce[0]),
		C.uint64_t(ctx.blockcnt), (*C.uchar)(&ctx.key[0]))
	ctx.blockcnt += 1
	ctx.XORKeyStream(dst, src)
}
