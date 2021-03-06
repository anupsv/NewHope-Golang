package NewHope

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math"
	"runtime"
	"unsafe"
)

const (
	KeySize      = 32
	NonceSize    = 8
	INonceSize   = 12
	XNonceSize   = 24
	HNonceSize   = 16
	BlockSize    = 64
	stateSize    = 16
	chachaRounds = 20
	sigma0       = uint32(0x61707865)
	sigma1       = uint32(0x3320646e)
	sigma2       = uint32(0x79622d32)
	sigma3       = uint32(0x6b206574)
)

func blocksRef(x *[stateSize]uint32, in []byte, out []byte, nrBlocks int, isIetf bool) {
	if isIetf {
		var totalBlocks uint64
		totalBlocks = uint64(x[8]) + uint64(nrBlocks)
		if totalBlocks > math.MaxUint32 {
			panic("chacha20: Exceeded keystream per nonce limit")
		}
	}

	for n := 0; n < nrBlocks; n++ {
		x0, x1, x2, x3 := sigma0, sigma1, sigma2, sigma3
		x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 := x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15]

		for i := chachaRounds; i > 0; i -= 2 {
			// quarterround(x, 0, 4, 8, 12)
			x0 += x4
			x12 ^= x0
			x12 = (x12 << 16) | (x12 >> 16)
			x8 += x12
			x4 ^= x8
			x4 = (x4 << 12) | (x4 >> 20)
			x0 += x4
			x12 ^= x0
			x12 = (x12 << 8) | (x12 >> 24)
			x8 += x12
			x4 ^= x8
			x4 = (x4 << 7) | (x4 >> 25)

			// quarterround(x, 1, 5, 9, 13)
			x1 += x5
			x13 ^= x1
			x13 = (x13 << 16) | (x13 >> 16)
			x9 += x13
			x5 ^= x9
			x5 = (x5 << 12) | (x5 >> 20)
			x1 += x5
			x13 ^= x1
			x13 = (x13 << 8) | (x13 >> 24)
			x9 += x13
			x5 ^= x9
			x5 = (x5 << 7) | (x5 >> 25)

			// quarterround(x, 2, 6, 10, 14)
			x2 += x6
			x14 ^= x2
			x14 = (x14 << 16) | (x14 >> 16)
			x10 += x14
			x6 ^= x10
			x6 = (x6 << 12) | (x6 >> 20)
			x2 += x6
			x14 ^= x2
			x14 = (x14 << 8) | (x14 >> 24)
			x10 += x14
			x6 ^= x10
			x6 = (x6 << 7) | (x6 >> 25)

			// quarterround(x, 3, 7, 11, 15)
			x3 += x7
			x15 ^= x3
			x15 = (x15 << 16) | (x15 >> 16)
			x11 += x15
			x7 ^= x11
			x7 = (x7 << 12) | (x7 >> 20)
			x3 += x7
			x15 ^= x3
			x15 = (x15 << 8) | (x15 >> 24)
			x11 += x15
			x7 ^= x11
			x7 = (x7 << 7) | (x7 >> 25)

			// quarterround(x, 0, 5, 10, 15)
			x0 += x5
			x15 ^= x0
			x15 = (x15 << 16) | (x15 >> 16)
			x10 += x15
			x5 ^= x10
			x5 = (x5 << 12) | (x5 >> 20)
			x0 += x5
			x15 ^= x0
			x15 = (x15 << 8) | (x15 >> 24)
			x10 += x15
			x5 ^= x10
			x5 = (x5 << 7) | (x5 >> 25)

			// quarterround(x, 1, 6, 11, 12)
			x1 += x6
			x12 ^= x1
			x12 = (x12 << 16) | (x12 >> 16)
			x11 += x12
			x6 ^= x11
			x6 = (x6 << 12) | (x6 >> 20)
			x1 += x6
			x12 ^= x1
			x12 = (x12 << 8) | (x12 >> 24)
			x11 += x12
			x6 ^= x11
			x6 = (x6 << 7) | (x6 >> 25)

			// quarterround(x, 2, 7, 8, 13)
			x2 += x7
			x13 ^= x2
			x13 = (x13 << 16) | (x13 >> 16)
			x8 += x13
			x7 ^= x8
			x7 = (x7 << 12) | (x7 >> 20)
			x2 += x7
			x13 ^= x2
			x13 = (x13 << 8) | (x13 >> 24)
			x8 += x13
			x7 ^= x8
			x7 = (x7 << 7) | (x7 >> 25)

			// quarterround(x, 3, 4, 9, 14)
			x3 += x4
			x14 ^= x3
			x14 = (x14 << 16) | (x14 >> 16)
			x9 += x14
			x4 ^= x9
			x4 = (x4 << 12) | (x4 >> 20)
			x3 += x4
			x14 ^= x3
			x14 = (x14 << 8) | (x14 >> 24)
			x9 += x14
			x4 ^= x9
			x4 = (x4 << 7) | (x4 >> 25)
		}

		// On amd64 at least, this is a rather big boost.
		if useUnsafe {
			if in != nil {
				inArr := (*[16]uint32)(unsafe.Pointer(&in[n*BlockSize]))
				outArr := (*[16]uint32)(unsafe.Pointer(&out[n*BlockSize]))
				outArr[0] = inArr[0] ^ (x0 + sigma0)
				outArr[1] = inArr[1] ^ (x1 + sigma1)
				outArr[2] = inArr[2] ^ (x2 + sigma2)
				outArr[3] = inArr[3] ^ (x3 + sigma3)
				outArr[4] = inArr[4] ^ (x4 + x[4])
				outArr[5] = inArr[5] ^ (x5 + x[5])
				outArr[6] = inArr[6] ^ (x6 + x[6])
				outArr[7] = inArr[7] ^ (x7 + x[7])
				outArr[8] = inArr[8] ^ (x8 + x[8])
				outArr[9] = inArr[9] ^ (x9 + x[9])
				outArr[10] = inArr[10] ^ (x10 + x[10])
				outArr[11] = inArr[11] ^ (x11 + x[11])
				outArr[12] = inArr[12] ^ (x12 + x[12])
				outArr[13] = inArr[13] ^ (x13 + x[13])
				outArr[14] = inArr[14] ^ (x14 + x[14])
				outArr[15] = inArr[15] ^ (x15 + x[15])
			} else {
				outArr := (*[16]uint32)(unsafe.Pointer(&out[n*BlockSize]))
				outArr[0] = x0 + sigma0
				outArr[1] = x1 + sigma1
				outArr[2] = x2 + sigma2
				outArr[3] = x3 + sigma3
				outArr[4] = x4 + x[4]
				outArr[5] = x5 + x[5]
				outArr[6] = x6 + x[6]
				outArr[7] = x7 + x[7]
				outArr[8] = x8 + x[8]
				outArr[9] = x9 + x[9]
				outArr[10] = x10 + x[10]
				outArr[11] = x11 + x[11]
				outArr[12] = x12 + x[12]
				outArr[13] = x13 + x[13]
				outArr[14] = x14 + x[14]
				outArr[15] = x15 + x[15]
			}
		} else {
			// Slow path, either the architecture cares about alignment, or is not little endian.
			x0 += sigma0
			x1 += sigma1
			x2 += sigma2
			x3 += sigma3
			x4 += x[4]
			x5 += x[5]
			x6 += x[6]
			x7 += x[7]
			x8 += x[8]
			x9 += x[9]
			x10 += x[10]
			x11 += x[11]
			x12 += x[12]
			x13 += x[13]
			x14 += x[14]
			x15 += x[15]
			if in != nil {
				binary.LittleEndian.PutUint32(out[0:4], binary.LittleEndian.Uint32(in[0:4])^x0)
				binary.LittleEndian.PutUint32(out[4:8], binary.LittleEndian.Uint32(in[4:8])^x1)
				binary.LittleEndian.PutUint32(out[8:12], binary.LittleEndian.Uint32(in[8:12])^x2)
				binary.LittleEndian.PutUint32(out[12:16], binary.LittleEndian.Uint32(in[12:16])^x3)
				binary.LittleEndian.PutUint32(out[16:20], binary.LittleEndian.Uint32(in[16:20])^x4)
				binary.LittleEndian.PutUint32(out[20:24], binary.LittleEndian.Uint32(in[20:24])^x5)
				binary.LittleEndian.PutUint32(out[24:28], binary.LittleEndian.Uint32(in[24:28])^x6)
				binary.LittleEndian.PutUint32(out[28:32], binary.LittleEndian.Uint32(in[28:32])^x7)
				binary.LittleEndian.PutUint32(out[32:36], binary.LittleEndian.Uint32(in[32:36])^x8)
				binary.LittleEndian.PutUint32(out[36:40], binary.LittleEndian.Uint32(in[36:40])^x9)
				binary.LittleEndian.PutUint32(out[40:44], binary.LittleEndian.Uint32(in[40:44])^x10)
				binary.LittleEndian.PutUint32(out[44:48], binary.LittleEndian.Uint32(in[44:48])^x11)
				binary.LittleEndian.PutUint32(out[48:52], binary.LittleEndian.Uint32(in[48:52])^x12)
				binary.LittleEndian.PutUint32(out[52:56], binary.LittleEndian.Uint32(in[52:56])^x13)
				binary.LittleEndian.PutUint32(out[56:60], binary.LittleEndian.Uint32(in[56:60])^x14)
				binary.LittleEndian.PutUint32(out[60:64], binary.LittleEndian.Uint32(in[60:64])^x15)
				in = in[BlockSize:]
			} else {
				binary.LittleEndian.PutUint32(out[0:4], x0)
				binary.LittleEndian.PutUint32(out[4:8], x1)
				binary.LittleEndian.PutUint32(out[8:12], x2)
				binary.LittleEndian.PutUint32(out[12:16], x3)
				binary.LittleEndian.PutUint32(out[16:20], x4)
				binary.LittleEndian.PutUint32(out[20:24], x5)
				binary.LittleEndian.PutUint32(out[24:28], x6)
				binary.LittleEndian.PutUint32(out[28:32], x7)
				binary.LittleEndian.PutUint32(out[32:36], x8)
				binary.LittleEndian.PutUint32(out[36:40], x9)
				binary.LittleEndian.PutUint32(out[40:44], x10)
				binary.LittleEndian.PutUint32(out[44:48], x11)
				binary.LittleEndian.PutUint32(out[48:52], x12)
				binary.LittleEndian.PutUint32(out[52:56], x13)
				binary.LittleEndian.PutUint32(out[56:60], x14)
				binary.LittleEndian.PutUint32(out[60:64], x15)
			}
			out = out[BlockSize:]
		}

		// Stoping at 2^70 bytes per nonce is the user's responsibility.
		ctr := uint64(x[13])<<32 | uint64(x[12])
		ctr++
		x[12] = uint32(ctr)
		x[13] = uint32(ctr >> 32)
	}
}

func hChaChaRef(x *[stateSize]uint32, out *[32]byte) {
	x0, x1, x2, x3 := sigma0, sigma1, sigma2, sigma3
	x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 := x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11]

	for i := chachaRounds; i > 0; i -= 2 {
		x0 += x4
		x12 ^= x0
		x12 = (x12 << 16) | (x12 >> 16)
		x8 += x12
		x4 ^= x8
		x4 = (x4 << 12) | (x4 >> 20)
		x0 += x4
		x12 ^= x0
		x12 = (x12 << 8) | (x12 >> 24)
		x8 += x12
		x4 ^= x8
		x4 = (x4 << 7) | (x4 >> 25)

		x1 += x5
		x13 ^= x1
		x13 = (x13 << 16) | (x13 >> 16)
		x9 += x13
		x5 ^= x9
		x5 = (x5 << 12) | (x5 >> 20)
		x1 += x5
		x13 ^= x1
		x13 = (x13 << 8) | (x13 >> 24)
		x9 += x13
		x5 ^= x9
		x5 = (x5 << 7) | (x5 >> 25)

		x2 += x6
		x14 ^= x2
		x14 = (x14 << 16) | (x14 >> 16)
		x10 += x14
		x6 ^= x10
		x6 = (x6 << 12) | (x6 >> 20)
		x2 += x6
		x14 ^= x2
		x14 = (x14 << 8) | (x14 >> 24)
		x10 += x14
		x6 ^= x10
		x6 = (x6 << 7) | (x6 >> 25)

		x3 += x7
		x15 ^= x3
		x15 = (x15 << 16) | (x15 >> 16)
		x11 += x15
		x7 ^= x11
		x7 = (x7 << 12) | (x7 >> 20)
		x3 += x7
		x15 ^= x3
		x15 = (x15 << 8) | (x15 >> 24)
		x11 += x15
		x7 ^= x11
		x7 = (x7 << 7) | (x7 >> 25)

		x0 += x5
		x15 ^= x0
		x15 = (x15 << 16) | (x15 >> 16)
		x10 += x15
		x5 ^= x10
		x5 = (x5 << 12) | (x5 >> 20)
		x0 += x5
		x15 ^= x0
		x15 = (x15 << 8) | (x15 >> 24)
		x10 += x15
		x5 ^= x10
		x5 = (x5 << 7) | (x5 >> 25)

		x1 += x6
		x12 ^= x1
		x12 = (x12 << 16) | (x12 >> 16)
		x11 += x12
		x6 ^= x11
		x6 = (x6 << 12) | (x6 >> 20)
		x1 += x6
		x12 ^= x1
		x12 = (x12 << 8) | (x12 >> 24)
		x11 += x12
		x6 ^= x11
		x6 = (x6 << 7) | (x6 >> 25)

		x2 += x7
		x13 ^= x2
		x13 = (x13 << 16) | (x13 >> 16)
		x8 += x13
		x7 ^= x8
		x7 = (x7 << 12) | (x7 >> 20)
		x2 += x7
		x13 ^= x2
		x13 = (x13 << 8) | (x13 >> 24)
		x8 += x13
		x7 ^= x8
		x7 = (x7 << 7) | (x7 >> 25)

		x3 += x4
		x14 ^= x3
		x14 = (x14 << 16) | (x14 >> 16)
		x9 += x14
		x4 ^= x9
		x4 = (x4 << 12) | (x4 >> 20)
		x3 += x4
		x14 ^= x3
		x14 = (x14 << 8) | (x14 >> 24)
		x9 += x14
		x4 ^= x9
		x4 = (x4 << 7) | (x4 >> 25)
	}

	// HChaCha returns x0...x3 | x12...x15, which corresponds to the
	// indexes of the ChaCha constant and the indexes of the IV.
	if useUnsafe {
		outArr := (*[16]uint32)(unsafe.Pointer(&out[0]))
		outArr[0] = x0
		outArr[1] = x1
		outArr[2] = x2
		outArr[3] = x3
		outArr[4] = x12
		outArr[5] = x13
		outArr[6] = x14
		outArr[7] = x15
	} else {
		binary.LittleEndian.PutUint32(out[0:4], x0)
		binary.LittleEndian.PutUint32(out[4:8], x1)
		binary.LittleEndian.PutUint32(out[8:12], x2)
		binary.LittleEndian.PutUint32(out[12:16], x3)
		binary.LittleEndian.PutUint32(out[16:20], x12)
		binary.LittleEndian.PutUint32(out[20:24], x13)
		binary.LittleEndian.PutUint32(out[24:28], x14)
		binary.LittleEndian.PutUint32(out[28:32], x15)
	}
	return
}

var (
	ErrInvalidKey     = errors.New("key length must be KeySize bytes")
	ErrInvalidNonce   = errors.New("nonce length must be NonceSize/INonceSize/XNonceSize bytes")
	ErrInvalidCounter = errors.New("block counter is invalid (out of range)")

	useUnsafe    = false
	usingVectors = false
	blocksFn     = blocksRef
)

type Cipher struct {
	state [stateSize]uint32

	buf  [BlockSize]byte
	off  int
	ietf bool
}

func (c *Cipher) Reset() {
	for i := range c.state {
		c.state[i] = 0
	}
	for i := range c.buf {
		c.buf[i] = 0
	}
}

func (c *Cipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		src = src[:len(dst)]
	}

	for remaining := len(src); remaining > 0; {
		// Process multiple blocks at once.
		if c.off == BlockSize {
			nrBlocks := remaining / BlockSize
			directBytes := nrBlocks * BlockSize
			if nrBlocks > 0 {
				blocksFn(&c.state, src, dst, nrBlocks, c.ietf)
				remaining -= directBytes
				if remaining == 0 {
					return
				}
				dst = dst[directBytes:]
				src = src[directBytes:]
			}

			// If there's a partial block, generate 1 block of keystream into
			// the internal buffer.
			blocksFn(&c.state, nil, c.buf[:], 1, c.ietf)
			c.off = 0
		}

		// Process partial blocks from the buffered keystream.
		toXor := BlockSize - c.off
		if remaining < toXor {
			toXor = remaining
		}
		if toXor > 0 {
			for i, v := range src[:toXor] {
				dst[i] = v ^ c.buf[c.off+i]
			}
			dst = dst[toXor:]
			src = src[toXor:]

			remaining -= toXor
			c.off += toXor
		}
	}
}

func (c *Cipher) KeyStream(dst []byte) {
	for remaining := len(dst); remaining > 0; {
		if c.off == BlockSize {
			nrBlocks := remaining / BlockSize
			directBytes := nrBlocks * BlockSize
			if nrBlocks > 0 {
				blocksFn(&c.state, nil, dst, nrBlocks, c.ietf)
				remaining -= directBytes
				if remaining == 0 {
					return
				}
				dst = dst[directBytes:]
			}

			blocksFn(&c.state, nil, c.buf[:], 1, c.ietf)
			c.off = 0
		}

		toCopy := BlockSize - c.off
		if remaining < toCopy {
			toCopy = remaining
		}
		if toCopy > 0 {
			copy(dst[:toCopy], c.buf[c.off:c.off+toCopy])
			dst = dst[toCopy:]
			remaining -= toCopy
			c.off += toCopy
		}
	}
}

func (c *Cipher) ReKey(key, nonce []byte) error {
	if len(key) != KeySize {
		return ErrInvalidKey
	}

	switch len(nonce) {
	case NonceSize:
	case INonceSize:
	case XNonceSize:
		var subkey [KeySize]byte
		var subnonce [HNonceSize]byte
		copy(subnonce[:], nonce[0:16])
		HChaCha(key, &subnonce, &subkey)
		key = subkey[:]
		nonce = nonce[16:24]
		defer func() {
			for i := range subkey {
				subkey[i] = 0
			}
		}()
	default:
		return ErrInvalidNonce
	}

	c.Reset()
	c.state[0] = sigma0
	c.state[1] = sigma1
	c.state[2] = sigma2
	c.state[3] = sigma3
	c.state[4] = binary.LittleEndian.Uint32(key[0:4])
	c.state[5] = binary.LittleEndian.Uint32(key[4:8])
	c.state[6] = binary.LittleEndian.Uint32(key[8:12])
	c.state[7] = binary.LittleEndian.Uint32(key[12:16])
	c.state[8] = binary.LittleEndian.Uint32(key[16:20])
	c.state[9] = binary.LittleEndian.Uint32(key[20:24])
	c.state[10] = binary.LittleEndian.Uint32(key[24:28])
	c.state[11] = binary.LittleEndian.Uint32(key[28:32])
	c.state[12] = 0
	if len(nonce) == INonceSize {
		c.state[13] = binary.LittleEndian.Uint32(nonce[0:4])
		c.state[14] = binary.LittleEndian.Uint32(nonce[4:8])
		c.state[15] = binary.LittleEndian.Uint32(nonce[8:12])
		c.ietf = true
	} else {
		c.state[13] = 0
		c.state[14] = binary.LittleEndian.Uint32(nonce[0:4])
		c.state[15] = binary.LittleEndian.Uint32(nonce[4:8])
		c.ietf = false
	}
	c.off = BlockSize
	return nil

}

func (c *Cipher) Seek(blockCounter uint64) error {
	if c.ietf {
		if blockCounter > math.MaxUint32 {
			return ErrInvalidCounter
		}
		c.state[12] = uint32(blockCounter)
	} else {
		c.state[12] = uint32(blockCounter)
		c.state[13] = uint32(blockCounter >> 32)
	}
	c.off = BlockSize
	return nil
}

func ChaCha20NewCipher(key, nonce []byte) (*Cipher, error) {
	c := new(Cipher)
	if err := c.ReKey(key, nonce); err != nil {
		return nil, err
	}
	return c, nil
}

func HChaCha(key []byte, nonce *[HNonceSize]byte, out *[32]byte) {
	var x [stateSize]uint32 // Last 4 slots unused, sigma hardcoded.
	x[0] = binary.LittleEndian.Uint32(key[0:4])
	x[1] = binary.LittleEndian.Uint32(key[4:8])
	x[2] = binary.LittleEndian.Uint32(key[8:12])
	x[3] = binary.LittleEndian.Uint32(key[12:16])
	x[4] = binary.LittleEndian.Uint32(key[16:20])
	x[5] = binary.LittleEndian.Uint32(key[20:24])
	x[6] = binary.LittleEndian.Uint32(key[24:28])
	x[7] = binary.LittleEndian.Uint32(key[28:32])
	x[8] = binary.LittleEndian.Uint32(nonce[0:4])
	x[9] = binary.LittleEndian.Uint32(nonce[4:8])
	x[10] = binary.LittleEndian.Uint32(nonce[8:12])
	x[11] = binary.LittleEndian.Uint32(nonce[12:16])
	hChaChaRef(&x, out)
}

func init() {
	switch runtime.GOARCH {
	case "386", "amd64":
		useUnsafe = true
	}
}

var _ cipher.Stream = (*Cipher)(nil)
