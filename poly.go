package NewHope_golang


import (
	"encoding/binary"
	"golang.org/x/crypto/sha3"
)


const (
	PolyBytes = 1792
	shake128Rate = 168
)

type poly struct {
	coeffs [paramN]uint16
}


func (p *poly) destroy() {
	for i := range p.coeffs {
		p.coeffs[i] = 0
	}
}


func (p *poly) poly_frombytes(a []byte) {
	for i := 0; i < paramN /4; i++ {
		p.coeffs[4*i+0] = uint16(a[7*i+0]) | ((uint16(a[7*i+1]) & 0x3f) << 8)
		p.coeffs[4*i+1] = (uint16(a[7*i+1]) >> 6) | (uint16(a[7*i+2]) << 2) | ((uint16(a[7*i+3]) & 0x0f) << 10)

		p.coeffs[4*i+2] = (uint16(a[7*i+3]) >> 4) | (uint16(a[7*i+4]) << 4) | ((uint16(a[7*i+5]) & 0x03) << 12)
		p.coeffs[4*i+3] = (uint16(a[7*i+5]) >> 2) | (uint16(a[7*i+6]) << 6)
	}
}



func (p *poly) poly_tobytes(r []byte) {
	for i := 0; i < paramN /4; i++ {
		// Make sure that coefficients have only 14 bits.
		t0 := barrettReduce(p.coeffs[4*i+0])
		t1 := barrettReduce(p.coeffs[4*i+1])
		t2 := barrettReduce(p.coeffs[4*i+2])
		t3 := barrettReduce(p.coeffs[4*i+3])

		// Make sure that coefficients are in [0,q]
		m := t0 - PARAMQ
		c := int16(m)
		c >>= 15
		t0 = m ^ ((t0 ^ m) & uint16(c))

		m = t1 - PARAMQ
		c = int16(m)
		c >>= 15
		t1 = m ^ ((t1 ^ m) & uint16(c))

		m = t2 - PARAMQ
		c = int16(m)
		c >>= 15
		t2 = m ^ ((t2 ^ m) & uint16(c))

		m = t3 - PARAMQ
		c = int16(m)
		c >>= 15
		t3 = m ^ ((t3 ^ m) & uint16(c))

		r[7*i+0] = byte(t0 & 0xff)
		r[7*i+1] = byte(t0>>8) | byte(t1<<6)
		r[7*i+2] = byte(t1 >> 2)
		r[7*i+3] = byte(t1>>10) | byte(t2<<4)
		r[7*i+4] = byte(t2 >> 4)
		r[7*i+5] = byte(t2>>12) | byte(t3<<2)
		r[7*i+6] = byte(t3 >> 6)
	}
}

func (p *poly) poly_uniform(seed *[SeedBytes]byte, torSampling bool) {
	if !torSampling {
		// Reference version, vartime.
		nBlocks := 14
		var buf [shake128Rate * 14]byte

		// h and buf are left unscrubbed because the output is public.
		h := sha3.NewShake128()
		h.Write(seed[:])
		h.Read(buf[:])

		for ctr, pos := 0, 0; ctr < paramN; {
			val := binary.LittleEndian.Uint16(buf[pos:])

			if val < 5* PARAMQ {
				p.coeffs[ctr] = val
				ctr++
			}
			pos += 2
			if pos > shake128Rate*nBlocks-2 {
				nBlocks = 1
				h.Read(buf[:shake128Rate])
				pos = 0
			}
		}
	}
}



func init() {
	if paramK != 16 {
		panic("Err")
	}
}