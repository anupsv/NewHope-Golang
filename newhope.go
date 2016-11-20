package NewHope

import (
	"io"
	"golang.org/x/crypto/sha3"
)

const (
	SharedSecretSize = 32
	RecBytes         = 256
	SendASize        = polyBytes + SeedBytes
	SendBSize        = polyBytes + RecBytes
)

var TorSampling = false

func encodeA(r []byte, pk *poly, seed *[SeedBytes]byte) {
	pk.polyToBytes(r)
	for i := 0; i < SeedBytes; i++ {
		r[polyBytes+i] = seed[i]
	}
}

func decodeA(pk *poly, seed *[SeedBytes]byte, r []byte) {
	pk.polyFromBytes(r)
	for i := range seed {
		seed[i] = r[polyBytes+i]
	}
}

func encodeB(r []byte, b *poly, c *poly) {
	b.polyToBytes(r)
	for i := 0; i < paramN/4; i++ {
		r[polyBytes+i] = byte(c.coeffs[4*i]) | byte(c.coeffs[4*i+1]<<2) | byte(c.coeffs[4*i+2]<<4) | byte(c.coeffs[4*i+3]<<6)
	}
}

func decodeB(b *poly, c *poly, r []byte) {
	b.polyFromBytes(r)
	for i := 0; i < paramN/4; i++ {
		c.coeffs[4*i+0] = uint16(r[polyBytes+i]) & 0x03
		c.coeffs[4*i+1] = uint16(r[polyBytes+i]>>2) & 0x03
		c.coeffs[4*i+2] = uint16(r[polyBytes+i]>>4) & 0x03
		c.coeffs[4*i+3] = uint16(r[polyBytes+i] >> 6)
	}
}

func memwipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// PublicKeyAlice is Alice's New Hope public key.
type PublicKeyAlice struct {
	Send [SendASize]byte
}

// PrivateKeyAlice is Alice's New Hope private key.
type PrivateKeyAlice struct {
	sk poly
}

func (k *PrivateKeyAlice) Reset() {
	k.sk.destroy()
}

func GenerateKeyPair(rand io.Reader) (*PrivateKeyAlice, *PublicKeyAlice, error) {
	var a, e, pk, r poly
	var seed, noiseSeed [SeedBytes]byte

	// seed <- Sample({0, 1}^256)
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, nil, err
	}
	seed = sha3.Sum256(seed[:]) // Don't send output of system RNG.
	// a <- Parse(SHAKE-128(seed))
	a.polyUniform(&seed, TorSampling)

	// s, e <- Sample(psi(n, 12))
	if _, err := io.ReadFull(rand, noiseSeed[:]); err != nil {
		return nil, nil, err
	}
	defer memwipe(noiseSeed[:])
	privKey := new(PrivateKeyAlice)
	privKey.sk.getNoise(&noiseSeed, 0)
	privKey.sk.polyNtt()
	e.getNoise(&noiseSeed, 1)
	e.polyNtt()

	// b <- as + e
	pubKey := new(PublicKeyAlice)
	r.pointWise(&privKey.sk, &a)
	pk.add(&e, &r)
	encodeA(pubKey.Send[:], &pk, &seed)

	return privKey, pubKey, nil
}

// PublicKeyBob is Bob's New Hope public key.
type PublicKeyBob struct {
	Send [SendBSize]byte
}

func KeyExchangeBob(rand io.Reader, alicePk *PublicKeyAlice) (*PublicKeyBob, []byte, error) {
	var pka, a, sp, ep, u, v, epp, r poly
	var seed, noiseSeed [SeedBytes]byte

	if _, err := io.ReadFull(rand, noiseSeed[:]); err != nil {
		return nil, nil, err
	}
	defer memwipe(noiseSeed[:])

	// a <- Parse(SHAKE-128(seed))
	decodeA(&pka, &seed, alicePk.Send[:])
	a.polyUniform(&seed, TorSampling)

	// s', e', e'' <- Sample(psi(n, 12))
	sp.getNoise(&noiseSeed, 0)
	sp.polyNtt()
	ep.getNoise(&noiseSeed, 1)
	ep.polyNtt()
	epp.getNoise(&noiseSeed, 2)

	// u <- as' + e'
	u.pointWise(&a, &sp)
	u.add(&u, &ep)

	// v <- bs' + e''
	v.pointWise(&pka, &sp)
	v.polyInvNtt()
	v.add(&v, &epp)

	// r <- Sample(HelpRec(v))
	r.helpRec(&v, &noiseSeed, 3)

	pubKey := new(PublicKeyBob)
	encodeB(pubKey.Send[:], &u, &r)

	var nu [SharedSecretSize]byte
	rec(&nu, &v, &r)

	mu := sha3.Sum256(nu[:])

	memwipe(nu[:])
	sp.destroy()
	v.destroy()

	return pubKey, mu[:], nil
}

func KeyExchangeAlice(bobPk *PublicKeyBob, aliceSk *PrivateKeyAlice) ([]byte, error) {
	var u, r, vp poly

	decodeB(&u, &r, bobPk.Send[:])

	// v' <- us
	vp.pointWise(&aliceSk.sk, &u)
	vp.polyInvNtt()

	// nu <- Rec(v', r)
	var nu [SharedSecretSize]byte
	rec(&nu, &vp, &r)

	// mu <- Sha3-256(nu)
	mu := sha3.Sum256(nu[:])

	// Scrub the sensitive stuff...
	memwipe(nu[:])
	vp.destroy()
	aliceSk.Reset()

	return mu[:], nil
}
