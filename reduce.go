package NewHope

const (
	QINV = 12287
	RLOG = 18
)

func montgomeryReduce(a uint32) uint16 {
	u := a * QINV
	u &= ((1 << RLOG) - 1)
	u *= PARAMQ
	a = (a + u) >> 18
	return uint16(a)
}

func barrettReduce(a uint16) uint16 {
	u := (uint32(a) * 5) >> 16
	u *= PARAMQ
	a -= uint16(u)
	return a
}
