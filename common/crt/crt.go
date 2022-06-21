// Chinese Remainder Theorem
package crt

import (
	"math/big"
)

// Recover calculate x that satisfies x = ai mod mi, where {mi} are coprime
// there is a unique x mod m, where m = m1*m2*...*mn
func Recover(ms []*big.Int, as []*big.Int) *big.Int {
	m := big.NewInt(1)
	for i := 0; i < len(ms); i++ {
		m = m.Mul(m, ms[i])
	}

	x := big.NewInt(0)
	for i := 0; i < len(ms); i++ {
		mi := new(big.Int).Div(m, ms[i])
		ti := new(big.Int).ModInverse(mi, ms[i])

		// x = sum(ai*ti*mi)
		s := new(big.Int).Mul(as[i], ti)
		s = s.Mul(s, mi)
		x = x.Add(x, s)
		x = x.Mod(x, m)
	}

	return x
}
