package crt

import (
	"math/big"
	"testing"
)

func TestAdd(t *testing.T) {
	// x = 123
	// x = 3 mod 5
	// x = 4 mod 7
	// x = 2 mod 11
	// x = 6 mod 13

	ms := []*big.Int{big.NewInt(5), big.NewInt(7), big.NewInt(11), big.NewInt(13)}
	as := []*big.Int{big.NewInt(3), big.NewInt(4), big.NewInt(2), big.NewInt(6)}

	x := Recover(ms, as)
	t.Log(x)
}
