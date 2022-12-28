package polynomial

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestMultiplyXns(t *testing.T) {
	// (x+1)*(x+2)*(x+3)*(x+4)
	xns := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	res, err := MultiplyXns(xns)
	if err != nil {
		t.Error(err)
	}
	// supposed to be x^4+10x^3+35x^2+50x+24
	t.Log(res)

	// (x-1)*(x-2)*(x-3)*(x-4)
	xns2 := []*big.Int{big.NewInt(-1), big.NewInt(-2), big.NewInt(-3), big.NewInt(-4)}
	res, err = MultiplyXns(xns2)
	if err != nil {
		t.Error(err)
	}
	// supposed to be x^4-10x^3+35x^2-50x+24
	t.Log(res)
}

func TestLagrangeInterpolation(t *testing.T) {
	// x^4+10x^3+35x^2+50x+24
	values := make(map[*big.Int]*big.Int)
	values[big.NewInt(1)] = big.NewInt(120)
	values[big.NewInt(2)] = big.NewInt(360)
	values[big.NewInt(3)] = big.NewInt(840)
	values[big.NewInt(4)] = big.NewInt(1680)
	values[big.NewInt(5)] = big.NewInt(3024)

	modulus, err := rand.Prime(rand.Reader, 1024)
	if err != nil {
		t.Error(err)
	}
	coefs, err := LagrangeInterpolation(values, modulus)
	if err != nil {
		t.Error(err)
	}
	// supposed to be [1 10 35 50 24]
	t.Log(coefs)
}
