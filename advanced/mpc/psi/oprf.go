package psi

import (
	"crypto/elliptic"
	"math/big"
)

var (
	DefaultCurveType = elliptic.P256()
)

// calRandRequest receiver calculates r*xG to hide secret, return (x,y)
func calRandRequest(secretX, r *big.Int) (*big.Int, *big.Int, error) {
	x, y := DefaultCurveType.ScalarBaseMult(secretX.Bytes())
	x, y = DefaultCurveType.ScalarMult(x, y, r.Bytes())
	return x, y, nil
}

// calRandResponse sender calculates k*r*xG to hide k
func calRandResponse(x, y, secretK *big.Int) (*big.Int, *big.Int) {
	x, y = DefaultCurveType.ScalarMult(x, y, secretK.Bytes())
	return x, y
}

// recoverPRF receiver recovers k*xG(PRF) using r inverse
func recoverPRF(x, y, r *big.Int) (*big.Int, *big.Int) {
	rInverse := new(big.Int).ModInverse(r, DefaultCurveType.Params().N)
	x, y = DefaultCurveType.ScalarMult(x, y, rInverse.Bytes())
	return x, y
}
