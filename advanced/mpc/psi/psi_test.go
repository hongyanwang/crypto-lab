package psi

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestPSI(t *testing.T) {
	Xs := []*big.Int{big.NewInt(101), big.NewInt(202), big.NewInt(505), big.NewInt(808), big.NewInt(909), big.NewInt(1000)}
	Ys := []*big.Int{big.NewInt(202), big.NewInt(303), big.NewInt(606), big.NewInt(808), big.NewInt(909)}
	validIntersect := []*big.Int{big.NewInt(202), big.NewInt(808), big.NewInt(909)}

	r, err := rand.Int(rand.Reader, DefaultCurveType.Params().N)
	if err != nil {
		t.Error(err)
	}
	secretK, err := rand.Int(rand.Reader, DefaultCurveType.Params().N)
	if err != nil {
		t.Error(err)
	}

	reqPoints := calOPRFRequest(Ys, r)
	respPoints := calOPRFResponse(reqPoints, secretK)
	recoverPoints := recoverPRF(respPoints, r)

	// calculate k*xG directly
	xPoints := calOPRFRequest(Xs, secretK)

	// calculate intersection
	intersection := intersect(xPoints, recoverPoints, Ys)

	if !setsEqual(intersection, validIntersect) {
		t.Errorf("OPRF test failed")
	}
}

func setsEqual(s1, s2 []*big.Int) bool {
	if len(s1) != len(s2) {
		return false
	}
	for _, s := range s1 {
		if !intExit(s, s2) {
			return false
		}
	}
	return true
}

func intExit(item *big.Int, set []*big.Int) bool {
	for _, s := range set {
		if item.Cmp(s) == 0 {
			return true
		}
	}
	return false
}
