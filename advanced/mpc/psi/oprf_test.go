package psi

import (
	"crypto/rand"
	"testing"
)

func TestOPRF(t *testing.T) {
	secretX, err := rand.Int(rand.Reader, DefaultCurveType.Params().N)
	if err != nil {
		t.Error(err)
	}
	r, err := rand.Int(rand.Reader, DefaultCurveType.Params().N)
	if err != nil {
		t.Error(err)
	}
	x, y, err := calRandRequest(secretX, r)
	if err != nil {
		t.Error(err)
	}

	secretK, err := rand.Int(rand.Reader, DefaultCurveType.Params().N)
	if err != nil {
		t.Error(err)
	}
	xResp, yResp := calRandResponse(x, y, secretK)

	xRecover, yRecover := recoverPRF(xResp, yResp, r)

	// calculate k*xG directly
	xG, yG := DefaultCurveType.ScalarBaseMult(secretX.Bytes())
	kxG, kyG := DefaultCurveType.ScalarMult(xG, yG, secretK.Bytes())
	if err != nil {
		t.Error(err)
	}

	// compare
	if xRecover.Cmp(kxG) != 0 || yRecover.Cmp(kyG) != 0 {
		t.Errorf("OPRF test failed")
	}
}
