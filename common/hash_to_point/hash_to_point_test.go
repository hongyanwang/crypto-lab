package hash_to_point

import (
	"math/big"
	"testing"
)

func TestHashToPoint(t *testing.T) {
	n := big.NewInt(123456)
	x, y, err := HashToPoint(n, 10)
	if err != nil {
		t.Errorf("HashToPoint failed: %v", err)
		t.FailNow()
	}

	if !DefaultCurveType.IsOnCurve(x, y) {
		t.Errorf("calculated (x,y) not on curve!")
	}
	t.Logf("x: %v", x)
	t.Logf("y: %v", y)
}
