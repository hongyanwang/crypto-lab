package bellare_micali

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestOT(t *testing.T) {
	c, err := rand.Int(rand.Reader, DefaultCurveType.Params().N)
	if err != nil {
		t.Error(err)
	}

	index := 1
	ms := []*big.Int{new(big.Int).SetInt64(12), new(big.Int).SetInt64(20)}
	k, pk0, err := ComputePKs(c, index)
	if err != nil {
		t.Error(err)
	}

	cs, err := ComputeCs(c, pk0, ms)
	if err != nil {
		t.Error(err)
	}

	m := RecoverM(cs, index, k)
	if m.Cmp(ms[index]) != 0 {
		t.Logf("message received: %v", m)
		t.Errorf("ot test failed")
	}
}
