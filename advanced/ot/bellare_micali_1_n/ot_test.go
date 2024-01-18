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

	// 1-out-of-2 test
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
		t.Errorf("1-out-of-2 ot test failed")
	}

	// 1-out-of-10 test
	index = 7
	ms = []*big.Int{new(big.Int).SetInt64(12), new(big.Int).SetInt64(34), new(big.Int).SetInt64(56),
		new(big.Int).SetInt64(78), new(big.Int).SetInt64(90), new(big.Int).SetInt64(112),
		new(big.Int).SetInt64(134), new(big.Int).SetInt64(256), new(big.Int).SetInt64(378), new(big.Int).SetInt64(490)}
	k, pk0, err = ComputePKs(c, index)
	if err != nil {
		t.Error(err)
	}

	cs, err = ComputeCs(c, pk0, ms)
	if err != nil {
		t.Error(err)
	}

	m = RecoverM(cs, index, k)
	if m.Cmp(ms[index]) != 0 {
		t.Logf("message received: %v", m)
		t.Errorf("1-out-of-n ot test failed")
	}
}
