package gc

import (
	"math/big"
	"testing"
)

func TestGC(t *testing.T) {
	// AND gate
	// 1. create truth gates
	gate0 := Gate{
		X: big.NewInt(0),
		Y: big.NewInt(0),
		W: big.NewInt(0),
	}
	gate1 := Gate{
		X: big.NewInt(0),
		Y: big.NewInt(1),
		W: big.NewInt(0),
	}
	gate2 := Gate{
		X: big.NewInt(1),
		Y: big.NewInt(0),
		W: big.NewInt(0),
	}
	gate3 := Gate{
		X: big.NewInt(1),
		Y: big.NewInt(1),
		W: big.NewInt(1),
	}
	truthGate := []Gate{gate0, gate1, gate2, gate3}

	// 2. generate random enc value for each x, y, z
	encMap, err := GenerateRandMap(truthGate)
	if err != nil {
		t.Error(err)
	}

	// 3. generate enc gates
	encGates := GenerateEncGates(truthGate, encMap)

	// 4. encrypt outputs
	encWs, err := EncOutputs(encGates)
	if err != nil {
		t.Error(err)
	}

	// 5. get enc input0 = 0
	encInput0 := encMap.Xmap[big.NewInt(0)]

	// 6. suppose bob got enc input1 = enc(1) using ot scheme
	encInput1 := encMap.Ymap[big.NewInt(1)]
	encW, err := DecOutput(encInput0, encInput1, encWs)
	if err != nil {
		t.Error(err)
	}

	// 7. recover result using map
	for key, value := range encMap.Wmap {
		if value == encW {
			t.Logf("result: %v\n", key)
			return
		}
	}
	t.Errorf("gc test failed")
}
