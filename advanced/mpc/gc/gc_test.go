package gc

import (
	"reflect"
	"testing"
)

func TestGC(t *testing.T) {
	// AND gate
	// 1. create truth gates
	gate0 := Gate{
		X: 0,
		Y: 0,
		W: 0,
	}
	gate1 := Gate{
		X: 0,
		Y: 1,
		W: 0,
	}
	gate2 := Gate{
		X: 1,
		Y: 0,
		W: 0,
	}
	gate3 := Gate{
		X: 1,
		Y: 1,
		W: 1,
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
	encInput0 := encMap.Xmap[0]

	// 6. suppose bob got enc input1 = enc(1) using ot scheme
	encInput1 := encMap.Ymap[1]

	encW, err := DecOutput(encInput0, encInput1, encWs)
	if err != nil {
		t.Error(err)
	}

	// 7. recover result using map
	for key, value := range encMap.Wmap {
		if reflect.DeepEqual(value, encW) {
			t.Logf("result: %v\n", key)
			return
		}
	}
	t.Errorf("gc test failed")
}
