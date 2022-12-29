package pir

import (
	"math/big"
	"testing"

	"github.com/hongyanwang/crypto-lab/asymmetric/paillier"
)

func TestPIR(t *testing.T) {
	values := make(map[*big.Int]*big.Int)
	values[big.NewInt(11)] = big.NewInt(101)
	values[big.NewInt(12)] = big.NewInt(201)
	values[big.NewInt(13)] = big.NewInt(301)
	values[big.NewInt(14)] = big.NewInt(401)
	values[big.NewInt(15)] = big.NewInt(501)

	privkey, err := paillier.GenerateKey(4096)
	checkErr(err, t)

	modulus := privkey.NN

	coefGx, err := GenGx(values, modulus)
	checkErr(err, t)
	coefFx, err := GenFx(values, modulus)
	checkErr(err, t)

	// retrieve 201
	targetIdx := big.NewInt(12)
	encVecs, err := GenSearchMaterial(targetIdx, &privkey.PublicKey, int64(len(values)))
	checkErr(err, t)

	encGx, encFx, err := GenEncGxFx(encVecs, coefGx, coefFx, &privkey.PublicKey)
	checkErr(err, t)

	target, err := RetrieveTargetValue(encGx, encFx, privkey)
	checkErr(err, t)
	t.Logf("target: %v", target)

	// retrieve nil
	targetIdx2 := big.NewInt(16)
	encVecs, err = GenSearchMaterial(targetIdx2, &privkey.PublicKey, int64(len(values)))
	checkErr(err, t)

	encGx, encFx, err = GenEncGxFx(encVecs, coefGx, coefFx, &privkey.PublicKey)
	checkErr(err, t)

	target2, err := RetrieveTargetValue(encGx, encFx, privkey)
	checkErr(err, t)
	t.Logf("target2: %v", target2)
}

func checkErr(err error, t *testing.T) {
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
}
