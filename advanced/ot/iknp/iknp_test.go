package iknp

import (
	"math"
	"math/big"
	"reflect"
	"testing"
)

func TestIKNP(t *testing.T) {
	data := randomDataVectorForTest(DefaultM, int64(math.Exp2(float64(DefaultL))), DefaultMax)
	rs := randomSelectVectorForTest(DefaultM, DefaultL)
	s := randomVector(DefaultK, big.NewInt(2))

	mT, mU, err := GenMatrixTU(DefaultM, DefaultK, rs)
	checkErr(err, t)

	mQ, err := GetMatrixQForTest(s, mT, mU)
	checkErr(err, t)

	ciphers, err := EncryptData(data, mQ, s)
	checkErr(err, t)

	wanted, err := getWantedDataForTest(data, rs)
	checkErr(err, t)
	t.Logf("wanted: %v\n", wanted)

	retrieved, err := RetrieveData(ciphers, rs, mT)
	checkErr(err, t)
	t.Logf("retrieved: %v\n", retrieved)

	if !reflect.DeepEqual(wanted, retrieved) {
		t.Errorf("OTE failed!!!")
	}
}

func TestRO(t *testing.T) {
	r := randomVector(DefaultK, big.NewInt(2))
	h := RO(r)
	t.Log(len(h))
	t.Log(h)
}

func TestColsFromRows(t *testing.T) {
	row1 := []*big.Int{big.NewInt(1), big.NewInt(11)}
	row2 := []*big.Int{big.NewInt(2), big.NewInt(22)}
	row3 := []*big.Int{big.NewInt(3), big.NewInt(33)}
	rows := [][]*big.Int{row1, row2, row3}
	cols := colsFromRows(rows)
	t.Log(cols)
}

func TestRowsFromCols(t *testing.T) {
	col1 := []*big.Int{big.NewInt(1), big.NewInt(11)}
	col2 := []*big.Int{big.NewInt(2), big.NewInt(22)}
	col3 := []*big.Int{big.NewInt(3), big.NewInt(33)}
	cols := [][]*big.Int{col1, col2, col3}
	rows := rowsFromCols(cols)
	t.Log(rows)
}

func TestIntBits(t *testing.T) {
	num := big.NewInt(123)
	t.Log(num)
	vec := intToBits(num, int(DefaultK))
	t.Log(vec)
	num2 := intFromBits(vec)
	t.Log(num2)
}

func TestRandomBVectors(t *testing.T) {
	data := randomDataVectorForTest(DefaultM, int64(math.Exp2(float64(DefaultL))), DefaultMax)
	t.Logf("data: %v\n\n", data)
	rs := randomSelectVectorForTest(DefaultM, DefaultL)
	t.Logf("rs: %v\n\n", rs)
	wanted, err := getWantedDataForTest(data, rs)
	checkErr(err, t)
	t.Logf("wanted: %v\n", wanted)
}

func TestCr(t *testing.T) {
	rs := randomSelectVectorForTest(DefaultM, DefaultL)
	t.Logf("rs[0]: %v\n", rs[0])
	cr, err := Cr(rs[0], DefaultK)
	checkErr(err, t)
	t.Logf("cr: %v\n", cr)
	t.Logf("cr len: %v\n", len(cr))
}

func checkErr(err error, t *testing.T) {
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
}
