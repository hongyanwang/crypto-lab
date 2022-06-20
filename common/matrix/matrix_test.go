package matrix

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

var p *big.Int

func init() {
	p, _ = rand.Prime(rand.Reader, 1024)
}

func TestTranspose(t *testing.T) {
	row1 := []*big.Int{big.NewInt(3), big.NewInt(5), big.NewInt(8)}
	row2 := []*big.Int{big.NewInt(2), big.NewInt(7), big.NewInt(9)}
	rows := [][]*big.Int{row1, row2}
	m1, err := NewMatrix(rows, p)
	if err != nil {
		t.Error(err)
	}
	m2 := Transpose(m1)
	m1.Print()
	fmt.Printf("transpose: \n")
	m2.Print()
}

func TestAdd(t *testing.T) {
	row1 := []*big.Int{big.NewInt(3), big.NewInt(5), big.NewInt(8)}
	row2 := []*big.Int{big.NewInt(2), big.NewInt(7), big.NewInt(9)}
	row3 := []*big.Int{big.NewInt(11), big.NewInt(2), big.NewInt(16)}
	row4 := []*big.Int{big.NewInt(7), big.NewInt(15), big.NewInt(10)}
	rows1 := [][]*big.Int{row1, row2}
	rows2 := [][]*big.Int{row3, row4}
	m1, err := NewMatrix(rows1, p)
	if err != nil {
		t.Error(err)
	}
	m2, err := NewMatrix(rows2, p)
	if err != nil {
		t.Error(err)
	}
	m, err := Add(m1, m2)
	if err != nil {
		t.Error(err)
	}
	m.Print()
}

func TestSub(t *testing.T) {
	row1 := []*big.Int{big.NewInt(3), big.NewInt(5), big.NewInt(8)}
	row2 := []*big.Int{big.NewInt(2), big.NewInt(7), big.NewInt(9)}
	row3 := []*big.Int{big.NewInt(11), big.NewInt(2), big.NewInt(16)}
	row4 := []*big.Int{big.NewInt(7), big.NewInt(15), big.NewInt(10)}
	rows1 := [][]*big.Int{row1, row2}
	rows2 := [][]*big.Int{row3, row4}
	m1, err := NewMatrix(rows1, p)
	if err != nil {
		t.Error(err)
	}
	m2, err := NewMatrix(rows2, p)
	if err != nil {
		t.Error(err)
	}
	m, err := Sub(m1, m2)
	if err != nil {
		t.Error(err)
	}
	m.Print()
}

func TestScalarMul(t *testing.T) {
	row1 := []*big.Int{big.NewInt(3), big.NewInt(5), big.NewInt(8)}
	row2 := []*big.Int{big.NewInt(2), big.NewInt(7), big.NewInt(9)}
	rows := [][]*big.Int{row1, row2}
	m1, err := NewMatrix(rows, p)
	if err != nil {
		t.Error(err)
	}
	m := ScalarMul(m1, big.NewInt(5))
	if err != nil {
		t.Error(err)
	}
	m.Print()
}

func TestMul(t *testing.T) {
	row1 := []*big.Int{big.NewInt(3), big.NewInt(5), big.NewInt(8)}
	row2 := []*big.Int{big.NewInt(2), big.NewInt(7), big.NewInt(9)}
	row3 := []*big.Int{big.NewInt(11), big.NewInt(6)}
	row4 := []*big.Int{big.NewInt(5), big.NewInt(9)}
	row5 := []*big.Int{big.NewInt(12), big.NewInt(15)}
	rows1 := [][]*big.Int{row1, row2}
	rows2 := [][]*big.Int{row3, row4, row5}
	m1, err := NewMatrix(rows1, p)
	if err != nil {
		t.Error(err)
	}
	m2, err := NewMatrix(rows2, p)
	if err != nil {
		t.Error(err)
	}
	m, err := Mul(m1, m2)
	if err != nil {
		t.Error(err)
	}
	m.Print()
}

func TestChildMatrix(t *testing.T) {
	row1 := []*big.Int{big.NewInt(3), big.NewInt(5), big.NewInt(8)}
	row2 := []*big.Int{big.NewInt(2), big.NewInt(7), big.NewInt(9)}
	row3 := []*big.Int{big.NewInt(11), big.NewInt(6), big.NewInt(6)}
	rows1 := [][]*big.Int{row1, row2, row3}
	m1, err := NewMatrix(rows1, p)
	if err != nil {
		t.Error(err)
	}
	cm, err := childMatrix(m1, 0, 0)
	if err != nil {
		t.Error(err)
	}
	m1.Print()
	fmt.Printf("remove [0,0]: \n")
	cm.Print()
}

func TestDet(t *testing.T) {
	row1 := []*big.Int{big.NewInt(3), big.NewInt(5), big.NewInt(8)}
	row2 := []*big.Int{big.NewInt(2), big.NewInt(7), big.NewInt(9)}
	row3 := []*big.Int{big.NewInt(11), big.NewInt(6), big.NewInt(6)}
	rows1 := [][]*big.Int{row1, row2, row3}
	m, err := NewMatrix(rows1, p)
	if err != nil {
		t.Error(err)
	}
	d1, err := Det(m)
	if err != nil {
		t.Error(err)
	}
	m.Print()
	fmt.Printf("det: %v\n", d1)
}

func TestInverse(t *testing.T) {
	row1 := []*big.Int{big.NewInt(3), big.NewInt(5), big.NewInt(8)}
	row2 := []*big.Int{big.NewInt(2), big.NewInt(7), big.NewInt(9)}
	row3 := []*big.Int{big.NewInt(11), big.NewInt(6), big.NewInt(6)}
	rows := [][]*big.Int{row1, row2, row3}
	m, err := NewMatrix(rows, p)
	if err != nil {
		t.Error(err)
	}
	inv, err := Inverse(m)
	if err != nil {
		t.Error(err)
	}

	mul, err := Mul(m, inv)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("m*inverse: \n")
	mul.Print()
}
