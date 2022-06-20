// matrix operation mod prime P
package matrix

import (
	"fmt"
	"math/big"
)

type Matrix struct {
	Rows [][]*big.Int // rows of a matrix, len(Rows) is number of rows, len(Rows[0]) is number of columns
	P    *big.Int     // prime modulus, each item in matrix is in filed(P)
}

// NewMatrix generate a matrix by rows
func NewMatrix(rows [][]*big.Int, p *big.Int) (*Matrix, error) {
	if len(rows) == 0 {
		return nil, fmt.Errorf("empty rows")
	}
	c1 := len(rows[0])
	for i := 1; i < len(rows); i++ {
		if len(rows[i]) != c1 {
			return nil, fmt.Errorf("rows do not have same itmes numbers")
		}
	}
	return &Matrix{
		Rows: rows,
		P:    p}, nil
}

// Transpose calculate transpose of a matrix
func Transpose(m *Matrix) *Matrix {
	rows := make([][]*big.Int, 0, len(m.Rows[0]))
	for i := 0; i < len(m.Rows[0]); i++ {
		row := make([]*big.Int, 0, len(m.Rows))
		for j := 0; j < len(m.Rows); j++ {
			row = append(row, m.Rows[j][i])
		}
		rows = append(rows, row)
	}
	return &Matrix{
		Rows: rows,
		P:    m.P,
	}
}

// Add add two matrix with same row and column numbers
func Add(m1, m2 *Matrix) (*Matrix, error) {
	if len(m1.Rows) != len(m2.Rows) {
		return nil, fmt.Errorf("failed to add, two matrices do not have same row numbers, %d!=%d", len(m1.Rows), len(m2.Rows))
	}
	if len(m1.Rows[0]) != len(m2.Rows[0]) {
		return nil, fmt.Errorf("failed to add, two matrices do not have same column numbers, %d!=%d", len(m1.Rows[0]), len(m2.Rows[0]))
	}
	if m1.P.Cmp(m2.P) != 0 {
		return nil, fmt.Errorf("failed to add, two matrices do not have same prime modulus, %v!=%v", m1.P, m2.P)
	}

	rows := make([][]*big.Int, 0, len(m1.Rows))
	for i := 0; i < len(m1.Rows); i++ {
		row := make([]*big.Int, 0, len(m1.Rows[0]))
		for j := 0; j < len(m1.Rows[0]); j++ {
			add := new(big.Int).Add(m1.Rows[i][j], m2.Rows[i][j])
			add = add.Mod(add, m1.P)
			row = append(row, add)
		}
		rows = append(rows, row)
	}
	return &Matrix{
		Rows: rows,
		P:    m1.P}, nil
}

// Sub substract a matrix by another one, two matrices must have same row and column numbers
func Sub(m1, m2 *Matrix) (*Matrix, error) {
	if len(m1.Rows) != len(m2.Rows) {
		return nil, fmt.Errorf("failed to sub, two matrices do not have same row numbers, %d!=%d", len(m1.Rows), len(m2.Rows))
	}
	if len(m1.Rows[0]) != len(m2.Rows[0]) {
		return nil, fmt.Errorf("failed to sub, two matrices do not have same column numbers, %d!=%d", len(m1.Rows[0]), len(m2.Rows[0]))
	}
	if m1.P.Cmp(m2.P) != 0 {
		return nil, fmt.Errorf("failed to sub, two matrices do not have same prime modulus, %v!=%v", m1.P, m2.P)
	}

	rows := make([][]*big.Int, 0, len(m1.Rows))
	for i := 0; i < len(m1.Rows); i++ {
		row := make([]*big.Int, 0, len(m1.Rows[0]))
		for j := 0; j < len(m1.Rows[0]); j++ {
			sub := new(big.Int).Sub(m1.Rows[i][j], m2.Rows[i][j])
			sub = sub.Mod(sub, m1.P)
			row = append(row, sub)
		}
		rows = append(rows, row)
	}
	return &Matrix{Rows: rows,
		P: m1.P}, nil
}

// ScalarMul multiply a matrix by a number
func ScalarMul(m *Matrix, k *big.Int) *Matrix {
	rows := make([][]*big.Int, 0, len(m.Rows))
	for i := 0; i < len(m.Rows); i++ {
		row := make([]*big.Int, 0, len(m.Rows[0]))
		for j := 0; j < len(m.Rows[0]); j++ {
			mul := new(big.Int).Mul(m.Rows[i][j], k)
			mul = mul.Mod(mul, m.P)
			row = append(row, mul)
		}
		rows = append(rows, row)
	}
	return &Matrix{
		Rows: rows,
		P:    m.P,
	}
}

// Mul multiply two matrices
func Mul(m1, m2 *Matrix) (*Matrix, error) {
	if len(m1.Rows[0]) != len(m2.Rows) {
		return nil, fmt.Errorf("failed to mul, column number of matrix A is not equal to row number of matrix B, %d!=%d", len(m1.Rows[0]), len(m2.Rows))
	}
	if m1.P.Cmp(m2.P) != 0 {
		return nil, fmt.Errorf("failed to mul, two matrices do not have same prime modulus, %v!=%v", m1.P, m2.P)
	}

	rows := make([][]*big.Int, 0, len(m1.Rows))
	for i := 0; i < len(m1.Rows); i++ {
		row := make([]*big.Int, 0, len(m2.Rows[0]))
		for j := 0; j < len(m2.Rows[0]); j++ {
			sum := big.NewInt(0)
			for k := 0; k < len(m1.Rows[0]); k++ {
				s := new(big.Int).Mul(m1.Rows[i][k], m2.Rows[k][j])
				sum = sum.Add(sum, s)
				sum = sum.Mod(sum, m1.P)
			}
			row = append(row, sum)
		}
		rows = append(rows, row)
	}
	return &Matrix{
		Rows: rows,
		P:    m1.P}, nil
}

// Det calculate determinant of a squared matrix
func Det(m *Matrix) (*big.Int, error) {
	if len(m.Rows) != len(m.Rows[0]) {
		return nil, fmt.Errorf("failed to calculate det, not a squared matrix, %d!=%d", len(m.Rows), len(m.Rows[0]))
	}

	if len(m.Rows) == 1 {
		return m.Rows[0][0], nil
	}
	if len(m.Rows) == 2 {
		a := new(big.Int).Mul(m.Rows[0][0], m.Rows[1][1])
		b := new(big.Int).Mul(m.Rows[0][1], m.Rows[1][0])
		sub := new(big.Int).Sub(a, b)
		sub = sub.Mod(sub, m.P)
		return sub, nil
	}

	det := big.NewInt(0)
	// expand by first row
	for j := 0; j < len(m.Rows[0]); j++ {
		c, err := cofactor(m, 0, j)
		if err != nil {
			return nil, err
		}
		det = new(big.Int).Add(det, new(big.Int).Mul(m.Rows[0][j], c))
		det = det.Mod(det, m.P)
	}

	return det, nil
}

// Inverse calculate inverse of a squared matrix
// a_ij = {|A*_ij|/det}^T
func Inverse(m *Matrix) (*Matrix, error) {
	if len(m.Rows) != len(m.Rows[0]) {
		return nil, fmt.Errorf("failed to inverse, not a squared matrix, %d!=%d", len(m.Rows), len(m.Rows[0]))
	}

	det, err := Det(m)
	if err != nil {
		return nil, err
	}
	if det.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("failed to inverse, not invertible")
	}
	detInv := new(big.Int).ModInverse(det, m.P)

	rows := make([][]*big.Int, 0, len(m.Rows))
	for i := 0; i < len(m.Rows); i++ {
		row := make([]*big.Int, 0, len(m.Rows[0]))
		for j := 0; j < len(m.Rows[0]); j++ {
			c, err := cofactor(m, i, j)
			if err != nil {
				return nil, err
			}

			r := new(big.Int).Mul(c, detInv)
			r = r.Mod(r, m.P)
			row = append(row, r)
		}
		rows = append(rows, row)
	}

	return Transpose(&Matrix{
		Rows: rows,
		P:    m.P}), nil
}

// cofactor calculate cofactor of a matrix
// (-1)^{i+j} * |A*_ij|, |A*_ij| is the det the child matrix removing ith row and jth column
func cofactor(m *Matrix, row, col int) (*big.Int, error) {
	cofactor := big.NewInt(1)
	if (row+col)%2 != 0 {
		cofactor = big.NewInt(-1)
	}
	cm, err := childMatrix(m, row, col)
	if err != nil {
		return nil, err
	}

	det, err := Det(cm)
	if err != nil {
		return nil, err
	}
	cofactor = cofactor.Mul(cofactor, det)
	cofactor = cofactor.Mod(cofactor, m.P)

	return cofactor, nil
}

// childMatrix get child matrix by deleting ith row and jth column of a matrix
func childMatrix(m *Matrix, r, col int) (*Matrix, error) {
	if r >= len(m.Rows) || col >= len(m.Rows[0]) {
		return nil, fmt.Errorf("r or col exceeded, row: %d, column: %d", len(m.Rows), len(m.Rows[0]))
	}

	rows := make([][]*big.Int, 0, len(m.Rows)-1)
	for i := 0; i < len(m.Rows); i++ {
		if i == r {
			continue
		}
		row := make([]*big.Int, 0, len(m.Rows[0])-1)
		for j := 0; j < len(m.Rows[0]); j++ {
			if j == col {
				continue
			}
			row = append(row, new(big.Int).Set(m.Rows[i][j]))
		}
		rows = append(rows, row)
	}

	return &Matrix{Rows: rows,
		P: m.P}, nil
}

func (m *Matrix) Print() {
	for i := 0; i < len(m.Rows); i++ {
		for j := 0; j < len(m.Rows[0]); j++ {
			fmt.Printf("%v\t", m.Rows[i][j])
		}
		fmt.Printf("\n")
	}
}
