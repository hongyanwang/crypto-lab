package blakley

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/hongyanwang/crypto-lab/common/matrix"
)

const (
	MinThreshold = 3
	secLen       = 1024
)

var p *big.Int

func init() {
	p, _ = rand.Prime(rand.Reader, secLen)
}

// GenerateShares generate N shares given number of participants and thresholds
func GenerateShares(partyNum, threshold int, secret *big.Int) ([][]*big.Int, error) {
	if threshold < MinThreshold {
		return nil, fmt.Errorf("threshold is too small, at least: %d", MinThreshold)
	}

	// 1. generate random coordinate to form a point (s=x0, x1, x2... x_{k-2}, y)
	coordinates := make([]*big.Int, 0, threshold)
	coordinates = append(coordinates, new(big.Int).Set(secret))
	for i := 1; i < threshold; i++ {
		r, err := rand.Int(rand.Reader, p)
		if err != nil {
			return nil, err
		}
		coordinates = append(coordinates, r)
	}

	// 2. for each party, generate random {a_0, a_1, ... a_{k-2}}
	//  and calculate c=y-(a_0*x_0+...a_{k-2}*x_{k-2})
	// each share is {a_0, a_1... a_{k-2}, c}
	shares := make([][]*big.Int, 0, partyNum)
	for i := 0; i < partyNum; i++ {
		share := make([]*big.Int, 0, threshold)
		sum := big.NewInt(0)
		for j := 0; j < threshold-1; j++ {
			a, err := rand.Int(rand.Reader, p)
			if err != nil {
				return nil, err
			}
			share = append(share, a)
			sum = sum.Add(sum, new(big.Int).Mul(a, coordinates[j]))
			sum = sum.Mod(sum, p)
		}
		c := new(big.Int).Sub(coordinates[threshold-1], sum)
		c = c.Mod(c, p)
		share = append(share, c)

		shares = append(shares, share)
	}

	return shares, nil
}

// RecoverSecret recover secret value using shares, number of shares must be equal to threshold
/*
	a_0,0	a_0,1	...	a_0,k-2, -1			x_0		 -c_0
	a_1,0	a_1,1	...	a_1,k-2, -1			x_1		 -c_1
			......						*		  =
	a_k-1,0	a_k-1,1	...	a_k-1,k-2, -1		y		 -c_k-1
*/
func RecoverSecret(shares [][]*big.Int) (*big.Int, error) {
	// set the matrix
	rows := make([][]*big.Int, 0, len(shares))
	for i := 0; i < len(shares); i++ {
		row := make([]*big.Int, 0, len(shares))
		row = append(row, shares[i][:len(shares)-1]...)
		row = append(row, big.NewInt(-1))

		rows = append(rows, row)
	}
	m, err := matrix.NewMatrix(rows, p)
	if err != nil {
		return nil, err
	}

	// set the constant matrix
	yRows := make([][]*big.Int, 0, len(shares))
	for i := 0; i < len(shares); i++ {
		row := make([]*big.Int, 0, 1)
		mc := new(big.Int).Neg(shares[i][len(shares)-1])
		row = append(row, mc)

		yRows = append(yRows, row)
	}
	my, err := matrix.NewMatrix(yRows, p)
	if err != nil {
		return nil, err
	}

	// find inverse of the matrix
	mInv, err := matrix.Inverse(m)
	if err != nil {
		return nil, err
	}

	// X = M^-1 * Y
	mx, err := matrix.Mul(mInv, my)
	if err != nil {
		return nil, err
	}

	return mx.Rows[0][0], nil
}
