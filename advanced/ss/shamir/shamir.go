package shamir

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	MinThreshold = 3
	secLen       = 2048
)

var p *big.Int

func init() {
	p, _ = rand.Prime(rand.Reader, secLen)
}

// GenerateShares generate N shares given number of participants and thresholds
func GenerateShares(partyNum, threshold int, secret *big.Int) (map[*big.Int]*big.Int, error) {
	if threshold < MinThreshold {
		return nil, fmt.Errorf("threshold is too small, at least: %d", MinThreshold)
	}

	// 1. generate random coefficients to form a polynomial
	coefficients := make([]*big.Int, threshold)
	coefficients[0] = new(big.Int).Set(secret)
	for i := 1; i < threshold; i++ {
		r, err := rand.Int(rand.Reader, p)
		if err != nil {
			return nil, err
		}
		coefficients[i] = r
	}

	// 2. generate random x_i and calculate y_i
	xFound := make(map[*big.Int]bool)
	shares := make(map[*big.Int]*big.Int)
	for i := 0; i < partyNum; i++ {
		x := new(big.Int)
		var err error
		for {
			x, err = rand.Int(rand.Reader, p)
			if err != nil {
				return nil, err
			}
			// avoid duplicate x
			if _, ok := xFound[x]; !ok {
				xFound[x] = true
				break
			}
		}
		shares[x] = calPolyByCoef(coefficients, x)
	}

	return shares, nil
}

// RecoverSecret recover secret value using (x,y) pairs
// use Lagrange Interpolation Polynomial
// sum( y_i*mul(-x_j)*{mul(x_i-x_j)}^-1 )
func RecoverSecret(shares map[*big.Int]*big.Int) (*big.Int, error) {
	result := new(big.Int)
	for x, y := range shares {
		m1 := new(big.Int).Set(y)
		m2 := big.NewInt(1)
		m3 := big.NewInt(1)
		for k := range shares {
			if k.Cmp(x) != 0 {
				kNeg := new(big.Int).Neg(k)
				m2 = new(big.Int).Mul(m2, kNeg)
				m2 = new(big.Int).Mod(m2, p)

				sub := new(big.Int).Sub(x, k)
				m3 = new(big.Int).Mul(m3, sub)
				m3 = new(big.Int).Mod(m3, p)
			}
		}
		// find inverse
		m3 = new(big.Int).ModInverse(m3, p)

		m1 = new(big.Int).Mul(m1, m2)
		m1 = new(big.Int).Mul(m1, m3)
		result = new(big.Int).Add(result, m1)
		result = new(big.Int).Mod(result, p)
	}

	return result, nil
}

// calPolyByCoef calculate y value of a polynomial by coefficients
// coefficients = {a_0, a_1 ...}, return a_0 + a_1*x + a_2*x^2...
func calPolyByCoef(coefficients []*big.Int, x *big.Int) *big.Int {
	result := new(big.Int).Set(coefficients[0])
	tmpX := new(big.Int).Set(x)
	for i := 1; i < len(coefficients); i++ {
		m := new(big.Int).Mul(coefficients[i], tmpX)
		result = new(big.Int).Add(result, m)
		tmpX = new(big.Int).Mul(tmpX, x)
	}

	return result
}
