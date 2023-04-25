// hash to ecc point using Try-and-Increment algorithm
package hash_to_point

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

var (
	DefaultCurveType = elliptic.P256()
	DefaultTryTimes  = 100
)

// HashToPoint hash a number to an ecc point, return (x,y)
func HashToPoint(t *big.Int, tryTimes int) (*big.Int, *big.Int, error) {
	if t.Cmp(DefaultCurveType.Params().P) >= 0 {
		return nil, nil, fmt.Errorf("invalid number, must smaller than P")
	}
	if tryTimes == 0 {
		tryTimes = DefaultTryTimes
	}

	for i := 0; i < tryTimes; i++ {
		x := new(big.Int).Add(t, big.NewInt(int64(i)))
		x = x.Mod(x, DefaultCurveType.Params().P)
		y := calY(x)
		if y != nil {
			return x, y, nil
		}
	}
	return nil, nil, fmt.Errorf("failed to find ecc poing, try increase trying times")
}

// y^2 = x^3 - 3x + b
func calY(x *big.Int) *big.Int {
	x2 := new(big.Int).Mul(x, x)
	x3 := new(big.Int).Mul(x2, x)

	ax := new(big.Int).Mul(big.NewInt(-3), x)

	ySquare := new(big.Int).Add(x3, ax)
	ySquare = ySquare.Add(ySquare, DefaultCurveType.Params().B)
	ySquare = ySquare.Mod(ySquare, DefaultCurveType.Params().P)

	return new(big.Int).ModSqrt(ySquare, DefaultCurveType.Params().P)
}
