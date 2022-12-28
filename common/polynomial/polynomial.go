package polynomial

import (
	"fmt"
	"math/big"
)

// MultiplyXns given {x1, x2,..., xn}, compute F(x)=(x+x1)*(x+x2)*...*(x+xn)
// return coefficents of F(x) {an,..., a1, a0}
func MultiplyXns(xs []*big.Int) ([]*big.Int, error) {
	if len(xs) == 0 {
		return nil, fmt.Errorf("xs cannot be empty")
	}

	res := []*big.Int{big.NewInt(1), xs[0]}
	var err error
	for i := 1; i < len(xs); i++ {
		xn := []*big.Int{big.NewInt(1), xs[i]}
		res, err = MultiplyTwoPoly(res, xn)
		if err != nil {
			return nil, fmt.Errorf("MultiplyTwoPoly failed: %v", err)
		}
	}

	return res, nil
}

// MultiplyTwoPoly compute (an*x^n + ... +a1*x + a0) * (bm*x^m + ... + b1*x + b0)
// return {c_{n+m},..., c1, c0}
func MultiplyTwoPoly(coef1, coef2 []*big.Int) ([]*big.Int, error) {
	if len(coef1) == 0 || len(coef2) == 0 {
		return nil, fmt.Errorf("coefficents cannot be empty")
	}

	// map degree to corresponding coeffient
	coefMap := make(map[int]*big.Int)
	for i := 0; i < len(coef1); i++ {
		for j := 0; j < len(coef2); j++ {
			degree := len(coef1) + len(coef2) - i - j - 2
			coef := new(big.Int).Mul(coef1[i], coef2[j])
			if v, exist := coefMap[degree]; !exist {
				coefMap[degree] = coef
			} else {
				coefMap[degree] = coefMap[degree].Add(v, coef)
			}
		}
	}

	res := make([]*big.Int, 0, len(coef1)+len(coef2)-1)
	for i := 0; i < len(coef1)+len(coef2)-1; i++ {
		res = append(res, coefMap[len(coef1)+len(coef2)-2-i])
	}

	return res, nil
}

// MultiplyXnsModP given {x1, x2,..., xn}, compute F(x)=(x+x1)*(x+x2)*...*(x+xn) (mod P)
// return coefficents of F(x) {an,..., a1, a0}
func MultiplyXnsModP(xs []*big.Int, modulus *big.Int) ([]*big.Int, error) {
	if len(xs) == 0 {
		return nil, fmt.Errorf("xs cannot be empty")
	}

	res := []*big.Int{big.NewInt(1), new(big.Int).Mod(xs[0], modulus)}
	var err error
	for i := 1; i < len(xs); i++ {
		xn := []*big.Int{big.NewInt(1), new(big.Int).Mod(xs[i], modulus)}
		res, err = MultiplyTwoPolyModP(res, xn, modulus)
		if err != nil {
			return nil, fmt.Errorf("MultiplyTwoPolyModM failed: %v", err)
		}
	}

	return res, nil
}

// MultiplyTwoPolyModP compute (an*x^n + ... +a1*x + a0) * (bm*x^m + ... + b1*x + b0) (mod P)
// return {c_{n+m},..., c1, c0}
func MultiplyTwoPolyModP(coef1, coef2 []*big.Int, modulus *big.Int) ([]*big.Int, error) {
	if len(coef1) == 0 || len(coef2) == 0 {
		return nil, fmt.Errorf("coefficents cannot be empty")
	}

	// map degree to corresponding coeffient
	coefMap := make(map[int]*big.Int)
	for i := 0; i < len(coef1); i++ {
		for j := 0; j < len(coef2); j++ {
			degree := len(coef1) + len(coef2) - i - j - 2
			coef := new(big.Int).Mul(coef1[i], coef2[j])
			coef = coef.Mod(coef, modulus)
			if v, exist := coefMap[degree]; !exist {
				coefMap[degree] = coef
			} else {
				coefMap[degree] = coefMap[degree].Add(v, coef)
				coefMap[degree] = coefMap[degree].Mod(coefMap[degree], modulus)
			}
		}
	}

	res := make([]*big.Int, 0, len(coef1)+len(coef2)-1)
	for i := 0; i < len(coef1)+len(coef2)-1; i++ {
		res = append(res, coefMap[len(coef1)+len(coef2)-2-i])
	}

	return res, nil
}

// LagrangeInterpolation generate G(x) = a_{n-1}*x^{n-1} + ... + a1*x + a0 (mod P) by
// lagrange interpolation using {x_i, m_i} pairs, where G(x_i) = m_i
// values is map from x_i to m_i, len(values)=n
// return {a_{n-1},..., a1, a0}
func LagrangeInterpolation(values map[*big.Int]*big.Int, modulus *big.Int) ([]*big.Int, error) {
	// G(x) = SUM_i (m_i * MUL_j((x-xj)/(xi-xj)))
	// G(x) = SUM_i (m_i * MUL_j(1/(xi-xj)) * MUL_j(x-xj))
	// for each i, (m_i * MUL_j(1/(xi-xj)) * MUL_j(x-xj)) is a polynomial with degree n-1
	res := make([]*big.Int, 0, len(values))
	for i := 0; i < len(values); i++ {
		res = append(res, big.NewInt(0))
	}
	for xi, yi := range values {
		// MUL_j (1/(xi-xj)), i != j
		mulInvXiMinusXj := big.NewInt(1)
		// denote {-xj} list
		xjList := make([]*big.Int, 0, len(values)-1)
		for xj, _ := range values {
			if xj.Cmp(xi) == 0 {
				continue
			}
			xiMinusXj := new(big.Int).Sub(xi, xj)
			xiMinusXj = xiMinusXj.ModInverse(xiMinusXj, modulus)
			mulInvXiMinusXj = mulInvXiMinusXj.Mul(mulInvXiMinusXj, xiMinusXj)
			mulInvXiMinusXj = mulInvXiMinusXj.Mod(mulInvXiMinusXj, modulus)
			xjList = append(xjList, new(big.Int).Neg(xj))
		}
		// yi * MUL_j (1/(xi-xj))
		left := new(big.Int).Mul(yi, mulInvXiMinusXj)
		left = left.Mod(left, modulus)
		right, err := MultiplyXnsModP(xjList, modulus)
		if err != nil {
			return nil, err
		}

		for i := 0; i < len(right); i++ {
			// yi * MUL_j (1/(xi-xj)) * MUL_j(x-xj)
			right[i] = right[i].Mul(right[i], left)
			// SUM_i (yi * MUL_j (1/(xi-xj)) * MUL_j(x-xj))
			res[i] = res[i].Add(res[i], right[i])
			res[i] = res[i].Mod(res[i], modulus)
		}
	}
	return res, nil
}
