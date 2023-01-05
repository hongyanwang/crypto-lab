package pir

import (
	"fmt"
	"math/big"

	"github.com/hongyanwang/crypto-lab/asymmetric/paillier"
	"github.com/hongyanwang/crypto-lab/common/polynomial"
)

// GenGx generate G(x) = a_0 + a_1*x + a_2*x^2 +...+ a_{n-1}*x^{n-1} by
// lagrange interpolation using {x_i, m_i} pairs, where G(x_i) = m_i
// values is map from x_i to m_i, len(values)=n
// return {a_0, a_1,..., a_{n-1}}
func GenGx(values map[*big.Int]*big.Int, modulus *big.Int) ([]*big.Int, error) {
	ans, err := polynomial.LagrangeInterpolation(values, modulus)
	if err != nil {
		return nil, err
	}
	// ans is {a_{n-1}}, ..., a_1, a_0}, need to be reverted
	for i := 0; i < len(ans)/2; i++ {
		ans[i], ans[len(ans)-i-1] = ans[len(ans)-i-1], ans[i]
	}
	return ans, nil
}

// GenFx generate F(x) = (x-x_1) * (x-x_2) *...* (x_x_n) using {x_i, m_i} pairs
// values is map from x_i to m_i, len(values)=n
// return coefficients of F(x) {b_0, b_1,..., b_{n-1}, b_n}
func GenFx(values map[*big.Int]*big.Int, modulus *big.Int) ([]*big.Int, error) {
	xns := make([]*big.Int, 0, len(values))
	for k, _ := range values {
		xns = append(xns, new(big.Int).Neg(k))
	}
	bns, err := polynomial.MultiplyXnsModP(xns, modulus)
	if err != nil {
		return nil, err
	}
	// bns is {b_n}, ..., b_1, b_0}, need to be reverted
	for i := 0; i < len(bns)/2; i++ {
		bns[i], bns[len(bns)-i-1] = bns[len(bns)-i-1], bns[i]
	}
	return bns, nil
}

// GenSearchMaterial generate material to search target value
// encrypt target {x_i, x_i^2,...x_i^n} by homomorphic public key
// return the encrypted vector
func GenSearchMaterial(targetIdx *big.Int, pubkey *paillier.PublicKey, totalItems int64) ([]*big.Int, error) {
	res := make([]*big.Int, 0, totalItems)
	target := new(big.Int).Set(targetIdx)
	var i int64 = 0
	for i < totalItems {
		enc, err := paillier.Encrypt(target, pubkey)
		if err != nil {
			return nil, err
		}
		res = append(res, enc)

		i++
		target = target.Mul(target, targetIdx)
	}
	return res, nil
}

// GenEncGxFx generate encrypted Gx and Fx
// encGx = Enc(a_0) + a_1*Enc(x) +...+ a_{n-1}*Enc(x^{n-1})
// encFx = Enc(b_0) + b_1*Enc(x) +...+ b_{n-1}*Enc(x^{n-1}) + b_n*Enc(x^n)
func GenEncGxFx(encVectors, coefGx, coefFx []*big.Int, pubkey *paillier.PublicKey) (*big.Int, *big.Int, error) {
	// check length of encVectors, coefGx and coefFx
	// length of encVectors and length of coefGx must be same
	// length of encVectors is one smallerr than length of coefFx
	if len(encVectors) != len(coefGx) {
		return nil, nil, fmt.Errorf("length of encVectors[%d] and length of coefGx[%d] are not equal", len(encVectors), len(coefGx))
	}
	if len(encVectors) != len(coefFx)-1 {
		return nil, nil, fmt.Errorf("length of encVectors[%d] are not equal to length of coefFx[%d]-1", len(encVectors), len(coefFx))
	}

	encGx, err := paillier.Encrypt(coefGx[0], pubkey)
	if err != nil {
		return nil, nil, fmt.Errorf("Paillier Encrypt failed: %v", err)
	}
	for i := 0; i < len(encVectors)-1; i++ {
		mul := paillier.ScalarMul(encVectors[i], coefGx[i+1], pubkey)
		encGx = paillier.Add(encGx, mul, pubkey)
	}

	encFx, err := paillier.Encrypt(coefFx[0], pubkey)
	if err != nil {
		return nil, nil, fmt.Errorf("Paillier Encrypt failed: %v", err)
	}
	for i := 0; i < len(encVectors); i++ {
		mul := paillier.ScalarMul(encVectors[i], coefFx[i+1], pubkey)
		encFx = paillier.Add(encFx, mul, pubkey)
	}
	return encGx, encFx, nil
}

// RetrieveTargetValue retrieve target value by homomorhpic decryption
// if F(x)=0, G(x) is the target value, otherwise target is not found
func RetrieveTargetValue(encGx, encFx *big.Int, privkey *paillier.PrivateKey) (*big.Int, error) {
	fx, err := paillier.Decrypt(encFx, privkey)
	if err != nil {
		return nil, err
	}
	if fx.Cmp(big.NewInt(0)) == 0 {
		gx, err := paillier.Decrypt(encGx, privkey)
		if err != nil {
			return nil, err
		}
		return gx, nil
	}
	return nil, nil
}
